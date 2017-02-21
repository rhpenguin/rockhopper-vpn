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

#include "rhp_trace.h"
#include "rhp_main_traceid.h"
#include "rhp_misc.h"
#include "rhp_version.h"
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
#include "rhp_dns_pxy.h"
#include "rhp_forward.h"
#include "rhp_radius_impl.h"


/*

	- Allow IPv6 autoconf (Remote config) - Rockhopper's private extension


  (1) IKE_SA_INIT Exchange


  (2) IKE_AUTH Exchange

   [Remote client]
   request             --> IDi, [CERT+],
                           [N+],
                           [IDr],
                           AUTH,
                           CP(CFG_REQUEST including a RHP_IPV6_AUTOCONF attribute),
                           [N+],
                           SA, TSi, TSr,
                           [V+][N+]

	 [Gateway/Concentrator]
   normal
   response            <-- IDr, [CERT+],
                           AUTH,
                           CP(CFG_REPLY including a RHP_IPV6_AUTOCONF attribute),
                           [N+],
                           SA,
                           TSi(ICMPv6 for linklocal/subnet address ranges
                               and the client's IPv4 address [narrowed]),
                           TSr(ICMPv6 for linklocal/subnet address ranges
                               and IPv4 address ranges),
                           [V+][N+]

    - ICMPv6's traffic selectors: See rhp_ikev2_cfg_alloc_v6_auto_tss()
                                  [rhp_ikev2_cfg.c].

    - IPV6_AUTOCONF has a field including a flag value (1 byte).
       1 : IPv6 autoconf is allowed for the client.
       0 : IPv6 autoconf is not allowed.


  (3) The remote client executes IPv6 autoconf via the first CHILD SA's
      tunnel.


  (4) INFORMATIONAL Exchange for notification including the new IPv6
      addresses.

   [Remote client]
   request             --> N(RHP_INTERNAL_IP4_ADDRESS),
                           N(RHP_INTERNAL_IP6_ADDRESS)+,
                           [N(RHP_INTERNAL_MAC_ADDRESS)]

    - The remote client always sends ALL IPv4 and IPv6 addresses.

	 [Gateway/Concentrator]
   normal
   response            <-- No payloads


  (5) CREATE_CHILD_SA Exchange for Rekeying a Child SA allowing
      the client's IPv6 addresses (Traffic selectors).

	 [Gateway/Concentrator]
   request             --> [N(REKEY_SA)],
                           [N+],
                           SA, Ni, [KEi],
                           TSi(ICMPv6 for linklocal/subnet address ranges
                               and other allowed IPv4/IPv6 address ranges or any)
                           TSr(ICMPv6 for linklocal/subnet address ranges
                               and the client's IPv4/IPv6 addresses [narrowed]),
                           [V+][N+]

   [Remote client]
   normal              <-- [N+],
                           SA, Nr, [KEr], TSi, TSr,
                           [V+][N+]


   - If the client needs to change/update the IPv6 address(es),
     the process is restarted from (3). [e.g. IPv6 privacy extension]

   - If the client's IPv6 adddress is already used by the other client,
     the address is ignored by gateway/concentrator and so it is not
     allowed for a newly rekeyed Child SA.

   - If traffic narrowing for remote clients is disabled, these
     process is never done.

*/



static int _rhp_ikev2_cfg_new_pkt_req(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_ikev2_mesg* tx_ikemesg)
{
	int err = -EINVAL;
	rhp_vpn_realm* rlm = NULL;
  rhp_ikev2_payload* ikepayload = NULL;

  RHP_TRC(0,RHPTRCID_IKEV2_CFG_NEW_PKT_REQ,"xxxd",tx_ikemesg,vpn,rlm,rhp_gcfg_ikev2_cfg_rmt_clt_req_old_addr);

	rlm = vpn->rlm;

	if( rlm == NULL ){
		err = -EINVAL;
		RHP_BUG("");
		goto error;
	}

	RHP_LOCK(&(rlm->lock));

	if( !_rhp_atomic_read(&(rlm->is_active)) ){
		err = -EINVAL;
	  RHP_TRC(0,RHPTRCID_IKEV2_CFG_NEW_PKT_REQ_RLM_NOT_ACTIVE,"xxx",tx_ikemesg,vpn,rlm);
		goto error_rlm_l;
	}

	if( rlm->config_service != RHP_IKEV2_CONFIG_CLIENT ){
	  RHP_TRC(0,RHPTRCID_IKEV2_CFG_NEW_PKT_REQ_RLM_NOT_CONFIG_CLIENT_ENABLED,"xxx",tx_ikemesg,vpn,rlm);
		goto ignore;
	}


	if( rlm->access_point_peer ){

		if( rhp_ikev2_id_cmp(&(rlm->access_point_peer->id),&(vpn->peer_id)) &&
				rhp_ip_addr_cmp_ip_only(&(rlm->access_point_peer->primary_addr),&(vpn->peer_addr)) &&
				rhp_ip_addr_cmp_ip_only(&(rlm->access_point_peer->secondary_addr),&(vpn->peer_addr)) ){

			RHP_TRC(0,RHPTRCID_IKEV2_CFG_NEW_PKT_REQ_PEER_IS_NOT_ACCESSPOINT,"xxx",tx_ikemesg,vpn,rlm);
			rhp_ikev2_id_dump("access_point_peer->id",&(rlm->access_point_peer->id));
			rhp_ikev2_id_dump("vpn->peer_id",&(vpn->peer_id));
			rhp_ip_addr_dump("vpn->peer_address",&(vpn->peer_addr));
			rhp_ip_addr_dump("primary_addr",&(rlm->access_point_peer->primary_addr));
			rhp_ip_addr_dump("secondary_addr",&(rlm->access_point_peer->secondary_addr));

			goto ignore;
		}
	}

	if( (rlm->access_point_peer_vpn_ref != NULL) && (RHP_VPN_REF(rlm->access_point_peer_vpn_ref) != vpn) ){

		RHP_TRC(0,RHPTRCID_IKEV2_CFG_NEW_PKT_REQ_ACCESSPOINT_IS_ALREADY_SET,"xxxx",tx_ikemesg,vpn,rlm,RHP_VPN_REF(rlm->access_point_peer_vpn_ref));
		goto ignore;
	}

	if( ( err = rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKE_PAYLOAD_CP,&ikepayload)) ){
		RHP_BUG("");
		goto error;
	}

	tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

	ikepayload->ext.cp->set_cfg_type(ikepayload,RHP_PROTO_IKE_CFG_REQUEST);


	if( rlm->internal_ifc->addrs_type == RHP_VIF_ADDR_IKEV2CFG ){

		rhp_ip_addr_list* internal_addr = rlm->internal_ifc->addrs;
		int flag = 0;

		while( internal_addr ){

			if( !rhp_ip_addr_null(&(internal_addr->ip_addr)) ){

				if( !(flag & 0x1) && internal_addr->ip_addr.addr_family == AF_INET ){

					err = ikepayload->ext.cp->alloc_and_put_attr(ikepayload,RHP_PROTO_IKE_CFG_ATTR_INTERNAL_IP4_ADDRESS,
								4,internal_addr->ip_addr.addr.raw);
					if( err ){
						RHP_BUG("%d",err);
						goto error;
					}

					err = ikepayload->ext.cp->alloc_and_put_attr(ikepayload,RHP_PROTO_IKE_CFG_ATTR_INTERNAL_IP4_NETMASK,
								4,internal_addr->ip_addr.netmask.raw);
					if( err ){
						RHP_BUG("%d",err);
						goto error;
					}

					flag |= 0x1;

				}else if( !rhp_gcfg_ipv6_disabled &&
									!rlm->internal_ifc->ikev2_config_ipv6_auto &&
									!(flag & 0x2) && internal_addr->ip_addr.addr_family == AF_INET6 &&
									!rhp_ipv6_is_linklocal(internal_addr->ip_addr.addr.raw) ){

					u8 buf[17];
					memcpy(buf,internal_addr->ip_addr.addr.raw,16);
					buf[16] = internal_addr->ip_addr.prefixlen;

					err = ikepayload->ext.cp->alloc_and_put_attr(ikepayload,RHP_PROTO_IKE_CFG_ATTR_INTERNAL_IP6_ADDRESS,17,buf);
					if( err ){
						RHP_BUG("%d",err);
						goto error;
					}

					flag |= 0x2;
				}
			}

			internal_addr = internal_addr->next;
		}

		if( !(flag & 0x1) ){

			rhp_ip_addr_dump("CFG_RMT_CLT_OLD_ADDR_V4",&(vpn->cfg_peer->ikev2_cfg_rmt_clt_old_addr_v4));

			if( rhp_gcfg_ikev2_cfg_rmt_clt_req_old_addr &&
					!rhp_ip_addr_null(&(vpn->cfg_peer->ikev2_cfg_rmt_clt_old_addr_v4)) ){

				err = ikepayload->ext.cp->alloc_and_put_attr(ikepayload,RHP_PROTO_IKE_CFG_ATTR_INTERNAL_IP4_ADDRESS,
							4,vpn->cfg_peer->ikev2_cfg_rmt_clt_old_addr_v4.addr.raw);
				if( err ){
					RHP_BUG("%d",err);
					goto error;
				}

				err = ikepayload->ext.cp->alloc_and_put_attr(ikepayload,RHP_PROTO_IKE_CFG_ATTR_INTERNAL_IP4_NETMASK,
							4,vpn->cfg_peer->ikev2_cfg_rmt_clt_old_addr_v4.netmask.raw);
				if( err ){
					RHP_BUG("%d",err);
					goto error;
				}

				flag |= 0x1;
			}
		}

		if( !(flag & 0x1) ){

			err = ikepayload->ext.cp->alloc_and_put_attr(ikepayload,RHP_PROTO_IKE_CFG_ATTR_INTERNAL_IP4_ADDRESS,0,NULL);
			if( err ){
				RHP_BUG("%d",err);
				goto error;
			}

			err = ikepayload->ext.cp->alloc_and_put_attr(ikepayload,RHP_PROTO_IKE_CFG_ATTR_INTERNAL_IP4_NETMASK,0,NULL);
			if( err ){
				RHP_BUG("%d",err);
				goto error;
			}
		}


		if( !rhp_gcfg_ipv6_disabled ){

			if( !(flag & 0x2) ){

				rhp_ip_addr_dump("CFG_RMT_CLT_OLD_ADDR_V6",&(vpn->cfg_peer->ikev2_cfg_rmt_clt_old_addr_v6));

				if( rhp_gcfg_ikev2_cfg_rmt_clt_req_old_addr &&
						!rhp_ip_addr_null(&(vpn->cfg_peer->ikev2_cfg_rmt_clt_old_addr_v6)) ){

					u8 buf[17];
					memcpy(buf,vpn->cfg_peer->ikev2_cfg_rmt_clt_old_addr_v6.addr.raw,16);
					buf[16] = vpn->cfg_peer->ikev2_cfg_rmt_clt_old_addr_v6.prefixlen;

					err = ikepayload->ext.cp->alloc_and_put_attr(ikepayload,RHP_PROTO_IKE_CFG_ATTR_INTERNAL_IP6_ADDRESS,17,buf);
					if( err ){
						RHP_BUG("%d",err);
						goto error;
					}

					flag |= 0x2;
				}
			}

			if( !(flag & 0x2) ){

				err = ikepayload->ext.cp->alloc_and_put_attr(ikepayload,RHP_PROTO_IKE_CFG_ATTR_INTERNAL_IP6_ADDRESS,0,NULL);
				if( err ){
					RHP_BUG("%d",err);
					goto error;
				}
			}
		}

	}else{

	  RHP_TRC(0,RHPTRCID_IKEV2_CFG_NEW_PKT_REQ_RLM_NOT_CONFIG_CLIENT_ENABLED_2,"xxxd",tx_ikemesg,vpn,rlm,rlm->internal_ifc->addrs_type);
	}


	err = ikepayload->ext.cp->alloc_and_put_attr(ikepayload,RHP_PROTO_IKE_CFG_ATTR_INTERNAL_IP4_SUBNET,0,NULL);
  if( err ){
  	RHP_BUG("%d",err);
  	goto error;
  }

	err = ikepayload->ext.cp->alloc_and_put_attr(ikepayload,RHP_PROTO_IKE_CFG_ATTR_INTERNAL_IP4_DNS,0,NULL);
	if( err ){
		RHP_BUG("%d",err);
		goto error;
	}

	if( !rhp_gcfg_ipv6_disabled ){

		err = ikepayload->ext.cp->alloc_and_put_attr(ikepayload,RHP_PROTO_IKE_CFG_ATTR_INTERNAL_IP6_SUBNET,0,NULL);
	  if( err ){
	  	RHP_BUG("%d",err);
	  	goto error;
	  }

		err = ikepayload->ext.cp->alloc_and_put_attr(ikepayload,RHP_PROTO_IKE_CFG_ATTR_INTERNAL_IP6_DNS,0,NULL);
		if( err ){
			RHP_BUG("%d",err);
			goto error;
		}
	}

	err = ikepayload->ext.cp->alloc_and_put_attr(ikepayload,RHP_PROTO_IKE_CFG_ATTR_APPLICATION_VERSION,0,NULL);
	if( err ){
		RHP_BUG("%d",err);
		goto error;
	}

  if( vpn->peer_is_rockhopper ){

  	err = ikepayload->ext.cp->alloc_and_put_attr(ikepayload,RHP_PROTO_IKE_CFG_ATTR_RHP_DNS_SFX,0,NULL);
  	if( err ){
  		RHP_BUG("%d",err);
  		goto error;
  	}

  	err = ikepayload->ext.cp->alloc_and_put_attr(ikepayload,RHP_PROTO_IKE_CFG_ATTR_RHP_IPV4_GATEWAY,0,NULL);
  	if( err ){
  		RHP_BUG("%d",err);
  		goto error;
  	}

  	if( !rhp_gcfg_ipv6_disabled ){

  		err = ikepayload->ext.cp->alloc_and_put_attr(ikepayload,RHP_PROTO_IKE_CFG_ATTR_RHP_IPV6_GATEWAY,0,NULL);
    	if( err ){
    		RHP_BUG("%d",err);
    		goto error;
    	}

    	if( rlm->internal_ifc->ikev2_config_ipv6_auto ){

    		err = ikepayload->ext.cp->alloc_and_put_attr(ikepayload,RHP_PROTO_IKE_CFG_ATTR_RHP_IPV6_AUTOCONF,0,NULL);
      	if( err ){
      		RHP_BUG("%d",err);
      		goto error;
      	}
    	}
  	}
  }

  RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_TX_CFG_REQ,"VPd",vpn,ikesa,vpn->peer_is_rockhopper);

ignore:
	RHP_UNLOCK(&(rlm->lock));

  RHP_TRC(0,RHPTRCID_IKEV2_CFG_NEW_PKT_REQ_RTRN,"xxx",tx_ikemesg,vpn,rlm);
	return 0;

error_rlm_l:
	RHP_UNLOCK(&(rlm->lock));
error:
	RHP_LOG_E(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_TX_CFG_REQ_ERR,"VPd",vpn,ikesa,vpn->peer_is_rockhopper);
	RHP_TRC(0,RHPTRCID_IKEV2_CFG_NEW_PKT_REQ_ERR,"xxxE",tx_ikemesg,vpn,rlm,err);
	return err;
}

static int _rhp_ikev2_cp_new_pkt_error_notify_rep(rhp_ikev2_mesg* tx_ikemesg,rhp_ikesa* ikesa,
		u8 protocol_id,u32 childsa_spi,u16 notify_mesg_type)
{
  rhp_ikev2_payload* ikepayload = NULL;

  RHP_TRC(0,RHPTRCID_IKEV2_CP_NEW_PKT_ERROR_NOTIFY_REP,"xxbJw",tx_ikemesg,ikesa,protocol_id,childsa_spi,notify_mesg_type);

  {
  	if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKE_PAYLOAD_N,&ikepayload) ){
    	RHP_BUG("");
    	goto error;
    }

  	tx_ikemesg->put_payload(tx_ikemesg,ikepayload);

  	ikepayload->ext.n->set_message_type(ikepayload,notify_mesg_type);

  	if( childsa_spi ){
    	ikepayload->ext.n->set_protocol_id(ikepayload,protocol_id);
  		ikepayload->ext.n->set_spi(ikepayload,childsa_spi);
    }else{
    	ikepayload->ext.n->set_protocol_id(ikepayload,0);
    }

    switch( notify_mesg_type ){

    case RHP_PROTO_IKE_NOTIFY_ERR_INVALID_SYNTAX:
    	break;

    case RHP_PROTO_IKE_NOTIFY_ERR_INTERNAL_ADDRESS_FAILURE:
    	break;

    case RHP_PROTO_IKE_NOTIFY_ERR_NO_PROPOSAL_CHOSEN:
    	break;

    default:
      RHP_BUG("%d",notify_mesg_type);
      goto error;
    }
  }

 	tx_ikemesg->tx_flag = RHP_IKEV2_SEND_REQ_FLAG_URGENT;

  RHP_TRC(0,RHPTRCID_IKEV2_CP_NEW_PKT_ERROR_NOTIFY_REP_RTRN,"x",tx_ikemesg);
  return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV2_CP_NEW_PKT_ERROR_NOTIFY_REP_ERR,"x",tx_ikemesg);
	return -1; // ikepayload will be released later by rhp_ikev2_destroy_mesg().
}



#define RHP_IKE_CFG_ATTR_SUPPORTED_NUM		14

static int _rhp_ikev2_cfg_srch_cp_req_attr_cb(rhp_ikev2_payload* payload,rhp_ikev2_cp_attr* cp_attr,void* ctx)
{
	rhp_cp_req_srch_pld_ctx* s_pld_ctx = (rhp_cp_req_srch_pld_ctx*)ctx;
	int cp_attr_type = cp_attr->get_attr_type(cp_attr);
	int cp_attr_len = cp_attr->get_attr_len(cp_attr);

  RHP_TRC(0,RHPTRCID_IKEV2_CFG_SRCH_CP_REQ_ATTR_CB,"xxxLdd",payload,cp_attr,ctx,"IKEV2_CFG_ATTR_TYPE",cp_attr_type,cp_attr_len);

	switch( cp_attr_type ){

	case RHP_PROTO_IKE_CFG_ATTR_INTERNAL_IP4_ADDRESS:

		if( cp_attr_len == 0 || cp_attr_len == 4 ){

			if( cp_attr_len ){
				s_pld_ctx->internal_addr.addr_family = AF_INET;
				memcpy(&(s_pld_ctx->internal_addr.addr.v4),cp_attr->get_attr(cp_attr),4);
			}

//		rhp_ip_addr_dump("CP_REQ_ATTR_CB_ITNL_V4_ADDR",&(s_pld_ctx->internal_addr));

			s_pld_ctx->internal_addr_flag = 1;

		}else{

	    RHP_TRC(0,RHPTRCID_IKEV2_CFG_SRCH_CP_REQ_ATTR_CB_INVALID_INTR_V4_ADDR,"xxxd",payload,cp_attr,ctx,cp_attr_len);
		}

		break;

	case RHP_PROTO_IKE_CFG_ATTR_INTERNAL_IP4_NETMASK:

		s_pld_ctx->internal_netmask_flag = 1;
		break;

	case RHP_PROTO_IKE_CFG_ATTR_INTERNAL_IP4_DNS:

		s_pld_ctx->internal_dns_flag = 1;
		break;

	case RHP_PROTO_IKE_CFG_ATTR_INTERNAL_IP4_SUBNET:

		s_pld_ctx->internal_subnet_flag = 1;
		break;

	case RHP_PROTO_IKE_CFG_ATTR_RHP_DNS_SFX:

		if( s_pld_ctx->peer_is_rockhopper ){
			s_pld_ctx->internal_dns_sfx_flag = 1;
		}
		break;

	case RHP_PROTO_IKE_CFG_ATTR_RHP_IPV4_GATEWAY:

		if( s_pld_ctx->peer_is_rockhopper ){
			s_pld_ctx->internal_gateway_flag = 1;
		}
		break;

	case RHP_PROTO_IKE_CFG_ATTR_INTERNAL_IP4_NBNS:

		s_pld_ctx->internal_wins_flag = 1;
		break;

	case RHP_PROTO_IKE_CFG_ATTR_INTERNAL_IP6_ADDRESS:

		if( cp_attr_len == 0 || cp_attr_len == 17 ){

			if( cp_attr_len ){

				u8* v = cp_attr->get_attr(cp_attr);

				s_pld_ctx->internal_addr_v6.addr_family = AF_INET6;
				memcpy(&(s_pld_ctx->internal_addr_v6.addr.v6),v,16);

				s_pld_ctx->internal_addr_v6.prefixlen = v[16];
				rhp_ipv6_prefixlen_to_netmask(
						s_pld_ctx->internal_addr_v6.prefixlen,s_pld_ctx->internal_addr_v6.netmask.v6);

			}

//		rhp_ip_addr_dump("CP_REQ_ATTR_CB_ITNL_V6_ADDR",&(s_pld_ctx->internal_addr));

			s_pld_ctx->internal_addr_v6_flag = 1;

		}else{

	    RHP_TRC(0,RHPTRCID_IKEV2_CFG_SRCH_CP_REQ_ATTR_CB_INVALID_INTR_V6_ADDR,"xxxd",payload,cp_attr,ctx,cp_attr_len);
		}

		break;

	case RHP_PROTO_IKE_CFG_ATTR_INTERNAL_IP6_DNS:

		s_pld_ctx->internal_dns_v6_flag = 1;
		break;

	case RHP_PROTO_IKE_CFG_ATTR_INTERNAL_IP6_SUBNET:

		s_pld_ctx->internal_subnet_v6_flag = 1;
		break;

	case RHP_PROTO_IKE_CFG_ATTR_RHP_IPV6_GATEWAY:

		if( s_pld_ctx->peer_is_rockhopper ){
			s_pld_ctx->internal_gateway_v6_flag = 1;
		}
		break;

	case RHP_PROTO_IKE_CFG_ATTR_INTERNAL_IP6_NBNS:

		s_pld_ctx->internal_wins_v6_flag = 1;
		break;

	case RHP_PROTO_IKE_CFG_ATTR_SUPPORTED_ATTRIBUTES:

		s_pld_ctx->supported_attrs = 1;
		break;

	case RHP_PROTO_IKE_CFG_ATTR_APPLICATION_VERSION:

		s_pld_ctx->app_ver_flag = 1;
		break;

	case RHP_PROTO_IKE_CFG_ATTR_RHP_IPV6_AUTOCONF:

		if( s_pld_ctx->peer_is_rockhopper ){
			s_pld_ctx->ipv6_autoconf_flag = 1;
		}
		break;

	default:
		break;
	}

  RHP_TRC(0,RHPTRCID_IKEV2_CFG_SRCH_CP_REQ_ATTR_CB_RTRN,"xxxLdd",payload,cp_attr,ctx,"IKEV2_CFG_ATTR_TYPE",cp_attr_type,cp_attr_len);
	return 0;
}

static int _rhp_ikev2_cfg_srch_cp_req_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,rhp_ikev2_payload* payload,void* ctx)
{
	int err = -EINVAL;
	rhp_cp_req_srch_pld_ctx* s_pld_ctx = (rhp_cp_req_srch_pld_ctx*)ctx;
	rhp_ikev2_cp_payload* cp_payload = payload->ext.cp;

  RHP_TRC(0,RHPTRCID_IKEV2_CFG_SRCH_CP_REQ_CB,"xdxd",rx_ikemesg,enum_end,ctx,s_pld_ctx->dup_flag);

  s_pld_ctx->dup_flag++;

  if( s_pld_ctx->dup_flag > 1 ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV2_CFG_SRCH_CP_REQ_CB_INVALID_MESG,"xdxd",rx_ikemesg,enum_end,ctx,s_pld_ctx->dup_flag);
    goto error;
  }

  err = cp_payload->enum_attr(payload,_rhp_ikev2_cfg_srch_cp_req_attr_cb,s_pld_ctx);
  if( err ){
    RHP_TRC(0,RHPTRCID_IKEV2_CFG_SRCH_CP_REQ_CB_ENUM_ATTR_ERR,"xdxE",rx_ikemesg,enum_end,ctx,err);
  	goto error;
  }

  s_pld_ctx->cp_payload = payload;

  RHP_TRC(0,RHPTRCID_IKEV2_CFG_SRCH_CP_REQ_CB_RTRN,"xdx",rx_ikemesg,enum_end,ctx);
  return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV2_CFG_SRCH_CP_REQ_CB_ERR,"xdxE",rx_ikemesg,enum_end,ctx,err);
	return err;
}


static int _rhp_ikev2_rx_cfg_req_internal_prefix_len(
		rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_ikev2_mesg* rx_req_ikemesg,
		rhp_cp_req_srch_pld_ctx* s_pld_ctx,
		rhp_vpn_realm* rlm,rhp_ip_addr* new_addr,
		u8* prefix_len_r)
{
	int err = -EINVAL;
	rhp_ip_addr* internal_ifc_addr = NULL;
	rhp_ip_addr* cfg_internal_netmask;
	rhp_ip_addr dmy_netmask;
	rhp_ip_addr_list* addr_lst = NULL;

	RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REQ_INTERNAL_PREFIX_LEN,"xxxxxxxLd",vpn,ikesa,rx_req_ikemesg,s_pld_ctx,rlm,new_addr,prefix_len_r,"VIF_ADDR",(rlm->internal_ifc ? rlm->internal_ifc->addrs_type : -1));
	rhp_ip_addr_dump("internal_prefix_len.new_addr",new_addr);

	if( new_addr->addr_family == AF_INET ){

		dmy_netmask.addr_family = AF_INET;
		dmy_netmask.addr.v4 = 0;

		if( new_addr->netmask.v4 ){

			dmy_netmask.netmask.v4 = new_addr->netmask.v4;
			dmy_netmask.prefixlen = rhp_ipv4_netmask_to_prefixlen(dmy_netmask.netmask.v4);

		}else if( new_addr->prefixlen ){

			dmy_netmask.netmask.v4 = rhp_ipv4_prefixlen_to_netmask(new_addr->prefixlen);
			dmy_netmask.prefixlen = new_addr->prefixlen;

		}else{

			dmy_netmask.netmask.v4 = 0xFFFFFFFF;
			dmy_netmask.prefixlen = 32;
		}

		cfg_internal_netmask = &(rlm->config_server.internal_netmask);

	}else	if( new_addr->addr_family == AF_INET6 ){

		dmy_netmask.addr_family = AF_INET6;
		memset(dmy_netmask.addr.v6,0,16);

		if( !rhp_ipv6_addr_null(new_addr->netmask.v6) ){

			memcpy(dmy_netmask.netmask.v6,new_addr->netmask.v6,16);
			dmy_netmask.prefixlen = rhp_ipv6_netmask_to_prefixlen(dmy_netmask.netmask.v6);

		}else if( new_addr->prefixlen ){

			rhp_ipv6_prefixlen_to_netmask(new_addr->prefixlen,dmy_netmask.netmask.v6);
			dmy_netmask.prefixlen = new_addr->prefixlen;

		}else{

			if( rhp_gcfg_ikev2_cfg_v6_internal_addr_def_prefix_len > 0 &&
					rhp_gcfg_ikev2_cfg_v6_internal_addr_def_prefix_len <= 128 ){

				rhp_ipv6_prefixlen_to_netmask(
						rhp_gcfg_ikev2_cfg_v6_internal_addr_def_prefix_len,dmy_netmask.netmask.v6);
				dmy_netmask.prefixlen = rhp_gcfg_ikev2_cfg_v6_internal_addr_def_prefix_len;

			}else{

				memset(dmy_netmask.netmask.v6,0xFF,16);
				dmy_netmask.prefixlen = 128;
			}
		}

		cfg_internal_netmask = &(rlm->config_server.internal_netmask_v6);

	}else{
		RHP_BUG("%d",new_addr->addr_family);
		return -EINVAL;
	}

	rhp_ip_addr_dump("internal_prefix_len.cfg_internal_netmask",cfg_internal_netmask);

	if( !rhp_netmask_null(cfg_internal_netmask) ){

		internal_ifc_addr = cfg_internal_netmask;

	}else if( rlm->internal_ifc->addrs_type == RHP_VIF_ADDR_NONE ){

		addr_lst = rlm->internal_ifc->bridge_addrs;
		while( addr_lst ){

			if( !rhp_netmask_null(&(addr_lst->ip_addr)) &&
					rhp_ip_same_subnet(&(addr_lst->ip_addr),new_addr->addr_family,new_addr->addr.raw) ){

				internal_ifc_addr = &(addr_lst->ip_addr);
				break;
			}

			addr_lst = addr_lst->next;
		}

		if( addr_lst == NULL ){
			internal_ifc_addr = &dmy_netmask;
			RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REQ_INTERNAL_PREFIX_LEN_INTERNAL_IF_ADDR_NOT_FOUND_BRIDGE,"xxxd",vpn,ikesa,rx_req_ikemesg,rlm->internal_ifc->addrs_type);
			RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_CFG_REQ_INTERNAL_IF_NO_SAME_SUBNET_ADDR_USE_DEF,"KAA",rx_req_ikemesg,new_addr,internal_ifc_addr);
		}

	}else if( rlm->internal_ifc->addrs_type == RHP_VIF_ADDR_STATIC ){

		addr_lst = rlm->internal_ifc->addrs;
		while( addr_lst ){

			if( rhp_ip_same_subnet(&(addr_lst->ip_addr),new_addr->addr_family,new_addr->addr.raw) ){

				internal_ifc_addr = &(addr_lst->ip_addr);
				break;
			}

			addr_lst = addr_lst->next;
		}

		if( internal_ifc_addr == NULL ){
			RHP_LOG_E(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_CFG_REQ_INTERNAL_IF_NO_SAME_SUBNET_ADDR,"KA",rx_req_ikemesg,new_addr);
		}

	}else{

		internal_ifc_addr = &dmy_netmask;

		RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REQ_INTERNAL_PREFIX_LEN_INTERNAL_IF_ADDR_NOT_FOUND,"xxxd",vpn,ikesa,rx_req_ikemesg,rlm->internal_ifc->addrs_type);
		RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_CFG_REQ_INTERNAL_IF_NO_SAME_SUBNET_ADDR_USE_DEF,"KAA",rx_req_ikemesg,new_addr,internal_ifc_addr);
	}

	if( internal_ifc_addr == NULL ||
			rhp_netmask_null(internal_ifc_addr) ){

			s_pld_ctx->notify_error = RHP_PROTO_IKE_NOTIFY_ERR_INTERNAL_ADDRESS_FAILURE;

			RHP_LOG_E(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_CFG_REQ_NO_INTERNAL_IF_NETMASK,"KLL",rx_req_ikemesg,"VIF_ADDR",rlm->internal_ifc->addrs_type,"PROTO_IKE_NOTIFY",(int)(s_pld_ctx->notify_error));

			if( new_addr->addr_family == AF_INET ){
				RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REQ_INTERNAL_PREFIX_LEN_NO_INTERNAL_IF_ADDR_NETMASK,"xxx4",vpn,ikesa,rx_req_ikemesg,(internal_ifc_addr ? internal_ifc_addr->netmask.v4 : 0));
			}else if( new_addr->addr_family == AF_INET6 ){
				RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REQ_INTERNAL_PREFIX_LEN_NO_INTERNAL_IF_ADDR_NETMASK_V6,"xxx6",vpn,ikesa,rx_req_ikemesg,(internal_ifc_addr ? internal_ifc_addr->netmask.v6 : 0));
			}

			goto error;
	}


	if( internal_ifc_addr->prefixlen ){

		*prefix_len_r = internal_ifc_addr->prefixlen;

		if( internal_ifc_addr->addr_family == AF_INET ){
			RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_CFG_REQ_INTERNAL_IPV4_PREFIX_LEN,"Kd",rx_req_ikemesg,*prefix_len_r);
		}else if( internal_ifc_addr->addr_family == AF_INET6 ){
			RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_CFG_REQ_INTERNAL_IPV6_PREFIX_LEN,"Kd",rx_req_ikemesg,*prefix_len_r);
		}

	}else if( internal_ifc_addr->addr_family == AF_INET ){

		*prefix_len_r = rhp_ipv4_netmask_to_prefixlen(internal_ifc_addr->netmask.v4);

		RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_CFG_REQ_INTERNAL_IPV4_SUBNET_ADDRESS,"K4d",rx_req_ikemesg,internal_ifc_addr->netmask.v4,*prefix_len_r);

	}else if( internal_ifc_addr->addr_family == AF_INET6 ){

		*prefix_len_r = rhp_ipv6_netmask_to_prefixlen(internal_ifc_addr->netmask.v6);

		RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_CFG_REQ_INTERNAL_IPV6_SUBNET_ADDRESS,"K6d",rx_req_ikemesg,internal_ifc_addr->netmask.v6,*prefix_len_r);

	}else{
		RHP_BUG("");
		err = -EINVAL;
		goto error;
	}

	RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REQ_INTERNAL_PREFIX_LEN_RTRN,"xxb",vpn,rx_req_ikemesg,*prefix_len_r);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REQ_INTERNAL_PREFIX_LEN_ERR,"xxE",vpn,rx_req_ikemesg,err);
	return err;
}


static int _rhp_ikev2_rx_cfg_req_clear_internal_net_info(rhp_vpn* vpn,rhp_ikesa* ikesa,
		int addr_family,rhp_ip_addr* old_peer_addr_r,u8* old_target_mac_r)
{
	rhp_ip_addr_list *peer_addr, *peer_addr_p = NULL,*peer_addr_n;

	RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REQ_CLEAR_INTERNAL_NET_INFO,"xxLdxxx",vpn,ikesa,"AF",addr_family,old_peer_addr_r,old_target_mac_r,vpn->internal_net_info.peer_addrs);

	peer_addr = vpn->internal_net_info.peer_addrs;
	while( peer_addr ){

		peer_addr_n = peer_addr->next;

		if( addr_family == peer_addr->ip_addr.addr_family &&
				peer_addr->ip_addr.tag == RHP_IPADDR_TAG_IKEV2_CFG_ASSIGNED ){

			rhp_ip_addr_dump("clear_internal_net_info.old_addr",&(peer_addr->ip_addr));

			memcpy(old_peer_addr_r,&(peer_addr->ip_addr),sizeof(rhp_ip_addr));

			if( peer_addr_p ){
				peer_addr_p->next = peer_addr_n;
			}else{
				vpn->internal_net_info.peer_addrs = peer_addr_n;
			}

			rhp_vpn_delete_by_peer_internal_addr(&(peer_addr->ip_addr),vpn);

			if( rhp_bridge_static_neigh_cache_delete(vpn->vpn_realm_id,
						&(peer_addr->ip_addr),vpn,old_target_mac_r) ){

				RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REQ_CLEAR_INTERNAL_NET_INFO_NO_CUR_ADDR_NEIGH_CACHE,"xx",vpn,ikesa);
			}

			_rhp_free(peer_addr);

		}else{

			rhp_ip_addr_dump("clear_internal_net_info.ignored",&(peer_addr->ip_addr));

			peer_addr_p = peer_addr;
		}

		peer_addr = peer_addr_n;
	}

	rhp_ip_addr_dump("old_peer_addr_r",old_peer_addr_r);
	RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REQ_CLEAR_INTERNAL_NET_INFO_RTRN,"xxM",vpn,ikesa,old_target_mac_r);
	return 0;
}

static int _rhp_ikev2_rx_cfg_req_update_internal_net_info(
		rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_ip_addr* new_addr)
{
	int err = -EINVAL;
	int cur_addr_flag = 0;
	rhp_ip_addr_list* new_peer_addrl = NULL;

	RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REQ_UPDATE_INTERNAL_NET_INFO,"xxx",vpn,ikesa,new_addr);
	rhp_ip_addr_dump("update_internal_net_info.new_addr",new_addr);

	if( new_addr->tag != RHP_IPADDR_TAG_IKEV2_CFG_ASSIGNED ){
		RHP_BUG("%d",new_addr->tag);
		return -EINVAL;
	}

	if( new_addr->addr_family != AF_INET && new_addr->addr_family != AF_INET6 ){
		RHP_BUG("%d",new_addr->addr_family);
		return -EINVAL;
	}


	cur_addr_flag
	= (rhp_ip_addr_list_included(vpn->internal_net_info.peer_addrs,new_addr,1) != NULL ? 1 : 0);

	if( !cur_addr_flag ){

		u8 old_target_mac[6];
		rhp_ip_addr old_peer_addr;

		RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REQ_UPDATE_INTERNAL_NET_INFO_CUR_DIFF_ADDR,"xxx",vpn,ikesa,new_addr);

		memset(old_target_mac,0,6);
		memset(&old_peer_addr,0,sizeof(rhp_ip_addr));

		new_peer_addrl = (rhp_ip_addr_list*)_rhp_malloc(sizeof(rhp_ip_addr_list));
		if( new_peer_addrl == NULL ){
			RHP_BUG("");
			err = -EINVAL;
			goto error;
		}

		memset(new_peer_addrl,0,sizeof(rhp_ip_addr_list));


		err = _rhp_ikev2_rx_cfg_req_clear_internal_net_info(vpn,ikesa,new_addr->addr_family,
					&old_peer_addr,old_target_mac);
		if( err ){
			RHP_BUG("%d",err);
			goto error;
		}


		err = rhp_vpn_put_by_peer_internal_addr(new_addr,vpn);
		if( err ){
			RHP_BUG("%d",err);
			goto error;
		}

		{
			memcpy(&(new_peer_addrl->ip_addr),new_addr,sizeof(rhp_ip_addr));

			if( !_rhp_mac_addr_null(old_target_mac) &&
					!rhp_ip_addr_null(&old_peer_addr) ){

				err = rhp_bridge_static_neigh_cache_update_for_vpn(vpn,&old_peer_addr,
								&(new_peer_addrl->ip_addr),old_target_mac,RHP_BRIDGE_SCACHE_IKEV2_CFG);

				if( err ){
					RHP_BUG("%d",err); // Ignored...
					err = 0;
				}
			}

			new_peer_addrl->next = vpn->internal_net_info.peer_addrs;
			vpn->internal_net_info.peer_addrs = new_peer_addrl;

			new_peer_addrl = NULL;
		}


		if( new_addr->addr_family == AF_INET ){
			vpn->internal_net_info.peer_addr_v4_cp = RHP_IKEV2_CFG_CP_ADDR_ASSIGNED;
		}else if( new_addr->addr_family == AF_INET6 ){
			vpn->internal_net_info.peer_addr_v6_cp = RHP_IKEV2_CFG_CP_ADDR_ASSIGNED;
		}

		rhp_vpn_internal_route_update(vpn);
	}


	if( new_peer_addrl ){
		_rhp_free(new_peer_addrl);
	}

	RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REQ_UPDATE_INTERNAL_NET_INFO_RTRN,"xxd",vpn,ikesa,cur_addr_flag);
	return 0;

error:
	if( new_peer_addrl ){
		_rhp_free(new_peer_addrl);
	}
	RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REQ_UPDATE_INTERNAL_NET_INFO_ERR,"xxdE",vpn,ikesa,cur_addr_flag,err);
	return err;
}

static int _rhp_ikev2_rx_cfg_req_internal_addr_radius(rhp_vpn* vpn,rhp_ikev2_mesg* rx_req_ikemesg,
		rhp_ip_addr* new_addr_v4_r,rhp_ip_addr* new_addr_v6_r)
{
	int ok = 0;

	RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REQ_INTERNAL_ADDR_RADIUS,"xxxxLdx",vpn,rx_req_ikemesg,new_addr_v4_r,new_addr_v6_r,"EAP_TYPE",vpn->eap.eap_method,vpn->radius.rx_accept_attrs);

  if( vpn->eap.eap_method == RHP_PROTO_EAP_TYPE_PRIV_RADIUS &&
  		vpn->radius.rx_accept_attrs ){

		RHP_LOCK(&rhp_eap_radius_cfg_lock);

  	if( new_addr_v4_r ){

			if( (rhp_eap_radius_rx_attr_enabled(rhp_gcfg_eap_radius->rx_internal_addr_ipv4,0,0) ||
					 rhp_eap_radius_rx_attr_enabled(rhp_gcfg_eap_radius->rx_common_priv_attr,0,0)) &&
					!rhp_ip_addr_null(&(vpn->radius.rx_accept_attrs->priv_internal_addr_ipv4)) ){

  			memcpy(new_addr_v4_r,&(vpn->radius.rx_accept_attrs->priv_internal_addr_ipv4),sizeof(rhp_ip_addr));
  			new_addr_v4_r->tag = RHP_IPADDR_TAG_IKEV2_CFG_ASSIGNED;
				RHP_VPN_RADIUS_ATTRS_MASK_SET(vpn,RHP_VPN_RADIUS_ATTRS_MASK_PRIV_ITNL_IPV4);

  			rhp_ip_addr_dump("new_addr_v4_r:priv_internal_addr_ipv4",new_addr_v4_r);
  			RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_CFG_REQ_INTERNAL_IPV4_ADDRESS_BY_RADIUS_PRIV_INTERNAL_ADDR_ATTR,"K4",rx_req_ikemesg,new_addr_v4_r->addr.v4);

  		}else if( rhp_eap_radius_rx_attr_enabled(RHP_RADIUS_ATTR_TYPE_FRAMED_IP_ADDRESS,0,0) &&
  							!rhp_ip_addr_null(&(vpn->radius.rx_accept_attrs->framed_ipv4)) ){

  			memcpy(new_addr_v4_r,&(vpn->radius.rx_accept_attrs->framed_ipv4),sizeof(rhp_ip_addr));
  			new_addr_v4_r->tag = RHP_IPADDR_TAG_IKEV2_CFG_ASSIGNED;
				RHP_VPN_RADIUS_ATTRS_MASK_SET(vpn,RHP_VPN_RADIUS_ATTRS_MASK_FRAMED_IP_V4);

  			rhp_ip_addr_dump("new_addr_v4_r:framed_ipv4",new_addr_v4_r);
  			RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_CFG_REQ_INTERNAL_IPV4_ADDRESS_BY_RADIUS_FRAMED_IPV4_ATTR,"K4",rx_req_ikemesg,new_addr_v4_r->addr.v4);
			}
  		ok++;
  	}

  	if( new_addr_v6_r ){

  		if( (rhp_eap_radius_rx_attr_enabled(rhp_gcfg_eap_radius->rx_internal_addr_ipv6,0,0) ||
  				 rhp_eap_radius_rx_attr_enabled(rhp_gcfg_eap_radius->rx_common_priv_attr,0,0)) &&
					!rhp_ip_addr_null(&(vpn->radius.rx_accept_attrs->priv_internal_addr_ipv6)) ){

  			memcpy(new_addr_v6_r,&(vpn->radius.rx_accept_attrs->priv_internal_addr_ipv6),sizeof(rhp_ip_addr));
  			new_addr_v6_r->tag = RHP_IPADDR_TAG_IKEV2_CFG_ASSIGNED;
				RHP_VPN_RADIUS_ATTRS_MASK_SET(vpn,RHP_VPN_RADIUS_ATTRS_MASK_PRIV_ITNL_IPV6);

  			rhp_ip_addr_dump("new_addr_v6_r:priv_internal_addr_ipv6",new_addr_v6_r);
  			RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_CFG_REQ_INTERNAL_IPV6_ADDRESS_BY_RADIUS_PRIV_INTERNAL_ADDR_ATTR,"K6",rx_req_ikemesg,new_addr_v6_r->addr.v6);

  		}else if( rhp_eap_radius_rx_attr_enabled(RHP_RADIUS_ATTR_TYPE_FRAMED_IPV6_ADDRESS,0,0) &&
								!rhp_ip_addr_null(&(vpn->radius.rx_accept_attrs->framed_ipv6)) ){

  			memcpy(new_addr_v6_r,&(vpn->radius.rx_accept_attrs->framed_ipv6),sizeof(rhp_ip_addr));
  			new_addr_v6_r->tag = RHP_IPADDR_TAG_IKEV2_CFG_ASSIGNED;
				RHP_VPN_RADIUS_ATTRS_MASK_SET(vpn,RHP_VPN_RADIUS_ATTRS_MASK_FRAMED_IP_V6);

  			rhp_ip_addr_dump("new_addr_v6_r:framed_ipv6",new_addr_v6_r);
  			RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_CFG_REQ_INTERNAL_IPV6_ADDRESS_BY_RADIUS_FRAMED_IPV6_ATTR,"K6",rx_req_ikemesg,new_addr_v6_r->addr.v6);
  		}
  		ok++;
  	}

		RHP_UNLOCK(&rhp_eap_radius_cfg_lock);
  }

	RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REQ_INTERNAL_ADDR_RADIUS_RTRN,"xxxxLdxd",vpn,rx_req_ikemesg,new_addr_v4_r,new_addr_v6_r,"EAP_TYPE",vpn->eap.eap_method,vpn->radius.rx_accept_attrs,ok);
  return (ok ? 0 : -ENOENT);
}

int rhp_ikev2_rx_cfg_req_internal_addr(
		rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_ikev2_mesg* rx_req_ikemesg,
		rhp_cp_req_srch_pld_ctx* s_pld_ctx,
		rhp_vpn_realm* rlm,rhp_ikev2_payload* ikepayload)
{
	int err = -EINVAL;
	rhp_ip_addr new_addr_local_v4, new_addr_local_v6;
	rhp_ip_addr new_addr_radius_v4, new_addr_radius_v6;
	rhp_ip_addr *new_addr_v4_p = NULL, *new_addr_v6_p = NULL;
	rhp_ip_addr *cur_addr_v4_p = NULL, *cur_addr_v6_p = NULL;
	u8 prefix_len = 0;
	u8 tx_pld_id = ikepayload->get_payload_id(ikepayload);
	int v1_add_expired = 0;

	RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REQ_INTERNAL_ADDR,"xxxxxxdddd",vpn,ikesa,rx_req_ikemesg,s_pld_ctx,rlm,ikepayload,s_pld_ctx->internal_netmask_flag,s_pld_ctx->internal_addr_flag,s_pld_ctx->internal_addr_v6_flag,vpn->internal_net_info.peer_exec_ipv6_autoconf);

	memset(&new_addr_local_v4,0,sizeof(rhp_ip_addr));
	memset(&new_addr_local_v6,0,sizeof(rhp_ip_addr));
	memset(&new_addr_radius_v4,0,sizeof(rhp_ip_addr));
	memset(&new_addr_radius_v4,0,sizeof(rhp_ip_addr));


	err = _rhp_ikev2_rx_cfg_req_internal_addr_radius(vpn,rx_req_ikemesg,&new_addr_radius_v4,&new_addr_radius_v6);
	if( err && err != -ENOENT ){
		goto error;
	}
	err = 0;


  if( s_pld_ctx->internal_addr_flag ){

  	vpn->internal_net_info.peer_addr_v4_cp = RHP_IKEV2_CFG_CP_ADDR_REQUESTED;

  	if( rhp_ip_addr_null(&new_addr_radius_v4) ){

  		new_addr_v4_p = &new_addr_local_v4;
  		cur_addr_v4_p = &(s_pld_ctx->internal_addr);
  	}
  }
	rhp_ip_addr_dump("req_internal_addr.cur_addr_v4_p",cur_addr_v4_p);

  if( s_pld_ctx->internal_addr_v6_flag ){

  	vpn->internal_net_info.peer_addr_v6_cp = RHP_IKEV2_CFG_CP_ADDR_REQUESTED;

  	if( rhp_ip_addr_null(&new_addr_radius_v6) &&
  			!vpn->internal_net_info.peer_exec_ipv6_autoconf ){

  		new_addr_v6_p = &new_addr_local_v6;
  		cur_addr_v6_p = &(s_pld_ctx->internal_addr_v6);
  	}
  }
	rhp_ip_addr_dump("req_internal_addr.cur_addr_v6_p",cur_addr_v6_p);


	if( new_addr_v4_p || new_addr_v6_p ){

		err = rhp_vpn_internal_address_assign(vpn,rlm,
					cur_addr_v4_p,cur_addr_v6_p,new_addr_v4_p,new_addr_v6_p);

		if( err ){

			if( new_addr_v4_p && new_addr_v6_p ){

				s_pld_ctx->notify_error = RHP_PROTO_IKE_NOTIFY_ERR_INTERNAL_ADDRESS_FAILURE;

				RHP_LOG_E(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_CFG_REQ_ASSIGN_INTERNAL_ADDR_FAILED,"KLE",rx_req_ikemesg,"PROTO_IKE_NOTIFY",(int)(s_pld_ctx->notify_error),err);
				goto error;
			}

			err = 0;
		}
	}

	if( s_pld_ctx->internal_addr_flag &&
			!rhp_ip_addr_null(&new_addr_radius_v4) ){

		new_addr_v4_p = &new_addr_radius_v4;
	}
	if( s_pld_ctx->internal_addr_v6_flag &&
			!rhp_ip_addr_null(&new_addr_radius_v6) ){

		new_addr_v6_p = &new_addr_radius_v6;
	}


	if( new_addr_v4_p ){

		if( !rhp_ip_addr_null(new_addr_v4_p) ){

			u32 netmask_v4 = 0;

			if( s_pld_ctx->internal_netmask_flag ){

				err = _rhp_ikev2_rx_cfg_req_internal_prefix_len(vpn,ikesa,rx_req_ikemesg,
								s_pld_ctx,rlm,new_addr_v4_p,&prefix_len);
				if( err ){
					goto error;
				}

				netmask_v4 = rhp_ipv4_prefixlen_to_netmask(prefix_len);
			}

			if( tx_pld_id == RHP_PROTO_IKE_PAYLOAD_CP ){

				err = ikepayload->ext.cp->alloc_and_put_attr(ikepayload,
								RHP_PROTO_IKE_CFG_ATTR_INTERNAL_IP4_ADDRESS,
								sizeof(u32),(u8*)&(new_addr_v4_p->addr.v4));

			}else if( tx_pld_id == RHP_PROTO_IKEV1_PAYLOAD_ATTR ){

				err = ikepayload->ext.v1_attr->alloc_and_put_attr(ikepayload,
								RHP_PROTO_IKEV1_CFG_ATTR_INTERNAL_IP4_ADDRESS,
								sizeof(u32),(u8*)&(new_addr_v4_p->addr.v4));

			}else{
				RHP_BUG("%d",tx_pld_id);
				err = -EINVAL;
			}
			if( err ){
				RHP_BUG("%d",err);
				goto error;
			}

			if( netmask_v4 ){

				if( tx_pld_id == RHP_PROTO_IKE_PAYLOAD_CP ){

					err = ikepayload->ext.cp->alloc_and_put_attr(ikepayload,
									RHP_PROTO_IKE_CFG_ATTR_INTERNAL_IP4_NETMASK,
									sizeof(u32),(u8*)&netmask_v4);

				}else if( tx_pld_id == RHP_PROTO_IKEV1_PAYLOAD_ATTR ){

					err = ikepayload->ext.v1_attr->alloc_and_put_attr(ikepayload,
									RHP_PROTO_IKEV1_CFG_ATTR_INTERNAL_IP4_NETMASK,
									sizeof(u32),(u8*)&netmask_v4);

				}else{
					RHP_BUG("%d",tx_pld_id);
					err = -EINVAL;
				}
				if( err ){
					RHP_BUG("%d",err);
					goto error;
				}
			}

			if( !v1_add_expired && tx_pld_id == RHP_PROTO_IKEV1_PAYLOAD_ATTR ){

				u32 expire = htonl((u32)rhp_gcfg_ikev1_mode_cfg_addr_expiry);

				err = ikepayload->ext.v1_attr->alloc_and_put_attr(ikepayload,
								RHP_PROTO_IKEV1_CFG_ATTR_INTERNAL_ADDRESS_EXPIRY,
								sizeof(u32),(u8*)&expire);
				if( err ){
					RHP_BUG("%d",err);
					goto error;
				}

				v1_add_expired = 1;
			}


			vpn->internal_net_info.peer_addr_v4_cp = RHP_IKEV2_CFG_CP_ADDR_ASSIGNED;

			_rhp_ikev2_rx_cfg_req_update_internal_net_info(vpn,ikesa,new_addr_v4_p);

			if( new_addr_v4_p != &new_addr_radius_v4 ){
				RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_CFG_REQ_INTERNAL_IPV4_ADDRESS,"K4",rx_req_ikemesg,new_addr_v4_p->addr.v4);
			}
			RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REQ_INTERNAL_ADDR_ASSIGNED_IPV4_ADDR,"xxx4",vpn,ikesa,rx_req_ikemesg,new_addr_v4_p->addr.v4);

		}else{

			RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_CFG_REQ_INTERNAL_IPV4_ADDRESS_NOT_ASSIGNED,"K",rx_req_ikemesg);
			RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REQ_INTERNAL_ADDR_NOT_ASSIGNED_IPV4_ADDR,"xxx",vpn,ikesa,rx_req_ikemesg);
		}
	}


	if( new_addr_v6_p ){

		if( !rhp_ip_addr_null(new_addr_v6_p) ){

			u8 tx_buf[17];

			err = _rhp_ikev2_rx_cfg_req_internal_prefix_len(vpn,ikesa,rx_req_ikemesg,
									s_pld_ctx,rlm,new_addr_v6_p,&prefix_len);
			if( err ){
				goto error;
			}

			memcpy(tx_buf,new_addr_v6_p->addr.v6,16);
			tx_buf[16] = prefix_len;

			if( tx_pld_id == RHP_PROTO_IKE_PAYLOAD_CP ){

				err = ikepayload->ext.cp->alloc_and_put_attr(ikepayload,
								RHP_PROTO_IKE_CFG_ATTR_INTERNAL_IP6_ADDRESS,17,tx_buf);

			}else if( tx_pld_id == RHP_PROTO_IKEV1_PAYLOAD_ATTR ){

				u8 v1_tx_netmask_v1[16];

				rhp_ipv6_prefixlen_to_netmask(prefix_len,v1_tx_netmask_v1);

				err = ikepayload->ext.v1_attr->alloc_and_put_attr(ikepayload,
								RHP_PROTO_IKEV1_CFG_ATTR_INTERNAL_IP6_ADDRESS,16,tx_buf);

				if( err ){
					RHP_BUG("%d",err);
					goto error;
				}

				err = ikepayload->ext.v1_attr->alloc_and_put_attr(ikepayload,
								RHP_PROTO_IKEV1_CFG_ATTR_INTERNAL_IP6_NETMASK,16,v1_tx_netmask_v1);


			}else{
				RHP_BUG("%d",tx_pld_id);
				err = -EINVAL;
			}
			if( err ){
				RHP_BUG("%d",err);
				goto error;
			}

			if( !v1_add_expired && tx_pld_id == RHP_PROTO_IKEV1_PAYLOAD_ATTR ){

				u32 expire = htonl((u32)rhp_gcfg_ikev1_mode_cfg_addr_expiry);

				err = ikepayload->ext.v1_attr->alloc_and_put_attr(ikepayload,
								RHP_PROTO_IKEV1_CFG_ATTR_INTERNAL_ADDRESS_EXPIRY,
								sizeof(u32),(u8*)&expire);
				if( err ){
					RHP_BUG("%d",err);
					goto error;
				}

				v1_add_expired = 1;
			}


			vpn->internal_net_info.peer_addr_v6_cp = RHP_IKEV2_CFG_CP_ADDR_ASSIGNED;

			_rhp_ikev2_rx_cfg_req_update_internal_net_info(vpn,ikesa,new_addr_v6_p);

			if( new_addr_v6_p != &new_addr_radius_v6 ){
				RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_CFG_REQ_INTERNAL_IPV6_ADDRESS,"K6",rx_req_ikemesg,new_addr_v6_p->addr.v6,(new_addr_v6_p == &new_addr_radius_v6 ? 1 : 0));
			}
			RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REQ_INTERNAL_ADDR_ASSIGNED_IPV6_ADDR,"xxx6",vpn,ikesa,rx_req_ikemesg,new_addr_v6_p->addr.v6);

		}else{

			RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_CFG_REQ_INTERNAL_IPV6_ADDRESS_NOT_ASSIGNED,"K",rx_req_ikemesg);
			RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REQ_INTERNAL_ADDR_NOT_ASSIGNED_IPV6_ADDR,"xxx",vpn,ikesa,rx_req_ikemesg);
		}
	}

	RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REQ_INTERNAL_ADDR_RTRN,"xxx",vpn,ikesa,rx_req_ikemesg);
  return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REQ_INTERNAL_ADDR_ERR,"xxxE",vpn,ikesa,rx_req_ikemesg,err);
	return err;
}

int rhp_ikev2_rx_cfg_req_internal_dns(
			rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_ikev2_mesg* rx_req_ikemesg,
			rhp_cp_req_srch_pld_ctx* s_pld_ctx,
			rhp_vpn_realm* rlm,rhp_ikev2_payload* ikepayload)
{
	int err = -EINVAL;
	rhp_ip_addr* dns_server_addr;
	int ok = 0;
	u8 tx_pld_id = ikepayload->get_payload_id(ikepayload);

	RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REQ_INTERNAL_DNS,"xxxxxxddd",vpn,ikesa,rx_req_ikemesg,s_pld_ctx,rlm,ikepayload,s_pld_ctx->internal_dns_flag,s_pld_ctx->internal_dns_v6_flag,s_pld_ctx->internal_dns_sfx_flag);

  if( s_pld_ctx->internal_dns_flag ){

  	dns_server_addr = &(rlm->config_server.dns_server_addr);
  	rhp_ip_addr_dump("internal_dns.dns_server_addr",dns_server_addr);


    if( rhp_ip_addr_null(dns_server_addr) ){

			if( vpn->eap.eap_method == RHP_PROTO_EAP_TYPE_PRIV_RADIUS &&
					vpn->radius.rx_accept_attrs ){

				RHP_LOCK(&rhp_eap_radius_cfg_lock);

				if( rhp_eap_radius_rx_attr_enabled(rhp_gcfg_eap_radius->rx_internal_dns_v4_attr_type,0,0) &&
						!rhp_ip_addr_null(&(vpn->radius.rx_accept_attrs->priv_internal_dns_server_ipv4)) ){

					dns_server_addr = &(vpn->radius.rx_accept_attrs->priv_internal_dns_server_ipv4);
					RHP_VPN_RADIUS_ATTRS_MASK_SET(vpn,RHP_VPN_RADIUS_ATTRS_MASK_PRIV_ITNL_DNS_V4);

					RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_CFG_REQ_INTERNAL_IPV4_DNS_SERVER_BY_RADIUS_PRIV_DNS_SERVER_ATTR,"K4",rx_req_ikemesg,dns_server_addr->addr.v4);

				}else if( rhp_eap_radius_rx_attr_enabled(RHP_RADIUS_ATTR_TYPE_VENDOR_SPECIFIC,
																								 RHP_RADIUS_ATTR_TYPE_VENDOR_SPECIFIC_MICROSOFT,
																								 RHP_RADIUS_VENDOR_MS_ATTR_TYPE_PRIMARY_DNS_SERVER) &&
									!rhp_ip_addr_null(&(vpn->radius.rx_accept_attrs->ms_primary_dns_server_ipv4)) ){

					dns_server_addr = &(vpn->radius.rx_accept_attrs->ms_primary_dns_server_ipv4);
					RHP_VPN_RADIUS_ATTRS_MASK_SET(vpn,RHP_VPN_RADIUS_ATTRS_MASK_MS_PRIMARY_DNS_SERVER_V4);

					RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_CFG_REQ_INTERNAL_IPV4_DNS_SERVER_BY_RADIUS_MS_PRIMARY_DNS_SERVER_ATTR,"K4",rx_req_ikemesg,dns_server_addr->addr.v4);
				}

				RHP_UNLOCK(&rhp_eap_radius_cfg_lock);
			}

    }else{

			RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REQ_INTERNAL_DNS_INTERNAL_DNS_SERVER_V4,"xxx4",vpn,ikesa,rx_req_ikemesg,dns_server_addr->addr.v4);
    }


		if( rhp_ip_addr_null(dns_server_addr) ){

			RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_CFG_REQ_NO_INTERNAL_DNS_SERVER,"K",rx_req_ikemesg);
			RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REQ_INTERNAL_DNS_NO_INTERNAL_DNS_SERVER_V4,"xxx",vpn,ikesa,rx_req_ikemesg);

		}else{

			if( tx_pld_id == RHP_PROTO_IKE_PAYLOAD_CP ){

				err = ikepayload->ext.cp->alloc_and_put_attr(ikepayload,
								RHP_PROTO_IKE_CFG_ATTR_INTERNAL_IP4_DNS,
								sizeof(u32),(u8*)&(dns_server_addr->addr.v4));

			}else if( tx_pld_id == RHP_PROTO_IKEV1_PAYLOAD_ATTR ){

				err = ikepayload->ext.v1_attr->alloc_and_put_attr(ikepayload,
								RHP_PROTO_IKEV1_CFG_ATTR_INTERNAL_IP4_DNS,
								sizeof(u32),(u8*)&(dns_server_addr->addr.v4));

			}else{
				RHP_BUG("%d",tx_pld_id);
				err = -EINVAL;
			}
			if( err ){
				RHP_BUG("%d",err);
				goto error;
			}

			RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_CFG_REQ_INTERNAL_IPV4_DNS_SERVER,"K4",rx_req_ikemesg,dns_server_addr->addr.v4);

			ok++;
		}
  }

  if( s_pld_ctx->internal_dns_v6_flag ){

  	dns_server_addr = &(rlm->config_server.dns_server_addr_v6);
  	rhp_ip_addr_dump("internal_dns.dns_server_addr_v6",dns_server_addr);


    if( rhp_ip_addr_null(dns_server_addr) ){

			if( vpn->eap.eap_method == RHP_PROTO_EAP_TYPE_PRIV_RADIUS &&
					vpn->radius.rx_accept_attrs ){

				RHP_LOCK(&rhp_eap_radius_cfg_lock);

				if( rhp_eap_radius_rx_attr_enabled(rhp_gcfg_eap_radius->rx_internal_dns_v6_attr_type,0,0) &&
						!rhp_ip_addr_null(&(vpn->radius.rx_accept_attrs->priv_internal_dns_server_ipv6)) ){

					dns_server_addr = &(vpn->radius.rx_accept_attrs->priv_internal_dns_server_ipv6);
					RHP_VPN_RADIUS_ATTRS_MASK_SET(vpn,RHP_VPN_RADIUS_ATTRS_MASK_PRIV_ITNL_DNS_V6);

					RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_CFG_REQ_INTERNAL_IPV6_DNS_SERVER_BY_RADIUS_PRIV_DNS_SERVER_ATTR,"K6",rx_req_ikemesg,dns_server_addr->addr.v6);

				}else if( rhp_eap_radius_rx_attr_enabled(RHP_RADIUS_ATTR_TYPE_DNS_IPV6_ADDRESS,0,0) &&
									!rhp_ip_addr_null(&(vpn->radius.rx_accept_attrs->dns_server_ipv6)) ){

					dns_server_addr = &(vpn->radius.rx_accept_attrs->dns_server_ipv6);
					RHP_VPN_RADIUS_ATTRS_MASK_SET(vpn,RHP_VPN_RADIUS_ATTRS_MASK_DNS_IPV6_SERVER);

					RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_CFG_REQ_INTERNAL_IPV6_DNS_SERVER_BY_RADIUS_DNS_IPV6_SERVER_ATTR,"K6",rx_req_ikemesg,dns_server_addr->addr.v6);
				}

				RHP_UNLOCK(&rhp_eap_radius_cfg_lock);
			}

    }else{

			RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_CFG_REQ_INTERNAL_IPV6_DNS_SERVER,"K6",rx_req_ikemesg,dns_server_addr->addr.v6);
    }


    if( rhp_ip_addr_null(dns_server_addr) ){

			RHP_LOG_D(RHP_LOG_SRC_IKEV2,0,RHP_LOG_ID_RX_CFG_REQ_NO_INTERNAL_DNS_SERVER_V6,"K",rx_req_ikemesg);
			RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REQ_INTERNAL_DNS_NO_INTERNAL_DNS_SERVER_V6,"xxx",vpn,ikesa,rx_req_ikemesg);

		}else{

			if( tx_pld_id == RHP_PROTO_IKE_PAYLOAD_CP ){

				err = ikepayload->ext.cp->alloc_and_put_attr(ikepayload,
								RHP_PROTO_IKE_CFG_ATTR_INTERNAL_IP6_DNS,
								16,dns_server_addr->addr.v6);

			}else if( tx_pld_id == RHP_PROTO_IKEV1_PAYLOAD_ATTR ){

				err = ikepayload->ext.v1_attr->alloc_and_put_attr(ikepayload,
								RHP_PROTO_IKEV1_CFG_ATTR_INTERNAL_IP6_DNS,
								16,dns_server_addr->addr.v6);

			}else{
				RHP_BUG("%d",tx_pld_id);
				err = -EINVAL;
			}
			if( err ){
				RHP_BUG("%d",err);
				goto error;
			}

			RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REQ_INTERNAL_DNS_INTERNAL_DNS_SERVER_V6,"xxx6",vpn,ikesa,rx_req_ikemesg,dns_server_addr->addr.v6);

			ok++;
		}
  }

	if( ok && s_pld_ctx->internal_dns_sfx_flag ){

		rhp_split_dns_domain* domain = rlm->config_server.domains;
		int by_radius = 0;

		if( domain == NULL ){

			RHP_LOCK(&rhp_eap_radius_cfg_lock);

			if( vpn->eap.eap_method == RHP_PROTO_EAP_TYPE_PRIV_RADIUS &&
					vpn->radius.rx_accept_attrs &&
					rhp_eap_radius_rx_attr_enabled(rhp_gcfg_eap_radius->rx_internal_domain_names_attr_type,0,0) ){

				domain = vpn->radius.rx_accept_attrs->priv_domain_names;
				RHP_VPN_RADIUS_ATTRS_MASK_SET(vpn,RHP_VPN_RADIUS_ATTRS_MASK_PRIV_ITNL_DOMAINS);

				by_radius = 1;
			}

			RHP_UNLOCK(&rhp_eap_radius_cfg_lock);
		}

		while( domain ){

			if( tx_pld_id == RHP_PROTO_IKE_PAYLOAD_CP ){

				err = ikepayload->ext.cp->alloc_and_put_attr(ikepayload,
								RHP_PROTO_IKE_CFG_ATTR_RHP_DNS_SFX,strlen(domain->name),(u8*)domain->name);

			}else if( tx_pld_id == RHP_PROTO_IKEV1_PAYLOAD_ATTR ){

				err = ikepayload->ext.v1_attr->alloc_and_put_attr(ikepayload,
								RHP_PROTO_IKE_CFG_ATTR_RHP_DNS_SFX,strlen(domain->name),(u8*)domain->name);

			}else{
				RHP_BUG("%d",tx_pld_id);
				err = -EINVAL;
			}
			if( err ){
				RHP_BUG("%d",err);
				goto error;
			}

			if( !by_radius ){
				RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_CFG_REQ_INTERNAL_DNS_SUFFIX,"Ks",rx_req_ikemesg,domain->name);
			}else{
				RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_CFG_REQ_INTERNAL_DNS_SUFFIX_BY_RADIUS_PRIV_DOMAIN_NAME_ATTR,"Ks",rx_req_ikemesg,domain->name);
			}
			RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REQ_INTERNAL_DNS_SUFFIX,"xxxs",vpn,ikesa,rx_req_ikemesg,domain->name);

			domain = domain->next;
		}
	}

	RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REQ_INTERNAL_DNS_RTRN,"xxxd",vpn,ikesa,rx_req_ikemesg,ok);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REQ_INTERNAL_DNS_ERR,"xxxdE",vpn,ikesa,rx_req_ikemesg,ok,err);
	return err;
}

int rhp_ikev2_rx_cfg_req_internal_subnets(
			rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_ikev2_mesg* rx_req_ikemesg,
			rhp_cp_req_srch_pld_ctx* s_pld_ctx,
			rhp_vpn_realm* rlm,rhp_ikev2_payload* ikepayload)
{
	int err = -EINVAL;
	rhp_internal_route_map* rt_map;
	rhp_ip_addr* gw_addr;
	int by_radius;
	u8 tx_pld_id = ikepayload->get_payload_id(ikepayload);

	RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REQ_INTERNAL_SUBNETS,"xxxxxxdddd",vpn,ikesa,rx_req_ikemesg,s_pld_ctx,rlm,ikepayload,s_pld_ctx->internal_subnet_flag,s_pld_ctx->internal_subnet_v6_flag,s_pld_ctx->internal_gateway_flag,s_pld_ctx->internal_gateway_v6_flag);

	if( s_pld_ctx->internal_subnet_flag ){

		rt_map = rlm->config_server.rt_maps;
		by_radius = 0;

		if( rt_map == NULL ){

			RHP_LOCK(&rhp_eap_radius_cfg_lock);

			if( vpn->eap.eap_method == RHP_PROTO_EAP_TYPE_PRIV_RADIUS &&
					vpn->radius.rx_accept_attrs &&
					rhp_eap_radius_rx_attr_enabled(rhp_gcfg_eap_radius->rx_internal_rt_maps_v4_attr_type,0,0) ){

				rt_map = vpn->radius.rx_accept_attrs->priv_internal_route_ipv4;
				RHP_VPN_RADIUS_ATTRS_MASK_SET(vpn,RHP_VPN_RADIUS_ATTRS_MASK_PRIV_ITNL_RT_MAP_V4);

				by_radius = 1;
			}

			RHP_UNLOCK(&rhp_eap_radius_cfg_lock);
		}

		while( rt_map ){

			u8 data[8];
			memcpy(data,&(rt_map->dest_addr.addr.v4),4);
			memcpy((data + 4),&(rt_map->dest_addr.netmask.v4),4);

			if( tx_pld_id == RHP_PROTO_IKE_PAYLOAD_CP ){

				err = ikepayload->ext.cp->alloc_and_put_attr(ikepayload,
								RHP_PROTO_IKE_CFG_ATTR_INTERNAL_IP4_SUBNET,8,data);

			}else if( tx_pld_id == RHP_PROTO_IKEV1_PAYLOAD_ATTR ){

				err = ikepayload->ext.v1_attr->alloc_and_put_attr(ikepayload,
								RHP_PROTO_IKEV1_CFG_ATTR_INTERNAL_IP4_SUBNET,8,data);

			}else{
				RHP_BUG("%d",tx_pld_id);
				err = -EINVAL;
			}
			if( err ){
				RHP_BUG("%d",err);
				goto error;
			}

			if( !by_radius ){
				RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_CFG_REQ_INTERNAL_IPV4_SUBNET,"K44",rx_req_ikemesg,rt_map->dest_addr.addr.v4,rt_map->dest_addr.netmask.v4);
			}else{
				RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_CFG_REQ_INTERNAL_IPV4_SUBNET_BY_RADIUS_PRIV_INTERNAL_ROUTE_ATTR,"K44",rx_req_ikemesg,rt_map->dest_addr.addr.v4,rt_map->dest_addr.netmask.v4);
			}
			RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REQ_INTERNAL_SUBNETS_SUBNET_V4,"xxx44",vpn,ikesa,rx_req_ikemesg,rt_map->dest_addr.addr.v4,rt_map->dest_addr.netmask.v4);

			rt_map = rt_map->next;
		}

		if( s_pld_ctx->internal_gateway_flag ){

			gw_addr = &(rlm->config_server.gw_addr);
			by_radius = 0;

			if( rhp_ip_addr_null(gw_addr) ){

				RHP_LOCK(&rhp_eap_radius_cfg_lock);

				if( vpn->eap.eap_method == RHP_PROTO_EAP_TYPE_PRIV_RADIUS &&
						vpn->radius.rx_accept_attrs &&
						rhp_eap_radius_rx_attr_enabled(rhp_gcfg_eap_radius->rx_internal_gw_v4_attr_type,0,0) ){

					gw_addr = &(vpn->radius.rx_accept_attrs->priv_internal_gateway_ipv4);
					RHP_VPN_RADIUS_ATTRS_MASK_SET(vpn,RHP_VPN_RADIUS_ATTRS_MASK_PRIV_ITNL_GW_V4);

					by_radius = 1;
				}

				RHP_UNLOCK(&rhp_eap_radius_cfg_lock);
			}

			if( !rhp_ip_addr_null(gw_addr) ){

				if( tx_pld_id == RHP_PROTO_IKE_PAYLOAD_CP ){

					err = ikepayload->ext.cp->alloc_and_put_attr(ikepayload,
									RHP_PROTO_IKE_CFG_ATTR_RHP_IPV4_GATEWAY,
									sizeof(u32),(u8*)&(gw_addr->addr.v4));

				}else if( tx_pld_id == RHP_PROTO_IKEV1_PAYLOAD_ATTR ){

					err = ikepayload->ext.v1_attr->alloc_and_put_attr(ikepayload,
									RHP_PROTO_IKE_CFG_ATTR_RHP_IPV4_GATEWAY,
									sizeof(u32),(u8*)&(gw_addr->addr.v4));

				}else{
					RHP_BUG("%d",tx_pld_id);
					err = -EINVAL;
				}
				if( err ){
					RHP_BUG("%d",err);
					goto error;
				}

				if( !by_radius ){
					RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_CFG_REQ_INTERNAL_IPV4_GATEWAY,"K4",rx_req_ikemesg,gw_addr->addr.v4);
				}else{
					RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_CFG_REQ_INTERNAL_IPV4_GATEWAY_BY_RADIUS_PRIV_GATEWAY_ATTR,"K4",rx_req_ikemesg,gw_addr->addr.v4);
				}
				RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REQ_INTERNAL_SUBNETS_GW_V4,"xxx4",vpn,ikesa,rx_req_ikemesg,gw_addr->addr.v4);
			}
		}
	}

	if( s_pld_ctx->internal_subnet_v6_flag ){

		rt_map = rlm->config_server.rt_maps_v6;
		by_radius = 0;

		if( rt_map == NULL ){

			RHP_LOCK(&rhp_eap_radius_cfg_lock);

			if( vpn->eap.eap_method == RHP_PROTO_EAP_TYPE_PRIV_RADIUS &&
					vpn->radius.rx_accept_attrs &&
					rhp_eap_radius_rx_attr_enabled(rhp_gcfg_eap_radius->rx_internal_rt_maps_v6_attr_type,0,0) ){

				rt_map = vpn->radius.rx_accept_attrs->priv_internal_route_ipv6;
				RHP_VPN_RADIUS_ATTRS_MASK_SET(vpn,RHP_VPN_RADIUS_ATTRS_MASK_PRIV_ITNL_RT_MAP_V6);

				by_radius = 1;
			}

			RHP_UNLOCK(&rhp_eap_radius_cfg_lock);
		}

		while( rt_map ){

			u8 data[17];
			memcpy(data,rt_map->dest_addr.addr.v6,16);
			data[16] = rt_map->dest_addr.prefixlen;

			if( tx_pld_id == RHP_PROTO_IKE_PAYLOAD_CP ){

				err = ikepayload->ext.cp->alloc_and_put_attr(ikepayload,
								RHP_PROTO_IKE_CFG_ATTR_INTERNAL_IP6_SUBNET,17,data);

			}else if( tx_pld_id == RHP_PROTO_IKEV1_PAYLOAD_ATTR ){

				err = ikepayload->ext.v1_attr->alloc_and_put_attr(ikepayload,
								RHP_PROTO_IKEV1_CFG_ATTR_INTERNAL_IP6_SUBNET,17,data);

			}else{
				RHP_BUG("%d",tx_pld_id);
				err = -EINVAL;
			}
			if( err ){
				RHP_BUG("%d",err);
				goto error;
			}

			if( !by_radius ){
				RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_CFG_REQ_INTERNAL_IPV6_SUBNET,"K6d",rx_req_ikemesg,rt_map->dest_addr.addr.v6,rt_map->dest_addr.prefixlen);
			}else{
				RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_CFG_REQ_INTERNAL_IPV6_SUBNET_BY_RADIUS_PRIV_INTERNAL_ROUTE_ATTR,"K6d",rx_req_ikemesg,rt_map->dest_addr.addr.v6,rt_map->dest_addr.prefixlen);
			}
			RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REQ_INTERNAL_SUBNETS_SUBNET_V6,"xxx6d",vpn,ikesa,rx_req_ikemesg,rt_map->dest_addr.addr.v6,rt_map->dest_addr.prefixlen);

			rt_map = rt_map->next;
		}

		if( s_pld_ctx->internal_gateway_v6_flag ){

			gw_addr = &(rlm->config_server.gw_addr_v6);
			by_radius = 0;

			if( rhp_ip_addr_null(gw_addr) ){

				RHP_LOCK(&rhp_eap_radius_cfg_lock);

				if( vpn->eap.eap_method == RHP_PROTO_EAP_TYPE_PRIV_RADIUS &&
						vpn->radius.rx_accept_attrs &&
						rhp_eap_radius_rx_attr_enabled(rhp_gcfg_eap_radius->rx_internal_gw_v6_attr_type,0,0) ){

					gw_addr = &(vpn->radius.rx_accept_attrs->priv_internal_gateway_ipv6);
					RHP_VPN_RADIUS_ATTRS_MASK_SET(vpn,RHP_VPN_RADIUS_ATTRS_MASK_PRIV_ITNL_GW_V6);

					by_radius = 1;
				}

				RHP_UNLOCK(&rhp_eap_radius_cfg_lock);
			}

			if( !rhp_ip_addr_null(gw_addr) ){

				if( tx_pld_id == RHP_PROTO_IKE_PAYLOAD_CP ){

					err = ikepayload->ext.cp->alloc_and_put_attr(ikepayload,
									RHP_PROTO_IKE_CFG_ATTR_RHP_IPV6_GATEWAY,
									16,gw_addr->addr.v6);

				}else if( tx_pld_id == RHP_PROTO_IKEV1_PAYLOAD_ATTR ){

					err = ikepayload->ext.v1_attr->alloc_and_put_attr(ikepayload,
									RHP_PROTO_IKE_CFG_ATTR_RHP_IPV6_GATEWAY,
									16,gw_addr->addr.v6);

				}else{
					RHP_BUG("%d",tx_pld_id);
					err = -EINVAL;
				}
				if( err ){
					RHP_BUG("%d",err);
					goto error;
				}

				if( !by_radius ){
					RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_CFG_REQ_INTERNAL_IPV6_GATEWAY,"K6",rx_req_ikemesg,gw_addr->addr.v6);
				}else{
					RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_CFG_REQ_INTERNAL_IPV6_GATEWAY_BY_RADIUS_GATEWAY_ATTR,"K6",rx_req_ikemesg,gw_addr->addr.v6);
				}
				RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REQ_INTERNAL_SUBNETS_GW_V6,"xxx6",vpn,ikesa,rx_req_ikemesg,gw_addr->addr.v6);
			}
		}
	}

	RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REQ_INTERNAL_SUBNETS_RTRN,"xxx",vpn,ikesa,rx_req_ikemesg);
  return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REQ_INTERNAL_SUBNETS_ERR,"xxxE",vpn,ikesa,rx_req_ikemesg,err);
	return err;
}

int rhp_ikev2_rx_cfg_req_internal_wins(
			rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_ikev2_mesg* rx_req_ikemesg,
			rhp_cp_req_srch_pld_ctx* s_pld_ctx,
			rhp_vpn_realm* rlm,rhp_ikev2_payload* ikepayload)
{
	int err = -EINVAL;
	rhp_ip_addr* wins_addr;
	int by_radius;
	u8 tx_pld_id = ikepayload->get_payload_id(ikepayload);

	RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REQ_INTERNAL_WINS,"xxxxxxdd",vpn,ikesa,rx_req_ikemesg,s_pld_ctx,rlm,ikepayload,s_pld_ctx->internal_wins_flag,s_pld_ctx->internal_wins_v6_flag);

	if( s_pld_ctx->internal_wins_flag ){

		wins_addr = &(rlm->config_server.wins_server_addr);
		by_radius = 0;

		if( rhp_ip_addr_null(wins_addr) ){

			if( vpn->eap.eap_method == RHP_PROTO_EAP_TYPE_PRIV_RADIUS &&
					vpn->radius.rx_accept_attrs &&
					rhp_eap_radius_rx_attr_enabled(RHP_RADIUS_ATTR_TYPE_VENDOR_SPECIFIC,
																				 RHP_RADIUS_ATTR_TYPE_VENDOR_SPECIFIC_MICROSOFT,
																				 RHP_RADIUS_VENDOR_MS_ATTR_TYPE_PRIMARY_NBNS_SERVER) ){

				wins_addr = &(vpn->radius.rx_accept_attrs->ms_primary_nbns_server_ipv4);
				RHP_VPN_RADIUS_ATTRS_MASK_SET(vpn,RHP_VPN_RADIUS_ATTRS_MASK_MS_PRIMARY_NBNS_SERVER_V4);

				by_radius = 1;
			}
		}

		if( !rhp_ip_addr_null(wins_addr) ){

			if( tx_pld_id == RHP_PROTO_IKE_PAYLOAD_CP ){

				err = ikepayload->ext.cp->alloc_and_put_attr(ikepayload,
								RHP_PROTO_IKE_CFG_ATTR_INTERNAL_IP4_NBNS,
								sizeof(u32),(u8*)&(wins_addr->addr.v4));

			}else if( tx_pld_id == RHP_PROTO_IKEV1_PAYLOAD_ATTR ){

				err = ikepayload->ext.v1_attr->alloc_and_put_attr(ikepayload,
								RHP_PROTO_IKEV1_CFG_ATTR_INTERNAL_IP4_NBNS,
								sizeof(u32),(u8*)&(wins_addr->addr.v4));

			}else{
				RHP_BUG("%d",tx_pld_id);
				err = -EINVAL;
			}
			if( err ){
				RHP_BUG("%d",err);
				goto error;
			}

			if( !by_radius ){
				RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_CFG_REQ_INTERNAL_IPV4_WINS,"K4",rx_req_ikemesg,wins_addr->addr.v4);
			}else{
				RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_CFG_REQ_INTERNAL_IPV4_WINS_BY_RADIUS_MS_PRIMARY_NBNS_SERVER_ATTR,"K4",rx_req_ikemesg,wins_addr->addr.v4);
			}
			RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REQ_INTERNAL_WINS_V4,"xxx4",vpn,ikesa,rx_req_ikemesg,wins_addr->addr.v4);
		}
	}

	if( s_pld_ctx->internal_wins_v6_flag ){

		wins_addr = &(rlm->config_server.wins_server_addr_v6);

		if( !rhp_ip_addr_null(wins_addr) ){

			if( tx_pld_id == RHP_PROTO_IKE_PAYLOAD_CP ){

				err = ikepayload->ext.cp->alloc_and_put_attr(ikepayload,
								RHP_PROTO_IKE_CFG_ATTR_INTERNAL_IP6_NBNS,
								16,wins_addr->addr.v6);

			}else if( tx_pld_id == RHP_PROTO_IKEV1_PAYLOAD_ATTR ){

				err = ikepayload->ext.v1_attr->alloc_and_put_attr(ikepayload,
								RHP_PROTO_IKEV1_CFG_ATTR_INTERNAL_IP6_NBNS,
								16,wins_addr->addr.v6);

			}else{
				RHP_BUG("%d",tx_pld_id);
				err = -EINVAL;
			}
			if( err ){
				RHP_BUG("%d",err);
				goto error;
			}

			RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_CFG_REQ_INTERNAL_IPV6_WINS,"K6",rx_req_ikemesg,wins_addr->addr.v6);
			RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REQ_INTERNAL_WINS_V6,"xxx6",vpn,ikesa,rx_req_ikemesg,wins_addr->addr.v6);
		}
	}

	RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REQ_INTERNAL_WINS_RTRN,"xxx",vpn,ikesa,rx_req_ikemesg);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REQ_INTERNAL_WINS_ERR,"xxxE",vpn,ikesa,rx_req_ikemesg,err);
	return err;
}

static int _rhp_ikev2_rx_cfg_req(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_ikev2_mesg* rx_req_ikemesg,
		rhp_ikev2_mesg* tx_resp_ikemesg)
{
	int err = -EINVAL;
	rhp_cp_req_srch_pld_ctx s_pld_ctx;
	rhp_vpn_realm* rlm = NULL;
  rhp_ikev2_payload* ikepayload = NULL;

  RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REQ_L,"xxxxLd",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg,"EAP_TYPE",vpn->eap.eap_method);

  if( vpn->radius.rx_accept_attrs && vpn->radius.rx_accept_attrs->dump ){
  	vpn->radius.rx_accept_attrs->dump(vpn->radius.rx_accept_attrs,NULL);
  }

	rlm = vpn->rlm;

	if( rlm == NULL ){
		err = -EINVAL;
		RHP_BUG("");
		goto error;
	}

	RHP_LOCK(&(rlm->lock));

	if( !_rhp_atomic_read(&(rlm->is_active)) ){
		err = -EINVAL;
	  RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REQ_L_RLM_NOT_ACTIVE,"xxx",rx_req_ikemesg,vpn,rlm);
		goto error_rlm_l;
	}

	if( rlm->config_service != RHP_IKEV2_CONFIG_SERVER ){
	  RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REQ_L_RLM_NOT_CONFIG_SERVER_ENABLED,"xxx",rx_req_ikemesg,vpn,rlm);
		goto ignore;
	}


	memset(&s_pld_ctx,0,sizeof(rhp_cp_req_srch_pld_ctx));

	s_pld_ctx.peer_is_rockhopper = vpn->peer_is_rockhopper;

  {
  	err = rx_req_ikemesg->search_payloads(rx_req_ikemesg,0,
  			rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKE_PAYLOAD_CP),
  			_rhp_ikev2_cfg_srch_cp_req_cb,&s_pld_ctx);

  	if( err != -ENOENT ){
  		RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_CFG_REQ_CP_PAYLOAD_ATTRS,"KddL4ddddddddL6ddddddLE",rx_req_ikemesg,s_pld_ctx.dup_flag,s_pld_ctx.internal_addr_flag,"AF",s_pld_ctx.internal_addr.addr_family,s_pld_ctx.internal_addr.addr.v4,s_pld_ctx.internal_netmask_flag,s_pld_ctx.internal_subnet_flag,s_pld_ctx.internal_dns_flag,s_pld_ctx.internal_dns_sfx_flag,s_pld_ctx.internal_gateway_flag,s_pld_ctx.internal_wins_flag,s_pld_ctx.supported_attrs,s_pld_ctx.internal_addr_v6_flag,"AF",s_pld_ctx.internal_addr_v6.addr_family,s_pld_ctx.internal_addr_v6.addr.v6,s_pld_ctx.internal_addr_v6.prefixlen,s_pld_ctx.internal_subnet_v6_flag,s_pld_ctx.internal_dns_v6_flag,s_pld_ctx.internal_gateway_v6_flag,s_pld_ctx.internal_wins_v6_flag,s_pld_ctx.ipv6_autoconf_flag,"PROTO_IKE_NOTIFY",(int)(s_pld_ctx.notify_error),err);
  	}

    if( err && err != RHP_STATUS_ENUM_OK ){

    	if( err == -ENOENT ){

    		if( rlm->config_server.reject_non_clients ){

    			s_pld_ctx.notify_error = RHP_PROTO_IKE_NOTIFY_ERR_NO_PROPOSAL_CHOSEN;

    			RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REQ_L_PAYLOAD_ERR_REJECT_NON_CLIENTS,"xxxxw",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg,s_pld_ctx.notify_error);

        	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_CFG_REQ_REJECT_NON_CLIENT,"KVP",rx_req_ikemesg,vpn,ikesa);

    		}else{
    			RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REQ_L_NO_CFG_PAYLOAD,"xxxx",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg);
    			goto ignore;
    		}
    	}

    	if( s_pld_ctx.notify_error ){
    	  RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REQ_L_PAYLOAD_ERR,"xxxxw",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg,s_pld_ctx.notify_error);
        goto notify_error;
    	}

  	  RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REQ_L_NO_CFG_PAYLOAD_ENUM_PAYLOAD_ERR,"xxxx",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg);

    	err = RHP_STATUS_INVALID_MSG;
    	goto error_rlm_l;
    }
  }

  {
  	u8 cfg_type = s_pld_ctx.cp_payload->ext.cp->get_cfg_type(s_pld_ctx.cp_payload);
  	if( cfg_type != RHP_PROTO_IKE_CFG_REQUEST ){

  		RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REQ_L_NOT_CFG_REQUEST,"xxx",rx_req_ikemesg,vpn,rlm);
    	RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_CFG_REQ_CP_PAYLOAD_NOT_SUPPORTED_CFG_TYPE,"KbVP",rx_req_ikemesg,cfg_type,vpn,ikesa);

  		if( rlm->config_server.reject_non_clients ){

  			s_pld_ctx.notify_error = RHP_PROTO_IKE_NOTIFY_ERR_NO_PROPOSAL_CHOSEN;

    		RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REQ_L_NOT_CFG_REQUEST_REJECT_NON_CLIENTS,"xxx",rx_req_ikemesg,vpn,rlm);

      	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_CFG_REQ_REJECT_NON_CLIENT,"KVP",rx_req_ikemesg,vpn,ikesa);

    		goto notify_error;

  		}else{

  			goto ignore;
  		}
  	}
  }


	if( rlm->config_server.reject_non_clients &&
			!s_pld_ctx.internal_addr_flag &&
			!s_pld_ctx.internal_addr_v6_flag &&
			(!s_pld_ctx.ipv6_autoconf_flag || !rlm->config_server.allow_ipv6_autoconf) ){

		s_pld_ctx.notify_error = RHP_PROTO_IKE_NOTIFY_ERR_NO_PROPOSAL_CHOSEN;

		RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REQ_L_NOT_CFG_REQUEST_REJECT_NON_CLIENTS_2,"xxx",rx_req_ikemesg,vpn,rlm);

  	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_CFG_REQ_REJECT_NON_CLIENT,"KVP",rx_req_ikemesg,vpn,ikesa);

		goto notify_error;
	}



	if( ( err = rhp_ikev2_new_payload_tx(tx_resp_ikemesg,RHP_PROTO_IKE_PAYLOAD_CP,&ikepayload)) ){
		RHP_BUG("");
		goto error_rlm_l;
	}

	ikepayload->ext.cp->set_cfg_type(ikepayload,RHP_PROTO_IKE_CFG_REPLY);


	{
		//
		// [NOTICE]
		// This must be processed before an internal v6 address is assigned.
		//
		if( s_pld_ctx.ipv6_autoconf_flag ){

			u8 ipv6_autoconf_flag = (rlm->config_server.allow_ipv6_autoconf ? 1 : 0 );

			err = ikepayload->ext.cp->alloc_and_put_attr(ikepayload,
							RHP_PROTO_IKE_CFG_ATTR_RHP_IPV6_AUTOCONF,
							sizeof(u8),&ipv6_autoconf_flag);
			if( err ){
				RHP_BUG("%d",err);
				goto error;
			}

			vpn->internal_net_info.peer_exec_ipv6_autoconf = ipv6_autoconf_flag;
			vpn->internal_net_info.ipv6_autoconf_narrow_ts_i = rhp_realm_cfg_svr_narrow_ts_i(rlm,vpn);

			if( ipv6_autoconf_flag ){
				RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_CFG_REQ_IPV6_AUTOCONF_ALLOWED,"Kd",rx_req_ikemesg,(int)ipv6_autoconf_flag);
			}else{
				RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_CFG_REQ_IPV6_AUTOCONF,"Kd",rx_req_ikemesg,(int)ipv6_autoconf_flag);
			}
			RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REQ_IPV6_AUTOCONF,"xxxbb",vpn,ikesa,rx_req_ikemesg,vpn->internal_net_info.peer_exec_ipv6_autoconf,vpn->internal_net_info.ipv6_autoconf_narrow_ts_i);
		}


		if( s_pld_ctx.internal_addr_flag || s_pld_ctx.internal_addr_v6_flag ){

			err = rhp_ikev2_rx_cfg_req_internal_addr(vpn,ikesa,rx_req_ikemesg,
							&s_pld_ctx,rlm,ikepayload);
			if( err ){

				if( s_pld_ctx.notify_error ){
					goto notify_error;
				}

				goto error_rlm_l;
			}
		}
	}


  if( s_pld_ctx.internal_dns_flag || s_pld_ctx.internal_dns_v6_flag ){

  	err = rhp_ikev2_rx_cfg_req_internal_dns(vpn,ikesa,rx_req_ikemesg,
  					&s_pld_ctx,rlm,ikepayload);
  	if( err ){

  		if( s_pld_ctx.notify_error ){
  			goto notify_error;
  		}

			goto error_rlm_l;
  	}
  }

  if( s_pld_ctx.internal_subnet_flag || s_pld_ctx.internal_subnet_v6_flag ){

  	err = rhp_ikev2_rx_cfg_req_internal_subnets(vpn,ikesa,rx_req_ikemesg,
  					&s_pld_ctx,rlm,ikepayload);
  	if( err ){

  		if( s_pld_ctx.notify_error ){
  			goto notify_error;
  		}

			goto error_rlm_l;
  	}
  }


  if( s_pld_ctx.internal_wins_flag || s_pld_ctx.internal_wins_v6_flag ){

  	err = rhp_ikev2_rx_cfg_req_internal_wins(vpn,ikesa,rx_req_ikemesg,
  					&s_pld_ctx,rlm,ikepayload);
  	if( err ){

  		if( s_pld_ctx.notify_error ){
  			goto notify_error;
  		}

			goto error_rlm_l;
  	}
  }


  if( s_pld_ctx.app_ver_flag ){

  	int app_str_len;
  	u8 app_ver_buf[RHP_IKE_CFG_ATTR_APP_VER_MAX_LEN];

  	memset(app_ver_buf,0,RHP_IKE_CFG_ATTR_APP_VER_MAX_LEN);

  	app_str_len = _rhp_print_version_mem(NULL,(char*)app_ver_buf,RHP_IKE_CFG_ATTR_APP_VER_MAX_LEN);
  	if( app_str_len ){

  		if( app_str_len & 1 ){
				app_ver_buf[app_str_len] = ' ';
				app_str_len++;
			}

			err = ikepayload->ext.cp->alloc_and_put_attr(ikepayload,
					RHP_PROTO_IKE_CFG_ATTR_APPLICATION_VERSION,app_str_len,app_ver_buf);

			if( err ){
				RHP_BUG("%d",err);
				goto error_rlm_l;
			}
  	}
  }


  if( s_pld_ctx.supported_attrs ){

  	u16 supported_attrs[RHP_IKE_CFG_ATTR_SUPPORTED_NUM];

  	supported_attrs[0] = htons(RHP_PROTO_IKE_CFG_ATTR_INTERNAL_IP4_ADDRESS);
  	supported_attrs[1] = htons(RHP_PROTO_IKE_CFG_ATTR_INTERNAL_IP4_NETMASK);
  	supported_attrs[2] = htons(RHP_PROTO_IKE_CFG_ATTR_INTERNAL_IP4_DNS);
  	supported_attrs[3] = htons(RHP_PROTO_IKE_CFG_ATTR_INTERNAL_IP4_SUBNET);
  	supported_attrs[4] = htons(RHP_PROTO_IKE_CFG_ATTR_INTERNAL_IP4_NBNS);
  	supported_attrs[5] = htons(RHP_PROTO_IKE_CFG_ATTR_INTERNAL_IP6_ADDRESS);
  	supported_attrs[6] = htons(RHP_PROTO_IKE_CFG_ATTR_INTERNAL_IP6_DNS);
  	supported_attrs[7] = htons(RHP_PROTO_IKE_CFG_ATTR_INTERNAL_IP6_SUBNET);
  	supported_attrs[8] = htons(RHP_PROTO_IKE_CFG_ATTR_INTERNAL_IP6_NBNS);
  	supported_attrs[9] = htons(RHP_PROTO_IKE_CFG_ATTR_APPLICATION_VERSION);
  	supported_attrs[10] = htons(RHP_PROTO_IKE_CFG_ATTR_RHP_DNS_SFX);
  	supported_attrs[11] = htons(RHP_PROTO_IKE_CFG_ATTR_RHP_IPV4_GATEWAY);
  	supported_attrs[12] = htons(RHP_PROTO_IKE_CFG_ATTR_RHP_IPV6_GATEWAY);
  	supported_attrs[13] = htons(RHP_PROTO_IKE_CFG_ATTR_RHP_IPV6_AUTOCONF);

		err = ikepayload->ext.cp->alloc_and_put_attr(ikepayload,RHP_PROTO_IKE_CFG_ATTR_SUPPORTED_ATTRIBUTES,
				sizeof(u16)*RHP_IKE_CFG_ATTR_SUPPORTED_NUM,(u8*)supported_attrs);

		if( err ){
  		RHP_BUG("%d",err);
			goto error_rlm_l;
		}

		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_CFG_REQ_SUPPORTED_ATTRIBUTES,"KWWWWW",rx_req_ikemesg,supported_attrs[0],supported_attrs[1],supported_attrs[2],supported_attrs[3],supported_attrs[4]);
  }

  tx_resp_ikemesg->put_payload(tx_resp_ikemesg,ikepayload);
	ikepayload = NULL;

	vpn->peer_is_remote_client = 1;

	RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_CFG_REQ_OK,"KVP",rx_req_ikemesg,vpn,ikesa);

ignore:
	RHP_UNLOCK(&(rlm->lock));

  RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REQ_L_RTRN,"xxxx",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg);
	return 0;

notify_error:

	err = _rhp_ikev2_cp_new_pkt_error_notify_rep(tx_resp_ikemesg,ikesa,
	  				RHP_PROTO_IKE_PROTOID_IKE,0,s_pld_ctx.notify_error);
	if( err ){
	  RHP_BUG("");
	  goto error_rlm_l;
	}
  err = RHP_STATUS_IKEV2_DESTROY_SA_AFTER_TX;

error_rlm_l:
	RHP_UNLOCK(&(rlm->lock));
error:
	if( ikepayload ){
		rhp_ikev2_destroy_payload(ikepayload);
	}

	RHP_LOG_E(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_CFG_REQ_ERR,"KVPEL",rx_req_ikemesg,vpn,ikesa,err,"PROTO_IKE_NOTIFY",s_pld_ctx.notify_error);
	RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REQ_L_ERR,"xxxxELd",vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg,err,"PROTO_IKE_NOTIFY",s_pld_ctx.notify_error);
	return err;
}

struct _rhp_cp_rep_subnet {

	struct _rhp_cp_rep_subnet* next;

	rhp_ip_addr subnet;
};
typedef struct _rhp_cp_rep_subnet	rhp_cp_rep_subnet;

struct _rhp_cp_rep_srch_pld_ctx {

	int dup_flag;

	int peer_is_rockhopper;

	rhp_ikev2_payload* cp_payload;

	int internal_addr_flag;
	int internal_netmask_flag;
	rhp_ip_addr internal_addr;

	int internal_addr_v6_flag;
	rhp_ip_addr internal_addr_v6;

	rhp_cp_rep_subnet* subnets;
	rhp_cp_rep_subnet* subnets_v6;

	int internal_dns_flag;
	rhp_ip_addr dns_server_addr;

	int internal_dns_v6_flag;
	rhp_ip_addr dns_server_addr_v6;

	rhp_split_dns_domain* domains;

	int internal_gateway_flag;
	rhp_ip_addr gw_addr;

	int internal_gateway_v6_flag;
	rhp_ip_addr gw_addr_v6;

	int ipv6_autoconf_flag;

	int app_ver_flag;
	u8 app_ver[RHP_IKE_CFG_ATTR_APP_VER_MAX_LEN];
};
typedef struct _rhp_cp_rep_srch_pld_ctx		rhp_cp_rep_srch_pld_ctx;

static void _rhp_ikev2_cfg_clear_rep_srch_ctx(rhp_cp_rep_srch_pld_ctx* s_pld_ctx)
{
	RHP_TRC(0,RHPTRCID_IKEV2_CFG_CLEAR_REP_SRCH_CTX,"x",s_pld_ctx);

	{
		rhp_cp_rep_subnet* sn = s_pld_ctx->subnets;

		while( sn ){
			rhp_cp_rep_subnet* sn_n = sn->next;
			_rhp_free(sn);
			sn = sn_n;
		}

		sn = s_pld_ctx->subnets_v6;
		while( sn ){
			rhp_cp_rep_subnet* sn_n = sn->next;
			_rhp_free(sn);
			sn = sn_n;
		}
	}

	_rhp_split_dns_domain_free(s_pld_ctx->domains);

	RHP_TRC(0,RHPTRCID_IKEV2_CFG_CLEAR_REP_SRCH_CTX_RTRN,"x",s_pld_ctx);
	return;
}

static int _rhp_ikev2_cfg_srch_cp_rep_attr_cb(rhp_ikev2_payload* payload,rhp_ikev2_cp_attr* cp_attr,void* ctx)
{
	int err = -EINVAL;
	rhp_cp_rep_srch_pld_ctx* s_pld_ctx = (rhp_cp_rep_srch_pld_ctx*)ctx;
	u16 cp_attr_type = cp_attr->get_attr_type(cp_attr);
	int cp_attr_len = cp_attr->get_attr_len(cp_attr);
	u8* cp_attr_val = cp_attr->get_attr(cp_attr);

  RHP_TRC(0,RHPTRCID_IKEV2_CFG_SRCH_CP_REP_ATTR_CB,"xxxLdd",payload,cp_attr,ctx,"IKEV2_CFG_ATTR_TYPE",cp_attr_type,cp_attr_len);

	switch( cp_attr_type ){

	case RHP_PROTO_IKE_CFG_ATTR_INTERNAL_IP4_ADDRESS:

		if( cp_attr_len == 4 ){

			s_pld_ctx->internal_addr.addr_family = AF_INET;
			memcpy(&(s_pld_ctx->internal_addr.addr.v4),cp_attr_val,4);

			s_pld_ctx->internal_addr_flag = 1;

		  RHP_TRC(0,RHPTRCID_IKEV2_CFG_SRCH_CP_REP_ATTR_CB_INTR_V4_ADDR,"xxx4",payload,cp_attr,ctx,s_pld_ctx->internal_addr.addr.v4);

		}else{

			RHP_TRC(0,RHPTRCID_IKEV2_CFG_SRCH_CP_REP_ATTR_CB_INVALID_INTR_V4_ADDR_LEN,"xxxd",payload,cp_attr,ctx,cp_attr_len);
		}

		break;

	case RHP_PROTO_IKE_CFG_ATTR_INTERNAL_IP6_ADDRESS:

		if( !rhp_gcfg_ipv6_disabled ){

			if( cp_attr_len == 17 ){

				if( cp_attr_val[16] > 0 && cp_attr_val[16] <= 128 ){

					s_pld_ctx->internal_addr_v6.addr_family = AF_INET6;
					memcpy(s_pld_ctx->internal_addr_v6.addr.v6,cp_attr_val,16);

					s_pld_ctx->internal_addr_v6.prefixlen = cp_attr_val[16];

					s_pld_ctx->internal_addr_v6_flag = 1;

					RHP_TRC(0,RHPTRCID_IKEV2_CFG_SRCH_CP_REP_ATTR_CB_INTR_V6_ADDR,"xxx6d",payload,cp_attr,ctx,s_pld_ctx->internal_addr_v6.addr.v6,s_pld_ctx->internal_addr_v6.prefixlen);

				}else{
					RHP_TRC(0,RHPTRCID_IKEV2_CFG_SRCH_CP_REP_ATTR_CB_INVALID_INTR_V6_PREFIX_LEN,"xxxb",payload,cp_attr,ctx,cp_attr_val[16]);
				}

			}else{

				RHP_TRC(0,RHPTRCID_IKEV2_CFG_SRCH_CP_REP_ATTR_CB_INVALID_INTR_V6_ADDR_LEN,"xxxd",payload,cp_attr,ctx,cp_attr_len);
			}
		}
		break;

	case RHP_PROTO_IKE_CFG_ATTR_INTERNAL_IP4_NETMASK:

		if( cp_attr_len == 4 ){

			s_pld_ctx->internal_addr.addr_family = AF_INET;
			memcpy(&(s_pld_ctx->internal_addr.netmask.v4),cp_attr_val,4);

			s_pld_ctx->internal_addr.prefixlen = rhp_ipv4_netmask_to_prefixlen(s_pld_ctx->internal_addr.netmask.v4);

			s_pld_ctx->internal_netmask_flag = 1;

			RHP_TRC(0,RHPTRCID_IKEV2_CFG_SRCH_CP_REP_ATTR_CB_INTR_V4_MASK,"xxx4d",payload,cp_attr,ctx,s_pld_ctx->internal_addr.netmask.v4,s_pld_ctx->internal_addr.prefixlen);

		}else{
		  RHP_TRC(0,RHPTRCID_IKEV2_CFG_SRCH_CP_REP_ATTR_CB_INVALID_INTR_V4_MASK_LEN,"xxxd",payload,cp_attr,ctx,cp_attr_len);
		}

		break;

	case RHP_PROTO_IKE_CFG_ATTR_INTERNAL_IP4_DNS:

		if( cp_attr_len == 4 ){

			s_pld_ctx->dns_server_addr.addr_family = AF_INET;
			memcpy(&(s_pld_ctx->dns_server_addr.addr.v4),cp_attr_val,4);

			s_pld_ctx->internal_dns_flag = 1;

			RHP_TRC(0,RHPTRCID_IKEV2_CFG_SRCH_CP_REP_ATTR_CB_INTR_V4_DNS,"xxx4",payload,cp_attr,ctx,s_pld_ctx->dns_server_addr.addr.v4);

		}else{

		  RHP_TRC(0,RHPTRCID_IKEV2_CFG_SRCH_CP_REP_ATTR_CB_INVALID_INTR_V4_DNS_LEN,"xxxd",payload,cp_attr,ctx,cp_attr_len);
		}
		break;

	case RHP_PROTO_IKE_CFG_ATTR_INTERNAL_IP6_DNS:

		if( !rhp_gcfg_ipv6_disabled ){

			if( cp_attr_len == 16 ){

				s_pld_ctx->dns_server_addr_v6.addr_family = AF_INET6;
				memcpy(&(s_pld_ctx->dns_server_addr_v6.addr.v6),cp_attr_val,16);

				s_pld_ctx->internal_dns_v6_flag = 1;

				RHP_TRC(0,RHPTRCID_IKEV2_CFG_SRCH_CP_REP_ATTR_CB_INTR_V6_DNS,"xxx6",payload,cp_attr,ctx,s_pld_ctx->dns_server_addr_v6.addr.v6);

			}else{

				RHP_TRC(0,RHPTRCID_IKEV2_CFG_SRCH_CP_REP_ATTR_CB_INVALID_INTR_V6_DNS_LEN,"xxxd",payload,cp_attr,ctx,cp_attr_len);
			}
		}
		break;

	case RHP_PROTO_IKE_CFG_ATTR_INTERNAL_IP4_SUBNET:
	{
		rhp_cp_rep_subnet* sn;
		u8* data = cp_attr_val;

		if( cp_attr_len == 8 ){

			sn = (rhp_cp_rep_subnet*)_rhp_malloc(sizeof(rhp_cp_rep_subnet));
			if( sn == NULL ){
				RHP_BUG("");
				err = -ENOMEM;
				goto error;
			}

			memset(sn,0,sizeof(rhp_cp_rep_subnet));

			sn->subnet.addr_family = AF_INET;
			memcpy(&(sn->subnet.addr.v4),data,4);
			memcpy(&(sn->subnet.netmask.v4),(data + 4),4);
			sn->subnet.prefixlen = rhp_ipv4_netmask_to_prefixlen(sn->subnet.netmask.v4);

			RHP_TRC(0,RHPTRCID_IKEV2_CFG_SRCH_CP_REP_ATTR_CB_INTR_V4_SUBNET,"xxx44",payload,cp_attr,ctx,sn->subnet.addr.v4,sn->subnet.netmask.v4);

			sn->next = s_pld_ctx->subnets;
			s_pld_ctx->subnets = sn;

		}else{

		  RHP_TRC(0,RHPTRCID_IKEV2_CFG_SRCH_CP_REP_ATTR_CB_INVALID_INTR_V4_SUBNET_LEN,"xxxd",payload,cp_attr,ctx,cp_attr_len);
		}
	}
		break;

	case RHP_PROTO_IKE_CFG_ATTR_INTERNAL_IP6_SUBNET:
	{
		rhp_cp_rep_subnet* sn;

		if( !rhp_gcfg_ipv6_disabled ){

			if( cp_attr_len == 17 ){

				if( cp_attr_val[16] > 0 && cp_attr_val[16] <= 128 ){

					sn = (rhp_cp_rep_subnet*)_rhp_malloc(sizeof(rhp_cp_rep_subnet));
					if( sn == NULL ){
						RHP_BUG("");
						err = -ENOMEM;
						goto error;
					}

					memset(sn,0,sizeof(rhp_cp_rep_subnet));

					sn->subnet.addr_family = AF_INET6;
					memcpy(sn->subnet.addr.v6,cp_attr_val,16);

					sn->subnet.prefixlen = cp_attr_val[16];
					rhp_ipv6_prefixlen_to_netmask(sn->subnet.prefixlen,sn->subnet.netmask.v6);

					RHP_TRC(0,RHPTRCID_IKEV2_CFG_SRCH_CP_REP_ATTR_CB_INTR_V6_SUBNET,"xxx66d",payload,cp_attr,ctx,sn->subnet.addr.v6,sn->subnet.netmask.v6,sn->subnet.prefixlen);

					sn->next = s_pld_ctx->subnets_v6;
					s_pld_ctx->subnets_v6 = sn;

				}else{
					RHP_TRC(0,RHPTRCID_IKEV2_CFG_SRCH_CP_REP_ATTR_CB_INVALID_INTR_V6_SUBNET_PREFIX_LEN,"xxxb",payload,cp_attr,ctx,cp_attr_val[16]);
				}

			}else{
				RHP_TRC(0,RHPTRCID_IKEV2_CFG_SRCH_CP_REP_ATTR_CB_INVALID_INTR_V6_SUBNET_LEN,"xxxd",payload,cp_attr,ctx,cp_attr_len);
			}
		}
	}
		break;

	case RHP_PROTO_IKE_CFG_ATTR_RHP_DNS_SFX:
	{

		if( s_pld_ctx->peer_is_rockhopper ){

			rhp_split_dns_domain* domain;
			u8* data = cp_attr_val;

			if( cp_attr_len ){

				domain = (rhp_split_dns_domain*)_rhp_malloc(sizeof(rhp_split_dns_domain));
				if( domain == NULL ){
					RHP_BUG("");
					err = -ENOMEM;
					goto error;
				}

				memset(domain,0,sizeof(rhp_split_dns_domain));

				domain->tag[0] = '#';
				domain->tag[1] = 'C';
				domain->tag[2] = 'S';
				domain->tag[3] = 'D';

				domain->name = (char*)_rhp_malloc(cp_attr_len + 1);
				if( domain->name == NULL ){
					RHP_BUG("");
					err = -ENOMEM;
					goto error;
				}

				domain->name[cp_attr_len] = '\0';
				memcpy(domain->name,data,cp_attr_len);

				RHP_TRC(0,RHPTRCID_IKEV2_CFG_SRCH_CP_REP_ATTR_CB_INTR_DNS_SFX,"xxxs",payload,cp_attr,ctx,domain->name);

				domain->ikev2_cfg = 1;

				domain->next = s_pld_ctx->domains;
				s_pld_ctx->domains = domain;

			}else{

				RHP_TRC(0,RHPTRCID_IKEV2_CFG_SRCH_CP_REP_ATTR_CB_INVALID_INTR_DNS_SFX_LEN,"xxxd",payload,cp_attr,ctx,cp_attr_len);
			}
		}
	}
		break;

	case RHP_PROTO_IKE_CFG_ATTR_RHP_IPV4_GATEWAY: // (***)

		// For bridge configuration...  [This node]---(VPN)---[Peer Node(Bridge)]---[Router(***)]--

		if( s_pld_ctx->peer_is_rockhopper ){

			if( cp_attr_len == 4 ){

				s_pld_ctx->gw_addr.addr_family = AF_INET;
				memcpy(&(s_pld_ctx->gw_addr.addr.v4),cp_attr_val,4);

				s_pld_ctx->internal_gateway_flag = 1;

				RHP_TRC(0,RHPTRCID_IKEV2_CFG_SRCH_CP_REP_ATTR_CB_INTR_V4_GATEWAY,"xxx4",payload,cp_attr,ctx,s_pld_ctx->gw_addr.addr.v4);

			}else{

				RHP_TRC(0,RHPTRCID_IKEV2_CFG_SRCH_CP_REP_ATTR_CB_INVALID_INTR_V4_GATEWAY_LEN,"xxxd",payload,cp_attr,ctx,cp_attr_len);
			}
		}
		break;

	case RHP_PROTO_IKE_CFG_ATTR_RHP_IPV6_GATEWAY: // (***)

		if( s_pld_ctx->peer_is_rockhopper && !rhp_gcfg_ipv6_disabled ){

			// For bridge configuration...  [This node]---(VPN)---[Peer Node(Bridge)]---[Router(***)]--

			if( cp_attr_len == 16 ){

				s_pld_ctx->gw_addr_v6.addr_family = AF_INET6;
				memcpy(s_pld_ctx->gw_addr_v6.addr.v6,cp_attr_val,16);

				s_pld_ctx->internal_gateway_v6_flag = 1;

				RHP_TRC(0,RHPTRCID_IKEV2_CFG_SRCH_CP_REP_ATTR_CB_INTR_V6_GATEWAY,"xxx6",payload,cp_attr,ctx,s_pld_ctx->gw_addr_v6.addr.v6);

			}else{

				RHP_TRC(0,RHPTRCID_IKEV2_CFG_SRCH_CP_REP_ATTR_CB_INVALID_INTR_V6_GATEWAY_LEN,"xxxd",payload,cp_attr,ctx,cp_attr_len);
			}
		}
		break;

	case RHP_PROTO_IKE_CFG_ATTR_RHP_IPV6_AUTOCONF:

		if( s_pld_ctx->peer_is_rockhopper && cp_attr_len == 1 ){

			s_pld_ctx->ipv6_autoconf_flag = (*cp_attr_val == 1 ? 1 : 0);
		}
		break;

	case RHP_PROTO_IKE_CFG_ATTR_APPLICATION_VERSION:

		if( cp_attr_len ){

			s_pld_ctx->app_ver_flag = 1;
			u8* rx_app_ver = cp_attr_val;

			memcpy(s_pld_ctx->app_ver,rx_app_ver,
					(cp_attr_len > (RHP_IKE_CFG_ATTR_APP_VER_MAX_LEN - 1) ? (RHP_IKE_CFG_ATTR_APP_VER_MAX_LEN - 1) : cp_attr_len));

			RHP_TRC(0,RHPTRCID_IKEV2_CFG_SRCH_CP_REP_ATTR_CB_APP_VER,"xxxp",payload,cp_attr,ctx,cp_attr_len,rx_app_ver);
		}
		break;

	default:
		break;
	}

  RHP_TRC(0,RHPTRCID_IKEV2_CFG_SRCH_CP_REP_ATTR_CB_RTRN,"xxxLd",payload,cp_attr,ctx,"IKEV2_CFG_ATTR_TYPE",cp_attr_type);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV2_CFG_SRCH_CP_REP_ATTR_CB_RTRN,"xxxLdE",payload,cp_attr,ctx,"IKEV2_CFG_ATTR_TYPE",cp_attr_type,err);
	return err;
}

static int _rhp_ikev2_cfg_srch_cp_rep_cb(rhp_ikev2_mesg* rx_ikemesg,
		int enum_end,rhp_ikev2_payload* payload,void* ctx)
{
	int err = -EINVAL;
	rhp_cp_rep_srch_pld_ctx* s_pld_ctx = (rhp_cp_rep_srch_pld_ctx*)ctx;
	rhp_ikev2_cp_payload* cp_payload = payload->ext.cp;

  RHP_TRC(0,RHPTRCID_IKEV2_CFG_SRCH_CP_REP_CB,"xdxd",rx_ikemesg,enum_end,ctx,s_pld_ctx->dup_flag);

  s_pld_ctx->dup_flag++;

  if( s_pld_ctx->dup_flag > 1 ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV2_CFG_SRCH_CP_REP_CB_INVALID_MESG,"xdx",rx_ikemesg,enum_end,ctx);
    goto error;
  }

  err = cp_payload->enum_attr(payload,_rhp_ikev2_cfg_srch_cp_rep_attr_cb,s_pld_ctx);
  if( err ){
  	RHP_BUG("%d",err);
  	goto error;
  }

  s_pld_ctx->cp_payload = payload;

  RHP_TRC(0,RHPTRCID_IKEV2_CFG_SRCH_CP_REP_CB_RTRN,"xdx",rx_ikemesg,enum_end,ctx);
  return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV2_CFG_SRCH_CP_REP_CB_ERR,"xdxE",rx_ikemesg,enum_end,ctx,err);
	return err;
}

static int _rhp_ikev2_cfg_clear_old_internal_addrs(rhp_if_entry* new_info,rhp_vpn_realm* rlm)
{
	int err = -EINVAL;
	rhp_if_entry* if_info = NULL;
	int n = 0, i;

  RHP_TRC(0,RHPTRCID_IKEV2_CFG_CLEAR_OLD_INTERNAL_ADDRS,"xx",new_info,rlm);
  rhp_if_entry_dump("_rhp_ikev2_cfg_clear_old_internal_addrs",new_info);

	if( rlm->internal_ifc->addrs_type == RHP_VIF_ADDR_IKEV2CFG ){

  	if( rlm->internal_ifc->ifc ){

  	  rhp_ifc_entry* v_ifc = rlm->internal_ifc->ifc;

  		RHP_LOCK(&(v_ifc->lock));
  		{
  			if( v_ifc->ifc_addrs_num ){

					if_info = (rhp_if_entry*)_rhp_malloc(sizeof(rhp_if_entry)*v_ifc->ifc_addrs_num);
					if( if_info == NULL ){

						RHP_BUG("");
						err = -ENOMEM;

					}else{

						rhp_ifc_addr* if_addr = v_ifc->ifc_addrs;

						memset(if_info,0,sizeof(rhp_if_entry)*v_ifc->ifc_addrs_num);

						for( i = 0; i < v_ifc->ifc_addrs_num; i++ ){

							if( (new_info->addr_family == if_addr->addr.addr_family) &&
									rhp_ip_addr_cmp_value(&(if_addr->addr),
										(new_info->addr_family == AF_INET ? 4 : 16),new_info->addr.raw) &&
									(if_addr->addr.addr_family == AF_INET ||
									 (if_addr->addr.addr_family == AF_INET6 &&
									  !rhp_ipv6_is_linklocal(if_addr->addr.addr.v6))) ){

								if_info[n].addr_family = if_addr->addr.addr_family;
								memcpy(if_info[n].addr.raw,if_addr->addr.addr.raw,16);
								if_info[n].prefixlen = if_addr->addr.prefixlen;

								strcpy(if_info[n].if_name,rlm->internal_ifc->if_name);

								n++;
							}

							if_addr = if_addr->lst_next;
						}
					}
  			}
  		}
  		RHP_UNLOCK(&(v_ifc->lock));

  		for( i = 0; i < n; i++ ){ // Out of the v_ifc->lock scope.

				err = rhp_ipc_send_update_vif_raw(rlm->id,rlm->internal_ifc->if_name,
								RHP_IPC_VIF_DELETE_ADDR,&(if_info[i]));
				if( err ){
					RHP_BUG("%d",err);
				}
  		}

  	}else{
  		RHP_BUG("");
  	}
	}

	if( if_info ){
		_rhp_free(if_info);
	}

  RHP_TRC(0,RHPTRCID_IKEV2_CFG_CLEAR_OLD_INTERNAL_ADDRS_RTRN,"xx",new_info,rlm);
	return 0;
}


static int _rhp_ikev2_rx_cfg_rep_internal_addr_v6_autoconf(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg* rx_resp_ikemesg,
		rhp_cp_rep_srch_pld_ctx* s_pld_ctx,rhp_vpn_realm* rlm,int* ok_r)
{
	int err = -EINVAL;
  RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REP_L_INTERNAL_ADDR_V6_AUTOCONF,"xxxx",vpn,ikesa,rlm,rx_resp_ikemesg);

	if( s_pld_ctx->ipv6_autoconf_flag ){

  	err = rhp_ipc_send_vif_exec_ipv6_autoconf(rlm->id,
  					rlm->internal_ifc->if_name);
  	if( err ){
  		RHP_BUG("%d",err);
  		goto error;
  	}

  	vpn->internal_net_info.exec_ipv6_autoconf = 1;

  	(*ok_r)++;
  }

  RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REP_L_INTERNAL_ADDR_V6_AUTOCONF_RTRN,"xxxx",vpn,ikesa,rlm,rx_resp_ikemesg);
  return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REP_L_INTERNAL_ADDR_V6_AUTOCONF_ERR,"xxxxE",vpn,ikesa,rlm,rx_resp_ikemesg,err);
	return err;
}


static int _rhp_ikev2_cfg_update_old_internal_addr_cache(rhp_vpn* vpn,rhp_vpn_realm* rlm,rhp_ip_addr* new_addr)
{
	rhp_cfg_peer* rlm_cfg_peer;

	if( new_addr ){

		rlm_cfg_peer = rlm->get_peer_by_id(rlm,&(vpn->cfg_peer->id));
		if( rlm_cfg_peer ){

			if( new_addr->addr_family == AF_INET ){
				memcpy(&(rlm_cfg_peer->ikev2_cfg_rmt_clt_old_addr_v4),new_addr,sizeof(rhp_ip_addr));
			}else if( new_addr->addr_family == AF_INET6 ){
				memcpy(&(rlm_cfg_peer->ikev2_cfg_rmt_clt_old_addr_v6),new_addr,sizeof(rhp_ip_addr));
			}
			rhp_ip_addr_dump("ikev2_cfg_update_old_internal_addr_cache.rlm_cfg_peer",new_addr);
		}

		if( vpn->cfg_peer ){

			if( new_addr->addr_family == AF_INET ){
				memcpy(&(vpn->cfg_peer->ikev2_cfg_rmt_clt_old_addr_v4),new_addr,sizeof(rhp_ip_addr));
			}else if( new_addr->addr_family == AF_INET6 ){
				memcpy(&(vpn->cfg_peer->ikev2_cfg_rmt_clt_old_addr_v6),new_addr,sizeof(rhp_ip_addr));
			}
			rhp_ip_addr_dump("ikev2_cfg_update_old_internal_addr_cache.vpn->cfg_peer",new_addr);
		}
	}

	RHP_TRC(0,RHPTRCID_IKEV2_CFG_UPDATE_OLD_INTERNAL_ADDR_CACHE,"xxx",vpn,rlm,new_addr);

	return 0;
}


static int _rhp_ikev2_rx_cfg_rep_internal_addr(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg* rx_resp_ikemesg,
		rhp_cp_rep_srch_pld_ctx* s_pld_ctx,rhp_vpn_realm* rlm,int* ok_r)
{
	int err = -EINVAL;
	rhp_if_entry new_info;

  RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REP_L_INTERNAL_ADDRESS,"xxxxxxdd",vpn,ikesa,rx_resp_ikemesg,s_pld_ctx,rlm,ok_r,rlm->internal_ifc->ikev2_config_ipv6_auto,s_pld_ctx->ipv6_autoconf_flag);

  if( s_pld_ctx->internal_addr_flag ){

	  RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REP_L_INTERNAL_ADDRESS_V4,"xxx",rx_resp_ikemesg,vpn,rlm);

		memset(&new_info,0,sizeof(rhp_if_entry));

		strcpy(new_info.if_name,rlm->internal_ifc->if_name);

  	{
			new_info.addr_family = AF_INET;
			new_info.addr.v4 = s_pld_ctx->internal_addr.addr.v4;

			if( s_pld_ctx->internal_netmask_flag ){
				new_info.prefixlen = s_pld_ctx->internal_addr.prefixlen;
			}else{
				new_info.prefixlen = 32;
				s_pld_ctx->internal_addr.prefixlen = 32;
			}

			memcpy(&(rx_resp_ikemesg->rx_cp_internal_addrs[0]),&(s_pld_ctx->internal_addr),sizeof(rhp_ip_addr));

			rhp_ip_addr_dump("&(rx_resp_ikemesg->rx_cp_internal_addrs[0])",&(rx_resp_ikemesg->rx_cp_internal_addrs[0]));

    	RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_CFG_RESP_INTERNAL_ADDRESS,"KVPs4d",rx_resp_ikemesg,vpn,ikesa,new_info.if_name,new_info.addr.v4,new_info.prefixlen);
  	}

	  RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REP_L_INTERNAL_ADDRESS_INFO,"xxx4d",rx_resp_ikemesg,vpn,rlm,new_info.addr.v4,new_info.prefixlen);


	  _rhp_ikev2_cfg_clear_old_internal_addrs(&new_info,rlm);


  	err = rhp_ipc_send_update_vif_raw(rlm->id,
  					rlm->internal_ifc->if_name,RHP_IPC_VIF_UPDATE_ADDR,&new_info);
  	if( err ){
  		RHP_BUG("%d",err);
  		goto error;
  	}


  	if( rhp_gcfg_ikev2_cfg_rmt_clt_req_old_addr ){

  	  _rhp_ikev2_cfg_update_old_internal_addr_cache(vpn,rlm,&(s_pld_ctx->internal_addr));
  	}


  	(*ok_r)++;
  }

  if( s_pld_ctx->internal_addr_v6_flag && !s_pld_ctx->ipv6_autoconf_flag ){

	  RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REP_L_INTERNAL_ADDRESS_V6,"xxx",rx_resp_ikemesg,vpn,rlm);

		memset(&new_info,0,sizeof(rhp_if_entry));

		strcpy(new_info.if_name,rlm->internal_ifc->if_name);

  	{
			new_info.addr_family = AF_INET6;
			memcpy(new_info.addr.v6,s_pld_ctx->internal_addr_v6.addr.v6,16);

			new_info.prefixlen = s_pld_ctx->internal_addr_v6.prefixlen;

			memcpy(&(rx_resp_ikemesg->rx_cp_internal_addrs[1]),&(s_pld_ctx->internal_addr_v6),sizeof(rhp_ip_addr));
			rhp_ip_addr_dump("&(rx_resp_ikemesg->rx_cp_internal_addrs[1])",&(rx_resp_ikemesg->rx_cp_internal_addrs[1]));

    	RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_CFG_RESP_INTERNAL_ADDRESS_V6,"KVPs6d",rx_resp_ikemesg,vpn,ikesa,new_info.if_name,new_info.addr.v6,new_info.prefixlen);
  	}

	  RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REP_L_INTERNAL_ADDRESS_V6_INFO,"xxx6d",rx_resp_ikemesg,vpn,rlm,new_info.addr.v6,new_info.prefixlen);


	  _rhp_ikev2_cfg_clear_old_internal_addrs(&new_info,rlm);


  	err = rhp_ipc_send_update_vif_raw(rlm->id,
  					rlm->internal_ifc->if_name,RHP_IPC_VIF_UPDATE_ADDR,&new_info);
  	if( err ){
  		RHP_BUG("%d",err);
  		goto error;
  	}


  	if( rhp_gcfg_ikev2_cfg_rmt_clt_req_old_addr ){

  	  _rhp_ikev2_cfg_update_old_internal_addr_cache(vpn,rlm,&(s_pld_ctx->internal_addr_v6));
  	}

  	(*ok_r)++;
  }

  RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REP_L_INTERNAL_ADDRESS_RTRN,"xxx",vpn,ikesa,rx_resp_ikemesg);
  return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REP_L_INTERNAL_ADDRESS_ERR,"xxxE",vpn,ikesa,rx_resp_ikemesg,err);
	return err;
}

static int _rhp_ikev2_rx_cfg_rep_internal_subnets_dmy_gw(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_cp_rep_srch_pld_ctx* s_pld_ctx,rhp_vpn_realm* rlm,
		int addr_family,rhp_ip_addr* dmy_gateway_addr_r)
{
	union {
		u32 v4;
		u8	v6[16];
	} dmy_gw_addr;
	int dmy_gw_prefix_len;
	rhp_ip_addr dmy_gateway_addr;
	int retry = 0;
	u32 s;

  RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REP_INTERNAL_SUBNETS_DMY_GW,"xxxxLdxd",vpn,ikesa,s_pld_ctx,rlm,"AF",addr_family,dmy_gateway_addr_r,s_pld_ctx->internal_netmask_flag);

	if( addr_family == AF_INET ){

		dmy_gw_addr.v4 = s_pld_ctx->internal_addr.addr.v4;
		dmy_gw_prefix_len = 32;

		if( !s_pld_ctx->internal_netmask_flag ){
		  RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REP_INTERNAL_SUBNETS_DMY_GW_V4_NO_NETMASK,"xxx",vpn,ikesa,s_pld_ctx);
			return -ENOENT;
		}

		if( rlm->internal_ifc->addrs_type == RHP_VIF_ADDR_STATIC ){

			rhp_ip_addr_list* addr_lst = rlm->internal_ifc->addrs;
			while( addr_lst ){

				if( addr_lst->ip_addr.addr_family == AF_INET &&
						!rhp_ip_addr_null(&(addr_lst->ip_addr)) ){

					dmy_gw_addr.v4 = addr_lst->ip_addr.addr.v4;
					dmy_gw_prefix_len = addr_lst->ip_addr.prefixlen;

					break;
				}

				addr_lst = addr_lst->next;
			}
		}

		if( !dmy_gw_addr.v4 ){
		  RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REP_INTERNAL_SUBNETS_DMY_GW_V4_NO_ENT,"xxx",vpn,ikesa,s_pld_ctx);
			return -ENOENT;
		}

		if( s_pld_ctx->internal_netmask_flag ){
			dmy_gw_prefix_len = s_pld_ctx->internal_addr.prefixlen;
		}

	}else if( addr_family == AF_INET6 ){

		memcpy(dmy_gw_addr.v6,s_pld_ctx->internal_addr_v6.addr.v6,16);
		dmy_gw_prefix_len = 128;

		if( rlm->internal_ifc->addrs_type == RHP_VIF_ADDR_STATIC ){

			rhp_ip_addr_list* addr_lst = rlm->internal_ifc->addrs;
			while( addr_lst ){

				if( addr_lst->ip_addr.addr_family == AF_INET6 &&
						!rhp_ip_addr_null(&(addr_lst->ip_addr)) &&
						!rhp_ipv6_is_linklocal(addr_lst->ip_addr.addr.v6) ){

					memcpy(dmy_gw_addr.v6,addr_lst->ip_addr.addr.v6,16);
					dmy_gw_prefix_len = addr_lst->ip_addr.prefixlen;

					break;
				}

				addr_lst = addr_lst->next;
			}
		}

		if( rhp_ipv6_addr_null(dmy_gw_addr.v6) ){
		  RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REP_INTERNAL_SUBNETS_DMY_GW_V6_NO_ENT,"xxx",vpn,ikesa,s_pld_ctx);
			return -ENOENT;
		}

	}else{
		RHP_BUG("");
		return -EINVAL;
	}


	memset(&dmy_gateway_addr,0,sizeof(rhp_ip_addr));

	if( addr_family == AF_INET ){

		s = ntohl(dmy_gw_addr.v4);
		u32 dmy_netmask_v4 = rhp_ipv4_prefixlen_to_netmask(dmy_gw_prefix_len);

gaddr_retry:
		dmy_gw_addr.v4 = htonl(++s);

		if( ((dmy_gw_addr.v4 & ~dmy_netmask_v4) == 0) || // subnet address
				((dmy_gw_addr.v4 & ~dmy_netmask_v4) == ~dmy_netmask_v4) ){ // subnet broadcast address

			if( retry < 2 ){
				retry++;
				goto gaddr_retry;
			}
		}

		dmy_gateway_addr.addr_family = AF_INET;
		dmy_gateway_addr.addr.v4 = dmy_gw_addr.v4;
		dmy_gateway_addr.prefixlen = dmy_gw_prefix_len;
		dmy_gateway_addr.netmask.v4 = dmy_netmask_v4;

	}else if( addr_family == AF_INET6 ){

		dmy_gw_addr.v6[15]++;

		dmy_gateway_addr.addr_family = AF_INET6;
		memcpy(dmy_gateway_addr.addr.v6,dmy_gw_addr.v6,16);
		dmy_gateway_addr.prefixlen = dmy_gw_prefix_len;
		rhp_ipv6_prefixlen_to_netmask(dmy_gw_prefix_len,dmy_gateway_addr.netmask.v6);
	}

	memcpy(dmy_gateway_addr_r,&dmy_gateway_addr,sizeof(rhp_ip_addr));

	rhp_ip_addr_dump("dmy_gw",dmy_gateway_addr_r);
  RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REP_INTERNAL_SUBNETS_DMY_GW_RTRN,"xxx",vpn,ikesa,s_pld_ctx);
	return 0;
}

static rhp_ip_addr* _rhp_ikev2_cfg_get_static_peer(rhp_vpn* vpn,int addr_family)
{
  RHP_TRC(0,RHPTRCID_IKEV2_CFG_GET_STATIC_PEER,"xLdd",vpn,"AF",addr_family,vpn->internal_net_info.static_peer_addr);

	if( vpn->internal_net_info.static_peer_addr ){

		rhp_ip_addr_list* peer_addr = vpn->internal_net_info.peer_addrs;
		while( peer_addr ){

			if( peer_addr->ip_addr.addr_family == addr_family &&
					peer_addr->ip_addr.tag == RHP_IPADDR_TAG_STATIC_PEER_ADDR ){

				rhp_ip_addr_dump("cfg_get_static_peer",&(peer_addr->ip_addr));
				RHP_TRC(0,RHPTRCID_IKEV2_CFG_GET_STATIC_PEER_RTRN,"xx",vpn,peer_addr);
				return &(peer_addr->ip_addr);
			}

			peer_addr = peer_addr->next;
		}
	}

  RHP_TRC(0,RHPTRCID_IKEV2_CFG_GET_STATIC_PEER_NO_ENT,"xLd",vpn,"AF",addr_family);
	return NULL;
}

static int _rhp_ikev2_rx_cfg_rep_internal_subnets(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg* rx_resp_ikemesg,
		rhp_cp_rep_srch_pld_ctx* s_pld_ctx,rhp_vpn_realm* rlm,int* ok_r)
{
	int err = -EINVAL;
	int static_cache = 0;

  RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REP_INTERNAL_SUBNETS,"xxxxxxdddddd",vpn,ikesa,rx_resp_ikemesg,s_pld_ctx,rlm,ok_r,s_pld_ctx->subnets,s_pld_ctx->subnets_v6,s_pld_ctx->internal_netmask_flag,s_pld_ctx->internal_gateway_flag,vpn->peer_is_rockhopper,vpn->internal_net_info.static_peer_addr);
	rhp_ip_addr_dump("cfg_rep_internal_subnets_gw_v4",&(s_pld_ctx->gw_addr));
	rhp_ip_addr_dump("cfg_rep_internal_subnets_gw_v6",&(s_pld_ctx->gw_addr_v6));

  if( s_pld_ctx->subnets || s_pld_ctx->subnets_v6 ){

  	rhp_cp_rep_subnet *sn_v4 = s_pld_ctx->subnets,*sn_v6 = s_pld_ctx->subnets_v6;
  	rhp_ip_addr dmy_gateway_addr_v4,dmy_gateway_addr_v6;
  	rhp_ip_addr *gateway_addr_v4_p = NULL, *gateway_addr_v6_p = NULL;
  	char tx_interface[RHP_IFNAMSIZ];


  	rhp_vpn_internal_route_delete(vpn,rlm);

  	rhp_vpn_ikev2_cfg_internal_routes_clear(rlm,vpn);


  	if( s_pld_ctx->subnets ){

  	  memset(&dmy_gateway_addr_v4,0,sizeof(rhp_ip_addr));
  	  tx_interface[0] = '\0';

  		if( s_pld_ctx->internal_gateway_flag &&
  				!rhp_ip_addr_null(&(s_pld_ctx->gw_addr)) ){

				gateway_addr_v4_p = &(s_pld_ctx->gw_addr);
				RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REP_INTERNAL_SUBNETS_V4_1,"xxx",vpn,ikesa,rx_resp_ikemesg);

  		}else if( vpn->internal_net_info.static_peer_addr ){

				gateway_addr_v4_p = _rhp_ikev2_cfg_get_static_peer(vpn,AF_INET);
				RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REP_INTERNAL_SUBNETS_V4_2,"xxx",vpn,ikesa,rx_resp_ikemesg);

			}else if( !vpn->peer_is_rockhopper ){

				if( s_pld_ctx->internal_netmask_flag ){

					_rhp_ikev2_rx_cfg_rep_internal_subnets_dmy_gw(vpn,ikesa,s_pld_ctx,rlm,
							AF_INET,&dmy_gateway_addr_v4);

					if( dmy_gateway_addr_v4.addr_family == AF_INET &&
							dmy_gateway_addr_v4.addr.v4 ){

						rhp_ip_addr_list* peer_addr;

						gateway_addr_v4_p = &dmy_gateway_addr_v4;

						peer_addr = rhp_ip_dup_addr_list(gateway_addr_v4_p);
						if( peer_addr ){

							peer_addr->next = vpn->internal_net_info.peer_addrs;
							vpn->internal_net_info.peer_addrs = peer_addr;

							static_cache++;

							RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REP_L_ADD_DUMMY_PEER_ADDR,"xxxM",rx_resp_ikemesg,vpn,rlm,vpn->internal_net_info.dummy_peer_mac);
							rhp_ip_addr_dump("dmy_gateway_addr_v4",gateway_addr_v4_p);

						}else{
							err = -ENOMEM;
							RHP_BUG("");
							goto error;
						}
					}
				}
			}

			if( gateway_addr_v4_p ){

				memcpy(&(rlm->ext_internal_gateway_addr),gateway_addr_v4_p,sizeof(rhp_ip_addr));

				RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_CFG_RESP_INTERNAL_GATEWAY,"KVP4d",rx_resp_ikemesg,vpn,ikesa,gateway_addr_v4_p->addr.v4,(gateway_addr_v4_p == &dmy_gateway_addr_v4 ? 1 : 0));
				RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REP_INTERNAL_SUBNETS_V4_EXT_ITNL_GW,"xxx4",vpn,ikesa,rx_resp_ikemesg,gateway_addr_v4_p->addr.v4);

			}else if( tx_interface[0] != '\0' ){

				snprintf(tx_interface,RHP_IFNAMSIZ,"%s%lu",RHP_VIRTUAL_IF_NAME,rlm->id);

				RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_CFG_RESP_FWD_PKT_DEST_INTERNALNET_TO_DEV,"KVPs",rx_resp_ikemesg,vpn,ikesa,tx_interface);
				RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REP_INTERNAL_SUBNETS_V4_EXT_ITNL_TX_IF,"xxxs",vpn,ikesa,rx_resp_ikemesg,tx_interface);
			}

			while( sn_v4 ){

				err = rlm->rtmap_put_ikev2_cfg(rlm,&(sn_v4->subnet),gateway_addr_v4_p,tx_interface);
				if( err ){
					RHP_BUG("%d",err);
					goto error;
				}

				RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_CFG_RESP_INTERNAL_SUBNET,"KVP44dAs",rx_resp_ikemesg,vpn,ikesa,sn_v4->subnet.addr.v4,sn_v4->subnet.netmask.v4,sn_v4->subnet.prefixlen,gateway_addr_v4_p,tx_interface);

				sn_v4 = sn_v4->next;
			}
  	}


  	if( s_pld_ctx->subnets_v6 ){

  	  memset(&dmy_gateway_addr_v6,0,sizeof(rhp_ip_addr));
  	  tx_interface[0] = '\0';

  		if( s_pld_ctx->internal_gateway_v6_flag &&
  				!rhp_ip_addr_null(&(s_pld_ctx->gw_addr_v6)) ){

				gateway_addr_v6_p = &(s_pld_ctx->gw_addr_v6);
				RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REP_INTERNAL_SUBNETS_V6_1,"xxx",vpn,ikesa,rx_resp_ikemesg);

  		}else if( vpn->internal_net_info.static_peer_addr ){

				gateway_addr_v6_p = _rhp_ikev2_cfg_get_static_peer(vpn,AF_INET6);
				RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REP_INTERNAL_SUBNETS_V6_2,"xxx",vpn,ikesa,rx_resp_ikemesg);

			}else if( !vpn->peer_is_rockhopper ){

				_rhp_ikev2_rx_cfg_rep_internal_subnets_dmy_gw(vpn,ikesa,s_pld_ctx,rlm,
						AF_INET6,&dmy_gateway_addr_v6);

				if( dmy_gateway_addr_v6.addr_family == AF_INET6 &&
						!rhp_ipv6_addr_null(dmy_gateway_addr_v6.addr.v6) ){

					rhp_ip_addr_list* peer_addr;

					gateway_addr_v6_p = &dmy_gateway_addr_v6;

					peer_addr = rhp_ip_dup_addr_list(gateway_addr_v6_p);
					if( peer_addr ){

						peer_addr->next = vpn->internal_net_info.peer_addrs;
						vpn->internal_net_info.peer_addrs = peer_addr;

						static_cache++;

						RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REP_L_ADD_DUMMY_PEER_ADDR_V6,"xxxM",rx_resp_ikemesg,vpn,rlm,vpn->internal_net_info.dummy_peer_mac);
						rhp_ip_addr_dump("dmy_gateway_addr_v6",gateway_addr_v6_p);

					}else{
						err = -ENOMEM;
						RHP_BUG("");
						goto error;
					}
				}
			}

			if( gateway_addr_v6_p ){

				memcpy(&(rlm->ext_internal_gateway_addr_v6),gateway_addr_v6_p,sizeof(rhp_ip_addr));

				RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_CFG_RESP_INTERNAL_GATEWAY_V6,"KVP6d",rx_resp_ikemesg,vpn,ikesa,gateway_addr_v6_p->addr.v6,(gateway_addr_v6_p == &dmy_gateway_addr_v6 ? 1 : 0));
				RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REP_INTERNAL_SUBNETS_V6_EXT_ITNL_GW,"xxx4",vpn,ikesa,rx_resp_ikemesg,gateway_addr_v6_p->addr.v6);

			}else if( tx_interface[0] != '\0' ){

				snprintf(tx_interface,RHP_IFNAMSIZ,"%s%lu",RHP_VIRTUAL_IF_NAME,rlm->id);

				RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_CFG_RESP_FWD_PKT_DEST_INTERNALNET_TO_DEV_V6,"KVPs",rx_resp_ikemesg,vpn,ikesa,tx_interface);
				RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REP_INTERNAL_SUBNETS_V6_EXT_ITNL_TX_IF,"xxxs",vpn,ikesa,rx_resp_ikemesg,tx_interface);
			}

			while( sn_v6 ){

				err = rlm->rtmap_put_ikev2_cfg(rlm,&(sn_v6->subnet),gateway_addr_v6_p,tx_interface);
				if( err ){
					RHP_BUG("%d",err);
					goto error;
				}

				RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_CFG_RESP_INTERNAL_SUBNET_V6,"KVP6dAs",rx_resp_ikemesg,vpn,ikesa,sn_v6->subnet.addr.v6,sn_v6->subnet.prefixlen,gateway_addr_v6_p,tx_interface);

				sn_v6 = sn_v6->next;
			}
  	}

  	if( static_cache ){

			err = rhp_bridge_static_cache_reset_for_vpn(vpn->vpn_realm_id,
							vpn,vpn->internal_net_info.dummy_peer_mac,
							vpn->internal_net_info.peer_addrs,RHP_BRIDGE_SCACHE_DUMMY);
			if( err ){
				RHP_BUG("%d",err);
			}
  	}

  	if( !rlm->internal_ifc->ikev2_config_ipv6_auto || !s_pld_ctx->ipv6_autoconf_flag ){

  		rhp_vpn_internal_route_update(vpn);
  	}

  	(*ok_r)++;
  }

  RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REP_INTERNAL_SUBNETS_RTRN,"xxxxdd",vpn,ikesa,rx_resp_ikemesg,s_pld_ctx,*ok_r,static_cache);
  return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REP_INTERNAL_SUBNETS_ERR,"xxxxE",vpn,ikesa,rx_resp_ikemesg,s_pld_ctx,err);
	return err;
}

static int _rhp_ikev2_rx_cfg_rep_internal_dns(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg* rx_resp_ikemesg,
		rhp_cp_rep_srch_pld_ctx* s_pld_ctx,rhp_vpn_realm* rlm,int* ok_r)
{
	int updated = 0;

	RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REP_INTERNAL_DNS,"xxxxxxddddddx",vpn,ikesa,rx_resp_ikemesg,s_pld_ctx,rlm,ok_r,s_pld_ctx->internal_dns_flag,s_pld_ctx->internal_dns_v6_flag,rlm->split_dns.static_internal_server_addr,rlm->split_dns.static_internal_server_addr_v6,rhp_gcfg_dns_pxy_fwd_any_queries_to_vpn_non_rockhopper,rhp_gcfg_dns_pxy_fwd_any_queries_to_vpn,s_pld_ctx->domains);

  if( s_pld_ctx->internal_dns_flag || s_pld_ctx->internal_dns_v6_flag ){

  	rhp_vpn_ikev2_cfg_split_dns_clear(rlm,vpn);

		if( s_pld_ctx->internal_dns_flag && !rlm->split_dns.static_internal_server_addr ){

			RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REP_INTERNAL_DNS_V4,"xxx",rx_resp_ikemesg,vpn,rlm);
			rhp_ip_addr_dump("_rhp_ikev2_rx_cfg_rep.s_pld_ctx",&(s_pld_ctx->dns_server_addr));
			rhp_ip_addr_dump("_rhp_ikev2_rx_cfg_rep.s_pld_rlm",&(rlm->split_dns.internal_server_addr));

			memcpy(&(rlm->split_dns.internal_server_addr),
					&(s_pld_ctx->dns_server_addr),sizeof(rhp_ip_addr));

			updated++;

			RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_CFG_RESP_INTERNAL_DNS_SERVER,"KVP4",rx_resp_ikemesg,vpn,ikesa,rlm->split_dns.internal_server_addr.addr.v4);
		}

		if( s_pld_ctx->internal_dns_v6_flag && !rlm->split_dns.static_internal_server_addr_v6 ){

			RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REP_INTERNAL_DNS_V6,"xxx",rx_resp_ikemesg,vpn,rlm);
			rhp_ip_addr_dump("_rhp_ikev2_rx_cfg_rep.s_pld_ctx_v6",&(s_pld_ctx->dns_server_addr_v6));
			rhp_ip_addr_dump("_rhp_ikev2_rx_cfg_rep.s_pld_rlm_v6",&(rlm->split_dns.internal_server_addr_v6));

			memcpy(&(rlm->split_dns.internal_server_addr_v6),
					&(s_pld_ctx->dns_server_addr_v6),sizeof(rhp_ip_addr));

			updated++;

			RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_CFG_RESP_INTERNAL_DNS_SERVER_V6,"KVP6",rx_resp_ikemesg,vpn,ikesa,rlm->split_dns.internal_server_addr_v6.addr.v6);
		}

		if( updated ){

			rhp_split_dns_domain* domain_tail = rlm->split_dns.domains;
			int rx_domains = 0;

			if( s_pld_ctx->domains ){

				domain_tail = rlm->split_dns.domains;
				while( domain_tail ){

					if( domain_tail->next == NULL ){
						break;
					}

					domain_tail = domain_tail->next;
				}

				{
					rhp_split_dns_domain* tdm = s_pld_ctx->domains;
					while( tdm ){
						RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_CFG_RESP_INTERNAL_DNS_SUFFIX,"KVPs",rx_resp_ikemesg,vpn,ikesa,tdm->name);
						RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REP_INTERNAL_DNS_SFX,"xxxs",rx_resp_ikemesg,vpn,ikesa,tdm->name);
						tdm = tdm->next;
					}
				}

				if( domain_tail ){

					domain_tail->next = s_pld_ctx->domains;

				}else{

					rlm->split_dns.domains = s_pld_ctx->domains;
				}

				s_pld_ctx->domains = NULL;
				rx_domains = 1;
			}

			if( rx_domains ){

				if( updated ){

		  		rhp_dns_pxy_inc_users();
		  	}

			}else{

				if( rlm->split_dns.domains == NULL &&
						((!vpn->peer_is_rockhopper && rhp_gcfg_dns_pxy_fwd_any_queries_to_vpn_non_rockhopper) ||
						 rhp_gcfg_dns_pxy_fwd_any_queries_to_vpn) ){

					if( updated && !vpn->internal_net_info.fwd_any_dns_queries ){

						vpn->internal_net_info.fwd_any_dns_queries = 1;

						_rhp_atomic_inc(&rhp_vpn_fwd_any_dns_queries);

			  		rhp_dns_pxy_inc_users();

			  		RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_CFG_RESP_FWD_ANY_DNS_QUERIES_ENABLED,"KVPu",rx_resp_ikemesg,vpn,ikesa,_rhp_atomic_read(&rhp_vpn_fwd_any_dns_queries));
						RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REP_INTERNAL_DNS_FWD_ANY_QUERIES_ENABLED,"xxx",rx_resp_ikemesg,vpn,ikesa);
			  	}
				}
			}


			if( rhp_dns_pxy_get_users() ){

				rhp_dns_pxy_main_start(AF_INET);
				rhp_dns_pxy_main_start(AF_INET6);
			}

			(*ok_r)++;
  	}
	}

  RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REP_INTERNAL_DNS_RTRN,"xxxdd",vpn,ikesa,rx_resp_ikemesg,*ok_r,updated);
  return 0;
}

static int _rhp_ikev2_rx_cfg_rep(rhp_vpn* vpn,rhp_ikesa* ikesa,
		rhp_ikev2_mesg* rx_resp_ikemesg,rhp_ikev2_mesg* tx_req_ikemesg)
{
	int err = -EINVAL;
	rhp_cp_rep_srch_pld_ctx s_pld_ctx;
	rhp_vpn_realm* rlm = NULL;
	int n = 0;

  RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REP_L,"xxxx",vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg);

	memset(&s_pld_ctx,0,sizeof(rhp_cp_rep_srch_pld_ctx));


	s_pld_ctx.peer_is_rockhopper = vpn->peer_is_rockhopper;

	rlm = vpn->rlm;

	if( rlm == NULL ){
		err = -EINVAL;
		RHP_BUG("");
		goto error;
	}

	RHP_LOCK(&(rlm->lock));

	if( !_rhp_atomic_read(&(rlm->is_active)) ){
		err = -EINVAL;
	  RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REP_L_RLM_NOT_ACTIVE,"xxx",rx_resp_ikemesg,vpn,rlm);
		goto error_rlm_l;
	}

	if( rlm->config_service != RHP_IKEV2_CONFIG_CLIENT ){
	  RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REP_L_RLM_CONFIG_CLIENT_DISABLED,"xxx",rx_resp_ikemesg,vpn,rlm);
		goto ignore;
	}

  {
  	err = rx_resp_ikemesg->search_payloads(rx_resp_ikemesg,0,
  			rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKE_PAYLOAD_CP),
  			_rhp_ikev2_cfg_srch_cp_rep_cb,&s_pld_ctx);

  	if( err != -ENOENT ){
  		RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_CFG_RESP_CP_PAYLOAD,"Kddd44d4dd4dE",rx_resp_ikemesg,s_pld_ctx.dup_flag,s_pld_ctx.internal_addr_flag,s_pld_ctx.internal_netmask_flag,s_pld_ctx.internal_addr.addr.v4,s_pld_ctx.internal_addr.netmask.v4,s_pld_ctx.internal_dns_flag,s_pld_ctx.dns_server_addr.addr.v4,(s_pld_ctx.domains ? 1 : 0),s_pld_ctx.internal_gateway_flag,s_pld_ctx.gw_addr.addr.v4,(s_pld_ctx.subnets ? 1 : 0),err);
  	}

    if( err && err != RHP_STATUS_ENUM_OK ){

    	if( err == -ENOENT ){
    	  RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REP_L_NO_CP_PAYLOAD,"xxxx",vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg);
    		goto ignore;
    	}

    	RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REP_L_INVALID_CP_PAYLOAD,"xxxxE",vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg,err);

    	err = RHP_STATUS_INVALID_MSG;
    	goto error_rlm_l;
    }
  }

  {
  	u8 cfg_type = s_pld_ctx.cp_payload->ext.cp->get_cfg_type(s_pld_ctx.cp_payload);
		if( cfg_type != RHP_PROTO_IKE_CFG_REPLY ){
			RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REP_L_NOT_CFG_REPLY,"xxx",rx_resp_ikemesg,vpn,rlm);
    	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_CFG_RESP_NOT_SUPPORTED_CFG_TYPE,"KbVP",rx_resp_ikemesg,cfg_type,vpn,ikesa);
			goto ignore;
		}
  }

  if( s_pld_ctx.app_ver_flag ){

  	RHP_LOG_I(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_CFG_RESP_APP_VER,"Ks",rx_resp_ikemesg,s_pld_ctx.app_ver);
  }


  {
		RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REP_L_NOT_CFG_REPLY_ADDR_ATTR_FLAGS,"xxxdddd",rx_resp_ikemesg,vpn,rlm,rlm->internal_ifc->ikev2_config_ipv6_auto,s_pld_ctx.internal_addr_v6_flag,s_pld_ctx.ipv6_autoconf_flag,s_pld_ctx.internal_addr_flag);

		if( !rlm->internal_ifc->ikev2_config_ipv6_auto ){
			s_pld_ctx.ipv6_autoconf_flag = 0;
		}

		if( !s_pld_ctx.internal_addr_v6_flag && s_pld_ctx.ipv6_autoconf_flag ){

			err = _rhp_ikev2_rx_cfg_rep_internal_addr_v6_autoconf(vpn,ikesa,
							rx_resp_ikemesg,&s_pld_ctx,rlm,&n);
			if( err ){
				goto error_rlm_l;
			}
		}

		if( s_pld_ctx.internal_addr_flag || s_pld_ctx.internal_addr_v6_flag ){

			err = _rhp_ikev2_rx_cfg_rep_internal_addr(vpn,ikesa,
							rx_resp_ikemesg,&s_pld_ctx,rlm,&n);
			if( err ){
				goto error_rlm_l;
			}
		}
  }


  if( s_pld_ctx.subnets || s_pld_ctx.subnets_v6 ){

  	err = _rhp_ikev2_rx_cfg_rep_internal_subnets(vpn,ikesa,
  					rx_resp_ikemesg,&s_pld_ctx,rlm,&n);
  	if( err ){
  		goto error_rlm_l;
  	}
  }

  if( s_pld_ctx.internal_dns_flag || s_pld_ctx.internal_dns_v6_flag ){

  	err = _rhp_ikev2_rx_cfg_rep_internal_dns(vpn,ikesa,
  					rx_resp_ikemesg,&s_pld_ctx,rlm,&n);
  	if( err ){
  		goto error_rlm_l;
  	}
  }

  if( n ){

  	if( (rlm->access_point_peer == NULL) && (rlm->access_point_peer_vpn_ref == NULL) ){

  	  RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REP_L_SET_ACCESS_POINT,"xxx",rx_resp_ikemesg,vpn,rlm);

  		vpn->cfg_peer->is_access_point = 1;

  		rlm->set_access_point(rlm,vpn);

  		RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_CFG_RESP_PEER_IS_ACCESSPOINT,"KVP",rx_resp_ikemesg,vpn,ikesa);

  	}else{

  		if( rlm->access_point_peer ){

  			rhp_ikev2_id_dump("access_point_peer_cfg",&(rlm->access_point_peer->id));
  			rhp_ip_addr_dump("primary_addr",&(rlm->access_point_peer->primary_addr));
  			rhp_ip_addr_dump("secondary_addr",&(rlm->access_point_peer->secondary_addr));
  		}
  	}
  }

	RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_CFG_RESP_OK,"KVP",rx_resp_ikemesg,vpn,ikesa);

ignore:
	RHP_UNLOCK(&(rlm->lock));

	_rhp_ikev2_cfg_clear_rep_srch_ctx(&s_pld_ctx);

  RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REP_L_RTRN,"xxxx",vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg);
	return 0;

error_rlm_l:
		RHP_UNLOCK(&(rlm->lock));
error:
	_rhp_ikev2_cfg_clear_rep_srch_ctx(&s_pld_ctx);

	RHP_LOG_E(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_CFG_RESP_ERR,"KVPE",rx_resp_ikemesg,vpn,ikesa,err);

  RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REP_L_ERR,"xxxxE",vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg,err);
	return err;
}

int rhp_ikev2_tx_cfg_req(rhp_ikev2_mesg* tx_req_ikemesg,rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,int req_initiator)
{
	int err = -EINVAL;
	rhp_ikesa* ikesa = NULL;

  RHP_TRC(0,RHPTRCID_IKEV2_TX_CFG_REQ,"xxLdGLd",tx_req_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,"IKEV2_MESG_HDLR",req_initiator);

	if( req_initiator == RHP_IKEV2_MESG_HANDLER_REKEY ){

		if( vpn->cfg_peer && !vpn->cfg_peer->is_access_point ){
		  RHP_TRC(0,RHPTRCID_IKEV2_TX_CFG_REQ_PEER_NOT_ACCESSPOINT,"xxLdG",tx_req_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi);
			goto ignore;
		}

		if( my_ikesa_spi == NULL ){
		  RHP_TRC(0,RHPTRCID_IKEV2_TX_CFG_REQ_NO_MY_IKESA_SPI,"xxLd",tx_req_ikemesg,vpn,"IKE_SIDE",my_ikesa_side);
			err = -EINVAL;
			goto error;
		}

		ikesa = vpn->ikesa_get(vpn,my_ikesa_side,my_ikesa_spi);
		if( ikesa == NULL ){
			err = -ENOENT;
		  RHP_TRC(0,RHPTRCID_IKEV2_TX_CFG_REQ_NO_IKESA,"xxLdG",tx_req_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi);
			goto error;
		}

		err = _rhp_ikev2_cfg_new_pkt_req(vpn,ikesa,tx_req_ikemesg);
		if( err ){
			goto error;
		}
	}

ignore:
	RHP_TRC(0,RHPTRCID_IKEV2_TX_CFG_REQ_RTRN,"xxLd",tx_req_ikemesg,vpn,"IKEV2_MESG_HDLR",req_initiator);
	return 0;

error:
	RHP_LOG_E(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_TX_CFG_REQ_REKEY_ERR,"VPE",vpn,ikesa,err);
	RHP_TRC(0,RHPTRCID_IKEV2_TX_CFG_REQ_ERR,"xxLdE",tx_req_ikemesg,vpn,"IKEV2_MESG_HDLR",req_initiator,err);
  return err;
}

int rhp_ikev2_rx_cfg_req(rhp_ikev2_mesg* rx_req_ikemesg,rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,rhp_ikev2_mesg* tx_resp_ikemesg)
{
	int err = -EINVAL;
	rhp_ikesa* ikesa = NULL;
	u8 exchange_type = rx_req_ikemesg->get_exchange_type(rx_req_ikemesg);

  RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REQ,"xxLdGxLbx",rx_req_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,tx_resp_ikemesg,"PROTO_IKE_EXCHG",exchange_type,vpn->cfg_peer);

	if( vpn->cfg_peer && vpn->cfg_peer->is_access_point ){
		return 0;
	}

	if( exchange_type == RHP_PROTO_IKE_EXCHG_IKE_SA_INIT ||
			exchange_type == RHP_PROTO_IKE_EXCHG_SESS_RESUME ){
		err = 0;
	  RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REQ_NOT_INTERESTED,"x",rx_req_ikemesg);
		goto ignore;
	}

  if( !rx_req_ikemesg->decrypted ){
  	err = 0;
	  RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REQ_NOT_DECRYPTED,"x",rx_req_ikemesg);
  	goto ignore;
  }

	if( my_ikesa_spi == NULL ){
		RHP_BUG("");
		err = -EINVAL;
		goto error;
	}

	ikesa = vpn->ikesa_get(vpn,my_ikesa_side,my_ikesa_spi);
	if( ikesa == NULL ){
		err = -ENOENT;
	  RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REQ_NO_IKESA2,"xxLdG",rx_req_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi);
		goto error;
	}

	err = _rhp_ikev2_rx_cfg_req(vpn,ikesa,rx_req_ikemesg,tx_resp_ikemesg);

error:
ignore:
	RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REQ_RTRN,"xxxE",rx_req_ikemesg,vpn,tx_resp_ikemesg,err);
  return err;
}

int rhp_ikev2_rx_cfg_rep(rhp_ikev2_mesg* rx_resp_ikemesg,rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,rhp_ikev2_mesg* tx_req_ikemesg)
{
	int err = -EINVAL;
	rhp_ikesa* ikesa = NULL;
	u8 exchange_type = rx_resp_ikemesg->get_exchange_type(rx_resp_ikemesg);

  RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REP,"xxLdGxLbx",rx_resp_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,tx_req_ikemesg,"PROTO_IKE_EXCHG",exchange_type,vpn->cfg_peer);

	if( my_ikesa_spi == NULL ){
		RHP_BUG("");
		err = -EINVAL;
		goto error;
	}

	ikesa = vpn->ikesa_get(vpn,my_ikesa_side,my_ikesa_spi);
	if( ikesa == NULL ){
		err = -ENOENT;
	  RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REP_NO_IKESA2,"xxLdG",rx_resp_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi);
		goto error;
	}


	if( exchange_type == RHP_PROTO_IKE_EXCHG_IKE_SA_INIT ||
			exchange_type == RHP_PROTO_IKE_EXCHG_SESS_RESUME ){

		err = _rhp_ikev2_cfg_new_pkt_req(vpn,ikesa,tx_req_ikemesg);

	}else{

	  if( !rx_resp_ikemesg->decrypted ){
	  	err = 0;
		  RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REP_NO_IKESA2_NOT_DECRYPTED,"xxLdG",rx_resp_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi);
	  	goto error;
	  }

		err = _rhp_ikev2_rx_cfg_rep(vpn,ikesa,rx_resp_ikemesg,tx_req_ikemesg);
	}

error:
	RHP_TRC(0,RHPTRCID_IKEV2_RX_CFG_REP_RTRN,"xxxE",rx_resp_ikemesg,vpn,tx_req_ikemesg,err);
  return err;
}


rhp_ikev2_traffic_selector* rhp_ikev2_cfg_my_v6_ra_tss = NULL;
rhp_ikev2_traffic_selector* rhp_ikev2_cfg_peer_v6_ra_tss = NULL;

int rhp_ikev2_cfg_alloc_v6_ra_tss(int type)
{
	int err = -EINVAL;
	rhp_proto_ike_ts_selector *my_tss[RHP_IKEV2_CFG_IPV6_RA_TSS_NUM], *peer_tss[RHP_IKEV2_CFG_IPV6_RA_TSS_NUM];
	rhp_ikev2_traffic_selector *my_tss_m[RHP_IKEV2_CFG_IPV6_RA_TSS_NUM], *peer_tss_m[RHP_IKEV2_CFG_IPV6_RA_TSS_NUM];
	u8 *start_addr, *end_addr;
	int i, my_tss_num, peer_tss_num;

  RHP_TRC(0,RHPTRCID_IKEV2_CFG_ALLOC_V6_RA_TSS,"ddxx",type,RHP_IKEV2_CFG_IPV6_RA_TSS_NUM,rhp_ikev2_cfg_my_v6_ra_tss,rhp_ikev2_cfg_peer_v6_ra_tss);

  memset(my_tss,(long)NULL,sizeof(rhp_proto_ike_ts_selector*)*RHP_IKEV2_CFG_IPV6_RA_TSS_NUM);
  memset(peer_tss,(long)NULL,sizeof(rhp_proto_ike_ts_selector*)*RHP_IKEV2_CFG_IPV6_RA_TSS_NUM);
  memset(my_tss_m,(long)NULL,sizeof(rhp_ikev2_traffic_selector*)*RHP_IKEV2_CFG_IPV6_RA_TSS_NUM);
  memset(peer_tss_m,(long)NULL,sizeof(rhp_ikev2_traffic_selector*)*RHP_IKEV2_CFG_IPV6_RA_TSS_NUM);

def_type:
  if( type == RHP_IKEV2_CFG_IPV6_RA_TSS_RA ){

  	my_tss_num = 2;
  	peer_tss_num = 3;

  }else if( type == RHP_IKEV2_CFG_IPV6_RA_TSS_ICMPV6 ){

  	my_tss_num = 2;
  	peer_tss_num = 2;

  }else if( type == RHP_IKEV2_CFG_IPV6_RA_TSS_ICMPV6_ADDR_ANY ){

  	my_tss_num = 1;
  	peer_tss_num = 1;

  }else if( type == RHP_IKEV2_CFG_IPV6_RA_TSS_RA_ADDR_ANY ){

  	my_tss_num = 1;
  	peer_tss_num = 1;

  }else{

  	RHP_BUG("%d",type);

  	type = RHP_IKEV2_CFG_IPV6_RA_TSS_ICMPV6;
  	goto def_type;
  }

  if( my_tss_num > RHP_IKEV2_CFG_IPV6_RA_TSS_NUM ||
  		peer_tss_num > RHP_IKEV2_CFG_IPV6_RA_TSS_NUM ){
  	RHP_BUG("%d, %d",my_tss_num,peer_tss_num);
  	return -EINVAL;
  }

	for( i = 0; i < my_tss_num; i++ ){

		my_tss[i] = (rhp_proto_ike_ts_selector*)_rhp_malloc(sizeof(rhp_proto_ike_ts_selector) + 32);
		if( my_tss[i] == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}
		memset(my_tss[i],0,sizeof(rhp_proto_ike_ts_selector) + 32);

	  err = rhp_ikev2_alloc_ts(RHP_PROTO_IKE_TS_IPV6_ADDR_RANGE,&(my_tss_m[i]));
	  if( err ){
			RHP_BUG("");
			goto error;
	  }

	  my_tss_m[i]->tsh = my_tss[i];

	  if( i > 0 ){
		  my_tss_m[i - 1]->next = my_tss_m[i];
	  }
	}

	for( i = 0; i < peer_tss_num; i++ ){

		peer_tss[i] = (rhp_proto_ike_ts_selector*)_rhp_malloc(sizeof(rhp_proto_ike_ts_selector) + 32);
		if( peer_tss[i] == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}
		memset(peer_tss[i],0,sizeof(rhp_proto_ike_ts_selector) + 32);

	  err = rhp_ikev2_alloc_ts(RHP_PROTO_IKE_TS_IPV6_ADDR_RANGE,&(peer_tss_m[i]));
	  if( err ){
			RHP_BUG("");
			goto error;
	  }

	  peer_tss_m[i]->tsh = peer_tss[i];

	  if( i > 0 ){
		  peer_tss_m[i - 1]->next = peer_tss_m[i];
	  }
	}

	if( type == RHP_IKEV2_CFG_IPV6_RA_TSS_RA ){

		{
			my_tss[0]->ts_type = RHP_PROTO_IKE_TS_IPV6_ADDR_RANGE;
			my_tss[0]->ip_protocol_id = RHP_PROTO_IP_IPV6_ICMP;
			my_tss[0]->len = htons(sizeof(rhp_proto_ike_ts_selector) + 32);
			my_tss[0]->start_port.icmp.type = RHP_PROTO_ICMP6_TYPE_ROUTER_SOLICIT;
			my_tss[0]->start_port.icmp.code = 0;
			my_tss[0]->end_port.icmp.type = RHP_PROTO_ICMP6_TYPE_ROUTER_SOLICIT;
			my_tss[0]->end_port.icmp.code = 0xFF;
			start_addr = (u8*)(my_tss[0] + 1);
			end_addr = start_addr + 16;

			memcpy(start_addr,rhp_ipv6_all_router_multicast_addr->addr.v6,16);
			memcpy(end_addr,rhp_ipv6_all_router_multicast_addr->addr.v6,16);
		}
		{
			my_tss[1]->ts_type = RHP_PROTO_IKE_TS_IPV6_ADDR_RANGE;
			my_tss[1]->ip_protocol_id = RHP_PROTO_IP_IPV6_ICMP;
			my_tss[1]->len = htons(sizeof(rhp_proto_ike_ts_selector) + 32);
			my_tss[1]->start_port.icmp.type = RHP_PROTO_ICMP6_TYPE_ROUTER_ADV;
			my_tss[1]->start_port.icmp.code = 0;
			my_tss[1]->end_port.icmp.type = RHP_PROTO_ICMP6_TYPE_ROUTER_ADV;
			my_tss[1]->end_port.icmp.code = 0xFF;
			start_addr = (u8*)(my_tss[1] + 1);
			end_addr = start_addr + 16;

			start_addr[0] = 0xFE;
			start_addr[1] = 0x80;
			end_addr[0] = 0xFE;
			end_addr[1] = 0x80;
			for( i = 2; i < 16; i++ ){
				start_addr[i] = 0;
				end_addr[i] = 0xFF;
			}
		}

		{
			peer_tss[0]->ts_type = RHP_PROTO_IKE_TS_IPV6_ADDR_RANGE;
			peer_tss[0]->ip_protocol_id = RHP_PROTO_IP_IPV6_ICMP;
			peer_tss[0]->len = htons(sizeof(rhp_proto_ike_ts_selector) + 32);
			peer_tss[0]->start_port.icmp.type = RHP_PROTO_ICMP6_TYPE_ROUTER_SOLICIT;
			peer_tss[0]->start_port.icmp.code = 0;
			peer_tss[0]->end_port.icmp.type = RHP_PROTO_ICMP6_TYPE_ROUTER_SOLICIT;
			peer_tss[0]->end_port.icmp.code = 0xFF;
			start_addr = (u8*)(peer_tss[0] + 1);
			end_addr = start_addr + 16;

			start_addr[0] = 0xFE;
			start_addr[1] = 0x80;
			end_addr[0] = 0xFE;
			end_addr[1] = 0x80;
			for( i = 2; i < 16; i++ ){
				start_addr[i] = 0;
				end_addr[i] = 0xFF;
			}
		}
		{
			peer_tss[1]->ts_type = RHP_PROTO_IKE_TS_IPV6_ADDR_RANGE;
			peer_tss[1]->ip_protocol_id = RHP_PROTO_IP_IPV6_ICMP;
			peer_tss[1]->len = htons(sizeof(rhp_proto_ike_ts_selector) + 32);
			peer_tss[1]->start_port.icmp.type = RHP_PROTO_ICMP6_TYPE_ROUTER_ADV;
			peer_tss[1]->start_port.icmp.code = 0;
			peer_tss[1]->end_port.icmp.type = RHP_PROTO_ICMP6_TYPE_ROUTER_ADV;
			peer_tss[1]->end_port.icmp.code = 0xFF;
			start_addr = (u8*)(peer_tss[1] + 1);
			end_addr = start_addr + 16;

			start_addr[0] = 0xFE;
			start_addr[1] = 0x80;
			end_addr[0] = 0xFE;
			end_addr[1] = 0x80;
			for( i = 2; i < 16; i++ ){
				start_addr[i] = 0;
				end_addr[i] = 0xFF;
			}
		}
		{
			peer_tss[2]->ts_type = RHP_PROTO_IKE_TS_IPV6_ADDR_RANGE;
			peer_tss[2]->ip_protocol_id = RHP_PROTO_IP_IPV6_ICMP;
			peer_tss[2]->len = htons(sizeof(rhp_proto_ike_ts_selector) + 32);
			peer_tss[2]->start_port.icmp.type = RHP_PROTO_ICMP6_TYPE_ROUTER_ADV;
			peer_tss[2]->start_port.icmp.code = 0;
			peer_tss[2]->end_port.icmp.type = RHP_PROTO_ICMP6_TYPE_ROUTER_ADV;
			peer_tss[2]->end_port.icmp.code = 0xFF;
			start_addr = (u8*)(peer_tss[2] + 1);
			end_addr = start_addr + 16;

			memcpy(start_addr,rhp_ipv6_all_node_multicast_addr->addr.v6,16);
			memcpy(end_addr,rhp_ipv6_all_node_multicast_addr->addr.v6,16);
		}

	}else if( type == RHP_IKEV2_CFG_IPV6_RA_TSS_ICMPV6 ){

		{
			my_tss[0]->ts_type = RHP_PROTO_IKE_TS_IPV6_ADDR_RANGE;
			my_tss[0]->ip_protocol_id = RHP_PROTO_IP_IPV6_ICMP;
			my_tss[0]->len = htons(sizeof(rhp_proto_ike_ts_selector) + 32);
			my_tss[0]->start_port.icmp.type = 0;
			my_tss[0]->start_port.icmp.code = 0;
			my_tss[0]->end_port.icmp.type = 0xFF;
			my_tss[0]->end_port.icmp.code = 0xFF;
			start_addr = (u8*)(my_tss[0] + 1);
			end_addr = start_addr + 16;

			start_addr[0] = 0xFE;
			start_addr[1] = 0x80;
			end_addr[0] = 0xFE;
			end_addr[1] = 0x80;
			for( i = 2; i < 16; i++ ){
				start_addr[i] = 0;
				end_addr[i] = 0xFF;
			}
		}
		{
			my_tss[1]->ts_type = RHP_PROTO_IKE_TS_IPV6_ADDR_RANGE;
			my_tss[1]->ip_protocol_id = RHP_PROTO_IP_IPV6_ICMP;
			my_tss[1]->len = htons(sizeof(rhp_proto_ike_ts_selector) + 32);
			my_tss[1]->start_port.icmp.type = 0;
			my_tss[1]->start_port.icmp.code = 0;
			my_tss[1]->end_port.icmp.type = 0xFF;
			my_tss[1]->end_port.icmp.code = 0xFF;
			start_addr = (u8*)(my_tss[1] + 1);
			end_addr = start_addr + 16;

			memcpy(start_addr,rhp_ipv6_all_router_multicast_addr->addr.v6,16);
			memcpy(end_addr,rhp_ipv6_all_router_multicast_addr->addr.v6,16);
		}

		{
			peer_tss[0]->ts_type = RHP_PROTO_IKE_TS_IPV6_ADDR_RANGE;
			peer_tss[0]->ip_protocol_id = RHP_PROTO_IP_IPV6_ICMP;
			peer_tss[0]->len = htons(sizeof(rhp_proto_ike_ts_selector) + 32);
			peer_tss[0]->start_port.icmp.type = 0;
			peer_tss[0]->start_port.icmp.code = 0;
			peer_tss[0]->end_port.icmp.type = 0xFF;
			peer_tss[0]->end_port.icmp.code = 0xFF;
			start_addr = (u8*)(peer_tss[0] + 1);
			end_addr = start_addr + 16;

			memcpy(start_addr,rhp_ipv6_all_node_multicast_addr->addr.v6,16);
			memcpy(end_addr,rhp_ipv6_all_node_multicast_addr->addr.v6,16);
		}
		{
			peer_tss[1]->ts_type = RHP_PROTO_IKE_TS_IPV6_ADDR_RANGE;
			peer_tss[1]->ip_protocol_id = RHP_PROTO_IP_IPV6_ICMP;
			peer_tss[1]->len = htons(sizeof(rhp_proto_ike_ts_selector) + 32);
			peer_tss[1]->start_port.icmp.type = 0;
			peer_tss[1]->start_port.icmp.code = 0;
			peer_tss[1]->end_port.icmp.type = 0xFF;
			peer_tss[1]->end_port.icmp.code = 0xFF;
			start_addr = (u8*)(peer_tss[1] + 1);
			end_addr = start_addr + 16;

			start_addr[0] = 0xFE;
			start_addr[1] = 0x80;
			end_addr[0] = 0xFE;
			end_addr[1] = 0x80;
			for( i = 2; i < 16; i++ ){
				start_addr[i] = 0;
				end_addr[i] = 0xFF;
			}
		}

	}else if( type == RHP_IKEV2_CFG_IPV6_RA_TSS_ICMPV6_ADDR_ANY ){

		{
			my_tss[0]->ts_type = RHP_PROTO_IKE_TS_IPV6_ADDR_RANGE;
			my_tss[0]->ip_protocol_id = RHP_PROTO_IP_IPV6_ICMP;
			my_tss[0]->len = htons(sizeof(rhp_proto_ike_ts_selector) + 32);
			my_tss[0]->start_port.icmp.type = 0;
			my_tss[0]->start_port.icmp.code = 0;
			my_tss[0]->end_port.icmp.type = 0xFF;
			my_tss[0]->end_port.icmp.code = 0xFF;
			start_addr = (u8*)(my_tss[0] + 1);
			end_addr = start_addr + 16;

			for( i = 0; i < 16; i++ ){
				start_addr[i] = 0;
				end_addr[i] = 0xFF;
			}
		}
		{
			peer_tss[0]->ts_type = RHP_PROTO_IKE_TS_IPV6_ADDR_RANGE;
			peer_tss[0]->ip_protocol_id = RHP_PROTO_IP_IPV6_ICMP;
			peer_tss[0]->len = htons(sizeof(rhp_proto_ike_ts_selector) + 32);
			peer_tss[0]->start_port.icmp.type = 0;
			peer_tss[0]->start_port.icmp.code = 0;
			peer_tss[0]->end_port.icmp.type = 0xFF;
			peer_tss[0]->end_port.icmp.code = 0xFF;
			start_addr = (u8*)(peer_tss[0] + 1);
			end_addr = start_addr + 16;

			for( i = 0; i < 16; i++ ){
				start_addr[i] = 0;
				end_addr[i] = 0xFF;
			}
		}

	}else if( type == RHP_IKEV2_CFG_IPV6_RA_TSS_RA_ADDR_ANY ){

		{
			my_tss[0]->ts_type = RHP_PROTO_IKE_TS_IPV6_ADDR_RANGE;
			my_tss[0]->ip_protocol_id = RHP_PROTO_IP_IPV6_ICMP;
			my_tss[0]->len = htons(sizeof(rhp_proto_ike_ts_selector) + 32);
			my_tss[0]->start_port.icmp.type = RHP_PROTO_ICMP6_TYPE_ROUTER_SOLICIT;
			my_tss[0]->start_port.icmp.code = 0;
			my_tss[0]->end_port.icmp.type = RHP_PROTO_ICMP6_TYPE_ROUTER_ADV;
			my_tss[0]->end_port.icmp.code = 0xFF;
			start_addr = (u8*)(my_tss[0] + 1);
			end_addr = start_addr + 16;

			for( i = 0; i < 16; i++ ){
				start_addr[i] = 0;
				end_addr[i] = 0xFF;
			}
		}
		{
			peer_tss[0]->ts_type = RHP_PROTO_IKE_TS_IPV6_ADDR_RANGE;
			peer_tss[0]->ip_protocol_id = RHP_PROTO_IP_IPV6_ICMP;
			peer_tss[0]->len = htons(sizeof(rhp_proto_ike_ts_selector) + 32);
			peer_tss[0]->start_port.icmp.type = RHP_PROTO_ICMP6_TYPE_ROUTER_SOLICIT;
			peer_tss[0]->start_port.icmp.code = 0;
			peer_tss[0]->end_port.icmp.type = RHP_PROTO_ICMP6_TYPE_ROUTER_ADV;
			peer_tss[0]->end_port.icmp.code = 0xFF;
			start_addr = (u8*)(peer_tss[0] + 1);
			end_addr = start_addr + 16;

			for( i = 0; i < 16; i++ ){
				start_addr[i] = 0;
				end_addr[i] = 0xFF;
			}
		}
	}

	rhp_ikev2_cfg_my_v6_ra_tss = my_tss_m[0];
	rhp_ikev2_cfg_peer_v6_ra_tss = peer_tss_m[0];

	rhp_ikev2_cfg_my_v6_ra_tss->dump(rhp_ikev2_cfg_my_v6_ra_tss,"rhp_ikev2_cfg_my_v6_ra_tss");
	rhp_ikev2_cfg_peer_v6_ra_tss->dump(rhp_ikev2_cfg_peer_v6_ra_tss,"rhp_ikev2_cfg_peer_v6_ra_tss");

  RHP_TRC(0,RHPTRCID_IKEV2_CFG_ALLOC_V6_RA_TSS_RTRN,"xxdd",rhp_ikev2_cfg_my_v6_ra_tss,rhp_ikev2_cfg_peer_v6_ra_tss,my_tss_num,peer_tss_num);
	return 0;

error:
	for( i = 0; i < RHP_IKEV2_CFG_IPV6_RA_TSS_NUM; i++ ){
		if( my_tss[i] ){
			_rhp_free(my_tss[i]);
		}
		if( peer_tss[i] ){
			_rhp_free(peer_tss[i]);
		}
		if( my_tss_m[i] ){
			rhp_ikev2_ts_payload_free_ts(my_tss_m[i]);
		}
		if(peer_tss_m[i]){
			rhp_ikev2_ts_payload_free_ts(peer_tss_m[i]);
		}
	}
  RHP_TRC(0,RHPTRCID_IKEV2_CFG_ALLOC_V6_RA_TSS_ERR,"xxddE",rhp_ikev2_cfg_my_v6_ra_tss,rhp_ikev2_cfg_peer_v6_ra_tss,my_tss_num,peer_tss_num,err);
	return err;
}


rhp_ikev2_traffic_selector* rhp_ikev2_cfg_my_v6_auto_tss = NULL;
rhp_ikev2_traffic_selector* rhp_ikev2_cfg_peer_v6_auto_tss = NULL;

int rhp_ikev2_cfg_alloc_v6_auto_tss(int type)
{
	int err = -EINVAL;
	rhp_proto_ike_ts_selector *my_tss[RHP_IKEV2_CFG_IPV6_AUTO_TSS_NUM], *peer_tss[RHP_IKEV2_CFG_IPV6_AUTO_TSS_NUM];
	rhp_ikev2_traffic_selector *my_tss_m[RHP_IKEV2_CFG_IPV6_AUTO_TSS_NUM], *peer_tss_m[RHP_IKEV2_CFG_IPV6_AUTO_TSS_NUM];
	u8 *start_addr, *end_addr;
	int i, my_tss_num, peer_tss_num;

  RHP_TRC(0,RHPTRCID_IKEV2_CFG_ALLOC_V6_AUTO_TSS,"ddxx",type,RHP_IKEV2_CFG_IPV6_AUTO_TSS_NUM,rhp_ikev2_cfg_my_v6_auto_tss,rhp_ikev2_cfg_peer_v6_auto_tss);

  memset(my_tss,(long)NULL,sizeof(rhp_proto_ike_ts_selector*)*RHP_IKEV2_CFG_IPV6_AUTO_TSS_NUM);
  memset(peer_tss,(long)NULL,sizeof(rhp_proto_ike_ts_selector*)*RHP_IKEV2_CFG_IPV6_AUTO_TSS_NUM);
  memset(my_tss_m,(long)NULL,sizeof(rhp_ikev2_traffic_selector*)*RHP_IKEV2_CFG_IPV6_AUTO_TSS_NUM);
  memset(peer_tss_m,(long)NULL,sizeof(rhp_ikev2_traffic_selector*)*RHP_IKEV2_CFG_IPV6_AUTO_TSS_NUM);

def_type:
  if( type == RHP_IKEV2_CFG_IPV6_AUTO_TSS_ICMPV6 ){

  	my_tss_num = 6;
  	peer_tss_num = 5;

  }else if( type == RHP_IKEV2_CFG_IPV6_AUTO_TSS_ICMPV6_ADDR_ANY ){

  	my_tss_num = 1;
  	peer_tss_num = 1;

  }else{

  	RHP_BUG("%d",type);

  	type = RHP_IKEV2_CFG_IPV6_RA_TSS_ICMPV6;
  	goto def_type;
  }

  if( my_tss_num > RHP_IKEV2_CFG_IPV6_AUTO_TSS_NUM ||
  		peer_tss_num > RHP_IKEV2_CFG_IPV6_AUTO_TSS_NUM ){
  	RHP_BUG("%d, %d",my_tss_num,peer_tss_num);
  	return -EINVAL;
  }

	for( i = 0; i < my_tss_num; i++ ){

		my_tss[i] = (rhp_proto_ike_ts_selector*)_rhp_malloc(sizeof(rhp_proto_ike_ts_selector) + 32);
		if( my_tss[i] == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}
		memset(my_tss[i],0,sizeof(rhp_proto_ike_ts_selector) + 32);

	  err = rhp_ikev2_alloc_ts(RHP_PROTO_IKE_TS_IPV6_ADDR_RANGE,&(my_tss_m[i]));
	  if( err ){
			RHP_BUG("");
			goto error;
	  }

	  my_tss_m[i]->tsh = my_tss[i];

	  if( i > 0 ){
		  my_tss_m[i - 1]->next = my_tss_m[i];
	  }
	}

	for( i = 0; i < peer_tss_num; i++ ){

		peer_tss[i] = (rhp_proto_ike_ts_selector*)_rhp_malloc(sizeof(rhp_proto_ike_ts_selector) + 32);
		if( peer_tss[i] == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}
		memset(peer_tss[i],0,sizeof(rhp_proto_ike_ts_selector) + 32);

	  err = rhp_ikev2_alloc_ts(RHP_PROTO_IKE_TS_IPV6_ADDR_RANGE,&(peer_tss_m[i]));
	  if( err ){
			RHP_BUG("");
			goto error;
	  }

	  peer_tss_m[i]->tsh = peer_tss[i];

	  if( i > 0 ){
		  peer_tss_m[i - 1]->next = peer_tss_m[i];
	  }
	}

	if( type == RHP_IKEV2_CFG_IPV6_AUTO_TSS_ICMPV6 ){

		{
			my_tss[0]->ts_type = RHP_PROTO_IKE_TS_IPV6_ADDR_RANGE;
			my_tss[0]->ip_protocol_id = RHP_PROTO_IP_IPV6_ICMP;
			my_tss[0]->len = htons(sizeof(rhp_proto_ike_ts_selector) + 32);
			my_tss[0]->start_port.icmp.type = 0;
			my_tss[0]->start_port.icmp.code = 0;
			my_tss[0]->end_port.icmp.type = 0xFF;
			my_tss[0]->end_port.icmp.code = 0xFF;
			start_addr = (u8*)(my_tss[0] + 1);
			end_addr = start_addr + 16;

			start_addr[0] = 0xFE;
			start_addr[1] = 0x80;
			end_addr[0] = 0xFE;
			end_addr[1] = 0x80;
			for( i = 2; i < 16; i++ ){
				start_addr[i] = 0;
				end_addr[i] = 0xFF;
			}
		}
		{
			my_tss[1]->ts_type = RHP_PROTO_IKE_TS_IPV6_ADDR_RANGE;
			my_tss[1]->ip_protocol_id = RHP_PROTO_IP_IPV6_ICMP;
			my_tss[1]->len = htons(sizeof(rhp_proto_ike_ts_selector) + 32);
			my_tss[1]->start_port.icmp.type = 0;
			my_tss[1]->start_port.icmp.code = 0;
			my_tss[1]->end_port.icmp.type = 0xFF;
			my_tss[1]->end_port.icmp.code = 0xFF;
			start_addr = (u8*)(my_tss[1] + 1);
			end_addr = start_addr + 16;

			memcpy(start_addr,rhp_ipv6_all_router_multicast_addr->addr.v6,16);
			memcpy(end_addr,rhp_ipv6_all_router_multicast_addr->addr.v6,16);
		}
		{
			my_tss[2]->ts_type = RHP_PROTO_IKE_TS_IPV6_ADDR_RANGE;
			my_tss[2]->ip_protocol_id = RHP_PROTO_IP_IPV6_ICMP;
			my_tss[2]->len = htons(sizeof(rhp_proto_ike_ts_selector) + 32);
			my_tss[2]->start_port.icmp.type = 0;
			my_tss[2]->start_port.icmp.code = 0;
			my_tss[2]->end_port.icmp.type = 0xFF;
			my_tss[2]->end_port.icmp.code = 0xFF;
			start_addr = (u8*)(my_tss[2] + 1);
			end_addr = start_addr + 16;

			memcpy(start_addr,rhp_ipv6_all_node_multicast_addr->addr.v6,16);
			memcpy(end_addr,rhp_ipv6_all_node_multicast_addr->addr.v6,16);
		}
		{
			my_tss[3]->ts_type = RHP_PROTO_IKE_TS_IPV6_ADDR_RANGE;
			my_tss[3]->ip_protocol_id = RHP_PROTO_IP_IPV6_ICMP;
			my_tss[3]->len = htons(sizeof(rhp_proto_ike_ts_selector) + 32);
			my_tss[3]->start_port.icmp.type = 0;
			my_tss[3]->start_port.icmp.code = 0;
			my_tss[3]->end_port.icmp.type = 0xFF;
			my_tss[3]->end_port.icmp.code = 0xFF;
			start_addr = (u8*)(my_tss[3] + 1);
			end_addr = start_addr + 16;

			memset(start_addr,0,16);
			memset(end_addr,0,16);
		}
		{
			my_tss[4]->ts_type = RHP_PROTO_IKE_TS_IPV6_ADDR_RANGE;
			my_tss[4]->ip_protocol_id = RHP_PROTO_IP_IPV6_ICMP;
			my_tss[4]->len = htons(sizeof(rhp_proto_ike_ts_selector) + 32);
			my_tss[4]->start_port.icmp.type = 0;
			my_tss[4]->start_port.icmp.code = 0;
			my_tss[4]->end_port.icmp.type = 0xFF;
			my_tss[4]->end_port.icmp.code = 0xFF;
			start_addr = (u8*)(my_tss[4] + 1);
			end_addr = start_addr + 16;

			memcpy(start_addr,rhp_ipv6_mld2_multicast_addr->addr.v6,16);
			memcpy(end_addr,rhp_ipv6_mld2_multicast_addr->addr.v6,16);
		}
		{
			my_tss[5]->ts_type = RHP_PROTO_IKE_TS_IPV6_ADDR_RANGE;
			my_tss[5]->ip_protocol_id = RHP_PROTO_IP_IPV6_ICMP;
			my_tss[5]->len = htons(sizeof(rhp_proto_ike_ts_selector) + 32);
			my_tss[5]->start_port.icmp.type = 0;
			my_tss[5]->start_port.icmp.code = 0;
			my_tss[5]->end_port.icmp.type = 0xFF;
			my_tss[5]->end_port.icmp.code = 0xFF;
			start_addr = (u8*)(my_tss[5] + 1);
			end_addr = start_addr + 16;

			start_addr[0] = 0xFF;
			start_addr[1] = 0x02;
			start_addr[2] = 0;
			start_addr[3] = 0;
			start_addr[4] = 0;
			start_addr[5] = 0;
			start_addr[6] = 0;
			start_addr[7] = 0;
			start_addr[8] = 0;
			start_addr[9] = 0;
			start_addr[10] = 0;
			start_addr[11] = 0x01;
			start_addr[12] = 0xff;

			end_addr[0] = 0xFF;
			end_addr[1] = 0x02;
			end_addr[2] = 0;
			end_addr[3] = 0;
			end_addr[4] = 0;
			end_addr[5] = 0;
			end_addr[6] = 0;
			end_addr[7] = 0;
			end_addr[8] = 0;
			end_addr[9] = 0;
			end_addr[10] = 0;
			end_addr[11] = 0x01;
			end_addr[12] = 0xff;

			for( i = 13; i < 16; i++ ){
				start_addr[i] = 0;
				end_addr[i] = 0xFF;
			}
		}


		{
			peer_tss[0]->ts_type = RHP_PROTO_IKE_TS_IPV6_ADDR_RANGE;
			peer_tss[0]->ip_protocol_id = RHP_PROTO_IP_IPV6_ICMP;
			peer_tss[0]->len = htons(sizeof(rhp_proto_ike_ts_selector) + 32);
			peer_tss[0]->start_port.icmp.type = 0;
			peer_tss[0]->start_port.icmp.code = 0;
			peer_tss[0]->end_port.icmp.type = 0xFF;
			peer_tss[0]->end_port.icmp.code = 0xFF;
			start_addr = (u8*)(peer_tss[0] + 1);
			end_addr = start_addr + 16;

			memcpy(start_addr,rhp_ipv6_all_node_multicast_addr->addr.v6,16);
			memcpy(end_addr,rhp_ipv6_all_node_multicast_addr->addr.v6,16);
		}
		{
			peer_tss[1]->ts_type = RHP_PROTO_IKE_TS_IPV6_ADDR_RANGE;
			peer_tss[1]->ip_protocol_id = RHP_PROTO_IP_IPV6_ICMP;
			peer_tss[1]->len = htons(sizeof(rhp_proto_ike_ts_selector) + 32);
			peer_tss[1]->start_port.icmp.type = 0;
			peer_tss[1]->start_port.icmp.code = 0;
			peer_tss[1]->end_port.icmp.type = 0xFF;
			peer_tss[1]->end_port.icmp.code = 0xFF;
			start_addr = (u8*)(peer_tss[1] + 1);
			end_addr = start_addr + 16;

			start_addr[0] = 0xFE;
			start_addr[1] = 0x80;
			end_addr[0] = 0xFE;
			end_addr[1] = 0x80;
			for( i = 2; i < 16; i++ ){
				start_addr[i] = 0;
				end_addr[i] = 0xFF;
			}
		}
		{
			peer_tss[2]->ts_type = RHP_PROTO_IKE_TS_IPV6_ADDR_RANGE;
			peer_tss[2]->ip_protocol_id = RHP_PROTO_IP_IPV6_ICMP;
			peer_tss[2]->len = htons(sizeof(rhp_proto_ike_ts_selector) + 32);
			peer_tss[2]->start_port.icmp.type = 0;
			peer_tss[2]->start_port.icmp.code = 0;
			peer_tss[2]->end_port.icmp.type = 0xFF;
			peer_tss[2]->end_port.icmp.code = 0xFF;
			start_addr = (u8*)(peer_tss[2] + 1);
			end_addr = start_addr + 16;

			memset(start_addr,0,16);
			memset(end_addr,0,16);
		}
		{
			peer_tss[3]->ts_type = RHP_PROTO_IKE_TS_IPV6_ADDR_RANGE;
			peer_tss[3]->ip_protocol_id = RHP_PROTO_IP_IPV6_ICMP;
			peer_tss[3]->len = htons(sizeof(rhp_proto_ike_ts_selector) + 32);
			peer_tss[3]->start_port.icmp.type = 0;
			peer_tss[3]->start_port.icmp.code = 0;
			peer_tss[3]->end_port.icmp.type = 0xFF;
			peer_tss[3]->end_port.icmp.code = 0xFF;
			start_addr = (u8*)(peer_tss[3] + 1);
			end_addr = start_addr + 16;

			memcpy(start_addr,rhp_ipv6_mld2_multicast_addr->addr.v6,16);
			memcpy(end_addr,rhp_ipv6_mld2_multicast_addr->addr.v6,16);
		}
		{
			peer_tss[4]->ts_type = RHP_PROTO_IKE_TS_IPV6_ADDR_RANGE;
			peer_tss[4]->ip_protocol_id = RHP_PROTO_IP_IPV6_ICMP;
			peer_tss[4]->len = htons(sizeof(rhp_proto_ike_ts_selector) + 32);
			peer_tss[4]->start_port.icmp.type = 0;
			peer_tss[4]->start_port.icmp.code = 0;
			peer_tss[4]->end_port.icmp.type = 0xFF;
			peer_tss[4]->end_port.icmp.code = 0xFF;
			start_addr = (u8*)(peer_tss[4] + 1);
			end_addr = start_addr + 16;

			start_addr[0] = 0xFF;
			start_addr[1] = 0x02;
			start_addr[2] = 0;
			start_addr[3] = 0;
			start_addr[4] = 0;
			start_addr[5] = 0;
			start_addr[6] = 0;
			start_addr[7] = 0;
			start_addr[8] = 0;
			start_addr[9] = 0;
			start_addr[10] = 0;
			start_addr[11] = 0x01;
			start_addr[12] = 0xff;

			end_addr[0] = 0xFF;
			end_addr[1] = 0x02;
			end_addr[2] = 0;
			end_addr[3] = 0;
			end_addr[4] = 0;
			end_addr[5] = 0;
			end_addr[6] = 0;
			end_addr[7] = 0;
			end_addr[8] = 0;
			end_addr[9] = 0;
			end_addr[10] = 0;
			end_addr[11] = 0x01;
			end_addr[12] = 0xff;

			for( i = 13; i < 16; i++ ){
				start_addr[i] = 0;
				end_addr[i] = 0xFF;
			}
		}

	}else if( type == RHP_IKEV2_CFG_IPV6_AUTO_TSS_ICMPV6_ADDR_ANY ){

		{
			my_tss[0]->ts_type = RHP_PROTO_IKE_TS_IPV6_ADDR_RANGE;
			my_tss[0]->ip_protocol_id = RHP_PROTO_IP_IPV6_ICMP;
			my_tss[0]->len = htons(sizeof(rhp_proto_ike_ts_selector) + 32);
			my_tss[0]->start_port.icmp.type = 0;
			my_tss[0]->start_port.icmp.code = 0;
			my_tss[0]->end_port.icmp.type = 0xFF;
			my_tss[0]->end_port.icmp.code = 0xFF;
			start_addr = (u8*)(my_tss[0] + 1);
			end_addr = start_addr + 16;

			for( i = 0; i < 16; i++ ){
				start_addr[i] = 0;
				end_addr[i] = 0xFF;
			}
		}

		{
			peer_tss[0]->ts_type = RHP_PROTO_IKE_TS_IPV6_ADDR_RANGE;
			peer_tss[0]->ip_protocol_id = RHP_PROTO_IP_IPV6_ICMP;
			peer_tss[0]->len = htons(sizeof(rhp_proto_ike_ts_selector) + 32);
			peer_tss[0]->start_port.icmp.type = 0;
			peer_tss[0]->start_port.icmp.code = 0;
			peer_tss[0]->end_port.icmp.type = 0xFF;
			peer_tss[0]->end_port.icmp.code = 0xFF;
			start_addr = (u8*)(peer_tss[0] + 1);
			end_addr = start_addr + 16;

			for( i = 0; i < 16; i++ ){
				start_addr[i] = 0;
				end_addr[i] = 0xFF;
			}
		}

	}

	rhp_ikev2_cfg_my_v6_auto_tss = my_tss_m[0];
	rhp_ikev2_cfg_peer_v6_auto_tss = peer_tss_m[0];

	rhp_ikev2_cfg_my_v6_auto_tss->dump(rhp_ikev2_cfg_my_v6_auto_tss,"rhp_ikev2_cfg_my_v6_auto_tss");
	rhp_ikev2_cfg_peer_v6_auto_tss->dump(rhp_ikev2_cfg_peer_v6_auto_tss,"rhp_ikev2_cfg_peer_v6_auto_tss");

  RHP_TRC(0,RHPTRCID_IKEV2_CFG_ALLOC_V6_AUTO_TSS_RTRN,"xxdd",rhp_ikev2_cfg_my_v6_auto_tss,rhp_ikev2_cfg_peer_v6_auto_tss,my_tss_num,peer_tss_num);
	return 0;

error:
	for( i = 0; i < RHP_IKEV2_CFG_IPV6_AUTO_TSS_NUM; i++ ){
		if( my_tss[i] ){
			_rhp_free(my_tss[i]);
		}
		if( peer_tss[i] ){
			_rhp_free(peer_tss[i]);
		}
		if( my_tss_m[i] ){
			rhp_ikev2_ts_payload_free_ts(my_tss_m[i]);
		}
		if(peer_tss_m[i]){
			rhp_ikev2_ts_payload_free_ts(peer_tss_m[i]);
		}
	}
  RHP_TRC(0,RHPTRCID_IKEV2_CFG_ALLOC_V6_AUTO_TSS_ERR,"xxddE",rhp_ikev2_cfg_my_v6_auto_tss,rhp_ikev2_cfg_peer_v6_auto_tss,my_tss_num,peer_tss_num,err);
	return err;
}
