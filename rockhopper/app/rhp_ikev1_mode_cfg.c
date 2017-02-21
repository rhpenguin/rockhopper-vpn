/*

	Copyright (C) 2015-2016 TETSUHARU HANADA <rhpenguine@gmail.com>
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
#include "rhp_forward.h"

#define RHP_IKEV1_CFG_ATTR_SUPPORTED_NUM	16

extern int rhp_ikev2_rx_cfg_req_internal_addr(
		rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_ikev2_mesg* rx_req_ikemesg,
		rhp_cp_req_srch_pld_ctx* s_pld_ctx,
		rhp_vpn_realm* rlm,rhp_ikev2_payload* ikepayload);

extern int rhp_ikev2_rx_cfg_req_internal_dns(
		rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_ikev2_mesg* rx_req_ikemesg,
		rhp_cp_req_srch_pld_ctx* s_pld_ctx,
		rhp_vpn_realm* rlm,rhp_ikev2_payload* ikepayload);

extern int rhp_ikev2_rx_cfg_req_internal_subnets(
		rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_ikev2_mesg* rx_req_ikemesg,
		rhp_cp_req_srch_pld_ctx* s_pld_ctx,
		rhp_vpn_realm* rlm,rhp_ikev2_payload* ikepayload);

extern int rhp_ikev2_rx_cfg_req_internal_wins(
		rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_ikev2_mesg* rx_req_ikemesg,
		rhp_cp_req_srch_pld_ctx* s_pld_ctx,
		rhp_vpn_realm* rlm,rhp_ikev2_payload* ikepayload);


static int _rhp_ikev1_mode_cfg_enum_attrs_cb(rhp_ikev2_payload* payload,rhp_ikev1_attr_attr* attr_attr,void* ctx)
{
	rhp_cp_req_srch_pld_ctx* s_pld_ctx = (rhp_cp_req_srch_pld_ctx*)ctx;
	int attr_attr_type = attr_attr->get_attr_type(attr_attr);
	int attr_attr_len = attr_attr->get_attr_len(attr_attr);

  RHP_TRC(0,RHPTRCID_IKEV1_MODE_CFG_ENUM_ATTRS_CB,"xxxLdd",payload,attr_attr,ctx,"IKEV2_CFG_ATTR_TYPE",attr_attr_type,attr_attr_len);

	switch( attr_attr_type ){

	case RHP_PROTO_IKEV1_CFG_ATTR_INTERNAL_IP4_ADDRESS:

		if( attr_attr_len == 0 || attr_attr_len == 4 ){

			if( attr_attr_len ){
				s_pld_ctx->internal_addr.addr_family = AF_INET;
				memcpy(&(s_pld_ctx->internal_addr.addr.v4),attr_attr->get_attr(attr_attr),4);
			}

			rhp_ip_addr_dump("MODE_CFG_REQ_ATTR_CB_ITNL_V4_ADDR",&(s_pld_ctx->internal_addr));

			s_pld_ctx->internal_addr_flag = 1;
			s_pld_ctx->v1_rx_attrs++;

		}else{

	    RHP_TRC(0,RHPTRCID_IKEV1_MODE_CFG_ENUM_ATTRS_CB_INVALID_INTR_V4_ADDR,"xxxd",payload,attr_attr,ctx,attr_attr_len);
		}

		break;

	case RHP_PROTO_IKEV1_CFG_ATTR_INTERNAL_IP4_NETMASK:

		s_pld_ctx->internal_netmask_flag = 1;
		break;

	case RHP_PROTO_IKEV1_CFG_ATTR_INTERNAL_IP4_DNS:

		s_pld_ctx->internal_dns_flag = 1;
		s_pld_ctx->v1_rx_attrs++;
		break;

	case RHP_PROTO_IKEV1_CFG_ATTR_INTERNAL_IP4_SUBNET:

		s_pld_ctx->internal_subnet_flag = 1;
		s_pld_ctx->v1_rx_attrs++;
		break;

	case RHP_PROTO_IKE_CFG_ATTR_RHP_DNS_SFX:

		if( s_pld_ctx->peer_is_rockhopper ){
			s_pld_ctx->internal_dns_sfx_flag = 1;
			s_pld_ctx->v1_rx_attrs++;
		}
		break;

	case RHP_PROTO_IKE_CFG_ATTR_RHP_IPV4_GATEWAY:

		if( s_pld_ctx->peer_is_rockhopper ){
			s_pld_ctx->internal_gateway_flag = 1;
			s_pld_ctx->v1_rx_attrs++;
		}
		break;

	case RHP_PROTO_IKEV1_CFG_ATTR_INTERNAL_IP4_NBNS:

		s_pld_ctx->internal_wins_flag = 1;
		s_pld_ctx->v1_rx_attrs++;
		break;

	case RHP_PROTO_IKEV1_CFG_ATTR_INTERNAL_IP6_ADDRESS:

		if( attr_attr_len == 0 || attr_attr_len == 16 ){

			if( attr_attr_len ){

				u8* v = attr_attr->get_attr(attr_attr);

				s_pld_ctx->internal_addr_v6.addr_family = AF_INET6;
				memcpy(&(s_pld_ctx->internal_addr_v6.addr.v6),v,16);
			}

			rhp_ip_addr_dump("MODE_CFG_REQ_ATTR_CB_ITNL_V4_ADDR",&(s_pld_ctx->internal_addr_v6));

			s_pld_ctx->internal_addr_v6_flag = 1;
			s_pld_ctx->v1_rx_attrs++;

		}else{

	    RHP_TRC(0,RHPTRCID_IKEV1_MODE_CFG_ENUM_ATTRS_CB_INVALID_INTR_V6_ADDR,"xxxd",payload,attr_attr,ctx,attr_attr_len);
		}

		break;

	case RHP_PROTO_IKEV1_CFG_ATTR_INTERNAL_IP6_NETMASK:

		if( attr_attr_len == 0 || attr_attr_len == 16 ){

			if( attr_attr_len ){

				u8* v = attr_attr->get_attr(attr_attr);

				s_pld_ctx->internal_addr_v6.prefixlen = rhp_ipv6_netmask_to_prefixlen(v);
				memcpy(s_pld_ctx->internal_addr_v6.netmask.v6,v,16);
			}

			rhp_ip_addr_dump("MODE_CFG_REQ_ATTR_CB_ITNL_V4_ADDR_2",&(s_pld_ctx->internal_addr_v6));

		}else{

	    RHP_TRC(0,RHPTRCID_IKEV1_MODE_CFG_ENUM_ATTRS_CB_INVALID_INTR_V6_NETMASK,"xxxd",payload,attr_attr,ctx,attr_attr_len);
		}

		break;

	case RHP_PROTO_IKEV1_CFG_ATTR_INTERNAL_IP6_DNS:

		s_pld_ctx->internal_dns_v6_flag = 1;
		s_pld_ctx->v1_rx_attrs++;
		break;

	case RHP_PROTO_IKEV1_CFG_ATTR_INTERNAL_IP6_SUBNET:

		s_pld_ctx->internal_subnet_v6_flag = 1;
		s_pld_ctx->v1_rx_attrs++;
		break;

	case RHP_PROTO_IKE_CFG_ATTR_RHP_IPV6_GATEWAY:

		if( s_pld_ctx->peer_is_rockhopper ){
			s_pld_ctx->internal_gateway_v6_flag = 1;
			s_pld_ctx->v1_rx_attrs++;
		}
		break;

	case RHP_PROTO_IKEV1_CFG_ATTR_INTERNAL_IP6_NBNS:

		s_pld_ctx->internal_wins_v6_flag = 1;
		s_pld_ctx->v1_rx_attrs++;
		break;

	case RHP_PROTO_IKEV1_CFG_ATTR_SUPPORTED_ATTRIBUTES:

		s_pld_ctx->supported_attrs = 1;
		s_pld_ctx->v1_rx_attrs++;
		break;

	case RHP_PROTO_IKEV1_CFG_ATTR_APPLICATION_VERSION:

		s_pld_ctx->app_ver_flag = 1;
		s_pld_ctx->v1_rx_attrs++;
		break;

	default:
		break;
	}

  RHP_TRC(0,RHPTRCID_IKEV1_MODE_CFG_ENUM_ATTRS_CB_RTRN,"xxxLddd",payload,attr_attr,ctx,"IKEV1_MODE_CFG_ATTR_TYPE",attr_attr_type,attr_attr_len,s_pld_ctx->v1_rx_attrs);
	return 0;
}

static int _rhp_ikev1_mode_cfg_srch_attr_req_cb(rhp_ikev2_mesg* rx_ikemesg,int enum_end,rhp_ikev2_payload* payload,void* ctx)
{
	int err = -EINVAL;
	rhp_cp_req_srch_pld_ctx* s_pld_ctx = (rhp_cp_req_srch_pld_ctx*)ctx;
	rhp_ikev1_attr_payload* attr_payload = payload->ext.v1_attr;

  RHP_TRC(0,RHPTRCID_IKEV1_MODE_CFG_SRCH_ATTR_REQ_CB,"xdxd",rx_ikemesg,enum_end,ctx,s_pld_ctx->dup_flag);

  s_pld_ctx->dup_flag++;

  if( s_pld_ctx->dup_flag > 1 ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV1_MODE_CFG_SRCH_ATTR_REQ_CB_INVALID_MESG,"xdxd",rx_ikemesg,enum_end,ctx,s_pld_ctx->dup_flag);
    goto error;
  }

  err = attr_payload->enum_attr(payload,_rhp_ikev1_mode_cfg_enum_attrs_cb,s_pld_ctx);
  if( err ){
    RHP_TRC(0,RHPTRCID_IKEV1_MODE_CFG_SRCH_ATTR_REQ_CB_ENUM_ATTR_ERR,"xdxE",rx_ikemesg,enum_end,ctx,err);
  	goto error;
  }

  s_pld_ctx->cp_payload = payload;

  RHP_TRC(0,RHPTRCID_IKEV1_MODE_CFG_SRCH_ATTR_REQ_CB_RTRN,"xdx",rx_ikemesg,enum_end,ctx);
  return 0;

error:
	RHP_TRC(0,RHPTRCID_IKEV1_MODE_CFG_SRCH_ATTR_REQ_CB_ERR,"xdxE",rx_ikemesg,enum_end,ctx,err);
	return err;
}

static int _rhp_ikev1_mode_cfg_r_add_hash_buf(rhp_ikev2_mesg* ikemesg,
		int enum_end,rhp_ikev2_payload* payload,void* ctx)
{
	int err = -EINVAL;
	rhp_packet* pkt_for_hash = (rhp_packet*)ctx;
	u8 pld_id = payload->get_payload_id(payload);

  RHP_TRC(0,RHPTRCID_IKEV1_MODE_CFG_R_ADD_HASH_BUF,"xxLbxxd",ikemesg,payload,"PROTO_IKE_PAYLOAD",payload->payload_id,ctx,pkt_for_hash,ikemesg->tx_mesg_len);

  if( pld_id == RHP_PROTO_IKEV1_PAYLOAD_N ||
  		pld_id == RHP_PROTO_IKEV1_PAYLOAD_ATTR ){

		err = payload->ext_serialize(payload,pkt_for_hash);
		if( err ){
			RHP_TRC(0,RHPTRCID_IKEV1_MODE_CFG_R_ADD_HASH_BUF_ERR,"xxLbxE",ikemesg,payload,"PROTO_IKE_PAYLOAD",payload->payload_id,ctx,err);
			return err;
		}
  }

  RHP_TRC(0,RHPTRCID_IKEV1_MODE_CFG_R_ADD_HASH_BUF_RTRN,"xxxd",ikemesg,payload,pkt_for_hash,ikemesg->tx_mesg_len);
	return 0;
}

static int _rhp_ikev1_rx_mode_cfg_req(rhp_vpn* vpn,rhp_ikesa* ikesa,rhp_ikev2_mesg* rx_ikemesg,
		rhp_ikev2_mesg* tx_ikemesg)
{
	int err = -EINVAL;
	rhp_cp_req_srch_pld_ctx s_pld_ctx;
	rhp_vpn_realm* rlm = NULL;
  rhp_ikev2_payload* ikepayload = NULL;

  RHP_TRC(0,RHPTRCID_IKEV1_RX_MODE_CFG_REQ,"xxxxLd",vpn,ikesa,rx_ikemesg,tx_ikemesg,"EAP_TYPE",vpn->eap.eap_method);

	rlm = vpn->rlm;

	if( rlm == NULL ){
		err = -EINVAL;
		RHP_BUG("");
		goto error;
	}

	RHP_LOCK(&(rlm->lock));

	if( !_rhp_atomic_read(&(rlm->is_active)) ){
		err = -EINVAL;
	  RHP_TRC(0,RHPTRCID_IKEV1_RX_MODE_CFG_REQ_RLM_NOT_ACTIVE,"xxx",rx_ikemesg,vpn,rlm);
		goto error_rlm_l;
	}

	memset(&s_pld_ctx,0,sizeof(rhp_cp_req_srch_pld_ctx));

	s_pld_ctx.peer_is_rockhopper = vpn->peer_is_rockhopper;

  {
  	err = rx_ikemesg->search_payloads(rx_ikemesg,0,
  			rhp_ikev2_mesg_srch_cond_payload_id,(void*)((unsigned long)RHP_PROTO_IKEV1_PAYLOAD_ATTR),
  			_rhp_ikev1_mode_cfg_srch_attr_req_cb,&s_pld_ctx);

  	if( (!err || err == RHP_STATUS_ENUM_OK) && s_pld_ctx.v1_rx_attrs < 1 ){
  		err = -ENOENT;
  	}

  	if( !err || err == RHP_STATUS_ENUM_OK ){

  		RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_MODE_CFG_REQ_ATTR_PAYLOAD_ATTRS,"KddL4ddddddddL6ddddddLE",rx_ikemesg,s_pld_ctx.dup_flag,s_pld_ctx.internal_addr_flag,"AF",s_pld_ctx.internal_addr.addr_family,s_pld_ctx.internal_addr.addr.v4,s_pld_ctx.internal_netmask_flag,s_pld_ctx.internal_subnet_flag,s_pld_ctx.internal_dns_flag,s_pld_ctx.internal_dns_sfx_flag,s_pld_ctx.internal_gateway_flag,s_pld_ctx.internal_wins_flag,s_pld_ctx.supported_attrs,s_pld_ctx.internal_addr_v6_flag,"AF",s_pld_ctx.internal_addr_v6.addr_family,s_pld_ctx.internal_addr_v6.addr.v6,s_pld_ctx.internal_addr_v6.prefixlen,s_pld_ctx.internal_subnet_v6_flag,s_pld_ctx.internal_dns_v6_flag,s_pld_ctx.internal_gateway_v6_flag,s_pld_ctx.internal_wins_v6_flag,s_pld_ctx.ipv6_autoconf_flag,"PROTO_IKE_NOTIFY",(int)(s_pld_ctx.notify_error),err);

  		if( rlm->config_service != RHP_IKEV2_CONFIG_SERVER ){

  			RHP_TRC(0,RHPTRCID_IKEV1_RX_MODE_CFG_REQ_RLM_NOT_CONFIG_SERVER_ENABLED,"xxx",rx_ikemesg,vpn,rlm);

  			s_pld_ctx.notify_error = RHP_PROTO_IKEV1_N_ERR_NO_PROPOSAL_CHOSEN;

  			RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_MODE_CFG_CONFIG_SERVER_NOT_ENABLED,"KVP",rx_ikemesg,vpn,ikesa);

  	    goto notify_error;
  		}

  	}else{

    	if( err == -ENOENT ){

    		if( rlm->config_server.reject_non_clients ){

    			s_pld_ctx.notify_error = RHP_PROTO_IKEV1_N_ERR_NO_PROPOSAL_CHOSEN;

    			RHP_TRC(0,RHPTRCID_IKEV1_RX_MODE_CFG_REQ_PAYLOAD_ERR_REJECT_NON_CLIENTS,"xxxxw",vpn,ikesa,rx_ikemesg,tx_ikemesg,s_pld_ctx.notify_error);

        	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_MODE_CFG_REQ_REJECT_NON_CLIENT,"KVP",rx_ikemesg,vpn,ikesa);

    		}else{
    			RHP_TRC(0,RHPTRCID_IKEV1_RX_MODE_CFG_REQ_NO_CFG_PAYLOAD,"xxxx",vpn,ikesa,rx_ikemesg,tx_ikemesg);
    			goto ignore;
    		}
    	}

    	if( s_pld_ctx.notify_error ){
    	  RHP_TRC(0,RHPTRCID_IKEV1_RX_MODE_CFG_REQ_PAYLOAD_ERR,"xxxxw",vpn,ikesa,rx_ikemesg,tx_ikemesg,s_pld_ctx.notify_error);
        goto notify_error;
    	}

  	  RHP_TRC(0,RHPTRCID_IKEV1_RX_MODE_CFG_REQ_NO_CFG_PAYLOAD_ENUM_PAYLOAD_ERR,"xxxx",vpn,ikesa,rx_ikemesg,tx_ikemesg);

    	err = RHP_STATUS_INVALID_MSG;
    	goto error_rlm_l;
    }
  }


  {
  	u8 cfg_type = s_pld_ctx.cp_payload->ext.v1_attr->get_type(s_pld_ctx.cp_payload);
  	if( cfg_type != RHP_PROTO_IKEV1_CFG_REQUEST ){

  		RHP_TRC(0,RHPTRCID_IKEV1_RX_MODE_CFG_REQ_NOT_CFG_REQUEST,"xxx",rx_ikemesg,vpn,rlm);
    	RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_MODE_CFG_REQ_CP_PAYLOAD_NOT_SUPPORTED_CFG_TYPE,"KbVP",rx_ikemesg,cfg_type,vpn,ikesa);

  		if( rlm->config_server.reject_non_clients ){

  			s_pld_ctx.notify_error = RHP_PROTO_IKEV1_N_ERR_NO_PROPOSAL_CHOSEN;

    		RHP_TRC(0,RHPTRCID_IKEV1_RX_MODE_CFG_REQ_NOT_CFG_REQUEST_REJECT_NON_CLIENTS,"xxx",rx_ikemesg,vpn,rlm);

      	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_MODE_CFG_REQ_REJECT_NON_CLIENT,"KVP",rx_ikemesg,vpn,ikesa);

    		goto notify_error;

  		}else{

  			goto ignore;
  		}
  	}
  }


	if( rlm->config_server.reject_non_clients &&
			!s_pld_ctx.internal_addr_flag &&
			!s_pld_ctx.internal_addr_v6_flag ){

		s_pld_ctx.notify_error = RHP_PROTO_IKEV1_N_ERR_NO_PROPOSAL_CHOSEN;

		RHP_TRC(0,RHPTRCID_IKEV1_RX_MODE_CFG_REQ_NOT_CFG_REQUEST_REJECT_NON_CLIENTS_2,"xxx",rx_ikemesg,vpn,rlm);

  	RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_MODE_CFG_REQ_REJECT_NON_CLIENT,"KVP",rx_ikemesg,vpn,ikesa);

		goto notify_error;
	}


	if( ( err = rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKEV1_PAYLOAD_ATTR,&ikepayload)) ){
		RHP_BUG("");
		goto error_rlm_l;
	}

	ikepayload->ext.v1_attr->set_type(ikepayload,RHP_PROTO_IKEV1_CFG_REPLY);


	if( s_pld_ctx.internal_addr_flag || s_pld_ctx.internal_addr_v6_flag ){

		err = rhp_ikev2_rx_cfg_req_internal_addr(vpn,ikesa,rx_ikemesg,
						&s_pld_ctx,rlm,ikepayload);
		if( err ){

			if( s_pld_ctx.notify_error ){
				goto notify_error;
			}

			goto error_rlm_l;
		}
	}


  if( s_pld_ctx.internal_dns_flag || s_pld_ctx.internal_dns_v6_flag ){

		err = rhp_ikev2_rx_cfg_req_internal_dns(vpn,ikesa,rx_ikemesg,
						&s_pld_ctx,rlm,ikepayload);
  	if( err ){

  		if( s_pld_ctx.notify_error ){
  			goto notify_error;
  		}

			goto error_rlm_l;
  	}
  }


  if( rhp_gcfg_ikev1_mode_cfg_tx_subnets ){

  	if( s_pld_ctx.internal_addr_flag ){

  		s_pld_ctx.internal_subnet_flag = 1;

  	}else if( s_pld_ctx.internal_addr_v6_flag ){

  		s_pld_ctx.internal_subnet_v6_flag = 1;
  	}
  }

  if( s_pld_ctx.internal_subnet_flag || s_pld_ctx.internal_subnet_v6_flag ){

  	err = rhp_ikev2_rx_cfg_req_internal_subnets(vpn,ikesa,rx_ikemesg,
  					&s_pld_ctx,rlm,ikepayload);
  	if( err ){

  		if( s_pld_ctx.notify_error ){
  			goto notify_error;
  		}

			goto error_rlm_l;
  	}
  }


  if( s_pld_ctx.internal_wins_flag || s_pld_ctx.internal_wins_v6_flag ){

  	err = rhp_ikev2_rx_cfg_req_internal_wins(vpn,ikesa,rx_ikemesg,
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

			err = ikepayload->ext.v1_attr->alloc_and_put_attr(ikepayload,
							RHP_PROTO_IKEV1_CFG_ATTR_APPLICATION_VERSION,app_str_len,app_ver_buf);

			if( err ){
				RHP_BUG("%d",err);
				goto error_rlm_l;
			}
  	}
  }


  if( s_pld_ctx.supported_attrs ){

  	u16 supported_attrs[RHP_IKEV1_CFG_ATTR_SUPPORTED_NUM];

  	supported_attrs[0] = htons(RHP_PROTO_IKEV1_CFG_ATTR_INTERNAL_IP4_ADDRESS);
  	supported_attrs[1] = htons(RHP_PROTO_IKEV1_CFG_ATTR_INTERNAL_IP4_NETMASK);
  	supported_attrs[2] = htons(RHP_PROTO_IKEV1_CFG_ATTR_INTERNAL_IP4_DNS);
  	supported_attrs[3] = htons(RHP_PROTO_IKEV1_CFG_ATTR_INTERNAL_IP4_NBNS);
  	supported_attrs[4] = htons(RHP_PROTO_IKEV1_CFG_ATTR_INTERNAL_ADDRESS_EXPIRY);
  	supported_attrs[5] = htons(RHP_PROTO_IKEV1_CFG_ATTR_APPLICATION_VERSION);
  	supported_attrs[6] = htons(RHP_PROTO_IKEV1_CFG_ATTR_INTERNAL_IP6_ADDRESS);
  	supported_attrs[7] = htons(RHP_PROTO_IKEV1_CFG_ATTR_INTERNAL_IP6_NETMASK);
  	supported_attrs[8] = htons(RHP_PROTO_IKEV1_CFG_ATTR_INTERNAL_IP6_DNS);
  	supported_attrs[9] = htons(RHP_PROTO_IKEV1_CFG_ATTR_INTERNAL_IP6_NBNS);
  	supported_attrs[10] = htons(RHP_PROTO_IKEV1_CFG_ATTR_INTERNAL_IP4_SUBNET);
  	supported_attrs[11] = htons(RHP_PROTO_IKEV1_CFG_ATTR_SUPPORTED_ATTRIBUTES);
  	supported_attrs[12] = htons(RHP_PROTO_IKEV1_CFG_ATTR_INTERNAL_IP6_SUBNET);
  	supported_attrs[13] = htons(RHP_PROTO_IKE_CFG_ATTR_RHP_DNS_SFX);
  	supported_attrs[14] = htons(RHP_PROTO_IKE_CFG_ATTR_RHP_IPV4_GATEWAY);
  	supported_attrs[15] = htons(RHP_PROTO_IKE_CFG_ATTR_RHP_IPV6_GATEWAY);

		err = ikepayload->ext.v1_attr->alloc_and_put_attr(ikepayload,
						RHP_PROTO_IKEV1_CFG_ATTR_SUPPORTED_ATTRIBUTES,
						sizeof(u16)*RHP_IKEV1_CFG_ATTR_SUPPORTED_NUM,(u8*)supported_attrs);

		if( err ){
  		RHP_BUG("%d",err);
			goto error_rlm_l;
		}

		RHP_LOG_DE(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_MODE_CFG_REQ_SUPPORTED_ATTRIBUTES,"KWWWWWWWWWWWWWWWW",rx_ikemesg,supported_attrs[0],supported_attrs[1],supported_attrs[2],supported_attrs[3],supported_attrs[4],supported_attrs[5],supported_attrs[6],supported_attrs[7],supported_attrs[8],supported_attrs[9],supported_attrs[10],supported_attrs[11],supported_attrs[12],supported_attrs[13],supported_attrs[14],supported_attrs[15]);
  }

  tx_ikemesg->put_payload(tx_ikemesg,ikepayload);
	ikepayload = NULL;


	if( rhp_ikev1_tx_info_mesg_hash_add(vpn,ikesa,
				tx_ikemesg,_rhp_ikev1_mode_cfg_r_add_hash_buf) ){
		RHP_BUG("");
		err = -EINVAL;
		goto error_rlm_l;
	}


	vpn->peer_is_remote_client = 1;

	rhp_ikev1_p2_session_rx_put(ikesa,rx_ikemesg,1);

  tx_ikemesg->v1_set_retrans_resp = 1;


	RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_MODE_CFG_REQ_OK,"KVP",rx_ikemesg,vpn,ikesa);

ignore:
	RHP_UNLOCK(&(rlm->lock));

  RHP_TRC(0,RHPTRCID_IKEV1_RX_MODE_CFG_REQ_RTRN,"xxxx",vpn,ikesa,rx_ikemesg,tx_ikemesg);
	return 0;

notify_error:
	if( s_pld_ctx.notify_error ){

		rhp_ikev2_payload* ikepayload_n = NULL;

		if( rhp_ikev2_new_payload_tx(tx_ikemesg,RHP_PROTO_IKEV1_PAYLOAD_ATTR,&ikepayload_n) ){
			RHP_BUG("");
			err = -EINVAL;
			goto error_rlm_l;
		}

		ikepayload_n->ext.v1_attr->set_type(ikepayload_n,RHP_PROTO_IKEV1_CFG_REPLY);

		tx_ikemesg->put_payload(tx_ikemesg,ikepayload_n);


		if( rhp_ikev1_tx_info_mesg_hash_add(vpn,ikesa,
					tx_ikemesg,_rhp_ikev1_mode_cfg_r_add_hash_buf) ){
			RHP_BUG("");
			err = -EINVAL;
			goto error_rlm_l;
		}

		rhp_ikev1_p2_session_rx_put(ikesa,rx_ikemesg,1);

		RHP_LOG_D(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_MODE_CFG_REQ_TX_ERR_NOTIFY,"KVPL",rx_ikemesg,vpn,ikesa,"PROTO_IKE_NOTIFY",s_pld_ctx.notify_error);

		err = RHP_STATUS_IKEV2_DESTROY_SA_AFTER_TX;
	}

error_rlm_l:
	RHP_UNLOCK(&(rlm->lock));
error:
	if( ikepayload ){
		rhp_ikev2_destroy_payload(ikepayload);
	}

	RHP_LOG_E(RHP_LOG_SRC_IKEV2,vpn->vpn_realm_id,RHP_LOG_ID_RX_MODE_CFG_REQ_ERR,"KVPEL",rx_ikemesg,vpn,ikesa,err,"PROTO_IKE_NOTIFY",s_pld_ctx.notify_error);
	RHP_TRC(0,RHPTRCID_IKEV1_RX_MODE_CFG_REQ_ERR,"xxxxELd",vpn,ikesa,rx_ikemesg,tx_ikemesg,err,"PROTO_IKE_NOTIFY",s_pld_ctx.notify_error);
	return err;
}

int rhp_ikev1_rx_mode_cfg(rhp_ikev2_mesg* rx_ikemesg,rhp_vpn* vpn,
		int my_ikesa_side,u8* my_ikesa_spi,rhp_ikev2_mesg* tx_ikemesg)
{
	int err = -EINVAL;
	rhp_ikesa* ikesa = NULL;
	u8 exchange_type = rx_ikemesg->get_exchange_type(rx_ikemesg);

  RHP_TRC(0,RHPTRCID_IKEV1_RX_MODE_CFG,"xxLdGxLbx",rx_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi,tx_ikemesg,"PROTO_IKE_EXCHG",exchange_type,vpn->cfg_peer);

	if( vpn->cfg_peer && vpn->cfg_peer->is_access_point ){
	  RHP_TRC(0,RHPTRCID_IKEV1_RX_MODE_CFG_NOT_INTERESTED,"x",rx_ikemesg);
		return 0;
	}

	if( exchange_type != RHP_PROTO_IKEV1_EXCHG_TRANSACTION ){
		err = 0;
	  RHP_TRC(0,RHPTRCID_IKEV1_RX_MODE_CFG_NOT_INTERESTED_2,"x",rx_ikemesg);
		goto ignore;
	}

	if( vpn->origin_side != RHP_IKE_RESPONDER ){
		err = 0;
	  RHP_TRC(0,RHPTRCID_IKEV1_RX_MODE_CFG_NOT_INTERESTED_3,"x",rx_ikemesg);
		goto ignore;
	}

  if( !rx_ikemesg->decrypted ){
  	err = 0;
	  RHP_TRC(0,RHPTRCID_IKEV1_RX_MODE_CFG_NOT_DECRYPTED,"x",rx_ikemesg);
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
	  RHP_TRC(0,RHPTRCID_IKEV1_RX_MODE_CFG_NO_IKESA2,"xxLdG",rx_ikemesg,vpn,"IKE_SIDE",my_ikesa_side,my_ikesa_spi);
		goto error;
	}

	if( ikesa->state != RHP_IKESA_STAT_V1_ESTABLISHED &&
			ikesa->state != RHP_IKESA_STAT_V1_REKEYING ){
  	err = 0;
	  RHP_TRC(0,RHPTRCID_IKEV1_RX_MODE_CFG_IKESA_BAD_STATE,"xLd",rx_ikemesg,"IKESA_STAT",ikesa->state);
  	goto ignore;
	}

	err = _rhp_ikev1_rx_mode_cfg_req(vpn,ikesa,rx_ikemesg,tx_ikemesg);

error:
ignore:
	RHP_TRC(0,RHPTRCID_IKEV1_RX_MODE_CFG_RTRN,"xxxE",rx_ikemesg,vpn,tx_ikemesg,err);
  return err;
}
