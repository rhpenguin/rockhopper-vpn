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
#include "rhp_process.h"
#include "rhp_netmng.h"
#include "rhp_protocol.h"
#include "rhp_packet.h"
#include "rhp_netsock.h"
#include "rhp_wthreads.h"
#include "rhp_packet.h"
#include "rhp_config.h"
#include "rhp_ikesa.h"
#include "rhp_ikev2_mesg.h"

extern int rhp_ikev2_sa_payload_new_rx(rhp_ikev2_mesg* ikemesg,u8 payload_id,
                                       rhp_proto_ike_payload* payloadh,int payload_len,rhp_ikev2_payload* ikepayload);

extern int rhp_ikev2_ke_payload_new_rx(rhp_ikev2_mesg* ikemesg,u8 payload_id,
                                       rhp_proto_ike_payload* payloadh,int payload_len,rhp_ikev2_payload* ikepayload);

extern int rhp_ikev2_nir_payload_new_rx(rhp_ikev2_mesg* ikemesg,u8 payload_id,
                                        rhp_proto_ike_payload* payloadh,int payload_len,rhp_ikev2_payload* ikepayload);

extern int rhp_ikev2_vid_payload_new_rx(rhp_ikev2_mesg* ikemesg,u8 payload_id,
                                        rhp_proto_ike_payload* payloadh,int payload_len,rhp_ikev2_payload* ikepayload);

extern int rhp_ikev2_id_payload_new_rx(rhp_ikev2_mesg* ikemesg,u8 payload_id,
                                       rhp_proto_ike_payload* payloadh,int payload_len,rhp_ikev2_payload* ikepayload);

extern int rhp_ikev2_auth_payload_new_rx(rhp_ikev2_mesg* ikemesg,u8 payload_id,
                                         rhp_proto_ike_payload* payloadh,int payload_len,rhp_ikev2_payload* ikepayload);

extern int rhp_ikev2_certreq_payload_new_rx(rhp_ikev2_mesg* ikemesg,u8 payload_id,
                                            rhp_proto_ike_payload* payloadh,int payload_len,rhp_ikev2_payload* ikepayload);

extern int rhp_ikev2_cert_payload_new_rx(rhp_ikev2_mesg* ikemesg,u8 payload_id,
                                         rhp_proto_ike_payload* payloadh,int payload_len,rhp_ikev2_payload* ikepayload);

extern int rhp_ikev2_n_payload_new_rx(rhp_ikev2_mesg* ikemesg,u8 payload_id,
                                      rhp_proto_ike_payload* payloadh,int payload_len,rhp_ikev2_payload* ikepayload);

extern int rhp_ikev2_ts_payload_new_rx(rhp_ikev2_mesg* ikemesg,u8 payload_id,
                                       rhp_proto_ike_payload* payloadh,int payload_len,rhp_ikev2_payload* ikepayload);

extern int rhp_ikev2_d_payload_new_rx(rhp_ikev2_mesg* ikemesg,u8 payload_id,
                                      rhp_proto_ike_payload* payloadh,int payload_len,rhp_ikev2_payload* payload);

extern int rhp_ikev2_cp_payload_new_rx(rhp_ikev2_mesg* ikemesg,u8 payload_id,
                                      rhp_proto_ike_payload* payloadh,int payload_len,rhp_ikev2_payload* payload);

extern int rhp_ikev2_eap_payload_new_rx(rhp_ikev2_mesg* ikemesg,u8 payload_id,
                                      rhp_proto_ike_payload* payloadh,int payload_len,rhp_ikev2_payload* payload);

extern int rhp_ikev2_stun_payload_new_rx(rhp_ikev2_mesg* ikemesg,u8 payload_id,
                                      rhp_proto_ike_payload* payloadh,int payload_len,rhp_ikev2_payload* payload);


extern int rhp_ikev1_sa_payload_new_rx(rhp_ikev2_mesg* ikemesg,u8 payload_id,
    rhp_proto_ike_payload* payloadh,int payload_len,rhp_ikev2_payload* payload);

extern int rhp_ikev1_ke_payload_new_rx(rhp_ikev2_mesg* ikemesg,u8 payload_id,
    rhp_proto_ike_payload* payloadh,int payload_len,rhp_ikev2_payload* payload);

extern int rhp_ikev1_id_payload_new_rx(rhp_ikev2_mesg* ikemesg,u8 payload_id,
    rhp_proto_ike_payload* payloadh,int payload_len,rhp_ikev2_payload* payload);

extern int rhp_ikev1_cr_payload_new_rx(rhp_ikev2_mesg* ikemesg,u8 payload_id,
    rhp_proto_ike_payload* payloadh,int payload_len,rhp_ikev2_payload* payload);

extern int rhp_ikev1_hash_payload_new_rx(rhp_ikev2_mesg* ikemesg,u8 payload_id,
    rhp_proto_ike_payload* payloadh,int payload_len,rhp_ikev2_payload* payload);

extern int rhp_ikev1_sig_payload_new_rx(rhp_ikev2_mesg* ikemesg,u8 payload_id,
    rhp_proto_ike_payload* payloadh,int payload_len,rhp_ikev2_payload* payload);

extern int rhp_ikev1_nat_d_payload_new_rx(rhp_ikev2_mesg* ikemesg,u8 payload_id,
    rhp_proto_ike_payload* payloadh,int payload_len,rhp_ikev2_payload* payload);

extern int rhp_ikev1_nat_oa_payload_new_rx(rhp_ikev2_mesg* ikemesg,u8 payload_id,
    rhp_proto_ike_payload* payloadh,int payload_len,rhp_ikev2_payload* payload);

extern int rhp_ikev1_attr_payload_new_rx(rhp_ikev2_mesg* ikemesg,u8 payload_id,
    rhp_proto_ike_payload* payloadh,int payload_len,rhp_ikev2_payload* payload);


typedef int (*RHP_IKEV2_NEW_PAYLOAD_RX)(rhp_ikev2_mesg* ikemesg,u8 payload_id,
                                        rhp_proto_ike_payload* payloadh,int payload_len,rhp_ikev2_payload* ikepayload);


static RHP_IKEV2_NEW_PAYLOAD_RX _rhp_ikev2_new_rx_payload_cb(u8 payload_id)
{
	RHP_IKEV2_NEW_PAYLOAD_RX cb = NULL;

	switch( payload_id ){

	case RHP_PROTO_IKE_NO_MORE_PAYLOADS:
		break;

	case RHP_PROTO_IKE_PAYLOAD_SA:
	  cb = rhp_ikev2_sa_payload_new_rx;
		break;

	case RHP_PROTO_IKE_PAYLOAD_KE:
		cb = rhp_ikev2_ke_payload_new_rx;
		break;

	case RHP_PROTO_IKE_PAYLOAD_ID_I:
		cb = rhp_ikev2_id_payload_new_rx;
		break;

	case RHP_PROTO_IKE_PAYLOAD_ID_R:
		cb = rhp_ikev2_id_payload_new_rx;
		break;

	case RHP_PROTO_IKE_PAYLOAD_CERT:
	case RHP_PROTO_IKEV1_PAYLOAD_CERT:
		cb = rhp_ikev2_cert_payload_new_rx;
		break;

	case RHP_PROTO_IKE_PAYLOAD_CERTREQ:
		cb = rhp_ikev2_certreq_payload_new_rx;
		break;

	case RHP_PROTO_IKE_PAYLOAD_AUTH:
		cb = rhp_ikev2_auth_payload_new_rx;
		break;

	case RHP_PROTO_IKE_PAYLOAD_N_I_R:
	case RHP_PROTO_IKEV1_PAYLOAD_NONCE:
		cb = rhp_ikev2_nir_payload_new_rx;
		break;

	case RHP_PROTO_IKE_PAYLOAD_N:
	case RHP_PROTO_IKEV1_PAYLOAD_N:
		cb = rhp_ikev2_n_payload_new_rx;
		break;

	case RHP_PROTO_IKE_PAYLOAD_D:
	case RHP_PROTO_IKEV1_PAYLOAD_D:
		cb = rhp_ikev2_d_payload_new_rx;
		break;

	case RHP_PROTO_IKE_PAYLOAD_V:
	case RHP_PROTO_IKEV1_PAYLOAD_VID:
		cb = rhp_ikev2_vid_payload_new_rx;
		break;

	case RHP_PROTO_IKE_PAYLOAD_TS_I:
		cb = rhp_ikev2_ts_payload_new_rx;
		break;

	case RHP_PROTO_IKE_PAYLOAD_TS_R:
		cb = rhp_ikev2_ts_payload_new_rx;
		break;

	case RHP_PROTO_IKE_PAYLOAD_E:
		break;

	case RHP_PROTO_IKE_PAYLOAD_CP:
		cb = rhp_ikev2_cp_payload_new_rx;
		break;

	case RHP_PROTO_IKE_PAYLOAD_EAP:
		cb = rhp_ikev2_eap_payload_new_rx;
		break;

/*
	case RHP_PROTO_IKE_PAYLOAD_RHP_STUN:
		cb = rhp_ikev2_stun_payload_new_rx;
		break;
*/

	case RHP_PROTO_IKEV1_PAYLOAD_SA:
		cb = rhp_ikev1_sa_payload_new_rx;
		break;

	case RHP_PROTO_IKEV1_PAYLOAD_KE:
		cb = rhp_ikev1_ke_payload_new_rx;
		break;

	case RHP_PROTO_IKEV1_PAYLOAD_ID:
		cb = rhp_ikev1_id_payload_new_rx;
		break;

	case RHP_PROTO_IKEV1_PAYLOAD_CR:
		cb = rhp_ikev1_cr_payload_new_rx;
		break;

	case RHP_PROTO_IKEV1_PAYLOAD_HASH:
		cb = rhp_ikev1_hash_payload_new_rx;
		break;

	case RHP_PROTO_IKEV1_PAYLOAD_SIG:
		cb = rhp_ikev1_sig_payload_new_rx;
		break;

	case RHP_PROTO_IKEV1_PAYLOAD_NAT_D:
		cb = rhp_ikev1_nat_d_payload_new_rx;
		break;

	case RHP_PROTO_IKEV1_PAYLOAD_NAT_OA:
		cb = rhp_ikev1_nat_oa_payload_new_rx;
		break;

	case RHP_PROTO_IKEV1_PAYLOAD_ATTR:
		cb = rhp_ikev1_attr_payload_new_rx;
		break;

	default:
		break;
	}

	RHP_TRC(0,RHPTRCID_IKEV2_NEW_RX_PAYLOAD_CB,"LbY","PROTO_IKE_PAYLOAD",payload_id,cb);
	return cb;
}

extern int rhp_ikev2_sa_payload_new_tx(rhp_ikev2_mesg* ikemesg,u8 payload_id,rhp_ikev2_payload* ikepayload);

extern int rhp_ikev2_ke_payload_new_tx(rhp_ikev2_mesg* ikemesg,u8 payload_id,rhp_ikev2_payload* ikepayload);

extern int rhp_ikev2_nir_payload_new_tx(rhp_ikev2_mesg* ikemesg,u8 payload_id,rhp_ikev2_payload* ikepayload);

extern int rhp_ikev2_vid_payload_new_tx(rhp_ikev2_mesg* ikemesg,u8 payload_id,rhp_ikev2_payload* payload);

extern int rhp_ikev2_id_payload_new_tx(rhp_ikev2_mesg* ikemesg,u8 payload_id,rhp_ikev2_payload* payload);

extern int rhp_ikev2_auth_payload_new_tx(rhp_ikev2_mesg* ikemesg,u8 payload_id,rhp_ikev2_payload* payload);

extern int rhp_ikev2_certreq_payload_new_tx(rhp_ikev2_mesg* ikemesg,u8 payload_id,rhp_ikev2_payload* payload);

extern int rhp_ikev2_cert_payload_new_tx(rhp_ikev2_mesg* ikemesg,u8 payload_id,rhp_ikev2_payload* payload);

extern int rhp_ikev2_n_payload_new_tx(rhp_ikev2_mesg* ikemesg,u8 payload_id,rhp_ikev2_payload* payload);

extern int rhp_ikev2_ts_payload_new_tx(rhp_ikev2_mesg* ikemesg,u8 payload_id,rhp_ikev2_payload* payload);

extern int rhp_ikev2_d_payload_new_tx(rhp_ikev2_mesg* ikemesg,u8 payload_id,rhp_ikev2_payload* payload);

extern int rhp_ikev2_cp_payload_new_tx(rhp_ikev2_mesg* ikemesg,u8 payload_id,rhp_ikev2_payload* payload);

extern int rhp_ikev2_eap_payload_new_tx(rhp_ikev2_mesg* ikemesg,u8 payload_id,rhp_ikev2_payload* payload);

extern int rhp_ikev2_stun_payload_new_tx(rhp_ikev2_mesg* ikemesg,u8 payload_id,rhp_ikev2_payload* payload);


extern int rhp_ikev1_sa_payload_new_tx(rhp_ikev2_mesg* ikemesg,u8 payload_id,rhp_ikev2_payload* payload);

extern int rhp_ikev1_ke_payload_new_tx(rhp_ikev2_mesg* ikemesg,u8 payload_id,rhp_ikev2_payload* payload);

extern int rhp_ikev1_id_payload_new_tx(rhp_ikev2_mesg* ikemesg,u8 payload_id,rhp_ikev2_payload* payload);

extern int rhp_ikev1_cr_payload_new_tx(rhp_ikev2_mesg* ikemesg,u8 payload_id,rhp_ikev2_payload* payload);

extern int rhp_ikev1_hash_payload_new_tx(rhp_ikev2_mesg* ikemesg,u8 payload_id,rhp_ikev2_payload* payload);

extern int rhp_ikev1_sig_payload_new_tx(rhp_ikev2_mesg* ikemesg,u8 payload_id,rhp_ikev2_payload* payload);

extern int rhp_ikev1_nat_d_payload_new_tx(rhp_ikev2_mesg* ikemesg,u8 payload_id,rhp_ikev2_payload* payload);

extern int rhp_ikev1_nat_oa_payload_new_tx(rhp_ikev2_mesg* ikemesg,u8 payload_id,rhp_ikev2_payload* payload);

extern int rhp_ikev1_attr_payload_new_tx(rhp_ikev2_mesg* ikemesg,u8 payload_id,rhp_ikev2_payload* payload);


typedef int (*RHP_IKEV2_NEW_PAYLOAD_TX)(rhp_ikev2_mesg* ikemesg,u8 payload_id,rhp_ikev2_payload* ikepayload);


static RHP_IKEV2_NEW_PAYLOAD_TX _rhp_ikev2_new_tx_payload_cb(u8 payload_id)
{
	RHP_IKEV2_NEW_PAYLOAD_TX cb = NULL;

	switch( payload_id ){

	case RHP_PROTO_IKE_NO_MORE_PAYLOADS:
		break;

	case RHP_PROTO_IKE_PAYLOAD_SA:
	  cb = rhp_ikev2_sa_payload_new_tx;
		break;

	case RHP_PROTO_IKE_PAYLOAD_KE:
		cb = rhp_ikev2_ke_payload_new_tx;
		break;

	case RHP_PROTO_IKE_PAYLOAD_ID_I:
		cb = rhp_ikev2_id_payload_new_tx;
		break;

	case RHP_PROTO_IKE_PAYLOAD_ID_R:
		cb = rhp_ikev2_id_payload_new_tx;
		break;

	case RHP_PROTO_IKE_PAYLOAD_CERT:
	case RHP_PROTO_IKEV1_PAYLOAD_CERT:
		cb = rhp_ikev2_cert_payload_new_tx;
		break;

	case RHP_PROTO_IKE_PAYLOAD_CERTREQ:
		cb = rhp_ikev2_certreq_payload_new_tx;
		break;

	case RHP_PROTO_IKE_PAYLOAD_AUTH:
		cb = rhp_ikev2_auth_payload_new_tx;
		break;

	case RHP_PROTO_IKE_PAYLOAD_N_I_R:
	case RHP_PROTO_IKEV1_PAYLOAD_NONCE:
		cb = rhp_ikev2_nir_payload_new_tx;
		break;

	case RHP_PROTO_IKE_PAYLOAD_N:
	case RHP_PROTO_IKEV1_PAYLOAD_N:
		cb = rhp_ikev2_n_payload_new_tx;
		break;

	case RHP_PROTO_IKE_PAYLOAD_D:
	case RHP_PROTO_IKEV1_PAYLOAD_D:
		cb = rhp_ikev2_d_payload_new_tx;
		break;

	case RHP_PROTO_IKE_PAYLOAD_V:
	case RHP_PROTO_IKEV1_PAYLOAD_VID:
		cb = rhp_ikev2_vid_payload_new_tx;
		break;

	case RHP_PROTO_IKE_PAYLOAD_TS_I:
		cb = rhp_ikev2_ts_payload_new_tx;
		break;

	case RHP_PROTO_IKE_PAYLOAD_TS_R:
		cb = rhp_ikev2_ts_payload_new_tx;
		break;

	case RHP_PROTO_IKE_PAYLOAD_E:
		break;

	case RHP_PROTO_IKE_PAYLOAD_CP:
		cb = rhp_ikev2_cp_payload_new_tx;
		break;

	case RHP_PROTO_IKE_PAYLOAD_EAP:
		cb = rhp_ikev2_eap_payload_new_tx;
		break;

/*
	case RHP_PROTO_IKE_PAYLOAD_RHP_STUN:
		cb = rhp_ikev2_stun_payload_new_tx;
		break;
*/

	case RHP_PROTO_IKEV1_PAYLOAD_SA:
		cb = rhp_ikev1_sa_payload_new_tx;
		break;

	case RHP_PROTO_IKEV1_PAYLOAD_KE:
		cb = rhp_ikev1_ke_payload_new_tx;
		break;

	case RHP_PROTO_IKEV1_PAYLOAD_ID:
		cb = rhp_ikev1_id_payload_new_tx;
		break;

	case RHP_PROTO_IKEV1_PAYLOAD_CR:
		cb = rhp_ikev1_cr_payload_new_tx;
		break;

	case RHP_PROTO_IKEV1_PAYLOAD_HASH:
		cb = rhp_ikev1_hash_payload_new_tx;
		break;

	case RHP_PROTO_IKEV1_PAYLOAD_SIG:
		cb = rhp_ikev1_sig_payload_new_tx;
		break;

	case RHP_PROTO_IKEV1_PAYLOAD_NAT_D:
		cb = rhp_ikev1_nat_d_payload_new_tx;
		break;

	case RHP_PROTO_IKEV1_PAYLOAD_NAT_OA:
		cb = rhp_ikev1_nat_oa_payload_new_tx;
		break;

	case RHP_PROTO_IKEV1_PAYLOAD_ATTR:
		cb = rhp_ikev1_attr_payload_new_tx;
		break;

	default:
		break;
	}

	RHP_TRC(0,RHPTRCID_IKEV2_NEW_TX_PAYLOAD_CB,"LbY","PROTO_IKE_PAYLOAD",payload_id,cb);
	return cb;
}


static u8 _rhp_ikev2_payload_get_payload_id(rhp_ikev2_payload* ikepayload)
{
  RHP_TRC(0,RHPTRCID_IKEV2_PAYLOAD_GET_PAYLOAD_ID,"xLb",ikepayload,"PROTO_IKE_PAYLOAD",ikepayload->payload_id);
  return ikepayload->payload_id;
}

static u8 _rhp_ikev2_payload_get_next_payload(rhp_ikev2_payload* ikepayload)
{
  rhp_proto_ike_payload* payloadh = ikepayload->payloadh;
  u8 next_id;
  if( payloadh ){
    next_id = payloadh->next_payload;
  }else{
    if( ikepayload->next ){
      next_id = ikepayload->next->get_payload_id(ikepayload->next);
    }else{
      next_id = RHP_PROTO_IKE_NO_MORE_PAYLOADS;
    }
  }
  RHP_TRC(0,RHPTRCID_IKEV2_PAYLOAD_GET_NEXT_PAYLOAD,"xLbxx",ikepayload,"PROTO_IKE_PAYLOAD",next_id,payloadh,ikepayload->next);
  return next_id;
}

static u16 _rhp_ikev2_payload_get_len_rx(rhp_ikev2_payload* ikepayload)
{
  rhp_proto_ike_payload* payloadh = ikepayload->payloadh;
  RHP_TRC(0,RHPTRCID_IKEV2_PAYLOAD_GET_LEN_RX,"xW",ikepayload,payloadh->len);
  return ntohs(payloadh->len);
}

static void _rhp_ikev2_payload_set_non_critical(rhp_ikev2_payload* ikepayload,int flag)
{
  RHP_TRC(0,RHPTRCID_IKEV2_PAYLOAD_SET_NON_CRITICAL,"xd",ikepayload,flag);
	ikepayload->non_critical = flag;
}

static rhp_ikev2_payload* _rhp_ikev2_alloc_payload()
{
  rhp_ikev2_payload* ikepayload = _rhp_malloc(sizeof(rhp_ikev2_payload));

  if( ikepayload == NULL ){
    RHP_BUG("");
    return NULL;
  }

  memset(ikepayload,0,sizeof(rhp_ikev2_payload));

  ikepayload->tag[0] = '#';
  ikepayload->tag[1] = 'I';
  ikepayload->tag[2] = 'K';
  ikepayload->tag[3] = 'P';

  ikepayload->get_payload_id = _rhp_ikev2_payload_get_payload_id;
  ikepayload->get_next_payload = _rhp_ikev2_payload_get_next_payload;
  ikepayload->get_len_rx = _rhp_ikev2_payload_get_len_rx;
  ikepayload->set_non_critical = _rhp_ikev2_payload_set_non_critical;

  RHP_TRC(0,RHPTRCID_IKEV2_ALLOC_PAYLOAD,"x",ikepayload);
  return ikepayload;
}

rhp_ikev2_payload* rhp_ikev2_alloc_payload_raw()
{
	return _rhp_ikev2_alloc_payload();
}

void rhp_ikev2_destroy_payload(rhp_ikev2_payload* ikepayload)
{
  RHP_TRC(0,RHPTRCID_IKEV2_DESTROY_PAYLOAD,"xxY",ikepayload,ikepayload->ext.raw,ikepayload->ext_destructor);

  if( ikepayload->ext.raw ){

    if( ikepayload->ext_destructor ){
      ikepayload->ext_destructor(ikepayload);
    }

  	_rhp_free(ikepayload->ext.raw);
  }

  _rhp_free(ikepayload);
  
  return;
}


int rhp_ikev2_new_payload_rx(rhp_ikev2_mesg* ikemesg,u8 payload_id,
                             rhp_proto_ike_payload* payloadh,int payload_len,rhp_ikev2_payload** ikepayload_r)
{
  int err;
  rhp_ikev2_payload* ikepayload = NULL;
  RHP_IKEV2_NEW_PAYLOAD_RX cb;

  RHP_TRC(0,RHPTRCID_IKEV2_NEW_PAYLOAD_RX,"xxLbxdxp",ikemesg,ikemesg->rx_pkt,"PROTO_IKE_PAYLOAD",payload_id,payloadh,payload_len,ikepayload_r,payload_len,payloadh);

  cb = _rhp_ikev2_new_rx_payload_cb(payload_id);
  if( cb == NULL ){
    RHP_TRC(0,RHPTRCID_IKEV2_NEW_PAYLOAD_RX_NOT_SUP_ID,"xb",ikemesg,payload_id);
    return RHP_STATUS_UNKNOWN_PAYLOAD;
  }

  RHP_TRC(0,RHPTRCID_IKEV2_NEW_PAYLOAD_RX_CB,"xY",ikemesg,cb);
  
  ikepayload = _rhp_ikev2_alloc_payload();
  if( ikepayload == NULL ){
    RHP_BUG("");
    return -ENOMEM;
  }

  ikepayload->ikemesg = ikemesg;
  ikepayload->payloadh = payloadh;
  ikepayload->payload_id = payload_id;
  ikepayload->is_v1 = ikemesg->is_v1;

  err = cb(ikemesg,payload_id,payloadh,payload_len,ikepayload);
  if( err ){

  	RHP_TRC(0,RHPTRCID_IKEV2_NEW_PAYLOAD_RX_INIT_FAILED,"xx",ikemesg,ikemesg->rx_pkt);

    rhp_ikev2_destroy_payload(ikepayload);
    return err;
  }

  *ikepayload_r = ikepayload;

  RHP_TRC(0,RHPTRCID_IKEV2_NEW_PAYLOAD_RX_RTRN,"xx",ikemesg,*ikepayload_r);
  return 0;
}

int rhp_ikev2_new_payload_tx(rhp_ikev2_mesg* ikemesg,u8 payload_id,rhp_ikev2_payload** ikepayload_r)
{
  int err;
  rhp_ikev2_payload* ikepayload = NULL;
  RHP_IKEV2_NEW_PAYLOAD_TX cb;

  RHP_TRC(0,RHPTRCID_IKEV2_NEW_PAYLOAD_TX,"xLbx",ikemesg,"PROTO_IKE_PAYLOAD",payload_id,ikepayload_r);

  cb = _rhp_ikev2_new_tx_payload_cb(payload_id);
  if( cb == NULL ){
    RHP_TRC(0,RHPTRCID_IKEV2_NEW_PAYLOAD_TX_NOT_SUP_ID,"xb",ikemesg,payload_id);
    return RHP_STATUS_UNKNOWN_PAYLOAD;
  }

  RHP_TRC(0,RHPTRCID_IKEV2_NEW_PAYLOAD_TX_CB,"xY",ikemesg,cb);
  
  ikepayload = _rhp_ikev2_alloc_payload();
  if( ikepayload == NULL ){
    RHP_BUG("");
    return -ENOMEM;
  }

  ikepayload->ikemesg = ikemesg;
  ikepayload->payload_id = payload_id;
  ikepayload->is_v1 = ikemesg->is_v1;

  err = cb(ikemesg,payload_id,ikepayload);
  if( err ){
    RHP_TRC(0,RHPTRCID_IKEV2_NEW_PAYLOAD_TX_INIT_FAILED,"x",ikemesg);
    rhp_ikev2_destroy_payload(ikepayload);
    return err;
  }

  *ikepayload_r = ikepayload;

  RHP_TRC(0,RHPTRCID_IKEV2_NEW_PAYLOAD_TX_RTRN,"xx",ikemesg,*ikepayload_r);
  return 0;
}

