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

static rhp_ikev2_transform* _rhp_ikev2_alloc_sa_transform(u8 transform_type,u16 transform_id)
{
  rhp_ikev2_transform* trans;

  trans = (rhp_ikev2_transform*)_rhp_malloc(sizeof(rhp_ikev2_transform));
  if( trans == NULL ){
    RHP_BUG("");
    return NULL;
  }

  memset(trans,0,sizeof(rhp_ikev2_transform));

  trans->type = transform_type;
  trans->id = transform_id;

  RHP_TRC(0,RHPTRCID_IKEV2_ALLOC_SA_TRANSFORM,"Lbwx","PROTO_IKE_TRANSFORM",transform_type,transform_id,trans);
  return trans;
}

static void _rhp_ikev2_sa_payload_put_trans(rhp_ikev2_proposal* prop,rhp_ikev2_transform* trans)
{
  if( prop->trans_list_head == NULL ){
    prop->trans_list_head = trans;
  }else{
    prop->trans_list_tail->next = trans;
  }
  prop->trans_list_tail = trans;
  prop->trans_num++;

  RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_PUT_TRANS,"xxLbwd",prop,trans,"PROTO_IKE_TRANSFORM",trans->type,trans->id,prop->trans_num);
  return;
}

static int _rhp_ikev2_sa_payload_enum_trans(rhp_ikev2_proposal* prop,
                    int (*callback)(rhp_ikev2_proposal* prop,rhp_ikev2_transform* trans,void* ctx),void* ctx)
{
  int err = 0;
  rhp_ikev2_transform* trans = prop->trans_list_head;

  RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_ENUM_TRANS,"xYx",prop,callback,ctx);

  if( trans == NULL ){
    RHP_BUG("");
    return -ENOENT;
  }

  while( trans ){
    if( (err = callback(prop,trans,ctx)) ){
      RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_ENUM_TRANS_ERR,"E",err);
      return err;
    }
    trans = trans->next;
  }
  return 0;
}

static int _rhp_ikev2_sa_payload_get_trans_num(rhp_ikev2_proposal* prop)
{
  RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_TRANS_NUM,"xd",prop,prop->trans_num);
  return prop->trans_num;
}

static u8 _rhp_ikev2_sa_payload_get_protocol_id(rhp_ikev2_proposal* prop)
{
  RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_GET_PROTOCOL_ID,"xLb",prop,"PROTO_IKE_PROTOID",prop->protocol_id);
  return prop->protocol_id;
}

static u8 _rhp_ikev2_sa_payload_get_proposal_number(rhp_ikev2_proposal* prop)
{
  RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_GET_PROPOSAL_NUM,"xb",prop,prop->proposal_number);
  return prop->proposal_number;
}

static int _rhp_ikev2_sa_payload_alloc_and_put_trans(rhp_ikev2_proposal* prop,u8 type,u16 id,int key_bits_len)
{
  rhp_ikev2_transform* trans;

  RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_ALLOC_AND_PUT_TRANS,"xLbwd",prop,"PROTO_IKE_TRANSFORM",type,id,key_bits_len);
  
  trans = _rhp_ikev2_alloc_sa_transform(type,id);

  if( trans == NULL ){
    RHP_BUG("");
    return -ENOMEM;
  }

  trans->key_bits_len = key_bits_len;

  prop->put_trans(prop,trans);

  RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_ALLOC_AND_PUT_TRANS_RTRN,"x",prop);
  return 0;
}

static int _rhp_ikev2_sa_payload_get_spi(struct _rhp_ikev2_proposal* prop,u8* spi,int* spi_len)
{
  if( prop->spi_len ){
    memcpy(spi,prop->spi,prop->spi_len);
    if( spi_len ){
      *spi_len = prop->spi_len;
    }

    if( prop->spi_len == 4 ){
    	RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_GET_SPI_4,"xdH",prop,prop->spi_len,*((u32*)prop->spi));
    }else if( prop->spi_len == 8 ){
    	RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_GET_SPI_8,"xdG",prop,prop->spi_len,prop->spi);
    }else{
    	RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_GET_SPI,"xp",prop,prop->spi_len,prop->spi);
    }
    return 0;
  }
  RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_GET_SPI_NO_SPI,"x",prop);
  return -ENOENT;
}

static rhp_ikev2_proposal* _rhp_ikev2_alloc_sa_proposal()
{
  rhp_ikev2_proposal* prop;

  prop = (rhp_ikev2_proposal*)_rhp_malloc(sizeof(rhp_ikev2_proposal));
  if( prop == NULL ){
    RHP_BUG("");
    return NULL;
  }

  memset(prop,0,sizeof(rhp_ikev2_proposal));

  prop->put_trans = _rhp_ikev2_sa_payload_put_trans;
  prop->enum_trans = _rhp_ikev2_sa_payload_enum_trans;
  prop->get_trans_num = _rhp_ikev2_sa_payload_get_trans_num;
  prop->get_protocol_id = _rhp_ikev2_sa_payload_get_protocol_id;
  prop->alloc_and_put_trans = _rhp_ikev2_sa_payload_alloc_and_put_trans;
  prop->get_proposal_number = _rhp_ikev2_sa_payload_get_proposal_number;
  prop->get_spi = _rhp_ikev2_sa_payload_get_spi;

  RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_ALLOC_SA_PROPOSAL,"x",prop);
  return prop;
}

static void _rhp_ikev2_sa_payload_put_prop(rhp_ikev2_payload* payload,rhp_ikev2_proposal* prop)
{
  rhp_ikev2_sa_payload* sa_payload = payload->ext.sa;
  int trans_num,spi_len = 0;
  u8 protocol_id,proposal_number;
  u8 spi[RHP_PROTO_SPI_MAX_SIZE];
  
  RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_PUT_PROP,"xxx",payload,prop,sa_payload);
  
  trans_num = prop->get_trans_num(prop);
  protocol_id = prop->get_protocol_id(prop);
  proposal_number = prop->get_proposal_number(prop);
  prop->get_spi(prop,spi,&spi_len);

  RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_PUT_PROP_DUMP,"xxdLbbp",payload,prop,trans_num,"PROTO_IKE_PROTOID",protocol_id,proposal_number,spi_len,spi);
  
  if( sa_payload->prop_list_head == NULL ){
    sa_payload->prop_list_head = prop;
  }else{
    sa_payload->prop_list_tail->next = prop;
  }
  sa_payload->prop_list_tail = prop;
  
  return;
}

static int _rhp_ikev2_sa_payload_enum_props(rhp_ikev2_payload* payload,
           int (*callback)(rhp_ikev2_payload* payload,rhp_ikev2_proposal* prop,void* ctx),void* ctx)
{
  int err = 0;
  rhp_ikev2_sa_payload* sa_payload = payload->ext.sa;
  rhp_ikev2_proposal* prop = sa_payload->prop_list_head;

  RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_ENUM_PROPS,"xYx",payload,callback,ctx);

  if( prop == NULL ){
    RHP_BUG("");
    return -ENOENT;
  }

  while( prop ){
    if( (err = callback(payload,prop,ctx)) ){
      RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_ENUM_PROPS_ERR,"E",err);
      return err;
    }
    prop = prop->next;
  }

  RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_ENUM_PROPS_RTRN,"");
  return 0;
}

static  int _rhp_ikev2_sa_payload_enum_ikesa_prop_cb(struct _rhp_ikev2_payload* payload,
    struct _rhp_ikev2_proposal* prop,void* ctx)
{
  rhp_res_sa_proposal* res_prop = (rhp_res_sa_proposal*)ctx;
  rhp_res_sa_proposal res_prop_tmp;

  RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_ENUM_IKESA_PROP_CB,"xxx",payload,prop,ctx);

  memset(&res_prop_tmp,0,sizeof(rhp_res_sa_proposal));

  if( !rhp_cfg_match_ikesa_proposal(prop,&res_prop_tmp) ){

  	if( !res_prop->number ||
  			 (( res_prop->encr_priority >= res_prop_tmp.encr_priority ) 		&&
 					( res_prop->prf_priority >= res_prop_tmp.prf_priority ) 			&&
 					( res_prop->integ_priority >= res_prop_tmp.integ_priority ) 	&&
 					( res_prop->dhgrp_priority >= res_prop_tmp.dhgrp_priority ))
  	){
  		memcpy(res_prop,&res_prop_tmp,sizeof(rhp_res_sa_proposal));
  	}

    return 0;
  }

  return 0;
}

static  int _rhp_ikev2_sa_payload_enum_childsa_prop_cb(struct _rhp_ikev2_payload* payload,
    struct _rhp_ikev2_proposal* prop,void* ctx)
{
	int err = -EINVAL;
  rhp_res_sa_proposal* res_prop = (rhp_res_sa_proposal*)ctx;
  rhp_res_sa_proposal res_prop_tmp;

  RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_ENUM_CHILDSA_PROP_CB,"xxx",payload,prop,ctx);

  memset(&res_prop_tmp,0,sizeof(rhp_res_sa_proposal));
  res_prop_tmp.pfs = res_prop->pfs;

  err = rhp_cfg_match_childsa_proposal(prop,&res_prop_tmp,res_prop->pfs);
  if( !err ){

  	if( !res_prop->number ||
  			( ( res_prop->encr_priority >= res_prop_tmp.encr_priority ) 		&&
 					( res_prop->integ_priority >= res_prop_tmp.integ_priority ) 	&&
 					( res_prop->esn_priority >= res_prop_tmp.esn_priority ) 			&&
 					( res_prop->dhgrp_priority >= res_prop_tmp.dhgrp_priority ) )
  	){
  		memcpy(res_prop,&res_prop_tmp,sizeof(rhp_res_sa_proposal));
  	}

  	return 0;

  }else if( err == RHP_STATUS_INVALID_IKEV2_MESG_PFS_REQUIRED ){

  	RHP_LOG_DE(RHP_LOG_SRC_CFG,0,RHP_LOG_ID_CHILDSA_PFS_BUT_NO_DH_ALG_IN_PROP,"K",payload->ikemesg);
  	err = 0;
  }

  return 0;
}

static int _rhp_ikev2_sa_payload_get_matched_ikesa_prop(rhp_ikev2_payload* payload,rhp_res_sa_proposal* res_prop)
{
  rhp_ikev2_sa_payload* sa_payload = payload->ext.sa;
  int err;

  RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_GET_MATCHED_IKESA_PROP,"xx",payload,res_prop);

  if( sa_payload == NULL ){
    RHP_BUG("");
    goto error;
  }

  res_prop->number = 0;
  res_prop->spi_len = 0;
  res_prop->dhgrp_id = 0;
  
  err = sa_payload->enum_props(payload,_rhp_ikev2_sa_payload_enum_ikesa_prop_cb,res_prop);
  if( err  ){
    RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_GET_MATCHED_IKESA_PROP_ERR,"xE",payload,err);
    goto error;
  }
  rhp_cfg_dump_res_sa_prop(res_prop);

  if( !res_prop->number ){
    RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_GET_MATCHED_IKESA_PROP_NOT_FOUND,"x",payload);
  	goto error;
  }

  RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_GET_MATCHED_IKESA_PROP_RTRN,"xxbLbpwdwwwwd",payload,res_prop,res_prop->number,"PROTO_IKE_PROTOID",res_prop->protocol_id,res_prop->spi_len,res_prop->spi,res_prop->encr_id,res_prop->encr_key_bits,res_prop->prf_id,res_prop->integ_id,res_prop->dhgrp_id,res_prop->esn,res_prop->pfs);
  return 0;

error:
	RHP_LOG_DE(RHP_LOG_SRC_CFG,0,RHP_LOG_ID_IKESA_NO_PROPOSAL_CHOSEN,"K",payload->ikemesg);
	RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_GET_MATCHED_IKESA_PROP_ERR,"xx",payload,res_prop);
  return -ENOENT;
}

static int _rhp_ikev2_sa_payload_get_matched_childsa_prop(rhp_ikev2_payload* payload,rhp_res_sa_proposal* res_prop)
{
  rhp_ikev2_sa_payload* sa_payload = payload->ext.sa;
  int err;

  RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_GET_MATCHED_CHILDSA_PROP,"xx",payload,res_prop);

  if( sa_payload == NULL ){
    RHP_BUG("");
    goto error;
  }

  res_prop->number = 0;
  res_prop->spi_len = 0;
  res_prop->esn = 0;
  res_prop->dhgrp_id = 0;
  
  err = sa_payload->enum_props(payload,_rhp_ikev2_sa_payload_enum_childsa_prop_cb,res_prop);
  if( err ){
    RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_GET_MATCHED_CHILDSA_PROP_ERR,"xE",payload,err);
    goto error;
  }
  rhp_cfg_dump_res_sa_prop(res_prop);

  if( !res_prop->number ){
    RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_GET_MATCHED_CHILDSA_PROP_NOT_FOUND,"x",payload);
  	goto error;
  }

  RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_GET_MATCHED_CHILDSA_PROP_RTRN,"xxbLbpwdwwwwd",payload,res_prop,res_prop->number,"PROTO_IKE_PROTOID",res_prop->protocol_id,res_prop->spi_len,res_prop->spi,res_prop->encr_id,res_prop->encr_key_bits,res_prop->prf_id,res_prop->integ_id,res_prop->dhgrp_id,res_prop->esn,res_prop->pfs);
  return 0;

error:
	RHP_LOG_DE(RHP_LOG_SRC_CFG,0,RHP_LOG_ID_CHILDSA_NO_PROPOSAL_CHOSEN,"K",payload->ikemesg);
	RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_GET_MATCHED_CHILDSA_PROP_ERR,"xx",payload,res_prop);
  return -ENOENT;
}

static void _rhp_ikev2_sa_payload_destructor(rhp_ikev2_payload* payload)
{
  rhp_ikev2_sa_payload* sa_payload = payload->ext.sa;
  rhp_ikev2_proposal *prop,*prop2;
  rhp_ikev2_transform *trans,*trans2;

  RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_DESTRUCTOR,"xx",payload,sa_payload);

  if( sa_payload == NULL ){
    RHP_BUG("");
    return;
  }

  prop = sa_payload->prop_list_head;
  while( prop ){

    prop2 = prop->next;

    trans = prop->trans_list_head;
    while( trans ){
      trans2 = trans->next;
      _rhp_free_zero(trans,sizeof(rhp_ikev2_transform));
      trans = trans2;
    }

    _rhp_free_zero(prop,sizeof(rhp_ikev2_proposal));
    prop = prop2;
  }

  sa_payload->prop_list_head = NULL;

  RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_DESTRUCTOR_RTRN,"xx",payload,sa_payload);
  return;
}

static int _rhp_ikev2_sa_payload_serialize(rhp_ikev2_payload* payload,rhp_packet* pkt)
{
  int err = -EINVAL;
  rhp_ikev2_proposal* prop = payload->ext.sa->prop_list_head;
  rhp_ikev2_transform* trans;

  RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_SERIALIZE,"xxx",payload,pkt,payload->ext.sa->prop_list_head);

  if( prop ){

    int len = sizeof(rhp_proto_ike_sa_payload);
    rhp_proto_ike_sa_payload* pldh;
    rhp_proto_ike_proposal* proph;
    rhp_proto_ike_transform* transh;
    rhp_proto_ike_attr* attrh;
    int pld_offset = 0;

    pldh = (rhp_proto_ike_sa_payload*)rhp_pkt_expand_tail(pkt,len);
    if( pldh == NULL ){
      RHP_BUG("");
      return -ENOMEM;
    }
    pld_offset = ((u8*)pldh) - pkt->head;

    pldh->next_payload = payload->get_next_payload(payload);
    pldh->critical_rsv = RHP_PROTO_IKE_PLD_SET_CRITICAL;

    while( prop ){

      int prop_len = sizeof(rhp_proto_ike_proposal) + prop->spi_len;
      int spi_len;
      int trans_num = 0;
      int prop_offset = 0;

      trans = prop->trans_list_head;

      if( trans == NULL ){
        err = -ENOENT;
        RHP_BUG("");
        goto error;
      }

      proph = (rhp_proto_ike_proposal*)rhp_pkt_expand_tail(pkt,prop_len);
      if( proph == NULL ){
        err = -ENOMEM;
        RHP_BUG("");
        goto error;
      }
      prop_offset = ((u8*)proph) - pkt->head;

      if( prop->next ){
        proph->last_or_more = RHP_PROTO_IKE_PROPOSAL_MORE;
      }else{
        proph->last_or_more = RHP_PROTO_IKE_PROPOSAL_LAST;
      }
      proph->reserved = 0;
      proph->proposal_number = prop->get_proposal_number(prop);
      proph->protocol = prop->get_protocol_id(prop);

      if( prop->spi_len ){
        spi_len = (int)proph->spi_len;
        err = prop->get_spi(prop,(u8*)(proph + 1),&spi_len);
        if( err ){
          RHP_BUG("");
          goto error;
        }
        proph->spi_len = (u8)spi_len;
      }else{
        proph->spi_len = 0;
      }

      while( trans ){

        int trans_len = sizeof(rhp_proto_ike_transform);
        int trans_offset = 0;

        transh = (rhp_proto_ike_transform*)rhp_pkt_expand_tail(pkt,trans_len);

        if( transh == NULL ){
          err = -ENOMEM;
          RHP_BUG("");
          goto error;
        }
        trans_offset = ((u8*)transh) - pkt->head;

        if( trans->next ){
          transh->last_or_more = RHP_PROTO_IKE_TRANSFORM_MORE;
        }else{
          transh->last_or_more = RHP_PROTO_IKE_TRANSFORM_LAST;
        }
        transh->reserved1 = 0;
        transh->reserved2 = 0;

        transh->transform_type = trans->type;
        transh->transform_id = htons(trans->id);

        // Ugly...
        if( trans->key_bits_len ){

          attrh = (rhp_proto_ike_attr*)rhp_pkt_expand_tail(pkt,sizeof(rhp_proto_ike_attr));

          if( attrh == NULL ){
            err = -ENOMEM;
            RHP_BUG("");
            goto error;
          }

          attrh->attr_type = RHP_PROTO_IKE_ATTR_SET_AF(htons(RHP_PROTO_IKE_ATTR_KEYLEN));
          attrh->len_or_value = htons(trans->key_bits_len);

          trans_len += sizeof(rhp_proto_ike_attr);
        }


        transh = (rhp_proto_ike_transform*)(pkt->head + trans_offset);

        transh->len = htons(trans_len);

        prop_len += trans_len;
        trans_num++;

        trans = trans->next;
      }


      proph = (rhp_proto_ike_proposal*)(pkt->head + prop_offset);

      proph->transform_num = trans_num;
//    proph->len = htons(prop_len - sizeof(rhp_proto_ike_proposal));
      proph->len = htons(prop_len);
      len += prop_len;

      prop = prop->next;
    }


    pldh = (rhp_proto_ike_sa_payload*)(pkt->head + pld_offset);
    pldh->len = htons(len);
    payload->ikemesg->tx_mesg_len += len;

    pldh->next_payload = RHP_PROTO_IKE_NO_MORE_PAYLOADS;
    if( payload->next ){
    	pldh->next_payload = payload->next->get_payload_id(payload->next);
    }

    RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_SERIALIZE_RTRN,"");
    rhp_pkt_trace_dump("_rhp_ikev2_sa_payload_serialize",pkt);
    return 0;
  }

error:
  RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_SERIALIZE_ERR,"E",err);
  return err;
}

static int _rhp_ikev2_sa_payload_set_def_ikesa_prop(rhp_ikev2_payload* payload,u8* spi,int spi_len,
		u16 dhgrp_id)
{
  int err = 0;
  rhp_cfg_ikesa* cfg_ikesa;
  rhp_cfg_transform* trans = NULL;
  rhp_ikev2_proposal* prop = NULL;
  rhp_ikev2_sa_payload* sa_payload = payload->ext.sa;

  RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_SET_DEF_IKESA_PROP,"xpxw",payload,spi_len,spi,sa_payload,dhgrp_id);

  if( sa_payload == NULL ){
    err = -EINVAL;
    RHP_BUG("");
    goto error;
  }

  RHP_LOCK(&rhp_cfg_lock);

  if( spi_len && spi_len != RHP_PROTO_IKE_SPI_SIZE ){
    err = -EINVAL;
    RHP_BUG("");
    goto error;
  }

  cfg_ikesa = rhp_cfg_get_ikesa_security();

  if( cfg_ikesa == NULL ){
    err = -ENOENT;
    RHP_BUG("");
    goto error;
  }

  if( cfg_ikesa->protocol_id != RHP_PROTO_IKE_PROTOID_IKE ){
    err = -ENOENT;
    RHP_BUG("%d",cfg_ikesa->protocol_id);
    goto error;
  }

  if( cfg_ikesa->encr_trans_list == NULL || cfg_ikesa->prf_trans_list == NULL ||
      cfg_ikesa->integ_trans_list == NULL || cfg_ikesa->dh_trans_list == NULL ){
    err = -ENOENT;
    RHP_BUG("0x%x,0x%x,0x%x,0x%x",cfg_ikesa->encr_trans_list,cfg_ikesa->prf_trans_list,cfg_ikesa->integ_trans_list,cfg_ikesa->dh_trans_list);
    goto error;
  }

  prop = _rhp_ikev2_alloc_sa_proposal();

  if( prop == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  prop->protocol_id = cfg_ikesa->protocol_id;
  prop->proposal_number = 1;

  if( spi_len ){
    memcpy(prop->spi,spi,spi_len);
  }
  prop->spi_len = spi_len;

  trans = cfg_ikesa->encr_trans_list;
  while( trans ){
    err = prop->alloc_and_put_trans(prop,trans->type,trans->id,trans->key_bits_len);
    if( err ){
      RHP_BUG("");
      goto error;
    }
    trans = trans->next;
  }

  trans = cfg_ikesa->prf_trans_list;
  while( trans ){
    err = prop->alloc_and_put_trans(prop,trans->type,trans->id,0);
    if( err ){
      RHP_BUG("");
      goto error;
    }
    trans = trans->next;
  }

  trans = cfg_ikesa->integ_trans_list;
  while( trans ){
    err = prop->alloc_and_put_trans(prop,trans->type,trans->id,0);
    if( err ){
      RHP_BUG("");
      goto error;
    }
    trans = trans->next;
  }

  {
  	if( dhgrp_id ){

	    trans = cfg_ikesa->dh_trans_list;
	    while( trans ){
	
	      if( trans->id == dhgrp_id ){
	   	    break;
	      }
	      trans = trans->next;
	    }
	
	    if( trans == NULL ){
	      goto error;    	
	    }
	    
	    err = prop->alloc_and_put_trans(prop,trans->type,trans->id,0);
	    if( err ){
	      RHP_BUG("");
	      goto error;
	    }
	    
	  }else{
		  
	    trans = cfg_ikesa->dh_trans_list;
	    while( trans ){
	      err = prop->alloc_and_put_trans(prop,trans->type,trans->id,0);
	      if( err ){
	        RHP_BUG("");
	        goto error;
	      }
	     trans = trans->next;
	    }
	  }
  }
  
  sa_payload->put_prop(payload,prop);

  RHP_UNLOCK(&rhp_cfg_lock);

  RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_SET_DEF_IKESA_PROP_RTRN,"x",prop);
  return 0;

error:
  if( prop){
    _rhp_free(prop);
  }
  RHP_UNLOCK(&rhp_cfg_lock);

  RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_SET_DEF_IKESA_PROP_ERR,"E",err);
  return err;
}

static int _rhp_ikev2_sa_payload_copy_ikesa_prop(rhp_ikev2_payload* payload,u8* spi,int spi_len,rhp_ikesa* old_ikesa)
{
  int err = 0;
  rhp_ikev2_proposal* prop = NULL;
  rhp_ikev2_sa_payload* sa_payload = payload->ext.sa;

  RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_COPY_IKESA_PROP,"xpxx",payload,spi_len,spi,sa_payload,old_ikesa);

  if( sa_payload == NULL ){
    err = -EINVAL;
    RHP_BUG("");
    goto error;
  }

  if( spi_len && spi_len != RHP_PROTO_IKE_SPI_SIZE ){
    err = -EINVAL;
    RHP_BUG("");
    goto error;
  }


  prop = _rhp_ikev2_alloc_sa_proposal();

  if( prop == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  prop->protocol_id = RHP_PROTO_IKE_PROTOID_IKE;
  prop->proposal_number = 1;

  if( spi_len ){
    memcpy(prop->spi,spi,spi_len);
  }
  prop->spi_len = spi_len;


	err = prop->alloc_and_put_trans(prop,RHP_PROTO_IKE_TRANSFORM_TYPE_ENCR,old_ikesa->encr->alg,old_ikesa->encr->alg_key_bits);
	if( err ){
		RHP_BUG("");
		goto error;
	}

  err = prop->alloc_and_put_trans(prop,RHP_PROTO_IKE_TRANSFORM_TYPE_PRF,old_ikesa->prf->alg,0);
  if( err ){
    RHP_BUG("");
    goto error;
  }

  err = prop->alloc_and_put_trans(prop,RHP_PROTO_IKE_TRANSFORM_TYPE_INTEG,old_ikesa->integ_i->alg,0);
  if( err ){
    RHP_BUG("");
    goto error;
  }

  err = prop->alloc_and_put_trans(prop,RHP_PROTO_IKE_TRANSFORM_TYPE_DH,old_ikesa->dh->grp,0);
  if( err ){
    RHP_BUG("");
    goto error;
  }


  sa_payload->put_prop(payload,prop);

  RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_COPY_IKESA_PROP_RTRN,"x",prop);
  return 0;

error:
  if( prop){
    _rhp_free(prop);
  }

  RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_COPY_IKESA_PROP_ERR,"E",err);
  return err;
}

static int _rhp_ikev2_sa_payload_set_def_childsa_prop(rhp_ikev2_payload* payload,u8* spi,int spi_len,u16 rekey_pfs_dhgrp_id)
{
  int err = 0;
  rhp_cfg_childsa* cfg_childsa;
  rhp_cfg_transform* trans = NULL;
  rhp_ikev2_proposal* prop = NULL;
  rhp_ikev2_sa_payload* sa_payload = payload->ext.sa;

  RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_SET_DEF_CHILDSA_PROP,"xpxw",payload,spi_len,spi,sa_payload,rekey_pfs_dhgrp_id);

  if( sa_payload == NULL ){
    err = -EINVAL;
    RHP_BUG("");
    goto error;
  }

  RHP_LOCK(&rhp_cfg_lock);

  if( spi_len != RHP_PROTO_IPSEC_SPI_SIZE ){
    err = -EINVAL;
    RHP_BUG("");
    goto error;
  }

  cfg_childsa = rhp_cfg_get_childsa_security();

  if( cfg_childsa == NULL ){
    err = -ENOENT;
    RHP_BUG("");
    goto error;
  }

  if( cfg_childsa->protocol_id != RHP_PROTO_IKE_PROTOID_ESP &&
      cfg_childsa->protocol_id != RHP_PROTO_IKE_PROTOID_AH ){
    err = -ENOENT;
    RHP_BUG("");
    goto error;
  }

  if( cfg_childsa->protocol_id == RHP_PROTO_IKE_PROTOID_ESP ){
    if( cfg_childsa->encr_trans_list == NULL ){
      err = -ENOENT;
      RHP_BUG("");
      goto error;
    }
  }

  if( cfg_childsa->protocol_id == RHP_PROTO_IKE_PROTOID_AH ){
    if( cfg_childsa->integ_trans_list == NULL ){
      err = -ENOENT;
      RHP_BUG("");
      goto error;
    }
  }

  prop = _rhp_ikev2_alloc_sa_proposal();

  if( prop == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  prop->protocol_id = cfg_childsa->protocol_id;
  prop->proposal_number = 1;
  memcpy(prop->spi,spi,spi_len);
  prop->spi_len = spi_len;

  trans = cfg_childsa->encr_trans_list;
  while( trans ){
    err = prop->alloc_and_put_trans(prop,trans->type,trans->id,trans->key_bits_len);
    if( err ){
      RHP_BUG("");
      goto error;
    }
    trans = trans->next;
  }

  trans = cfg_childsa->integ_trans_list;
  while( trans ){
    err = prop->alloc_and_put_trans(prop,trans->type,trans->id,0);
    if( err ){
      RHP_BUG("");
      goto error;
    }
    trans = trans->next;
  }

  if( rekey_pfs_dhgrp_id ){
	  
    err = prop->alloc_and_put_trans(prop,RHP_PROTO_IKE_TRANSFORM_TYPE_DH,rekey_pfs_dhgrp_id,0);
    if( err ){
      RHP_BUG("");
      goto error;
    }
  }
  
  trans = cfg_childsa->esn_trans;
  while( trans ){
    err = prop->alloc_and_put_trans(prop,trans->type,trans->id,0);
    if( err ){
      RHP_BUG("");
      goto error;
    }
    trans = trans->next;
  }

  sa_payload->put_prop(payload,prop);

  RHP_UNLOCK(&rhp_cfg_lock);

  RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_SET_DEF_CHILDSA_PROP_RTRN,"x",prop);
  return 0;

error:
  if( prop ){
    _rhp_free(prop);
  }
  RHP_UNLOCK(&rhp_cfg_lock);

  RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_SET_DEF_CHILDSA_PROP_ERR,"E",err);
  return err;
}

static int _rhp_ikev2_sa_payload_copy_childsa_prop(rhp_ikev2_payload* payload,u8* spi,int spi_len,
		rhp_childsa* old_childsa,u16 rekey_pfs_dhgrp_id)
{
  int err = 0;
  rhp_ikev2_proposal* prop = NULL;
  rhp_ikev2_sa_payload* sa_payload = payload->ext.sa;

  RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_COPY_CHILDSA_PROP,"xpxxw",payload,spi_len,spi,sa_payload,old_childsa,rekey_pfs_dhgrp_id);

  if( sa_payload == NULL ){
    err = -EINVAL;
    RHP_BUG("");
    goto error;
  }

  if( spi_len != RHP_PROTO_IPSEC_SPI_SIZE ){
    err = -EINVAL;
    RHP_BUG("");
    goto error;
  }


  prop = _rhp_ikev2_alloc_sa_proposal();

  if( prop == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  prop->protocol_id = RHP_PROTO_IKE_PROTOID_ESP;
  prop->proposal_number = 1;
  memcpy(prop->spi,spi,spi_len);
  prop->spi_len = spi_len;

  err = prop->alloc_and_put_trans(prop,RHP_PROTO_IKE_TRANSFORM_TYPE_ENCR,old_childsa->encr->alg,old_childsa->encr->alg_key_bits);
  if( err ){
    RHP_BUG("");
    goto error;
  }

  err = prop->alloc_and_put_trans(prop,RHP_PROTO_IKE_TRANSFORM_TYPE_INTEG,old_childsa->integ_inb->alg,0);
  if( err ){
    RHP_BUG("");
    goto error;
  }

  if( rekey_pfs_dhgrp_id ){

    err = prop->alloc_and_put_trans(prop,RHP_PROTO_IKE_TRANSFORM_TYPE_DH,rekey_pfs_dhgrp_id,0);
    if( err ){
      RHP_BUG("");
      goto error;
    }
  }

  err = prop->alloc_and_put_trans(prop,RHP_PROTO_IKE_TRANSFORM_TYPE_ESN,(old_childsa->esn ? 1 : 0),0);
  if( err ){
    RHP_BUG("");
    goto error;
  }


  sa_payload->put_prop(payload,prop);

  RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_COPY_CHILDSA_PROP_RTRN,"x",prop);
  return 0;

error:
  if( prop ){
    _rhp_free(prop);
  }

  RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_COPY_CHILDSA_PROP_ERR,"E",err);
  return err;
}

static int _rhp_ikev2_sa_payload_set_matched_ikesa_prop(rhp_ikev2_payload* payload,
    rhp_res_sa_proposal* res_prop,u8* spi,int spi_len)
{
  int err = 0;
  rhp_ikev2_sa_payload* sa_payload = payload->ext.sa;
  rhp_ikev2_proposal* prop = NULL;

  RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_SET_MACHED_IKESA_PROP,"xxp",payload,res_prop,spi_len,spi);

  if( sa_payload == NULL ){
    err = -EINVAL;
    RHP_BUG("");
    goto error;
  }
  
  if( spi && spi_len != RHP_PROTO_IKE_SPI_SIZE ){
    err = -EINVAL;
    RHP_BUG("");
    goto error;
  }

  if( res_prop->protocol_id != RHP_PROTO_IKE_PROTOID_IKE ){
    err = -ENOENT;
    RHP_BUG("");
    goto error;
  }

  if( res_prop->prf_id == 0   || res_prop->integ_id == 0 ||
	   res_prop->dhgrp_id == 0 || res_prop->encr_id == 0 ){
    err = -ENOENT;
    RHP_BUG("%d,%d,%d,%d",res_prop->prf_id,res_prop->integ_id,res_prop->dhgrp_id,res_prop->encr_id);
    goto error;
  }

  prop = _rhp_ikev2_alloc_sa_proposal();

  if( prop == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  prop->protocol_id = res_prop->protocol_id;
  prop->proposal_number = res_prop->number;

  if( spi ){
    memcpy(prop->spi,spi,spi_len);
    prop->spi_len = spi_len;
  }else{
    prop->spi_len = 0;
  }

  err = prop->alloc_and_put_trans(prop,RHP_PROTO_IKE_TRANSFORM_TYPE_ENCR,res_prop->encr_id,res_prop->encr_key_bits);
  if( err ){
    RHP_BUG("");
    goto error;
  }

  err = prop->alloc_and_put_trans(prop,RHP_PROTO_IKE_TRANSFORM_TYPE_PRF,res_prop->prf_id,0);
  if( err ){
    RHP_BUG("");
    goto error;
  }

  err = prop->alloc_and_put_trans(prop,RHP_PROTO_IKE_TRANSFORM_TYPE_INTEG,res_prop->integ_id,0);
  if( err ){
    RHP_BUG("");
    goto error;
  }

	err = prop->alloc_and_put_trans(prop,RHP_PROTO_IKE_TRANSFORM_TYPE_DH,res_prop->dhgrp_id,0);
	if( err ){
		RHP_BUG("");
		goto error;
	}

  sa_payload->put_prop(payload,prop);
  
  RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_SET_MACHED_IKESA_PROP_RTRN,"");
  return 0;

error:
  if( prop){
    _rhp_free(prop);
  }

  RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_SET_MACHED_IKESA_PROP_ERR,"E",err);
  return err;
}

static int _rhp_ikev2_sa_payload_set_matched_childsa_prop(rhp_ikev2_payload* payload,
    rhp_res_sa_proposal* res_prop,u32 spi)
{
  int err = 0;
  rhp_ikev2_sa_payload* sa_payload = payload->ext.sa;
  rhp_ikev2_proposal* prop = NULL;

  RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_SET_MACHED_CHILDSA_PROP,"xxux",payload,res_prop,spi,spi);

  if( sa_payload == NULL ){
    err = -EINVAL;
    RHP_BUG("");
    goto error;
  }
  
  if( res_prop->protocol_id != RHP_PROTO_IKE_PROTOID_ESP &&
      res_prop->protocol_id != RHP_PROTO_IKE_PROTOID_AH ){
    err = -ENOENT;
    RHP_BUG("");
    goto error;
  }

  if( res_prop->protocol_id == RHP_PROTO_IKE_PROTOID_ESP ){
    if( res_prop->encr_id == 0 ){
      err = -ENOENT;
      RHP_BUG("");
      goto error;
    }
  }

  if( res_prop->protocol_id == RHP_PROTO_IKE_PROTOID_AH ){
    if( res_prop->integ_id == 0 ){
      err = -ENOENT;
      RHP_BUG("");
      goto error;
    }
  }

  prop = _rhp_ikev2_alloc_sa_proposal();

  if( prop == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  prop->protocol_id = res_prop->protocol_id;
  prop->proposal_number = res_prop->number;
  memcpy(prop->spi,(u8*)&spi,RHP_PROTO_IPSEC_SPI_SIZE);
  prop->spi_len = RHP_PROTO_IPSEC_SPI_SIZE;

  err = prop->alloc_and_put_trans(prop,RHP_PROTO_IKE_TRANSFORM_TYPE_ENCR,res_prop->encr_id,res_prop->encr_key_bits);
  if( err ){
    RHP_BUG("");
    goto error;
  }

  err = prop->alloc_and_put_trans(prop,RHP_PROTO_IKE_TRANSFORM_TYPE_INTEG,res_prop->integ_id,0);
  if( err ){
    RHP_BUG("");
    goto error;
  }

  if( res_prop->pfs && res_prop->dhgrp_id ){
	  
  	err = prop->alloc_and_put_trans(prop,RHP_PROTO_IKE_TRANSFORM_TYPE_DH,res_prop->dhgrp_id,0);
  	if( err ){
  		RHP_BUG("");
  		goto error;
    }
  }
  
  err = prop->alloc_and_put_trans(prop,RHP_PROTO_IKE_TRANSFORM_TYPE_ESN,res_prop->esn,0);
  if( err ){
    RHP_BUG("");
    goto error;
  }

  sa_payload->put_prop(payload,prop);
  
  RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_SET_MACHED_CHILDSA_PROP_RTRN,"");
  return 0;

error:
  if( prop){
    _rhp_free(prop);
  }

  RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_SET_MACHED_CHILDSA_PROP_ERR,"d",err);
  return err;
}

static int _rhp_ikev2_rx_payload_is_for_ikesa(rhp_ikev2_payload* payload)
{
  return payload->ext.sa->is_for_ikesa;	
}

static rhp_ikev2_sa_payload* _rhp_ikev2_alloc_sa_payload()
{
  rhp_ikev2_sa_payload* sa_payload;

  sa_payload = (rhp_ikev2_sa_payload*)_rhp_malloc(sizeof(rhp_ikev2_sa_payload));
  if( sa_payload == NULL ){
    RHP_BUG("");
    return NULL;
  }

  memset(sa_payload,0,sizeof(rhp_ikev2_sa_payload));

  sa_payload->put_prop = _rhp_ikev2_sa_payload_put_prop;
  sa_payload->enum_props = _rhp_ikev2_sa_payload_enum_props;
  sa_payload->get_matched_ikesa_prop = _rhp_ikev2_sa_payload_get_matched_ikesa_prop;
  sa_payload->get_matched_childsa_prop = _rhp_ikev2_sa_payload_get_matched_childsa_prop;
  sa_payload->set_def_ikesa_prop = _rhp_ikev2_sa_payload_set_def_ikesa_prop;
  sa_payload->copy_ikesa_prop = _rhp_ikev2_sa_payload_copy_ikesa_prop;
  sa_payload->set_def_childsa_prop = _rhp_ikev2_sa_payload_set_def_childsa_prop;
  sa_payload->copy_childsa_prop = _rhp_ikev2_sa_payload_copy_childsa_prop;
  sa_payload->set_matched_ikesa_prop = _rhp_ikev2_sa_payload_set_matched_ikesa_prop;
  sa_payload->set_matched_childsa_prop = _rhp_ikev2_sa_payload_set_matched_childsa_prop;
  sa_payload->rx_payload_is_for_ikesa = _rhp_ikev2_rx_payload_is_for_ikesa;
  
  RHP_TRC(0,RHPTRCID_IKEV2_ALLOC_SA_PAYLOAD,"x",sa_payload);
  return sa_payload;
}


static int _rhp_ikev2_sa_payload_prop_dump_cb(rhp_ikev2_proposal* prop,rhp_ikev2_transform* trans,void* ctx)
{
  int len = 0;

  if( trans->transh ){
    len = ntohs(trans->transh->len);
  }

  RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_TRANS_DUMP,"xxxbwdp",prop,trans->next,trans->transh,trans->type,trans->id,trans->key_bits_len,len,trans->transh);

  return 0;
}

static int _rhp_ikev2_sa_payload_dump_cb(rhp_ikev2_payload* payload,rhp_ikev2_proposal* prop,void* ctx)
{
  int len = 0;

  if( prop->proph ){
    len = ntohs(prop->proph->len);
  }

  RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_PROP_DUMP,"xxxdxxbbdpp",payload,prop->next,prop->proph,prop->trans_num,prop->trans_list_head,prop->trans_list_tail,prop->protocol_id,prop->proposal_number,prop->spi_len,RHP_PROTO_SPI_MAX_SIZE,prop->spi,len,prop->proph);

  prop->enum_trans(prop,_rhp_ikev2_sa_payload_prop_dump_cb,NULL);

  return 0;
}

static void _rhp_ikev2_sa_payload_dump(rhp_ikev2_payload* payload)
{
  rhp_ikev2_sa_payload* sa_payload = payload->ext.sa;
  int len = 0;

  if( sa_payload == NULL ){
    RHP_BUG("");
    return;
  }

  if( payload->payloadh ){
    len = ntohs(payload->payloadh->len);
  }

  RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_DUMP,"xxxxxbxxp",payload,sa_payload,payload->next,payload->ikemesg,payload->payloadh,payload->payload_id,sa_payload->prop_list_head,sa_payload->prop_list_tail,len,payload->payloadh);

  sa_payload->enum_props(payload,_rhp_ikev2_sa_payload_dump_cb,NULL);
}


int rhp_ikev2_sa_payload_new_rx(rhp_ikev2_mesg* ikemesg,u8 payload_id,
                                rhp_proto_ike_payload* payloadh,int payload_len,rhp_ikev2_payload* payload)
{
  int i;
  int err = 0;
  rhp_ikev2_sa_payload* sa_payload;
  rhp_proto_ike_sa_payload* sa_payloadh = (rhp_proto_ike_sa_payload*)payloadh;
  rhp_proto_ike_proposal* proph;
  rhp_proto_ike_transform* transh;
  rhp_proto_ike_attr* attrh;
  int last_prop_flag = 0;
  int prop_len,trans_len;
  u8* prop_spi;
  rhp_ikev2_proposal* prop;
  rhp_ikev2_transform* trans;
  u8 exchange_type;

  RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_NEW_RX,"xLbxdxp",ikemesg,"PROTO_IKE_PAYLOAD",payload_id,payloadh,payload_len,payload,payload_len,payloadh);

  exchange_type = ikemesg->get_exchange_type(ikemesg);

  if( payload_len
      <= (int)sizeof(rhp_proto_ike_sa_payload) + (int)sizeof(rhp_proto_ike_proposal) + (int)sizeof(rhp_proto_ike_transform)  ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_NEW_RX_INVALID_MESG_1,"xdddd",ikemesg,payload_len,sizeof(rhp_proto_ike_sa_payload),sizeof(rhp_proto_ike_proposal),sizeof(rhp_proto_ike_transform));
    goto error;
  }

  sa_payload = _rhp_ikev2_alloc_sa_payload();
  if( sa_payload == NULL ){
    err = -ENOMEM;
    RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_NEW_RX_INVALID_MESG_2,"x",ikemesg);
    goto error;
  }

  payload->ext.sa = sa_payload;
  payload->ext_destructor = _rhp_ikev2_sa_payload_destructor;
  payload->ext_serialize = _rhp_ikev2_sa_payload_serialize;
  payload->ext_dump = _rhp_ikev2_sa_payload_dump;

  sa_payloadh = (rhp_proto_ike_sa_payload*)_rhp_pkt_pull(ikemesg->rx_pkt,sizeof(rhp_proto_ike_sa_payload));
  if( sa_payloadh == NULL ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_NEW_RX_INVALID_MESG_3,"x",ikemesg);
    goto error;
  }

  do{

  	proph = (rhp_proto_ike_proposal*)_rhp_pkt_pull(ikemesg->rx_pkt,sizeof(rhp_proto_ike_proposal));
  	if( proph == NULL ){
      err = RHP_STATUS_INVALID_MSG;
      RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_NEW_RX_INVALID_MESG_4,"x",ikemesg);
      goto error;
    }

  	if( proph->last_or_more != RHP_PROTO_IKE_PROPOSAL_LAST &&
        proph->last_or_more != RHP_PROTO_IKE_PROPOSAL_MORE ){
      err = RHP_STATUS_INVALID_MSG;
      RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_NEW_RX_INVALID_MESG_5,"xb",ikemesg,proph->last_or_more);
      goto error;
    }

  	if( proph->transform_num == 0 ){
      err = RHP_STATUS_INVALID_MSG;
      RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_NEW_RX_INVALID_MESG_6,"xd",ikemesg);
      goto error;
    }

  	prop_len = ntohs(proph->len);

  	if( prop_len == 0 || _rhp_pkt_try_pull(ikemesg->rx_pkt,prop_len) ){
      err = RHP_STATUS_INVALID_MSG;
      RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_NEW_RX_INVALID_MESG_7,"x",ikemesg);
      goto error;
    }

  	if( proph->spi_len > 0 ){

    	if( proph->spi_len > RHP_PROTO_SPI_MAX_SIZE ){
        err = RHP_STATUS_INVALID_MSG;
        RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_NEW_RX_INVALID_MESG_8,"xbd",ikemesg,proph->spi_len,RHP_PROTO_SPI_MAX_SIZE);
        goto error;
      }

     prop_spi = (u8*)_rhp_pkt_pull(ikemesg->rx_pkt,proph->spi_len);
     if( prop_spi == NULL ){
       err = RHP_STATUS_INVALID_MSG;
       RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_NEW_RX_INVALID_MESG_9,"x",ikemesg);
       goto error;
     	}

  	}else{

  		prop_spi = NULL;
  	}

  	if( proph->protocol == RHP_PROTO_IKE_PROTOID_IKE ){

  		if( exchange_type == RHP_PROTO_IKE_EXCHG_IKE_SA_INIT ){
  			
  			if( proph->spi_len != 0 ){
          err = RHP_STATUS_INVALID_MSG;
          RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_NEW_RX_INVALID_MESG_10,"xb",ikemesg,proph->spi_len);
          goto error;
        }
  			
  		}else if( exchange_type == RHP_PROTO_IKE_EXCHG_CREATE_CHILD_SA ){

  			if( proph->spi_len != RHP_PROTO_IKE_SPI_SIZE ){
          err = RHP_STATUS_INVALID_MSG;
          RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_NEW_RX_INVALID_MESG_11,"xb",ikemesg,proph->spi_len,RHP_PROTO_IKE_SPI_SIZE);
          goto error;
        }
  			
  			ikemesg->for_rekey_req = 1;
  			ikemesg->for_ikesa_rekey = 1;

  		}else{
        err = RHP_STATUS_INVALID_MSG;
        RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_NEW_RX_INVALID_MESG_12,"xb",ikemesg,exchange_type);
        goto error;
  		}
      
  		sa_payload->is_for_ikesa = 1;
  	
  	}else if( proph->protocol == RHP_PROTO_IKE_PROTOID_ESP || proph->protocol == RHP_PROTO_IKE_PROTOID_AH ){

  		if( ( exchange_type == RHP_PROTO_IKE_EXCHG_IKE_AUTH || exchange_type == RHP_PROTO_IKE_EXCHG_CREATE_CHILD_SA ) ){

  			if( proph->spi_len != RHP_PROTO_IPSEC_SPI_SIZE ){
          err = RHP_STATUS_INVALID_MSG;
          RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_NEW_RX_INVALID_MESG_13,"xbbd",ikemesg,exchange_type,proph->spi_len,RHP_PROTO_IPSEC_SPI_SIZE);
          goto error;
        }

  		}else{
  			err = RHP_STATUS_INVALID_MSG;
  			RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_NEW_RX_INVALID_MESG_14,"xb",ikemesg,exchange_type);
  			goto error;
      }

  	}else{
      err = RHP_STATUS_INVALID_MSG;
      RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_NEW_RX_INVALID_MESG_15,"xb",ikemesg,proph->protocol);
      goto error;
    }

  	prop = _rhp_ikev2_alloc_sa_proposal();
  	if( prop == NULL ){
     err = -ENOMEM;
     RHP_BUG("");
     goto error;
  	}

  	prop->proph = proph;
  	sa_payload->put_prop(payload,prop);

  	if( prop_spi ){
     memcpy(prop->spi,prop_spi,proph->spi_len);
     prop->spi_len = proph->spi_len;
  	}else{
     prop->spi_len = 0;
  	}

   for( i = 0; i < proph->transform_num;i++ ){

  	 transh = (rhp_proto_ike_transform*)_rhp_pkt_pull(ikemesg->rx_pkt,sizeof(rhp_proto_ike_transform));
  	 if( transh == NULL ){
  		 err = RHP_STATUS_INVALID_MSG;
  		 RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_NEW_RX_INVALID_MESG_16,"xd",ikemesg,i);
  		 goto error;
  	 }

  	 if( transh->last_or_more != RHP_PROTO_IKE_TRANSFORM_LAST &&
    			transh->last_or_more != RHP_PROTO_IKE_TRANSFORM_MORE ){
        err = RHP_STATUS_INVALID_MSG;
        RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_NEW_RX_INVALID_MESG_17,"xdb",ikemesg,i,transh->last_or_more);
        goto error;
  	 }

  	 trans_len = ntohs(transh->len);

    if( trans_len == 0 || _rhp_pkt_try_pull(ikemesg->rx_pkt,trans_len) ){
    	err = RHP_STATUS_INVALID_MSG;
    	RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_NEW_RX_INVALID_MESG_18,"xdd",ikemesg,i,trans_len);
    	goto error;
    }

    switch( transh->transform_type ){
    case RHP_PROTO_IKE_TRANSFORM_TYPE_ENCR:
    case RHP_PROTO_IKE_TRANSFORM_TYPE_PRF:
    case RHP_PROTO_IKE_TRANSFORM_TYPE_INTEG:
    case RHP_PROTO_IKE_TRANSFORM_TYPE_DH:
    case RHP_PROTO_IKE_TRANSFORM_TYPE_ESN:
    	break;
    default:  
    	err = RHP_STATUS_UNKNOWN_PARAM;
    	RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_NEW_RX_INVALID_MESG_19,"xdb",ikemesg,i,transh->transform_type);
    	goto error;
    }
      
    trans = _rhp_ikev2_alloc_sa_transform(transh->transform_type,ntohs(transh->transform_id));
    if( trans == NULL ){
      err = -ENOMEM;
      RHP_BUG("");
      goto error;
    }

    trans->transh = transh;
    prop->put_trans(prop,trans);

    if( trans_len > (int)sizeof(rhp_proto_ike_transform) ){

    	// Ugly...
    	if( transh->transform_type == RHP_PROTO_IKE_TRANSFORM_TYPE_ENCR ){

    		attrh = (rhp_proto_ike_attr*)_rhp_pkt_pull(ikemesg->rx_pkt,sizeof(rhp_proto_ike_attr));
    		if( attrh == NULL ){
    			err = RHP_STATUS_INVALID_MSG;
    			RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_NEW_RX_INVALID_MESG_20,"xd",ikemesg,i);
    			goto error;
        }

    		if( RHP_PROTO_IKE_ATTR_TYPE(attrh->attr_type ) == RHP_PROTO_IKE_ATTR_KEYLEN &&
           RHP_PROTO_IKE_ATTR_AF(attrh->attr_type ) ){
    			trans->key_bits_len = ntohs(attrh->len_or_value);
    		}
    	}
     } 
   }

   last_prop_flag = (proph->last_or_more == RHP_PROTO_IKE_PROPOSAL_LAST);

  }while( !last_prop_flag );

  RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_NEW_RX_RTRN,"x",ikemesg);
  return 0;

error:
  if( payload->ext_destructor ){
    payload->ext_destructor(payload);
  }

  RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_NEW_RX_ERR,"xE",ikemesg,err);
  return err;
}


int rhp_ikev2_sa_payload_new_tx(rhp_ikev2_mesg* ikemesg,u8 payload_id,rhp_ikev2_payload* payload)
{
  int err = 0;
  rhp_ikev2_sa_payload* sa_payload;

  RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_NEW_TX,"xLbx",ikemesg,"PROTO_IKE_PAYLOAD",payload_id,payload);

  sa_payload = _rhp_ikev2_alloc_sa_payload();
  if( sa_payload == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  payload->ext.sa = sa_payload;
  payload->ext_destructor = _rhp_ikev2_sa_payload_destructor;
  payload->ext_serialize = _rhp_ikev2_sa_payload_serialize;
  payload->ext_dump = _rhp_ikev2_sa_payload_dump;

  RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_NEW_TX_RTRN,"x",ikemesg);
  return 0;

error:
  if( payload->ext_destructor ){
    payload->ext_destructor(payload);
  }

  RHP_TRC(0,RHPTRCID_IKEV2_SA_PAYLOAD_NEW_TX_ERR,"xE",ikemesg,err);
  return err;
}



