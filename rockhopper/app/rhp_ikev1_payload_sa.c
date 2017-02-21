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

static rhp_ikev1_transform* _rhp_ikev1_alloc_sa_transform(u8 trans_number,u8 trans_id)
{
  rhp_ikev1_transform* trans;

  trans = (rhp_ikev1_transform*)_rhp_malloc(sizeof(rhp_ikev1_transform));
  if( trans == NULL ){
    RHP_BUG("");
    return NULL;
  }

  memset(trans,0,sizeof(rhp_ikev1_transform));

  trans->trans_number = trans_number;
  trans->trans_id = trans_id;

  RHP_TRC(0,RHPTRCID_IKEV1_ALLOC_SA_TRANSFORM,"bLbx",trans_number,"PROTO_IKEV1_TF",trans_id,trans);
  return trans;
}

static void _rhp_ikev1_sa_payload_put_trans(rhp_ikev1_proposal* prop,rhp_ikev1_transform* trans)
{
  if( prop->trans_list_head == NULL ){
    prop->trans_list_head = trans;
  }else{
    prop->trans_list_tail->next = trans;
  }
  prop->trans_list_tail = trans;
  prop->trans_num++;

  RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_PUT_TRANS,"xxbLbd",prop,trans,trans->trans_number,"PROTO_IKEV1_TF",trans->trans_id,prop->trans_num);
  return;
}

static int _rhp_ikev1_sa_payload_enum_trans(rhp_ikev1_proposal* prop,
                    int (*callback)(rhp_ikev1_proposal* prop,rhp_ikev1_transform* trans,void* ctx),void* ctx)
{
  int err = 0;
  rhp_ikev1_transform* trans = prop->trans_list_head;

  RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_ENUM_TRANS,"xYx",prop,callback,ctx);

  if( trans == NULL ){
    RHP_BUG("");
    return -ENOENT;
  }

  while( trans ){
    if( (err = callback(prop,trans,ctx)) ){
      RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_ENUM_TRANS_ERR,"E",err);
      return err;
    }
    trans = trans->next;
  }
  return 0;
}

static int _rhp_ikev1_sa_payload_get_trans_num(rhp_ikev1_proposal* prop)
{
  RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_TRANS_NUM,"xd",prop,prop->trans_num);
  return prop->trans_num;
}

static u8 _rhp_ikev1_sa_payload_get_protocol_id(rhp_ikev1_proposal* prop)
{
  RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_GET_PROTOCOL_ID,"xLb",prop,"PROTO_IKEV1_PROP_PROTO_ID",prop->protocol_id);
  return prop->protocol_id;
}

static u8 _rhp_ikev1_sa_payload_get_proposal_number(rhp_ikev1_proposal* prop)
{
  RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_GET_PROPOSAL_NUM,"xb",prop,prop->proposal_number);
  return prop->proposal_number;
}

static int _rhp_ikev1_sa_payload_alloc_and_put_trans(rhp_ikev1_proposal* prop,
		u8 trans_number,u8 trans_id,rhp_ikev1_transform** trans_r)
{
  rhp_ikev1_transform* trans;

  RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_ALLOC_AND_PUT_TRANS,"xLbbx",prop,"PROTO_IKEV1_TF",trans_id,trans_number,trans_r);
  
  trans = _rhp_ikev1_alloc_sa_transform(trans_number,trans_id);
  if( trans == NULL ){
    RHP_BUG("");
    return -ENOMEM;
  }

  prop->put_trans(prop,trans);

  if( trans_r ){
  	*trans_r = trans;
  }

  RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_ALLOC_AND_PUT_TRANS_RTRN,"xx",prop,trans);
  return 0;
}

static int _rhp_ikev1_sa_payload_get_spi(rhp_ikev1_proposal* prop,u8* spi,int* spi_len)
{
  if( prop->spi_len ){
    memcpy(spi,prop->spi,prop->spi_len);
    if( spi_len ){
      *spi_len = prop->spi_len;
    }

    if( prop->spi_len == 4 ){
    	RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_GET_SPI_4,"xdH",prop,prop->spi_len,*((u32*)prop->spi));
    }else if( prop->spi_len == 8 ){
    	RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_GET_SPI_8,"xdG",prop,prop->spi_len,prop->spi);
    }else{
    	RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_GET_SPI,"xp",prop,prop->spi_len,prop->spi);
    }
    return 0;
  }
  RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_GET_SPI_NO_SPI,"x",prop);
  return -ENOENT;
}

static rhp_ikev1_proposal* _rhp_ikev1_alloc_sa_proposal()
{
  rhp_ikev1_proposal* prop;

  prop = (rhp_ikev1_proposal*)_rhp_malloc(sizeof(rhp_ikev1_proposal));
  if( prop == NULL ){
    RHP_BUG("");
    return NULL;
  }

  memset(prop,0,sizeof(rhp_ikev1_proposal));

  prop->put_trans = _rhp_ikev1_sa_payload_put_trans;
  prop->enum_trans = _rhp_ikev1_sa_payload_enum_trans;
  prop->get_trans_num = _rhp_ikev1_sa_payload_get_trans_num;
  prop->get_protocol_id = _rhp_ikev1_sa_payload_get_protocol_id;
  prop->alloc_and_put_trans = _rhp_ikev1_sa_payload_alloc_and_put_trans;
  prop->get_proposal_number = _rhp_ikev1_sa_payload_get_proposal_number;
  prop->get_spi = _rhp_ikev1_sa_payload_get_spi;

  RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_ALLOC_SA_PROPOSAL,"x",prop);
  return prop;
}

static void _rhp_ikev1_sa_payload_put_prop(rhp_ikev2_payload* payload,rhp_ikev1_proposal* prop)
{
  rhp_ikev1_sa_payload* sa_payload = payload->ext.v1_sa;
  int trans_num,spi_len = 0;
  u8 protocol_id,proposal_number;
  u8 spi[RHP_PROTO_SPI_MAX_SIZE];
  
  RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_PUT_PROP,"xxx",payload,prop,sa_payload);
  
  trans_num = prop->get_trans_num(prop);
  protocol_id = prop->get_protocol_id(prop);
  proposal_number = prop->get_proposal_number(prop);
  prop->get_spi(prop,spi,&spi_len);

  RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_PUT_PROP_DUMP,"xxdLbbp",payload,prop,trans_num,"PROTO_IKEV1_PROP_PROTO_ID",protocol_id,proposal_number,spi_len,spi);
  
  if( sa_payload->prop_list_head == NULL ){
    sa_payload->prop_list_head = prop;
  }else{
    sa_payload->prop_list_tail->next = prop;
  }
  sa_payload->prop_list_tail = prop;
  
  return;
}

static int _rhp_ikev1_sa_payload_enum_props(rhp_ikev2_payload* payload,
           int (*callback)(rhp_ikev2_payload* payload,rhp_ikev1_proposal* prop,void* ctx),void* ctx)
{
  int err = 0;
  rhp_ikev1_sa_payload* sa_payload = payload->ext.v1_sa;
  rhp_ikev1_proposal* prop = sa_payload->prop_list_head;

  RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_ENUM_PROPS,"xYx",payload,callback,ctx);

  if( prop == NULL ){
    RHP_BUG("");
    return -ENOENT;
  }

  while( prop ){

    if( (err = callback(payload,prop,ctx)) ){
      RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_ENUM_PROPS_ERR,"E",err);
      return err;
    }

    prop = prop->next;
  }

  RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_ENUM_PROPS_RTRN,"");
  return 0;
}

static  int _rhp_ikev1_sa_payload_enum_ikesa_prop_cb(rhp_ikev2_payload* payload,
    rhp_ikev1_proposal* prop,void* ctx)
{
  rhp_res_ikev1_sa_proposal* res_prop = (rhp_res_ikev1_sa_proposal*)ctx;
  rhp_res_ikev1_sa_proposal res_prop_tmp;

  RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_ENUM_IKESA_PROP_CB,"xxxdu",payload,prop,ctx,res_prop->auth_method,res_prop->life_time);

  memset(&res_prop_tmp,0,sizeof(rhp_res_ikev1_sa_proposal));
  res_prop_tmp.auth_method = res_prop->auth_method;
  res_prop_tmp.xauth_method = res_prop->xauth_method;
  res_prop_tmp.life_time = res_prop->life_time;

  if( !rhp_cfg_match_ikev1_ikesa_proposal(prop,&res_prop_tmp) ){

  	if( !res_prop->dh_group ||
  			res_prop->cfg_priority > res_prop_tmp.cfg_priority ){

  		memcpy(res_prop,&res_prop_tmp,sizeof(rhp_res_ikev1_sa_proposal));
  	}

  	return 0;
  }

  return 0;
}

static  int _rhp_ikev1_sa_payload_enum_ipsecsa_prop_cb(rhp_ikev2_payload* payload,
    rhp_ikev1_proposal* prop,void* ctx)
{
	int err = -EINVAL;
  rhp_res_ikev1_sa_proposal* res_prop = (rhp_res_ikev1_sa_proposal*)ctx;
  rhp_res_ikev1_sa_proposal res_prop_tmp;

  RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_ENUM_IPSECSA_PROP_CB,"xxx",payload,prop,ctx);

  memset(&res_prop_tmp,0,sizeof(rhp_res_ikev1_sa_proposal));
  res_prop_tmp.life_time = res_prop->life_time;

  err = rhp_cfg_match_ikev1_ipsecsa_proposal(prop,&res_prop_tmp);
  if( !err ){

  	if( !res_prop->trans_id ||
  			res_prop->cfg_priority > res_prop_tmp.cfg_priority ){

  		memcpy(res_prop,&res_prop_tmp,sizeof(rhp_res_ikev1_sa_proposal));
  	}

  	return 0;

  }else if( err == RHP_STATUS_INVALID_IKEV2_MESG_PFS_REQUIRED ){

  	RHP_LOG_DE(RHP_LOG_SRC_CFG,0,RHP_LOG_ID_CHILDSA_PFS_BUT_NO_DH_ALG_IN_PROP,"K",payload->ikemesg);
  	err = 0;
  }

  return 0;
}

static int _rhp_ikev1_sa_payload_get_matched_ikesa_prop(
		rhp_ikev2_payload* payload,rhp_res_ikev1_sa_proposal* res_prop)
{
  rhp_ikev1_sa_payload* sa_payload = payload->ext.v1_sa;
  int err;

  RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_GET_MATCHED_IKESA_PROP,"xx",payload,res_prop);

  if( sa_payload == NULL ){
    RHP_BUG("");
    goto error;
  }

  res_prop->number = 0;
  res_prop->spi_len = 0;
  res_prop->dh_group = 0;
  
  err = sa_payload->enum_props(payload,_rhp_ikev1_sa_payload_enum_ikesa_prop_cb,res_prop);
  if( err && err != RHP_STATUS_ENUM_OK ){
    RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_GET_MATCHED_IKESA_PROP_ERR,"xE",payload,err);
    goto error;
  }
  err = 0;

  rhp_cfg_dump_res_ikev1_sa_prop(res_prop);

  if( !res_prop->dh_group ){
    RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_GET_MATCHED_IKESA_PROP_NOT_FOUND,"x",payload);
  	goto error;
  }

  RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_GET_MATCHED_IKESA_PROP_RTRN,"xxbLbpddddudd",payload,res_prop,res_prop->number,"PROTO_IKEV1_PROP_PROTO_ID",res_prop->protocol_id,res_prop->spi_len,res_prop->spi,res_prop->enc_alg,res_prop->hash_alg,res_prop->auth_method,res_prop->dh_group,res_prop->life_time,res_prop->key_bits_len,res_prop->cfg_priority);
  return 0;

error:
	RHP_LOG_DE(RHP_LOG_SRC_CFG,0,RHP_LOG_ID_IKESA_NO_PROPOSAL_CHOSEN,"K",payload->ikemesg);
	RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_GET_MATCHED_IKESA_PROP_ERR,"xx",payload,res_prop);
  return -ENOENT;
}

static int _rhp_ikev1_sa_payload_get_matched_ipsecsa_prop(
		rhp_ikev2_payload* payload,rhp_res_ikev1_sa_proposal* res_prop)
{
  rhp_ikev1_sa_payload* sa_payload = payload->ext.v1_sa;
  int err;

  RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_GET_MATCHED_IPSECSA_PROP,"xx",payload,res_prop);

  if( sa_payload == NULL ){
    RHP_BUG("");
    goto error;
  }

  res_prop->number = 0;
  res_prop->spi_len = 0;
  res_prop->esn = 0;
  res_prop->dh_group = 0;
  res_prop->trans_id = 0;
  
  err = sa_payload->enum_props(payload,_rhp_ikev1_sa_payload_enum_ipsecsa_prop_cb,res_prop);
  if( err ){
    RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_GET_MATCHED_IPSECSA_PROP_ERR,"xE",payload,err);
    goto error;
  }
  rhp_cfg_dump_res_ikev1_sa_prop(res_prop);

  if( !res_prop->trans_id ){
    RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_GET_MATCHED_IPSECSA_PROP_NOT_FOUND,"x",payload);
  	goto error;
  }

  RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_GET_MATCHED_IPSECSA_PROP_RTRN,"xxbLbpduuddddd",payload,res_prop,res_prop->number,"PROTO_IKEV1_PROP_PROTO_ID",res_prop->protocol_id,res_prop->spi_len,res_prop->spi,res_prop->dh_group,res_prop->life_time,res_prop->life_bytes,res_prop->trans_id,res_prop->auth_alg,res_prop->esn,res_prop->key_bits_len,res_prop->cfg_priority);
  return 0;

error:
	RHP_LOG_DE(RHP_LOG_SRC_CFG,0,RHP_LOG_ID_CHILDSA_NO_PROPOSAL_CHOSEN,"K",payload->ikemesg);
	RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_GET_MATCHED_IPSECSA_PROP_ERR,"xx",payload,res_prop);
  return -ENOENT;
}

static void _rhp_ikev1_sa_payload_destructor(rhp_ikev2_payload* payload)
{
  rhp_ikev1_sa_payload* sa_payload = payload->ext.v1_sa;
  rhp_ikev1_proposal *prop,*prop2;
  rhp_ikev1_transform *trans,*trans2;

  RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_DESTRUCTOR,"xx",payload,sa_payload);

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
      _rhp_free_zero(trans,sizeof(rhp_ikev1_transform));
      trans = trans2;
    }

    _rhp_free_zero(prop,sizeof(rhp_ikev1_proposal));
    prop = prop2;
  }

  sa_payload->prop_list_head = NULL;

  RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_DESTRUCTOR_RTRN,"xx",payload,sa_payload);
  return;
}

static int _rhp_ikev1_sa_payload_serialize(rhp_ikev2_payload* payload,rhp_packet* pkt)
{
  int err = -EINVAL;
  rhp_ikev1_proposal* prop = payload->ext.v1_sa->prop_list_head;
  rhp_ikev1_transform* trans;

  RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_SERIALIZE,"xxx",payload,pkt,payload->ext.v1_sa->prop_list_head);

  if( prop ){

    int len = sizeof(rhp_proto_ikev1_sa_payload);
    rhp_proto_ikev1_sa_payload* pldh;
    rhp_proto_ikev1_proposal_payload* proph;
    rhp_proto_ikev1_transform_payload* transh;
    rhp_proto_ikev1_attr* attrh;
    int pld_offset = 0;

    pldh = (rhp_proto_ikev1_sa_payload*)rhp_pkt_expand_tail(pkt,len);
    if( pldh == NULL ){
      RHP_BUG("");
      return -ENOMEM;
    }
    pld_offset = ((u8*)pldh) - pkt->head;

    pldh->next_payload = payload->get_next_payload(payload);
    pldh->doi = htonl(RHP_PROTO_IKEV1_DOI_IPSEC);
    pldh->reserved = 0;
    pldh->situation = htonl(RHP_PROTO_IKEV1_SIT_IDENTITY_ONLY);

    while( prop ){

      int prop_len = sizeof(rhp_proto_ikev1_proposal_payload) + prop->spi_len;
      int spi_len;
      int trans_num = 0;
      int prop_offset = 0;

      trans = prop->trans_list_head;

      if( trans == NULL ){
        err = -ENOENT;
        RHP_BUG("");
        goto error;
      }

      proph = (rhp_proto_ikev1_proposal_payload*)rhp_pkt_expand_tail(pkt,prop_len);
      if( proph == NULL ){
        err = -ENOMEM;
        RHP_BUG("");
        goto error;
      }
      prop_offset = ((u8*)proph) - pkt->head;

      if( prop->next ){
        proph->next_payload = RHP_PROTO_IKEV1_PAYLOAD_P;
      }else{
        proph->next_payload = RHP_PROTO_IKE_NO_MORE_PAYLOADS;
      }
      proph->reserved = 0;
      proph->proposal_number = prop->get_proposal_number(prop);
      proph->protocol_id = prop->get_protocol_id(prop);


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

        int trans_len = sizeof(rhp_proto_ikev1_transform_payload);
        int trans_offset = 0;

        transh = (rhp_proto_ikev1_transform_payload*)rhp_pkt_expand_tail(pkt,trans_len);

        if( transh == NULL ){
          err = -ENOMEM;
          RHP_BUG("");
          goto error;
        }
        trans_offset = ((u8*)transh) - pkt->head;

        if( trans->next ){
          transh->next_payload = RHP_PROTO_IKEV1_PAYLOAD_T;
        }else{
          transh->next_payload = RHP_PROTO_IKE_NO_MORE_PAYLOADS;
        }
        transh->reserved = 0;
        transh->reserved2 = 0;

        transh->transform_number = trans->trans_number;
        transh->transform_id = trans->trans_id;


        if( proph->protocol_id == RHP_PROTO_IKEV1_PROP_PROTO_ID_ISAKMP ){

        	if( trans->enc_alg ){

            attrh = (rhp_proto_ikev1_attr*)rhp_pkt_expand_tail(pkt,sizeof(rhp_proto_ikev1_attr));
            if( attrh == NULL ){
              err = -ENOMEM;
              RHP_BUG("");
              goto error;
            }

            attrh->attr_type = RHP_PROTO_IKE_ATTR_SET_AF(htons(RHP_PROTO_IKEV1_P1_ATTR_TYPE_ENCRYPTION));
            attrh->len_or_value = htons((u16)trans->enc_alg);

            trans_len += sizeof(rhp_proto_ikev1_attr);
        	}

        	if( trans->hash_alg ){

            attrh = (rhp_proto_ikev1_attr*)rhp_pkt_expand_tail(pkt,sizeof(rhp_proto_ikev1_attr));
            if( attrh == NULL ){
              err = -ENOMEM;
              RHP_BUG("");
              goto error;
            }

            attrh->attr_type = RHP_PROTO_IKE_ATTR_SET_AF(htons(RHP_PROTO_IKEV1_P1_ATTR_TYPE_HASH));
            attrh->len_or_value = htons((u16)trans->hash_alg);

            trans_len += sizeof(rhp_proto_ikev1_attr);
        	}

        	if( trans->auth_method ){

            attrh = (rhp_proto_ikev1_attr*)rhp_pkt_expand_tail(pkt,sizeof(rhp_proto_ikev1_attr));
            if( attrh == NULL ){
              err = -ENOMEM;
              RHP_BUG("");
              goto error;
            }

            attrh->attr_type = RHP_PROTO_IKE_ATTR_SET_AF(htons(RHP_PROTO_IKEV1_P1_ATTR_TYPE_AUTH_METHOD));
            attrh->len_or_value = htons((u16)trans->auth_method);

            trans_len += sizeof(rhp_proto_ikev1_attr);
        	}

        	if( trans->dh_group ){

            attrh = (rhp_proto_ikev1_attr*)rhp_pkt_expand_tail(pkt,sizeof(rhp_proto_ikev1_attr));
            if( attrh == NULL ){
              err = -ENOMEM;
              RHP_BUG("");
              goto error;
            }

            attrh->attr_type = RHP_PROTO_IKE_ATTR_SET_AF(htons(RHP_PROTO_IKEV1_P1_ATTR_TYPE_GROUP_DESC));
            attrh->len_or_value = htons((u16)trans->dh_group);

            trans_len += sizeof(rhp_proto_ikev1_attr);
        	}

        	if( trans->life_time ){

            attrh = (rhp_proto_ikev1_attr*)rhp_pkt_expand_tail(pkt,sizeof(rhp_proto_ikev1_attr));
            if( attrh == NULL ){
              err = -ENOMEM;
              RHP_BUG("");
              goto error;
            }

            attrh->attr_type = RHP_PROTO_IKE_ATTR_SET_AF(htons(RHP_PROTO_IKEV1_P1_ATTR_TYPE_LIFE_TYPE));
            attrh->len_or_value = htons(RHP_PROTO_IKEV1_ATTR_LIFE_TYPE_SECONDS);

            trans_len += sizeof(rhp_proto_ikev1_attr);


            attrh = (rhp_proto_ikev1_attr*)rhp_pkt_expand_tail(pkt,sizeof(rhp_proto_ikev1_attr) + 4);
            if( attrh == NULL ){
              err = -ENOMEM;
              RHP_BUG("");
              goto error;
            }

            attrh->attr_type = htons(RHP_PROTO_IKEV1_P1_ATTR_TYPE_LIFE_DURATION);
            attrh->len_or_value = htons(4);
            *((u32*)(attrh + 1)) = htonl((u32)trans->life_time);

            trans_len += sizeof(rhp_proto_ikev1_attr) + 4;
        	}

        	if( trans->life_bytes ){

            attrh = (rhp_proto_ikev1_attr*)rhp_pkt_expand_tail(pkt,sizeof(rhp_proto_ikev1_attr));
            if( attrh == NULL ){
              err = -ENOMEM;
              RHP_BUG("");
              goto error;
            }

            attrh->attr_type = RHP_PROTO_IKE_ATTR_SET_AF(htons(RHP_PROTO_IKEV1_P1_ATTR_TYPE_LIFE_TYPE));
            attrh->len_or_value = htons(RHP_PROTO_IKEV1_ATTR_LIFE_TYPE_KILOBYTES);

            trans_len += sizeof(rhp_proto_ikev1_attr);


            attrh = (rhp_proto_ikev1_attr*)rhp_pkt_expand_tail(pkt,sizeof(rhp_proto_ikev1_attr) + 4);
            if( attrh == NULL ){
              err = -ENOMEM;
              RHP_BUG("");
              goto error;
            }

            attrh->attr_type = htons(RHP_PROTO_IKEV1_P1_ATTR_TYPE_LIFE_DURATION);
            attrh->len_or_value = htons(4);
            *((u32*)(attrh + 1)) = htonl((u32)trans->life_bytes);

            trans_len += sizeof(rhp_proto_ikev1_attr) + 4;
        	}

          if( trans->key_bits_len ){

            attrh = (rhp_proto_ikev1_attr*)rhp_pkt_expand_tail(pkt,sizeof(rhp_proto_ikev1_attr));
            if( attrh == NULL ){
              err = -ENOMEM;
              RHP_BUG("");
              goto error;
            }

            attrh->attr_type = RHP_PROTO_IKE_ATTR_SET_AF(htons(RHP_PROTO_IKEV1_P1_ATTR_TYPE_KEY_LEN));
            attrh->len_or_value = htons((u16)trans->key_bits_len);

            trans_len += sizeof(rhp_proto_ikev1_attr);
          }


        }else if( proph->protocol_id == RHP_PROTO_IKEV1_PROP_PROTO_ID_ESP ){

        	if( trans->life_time ){

            attrh = (rhp_proto_ikev1_attr*)rhp_pkt_expand_tail(pkt,sizeof(rhp_proto_ikev1_attr));
            if( attrh == NULL ){
              err = -ENOMEM;
              RHP_BUG("");
              goto error;
            }

            attrh->attr_type = RHP_PROTO_IKE_ATTR_SET_AF(htons(RHP_PROTO_IKEV1_P2_ATTR_TYPE_LIFE_TYPE));
            attrh->len_or_value = htons(RHP_PROTO_IKEV1_ATTR_LIFE_TYPE_SECONDS);

            trans_len += sizeof(rhp_proto_ikev1_attr);


            attrh = (rhp_proto_ikev1_attr*)rhp_pkt_expand_tail(pkt,sizeof(rhp_proto_ikev1_attr) + 4);
            if( attrh == NULL ){
              err = -ENOMEM;
              RHP_BUG("");
              goto error;
            }

            attrh->attr_type = htons(RHP_PROTO_IKEV1_P2_ATTR_TYPE_LIFE_DURATION);
            attrh->len_or_value = htons(4);
            *((u32*)(attrh + 1)) = htonl((u32)trans->life_time);

            trans_len += sizeof(rhp_proto_ikev1_attr) + 4;
        	}

        	if( trans->life_bytes ){

            attrh = (rhp_proto_ikev1_attr*)rhp_pkt_expand_tail(pkt,sizeof(rhp_proto_ikev1_attr));
            if( attrh == NULL ){
              err = -ENOMEM;
              RHP_BUG("");
              goto error;
            }

            attrh->attr_type = RHP_PROTO_IKE_ATTR_SET_AF(htons(RHP_PROTO_IKEV1_P2_ATTR_TYPE_LIFE_TYPE));
            attrh->len_or_value = htons(RHP_PROTO_IKEV1_ATTR_LIFE_TYPE_KILOBYTES);

            trans_len += sizeof(rhp_proto_ikev1_attr);


            attrh = (rhp_proto_ikev1_attr*)rhp_pkt_expand_tail(pkt,sizeof(rhp_proto_ikev1_attr) + 4);
            if( attrh == NULL ){
              err = -ENOMEM;
              RHP_BUG("");
              goto error;
            }

            attrh->attr_type = htons(RHP_PROTO_IKEV1_P2_ATTR_TYPE_LIFE_DURATION);
            attrh->len_or_value = htons(4);
            *((u32*)(attrh + 1)) = htonl((u32)trans->life_bytes);

            trans_len += sizeof(rhp_proto_ikev1_attr) + 4;
        	}

        	if( trans->dh_group ){

            attrh = (rhp_proto_ikev1_attr*)rhp_pkt_expand_tail(pkt,sizeof(rhp_proto_ikev1_attr));
            if( attrh == NULL ){
              err = -ENOMEM;
              RHP_BUG("");
              goto error;
            }

            attrh->attr_type = RHP_PROTO_IKE_ATTR_SET_AF(htons(RHP_PROTO_IKEV1_P2_ATTR_TYPE_GROUP_DESC));
            attrh->len_or_value = htons((u16)trans->dh_group);

            trans_len += sizeof(rhp_proto_ikev1_attr);
        	}

        	if( trans->encap_mode ){

            attrh = (rhp_proto_ikev1_attr*)rhp_pkt_expand_tail(pkt,sizeof(rhp_proto_ikev1_attr));
            if( attrh == NULL ){
              err = -ENOMEM;
              RHP_BUG("");
              goto error;
            }

            attrh->attr_type = RHP_PROTO_IKE_ATTR_SET_AF(htons(RHP_PROTO_IKEV1_P2_ATTR_TYPE_ENCAP_MODE));
            attrh->len_or_value = htons((u16)trans->encap_mode);

            trans_len += sizeof(rhp_proto_ikev1_attr);
        	}

        	if( trans->auth_alg ){

            attrh = (rhp_proto_ikev1_attr*)rhp_pkt_expand_tail(pkt,sizeof(rhp_proto_ikev1_attr));
            if( attrh == NULL ){
              err = -ENOMEM;
              RHP_BUG("");
              goto error;
            }

            attrh->attr_type = RHP_PROTO_IKE_ATTR_SET_AF(htons(RHP_PROTO_IKEV1_P2_ATTR_TYPE_AUTH));
            attrh->len_or_value = htons((u16)trans->auth_alg);

            trans_len += sizeof(rhp_proto_ikev1_attr);
        	}

          if( trans->key_bits_len ){

            attrh = (rhp_proto_ikev1_attr*)rhp_pkt_expand_tail(pkt,sizeof(rhp_proto_ikev1_attr));
            if( attrh == NULL ){
              err = -ENOMEM;
              RHP_BUG("");
              goto error;
            }

            attrh->attr_type = RHP_PROTO_IKE_ATTR_SET_AF(htons(RHP_PROTO_IKEV1_P2_ATTR_TYPE_KEY_LEN));
            attrh->len_or_value = htons((u16)trans->key_bits_len);

            trans_len += sizeof(rhp_proto_ikev1_attr);
          }

          if( trans->esn ){

            attrh = (rhp_proto_ikev1_attr*)rhp_pkt_expand_tail(pkt,sizeof(rhp_proto_ikev1_attr));
            if( attrh == NULL ){
              err = -ENOMEM;
              RHP_BUG("");
              goto error;
            }

            attrh->attr_type = RHP_PROTO_IKE_ATTR_SET_AF(htons(RHP_PROTO_IKEV1_P2_ATTR_TYPE_ESN));
            attrh->len_or_value = htons((u16)trans->esn);

            trans_len += sizeof(rhp_proto_ikev1_attr);
          }

        }else{
        	RHP_BUG("%d",proph->protocol_id);
        	goto error;
        }


        transh = (rhp_proto_ikev1_transform_payload*)(pkt->head + trans_offset);

        transh->len = htons(trans_len);

        prop_len += trans_len;
        trans_num++;

        trans = trans->next;
      }


      proph = (rhp_proto_ikev1_proposal_payload*)(pkt->head + prop_offset);

      proph->transform_num = trans_num;
      proph->len = htons(prop_len);
      len += prop_len;

      prop = prop->next;
    }


    pldh = (rhp_proto_ikev1_sa_payload*)(pkt->head + pld_offset);
    pldh->len = htons(len);
    payload->ikemesg->tx_mesg_len += len;
    payload->ext.v1_sa->sa_b = pldh;

    pldh->next_payload = RHP_PROTO_IKE_NO_MORE_PAYLOADS;
    if( payload->next ){
    	pldh->next_payload = payload->next->get_payload_id(payload->next);
    }

    RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_SERIALIZE_RTRN,"");
    rhp_pkt_trace_dump("_rhp_ikev1_sa_payload_serialize",pkt);
    return 0;
  }

error:
  RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_SERIALIZE_ERR,"E",err);
  return err;
}

static int _rhp_ikev1_sa_payload_set_def_ikesa_prop(rhp_ikev2_payload* payload,u8* spi,int spi_len,
		u16 dhgrp_id,int auth_method,unsigned long lifetime)
{
  int err = 0;
  rhp_cfg_ikev1_ikesa* cfg_ikesa;
  rhp_cfg_ikev1_transform* cfg_trans = NULL;
  rhp_ikev1_proposal* prop = NULL;
  rhp_ikev1_sa_payload* sa_payload = payload->ext.v1_sa;
  int trans_number = 1;

  RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_SET_DEF_IKESA_PROP,"xpxwdu",payload,spi_len,spi,sa_payload,dhgrp_id,auth_method,lifetime);

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

  cfg_ikesa = rhp_cfg_ikev1_get_ikesa_security();
  if( cfg_ikesa == NULL ){
    err = -ENOENT;
    RHP_BUG("");
    goto error;
  }

  if( cfg_ikesa->trans_list == NULL ){
    err = -ENOENT;
    RHP_BUG("");
    goto error;
  }

  prop = _rhp_ikev1_alloc_sa_proposal();
  if( prop == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  prop->protocol_id = RHP_PROTO_IKEV1_PROP_PROTO_ID_ISAKMP;
  prop->proposal_number = 1;

  if( spi_len ){
    memcpy(prop->spi,spi,spi_len);
  }
  prop->spi_len = spi_len;


  cfg_trans = cfg_ikesa->trans_list;
  while( cfg_trans ){

  	rhp_ikev1_transform* trans = NULL;

  	if( dhgrp_id &&
  			dhgrp_id != cfg_trans->dh_group ){
  		goto next;
  	}

    err = prop->alloc_and_put_trans(prop,trans_number,RHP_PROTO_IKEV1_TF_ISAKMP_KEY_IKE,&trans);
    if( err ){
      RHP_BUG("");
      goto error;
    }

    trans->enc_alg = cfg_trans->enc_alg;
    trans->hash_alg = cfg_trans->hash_alg;
    trans->dh_group = cfg_trans->dh_group;
    trans->key_bits_len = cfg_trans->key_bits_len;

    if( auth_method == RHP_PROTO_IKE_AUTHMETHOD_SHARED_KEY ){
      trans->auth_method = RHP_PROTO_IKEV1_P1_ATTR_AUTH_METHOD_PSK;
    }else if( auth_method == RHP_PROTO_IKE_AUTHMETHOD_RSA_SIG ){
      trans->auth_method = RHP_PROTO_IKEV1_P1_ATTR_AUTH_METHOD_RSASIG;
    }else if( auth_method ){
    	RHP_BUG("%d",auth_method);
    }

    trans->life_time = lifetime;

    trans_number++;

next:
		cfg_trans = cfg_trans->next;
  }
  
  sa_payload->put_prop(payload,prop);

  RHP_UNLOCK(&rhp_cfg_lock);

  RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_SET_DEF_IKESA_PROP_RTRN,"x",prop);
  return 0;

error:
  if( prop ){
  	rhp_ikev1_transform* trans = prop->trans_list_head;
  	while( trans ){
  		rhp_ikev1_transform* trans_n = trans->next;
  		_rhp_free(trans_n);
  		trans = trans_n;
  	}
    _rhp_free(prop);
  }
  RHP_UNLOCK(&rhp_cfg_lock);

  RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_SET_DEF_IKESA_PROP_ERR,"E",err);
  return err;
}

static int _rhp_ikev1_sa_payload_copy_ikesa_prop(rhp_ikev2_payload* payload,u8* spi,int spi_len,rhp_ikesa* old_ikesa)
{
  int err = 0;
  rhp_ikev1_proposal *prop = NULL;
  rhp_ikev1_sa_payload* sa_payload = payload->ext.v1_sa;
	rhp_ikev1_transform* trans = NULL;

  RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_COPY_IKESA_PROP,"xpxx",payload,spi_len,spi,sa_payload,old_ikesa);

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


  prop = _rhp_ikev1_alloc_sa_proposal();
  if( prop == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  prop->protocol_id = RHP_PROTO_IKEV1_PROP_PROTO_ID_ISAKMP;
  prop->proposal_number = 1;

  if( spi_len ){
    memcpy(prop->spi,spi,spi_len);
  }
  prop->spi_len = spi_len;


  err = prop->alloc_and_put_trans(prop,1,RHP_PROTO_IKEV1_TF_ISAKMP_KEY_IKE,&trans);
  if( err ){
    RHP_BUG("");
    goto error;
  }

  trans->auth_method = old_ikesa->auth_method;
  trans->enc_alg = old_ikesa->v1.enc_alg;
  trans->key_bits_len = old_ikesa->encr->alg_key_bits;
  trans->hash_alg = old_ikesa->v1.hash_alg;
  trans->dh_group = old_ikesa->dh->grp;

  sa_payload->put_prop(payload,prop);

  RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_COPY_IKESA_PROP_RTRN,"x",prop);
  return 0;

error:
	if( prop ){
		trans = prop->trans_list_head;
		while( trans ){
			rhp_ikev1_transform* trans_n = trans->next;
			_rhp_free(trans_n);
			trans = trans_n;
		}
		_rhp_free(prop);
	}

  RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_COPY_IKESA_PROP_ERR,"E",err);
  return err;
}

static int _rhp_ikev1_sa_payload_set_def_ipsecsa_prop(rhp_ikev2_payload* payload,u32 spi,
		u16 pfs_dhgrp_id,int encap_mode,unsigned long lifetime)
{
  int err = 0;
  rhp_cfg_ikev1_ipsecsa* cfg_ipsecsa;
  rhp_cfg_ikev1_transform* cfg_trans = NULL;
  rhp_ikev1_proposal* prop = NULL;
  rhp_ikev1_sa_payload* sa_payload = payload->ext.v1_sa;
  int trans_number = 1;

  RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_SET_DEF_IPSECSA_PROP,"xpxwdu",payload,RHP_PROTO_IPSEC_SPI_SIZE,&spi,sa_payload,pfs_dhgrp_id,encap_mode,lifetime);

  if( sa_payload == NULL ){
    err = -EINVAL;
    RHP_BUG("");
    goto error;
  }

  RHP_LOCK(&rhp_cfg_lock);


  cfg_ipsecsa = rhp_cfg_ikev1_get_ipsecsa_security();
  if( cfg_ipsecsa == NULL ){
    err = -ENOENT;
    RHP_BUG("");
    goto error;
  }

  if( cfg_ipsecsa->protocol_id != RHP_PROTO_IKEV1_PROP_PROTO_ID_ESP ){
    err = -ENOENT;
    RHP_BUG("%d",cfg_ipsecsa->protocol_id);
    goto error;
  }

  if( cfg_ipsecsa->trans_list == NULL ){
    err = -ENOENT;
    RHP_BUG("");
    goto error;
  }


  prop = _rhp_ikev1_alloc_sa_proposal();
  if( prop == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  prop->protocol_id = cfg_ipsecsa->protocol_id;
  prop->proposal_number = 1;
  memcpy(prop->spi,(u8*)&spi,RHP_PROTO_IPSEC_SPI_SIZE);
  prop->spi_len = RHP_PROTO_IPSEC_SPI_SIZE;

  cfg_trans = cfg_ipsecsa->trans_list;
  while( cfg_trans ){

  	rhp_ikev1_transform* trans = NULL;

    err = prop->alloc_and_put_trans(prop,trans_number,cfg_trans->trans_id,&trans);
    if( err ){
      RHP_BUG("");
      goto error;
    }

    trans->auth_alg = cfg_trans->auth_alg;
    trans->esn = cfg_trans->esn;
    trans->key_bits_len = cfg_trans->key_bits_len;

    if( pfs_dhgrp_id ){
      trans->dh_group = pfs_dhgrp_id;
    }else if( cfg_trans->dh_group ){
      trans->dh_group = cfg_trans->dh_group;
    }

    trans->life_time = lifetime;
    trans->encap_mode = encap_mode;

    trans_number++;

    cfg_trans = cfg_trans->next;
  }

  sa_payload->put_prop(payload,prop);

  RHP_UNLOCK(&rhp_cfg_lock);

  RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_SET_DEF_IPSECSA_PROP_RTRN,"x",prop);
  return 0;

error:
	if( prop ){
		rhp_ikev1_transform* trans = prop->trans_list_head;
		while( trans ){
			rhp_ikev1_transform* trans_n = trans->next;
			_rhp_free(trans_n);
			trans = trans_n;
		}
		_rhp_free(prop);
	}
  RHP_UNLOCK(&rhp_cfg_lock);

  RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_SET_DEF_IPSECSA_PROP_ERR,"E",err);
  return err;
}

static int _rhp_ikev1_sa_payload_copy_ipsecsa_prop(rhp_ikev2_payload* payload,u32 spi,
		rhp_childsa* old_ipsecsa,u16 pfs_dhgrp_id)
{
  int err = 0;
  rhp_ikev1_proposal* prop = NULL;
  rhp_ikev1_sa_payload* sa_payload = payload->ext.v1_sa;
	rhp_ikev1_transform* trans = NULL;

  RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_COPY_IPSECSA_PROP,"xpxxw",payload,RHP_PROTO_IPSEC_SPI_SIZE,&spi,sa_payload,old_ipsecsa,pfs_dhgrp_id);

  if( sa_payload == NULL ){
    err = -EINVAL;
    RHP_BUG("");
    goto error;
  }


  prop = _rhp_ikev1_alloc_sa_proposal();
  if( prop == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  prop->protocol_id = RHP_PROTO_IKEV1_PROP_PROTO_ID_ESP;
  prop->proposal_number = 1;
  memcpy(prop->spi,(u8*)&spi,RHP_PROTO_IPSEC_SPI_SIZE);
  prop->spi_len = RHP_PROTO_IPSEC_SPI_SIZE;


  err = prop->alloc_and_put_trans(prop,1,old_ipsecsa->v1.trans_id,&trans);
  if( err ){
    RHP_BUG("");
    goto error;
  }

  trans->auth_alg = old_ipsecsa->v1.auth_id;
  trans->esn = old_ipsecsa->esn ? 1 : 0;
  trans->key_bits_len = old_ipsecsa->encr->alg_key_bits;

  if( pfs_dhgrp_id ){
    trans->dh_group = pfs_dhgrp_id;
  }else if( old_ipsecsa->v1.dh ){
    trans->dh_group = old_ipsecsa->v1.dh->grp;
  }

  sa_payload->put_prop(payload,prop);

  RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_COPY_IPSECSA_PROP_RTRN,"x",prop);
  return 0;

error:
  if( prop ){
    _rhp_free(prop);
  }

  RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_COPY_IPSECSA_PROP_ERR,"E",err);
  return err;
}

static int _rhp_ikev1_sa_payload_set_matched_ikesa_prop(rhp_ikev2_payload* payload,
    rhp_res_ikev1_sa_proposal* res_prop,u8* spi,int spi_len)
{
  int err = 0;
  rhp_ikev1_sa_payload* sa_payload = payload->ext.v1_sa;
  rhp_ikev1_proposal* prop = NULL;
	rhp_ikev1_transform* trans = NULL;

  RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_SET_MACHED_IKESA_PROP,"xxp",payload,res_prop,spi_len,spi);

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

  if( res_prop->protocol_id != RHP_PROTO_IKEV1_PROP_PROTO_ID_ISAKMP ){
    err = -ENOENT;
    RHP_BUG("");
    goto error;
  }


  if( res_prop->enc_alg == 0 || res_prop->hash_alg == 0 || res_prop->dh_group == 0 ||
	   (res_prop->auth_method == 0 && res_prop->xauth_method == 0) || res_prop->life_time == 0 ){
    err = -ENOENT;
    RHP_BUG("%d,%d,%d,%d,%d",res_prop->enc_alg,res_prop->hash_alg,res_prop->dh_group,res_prop->auth_method,res_prop->life_time);
    goto error;
  }

  prop = _rhp_ikev1_alloc_sa_proposal();
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

  err = prop->alloc_and_put_trans(prop,res_prop->trans_number,RHP_PROTO_IKEV1_TF_ISAKMP_KEY_IKE,&trans);
  if( err ){
    RHP_BUG("");
    goto error;
  }

  trans->enc_alg = res_prop->enc_alg;
  trans->key_bits_len = res_prop->key_bits_len;

  trans->hash_alg = res_prop->hash_alg;

  if( res_prop->xauth_method ){
    trans->auth_method = res_prop->xauth_method;
  }else if( res_prop->auth_method == RHP_PROTO_IKE_AUTHMETHOD_SHARED_KEY ){
    trans->auth_method = RHP_PROTO_IKEV1_P1_ATTR_AUTH_METHOD_PSK;
  }else if( res_prop->auth_method == RHP_PROTO_IKE_AUTHMETHOD_RSA_SIG ){
    trans->auth_method = RHP_PROTO_IKEV1_P1_ATTR_AUTH_METHOD_RSASIG;
  }else if( res_prop->auth_method ){
  	RHP_BUG("%d",res_prop->auth_method);
  }

  trans->dh_group = res_prop->dh_group;

  trans->life_time = res_prop->life_time;


  sa_payload->put_prop(payload,prop);
  
  RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_SET_MACHED_IKESA_PROP_RTRN,"");
  return 0;

error:
  if( prop){
    _rhp_free(prop);
  }

  RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_SET_MACHED_IKESA_PROP_ERR,"E",err);
  return err;
}

static int _rhp_ikev1_sa_payload_set_matched_ipsecsa_prop(rhp_ikev2_payload* payload,
    rhp_res_ikev1_sa_proposal* res_prop,u32 spi)
{
  int err = 0;
  rhp_ikev1_sa_payload* sa_payload = payload->ext.v1_sa;
  rhp_ikev1_proposal* prop = NULL;
	rhp_ikev1_transform* trans = NULL;

  RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_SET_MACHED_IPSECSA_PROP,"xxux",payload,res_prop,spi,spi);

  if( sa_payload == NULL ){
    err = -EINVAL;
    RHP_BUG("");
    goto error;
  }
  
  if( res_prop->protocol_id != RHP_PROTO_IKEV1_PROP_PROTO_ID_ESP ){
    err = -ENOENT;
    RHP_BUG("");
    goto error;
  }

  if( res_prop->trans_id == 0 ){
    err = -ENOENT;
    RHP_BUG("");
    goto error;
  }


  prop = _rhp_ikev1_alloc_sa_proposal();
  if( prop == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  prop->protocol_id = res_prop->protocol_id;
  prop->proposal_number = res_prop->number;
  memcpy(prop->spi,(u8*)&spi,RHP_PROTO_IPSEC_SPI_SIZE);
  prop->spi_len = RHP_PROTO_IPSEC_SPI_SIZE;


  err = prop->alloc_and_put_trans(prop,res_prop->trans_number,res_prop->trans_id,&trans);
  if( err ){
    RHP_BUG("");
    goto error;
  }

  trans->dh_group = res_prop->dh_group;
  trans->life_time = res_prop->life_time;
  trans->life_bytes = res_prop->life_bytes;
  trans->encap_mode = res_prop->encap_mode;
  trans->auth_alg = res_prop->auth_alg;
  trans->esn = res_prop->esn ? 1 : 0;
  trans->key_bits_len = res_prop->key_bits_len;

  
  sa_payload->put_prop(payload,prop);
  
  RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_SET_MACHED_IPSECSA_PROP_RTRN,"");
  return 0;

error:
  if( prop){
    _rhp_free(prop);
  }

  RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_SET_MACHED_IPSECSA_PROP_ERR,"d",err);
  return err;
}

static int _rhp_ikev1_rx_payload_is_for_ikesa(rhp_ikev2_payload* payload)
{
  return payload->ext.v1_sa->is_for_ikesa;
}

static rhp_ikev1_sa_payload* _rhp_ikev1_alloc_sa_payload()
{
  rhp_ikev1_sa_payload* sa_payload;

  sa_payload = (rhp_ikev1_sa_payload*)_rhp_malloc(sizeof(rhp_ikev1_sa_payload));
  if( sa_payload == NULL ){
    RHP_BUG("");
    return NULL;
  }

  memset(sa_payload,0,sizeof(rhp_ikev1_sa_payload));

  sa_payload->put_prop = _rhp_ikev1_sa_payload_put_prop;
  sa_payload->enum_props = _rhp_ikev1_sa_payload_enum_props;
  sa_payload->get_matched_ikesa_prop = _rhp_ikev1_sa_payload_get_matched_ikesa_prop;
  sa_payload->get_matched_ipsecsa_prop = _rhp_ikev1_sa_payload_get_matched_ipsecsa_prop;
  sa_payload->set_def_ikesa_prop = _rhp_ikev1_sa_payload_set_def_ikesa_prop;
  sa_payload->copy_ikesa_prop = _rhp_ikev1_sa_payload_copy_ikesa_prop;
  sa_payload->set_def_ipsecsa_prop = _rhp_ikev1_sa_payload_set_def_ipsecsa_prop;
  sa_payload->copy_ipsecsa_prop = _rhp_ikev1_sa_payload_copy_ipsecsa_prop;
  sa_payload->set_matched_ikesa_prop = _rhp_ikev1_sa_payload_set_matched_ikesa_prop;
  sa_payload->set_matched_ipsecsa_prop = _rhp_ikev1_sa_payload_set_matched_ipsecsa_prop;
  sa_payload->rx_payload_is_for_ikesa = _rhp_ikev1_rx_payload_is_for_ikesa;
  
  RHP_TRC(0,RHPTRCID_IKEV1_ALLOC_SA_PAYLOAD,"x",sa_payload);
  return sa_payload;
}


static int _rhp_ikev1_sa_payload_prop_dump_cb(rhp_ikev1_proposal* prop,rhp_ikev1_transform* trans,void* ctx)
{
  int len = 0;

  if( trans->transh ){
    len = ntohs(trans->transh->len);
  }

  RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_TRANS_DUMP,"xxxbbdddduuddddp",prop,trans->next,trans->transh,trans->trans_number,trans->trans_id,trans->enc_alg,trans->hash_alg,trans->auth_method,trans->dh_group,trans->life_time,trans->life_bytes,trans->encap_mode,trans->auth_alg,trans->esn,trans->key_bits_len,len,trans->transh);

  return 0;
}

static int _rhp_ikev1_sa_payload_dump_cb(rhp_ikev2_payload* payload,rhp_ikev1_proposal* prop,void* ctx)
{
  int len = 0;

  if( prop->proph ){
    len = ntohs(prop->proph->len);
  }

  RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_PROP_DUMP,"xxxdxxbbdpp",payload,prop->next,prop->proph,prop->trans_num,prop->trans_list_head,prop->trans_list_tail,prop->protocol_id,prop->proposal_number,prop->spi_len,RHP_PROTO_SPI_MAX_SIZE,prop->spi,len,prop->proph);

  prop->enum_trans(prop,_rhp_ikev1_sa_payload_prop_dump_cb,NULL);

  return 0;
}

static void _rhp_ikev1_sa_payload_dump(rhp_ikev2_payload* payload)
{
  rhp_ikev1_sa_payload* sa_payload = payload->ext.v1_sa;
  int len = 0;

  if( sa_payload == NULL ){
    RHP_BUG("");
    return;
  }

  if( payload->payloadh ){
    len = ntohs(payload->payloadh->len);
  }

  RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_DUMP,"xxxxxbxxp",payload,sa_payload,payload->next,payload->ikemesg,payload->payloadh,payload->payload_id,sa_payload->prop_list_head,sa_payload->prop_list_tail,len,payload->payloadh);

  sa_payload->enum_props(payload,_rhp_ikev1_sa_payload_dump_cb,NULL);

  return;
}


int rhp_ikev1_sa_payload_new_rx(rhp_ikev2_mesg* ikemesg,u8 payload_id,
                                rhp_proto_ike_payload* payloadh,int payload_len,rhp_ikev2_payload* payload)
{
  int i;
  int err = 0;
  rhp_ikev1_sa_payload* sa_payload;
  rhp_proto_ikev1_sa_payload* sa_payloadh = (rhp_proto_ikev1_sa_payload*)payloadh;
  rhp_proto_ikev1_proposal_payload* proph;
  rhp_proto_ikev1_transform_payload* transh;
  rhp_proto_ikev1_attr* attrh;
  int last_prop_flag = 0;
  int prop_len,trans_len;
  u8* prop_spi;
  rhp_ikev1_proposal* prop;
  rhp_ikev1_transform* trans;
  u8 exchange_type;

  RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_NEW_RX,"xLbxdxp",ikemesg,"PROTO_IKE_PAYLOAD",payload_id,payloadh,payload_len,payload,payload_len,payloadh);

  exchange_type = ikemesg->get_exchange_type(ikemesg);

  if( payload_len
      <= (int)sizeof(rhp_proto_ikev1_sa_payload) + (int)sizeof(rhp_proto_ikev1_proposal_payload) + (int)sizeof(rhp_proto_ikev1_transform_payload) ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_NEW_RX_INVALID_MESG_1,"xdddd",ikemesg,payload_len,sizeof(rhp_proto_ikev1_sa_payload),sizeof(rhp_proto_ikev1_proposal_payload),sizeof(rhp_proto_ikev1_transform_payload));
    goto error;
  }

  sa_payload = _rhp_ikev1_alloc_sa_payload();
  if( sa_payload == NULL ){
    err = -ENOMEM;
    RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_NEW_RX_INVALID_MESG_2,"x",ikemesg);
    goto error;
  }

  payload->ext.v1_sa = sa_payload;
  payload->ext_destructor = _rhp_ikev1_sa_payload_destructor;
  payload->ext_serialize = _rhp_ikev1_sa_payload_serialize;
  payload->ext_dump = _rhp_ikev1_sa_payload_dump;

  sa_payloadh = (rhp_proto_ikev1_sa_payload*)_rhp_pkt_pull(ikemesg->rx_pkt,sizeof(rhp_proto_ikev1_sa_payload));
  if( sa_payloadh == NULL ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_NEW_RX_INVALID_MESG_3,"x",ikemesg);
    goto error;
  }

  payload->ext.v1_sa->sa_b = sa_payloadh;

  do{

  	int prop_rem;

  	proph = (rhp_proto_ikev1_proposal_payload*)_rhp_pkt_pull(ikemesg->rx_pkt,sizeof(rhp_proto_ikev1_proposal_payload));
  	if( proph == NULL ){
      err = RHP_STATUS_INVALID_MSG;
      RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_NEW_RX_INVALID_MESG_4,"x",ikemesg);
      goto error;
    }

  	if( proph->next_payload != RHP_PROTO_IKEV1_PAYLOAD_P &&
        proph->next_payload != RHP_PROTO_IKE_NO_MORE_PAYLOADS ){
      err = RHP_STATUS_INVALID_MSG;
      RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_NEW_RX_INVALID_MESG_5,"xb",ikemesg,proph->next_payload);
      goto error;
    }

  	if( proph->transform_num == 0 ){
      err = RHP_STATUS_INVALID_MSG;
      RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_NEW_RX_INVALID_MESG_6,"xd",ikemesg);
      goto error;
    }

  	prop_len = ntohs(proph->len);
  	prop_rem = prop_len;

  	if( prop_len == 0 || _rhp_pkt_try_pull(ikemesg->rx_pkt,prop_len) ){
      err = RHP_STATUS_INVALID_MSG;
      RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_NEW_RX_INVALID_MESG_7,"x",ikemesg);
      goto error;
    }

    RHP_TRC_FREQ(0,RHPTRCID_IKEV1_SA_PAYLOAD_NEW_RX_PROP_DATA,"xxp",ikemesg,proph,prop_len,proph);

  	if( proph->spi_len > 0 ){

  		if( proph->spi_len > RHP_PROTO_SPI_MAX_SIZE ){
        err = RHP_STATUS_INVALID_MSG;
        RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_NEW_RX_INVALID_MESG_8,"xbd",ikemesg,proph->spi_len,RHP_PROTO_SPI_MAX_SIZE);
        goto error;
      }

  		prop_spi = (u8*)_rhp_pkt_pull(ikemesg->rx_pkt,proph->spi_len);
  		if( prop_spi == NULL ){
  			err = RHP_STATUS_INVALID_MSG;
  			RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_NEW_RX_INVALID_MESG_9,"x",ikemesg);
  			goto error;
     	}

  		prop_rem -= proph->spi_len;

  	}else{

  		prop_spi = NULL;
  	}

  	if( proph->protocol_id == RHP_PROTO_IKEV1_PROP_PROTO_ID_ISAKMP ){

  		if( exchange_type == RHP_PROTO_IKEV1_EXCHG_ID_PROTECTION ||
  				exchange_type == RHP_PROTO_IKEV1_EXCHG_AGGRESSIVE ){
  			
  			if( proph->spi_len != 0 ){
          err = RHP_STATUS_INVALID_MSG;
          RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_NEW_RX_INVALID_MESG_10,"xb",ikemesg,proph->spi_len);
          goto error;
        }

  		}else{
        err = RHP_STATUS_INVALID_MSG;
        RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_NEW_RX_INVALID_MESG_12,"xb",ikemesg,exchange_type);
        goto error;
  		}
      
  		sa_payload->is_for_ikesa = 1;
  	
  	}else if( proph->protocol_id == RHP_PROTO_IKEV1_PROP_PROTO_ID_ESP ){

  		if( exchange_type == RHP_PROTO_IKEV1_EXCHG_QUICK ){

  			if( proph->spi_len != RHP_PROTO_IPSEC_SPI_SIZE ){
          err = RHP_STATUS_INVALID_MSG;
          RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_NEW_RX_INVALID_MESG_13,"xbbd",ikemesg,exchange_type,proph->spi_len,RHP_PROTO_IPSEC_SPI_SIZE);
          goto error;
        }

  		}else{
  			err = RHP_STATUS_INVALID_MSG;
  			RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_NEW_RX_INVALID_MESG_14,"xb",ikemesg,exchange_type);
  			goto error;
      }

  	}else{

  		if( _rhp_pkt_pull(ikemesg->rx_pkt,prop_rem) == NULL ){
  			err = RHP_STATUS_INVALID_MSG;
  			RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_NEW_RX_INVALID_MESG_15,"xbd",ikemesg,proph->protocol_id,prop_rem);
  			goto error;
  		}

  		RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_NEW_RX_UNSUP_PROTO_ID,"xb",ikemesg,proph->protocol_id);
      goto ignore;
  	}


  	prop = _rhp_ikev1_alloc_sa_proposal();
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

  		int trans_rem;
  		int trans_attr_life_type = 0;

  		transh = (rhp_proto_ikev1_transform_payload*)_rhp_pkt_pull(ikemesg->rx_pkt,sizeof(rhp_proto_ikev1_transform_payload));
  		if( transh == NULL ){
  			err = RHP_STATUS_INVALID_MSG;
  			RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_NEW_RX_INVALID_MESG_16,"xd",ikemesg,i);
  			goto error;
  		}

  		if( transh->next_payload != RHP_PROTO_IKEV1_PAYLOAD_T &&
  				transh->next_payload != RHP_PROTO_IKE_NO_MORE_PAYLOADS ){
  			err = RHP_STATUS_INVALID_MSG;
        RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_NEW_RX_INVALID_MESG_17,"xdb",ikemesg,i,transh->next_payload);
        goto error;
  		}

  		trans_len = ntohs(transh->len);
  		trans_rem = trans_len - (int)sizeof(rhp_proto_ikev1_transform_payload);
  		prop_rem -= trans_len;

  		if( trans_len == 0 || _rhp_pkt_try_pull(ikemesg->rx_pkt,trans_len) || trans_rem < 1 ){
  			err = RHP_STATUS_INVALID_MSG;
  			RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_NEW_RX_INVALID_MESG_18,"xddd",ikemesg,i,trans_len,trans_rem);
  			goto error;
  		}

      RHP_TRC_FREQ(0,RHPTRCID_IKEV1_SA_PAYLOAD_NEW_RX_TRANSFORM_DATA,"xxxp",ikemesg,proph,transh,trans_len,transh);

  		if( (exchange_type == RHP_PROTO_IKEV1_EXCHG_ID_PROTECTION ||
  				 exchange_type == RHP_PROTO_IKEV1_EXCHG_AGGRESSIVE) ){

  			if( transh->transform_id != RHP_PROTO_IKEV1_TF_ISAKMP_KEY_IKE ){
					err = RHP_STATUS_INVALID_MSG;
					RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_NEW_RX_INVALID_MESG_19,"xbb",ikemesg,exchange_type,transh->transform_id);
					goto error;
  			}

  		}else if( exchange_type == RHP_PROTO_IKEV1_EXCHG_QUICK ){

				if( transh->transform_id != RHP_PROTO_IKEV1_TF_ESP_3DES &&
						transh->transform_id != RHP_PROTO_IKEV1_TF_ESP_AES_CBC ){

					if( _rhp_pkt_pull(ikemesg->rx_pkt,trans_rem) == NULL ){
						err = RHP_STATUS_UNKNOWN_PARAM;
						RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_NEW_RX_INVALID_MESG_20,"xdbdd",ikemesg,i,transh->transform_id,trans_len,trans_rem);
						goto error;
					}

					RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_NEW_RX_UNSUP_TRANSFORM_ID,"xbd",ikemesg,transh->transform_id,trans_len,trans_rem);
					continue;
				}

  		}else{

				if( _rhp_pkt_pull(ikemesg->rx_pkt,trans_rem) == NULL ){
					err = RHP_STATUS_UNKNOWN_PARAM;
					RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_NEW_RX_INVALID_MESG_21,"xdbbdd",ikemesg,i,transh->transform_id,exchange_type,trans_len,trans_rem);
					goto error;
				}
  		}


  		trans = _rhp_ikev1_alloc_sa_transform(transh->transform_number,transh->transform_id);
  		if( trans == NULL ){
  			err = -ENOMEM;
  			RHP_BUG("");
  			goto error;
  		}

  		trans->transh = transh;
  		prop->put_trans(prop,trans);


  		while( trans_rem > 0 ){

  			int attr_val_len = 0;
  			u8* attr_val = NULL;

  			if( trans_rem < (int)sizeof(rhp_proto_ikev1_attr) ){
					err = RHP_STATUS_INVALID_MSG;
  				RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_NEW_RX_INVALID_MESG_20,"xdd",ikemesg,i,trans_rem);
  				goto error;
  			}

				attrh = (rhp_proto_ikev1_attr*)_rhp_pkt_pull(ikemesg->rx_pkt,sizeof(rhp_proto_ikev1_attr));
				if( attrh == NULL ){
					err = RHP_STATUS_INVALID_MSG;
  				RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_NEW_RX_INVALID_MESG_20,"xd",ikemesg,i);
  				goto error;
				}

				if( RHP_PROTO_IKE_ATTR_AF(attrh->attr_type) ){

					attr_val_len = 0;

  				RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_NEW_RX_PROP_ATTR_AF,"xdWp",ikemesg,i,attrh->attr_type,sizeof(rhp_proto_ikev1_attr),attrh);

				}else{

					attr_val_len = ntohs(attrh->len_or_value);
					if( attr_val_len < 1 ){
						err = RHP_STATUS_INVALID_MSG;
	  				RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_NEW_RX_INVALID_MESG_21,"xddW",ikemesg,i,attr_val_len,attrh->attr_type);
	  				goto error;
					}

					attr_val = (u8*)_rhp_pkt_pull(ikemesg->rx_pkt,attr_val_len);
					if( attr_val == NULL ){
						err = RHP_STATUS_INVALID_MSG;
	  				RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_NEW_RX_INVALID_MESG_22,"xddW",ikemesg,i,attr_val_len,attrh->attr_type);
	  				goto error;
					}

					RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_NEW_RX_PROP_ATTR,"xdWp",ikemesg,i,attrh->attr_type,(sizeof(rhp_proto_ikev1_attr) + attr_val_len),attrh);
				}

	      RHP_TRC_FREQ(0,RHPTRCID_IKEV1_SA_PAYLOAD_NEW_RX_TRANSFORM_ATTR_DATA,"xxxxp",ikemesg,proph,transh,attrh,attr_val_len,attrh);

	  		if( (exchange_type == RHP_PROTO_IKEV1_EXCHG_ID_PROTECTION ||
	  				 exchange_type == RHP_PROTO_IKEV1_EXCHG_AGGRESSIVE) ){

	  			switch( RHP_PROTO_IKE_ATTR_TYPE(attrh->attr_type) ){

					case RHP_PROTO_IKEV1_P1_ATTR_TYPE_ENCRYPTION:

	  				RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_NEW_RX_P1_PROP_ATTR_ENCRYPTION,"xddW",ikemesg,i,attr_val_len,attrh->len_or_value);

						if( attr_val_len ){
							goto next_attr;
						}

						trans->enc_alg = ntohs(attrh->len_or_value);

						break;

					case RHP_PROTO_IKEV1_P1_ATTR_TYPE_HASH:

	  				RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_NEW_RX_P1_PROP_ATTR_HASH,"xddW",ikemesg,i,attr_val_len,attrh->len_or_value);

						if( attr_val_len ){
							goto next_attr;
						}

						trans->hash_alg = ntohs(attrh->len_or_value);
						break;

					case RHP_PROTO_IKEV1_P1_ATTR_TYPE_AUTH_METHOD:

	  				RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_NEW_RX_P1_PROP_ATTR_AUTH_METHOD,"xddW",ikemesg,i,attr_val_len,attrh->len_or_value);

						if( attr_val_len ){
							goto next_attr;
						}

						trans->auth_method = ntohs(attrh->len_or_value);
						break;

					case RHP_PROTO_IKEV1_P1_ATTR_TYPE_GROUP_DESC:

	  				RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_NEW_RX_P1_PROP_ATTR_GROUP_DESC,"xddW",ikemesg,i,attr_val_len,attrh->len_or_value);

						if( attr_val_len ){
							goto next_attr;
						}

						trans->dh_group = ntohs(attrh->len_or_value);
						break;

					case RHP_PROTO_IKEV1_P1_ATTR_TYPE_LIFE_TYPE:

	  				RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_NEW_RX_P1_PROP_ATTR_LIFE_TYPE,"xddW",ikemesg,i,attr_val_len,attrh->len_or_value);

						if( attr_val_len ){
							goto next_attr;
						}

						trans_attr_life_type = ntohs(attrh->len_or_value);
						break;

					case RHP_PROTO_IKEV1_P1_ATTR_TYPE_LIFE_DURATION:

						if( !trans_attr_life_type ){
							trans_attr_life_type = 0;
							goto next_attr;
						}

						if( !attr_val_len ){

		  				RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_NEW_RX_P1_PROP_ATTR_LIFE_DURATION_1,"xddW",ikemesg,i,attr_val_len,attrh->len_or_value);

							if( trans_attr_life_type == RHP_PROTO_IKEV1_ATTR_LIFE_TYPE_SECONDS ){
								trans->life_time = ntohs(attrh->len_or_value);
							}else if( trans_attr_life_type == RHP_PROTO_IKEV1_ATTR_LIFE_TYPE_KILOBYTES ){
								trans->life_bytes = ntohs(attrh->len_or_value);
							}

						}else{

		  				RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_NEW_RX_P1_PROP_ATTR_LIFE_DURATION_2,"xdWp",ikemesg,i,attrh->len_or_value,attr_val_len,attr_val);

							if( attr_val_len != (int)sizeof(u32) ){
								trans_attr_life_type = 0;
								goto next_attr;
							}

							if( trans_attr_life_type == RHP_PROTO_IKEV1_ATTR_LIFE_TYPE_SECONDS ){
								trans->life_time = ntohl(*((u32*)attr_val));
							}else if( trans_attr_life_type == RHP_PROTO_IKEV1_ATTR_LIFE_TYPE_KILOBYTES ){
								trans->life_bytes = ntohl(*((u32*)attr_val));
							}
						}

						trans_attr_life_type = 0;
						break;

					case RHP_PROTO_IKEV1_P1_ATTR_TYPE_KEY_LEN:

	  				RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_NEW_RX_P1_PROP_ATTR_KEY_LEN,"xddW",ikemesg,i,attr_val_len,attrh->len_or_value);

						if( attr_val_len ){
							goto next_attr;
						}

						trans->key_bits_len = ntohs(attrh->len_or_value);
						break;

					default:
	  				RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_NEW_RX_P1_PROP_ATTR_UNKNOWN,"xdw",ikemesg,i,RHP_PROTO_IKE_ATTR_TYPE(attrh->attr_type));
						goto next_attr;
	  			}

	  		}else if( exchange_type == RHP_PROTO_IKEV1_EXCHG_QUICK ){

	  			switch( RHP_PROTO_IKE_ATTR_TYPE(attrh->attr_type) ){

					case RHP_PROTO_IKEV1_P2_ATTR_TYPE_LIFE_TYPE:

	  				RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_NEW_RX_P2_PROP_ATTR_LIFE_TYPE,"xddW",ikemesg,i,attr_val_len,attrh->len_or_value);

						if( attr_val_len ){
							goto next_attr;
						}

						trans_attr_life_type = ntohs(attrh->len_or_value);
						break;

					case RHP_PROTO_IKEV1_P2_ATTR_TYPE_LIFE_DURATION:

						if( !trans_attr_life_type ){
							trans_attr_life_type = 0;
							goto next_attr;
						}

						if( !attr_val_len ){

		  				RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_NEW_RX_P2_PROP_ATTR_LIFE_DURATION_1,"xddW",ikemesg,i,attr_val_len,attrh->len_or_value);

							if( trans_attr_life_type == RHP_PROTO_IKEV1_ATTR_LIFE_TYPE_SECONDS ){
								trans->life_time = ntohs(attrh->len_or_value);
							}else if( trans_attr_life_type == RHP_PROTO_IKEV1_ATTR_LIFE_TYPE_KILOBYTES ){
								trans->life_bytes = ntohs(attrh->len_or_value);
							}

						}else{

		  				RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_NEW_RX_P2_PROP_ATTR_LIFE_DURATION_2,"xdWp",ikemesg,i,attrh->len_or_value,attr_val_len,attr_val);

							if( attr_val_len != (int)sizeof(u32) ){
								trans_attr_life_type = 0;
								goto next_attr;
							}

							if( trans_attr_life_type == RHP_PROTO_IKEV1_ATTR_LIFE_TYPE_SECONDS ){
								trans->life_time = ntohl(*((u32*)attr_val));
							}else if( trans_attr_life_type == RHP_PROTO_IKEV1_ATTR_LIFE_TYPE_KILOBYTES ){
								trans->life_bytes = ntohl(*((u32*)attr_val));
							}
						}

						trans_attr_life_type = 0;
						break;

					case RHP_PROTO_IKEV1_P2_ATTR_TYPE_GROUP_DESC:

	  				RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_NEW_RX_P2_PROP_ATTR_GROUP_DESC,"xddW",ikemesg,i,attr_val_len,attrh->len_or_value);

						if( attr_val_len ){
							goto next_attr;
						}

						trans->dh_group = ntohs(attrh->len_or_value);
						break;

						break;

					case RHP_PROTO_IKEV1_P2_ATTR_TYPE_ENCAP_MODE:

	  				RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_NEW_RX_P2_PROP_ATTR_ENCAP_MODE,"xddW",ikemesg,i,attr_val_len,attrh->len_or_value);

						if( attr_val_len ){
							goto next_attr;
						}

						trans->encap_mode = ntohs(attrh->len_or_value);
						break;

						break;

					case RHP_PROTO_IKEV1_P2_ATTR_TYPE_AUTH:

	  				RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_NEW_RX_P2_PROP_ATTR_AUTH,"xddW",ikemesg,i,attr_val_len,attrh->len_or_value);

						if( attr_val_len ){
							goto next_attr;
						}

						trans->auth_alg = ntohs(attrh->len_or_value);
						break;

					case RHP_PROTO_IKEV1_P2_ATTR_TYPE_KEY_LEN:

	  				RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_NEW_RX_P2_PROP_ATTR_KEY_LEN,"xddW",ikemesg,i,attr_val_len,attrh->len_or_value);

						if( attr_val_len ){
							goto next_attr;
						}

						trans->key_bits_len = ntohs(attrh->len_or_value);
						break;

					case RHP_PROTO_IKEV1_P2_ATTR_TYPE_ESN:

	  				RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_NEW_RX_P2_PROP_ATTR_ESN,"xddW",ikemesg,i,attr_val_len,attrh->len_or_value);

						if( attr_val_len ){
							goto next_attr;
						}

						trans->esn = ntohs(attrh->len_or_value);
						break;

					default:
	  				RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_NEW_RX_P2_PROP_ATTR_UNKNOWN,"xdw",ikemesg,i,RHP_PROTO_IKE_ATTR_TYPE(attrh->attr_type));
						goto next_attr;
	  			}

	  		}else{
  				RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_NEW_RX_PROP_ATTR_UNKNOWN_EXCHANGE_MODE,"xdb",ikemesg,i,exchange_type);
	  			goto next_attr;
	  		}


next_attr:
				trans_rem -= attr_val_len + (int)sizeof(rhp_proto_ikev1_attr);
  		}
  	}

ignore:
   last_prop_flag = (proph->next_payload == RHP_PROTO_IKE_NO_MORE_PAYLOADS);

  }while( !last_prop_flag );

  RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_NEW_RX_RTRN,"x",ikemesg);
  return 0;

error:
  if( payload->ext_destructor ){
    payload->ext_destructor(payload);
  }

  RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_NEW_RX_ERR,"xE",ikemesg,err);
  return err;
}


int rhp_ikev1_sa_payload_new_tx(rhp_ikev2_mesg* ikemesg,u8 payload_id,rhp_ikev2_payload* payload)
{
  int err = 0;
  rhp_ikev1_sa_payload* sa_payload;

  RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_NEW_TX,"xLbx",ikemesg,"PROTO_IKE_PAYLOAD",payload_id,payload);

  sa_payload = _rhp_ikev1_alloc_sa_payload();
  if( sa_payload == NULL ){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }

  payload->ext.v1_sa = sa_payload;
  payload->ext_destructor = _rhp_ikev1_sa_payload_destructor;
  payload->ext_serialize = _rhp_ikev1_sa_payload_serialize;
  payload->ext_dump = _rhp_ikev1_sa_payload_dump;

  RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_NEW_TX_RTRN,"x",ikemesg);
  return 0;

error:
  if( payload->ext_destructor ){
    payload->ext_destructor(payload);
  }

  RHP_TRC(0,RHPTRCID_IKEV1_SA_PAYLOAD_NEW_TX_ERR,"xE",ikemesg,err);
  return err;
}



