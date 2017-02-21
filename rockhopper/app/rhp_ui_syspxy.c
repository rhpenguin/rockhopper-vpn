/*

	Copyright (C) 2009-2010 TETSUHARU HANADA <rhpenguine@gmail.com>
	All rights reserved.
	
	You can redistribute and/or modify this software under the 
	LESSER GPL version 2.1.
	See also LICENSE.txt and LICENSE_LGPL2.1.txt.

*/


#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/capability.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

#include "rhp_trace.h"
#include "rhp_main_traceid.h"
#include "rhp_misc.h"
#include "rhp_process.h"
#include "rhp_netmng.h"
#include "rhp_packet.h"
#include "rhp_netsock.h"
#include "rhp_timer.h"
#include "rhp_wthreads.h"
#include "rhp_config.h"
#include "rhp_ikev2_mesg.h"
#include "rhp_crypto.h"
#include "rhp_auth_tool.h"
#include "rhp_cert.h"
#include "rhp_ui.h"
#include "rhp_eap_auth_impl.h"
#include "rhp_radius_impl.h"


extern rhp_mutex_t rhp_auth_lock;

extern rhp_vpn_auth_realm* rhp_auth_realm_list_head;

extern char* rhp_syspxy_cert_store_path;
extern char* rhp_syspxy_policy_conf_path;

extern char* rhp_syspxy_auth_conf_path;

extern rhp_auth_admin_info* rhp_auth_admin_head;

char* rhp_syspxy_home_dir = NULL;

char* rhp_syspxy_cfg_bkup_cmd_path = NULL;
char* rhp_syspxy_cfg_bkup_path = NULL;

char* rhp_syspxy_cfg_cert_cmd_path = NULL;
char* rhp_syspxy_cfg_cert_uploaded_path = NULL;

char* rhp_mng_cmd_path = NULL;
char* rhp_mng_cmd_dir = NULL;

extern int rhp_auth_resolve_my_auth_cert_my_id(rhp_my_auth* my_auth,rhp_cert_store* cert_store);

extern void rhp_cfg_trc_dump_auth_realm(rhp_vpn_auth_realm* auth_rlm);


struct _rhp_ui_ipc_get_enum_ctx {
	unsigned long rlm_id;
	void* writer;
	int idx;
	int* n2;
} ;
typedef struct _rhp_ui_ipc_get_enum_ctx		rhp_ui_ipc_get_enum_ctx;


static int _rhp_syspxy_ui_get_enum_auth_xml_my_auth(xmlNodePtr node,void* ctx)
{
  rhp_ui_ipc_get_enum_ctx* enum_ctx = (rhp_ui_ipc_get_enum_ctx*)ctx;
  xmlAttrPtr attr = NULL;

  RHP_TRC(0,RHPTRCID_SYSPXY_UI_GET_ENUM_AUTH_XML_MY_AUTH,"xsxxxu",node,node->name,ctx,enum_ctx->writer,enum_ctx->n2,enum_ctx->rlm_id);

  if( !xmlStrcmp(node->name,(xmlChar*)"my_psk") ){

		{
			attr =	xmlHasProp(node,(xmlChar*)"hashed_key");
			if( attr ){

				xmlRemoveProp(attr);

				if( xmlNewProp(node,(xmlChar*)"hashed_key",(xmlChar*)"xxxxxxx") == NULL ){
					RHP_BUG("");
				}
			}
		}

		{
			attr =	xmlHasProp(node,(xmlChar*)"key");
			if( attr ){

				xmlRemoveProp(attr);

				if( xmlNewProp(node,(xmlChar*)"key",(xmlChar*)"xxxxxxx") == NULL ){
					RHP_BUG("");
				}
			}
		}

		{
			attr =	xmlHasProp(node,(xmlChar*)"mschapv2_key");
			if( attr ){

				xmlRemoveProp(attr);

				if( xmlNewProp(node,(xmlChar*)"mschapv2_key",(xmlChar*)"xxxxxxx") == NULL ){
					RHP_BUG("");
				}
			}
		}
  }

  RHP_TRC(0,RHPTRCID_SYSPXY_UI_GET_ENUM_AUTH_XML_MY_AUTH_RTRN,"xsxxxu",node,node->name,ctx,enum_ctx->writer,enum_ctx->n2,enum_ctx->rlm_id);
  return 0;
}

static int _rhp_syspxy_ui_get_enum_auth_xml_peer(xmlNodePtr node,void* ctx)
{
  rhp_ui_ipc_get_enum_ctx* enum_ctx = (rhp_ui_ipc_get_enum_ctx*)ctx;
  xmlAttrPtr attr = NULL;

  RHP_TRC(0,RHPTRCID_SYSPXY_UI_GET_ENUM_AUTH_XML_PEER,"xsxxxu",node,node->name,ctx,enum_ctx->writer,enum_ctx->n2,enum_ctx->rlm_id);

  if( !xmlStrcmp(node->name,(xmlChar*)"peer_psk") ){

		{
			attr =	xmlHasProp(node,(xmlChar*)"hashed_key");
			if( attr ){

				xmlRemoveProp(attr);

				if( xmlNewProp(node,(xmlChar*)"hashed_key",(xmlChar*)"xxxxxxx") == NULL ){
					RHP_BUG("");
				}
			}
		}

		{
			attr =	xmlHasProp(node,(xmlChar*)"key");
			if( attr ){

				xmlRemoveProp(attr);

				if( xmlNewProp(node,(xmlChar*)"key",(xmlChar*)"xxxxxxx") == NULL ){
					RHP_BUG("");
				}
			}
		}

		{
			attr =	xmlHasProp(node,(xmlChar*)"mschapv2_key");
			if( attr ){

				xmlRemoveProp(attr);

				if( xmlNewProp(node,(xmlChar*)"mschapv2_key",(xmlChar*)"xxxxxxx") == NULL ){
					RHP_BUG("");
				}
			}
		}
  }

  RHP_TRC(0,RHPTRCID_SYSPXY_UI_GET_ENUM_AUTH_XML_PEER_RTRN,"xsxxxu",node,node->name,ctx,enum_ctx->writer,enum_ctx->n2,enum_ctx->rlm_id);
  return 0;
}

static int _rhp_syspxy_ui_get_enum_auth_xml_peers(xmlNodePtr node,void* ctx)
{
	int err = -EINVAL;
  rhp_ui_ipc_get_enum_ctx* enum_ctx = (rhp_ui_ipc_get_enum_ctx*)ctx;

  RHP_TRC(0,RHPTRCID_SYSPXY_UI_GET_ENUM_AUTH_XML_PEERS,"xsxxxu",node,node->name,ctx,enum_ctx->writer,enum_ctx->n2,enum_ctx->rlm_id);

  err = rhp_xml_enum_tags(node,NULL,_rhp_syspxy_ui_get_enum_auth_xml_peer,(void*)enum_ctx,1);
  if( err && err != -ENOENT ){
  	RHP_BUG("");
  	goto error;
  }
  err = 0;

  RHP_TRC(0,RHPTRCID_SYSPXY_UI_GET_ENUM_AUTH_XML_PEERS_RTRN,"xsxxxu",node,node->name,ctx,enum_ctx->writer,enum_ctx->n2,enum_ctx->rlm_id);
  return 0;

error:
	RHP_TRC(0,RHPTRCID_SYSPXY_UI_GET_ENUM_AUTH_XML_PEERS_ERR,"xsxxxuE",node,node->name,ctx,enum_ctx->writer,enum_ctx->n2,enum_ctx->rlm_id,err);
	return err;
}

static int _rhp_syspxy_ui_get_enum_auth_xml_vpn_realm(xmlNodePtr node,void* ctx)
{
	int err = -EINVAL;
  rhp_ui_ipc_get_enum_ctx* enum_ctx = (rhp_ui_ipc_get_enum_ctx*)ctx;

  RHP_TRC(0,RHPTRCID_SYSPXY_UI_GET_ENUM_AUTH_XML_VPN_REALM,"xsxxxu",node,node->name,ctx,enum_ctx->writer,enum_ctx->n2,enum_ctx->rlm_id);

  if( !xmlStrcmp(node->name,(xmlChar*)"roles") 	||
  		!xmlStrcmp(node->name,(xmlChar*)"eap")		||
  		!xmlStrcmp(node->name,(xmlChar*)"xauth")		||
  		!xmlStrcmp(node->name,(xmlChar*)"cert_store")	||
  		!xmlStrcmp(node->name,(xmlChar*)"eap_server") ||
  		!xmlStrcmp(node->name,(xmlChar*)"cert_urls")  ||
  		!xmlStrcmp(node->name,(xmlChar*)"auth_method_for_peers") ){

		err = rhp_xml_write_node(node,(xmlTextWriterPtr)enum_ctx->writer,enum_ctx->n2,1,NULL,NULL,NULL);
  	if( err ){
    	RHP_BUG("%d");
  		goto error;
  	}

  }else if( !xmlStrcmp(node->name,(xmlChar*)"cert_my_priv_key") ){

		{
			xmlAttrPtr attr =	xmlHasProp(node,(xmlChar*)"password");
			if( attr ){

				xmlRemoveProp(attr);

				if( xmlNewProp(node,(xmlChar*)"password",(xmlChar*)"xxxxxxx") == NULL ){
					RHP_BUG("");
				}
			}
		}

		err = rhp_xml_write_node(node,(xmlTextWriterPtr)enum_ctx->writer,enum_ctx->n2,1,NULL,NULL,NULL);
  	if( err ){
    	RHP_BUG("");
  		goto error;
  	}

  }else if( !xmlStrcmp(node->name,(xmlChar*)"my_auth") ){

    err = rhp_xml_enum_tags(node,NULL,_rhp_syspxy_ui_get_enum_auth_xml_my_auth,(void*)enum_ctx,1);
    if( err && err != -ENOENT ){
    	RHP_BUG("");
    	goto error;
    }
    err = 0;

		err = rhp_xml_write_node(node,(xmlTextWriterPtr)enum_ctx->writer,enum_ctx->n2,1,NULL,NULL,NULL);
		if( err ){
    	RHP_BUG("");
			goto error;
		}

  }else if( !xmlStrcmp(node->name,(xmlChar*)"peers") ){

    err = rhp_xml_enum_tags(node,NULL,_rhp_syspxy_ui_get_enum_auth_xml_peers,(void*)enum_ctx,1);
    if( err && err != -ENOENT ){
    	RHP_BUG("");
    	goto error;
    }
    err = 0;

		err = rhp_xml_write_node(node,(xmlTextWriterPtr)enum_ctx->writer,enum_ctx->n2,1,NULL,NULL,NULL);
		if( err ){
    	RHP_BUG("");
			goto error;
		}

  }

  RHP_TRC(0,RHPTRCID_SYSPXY_UI_GET_ENUM_AUTH_XML_VPN_REALM_RTRN,"xsxxdu",node,node->name,ctx,enum_ctx->writer,*(enum_ctx->n2),enum_ctx->rlm_id);
  return 0;

error:
	RHP_TRC(0,RHPTRCID_SYSPXY_UI_GET_ENUM_AUTH_XML_VPN_REALM_ERR,"xsxxxuE",node,node->name,ctx,enum_ctx->writer,enum_ctx->n2,enum_ctx->rlm_id,err);
	return err;
}

static int _rhp_syspxy_ui_get_enum_auth_xml_vpn_realms(xmlNodePtr node,void* ctx)
{
	int err = -EINVAL;
	int ret_len;
  rhp_ui_ipc_get_enum_ctx* enum_ctx = (rhp_ui_ipc_get_enum_ctx*)ctx;
  unsigned long rlm_id;

  RHP_TRC(0,RHPTRCID_SYSPXY_UI_GET_ENUM_AUTH_XML_VPN_REALMS,"xxuu",node,ctx,rlm_id,enum_ctx->rlm_id);

  if( rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"id"),RHP_XML_DT_ULONG,&rlm_id,&ret_len,NULL,0) ){
    RHP_BUG("");
    goto error;
  }

  if( (rlm_id == enum_ctx->rlm_id) || (enum_ctx->rlm_id == 0) ){

  	err = rhp_xml_write_node_start(node,enum_ctx->writer,enum_ctx->n2,NULL,NULL);
    if( err ){
    	RHP_BUG("");
    	goto error;
    }

    err = rhp_xml_enum_tags(node,NULL,_rhp_syspxy_ui_get_enum_auth_xml_vpn_realm,(void*)enum_ctx,1);
    if( err && err != -ENOENT ){
    	RHP_BUG("");
    	goto error;
    }
    err = 0;

  	err = rhp_xml_write_node_end(node,enum_ctx->writer,enum_ctx->n2);
    if( err ){
    	RHP_BUG("");
    	goto error;
    }
  }

  RHP_TRC(0,RHPTRCID_SYSPXY_UI_GET_ENUM_AUTH_XML_VPN_REALMS_RTRN,"xxd",node,ctx,*(enum_ctx->n2));
  return 0;

error:
	RHP_TRC(0,RHPTRCID_SYSPXY_UI_GET_ENUM_AUTH_XML_VPN_REALMS_ERR,"xxE",node,ctx,err);
	return err;
}


static int _rhp_syspxy_ui_get(rhp_ipcmsg_syspxy_cfg_sub* cfg_sub_dt,rhp_ipcmsg_syspxy_cfg_sub* cfg_sub_dt_rep,
		xmlTextWriterPtr writer,int* n)
{
	int err = -EINVAL;
	rhp_ui_ipc_get_enum_ctx enum_ctx;
  xmlDocPtr auth_doc = NULL;
  xmlNodePtr auth_root_node = NULL;

  RHP_TRC(0,RHPTRCID_SYSPXY_UI_GET,"xxx",cfg_sub_dt,cfg_sub_dt_rep,writer);

	enum_ctx.idx = 0;
	enum_ctx.writer = writer;
	enum_ctx.n2 = n;
	enum_ctx.rlm_id = cfg_sub_dt->target_rlm_id;

	auth_doc = xmlParseFile(rhp_syspxy_auth_conf_path);
  if( auth_doc == NULL ){
    RHP_BUG(" %s ",rhp_syspxy_auth_conf_path);
    err = -ENOENT;
    goto error;
  }

  auth_root_node = xmlDocGetRootElement(auth_doc);
  if( auth_root_node == NULL ){
    RHP_BUG(" %s ",rhp_syspxy_auth_conf_path);
    err = -ENOENT;
    goto error;
  }

  err = rhp_xml_enum_tags(auth_root_node,(xmlChar*)"vpn_realm",
  				_rhp_syspxy_ui_get_enum_auth_xml_vpn_realms,(void*)&enum_ctx,1);
  if( err && err != -ENOENT ){
    RHP_BUG(" %s ",rhp_syspxy_auth_conf_path);
    goto error;
  }
  err = 0;


	xmlFreeDoc(auth_doc);

  RHP_TRC(0,RHPTRCID_SYSPXY_UI_GET_RTRN,"xxxd",cfg_sub_dt,cfg_sub_dt_rep,writer,*n);
	return 0;

error:
	if( auth_doc ){
		xmlFreeDoc(auth_doc);
	}

	RHP_TRC(0,RHPTRCID_SYSPXY_UI_GET_ERR,"xxxE",cfg_sub_dt,cfg_sub_dt_rep,writer,err);
	return err;
}

static int _rhp_syspxy_ui_get_resource_statistics(rhp_ipcmsg_syspxy_cfg_sub* cfg_sub_dt,rhp_ipcmsg_syspxy_cfg_sub* cfg_sub_dt_rep,
		xmlTextWriterPtr writer,int* n)
{
	int err = -EINVAL;
	int n2,i;
	u64 main_alloc_size = 0;
	u64 main_free_size = 0;
	rhp_wts_worker_statistics* wts_tables = NULL;
	int wts_tables_num = 0;

	RHP_TRC(0,RHPTRCID_SYSPXY_UI_GET_RESOURCE_STATISTICS,"xxxx",cfg_sub_dt,cfg_sub_dt_rep,writer,n);

	if( rhp_wts_get_statistics(&wts_tables,&wts_tables_num) ){
		RHP_BUG("");
	}

	if( rhp_mem_statistics_get(&main_alloc_size,&main_free_size) ){
		RHP_BUG("");
	}

	n2 = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"protected_process");
	if(n2 < 0) {
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
  *n += n2;

  n2 = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"memory_alloc_bytes","%llu",main_alloc_size);
	if(n2 < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
  *n += n2;

  n2 = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"memory_freed_bytes","%llu",main_free_size);
	if(n2 < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
  *n += n2;

  n2 = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"memory_used_bytes","%llu",(main_alloc_size - main_free_size));
	if(n2 < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
  *n += n2;

	for( i = 0; i < wts_tables_num; i++ ){

		n2 = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"worker_thread");
		if(n2 < 0) {
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
	  *n += n2;

	  n2 = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"worker_thread_id","%d",i);
		if(n2 < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
	  *n += n2;

	  n2 = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"exec_tasks","%llu",wts_tables[i].exec_tasks_counter);
		if(n2 < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
	  *n += n2;

		n2 = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
		if(n2 < 0) {
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
	  *n += n2;
	}

	n2 = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
	if(n2 < 0) {
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
  *n += n2;

  if( wts_tables ){
  	_rhp_free(wts_tables);
  }

  RHP_TRC(0,RHPTRCID_SYSPXY_UI_GET_RESOURCE_STATISTICS_RTRN,"xxx",cfg_sub_dt,cfg_sub_dt_rep,writer);
  return 0;

error:
	if( wts_tables ){
		_rhp_free(wts_tables);
	}
	RHP_TRC(0,RHPTRCID_SYSPXY_UI_GET_RESOURCE_STATISTICS_ERR,"xxxE",cfg_sub_dt,cfg_sub_dt_rep,writer,err);
	return err;
}

static xmlNodePtr _rhp_syspxy_ui_create_xml_def_realm(unsigned long rlm_id)
{
	int err = -EINVAL;
	xmlNodePtr root_node = NULL;
	xmlNodePtr realm_node = NULL;
	xmlChar vpn_realm_str[32];

  RHP_TRC(0,RHPTRCID_SYSPXY_UI_CREATE_XML_DEF_REALM,"u",rlm_id);

	vpn_realm_str[0] = '\0';

	root_node =	xmlNewNode(NULL,(xmlChar*)"rhp_auth");
	if( root_node == NULL ){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}

	realm_node =	xmlNewNode(NULL,(xmlChar*)"vpn_realm");
	if( realm_node == NULL ){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}

	if( snprintf((char*)vpn_realm_str,32,"%lu",rlm_id) >= 32 ){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}

	if( xmlNewProp(realm_node,(xmlChar*)"id",vpn_realm_str) == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}

	if( xmlAddChild(root_node,realm_node) == NULL ){
  	RHP_BUG("");
		err = -EINVAL;
		goto error;
	}

  RHP_TRC(0,RHPTRCID_SYSPXY_UI_CREATE_XML_DEF_REALM,"ux",rlm_id,root_node);
	return root_node;

error:
	if( realm_node ){
		xmlUnlinkNode(realm_node);
		xmlFreeNode(realm_node);
	}
	if( root_node ){
		xmlUnlinkNode(root_node);
		xmlFreeNode(root_node);
	}
  RHP_TRC(0,RHPTRCID_SYSPXY_UI_CREATE_XML_DEF_REALM_ERR,"u",rlm_id);
	return NULL;
}


static int _rhp_syspxy_ui_create_parse_realm(xmlNodePtr node,unsigned long rlm_id,xmlNodePtr cfg_parent)
{
	int err = -EINVAL;
	rhp_vpn_auth_realm* auth_rlm = NULL;
  xmlNodePtr dup_node = NULL;

  RHP_TRC(0,RHPTRCID_SYSPXY_UI_CREATE_PARSE_REALM,"xux",node,rlm_id,cfg_parent);

  auth_rlm =  rhp_auth_parse_auth_realm(node);
  if( auth_rlm == NULL ){
  	RHP_BUG("%d",rlm_id);
  	err = -EINVAL;
  	goto error;
  }
	rhp_auth_realm_hold(auth_rlm);

	if( auth_rlm->disabled ){
  	RHP_BUG("%d",rlm_id);
    err = RHP_STATUS_INVALID_MSG;
  	goto error;
	}

  if( auth_rlm->id != rlm_id ){
  	RHP_BUG(" %u, %u ",auth_rlm->id,rlm_id);
    err = RHP_STATUS_INVALID_MSG;
  	goto error;
  }

  _rhp_atomic_set(&(auth_rlm->is_active),1);

	err = rhp_auth_realm_put(auth_rlm);
  if( err ){
  	RHP_BUG("%d",auth_rlm->id);
  	goto error;
  }

  if( cfg_parent ){

  	dup_node = xmlCopyNode(node,1);
		if( dup_node ){

			if( xmlAddChild(cfg_parent,dup_node) == NULL ){
				RHP_BUG("%d",auth_rlm->id);
			}

		}else{
			RHP_BUG("%d",auth_rlm->id);
		}
  }

	rhp_auth_realm_unhold(auth_rlm);

	RHP_TRC(0,RHPTRCID_SYSPXY_UI_CREATE_PARSE_REALM_RTRN,"xux",node,rlm_id,cfg_parent);
	return 0;

error:
	if( auth_rlm ){
		rhp_auth_realm_unhold(auth_rlm);
	}

	RHP_TRC(0,RHPTRCID_SYSPXY_UI_CREATE_PARSE_REALM_ERR,"xuxE",node,rlm_id,cfg_parent,err);
  return err;
}

static int _rhp_syspxy_ui_create_realm(rhp_ipcmsg_syspxy_cfg_sub* cfg_sub_dt,
		rhp_ipcmsg_syspxy_cfg_sub* cfg_sub_dt_rep,xmlTextWriterPtr writer,int* n2)
{
	int err = -EINVAL;
	unsigned long rlm_id = cfg_sub_dt->target_rlm_id;
	xmlDocPtr cfg_doc = NULL;
	xmlNodePtr cfg_root_node = NULL;
	xmlNodePtr rhp_auth_node = NULL;

  RHP_TRC(0,RHPTRCID_SYSPXY_UI_CREATE_REALM,"xxxxdu",cfg_sub_dt,cfg_sub_dt_rep,writer,n2,*n2,rlm_id);

  if( rlm_id == 0 || rlm_id > RHP_VPN_REALM_ID_MAX ){

    RHP_TRC(0,RHPTRCID_SYSPXY_UI_CREATE_REALM_NOT_PERMITTED,"xu",cfg_sub_dt,rlm_id);
  	err = -EPERM;
		goto error;

  }else{

  	rhp_vpn_auth_realm* auth_rlm = rhp_auth_realm_get(rlm_id);
  	if( auth_rlm ){

      RHP_TRC(0,RHPTRCID_SYSPXY_UI_CREATE_REALM_ALREADY_EXISTS,"xu",cfg_sub_dt,rlm_id);
  		err = -EEXIST;
      rhp_auth_realm_hold(auth_rlm);

  		goto error;
  	}
  }

  {
		cfg_doc = xmlParseFile(rhp_syspxy_auth_conf_path);
		if( cfg_doc == NULL ){
			RHP_BUG(" %s ",rhp_syspxy_auth_conf_path);
			err = -ENOENT;
			goto error;
		}

		cfg_root_node = xmlDocGetRootElement(cfg_doc);
		if( cfg_root_node == NULL ){
			RHP_BUG(" %s ",rhp_syspxy_auth_conf_path);
			err = -ENOENT;
			goto error;
		}
	}

	rhp_auth_node = _rhp_syspxy_ui_create_xml_def_realm(rlm_id);
	if( rhp_auth_node == NULL ){
		RHP_BUG("");
		goto error;
	}

	err = _rhp_syspxy_ui_create_parse_realm(rhp_auth_node->children,rlm_id,cfg_root_node);
	if( err ){
		RHP_BUG("%d",err);
		goto error;
	}

	err = rhp_cfg_save_config(rhp_syspxy_auth_conf_path,cfg_doc);
	if( err ){
		RHP_BUG("%d",err);
	}

	if( cfg_doc ){
		xmlFreeDoc(cfg_doc);
		cfg_doc = NULL;
	}

	RHP_LOG_I(RHP_LOG_SRC_UI,0,RHP_LOG_ID_SYSPXY_CREATE_REALM,"u",rlm_id);
  RHP_TRC(0,RHPTRCID_SYSPXY_UI_CREATE_REALM_RTRN,"xu",cfg_sub_dt,rlm_id);
  return 0;

error:
	RHP_LOG_E(RHP_LOG_SRC_UI,0,RHP_LOG_ID_SYSPXY_CREATE_REALM_ERR,"uE",rlm_id,err);
	RHP_TRC(0,RHPTRCID_SYSPXY_UI_CREATE_REALM_ERR,"xuE",cfg_sub_dt,rlm_id,err);
	return err;
}


static int _rhp_syspxy_ui_enable_realm_cb(xmlNodePtr node,void* ctx)
{
	int err = -EINVAL;
	int ret_len;
  rhp_ui_ipc_get_enum_ctx* enum_ctx = (rhp_ui_ipc_get_enum_ctx*)ctx;
  unsigned long rlm_id;

  RHP_TRC(0,RHPTRCID_SYSPXY_UI_ENABLE_REALM_CB,"xxuu",node,ctx,rlm_id,enum_ctx->rlm_id);

  if( rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"id"),
  			RHP_XML_DT_ULONG,&rlm_id,&ret_len,NULL,0) ){
    RHP_BUG("");
    goto error;
  }

  if( rlm_id == enum_ctx->rlm_id ){

  	xmlAttrPtr status_attr;

  	status_attr =	xmlHasProp(node,(xmlChar*)"status");

		if( xmlNewProp(node,(xmlChar*)"status",(xmlChar*)"enable") == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		if( status_attr ){
			xmlRemoveProp(status_attr);
		}

  	err = _rhp_syspxy_ui_create_parse_realm(node,rlm_id,NULL);
  	if( err ){
  		RHP_BUG("");
  		goto error;
  	}

		rhp_auth_realm_disabled_delete(rlm_id);

  	err = RHP_STATUS_ENUM_OK;

  }else{

  	err = 0;
  }

  RHP_TRC(0,RHPTRCID_SYSPXY_UI_ENABLE_REALM_CB_RTRN,"xxdE",node,ctx,*(enum_ctx->n2),err);
  return err;

error:
	RHP_TRC(0,RHPTRCID_SYSPXY_UI_ENABLE_REALM_CB_ERR,"xxE",node,ctx,err);
	return err;
}

static int _rhp_syspxy_ui_enable_realm(rhp_ipcmsg_syspxy_cfg_sub* cfg_sub_dt,
		rhp_ipcmsg_syspxy_cfg_sub* cfg_sub_dt_rep,xmlTextWriterPtr writer,int* n)
{
	int err = -EINVAL;
	rhp_ui_ipc_get_enum_ctx enum_ctx;
  xmlDocPtr auth_doc = NULL;
  xmlNodePtr auth_root_node = NULL;

  RHP_TRC(0,RHPTRCID_SYSPXY_UI_ENABLE,"xxx",cfg_sub_dt,cfg_sub_dt_rep,writer);

  {
		rhp_vpn_auth_realm* auth_rlm = rhp_auth_realm_get(cfg_sub_dt->target_rlm_id);
		if( auth_rlm ){

			RHP_TRC(0,RHPTRCID_SYSPXY_UI_ENABLE_ALREADY_ENABLED,"xu",cfg_sub_dt,cfg_sub_dt->target_rlm_id);
			err = -EEXIST;
			rhp_auth_realm_hold(auth_rlm);

			goto error;
		}
  }

	enum_ctx.idx = 0;
	enum_ctx.writer = writer;
	enum_ctx.n2 = n;
	enum_ctx.rlm_id = cfg_sub_dt->target_rlm_id;

	auth_doc = xmlParseFile(rhp_syspxy_auth_conf_path);
  if( auth_doc == NULL ){
    RHP_BUG(" %s ",rhp_syspxy_auth_conf_path);
    err = -ENOENT;
    goto error;
  }

  auth_root_node = xmlDocGetRootElement(auth_doc);
  if( auth_root_node == NULL ){
    RHP_BUG(" %s ",rhp_syspxy_auth_conf_path);
    err = -ENOENT;
    goto error;
  }

  err = rhp_xml_enum_tags(auth_root_node,(xmlChar*)"vpn_realm",
  			_rhp_syspxy_ui_enable_realm_cb,(void*)&enum_ctx,1);
  if( err == RHP_STATUS_ENUM_OK ){

  	err = rhp_cfg_save_config(rhp_syspxy_auth_conf_path,auth_doc);
  	if( err ){
  		RHP_BUG("%d",err);
  	}

  }else if( err && err != -ENOENT ){
    RHP_BUG(" %s ",rhp_syspxy_auth_conf_path);
    goto error;
  }
  err = 0;

	xmlFreeDoc(auth_doc);

  RHP_TRC(0,RHPTRCID_SYSPXY_UI_ENABLE_RTRN,"xxxd",cfg_sub_dt,cfg_sub_dt_rep,writer,*n);
	return 0;

error:
	if( auth_doc ){
		xmlFreeDoc(auth_doc);
	}

	RHP_TRC(0,RHPTRCID_SYSPXY_UI_ENABLE_ERR,"xxxE",cfg_sub_dt,cfg_sub_dt_rep,writer,err);
	return err;
}

static int _rhp_syspxy_ui_disable_realm_cb(xmlNodePtr node,void* ctx)
{
	int err = -EINVAL;
	int ret_len;
  unsigned long tgt_rlm_id = (unsigned long)ctx, elm_rlm_id = 0;

  RHP_TRC(0,RHPTRCID_SYSPXY_UI_DISABLE_REALM_CB,"xxu",node,ctx,tgt_rlm_id);

  if( rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"id"),
  			RHP_XML_DT_ULONG,&elm_rlm_id,&ret_len,NULL,0) ){
    RHP_BUG("");
    goto error;
  }

  if( elm_rlm_id == tgt_rlm_id ){

  	xmlAttrPtr status_attr;

  	status_attr =	xmlHasProp(node,(xmlChar*)"status");

		if( xmlNewProp(node,(xmlChar*)"status",(xmlChar*)"disable") == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		if( status_attr ){
			xmlRemoveProp(status_attr);
		}

  	err = RHP_STATUS_ENUM_OK;

  }else{

  	err = 0;
  }

  RHP_TRC(0,RHPTRCID_SYSPXY_UI_DISABLE_REALM_CB_RTRN,"xxE",node,ctx,err);
  return err;

error:
	RHP_TRC(0,RHPTRCID_SYSPXY_UI_DISABLE_REALM_CB_ERR,"xxE",node,ctx,err);
	return err;
}


static int _rhp_syspxy_ui_delete_realm_unlink_node(xmlNodePtr node,void* ctx)
{
	int err = -EINVAL;
	unsigned long tgt_rlm_id = (unsigned long)ctx;
	unsigned long elm_rlm_id;
	int ret_len;

	RHP_TRC(0,RHPTRCID_SYSPXY_UI_DELETE_REALM_UNLINK_NODE,"xu",node,tgt_rlm_id);

  err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"id"),
  				RHP_XML_DT_ULONG,&elm_rlm_id,&ret_len,NULL,0);
  if( !err ){

  	if( tgt_rlm_id == elm_rlm_id ){

  		xmlUnlinkNode(node);
  		xmlFreeNode(node);

  		RHP_TRC(0,RHPTRCID_SYSPXY_UI_DELETE_REALM_UNLINK_NODE_ENUM_OK_RTRN,"xu",node,tgt_rlm_id);
  		return RHP_STATUS_ENUM_OK;
  	}

  }else{
  	RHP_TRC(0,RHPTRCID_SYSPXY_UI_DELETE_REALM_UNLINK_NODE_GET_VAL_ERR,"xuE",node,tgt_rlm_id,err);
  }

	RHP_TRC(0,RHPTRCID_SYSPXY_UI_DELETE_REALM_UNLINK_NODE_RTRN,"xu",node,tgt_rlm_id);
  return 0;
}

static int _rhp_syspxy_ui_delete_realm(int disable_rlm_cfg,
		rhp_ipcmsg_syspxy_cfg_sub* cfg_sub_dt,rhp_ipcmsg_syspxy_cfg_sub* cfg_sub_dt_rep,
		xmlTextWriterPtr writer,int* n)
{
	int err = -EINVAL;
	unsigned long rlm_id = cfg_sub_dt->target_rlm_id;
	xmlDocPtr cfg_doc = NULL;
	xmlNodePtr cfg_root_node = NULL;
	rhp_vpn_auth_realm* auth_rlm = NULL;

	RHP_TRC(0,RHPTRCID_SYSPXY_UI_DELETE_REALM,"dxxxxdu",disable_rlm_cfg,cfg_sub_dt,cfg_sub_dt_rep,writer,n,*n,rlm_id);

  if( rlm_id == 0 || rlm_id > RHP_VPN_REALM_ID_MAX ){
  	RHP_TRC(0,RHPTRCID_SYSPXY_UI_DELETE_REALM_NOT_PERMITTED,"xxxxdu",cfg_sub_dt,cfg_sub_dt_rep,writer,n,*n,rlm_id);
  	err = -EPERM;
		goto error;
  }

  auth_rlm = rhp_auth_realm_delete_by_id(rlm_id); // auth_rlm may be NULL.
  if( auth_rlm ){

  	_rhp_atomic_set(&(auth_rlm->is_active),0);

  	if( disable_rlm_cfg ){

  		err = rhp_auth_realm_disabled_put(rlm_id);
  		if( err ){
  			RHP_BUG("");
  			goto error;
  		}

  		auth_rlm->just_updated = 1;
  	}

  }else if( !disable_rlm_cfg &&
  					rhp_auth_realm_disabled_exists(rlm_id) ){

  	rhp_auth_realm_disabled_delete(rlm_id);

  }else{

  	err = 0;
  	RHP_TRC(0,RHPTRCID_SYSPXY_UI_DELETE_REALM_NOT_FOUND,"xxxxdu",cfg_sub_dt,cfg_sub_dt_rep,writer,n,*n,rlm_id);
  	goto error;
  }

  {
		cfg_doc = xmlParseFile(rhp_syspxy_auth_conf_path);
		if( cfg_doc == NULL ){
			RHP_BUG(" %s ",rhp_syspxy_auth_conf_path);
			err = -ENOENT;
			goto error;
		}

		cfg_root_node = xmlDocGetRootElement(cfg_doc);
		if( cfg_root_node == NULL ){
			RHP_BUG(" %s ",rhp_syspxy_auth_conf_path);
			err = -ENOENT;
			goto error;
		}

	  err = rhp_xml_enum_tags(cfg_root_node,(xmlChar*)"vpn_realm",
	  			(disable_rlm_cfg ? _rhp_syspxy_ui_disable_realm_cb : _rhp_syspxy_ui_delete_realm_unlink_node),
	  			(void*)rlm_id,1);
	  if( err == RHP_STATUS_ENUM_OK || err == -ENOENT ){
	  	err = 0;
	  }else if( err ){
	  	RHP_TRC(0,RHPTRCID_SYSPXY_UI_DELETE_REALM_ENUM_NODE_ERR,"xuE",cfg_sub_dt,rlm_id,err);
	  	goto error;
	  }

		err = rhp_cfg_save_config(rhp_syspxy_auth_conf_path,cfg_doc);
		if( err ){
			RHP_BUG("%d",err);
		}
  }

  if( cfg_doc ){
	  xmlFreeDoc(cfg_doc);
  }

  if( auth_rlm ){
  	rhp_auth_realm_unhold(auth_rlm);
	}

	RHP_LOG_I(RHP_LOG_SRC_UI,0,RHP_LOG_ID_SYSPXY_DELETE_REALM,"u",rlm_id);

	RHP_TRC(0,RHPTRCID_SYSPXY_UI_DELETE_REALM_RTRN,"xxxxdu",cfg_sub_dt,cfg_sub_dt_rep,writer,n,*n,rlm_id);
  return 0;

error:
	RHP_LOG_E(RHP_LOG_SRC_UI,0,RHP_LOG_ID_SYSPXY_DELETE_REALM_ERR,"uE",rlm_id,err);
	if( auth_rlm ){
		rhp_auth_realm_unhold(auth_rlm);
	}
	if( cfg_doc ){
		xmlFreeDoc(cfg_doc);
	}

	RHP_TRC(0,RHPTRCID_SYSPXY_UI_DELETE_REALM_ERR,"xxxxdu",cfg_sub_dt,cfg_sub_dt_rep,writer,n,*n,rlm_id,err);
	return err;
}


struct _rhp_ui_update_enum_ctx {

	rhp_vpn_auth_realm* new_auth_rlm;
	xmlNodePtr upd_realm_node;
	unsigned long rlm_id;

	xmlDocPtr cfg_doc;
	xmlNodePtr cfg_root_node;

	unsigned long opr_user_rlm_id;
	xmlNodePtr new_realm_child_node;
};
typedef struct _rhp_ui_update_enum_ctx	rhp_ui_update_enum_ctx;


static int _rhp_syspxy_ui_update_cleanup_unintereseted(xmlNodePtr upd_realm_child_node,void* ctx)
{
  rhp_ui_update_enum_ctx* enum_ctx = (rhp_ui_update_enum_ctx*)ctx;

	if( (enum_ctx->opr_user_rlm_id != 0 && !xmlStrcmp(upd_realm_child_node->name,(xmlChar*)"roles") ) ||
			(enum_ctx->opr_user_rlm_id != 0 && !xmlStrcmp(upd_realm_child_node->name,(xmlChar*)"eap_server") ) ||
			(xmlStrcmp(upd_realm_child_node->name,(xmlChar*)"roles") &&
			 xmlStrcmp(upd_realm_child_node->name,(xmlChar*)"eap") &&
			 xmlStrcmp(upd_realm_child_node->name,(xmlChar*)"eap_server") &&
			 xmlStrcmp(upd_realm_child_node->name,(xmlChar*)"xauth") &&
			 xmlStrcmp(upd_realm_child_node->name,(xmlChar*)"cert_store") &&
			 xmlStrcmp(upd_realm_child_node->name,(xmlChar*)"auth_method_for_peers")) ){

		RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_CLEANUP_UNINTERESTED,"xs",upd_realm_child_node,upd_realm_child_node->name);

		xmlUnlinkNode(upd_realm_child_node);
		xmlFreeNode(upd_realm_child_node);
	}
	return 0;
}

static int _rhp_syspxy_ui_update_merge_realm_node(xmlNodePtr old_realm_child_node,void* ctx)
{
	int err = -EINVAL;
	xmlNodePtr dup_node = NULL;
  rhp_ui_update_enum_ctx* enum_ctx = (rhp_ui_update_enum_ctx*)ctx;
	xmlNodePtr new_realm_child_node = enum_ctx->new_realm_child_node;

	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_MERGE_REALM_NODE,"xsxs",old_realm_child_node,old_realm_child_node->name,new_realm_child_node,new_realm_child_node->name);

	if( (enum_ctx->opr_user_rlm_id != 0 && !xmlStrcmp(old_realm_child_node->name,(xmlChar*)"roles") ) ||
			(enum_ctx->opr_user_rlm_id != 0 && !xmlStrcmp(old_realm_child_node->name,(xmlChar*)"eap_server") ) ||
			(xmlStrcmp(old_realm_child_node->name,(xmlChar*)"roles") &&
			 xmlStrcmp(old_realm_child_node->name,(xmlChar*)"eap") &&
			 xmlStrcmp(old_realm_child_node->name,(xmlChar*)"xauth") &&
			 xmlStrcmp(old_realm_child_node->name,(xmlChar*)"eap_server") &&
			 xmlStrcmp(old_realm_child_node->name,(xmlChar*)"cert_store") &&
			 xmlStrcmp(old_realm_child_node->name,(xmlChar*)"auth_method_for_peers")) ){

		dup_node = xmlCopyNode(old_realm_child_node,1);
		if( dup_node == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		if( xmlAddChild(new_realm_child_node,dup_node) == NULL ){
			err = -EINVAL;
			RHP_BUG("");
			goto error;
		}

		RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_MERGE_REALM_NODE_ADD_CHILD,"xsxsss",old_realm_child_node,old_realm_child_node->name,new_realm_child_node,new_realm_child_node->name,new_realm_child_node->name,dup_node->name);
	}

	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_MERGE_REALM_NODE_RTRN,"xsxs",old_realm_child_node,old_realm_child_node->name,new_realm_child_node,new_realm_child_node->name);
	return 0;

error:
	if( dup_node ){
		xmlFreeNode(dup_node);
	}
	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_MERGE_REALM_NODE_ERR,"xsxsE",old_realm_child_node,old_realm_child_node->name,new_realm_child_node,new_realm_child_node->name,err);
	return err;
}

static int _rhp_syspxy_ui_update_parse_realm(xmlNodePtr upd_realm_node,void* ctx)
{
	int err = -EINVAL;
  rhp_vpn_auth_realm* new_auth_rlm = NULL;
  rhp_ui_update_enum_ctx* enum_ctx = (rhp_ui_update_enum_ctx*)ctx;
	xmlDocPtr cfg_doc = NULL;
	xmlNodePtr cfg_root_node = NULL;
	xmlNodePtr cfg_rlm_node = NULL;
	xmlChar* realm_id_str = NULL;

	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_PARSE_REALM,"xx",upd_realm_node,ctx);

	realm_id_str = rhp_xml_get_prop(upd_realm_node,(const xmlChar*)"id");
	if( realm_id_str == NULL ){
		RHP_BUG("");
		goto error;
	}

	{
		cfg_doc = xmlParseFile(rhp_syspxy_auth_conf_path);
		if( cfg_doc == NULL ){
			RHP_BUG(" %s ",rhp_syspxy_auth_conf_path);
			goto error;
		}

		cfg_root_node = xmlDocGetRootElement(cfg_doc);
		if( cfg_root_node == NULL ){
			RHP_BUG(" %s ",rhp_syspxy_auth_conf_path);
			goto error;
		}
	}

	rhp_xml_doc_dump("_rhp_syspxy_ui_update_parse_realm.cfg_doc B4",cfg_doc);

  enum_ctx->upd_realm_node = upd_realm_node;

  cfg_rlm_node = rhp_xml_search_prop_value_in_children(cfg_root_node,(xmlChar*)"vpn_realm",(xmlChar*)"id",realm_id_str);
  if( cfg_rlm_node == NULL ){
		RHP_BUG("");
		goto error;
  }


	err = rhp_xml_enum_tags(upd_realm_node,NULL,_rhp_syspxy_ui_update_cleanup_unintereseted,(void*)enum_ctx,1);
	if( err == -ENOENT ){

		RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_PARSE_REALM_CLENUP_ERR,"xs",upd_realm_node,upd_realm_node->name);
  	err = 0;

  }else if( err ){
  	RHP_BUG("%d",err);
  	goto error;
  }


	enum_ctx->new_realm_child_node = upd_realm_node;

	err = rhp_xml_enum_tags(cfg_rlm_node,NULL,_rhp_syspxy_ui_update_merge_realm_node,enum_ctx,1);
  if( err == -ENOENT ){

		RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_PARSE_REALM_MERGE_ERR,"xsxs",cfg_rlm_node,cfg_rlm_node->name,upd_realm_node,upd_realm_node->name);
  	err = 0;

  }else if( err ){
  	RHP_BUG("%d",err);
  	goto error;
  }

	rhp_xml_doc_dump("_rhp_syspxy_ui_update_parse_realm.cfg_doc AFTR",cfg_doc);


  new_auth_rlm =  rhp_auth_parse_auth_realm(upd_realm_node);
  if( new_auth_rlm == NULL ){
  	RHP_BUG("");
    err = -EINVAL;
  	goto error;
  }
  rhp_auth_realm_hold(new_auth_rlm);

  rhp_cfg_trc_dump_auth_realm(new_auth_rlm);

	if( new_auth_rlm->disabled ){
  	RHP_BUG("%d",new_auth_rlm->id);
    err = RHP_STATUS_INVALID_MSG;
  	goto error;
	}

  if( new_auth_rlm->id != enum_ctx->rlm_id ){
  	RHP_BUG("%d, %d",new_auth_rlm->id,enum_ctx->rlm_id);
    err = RHP_STATUS_INVALID_MSG;
  	goto error;
  }

  _rhp_atomic_set(&(new_auth_rlm->is_active),1);

  enum_ctx->new_auth_rlm = new_auth_rlm;
	rhp_auth_realm_hold(new_auth_rlm);

	enum_ctx->cfg_doc = cfg_doc;
	enum_ctx->cfg_root_node = cfg_root_node;

	rhp_auth_realm_unhold(new_auth_rlm);

	if( realm_id_str ){
		_rhp_free(realm_id_str);
	}

	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_PARSE_REALM_RTRN,"xx",upd_realm_node,ctx);
	return 0;

error:
	if( new_auth_rlm ){
		rhp_auth_realm_unhold(new_auth_rlm);
	}
	if( cfg_doc ){
		xmlFreeDoc(cfg_doc);
	}
  enum_ctx->upd_realm_node = NULL;

  if( realm_id_str ){
		_rhp_free(realm_id_str);
	}

	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_PARSE_REALM_ERR,"xxE",upd_realm_node,ctx,err);
  return err;
}

static int _rhp_syspxy_ui_update_realm_update_node(xmlNodePtr realm_node,void* ctx)
{
	int err = -EINVAL;
	rhp_ui_update_enum_ctx* enum_ctx = (rhp_ui_update_enum_ctx*)ctx;
  xmlNodePtr dup_node = NULL;
	unsigned long elm_rlm_id;
	int ret_len;

	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_REALM_UPDATE_NODE,"xx",realm_node,ctx);

  err = rhp_xml_str2val(rhp_xml_get_prop_static(realm_node,(const xmlChar*)"id"),RHP_XML_DT_ULONG,&elm_rlm_id,&ret_len,NULL,0);
  if( !err ){

  	if( enum_ctx->rlm_id == elm_rlm_id ){

  	  if( enum_ctx->cfg_root_node ){

  	  	dup_node = xmlCopyNode(enum_ctx->upd_realm_node,1);
  			if( dup_node ){

  				if( xmlAddChild(enum_ctx->cfg_root_node,dup_node) == NULL ){
  			  	RHP_BUG("%d",enum_ctx->rlm_id);
  				}

  			}else{
  		  	RHP_BUG("%d",enum_ctx->rlm_id);
  			}
  	  }

  		xmlUnlinkNode(realm_node);
  		xmlFreeNode(realm_node);

  		RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_REALM_UPDATE_NODE_ENUM_OK_RTRN,"xx",realm_node,ctx);
  		return RHP_STATUS_ENUM_OK;
  	}

  }else{
  	RHP_BUG("%d",enum_ctx->rlm_id);
  }

	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_REALM_UPDATE_NODE_RTRN,"xx",realm_node,ctx);
  return 0;
}


static int _rhp_syspxy_ui_update_realm(rhp_ipcmsg_syspxy_cfg_sub* cfg_sub_dt,
		rhp_ipcmsg_syspxy_cfg_sub* cfg_sub_dt_rep,xmlTextWriterPtr writer,int* n,
		int opr_user_rlm_id)
{
	int err = -EINVAL;
	unsigned long rlm_id = cfg_sub_dt->target_rlm_id;
	xmlDocPtr cfg_doc = NULL;
	xmlNodePtr cfg_root_node = NULL;
  xmlDocPtr upd_auth_doc = NULL;
  xmlNodePtr upd_auth_root_node = NULL;
	rhp_ui_update_enum_ctx enum_ctx;
	rhp_vpn_auth_realm *old_auth_rlm = NULL,*new_auth_rlm = NULL;

	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_REALM,"xxxxduu",cfg_sub_dt,cfg_sub_dt_rep,writer,n,*n,rlm_id,opr_user_rlm_id);

	memset(&enum_ctx,0,sizeof(rhp_ui_update_enum_ctx));

  if( rlm_id == 0 || rlm_id > RHP_VPN_REALM_ID_MAX ){
  	err = -EPERM;
  	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_REALM_NOT_PERMITTED,"xu",cfg_sub_dt,rlm_id);
		goto error;
  }

  if( cfg_sub_dt->len <= sizeof(rhp_ipcmsg_syspxy_cfg_sub) ){
  	err = -EINVAL;
  	RHP_BUG("");
  	goto error;
  }

  {
  	upd_auth_doc = xmlParseMemory((void*)(cfg_sub_dt + 1),(cfg_sub_dt->len - sizeof(rhp_ipcmsg_syspxy_cfg_sub)));
  	if( upd_auth_doc == NULL ){
  		err = -EINVAL;
  		RHP_BUG("");
  		goto error;
  	}

  	upd_auth_root_node = xmlDocGetRootElement(upd_auth_doc);
  	if( upd_auth_root_node == NULL ){
  		err = -EINVAL;
  		RHP_BUG("");
  		goto error;
  	}
  }

  enum_ctx.rlm_id = rlm_id;
  enum_ctx.opr_user_rlm_id = opr_user_rlm_id;

	err = rhp_xml_enum_tags(upd_auth_root_node,
			(xmlChar*)"vpn_realm",_rhp_syspxy_ui_update_parse_realm,&enum_ctx,0);

	if( err == -EINVAL || err == -ENOENT || (enum_ctx.new_auth_rlm == NULL) ){
  	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_REALM_INVALID_MESG,"xuE",cfg_sub_dt,rlm_id,err);
  	err = RHP_STATUS_INVALID_MSG;
  	goto error;
  }else if( err ){
  	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_REALM_PARSE_ERR,"xuE",cfg_sub_dt,rlm_id,err);
  	goto error;
  }

	cfg_doc = enum_ctx.cfg_doc;
	cfg_root_node = enum_ctx.cfg_root_node;

  new_auth_rlm = enum_ctx.new_auth_rlm;


  old_auth_rlm = rhp_auth_realm_delete_by_id(rlm_id);
  if( old_auth_rlm == NULL ){
  	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_REALM_NOT_FOUND,"xu",cfg_sub_dt,rlm_id);
		err = -ENOENT;
		goto error;
  }

  _rhp_atomic_set(&(old_auth_rlm->is_active),0);
  old_auth_rlm->just_updated = 1;


  if( new_auth_rlm->my_auth ){

  	if( old_auth_rlm->my_auth ){

  		if( new_auth_rlm->my_auth->cert_store == NULL && old_auth_rlm->my_auth->cert_store ){

  			new_auth_rlm->my_auth->cert_store = old_auth_rlm->my_auth->cert_store;
  			old_auth_rlm->my_auth->cert_store = NULL;

  		}else if( new_auth_rlm->my_auth->cert_store_tmp == NULL && old_auth_rlm->my_auth->cert_store_tmp ){

  			new_auth_rlm->my_auth->cert_store_tmp = old_auth_rlm->my_auth->cert_store_tmp;
  			old_auth_rlm->my_auth->cert_store_tmp = NULL;
  		}

  		if( new_auth_rlm->my_cert_store_password == NULL ){
  			new_auth_rlm->my_cert_store_password = old_auth_rlm->my_cert_store_password;
  			old_auth_rlm->my_cert_store_password = NULL;
  		}
  	}

  }else{

  	new_auth_rlm->my_auth = old_auth_rlm->my_auth;
  	old_auth_rlm->my_auth = NULL;
  }


  err = rhp_auth_realm_put(new_auth_rlm);
  if( err ){
  	RHP_BUG("%d",rlm_id);
  	goto error;
  }

  {
	  err = rhp_xml_enum_tags(cfg_root_node,(xmlChar*)"vpn_realm",
	  		_rhp_syspxy_ui_update_realm_update_node,&enum_ctx,1);

	  if( err == RHP_STATUS_ENUM_OK || err == -ENOENT ){
	  	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_REALM_ENUM2_OK,"xuE",cfg_sub_dt,rlm_id,err);
	  	err = 0;
	  }else if( err ){
	  	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_REALM_ENUM2_ERR,"xuE",cfg_sub_dt,rlm_id,err);
	  	goto error;
	  }

		err = rhp_cfg_save_config(rhp_syspxy_auth_conf_path,cfg_doc);
		if( err ){
			RHP_BUG("%d",err);
		}
  }

  if( new_auth_rlm->my_auth == NULL ){

  	RHP_LOG_N(RHP_LOG_SRC_AUTHCFG,rlm_id,RHP_LOG_ID_NO_MY_AUTH_INFO,"u",rlm_id);

  }else if( new_auth_rlm->my_auth->auth_method ==  RHP_PROTO_IKE_AUTHMETHOD_SHARED_KEY &&
  					new_auth_rlm->my_auth->my_psks == NULL ){

  	RHP_LOG_N(RHP_LOG_SRC_AUTHCFG,rlm_id,RHP_LOG_ID_NO_MY_PSK,"u",rlm_id);

  }else if( new_auth_rlm->my_auth->auth_method ==  RHP_PROTO_IKE_AUTHMETHOD_RSA_SIG &&
  					new_auth_rlm->my_auth->cert_store == NULL ){

  	RHP_LOG_N(RHP_LOG_SRC_AUTHCFG,rlm_id,RHP_LOG_ID_NO_MY_CERT,"u",rlm_id);
  }

  {
  	int peer_idx = 0;
  	rhp_auth_peer* peer = new_auth_rlm->peers;

  	while( peer ){
  		if( peer->peer_psks ){
  			peer_idx = 1;
  			break;
  		}
  		peer = peer->next;
  	}

  	if( peer_idx == 0 &&
  			( new_auth_rlm->my_auth == NULL || new_auth_rlm->my_auth->cert_store == NULL) ){
  		RHP_LOG_N(RHP_LOG_SRC_AUTHCFG,rlm_id,RHP_LOG_ID_NO_PEER_AUTH_INFO,"u",rlm_id);
  	}
  }

	if( cfg_doc ){
		xmlFreeDoc(cfg_doc);
	}

  if( upd_auth_doc ){
	  xmlFreeDoc(upd_auth_doc);
  }

	RHP_LOG_I(RHP_LOG_SRC_UI,rlm_id,RHP_LOG_ID_SYSPXY_UPDATE_REALM,"u",rlm_id);

	if( old_auth_rlm ){
		rhp_auth_realm_unhold(old_auth_rlm);
	}

	rhp_auth_realm_unhold(new_auth_rlm);

	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_REALM_RTRN,"xxxxdu",cfg_sub_dt,cfg_sub_dt_rep,writer,n,*n,rlm_id);
  return 0;

error:
	RHP_LOG_E(RHP_LOG_SRC_UI,rlm_id,RHP_LOG_ID_SYSPXY_UPDATE_REALM_ERR,"uE",rlm_id,err);
	if( cfg_doc ){
		xmlFreeDoc(cfg_doc);
	}
	if( upd_auth_doc ){
		xmlFreeDoc(upd_auth_doc);
	}
	if( new_auth_rlm ){
		rhp_auth_realm_unhold(new_auth_rlm);
	}
	if( old_auth_rlm ){
		rhp_auth_realm_unhold(old_auth_rlm);
	}
	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_REALM_ERR,"xxxxduE",cfg_sub_dt,cfg_sub_dt_rep,writer,n,*n,rlm_id,err);
  return err;
}


struct _rhp_ui_key_info_enum_ctx {

	rhp_my_auth* new_my_auth;
  rhp_auth_peer* new_auth_peer;

  unsigned long rlm_id;
	xmlNodePtr new_node;

	xmlDocPtr cfg_doc;
	xmlNodePtr cfg_root_node;
	xmlNodePtr peer_auth_node;
	int my_key_dup;

	int accept_expired_cert;
};
typedef struct _rhp_ui_key_info_enum_ctx		rhp_ui_key_info_enum_ctx;

#define RHP_UI_KEY_UPD_ACTION_NOP			0
#define RHP_UI_KEY_UPD_ACTION_UPDATE	1
#define RHP_UI_KEY_UPD_ACTION_DELETE	2


#define RHP_SYSPXY_CFG_TRANS_ID_NUM		5
static int _ikev2_ui_psk_prf_method[RHP_SYSPXY_CFG_TRANS_ID_NUM] = {
		RHP_PROTO_IKE_TRANSFORM_ID_PRF_HMAC_MD5,
		RHP_PROTO_IKE_TRANSFORM_ID_PRF_HMAC_SHA1,
		RHP_PROTO_IKE_TRANSFORM_ID_PRF_HMAC_SHA2_256,
		RHP_PROTO_IKE_TRANSFORM_ID_PRF_HMAC_SHA2_384,
		RHP_PROTO_IKE_TRANSFORM_ID_PRF_HMAC_SHA2_512
};
static char* _ikev2_ui_psk_prf_method_str[RHP_SYSPXY_CFG_TRANS_ID_NUM] = {
		"hmac-md5",
		"hmac-sha1",
		"hmac-sha2-256",
		"hmac-sha2-384",
		"hmac-sha2-512"
};


static int  _rhp_syspxy_ui_update_key_info_setup_node(xmlNodePtr new_my_auth_child_node,void* ctx)
{
	int err = -EINVAL;
	rhp_ui_key_info_enum_ctx* enum_ctx = (rhp_ui_key_info_enum_ctx*)ctx;
  rhp_crypto_prf* prf = NULL;
  u8* hashed_key = NULL;
  int hashed_key_len = 0;
  unsigned char* res_text = NULL;
  xmlNodePtr new_node = NULL;
	xmlChar* key = NULL;

	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_KEY_INFO_SETUP_NODE,"xsx",new_my_auth_child_node,new_my_auth_child_node->name,enum_ctx);

	if( !xmlStrcmp(new_my_auth_child_node->name,(xmlChar*)"my_psk") ||
			!xmlStrcmp(new_my_auth_child_node->name,(xmlChar*)"peer_psk") ){

	  int i;

		if( enum_ctx->my_key_dup > 1 ){
			err = -EINVAL;
			RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_KEY_INFO_SETUP_NODE_DUP_ERR,"xsxd",new_my_auth_child_node,new_my_auth_child_node->name,enum_ctx,enum_ctx->my_key_dup);
			goto error;
		}

		key = rhp_xml_get_prop(new_my_auth_child_node,(xmlChar*)"key");
		if( key == NULL ){

			key = rhp_xml_get_prop(new_my_auth_child_node,(xmlChar*)"mschapv2_key");
			if( key == NULL ){
				err = -EINVAL;
				goto error;
			}

			goto ignore;
		}

		if( xmlStrlen(key) < 1 ){
			err = -EINVAL;
			goto error;
		}

	  for( i = 0; i < RHP_SYSPXY_CFG_TRANS_ID_NUM; i++ ){

	  	prf  = rhp_crypto_prf_alloc(_ikev2_ui_psk_prf_method[i]);
	  	if( prf == NULL ){
	  		RHP_BUG("");
	  		err = -EINVAL;
	  		goto error;
	  	}

	  	hashed_key_len = prf->get_output_len(prf);

	  	hashed_key = (u8*)_rhp_malloc(hashed_key_len);
	  	if( hashed_key == NULL ){
	  		RHP_BUG("");
	  		err = -ENOMEM;
	  		goto error;
	  	}

	  	if( prf->set_key(prf,(unsigned char*)key,strlen((char*)key)) ){
	  		RHP_BUG("");
	  		err = -EINVAL;
	  		goto error;
	  	}

	  	if( prf->compute(prf,(unsigned char*)RHP_PROTO_IKE_AUTH_KEYPAD,strlen(RHP_PROTO_IKE_AUTH_KEYPAD),
        hashed_key,hashed_key_len) ){
	  		RHP_BUG("");
	  		err = -EINVAL;
	  		goto error;
	  	}

	  	err = rhp_base64_encode(hashed_key,hashed_key_len,&res_text);
	  	if( err ){
	  		RHP_BUG("%d",err);
	  		goto error;
	  	}

	  	new_node = xmlNewNode(NULL,new_my_auth_child_node->name);
	  	if( new_node == NULL ){
	  		err = -ENOMEM;
	  		RHP_BUG("");
	  		goto error;
	  	}


			if( xmlNewProp(new_node,(xmlChar*)"prf_method",(xmlChar*)_ikev2_ui_psk_prf_method_str[i]) == NULL ){
				RHP_BUG("");
				err = -ENOMEM;
				goto error;
			}

			if( xmlNewProp(new_node,(xmlChar*)"hashed_key",(xmlChar*)res_text) == NULL ){
				RHP_BUG("");
				err = -ENOMEM;
				goto error;
			}

			if( xmlAddChild(new_my_auth_child_node->parent,new_node) == NULL ){
		  	RHP_BUG("");
			}

			RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_KEY_INFO_SETUP_NODE_ADD_CHILD,"xsxss",new_my_auth_child_node,new_my_auth_child_node->name,enum_ctx,new_my_auth_child_node->parent->name,new_node->name);

			new_node = NULL;

  		rhp_crypto_prf_free(prf);
  		prf = NULL;

  		_rhp_free(hashed_key);
  		hashed_key = NULL;

  		_rhp_free(res_text);
  		res_text = NULL;
	  }

		enum_ctx->my_key_dup++;
	}

	if( !rhp_gcfg_ikev1_enabled ){
		xmlUnlinkNode(new_my_auth_child_node);
		xmlFreeNode(new_my_auth_child_node);
	}

ignore:
	if( key ){
		_rhp_free_zero(key,xmlStrlen(key));
	}

	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_KEY_INFO_SETUP_NODE_RTRN,"xx",new_my_auth_child_node,enum_ctx);
	return 0;

error:
	if( prf ){
		rhp_crypto_prf_free(prf);
	}
	if( new_node ){
		xmlFreeNode(new_node);
	}
	if( hashed_key ){
		_rhp_free(hashed_key);
	}
	if( res_text ){
		_rhp_free(res_text);
	}
	if( key ){
		_rhp_free_zero(key,xmlStrlen(key));
	}

	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_KEY_INFO_SETUP_NODE_ERR,"xxE",new_my_auth_child_node,enum_ctx,err);
	return err;
}

static int  _rhp_syspxy_ui_update_key_info_merge_node(xmlNodePtr old_my_auth_child_node,void* ctx)
{
	int err = -EINVAL;
	xmlNodePtr dup_node = NULL;
	xmlNodePtr new_my_auth_node = (xmlNodePtr)ctx;
	int key_upd_action = RHP_UI_KEY_UPD_ACTION_NOP;
	xmlChar* key_upd_action_str = NULL;

	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_KEY_INFO_MERGE_NODE,"xsxs",old_my_auth_child_node,old_my_auth_child_node->name,new_my_auth_node,new_my_auth_node->name);

	{
		key_upd_action_str = rhp_xml_get_prop_static(new_my_auth_node,(xmlChar*)"key_update_action");

		if( key_upd_action_str ){
			if( !xmlStrcmp(key_upd_action_str,(xmlChar*)"update") ){
				key_upd_action = RHP_UI_KEY_UPD_ACTION_UPDATE;
			}else if( !xmlStrcmp(key_upd_action_str,(xmlChar*)"delete") ){
				key_upd_action = RHP_UI_KEY_UPD_ACTION_DELETE;
			}
		}
	}

	if( ( xmlStrcmp(old_my_auth_child_node->name,(xmlChar*)"my_psk") &&
			  xmlStrcmp(old_my_auth_child_node->name,(xmlChar*)"peer_psk")) ||
			( !xmlStrcmp(old_my_auth_child_node->name,(xmlChar*)"my_psk") &&
				(key_upd_action_str && key_upd_action == RHP_UI_KEY_UPD_ACTION_NOP) ) ){

		dup_node = xmlCopyNode(old_my_auth_child_node,1);
		if( dup_node == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		if( xmlAddChild(new_my_auth_node,dup_node) == NULL ){
			err = -EINVAL;
			RHP_BUG("");
			goto error;
		}

		RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_KEY_INFO_MERGE_NODE_ADD_CHILD,"xsxsss",old_my_auth_child_node,old_my_auth_child_node->name,new_my_auth_node,new_my_auth_node->name,new_my_auth_node->name,dup_node->name);
	}

	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_KEY_INFO_MERGE_NODE_RTRN,"xsxs",old_my_auth_child_node,old_my_auth_child_node->name,new_my_auth_node,new_my_auth_node->name);
	return 0;

error:
	if( dup_node ){
		xmlFreeNode(dup_node);
	}

	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_KEY_INFO_MERGE_NODE_ERR,"xsxs",old_my_auth_child_node,old_my_auth_child_node->name,new_my_auth_node,new_my_auth_node->name);
	return err;
}

static int _rhp_syspxy_ui_update_my_key_info_parse(xmlNodePtr upd_my_auth_node,rhp_ui_key_info_enum_ctx* enum_ctx)
{
	int err = -EINVAL;
	xmlDocPtr cfg_doc = NULL;
	xmlNodePtr cfg_root_node = NULL;
	xmlNodePtr cfg_rlm_node = NULL;
	xmlNodePtr my_auth_node = NULL;
  rhp_my_auth* my_auth = NULL;
  char realm_id_str[64];

	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_MY_KEY_INFO_PARSE,"xsx",upd_my_auth_node,upd_my_auth_node->name,enum_ctx);

  realm_id_str[0] = '\0';
  snprintf(realm_id_str,64,"%lu",enum_ctx->rlm_id);

	{
		cfg_doc = xmlParseFile(rhp_syspxy_auth_conf_path);
		if( cfg_doc == NULL ){
			RHP_BUG(" %s ",rhp_syspxy_auth_conf_path);
			goto error;
		}

		cfg_root_node = xmlDocGetRootElement(cfg_doc);
		if( cfg_root_node == NULL ){
			RHP_BUG(" %s ",rhp_syspxy_auth_conf_path);
			goto error;
		}
	}

  cfg_rlm_node = rhp_xml_search_prop_value_in_children(cfg_root_node,
  		(xmlChar*)"vpn_realm",(xmlChar*)"id",(xmlChar*)realm_id_str);

  if( cfg_rlm_node == NULL ){
		RHP_BUG("");
		goto error;
  }

  my_auth_node = rhp_xml_get_child(cfg_rlm_node,(xmlChar*)"my_auth");


  enum_ctx->my_key_dup = 0;

	err = rhp_xml_enum_tags(upd_my_auth_node,NULL,_rhp_syspxy_ui_update_key_info_setup_node,enum_ctx,1);
  if( err == -ENOENT ){
  	err = 0;
  	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_MY_KEY_INFO_PARSE_ENUM_NOT_FOUND,"xsx",upd_my_auth_node,upd_my_auth_node->name,enum_ctx);
  }else if( err ){
  	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_MY_KEY_INFO_PARSE_ENUM_ERR,"xsxE",upd_my_auth_node,upd_my_auth_node->name,enum_ctx,err);
  	goto error;
  }


	if( my_auth_node ){

  	err = rhp_xml_enum_tags(my_auth_node,NULL,_rhp_syspxy_ui_update_key_info_merge_node,upd_my_auth_node,1);
  	if( err == -ENOENT ){
    	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_MY_KEY_INFO_PARSE_ENUM2_NOT_FOUND,"xsx",upd_my_auth_node,upd_my_auth_node->name,enum_ctx);
  		err = 0;
  	}else if( err ){
    	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_MY_KEY_INFO_PARSE_ENUM2_ERR,"xsxE",upd_my_auth_node,upd_my_auth_node->name,enum_ctx,err);
  		goto error;
  	}
  }


  my_auth = rhp_auth_parse_auth_my_auth(upd_my_auth_node,enum_ctx->rlm_id);
  if( my_auth == NULL ){
  	RHP_BUG("");
  	goto error;
  }

  rhp_xml_check_enable(upd_my_auth_node,(xmlChar*)"accept_expired_cert",&(enum_ctx->accept_expired_cert));

  enum_ctx->new_my_auth = my_auth;
  enum_ctx->new_node = upd_my_auth_node;
	enum_ctx->cfg_doc = cfg_doc;
	enum_ctx->cfg_root_node = cfg_root_node;

	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_MY_KEY_INFO_PARSE_RTRN,"xsx",upd_my_auth_node,upd_my_auth_node->name,enum_ctx);
	return 0;

error:
	if( my_auth ){
		rhp_auth_free_my_auth(my_auth);
	}
	if( cfg_doc ){
		xmlFreeDoc(cfg_doc);
	}
	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_MY_KEY_INFO_PARSE_ERR,"xsx",upd_my_auth_node,upd_my_auth_node->name,enum_ctx,err);
  return err;
}

static int _rhp_syspxy_ui_update_my_key_info_my_auth_node(xmlNodePtr my_auth,void* ctx)
{
	rhp_ui_key_info_enum_ctx* enum_ctx = (rhp_ui_key_info_enum_ctx*)ctx;
  xmlNodePtr dup_node = NULL;

	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_MY_KEY_INFO_MY_AUTH_NODE,"xsx",my_auth,my_auth->name,enum_ctx);

	dup_node = xmlCopyNode(enum_ctx->new_node,1);
	if( dup_node ){

		if( xmlAddChild(my_auth->parent,dup_node) == NULL ){
	  	RHP_BUG("%d",enum_ctx->rlm_id);
		}

		RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_MY_KEY_INFO_MY_AUTH_NODE_ADD_CHILD,"xsxss",my_auth,my_auth->name,enum_ctx,my_auth->parent->name,dup_node->name);

		xmlUnlinkNode(my_auth);
		xmlFreeNode(my_auth);

	}else{
  	RHP_BUG("%d",enum_ctx->rlm_id);
	}

	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_MY_KEY_INFO_MY_AUTH_NODE_RTRN,"xsx",my_auth,my_auth->name,enum_ctx);
	return RHP_STATUS_ENUM_OK;
}

static int _rhp_syspxy_ui_update_my_key_info_node(xmlNodePtr realm_node,void* ctx)
{
	int err = -EINVAL;
	rhp_ui_key_info_enum_ctx* enum_ctx = (rhp_ui_key_info_enum_ctx*)ctx;
	unsigned long elm_rlm_id;
	int ret_len;

	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_MY_KEY_INFO_NODE,"xsx",realm_node,realm_node->name,enum_ctx);

  err = rhp_xml_str2val(rhp_xml_get_prop_static(realm_node,(const xmlChar*)"id"),RHP_XML_DT_ULONG,&elm_rlm_id,&ret_len,NULL,0);
  if( !err ){

  	if( enum_ctx->rlm_id == elm_rlm_id ){

  		err = rhp_xml_enum_tags(realm_node,(xmlChar*)"my_auth",_rhp_syspxy_ui_update_my_key_info_my_auth_node,enum_ctx,0);

  		if( err == -ENOENT ){

  		  xmlNodePtr dup_node = NULL;

  			dup_node = xmlCopyNode(enum_ctx->new_node,1);
  			if( dup_node ){

  				if( xmlAddChild(realm_node,dup_node) == NULL ){
  			  	RHP_BUG("%d",enum_ctx->rlm_id);
  				}

  				RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_MY_KEY_INFO_NODE_ADD_CHILD,"xsxssd",realm_node,realm_node->name,enum_ctx,realm_node->name,dup_node->name,elm_rlm_id);

  			}else{
  		  	RHP_BUG("%d",enum_ctx->rlm_id);
  			}

  		}else if( err && err != RHP_STATUS_ENUM_OK ){
  	  	RHP_BUG("%d",err);
  	  	goto error;
  	  }

  		RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_MY_KEY_INFO_NODE_ENUM_OK_RTRN,"xsx",realm_node,realm_node->name,enum_ctx);
  	  return RHP_STATUS_ENUM_OK;
  	}

  }else{
  	RHP_BUG("%d",enum_ctx->rlm_id);
  }

	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_MY_KEY_INFO_NODE_RTRN,"xsx",realm_node,realm_node->name,enum_ctx);
  return 0;

error:
	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_MY_KEY_INFO_NODE_ERR,"xsxE",realm_node,realm_node->name,enum_ctx,err);
	return err;
}

static int _rhp_syspxy_ui_update_my_key_info(rhp_ipcmsg_syspxy_cfg_sub* cfg_sub_dt,
		rhp_vpn_auth_realm *auth_rlm,xmlDocPtr upd_auth_doc,xmlNodePtr upd_auth_root_node)
{
	int err = -EINVAL;
	unsigned long rlm_id = cfg_sub_dt->target_rlm_id;
	xmlDocPtr cfg_doc = NULL;
	xmlNodePtr cfg_root_node = NULL;
  rhp_ui_key_info_enum_ctx enum_ctx;
	rhp_my_auth *new_my_auth = NULL,*old_my_auth = NULL;
  u8* id_value = NULL;
  int id_len = 0;
  int id_type = RHP_PROTO_IKE_ID_PRIVATE_NOT_RESOLVED;
	char* id_type_str = NULL;
	char* id_str = NULL;
	int eap_sup_enabled = 0;
	int eap_sup_ask_for_user_key = 0, eap_sup_method = 0, eap_sup_user_key_cache_enabled = 0;
  int psk_for_peers = 0, rsa_sig_for_peers = 0, eap_for_peers = 0, null_auth_for_peers = 0;
	int auth_method = 0;
	int rsasig_resolve_id = 0;
	int my_auth_method = RHP_PROTO_IKE_AUTHMETHOD_NONE, my_xauth_method = RHP_PROTO_IKE_AUTHMETHOD_NONE;
  u8 *my_cert_issuer_dn_der = NULL, *untrust_sub_ca_cert_issuer_dn_der = NULL;
  int my_cert_issuer_dn_der_len = 0, untrust_sub_ca_cert_issuer_dn_der_len = 0;

	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_MY_KEY_INFO,"xxdxxs",cfg_sub_dt,auth_rlm,auth_rlm->id,upd_auth_doc,upd_auth_root_node,upd_auth_root_node->name);
	rhp_xml_doc_dump("_rhp_syspxy_ui_update_my_key_info.upd_auth_doc",upd_auth_doc);


	memset(&enum_ctx,0,sizeof(rhp_ui_key_info_enum_ctx));

  enum_ctx.rlm_id = rlm_id;
  enum_ctx.accept_expired_cert = -1;

  err = _rhp_syspxy_ui_update_my_key_info_parse(upd_auth_root_node,&enum_ctx);

  if( err == -EINVAL || err == -ENOENT || (enum_ctx.new_my_auth == NULL) ){

  	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_MY_KEY_INFO_PARSE_ERR,"xxE",cfg_sub_dt,auth_rlm,err);

  	err = RHP_STATUS_INVALID_MSG;
  	goto error;

  }else if( err ){
  	RHP_BUG("");
  	goto error;
  }

	cfg_doc = enum_ctx.cfg_doc;
	cfg_root_node = enum_ctx.cfg_root_node;

  new_my_auth = enum_ctx.new_my_auth;

	rhp_ikev2_id_to_string(&(new_my_auth->my_id),&id_type_str,&id_str);
  auth_method = new_my_auth->auth_method;

  //
  // [CAUTION]
  //  Don't ref eap_sup_enabled here, yet.
  //
  RHP_LOCK(&(auth_rlm->lock));
  {

  	old_my_auth = auth_rlm->my_auth;

  	auth_rlm->my_auth = new_my_auth;
		new_my_auth = NULL;

		if( enum_ctx.accept_expired_cert != -1 ){
			auth_rlm->accept_expired_cert = enum_ctx.accept_expired_cert;
		}

		my_auth_method = auth_rlm->my_auth->auth_method;
		my_xauth_method = auth_rlm->xauth.p1_auth_method;

		if( auth_rlm->my_auth->auth_method != RHP_PROTO_IKE_AUTHMETHOD_NONE ){

			err = rhp_ikev2_id_value(&(auth_rlm->my_auth->my_id),&id_value,&id_len,&id_type);
			if( err == -ENOENT ){

				if( old_my_auth && auth_method == old_my_auth->auth_method ){

					RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_MY_KEY_INFO_GET_OLD_MY_AUTH_ID,"xxuxxd",cfg_sub_dt,auth_rlm,auth_rlm->id,old_my_auth,auth_rlm->my_auth,auth_method);

					err = rhp_ikev2_id_dup(&(auth_rlm->my_auth->my_id),&(old_my_auth->my_id));
					if( err ){
						RHP_BUG("%d",err);
						RHP_UNLOCK(&(auth_rlm->lock));
						goto error;
					}

					err = rhp_ikev2_id_value(&(auth_rlm->my_auth->my_id),&id_value,&id_len,&id_type);
					if( err && err != -ENOENT ){
						RHP_BUG("%d",err);
						RHP_UNLOCK(&(auth_rlm->lock));
						goto error;
					}
				}

				if( err == -ENOENT ){

					RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_MY_KEY_INFO_TRY_RES_CERT_ID,"xxuxdx",cfg_sub_dt,auth_rlm,auth_rlm->id,auth_rlm->my_auth,auth_rlm->my_auth->auth_method,auth_rlm->my_auth->cert_store);

					if( auth_rlm->my_auth->auth_method == RHP_PROTO_IKE_AUTHMETHOD_RSA_SIG ){

						rsasig_resolve_id = 1;
					}
				}

				if( err ){
					RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_MY_KEY_INFO_MY_ID_NOT_RESOLVED,"xxudx",cfg_sub_dt,auth_rlm,auth_rlm->id,auth_rlm->my_auth->auth_method,auth_rlm->my_auth->cert_store);
				}

				err = 0;

			}else if( err ){

				RHP_BUG("%d",err);
				RHP_UNLOCK(&(auth_rlm->lock));
				goto error;
			}

		}else{

			// EAP supplicant (peer)

			if( auth_rlm->my_auth->my_eap_sup_id.method == RHP_PROTO_EAP_TYPE_NONE ){

				err = -EINVAL;

				RHP_BUG("");
				RHP_UNLOCK(&(auth_rlm->lock));
				goto error;
			}


			if( auth_rlm->eap.role != RHP_EAP_SUPPLICANT ){

		  	err = RHP_STATUS_INVALID_MSG;

				RHP_LOG_DE(RHP_LOG_SRC_UI,0,RHP_LOG_ID_UI_UPDATE_MY_KEY_INFO_NOT_EAP_SUP,"u",rlm_id);

		  	RHP_UNLOCK(&(auth_rlm->lock));
		  	goto error;
			}
		}

		if( auth_rlm->my_auth && old_my_auth ){

			if( auth_rlm->my_auth->cert_store == NULL && old_my_auth->cert_store ){

				auth_rlm->my_auth->cert_store = old_my_auth->cert_store;
				old_my_auth->cert_store = NULL;

			}else if( auth_rlm->my_auth->cert_store_tmp == NULL && old_my_auth->cert_store_tmp ){

				auth_rlm->my_auth->cert_store_tmp = old_my_auth->cert_store_tmp;
				old_my_auth->cert_store_tmp = NULL;
			}

			if( rsasig_resolve_id && auth_rlm->my_auth->cert_store ){

				err = rhp_auth_resolve_my_auth_cert_my_id(auth_rlm->my_auth,auth_rlm->my_auth->cert_store);
				if( err == -ENOENT ){

					RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_MY_KEY_INFO_CERT_MY_ID_NOT_FOUND,"xxux",cfg_sub_dt,auth_rlm,auth_rlm->id,auth_rlm->my_auth->cert_store);
					err = 0;

				}else if( err ){

					RHP_BUG("%d",err);
					RHP_UNLOCK(&(auth_rlm->lock));
					goto error;

				}else{

					err = rhp_ikev2_id_value(&(auth_rlm->my_auth->my_id),&id_value,&id_len,&id_type);
					if( err && err != -ENOENT ){
						RHP_BUG("%d",err);
						RHP_UNLOCK(&(auth_rlm->lock));
						goto error;
					}

					err = 0;
				}
			}
		}

	  psk_for_peers = auth_rlm->psk_for_peers;
	  rsa_sig_for_peers = auth_rlm->rsa_sig_for_peers;
	  eap_for_peers = auth_rlm->eap_for_peers;
	  null_auth_for_peers = auth_rlm->null_auth_for_peers;

	  if( auth_rlm->my_auth ){

	  	rhp_ikev2_id_dump("auth_rlm->my_auth->my_id",&(auth_rlm->my_auth->my_id));

	    if( auth_rlm->my_auth->cert_store ){

	    	auth_rlm->my_auth->cert_store->get_my_cert_issuer_dn_der(
	    			auth_rlm->my_auth->cert_store,&untrust_sub_ca_cert_issuer_dn_der,&untrust_sub_ca_cert_issuer_dn_der_len);

	    	auth_rlm->my_auth->cert_store->get_untrust_sub_ca_issuer_dn_der(auth_rlm->my_auth->cert_store,
	    			&untrust_sub_ca_cert_issuer_dn_der,&untrust_sub_ca_cert_issuer_dn_der_len);
	    }
	  }
  }
  RHP_UNLOCK(&(auth_rlm->lock));


	eap_sup_enabled = rhp_auth_sup_is_enabled(rlm_id,
											&eap_sup_method,&eap_sup_ask_for_user_key,
											&eap_sup_user_key_cache_enabled);

  {
	  err = rhp_xml_enum_tags(cfg_root_node,(xmlChar*)"vpn_realm",
	  		_rhp_syspxy_ui_update_my_key_info_node,&enum_ctx,1);

	  if( err == RHP_STATUS_ENUM_OK || err == -ENOENT ){

	  	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_MY_KEY_INFO_UPDATE_MY_KEY_INFO_NODE_ERR,"xxE",cfg_sub_dt,auth_rlm,err);
	  	err = 0;

	  }else if( err ){
	  	goto error;
	  }

		err = rhp_cfg_save_config(rhp_syspxy_auth_conf_path,cfg_doc);
		if( err ){
			RHP_BUG("%d",err);
		}
  }

  if( id_len || rhp_ikev2_is_null_auth_id(id_type) || eap_sup_enabled ){

  	rhp_ipcmsg_resolve_my_id_rep* res_my_id_rep
  		= rhp_auth_ipc_alloc_rslv_my_id_rep(rlm_id,0,1,id_type,id_len,id_value,my_auth_method,my_xauth_method,
  				eap_sup_enabled,eap_sup_ask_for_user_key,eap_sup_method,eap_sup_user_key_cache_enabled,
  				psk_for_peers,rsa_sig_for_peers,eap_for_peers,null_auth_for_peers,
  				my_cert_issuer_dn_der_len,my_cert_issuer_dn_der,
  				untrust_sub_ca_cert_issuer_dn_der_len,untrust_sub_ca_cert_issuer_dn_der);

  	if( res_my_id_rep == NULL ){
			RHP_BUG("");
			goto error;
		}

		if( rhp_ipc_send(RHP_MY_PROCESS,(void*)res_my_id_rep,res_my_id_rep->len,0) < 0 ){
				RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_MY_KEY_INFO_IPC_SEND_ERR,"xxdd",RHP_MY_PROCESS,res_my_id_rep,res_my_id_rep->len,0);
		}
		_rhp_free_zero(res_my_id_rep,res_my_id_rep->len);
  }

  if( id_value ){
  	_rhp_free(id_value);
  }

	if( cfg_doc ){
		xmlFreeDoc(cfg_doc);
	}

	if( old_my_auth ){
		rhp_auth_free_my_auth(old_my_auth);
	}

	if( id_len ){
		RHP_LOG_D(RHP_LOG_SRC_UI,0,RHP_LOG_ID_UI_UPDATE_MY_KEY_INFO,"ussL",rlm_id,id_str,id_type_str,"PROTO_IKE_AUTHMETHOD",auth_method);
	}else if( eap_sup_enabled ){
		RHP_LOG_D(RHP_LOG_SRC_UI,0,RHP_LOG_ID_UI_UPDATE_MY_KEY_INFO_EAP_SUP_ENABLED,"u",rlm_id);
	}

  if( id_str ){
  	_rhp_free(id_str);
  }
  if( id_type_str ){
  	_rhp_free(id_type_str);
  }

  if( my_cert_issuer_dn_der ){
  	_rhp_free(my_cert_issuer_dn_der);
  }

  if( untrust_sub_ca_cert_issuer_dn_der ){
  	_rhp_free(untrust_sub_ca_cert_issuer_dn_der);
  }

	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_MY_KEY_INFO_RTRN,"xxd",cfg_sub_dt,auth_rlm,auth_rlm->id);
  return 0;

error:
	RHP_LOG_E(RHP_LOG_SRC_UI,0,RHP_LOG_ID_UI_UPDATE_MY_KEY_INFO_ERR,"ussLE",rlm_id,id_str,id_type_str,"PROTO_IKE_AUTHMETHOD",auth_method,err);
	if( cfg_doc ){
		xmlFreeDoc(cfg_doc);
	}
	if( new_my_auth ){
		rhp_auth_free_my_auth(new_my_auth);
	}
	if( old_my_auth ){
		rhp_auth_free_my_auth(old_my_auth);
	}
  if( id_value ){
  	_rhp_free(id_value);
  }
  if( id_str ){
  	_rhp_free(id_str);
  }
  if( id_type_str ){
  	_rhp_free(id_type_str);
  }
  if( my_cert_issuer_dn_der ){
  	_rhp_free(my_cert_issuer_dn_der);
  }

  if( untrust_sub_ca_cert_issuer_dn_der ){
  	_rhp_free(untrust_sub_ca_cert_issuer_dn_der);
  }

  RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_MY_KEY_INFO_ERR,"xxdE",cfg_sub_dt,auth_rlm,auth_rlm->id,err);
  return err;
}


static int _rhp_syspxy_ui_update_peer_key_info_parse(xmlNodePtr upd_peer_node,rhp_ui_key_info_enum_ctx* enum_ctx)
{
	int err = -EINVAL;
	xmlDocPtr cfg_doc = NULL;
	xmlNodePtr cfg_root_node = NULL;
	xmlNodePtr cfg_rlm_node = NULL;
	xmlNodePtr peer_auth_node = NULL;
  char realm_id_str[64];
  rhp_auth_peer* auth_peer = NULL;
  xmlChar *peerid_type = NULL, *peerid = NULL;

	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_PEER_KEY_INFO_PARSE,"xsx",upd_peer_node,upd_peer_node->name,enum_ctx);

  realm_id_str[0] = '\0';
  snprintf(realm_id_str,64,"%lu",enum_ctx->rlm_id);

  peerid_type = rhp_xml_get_prop(upd_peer_node,(xmlChar*)"id_type");
  peerid = rhp_xml_get_prop(upd_peer_node,(xmlChar*)"id");

  if( (peerid_type == NULL) || (peerid == NULL) ){

  	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_PEER_KEY_INFO_PARSE_NO_ID_ERR,"xsxxx",upd_peer_node,upd_peer_node->name,enum_ctx,peerid_type,peerid);

  	err = -EINVAL;
  	goto error;
  }

	{
		cfg_doc = xmlParseFile(rhp_syspxy_auth_conf_path);
		if( cfg_doc == NULL ){
			RHP_BUG(" %s ",rhp_syspxy_auth_conf_path);
			goto error;
		}

		cfg_root_node = xmlDocGetRootElement(cfg_doc);
		if( cfg_root_node == NULL ){
			RHP_BUG(" %s ",rhp_syspxy_auth_conf_path);
			goto error;
		}
	}

  cfg_rlm_node = rhp_xml_search_prop_value_in_children(cfg_root_node,
  		(xmlChar*)"vpn_realm",(xmlChar*)"id",(xmlChar*)realm_id_str);

  if( cfg_rlm_node == NULL ){
		RHP_BUG("");
		err = -ENOENT;
		goto error;
  }

  peer_auth_node = rhp_xml_get_child(cfg_rlm_node,(xmlChar*)"peers");
  if( peer_auth_node ){

  	peer_auth_node = rhp_xml_search_prop_value_in_children2(peer_auth_node,
  			(xmlChar*)"peer",(xmlChar*)"id_type",(xmlChar*)peerid_type,(xmlChar*)"id",(xmlChar*)peerid);
  }


  enum_ctx->my_key_dup = 0;

	err = rhp_xml_enum_tags(upd_peer_node,NULL,_rhp_syspxy_ui_update_key_info_setup_node,enum_ctx,1);
  if( err == -ENOENT ){

  	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_PEER_KEY_INFO_PARSE_SETUP_NODE_NOENT,"xsx",upd_peer_node,upd_peer_node->name,enum_ctx);
  	err = 0;

  }else if( err ){
  	RHP_BUG("%d",err);
  	goto error;
  }

  if( peer_auth_node ){

  	err = rhp_xml_enum_tags(peer_auth_node,NULL,_rhp_syspxy_ui_update_key_info_merge_node,upd_peer_node,1);
		if( err == -ENOENT ){

			RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_PEER_KEY_INFO_PARSE_MERGE_NODE_NOENT,"xsx",upd_peer_node,upd_peer_node->name,enum_ctx);
			err = 0;

		}else if( err ){
	  	RHP_BUG("%d",err);
			goto error;
		}
  }


  auth_peer = rhp_auth_parse_auth_peer(upd_peer_node);
  if( auth_peer == NULL ){
  	RHP_BUG("");
  	goto error;
  }

  enum_ctx->new_auth_peer = auth_peer;
  enum_ctx->new_node = upd_peer_node;
	enum_ctx->cfg_doc = cfg_doc;
	enum_ctx->cfg_root_node = cfg_root_node;
	enum_ctx->peer_auth_node = peer_auth_node;

	if( peerid_type ){
		_rhp_free(peerid_type);
	}
	if( peerid ){
		_rhp_free(peerid);
	}

	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_PEER_KEY_INFO_PARSE_RTRN,"xsx",upd_peer_node,upd_peer_node->name,enum_ctx);
	return 0;

error:
	if( auth_peer ){
		rhp_auth_free_auth_peer(auth_peer);
	}
	if( cfg_doc ){
		xmlFreeDoc(cfg_doc);
	}
	if( peerid_type ){
		_rhp_free(peerid_type);
	}
	if( peerid ){
		_rhp_free(peerid);
	}

	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_PEER_KEY_INFO_PARSE_ERR,"xsxE",upd_peer_node,upd_peer_node->name,enum_ctx,err);
  return err;
}

static int _rhp_syspxy_ui_update_peer_key_info_node(xmlNodePtr realm_node,void* ctx)
{
	int err = -EINVAL;
	rhp_ui_key_info_enum_ctx* enum_ctx = (rhp_ui_key_info_enum_ctx*)ctx;
	unsigned long elm_rlm_id;
	int ret_len;

	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_PEER_KEY_INFO_NODE,"xsx",realm_node,realm_node->name,enum_ctx);

  err = rhp_xml_str2val(rhp_xml_get_prop_static(realm_node,(const xmlChar*)"id"),RHP_XML_DT_ULONG,&elm_rlm_id,&ret_len,NULL,0);
  if( !err ){

  	if( enum_ctx->rlm_id == elm_rlm_id ){

		  xmlNodePtr dup_node = NULL,peers_node = NULL;;

		  peers_node = rhp_xml_get_child(realm_node,(xmlChar*)"peers");
		  if( peers_node == NULL ){

		  	peers_node = xmlNewNode(NULL,(xmlChar*)"peers");

		  	if( peers_node == NULL ){
		  		RHP_BUG("");
		  		err = -ENOMEM;
		  		goto error;
		  	}

		  	if( xmlAddChild(realm_node,peers_node) == NULL ){
			  	RHP_BUG("%d",enum_ctx->rlm_id);
				}

		  	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_PEER_KEY_INFO_NODE_ADD_CHILD_1,"xsxss",realm_node,realm_node->name,enum_ctx,realm_node->name,peers_node->name);
		  }


			dup_node = xmlCopyNode(enum_ctx->new_node,1);
			if( dup_node ){

				if( xmlAddChild(peers_node,dup_node) == NULL ){
			  	RHP_BUG("%d",enum_ctx->rlm_id);
				}

		  	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_PEER_KEY_INFO_NODE_ADD_CHILD_2,"xsxss",realm_node,realm_node->name,enum_ctx,peers_node->name,dup_node->name);

		  	if( enum_ctx->peer_auth_node ){
					xmlUnlinkNode(enum_ctx->peer_auth_node);
					xmlFreeNode(enum_ctx->peer_auth_node);
				}

			}else{
		  	RHP_BUG("%d",enum_ctx->rlm_id);
			}

			RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_PEER_KEY_INFO_NODE_ENUM_OK_RTRN,"xsx",realm_node,realm_node->name,enum_ctx);
  	  return RHP_STATUS_ENUM_OK;
  	}
  }

	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_PEER_KEY_INFO_NODE_RTRN,"xsx",realm_node,realm_node->name,enum_ctx);
  return 0;

error:
	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_PEER_KEY_INFO_NODE_ERR,"xsxE",realm_node,realm_node->name,enum_ctx,err);
	return err;
}

static int _rhp_syspxy_ui_update_peer_key_info(rhp_ipcmsg_syspxy_cfg_sub* cfg_sub_dt,
		rhp_vpn_auth_realm *auth_rlm,xmlDocPtr upd_auth_doc,xmlNodePtr upd_auth_root_node)
{
	int err = -EINVAL;
	unsigned long rlm_id = cfg_sub_dt->target_rlm_id;
	xmlDocPtr cfg_doc = NULL;
	xmlNodePtr cfg_root_node = NULL;
  rhp_ui_key_info_enum_ctx enum_ctx;
  rhp_auth_peer *new_auth_peer = NULL;
  char* id_str = NULL;
  char* id_type_str = NULL;
  int peer_id_type = 0;
  int eap_id_method = 0;

	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_PEER_KEY_INFO,"xxdxxs",cfg_sub_dt,auth_rlm,auth_rlm->id,upd_auth_doc,upd_auth_root_node,upd_auth_root_node->name);
	rhp_xml_doc_dump("_rhp_syspxy_ui_update_peer_key_info.upd_auth_doc",upd_auth_doc);

	memset(&enum_ctx,0,sizeof(rhp_ui_key_info_enum_ctx));

  enum_ctx.rlm_id = rlm_id;

	err = _rhp_syspxy_ui_update_peer_key_info_parse(upd_auth_root_node,&enum_ctx);

	if( err == -EINVAL || err == -ENOENT || (enum_ctx.new_auth_peer == NULL) ){

		RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_PEER_KEY_INFO_PARSE_ERR,"xxE",cfg_sub_dt,auth_rlm,err);
		err = RHP_STATUS_INVALID_MSG;
  	goto error;

	}else if( err ){
  	RHP_BUG("");
  	goto error;
  }

	cfg_doc = enum_ctx.cfg_doc;
	cfg_root_node = enum_ctx.cfg_root_node;

	new_auth_peer = enum_ctx.new_auth_peer;

	if( new_auth_peer->peer_id_type == RHP_PEER_ID_TYPE_IKEV2 ){

		rhp_ikev2_id_to_string(&(new_auth_peer->peer_id.ikev2),&id_type_str,&id_str);

	}else if( new_auth_peer->peer_id_type == RHP_PEER_ID_TYPE_EAP ){

		if( !rhp_eap_id_is_null(&(new_auth_peer->peer_id.eap)) ){

			rhp_eap_id_to_string(&(new_auth_peer->peer_id.eap),NULL,&id_str);
		}
	}

  RHP_LOCK(&(auth_rlm->lock));
  {

  	err = auth_rlm->replace_auth_peer(auth_rlm,new_auth_peer);
  	if( err ){
  		RHP_BUG("%d",err);
  	  RHP_UNLOCK(&(auth_rlm->lock));
  		goto error;
  	}

  	peer_id_type = new_auth_peer->peer_id_type;
  	new_auth_peer = NULL;
  }
  RHP_UNLOCK(&(auth_rlm->lock));


  //
  // [CAUTION] Don't touch 'new_auth_peer' anymore.
  //

  {
	  err = rhp_xml_enum_tags(cfg_root_node,(xmlChar*)"vpn_realm",_rhp_syspxy_ui_update_peer_key_info_node,&enum_ctx,1);
	  if( err == RHP_STATUS_ENUM_OK || err == -ENOENT ){

	  	err = 0;

	  }else if( err ){
			RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_PEER_KEY_INFO_UPDATE_NODE_ERR,"xxE",cfg_sub_dt,auth_rlm,err);
	  	goto error;
	  }

		err = rhp_cfg_save_config(rhp_syspxy_auth_conf_path,cfg_doc);
		if( err ){
			RHP_BUG("%d",err);
		}
  }

	if( peer_id_type == RHP_PEER_ID_TYPE_IKEV2 ){
		RHP_LOG_I(RHP_LOG_SRC_UI,0,RHP_LOG_ID_UI_UPDATE_PEER_KEY,"ussL",rlm_id,id_str,id_type_str,"PROTO_IKE_AUTHMETHOD",RHP_PROTO_IKE_AUTHMETHOD_SHARED_KEY);
	}else if( peer_id_type == RHP_PEER_ID_TYPE_EAP ){
		RHP_LOG_I(RHP_LOG_SRC_UI,0,RHP_LOG_ID_UI_UPDATE_PEER_EAP_KEY,"usL",rlm_id,id_str,"EAP_TYPE",eap_id_method);
	}

	if( cfg_doc ){
		xmlFreeDoc(cfg_doc);
	}

	if( id_str ){
		_rhp_free(id_str);
	}
	if( id_type_str ){
		_rhp_free(id_type_str);
	}

	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_PEER_KEY_INFO_RTRN,"xx",cfg_sub_dt,auth_rlm);
  return 0;

error:
	if( peer_id_type == RHP_PEER_ID_TYPE_IKEV2 ){
		RHP_LOG_E(RHP_LOG_SRC_UI,0,RHP_LOG_ID_UI_UPDATE_PEER_KEY_ERR,"ussLE",rlm_id,id_str,id_type_str,"PROTO_IKE_AUTHMETHOD",RHP_PROTO_IKE_AUTHMETHOD_SHARED_KEY,err);
	}

	if( cfg_doc ){
		xmlFreeDoc(cfg_doc);
	}
	if( new_auth_peer ){
		rhp_auth_free_auth_peer(new_auth_peer);
	}

	if( id_str ){
		_rhp_free(id_str);
	}
	if( id_type_str ){
		_rhp_free(id_type_str);
	}

	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_PEER_KEY_INFO_ERR,"xxE",cfg_sub_dt,auth_rlm,err);
  return err;
}

static int _rhp_syspxy_ui_update_key_info(rhp_ipcmsg_syspxy_cfg_sub* cfg_sub_dt,
		rhp_ipcmsg_syspxy_cfg_sub* cfg_sub_dt_rep,xmlTextWriterPtr writer,int* n)
{
	int err = -EINVAL;
	unsigned long rlm_id = cfg_sub_dt->target_rlm_id;
  xmlDocPtr upd_auth_doc = NULL;
  xmlNodePtr upd_auth_root_node = NULL;
	rhp_vpn_auth_realm *auth_rlm = NULL;

	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_KEY_INFO,"xxxx",cfg_sub_dt,cfg_sub_dt_rep,writer,n);

  if( rlm_id == 0 || rlm_id > RHP_VPN_REALM_ID_MAX ){

  	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_KEY_INFO_PERM_ERR,"xxxxu",cfg_sub_dt,cfg_sub_dt_rep,writer,n,rlm_id);

  	err = -EPERM;
		goto error;
  }

  if( cfg_sub_dt->len <= sizeof(rhp_ipcmsg_syspxy_cfg_sub) ){
  	err = -EINVAL;
  	RHP_BUG("");
  	goto error;
  }

  {
  	upd_auth_doc = xmlParseMemory((void*)(cfg_sub_dt + 1),(cfg_sub_dt->len - sizeof(rhp_ipcmsg_syspxy_cfg_sub)));
  	if( upd_auth_doc == NULL ){
  		err = -EINVAL;
  		RHP_BUG("");
  		goto error;
  	}

  	upd_auth_root_node = xmlDocGetRootElement(upd_auth_doc);
  	if( upd_auth_root_node == NULL ){
  		err = -EINVAL;
  		RHP_BUG("");
  		goto error;
  	}
  }


  auth_rlm = rhp_auth_realm_get(rlm_id);
  if( auth_rlm == NULL ){

  	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_KEY_INFO_RLM_NOT_FOUND,"xxxxu",cfg_sub_dt,cfg_sub_dt_rep,writer,n,rlm_id);
  	err = -ENOENT;
		goto error;
  }


  if( !xmlStrcmp(upd_auth_root_node->name,(xmlChar*)"my_auth") ){

  	err = _rhp_syspxy_ui_update_my_key_info(cfg_sub_dt,auth_rlm,upd_auth_doc,upd_auth_root_node);
  	if( err ){
    	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_KEY_INFO_MY_KEY_INFO_ERR,"xxxxuE",cfg_sub_dt,cfg_sub_dt_rep,writer,n,rlm_id,err);
  		goto error;
  	}

  }else if( !xmlStrcmp(upd_auth_root_node->name,(xmlChar*)"peer") ){

  	err = _rhp_syspxy_ui_update_peer_key_info(cfg_sub_dt,auth_rlm,upd_auth_doc,upd_auth_root_node);
  	if( err ){
    	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_KEY_INFO_PEER_KEY_INFO_ERR,"xxxxuE",cfg_sub_dt,cfg_sub_dt_rep,writer,n,rlm_id,err);
  		goto error;
  	}

  }else{

  	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_KEY_INFO_INVALID_KEY_INFO,"xxxxuE",cfg_sub_dt,cfg_sub_dt_rep,writer,n,rlm_id,err);
  	err = -EINVAL;
  	goto error;
  }

  if( upd_auth_doc ){
	  xmlFreeDoc(upd_auth_doc);
  }

	rhp_auth_realm_unhold(auth_rlm);

	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_KEY_INFO_RTRN,"xxxxu",cfg_sub_dt,cfg_sub_dt_rep,writer,n,rlm_id);
  return 0;

error:
	if( upd_auth_doc ){
		xmlFreeDoc(upd_auth_doc);
	}
	if( auth_rlm ){
		rhp_auth_realm_unhold(auth_rlm);
	}

	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_KEY_INFO_ERR,"xxxxuE",cfg_sub_dt,cfg_sub_dt_rep,writer,n,rlm_id,err);
  return err;
}

static int _rhp_syspxy_ui_delete_key_info(rhp_ipcmsg_syspxy_cfg_sub* cfg_sub_dt,
		rhp_ipcmsg_syspxy_cfg_sub* cfg_sub_dt_rep,xmlTextWriterPtr writer,int* n)
{
	int err = -EINVAL;
	unsigned long rlm_id = cfg_sub_dt->target_rlm_id;
  xmlDocPtr upd_auth_doc = NULL;
  xmlNodePtr upd_auth_peer_node = NULL;
	xmlDocPtr cfg_doc = NULL;
	xmlNodePtr cfg_root_node = NULL;
  xmlNodePtr cfg_rlm_node,cfg_peers_node,cfg_peer_node;
	rhp_vpn_auth_realm *auth_rlm = NULL;
  xmlChar *peerid_type = NULL, *peerid = NULL;
	rhp_ikev2_id ikev2_id;
	rhp_eap_id eap_id;
	int peer_id_type = 0;
	void* peer_id = NULL;
  char realm_id_str[64];

	RHP_TRC(0,RHPTRCID_SYSPXY_UI_DELETE_KEY_INFO,"xxxxdu",cfg_sub_dt,cfg_sub_dt_rep,writer,n,*n,rlm_id);

  if( rlm_id == 0 || rlm_id > RHP_VPN_REALM_ID_MAX ){
  	err = -EPERM;
  	RHP_TRC(0,RHPTRCID_SYSPXY_UI_DELETE_KEY_INFO_NOT_PERMITTED,"xu",cfg_sub_dt,rlm_id);
		goto error;
  }

  if( cfg_sub_dt->len <= sizeof(rhp_ipcmsg_syspxy_cfg_sub) ){
  	err = -EINVAL;
  	RHP_BUG("");
  	goto error;
  }

  realm_id_str[0] = '\0';
  snprintf(realm_id_str,64,"%lu",rlm_id);

  memset(&ikev2_id,0,sizeof(rhp_ikev2_id));
  memset(&eap_id,0,sizeof(rhp_eap_id));


  {
  	upd_auth_doc = xmlParseMemory((void*)(cfg_sub_dt + 1),(cfg_sub_dt->len - sizeof(rhp_ipcmsg_syspxy_cfg_sub)));
  	if( upd_auth_doc == NULL ){
  		err = -EINVAL;
  		RHP_BUG("");
  		goto error;
  	}

  	upd_auth_peer_node = xmlDocGetRootElement(upd_auth_doc);
  	if( upd_auth_peer_node == NULL ){
  		err = -EINVAL;
  		RHP_BUG("");
  		goto error;
  	}

  	if( xmlStrcmp(upd_auth_peer_node->name,(xmlChar*)"peer") ){
  		RHP_TRC(0,RHPTRCID_SYSPXY_UI_DELETE_KEY_INFO_INVALID_PEER_TAG_NAME,"xus",cfg_sub_dt,rlm_id,upd_auth_peer_node->name);
  		err = -EINVAL;
  		goto error;
  	}
  }


  peerid_type = rhp_xml_get_prop(upd_auth_peer_node,(xmlChar*)"id_type");
  peerid = rhp_xml_get_prop(upd_auth_peer_node,(xmlChar*)"id");

  if( (peerid_type == NULL) || (peerid == NULL) ){
		RHP_TRC(0,RHPTRCID_SYSPXY_UI_DELETE_KEY_INFO_INVALID_ID_VALUE,"xu",cfg_sub_dt,rlm_id);
  	err = -EINVAL;
  	goto error;
  }


  err = rhp_cfg_parse_ikev2_id(upd_auth_peer_node,(xmlChar*)"id_type",(xmlChar*)"id",&ikev2_id);
  if( !err ){

  	peer_id_type = RHP_PEER_ID_TYPE_IKEV2;

    if( ikev2_id.type != RHP_PROTO_IKE_ID_FQDN &&
    		ikev2_id.type != RHP_PROTO_IKE_ID_RFC822_ADDR &&
    		ikev2_id.type != RHP_PROTO_IKE_ID_IPV4_ADDR &&
    		ikev2_id.type != RHP_PROTO_IKE_ID_IPV6_ADDR &&
    		ikev2_id.type != RHP_PROTO_IKE_ID_DER_ASN1_DN &&
    		ikev2_id.type != RHP_PROTO_IKE_ID_ANY ){
      RHP_BUG("");
      err = -EINVAL;
      goto error;
    }

    peer_id = (void*)&ikev2_id;

  }else if( err == -ENOENT ){

  	peer_id_type = RHP_PEER_ID_TYPE_EAP;

    err = rhp_cfg_parse_eap_id(upd_auth_peer_node,(const xmlChar*)"id_type",(const xmlChar*)"id",&eap_id);
    if( err ){
    	RHP_BUG("");
    	goto error;
    }

    peer_id = (void*)&eap_id;

  }else{
		RHP_TRC(0,RHPTRCID_SYSPXY_UI_DELETE_KEY_INFO_INVALID_ID_TYPE,"xu",cfg_sub_dt,rlm_id);
    goto error;
  }


  auth_rlm = rhp_auth_realm_get(rlm_id);
  if( auth_rlm == NULL ){
		RHP_TRC(0,RHPTRCID_SYSPXY_UI_DELETE_KEY_INFO_REALM_NOT_FOUND,"xu",cfg_sub_dt,rlm_id);
		err = -ENOENT;
		goto error;
  }

  RHP_LOCK(&(auth_rlm->lock));
  {

  	err = auth_rlm->delete_auth_peer(auth_rlm,peer_id_type,peer_id);
  	if( err ){
  	  RHP_UNLOCK(&(auth_rlm->lock));
  		RHP_TRC(0,RHPTRCID_SYSPXY_UI_DELETE_KEY_INFO_DELETE_AUTH_PEER_ERR,"xuE",cfg_sub_dt,rlm_id,err);
  	  goto error;
  	}
  }
  RHP_UNLOCK(&(auth_rlm->lock));


  {
		cfg_doc = xmlParseFile(rhp_syspxy_auth_conf_path);
		if( cfg_doc == NULL ){
			RHP_BUG(" %s ",rhp_syspxy_auth_conf_path);
			err = -ENOENT;
			goto error;
		}

		cfg_root_node = xmlDocGetRootElement(cfg_doc);
		if( cfg_root_node == NULL ){
			RHP_BUG(" %s ",rhp_syspxy_auth_conf_path);
			err = -ENOENT;
			goto error;
		}

	  cfg_rlm_node = rhp_xml_search_prop_value_in_children(cfg_root_node,(xmlChar*)"vpn_realm",(xmlChar*)"id",(xmlChar*)realm_id_str);
	  if( cfg_rlm_node == NULL ){
			RHP_BUG("");
			goto error;
	  }

	  cfg_peers_node = rhp_xml_get_child(cfg_rlm_node,(xmlChar*)"peers");
	  if( cfg_peers_node == NULL ){
			RHP_BUG("");
			goto error;
	  }

		cfg_peer_node = rhp_xml_search_prop_value_in_children2(cfg_peers_node,(xmlChar*)"peer",
				(xmlChar*)"id_type",peerid_type,(xmlChar*)"id",peerid);

		if( cfg_peer_node ){
			xmlUnlinkNode(cfg_peer_node);
			xmlFreeNode(cfg_peer_node);
		}

		err = rhp_cfg_save_config(rhp_syspxy_auth_conf_path,cfg_doc);
		if( err ){
			RHP_BUG("%d",err);
		}
  }


  if( upd_auth_doc ){
	  xmlFreeDoc(upd_auth_doc);
  }

	rhp_auth_realm_unhold(auth_rlm);

	RHP_LOG_I(RHP_LOG_SRC_UI,rlm_id,RHP_LOG_ID_UI_DELETE_PEER_KEY,"uss",rlm_id,peerid,peerid_type);

	if( peerid_type ){
		_rhp_free(peerid_type);
	}
	if( peerid ){
		_rhp_free(peerid);
	}

	RHP_TRC(0,RHPTRCID_SYSPXY_UI_DELETE_KEY_INFO_RTRN,"xxxxdu",cfg_sub_dt,cfg_sub_dt_rep,writer,n,*n,rlm_id);
  return 0;

error:
	if( err != -ENOENT ){
		RHP_LOG_E(RHP_LOG_SRC_UI,rlm_id,RHP_LOG_ID_UI_DELETE_PEER_KEY_ERR,"ussE",rlm_id,peerid,peerid_type,err);
	}
	if( upd_auth_doc ){
		xmlFreeDoc(upd_auth_doc);
	}
	if( auth_rlm ){
		rhp_auth_realm_unhold(auth_rlm);
	}
	if( peerid_type ){
		_rhp_free(peerid_type);
	}
	if( peerid ){
		_rhp_free(peerid);
	}
	RHP_TRC(0,RHPTRCID_SYSPXY_UI_DELETE_KEY_INFO_ERR,"xxxxduE",cfg_sub_dt,cfg_sub_dt_rep,writer,n,*n,rlm_id,err);
  return err;
}


static int _rhp_syspxy_ui_update_cert(rhp_ipcmsg_syspxy_cfg_sub* cfg_sub_dt,
		rhp_ipcmsg_syspxy_cfg_sub* cfg_sub_dt_rep,xmlTextWriterPtr writer,int* n,
		int cert_file_uploaded)
{
	int err = -EINVAL;
	unsigned long rlm_id = cfg_sub_dt->target_rlm_id;
  xmlDocPtr upd_auth_doc = NULL;
  xmlNodePtr upd_cert_store_node = NULL;
  xmlNodePtr upd_cert_my_cert = NULL,upd_cert_my_privkey = NULL,upd_cert_ca_certs = NULL;
  xmlDocPtr cfg_doc = NULL;
  xmlNodePtr cfg_root_node = NULL;
	rhp_vpn_auth_realm *auth_rlm = NULL;
  char realm_id_str[64];
  char *password = NULL;
  u8 *my_cert = NULL,*my_priv_key = NULL,*ca_certs = NULL;
  int my_cert_len = 0,my_priv_key_len = 0,ca_certs_len = 0;
	rhp_cert_store* new_cert_store = NULL;
	int my_id_resolved = 0;
	int update_pw = 0;
	char* my_id_str = NULL;
	char* my_id_type_str = NULL;
	int eap_sup_enabled = 0;
	int eap_sup_ask_for_user_key = 0, eap_sup_method = 0, eap_sup_user_key_cache_enabled = 0;
  int psk_for_peers = 0, rsa_sig_for_peers = 0, eap_for_peers = 0, null_auth_for_peers = 0;
	rhp_cert_url* cert_urls = NULL;
  u8* my_id_value = NULL;
  int my_id_len = 0;
  int my_id_type = 0;
  int my_auth_method = RHP_PROTO_IKE_AUTHMETHOD_NONE, my_xauth_method = RHP_PROTO_IKE_AUTHMETHOD_NONE;
  u8 *my_cert_issuer_dn_der = NULL, *untrust_sub_ca_cert_issuer_dn_der = NULL;
  int my_cert_issuer_dn_der_len = 0, untrust_sub_ca_cert_issuer_dn_der_len = 0;

	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_CERT,"xxxxdudx",cfg_sub_dt,cfg_sub_dt_rep,writer,n,*n,rlm_id,cert_file_uploaded);

  if( rlm_id == 0 || rlm_id > RHP_VPN_REALM_ID_MAX ){
  	err = -EPERM;
  	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_CERT_NOT_PERMITTED,"xu",cfg_sub_dt,rlm_id);
		goto error;
  }

  if( cfg_sub_dt->len <= sizeof(rhp_ipcmsg_syspxy_cfg_sub) ){
  	err = -EINVAL;
  	RHP_BUG("");
  	goto error;
  }

  realm_id_str[0] = '\0';
  snprintf(realm_id_str,64,"%lu",rlm_id);

  RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_CERT_CONTENT,"p",(cfg_sub_dt->len - sizeof(rhp_ipcmsg_syspxy_cfg_sub)),(cfg_sub_dt + 1));

  {
  	upd_auth_doc = xmlParseMemory((void*)(cfg_sub_dt + 1),(cfg_sub_dt->len - sizeof(rhp_ipcmsg_syspxy_cfg_sub)));
  	if( upd_auth_doc == NULL ){
  		err = -EINVAL;
  		RHP_BUG("");
  		goto error;
  	}

		upd_cert_store_node = xmlDocGetRootElement(upd_auth_doc);
		if( upd_cert_store_node == NULL ){
			err = -EINVAL;
			RHP_BUG("");
			goto error;
		}

		if( xmlStrcmp(upd_cert_store_node->name,(const xmlChar*)"cert_store") ){
			err = -EINVAL;
			RHP_BUG("");
			goto error;
		}
  }


  auth_rlm = rhp_auth_realm_get(rlm_id);
  if( auth_rlm == NULL ){
		err = -ENOENT;
  	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_CERT_REALM_NOT_FOUND,"xu",cfg_sub_dt,rlm_id);
		goto error;
  }

	RHP_LOCK(&(auth_rlm->lock));
	{
		if( auth_rlm->my_auth == NULL ){

			err = -ENOENT;
			RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_CERT_MY_AUTH_NOT_FOUND,"xu",cfg_sub_dt,rlm_id);

			RHP_LOG_E(RHP_LOG_SRC_UI,rlm_id,RHP_LOG_ID_UI_UPDATE_CERT_NO_MY_AUTH,"u",rlm_id);

			RHP_UNLOCK(&(auth_rlm->lock));
			goto error;
		}
	}
	RHP_UNLOCK(&(auth_rlm->lock));


	if( !cert_file_uploaded ){

		upd_cert_my_cert = rhp_xml_get_child(upd_cert_store_node,(xmlChar*)"my_cert");
		upd_cert_my_privkey = rhp_xml_get_child(upd_cert_store_node,(xmlChar*)"my_priv_key");
		upd_cert_ca_certs  = rhp_xml_get_child(upd_cert_store_node,(xmlChar*)"ca_certs");
	}

  if( upd_cert_my_privkey ){
  	rhp_xml_get_text_or_cdata_content(upd_cert_my_privkey,(xmlChar**)&my_priv_key,&my_priv_key_len);
  }

  if( upd_cert_my_cert ){
  	rhp_xml_get_text_or_cdata_content(upd_cert_my_cert,(xmlChar**)&my_cert,&my_cert_len);
  }

  if( upd_cert_ca_certs ){
  	rhp_xml_get_text_or_cdata_content(upd_cert_ca_certs,(xmlChar**)&ca_certs,&ca_certs_len);
  }

  {
		password = (char*)rhp_xml_get_prop(upd_cert_store_node,(xmlChar*)"password");
		if( password ){
			update_pw = 1;
		}else{
			RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_CERT_NO_PASSWORD,"xu",cfg_sub_dt,rlm_id);
		}
  }

  {
  	cert_urls = rhp_auth_parse_realm_cert_urls(upd_cert_store_node,rlm_id);
  	if( cert_urls == NULL ){
			RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_CERT_NO_CERT_URLS,"xu",cfg_sub_dt,rlm_id);
  	}
  }

	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_CERT_CONTENTS,"xuppps",cfg_sub_dt,rlm_id,my_cert_len,my_cert,my_priv_key_len,my_priv_key,ca_certs_len,ca_certs,password);


	RHP_LOCK(&(auth_rlm->lock));
	{
		if( cert_file_uploaded ||
				my_cert_len > 1 || my_priv_key_len > 1 || ca_certs_len > 1 ){ // Each xxx_len includes '\0' as the last char.


			if( cert_file_uploaded ){

				err = rhp_cert_update2(rlm_id,
						( password ? password : auth_rlm->my_cert_store_password ),
						rhp_syspxy_cert_store_path,&new_cert_store);

			}else if( my_cert_len > 1 || my_priv_key_len > 1 || ca_certs_len > 1 ){ // Each xxx_len includes '\0' as the last char.

				err = rhp_cert_update(rlm_id,
						( my_cert_len > 1 ? (my_cert_len - 1) : 0 ),my_cert,
						( my_priv_key_len > 1 ? (my_priv_key_len - 1) : 0 ),my_priv_key,
						( ca_certs_len > 1 ? (ca_certs_len - 1) : 0 ),ca_certs,
						( password ? password : auth_rlm->my_cert_store_password ),
						rhp_syspxy_cert_store_path,&new_cert_store);
			}

			if( err ){
				RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_CERT_FAILED_TO_UPDATE,"xuE",cfg_sub_dt,rlm_id,err);
				RHP_UNLOCK(&(auth_rlm->lock));
				goto error;
			}

			if( auth_rlm->my_auth->cert_store ){
				rhp_cert_store_destroy(auth_rlm->my_auth->cert_store);
				rhp_cert_store_unhold(auth_rlm->my_auth->cert_store);
				auth_rlm->my_auth->cert_store = NULL;
			}

			if( auth_rlm->my_auth->cert_store_tmp ){
				rhp_cert_store_destroy(auth_rlm->my_auth->cert_store_tmp);
				rhp_cert_store_unhold(auth_rlm->my_auth->cert_store_tmp);
				auth_rlm->my_auth->cert_store_tmp = NULL;
			}


			if( auth_rlm->my_auth->auth_method == RHP_PROTO_IKE_AUTHMETHOD_RSA_SIG ){

				if( new_cert_store->imcomplete ){

					auth_rlm->my_auth->cert_store_tmp = new_cert_store;

				}else{

					if( cert_file_uploaded || my_cert_len > 1 ){

						my_id_type = auth_rlm->my_auth->my_id.type;

						rhp_ikev2_id_clear(&(auth_rlm->my_auth->my_id));
						auth_rlm->my_auth->my_id.type = my_id_type;

						err = rhp_auth_resolve_my_auth_cert_my_id(auth_rlm->my_auth,new_cert_store);
						if( err == -ENOENT ){

							err = 0;
							RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_CERT_MY_ID_NOT_FOUND,"xu",cfg_sub_dt,rlm_id);

						}else if( err ){

							RHP_BUG("%d",err);
							RHP_UNLOCK(&(auth_rlm->lock));
							goto error;

						}else{

							RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_CERT_MY_ID_RESOLVED_OK,"xu",cfg_sub_dt,rlm_id);

							my_id_resolved = 1;
						}

						rhp_ikev2_id_to_string(&(auth_rlm->my_auth->my_id),&my_id_type_str,&my_id_str);
					}

					auth_rlm->my_auth->cert_store = new_cert_store;
				}

			}else{

				RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_CERT_MY_AUTH_METHOD_NOT_RSA_SIG,"xuLdxd",cfg_sub_dt,rlm_id,"PROTO_IKE_AUTHMETHOD",auth_rlm->my_auth->auth_method,new_cert_store,(new_cert_store ? new_cert_store->imcomplete : -1));

				auth_rlm->my_auth->cert_store = new_cert_store;
			}

			new_cert_store = NULL;
		}

		if( update_pw ){

			int n_pw_len = strlen(password);

			if( auth_rlm->my_cert_store_password ){
				_rhp_free_zero(auth_rlm->my_cert_store_password,strlen(auth_rlm->my_cert_store_password) + 1);
			}

			auth_rlm->my_cert_store_password = (char*)_rhp_malloc(n_pw_len + 1);
			if( auth_rlm->my_cert_store_password == NULL ){
				RHP_BUG("");
				err = -ENOMEM;
				RHP_UNLOCK(&(auth_rlm->lock));
				goto error;
			}

			if( n_pw_len ){
				memcpy(auth_rlm->my_cert_store_password,password,n_pw_len);
			}
			auth_rlm->my_cert_store_password[n_pw_len] = '\0';

		}else{
			RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_CERT_PW_NOT_UPDATED,"xu",cfg_sub_dt,rlm_id);
	  }

		if( auth_rlm->my_auth->cert_store ){

			if( auth_rlm->my_auth->cert_urls ){

				rhp_auth_free_cert_urls(auth_rlm->my_auth->cert_urls);
				auth_rlm->my_auth->cert_urls = NULL;
			}

			if( cert_urls ){

				auth_rlm->my_auth->cert_urls = cert_urls;
				cert_urls = NULL;

				err = rhp_auth_setup_cert_urls(auth_rlm->my_auth->cert_store,auth_rlm->my_auth,rlm_id);
				if( err ){
					RHP_BUG("%d",err);
					RHP_UNLOCK(&(auth_rlm->lock));
					goto error;
				}

			}else{
				RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_CERT_CERT_URL_NOT_UPADTED,"xu",cfg_sub_dt,rlm_id);
			}


	  	auth_rlm->my_auth->cert_store->get_my_cert_issuer_dn_der(
	  			auth_rlm->my_auth->cert_store,&untrust_sub_ca_cert_issuer_dn_der,&untrust_sub_ca_cert_issuer_dn_der_len);

	  	auth_rlm->my_auth->cert_store->get_untrust_sub_ca_issuer_dn_der(auth_rlm->my_auth->cert_store,
	  			&untrust_sub_ca_cert_issuer_dn_der,&untrust_sub_ca_cert_issuer_dn_der_len);

		}else{
			RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_CERT_CERT_URL_NOT_UPADTED_NO_CERT_STORE,"xu",cfg_sub_dt,rlm_id);
		}


		if( my_id_resolved ){

			if( rhp_ikev2_id_value(&(auth_rlm->my_auth->my_id),&my_id_value,&my_id_len,&my_id_type) ){
				RHP_BUG("");
			}

			my_auth_method = auth_rlm->my_auth->auth_method;
			my_xauth_method = auth_rlm->xauth.p1_auth_method;
			psk_for_peers = auth_rlm->psk_for_peers;
			rsa_sig_for_peers = auth_rlm->rsa_sig_for_peers;
			eap_for_peers = auth_rlm->eap_for_peers;
			null_auth_for_peers = auth_rlm->null_auth_for_peers;
		}
	}
	RHP_UNLOCK(&(auth_rlm->lock));


	eap_sup_enabled = rhp_auth_sup_is_enabled(rlm_id,
											&eap_sup_method,&eap_sup_ask_for_user_key,
											&eap_sup_user_key_cache_enabled);

	{
		xmlNodePtr node,rlm_node;
		xmlAttrPtr pw_attr;

		cfg_doc = xmlParseFile(rhp_syspxy_auth_conf_path);
		if( cfg_doc == NULL ){
			RHP_BUG(" %s ",rhp_syspxy_auth_conf_path);
			goto error;
		}

		cfg_root_node = xmlDocGetRootElement(cfg_doc);
		if( cfg_root_node == NULL ){
			RHP_BUG(" %s ",rhp_syspxy_auth_conf_path);
			goto error;
		}

		rlm_node = rhp_xml_search_prop_value_in_children(cfg_root_node,
				(xmlChar*)"vpn_realm",(xmlChar*)"id",(xmlChar*)realm_id_str);

		if( rlm_node == NULL ){
			RHP_BUG("");
			goto error;
	  }

		if( update_pw ){

			node = rhp_xml_get_child(rlm_node,(xmlChar*)"cert_my_priv_key");
			if( node == NULL ){

				node = xmlNewChild(rlm_node,NULL,(xmlChar*)"cert_my_priv_key",NULL);
				if( node == NULL ){
					RHP_BUG("");
					goto error;
				}
			}

			pw_attr = xmlHasProp(node,(xmlChar*)"password");

			if( xmlNewProp(node,(xmlChar*)"password",(xmlChar*)password) == NULL ){
				RHP_BUG("");
				err = -ENOMEM;
				goto error;
			}

			if( pw_attr ){
				xmlRemoveProp(pw_attr);
			}
		}

		{
			err = rhp_xml_replace_child(rlm_node,upd_cert_store_node,(xmlChar*)"cert_urls",1);
			if( err ){
				RHP_BUG("%d",err);
				goto error;
			}
		}

		err = rhp_cfg_save_config(rhp_syspxy_auth_conf_path,cfg_doc);
		if( err ){
			RHP_BUG("%d",err);
		}
	}

	if( my_id_resolved ){

	  if( my_id_len ){

	  	rhp_ipcmsg_resolve_my_id_rep* res_my_id_rep
	  		= rhp_auth_ipc_alloc_rslv_my_id_rep(rlm_id,0,1,my_id_type,my_id_len,my_id_value,my_auth_method,my_xauth_method,
	  				eap_sup_enabled,eap_sup_ask_for_user_key,eap_sup_method,eap_sup_user_key_cache_enabled,
	  				psk_for_peers,rsa_sig_for_peers,eap_for_peers,null_auth_for_peers,
	  	  		my_cert_issuer_dn_der_len,my_cert_issuer_dn_der,
	  	  		untrust_sub_ca_cert_issuer_dn_der_len,untrust_sub_ca_cert_issuer_dn_der);

			if( res_my_id_rep == NULL ){

				RHP_BUG("");

			}else{

				if( rhp_ipc_send(RHP_MY_PROCESS,(void*)res_my_id_rep,res_my_id_rep->len,0) < 0 ){
					RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_MY_KEY_INFO_IPC_SEND_ERR,"xxdd",RHP_MY_PROCESS,res_my_id_rep,res_my_id_rep->len,0);
					RHP_BUG("");
				}

				_rhp_free_zero(res_my_id_rep,res_my_id_rep->len);
			}
	  }
	}

  if( upd_auth_doc ){
	  xmlFreeDoc(upd_auth_doc);
  }

	rhp_auth_realm_unhold(auth_rlm);

	if( password ){
		_rhp_free_zero(password,strlen(password));
	}

	if( upd_cert_my_cert || upd_cert_my_privkey ){
		RHP_LOG_I(RHP_LOG_SRC_UI,rlm_id,RHP_LOG_ID_UI_UPDATE_MY_CERT,"uss",rlm_id,my_id_str,my_id_type_str);
	}
	if( upd_cert_ca_certs ){
		RHP_LOG_I(RHP_LOG_SRC_UI,rlm_id,RHP_LOG_ID_UI_UPDATE_CA_CERT,"u",rlm_id);
	}

	if( cert_file_uploaded ){
		RHP_LOG_I(RHP_LOG_SRC_UI,rlm_id,RHP_LOG_ID_UI_UPDATE_CERTIFICATE_FILE,"u",rlm_id);
	}

	if( my_cert ){
		_rhp_free(my_cert);
	}
	if( my_priv_key ){
		_rhp_free_zero(my_priv_key,my_priv_key_len);
	}
	if( ca_certs ){
		_rhp_free(ca_certs);
	}
	if( my_id_str ){
		_rhp_free(my_id_str);
	}
	if( my_id_type_str ){
		_rhp_free(my_id_type_str);
	}
  if( my_id_value ){
    _rhp_free(my_id_value);
  }
  if( my_cert_issuer_dn_der ){
  	_rhp_free(my_cert_issuer_dn_der);
  }
  if( untrust_sub_ca_cert_issuer_dn_der ){
  	_rhp_free(untrust_sub_ca_cert_issuer_dn_der);
  }


	err = rhp_auth_ipc_send_ca_pubkey_digests_update();
	if( err ){
		RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_CERT_SEND_PUBKEY_DIGESTS_UPDATE_ERR,"xE",cfg_sub_dt,err);
		err = 0;
	}


	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_CERT_RTRN,"xxxxdu",cfg_sub_dt,cfg_sub_dt_rep,writer,n,*n,rlm_id);
	return 0;

error:
	if( upd_cert_my_cert || upd_cert_my_privkey ){
		RHP_LOG_E(RHP_LOG_SRC_UI,rlm_id,RHP_LOG_ID_UI_UPDATE_MY_CERT_ERR,"ussE",rlm_id,my_id_str,my_id_type_str,err);
	}else if( upd_cert_ca_certs ){
		RHP_LOG_E(RHP_LOG_SRC_UI,rlm_id,RHP_LOG_ID_UI_UPDATE_CA_CERT_ERR,"uE",rlm_id,err);
	}else if( cert_file_uploaded ){
		RHP_LOG_E(RHP_LOG_SRC_UI,rlm_id,RHP_LOG_ID_UI_UPDATE_CERTIFICATE_FILE_ERR,"ussE",rlm_id,my_id_str,my_id_type_str,err);
	}else 	if( upd_cert_my_cert == NULL && upd_cert_my_privkey == NULL && upd_cert_ca_certs == NULL  ){
		RHP_LOG_E(RHP_LOG_SRC_UI,rlm_id,RHP_LOG_ID_UI_UPDATE_CERT_ERR,"uE",rlm_id,err);
	}


	if( upd_auth_doc ){
		xmlFreeDoc(upd_auth_doc);
	}
	if( auth_rlm ){
		rhp_auth_realm_unhold(auth_rlm);
	}
	if( password ){
		_rhp_free_zero(password,strlen(password));
	}
	if( my_cert ){
		_rhp_free(my_cert);
	}
	if( my_priv_key ){
		_rhp_free_zero(my_priv_key,my_priv_key_len);
	}
	if( ca_certs ){
		_rhp_free(ca_certs);
	}
	if( new_cert_store ){
		rhp_cert_store_destroy(new_cert_store);
		rhp_cert_store_unhold(new_cert_store);
	}
	if( my_id_str ){
		_rhp_free(my_id_str);
	}
	if( my_id_type_str ){
		_rhp_free(my_id_type_str);
	}
  if( my_id_value ){
    _rhp_free(my_id_value);
  }
	if( cert_urls ){
		rhp_auth_free_cert_urls(cert_urls);
	}
  if( my_cert_issuer_dn_der ){
  	_rhp_free(my_cert_issuer_dn_der);
  }
  if( untrust_sub_ca_cert_issuer_dn_der ){
  	_rhp_free(untrust_sub_ca_cert_issuer_dn_der);
  }

	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_CERT_ERR,"xxxxdu",cfg_sub_dt,cfg_sub_dt_rep,writer,n,*n,rlm_id,err);
  return err;
}


/*
static int _rhp_syspxy_ui_delete_cert(rhp_ipcmsg_syspxy_cfg_sub* cfg_sub_dt,
		rhp_ipcmsg_syspxy_cfg_sub* cfg_sub_dt_rep,xmlTextWriterPtr writer,int* n)
{
	int err = -EINVAL;
  xmlDocPtr cfg_doc = NULL;
  xmlNodePtr cfg_root_node = NULL;
	unsigned long rlm_id = cfg_sub_dt->vpn_realm_id;
	rhp_vpn_auth_realm *auth_rlm = NULL;
  char realm_id_str[64];

	RHP_TRC(0,RHPTRCID_SYSPXY_UI_DELETE_CERT,"xxxxdu",cfg_sub_dt,cfg_sub_dt_rep,writer,n,*n,rlm_id);

  if( rlm_id == 0 || rlm_id > RHP_VPN_REALM_ID_MAX ){
  	RHP_TRC(0,RHPTRCID_SYSPXY_UI_DELETE_CERT_NOT_PERMITTED,"xu",cfg_sub_dt,rlm_id);
  	err = -EPERM;
		goto error;
  }

  if( cfg_sub_dt->len <= sizeof(rhp_ipcmsg_syspxy_cfg_sub) ){
  	err = -EINVAL;
  	RHP_BUG("");
  	goto error;
  }

  realm_id_str[0] = '\0';
  snprintf(realm_id_str,64,"%lu",rlm_id);

  auth_rlm = rhp_auth_realm_get(rlm_id);
  if( auth_rlm == NULL ){
  	RHP_TRC(0,RHPTRCID_SYSPXY_UI_DELETE_CERT_REALM_NOT_FOUND,"xu",cfg_sub_dt,rlm_id);
		err = -ENOENT;
		goto error;
  }

	RHP_LOCK(&(auth_rlm->lock));
	{

		if( (auth_rlm->my_auth == NULL) ||
				(auth_rlm->my_auth->cert_store == NULL && auth_rlm->my_auth->cert_store_tmp == NULL) ){
	  	RHP_TRC(0,RHPTRCID_SYSPXY_UI_DELETE_CERT_MY_AUTH_OR_CERT_STORE_NOT_FOUND,"xu",cfg_sub_dt,rlm_id);
			err = -ENOENT;
			RHP_UNLOCK(&(auth_rlm->lock));
			goto error;
		}

		rhp_cert_store* cert_store = auth_rlm->my_auth->cert_store;
		if( cert_store == NULL ){
			cert_store = auth_rlm->my_auth->cert_store_tmp;
	  	RHP_TRC(0,RHPTRCID_SYSPXY_UI_DELETE_CERT_MY_AUTH_OR_CERT_STORE_TMP_FOUND,"xu",cfg_sub_dt,rlm_id);
		}

		err = rhp_cert_delete(rlm_id,rhp_syspxy_cert_store_path,cert_store);

		if( err ){
			RHP_BUG("%d",err);
			RHP_UNLOCK(&(auth_rlm->lock));
			goto error;
		}

		auth_rlm->my_auth->cert_store = NULL;
		auth_rlm->my_auth->cert_store_tmp = NULL;

		if( auth_rlm->my_cert_store_password ){
			_rhp_free_zero(auth_rlm->my_cert_store_password,strlen(auth_rlm->my_cert_store_password) + 1);
			auth_rlm->my_cert_store_password = NULL;
		}
	}
	RHP_UNLOCK(&(auth_rlm->lock));


	{
		xmlNodePtr node;

		cfg_doc = xmlParseFile(rhp_syspxy_auth_conf_path);
		if( cfg_doc == NULL ){
			RHP_BUG(" %s ",rhp_syspxy_auth_conf_path);
			goto error;
		}

		cfg_root_node = xmlDocGetRootElement(cfg_doc);
		if( cfg_root_node == NULL ){
			RHP_BUG(" %s ",rhp_syspxy_auth_conf_path);
			goto error;
		}

		node = rhp_xml_search_prop_value_in_children(cfg_root_node,(xmlChar*)"vpn_realm",(xmlChar*)"id",(xmlChar*)realm_id_str);
	  if( node == NULL ){
			RHP_BUG("");
			goto error;
	  }

		node = rhp_xml_get_child(node,(xmlChar*)"my_auth");
	  if( node == NULL ){
			RHP_BUG("");
			goto error;
	  }

		node = rhp_xml_get_child(node,(xmlChar*)"cert_store");
	  if( node ){

	  	xmlAttrPtr pw_attr = xmlHasProp(node,(xmlChar*)"password");
			if( pw_attr ){

				xmlRemoveProp(pw_attr);

				err = rhp_cfg_save_config(rhp_syspxy_auth_conf_path,cfg_doc);
				if( err ){
					RHP_BUG("%d",err);
				}
			}
	  }
	}

	rhp_auth_realm_unhold(auth_rlm);

	RHP_TRC(0,RHPTRCID_SYSPXY_UI_DELETE_CERT_RTRN,"xxxxdu",cfg_sub_dt,cfg_sub_dt_rep,writer,n,*n,rlm_id);
  return 0;

error:
	if( auth_rlm ){
		rhp_auth_realm_unhold(auth_rlm);
	}
	RHP_TRC(0,RHPTRCID_SYSPXY_UI_DELETE_CERT_ERR,"xxxxduE",cfg_sub_dt,cfg_sub_dt_rep,writer,n,*n,rlm_id,err);
  return err;
}
*/

static int _rhp_syspxy_ui_get_printed_certs(rhp_ipcmsg_syspxy_cfg_sub* cfg_sub_dt,
		rhp_ipcmsg_syspxy_cfg_sub* cfg_sub_dt_rep,xmlTextWriterPtr writer,int* n)
{
	int err = -EINVAL;
	unsigned long rlm_id = cfg_sub_dt->target_rlm_id;
	int target = cfg_sub_dt->priv[0];
	rhp_vpn_auth_realm *auth_rlm = NULL;
  char realm_id_str[64];
  int n2;
  u8* cert_text = NULL;
  int cert_text_len = 0;

	RHP_TRC(0,RHPTRCID_SYSPXY_UI_GET_PRINTED_CERTS,"xxxxdud",cfg_sub_dt,cfg_sub_dt_rep,writer,n,*n,rlm_id,target);

  if( rlm_id == 0 || rlm_id > RHP_VPN_REALM_ID_MAX ){
  	RHP_TRC(0,RHPTRCID_SYSPXY_UI_GET_PRINTED_CERTS_NOT_PERMITTED,"xu",cfg_sub_dt,rlm_id);
  	err = -EPERM;
		goto error;
  }

  if( cfg_sub_dt->len < sizeof(rhp_ipcmsg_syspxy_cfg_sub) ){
  	err = -EINVAL;
  	RHP_BUG("");
  	goto error;
  }

  realm_id_str[0] = '\0';
  snprintf(realm_id_str,64,"%lu",rlm_id);

  auth_rlm = rhp_auth_realm_get(rlm_id);
  if( auth_rlm == NULL ){
		err = -ENOENT;
  	RHP_TRC(0,RHPTRCID_SYSPXY_UI_GET_PRINTED_CERTS_REALM_NOT_FOUND,"xu",cfg_sub_dt,rlm_id);
		goto error;
  }

	RHP_LOCK(&(auth_rlm->lock));
	{
		rhp_cert_store* cert_store;

		if( (auth_rlm->my_auth == NULL) ||
				((auth_rlm->my_auth->cert_store == NULL) && (auth_rlm->my_auth->cert_store_tmp == NULL)) ){
			err = -ENOENT;
	  	RHP_TRC(0,RHPTRCID_SYSPXY_UI_GET_PRINTED_CERTS_MY_AUTH_OR_CERT_STORE_NOT_FOUND,"xu",cfg_sub_dt,rlm_id);
			RHP_UNLOCK(&(auth_rlm->lock));
			goto error;
		}

		cert_store = auth_rlm->my_auth->cert_store;
		if( cert_store == NULL ){
			cert_store = auth_rlm->my_auth->cert_store_tmp;
	  	RHP_TRC(0,RHPTRCID_SYSPXY_UI_GET_PRINTED_CERTS_CERT_STORE_TMP_FOUND,"xux",cfg_sub_dt,rlm_id,cert_store);
		}

    n2 = xmlTextWriterStartElement(writer,(xmlChar*)"rhp_printed_certs");
    if(n2 < 0) {
      err = -ENOMEM;
      RHP_BUG("");
			RHP_UNLOCK(&(auth_rlm->lock));
      goto error;
    }
    *n += n2;


  	cfg_sub_dt_rep->priv[0] = target;
    if( target == RHP_IPC_SYSPXY_CFG_GET_PRINTED_CERTS_MY_CERT ){

    	err = cert_store->get_my_and_intermediate_ca_certs_printed_text(cert_store,&cert_text,&cert_text_len);

    }else if( target == RHP_IPC_SYSPXY_CFG_GET_PRINTED_CERTS_CA_CERTS ){

    	err = cert_store->get_ca_certs_printed_text(cert_store,&cert_text,&cert_text_len);

    }else if( target == RHP_IPC_SYSPXY_CFG_GET_PRINTED_CERTS_CRL ){

    	err = cert_store->get_crls_printed_text(cert_store,&cert_text,&cert_text_len);

    }else{
    	err = -EINVAL;
    	RHP_BUG("%d",target);
		}

    if( err ){
	  	RHP_TRC(0,RHPTRCID_SYSPXY_UI_GET_PRINTED_CERTS_FAIL_TO_GET_CERTS,"xuE",cfg_sub_dt,rlm_id,err);
			RHP_UNLOCK(&(auth_rlm->lock));
      goto error;
    }

	  n2 = xmlTextWriterWriteCDATA((xmlTextWriterPtr)writer,(xmlChar*)cert_text);
    if(n2 < 0) {
      err = -ENOMEM;
      RHP_BUG("");
			RHP_UNLOCK(&(auth_rlm->lock));
      goto error;
    }
    *n += n2;

		n2 = xmlTextWriterEndElement( (xmlTextWriterPtr) writer );
    if(n2 < 0) {
      err = -ENOMEM;
      RHP_BUG("");
			RHP_UNLOCK(&(auth_rlm->lock));
      goto error;
    }
    *n += n2;
	}
	RHP_UNLOCK(&(auth_rlm->lock));

	rhp_auth_realm_unhold(auth_rlm);

	_rhp_free(cert_text);

	RHP_TRC(0,RHPTRCID_SYSPXY_UI_GET_PRINTED_CERTS_RTRN,"xxxxdud",cfg_sub_dt,cfg_sub_dt_rep,writer,n,*n,rlm_id,target);
  return 0;

error:
	if( auth_rlm ){
		rhp_auth_realm_unhold(auth_rlm);
	}
	if( cert_text ){
		_rhp_free(cert_text);
	}
	RHP_TRC(0,RHPTRCID_SYSPXY_UI_GET_PRINTED_CERTS_ERR,"xxxxdudE",cfg_sub_dt,cfg_sub_dt_rep,writer,n,*n,rlm_id,target,err);
  return err;
}

static int  _rhp_syspxy_ui_update_admin_setup_node(xmlNodePtr new_admin_info_node,unsigned long rlm_id)
{
	int err = -EINVAL;
  rhp_crypto_prf* prf = NULL;
  u8* hashed_key = NULL;
  int hashed_key_len = 0;
  unsigned char* res_text = NULL;
	xmlChar* id = NULL;
	xmlChar* key = NULL;
	xmlAttrPtr key_attr = NULL;
  char realm_id_str[64];

	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_ADMIN_SETUP_NODE,"xu",new_admin_info_node,rlm_id);

  realm_id_str[0] = '\0';
  snprintf(realm_id_str,64,"%lu",rlm_id);

	id = rhp_xml_get_prop(new_admin_info_node,(xmlChar*)"id");
	if( id == NULL ){
		err = -EINVAL;
		RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_ADMIN_SETUP_NODE_ID_NOT_FOUND,"xu",new_admin_info_node,rlm_id);
		goto error;
	}

	key = rhp_xml_get_prop(new_admin_info_node,(xmlChar*)"key"); // NULL is OK.
	if( key == NULL ){
		RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_ADMIN_SETUP_NODE_KEY_NOT_FOUND,"xu",new_admin_info_node,rlm_id);
	}

	key_attr =	xmlHasProp(new_admin_info_node,(xmlChar*)"key"); // NULL is OK.


	if( xmlNewProp(new_admin_info_node,(xmlChar*)"prf_method",(xmlChar*)"hmac-sha1") == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}


	if( key ){

		prf  = rhp_crypto_prf_alloc(RHP_PROTO_IKE_TRANSFORM_ID_PRF_HMAC_SHA1);
		if( prf == NULL ){
			RHP_BUG("");
			err = -EINVAL;
			goto error;
		}

		err = _rhp_auth_hashed_auth_key(prf,(unsigned char*)id,strlen((char*)id)+1,
					 (unsigned char*)key,strlen((char*)key)+1,&hashed_key,&hashed_key_len);


		err = rhp_base64_encode(hashed_key,hashed_key_len,&res_text);
		if( err ){
			RHP_BUG("%d",err);
			goto error;
		}

		if( xmlNewProp(new_admin_info_node,(xmlChar*)"hashed_key",(xmlChar*)res_text) == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}
	}

	if( rlm_id ){

		if( xmlNewProp(new_admin_info_node,(xmlChar*)"vpn_realm",(xmlChar*)realm_id_str) == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

	}else{

		if( xmlNewProp(new_admin_info_node,(xmlChar*)"vpn_realm",(xmlChar*)"any") == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}
	}

	if( key_attr ){
		xmlRemoveProp(key_attr);
	}

	rhp_crypto_prf_free(prf);
	_rhp_free(hashed_key);
	_rhp_free(res_text);

	if( id ){
		_rhp_free(id);
	}
	if( key ){
		_rhp_free_zero(key,xmlStrlen(key));
	}

	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_ADMIN_SETUP_NODE_RTRN,"xu",new_admin_info_node,rlm_id);
	return 0;

error:
	if( prf ){
		rhp_crypto_prf_free(prf);
	}
	if( hashed_key ){
		_rhp_free(hashed_key);
	}
	if( res_text ){
		_rhp_free(res_text);
	}
	if( id ){
		_rhp_free(id);
	}
	if( key ){
		_rhp_free_zero(key,xmlStrlen(key));
	}
	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_ADMIN_SETUP_NODE_ERR,"xuE",new_admin_info_node,rlm_id,err);
	return err;
}

static int _rhp_syspxy_ui_update_admin(rhp_ipcmsg_syspxy_cfg_sub* cfg_sub_dt,
		rhp_ipcmsg_syspxy_cfg_sub* cfg_sub_dt_rep,xmlTextWriterPtr writer,int* n,
		char* opr_user_name,unsigned long opr_user_rlm_id)
{
  int err = -EINVAL;
  unsigned long tgt_rlm_id = cfg_sub_dt->target_rlm_id;
  xmlDocPtr upd_auth_doc = NULL;
  xmlDocPtr cfg_doc = NULL;
  xmlNodePtr cfg_root_node = NULL;
  xmlNodePtr upd_admin_node,old_admin_node = NULL;
  xmlChar *upd_admin_name = NULL,*upd_admin_key = NULL;
  rhp_auth_admin_info *new_admin_info = NULL;
  int is_su = 0;

	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_ADMIN,"xxxxdusu",cfg_sub_dt,cfg_sub_dt_rep,writer,n,*n,tgt_rlm_id,opr_user_name,opr_user_rlm_id);

  if( tgt_rlm_id > RHP_VPN_REALM_ID_MAX ){
  	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_ADMIN_NOT_PERMITTED,"xu",cfg_sub_dt,tgt_rlm_id);
  	err = -EPERM;
  	goto error;
  }

  if( cfg_sub_dt->len <= sizeof(rhp_ipcmsg_syspxy_cfg_sub) ){
  	err = -EINVAL;
  	RHP_BUG("");
  	goto error;
  }

  if( !strcmp(opr_user_name,"admin") ){

  	if( opr_user_rlm_id != 0 ){
  		RHP_BUG("%lu",opr_user_rlm_id);
    	err = -EINVAL;
    	goto error;
  	}

  	is_su = 1;
  }

  {
  	upd_auth_doc = xmlParseMemory((void*)(cfg_sub_dt + 1),(cfg_sub_dt->len - sizeof(rhp_ipcmsg_syspxy_cfg_sub)));
  	if( upd_auth_doc == NULL ){
  		err = -EINVAL;
  		RHP_BUG("");
  		goto error;
  	}

  	upd_admin_node = xmlDocGetRootElement(upd_auth_doc);
  	if( upd_admin_node == NULL ){
  		err = -EINVAL;
  		RHP_BUG("");
  		goto error;
  	}

  	if( xmlStrcmp(upd_admin_node->name,(xmlChar*)"admin") ){ // Here, 'admin' is the element name(tag).
  		err = -EINVAL;
    	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_ADMIN_INVALID_ADMIN_TAG,"xus",cfg_sub_dt,tgt_rlm_id,upd_admin_node->name);
  		goto error;
  	}
  }

  upd_admin_name = rhp_xml_get_prop(upd_admin_node,(xmlChar*)"id");
  if( upd_admin_name == NULL ){
  	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_ADMIN_ID_NOT_FOUND,"xu",cfg_sub_dt,tgt_rlm_id);
  	err = -EINVAL;
  	goto error;
  }

  upd_admin_key = rhp_xml_get_prop(upd_admin_node,(xmlChar*)"key"); // NULL is OK.


  if( !xmlStrcmp(upd_admin_name,(xmlChar*)"admin") && !is_su  ){ // Like root (superuser) ...
  	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_ADMIN_INVALID_ADMIN_ID_AS_SUPER_USER,"xu",cfg_sub_dt,tgt_rlm_id);
  	err = -EPERM;
  	goto error;
  }


  RHP_LOCK(&(rhp_auth_lock));
  {
		rhp_auth_admin_info* upd_admin_info
		= rhp_auth_admin_get((char*)upd_admin_name,(unsigned int)(xmlStrlen(upd_admin_name) + 1));

		if( upd_admin_info &&
				upd_admin_info->vpn_realm_id == 0 &&
				!is_su &&
				strcmp((char*)upd_admin_name,opr_user_name) ){

			RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_ADMIN_NOT_PERMITTED2,"xu",cfg_sub_dt,tgt_rlm_id);
	  	err = -EPERM;
	  	RHP_UNLOCK(&(rhp_auth_lock));
	  	goto error;
		}

		if( upd_admin_key == NULL ){

			if( upd_admin_info == NULL || upd_admin_info->hashed_key_base64 == NULL ){
				RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_ADMIN_NOT_PERMITTED3,"xu",cfg_sub_dt,tgt_rlm_id);
				err = -EINVAL;
				RHP_UNLOCK(&(rhp_auth_lock));
				goto error;
			}

			upd_admin_key = (xmlChar*)_rhp_malloc(strlen(upd_admin_info->hashed_key_base64) + 1);
			if( upd_admin_key == NULL ){
				RHP_BUG("");
				err = -ENOMEM;
				RHP_UNLOCK(&(rhp_auth_lock));
				goto error;
			}

			upd_admin_info->hashed_key_base64[0] = '\0';
			strcpy((char*)upd_admin_key,upd_admin_info->hashed_key_base64);
		}
  }
  RHP_UNLOCK(&(rhp_auth_lock));


  err = _rhp_syspxy_ui_update_admin_setup_node(upd_admin_node,tgt_rlm_id);
  if( err ){
  	RHP_BUG("");
  	goto error;
  }


  //
  // [CAUTION]
  // 	Don't access upd_admin_key anymore.
  //
  // upd_admin_key: hashed base64-encoded string, if any.
  //
  new_admin_info = rhp_auth_parse_admin(upd_admin_node,NULL,(char**)&upd_admin_key);
  if( new_admin_info == NULL ){
  	err = -EINVAL;
  	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_ADMIN_PARSE_ERR,"xu",cfg_sub_dt,tgt_rlm_id);
  	goto error;
  }


  RHP_LOCK(&(rhp_auth_lock));
  {
  	rhp_auth_admin_replace(new_admin_info);
  }
  RHP_UNLOCK(&(rhp_auth_lock));


  {
    cfg_doc = xmlParseFile(rhp_syspxy_auth_conf_path);
    if( cfg_doc == NULL ){
      RHP_BUG(" %s ",rhp_syspxy_auth_conf_path);
      goto error;
    }

    cfg_root_node = xmlDocGetRootElement(cfg_doc);
    if( cfg_root_node == NULL ){
      RHP_BUG(" %s ",rhp_syspxy_auth_conf_path);
      goto error;
    }
  }

  {
    xmlNodePtr dup_node;

    old_admin_node
    = rhp_xml_search_prop_value_in_children(cfg_root_node,(xmlChar*)"admin",(xmlChar*)"id",upd_admin_name);

    dup_node = xmlCopyNode(upd_admin_node,1);
    if( dup_node == NULL ){
    	RHP_BUG("");
      err = -ENOMEM;
      goto error;
    }

    if( xmlAddChild(cfg_root_node,dup_node) == NULL ){
      err = -EINVAL;
      RHP_BUG("");
      xmlFreeNode(dup_node);
      goto error;
    }

    if( old_admin_node ){
      xmlUnlinkNode(old_admin_node);
      xmlFreeNode(old_admin_node);
    }

    err = rhp_cfg_save_config(rhp_syspxy_auth_conf_path,cfg_doc);
    if( err ){
      RHP_BUG("%d",err);
    }
  }

  if( !err ){
  	RHP_LOG_I(RHP_LOG_SRC_UI,0,RHP_LOG_ID_UI_UPDATE_ADMIN,"su",upd_admin_name,tgt_rlm_id);
  }else{
  	RHP_LOG_E(RHP_LOG_SRC_UI,0,RHP_LOG_ID_UI_UPDATE_ADMIN_ERR,"suE",upd_admin_name,tgt_rlm_id,err);
  }

  if( upd_auth_doc ){
	  xmlFreeDoc(upd_auth_doc);
  }

  if( upd_admin_name ){
  	_rhp_free(upd_admin_name);
  }
  if( upd_admin_key ){
  	_rhp_free_zero(upd_admin_key,xmlStrlen(upd_admin_key));
  }

  xmlFreeDoc(cfg_doc);

	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_ADMIN_RTRN,"xxxxdu",cfg_sub_dt,cfg_sub_dt_rep,writer,n,*n,tgt_rlm_id);
  return 0;

error:
	RHP_LOG_E(RHP_LOG_SRC_UI,0,RHP_LOG_ID_UI_UPDATE_ADMIN_ERR,"suE",upd_admin_name,tgt_rlm_id,err);
  if( upd_auth_doc ){
  	xmlFreeDoc(upd_auth_doc);
  }
  if( cfg_doc ){
    xmlFreeDoc(cfg_doc);
  }
  if( upd_admin_name ){
  	_rhp_free(upd_admin_name);
  }
  if( upd_admin_key ){
  	_rhp_free_zero(upd_admin_key,xmlStrlen(upd_admin_key));
  }
	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_ADMIN_ERR,"xxxxduE",cfg_sub_dt,cfg_sub_dt_rep,writer,n,*n,tgt_rlm_id,err);
  return err;
}

static int _rhp_syspxy_ui_update_realm_admin(rhp_ipcmsg_syspxy_cfg_sub* cfg_sub_dt,
		rhp_ipcmsg_syspxy_cfg_sub* cfg_sub_dt_rep,xmlTextWriterPtr writer,int* n,
		char* opr_user_name,unsigned long opr_user_rlm_id)
{
  int err = -EINVAL;
  unsigned long tgt_rlm_id = cfg_sub_dt->target_rlm_id;
  xmlDocPtr upd_auth_doc = NULL;
  xmlDocPtr cfg_doc = NULL;
  xmlNodePtr cfg_root_node = NULL;
  xmlNodePtr upd_admin_node = NULL, old_admin_node = NULL;
  xmlChar *upd_admin_name = NULL,*upd_admin_key = NULL;
	xmlAttrPtr key_attr = NULL;

	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_REALM_ADMIN,"xxxxdusu",cfg_sub_dt,cfg_sub_dt_rep,writer,n,*n,tgt_rlm_id,opr_user_name,opr_user_rlm_id);

  if( tgt_rlm_id > RHP_VPN_REALM_ID_MAX ){
  	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_REALM_ADMIN_NOT_PERMITTED,"xu",cfg_sub_dt,tgt_rlm_id);
  	err = -EPERM;
  	goto error;
  }

  if( cfg_sub_dt->len <= sizeof(rhp_ipcmsg_syspxy_cfg_sub) ){
  	err = -EINVAL;
  	RHP_BUG("");
  	goto error;
  }

  if( opr_user_rlm_id && (tgt_rlm_id != opr_user_rlm_id) ){
  	err = -EINVAL;
  	RHP_BUG("%lu , %lu",tgt_rlm_id,opr_user_rlm_id);
  	goto error;
  }

  {
  	upd_auth_doc = xmlParseMemory((void*)(cfg_sub_dt + 1),(cfg_sub_dt->len - sizeof(rhp_ipcmsg_syspxy_cfg_sub)));
  	if( upd_auth_doc == NULL ){
  		err = -EINVAL;
  		RHP_BUG("");
  		goto error;
  	}

  	upd_admin_node = xmlDocGetRootElement(upd_auth_doc);
  	if( upd_admin_node == NULL ){
  		err = -EINVAL;
  		RHP_BUG("");
  		goto error;
  	}

  	if( xmlStrcmp(upd_admin_node->name,(xmlChar*)"admin") ){ // Here, 'admin' is the element name(tag).
  		err = -EINVAL;
    	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_REALM_ADMIN_INVALID_ADMIN_TAG,"xus",cfg_sub_dt,tgt_rlm_id,upd_admin_node->name);
  		goto error;
  	}
  }

  upd_admin_name = rhp_xml_get_prop(upd_admin_node,(xmlChar*)"id");
  if( upd_admin_name == NULL ){
  	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_REALM_ADMIN_ID_NOT_FOUND,"xu",cfg_sub_dt,tgt_rlm_id);
  	err = -EINVAL;
  	goto error;
  }

  upd_admin_key = rhp_xml_get_prop(upd_admin_node,(xmlChar*)"key");
  if( upd_admin_key == NULL ){
  	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_REALM_ADMIN_KEY_NOT_FOUND,"xu",cfg_sub_dt,tgt_rlm_id);
  	err = -EINVAL;
  	goto error;
  }

  if( !xmlStrcmp(upd_admin_name,(xmlChar*)"admin") ){ // Like root (superuser) ...
  	RHP_BUG("");
  	err = -EPERM;
  	goto error;
  }


  {
    cfg_doc = xmlParseFile(rhp_syspxy_auth_conf_path);
    if( cfg_doc == NULL ){
      RHP_BUG(" %s ",rhp_syspxy_auth_conf_path);
      goto error;
    }

    cfg_root_node = xmlDocGetRootElement(cfg_doc);
    if( cfg_root_node == NULL ){
      RHP_BUG(" %s ",rhp_syspxy_auth_conf_path);
      goto error;
    }
  }

  {
  	old_admin_node
    = rhp_xml_search_prop_value_in_children(cfg_root_node,(xmlChar*)"admin",(xmlChar*)"id",upd_admin_name);

    RHP_LOCK(&(rhp_auth_lock));
    {
  		rhp_auth_admin_info* upd_admin_info
  		= rhp_auth_admin_get((char*)upd_admin_name,(unsigned int)(xmlStrlen(upd_admin_name) + 1));

  		if( upd_admin_info == NULL ){
  			RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_REALM_ADMIN_NO_ADMIN_INFO,"xu",cfg_sub_dt,tgt_rlm_id);
  	  	err = -EPERM;
  	  	RHP_UNLOCK(&(rhp_auth_lock));
  	  	goto error;
  		}

  		err = rhp_auth_admin_replace_key(upd_admin_info,(char*)upd_admin_key);
  		if( err ){
  	  	RHP_UNLOCK(&(rhp_auth_lock));
  	  	goto error;
  		}

    	key_attr = xmlHasProp(old_admin_node,(xmlChar*)"hashed_key");
    	if( key_attr ){
    		xmlRemoveProp(key_attr);
    	}

  		if( xmlNewProp(old_admin_node,(xmlChar*)"hashed_key",(xmlChar*)upd_admin_info->hashed_key_base64) == NULL ){
  	  	RHP_UNLOCK(&(rhp_auth_lock));
  			RHP_BUG("");
  			err = -ENOMEM;
  			goto error;
  		}
    }
    RHP_UNLOCK(&(rhp_auth_lock));


    err = rhp_cfg_save_config(rhp_syspxy_auth_conf_path,cfg_doc);
    if( err ){
      RHP_BUG("%d",err);
    }
  }

  if( !err ){
  	RHP_LOG_I(RHP_LOG_SRC_UI,0,RHP_LOG_ID_UI_UPDATE_ADMIN,"su",upd_admin_name,tgt_rlm_id);
  }else{
  	RHP_LOG_E(RHP_LOG_SRC_UI,0,RHP_LOG_ID_UI_UPDATE_ADMIN_ERR,"suE",upd_admin_name,tgt_rlm_id,err);
  }

  if( upd_auth_doc ){
	  xmlFreeDoc(upd_auth_doc);
  }

  if( upd_admin_name ){
  	_rhp_free(upd_admin_name);
  }
  if( upd_admin_key ){
  	_rhp_free_zero(upd_admin_key,xmlStrlen(upd_admin_key));
  }

  xmlFreeDoc(cfg_doc);

	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_REALM_ADMIN_RTRN,"xxxxdu",cfg_sub_dt,cfg_sub_dt_rep,writer,n,*n,tgt_rlm_id);
  return 0;

error:
	RHP_LOG_E(RHP_LOG_SRC_UI,0,RHP_LOG_ID_UI_UPDATE_ADMIN_ERR,"suE",upd_admin_name,tgt_rlm_id,err);
  if( upd_auth_doc ){
  	xmlFreeDoc(upd_auth_doc);
  }
  if( cfg_doc ){
    xmlFreeDoc(cfg_doc);
  }
  if( upd_admin_name ){
  	_rhp_free(upd_admin_name);
  }
  if( upd_admin_key ){
  	_rhp_free_zero(upd_admin_key,xmlStrlen(upd_admin_key));
  }
	RHP_TRC(0,RHPTRCID_SYSPXY_UI_UPDATE_REALM_ADMIN_ERR,"xxxxduE",cfg_sub_dt,cfg_sub_dt_rep,writer,n,*n,tgt_rlm_id,err);
  return err;
}

static int _rhp_syspxy_ui_delete_admin(rhp_ipcmsg_syspxy_cfg_sub* cfg_sub_dt,
		rhp_ipcmsg_syspxy_cfg_sub* cfg_sub_dt_rep,xmlTextWriterPtr writer,int* n,
		char* opr_user_name,unsigned long opr_user_rlm_id)
{
  int err = -EINVAL;
  xmlDocPtr del_auth_doc = NULL;
  xmlDocPtr cfg_doc = NULL;
  xmlNodePtr cfg_root_node = NULL;
  xmlNodePtr del_admin_node,old_admin_node = NULL;
  xmlChar* del_admin_name = NULL;
  int is_su = 0;

	RHP_TRC(0,RHPTRCID_SYSPXY_UI_DELETE_ADMIN,"xxxxdsu",cfg_sub_dt,cfg_sub_dt_rep,writer,n,*n,opr_user_name,opr_user_rlm_id);


  if( cfg_sub_dt->len <= sizeof(rhp_ipcmsg_syspxy_cfg_sub) ){
  	err = -EINVAL;
  	RHP_BUG("");
  	goto error;
  }

  if( !strcmp(opr_user_name,"admin") ){

  	if( opr_user_rlm_id != 0 ){
  		RHP_BUG("%lu",opr_user_rlm_id);
    	err = -EINVAL;
    	goto error;
  	}

  	is_su = 1;
  }

  {
  	del_auth_doc = xmlParseMemory((void*)(cfg_sub_dt + 1),(cfg_sub_dt->len - sizeof(rhp_ipcmsg_syspxy_cfg_sub)));
  	if( del_auth_doc == NULL ){
      err = -EINVAL;
      RHP_BUG("");
      goto error;
  	}

  	del_admin_node = xmlDocGetRootElement(del_auth_doc);
  	if( del_admin_node == NULL ){
      err = -EINVAL;
      RHP_BUG("");
      goto error;
  	}

  	if( xmlStrcmp(del_admin_node->name,(xmlChar*)"admin") ){ // Here, 'admin' is the element name(tag).
    	RHP_TRC(0,RHPTRCID_SYSPXY_UI_DELETE_ADMIN_INVALID_ADMIN_TAG,"xs",cfg_sub_dt,del_admin_node->name);
      err = -EINVAL;
      goto error;
  	}
  }

  del_admin_name = rhp_xml_get_prop(del_admin_node,(xmlChar*)"id");
  if( del_admin_name == NULL ){
  	RHP_TRC(0,RHPTRCID_SYSPXY_UI_DELETE_ADMIN_ID_NOT_FOUND,"x",cfg_sub_dt);
  	err = -EINVAL;
  	goto error;
  }

  if( !xmlStrcmp(del_admin_name,(xmlChar*)"admin") ){ // Like root (superuser) ....
  	RHP_TRC(0,RHPTRCID_SYSPXY_UI_DELETE_ADMIN_NOT_PERMITTED2,"x",cfg_sub_dt);
  	err = -EINVAL;
  	goto error;
  }

  RHP_LOCK(&(rhp_auth_lock));
  {
		rhp_auth_admin_info* del_admin_info
		= rhp_auth_admin_get((char*)del_admin_name,(unsigned int)(xmlStrlen(del_admin_name) + 1));

		if( del_admin_info == NULL ){

			RHP_TRC(0,RHPTRCID_SYSPXY_UI_DELETE_ADMIN_NO_ENT,"x",cfg_sub_dt);
			err = -ENOENT;
			RHP_UNLOCK(&(rhp_auth_lock));
			goto error;

		}else{

			if( del_admin_info->vpn_realm_id == 0 &&
					!is_su &&
					strcmp((char*)del_admin_name,opr_user_name) ){

				RHP_TRC(0,RHPTRCID_SYSPXY_UI_DELETE_ADMIN_NOT_PERMITTED3,"x",cfg_sub_dt);
				err = -EPERM;
				RHP_UNLOCK(&(rhp_auth_lock));
				goto error;
			}
		}

  	rhp_auth_admin_delete((char*)del_admin_name);
  }
  RHP_UNLOCK(&(rhp_auth_lock));


  {
      cfg_doc = xmlParseFile(rhp_syspxy_auth_conf_path);
      if( cfg_doc == NULL ){
          RHP_BUG(" %s ",rhp_syspxy_auth_conf_path);
          goto error;
      }

      cfg_root_node = xmlDocGetRootElement(cfg_doc);
      if( cfg_root_node == NULL ){
          RHP_BUG(" %s ",rhp_syspxy_auth_conf_path);
          goto error;
      }
  }

  {
    old_admin_node = rhp_xml_search_prop_value_in_children(cfg_root_node,
    		(xmlChar*)"admin",(xmlChar*)"id",del_admin_name);

    if( old_admin_node ){

    	xmlUnlinkNode(old_admin_node);
      xmlFreeNode(old_admin_node);

      err = rhp_cfg_save_config(rhp_syspxy_auth_conf_path,cfg_doc);
      if( err ){
      	RHP_BUG("%d",err);
      }
    }
  }

	RHP_LOG_I(RHP_LOG_SRC_UI,0,RHP_LOG_ID_UI_DELETE_ADMIN,"s",del_admin_name);

  if( del_auth_doc ){
    xmlFreeDoc(del_auth_doc);
  }

  if( del_admin_name ){
  	_rhp_free(del_admin_name);
  }

  xmlFreeDoc(cfg_doc);

	RHP_TRC(0,RHPTRCID_SYSPXY_UI_DELETE_ADMIN_RTRN,"xxxxd",cfg_sub_dt,cfg_sub_dt_rep,writer,n,*n);
  return 0;

error:
	RHP_LOG_E(RHP_LOG_SRC_UI,0,RHP_LOG_ID_UI_DELETE_ADMIN_ERR,"sE",del_admin_name,err);
  if( del_auth_doc ){
    xmlFreeDoc(del_auth_doc);
  }
  if( cfg_doc ){
    xmlFreeDoc(cfg_doc);
  }
  if( del_admin_name ){
  	_rhp_free(del_admin_name);
  }
	RHP_TRC(0,RHPTRCID_SYSPXY_UI_DELETE_ADMIN_ERR,"xxxxdE",cfg_sub_dt,cfg_sub_dt_rep,writer,n,*n,err);
  return err;
}

static int _rhp_syspxy_ui_enum_admin(rhp_ipcmsg_syspxy_cfg_sub* cfg_sub_dt,
		rhp_ipcmsg_syspxy_cfg_sub* cfg_sub_dt_rep,xmlTextWriterPtr writer,int* n,
		unsigned long opr_user_rlm_id)
{
  int err = -EINVAL;
  int n2;

	RHP_TRC(0,RHPTRCID_SYSPXY_UI_ENUM_ADMIN,"xxxxdu",cfg_sub_dt,cfg_sub_dt_rep,writer,n,*n,opr_user_rlm_id);

  if( opr_user_rlm_id > RHP_VPN_REALM_ID_MAX ){
  	RHP_TRC(0,RHPTRCID_SYSPXY_UI_ENUM_ADMIN_NOT_PERMITTED,"xu",cfg_sub_dt,opr_user_rlm_id);
  	err = -EPERM;
  	goto error;
  }

  RHP_LOCK(&(rhp_auth_lock));
  {
  	rhp_auth_admin_info* admin_info = rhp_auth_admin_head;

  	while( admin_info ){

  		if( (opr_user_rlm_id == 0 ||
  				 opr_user_rlm_id == admin_info->vpn_realm_id) && !admin_info->is_nobody ){

  			n2 = xmlTextWriterStartElement(writer,(xmlChar*)"admin");
				if(n2 < 0) {
					err = -ENOMEM;
					RHP_BUG("");
					goto error_l;
				}
				*n += n2;

				n2 = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"id","%s",admin_info->id);
				if(n2 < 0) {
					err = -ENOMEM;
					RHP_BUG("");
					goto error_l;
				}
				*n += n2;

				if( admin_info->vpn_realm_id == 0 ){
					n2 = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"vpn_realm","%s","any");
				}else{
					n2 = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"vpn_realm","%lu",admin_info->vpn_realm_id);
				}
				if(n2 < 0) {
					err = -ENOMEM;
					RHP_BUG("");
					goto error_l;
				}
				*n += n2;

				n2 = xmlTextWriterEndElement( (xmlTextWriterPtr) writer );
				if(n2 < 0) {
					err = -ENOMEM;
					RHP_BUG("");
					goto error_l;
				}
				*n += n2;
  		}

  		admin_info = admin_info->next_list;
  	}
  }
  RHP_UNLOCK(&(rhp_auth_lock));

	RHP_TRC(0,RHPTRCID_SYSPXY_UI_ENUM_ADMIN_RTRN,"xxxxdu",cfg_sub_dt,cfg_sub_dt_rep,writer,n,*n,opr_user_rlm_id);
  return 0;

error_l:
	RHP_UNLOCK(&(rhp_auth_lock));
error:
	RHP_TRC(0,RHPTRCID_SYSPXY_UI_ENUM_ADMIN_ERR,"xxxxduE",cfg_sub_dt,cfg_sub_dt_rep,writer,n,*n,opr_user_rlm_id,err);
  return err;
}


static int _rhp_syspxy_ui_cfg_bkup_save(rhp_ipcmsg_syspxy_cfg_sub* cfg_sub_dt,
		rhp_ipcmsg_syspxy_cfg_sub* cfg_sub_dt_rep,xmlTextWriterPtr writer,int* n2,
		char* opr_user_name,unsigned long opr_user_rlm_id)
{
	int err = -EINVAL;
	u8* file_pw = NULL;
	int file_pw_len = cfg_sub_dt->len - sizeof(rhp_ipcmsg_syspxy_cfg_sub);
  char *pw_path = NULL, *pw_cont = NULL;
	rhp_cmd_tlv_list tlvlst;

  RHP_TRC(0,RHPTRCID_SYSPXY_UI_CFG_BKUP_SAVE,"xxxxdsu",cfg_sub_dt,cfg_sub_dt_rep,writer,n2,*n2,opr_user_name,opr_user_rlm_id);

	memset(&tlvlst,0,sizeof(rhp_cmd_tlv_list));

  if( opr_user_rlm_id != 0 ){
    RHP_TRC(0,RHPTRCID_SYSPXY_UI_CFG_BKUP_SAVE_NOT_PERMITTED,"xu",cfg_sub_dt,opr_user_rlm_id);
  	err = -EPERM;
		goto error;
  }

  file_pw = (u8*)(cfg_sub_dt + 1);
  if( file_pw[file_pw_len - 1] != '\0' ){
  	RHP_BUG("");
  	err = -EINVAL;
  	goto error;
  }

  {
		pw_path = (char*)_rhp_malloc( strlen(rhp_syspxy_home_dir) + strlen("/tmp/rockhopper_rcfg_save_pw") + 1 );
		if( pw_path == NULL ){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		pw_path[0] = '\0';

		sprintf(pw_path,"%s/%s",rhp_syspxy_home_dir,"tmp/rockhopper_rcfg_save_pw");

		unlink(pw_path);


		pw_cont = (char*)_rhp_malloc( (file_pw_len - 1)*2 + 4 );
		if( pw_cont == NULL ){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		pw_cont[0] = '\0';

		sprintf(pw_cont,"%s\n%s\n",file_pw,file_pw);


		err = rhp_file_write(pw_path,(u8*)pw_cont,strlen(pw_cont),(S_IRUSR | S_IWUSR | S_IXUSR));
		if( err ){
			RHP_BUG("%d",err);
			goto error;
		}
	}

	{
		err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_STRING,"RHP_CFG_BKUP_PW",(strlen(pw_path) + 1),pw_path);
		if( err ){
			RHP_BUG("");
			goto error;
		}

		err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_STRING,"RHP_CFG_BKUP_RES_DIR",
				(strlen(rhp_syspxy_cfg_bkup_path) + 1),rhp_syspxy_cfg_bkup_path);

		if( err ){
			RHP_BUG("");
			goto error;
		}

		err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_STRING,"RHP_CFG_BKUP_HOME_DIR",
				(strlen(rhp_syspxy_home_dir) + 1),rhp_syspxy_home_dir);

		if( err ){
			RHP_BUG("");
			goto error;
		}

		err = rhp_cmd_exec(rhp_syspxy_cfg_bkup_cmd_path,&tlvlst,1);
		if( err ){
			RHP_BUG("%d",err);
			goto error;
		}

		rhp_cmd_tlv_clear(&tlvlst);
	}

	unlink(pw_path);
	_rhp_free(pw_path);
	_rhp_free(pw_cont);

  RHP_TRC(0,RHPTRCID_SYSPXY_UI_CFG_BKUP_SAVE_RTRN,"x",cfg_sub_dt);
  return 0;

error:
	if( pw_path ){
		unlink(pw_path);
		_rhp_free(pw_path);
	}
	if( pw_cont ){
		_rhp_free(pw_cont);
	}
	rhp_cmd_tlv_clear(&tlvlst);

	RHP_TRC(0,RHPTRCID_SYSPXY_UI_CFG_BKUP_SAVE_ERR,"xE",cfg_sub_dt,err);
	return err;
}

static int _rhp_syspxy_ui_cfg_reset_qcd_key(rhp_ipcmsg_syspxy_cfg_sub* cfg_sub_dt,
		rhp_ipcmsg_syspxy_cfg_sub* cfg_sub_dt_rep,xmlTextWriterPtr writer,int* n2,
		char* opr_user_name,unsigned long opr_user_rlm_id)
{
	int err = -EINVAL;
	rhp_cmd_tlv_list tlvlst;

  RHP_TRC(0,RHPTRCID_SYSPXY_UI_CFG_RESET_QCD_KEY,"xxxxdsu",cfg_sub_dt,cfg_sub_dt_rep,writer,n2,*n2,opr_user_name,opr_user_rlm_id);

	memset(&tlvlst,0,sizeof(rhp_cmd_tlv_list));

  if( opr_user_rlm_id != 0 ){
    RHP_TRC(0,RHPTRCID_SYSPXY_UI_CFG_RESET_QCD_KEY_NOT_PERMITTED,"xu",cfg_sub_dt,opr_user_rlm_id);
  	err = -EPERM;
		goto error;
  }

	{
  	err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_STRING,"RHP_ACTION",
  					(strlen("MNG_RESET_QCD_KEY") + 1),"MNG_RESET_QCD_KEY");
  	if( err ){
  		RHP_BUG("");
  		goto error;
  	}

		err = rhp_cmd_exec(rhp_mng_cmd_path,&tlvlst,1);
		if( err ){
			RHP_BUG("%d",err);
			goto error;
		}

		rhp_cmd_tlv_clear(&tlvlst);
	}

  RHP_TRC(0,RHPTRCID_SYSPXY_UI_CFG_RESET_QCD_KEY_RTRN,"x",cfg_sub_dt);
  return 0;

error:
	rhp_cmd_tlv_clear(&tlvlst);

	RHP_TRC(0,RHPTRCID_SYSPXY_UI_CFG_RESET_QCD_KEY_ERR,"xE",cfg_sub_dt,err);
	return err;
}

static int _rhp_syspxy_ui_cfg_reset_sess_resume_key(rhp_ipcmsg_syspxy_cfg_sub* cfg_sub_dt,
		rhp_ipcmsg_syspxy_cfg_sub* cfg_sub_dt_rep,xmlTextWriterPtr writer,int* n2,
		char* opr_user_name,unsigned long opr_user_rlm_id)
{
	int err = -EINVAL;
	rhp_cmd_tlv_list tlvlst;

  RHP_TRC(0,RHPTRCID_SYSPXY_UI_CFG_RESET_SESS_RESUME_KEY,"xxxxdsu",cfg_sub_dt,cfg_sub_dt_rep,writer,n2,*n2,opr_user_name,opr_user_rlm_id);

	memset(&tlvlst,0,sizeof(rhp_cmd_tlv_list));

  if( opr_user_rlm_id != 0 ){
    RHP_TRC(0,RHPTRCID_SYSPXY_UI_CFG_RESET_SESS_RESUME_KEY_NOT_PERMITTED,"xu",cfg_sub_dt,opr_user_rlm_id);
  	err = -EPERM;
		goto error;
  }

	{
  	err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_STRING,"RHP_ACTION",
  					(strlen("MNG_RESET_SESS_RESUME_KEY") + 1),"MNG_RESET_SESS_RESUME_KEY");
  	if( err ){
  		RHP_BUG("");
  		goto error;
  	}

		err = rhp_cmd_exec(rhp_mng_cmd_path,&tlvlst,1);
		if( err ){
			RHP_BUG("%d",err);
			goto error;
		}

		rhp_cmd_tlv_clear(&tlvlst);
	}

  RHP_TRC(0,RHPTRCID_SYSPXY_UI_CFG_RESET_SESS_RESUME_KEY_RTRN,"x",cfg_sub_dt);
  return 0;

error:
	rhp_cmd_tlv_clear(&tlvlst);

	RHP_TRC(0,RHPTRCID_SYSPXY_UI_CFG_RESET_SESS_RESUME_KEY_ERR,"xE",cfg_sub_dt,err);
	return err;
}

static int _rhp_syspxy_ui_upload_cert(rhp_ipcmsg_syspxy_cfg_sub* cfg_sub_dt,
		rhp_ipcmsg_syspxy_cfg_sub* cfg_sub_dt_rep,xmlTextWriterPtr writer,int* n2)
{
	int err = -EINVAL;
	unsigned long rlm_id = cfg_sub_dt->target_rlm_id;
	u8* file_pw = NULL;
	int file_pw_len = cfg_sub_dt->len - sizeof(rhp_ipcmsg_syspxy_cfg_sub);
  char *pw_path = NULL, *pw_cont = NULL;
	rhp_cmd_tlv_list tlvlst;
	int free_pw_str = 0;
	long accept_expired_cert = (long)cfg_sub_dt->priv[1];

  RHP_TRC(0,RHPTRCID_SYSPXY_UI_CFG_UPLOAD_CERT,"xxxxdud",cfg_sub_dt,cfg_sub_dt_rep,writer,n2,*n2,rlm_id,(int)accept_expired_cert);

	memset(&tlvlst,0,sizeof(rhp_cmd_tlv_list));

  if( rlm_id == 0 ){
    RHP_TRC(0,RHPTRCID_SYSPXY_UI_CFG_UPLOAD_CERT_NOT_PERMITTED,"xu",cfg_sub_dt,rlm_id);
  	err = -EPERM;
		goto error;
  }

  if( file_pw_len ){

  	file_pw = (u8*)(cfg_sub_dt + 1);
		if( file_pw[file_pw_len - 1] != '\0' ){
			RHP_BUG("");
			err = -EINVAL;
			goto error;
		}

  }else{

  	rhp_vpn_auth_realm* auth_rlm = rhp_auth_realm_get(rlm_id);
    if( auth_rlm ){

			RHP_LOCK(&(auth_rlm->lock));
			{
				if( auth_rlm->my_auth && auth_rlm->my_auth->rsa_priv_key_pw ){

					file_pw_len = strlen((char*)auth_rlm->my_auth->rsa_priv_key_pw) + 1;
					file_pw = auth_rlm->my_auth->rsa_priv_key_pw;

					auth_rlm->my_auth->rsa_priv_key_pw = NULL;

					free_pw_str = 1;
				}
			}
			RHP_UNLOCK(&(auth_rlm->lock));

	    RHP_TRC(0,RHPTRCID_SYSPXY_UI_CFG_UPLOAD_CERT_USE_RSA_PRIV_KEY_PLACEHOLDER,"xuxxds",cfg_sub_dt,rlm_id,auth_rlm,auth_rlm->my_auth,file_pw_len,file_pw);
	    rhp_auth_realm_unhold(auth_rlm);
    }
  }

	if( file_pw_len ){

		pw_path = (char*)_rhp_malloc( strlen(rhp_syspxy_home_dir) + strlen("/tmp/rockhopper_cert_update_pw") + 1 );
		if( pw_path == NULL ){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		pw_path[0] = '\0';

		sprintf(pw_path,"%s/%s",rhp_syspxy_home_dir,"tmp/rockhopper_cert_update_pw");

		unlink(pw_path);


		pw_cont = (char*)_rhp_malloc( (file_pw_len - 1)*2 + 4 );
		if( pw_cont == NULL ){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		pw_cont[0] = '\0';

		sprintf(pw_cont,"%s\n%s\n",file_pw,file_pw);


		err = rhp_file_write(pw_path,(u8*)pw_cont,strlen(pw_cont),(S_IRUSR | S_IWUSR | S_IXUSR));
		if( err ){
			RHP_BUG("%d",err);
			goto error;
		}
	}

	{
		err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_ULONG,"RHP_CFG_CERT_FILE_REALM",sizeof(rlm_id),&rlm_id);
		if( err ){
			RHP_BUG("");
			goto error;
		}

		if( pw_path ){

			err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_STRING,"RHP_CFG_CERT_FILE_PW",(strlen(pw_path) + 1),pw_path);
			if( err ){
				RHP_BUG("");
				goto error;
			}
		}

		err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_STRING,"RHP_CFG_CERT_FILE_UPLOADED_DIR",
				(strlen(rhp_syspxy_cfg_cert_uploaded_path) + 1),rhp_syspxy_cfg_cert_uploaded_path);

		if( err ){
			RHP_BUG("");
			goto error;
		}

		err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_STRING,"RHP_CFG_CERT_FILE_HOME_DIR",
				(strlen(rhp_syspxy_home_dir) + 1),rhp_syspxy_home_dir);

		if( err ){
			RHP_BUG("");
			goto error;
		}

		err = rhp_cmd_exec(rhp_syspxy_cfg_cert_cmd_path,&tlvlst,1);
		if( err ){
		  RHP_TRC(0,RHPTRCID_SYSPXY_UI_CFG_UPLOAD_CERT_CMD_EXEC_ERR,"xuE",cfg_sub_dt,rlm_id,err);
			goto error;
		}

		rhp_cmd_tlv_clear(&tlvlst);
	}


	if( accept_expired_cert != -1 ){

		rhp_vpn_auth_realm* auth_rlm = rhp_auth_realm_get(rlm_id);
		if( auth_rlm ){

			RHP_LOCK(&(auth_rlm->lock));
			{
				auth_rlm->accept_expired_cert = accept_expired_cert;
			}
			RHP_UNLOCK(&(auth_rlm->lock));

			RHP_TRC(0,RHPTRCID_SYSPXY_UI_CFG_UPLOAD_CERT_SET_ACCEPT_EXPIRED_CERT,"xux",cfg_sub_dt,rlm_id,auth_rlm,accept_expired_cert);
			rhp_auth_realm_unhold(auth_rlm);
		}
	}

	if( pw_path ){
		unlink(pw_path);
		_rhp_free(pw_path);
	}
	if( pw_cont ){
		_rhp_free(pw_cont);
	}
	if( free_pw_str ){
		_rhp_free(file_pw);
	}

	cfg_sub_dt_rep->priv[0] = cfg_sub_dt->priv[0];

  RHP_TRC(0,RHPTRCID_SYSPXY_UI_CFG_UPLOAD_CERT_RTRN,"xu",cfg_sub_dt,rlm_id);
  return 0;

error:
	if( pw_path ){
		unlink(pw_path);
		_rhp_free(pw_path);
	}
	if( pw_cont ){
		_rhp_free(pw_cont);
	}
	rhp_cmd_tlv_clear(&tlvlst);

	if( free_pw_str ){
		_rhp_free(file_pw);
	}

	RHP_TRC(0,RHPTRCID_SYSPXY_UI_CFG_UPLOAD_CERT_ERR,"xuE",cfg_sub_dt,rlm_id,err);
	return err;
}

static int _rhp_syspxy_ui_cfg_update_radius(rhp_ipcmsg_syspxy_cfg_sub* cfg_sub_dt,
		rhp_ipcmsg_syspxy_cfg_sub* cfg_sub_dt_rep,xmlTextWriterPtr writer,int* n,
		char* opr_user_name,unsigned long opr_user_rlm_id)
{
  int err = -EINVAL;
  xmlDocPtr upd_auth_doc = NULL;
  xmlDocPtr cfg_doc = NULL;
  xmlNodePtr cfg_root_node = NULL;
  xmlNodePtr upd_radius_node;
  xmlChar *upd_secret = NULL, *upd_secret_secondary = NULL;
  xmlChar *upd_acct_secret = NULL, *upd_acct_secret_secondary = NULL;
  int ret_len;

	RHP_TRC(0,RHPTRCID_SYSPXY_UI_CFG_UPDATE_RADIUS,"xxxxdsu",cfg_sub_dt,cfg_sub_dt_rep,writer,n,*n,opr_user_name,opr_user_rlm_id);


  if( cfg_sub_dt->len <= sizeof(rhp_ipcmsg_syspxy_cfg_sub) ){
  	err = -EINVAL;
  	RHP_BUG("");
  	goto error;
  }

  {
  	upd_auth_doc = xmlParseMemory((void*)(cfg_sub_dt + 1),(cfg_sub_dt->len - sizeof(rhp_ipcmsg_syspxy_cfg_sub)));
  	if( upd_auth_doc == NULL ){
  		err = -EINVAL;
  		RHP_BUG("");
  		goto error;
  	}

  	upd_radius_node = xmlDocGetRootElement(upd_auth_doc);
  	if( upd_radius_node == NULL ){
  		err = -EINVAL;
  		RHP_BUG("");
  		goto error;
  	}

  	if( xmlStrcmp(upd_radius_node->name,(xmlChar*)"radius") ){
  		err = -EINVAL;
    	RHP_TRC(0,RHPTRCID_SYSPXY_UI_CFG_UPDATE_RADIUS_INVALID_RADIUS_TAG,"xs",cfg_sub_dt,upd_radius_node->name);
  		goto error;
  	}
  }

  upd_secret = rhp_xml_get_prop(upd_radius_node,(xmlChar*)"secret");
  if( upd_secret ){

		err = rhp_eap_auth_impl_radius_set_secret(RHP_RADIUS_SECRET_IDX_PRIMARY,
					(u8*)upd_secret,xmlStrlen(upd_secret));
		if( err ){
	  	RHP_LOG_E(RHP_LOG_SRC_UI,0,RHP_LOG_ID_UI_UPDATE_RADIUS_SECRET_ERR,"E",err);
			goto error;
		}

  	RHP_LOG_I(RHP_LOG_SRC_UI,0,RHP_LOG_ID_UI_UPDATE_RADIUS_SECRET,"");
  }

  upd_secret_secondary = rhp_xml_get_prop(upd_radius_node,(xmlChar*)"secondary_secret");
  if( upd_secret_secondary ){

		err = rhp_eap_auth_impl_radius_set_secret(RHP_RADIUS_SECRET_IDX_SECONDARY,
					(u8*)upd_secret_secondary,xmlStrlen(upd_secret_secondary));
		if( err ){
	  	RHP_LOG_E(RHP_LOG_SRC_UI,0,RHP_LOG_ID_UI_UPDATE_RADIUS_SECRET_FOR_SECONDARY_SERVER_ERR,"E",err);
			goto error;
		}

  	RHP_LOG_I(RHP_LOG_SRC_UI,0,RHP_LOG_ID_UI_UPDATE_RADIUS_SECRET_FOR_SECONDARY_SERVER,"");
  }


  upd_acct_secret = rhp_xml_get_prop(upd_radius_node,(xmlChar*)"acct_secret");
  if( upd_acct_secret ){

		err = rhp_eap_auth_impl_radius_set_secret(RHP_RADIUS_SECRET_IDX_ACCT_PRIMARY,
					(u8*)upd_acct_secret,xmlStrlen(upd_acct_secret));
		if( err ){
	  	RHP_LOG_E(RHP_LOG_SRC_UI,0,RHP_LOG_ID_UI_UPDATE_RADIUS_ACCT_SECRET_ERR,"E",err);
			goto error;
		}

  	RHP_LOG_I(RHP_LOG_SRC_UI,0,RHP_LOG_ID_UI_UPDATE_RADIUS_ACCT_SECRET,"");
  }

  upd_acct_secret_secondary = rhp_xml_get_prop(upd_radius_node,(xmlChar*)"acct_secondary_secret");
  if( upd_acct_secret_secondary ){

		err = rhp_eap_auth_impl_radius_set_secret(RHP_RADIUS_SECRET_IDX_ACCT_SECONDARY,
					(u8*)upd_acct_secret_secondary,xmlStrlen(upd_acct_secret_secondary));
		if( err ){
	  	RHP_LOG_E(RHP_LOG_SRC_UI,0,RHP_LOG_ID_UI_UPDATE_RADIUS_ACCT_SECRET_FOR_SECONDARY_SERVER_ERR,"E",err);
			goto error;
		}

  	RHP_LOG_I(RHP_LOG_SRC_UI,0,RHP_LOG_ID_UI_UPDATE_RADIUS_ACCT_SECRET_FOR_SECONDARY_SERVER,"");
  }


  {
  	int tmp;
  	u8 priv_attr_type_realm_id = 0;
  	u8 priv_attr_type_realm_role = 0;
  	u8 priv_attr_type_common = 0;
  	int tunnel_private_group_id_attr_enabled = 0;

  	tmp = 0;
  	rhp_xml_str2val(rhp_xml_get_prop_static(upd_radius_node,(const xmlChar*)"priv_attr_type_vpn_realm_id"),
				RHP_XML_DT_INT,&tmp,&ret_len,NULL,0);
  	if( tmp > 255 ){
  		RHP_BUG("%d",tmp);
  	}else{
  		priv_attr_type_realm_id = (u8)tmp;
  	}

  	tmp = 0;
  	rhp_xml_str2val(rhp_xml_get_prop_static(upd_radius_node,(const xmlChar*)"priv_attr_type_vpn_realm_role"),
				RHP_XML_DT_INT,&tmp,&ret_len,NULL,0);
  	if( tmp > 255 ){
  		RHP_BUG("%d",tmp);
  	}else{
  		priv_attr_type_realm_role = (u8)tmp;
  	}

  	tmp = 0;
  	rhp_xml_str2val(rhp_xml_get_prop_static(upd_radius_node,(const xmlChar*)"priv_attr_type_common"),
				RHP_XML_DT_INT,&tmp,&ret_len,NULL,0);
  	if( tmp > 255 ){
  		RHP_BUG("%d",tmp);
  	}else{
  		priv_attr_type_common = (u8)tmp;
  	}

		rhp_xml_check_enable(upd_radius_node,(xmlChar*)"attr_tunnel_private_group_id",&tunnel_private_group_id_attr_enabled);

		rhp_auth_radius_set_settings(
				&priv_attr_type_realm_id,&priv_attr_type_realm_role,&priv_attr_type_common,
				&tunnel_private_group_id_attr_enabled);
  }


  {
  	xmlNodePtr old_node = NULL;
  	xmlNodePtr dup_node;

    cfg_doc = xmlParseFile(rhp_syspxy_auth_conf_path);
    if( cfg_doc == NULL ){
      RHP_BUG(" %s ",rhp_syspxy_auth_conf_path);
      goto error;
    }

    cfg_root_node = xmlDocGetRootElement(cfg_doc);
    if( cfg_root_node == NULL ){
      RHP_BUG(" %s ",rhp_syspxy_auth_conf_path);
      goto error;
    }

  	old_node = rhp_xml_get_child(cfg_root_node,(xmlChar*)"radius");

    dup_node = xmlCopyNode(upd_radius_node,1);
    if( dup_node == NULL ){
    	RHP_BUG("");
      err = -ENOMEM;
      goto error;
    }

  	if( old_node ){

  		xmlChar* old_secret;

  		{
				old_secret = rhp_xml_get_prop(old_node,(xmlChar*)"secret");
				if( upd_secret == NULL && old_secret ){

					err = rhp_xml_set_prop(dup_node,(xmlChar*)"secret",old_secret);
					if( err ){
						_rhp_free_zero(old_secret,xmlStrlen(old_secret));
						RHP_BUG("%d",err);
						goto error;
					}
				}

				if( old_secret ){
					_rhp_free_zero(old_secret,xmlStrlen(old_secret));
				}
  		}

  		{
				old_secret = rhp_xml_get_prop(old_node,(xmlChar*)"secondary_secret");
				if( upd_secret_secondary == NULL && old_secret ){

					err = rhp_xml_set_prop(dup_node,(xmlChar*)"secondary_secret",old_secret);
					if( err ){
						_rhp_free_zero(old_secret,xmlStrlen(old_secret));
						RHP_BUG("%d",err);
						goto error;
					}
				}

				if( old_secret ){
					_rhp_free_zero(old_secret,xmlStrlen(old_secret));
				}
  		}

  		{
				old_secret = rhp_xml_get_prop(old_node,(xmlChar*)"acct_secret");
				if( upd_acct_secret == NULL && old_secret ){

					err = rhp_xml_set_prop(dup_node,(xmlChar*)"acct_secret",old_secret);
					if( err ){
						_rhp_free_zero(old_secret,xmlStrlen(old_secret));
						RHP_BUG("%d",err);
						goto error;
					}
				}

				if( old_secret ){
					_rhp_free_zero(old_secret,xmlStrlen(old_secret));
				}
  		}

  		{
				old_secret = rhp_xml_get_prop(old_node,(xmlChar*)"acct_secondary_secret");
				if( upd_acct_secret_secondary == NULL && old_secret ){

					err = rhp_xml_set_prop(dup_node,(xmlChar*)"acct_secondary_secret",old_secret);
					if( err ){
						_rhp_free_zero(old_secret,xmlStrlen(old_secret));
						RHP_BUG("%d",err);
						goto error;
					}
				}

				if( old_secret ){
					_rhp_free_zero(old_secret,xmlStrlen(old_secret));
				}
  		}
  	}

    if( xmlAddChild(cfg_root_node,dup_node) == NULL ){
      err = -EINVAL;
      RHP_BUG("");
      xmlFreeNode(dup_node);
      goto error;
    }

  	if( old_node ){
      xmlUnlinkNode(old_node);
      xmlFreeNode(old_node);
    }

    err = rhp_cfg_save_config(rhp_syspxy_auth_conf_path,cfg_doc);
    if( err ){
      RHP_BUG("%d",err);
    }
  }

  if( upd_auth_doc ){
	  xmlFreeDoc(upd_auth_doc);
  }

  if( upd_secret ){
  	_rhp_free_zero(upd_secret,xmlStrlen(upd_secret));
  }

  if( upd_secret_secondary ){
  	_rhp_free_zero(upd_secret_secondary,xmlStrlen(upd_secret_secondary));
  }

  xmlFreeDoc(cfg_doc);

  if( !err ){
  	RHP_LOG_I(RHP_LOG_SRC_UI,0,RHP_LOG_ID_UI_UPDATE_RADIUS_SYSPXY_CFG,"");
  }else{
  	RHP_LOG_E(RHP_LOG_SRC_UI,0,RHP_LOG_ID_UI_UPDATE_RADIUS_SYSPXY_CFG_ERR,"E",err);
  }

	RHP_TRC(0,RHPTRCID_SYSPXY_UI_CFG_UPDATE_RADIUS_RTRN,"xxxxd",cfg_sub_dt,cfg_sub_dt_rep,writer,n,*n);
  return 0;

error:
	RHP_LOG_E(RHP_LOG_SRC_UI,0,RHP_LOG_ID_UI_UPDATE_RADIUS_SYSPXY_CFG_ERR,"E",err);
  if( upd_auth_doc ){
  	xmlFreeDoc(upd_auth_doc);
  }
  if( cfg_doc ){
    xmlFreeDoc(cfg_doc);
  }
  if( upd_secret ){
  	_rhp_free_zero(upd_secret,xmlStrlen(upd_secret));
  }
  if( upd_secret_secondary ){
  	_rhp_free_zero(upd_secret_secondary,xmlStrlen(upd_secret_secondary));
  }
	RHP_TRC(0,RHPTRCID_SYSPXY_UI_CFG_UPDATE_RADIUS_ERR,"xxxxdE",cfg_sub_dt,cfg_sub_dt_rep,writer,n,*n,err);
  return err;
}

static int _rhp_syspxy_ui_ipc_permitted(unsigned long opr_user_rlm_id,unsigned int cfg_type)
{
  if( ((cfg_type == RHP_IPC_SYSPXY_CFG_CREATE_REALM) 	||
  		 (cfg_type == RHP_IPC_SYSPXY_CFG_DELETE_REALM)  ||
  		 (cfg_type == RHP_IPC_SYSPXY_CFG_ENABLE_REALM)  ||
  		 (cfg_type == RHP_IPC_SYSPXY_CFG_DISABLE_REALM) ||
  		 (cfg_type == RHP_IPC_SYSPXY_CFG_DELETE_ADMIN)  ||
  		 (cfg_type == RHP_IPC_SYSPXY_CFG_RESET_QCD_KEY) ||
  		 (cfg_type == RHP_IPC_SYSPXY_CFG_RESET_SESS_RESUME_KEY) ||
  		 (cfg_type == RHP_IPC_SYSPXY_CFG_UPDATE_RADIUS_MNG) )
  		&& (opr_user_rlm_id != 0) ){
    RHP_TRC(0,RHPTRCID_SYSPXY_UI_IPC_PERMITTED_NG,"uLd",opr_user_rlm_id,"IPC_SYSPXY_CFG",cfg_type);
  	return -EPERM;
  }

  RHP_TRC(0,RHPTRCID_SYSPXY_UI_IPC_PERMITTED_OK,"uLd",opr_user_rlm_id,"IPC_SYSPXY_CFG",cfg_type);
  return 0;
}

/*
static int _rhp_syspxy_ui_ipc_cfg_updated(unsigned int cfg_type)
{
  if( (cfg_type == RHP_IPC_SYSPXY_CFG_UPDATE_KEY_INFO) 	||
  		(cfg_type == RHP_IPC_SYSPXY_CFG_DELETE_KEY_INFO)  ||
  		(cfg_type == RHP_IPC_SYSPXY_CFG_UPDATE_CERT)  		||
  		(cfg_type == RHP_IPC_SYSPXY_CFG_UPDATE_CERT_FILE) ||
  		(cfg_type == RHP_IPC_SYSPXY_CFG_UPLOAD_CERT_FILE) ||
  		(cfg_type == RHP_IPC_SYSPXY_CFG_DELETE_CERT) ){
    RHP_TRC(0,RHPTRCID_SYSPXY_UI_IPC_CFG_UPDATED_DO,"Ld","IPC_SYSPXY_CFG",cfg_type);
  	return 1;
  }

  RHP_TRC(0,RHPTRCID_SYSPXY_UI_IPC_CFG_UPDATED_NOT_INTERESTED,"Ld","IPC_SYSPXY_CFG",cfg_type);
  return 0;
}
*/

int rhp_syspxy_ui_ipc_handle(rhp_ipcmsg *ipcmsg)
{
  int err = 0;
  rhp_ipcmsg_syspxy_cfg_req* cfg_req = (rhp_ipcmsg_syspxy_cfg_req*)ipcmsg;
  rhp_ipcmsg_syspxy_cfg_rep* cfg_rep = NULL;
  rhp_ipcmsg_syspxy_cfg_sub* cfg_sub_dt;
  xmlTextWriterPtr writer = NULL;
  xmlBufferPtr buf = NULL;
  char* res_xml = NULL;
  int res_xml_len = 0;
  char* opr_user_name = NULL;
  unsigned long opr_user_rlm_id = RHP_VPN_REALM_ID_UNKNOWN;
  rhp_ipcmsg_syspxy_cfg_sub cfg_sub_dt_rep;
  int n = 0;
  int n2 = 0;
  unsigned int cfg_sub_type = 0;

  RHP_TRC(0,RHPTRCID_SYSPXY_UI_HANDLE,"xLu",ipcmsg,"IPC",ipcmsg->type);

  if( ipcmsg->len < sizeof(rhp_ipcmsg_syspxy_cfg_req) ){
  	RHP_BUG("");
  	err = -EINVAL;
  	goto error;
  }

  if( cfg_req->opr_user_name_len < 2 ){
  	RHP_BUG("");
  	err = -EINVAL;
  	goto error;
  }

  if( cfg_req->len < (sizeof(rhp_ipcmsg_syspxy_cfg_req)
  									 + cfg_req->opr_user_name_len + sizeof(rhp_ipcmsg_syspxy_cfg_sub))  ){
  	RHP_BUG("");
  	err = -EINVAL;
  	goto error;
  }

  opr_user_name = (char*)(cfg_req + 1);
  if( opr_user_name[cfg_req->opr_user_name_len - 1] != '\0' ){
  	RHP_BUG("");
  	err = -EINVAL;
  	goto error;
  }


  cfg_sub_dt = (rhp_ipcmsg_syspxy_cfg_sub*)( ((u8*)opr_user_name) + cfg_req->opr_user_name_len );

  RHP_TRC(0,RHPTRCID_SYSPXY_UI_HANDLE_MSG,"xLuuuuuu",ipcmsg,"IPC_SYSPXY_CFG",cfg_sub_dt->cfg_type,cfg_sub_dt->len,cfg_sub_dt->target_rlm_id,cfg_sub_dt->result,cfg_sub_dt->priv[0],cfg_sub_dt->priv[1]);

  RHP_LOCK(&(rhp_auth_lock));
  {
    rhp_auth_admin_info* admin_info = NULL;

    admin_info = rhp_auth_admin_get(opr_user_name,cfg_req->opr_user_name_len);
    if( admin_info == NULL ){

      RHP_TRC(0,RHPTRCID_SYSPXY_UI_HANDLE_NO_ADMIN_USER,"xp",ipcmsg,cfg_req->opr_user_name_len,opr_user_name);

      RHP_UNLOCK(&(rhp_auth_lock));
      err = -EPERM;
      goto error;
    }

    if( admin_info->vpn_realm_id && (admin_info->vpn_realm_id != cfg_sub_dt->target_rlm_id) ){

      RHP_TRC(0,RHPTRCID_SYSPXY_UI_HANDLE_INVALID_RLM,"xpuu",ipcmsg,cfg_req->opr_user_name_len,opr_user_name,admin_info->vpn_realm_id,cfg_sub_dt->target_rlm_id);

      RHP_UNLOCK(&(rhp_auth_lock));
      err = -EPERM;
      goto error;
    }

    opr_user_rlm_id = admin_info->vpn_realm_id;
  }
  RHP_UNLOCK(&(rhp_auth_lock));



  if( (err = _rhp_syspxy_ui_ipc_permitted(opr_user_rlm_id,cfg_sub_dt->cfg_type)) ){

  	RHP_TRC(0,RHPTRCID_SYSPXY_UI_HANDLE_NOT_PERMITTED,"xu",ipcmsg,opr_user_rlm_id);
  	goto error;
  }


  {
    buf = xmlBufferCreate();
    if( buf == NULL ){
      err = -ENOMEM;
      RHP_BUG("");
      goto error;
    }

    writer = xmlNewTextWriterMemory(buf,0);
    if (writer == NULL) {
      err = -ENOMEM;
      RHP_BUG("");
      goto error;
    }

    n = xmlTextWriterStartDocument(writer,NULL,NULL,NULL); // 1.0,UTF-8,standalone
    if(n < 0) {
      err = -ENOMEM;
      RHP_BUG("");
      goto error;
    }
    n2 += n;

    n = xmlTextWriterStartElement(writer,(xmlChar*)"rhp_syspxy_cfg_ipc_response");
    if(n < 0) {
      err = -ENOMEM;
      RHP_BUG("");
      goto error;
    }
    n2 += n;
  }

  memset(&cfg_sub_dt_rep,0,sizeof(rhp_ipcmsg_syspxy_cfg_sub));

  cfg_sub_dt_rep.cfg_type = cfg_sub_dt->cfg_type;
  cfg_sub_dt_rep.target_rlm_id = cfg_sub_dt->target_rlm_id;
  cfg_sub_type = cfg_sub_dt->cfg_type;


  switch( cfg_sub_dt->cfg_type ){

  case RHP_IPC_SYSPXY_CFG_GET:

      err = _rhp_syspxy_ui_get(cfg_sub_dt,&cfg_sub_dt_rep,writer,&n2);
      break;

  case RHP_IPC_SYSPXY_CFG_CREATE_REALM:

      err = _rhp_syspxy_ui_create_realm(cfg_sub_dt,&cfg_sub_dt_rep,writer,&n2);
      break;

  case RHP_IPC_SYSPXY_CFG_DELETE_REALM:

      err = _rhp_syspxy_ui_delete_realm(0,cfg_sub_dt,&cfg_sub_dt_rep,writer,&n2);
      break;

  case RHP_IPC_SYSPXY_CFG_UPDATE_REALM:

      err = _rhp_syspxy_ui_update_realm(cfg_sub_dt,&cfg_sub_dt_rep,writer,&n2,opr_user_rlm_id);
      break;

  case RHP_IPC_SYSPXY_CFG_ENABLE_REALM:

      err = _rhp_syspxy_ui_enable_realm(cfg_sub_dt,&cfg_sub_dt_rep,writer,&n2);
      break;

  case RHP_IPC_SYSPXY_CFG_DISABLE_REALM:

  		err = _rhp_syspxy_ui_delete_realm(1,cfg_sub_dt,&cfg_sub_dt_rep,writer,&n2);
      break;

  case RHP_IPC_SYSPXY_CFG_UPDATE_KEY_INFO:

      err = _rhp_syspxy_ui_update_key_info(cfg_sub_dt,&cfg_sub_dt_rep,writer,&n2);
      break;

  case RHP_IPC_SYSPXY_CFG_DELETE_KEY_INFO:

      err = _rhp_syspxy_ui_delete_key_info(cfg_sub_dt,&cfg_sub_dt_rep,writer,&n2);
      break;

  case RHP_IPC_SYSPXY_CFG_UPDATE_CERT:

      err = _rhp_syspxy_ui_update_cert(cfg_sub_dt,&cfg_sub_dt_rep,writer,&n2,0);
      break;

  case RHP_IPC_SYSPXY_CFG_UPDATE_CERT_FILE:

  		err = _rhp_syspxy_ui_update_cert(cfg_sub_dt,&cfg_sub_dt_rep,writer,&n2,1);
      break;

  case RHP_IPC_SYSPXY_CFG_UPLOAD_CERT_FILE:

  		err = _rhp_syspxy_ui_upload_cert(cfg_sub_dt,&cfg_sub_dt_rep,writer,&n2);
      break;

/*
  case RHP_IPC_SYSPXY_CFG_DELETE_CERT :

      err = _rhp_syspxy_ui_delete_cert(cfg_sub_dt,&cfg_sub_dt_rep,writer,&n2);
      break;
*/
  case RHP_IPC_SYSPXY_CFG_GET_PRINTED_CERTS:

      err = _rhp_syspxy_ui_get_printed_certs(cfg_sub_dt,&cfg_sub_dt_rep,writer,&n2);
      break;

  case RHP_IPC_SYSPXY_CFG_UPDATE_ADMIN:

  		if( opr_user_rlm_id == 0 ){

				err = _rhp_syspxy_ui_update_admin(cfg_sub_dt,&cfg_sub_dt_rep,writer,&n2,
								opr_user_name,opr_user_rlm_id);

  		}else{

				err = _rhp_syspxy_ui_update_realm_admin(cfg_sub_dt,&cfg_sub_dt_rep,writer,&n2,
								opr_user_name,opr_user_rlm_id);
  		}
  		break;

  case RHP_IPC_SYSPXY_CFG_DELETE_ADMIN:

      err = _rhp_syspxy_ui_delete_admin(cfg_sub_dt,&cfg_sub_dt_rep,writer,&n2,
      				opr_user_name,opr_user_rlm_id);
      break;

  case RHP_IPC_SYSPXY_CFG_ENUM_ADMIN:

      err = _rhp_syspxy_ui_enum_admin(cfg_sub_dt,&cfg_sub_dt_rep,writer,&n2,opr_user_rlm_id);
      break;

  case RHP_IPC_SYSPXY_CFG_BKUP_SAVE:

    err = _rhp_syspxy_ui_cfg_bkup_save(cfg_sub_dt,&cfg_sub_dt_rep,writer,&n2,
    				opr_user_name,opr_user_rlm_id);
    break;

  case RHP_IPC_SYSPXY_CFG_RSRC_STATISTICS:

    err = _rhp_syspxy_ui_get_resource_statistics(cfg_sub_dt,&cfg_sub_dt_rep,writer,&n2);
    break;

  case RHP_IPC_SYSPXY_CFG_RESET_QCD_KEY:

    err = _rhp_syspxy_ui_cfg_reset_qcd_key(cfg_sub_dt,&cfg_sub_dt_rep,writer,&n2,
    				opr_user_name,opr_user_rlm_id);
  	break;

  case RHP_IPC_SYSPXY_CFG_RESET_SESS_RESUME_KEY:

    err = _rhp_syspxy_ui_cfg_reset_sess_resume_key(cfg_sub_dt,&cfg_sub_dt_rep,writer,&n2,
    				opr_user_name,opr_user_rlm_id);
  	break;

  case RHP_IPC_SYSPXY_CFG_UPDATE_RADIUS_MNG:

    err = _rhp_syspxy_ui_cfg_update_radius(cfg_sub_dt,&cfg_sub_dt_rep,writer,&n2,
    				opr_user_name,opr_user_rlm_id);
  	break;

  default:
      RHP_BUG("%d",ipcmsg->type);
      goto ignore;
  }

  if( err ){
  	RHP_TRC(0,RHPTRCID_SYSPXY_UI_HANDLE_HANDLER_ERR,"xuE",ipcmsg,opr_user_rlm_id,err);
  	goto error;
  }

  {
		n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
		if(n < 0) {
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		n2 += n;

		n = xmlTextWriterEndDocument(writer);
		if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
		}
		n2 += n;

		n = xmlTextWriterFlush(writer);
		if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
		}
		n2 += n;

    xmlFreeTextWriter(writer);
    writer = NULL;

		res_xml_len = xmlStrlen(buf->content) + 1;

		res_xml = (char*)_rhp_malloc(res_xml_len);
		if( res_xml == NULL ){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
		}

		RHP_BINDUMP_FREQ(0,"XML",res_xml_len,buf->content);

		memcpy(res_xml,buf->content,res_xml_len);
  }


  if( cfg_sub_dt_rep.cfg_type != RHP_IPC_SYSPXY_CFG_NONE ){

  	int tot_len = sizeof(rhp_ipcmsg_syspxy_cfg_rep) + cfg_req->opr_user_name_len
  								+ sizeof(rhp_ipcmsg_syspxy_cfg_sub) + res_xml_len;
  	u8* p;

  	cfg_rep = (rhp_ipcmsg_syspxy_cfg_rep*)rhp_ipc_alloc_msg(RHP_IPC_SYSPXY_CFG_REPLY,tot_len);

  	if( cfg_rep == NULL ){
      RHP_BUG("");
      goto error;
    }

    cfg_rep->len = tot_len;
    cfg_rep->txn_id = cfg_req->txn_id;
    cfg_rep->request_user = cfg_req->request_user;
    cfg_rep->http_bus_session_id = cfg_req->http_bus_session_id;

    p = (u8*)(cfg_rep + 1);

    cfg_rep->opr_user_name_len = cfg_req->opr_user_name_len;
    if( cfg_req->opr_user_name_len ){
      memcpy(p,opr_user_name,cfg_req->opr_user_name_len);
    }
    p += cfg_rep->opr_user_name_len;

    cfg_sub_dt_rep.len += res_xml_len + sizeof(rhp_ipcmsg_syspxy_cfg_sub);
    cfg_sub_dt_rep.result = 1;

/*
    if( _rhp_syspxy_ui_ipc_cfg_updated(cfg_sub_dt->cfg_type) ){

    	cfg_sub_dt_rep.config_updated = 1;
    }
*/

    memcpy(p,&cfg_sub_dt_rep,sizeof(rhp_ipcmsg_syspxy_cfg_sub));
    p += sizeof(rhp_ipcmsg_syspxy_cfg_sub);

    if( res_xml_len ){
    	memcpy(p,res_xml,res_xml_len);
    }

    if( rhp_ipc_send(RHP_MY_PROCESS,(void*)cfg_rep,cfg_rep->len,0) < 0 ){
      RHP_TRC(0,RHPTRCID_SYSPXY_UI_HANDLE_SEND_ERR,"xxdd",RHP_MY_PROCESS,cfg_rep,cfg_rep->len,0);
    }
  }

  err = 0;
	RHP_TRC(0,RHPTRCID_SYSPXY_UI_HANDLE_OK,"xu",ipcmsg,opr_user_rlm_id);

error:
ignore:
  if( err ){

    int tot_len = sizeof(rhp_ipcmsg_syspxy_cfg_rep)
    							+ cfg_req->opr_user_name_len + sizeof(rhp_ipcmsg_syspxy_cfg_sub);
    u8* p;

    cfg_rep = (rhp_ipcmsg_syspxy_cfg_rep*)rhp_ipc_alloc_msg(RHP_IPC_SYSPXY_CFG_REPLY,tot_len);

    if( cfg_rep == NULL ){
      RHP_BUG("");
      goto error;
    }

    cfg_rep->len = tot_len;
    cfg_rep->txn_id = cfg_req->txn_id;
    cfg_rep->request_user = cfg_req->request_user;
    cfg_rep->http_bus_session_id = cfg_req->http_bus_session_id;

    p = (u8*)(cfg_rep + 1);

    cfg_rep->opr_user_name_len = cfg_req->opr_user_name_len;
    if( cfg_req->opr_user_name_len ){
      memcpy(p,opr_user_name,cfg_req->opr_user_name_len);
    }
    p += cfg_rep->opr_user_name_len;

    cfg_sub_dt_rep.len += res_xml_len + sizeof(rhp_ipcmsg_syspxy_cfg_sub);
    cfg_sub_dt_rep.result = 0;

    memcpy(p,&cfg_sub_dt_rep,sizeof(rhp_ipcmsg_syspxy_cfg_sub));

    if( rhp_ipc_send(RHP_MY_PROCESS,(void*)cfg_rep,cfg_rep->len,0) < 0 ){
      RHP_TRC(0,RHPTRCID_SYSPXY_UI_HANDLE_SEND_ERR_2,"xxdd",RHP_MY_PROCESS,cfg_rep,cfg_rep->len,0);
    }
  }

	if( err == -EPERM ){
		RHP_LOG_E(RHP_LOG_SRC_UI,0,RHP_LOG_ID_UI_SYSPXY_NOT_PERMITTED,"usL",opr_user_rlm_id,opr_user_name,"IPC_SYSPXY_CFG",cfg_sub_type);
	}else if( err && err != -ENOENT ){
		RHP_LOG_E(RHP_LOG_SRC_UI,0,RHP_LOG_ID_UI_SYSPXY_HANDLE_ERR,"usLE",opr_user_rlm_id,opr_user_name,"IPC_SYSPXY_CFG",cfg_sub_type,err);
	}

  if( cfg_rep ){
    _rhp_free_zero(cfg_rep,cfg_rep->len);
  }
  if( cfg_req ){
    _rhp_free_zero(cfg_req,cfg_req->len);
  }
  if( writer ){
    xmlFreeTextWriter(writer);
  }
  if( buf ){
    xmlBufferFree(buf);
  }
  if( res_xml ){
  	_rhp_free_zero(res_xml,res_xml_len);
  }
  RHP_TRC(0,RHPTRCID_SYSPXY_UI_HANDLE_RTRN,"xE",ipcmsg,err);
  return err;
}
