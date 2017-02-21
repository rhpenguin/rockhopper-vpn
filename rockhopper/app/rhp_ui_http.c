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
#include <byteswap.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <libxml/encoding.h>
#include <libxml/xmlwriter.h>


#include "rhp_trace.h"
#include "rhp_main_traceid.h"
#include "rhp_misc.h"
#include "rhp_process.h"
#include "rhp_netmng.h"
#include "rhp_protocol.h"
#include "rhp_packet.h"
#include "rhp_netsock.h"
#include "rhp_config.h"
#include "rhp_vpn.h"
#include "rhp_ikev2_mesg.h"
#include "rhp_ikev2.h"
#include "rhp_http.h"
#include "rhp_wthreads.h"
#include "rhp_event.h"
#include "rhp_ui.h"
#include "rhp_dns_pxy.h"
#include "rhp_tuntap.h"
#include "rhp_forward.h"
#include "rhp_cert.h"
#include "rhp_esp.h"
#include "rhp_forward.h"
#include "rhp_eap.h"
#include "rhp_eap_auth_impl.h"
#include "rhp_eap_sup_impl.h"
#include "rhp_radius_impl.h"
#include "rhp_nhrp.h"
#include "rhp_pcap.h"



static rhp_atomic_t _rhp_ui_http_access_lock;

static rhp_mutex_t _rhp_ui_http_packet_capture_lock;

#define RHP_UI_HTTP_LOCKED() 		(_rhp_atomic_read(&_rhp_ui_http_access_lock))
#define RHP_UI_HTTP_LOCK() 			(_rhp_atomic_set(&_rhp_ui_http_access_lock,1))
#define RHP_UI_HTTP_UNLOCK() 		(_rhp_atomic_set(&_rhp_ui_http_access_lock,0))

char* rhp_home_dir = NULL;
char* rhp_cfg_bkup_cmd_path = NULL;

static int _rhp_ui_http_permitted(rhp_http_conn* http_conn,
							rhp_http_bus_session* http_bus_sess,unsigned long rlm_id)
{
	int err = -EINVAL;

	if( http_bus_sess && (http_conn->user_realm_id != http_bus_sess->user_realm_id) ){
		err = -EPERM;
		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_NOT_PERMITTED,"xxuu",http_conn,http_bus_sess,http_conn->user_realm_id,http_bus_sess->user_realm_id);
		goto error;
	}

	if( http_conn->user_realm_id && (http_conn->user_realm_id != rlm_id) ){
		err = -EPERM;
		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_NOT_PERMITTED2,"xxuu",http_conn,http_bus_sess,http_conn->user_realm_id,rlm_id);
		goto error;
	}

	if( http_bus_sess && http_bus_sess->user_realm_id && (http_bus_sess->user_realm_id != rlm_id) ){
		err = -EPERM;
		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_NOT_PERMITTED3,"xxuu",http_conn,http_bus_sess,http_bus_sess->user_realm_id,rlm_id);
		goto error;
	}

	return 0;

error:
	return err;
}

static int _rhp_ui_http_get_user_realm_id(rhp_http_conn* http_conn,
		rhp_http_bus_session* http_bus_sess,unsigned long* rlm_id_r)
{
	int err = -EINVAL;

	if( http_conn->user_realm_id != http_bus_sess->user_realm_id ){
		err = -EPERM;
		RHP_TRC(0,RHPTRCID_UI_HTTP_GET_USER_REALM_ID_NOT_PERMITTED,"xxuu",http_conn,http_bus_sess,http_conn->user_realm_id,http_bus_sess->user_realm_id);
		goto error;
	}

	*rlm_id_r = http_conn->user_realm_id;

	RHP_TRC(0,RHPTRCID_UI_HTTP_GET_USER_REALM_ID,"xxuu",http_conn,http_bus_sess,http_bus_sess->user_realm_id,*rlm_id_r);
	return 0;

error:
	return err;
}

static int _rhp_ui_http_get_peer_addr_port(xmlNodePtr node,
		rhp_ip_addr* peer_addr_r,char** peer_fqdn_r,u16* peer_port_r)
{
	int err = -EINVAL;
  int ret_len;
  u16 dmy_port = rhp_gcfg_ike_port; // LOCK not needed.;
  xmlChar* peer_addr_str = NULL;
  rhp_ip_addr peer_addr;
  u16 port;
  int peer_addr_family = AF_UNSPEC;

	RHP_TRC(0,RHPTRCID_UI_HTTP_GET_PEER_ADDR_PORT,"xxxx",node,peer_addr_r,peer_fqdn_r,peer_port_r);

	memset(&peer_addr,0,sizeof(rhp_ip_addr));
	*peer_fqdn_r = NULL;
	*peer_port_r = 0;

	peer_addr_str = rhp_xml_get_prop(node,(const xmlChar*)"peer_address");

	if( peer_addr_str == NULL ){

		peer_addr_str = rhp_xml_get_prop(node,(const xmlChar*)"peer_address_v4");
		peer_addr_family = AF_INET;
	}

	if( peer_addr_str == NULL ){

		peer_addr_str = rhp_xml_get_prop(node,(const xmlChar*)"peer_address_v6");
		peer_addr_family = AF_INET6;
	}

	if( peer_addr_str ){

		err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"peer_port"),
						RHP_XML_DT_PORT,&port,&ret_len,&dmy_port,sizeof(dmy_port));
		if( err && err != -ENOENT ){
			RHP_TRC(0,RHPTRCID_UI_HTTP_GET_PEER_ADDR_PORT_GET_PORT_ERR,"xE",node,err);
			goto error;
		}

		if( rhp_ip_str2addr(peer_addr_family,(char*)peer_addr_str,&peer_addr) ){

			*peer_fqdn_r = (char*)peer_addr_str; // Don't free!

		}else{

			memcpy(peer_addr_r,&peer_addr,sizeof(rhp_ip_addr));

			rhp_ip_addr_dump("_rhp_ui_http_get_peer_addr_port",peer_addr_r);
		}

		*peer_port_r = port;

	}else{

		RHP_TRC(0,RHPTRCID_UI_HTTP_GET_PEER_ADDR_PORT_PEER_ADDR_NOT_FOUND,"x",node);
	}

	if( peer_addr_str ){
		_rhp_free(peer_addr_str);
	}

	RHP_TRC(0,RHPTRCID_UI_HTTP_GET_PEER_ADDR_PORT_RTRN,"xxxx",node,peer_addr_r,peer_fqdn_r,peer_port_r);
	return 0;

error:
	if( peer_addr_str ){
		_rhp_free(peer_addr_str);
	}
	RHP_TRC(0,RHPTRCID_UI_HTTP_GET_PEER_ADDR_PORT_ERR,"xxxxE",node,peer_addr_r,peer_fqdn_r,peer_port_r,err);
	return err;
}

struct _rhp_connect_i_task_ctx {

	u8 tag[4]; // '#COT'

	unsigned long rlm_id;

	rhp_ikev2_id peer_id;
	rhp_ip_addr peer_addr;
	char* peer_fqdn;
	rhp_ip_addr peer_fqdn_addr_primary;
	rhp_ip_addr peer_fqdn_addr_secondary;
	u16 peer_port;
	u16 reserved0;


	int vpn_unique_id_flag;
	u8 vpn_unique_id[RHP_VPN_UNIQUE_ID_SIZE];

	int eap_sup_method;
	char* eap_sup_user_id;
	char* eap_sup_user_key;

	rhp_ui_ctx ui_ctx;
	int auto_reconnect;
	int err;
};
typedef struct _rhp_connect_i_task_ctx		rhp_connect_i_task_ctx;


static void _rhp_ui_http_vpn_conn_i_task_free_ctx(void* ctx)
{
	rhp_connect_i_task_ctx* task_ctx = (rhp_connect_i_task_ctx*)ctx;

	RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_CONN_I_TASK_FREE_CTX,"x",task_ctx);

	rhp_ikev2_id_clear(&(task_ctx->peer_id));

	if( task_ctx->peer_fqdn ){
		_rhp_free(task_ctx->peer_fqdn);
	}

	if( task_ctx->eap_sup_user_id ){
		_rhp_free_zero(task_ctx->eap_sup_user_id,strlen(task_ctx->eap_sup_user_id));
	}
	if( task_ctx->eap_sup_user_key ){
		_rhp_free_zero(task_ctx->eap_sup_user_key,strlen(task_ctx->eap_sup_user_key));
	}

	_rhp_free(task_ctx);

	RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_CONN_I_TASK_FREE_CTX_RTRN,"x",task_ctx);
}

static void* _rhp_ui_http_vpn_conn_i_task_alloc_ctx(unsigned long rlm_id,
		rhp_ikev2_id* peer_id,rhp_ip_addr* peer_addr,char* peer_fqdn,u16 peer_port,
		rhp_ui_ctx* ui_ctx,int auto_reconnect,int unique_id_flag,u8* unique_id,
		int eap_sup_method,char* eap_sup_user_id,char* eap_sup_user_key)
{
	int err = -EINVAL;
	rhp_connect_i_task_ctx* task_ctx = (rhp_connect_i_task_ctx*)_rhp_malloc(sizeof(rhp_connect_i_task_ctx));

	if( task_ctx == NULL ){
		RHP_BUG("");
		return NULL;
	}

	memset(task_ctx,0,sizeof(rhp_connect_i_task_ctx));

	task_ctx->tag[0] = '#';
	task_ctx->tag[1] = 'C';
	task_ctx->tag[2] = 'O';
	task_ctx->tag[3] = 'T';

	task_ctx->rlm_id = rlm_id;

	if( peer_id ){

		err = rhp_ikev2_id_dup(&(task_ctx->peer_id),peer_id);
		if( err ){
			RHP_BUG("%d",err);
			goto error;
		}
	}

	if( peer_addr ){
		memcpy(&(task_ctx->peer_addr),peer_addr,sizeof(rhp_ip_addr));
	}

	if( peer_fqdn ){

		task_ctx->peer_fqdn = (char*)_rhp_malloc(strlen(peer_fqdn) + 1);
		if( task_ctx->peer_fqdn == NULL ){
			RHP_BUG("");
			goto error;
		}

		task_ctx->peer_fqdn[0] = '\0';
		strcpy(task_ctx->peer_fqdn,peer_fqdn);
	}

	task_ctx->peer_port = peer_port;

	if( eap_sup_method ){

		task_ctx->eap_sup_method = eap_sup_method;

		if( eap_sup_user_id ){

			int len = strlen(eap_sup_user_id);

			if( len ){

				task_ctx->eap_sup_user_id = (char*)_rhp_malloc(len + 1);
				if( task_ctx->eap_sup_user_id == NULL ){
					RHP_BUG("");
					goto error;
				}

				task_ctx->eap_sup_user_id[len] = '\0';
				strcpy(task_ctx->eap_sup_user_id,eap_sup_user_id);
			}
		}

		if( eap_sup_user_key ){

			int len = strlen(eap_sup_user_key);

			if( len ){

				task_ctx->eap_sup_user_key = (char*)_rhp_malloc(len + 1);
				if( task_ctx->eap_sup_user_key == NULL ){
					RHP_BUG("");
					goto error;
				}

				task_ctx->eap_sup_user_key[len] = '\0';
				strcpy(task_ctx->eap_sup_user_key,eap_sup_user_key);
			}
		}
	}

	if( ui_ctx ){
		memcpy(&(task_ctx->ui_ctx),ui_ctx,sizeof(rhp_ui_ctx));
	}

	task_ctx->auto_reconnect = auto_reconnect;

	if( unique_id_flag ){
		task_ctx->vpn_unique_id_flag = unique_id_flag;
		memcpy(task_ctx->vpn_unique_id,unique_id,RHP_VPN_UNIQUE_ID_SIZE);
	}

	RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_CONN_I_TASK_ALLOC_CTX,"x",task_ctx);
	return (void*)task_ctx;

error:
	_rhp_ui_http_vpn_conn_i_task_free_ctx((void*)task_ctx);
	return NULL;
}

extern void rhp_ui_http_btx_async_conn_close_cleanup(void* ctx);

static int _rhp_ui_http_vpn_connect_i_err_serialize(void* http_bus_sess_d,void* ctx,void* writer,int idx)
{
	rhp_http_bus_session* http_bus_sess = (rhp_http_bus_session*) http_bus_sess_d;
	rhp_connect_i_task_ctx* task_ctx = (rhp_connect_i_task_ctx*)ctx;

  int err = -EINVAL;
  int n = 0;
  int n2 = 0;

  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_CONNECT_I_ERR_SERIALIZE,"xxdx",http_bus_sess,writer,idx,task_ctx);

  n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"rhp_http_bus_record");
  if(n < 0) {
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"index","%d",idx);
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"service",(xmlChar*)"ui_http_vpn");
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  if( task_ctx->err == RHP_STATUS_CONNECT_VPN_I_EAP_SUP_USER_KEY_NEEDED ){

  	rhp_vpn_realm* rlm = NULL;
  	int eap_sup_enabled;
  	rhp_eap_sup_info info;
  	char* method_str = NULL;

  	memset(&info,0,sizeof(rhp_eap_sup_info));

  	n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"action",(xmlChar*)"eap_sup_vpn_connect_i_user_key_needed");
    if(n < 0){
      err = -ENOMEM;
      RHP_BUG("");
      goto error;
    }
    n2 += n;

    rlm = rhp_realm_get(task_ctx->rlm_id);
		if( rlm == NULL ){
			err = -ENOENT;
			RHP_BUG("%d",task_ctx->rlm_id);
			goto error;
		}

		RHP_LOCK(&(rlm->lock));

		eap_sup_enabled = rhp_eap_sup_impl_is_enabled(rlm,&info);
		if( !eap_sup_enabled ){
			err = -ENOENT;
			RHP_BUG("");
			RHP_UNLOCK(&(rlm->lock));
			goto error;
		}

		RHP_UNLOCK(&(rlm->lock));

		method_str = rhp_eap_sup_impl_method2str(info.eap_method);
		if( method_str == NULL ){
			err = -EINVAL;
			RHP_BUG("");
			goto error;
		}

  	n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"eap_sup_method",(xmlChar*)method_str);
    if(n < 0){
      _rhp_free(method_str);
      err = -ENOMEM;
      RHP_BUG("");
      goto error;
    }
    n2 += n;

    _rhp_free(method_str);

  }else if( task_ctx->err == RHP_STATUS_IKESA_EXISTS ){

  	n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"action",(xmlChar*)"vpn_connect_i_exists");
    if(n < 0){
      err = -ENOMEM;
      RHP_BUG("");
      goto error;
    }
    n2 += n;

  }else{

  	n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"action",(xmlChar*)"vpn_connect_i_error");
    if(n < 0){
      err = -ENOMEM;
      RHP_BUG("");
      goto error;
    }
    n2 += n;
  }

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"session_id","%llu",http_bus_sess->session_id);
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"vpn_realm_id","%lu",task_ctx->rlm_id);
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  if( !rhp_ip_addr_null(&(task_ctx->peer_addr)) ){

  	if( task_ctx->peer_addr.addr_family == AF_INET ){

  		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"peer_address_v4","%d.%d.%d.%d",
  				((u8*)&task_ctx->peer_addr.addr.v4)[0],((u8*)&task_ctx->peer_addr.addr.v4)[1],((u8*)&task_ctx->peer_addr.addr.v4)[2],((u8*)&task_ctx->peer_addr.addr.v4)[3]);

  	}else if( task_ctx->peer_addr.addr_family == AF_INET6 ){

  		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"peer_address_v6","%s",
  				rhp_ipv6_string(task_ctx->peer_addr.addr.v6));
  	}
    if(n < 0){
      err = -ENOMEM;
      RHP_BUG("");
      goto error;
    }
    n2 += n;

    if( task_ctx->peer_port ){

    	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"peer_port","%d",ntohs(task_ctx->peer_port));
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			n2 += n;
    }
  }

	if( task_ctx->peer_id.type ){

		char *id_type,*id_str;

		err = rhp_ikev2_id_to_string(&(task_ctx->peer_id),&id_type,&id_str);
		if( err ){
      RHP_BUG("");
      goto error;
		}

		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"peerid_type","%s",id_type);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			_rhp_free(id_type);
			_rhp_free(id_str);
      goto error;
		}
		n2 += n;

		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"peerid","%s",id_str);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			_rhp_free(id_type);
			_rhp_free(id_str);
      goto error;
		}
		n2 += n;

		_rhp_free(id_type);
		_rhp_free(id_str);
	}

	if( task_ctx->peer_fqdn ){

		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"peer_fqdn","%s",task_ctx->peer_fqdn);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
      goto error;
		}
		n2 += n;
	}

  n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
  if(n < 0) {
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_CONNECT_I_ERR_SERIALIZE_RTRN,"xxd",http_bus_sess,task_ctx,n2);
  return n2;

error:
	RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_CONNECT_I_ERR_SERIALIZE_ERR,"xxE",http_bus_sess,task_ctx,err);
  return err;
}

static void _rhp_ui_http_vpn_connect_i_task(int worker_index,void *ctx);

static void _rhp_ui_http_vpn_connect_i_dns_task(void* cb_ctx,void* not_used,int err,int res_addrs_num,rhp_ip_addr* res_addrs)
{
	rhp_connect_i_task_ctx* task_ctx = (rhp_connect_i_task_ctx*)cb_ctx;

	RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_CONNECT_I_DNS_TASK,"xEdx",task_ctx,err,res_addrs_num,res_addrs);

	if( err ){
		goto error;
	}else if( res_addrs_num == 0 ){
		err = -ENOENT;
		goto error;
	}

	{
		if( rhp_ip_addr_null(&(res_addrs[0])) ){
			RHP_BUG("");
			err = -EINVAL;
			goto error;
		}

		memcpy(&(task_ctx->peer_fqdn_addr_primary),&(res_addrs[0]),sizeof(rhp_ip_addr));
		task_ctx->peer_fqdn_addr_primary.port = htons(rhp_gcfg_ike_port); // LOCK not needed.;

		rhp_ip_addr_dump("_rhp_ui_http_vpn_connect_i_dns_task:1",&(task_ctx->peer_fqdn_addr_primary));
	}

	if( res_addrs_num > 1 ){

		if( rhp_ip_addr_null(&(res_addrs[1])) ){
			RHP_BUG("");
			err = -EINVAL;
			goto error;
		}

		memcpy(&(task_ctx->peer_fqdn_addr_secondary),&(res_addrs[1]),sizeof(rhp_ip_addr));
		task_ctx->peer_fqdn_addr_secondary.port = htons(rhp_gcfg_ike_port); // LOCK not needed.

		rhp_ip_addr_dump("_rhp_ui_http_vpn_connect_i_dns_task:2",&(task_ctx->peer_fqdn_addr_secondary));
	}


	RHP_LOG_D(RHP_LOG_SRC_UI,task_ctx->rlm_id,RHP_LOG_ID_CONNECT_I_RSLV_PEER_ADDRS,"IsAA",&(task_ctx->peer_id),task_ctx->peer_fqdn,&(task_ctx->peer_fqdn_addr_primary),&(task_ctx->peer_fqdn_addr_secondary));

	if( !rhp_wts_dispach_ok(RHP_WTS_DISP_LEVEL_HIGH_2,0) ){
		err = -EBUSY;
		goto error;
	}

	err = rhp_wts_add_task(RHP_WTS_DISP_RULE_RAND,RHP_WTS_DISP_LEVEL_HIGH_2,NULL,
			_rhp_ui_http_vpn_connect_i_task,task_ctx);

	if( err ){
		RHP_BUG("%d",err);
		goto error;
	}

	RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_CONNECT_I_DNS_TASK_RTRN,"x",task_ctx);
	return;

error:
	RHP_LOG_E(RHP_LOG_SRC_UI,task_ctx->rlm_id,RHP_LOG_ID_CONNECT_I_RSLV_PEER_ADDRS_ERR,"IsE",&(task_ctx->peer_id),task_ctx->peer_fqdn,err);

	{
		task_ctx->err = err;

		rhp_http_bus_send_async(task_ctx->ui_ctx.http.http_bus_sess_id,task_ctx->ui_ctx.user_name,
			task_ctx->rlm_id,1,1,
			_rhp_ui_http_vpn_connect_i_err_serialize,(void*)task_ctx);

		rhp_vpn_connect_i_pending_clear(task_ctx->rlm_id,&(task_ctx->peer_id),NULL);
	}

	_rhp_ui_http_vpn_conn_i_task_free_ctx(task_ctx);

	RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_CONNECT_I_DNS_TASK_ERR,"xE",task_ctx,err);
	return;
}

static void _rhp_ui_http_vpn_connect_i_task(int worker_index,void *ctx)
{
	int err = -EINVAL;
	rhp_connect_i_task_ctx* task_ctx = (rhp_connect_i_task_ctx*)ctx;
	rhp_ip_addr* peer_addr_p = NULL;
	int cont_flag = 0;

	RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_CONNECT_I_TASK,"x",task_ctx);

	if( task_ctx->err ){
		RHP_BUG("%d",task_ctx->err);
		goto error;
	}

	peer_addr_p = &(task_ctx->peer_addr);
	if( rhp_ip_addr_null(peer_addr_p) ){
		peer_addr_p = NULL;
	}

	if( peer_addr_p == NULL ){

rslv_peer_id_fqdn:

		if( task_ctx->peer_fqdn && rhp_ip_addr_null(&(task_ctx->peer_fqdn_addr_primary)) ){

			err = rhp_dns_resolve(RHP_WTS_DISP_LEVEL_HIGH_2,task_ctx->peer_fqdn,AF_UNSPEC,
					_rhp_ui_http_vpn_connect_i_dns_task,ctx,NULL);
			if( err ){
				RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_CONNECT_I_TASK_CONN_DNS_ERR,"xE",task_ctx,err);
				goto error_notify;
			}

			RHP_LOG_D(RHP_LOG_SRC_UI,task_ctx->rlm_id,RHP_LOG_ID_CONNECT_I_RSLV_PEER_ADDR_START,"s",task_ctx->peer_fqdn);

			cont_flag = 1;
			err = 0;
		}
	}


	if( !cont_flag ){

		if( peer_addr_p == NULL && task_ctx->peer_fqdn == NULL ){

			rhp_vpn_realm* rlm = NULL;

			rlm = rhp_realm_get(task_ctx->rlm_id);
			if( rlm ){

				RHP_LOCK(&(rlm->lock));
				{
					rhp_cfg_peer* cfg_peer;

					cfg_peer = rlm->get_peer_by_id(rlm,&(task_ctx->peer_id));
					if( cfg_peer ){

						if( rhp_ip_addr_null(&(cfg_peer->primary_addr)) ){

							if( cfg_peer->primary_addr_fqdn ){

								int fqdn_len = strlen(cfg_peer->primary_addr_fqdn) + 1;

								memset(&(task_ctx->peer_fqdn_addr_primary),0,sizeof(rhp_ip_addr));

								task_ctx->peer_fqdn = (char*)_rhp_malloc(fqdn_len);
								if( task_ctx->peer_fqdn == NULL ){
									RHP_BUG("");
									RHP_UNLOCK(&(rlm->lock));
									rhp_realm_unhold(rlm);
									err = -ENOMEM;
									goto error_notify;
								}

								memcpy(task_ctx->peer_fqdn,cfg_peer->primary_addr_fqdn,fqdn_len);
								RHP_UNLOCK(&(rlm->lock));
								rhp_realm_unhold(rlm);

								RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_CONNECT_I_TASK_CONN_RES_FQDN_PRIMARY_ADDR_FQDN,"xs",task_ctx,cfg_peer->primary_addr_fqdn);
								goto rslv_peer_id_fqdn;

							}else if( task_ctx->peer_id.type == RHP_PROTO_IKE_ID_FQDN ){

								int id_len;
								int id_type;

								memset(&(task_ctx->peer_fqdn_addr_primary),0,sizeof(rhp_ip_addr));

								err = rhp_ikev2_id_value_str(&(task_ctx->peer_id),(u8**)&(task_ctx->peer_fqdn),&id_len,&id_type); // '\0' included.
								RHP_UNLOCK(&(rlm->lock));
								rhp_realm_unhold(rlm);

								if( err ){
									RHP_BUG("");
									goto error_notify;
								}

								RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_CONNECT_I_TASK_CONN_RES_FQDN_IKEV2_ID_FQDN,"xs",task_ctx,task_ctx->peer_fqdn);
								goto rslv_peer_id_fqdn;
							}
						}
					}
				}
				RHP_UNLOCK(&(rlm->lock));
				rhp_realm_unhold(rlm);
			}
		}

		{
			rhp_vpn_conn_args conn_args;
			rhp_vpn_reconn_args reconn_args;

			memset(&conn_args,0,sizeof(rhp_vpn_conn_args));
			memset(&reconn_args,0,sizeof(rhp_vpn_reconn_args));

			conn_args.peer_id = &(task_ctx->peer_id);
			conn_args.peer_addr = peer_addr_p;
			conn_args.peer_fqdn = task_ctx->peer_fqdn;
			conn_args.peer_fqdn_addr_primary = &(task_ctx->peer_fqdn_addr_primary);
			conn_args.peer_fqdn_addr_secondary = &(task_ctx->peer_fqdn_addr_secondary);
			conn_args.peer_port = task_ctx->peer_port;
			conn_args.eap_sup_method = task_ctx->eap_sup_method;
			conn_args.eap_sup_user_id_len = (task_ctx->eap_sup_user_id ? strlen(task_ctx->eap_sup_user_id) : 0);
			conn_args.eap_sup_user_id = (u8*)task_ctx->eap_sup_user_id;
			conn_args.eap_sup_user_key_len = (task_ctx->eap_sup_user_key ? strlen(task_ctx->eap_sup_user_key) : 0);
			conn_args.eap_sup_user_key = (u8*)task_ctx->eap_sup_user_key;
			conn_args.ui_info = &(task_ctx->ui_ctx);

			reconn_args.auto_reconnect = task_ctx->auto_reconnect;
			reconn_args.exec_auto_reconnect = 0;
			reconn_args.auto_reconnect_retries = 0;
			reconn_args.sess_resume_material_i = NULL;

			err = rhp_vpn_connect_i(task_ctx->rlm_id,&conn_args,&reconn_args,1);
			if( err ){

error_notify:
				RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_CONNECT_I_TASK_CONN_ERR,"xE",task_ctx,err);

				task_ctx->err = err;

				rhp_http_bus_send_async(task_ctx->ui_ctx.http.http_bus_sess_id,task_ctx->ui_ctx.user_name,
						task_ctx->rlm_id,1,1,
						_rhp_ui_http_vpn_connect_i_err_serialize,(void*)task_ctx);

				goto error;
			}
		}
	}

error:
	if( err == RHP_STATUS_IKESA_EXISTS ){
		RHP_LOG_I(RHP_LOG_SRC_UI,task_ctx->rlm_id,RHP_LOG_ID_CONNECT_I_CONN_EXISTS,"IAs",&(task_ctx->peer_id),&(task_ctx->peer_addr),task_ctx->peer_fqdn);
	}else if( err == RHP_STATUS_CONNECT_VPN_I_EAP_SUP_USER_KEY_NEEDED ){
		// OK
	}else if( err ){
		RHP_LOG_E(RHP_LOG_SRC_UI,task_ctx->rlm_id,RHP_LOG_ID_CONNECT_I_ERR,"IAsE",&(task_ctx->peer_id),&(task_ctx->peer_addr),task_ctx->peer_fqdn,err);
	}else{

		if( !cont_flag ){
	  	RHP_LOG_I(RHP_LOG_SRC_UI,task_ctx->rlm_id,RHP_LOG_ID_CONNECT_I_START,"IAs",&(task_ctx->peer_id),&(task_ctx->peer_addr),task_ctx->peer_fqdn);
	  }
	}

	if( err ){
		rhp_vpn_connect_i_pending_clear(task_ctx->rlm_id,&(task_ctx->peer_id),NULL);
	}

	if( !cont_flag ){
		_rhp_ui_http_vpn_conn_i_task_free_ctx(ctx);
	}

	RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_CONNECT_I_TASK_RTRN,"xE",task_ctx,err);
	return;
}

static void _rhp_ui_http_vpn_close_task(int worker_index,void *ctx)
{
	int err = -EINVAL;
	rhp_connect_i_task_ctx* task_ctx = (rhp_connect_i_task_ctx*)ctx;
	rhp_ip_addr* peer_addr_p = NULL;

	RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_CLOSE_TASK,"x",task_ctx);

	peer_addr_p = &(task_ctx->peer_addr);
	if( rhp_ip_addr_null(peer_addr_p) ){
		peer_addr_p = NULL;
	}

  err = rhp_vpn_close(task_ctx->rlm_id,
  		&(task_ctx->peer_id),peer_addr_p,task_ctx->peer_fqdn,
  		(task_ctx->vpn_unique_id_flag ? task_ctx->vpn_unique_id : NULL),&(task_ctx->ui_ctx));

  if( err ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_CLOSE_TASK_CONN_ERR,"xE",task_ctx,err);
    goto error;
  }

error:
	if( err ){
		RHP_LOG_E(RHP_LOG_SRC_UI,task_ctx->rlm_id,RHP_LOG_ID_CLOSE_VPN_ERR,"IAsNE",&(task_ctx->peer_id),&(task_ctx->peer_addr),task_ctx->peer_fqdn,task_ctx->vpn_unique_id,err);
	}
	_rhp_ui_http_vpn_conn_i_task_free_ctx(ctx);

	RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_CLOSE_TASK_RTRN,"xE",task_ctx,err);
	return;
}

static int _rhp_ui_http_vpn_connect_i(xmlDocPtr doc,xmlNodePtr node,rhp_http_conn* http_conn,
		rhp_http_bus_session* http_bus_sess,rhp_http_request* http_req,void* ctx)
{
  int err = -EINVAL;
  char* vpn_realm_str = NULL;
  char* peer_id_type_str = NULL;
  char* peer_id_str = NULL;
  rhp_ikev2_id peer_id;
  rhp_ikev2_id* peer_id_p = NULL;
  rhp_ip_addr peer_addr;
  rhp_ip_addr* peer_addr_p = NULL;
  u16 peer_port = 0;
  unsigned long rlm_id = 0;
  char* peer_fqdn_p = NULL;
  char* endp;
  rhp_ui_ctx ui_ctx;
  int auto_reconnect = 0;
  char* eap_sup_method_str = NULL;
  char* eap_sup_user_id = NULL;
  char* eap_sup_user_key = NULL;
  int eap_sup_method = 0;

  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_CONNECT_I,"xxxxxx",doc,node,http_conn,http_bus_sess,http_req,ctx);

  memset(&ui_ctx,0,sizeof(rhp_ui_ctx));
	memset(&peer_id,0,sizeof(rhp_ikev2_id));
	memset(&peer_addr,0,sizeof(rhp_ip_addr));

  if( doc == NULL || node == NULL ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_CONNECT_I_NO_DOC_NODE,"xxx",http_conn,http_bus_sess,http_req);
    err = -EINVAL;
		goto error;
  }

  {
		vpn_realm_str = (char*)rhp_xml_get_prop(node,(const xmlChar*)"vpn_realm");
		if( vpn_realm_str == NULL ){
			err = RHP_STATUS_INVALID_MSG;
			RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_CONNECT_I_NO_VPN_REALM,"xxx",http_conn,http_bus_sess,http_req);
			goto error;
		}

		rlm_id = strtoul((char*)vpn_realm_str,&endp,0);
		if( (rlm_id == ULONG_MAX && errno == ERANGE) || *endp != '\0' ){
			err = -ENOENT;
			RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_CONNECT_I_NO_VPN_REALM_2,"xxxs",http_conn,http_bus_sess,http_req,vpn_realm_str);
			goto error;
		}
  }

  if( _rhp_ui_http_permitted(http_conn,http_bus_sess,rlm_id) ){
  	err = -EPERM;
		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_CONNECT_I_NOT_PERMITTED,"xxxuu",http_conn,http_bus_sess,http_req,http_conn->user_realm_id,http_bus_sess->user_realm_id);
		goto error;
	}

  if( rlm_id == 0 ){
  	err = -ENOENT;
		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_CONNECT_I_RLM_ZERO,"xxxuu",http_conn,http_bus_sess,http_req,http_conn->user_realm_id,http_bus_sess->user_realm_id);
		goto error;
  }

  {
		peer_id_type_str = (char*)rhp_xml_get_prop(node,(const xmlChar*)"peer_id_type");

		if( peer_id_type_str ){

			peer_id_str = (char*)rhp_xml_get_prop(node,(const xmlChar*)"peer_id");
			if( peer_id_str == NULL ){
				err = RHP_STATUS_INVALID_MSG;
				RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_CONNECT_I_NO_PEER_ID,"xxx",http_conn,http_bus_sess,http_req);
				goto error;
			}

			err = rhp_cfg_parse_ikev2_id(node,(xmlChar*)"peer_id_type",(xmlChar*)"peer_id",&peer_id);
			if( err ){
				RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_CONNECT_I_NO_PEER_ID_2,"xxxss",http_conn,http_bus_sess,http_req,peer_id_str,peer_id_str);
				goto error;
			}

			peer_id_p = &peer_id;

			if( rhp_vpn_connect_i_pending_put(rlm_id,peer_id_p,NULL) ){
				RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_CONNECT_I_RSLV_FQDN_PENDING,"xxxss",http_conn,http_bus_sess,http_req,peer_id_str,peer_id_str);
				err = -EBUSY;
				goto error;
			}
		}
  }


  if( rhp_gcfg_webmng_allow_nobody_admin &&
  		http_conn->is_nobody && http_bus_sess->is_nobody ){

  	auto_reconnect = rhp_gcfg_webmng_auto_reconnect_nobody_admin;
  }
  rhp_xml_check_enable(node,(xmlChar*)"auto_reconnect",&auto_reconnect);


  {
		err = _rhp_ui_http_get_peer_addr_port(node,&peer_addr,&peer_fqdn_p,&peer_port);
		if( err ){
			RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_CONNECT_I_PARSE_PEER_ADDR_ERR,"xxx",http_conn,http_bus_sess,http_req);
			goto error;
		}

		if( !rhp_ip_addr_null(&peer_addr) ){
			peer_addr_p = &peer_addr;
		}
  }


  {
  	eap_sup_method_str = (char*)rhp_xml_get_prop(node,(const xmlChar*)"eap_sup_method");
		if( eap_sup_method_str ){

			eap_sup_method = rhp_eap_sup_impl_str2method(eap_sup_method_str);
			if( eap_sup_method < 1 ){
				err = RHP_STATUS_INVALID_MSG;
				RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_CONNECT_I_UNKNOWN_EAP_SUP_METHOD,"xxx",http_conn,http_bus_sess,http_req);
				goto error;
			}

			eap_sup_user_id = (char*)rhp_xml_get_prop(node,(const xmlChar*)"eap_sup_user_id");
			eap_sup_user_key = (char*)rhp_xml_get_prop(node,(const xmlChar*)"eap_sup_user_key");

			if( eap_sup_user_id == NULL || eap_sup_user_key == NULL ){
				err = RHP_STATUS_INVALID_MSG;
				RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_CONNECT_I_UNKNOWN_EAP_SUP_NO_USER_ID_OR_KEY,"xxxss",http_conn,http_bus_sess,http_req,eap_sup_user_id,eap_sup_user_key);
				goto error;
			}
		}
  }


  ui_ctx.ui_type = RHP_UI_TYPE_HTTP;
  strcpy(ui_ctx.user_name,http_bus_sess->user_name);
  ui_ctx.http.http_bus_sess_id = http_bus_sess->session_id;
  ui_ctx.vpn_realm_id = http_conn->user_realm_id;

  {
		void* con_task_ctx = _rhp_ui_http_vpn_conn_i_task_alloc_ctx(rlm_id,
				peer_id_p,peer_addr_p,peer_fqdn_p,peer_port,&ui_ctx,auto_reconnect,0,NULL,
				eap_sup_method,eap_sup_user_id,eap_sup_user_key);

		if( con_task_ctx == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		err = rhp_wts_switch_ctx(RHP_WTS_DISP_LEVEL_HIGH_2,
				_rhp_ui_http_vpn_connect_i_task,con_task_ctx);

		if( err ){
			_rhp_ui_http_vpn_conn_i_task_free_ctx(con_task_ctx);
			RHP_BUG("%d",err);
			goto error;
		}
  }

  err = rhp_http_bus_send_response(http_conn,http_bus_sess,NULL,NULL);
  if( err ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_CONNECT_I_TX_RESP_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
    goto error;
  }

  if( vpn_realm_str ){
  	_rhp_free(vpn_realm_str);
  }
  if( peer_id_type_str ){
  	_rhp_free(peer_id_type_str);
  }
  if( peer_id_str ){
  	_rhp_free(peer_id_str);
  }
  rhp_ikev2_id_clear(&peer_id);

  if( eap_sup_method_str ){
  	_rhp_free(eap_sup_method_str);
  }
  if( eap_sup_user_key ){
  	_rhp_free(eap_sup_user_key);
  }
  if( eap_sup_user_id ){
  	_rhp_free(eap_sup_user_id);
  }

  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_CONNECT_I_RTRN,"xxx",http_conn,http_bus_sess,http_req);
  return RHP_STATUS_CLOSE_HTTP_CONN;

error:

	if( err != -EBUSY ){
		RHP_LOG_E(RHP_LOG_SRC_UI,rlm_id,RHP_LOG_ID_CONNECT_I_ERR,"IAsE",&peer_id,&peer_addr,peer_fqdn_p,err);
	}

	if( vpn_realm_str ){
		_rhp_free(vpn_realm_str);
	}
  if( peer_id_type_str ){
  	_rhp_free(peer_id_type_str);
  }
  if( peer_id_str ){
  	_rhp_free(peer_id_str);
  }

  if( eap_sup_method_str ){
  	_rhp_free(eap_sup_method_str);
  }
  if( eap_sup_user_key ){
  	_rhp_free(eap_sup_user_key);
  }
  if( eap_sup_user_id ){
  	_rhp_free(eap_sup_user_id);
  }

  if( peer_id_p ){
  	rhp_vpn_connect_i_pending_clear(rlm_id,peer_id_p,NULL);
  }
  rhp_ikev2_id_clear(&peer_id);

  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_CONNECT_I_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  return err;
}

static int _rhp_ui_http_vpn_close(xmlDocPtr doc,xmlNodePtr node,rhp_http_conn* http_conn,
		rhp_http_bus_session* http_bus_sess,rhp_http_request* http_req,void* ctx)
{
  int err = -EINVAL;
  char* vpn_realm_str = NULL;
  char* peer_id_type_str = NULL;
  char* peer_id_str = NULL;
  rhp_ikev2_id peer_id;
  rhp_ip_addr peer_addr;
  rhp_ip_addr* peer_addr_p = NULL;
  char* peer_fqdn_p = NULL;
  unsigned long rlm_id = (unsigned long)-1;
  char* endp;
  rhp_ui_ctx ui_ctx;
  char* unique_id_str = NULL;
  int vpn_unique_id_flag = 0;
	u8 vpn_unique_id[RHP_VPN_UNIQUE_ID_SIZE];


  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_CLOSE,"xxxxxx",doc,node,http_conn,http_bus_sess,http_req,ctx);

  memset(&ui_ctx,0,sizeof(rhp_ui_ctx));
	memset(&peer_id,0,sizeof(rhp_ikev2_id));

  if( doc == NULL || node == NULL ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_CLOSE_NO_DOC_NODE,"xxx",http_conn,http_bus_sess,http_req);
    return -EINVAL;
  }

  vpn_realm_str = (char*)rhp_xml_get_prop(node,(const xmlChar*)"vpn_realm");
  if( vpn_realm_str == NULL ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_CLOSE_NO_VPN_REALM,"xxx",http_conn,http_bus_sess,http_req);
    goto error;
  }

  rlm_id = strtoul((char*)vpn_realm_str,&endp,0);
  if( (rlm_id == ULONG_MAX && errno == ERANGE) || *endp != '\0' ){
  	err = -ENOENT;
  	RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_CLOSE_NO_VPN_REALM_2,"xxxs",http_conn,http_bus_sess,http_req,vpn_realm_str);
  	goto error;
  }

  if( _rhp_ui_http_permitted(http_conn,http_bus_sess,rlm_id) ){
			err = -EPERM;
			RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_CLOSE_NOT_PERMITTED,"xxxuu",http_conn,http_bus_sess,http_req,http_conn->user_realm_id,http_bus_sess->user_realm_id);
			goto error;
	}

	peer_id.type = RHP_PROTO_IKE_ID_ANY;

  peer_id_type_str = (char*)rhp_xml_get_prop(node,(const xmlChar*)"peer_id_type");

  if( peer_id_type_str ){

		peer_id_str = (char*)rhp_xml_get_prop(node,(const xmlChar*)"peer_id");
		if( peer_id_str == NULL ){
			err = RHP_STATUS_INVALID_MSG;
			RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_CLOSE_NO_PEER_ID,"xxx",http_conn,http_bus_sess,http_req);
			goto error;
		}

	  err = rhp_cfg_parse_ikev2_id(node,(xmlChar*)"peer_id_type",(xmlChar*)"peer_id",&peer_id);
	  if( err ){
	    RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_CLOSE_NO_PEER_ID_2,"xxxss",http_conn,http_bus_sess,http_req,peer_id_str,peer_id_str);
	    goto error;
	  }
  }

  {
  	u16 peer_port = 0;

  	err = _rhp_ui_http_get_peer_addr_port(node,&peer_addr,&peer_fqdn_p,&peer_port);
  	if( err ){
  		goto error;
  	}

  	if( !rhp_ip_addr_null(&peer_addr) ){
  		peer_addr_p = &peer_addr;
  	}
  }


  unique_id_str = (char*)rhp_xml_get_prop(node,(const xmlChar*)"vpn_unique_id");
  if( unique_id_str ){

  	memset(vpn_unique_id,0,RHP_VPN_UNIQUE_ID_SIZE);

  	err = rhp_str_to_vpn_unique_id(unique_id_str,vpn_unique_id);
  	if( err ){
  		goto error;
  	}

  	vpn_unique_id_flag = 1;
  }


  ui_ctx.ui_type = RHP_UI_TYPE_HTTP;
  strcpy(ui_ctx.user_name,http_bus_sess->user_name);
  ui_ctx.http.http_bus_sess_id = http_bus_sess->session_id;
  ui_ctx.vpn_realm_id = http_conn->user_realm_id;

  {
		void* con_task_ctx = _rhp_ui_http_vpn_conn_i_task_alloc_ctx(rlm_id,
				&peer_id,peer_addr_p,peer_fqdn_p,0,&ui_ctx,0,vpn_unique_id_flag,vpn_unique_id,
				0,NULL,NULL);

		if( con_task_ctx == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		err = rhp_wts_switch_ctx(RHP_WTS_DISP_LEVEL_HIGH_2,
				_rhp_ui_http_vpn_close_task,con_task_ctx);

		if( err ){
			_rhp_ui_http_vpn_conn_i_task_free_ctx(con_task_ctx);
			RHP_BUG("%d",err);
			goto error;
		}
  }


  err = rhp_http_bus_send_response(http_conn,http_bus_sess,NULL,NULL);
  if( err ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_CLOSE_TX_RESP_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
    goto error;
  }

  if( vpn_realm_str ){
  	_rhp_free(vpn_realm_str);
  }
  if( peer_id_type_str ){
  	_rhp_free(peer_id_type_str);
  }
  if( peer_id_str ){
  	_rhp_free(peer_id_str);
  }
  if( unique_id_str ){
  	_rhp_free(unique_id_str);
  }

  rhp_ikev2_id_clear(&peer_id);

  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_CLOSE_RTRN,"xxxsss",http_conn,http_bus_sess,http_req,vpn_realm_str,peer_id_type_str,peer_id_str);
  return RHP_STATUS_CLOSE_HTTP_CONN;

error:
	RHP_LOG_E(RHP_LOG_SRC_UI,rlm_id,RHP_LOG_ID_CLOSE_VPN_ERR,"IAsE",&peer_id,&peer_addr,peer_fqdn_p,err);
	if( vpn_realm_str ){
		_rhp_free(vpn_realm_str);
	}
	if( peer_id_type_str ){
		_rhp_free(peer_id_type_str);
	}
	if( peer_id_str ){
		_rhp_free(peer_id_str);
	}
  if( unique_id_str ){
  	_rhp_free(unique_id_str);
  }
  rhp_ikev2_id_clear(&peer_id);

  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_CLOSE_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  return err;
}


extern int rhp_ikev2_mobike_i_start_ui(unsigned long rlm_id,rhp_ikev2_id* peer_id,
		u8* vpn_unique_id,rhp_ui_ctx* ui_info);

static int _rhp_ui_http_vpn_mobike_i_start_rt_check(xmlDocPtr doc,xmlNodePtr node,rhp_http_conn* http_conn,
		rhp_http_bus_session* http_bus_sess,rhp_http_request* http_req,void* ctx)
{
  int err = -EINVAL;
  char* vpn_realm_str = NULL;
  char* peer_id_type_str = NULL;
  char* peer_id_str = NULL;
  rhp_ikev2_id peer_id;
  unsigned long rlm_id = (unsigned long)-1;
  char* endp;
  rhp_ui_ctx ui_ctx;
  char* unique_id_str = NULL;
  int vpn_unique_id_flag = 0;
	u8 vpn_unique_id[RHP_VPN_UNIQUE_ID_SIZE];


  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_MOBIKE_I_START_RT_CHECK,"xxxxxx",doc,node,http_conn,http_bus_sess,http_req,ctx);

  memset(&ui_ctx,0,sizeof(rhp_ui_ctx));
	memset(&peer_id,0,sizeof(rhp_ikev2_id));

  if( doc == NULL || node == NULL ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_MOBIKE_I_START_RT_CHECK_NO_DOC_NODE,"xxx",http_conn,http_bus_sess,http_req);
    return -EINVAL;
  }

  vpn_realm_str = (char*)rhp_xml_get_prop(node,(const xmlChar*)"vpn_realm");
  if( vpn_realm_str == NULL ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_MOBIKE_I_START_RT_CHECK_NO_VPN_REALM,"xxx",http_conn,http_bus_sess,http_req);
    goto error;
  }

  rlm_id = strtoul((char*)vpn_realm_str,&endp,0);
  if( (rlm_id == ULONG_MAX && errno == ERANGE) || *endp != '\0' ){
  	err = -ENOENT;
  	RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_MOBIKE_I_START_RT_CHECK_NO_VPN_REALM_2,"xxxs",http_conn,http_bus_sess,http_req,vpn_realm_str);
  	goto error;
  }

  if( _rhp_ui_http_permitted(http_conn,http_bus_sess,rlm_id) ){
			err = -EPERM;
			RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_MOBIKE_I_START_RT_CHECK_NOT_PERMITTED,"xxxuu",http_conn,http_bus_sess,http_req,http_conn->user_realm_id,http_bus_sess->user_realm_id);
			goto error;
	}

  if( rlm_id == 0 ){
		err = -ENOENT;
		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_MOBIKE_I_START_RT_CHECK_RLM_ZERO,"xxxuu",http_conn,http_bus_sess,http_req,http_conn->user_realm_id,http_bus_sess->user_realm_id);
		goto error;
  }

	peer_id.type = RHP_PROTO_IKE_ID_ANY;

  peer_id_type_str = (char*)rhp_xml_get_prop(node,(const xmlChar*)"peer_id_type");

  if( peer_id_type_str ){

		peer_id_str = (char*)rhp_xml_get_prop(node,(const xmlChar*)"peer_id");
		if( peer_id_str == NULL ){
			err = RHP_STATUS_INVALID_MSG;
			RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_MOBIKE_I_START_RT_CHECK_NO_PEER_ID,"xxx",http_conn,http_bus_sess,http_req);
			goto error;
		}

	  err = rhp_cfg_parse_ikev2_id(node,(xmlChar*)"peer_id_type",(xmlChar*)"peer_id",&peer_id);
	  if( err ){
	    RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_MOBIKE_I_START_RT_CHECK_NO_PEER_ID_2,"xxxss",http_conn,http_bus_sess,http_req,peer_id_str,peer_id_str);
	    goto error;
	  }
  }


  unique_id_str = (char*)rhp_xml_get_prop(node,(const xmlChar*)"vpn_unique_id");
  if( unique_id_str ){

  	memset(vpn_unique_id,0,RHP_VPN_UNIQUE_ID_SIZE);

  	err = rhp_str_to_vpn_unique_id(unique_id_str,vpn_unique_id);
  	if( err ){
  		goto error;
  	}

  	vpn_unique_id_flag = 1;
  }


  ui_ctx.ui_type = RHP_UI_TYPE_HTTP;
  strcpy(ui_ctx.user_name,http_bus_sess->user_name);
  ui_ctx.http.http_bus_sess_id = http_bus_sess->session_id;
  ui_ctx.vpn_realm_id = http_conn->user_realm_id;


  err = rhp_ikev2_mobike_i_start_ui(rlm_id,&peer_id,
  				(vpn_unique_id_flag ? vpn_unique_id : NULL),&ui_ctx);

  if( err ){
		goto error;
	}


  err = rhp_http_bus_send_response(http_conn,http_bus_sess,NULL,NULL);
  if( err ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_MOBIKE_I_START_RT_CHECK_TX_RESP_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
    goto error;
  }

  if( vpn_realm_str ){
  	_rhp_free(vpn_realm_str);
  }
  if( peer_id_type_str ){
  	_rhp_free(peer_id_type_str);
  }
  if( peer_id_str ){
  	_rhp_free(peer_id_str);
  }
  if( unique_id_str ){
  	_rhp_free(unique_id_str);
  }

  rhp_ikev2_id_clear(&peer_id);

  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_MOBIKE_I_START_RT_CHECK_RTRN,"xxxsss",http_conn,http_bus_sess,http_req,vpn_realm_str,peer_id_type_str,peer_id_str);
  return RHP_STATUS_CLOSE_HTTP_CONN;

error:
	RHP_LOG_E(RHP_LOG_SRC_UI,rlm_id,RHP_LOG_ID_MOBIKE_I_START_RT_CHECK_ERR,"IE",&peer_id,err);
	if( vpn_realm_str ){
		_rhp_free(vpn_realm_str);
	}
	if( peer_id_type_str ){
		_rhp_free(peer_id_type_str);
	}
	if( peer_id_str ){
		_rhp_free(peer_id_str);
	}
  if( unique_id_str ){
  	_rhp_free(unique_id_str);
  }
  rhp_ikev2_id_clear(&peer_id);

  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_MOBIKE_I_START_RT_CHECK_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  return err;
}

static int _rhp_ui_http_vpn_get_info_ikesa_serialize(rhp_vpn* vpn,void* writer,int* n2)
{
	int err = -EINVAL;
	rhp_ikesa* ikesa = vpn->ikesa_list_head;
	int idx = 0;
	int n = 0;

	//
	// vpn->rlm is already acquired.
	//

	while( ikesa ){

		n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"ikesa");
		if(n < 0) {
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;

		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"index","%d",idx);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;

		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"initiator_spi",
			"%llu(0x%02x%02x%02x%02x%02x%02x%02x%02x)",bswap_64(*((u64*)ikesa->init_spi)),
			ikesa->init_spi[0],ikesa->init_spi[1],ikesa->init_spi[2],ikesa->init_spi[3],ikesa->init_spi[4],ikesa->init_spi[5],ikesa->init_spi[6],ikesa->init_spi[7]);

		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;

		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"responder_spi",
			"%llu(0x%02x%02x%02x%02x%02x%02x%02x%02x)",bswap_64(*((u64*)ikesa->resp_spi)),
			ikesa->resp_spi[0],ikesa->resp_spi[1],ikesa->resp_spi[2],ikesa->resp_spi[3],ikesa->resp_spi[4],ikesa->resp_spi[5],ikesa->resp_spi[6],ikesa->resp_spi[7]);

		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;

		if( ikesa->side == RHP_IKE_INITIATOR ){
			n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"side",(xmlChar*)"initiator");
		}else{
			n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"side",(xmlChar*)"responder");
		}
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;


		{
			switch( ikesa->state ){

			case RHP_IKESA_STAT_DEFAULT:
				n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"state",(xmlChar*)"default");
				break;

			case RHP_IKESA_STAT_I_IKE_SA_INIT_SENT:
				n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"state",(xmlChar*)"i_ike_sa_init_sent");
				break;
			case RHP_IKESA_STAT_I_AUTH_SENT:
				n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"state",(xmlChar*)"i_auth_sent");
				break;
			case RHP_IKESA_STAT_R_IKE_SA_INIT_SENT:
				n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"state",(xmlChar*)"r_ike_sa_init_sent");
				break;
			case RHP_IKESA_STAT_ESTABLISHED:
				n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"state",(xmlChar*)"established");
				break;
			case RHP_IKESA_STAT_REKEYING:
				if( ikesa->side == RHP_IKE_RESPONDER && vpn->rlm->ikesa.resp_not_rekeying ){
 					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"state",(xmlChar*)"established");
 				}else{
 					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"state",(xmlChar*)"rekeying");
 				}
				break;
			case RHP_IKESA_STAT_DELETE:
				n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"state",(xmlChar*)"delete");
				break;
			case RHP_IKESA_STAT_DELETE_WAIT:
				n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"state",(xmlChar*)"delete_wait");
				break;
			case RHP_IKESA_STAT_I_REKEY_SENT:
				n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"state",(xmlChar*)"i_rekey_sent");
				break;
			case RHP_IKESA_STAT_DEAD:
				n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"state",(xmlChar*)"dead");
				break;

			case RHP_IKESA_STAT_V1_MAIN_1ST_SENT_I:
				n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"state",(xmlChar*)"i_1st_sent");
				break;
			case RHP_IKESA_STAT_V1_MAIN_3RD_SENT_I:
				n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"state",(xmlChar*)"i_3rd_sent");
				break;
			case RHP_IKESA_STAT_V1_MAIN_5TH_SENT_I:
				n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"state",(xmlChar*)"i_5th_sent");
				break;
			case RHP_IKESA_STAT_V1_MAIN_2ND_SENT_R:
				n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"state",(xmlChar*)"r_2nd_sent");
				break;
			case RHP_IKESA_STAT_V1_MAIN_4TH_SENT_R:
				n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"state",(xmlChar*)"r_4th_sent");
				break;
			case RHP_IKESA_STAT_V1_AGG_1ST_SENT_I:
				n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"state",(xmlChar*)"i_1st_sent");
				break;
			case RHP_IKESA_STAT_V1_AGG_WAIT_COMMIT_I:
				n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"state",(xmlChar*)"i_commit_wait");
				break;
			case RHP_IKESA_STAT_V1_AGG_2ND_SENT_R:
				n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"state",(xmlChar*)"r_2nd_sent");
				break;
			case RHP_IKESA_STAT_V1_ESTABLISHED:
				n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"state",(xmlChar*)"established");
				break;
			case RHP_IKESA_STAT_V1_REKEYING:
				if( ikesa->side == RHP_IKE_RESPONDER && vpn->rlm->ikesa.resp_not_rekeying ){
 					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"state",(xmlChar*)"established");
 				}else{
 					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"state",(xmlChar*)"rekeying");
 				}
				break;
			case RHP_IKESA_STAT_V1_DELETE:
				n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"state",(xmlChar*)"delete");
				break;
			case RHP_IKESA_STAT_V1_DELETE_WAIT:
				n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"state",(xmlChar*)"delete_wait");
				break;
			case RHP_IKESA_STAT_V1_DEAD:
				n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"state",(xmlChar*)"dead");
				break;

			case RHP_IKESA_STAT_V1_XAUTH_PEND_I:
				n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"state",(xmlChar*)"i_xauth_pending");
				break;
			case RHP_IKESA_STAT_V1_XAUTH_PEND_R:
				n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"state",(xmlChar*)"r_xauth_pending");
				break;

			default:
				n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"state",(xmlChar*)"unknown");
				break;
			}

			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;
		}


		{
			switch( ikesa->auth_method ){
			case RHP_PROTO_IKE_AUTHMETHOD_RSA_SIG:
				n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"auth_method",(xmlChar*)"rsa-sig");
				break;
			case RHP_PROTO_IKE_AUTHMETHOD_SHARED_KEY:
				n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"auth_method",(xmlChar*)"psk");
				break;
			case RHP_PROTO_IKE_AUTHMETHOD_DSS_SIG:
				n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"auth_method",(xmlChar*)"dss-sig");
				break;
			case RHP_PROTO_IKE_AUTHMETHOD_NULL_AUTH:
				n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"auth_method",(xmlChar*)"null-auth");
				break;
			default:
				n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"auth_method",(xmlChar*)"unknown");
				break;
			}

			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;
		}

		{
			switch( ikesa->peer_auth_method ){
			case RHP_PROTO_IKE_AUTHMETHOD_RSA_SIG:
				n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"peer_auth_method",(xmlChar*)"rsa-sig");
				break;
			case RHP_PROTO_IKE_AUTHMETHOD_SHARED_KEY:
				n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"peer_auth_method",(xmlChar*)"psk");
				break;
			case RHP_PROTO_IKE_AUTHMETHOD_DSS_SIG:
				n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"peer_auth_method",(xmlChar*)"dss_sig");
				break;
			case RHP_PROTO_IKE_AUTHMETHOD_NULL_AUTH:
				n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"peer_auth_method",(xmlChar*)"null-auth");
				break;
			default:
				n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"peer_auth_method",(xmlChar*)"unknown");
				break;
			}

			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;
		}


		if( !vpn->is_v1 ){

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"proposal_no","%d",ikesa->prop.v2.number);
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;

			{
				switch( ikesa->prop.v2.prf_id ){
				case RHP_PROTO_IKE_TRANSFORM_ID_PRF_HMAC_MD5:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"prf",(xmlChar*)"hmac_md5");
					break;
				case RHP_PROTO_IKE_TRANSFORM_ID_PRF_HMAC_SHA1:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"prf",(xmlChar*)"hmac_sha1");
					break;
				case RHP_PROTO_IKE_TRANSFORM_ID_PRF_HMAC_TIGER:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"prf",(xmlChar*)"hmac_tiger");
					break;
				case RHP_PROTO_IKE_TRANSFORM_ID_PRF_AES128_CBC:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"prf",(xmlChar*)"aes128_cbc");
					break;
				case RHP_PROTO_IKE_TRANSFORM_ID_PRF_HMAC_SHA2_256:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"prf",(xmlChar*)"hmac_sha2_256");
					break;
				case RHP_PROTO_IKE_TRANSFORM_ID_PRF_HMAC_SHA2_384:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"prf",(xmlChar*)"hmac_sha2_384");
					break;
				case RHP_PROTO_IKE_TRANSFORM_ID_PRF_HMAC_SHA2_512:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"prf",(xmlChar*)"hmac_sha2_512");
					break;
				default:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"prf",(xmlChar*)"unknown");
					break;
				}

				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error;
				}
				*n2 += n;
			}

			{
				switch( ikesa->prop.v2.dhgrp_id ){
				case RHP_PROTO_IKE_TRANSFORM_ID_DH_1:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"dh_group",(xmlChar*)"1");
					break;
				case RHP_PROTO_IKE_TRANSFORM_ID_DH_2:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"dh_group",(xmlChar*)"2");
					break;
				case RHP_PROTO_IKE_TRANSFORM_ID_DH_5:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"dh_group",(xmlChar*)"5");
					break;
				case RHP_PROTO_IKE_TRANSFORM_ID_DH_14:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"dh_group",(xmlChar*)"14");
					break;
				case RHP_PROTO_IKE_TRANSFORM_ID_DH_15:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"dh_group",(xmlChar*)"15");
					break;
				case RHP_PROTO_IKE_TRANSFORM_ID_DH_16:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"dh_group",(xmlChar*)"16");
					break;
				case RHP_PROTO_IKE_TRANSFORM_ID_DH_17:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"dh_group",(xmlChar*)"17");
					break;
				case RHP_PROTO_IKE_TRANSFORM_ID_DH_18:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"dh_group",(xmlChar*)"18");
					break;
				default:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"dh_group",(xmlChar*)"unknown");
					break;
				}

				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error;
				}
				*n2 += n;
			}

			{
				switch( ikesa->prop.v2.integ_id ){
				case RHP_PROTO_IKE_TRANSFORM_ID_AUTH_HMAC_MD5_96:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"integ",(xmlChar*)"hmac_md5_96");
					break;
				case RHP_PROTO_IKE_TRANSFORM_ID_AUTH_HMAC_SHA1_96:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"integ",(xmlChar*)"hmac_sha1_96");
					break;
				case RHP_PROTO_IKE_TRANSFORM_ID_AUTH_DES_MAC:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"integ",(xmlChar*)"des_mac");
					break;
				case RHP_PROTO_IKE_TRANSFORM_ID_AUTH_KPDK_MD5:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"integ",(xmlChar*)"kpdk_md5");
					break;
				case RHP_PROTO_IKE_TRANSFORM_ID_AUTH_AES_XCBC_96:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"integ",(xmlChar*)"aes_xcbc_96");
					break;
				case RHP_PROTO_IKE_TRANSFORM_ID_AUTH_HMAC_SHA2_256_128:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"integ",(xmlChar*)"hmac_sha2_256_128");
					break;
				case RHP_PROTO_IKE_TRANSFORM_ID_AUTH_HMAC_SHA2_384_192:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"integ",(xmlChar*)"hmac_sha2_384_192");
					break;
				case RHP_PROTO_IKE_TRANSFORM_ID_AUTH_HMAC_SHA2_512_256:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"integ",(xmlChar*)"hmac_sha2_512_256");
					break;
				default:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"integ",(xmlChar*)"unknown");
					break;
				}

				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error;
				}
				*n2 += n;
			}

			{
				switch( ikesa->prop.v2.encr_id ){
				case RHP_PROTO_IKE_TRANSFORM_ID_ENCR_DES:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"encr",(xmlChar*)"des");
					break;
				case RHP_PROTO_IKE_TRANSFORM_ID_ENCR_3DES:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"encr",(xmlChar*)"3des");
					break;
				case RHP_PROTO_IKE_TRANSFORM_ID_ENCR_AES_CBC:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"encr",(xmlChar*)"aes_cbc");
					break;
				case RHP_PROTO_IKE_TRANSFORM_ID_ENCR_AES_CTR:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"encr",(xmlChar*)"aes_ctr");
					break;
				case RHP_PROTO_IKE_TRANSFORM_ID_ENCR_NULL:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"encr",(xmlChar*)"null");
					break;
				default:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"encr",(xmlChar*)"unknown");
					break;
				}

				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error;
				}
				*n2 += n;

				if( ikesa->prop.v2.encr_key_bits ){

					n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"encr_key_bits","%d",
							ikesa->prop.v2.encr_key_bits);
					if(n < 0){
						err = -ENOMEM;
						RHP_BUG("");
						goto error;
					}
					*n2 += n;
				}
			}

		}else{ // vpn->is_v1 == 1

			{
				switch( ikesa->v1.p1_exchange_mode ){
				case RHP_PROTO_IKEV1_EXCHG_ID_PROTECTION:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"v1_exchange_mode",(xmlChar*)"main");
					break;
				case RHP_PROTO_IKEV1_EXCHG_AGGRESSIVE:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"v1_exchange_mode",(xmlChar*)"aggressive");
					break;
				default:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"v1_exchange_mode",(xmlChar*)"unknown");
					break;
				}

				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error;
				}
				*n2 += n;
			}


			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"proposal_no","%d",ikesa->prop.v1.number);
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;

			{
				switch( ikesa->prop.v1.hash_alg ){
				case RHP_PROTO_IKEV1_P1_ATTR_HASH_MD5:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"hash",(xmlChar*)"md5");
					break;
				case RHP_PROTO_IKEV1_P1_ATTR_HASH_SHA1:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"hash",(xmlChar*)"sha1");
					break;
				case RHP_PROTO_IKEV1_P1_ATTR_HASH_SHA2_256:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"hash",(xmlChar*)"sha256");
					break;
				case RHP_PROTO_IKEV1_P1_ATTR_HASH_SHA2_384:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"hash",(xmlChar*)"sha384");
					break;
				case RHP_PROTO_IKEV1_P1_ATTR_HASH_SHA2_512:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"hash",(xmlChar*)"sha512");
					break;
				default:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"hash",(xmlChar*)"unknown");
					break;
				}

				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error;
				}
				*n2 += n;
			}

			if( ikesa->prf ){

				switch( ikesa->prf->alg ){
				case RHP_PROTO_IKE_TRANSFORM_ID_PRF_HMAC_MD5:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"prf",(xmlChar*)"hmac_md5");
					break;
				case RHP_PROTO_IKE_TRANSFORM_ID_PRF_HMAC_SHA1:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"prf",(xmlChar*)"hmac_sha1");
					break;
				case RHP_PROTO_IKE_TRANSFORM_ID_PRF_HMAC_TIGER:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"prf",(xmlChar*)"hmac_tiger");
					break;
				case RHP_PROTO_IKE_TRANSFORM_ID_PRF_AES128_CBC:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"prf",(xmlChar*)"aes128_cbc");
					break;
				case RHP_PROTO_IKE_TRANSFORM_ID_PRF_HMAC_SHA2_256:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"prf",(xmlChar*)"hmac_sha2_256");
					break;
				case RHP_PROTO_IKE_TRANSFORM_ID_PRF_HMAC_SHA2_384:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"prf",(xmlChar*)"hmac_sha2_384");
					break;
				case RHP_PROTO_IKE_TRANSFORM_ID_PRF_HMAC_SHA2_512:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"prf",(xmlChar*)"hmac_sha2_512");
					break;
				default:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"prf",(xmlChar*)"unknown");
					break;
				}

				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error;
				}
				*n2 += n;
			}

			{
				switch( ikesa->prop.v1.dh_group ){
				case RHP_PROTO_IKEV1_ATTR_GROUP_MODP_768:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"dh_group",(xmlChar*)"1");
					break;
				case RHP_PROTO_IKEV1_ATTR_GROUP_MODP_1024:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"dh_group",(xmlChar*)"2");
					break;
				case RHP_PROTO_IKEV1_ATTR_GROUP_MODP_1536:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"dh_group",(xmlChar*)"5");
					break;
				case RHP_PROTO_IKEV1_ATTR_GROUP_MODP_2048:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"dh_group",(xmlChar*)"14");
					break;
				case RHP_PROTO_IKEV1_ATTR_GROUP_MODP_3072:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"dh_group",(xmlChar*)"15");
					break;
				case RHP_PROTO_IKEV1_ATTR_GROUP_MODP_4096:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"dh_group",(xmlChar*)"16");
					break;
				case RHP_PROTO_IKEV1_ATTR_GROUP_MODP_6144:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"dh_group",(xmlChar*)"17");
					break;
				case RHP_PROTO_IKEV1_ATTR_GROUP_MODP_8192:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"dh_group",(xmlChar*)"18");
					break;
				default:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"dh_group",(xmlChar*)"unknown");
					break;
				}

				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error;
				}
				*n2 += n;
			}

			{
				switch( ikesa->prop.v1.enc_alg ){
				case RHP_PROTO_IKEV1_P1_ATTR_ENC_3DES_CBC:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"encr",(xmlChar*)"3des");
					break;
				case RHP_PROTO_IKEV1_P1_ATTR_ENC_AES_CBC:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"encr",(xmlChar*)"aes_cbc");
					break;
				default:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"encr",(xmlChar*)"unknown");
					break;
				}

				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error;
				}
				*n2 += n;

				if( ikesa->prop.v1.key_bits_len ){

					n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"encr_key_bits","%d",
							ikesa->prop.v1.key_bits_len);
					if(n < 0){
						err = -ENOMEM;
						RHP_BUG("");
						goto error;
					}
					*n2 += n;
				}
			}
		}


		{
			time_t now = _rhp_get_time();
			time_t tt = 0;

			if( ikesa->established_time ){
				tt = (now - ikesa->established_time);
			}else{
				tt = 0;
			}

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"established_time_elapsed","%ld",tt);
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;

			if( ikesa->created_time ){
				tt = (now - ikesa->created_time);
			}else{
				tt = 0;
			}

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"created_time_elapsed","%ld",tt);
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;

			if( ikesa->expire_hard ){
				tt = (ikesa->expire_hard - now);
			}else{
				tt = 0;
			}

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"expire_hard","%ld",tt);
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;

			if( ikesa->expire_soft ){
				tt = (ikesa->expire_soft - now);
			}else{
				tt = 0;
			}

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"expire_soft","%ld",tt);
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;
		}


		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rekeyed_gen","%d",ikesa->rekeyed_gen);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;


		switch( ikesa->eap.state ){
		case RHP_IKESA_EAP_STAT_DEFAULT:
			n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"eap_state",(xmlChar*)"default");
			break;
		case RHP_IKESA_EAP_STAT_I_PEND:
		case RHP_IKESA_EAP_STAT_R_PEND:
			n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"eap_state",(xmlChar*)"pending");
			break;
		case RHP_IKESA_EAP_STAT_I_COMP:
		case RHP_IKESA_EAP_STAT_R_COMP:
			n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"eap_state",(xmlChar*)"completed");
			break;
		default:
			n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"eap_state",(xmlChar*)"unknown");
			break;
		}
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;


		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"gen_by_sess_resume","%d",ikesa->gen_by_sess_resume);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;


		n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
		if(n < 0) {
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;


		idx++;
		ikesa = ikesa->next_vpn_list;
	}

	return 0;

error:
	return err;
}

static int _rhp_ui_http_vpn_get_info_childsa_serialize(rhp_vpn* vpn,void* writer,int* n2)
{
	int err = -EINVAL;
	rhp_childsa* childsa = vpn->childsa_list_head;
	int idx = 0;
	int n = 0;

	while( childsa ){

		n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"childsa");
		if(n < 0) {
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;

		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"index","%d",idx);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;

		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"inbound_spi",
			"%u(0x%x)",ntohl(childsa->spi_inb),ntohl(childsa->spi_inb));

		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;

		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"outbound_spi",
				"%u(0x%x)",ntohl(childsa->spi_outb),ntohl(childsa->spi_outb));

		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;

		if( childsa->side == RHP_IKE_INITIATOR ){
			n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"side",(xmlChar*)"initiator");
		}else{
			n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"side",(xmlChar*)"responder");
		}
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;


		{
			switch( childsa->state ){

			case RHP_CHILDSA_STAT_DEFAULT:
				n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"state",(xmlChar*)"default");
				break;

			case RHP_CHILDSA_STAT_LARVAL:
				n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"state",(xmlChar*)"negotiating");
				break;
			case RHP_CHILDSA_STAT_MATURE:
				n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"state",(xmlChar*)"established");
				break;
			case RHP_CHILDSA_STAT_REKEYING:
				if( childsa->side == RHP_IKE_RESPONDER && vpn->rlm->childsa.resp_not_rekeying ){
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"state",(xmlChar*)"established");
				}else{
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"state",(xmlChar*)"rekeying");
				}
				break;
			case RHP_CHILDSA_STAT_DELETE:
				n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"state",(xmlChar*)"delete");
				break;
			case RHP_CHILDSA_STAT_DELETE_WAIT:
				n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"state",(xmlChar*)"delete_wait");
				break;
			case RHP_CHILDSA_STAT_DEAD:
				n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"state",(xmlChar*)"dead");
				break;

			case RHP_IPSECSA_STAT_V1_1ST_SENT_I:
				n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"state",(xmlChar*)"i_1st_sent");
				break;
			case RHP_IPSECSA_STAT_V1_WAIT_COMMIT_I:
				n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"state",(xmlChar*)"i_commit_wait");
				break;
			case RHP_IPSECSA_STAT_V1_2ND_SENT_R:
				n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"state",(xmlChar*)"r_2nd_sent");
				break;
			case RHP_IPSECSA_STAT_V1_MATURE:
				n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"state",(xmlChar*)"established");
				break;
			case RHP_IPSECSA_STAT_V1_REKEYING:
				if( childsa->side == RHP_IKE_RESPONDER && vpn->rlm->childsa.resp_not_rekeying ){
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"state",(xmlChar*)"established");
				}else{
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"state",(xmlChar*)"rekeying");
				}
				break;
			case RHP_IPSECSA_STAT_V1_DELETE:
				n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"state",(xmlChar*)"delete");
				break;
			case RHP_IPSECSA_STAT_V1_DELETE_WAIT:
				n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"state",(xmlChar*)"delete_wait");
				break;
			case RHP_IPSECSA_STAT_V1_DEAD:
				n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"state",(xmlChar*)"dead");
				break;

			default:
				n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"state",(xmlChar*)"unknown");
				break;
			}

			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;
		}

		{
			switch( childsa->ipsec_mode ){
			case RHP_CHILDSA_MODE_TRANSPORT:
				n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"ipsec_mode",(xmlChar*)"transport");
				break;
			case RHP_CHILDSA_MODE_TUNNEL:
				n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"ipsec_mode",(xmlChar*)"tunnel");
				break;
			default:
				n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"ipsec_mode",(xmlChar*)"unknown");
				break;
			}

			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;
		}


		if( !vpn->is_v1 ){

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"proposal_no","%d",childsa->prop.v2.number);
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;


			{
				switch( childsa->prop.v2.dhgrp_id ){
				case RHP_PROTO_IKE_TRANSFORM_ID_DH_1:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"dh_group",(xmlChar*)"1");
					break;
				case RHP_PROTO_IKE_TRANSFORM_ID_DH_2:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"dh_group",(xmlChar*)"2");
					break;
				case RHP_PROTO_IKE_TRANSFORM_ID_DH_5:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"dh_group",(xmlChar*)"5");
					break;
				case RHP_PROTO_IKE_TRANSFORM_ID_DH_14:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"dh_group",(xmlChar*)"14");
					break;
				case RHP_PROTO_IKE_TRANSFORM_ID_DH_15:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"dh_group",(xmlChar*)"15");
					break;
				case RHP_PROTO_IKE_TRANSFORM_ID_DH_16:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"dh_group",(xmlChar*)"16");
					break;
				case RHP_PROTO_IKE_TRANSFORM_ID_DH_17:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"dh_group",(xmlChar*)"17");
					break;
				case RHP_PROTO_IKE_TRANSFORM_ID_DH_18:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"dh_group",(xmlChar*)"18");
					break;
				default:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"dh_group",(xmlChar*)"unknown");
					break;
				}

				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error;
				}
				*n2 += n;
			}

			{
				switch( childsa->prop.v2.integ_id ){
				case RHP_PROTO_IKE_TRANSFORM_ID_AUTH_HMAC_MD5_96:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"integ",(xmlChar*)"hmac_md5_96");
					break;
				case RHP_PROTO_IKE_TRANSFORM_ID_AUTH_HMAC_SHA1_96:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"integ",(xmlChar*)"hmac_sha1_96");
					break;
				case RHP_PROTO_IKE_TRANSFORM_ID_AUTH_DES_MAC:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"integ",(xmlChar*)"des_mac");
					break;
				case RHP_PROTO_IKE_TRANSFORM_ID_AUTH_KPDK_MD5:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"integ",(xmlChar*)"kpdk_md5");
					break;
				case RHP_PROTO_IKE_TRANSFORM_ID_AUTH_AES_XCBC_96:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"integ",(xmlChar*)"aes_xcbc_96");
					break;
				case RHP_PROTO_IKE_TRANSFORM_ID_AUTH_HMAC_SHA2_256_128:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"integ",(xmlChar*)"hmac_sha2_256_128");
					break;
				case RHP_PROTO_IKE_TRANSFORM_ID_AUTH_HMAC_SHA2_384_192:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"integ",(xmlChar*)"hmac_sha2_384_192");
					break;
				case RHP_PROTO_IKE_TRANSFORM_ID_AUTH_HMAC_SHA2_512_256:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"integ",(xmlChar*)"hmac_sha2_512_256");
					break;
				default:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"integ",(xmlChar*)"unknown");
					break;
				}

				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error;
				}
				*n2 += n;
			}

			{
				switch( childsa->prop.v2.encr_id ){
				case RHP_PROTO_IKE_TRANSFORM_ID_ENCR_DES:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"encr",(xmlChar*)"des");
					break;
				case RHP_PROTO_IKE_TRANSFORM_ID_ENCR_3DES:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"encr",(xmlChar*)"3des");
					break;
				case RHP_PROTO_IKE_TRANSFORM_ID_ENCR_AES_CBC:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"encr",(xmlChar*)"aes_cbc");
					break;
				case RHP_PROTO_IKE_TRANSFORM_ID_ENCR_AES_CTR:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"encr",(xmlChar*)"aes_ctr");
					break;
				case RHP_PROTO_IKE_TRANSFORM_ID_ENCR_NULL:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"encr",(xmlChar*)"null");
					break;
				default:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"encr",(xmlChar*)"unknown");
					break;
				}

				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error;
				}
				*n2 += n;

				if( childsa->prop.v2.encr_key_bits ){

					n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"encr_key_bits","%d",
							childsa->prop.v2.encr_key_bits);
					if(n < 0){
						err = -ENOMEM;
						RHP_BUG("");
						goto error;
					}
					*n2 += n;
				}
			}

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"pfs","%d",childsa->prop.v2.pfs);
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;


		}else{ // vpn->is_v1 == 1

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"proposal_no","%d",childsa->prop.v1.number);
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;


			if( childsa->v1.dh ){

				switch( childsa->v1.dh->grp ){
				case RHP_PROTO_IKEV1_ATTR_GROUP_MODP_768:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"dh_group",(xmlChar*)"1");
					break;
				case RHP_PROTO_IKEV1_ATTR_GROUP_MODP_1024:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"dh_group",(xmlChar*)"2");
					break;
				case RHP_PROTO_IKEV1_ATTR_GROUP_MODP_1536:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"dh_group",(xmlChar*)"5");
					break;
				case RHP_PROTO_IKEV1_ATTR_GROUP_MODP_2048:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"dh_group",(xmlChar*)"14");
					break;
				case RHP_PROTO_IKEV1_ATTR_GROUP_MODP_3072:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"dh_group",(xmlChar*)"15");
					break;
				case RHP_PROTO_IKEV1_ATTR_GROUP_MODP_4096:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"dh_group",(xmlChar*)"16");
					break;
				case RHP_PROTO_IKEV1_ATTR_GROUP_MODP_6144:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"dh_group",(xmlChar*)"17");
					break;
				case RHP_PROTO_IKEV1_ATTR_GROUP_MODP_8192:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"dh_group",(xmlChar*)"18");
					break;
				default:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"dh_group",(xmlChar*)"unknown");
					break;
				}

				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error;
				}
				*n2 += n;
			}

			{
				switch( childsa->prop.v1.auth_alg ){
				case RHP_PROTO_IKEV1_P2_ATTR_AUTH_HMAC_MD5:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"integ",(xmlChar*)"hmac_md5_96");
					break;
				case RHP_PROTO_IKEV1_P2_ATTR_AUTH_HMAC_SHA1:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"integ",(xmlChar*)"hmac_sha1_96");
					break;
				case RHP_PROTO_IKEV1_P2_ATTR_AUTH_HMAC_SHA2_256:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"integ",(xmlChar*)"hmac_sha2_256_128");
					break;
				case RHP_PROTO_IKEV1_P2_ATTR_AUTH_HMAC_SHA2_384:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"integ",(xmlChar*)"hmac_sha2_384_192");
					break;
				case RHP_PROTO_IKEV1_P2_ATTR_AUTH_HMAC_SHA2_512:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"integ",(xmlChar*)"hmac_sha2_512_256");
					break;
				default:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"integ",(xmlChar*)"unknown");
					break;
				}

				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error;
				}
				*n2 += n;
			}

			{
				switch( childsa->v1.trans_id ){
				case RHP_PROTO_IKEV1_TF_ESP_3DES:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"encr",(xmlChar*)"3des");
					break;
				case RHP_PROTO_IKEV1_TF_ESP_AES_CBC:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"encr",(xmlChar*)"aes_cbc");
					break;
				case RHP_PROTO_IKEV1_TF_ESP_NULL:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"encr",(xmlChar*)"null");
					break;
				default:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"encr",(xmlChar*)"unknown");
					break;
				}

				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error;
				}
				*n2 += n;

				if( childsa->prop.v1.key_bits_len ){

					n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"encr_key_bits","%d",
							childsa->prop.v1.key_bits_len);
					if(n < 0){
						err = -ENOMEM;
						RHP_BUG("");
						goto error;
					}
					*n2 += n;
				}
			}


			if( childsa->v1.dh ){
				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"pfs","%d",1);
			}else{
				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"pfs","%d",0);
			}
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;
		}


		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"anti_replay","%d",childsa->anti_replay);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;

		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"esn","%d",childsa->esn);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;

		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"tfc_padding","%d",childsa->tfc_padding);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;

		{
			int udp_encap = ( vpn->nat_t_info.exec_nat_t || vpn->nat_t_info.always_use_nat_t_port );

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"udp_encap","%d",udp_encap);
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;
		}

		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"out_of_order_drop","%d",
				childsa->out_of_order_drop);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;

		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"pmtu_default","%u",childsa->pmtu_default);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;

		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"pmtu_cache","%u",childsa->pmtu_cache);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;

		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"collision_detected","%d",
				childsa->collision_detected);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;


		{
			time_t now = _rhp_get_time();
			time_t tt = 0;

			if( childsa->established_time ){
				tt = (now - childsa->established_time);
			}else{
				tt = 0;
			}

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"established_time_elapsed","%ld",tt);
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;

			if( childsa->created_time ){
				tt = (now - childsa->created_time);
			}else{
				tt = 0;
			}

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"created_time_elapsed","%ld",tt);
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;

			if( childsa->expire_hard ){
				tt = (childsa->expire_hard - now);
			}else{
				tt = 0;
			}

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"expire_hard","%ld",tt);
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;

			if( childsa->expire_soft ){
				tt = (childsa->expire_soft - now);
			}else{
				tt = 0;
			}

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"expire_soft","%ld",tt);
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;
		}

		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rekeyed_gen","%d",childsa->rekeyed_gen);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;


		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"tx_esp_packets","%llu",childsa->statistics.tx_esp_packets);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;

		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rx_esp_packets","%llu",childsa->statistics.rx_esp_packets);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;


		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"antireplay_tx_seq","%llu",childsa->tx_seq);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;

		if( childsa->anti_replay ){

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"antireplay_rx_window_size","%u",
					childsa->rx_anti_replay.window_mask->get_bits_len(childsa->rx_anti_replay.window_mask));
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;


			if( childsa->esn ){

				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
						(xmlChar*)"antireplay_rx_esn_seq_b","%llu",childsa->rx_anti_replay.rx_seq.esn.b);
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error;
				}
				*n2 += n;

				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
						(xmlChar*)"antireplay_rx_esn_seq_t","%llu",childsa->rx_anti_replay.rx_seq.esn.t);
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error;
				}
				*n2 += n;

			}else{

				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
						(xmlChar*)"antireplay_rx_non_esn_seq_last","%u",childsa->rx_anti_replay.rx_seq.non_esn.last);
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error;
				}
				*n2 += n;
			}

			{
				int bits_len = childsa->rx_anti_replay.window_mask->get_bits_len(childsa->rx_anti_replay.window_mask);
				char* bitmask_str = (char*)_rhp_malloc(bits_len + 1);
				int i;

				if( bitmask_str ){

					for( i = 0; i < bits_len; i++ ){
						if( childsa->rx_anti_replay.window_mask->bit_is_set(childsa->rx_anti_replay.window_mask,i) ){
							bitmask_str[i] = '1';
						}else{
							bitmask_str[i] = '0';
						}
					}

					bitmask_str[bits_len] = '\0';

					n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
							(xmlChar*)"antireplay_rx_window_mask","%s",bitmask_str);
					if(n < 0){
						err = -ENOMEM;
						RHP_BUG("");
						goto error;
					}
					*n2 += n;

					_rhp_free(bitmask_str);
				}
			}
		}

		{
			int tss_enum;
			rhp_childsa_ts* tss = NULL;
			int ts_idx;

			for( tss_enum = 0; tss_enum < 2; tss_enum++ ){

				ts_idx = 0;

				if( tss_enum == 0 ){

					tss = childsa->my_tss;

					n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"my_traffic_selectors");

				}else if( tss_enum == 1 ){

					tss = childsa->peer_tss;

					n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"peer_traffic_selectors");
				}

				if(n < 0) {
					err = -ENOMEM;
					RHP_BUG("");
					goto error;
				}
				*n2 += n;


				while( tss ){

					int tss_addr_family = AF_UNSPEC;
					char ipv6_star_addr_str[INET6_ADDRSTRLEN + 1],
							 ipv6_end_addr_str[INET6_ADDRSTRLEN + 1];

					if( tss_enum == 0 ){
						n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"my_traffic_selector");
					}else if( tss_enum == 1 ){
						n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"peer_traffic_selector");
					}
					if(n < 0) {
						err = -ENOMEM;
						RHP_BUG("");
						goto error;
					}
					*n2 += n;


					n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"index","%d",ts_idx);
					if(n < 0){
						err = -ENOMEM;
						RHP_BUG("");
						goto error;
					}
					*n2 += n;


					n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
							(xmlChar*)"is_pending","%d",(tss->flag == RHP_CHILDSA_TS_IS_PENDING) ? 1 : 0);
					if(n < 0){
						err = -ENOMEM;
						RHP_BUG("");
						goto error;
					}
					*n2 += n;


					n = 0;
					if( tss->is_v1 && tss->ts_or_id_type == RHP_PROTO_IKEV1_ID_IPV4_ADDR_RANGE ){

						n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,
								(xmlChar*)"traffic_selector_type",(xmlChar*)"v1_ipv4_addr_range");

						tss_addr_family = AF_INET;

					}else if( tss->is_v1 && tss->ts_or_id_type == RHP_PROTO_IKEV1_ID_IPV6_ADDR_RANGE ){

						n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,
								(xmlChar*)"traffic_selector_type",(xmlChar*)"v1_ipv6_addr_range");

						tss_addr_family = AF_INET6;

					}else if( tss->is_v1 && tss->ts_or_id_type == RHP_PROTO_IKEV1_ID_IPV4_ADDR_SUBNET ){

						n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,
								(xmlChar*)"traffic_selector_type",(xmlChar*)"v1_ipv4_addr_subnet");

						tss_addr_family = AF_INET;

					}else if( tss->is_v1 && tss->ts_or_id_type == RHP_PROTO_IKEV1_ID_IPV6_ADDR_SUBNET ){

						n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,
								(xmlChar*)"traffic_selector_type",(xmlChar*)"v1_ipv6_addr_subnet");

						tss_addr_family = AF_INET6;

					}else if( tss->ts_or_id_type == RHP_PROTO_IKE_TS_IPV4_ADDR_RANGE ){

						n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,
								(xmlChar*)"traffic_selector_type",(xmlChar*)"ipv4_addr_range");

						tss_addr_family = AF_INET;

					}else if( tss->ts_or_id_type == RHP_PROTO_IKE_TS_IPV6_ADDR_RANGE ){

						n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,
								(xmlChar*)"traffic_selector_type",(xmlChar*)"ipv6_addr_range");

						tss_addr_family = AF_INET6;

					}else{
						RHP_BUG("%d",tss->ts_or_id_type);
					}

					if(n < 0){
						err = -ENOMEM;
						RHP_BUG("");
						goto error;
					}
					*n2 += n;


					n = 0;
					if( tss->protocol == RHP_PROTO_IP_ICMP &&
							tss_addr_family == AF_INET ){

						n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
								(xmlChar*)"traffic_selector",
								"proto:ICMP(%d), icmp_type:%d--%d, icmp_code:%d--%d, %d.%d.%d.%d--%d.%d.%d.%d (ipv4)",
								tss->protocol,
								tss->icmp_start_type,tss->icmp_end_type,
								tss->icmp_start_code,tss->icmp_end_code,
								((u8*)&tss->start_addr.addr.v4)[0],((u8*)&tss->start_addr.addr.v4)[1],
								((u8*)&tss->start_addr.addr.v4)[2],((u8*)&tss->start_addr.addr.v4)[3],
								((u8*)&tss->end_addr.addr.v4)[0],((u8*)&tss->end_addr.addr.v4)[1],
								((u8*)&tss->end_addr.addr.v4)[2],((u8*)&tss->end_addr.addr.v4)[3]);

					}else if( tss->protocol == RHP_PROTO_IP_IPV6_ICMP &&
										tss_addr_family == AF_INET6 ){

							n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
									(xmlChar*)"traffic_selector",
									"proto:ICMPv6(%d), icmp_type:%d--%d, icmp_code:%d--%d, %s--%s (ipv6)",
									tss->protocol,
									tss->icmp_start_type,tss->icmp_end_type,
									tss->icmp_start_code,tss->icmp_end_code,
									rhp_ipv6_string2(tss->start_addr.addr.v6,ipv6_star_addr_str),
									rhp_ipv6_string2(tss->end_addr.addr.v6,ipv6_end_addr_str));

					}else{

						char prot_str[16];
						prot_str[0] = '\0';

						if( tss->protocol == 0 ){
							strcpy(prot_str,"ANY");
						}else if( tss->protocol == RHP_PROTO_IP_UDP ){
							strcpy(prot_str,"UDP");
						}else if( tss->protocol == RHP_PROTO_IP_TCP ){
							strcpy(prot_str,"TCP");
						}else if( tss->protocol == RHP_PROTO_IP_SCTP ){
							strcpy(prot_str,"SCTP");
						}else if( tss->protocol == RHP_PROTO_IP_ETHERIP ){
							strcpy(prot_str,"EtherIP");
						}else if( tss->protocol == RHP_PROTO_IP_GRE ){
							strcpy(prot_str,"GRE");
						}else if( tss->protocol == RHP_PROTO_IP_UDPLITE ){
							strcpy(prot_str,"UDP_LITE");
						}else{
							strcpy(prot_str,"Unknown");
						}

						if( tss_addr_family == AF_INET ){

							n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
									(xmlChar*)"traffic_selector",
									"proto:%s(%d), port:%d--%d, %d.%d.%d.%d--%d.%d.%d.%d (ipv4)",
									prot_str,tss->protocol,
									ntohs(tss->start_port),ntohs(tss->end_port),
									((u8*)&tss->start_addr.addr.v4)[0],((u8*)&tss->start_addr.addr.v4)[1],
									((u8*)&tss->start_addr.addr.v4)[2],((u8*)&tss->start_addr.addr.v4)[3],
									((u8*)&tss->end_addr.addr.v4)[0],((u8*)&tss->end_addr.addr.v4)[1],
									((u8*)&tss->end_addr.addr.v4)[2],((u8*)&tss->end_addr.addr.v4)[3]);

						}else if( tss_addr_family == AF_INET6 ){

							n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
									(xmlChar*)"traffic_selector",
									"proto:%s(%d), port:%d--%d, %s--%s (ipv6)",
									prot_str,tss->protocol,
									ntohs(tss->start_port),ntohs(tss->end_port),
									rhp_ipv6_string2(tss->start_addr.addr.v6,ipv6_star_addr_str),
									rhp_ipv6_string2(tss->end_addr.addr.v6,ipv6_end_addr_str));
						}
					}

					if(n < 0){
						err = -ENOMEM;
						RHP_BUG("");
						goto error;
					}
					*n2 += n;


					n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
							(xmlChar*)"protocol","%d",tss->protocol);
					if(n < 0){
						err = -ENOMEM;
						RHP_BUG("");
						goto error;
					}
					*n2 += n;

					if( tss->protocol == RHP_PROTO_IP_ICMP ||
							tss->protocol == RHP_PROTO_IP_IPV6_ICMP ){

						n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
								(xmlChar*)"start_icmp_type","%d",tss->icmp_start_type);
						if(n < 0){
							err = -ENOMEM;
							RHP_BUG("");
							goto error;
						}
						*n2 += n;

						n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
								(xmlChar*)"end_icmp_type","%d",tss->icmp_end_type);
						if(n < 0){
							err = -ENOMEM;
							RHP_BUG("");
							goto error;
						}
						*n2 += n;

						n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
								(xmlChar*)"start_icmp_code","%d",tss->icmp_start_code);
						if(n < 0){
							err = -ENOMEM;
							RHP_BUG("");
							goto error;
						}
						*n2 += n;

						n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
								(xmlChar*)"end_icmp_code","%d",tss->icmp_end_code);
						if(n < 0){
							err = -ENOMEM;
							RHP_BUG("");
							goto error;
						}
						*n2 += n;

					}else{

						n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
								(xmlChar*)"start_port","%d",ntohs(tss->start_port));
						if(n < 0){
							err = -ENOMEM;
							RHP_BUG("");
							goto error;
						}
						*n2 += n;

						n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
								(xmlChar*)"end_port","%d",ntohs(tss->end_port));
						if(n < 0){
							err = -ENOMEM;
							RHP_BUG("");
							goto error;
						}
						*n2 += n;
					}

					if( tss_addr_family == AF_INET ){

						n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
								(xmlChar*)"start_addr_v4","%d.%d.%d.%d",
								((u8*)&tss->start_addr.addr.v4)[0],((u8*)&tss->start_addr.addr.v4)[1],
								((u8*)&tss->start_addr.addr.v4)[2],((u8*)&tss->start_addr.addr.v4)[3]);
						if(n < 0){
							err = -ENOMEM;
							RHP_BUG("");
							goto error;
						}
						*n2 += n;

						n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
								(xmlChar*)"end_addr_v4","%d.%d.%d.%d",
								((u8*)&tss->end_addr.addr.v4)[0],((u8*)&tss->end_addr.addr.v4)[1],
								((u8*)&tss->end_addr.addr.v4)[2],((u8*)&tss->end_addr.addr.v4)[3]);
						if(n < 0){
							err = -ENOMEM;
							RHP_BUG("");
							goto error;
						}
						*n2 += n;

					}else if( tss_addr_family == AF_INET6 ){

						n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
								(xmlChar*)"start_addr_v6","%s",
								rhp_ipv6_string2(tss->start_addr.addr.v6,ipv6_star_addr_str));
						if(n < 0){
							err = -ENOMEM;
							RHP_BUG("");
							goto error;
						}
						*n2 += n;

						n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
								(xmlChar*)"end_addr_v6","%s",
								rhp_ipv6_string2(tss->end_addr.addr.v6,ipv6_end_addr_str));
						if(n < 0){
							err = -ENOMEM;
							RHP_BUG("");
							goto error;
						}
						*n2 += n;
					}

					n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
					if(n < 0) {
						err = -ENOMEM;
						RHP_BUG("");
						goto error;
					}
					*n2 += n;

					ts_idx++;
					tss = tss->next;
				}

				n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
				if(n < 0) {
					err = -ENOMEM;
					RHP_BUG("");
					goto error;
				}
				*n2 += n;
			}
		}

		n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
		if(n < 0) {
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;


		idx++;
		childsa = childsa->next_vpn_list;
	}

	return 0;

error:
	return err;
}

static int _rhp_ui_http_vpn_get_info_vpn_serialize(rhp_http_bus_session* http_bus_sess,void* ctx,void* writer,int idx)
{
  int err = -EINVAL;
  int n = 0;
  int n2 = 0;
  rhp_vpn* vpn = (rhp_vpn*)ctx;
  rhp_vpn_realm* rlm;

  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_GET_INFO_VPN_SERIALIZE,"xxxd",http_bus_sess,vpn,writer,idx);

  RHP_LOCK(&(vpn->lock));

  rlm = vpn->rlm;

  if( rlm == NULL ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_GET_INFO_VPN_SERIALIZE_NO_RLM,"xxx",http_bus_sess,vpn);
    err = -ENOENT;
  	goto error_vpn_l;
  }

  RHP_LOCK(&(rlm->lock));

  {
		n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"rhp_http_bus_record");
		if(n < 0) {
			err = -ENOMEM;
			RHP_BUG("");
			goto error_vpn_rlm_l;
		}
		n2 += n;

		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"index","%d",idx);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error_vpn_rlm_l;
		}
		n2 += n;

		n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"service",(xmlChar*)"ui_http_vpn");
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error_vpn_rlm_l;
		}
		n2 += n;

		n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"action",(xmlChar*)"status_vpn");
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error_vpn_rlm_l;
		}
		n2 += n;

		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"session_id","%llu",http_bus_sess->session_id);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error_vpn_rlm_l;
		}
		n2 += n;

		{
			n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"vpn");
			if(n < 0) {
				err = -ENOMEM;
				RHP_BUG("");
				goto error_vpn_rlm_l;
			}
			n2 += n;

			n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"index",(xmlChar*)"0");
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error_vpn_rlm_l;
			}
			n2 += n;

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"vpn_unique_id",
					"0x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
					vpn->unique_id[0],vpn->unique_id[1],vpn->unique_id[2],vpn->unique_id[3],vpn->unique_id[4],vpn->unique_id[5],vpn->unique_id[6],vpn->unique_id[7],
					vpn->unique_id[8],vpn->unique_id[9],vpn->unique_id[10],vpn->unique_id[11],vpn->unique_id[12],vpn->unique_id[13],vpn->unique_id[14],vpn->unique_id[15]);

			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error_vpn_rlm_l;
			}
			n2 += n;

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"vpn_realm_id","%lu",vpn->vpn_realm_id);
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error_vpn_rlm_l;
			}
			n2 += n;

			if( rlm->name ){

				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"vpn_realm_name","%s",rlm->name);
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error_vpn_rlm_l;
				}
				n2 += n;
			}

			{
				if( vpn->is_v1 ){
					n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"ike_version","%s","1");
				}else{
					n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"ike_version","%s","2");
				}
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error_vpn_rlm_l;
				}
				n2 += n;
			}

			{
				char *id_type,*id_str;

				err = rhp_ikev2_id_to_string(&(vpn->my_id),&id_type,&id_str);
				if( err ){
					goto error_vpn_rlm_l;
				}

				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"myid_type","%s",id_type);
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					_rhp_free(id_type);
					_rhp_free(id_str);
					goto error_vpn_rlm_l;
				}
				n2 += n;

				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"myid","%s",id_str);
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					_rhp_free(id_type);
					_rhp_free(id_str);
					goto error_vpn_rlm_l;
				}
				n2 += n;

				_rhp_free(id_type);
				_rhp_free(id_str);


				if( vpn->sess_resume.gen_by_sess_resume && vpn->origin_side == RHP_IKE_RESPONDER ){

					switch( vpn->sess_resume.auth_method_r_org ){
					case RHP_PROTO_IKE_AUTHMETHOD_RSA_SIG:
						n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"auth_method_r_org",(xmlChar*)"rsa-sig");
						break;
					case RHP_PROTO_IKE_AUTHMETHOD_SHARED_KEY:
						n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"auth_method_r_org",(xmlChar*)"psk");
						break;
					case RHP_PROTO_IKE_AUTHMETHOD_DSS_SIG:
						n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"auth_method_r_org",(xmlChar*)"dss-sig");
						break;
					case RHP_PROTO_IKE_AUTHMETHOD_NULL_AUTH:
						n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"auth_method_r_org",(xmlChar*)"null-auth");
						break;
					default:
						n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"auth_method_r_org",(xmlChar*)"unknown");
						break;
					}

					if(n < 0){
						err = -ENOMEM;
						RHP_BUG("");
						goto error_vpn_rlm_l;
					}
					n2 += n;
				}
			}

			{
				char *id_type,*id_str;

				err = rhp_ikev2_id_to_string(&(vpn->peer_id),&id_type,&id_str);
				if( err ){
					goto error_vpn_rlm_l;
				}

				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"peerid_type","%s",id_type);
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					_rhp_free(id_type);
					_rhp_free(id_str);
					goto error_vpn_rlm_l;
				}
				n2 += n;

				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"peerid","%s",id_str);
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					_rhp_free(id_type);
					_rhp_free(id_str);
					goto error_vpn_rlm_l;
				}
				n2 += n;

				_rhp_free(id_type);
				_rhp_free(id_str);


				if( vpn->sess_resume.gen_by_sess_resume && vpn->origin_side == RHP_IKE_RESPONDER ){

					switch( vpn->sess_resume.auth_method_i_org ){
					case RHP_PROTO_IKE_AUTHMETHOD_RSA_SIG:
						n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"auth_method_i_org",(xmlChar*)"rsa-sig");
						break;
					case RHP_PROTO_IKE_AUTHMETHOD_SHARED_KEY:
						n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"auth_method_i_org",(xmlChar*)"psk");
						break;
					case RHP_PROTO_IKE_AUTHMETHOD_DSS_SIG:
						n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"auth_method_i_org",(xmlChar*)"dss-sig");
						break;
					case RHP_PROTO_IKE_AUTHMETHOD_NULL_AUTH:
						n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"auth_method_i_org",(xmlChar*)"null-auth");
						break;
					default:
						n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"auth_method_i_org",(xmlChar*)"unknown");
						break;
					}

					if(n < 0){
						err = -ENOMEM;
						RHP_BUG("");
						goto error_vpn_rlm_l;
					}
					n2 += n;
				}

				if( vpn->peer_id.alt_id ){

					err = rhp_ikev2_id_to_string(vpn->peer_id.alt_id,&id_type,&id_str);
					if( err ){
						goto error_vpn_rlm_l;
					}

					n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"alt_peerid_type","%s",id_type);
					if(n < 0){
						err = -ENOMEM;
						RHP_BUG("");
						_rhp_free(id_type);
						_rhp_free(id_str);
						goto error_vpn_rlm_l;
					}
					n2 += n;

					n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"alt_peerid","%s",id_str);
					if(n < 0){
						err = -ENOMEM;
						RHP_BUG("");
						_rhp_free(id_type);
						_rhp_free(id_str);
						goto error_vpn_rlm_l;
					}
					n2 += n;

					_rhp_free(id_type);
					_rhp_free(id_str);
				}
			}

			{
				if( vpn->eap.role == RHP_EAP_AUTHENTICATOR ){
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"eap_role",(xmlChar*)"server");
				}else if( vpn->eap.role == RHP_EAP_SUPPLICANT ){
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"eap_role",(xmlChar*)"peer");
				}else{
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"eap_role",(xmlChar*)"disabled");
				}
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error_vpn_rlm_l;
				}
				n2 += n;


				if( vpn->eap.role == RHP_EAP_AUTHENTICATOR || vpn->eap.role == RHP_EAP_SUPPLICANT ){

					char* method_name = rhp_eap_sup_impl_method2str(vpn->eap.eap_method);
					if( method_name == NULL ){
						err = -ENOMEM;
						RHP_BUG("");
						goto error_vpn_rlm_l;
					}

					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"eap_method",(xmlChar*)method_name);
					_rhp_free(method_name);
					if(n < 0){
						err = -ENOMEM;
						RHP_BUG("");
						goto error_vpn_rlm_l;
					}
					n2 += n;


					if( vpn->eap.eap_method == RHP_PROTO_EAP_TYPE_PRIV_RADIUS ){

						method_name = rhp_eap_sup_impl_method2str(vpn->radius.eap_method);
						if( method_name == NULL ){
							err = -ENOMEM;
							RHP_BUG("");
							goto error_vpn_rlm_l;
						}

						n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"eap_method_on_radius",(xmlChar*)method_name);
						_rhp_free(method_name);
						if(n < 0){
							err = -ENOMEM;
							RHP_BUG("");
							goto error_vpn_rlm_l;
						}
						n2 += n;
					}


					if( !rhp_eap_id_is_null(&(vpn->eap.peer_id)) ){

						n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"eap_peer_identity","%s",vpn->eap.peer_id.identity);
						if(n < 0){
							err = -ENOMEM;
							RHP_BUG("");
							goto error_vpn_rlm_l;
						}
						n2 += n;

						if( vpn->eap.peer_id.radius.eap_method != RHP_PROTO_EAP_TYPE_NONE ){

							char* eap_method_str = rhp_eap_auth_impl_method2str(vpn->eap.peer_id.radius.eap_method);

							n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"radius_eap_peer_id_method","%s",
										(eap_method_str ? eap_method_str : "unknown"));
							if(n < 0){
								if( eap_method_str ){
									_rhp_free(eap_method_str);
								}
								err = -ENOMEM;
								RHP_BUG("");
								goto error_vpn_rlm_l;
							}
							n2 += n;
							if( eap_method_str ){
								_rhp_free(eap_method_str);
							}

							if( vpn->eap.peer_id.radius.user_index ){

								n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"radius_eap_peer_id_user_index","%s",
											vpn->eap.peer_id.radius.user_index);
								if(n < 0){
									err = -ENOMEM;
									RHP_BUG("");
									goto error_vpn_rlm_l;
								}
								n2 += n;
							}

							if( vpn->eap.peer_id.radius.assigned_addr_v4 ){

								n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"radius_eap_peer_id_assigned_addr_v4","%d.%d.%d.%d",
											((u8*)&(vpn->eap.peer_id.radius.assigned_addr_v4->addr.v4))[0],
											((u8*)&(vpn->eap.peer_id.radius.assigned_addr_v4->addr.v4))[1],
											((u8*)&(vpn->eap.peer_id.radius.assigned_addr_v4->addr.v4))[2],
											((u8*)&(vpn->eap.peer_id.radius.assigned_addr_v4->addr.v4))[3]);
								if(n < 0){
									err = -ENOMEM;
									RHP_BUG("");
									goto error_vpn_rlm_l;
								}
								n2 += n;
							}

							if( vpn->eap.peer_id.radius.assigned_addr_v6 ){

								n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"radius_eap_peer_id_assigned_addr_v6","%s",
										rhp_ipv6_string(vpn->eap.peer_id.radius.assigned_addr_v6->addr.v6));
								if(n < 0){
									err = -ENOMEM;
									RHP_BUG("");
									goto error_vpn_rlm_l;
								}
								n2 += n;
							}

							if( vpn->eap.peer_id.radius.salt ){

								n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"radius_eap_peer_id_assigned_addr_v6","0x%x",
										vpn->eap.peer_id.radius.salt);
								if(n < 0){
									err = -ENOMEM;
									RHP_BUG("");
									goto error_vpn_rlm_l;
								}
								n2 += n;
							}
						}
					}

					if( !rhp_eap_id_is_null(&(vpn->eap.my_id)) ){

						n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"eap_my_identity","%s",vpn->eap.my_id.identity);
						if(n < 0){
							err = -ENOMEM;
							RHP_BUG("");
							goto error_vpn_rlm_l;
						}
						n2 += n;
					}
				}
			}


			if( vpn->peer_is_rockhopper ){

				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"peer_is_rockhopper","%d",vpn->peer_is_rockhopper);
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error_vpn_rlm_l;
				}
				n2 += n;
			}

			if( vpn->is_configured_peer ){

				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"is_configured_peer","%d",vpn->is_configured_peer);
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error_vpn_rlm_l;
				}
				n2 += n;
			}

			{
				char encap_mode_str[32];

				encap_mode_str[0] = '\0';
				if( vpn->internal_net_info.encap_mode_c == RHP_VPN_ENCAP_ETHERIP ){
					strcpy(encap_mode_str,"etherip");
				}else if( vpn->internal_net_info.encap_mode_c == RHP_VPN_ENCAP_IPIP ){
					strcpy(encap_mode_str,"ipip");
				}else if( vpn->internal_net_info.encap_mode_c == RHP_VPN_ENCAP_GRE ){
					strcpy(encap_mode_str,"gre");
				}else{
					strcpy(encap_mode_str,"unknown");
				}

				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"encap_mode","%s",encap_mode_str);
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error_vpn_rlm_l;
				}
				n2 += n;
			}

			{
				n = 0;
				u32 ip;;
				if( vpn->peer_addr.addr_family == AF_INET ){

					ip = vpn->peer_addr.addr.v4;

					n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
							(xmlChar*)"peer_addr_v4","%d.%d.%d.%d",
							((u8*)&ip)[0],((u8*)&ip)[1],((u8*)&ip)[2],((u8*)&ip)[3]);

				}else if( vpn->peer_addr.addr_family == AF_INET6 ){

					n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
							(xmlChar*)"peer_addr_v6","%s",
							rhp_ipv6_string(vpn->peer_addr.addr.v6));
				}
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error_vpn_rlm_l;
				}
				n2 += n;


				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
						(xmlChar*)"peer_port","%d",ntohs(vpn->peer_addr.port));
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error_vpn_rlm_l;
				}
				n2 += n;


				n = 0;
				if( vpn->peer_addr.addr_family == AF_INET ){

					ip = vpn->local.if_info.addr.v4;

					n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
							(xmlChar*)"my_addr_v4","%d.%d.%d.%d",
							((u8*)&ip)[0],((u8*)&ip)[1],((u8*)&ip)[2],((u8*)&ip)[3]);

				}else if( vpn->peer_addr.addr_family == AF_INET6 ){

					n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
							(xmlChar*)"my_addr_v6","%s",
							rhp_ipv6_string(vpn->local.if_info.addr.v6));

				}
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error_vpn_rlm_l;
				}
				n2 += n;


				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
						(xmlChar*)"my_if_name","%s",vpn->local.if_info.if_name);
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error_vpn_rlm_l;
				}
				n2 += n;

				if( !vpn->nat_t_info.use_nat_t_port && !vpn->nat_t_info.always_use_nat_t_port ){

					n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
							(xmlChar*)"my_port","%d",ntohs(vpn->local.port));
					if(n < 0){
						err = -ENOMEM;
						RHP_BUG("");
						goto error_vpn_rlm_l;
					}
					n2 += n;

				}else{

					n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
							(xmlChar*)"my_port","%d",ntohs(vpn->local.port_nat_t));
					if(n < 0){
						err = -ENOMEM;
						RHP_BUG("");
						goto error_vpn_rlm_l;
					}
					n2 += n;

					n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
							(xmlChar*)"exec_nat_t","%d",vpn->nat_t_info.exec_nat_t);
					if(n < 0){
						err = -ENOMEM;
						RHP_BUG("");
						goto error_vpn_rlm_l;
					}
					n2 += n;

					n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
							(xmlChar*)"behind_a_nat","%d",vpn->nat_t_info.behind_a_nat);
					if(n < 0){
						err = -ENOMEM;
						RHP_BUG("");
						goto error_vpn_rlm_l;
					}
					n2 += n;
				}
			}

			{
				if( vpn->nhrp.role == RHP_NHRP_SERVICE_SERVER ){
					n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
							(xmlChar*)"nhrp_role","%s",(xmlChar*)"server");
				}else if( vpn->nhrp.role == RHP_NHRP_SERVICE_CLIENT ){
					n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
							(xmlChar*)"nhrp_role","%s",(xmlChar*)"client");
				}else{
					n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
							(xmlChar*)"nhrp_role","%s",(xmlChar*)"none");
				}
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error_vpn_rlm_l;
				}
				n2 += n;

				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"dmvpn_enabled","%d",vpn->nhrp.dmvpn_enabled);
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error_vpn_rlm_l;
				}
				n2 += n;

				if( vpn->nhrp.dmvpn_enabled ){

					n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"is_dmvpn_shortcut","%d",vpn->nhrp.dmvpn_shortcut);
					if(n < 0){
						err = -ENOMEM;
						RHP_BUG("");
						goto error_vpn_rlm_l;
					}
					n2 += n;
				}
			}



			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"tx_esp_packets","%llu",vpn->statistics.tx_esp_packets);
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error_vpn_rlm_l;
			}
			n2 += n;

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rx_esp_packets","%llu",vpn->statistics.rx_esp_packets);
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error_vpn_rlm_l;
			}
			n2 += n;



			{
				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
						(xmlChar*)"http_cert_lookup_supported","%d",
						(rhp_gcfg_hash_url_enabled(vpn->origin_side) && vpn->peer_http_cert_lookup_supported) ? 1 : 0);
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error_vpn_rlm_l;
				}
				n2 += n;
			}


			if( vpn->is_v1 ){

				if( vpn->v1.commit_bit_enabled ){
					n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
							(xmlChar*)"v1_commit_bit_enabled","%d",vpn->v1.commit_bit_enabled ? 1 : 0);
					if(n < 0){
						err = -ENOMEM;
						RHP_BUG("");
						goto error_vpn_rlm_l;
					}
					n2 += n;
				}

				if( vpn->v1.dpd_enabled ){
					n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
							(xmlChar*)"v1_dpd_enabled","%d",vpn->v1.dpd_enabled ? 1 : 0);
					if(n < 0){
						err = -ENOMEM;
						RHP_BUG("");
						goto error_vpn_rlm_l;
					}
					n2 += n;
				}
			}


			{
				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
						(xmlChar*)"created_ikesas","%lu",vpn->created_ikesas);
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error_vpn_rlm_l;
				}
				n2 += n;

				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
						(xmlChar*)"created_childsas","%lu",vpn->created_childsas);
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error_vpn_rlm_l;
				}
				n2 += n;
			}

			{
				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
						(xmlChar*)"udp_encap_v6","%lu",
						(((!rhp_gcfg_udp_encap_for_v6_after_rx_rockhopper_also && vpn->peer_is_rockhopper) ||
							!rlm->childsa.v6_enable_udp_encap_after_rx ||
							vpn->nat_t_info.rx_udp_encap_from_remote_peer) ? 1 : 0));
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error_vpn_rlm_l;
				}
				n2 += n;
			}

			{
				char vif_addr_type_str[32];

				vif_addr_type_str[0] = '\0';
				if( rlm->internal_ifc->addrs_type == RHP_VIF_ADDR_STATIC ){
					strcpy(vif_addr_type_str,"static");
				}else if( rlm->internal_ifc->addrs_type == RHP_VIF_ADDR_IKEV2CFG ){
					strcpy(vif_addr_type_str,"ikev2cfg");
				}else if( rlm->internal_ifc->addrs_type == RHP_VIF_ADDR_DHCP ){
					strcpy(vif_addr_type_str,"dhcp");
				}else if( rlm->internal_ifc->addrs_type == RHP_VIF_ADDR_NONE ){
					strcpy(vif_addr_type_str,"none");
				}else{
					strcpy(vif_addr_type_str,"unknown");
				}

				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
						(xmlChar*)"internal_if_addr_type","%s",vif_addr_type_str);
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error_vpn_rlm_l;
				}
				n2 += n;


				n = 0;
				if( rlm->internal_ifc ){

					if( rlm->internal_ifc->gw_addr.addr_family == AF_INET ){

						u32 ip = rlm->internal_ifc->gw_addr.addr.v4;

						n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
								(xmlChar*)"internal_gateway_addr_v4","%d.%d.%d.%d",
								((u8*)&ip)[0],((u8*)&ip)[1],((u8*)&ip)[2],((u8*)&ip)[3]);
						if(n < 0){
							err = -ENOMEM;
							RHP_BUG("");
							goto error_vpn_rlm_l;
						}
						n2 += n;
					}

					if( rlm->internal_ifc->gw_addr_v6.addr_family == AF_INET6 ){

						n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
								(xmlChar*)"internal_gateway_addr_v6","%s",
								rhp_ipv6_string(rlm->internal_ifc->gw_addr_v6.addr.v6));
						if(n < 0){
							err = -ENOMEM;
							RHP_BUG("");
							goto error_vpn_rlm_l;
						}
						n2 += n;
					}

					if( rlm->internal_ifc->sys_def_gw_addr.addr_family == AF_INET ){

						u32 ip = rlm->internal_ifc->sys_def_gw_addr.addr.v4;

						n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
								(xmlChar*)"internal_sys_def_gateway_addr_v4","%d.%d.%d.%d",
								((u8*)&ip)[0],((u8*)&ip)[1],((u8*)&ip)[2],((u8*)&ip)[3]);
						if(n < 0){
							err = -ENOMEM;
							RHP_BUG("");
							goto error_vpn_rlm_l;
						}
						n2 += n;
					}

					if( rlm->internal_ifc->sys_def_gw_addr_v6.addr_family == AF_INET6 ){

						n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
								(xmlChar*)"internal_sys_def_gateway_addr_v6","%s",
								rhp_ipv6_string(rlm->internal_ifc->sys_def_gw_addr_v6.addr.v6));
						if(n < 0){
							err = -ENOMEM;
							RHP_BUG("");
							goto error_vpn_rlm_l;
						}
						n2 += n;
					}
				}
			}


			if( vpn->internal_net_info.peer_addr_v4_cp == RHP_IKEV2_CFG_CP_ADDR_ASSIGNED ||
					vpn->internal_net_info.peer_addr_v6_cp == RHP_IKEV2_CFG_CP_ADDR_ASSIGNED ){

				n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,
						(xmlChar*)"internal_peer_addr_cp",(xmlChar*)"1");
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error_vpn_rlm_l;
				}
				n2 += n;
			}

			if( vpn->cfg_peer && vpn->cfg_peer->is_access_point ){

				n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,
						(xmlChar*)"peer_is_access_point",(xmlChar*)"1");
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error_vpn_rlm_l;
				}
				n2 += n;
			}

			if( rlm->is_access_point ){

				n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,
						(xmlChar*)"is_access_point",(xmlChar*)"1");
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error_vpn_rlm_l;
				}
				n2 += n;
			}

			if( rlm->config_service == RHP_IKEV2_CONFIG_SERVER ){

				n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,
						(xmlChar*)"is_config_server",(xmlChar*)"1");
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error_vpn_rlm_l;
				}
				n2 += n;
			}

			if( rlm->config_service == RHP_IKEV2_CONFIG_CLIENT ){

				n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,
						(xmlChar*)"is_config_client",(xmlChar*)"1");
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error_vpn_rlm_l;
				}
				n2 += n;
			}


			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
					(xmlChar*)"dummy_peer_mac",
					"%02x:%02x:%02x:%02x:%02x:%02x",
					vpn->internal_net_info.dummy_peer_mac[0],vpn->internal_net_info.dummy_peer_mac[1],
					vpn->internal_net_info.dummy_peer_mac[2],vpn->internal_net_info.dummy_peer_mac[3],
					vpn->internal_net_info.dummy_peer_mac[4],vpn->internal_net_info.dummy_peer_mac[5]);

			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error_vpn_rlm_l;
			}
			n2 += n;


			if( vpn->internal_net_info.exec_ipv6_autoconf ){

				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
						(xmlChar*)"exec_ipv6_autoconf","%d",vpn->internal_net_info.exec_ipv6_autoconf);

				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error_vpn_rlm_l;
				}
				n2 += n;
			}

			if( vpn->internal_net_info.peer_exec_ipv6_autoconf ){

				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
						(xmlChar*)"peer_exec_ipv6_autoconf","%d",vpn->internal_net_info.peer_exec_ipv6_autoconf);

				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error_vpn_rlm_l;
				}
				n2 += n;
			}


			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
					(xmlChar*)"ikesa_num","%d",vpn->ikesa_num);
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error_vpn_rlm_l;
			}
			n2 += n;

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
					(xmlChar*)"childsa_num","%d",vpn->childsa_num);
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error_vpn_rlm_l;
			}
			n2 += n;

			{
				time_t now = _rhp_get_time();

				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
						(xmlChar*)"time_elapsed","%ld",(now - vpn->created));
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error_vpn_rlm_l;
				}
				n2 += n;
			}

			{
				int flag = (_rhp_atomic_read(&rhp_vpn_fwd_any_dns_queries) ? 1 : 0);

				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
						(xmlChar*)"dns_pxy_fwd_any_queries_to_vpn","%d",flag);
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error_vpn_rlm_l;
				}
				n2 += n;
			}

			{
				int my_token_enabled = 0, peer_token_enabled = 0;

				if( vpn->ikesa_list_head ){

					my_token_enabled = vpn->ikesa_list_head->qcd.my_token_enabled;
					peer_token_enabled = (vpn->ikesa_list_head->qcd.peer_token_len ? 1 : 0);
				}

				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
						(xmlChar*)"qcd_my_token_enabled","%d",my_token_enabled);
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error_vpn_rlm_l;
				}
				n2 += n;

				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
						(xmlChar*)"qcd_peer_token_enabled","%d",peer_token_enabled);
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error_vpn_rlm_l;
				}
				n2 += n;
			}

			{
				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
						(xmlChar*)"origin_side","%s",
						(vpn->origin_side == RHP_IKE_INITIATOR ? "initiator" : "responder"));
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error_vpn_rlm_l;
				}
				n2 += n;
			}

			if( rlm->internal_ifc->ifc ){

			  rhp_ifc_entry* ifc = rlm->internal_ifc->ifc;

				RHP_LOCK(&(ifc->lock));

				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
						(xmlChar*)"internal_if_name","%s",ifc->if_name);
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					RHP_UNLOCK(&(ifc->lock));
					goto error_vpn_rlm_l;
				}
				n2 += n;

				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
						(xmlChar*)"internal_if_mac",
						"%02x:%02x:%02x:%02x:%02x:%02x",
						ifc->mac[0],ifc->mac[1],ifc->mac[2],ifc->mac[3],ifc->mac[4],ifc->mac[5]);

				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					RHP_UNLOCK(&(ifc->lock));
					goto error_vpn_rlm_l;
				}
				n2 += n;

				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
						(xmlChar*)"internal_if_mtu","%d",ifc->mtu);
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					RHP_UNLOCK(&(ifc->lock));
					goto error_vpn_rlm_l;
				}
				n2 += n;

				RHP_UNLOCK(&(ifc->lock));
			}

			{
				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
						(xmlChar*)"exec_ikev2_fragmentation","%d",vpn->exec_ikev2_frag);
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error_vpn_rlm_l;
				}
				n2 += n;
			}

			{
				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
						(xmlChar*)"exec_sess_resume","%d",vpn->sess_resume.exec_sess_resume);
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error_vpn_rlm_l;
				}
				n2 += n;

				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
						(xmlChar*)"gen_by_sess_resume","%d",vpn->sess_resume.gen_by_sess_resume);
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error_vpn_rlm_l;
				}
				n2 += n;
			}

			{
				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
						(xmlChar*)"exec_mobike","%d",vpn->exec_mobike);
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error_vpn_rlm_l;
				}
				n2 += n;

				if( vpn->exec_mobike ){

					n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
								(xmlChar*)"mobike_exec_rt_ck_times","%lu",vpn->mobike_exec_rt_ck_times);
					if(n < 0){
						err = -ENOMEM;
						RHP_BUG("");
						goto error_vpn_rlm_l;
					}
					n2 += n;

					if( vpn->origin_side == RHP_IKE_INITIATOR ){

						int m;
						rhp_ip_addr_list* m_aaddr = vpn->mobike.init.additional_addrs;


						n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
								(xmlChar*)"rt_ck_pending","%s",
								(vpn->mobike.init.rt_ck_pending ? "1" : "0"));
						if(n < 0){
							err = -ENOMEM;
							RHP_BUG("");
							goto error_vpn_rlm_l;
						}
						n2 += n;

						n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
								(xmlChar*)"rt_ck_waiting","%s",
								(vpn->mobike.init.rt_ck_waiting ? "1" : "0"));
						if(n < 0){
							err = -ENOMEM;
							RHP_BUG("");
							goto error_vpn_rlm_l;
						}
						n2 += n;

						n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
									(xmlChar*)"mobike_nat_t_addr_changed_times","%lu",
									vpn->mobike.init.nat_t_addr_changed_times);
						if(n < 0){
							err = -ENOMEM;
							RHP_BUG("");
							goto error_vpn_rlm_l;
						}
						n2 += n;

						n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
								(xmlChar*)"mobike_additional_addrs_num","%d",
								vpn->mobike.init.additional_addrs_num);
						if(n < 0){
							err = -ENOMEM;
							RHP_BUG("");
							goto error_vpn_rlm_l;
						}
						n2 += n;

						for( m = 0; m < vpn->mobike.init.additional_addrs_num; m++ ){

							n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,
									(xmlChar*)"mobike_additional_addr");
							if(n < 0) {
								err = -ENOMEM;
								RHP_BUG("");
								goto error_vpn_rlm_l;
							}
							n2 += n;

							n = 0;
							if( m_aaddr->ip_addr.addr_family == AF_INET ){

								u32 ip = m_aaddr->ip_addr.addr.v4;

								n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
										(xmlChar*)"mobike_peer_addr_v4","%d.%d.%d.%d",
										((u8*)&ip)[0],((u8*)&ip)[1],((u8*)&ip)[2],((u8*)&ip)[3]);

							}else	if( m_aaddr->ip_addr.addr_family == AF_INET6 ){

								n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
										(xmlChar*)"mobike_peer_addr_v6","%s",
										rhp_ipv6_string(m_aaddr->ip_addr.addr.v6));
							}
							if(n < 0){
								err = -ENOMEM;
								RHP_BUG("");
								goto error_vpn_rlm_l;
							}
							n2 += n;


							n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
							if(n < 0) {
								err = -ENOMEM;
								RHP_BUG("");
								goto error_vpn_rlm_l;
							}
							n2 += n;

							m_aaddr = m_aaddr->next;
						}


						for( m = 0; m < vpn->mobike.init.cand_path_maps_num_result; m++ ){

							rhp_mobike_path_map* pmap = &(vpn->mobike.init.cand_path_maps_result[m]);

							n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,
									(xmlChar*)"mobike_init_rt_check_result");
							if(n < 0) {
								err = -ENOMEM;
								RHP_BUG("");
								goto error_vpn_rlm_l;
							}
							n2 += n;


							n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
									(xmlChar*)"my_if","%s",pmap->my_if_info.if_name);
							if(n < 0){
								err = -ENOMEM;
								RHP_BUG("");
								goto error_vpn_rlm_l;
							}
							n2 += n;


							n = 0;
							if( pmap->my_if_info.addr_family == AF_INET ){

								u32 ip = pmap->my_if_info.addr.v4;

								n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
										(xmlChar*)"my_addr_v4","%d.%d.%d.%d/%d",
										((u8*)&ip)[0],((u8*)&ip)[1],((u8*)&ip)[2],((u8*)&ip)[3],pmap->my_if_info.prefixlen);

							}else	if( pmap->my_if_info.addr_family == AF_INET6 ){

								n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
										(xmlChar*)"my_addr_v6","%s/%d",
										rhp_ipv6_string(pmap->my_if_info.addr.v6),pmap->my_if_info.prefixlen);
							}
							if(n < 0){
								err = -ENOMEM;
								RHP_BUG("");
								goto error_vpn_rlm_l;
							}
							n2 += n;


							if( pmap->peer_type == RHP_MOBIKE_PEER_CFG ){
								n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
									(xmlChar*)"peer_type","%s","config");
							}else if( pmap->peer_type == RHP_MOBIKE_PEER_ADDITIONAL ){
								n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
									(xmlChar*)"peer_type","%s","additional");
							}else{
								n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
									(xmlChar*)"peer_type","%s","unknown");
							}
							if(n < 0){
								err = -ENOMEM;
								RHP_BUG("");
								goto error_vpn_rlm_l;
							}
							n2 += n;


							n = 0;
							if( pmap->peer_addr.addr_family == AF_INET ){

								u32 ip = pmap->peer_addr.addr.v4;

								n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
										(xmlChar*)"peer_addr_v4","%d.%d.%d.%d",
										((u8*)&ip)[0],((u8*)&ip)[1],((u8*)&ip)[2],((u8*)&ip)[3]);

							}else	if( pmap->peer_addr.addr_family == AF_INET6 ){

								n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
										(xmlChar*)"peer_addr_v6","%s",
										rhp_ipv6_string(pmap->peer_addr.addr.v6));
							}
							if(n < 0){
								err = -ENOMEM;
								RHP_BUG("");
								goto error_vpn_rlm_l;
							}
							n2 += n;


							n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
									(xmlChar*)"result","%d",pmap->result);
							if(n < 0){
								err = -ENOMEM;
								RHP_BUG("");
								goto error_vpn_rlm_l;
							}
							n2 += n;


							n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
							if(n < 0) {
								err = -ENOMEM;
								RHP_BUG("");
								goto error_vpn_rlm_l;
							}
							n2 += n;
						}


					}else{

						// RHP_IKE_RESPONDER

						n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
								(xmlChar*)"mobike_keepalive_pending","%d",
								vpn->mobike.resp.keepalive_pending);
						if(n < 0){
							err = -ENOMEM;
							RHP_BUG("");
							goto error_vpn_rlm_l;
						}
						n2 += n;
					}
				}
			}

			{
				rhp_ip_addr_list* peer_addr = vpn->internal_net_info.peer_addrs;

				if( peer_addr == NULL ){
					peer_addr = vpn->nhrp.nhs_next_hop_addrs;
				}

				while( peer_addr ){

					n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"internal_peer_addr");
					if(n < 0) {
						err = -ENOMEM;
						RHP_BUG("");
						goto error_vpn_rlm_l;
					}
					n2 += n;

					if( peer_addr->ip_addr.addr_family == AF_INET ){

						u32 ip = peer_addr->ip_addr.addr.v4;

						n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
								(xmlChar*)"address_v4","%d.%d.%d.%d",
								((u8*)&ip)[0],((u8*)&ip)[1],((u8*)&ip)[2],((u8*)&ip)[3]);

					}else if( peer_addr->ip_addr.addr_family == AF_INET6 ){

						n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
								(xmlChar*)"address_v6","%s",
								rhp_ipv6_string(peer_addr->ip_addr.addr.v6));

					}else{
						RHP_BUG("%d",peer_addr->ip_addr.addr_family);
						goto next_peer_addr;
					}

					if(n < 0){
						err = -ENOMEM;
						RHP_BUG("");
						goto error_vpn_rlm_l;
					}
					n2 += n;

					n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
					if(n < 0) {
						err = -ENOMEM;
						RHP_BUG("");
						goto error_vpn_rlm_l;
					}
					n2 += n;

next_peer_addr:
					peer_addr = peer_addr->next;
				}
			}

			if( rlm->internal_ifc->ifc ){

				rhp_ip_addr_list* addr_lst;
			  rhp_ifc_entry* ifc = rlm->internal_ifc->ifc;

				RHP_LOCK(&(ifc->lock));

				addr_lst = rlm->internal_ifc->addrs;
				while( addr_lst ){

					n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"internal_if_addr");
					if(n < 0) {
						err = -ENOMEM;
						RHP_BUG("");
						RHP_UNLOCK(&(ifc->lock));
						goto error_vpn_rlm_l;
					}
					n2 += n;

					if( addr_lst->ip_addr.addr_family == AF_INET ){

						u32 ip = addr_lst->ip_addr.addr.v4;

						n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
								(xmlChar*)"address_v4","%d.%d.%d.%d/%d",
								((u8*)&ip)[0],((u8*)&ip)[1],((u8*)&ip)[2],((u8*)&ip)[3],
								addr_lst->ip_addr.prefixlen);
						if(n < 0){
							err = -ENOMEM;
							RHP_BUG("");
							RHP_UNLOCK(&(ifc->lock));
							goto error_vpn_rlm_l;
						}
						n2 += n;

					}else if( addr_lst->ip_addr.addr_family == AF_INET6 ){

						n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
								(xmlChar*)"address_v6",
								"%s/%d",
								rhp_ipv6_string(addr_lst->ip_addr.addr.v6),
								addr_lst->ip_addr.prefixlen);

						if(n < 0){
							err = -ENOMEM;
							RHP_BUG("");
							RHP_UNLOCK(&(ifc->lock));
							goto error_vpn_rlm_l;
						}
						n2 += n;
					}

					n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
					if(n < 0) {
						err = -ENOMEM;
						RHP_BUG("");
						RHP_UNLOCK(&(ifc->lock));
						goto error_vpn_rlm_l;
					}
					n2 += n;

					addr_lst = addr_lst->next;
				}

				{
					rhp_ifc_addr* ifc_addr = ifc->ifc_addrs;
					while( ifc_addr ){

						n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,
								(xmlChar*)"internal_if_addr_ifc");
						if(n < 0) {
							err = -ENOMEM;
							RHP_BUG("");
							RHP_UNLOCK(&(ifc->lock));
							goto error_vpn_rlm_l;
						}
						n2 += n;

						if( ifc_addr->addr.addr_family == AF_INET ){

							u32 ip = ifc_addr->addr.addr.v4;

							n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
									(xmlChar*)"address_v4","%d.%d.%d.%d/%d",
									((u8*)&ip)[0],((u8*)&ip)[1],((u8*)&ip)[2],((u8*)&ip)[3],
									ifc_addr->addr.prefixlen);
							if(n < 0){
								err = -ENOMEM;
								RHP_BUG("");
								RHP_UNLOCK(&(ifc->lock));
								goto error_vpn_rlm_l;
							}
							n2 += n;

						}else	if( ifc_addr->addr.addr_family == AF_INET6 ){

							n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
									(xmlChar*)"address_v6",
									"%s/%d",
									rhp_ipv6_string(ifc_addr->addr.addr.v6),
									ifc_addr->addr.prefixlen);

							if(n < 0){
								err = -ENOMEM;
								RHP_BUG("");
								RHP_UNLOCK(&(ifc->lock));
								goto error_vpn_rlm_l;
							}
							n2 += n;
						}

						n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
						if(n < 0) {
							err = -ENOMEM;
							RHP_BUG("");
							RHP_UNLOCK(&(ifc->lock));
							goto error_vpn_rlm_l;
						}
						n2 += n;


						ifc_addr = ifc_addr->lst_next;
					}
				}

				RHP_UNLOCK(&(ifc->lock));
			}

			if( vpn->cfg_peer && vpn->cfg_peer->is_access_point ){

				{
					rhp_route_map* rtmap = rlm->route_maps;

					rhp_ip_addr *intr_gw_addr_v4 = NULL, *intr_gw_addr_v6 = NULL;
					int flag = 0;

					intr_gw_addr_v4 = rhp_vpn_internal_route_get_gw_addr(AF_INET,rlm,vpn,NULL);
					if( intr_gw_addr_v4 == NULL ||
							rhp_ip_addr_null(intr_gw_addr_v4) ){

						intr_gw_addr_v4 = &(rlm->ext_internal_gateway_addr);
					}


					intr_gw_addr_v6 = rhp_vpn_internal_route_get_gw_addr(AF_INET6,rlm,vpn,NULL);
					if( intr_gw_addr_v6 == NULL ||
							rhp_ip_addr_null(intr_gw_addr_v6) ){

						intr_gw_addr_v6 = &(rlm->ext_internal_gateway_addr_v6);
					}

					while( rtmap ){

						if( !rtmap->ikev2_cfg ){
							goto rtmap_next;
						}

						if( rtmap->dest_addr.addr_family == AF_INET ||
								rtmap->dest_addr.addr_family == AF_INET6 ){

							if( !flag ){

								n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,
										(xmlChar*)"internal_networks");
								if(n < 0) {
									err = -ENOMEM;
									RHP_BUG("");
									goto error_vpn_rlm_l;
								}
								n2 += n;

								if( intr_gw_addr_v4  ){

									u32 ip = intr_gw_addr_v4->addr.v4;

									n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
											(xmlChar*)"internal_gateway_v4","%d.%d.%d.%d",
											((u8*)&ip)[0],((u8*)&ip)[1],((u8*)&ip)[2],((u8*)&ip)[3]);

									if(n < 0){
										err = -ENOMEM;
										RHP_BUG("");
										goto error_vpn_rlm_l;
									}
									n2 += n;

								}

								if( intr_gw_addr_v6 ){

									n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
											(xmlChar*)"internal_gateway_v6","%s",
											rhp_ipv6_string(intr_gw_addr_v6->addr.v6));

									if(n < 0){
										err = -ENOMEM;
										RHP_BUG("");
										goto error_vpn_rlm_l;
									}
									n2 += n;
								}

								flag = 1;
							}

							if( rtmap->dest_addr.addr_family == AF_INET ){

								u32 ip = rtmap->dest_addr.addr.v4;

								n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,
										(xmlChar*)"internal_subnet_v4");
								if(n < 0) {
									err = -ENOMEM;
									RHP_BUG("");
									goto error_vpn_rlm_l;
								}
								n2 += n;

								n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
										(xmlChar*)"network_v4","%d.%d.%d.%d/%d",
										((u8*)&ip)[0],((u8*)&ip)[1],((u8*)&ip)[2],((u8*)&ip)[3],
										rtmap->dest_addr.prefixlen);
								if(n < 0){
									err = -ENOMEM;
									RHP_BUG("");
									goto error_vpn_rlm_l;
								}
								n2 += n;

							}else if( rtmap->dest_addr.addr_family == AF_INET6 ){

								n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,
										(xmlChar*)"internal_subnet_v6");
								if(n < 0) {
									err = -ENOMEM;
									RHP_BUG("");
									goto error_vpn_rlm_l;
								}
								n2 += n;

								n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
										(xmlChar*)"network_v6","%s/%d",
											rhp_ipv6_string(rtmap->dest_addr.addr.v6),rtmap->dest_addr.prefixlen);

								if(n < 0){
									err = -ENOMEM;
									RHP_BUG("");
									goto error_vpn_rlm_l;
								}
								n2 += n;
							}

							n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
							if(n < 0) {
								err = -ENOMEM;
								RHP_BUG("");
								goto error_vpn_rlm_l;
							}
							n2 += n;
						}

rtmap_next:
						rtmap = rtmap->next;
					}

					if( flag ){

						n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
						if(n < 0) {
							err = -ENOMEM;
							RHP_BUG("");
							goto error_vpn_rlm_l;
						}
						n2 += n;
					}
				}


				{
					rhp_split_dns_domain* domain = rlm->split_dns.domains;
					rhp_ip_addr* name_server = &(rlm->split_dns.internal_server_addr);
					rhp_ip_addr* name_server_v6 = &(rlm->split_dns.internal_server_addr_v6);

					if( !rhp_ip_addr_null(name_server) || !rhp_ip_addr_null(name_server_v6) ){

						n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"split_dns");
						if(n < 0) {
							err = -ENOMEM;
							RHP_BUG("");
							goto error_vpn_rlm_l;
						}
						n2 += n;

						n = 0;
						if( name_server->addr_family == AF_INET ){

							u32 ip = name_server->addr.v4;

							n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
									(xmlChar*)"internal_dns_server_v4","%d.%d.%d.%d",
									((u8*)&ip)[0],((u8*)&ip)[1],((u8*)&ip)[2],((u8*)&ip)[3]);
							if(n < 0){
								err = -ENOMEM;
								RHP_BUG("");
								goto error_vpn_rlm_l;
							}
							n2 += n;

						}

						if( name_server_v6->addr_family == AF_INET6 ){

							n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
									(xmlChar*)"internal_dns_server_v6","%s",
									rhp_ipv6_string(name_server_v6->addr.v6));
							if(n < 0){
								err = -ENOMEM;
								RHP_BUG("");
								goto error_vpn_rlm_l;
							}
							n2 += n;
						}


						while( domain ){

							if( domain->ikev2_cfg ){

								n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,
										(xmlChar*)"split_dns_domain");
								if(n < 0) {
									err = -ENOMEM;
									RHP_BUG("");
									goto error_vpn_rlm_l;
								}
								n2 += n;

								n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
										(xmlChar*)"internal_domain_suffix","%s",domain->name);

								if(n < 0){
									err = -ENOMEM;
									RHP_BUG("");
									goto error_vpn_rlm_l;
								}
								n2 += n;

								n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
								if(n < 0) {
									err = -ENOMEM;
									RHP_BUG("");
									goto error_vpn_rlm_l;
								}
								n2 += n;
							}

							domain = domain->next;
						}

						n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
						if(n < 0) {
							err = -ENOMEM;
							RHP_BUG("");
							goto error_vpn_rlm_l;
						}
						n2 += n;
					}
				}
			}


			if( vpn->eap.eap_method == RHP_PROTO_EAP_TYPE_PRIV_RADIUS && vpn->radius.rx_accept_attrs ){

				int at;
				struct {
#define RHP_UI_HTTP_RADIUS_RX_ATTR_IP_ADDR			1 // rhp_ip_addr*
#define RHP_UI_HTTP_RADIUS_RX_ATTR_U32					2 // u32
#define RHP_UI_HTTP_RADIUS_RX_ATTR_ULONG				3 // unsigned long
#define RHP_UI_HTTP_RADIUS_RX_ATTR_CHAR					4 // char*
#define RHP_UI_HTTP_RADIUS_RX_ATTR_STRING_LIST	5 // rhp_string_list* head
#define RHP_UI_HTTP_RADIUS_RX_ATTR_RT_MAP_LIST	6 // rhp_internal_route_map* head
#define RHP_UI_HTTP_RADIUS_RX_ATTR_DOMAIN_LIST	7 // rhp_split_dns_domain* head
					int type;
					char* name;
					void* value;
				} rx_attrs[] = {
						{
							type: RHP_UI_HTTP_RADIUS_RX_ATTR_IP_ADDR,
							name: "Framed-IP-Address",
							value: &(vpn->radius.rx_accept_attrs->framed_ipv4)
						},
						{
							type: RHP_UI_HTTP_RADIUS_RX_ATTR_IP_ADDR,
							name: "Framed-IPv6-Address",
							value: &(vpn->radius.rx_accept_attrs->framed_ipv6)
						},
						{
							type: RHP_UI_HTTP_RADIUS_RX_ATTR_IP_ADDR,
							name: "MS-Primary-DNS-Server",
							value: &(vpn->radius.rx_accept_attrs->ms_primary_dns_server_ipv4)
						},
						{
							type: RHP_UI_HTTP_RADIUS_RX_ATTR_IP_ADDR,
							name: "DNS-Server-IPv6-Address",
							value: &(vpn->radius.rx_accept_attrs->dns_server_ipv6)
						},
						{
							type: RHP_UI_HTTP_RADIUS_RX_ATTR_IP_ADDR,
							name: "MS-Primary-NBNS-Server",
							value: &(vpn->radius.rx_accept_attrs->ms_primary_nbns_server_ipv4)
						},
						{
							type: RHP_UI_HTTP_RADIUS_RX_ATTR_U32,
							name: "Session-Timeout",
							value: &(vpn->radius.rx_accept_attrs->session_timeout)
						},
						{
							type: RHP_UI_HTTP_RADIUS_RX_ATTR_U32,
							name: "Framed-MTU",
							value: &(vpn->radius.rx_accept_attrs->framed_mtu)
						},
						{
							type: RHP_UI_HTTP_RADIUS_RX_ATTR_ULONG,
							name: "Private-VPN-Realm-ID",
							value: &(vpn->radius.rx_accept_attrs->priv_realm_id)
						},
						{
							type: RHP_UI_HTTP_RADIUS_RX_ATTR_STRING_LIST,
							name: "Tunnel-Private-Group-ID",
							value: vpn->radius.rx_accept_attrs->tunnel_private_group_ids
						},
						{
							type: RHP_UI_HTTP_RADIUS_RX_ATTR_STRING_LIST,
							name: "Private-VPN-Realm-Role",
							value: vpn->radius.rx_accept_attrs->priv_realm_roles
						},
						{
							type: RHP_UI_HTTP_RADIUS_RX_ATTR_CHAR,
							name: "Tunnel-Client-Auth-ID",
							value: vpn->radius.rx_accept_attrs->tunnel_client_auth_id
						},
						{
							type: RHP_UI_HTTP_RADIUS_RX_ATTR_CHAR,
							name: "Private-User-Index",
							value: vpn->radius.rx_accept_attrs->priv_user_index
						},
						{
							type: RHP_UI_HTTP_RADIUS_RX_ATTR_IP_ADDR,
							name: "Private-Internal-IPv4-Address",
							value: &(vpn->radius.rx_accept_attrs->priv_internal_addr_ipv4)
						},
						{
							type: RHP_UI_HTTP_RADIUS_RX_ATTR_IP_ADDR,
							name: "Private-Internal-IPv6-Address",
							value: &(vpn->radius.rx_accept_attrs->priv_internal_addr_ipv6)
						},
						{
							type: RHP_UI_HTTP_RADIUS_RX_ATTR_IP_ADDR,
							name: "Private-Internal-DNS-IPv4-Server",
							value: &(vpn->radius.rx_accept_attrs->priv_internal_dns_server_ipv4)
						},
						{
							type: RHP_UI_HTTP_RADIUS_RX_ATTR_IP_ADDR,
							name: "Private-Internal-DNS-IPv6-Server",
							value: &(vpn->radius.rx_accept_attrs->priv_internal_dns_server_ipv6)
						},
						{
							type: RHP_UI_HTTP_RADIUS_RX_ATTR_DOMAIN_LIST,
							name: "Private-Internal-Domain-Name",
							value: vpn->radius.rx_accept_attrs->priv_domain_names
						},
						{
							type: RHP_UI_HTTP_RADIUS_RX_ATTR_RT_MAP_LIST,
							name: "Private-Internal-Route-IPv4",
							value: vpn->radius.rx_accept_attrs->priv_internal_route_ipv4
						},
						{
							type: RHP_UI_HTTP_RADIUS_RX_ATTR_RT_MAP_LIST,
							name: "Private-Internal-Route-IPv6",
							value: vpn->radius.rx_accept_attrs->priv_internal_route_ipv6
						},
						{
							type: RHP_UI_HTTP_RADIUS_RX_ATTR_IP_ADDR,
							name: "Private-Internal-Gateway-IPv4",
							value: &(vpn->radius.rx_accept_attrs->priv_internal_gateway_ipv4)
						},
						{
							type: RHP_UI_HTTP_RADIUS_RX_ATTR_IP_ADDR,
							name: "Private-Internal-Gateway-IPv6",
							value: &(vpn->radius.rx_accept_attrs->priv_internal_gateway_ipv6)
						},
						{0,NULL,NULL}
				};

				n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"radius_rx_attrs");
				if(n < 0) {
					err = -ENOMEM;
					RHP_BUG("");
					goto error_vpn_rlm_l;
				}
				n2 += n;

				for( at = 0;; at++ ){

					int is_list = 0;

					if( !rx_attrs[at].type ){
						break;
					}

					if( rx_attrs[at].type != RHP_UI_HTTP_RADIUS_RX_ATTR_STRING_LIST &&
							rx_attrs[at].type != RHP_UI_HTTP_RADIUS_RX_ATTR_RT_MAP_LIST &&
							rx_attrs[at].type != RHP_UI_HTTP_RADIUS_RX_ATTR_DOMAIN_LIST ){

						n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"rx_attr");
						if(n < 0) {
							err = -ENOMEM;
							RHP_BUG("");
							goto error_vpn_rlm_l;
						}
						n2 += n;

						n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
								(xmlChar*)"name","%s",rx_attrs[at].name);
						if(n < 0){
							err = -ENOMEM;
							RHP_BUG("");
							goto error_vpn_rlm_l;
						}
						n2 += n;

					}else{

						is_list = 1;
					}


					switch( rx_attrs[at].type ){

					case RHP_UI_HTTP_RADIUS_RX_ATTR_IP_ADDR:
					{
						rhp_ip_addr* ip_addr = (rhp_ip_addr*)rx_attrs[at].value;

						if( ip_addr->addr_family == AF_INET ){

							n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
									(xmlChar*)"value","%d.%d.%d.%d",
									((u8*)&(ip_addr->addr.v4))[0],((u8*)&(ip_addr->addr.v4))[1],((u8*)&(ip_addr->addr.v4))[2],((u8*)&(ip_addr->addr.v4))[3]);
							if(n < 0){
								err = -ENOMEM;
								RHP_BUG("");
								goto error_vpn_rlm_l;
							}
							n2 += n;

						}else if( ip_addr->addr_family == AF_INET6 ){

							n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
									(xmlChar*)"value","%s",
									rhp_ipv6_string(ip_addr->addr.v6));
							if(n < 0){
								err = -ENOMEM;
								RHP_BUG("");
								goto error_vpn_rlm_l;
							}
							n2 += n;
						}
					}
						break;

					case RHP_UI_HTTP_RADIUS_RX_ATTR_U32:

						if( *((u32*)rx_attrs[at].value) ){

							n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
									(xmlChar*)"value","%u",
									*((u32*)rx_attrs[at].value));
							if(n < 0){
								err = -ENOMEM;
								RHP_BUG("");
								goto error_vpn_rlm_l;
							}
							n2 += n;
						}
						break;

					case RHP_UI_HTTP_RADIUS_RX_ATTR_ULONG:

						if( *((unsigned long*)rx_attrs[at].value) &&
								(strcmp(rx_attrs[at].name,"Private-VPN-Realm-ID") ||
								 (*((unsigned long*)rx_attrs[at].value) != RHP_VPN_REALM_ID_UNKNOWN)) ){

							n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
									(xmlChar*)"value","%lu",
									*((unsigned long*)rx_attrs[at].value));
							if(n < 0){
								err = -ENOMEM;
								RHP_BUG("");
								goto error_vpn_rlm_l;
							}
							n2 += n;
						}
						break;

					case RHP_UI_HTTP_RADIUS_RX_ATTR_CHAR:

						if( rx_attrs[at].value ){

							n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
									(xmlChar*)"value","%s",
									(char*)rx_attrs[at].value);
							if(n < 0){
								err = -ENOMEM;
								RHP_BUG("");
								goto error_vpn_rlm_l;
							}
							n2 += n;
						}
						break;

					case RHP_UI_HTTP_RADIUS_RX_ATTR_STRING_LIST:
					{
						rhp_string_list* str_lst = (rhp_string_list*)rx_attrs[at].value;

						while( str_lst ){

							n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"rx_attr");
							if(n < 0) {
								err = -ENOMEM;
								RHP_BUG("");
								goto error_vpn_rlm_l;
							}
							n2 += n;

							n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
									(xmlChar*)"name","%s",rx_attrs[at].name);
							if(n < 0){
								err = -ENOMEM;
								RHP_BUG("");
								goto error_vpn_rlm_l;
							}
							n2 += n;

							n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
									(xmlChar*)"value","%s",
									str_lst->string);
							if(n < 0){
								err = -ENOMEM;
								RHP_BUG("");
								goto error_vpn_rlm_l;
							}
							n2 += n;

							n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
							if(n < 0) {
								err = -ENOMEM;
								RHP_BUG("");
								goto error_vpn_rlm_l;
							}
							n2 += n;

							str_lst = str_lst->next;
						}
					}
						break;

					case RHP_UI_HTTP_RADIUS_RX_ATTR_RT_MAP_LIST:
					{
						rhp_internal_route_map* rtmap_lst = (rhp_internal_route_map*)rx_attrs[at].value;

						while( rtmap_lst ){

							rhp_ip_addr* dest_addr = &(rtmap_lst->dest_addr);

							if( dest_addr->addr_family == AF_INET || dest_addr->addr_family == AF_INET6 ){
								n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"rx_attr");
								if(n < 0) {
									err = -ENOMEM;
									RHP_BUG("");
									goto error_vpn_rlm_l;
								}
								n2 += n;

								n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
										(xmlChar*)"name","%s",rx_attrs[at].name);
								if(n < 0){
									err = -ENOMEM;
									RHP_BUG("");
									goto error_vpn_rlm_l;
								}
								n2 += n;

								if( dest_addr->addr_family == AF_INET ){

									n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
											(xmlChar*)"value","%d.%d.%d.%d/%d",
											((u8*)&(dest_addr->addr.v4))[0],((u8*)&(dest_addr->addr.v4))[1],((u8*)&(dest_addr->addr.v4))[2],((u8*)&(dest_addr->addr.v4))[3],
											dest_addr->prefixlen);

									if(n < 0){
										err = -ENOMEM;
										RHP_BUG("");
										goto error_vpn_rlm_l;
									}
									n2 += n;

								}else if( dest_addr->addr_family == AF_INET6 ){

									n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
											(xmlChar*)"value","%s/%d",
											rhp_ipv6_string(dest_addr->addr.v6),dest_addr->prefixlen);
									if(n < 0){
										err = -ENOMEM;
										RHP_BUG("");
										goto error_vpn_rlm_l;
									}
									n2 += n;
								}


								n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
								if(n < 0) {
									err = -ENOMEM;
									RHP_BUG("");
									goto error_vpn_rlm_l;
								}
								n2 += n;
							}

							rtmap_lst = rtmap_lst->next;
						}
					}
						break;

					case RHP_UI_HTTP_RADIUS_RX_ATTR_DOMAIN_LIST:
					{
						rhp_split_dns_domain* domain_lst = (rhp_split_dns_domain*)rx_attrs[at].value;

						while( domain_lst ){

							n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"rx_attr");
							if(n < 0) {
								err = -ENOMEM;
								RHP_BUG("");
								goto error_vpn_rlm_l;
							}
							n2 += n;

							n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
									(xmlChar*)"name","%s",rx_attrs[at].name);
							if(n < 0){
								err = -ENOMEM;
								RHP_BUG("");
								goto error_vpn_rlm_l;
							}
							n2 += n;

							n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
									(xmlChar*)"value","%s",
									domain_lst->name);
							if(n < 0){
								err = -ENOMEM;
								RHP_BUG("");
								goto error_vpn_rlm_l;
							}
							n2 += n;

							n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
							if(n < 0) {
								err = -ENOMEM;
								RHP_BUG("");
								goto error_vpn_rlm_l;
							}
							n2 += n;

							domain_lst = domain_lst->next;
						}
					}
						break;

					default:
						RHP_BUG("%d",rx_attrs[at].type);
						break;
					}

					if( !is_list ){

						n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
						if(n < 0) {
							err = -ENOMEM;
							RHP_BUG("");
							goto error_vpn_rlm_l;
						}
						n2 += n;
					}
				}

				n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
				if(n < 0) {
					err = -ENOMEM;
					RHP_BUG("");
					goto error_vpn_rlm_l;
				}
				n2 += n;
			}

			if( vpn->nhrp.role == RHP_NHRP_SERVICE_CLIENT ){

				if( vpn->nhrp.nhc_addr_maps_head ){

			  	rhp_nhrp_addr_map* nhc_addr_map = vpn->nhrp.nhc_addr_maps_head;

					n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"nhrp_client");
					if(n < 0) {
						err = -ENOMEM;
						RHP_BUG("");
						goto error_vpn_rlm_l;
					}
					n2 += n;


					while( nhc_addr_map ){

						n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"nhc_addr_map");
						if(n < 0) {
							err = -ENOMEM;
							RHP_BUG("");
							goto error_vpn_rlm_l;
						}
						n2 += n;


						if( nhc_addr_map->nbma_addr_family == AF_INET ){

							n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
									(xmlChar*)"nbma_addr_v4","%d.%d.%d.%d",
									((u8*)&(nhc_addr_map->nbma_addr.v4))[0],((u8*)&(nhc_addr_map->nbma_addr.v4))[1],
									((u8*)&(nhc_addr_map->nbma_addr.v4))[2],((u8*)&(nhc_addr_map->nbma_addr.v4))[3]);

							if(n < 0){
								err = -ENOMEM;
								RHP_BUG("");
								goto error_vpn_rlm_l;
							}
							n2 += n;

						}else if( nhc_addr_map->nbma_addr_family == AF_INET6 ){

							n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
									(xmlChar*)"nbma_addr_v6","%s",
									rhp_ipv6_string(nhc_addr_map->nbma_addr.v6));
							if(n < 0){
								err = -ENOMEM;
								RHP_BUG("");
								goto error_vpn_rlm_l;
							}
							n2 += n;
						}


						if( nhc_addr_map->proto_addr_family == AF_INET ){

							n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
									(xmlChar*)"protocol_addr_v4","%d.%d.%d.%d",
									((u8*)&(nhc_addr_map->proto_addr.v4))[0],((u8*)&(nhc_addr_map->proto_addr.v4))[1],
									((u8*)&(nhc_addr_map->proto_addr.v4))[2],((u8*)&(nhc_addr_map->proto_addr.v4))[3]);
							if(n < 0){
								err = -ENOMEM;
								RHP_BUG("");
								goto error_vpn_rlm_l;
							}
							n2 += n;

						}else if( nhc_addr_map->proto_addr_family == AF_INET6 ){

							n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
									(xmlChar*)"protocol_addr_v6","%s",
									rhp_ipv6_string(nhc_addr_map->proto_addr.v6));
							if(n < 0){
								err = -ENOMEM;
								RHP_BUG("");
								goto error_vpn_rlm_l;
							}
							n2 += n;
						}


						if( nhc_addr_map->nat_nbma_addr_family == AF_INET ){

							n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
									(xmlChar*)"nat_nbma_addr_v4","%d.%d.%d.%d",
									((u8*)&(nhc_addr_map->nat_nbma_addr.v4))[0],((u8*)&(nhc_addr_map->nat_nbma_addr.v4))[1],
									((u8*)&(nhc_addr_map->nat_nbma_addr.v4))[2],((u8*)&(nhc_addr_map->nat_nbma_addr.v4))[3]);
							if(n < 0){
								err = -ENOMEM;
								RHP_BUG("");
								goto error_vpn_rlm_l;
							}
							n2 += n;

						}else if( nhc_addr_map->nat_nbma_addr_family == AF_INET6 ){

							n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
									(xmlChar*)"nat_nbma_addr_v6","%s",
									rhp_ipv6_string(nhc_addr_map->nat_nbma_addr.v6));
							if(n < 0){
								err = -ENOMEM;
								RHP_BUG("");
								goto error_vpn_rlm_l;
							}
							n2 += n;
						}

						n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
						if(n < 0) {
							err = -ENOMEM;
							RHP_BUG("");
							goto error_vpn_rlm_l;
						}
						n2 += n;

						nhc_addr_map = nhc_addr_map->next;
					}

					n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
					if(n < 0) {
						err = -ENOMEM;
						RHP_BUG("");
						goto error_vpn_rlm_l;
					}
					n2 += n;
				}
			}



			err = _rhp_ui_http_vpn_get_info_ikesa_serialize(vpn,writer,&n2);
			if( err ){
				RHP_BUG("");
				goto error_vpn_rlm_l;
			}

			err = _rhp_ui_http_vpn_get_info_childsa_serialize(vpn,writer,&n2);
			if( err ){
				RHP_BUG("");
				goto error_vpn_rlm_l;
			}


			n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
			if(n < 0) {
				err = -ENOMEM;
				RHP_BUG("");
				goto error_vpn_rlm_l;
			}
			n2 += n;
		}



		n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
		if(n < 0) {
			err = -ENOMEM;
			RHP_BUG("");
			goto error_vpn_rlm_l;
		}
		n2 += n;
  }

  RHP_UNLOCK(&(rlm->lock));

  RHP_UNLOCK(&(vpn->lock));


  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_GET_INFO_VPN_SERIALIZE_RTRN,"xd",http_bus_sess,n2);
  return n2;


error_vpn_rlm_l:
	RHP_UNLOCK(&(rlm->lock));
error_vpn_l:
	RHP_UNLOCK(&(vpn->lock));

  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_GET_INFO_VPN_SERIALIZE_ERR,"xE",http_bus_sess,err);
  return err;
}

static int _rhp_ui_http_vpn_get_info_vpn(xmlDocPtr doc,xmlNodePtr node,rhp_http_conn* http_conn,
		rhp_http_bus_session* http_bus_sess,rhp_http_request* http_req,void* ctx)
{
  int err = -EINVAL;
  char* vpn_realm_str = NULL;
  char* peer_id_type_str = NULL;
  char* peer_id_str = NULL;
  char* unique_id_str = NULL;
  rhp_ikev2_id peer_id;
  unsigned long rlm_id = 0;
  char* endp;
  rhp_vpn* vpn = NULL;
  void* vpn_ref = NULL;

  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_GET_INFO_VPN,"xxxxxx",doc,node,http_conn,http_bus_sess,http_req,ctx);

	memset(&peer_id,0,sizeof(rhp_ikev2_id));

  if( doc == NULL || node == NULL ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_GET_INFO_VPN_NO_DOC_NODE,"xxx",http_conn,http_bus_sess,http_req);
    return -EINVAL;
  }

  vpn_realm_str = (char*)rhp_xml_get_prop(node,(const xmlChar*)"vpn_realm");
  if( vpn_realm_str == NULL ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_GET_INFO_VPN_NO_VPN_REALM,"xxx",http_conn,http_bus_sess,http_req);
    goto error;
  }

  rlm_id = strtoul((char*)vpn_realm_str,&endp,0);
  if( (rlm_id == ULONG_MAX && errno == ERANGE) || *endp != '\0' ){
  	err = -ENOENT;
  	RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_GET_INFO_VPN_NO_VPN_REALM_2,"xxxs",http_conn,http_bus_sess,http_req,vpn_realm_str);
  	goto error;
  }

  if( _rhp_ui_http_permitted(http_conn,http_bus_sess,rlm_id) ){
			err = -EPERM;
			RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_GET_INFO_VPN_NOT_PERMITTED,"xxxuu",http_conn,http_bus_sess,http_req,http_conn->user_realm_id,http_bus_sess->user_realm_id);
			goto error;
	}

  unique_id_str = (char*)rhp_xml_get_prop(node,(const xmlChar*)"vpn_unique_id");

  if( unique_id_str ){

  	u8 vpn_unique_id[RHP_VPN_UNIQUE_ID_SIZE];

  	memset(vpn_unique_id,0,RHP_VPN_UNIQUE_ID_SIZE);

  	err = rhp_str_to_vpn_unique_id(unique_id_str,vpn_unique_id);
  	if( err ){
			err = RHP_STATUS_INVALID_MSG;
  		goto error;
  	}

  	vpn_ref = rhp_vpn_get_by_unique_id(vpn_unique_id);
		vpn = RHP_VPN_REF(vpn_ref);

  }else{

		peer_id_type_str = (char*)rhp_xml_get_prop(node,(const xmlChar*)"peer_id_type");
		if( peer_id_type_str == NULL ){
			err = RHP_STATUS_INVALID_MSG;
			RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_GET_INFO_VPN_NO_PEER_ID_TYPE,"xxx",http_conn,http_bus_sess,http_req);
			goto error;
		}

		peer_id_str = (char*)rhp_xml_get_prop(node,(const xmlChar*)"peer_id");
		if( peer_id_str == NULL ){
			err = RHP_STATUS_INVALID_MSG;
			RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_GET_INFO_VPN_NO_PEER_ID,"xxx",http_conn,http_bus_sess,http_req);
			goto error;
		}

		err = rhp_cfg_parse_ikev2_id(node,(xmlChar*)"peer_id_type",(xmlChar*)"peer_id",&peer_id);
		if( err == -ENOENT ){

			rhp_eap_id eap_peer_id;
			memset(&eap_peer_id,0,sizeof(rhp_eap_id));

			err = rhp_cfg_parse_eap_id(node,(xmlChar*)"peer_id_type",(xmlChar*)"peer_id",&eap_peer_id);
			if( !err ){

				vpn_ref = rhp_vpn_get_by_eap_peer_id(rlm_id,&eap_peer_id);
				vpn = RHP_VPN_REF(vpn_ref);

				rhp_eap_id_clear(&eap_peer_id);

				if( vpn ){

				  RHP_LOCK(&(vpn->lock));

				  err = rhp_ikev2_id_dup(&peer_id,&(vpn->peer_id));
					if( err ){
					  RHP_UNLOCK(&(vpn->lock));
						RHP_BUG("");
						goto error;
					}

					RHP_UNLOCK(&(vpn->lock));
				}
			}

		}else if( !err ){

			vpn_ref = rhp_vpn_get_in_valid_rlm_cfg(rlm_id,&peer_id);
			vpn = RHP_VPN_REF(vpn_ref);
		}

		if( err ){
			RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_GET_INFO_VPN_NO_PEER_ID_2,"xxxss",http_conn,http_bus_sess,http_req,peer_id_str,peer_id_str);
			goto error;
		}
  }

  if( vpn == NULL ){
		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_GET_INFO_VPN_NO_ENT_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
		err = -ENOENT;
		goto error;
	}

  if( http_conn->user_realm_id && vpn->vpn_realm_id != http_conn->user_realm_id ){
		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_GET_INFO_VPN_INVALID_REALM_ID,"xxxuuE",http_conn,http_bus_sess,http_req,vpn->vpn_realm_id,http_conn->user_realm_id,err);
		err = -EPERM;
		goto error;
  }

  err = rhp_http_bus_send_response(http_conn,http_bus_sess,_rhp_ui_http_vpn_get_info_vpn_serialize,vpn);
  if( err ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_GET_INFO_VPN_TX_RESP_ERR,"xxxxE",http_conn,http_bus_sess,http_req,vpn,err);
    goto error;
  }

  rhp_vpn_unhold(vpn_ref);

  if( vpn_realm_str ){
  	_rhp_free(vpn_realm_str);
  }
  if( peer_id_type_str ){
  	_rhp_free(peer_id_type_str);
  }
  if( peer_id_str ){
  	_rhp_free(peer_id_str);
  }
  if( unique_id_str ){
  	_rhp_free(unique_id_str);
  }
  rhp_ikev2_id_clear(&peer_id);

  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_GET_INFO_VPN_RTRN,"xxxx",http_conn,http_bus_sess,http_req,vpn);
  return RHP_STATUS_CLOSE_HTTP_CONN;

error:
	if( vpn ){
	  rhp_vpn_unhold(vpn_ref);
	}
  if( vpn_realm_str ){
  	_rhp_free(vpn_realm_str);
  }
  if( peer_id_type_str ){
  	_rhp_free(peer_id_type_str);
  }
  if( peer_id_str ){
  	_rhp_free(peer_id_str);
  }
  if( unique_id_str ){
  	_rhp_free(unique_id_str);
  }
  rhp_ikev2_id_clear(&peer_id);

  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_GET_INFO_VPN_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  return err;
}

struct _rhp_ui_http_enum_ctx {
	unsigned long rlm_id;
	void* writer;
	int idx;
	int* n2;
	char* xml_tag_name;
	int ignore_resp_negotiating;
	unsigned long priv;
};
typedef struct _rhp_ui_http_enum_ctx	rhp_ui_http_enum_ctx;

struct _rhp_ui_http_cfg_update_enum_ctx {
	rhp_vpn_realm* new_rlm;
	xmlNodePtr new_node;
	unsigned long rlm_id;
  xmlNodePtr cfg_parent;
  time_t created_time;
  time_t updated_time;
  time_t sess_resume_policy_index;
  int update_sess_resume_policy_index;
};
typedef struct _rhp_ui_http_cfg_update_enum_ctx	rhp_ui_http_cfg_update_enum_ctx;


static int _rhp_ui_http_vpn_get_peers_enum_cb(rhp_vpn* vpn,void* ctx)
{
	int err = -EINVAL;
	int n;
	rhp_ui_http_enum_ctx* enum_ctx = (rhp_ui_http_enum_ctx*)ctx;
	rhp_vpn_realm* rlm;
	void* writer = enum_ctx->writer;
	int* n2 = enum_ctx->n2;

	RHP_LOCK(&(vpn->lock));

	rlm = vpn->rlm;
	if( rlm == NULL ){

		RHP_UNLOCK(&(vpn->lock));

		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_GET_PEERS_ENUM_CB_IGNORED_RLM_NOT_RESOLVED,"x",vpn);

		return 0;
	}


	if( enum_ctx->ignore_resp_negotiating ){

		if( vpn->origin_side == RHP_IKE_RESPONDER && vpn->ikesa_num ){

			rhp_ikesa* ikesa = vpn->ikesa_list_head;

			switch( ikesa->state ){
			// IKEv2
			case RHP_IKESA_STAT_ESTABLISHED:
			case RHP_IKESA_STAT_REKEYING:
			case RHP_IKESA_STAT_DELETE:
			case RHP_IKESA_STAT_DELETE_WAIT:
			case RHP_IKESA_STAT_I_REKEY_SENT:
			case RHP_IKESA_STAT_DEAD:
			// IKEv1
			case RHP_IKESA_STAT_V1_ESTABLISHED:
			case RHP_IKESA_STAT_V1_REKEYING:
			case RHP_IKESA_STAT_V1_DELETE:
			case RHP_IKESA_STAT_V1_DELETE_WAIT:
			case RHP_IKESA_STAT_V1_DEAD:

				break;

			default:

			  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_GET_PEERS_ENUM_CB_IGNORED_PEER_STATUS,"xx",vpn,ikesa);
			  ikesa->dump(ikesa);

				RHP_UNLOCK(&(vpn->lock));
				return 0;
			}
		}
	}


	RHP_LOCK(&(rlm->lock));

	{
		n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"peer");
		if(n < 0) {
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;

		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"index","%d",enum_ctx->idx++);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;

		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"vpn_realm_id","%lu",vpn->vpn_realm_id);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;

		if( rlm->name ){

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"vpn_realm_name","%s",rlm->name);
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;
		}

		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"vpn_unique_id",
				"0x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
				vpn->unique_id[0],vpn->unique_id[1],vpn->unique_id[2],vpn->unique_id[3],vpn->unique_id[4],vpn->unique_id[5],vpn->unique_id[6],vpn->unique_id[7],
				vpn->unique_id[8],vpn->unique_id[9],vpn->unique_id[10],vpn->unique_id[11],vpn->unique_id[12],vpn->unique_id[13],vpn->unique_id[14],vpn->unique_id[15]);

		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;

		{
			char *id_type,*id_str;

			err = rhp_ikev2_id_to_string(&(vpn->peer_id),&id_type,&id_str);
			if( err ){
				goto error;
			}

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"peerid_type","%s",id_type);
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				_rhp_free(id_type);
				_rhp_free(id_str);
				goto error;
			}
			*n2 += n;

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"peerid","%s",id_str);
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				_rhp_free(id_type);
				_rhp_free(id_str);
				goto error;
			}
			*n2 += n;

			_rhp_free(id_type);
			_rhp_free(id_str);


			if( vpn->peer_id.alt_id ){

				err = rhp_ikev2_id_to_string(vpn->peer_id.alt_id,&id_type,&id_str);
				if( err ){
					goto error;
				}

				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"alt_peerid_type","%s",id_type);
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					_rhp_free(id_type);
					_rhp_free(id_str);
					goto error;
				}
				*n2 += n;

				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"alt_peerid","%s",id_str);
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					_rhp_free(id_type);
					_rhp_free(id_str);
					goto error;
				}
				*n2 += n;

				_rhp_free(id_type);
				_rhp_free(id_str);
			}
		}

		if( vpn->eap.role == RHP_EAP_AUTHENTICATOR || vpn->eap.role == RHP_EAP_SUPPLICANT ){

			if( !rhp_eap_id_is_null(&(vpn->eap.peer_id))){

				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"eap_peer_identity","%s",vpn->eap.peer_id.identity);
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error;
				}
				*n2 += n;
			}
		}


		{
			n = 0;
			if( vpn->peer_addr.addr_family == AF_INET ){

				u32 ip = vpn->peer_addr.addr.v4;

				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
						(xmlChar*)"peer_addr_v4","%d.%d.%d.%d",
						((u8*)&ip)[0],((u8*)&ip)[1],((u8*)&ip)[2],((u8*)&ip)[3]);
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error;
				}
				*n2 += n;

				ip = vpn->local.if_info.addr.v4;

				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
						(xmlChar*)"my_addr_v4","%d.%d.%d.%d",
						((u8*)&ip)[0],((u8*)&ip)[1],((u8*)&ip)[2],((u8*)&ip)[3]);
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error;
				}
				*n2 += n;

			}else	if( vpn->peer_addr.addr_family == AF_INET6 ){

				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
						(xmlChar*)"peer_addr_v6","%s",
						rhp_ipv6_string(vpn->peer_addr.addr.v6));
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error;
				}
				*n2 += n;

				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
						(xmlChar*)"my_addr_v6","%s",
						rhp_ipv6_string(vpn->local.if_info.addr.v6));
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error;
				}
				*n2 += n;
			}

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
					(xmlChar*)"my_if_name","%s",vpn->local.if_info.if_name);
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;
		}


		{
			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
					(xmlChar*)"exec_mobike","%d",vpn->exec_mobike);
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;

			if( vpn->exec_mobike ){

				if( vpn->origin_side == RHP_IKE_INITIATOR ){

					n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
							(xmlChar*)"rt_ck_pending","%s",
							(vpn->mobike.init.rt_ck_pending ? "1" : "0"));
					if(n < 0){
						err = -ENOMEM;
						RHP_BUG("");
						goto error;
					}
					*n2 += n;

					n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
							(xmlChar*)"rt_ck_waiting","%s",
							(vpn->mobike.init.rt_ck_waiting ? "1" : "0"));
					if(n < 0){
						err = -ENOMEM;
						RHP_BUG("");
						goto error;
					}
					*n2 += n;

				}else{

					// RHP_IKE_RESPONDER

					n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
							(xmlChar*)"mobike_keepalive_pending","%d",
							vpn->mobike.resp.keepalive_pending);
					if(n < 0){
						err = -ENOMEM;
						RHP_BUG("");
						goto error;
					}
					*n2 += n;
				}
			}
		}

		if( vpn->ikesa_num ){

			rhp_ikesa* ikesa = vpn->ikesa_list_head;

			{
				switch( ikesa->state ){
				case RHP_IKESA_STAT_DEFAULT:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"ikesa_state",(xmlChar*)"default");
					break;
				case RHP_IKESA_STAT_I_IKE_SA_INIT_SENT:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"ikesa_state",(xmlChar*)"i_ike_sa_init_sent");
					break;
				case RHP_IKESA_STAT_I_AUTH_SENT:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"ikesa_state",(xmlChar*)"i_auth_sent");
					break;
				case RHP_IKESA_STAT_R_IKE_SA_INIT_SENT:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"ikesa_state",(xmlChar*)"r_ike_sa_init_sent");
					break;
				case RHP_IKESA_STAT_ESTABLISHED:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"ikesa_state",(xmlChar*)"established");
					break;
				case RHP_IKESA_STAT_REKEYING:
					if( ikesa->side == RHP_IKE_RESPONDER && rlm->ikesa.resp_not_rekeying ){
						n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"ikesa_state",(xmlChar*)"established");
					}else{
						n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"ikesa_state",(xmlChar*)"rekeying");
					}
					break;
				case RHP_IKESA_STAT_DELETE:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"ikesa_state",(xmlChar*)"delete");
					break;
				case RHP_IKESA_STAT_DELETE_WAIT:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"ikesa_state",(xmlChar*)"delete_wait");
					break;
				case RHP_IKESA_STAT_I_REKEY_SENT:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"ikesa_state",(xmlChar*)"i_rekey_sent");
					break;
				case RHP_IKESA_STAT_DEAD:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"ikesa_state",(xmlChar*)"dead");
					break;

				case RHP_IKESA_STAT_V1_MAIN_1ST_SENT_I:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"ikesa_state",(xmlChar*)"i_1st_sent");
					break;
				case RHP_IKESA_STAT_V1_MAIN_3RD_SENT_I:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"ikesa_state",(xmlChar*)"i_3rd_sent");
					break;
				case RHP_IKESA_STAT_V1_MAIN_5TH_SENT_I:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"ikesa_state",(xmlChar*)"i_5th_sent");
					break;
				case RHP_IKESA_STAT_V1_MAIN_2ND_SENT_R:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"ikesa_state",(xmlChar*)"r_2nd_sent");
					break;
				case RHP_IKESA_STAT_V1_MAIN_4TH_SENT_R:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"ikesa_state",(xmlChar*)"r_4th_sent");
					break;
				case RHP_IKESA_STAT_V1_AGG_1ST_SENT_I:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"ikesa_state",(xmlChar*)"i_1st_sent");
					break;
				case RHP_IKESA_STAT_V1_AGG_WAIT_COMMIT_I:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"ikesa_state",(xmlChar*)"i_commit_wait");
					break;
				case RHP_IKESA_STAT_V1_AGG_2ND_SENT_R:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"ikesa_state",(xmlChar*)"r_2nd_sent");
					break;
				case RHP_IKESA_STAT_V1_ESTABLISHED:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"ikesa_state",(xmlChar*)"established");
					break;
				case RHP_IKESA_STAT_V1_REKEYING:
					if( ikesa->side == RHP_IKE_RESPONDER && vpn->rlm->ikesa.resp_not_rekeying ){
	 					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"ikesa_state",(xmlChar*)"established");
	 				}else{
	 					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"ikesa_state",(xmlChar*)"rekeying");
	 				}
					break;
				case RHP_IKESA_STAT_V1_DELETE:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"ikesa_state",(xmlChar*)"delete");
					break;
				case RHP_IKESA_STAT_V1_DELETE_WAIT:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"ikesa_state",(xmlChar*)"delete_wait");
					break;
				case RHP_IKESA_STAT_V1_DEAD:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"ikesa_state",(xmlChar*)"dead");
					break;

				default:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"ikesa_state",(xmlChar*)"unknown");
					break;
				}

				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error;
				}
				*n2 += n;
			}
		}

		if( vpn->childsa_num ){

			rhp_childsa* childsa = vpn->childsa_list_head;

			{
				switch( childsa->state ){
				case RHP_CHILDSA_STAT_DEFAULT:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"childsa_state",(xmlChar*)"default");
					break;
				case RHP_CHILDSA_STAT_LARVAL:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"childsa_state",(xmlChar*)"negotiating");
					break;
				case RHP_CHILDSA_STAT_MATURE:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"childsa_state",(xmlChar*)"established");
					break;
				case RHP_CHILDSA_STAT_REKEYING:
					if( childsa->side == RHP_IKE_RESPONDER && rlm->childsa.resp_not_rekeying ){
						n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"childsa_state",(xmlChar*)"established");
					}else{
						n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"childsa_state",(xmlChar*)"rekeying");
					}
					break;
				case RHP_CHILDSA_STAT_DELETE:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"childsa_state",(xmlChar*)"delete");
					break;
				case RHP_CHILDSA_STAT_DELETE_WAIT:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"childsa_state",(xmlChar*)"delete_wait");
					break;
				case RHP_CHILDSA_STAT_DEAD:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"childsa_state",(xmlChar*)"dead");
					break;

				case RHP_IPSECSA_STAT_V1_1ST_SENT_I:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"childsa_state",(xmlChar*)"i_1st_sent");
					break;
				case RHP_IPSECSA_STAT_V1_WAIT_COMMIT_I:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"childsa_state",(xmlChar*)"i_commit_wait");
					break;
				case RHP_IPSECSA_STAT_V1_2ND_SENT_R:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"childsa_state",(xmlChar*)"r_2nd_sent");
					break;
				case RHP_IPSECSA_STAT_V1_MATURE:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"childsa_state",(xmlChar*)"established");
					break;
				case RHP_IPSECSA_STAT_V1_REKEYING:
					if( childsa->side == RHP_IKE_RESPONDER && vpn->rlm->childsa.resp_not_rekeying ){
						n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"childsa_state",(xmlChar*)"established");
					}else{
						n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"childsa_state",(xmlChar*)"rekeying");
					}
					break;
				case RHP_IPSECSA_STAT_V1_DELETE:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"childsa_state",(xmlChar*)"delete");
					break;
				case RHP_IPSECSA_STAT_V1_DELETE_WAIT:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"childsa_state",(xmlChar*)"delete_wait");
					break;
				case RHP_IPSECSA_STAT_V1_DEAD:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"childsa_state",(xmlChar*)"dead");
					break;

				default:
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"childsa_state",(xmlChar*)"unknown");
					break;
				}

				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error;
				}
				*n2 += n;
			}
		}

		{
			rhp_ip_addr_list* peer_addr = vpn->internal_net_info.peer_addrs;

			while( peer_addr ){

				n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"internal_peer_addr");
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error;
				}
				*n2 += n;

				if( peer_addr->ip_addr.addr_family == AF_INET ){

					u32 ip = peer_addr->ip_addr.addr.v4;

					n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
							(xmlChar*)"address_v4","%d.%d.%d.%d",
							((u8*)&ip)[0],((u8*)&ip)[1],((u8*)&ip)[2],((u8*)&ip)[3]);

				}else if( peer_addr->ip_addr.addr_family == AF_INET6 ){

					n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
							(xmlChar*)"address_v6","%s",
							rhp_ipv6_string(peer_addr->ip_addr.addr.v6));

				}else{
					RHP_BUG("%d",peer_addr->ip_addr.addr_family);
					goto next_peer_addr;
				}

				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error;
				}
				*n2 += n;

				n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error;
				}
				*n2 += n;

next_peer_addr:
				peer_addr = peer_addr->next;
			}
		}


		if( rlm->internal_ifc->ifc ){

			rhp_ifc_entry* ifc = rlm->internal_ifc->ifc;
			rhp_ip_addr_list* addr_lst;
			rhp_ifc_addr* ifc_addr;

			RHP_LOCK(&(ifc->lock));

			addr_lst = rlm->internal_ifc->addrs;
			while( addr_lst ){

				n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"internal_if_addr");
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					RHP_UNLOCK(&(ifc->lock));
					goto error;
				}
				*n2 += n;

				if( addr_lst->ip_addr.addr_family == AF_INET ){

					u32 ip = addr_lst->ip_addr.addr.v4;

					n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"address_v4","%d.%d.%d.%d/%d",
							((u8*)&ip)[0],((u8*)&ip)[1],((u8*)&ip)[2],((u8*)&ip)[3],addr_lst->ip_addr.prefixlen);
					if(n < 0){
						err = -ENOMEM;
						RHP_BUG("");
						RHP_UNLOCK(&(ifc->lock));
						goto error;
					}
					*n2 += n;

				}else	if( addr_lst->ip_addr.addr_family == AF_INET6 ){

					n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"address_v6",
							"%s/%d",
							rhp_ipv6_string(addr_lst->ip_addr.addr.v6),
							addr_lst->ip_addr.prefixlen);
					if(n < 0){
						err = -ENOMEM;
						RHP_BUG("");
						RHP_UNLOCK(&(ifc->lock));
						goto error;
					}
					*n2 += n;
				}

				n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					RHP_UNLOCK(&(ifc->lock));
					goto error;
				}
				*n2 += n;


				addr_lst = addr_lst->next;
			}


			ifc_addr = ifc->ifc_addrs;
			while( ifc_addr ){

				n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,
						(xmlChar*)"internal_if_addr_ifc");
				if(n < 0) {
					err = -ENOMEM;
					RHP_BUG("");
					RHP_UNLOCK(&(ifc->lock));
					goto error;
				}
				*n2 += n;

				if( ifc_addr->addr.addr_family == AF_INET ){

					u32 ip = ifc_addr->addr.addr.v4;

					n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
							(xmlChar*)"address_v4","%d.%d.%d.%d/%d",
							((u8*)&ip)[0],((u8*)&ip)[1],((u8*)&ip)[2],((u8*)&ip)[3],
							ifc_addr->addr.prefixlen);
					if(n < 0){
						err = -ENOMEM;
						RHP_BUG("");
						RHP_UNLOCK(&(ifc->lock));
						goto error;
					}
					*n2 += n;

				}else	if( ifc_addr->addr.addr_family == AF_INET6 ){

					n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
							(xmlChar*)"address_v6",
							"%s/%d",
							rhp_ipv6_string(ifc_addr->addr.addr.v6),
							ifc_addr->addr.prefixlen);

					if(n < 0){
						err = -ENOMEM;
						RHP_BUG("");
						RHP_UNLOCK(&(ifc->lock));
						goto error;
					}
					*n2 += n;
				}

				n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
				if(n < 0) {
					err = -ENOMEM;
					RHP_BUG("");
					RHP_UNLOCK(&(ifc->lock));
					goto error;
				}
				*n2 += n;


				ifc_addr = ifc_addr->lst_next;
			}

			RHP_UNLOCK(&(ifc->lock));
		}

		n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
		if(n < 0) {
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;
	}

	RHP_UNLOCK(&(rlm->lock));

	RHP_UNLOCK(&(vpn->lock));

	return 0;

error:
	RHP_UNLOCK(&(rlm->lock));

	RHP_UNLOCK(&(vpn->lock));
	return err;
}

struct _rhp_ui_http_get_peers_sl_ctx {
	unsigned long rlm_id;
  int ignore_resp_negotiating;
};
typedef struct _rhp_ui_http_get_peers_sl_ctx	rhp_ui_http_get_peers_sl_ctx;

static int _rhp_ui_http_vpn_get_peers_serialize(rhp_http_bus_session* http_bus_sess,void* ctx,void* writer,int idx)
{
  int err = -EINVAL;
  int n = 0;
  int n2 = 0;
  rhp_ui_http_get_peers_sl_ctx* sl_ctx = (rhp_ui_http_get_peers_sl_ctx*)ctx;
  unsigned long rlm_id = sl_ctx->rlm_id;
  int ignore_resp_negotiating = sl_ctx->ignore_resp_negotiating;
  rhp_ui_http_enum_ctx enum_ctx;

  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_GET_PEERS_SERIALIZE,"xuxd",http_bus_sess,rlm_id,writer,idx);

	n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"rhp_http_bus_record");
	if(n < 0) {
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"index","%d",idx);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"service",(xmlChar*)"ui_http_vpn");
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"action",(xmlChar*)"status_vpn_peers");
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"session_id","%llu",http_bus_sess->session_id);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	{
		enum_ctx.idx = 0;
		enum_ctx.writer = writer;
		enum_ctx.n2 = &n2;
		enum_ctx.rlm_id = rlm_id;
		enum_ctx.ignore_resp_negotiating = ignore_resp_negotiating;

		err = rhp_vpn_enum(rlm_id,_rhp_ui_http_vpn_get_peers_enum_cb,&enum_ctx);
		if( err ){
			goto error;
		}
	}


	n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
	if(n < 0) {
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_GET_PEERS_SERIALIZE_RTRN,"xd",http_bus_sess,n2);
  return n2;

error:
  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_GET_PEERS_SERIALIZE_ERR,"xE",http_bus_sess,err);
  return err;
}

static int _rhp_ui_http_vpn_get_peers(xmlDocPtr doc,xmlNodePtr node,rhp_http_conn* http_conn,
		rhp_http_bus_session* http_bus_sess,rhp_http_request* http_req,void* ctx)
{
  int err = -EINVAL;
  char* vpn_realm_str = NULL;
  unsigned long rlm_id;
  char* endp;
  rhp_ui_http_get_peers_sl_ctx sl_ctx;
  int ignore_resp_negotiating = 0;
	int ret_len;

  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_GET_PEERS,"xxxxxx",doc,node,http_conn,http_bus_sess,http_req,ctx);

  memset(&sl_ctx,0,sizeof(rhp_ui_http_get_peers_sl_ctx));

  if( doc == NULL || node == NULL ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_GET_PEERS_NO_DOC_NODE,"xxx",http_conn,http_bus_sess,http_req);
    return -EINVAL;
  }

  vpn_realm_str = (char*)rhp_xml_get_prop(node,(const xmlChar*)"vpn_realm");
  if( vpn_realm_str ){

		rlm_id = strtoul((char*)vpn_realm_str,&endp,0);
		if( (rlm_id == ULONG_MAX && errno == ERANGE) || *endp != '\0' ){
			err = -ENOENT;
			RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_GET_PEERS_NO_VPN_REALM_2,"xxxs",http_conn,http_bus_sess,http_req,vpn_realm_str);
			goto error;
		}

  }else{

  	if( http_conn->user_realm_id == 0 ){
  		err = RHP_STATUS_INVALID_MSG;
  		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_GET_PEERS_NO_VPN_REALM,"xxx",http_conn,http_bus_sess,http_req);
  		goto error;
  	}

  	rlm_id = http_conn->user_realm_id;
  }

  if( _rhp_ui_http_permitted(http_conn,http_bus_sess,rlm_id) ){
			err = -EPERM;
			RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_GET_PEERS_NOT_PERMITTED,"xxxuu",http_conn,http_bus_sess,http_req,http_conn->user_realm_id,http_bus_sess->user_realm_id);
			goto error;
	}

  if( rlm_id == 0 ){
  	err = -ENOENT;
  	RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_GET_PEERS_NO_VPN_REALM_ZERO,"xxxs",http_conn,http_bus_sess,http_req,vpn_realm_str);
  	goto error;
  }

  {
  	rhp_vpn_realm* rlm = rhp_realm_get(rlm_id);
  	if( rlm == NULL ){
  		err = -ENOENT;
  		goto error;
  	}
  	rhp_realm_unhold(rlm);
  }


  rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"ignore_resp_negotiating"),
  		RHP_XML_DT_INT,&ignore_resp_negotiating,&ret_len,NULL,0);


  sl_ctx.rlm_id = rlm_id;
  sl_ctx.ignore_resp_negotiating = ignore_resp_negotiating;

  err = rhp_http_bus_send_response(http_conn,http_bus_sess,_rhp_ui_http_vpn_get_peers_serialize,(void*)&sl_ctx);
  if( err ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_GET_PEERS_TX_RESP_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
    goto error;
  }

  if( vpn_realm_str ){
  	_rhp_free(vpn_realm_str);
  }
  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_GET_PEERS_RTRN,"xxxs",http_conn,http_bus_sess,http_req,vpn_realm_str);
  return RHP_STATUS_CLOSE_HTTP_CONN;

error:
	if( vpn_realm_str ){
		_rhp_free(vpn_realm_str);
	}
  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_GET_PEERS_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  return err;
}


static int _rhp_ui_http_vpn_get_bridge_info_enum_cb(rhp_bridge_cache* br_c,void* ctx)
{
	int err = -EINVAL;
	int n;
	rhp_ui_http_enum_ctx* enum_ctx = (rhp_ui_http_enum_ctx*)ctx;
	void* writer = enum_ctx->writer;
	int* n2 = enum_ctx->n2;


	{
		n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"bridge");
		if(n < 0) {
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;

		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"index","%d",enum_ctx->idx++);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;

		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"vpn_realm_id","%lu",br_c->vpn_realm_id);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;

		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"dest_mac",
				"%02x:%02x:%02x:%02x:%02x:%02x",
				br_c->dest_mac[0],br_c->dest_mac[1],br_c->dest_mac[2],br_c->dest_mac[3],br_c->dest_mac[4],br_c->dest_mac[5]);

		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;

		{
			if( br_c->side == RHP_BRIDGE_SIDE_TUNTAP ){

				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"side","%s","protected");
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error;
				}
				*n2 += n;

			}else if( br_c->side == RHP_BRIDGE_SIDE_VPN ){

				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"side","%s","vpn");
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error;
				}
				*n2 += n;
			}
		}

		if( br_c->static_cache ){

			if( br_c->static_cache == RHP_BRIDGE_SCACHE_IKEV2_EXCHG ){
				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"static_cache","%s","exchanged");
			}else if( br_c->static_cache == RHP_BRIDGE_SCACHE_DUMMY ){
				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"static_cache","%s","pseudo_mac");
			}else if( br_c->static_cache == RHP_BRIDGE_SCACHE_V6_DUMMY_LL_ADDR ){
				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"static_cache","%s","v6_aux_link_local");
			}else if( br_c->static_cache == RHP_BRIDGE_SCACHE_IKEV2_CFG ){
				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"static_cache","%s","ikev2_cfg");
			}else{
				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"static_cache","%s","unknown");
			}
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;
		}

		{
			time_t elasp = _rhp_get_time(NULL) - br_c->last_checked_time;

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"time_elapsed","%ld",elasp);
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;
		}

		if( br_c->vpn_ref ){

			char *id_type,*id_str;
			rhp_vpn* vpn = RHP_VPN_REF(br_c->vpn_ref);

			err = rhp_ikev2_id_to_string(&(vpn->peer_id),&id_type,&id_str);
			if( err ){
				goto error;
			}

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"peerid_type","%s",id_type);
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				_rhp_free(id_type);
				_rhp_free(id_str);
				goto error;
			}
			*n2 += n;

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"peerid","%s",id_str);
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				_rhp_free(id_type);
				_rhp_free(id_str);
				goto error;
			}
			*n2 += n;

			if( !rhp_eap_id_is_null(&(vpn->eap.peer_id)) ){

				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"eap_peer_id","%s",vpn->eap.peer_id.identity);
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					_rhp_free(id_type);
					_rhp_free(id_str);
					goto error;
				}
				*n2 += n;
			}

			_rhp_free(id_type);
			_rhp_free(id_str);
		}


		n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
		if(n < 0) {
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;
	}

	return 0;

error:
	return err;
}

static int _rhp_ui_http_vpn_get_bridge_info_serialize(rhp_http_bus_session* http_bus_sess,void* ctx,void* writer,int idx)
{
  int err = -EINVAL;
  int n = 0;
  int n2 = 0;
  unsigned long rlm_id = (unsigned long)ctx;
  rhp_ui_http_enum_ctx enum_ctx;

  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_GET_BRIDGE_INFO_SERIALIZE,"xuxd",http_bus_sess,rlm_id,writer,idx);

	n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"rhp_http_bus_record");
	if(n < 0) {
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"index","%d",idx);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"service",(xmlChar*)"ui_http_vpn");
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"action",(xmlChar*)"status_bridge");
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"session_id","%llu",http_bus_sess->session_id);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	{
		enum_ctx.idx = 0;
		enum_ctx.writer = writer;
		enum_ctx.n2 = &n2;
		enum_ctx.rlm_id = rlm_id;

		err = rhp_bridge_enum(rlm_id,_rhp_ui_http_vpn_get_bridge_info_enum_cb,&enum_ctx);
		if( err ){
			RHP_BUG("");
			goto error;
		}
	}


	n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
	if(n < 0) {
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_GET_BRIDGE_INFO_SERIALIZE_RTRN,"xd",http_bus_sess,n2);
  return n2;

error:
  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_GET_BRIDGE_INFO_SERIALIZE_ERR,"xE",http_bus_sess,err);
  return err;
}

static int _rhp_ui_http_vpn_get_bridge_info(xmlDocPtr doc,xmlNodePtr node,rhp_http_conn* http_conn,
		rhp_http_bus_session* http_bus_sess,rhp_http_request* http_req,void* ctx)
{
  int err = -EINVAL;
  char* vpn_realm_str = NULL;
  unsigned long rlm_id;
  char* endp;

  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_GET_BRIDGE_INFO,"xxxxxx",doc,node,http_conn,http_bus_sess,http_req,ctx);

  if( doc == NULL || node == NULL ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_GET_BRIDGE_INFO_NO_DOC_NODE,"xxx",http_conn,http_bus_sess,http_req);
    return -EINVAL;
  }

  vpn_realm_str = (char*)rhp_xml_get_prop(node,(const xmlChar*)"vpn_realm");
  if( vpn_realm_str == NULL ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_GET_BRIDGE_INFO_NO_VPN_REALM,"xxx",http_conn,http_bus_sess,http_req);
    goto error;
  }

  rlm_id = strtoul((char*)vpn_realm_str,&endp,0);
  if( (rlm_id == ULONG_MAX && errno == ERANGE) || *endp != '\0' ){
  	err = -ENOENT;
  	RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_GET_BRIDGE_INFO_NO_VPN_REALM_2,"xxxs",http_conn,http_bus_sess,http_req,vpn_realm_str);
  	goto error;
  }

  if( _rhp_ui_http_permitted(http_conn,http_bus_sess,rlm_id) ){
			err = -EPERM;
			RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_GET_BRIDGE_INFO_NOT_PERMITTED,"xxxuu",http_conn,http_bus_sess,http_req,http_conn->user_realm_id,http_bus_sess->user_realm_id);
			goto error;
	}

  if( rlm_id == 0 ){
  	err = -ENOENT;
  	RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_GET_BRIDGE_INFO_NO_VPN_REALM_ZERO,"xxxs",http_conn,http_bus_sess,http_req,vpn_realm_str);
  	goto error;
  }

  {
  	rhp_vpn_realm* rlm = rhp_realm_get(rlm_id);
  	if( rlm == NULL ){
  		err = -ENOENT;
  		goto error;
  	}
  	rhp_realm_unhold(rlm);
  }

  err = rhp_http_bus_send_response(http_conn,http_bus_sess,_rhp_ui_http_vpn_get_bridge_info_serialize,(void*)rlm_id);
  if( err ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_GET_BRIDGE_INFO_TX_RESP_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
    goto error;
  }

  if( vpn_realm_str ){
  	_rhp_free(vpn_realm_str);
  }
  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_GET_BRIDGE_INFO_RTRN,"xxxs",http_conn,http_bus_sess,http_req,vpn_realm_str);
  return RHP_STATUS_CLOSE_HTTP_CONN;

error:
	if( vpn_realm_str ){
		_rhp_free(vpn_realm_str);
	}
  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_GET_BRIDGE_INFO_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  return err;
}


static int _rhp_ui_http_vpn_get_bridge_neigh_info_enum_cb0(
		rhp_bridge_neigh_cache* br_c_n,void* ctx)
{
	int err = -EINVAL;
	int n;
	rhp_ui_http_enum_ctx* enum_ctx = (rhp_ui_http_enum_ctx*)ctx;
	void* writer = enum_ctx->writer;
	int* n2 = enum_ctx->n2;


	{
		if( br_c_n->addr_family == AF_INET ){
			n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"arp");
		}else if( br_c_n->addr_family == AF_INET6 ){
			n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"ipv6_nd");
		}else{
			err = -EINVAL;
			RHP_BUG("");
			goto error;
		}
		if(n < 0) {
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;

		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"index","%d",enum_ctx->idx++);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;

		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"vpn_realm_id","%lu",br_c_n->vpn_realm_id);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;

		if( br_c_n->addr_family == AF_INET ){

			u32 ip = br_c_n->target_ip.addr.v4;

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"dest_addr","%d.%d.%d.%d",
					((u8*)&ip)[0],((u8*)&ip)[1],((u8*)&ip)[2],((u8*)&ip)[3]);

		}else if( br_c_n->addr_family == AF_INET6 ){

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"dest_addr","%s",
					rhp_ipv6_string(br_c_n->target_ip.addr.v6));
		}
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;

		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"dest_mac",
				"%02x:%02x:%02x:%02x:%02x:%02x",
				br_c_n->target_mac[0],br_c_n->target_mac[1],br_c_n->target_mac[2],
				br_c_n->target_mac[3],br_c_n->target_mac[4],br_c_n->target_mac[5]);

		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;

		{
			if( br_c_n->side == RHP_BRIDGE_SIDE_TUNTAP ){

				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"side","%s","protected");
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error;
				}
				*n2 += n;

			}else if( br_c_n->side == RHP_BRIDGE_SIDE_VPN ){

				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"side","%s","vpn");
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error;
				}
				*n2 += n;
			}
		}

		if( br_c_n->static_cache ){

			if( br_c_n->static_cache == RHP_BRIDGE_SCACHE_IKEV2_EXCHG ){
				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"static_cache","%s","exchanged");
			}else if( br_c_n->static_cache == RHP_BRIDGE_SCACHE_DUMMY ){
				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"static_cache","%s","pseudo_mac");
			}else if( br_c_n->static_cache == RHP_BRIDGE_SCACHE_V6_DUMMY_LL_ADDR ){
				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"static_cache","%s","v6_aux_link_local");
			}else if( br_c_n->static_cache == RHP_BRIDGE_SCACHE_IKEV2_CFG ){
				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"static_cache","%s","ikev2_cfg");
			}else{
				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"static_cache","%s","unknown");
			}
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;
		}

		{
			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"stale","%d",br_c_n->stale);
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;
		}

		{
			time_t elasp = _rhp_get_time() - br_c_n->last_checked_time;

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"time_elapsed","%ld",elasp);
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;
		}

		if( br_c_n->vpn_ref ){

			char *id_type,*id_str;
			rhp_vpn* vpn = RHP_VPN_REF(br_c_n->vpn_ref);

			err = rhp_ikev2_id_to_string(&(vpn->peer_id),&id_type,&id_str);
			if( err ){
				goto error;
			}

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"peerid_type","%s",id_type);
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				_rhp_free(id_type);
				_rhp_free(id_str);
				goto error;
			}
			*n2 += n;

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"peerid","%s",id_str);
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				_rhp_free(id_type);
				_rhp_free(id_str);
				goto error;
			}
			*n2 += n;

			if( !rhp_eap_id_is_null(&(vpn->eap.peer_id))){

				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"eap_peer_id","%s",vpn->eap.peer_id.identity);
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					_rhp_free(id_type);
					_rhp_free(id_str);
					goto error;
				}
				*n2 += n;
			}

			_rhp_free(id_type);
			_rhp_free(id_str);
		}


		n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
		if(n < 0) {
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;
	}

	return 0;

error:
	return err;
}

static int _rhp_ui_http_vpn_get_bridge_neigh_info_enum_cb1(
		rhp_neigh_rslv_ctx* br_c_n,void* ctx)
{
	int err = -EINVAL;
	int n;
	rhp_ui_http_enum_ctx* enum_ctx = (rhp_ui_http_enum_ctx*)ctx;
	void* writer = enum_ctx->writer;
	int* n2 = enum_ctx->n2;

	{
		if( br_c_n->addr_family == AF_INET ){
			n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"arp_resolving");
		}else if( br_c_n->addr_family == AF_INET6 ){
			n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"ipv6_nd_resolving");
		}else{
			err = -EINVAL;
			RHP_BUG("");
			goto error;
		}
		if(n < 0) {
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;

		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"index","%d",enum_ctx->idx++);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;

		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"vpn_realm_id","%lu",br_c_n->vpn_realm_id);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;

		{
			if( br_c_n->addr_family == AF_INET ){

				u32 ip = br_c_n->target_ip.addr.v4;

				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"dest_addr","%d.%d.%d.%d",
						((u8*)&ip)[0],((u8*)&ip)[1],((u8*)&ip)[2],((u8*)&ip)[3]);
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error;
				}
				*n2 += n;


				ip = br_c_n->sender_ip.addr.v4;

				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"src_addr","%d.%d.%d.%d",
						((u8*)&ip)[0],((u8*)&ip)[1],((u8*)&ip)[2],((u8*)&ip)[3]);
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error;
				}
				*n2 += n;

			}else if( br_c_n->addr_family == AF_INET6 ){

				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"dest_addr","%s",
						rhp_ipv6_string(br_c_n->target_ip.addr.v6));
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error;
				}
				*n2 += n;


				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"src_addr","%s",
						rhp_ipv6_string(br_c_n->sender_ip.addr.v6));
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error;
				}
				*n2 += n;
			}


			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"src_mac",
					"%02x:%02x:%02x:%02x:%02x:%02x",
					br_c_n->sender_mac[0],br_c_n->sender_mac[1],br_c_n->sender_mac[2],
					br_c_n->sender_mac[3],br_c_n->sender_mac[4],br_c_n->sender_mac[5]);
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;
		}

		{
			time_t elasp = _rhp_get_time() - br_c_n->created_time;

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"time_elapsed","%ld",elasp);
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;
		}

		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"retries","%d",br_c_n->retries);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;

		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"pkt_q_num","%d",br_c_n->pkt_q_num);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;


		if( br_c_n->rx_vpn_ref ){

			char *id_type,*id_str;
			rhp_vpn* rx_vpn = RHP_VPN_REF(br_c_n->rx_vpn_ref);

			err = rhp_ikev2_id_to_string(&(rx_vpn->peer_id),&id_type,&id_str);
			if( err ){
				goto error;
			}

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"peerid_type","%s",id_type);
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				_rhp_free(id_type);
				_rhp_free(id_str);
				goto error;
			}
			*n2 += n;

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"peerid","%s",id_str);
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				_rhp_free(id_type);
				_rhp_free(id_str);
				goto error;
			}
			*n2 += n;

			_rhp_free(id_type);
			_rhp_free(id_str);

			if( !rhp_eap_id_is_null(&(rx_vpn->eap.peer_id)) ){

				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"eap_peer_id","%s",rx_vpn->eap.peer_id.identity);
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					_rhp_free(id_type);
					_rhp_free(id_str);
					goto error;
				}
				*n2 += n;
			}
		}


		n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
		if(n < 0) {
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;
	}

	return 0;

error:
	return err;
}

static int _rhp_ui_http_vpn_get_bridge_neigh_info_serialize_impl(
		rhp_http_bus_session* http_bus_sess,void* ctx,void* writer,int idx,int addr_family)
{
  int err = -EINVAL;
  int n = 0;
  int n2 = 0;
  unsigned long rlm_id = (unsigned long)ctx;
  rhp_ui_http_enum_ctx enum_ctx;

  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_GET_BRIDGE_NEIGH_INFO_SERIALIZE,"xuxdLd",http_bus_sess,rlm_id,writer,idx,"AF",addr_family);

	n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"rhp_http_bus_record");
	if(n < 0) {
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"index","%d",idx);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"service",(xmlChar*)"ui_http_vpn");
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"action",(xmlChar*)"status_neigh");
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"session_id","%llu",http_bus_sess->session_id);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;


	enum_ctx.idx = 0;
	enum_ctx.writer = writer;
	enum_ctx.n2 = &n2;
	enum_ctx.rlm_id = rlm_id;

	if( addr_family == AF_INET ){

		n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"ip_version",(xmlChar*)"ipv4");
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		n2 += n;

		err = rhp_bridge_arp_enum(rlm_id,
						_rhp_ui_http_vpn_get_bridge_neigh_info_enum_cb0,&enum_ctx,
						_rhp_ui_http_vpn_get_bridge_neigh_info_enum_cb1,&enum_ctx);

		if( err ){
			goto error;
		}

	}else if( addr_family == AF_INET6 ){

		n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"ip_version",(xmlChar*)"ipv6");
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		n2 += n;

		err = rhp_bridge_nd_enum(rlm_id,
						_rhp_ui_http_vpn_get_bridge_neigh_info_enum_cb0,&enum_ctx,
						_rhp_ui_http_vpn_get_bridge_neigh_info_enum_cb1,&enum_ctx);

		if( err ){
			goto error;
		}
	}


	n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
	if(n < 0) {
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_GET_BRIDGE_NEIGH_INFO_SERIALIZE_RTRN,"xd",http_bus_sess,n2);
  return n2;

error:
  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_GET_BRIDGE_NEIGH_INFO_SERIALIZE_ERR,"xE",http_bus_sess,err);
  return err;
}

static int _rhp_ui_http_vpn_get_bridge_neigh_info_serialize_v4(
		rhp_http_bus_session* http_bus_sess,void* ctx,void* writer,int idx)
{
	return _rhp_ui_http_vpn_get_bridge_neigh_info_serialize_impl(http_bus_sess,ctx,writer,idx,AF_INET);
}

static int _rhp_ui_http_vpn_get_bridge_neigh_info_serialize_v6(
		rhp_http_bus_session* http_bus_sess,void* ctx,void* writer,int idx)
{
	return _rhp_ui_http_vpn_get_bridge_neigh_info_serialize_impl(http_bus_sess,ctx,writer,idx,AF_INET6);
}

static int _rhp_ui_http_vpn_get_bridge_neigh_info(xmlDocPtr doc,xmlNodePtr node,rhp_http_conn* http_conn,
		rhp_http_bus_session* http_bus_sess,rhp_http_request* http_req,void* ctx)
{
  int err = -EINVAL;
  char* vpn_realm_str = NULL;
  unsigned long rlm_id;
  char* endp;
  char* ip_ver_str = NULL;

  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_GET_BRIDGE_NEIGH_INFO,"xxxxxx",doc,node,http_conn,http_bus_sess,http_req,ctx);

  if( doc == NULL || node == NULL ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_GET_BRIDGE_NEIGH_INFO_NO_DOC_NODE,"xxx",http_conn,http_bus_sess,http_req);
    return -EINVAL;
  }

  vpn_realm_str = (char*)rhp_xml_get_prop(node,(const xmlChar*)"vpn_realm");
  if( vpn_realm_str == NULL ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_GET_BRIDGE_NEIGH_INFO_NO_VPN_REALM,"xxx",http_conn,http_bus_sess,http_req);
    goto error;
  }

	ip_ver_str = (char*)rhp_xml_get_prop(node,(const xmlChar*)"ip_version");
	if( ip_ver_str == NULL ){
   err = RHP_STATUS_INVALID_MSG;
   RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_GET_BRIDGE_NEIGH_INFO_NO_IP_VERSION,"xxx",http_conn,http_bus_sess,http_req);
   goto error;
	}

  rlm_id = strtoul((char*)vpn_realm_str,&endp,0);
  if( (rlm_id == ULONG_MAX && errno == ERANGE) || *endp != '\0' ){
  	err = -ENOENT;
  	RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_GET_BRIDGE_NEIGH_INFO_NO_VPN_REALM_2,"xxxs",http_conn,http_bus_sess,http_req,vpn_realm_str);
  	goto error;
  }

  if( _rhp_ui_http_permitted(http_conn,http_bus_sess,rlm_id) ){
			err = -EPERM;
			RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_GET_BRIDGE_NEIGH_INFO_NOT_PERMITTED,"xxxuu",http_conn,http_bus_sess,http_req,http_conn->user_realm_id,http_bus_sess->user_realm_id);
			goto error;
	}

  if( rlm_id == 0 ){
  	err = -ENOENT;
  	RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_GET_BRIDGE_NEIGH_INFO_NO_VPN_REALM_ZERO,"xxxs",http_conn,http_bus_sess,http_req,vpn_realm_str);
  	goto error;
  }

  {
  	rhp_vpn_realm* rlm = rhp_realm_get(rlm_id);
  	if( rlm == NULL ){
  		err = -ENOENT;
  		goto error;
  	}
  	rhp_realm_unhold(rlm);
  }

  if( !strcmp(ip_ver_str,"ipv4") ){

  	err = rhp_http_bus_send_response(http_conn,http_bus_sess,
  		_rhp_ui_http_vpn_get_bridge_neigh_info_serialize_v4,(void*)rlm_id);

  }else if( !strcmp(ip_ver_str,"ipv6") ){

  	err = rhp_http_bus_send_response(http_conn,http_bus_sess,
  		_rhp_ui_http_vpn_get_bridge_neigh_info_serialize_v6,(void*)rlm_id);

  }else{

		err = -ENOENT;
		goto error;
  }
  if( err ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_GET_BRIDGE_NEIGH_INFO_TX_RESP_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
    goto error;
  }

  if( vpn_realm_str ){
  	_rhp_free(vpn_realm_str);
  }

  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_GET_BRIDGE_NEIGH_INFO_RTRN,"xxxs",http_conn,http_bus_sess,http_req,vpn_realm_str);
  return RHP_STATUS_CLOSE_HTTP_CONN;

error:
	if( vpn_realm_str ){
		_rhp_free(vpn_realm_str);
	}
  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_GET_BRIDGE_NEIGH_INFO_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  return err;
}


static int _rhp_ui_http_vpn_get_address_pool_info_enum_cb(rhp_internal_address* intr_addr,void* ctx)
{
	int err = -EINVAL;
	int n;
	rhp_ui_http_enum_ctx* enum_ctx = (rhp_ui_http_enum_ctx*)ctx;
	void* writer = enum_ctx->writer;
	int* n2 = enum_ctx->n2;


	{
		n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"address_pool");
		if(n < 0) {
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;

		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"index","%d",enum_ctx->idx++);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;

		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"vpn_realm_id","%lu",intr_addr->vpn_realm_id);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;

		{
			if( intr_addr->assigned_addr_v4.addr_family == AF_INET ){

				u32 ip = intr_addr->assigned_addr_v4.addr.v4;

				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
						(xmlChar*)"assigned_addr_v4","%d.%d.%d.%d",
						((u8*)&ip)[0],((u8*)&ip)[1],((u8*)&ip)[2],((u8*)&ip)[3]);

				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error;
				}
				*n2 += n;
			}

			if( intr_addr->assigned_addr_v6.addr_family == AF_INET6 ){

				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
						(xmlChar*)"assigned_addr_v6","%s",
						rhp_ipv6_string(intr_addr->assigned_addr_v6.addr.v6));

				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error;
				}
				*n2 += n;
			}
		}


		{
			time_t expire = 0;

			if( intr_addr->expire ){
				expire = intr_addr->expire - _rhp_get_time();
			}

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"expire","%ld",expire);
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;
		}

		{
			char *id_type,*id_str;

			err = rhp_ikev2_id_to_string(&(intr_addr->peer_id),&id_type,&id_str);
			if( err ){
				goto error;
			}

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"peerid_type","%s",id_type);
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				_rhp_free(id_type);
				_rhp_free(id_str);
				goto error;
			}
			*n2 += n;

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"peerid","%s",id_str);
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				_rhp_free(id_type);
				_rhp_free(id_str);
				goto error;
			}
			*n2 += n;

			_rhp_free(id_type);
			_rhp_free(id_str);

			if( intr_addr->peer_id.alt_id ){

				err = rhp_ikev2_id_to_string(intr_addr->peer_id.alt_id,&id_type,&id_str);
				if( err ){
					goto error;
				}

				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"alt_peerid_type","%s",id_type);
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					_rhp_free(id_type);
					_rhp_free(id_str);
					goto error;
				}
				*n2 += n;

				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"alt_peerid","%s",id_str);
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					_rhp_free(id_type);
					_rhp_free(id_str);
					goto error;
				}
				*n2 += n;

				_rhp_free(id_type);
				_rhp_free(id_str);
			}
		}

		if( !rhp_eap_id_is_null(&(intr_addr->eap_peer_id)) ){

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"eap_peer_identity",
					"%s",intr_addr->eap_peer_id.identity);
			if(n < 0) {
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;
		}

		n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
		if(n < 0) {
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;
	}

	return 0;

error:
	return err;
}

static int _rhp_ui_http_vpn_get_address_pool_info_serialize(rhp_http_bus_session* http_bus_sess,void* ctx,void* writer,int idx)
{
  int err = -EINVAL;
  int n = 0;
  int n2 = 0;
  rhp_vpn_realm* rlm = (rhp_vpn_realm*)ctx;
  rhp_ui_http_enum_ctx enum_ctx;
  unsigned long rlm_id = rlm->id;


  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_GET_ADDRESS_POOL_INFO_SERIALIZE,"xxuxd",http_bus_sess,rlm,rlm_id,writer,idx);

	n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"rhp_http_bus_record");
	if(n < 0) {
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"index","%d",idx);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"service",(xmlChar*)"ui_http_vpn");
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"action",(xmlChar*)"status_address_pool");
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"session_id","%llu",http_bus_sess->session_id);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;


	{
		enum_ctx.idx = 0;
		enum_ctx.writer = writer;
		enum_ctx.n2 = &n2;
		enum_ctx.rlm_id = rlm_id;

		err = rhp_vpn_internal_address_enum(rlm_id,_rhp_ui_http_vpn_get_address_pool_info_enum_cb,&enum_ctx);
		if( err ){
			goto error;
		}
	}


	n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
	if(n < 0) {
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_GET_ADDRESS_POOL_INFO_SERIALIZE_RTRN,"xxd",http_bus_sess,rlm,n2);
  return n2;

error:
  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_GET_ADDRESS_POOL_INFO_SERIALIZE_ERR,"xxE",http_bus_sess,rlm,err);
  return err;
}

static int _rhp_ui_http_vpn_get_address_pool_info(xmlDocPtr doc,xmlNodePtr node,rhp_http_conn* http_conn,
		rhp_http_bus_session* http_bus_sess,rhp_http_request* http_req,void* ctx)
{
  int err = -EINVAL;
  char* vpn_realm_str = NULL;
  unsigned long rlm_id;
  char* endp;
  rhp_vpn_realm* rlm = NULL;

  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_GET_ADDRESS_POOL_INFO,"xxxxxx",doc,node,http_conn,http_bus_sess,http_req,ctx);

  if( doc == NULL || node == NULL ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_GET_ADDRESS_POOL_INFO_NO_DOC_NODE,"xxx",http_conn,http_bus_sess,http_req);
    return -EINVAL;
  }

  vpn_realm_str = (char*)rhp_xml_get_prop(node,(const xmlChar*)"vpn_realm");
  if( vpn_realm_str == NULL ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_GET_ADDRESS_POOL_INFO_NO_VPN_REALM,"xxx",http_conn,http_bus_sess,http_req);
    goto error;
  }

  rlm_id = strtoul((char*)vpn_realm_str,&endp,0);
  if( (rlm_id == ULONG_MAX && errno == ERANGE) || *endp != '\0' ){
  	err = -ENOENT;
  	RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_GET_ADDRESS_POOL_INFO_NO_VPN_REALM_2,"xxxs",http_conn,http_bus_sess,http_req,vpn_realm_str);
  	goto error;
  }

  if( _rhp_ui_http_permitted(http_conn,http_bus_sess,rlm_id) ){
			err = -EPERM;
			RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_GET_ADDRESS_POOL_INFO_NOT_PERMITTED,"xxxuu",http_conn,http_bus_sess,http_req,http_conn->user_realm_id,http_bus_sess->user_realm_id);
			goto error;
	}

  if( rlm_id == 0 ){
  	err = -ENOENT;
  	RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_GET_ADDRESS_POOL_INFO_NO_VPN_REALM_ZERO,"xxxs",http_conn,http_bus_sess,http_req,vpn_realm_str);
  	goto error;
  }

	rlm = rhp_realm_get(rlm_id);
	if( rlm == NULL ){
		err = -ENOENT;
		goto error;
	}

	RHP_LOCK(&(rlm->lock));

  err = rhp_http_bus_send_response(http_conn,http_bus_sess,_rhp_ui_http_vpn_get_address_pool_info_serialize,(void*)rlm);
  if( err ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_GET_ADDRESS_POOL_INFO_TX_RESP_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
    goto error;
  }

	RHP_UNLOCK(&(rlm->lock));
  rhp_realm_unhold(rlm);

  if( vpn_realm_str ){
  	_rhp_free(vpn_realm_str);
  }

  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_GET_ADDRESS_POOL_INFO_RTRN,"xxxs",http_conn,http_bus_sess,http_req,vpn_realm_str);
  return RHP_STATUS_CLOSE_HTTP_CONN;

error:
	if( rlm ){
		RHP_UNLOCK(&(rlm->lock));
	  rhp_realm_unhold(rlm);
	}
  if( vpn_realm_str ){
  	_rhp_free(vpn_realm_str);
  }
  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_GET_ADDRESS_POOL_INFO_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  return err;
}

int _rhp_ui_http_cfg_peers_enum_cb(rhp_vpn_realm* rlm,void* ctx)
{
	int err = -EINVAL;
	int n;
	rhp_ui_http_enum_ctx* enum_ctx = (rhp_ui_http_enum_ctx*)ctx;
	void* writer = enum_ctx->writer;
	int* n2 = enum_ctx->n2;
	rhp_cfg_peer* cfg_peer;

	RHP_LOCK(&(rlm->lock));

	n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"vpn_realm");
	if(n < 0) {
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	*n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"vpn_realm_id","%lu",rlm->id);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	*n2 += n;

	if( rlm->name ){

		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"vpn_realm_name","%s",rlm->name);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;
	}

	{
    int eap_sup_enabled = 0;
    rhp_eap_sup_info eap_sup_i;

    eap_sup_enabled = rhp_eap_sup_impl_is_enabled(rlm,&eap_sup_i);

		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"eap_supplicant_enabled","%d",eap_sup_enabled);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;

		if( eap_sup_enabled ){

			char* method_name = rhp_eap_sup_impl_method2str(eap_sup_i.eap_method);
			if( method_name == NULL ){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"eap_sup_method","%s",(xmlChar*)method_name);
			_rhp_free(method_name);
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"eap_sup_ask_for_usr_key","%d",eap_sup_i.ask_for_user_key);
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"eap_sup_usr_key_cache","%d",eap_sup_i.user_key_cache_enabled);
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;
		}
	}


	cfg_peer = rlm->peers;

	while( cfg_peer ){

		n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"peer");
		if(n < 0) {
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;

		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"index","%d",enum_ctx->idx++);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;

		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"vpn_realm_id","%lu",rlm->id);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;

		{
			char *id_type,*id_str;

			err = rhp_ikev2_id_to_string(&(cfg_peer->id),&id_type,&id_str);
			if( err ){
				goto error;
			}

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
					(xmlChar*)"peerid_type","%s",id_type);
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				_rhp_free(id_type);
				_rhp_free(id_str);
				goto error;
			}
			*n2 += n;

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
					(xmlChar*)"peerid","%s",id_str);
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				_rhp_free(id_type);
				_rhp_free(id_str);
				goto error;
			}
			*n2 += n;

			_rhp_free(id_type);
			_rhp_free(id_str);
		}

		{
			n = 0;
			if( cfg_peer->primary_addr.addr_family == AF_INET ){

				u32 ip = cfg_peer->primary_addr.addr.v4;

				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
						(xmlChar*)"peer_addr_v4","%d.%d.%d.%d",
						((u8*)&ip)[0],((u8*)&ip)[1],((u8*)&ip)[2],((u8*)&ip)[3]);

			}else if( cfg_peer->primary_addr.addr_family == AF_INET6 ){

				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
						(xmlChar*)"peer_addr_v6","%s",
						rhp_ipv6_string(cfg_peer->primary_addr.addr.v6));
			}
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;
		}

		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
				(xmlChar*)"is_access_point","%d",cfg_peer->is_access_point);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;


		n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
		if(n < 0) {
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;

		cfg_peer = cfg_peer->next;
	}


	n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
	if(n < 0) {
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	*n2 += n;

	RHP_UNLOCK(&(rlm->lock));

	return 0;

error:
	RHP_UNLOCK(&(rlm->lock));

	return err;
}

static int _rhp_ui_http_cfg_peers_serialize(rhp_http_bus_session* http_bus_sess,void* ctx,void* writer,int idx)
{
  int err = -EINVAL;
  int n = 0;
  int n2 = 0;
  unsigned long rlm_id = (unsigned long)ctx;
  rhp_ui_http_enum_ctx enum_ctx;

  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_GET_PEERS_SERIALIZE,"xuxd",http_bus_sess,rlm_id,writer,idx);

	n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"rhp_http_bus_record");
	if(n < 0) {
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"index","%d",idx);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"service",(xmlChar*)"ui_http_vpn");
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"action",(xmlChar*)"config_peers");
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"session_id","%llu",http_bus_sess->session_id);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	{
		enum_ctx.idx = 0;
		enum_ctx.writer = writer;
		enum_ctx.n2 = &n2;
		enum_ctx.rlm_id = rlm_id;

		err = rhp_realm_enum(rlm_id,_rhp_ui_http_cfg_peers_enum_cb,&enum_ctx);
		if( err ){
			goto error;
		}
	}


	n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
	if(n < 0) {
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_GET_PEERS_SERIALIZE_RTRN,"xd",http_bus_sess,n2);
  return n2;

error:
  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_GET_PEERS_SERIALIZE_ERR,"xE",http_bus_sess,err);
  return err;
}

static int _rhp_ui_http_cfg_peers(xmlDocPtr doc,xmlNodePtr node,rhp_http_conn* http_conn,
		rhp_http_bus_session* http_bus_sess,rhp_http_request* http_req,void* ctx)
{
  int err = -EINVAL;
  char* vpn_realm_str = NULL;
  unsigned long rlm_id;
  char* endp;

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_PEERS,"xxxxxx",doc,node,http_conn,http_bus_sess,http_req,ctx);

  if( doc == NULL || node == NULL ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_PEERS_NO_DOC_NODE,"xxx",http_conn,http_bus_sess,http_req);
    return -EINVAL;
  }

  vpn_realm_str = (char*)rhp_xml_get_prop(node,(const xmlChar*)"vpn_realm");
  if( vpn_realm_str ){

  	rlm_id = strtoul((char*)vpn_realm_str,&endp,0);
  	if( (rlm_id == ULONG_MAX && errno == ERANGE) || *endp != '\0' ){
  		err = -ENOENT;
  		RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_PEERS_NO_VPN_REALM_2,"xxxs",http_conn,http_bus_sess,http_req,vpn_realm_str);
  		goto error;
  	}

  }else{

  	rlm_id = http_conn->user_realm_id;
  }

  if( _rhp_ui_http_permitted(http_conn,http_bus_sess,rlm_id) ){
			err = -EPERM;
			RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_PEERS_NOT_PERMITTED,"xxxuu",http_conn,http_bus_sess,http_req,http_conn->user_realm_id,http_bus_sess->user_realm_id);
			goto error;
	}

  if( rlm_id != 0 ){

  	rhp_vpn_realm* rlm = rhp_realm_get(rlm_id);
  	if( rlm == NULL ){
  		err = -ENOENT;
  		goto error;
  	}

  	rhp_realm_unhold(rlm);
  }

  err = rhp_http_bus_send_response(http_conn,http_bus_sess,_rhp_ui_http_cfg_peers_serialize,(void*)rlm_id);
  if( err ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_PEERS_TX_RESP_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
    goto error;
  }

  if( vpn_realm_str ){
  	_rhp_free(vpn_realm_str);
  }

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_PEERS_RTRN,"xxxs",http_conn,http_bus_sess,http_req,vpn_realm_str);
  return RHP_STATUS_CLOSE_HTTP_CONN;

error:
	if( vpn_realm_str ){
		_rhp_free(vpn_realm_str);
	}
  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_PEERS_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  return err;
}

static int _rhp_ui_http_cfg_get_enum_xml(xmlNodePtr node,void* ctx)
{
	int err = -EINVAL;
	int ret_len;
  rhp_ui_http_enum_ctx* enum_ctx = (rhp_ui_http_enum_ctx*)ctx;

  if( !xmlStrcmp(node->name,(xmlChar*)"vpn_realm") ){

  	unsigned long rlm_id;

    if( rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"id"),RHP_XML_DT_ULONG,&rlm_id,&ret_len,NULL,0) ){
      RHP_BUG("");
      goto error;
    }

    if( (rlm_id == enum_ctx->rlm_id) || (enum_ctx->rlm_id == 0) ){

    	err = rhp_xml_write_node(node,(xmlTextWriterPtr)enum_ctx->writer,enum_ctx->n2,1,NULL,NULL,NULL);
    	if( err ){
      	RHP_BUG("");
    		goto error;
    	}
    }
/*
  }else if( !xmlStrcmp(node->name,(xmlChar*)"vpn") ||
							 !xmlStrcmp(node->name,(xmlChar*)"ikesa") ||
							 !xmlStrcmp(node->name,(xmlChar*)"childsa") ||
							 !xmlStrcmp(node->name,(xmlChar*)"peer_acls") ||
							 !xmlStrcmp(node->name,(xmlChar*)"ikesa_security") ||
							 !xmlStrcmp(node->name,(xmlChar*)"childsa_security") ){

		err = rhp_xml_write_node(node,(xmlTextWriterPtr)enum_ctx->writer,enum_ctx->n2,1,NULL,NULL,NULL);
  	if( err ){
    	RHP_BUG("");
  		goto error;
  	}

  }else if( !xmlStrcmp(node->name,(xmlChar*)"admin_services") ){

  	if( enum_ctx->rlm_id == 0 ){

  		err = rhp_xml_write_node(node,(xmlTextWriterPtr)enum_ctx->writer,enum_ctx->n2,1,NULL,NULL,NULL);
    	if( err ){
      	RHP_BUG("");
    		goto error;
    	}
  	}
*/
  }

  return 0;

error:
	RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_GET_ENUM_XML_ERR,"xxE",node,ctx,err);
	return err;
}

static int _rhp_ui_http_cfg_get_enum_auth_xml(xmlNodePtr node,void* ctx)
{
	int err = -EINVAL;
  rhp_ui_http_enum_ctx* enum_ctx = (rhp_ui_http_enum_ctx*)ctx;

	RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_GET_ENUM_AUTH_XML,"xx",node,ctx);

  err = rhp_xml_write_node(node,(xmlTextWriterPtr)enum_ctx->writer,enum_ctx->n2,1,NULL,NULL,NULL);
  if( err ){
  	RHP_BUG("");
  	goto error;
  }

	RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_GET_ENUM_AUTH_XML_RTRN,"xx",node,ctx);
  return 0;

error:
	RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_GET_ENUM_AUTH_XML_ERR,"xxE",node,ctx,err);
	return err;
}

static int _rhp_ui_http_cfg_get_serialize(rhp_http_bus_session* http_bus_sess,void* ctx,void* writer,int idx)
{
  int err = -EINVAL;
  int n = 0;
  int n2 = 0;
	rhp_ipcmsg_syspxy_cfg_sub* cfg_sub_dt = (rhp_ipcmsg_syspxy_cfg_sub*)ctx;
  rhp_ui_http_enum_ctx enum_ctx;
  xmlDocPtr cfg_doc = NULL;
  xmlNodePtr cfg_root_node;
  xmlDocPtr auth_doc = NULL;
  xmlNodePtr auth_root_node = NULL;
  int sub_dt_xml_len = 0;

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_GET_SERIALIZE,"xuxd",http_bus_sess,cfg_sub_dt->target_rlm_id,writer,idx);


  sub_dt_xml_len = cfg_sub_dt->len - sizeof(rhp_ipcmsg_syspxy_cfg_sub);

  if( sub_dt_xml_len > 0  ){

  	auth_doc = xmlParseMemory((void*)(cfg_sub_dt + 1),sub_dt_xml_len);
  	if( auth_doc == NULL ){
  		err = -EINVAL;
  		RHP_BUG("");
  		goto error;
  	}

  	auth_root_node = xmlDocGetRootElement(auth_doc);
  	if( auth_root_node == NULL ){
  		xmlFreeDoc(auth_doc);
  		RHP_BUG("");
  		auth_doc = NULL;
  	}
  }


	n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"rhp_http_bus_record");
	if(n < 0) {
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"index","%d",idx);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"service",(xmlChar*)"ui_http_vpn");
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"action",(xmlChar*)"config_get");
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"session_id","%llu",http_bus_sess->session_id);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	{
		enum_ctx.idx = 0;
		enum_ctx.writer = writer;
		enum_ctx.n2 = &n2;
		enum_ctx.rlm_id = cfg_sub_dt->target_rlm_id;

	  cfg_doc = xmlParseFile(rhp_main_conf_path);
	  if( cfg_doc == NULL ){
	    RHP_BUG(" %s ",rhp_main_conf_path);
	    err = -ENOENT;
	    goto error;
	  }

	  cfg_root_node = xmlDocGetRootElement(cfg_doc);
	  if( cfg_root_node == NULL ){
	    RHP_BUG(" %s ",rhp_main_conf_path);
	    err = -ENOENT;
	    goto error;
	  }

    n = xmlTextWriterStartElement(writer,(xmlChar*)"rhp_config");
    if(n < 0) {
      err = -ENOMEM;
      RHP_BUG("");
      goto error;
    }
    n2 += n;

	  err = rhp_xml_enum_tags(cfg_root_node,NULL,_rhp_ui_http_cfg_get_enum_xml,(void*)&enum_ctx,1);
	  if( err ){
	    RHP_BUG(" %s ",rhp_main_conf_path);
	    goto error;
	  }

		n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
		if(n < 0) {
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		n2 += n;
	}

	if( auth_doc ){

    n = xmlTextWriterStartElement(writer,(xmlChar*)"rhp_auth");
    if(n < 0) {
      err = -ENOMEM;
      RHP_BUG("");
      goto error;
    }
    n2 += n;

	  err = rhp_xml_enum_tags(auth_root_node,NULL,_rhp_ui_http_cfg_get_enum_auth_xml,(void*)&enum_ctx,1);
	  if( err && err != -ENOENT ){
	    RHP_BUG(" %s ",rhp_main_conf_path);
	    goto error;
	  }
	  err = 0;

		n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
		if(n < 0) {
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		n2 += n;
	}


	n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
	if(n < 0) {
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;


	if( auth_doc ){
		xmlFreeDoc(auth_doc);
	}

	xmlFreeDoc(cfg_doc);

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_GET_SERIALIZE_RTRN,"xd",http_bus_sess,n2);
  return n2;

error:
	if( cfg_doc ){
		xmlFreeDoc(cfg_doc);
	}
	if( auth_doc ){
		xmlFreeDoc(auth_doc);
	}
  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_GET_SERIALIZE_ERR,"xE",http_bus_sess,err);
  return err;
}

static int _rhp_ui_http_cfg_get_bh(xmlDocPtr doc,xmlNodePtr node,rhp_http_conn* http_conn,rhp_http_bus_session* http_bus_sess,
  				rhp_http_request* http_req,int data_len,u8* data,void* ipc_bus_cb_ctx)
{
  int err = -EINVAL;
	rhp_ipcmsg_syspxy_cfg_sub* cfg_sub_dt = (rhp_ipcmsg_syspxy_cfg_sub*)data;

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_GET_BH,"xxxxxpx",doc,node,http_conn,http_bus_sess,http_req,data_len,data,ipc_bus_cb_ctx);

	if( data_len < (int)sizeof(rhp_ipcmsg_syspxy_cfg_sub) && (int)cfg_sub_dt->len != data_len ){
		err = -EINVAL;
		RHP_BUG("%d, %d, %d",cfg_sub_dt->len,data_len,sizeof(rhp_ipcmsg_syspxy_cfg_sub));
		goto error;
	}

	if( !cfg_sub_dt->result ){
		err = -EPERM;
	  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_GET_BH_RESULT_FAILED,"xxxxx",doc,node,http_conn,http_bus_sess,http_req);
		goto error;
	}

  err = rhp_http_bus_send_response(http_conn,http_bus_sess,_rhp_ui_http_cfg_get_serialize,(void*)cfg_sub_dt);
  if( err ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_GET_BH_TX_RESP_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
    goto error;
  }

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_GET_BH_RTRN,"xxxxx",doc,node,http_conn,http_bus_sess,http_req);
  return RHP_STATUS_CLOSE_HTTP_CONN;

error:
	RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_GET_BH_ERR,"xxxxxE",doc,node,http_conn,http_bus_sess,http_req,err);
	return err;
}

static int _rhp_ui_http_cfg_get(xmlDocPtr doc,xmlNodePtr node,rhp_http_conn* http_conn,
		rhp_http_bus_session* http_bus_sess,rhp_http_request* http_req,void* ctx)
{
  int err = -EINVAL;
  char* vpn_realm_str = NULL;
  unsigned long rlm_id = RHP_VPN_REALM_ID_UNKNOWN;
  char* endp;

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_GET,"xxxxxx",doc,node,http_conn,http_bus_sess,http_req,ctx);

  if( doc == NULL || node == NULL ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_GET_NO_DOC_NODE,"xxx",http_conn,http_bus_sess,http_req);
    return -EINVAL;
  }

  vpn_realm_str = (char*)rhp_xml_get_prop(node,(const xmlChar*)"vpn_realm");
  if( vpn_realm_str ){

		rlm_id = strtoul((char*)vpn_realm_str,&endp,0);
		if( (rlm_id == ULONG_MAX && errno == ERANGE) || *endp != '\0' ){
			err = -ENOENT;
			RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_GET_NO_VPN_REALM_2,"xxxs",http_conn,http_bus_sess,http_req,vpn_realm_str);
			goto error;
		}

		if( _rhp_ui_http_permitted(http_conn,http_bus_sess,rlm_id) ){
				err = -EPERM;
				RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_GET_NOT_PERMITTED,"xxxuu",http_conn,http_bus_sess,http_req,http_conn->user_realm_id,http_bus_sess->user_realm_id);
				goto error;
		}

  }else{

  	err = _rhp_ui_http_get_user_realm_id(http_conn,http_bus_sess,&rlm_id);
		if( err ){
			RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_GET_NOT_PERMITTED2,"xxxuu",http_conn,http_bus_sess,http_req,http_conn->user_realm_id,http_bus_sess->user_realm_id);
			goto error;
		}
  }

  if( rlm_id != 0 ){

  	rhp_vpn_realm* rlm = rhp_realm_get(rlm_id);
  	if( rlm == NULL ){

  	  if( http_conn->user_realm_id ||
  	  		!rhp_realm_disabled_exists(rlm_id) ){

    	  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_GET_NO_REALM_FOUND,"xxxxxu",doc,node,http_conn,http_bus_sess,http_req,rlm_id);

  	  	err = -ENOENT;
  	  	goto error;
  	  }
  	}

  	if( rlm ){
  		rhp_realm_unhold(rlm);
  	}
  }

  {
  	rhp_ipcmsg_syspxy_cfg_sub cfg_sub_dt;

  	cfg_sub_dt.cfg_type = RHP_IPC_SYSPXY_CFG_GET;
  	cfg_sub_dt.len = sizeof(rhp_ipcmsg_syspxy_cfg_sub);
  	cfg_sub_dt.target_rlm_id = rlm_id;

  	err = rhp_http_bus_ipc_cfg_request(http_conn,http_bus_sess,
  			sizeof(rhp_ipcmsg_syspxy_cfg_sub),(u8*)&cfg_sub_dt,_rhp_ui_http_cfg_get_bh,NULL);
  	if( err ){
  		RHP_BUG("");
  		goto error;
  	}
  }

  if( vpn_realm_str ){
  	_rhp_free(vpn_realm_str);
  }

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_GET_RTRN,"xxxs",http_conn,http_bus_sess,http_req,vpn_realm_str);
  return RHP_STATUS_HTTP_REQ_PENDING;

error:
	if( vpn_realm_str ){
		_rhp_free(vpn_realm_str);
	}
  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_GET_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  return err;
}

static int _rhp_ui_http_cfg_get_global_params_enum_xml(xmlNodePtr node,void* ctx)
{
	int err = -EINVAL;
  rhp_ui_http_enum_ctx* enum_ctx = (rhp_ui_http_enum_ctx*)ctx;

  if( !xmlStrcmp(node->name,(xmlChar*)"vpn") ||
			!xmlStrcmp(node->name,(xmlChar*)"ikesa") ||
			!xmlStrcmp(node->name,(xmlChar*)"childsa") ||
			!xmlStrcmp(node->name,(xmlChar*)"peer_acls") ||
			!xmlStrcmp(node->name,(xmlChar*)"firewall") ||
			!xmlStrcmp(node->name,(xmlChar*)"ikev2_hash_url") ||
			!xmlStrcmp(node->name,(xmlChar*)"radius") ||
			!xmlStrcmp(node->name,(xmlChar*)"radius_acct") ||
			!xmlStrcmp(node->name,(xmlChar*)"ikesa_security") ||
			!xmlStrcmp(node->name,(xmlChar*)"childsa_security") ||
			!xmlStrcmp(node->name,(xmlChar*)"ikev1_ikesa_security") ||
			!xmlStrcmp(node->name,(xmlChar*)"ikev1_ipsecsa_security") ){

		err = rhp_xml_write_node(node,(xmlTextWriterPtr)enum_ctx->writer,enum_ctx->n2,1,NULL,NULL,NULL);
  	if( err ){
    	RHP_BUG("");
  		goto error;
  	}

  }else if( !xmlStrcmp(node->name,(xmlChar*)"admin_services") ){

  	if( enum_ctx->rlm_id == 0 ){

  		err = rhp_xml_write_node(node,(xmlTextWriterPtr)enum_ctx->writer,enum_ctx->n2,1,NULL,NULL,NULL);
    	if( err ){
      	RHP_BUG("");
    		goto error;
    	}
  	}
  }

  return 0;

error:
	RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_GET_ENUM_XML_ERR,"xxE",node,ctx,err);
	return err;
}

static int _rhp_ui_http_cfg_get_global_params_serialize(
		rhp_http_bus_session* http_bus_sess,void* ctx,void* writer,int idx)
{
  int err = -EINVAL;
  int n = 0;
  int n2 = 0;
  rhp_ui_http_enum_ctx enum_ctx;
  xmlDocPtr cfg_doc = NULL;
  xmlNodePtr cfg_root_node;
  unsigned long rlm_id = (unsigned long)ctx;

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_GET_GLOBAL_PARAMS_SERIALIZE,"xxd",http_bus_sess,writer,idx);

	n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"rhp_http_bus_record");
	if(n < 0) {
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"index","%d",idx);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"service",(xmlChar*)"ui_http_vpn");
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,
				(xmlChar*)"action",(xmlChar*)"config_get_global_config");
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
				(xmlChar*)"session_id","%llu",http_bus_sess->session_id);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	{
		enum_ctx.idx = 0;
		enum_ctx.writer = writer;
		enum_ctx.n2 = &n2;
		enum_ctx.rlm_id = rlm_id;

	  cfg_doc = xmlParseFile(rhp_main_conf_path);
	  if( cfg_doc == NULL ){
	    RHP_BUG(" %s ",rhp_main_conf_path);
	    err = -ENOENT;
	    goto error;
	  }

	  cfg_root_node = xmlDocGetRootElement(cfg_doc);
	  if( cfg_root_node == NULL ){
	    RHP_BUG(" %s ",rhp_main_conf_path);
	    err = -ENOENT;
	    goto error;
	  }

    n = xmlTextWriterStartElement(writer,(xmlChar*)"rhp_config");
    if(n < 0) {
      err = -ENOMEM;
      RHP_BUG("");
      goto error;
    }
    n2 += n;

	  err = rhp_xml_enum_tags(cfg_root_node,NULL,_rhp_ui_http_cfg_get_global_params_enum_xml,(void*)&enum_ctx,1);
	  if( err ){
	    RHP_BUG(" %s ",rhp_main_conf_path);
	    goto error;
	  }

		n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
		if(n < 0) {
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		n2 += n;
	}

	n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
	if(n < 0) {
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	xmlFreeDoc(cfg_doc);

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_GET_GLOBAL_PARAMS_SERIALIZE_RTRN,"xd",http_bus_sess,n2);
  return n2;

error:
	if( cfg_doc ){
		xmlFreeDoc(cfg_doc);
	}
  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_GET_GLOBAL_PARAMS_SERIALIZE_ERR,"xE",http_bus_sess,err);
  return err;
}

static int _rhp_ui_http_cfg_get_global_params(xmlDocPtr doc,xmlNodePtr node,rhp_http_conn* http_conn,
		rhp_http_bus_session* http_bus_sess,rhp_http_request* http_req,void* ctx)
{
  int err = -EINVAL;
  char* vpn_realm_str = NULL;
  unsigned long rlm_id_r = RHP_VPN_REALM_ID_UNKNOWN;

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_GET_GLOBAL_PARAMS,"xxxxxx",doc,node,http_conn,http_bus_sess,http_req,ctx);

  if( doc == NULL || node == NULL ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_GET_GLOBAL_PARAMS_NO_DOC_NODE,"xxx",http_conn,http_bus_sess,http_req);
    return -EINVAL;
  }

  err = _rhp_ui_http_get_user_realm_id(http_conn,http_bus_sess,&rlm_id_r);
  if( err ){
			RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_GET_GLOBAL_PARAMS_NOT_PERMITTED,"xxxuu",http_conn,http_bus_sess,http_req,http_conn->user_realm_id,http_bus_sess->user_realm_id);
			goto error;
	}

  err = rhp_http_bus_send_response(http_conn,http_bus_sess,_rhp_ui_http_cfg_get_global_params_serialize,(void*)rlm_id_r);
  if( err ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_GET_GLOBAL_PARAMS_TX_RESP_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
    goto error;
  }

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_GET_GLOBAL_PARAMS_RTRN,"xxxs",http_conn,http_bus_sess,http_req,vpn_realm_str);
  return RHP_STATUS_CLOSE_HTTP_CONN;

error:
  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_GET_GLOBAL_PARAMS_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  return err;
}

static int _rhp_ui_http_cfg_get_printed_certs_enum_resp(xmlNodePtr node,void* ctx)
{
	int err = -EINVAL;
  rhp_ui_http_enum_ctx* enum_ctx = (rhp_ui_http_enum_ctx*)ctx;

	RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_GET_PRINTED_CERTS_ENUM_RESP,"xx",node,ctx);

  err = rhp_xml_write_node(node,(xmlTextWriterPtr)enum_ctx->writer,enum_ctx->n2,1,NULL,NULL,NULL);
  if( err ){
  	RHP_BUG("");
  	goto error;
  }

	RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_GET_PRINTED_CERTS_ENUM_RESP_RTRN,"xx",node,ctx);
  return 0;

error:
	RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_GET_PRINTED_CERTS_ENUM_RESP_ERR,"xxE",node,ctx,err);
	return err;
}

static int _rhp_ui_http_cfg_get_printed_certs_serialize(rhp_http_bus_session* http_bus_sess,void* ctx,void* writer,int idx)
{
  int err = -EINVAL;
  int n = 0;
  int n2 = 0;
	rhp_ipcmsg_syspxy_cfg_sub* cfg_sub_dt = (rhp_ipcmsg_syspxy_cfg_sub*)ctx;
  rhp_ui_http_enum_ctx enum_ctx;
  xmlDocPtr auth_doc = NULL;
  xmlNodePtr auth_root_node = NULL;
  int sub_dt_xml_len = 0;
  int target = cfg_sub_dt->priv[0];

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_GET_PRINTED_CERTS_SERIALIZE,"xuxd",http_bus_sess,cfg_sub_dt->target_rlm_id,writer,idx);

  sub_dt_xml_len = cfg_sub_dt->len - sizeof(rhp_ipcmsg_syspxy_cfg_sub);

  if( sub_dt_xml_len < 1 ){
  	err = -EINVAL;
		RHP_BUG("");
  	goto error;
  }

  auth_doc = xmlParseMemory( (void*) (cfg_sub_dt + 1), sub_dt_xml_len);
	if(auth_doc == NULL){
		err = -EINVAL;
		RHP_BUG( "" );
		goto error;
	}

	auth_root_node = xmlDocGetRootElement( auth_doc );
	if(auth_root_node == NULL){
		xmlFreeDoc( auth_doc );
		RHP_BUG( "" );
		auth_doc = NULL;
	}


	n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"rhp_http_bus_record");
	if(n < 0) {
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"index","%d",idx);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"service",(xmlChar*)"ui_http_vpn");
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	switch( target ){
	case RHP_IPC_SYSPXY_CFG_GET_PRINTED_CERTS_MY_CERT:
		n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"action",(xmlChar*)"config_get_my_printed_cert");
		break;
	case RHP_IPC_SYSPXY_CFG_GET_PRINTED_CERTS_CA_CERTS:
		n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"action",(xmlChar*)"config_get_printed_ca_certs");
		break;
	case RHP_IPC_SYSPXY_CFG_GET_PRINTED_CERTS_CRL:
		n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"action",(xmlChar*)"config_get_printed_crls");
		break;
	}
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"session_id","%llu",http_bus_sess->session_id);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	enum_ctx.idx = 0;
	enum_ctx.writer = writer;
	enum_ctx.n2 = &n2;
	enum_ctx.rlm_id = cfg_sub_dt->target_rlm_id;

	err = rhp_xml_enum_tags(auth_root_node,NULL,_rhp_ui_http_cfg_get_printed_certs_enum_resp,(void*)&enum_ctx,1);
	if( err && err != -ENOENT ){
		RHP_BUG("");
	  goto error;
	}
	err = 0;


	n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
	if(n < 0) {
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	xmlFreeDoc(auth_doc);

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_GET_PRINTED_CERTS_SERIALIZE_RTRN,"xd",http_bus_sess,n2);
  return n2;

error:
	if( auth_doc ){
		xmlFreeDoc(auth_doc);
	}
  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_GET_PRINTED_CERTS_SERIALIZE_ERR,"xE",http_bus_sess,err);
  return err;
}

static int _rhp_ui_http_cfg_get_printed_certs_bh(xmlDocPtr doc,xmlNodePtr node,rhp_http_conn* http_conn,rhp_http_bus_session* http_bus_sess,
  				rhp_http_request* http_req,int data_len,u8* data,void* ipc_bus_cb_ctx)
{
  int err = -EINVAL;
	rhp_ipcmsg_syspxy_cfg_sub* cfg_sub_dt = (rhp_ipcmsg_syspxy_cfg_sub*)data;

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_GET_PRINTED_CERTS_BH,"xxxxxpx",doc,node,http_conn,http_bus_sess,http_req,data_len,data,ipc_bus_cb_ctx);

	if( data_len < (int)sizeof(rhp_ipcmsg_syspxy_cfg_sub) && (int)cfg_sub_dt->len != data_len ){
		err = -EINVAL;
		RHP_BUG("%d, %d, %d",cfg_sub_dt->len,data_len,sizeof(rhp_ipcmsg_syspxy_cfg_sub));
		goto error;
	}

	if( !cfg_sub_dt->result ){
		err = -ENOENT;
	  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_GET_PRINTED_CERTS_BH_RESULT_FAILED,"xxxxx",doc,node,http_conn,http_bus_sess,http_req);
		goto error;
	}

  err = rhp_http_bus_send_response(http_conn,http_bus_sess,_rhp_ui_http_cfg_get_printed_certs_serialize,(void*)cfg_sub_dt);
  if( err ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_GET_PRINTED_CERTS_BH_TX_RESP_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
    goto error;
  }

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_GET_PRINTED_CERTS_BH_RTRN,"xxxxx",doc,node,http_conn,http_bus_sess,http_req);
  return RHP_STATUS_CLOSE_HTTP_CONN;

error:
	RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_GET_PRINTED_CERTS_BH_ERR,"xxxxxE",doc,node,http_conn,http_bus_sess,http_req,err);
	return err;
}

static int _rhp_ui_http_cfg_get_printed_certs(xmlDocPtr doc,xmlNodePtr node,rhp_http_conn* http_conn,
		rhp_http_bus_session* http_bus_sess,rhp_http_request* http_req,void* ctx,int target)
{
  int err = -EINVAL;
  char* vpn_realm_str = NULL;
  unsigned long rlm_id;
  char* endp;

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_GET_PRINTED_CERTS,"xxxxxxd",doc,node,http_conn,http_bus_sess,http_req,ctx,target);

  if( doc == NULL || node == NULL ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_GET_PRINTED_CERTS_NO_DOC_NODE,"xxx",http_conn,http_bus_sess,http_req);
    return -EINVAL;
  }

  vpn_realm_str = (char*)rhp_xml_get_prop(node,(const xmlChar*)"vpn_realm");
  if( vpn_realm_str == NULL ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_GET_PRINTED_CERTS_NO_VPN_REALM,"xxx",http_conn,http_bus_sess,http_req);
    goto error;
  }

  rlm_id = strtoul((char*)vpn_realm_str,&endp,0);
  if( (rlm_id == ULONG_MAX && errno == ERANGE) || *endp != '\0' ){
  	err = -ENOENT;
  	RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_GET_PRINTED_CERTS_NO_VPN_REALM_2,"xxxs",http_conn,http_bus_sess,http_req,vpn_realm_str);
  	goto error;
  }

  if( rlm_id == 0 ){
		err = -EPERM;
  	RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_GET_PRINTED_CERTS_REALMID_NOT_SPECIFIED,"xxxs",http_conn,http_bus_sess,http_req,vpn_realm_str);
		goto error;
  }

  if( _rhp_ui_http_permitted(http_conn,http_bus_sess,rlm_id) ){
			err = -EPERM;
			RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_GET_PRINTED_CERTS_NOT_PERMITTED,"xxxuu",http_conn,http_bus_sess,http_req,http_conn->user_realm_id,http_bus_sess->user_realm_id);
			goto error;
	}

  {
  	rhp_vpn_realm* rlm = rhp_realm_get(rlm_id);
  	if( rlm == NULL ){

  	  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_GET_PRINTED_CERTS_NO_REALM_FOUND,"xxxxxu",doc,node,http_conn,http_bus_sess,http_req,rlm_id);

  		err = -ENOENT;
  		goto error;
  	}

  	rhp_realm_unhold(rlm);
  }

  {
  	rhp_ipcmsg_syspxy_cfg_sub cfg_sub_dt;

  	cfg_sub_dt.cfg_type = RHP_IPC_SYSPXY_CFG_GET_PRINTED_CERTS;
  	cfg_sub_dt.len = sizeof(rhp_ipcmsg_syspxy_cfg_sub);
  	cfg_sub_dt.target_rlm_id = rlm_id;
  	cfg_sub_dt.priv[0] = target;

  	err = rhp_http_bus_ipc_cfg_request(http_conn,http_bus_sess,
  			sizeof(rhp_ipcmsg_syspxy_cfg_sub),(u8*)&cfg_sub_dt,_rhp_ui_http_cfg_get_printed_certs_bh,NULL);

  	if( err ){
  		RHP_BUG("");
  		goto error;
  	}
  }

  if( vpn_realm_str ){
  	_rhp_free(vpn_realm_str);
  }

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_GET_PRINTED_CERTS_RTRN,"xxxs",http_conn,http_bus_sess,http_req,vpn_realm_str);
  return RHP_STATUS_HTTP_REQ_PENDING;

error:
	if( vpn_realm_str ){
		_rhp_free(vpn_realm_str);
	}
  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_GET_PRINTED_CERTS_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  return err;
}


static int _rhp_ui_http_get_vpn_peer_printed_certs_serialize(rhp_http_bus_session* http_bus_sess,void* ctx,void* writer,int idx)
{
  int err = -EINVAL;
  int n = 0;
  int n2 = 0;
  rhp_vpn* vpn = (rhp_vpn*)ctx;
  unsigned long rlm_id = vpn->vpn_realm_id;

  RHP_TRC(0,RHPTRCID_UI_HTTP_GET_VPN_PEER_PRINTED_CERTS_SERIALIZE,"xuxd",http_bus_sess,rlm_id,writer,idx);

  RHP_LOCK(&(vpn->lock));


	n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"rhp_http_bus_record");
	if(n < 0) {
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"index","%d",idx);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"service",(xmlChar*)"ui_http_vpn");
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;


	n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"action",(xmlChar*)"config_get_peer_printed_certs");
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"session_id","%llu",http_bus_sess->session_id);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;


	{
		u8* cert_txt = NULL;
		int cert_txt_len = 0;

    n = xmlTextWriterStartElement(writer,(xmlChar*)"rhp_printed_certs");
		if(n < 0) {
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		n2 += n;

		err = rhp_cert_get_certs_printed_text(vpn->rx_peer_cert,vpn->rx_peer_cert_len,1,&cert_txt,&cert_txt_len);
		if( err ){
			RHP_BUG("");
			goto error;
		}

		n = xmlTextWriterWriteCDATA((xmlTextWriterPtr)writer,(xmlChar*)cert_txt);
		if(n < 0) {
			err = -ENOMEM;
			RHP_BUG("");
			_rhp_free(cert_txt);
			goto error;
		}
		n2 += n;

		n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
		if(n < 0) {
			err = -ENOMEM;
			RHP_BUG("");
			_rhp_free(cert_txt);
			goto error;
		}
		n2 += n;

		_rhp_free(cert_txt);


		if( vpn->rx_peer_cert_url && vpn->rx_peer_cert_hash ){

			n = xmlTextWriterStartElement(writer,(xmlChar*)"rhp_printed_peer_cert_hash_url");
			if(n < 0) {
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			n2 += n;

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"url","%s",vpn->rx_peer_cert_url);
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			n2 += n;

			err = rhp_bin2str_dump(vpn->rx_peer_cert_hash_len,vpn->rx_peer_cert_hash,0,&cert_txt_len,(char**)&cert_txt);
			if( err ){
				RHP_BUG("");
				goto error;
			}

			n = xmlTextWriterWriteCDATA((xmlTextWriterPtr)writer,(xmlChar*)cert_txt);
			if(n < 0) {
				err = -ENOMEM;
				RHP_BUG("");
				_rhp_free(cert_txt);
				goto error;
			}
			n2 += n;

			n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
			if(n < 0) {
				err = -ENOMEM;
				RHP_BUG("");
				_rhp_free(cert_txt);
				goto error;
			}
			n2 += n;

			_rhp_free(cert_txt);
		}


		if( vpn->rx_untrust_ca_certs ){

			u8* untrust_ca_certs_p;
			int untrust_ca_certs_len;

			if( vpn->rx_untrust_ca_certs_num > 1 ){
				untrust_ca_certs_p = vpn->rx_untrust_ca_certs;
				untrust_ca_certs_len = vpn->rx_untrust_ca_certs_len;
			}else{
				untrust_ca_certs_p = ((u8*)vpn->rx_untrust_ca_certs) + sizeof(rhp_cert_data);
				untrust_ca_certs_len = vpn->rx_untrust_ca_certs_len - sizeof(rhp_cert_data);
			}

			n = xmlTextWriterStartElement(writer,(xmlChar*)"rhp_printed_certs");
			if(n < 0) {
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			n2 += n;

			err = rhp_cert_get_certs_printed_text(untrust_ca_certs_p,
					untrust_ca_certs_len,vpn->rx_untrust_ca_certs_num,&cert_txt,&cert_txt_len);
			if( err ){
				RHP_BUG("");
				goto error;
			}

			n = xmlTextWriterWriteCDATA((xmlTextWriterPtr)writer,(xmlChar*)cert_txt);
			if(n < 0) {
				err = -ENOMEM;
				RHP_BUG("");
				_rhp_free(cert_txt);
				goto error;
			}
			n2 += n;

			n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
			if(n < 0) {
				err = -ENOMEM;
				RHP_BUG("");
				_rhp_free(cert_txt);
				goto error;
			}
			n2 += n;

			_rhp_free(cert_txt);
		}
	}


	n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
	if(n < 0) {
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  RHP_UNLOCK(&(vpn->lock));

  RHP_TRC(0,RHPTRCID_UI_HTTP_GET_VPN_PEER_PRINTED_CERTS_SERIALIZE_RTRN,"xd",http_bus_sess,n2);
  return n2;

error:
	RHP_UNLOCK(&(vpn->lock));
  RHP_TRC(0,RHPTRCID_UI_HTTP_GET_VPN_PEER_PRINTED_CERTS_SERIALIZE_ERR,"xE",http_bus_sess,err);
  return err;
}

static int _rhp_ui_http_get_vpn_peer_printed_certs(xmlDocPtr doc,xmlNodePtr node,rhp_http_conn* http_conn,
		rhp_http_bus_session* http_bus_sess,rhp_http_request* http_req,void* ctx)
{
  int err = -EINVAL;
  char* vpn_realm_str = NULL;
  char* peer_id_type_str = NULL;
  char* peer_id_str = NULL;
  char* unique_id_str = NULL;
  rhp_ikev2_id peer_id;
  unsigned long rlm_id = 0;
  char* endp;
  rhp_vpn* vpn = NULL;
  rhp_vpn_ref* vpn_ref = NULL;

  RHP_TRC(0,RHPTRCID_UI_HTTP_GET_VPN_PEER_PRINTED_CERTS,"xxxxxx",doc,node,http_conn,http_bus_sess,http_req,ctx);

  if( doc == NULL || node == NULL ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_GET_VPN_PEER_PRINTED_CERTS_NO_DOC_NODE,"xxx",http_conn,http_bus_sess,http_req);
    return -EINVAL;
  }

  vpn_realm_str = (char*)rhp_xml_get_prop(node,(const xmlChar*)"vpn_realm");
  if( vpn_realm_str == NULL ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_UI_HTTP_GET_VPN_PEER_PRINTED_CERTS_NO_VPN_REALM,"xxx",http_conn,http_bus_sess,http_req);
    goto error;
  }

  rlm_id = strtoul((char*)vpn_realm_str,&endp,0);
  if( (rlm_id == ULONG_MAX && errno == ERANGE) || *endp != '\0' ){
  	err = -ENOENT;
  	RHP_TRC(0,RHPTRCID_UI_HTTP_GET_VPN_PEER_PRINTED_CERTS_NO_VPN_REALM_2,"xxxs",http_conn,http_bus_sess,http_req,vpn_realm_str);
  	goto error;
  }

  if( _rhp_ui_http_permitted(http_conn,http_bus_sess,rlm_id) ){
			err = -EPERM;
			RHP_TRC(0,RHPTRCID_UI_HTTP_GET_VPN_PEER_PRINTED_CERTS_NOT_PERMITTED,"xxxuu",http_conn,http_bus_sess,http_req,http_conn->user_realm_id,http_bus_sess->user_realm_id);
			goto error;
	}

  unique_id_str = (char*)rhp_xml_get_prop(node,(const xmlChar*)"vpn_unique_id");

  if( unique_id_str ){

  	u8 vpn_unique_id[RHP_VPN_UNIQUE_ID_SIZE];

  	memset(vpn_unique_id,0,RHP_VPN_UNIQUE_ID_SIZE);

  	err = rhp_str_to_vpn_unique_id(unique_id_str,vpn_unique_id);
  	if( err ){
			err = RHP_STATUS_INVALID_MSG;
  		goto error;
  	}

  	vpn_ref = rhp_vpn_get_by_unique_id(vpn_unique_id);
  	vpn = RHP_VPN_REF(vpn_ref);

  }else{

		peer_id_type_str = (char*)rhp_xml_get_prop(node,(const xmlChar*)"peer_id_type");
		if( peer_id_type_str == NULL ){
			err = RHP_STATUS_INVALID_MSG;
			RHP_TRC(0,RHPTRCID_UI_HTTP_GET_VPN_PEER_PRINTED_CERTS_NO_PEER_ID_TYPE,"xxx",http_conn,http_bus_sess,http_req);
			goto error;
		}

		peer_id_str = (char*)rhp_xml_get_prop(node,(const xmlChar*)"peer_id");
		if( peer_id_str == NULL ){
			err = RHP_STATUS_INVALID_MSG;
			RHP_TRC(0,RHPTRCID_UI_HTTP_GET_VPN_PEER_PRINTED_CERTS_NO_PEER_ID,"xxx",http_conn,http_bus_sess,http_req);
			goto error;
		}

		memset(&peer_id,0,sizeof(rhp_ikev2_id));
		err = rhp_cfg_parse_ikev2_id(node,(xmlChar*)"peer_id_type",(xmlChar*)"peer_id",&peer_id);
		if( err ){
			RHP_TRC(0,RHPTRCID_UI_HTTP_GET_VPN_PEER_PRINTED_CERTS_NO_PEER_ID_2,"xxxss",http_conn,http_bus_sess,http_req,peer_id_str,peer_id_str);
			goto error;
		}

		vpn_ref = rhp_vpn_get_in_valid_rlm_cfg(rlm_id,&peer_id);
  	vpn = RHP_VPN_REF(vpn_ref);
  }

  if( vpn == NULL ){
		RHP_TRC(0,RHPTRCID_UI_HTTP_GET_VPN_PEER_PRINTED_CERTS_NO_ENT_ERR,"xxx",http_conn,http_bus_sess,http_req);
		err = -ENOENT;
		goto error;
	}

  if( http_conn->user_realm_id && vpn->vpn_realm_id != http_conn->user_realm_id ){
		RHP_TRC(0,RHPTRCID_UI_HTTP_GET_VPN_PEER_PRINTED_CERTS_INVALID_RLM_ID,"xxxuu",http_conn,http_bus_sess,http_req,vpn->vpn_realm_id,http_conn->user_realm_id);
		err = -EPERM;
		goto error;
  }


  if( vpn->rx_peer_cert == NULL ){
		RHP_TRC(0,RHPTRCID_UI_HTTP_GET_VPN_PEER_PRINTED_CERTS_NO_RX_PEER_CERT_ERR,"xxx",http_conn,http_bus_sess,http_req);
  	err = -ENOENT;
  	goto error;
  }


  err = rhp_http_bus_send_response(http_conn,http_bus_sess,_rhp_ui_http_get_vpn_peer_printed_certs_serialize,vpn);
  if( err ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_GET_VPN_PEER_PRINTED_CERTS_TX_RESP_ERR,"xxxxE",http_conn,http_bus_sess,http_req,vpn,err);
    goto error;
  }

  rhp_vpn_unhold(vpn_ref);

  if( vpn_realm_str ){
  	_rhp_free(vpn_realm_str);
  }
  if( peer_id_type_str ){
  	_rhp_free(peer_id_type_str);
  }
  if( peer_id_str ){
  	_rhp_free(peer_id_str);
  }
  if( unique_id_str ){
  	_rhp_free(unique_id_str);
  }

  RHP_TRC(0,RHPTRCID_UI_HTTP_GET_VPN_PEER_PRINTED_CERTS_RTRN,"xxxx",http_conn,http_bus_sess,http_req,vpn);
  return RHP_STATUS_CLOSE_HTTP_CONN;

error:
	if( vpn ){
	  rhp_vpn_unhold(vpn_ref);
	}
  if( vpn_realm_str ){
  	_rhp_free(vpn_realm_str);
  }
  if( peer_id_type_str ){
  	_rhp_free(peer_id_type_str);
  }
  if( peer_id_str ){
  	_rhp_free(peer_id_str);
  }
  if( unique_id_str ){
  	_rhp_free(unique_id_str);
  }
  RHP_TRC(0,RHPTRCID_UI_HTTP_GET_VPN_PEER_PRINTED_CERTS_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  return err;
}


static int _rhp_ui_http_cfg_enum_admin_enum_resp(xmlNodePtr node,void* ctx)
{
	int err = -EINVAL;
  rhp_ui_http_enum_ctx* enum_ctx = (rhp_ui_http_enum_ctx*)ctx;

	RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_ENUM_ADMIN_ENUM_RESP,"xx",node,ctx);

  err = rhp_xml_write_node(node,(xmlTextWriterPtr)enum_ctx->writer,enum_ctx->n2,1,NULL,NULL,NULL);
  if( err ){
  	RHP_BUG("");
  	goto error;
  }

	RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_ENUM_ADMIN_ENUM_RESP_RTRN,"xx",node,ctx);
  return 0;

error:
	RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_ENUM_ADMIN_ENUM_RESP_ERR,"xxE",node,ctx,err);
	return err;
}

static int _rhp_ui_http_cfg_enum_admin_serialize(rhp_http_bus_session* http_bus_sess,void* ctx,void* writer,int idx)
{
  int err = -EINVAL;
  int n = 0;
  int n2 = 0;
	rhp_ipcmsg_syspxy_cfg_sub* cfg_sub_dt = (rhp_ipcmsg_syspxy_cfg_sub*)ctx;
  rhp_ui_http_enum_ctx enum_ctx;
  xmlDocPtr auth_doc = NULL;
  xmlNodePtr auth_root_node = NULL;
  int sub_dt_xml_len = 0;

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_ENUM_ADMIN_SERIALIZE,"xuxd",http_bus_sess,cfg_sub_dt->target_rlm_id,writer,idx);

  sub_dt_xml_len = cfg_sub_dt->len - sizeof(rhp_ipcmsg_syspxy_cfg_sub);

  if( sub_dt_xml_len < 1 ){
  	err = -EINVAL;
		RHP_BUG("");
  	goto error;
  }

  auth_doc = xmlParseMemory( (void*) (cfg_sub_dt + 1), sub_dt_xml_len);
	if(auth_doc == NULL){
		err = -EINVAL;
		RHP_BUG( "" );
		goto error;
	}

	auth_root_node = xmlDocGetRootElement( auth_doc );
	if(auth_root_node == NULL){
		xmlFreeDoc( auth_doc );
		RHP_BUG( "" );
		auth_doc = NULL;
	}


	n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"rhp_http_bus_record");
	if(n < 0) {
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"index","%d",idx);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"service",(xmlChar*)"ui_http_vpn");
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"action",(xmlChar*)"config_enum_admin");
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"session_id","%llu",http_bus_sess->session_id);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	enum_ctx.idx = 0;
	enum_ctx.writer = writer;
	enum_ctx.n2 = &n2;
	enum_ctx.rlm_id = cfg_sub_dt->target_rlm_id;

	err = rhp_xml_enum_tags(auth_root_node,NULL,_rhp_ui_http_cfg_enum_admin_enum_resp,(void*)&enum_ctx,1);
	if( err && err != -ENOENT ){
		RHP_BUG("");
	  goto error;
	}
	err = 0;


	n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
	if(n < 0) {
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	xmlFreeDoc(auth_doc);

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_ENUM_ADMIN_SERIALIZE_RTRN,"xd",http_bus_sess,n2);
  return n2;

error:
	if( auth_doc ){
		xmlFreeDoc(auth_doc);
	}
  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_ENUM_ADMIN_SERIALIZE_ERR,"xE",http_bus_sess,err);
  return err;
}

static int _rhp_ui_http_cfg_enum_admin_bh(xmlDocPtr doc,xmlNodePtr node,rhp_http_conn* http_conn,rhp_http_bus_session* http_bus_sess,
  				rhp_http_request* http_req,int data_len,u8* data,void* ipc_bus_cb_ctx)
{
  int err = -EINVAL;
	rhp_ipcmsg_syspxy_cfg_sub* cfg_sub_dt = (rhp_ipcmsg_syspxy_cfg_sub*)data;

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_ENUM_ADMIN_BH,"xxxxxpx",doc,node,http_conn,http_bus_sess,http_req,data_len,data,ipc_bus_cb_ctx);

	if( data_len < (int)sizeof(rhp_ipcmsg_syspxy_cfg_sub) && (int)cfg_sub_dt->len != data_len ){
		err = -EINVAL;
		RHP_BUG("%d, %d, %d",cfg_sub_dt->len,data_len,sizeof(rhp_ipcmsg_syspxy_cfg_sub));
		goto error;
	}

	if( !cfg_sub_dt->result ){
		err = -ENOENT;
	  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_ENUM_ADMIN_BH_RESULT_FAILED,"xxxxx",doc,node,http_conn,http_bus_sess,http_req);
		goto error;
	}

  err = rhp_http_bus_send_response(http_conn,http_bus_sess,_rhp_ui_http_cfg_enum_admin_serialize,(void*)cfg_sub_dt);
  if( err ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_ENUM_ADMIN_BH_TX_RESP_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
    goto error;
  }

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_ENUM_ADMIN_BH_RTRN,"xxxxx",doc,node,http_conn,http_bus_sess,http_req);
  return RHP_STATUS_CLOSE_HTTP_CONN;

error:
	RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_ENUM_ADMIN_BH_ERR,"xxxxxE",doc,node,http_conn,http_bus_sess,http_req,err);
	return err;
}

static int _rhp_ui_http_cfg_enum_admin(xmlDocPtr doc,xmlNodePtr node,rhp_http_conn* http_conn,
		rhp_http_bus_session* http_bus_sess,rhp_http_request* http_req,void* ctx)
{
  int err = -EINVAL;
  char* vpn_realm_str = NULL;
  unsigned long rlm_id = RHP_VPN_REALM_ID_UNKNOWN;

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_ENUM_ADMIN,"xxxxxx",doc,node,http_conn,http_bus_sess,http_req,ctx);

  if( doc == NULL || node == NULL ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_ENUM_ADMIN_NO_DOC_NODE,"xxx",http_conn,http_bus_sess,http_req);
    return -EINVAL;
  }

  if( _rhp_ui_http_get_user_realm_id(http_conn,http_bus_sess,&rlm_id) ){
			err = -EPERM;
			RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_ENUM_ADMIN_NOT_PERMITTED,"xxxuu",http_conn,http_bus_sess,http_req,http_conn->user_realm_id,http_bus_sess->user_realm_id);
			goto error;
	}

  if( rlm_id ){

  	rhp_vpn_realm* rlm = rhp_realm_get(rlm_id);
  	if( rlm == NULL ){

  	  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_ENUM_ADMIN_NO_REALM_FOUND,"xxxxxu",doc,node,http_conn,http_bus_sess,http_req,rlm_id);

  		err = -ENOENT;
  		goto error;
  	}

  	rhp_realm_unhold(rlm);
  }

  {
  	rhp_ipcmsg_syspxy_cfg_sub cfg_sub_dt;

  	cfg_sub_dt.cfg_type = RHP_IPC_SYSPXY_CFG_ENUM_ADMIN;
  	cfg_sub_dt.len = sizeof(rhp_ipcmsg_syspxy_cfg_sub);
  	cfg_sub_dt.target_rlm_id = rlm_id;

  	err = rhp_http_bus_ipc_cfg_request(http_conn,http_bus_sess,
  			sizeof(rhp_ipcmsg_syspxy_cfg_sub),(u8*)&cfg_sub_dt,_rhp_ui_http_cfg_enum_admin_bh,NULL);

  	if( err ){
  		RHP_BUG("");
  		goto error;
  	}
  }

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_ENUM_ADMIN_RTRN,"xxxs",http_conn,http_bus_sess,http_req,vpn_realm_str);
  return RHP_STATUS_HTTP_REQ_PENDING;

error:
  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_ENUM_ADMIN_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  return err;
}

static int _rhp_ui_http_cfg_realm_exists(xmlDocPtr doc,xmlNodePtr node,rhp_http_conn* http_conn,
		rhp_http_bus_session* http_bus_sess,rhp_http_request* http_req,void* ctx)
{
  int err = -EINVAL;
  char* vpn_realm_str = NULL;
  unsigned long rlm_id;
  char* endp;

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_REALM_EXISTS,"xxxxxx",doc,node,http_conn,http_bus_sess,http_req,ctx);

  if( doc == NULL || node == NULL ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_REALM_EXISTS_NO_DOC_NODE,"xxx",http_conn,http_bus_sess,http_req);
    return -EINVAL;
  }

  vpn_realm_str = (char*)rhp_xml_get_prop(node,(const xmlChar*)"vpn_realm");
  if( vpn_realm_str == NULL ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_REALM_EXISTS_NO_VPN_REALM,"xxx",http_conn,http_bus_sess,http_req);
    goto error;
  }

  rlm_id = strtoul((char*)vpn_realm_str,&endp,0);
  if( (rlm_id == ULONG_MAX && errno == ERANGE) || *endp != '\0' ){
  	err = -ENOENT;
  	RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_REALM_EXISTS_NO_VPN_REALM_2,"xxxs",http_conn,http_bus_sess,http_req,vpn_realm_str);
  	goto error;
  }

  if( _rhp_ui_http_permitted(http_conn,http_bus_sess,rlm_id) ){
			err = -EPERM;
			RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_REALM_EXISTS_NOT_PERMITTED,"xxxuu",http_conn,http_bus_sess,http_req,http_conn->user_realm_id,http_bus_sess->user_realm_id);
			goto error;
	}

  if( rlm_id ){

  	rhp_vpn_realm* rlm = rhp_realm_get(rlm_id);
  	if( rlm == NULL ){

  		if( !rhp_realm_disabled_exists(rlm_id) ){

				RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_REALM_EXISTS_NO_ENT,"xxxxxu",doc,node,http_conn,http_bus_sess,http_req,rlm_id);

				err = -ENOENT;
				goto error;
  		}
  	}

  	if( rlm ){
  		rhp_realm_unhold(rlm);
  	}

  }else{

  	err = -EINVAL;
  	goto error;
  }

	err = rhp_http_bus_send_response(http_conn,http_bus_sess,NULL,NULL);
  if( err ){
  	goto error;
  }

  if( vpn_realm_str ){
  	_rhp_free(vpn_realm_str);
  }

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_REALM_EXISTS_RTRN,"xxxs",http_conn,http_bus_sess,http_req,vpn_realm_str);
  return RHP_STATUS_CLOSE_HTTP_CONN;

error:
	if( vpn_realm_str ){
		_rhp_free(vpn_realm_str);
	}
  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_REALM_EXISTS_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  return err;
}


#define RHP_UI_HTTP_CFG_RLM_TIME_STR_LEN	64
static __thread char _rhp_ui_http_cfg_rlm_time_str_buf[RHP_UI_HTTP_CFG_RLM_TIME_STR_LEN];

static char* _rhp_ui_http_cfg_realm_time_str(time_t* rlm_time)
{
  struct tm ts;

  _rhp_ui_http_cfg_rlm_time_str_buf[0] = '\0';
  localtime_r(rlm_time,&ts);

  snprintf(_rhp_ui_http_cfg_rlm_time_str_buf,RHP_UI_HTTP_CFG_RLM_TIME_STR_LEN,
  		"%d-%02d-%02d %02d:%02d:%02d",
  		ts.tm_year + 1900,ts.tm_mon + 1, ts.tm_mday, ts.tm_hour, ts.tm_min, ts.tm_sec);

  return _rhp_ui_http_cfg_rlm_time_str_buf;
}

static int _rhp_ui_http_cfg_enum_realms_cb(rhp_vpn_realm* rlm,void* ctx)
{
  int err = -EINVAL;
  int n;
  rhp_ui_http_enum_ctx* enum_ctx = (rhp_ui_http_enum_ctx*)ctx;

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_ENUM_REALMS_CB,"xx",rlm,ctx);

  RHP_LOCK(&(rlm->lock));

  n = xmlTextWriterStartElement((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"vpn_realm");
  if(n < 0) {
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  *(enum_ctx->n2) += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"id","%lu",rlm->id);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
  *(enum_ctx->n2) += n;

  if( rlm->name ){

  	n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"name",(xmlChar*)rlm->name);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*(enum_ctx->n2) += n;
  }

  if( rlm->mode_label ){

  	n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"mode",(xmlChar*)rlm->mode_label);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*(enum_ctx->n2) += n;
  }

  if( rlm->description ){

  	n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"description",(xmlChar*)rlm->description);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*(enum_ctx->n2) += n;
  }

	n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"status",(xmlChar*)"enable");
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	*(enum_ctx->n2) += n;


	if( rlm->realm_created_time > 0 ){

		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"created_time",
				"%lld",rlm->realm_created_time);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*(enum_ctx->n2) += n;

		n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"created_local_time",
				(xmlChar*)_rhp_ui_http_cfg_realm_time_str(&(rlm->realm_created_time)));
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*(enum_ctx->n2) += n;
	}

	if( rlm->realm_updated_time > 0 ){

		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"updated_time",
				"%lld",rlm->realm_updated_time);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*(enum_ctx->n2) += n;

		n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"updated_local_time",
				(xmlChar*)_rhp_ui_http_cfg_realm_time_str(&(rlm->realm_updated_time)));
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*(enum_ctx->n2) += n;
	}


  n = xmlTextWriterEndElement((xmlTextWriterPtr)enum_ctx->writer);
	if(n < 0) {
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
  *(enum_ctx->n2) += n;

  RHP_UNLOCK(&(rlm->lock));

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_ENUM_REALMS_CB_RTRN,"xx",rlm,ctx);
  return 0;

error:
	RHP_UNLOCK(&(rlm->lock));

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_ENUM_REALMS_CB_ERR,"xxE",rlm,ctx,err);
	return err;
}

static int _rhp_ui_http_cfg_enum_realms_disabled_cb(rhp_vpn_realm_disabled* rlm_disabled,void* ctx)
{
  int err = -EINVAL;
  int n;
  rhp_ui_http_enum_ctx* enum_ctx = (rhp_ui_http_enum_ctx*)ctx;

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_ENUM_REALMS_DISABLED_CB,"xx",rlm_disabled,ctx);

  n = xmlTextWriterStartElement((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"vpn_realm");
  if(n < 0) {
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  *(enum_ctx->n2) += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"id","%lu",rlm_disabled->id);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
  *(enum_ctx->n2) += n;

  if( rlm_disabled->name ){

  	n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"name",(xmlChar*)rlm_disabled->name);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*(enum_ctx->n2) += n;
  }

  if( rlm_disabled->mode_label ){

  	n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"mode",(xmlChar*)rlm_disabled->mode_label);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*(enum_ctx->n2) += n;
  }

  if( rlm_disabled->description ){

  	n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"description",(xmlChar*)rlm_disabled->description);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*(enum_ctx->n2) += n;
  }

	n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"status",(xmlChar*)"disable");
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	*(enum_ctx->n2) += n;


	if( rlm_disabled->created_time > 0 ){

		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"created_time",
				"%lld",rlm_disabled->created_time);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*(enum_ctx->n2) += n;

		n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"created_local_time",
				(xmlChar*)_rhp_ui_http_cfg_realm_time_str(&(rlm_disabled->created_time)));
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*(enum_ctx->n2) += n;
	}

	if( rlm_disabled->updated_time > 0 ){

		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"updated_time",
				"%lld",rlm_disabled->updated_time);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*(enum_ctx->n2) += n;

		n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"updated_local_time",
				(xmlChar*)_rhp_ui_http_cfg_realm_time_str(&(rlm_disabled->updated_time)));
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*(enum_ctx->n2) += n;
	}


  n = xmlTextWriterEndElement((xmlTextWriterPtr)enum_ctx->writer);
	if(n < 0) {
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
  *(enum_ctx->n2) += n;

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_ENUM_REALMS_DISABLED_CB_RTRN,"xx",rlm_disabled,ctx);
  return 0;

error:
  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_ENUM_REALMS_DISABLED_CB_ERR,"xxE",rlm_disabled,ctx,err);
	return err;
}

static int _rhp_ui_http_cfg_enum_realms_serialize(rhp_http_bus_session* http_bus_sess,void* ctx,void* writer,int idx)
{
  int err = -EINVAL;
  int n = 0;
  int n2 = 0;
  rhp_ui_http_enum_ctx enum_ctx;
  unsigned long rlm_id = (unsigned long)ctx;

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_ENUM_REALMS_SERIALIZE,"xuxd",http_bus_sess,rlm_id,writer,idx);

  if( rlm_id ){

    rhp_vpn_realm* rlm = rhp_realm_get(rlm_id);
  	if( rlm == NULL &&
  			!rhp_realm_disabled_exists(rlm_id) ){

			RHP_BUG("%d",rlm_id);
			err = -EINVAL;
			goto error;
  	}

  	rhp_realm_unhold(rlm);
  }

	n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"rhp_http_bus_record");
	if(n < 0) {
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"index","%d",idx);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"service",(xmlChar*)"ui_http_vpn");
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"action",(xmlChar*)"config_enum_realms");
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"session_id","%llu",http_bus_sess->session_id);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	enum_ctx.idx = 0;
	enum_ctx.writer = writer;
	enum_ctx.n2 = &n2;

	{
		int rnum = 0;

		enum_ctx.rlm_id = rlm_id;

		err = rhp_realm_enum(rlm_id,_rhp_ui_http_cfg_enum_realms_cb,(void*)&enum_ctx);
		if( err && err != -ENOENT ){
			goto error;
		}else if( !err ){
			rnum++;
		}

		err = rhp_realm_disabled_enum(rlm_id,
						_rhp_ui_http_cfg_enum_realms_disabled_cb,(void*)&enum_ctx);
		if( err && err != -ENOENT ){
			goto error;
		}else if( !err ){
			rnum++;
		}

		if( rnum == 0 ){
			err = -ENOENT;
			goto error;
		}

		err = 0;
	}

	n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
	if(n < 0) {
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_ENUM_REALMS_SERIALIZE_RTRN,"xd",http_bus_sess,n2);
  return n2;

error:
  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_ENUM_REALMS_SERIALIZE_ERR,"xE",http_bus_sess,err);
  return err;
}

static int _rhp_ui_http_cfg_enum_realms(xmlDocPtr doc,xmlNodePtr node,rhp_http_conn* http_conn,
		rhp_http_bus_session* http_bus_sess,rhp_http_request* http_req,void* ctx)
{
  int err = -EINVAL;
  char* vpn_realm_str = NULL;
  char* endp;
  unsigned long rlm_id = RHP_VPN_REALM_ID_UNKNOWN;
  rhp_vpn_realm* rlm = NULL;

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_ENUM_REALMS,"xxxxxx",doc,node,http_conn,http_bus_sess,http_req,ctx);

  if( doc == NULL || node == NULL ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_ENUM_REALMS_NO_DOC_NODE,"xxx",http_conn,http_bus_sess,http_req);
    return -EINVAL;
  }


  vpn_realm_str = (char*)rhp_xml_get_prop(node,(const xmlChar*)"vpn_realm");
  if( vpn_realm_str ){

		rlm_id = strtoul((char*)vpn_realm_str,&endp,0);
		if( (rlm_id == ULONG_MAX && errno == ERANGE) || *endp != '\0' ){
			err = -ENOENT;
			RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_ENUM_REALMS_NO_ENT,"xxxuus",http_conn,http_bus_sess,http_req,http_conn->user_realm_id,http_bus_sess->user_realm_id,vpn_realm_str);
			goto error;
		}

		if( _rhp_ui_http_permitted(http_conn,http_bus_sess,rlm_id) ){
				err = -EPERM;
				RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_ENUM_REALMS_NOT_PERMITTED,"xxxuu",http_conn,http_bus_sess,http_req,http_conn->user_realm_id,http_bus_sess->user_realm_id);
				goto error;
		}

  }else{

		if( _rhp_ui_http_get_user_realm_id(http_conn,http_bus_sess,&rlm_id)  ){
	  	err = -EPERM;
			RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_ENUM_REALMS_NOT_PERMITTED_2,"xxxuu",http_conn,http_bus_sess,http_req,http_conn->user_realm_id,http_bus_sess->user_realm_id);
			goto error;
	  }
  }


  if( rlm_id ){

  	rlm = rhp_realm_get(rlm_id);
  	if( rlm == NULL ){

  		if( !rhp_realm_disabled_exists(rlm_id) ){

  			RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_ENUM_REALMS_NO_ENT_2,"xxxxxu",doc,node,http_conn,http_bus_sess,http_req,rlm_id);

  			err = -ENOENT;
  			goto error;
  		}
  	}
  }

	err = rhp_http_bus_send_response(
			http_conn,http_bus_sess,_rhp_ui_http_cfg_enum_realms_serialize,rlm_id);

	if( err ){
  	goto error;
  }

  if( rlm ){
  	rhp_realm_unhold(rlm);
  }

  if( vpn_realm_str ){
  	_rhp_free(vpn_realm_str);
  }

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_ENUM_REALMS_RTRN,"xxx",http_conn,http_bus_sess,http_req);
  return RHP_STATUS_CLOSE_HTTP_CONN;

error:
	if( rlm ){
		rhp_realm_unhold(rlm);
	}
  if( vpn_realm_str ){
  	_rhp_free(vpn_realm_str);
  }
  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_ENUM_REALMS_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  return err;
}



static int _rhp_ui_http_cfg_node_update_realm_time(xmlNodePtr node,time_t created_time,time_t updated_time,
		time_t sess_resume_policy_index,int update_sess_resume_policy_index)
{
	xmlAttrPtr created_time_attr = NULL;
	char created_time_str[32];

	if( !update_sess_resume_policy_index && created_time > -1 ){

		created_time_str[0] = '\0';
		snprintf(created_time_str,32,"%lld",(int64_t)created_time);

		created_time_attr =	xmlHasProp(node,(xmlChar*)"created_time");

		if( xmlNewProp(node,(xmlChar*)"created_time",(xmlChar*)created_time_str) == NULL ){
			RHP_BUG("");
		}else{
			if( created_time_attr ){
				xmlRemoveProp(created_time_attr);
			}
		}

		created_time_attr =	xmlHasProp(node,(xmlChar*)"created_local_time");

		if( xmlNewProp(node,(xmlChar*)"created_local_time",
				(xmlChar*)_rhp_ui_http_cfg_realm_time_str(&created_time)) == NULL ){
			RHP_BUG("");
		}else{
			if( created_time_attr ){
				xmlRemoveProp(created_time_attr);
			}
		}
	}

	if( !update_sess_resume_policy_index && updated_time > -1 ){

		created_time_str[0] = '\0';
		snprintf(created_time_str,32,"%lld",(int64_t)updated_time);

		created_time_attr =	xmlHasProp(node,(xmlChar*)"updated_time");

		if( xmlNewProp(node,(xmlChar*)"updated_time",(xmlChar*)created_time_str) == NULL ){
			RHP_BUG("");
		}else{
			if( created_time_attr ){
				xmlRemoveProp(created_time_attr);
			}
		}

		created_time_attr =	xmlHasProp(node,(xmlChar*)"updated_local_time");

		if( xmlNewProp(node,(xmlChar*)"updated_local_time",
				(xmlChar*)_rhp_ui_http_cfg_realm_time_str(&updated_time)) == NULL ){
			RHP_BUG("");
		}else{
			if( created_time_attr ){
				xmlRemoveProp(created_time_attr);
			}
		}
	}

	if( sess_resume_policy_index > -1 ){

		created_time_str[0] = '\0';
		snprintf(created_time_str,32,"%lld",(int64_t)sess_resume_policy_index);

		created_time_attr =	xmlHasProp(node,(xmlChar*)"sess_resume_policy_index");

		if( xmlNewProp(node,(xmlChar*)"sess_resume_policy_index",(xmlChar*)created_time_str) == NULL ){
			RHP_BUG("");
		}else{
			if( created_time_attr ){
				xmlRemoveProp(created_time_attr);
			}
		}
	}

	return 0;
}

static int _rhp_ui_http_cfg_doc_enum_update_realm_time(xmlNodePtr node,void* ctx)
{
	int err = -EINVAL;
	rhp_ui_http_cfg_update_enum_ctx* enum_ctx = (rhp_ui_http_cfg_update_enum_ctx*)ctx;
	unsigned long elm_rlm_id;
	int ret_len;

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_DOC_NODE_UPDATE_REALM_TIME,"xxxxxuTTTd",node,enum_ctx,enum_ctx->cfg_parent,enum_ctx->new_node,enum_ctx->new_rlm,enum_ctx->rlm_id,enum_ctx->created_time,enum_ctx->updated_time,enum_ctx->sess_resume_policy_index,enum_ctx->update_sess_resume_policy_index);

  err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"id"),RHP_XML_DT_ULONG,&elm_rlm_id,&ret_len,NULL,0);
  if( !err ){

  	if( enum_ctx->rlm_id == elm_rlm_id ){

  	  if( enum_ctx->cfg_parent ){

				if( _rhp_ui_http_cfg_node_update_realm_time(node,
							enum_ctx->created_time,enum_ctx->updated_time,
							enum_ctx->sess_resume_policy_index,enum_ctx->update_sess_resume_policy_index) ){
			  	RHP_BUG("%d",enum_ctx->rlm_id);
				}
  	  }

  		return RHP_STATUS_ENUM_OK;
  	}

  }else{
  	RHP_BUG("%d",enum_ctx->rlm_id);
  }

  return 0;
}

static int _rhp_ui_http_cfg_doc_update_realm_time(unsigned long rlm_id,
		time_t created_time,time_t updated_time,
		time_t sess_resume_policy_index,int update_sess_resume_policy_index)
{
	int err = -EINVAL;
	xmlDocPtr cfg_doc = NULL;
	xmlNodePtr cfg_root_node = NULL;
	rhp_ui_http_cfg_update_enum_ctx enum_ctx;

	memset(&enum_ctx,0,sizeof(rhp_ui_http_cfg_update_enum_ctx));

	enum_ctx.rlm_id = rlm_id;
	enum_ctx.created_time = created_time;
	enum_ctx.updated_time = updated_time;
	enum_ctx.update_sess_resume_policy_index = update_sess_resume_policy_index;
	enum_ctx.sess_resume_policy_index = sess_resume_policy_index;


	cfg_doc = xmlParseFile(rhp_main_conf_path);
	if( cfg_doc == NULL ){
		RHP_BUG(" %s ",rhp_main_conf_path);
		err = -ENOENT;
		goto error;
	}

	cfg_root_node = xmlDocGetRootElement(cfg_doc);
	if( cfg_root_node == NULL ){
		RHP_BUG(" %s ",rhp_main_conf_path);
		err = -ENOENT;
		goto error;
	}

	enum_ctx.cfg_parent = cfg_root_node;

  err = rhp_xml_enum_tags(cfg_root_node,
  		(xmlChar*)"vpn_realm",_rhp_ui_http_cfg_doc_enum_update_realm_time,(void*)&enum_ctx,1);

  if( err == RHP_STATUS_ENUM_OK || err == -ENOENT ){
  	err = 0;
  }else if( err ){
  	goto error;
  }

  err = rhp_cfg_save_config(rhp_main_conf_path,cfg_doc);
	if( err ){
		RHP_BUG("%d",err);
	}

	if( cfg_doc ){
		xmlFreeDoc(cfg_doc);
	}

	return 0;

error:
	return err;
}


static void _rhp_ui_http_cfg_update_realm_time(rhp_vpn_realm* updated_rlm, time_t old_created_time,
		int update_sess_resume_policy_index)
{
	time_t now = _rhp_get_realtime();
	if( !update_sess_resume_policy_index ){
		updated_rlm->realm_created_time = old_created_time;
		updated_rlm->realm_updated_time = now;
	}
	updated_rlm->sess_resume_policy_index = now;
}

static int _rhp_ui_http_cfg_update_realm_time_lock(unsigned long rlm_id,
		time_t* created_time_r,time_t* updated_time_r,
		time_t* sess_resume_policy_index_r,int update_sess_resume_policy_index)
{
	rhp_vpn_realm* updated_rlm = NULL;
	time_t old_created_time = -1;

	updated_rlm = rhp_realm_get(rlm_id);
	if( updated_rlm ){

		RHP_LOCK(&(updated_rlm->lock));

		old_created_time = updated_rlm->realm_created_time;

		_rhp_ui_http_cfg_update_realm_time(updated_rlm,old_created_time,
				update_sess_resume_policy_index);

		if( created_time_r ){
			*created_time_r = updated_rlm->realm_created_time;
		}
		if( updated_time_r ){
			*updated_time_r = updated_rlm->realm_updated_time;
		}
		if( sess_resume_policy_index_r ){
			*sess_resume_policy_index_r = updated_rlm->sess_resume_policy_index;
		}

		RHP_UNLOCK(&(updated_rlm->lock));

		rhp_realm_unhold(updated_rlm);

		return 0;
	}

	return -ENOENT;
}

static int _rhp_ui_http_cfg_update_realm_update_node(xmlNodePtr node,void* ctx)
{
	int err = -EINVAL;
	rhp_ui_http_cfg_update_enum_ctx* enum_ctx = (rhp_ui_http_cfg_update_enum_ctx*)ctx;
  xmlNodePtr dup_node = NULL;
	unsigned long elm_rlm_id;
	int ret_len;

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_UPDATE_REALM_UPDATE_NODE,"xxxxxuTTT",node,enum_ctx,enum_ctx->cfg_parent,enum_ctx->new_node,enum_ctx->new_rlm,enum_ctx->rlm_id,enum_ctx->created_time,enum_ctx->updated_time,enum_ctx->sess_resume_policy_index);

  err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"id"),RHP_XML_DT_ULONG,&elm_rlm_id,&ret_len,NULL,0);
  if( !err ){

  	if( enum_ctx->rlm_id == elm_rlm_id ){

  		xmlUnlinkNode(node);

  	  if( enum_ctx->cfg_parent ){

  	  	dup_node = xmlCopyNode(enum_ctx->new_node,1);
  			if( dup_node ){

  				if( _rhp_ui_http_cfg_node_update_realm_time(dup_node,
  							enum_ctx->created_time,enum_ctx->updated_time,
  							enum_ctx->sess_resume_policy_index,enum_ctx->update_sess_resume_policy_index) ){
  			  	RHP_BUG("%d",enum_ctx->rlm_id);
  				}

  				if( xmlAddChild(enum_ctx->cfg_parent,dup_node) == NULL ){
  			  	RHP_BUG("%d",enum_ctx->rlm_id);
  				}

  			}else{
  		  	RHP_BUG("%d",enum_ctx->rlm_id);
  			}
  	  }

  	  xmlFreeNode(node);

  		return RHP_STATUS_ENUM_OK;
  	}

  }else{
  	RHP_BUG("%d",enum_ctx->rlm_id);
  }

  return 0;
}

static int _rhp_ui_http_cfg_update_realm_serialize(void* http_bus_sess_d,void* ctx,void* writer,int idx)
{
	rhp_http_bus_session* http_bus_sess = (rhp_http_bus_session*) http_bus_sess_d;
	unsigned long rlm_id = (unsigned long)ctx;

  int err = -EINVAL;
  int n = 0;
  int n2 = 0;

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_UPDATE_REALM_SERIALIZE,"xxdu",http_bus_sess,writer,idx,rlm_id);

  n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"rhp_http_bus_record");
  if(n < 0) {
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"index","%d",idx);
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"service",(xmlChar*)"ui_http_vpn");
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"action",(xmlChar*)"realm_config_updated");
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"session_id","%llu",http_bus_sess->session_id);
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"vpn_realm_id","%lu",rlm_id);
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;


  n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
  if(n < 0) {
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_UPDATE_REALM_SERIALIZE_RTRN,"xud",http_bus_sess,rlm_id,n2);
  return n2;

error:
	RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_UPDATE_REALM_SERIALIZE_ERR,"xuE",http_bus_sess,rlm_id,err);
  return err;
}

static int _rhp_ui_http_cfg_update_realm_state_serialize(rhp_http_bus_session* http_bus_sess,void* ctx,void* writer,int idx)
{
  int err = -EINVAL;
  int n = 0;
  int n2 = 0;
  unsigned long rlm_id = (unsigned long)ctx;

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_UPDATE_REALM_STATE_SERIALIZE,"xuxd",http_bus_sess,rlm_id,writer,idx);


	n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"rhp_http_bus_record");
	if(n < 0) {
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"index","%d",idx);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"service",(xmlChar*)"ui_http_vpn");
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"action",(xmlChar*)"config_update_realm_state");
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"session_id","%llu",http_bus_sess->session_id);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"vpn_realm_id","%lu",rlm_id);
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

	n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
	if(n < 0) {
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_UPDATE_REALM_STATE_SERIALIZE_RTRN,"xd",http_bus_sess,n2);
  return n2;

error:
  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_UPDATE_REALM_STATE_SERIALIZE_ERR,"xE",http_bus_sess,err);
  return err;
}

static int _rhp_ui_http_cfg_update_realm_state(xmlDocPtr doc,xmlNodePtr node,rhp_http_conn* http_conn,
		rhp_http_bus_session* http_bus_sess,rhp_http_request* http_req,void* ctx)
{
  int err = -EINVAL;
  char *vpn_realm_str = NULL, *action_str = NULL;
  char* endp;
  unsigned long rlm_id = RHP_VPN_REALM_ID_UNKNOWN;
  int update_sess_resume_policy_index = 0;

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_UPDATE_REALM_STATE,"xxxxxx",doc,node,http_conn,http_bus_sess,http_req,ctx);

  if( doc == NULL || node == NULL ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_UPDATE_REALM_STATE_NO_DOC_NODE,"xxx",http_conn,http_bus_sess,http_req);
    return -EINVAL;
  }


  vpn_realm_str = (char*)rhp_xml_get_prop(node,(const xmlChar*)"vpn_realm");
  if( vpn_realm_str ){

		rlm_id = strtoul((char*)vpn_realm_str,&endp,0);
		if( (rlm_id == ULONG_MAX && errno == ERANGE) || *endp != '\0' ){
			err = -ENOENT;
			RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_UPDATE_REALM_STATE_NO_ENT,"xxxuus",http_conn,http_bus_sess,http_req,http_conn->user_realm_id,http_bus_sess->user_realm_id,vpn_realm_str);
			goto error;
		}

		if( _rhp_ui_http_permitted(http_conn,http_bus_sess,rlm_id) ){
				err = -EPERM;
				RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_UPDATE_REALM_STATE_NOT_PERMITTED,"xxxuu",http_conn,http_bus_sess,http_req,http_conn->user_realm_id,http_bus_sess->user_realm_id);
				goto error;
		}

  }else{

		if( _rhp_ui_http_get_user_realm_id(http_conn,http_bus_sess,&rlm_id)  ){
	  	err = -EPERM;
			RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_UPDATE_REALM_STATE_NOT_PERMITTED_2,"xxxuu",http_conn,http_bus_sess,http_req,http_conn->user_realm_id,http_bus_sess->user_realm_id);
			goto error;
	  }
  }

  if( rlm_id == 0 || rlm_id > RHP_VPN_REALM_ID_MAX ){
  	err = -EPERM;
		goto error;
  }


  action_str = (char*)rhp_xml_get_prop(node,(const xmlChar*)"state_action");
  if( action_str && !strcmp(action_str,"sess_resume_policy_index") ){
  	update_sess_resume_policy_index = 1;
  }


  {
  	time_t created_time = -1, updated_time = -1, sess_resume_policy_index = -1;

		if( !_rhp_ui_http_cfg_update_realm_time_lock(rlm_id,
						&created_time,
						&updated_time,
						&sess_resume_policy_index,update_sess_resume_policy_index) ){

			if( _rhp_ui_http_cfg_doc_update_realm_time(rlm_id,
						created_time,updated_time,
						sess_resume_policy_index,update_sess_resume_policy_index) ){
				RHP_BUG("%d",rlm_id);
			}

			if( update_sess_resume_policy_index ){

				RHP_LOG_I(RHP_LOG_SRC_UI,rlm_id,RHP_LOG_ID_INVALIDATE_SESS_RESUME_TKTS,"TTT",sess_resume_policy_index,created_time,updated_time);
			}

		}else{

			RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_UPDATE_REALM_STATE_NO_ENT,"xxxxxu",doc,node,http_conn,http_bus_sess,http_req,rlm_id);
  		err = -ENOENT;
  		goto error;
		}
  }

	err = rhp_http_bus_send_response(
			http_conn,http_bus_sess,_rhp_ui_http_cfg_update_realm_state_serialize,rlm_id);

	if( err ){
  	goto error;
  }

	rhp_http_bus_broadcast_async(rlm_id,1,1,
		_rhp_ui_http_cfg_update_realm_serialize,NULL,(void*)rlm_id);


  if( vpn_realm_str ){
  	_rhp_free(vpn_realm_str);
  }

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_UPDATE_REALM_STATE_RTRN,"xxx",http_conn,http_bus_sess,http_req);
  return RHP_STATUS_CLOSE_HTTP_CONN;

error:
  if( vpn_realm_str ){
  	_rhp_free(vpn_realm_str);
  }
  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_UPDATE_REALM_STATE_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  return err;
}


static int _rhp_ui_http_hostname_serialize(rhp_http_bus_session* http_bus_sess,void* ctx,void* writer,int idx)
{
  int err = -EINVAL;
  int n = 0;
  int n2 = 0;
  char hostname[HOST_NAME_MAX + 4];
  size_t len = HOST_NAME_MAX + 1;

  RHP_TRC(0,RHPTRCID_UI_HTTP_GET_HOSTNAME_SERIALIZE,"xxd",http_bus_sess,writer,idx);

  memset(hostname,0,HOST_NAME_MAX + 4);

	n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"rhp_http_bus_record");
	if(n < 0) {
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"index","%d",idx);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"service",(xmlChar*)"ui_http_vpn");
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"action",(xmlChar*)"get_hostname");
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"session_id","%llu",http_bus_sess->session_id);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	if( gethostname(hostname,len) < 0 ){
		err = -errno;
		RHP_BUG("");
		goto error;
	}

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"hostname","%s",hostname);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;


	n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
	if(n < 0) {
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  RHP_TRC(0,RHPTRCID_UI_HTTP_GET_HOSTNAME_SERIALIZE_RTRN,"xds",http_bus_sess,n2,hostname);
  return n2;

error:
  RHP_TRC(0,RHPTRCID_UI_HTTP_GET_HOSTNAME_SERIALIZE_ERR,"xE",http_bus_sess,err);
  return err;
}

static int _rhp_ui_http_get_hostname(xmlDocPtr doc,xmlNodePtr node,rhp_http_conn* http_conn,
		rhp_http_bus_session* http_bus_sess,rhp_http_request* http_req,void* ctx)
{
  int err = -EINVAL;

  RHP_TRC(0,RHPTRCID_UI_HTTP_GET_HOSTNAME,"xxxxxx",doc,node,http_conn,http_bus_sess,http_req,ctx);

  if( doc == NULL || node == NULL ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_GET_HOSTNAME_NO_DOC_NODE,"xxx",http_conn,http_bus_sess,http_req);
    return -EINVAL;
  }

	err = rhp_http_bus_send_response(
			http_conn,http_bus_sess,_rhp_ui_http_hostname_serialize,NULL);

	if( err ){
  	goto error;
  }

  RHP_TRC(0,RHPTRCID_UI_HTTP_GET_HOSTNAME_RTRN,"xxx",http_conn,http_bus_sess,http_req);
  return RHP_STATUS_CLOSE_HTTP_CONN;

error:
  RHP_TRC(0,RHPTRCID_UI_HTTP_GET_HOSTNAME_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  return err;
}


static int _rhp_ui_http_status_enum_interfaces_cb(rhp_ifc_entry* ifc,void* ctx)
{
  int err = -EINVAL;
  int n;
  rhp_ui_http_enum_ctx* enum_ctx = (rhp_ui_http_enum_ctx*)ctx;

  RHP_TRC(0,RHPTRCID_UI_HTTP_STATUS_ENUM_INTERFACES_CB,"xx",ifc,ctx);

  if( enum_ctx->rlm_id && ifc->tuntap_vpn_realm_id &&
  		enum_ctx->rlm_id != ifc->tuntap_vpn_realm_id){
    RHP_TRC(0,RHPTRCID_UI_HTTP_STATUS_ENUM_INTERFACES_CB_RLM_NOT_MATCH,"xxuu",ifc,ctx,enum_ctx->rlm_id,ifc->tuntap_vpn_realm_id);
  	return 0;
  }

  n = xmlTextWriterStartElement((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"interface");
  if(n < 0) {
    err = -ENOMEM;
    RHP_BUG("");
    goto error_nl;
  }
  *(enum_ctx->n2) += n;


  RHP_LOCK(&(ifc->lock));

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"id","%d",ifc->if_index);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
  *(enum_ctx->n2) += n;

	n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"name",(xmlChar*)ifc->if_name);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
  *(enum_ctx->n2) += n;


	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"mac",
			"%02x:%02x:%02x:%02x:%02x:%02x",
			ifc->mac[0],ifc->mac[1],ifc->mac[2],ifc->mac[3],ifc->mac[4],ifc->mac[5]);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
  *(enum_ctx->n2) += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,
			(xmlChar*)"mtu","%u",ifc->mtu);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
  *(enum_ctx->n2) += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,
  		(xmlChar*)"vpn_realm","%lu",ifc->tuntap_vpn_realm_id);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
  *(enum_ctx->n2) += n;

  if( !ifc->tuntap_vpn_realm_id ){

  	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,
  				(xmlChar*)"used","%ld",
  				(rhp_ifc_cfg_users(ifc,AF_INET) + rhp_ifc_cfg_users(ifc,AF_INET6)));
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
  	*(enum_ctx->n2) += n;

  }else{

  	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,
  				(xmlChar*)"tuntap_activated","%d",(ifc->tuntap_fd >= 0 ? 1 : 0));
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
  	*(enum_ctx->n2) += n;


  	if( ifc->v6_aux_lladdr.state == RHP_V6_LINK_LOCAL_ADDR_AVAILABLE ){

  		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"v6_aux_lladdr_mac",
  				"%02x:%02x:%02x:%02x:%02x:%02x",
  				ifc->v6_aux_lladdr.mac[0],ifc->v6_aux_lladdr.mac[1],
  				ifc->v6_aux_lladdr.mac[2],ifc->v6_aux_lladdr.mac[3],
  				ifc->v6_aux_lladdr.mac[4],ifc->v6_aux_lladdr.mac[5]);
  		if(n < 0){
  			err = -ENOMEM;
  			RHP_BUG("");
  			goto error;
  		}
  	  *(enum_ctx->n2) += n;

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"v6_aux_lladdr_lladdr",
					"%s",rhp_ipv6_string(ifc->v6_aux_lladdr.lladdr.addr.v6));
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*(enum_ctx->n2) += n;
  	}
  }

  RHP_UNLOCK(&(ifc->lock));



  if( ifc->tuntap_vpn_realm_id ){ // TUN/TAP

  	rhp_vpn_realm* rlm = rhp_realm_get(ifc->tuntap_vpn_realm_id);
  	if( rlm ){

  	  RHP_LOCK(&(rlm->lock));

  	  if( rlm->internal_ifc ){

  	  	switch( rlm->internal_ifc->addrs_type ){
  	  	case RHP_VIF_ADDR_STATIC:
    			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"address_type",
    					"%s","static");
  	  		break;
  	  	case RHP_VIF_ADDR_IKEV2CFG:
    			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"address_type",
    					"%s","ikev2cfg");
  	  		break;
  	  	case RHP_VIF_ADDR_DHCP:
    			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"address_type",
    					"%s","dhcp");
  	  		break;
  	  	case RHP_VIF_ADDR_NONE:
    			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"address_type",
    					"%s","unnumbered");
  	  		break;
  	  	default:
    			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"address_type",
    					"%s","unknown");
  	  		break;
  	  	}
  			if(n < 0){
  				err = -ENOMEM;
  				RHP_BUG("");
  	  	  RHP_UNLOCK(&(rlm->lock));
  	  	  rhp_realm_unhold(rlm);
  				goto error_nl;
  			}
  			*(enum_ctx->n2) += n;


				if( rlm->internal_ifc->gw_addr.addr_family == AF_INET ){

					u32 ip = rlm->internal_ifc->gw_addr.addr.v4;

					n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,
							(xmlChar*)"internal_gateway_addr_v4","%d.%d.%d.%d",
							((u8*)&ip)[0],((u8*)&ip)[1],((u8*)&ip)[2],((u8*)&ip)[3]);
	  			if(n < 0){
	  				err = -ENOMEM;
	  				RHP_BUG("");
	  	  	  RHP_UNLOCK(&(rlm->lock));
	  	  	  rhp_realm_unhold(rlm);
	  				goto error_nl;
	  			}
	  			*(enum_ctx->n2) += n;
				}

				if( rlm->internal_ifc->gw_addr_v6.addr_family == AF_INET6 ){

					n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,
							(xmlChar*)"internal_gateway_addr_v6","%s",
							rhp_ipv6_string(rlm->internal_ifc->gw_addr_v6.addr.v6));
	  			if(n < 0){
	  				err = -ENOMEM;
	  				RHP_BUG("");
	  	  	  RHP_UNLOCK(&(rlm->lock));
	  	  	  rhp_realm_unhold(rlm);
	  				goto error_nl;
	  			}
	  			*(enum_ctx->n2) += n;
				}

				if( rlm->internal_ifc->sys_def_gw_addr.addr_family == AF_INET ){

					u32 ip = rlm->internal_ifc->sys_def_gw_addr.addr.v4;

					n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,
							(xmlChar*)"internal_sys_def_gateway_addr_v4","%d.%d.%d.%d",
							((u8*)&ip)[0],((u8*)&ip)[1],((u8*)&ip)[2],((u8*)&ip)[3]);
	  			if(n < 0){
	  				err = -ENOMEM;
	  				RHP_BUG("");
	  	  	  RHP_UNLOCK(&(rlm->lock));
	  	  	  rhp_realm_unhold(rlm);
	  				goto error_nl;
	  			}
	  			*(enum_ctx->n2) += n;
				}

				if( rlm->internal_ifc->sys_def_gw_addr_v6.addr_family == AF_INET6 ){

					n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,
							(xmlChar*)"internal_sys_def_gateway_addr_v6","%s",
							rhp_ipv6_string(rlm->internal_ifc->sys_def_gw_addr_v6.addr.v6));
	  			if(n < 0){
	  				err = -ENOMEM;
	  				RHP_BUG("");
	  	  	  RHP_UNLOCK(&(rlm->lock));
	  	  	  rhp_realm_unhold(rlm);
	  				goto error_nl;
	  			}
	  			*(enum_ctx->n2) += n;
				}


				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,
						(xmlChar*)"fixed_mtu","%d",rlm->internal_ifc->fixed_mtu);
  			if(n < 0){
  				err = -ENOMEM;
  				RHP_BUG("");
  	  	  RHP_UNLOCK(&(rlm->lock));
  	  	  rhp_realm_unhold(rlm);
  				goto error_nl;
  			}
  			*(enum_ctx->n2) += n;

				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,
						(xmlChar*)"default_mtu","%d",rlm->internal_ifc->default_mtu);
  			if(n < 0){
  				err = -ENOMEM;
  				RHP_BUG("");
  	  	  RHP_UNLOCK(&(rlm->lock));
  	  	  rhp_realm_unhold(rlm);
  				goto error_nl;
  			}
  			*(enum_ctx->n2) += n;


  			if( rlm->internal_ifc->bridge_name ){

  				rhp_ip_addr_list* br_ifc_addr = rlm->internal_ifc->bridge_addrs;

  				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,
  						(xmlChar*)"bridge_name","%s",rlm->internal_ifc->bridge_name);
    			if(n < 0){
    				err = -ENOMEM;
    				RHP_BUG("");
    	  	  RHP_UNLOCK(&(rlm->lock));
    	  	  rhp_realm_unhold(rlm);
    				goto error_nl;
    			}
    			*(enum_ctx->n2) += n;

  				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,
  						(xmlChar*)"bridge_def_mtu","%d",rlm->internal_ifc->bridge_def_mtu);
    			if(n < 0){
    				err = -ENOMEM;
    				RHP_BUG("");
    	  	  RHP_UNLOCK(&(rlm->lock));
    	  	  rhp_realm_unhold(rlm);
    				goto error_nl;
    			}
    			*(enum_ctx->n2) += n;


					while( br_ifc_addr ){

						n = xmlTextWriterStartElement((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"bridge_interface_address");
						if(n < 0) {
							err = -ENOMEM;
							RHP_BUG("");
							RHP_UNLOCK(&(rlm->lock));
				  	  rhp_realm_unhold(rlm);
							goto error_nl;
						}
						*(enum_ctx->n2) += n;

						if( br_ifc_addr->ip_addr.addr_family == AF_INET ){

							n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"address_v4","%d.%d.%d.%d/%d",
									br_ifc_addr->ip_addr.addr.raw[0],br_ifc_addr->ip_addr.addr.raw[1],
									br_ifc_addr->ip_addr.addr.raw[2],br_ifc_addr->ip_addr.addr.raw[3],
									br_ifc_addr->ip_addr.prefixlen);
							if(n < 0){
								err = -ENOMEM;
								RHP_BUG("");
								RHP_UNLOCK(&(rlm->lock));
					  	  rhp_realm_unhold(rlm);
								goto error_nl;
							}
							*(enum_ctx->n2) += n;

						}else	if( br_ifc_addr->ip_addr.addr_family == AF_INET6 ){

							n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"address_v6",
									"%s/%d",rhp_ipv6_string(br_ifc_addr->ip_addr.addr.v6),br_ifc_addr->ip_addr.prefixlen);
							if(n < 0){
								err = -ENOMEM;
								RHP_BUG("");
								RHP_UNLOCK(&(rlm->lock));
					  	  rhp_realm_unhold(rlm);
								goto error_nl;
							}
							*(enum_ctx->n2) += n;
						}

					  n = xmlTextWriterEndElement((xmlTextWriterPtr)enum_ctx->writer);
						if(n < 0) {
							err = -ENOMEM;
							RHP_BUG("");
							RHP_UNLOCK(&(rlm->lock));
				  	  rhp_realm_unhold(rlm);
							goto error_nl;
						}
						*(enum_ctx->n2) += n;

						br_ifc_addr = br_ifc_addr->next;
					}
  			}
  	  }

  	  RHP_UNLOCK(&(rlm->lock));
  	  rhp_realm_unhold(rlm);
  	}
  }


  RHP_LOCK(&(ifc->lock));

  {
  	rhp_ifc_addr* ifc_addr = ifc->ifc_addrs;
  	while( ifc_addr ){

  	  n = xmlTextWriterStartElement((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"interface_address");
  	  if(n < 0) {
  	    err = -ENOMEM;
  	    RHP_BUG("");
  	    goto error;
  	  }
  	  *(enum_ctx->n2) += n;

			if( ifc_addr->addr.addr_family == AF_INET ){

				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"address_v4","%d.%d.%d.%d",
						ifc_addr->addr.addr.raw[0],ifc_addr->addr.addr.raw[1],ifc_addr->addr.addr.raw[2],ifc_addr->addr.addr.raw[3]);
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error;
				}
				*(enum_ctx->n2) += n;

			}else	if( ifc_addr->addr.addr_family == AF_INET6 ){

				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"address_v6",
						"%s",rhp_ipv6_string(ifc_addr->addr.addr.v6));
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error;
				}
				*(enum_ctx->n2) += n;
			}

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"prefix_length","%d",
					ifc_addr->addr.prefixlen);
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*(enum_ctx->n2) += n;

		  n = xmlTextWriterEndElement((xmlTextWriterPtr)enum_ctx->writer);
			if(n < 0) {
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
		  *(enum_ctx->n2) += n;

			ifc_addr = ifc_addr->lst_next;
  	}
  }



  n = xmlTextWriterStartElement((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"statistics");
  if(n < 0) {
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  *(enum_ctx->n2) += n;


  if( ifc->tuntap_vpn_realm_id ){ // TUN/TAP

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"read_packets","%llu",ifc->statistics.tuntap.read_pkts);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"read_arp_packets","%llu",ifc->statistics.tuntap.read_arp_pkts);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"read_ipv4_packets","%llu",ifc->statistics.tuntap.read_ipv4_pkts);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"read_ipv4_icmp_packets","%llu",ifc->statistics.tuntap.read_ipv4_icmp_pkts);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"read_ipv4_tcp_packets","%llu",ifc->statistics.tuntap.read_ipv4_tcp_pkts);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"read_ipv4_udp_packets","%llu",ifc->statistics.tuntap.read_ipv4_udp_pkts);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"read_ipv4_other_packets","%llu",ifc->statistics.tuntap.read_ipv4_other_pkts);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"read_ipv6_packets","%llu",ifc->statistics.tuntap.read_ipv6_pkts);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"read_other_packets","%llu",ifc->statistics.tuntap.read_other_pkts);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"read_err_packets","%llu",ifc->statistics.tuntap.read_err_pkts);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"read_err_arp_packets","%llu",ifc->statistics.tuntap.read_err_arp_pkts);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"read_err_ipv4_packets","%llu",ifc->statistics.tuntap.read_err_ipv4_pkts);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"read_err_ipv4_icmp_packets","%llu",ifc->statistics.tuntap.read_err_ipv4_icmp_pkts);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"read_err_ipv4_tcp_packets","%llu",ifc->statistics.tuntap.read_err_ipv4_tcp_pkts);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"read_err_ipv4_udp_packets","%llu",ifc->statistics.tuntap.read_err_ipv4_udp_pkts);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"read_err_ipv4_other_packets","%llu",ifc->statistics.tuntap.read_err_ipv4_other_pkts);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"read_err_ipv6_packets","%llu",ifc->statistics.tuntap.read_err_ipv6_pkts);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"read_err_other_packets","%llu",ifc->statistics.tuntap.read_err_other_pkts);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"read_bytes","%llu",ifc->statistics.tuntap.read_bytes);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;


    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"tx_esp_pend_packets","%ld",_rhp_atomic_flag_read_cnt(&(ifc->tx_esp_pkt_pend_flag)));
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"read_stop","%llu",ifc->statistics.tuntap.read_stop);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"read_restart","%llu",ifc->statistics.tuntap.read_restart);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"write_packets","%llu",ifc->statistics.tuntap.write_pkts);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"write_arp_packets","%llu",ifc->statistics.tuntap.write_arp_pkts);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"write_ipv4_packets","%llu",ifc->statistics.tuntap.write_ipv4_pkts);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"write_ipv4_icmp_packets","%llu",ifc->statistics.tuntap.write_ipv4_icmp_pkts);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"write_ipv4_tcp_packets","%llu",ifc->statistics.tuntap.write_ipv4_tcp_pkts);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"write_ipv4_udp_packets","%llu",ifc->statistics.tuntap.write_ipv4_udp_pkts);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"write_ipv4_other_packets","%llu",ifc->statistics.tuntap.write_ipv4_other_pkts);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"write_ipv6_packets","%llu",ifc->statistics.tuntap.write_ipv6_pkts);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"write_other_packets","%llu",ifc->statistics.tuntap.write_other_pkts);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"write_err_packets","%llu",ifc->statistics.tuntap.write_err_pkts);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"write_err_arp_packets","%llu",ifc->statistics.tuntap.write_err_arp_pkts);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"write_err_ipv4_packets","%llu",ifc->statistics.tuntap.write_err_ipv4_pkts);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"write_err_ipv4_icmp_packets","%llu",ifc->statistics.tuntap.write_err_ipv4_icmp_pkts);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"write_err_ipv4_tcp_packets","%llu",ifc->statistics.tuntap.write_err_ipv4_tcp_pkts);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"write_err_ipv4_udp_packets","%llu",ifc->statistics.tuntap.write_err_ipv4_udp_pkts);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"write_err_ipv4_other_packets","%llu",ifc->statistics.tuntap.write_err_ipv4_other_pkts);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"write_err_ipv6_packets","%llu",ifc->statistics.tuntap.write_err_ipv6_pkts);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"write_err_other_packets","%llu",ifc->statistics.tuntap.write_err_other_pkts);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"write_bytes","%llu",ifc->statistics.tuntap.write_bytes);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"bridge_rx_from_tuntap","%llu",ifc->statistics.tuntap.bridge_rx_from_tuntap);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"drop_icmpv6_router_adv","%llu",ifc->statistics.tuntap.drop_icmpv6_router_adv);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"drop_icmpv6_router_solicit","%llu",ifc->statistics.tuntap.drop_icmpv6_router_solicit);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

  }else{

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"rx_packets","%llu",ifc->statistics.netif.rx_pkts);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"rx_err_packets","%llu",ifc->statistics.netif.rx_err_pkts);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"rx_trunc_err_packets","%llu",ifc->statistics.netif.rx_trunc_err_pkts);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"rx_invalid_packets","%llu",ifc->statistics.netif.rx_invalid_pkts);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"rx_bytes","%llu",ifc->statistics.netif.rx_bytes);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"rx_ikev2_packets","%llu",ifc->statistics.netif.rx_ikev2_pkts);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"rx_ikev2_nat_t_packets","%llu",ifc->statistics.netif.rx_ikev2_nat_t_pkts);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"rx_esp_nat_t_packets","%llu",ifc->statistics.netif.rx_esp_nat_t_pkts);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"rx_esp_packets","%llu",ifc->statistics.netif.rx_esp_pkts);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"rx_ikev2_nat_t_err_packets","%llu",ifc->statistics.netif.rx_ikev2_nat_t_err_pkts);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"rx_ikev2_err_packets","%llu",ifc->statistics.netif.rx_ikev2_err_pkts);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"rx_esp_nat_t_err_packets","%llu",ifc->statistics.netif.rx_esp_nat_t_err_pkts);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"rx_esp_err_packets","%llu",ifc->statistics.netif.rx_esp_err_pkts);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"rx_ikev2_invalid_packets","%llu",ifc->statistics.netif.rx_ikev2_invalid_pkts);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"rx_ikev2_nat_t_invalid_packets","%llu",ifc->statistics.netif.rx_ikev2_nat_t_invalid_pkts);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"rx_esp_nat_t_invalid_packets","%llu",ifc->statistics.netif.rx_esp_nat_t_invalid_pkts);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"rx_esp_invalid_packets","%llu",ifc->statistics.netif.rx_esp_invalid_pkts);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"rx_ikev2_trunc_err_packets","%llu",ifc->statistics.netif.rx_ikev2_sk_trunc_err_pkts);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"rx_nat_t_trunc_err_packets","%llu",ifc->statistics.netif.rx_nat_t_sk_trunc_err_pkts);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"rx_esp_trunc_err_packets","%llu",ifc->statistics.netif.rx_esp_raw_sk_trunc_err_pkts);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"rx_ikev2_too_large_packets","%llu",ifc->statistics.netif.rx_ikev2_too_large_pkts);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"rx_ikev2_nat_t_too_large_packets","%llu",ifc->statistics.netif.rx_ikev2_nat_t_too_large_pkts);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"rx_ikev2_bytes","%llu",ifc->statistics.netif.rx_ikev2_bytes);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"rx_ikev2_nat_t_bytes","%llu",ifc->statistics.netif.rx_ikev2_nat_t_bytes);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"rx_esp_nat_t_bytes","%llu",ifc->statistics.netif.rx_esp_nat_t_bytes);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"rx_esp_bytes","%llu",ifc->statistics.netif.rx_esp_bytes);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;


    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"rx_esp_pend_packets","%ld",_rhp_atomic_flag_read_cnt(&(ifc->rx_esp_pkt_pend_flag)));
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"rx_stop","%llu",ifc->statistics.netif.rx_stop);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"rx_restart","%llu",ifc->statistics.netif.rx_restart);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"rx_net_events","%llu",ifc->statistics.netif.rx_net_events);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"rx_net_err_events","%llu",ifc->statistics.netif.rx_net_err_events);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"rx_nat_t_keepalive_packets","%llu",ifc->statistics.netif.rx_nat_t_keep_alive_pkts);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"tx_packets","%llu",ifc->statistics.netif.tx_pkts);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"tx_ikev2_packets","%llu",ifc->statistics.netif.tx_ikev2_pkts);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"tx_ikev2_nat_t_packets","%llu",ifc->statistics.netif.tx_ikev2_nat_t_pkts);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"tx_esp_nat_t_packets","%llu",ifc->statistics.netif.tx_esp_nat_t_pkts);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"tx_esp_packets","%llu",ifc->statistics.netif.tx_esp_pkts);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"tx_err_packets","%llu",ifc->statistics.netif.tx_err_pkts);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"tx_ikev2_err_packets","%llu",ifc->statistics.netif.tx_ikev2_err_pkts);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"tx_ikev2_nat_t_err_packets","%llu",ifc->statistics.netif.tx_ikev2_nat_t_err_pkts);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"tx_esp_nat_t_err_packets","%llu",ifc->statistics.netif.tx_esp_nat_t_err_pkts);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"tx_esp_err_packets","%llu",ifc->statistics.netif.tx_esp_err_pkts);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"tx_bytes","%llu",ifc->statistics.netif.tx_bytes);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"tx_ikev2_bytes","%llu",ifc->statistics.netif.tx_ikev2_bytes);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"tx_ikev2_nat_t_bytes","%llu",ifc->statistics.netif.tx_ikev2_nat_t_bytes);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"tx_esp_nat_t_bytes","%llu",ifc->statistics.netif.tx_esp_nat_t_bytes);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"tx_esp_bytes","%llu",ifc->statistics.netif.tx_esp_bytes);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;

    n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)enum_ctx->writer,(xmlChar*)"tx_nat_t_keepalive_packets","%llu",ifc->statistics.netif.tx_nat_t_keep_alive_pkts);
  	if(n < 0){
  		err = -ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}
    *(enum_ctx->n2) += n;
  }


  n = xmlTextWriterEndElement((xmlTextWriterPtr)enum_ctx->writer);
	if(n < 0) {
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
  *(enum_ctx->n2) += n;


  RHP_UNLOCK(&(ifc->lock));


  n = xmlTextWriterEndElement((xmlTextWriterPtr)enum_ctx->writer);
	if(n < 0) {
		err = -ENOMEM;
		RHP_BUG("");
		goto error_nl;
	}
  *(enum_ctx->n2) += n;

  RHP_TRC(0,RHPTRCID_UI_HTTP_STATUS_ENUM_INTERFACES_CB_RTRN,"xx",ifc,ctx);
  return 0;

error:
	RHP_UNLOCK(&(ifc->lock));
error_nl:
  RHP_TRC(0,RHPTRCID_UI_HTTP_STATUS_ENUM_INTERFACES_CB_ERR,"xxE",ifc,ctx,err);
	return err;
}

static int _rhp_ui_http_status_enum_interfaces_serialize(rhp_http_bus_session* http_bus_sess,void* ctx,void* writer,int idx)
{
  int err = -EINVAL;
  int n = 0;
  int n2 = 0;
  rhp_ui_http_enum_ctx enum_ctx;
  char* if_name_str = (char*)ctx;
  unsigned long rlm_id = http_bus_sess->user_realm_id;

  RHP_TRC(0,RHPTRCID_UI_HTTP_STATUS_ENUM_INTERFACES_SERIALIZE,"xxdu",http_bus_sess,writer,idx,rlm_id);

	n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"rhp_http_bus_record");
	if(n < 0) {
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"index","%d",idx);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"service",(xmlChar*)"ui_http_vpn");
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"action",(xmlChar*)"status_enum_interfaces");
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"session_id","%llu",http_bus_sess->session_id);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	enum_ctx.idx = 0;
	enum_ctx.writer = writer;
	enum_ctx.n2 = &n2;
	enum_ctx.rlm_id = rlm_id;

	if( if_name_str ){

		rhp_ifc_entry* ifc = rhp_ifc_get(if_name_str);
		if( ifc == NULL ){
			err = -ENOENT;
			goto error;
		}

		err = _rhp_ui_http_status_enum_interfaces_cb(ifc,(void*)&enum_ctx);
	  rhp_ifc_unhold(ifc);

		if( err ){
			goto error;
		}

	}else{

		err = rhp_ifc_enum(_rhp_ui_http_status_enum_interfaces_cb,(void*)&enum_ctx);
		if( err ){
			goto error;
		}
	}

	n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
	if(n < 0) {
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  RHP_TRC(0,RHPTRCID_UI_HTTP_STATUS_ENUM_INTERFACES_SERIALIZE_RTRN,"xd",http_bus_sess,n2);
  return n2;

error:
  RHP_TRC(0,RHPTRCID_UI_HTTP_STATUS_ENUM_INTERFACES_SERIALIZE_ERR,"xE",http_bus_sess,err);
  return err;
}

static int _rhp_ui_http_status_enum_interfaces(xmlDocPtr doc,xmlNodePtr node,rhp_http_conn* http_conn,
		rhp_http_bus_session* http_bus_sess,rhp_http_request* http_req,void* ctx)
{
  int err = -EINVAL;
  unsigned long rlm_id = RHP_VPN_REALM_ID_UNKNOWN;
  char* if_name_str = NULL;

  RHP_TRC(0,RHPTRCID_UI_HTTP_STATUS_ENUM_INTERFACES,"xxxxxx",doc,node,http_conn,http_bus_sess,http_req,ctx);

  if( doc == NULL || node == NULL ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_STATUS_ENUM_INTERFACES_NO_DOC_NODE,"xxx",http_conn,http_bus_sess,http_req);
    return -EINVAL;
  }

  if( _rhp_ui_http_get_user_realm_id(http_conn,http_bus_sess,&rlm_id)  ){
  	err = -EPERM;
		RHP_TRC(0,RHPTRCID_UI_HTTP_STATUS_ENUM_INTERFACES_NOT_PERMITTED,"xxxuu",http_conn,http_bus_sess,http_req,http_conn->user_realm_id,http_bus_sess->user_realm_id);
		goto error;
  }

  if_name_str = (char*)rhp_xml_get_prop(node,(const xmlChar*)"interface");
  if( if_name_str ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_STATUS_ENUM_INTERFACES_IFNAME,"xxxs",http_conn,http_bus_sess,http_req,if_name_str);
  }


	err = rhp_http_bus_send_response(
			http_conn,http_bus_sess,_rhp_ui_http_status_enum_interfaces_serialize,if_name_str);

	if( err ){
  	goto error;
  }

  if( if_name_str ){
  	_rhp_free(if_name_str);
  }

  RHP_TRC(0,RHPTRCID_UI_HTTP_STATUS_ENUM_INTERFACES_RTRN,"xxx",http_conn,http_bus_sess,http_req);
  return RHP_STATUS_CLOSE_HTTP_CONN;

error:
  if( if_name_str ){
  	_rhp_free(if_name_str);
  }
  RHP_TRC(0,RHPTRCID_UI_HTTP_STATUS_ENUM_INTERFACES_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  return err;
}



static int _rhp_ui_http_status_enum_realm_src_interfaces_serialize(rhp_http_bus_session* http_bus_sess,void* ctx,void* writer,int idx)
{
  int err = -EINVAL;
  int n = 0;
  int n2 = 0;
  rhp_ui_http_enum_ctx enum_ctx;
  rhp_vpn_realm* rlm = (rhp_vpn_realm*)ctx;

  RHP_TRC(0,RHPTRCID_UI_HTTP_STATUS_ENUM_REALM_SRC_INTERFACES_SERIALIZE,"xxxd",http_bus_sess,writer,rlm,idx);


	n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"rhp_http_bus_record");
	if(n < 0) {
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"index","%d",idx);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"service",(xmlChar*)"ui_http_vpn");
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"action",(xmlChar*)"status_enum_src_interfaces");
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"session_id","%llu",http_bus_sess->session_id);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"vpn_realm_id","%lu",rlm->id);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;


	{
		rhp_cfg_if* cfg_if = NULL;
		int priority = 1;
		int err2 = 0;

		// cfg_if->ifc is already linked to rlm->my_interfaces. rhp_ifc_hold() not needed;

		cfg_if = rlm->my_interfaces;

		while( cfg_if ){

			rhp_ifc_entry* ifc = cfg_if->ifc;

			if( ifc ){

				RHP_LOCK(&(ifc->lock));

				n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"interface");
				if(n < 0) {
					err = err2 = -ENOMEM;
					RHP_BUG("");
					goto error_ifc;
				}
				n2 += n;

				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"priority","%d",priority);
				if(n < 0) {
					err = err2 = -ENOMEM;
					RHP_BUG("");
					goto error_ifc;
				}
				n2 += n;

				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"cfg_priority","%d",cfg_if->priority);
				if(n < 0) {
					err = err2 = -ENOMEM;
					RHP_BUG("");
					goto error_ifc;
				}
				n2 += n;

				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"id","%d",ifc->if_index);
				if(n < 0) {
					err = err2 = -ENOMEM;
					RHP_BUG("");
					goto error_ifc;
				}
				n2 += n;

				n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"name",(xmlChar*)ifc->if_name);
				if(n < 0) {
					err = err2 = -ENOMEM;
					RHP_BUG("");
					goto error_ifc;
				}
				n2 += n;

				if( rhp_ifc_is_active(ifc,AF_UNSPEC,NULL) ){
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"status",(xmlChar*)"up");
				}else{
					n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"status",(xmlChar*)"down");
				}
				if(n < 0) {
					err = err2 = -ENOMEM;
					RHP_BUG("");
					goto error_ifc;
				}
				n2 += n;


				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"mac","%02x:%02x:%02x:%02x:%02x:%02x",
						ifc->mac[0],ifc->mac[1],ifc->mac[2],ifc->mac[3],ifc->mac[4],ifc->mac[5]);
				if(n < 0) {
					err = err2 = -ENOMEM;
					RHP_BUG("");
					goto error_ifc;
				}
				n2 += n;

				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"mtu","%u",ifc->mtu);
				if(n < 0) {
					err = err2 = -ENOMEM;
					RHP_BUG("");
					goto error_ifc;
				}
				n2 += n;

				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
						(xmlChar*)"is_def_route","%d",cfg_if->is_by_def_route);
				if(n < 0) {
					err = err2 = -ENOMEM;
					RHP_BUG("");
					goto error_ifc;
				}
				n2 += n;

				{
					char* ipver = "none";
					if( cfg_if->addr_family == AF_UNSPEC ){
						ipver = "all";
					}else if( cfg_if->addr_family == AF_INET ){
						ipver = "ipv4";
					}else if( cfg_if->addr_family == AF_INET6 ){
						ipver = "ipv6";
					}

					n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
							(xmlChar*)"ip_version","%s",ipver);
					if(n < 0) {
						err = err2 = -ENOMEM;
						RHP_BUG("");
						goto error_ifc;
					}
					n2 += n;
				}

				{
					rhp_ifc_addr* ifc_addr = ifc->ifc_addrs;
					while( ifc_addr ){

						n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"interface_address");
						if(n < 0) {
							err = err2 = -ENOMEM;
							RHP_BUG("");
							goto error_ifc;
						}
						n2 += n;

						if( ifc_addr->addr.addr_family == AF_INET ){

							n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"address_v4","%d.%d.%d.%d",
									ifc_addr->addr.addr.raw[0],ifc_addr->addr.addr.raw[1],ifc_addr->addr.addr.raw[2],ifc_addr->addr.addr.raw[3]);
							if(n < 0) {
								err = err2 = -ENOMEM;
								RHP_BUG("");
								goto error_ifc;
							}
							n2 += n;

						}else if( ifc_addr->addr.addr_family == AF_INET6 ){

							n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"address_v6",
									"%s",
									rhp_ipv6_string(ifc_addr->addr.addr.v6));

							if(n < 0) {
								err = err2 = -ENOMEM;
								RHP_BUG("");
								goto error_ifc;
							}
							n2 += n;
						}

						n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"prefix_length","%d",ifc_addr->addr.prefixlen);
						if(n < 0) {
							err = err2 = -ENOMEM;
							RHP_BUG("");
							goto error_ifc;
						}
						n2 += n;

						n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
						if(n < 0) {
							err = err2 = -ENOMEM;
							RHP_BUG("");
							goto error_ifc;
						}
						n2 += n;


						ifc_addr = ifc_addr->lst_next;
					}
				}

				n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
				if(n < 0) {
					err = err2 = -ENOMEM;
					RHP_BUG("");
					goto error_ifc;
				}
				n2 += n;

error_ifc:
				RHP_UNLOCK(&(ifc->lock));

				if( err2 ){
					goto error;
				}

				priority++;
			}

			cfg_if = cfg_if->next;
		}
	}


	n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
	if(n < 0) {
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  RHP_TRC(0,RHPTRCID_UI_HTTP_STATUS_ENUM_REALM_SRC_INTERFACES_SERIALIZE_RTRN,"xd",http_bus_sess,n2);
  return n2;

error:
  RHP_TRC(0,RHPTRCID_UI_HTTP_STATUS_ENUM_REALM_SRC_INTERFACES_SERIALIZE_ERR,"xE",http_bus_sess,err);
  return err;
}

static int _rhp_ui_http_status_enum_realm_src_interfaces(xmlDocPtr doc,xmlNodePtr node,rhp_http_conn* http_conn,
		rhp_http_bus_session* http_bus_sess,rhp_http_request* http_req,void* ctx)
{
  int err = -EINVAL;
  char* vpn_realm_str = NULL;
  unsigned long rlm_id;
  char* endp;
  rhp_vpn_realm* rlm = NULL;

  RHP_TRC(0,RHPTRCID_UI_HTTP_STATUS_ENUM_REALM_SRC_INTERFACES,"xxxxxx",doc,node,http_conn,http_bus_sess,http_req,ctx);

  if( doc == NULL || node == NULL ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_STATUS_ENUM_REALM_SRC_INTERFACES_NO_DOC_NODE,"xxx",http_conn,http_bus_sess,http_req);
    return -EINVAL;
  }

  vpn_realm_str = (char*)rhp_xml_get_prop(node,(const xmlChar*)"vpn_realm");
  if( vpn_realm_str == NULL ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_UI_HTTP_STATUS_ENUM_REALM_SRC_INTERFACES_NO_VPN_REALM,"xxx",http_conn,http_bus_sess,http_req);
    goto error;
  }

  rlm_id = strtoul((char*)vpn_realm_str,&endp,0);
  if( (rlm_id == ULONG_MAX && errno == ERANGE) || *endp != '\0' ){
  	err = -ENOENT;
  	RHP_TRC(0,RHPTRCID_UI_HTTP_STATUS_ENUM_REALM_SRC_INTERFACES_NO_VPN_REALM_2,"xxxs",http_conn,http_bus_sess,http_req,vpn_realm_str);
  	goto error;
  }

  if( _rhp_ui_http_permitted(http_conn,http_bus_sess,rlm_id) ){
			err = -EPERM;
			RHP_TRC(0,RHPTRCID_UI_HTTP_STATUS_ENUM_REALM_SRC_INTERFACES_NOT_PERMITTED,"xxxuu",http_conn,http_bus_sess,http_req,http_conn->user_realm_id,http_bus_sess->user_realm_id);
			goto error;
	}

  if( rlm_id == 0 ){
  	err = -ENOENT;
  	RHP_TRC(0,RHPTRCID_UI_HTTP_STATUS_ENUM_REALM_SRC_INTERFACES_NO_VPN_REALM_ZERO,"xxxs",http_conn,http_bus_sess,http_req,vpn_realm_str);
  	goto error;
  }

	rlm = rhp_realm_get(rlm_id);
	if( rlm == NULL ){
		err = -ENOENT;
		goto error;
	}

	RHP_LOCK(&(rlm->lock));

  err = rhp_http_bus_send_response(http_conn,http_bus_sess,_rhp_ui_http_status_enum_realm_src_interfaces_serialize,(void*)rlm);
  if( err ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_STATUS_ENUM_REALM_SRC_INTERFACES_TX_RESP_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
    goto error;
  }

	RHP_UNLOCK(&(rlm->lock));
  rhp_realm_unhold(rlm);

  if( vpn_realm_str ){
  	_rhp_free(vpn_realm_str);
  }

  RHP_TRC(0,RHPTRCID_UI_HTTP_STATUS_ENUM_REALM_SRC_INTERFACES_RTRN,"xxxs",http_conn,http_bus_sess,http_req,vpn_realm_str);
  return RHP_STATUS_CLOSE_HTTP_CONN;

error:
	if( rlm ){
		RHP_UNLOCK(&(rlm->lock));
	  rhp_realm_unhold(rlm);
	}
  if( vpn_realm_str ){
  	_rhp_free(vpn_realm_str);
  }
  RHP_TRC(0,RHPTRCID_UI_HTTP_STATUS_ENUM_REALM_SRC_INTERFACES_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  return err;
}


static int _rhp_ui_http_status_enum_route_maps_cb(rhp_rtmapc_entry* rtmapc,void* ctx)
{
	int err = -EINVAL;
	int n;
	rhp_ui_http_enum_ctx* enum_ctx = (rhp_ui_http_enum_ctx*)ctx;
	void* writer = enum_ctx->writer;
	int* n2 = enum_ctx->n2;
	int addr_family = (int)enum_ctx->priv;

	RHP_LOCK(&(rtmapc->lock));

	if( rtmapc->info.addr_family != addr_family ){
		RHP_UNLOCK(&(rtmapc->lock));
		return 0;
	}


	{
		n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"route_map");
		if(n < 0) {
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;

		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"index","%d",enum_ctx->idx++);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;

		{
			switch( rtmapc->info.type ){

			case RHP_RTMAP_TYPE_UNKNOWN:
				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"type","%s","unknown");
				break;
			case RHP_RTMAP_TYPE_DEFAULT:
				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"type","%s","default");
				break;
			case RHP_RTMAP_TYPE_STATIC:
				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"type","%s","static");
				break;
			case RHP_RTMAP_TYPE_DYNAMIC:
				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"type","%s","dynamic");
				break;
			case RHP_RTMAP_TYPE_DYNAMIC_DEFAULT:
				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"type","%s","dynamic_default");
				break;
			case RHP_RTMAP_TYPE_DEFAULT_INTERNAL:
				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"type","%s","internal_default");
				break;
			case RHP_RTMAP_TYPE_STATIC_INTERNAL:
				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"type","%s","internal_static");
				break;
			case RHP_RTMAP_TYPE_DYNAMIC_INTERNAL:
				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"type","%s","internal_dynamic");
				break;
			case RHP_RTMAP_TYPE_DYNAMIC_DEFAULT_INTERNAL:
				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"type","%s","internal_dynamic_default");
				break;
			case RHP_RTMAP_TYPE_NHRP_CACHE:
				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"type","%s","nhrp_cache");
				break;
			default:
				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"type","%s(%d)","not_defined",rtmapc->info.type);
				break;
			}
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;
		}


		{
			switch( rtmapc->info.rtm_type ){

			case RTN_UNICAST:
				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rtn_type","%s","unicast");
				break;
			case RTN_LOCAL:
				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rtn_type","%s","local");
				break;
			case RTN_BROADCAST:
				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rtn_type","%s","broadcast");
				break;
			case RTN_ANYCAST:
				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rtn_type","%s","anycast");
				break;
			case RTN_MULTICAST:
				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rtn_type","%s","multicast");
				break;
			default:
				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rtn_type","%s(%d)","unknown",rtmapc->info.rtm_type);
				break;
			}
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;
		}


		if( addr_family == AF_INET ){

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"ip_version","%s","ipv4");
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"destination","%d.%d.%d.%d/%d",
					((u8*)&(rtmapc->info.dest_network.addr.v4))[0],
					((u8*)&(rtmapc->info.dest_network.addr.v4))[1],
					((u8*)&(rtmapc->info.dest_network.addr.v4))[2],
					((u8*)&(rtmapc->info.dest_network.addr.v4))[3],
					rtmapc->info.dest_network.prefixlen);
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;

			if( !rhp_ip_addr_null(&(rtmapc->info.gateway_addr)) ){

				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"gateway","%d.%d.%d.%d",
						((u8*)&(rtmapc->info.gateway_addr.addr.v4))[0],
						((u8*)&(rtmapc->info.gateway_addr.addr.v4))[1],
						((u8*)&(rtmapc->info.gateway_addr.addr.v4))[2],
						((u8*)&(rtmapc->info.gateway_addr.addr.v4))[3]);
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error;
				}
				*n2 += n;
			}

		}else if( addr_family == AF_INET6 ){

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"ip_version","%s","ipv6");
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"destination","%s/%d",
					rhp_ipv6_string(rtmapc->info.dest_network.addr.v6),
					rtmapc->info.dest_network.prefixlen);
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;

			if( !rhp_ip_addr_null(&(rtmapc->info.gateway_addr)) ){

				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"gateway","%s",
						rhp_ipv6_string(rtmapc->info.gateway_addr.addr.v6));
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error;
				}
				*n2 += n;
			}

		}else{
			RHP_BUG("%d",addr_family);
			err = -EINVAL;
			goto error;
		}


		if( rtmapc->info.oif_index ){

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"oif_name","%s",rtmapc->info.oif_name);
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"oif_index","%d",rtmapc->info.oif_index);
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;
		}


		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"metric","%d",rtmapc->info.metric);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;

		n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
		if(n < 0) {
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;
	}

	RHP_UNLOCK(&(rtmapc->lock));

	return 0;

error:
	RHP_UNLOCK(&(rtmapc->lock));
	return err;
}

static int _rhp_ui_http_status_enum_route_maps_serialize(rhp_http_bus_session* http_bus_sess,void* ctx,void* writer,int idx)
{
  int err0 = -EINVAL,err1 = -EINVAL;
  int n = 0;
  int n2 = 0;
  rhp_ui_http_enum_ctx enum_ctx;

  RHP_TRC(0,RHPTRCID_UI_HTTP_STATUS_ENUM_ROUTE_MAPS_SERIALIZE,"xxd",http_bus_sess,writer,idx);


	n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"rhp_http_bus_record");
	if(n < 0) {
		err0 = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"index","%d",idx);
	if(n < 0){
		err0 = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"service",(xmlChar*)"ui_http_vpn");
	if(n < 0){
		err0 = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"action",(xmlChar*)"status_enum_route_maps");
	if(n < 0){
		err0 = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"session_id","%llu",http_bus_sess->session_id);
	if(n < 0){
		err0 = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;


	{
		enum_ctx.idx = 0;
		enum_ctx.writer = writer;
		enum_ctx.n2 = &n2;
		enum_ctx.rlm_id = 0;
		enum_ctx.ignore_resp_negotiating = 0;

		enum_ctx.priv = (unsigned long)AF_INET;
		err0 = rhp_rtmapc_enum(_rhp_ui_http_status_enum_route_maps_cb,&enum_ctx);

		enum_ctx.priv = (unsigned long)AF_INET6;
		err1 = rhp_rtmapc_enum(_rhp_ui_http_status_enum_route_maps_cb,&enum_ctx);

		if( err0 && err1 ){
			err0 = -ENOENT;
			goto error;
		}
	}


	n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
	if(n < 0) {
		err0 = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  RHP_TRC(0,RHPTRCID_UI_HTTP_STATUS_ENUM_ROUTE_MAPS_SERIALIZE_RTRN,"xd",http_bus_sess,n2);
  return n2;

error:
  RHP_TRC(0,RHPTRCID_UI_HTTP_STATUS_ENUM_ROUTE_MAPS_SERIALIZE_ERR,"xE",http_bus_sess,err0);
  return err0;
}

static int _rhp_ui_http_status_enum_route_maps(xmlDocPtr doc,xmlNodePtr node,rhp_http_conn* http_conn,
		rhp_http_bus_session* http_bus_sess,rhp_http_request* http_req,void* ctx)
{
  int err = -EINVAL;

  RHP_TRC(0,RHPTRCID_UI_HTTP_STATUS_ENUM_ROUTE_MAPS,"xxxxxx",doc,node,http_conn,http_bus_sess,http_req,ctx);

  if( doc == NULL || node == NULL ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_STATUS_ENUM_ROUTE_MAPS_NO_DOC_NODE,"xxx",http_conn,http_bus_sess,http_req);
    return -EINVAL;
  }


  err = rhp_http_bus_send_response(http_conn,http_bus_sess,_rhp_ui_http_status_enum_route_maps_serialize,NULL);
  if( err ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_STATUS_ENUM_ROUTE_MAPS_TX_RESP_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
    goto error;
  }

  RHP_TRC(0,RHPTRCID_UI_HTTP_STATUS_ENUM_ROUTE_MAPS_RTRN,"xxx",http_conn,http_bus_sess,http_req);
  return RHP_STATUS_CLOSE_HTTP_CONN;

error:
  RHP_TRC(0,RHPTRCID_UI_HTTP_STATUS_ENUM_ROUTE_MAPS_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  return err;
}


static int _rhp_ui_http_status_enum_ip_routing_table_cb(int addr_family,
		rhp_ip_routing_bkt* ip_rt_bkt,rhp_ip_routing_entry* ip_rt_ent,void* ctx)
{
	int err = -EINVAL;
	int n;
	rhp_ui_http_enum_ctx* enum_ctx = (rhp_ui_http_enum_ctx*)ctx;
	void* writer = enum_ctx->writer;
	int* n2 = enum_ctx->n2;

	if( enum_ctx->priv != (unsigned long)ip_rt_bkt ){

		n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"ip_routing_bucket");
		if(n < 0) {
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;

		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"bucket_id","%d",ip_rt_bkt->prefix_len);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;

		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"bucket_size","%u",ip_rt_bkt->bkt_size);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;

		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"entries_num","%u",ip_rt_bkt->entries_num);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;

		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rehashed","%d",ip_rt_bkt->rehashed);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;


		if( addr_family == AF_INET ){

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"ip_version","%s","ipv4");
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"prefix_len","%d",ip_rt_bkt->prefix_len);
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"netmask","%d.%d.%d.%d",
					((u8*)&(ip_rt_bkt->netmask.v4))[0],((u8*)&(ip_rt_bkt->netmask.v4))[1],((u8*)&(ip_rt_bkt->netmask.v4))[2],((u8*)&(ip_rt_bkt->netmask.v4))[3]);
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;

		}else if( addr_family == AF_INET6 ){

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"ip_version","%s","ipv6");
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"prefix_len","%d",ip_rt_bkt->prefix_len);
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"netmask",
						"%s",rhp_ipv6_string(ip_rt_bkt->netmask.v6));
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;
		}

		n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
		if(n < 0) {
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;

		enum_ctx->priv = (unsigned long)ip_rt_bkt;
	}


	{
		n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"ip_routing_entry");
		if(n < 0) {
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;

		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"index","%d",enum_ctx->idx++);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;

		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"bucket_id","%d",ip_rt_bkt->prefix_len);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;

		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"prefix_len","%d",ip_rt_bkt->prefix_len);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;

		{
			switch( ip_rt_ent->info.type ){

			case RHP_RTMAP_TYPE_UNKNOWN:
				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"type","%s","unknown");
				break;
			case RHP_RTMAP_TYPE_DEFAULT:
				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"type","%s","default");
				break;
			case RHP_RTMAP_TYPE_STATIC:
				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"type","%s","static");
				break;
			case RHP_RTMAP_TYPE_DYNAMIC:
				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"type","%s","dynamic");
				break;
			case RHP_RTMAP_TYPE_DYNAMIC_DEFAULT:
				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"type","%s","dynamic_default");
				break;
			case RHP_RTMAP_TYPE_DEFAULT_INTERNAL:
				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"type","%s","internal_default");
				break;
			case RHP_RTMAP_TYPE_STATIC_INTERNAL:
				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"type","%s","internal_static");
				break;
			case RHP_RTMAP_TYPE_DYNAMIC_INTERNAL:
				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"type","%s","internal_dynamic");
				break;
			case RHP_RTMAP_TYPE_DYNAMIC_DEFAULT_INTERNAL:
				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"type","%s","internal_dynamic_default");
				break;
			case RHP_RTMAP_TYPE_NHRP_CACHE:
				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"type","%s","nhrp_cache");
				break;
			default:
				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"type","%s(%d)","not_defined",ip_rt_ent->info.type);
				break;
			}
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;
		}


		{
			switch( ip_rt_ent->info.rtm_type ){

			case RTN_UNICAST:
				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rtn_type","%s","unicast");
				break;
			case RTN_LOCAL:
				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rtn_type","%s","local");
				break;
			case RTN_BROADCAST:
				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rtn_type","%s","broadcast");
				break;
			case RTN_ANYCAST:
				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rtn_type","%s","anycast");
				break;
			case RTN_MULTICAST:
				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rtn_type","%s","multicast");
				break;
			default:
				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rtn_type","%s(%d)","unknown",ip_rt_ent->info.rtm_type);
				break;
			}
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;
		}


		if( addr_family == AF_INET ){

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"ip_version","%s","ipv4");
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"destination","%d.%d.%d.%d/%d",
					((u8*)&(ip_rt_ent->info.dest_network.addr.v4))[0],
					((u8*)&(ip_rt_ent->info.dest_network.addr.v4))[1],
					((u8*)&(ip_rt_ent->info.dest_network.addr.v4))[2],
					((u8*)&(ip_rt_ent->info.dest_network.addr.v4))[3],
					ip_rt_ent->info.dest_network.prefixlen);
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;

			if( !rhp_ip_addr_null(&(ip_rt_ent->info.gateway_addr)) ){

				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"gateway","%d.%d.%d.%d",
						((u8*)&(ip_rt_ent->info.gateway_addr.addr.v4))[0],
						((u8*)&(ip_rt_ent->info.gateway_addr.addr.v4))[1],
						((u8*)&(ip_rt_ent->info.gateway_addr.addr.v4))[2],
						((u8*)&(ip_rt_ent->info.gateway_addr.addr.v4))[3]);
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error;
				}
				*n2 += n;
			}

		}else if( addr_family == AF_INET6 ){

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"ip_version","%s","ipv6");
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"destination","%s/%d",
					rhp_ipv6_string(ip_rt_ent->info.dest_network.addr.v6),
					ip_rt_ent->info.dest_network.prefixlen);
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;

			if( !rhp_ip_addr_null(&(ip_rt_ent->info.gateway_addr)) ){

				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"gateway","%s",
						rhp_ipv6_string(ip_rt_ent->info.gateway_addr.addr.v6));
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error;
				}
				*n2 += n;
			}

		}else{
			RHP_BUG("%d",addr_family);
			err = -EINVAL;
			goto error;
		}


		if( ip_rt_ent->info.oif_index ){

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"oif_name","%s",ip_rt_ent->info.oif_name);
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"oif_index","%d",ip_rt_ent->info.oif_index);
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;
		}


		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"metric","%d",ip_rt_ent->info.metric);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;


		if( ip_rt_ent->out_realm_id ){

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"out_realm_id","%lu",ip_rt_ent->out_realm_id);
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;
		}


		if( ip_rt_ent->type == RHP_IP_RT_ENT_TYPE_NHRP ){

			if( ip_rt_ent->tx_vpn_ref ){

				char *id_type,*id_str;
				rhp_vpn* vpn = RHP_VPN_REF(ip_rt_ent->tx_vpn_ref);

				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"vpn_realm_id","%lu",vpn->vpn_realm_id);
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					_rhp_free(id_type);
					_rhp_free(id_str);
					goto error;
				}
				*n2 += n;

				// vpn_unique_id is immutable.
				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"vpn_unique_id",
						"0x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
						vpn->unique_id[0],vpn->unique_id[1],vpn->unique_id[2],vpn->unique_id[3],vpn->unique_id[4],vpn->unique_id[5],vpn->unique_id[6],vpn->unique_id[7],
						vpn->unique_id[8],vpn->unique_id[9],vpn->unique_id[10],vpn->unique_id[11],vpn->unique_id[12],vpn->unique_id[13],vpn->unique_id[14],vpn->unique_id[15]);
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error;
				}
				*n2 += n;


				err = rhp_ikev2_id_to_string(&(vpn->peer_id),&id_type,&id_str);
				if( err ){
					goto error;
				}

				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"peerid_type","%s",id_type);
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					_rhp_free(id_type);
					_rhp_free(id_str);
					goto error;
				}
				*n2 += n;

				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"peerid","%s",id_str);
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					_rhp_free(id_type);
					_rhp_free(id_str);
					goto error;
				}
				*n2 += n;

				if( !rhp_eap_id_is_null(&(vpn->eap.peer_id))){

					n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"eap_peer_id","%s",vpn->eap.peer_id.identity);
					if(n < 0){
						err = -ENOMEM;
						RHP_BUG("");
						_rhp_free(id_type);
						_rhp_free(id_str);
						goto error;
					}
					*n2 += n;
				}

				_rhp_free(id_type);
				_rhp_free(id_str);

				if( vpn->peer_id.alt_id ){

					err = rhp_ikev2_id_to_string(vpn->peer_id.alt_id,&id_type,&id_str);
					if( err ){
						goto error;
					}

					n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"alt_peerid_type","%s",id_type);
					if(n < 0){
						err = -ENOMEM;
						RHP_BUG("");
						_rhp_free(id_type);
						_rhp_free(id_str);
						goto error;
					}
					*n2 += n;

					n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"alt_peerid","%s",id_str);
					if(n < 0){
						err = -ENOMEM;
						RHP_BUG("");
						_rhp_free(id_type);
						_rhp_free(id_str);
						goto error;
					}
					*n2 += n;

					_rhp_free(id_type);
					_rhp_free(id_str);
				}
			}


			{
				time_t now = _rhp_get_time();

				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"elapsed","%ld",(now - ip_rt_ent->created_time));
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error;
				}
				*n2 += n;
			}


			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"hold_time","%d",(int)ip_rt_ent->hold_time);
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;
		}


		n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
		if(n < 0) {
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;
	}

	return 0;

error:
	return err;
}

static int _rhp_ui_http_status_enum_ip_routing_table_serialize(rhp_http_bus_session* http_bus_sess,void* ctx,void* writer,int idx)
{
  int err0 = -EINVAL,err1 = -EINVAL;
  int n = 0;
  int n2 = 0;
  rhp_ui_http_enum_ctx enum_ctx;

  RHP_TRC(0,RHPTRCID_UI_HTTP_STATUS_ENUM_ROUTING_TABLE_SERIALIZE,"xxd",http_bus_sess,writer,idx);


	n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"rhp_http_bus_record");
	if(n < 0) {
		err0 = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"index","%d",idx);
	if(n < 0){
		err0 = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"service",(xmlChar*)"ui_http_vpn");
	if(n < 0){
		err0 = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"action",(xmlChar*)"status_ip_routing_table");
	if(n < 0){
		err0 = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"session_id","%llu",http_bus_sess->session_id);
	if(n < 0){
		err0 = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;


	{
		enum_ctx.idx = 0;
		enum_ctx.writer = writer;
		enum_ctx.n2 = &n2;
		enum_ctx.rlm_id = 0;
		enum_ctx.ignore_resp_negotiating = 0;
		enum_ctx.priv = 0;

		err0 = rhp_ip_routing_enum(AF_INET,_rhp_ui_http_status_enum_ip_routing_table_cb,&enum_ctx);

		err1 = rhp_ip_routing_enum(AF_INET6,_rhp_ui_http_status_enum_ip_routing_table_cb,&enum_ctx);

		if( err0 && err1 ){
			err0 = -ENOENT;
			goto error;
		}
	}


	n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
	if(n < 0) {
		err0 = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  RHP_TRC(0,RHPTRCID_UI_HTTP_STATUS_ENUM_ROUTING_TABLE_SERIALIZE_RTRN,"xd",http_bus_sess,n2);
  return n2;

error:
  RHP_TRC(0,RHPTRCID_UI_HTTP_STATUS_ENUM_ROUTING_TABLE_SERIALIZE_ERR,"xE",http_bus_sess,err0);
  return err0;
}

static int _rhp_ui_http_status_enum_ip_routing_table(xmlDocPtr doc,xmlNodePtr node,rhp_http_conn* http_conn,
		rhp_http_bus_session* http_bus_sess,rhp_http_request* http_req,void* ctx)
{
  int err = -EINVAL;

  RHP_TRC(0,RHPTRCID_UI_HTTP_STATUS_ENUM_IP_ROUTING_TABLE,"xxxxxx",doc,node,http_conn,http_bus_sess,http_req,ctx);

  if( doc == NULL || node == NULL ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_STATUS_ENUM_IP_ROUTING_TABLE_NO_DOC_NODE,"xxx",http_conn,http_bus_sess,http_req);
    return -EINVAL;
  }


  err = rhp_http_bus_send_response(http_conn,http_bus_sess,_rhp_ui_http_status_enum_ip_routing_table_serialize,NULL);
  if( err ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_STATUS_ENUM_IP_ROUTING_TABLE_TX_RESP_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
    goto error;
  }

  RHP_TRC(0,RHPTRCID_UI_HTTP_STATUS_ENUM_IP_ROUTING_TABLE_RTRN,"xxx",http_conn,http_bus_sess,http_req);
  return RHP_STATUS_CLOSE_HTTP_CONN;

error:
  RHP_TRC(0,RHPTRCID_UI_HTTP_STATUS_ENUM_IP_ROUTING_TABLE_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  return err;
}


static int _rhp_ui_http_status_enum_ip_routing_cache_cb(int addr_family,
		rhp_ip_route_cache* ip_rt_c,void* ctx)
{
	int err = -EINVAL;
	int n;
	rhp_ui_http_enum_ctx* enum_ctx = (rhp_ui_http_enum_ctx*)ctx;
	void* writer = enum_ctx->writer;
	int* n2 = enum_ctx->n2;

	{
		n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"ip_routing_cache");
		if(n < 0) {
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;

		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"index","%d",enum_ctx->idx++);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;


		if( ip_rt_c->type == RHP_IP_RT_ENT_TYPE_SYSTEM ){
			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"type","%s","system");
		}else if( ip_rt_c->type == RHP_IP_RT_ENT_TYPE_NHRP ){
			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"type","%s","nhrp");
		}else{
			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"type","%s","unknown");
		}
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;


		if( addr_family == AF_INET ){

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"ip_version","%s","ipv4");
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"src_address","%d.%d.%d.%d",
					((u8*)&(ip_rt_c->src_addr.v4))[0],
					((u8*)&(ip_rt_c->src_addr.v4))[1],
					((u8*)&(ip_rt_c->src_addr.v4))[2],
					((u8*)&(ip_rt_c->src_addr.v4))[3]);
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"dst_address","%d.%d.%d.%d",
					((u8*)&(ip_rt_c->dst_addr.v4))[0],
					((u8*)&(ip_rt_c->dst_addr.v4))[1],
					((u8*)&(ip_rt_c->dst_addr.v4))[2],
					((u8*)&(ip_rt_c->dst_addr.v4))[3]);
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"next_hop_address","%d.%d.%d.%d",
					((u8*)&(ip_rt_c->nexthop_addr.v4))[0],
					((u8*)&(ip_rt_c->nexthop_addr.v4))[1],
					((u8*)&(ip_rt_c->nexthop_addr.v4))[2],
					((u8*)&(ip_rt_c->nexthop_addr.v4))[3]);
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;

		}else if( addr_family == AF_INET6 ){

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"ip_version","%s","ipv6");
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"src_address","%s",
					rhp_ipv6_string(ip_rt_c->src_addr.v6));
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"dst_address","%s",
					rhp_ipv6_string(ip_rt_c->dst_addr.v6));
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"next_hop_address","%s",
					rhp_ipv6_string(ip_rt_c->nexthop_addr.v6));
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;

		}else{
			RHP_BUG("%d",addr_family);
			err = -EINVAL;
			goto error;
		}


		if( ip_rt_c->src_vpn_ref || ip_rt_c->tx_vpn_ref ){

			char *id_type,*id_str;
			rhp_vpn* vpn
				= ip_rt_c->src_vpn_ref ? RHP_VPN_REF(ip_rt_c->src_vpn_ref) : RHP_VPN_REF(ip_rt_c->tx_vpn_ref);

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"vpn_realm_id","%lu",vpn->vpn_realm_id);
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				_rhp_free(id_type);
				_rhp_free(id_str);
				goto error;
			}
			*n2 += n;

			// vpn_unique_id is immutable.
			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"vpn_unique_id",
					"0x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
					vpn->unique_id[0],vpn->unique_id[1],vpn->unique_id[2],vpn->unique_id[3],vpn->unique_id[4],vpn->unique_id[5],vpn->unique_id[6],vpn->unique_id[7],
					vpn->unique_id[8],vpn->unique_id[9],vpn->unique_id[10],vpn->unique_id[11],vpn->unique_id[12],vpn->unique_id[13],vpn->unique_id[14],vpn->unique_id[15]);
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;


			err = rhp_ikev2_id_to_string(&(vpn->peer_id),&id_type,&id_str);
			if( err ){
				goto error;
			}

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"peerid_type","%s",id_type);
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				_rhp_free(id_type);
				_rhp_free(id_str);
				goto error;
			}
			*n2 += n;

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"peerid","%s",id_str);
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				_rhp_free(id_type);
				_rhp_free(id_str);
				goto error;
			}
			*n2 += n;

			if( !rhp_eap_id_is_null(&(vpn->eap.peer_id))){

				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"eap_peer_id","%s",vpn->eap.peer_id.identity);
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					_rhp_free(id_type);
					_rhp_free(id_str);
					goto error;
				}
				*n2 += n;
			}

			_rhp_free(id_type);
			_rhp_free(id_str);

			if( vpn->peer_id.alt_id ){

				err = rhp_ikev2_id_to_string(vpn->peer_id.alt_id,&id_type,&id_str);
				if( err ){
					goto error;
				}

				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"alt_peerid_type","%s",id_type);
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					_rhp_free(id_type);
					_rhp_free(id_str);
					goto error;
				}
				*n2 += n;

				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"alt_peerid","%s",id_str);
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					_rhp_free(id_type);
					_rhp_free(id_str);
					goto error;
				}
				*n2 += n;

				_rhp_free(id_type);
				_rhp_free(id_str);
			}
		}


		if( ip_rt_c->out_realm_id ){

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"out_realm_id","%lu",ip_rt_c->out_realm_id);
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;
		}

		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"used","%lu",ip_rt_c->used_cnt);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;

		{
			time_t now = _rhp_get_time();

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"elapsed","%ld",(now - ip_rt_c->created));
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;
		}

		n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
		if(n < 0) {
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;
	}

	return 0;

error:
	return err;
}

static int _rhp_ui_http_status_enum_ip_routing_cache_serialize(rhp_http_bus_session* http_bus_sess,void* ctx,void* writer,int idx)
{
  int err0 = -EINVAL,err1 = -EINVAL;
  int n = 0;
  int n2 = 0;
  rhp_ui_http_enum_ctx enum_ctx;

  RHP_TRC(0,RHPTRCID_UI_HTTP_STATUS_ENUM_ROUTING_CACHE_SERIALIZE,"xxd",http_bus_sess,writer,idx);


	n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"rhp_http_bus_record");
	if(n < 0) {
		err0 = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"index","%d",idx);
	if(n < 0){
		err0 = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"service",(xmlChar*)"ui_http_vpn");
	if(n < 0){
		err0 = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"action",(xmlChar*)"status_ip_routing_cache");
	if(n < 0){
		err0 = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"session_id","%llu",http_bus_sess->session_id);
	if(n < 0){
		err0 = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;


	{
		enum_ctx.idx = 0;
		enum_ctx.writer = writer;
		enum_ctx.n2 = &n2;
		enum_ctx.rlm_id = 0;
		enum_ctx.ignore_resp_negotiating = 0;
		enum_ctx.priv = 0;

		err0 = rhp_ip_routing_cache_enum(AF_INET,_rhp_ui_http_status_enum_ip_routing_cache_cb,&enum_ctx);

		err1 = rhp_ip_routing_cache_enum(AF_INET6,_rhp_ui_http_status_enum_ip_routing_cache_cb,&enum_ctx);

		if( err0 && err1 ){
			err0 = -ENOENT;
			goto error;
		}
	}


	n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
	if(n < 0) {
		err0 = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  RHP_TRC(0,RHPTRCID_UI_HTTP_STATUS_ENUM_ROUTING_CACHE_SERIALIZE_RTRN,"xd",http_bus_sess,n2);
  return n2;

error:
  RHP_TRC(0,RHPTRCID_UI_HTTP_STATUS_ENUM_ROUTING_CACHE_SERIALIZE_ERR,"xE",http_bus_sess,err0);
  return err0;
}

static int _rhp_ui_http_status_enum_ip_routing_cache(xmlDocPtr doc,xmlNodePtr node,rhp_http_conn* http_conn,
		rhp_http_bus_session* http_bus_sess,rhp_http_request* http_req,void* ctx)
{
  int err = -EINVAL;

  RHP_TRC(0,RHPTRCID_UI_HTTP_STATUS_ENUM_IP_ROUTING_CACHE,"xxxxxx",doc,node,http_conn,http_bus_sess,http_req,ctx);

  if( doc == NULL || node == NULL ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_STATUS_ENUM_IP_ROUTING_CACHE_NO_DOC_NODE,"xxx",http_conn,http_bus_sess,http_req);
    return -EINVAL;
  }


  err = rhp_http_bus_send_response(http_conn,http_bus_sess,_rhp_ui_http_status_enum_ip_routing_cache_serialize,NULL);
  if( err ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_STATUS_ENUM_IP_ROUTING_CACHE_TX_RESP_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
    goto error;
  }

  RHP_TRC(0,RHPTRCID_UI_HTTP_STATUS_ENUM_IP_ROUTING_CACHE_RTRN,"xxx",http_conn,http_bus_sess,http_req);
  return RHP_STATUS_CLOSE_HTTP_CONN;

error:
  RHP_TRC(0,RHPTRCID_UI_HTTP_STATUS_ENUM_IP_ROUTING_CACHE_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  return err;
}


static int _rhp_ui_http_status_enum_nhrp_cache_cb(rhp_nhrp_cache* nhrp_c,void* ctx)
{
	int err = -EINVAL;
	int n;
	rhp_ui_http_enum_ctx* enum_ctx = (rhp_ui_http_enum_ctx*)ctx;
	void* writer = enum_ctx->writer;
	int* n2 = enum_ctx->n2;

	{
		n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"nhrp_cache");
		if(n < 0) {
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;

		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"index","%d",enum_ctx->idx++);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;

		if( nhrp_c->protocol_addr.addr_family == AF_INET ){

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"protocol_addr_ip_version","%s","ipv4");
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"protocol_addr","%d.%d.%d.%d",
					((u8*)&(nhrp_c->protocol_addr.addr.v4))[0],
					((u8*)&(nhrp_c->protocol_addr.addr.v4))[1],
					((u8*)&(nhrp_c->protocol_addr.addr.v4))[2],
					((u8*)&(nhrp_c->protocol_addr.addr.v4))[3]);
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;


		}else if( nhrp_c->protocol_addr.addr_family == AF_INET6 ){

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"protocol_addr_ip_version","%s","ipv6");
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"protocol_addr","%s",
					rhp_ipv6_string(nhrp_c->protocol_addr.addr.v6));
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;

		}else{
			RHP_BUG("%d",nhrp_c->protocol_addr.addr_family);
			err = -EINVAL;
			goto error;
		}


		if( nhrp_c->nbma_addr.addr_family == AF_INET ){

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"nbma_addr_ip_version","%s","ipv4");
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"nbma_addr","%d.%d.%d.%d",
					((u8*)&(nhrp_c->nbma_addr.addr.v4))[0],
					((u8*)&(nhrp_c->nbma_addr.addr.v4))[1],
					((u8*)&(nhrp_c->nbma_addr.addr.v4))[2],
					((u8*)&(nhrp_c->nbma_addr.addr.v4))[3]);
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;


		}else if( nhrp_c->nbma_addr.addr_family == AF_INET6 ){

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"nbma_addr_ip_version","%s","ipv6");
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"nbma_addr","%s",
					rhp_ipv6_string(nhrp_c->nbma_addr.addr.v6));
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;

		}else{
			RHP_BUG("%d",nhrp_c->nbma_addr.addr_family);
			err = -EINVAL;
			goto error;
		}

		if( !rhp_ip_addr_null(&(nhrp_c->nat_addr)) ){

			if( nhrp_c->nat_addr.addr_family == AF_INET ){

				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"nat_addr_ip_version","%s","ipv4");
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error;
				}
				*n2 += n;

				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"nat_addr","%d.%d.%d.%d",
						((u8*)&(nhrp_c->nat_addr.addr.v4))[0],
						((u8*)&(nhrp_c->nat_addr.addr.v4))[1],
						((u8*)&(nhrp_c->nat_addr.addr.v4))[2],
						((u8*)&(nhrp_c->nat_addr.addr.v4))[3]);
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error;
				}
				*n2 += n;


			}else if( nhrp_c->nat_addr.addr_family == AF_INET6 ){

				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"nat_addr_ip_version","%s","ipv6");
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error;
				}
				*n2 += n;

				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"nat_addr","%s",
						rhp_ipv6_string(nhrp_c->nat_addr.addr.v6));
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					goto error;
				}
				*n2 += n;

			}else{
				RHP_BUG("%d",nhrp_c->nat_addr.addr_family);
				err = -EINVAL;
				goto error;
			}
		}


		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"vpn_realm_id","%lu",nhrp_c->vpn_realm_id);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;


		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
					(xmlChar*)"vpn_dummy_mac",
					"%02x:%02x:%02x:%02x:%02x:%02x",
					nhrp_c->vpn_dummy_mac[0],nhrp_c->vpn_dummy_mac[1],
					nhrp_c->vpn_dummy_mac[2],nhrp_c->vpn_dummy_mac[3],
					nhrp_c->vpn_dummy_mac[4],nhrp_c->vpn_dummy_mac[5]);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;


		if( nhrp_c->vpn_ref ){

			char *id_type,*id_str;
			rhp_vpn* vpn = RHP_VPN_REF(nhrp_c->vpn_ref);

			// vpn_unique_id is immutable.
			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"vpn_unique_id",
					"0x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
					vpn->unique_id[0],vpn->unique_id[1],vpn->unique_id[2],vpn->unique_id[3],vpn->unique_id[4],vpn->unique_id[5],vpn->unique_id[6],vpn->unique_id[7],
					vpn->unique_id[8],vpn->unique_id[9],vpn->unique_id[10],vpn->unique_id[11],vpn->unique_id[12],vpn->unique_id[13],vpn->unique_id[14],vpn->unique_id[15]);
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;


			err = rhp_ikev2_id_to_string(&(vpn->peer_id),&id_type,&id_str);
			if( err ){
				goto error;
			}

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"peerid_type","%s",id_type);
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				_rhp_free(id_type);
				_rhp_free(id_str);
				goto error;
			}
			*n2 += n;

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"peerid","%s",id_str);
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				_rhp_free(id_type);
				_rhp_free(id_str);
				goto error;
			}
			*n2 += n;

			if( !rhp_eap_id_is_null(&(vpn->eap.peer_id))){

				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"eap_peer_id","%s",vpn->eap.peer_id.identity);
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					_rhp_free(id_type);
					_rhp_free(id_str);
					goto error;
				}
				*n2 += n;
			}

			_rhp_free(id_type);
			_rhp_free(id_str);

			if( vpn->peer_id.alt_id ){

				err = rhp_ikev2_id_to_string(vpn->peer_id.alt_id,&id_type,&id_str);
				if( err ){
					goto error;
				}

				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"alt_peerid_type","%s",id_type);
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					_rhp_free(id_type);
					_rhp_free(id_str);
					goto error;
				}
				*n2 += n;

				n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"alt_peerid","%s",id_str);
				if(n < 0){
					err = -ENOMEM;
					RHP_BUG("");
					_rhp_free(id_type);
					_rhp_free(id_str);
					goto error;
				}
				*n2 += n;

				_rhp_free(id_type);
				_rhp_free(id_str);
			}
		}


		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"uniqueness","%d",nhrp_c->uniqueness);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;


		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rx_hold_time","%d",nhrp_c->rx_hold_time);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;


		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rx_mtu","%d",nhrp_c->rx_mtu);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;


		{
			time_t now = _rhp_get_time();

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"elapsed","%ld",(now - nhrp_c->created_time));
			if(n < 0){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*n2 += n;
		}


		n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
		if(n < 0) {
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*n2 += n;
	}

	return 0;

error:
	return err;
}

static int _rhp_ui_http_status_enum_nhrp_cache_serialize(rhp_http_bus_session* http_bus_sess,void* ctx,void* writer,int idx)
{
  int err0 = -EINVAL,err1 = -EINVAL;
  int n = 0;
  int n2 = 0;
  rhp_ui_http_enum_ctx enum_ctx;

  RHP_TRC(0,RHPTRCID_UI_HTTP_STATUS_ENUM_NHRP_CACHE_SERIALIZE,"xxd",http_bus_sess,writer,idx);


	n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"rhp_http_bus_record");
	if(n < 0) {
		err0 = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"index","%d",idx);
	if(n < 0){
		err0 = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"service",(xmlChar*)"ui_http_vpn");
	if(n < 0){
		err0 = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"action",(xmlChar*)"status_nhrp_cache");
	if(n < 0){
		err0 = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"session_id","%llu",http_bus_sess->session_id);
	if(n < 0){
		err0 = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;


	{
		enum_ctx.idx = 0;
		enum_ctx.writer = writer;
		enum_ctx.n2 = &n2;
		enum_ctx.rlm_id = 0;
		enum_ctx.ignore_resp_negotiating = 0;
		enum_ctx.priv = 0;

		err0 = rhp_nhrp_cache_enum(0,AF_INET,_rhp_ui_http_status_enum_nhrp_cache_cb,&enum_ctx);

		err1 = rhp_nhrp_cache_enum(0,AF_INET6,_rhp_ui_http_status_enum_nhrp_cache_cb,&enum_ctx);

		if( err0 && err1 ){
			err0 = -ENOENT;
			goto error;
		}
	}


	n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
	if(n < 0) {
		err0 = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  RHP_TRC(0,RHPTRCID_UI_HTTP_STATUS_ENUM_NHRP_CACHE_SERIALIZE_RTRN,"xd",http_bus_sess,n2);
  return n2;

error:
  RHP_TRC(0,RHPTRCID_UI_HTTP_STATUS_ENUM_NHRP_CACHE_SERIALIZE_ERR,"xE",http_bus_sess,err0);
  return err0;
}

static int _rhp_ui_http_status_enum_nhrp_cache(xmlDocPtr doc,xmlNodePtr node,rhp_http_conn* http_conn,
		rhp_http_bus_session* http_bus_sess,rhp_http_request* http_req,void* ctx)
{
  int err = -EINVAL;

  RHP_TRC(0,RHPTRCID_UI_HTTP_STATUS_ENUM_NHRP_CACHE,"xxxxxx",doc,node,http_conn,http_bus_sess,http_req,ctx);

  if( doc == NULL || node == NULL ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_STATUS_ENUM_NHRP_CACHE_NO_DOC_NODE,"xxx",http_conn,http_bus_sess,http_req);
    return -EINVAL;
  }


  err = rhp_http_bus_send_response(http_conn,http_bus_sess,_rhp_ui_http_status_enum_nhrp_cache_serialize,NULL);
  if( err ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_STATUS_ENUM_NHRP_CACHE_TX_RESP_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
    goto error;
  }

  RHP_TRC(0,RHPTRCID_UI_HTTP_STATUS_ENUM_NHRP_CACHE_RTRN,"xxx",http_conn,http_bus_sess,http_req);
  return RHP_STATUS_CLOSE_HTTP_CONN;

error:
  RHP_TRC(0,RHPTRCID_UI_HTTP_STATUS_ENUM_NHRP_CACHE_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  return err;
}


static int _rhp_ui_http_get_global_esp_statistics_serialize(rhp_http_bus_session* http_bus_sess,void* ctx,void* writer,int idx)
{
  int err = -EINVAL;
  int n = 0;
  int n2 = 0;
  rhp_esp_global_statistics table;

  RHP_TRC(0,RHPTRCID_UI_HTTP_GET_GLOBAL_ESP_STATISTICS_SERIALIZE,"xxd",http_bus_sess,writer,idx);

	n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"rhp_http_bus_record");
	if(n < 0) {
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"index","%d",idx);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"service",(xmlChar*)"ui_http_vpn");
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"action",(xmlChar*)"global_statistics_esp");
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"session_id","%llu",http_bus_sess->session_id);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	rhp_esp_get_statistics(&table);

	n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"esp");
	if(n < 0) {
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rx_no_vpn_err_packets","%llu",table.rx_esp_no_vpn_err_packets);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rx_no_childsa_err_packets","%llu",table.rx_esp_no_childsa_err_packets);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rx_anti_replay_err_packets","%llu",table.rx_esp_anti_replay_err_packets);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rx_decrypt_err_packets","%llu",table.rx_esp_decrypt_err_packets);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"tx_ts_err_packets","%llu",table.tx_esp_ts_err_packets);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"tx_integ_err_packets","%llu",table.tx_esp_integ_err_packets);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"tx_invalid_packets","%llu",table.tx_esp_invalid_packets);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rx_unknown_proto_packets","%llu",table.rx_esp_unknown_proto_packets);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rx_invalid_nat_t_packets","%llu",table.rx_esp_invalid_nat_t_packets);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rx_err_packets","%llu",table.rx_esp_err_packets);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rx_src_changed_packets","%llu",table.rx_esp_src_changed_packets);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"tx_no_childsa_err_packets","%llu",table.tx_esp_no_childsa_err_packets);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"tx_encrypt_err_packets","%llu",table.tx_esp_encrypt_err_packets);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rx_ts_err_packets","%llu",table.rx_esp_ts_err_packets);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rx_integ_err_packets","%llu",table.rx_esp_integ_err_packets);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rx_invalid_packets","%llu",table.rx_esp_invalid_packets);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"tx_err_packets","%llu",table.tx_esp_err_packets);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;



  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"dns_pxy_drop_queries","%llu",table.dns_pxy_drop_queries);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"dns_pxy_max_pending_queries_reached","%llu",table.dns_pxy_max_pending_queries_reached);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"dns_pxy_timedout_queries","%llu",table.dns_pxy_gc_drop_queries);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"dns_pxy_fwd_queries_to_inet","%llu",table.dns_pxy_fwd_queries_to_inet);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"dns_pxy_fwd_queries_to_vpn","%llu",table.dns_pxy_fwd_queries_to_vpn);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"dns_pxy_rx_answers_from_inet","%llu",table.dns_pxy_rx_answers_from_inet);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"dns_pxy_rx_answers_from_vpn","%llu",table.dns_pxy_rx_answers_from_vpn);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"dns_pxy_rx_unknown_answers","%llu",table.dns_pxy_rx_unknown_txnid_answers);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;


  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"dns_pxy_no_internal_nameserver_v4","%llu",table.dns_pxy_no_internal_nameserver_v4);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"dns_pxy_no_internal_nameserver_v6","%llu",table.dns_pxy_no_internal_nameserver_v6);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"dns_pxy_no_valid_src_addr_v4","%llu",table.dns_pxy_no_valid_src_addr_v4);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"dns_pxy_no_valid_src_addr_v6","%llu",table.dns_pxy_no_valid_src_addr_v6);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;


  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
  			(xmlChar*)"dns_pxy_activated_v4","%llu",table.dc.dns_pxy_activated_v4);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
  			(xmlChar*)"dns_pxy_deactivated_v4","%llu",table.dc.dns_pxy_deactivated_v4);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
  			(xmlChar*)"dns_pxy_activated_v6","%llu",table.dc.dns_pxy_activated_v6);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
  			(xmlChar*)"dns_pxy_deactivated_v6","%llu",table.dc.dns_pxy_deactivated_v6);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;


	n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
	if(n < 0) {
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
	if(n < 0) {
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  RHP_TRC(0,RHPTRCID_UI_HTTP_GET_GLOBAL_ESP_STATISTICS_SERIALIZE_RTRN,"xd",http_bus_sess,n2);
  return n2;

error:
  RHP_TRC(0,RHPTRCID_UI_HTTP_GET_GLOBAL_ESP_STATISTICS_SERIALIZE_ERR,"xE",http_bus_sess,err);
  return err;
}

static int _rhp_ui_http_get_global_esp_statistics(xmlDocPtr doc,xmlNodePtr node,rhp_http_conn* http_conn,
		rhp_http_bus_session* http_bus_sess,rhp_http_request* http_req,void* ctx)
{
  int err = -EINVAL;
  unsigned long rlm_id = RHP_VPN_REALM_ID_UNKNOWN;

  RHP_TRC(0,RHPTRCID_UI_HTTP_GET_GLOBAL_ESP_STATISTICS,"xxxxxx",doc,node,http_conn,http_bus_sess,http_req,ctx);

  if( doc == NULL || node == NULL ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_GET_GLOBAL_ESP_STATISTICS_NO_DOC_NODE,"xxx",http_conn,http_bus_sess,http_req);
    return -EINVAL;
  }

  if( _rhp_ui_http_get_user_realm_id(http_conn,http_bus_sess,&rlm_id)  ){
  	err = -EPERM;
		RHP_TRC(0,RHPTRCID_UI_HTTP_GET_GLOBAL_ESP_STATISTICS_NOT_PERMITTED,"xxxuu",http_conn,http_bus_sess,http_req,http_conn->user_realm_id,http_bus_sess->user_realm_id);
		goto error;
  }


	err = rhp_http_bus_send_response(
			http_conn,http_bus_sess,_rhp_ui_http_get_global_esp_statistics_serialize,NULL);

	if( err ){
  	goto error;
  }

  RHP_TRC(0,RHPTRCID_UI_HTTP_GET_GLOBAL_ESP_STATISTICS_RTRN,"xxx",http_conn,http_bus_sess,http_req);
  return RHP_STATUS_CLOSE_HTTP_CONN;

error:
  RHP_TRC(0,RHPTRCID_UI_HTTP_GET_GLOBAL_ESP_STATISTICS_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  return err;
}


static int _rhp_ui_http_get_global_bridge_statistics_serialize(rhp_http_bus_session* http_bus_sess,void* ctx,void* writer,int idx)
{
  int err = -EINVAL;
  int n = 0;
  int n2 = 0;
  rhp_bridge_cache_global_statistics table;

  RHP_TRC(0,RHPTRCID_UI_HTTP_GET_GLOBAL_BRIDGE_STATISTICS_SERIALIZE,"xxd",http_bus_sess,writer,idx);

	n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"rhp_http_bus_record");
	if(n < 0) {
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"index","%d",idx);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"service",(xmlChar*)"ui_http_vpn");
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"action",(xmlChar*)"global_statistics_bridge");
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"session_id","%llu",http_bus_sess->session_id);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	rhp_bridge_get_statistics(&table);

	n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"bridge");
	if(n < 0) {
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"bridge.cache_num","%lu",table.dc.bridge.cache_num);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"bridge.referenced","%llu",table.bridge.referenced);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"bridge.static_dmy_cached_found","%llu",table.bridge.static_dmy_cached_found);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"bridge.static_exchg_cached_found","%llu",table.bridge.static_exchg_cached_found);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"bridge.dyn_cached_found","%llu",table.bridge.dyn_cached_found);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"bridge.cached_not_found","%llu",table.bridge.cached_not_found);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"bridge.rx_to_vpn_err_pkts","%llu",table.bridge.rx_to_vpn_err_pkts);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"bridge.rx_from_vpn_err_pkts","%llu",table.bridge.rx_from_vpn_err_pkts);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"bridge.rx_from_vpn_ipip_fwd_err_pkts","%llu",table.bridge.rx_from_vpn_ipip_fwd_err_pkts);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"bridge.tx_from_vpn_flooding_pkts","%llu",table.bridge.tx_from_vpn_flooding_pkts);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"bridge.tx_to_vpn_flooding_pkts","%llu",table.bridge.tx_to_vpn_flooding_pkts);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"neigh.cache_num","%lu",table.dc.neigh.cache_num);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;


	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"neigh.incomplete_addrs","%lu",table.dc.neigh.resolving_addrs);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"arp.pxy_arp_queued_num","%llu",table.dc.arp.pxy_arp_queued_num);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"ipv6_neigh.pxy_nd_queued_num","%llu",table.dc.v6_neigh.pxy_nd_queued_num);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"neigh_cache.referenced","%llu",table.neigh_cache.referenced);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"neigh_cache.static_dmy_cached_found","%llu",table.neigh_cache.static_dmy_cached_found);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"neigh_cache.static_exchg_cached_found","%llu",table.neigh_cache.static_exchg_cached_found);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"neigh_cache.dyn_cached_found","%llu",table.neigh_cache.dyn_cached_found);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"neigh_cache.static_v6_dmy_ll_addr_cached_found","%llu",table.neigh_cache.static_v6_dmy_linklocal_cached_found);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"neigh_cache.static_ikev2_cfg_cached_found","%llu",table.neigh_cache.static_ikev2_cfg_cached_found);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"neigh_cache.cached_not_found","%llu",table.neigh_cache.cached_not_found);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"arp.pxy_arp_reply","%llu",table.arp.pxy_arp_reply);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"arp.pxy_arp_tx_req","%llu",table.arp.pxy_arp_tx_req);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"arp.pxy_arp_queued_packets","%llu",table.arp.pxy_arp_queued_packets);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"arp.pxy_arp_req_rslv_err","%llu",table.arp.pxy_arp_req_rslv_err);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"arp.pxy_arp_tx_req_retried","%llu",table.arp.pxy_arp_tx_req_retried);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;


	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"ipv6_neigh.pxy_nd_tx_sol","%llu",table.v6_neigh.pxy_nd_tx_sol);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"ipv6_neigh.pxy_nd_queued_packets","%llu",table.v6_neigh.pxy_nd_queued_packets);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"ipv6_neigh.pxy_nd_tx_sol_retried","%llu",table.v6_neigh.pxy_nd_tx_sol_retried);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"ipv6_neigh.pxy_nd_sol_rslv_err","%llu",table.v6_neigh.pxy_nd_sol_rslv_err);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"v6_neigh.pxy_nd_adv","%llu",table.v6_neigh.pxy_nd_adv);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;


	n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
	if(n < 0) {
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
	if(n < 0) {
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  RHP_TRC(0,RHPTRCID_UI_HTTP_GET_GLOBAL_BRIDGE_STATISTICS_SERIALIZE_RTRN,"xd",http_bus_sess,n2);
  return n2;

error:
  RHP_TRC(0,RHPTRCID_UI_HTTP_GET_GLOBAL_BRIDGE_STATISTICS_SERIALIZE_ERR,"xE",http_bus_sess,err);
  return err;
}

static int _rhp_ui_http_get_global_bridge_statistics(xmlDocPtr doc,xmlNodePtr node,rhp_http_conn* http_conn,
		rhp_http_bus_session* http_bus_sess,rhp_http_request* http_req,void* ctx)
{
  int err = -EINVAL;
  unsigned long rlm_id = RHP_VPN_REALM_ID_UNKNOWN;

  RHP_TRC(0,RHPTRCID_UI_HTTP_GET_GLOBAL_BRIDGE_STATISTICS,"xxxxxx",doc,node,http_conn,http_bus_sess,http_req,ctx);

  if( doc == NULL || node == NULL ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_GET_GLOBAL_BRIDGE_STATISTICS_NO_DOC_NODE,"xxx",http_conn,http_bus_sess,http_req);
    return -EINVAL;
  }

  if( _rhp_ui_http_get_user_realm_id(http_conn,http_bus_sess,&rlm_id)  ){
  	err = -EPERM;
		RHP_TRC(0,RHPTRCID_UI_HTTP_GET_GLOBAL_BRIDGE_STATISTICS_NOT_PERMITTED,"xxxuu",http_conn,http_bus_sess,http_req,http_conn->user_realm_id,http_bus_sess->user_realm_id);
		goto error;
  }


	err = rhp_http_bus_send_response(
			http_conn,http_bus_sess,_rhp_ui_http_get_global_bridge_statistics_serialize,NULL);

	if( err ){
  	goto error;
  }

  RHP_TRC(0,RHPTRCID_UI_HTTP_GET_GLOBAL_BRIDGE_STATISTICS_RTRN,"xxx",http_conn,http_bus_sess,http_req);
  return RHP_STATUS_CLOSE_HTTP_CONN;

error:
  RHP_TRC(0,RHPTRCID_UI_HTTP_GET_GLOBAL_BRIDGE_STATISTICS_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  return err;
}


static int _rhp_ui_http_get_global_ikev2_statistics_serialize(rhp_http_bus_session* http_bus_sess,void* ctx,void* writer,int idx)
{
  int err = -EINVAL;
  int n = 0;
  int n2 = 0;
  rhp_ikev2_global_statistics table;

  RHP_TRC(0,RHPTRCID_UI_HTTP_GET_GLOBAL_IKEV2_STATISTICS_SERIALIZE,"xxd",http_bus_sess,writer,idx);

	n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"rhp_http_bus_record");
	if(n < 0) {
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"index","%d",idx);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"service",(xmlChar*)"ui_http_vpn");
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"action",(xmlChar*)"global_statistics_ikev2");
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"session_id","%llu",http_bus_sess->session_id);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	rhp_ikev2_get_statistics(&table);

	n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"ikev2");
	if(n < 0) {
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rx_invalid_packets","%llu",table.rx_ikev2_invalid_packets);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rx_err_packets","%llu",table.rx_ikev2_err_packets);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rx_acl_err_packets","%llu",table.rx_ikev2_acl_err_packets);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rx_resp_verify_err_packets","%llu",table.rx_ikev2_resp_verify_err_packets);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rx_resp_unknown_if_err_packets","%llu",table.rx_ikev2_resp_unknown_if_err_packets);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rx_resp_no_ikesa_err_packets","%llu",table.rx_ikev2_resp_no_ikesa_err_packets);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rx_resp_bad_ikesa_state_packets","%llu",table.rx_ikev2_resp_bad_ikesa_state_packets);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rx_resp_no_req_err_packets","%llu",table.rx_ikev2_resp_no_req_err_packets);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rx_resp_invalid_seq_packets","%llu",table.rx_ikev2_resp_invalid_seq_packets);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rx_resp_invalid_exchg_type_packets","%llu",table.rx_ikev2_resp_invalid_exchg_type_packets);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rx_resp_not_encrypted_packets","%llu",table.rx_ikev2_resp_not_encrypted_packets);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rx_resp_integ_err_packets","%llu",table.rx_ikev2_resp_integ_err_packets);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rx_resp_invalid_len_packets","%llu",table.rx_ikev2_resp_invalid_len_packets);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rx_resp_invalid_spi_packets","%llu",table.rx_ikev2_resp_invalid_spi_packets);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rx_resp_parse_err_packets","%llu",table.rx_ikev2_resp_parse_err_packets);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rx_resp_unsup_ver_packets","%llu",table.rx_ikev2_resp_unsup_ver_packets);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rx_resp_err_packets","%llu",table.rx_ikev2_resp_err_packets);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rx_resp_process_err_packets","%llu",table.rx_ikev2_resp_process_err_packets);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rx_resp_from_unknown_peer_packets","%llu",table.rx_ikev2_resp_from_unknown_peer_packets);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	{
		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rx_resp_frag_packets","%llu",table.rx_ikev2_resp_frag_packets);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		n2 += n;

		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rx_resp_invalid_frag_packets","%llu",table.rx_ikev2_resp_invalid_frag_packets);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		n2 += n;

		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rx_resp_too_many_frag_packets","%llu",table.rx_ikev2_resp_too_many_frag_packets);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		n2 += n;

		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rx_resp_too_long_frag_packets","%llu",table.rx_ikev2_resp_too_long_frag_packets);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		n2 += n;

		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rx_resp_rx_dup_frag_packets","%llu",table.rx_ikev2_resp_rx_dup_frag_packets);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		n2 += n;
	}

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rx_req_apply_cookie_packets","%llu",table.rx_ikev2_req_apply_cookie_packets);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"tx_resp_rate_limited_err_packets","%llu",table.tx_ikev2_resp_rate_limited_err_packets);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"tx_resp_retransmit_packets","%llu",table.tx_ikev2_resp_retransmit_packets);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"tx_resp_cookie_packets","%llu",table.tx_ikev2_resp_cookie_packets);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rx_req_verify_err_packets","%llu",table.rx_ikev2_req_verify_err_packets);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rx_req_new_ike_sa_init_packets","%llu",table.rx_ikev2_req_new_ike_sa_init_packets);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rx_req_no_ikesa_err_packets","%llu",table.rx_ikev2_req_no_ikesa_err_packets);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rx_req_unknown_if_err_packets","%llu",table.rx_ikev2_req_unknown_if_err_packets);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rx_req_invalid_exchg_type_packets","%llu",table.rx_ikev2_req_invalid_exchg_type_packets);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rx_req_bad_ikesa_state_packets","%llu",table.rx_ikev2_req_bad_ikesa_state_packets);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rx_req_busy_err_packets","%llu",table.rx_ikev2_req_busy_err_packets);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rx_req_invalid_seq_packets","%llu",table.rx_ikev2_req_invalid_seq_packets);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rx_req_not_encrypted_packets","%llu",table.rx_ikev2_req_not_encrypted_packets);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rx_req_integ_err_packets","%llu",table.rx_ikev2_req_integ_err_packets);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rx_req_invalid_len_packets","%llu",table.rx_ikev2_req_invalid_len_packets);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rx_req_invalid_spi_packets","%llu",table.rx_ikev2_req_invalid_spi_packets);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rx_req_parse_err_packets","%llu",table.rx_ikev2_req_parse_err_packets);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rx_req_unsup_ver_packets","%llu",table.rx_ikev2_req_unsup_ver_packets);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rx_req_err_packets","%llu",table.rx_ikev2_req_err_packets);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rx_req_process_err_packets","%llu",table.rx_ikev2_req_process_err_packets);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rx_req_from_unknown_peer_packets","%llu",table.rx_ikev2_req_from_unknown_peer_packets);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	{
		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rx_req_frag_packets","%llu",table.rx_ikev2_req_frag_packets);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		n2 += n;

		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rx_req_invalid_frag_packets","%llu",table.rx_ikev2_req_invalid_frag_packets);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		n2 += n;

		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rx_req_too_many_frag_packets","%llu",table.rx_ikev2_req_too_many_frag_packets);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		n2 += n;

		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rx_req_too_long_frag_packets","%llu",table.rx_ikev2_req_too_long_frag_packets);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		n2 += n;

		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rx_req_rx_dup_frag_packets","%llu",table.rx_ikev2_req_rx_dup_frag_packets);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		n2 += n;

		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rx_req_rx_frag_timedout","%llu",table.rx_ikev2_req_rx_frag_timedout);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		n2 += n;
	}

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"tx_req_process_err_packets","%llu",table.tx_ikev2_req_process_err_packets);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"tx_req_no_ikesa_err_packets","%llu",table.tx_ikev2_req_no_ikesa_err_packets);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"tx_req_queued_packets","%llu",table.tx_ikev2_req_queued_packets);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"tx_req_alloc_packet_err","%llu",table.tx_ikev2_req_alloc_packet_err);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"tx_req_no_if_err_packets","%llu",table.tx_ikev2_req_no_if_err_packets);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"tx_req_err_packets","%llu",table.tx_ikev2_req_err_packets);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"tx_req_retransmit_packets","%llu",table.tx_ikev2_req_retransmit_packets);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"tx_req_retransmit_errors","%llu",table.tx_ikev2_req_retransmit_errors);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"tx_resp_no_if_err_packets","%llu",table.tx_ikev2_resp_no_if_err_packets);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"tx_resp_process_err_packets","%llu",table.tx_ikev2_resp_process_err_packets);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"tx_resp_err_packets","%llu",table.tx_ikev2_resp_err_packets);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;


  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"qcd_rx_req_packets","%llu",table.qcd_rx_req_packets);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"qcd_rx_req_err_packets","%llu",table.qcd_rx_req_err_packets);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"qcd_rx_req_ignored_packets","%llu",table.qcd_rx_req_ignored_packets);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"qcd_pend_req_packets","%llu",table.dc.qcd_pend_req_packets);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;


  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"qcd_tx_err_resp_packets","%llu",table.qcd_tx_err_resp_packets);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"qcd_rx_err_resp_packets","%llu",table.qcd_rx_err_resp_packets);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"qcd_rx_err_resp_ignored_packets","%llu",table.qcd_rx_err_resp_ignored_packets);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"qcd_rx_err_resp_cleared_ikesas","%llu",table.qcd_rx_err_resp_cleared_ikesas);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}

	n2 += n;
  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"qcd_rx_err_resp_bad_tokens","%llu",table.qcd_rx_err_resp_bad_tokens);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"qcd_rx_err_resp_no_ikesa","%llu",table.qcd_rx_err_resp_no_ikesa);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;


	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"ikev2_alloc_tx_messages","%llu",table.dc.ikev2_alloc_tx_messages);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"ikev2_alloc_rx_messages","%llu",table.dc.ikev2_alloc_rx_messages);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;


	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"max_vpn_sessions_reached","%llu",table.max_vpn_sessions_reached);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"max_half_open_sessions_reached","%llu",table.max_ikesa_half_open_sessions_reached);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"cookie_max_half_open_reached","%llu",table.max_cookie_half_open_sessions_reached);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"cookie_max_half_open_per_sec_reached","%llu",table.max_cookie_half_open_sessions_per_sec_reached);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;


	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"http_clt_get_cert_err","%llu",table.http_clt_get_cert_err);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;


	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"mobike_init_tx_update_sa_addr","%llu",table.mobike_init_tx_update_sa_addr_times);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"mobike_init_exec_rt_check","%llu",table.mobike_init_exec_rt_check_times);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"mobike_init_net_outage","%llu",table.mobike_init_net_outage_times);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"mobike_init_nat_t_addr_changed","%llu",table.mobike_init_nat_t_addr_changed_times);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"mobike_init_tx_probe_packets","%llu",table.mobike_init_tx_probe_packets);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"mobike_resp_rx_update_sa_addr","%llu",table.mobike_resp_rx_update_sa_addr_times);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"mobike_resp_net_outage","%llu",table.mobike_resp_net_outage_times);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;


  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"ikesa_established_as_initiator","%llu",table.ikesa_established_as_initiator);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"ikesa_negotiated_as_initiator","%llu",table.ikesa_negotiated_as_initiator);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"ikesa_deleted_as_initiator","%llu",table.ikesa_deleted_as_initiator);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"ikesa_established_as_responder","%llu",table.ikesa_established_as_responder);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"ikesa_negotiated_as_responder","%llu",table.ikesa_negotiated_as_responder);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"ikesa_deleted_as_responder","%llu",table.ikesa_deleted_as_responder);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"ikesa_responder_exchg_started","%llu",table.ikesa_responder_exchg_started);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"ikesa_auth_errors","%llu",table.ikesa_auth_errors);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"ikesa_auth_rsa_sig","%llu",table.ikesa_auth_rsa_sig);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"ikesa_auth_psk","%llu",table.ikesa_auth_psk);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"ikesa_auth_eap","%llu",table.ikesa_auth_eap);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;




  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"half_open_ikesa_num","%llu",table.dc.ikesa_half_open_num);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"ikesa_initiator_num","%llu",table.dc.ikesa_initiator_num);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"ikesa_responder_num","%llu",table.dc.ikesa_responder_num);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"childsa_established_as_initiator","%llu",table.childsa_established_as_initiator);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"childsa_negotiated_as_initiator","%llu",table.childsa_negotiated_as_initiator);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"childsa_deleted_as_initiator","%llu",table.childsa_deleted_as_initiator);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"childsa_established_as_responder","%llu",table.childsa_established_as_responder);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"childsa_negotiated_as_responder","%llu",table.childsa_negotiated_as_responder);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"childsa_deleted_as_responder","%llu",table.childsa_deleted_as_responder);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"childsa_initiator_num","%llu",table.dc.childsa_initiator_num);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"childsa_responder_num","%llu",table.dc.childsa_responder_num);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;


  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"vpn_num","%lu",table.dc.vpn_num);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"vpn_allocated","%llu",table.vpn_allocated);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"vpn_deleted","%llu",table.vpn_deleted);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
	if(n < 0) {
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
	if(n < 0) {
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  RHP_TRC(0,RHPTRCID_UI_HTTP_GET_GLOBAL_IKEV2_STATISTICS_SERIALIZE_RTRN,"xd",http_bus_sess,n2);
  return n2;

error:
  RHP_TRC(0,RHPTRCID_UI_HTTP_GET_GLOBAL_IKEV2_STATISTICS_SERIALIZE_ERR,"xE",http_bus_sess,err);
  return err;
}

static int _rhp_ui_http_get_global_ikev2_statistics(xmlDocPtr doc,xmlNodePtr node,rhp_http_conn* http_conn,
		rhp_http_bus_session* http_bus_sess,rhp_http_request* http_req,void* ctx)
{
  int err = -EINVAL;
  unsigned long rlm_id = RHP_VPN_REALM_ID_UNKNOWN;

  RHP_TRC(0,RHPTRCID_UI_HTTP_GET_GLOBAL_IKEV2_STATISTICS,"xxxxxx",doc,node,http_conn,http_bus_sess,http_req,ctx);

  if( doc == NULL || node == NULL ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_GET_GLOBAL_IKEV2_STATISTICS_NO_DOC_NODE,"xxx",http_conn,http_bus_sess,http_req);
    return -EINVAL;
  }

  if( _rhp_ui_http_get_user_realm_id(http_conn,http_bus_sess,&rlm_id)  ){
  	err = -EPERM;
		RHP_TRC(0,RHPTRCID_UI_HTTP_GET_GLOBAL_IKEV2_STATISTICS_NOT_PERMITTED,"xxxuu",http_conn,http_bus_sess,http_req,http_conn->user_realm_id,http_bus_sess->user_realm_id);
		goto error;
  }


	err = rhp_http_bus_send_response(
			http_conn,http_bus_sess,_rhp_ui_http_get_global_ikev2_statistics_serialize,NULL);

	if( err ){
  	goto error;
  }

  RHP_TRC(0,RHPTRCID_UI_HTTP_GET_GLOBAL_IKEV2_STATISTICS_RTRN,"xxx",http_conn,http_bus_sess,http_req);
  return RHP_STATUS_CLOSE_HTTP_CONN;

error:
  RHP_TRC(0,RHPTRCID_UI_HTTP_GET_GLOBAL_IKEV2_STATISTICS_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  return err;
}


extern u64 rhp_ui_log_statistics_dropped_log_records;
extern rhp_mutex_t rhp_ui_log_statistics_lock;

extern long rhp_http_svr_get_open_sk_num();
extern long rhp_dns_pxy_get_open_sk_num();
extern long rhp_http_clt_get_open_sk_num();
extern long rhp_dns_resolve_pend_num();

static int _rhp_ui_http_get_global_resource_statistics_serialize(rhp_http_bus_session* http_bus_sess,void* ctx,void* writer,int idx)
{
  int err = -EINVAL;
  int n = 0;
  int n2 = 0;
	rhp_ipcmsg_syspxy_cfg_sub* cfg_sub_dt = (rhp_ipcmsg_syspxy_cfg_sub*)ctx;
  xmlDocPtr auth_doc = NULL;
  xmlNodePtr auth_root_node = NULL;
  int sub_dt_xml_len = 0;
	u64 main_alloc_size = 0;
	u64 main_free_size = 0;
	rhp_wts_worker_statistics* wts_tables = NULL;
	int wts_tables_num = 0;
	int i;


  RHP_TRC(0,RHPTRCID_UI_HTTP_GET_GLOBAL_RESOURCE_STATISTICS_SERIALIZE,"xxd",http_bus_sess,writer,idx);

  sub_dt_xml_len = cfg_sub_dt->len - sizeof(rhp_ipcmsg_syspxy_cfg_sub);

  if( sub_dt_xml_len > 0  ){

  	auth_doc = xmlParseMemory((void*)(cfg_sub_dt + 1),sub_dt_xml_len);
  	if( auth_doc == NULL ){
  		err = -EINVAL;
  		RHP_BUG("");
  		goto error;
  	}

  	auth_root_node = xmlDocGetRootElement(auth_doc);
  	if( auth_root_node == NULL ){
  		xmlFreeDoc(auth_doc);
  		RHP_BUG("");
  		auth_doc = NULL;
  	}
  }

	n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"rhp_http_bus_record");
	if(n < 0) {
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"index","%d",idx);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"service",(xmlChar*)"ui_http_vpn");
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"action",(xmlChar*)"global_statistics_resource");
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"session_id","%llu",http_bus_sess->session_id);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	if( rhp_wts_get_statistics(&wts_tables,&wts_tables_num) ){
		RHP_BUG("");
	}

	if( rhp_mem_statistics_get(&main_alloc_size,&main_free_size) ){
		RHP_BUG("");
	}

	n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"resource");
	if(n < 0) {
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"main_process");
	if(n < 0) {
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"memory_alloc_bytes","%llu",main_alloc_size);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"memory_freed_bytes","%llu",main_free_size);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"memory_used_bytes","%llu",(main_alloc_size - main_free_size));
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	RHP_LOCK(&rhp_pkt_lock_statistics);

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"packet_alloc_no_pool","%llu",rhp_pkt_statistics_alloc_no_pool);
	if(n < 0){
		RHP_UNLOCK(&rhp_pkt_lock_statistics);
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"alloc_large_packets","%llu",rhp_pkt_statistics_alloc_large_pkt);
	if(n < 0){
		RHP_UNLOCK(&rhp_pkt_lock_statistics);
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	RHP_UNLOCK(&rhp_pkt_lock_statistics);

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"packet_pool_num","%d",rhp_pkt_get_pool_cur_num());
	if(n < 0){
		RHP_UNLOCK(&rhp_pkt_lock_statistics);
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;


	RHP_LOCK(&rhp_ui_log_statistics_lock);
	{
		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"dropped_log_records","%llu",rhp_ui_log_statistics_dropped_log_records);
		if(n < 0){
			RHP_UNLOCK(&rhp_ui_log_statistics_lock);
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		n2 += n;
	}
	RHP_UNLOCK(&rhp_ui_log_statistics_lock);


	{
		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"http_svr_open_sks","%ld",rhp_http_svr_get_open_sk_num());
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		n2 += n;
	}


	{
		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"http_clt_open_sks","%ld",rhp_http_clt_get_open_sk_num());
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		n2 += n;
	}


	{
		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"dns_pxy_open_sks","%ld",rhp_dns_pxy_get_open_sk_num());
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		n2 += n;
	}

	{
		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"dns_resolv_pending_num","%ld",rhp_dns_resolve_pend_num());
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		n2 += n;
	}


	{
		rhp_netsock_stat netsock_stat;

		rhp_netsock_get_stat(&netsock_stat);

		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rx_cur_buffer_bytes","%d",netsock_stat.rx_cur_buffer_size);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		n2 += n;

		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rx_ike_cur_buffer_bytes","%d",netsock_stat.rx_ike_cur_buffer_size);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		n2 += n;

		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"rx_def_pkt_size_cnt","%d",netsock_stat.rx_def_pkt_size_cnt);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		n2 += n;

		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"max_rx_bytes_ike_sk","%ld",netsock_stat.max_rx_pkt_ike_sk);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		n2 += n;

		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"max_rx_bytes_ike_natt_sk","%ld",netsock_stat.max_rx_pkt_ike_natt_sk);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		n2 += n;

		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"max_rx_bytes_esp_sk","%ld",netsock_stat.max_rx_pkt_esp_sk);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		n2 += n;
	}




	for( i = 0; i < wts_tables_num; i++ ){

		n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"worker_thread");
		if(n < 0) {
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		n2 += n;

	  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"worker_thread_id","%d",i);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		n2 += n;

	  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"exec_tasks","%llu",wts_tables[i].exec_tasks_counter);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		n2 += n;

	  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"exec_packet_tasks","%llu",wts_tables[i].exec_sta_pkt_tasks_counter);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		n2 += n;

	  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"packet_task_packets","%llu",wts_tables[i].exec_sta_pkt_task_pkts);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		n2 += n;

	  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"esp_tx_packets","%llu",wts_tables[i].exec_sta_esp_tx_tasks_pkts);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		n2 += n;

	  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"netsock_rx_packets","%llu",wts_tables[i].exec_sta_netsock_rx_tasks_pkts);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		n2 += n;

	  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"tuntap_read_packets","%llu",wts_tables[i].exec_sta_tuntap_rd_tasks_pkts);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		n2 += n;

		n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
		if(n < 0) {
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		n2 += n;
	}

	n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
	if(n < 0) {
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;



	if( auth_doc ){

	  err = rhp_xml_write_node(auth_root_node,(xmlTextWriterPtr)writer,&n2,1,NULL,NULL,NULL);
	  if( err ){
	  	RHP_BUG("");
	  	goto error;
	  }
	}

	n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
	if(n < 0) {
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;


	n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
	if(n < 0) {
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	if( auth_doc ){
		xmlFreeDoc(auth_doc);
	}

  if( wts_tables ){
  	_rhp_free(wts_tables);
  }

  RHP_TRC(0,RHPTRCID_UI_HTTP_GET_GLOBAL_RESOURCE_STATISTICS_SERIALIZE_RTRN,"xd",http_bus_sess,n2);
  return n2;

error:
	if( auth_doc ){
		xmlFreeDoc(auth_doc);
	}
  if( wts_tables ){
  	_rhp_free(wts_tables);
  }
  RHP_TRC(0,RHPTRCID_UI_HTTP_GET_GLOBAL_RESOURCE_STATISTICS_SERIALIZE_ERR,"xE",http_bus_sess,err);
  return err;
}


static int _rhp_ui_http_get_global_resource_statistics_bh(xmlDocPtr doc,xmlNodePtr node,rhp_http_conn* http_conn,rhp_http_bus_session* http_bus_sess,
  				rhp_http_request* http_req,int data_len,u8* data,void* ipc_bus_cb_ctx)
{
  int err = -EINVAL;
	rhp_ipcmsg_syspxy_cfg_sub* cfg_sub_dt = (rhp_ipcmsg_syspxy_cfg_sub*)data;

  RHP_TRC(0,RHPTRCID_UI_HTTP_GET_GLOBAL_RESOURCE_STATISTICS_BH,"xxxxxpx",doc,node,http_conn,http_bus_sess,http_req,data_len,data,ipc_bus_cb_ctx);

	if( data_len < (int)sizeof(rhp_ipcmsg_syspxy_cfg_sub) ){
		err = -EINVAL;
		RHP_BUG("%d, %d, %d",cfg_sub_dt->len,data_len,sizeof(rhp_ipcmsg_syspxy_cfg_sub));
		goto error;
	}

	if( !cfg_sub_dt->result ){
		err = -EPERM;
	  RHP_TRC(0,RHPTRCID_UI_HTTP_GET_GLOBAL_RESOURCE_STATISTICS_BH_RESULT_FAILED,"xxxxx",doc,node,http_conn,http_bus_sess,http_req);
		goto error;
	}

  err = rhp_http_bus_send_response(http_conn,http_bus_sess,_rhp_ui_http_get_global_resource_statistics_serialize,(void*)cfg_sub_dt);
  if( err ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_GET_GLOBAL_RESOURCE_STATISTICS_BH_TX_RESP_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
    goto error;
  }

  RHP_TRC(0,RHPTRCID_UI_HTTP_GET_GLOBAL_RESOURCE_STATISTICS_BH_RTRN,"xxxxx",doc,node,http_conn,http_bus_sess,http_req);
  return RHP_STATUS_CLOSE_HTTP_CONN;

error:
	RHP_TRC(0,RHPTRCID_UI_HTTP_GET_GLOBAL_RESOURCE_STATISTICS_BH_ERR,"xxxxxE",doc,node,http_conn,http_bus_sess,http_req,err);
	return err;
}

static int _rhp_ui_http_get_global_resource_statistics(xmlDocPtr doc,xmlNodePtr node,rhp_http_conn* http_conn,
		rhp_http_bus_session* http_bus_sess,rhp_http_request* http_req,void* ctx)
{
  int err = -EINVAL;

  RHP_TRC(0,RHPTRCID_UI_HTTP_GET_GLOBAL_RESOURCE_STATISTICS,"xxxxxx",doc,node,http_conn,http_bus_sess,http_req,ctx);

  if( doc == NULL || node == NULL ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_GET_GLOBAL_RESOURCE_STATISTICS_NO_DOC_NODE,"xxx",http_conn,http_bus_sess,http_req);
    return -EINVAL;
  }

  {
  	rhp_ipcmsg_syspxy_cfg_sub cfg_sub_dt;

  	cfg_sub_dt.cfg_type = RHP_IPC_SYSPXY_CFG_RSRC_STATISTICS;
  	cfg_sub_dt.len = sizeof(rhp_ipcmsg_syspxy_cfg_sub);
  	cfg_sub_dt.target_rlm_id = http_conn->user_realm_id;

  	err = rhp_http_bus_ipc_cfg_request(http_conn,http_bus_sess,
  					sizeof(rhp_ipcmsg_syspxy_cfg_sub),(u8*)&cfg_sub_dt,
  					_rhp_ui_http_get_global_resource_statistics_bh,NULL);
  	if( err ){
  		RHP_BUG("");
  		goto error;
  	}
  }

  RHP_TRC(0,RHPTRCID_UI_HTTP_GET_GLOBAL_RESOURCE_STATISTICS_RTRN,"xxx",http_conn,http_bus_sess,http_req);
  return RHP_STATUS_HTTP_REQ_PENDING;

error:
  RHP_TRC(0,RHPTRCID_UI_HTTP_GET_GLOBAL_RESOURCE_STATISTICS_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  return err;
}


struct _rhp_ui_http_event_log_ctx {
	u8 tag[4]; // '#HEL'
	u64 session_id;
	char* user_name;
	unsigned long vpn_realm_id;
	char* file_name;
	int save_as_txt;
	int err;
};
typedef struct _rhp_ui_http_event_log_ctx	rhp_ui_http_event_log_ctx;

static int _rhp_ui_http_event_log_save_serialize(void* http_bus_sess_d,void* cb_ctx,void* writer,int idx)
{
  int err = -EINVAL;
  rhp_http_bus_session* http_bus_sess = (rhp_http_bus_session*)http_bus_sess_d;
  int n = 0;
  int n2 = 0;
  rhp_ui_http_event_log_ctx* ctx = (rhp_ui_http_event_log_ctx*)cb_ctx;

  RHP_TRC(0,RHPTRCID_UI_HTTP_EVENT_LOG_SAVE_SERIALIZE,"xxdx",http_bus_sess,writer,idx,ctx);

	n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"rhp_http_bus_record");
	if(n < 0) {
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"index","%d",idx);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"service",(xmlChar*)"ui_http_vpn");
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	if( ctx ){

		n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"action",(xmlChar*)"save_event_log_done");
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		n2 += n;

	}else{

		n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"action",(xmlChar*)"save_event_log_error");
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		n2 += n;
	}

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"session_id","%llu",
			http_bus_sess->session_id);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	if( !ctx->err ){

		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"url","%s",ctx->file_name);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		n2 += n;
	}

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"save_as_txt","%s",
			(ctx->save_as_txt ? "enable" : "disable"));
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
	if(n < 0) {
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  RHP_TRC(0,RHPTRCID_UI_HTTP_EVENT_LOG_SAVE_SERIALIZE_RTRN,"xd",http_bus_sess,n2);
  return n2;

error:
  RHP_TRC(0,RHPTRCID_UI_HTTP_EVENT_LOG_SAVE_SERIALIZE_ERR,"xE",http_bus_sess,err);
  return err;
}

static void _rhp_ui_http_event_log_save_finished(int err,void* ctx_d)
{
	rhp_ui_http_event_log_ctx* ctx = (rhp_ui_http_event_log_ctx*)ctx_d;

	RHP_TRC(0,RHPTRCID_UI_HTTP_EVENT_LOG_SAVE_FINISHED,"Exqsus",err,ctx,ctx->session_id,ctx->user_name,ctx->vpn_realm_id,ctx->file_name);

	ctx->err = err;

	rhp_http_bus_send_async(ctx->session_id,ctx->user_name,ctx->vpn_realm_id,1,0,
			_rhp_ui_http_event_log_save_serialize,ctx);

	if( ctx->user_name ){
		_rhp_free(ctx->user_name);
	}
	if( ctx->file_name ){
		_rhp_free(ctx->file_name);
	}
	_rhp_free(ctx);

	RHP_TRC(0,RHPTRCID_UI_HTTP_EVENT_LOG_SAVE_FINISHED_RTRN,"Ex",err,ctx);
	return;
}

static int _rhp_ui_http_event_log_save(xmlDocPtr doc,xmlNodePtr node,rhp_http_conn* http_conn,
		rhp_http_bus_session* http_bus_sess,rhp_http_request* http_req,void* ctx)
{
  int err = -EINVAL;
  unsigned long rlm_id = RHP_VPN_REALM_ID_UNKNOWN;
  rhp_vpn_realm* rlm = NULL;
  char* path = NULL;
  rhp_ui_http_event_log_ctx* cb_ctx = NULL;
  unsigned long limit_num = 0;
	int ret_len;
	int save_as_txt = 0;

  RHP_TRC(0,RHPTRCID_UI_HTTP_EVENT_LOG_SAVE,"xxxxxx",doc,node,http_conn,http_bus_sess,http_req,ctx);

  if( doc == NULL || node == NULL ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_EVENT_LOG_SAVE_NO_DOC_NODE,"xxx",http_conn,http_bus_sess,http_req);
    return -EINVAL;
  }

  if( _rhp_ui_http_get_user_realm_id(http_conn,http_bus_sess,&rlm_id)  ){
  	err = -EPERM;
		RHP_TRC(0,RHPTRCID_UI_HTTP_EVENT_LOG_SAVE_NOT_PERMITTED,"xxxuu",http_conn,http_bus_sess,http_req,http_conn->user_realm_id,http_bus_sess->user_realm_id);
		goto error;
  }


  rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"limit"),RHP_XML_DT_ULONG,&limit_num,&ret_len,NULL,0);
  if( limit_num > (unsigned long)rhp_gcfg_max_event_log_records ){
  	limit_num = (unsigned long)rhp_gcfg_max_event_log_records;
  }

  rhp_xml_check_enable(node,(const xmlChar*)"save_as_txt",&save_as_txt);


  if( rlm_id ){

  	rlm = rhp_realm_get(rlm_id);
  	if( rlm == NULL ){

  	  RHP_TRC(0,RHPTRCID_UI_HTTP_EVENT_LOG_SAVE_REALM_NO_ENT,"xxxxxu",doc,node,http_conn,http_bus_sess,http_req,rlm_id);
    	err = -EPERM;
  		goto error;
  	}
  }

  {
  	int path_len = strlen(http_conn->root_dir) + strlen(http_bus_sess->user_name) + 64;
  	int file_name_len;

  	if( !save_as_txt ){
  		file_name_len = strlen("/protected/log/old_log.xml") + 1;
  	}else{
  		file_name_len = strlen("/protected/log/rockhopper_log.txt") + 1;
  	}

  	path = (char*)_rhp_malloc( path_len );
		if( path == NULL ){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		path[0] = '\0';

  	if( !save_as_txt ){
  		path_len = snprintf(path,path_len,"%s/tmp/event_log_%s.xml",http_conn->root_dir,http_bus_sess->user_name);
  	}else{
  		path_len = snprintf(path,path_len,"%s/tmp/event_log_%s.txt",http_conn->root_dir,http_bus_sess->user_name);
  	}
		path_len++;

  	cb_ctx = (rhp_ui_http_event_log_ctx*)_rhp_malloc(sizeof(rhp_ui_http_event_log_ctx));
		if( cb_ctx == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}
		memset(cb_ctx,0,sizeof(rhp_ui_http_event_log_ctx));

		cb_ctx->user_name = (char*)_rhp_malloc(strlen(http_bus_sess->user_name) + 1);
		if( cb_ctx->user_name == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		cb_ctx->file_name = (char*)_rhp_malloc(file_name_len);
		if( cb_ctx->file_name == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		cb_ctx->tag[0] = '#';
		cb_ctx->tag[1] = 'H';
		cb_ctx->tag[2] = 'E';
		cb_ctx->tag[3] = 'L';

		cb_ctx->session_id = http_bus_sess->session_id;
		cb_ctx->err = 0;
		cb_ctx->save_as_txt = save_as_txt;
		cb_ctx->vpn_realm_id = rlm_id;

		cb_ctx->user_name[0] = '\0';
		strcpy(cb_ctx->user_name,http_bus_sess->user_name);

		cb_ctx->file_name[0] = '\0';
	 	if( !save_as_txt ){
	 		snprintf(cb_ctx->file_name,file_name_len,"%s","/protected/log/old_log.xml");
	 	}else{
	 		snprintf(cb_ctx->file_name,file_name_len,"%s","/protected/log/rockhopper_log.txt");
	 	}
  }


	RHP_TRC(0,RHPTRCID_UI_HTTP_EVENT_LOG_SAVE_CB_CTX,"xqsusd",cb_ctx,cb_ctx->session_id,cb_ctx->user_name,cb_ctx->vpn_realm_id,cb_ctx->file_name,save_as_txt);

	{
 		int file_type = (!save_as_txt ? RHP_LOG_SAVE_TYPE_XML : RHP_LOG_SAVE_TYPE_TXT);

 		if( file_type == RHP_LOG_SAVE_TYPE_TXT ){
 	  	RHP_LOG_I(RHP_LOG_SRC_UI,http_conn->user_realm_id,RHP_LOG_ID_EVENT_LOG_SAVED_AS_TXT,"su",http_conn->user_name,http_conn->user_realm_id);
 		}

 		err = rhp_log_save(file_type,path,rlm_id,limit_num,_rhp_ui_http_event_log_save_finished,(void*)cb_ctx);
 		if( err ){
 			goto error;
 		}
 	}

	err = rhp_http_bus_send_response(http_conn,http_bus_sess,NULL,NULL);
	if( err ){
  	goto error;
  }

  if( rlm ){
  	rhp_realm_unhold(rlm);
  }

  if( path ){
	  _rhp_free(path);
  }

  RHP_TRC(0,RHPTRCID_UI_HTTP_EVENT_LOG_SAVE_RTRN,"xxx",http_conn,http_bus_sess,http_req);
  return RHP_STATUS_CLOSE_HTTP_CONN;

error:
	if( rlm ){
		rhp_realm_unhold(rlm);
	}
  if( path ){
	  _rhp_free(path);
  }
  if( cb_ctx ){
  	if( cb_ctx->user_name ){
  		_rhp_free(cb_ctx->user_name);
  	}
  	if( cb_ctx->file_name ){
  		_rhp_free(cb_ctx->file_name);
  	}
  	_rhp_free(cb_ctx);
  }
  RHP_TRC(0,RHPTRCID_UI_HTTP_EVENT_LOG_SAVE_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  return err;
}

static int _rhp_ui_http_event_log_reset(xmlDocPtr doc,xmlNodePtr node,rhp_http_conn* http_conn,
		rhp_http_bus_session* http_bus_sess,rhp_http_request* http_req,void* ctx)
{
  int err = -EINVAL;
  unsigned long rlm_id = RHP_VPN_REALM_ID_UNKNOWN;

  RHP_TRC(0,RHPTRCID_UI_HTTP_EVENT_LOG_RESET,"xxxxxx",doc,node,http_conn,http_bus_sess,http_req,ctx);

  if( doc == NULL || node == NULL ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_EVENT_LOG_RESET_NO_DOC_NODE,"xxx",http_conn,http_bus_sess,http_req);
    return -EINVAL;
  }

  if( _rhp_ui_http_get_user_realm_id(http_conn,http_bus_sess,&rlm_id)  ){
  	err = -EPERM;
		RHP_TRC(0,RHPTRCID_UI_HTTP_EVENT_LOG_RESET_NOT_PERMITTED,"xxxuu",http_conn,http_bus_sess,http_req,http_conn->user_realm_id,http_bus_sess->user_realm_id);
		goto error;
  }

  if( rlm_id != 0 ){
	  RHP_TRC(0,RHPTRCID_UI_HTTP_EVENT_LOG_RESET_REALM_NO_ENT,"xxxxxu",doc,node,http_conn,http_bus_sess,http_req,rlm_id);
  	err = -EPERM;
		goto error;
  }

  err = rhp_log_reset(NULL,NULL);
  if( err ){
  	goto error;
  }

	err = rhp_http_bus_send_response(http_conn,http_bus_sess,NULL,NULL);
	if( err ){
  	goto error;
  }

  RHP_TRC(0,RHPTRCID_UI_HTTP_EVENT_LOG_RESET_RTRN,"xxx",http_conn,http_bus_sess,http_req);
  return RHP_STATUS_CLOSE_HTTP_CONN;

error:
  RHP_TRC(0,RHPTRCID_UI_HTTP_EVENT_LOG_RESET_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  return err;
}


static int _rhp_ui_http_ikev2_qcd_reset_key_bh(xmlDocPtr doc,xmlNodePtr node,rhp_http_conn* http_conn,rhp_http_bus_session* http_bus_sess,
  				rhp_http_request* http_req,int data_len,u8* data,void* ipc_bus_cb_ctx)
{
  int err = -EINVAL;
	rhp_ipcmsg_syspxy_cfg_sub* cfg_sub_dt = (rhp_ipcmsg_syspxy_cfg_sub*)data;

  RHP_TRC(0,RHPTRCID_UI_HTTP_IKEV2_QCD_RESET_KEY_BH,"xxxxxpx",doc,node,http_conn,http_bus_sess,http_req,data_len,data,ipc_bus_cb_ctx);

	if( data_len < (int)sizeof(rhp_ipcmsg_syspxy_cfg_sub) && (int)cfg_sub_dt->len != data_len ){
		err = -EINVAL;
		RHP_BUG("%d, %d, %d",cfg_sub_dt->len,data_len,sizeof(rhp_ipcmsg_syspxy_cfg_sub));
		goto error;
	}

	if( !cfg_sub_dt->result ){
		err = -EINVAL;
	  RHP_TRC(0,RHPTRCID_UI_HTTP_IKEV2_QCD_RESET_KEY_BH_RESULT_FAILED,"xxxxx",doc,node,http_conn,http_bus_sess,http_req);
		goto error;
	}

  err = rhp_http_bus_send_response(http_conn,http_bus_sess,_rhp_ui_http_cfg_enum_admin_serialize,(void*)cfg_sub_dt);
  if( err ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_IKEV2_QCD_RESET_KEY_BH_TX_RESP_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
    goto error;
  }

	RHP_LOG_I(RHP_LOG_SRC_UI,0,RHP_LOG_ID_RESET_IKEV2_QCD_KEY,"");

  RHP_TRC(0,RHPTRCID_UI_HTTP_IKEV2_QCD_RESET_KEY_BH_RTRN,"xxxxx",doc,node,http_conn,http_bus_sess,http_req);
  return RHP_STATUS_CLOSE_HTTP_CONN;

error:
	RHP_LOG_E(RHP_LOG_SRC_UI,0,RHP_LOG_ID_RESET_IKEV2_QCD_KEY_ERR,"E",err);
	RHP_TRC(0,RHPTRCID_UI_HTTP_IKEV2_QCD_RESET_KEY_BH_ERR,"xxxxxE",doc,node,http_conn,http_bus_sess,http_req,err);
	return err;
}

static int _rhp_ui_http_ikev2_qcd_reset_key(xmlDocPtr doc,xmlNodePtr node,rhp_http_conn* http_conn,
		rhp_http_bus_session* http_bus_sess,rhp_http_request* http_req,void* ctx)
{
  int err = -EINVAL;
  char* vpn_realm_str = NULL;
  unsigned long rlm_id = RHP_VPN_REALM_ID_UNKNOWN;

  RHP_TRC(0,RHPTRCID_UI_HTTP_IKEV2_QCD_RESET_KEY,"xxxxxx",doc,node,http_conn,http_bus_sess,http_req,ctx);

  if( doc == NULL || node == NULL ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_IKEV2_QCD_RESET_KEY_NO_DOC_NODE,"xxx",http_conn,http_bus_sess,http_req);
    return -EINVAL;
  }

  if( _rhp_ui_http_get_user_realm_id(http_conn,http_bus_sess,&rlm_id) ){
			err = -EPERM;
			RHP_TRC(0,RHPTRCID_UI_HTTP_IKEV2_QCD_RESET_KEY_NOT_PERMITTED,"xxxuu",http_conn,http_bus_sess,http_req,http_conn->user_realm_id,http_bus_sess->user_realm_id);
			goto error;
	}

  if( rlm_id ){
		err = -EPERM;
		RHP_TRC(0,RHPTRCID_UI_HTTP_IKEV2_QCD_RESET_KEY_NOT_PERMITTED_2,"xxxuu",http_conn,http_bus_sess,http_req,http_conn->user_realm_id,http_bus_sess->user_realm_id);
		goto error;
  }

  {
  	rhp_ipcmsg_syspxy_cfg_sub cfg_sub_dt;

  	cfg_sub_dt.cfg_type = RHP_IPC_SYSPXY_CFG_RESET_QCD_KEY;
  	cfg_sub_dt.len = sizeof(rhp_ipcmsg_syspxy_cfg_sub);
  	cfg_sub_dt.target_rlm_id = 0;

  	err = rhp_http_bus_ipc_cfg_request(http_conn,http_bus_sess,
  			sizeof(rhp_ipcmsg_syspxy_cfg_sub),(u8*)&cfg_sub_dt,_rhp_ui_http_ikev2_qcd_reset_key_bh,NULL);

  	if( err ){
  		RHP_BUG("");
  		goto error;
  	}
  }

  RHP_TRC(0,RHPTRCID_UI_HTTP_IKEV2_QCD_RESET_KEY_RTRN,"xxxs",http_conn,http_bus_sess,http_req,vpn_realm_str);
  return RHP_STATUS_HTTP_REQ_PENDING;

error:
	RHP_LOG_E(RHP_LOG_SRC_UI,0,RHP_LOG_ID_RESET_IKEV2_QCD_KEY_ERR,"E",err);
  RHP_TRC(0,RHPTRCID_UI_HTTP_IKEV2_QCD_RESET_KEY_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  return err;
}

static int _rhp_ui_http_ikev2_sess_resume_reset_key_bh(xmlDocPtr doc,xmlNodePtr node,rhp_http_conn* http_conn,rhp_http_bus_session* http_bus_sess,
  				rhp_http_request* http_req,int data_len,u8* data,void* ipc_bus_cb_ctx)
{
  int err = -EINVAL;
	rhp_ipcmsg_syspxy_cfg_sub* cfg_sub_dt = (rhp_ipcmsg_syspxy_cfg_sub*)data;

  RHP_TRC(0,RHPTRCID_UI_HTTP_IKEV2_SESS_RESUME_RESET_KEY_BH,"xxxxxpx",doc,node,http_conn,http_bus_sess,http_req,data_len,data,ipc_bus_cb_ctx);

	if( data_len < (int)sizeof(rhp_ipcmsg_syspxy_cfg_sub) && (int)cfg_sub_dt->len != data_len ){
		err = -EINVAL;
		RHP_BUG("%d, %d, %d",cfg_sub_dt->len,data_len,sizeof(rhp_ipcmsg_syspxy_cfg_sub));
		goto error;
	}

	if( !cfg_sub_dt->result ){
		err = -EINVAL;
	  RHP_TRC(0,RHPTRCID_UI_HTTP_IKEV2_SESS_RESUME_RESET_KEY_BH_RESULT_FAILED,"xxxxx",doc,node,http_conn,http_bus_sess,http_req);
		goto error;
	}

  err = rhp_http_bus_send_response(http_conn,http_bus_sess,_rhp_ui_http_cfg_enum_admin_serialize,(void*)cfg_sub_dt);
  if( err ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_IKEV2_SESS_RESUME_RESET_KEY_BH_TX_RESP_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
    goto error;
  }

	RHP_LOG_I(RHP_LOG_SRC_UI,0,RHP_LOG_ID_RESET_IKEV2_SESS_RESUME_KEY,"");

  RHP_TRC(0,RHPTRCID_UI_HTTP_IKEV2_SESS_RESUME_RESET_KEY_BH_RTRN,"xxxxx",doc,node,http_conn,http_bus_sess,http_req);
  return RHP_STATUS_CLOSE_HTTP_CONN;

error:
	RHP_LOG_E(RHP_LOG_SRC_UI,0,RHP_LOG_ID_RESET_IKEV2_SESS_RESUME_KEY_ERR,"E",err);
	RHP_TRC(0,RHPTRCID_UI_HTTP_IKEV2_SESS_RESUME_RESET_KEY_BH_ERR,"xxxxxE",doc,node,http_conn,http_bus_sess,http_req,err);
	return err;
}

static int _rhp_ui_http_ikev2_sess_resume_reset_key(xmlDocPtr doc,xmlNodePtr node,rhp_http_conn* http_conn,
		rhp_http_bus_session* http_bus_sess,rhp_http_request* http_req,void* ctx)
{
  int err = -EINVAL;
  char* vpn_realm_str = NULL;
  unsigned long rlm_id = RHP_VPN_REALM_ID_UNKNOWN;

  RHP_TRC(0,RHPTRCID_UI_HTTP_IKEV2_SESS_RESUME_RESET_KEY,"xxxxxx",doc,node,http_conn,http_bus_sess,http_req,ctx);

  if( doc == NULL || node == NULL ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_IKEV2_SESS_RESUME_RESET_KEY_NO_DOC_NODE,"xxx",http_conn,http_bus_sess,http_req);
    return -EINVAL;
  }

  if( _rhp_ui_http_get_user_realm_id(http_conn,http_bus_sess,&rlm_id) ){
			err = -EPERM;
			RHP_TRC(0,RHPTRCID_UI_HTTP_IKEV2_SESS_RESUME_RESET_KEY_NOT_PERMITTED,"xxxuu",http_conn,http_bus_sess,http_req,http_conn->user_realm_id,http_bus_sess->user_realm_id);
			goto error;
	}

  if( rlm_id ){
		err = -EPERM;
		RHP_TRC(0,RHPTRCID_UI_HTTP_IKEV2_SESS_RESUME_RESET_KEY_NOT_PERMITTED_2,"xxxuu",http_conn,http_bus_sess,http_req,http_conn->user_realm_id,http_bus_sess->user_realm_id);
		goto error;
  }

  {
  	rhp_ipcmsg_syspxy_cfg_sub cfg_sub_dt;

  	cfg_sub_dt.cfg_type = RHP_IPC_SYSPXY_CFG_RESET_SESS_RESUME_KEY;
  	cfg_sub_dt.len = sizeof(rhp_ipcmsg_syspxy_cfg_sub);
  	cfg_sub_dt.target_rlm_id = 0;

  	err = rhp_http_bus_ipc_cfg_request(http_conn,http_bus_sess,
  			sizeof(rhp_ipcmsg_syspxy_cfg_sub),(u8*)&cfg_sub_dt,_rhp_ui_http_ikev2_sess_resume_reset_key_bh,NULL);

  	if( err ){
  		RHP_BUG("");
  		goto error;
  	}
  }

  RHP_TRC(0,RHPTRCID_UI_HTTP_IKEV2_SESS_RESUME_RESET_KEY_RTRN,"xxxs",http_conn,http_bus_sess,http_req,vpn_realm_str);
  return RHP_STATUS_HTTP_REQ_PENDING;

error:
	RHP_LOG_E(RHP_LOG_SRC_UI,0,RHP_LOG_ID_RESET_IKEV2_SESS_RESUME_KEY_ERR,"E",err);
  RHP_TRC(0,RHPTRCID_UI_HTTP_IKEV2_SESS_RESUME_RESET_KEY_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  return err;
}


static u64 _rhp_ui_http_packet_capture_session_id = 0;
static char* _rhp_ui_http_packet_capture_user_id = NULL;

static int _rhp_ui_http_packet_capture_start(xmlDocPtr doc,xmlNodePtr node,rhp_http_conn* http_conn,
		rhp_http_bus_session* http_bus_sess,rhp_http_request* http_req,void* ctx)
{
  int err = -EINVAL;
  unsigned long rlm_id = RHP_VPN_REALM_ID_UNKNOWN;
  rhp_vpn_realm* rlm = NULL;
	int ret_len;
	rhp_pcap_cfg pcap_cfg;
	unsigned long cap_rlm_id = 0;
	int cap_esp_plain_txt = 0, cap_esp_cipher_txt = 0,
			cap_ikev2_plain_txt = 0, cap_ikev2_cipher_txt = 0, cap_vif = 0,
			cap_radius = 0, cap_esp_plain_txt_not_checked = 0;

  RHP_TRC(0,RHPTRCID_UI_HTTP_PACKET_CAPTURE_START,"xxxxxx",doc,node,http_conn,http_bus_sess,http_req,ctx);

  memset(&pcap_cfg,0,sizeof(pcap_cfg));

  if( doc == NULL || node == NULL ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_PACKET_CAPTURE_START_NO_DOC_NODE,"xxx",http_conn,http_bus_sess,http_req);
    return -EINVAL;
  }

  if( _rhp_ui_http_get_user_realm_id(http_conn,http_bus_sess,&rlm_id)  ){
  	err = -EPERM;
		RHP_TRC(0,RHPTRCID_UI_HTTP_PACKET_CAPTURE_START_NOT_PERMITTED,"xxxuu",http_conn,http_bus_sess,http_req,http_conn->user_realm_id,http_bus_sess->user_realm_id);
		goto error;
  }

  if( rlm_id != 0 ){
  	err = -EPERM;
		RHP_TRC(0,RHPTRCID_UI_HTTP_PACKET_CAPTURE_START_NOT_PERMITTED_2,"xxxuuu",http_conn,http_bus_sess,http_req,http_conn->user_realm_id,http_bus_sess->user_realm_id,rlm_id);
  }


  pcap_cfg.file_name = rhp_packet_capture_file_path;

  rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"max_bytes"),RHP_XML_DT_ULONG,&(pcap_cfg.max_bytes),&ret_len,NULL,0);
  rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"max_packets"),RHP_XML_DT_ULONG,&(pcap_cfg.max_packets),&ret_len,NULL,0);
  rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"capture_interval"),RHP_XML_DT_LONG,&(pcap_cfg.capture_interval),&ret_len,NULL,0);
  rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"vpn_realm_id"),RHP_XML_DT_ULONG,&cap_rlm_id,&ret_len,NULL,0);

  rhp_xml_check_enable(node,(const xmlChar*)"capture_esp_plain_txt",&cap_esp_plain_txt);
  rhp_xml_check_enable(node,(const xmlChar*)"capture_esp_cipher_txt",&cap_esp_cipher_txt);
  rhp_xml_check_enable(node,(const xmlChar*)"capture_ikev2_plain_txt",&cap_ikev2_plain_txt);
  rhp_xml_check_enable(node,(const xmlChar*)"capture_ikev2_cipher_txt",&cap_ikev2_cipher_txt);
  rhp_xml_check_enable(node,(const xmlChar*)"capture_vpn_if",&cap_vif);
  rhp_xml_check_enable(node,(const xmlChar*)"capture_radius",&cap_radius);
  rhp_xml_check_enable(node,(const xmlChar*)"capture_esp_plain_txt_not_checked",&cap_esp_plain_txt_not_checked);


  if( pcap_cfg.max_bytes < 1 && pcap_cfg.max_packets < 1 ){
  	RHP_BUG("%lu, %lu",pcap_cfg.max_bytes,pcap_cfg.max_packets);
  	err = -EINVAL;
  	goto error;
  }

  if( !cap_esp_plain_txt && !cap_esp_cipher_txt && !cap_ikev2_plain_txt &&
  		!cap_ikev2_cipher_txt && !cap_vif && !cap_radius){
  	RHP_BUG("");
  	err = -EINVAL;
  	goto error;
  }

  if( cap_rlm_id ){

  	rlm = rhp_realm_get(cap_rlm_id);
  	if( rlm == NULL ){

  	  RHP_TRC(0,RHPTRCID_UI_HTTP_PACKET_CAPTURE_START_REALM_NO_ENT,"xxxxxu",doc,node,http_conn,http_bus_sess,http_req,rlm_id);
    	err = -EPERM;
  		goto error;
  	}
  }


  err = rhp_pcap_start(&pcap_cfg);
  if( err ){
		RHP_TRC(0,RHPTRCID_UI_HTTP_PACKET_CAPTURE_START_CAP_START_FAILED,"xxxuuu",http_conn,http_bus_sess,http_req,http_conn->user_realm_id,http_bus_sess->user_realm_id,rlm_id);
  	goto error;
  }


	err = rhp_http_bus_send_response(http_conn,http_bus_sess,NULL,NULL);
	if( err ){
  	goto error;
  }


  rhp_packet_capture_flags[RHP_PKT_CAP_FLAG_ESP_PLAIN] = cap_esp_plain_txt;
  rhp_packet_capture_flags[RHP_PKT_CAP_FLAG_ESP_CIPHER] = cap_esp_cipher_txt;
  rhp_packet_capture_flags[RHP_PKT_CAP_FLAG_IKEV2_PLAIN] = cap_ikev2_plain_txt;
  rhp_packet_capture_flags[RHP_PKT_CAP_FLAG_IKEV2_CIPHER] = cap_ikev2_cipher_txt;
  rhp_packet_capture_flags[RHP_PKT_CAP_FLAG_VIF] = cap_vif;
  rhp_packet_capture_flags[RHP_PKT_CAP_FLAG_RADIUS] = cap_radius;
  rhp_packet_capture_flags[RHP_PKT_CAP_FLAG_ESP_PLAIN_NOT_CHECKED] = cap_esp_plain_txt_not_checked;


  RHP_LOCK(&_rhp_ui_http_packet_capture_lock);
  {
  	int user_name_len = strlen(http_conn->user_name);

  	if( _rhp_ui_http_packet_capture_user_id ){
  		_rhp_free(_rhp_ui_http_packet_capture_user_id);
  		_rhp_ui_http_packet_capture_session_id = 0;
  	}

  	_rhp_ui_http_packet_capture_user_id = (char*)_rhp_malloc(user_name_len + 1);
  	if( _rhp_ui_http_packet_capture_user_id ){
  		memcpy(_rhp_ui_http_packet_capture_user_id,http_conn->user_name,user_name_len);
  		_rhp_ui_http_packet_capture_user_id[user_name_len] = '\0';
  	}

  	_rhp_ui_http_packet_capture_session_id = http_bus_sess->session_id;
  }
  RHP_UNLOCK(&_rhp_ui_http_packet_capture_lock);


  if( rlm ){
  	rhp_realm_unhold(rlm);
  }

  RHP_TRC(0,RHPTRCID_UI_HTTP_PACKET_CAPTURE_START_RTRN,"xxx",http_conn,http_bus_sess,http_req);
  return RHP_STATUS_CLOSE_HTTP_CONN;

error:

	if( rlm ){
		rhp_realm_unhold(rlm);
	}
  RHP_TRC(0,RHPTRCID_UI_HTTP_PACKET_CAPTURE_START_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  return err;
}

static int _rhp_ui_http_packet_capture_status_serialize(rhp_http_bus_session* http_bus_sess,void* cb_ctx,void* writer,int idx)
{
  int err = -EINVAL;
  int n = 0;
  int n2 = 0;
	rhp_pcap_status* pcap_status = (rhp_pcap_status*)cb_ctx;

  RHP_TRC(0,RHPTRCID_UI_HTTP_CAPTURE_PACKET_STATUS_SERIALIZE,"xxdx",http_bus_sess,writer,idx,cb_ctx);

	n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"rhp_http_bus_record");
	if(n < 0) {
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"index","%d",idx);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"service",(xmlChar*)"ui_http_vpn");
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"action",(xmlChar*)"packet_capture_status");
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"session_id","%llu",
			http_bus_sess->session_id);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;


	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"is_active","%d",pcap_status->is_active);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"captured_bytes","%lu",pcap_status->captured_bytes);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"captured_packets","%lu",pcap_status->captured_packets);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"capture_finished","%d",pcap_status->capture_finished);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;


	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"expire_time","%ld",pcap_status->expire_time);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"elapsed_time","%ld",pcap_status->elapsed_time);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
	if(n < 0) {
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  RHP_TRC(0,RHPTRCID_UI_HTTP_CAPTURE_PACKET_STATUS_SERIALIZE_RTRN,"xd",http_bus_sess,n2);
  return n2;

error:
  RHP_TRC(0,RHPTRCID_UI_HTTP_CAPTURE_PACKET_STATUS_SERIALIZE_ERR,"xE",http_bus_sess,err);
  return err;
}

static int _rhp_ui_http_packet_capture_status(xmlDocPtr doc,xmlNodePtr node,rhp_http_conn* http_conn,
		rhp_http_bus_session* http_bus_sess,rhp_http_request* http_req,void* ctx)
{
  int err = -EINVAL;
  unsigned long rlm_id = RHP_VPN_REALM_ID_UNKNOWN;
	rhp_pcap_status pcap_status;

  RHP_TRC(0,RHPTRCID_UI_HTTP_PACKET_CAPTURE_STATUS,"xxxxxx",doc,node,http_conn,http_bus_sess,http_req,ctx);

  memset(&pcap_status,0,sizeof(rhp_pcap_status));

  if( doc == NULL || node == NULL ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_PACKET_CAPTURE_STATUS_NO_DOC_NODE,"xxx",http_conn,http_bus_sess,http_req);
    return -EINVAL;
  }

  if( _rhp_ui_http_get_user_realm_id(http_conn,http_bus_sess,&rlm_id)  ){
  	err = -EPERM;
		RHP_TRC(0,RHPTRCID_UI_HTTP_PACKET_CAPTURE_STATUS_NOT_PERMITTED,"xxxuu",http_conn,http_bus_sess,http_req,http_conn->user_realm_id,http_bus_sess->user_realm_id);
		goto error;
  }

  if( rlm_id != 0 ){
  	err = -EPERM;
		RHP_TRC(0,RHPTRCID_UI_HTTP_PACKET_CAPTURE_STATUS_NOT_PERMITTED_2,"xxxuuu",http_conn,http_bus_sess,http_req,http_conn->user_realm_id,http_bus_sess->user_realm_id,rlm_id);
  }


  rhp_pcap_get_status(&pcap_status);


	err = rhp_http_bus_send_response(http_conn,http_bus_sess,
			_rhp_ui_http_packet_capture_status_serialize,&pcap_status);
	if( err ){
  	goto error;
  }

  RHP_TRC(0,RHPTRCID_UI_HTTP_PACKET_CAPTURE_STATUS_RTRN,"xxx",http_conn,http_bus_sess,http_req);
  return RHP_STATUS_CLOSE_HTTP_CONN;

error:
  RHP_TRC(0,RHPTRCID_UI_HTTP_PACKET_CAPTURE_STATUS_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  return err;
}

static int _rhp_ui_http_packet_capture_save_serialize(rhp_http_bus_session* http_bus_sess,void* cb_ctx,void* writer,int idx)
{
  int err = -EINVAL;
  int n = 0;
  int n2 = 0;

  RHP_TRC(0,RHPTRCID_UI_HTTP_PACKET_CAPTURE_SAVE_SERIALIZE,"xxdx",http_bus_sess,writer,idx,cb_ctx);

	n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"rhp_http_bus_record");
	if(n < 0) {
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"index","%d",idx);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"service",(xmlChar*)"ui_http_vpn");
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"action",(xmlChar*)"packet_capture_save");
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"session_id","%llu",
			http_bus_sess->session_id);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"url",
			"%s","/protected/packet_capture/rockhopper.pcap");
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
	if(n < 0) {
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  RHP_TRC(0,RHPTRCID_UI_HTTP_PACKET_CAPTURE_SAVE_SERIALIZE_RTRN,"xd",http_bus_sess,n2);
  return n2;

error:
  RHP_TRC(0,RHPTRCID_UI_HTTP_PACKET_CAPTURE_SAVE_SERIALIZE_ERR,"xE",http_bus_sess,err);
  return err;
}

static int _rhp_ui_http_packet_capture_save(xmlDocPtr doc,xmlNodePtr node,rhp_http_conn* http_conn,
		rhp_http_bus_session* http_bus_sess,rhp_http_request* http_req,void* ctx)
{
  int err = -EINVAL;
  unsigned long rlm_id = RHP_VPN_REALM_ID_UNKNOWN;

  RHP_TRC(0,RHPTRCID_UI_HTTP_PACKET_CAPTURE_SAVE,"xxxxxx",doc,node,http_conn,http_bus_sess,http_req,ctx);

  if( doc == NULL || node == NULL ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_PACKET_CAPTURE_SAVE_NO_DOC_NODE,"xxx",http_conn,http_bus_sess,http_req);
    return -EINVAL;
  }

  if( _rhp_ui_http_get_user_realm_id(http_conn,http_bus_sess,&rlm_id)  ){
  	err = -EPERM;
		RHP_TRC(0,RHPTRCID_UI_HTTP_PACKET_CAPTURE_SAVE_NOT_PERMITTED,"xxxuu",http_conn,http_bus_sess,http_req,http_conn->user_realm_id,http_bus_sess->user_realm_id);
		goto error;
  }

  if( rlm_id != 0 ){
  	err = -EPERM;
		RHP_TRC(0,RHPTRCID_UI_HTTP_PACKET_CAPTURE_SAVE_NOT_PERMITTED_2,"xxxuuu",http_conn,http_bus_sess,http_req,http_conn->user_realm_id,http_bus_sess->user_realm_id,rlm_id);
		goto error;
  }


	err = rhp_pcap_stop();
	if( err ){
		goto error;
	}


	rhp_packet_capture_flags[RHP_PKT_CAP_FLAG_ESP_PLAIN] = 0;
	rhp_packet_capture_flags[RHP_PKT_CAP_FLAG_ESP_CIPHER] = 0;
	rhp_packet_capture_flags[RHP_PKT_CAP_FLAG_IKEV2_PLAIN] = 0;
	rhp_packet_capture_flags[RHP_PKT_CAP_FLAG_IKEV2_CIPHER] = 0;
	rhp_packet_capture_flags[RHP_PKT_CAP_FLAG_MAX] = 0;


  RHP_LOCK(&_rhp_ui_http_packet_capture_lock);
  {
  	if( _rhp_ui_http_packet_capture_user_id ){
  		_rhp_free(_rhp_ui_http_packet_capture_user_id);
  		_rhp_ui_http_packet_capture_user_id = NULL;
  	}

  	_rhp_ui_http_packet_capture_session_id = 0;
  }
  RHP_UNLOCK(&_rhp_ui_http_packet_capture_lock);



	err = rhp_http_bus_send_response(http_conn,http_bus_sess,_rhp_ui_http_packet_capture_save_serialize,NULL);
	if( err ){
  	goto error;
  }

  RHP_TRC(0,RHPTRCID_UI_HTTP_PACKET_CAPTURE_SAVE_RTRN,"xxx",http_conn,http_bus_sess,http_req);
  return RHP_STATUS_CLOSE_HTTP_CONN;

error:
  RHP_TRC(0,RHPTRCID_UI_HTTP_PACKET_CAPTURE_SAVE_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  return err;
}


static int _rhp_ui_http_packet_capture_timer_update_cb_serialize(void* http_bus_sess_d,void* cb_ctx,void* writer,int idx)
{
	return _rhp_ui_http_packet_capture_status_serialize(
			(rhp_http_bus_session*)http_bus_sess_d,cb_ctx,writer,idx);
}

void rhp_ui_http_packet_capture_timer_update_cb(rhp_pcap_status* status,void* cb_ctx)
{
	RHP_TRC(0,RHPTRCID_UI_HTTP_PACKET_CAPTURE_TIMER_UPDATE_CB,"xx",status,cb_ctx);

  RHP_LOCK(&_rhp_ui_http_packet_capture_lock);
  {
  	if( _rhp_ui_http_packet_capture_user_id &&
  			_rhp_ui_http_packet_capture_session_id ){

  		rhp_http_bus_send_async(_rhp_ui_http_packet_capture_session_id,
  				_rhp_ui_http_packet_capture_user_id,0,1,0,
					_rhp_ui_http_packet_capture_timer_update_cb_serialize,status);
  	}
  }
  RHP_UNLOCK(&_rhp_ui_http_packet_capture_lock);

	RHP_TRC(0,RHPTRCID_UI_HTTP_PACKET_CAPTURE_TIMER_UPDATE_CB_RTRN,"xx",status,cb_ctx);
	return;
}



static int _rhp_ui_http_clear_interface_statistics(xmlDocPtr doc,xmlNodePtr node,rhp_http_conn* http_conn,
		rhp_http_bus_session* http_bus_sess,rhp_http_request* http_req,void* ctx)
{
  int err = -EINVAL;
  unsigned long rlm_id = RHP_VPN_REALM_ID_UNKNOWN;
  char* if_name_str = NULL;

  RHP_TRC(0,RHPTRCID_UI_HTTP_CLEAR_INTERFACE_STATISTICS,"xxxxxx",doc,node,http_conn,http_bus_sess,http_req,ctx);

  if( doc == NULL || node == NULL ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_CLEAR_INTERFACE_STATISTICS_NO_DOC_NODE,"xxx",http_conn,http_bus_sess,http_req);
    return -EINVAL;
  }

  if( _rhp_ui_http_get_user_realm_id(http_conn,http_bus_sess,&rlm_id)  ){
  	err = -EPERM;
		RHP_TRC(0,RHPTRCID_UI_HTTP_CLEAR_INTERFACE_STATISTICS_NOT_PERMITTED,"xxxuu",http_conn,http_bus_sess,http_req,http_conn->user_realm_id,http_bus_sess->user_realm_id);
		goto error;
  }

  if( rlm_id != 0 ){
	  RHP_TRC(0,RHPTRCID_UI_HTTP_CLEAR_INTERFACE_STATISTICS_REALM_NO_ENT,"xxxxxu",doc,node,http_conn,http_bus_sess,http_req,rlm_id);
  	err = -EPERM;
		goto error;
  }

  if_name_str = (char*)rhp_xml_get_prop(node,(const xmlChar*)"interface");
  if( if_name_str == NULL ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_CLEAR_INTERFACE_STATISTICS_NO_IFNAME,"xxx",http_conn,http_bus_sess,http_req);
    err = -ENOENT;
    goto error;
  }else{
    RHP_TRC(0,RHPTRCID_UI_HTTP_CLEAR_INTERFACE_STATISTICS_IFNAME,"xxxs",http_conn,http_bus_sess,http_req,if_name_str);
  }

  {
  	rhp_ifc_entry* ifc = rhp_ifc_get(if_name_str);
  	if( ifc == NULL ){
  		err = -ENOENT;
  		goto error;
  	}

    RHP_LOCK(&(ifc->lock));

    memset(&(ifc->statistics.raw),0,sizeof(ifc->statistics));
    RHP_TRC(0,RHPTRCID_UI_HTTP_CLEAR_INTERFACE_STATISTICS_CLEARED,"xxxxsd",http_conn,http_bus_sess,http_req,ifc,if_name_str,(int)sizeof(ifc->statistics));

    RHP_UNLOCK(&(ifc->lock));
  }

	err = rhp_http_bus_send_response(http_conn,http_bus_sess,NULL,NULL);
	if( err ){
  	goto error;
  }

  RHP_TRC(0,RHPTRCID_UI_HTTP_CLEAR_INTERFACE_STATISTICS_RTRN,"xxx",http_conn,http_bus_sess,http_req);
  return RHP_STATUS_CLOSE_HTTP_CONN;

error:
  RHP_TRC(0,RHPTRCID_UI_HTTP_CLEAR_INTERFACE_STATISTICS_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  return err;
}

static int _rhp_ui_http_clear_global_statistics(xmlDocPtr doc,xmlNodePtr node,rhp_http_conn* http_conn,
		rhp_http_bus_session* http_bus_sess,rhp_http_request* http_req,void* ctx,char* action_str)
{
  int err = -EINVAL;
  unsigned long rlm_id = RHP_VPN_REALM_ID_UNKNOWN;

  RHP_TRC(0,RHPTRCID_UI_HTTP_CLEAR_GLOBAL_STATISTICS,"xxxxxxs",doc,node,http_conn,http_bus_sess,http_req,ctx,action_str);

  if( doc == NULL || node == NULL ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_CLEAR_GLOBAL_STATISTICS_NO_DOC_NODE,"xxx",http_conn,http_bus_sess,http_req);
    return -EINVAL;
  }

  if( _rhp_ui_http_get_user_realm_id(http_conn,http_bus_sess,&rlm_id)  ){
  	err = -EPERM;
		RHP_TRC(0,RHPTRCID_UI_HTTP_CLEAR_GLOBAL_STATISTICS_NOT_PERMITTED,"xxxuu",http_conn,http_bus_sess,http_req,http_conn->user_realm_id,http_bus_sess->user_realm_id);
		goto error;
  }

  if( rlm_id != 0 ){
	  RHP_TRC(0,RHPTRCID_UI_HTTP_CLEAR_GLOBAL_STATISTICS_REALM_NO_ENT,"xxxxxu",doc,node,http_conn,http_bus_sess,http_req,rlm_id);
  	err = -EPERM;
		goto error;
  }

  if( !strcmp(action_str,"clear_global_statistics_esp") ){

  	rhp_esp_clear_statistics();

  }else if( !strcmp(action_str,"clear_global_statistics_ikev2") ){

  	rhp_ikev2_clear_statistics();

  }else if( !strcmp(action_str,"clear_global_statistics_bridge") ){

  	rhp_bridge_clear_statistics();

  }else if( !strcmp(action_str,"clear_global_statistics_resource") ){

  	if( rhp_wts_clear_statistics() ){
  		RHP_BUG("");
  	}

  }else{
  	RHP_BUG("");
  	err = -EPERM;
  	goto error;
  }

	err = rhp_http_bus_send_response(http_conn,http_bus_sess,NULL,NULL);
	if( err ){
  	goto error;
  }

  RHP_TRC(0,RHPTRCID_UI_HTTP_CLEAR_GLOBAL_STATISTICS_RTRN,"xxx",http_conn,http_bus_sess,http_req);
  return RHP_STATUS_CLOSE_HTTP_CONN;

error:
  RHP_TRC(0,RHPTRCID_UI_HTTP_CLEAR_GLOBAL_STATISTICS_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  return err;
}



struct _rhp_ui_http_cfg_arch_ctx {
	u8 tag[4]; // '#CFB'
	u64 session_id;
	char* user_name;
	char* file_name;
	char* file_pw;
	int err_resp;
};
typedef struct _rhp_ui_http_cfg_arch_ctx	rhp_ui_http_cfg_arch_ctx;

static rhp_ui_http_cfg_arch_ctx* _rhp_ui_http_cfg_arch_ctx_alloc(
		u64 session_id,char* user_name,char* file_name,char* file_pw)
{
	rhp_ui_http_cfg_arch_ctx* cb_ctx = NULL;

	cb_ctx = (rhp_ui_http_cfg_arch_ctx*)_rhp_malloc(sizeof(rhp_ui_http_cfg_arch_ctx));
	if( cb_ctx == NULL ){
		RHP_BUG("");
		goto error;
	}
	memset(cb_ctx,0,sizeof(rhp_ui_http_cfg_arch_ctx));

	if( user_name ){
		cb_ctx->user_name = (char*)_rhp_malloc(strlen(user_name) + 1);
		if( cb_ctx->user_name == NULL ){
			RHP_BUG("");
			goto error;
		}
	}

	if( file_name ){
		cb_ctx->file_name = (char*)_rhp_malloc(strlen(file_name) + 1);
		if( cb_ctx->file_name == NULL ){
			RHP_BUG("");
			goto error;
		}
	}

	if( file_pw ){
		cb_ctx->file_pw = (char*)_rhp_malloc(strlen(file_pw) + 1);
		if( cb_ctx->file_pw == NULL ){
			RHP_BUG("");
			goto error;
		}
	}

	cb_ctx->tag[0] = '#';
	cb_ctx->tag[1] = 'C';
	cb_ctx->tag[2] = 'F';
	cb_ctx->tag[3] = 'B';

	cb_ctx->session_id = session_id;

	if( user_name ){
		cb_ctx->user_name[0] = '\0';
		strcpy(cb_ctx->user_name,user_name);
	}

	if( file_name ){
		cb_ctx->file_name[0] = '\0';
		strcpy(cb_ctx->file_name,file_name);
	}

	if( file_pw ){
		cb_ctx->file_pw[0] = '\0';
		strcpy(cb_ctx->file_pw,file_pw);
	}

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_ARCH_CTX_ALLOC,"x",cb_ctx);
	return cb_ctx;

error:
	return NULL;
}


static void _rhp_ui_http_cfg_arch_ctx_free(void* ctx)
{
	rhp_ui_http_cfg_arch_ctx* cb_ctx = (rhp_ui_http_cfg_arch_ctx*)ctx;

	RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_ARCH_CTX_FREE,"x",cb_ctx);

	if( cb_ctx ){
		if( cb_ctx->user_name ){
			_rhp_free(cb_ctx->user_name);
		}
		if( cb_ctx->file_name ){
			_rhp_free(cb_ctx->file_name);
		}
		if( cb_ctx->file_pw ){
			_rhp_free_zero(cb_ctx->file_pw,strlen(cb_ctx->file_pw));
		}
		_rhp_free(cb_ctx);
	}
}

static int _rhp_ui_http_cfg_bkup_save_serialize(void* http_bus_sess_d,void* ctx,void* writer,int idx)
{
  int err = -EINVAL;
  rhp_http_bus_session* http_bus_sess = (rhp_http_bus_session*)http_bus_sess_d;
  int n = 0;
  int n2 = 0;

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_BKUP_SAVE_SERIALIZE,"xxdx",http_bus_sess,writer,idx,ctx);

	n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"rhp_http_bus_record");
	if(n < 0) {
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"index","%d",idx);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"service",(xmlChar*)"ui_http_vpn");
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	if( ctx ){

		n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"action",(xmlChar*)"config_archive_save_done");
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		n2 += n;

	}else{

		n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"action",(xmlChar*)"config_archive_save_error");
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		n2 += n;
	}

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"session_id","%llu",http_bus_sess->session_id);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	if( ctx ){

		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"url","%s",(char*)ctx);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		n2 += n;
	}

	n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
	if(n < 0) {
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_BKUP_SAVE_SERIALIZE_RTRN,"xd",http_bus_sess,n2);
  return n2;

error:
  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_BKUP_SAVE_SERIALIZE_ERR,"xE",http_bus_sess,err);
  return err;
}

static void _rhp_ui_http_cfg_bkup_save_finished(rhp_http_bus_session* http_bus_sess,int err,void* ctx_d)
{
	rhp_ui_http_cfg_arch_ctx* ctx = (rhp_ui_http_cfg_arch_ctx*)ctx_d;
	char* file_name = NULL;

	RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_BKUP_SAVE_FINISHED,"xExqss",http_bus_sess,err,ctx,ctx->session_id,ctx->user_name,ctx->file_name);

	if( !err ){
		file_name = ctx->file_name;
	}

	rhp_http_bus_send_async_unlocked(http_bus_sess,0,1,0,
			_rhp_ui_http_cfg_bkup_save_serialize,(void*)file_name);

	RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_BKUP_SAVE_FINISHED_RTRN,"Ex",err,ctx);
	return;
}


int rhp_ui_http_cfg_bkup_save_bh(rhp_http_bus_session* http_bus_sess,rhp_ipcmsg_syspxy_cfg_sub* cfg_sub_dt)
{
  int err = -EINVAL;
  rhp_ui_http_cfg_arch_ctx* cb_ctx = (rhp_ui_http_cfg_arch_ctx*)http_bus_sess->cfg_save_cb_ctx;
  char *pw_path = NULL, *pw_cont = NULL;
	rhp_cmd_tlv_list tlvlst;

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_BKUP_SAVE_BH,"xpx",http_bus_sess,cfg_sub_dt->len,cfg_sub_dt,cb_ctx);

  memset(&tlvlst,0,sizeof(rhp_cmd_tlv_list));

  http_bus_sess->cfg_save_cb_ctx = NULL;
  http_bus_sess->cfg_save_cb_ctx_free = NULL;

	if( !cfg_sub_dt->result ){
		err = -EINVAL;
	  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_BKUP_SAVE_BH_RESULT_FAILED,"x",http_bus_sess);
		goto error;
	}

  {
		pw_path = (char*)_rhp_malloc( strlen(rhp_home_dir) + strlen("/tmp/rockhopper_rcfg_save_pw") + 1 );
		if( pw_path == NULL ){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		pw_path[0] = '\0';

		sprintf(pw_path,"%s/%s",rhp_home_dir,"tmp/rockhopper_rcfg_save_pw");

		unlink(pw_path);

		pw_cont = (char*)_rhp_malloc( strlen(cb_ctx->file_pw)*2 + 4 );
		if( pw_cont == NULL ){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		pw_cont[0] = '\0';

		sprintf(pw_cont,"%s\n%s\n",cb_ctx->file_pw,cb_ctx->file_pw);


		err = rhp_file_write(pw_path,(u8*)pw_cont,strlen(pw_cont),(S_IRUSR | S_IWUSR | S_IXUSR));
		if( err ){
			RHP_BUG("%d",err);
			goto error;
		}
	}

	{
		err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_STRING,"RHP_CFG_BKUP_ACTION",(strlen("SAVE") + 1),"SAVE");
		if( err ){
			RHP_BUG("");
			goto error;
		}

		err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_STRING,"RHP_CFG_BKUP_PW",(strlen(pw_path) + 1),pw_path);
		if( err ){
			RHP_BUG("");
			goto error;
		}

		err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_STRING,"RHP_CFG_BKUP_HOME_DIR",
				(strlen(rhp_home_dir) + 1),rhp_home_dir);

		if( err ){
			RHP_BUG("");
			goto error;
		}

		err = rhp_cmd_exec(rhp_cfg_bkup_cmd_path,&tlvlst,1);
		if( err ){
			RHP_BUG("%d",err);
			goto error;
		}

		rhp_cmd_tlv_clear(&tlvlst);
	}

	_rhp_ui_http_cfg_bkup_save_finished(http_bus_sess,0,cb_ctx);

	_rhp_ui_http_cfg_arch_ctx_free(cb_ctx);

	unlink(pw_path);
	_rhp_free(pw_path);

	_rhp_free(pw_cont);

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_BKUP_SAVE_BH_RTRN,"xx",http_bus_sess,cfg_sub_dt);
  return 0;


error:
	_rhp_ui_http_cfg_bkup_save_finished(http_bus_sess,err,cb_ctx);
	_rhp_ui_http_cfg_arch_ctx_free(cb_ctx);
	if( pw_path ){
		unlink(pw_path);
		_rhp_free(pw_path);
	}
	if( pw_cont ){
		_rhp_free(pw_cont);
	}
	rhp_cmd_tlv_clear(&tlvlst);

	RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_BKUP_SAVE_BH_ERR,"xxE",http_bus_sess,cfg_sub_dt,err);
	return 0; // Return success to notify error status of the client.
}

#define RHP_CFG_BKUP_MAX_PW_LEN		64

static int _rhp_ui_http_cfg_bkup_save(xmlDocPtr doc,xmlNodePtr node,rhp_http_conn* http_conn,
		rhp_http_bus_session* http_bus_sess,rhp_http_request* http_req,void* ctx)
{
  int err = -EINVAL;
  unsigned long rlm_id = RHP_VPN_REALM_ID_UNKNOWN;
  rhp_ui_http_cfg_arch_ctx* cb_ctx = NULL;
  char* file_pw = NULL;
  int file_pw_len = 0;


  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_BKUP_SAVE,"xxxxxx",doc,node,http_conn,http_bus_sess,http_req,ctx);

  if( doc == NULL || node == NULL ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_BKUP_SAVE_NO_DOC_NODE,"xxx",http_conn,http_bus_sess,http_req);
    return -EINVAL;
  }

  if( _rhp_ui_http_get_user_realm_id(http_conn,http_bus_sess,&rlm_id) || rlm_id != 0 ){
  	err = -EPERM;
		RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_BKUP_SAVE_NOT_PERMITTED,"xxxuu",http_conn,http_bus_sess,http_req,http_conn->user_realm_id,http_bus_sess->user_realm_id);
		goto error;
  }

  file_pw = (char*)rhp_xml_get_prop(node,(const xmlChar*)"password");
  if( file_pw == NULL ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_BKUP_SAVE_NO_FILE_PASSWORD,"xxx",http_conn,http_bus_sess,http_req);
    goto error;
  }

  file_pw_len = strlen(file_pw);
  if( file_pw_len > (RHP_CFG_BKUP_MAX_PW_LEN - 1) ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_BKUP_SAVE_TOO_LONG_FILE_PASSWORD,"xxx",http_conn,http_bus_sess,http_req);
    goto error;
  }

  {
  	cb_ctx =  _rhp_ui_http_cfg_arch_ctx_alloc(http_bus_sess->session_id,
  							http_bus_sess->user_name,"/protected/config/rockhopper.rcfg",file_pw);
  	if( cb_ctx == NULL ){
  		RHP_BUG("");
  		err = -ENOMEM;
  		goto error;
  	}
  }

	RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_BKUP_SAVE_CB_CTX,"xqss",cb_ctx,cb_ctx->session_id,cb_ctx->user_name,cb_ctx->file_name);


  {
  	u8 cfg_sub_dt_buf[sizeof(rhp_ipcmsg_syspxy_cfg_sub) + RHP_CFG_BKUP_MAX_PW_LEN];
  	rhp_ipcmsg_syspxy_cfg_sub* cfg_sub_dt = (rhp_ipcmsg_syspxy_cfg_sub*)cfg_sub_dt_buf;

  	memset(cfg_sub_dt,0,sizeof(rhp_ipcmsg_syspxy_cfg_sub));

  	cfg_sub_dt->cfg_type = RHP_IPC_SYSPXY_CFG_BKUP_SAVE;
  	cfg_sub_dt->len = sizeof(rhp_ipcmsg_syspxy_cfg_sub) + (file_pw_len + 1);
  	cfg_sub_dt->target_rlm_id = http_conn->user_realm_id;

		memcpy((u8*)(cfg_sub_dt + 1),file_pw,file_pw_len);
		((u8*)(cfg_sub_dt + 1))[file_pw_len] = '\0';

  	err = rhp_http_bus_ipc_cfg_request_async(http_conn,http_bus_sess->session_id,cfg_sub_dt->len,(u8*)cfg_sub_dt);
  	if( err ){
  		RHP_BUG("");
  		goto error;
  	}
  }


	err = rhp_http_bus_send_response(http_conn,http_bus_sess,NULL,NULL);
	if( err ){
  	goto error;
  }

  if( file_pw ){
  	_rhp_free_zero(file_pw,strlen(file_pw));
  }


	http_bus_sess->cfg_save_cb_ctx = (void*)cb_ctx;
  http_bus_sess->cfg_save_cb_ctx_free = _rhp_ui_http_cfg_arch_ctx_free;


  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_BKUP_SAVE_RTRN,"xxx",http_conn,http_bus_sess,http_req);
  return RHP_STATUS_CLOSE_HTTP_CONN;

error:
  if( file_pw ){
  	_rhp_free_zero(file_pw,strlen(file_pw));
  }
  if( cb_ctx ){
  	_rhp_ui_http_cfg_arch_ctx_free(cb_ctx);
  }

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_BKUP_SAVE_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  return err;
}

static int _rhp_ui_http_cfg_bkup_restore_0(xmlDocPtr doc,xmlNodePtr node,rhp_http_conn* http_conn,
		rhp_http_bus_session* http_bus_sess,rhp_http_request* http_req,void* ctx)
{
  int err = -EINVAL;
  unsigned long rlm_id = RHP_VPN_REALM_ID_UNKNOWN;
  rhp_ui_http_cfg_arch_ctx* cb_ctx = NULL;
  char* file_pw = NULL;


  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_BKUP_RESTORE_0,"xxxxxx",doc,node,http_conn,http_bus_sess,http_req,ctx);

  if( doc == NULL || node == NULL ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_BKUP_RESTORE_0_NO_DOC_NODE,"xxx",http_conn,http_bus_sess,http_req);
    return -EINVAL;
  }

  if( _rhp_ui_http_get_user_realm_id(http_conn,http_bus_sess,&rlm_id)  || rlm_id != 0 ){
  	err = -EPERM;
		RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_BKUP_RESTORE_0_NOT_PERMITTED,"xxxuu",http_conn,http_bus_sess,http_req,http_conn->user_realm_id,http_bus_sess->user_realm_id);
		goto error;
  }

  file_pw = (char*)rhp_xml_get_prop(node,(const xmlChar*)"upload_config_password");
  if( file_pw == NULL ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_BKUP_RESTORE_0_NO_FILE_PASSWORD,"xxx",http_conn,http_bus_sess,http_req);
    goto error;
  }

  {
  	cb_ctx =  _rhp_ui_http_cfg_arch_ctx_alloc(http_bus_sess->session_id,
  							http_bus_sess->user_name,NULL,file_pw);
  	if( cb_ctx == NULL ){
  		RHP_BUG("");
  		err = -ENOMEM;
  		goto error;
  	}
  }

	RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_BKUP_RESTORE_0_CB_CTX,"xqss",cb_ctx,cb_ctx->session_id,cb_ctx->user_name,cb_ctx->file_name);


	err = rhp_http_bus_send_response(http_conn,http_bus_sess,NULL,NULL);
	if( err ){
  	goto error;
  }

  if( file_pw ){
  	_rhp_free_zero(file_pw,strlen(file_pw));
  }


	http_bus_sess->cfg_restore_cb_ctx = (void*)cb_ctx;
  http_bus_sess->cfg_restore_cb_ctx_free = _rhp_ui_http_cfg_arch_ctx_free;


  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_BKUP_RESTORE_0_RTRN,"xxx",http_conn,http_bus_sess,http_req);
  return RHP_STATUS_CLOSE_HTTP_CONN;

error:
  if( file_pw ){
  	_rhp_free_zero(file_pw,strlen(file_pw));
  }
  if( cb_ctx ){
  	_rhp_ui_http_cfg_arch_ctx_free(cb_ctx);
  }

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_BKUP_RESTORE_0_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  return err;
}

struct _rhp_ui_http_create_rlm_enum_ctx {
	xmlNodePtr cfg_parent;
	unsigned long rlm_id;
};
typedef struct _rhp_ui_http_create_rlm_enum_ctx	rhp_ui_http_create_rlm_enum_ctx;


static int _rhp_ui_http_cfg_create_parse_realm(xmlNodePtr node,unsigned long rlm_id,xmlNodePtr cfg_parent)
{
	int err = -EINVAL;
  rhp_vpn_realm* rlm = NULL;
  xmlNodePtr dup_node = NULL;

  rlm =  rhp_cfg_parse_realm(node);
  if( rlm == NULL ){
  	RHP_BUG("%d",rlm_id);
  	err = -EINVAL;
  	goto error;
  }
	rhp_realm_hold(rlm);

	if( rlm->disabled ){
  	RHP_BUG("%d",rlm_id);
    err = RHP_STATUS_INVALID_MSG;
  	goto error;
	}

  if( rlm->id != rlm_id ){
  	RHP_BUG(" %u, %u ",rlm->id,rlm_id);
    err = RHP_STATUS_INVALID_MSG;
  	goto error;
  }

  _rhp_atomic_set(&(rlm->is_active),1);

  if( rlm->split_dns.domains != NULL ){

  	if( !rhp_ip_addr_null(&(rlm->split_dns.internal_server_addr)) ||
  			(!rhp_gcfg_ipv6_disabled && !rhp_ip_addr_null(&(rlm->split_dns.internal_server_addr_v6))) ){

  		rhp_dns_pxy_inc_users();
  	}
  }


  err = rhp_vpn_aoc_put(rlm); // Call this before rhp_realm_put()!!!
  if( !err ){

  	rhp_vpn_aoc_update();

  }else if( err == -ENOENT ){

  	err = 0;

  }else{
  	RHP_BUG("%d");
  	goto error;
  }


  err = rhp_realm_put(rlm);
  if( err ){
  	RHP_BUG("%d",rlm->id);
  	goto error;
  }

  RHP_LOCK(&(rlm->lock));
  {

  	err = rhp_ipc_send_my_id_resolve_req(rlm->id);
  	if( err ){
  		RHP_BUG("%d",err);
  	}

  	err = rhp_ipc_send_create_vif(rlm);
  	if( err ){
  		RHP_BUG("%d",err);
  	}
  }
  RHP_UNLOCK(&(rlm->lock));


  if( rhp_dns_pxy_get_users() ){

  	rhp_dns_pxy_main_start(AF_INET);
  	rhp_dns_pxy_main_start(AF_INET6);
  }


  if( cfg_parent ){

  	dup_node = xmlCopyNode(node,1);
		if( dup_node ){

			if( xmlAddChild(cfg_parent,dup_node) == NULL ){
				RHP_BUG("%d",rlm->id);
			}

		}else{
			RHP_BUG("%d",rlm->id);
		}
  }

	rhp_realm_unhold(rlm);
	return 0;

error:
	if( rlm ){
		rhp_realm_unhold(rlm);
	}
  return err;
}

static xmlNodePtr _rhp_ui_http_create_xml_def_realm(
		xmlChar* vpn_realm_str,xmlChar* vpn_realm_name_str,
		xmlChar* vpn_realm_mode_str,xmlChar* vpn_realm_desc_str,xmlNodePtr parent_node)
{
	int err = -EINVAL;
	xmlNodePtr root_node = NULL;
	xmlNodePtr realm_node = NULL;

	root_node =	xmlNewNode(NULL,(xmlChar*)"rhp_config");
	if( root_node == NULL ){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}

	if( xmlAddChild(parent_node,root_node) == NULL ){
  	RHP_BUG("");
		err = -EINVAL;
		goto error;
	}

	realm_node =	xmlNewNode(NULL,(xmlChar*)"vpn_realm");
	if( realm_node == NULL ){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}

	if( xmlNewProp(realm_node,(xmlChar*)"id",vpn_realm_str) == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}

	if( vpn_realm_name_str ){

		if( xmlNewProp(realm_node,(xmlChar*)"name",vpn_realm_name_str) == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}
	}

	if( vpn_realm_mode_str ){

		if( xmlNewProp(realm_node,(xmlChar*)"mode",vpn_realm_mode_str) == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}
	}

	if( vpn_realm_desc_str ){

		if( xmlNewProp(realm_node,(xmlChar*)"description",vpn_realm_desc_str) == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}
	}

	{
		char created_time_str[32];
		time_t created_time = _rhp_get_realtime();
		created_time_str[0] = '\0';

		snprintf(created_time_str,32,"%lld",(int64_t)created_time);

		if( xmlNewProp(realm_node,(xmlChar*)"created_time",(xmlChar*)created_time_str) == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		if( xmlNewProp(realm_node,(xmlChar*)"created_local_time",
				(xmlChar*)_rhp_ui_http_cfg_realm_time_str(&created_time)) == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		if( xmlNewProp(realm_node,(xmlChar*)"updated_time",(xmlChar*)created_time_str) == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		if( xmlNewProp(realm_node,(xmlChar*)"updated_local_time",
				(xmlChar*)_rhp_ui_http_cfg_realm_time_str(&created_time)) == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}
	}


	if( xmlAddChild(root_node,realm_node) == NULL ){
  	RHP_BUG("");
		err = -EINVAL;
		goto error;
	}

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
	return NULL;
}

static int _rhp_ui_http_cfg_create_realm_bh(xmlDocPtr doc,xmlNodePtr req_root_node,rhp_http_conn* http_conn,rhp_http_bus_session* http_bus_sess,
  				rhp_http_request* http_req,int data_len,u8* data,void* ipc_bus_cb_ctx)
{
  int err = -EINVAL;
  xmlChar *vpn_realm_str = NULL,*vpn_realm_name_str = NULL,
  		*vpn_realm_mode_str = NULL,*vpn_realm_desc_str = NULL;
  unsigned long rlm_id;
  char* endp;
	xmlDocPtr cfg_doc = NULL;
	xmlNodePtr cfg_root_node = NULL;
	xmlNodePtr rhp_cfg_node = NULL;
	rhp_ipcmsg_syspxy_cfg_sub* cfg_sub_dt = (rhp_ipcmsg_syspxy_cfg_sub*)data;

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_CREATE_REALM_BH,"xxxxxpx",doc,req_root_node,http_conn,http_bus_sess,http_req,data_len,data,ipc_bus_cb_ctx);

	if( data_len < (int)sizeof(rhp_ipcmsg_syspxy_cfg_sub) && (int)cfg_sub_dt->len != data_len ){
		err = -EINVAL;
		RHP_BUG("%d, %d, %d",cfg_sub_dt->len,data_len,sizeof(rhp_ipcmsg_syspxy_cfg_sub));
		goto error;
	}

	if( !cfg_sub_dt->result ){
		err = -EPERM;
	  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_CREATE_REALM_BH_RESULT_FAILED,"xxxxx",doc,req_root_node,http_conn,http_bus_sess,http_req);
		goto error;
	}

  vpn_realm_str = rhp_xml_get_prop(req_root_node,(const xmlChar*)"vpn_realm");
  if( vpn_realm_str == NULL ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_CREATE_REALM_NO_VPN_REALM,"xxx",http_conn,http_bus_sess,http_req);
    goto error;
  }

  vpn_realm_name_str = rhp_xml_get_prop(req_root_node,(const xmlChar*)"vpn_realm_name");
  vpn_realm_mode_str = rhp_xml_get_prop(req_root_node,(const xmlChar*)"vpn_realm_mode");
  vpn_realm_desc_str = rhp_xml_get_prop(req_root_node,(const xmlChar*)"vpn_realm_desc");


  rlm_id = strtoul((char*)vpn_realm_str,&endp,0);
  if( (rlm_id == ULONG_MAX && errno == ERANGE) || *endp != '\0' ){
  	err = -ENOENT;
  	RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_CREATE_REALM_NO_VPN_REALM_2,"xxxs",http_conn,http_bus_sess,http_req,vpn_realm_str);
  	goto error;
  }

  if( rlm_id != cfg_sub_dt->target_rlm_id ){
  	err = -EINVAL;
  	RHP_BUG("%d, %d",rlm_id,cfg_sub_dt->target_rlm_id);
  	goto error;
  }

  {
		cfg_doc = xmlParseFile(rhp_main_conf_path);
		if( cfg_doc == NULL ){
			RHP_BUG(" %s ",rhp_main_conf_path);
			err = -ENOENT;
			goto error;
		}

		cfg_root_node = xmlDocGetRootElement(cfg_doc);
		if( cfg_root_node == NULL ){
			RHP_BUG(" %s ",rhp_main_conf_path);
			err = -ENOENT;
			goto error;
		}
	}

	rhp_cfg_node = _rhp_ui_http_create_xml_def_realm(
			vpn_realm_str,vpn_realm_name_str,vpn_realm_mode_str,vpn_realm_desc_str,req_root_node);

	if( rhp_cfg_node == NULL ){
		RHP_BUG("");
		goto error;
	}

	err = _rhp_ui_http_cfg_create_parse_realm(rhp_cfg_node->children,rlm_id,cfg_root_node);
	if( err ){
		RHP_BUG("%d",err);
		goto error;
	}


	err = rhp_cfg_save_config(rhp_main_conf_path,cfg_doc);
	if( err ){
		RHP_BUG("%d",err);
	}

	if( cfg_doc ){
		xmlFreeDoc(cfg_doc);
		cfg_doc = NULL;
	}

  err = rhp_http_bus_send_response(http_conn,http_bus_sess,NULL,NULL);
  if( err ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_CREATE_REALM_BH_TX_RESP_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
    goto error;
  }

  RHP_LOG_I(RHP_LOG_SRC_UI,0,RHP_LOG_ID_MAIN_CREATE_REALM,"ss",vpn_realm_str,vpn_realm_name_str);

  if( vpn_realm_str ){
  	_rhp_free(vpn_realm_str);
  }
  if( vpn_realm_name_str ){
  	_rhp_free(vpn_realm_name_str);
  }
  if( vpn_realm_mode_str ){
  	_rhp_free(vpn_realm_mode_str);
  }
  if( vpn_realm_desc_str ){
  	_rhp_free(vpn_realm_desc_str);
  }


  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_CREATE_REALM_BH_RTRN,"xxxs",http_conn,http_bus_sess,http_req,vpn_realm_str);
  return RHP_STATUS_CLOSE_HTTP_CONN;

error:
	RHP_LOG_E(RHP_LOG_SRC_UI,0,RHP_LOG_ID_MAIN_CREATE_REALM_ERR,"sE",vpn_realm_str,err);
	if( cfg_doc ){
		xmlFreeDoc(cfg_doc);
	}
  if( vpn_realm_str ){
  	_rhp_free(vpn_realm_str);
  }
  if( vpn_realm_name_str ){
  	_rhp_free(vpn_realm_name_str);
  }
  if( vpn_realm_mode_str ){
  	_rhp_free(vpn_realm_mode_str);
  }
  if( vpn_realm_desc_str ){
  	_rhp_free(vpn_realm_desc_str);
  }

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_CREATE_REALM_BH_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  return err;
}

static int _rhp_ui_http_cfg_create_realm(xmlDocPtr doc,xmlNodePtr req_root_node,rhp_http_conn* http_conn,
		rhp_http_bus_session* http_bus_sess,rhp_http_request* http_req,void* ctx)
{
  int err = -EINVAL;
  xmlChar* vpn_realm_str = NULL;
  unsigned long rlm_id = RHP_VPN_REALM_ID_UNKNOWN;
  unsigned long user_rlm_id = RHP_VPN_REALM_ID_UNKNOWN;
  char* endp;

	RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_CREATE_REALM,"xxxxxx",doc,req_root_node,http_conn,http_bus_sess,http_req,ctx);

  if( doc == NULL || req_root_node == NULL ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_CREATE_REALM_NO_DOC_NODE,"xxxxx",http_conn,http_bus_sess,http_req,doc,req_root_node);
    return -EINVAL;
  }

  if( _rhp_ui_http_get_user_realm_id(http_conn,http_bus_sess,&user_rlm_id) || user_rlm_id != 0 ){
  	err = -EPERM;
  	RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_CREATE_REALM_INVALID_USER_REALM,"xxxuu",http_conn,http_bus_sess,http_req,http_conn->user_realm_id,user_rlm_id);
		goto error;
  }

  vpn_realm_str = rhp_xml_get_prop(req_root_node,(const xmlChar*)"vpn_realm");
  if( vpn_realm_str == NULL ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_CREATE_REALM_NO_VPN_REALM,"xxx",http_conn,http_bus_sess,http_req);
    goto error;
  }

  rlm_id = strtoul((char*)vpn_realm_str,&endp,0);
  if( (rlm_id == ULONG_MAX && errno == ERANGE) || *endp != '\0' ){
  	err = -ENOENT;
  	RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_CREATE_REALM_NO_VPN_REALM_2,"xxxs",http_conn,http_bus_sess,http_req,vpn_realm_str);
  	goto error;
  }

  if( rlm_id == 0 || rlm_id > RHP_VPN_REALM_ID_MAX ){

  	err = -EPERM;
  	RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_CREATE_REALM_INVALID_REALM_ID,"xxxu",http_conn,http_bus_sess,http_req,rlm_id);
		goto error;

  }else{

  	rhp_vpn_realm* rlm = rhp_realm_get(rlm_id);
  	if( rlm ){

    	RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_CREATE_REALM_EXISTS,"xxxu",http_conn,http_bus_sess,http_req,rlm_id);

  		err = -EEXIST;
  		rhp_realm_unhold(rlm);

  		goto error;
  	}
  }

  {
  	rhp_ipcmsg_syspxy_cfg_sub cfg_sub_dt;

  	cfg_sub_dt.cfg_type = RHP_IPC_SYSPXY_CFG_CREATE_REALM;
  	cfg_sub_dt.len = sizeof(rhp_ipcmsg_syspxy_cfg_sub);
  	cfg_sub_dt.target_rlm_id = rlm_id;

  	err = rhp_http_bus_ipc_cfg_request(http_conn,http_bus_sess,
  			sizeof(rhp_ipcmsg_syspxy_cfg_sub),(u8*)&cfg_sub_dt,_rhp_ui_http_cfg_create_realm_bh,NULL);

  	if( err ){
			RHP_BUG("");
			goto error;
		}
  }

  if( vpn_realm_str ){
  	_rhp_free(vpn_realm_str);
  }

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_CREATE_REALM_RTRN,"xxxs",http_conn,http_bus_sess,http_req,vpn_realm_str);
  return RHP_STATUS_HTTP_REQ_PENDING;

error:
	RHP_LOG_E(RHP_LOG_SRC_UI,0,RHP_LOG_ID_MAIN_CREATE_REALM_ERR,"sE",vpn_realm_str,err);
	if( vpn_realm_str ){
		_rhp_free(vpn_realm_str);
	}
  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_CREATE_REALM_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  return err;
}


static int _rhp_ui_http_cfg_update_realm_enum_ifc_cb0(rhp_ifc_entry* ifc,void* ctx)
{
	rhp_vpn_realm* new_rlm = (rhp_vpn_realm*)ctx;

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_UPDATE_REALM_ENUM_IFC_CB0,"xsx",ifc,ifc->if_name,new_rlm);

	RHP_LOCK(&(ifc->lock));

	rhp_realm_setup_ifc(new_rlm,ifc,0,-1);

	RHP_UNLOCK(&(ifc->lock));

	return 0;
}

static int _rhp_ui_http_cfg_update_realm_enum_ifc_cb1(rhp_ifc_entry* ifc,void* ctx)
{

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_UPDATE_REALM_ENUM_IFC_CB1,"xsx",ifc,ifc->if_name,ctx);

	RHP_LOCK(&(ifc->lock));

	rhp_realm_open_ifc_socket(ifc,0);

	RHP_UNLOCK(&(ifc->lock));

	return 0;
}

static int _rhp_ui_http_cfg_update_realm_enum_rtmapc_cb0(rhp_rtmapc_entry* rtmapc,void* ctx)
{
	rhp_vpn_realm* rlm = (rhp_vpn_realm*)ctx;
	rhp_ifc_entry* ifc = NULL;
	int addr_family = -1;

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_UPDATE_REALM_ENUM_RTMAPC_CB0,"xx",rtmapc,rlm);

  RHP_LOCK(&(rtmapc->lock));

	if( rlm->my_interface_use_def_route &&
			(rtmapc->info.type == RHP_RTMAP_TYPE_DEFAULT ||
			 rtmapc->info.type == RHP_RTMAP_TYPE_DYNAMIC_DEFAULT) ){

	  ifc = rhp_ifc_get(rtmapc->info.oif_name);
	  if( ifc == NULL ){
	  	RHP_BUG("%s",rtmapc->info.oif_name);
  	  RHP_UNLOCK(&(rtmapc->lock));
	  	goto error;
	  }
	}

	addr_family = rtmapc->info.addr_family;

	RHP_UNLOCK(&(rtmapc->lock));

	if( ifc ){

		RHP_LOCK(&(ifc->lock));

		rhp_realm_setup_ifc(rlm,ifc,1,addr_family);

		RHP_UNLOCK(&(ifc->lock));

    rhp_ifc_unhold(ifc); // For rhp_ifc_get().
	}

error:
  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_UPDATE_REALM_ENUM_RTMAPC_CB0_RTRN,"xxx",rtmapc,rlm,ifc);
	return 0;
}

static int _rhp_ui_http_cfg_update_realm_exec(rhp_http_conn* http_conn,rhp_http_bus_session* http_bus_sess,rhp_vpn_realm* new_rlm)
{
	int err = -EINVAL;
	unsigned long rlm_id = new_rlm->id;
	int new_dns_pxy = 0;

  err = rhp_vpn_aoc_put(new_rlm); // Call this before rhp_realm_put()!!!
  if( !err ){
  	rhp_vpn_aoc_update();
  }else if( err == -ENOENT ){
  	err = 0;
  }else{
  	RHP_BUG("%d");
  	goto error;
  }

  err = rhp_realm_put(new_rlm);
  if( err ){
  	RHP_BUG("%d",rlm_id);
  	goto error;
  }

  RHP_LOCK(&(new_rlm->lock));
  {

  	err = rhp_ipc_send_my_id_resolve_req(new_rlm->id);
  	if( err ){
  		RHP_BUG("%d",err);
  	}

  	err = rhp_ipc_send_create_vif(new_rlm);
  	if( err ){
  		RHP_BUG("%d",err);
  	}

  	err = rhp_ifc_enum(_rhp_ui_http_cfg_update_realm_enum_ifc_cb0,new_rlm);
  	if( !err ){

    	err = rhp_ifc_enum(_rhp_ui_http_cfg_update_realm_enum_ifc_cb1,new_rlm);
    	if( err ){
    		RHP_BUG("%d",err);
    	}
  	}
  	err = 0;

  	if( new_rlm->my_interface_use_def_route ){

  		rhp_rtmapc_enum(_rhp_ui_http_cfg_update_realm_enum_rtmapc_cb0,new_rlm);
    	if( !err ){

      	err = rhp_ifc_enum(_rhp_ui_http_cfg_update_realm_enum_ifc_cb1,new_rlm);
      	if( err ){
      		RHP_BUG("%d",err);
      	}
    	}
    	err = 0;
  	}

		if( new_rlm->split_dns.domains != NULL ){

			if( !rhp_ip_addr_null(&(new_rlm->split_dns.internal_server_addr)) ){
				new_dns_pxy++;
	  	}

			if( !rhp_ip_addr_null(&(new_rlm->split_dns.internal_server_addr_v6)) ){
				new_dns_pxy++;
	  	}
		}


    if( new_rlm->internal_ifc && new_rlm->internal_ifc->bridge_name ){

    	rhp_ifc_entry* br_ifc = rhp_ifc_get(new_rlm->internal_ifc->bridge_name);
    	if( br_ifc ){

    		rhp_ifc_addr* ifc_addr;

    		RHP_LOCK(&(br_ifc->lock));

    		ifc_addr = br_ifc->ifc_addrs;
    		while( ifc_addr ){

    			rhp_ip_addr_list *addr_lst
    			= (rhp_ip_addr_list*)_rhp_malloc(sizeof(rhp_ip_addr_list));

    			if( addr_lst == NULL ){
        		RHP_UNLOCK(&(br_ifc->lock));
    				RHP_BUG("");
    				err = -ENOMEM;
    				goto error;
    			}

  				memset(addr_lst,0,sizeof(rhp_ip_addr_list));

  				addr_lst->next = new_rlm->internal_ifc->bridge_addrs;
  				new_rlm->internal_ifc->bridge_addrs = addr_lst;

    			if( ifc_addr->addr.addr_family == AF_INET ){

    				RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_UPDATE_REALM_BH_SET_BRIDGE_INFO,"xxsxx44dx",http_conn,http_bus_sess,new_rlm->internal_ifc->bridge_name,new_rlm,new_rlm->internal_ifc,addr_lst->ip_addr.addr.v4,addr_lst->ip_addr.netmask.v4,addr_lst->ip_addr.prefixlen,br_ifc);

    				addr_lst->ip_addr.addr_family = ifc_addr->addr.addr_family;
    				addr_lst->ip_addr.addr.v4 = ifc_addr->addr.addr.v4;
    				addr_lst->ip_addr.prefixlen = ifc_addr->addr.prefixlen;
    				addr_lst->ip_addr.netmask.v4 = rhp_ipv4_prefixlen_to_netmask(ifc_addr->addr.prefixlen);

    			}else if( ifc_addr->addr.addr_family == AF_INET6 ){

    				RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_UPDATE_REALM_BH_SET_BRIDGE_INFO_V6,"xxsxx66dx",http_conn,http_bus_sess,new_rlm->internal_ifc->bridge_name,new_rlm,new_rlm->internal_ifc,addr_lst->ip_addr.addr.v6,addr_lst->ip_addr.netmask.v6,addr_lst->ip_addr.prefixlen,br_ifc);

    				addr_lst->ip_addr.addr_family = ifc_addr->addr.addr_family;
    				memcpy(addr_lst->ip_addr.addr.v6,ifc_addr->addr.addr.v6,16);
    				addr_lst->ip_addr.prefixlen = ifc_addr->addr.prefixlen;
    				rhp_ipv6_prefixlen_to_netmask(ifc_addr->addr.prefixlen,addr_lst->ip_addr.netmask.v6);
    			}

    			ifc_addr = ifc_addr->lst_next;
    		}

    		RHP_UNLOCK(&(br_ifc->lock));

    		rhp_ifc_unhold(br_ifc);
    	}
    }
  }
  RHP_UNLOCK(&(new_rlm->lock));


	if( new_dns_pxy ){

		rhp_dns_pxy_inc_users();

		rhp_dns_pxy_main_start(AF_INET);
		rhp_dns_pxy_main_start(AF_INET6);
	}

	return 0;

error:
	return err;
}

static int _rhp_ui_http_cfg_enable_enum_xml(xmlNodePtr node,void* ctx)
{
	int err = -EINVAL;
	int ret_len;
	rhp_ui_http_cfg_update_enum_ctx* enum_ctx = (rhp_ui_http_cfg_update_enum_ctx*)ctx;

  if( !xmlStrcmp(node->name,(xmlChar*)"vpn_realm") ){

  	unsigned long rlm_id;

    if( rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"id"),RHP_XML_DT_ULONG,&rlm_id,&ret_len,NULL,0) ){
      RHP_BUG("");
      goto error;
    }

    if( rlm_id == enum_ctx->rlm_id ){

    	enum_ctx->new_node = node;

    	return RHP_STATUS_ENUM_OK;
    }
  }

  return 0;

error:
	RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_ENABLE_ENUM_XML_ERR,"xxE",node,ctx,err);
	return err;
}

static int _rhp_ui_http_cfg_update_parse_realm(xmlNodePtr node,void* ctx)
{
	int err = -EINVAL;
  rhp_vpn_realm* rlm = NULL;
  rhp_ui_http_cfg_update_enum_ctx* enum_ctx = (rhp_ui_http_cfg_update_enum_ctx*)ctx;

  rlm =  rhp_cfg_parse_realm(node);
  if( rlm == NULL ){
  	RHP_BUG("");
    err = -EINVAL;
  	goto error;
  }
	rhp_realm_hold(rlm);

	if( rlm->disabled ){
  	RHP_BUG("%d",rlm->id);
    err = RHP_STATUS_INVALID_MSG;
  	goto error;
	}

  if( rlm->id != enum_ctx->rlm_id ){
  	RHP_BUG("%d, %d",rlm->id,enum_ctx->rlm_id);
    err = RHP_STATUS_INVALID_MSG;
  	goto error;
  }

  _rhp_atomic_set(&(rlm->is_active),1);

  enum_ctx->new_node = node;
  enum_ctx->new_rlm = rlm;
	rhp_realm_hold(rlm);

	rhp_realm_unhold(rlm);

	return 0;

error:
	if( rlm ){
		rhp_realm_unhold(rlm);
	}
  return err;
}

static int _rhp_ui_http_cfg_enable_realm_serialize(void* http_bus_sess_d,void* ctx,void* writer,int idx)
{
	rhp_http_bus_session* http_bus_sess = (rhp_http_bus_session*) http_bus_sess_d;
	unsigned long rlm_id = (unsigned long)ctx;

  int err = -EINVAL;
  int n = 0;
  int n2 = 0;

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_ENABLE_REALM_SERIALIZE,"xxdu",http_bus_sess,writer,idx,rlm_id);

  n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"rhp_http_bus_record");
  if(n < 0) {
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"index","%d",idx);
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"service",(xmlChar*)"ui_http_vpn");
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"action",(xmlChar*)"realm_config_enabled");
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"session_id","%llu",http_bus_sess->session_id);
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"vpn_realm_id","%lu",rlm_id);
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;


  n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
  if(n < 0) {
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_ENABLE_REALM_SERIALIZE_RTRN,"xud",http_bus_sess,rlm_id,n2);
  return n2;

error:
	RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_ENABLE_REALM_SERIALIZE_ERR,"xuE",http_bus_sess,rlm_id,err);
  return err;
}

static int _rhp_ui_http_cfg_enable_realm_bh(xmlDocPtr doc,xmlNodePtr req_root_node,rhp_http_conn* http_conn,rhp_http_bus_session* http_bus_sess,
  				rhp_http_request* http_req,int data_len,u8* data,void* ipc_bus_cb_ctx)
{
  int err = -EINVAL;
  xmlChar *vpn_realm_str = NULL;
  unsigned long rlm_id;
  char* endp;
	xmlDocPtr cfg_doc = NULL;
	xmlNodePtr cfg_root_node = NULL;
	rhp_ipcmsg_syspxy_cfg_sub* cfg_sub_dt = (rhp_ipcmsg_syspxy_cfg_sub*)data;
	rhp_vpn_realm* new_rlm = NULL;
	rhp_ui_http_cfg_update_enum_ctx enum_ctx;

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_ENABLE_REALM_BH,"xxxxxpx",doc,req_root_node,http_conn,http_bus_sess,http_req,data_len,data,ipc_bus_cb_ctx);

  memset(&enum_ctx,0,sizeof(rhp_ui_http_cfg_update_enum_ctx));

	if( data_len < (int)sizeof(rhp_ipcmsg_syspxy_cfg_sub) && (int)cfg_sub_dt->len != data_len ){
		err = -EINVAL;
		RHP_BUG("%d, %d, %d",cfg_sub_dt->len,data_len,sizeof(rhp_ipcmsg_syspxy_cfg_sub));
		goto error;
	}

	if( !cfg_sub_dt->result ){
		err = -EPERM;
	  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_ENABLE_REALM_BH_RESULT_FAILED,"xxxxx",doc,req_root_node,http_conn,http_bus_sess,http_req);
		goto error;
	}

  vpn_realm_str = rhp_xml_get_prop(req_root_node,(const xmlChar*)"vpn_realm");
  if( vpn_realm_str == NULL ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_ENABLE_REALM_NO_VPN_REALM,"xxx",http_conn,http_bus_sess,http_req);
    goto error;
  }

  rlm_id = strtoul((char*)vpn_realm_str,&endp,0);
  if( (rlm_id == ULONG_MAX && errno == ERANGE) || *endp != '\0' ){
  	err = -ENOENT;
  	RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_ENABLE_REALM_NO_VPN_REALM_2,"xxxs",http_conn,http_bus_sess,http_req,vpn_realm_str);
  	goto error;
  }

  if( rlm_id != cfg_sub_dt->target_rlm_id ){
  	err = -EINVAL;
  	RHP_BUG("%d, %d",rlm_id,cfg_sub_dt->target_rlm_id);
  	goto error;
  }


	cfg_doc = xmlParseFile(rhp_main_conf_path);
	if( cfg_doc == NULL ){
		RHP_BUG(" %s ",rhp_main_conf_path);
		err = -ENOENT;
		goto error;
	}

	cfg_root_node = xmlDocGetRootElement(cfg_doc);
	if( cfg_root_node == NULL ){
		RHP_BUG(" %s ",rhp_main_conf_path);
		err = -ENOENT;
		goto error;
	}


	enum_ctx.rlm_id = cfg_sub_dt->target_rlm_id;

  err = rhp_xml_enum_tags(cfg_root_node,NULL,_rhp_ui_http_cfg_enable_enum_xml,(void*)&enum_ctx,1);
  if( err != RHP_STATUS_ENUM_OK ){
    RHP_BUG(" %s ",rhp_main_conf_path);
    goto error;
  }
  err = 0;


  {
		xmlAttrPtr status_attr;

		status_attr =	xmlHasProp(enum_ctx.new_node,(xmlChar*)"status");

		if( xmlNewProp(enum_ctx.new_node,(xmlChar*)"status",(xmlChar*)"enable") == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		if( status_attr ){
			xmlRemoveProp(status_attr);
		}
  }

  err = _rhp_ui_http_cfg_update_parse_realm(enum_ctx.new_node,(void*)&enum_ctx);
  if( err ){
    RHP_BUG(" %s ",rhp_main_conf_path);
    goto error;
  }

  new_rlm = enum_ctx.new_rlm;

  err = _rhp_ui_http_cfg_update_realm_exec(http_conn,http_bus_sess,new_rlm);
  if( err ){
  	goto error;
  }


  rhp_realm_disabled_delete(cfg_sub_dt->target_rlm_id);


  err = rhp_cfg_save_config(rhp_main_conf_path,cfg_doc);
	if( err ){
		RHP_BUG("%d",err);
	}

	if( cfg_doc ){
		xmlFreeDoc(cfg_doc);
		cfg_doc = NULL;
	}

  err = rhp_http_bus_send_response(http_conn,http_bus_sess,NULL,NULL);
  if( err ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_ENABLE_REALM_BH_TX_RESP_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
    goto error;
  }

	rhp_realm_unhold(new_rlm);

  rhp_bridge_cache_flush(NULL,rlm_id);

  RHP_LOG_I(RHP_LOG_SRC_UI,rlm_id,RHP_LOG_ID_MAIN_ENABLE_REALM,"s",vpn_realm_str);

	rhp_http_bus_broadcast_async(rlm_id,1,1,
			_rhp_ui_http_cfg_enable_realm_serialize,NULL,(void*)rlm_id);


  if( vpn_realm_str ){
  	_rhp_free(vpn_realm_str);
  }

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_ENABLE_REALM_BH_RTRN,"xxxx",http_conn,http_bus_sess,http_req,new_rlm);
  return RHP_STATUS_CLOSE_HTTP_CONN;

  if( vpn_realm_str ){
  	_rhp_free(vpn_realm_str);
  }


  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_ENABLE_REALM_BH_RTRN,"xxxs",http_conn,http_bus_sess,http_req,vpn_realm_str);
  return RHP_STATUS_CLOSE_HTTP_CONN;

error:
	RHP_LOG_E(RHP_LOG_SRC_UI,0,RHP_LOG_ID_MAIN_ENABLE_REALM_ERR,"sE",vpn_realm_str,err);
	if( cfg_doc ){
		xmlFreeDoc(cfg_doc);
	}
  if( vpn_realm_str ){
  	_rhp_free(vpn_realm_str);
  }
  if( new_rlm ){
  	rhp_realm_unhold(new_rlm);
  }
  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_ENABLE_REALM_BH_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  return err;
}

static int _rhp_ui_http_cfg_enable_realm(xmlDocPtr doc,xmlNodePtr req_root_node,rhp_http_conn* http_conn,
		rhp_http_bus_session* http_bus_sess,rhp_http_request* http_req,void* ctx)
{
  int err = -EINVAL;
  xmlChar* vpn_realm_str = NULL;
  unsigned long rlm_id = RHP_VPN_REALM_ID_UNKNOWN;
  unsigned long user_rlm_id = RHP_VPN_REALM_ID_UNKNOWN;
  char* endp;

	RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_ENABLE_REALM,"xxxxxx",doc,req_root_node,http_conn,http_bus_sess,http_req,ctx);

  if( doc == NULL || req_root_node == NULL ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_ENABLE_REALM_NO_DOC_NODE,"xxxxx",http_conn,http_bus_sess,http_req,doc,req_root_node);
    return -EINVAL;
  }

  if( _rhp_ui_http_get_user_realm_id(http_conn,http_bus_sess,&user_rlm_id) || user_rlm_id != 0 ){
  	err = -EPERM;
  	RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_ENABLE_REALM_INVALID_USER_REALM,"xxxuu",http_conn,http_bus_sess,http_req,http_conn->user_realm_id,user_rlm_id);
		goto error;
  }

  vpn_realm_str = rhp_xml_get_prop(req_root_node,(const xmlChar*)"vpn_realm");
  if( vpn_realm_str == NULL ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_ENABLE_REALM_NO_VPN_REALM,"xxx",http_conn,http_bus_sess,http_req);
    goto error;
  }

  rlm_id = strtoul((char*)vpn_realm_str,&endp,0);
  if( (rlm_id == ULONG_MAX && errno == ERANGE) || *endp != '\0' ){
  	err = -ENOENT;
  	RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_ENABLE_REALM_NO_VPN_REALM_2,"xxxs",http_conn,http_bus_sess,http_req,vpn_realm_str);
  	goto error;
  }

  if( rlm_id == 0 || rlm_id > RHP_VPN_REALM_ID_MAX ){

  	err = -EPERM;
  	RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_ENABLE_REALM_INVALID_REALM_ID,"xxxu",http_conn,http_bus_sess,http_req,rlm_id);
		goto error;

  }else{

  	rhp_vpn_realm* rlm = rhp_realm_get(rlm_id);
  	if( rlm ){

    	RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_ENABLE_REALM_EXISTS,"xxxu",http_conn,http_bus_sess,http_req,rlm_id);

  		err = -EEXIST;
  		rhp_realm_unhold(rlm);

  		goto error;
  	}

  	if( !rhp_realm_disabled_exists(rlm_id) ){

    	RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_ENABLE_REALM_NO_ENT,"xxxu",http_conn,http_bus_sess,http_req,rlm_id);

  		err = -ENOENT;
  		goto error;
  	}
  }

  {
  	rhp_ipcmsg_syspxy_cfg_sub cfg_sub_dt;

  	cfg_sub_dt.cfg_type = RHP_IPC_SYSPXY_CFG_ENABLE_REALM;
  	cfg_sub_dt.len = sizeof(rhp_ipcmsg_syspxy_cfg_sub);
  	cfg_sub_dt.target_rlm_id = rlm_id;

  	err = rhp_http_bus_ipc_cfg_request(http_conn,http_bus_sess,
  			sizeof(rhp_ipcmsg_syspxy_cfg_sub),(u8*)&cfg_sub_dt,_rhp_ui_http_cfg_enable_realm_bh,NULL);

  	if( err ){
			RHP_BUG("");
			goto error;
		}
  }

  if( vpn_realm_str ){
  	_rhp_free(vpn_realm_str);
  }

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_ENABLE_REALM_RTRN,"xxxs",http_conn,http_bus_sess,http_req,vpn_realm_str);
  return RHP_STATUS_HTTP_REQ_PENDING;

error:
	RHP_LOG_E(RHP_LOG_SRC_UI,0,RHP_LOG_ID_MAIN_ENABLE_REALM_ERR,"sE",vpn_realm_str,err);
	if( vpn_realm_str ){
		_rhp_free(vpn_realm_str);
	}
  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_ENABLE_REALM_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  return err;
}

static int _rhp_ui_http_cfg_realm_is_enabled(xmlDocPtr doc,xmlNodePtr node,rhp_http_conn* http_conn,
		rhp_http_bus_session* http_bus_sess,rhp_http_request* http_req,void* ctx)
{
  int err = -EINVAL;
  char* vpn_realm_str = NULL;
  unsigned long rlm_id = RHP_VPN_REALM_ID_UNKNOWN;
  char* endp;

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_REALM_IS_ENABLED,"xxxxxx",doc,node,http_conn,http_bus_sess,http_req,ctx);

  if( doc == NULL || node == NULL ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_REALM_IS_ENABLED_NO_DOC_NODE,"xxxxx",http_conn,http_bus_sess,http_req,doc,node);
    return -EINVAL;
  }

  vpn_realm_str = (char*)rhp_xml_get_prop(node,(const xmlChar*)"vpn_realm");
  if( vpn_realm_str == NULL ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_REALM_IS_ENABLED_NO_VPN_REALM,"xxx",http_conn,http_bus_sess,http_req);
    goto error;
  }

  rlm_id = strtoul((char*)vpn_realm_str,&endp,0);
  if( (rlm_id == ULONG_MAX && errno == ERANGE) || *endp != '\0' ){
  	err = -ENOENT;
  	RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_REALM_IS_ENABLED_NO_VPN_REALM_2,"xxxs",http_conn,http_bus_sess,http_req,vpn_realm_str);
  	goto error;
  }

  if( http_conn->user_realm_id && http_conn->user_realm_id != rlm_id ){
  	err = -EPERM;
		goto error;
  }

  if( rlm_id == 0 || rlm_id > RHP_VPN_REALM_ID_MAX ){

  	err = -EPERM;
		goto error;

  }else{

  	if( rhp_realm_disabled_exists(rlm_id) ){
  		err = -ENOENT;
  		goto error;
  	}
  }


  err = rhp_http_bus_send_response(http_conn,http_bus_sess,NULL,NULL);
  if( err ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_REALM_IS_ENABLED_TX_RESP_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
    goto error;
  }

  if( vpn_realm_str ){
  	_rhp_free(vpn_realm_str);
  }

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_REALM_IS_ENABLED_RTRN,"xxxs",http_conn,http_bus_sess,http_req,vpn_realm_str);
  return RHP_STATUS_CLOSE_HTTP_CONN;

error:
	if( vpn_realm_str ){
		_rhp_free(vpn_realm_str);
	}
  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_REALM_IS_ENABLED_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  return err;
}

static int _rhp_ui_http_cfg_delete_realm_unlink_node(xmlNodePtr node,void* ctx)
{
	int err = -EINVAL;
	unsigned long rlm_id = (unsigned long)ctx;
	unsigned long elm_rlm_id;
	int ret_len;

  err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"id"),RHP_XML_DT_ULONG,&elm_rlm_id,&ret_len,NULL,0);
  if( !err ){

  	if( rlm_id == elm_rlm_id ){

  		xmlUnlinkNode(node);
  		xmlFreeNode(node);

  		return RHP_STATUS_ENUM_OK;
  	}

  }else{
  	RHP_BUG("%d",rlm_id);
  }

  return 0;
}

static int _rhp_ui_http_cfg_delete_realm_serialize(void* http_bus_sess_d,void* ctx,void* writer,int idx)
{
	rhp_http_bus_session* http_bus_sess = (rhp_http_bus_session*) http_bus_sess_d;
	unsigned long rlm_id = (unsigned long)ctx;

  int err = -EINVAL;
  int n = 0;
  int n2 = 0;

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_DELETE_REALM_SERIALIZE,"xxdu",http_bus_sess,writer,idx,rlm_id);

  n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"rhp_http_bus_record");
  if(n < 0) {
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"index","%d",idx);
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"service",(xmlChar*)"ui_http_vpn");
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"action",(xmlChar*)"realm_config_deleted");
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"session_id","%llu",http_bus_sess->session_id);
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"vpn_realm_id","%lu",rlm_id);
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;


  n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
  if(n < 0) {
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_DELETE_REALM_SERIALIZE_RTRN,"xud",http_bus_sess,rlm_id,n2);
  return n2;

error:
	RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_DELETE_REALM_SERIALIZE_ERR,"xuE",http_bus_sess,rlm_id,err);
  return err;
}

static int _rhp_ui_http_cfg_delete_realm_exec(unsigned long rlm_id,rhp_vpn_realm** rlm_r)
{
	int err = -EINVAL;
  rhp_vpn_realm* rlm = NULL;
  int dns_pxy = 0;

  rlm = rhp_realm_delete_by_id(rlm_id);
  if( rlm ){

		_rhp_atomic_set(&(rlm->is_active),0);


		err = rhp_vpn_cleanup_by_realm_id(rlm_id,0);
		if( err ){
			RHP_BUG("%d",err);
			goto error;
		}

		rhp_bridge_cache_cleanup_by_realm_id(rlm_id);


		RHP_LOCK(&(rlm->lock));
		{
			rhp_ifc_entry* v_ifc = rlm->internal_ifc->ifc;

			if( v_ifc ){

				RHP_LOCK(&(v_ifc->lock));
				{

					rhp_tuntap_close(v_ifc);

					v_ifc->tuntap_deleting = 1;
				}
				RHP_UNLOCK(&(v_ifc->lock));

				err = rhp_ipc_send_delete_vif(rlm);
				if( err ){
					RHP_BUG("%d",err);
				}
			}

			err = rhp_ipc_send_delete_all_static_routes(rlm);
			if( err ){
				RHP_BUG("%d",err);
			}

			dns_pxy = (rlm->split_dns.domains != NULL);
		}
		RHP_UNLOCK(&(rlm->lock));

		if( dns_pxy && rhp_dns_pxy_dec_and_test_users() ){

			rhp_dns_pxy_main_end(AF_INET);
			rhp_dns_pxy_main_end(AF_INET6);
		}

		*rlm_r = rlm;

  }else if( rhp_realm_disabled_exists(rlm_id) ){

  	rhp_realm_disabled_delete(rlm_id);

  }else{

  	err = -ENOENT;
		goto error;
  }

  return 0;

error:
	return err;
}

static int _rhp_ui_http_cfg_delete_realm_bh(xmlDocPtr doc,xmlNodePtr req_root_node,rhp_http_conn* http_conn,rhp_http_bus_session* http_bus_sess,
  				rhp_http_request* http_req,int data_len,u8* data,void* ipc_bus_cb_ctx)
{
  int err = -EINVAL;
  char* vpn_realm_str = NULL;
  unsigned long rlm_id = RHP_VPN_REALM_ID_UNKNOWN;
  rhp_vpn_realm* rlm = NULL;
  char* endp;
	xmlDocPtr cfg_doc = NULL;
	xmlNodePtr cfg_root_node = NULL;
	rhp_ipcmsg_syspxy_cfg_sub* cfg_sub_dt = (rhp_ipcmsg_syspxy_cfg_sub*)data;

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_DELETE_REALM_BH,"xxxxxpx",doc,req_root_node,http_conn,http_bus_sess,http_req,data_len,data,ipc_bus_cb_ctx);

	if( data_len < (int)sizeof(rhp_ipcmsg_syspxy_cfg_sub) && (int)cfg_sub_dt->len != data_len ){
		err = -EINVAL;
		RHP_BUG("%d, %d, %d",cfg_sub_dt->len,data_len,sizeof(rhp_ipcmsg_syspxy_cfg_sub));
		goto error;
	}

	if( !cfg_sub_dt->result ){
		err = -EPERM;
	  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_DELETE_REALM_BH_RESULT_FAILED,"xxxxx",doc,req_root_node,http_conn,http_bus_sess,http_req);
		goto error;
	}

  vpn_realm_str = (char*)rhp_xml_get_prop(req_root_node,(const xmlChar*)"vpn_realm");
  if( vpn_realm_str == NULL ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_DELETE_REALM_BH_NO_VPN_REALM,"xxx",http_conn,http_bus_sess,http_req);
    goto error;
  }

  rlm_id = strtoul((char*)vpn_realm_str,&endp,0);
  if( (rlm_id == ULONG_MAX && errno == ERANGE) || *endp != '\0' ){
  	err = -ENOENT;
  	RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_DELETE_REALM_BH_NO_VPN_REALM_2,"xxxs",http_conn,http_bus_sess,http_req,vpn_realm_str);
  	goto error;
  }

  if( rlm_id != cfg_sub_dt->target_rlm_id ){
  	err = -EINVAL;
  	RHP_BUG("%d, %d",rlm_id,cfg_sub_dt->target_rlm_id);
  	goto error;
  }


  err = _rhp_ui_http_cfg_delete_realm_exec(rlm_id,&rlm); // rlm may be NULL.
  if( err ){
  	goto error;
  }


  {
		cfg_doc = xmlParseFile(rhp_main_conf_path);
		if( cfg_doc == NULL ){
			RHP_BUG(" %s ",rhp_main_conf_path);
			err = -ENOENT;
			goto error;
		}

		cfg_root_node = xmlDocGetRootElement(cfg_doc);
		if( cfg_root_node == NULL ){
			RHP_BUG(" %s ",rhp_main_conf_path);
			err = -ENOENT;
			goto error;
		}

	  err = rhp_xml_enum_tags(cfg_root_node,(xmlChar*)"vpn_realm",
	  				_rhp_ui_http_cfg_delete_realm_unlink_node,(void*)rlm_id,1);
	  if( err == RHP_STATUS_ENUM_OK || err == -ENOENT ){
	  	err = 0;
	  }else if( err ){
	  	goto error;
	  }

	  err = rhp_cfg_save_config(rhp_main_conf_path,cfg_doc);
		if( err ){
			RHP_BUG("%d",err);
		}
  }

  err = rhp_http_bus_send_response(http_conn,http_bus_sess,NULL,NULL);
  if( err ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_DELETE_REALM_BH_TX_RESP_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
    goto error;
  }

  if( cfg_doc ){
	  xmlFreeDoc(cfg_doc);
  }

  if( rlm ){
  	rhp_realm_unhold(rlm);
  }

  rhp_bridge_cache_flush(NULL,rlm_id);

	RHP_LOG_I(RHP_LOG_SRC_UI,0,RHP_LOG_ID_MAIN_DELETE_REALM,"s",vpn_realm_str);

	rhp_http_bus_broadcast_async(rlm_id,1,1,
			_rhp_ui_http_cfg_delete_realm_serialize,NULL,(void*)rlm_id);

  if( vpn_realm_str ){
  	_rhp_free(vpn_realm_str);
  }

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_DELETE_REALM_BH_RTRN,"xxxs",http_conn,http_bus_sess,http_req,vpn_realm_str);
  return RHP_STATUS_CLOSE_HTTP_CONN;

error:
	RHP_LOG_E(RHP_LOG_SRC_UI,0,RHP_LOG_ID_MAIN_DELETE_REALM_ERR,"sE",vpn_realm_str,err);
	if( rlm ){
	  rhp_realm_unhold(rlm);
	}
	if( cfg_doc ){
		xmlFreeDoc(cfg_doc);
	}
  if( vpn_realm_str ){
  	_rhp_free(vpn_realm_str);
  }
  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_DELETE_REALM_BH_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  return err;
}

static int _rhp_ui_http_cfg_delete_realm(xmlDocPtr doc,xmlNodePtr node,rhp_http_conn* http_conn,
		rhp_http_bus_session* http_bus_sess,rhp_http_request* http_req,void* ctx)
{
  int err = -EINVAL;
  char* vpn_realm_str = NULL;
  unsigned long rlm_id = RHP_VPN_REALM_ID_UNKNOWN;
  char* endp;
  unsigned long user_rlm_id = RHP_VPN_REALM_ID_UNKNOWN;

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_DELETE_REALM,"xxxxxx",doc,node,http_conn,http_bus_sess,http_req,ctx);

  if( doc == NULL || node == NULL ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_DELETE_REALM_NO_DOC_NODE,"xxxxx",http_conn,http_bus_sess,http_req,doc,node);
    return -EINVAL;
  }

  vpn_realm_str = (char*)rhp_xml_get_prop(node,(const xmlChar*)"vpn_realm");
  if( vpn_realm_str == NULL ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_DELETE_REALM_NO_VPN_REALM,"xxx",http_conn,http_bus_sess,http_req);
    goto error;
  }

  rlm_id = strtoul((char*)vpn_realm_str,&endp,0);
  if( (rlm_id == ULONG_MAX && errno == ERANGE) || *endp != '\0' ){
  	err = -ENOENT;
  	RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_DELETE_REALM_NO_VPN_REALM_2,"xxxs",http_conn,http_bus_sess,http_req,vpn_realm_str);
  	goto error;
  }

  if( _rhp_ui_http_get_user_realm_id(http_conn,http_bus_sess,&user_rlm_id) || user_rlm_id != 0 ){
  	err = -EPERM;
  	RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_DELETE_REALM_INVALID_USER_REALM,"xxxuu",http_conn,http_bus_sess,http_req,http_conn->user_realm_id,user_rlm_id);
		goto error;
  }

  if( rlm_id == 0 || rlm_id > RHP_VPN_REALM_ID_MAX ){

  	err = -EPERM;
		goto error;

  }else{

  	rhp_vpn_realm* rlm = rhp_realm_get(rlm_id);
  	if( rlm == NULL ){

  		if( !rhp_realm_disabled_exists(rlm_id) ){
  			err = -ENOENT;
  			goto error;
  		}
  	}

  	if( rlm ){
  		rhp_realm_unhold(rlm);
  	}
  }

  {
  	rhp_ipcmsg_syspxy_cfg_sub cfg_sub_dt;

  	cfg_sub_dt.cfg_type = RHP_IPC_SYSPXY_CFG_DELETE_REALM;
  	cfg_sub_dt.len = sizeof(rhp_ipcmsg_syspxy_cfg_sub);
  	cfg_sub_dt.target_rlm_id = rlm_id;

  	err = rhp_http_bus_ipc_cfg_request(http_conn,http_bus_sess,
  			sizeof(rhp_ipcmsg_syspxy_cfg_sub),(u8*)&cfg_sub_dt,_rhp_ui_http_cfg_delete_realm_bh,NULL);

  	if( err ){
			RHP_BUG("");
			goto error;
		}
  }

  if( vpn_realm_str ){
  	_rhp_free(vpn_realm_str);
  }

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_DELETE_REALM_RTRN,"xxxs",http_conn,http_bus_sess,http_req,vpn_realm_str);
  return RHP_STATUS_HTTP_REQ_PENDING;

error:
	RHP_LOG_E(RHP_LOG_SRC_UI,0,RHP_LOG_ID_MAIN_DELETE_REALM_ERR,"sE",vpn_realm_str,err);
	if( vpn_realm_str ){
		_rhp_free(vpn_realm_str);
	}
  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_DELETE_REALM_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  return err;
}

static int _rhp_ui_http_cfg_disable_realm_serialize(void* http_bus_sess_d,void* ctx,void* writer,int idx)
{
	rhp_http_bus_session* http_bus_sess = (rhp_http_bus_session*) http_bus_sess_d;
	unsigned long rlm_id = (unsigned long)ctx;

  int err = -EINVAL;
  int n = 0;
  int n2 = 0;

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_DISABLE_REALM_SERIALIZE,"xxdu",http_bus_sess,writer,idx,rlm_id);

  n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"rhp_http_bus_record");
  if(n < 0) {
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"index","%d",idx);
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"service",(xmlChar*)"ui_http_vpn");
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"action",(xmlChar*)"realm_config_disabled");
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"session_id","%llu",http_bus_sess->session_id);
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"vpn_realm_id","%lu",rlm_id);
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;


  n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
  if(n < 0) {
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_DISABLE_REALM_SERIALIZE_RTRN,"xud",http_bus_sess,rlm_id,n2);
  return n2;

error:
	RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_DISABLE_REALM_SERIALIZE_ERR,"xuE",http_bus_sess,rlm_id,err);
  return err;
}

static int _rhp_ui_http_cfg_disable_realm_bh(xmlDocPtr doc,xmlNodePtr req_root_node,rhp_http_conn* http_conn,rhp_http_bus_session* http_bus_sess,
  				rhp_http_request* http_req,int data_len,u8* data,void* ipc_bus_cb_ctx)
{
  int err = -EINVAL;
  char* vpn_realm_str = NULL;
  unsigned long rlm_id = RHP_VPN_REALM_ID_UNKNOWN;
  rhp_vpn_realm* rlm = NULL;
  char* endp;
	xmlDocPtr cfg_doc = NULL;
	xmlNodePtr cfg_root_node = NULL;
	rhp_ipcmsg_syspxy_cfg_sub* cfg_sub_dt = (rhp_ipcmsg_syspxy_cfg_sub*)data;

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_DISABLE_REALM_BH,"xxxxxpx",doc,req_root_node,http_conn,http_bus_sess,http_req,data_len,data,ipc_bus_cb_ctx);

	if( data_len < (int)sizeof(rhp_ipcmsg_syspxy_cfg_sub) && (int)cfg_sub_dt->len != data_len ){
		err = -EINVAL;
		RHP_BUG("%d, %d, %d",cfg_sub_dt->len,data_len,sizeof(rhp_ipcmsg_syspxy_cfg_sub));
		goto error;
	}

	if( !cfg_sub_dt->result ){
		err = -EPERM;
	  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_DISABLE_REALM_BH_RESULT_FAILED,"xxxxx",doc,req_root_node,http_conn,http_bus_sess,http_req);
		goto error;
	}

  vpn_realm_str = (char*)rhp_xml_get_prop(req_root_node,(const xmlChar*)"vpn_realm");
  if( vpn_realm_str == NULL ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_DISABLE_REALM_BH_NO_VPN_REALM,"xxx",http_conn,http_bus_sess,http_req);
    goto error;
  }

  rlm_id = strtoul((char*)vpn_realm_str,&endp,0);
  if( (rlm_id == ULONG_MAX && errno == ERANGE) || *endp != '\0' ){
  	err = -ENOENT;
  	RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_DISABLE_REALM_BH_NO_VPN_REALM_2,"xxxs",http_conn,http_bus_sess,http_req,vpn_realm_str);
  	goto error;
  }

  if( rlm_id != cfg_sub_dt->target_rlm_id ){
  	err = -EINVAL;
  	RHP_BUG("%d, %d",rlm_id,cfg_sub_dt->target_rlm_id);
  	goto error;
  }


  err = _rhp_ui_http_cfg_delete_realm_exec(rlm_id,&rlm);
  if( err ){
  	goto error;
  }

  rhp_realm_disabled_put(rlm->id,rlm->name,rlm->mode_label,
  		rlm->description,rlm->realm_created_time,rlm->realm_updated_time);

  {
  	rhp_ui_http_cfg_update_enum_ctx enum_ctx;
		xmlAttrPtr status_attr;

  	memset(&enum_ctx,0,sizeof(rhp_ui_http_cfg_update_enum_ctx));

		cfg_doc = xmlParseFile(rhp_main_conf_path);
		if( cfg_doc == NULL ){
			RHP_BUG(" %s ",rhp_main_conf_path);
			err = -ENOENT;
			goto error;
		}

		cfg_root_node = xmlDocGetRootElement(cfg_doc);
		if( cfg_root_node == NULL ){
			RHP_BUG(" %s ",rhp_main_conf_path);
			err = -ENOENT;
			goto error;
		}


		enum_ctx.rlm_id = cfg_sub_dt->target_rlm_id;

	  err = rhp_xml_enum_tags(cfg_root_node,NULL,_rhp_ui_http_cfg_enable_enum_xml,(void*)&enum_ctx,1);
	  if( err != RHP_STATUS_ENUM_OK ){
	    RHP_BUG(" %s ",rhp_main_conf_path);
	    goto error;
	  }
	  err = 0;


		status_attr =	xmlHasProp(enum_ctx.new_node,(xmlChar*)"status");

		if( xmlNewProp(enum_ctx.new_node,(xmlChar*)"status",(xmlChar*)"disable") == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		if( status_attr ){
			xmlRemoveProp(status_attr);
		}


	  err = rhp_cfg_save_config(rhp_main_conf_path,cfg_doc);
		if( err ){
			RHP_BUG("%d",err);
		}
  }

  err = rhp_http_bus_send_response(http_conn,http_bus_sess,NULL,NULL);
  if( err ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_DISABLE_REALM_BH_TX_RESP_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
    goto error;
  }

  if( cfg_doc ){
	  xmlFreeDoc(cfg_doc);
  }

  rhp_realm_unhold(rlm);

  rhp_bridge_cache_flush(NULL,rlm_id);

	RHP_LOG_I(RHP_LOG_SRC_UI,0,RHP_LOG_ID_MAIN_DISABLE_REALM,"s",vpn_realm_str);

	rhp_http_bus_broadcast_async(rlm_id,1,1,
			_rhp_ui_http_cfg_disable_realm_serialize,NULL,(void*)rlm_id);

  if( vpn_realm_str ){
  	_rhp_free(vpn_realm_str);
  }

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_DISABLE_REALM_BH_RTRN,"xxxs",http_conn,http_bus_sess,http_req,vpn_realm_str);
  return RHP_STATUS_CLOSE_HTTP_CONN;

error:
	RHP_LOG_E(RHP_LOG_SRC_UI,0,RHP_LOG_ID_MAIN_DISABLE_REALM_ERR,"sE",vpn_realm_str,err);
	if( rlm ){
	  rhp_realm_unhold(rlm);
	}
	if( cfg_doc ){
		xmlFreeDoc(cfg_doc);
	}
  if( vpn_realm_str ){
  	_rhp_free(vpn_realm_str);
  }
  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_DISABLE_REALM_BH_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  return err;
}

static int _rhp_ui_http_cfg_disable_realm(xmlDocPtr doc,xmlNodePtr node,rhp_http_conn* http_conn,
		rhp_http_bus_session* http_bus_sess,rhp_http_request* http_req,void* ctx)
{
  int err = -EINVAL;
  char* vpn_realm_str = NULL;
  unsigned long rlm_id = RHP_VPN_REALM_ID_UNKNOWN;
  char* endp;
  unsigned long user_rlm_id = RHP_VPN_REALM_ID_UNKNOWN;

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_DISABLE_REALM,"xxxxxx",doc,node,http_conn,http_bus_sess,http_req,ctx);

  if( doc == NULL || node == NULL ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_DISABLE_REALM_NO_DOC_NODE,"xxxxx",http_conn,http_bus_sess,http_req,doc,node);
    return -EINVAL;
  }

  vpn_realm_str = (char*)rhp_xml_get_prop(node,(const xmlChar*)"vpn_realm");
  if( vpn_realm_str == NULL ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_DISABLE_REALM_NO_VPN_REALM,"xxx",http_conn,http_bus_sess,http_req);
    goto error;
  }

  rlm_id = strtoul((char*)vpn_realm_str,&endp,0);
  if( (rlm_id == ULONG_MAX && errno == ERANGE) || *endp != '\0' ){
  	err = -ENOENT;
  	RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_DISABLE_REALM_NO_VPN_REALM_2,"xxxs",http_conn,http_bus_sess,http_req,vpn_realm_str);
  	goto error;
  }

  if( _rhp_ui_http_get_user_realm_id(http_conn,http_bus_sess,&user_rlm_id) || user_rlm_id != 0 ){
  	err = -EPERM;
  	RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_DISABLE_REALM_INVALID_USER_REALM,"xxxuu",http_conn,http_bus_sess,http_req,http_conn->user_realm_id,user_rlm_id);
		goto error;
  }

  if( rlm_id == 0 || rlm_id > RHP_VPN_REALM_ID_MAX ){

  	err = -EPERM;
		goto error;

  }else{

  	rhp_vpn_realm* rlm;

  	if( rhp_realm_disabled_exists(rlm_id) ){

    	RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_DISABLE_REALM_ALREADY_DISABLED,"xxxu",http_conn,http_bus_sess,http_req,rlm_id);

  		err = -EEXIST;
  		goto error;
  	}

  	rlm = rhp_realm_get(rlm_id);
  	if( rlm == NULL ){

    	RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_DISABLE_REALM_NO_ENT,"xxxu",http_conn,http_bus_sess,http_req,rlm_id);

  		err = -ENOENT;
  		goto error;
  	}

  	rhp_realm_unhold(rlm);
  }

  {
  	rhp_ipcmsg_syspxy_cfg_sub cfg_sub_dt;

  	cfg_sub_dt.cfg_type = RHP_IPC_SYSPXY_CFG_DISABLE_REALM;
  	cfg_sub_dt.len = sizeof(rhp_ipcmsg_syspxy_cfg_sub);
  	cfg_sub_dt.target_rlm_id = rlm_id;

  	err = rhp_http_bus_ipc_cfg_request(http_conn,http_bus_sess,
  			sizeof(rhp_ipcmsg_syspxy_cfg_sub),(u8*)&cfg_sub_dt,_rhp_ui_http_cfg_disable_realm_bh,NULL);

  	if( err ){
			RHP_BUG("");
			goto error;
		}
  }

  if( vpn_realm_str ){
  	_rhp_free(vpn_realm_str);
  }

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_DISABLE_REALM_RTRN,"xxxs",http_conn,http_bus_sess,http_req,vpn_realm_str);
  return RHP_STATUS_HTTP_REQ_PENDING;

error:
	RHP_LOG_E(RHP_LOG_SRC_UI,0,RHP_LOG_ID_MAIN_DISABLE_REALM_ERR,"sE",vpn_realm_str,err);
	if( vpn_realm_str ){
		_rhp_free(vpn_realm_str);
	}
  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_DISABLE_REALM_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  return err;
}

static int _rhp_ui_http_cfg_realm_is_disabled(xmlDocPtr doc,xmlNodePtr node,rhp_http_conn* http_conn,
		rhp_http_bus_session* http_bus_sess,rhp_http_request* http_req,void* ctx)
{
  int err = -EINVAL;
  char* vpn_realm_str = NULL;
  unsigned long rlm_id = RHP_VPN_REALM_ID_UNKNOWN;
  char* endp;

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_REALM_IS_DISABLED,"xxxxxx",doc,node,http_conn,http_bus_sess,http_req,ctx);

  if( doc == NULL || node == NULL ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_REALM_IS_DISABLED_NO_DOC_NODE,"xxxxx",http_conn,http_bus_sess,http_req,doc,node);
    return -EINVAL;
  }

  vpn_realm_str = (char*)rhp_xml_get_prop(node,(const xmlChar*)"vpn_realm");
  if( vpn_realm_str == NULL ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_REALM_IS_DISABLED_NO_VPN_REALM,"xxx",http_conn,http_bus_sess,http_req);
    goto error;
  }

  rlm_id = strtoul((char*)vpn_realm_str,&endp,0);
  if( (rlm_id == ULONG_MAX && errno == ERANGE) || *endp != '\0' ){
  	err = -ENOENT;
  	RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_REALM_IS_DISABLED_NO_VPN_REALM_2,"xxxs",http_conn,http_bus_sess,http_req,vpn_realm_str);
  	goto error;
  }

  if( http_conn->user_realm_id && http_conn->user_realm_id != rlm_id ){
  	err = -EPERM;
		goto error;
  }

  if( rlm_id == 0 || rlm_id > RHP_VPN_REALM_ID_MAX ){

  	err = -EPERM;
		goto error;

  }else{

  	if( !rhp_realm_disabled_exists(rlm_id) ){
  		err = -ENOENT;
  		goto error;
  	}
  }


  err = rhp_http_bus_send_response(http_conn,http_bus_sess,NULL,NULL);
  if( err ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_REALM_IS_DISABLED_TX_RESP_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
    goto error;
  }

  if( vpn_realm_str ){
  	_rhp_free(vpn_realm_str);
  }

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_REALM_IS_DISABLED_RTRN,"xxxs",http_conn,http_bus_sess,http_req,vpn_realm_str);
  return RHP_STATUS_CLOSE_HTTP_CONN;

error:
	if( vpn_realm_str ){
		_rhp_free(vpn_realm_str);
	}
  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_REALM_IS_DISABLED_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  return err;
}

static int _rhp_ui_http_vpn_clear_all(xmlDocPtr doc,xmlNodePtr node,rhp_http_conn* http_conn,
		rhp_http_bus_session* http_bus_sess,rhp_http_request* http_req,void* ctx)
{
  int err = -EINVAL;
  char* vpn_realm_str = NULL;
  unsigned long rlm_id = 0;
  char* endp;
  int only_dormant = 0;

  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_CLEAR_ALL,"xxxxxx",doc,node,http_conn,http_bus_sess,http_req,ctx);

  if( doc == NULL || node == NULL ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_CLEAR_ALL_NO_DOC_NODE,"xxxxx",http_conn,http_bus_sess,http_req,doc,node);
    return -EINVAL;
  }

  vpn_realm_str = (char*)rhp_xml_get_prop(node,(const xmlChar*)"vpn_realm");
  if( vpn_realm_str == NULL ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_CLEAR_ALL_NO_VPN_REALM,"xxx",http_conn,http_bus_sess,http_req);
    goto error;
  }

  rlm_id = strtoul((char*)vpn_realm_str,&endp,0);
  if( (rlm_id == ULONG_MAX && errno == ERANGE) || *endp != '\0' ){
  	err = -ENOENT;
  	RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_CLEAR_ALL_NO_VPN_REALM_2,"xxxs",http_conn,http_bus_sess,http_req,vpn_realm_str);
  	goto error;
  }

  if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(xmlChar*)"type"),(xmlChar*)"all") ){
  	only_dormant = 0;
  }else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(xmlChar*)"type"),(xmlChar*)"dormant") ){
  	only_dormant = 1;
  }

  if( _rhp_ui_http_permitted(http_conn,http_bus_sess,rlm_id) ){
			err = -EPERM;
			RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_CLEAR_ALL_NOT_PERMITTED,"xxxuu",http_conn,http_bus_sess,http_req,http_conn->user_realm_id,http_bus_sess->user_realm_id);
			goto error;
	}

  if( rlm_id == 0 || rlm_id > RHP_VPN_REALM_ID_MAX ){

  	err = -EPERM;
		goto error;

  }else{

  	rhp_vpn_realm* rlm = rhp_realm_get(rlm_id);
  	if( rlm == NULL ){
  		err = -ENOENT;
  		goto error;
  	}

  	rhp_realm_unhold(rlm);
  }

  err = rhp_vpn_cleanup_by_realm_id(rlm_id,only_dormant);
  if( err ){
  	RHP_BUG("%d",err);
  	goto error;
  }


	RHP_LOG_I(RHP_LOG_SRC_UI,rlm_id,RHP_LOG_ID_VPN_CLEAR_ALL,"");


	err = rhp_http_bus_send_response(http_conn,http_bus_sess,NULL,NULL);
  if( err ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_CLEAR_ALL_TX_RESP_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
    goto error;
  }

	if( vpn_realm_str ){
  	_rhp_free(vpn_realm_str);
  }

  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_CLEAR_ALL_RTRN,"xxxs",http_conn,http_bus_sess,http_req,vpn_realm_str);
  return RHP_STATUS_CLOSE_HTTP_CONN;

error:
	RHP_LOG_E(RHP_LOG_SRC_UI,rlm_id,RHP_LOG_ID_VPN_CLEAR_ALL_ERR,"E",err);
	if( vpn_realm_str ){
		_rhp_free(vpn_realm_str);
	}
  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_CLEAR_ALL_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  return err;
}

static int _rhp_ui_http_vpn_mobike_clear_additional_addr_cache(xmlDocPtr doc,xmlNodePtr node,rhp_http_conn* http_conn,
		rhp_http_bus_session* http_bus_sess,rhp_http_request* http_req,void* ctx)
{
  int err = -EINVAL;
  char* vpn_realm_str = NULL;
  unsigned long rlm_id = 0;
  char* endp;

  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_MOBIKE_CLEAR_ADDITIONAL_ADDR_CACHE,"xxxxxx",doc,node,http_conn,http_bus_sess,http_req,ctx);

  if( doc == NULL || node == NULL ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_MOBIKE_CLEAR_ADDITIONAL_ADDR_CACHE_NO_DOC_NODE,"xxxxx",http_conn,http_bus_sess,http_req,doc,node);
    return -EINVAL;
  }

  vpn_realm_str = (char*)rhp_xml_get_prop(node,(const xmlChar*)"vpn_realm");
  if( vpn_realm_str == NULL ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_MOBIKE_CLEAR_ADDITIONAL_ADDR_CACHE_NO_VPN_REALM,"xxx",http_conn,http_bus_sess,http_req);
    goto error;
  }

  rlm_id = strtoul((char*)vpn_realm_str,&endp,0);
  if( (rlm_id == ULONG_MAX && errno == ERANGE) || *endp != '\0' ){
  	err = -ENOENT;
  	RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_MOBIKE_CLEAR_ADDITIONAL_ADDR_CACHE_NO_VPN_REALM_2,"xxxs",http_conn,http_bus_sess,http_req,vpn_realm_str);
  	goto error;
  }

  if( _rhp_ui_http_permitted(http_conn,http_bus_sess,rlm_id) ){
			err = -EPERM;
			RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_MOBIKE_CLEAR_ADDITIONAL_ADDR_CACHE_NOT_PERMITTED,"xxxuu",http_conn,http_bus_sess,http_req,http_conn->user_realm_id,http_bus_sess->user_realm_id);
			goto error;
	}

  if( rlm_id == 0 || rlm_id > RHP_VPN_REALM_ID_MAX ){

  	err = -EPERM;
		goto error;

  }else{

  	rhp_vpn_realm* rlm;
  	rhp_cfg_peer* cfg_peer;

  	rlm = rhp_realm_get(rlm_id);
  	if( rlm == NULL ){
  		err = -ENOENT;
  		goto error;
  	}

  	RHP_LOCK(&(rlm->lock));

  	cfg_peer = rlm->peers;
  	while( cfg_peer ){

  		memset(&(cfg_peer->mobike_additional_addr_cache),0,sizeof(rhp_ip_addr));

  		cfg_peer = cfg_peer->next;
  	}

  	RHP_UNLOCK(&(rlm->lock));

  	rhp_realm_unhold(rlm);
  }


	RHP_LOG_I(RHP_LOG_SRC_UI,rlm_id,RHP_LOG_ID_VPN_MOBIKE_CLEAR_ADDITIONAL_ADDR_CACHE,"");


	err = rhp_http_bus_send_response(http_conn,http_bus_sess,NULL,NULL);
  if( err ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_MOBIKE_CLEAR_ADDITIONAL_ADDR_CACHE_TX_RESP_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
    goto error;
  }

	if( vpn_realm_str ){
  	_rhp_free(vpn_realm_str);
  }

  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_MOBIKE_CLEAR_ADDITIONAL_ADDR_CACHE_RTRN,"xxxs",http_conn,http_bus_sess,http_req,vpn_realm_str);
  return RHP_STATUS_CLOSE_HTTP_CONN;

error:
	RHP_LOG_E(RHP_LOG_SRC_UI,rlm_id,RHP_LOG_ID_VPN_MOBIKE_CLEAR_ADDITIONAL_ADDR_CACHE_ERR,"E",err);
	if( vpn_realm_str ){
		_rhp_free(vpn_realm_str);
	}
  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_MOBIKE_CLEAR_ADDITIONAL_ADDR_CACHE_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  return err;
}



static int _rhp_ui_http_cfg_update_realm_bh(xmlDocPtr doc,xmlNodePtr req_root_node,rhp_http_conn* http_conn,rhp_http_bus_session* http_bus_sess,
  				rhp_http_request* http_req,int data_len,u8* data,void* ipc_bus_cb_ctx)
{
  int err = -EINVAL;
  char* vpn_realm_str = NULL;
  unsigned long rlm_id = RHP_VPN_REALM_ID_UNKNOWN;
  char* endp;
	xmlDocPtr cfg_doc = NULL;
	xmlNodePtr cfg_root_node = NULL;
	rhp_vpn_realm *old_rlm = NULL,*new_rlm = NULL;
	rhp_ui_http_cfg_update_enum_ctx enum_ctx;
	int old_dns_pxy = 0;
	xmlNodePtr rhp_cfg_node = NULL;
	rhp_ipcmsg_syspxy_cfg_sub* cfg_sub_dt = (rhp_ipcmsg_syspxy_cfg_sub*)data;
	time_t old_created_time = -1;

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_UPDATE_REALM_BH,"xxxxxpx",doc,req_root_node,http_conn,http_bus_sess,http_req,data_len,data,ipc_bus_cb_ctx);

	if( data_len < (int)sizeof(rhp_ipcmsg_syspxy_cfg_sub) && (int)cfg_sub_dt->len != data_len ){
		err = -EINVAL;
		RHP_BUG("%d, %d, %d",cfg_sub_dt->len,data_len,sizeof(rhp_ipcmsg_syspxy_cfg_sub));
		goto error;
	}

	if( !cfg_sub_dt->result ){
		err = -EPERM;
	  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_UPDATE_REALM_BH_RESULT_FAILED,"xxxxx",doc,req_root_node,http_conn,http_bus_sess,http_req);
		goto error;
	}

	memset(&enum_ctx,0,sizeof(rhp_ui_http_cfg_update_enum_ctx));

  if( doc == NULL || req_root_node == NULL ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_UPDATE_REALM_BH_NO_DOC_NODE,"xxxxx",http_conn,http_bus_sess,http_req,doc,req_root_node);
    return -EINVAL;
  }

  rhp_cfg_node = rhp_xml_get_child(req_root_node,(xmlChar*)"rhp_config");
  if( rhp_cfg_node == NULL ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_UPDATE_REALM_BH_NO_TOP_ELM,"xxx",http_conn,http_bus_sess,http_req);
    goto error;
  }

  vpn_realm_str = (char*)rhp_xml_get_prop(req_root_node,(const xmlChar*)"vpn_realm");
  if( vpn_realm_str == NULL ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_UPDATE_REALM_BH_NO_VPN_REALM,"xxx",http_conn,http_bus_sess,http_req);
    goto error;
  }

  rlm_id = strtoul((char*)vpn_realm_str,&endp,0);
  if( (rlm_id == ULONG_MAX && errno == ERANGE) || *endp != '\0' ){
  	err = -ENOENT;
  	RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_UPDATE_REALM_BH_NO_VPN_REALM_2,"xxxs",http_conn,http_bus_sess,http_req,vpn_realm_str);
  	goto error;
  }


  if( rlm_id != cfg_sub_dt->target_rlm_id ){
  	err = -EINVAL;
  	RHP_BUG("%d, %d",rlm_id,cfg_sub_dt->target_rlm_id);
  	goto error;
  }


  enum_ctx.rlm_id = rlm_id;

	err = rhp_xml_enum_tags(rhp_cfg_node,
			(xmlChar*)"vpn_realm",_rhp_ui_http_cfg_update_parse_realm,&enum_ctx,0);

	if( err == -EINVAL || err == -ENOENT || (enum_ctx.new_rlm == NULL) ){
  	err = RHP_STATUS_INVALID_MSG;
  	goto error;
  }else if( err ){
  	goto error;
  }

  new_rlm = enum_ctx.new_rlm;

  if( new_rlm == NULL ){
  	err = RHP_STATUS_INVALID_MSG;
  	goto error;
  }


  {
  	old_rlm = rhp_realm_delete_by_id(rlm_id);
		if( old_rlm == NULL ){
			err = -ENOENT;
			goto error;
		}

		_rhp_atomic_set(&(old_rlm->is_active),0);


		err = rhp_vpn_cleanup_by_realm_id(rlm_id,0);
		if( err ){
			RHP_BUG("%d",err);
			goto error;
		}

		rhp_bridge_cache_cleanup_by_realm_id(rlm_id);


		RHP_LOCK(&(old_rlm->lock));
		{
			rhp_ifc_entry* v_ifc = old_rlm->internal_ifc->ifc;

			if( v_ifc ){

				RHP_LOCK(&(v_ifc->lock));
				{

					rhp_tuntap_close(v_ifc);

					v_ifc->tuntap_deleting = 1;
				}
				RHP_UNLOCK(&(v_ifc->lock));

				err = rhp_ipc_send_delete_vif(old_rlm);
				if( err ){
					RHP_BUG("%d",err);
				}
			}

			err = rhp_ipc_send_delete_all_static_routes(old_rlm);
			if( err ){
				RHP_BUG("%d",err);
			}

			if( old_rlm->split_dns.domains != NULL ){

				if( !rhp_ip_addr_null(&(old_rlm->split_dns.internal_server_addr)) ){
		  		old_dns_pxy++;
		  	}

				if( !rhp_ip_addr_null(&(old_rlm->split_dns.internal_server_addr_v6)) ){
		  		old_dns_pxy++;
		  	}
			}

			old_created_time = old_rlm->realm_created_time;
		}
		RHP_UNLOCK(&(old_rlm->lock));
  }

  {
  	_rhp_ui_http_cfg_update_realm_time(new_rlm,old_created_time,0);

		enum_ctx.created_time = old_created_time;
		enum_ctx.updated_time = new_rlm->realm_updated_time;
		enum_ctx.sess_resume_policy_index = new_rlm->sess_resume_policy_index;
		enum_ctx.update_sess_resume_policy_index = 0;
  }


  err = _rhp_ui_http_cfg_update_realm_exec(http_conn,http_bus_sess,new_rlm);
  if( err ){
  	goto error;
  }


	if( old_dns_pxy && rhp_dns_pxy_dec_and_test_users() ){

		rhp_dns_pxy_main_end(AF_INET);
		rhp_dns_pxy_main_end(AF_INET6);
	}


  {
		cfg_doc = xmlParseFile(rhp_main_conf_path);
		if( cfg_doc == NULL ){
			RHP_BUG(" %s ",rhp_main_conf_path);
			err = -ENOENT;
			goto error;
		}

		cfg_root_node = xmlDocGetRootElement(cfg_doc);
		if( cfg_root_node == NULL ){
			RHP_BUG(" %s ",rhp_main_conf_path);
			err = -ENOENT;
			goto error;
		}

		enum_ctx.cfg_parent = cfg_root_node;

	  err = rhp_xml_enum_tags(cfg_root_node,
	  		(xmlChar*)"vpn_realm",_rhp_ui_http_cfg_update_realm_update_node,(void*)&enum_ctx,1);

	  if( err == RHP_STATUS_ENUM_OK || err == -ENOENT ){
	  	err = 0;
	  }else if( err ){
	  	goto error;
	  }

	  err = rhp_cfg_save_config(rhp_main_conf_path,cfg_doc);
		if( err ){
			RHP_BUG("%d",err);
		}
  }

	if( cfg_doc ){
		xmlFreeDoc(cfg_doc);
	}

  err = rhp_http_bus_send_response(http_conn,http_bus_sess,NULL,NULL);
  if( err ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_UPDATE_REALM_BH_TX_RESP_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
    goto error;
  }

	rhp_realm_unhold(new_rlm);
	rhp_realm_unhold(old_rlm);

  rhp_bridge_cache_flush(NULL,rlm_id);


  RHP_LOG_I(RHP_LOG_SRC_UI,rlm_id,RHP_LOG_ID_MAIN_UPDATE_REALM,"s",vpn_realm_str);

	rhp_http_bus_broadcast_async(rlm_id,1,1,
			_rhp_ui_http_cfg_update_realm_serialize,NULL,(void*)rlm_id);


  if( vpn_realm_str ){
  	_rhp_free(vpn_realm_str);
  }

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_UPDATE_REALM_BH_RTRN,"xxxxx",http_conn,http_bus_sess,http_req,new_rlm,old_rlm);
  return RHP_STATUS_CLOSE_HTTP_CONN;

error:
	if( rlm_id > 0 && rlm_id != (unsigned long)-1 ){
		RHP_LOG_E(RHP_LOG_SRC_UI,rlm_id,RHP_LOG_ID_MAIN_UPDATE_REALM_ERR,"sE",vpn_realm_str,err);
	}else{
		RHP_LOG_E(RHP_LOG_SRC_UI,0,RHP_LOG_ID_MAIN_UPDATE_REALM_ERR,"sE",vpn_realm_str,err);
	}
	if( cfg_doc ){
		xmlFreeDoc(cfg_doc);
	}
	if( new_rlm ){
		rhp_realm_unhold(new_rlm);
	}
	if( old_rlm ){
		rhp_realm_unhold(old_rlm);
	}
  if( vpn_realm_str ){
  	_rhp_free(vpn_realm_str);
  }
  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_UPDATE_REALM_BH_ERR,"xxxxxE",http_conn,http_bus_sess,http_req,new_rlm,old_rlm,err);
  return err;
}

static int _rhp_ui_http_cfg_update_realm(xmlDocPtr doc,xmlNodePtr req_root_node,rhp_http_conn* http_conn,
		rhp_http_bus_session* http_bus_sess,rhp_http_request* http_req,void* ctx)
{
  int err = -EINVAL;
  char* vpn_realm_str = NULL;
  unsigned long rlm_id = (unsigned long)-1;
  char* endp;
	xmlNodePtr rhp_cfg_node = NULL;
  xmlTextWriterPtr writer = NULL;
  xmlBufferPtr buf = NULL;
	rhp_ipcmsg_syspxy_cfg_sub* cfg_sub_dt = NULL;
	int cfg_sub_dt_len = 0;

	RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_UPDATE_REALM,"xxxxxx",doc,req_root_node,http_conn,http_bus_sess,http_req,ctx);

  if( doc == NULL || req_root_node == NULL ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_UPDATE_REALM_NO_DOC_NODE,"xxxxx",http_conn,http_bus_sess,http_req,doc,req_root_node);
    return -EINVAL;
  }

  rhp_cfg_node = rhp_xml_get_child(req_root_node,(xmlChar*)"rhp_config");
  if( rhp_cfg_node == NULL ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_UPDATE_REALM_NO_TOP_ELM,"xxx",http_conn,http_bus_sess,http_req);
    goto error;
  }

  vpn_realm_str = (char*)rhp_xml_get_prop(req_root_node,(const xmlChar*)"vpn_realm");
  if( vpn_realm_str == NULL ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_UPDATE_REALM_NO_VPN_REALM,"xxx",http_conn,http_bus_sess,http_req);
    goto error;
  }

  rlm_id = strtoul((char*)vpn_realm_str,&endp,0);
  if( (rlm_id == ULONG_MAX && errno == ERANGE) || *endp != '\0' ){
  	err = -ENOENT;
  	RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_UPDATE_REALM_NO_VPN_REALM_2,"xxxs",http_conn,http_bus_sess,http_req,vpn_realm_str);
  	goto error;
  }

  if( _rhp_ui_http_permitted(http_conn,http_bus_sess,rlm_id) ){
			err = -EPERM;
			RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_UPDATE_REALM_NOT_PERMITTED,"xxxuu",http_conn,http_bus_sess,http_req,http_conn->user_realm_id,http_bus_sess->user_realm_id);
			goto error;
	}

  if( rlm_id == 0 || rlm_id > RHP_VPN_REALM_ID_MAX ){

  	err = -EPERM;
		goto error;

  }else{

  	rhp_vpn_realm* old_rlm = rhp_realm_get(rlm_id);
  	if( old_rlm == NULL ){
  		err = -ENOENT;
  		goto error;
  	}
  	rhp_realm_unhold(old_rlm);
  }

  {
  	xmlNodePtr rhp_auth_node;
  	int n2 = 0;

  	rhp_auth_node = rhp_xml_get_child(req_root_node,(xmlChar*)"rhp_auth");

  	if( rhp_auth_node ){

  		int n = 0;

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

				err = rhp_xml_write_node(rhp_auth_node,writer,&n,1,NULL,NULL,NULL);
				if( err ){
					RHP_BUG("%d",err);
					goto error;
				}

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
  		}

		  xmlFreeTextWriter(writer);
		  writer = NULL;


  		cfg_sub_dt_len = xmlStrlen(buf->content) + 1 + sizeof(rhp_ipcmsg_syspxy_cfg_sub);

  		cfg_sub_dt = (rhp_ipcmsg_syspxy_cfg_sub*)_rhp_malloc(cfg_sub_dt_len);
			if( cfg_sub_dt == NULL ){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}

  		cfg_sub_dt->cfg_type = RHP_IPC_SYSPXY_CFG_UPDATE_REALM;
			cfg_sub_dt->len = cfg_sub_dt_len;
			cfg_sub_dt->target_rlm_id = rlm_id;

			memcpy((cfg_sub_dt + 1),buf->content,(cfg_sub_dt_len - sizeof(rhp_ipcmsg_syspxy_cfg_sub)));

			err = rhp_http_bus_ipc_cfg_request(http_conn,http_bus_sess,
					cfg_sub_dt_len,(u8*)cfg_sub_dt,_rhp_ui_http_cfg_update_realm_bh,NULL);

			if( err ){
				RHP_BUG("");
				goto error;
			}

		  xmlBufferFree(buf);
		  buf = NULL;
		  _rhp_free_zero(cfg_sub_dt,cfg_sub_dt_len);
		  cfg_sub_dt = NULL;

  	}else{

  		rhp_ipcmsg_syspxy_cfg_sub cfg_sub_dt_dmy;

  		memset(&cfg_sub_dt_dmy,0,sizeof(rhp_ipcmsg_syspxy_cfg_sub));

  		cfg_sub_dt_dmy.cfg_type = RHP_IPC_SYSPXY_CFG_UPDATE_REALM;
			cfg_sub_dt_dmy.len = sizeof(rhp_ipcmsg_syspxy_cfg_sub);
			cfg_sub_dt_dmy.target_rlm_id = rlm_id;
			cfg_sub_dt_dmy.result = 1;

  		err = _rhp_ui_http_cfg_update_realm_bh(doc,req_root_node,http_conn,http_bus_sess,http_req,
  				sizeof(rhp_ipcmsg_syspxy_cfg_sub),(u8*)&cfg_sub_dt_dmy,NULL);

  		if( err == RHP_STATUS_CLOSE_HTTP_CONN ){
  			goto end;
  		}else if( err ){
  			goto error;
  		}
  	}
  }

   if( vpn_realm_str ){
  	_rhp_free(vpn_realm_str);
  }

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_UPDATE_REALM_PENDING_RTRN,"xxxs",http_conn,http_bus_sess,http_req,vpn_realm_str);
  return RHP_STATUS_HTTP_REQ_PENDING;

end:
	RHP_LOG_I(RHP_LOG_SRC_UI,rlm_id,RHP_LOG_ID_MAIN_UPDATE_REALM,"s",vpn_realm_str);
	if( vpn_realm_str ){
		_rhp_free(vpn_realm_str);
	}
	RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_UPDATE_REALM_NO_AUTH_RLM_UPDATE_RTRN,"xxxs",http_conn,http_bus_sess,http_req,vpn_realm_str);
	return RHP_STATUS_CLOSE_HTTP_CONN;

error:
	if( rlm_id > 0 && rlm_id != (unsigned long)-1 ){
		RHP_LOG_E(RHP_LOG_SRC_UI,rlm_id,RHP_LOG_ID_MAIN_UPDATE_REALM_ERR,"sE",vpn_realm_str,err);
	}else{
		RHP_LOG_E(RHP_LOG_SRC_UI,0,RHP_LOG_ID_MAIN_UPDATE_REALM_ERR,"sE",vpn_realm_str,err);
	}
	if( writer ){
		xmlFreeTextWriter(writer);
	}
	if( buf ){
		xmlBufferFree(buf);
	}
	if( cfg_sub_dt ){
		_rhp_free_zero(cfg_sub_dt,cfg_sub_dt_len);
	}
  if( vpn_realm_str ){
  	_rhp_free(vpn_realm_str);
  }
  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_UPDATE_REALM_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  return err;
}


struct _rhp_ui_http__global_cfg_enum_ctx {
  rhp_cfg_admin_service *cfg_admin_srvs_head;
  rhp_cfg_peer_acl *cfg_peer_acls_head;
  rhp_cfg_firewall* cfg_firewall_rules_head;
  rhp_gcfg_hash_url* cfg_hash_url;
	rhp_eap_radius_gcfg* cfg_eap_radius;
	rhp_radius_acct_gcfg* cfg_radius_acct;
};
typedef struct _rhp_ui_http__global_cfg_enum_ctx		rhp_ui_http_global_cfg_enum_ctx;

static int _rhp_ui_http_cfg_update_global_admin_service_parse(xmlNodePtr node,void* ctx)
{
	int err = -EINVAL;
	rhp_ui_http_global_cfg_enum_ctx* enum_ctx = (rhp_ui_http_global_cfg_enum_ctx*)ctx;
	rhp_cfg_admin_service* cfg_admin_srv;
  rhp_cfg_admin_service *cfg_admin_srv_p = NULL,*cfg_admin_srv_c = NULL;

  cfg_admin_srv = rhp_cfg_parse_admin_service(node);
	if( cfg_admin_srv == NULL ){
		err = -EINVAL;
		goto error;
	}

  cfg_admin_srv_c = enum_ctx->cfg_admin_srvs_head;
  while( cfg_admin_srv_c ){
    cfg_admin_srv_p = cfg_admin_srv_c;
    cfg_admin_srv_c = cfg_admin_srv_c->next;
  }

  if( cfg_admin_srv_p == NULL ){
  	enum_ctx->cfg_admin_srvs_head = cfg_admin_srv;
  }else{
    cfg_admin_srv_p->next = cfg_admin_srv;
  }

	return 0;

error:
	return err;
}

static int _rhp_ui_http_cfg_update_global_peer_acl_parse(xmlNodePtr node,void* ctx)
{
	int err = -EINVAL;
	rhp_ui_http_global_cfg_enum_ctx* enum_ctx = (rhp_ui_http_global_cfg_enum_ctx*)ctx;
	rhp_cfg_peer_acl* cfg_peer_acl;
  rhp_cfg_peer_acl *cfg_peer_acl_p = NULL,*cfg_peer_acl_c = NULL;

	cfg_peer_acl = rhp_cfg_parse_peer_acl(node);
	if( cfg_peer_acl == NULL ){
		err = -EINVAL;
		goto error;
	}

  cfg_peer_acl_c = enum_ctx->cfg_peer_acls_head;

  while( cfg_peer_acl_c ){
    if( cfg_peer_acl_c->priority > cfg_peer_acl->priority ){
      break;
    }
    cfg_peer_acl_p = cfg_peer_acl_c;
    cfg_peer_acl_c = cfg_peer_acl_c->next;
  }

  if( cfg_peer_acl_p == NULL ){
  	cfg_peer_acl->next = enum_ctx->cfg_peer_acls_head;
  	enum_ctx->cfg_peer_acls_head = cfg_peer_acl;
  }else{
    cfg_peer_acl->next = cfg_peer_acl_p->next;
    cfg_peer_acl_p->next = cfg_peer_acl;
  }

	return 0;

error:
	return err;
}

static int _rhp_ui_http_cfg_update_global_firewall_parse(xmlNodePtr node,void* ctx)
{
	int err = -EINVAL;
	rhp_ui_http_global_cfg_enum_ctx* enum_ctx = (rhp_ui_http_global_cfg_enum_ctx*)ctx;
	rhp_cfg_firewall* cfg_fw = NULL;
	rhp_cfg_firewall *cfg_fw_p = NULL,*cfg_fw_c = NULL;

	cfg_fw = rhp_cfg_parse_firewall_rule(node);
  if( cfg_fw == NULL ){
  	RHP_BUG("");
  	err = -EINVAL;
  	goto error;
  }

  cfg_fw_c = enum_ctx->cfg_firewall_rules_head;

  while( cfg_fw_c ){

  	if( cfg_fw_c->priority > cfg_fw->priority ){
      break;
    }

  	cfg_fw_p = cfg_fw_c;
    cfg_fw_c = cfg_fw_c->next;
  }

  if( cfg_fw_p == NULL ){
  	cfg_fw->next = enum_ctx->cfg_firewall_rules_head;
  	enum_ctx->cfg_firewall_rules_head = cfg_fw;
  }else{
  	cfg_fw->next = cfg_fw_p->next;
  	cfg_fw_p->next = cfg_fw;
  }

  return 0;

error:
  if( cfg_fw ){
    _rhp_free(cfg_fw);
  }
  return -EINVAL;
}


static int _rhp_ui_http_cfg_update_global_cfg_parse(xmlNodePtr node,void* ctx)
{
	int err = -EINVAL;
	rhp_ui_http_global_cfg_enum_ctx* enum_ctx = (rhp_ui_http_global_cfg_enum_ctx*)ctx;

	if( !xmlStrcmp(node->name,(xmlChar*)"admin_services") ){

	  err = rhp_xml_enum_tags(node,(xmlChar*)"admin_service",_rhp_ui_http_cfg_update_global_admin_service_parse,enum_ctx,1);
	  if( err == -ENOENT ){
	  	err = 0;
	  }else if( err ){
	  	RHP_LOG_E(RHP_LOG_SRC_UI,0,RHP_LOG_ID_PARSE_GLOBAL_CFG_ERR,"sE","&ltadmin_service&gt",err);
	  	RHP_BUG("%d",err);
	  	goto error;
	  }

	}else if( !xmlStrcmp(node->name,(xmlChar*)"peer_acls") ){

	  err = rhp_xml_enum_tags(node,(xmlChar*)"peer_acl",_rhp_ui_http_cfg_update_global_peer_acl_parse,enum_ctx,1);
	  if( err == -ENOENT ){
	  	err = 0;
	  }else if( err ){
	  	RHP_LOG_E(RHP_LOG_SRC_UI,0,RHP_LOG_ID_PARSE_GLOBAL_CFG_ERR,"sE","&ltpeer_acl&gt",err);
	  	RHP_BUG("%d",err);
	  	goto error;
	  }

	}else if( !xmlStrcmp(node->name,(xmlChar*)"firewall") ){

	  err = rhp_xml_enum_tags(node,(xmlChar*)"firewall_rule",_rhp_ui_http_cfg_update_global_firewall_parse,enum_ctx,1);
	  if( err == -ENOENT ){
	  	err = 0;
	  }else if( err ){
	  	RHP_LOG_E(RHP_LOG_SRC_UI,0,RHP_LOG_ID_PARSE_GLOBAL_CFG_ERR,"sE","&ltfirewall&gt",err);
	  	RHP_BUG("%d",err);
	  	goto error;
	  }

	}else if( !xmlStrcmp(node->name,(xmlChar*)"ikev2_hash_url") ){

		if( enum_ctx->cfg_hash_url == NULL ){

			enum_ctx->cfg_hash_url = rhp_gcfg_parse_hash_url(node);
			if( enum_ctx->cfg_hash_url == NULL ){
			  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_UPDATE_GLOBAL_NO_HASH_URL,"x",enum_ctx);
			}
		}

	}else if( !xmlStrcmp(node->name,(xmlChar*)"radius") ){

		if( enum_ctx->cfg_eap_radius == NULL ){

			enum_ctx->cfg_eap_radius = rhp_gcfg_alloc_eap_radius();
			if( enum_ctx->cfg_eap_radius == NULL ){
			  RHP_BUG("");
				goto error;
			}

			err = rhp_gcfg_parse_eap_radius(node,enum_ctx->cfg_eap_radius);
			if( err ){
				RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_UPDATE_GLOBAL_NO_RADIUS,"x",enum_ctx);
				rhp_gcfg_free_eap_radius(enum_ctx->cfg_eap_radius);
				enum_ctx->cfg_eap_radius = NULL;
			}
		}

	}else if( !xmlStrcmp(node->name,(xmlChar*)"radius_acct") ){

		if( enum_ctx->cfg_radius_acct == NULL ){

			enum_ctx->cfg_radius_acct = rhp_gcfg_alloc_radius_acct();
			if( enum_ctx->cfg_radius_acct == NULL ){
			  RHP_BUG("");
				goto error;
			}

			err = rhp_gcfg_parse_radius_acct(node,enum_ctx->cfg_radius_acct);
			if( err ){
				RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_UPDATE_GLOBAL_NO_RADIUS_ACCT,"x",enum_ctx);
				rhp_gcfg_free_radius_acct(enum_ctx->cfg_radius_acct);
				enum_ctx->cfg_radius_acct = NULL;
			}
		}

	}else if( !xmlStrcmp(node->name,(xmlChar*)"ikesa_security") ){

		rhp_cfg_ikesa* cfg_ikesa = rhp_cfg_parse_ikesa_security(node);
		if( cfg_ikesa == NULL ){
	  	RHP_LOG_E(RHP_LOG_SRC_UI,0,RHP_LOG_ID_PARSE_GLOBAL_CFG_ERR,"sE","&ltikesa_security&gt",err);
			err = -EINVAL;
			goto error;
		}
		rhp_cfg_free_ikesa_security(cfg_ikesa);

	}else if( !xmlStrcmp(node->name,(xmlChar*)"childsa_security") ){

		rhp_cfg_childsa* cfg_childsa = rhp_cfg_parse_childsa_security(node);
		if( cfg_childsa == NULL ){
	  	RHP_LOG_E(RHP_LOG_SRC_UI,0,RHP_LOG_ID_PARSE_GLOBAL_CFG_ERR,"sE","&ltchildsa_security&gt",err);
			err = -EINVAL;
			goto error;
		}
		rhp_cfg_free_childsa_security(cfg_childsa);

	}else if( !xmlStrcmp(node->name,(xmlChar*)"ikev1_ikesa_security") ){

		rhp_cfg_ikev1_ikesa* cfg_ikesa = rhp_cfg_parse_ikev1_ikesa_security(node);
		if( cfg_ikesa == NULL ){
	  	RHP_LOG_E(RHP_LOG_SRC_UI,0,RHP_LOG_ID_PARSE_GLOBAL_CFG_ERR,"sE","&ltikev1_ikesa_security&gt",err);
			err = -EINVAL;
			goto error;
		}
		rhp_cfg_free_ikev1_ikesa_security(cfg_ikesa);

	}else if( !xmlStrcmp(node->name,(xmlChar*)"ikev1_ipsecsa_security") ){

		rhp_cfg_ikev1_ipsecsa* cfg_childsa = rhp_cfg_parse_ikev1_ipsecsa_security(node);
		if( cfg_childsa == NULL ){
	  	RHP_LOG_E(RHP_LOG_SRC_UI,0,RHP_LOG_ID_PARSE_GLOBAL_CFG_ERR,"sE","&ltikev1_ikesa_security&gt",err);
			err = -EINVAL;
			goto error;
		}
		rhp_cfg_free_ikev1_ipsecsa_security(cfg_childsa);
	}

	return 0;

error:
	return err;
}

static int _rhp_ui_http_cfg_update_global_admin_services_ex_cb(xmlNodePtr node,void* ctx)
{
	int err = -EINVAL;
	unsigned long id;
	int ret_len;
	rhp_cfg_admin_service* cur_cfg_admin_srv = rhp_cfg_admin_services;

	err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"id"),RHP_XML_DT_ULONG,&id,&ret_len,NULL,0);
	if( err ){
		RHP_BUG("");
		return err;
	}

	while( cur_cfg_admin_srv ){

		if( cur_cfg_admin_srv->id == id ){

			if( cur_cfg_admin_srv->root_dir ){

					err = rhp_xml_set_prop(node,(xmlChar*)"root_dir",(xmlChar*)cur_cfg_admin_srv->root_dir);
					if( err ){
						RHP_BUG("");
						return err;
					}
			}

			break;
		}

		cur_cfg_admin_srv = cur_cfg_admin_srv->next;
	}

	return 0;
}

static int _rhp_ui_http_cfg_update_global_admin_services_ex(xmlNodePtr rhp_cfg_node)
{
	int err = -EINVAL;
	xmlNodePtr cur_node;

	cur_node = rhp_xml_get_child(rhp_cfg_node,(xmlChar*)"admin_services");
	if( cur_node == NULL ){
		return 0;
	}

	err = rhp_xml_enum_tags(cur_node,(xmlChar*)"admin_service",
			_rhp_ui_http_cfg_update_global_admin_services_ex_cb,NULL,1);
	if( err && err != -ENOENT ){
		RHP_BUG("%d",err);
		return err;
	}

	return 0;
}

static int _rhp_ui_http_cfg_update_global_cfg(xmlDocPtr doc,xmlNodePtr node,rhp_http_conn* http_conn,
		rhp_http_bus_session* http_bus_sess,rhp_http_request* http_req,void* ctx)
{
  int err = -EINVAL;
	xmlDocPtr cfg_doc = NULL;
	xmlNodePtr cfg_root_node = NULL;
	xmlNodePtr rhp_cfg_node = NULL;
	rhp_ui_http_global_cfg_enum_ctx enum_ctx;
	unsigned long rlm_id_r = RHP_VPN_REALM_ID_UNKNOWN;
	int i;

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_UPDATE_GLOBAL_CFG,"xxxxxx",doc,node,http_conn,http_bus_sess,http_req,ctx);

  if( doc == NULL || node == NULL ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_UPDATE_GLOBAL_CFG_NO_DOC_NODE,"xxxxx",http_conn,http_bus_sess,http_req,doc,node);
    return -EINVAL;
  }

  rhp_cfg_node = rhp_xml_get_child(node,(xmlChar*)"rhp_config");
  if( rhp_cfg_node == NULL ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_UPDATE_GLOBAL_CFG_NO_TOP_ELM,"xxx",http_conn,http_bus_sess,http_req);
    goto error;
  }

  err = _rhp_ui_http_get_user_realm_id(http_conn,http_bus_sess,&rlm_id_r);
  if( err ){
			RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_UPDATE_GLOBAL_CFG_NOT_PEMITTED,"xxxuu",http_conn,http_bus_sess,http_req,http_conn->user_realm_id,http_bus_sess->user_realm_id);
			goto error;
	}

  if( rlm_id_r != 0 ){
  	err = -EPERM;
		RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_UPDATE_GLOBAL_CFG_NOT_PEMITTED2,"xxxuu",http_conn,http_bus_sess,http_req,http_conn->user_realm_id,http_bus_sess->user_realm_id);
		goto error;
  }

  memset(&enum_ctx,0,sizeof(rhp_ui_http_global_cfg_enum_ctx));


  err = rhp_xml_enum_tags(rhp_cfg_node,NULL,_rhp_ui_http_cfg_update_global_cfg_parse,&enum_ctx,1);
  if( err == -ENOENT || err == -EINVAL ){
  	err = RHP_STATUS_INVALID_MSG;
  	goto error;
  }else if( err ){
  	RHP_BUG("%d",err);
  	goto error;
  }


	// Web Management Service's ACLs for active listening socket.
	{
		rhp_cfg_admin_service* new_cfg_admin_srv = enum_ctx.cfg_admin_srvs_head;

		while( new_cfg_admin_srv ){

			rhp_http_listen* listen_sk = rhp_cfg_admin_services_listen_sks;
			while( listen_sk ){

				if( listen_sk->id == new_cfg_admin_srv->id ){

						RHP_LOCK(&(listen_sk->lock));
						{
								err = rhp_http_server_set_client_acls(listen_sk,new_cfg_admin_srv->client_acls);
								if( err ){

									RHP_BUG("%d",err);

									RHP_UNLOCK(&(listen_sk->lock));
									goto error;
								}
						}
						RHP_UNLOCK(&(listen_sk->lock));

						break;
				}

				listen_sk = listen_sk->cfg_next;
			}

			new_cfg_admin_srv = new_cfg_admin_srv->next;
		}
	}


	RHP_LOCK(&rhp_cfg_lock);
  {

		// Web Management Service's ACLs
		//
		// rhp_cfg_admin_services is NOT dynamically updated. Restarting service is required.
		// Only client's ACLs are updated here.
		//
  	{
			rhp_cfg_admin_service* new_cfg_admin_srv = enum_ctx.cfg_admin_srvs_head;
			rhp_cfg_admin_service* cur_cfg_admin_srv = rhp_cfg_admin_services; // TODO: currently only one service exists!

			//
			// TODO : Multiple admin_services/listen sockets support.
			//

			while( new_cfg_admin_srv ){

				if( new_cfg_admin_srv->id == cur_cfg_admin_srv->id ){

					if( new_cfg_admin_srv->protocol == RHP_CFG_ADMIN_SERVICE_PROTO_HTTP ){

						RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_UPDATE_GLOBAL_CFG_NOBODY_CFG,"xxdddd",http_conn,http_bus_sess,rhp_gcfg_webmng_allow_nobody_admin,new_cfg_admin_srv->nobody_allowed_tmp,rhp_gcfg_webmng_auto_reconnect_nobody_admin,new_cfg_admin_srv->nobody_auto_reconnect_tmp);

						if( (rhp_gcfg_webmng_allow_nobody_admin != new_cfg_admin_srv->nobody_allowed_tmp) ||
								(rhp_gcfg_webmng_auto_reconnect_nobody_admin != new_cfg_admin_srv->nobody_auto_reconnect_tmp) ){
				  		RHP_LOG_D(RHP_LOG_SRC_UI,0,RHP_LOG_ID_ADMIN_NOBODY_USER_CFG_UPDATED,"ddd",rhp_gcfg_webmng_allow_nobody_admin,new_cfg_admin_srv->nobody_allowed_tmp,new_cfg_admin_srv->nobody_auto_reconnect_tmp);
						}

						rhp_gcfg_webmng_allow_nobody_admin = new_cfg_admin_srv->nobody_allowed_tmp;
						rhp_gcfg_webmng_auto_reconnect_nobody_admin = new_cfg_admin_srv->nobody_auto_reconnect_tmp;
					}


					rhp_cfg_free_peer_acls(cur_cfg_admin_srv->client_acls);

					cur_cfg_admin_srv->client_acls = new_cfg_admin_srv->client_acls;
					new_cfg_admin_srv->client_acls = NULL;

					break;
				}

				new_cfg_admin_srv = new_cfg_admin_srv->next;
			}
  	}


  	// Peer's ACLs
  	{
  		rhp_cfg_free_peer_acls(rhp_cfg_peer_acl_list);

  		rhp_cfg_peer_acl_list = enum_ctx.cfg_peer_acls_head;
  		enum_ctx.cfg_peer_acls_head = NULL;
  	}


  	// iptables rules
  	{
  		rhp_cfg_free_firewall_rules(rhp_cfg_firewall_rules);

  		rhp_cfg_firewall_rules = enum_ctx.cfg_firewall_rules_head;
  		enum_ctx.cfg_firewall_rules_head = NULL;

  		err = rhp_cfg_apply_firewall_rules(rhp_cfg_firewall_rules,rhp_cfg_admin_services);
  		if( err ){
  			RHP_BUG("%d",err);
  		}
  	}
  }
  RHP_UNLOCK(&rhp_cfg_lock);


  if( enum_ctx.cfg_hash_url ){

  	RHP_LOCK(&rhp_gcfg_hash_url_lock);

		if( rhp_global_cfg_hash_url ){
			rhp_gcfg_free_hash_url(rhp_global_cfg_hash_url);
		}

		rhp_global_cfg_hash_url = enum_ctx.cfg_hash_url;

		RHP_UNLOCK(&rhp_gcfg_hash_url_lock);
  }


  if( enum_ctx.cfg_eap_radius ){

  	RHP_LOCK(&rhp_eap_radius_cfg_lock);

		if( rhp_gcfg_eap_radius ){
			rhp_gcfg_free_eap_radius(rhp_gcfg_eap_radius);
		}

		rhp_gcfg_eap_radius = enum_ctx.cfg_eap_radius;

		RHP_UNLOCK(&rhp_eap_radius_cfg_lock);
  }

  if( enum_ctx.cfg_radius_acct ){

  	RHP_LOCK(&rhp_eap_radius_cfg_lock);

		if( rhp_gcfg_radius_acct ){
			rhp_gcfg_free_radius_acct(rhp_gcfg_radius_acct);
		}

		rhp_gcfg_radius_acct = enum_ctx.cfg_radius_acct;

		RHP_UNLOCK(&rhp_eap_radius_cfg_lock);
  }


  {
		cfg_doc = xmlParseFile(rhp_main_conf_path);
		if( cfg_doc == NULL ){
			RHP_BUG(" %s ",rhp_main_conf_path);
			err = -ENOENT;
			goto error;
		}

		cfg_root_node = xmlDocGetRootElement(cfg_doc);
		if( cfg_root_node == NULL ){
			RHP_BUG(" %s ",rhp_main_conf_path);
			err = -ENOENT;
			goto error;
		}

		rhp_xml_delete_child(cfg_root_node,(xmlChar*)"vpn");
		rhp_xml_delete_child(cfg_root_node,(xmlChar*)"ikesa");
		rhp_xml_delete_child(cfg_root_node,(xmlChar*)"childsa");

		{
			for( i = 0; ; i++ ){

				if( rhp_gcfg_vpn_params[i].type < 0 ){
					break;
				}

				err = rhp_xml_prop_update_in_children(cfg_root_node,rhp_cfg_node,(xmlChar*)"vpn",(xmlChar*)rhp_gcfg_vpn_params[i].val_name);
				if( err ){
					RHP_BUG("%d",err);
					goto error;
				}
			}
		}

		{
			for( i = 0; ; i++ ){

				if( rhp_gcfg_ikesa_params[i].type < 0 ){
					break;
				}

				err = rhp_xml_prop_update_in_children(cfg_root_node,rhp_cfg_node,(xmlChar*)"ikesa",(xmlChar*)rhp_gcfg_ikesa_params[i].val_name);
				if( err ){
					RHP_BUG("%d",err);
					goto error;
				}
			}
		}

		{
			for( i = 0; ; i++ ){

				if( rhp_gcfg_childsa_params[i].type < 0 ){
					break;
				}

				err = rhp_xml_prop_update_in_children(cfg_root_node,rhp_cfg_node,(xmlChar*)"childsa",(xmlChar*)rhp_gcfg_childsa_params[i].val_name);
				if( err ){
					RHP_BUG("%d",err);
					goto error;
				}
			}
		}

		{
			err = _rhp_ui_http_cfg_update_global_admin_services_ex(rhp_cfg_node);
			if( err ){
				RHP_BUG("%d",err);
				goto error;
			}

			err = rhp_xml_replace_child(cfg_root_node,rhp_cfg_node,(xmlChar*)"admin_services",0);
			if( err ){
				RHP_BUG("%d",err);
				goto error;
			}
		}

		{
			err = rhp_xml_replace_child(cfg_root_node,rhp_cfg_node,(xmlChar*)"peer_acls",1);
			if( err ){
				RHP_BUG("%d",err);
				goto error;
			}

			err = rhp_xml_replace_child(cfg_root_node,rhp_cfg_node,(xmlChar*)"firewall",1);
			if( err ){
				RHP_BUG("%d",err);
				goto error;
			}

			err = rhp_xml_replace_child(cfg_root_node,rhp_cfg_node,(xmlChar*)"ikev2_hash_url",1);
			if( err ){
				RHP_BUG("%d",err);
				goto error;
			}

			err = rhp_xml_replace_child(cfg_root_node,rhp_cfg_node,(xmlChar*)"radius",1);
			if( err ){
				RHP_BUG("%d",err);
				goto error;
			}

			err = rhp_xml_replace_child(cfg_root_node,rhp_cfg_node,(xmlChar*)"radius_acct",1);
			if( err ){
				RHP_BUG("%d",err);
				goto error;
			}

			err = rhp_xml_replace_child(cfg_root_node,rhp_cfg_node,(xmlChar*)"ikesa_security",1);
			if( err ){
				RHP_BUG("%d",err);
				goto error;
			}

			err = rhp_xml_replace_child(cfg_root_node,rhp_cfg_node,(xmlChar*)"childsa_security",1);
			if( err ){
				RHP_BUG("%d",err);
				goto error;
			}

			err = rhp_xml_replace_child(cfg_root_node,rhp_cfg_node,(xmlChar*)"ikev1_ikesa_security",1);
			if( err ){
				RHP_BUG("%d",err);
				goto error;
			}

			err = rhp_xml_replace_child(cfg_root_node,rhp_cfg_node,(xmlChar*)"ikev1_ipsecsa_security",1);
			if( err ){
				RHP_BUG("%d",err);
				goto error;
			}
		}

		err = rhp_cfg_save_config(rhp_main_conf_path,cfg_doc);
		if( err ){
			RHP_BUG("%d",err);
		}
  }

  err = rhp_http_bus_send_response(http_conn,http_bus_sess,NULL,NULL);
  if( err ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_UPDATE_GLOBAL_CFG_TX_RESP_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
    goto error;
  }

	RHP_LOG_I(RHP_LOG_SRC_UI,0,RHP_LOG_ID_UPDATE_GLOBAL_CFG,"");

  if( cfg_doc ){
	  xmlFreeDoc(cfg_doc);
  }

  if( enum_ctx.cfg_admin_srvs_head ){
  	rhp_cfg_free_admin_services(enum_ctx.cfg_admin_srvs_head);
  }

  if( enum_ctx.cfg_peer_acls_head ){
  	rhp_cfg_free_peer_acls(enum_ctx.cfg_peer_acls_head);
  }

  if( enum_ctx.cfg_firewall_rules_head ){
  	rhp_cfg_free_firewall_rules(enum_ctx.cfg_firewall_rules_head);
  }


  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_UPDATE_GLOBAL_CFG_RTRN,"xxx",http_conn,http_bus_sess,http_req);
  return RHP_STATUS_CLOSE_HTTP_CONN;


error:
	RHP_LOG_E(RHP_LOG_SRC_UI,0,RHP_LOG_ID_UPDATE_GLOBAL_CFG_ERR,"E",err);
	if( cfg_doc ){
		xmlFreeDoc(cfg_doc);
	}
  if( enum_ctx.cfg_admin_srvs_head ){
  	rhp_cfg_free_admin_services(enum_ctx.cfg_admin_srvs_head);
  }

  if( enum_ctx.cfg_peer_acls_head ){
  	rhp_cfg_free_peer_acls(enum_ctx.cfg_peer_acls_head);
  }

  if( enum_ctx.cfg_firewall_rules_head ){
  	rhp_cfg_free_firewall_rules(enum_ctx.cfg_firewall_rules_head);
  }

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_UPDATE_GLOBAL_CFG_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  return err;
}


static int _rhp_ui_http_cfg_forward_auth_realm_config_serialize(rhp_http_bus_session* http_bus_sess,
		void* ctx,void* writer,int idx)
{
  int err = -EINVAL;
  int n = 0;
  int n2 = 0;
	rhp_ipcmsg_syspxy_cfg_sub* cfg_sub_dt = (rhp_ipcmsg_syspxy_cfg_sub*)ctx;
  rhp_ui_http_enum_ctx enum_ctx;
  xmlDocPtr auth_doc = NULL;
  xmlNodePtr auth_root_node = NULL;
  int sub_dt_xml_len = 0;

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_FORWARD_AUTH_REALM_CONFIG_SERIALIZE,"xuxd",http_bus_sess,cfg_sub_dt->target_rlm_id,writer,idx);


  sub_dt_xml_len = cfg_sub_dt->len - sizeof(rhp_ipcmsg_syspxy_cfg_sub);

  if( sub_dt_xml_len <= 0  ){
  	goto end;
  }

  auth_doc = xmlParseMemory((void*)(cfg_sub_dt + 1),sub_dt_xml_len);
	if( auth_doc == NULL ){
		err = -EINVAL;
		RHP_BUG("");
		goto error;
	}

	auth_root_node = xmlDocGetRootElement(auth_doc);
	if( auth_root_node == NULL ){
		xmlFreeDoc(auth_doc);
		RHP_BUG("");
		auth_doc = NULL;
	}

	n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"rhp_http_bus_record");
	if(n < 0) {
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"index","%d",idx);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"service",(xmlChar*)"ui_http_vpn");
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	if( cfg_sub_dt->priv[0] ){

		n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"action",(xmlChar*)cfg_sub_dt->priv[0]);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		n2 += n;
	}

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"session_id","%llu",http_bus_sess->session_id);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  err = rhp_xml_enum_tags(auth_root_node,NULL,_rhp_ui_http_cfg_get_enum_auth_xml,(void*)&enum_ctx,1);
  if( err && err != -ENOENT ){
    RHP_BUG(" %s ",rhp_main_conf_path);
    goto error;
  }
  err = 0;


	n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
	if(n < 0) {
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;


	xmlFreeDoc(auth_doc);

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_FORWARD_AUTH_REALM_CONFIG_SERIALIZE_RTRN,"xd",http_bus_sess,n2);
  return n2;

error:
	if( auth_doc ){
		xmlFreeDoc(auth_doc);
	}
  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_FORWARD_AUTH_REALM_CONFIG_SERIALIZE_ERR,"xE",http_bus_sess,err);
  return err;

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_FORWARD_AUTH_REALM_CONFIG_SERIALIZE_NO_DATA,"xE",http_bus_sess,err);
end:
	return 0;
}

static int _rhp_ui_http_cfg_forward_auth_realm_config_bh(xmlDocPtr doc,xmlNodePtr node,rhp_http_conn* http_conn,
		rhp_http_bus_session* http_bus_sess,rhp_http_request* http_req,int data_len,u8* data,void* ipc_bus_cb_ctx)
{
  int err = -EINVAL;
  char* action_str = (char*)ipc_bus_cb_ctx;
	rhp_ipcmsg_syspxy_cfg_sub* cfg_sub_dt = (rhp_ipcmsg_syspxy_cfg_sub*)data;
	int tx_cfg_update = 0;

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_FORWARD_AUTH_REALM_CONFIG_BH,"xxxxxpxs",doc,node,http_conn,http_bus_sess,http_req,data_len,data,ipc_bus_cb_ctx,(char*)ipc_bus_cb_ctx);

	if( data_len < (int)sizeof(rhp_ipcmsg_syspxy_cfg_sub) && (int)cfg_sub_dt->len != data_len ){
		err = -EINVAL;
		RHP_BUG("%d, %d, %d",cfg_sub_dt->len,data_len,sizeof(rhp_ipcmsg_syspxy_cfg_sub));
		goto error;
	}

	if( !cfg_sub_dt->result ){
		err = -EPERM;
	  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_FORWARD_AUTH_REALM_CONFIG_BH_RESULT_FAILED,"xxxxx",doc,node,http_conn,http_bus_sess,http_req);
		goto error;
	}

	//
	// Actually, the following code never works. See rhp_syspxy_ui_ipc_handle() [rhp_ui_syspxy.c].
	//
	if( cfg_sub_dt->target_rlm_id && cfg_sub_dt->config_updated ){

		time_t created_time = -1, updated_time = -1, sess_resume_policy_index = -1;

		if( !_rhp_ui_http_cfg_update_realm_time_lock(cfg_sub_dt->target_rlm_id,
					&created_time,&updated_time,&sess_resume_policy_index,0) ){

			if( _rhp_ui_http_cfg_doc_update_realm_time(cfg_sub_dt->target_rlm_id,
						created_time,updated_time,sess_resume_policy_index,0) ){
				RHP_BUG("%d",cfg_sub_dt->target_rlm_id);
			}

		}else{
			RHP_BUG("%d",cfg_sub_dt->target_rlm_id);
		}

		tx_cfg_update = 1;
	}


	cfg_sub_dt->priv[0] = (unsigned long)action_str;
  err = rhp_http_bus_send_response(http_conn,http_bus_sess,
  				_rhp_ui_http_cfg_forward_auth_realm_config_serialize,cfg_sub_dt);
  if( err ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_FORWARD_AUTH_REALM_CONFIG_BH_TX_RESP_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
    goto error;
  }

	//
	// Actually, the following code never works. See rhp_syspxy_ui_ipc_handle() [rhp_ui_syspxy.c].
  // tx_cfg_update is always zero. See above.
	//
  if( tx_cfg_update ){

  	rhp_http_bus_broadcast_async(cfg_sub_dt->target_rlm_id,1,1,
			_rhp_ui_http_cfg_update_realm_serialize,NULL,(void*)cfg_sub_dt->target_rlm_id);
  }


  if( action_str ){
  	_rhp_free(action_str);
  }
  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_FORWARD_AUTH_REALM_CONFIG_BH_RTRN,"xxxxx",doc,node,http_conn,http_bus_sess,http_req);
  return RHP_STATUS_CLOSE_HTTP_CONN;

error:
	RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_FORWARD_AUTH_REALM_CONFIG_BH_ERR,"xxxxxE",doc,node,http_conn,http_bus_sess,http_req,err);
	return err;
}

static int _rhp_ui_http_cfg_forward_auth_realm_config(xmlDocPtr doc,xmlNodePtr req_root_node,rhp_http_conn* http_conn,
		rhp_http_bus_session* http_bus_sess,rhp_http_request* http_req,
		void* ctx,char* action_str,char* fwd_root_node_name,int opr_sub_type)
{
  int err = -EINVAL;
  xmlChar* vpn_realm_str = NULL;
  unsigned long rlm_id = RHP_VPN_REALM_ID_UNKNOWN;
  char* endp;
  xmlTextWriterPtr writer = NULL;
  xmlBufferPtr buf = NULL;
	rhp_ipcmsg_syspxy_cfg_sub* cfg_sub_dt = NULL;
	int cfg_sub_dt_len = 0;
	char* action_str_ctx = NULL;

	RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_FORWARD_AUTH_REALM_CONFIG,"xxxxxxssd",doc,req_root_node,http_conn,http_bus_sess,http_req,ctx,action_str,fwd_root_node_name,opr_sub_type);

  if( doc == NULL || req_root_node == NULL ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_FORWARD_AUTH_REALM_CONFIG_NO_DOC_NODE,"xxxxx",http_conn,http_bus_sess,http_req,doc,req_root_node);
    return -EINVAL;
  }

  vpn_realm_str = rhp_xml_get_prop(req_root_node,(const xmlChar*)"vpn_realm");
  if( vpn_realm_str ){

		rlm_id = strtoul((char*)vpn_realm_str,&endp,0);
		if( (rlm_id == ULONG_MAX && errno == ERANGE) || *endp != '\0' ){
			err = -ENOENT;
			RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_FORWARD_AUTH_REALM_CONFIG_NO_VPN_REALM_2,"xxxs",http_conn,http_bus_sess,http_req,vpn_realm_str);
			goto error;
		}

		if( _rhp_ui_http_permitted(http_conn,http_bus_sess,rlm_id) ){
				err = -EPERM;
				RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_FORWARD_AUTH_REALM_CONFIG_NOT_PERMITTED,"xxxuu",http_conn,http_bus_sess,http_req,http_conn->user_realm_id,http_bus_sess->user_realm_id);
				goto error;
		}

  }else{

  	err = _rhp_ui_http_get_user_realm_id(http_conn,http_bus_sess,&rlm_id);
  	if( err ){
  		RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_FORWARD_AUTH_REALM_CONFIG_NOT_PERMITTED2,"xxxuu",http_conn,http_bus_sess,http_req,http_conn->user_realm_id,http_bus_sess->user_realm_id);
			goto error;
  	}
  }

  if( rlm_id ){

		if( rlm_id > RHP_VPN_REALM_ID_MAX ){

			err = -EPERM;
			goto error;

		}else{

			rhp_vpn_realm* rlm = rhp_realm_get(rlm_id);
			if( rlm == NULL ){
				err = -ENOENT;
				goto error;
			}
			rhp_realm_unhold(rlm);
		}
  }

  action_str_ctx = (char*)_rhp_malloc(strlen(action_str) + 1);
  if( action_str_ctx == NULL ){
  	err = -ENOMEM;
  	RHP_BUG("");
  	goto error;
  }
  action_str_ctx[0] = '\0';
  strcpy(action_str_ctx,action_str);


  if( fwd_root_node_name ){

  	xmlNodePtr auth_key_node;
		int n = 0;
  	int n2 = 0;

  	auth_key_node = rhp_xml_get_child(req_root_node,(xmlChar*)fwd_root_node_name);

  	if( auth_key_node == NULL ){
  		RHP_BUG("");
  		err = -ENOENT;
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

			err = rhp_xml_write_node(auth_key_node,writer,&n,1,NULL,NULL,NULL);
			if( err ){
				RHP_BUG("%d",err);
				goto error;
			}

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
		}

		cfg_sub_dt_len = xmlStrlen(buf->content) + 1 + sizeof(rhp_ipcmsg_syspxy_cfg_sub);

		cfg_sub_dt = (rhp_ipcmsg_syspxy_cfg_sub*)_rhp_malloc(cfg_sub_dt_len);
		if( cfg_sub_dt == NULL ){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}

		cfg_sub_dt->cfg_type = opr_sub_type;
		cfg_sub_dt->len = cfg_sub_dt_len;
	  if( vpn_realm_str ){
	  	cfg_sub_dt->target_rlm_id = rlm_id;
	  }else{
	  	cfg_sub_dt->target_rlm_id = rlm_id;
	  }
		memcpy((cfg_sub_dt + 1),buf->content,cfg_sub_dt_len - sizeof(rhp_ipcmsg_syspxy_cfg_sub));

		err = rhp_http_bus_ipc_cfg_request(http_conn,http_bus_sess,
				cfg_sub_dt_len,(u8*)cfg_sub_dt,_rhp_ui_http_cfg_forward_auth_realm_config_bh,action_str_ctx);

		if( err ){
			RHP_BUG("");
			goto error;
		}

	  xmlBufferFree(buf);
	  buf = NULL;

	  _rhp_free_zero(cfg_sub_dt,cfg_sub_dt_len);

  }else{

  	cfg_sub_dt_len = sizeof(rhp_ipcmsg_syspxy_cfg_sub);
		cfg_sub_dt = (rhp_ipcmsg_syspxy_cfg_sub*)_rhp_malloc(cfg_sub_dt_len);
		if( cfg_sub_dt == NULL ){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}

		cfg_sub_dt->cfg_type = opr_sub_type;
		cfg_sub_dt->len = cfg_sub_dt_len;
	  if( vpn_realm_str ){
	  	cfg_sub_dt->target_rlm_id = rlm_id;
	  }else{
	  	cfg_sub_dt->target_rlm_id = rlm_id;
	  }

		err = rhp_http_bus_ipc_cfg_request(http_conn,http_bus_sess,
				cfg_sub_dt_len,(u8*)cfg_sub_dt,_rhp_ui_http_cfg_forward_auth_realm_config_bh,action_str_ctx);

		if( err ){
			RHP_BUG("");
			goto error;
		}

	  _rhp_free_zero(cfg_sub_dt,cfg_sub_dt_len);
  }

  if( vpn_realm_str ){
  	_rhp_free(vpn_realm_str);
  }

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_FORWARD_AUTH_REALM_CONFIG_PENDING_RTRN,"xxxsx",http_conn,http_bus_sess,http_req,vpn_realm_str,cfg_sub_dt);
  return RHP_STATUS_HTTP_REQ_PENDING;

error:
	if( writer ){
		xmlFreeTextWriter(writer);
	}
	if( buf ){
		xmlBufferFree(buf);
	}
	if( cfg_sub_dt ){
		_rhp_free_zero(cfg_sub_dt,cfg_sub_dt_len);
	}
	if( action_str_ctx ){
		_rhp_free(action_str_ctx);
	}
  if( vpn_realm_str ){
  	_rhp_free(vpn_realm_str);
  }
  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_FORWARD_AUTH_REALM_CONFIG_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  return err;
}

static int _rhp_ui_http_flush_bridge(xmlDocPtr doc,xmlNodePtr node,rhp_http_conn* http_conn,
		rhp_http_bus_session* http_bus_sess,rhp_http_request* http_req,void* ctx)
{
  int err = -EINVAL;
  char* vpn_realm_str = NULL;
  unsigned long rlm_id;
  char* endp;

  RHP_TRC(0,RHPTRCID_UI_HTTP_FLUSH_BRIDGE,"xxxxxx",doc,node,http_conn,http_bus_sess,http_req,ctx);

  if( doc == NULL || node == NULL ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_FLUSH_BRIDGE_NO_DOC_NODE,"xxx",http_conn,http_bus_sess,http_req);
    return -EINVAL;
  }

  vpn_realm_str = (char*)rhp_xml_get_prop(node,(const xmlChar*)"vpn_realm");
  if( vpn_realm_str == NULL ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_UI_HTTP_FLUSH_BRIDGE_NO_VPN_REALM,"xxx",http_conn,http_bus_sess,http_req);
    goto error;
  }

  rlm_id = strtoul((char*)vpn_realm_str,&endp,0);
  if( (rlm_id == ULONG_MAX && errno == ERANGE) || *endp != '\0' ){
  	err = -ENOENT;
  	RHP_TRC(0,RHPTRCID_UI_HTTP_FLUSH_BRIDGE_NO_VPN_REALM_2,"xxxs",http_conn,http_bus_sess,http_req,vpn_realm_str);
  	goto error;
  }

  if( _rhp_ui_http_permitted(http_conn,http_bus_sess,rlm_id) ){
			err = -EPERM;
			RHP_TRC(0,RHPTRCID_UI_HTTP_FLUSH_BRIDGE_NOT_PERMITTED,"xxxuu",http_conn,http_bus_sess,http_req,http_conn->user_realm_id,http_bus_sess->user_realm_id);
			goto error;
	}

  if( rlm_id != 0 ){

  	rhp_vpn_realm* rlm = rhp_realm_get(rlm_id);
  	if( rlm == NULL ){
  		err = -ENOENT;
  		goto error;
  	}

  	rhp_realm_unhold(rlm);
  }


  rhp_bridge_cache_flush(NULL,rlm_id);


  err = rhp_http_bus_send_response(http_conn,http_bus_sess,NULL,NULL);
  if( err ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_FLUSH_BRIDGE_TX_RESP_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
    goto error;
  }

  if( vpn_realm_str ){
  	_rhp_free(vpn_realm_str);
  }

  RHP_TRC(0,RHPTRCID_UI_HTTP_FLUSH_BRIDGE_RTRN,"xxxs",http_conn,http_bus_sess,http_req,vpn_realm_str);
  return RHP_STATUS_CLOSE_HTTP_CONN;

error:
	if( vpn_realm_str ){
		_rhp_free(vpn_realm_str);
	}
  RHP_TRC(0,RHPTRCID_UI_HTTP_FLUSH_BRIDGE_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  return err;
}


static int _rhp_ui_http_flush_address_pool(xmlDocPtr doc,xmlNodePtr node,rhp_http_conn* http_conn,
		rhp_http_bus_session* http_bus_sess,rhp_http_request* http_req,void* ctx)
{
  int err = -EINVAL;
  char* vpn_realm_str = NULL;
  unsigned long rlm_id;
  char* endp;

  RHP_TRC(0,RHPTRCID_UI_HTTP_FLUSH_ADDRESS_POOL,"xxxxxx",doc,node,http_conn,http_bus_sess,http_req,ctx);

  if( doc == NULL || node == NULL ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_FLUSH_ADDRESS_POOL_NO_DOC_NODE,"xxx",http_conn,http_bus_sess,http_req);
    return -EINVAL;
  }

  vpn_realm_str = (char*)rhp_xml_get_prop(node,(const xmlChar*)"vpn_realm");
  if( vpn_realm_str == NULL ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_UI_HTTP_FLUSH_ADDRESS_POOL_NO_VPN_REALM,"xxx",http_conn,http_bus_sess,http_req);
    goto error;
  }

  rlm_id = strtoul((char*)vpn_realm_str,&endp,0);
  if( (rlm_id == ULONG_MAX && errno == ERANGE) || *endp != '\0' ){
  	err = -ENOENT;
  	RHP_TRC(0,RHPTRCID_UI_HTTP_FLUSH_ADDRESS_POOL_NO_VPN_REALM_2,"xxxs",http_conn,http_bus_sess,http_req,vpn_realm_str);
  	goto error;
  }

  if( _rhp_ui_http_permitted(http_conn,http_bus_sess,rlm_id) ){
			err = -EPERM;
			RHP_TRC(0,RHPTRCID_UI_HTTP_FLUSH_ADDRESS_POOL_NOT_PERMITTED,"xxxuu",http_conn,http_bus_sess,http_req,http_conn->user_realm_id,http_bus_sess->user_realm_id);
			goto error;
	}

  if( rlm_id != 0 ){

  	rhp_vpn_realm* rlm = rhp_realm_get(rlm_id);
  	if( rlm == NULL ){
  		err = -ENOENT;
  		goto error;
  	}

  	rhp_realm_unhold(rlm);
  }


  rhp_vpn_internal_address_clear_cache(rlm_id);


  err = rhp_http_bus_send_response(http_conn,http_bus_sess,NULL,NULL);
  if( err ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_FLUSH_ADDRESS_POOL_TX_RESP_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
    goto error;
  }

  if( vpn_realm_str ){
  	_rhp_free(vpn_realm_str);
  }

  RHP_TRC(0,RHPTRCID_UI_HTTP_FLUSH_ADDRESS_POOL_RTRN,"xxxs",http_conn,http_bus_sess,http_req,vpn_realm_str);
  return RHP_STATUS_CLOSE_HTTP_CONN;

error:
	if( vpn_realm_str ){
		_rhp_free(vpn_realm_str);
	}
  RHP_TRC(0,RHPTRCID_UI_HTTP_FLUSH_ADDRESS_POOL_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  return err;
}


static int _rhp_ui_http_flush_ip_route_cache(xmlDocPtr doc,xmlNodePtr node,rhp_http_conn* http_conn,
		rhp_http_bus_session* http_bus_sess,rhp_http_request* http_req,void* ctx)
{
  int err = -EINVAL;
  unsigned long user_rlm_id = RHP_VPN_REALM_ID_UNKNOWN;

  RHP_TRC(0,RHPTRCID_UI_HTTP_FLUSH_IP_ROUTE_CACHE,"xxxxxx",doc,node,http_conn,http_bus_sess,http_req,ctx);

  if( doc == NULL || node == NULL ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_FLUSH_IP_ROUTE_CACHE_NO_DOC_NODE,"xxx",http_conn,http_bus_sess,http_req);
    return -EINVAL;
  }


  if( _rhp_ui_http_get_user_realm_id(http_conn,http_bus_sess,&user_rlm_id) || user_rlm_id != 0 ){
  	err = -EPERM;
  	RHP_TRC(0,RHPTRCID_UI_HTTP_FLUSH_IP_ROUTE_CACHE_NOT_PERMITTED,"xxxuu",http_conn,http_bus_sess,http_req,http_conn->user_realm_id,user_rlm_id);
		goto error;
  }


  rhp_ip_routing_cache_flush(AF_INET);

  rhp_ip_routing_cache_flush(AF_INET6);


  err = rhp_http_bus_send_response(http_conn,http_bus_sess,NULL,NULL);
  if( err ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_FLUSH_IP_ROUTE_CACHE_TX_RESP_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
    goto error;
  }

  RHP_TRC(0,RHPTRCID_UI_HTTP_FLUSH_IP_ROUTE_CACHE_RTRN,"xxx",http_conn,http_bus_sess,http_req);
  return RHP_STATUS_CLOSE_HTTP_CONN;

error:
  RHP_TRC(0,RHPTRCID_UI_HTTP_FLUSH_IP_ROUTE_CACHE_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  return err;
}


static int _rhp_ui_http_tx_dmy_packet(xmlDocPtr doc,xmlNodePtr node,rhp_http_conn* http_conn,
		rhp_http_bus_session* http_bus_sess,rhp_http_request* http_req,void* ctx)
{
  int err = -EINVAL;
  char* vpn_realm_str = NULL;
  unsigned long rlm_id;
  char* endp;

  RHP_TRC(0,RHPTRCID_UI_HTTP_TX_DMY_PACKET,"xxxxxx",doc,node,http_conn,http_bus_sess,http_req,ctx);

  if( doc == NULL || node == NULL ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_TX_DMY_PACKET_NO_DOC_NODE,"xxx",http_conn,http_bus_sess,http_req);
    return -EINVAL;
  }

  if( http_conn->user_realm_id != 0 ){
			err = -EPERM;
			RHP_TRC(0,RHPTRCID_UI_HTTP_TX_DMY_PACKET_NOT_PERMITTED,"xxxuu",http_conn,http_bus_sess,http_req,http_conn->user_realm_id,http_bus_sess->user_realm_id);
			goto error;
	}

  vpn_realm_str = (char*)rhp_xml_get_prop(node,(const xmlChar*)"vpn_realm");
  if( vpn_realm_str == NULL ){
    err = RHP_STATUS_INVALID_MSG;
    RHP_TRC(0,RHPTRCID_UI_HTTP_TX_DMY_PACKET_NO_VPN_REALM,"xxx",http_conn,http_bus_sess,http_req);
    goto error;
  }

  rlm_id = strtoul((char*)vpn_realm_str,&endp,0);
  if( (rlm_id == ULONG_MAX && errno == ERANGE) || *endp != '\0' ){
  	err = -ENOENT;
  	RHP_TRC(0,RHPTRCID_UI_HTTP_TX_DMY_PACKET_NO_VPN_REALM_2,"xxxs",http_conn,http_bus_sess,http_req,vpn_realm_str);
  	goto error;
  }

  if( rlm_id ){

  	rhp_vpn_realm* rlm = rhp_realm_get(rlm_id);
  	if( rlm == NULL ){

  	  RHP_TRC(0,RHPTRCID_UI_HTTP_TX_DMY_PACKET_NO_ENT,"xxxxxu",doc,node,http_conn,http_bus_sess,http_req,rlm_id);

  		err = -ENOENT;
  		goto error;
  	}

  	rhp_realm_unhold(rlm);

  }else{

  	err = -EINVAL;
  	goto error;
  }

  {
  	u8 protocol;
  	u8 src_mac[6],dst_mac[6];
  	rhp_ip_addr src_ip_addr,dst_ip_addr;
  	int data_len = 512;
  	u64 esp_tx_seq = 0;
  	char *src_mac_str = NULL,*dst_mac_str = NULL;
  	int ret_len;

  	memset(&src_ip_addr,0,sizeof(rhp_ip_addr));
  	memset(&dst_ip_addr,0,sizeof(rhp_ip_addr));

  	memset(src_mac,0,6);
  	memset(dst_mac,0,6);

  	src_ip_addr.addr_family = AF_INET;
  	dst_ip_addr.addr_family = AF_INET;

    if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(xmlChar*)"protocol"),(xmlChar*)"icmp_echo") ){
    	protocol = RHP_PROTO_IP_ICMP;
    }else if( !rhp_xml_strcasecmp(rhp_xml_get_prop_static(node,(xmlChar*)"protocol"),(xmlChar*)"udp") ){

    	protocol = RHP_PROTO_IP_UDP;

    	src_ip_addr.port = htons(7777);
    	dst_ip_addr.port = htons(8888);

    	rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"src_port"),RHP_XML_DT_PORT,&src_ip_addr.port,&ret_len,NULL,0);
      rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"dst_port"),RHP_XML_DT_PORT,&dst_ip_addr.port,&ret_len,NULL,0);

    }else{
    	RHP_BUG("");
    	goto ignore;
    }

    rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"data_len"),RHP_XML_DT_INT,&data_len,&ret_len,NULL,0);

    rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"esp_tx_seq"),RHP_XML_DT_ULONGLONG,&esp_tx_seq,&ret_len,NULL,0);

    err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"src_ip_addr"),RHP_XML_DT_IPV4,&(src_ip_addr.addr.v4),&ret_len,NULL,0);
    if( err ){
    	RHP_BUG("");
    	goto ignore;
    }

    err = rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"dst_ip_addr"),RHP_XML_DT_IPV4,&(dst_ip_addr.addr.v4),&ret_len,NULL,0);
    if( err ){
    	RHP_BUG("");
    	goto ignore;
    }

    src_mac_str = (char*)rhp_xml_get_prop(node,(const xmlChar*)"src_mac");
    if( src_mac_str ){

    	err = rhp_str_to_mac(src_mac_str,src_mac);
      if( err ){
        _rhp_free(src_mac_str);
      	RHP_BUG("");
      	goto ignore;
      }
      _rhp_free(src_mac_str);
    }

    dst_mac_str = (char*)rhp_xml_get_prop(node,(const xmlChar*)"dst_mac");
    if( dst_mac_str ){

    	err = rhp_str_to_mac(dst_mac_str,dst_mac);
      if( err ){
        _rhp_free(dst_mac_str);
      	RHP_BUG("");
      	goto ignore;
      }
      _rhp_free(dst_mac_str);
    }

    rhp_tuntap_dmy_pkt_read(rlm_id,protocol,src_mac,dst_mac,&src_ip_addr,&dst_ip_addr,data_len,esp_tx_seq);
  }

ignore:
	err = rhp_http_bus_send_response(http_conn,http_bus_sess,NULL,NULL);
  if( err ){
  	goto error;
  }

  if( vpn_realm_str ){
  	_rhp_free(vpn_realm_str);
  }

  RHP_TRC(0,RHPTRCID_UI_HTTP_TX_DMY_PACKET_RTRN,"xxxs",http_conn,http_bus_sess,http_req,vpn_realm_str);
  return RHP_STATUS_CLOSE_HTTP_CONN;

error:
	if( vpn_realm_str ){
		_rhp_free(vpn_realm_str);
	}
  RHP_TRC(0,RHPTRCID_UI_HTTP_TX_DMY_PACKET_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  return err;
}


#ifdef RHP_MEMORY_DBG
static int _rhp_ui_http_memory_dbg(xmlDocPtr doc,xmlNodePtr node,rhp_http_conn* http_conn,
		rhp_http_bus_session* http_bus_sess,rhp_http_request* http_req,void* ctx)
{
  int err = -EINVAL;
  int start_time = 0;
  int elapsing_time = 0;
  int ret_len;

  RHP_TRC(0,RHPTRCID_UI_HTTP_MEMORY_DBG,"xxxxxx",doc,node,http_conn,http_bus_sess,http_req,ctx);

  if( doc == NULL || node == NULL ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_MEMORY_DBG_NO_DOC_NODE,"xxx",http_conn,http_bus_sess,http_req);
    return -EINVAL;
  }

  if( http_conn->user_realm_id != 0 ){
			err = -EPERM;
			RHP_TRC(0,RHPTRCID_UI_HTTP_MEMORY_DBG_NOT_PERMITTED,"xxxuu",http_conn,http_bus_sess,http_req,http_conn->user_realm_id,http_bus_sess->user_realm_id);
			goto error;
	}

  rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"start_time"),RHP_XML_DT_LONG,&start_time,&ret_len,NULL,0);

  rhp_xml_str2val(rhp_xml_get_prop_static(node,(const xmlChar*)"elapsing_time"),RHP_XML_DT_LONG,&elapsing_time,&ret_len,NULL,0);

  rhp_memory_dbg_leak_print(start_time,elapsing_time);

#ifdef RHP_REFCNT_DEBUG
#ifdef RHP_REFCNT_DEBUG_X
  rhp_refcnt_dbg_print();
#endif // RHP_REFCNT_DEBUG_X
#endif // RHP_REFCNT_DEBUG

  {
    rhp_ipcmsg_syspxy_mem_dbg mem_dbg;

    mem_dbg.tag[0] = '#';
    mem_dbg.tag[1] = 'I';
    mem_dbg.tag[2] = 'M';
    mem_dbg.tag[3] = 'S';

    mem_dbg.type = RHP_IPC_SYSPXY_MEMORY_DBG;
    mem_dbg.len = sizeof(rhp_ipcmsg_syspxy_mem_dbg);

    mem_dbg.start_time = start_time;
    mem_dbg.elapsing_time = elapsing_time;

    if( rhp_ipc_send(RHP_MY_PROCESS,(void*)&mem_dbg,mem_dbg.len,0) < 0 ){
    	RHP_BUG("");
    }
  }

	err = rhp_http_bus_send_response(http_conn,http_bus_sess,NULL,NULL);
  if( err ){
  	goto error;
  }

  RHP_TRC(0,RHPTRCID_UI_HTTP_MEMORY_DBG_RTRN,"xxx",http_conn,http_bus_sess,http_req);
  return RHP_STATUS_CLOSE_HTTP_CONN;

error:
  RHP_TRC(0,RHPTRCID_UI_HTTP_MEMORY_DBG_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  return err;
}
#endif // RHP_MEMORY_DBG

static int _rhp_ui_http_debug_log_ctrl(xmlDocPtr doc,xmlNodePtr node,rhp_http_conn* http_conn,
		rhp_http_bus_session* http_bus_sess,rhp_http_request* http_req,void* ctx)
{
  int err = -EINVAL;
  unsigned long rlm_id = RHP_VPN_REALM_ID_UNKNOWN;
  int flag = 0;

  RHP_TRC(0,RHPTRCID_UI_HTTP_DEBUG_LOG_FLAG,"xxxxxx",doc,node,http_conn,http_bus_sess,http_req,ctx);

  if( doc == NULL || node == NULL ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_DEBUG_LOG_FLAG_NO_DOC_NODE,"xxx",http_conn,http_bus_sess,http_req);
    return -EINVAL;
  }

  if( _rhp_ui_http_get_user_realm_id(http_conn,http_bus_sess,&rlm_id)  ){
  	err = -EPERM;
		RHP_TRC(0,RHPTRCID_UI_HTTP_DEBUG_LOG_FLAG_NOT_PERMITTED,"xxxuu",http_conn,http_bus_sess,http_req,http_conn->user_realm_id,http_bus_sess->user_realm_id);
		goto error;
  }

  if( rlm_id != 0 ){
	  RHP_TRC(0,RHPTRCID_UI_HTTP_DEBUG_LOG_FLAG_NOT_PERMITTED_2,"xxxxxu",doc,node,http_conn,http_bus_sess,http_req,rlm_id);
  	err = -EPERM;
		goto error;
  }


  rhp_xml_check_enable(node,(xmlChar*)"debug_log",&flag);

	rhp_ui_log_main_log_ctl(flag);


	err = rhp_http_bus_send_response(http_conn,http_bus_sess,NULL,NULL);
  if( err ){
  	goto error;
  }

  RHP_TRC(0,RHPTRCID_UI_HTTP_DEBUG_LOG_FLAG_RTRN,"xxxd",http_conn,http_bus_sess,http_req,flag);
  return RHP_STATUS_CLOSE_HTTP_CONN;

error:
  RHP_TRC(0,RHPTRCID_UI_HTTP_DEBUG_LOG_FLAG_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  return err;
}


struct _rhp_ui_http_eap_sup_slz_ctx {
	rhp_vpn* vpn;
	int my_ikesa_side;
	u8* my_ikesa_spi;
	int eap_method; // RHP_PROTO_EAP_TYPE_XXX
	u8* user_id;
	int user_id_len;
	unsigned long txn_id;
};
typedef struct _rhp_ui_http_eap_sup_slz_ctx	rhp_ui_http_eap_sup_slz_ctx;

static int rhp_ui_http_eap_sup_ask_for_user_key_serialize(void* http_bus_sess_d,void* cb_ctx,void* writer,int idx)
{
  int err = -EINVAL;
  rhp_http_bus_session* http_bus_sess = (rhp_http_bus_session*)http_bus_sess_d;
  int n = 0;
  int n2 = 0;
  rhp_ui_http_eap_sup_slz_ctx* ctx = (rhp_ui_http_eap_sup_slz_ctx*)cb_ctx;
  rhp_vpn* vpn = ctx->vpn;

  RHP_TRC(0,RHPTRCID_UI_HTTP_EAP_SUP_ASK_FOR_USER_KEY_SERIALIZE,"xxdx",http_bus_sess,writer,idx,ctx);

	n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"rhp_http_bus_record");
	if(n < 0) {
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"index","%d",idx);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"service",(xmlChar*)"ui_http_vpn");
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"action",(xmlChar*)"eap_sup_ask_for_user_key_req");
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"session_id","%llu",http_bus_sess->session_id);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;


	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"vpn_unique_id",
			"0x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
			vpn->unique_id[0],vpn->unique_id[1],vpn->unique_id[2],vpn->unique_id[3],vpn->unique_id[4],vpn->unique_id[5],vpn->unique_id[6],vpn->unique_id[7],
			vpn->unique_id[8],vpn->unique_id[9],vpn->unique_id[10],vpn->unique_id[11],vpn->unique_id[12],vpn->unique_id[13],vpn->unique_id[14],vpn->unique_id[15]);

	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"vpn_realm_id","%lu",vpn->vpn_realm_id);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;


	{
		char *id_type,*id_str;

		err = rhp_ikev2_id_to_string(&(vpn->peer_id),&id_type,&id_str);
		if( err ){
			goto error;
		}

		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"peerid_type","%s",id_type);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			_rhp_free(id_type);
			_rhp_free(id_str);
			goto error;
		}
		n2 += n;

		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"peerid","%s",id_str);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			_rhp_free(id_type);
			_rhp_free(id_str);
			goto error;
		}
		n2 += n;

		_rhp_free(id_type);
		_rhp_free(id_str);
	}

	{
		n = 0;
		if( vpn->peer_addr.addr_family == AF_INET ){

			u32 ip = vpn->peer_addr.addr.v4;

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
					(xmlChar*)"peer_addr_v4","%d.%d.%d.%d",
					((u8*)&ip)[0],((u8*)&ip)[1],((u8*)&ip)[2],((u8*)&ip)[3]);

		}else	if( vpn->peer_addr.addr_family == AF_INET6 ){

			n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
					(xmlChar*)"peer_addr_v6","%s",
					rhp_ipv6_string(vpn->peer_addr.addr.v6));
		}
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		n2 += n;

		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,
				(xmlChar*)"peer_port","%d",ntohs(vpn->peer_addr.port));
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		n2 += n;
	}

	{
		char* method_name = rhp_eap_sup_impl_method2str(ctx->eap_method);
		if( method_name == NULL ){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}

		n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"eap_sup_method",(xmlChar*)method_name);
		_rhp_free(method_name);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		n2 += n;
	}

	if( ctx->user_id_len ){

		char* user_id = (char*)_rhp_malloc(ctx->user_id_len + 1);
		memcpy(user_id,ctx->user_id,ctx->user_id_len);
		user_id[ctx->user_id_len] = '\0';

		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"eap_sup_user_id","%s",user_id);
		_rhp_free(user_id);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		n2 += n;
	}

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"txn_id","%lu",ctx->txn_id);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;


	n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
	if(n < 0) {
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  RHP_TRC(0,RHPTRCID_UI_HTTP_EAP_SUP_ASK_FOR_USER_KEY_SERIALIZE_RTRN,"xd",http_bus_sess,n2);
  return n2;

error:
  RHP_TRC(0,RHPTRCID_UI_HTTP_EAP_SUP_ASK_FOR_USER_KEY_SERIALIZE_ERR,"xE",http_bus_sess,err);
  return err;
}


int rhp_ui_http_eap_sup_ask_for_user_key(rhp_vpn* vpn,int my_ikesa_side,u8* my_ikesa_spi,
		int eap_method, // RHP_PROTO_EAP_TYPE_XXX
		u8* user_id,int user_id_len)
{
	rhp_ui_http_eap_sup_slz_ctx ctx;
	unsigned long txn_id;

	memset(&ctx,0,sizeof(rhp_ui_http_eap_sup_slz_ctx));

	rhp_random_bytes((u8*)&txn_id,sizeof(unsigned long));

	ctx.vpn = vpn;
	ctx.my_ikesa_side = my_ikesa_side;
	ctx.my_ikesa_spi = my_ikesa_spi;
	ctx.eap_method = eap_method;
	ctx.user_id = user_id;
	ctx.user_id_len = user_id_len;
	ctx.txn_id = txn_id;

	rhp_http_bus_send_async(vpn->ui_info.http.http_bus_sess_id,vpn->ui_info.user_name,vpn->vpn_realm_id,1,1,
			rhp_ui_http_eap_sup_ask_for_user_key_serialize,(void*)&ctx);

	vpn->eap.ask_usr_key_ui_txn_id = txn_id;

	return 0;
}

extern int rhp_eap_sup_ask_for_user_key_reply(rhp_vpn* vpn,int eap_method,
		u8* user_id,int user_id_len,u8* user_key,int user_key_len);

static int _rhp_ui_http_vpn_eap_sup_user_key_rep(xmlDocPtr doc,xmlNodePtr node,rhp_http_conn* http_conn,
		rhp_http_bus_session* http_bus_sess,rhp_http_request* http_req,void* ctx)
{
  int err = -EINVAL;
  char* vpn_realm_str = NULL;
  char* unique_id_str = NULL;
  char* txn_id_str = NULL;
  char* eap_method_str = NULL;
  char* eap_user_id = NULL;
  char* eap_user_key = NULL;
  char* eap_action = NULL;
  unsigned long rlm_id = 0;
  unsigned long txn_id = 0;
  int eap_method = 0;
  char* endp;
  rhp_vpn* vpn = NULL;
  rhp_vpn_ref* vpn_ref = NULL;

  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_EAP_SUP_USER_KEY_REP,"xxxxxx",doc,node,http_conn,http_bus_sess,http_req,ctx);

  if( doc == NULL || node == NULL ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_EAP_SUP_USER_KEY_REP_NO_DOC_NODE,"xxx",http_conn,http_bus_sess,http_req);
    return -EINVAL;
  }

  {
		vpn_realm_str = (char*)rhp_xml_get_prop(node,(const xmlChar*)"vpn_realm");
		if( vpn_realm_str == NULL ){
			err = RHP_STATUS_INVALID_MSG;
			RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_EAP_SUP_USER_KEY_REP_NO_VPN_REALM,"xxx",http_conn,http_bus_sess,http_req);
			goto error;
		}

		rlm_id = strtoul((char*)vpn_realm_str,&endp,0);
		if( (rlm_id == ULONG_MAX && errno == ERANGE) || *endp != '\0' ){
			err = -ENOENT;
			RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_EAP_SUP_USER_KEY_REP_NO_VPN_REALM_2,"xxxs",http_conn,http_bus_sess,http_req,vpn_realm_str);
			goto error;
		}
  }

  if( _rhp_ui_http_permitted(http_conn,http_bus_sess,rlm_id) ){
			err = -EPERM;
			RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_EAP_SUP_USER_KEY_REP_NOT_PERMITTED,"xxxuu",http_conn,http_bus_sess,http_req,http_conn->user_realm_id,http_bus_sess->user_realm_id);
			goto error;
	}

  unique_id_str = (char*)rhp_xml_get_prop(node,(const xmlChar*)"vpn_unique_id");

  if( unique_id_str ){

  	u8 vpn_unique_id[RHP_VPN_UNIQUE_ID_SIZE];

  	memset(vpn_unique_id,0,RHP_VPN_UNIQUE_ID_SIZE);

  	err = rhp_str_to_vpn_unique_id(unique_id_str,vpn_unique_id);
  	if( err ){
			err = RHP_STATUS_INVALID_MSG;
  		goto error;
  	}

  	vpn_ref = rhp_vpn_get_by_unique_id(vpn_unique_id);
  	vpn = RHP_VPN_REF(vpn_ref);
  }

  if( vpn == NULL ){
		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_EAP_SUP_USER_KEY_REP_NO_VPN_ENT_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
		err = -ENOENT;
		goto error;
	}

  if( http_conn->user_realm_id && vpn->vpn_realm_id != http_conn->user_realm_id ){
		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_EAP_SUP_USER_KEY_REP_INVALID_REALM_ID,"xxxuuE",http_conn,http_bus_sess,http_req,vpn->vpn_realm_id,http_conn->user_realm_id,err);
		err = -EPERM;
		goto error;
  }

  {
		txn_id_str = (char*)rhp_xml_get_prop(node,(const xmlChar*)"txn_id");
		if( txn_id_str == NULL ){
			err = RHP_STATUS_INVALID_MSG;
			RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_EAP_SUP_USER_KEY_REP_NO_TXN_ID,"xxx",http_conn,http_bus_sess,http_req);
			goto error;
		}

		txn_id = strtoul((char*)txn_id_str,&endp,0);
		if( (txn_id == ULONG_MAX && errno == ERANGE) || *endp != '\0' ){
			err = -ENOENT;
			RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_EAP_SUP_USER_KEY_REP_NO_TXN_ID_2,"xxxs",http_conn,http_bus_sess,http_req,txn_id_str);
			goto error;
		}
  }

  {
		eap_action = (char*)rhp_xml_get_prop(node,(const xmlChar*)"eap_sup_action");
		if( eap_action == NULL ){
			err = RHP_STATUS_INVALID_MSG;
			RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_EAP_SUP_USER_KEY_REP_NO_EAP_SUP_ACTION,"xxx",http_conn,http_bus_sess,http_req);
			goto error;
		}
  }


  RHP_LOCK(&(vpn->lock));

	if( !_rhp_atomic_read(&(vpn->is_active)) ){
		err = -ENOENT;
		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_EAP_SUP_USER_KEY_REP_VPN_NOT_ACTIVE,"xxxx",http_conn,http_bus_sess,http_req,vpn);
		goto error_l;
	}

	if( vpn->eap.ask_usr_key_ui_txn_id == 0 || (txn_id != vpn->eap.ask_usr_key_ui_txn_id) ){
		err = RHP_STATUS_INVALID_MSG;
		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_EAP_SUP_USER_KEY_REP_INVALID_UI_TXN_ID,"xxxx",http_conn,http_bus_sess,http_req,vpn);
		goto error_l;
	}

	vpn->eap.ask_usr_key_ui_txn_id = 0;


  if( !strcmp(eap_action,"continue") ){

  	eap_method_str = (char*)rhp_xml_get_prop(node,(const xmlChar*)"eap_sup_method");
		if( eap_method_str == NULL ){
			err = RHP_STATUS_INVALID_MSG;
			RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_EAP_SUP_USER_KEY_REP_NO_EAP_SUP_METHOD,"xxx",http_conn,http_bus_sess,http_req);
			goto error;
		}

		eap_method = rhp_eap_sup_impl_str2method(eap_method_str);
	  if( eap_method < 1 ){
			err = RHP_STATUS_INVALID_MSG;
			RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_EAP_SUP_USER_KEY_REP_UNKNOWN_EAP_SUP_METHOD,"xxx",http_conn,http_bus_sess,http_req);
			goto error_l;
		}

	  eap_user_id = (char*)rhp_xml_get_prop(node,(const xmlChar*)"eap_sup_user_id");
		if( eap_user_id == NULL || strlen(eap_user_id) < 1 ){
			err = RHP_STATUS_INVALID_MSG;
			RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_EAP_SUP_USER_KEY_REP_NO_EAP_SUP_USER_ID,"xxx",http_conn,http_bus_sess,http_req);
			goto error_l;
		}

  	eap_user_key = (char*)rhp_xml_get_prop(node,(const xmlChar*)"eap_sup_user_key");
		if( eap_user_key == NULL || strlen(eap_user_key) < 1 ){
			err = RHP_STATUS_INVALID_MSG;
			RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_EAP_SUP_USER_KEY_REP_NO_EAP_SUP_USER_KEY,"xxx",http_conn,http_bus_sess,http_req);
			goto error_l;
		}


		err = rhp_eap_sup_ask_for_user_key_reply(vpn,eap_method,
				(u8*)eap_user_id,strlen(eap_user_id),(u8*)eap_user_key,strlen(eap_user_key));

		if( err ){
			RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_EAP_SUP_USER_KEY_REP_EAP_SUP_CALL_ERR,"xxxxE",http_conn,http_bus_sess,http_req,vpn,err);
			goto error_l;
		}

  }else if( !strcmp(eap_action,"cancel") ){

		if( vpn->ikesa_list_head ){
			vpn->ikesa_list_head->timers->schedule_delete(vpn,vpn->ikesa_list_head,0);
		}else{
			rhp_vpn_destroy(vpn);
		}

	}else{

		err = RHP_STATUS_INVALID_MSG;
		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_EAP_SUP_USER_KEY_REP_UNKNOWN_EAP_SUP_ACTION,"xxx",http_conn,http_bus_sess,http_req);
		goto error_l;
	}

	RHP_UNLOCK(&(vpn->lock));


  err = rhp_http_bus_send_response(http_conn,http_bus_sess,NULL,NULL);
  if( err ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_EAP_SUP_USER_KEY_REP_TX_RESP_ERR,"xxxxE",http_conn,http_bus_sess,http_req,vpn,err);
    goto error;
  }


  rhp_vpn_unhold(vpn_ref);

  _rhp_free(vpn_realm_str);
  _rhp_free(txn_id_str);
  _rhp_free(unique_id_str);
  _rhp_free(eap_action);

  if( eap_method_str ){
  	_rhp_free(eap_method_str);
  }
  if( eap_user_key ){
  	_rhp_free_zero(eap_user_key,strlen(eap_user_key));
  }
  if( eap_user_id ){
  	_rhp_free_zero(eap_user_id,strlen(eap_user_id));
  }

  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_EAP_SUP_USER_KEY_REP_RTRN,"xxxx",http_conn,http_bus_sess,http_req,vpn);
  return RHP_STATUS_CLOSE_HTTP_CONN;


error_l:
	if( vpn ){

		if( vpn->ikesa_list_head ){
			vpn->ikesa_list_head->timers->schedule_delete(vpn,vpn->ikesa_list_head,0);
		}else{
			rhp_vpn_destroy(vpn);
		}

		RHP_UNLOCK(&(vpn->lock));
	}
error:
	if( vpn ){
	  rhp_vpn_unhold(vpn_ref);
	}
  if( vpn_realm_str ){
  	_rhp_free(vpn_realm_str);
  }
  if( txn_id_str ){
  	_rhp_free(txn_id_str);
  }
  if( eap_method_str ){
  	_rhp_free(eap_method_str);
  }
  if( eap_user_key ){
  	_rhp_free_zero(eap_user_key,strlen(eap_user_key));
  }
  if( eap_user_id ){
  	_rhp_free_zero(eap_user_id,strlen(eap_user_id));
  }
  if( unique_id_str ){
  	_rhp_free(unique_id_str);
  }
  if( eap_action ){
  	_rhp_free(eap_action);
  }

  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_EAP_SUP_USER_KEY_REP_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  return err;
}

static int _rhp_ui_http_vpn_eap_sup_clear_user_key_cache(xmlDocPtr doc,xmlNodePtr node,rhp_http_conn* http_conn,
		rhp_http_bus_session* http_bus_sess,rhp_http_request* http_req,void* ctx)
{
  int err = -EINVAL;
  char* vpn_realm_str = NULL;
  unsigned long rlm_id = 0;
  char* endp;

  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_EAP_SUP_CLEAR_USER_KEY_CACHE,"xxxxxx",doc,node,http_conn,http_bus_sess,http_req,ctx);

  if( doc == NULL || node == NULL ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_EAP_SUP_CLEAR_USER_KEY_CACHE_NO_DOC_NODE,"xxx",http_conn,http_bus_sess,http_req);
    return -EINVAL;
  }

  {
		vpn_realm_str = (char*)rhp_xml_get_prop(node,(const xmlChar*)"vpn_realm");
		if( vpn_realm_str == NULL ){
			err = RHP_STATUS_INVALID_MSG;
			RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_EAP_SUP_CLEAR_USER_KEY_CACHE_NO_VPN_REALM,"xxx",http_conn,http_bus_sess,http_req);
			goto error;
		}

		rlm_id = strtoul((char*)vpn_realm_str,&endp,0);
		if( (rlm_id == ULONG_MAX && errno == ERANGE) || *endp != '\0' ){
			err = -ENOENT;
			RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_EAP_SUP_CLEAR_USER_KEY_CACHE_NO_VPN_REALM_2,"xxxs",http_conn,http_bus_sess,http_req,vpn_realm_str);
			goto error;
		}
  }

  if( _rhp_ui_http_permitted(http_conn,http_bus_sess,rlm_id) ){
			err = -EPERM;
			RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_EAP_SUP_CLEAR_USER_KEY_CACHE_NOT_PERMITTED,"xxxuu",http_conn,http_bus_sess,http_req,http_conn->user_realm_id,http_bus_sess->user_realm_id);
			goto error;
	}

  {
  	rhp_vpn_realm* rlm = NULL;

  	rlm = rhp_realm_get(rlm_id);
  	if( rlm ){

  		RHP_LOCK(&(rlm->lock));

  	  rhp_eap_sup_impl_clear_user_key_cache(rlm);

  	  RHP_UNLOCK(&(rlm->lock));

  	}else{

  		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_EAP_SUP_CLEAR_USER_KEY_CACHE_NO_RLM,"xxxuu",http_conn,http_bus_sess,http_req,http_conn->user_realm_id,http_bus_sess->user_realm_id);

  		err = -ENOENT;
			goto error;
  	}
  }


  err = rhp_http_bus_send_response(http_conn,http_bus_sess,NULL,NULL);
  if( err ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_EAP_SUP_CLEAR_USER_KEY_CACHE_TX_RESP_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
    goto error;
  }

  if( vpn_realm_str ){
  	_rhp_free(vpn_realm_str);
  }

	RHP_LOG_I(RHP_LOG_SRC_UI,rlm_id,RHP_LOG_ID_VPN_EAP_SUP_CLEAR_USER_KEY_CACHE,"");

  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_EAP_SUP_CLEAR_USER_KEY_CACHE_RTRN,"xxx",http_conn,http_bus_sess,http_req);
  return RHP_STATUS_CLOSE_HTTP_CONN;

error:
  if( vpn_realm_str ){
  	_rhp_free(vpn_realm_str);
  }

	RHP_LOG_E(RHP_LOG_SRC_UI,rlm_id,RHP_LOG_ID_VPN_EAP_SUP_CLEAR_USER_KEY_CACHE_ERR,"E",err);

  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_EAP_SUP_CLEAR_USER_KEY_CACHE_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  return err;
}

static int _rhp_ui_http_vpn_req_handler_nobody_allowed(rhp_http_conn* http_conn,
		rhp_http_bus_session* http_bus_sess,rhp_http_request* http_req,char* action_str)
{
  if( !strcmp(action_str,"connect") 					||
  		!strcmp(action_str,"close") 						||
  		!strcmp(action_str,"eap_sup_user_key_reply") 				||
  		!strcmp(action_str,"eap_sup_clear_user_key_cache")	||
  		!strcmp(action_str,"mobike_i_start_routability_check")	||
  		!strcmp(action_str,"status_vpn") 				||
  		!strcmp(action_str,"status_vpn_peers") 	||
  		!strcmp(action_str,"status_bridge") 		||
  		!strcmp(action_str,"status_neigh") 			||
  		!strcmp(action_str,"config_peers") 			||
  		!strcmp(action_str,"config_realm_exists") 			 ||
  		!strcmp(action_str,"config_enum_realms") 				 ||
  		!strcmp(action_str,"status_enum_interfaces") 		 ||
  		!strcmp(action_str,"status_enum_src_interfaces") ||
  		!strcmp(action_str,"status_enum_route_maps") 		 ||
  		!strcmp(action_str,"status_ip_routing_table") 	 ||
  		!strcmp(action_str,"status_ip_routing_cache") 	 ||
  		!strcmp(action_str,"global_statistics_esp") 		 ||
  		!strcmp(action_str,"global_statistics_ikev2") 	 ||
  		!strcmp(action_str,"global_statistics_bridge") 	 ||
  		!strcmp(action_str,"global_statistics_resource") ){

  	RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_REQ_HANDLER_NOBODY_USER_ALLOWED,"xxxs",http_conn,http_bus_sess,http_req,action_str);
  	return 0;

  }else{

  	RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_REQ_HANDLER_NOBODY_USER_NOT_ALLOWED,"xxxs",http_conn,http_bus_sess,http_req,action_str);
    RHP_LOG_DE(RHP_LOG_SRC_UI,0,RHP_LOG_ID_UI_HTTP_NOBODY_USER_NOT_ALLOWED_ACTION,"uss",http_conn->user_realm_id,http_conn->user_name,action_str);

    return -EPERM;
  }
}

static int _rhp_ui_http_vpn_req_handler(rhp_http_conn* http_conn,rhp_http_bus_session* http_bus_sess,
		rhp_http_request* http_req,void* ctx)
{
  int err = -EINVAL;
  char* action_str = NULL;
  xmlDocPtr doc = (xmlDocPtr)http_req->xml_doc;
  xmlNodePtr root_node = (xmlNodePtr)http_req->xml_root_node;

  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_REQ_HANDLER,"xxxx",http_conn,http_bus_sess,http_req,ctx);

  action_str = (char*)rhp_xml_get_prop(root_node,(const xmlChar*)"action");
  if( action_str == NULL ){
    RHP_BUG("");
    return RHP_STATUS_INVALID_MSG;
  }

  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_REQ_HANDLER_ACTION,"xxxs",http_conn,http_bus_sess,http_req,action_str);


  if( http_conn->is_nobody ){

  	err = _rhp_ui_http_vpn_req_handler_nobody_allowed(http_conn,http_bus_sess,http_req,action_str);
  	if( err ){
      RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_REQ_HANDLER_NOBODY_USER_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  		return err;
  	}
  }

  if( RHP_UI_HTTP_LOCKED() ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_REQ_HANDLER_BUSY,"xxxx",http_conn,http_bus_sess,http_req,ctx);
    return -EBUSY;
  }

  RHP_UI_HTTP_LOCK();


  if( !strcmp(action_str,"connect") ){

    err = _rhp_ui_http_vpn_connect_i(doc,root_node,http_conn,http_bus_sess,http_req,ctx);
    if( err ){
      RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_REQ_HANDLER_CONNECT_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
      goto error;
    }

  }else if( !strcmp(action_str,"close") ){

  	err = _rhp_ui_http_vpn_close(doc,root_node,http_conn,http_bus_sess,http_req,ctx);
  	if( err ){
  		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_REQ_HANDLER_CLOSE_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  		goto error;
    }

  }else if( !strcmp(action_str,"mobike_i_start_routability_check") ){

  	err = _rhp_ui_http_vpn_mobike_i_start_rt_check(doc,root_node,http_conn,http_bus_sess,http_req,ctx);
  	if( err ){
  		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_MOBIKE_I_START_RT_CHECK_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  		goto error;
    }

  }else if( !strcmp(action_str,"vpn_clear_all") ){

  	err = _rhp_ui_http_vpn_clear_all(doc,root_node,http_conn,http_bus_sess,http_req,ctx);
  	if( err ){
  		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_REQ_HANDLER_VPN_CLEAR_ALL_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  		goto error;
    }

  }else if( !strcmp(action_str,"mobike_clear_additional_address_cache") ){

  	err = _rhp_ui_http_vpn_mobike_clear_additional_addr_cache(doc,root_node,http_conn,http_bus_sess,http_req,ctx);
  	if( err ){
  		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_REQ_HANDLER_MOBIKE_CLEAR_ADDITIONAL_ADDRESS_CACHE_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  		goto error;
    }

  }else if( !strcmp(action_str,"eap_sup_user_key_reply") ){

  	err = _rhp_ui_http_vpn_eap_sup_user_key_rep(doc,root_node,http_conn,http_bus_sess,http_req,ctx);
  	if( err ){
  		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_REQ_HANDLER_EAP_SUP_USER_KEY_REPLY_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  		goto error;
    }

  }else if( !strcmp(action_str,"eap_sup_clear_user_key_cache") ){

  	err = _rhp_ui_http_vpn_eap_sup_clear_user_key_cache(doc,root_node,http_conn,http_bus_sess,http_req,ctx);
  	if( err ){
  		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_REQ_HANDLER_EAP_SUP_CLEAR_USER_KEY_CACHE_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  		goto error;
    }

  }else if( !strcmp(action_str,"status_vpn") ){

  	err = _rhp_ui_http_vpn_get_info_vpn(doc,root_node,http_conn,http_bus_sess,http_req,ctx);
  	if( err ){
  		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_REQ_HANDLER_GET_INFO_VPN_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  		goto error;
    }

  }else if( !strcmp(action_str,"status_vpn_peers") ){

  	err = _rhp_ui_http_vpn_get_peers(doc,root_node,http_conn,http_bus_sess,http_req,ctx);
  	if( err ){
  		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_REQ_HANDLER_GET_PEERS_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  		goto error;
    }

  }else if( !strcmp(action_str,"status_bridge") ){

  	err = _rhp_ui_http_vpn_get_bridge_info(doc,root_node,http_conn,http_bus_sess,http_req,ctx);
  	if( err ){
  		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_REQ_HANDLER_GET_BRIDGE_INFO_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  		goto error;
    }

  }else if( !strcmp(action_str,"status_neigh") ){

  	err = _rhp_ui_http_vpn_get_bridge_neigh_info(doc,root_node,http_conn,http_bus_sess,http_req,ctx);
  	if( err ){
  		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_REQ_HANDLER_GET_BRIDGE_NEIGH_INFO_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  		goto error;
    }

  }else if( !strcmp(action_str,"status_address_pool") ){

  	err = _rhp_ui_http_vpn_get_address_pool_info(doc,root_node,http_conn,http_bus_sess,http_req,ctx);
  	if( err ){
  		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_REQ_HANDLER_GET_ADDRESS_POOL_INFO_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  		goto error;
    }

  }else if( !strcmp(action_str,"config_peers") ){

   	err = 	_rhp_ui_http_cfg_peers(doc,root_node,http_conn,http_bus_sess,http_req,ctx);
    if( err ){
   		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_REQ_HANDLER_CONFIG_PEERS_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
   		goto error;
    }

  }else if( !strcmp(action_str,"config_get") ){

  	err = _rhp_ui_http_cfg_get(doc,root_node,http_conn,http_bus_sess,http_req,ctx);
    if( err ){
  		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_REQ_HANDLER_CONFIG_GET_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  		goto error;
    }

  }else if( !strcmp(action_str,"config_create_realm") ){

  	err = _rhp_ui_http_cfg_create_realm(doc,root_node,http_conn,http_bus_sess,http_req,ctx);
    if( err ){
  		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_REQ_HANDLER_CONFIG_CREATE_REALM_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  		goto error;
    }

  }else if( !strcmp(action_str,"config_update_realm") ){

  	err = _rhp_ui_http_cfg_update_realm(doc,root_node,http_conn,http_bus_sess,http_req,ctx);
    if( err ){
  		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_REQ_HANDLER_CONFIG_UPDATE_REALM_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  		goto error;
    }

  }else if( !strcmp(action_str,"config_delete_realm") ){

  	err = _rhp_ui_http_cfg_delete_realm(doc,root_node,http_conn,http_bus_sess,http_req,ctx);
    if( err ){
  		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_REQ_HANDLER_CONFIG_DELETE_REALM_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  		goto error;
    }

  }else if( !strcmp(action_str,"config_update_realm_state") ){

  	err = _rhp_ui_http_cfg_update_realm_state(doc,root_node,http_conn,http_bus_sess,http_req,ctx);
    if( err ){
  		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_REQ_HANDLER_CONFIG_UPDATE_REALM_STATE_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  		goto error;
    }

  }else if( !strcmp(action_str,"config_enable_realm") ){

    err = _rhp_ui_http_cfg_enable_realm(doc,root_node,http_conn,http_bus_sess,http_req,ctx);
    if( err ){
  		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_REQ_HANDLER_CONFIG_ENABLE_REALM_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  		goto error;
    }

  }else if( !strcmp(action_str,"config_disable_realm") ){

    err = _rhp_ui_http_cfg_disable_realm(doc,root_node,http_conn,http_bus_sess,http_req,ctx);
    if( err ){
  		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_REQ_HANDLER_CONFIG_DISABLE_REALM_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  		goto error;
    }

  }else if( !strcmp(action_str,"config_realm_is_enabled") ){

    err = _rhp_ui_http_cfg_realm_is_enabled(doc,root_node,http_conn,http_bus_sess,http_req,ctx);
    if( err ){
  		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_REQ_HANDLER_CONFIG_REALM_IS_ENABLED_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  		goto error;
    }

  }else if( !strcmp(action_str,"config_realm_is_disabled") ){

    err = _rhp_ui_http_cfg_realm_is_disabled(doc,root_node,http_conn,http_bus_sess,http_req,ctx);
    if( err ){
  		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_REQ_HANDLER_CONFIG_REALM_IS_DISABLED_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  		goto error;
    }

  }else if( !strcmp(action_str,"config_get_global_config") ){

    err = _rhp_ui_http_cfg_get_global_params(doc,root_node,http_conn,http_bus_sess,http_req,ctx);
    if( err ){
  		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_REQ_HANDLER_CONFIG_GET_GLOBAL_CFG_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  		goto error;
    }

  }else if( !strcmp(action_str,"config_update_global_config") ){

  	err = _rhp_ui_http_cfg_update_global_cfg(doc,root_node,http_conn,http_bus_sess,http_req,ctx);
    if( err ){
  		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_REQ_HANDLER_CONFIG_UPDATE_GLOBAL_CFG_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  		goto error;
    }

  }else if( !strcmp(action_str,"config_update_my_key_info") ){

  	err = _rhp_ui_http_cfg_forward_auth_realm_config(doc,root_node,http_conn,http_bus_sess,http_req,ctx,
  			"config_update_key_info","my_auth",RHP_IPC_SYSPXY_CFG_UPDATE_KEY_INFO);

  	if( err ){
  		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_REQ_HANDLER_CONFIG_UPDATE_KEY_INFO__ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  		goto error;
    }

  }else if( !strcmp(action_str,"config_update_peer_key_info") ){

  	err = _rhp_ui_http_cfg_forward_auth_realm_config(doc,root_node,http_conn,http_bus_sess,http_req,ctx,
  			"config_update_key_info","peer",RHP_IPC_SYSPXY_CFG_UPDATE_KEY_INFO);

  	if( err ){
  		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_REQ_HANDLER_CONFIG_UPDATE_KEY_INFO__ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  		goto error;
    }

  }else if( !strcmp(action_str,"config_delete_peer_key_info") ){

  	err = _rhp_ui_http_cfg_forward_auth_realm_config(doc,root_node,http_conn,http_bus_sess,http_req,ctx,
  			"config_delete_key_info","peer",RHP_IPC_SYSPXY_CFG_DELETE_KEY_INFO);

  	if( err ){
  		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_REQ_HANDLER_CONFIG_DELETE_KEY_INFO__ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  		goto error;
    }

  }else if( !strcmp(action_str,"config_update_cert") ){

  	err = _rhp_ui_http_cfg_forward_auth_realm_config(doc,root_node,http_conn,http_bus_sess,http_req,ctx,
  			"config_update_cert","cert_store",RHP_IPC_SYSPXY_CFG_UPDATE_CERT);

  	if( err ){
  		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_REQ_HANDLER_CONFIG_UPDATE_CERT__ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  		goto error;
    }

  }else if( !strcmp(action_str,"config_update_cert_file") ){

  	err = _rhp_ui_http_cfg_forward_auth_realm_config(doc,root_node,http_conn,http_bus_sess,http_req,ctx,
  			"config_update_cert","cert_store",RHP_IPC_SYSPXY_CFG_UPDATE_CERT_FILE);

  	if( err ){
  		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_REQ_HANDLER_CONFIG_UPDATE_CERT__ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  		goto error;
    }

  }else if( !strcmp(action_str,"config_delete_cert") ){

  	err = _rhp_ui_http_cfg_forward_auth_realm_config(doc,root_node,http_conn,http_bus_sess,http_req,ctx,
  			"config_delete_cert","cert_store",RHP_IPC_SYSPXY_CFG_DELETE_CERT);

  	if( err ){
  		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_REQ_HANDLER_CONFIG_DELETE_CERT__ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  		goto error;
    }

  }else if( !strcmp(action_str,"config_get_my_printed_cert") ){

  	err = _rhp_ui_http_cfg_get_printed_certs(doc,root_node,http_conn,http_bus_sess,http_req,ctx,RHP_IPC_SYSPXY_CFG_GET_PRINTED_CERTS_MY_CERT);
    if( err ){
  		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_REQ_HANDLER_CONFIG_GET_MY_CERT_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  		goto error;
    }

  }else if( !strcmp(action_str,"config_get_printed_ca_certs") ){

  	err = _rhp_ui_http_cfg_get_printed_certs(doc,root_node,http_conn,http_bus_sess,http_req,ctx,RHP_IPC_SYSPXY_CFG_GET_PRINTED_CERTS_CA_CERTS);
    if( err ){
  		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_REQ_HANDLER_CONFIG_GET_CA_CERTS_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  		goto error;
    }

  }else if( !strcmp(action_str,"config_get_printed_crls") ){

  	err = _rhp_ui_http_cfg_get_printed_certs(doc,root_node,http_conn,http_bus_sess,http_req,ctx,RHP_IPC_SYSPXY_CFG_GET_PRINTED_CERTS_CRL);
    if( err ){
  		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_REQ_HANDLER_CONFIG_GET_CRLS_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  		goto error;
    }

  }else if( !strcmp(action_str,"config_get_peer_printed_certs") ){

  	err = _rhp_ui_http_get_vpn_peer_printed_certs(doc,root_node,http_conn,http_bus_sess,http_req,ctx);
    if( err ){
  		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_REQ_HANDLER_CONFIG_GET_PEER_CERT_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  		goto error;
    }

  }else if( !strcmp(action_str,"config_update_admin") ){

  	err = 	_rhp_ui_http_cfg_forward_auth_realm_config(doc,root_node,http_conn,http_bus_sess,http_req,ctx,
  			"config_update_admin","admin",RHP_IPC_SYSPXY_CFG_UPDATE_ADMIN);

  	if( err ){
  		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_REQ_HANDLER_CONFIG_UPDATE_ADMIN__ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  		goto error;
    }

  }else if( !strcmp(action_str,"config_delete_admin") ){

  	err = _rhp_ui_http_cfg_forward_auth_realm_config(doc,root_node,http_conn,http_bus_sess,http_req,ctx,
  			"config_delete_admin","admin",RHP_IPC_SYSPXY_CFG_DELETE_ADMIN);

  	if( err ){
  		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_REQ_HANDLER_CONFIG_DELETE_ADMIN__ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  		goto error;
    }

  }else if( !strcmp(action_str,"config_enum_admin") ){

  	err = _rhp_ui_http_cfg_enum_admin(doc,root_node,http_conn,http_bus_sess,http_req,ctx);

  	if( err ){
  		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_REQ_HANDLER_CONFIG_ENUM_ADMIN__ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  		goto error;
    }

  }else if( !strcmp(action_str,"config_update_radius_mng") ){

  	err = _rhp_ui_http_cfg_forward_auth_realm_config(doc,root_node,http_conn,http_bus_sess,http_req,ctx,
  			"config_update_radius_mng","radius",RHP_IPC_SYSPXY_CFG_UPDATE_RADIUS_MNG);

  	if( err ){
  		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_REQ_HANDLER_CONFIG_UPDATE_RADIUS_MNG_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  		goto error;
    }

  }else if( !strcmp(action_str,"flush_bridge") ){

  	err = _rhp_ui_http_flush_bridge(doc,root_node,http_conn,http_bus_sess,http_req,ctx);
    if( err ){
  		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_REQ_HANDLER_FLUSH_BRIDGE,"xxxE",http_conn,http_bus_sess,http_req,err);
  		goto error;
    }

  }else if( !strcmp(action_str,"flush_address_pool") ){

  	err = _rhp_ui_http_flush_address_pool(doc,root_node,http_conn,http_bus_sess,http_req,ctx);
    if( err ){
  		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_REQ_HANDLER_FLUSH_ADDRESS_POOL,"xxxE",http_conn,http_bus_sess,http_req,err);
  		goto error;
    }

  }else if( !strcmp(action_str,"flush_ip_route_cache") ){

  	err = _rhp_ui_http_flush_ip_route_cache(doc,root_node,http_conn,http_bus_sess,http_req,ctx);
    if( err ){
  		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_REQ_HANDLER_FLUSH_IP_ROUTE_CACHE,"xxxE",http_conn,http_bus_sess,http_req,err);
  		goto error;
    }

  }else if( !strcmp(action_str,"config_realm_exists") ){

  	err = _rhp_ui_http_cfg_realm_exists(doc,root_node,http_conn,http_bus_sess,http_req,ctx);
    if( err ){
  		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_REQ_HANDLER_CONFIG_REALM_EXISTS_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  		goto error;
    }

  }else if( !strcmp(action_str,"config_enum_realms") ){

  	err = _rhp_ui_http_cfg_enum_realms(doc,root_node,http_conn,http_bus_sess,http_req,ctx);
    if( err ){
  		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_REQ_HANDLER_CONFIG_ENUM_REALMS_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  		goto error;
    }

  }else if( !strcmp(action_str,"get_hostname") ){

  	err = _rhp_ui_http_get_hostname(doc,root_node,http_conn,http_bus_sess,http_req,ctx);
    if( err ){
  		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_REQ_HANDLER_GET_HOSTNAME_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  		goto error;
    }

  }else if( !strcmp(action_str,"status_enum_interfaces") ){

  	err = _rhp_ui_http_status_enum_interfaces(doc,root_node,http_conn,http_bus_sess,http_req,ctx);
    if( err ){
  		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_REQ_HANDLER_STATUS_ENUM_INTERFACES_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  		goto error;
    }

  }else if( !strcmp(action_str,"status_enum_src_interfaces") ){

  	err = _rhp_ui_http_status_enum_realm_src_interfaces(doc,root_node,http_conn,http_bus_sess,http_req,ctx);
    if( err ){
  		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_REQ_HANDLER_STATUS_ENUM_SRC_INTERFACES_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  		goto error;
    }

  }else if( !strcmp(action_str,"status_enum_route_maps") ){

  	err = _rhp_ui_http_status_enum_route_maps(doc,root_node,http_conn,http_bus_sess,http_req,ctx);
    if( err ){
  		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_REQ_HANDLER_STATUS_ENUM_ROUTE_MAPS_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  		goto error;
    }

  }else if( !strcmp(action_str,"status_ip_routing_table") ){

  	err = _rhp_ui_http_status_enum_ip_routing_table(doc,root_node,http_conn,http_bus_sess,http_req,ctx);
    if( err ){
  		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_REQ_HANDLER_STATUS_ENUM_IP_ROUTING_TABLE_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  		goto error;
    }

  }else if( !strcmp(action_str,"status_ip_routing_cache") ){

  	err = _rhp_ui_http_status_enum_ip_routing_cache(doc,root_node,http_conn,http_bus_sess,http_req,ctx);
    if( err ){
  		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_REQ_HANDLER_STATUS_ENUM_IP_ROUTING_CACHE_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  		goto error;
    }

  }else if( !strcmp(action_str,"status_nhrp_cache") ){

  	err = _rhp_ui_http_status_enum_nhrp_cache(doc,root_node,http_conn,http_bus_sess,http_req,ctx);
    if( err ){
  		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_REQ_HANDLER_STATUS_ENUM_NHRP_CACHE_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  		goto error;
    }

  }else if( !strcmp(action_str,"global_statistics_esp") ){

  	err = _rhp_ui_http_get_global_esp_statistics(doc,root_node,http_conn,http_bus_sess,http_req,ctx);
    if( err ){
  		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_REQ_HANDLER_GET_GLOBAL_STATISTICS_ESP_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  		goto error;
    }

  }else if( !strcmp(action_str,"global_statistics_ikev2") ){

  	err = _rhp_ui_http_get_global_ikev2_statistics(doc,root_node,http_conn,http_bus_sess,http_req,ctx);
    if( err ){
  		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_REQ_HANDLER_GET_GLOBAL_STATISTICS_IKEV2_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  		goto error;
    }

  }else if( !strcmp(action_str,"global_statistics_bridge") ){

  	err = _rhp_ui_http_get_global_bridge_statistics(doc,root_node,http_conn,http_bus_sess,http_req,ctx);
    if( err ){
  		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_REQ_HANDLER_GET_GLOBAL_STATISTICS_BRIDGE_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  		goto error;
    }

  }else if( !strcmp(action_str,"global_statistics_resource") ){

  	err = _rhp_ui_http_get_global_resource_statistics(doc,root_node,http_conn,http_bus_sess,http_req,ctx);
    if( err ){
  		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_REQ_HANDLER_GET_GLOBAL_STATISTICS_RESOURCE_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  		goto error;
    }

  }else if( !strcmp(action_str,"clear_interface_statistics") ){

  	err = _rhp_ui_http_clear_interface_statistics(doc,root_node,http_conn,http_bus_sess,http_req,ctx);
    if( err ){
  		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_REQ_HANDLER_CLEAR_INTERFACE_STATISTICS_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  		goto error;
    }

  }else if( !strcmp(action_str,"clear_global_statistics_esp") ||
  		 	 	 	!strcmp(action_str,"clear_global_statistics_ikev2") ||
  		 	 	 	!strcmp(action_str,"clear_global_statistics_bridge") ||
  		 	 	 	!strcmp(action_str,"clear_global_statistics_resource") ){

  	err = _rhp_ui_http_clear_global_statistics(doc,root_node,http_conn,http_bus_sess,http_req,ctx,action_str);
    if( err ){
  		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_REQ_HANDLER_CLEAR_INTERFACE_STATISTICS_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  		goto error;
    }

  }else if( !strcmp(action_str,"event_log_save") ){

  	err = _rhp_ui_http_event_log_save(doc,root_node,http_conn,http_bus_sess,http_req,ctx);
    if( err ){
  		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_REQ_HANDLER_EVENT_LOG_SAVE_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  		goto error;
    }

  }else if( !strcmp(action_str,"event_log_reset") ){

  	err = _rhp_ui_http_event_log_reset(doc,root_node,http_conn,http_bus_sess,http_req,ctx);
    if( err ){
  		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_REQ_HANDLER_EVENT_LOG_RESET_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  		goto error;
    }

  }else if( !strcmp(action_str,"event_log_control") ){

  	err = _rhp_ui_http_debug_log_ctrl(doc,root_node,http_conn,http_bus_sess,http_req,ctx);
    if( err ){
  		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_REQ_HANDLER_EVENT_LOG_CTRL_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  		goto error;
    }

  }else if( !strcmp(action_str,"ikev2_qcd_reset_key") ){

  	err = _rhp_ui_http_ikev2_qcd_reset_key(doc,root_node,http_conn,http_bus_sess,http_req,ctx);
    if( err ){
  		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_REQ_HANDLER_IKEV2_QCD_RESET_KEY_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  		goto error;
    }

  }else if( !strcmp(action_str,"ikev2_sess_resume_reset_key") ){

  	err = _rhp_ui_http_ikev2_sess_resume_reset_key(doc,root_node,http_conn,http_bus_sess,http_req,ctx);
    if( err ){
  		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_REQ_HANDLER_IKEV2_SESS_RESUME_RESET_KEY_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  		goto error;
    }

  }else if( !strcmp(action_str,"config_backup_save") ){

  	err = _rhp_ui_http_cfg_bkup_save(doc,root_node,http_conn,http_bus_sess,http_req,ctx);
    if( err ){
  		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_REQ_HANDLER_CFG_BKUP_SAVE_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  		goto error;
    }

  }else if( !strcmp(action_str,"config_backup_restore") ){

  	err = _rhp_ui_http_cfg_bkup_restore_0(doc,root_node,http_conn,http_bus_sess,http_req,ctx);
    if( err ){
  		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_REQ_HANDLER_CFG_BKUP_RESTORE_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  		goto error;
    }

  }else if( !strcmp(action_str,"packet_capture_start") ){

  	err = _rhp_ui_http_packet_capture_start(doc,root_node,http_conn,http_bus_sess,http_req,ctx);
    if( err ){
  		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_REQ_HANDLER_PACKET_CAPTURE_START_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  		goto error;
    }

  }else if( !strcmp(action_str,"packet_capture_save") ){

  	err = _rhp_ui_http_packet_capture_save(doc,root_node,http_conn,http_bus_sess,http_req,ctx);
    if( err ){
  		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_REQ_HANDLER_PACKET_CAPTURE_SAVE_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  		goto error;
    }

  }else if( !strcmp(action_str,"packet_capture_status") ){

  	err = _rhp_ui_http_packet_capture_status(doc,root_node,http_conn,http_bus_sess,http_req,ctx);
    if( err ){
  		RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_REQ_HANDLER_PACKET_CAPTURE_STATUS_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  		goto error;
    }

#ifdef RHP_MEMORY_DBG
  }else if( !strcmp(action_str,"memory_dbg") ){

  	err = 	_rhp_ui_http_memory_dbg(doc,root_node,http_conn,http_bus_sess,http_req,ctx);

  	if( err ){
  		RHP_TRC(0,RHPTRCID_UI_HTTP_TX_DMY_PACKET_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  		goto error;
    }

#endif // RHP_MEMORY_DBG

  }else if( !strcmp(action_str,"tx_dummy_pkt") ){

  	err = _rhp_ui_http_tx_dmy_packet(doc,root_node,http_conn,http_bus_sess,http_req,ctx);

  	if( err ){
  		RHP_TRC(0,RHPTRCID_UI_HTTP_TX_DMY_PACKET_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
  		goto error;
    }

  }else{
    RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_REQ_HANDLER_UNKNOWN_ACTION,"xxx",http_conn,http_bus_sess,http_req);
    err = -ENOENT;
    goto close_conn;
  }

  RHP_UI_HTTP_UNLOCK();

  if( action_str ){
  	_rhp_free(action_str);
  }

	RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_REQ_HANDLER_RTRN,"xxx",http_conn,http_bus_sess,http_req);
  return 0;

error:
	if( err == -EPERM ){
		RHP_LOG_E(RHP_LOG_SRC_UI,http_bus_sess->user_realm_id,RHP_LOG_ID_UI_HTTP_NOT_PERMITTED,"ss",http_bus_sess->user_name,action_str);
	}else if( err != -ENOENT &&
						err != RHP_STATUS_CLOSE_HTTP_CONN &&
						err != RHP_STATUS_HTTP_REQ_PENDING ){
		RHP_LOG_E(RHP_LOG_SRC_UI,http_bus_sess->user_realm_id,RHP_LOG_ID_UI_HTTP_HANDLE_ERR,"ssE",http_bus_sess->user_name,action_str,err);
	}

close_conn:
	RHP_UI_HTTP_UNLOCK();

	if( action_str ){
		_rhp_free(action_str);
	}

	RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_REQ_HANDLER_ERR,"xxxE",http_conn,http_bus_sess,http_req,err);
	return err;
}

void rhp_ui_http_vpn_bus_btx_async_cleanup(void* ctx)
{
	rhp_vpn_ref* vpn_ref = (rhp_vpn_ref*)ctx;
  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_BUS_BTX_ASYNC_CLEANUP,"xx",vpn_ref,RHP_VPN_REF(vpn_ref));
	rhp_vpn_unhold(vpn_ref); // (*x*)
}

int rhp_ui_http_vpn_added_serialize(void* http_bus_sess_d,void* ctx,void* writer,int idx)
{
	rhp_http_bus_session* http_bus_sess = (rhp_http_bus_session*) http_bus_sess_d;
	rhp_vpn_ref* vpn_ref = (rhp_vpn_ref*)ctx;
	rhp_vpn* vpn = RHP_VPN_REF(vpn_ref);

  int err = -EINVAL;
  int n = 0;
  int n2 = 0;

  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_ADDED_SERIALIZE,"xxdxpux",http_bus_sess,writer,idx,vpn,RHP_VPN_UNIQUE_ID_SIZE,vpn->unique_id,vpn->vpn_realm_id,vpn->rlm);

  n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"rhp_http_bus_record");
  if(n < 0) {
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"index","%d",idx);
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"service",(xmlChar*)"ui_http_vpn");
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"action",(xmlChar*)"vpn_added");
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"session_id","%llu",http_bus_sess->session_id);
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"vpn_realm_id","%lu",vpn->vpn_realm_id);
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"vpn_unique_id",
			"0x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
			vpn->unique_id[0],vpn->unique_id[1],vpn->unique_id[2],vpn->unique_id[3],vpn->unique_id[4],vpn->unique_id[5],vpn->unique_id[6],vpn->unique_id[7],
			vpn->unique_id[8],vpn->unique_id[9],vpn->unique_id[10],vpn->unique_id[11],vpn->unique_id[12],vpn->unique_id[13],vpn->unique_id[14],vpn->unique_id[15]);
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  if( vpn->auto_reconnect_retries ){

  	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"vpn_auto_reconnect_retries","%d",vpn->auto_reconnect_retries);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		n2 += n;
  }


  n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
  if(n < 0) {
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_ADDED_SERIALIZE_RTRN,"xxd",http_bus_sess,vpn,n2);
  return n2;

error:
	RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_ADDED_SERIALIZE_ERR,"xxE",http_bus_sess,vpn,err);
  return err;
}

int rhp_ui_http_vpn_deleted_serialize(void* http_bus_sess_d,void* ctx,void* writer,int idx)
{
	rhp_http_bus_session* http_bus_sess = (rhp_http_bus_session*) http_bus_sess_d;
	rhp_vpn_ref* vpn_ref = (rhp_vpn_ref*)ctx;
	rhp_vpn* vpn = RHP_VPN_REF(vpn_ref);

  int err = -EINVAL;
  int n = 0;
  int n2 = 0;


  //
  // [CAUTION]
  //  This call is in deleting vpn context. So, nobody change the values of vpn->xxx
  //  and vpn->lock is not acquired here.
  //


  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_DELETED_SERIALIZE,"xxdxpux",http_bus_sess,writer,idx,vpn,RHP_VPN_UNIQUE_ID_SIZE,vpn->unique_id,vpn->vpn_realm_id,vpn->rlm);

  n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"rhp_http_bus_record");
  if(n < 0) {
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"index","%d",idx);
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"service",(xmlChar*)"ui_http_vpn");
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  if( !vpn->established && vpn->is_initiated_by_user ){

  	n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"action",(xmlChar*)"vpn_connect_i_error");
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		n2 += n;

  }else{

  	n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"action",(xmlChar*)"vpn_deleted");
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		n2 += n;
  }

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"session_id","%llu",http_bus_sess->session_id);
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"vpn_realm_id","%lu",vpn->vpn_realm_id);
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"vpn_unique_id",
			"0x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
			vpn->unique_id[0],vpn->unique_id[1],vpn->unique_id[2],vpn->unique_id[3],vpn->unique_id[4],vpn->unique_id[5],vpn->unique_id[6],vpn->unique_id[7],
			vpn->unique_id[8],vpn->unique_id[9],vpn->unique_id[10],vpn->unique_id[11],vpn->unique_id[12],vpn->unique_id[13],vpn->unique_id[14],vpn->unique_id[15]);
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;


	if( vpn->is_configured_peer ){

		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"is_configured_peer","%d",vpn->is_configured_peer);
	  if(n < 0){
	    err = -ENOMEM;
	    RHP_BUG("");
	    goto error;
	  }
	  n2 += n;
	}

  {
		char *id_type,*id_str;

		err = rhp_ikev2_id_to_string(&(vpn->peer_id),&id_type,&id_str);
		if( err ){
	    goto error;
		}

		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"peerid_type","%s",id_type);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			_rhp_free(id_type);
			_rhp_free(id_str);
	    goto error;
		}
		n2 += n;

		n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"peerid","%s",id_str);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			_rhp_free(id_type);
			_rhp_free(id_str);
	    goto error;
		}
		n2 += n;

		_rhp_free(id_type);
		_rhp_free(id_str);
	}

  if( vpn->auto_reconnect_retries ){

  	int auto_reconnect_failed = 0;

  	if( vpn->auto_reconnect_retries >= rhp_gcfg_vpn_auto_reconnect_max_retries ){
  		auto_reconnect_failed = 1;
  	}

  	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"vpn_auto_reconnect_retries","%d",vpn->auto_reconnect_retries);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		n2 += n;

  	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"auto_reconnect_failed","%d",auto_reconnect_failed);
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		n2 += n;
  }

  n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
  if(n < 0) {
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_DELETED_SERIALIZE_RTRN,"xxd",http_bus_sess,vpn,n2);
  return n2;

error:
  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_DELETED_SERIALIZE_ERR,"xxE",http_bus_sess,vpn,err);
  return err;
}


int rhp_ui_http_vpn_established_serialize(void* http_bus_sess_d,void* ctx,void* writer,int idx)
{
	rhp_http_bus_session* http_bus_sess = (rhp_http_bus_session*) http_bus_sess_d;
	rhp_vpn_ref* vpn_ref = (rhp_vpn_ref*)ctx;
	rhp_vpn* vpn = RHP_VPN_REF(vpn_ref);
  int err = -EINVAL;
  int n = 0;
  int n2 = 0;

  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_ESTABLISHED_SERIALIZE,"xxdxpux",http_bus_sess,writer,idx,vpn,RHP_VPN_UNIQUE_ID_SIZE,vpn->unique_id,vpn->vpn_realm_id,vpn->rlm);

  n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"rhp_http_bus_record");
  if(n < 0) {
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"index","%d",idx);
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"service",(xmlChar*)"ui_http_vpn");
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"action",(xmlChar*)"vpn_established");
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"session_id","%llu",http_bus_sess->session_id);
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"vpn_realm_id","%lu",vpn->vpn_realm_id);
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"vpn_unique_id",
			"0x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
			vpn->unique_id[0],vpn->unique_id[1],vpn->unique_id[2],vpn->unique_id[3],vpn->unique_id[4],vpn->unique_id[5],vpn->unique_id[6],vpn->unique_id[7],
			vpn->unique_id[8],vpn->unique_id[9],vpn->unique_id[10],vpn->unique_id[11],vpn->unique_id[12],vpn->unique_id[13],vpn->unique_id[14],vpn->unique_id[15]);
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
  if(n < 0) {
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

	RHP_LOG_N(RHP_LOG_SRC_VPNMNG,vpn->vpn_realm_id,RHP_LOG_ID_VPN_ESTABLISHED,"IAsN",&(vpn->peer_id),&(vpn->peer_addr),vpn->peer_fqdn,vpn->unique_id);

  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_ESTABLISHED_SERIALIZE_RTRN,"xxd",http_bus_sess,vpn,n2);
  return n2;

error:
  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_ESTABLISHED_SERIALIZE_ERR,"xxE",http_bus_sess,vpn,err);
  return err;
}

int rhp_ui_http_vpn_close_serialize(void* http_bus_sess_d,void* ctx,void* writer,int idx)
{
	rhp_http_bus_session* http_bus_sess = (rhp_http_bus_session*) http_bus_sess_d;
	rhp_vpn_ref* vpn_ref = (rhp_vpn_ref*)ctx;
	rhp_vpn* vpn = RHP_VPN_REF(vpn_ref);

  int err = -EINVAL;
  int n = 0;
  int n2 = 0;

  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_CLOSE_SERIALIZE,"xxdxpux",http_bus_sess,writer,idx,vpn,RHP_VPN_UNIQUE_ID_SIZE,vpn->unique_id,vpn->vpn_realm_id,vpn->rlm);

  n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"rhp_http_bus_record");
  if(n < 0) {
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"index","%d",idx);
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"service",(xmlChar*)"ui_http_vpn");
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"action",(xmlChar*)"vpn_closing");
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"session_id","%llu",http_bus_sess->session_id);
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"vpn_realm_id","%lu",vpn->vpn_realm_id); // vpn_realm_id: Immutable
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"vpn_unique_id", // unique_id[]: Immutable
			"0x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
			vpn->unique_id[0],vpn->unique_id[1],vpn->unique_id[2],vpn->unique_id[3],vpn->unique_id[4],vpn->unique_id[5],vpn->unique_id[6],vpn->unique_id[7],
			vpn->unique_id[8],vpn->unique_id[9],vpn->unique_id[10],vpn->unique_id[11],vpn->unique_id[12],vpn->unique_id[13],vpn->unique_id[14],vpn->unique_id[15]);
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
  if(n < 0) {
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_CLOSE_SERIALIZE_RTRN,"xxd",http_bus_sess,vpn,n2);
  return n2;

error:
  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_CLOSE_SERIALIZE_ERR,"xxE",http_bus_sess,vpn,err);
  return err;
}

int rhp_ui_http_vpn_mobike_i_rt_check_start_serialize(void* http_bus_sess_d,void* ctx,void* writer,int idx)
{
	rhp_http_bus_session* http_bus_sess = (rhp_http_bus_session*) http_bus_sess_d;
	rhp_vpn_ref* vpn_ref = (rhp_vpn_ref*)ctx;
	rhp_vpn* vpn = RHP_VPN_REF(vpn_ref);

  int err = -EINVAL;
  int n = 0;
  int n2 = 0;

  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_MOBIKE_I_RT_CHECK_START_SERIALIZE,"xxdxpux",http_bus_sess,writer,idx,vpn,RHP_VPN_UNIQUE_ID_SIZE,vpn->unique_id,vpn->vpn_realm_id,vpn->rlm);

  n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"rhp_http_bus_record");
  if(n < 0) {
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"index","%d",idx);
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"service",(xmlChar*)"ui_http_vpn");
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"action",(xmlChar*)"vpn_mobike_i_routability_check_start");
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"session_id","%llu",http_bus_sess->session_id);
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"vpn_realm_id","%lu",vpn->vpn_realm_id);
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"vpn_unique_id",
			"0x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
			vpn->unique_id[0],vpn->unique_id[1],vpn->unique_id[2],vpn->unique_id[3],vpn->unique_id[4],vpn->unique_id[5],vpn->unique_id[6],vpn->unique_id[7],
			vpn->unique_id[8],vpn->unique_id[9],vpn->unique_id[10],vpn->unique_id[11],vpn->unique_id[12],vpn->unique_id[13],vpn->unique_id[14],vpn->unique_id[15]);
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
  if(n < 0) {
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_MOBIKE_I_RT_CHECK_START_SERIALIZE_RTRN,"xxd",http_bus_sess,vpn,n2);
  return n2;

error:
  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_MOBIKE_I_RT_CHECK_START_SERIALIZE_ERR,"xxE",http_bus_sess,vpn,err);
  return err;
}

int rhp_ui_http_vpn_mobike_i_rt_check_finished_serialize(void* http_bus_sess_d,void* ctx,void* writer,int idx)
{
	rhp_http_bus_session* http_bus_sess = (rhp_http_bus_session*) http_bus_sess_d;
	rhp_vpn_ref* vpn_ref = (rhp_vpn_ref*)ctx;
	rhp_vpn* vpn = RHP_VPN_REF(vpn_ref);

  int err = -EINVAL;
  int n = 0;
  int n2 = 0;

  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_MOBIKE_I_RT_CHECK_FINISHED_SERIALIZE,"xxdxpux",http_bus_sess,writer,idx,vpn,RHP_VPN_UNIQUE_ID_SIZE,vpn->unique_id,vpn->vpn_realm_id,vpn->rlm);

  n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"rhp_http_bus_record");
  if(n < 0) {
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"index","%d",idx);
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"service",(xmlChar*)"ui_http_vpn");
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"action",(xmlChar*)"vpn_mobike_i_routability_check_finished");
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"session_id","%llu",http_bus_sess->session_id);
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"vpn_realm_id","%lu",vpn->vpn_realm_id);
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"vpn_unique_id",
			"0x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
			vpn->unique_id[0],vpn->unique_id[1],vpn->unique_id[2],vpn->unique_id[3],vpn->unique_id[4],vpn->unique_id[5],vpn->unique_id[6],vpn->unique_id[7],
			vpn->unique_id[8],vpn->unique_id[9],vpn->unique_id[10],vpn->unique_id[11],vpn->unique_id[12],vpn->unique_id[13],vpn->unique_id[14],vpn->unique_id[15]);
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
  if(n < 0) {
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_MOBIKE_I_RT_CHECK_FINISHED_SERIALIZE_RTRN,"xxd",http_bus_sess,vpn,n2);
  return n2;

error:
  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_MOBIKE_I_RT_CHECK_FINISHED_SERIALIZE_ERR,"xxE",http_bus_sess,vpn,err);
  return err;
}

int rhp_ui_http_vpn_mobike_r_net_outage_detected_serialize(void* http_bus_sess_d,void* ctx,void* writer,int idx)
{
	rhp_http_bus_session* http_bus_sess = (rhp_http_bus_session*) http_bus_sess_d;
	rhp_vpn_ref* vpn_ref = (rhp_vpn_ref*)ctx;
	rhp_vpn* vpn = RHP_VPN_REF(vpn_ref);


  int err = -EINVAL;
  int n = 0;
  int n2 = 0;

  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_MOBIKE_R_NET_OUTAGE_DETECTED_SERIALIZE,"xxdxpux",http_bus_sess,writer,idx,vpn,RHP_VPN_UNIQUE_ID_SIZE,vpn->unique_id,vpn->vpn_realm_id,vpn->rlm);

  n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"rhp_http_bus_record");
  if(n < 0) {
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"index","%d",idx);
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"service",(xmlChar*)"ui_http_vpn");
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"action",(xmlChar*)"vpn_mobike_r_net_outage_detected");
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"session_id","%llu",http_bus_sess->session_id);
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"vpn_realm_id","%lu",vpn->vpn_realm_id);
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"vpn_unique_id",
			"0x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
			vpn->unique_id[0],vpn->unique_id[1],vpn->unique_id[2],vpn->unique_id[3],vpn->unique_id[4],vpn->unique_id[5],vpn->unique_id[6],vpn->unique_id[7],
			vpn->unique_id[8],vpn->unique_id[9],vpn->unique_id[10],vpn->unique_id[11],vpn->unique_id[12],vpn->unique_id[13],vpn->unique_id[14],vpn->unique_id[15]);
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
  if(n < 0) {
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_MOBIKE_R_NET_OUTAGE_DETECTED_SERIALIZE_RTRN,"xxd",http_bus_sess,vpn,n2);
  return n2;

error:
  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_MOBIKE_R_NET_OUTAGE_DETECTED_SERIALIZE_ERR,"xxE",http_bus_sess,vpn,err);
  return err;
}

int rhp_ui_http_vpn_mobike_r_net_outage_finished_serialize(void* http_bus_sess_d,void* ctx,void* writer,int idx)
{
	rhp_http_bus_session* http_bus_sess = (rhp_http_bus_session*) http_bus_sess_d;
	rhp_vpn_ref* vpn_ref = (rhp_vpn_ref*)ctx;
	rhp_vpn* vpn = RHP_VPN_REF(vpn_ref);

  int err = -EINVAL;
  int n = 0;
  int n2 = 0;

  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_MOBIKE_R_NET_OUTAGE_FINISHED_SERIALIZE,"xxdxpux",http_bus_sess,writer,idx,vpn,RHP_VPN_UNIQUE_ID_SIZE,vpn->unique_id,vpn->vpn_realm_id,vpn->rlm);

  n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"rhp_http_bus_record");
  if(n < 0) {
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"index","%d",idx);
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"service",(xmlChar*)"ui_http_vpn");
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"action",(xmlChar*)"vpn_mobike_r_net_outage_finished");
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"session_id","%llu",http_bus_sess->session_id);
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"vpn_realm_id","%lu",vpn->vpn_realm_id);
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"vpn_unique_id",
			"0x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
			vpn->unique_id[0],vpn->unique_id[1],vpn->unique_id[2],vpn->unique_id[3],vpn->unique_id[4],vpn->unique_id[5],vpn->unique_id[6],vpn->unique_id[7],
			vpn->unique_id[8],vpn->unique_id[9],vpn->unique_id[10],vpn->unique_id[11],vpn->unique_id[12],vpn->unique_id[13],vpn->unique_id[14],vpn->unique_id[15]);
  if(n < 0){
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
  if(n < 0) {
    err = -ENOMEM;
    RHP_BUG("");
    goto error;
  }
  n2 += n;

  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_MOBIKE_R_NET_OUTAGE_FINISHED_SERIALIZE_RTRN,"xxd",http_bus_sess,vpn,n2);
  return n2;

error:
  RHP_TRC(0,RHPTRCID_UI_HTTP_VPN_MOBIKE_R_NET_OUTAGE_FINISHED_SERIALIZE_ERR,"xxE",http_bus_sess,vpn,err);
  return err;
}



void rhp_ui_http_btx_async_conn_close_cleanup(void* ctx)
{
	_rhp_ui_http_vpn_conn_i_task_free_ctx(ctx);
}



static int _rhp_ui_http_cfg_bkup_restore_serialize(void* http_bus_sess_d,void* ctx,void* writer,int idx)
{
  int err = -EINVAL;
  rhp_http_bus_session* http_bus_sess = (rhp_http_bus_session*)http_bus_sess_d;
  int n = 0;
  int n2 = 0;

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_BKUP_RESTORE_1_SERIALIZE,"xqxdx",http_bus_sess,http_bus_sess->session_id,writer,idx,ctx);

	n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"rhp_http_bus_record");
	if(n < 0) {
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"index","%d",idx);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"service",(xmlChar*)"ui_http_vpn");
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	if( !((int)ctx) ){

		n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"action",(xmlChar*)"config_archive_restore_done");
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		n2 += n;

	}else{

		n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"action",(xmlChar*)"config_archive_restore_error");
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		n2 += n;
	}

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"session_id","%llu",http_bus_sess->session_id);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;


	n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
	if(n < 0) {
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_BKUP_RESTORE_1_SERIALIZE_RTRN,"xd",http_bus_sess,n2);
  return n2;

error:
  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_BKUP_RESTORE_1_SERIALIZE_ERR,"xE",http_bus_sess,err);
  return err;
}

static void _rhp_ui_http_cfg_bkup_restore_finished(int err,void* ctx_d)
{
	rhp_ui_http_cfg_arch_ctx* ctx = (rhp_ui_http_cfg_arch_ctx*)ctx_d;

	RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_BKUP_RESTORE_1_FINISHED,"Exqs",err,ctx,ctx->session_id,ctx->user_name);

	rhp_http_bus_send_async(ctx->session_id,ctx->user_name,0,1,0,
			_rhp_ui_http_cfg_bkup_restore_serialize,(void*)err);

	RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_BKUP_RESTORE_1_FINISHED_RTRN,"Ex",err,ctx);
	return;
}

static void _rhp_ui_http_cfg_bkup_restore_bh_task(int worker_index,void* ctx)
{
	int err = -EINVAL;
  rhp_ui_http_cfg_arch_ctx* cb_ctx = (rhp_ui_http_cfg_arch_ctx*)ctx;
  char *pw_path = NULL, *pw_cont = NULL;
	rhp_cmd_tlv_list tlvlst;

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_BKUP_RESTORE_1_BH_TASK,"dxd",worker_index,ctx,cb_ctx->err_resp);

	memset(&tlvlst,0,sizeof(rhp_cmd_tlv_list));

  if( cb_ctx->err_resp ){
  	err = cb_ctx->err_resp;
  	goto error;
  }

  {
		pw_path = (char*)_rhp_malloc( strlen(rhp_home_dir) + strlen("/tmp/rockhopper_rcfg_restore_pw") + 1 );
		if( pw_path == NULL ){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		pw_path[0] = '\0';

		sprintf(pw_path,"%s/%s",rhp_home_dir,"tmp/rockhopper_rcfg_restore_pw");

		unlink(pw_path);


		pw_cont = (char*)_rhp_malloc( strlen(cb_ctx->file_pw)*2 + 4 );
		if( pw_cont == NULL ){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		pw_cont[0] = '\0';

		sprintf(pw_cont,"%s\n%s\n",cb_ctx->file_pw,cb_ctx->file_pw);


		err = rhp_file_write(pw_path,(u8*)pw_cont,strlen(pw_cont),(S_IRUSR | S_IWUSR | S_IXUSR));
		if( err ){
			RHP_BUG("%d",err);
			goto error;
		}
	}

	{
		err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_STRING,"RHP_CFG_BKUP_ACTION",(strlen("RESTORE") + 1),"RESTORE");
		if( err ){
			RHP_BUG("");
			goto error;
		}

		err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_STRING,"RHP_CFG_BKUP_PW",(strlen(pw_path) + 1),pw_path);
		if( err ){
			RHP_BUG("");
			goto error;
		}

		err = rhp_cmd_tlv_add(&tlvlst,RHP_CMD_TLV_STRING,"RHP_CFG_BKUP_HOME_DIR",
				(strlen(rhp_home_dir) + 1),rhp_home_dir);

		if( err ){
			RHP_BUG("");
			goto error;
		}

		err = rhp_cmd_exec(rhp_cfg_bkup_cmd_path,&tlvlst,1);
		if( err ){
			RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_BKUP_RESTORE_1_BH_TASK_CMD_EXEC_ERR,"dxE",worker_index,ctx,err);
			goto error;
		}

		rhp_cmd_tlv_clear(&tlvlst);
	}


	_rhp_ui_http_cfg_bkup_restore_finished(0,cb_ctx);

	_rhp_ui_http_cfg_arch_ctx_free(cb_ctx);

	unlink(pw_path);
	_rhp_free(pw_path);
	_rhp_free(pw_cont);

	RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_BKUP_RESTORE_1_BH_TASK_RTRN,"dx",worker_index,ctx);
	return;


error:
	_rhp_ui_http_cfg_bkup_restore_finished(err,cb_ctx);
	_rhp_ui_http_cfg_arch_ctx_free(cb_ctx);
	if( pw_path ){
		unlink(pw_path);
		_rhp_free(pw_path);
	}
	if( pw_cont ){
		_rhp_free(pw_cont);
	}
	rhp_cmd_tlv_clear(&tlvlst);

	RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_BKUP_RESTORE_1_BH_TASK_ERR,"dxE",worker_index,ctx,err);
	return;
}

static int _rhp_ui_http_cfg_bkup_restore_1(rhp_http_conn* http_conn)
{
  int err = -EINVAL;
  rhp_http_request* http_req = http_conn->http_req;
  rhp_http_body_multipart_form_data* multipart_from_data = http_req->multipart_form_data;
  rhp_http_body_part *bpart_file_pw, *bpart_file,*bpart_session_id;
  char* path = NULL;
  int file_pw_len = 0;
  char* file_pw = NULL;
	int session_id_len;
	char* session_id_str = NULL;
  u64 session_id = 0;
  rhp_ui_http_cfg_arch_ctx *cb_ctx = NULL,*cb_ctx0 = NULL;

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_BKUP_RESTORE_1,"xxx",http_conn,http_req,multipart_from_data);

  if( http_conn->user_realm_id != 0 ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_BKUP_RESTORE_1_NO_FILE_PASSWORD_USER_NOT_ALLOWED,"xu",http_conn,http_conn->user_realm_id);
    err = -EPERM;
    goto error;
  }

  {
    char* endp;

  	bpart_session_id = multipart_from_data->get_body_part(multipart_from_data,"upload_config_bus_session_id");
		if( bpart_session_id == NULL || bpart_session_id->data == NULL ){
			err = RHP_STATUS_INVALID_MSG;
			RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_BKUP_RESTORE_1_NO_HTTP_BUS_SESSION_ID,"xx",http_conn,http_req);
			goto error;
		}

		session_id_len = bpart_session_id->data_len;

		session_id_str = (char*)_rhp_malloc(session_id_len + 1);
		if( session_id_str == NULL ){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}

		memcpy(session_id_str,bpart_session_id->data,session_id_len);
		session_id_str[session_id_len] = '\0';

    if( rhp_http_bus_check_session_id(session_id_str) ){
    	err = -ENOENT;
     RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_BKUP_RESTORE_1_BAD_HTTP_BUS_SESSION_ID,"xxs",http_conn,http_req,session_id_str);
     goto error;
    }

    session_id = strtoull((char*)session_id_str,&endp,0);

    if( (session_id == ULLONG_MAX && errno == ERANGE) || *endp != '\0' ){
    	err = -ENOENT;
      RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_BKUP_RESTORE_1_BAD_HTTP_BUS_SESSION_ID_2,"xxs",http_conn,http_req,session_id_str);
     goto error;
    }

    {
    	rhp_http_bus_session* http_bus_sess = rhp_http_bus_sess_get(session_id,http_conn->user_name);

    	if( http_bus_sess == NULL ){
    		err = -ENOENT;
        RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_BKUP_RESTORE_1_BAD_HTTP_BUS_SESSION_ID_3,"xxs",http_conn,http_req,session_id_str);
        goto error;
    	}

      RHP_LOCK(&(http_bus_sess->lock));

    	cb_ctx0 = (rhp_ui_http_cfg_arch_ctx*)http_bus_sess->cfg_restore_cb_ctx;
    	if( cb_ctx0 ){
    		http_bus_sess->cfg_restore_cb_ctx = NULL;
    		http_bus_sess->cfg_save_cb_ctx_free = NULL;
    	}

      RHP_UNLOCK(&(http_bus_sess->lock));

    	rhp_http_bus_sess_unhold(http_bus_sess);
    }
  }

  {
  	u8* pw_data = NULL;

  	bpart_file_pw = multipart_from_data->get_body_part(multipart_from_data,"upload_config_password");
		if( bpart_file_pw && bpart_file_pw->data ){

			file_pw_len = bpart_file_pw->data_len;
			pw_data = bpart_file_pw->data;

		}else{

			if( cb_ctx0 ){
				file_pw_len = strlen(cb_ctx0->file_pw);
				pw_data = (u8*)cb_ctx0->file_pw;
			}
		}

		if( file_pw_len < 1 ){
			err = RHP_STATUS_INVALID_MSG;
			RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_BKUP_RESTORE_1_NO_FILE_PASSWORD,"xx",http_conn,http_req);
			goto error;
		}

		if( file_pw_len > (RHP_CFG_BKUP_MAX_PW_LEN - 1) ){
			err = RHP_STATUS_INVALID_MSG;
			RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_BKUP_RESTORE_1_TOO_LONG_FILE_PASSWORD,"xxx",http_conn,http_req,bpart_file_pw);
			goto error;
		}

		file_pw = (char*)_rhp_malloc(file_pw_len + 1);
		if( file_pw == NULL ){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}

		memcpy(file_pw,pw_data,file_pw_len);
		file_pw[file_pw_len] = '\0';
  }

  {
    rhp_http_header* bpart_header;

    bpart_file = multipart_from_data->get_body_part(multipart_from_data,"upload_config");
		if( bpart_file == NULL || bpart_file->data == NULL ){
			err = RHP_STATUS_INVALID_MSG;
			RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_BKUP_RESTORE_1_NO_CFG_FILE,"xx",http_conn,http_req);
			goto error;
		}

		bpart_header = bpart_file->get_header(bpart_file,"Content-Type");
		if( bpart_header == NULL || bpart_header->value == NULL ){
			err = -ENOENT;
			RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_BKUP_RESTORE_1_NO_CONTENT_TYPE,"xx",http_req,bpart_file);
			goto error;
		}

		if( (strcasestr(bpart_header->value,"application/octet-stream") == NULL) ){
			err = RHP_STATUS_INVALID_MSG;
			RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_BKUP_RESTORE_1_NOT_APP_OCTET_STREAM,"xsx",http_req,bpart_header->value,bpart_file);
			goto error;
		}
  }

  {
		path = (char*)_rhp_malloc( strlen(rhp_home_dir) + strlen("restore/rockhopper_restore.rcfg") + 2 );
		if( path == NULL ){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		path[0] = '\0';

		sprintf(path,"%s/%s",rhp_home_dir,"restore/rockhopper_restore.rcfg");

		err = rhp_file_write(path,(u8*)bpart_file->data,bpart_file->data_len,(S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP));
		if( err ){
			RHP_BUG("%d",err);
			goto error;
		}
	}


  cb_ctx = _rhp_ui_http_cfg_arch_ctx_alloc(session_id,http_conn->user_name,path,file_pw);
  if( cb_ctx == NULL ){
  	err = -ENOMEM;
  	RHP_BUG("");
  	goto error;
  }


	err = rhp_wts_add_task(RHP_WTS_DISP_RULE_MISC,RHP_WTS_DISP_LEVEL_HIGH_1,NULL,
			_rhp_ui_http_cfg_bkup_restore_bh_task,(void*)cb_ctx);

	if( err ){
  	RHP_BUG("%d",err);
  	goto error;
  }
	cb_ctx = NULL;

	if( cb_ctx0 ){
		_rhp_ui_http_cfg_arch_ctx_free(cb_ctx0);
		cb_ctx0 = NULL;
	}

  _rhp_free(path);
	_rhp_free_zero(file_pw,file_pw_len);
	_rhp_free(session_id_str);

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_BKUP_RESTORE_1_RTRN,"xx",http_conn,http_req);
  return 0;

error:
  if( session_id ){

  	if( cb_ctx == NULL ){
  		cb_ctx = _rhp_ui_http_cfg_arch_ctx_alloc(session_id,http_conn->user_name,path,file_pw);
  	}

  	if( cb_ctx ){

  		if( !err ){
  			RHP_BUG("_rhp_ui_http_cfg_bkup_restore_1: invalid err");
  		}

  		cb_ctx->err_resp = err;

  		if( !rhp_wts_add_task(RHP_WTS_DISP_RULE_MISC,RHP_WTS_DISP_LEVEL_HIGH_1,NULL,
  			_rhp_ui_http_cfg_bkup_restore_bh_task,(void*)cb_ctx) ){

  			cb_ctx = NULL;
  		}
  	}
  }

  if( path ){
	  _rhp_free(path);
  }
  if( file_pw ){
  	_rhp_free_zero(file_pw,file_pw_len);
  }
  if( session_id_str ){
  	_rhp_free(session_id_str);
  }
  if( cb_ctx ){
  	_rhp_ui_http_cfg_arch_ctx_free(cb_ctx);
  }
	if( cb_ctx0 ){
		_rhp_ui_http_cfg_arch_ctx_free(cb_ctx0);
	}

  RHP_TRC(0,RHPTRCID_UI_HTTP_CFG_BKUP_RESTORE_1_ERR,"xxE",http_conn,http_req,err);
  return err;
}


static int _rhp_ui_http_upload_cert_file_serialize(void* http_bus_sess_d,void* ctx,void* writer,int idx)
{
	rhp_ipcmsg_syspxy_cfg_sub* cfg_sub_dt = (rhp_ipcmsg_syspxy_cfg_sub*)ctx;
  int err = -EINVAL;
  rhp_http_bus_session* http_bus_sess = (rhp_http_bus_session*)http_bus_sess_d;
  int n = 0;
  int n2 = 0;

  RHP_TRC(0,RHPTRCID_UI_HTTP_UPLOAD_CERT_FILE_SERIALIZE,"xxdxux",http_bus_sess,writer,idx,cfg_sub_dt,cfg_sub_dt->target_rlm_id,cfg_sub_dt->priv[0]);

	n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"rhp_http_bus_record");
	if(n < 0) {
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"index","%d",idx);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"service",(xmlChar*)"ui_http_vpn");
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"vpn_realm_id","%lu",cfg_sub_dt->target_rlm_id);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;


	if( cfg_sub_dt->result ){

		n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"action",(xmlChar*)"config_cert_file_upload_done");
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		n2 += n;

	}else{

		n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"action",(xmlChar*)"config_cert_file_upload_error");
		if(n < 0){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		n2 += n;
	}


	if( cfg_sub_dt->priv[0] & RHP_IPC_SYSPXY_CFG_UPDATE_CERT_FILE_PKCS12 ){
		n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"pkcs12",(xmlChar*)"true");
	}else{
		n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"pkcs12",(xmlChar*)"false");
	}
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	if( cfg_sub_dt->priv[0] & RHP_IPC_SYSPXY_CFG_UPDATE_CERT_FILE_MY_CERT_PEM ){
		n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"my_cert_pem",(xmlChar*)"true");
	}else{
		n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"my_cert_pem",(xmlChar*)"false");
	}
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	if( cfg_sub_dt->priv[0] & RHP_IPC_SYSPXY_CFG_UPDATE_CERT_FILE_MY_PRIVKEY_PEM ){
		n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"my_privkey_pem",(xmlChar*)"true");
	}else{
		n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"my_privkey_pem",(xmlChar*)"false");
	}
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	if( cfg_sub_dt->priv[0] & RHP_IPC_SYSPXY_CFG_UPDATE_CERT_FILE_CA_PEM ){
		n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"ca_cert_pem",(xmlChar*)"true");
	}else{
		n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"ca_cert_pem",(xmlChar*)"false");
	}
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	if( cfg_sub_dt->priv[0] & RHP_IPC_SYSPXY_CFG_UPDATE_CERT_FILE_CRL_PEM ){
		n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"crl_pem",(xmlChar*)"true");
	}else{
		n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"crl_pem",(xmlChar*)"false");
	}
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;


	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"session_id","%llu",http_bus_sess->session_id);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
	if(n < 0) {
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  RHP_TRC(0,RHPTRCID_UI_HTTP_UPLOAD_CERT_FILE_SERIALIZE_RTRN,"xxd",http_bus_sess,cfg_sub_dt,n2);
  return n2;

error:
  RHP_TRC(0,RHPTRCID_UI_HTTP_UPLOAD_CERT_FILE_SERIALIZE_ERR,"xxE",http_bus_sess,cfg_sub_dt,err);
  return err;
}

int rhp_ui_http_upload_cert_file_bh(rhp_http_bus_session* http_bus_sess,rhp_ipcmsg_syspxy_cfg_sub* cfg_sub_dt)
{
  RHP_TRC(0,RHPTRCID_UI_HTTP_UPLOAD_CERT_FILE_BH,"xpx",http_bus_sess,cfg_sub_dt->len,cfg_sub_dt,NULL);

	rhp_http_bus_send_async_unlocked(http_bus_sess,cfg_sub_dt->target_rlm_id,1,0,
			_rhp_ui_http_upload_cert_file_serialize,(void*)cfg_sub_dt);

  RHP_TRC(0,RHPTRCID_UI_HTTP_UPLOAD_CERT_FILE_BH_RTRN,"xx",http_bus_sess,cfg_sub_dt);
  return 0;
}


struct _rhp_ui_http_upld_cert_file_async_err {
	u8 tag[4]; // '#UHC'
	u64 bus_session_id;
	unsigned long rlm_id;
	char* user_name;
};
typedef struct _rhp_ui_http_upld_cert_file_async_err rhp_ui_http_upld_cert_file_async_err;

static void _rhp_ui_http_upload_cert_file_async_err_resp_task(int worker_index,void* ctx)
{
	rhp_ui_http_upld_cert_file_async_err* cb_ctx = (rhp_ui_http_upld_cert_file_async_err*)ctx;
	rhp_ipcmsg_syspxy_cfg_sub cfg_sub_dt;

  RHP_TRC(0,RHPTRCID_UI_HTTP_UPLOAD_CERT_FILE_ASYNC_ERR_RESP_TASK,"xqus",cb_ctx,cb_ctx->bus_session_id,cb_ctx->rlm_id,cb_ctx->user_name);

	cfg_sub_dt.cfg_type = RHP_IPC_SYSPXY_CFG_UPLOAD_CERT_FILE;
	cfg_sub_dt.len = sizeof(rhp_ipcmsg_syspxy_cfg_sub);
	cfg_sub_dt.target_rlm_id = cb_ctx->rlm_id;
	cfg_sub_dt.result = 0;

	rhp_http_bus_send_async(cb_ctx->bus_session_id,cb_ctx->user_name,cb_ctx->rlm_id,1,0,
			_rhp_ui_http_upload_cert_file_serialize,(void*)&cfg_sub_dt);

	_rhp_free(cb_ctx->user_name);
	_rhp_free(cb_ctx);

  RHP_TRC(0,RHPTRCID_UI_HTTP_UPLOAD_CERT_FILE_ASYNC_ERR_RESP_TASK_RTRN,"x",cb_ctx);
	return;
}

static int _rhp_ui_http_upload_cert_file_async_err_resp(rhp_http_conn* http_conn,u64 session_id,unsigned long rlm_id)
{
	int err = -EINVAL;
	rhp_ui_http_upld_cert_file_async_err* ctx
	= (rhp_ui_http_upld_cert_file_async_err*)_rhp_malloc(sizeof(rhp_ui_http_upld_cert_file_async_err));

	if( ctx == NULL ){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	memset(ctx,0,sizeof(rhp_ui_http_upld_cert_file_async_err));

	ctx->tag[0] = '#';
	ctx->tag[1] = 'U';
	ctx->tag[2] = 'H';
	ctx->tag[3] = 'C';

	ctx->user_name = (char*)_rhp_malloc(strlen(http_conn->user_name) + 1);
	if( ctx->user_name == NULL ){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	ctx->user_name[0] = '\0';
	strcpy(ctx->user_name,http_conn->user_name);

	ctx->bus_session_id = session_id;
	ctx->rlm_id = rlm_id;

	rhp_wts_add_task(RHP_WTS_DISP_RULE_MISC,RHP_WTS_DISP_LEVEL_HIGH_1,NULL,
			_rhp_ui_http_upload_cert_file_async_err_resp_task,(void*)ctx);

	return 0;

error:
	if( ctx ){
		if( ctx->user_name ){
			_rhp_free(ctx->user_name);
		}
		_rhp_free(ctx);
	}
	return err;
}


static int _rhp_ui_http_upload_cert_file_low_err_serialize(void* http_bus_sess_d,void* ctx,void* writer,int idx)
{
  int err = -EINVAL;
  rhp_http_bus_session* http_bus_sess = (rhp_http_bus_session*)http_bus_sess_d;
  unsigned long rlm_id = (unsigned long)ctx;
  int n = 0;
  int n2 = 0;

  RHP_TRC(0,RHPTRCID_UI_HTTP_UPLOAD_CERT_FILE_LOW_ERR_SERIALIZE,"xxdu",http_bus_sess,writer,idx,rlm_id);

	n = xmlTextWriterStartElement((xmlTextWriterPtr)writer,(xmlChar*)"rhp_http_bus_record");
	if(n < 0) {
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"index","%d",idx);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"service",(xmlChar*)"ui_http_vpn");
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"vpn_realm_id","%lu",rlm_id);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,(xmlChar*)"action",(xmlChar*)"config_cert_file_upload_error");
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterWriteFormatAttribute((xmlTextWriterPtr)writer,(xmlChar*)"session_id","%llu",http_bus_sess->session_id);
	if(n < 0){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

	n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
	if(n < 0) {
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	n2 += n;

  RHP_TRC(0,RHPTRCID_UI_HTTP_UPLOAD_CERT_FILE_LOW_ERR_SERIALIZE_RTRN,"xud",http_bus_sess,rlm_id,n2);
  return n2;

error:
  RHP_TRC(0,RHPTRCID_UI_HTTP_UPLOAD_CERT_FILE_LOW_ERR_SERIALIZE_ERR,"xuE",http_bus_sess,rlm_id,err);
  return err;
}


static int _rhp_ui_http_upload_cert_file_parse_uri(rhp_http_conn* http_conn,
		rhp_http_request* http_req,unsigned long* rlm_id_r,u64* session_id_r,char** rlm_id_str_r)
{
	int err = -EINVAL;
  char *endp,*p;
  char *rlm_id_str = NULL,*rlm_id_str2 = NULL;
  unsigned long rlm_id = -1;
	char* session_id_str = NULL;
  u64 session_id = 0;


	rlm_id_str = http_req->uri + strlen("/protected/certs/");

	p = rlm_id_str;
	while( *p != '\0' ){

		if( *p == '/' ){
			break;
		}

		p++;
	}

	if( p == rlm_id_str || *p != '/' ){
		err = RHP_STATUS_INVALID_MSG;
		RHP_TRC(0,RHPTRCID_UI_HTTP_UPLOAD_CERT_FILE_NO_REALM_ID_1,"xx",http_conn,http_req);
		goto error;
	}

	*p = '\0';

	{
		rlm_id_str2 = (char*)_rhp_malloc(strlen(rlm_id_str) + 1);
		if( rlm_id_str2 == NULL ){
			RHP_BUG("");
			*p = '/';
			err = -ENOMEM;
			goto error;
		}
		rlm_id_str2[0] = '\0';
		strcpy(rlm_id_str2,rlm_id_str);
	}

	rlm_id = strtoul((char*)rlm_id_str,&endp,0);
  if( (rlm_id == ULONG_MAX && errno == ERANGE) || *endp != '\0' ){
  	*p = '/';
  	err = -ENOENT;
  	RHP_TRC(0,RHPTRCID_UI_HTTP_UPLOAD_CERT_FILE_NO_REALM_ID_2,"xxs",http_conn,http_req,rlm_id_str);
  	goto error;
  }
	*p = '/';


	session_id_str = ++p;

	if( *p == '\0' ){
		err = RHP_STATUS_INVALID_MSG;
		RHP_TRC(0,RHPTRCID_UI_HTTP_UPLOAD_CERT_FILE_NO_HTTP_BUS_SESSION_ID,"xx",http_conn,http_req);
		goto error;
	}

  if( rhp_http_bus_check_session_id(session_id_str) ){
  	err = -ENOENT;
  	RHP_TRC(0,RHPTRCID_UI_HTTP_UPLOAD_CERT_FILE_BAD_HTTP_BUS_SESSION_ID,"xxs",http_conn,http_req,session_id_str);
  	goto error;
  }

  session_id = strtoull((char*)session_id_str,&endp,0);

  if( (session_id == ULLONG_MAX && errno == ERANGE) || *endp != '\0' ){
  	err = -ENOENT;
    RHP_TRC(0,RHPTRCID_UI_HTTP_UPLOAD_CERT_FILE_BAD_HTTP_BUS_SESSION_ID_2,"xxs",http_conn,http_req,session_id_str);
   goto error;
  }

  *rlm_id_r = rlm_id;
  *session_id_r = session_id;
  if( rlm_id_str_r ){
  	*rlm_id_str_r = rlm_id_str2;
  }else{
  	_rhp_free(rlm_id_str2);
  }

  RHP_TRC(0,RHPTRCID_UI_HTTP_UPLOAD_CERT_FILE_PARSE_URI,"xxsuq",http_conn,http_req,http_req->uri,*rlm_id_r,*session_id_r);
  return 0;

error:
	RHP_TRC(0,RHPTRCID_UI_HTTP_UPLOAD_CERT_FILE_PARSE_URI_ERR,"xxsE",http_conn,http_req,http_req->uri,err);
	if( rlm_id_str2 ){
		_rhp_free(rlm_id_str2);
	}
	return err;
}

void rhp_ui_http_lower_err_handle(rhp_http_conn* http_conn,rhp_http_request* http_req)
{
	int err = -ENOENT;

  RHP_TRC(0,RHPTRCID_UI_HTTP_LOWER_ERR_HANDLE,"xx",http_conn,http_req);

  if( http_req == NULL ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_LOWER_ERR_HANDLE_NO_REQ,"x",http_conn);
    return;
  }

  if( http_req->method == NULL || http_req->uri == NULL ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_LOWER_ERR_HANDLE_NO_METHOD_URI,"xxx",http_conn,http_req->method,http_req->uri);
    return;
  }

  RHP_TRC(0,RHPTRCID_UI_HTTP_UPLOAD_FILE_HANDLER_PARMS,"xss",http_conn,http_req->method,http_req->uri);

  if( !strcmp(http_req->method,"POST") ){

  	int fixed_uri_len;

		if( http_req->cookie.user_name &&
				( strlen(http_req->uri) > (fixed_uri_len = strlen("/protected/certs/")) &&
				  !strncasecmp(http_req->uri,"/protected/certs/",fixed_uri_len)) ){

			unsigned long rlm_id = 0;
			u64 session_id = 0;

		  err = _rhp_ui_http_upload_cert_file_parse_uri(http_conn,http_req,&rlm_id,&session_id,NULL);
		  if( !err ){

		  	rhp_http_bus_send_async(session_id,http_req->cookie.user_name,rlm_id,1,0,
		  			_rhp_ui_http_upload_cert_file_low_err_serialize,(void*)rlm_id);
		  }
		}

		//
		// TODO : config_archive_restore_error's handling.
		//
	}

  RHP_TRC(0,RHPTRCID_UI_HTTP_LOWER_ERR_HANDLE_RTRN,"xxE",http_conn,http_req,err);
  return;
}

static int _rhp_ui_http_upload_cert_file(rhp_http_conn* http_conn)
{
  int err = -EINVAL;
  rhp_http_request* http_req = http_conn->http_req;
  rhp_http_body_multipart_form_data* multipart_from_data = http_req->multipart_form_data;
  rhp_http_body_part *bpart_file_pw = NULL, *bpart_accept_expired_cert = NULL;
  rhp_http_body_part *bpart_file_privkey_pem = NULL,*bpart_file_my_cert_pem = NULL, *bpart_file_pkcs12 = NULL;
  rhp_http_body_part *bpart_file_cacert_pem = NULL,*bpart_file_crl_pem = NULL;
  int file_pw_len = 0;
  char* file_pw = NULL;
  char *pkcs12_path = NULL,*my_cert_path = NULL,*my_priv_key_path = NULL,*ca_cert_path = NULL,*crl_path = NULL;
  char* rlm_id_str = NULL;
  unsigned long rlm_id = 0;
  u64 session_id = 0;
  unsigned long file_flag = 0;
  long accept_expired_cert = -1;

  RHP_TRC(0,RHPTRCID_UI_HTTP_UPLOAD_CERT_FILE,"xxx",http_conn,http_req,multipart_from_data);


  err = _rhp_ui_http_upload_cert_file_parse_uri(http_conn,http_req,&rlm_id,&session_id,&rlm_id_str);
  if( err ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_UPLOAD_CERT_FILE_PARSE_URI_ERR,"xxE",http_conn,http_req,err);
  	goto error;
  }

  {
	  if( rlm_id == 0 ){
	  	err = -EPERM;
	  	RHP_TRC(0,RHPTRCID_UI_HTTP_UPLOAD_CERT_FILE_REALM_ID_ZERO,"xxu",http_conn,http_req,rlm_id);
	  	goto error;
	  }

	  if( _rhp_ui_http_permitted(http_conn,NULL,rlm_id) ){
				err = -EPERM;
				RHP_TRC(0,RHPTRCID_UI_HTTP_UPLOAD_CERT_FILE_NOT_PERMITTED,"xxuu",http_conn,http_req,http_conn->user_realm_id,rlm_id);
				goto error;
		}

	  {
	  	rhp_vpn_realm* rlm = rhp_realm_get(rlm_id);
	  	if( rlm == NULL ){
	  	  RHP_TRC(0,RHPTRCID_UI_HTTP_UPLOAD_CERT_FILE_NO_REALM_FOUND,"xxu",http_conn,http_req,rlm_id);
	  		err = -ENOENT;
	  		goto error;
	  	}

	  	rhp_realm_unhold(rlm);
	  }
  }


  {
  	rhp_http_bus_session* http_bus_sess = rhp_http_bus_sess_get(session_id,http_conn->user_name);

  	if( http_bus_sess == NULL ){
  		err = -ENOENT;
      RHP_TRC(0,RHPTRCID_UI_HTTP_UPLOAD_CERT_FILE_BAD_HTTP_BUS_SESSION_ID_3,"xxq",http_conn,http_req,session_id);
      goto error;
  	}

  	rhp_http_bus_sess_unhold(http_bus_sess);
  }


  {
    rhp_http_header* bpart_header;

    bpart_file_pkcs12 = multipart_from_data->get_body_part(multipart_from_data,"upload_cert_file_pkcs12");
		if( bpart_file_pkcs12 && bpart_file_pkcs12->form_filename &&
				(bpart_file_pkcs12->form_filename[0] != '\0') && bpart_file_pkcs12->data ){

			bpart_header = bpart_file_pkcs12->get_header(bpart_file_pkcs12,"Content-Type");
			if( bpart_header == NULL || bpart_header->value == NULL ){
				err = -ENOENT;
				RHP_TRC(0,RHPTRCID_UI_HTTP_UPLOAD_CERT_FILE_PKCS12_NO_CONTENT_TYPE,"xx",http_req,bpart_file_pkcs12);
				goto error;
			}

			if( (strcasestr(bpart_header->value,"application/octet-stream") == NULL) &&
					(strcasestr(bpart_header->value,"application/x-pkcs12") == NULL) &&
					(strcasestr(bpart_header->value,"application/x-x509-ca-cert")	== NULL) ){
				err = RHP_STATUS_INVALID_MSG;
				RHP_TRC(0,RHPTRCID_UI_HTTP_UPLOAD_CERT_FILE_PKCS12_NOT_APP_OCTET_STREAM,"xsx",http_req,bpart_header->value,bpart_file_pkcs12);
				goto error;
			}

			file_flag |= RHP_IPC_SYSPXY_CFG_UPDATE_CERT_FILE_PKCS12;
		}


		bpart_file_privkey_pem = multipart_from_data->get_body_part(multipart_from_data,"upload_cert_file_privkey_pem");
		if( bpart_file_privkey_pem && bpart_file_privkey_pem->form_filename &&
				(bpart_file_privkey_pem->form_filename[0] != '\0') && bpart_file_privkey_pem->data ){

			bpart_header = bpart_file_privkey_pem->get_header(bpart_file_privkey_pem,"Content-Type");
			if( bpart_header == NULL || bpart_header->value == NULL ){
				err = -ENOENT;
				RHP_TRC(0,RHPTRCID_UI_HTTP_UPLOAD_CERT_MY_PRIVKEY_FILE_NO_CONTENT_TYPE,"xx",http_req,bpart_file_privkey_pem);
				goto error;
			}

			if( (strcasestr(bpart_header->value,"application/octet-stream") == NULL) &&
					(strcasestr(bpart_header->value,"application/x-x509-ca-cert")	== NULL) &&
					(strcasestr(bpart_header->value,"application/pkix-cert")	== NULL) &&
				  (strcasestr(bpart_header->value,"text/plain") == NULL)){
				err = RHP_STATUS_INVALID_MSG;
				RHP_TRC(0,RHPTRCID_UI_HTTP_UPLOAD_CERT_FILE_MY_PRIVKEY_NOT_APP_OCTET_STREAM,"xsx",http_req,bpart_header->value,bpart_file_privkey_pem);
				goto error;
			}

			file_flag |= RHP_IPC_SYSPXY_CFG_UPDATE_CERT_FILE_MY_PRIVKEY_PEM;
		}


		bpart_file_my_cert_pem = multipart_from_data->get_body_part(multipart_from_data,"upload_cert_file_my_cert_pem");
		if( bpart_file_my_cert_pem && bpart_file_my_cert_pem->form_filename &&
				(bpart_file_my_cert_pem->form_filename[0] != '\0') && bpart_file_my_cert_pem->data ){

			bpart_header = bpart_file_my_cert_pem->get_header(bpart_file_my_cert_pem,"Content-Type");
			if( bpart_header == NULL || bpart_header->value == NULL ){
				err = -ENOENT;
				RHP_TRC(0,RHPTRCID_UI_HTTP_UPLOAD_CERT_FILE_MY_CERT_NO_CONTENT_TYPE,"xx",http_req,bpart_file_my_cert_pem);
				goto error;
			}

			if( (strcasestr(bpart_header->value,"application/octet-stream") == NULL) &&
					(strcasestr(bpart_header->value,"application/x-x509-ca-cert")	== NULL) &&
					(strcasestr(bpart_header->value,"application/pkix-cert")	== NULL) &&
					(strcasestr(bpart_header->value,"text/plain") == NULL)){
				err = RHP_STATUS_INVALID_MSG;
				RHP_TRC(0,RHPTRCID_UI_HTTP_UPLOAD_CERT_FILE_MY_CERT_NOT_APP_OCTET_STREAM,"xsx",http_req,bpart_header->value,bpart_file_my_cert_pem);
				goto error;
			}

			file_flag |= RHP_IPC_SYSPXY_CFG_UPDATE_CERT_FILE_MY_CERT_PEM;
		}


		bpart_file_cacert_pem = multipart_from_data->get_body_part(multipart_from_data,"upload_ca_cert_file_pem");
		if( bpart_file_cacert_pem && bpart_file_cacert_pem->form_filename &&
				(bpart_file_cacert_pem->form_filename[0] != '\0') && bpart_file_cacert_pem->data ){

			bpart_header = bpart_file_cacert_pem->get_header(bpart_file_cacert_pem,"Content-Type");
			if( bpart_header == NULL || bpart_header->value == NULL ){
				err = -ENOENT;
				RHP_TRC(0,RHPTRCID_UI_HTTP_UPLOAD_CERT_FILE_CA_CERT_NO_CONTENT_TYPE,"xx",http_req,bpart_file_cacert_pem);
				goto error;
			}

			if( (strcasestr(bpart_header->value,"application/octet-stream") == NULL) &&
					(strcasestr(bpart_header->value,"application/x-x509-ca-cert")	== NULL) &&
					(strcasestr(bpart_header->value,"application/pkix-cert")	== NULL) &&
					(strcasestr(bpart_header->value,"text/plain") == NULL) ){
				err = RHP_STATUS_INVALID_MSG;
				RHP_TRC(0,RHPTRCID_UI_HTTP_UPLOAD_CERT_FILE_CA_CERT_NOT_APP_OCTET_STREAM,"xsx",http_req,bpart_header->value,bpart_file_cacert_pem);
				goto error;
			}

			file_flag |= RHP_IPC_SYSPXY_CFG_UPDATE_CERT_FILE_CA_PEM;
		}


		bpart_file_crl_pem = multipart_from_data->get_body_part(multipart_from_data,"upload_crl_file_pem");
		if( bpart_file_crl_pem && bpart_file_crl_pem->form_filename &&
				(bpart_file_crl_pem->form_filename[0] != '\0') && bpart_file_crl_pem->data ){

			bpart_header = bpart_file_crl_pem->get_header(bpart_file_crl_pem,"Content-Type");
			if( bpart_header == NULL || bpart_header->value == NULL ){
				err = -ENOENT;
				RHP_TRC(0,RHPTRCID_UI_HTTP_UPLOAD_CERT_FILE_CRL_NO_CONTENT_TYPE,"xx",http_req,bpart_file_crl_pem);
				goto error;
			}

			if( (strcasestr(bpart_header->value,"application/octet-stream") == NULL) &&
					(strcasestr(bpart_header->value,"application/x-x509-ca-cert")	== NULL) &&
					(strcasestr(bpart_header->value,"application/pkix-cert")	== NULL) &&
					(strcasestr(bpart_header->value,"application/pkix-crl")	== NULL) &&
					(strcasestr(bpart_header->value,"text/plain") == NULL) ){
				err = RHP_STATUS_INVALID_MSG;
				RHP_TRC(0,RHPTRCID_UI_HTTP_UPLOAD_CERT_FILE_CRL_NOT_APP_OCTET_STREAM,"xsx",http_req,bpart_header->value,bpart_file_crl_pem);
				goto error;
			}

			file_flag |= RHP_IPC_SYSPXY_CFG_UPDATE_CERT_FILE_CRL_PEM;
		}
  }


  if( file_flag & (RHP_IPC_SYSPXY_CFG_UPDATE_CERT_FILE_PKCS12 | RHP_IPC_SYSPXY_CFG_UPDATE_CERT_FILE_MY_PRIVKEY_PEM) ){

  	bpart_file_pw = multipart_from_data->get_body_part(multipart_from_data,"upload_cert_file_password");
		if( bpart_file_pw && bpart_file_pw->data == NULL ){
			err = RHP_STATUS_INVALID_MSG;
			RHP_TRC(0,RHPTRCID_UI_HTTP_UPLOAD_CERT_FILE_NO_PRIVKEY_PASSWORD_DATA,"xx",http_conn,http_req);
			goto error;
		}

		if( bpart_file_pw ){

			file_pw_len = bpart_file_pw->data_len;

			file_pw = (char*)_rhp_malloc(file_pw_len + 1);
			if( file_pw == NULL ){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}

			memcpy(file_pw,bpart_file_pw->data,file_pw_len);
			file_pw[file_pw_len] = '\0';

		}else{

			RHP_TRC(0,RHPTRCID_UI_HTTP_UPLOAD_CERT_FILE_NO_PRIVKEY_PASSWORD_SPECIFIED_HERE,"xx",http_conn,http_req);
		}
  }


  bpart_accept_expired_cert = multipart_from_data->get_body_part(multipart_from_data,"accept_expired_cert");
	if( bpart_accept_expired_cert && bpart_accept_expired_cert->data ){

		char accept_expired_cert_str[16];

		if( bpart_accept_expired_cert->data_len == strlen("enable") ||
				bpart_accept_expired_cert->data_len == strlen("disable") ){

			memcpy(accept_expired_cert_str,bpart_accept_expired_cert->data,bpart_accept_expired_cert->data_len);
			accept_expired_cert_str[bpart_accept_expired_cert->data_len] = '\0';

			if( !strcmp(accept_expired_cert_str,"enable") ){
				accept_expired_cert = 1;
			}else if( !strcmp(accept_expired_cert_str,"disable") ){
				accept_expired_cert = 0;
			}
		}
	}


  if( file_flag & RHP_IPC_SYSPXY_CFG_UPDATE_CERT_FILE_PKCS12 ){

  	pkcs12_path = (char*)_rhp_malloc( strlen(rhp_home_dir) + strlen("/certs/.p12") + strlen(rlm_id_str) + 1 );
		if( pkcs12_path == NULL ){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		pkcs12_path[0] = '\0';

		sprintf(pkcs12_path,"%s/certs/%s.p12",rhp_home_dir,rlm_id_str);

		if( !rhp_file_exists(pkcs12_path) ){
			RHP_TRC(0,RHPTRCID_UI_HTTP_UPLOAD_CERT_FILE_CA_CERT_BUSY_PKCS12,"xs",http_req,pkcs12_path);
			err = -EBUSY;
			goto error;
		}

		err = rhp_file_write(pkcs12_path,(u8*)bpart_file_pkcs12->data,bpart_file_pkcs12->data_len,(S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP));
		if( err ){
			RHP_BUG("%d",err);
			goto error;
		}

		RHP_LOG_D(RHP_LOG_SRC_UI,rlm_id,RHP_LOG_ID_UPLOAD_PKCS12_FILE_OK,"s",pkcs12_path);
	}

  if( file_flag & RHP_IPC_SYSPXY_CFG_UPDATE_CERT_FILE_MY_PRIVKEY_PEM ){

		my_priv_key_path = (char*)_rhp_malloc( strlen(rhp_home_dir) + strlen("/certs/privkey.pem") + strlen(rlm_id_str) + 1 );
		if( my_priv_key_path == NULL ){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		my_priv_key_path[0] = '\0';

		sprintf(my_priv_key_path,"%s/certs/privkey%s.pem",rhp_home_dir,rlm_id_str);

		if( !rhp_file_exists(my_priv_key_path) ){
			RHP_TRC(0,RHPTRCID_UI_HTTP_UPLOAD_CERT_FILE_CA_CERT_BUSY_PRIVKEY_PEM,"xs",http_req,my_priv_key_path);
			err = -EBUSY;
			goto error;
		}

		err = rhp_file_write(my_priv_key_path,(u8*)bpart_file_privkey_pem->data,bpart_file_privkey_pem->data_len,(S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP));
		if( err ){
			RHP_BUG("%d",err);
			goto error;
		}

		RHP_LOG_D(RHP_LOG_SRC_UI,rlm_id,RHP_LOG_ID_UPLOAD_MY_PRIVATE_KEY_PEM_FILE_OK,"s",my_priv_key_path);
  }

  if( file_flag & RHP_IPC_SYSPXY_CFG_UPDATE_CERT_FILE_MY_CERT_PEM ){

		my_cert_path = (char*)_rhp_malloc( strlen(rhp_home_dir) + strlen("/certs/mycert.pem") + strlen(rlm_id_str) + 1 );
		if( my_cert_path == NULL ){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		my_cert_path[0] = '\0';

		sprintf(my_cert_path,"%s/certs/mycert%s.pem",rhp_home_dir,rlm_id_str);

		if( !rhp_file_exists(my_cert_path) ){
			RHP_TRC(0,RHPTRCID_UI_HTTP_UPLOAD_CERT_FILE_CA_CERT_BUSY_MY_CERT_PEM,"xs",http_req,my_cert_path);
			err = -EBUSY;
			goto error;
		}

		err = rhp_file_write(my_cert_path,(u8*)bpart_file_my_cert_pem->data,bpart_file_my_cert_pem->data_len,(S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP));
		if( err ){
			RHP_BUG("%d",err);
			goto error;
		}

		RHP_LOG_D(RHP_LOG_SRC_UI,0,RHP_LOG_ID_UPLOAD_MY_CERT_PEM_FILE_OK,"ss",rlm_id_str,my_cert_path);
	}

  if( file_flag & RHP_IPC_SYSPXY_CFG_UPDATE_CERT_FILE_CA_PEM ){

		ca_cert_path = (char*)_rhp_malloc( strlen(rhp_home_dir) + strlen("/certs/cacert.pem") + strlen(rlm_id_str) + 1 );
		if( ca_cert_path == NULL ){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		ca_cert_path[0] = '\0';

		sprintf(ca_cert_path,"%s/certs/cacert%s.pem",rhp_home_dir,rlm_id_str);

		if( !rhp_file_exists(ca_cert_path) ){
			RHP_TRC(0,RHPTRCID_UI_HTTP_UPLOAD_CERT_FILE_CA_CERT_BUSY_CA_CERT_PEM,"xs",http_req,ca_cert_path);
			err = -EBUSY;
			goto error;
		}

		err = rhp_file_write(ca_cert_path,(u8*)bpart_file_cacert_pem->data,bpart_file_cacert_pem->data_len,(S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP  | S_IXGRP));
		if( err ){
			RHP_BUG("%d",err);
			goto error;
		}

		RHP_LOG_D(RHP_LOG_SRC_UI,rlm_id,RHP_LOG_ID_UPLOAD_CA_CERT_PEM_FILE_OK,"s",ca_cert_path);
  }

  if( file_flag & RHP_IPC_SYSPXY_CFG_UPDATE_CERT_FILE_CRL_PEM ){

		crl_path = (char*)_rhp_malloc( strlen(rhp_home_dir) + strlen("/certs/crl.pem") + strlen(rlm_id_str) + 1 );
		if( crl_path == NULL ){
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		crl_path[0] = '\0';

		sprintf(crl_path,"%s/certs/crl%s.pem",rhp_home_dir,rlm_id_str);

		if( !rhp_file_exists(crl_path) ){
			RHP_TRC(0,RHPTRCID_UI_HTTP_UPLOAD_CERT_FILE_CA_CERT_BUSY_CA_CERT_PEM,"xs",http_req,crl_path);
			err = -EBUSY;
			goto error;
		}

		err = rhp_file_write(crl_path,(u8*)bpart_file_crl_pem->data,bpart_file_crl_pem->data_len,(S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP  | S_IXGRP));
		if( err ){
			RHP_BUG("%d",err);
			goto error;
		}

		RHP_LOG_D(RHP_LOG_SRC_UI,rlm_id,RHP_LOG_ID_UPLOAD_CRL_PEM_FILE_OK,"s",crl_path);
  }


  if( !file_flag ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_UPLOAD_CERT_FILE_NO_FILE_CONTENTS,"xx",http_conn,http_req);
  	err = RHP_STATUS_INVALID_MSG;
  	goto error;
  }


  {
  	rhp_ipcmsg_syspxy_cfg_sub* cfg_sub_dt
  	= (rhp_ipcmsg_syspxy_cfg_sub*)_rhp_malloc(sizeof(rhp_ipcmsg_syspxy_cfg_sub) + file_pw_len);

  	if( cfg_sub_dt == NULL ){
  		err =-ENOMEM;
  		RHP_BUG("");
  		goto error;
  	}

  	memset(cfg_sub_dt,0,sizeof(rhp_ipcmsg_syspxy_cfg_sub));

  	cfg_sub_dt->cfg_type = RHP_IPC_SYSPXY_CFG_UPLOAD_CERT_FILE;
  	cfg_sub_dt->len = sizeof(rhp_ipcmsg_syspxy_cfg_sub) + (file_pw_len ? (file_pw_len + 1) : 0);
  	cfg_sub_dt->target_rlm_id = rlm_id;
  	cfg_sub_dt->priv[0] = file_flag;
  	cfg_sub_dt->priv[1] = (unsigned long)accept_expired_cert;

  	if( file_pw ){
  		memcpy((u8*)(cfg_sub_dt + 1),file_pw,file_pw_len);
  		((u8*)(cfg_sub_dt + 1))[file_pw_len] = '\0';
  	}

  	err = rhp_http_bus_ipc_cfg_request_async(http_conn,session_id,cfg_sub_dt->len,(u8*)cfg_sub_dt);
  	_rhp_free(cfg_sub_dt);

  	if( err ){
  		RHP_BUG("");
  		goto error;
  	}
  }


  if( pkcs12_path ){
    _rhp_free(pkcs12_path);
  }
  if( my_priv_key_path ){
    _rhp_free(my_priv_key_path);
  }
  if( my_cert_path ){
    _rhp_free(my_cert_path);
  }
  if( ca_cert_path ){
    _rhp_free(ca_cert_path);
  }
  if( crl_path ){
  	_rhp_free(crl_path);
  }
  if( file_pw ){
  	_rhp_free_zero(file_pw,file_pw_len);
  }
	_rhp_free(rlm_id_str);

  RHP_TRC(0,RHPTRCID_UI_HTTP_UPLOAD_CERT_FILE_RTRN,"xxx",http_conn,http_req,file_flag);
  return 0;

error:
	_rhp_ui_http_upload_cert_file_async_err_resp(http_conn,session_id,rlm_id);

  RHP_LOG_DE(RHP_LOG_SRC_UI,rlm_id,RHP_LOG_ID_UPLOAD_CERT_FILE_ERR,"E",err);

  if( pkcs12_path ){
  	unlink(pkcs12_path);
    _rhp_free(pkcs12_path);
  }
  if( my_priv_key_path ){
  	unlink(my_priv_key_path);
    _rhp_free(my_priv_key_path);
  }
  if( my_cert_path ){
  	unlink(my_cert_path);
    _rhp_free(my_cert_path);
  }
  if( ca_cert_path ){
  	unlink(ca_cert_path);
    _rhp_free(ca_cert_path);
  }
  if( crl_path ){
  	_rhp_free(crl_path);
  }
  if( file_pw ){
		_rhp_free_zero(file_pw,file_pw_len);
	}
  if( rlm_id_str ){
  	_rhp_free(rlm_id_str);
  }

  RHP_TRC(0,RHPTRCID_UI_HTTP_UPLOAD_CERT_FILE_ERR,"xxxE",http_conn,http_req,file_flag,err);
  return err;
}


static int _rhp_ui_http_upload_file_handler(rhp_http_conn* http_conn,int authorized,void* ctx)
{
  int err = RHP_STATUS_SKIP;
  rhp_http_request* http_req = http_conn->http_req;
  rhp_http_response* http_res = NULL;
  int n_err = -EINVAL;

  RHP_TRC(0,RHPTRCID_UI_HTTP_UPLOAD_FILE_HANDLER,"xdx",http_conn,authorized,ctx);

  if( http_req == NULL ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_UPLOAD_FILE_HANDLER_NO_REQ,"x",http_conn);
    return RHP_STATUS_SKIP;
  }

  if( http_req->method == NULL || http_req->uri == NULL ){
    RHP_TRC(0,RHPTRCID_UI_HTTP_UPLOAD_FILE_HANDLER_REQ_INVALID_PARMS,"xxx",http_conn,http_req->method,http_req->uri);
    return RHP_STATUS_SKIP;
  }

  RHP_TRC(0,RHPTRCID_UI_HTTP_UPLOAD_FILE_HANDLER_PARMS,"xss",http_conn,http_req->method,http_req->uri);

  if( !strcmp(http_req->method,"POST") ){

  	int fixed_uri_len;

		if( !strcasecmp(http_req->uri,"/protected/config") ||
				(strlen(http_req->uri) > (fixed_uri_len = strlen("/protected/certs/")) &&
				!strncasecmp(http_req->uri,"/protected/certs/",fixed_uri_len)) ){

			// Go next.

		}else{

		  err = RHP_STATUS_SKIP;
		  RHP_TRC(0,RHPTRCID_UI_HTTP_UPLOAD_FILE_HANDLER_GET_INVALID_URI,"x",http_conn);
		  goto error;
		}

		if( !authorized ){

		   err = rhp_http_auth_request_impl(http_conn,(unsigned long)-1,1); // Normal HTTP Basic Auth is allowed.
		   if( err ){

		  	 if( err == RHP_STATUS_HTTP_BASIC_UNAUTHORIZED ){
		  		 err = RHP_STATUS_HTTP_UNAUTHORIZED_BASIC_AUTH_PROMPT;
		  	 }

		  	RHP_TRC(0,RHPTRCID_UI_HTTP_UPLOAD_FILE_HANDLER_GET_AUTH_BASIC_ERR,"xE",http_conn,err);
				goto error;
			}

			err = rhp_http_server_conn_timer_restart(http_conn);
			if( err ){
	   		 RHP_BUG("%d",err);
	   		 goto error;
			}

			err = RHP_STATUS_HTTP_REQ_PENDING;

		  RHP_TRC(0,RHPTRCID_UI_HTTP_UPLOAD_FILE_HANDLER_GET_GO_PEND,"x",http_conn);
		  goto pending;
		}



	  if( http_req->multipart_form_data == NULL ){
	    RHP_TRC(0,RHPTRCID_HTTP_BUS_WRITE_NO_DATA,"xx",http_conn,http_req);
	    err = -ENOENT;
	    goto error;
	  }


		if( !strcasecmp(http_req->uri,"/protected/config") ){

			n_err = _rhp_ui_http_cfg_bkup_restore_1(http_conn);

		}else if( !strncasecmp(http_req->uri,"/protected/certs/",strlen("/protected/certs/")) ){

			n_err = _rhp_ui_http_upload_cert_file(http_conn);

		}else{
			RHP_BUG("%s",http_req->uri);
			goto error;
		}

		if( n_err && n_err != RHP_STATUS_RESTORE_CFG_ARCHIVE_USER_ERR ){
	  	err = n_err;
	  	goto error;
	  }

	  {
	  	http_res = rhp_http_res_alloc("200","OK");
			if( http_res == NULL ){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}

			err = rhp_http_tx_server_response(http_conn,http_res,1);
			if( err ){
				RHP_TRC(0,RHPTRCID_UI_HTTP_UPLOAD_FILE_HANDLER_GET_TX_RESP_ERR,"xE",http_conn,err);
				err = RHP_STATUS_ABORT_HTTP_CONN;
				goto error;
			}
	  }

    rhp_http_res_free(http_res);

 		RHP_TRC(0,RHPTRCID_UI_HTTP_UPLOAD_FILE_HANDLER_RTRN,"x",http_conn);
 		return RHP_STATUS_CLOSE_HTTP_CONN;
  }

pending:
error:
  if( http_res ){
    rhp_http_res_free(http_res);
  }
  RHP_TRC(0,RHPTRCID_UI_HTTP_UPLOAD_FILE_HANDLER_ERR,"x",http_conn);
  return err;
}


int rhp_ui_http_init()
{
  int err = -EINVAL;

  rhp_http_server_register_handler(_rhp_ui_http_upload_file_handler,NULL,0);

  err = rhp_http_bus_register_request_handler("ui_http_vpn",_rhp_ui_http_vpn_req_handler,NULL,1);
  if( err ){
    RHP_BUG("%d",err);
    return err;
  }

  _rhp_atomic_init(&_rhp_ui_http_access_lock);

  _rhp_mutex_init("PCP",&_rhp_ui_http_packet_capture_lock);

  RHP_TRC(0,RHPTRCID_UI_HTTP_INIT,"");

  return 0;
}

int rhp_ui_http_cleanup()
{

	_rhp_atomic_destroy(&_rhp_ui_http_access_lock);

	_rhp_mutex_destroy(&_rhp_ui_http_packet_capture_lock);

  RHP_TRC(0,RHPTRCID_UI_HTTP_CLEANUP,"");

  return 0;
}
