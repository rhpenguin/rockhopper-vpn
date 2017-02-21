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
#include <unistd.h>
#include <asm/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/capability.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netdb.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <byteswap.h>


#include "rhp_trace.h"
#include "rhp_main_traceid.h"
#include "rhp_misc.h"
#include "rhp_crypto.h"
#include "rhp_cert.h"
#include "rhp_process.h"
#include "rhp_netmng.h"
#include "rhp_config.h"
#include "rhp_wthreads.h"
#include "rhp_packet.h"
#include "rhp_ikev2_mesg.h"
#include "rhp_ikev2.h"
#include "rhp_eap.h"
#include "rhp_radius_impl.h"


rhp_ip_addr _rhp_ipv6_loopback_addr = {
		.addr_family = AF_INET6,
		.addr.v6 = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x01},
		.netmask.v6 = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
				           0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF},
		.prefixlen = 128,
		.port = 0,
		.ipv6_scope_id = 0
};
rhp_ip_addr* rhp_ipv6_loopback_addr = &_rhp_ipv6_loopback_addr;

rhp_ip_addr _rhp_ipv6_all_node_multicast_addr = {
		.addr_family = AF_INET6,
		.addr.v6 = {0xFF,0x02,0,0,0,0,0,0,0,0,0,0,0,0,0,0x01},
		.netmask.v6 = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
				           0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF},
		.prefixlen = 128,
		.port = 0,
		.ipv6_scope_id = 0
};
rhp_ip_addr* rhp_ipv6_all_node_multicast_addr = &_rhp_ipv6_all_node_multicast_addr;

rhp_ip_addr _rhp_ipv6_all_router_multicast_addr = {
		.addr_family = AF_INET6,
		.addr.v6 = {0xFF,0x02,0,0,0,0,0,0,0,0,0,0,0,0,0,0x02},
		.netmask.v6 = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
				           0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF},
		.prefixlen = 128,
		.port = 0,
		.ipv6_scope_id = 0
};
rhp_ip_addr* rhp_ipv6_all_router_multicast_addr = &_rhp_ipv6_all_router_multicast_addr;

rhp_ip_addr _rhp_ipv6_mld2_multicast_addr = {
		.addr_family = AF_INET6,
		.addr.v6 = {0xFF,0x02,0,0,0,0,0,0,0,0,0,0,0,0,0,0x16},
		.netmask.v6 = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
				           0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF},
		.prefixlen = 128,
		.port = 0,
		.ipv6_scope_id = 0
};
rhp_ip_addr* rhp_ipv6_mld2_multicast_addr = &_rhp_ipv6_mld2_multicast_addr;


int rhp_string_prefix_search(u8* bytes,int len/*'\0' NOT included.*/,char* pattern)
{
  int pat_len = strlen(pattern);

  if( len < pat_len ){
    return -1;
  }

  if( strncmp((char*)bytes,pattern,pat_len) ){
   return -1;
  }

  return 0;
}

int rhp_string_suffix_search(u8* bytes,int len/*'\0' NOT included.*/,char* pattern)
{
  int pat_len = strlen(pattern);
  int i,j;

  if( len < pat_len ){
    return -1;
  }

  for( i = len - 1,j = pat_len - 1;i >= 0 && j >= 0; i--,j-- ){
    if( bytes[i] != pattern[j] ){
      return -1;
    }
  }

  if( j == -1 ){
    return 0;
  }
  return -1;
}


int rhp_xml_enum_tags(xmlNodePtr parent_node,xmlChar* tag,int (*callback)(xmlNodePtr node,void* ctx),void* ctx,int enum_all)
{
  int err = 0;
  int c = 0;
  xmlNodePtr cur,cur_n;

  cur = parent_node->xmlChildrenNode;

  while( cur != NULL ){

  	cur_n = cur->next;

  	if( tag == NULL || (!xmlStrcmp(cur->name,tag)) ){

  		if( (err = callback(cur,ctx)) ){
      	RHP_TRC_FREQ(0,RHPTRCID_XML_ENUM_TAGS_RTRN,"xssYxddE",parent_node,parent_node->name,cur->name,callback,ctx,enum_all,c,err);
        return err;
      }

      c++;

      if( !enum_all ){
        return err;
      }
    }

    cur = cur_n;
  }

	RHP_TRC_FREQ(0,RHPTRCID_XML_ENUM_TAGS_ERR,"xssYxddE",parent_node,parent_node->name,tag,callback,ctx,enum_all,c,err);

  return ( c == 0 ? -ENOENT : err  );
}

xmlNodePtr rhp_xml_get_child(xmlNodePtr parent_node,xmlChar* tag)
{
  xmlNodePtr cur_node;

  cur_node = parent_node->xmlChildrenNode;

  while( cur_node != NULL ){

  	if( (!xmlStrcmp(cur_node->name,tag)) ){
    	RHP_TRC_FREQ(0,RHPTRCID_XML_GET_CHILD,"xssxs",parent_node,parent_node->name,tag,cur_node,cur_node->name);
      return cur_node;
    }

  	cur_node = cur_node->next;
  }

	RHP_TRC_FREQ(0,RHPTRCID_XML_GET_CHILD_NO_ENT,"xss",parent_node,parent_node->name,tag);
  return NULL;
}

void rhp_xml_delete_child(xmlNodePtr parent_node,xmlChar* tag)
{
  xmlNodePtr cur_node,cur_node_n;
  int cnt = 0;

  cur_node = parent_node->xmlChildrenNode;

  while( cur_node != NULL ){

  	cur_node_n = cur_node->next;

  	if( (!xmlStrcmp(cur_node->name,tag)) ){

  		RHP_TRC_FREQ(0,RHPTRCID_XML_DELETE_CHILD,"xssxs",parent_node,parent_node->name,tag,cur_node,cur_node->name);

			xmlUnlinkNode(cur_node);
			xmlFreeNode(cur_node);
  		cnt++;
    }

  	cur_node = cur_node_n;
  }

	RHP_TRC_FREQ(0,RHPTRCID_XML_DELETE_CHILD_RTRN,"xssd",parent_node,parent_node->name,tag,cnt);
  return;
}

int rhp_xml_get_text_or_cdata_content(xmlNodePtr node,xmlChar** content_r,int* content_len_r)
{
	xmlNodePtr child_node = node->children;
	int clen = 0;
	xmlChar* ret = NULL;

	while( child_node ){

  	if( child_node->content ){

			if( child_node->type == XML_CDATA_SECTION_NODE ||
					 child_node->type == XML_TEXT_NODE ){

				clen = xmlStrlen(child_node->content);
				if( clen > 0 ){

					ret = (xmlChar*)_rhp_malloc(clen + 1);
					if( ret == NULL ){
						RHP_BUG("");
						return -ENOMEM;
					}

					memcpy(ret,child_node->content,clen);
					ret[clen] = '\0';

					*content_r = ret;
					*content_len_r = clen + 1;

					return 0;
				}
			}
  	}

		child_node = child_node->next;
	}

	return -ENOENT;
}

int rhp_xml_write_node(xmlNodePtr node,xmlTextWriterPtr writer,
		int* len,int recursively,
		int (*node_filter_callback)(xmlNodePtr node,void* ctx),
		int (*attr_filter_callback)(xmlNodePtr node,xmlAttrPtr attr,char** new_prop_val,void* ctx),void* ctx)
{
	int flag = 0;
	int err = -EINVAL;
  xmlAttrPtr cur_attr = node->properties;
  xmlNodePtr child_node = node->children;
  int n;

	RHP_TRC_FREQ(0,RHPTRCID_XML_WRITENODE,"xsLd",node,node->name,"XML_NODE",node->type);

  if( node->type != XML_CDATA_SECTION_NODE &&
  		node->type != XML_TEXT_NODE &&
  		node->type != XML_ELEMENT_NODE ){
  	RHP_TRC_FREQ(0,RHPTRCID_XML_WRITENODE_NOT_INTERESTED,"xsLd",node,node->name,"XML_NODE",node->type);
  	return 0;
  }

	if( node_filter_callback ){
		flag = node_filter_callback(node,ctx);
	}

	if( flag > 0 ){
		return 0;
	}else if( flag < 0 ){
		err = flag;
		goto error;
	}

  if( node->type == XML_CDATA_SECTION_NODE ){

  	if( node->content ){

  		n = xmlTextWriterWriteCDATA((xmlTextWriterPtr)writer,node->content);
			if(n < 0) {
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*len += n;

	  	RHP_TRC_FREQ(0,RHPTRCID_XML_WRITENODE_CDATA,"xs",node,node->content);

  	}else{

  		RHP_TRC_FREQ(0,RHPTRCID_XML_WRITENODE_CDATA_NO_CONTENTS,"x",node);
  	}

  }else if( node->type == XML_TEXT_NODE ){

  	if( node->content ){

  		n = xmlTextWriterWriteRaw((xmlTextWriterPtr)writer,node->content);
  		if(n < 0){
  			err = -ENOMEM;
  			RHP_BUG("");
  			goto error;
  		}
  		*len += n;

  		 RHP_TRC_FREQ(0,RHPTRCID_XML_WRITENODE_TEXT,"xs",node,node->content);
  	}

  }else if( node->type == XML_ELEMENT_NODE ){

		n = xmlTextWriterStartElement(writer,node->name);
		if(n < 0) {
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*len += n;

		RHP_TRC_FREQ(0,RHPTRCID_XML_WRITENODE_WRITE_START_ELEMENT,"sdd",node->name,n,*len);

		while( cur_attr ){

			xmlChar* prop_val = rhp_xml_get_prop(node,cur_attr->name);
			char* new_prop_val = NULL;

			if( prop_val ){

				flag = 0;

				if( attr_filter_callback ){
					flag = attr_filter_callback(node,cur_attr,&new_prop_val,ctx);
				}

				if( flag > 1 ){
					goto next_attr;
				}else if( flag < 0 ){
					err = flag;
					goto error;
				}

				if( new_prop_val ){
					_rhp_free(prop_val);
					prop_val = (xmlChar*)new_prop_val;
				}

				n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,cur_attr->name,prop_val);
				if(n < 0){
					_rhp_free(prop_val);
					err = -ENOMEM;
					RHP_BUG("");
					goto error;
				}
				*len += n;

				RHP_TRC_FREQ(0,RHPTRCID_XML_WRITENODE_WRITE_ATTRIBUTE,"sssdd",node->name,cur_attr->name,prop_val,n,*len);

				_rhp_free(prop_val);
			}

next_attr:
			cur_attr = cur_attr->next;
		}

		if( recursively  ){

			while( child_node ){

				err = rhp_xml_write_node(child_node,writer,len,recursively,node_filter_callback,attr_filter_callback,ctx);
				if( err ){
					goto error;
				}

				child_node = child_node->next;
			}
		}

		n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
		if(n < 0) {
			err = -ENOMEM;
			RHP_BUG("");
			goto error;
		}
		*len += n;

		RHP_TRC_FREQ(0,RHPTRCID_XML_WRITENODE_WRITE_END_ELEMENT,"sdd",node->name,n,*len);

  }else{
  	RHP_TRC_FREQ(0,RHPTRCID_XML_WRITENODE_NOT_INTERESTED_RTRN,"xsLd",node,node->name,"XML_NODE",node->type);
  	return 0;
  }

  return 0;

error:
	return err;
}

int rhp_xml_write_node_start(xmlNodePtr node,xmlTextWriterPtr writer,int* len,
		int (*attr_filter_callback)(xmlNodePtr node,xmlAttrPtr attr,char** new_prop_val,void* ctx),void* ctx)
{
	int flag = 0;
	int err = -EINVAL;
  xmlAttrPtr cur_attr = node->properties;
  int n;

  if( !xmlStrcmp(node->name,(xmlChar*)"text") || !xmlStrcmp(node->name,(xmlChar*)"comment") ){
  	return 0;
  }

	n = xmlTextWriterStartElement(writer,node->name);
	if(n < 0) {
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	*len += n;

	RHP_TRC_FREQ(0,RHPTRCID_XML_WRITENODE_START_WRITE_START_ELEMENT,"sdd",node->name,n,len);

	while( cur_attr ){

		xmlChar* prop_val = rhp_xml_get_prop(node,cur_attr->name);
		char* new_prop_val = NULL;

		if( prop_val ){

			flag = 0;

		  if( attr_filter_callback ){
		  	flag = attr_filter_callback(node,cur_attr,&new_prop_val,ctx);
		  }

		  if( flag > 1 ){
		  	goto next_attr;
		  }else if( flag < 0 ){
		  	err = flag;
		  	goto error;
		  }

		  if( new_prop_val ){
		  	_rhp_free(prop_val);
		  	prop_val = (xmlChar*)new_prop_val;
		  }

		  n = xmlTextWriterWriteAttribute((xmlTextWriterPtr)writer,cur_attr->name,prop_val);
			if(n < 0){
			  _rhp_free(prop_val);
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}
			*len += n;

			RHP_TRC_FREQ(0,RHPTRCID_XML_WRITENODE_START_WRITE_ATTRIBUTE,"sssdd",node->name,cur_attr->name,prop_val,n,len);

		  _rhp_free(prop_val);
		}

next_attr:
		cur_attr = cur_attr->next;
	}


  return 0;

error:
	return err;
}

int rhp_xml_write_node_end(xmlNodePtr node,xmlTextWriterPtr writer,int* len)
{
	int err = -EINVAL;
  int n;

  if( !xmlStrcmp(node->name,(xmlChar*)"text") || !xmlStrcmp(node->name,(xmlChar*)"comment") ){
  	return 0;
  }

	n = xmlTextWriterEndElement((xmlTextWriterPtr)writer);
	if(n < 0) {
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	*len += n;

	RHP_TRC_FREQ(0,RHPTRCID_XML_WRITENODE_END_WRITE_END_ELEMENT,"sdd",node->name,n,*len);

  return 0;

error:
	return err;
}

int rhp_xml_strcasecmp(xmlChar* str1,xmlChar* str2)
{

	RHP_TRC_FREQ(0,RHPTRCID_XML_STRCASECMP,"ss",str1,str2);

	if( str1 == NULL || str2 == NULL ){
    return -1;
  }
  return strcasecmp((char*)str1,(char*)str2);
}

static __thread  xmlChar* _xml_stastc_prop_ret = NULL;
static __thread int _xml_stastc_prop_ret_len = 0;

xmlChar* rhp_xml_get_prop_static(xmlNodePtr node,const xmlChar* prop_name)
{
	xmlChar *ret_tmp = NULL,*ret = NULL;
	int clen;

	ret_tmp = xmlGetProp(node,prop_name);

	if( ret_tmp ){

		clen = xmlStrlen(ret_tmp);

		if( _xml_stastc_prop_ret && _xml_stastc_prop_ret_len < clen ){
			_rhp_free(_xml_stastc_prop_ret);
			_xml_stastc_prop_ret = NULL;
			_xml_stastc_prop_ret_len = 0;
		}

		if( _xml_stastc_prop_ret == NULL ){
			_xml_stastc_prop_ret = (xmlChar*)_rhp_malloc(clen + 1);
			_xml_stastc_prop_ret_len = clen;
		}

		if( _xml_stastc_prop_ret == NULL ){
			_xml_stastc_prop_ret_len = 0;
			RHP_BUG("");
			goto error;
		}

		memcpy(_xml_stastc_prop_ret,ret_tmp,clen);
		_xml_stastc_prop_ret[clen] = '\0';

		ret = _xml_stastc_prop_ret;

	}else{

		RHP_TRC_FREQ(0,RHPTRCID_XML_GET_PROP_STATIC_NO_ENT,"xss",node,node->name,prop_name);
		ret = NULL;
	}

error:
	if( ret_tmp ){
		memset(ret_tmp,0,clen);
		xmlFree(ret_tmp);
	}

	RHP_TRC_FREQ(0,RHPTRCID_XML_GET_PROP_STATIC,"xssxs",node,node->name,prop_name,ret,ret);
	return ret;
}

xmlChar* rhp_xml_get_prop(xmlNodePtr node,const xmlChar* prop_name)
{
	xmlChar *ret_tmp = NULL,*ret = NULL;
	int clen;

	ret_tmp = xmlGetProp(node,prop_name);

	if( ret_tmp ){

		clen = xmlStrlen(ret_tmp);
		ret = (xmlChar*)_rhp_malloc(clen + 1);
		if( ret == NULL ){
			RHP_BUG("");
			goto error;
		}

		memcpy(ret,ret_tmp,clen);
		ret[clen] = '\0';

	}else{
		RHP_TRC_FREQ(0,RHPTRCID_XML_GET_PROP_NO_ENT,"xss",node,node->name,prop_name);
	}

error:
	if( ret_tmp ){
		memset(ret_tmp,0,clen);
		xmlFree(ret_tmp);
	}

	RHP_TRC_FREQ(0,RHPTRCID_XML_GET_PROP,"xssxs",node,node->name,prop_name,ret,ret);
	return ret;
}

xmlChar* rhp_xml_search_prop_in_children(xmlNodePtr parent_node,xmlChar* elm_tag,xmlChar* prop_name,xmlNodePtr* node_r)
{
  xmlNodePtr cur;

  cur = parent_node->xmlChildrenNode;

  while( cur != NULL ){

  	if( (!xmlStrcmp(cur->name,elm_tag)) ){

  		xmlChar* prop = rhp_xml_get_prop(cur,prop_name);

  		if( prop ){

  			if( node_r ){
  				*node_r = cur;
  			}

  			return prop;
  		}
    }

    cur = cur->next;
  }

  return NULL;
}

xmlNodePtr rhp_xml_search_prop_value_in_children(xmlNodePtr parent_node,xmlChar* elm_tag,xmlChar* prop_name,xmlChar* prop_val)
{
  xmlNodePtr cur;

  cur = parent_node->xmlChildrenNode;

  while( cur != NULL ){

  	if( (!xmlStrcmp(cur->name,elm_tag)) ){

  		xmlChar* prop = rhp_xml_get_prop(cur,prop_name);

  		if( prop && !xmlStrcmp(prop,prop_val) ){
  			_rhp_free(prop);
  			return cur;
  		}else{
  			if( prop ){
  				_rhp_free(prop);
  			}
  		}
    }

    cur = cur->next;
  }

  return NULL;
}

xmlNodePtr rhp_xml_search_prop_value_in_children2(xmlNodePtr parent_node,xmlChar* elm_tag,
		xmlChar* prop_name,xmlChar* prop_val,xmlChar* prop_name2,xmlChar* prop_val2)
{
  xmlNodePtr cur;

  cur = parent_node->xmlChildrenNode;

  while( cur != NULL ){

  	if( (!xmlStrcmp(cur->name,elm_tag)) ){

  		xmlChar* prop = rhp_xml_get_prop(cur,prop_name);

  		if( prop && !xmlStrcmp(prop,prop_val) ){

  			_rhp_free(prop);

    		prop = rhp_xml_get_prop(cur,prop_name2);

    		if( prop && !xmlStrcmp(prop,prop_val2) ){
    			_rhp_free(prop);
    			return cur;
    		}else{
					if( prop ){
						_rhp_free(prop);
					}
    		}

  		}else{

  			if( prop ){
  				_rhp_free(prop);
  			}
  		}
    }

    cur = cur->next;
  }

  return NULL;
}

int rhp_xml_set_prop(xmlNodePtr cur_node,xmlChar* name,xmlChar* value)
{
	xmlAttrPtr cur_attr;

	cur_attr =	xmlHasProp(cur_node,name);
	if( cur_attr ){
		xmlRemoveProp(cur_attr);
	}

	if( xmlNewProp(cur_node,name,value) == NULL ){
		RHP_BUG("");
		return -ENOMEM;
	}

	return 0;
}

int rhp_xml_prop_update_in_children(xmlNodePtr cur_parent_node,xmlNodePtr new_parent_node,xmlChar* elm_tag,xmlChar* prop_name)
{
	int err = -EINVAL;
	xmlChar *cur_prop = NULL,*new_prop = NULL;
  xmlNodePtr cur_node = NULL,new_node = NULL;
  xmlAttrPtr cur_attr = NULL;

	cur_prop = rhp_xml_search_prop_in_children(cur_parent_node,elm_tag,prop_name,&cur_node);
	new_prop = rhp_xml_search_prop_in_children(new_parent_node,elm_tag,prop_name,&new_node);

	if( cur_prop ){

		cur_attr =	xmlHasProp(cur_node,prop_name);
		if( cur_attr == NULL ){
			RHP_BUG("%s",prop_name);
		}
	}

	if( new_prop ){

		if( cur_node == NULL ){

			cur_node =	xmlNewNode(NULL,elm_tag);
			if( cur_node == NULL ){
				err = -ENOMEM;
				RHP_BUG("");
				goto error;
			}

			if( xmlAddChild(cur_parent_node,cur_node) == NULL ){
		  	RHP_BUG("");
			}
		}

		if( xmlNewProp(cur_node,prop_name,new_prop) == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		if( cur_attr ){
			xmlRemoveProp(cur_attr);
		}
	}

	if( cur_prop ){
		_rhp_free(cur_prop);
	}
	if( new_prop ){
		_rhp_free(new_prop);
	}
	return 0;

error:
	if( cur_prop ){
		_rhp_free(cur_prop);
	}
	if( new_prop ){
		_rhp_free(new_prop);
	}
	return err;
}

int rhp_xml_replace_child(xmlNodePtr cur_parent_node,xmlNodePtr new_parent_node,xmlChar* elm_tag,int clear_flag)
{
	int err = -EINVAL;
	xmlNodePtr cur_node,new_node;
	xmlNodePtr dup_node = NULL;

	cur_node = rhp_xml_get_child(cur_parent_node,elm_tag);
	new_node =  rhp_xml_get_child(new_parent_node,elm_tag);

	if( new_node ){

		dup_node = xmlCopyNode(new_node,1);
		if( dup_node == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		if( xmlAddChild(cur_parent_node,dup_node) == NULL ){
			err = -EINVAL;
			RHP_BUG("");
			goto error;
		}

		if( cur_node ){
			xmlUnlinkNode(cur_node);
			xmlFreeNode(cur_node);
		}

	}else if( clear_flag ){

		if( cur_node ){
			xmlUnlinkNode(cur_node);
			xmlFreeNode(cur_node);
		}
	}

	return 0;

error:
	if( dup_node ){
		xmlFreeNode(dup_node);
	}
	return err;
}

int rhp_xml_str2val(xmlChar* str,int data_type,void* retval,int* retval_len,void* def_val,int def_val_len)
{
  char* endp;
  char* p;

  if( str == NULL || *str == '\0' ){

    if( def_val != NULL ){

      switch( data_type ){

      	case RHP_XML_DT_INT:
      	{
      		*((int*)retval) = *((int*)def_val);
      		*retval_len = sizeof(int);

					RHP_TRC_FREQ(0,RHPTRCID_XML_STR2VAL_DEF_INT,"sLdpp",str,"XML_DT",data_type,*retval_len,retval,def_val_len,def_val);
					return 0;
				}
				break;

				case RHP_XML_DT_UINT:
				{
					*((unsigned int*)retval) = *((unsigned int*)def_val);
					*retval_len = sizeof(unsigned int);

					RHP_TRC_FREQ(0,RHPTRCID_XML_STR2VAL_DEF_UINT,"sLdpp",str,"XML_DT",data_type,*retval_len,retval,def_val_len,def_val);
					return 0;
				}
				break;

				case RHP_XML_DT_LONG:
        {
          *((long*)retval) = *((long*)def_val);
          *retval_len = sizeof(long);

          RHP_TRC_FREQ(0,RHPTRCID_XML_STR2VAL_DEF_LONG,"sLdpp",str,"XML_DT",data_type,*retval_len,retval,def_val_len,def_val);
          return 0;
        }
        break;

        case RHP_XML_DT_ULONG:
        {
          *((unsigned long*)retval) = *((unsigned long*)def_val);
          *retval_len = sizeof(unsigned long);

          RHP_TRC_FREQ(0,RHPTRCID_XML_STR2VAL_DEF_ULONG,"sLdpp",str,"XML_DT",data_type,*retval_len,retval,def_val_len,def_val);
          return 0;
        }
        break;

        case RHP_XML_DT_LONGLONG:
        {
          *((long long*)retval) = *((long long*)def_val);
          *retval_len = sizeof(long long);

          RHP_TRC_FREQ(0,RHPTRCID_XML_STR2VAL_DEF_LONGLONG,"sLdpp",str,"XML_DT",data_type,*retval_len,retval,def_val_len,def_val);
          return 0;
        }
        break;

        case RHP_XML_DT_ULONGLONG:
        {
          *((unsigned long long*)retval) = *((unsigned long long*)def_val);
          *retval_len = sizeof(unsigned long long);

          RHP_TRC_FREQ(0,RHPTRCID_XML_STR2VAL_DEF_ULONGLONG,"sLdpp",str,"XML_DT",data_type,*retval_len,retval,def_val_len,def_val);
          return 0;
        }
        break;

        case RHP_XML_DT_DOUBLE:
        {
          *((double*)retval) = *((double*)def_val);
          *retval_len = sizeof(double);

          RHP_TRC_FREQ(0,RHPTRCID_XML_STR2VAL_DEF_DOUBLE,"sLdpp",str,"XML_DT",data_type,*retval_len,retval,def_val_len,def_val);
          return 0;
        }
        break;

        case RHP_XML_DT_IPV4:
        {
          *((u32*)retval) = htonl(*((u32*)def_val));
          *retval_len = sizeof(u32);

          RHP_TRC_FREQ(0,RHPTRCID_XML_STR2VAL_DEF_IPV4,"sLdpp",str,"XML_DT",data_type,*retval_len,retval,def_val_len,def_val);
          return 0;
        }
        break;

        case RHP_XML_DT_PORT:
        {
          *((u16*)retval) = htons(*((u16*)def_val));
          *retval_len = sizeof(u16);

          RHP_TRC_FREQ(0,RHPTRCID_XML_STR2VAL_DEF_PORT,"sLdpp",str,"XML_DT",data_type,*retval_len,retval,def_val_len,def_val);
          return 0;
        }
        break;

        case RHP_XML_DT_STRING:
        {
          char* ret_str = (char*)_rhp_malloc(strlen((char*)def_val)+1);

          if( ret_str == NULL ){
            RHP_BUG("%d",data_type);
            return -1;
          }

          ret_str[0] = '\0';
          strcpy(ret_str,(char*)def_val);

          *((char**)retval) = ret_str;
          *retval_len = strlen(ret_str) + 1;

          RHP_TRC_FREQ(0,RHPTRCID_XML_STR2VAL_DEF_STRING,"sLdpp",str,"XML_DT",data_type,*retval_len,*((u8**)retval),def_val_len,def_val);
          return 0;
        }
        break;

        case RHP_XML_DT_BASE64:
        {
          u8* ret_bin = (u8*)_rhp_malloc(def_val_len);

          if( ret_bin == NULL ){
            RHP_BUG("%d",data_type);
            return -1;
          }
          memcpy(ret_bin,(u8*)def_val,def_val_len);

          *((u8**)retval) = ret_bin;
          *retval_len = def_val_len;

          RHP_TRC_FREQ(0,RHPTRCID_XML_STR2VAL_DEF_BASE64,"sLdpp",str,"XML_DT",data_type,*retval_len,*((u8**)retval),def_val_len,def_val);
          return 0;
        }
        break;

        case RHP_XML_DT_IPV4_SUBNET:
        {
          rhp_ip_addr* ret_ipv4;

          ret_ipv4 = (rhp_ip_addr*)_rhp_malloc(sizeof(rhp_ip_addr));
          if( ret_ipv4 == NULL ){
            RHP_BUG("%d",data_type);
            return -1;
          }
          memcpy((u8*)ret_ipv4,(u8*)def_val,sizeof(rhp_ip_addr));

          ret_ipv4->addr_family = AF_INET;
          *((rhp_ip_addr**)retval) = ret_ipv4;
          *retval_len = sizeof(rhp_ip_addr);

          RHP_TRC_FREQ(0,RHPTRCID_XML_STR2VAL_DEF_IPV4_SUBNET,"sLdpp",str,"XML_DT",data_type,*retval_len,*((u8**)retval),def_val_len,def_val);
          return 0;
        }
        break;

        case RHP_XML_DT_DN_DER:
        {
          u8* ret_bin = (u8*)_rhp_malloc(def_val_len);

          if( ret_bin == NULL ){
            RHP_BUG("%d",data_type);
            return -1;
          }
          memcpy(ret_bin,(u8*)def_val,def_val_len);

          *((u8**)retval) = ret_bin;
          *retval_len = def_val_len;

          RHP_TRC_FREQ(0,RHPTRCID_XML_STR2VAL_DEF_DN_DER,"sLdpp",str,"XML_DT",data_type,*retval_len,*((u8**)retval),def_val_len,def_val);
          return 0;
        }
        break;

        case RHP_XML_DT_IPV6:
        {
          rhp_ip_addr* ret_ipv6 = (rhp_ip_addr*)retval;

          memcpy((u8*)ret_ipv6,(u8*)def_val,sizeof(rhp_ip_addr));
          *retval_len = sizeof(rhp_ip_addr);

          RHP_TRC_FREQ(0,RHPTRCID_XML_STR2VAL_DEF_IPV6,"sLdpp",str,"XML_DT",data_type,*retval_len,retval,def_val_len,def_val);
          return 0;
        }
        break;

        case RHP_XML_DT_IPV6_SUBNET:
        {
          rhp_ip_addr* ret_ipv6;

          ret_ipv6 = (rhp_ip_addr*)_rhp_malloc(sizeof(rhp_ip_addr));
          if( ret_ipv6 == NULL ){
            RHP_BUG("%d",data_type);
            return -1;
          }
          memcpy((u8*)ret_ipv6,(u8*)def_val,sizeof(rhp_ip_addr));

          ret_ipv6->addr_family = AF_INET6;
          *((rhp_ip_addr**)retval) = ret_ipv6;
          *retval_len = sizeof(rhp_ip_addr);

          RHP_TRC_FREQ(0,RHPTRCID_XML_STR2VAL_DEF_IPV6_SUBNET,"sLdpp",str,"XML_DT",data_type,*retval_len,*((u8**)retval),def_val_len,def_val);
          return 0;
        }
        break;

        default:
          RHP_BUG("%d",data_type);
          break;
      }

    }else{
    	RHP_TRC_FREQ(0,RHPTRCID_XML_STR2VAL_ERR_NOENT,"sd",str,data_type);
    	return -ENOENT;
    }

  	RHP_TRC_FREQ(0,RHPTRCID_XML_STR2VAL_ERR_DEF,"sd",str,data_type);
    goto error;
  }

  switch( data_type ){

		case RHP_XML_DT_INT:
		{
			int ret_int = (int)strtol((char*)str,&endp,0);
			if( *endp != '\0' ){
				RHP_TRC_FREQ(0,RHPTRCID_XML_STR2VAL_ERR_TRS_INT,"sdEbd",str,data_type,-errno,*endp,ret_int);
				return -1;
			}
			*((int*)retval) = ret_int;
			*retval_len = sizeof(int);

			RHP_TRC_FREQ(0,RHPTRCID_XML_STR2VAL_INT,"sLdp",str,"XML_DT",data_type,*retval_len,retval);
			return 0;
		}
			break;

		case RHP_XML_DT_UINT:
		{
			unsigned int ret_uint = (unsigned int)strtoul((char*)str,&endp,0);
			if( *endp != '\0' ){
				RHP_TRC_FREQ(0,RHPTRCID_XML_STR2VAL_ERR_TRS_UINT,"sdEbu",str,data_type,-errno,*endp,ret_uint);
				return -1;
			}
			*((unsigned int*)retval) = ret_uint;
			*retval_len = sizeof(unsigned int);

			RHP_TRC_FREQ(0,RHPTRCID_XML_STR2VAL_UINT,"sLdp",str,"XML_DT",data_type,*retval_len,retval);
			return 0;
		}
		break;

		case RHP_XML_DT_LONG:
    {
      long ret_long = strtol((char*)str,&endp,0);
      if( *endp != '\0' ){
      	RHP_TRC_FREQ(0,RHPTRCID_XML_STR2VAL_ERR_TRS_LONG,"sdEbf",str,data_type,-errno,*endp,ret_long);
        return -1;
      }
      *((long*)retval) = ret_long;
      *retval_len = sizeof(long);

      RHP_TRC_FREQ(0,RHPTRCID_XML_STR2VAL_LONG,"sLfp",str,"XML_DT",data_type,*retval_len,retval);
      return 0;
    }
      break;

    case RHP_XML_DT_ULONG:
    {
      unsigned long ret_ulong = strtoul((char*)str,&endp,0);
      if( *endp != '\0' ){
      	RHP_TRC_FREQ(0,RHPTRCID_XML_STR2VAL_ERR_TRS_ULONG,"sdEbF",str,data_type,-errno,*endp,ret_ulong);
        return -1;
      }
      *((unsigned long*)retval) = ret_ulong;
      *retval_len = sizeof(unsigned long);

      RHP_TRC_FREQ(0,RHPTRCID_XML_STR2VAL_ULONG,"sLFp",str,"XML_DT",data_type,*retval_len,retval);
      return 0;
    }
    break;

    case RHP_XML_DT_LONGLONG:
    {
      long long ret_longlong = strtoll((char*)str,&endp,0);
      if( *endp != '\0' ){
      	RHP_TRC_FREQ(0,RHPTRCID_XML_STR2VAL_ERR_TRS_LONGLONG,"sdEbq",str,data_type,-errno,*endp,ret_longlong);
        return -1;
      }
      *((long long*)retval) = ret_longlong;
      *retval_len = sizeof(long long);

      RHP_TRC_FREQ(0,RHPTRCID_XML_STR2VAL_LONGLONG,"sLdp",str,"XML_DT",data_type,*retval_len,retval);
      return 0;
    }
    break;

    case RHP_XML_DT_DOUBLE:
    {
      double ret_double = strtod((char*)str,&endp);
      if( *endp != '\0' ){
      	RHP_TRC_FREQ(0,RHPTRCID_XML_STR2VAL_ERR_TRS_DOUBLE,"sdEbq",str,data_type,-errno,*endp,ret_double);
        return -1;
      }
      *((double*)retval) = ret_double;
      *retval_len = sizeof(double);

      RHP_TRC_FREQ(0,RHPTRCID_XML_STR2VAL_DOUBLE,"sLdp",str,"XML_DT",data_type,*retval_len,retval);
      return 0;
    }
    break;

    case RHP_XML_DT_ULONGLONG:
    {
      unsigned long long ret_ulonglong = strtoull((char*)str,&endp,0);
      if( *endp != '\0' ){
      	RHP_TRC_FREQ(0,RHPTRCID_XML_STR2VAL_ERR_TRS_ULONGLONG,"sdEbq",str,data_type,-errno,*endp,ret_ulonglong);
        return -1;
      }
      *((unsigned long long*)retval) = ret_ulonglong;
      *retval_len = sizeof(unsigned long long);

      RHP_TRC_FREQ(0,RHPTRCID_XML_STR2VAL_ULONGLONG,"sLdp",str,"XML_DT",data_type,*retval_len,retval);
      return 0;
    }
    break;

    case RHP_XML_DT_IPV4:
    {
      struct in_addr inp;
      if( !inet_aton((char*)str,&inp ) ){

				RHP_LOG_DE(RHP_LOG_SRC_CFG,0,RHP_LOG_ID_PARSE_ERR_XML_IPV4_ATTR,"s",(char*)str);

      	RHP_TRC_FREQ(0,RHPTRCID_XML_STR2VAL_ERR_TRS_IPV4,"sd",str,data_type);
        return -1;
      }
      *((u32*)retval) = inp.s_addr;
      *retval_len = sizeof(u32);

      RHP_TRC_FREQ(0,RHPTRCID_XML_STR2VAL_IPV4,"sLdp",str,"XML_DT",data_type,*retval_len,retval);
      return 0;
    }
      break;

    case RHP_XML_DT_PORT:
    {
      long ret_port = strtol((char*)str,&endp,0);
      if( *endp != '\0' ){
      	RHP_TRC_FREQ(0,RHPTRCID_XML_STR2VAL_ERR_TRS_PORT,"sd",str,data_type);
        return -1;
      }

      if( ret_port > 0xFFFF ){
      	RHP_TRC_FREQ(0,RHPTRCID_XML_STR2VAL_ERR_TRS_PORT_2,"sd",str,data_type);
        return -1;
      }

      *((u16*)retval) = htons((u16)ret_port);
      *retval_len = sizeof(u16);

      RHP_TRC_FREQ(0,RHPTRCID_XML_STR2VAL_PORT,"sLdp",str,"XML_DT",data_type,*retval_len,retval);
      return 0;
    }
      break;

    case RHP_XML_DT_STRING:
    {
      char* ret_str = (char*)_rhp_malloc(strlen((char*)str)+1);

      if( ret_str == NULL ){
      	RHP_TRC_FREQ(0,RHPTRCID_XML_STR2VAL_ERR_TRS_STRING,"sd",str,data_type);
        return -1;
      }

      ret_str[0] = '\0';
      strcpy(ret_str,(char*)str);

      *((char**)retval) = ret_str;
      *retval_len = strlen(ret_str) + 1;

      RHP_TRC_FREQ(0,RHPTRCID_XML_STR2VAL_STRING,"sLdp",str,"XML_DT",data_type,*retval_len,*((u8**)retval));
      return 0;
    }
      break;


    case RHP_XML_DT_BASE64:
    {
    	int bs64_err = rhp_base64_decode(str,(u8**)retval,retval_len);
    	if( bs64_err ){

				RHP_LOG_DE(RHP_LOG_SRC_CFG,0,RHP_LOG_ID_PARSE_ERR_XML_BASE64_ATTR,"s",(char*)str);

    		RHP_TRC_FREQ(0,RHPTRCID_XML_STR2VAL_ERR_TRS_BASE64,"sdE",str,data_type,bs64_err);
    	}else{
        RHP_TRC_FREQ(0,RHPTRCID_XML_STR2VAL_BASE64,"sLdp",str,"XML_DT",data_type,*retval_len,*((u8**)retval));
    	}
    	return bs64_err;
    }

    case RHP_XML_DT_IPV4_SUBNET:
    {
      struct in_addr inp;
      rhp_ip_addr* ret_ipv4;

      ret_ipv4 = (rhp_ip_addr*)_rhp_malloc(sizeof(rhp_ip_addr));
      if( ret_ipv4 == NULL ){
      	RHP_TRC_FREQ(0,RHPTRCID_XML_STR2VAL_ERR_TRS_IPV4_SUBNET,"sd",str,data_type);
        return -1;
      }
      memset(ret_ipv4,0,sizeof(rhp_ip_addr));

      ret_ipv4->addr_family = AF_INET;

      p = (char*)str;
      while( *p != '\0' ){
        if( *p == '/' ){
          break;
        }
        p++;
      }

      if( *p == '/' ){

        *p = '\0';

        if( !inet_aton((char*)str,&inp ) ){
          *p = '/';
  				RHP_LOG_DE(RHP_LOG_SRC_CFG,0,RHP_LOG_ID_PARSE_ERR_XML_IPV4_SUBNET_ATTR,"s",(char*)str);
          RHP_BUG("%s",str);
          _rhp_free(ret_ipv4);
        	RHP_TRC_FREQ(0,RHPTRCID_XML_STR2VAL_ERR_TRS_IPV4_SUBNET_2,"sd",str,data_type);
          return -1;
        }
        ret_ipv4->addr.v4 = inp.s_addr;

        ret_ipv4->prefixlen = (u8)strtol((p+1),&endp,10);
        if( *endp != '\0' ){
          _rhp_free(ret_ipv4);
          *p = '/';
  				RHP_LOG_DE(RHP_LOG_SRC_CFG,0,RHP_LOG_ID_PARSE_ERR_XML_IPV4_SUBNET_ATTR,"s",(char*)str);
          RHP_BUG("%s",p+1);
        	RHP_TRC_FREQ(0,RHPTRCID_XML_STR2VAL_ERR_TRS_IPV4_SUBNET_3,"sd",str,data_type);
          return -1;
        }

        *p = '/';

        if( ret_ipv4->prefixlen < 0 || ret_ipv4->prefixlen > 32 ){
  				RHP_LOG_DE(RHP_LOG_SRC_CFG,0,RHP_LOG_ID_PARSE_ERR_XML_IPV4_SUBNET_ATTR,"s",(char*)str);
          RHP_BUG("%d",ret_ipv4->prefixlen);
          _rhp_free(ret_ipv4);
        	RHP_TRC_FREQ(0,RHPTRCID_XML_STR2VAL_ERR_TRS_IPV4_SUBNET_4,"sd",str,data_type);
          return -1;
        }

        if( ret_ipv4->prefixlen >= 32 ){
          ret_ipv4->netmask.v4 = 0xFFFFFFFF;
        }else if( ret_ipv4->prefixlen == 0 ){
          ret_ipv4->netmask.v4 = 0;
        }else{
          int a,b;
          for( a = 31,b = 0; b < ret_ipv4->prefixlen; b++,a-- ){
            ret_ipv4->netmask.v4 |= (1 << a);
          }
          ret_ipv4->netmask.v4 = htonl(ret_ipv4->netmask.v4);
        }

      }else{

        if( !inet_aton((char*)str,&inp ) ){
  				RHP_LOG_DE(RHP_LOG_SRC_CFG,0,RHP_LOG_ID_PARSE_ERR_XML_IPV4_SUBNET_ATTR,"s",(char*)str);
          RHP_BUG("%s",str);
          _rhp_free(ret_ipv4);
        	RHP_TRC_FREQ(0,RHPTRCID_XML_STR2VAL_ERR_TRS_IPV4_SUBNET_5,"sd",str,data_type);
          return -1;
        }
        ret_ipv4->addr.v4 = inp.s_addr;
        ret_ipv4->prefixlen = 32;
        ret_ipv4->netmask.v4 = 0xFFFFFFFF;
      }

      *((rhp_ip_addr**)retval) = ret_ipv4;
      *retval_len = sizeof(rhp_ip_addr);

      RHP_TRC_FREQ(0,RHPTRCID_XML_STR2VAL_IPV4_SUBNET,"sLdp",str,"XML_DT",data_type,*retval_len,*((u8**)retval));
      return 0;
    }
      break;

    case RHP_XML_DT_DN_DER:
    {
      rhp_cert_dn* cert_dn;

      cert_dn = rhp_cert_dn_alloc_by_text((char*)str);
      if( cert_dn == NULL ){
				RHP_LOG_DE(RHP_LOG_SRC_CFG,0,RHP_LOG_ID_PARSE_ERR_XML_DN_ATTR,"s",(char*)str);
      	RHP_TRC_FREQ(0,RHPTRCID_XML_STR2VAL_ERR_TRS_DN_DER,"sd",str,data_type);
        return -1;
      }

      if( cert_dn->DER_encode(cert_dn,(u8**)retval,retval_len) ){
        rhp_cert_dn_free(cert_dn);
      	RHP_TRC_FREQ(0,RHPTRCID_XML_STR2VAL_ERR_TRS_DN_DER,"sd",str,data_type);
        return -1;
      }

      rhp_cert_dn_free(cert_dn);

      RHP_TRC_FREQ(0,RHPTRCID_XML_STR2VAL_DN_DER,"sLdp",str,"XML_DT",data_type,*retval_len,*((u8**)retval));
      return 0;
    }
      break;

    case RHP_XML_DT_IPV6:
    {
    	rhp_ip_addr* ret_ipv6 = (rhp_ip_addr*)retval;

    	if( rhp_ip_str2addr(AF_INET6,(char*)str,ret_ipv6) ){
				RHP_LOG_DE(RHP_LOG_SRC_CFG,0,RHP_LOG_ID_PARSE_ERR_XML_IPV6_ATTR,"s",(char*)str);
        RHP_BUG("%s",str);
      	RHP_TRC_FREQ(0,RHPTRCID_XML_STR2VAL_ERR_TRS_IPV6,"sd",str,data_type);
    		return -1;
    	}

      *retval_len = sizeof(rhp_ip_addr);

      RHP_TRC_FREQ(0,RHPTRCID_XML_STR2VAL_IPV6,"sLdp",str,"XML_DT",data_type,*retval_len,retval);
      return 0;
    }
    	break;

    case RHP_XML_DT_IPV6_SUBNET:
    {
      rhp_ip_addr* ret_ipv6;
      int is_subnet = 0;

      ret_ipv6 = (rhp_ip_addr*)_rhp_malloc(sizeof(rhp_ip_addr));
      if( ret_ipv6 == NULL ){
      	RHP_BUG("");
        return -1;
      }
      memset(ret_ipv6,0,sizeof(rhp_ip_addr));

      ret_ipv6->addr_family = AF_INET6;

      p = (char*)str;
      while( *p != '\0' ){
        if( *p == '/' ){
          break;
        }
        p++;
      }

      if( *p == '/' ){
        *p = '\0';
        is_subnet = 1;
      }

      if( rhp_ip_str2addr(AF_INET6,(char*)str,ret_ipv6) ){
        if( is_subnet ){
          *p = '/';
        }
				_rhp_free(ret_ipv6);
				RHP_LOG_DE(RHP_LOG_SRC_CFG,0,RHP_LOG_ID_PARSE_ERR_XML_IPV6_SUBNET_ATTR,"s",(char*)str);
        RHP_BUG("%s",str);
				RHP_TRC_FREQ(0,RHPTRCID_XML_STR2VAL_ERR_TRS_IPV6_SUBNET_1,"sd",str,data_type);
				return -1;
      }

      if( is_subnet ){

				ret_ipv6->prefixlen = (u8)strtol((p+1),&endp,10);
				if( *endp != '\0' ){
					*p = '/';
					_rhp_free(ret_ipv6);
					RHP_LOG_DE(RHP_LOG_SRC_CFG,0,RHP_LOG_ID_PARSE_ERR_XML_IPV6_SUBNET_ATTR,"s",(char*)str);
	        RHP_BUG("%s",str);
					RHP_TRC_FREQ(0,RHPTRCID_XML_STR2VAL_ERR_TRS_IPV6_SUBNET_2,"sd",str,data_type);
					return -1;
				}

				*p = '/';

				if( ret_ipv6->prefixlen < 0 || ret_ipv6->prefixlen > 128 ){
					_rhp_free(ret_ipv6);
					RHP_LOG_DE(RHP_LOG_SRC_CFG,0,RHP_LOG_ID_PARSE_ERR_XML_IPV6_SUBNET_ATTR,"s",(char*)str);
	        RHP_BUG("%s",str);
					RHP_TRC_FREQ(0,RHPTRCID_XML_STR2VAL_ERR_TRS_IPV6_SUBNET_3,"sd",str,data_type);
					return -1;
				}

				rhp_ipv6_prefixlen_to_netmask(ret_ipv6->prefixlen,ret_ipv6->netmask.v6);

      }else{

      	ret_ipv6->prefixlen = 128;
      	memset(ret_ipv6->netmask.v6,0xFF,16);
      }

      *((rhp_ip_addr**)retval) = ret_ipv6;
      *retval_len = sizeof(rhp_ip_addr);

      RHP_TRC_FREQ(0,RHPTRCID_XML_STR2VAL_IPV6_SUBNET,"sLdp",str,"XML_DT",data_type,*retval_len,*((u8**)retval));
      return 0;
    }
      break;

    default:
    	RHP_BUG("%s:%d",str,data_type);
      break;
  }

	RHP_TRC_FREQ(0,RHPTRCID_XML_STR2VAL_ERR_RTRN,"sd",str,data_type);

error:
  return -1;
}

int rhp_xml_check_enable(xmlNodePtr node,const xmlChar* prop_name,int* flag_r)
{
	xmlChar* prop_val = rhp_xml_get_prop(node,prop_name);

	if( prop_val ){

		if( !rhp_xml_strcasecmp(prop_val,(xmlChar*)"enable") ){
			*flag_r = 1;
		}else	if( !rhp_xml_strcasecmp(prop_val,(xmlChar*)"disable") ){
			*flag_r = 0;
		}

		_rhp_free(prop_val);

	}else{
		return -ENOENT;
	}

	return 0;
}

void rhp_xml_doc_dump(char* label,xmlDocPtr doc)
{
	int size = 0;
	xmlChar* text = NULL;

	_RHP_TRC_FLG_UPDATE(_rhp_trc_user_id());
  if( _RHP_TRC_COND(_rhp_trc_user_id(),0) ){

		xmlDocDumpMemory(doc,&text,&size)	;

		if( size ){

			RHP_TRC_FREQ(0,RHPTRCID_XML_DOC_DUMP,"sds",label,size,text);

			xmlFree(text);

		}else{

			RHP_BUG("");
		}
  }

	return;
}

void rhp_ikev2_id_clear(rhp_ikev2_id* id)
{
  rhp_ikev2_id_dump("rhp_ikev2_id_clear",id);

  if( id->string ){
    _rhp_free(id->string);
    id->string = NULL;
  }

  if( id->dn_der ){
    _rhp_free(id->dn_der);
    id->dn_der = NULL;
    id->dn_der_len = 0;
  }

  if( id->alt_id ){
  	rhp_ikev2_id_clear(id->alt_id);
  	_rhp_free(id->alt_id);
  	id->alt_id = NULL;
  }

  if( id->conn_name_for_null_id ){
  	_rhp_free(id->conn_name_for_null_id);
  	id->conn_name_for_null_id = NULL;
  }


  memset(&(id->addr),0,sizeof(rhp_ip_addr));

  id->type = RHP_PROTO_IKE_ID_ANY;
  id->cert_sub_type = RHP_PROTO_IKE_ID_ANY;

  return;
}

int rhp_eap_id_setup(int method, // RHP_PROTO_EAP_TYPE_XXX
		int identity_len, // NOT including the last '\0'
		u8* identity,		 	// NOT '\0' terminated.
		int for_xauth,
		rhp_eap_id* eap_id_r)
{
	if( identity ){

		eap_id_r->identity = (u8*)_rhp_malloc(identity_len + 1);
		if( eap_id_r->identity == NULL ){
			RHP_BUG("");
			return -ENOMEM;
		}

		memcpy(eap_id_r->identity,identity,identity_len);
		eap_id_r->identity[identity_len] = '\0';

		eap_id_r->identity_len = identity_len;

		eap_id_r->for_xauth = for_xauth;
	}

	eap_id_r->method = method;

	return 0;
}

void rhp_eap_id_clear(rhp_eap_id* id)
{
	rhp_eap_id_dump("rhp_eap_id_clear",id);

	if( id->identity ){
		_rhp_free(id->identity);
		id->identity = NULL;
	}

	if( id->radius.user_index ){
		_rhp_free(id->radius.user_index);
		id->radius.user_index = NULL;
	}

	if( id->radius.assigned_addr_v4 ){
		_rhp_free(id->radius.assigned_addr_v4);
		id->radius.assigned_addr_v4 = NULL;
	}

	if( id->radius.assigned_addr_v6 ){
		_rhp_free(id->radius.assigned_addr_v6);
		id->radius.assigned_addr_v6 = NULL;
	}

	id->method = RHP_PROTO_EAP_TYPE_NONE;
	id->identity_len = 0;

	id->radius.eap_method = RHP_PROTO_EAP_TYPE_NONE;

	return;
}

int rhp_ikev2_id_dup(rhp_ikev2_id* id_to,rhp_ikev2_id* id_from)
{
  rhp_ikev2_id id;

//  rhp_ikev2_id_dump("rhp_ikev2_id_dup:from",id_from);

  memset(&id,0,sizeof(rhp_ikev2_id));
  id.type = id_from->type;
  id.cert_sub_type = id_from->cert_sub_type;

  if( id_from->string ){
  	int slen = strlen(id_from->string) + 1;
    id.string = (char*)_rhp_malloc(slen);
    if( id.string == NULL ){
  		RHP_BUG("");
      goto error;
    }
    memset(id.string,0,slen);
    memcpy(id.string,id_from->string,slen);
  }

  if( id_from->dn_der ){
    id.dn_der = (u8*)_rhp_malloc(id_from->dn_der_len);
    if( id.dn_der == NULL ){
  		RHP_BUG("");
      goto error;
    }
    memset(id.dn_der,0,id_from->dn_der_len);
    memcpy(id.dn_der,id_from->dn_der,id_from->dn_der_len);
    id.dn_der_len = id_from->dn_der_len;
  }

  if( id_from->conn_name_for_null_id ){
  	int slen = strlen(id_from->conn_name_for_null_id) + 1;
    id.conn_name_for_null_id = (char*)_rhp_malloc(slen);
    if( id.conn_name_for_null_id == NULL ){
  		RHP_BUG("");
      goto error;
    }
    memset(id.conn_name_for_null_id,0,slen);
    memcpy(id.conn_name_for_null_id,id_from->conn_name_for_null_id,slen);
  }

  memcpy(&(id.addr),&(id_from->addr),sizeof(rhp_ip_addr));


  memcpy(id_to,&id,sizeof(rhp_ikev2_id));

  if( id_from->alt_id ){

  	id_to->alt_id = (rhp_ikev2_id*)_rhp_malloc(sizeof(rhp_ikev2_id));
  	if( id_to->alt_id == NULL ){
  		RHP_BUG("");
  		goto error;
  	}

  	if( rhp_ikev2_id_dup(id_to->alt_id,id_from->alt_id) ){
  		RHP_BUG("");
  		goto error;
  	}
  }

  rhp_ikev2_id_dump("rhp_ikev2_id_dup:to",id_to);
  return 0;

error:
  if( id.string ){
    _rhp_free(id.string);
  }
  if( id.dn_der ){
  	_rhp_free(id.dn_der);
  }
  return -ENOMEM;
}

int rhp_eap_id_dup(rhp_eap_id* id_to,rhp_eap_id* id_from)
{
	int err = -EINVAL;
	rhp_eap_id id;

	rhp_eap_id_dump("rhp_eap_id_dup:from",id_from);

	memset(&id,0,sizeof(rhp_eap_id));

	id.method = id_from->method;
	if( id_from->identity && id_from->identity_len ){

		id.identity = (u8*)_rhp_malloc(id_from->identity_len + 1);
		if( id.identity == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		memcpy(id.identity,id_from->identity,id_from->identity_len);
		id.identity[id_from->identity_len] = '\0';

		id.identity_len = id_from->identity_len;
	}

	if( id_from->method == RHP_PROTO_EAP_TYPE_PRIV_RADIUS ){

		id.radius.eap_method = id_from->radius.eap_method;

		if( id_from->radius.user_index ){

			int user_index_len = strlen(id_from->radius.user_index);

			id.radius.user_index = (char*)_rhp_malloc(user_index_len + 1);
			if( id.radius.user_index == NULL ){
				RHP_BUG("");
				err = -ENOMEM;
				goto error;
			}

			memcpy(id.radius.user_index,id_from->radius.user_index,user_index_len);
			id.radius.user_index[user_index_len] = '\0';
		}

		if( id_from->radius.assigned_addr_v4 ){

			id.radius.assigned_addr_v4 = (rhp_ip_addr*)_rhp_malloc(sizeof(rhp_ip_addr));
			if( id.radius.assigned_addr_v4 == NULL ){
				RHP_BUG("");
				err = -ENOMEM;
				goto error;
			}

			memcpy(id.radius.assigned_addr_v4,id_from->radius.assigned_addr_v4,sizeof(rhp_ip_addr));
		}

		if( id_from->radius.assigned_addr_v6 ){

			id.radius.assigned_addr_v6 = (rhp_ip_addr*)_rhp_malloc(sizeof(rhp_ip_addr));
			if( id.radius.assigned_addr_v6 == NULL ){
				RHP_BUG("");
				err = -ENOMEM;
				goto error;
			}

			memcpy(id.radius.assigned_addr_v6,id_from->radius.assigned_addr_v6,sizeof(rhp_ip_addr));
		}

		id.radius.salt = id_from->radius.salt;

	}else{

		id.radius.eap_method = RHP_PROTO_EAP_TYPE_NONE;
	}


	memcpy(id_to,&id,sizeof(rhp_eap_id));

	rhp_eap_id_dump("rhp_eap_id_dup:to",id_to);
	return 0;

error:
	rhp_eap_id_clear(&id);
	return err;
}


int rhp_ikev2_id_setup_ex(int type,void* val,int val_len,
		void* val2,int val2_len,rhp_ikev2_id* id_to)
{
   if( type == RHP_PROTO_IKE_ID_FQDN ||
  		 type == RHP_PROTO_IKE_ID_RFC822_ADDR ){

     id_to->string = (char*)_rhp_malloc(val_len + 1); // val_len NOT including '\0'.
     if( id_to->string == NULL ){
			 RHP_BUG("");
       return -ENOMEM;
     }
     memcpy(id_to->string,val,val_len);
     id_to->string[val_len] = '\0';

   }else if( type == RHP_PROTO_IKE_ID_DER_ASN1_DN ){

     id_to->dn_der = (u8*)_rhp_malloc(val_len);
     if( id_to->dn_der == NULL ){
			 RHP_BUG("");
       return -ENOMEM;
     }
     memcpy(id_to->dn_der,val,val_len);
     id_to->dn_der_len = val_len;

   }else if( type == RHP_PROTO_IKE_ID_IPV4_ADDR ){

  	 if( val_len != 4 ){
			 RHP_BUG("");
  		 return -EINVAL;
  	 }

  	 id_to->addr.addr_family = AF_INET;
  	 memcpy(id_to->addr.addr.raw,val,val_len);

   }else if( type == RHP_PROTO_IKE_ID_IPV6_ADDR ){

  	 if( val_len != 16 ){
			 RHP_BUG("");
  		 return -EINVAL;
  	 }

  	 id_to->addr.addr_family = AF_INET6;
  	 memcpy(id_to->addr.addr.raw,val,val_len);

   }else if( type == RHP_PROTO_IKE_ID_NULL_ID ){

  	 if( val_len ){

			 id_to->conn_name_for_null_id = (char*)_rhp_malloc(val_len + 1); // val_len NOT including '\0'.
			 if( id_to->conn_name_for_null_id == NULL ){
				 RHP_BUG("");
				 return -ENOMEM;
			 }
	     memcpy(id_to->conn_name_for_null_id,val,val_len);
	     id_to->conn_name_for_null_id[val_len] = '\0';
  	 }

   }else if( type == RHP_PROTO_IKE_ID_PRIVATE_NULL_ID_WITH_ADDR ){

  	 rhp_ip_addr* val_addr_port = (rhp_ip_addr*)val;

  	 if( val_len ){

  		 if( val_len != sizeof(rhp_ip_addr) ){
				 RHP_BUG("");
				 return -EINVAL;
			 }

			 if( val_addr_port->addr_family != AF_INET &&
					 val_addr_port->addr_family != AF_INET6 ){
				 RHP_BUG("");
				 return -EINVAL;
			 }

			 id_to->addr.addr_family = val_addr_port->addr_family;
			 id_to->addr.port = val_addr_port->port;
			 memcpy(id_to->addr.addr.raw,val_addr_port->addr.raw,16);
  	 }

  	 if( val2_len ){

			 id_to->conn_name_for_null_id = (char*)_rhp_malloc(val2_len + 1); // val_len NOT including '\0'.
			 if( id_to->conn_name_for_null_id == NULL ){
				 RHP_BUG("");
				 return -ENOMEM;
			 }
	     memcpy(id_to->conn_name_for_null_id,val2,val2_len);
	     id_to->conn_name_for_null_id[val2_len] = '\0';
  	 }

   }else{
  	 RHP_BUG("%d",type);
     return -EINVAL;
   }

   id_to->type = type;
   return 0;
}

int rhp_ikev2_id_setup(int type,void* val,int val_len,rhp_ikev2_id* id_to)
{
	return rhp_ikev2_id_setup_ex(type,val,val_len,NULL,0,id_to);
}

int rhp_ikev2_id_alt_setup(int type,void* val,int val_len,rhp_ikev2_id* id_to)
{
	int err = -EINVAL;

	id_to->alt_id = (rhp_ikev2_id*)_rhp_malloc(sizeof(rhp_ikev2_id));
	if( id_to->alt_id == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}
	memset(id_to->alt_id,0,sizeof(rhp_ikev2_id));

	err = rhp_ikev2_id_setup(type,val,val_len,id_to->alt_id);
	if( err ){
		RHP_BUG("");
		goto error;
	}

	return 0;

error:
	return err;
}

int rhp_ikev2_id_hash(rhp_ikev2_id* id,u32 rnd,u32* hval_r)
{
  u8* key;
  int key_len;

  if( id->string ){

  	key = (u8*)(id->string);
    key_len = strlen(id->string);

  }else if( id->dn_der ){

  	key = id->dn_der;
    key_len = id->dn_der_len;

  }else if( id->type == RHP_PROTO_IKE_ID_IPV4_ADDR ||
  					(id->type == RHP_PROTO_IKE_ID_PRIVATE_NULL_ID_WITH_ADDR && id->addr.addr_family == AF_INET) ){

  	key = id->addr.addr.raw;
    key_len = 4;

  }else if( id->type == RHP_PROTO_IKE_ID_IPV6_ADDR  ||
					 (id->type == RHP_PROTO_IKE_ID_PRIVATE_NULL_ID_WITH_ADDR && id->addr.addr_family == AF_INET6) ){

  	key = id->addr.addr.raw;
    key_len = 16;

  }else if( id->type == RHP_PROTO_IKE_ID_NULL_ID &&
  					id->conn_name_for_null_id ){

    key = (u8*)(id->conn_name_for_null_id);
    key_len = strlen(id->conn_name_for_null_id);

  }else{
    RHP_BUG("");
    return -ENOENT;
  }

  *hval_r = _rhp_hash_bytes(key,key_len,rnd);
  return 0;
}

int rhp_eap_id_hash(rhp_eap_id* eap_peer_id,u32 rnd,u32* hval_r)
{
	u32 hval;

	if( eap_peer_id->method == RHP_PROTO_EAP_TYPE_PRIV_RADIUS ){

		if( eap_peer_id->radius.user_index ){

			hval = _rhp_hash_bytes(eap_peer_id->radius.user_index,
							(u32)(int)strlen((char*)eap_peer_id->radius.user_index),rnd);

		}else if( eap_peer_id->radius.assigned_addr_v4 ){

			hval = _rhp_hash_bytes(&(eap_peer_id->radius.assigned_addr_v4->addr.v4),4,rnd);

		}else if( eap_peer_id->radius.assigned_addr_v6 ){

			hval = _rhp_hash_bytes(eap_peer_id->radius.assigned_addr_v6->addr.v6,16,rnd);

		}else if( eap_peer_id->radius.salt ){

			hval = eap_peer_id->radius.salt;

		}else{

			hval = _rhp_hash_bytes(eap_peer_id->identity,
							(u32)(eap_peer_id->identity_len ? eap_peer_id->identity_len : (int)strlen((char*)eap_peer_id->identity)),rnd);
		}

	}else{

		hval = _rhp_hash_bytes(eap_peer_id->identity,
						(u32)(eap_peer_id->identity_len ? eap_peer_id->identity_len : (int)strlen((char*)eap_peer_id->identity)),rnd);
	}

	*hval_r = hval;
	return 0;
}

static int _rhp_ikev2_id_value_impl(rhp_ikev2_id* id,
		u8** value_r,int* len_r,int* id_type_r,int to_str)
{
  u8* value = NULL;
  int id_type = 0;
  int len = 0;

	RHP_TRC(0,RHPTRCID_IKEV2_ID_VALUE,"xLdLdspxxxdx",id,"PROTO_IKE_ID",id->type,"PROTO_IKE_ID",id->cert_sub_type,id->string,id->dn_der_len,id->dn_der,value_r,len_r,id_type_r,to_str,id->alt_id);
	if( id->addr.addr_family ){
		rhp_ip_addr_dump("id.addr",&(id->addr));
	}

  id_type = id->type;

  switch( id->type ){

    case RHP_PROTO_IKE_ID_FQDN: // Returned value_r NOT including '\0'.
    case RHP_PROTO_IKE_ID_RFC822_ADDR:

value_string:
      if( id->string == NULL ){
      	RHP_TRC(0,RHPTRCID_IKEV2_ID_VALUE_NO_ENT_ERR1,"x",id);
        return -ENOENT;
      }

      len = strlen(id->string);

      value = (u8*)_rhp_malloc(len + (to_str ? 1 : 0));
      if( value == NULL ){
      	RHP_BUG("");
        return -ENOMEM;
      }

      memcpy(value,id->string,len); // '\0' NOT included.
      if( to_str ){
      	value[len] = '\0';
      	len++;
      }
      break;

    case RHP_PROTO_IKE_ID_DER_ASN1_DN:

value_dn:
      if( id->dn_der == NULL ){
      	RHP_TRC(0,RHPTRCID_IKEV2_ID_VALUE_NO_ENT_ERR2,"x",id);
        return -ENOENT;
      }

    	if( !to_str ){

    		value = (u8*)_rhp_malloc(id->dn_der_len);
				if( value == NULL ){
					RHP_BUG("");
					return -ENOMEM;
				}

				memcpy(value,id->dn_der,id->dn_der_len);
				len = id->dn_der_len;

    	}else{

    		rhp_cert_dn* dn = rhp_cert_dn_alloc_by_DER(id->dn_der,id->dn_der_len);

    		if( dn == NULL ){
    			RHP_BUG("");
    			return -ENOMEM;
    		}

    		value = (u8*)dn->to_text(dn);
				if( value == NULL ){
					RHP_BUG("");
	    		rhp_cert_dn_free(dn);
					return -ENOMEM;
				}
				len = strlen((char*)value) + 1;

    		rhp_cert_dn_free(dn);
    	}

      break;

    case RHP_PROTO_IKE_ID_PRIVATE_SUBJECTALTNAME:

      if( id->cert_sub_type == RHP_PROTO_IKE_ID_FQDN ||
          id->cert_sub_type == RHP_PROTO_IKE_ID_RFC822_ADDR ){

        id_type = id->cert_sub_type;
        goto value_string;
      }

    	RHP_TRC(0,RHPTRCID_IKEV2_ID_VALUE_NO_ENT_ERR3,"x",id);
      return -ENOENT;

    case RHP_PROTO_IKE_ID_PRIVATE_CERT_AUTO:

      if( id->cert_sub_type == RHP_PROTO_IKE_ID_FQDN ||
          id->cert_sub_type == RHP_PROTO_IKE_ID_RFC822_ADDR ){

        id_type = id->cert_sub_type;
        goto value_string;

      }else if( id->cert_sub_type == RHP_PROTO_IKE_ID_DER_ASN1_DN ){

      	id_type = id->cert_sub_type;
        goto value_dn;
      }

    	RHP_TRC(0,RHPTRCID_IKEV2_ID_VALUE_NO_ENT_ERR4,"x",id);
      return -ENOENT;

    case RHP_PROTO_IKE_ID_IPV4_ADDR:

    	if( !to_str ){

				len = 4;
				value = (u8*)_rhp_malloc(len);
				if( value == NULL ){
					RHP_BUG("");
					return -ENOMEM;
				}
				memcpy(value,id->addr.addr.raw,len);

    	}else{

    		char v4_str[32];
    		v4_str[0] = '\0';

    		snprintf(v4_str,32,"%d.%d.%d.%d",
    				((u8*)&(id->addr.addr.v4))[0],((u8*)&(id->addr.addr.v4))[1],
    				((u8*)&(id->addr.addr.v4))[2],((u8*)&(id->addr.addr.v4))[3]);

    		len = strlen(v4_str) + 1;
				value = (u8*)_rhp_malloc(len);
				if( value == NULL ){
					RHP_BUG("");
					return -ENOMEM;
				}
				memcpy(value,v4_str,len);
    	}

    	break;

    case RHP_PROTO_IKE_ID_IPV6_ADDR:

    	if( !to_str ){

    		len = 16;
				value = (u8*)_rhp_malloc(len);
				if( value == NULL ){
					RHP_BUG("");
					return -ENOMEM;
				}
				memcpy(value,id->addr.addr.raw,len);

    	}else{

    		char v6_str[INET6_ADDRSTRLEN + 1];

    		if( rhp_ipv6_string2(id->addr.addr.v6,v6_str) == NULL ){
					RHP_BUG("");
					return -ENOMEM;
    		}

    		len = strlen(v6_str) + 1;
				value = (u8*)_rhp_malloc(len);
				if( value == NULL ){
					RHP_BUG("");
					return -ENOMEM;
				}
				memcpy(value,v6_str,len);
    	}

    	break;

    case RHP_PROTO_IKE_ID_NULL_ID:

    	id_type = RHP_PROTO_IKE_ID_NULL_ID;

    	if( !to_str ){

  			len = 0;
  			value = NULL;

    	}else{

  			if( id->conn_name_for_null_id ){
  				len = strlen(id->conn_name_for_null_id) + 1;
  			}else{
  				len = strlen("Null") + 1;
  			}
				value = (u8*)_rhp_malloc(len);
				if( value == NULL ){
					RHP_BUG("");
					return -ENOMEM;
				}
				value[0] = '\0';

				snprintf((char*)value,len,"%s",(id->conn_name_for_null_id ? id->conn_name_for_null_id : "Null"));
    	}

    	break;

    case RHP_PROTO_IKE_ID_PRIVATE_NULL_ID_WITH_ADDR:

    	id_type = RHP_PROTO_IKE_ID_NULL_ID;

    	if( !to_str ){

  			len = 0;
  			value = NULL;

    	}else{

				char null_id_ip_str[INET6_ADDRSTRLEN + 1];
				null_id_ip_str[0] = '\0';

				if( id->addr.addr_family == AF_INET ){

					snprintf(null_id_ip_str,(INET6_ADDRSTRLEN + 1),"%d.%d.%d.%d",
							((u8*)&(id->addr.addr.v4))[0],((u8*)&(id->addr.addr.v4))[1],
							((u8*)&(id->addr.addr.v4))[2],((u8*)&(id->addr.addr.v4))[3]);

				}else if( id->addr.addr_family == AF_INET6 ){

					if( rhp_ipv6_string2(id->addr.addr.v6,null_id_ip_str) == NULL ){
						RHP_BUG("");
						return -ENOMEM;
					}

				}else{

					RHP_BUG("");
					return -EINVAL;
				}

  			if( id->conn_name_for_null_id ){
  				len = strlen(id->conn_name_for_null_id) + 1;
  			}else{
  				len = strlen("Null") + 1;
  			}
				len += strlen(null_id_ip_str) + 9;
				value = (u8*)_rhp_malloc(len);
				if( value == NULL ){
					RHP_BUG("");
					return -ENOMEM;
				}
				value[0] = '\0';

				if( id->addr.addr_family == AF_INET ){

					snprintf((char*)value,len,"%s:%d %s",null_id_ip_str,(int)ntohs(id->addr.port),(id->conn_name_for_null_id ? id->conn_name_for_null_id : "Null"));

				}else if( id->addr.addr_family == AF_INET6 ){

					snprintf((char*)value,len,"%s.%d %s",null_id_ip_str,(int)ntohs(id->addr.port),(id->conn_name_for_null_id ? id->conn_name_for_null_id : "Null"));
				}
    	}

    	break;

    default:
    	RHP_BUG("");
      return -EINVAL;
  }

  if( id_type_r ){
  	*id_type_r = id_type;
  }
  if( value_r ){
  	*value_r = value;
  }else{
  	_rhp_free(value);
  }
  if( len_r ){
  	*len_r = len;
  }
	RHP_TRC(0,RHPTRCID_IKEV2_ID_VALUE_RTRN,"xLdp",id,"PROTO_IKE_ID",(id_type_r ? *id_type_r : 0),(len_r ? *len_r : 0),(len_r && value_r ? *value_r : NULL));
  return 0;
}

int rhp_ikev2_id_value(rhp_ikev2_id* id,u8** value_r,int* len_r,int* id_type_r)
{
	return _rhp_ikev2_id_value_impl(id,value_r,len_r,id_type_r,0);
}

int rhp_ikev2_id_value_str(rhp_ikev2_id* id,u8** value_r,int* len_r,int* id_type_r)
{
	return _rhp_ikev2_id_value_impl(id,value_r,len_r,id_type_r,1);
}

static int _rhp_ikev2_id_cmp_impl(rhp_ikev2_id* id0,rhp_ikev2_id* id1,int no_alt_id)
{
	int type0,type1;

	rhp_ikev2_id_dump("_rhp_ikev2_id_cmp_impl_id0",id0);
	rhp_ikev2_id_dump("_rhp_ikev2_id_cmp_impl_id1",id1);

	if( id0 == NULL || id1 == NULL ){
    return -1;
  }

	type0 = id0->type;
	type1 = id1->type;


  if( type0 != type1 ){
    return -1;
  }

  if( !no_alt_id ){

  	if( (id0->alt_id && id1->alt_id == NULL) ||
				(id1->alt_id && id0->alt_id == NULL) ){

			return -1;

		}else if( id0->alt_id && id1->alt_id ){

			if( rhp_ikev2_id_cmp(id0->alt_id,id1->alt_id) ){
				return -1;
			}
		}
  }


  switch( type0 ){

  case RHP_PROTO_IKE_ID_FQDN:
  case RHP_PROTO_IKE_ID_RFC822_ADDR:

    if( id0->string == NULL || id1->string == NULL ){
      return -1;
    }

    if( strcmp(id0->string,id1->string) ){
      return -1;
    }
    break;

  case RHP_PROTO_IKE_ID_DER_ASN1_DN:

    if( id0->dn_der == NULL || id1->dn_der == NULL ){
      return -1;
    }

    if( id0->dn_der_len != id1->dn_der_len ){
      return -1;
    }

    if( memcmp(id0->dn_der,id1->dn_der,id0->dn_der_len) ){
      return -1;
    }

    break;

  case RHP_PROTO_IKE_ID_IPV4_ADDR:
  case RHP_PROTO_IKE_ID_IPV6_ADDR:

  	if( rhp_ip_addr_cmp_ip_only(&(id0->addr),&(id1->addr)) ){
  		return -1;
  	}
    break;

  case RHP_PROTO_IKE_ID_NULL_ID:
  case RHP_PROTO_IKE_ID_PRIVATE_NULL_ID_WITH_ADDR:

  	if( id0->conn_name_for_null_id || id1->conn_name_for_null_id ){

  		if( (id0->conn_name_for_null_id == NULL && id1->conn_name_for_null_id) ||
  				(id1->conn_name_for_null_id == NULL && id0->conn_name_for_null_id) ||
  				strcmp(id0->conn_name_for_null_id,id1->conn_name_for_null_id) ){
  			return -1;
  		}
  	}

  	if( type0 == RHP_PROTO_IKE_ID_PRIVATE_NULL_ID_WITH_ADDR ){

  		if( rhp_ip_addr_cmp_ip_only(&(id0->addr),&(id1->addr)) ||
					id0->addr.port != id1->addr.port ){
				return -1;
			}
  	}
    break;

  default:
    return -1;
  }

  return 0;
}

int rhp_ikev2_id_cmp(rhp_ikev2_id* id0,rhp_ikev2_id* id1)
{
	return _rhp_ikev2_id_cmp_impl(id0,id1,0);
}

int rhp_eap_id_cmp(rhp_eap_id* eap_id0,rhp_eap_id* eap_id1)
{

	rhp_eap_id_dump("rhp_eap_id_cmp:eap_id0",eap_id0);
	rhp_eap_id_dump("rhp_eap_id_cmp:eap_id1",eap_id1);

	if( (eap_id0 == NULL && eap_id1 == NULL) ||
			(eap_id0 && eap_id1 == NULL) ||
			(eap_id0 == NULL && eap_id1) ){
		return -1;
	}

	if( eap_id0->for_xauth != eap_id1->for_xauth ){
		return -1;
	}

	if( eap_id0->method != eap_id1->method ){
		return -1;
	}

	if( (eap_id0->identity_len != eap_id1->identity_len) ||
			memcmp(eap_id0->identity,eap_id1->identity,eap_id0->identity_len) ){
		return -1;
	}

	if( eap_id0->method == RHP_PROTO_EAP_TYPE_PRIV_RADIUS &&
			!rhp_eap_identity_not_protected(eap_id0->radius.eap_method) ){

		if( eap_id0->radius.user_index && eap_id1->radius.user_index &&
				!strcmp(eap_id0->radius.user_index,eap_id1->radius.user_index) ){
			RHP_TRC(0,RHPTRCID_EAP_ID_CMP_RADIUS_USER_INDEX_MATCHED,"xx",eap_id0,eap_id1);
			return 0;
		}

		if( eap_id0->radius.assigned_addr_v4 && eap_id1->radius.assigned_addr_v4 &&
				!rhp_ip_addr_cmp_ip_only(eap_id0->radius.assigned_addr_v4,eap_id1->radius.assigned_addr_v4) ){
		  RHP_TRC(0,RHPTRCID_EAP_ID_CMP_RADIUS_ASSIGNED_V4_MATCHED,"xx",eap_id0,eap_id1);
			return 0;
		}

		if( eap_id0->radius.assigned_addr_v6 && eap_id1->radius.assigned_addr_v6 &&
				!rhp_ip_addr_cmp_ip_only(eap_id0->radius.assigned_addr_v6,eap_id1->radius.assigned_addr_v6) ){
		  RHP_TRC(0,RHPTRCID_EAP_ID_CMP_RADIUS_ASSIGNED_V6_MATCHED,"xx",eap_id0,eap_id1);
			return 0;
		}

	  RHP_TRC(0,RHPTRCID_EAP_ID_CMP_RADIUS_NOT_MATCHED,"xx",eap_id0,eap_id1);
		return -1;
	}

	return 0;
}

int rhp_eap_id_is_null(rhp_eap_id* id)
{
	if( id == NULL ||
			id->identity == NULL || id->identity_len < 1 ){
		return 1;
	}
	return 0;
}

int rhp_eap_id_radius_not_null(rhp_eap_id* id)
{
	int flag = 0;
	if( id->method != RHP_PROTO_EAP_TYPE_PRIV_RADIUS ||
			rhp_eap_identity_not_protected(id->radius.eap_method) ||
			id->radius.user_index ||
			id->radius.assigned_addr_v4 ||
			id->radius.assigned_addr_v6 ){
		flag = 1;
	}
	RHP_TRC(0,RHPTRCID_EAP_ID_RADIUS_NOT_NULL,"xdddsxxd",id,id->method,rhp_gcfg_radius_mschapv2_eap_identity_not_protected,id->radius.eap_method,id->radius.user_index,id->radius.assigned_addr_v4,id->radius.assigned_addr_v6,flag);
	return flag;
}

int rhp_ikev2_id_cmp_no_alt_id(rhp_ikev2_id* id0,rhp_ikev2_id* id1)
{
	return _rhp_ikev2_id_cmp_impl(id0,id1,1);
}

int rhp_ikev2_id_cmp_sub_type_too(rhp_ikev2_id* id0,rhp_ikev2_id* id1)
{
	int type0,type1;

	if( id0 == NULL || id1 == NULL ){
    return -1;
  }

	type0 = id0->type;
	type1 = id1->type;

	if( type0 == RHP_PROTO_IKE_ID_PRIVATE_SUBJECTALTNAME ||
			type0 == RHP_PROTO_IKE_ID_PRIVATE_CERT_AUTO ){

		type0 = id0->cert_sub_type;
	}

	if( type1 == RHP_PROTO_IKE_ID_PRIVATE_SUBJECTALTNAME ||
			type1 == RHP_PROTO_IKE_ID_PRIVATE_CERT_AUTO ){

		type1 = id1->cert_sub_type;
	}

  if( type0 != type1 ){
    return -1;
  }

  switch( type0 ){

  case RHP_PROTO_IKE_ID_FQDN:
  case RHP_PROTO_IKE_ID_RFC822_ADDR:

    if( id0->string == NULL || id1->string == NULL ){
      return -1;
    }

    if( strcmp(id0->string,id1->string) ){
      return -1;
    }
    break;

  case RHP_PROTO_IKE_ID_DER_ASN1_DN:

    if( id0->dn_der == NULL || id1->dn_der == NULL ){
      return -1;
    }

    if( id0->dn_der_len != id1->dn_der_len ){
      return -1;
    }

    if( memcmp(id0->dn_der,id1->dn_der,id0->dn_der_len) ){
      return -1;
    }

    break;

  case RHP_PROTO_IKE_ID_IPV4_ADDR:
  case RHP_PROTO_IKE_ID_IPV6_ADDR:

  	if( rhp_ip_addr_cmp(&(id0->addr),&(id1->addr)) ){
  		return -1;
  	}
  	break;

  case RHP_PROTO_IKE_ID_NULL_ID:

    if( (id0->string && id1->string == NULL) ||
    		(id1->string && id0->string == NULL) ){

    	return -1;

    }else if( id0->string && id1->string ){

    	if( strcmp(id0->string,id1->string) ){
    		return -1;
    	}
    }
  	break;

  case RHP_PROTO_IKE_ID_PRIVATE_NULL_ID_WITH_ADDR:

  	if( rhp_ip_addr_cmp(&(id0->addr),&(id1->addr)) ||
  			id0->addr.port != id1->addr.port ){
  		return -1;
  	}
  	break;

  default:
    return -1;
  }

  return 0;
}

//
// [CAUTION]
//
//  In case of IKEv2 Null-ID, internal values (alt_id, conn_name and/or addr) are not compared.
//
int rhp_ikev2_id_cmp_by_value(rhp_ikev2_id* id0,int id1_type,int id1_len,u8* id1)
{
  char* string1;
  int type0;

  if( id0 == NULL ){
    return -1;
  }

	type0 = id0->type;

	if( rhp_ikev2_is_null_auth_id(type0) ){
		type0 = RHP_PROTO_IKE_ID_NULL_ID;
	}

	if( rhp_ikev2_is_null_auth_id(id1_type) ){
		id1_type = RHP_PROTO_IKE_ID_NULL_ID;
	}

  if( type0 != id1_type ){
    return -1;
  }

  switch( type0 ){

    case RHP_PROTO_IKE_ID_FQDN:
    case RHP_PROTO_IKE_ID_RFC822_ADDR:

      if( id0->string == NULL ){
        return -1;
      }

      string1 = (char*)id1;

      if( id1_len != (int)strlen(id0->string) ){
        return -1;
      }

      if( memcmp(id0->string,string1,id1_len) ){
        return -1;
      }
      break;

    case RHP_PROTO_IKE_ID_DER_ASN1_DN:

      if( id0->dn_der == NULL ){
        return -1;
      }

      if( id0->dn_der_len != id1_len ){
        return -1;
      }

      if( memcmp(id0->dn_der,id1,id0->dn_der_len) ){
        return -1;
      }
      break;

    case RHP_PROTO_IKE_ID_IPV4_ADDR:
    case RHP_PROTO_IKE_ID_IPV6_ADDR:

    	if( rhp_ip_addr_cmp_value(&(id0->addr),id1_len,id1) ){
    		return -1;
    	}
    	break;

    case RHP_PROTO_IKE_ID_NULL_ID:
    	break;

    case RHP_PROTO_IKE_ID_ANY:
    default:
      return -1;
  }

  return 0;
}

//
// [CAUTION]
//
//  In case of IKEv2 Null-ID, internal values (alt_id, conn_name and/or addr) are not compared.
//
int rhp_ikev2_id_cmp_sub_type_too_by_value(rhp_ikev2_id* id0,int id1_type,int id1_len,u8* id1)
{
  char* string1;
  int type0;

  if( id0 == NULL ){
    return -1;
  }

	type0 = id0->type;

	if( rhp_ikev2_is_null_auth_id(type0) ){

		type0 = RHP_PROTO_IKE_ID_NULL_ID;

	}else if( type0 == RHP_PROTO_IKE_ID_PRIVATE_SUBJECTALTNAME ||
						type0 == RHP_PROTO_IKE_ID_PRIVATE_CERT_AUTO ){

		type0 = id0->cert_sub_type;
	}

	if( rhp_ikev2_is_null_auth_id(id1_type) ){
		id1_type = RHP_PROTO_IKE_ID_NULL_ID;
	}


  if( type0 != id1_type ){
    return -1;
  }

  switch( type0 ){

    case RHP_PROTO_IKE_ID_FQDN:
    case RHP_PROTO_IKE_ID_RFC822_ADDR:

      if( id0->string == NULL ){
        return -1;
      }

      string1 = (char*)id1;

      if( id1_len != (int)strlen(id0->string) ){
        return -1;
      }

      if( memcmp(id0->string,string1,id1_len) ){
        return -1;
      }
      break;

    case RHP_PROTO_IKE_ID_DER_ASN1_DN:

      if( id0->dn_der == NULL ){
        return -1;
      }

      if( id0->dn_der_len != id1_len ){
        return -1;
      }

      if( memcmp(id0->dn_der,id1,id0->dn_der_len) ){
        return -1;
      }
      break;

    case RHP_PROTO_IKE_ID_IPV4_ADDR:
    case RHP_PROTO_IKE_ID_IPV6_ADDR:

    	if( rhp_ip_addr_cmp_value(&(id0->addr),id1_len,id1) ){
    		return -1;
    	}
    	break;

    case RHP_PROTO_IKE_ID_NULL_ID:
    	break;

    case RHP_PROTO_IKE_ID_ANY:
    default:
      return -1;
  }

  return 0;
}


int rhp_ipv4_netmask_to_prefixlen(u32 netmask)
{
	int i;

	netmask = ntohl(netmask);

	for( i = 0; i < 32; i++){

		if( !netmask ){
			break;
		}

		netmask <<= 1;
	}

	return i;
}

u32 rhp_ipv4_prefixlen_to_netmask(int prefix_len)
{
  u32 netmask = 0;

  if( prefix_len == 0 ){
    netmask = 0;
  }else if( prefix_len >= 32 ){
    netmask = 0xFFFFFFFF;
  }else{
  	netmask = ~((1 << (32-prefix_len)) - 1);
  }

  return htonl(netmask);
}

int rhp_ip_addr_null(rhp_ip_addr* addr)
{
	if( addr == NULL ){
		return 1;
	}

  if( addr->addr_family == AF_INET ){

  	if( addr->addr.v4 ){
      return 0;
    }

  }else if( addr->addr_family == AF_INET6 ){

  	u64* a = (u64*)addr->addr.v6;

  	if( a[0] || a[1] ){
  		return 0;
    }
  }

  return 1;
}

int rhp_netmask_null(rhp_ip_addr* addr)
{
	if( addr == NULL ){
		RHP_BUG("");
		return 1;
	}

  if( addr->addr_family == AF_INET ){

  	if( addr->netmask.v4 ){
      return 0;
    }

  }else if( addr->addr_family == AF_INET6 ){

  	u64* a = (u64*)addr->netmask.v6;

  	if( a[0] || a[1] || a[2] || a[3] ){
  		return 0;
    }
  }

  return 1;
}

int rhp_ip_multicast(int addr_family,u8* addr)
{
  if( addr_family == AF_INET ){

  	if( ( addr[0] & 0xF0 ) == 0xE0 ){
  		return 1;
  	}

  }else if( addr_family == AF_INET6 ){

  	if( addr[0] == 0xFF ){
  		return 1;
  	}
  }

  return 0;
}

int rhp_ip_is_loopback(rhp_ip_addr* addr)
{
  if( addr->addr_family == AF_INET ){

  	return rhp_ipv4_is_loopback(addr->addr.v4);

  }else if( addr->addr_family == AF_INET6 ){

  	return rhp_ipv6_is_loopback(addr->addr.v6);
  }

  return 0;
}

int rhp_ipv4_is_loopback(u32 addr)
{
	if( (addr & htonl(0xFFFFFF00)) == htonl(0x7F000000) ){
    return 1;
  }
	return 0;
}

int rhp_ipv6_is_loopback(u8* addr)
{
	u32* a = (u32*)addr;

	if( a[0] == 0 && a[1] == 0 &&
			a[2] == 0 && a[3] == htonl(0x01) ){
		return 1;
	}

  return 0;
}

int rhp_ipv6_addr_null(u8* addr)
{
	u64* a = (u64*)addr;

	if( a[0] || a[1] ){
		return 0;
	}

	return 1;
}

int rhp_ipv6_netmask_to_prefixlen(u8* netmask)
{
	int j, len = 0;

	for( j = 0; j < 16; j++){

		u8 b = netmask[j];
		int i;

		if( b == 0xFF ){
			len += 8;
			continue;
		}

		for( i = 0; i < 8; i++){

			if( !b ){
				goto end;
			}

			b <<= 1;

			len++;
		}
	}

end:
	return len;
}

void rhp_ipv6_prefixlen_to_netmask(int prefix_len,u8* mask_r)
{

	if( prefix_len >= 128 ){

  	memset(mask_r,0xFF,16);

  }else if( prefix_len <= 0 ){

  	memset(mask_r,0,16);

  }else{

  	int nb = prefix_len / 8;
  	int rb = prefix_len % 8;

  	memset(mask_r,0,16);
  	memset(mask_r,0xFF,nb);

  	if( rb ){
  		mask_r[nb] = (0xFF << (8 - rb));
  	}
  }

  return;
}

int rhp_ipv4_is_linklocal(u32 addr)
{
	if( (addr & htonl(0xFFFF0000)) == htonl(0xA9FE0000) ){
    return 1;
  }
	return 0;
}

int rhp_ipv6_is_linklocal(u8* addr)
{
	if( addr[0] == 0xFE && (addr[1] & 0x80) ){
		return 1;
	}
	return 0;
}

int rhp_ipv6_is_linklocal_all_types(u8* addr)
{
	if( (addr[0] & 0xFE) == 0xFE ){
		return 1;
	}
	return 0;
}


int rhp_ip_is_linklocal(int addr_family,u8* addr)
{
	if( addr_family == AF_INET ){
		return rhp_ipv4_is_linklocal(*((u32*)addr));
	}else if( addr_family == AF_INET6 ){
		return rhp_ipv6_is_linklocal(addr);
	}
	return 0;
}

static int _rhp_ipv6_cmp_src_addr_scope(u8* addr)
{
	int scope = RHP_IPV6_MSCOPE_UNKNOWN;

	if( rhp_ip_multicast(AF_INET6,addr) ){

		scope = addr[1] & 0x0F;

		switch( scope ){
		case RHP_IPV6_MSCOPE_IF_LOCAL:
		case RHP_IPV6_MSCOPE_LINK_LOCAL:
		case RHP_IPV6_MSCOPE_ADMIN_LOCAL:
		case RHP_IPV6_MSCOPE_SITE_LOCAL:
		case RHP_IPV6_MSCOPE_ORG_LOCAL:
		case RHP_IPV6_MSCOPE_GLOBAL:
			return scope;
		default:
			break;
		}

	}else{

		if( rhp_ipv6_is_loopback(addr) ){
			return RHP_IPV6_MSCOPE_IF_LOCAL;
		}else if( rhp_ipv6_is_linklocal(addr) ){
			return RHP_IPV6_MSCOPE_LINK_LOCAL;
		}else if( addr[0] == 0xFE && (addr[1] & 0xC0) ){
			return RHP_IPV6_MSCOPE_SITE_LOCAL;
		}

		return RHP_IPV6_MSCOPE_GLOBAL;
	}

	return RHP_IPV6_MSCOPE_UNKNOWN;
}

int rhp_ip_addr_longest_match(rhp_ip_addr* addr0,rhp_ip_addr* addr1,int max_prefix_len)
{
	u8 *p0 = addr0->addr.raw, *p1 = addr1->addr.raw;
	int i, j, pl = 0, alen;

	if( addr0->addr_family != addr1->addr_family ||
			(addr0->addr_family != AF_INET && addr0->addr_family != AF_INET6) ){
		RHP_BUG("");
		pl = -1;
		goto end;
	}

	if( addr0->addr_family == AF_INET ){
		if( max_prefix_len < 1 || max_prefix_len > 32 ){
			max_prefix_len = 32;
		}
	}else{ // AF_INET6
		if( max_prefix_len < 1 || max_prefix_len > 128 ){
			max_prefix_len = 128;
		}
	}

	alen = (addr0->addr_family == AF_INET ? 4 : 16);
	for( i = 0; i < alen && pl <= max_prefix_len; i++ ){

		if( p0[i] == p1[i] ){
			pl += 8;
			continue;
		}

		for(j = 0; j < 8; j++){
			if( ((p0[i] << j) & 0x80) != ((p1[i] << j) & 0x80) ){
				goto end;
			}
			pl++;
		}

		break;
	}

end:
	if( addr0->addr_family == AF_INET && addr1->addr_family == AF_INET ){
		RHP_TRC(0,RHPTRCID_IP_ADDR_LONGEST_MATCH,"xxdLdLd44d",addr0,addr1,max_prefix_len,"AF",addr0->addr_family,"AF",addr1->addr_family,addr0->addr.v4,addr1->addr.v4,pl);
	}else	if( addr0->addr_family == AF_INET6 && addr1->addr_family == AF_INET6 ){
		RHP_TRC(0,RHPTRCID_IP_ADDR_LONGEST_MATCH_V6,"xxdLdLd66d",addr0,addr1,max_prefix_len,"AF",addr0->addr_family,"AF",addr1->addr_family,addr0->addr.v6,addr1->addr.v6,pl);
	}else{
		RHP_BUG("%d, %d",addr0->addr_family,addr1->addr_family);
	}
	return pl;
}

static inline int _rhp_ipv6_addr_cmp_prefix_2(u8* addr0,u8* addr1,int prefix_len)
{
	u64 mask;

	if( prefix_len < 1 ){
		return 1;
	}

	mask = _rhp_ntohll((0xFFFFFFFFFFFFFFFFUL << (64 - prefix_len)));

	if( (*((u64*)addr0) & mask) == (*((u64*)addr1) & mask) ){
		return 1;
	}

	return 0;
}

int rhp_ipv6_addr_cmp_prefix(u8* addr0,u8* addr1,int prefix_len)
{
	u64* a0 = (u64*)addr0;
	u64* a1 = (u64*)addr1;

	if( prefix_len < 64 ){
		return _rhp_ipv6_addr_cmp_prefix_2(addr0,addr1,prefix_len);
	}

	if( *a0 != *a1 ){
		return 0;
	}
	return _rhp_ipv6_addr_cmp_prefix_2((u8*)(a0 + 1),(u8*)(a1 + 1),(prefix_len - 64));
}

void rhp_ip_addr_set(rhp_ip_addr* ipaddr,int addr_family,u8* addr,u8* netmask,int prefixlen,
		u16 port,u32 ipv6_scope_id)
{
	ipaddr->addr_family = addr_family;

	if( addr_family == AF_INET ){

		if( addr ){
			ipaddr->addr.v4 = *((u32*)addr);
		}

		if( netmask ){
			ipaddr->netmask.v4 = *((u32*)netmask);
		}

		ipaddr->prefixlen = prefixlen;
		if( netmask == NULL && prefixlen ){
			ipaddr->netmask.v4 = rhp_ipv4_prefixlen_to_netmask(prefixlen);
		}

		ipaddr->port = port;

		ipaddr->ipv6_scope_id = 0;

	}else if( addr_family == AF_INET6 ){

		if( addr ){
			memcpy(ipaddr->addr.v6,addr,16);
		}

		if( netmask ){
			memcpy(ipaddr->netmask.v6,netmask,16);
		}

		ipaddr->prefixlen = prefixlen;
		if( netmask == NULL && prefixlen ){
			rhp_ipv6_prefixlen_to_netmask(prefixlen,ipaddr->netmask.v6);
		}

		ipaddr->port = port;

		ipaddr->ipv6_scope_id = ipv6_scope_id;
	}
}

void rhp_ip_addr_set2(rhp_ip_addr* ipaddr,int addr_family,u8* addr,u16 port)
{
	rhp_ip_addr_set(ipaddr,addr_family,addr,NULL,0,port,0);
}

void rhp_ip_addr_reset(rhp_ip_addr* ipaddr)
{
	memset(ipaddr,0,sizeof(rhp_ip_addr));
	ipaddr->addr_family = AF_UNSPEC;
}

rhp_ip_addr_list* rhp_ip_dup_addr_list(rhp_ip_addr* ipaddr)
{
	rhp_ip_addr_list* addr_lst = (rhp_ip_addr_list*)_rhp_malloc(sizeof(rhp_ip_addr_list));

	if( addr_lst == NULL ){
		RHP_BUG("");
		return NULL;
	}

	memcpy(&(addr_lst->ip_addr),ipaddr,sizeof(rhp_ip_addr));
	addr_lst->next = NULL;

	return addr_lst;
}

// Linklocal address (IPv6) is ignored.
int rhp_ip_search_addr_list_cb_addr_family_no_linklocal(rhp_ip_addr* ipaddr,void* ctx)
{
	int addr_family = (int)ctx;

	if( ipaddr->addr_family == addr_family ){

		if( rhp_ip_addr_null(ipaddr) ){
			return 0;
		}

		if( ipaddr->addr_family == AF_INET6 &&
				rhp_ipv6_is_linklocal(ipaddr->addr.v6) ){
			return 0;
		}else if( ipaddr->addr_family == AF_INET &&
				rhp_ipv4_is_linklocal(ipaddr->addr.v4) ){
			return 0;
		}

		return 1;
	}

	return 0;
}

// Linklocal address (IPv6) is ignored.
int rhp_ip_search_addr_list_cb_v6_linklocal(rhp_ip_addr* ipaddr,void* ctx)
{
	if( ipaddr->addr_family == AF_INET6 &&
			rhp_ipv6_is_linklocal(ipaddr->addr.v6) ){
		return 1;
	}

	return 0;
}

int rhp_ip_search_addr_list_cb_addr_family(rhp_ip_addr* ipaddr,void* ctx)
{
	int addr_family = (int)ctx;

	if( ipaddr->addr_family == addr_family ){

		if( rhp_ip_addr_null(ipaddr) ){
			return 0;
		}

		return 1;
	}

	return 0;
}

int rhp_ip_search_addr_list_cb_addr_tag(rhp_ip_addr* ipaddr,void* ctx)
{
	int addr_tag = (int)ctx;

	if( ipaddr->tag == addr_tag ){
		return 1;
	}

	return 0;
}

int rhp_ip_search_addr_list_cb_addr_ipv4_tag(rhp_ip_addr* ipaddr,void* ctx)
{
	int addr_tag = (int)ctx;

	if( ipaddr->addr_family == AF_INET && ipaddr->tag == addr_tag ){
		return 1;
	}

	return 0;
}

int rhp_ip_search_addr_list_cb_addr_ipv6_tag(rhp_ip_addr* ipaddr,void* ctx)
{
	int addr_tag = (int)ctx;

	if( ipaddr->addr_family == AF_INET6 && ipaddr->tag == addr_tag ){
		return 1;
	}

	return 0;
}

rhp_ip_addr* rhp_ip_search_addr_list(rhp_ip_addr_list* addr_lst,
		int (*filter)(rhp_ip_addr* ipaddr,void* ctx),void* ctx)
{
	rhp_ip_addr_list* addr = addr_lst;

	while( addr ){

		if( filter && filter(&(addr->ip_addr),ctx) ){
			return &(addr->ip_addr);
		}

		addr = addr->next;
	}

	return NULL;
}


struct _rhp_ipv6_src_label
{
	u8 prefix[16];
	int prefix_len;
	u32 label;
};
typedef struct _rhp_ipv6_src_label	rhp_ipv6_src_label;

#define RHP_IPV6_SRC_LABEL_UNKNOWN	0xFFFFFFFF

static rhp_ipv6_src_label _rhp_ipv6_src_def_labels[] = {
		{
				.prefix = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1},
				.prefix_len = 128,
				.label = 0
		},
		{
				.prefix = {0x20,0x02},
				.prefix_len = 16,
				.label = 0
		},
		{
				.prefix = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
				.prefix_len = 96,
				.label = 0
		},
		{
				.prefix = {0,0,0,0,0,0,0,0,0,0,0,0,0xFF,0xFF,0,0},
				.prefix_len = 96,
				.label = 0
		},
		{
				.prefix = {0xFC},
				.prefix_len = 7,
				.label = 0
		},
		{
				.prefix = {0x20,0x01},
				.prefix_len = 32,
				.label = 0
		},
		{
				.prefix = {0x20,0x01,0,0x10},
				.prefix_len = 28,
				.label = 0
		},
		{
				.prefix = {0xFE,0xC0},
				.prefix_len = 10,
				.label = 0
		},
		{
				.prefix = {0x3F,0xFE},
				.prefix_len = 16,
				.label = 0
		},
		{   // Terminator.
				.prefix = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
				.prefix_len = 0,
				.label = 1
		}
};


// TODO: Read label definition from config file.
static u32 _rhp_ipv6_src_label(u8* addr)
{
	int i;

	for( i = 0; !rhp_ipv6_addr_null(_rhp_ipv6_src_def_labels[i].prefix); i++ ){

		if( !rhp_ipv6_addr_cmp_prefix(addr,
				_rhp_ipv6_src_def_labels[i].prefix,
				_rhp_ipv6_src_def_labels[i].prefix_len) ){

			return _rhp_ipv6_src_def_labels[i].label;
		}
	}

	return RHP_IPV6_SRC_LABEL_UNKNOWN;
}

int rhp_ipv6_valid_peer_addrs(u8* addr0,u8* addr1)
{
	int addr0_flag = rhp_ipv6_is_linklocal(addr0);
	int addr1_flag = rhp_ipv6_is_linklocal(addr1);

	if( (addr0_flag && addr1_flag) || (!addr0_flag && !addr1_flag) ){
		return 1;
	}

	return 0;
}

int rhp_ipv4_valid_peer_addrs(u32 addr0,u32 addr1)
{
	int addr0_flag = rhp_ipv4_is_linklocal(addr0);
	int addr1_flag = rhp_ipv4_is_linklocal(addr1);

	if( (addr0_flag && addr1_flag) || (!addr0_flag && !addr1_flag) ){
		return 1;
	}

	return 0;
}

int rhp_ip_valid_peer_addrs(int addr_family,u8* addr0,u8* addr1)
{
	if( addr_family == AF_INET ){
		return rhp_ipv4_valid_peer_addrs(*((u32*)addr0),*((u32*)addr1));
	}else if( addr_family == AF_INET6 ){
		return rhp_ipv6_valid_peer_addrs(addr0,addr1);
	}
	return 0;
}

// [RFC6742] - http://www.rfc-editor.org/rfc/rfc6724.txt
// -1 : error, 0: tiebreaker, 1: src_addr0 wins and 2: src_addr1 wins.
int rhp_ipv6_cmp_src_addr(
		rhp_ip_addr* src_addr0,unsigned int src_addr0_flag,
		rhp_ip_addr* src_addr1,unsigned int src_addr1_flag,
		rhp_ip_addr* dest_addr)
{
	RHP_TRC(0,RHPTRCID_IPV6_CMP_SRC_ADDR,"xdxdx",src_addr0,src_addr0_flag,src_addr1,src_addr1_flag,dest_addr);
	rhp_ip_addr_dump("src_addr0",src_addr0);
	rhp_ip_addr_dump("src_addr1",src_addr1);
	rhp_ip_addr_dump("dest_addr",dest_addr);

	if( src_addr0->addr_family != AF_INET6 || src_addr1->addr_family != AF_INET6 ||
			dest_addr->addr_family != AF_INET6){
		RHP_BUG("");
		return -1;
	}

	if( src_addr0->prefixlen < 1 || src_addr1->prefixlen < 1 ){
		RHP_BUG("");
		return -1;
	}

	{
		int lflag0 = rhp_ipv6_is_loopback(src_addr0->addr.v6);
		int lflag1 = rhp_ipv6_is_loopback(src_addr1->addr.v6);

		if( !lflag0 && lflag1 ){
			RHP_TRC(0,RHPTRCID_IPV6_CMP_SRC_ADDR_LOOPBACK_1,"xxx",src_addr0,src_addr1,dest_addr);
			return 1;
		}else if( lflag0 && !lflag1 ){
			RHP_TRC(0,RHPTRCID_IPV6_CMP_SRC_ADDR_LOOPBACK_2,"xxx",src_addr0,src_addr1,dest_addr);
			return 2;
		}
	}

	if( RHP_IFA_F_TENTATIVE(src_addr0_flag) && !RHP_IFA_F_TENTATIVE(src_addr1_flag) ){
		RHP_TRC(0,RHPTRCID_IPV6_CMP_SRC_ADDR_TENTATIVE_1,"xxx",src_addr0,src_addr1,dest_addr);
		return 2;
	}else	if( RHP_IFA_F_TENTATIVE(src_addr1_flag) && !RHP_IFA_F_TENTATIVE(src_addr0_flag) ){
		RHP_TRC(0,RHPTRCID_IPV6_CMP_SRC_ADDR_TENTATIVE_2,"xxx",src_addr0,src_addr1,dest_addr);
		return 1;
	}else if( RHP_IFA_F_TENTATIVE(src_addr0_flag) && RHP_IFA_F_TENTATIVE(src_addr1_flag) ){
		RHP_TRC(0,RHPTRCID_IPV6_CMP_SRC_ADDR_TENTATIVE_3,"xxx",src_addr0,src_addr1,dest_addr);
		return -1;
	}

	if( !rhp_ip_addr_cmp_ip_only(src_addr0,src_addr1) ){
		RHP_TRC(0,RHPTRCID_IPV6_CMP_SRC_ADDR_SAME_ADDRS,"xxx",src_addr0,src_addr1,dest_addr);
		return 0;
	}

	// Rule 1: Prefer same address.
	if( !rhp_ip_addr_cmp_ip_only(src_addr0,dest_addr) ){
		RHP_TRC(0,RHPTRCID_IPV6_CMP_SRC_ADDR_RULE1_1,"xxx",src_addr0,src_addr1,dest_addr);
		return 1;
	}else if( !rhp_ip_addr_cmp_ip_only(src_addr1,dest_addr) ){
		RHP_TRC(0,RHPTRCID_IPV6_CMP_SRC_ADDR_RULE1_2,"xxx",src_addr0,src_addr1,dest_addr);
		return 2;
	}

	// Rule 2: Prefer appropriate scope.
	{
		int src0_scope = _rhp_ipv6_cmp_src_addr_scope(src_addr0->addr.v6);
		int src1_scope = _rhp_ipv6_cmp_src_addr_scope(src_addr1->addr.v6);
		int dst_scope = _rhp_ipv6_cmp_src_addr_scope(dest_addr->addr.v6);

		if( src0_scope < src1_scope ){

			if( src0_scope < dst_scope ){
				RHP_TRC(0,RHPTRCID_IPV6_CMP_SRC_ADDR_RULE2_1,"xxx",src_addr0,src_addr1,dest_addr);
				return 2;
			}else{
				RHP_TRC(0,RHPTRCID_IPV6_CMP_SRC_ADDR_RULE2_2,"xxx",src_addr0,src_addr1,dest_addr);
				return 1;
			}

		}else if( src1_scope < src0_scope ){

			if( src1_scope < dst_scope ){
				RHP_TRC(0,RHPTRCID_IPV6_CMP_SRC_ADDR_RULE2_3,"xxx",src_addr0,src_addr1,dest_addr);
				return 1;
			}else{
				RHP_TRC(0,RHPTRCID_IPV6_CMP_SRC_ADDR_RULE2_4,"xxx",src_addr0,src_addr1,dest_addr);
				return 2;
			}
		}
	}

	// Rule 3: Avoid deprecated addresses.
	{
		if( RHP_IFA_F_DEPRECATED(src_addr0_flag) && !RHP_IFA_F_DEPRECATED(src_addr1_flag) ){
			RHP_TRC(0,RHPTRCID_IPV6_CMP_SRC_ADDR_RULE3_1,"xxx",src_addr0,src_addr1,dest_addr);
			return 2;
		}else	if( RHP_IFA_F_DEPRECATED(src_addr1_flag) && !RHP_IFA_F_DEPRECATED(src_addr0_flag) ){
			RHP_TRC(0,RHPTRCID_IPV6_CMP_SRC_ADDR_RULE3_2,"xxx",src_addr0,src_addr1,dest_addr);
			return 1;
		}
	}

	// Rule 4: Prefer home addresses.
	{
		if( RHP_IFA_F_HOMEADDRESS(src_addr0_flag) && !RHP_IFA_F_HOMEADDRESS(src_addr1_flag) ){
			RHP_TRC(0,RHPTRCID_IPV6_CMP_SRC_ADDR_RULE4_1,"xxx",src_addr0,src_addr1,dest_addr);
			return 1;
		}else	if( RHP_IFA_F_HOMEADDRESS(src_addr1_flag) && !RHP_IFA_F_HOMEADDRESS(src_addr0_flag) ){
			RHP_TRC(0,RHPTRCID_IPV6_CMP_SRC_ADDR_RULE4_2,"xxx",src_addr0,src_addr1,dest_addr);
			return 2;
		}
	}


	// Rule 5: Prefer outgoing interface. Not evaluated.


	// Rule 6: Prefer matching label.
	{
		u32 src_label0 = _rhp_ipv6_src_label(src_addr0->addr.v6);
		u32 src_label1 = _rhp_ipv6_src_label(src_addr1->addr.v6);
		u32 dst_label = _rhp_ipv6_src_label(dest_addr->addr.v6);

		if( src_label0 == dst_label && src_label1 != dst_label ){
			RHP_TRC(0,RHPTRCID_IPV6_CMP_SRC_ADDR_RULE6_1,"xxx",src_addr0,src_addr1,dest_addr);
			return 1;
		}else if( src_label1 == dst_label && src_label0 != dst_label ){
			RHP_TRC(0,RHPTRCID_IPV6_CMP_SRC_ADDR_RULE6_2,"xxx",src_addr0,src_addr1,dest_addr);
			return 2;
		}
	}

	// Rule 7: Prefer temporary addresses.
	{
		if( RHP_IFA_F_TEMPORARY(src_addr0_flag) && !RHP_IFA_F_TEMPORARY(src_addr1_flag) ){
			RHP_TRC(0,RHPTRCID_IPV6_CMP_SRC_ADDR_RULE7_1,"xxx",src_addr0,src_addr1,dest_addr);
			return 1;
		}else	if( RHP_IFA_F_TEMPORARY(src_addr1_flag) && !RHP_IFA_F_TEMPORARY(src_addr0_flag) ){
			RHP_TRC(0,RHPTRCID_IPV6_CMP_SRC_ADDR_RULE7_2,"xxx",src_addr0,src_addr1,dest_addr);
			return 2;
		}
	}

	// Rule 8: Use longest matching prefix.
	{
		int plen0 = rhp_ip_addr_longest_match(src_addr0,dest_addr,src_addr0->prefixlen);
		int plen1 = rhp_ip_addr_longest_match(src_addr1,dest_addr,src_addr1->prefixlen);

		if( plen0 > plen1 ){
			RHP_TRC(0,RHPTRCID_IPV6_CMP_SRC_ADDR_RULE8_1,"xxx",src_addr0,src_addr1,dest_addr);
			return 1;
		}else if( plen0 < plen1 ){
			RHP_TRC(0,RHPTRCID_IPV6_CMP_SRC_ADDR_RULE8_2,"xxx",src_addr0,src_addr1,dest_addr);
			return 2;
		}
	}

	RHP_TRC(0,RHPTRCID_IPV6_CMP_SRC_ADDR_TIEBRAKER,"xxx",src_addr0,src_addr1,dest_addr);
	return 0;
}

// -1 : error, 0: tiebreaker, 1: src_addr0 wins and 2: src_addr1 wins.
int rhp_ipv4_cmp_src_addr(
		rhp_ip_addr* src_addr0,rhp_ip_addr* src_addr1,rhp_ip_addr* dest_addr)
{
	RHP_TRC(0,RHPTRCID_IPV4_CMP_SRC_ADDR,"xxx",src_addr0,src_addr1,dest_addr);
	rhp_ip_addr_dump("src_addr0",src_addr0);
	rhp_ip_addr_dump("src_addr1",src_addr1);
	rhp_ip_addr_dump("dest_addr",dest_addr);

	if( src_addr0->addr_family != AF_INET || src_addr1->addr_family != AF_INET ||
			dest_addr->addr_family != AF_INET ){
		RHP_BUG("");
		return -1;
	}

	if( src_addr0->prefixlen < 1 || src_addr1->prefixlen < 1 ){
		RHP_BUG("");
		return -1;
	}

	{
		int lflag0 = rhp_ipv4_is_loopback(src_addr0->addr.v4);
		int lflag1 = rhp_ipv4_is_loopback(src_addr1->addr.v4);

		if( !lflag0 && lflag1 ){
			RHP_TRC(0,RHPTRCID_IPV4_CMP_SRC_ADDR_LOOPBACK_1,"xxx",src_addr0,src_addr1,dest_addr);
			return 1;
		}else if( lflag0 && !lflag1 ){
			RHP_TRC(0,RHPTRCID_IPV4_CMP_SRC_ADDR_LOOPBACK_2,"xxx",src_addr0,src_addr1,dest_addr);
			return 2;
		}
	}


	if( !rhp_ip_addr_cmp_ip_only(src_addr0,src_addr1) ){
		RHP_TRC(0,RHPTRCID_IPV4_CMP_SRC_ADDR_SAME_ADDRS,"xxx",src_addr0,src_addr1,dest_addr);
		return 0;
	}


	if( !rhp_ip_addr_cmp_ip_only(src_addr0,dest_addr) ){
		RHP_TRC(0,RHPTRCID_IPV4_CMP_SRC_ADDR_DST_SAME_ADDR_1,"xxx",src_addr0,src_addr1,dest_addr);
		return 1;
	}else if( !rhp_ip_addr_cmp_ip_only(src_addr1,dest_addr) ){
		RHP_TRC(0,RHPTRCID_IPV4_CMP_SRC_ADDR_DST_SAME_ADDR_2,"xxx",src_addr0,src_addr1,dest_addr);
		return 2;
	}


	{
		int plen0 = rhp_ip_addr_longest_match(src_addr0,dest_addr,src_addr0->prefixlen);
		int plen1 = rhp_ip_addr_longest_match(src_addr1,dest_addr,src_addr1->prefixlen);

		if( plen0 > plen1 ){
			RHP_TRC(0,RHPTRCID_IPV4_CMP_SRC_ADDR_LONGEST_MATCH_1,"xxx",src_addr0,src_addr1,dest_addr);
			return 1;
		}else if( plen0 < plen1 ){
			RHP_TRC(0,RHPTRCID_IPV4_CMP_SRC_ADDR_LONGEST_MATCH_2,"xxx",src_addr0,src_addr1,dest_addr);
			return 2;
		}
	}

	RHP_TRC(0,RHPTRCID_IPV4_CMP_SRC_ADDR_TIEBRAKER,"xxx",src_addr0,src_addr1,dest_addr);
	return 0;
}


int rhp_ip_subnet_broadcast(rhp_ip_addr* subnet_addr,int addr_family,u8* addr)
{

  if( addr_family == AF_INET ){

  	u32 mask;

    if( subnet_addr == NULL ){
      return 0;
    }

    if( subnet_addr->addr_family != addr_family ){
    	return 0;
    }

    if( !subnet_addr->netmask.v4 && !subnet_addr->prefixlen ){
    	return 0;
    }

  	if( subnet_addr->netmask.v4 ){
  		mask = subnet_addr->netmask.v4;
  	}else{
  		mask = rhp_ipv4_prefixlen_to_netmask(subnet_addr->prefixlen);
  		subnet_addr->netmask.v4 = mask;
  	}

  	if( subnet_addr->addr.v4 && *((u32*)addr) &&
  			((*((u32*)addr) & ~mask) == ~mask) ){
  		return 1;
  	}

  }else if( addr_family == AF_INET6 ){

  	if( addr[0] == 0xFF && addr[1] == 0x02 ){
  		return 1;
  	}
  }

  return 0;
}

int rhp_ip_same_subnet(rhp_ip_addr* subnet_addr,int addr_family,u8* addr)
{
  if( subnet_addr == NULL ){
    return 0;
  }

  if( subnet_addr->addr_family != addr_family ){
  	return 0;
  }

  if( addr_family == AF_INET ){

  	u32 mask;

    if( !subnet_addr->netmask.v4 && !subnet_addr->prefixlen ){
    	return 0;
    }

  	if( subnet_addr->netmask.v4 ){
  		mask = subnet_addr->netmask.v4;
  	}else{
  		mask = rhp_ipv4_prefixlen_to_netmask(subnet_addr->prefixlen);
  		subnet_addr->netmask.v4 = mask;
  	}

  	if( subnet_addr->addr.v4 && *((u32*)addr) &&
  			((subnet_addr->addr.v4 & mask) == (*((u32*)addr) & mask)) ){
  		return 1;
  	}

  }else if( addr_family == AF_INET6 ){

  	int plen;

  	if( rhp_ipv6_is_linklocal(subnet_addr->addr.v6) ){
  		if( rhp_ipv6_is_linklocal(addr) ){
  			return 1;
  		}
			return 0;
  	}

  	if( rhp_netmask_null(subnet_addr) && !subnet_addr->prefixlen ){
    	return 0;
  	}

  	if( subnet_addr->prefixlen < 1 ){
  		plen = rhp_ipv6_netmask_to_prefixlen(subnet_addr->netmask.v6);
  	}else{
  		plen = subnet_addr->prefixlen;
  	}

  	return rhp_ipv6_addr_cmp_prefix(subnet_addr->addr.v6,addr,plen);
  }

  return 0;
}

int rhp_ip_same_subnet_v4(u32 addr0,u32 addr1,int prefixlen)
{
  	u32 mask;

  	mask = rhp_ipv4_prefixlen_to_netmask(prefixlen);

  	if( (addr0 & mask) == (addr1 & mask) ){
  		return 1;
  	}

  	return 0;
}

int rhp_ip_same_subnet_v6(u8* addr0,u8* addr1,int prefixlen)
{
	u8 mask[16];
	int plen, r;

	if( rhp_ipv6_is_linklocal(addr0) ){
		if( rhp_ipv6_is_linklocal(addr1) ){
			return 1;
		}
		return 0;
	}

	rhp_ipv6_prefixlen_to_netmask(prefixlen,mask);

	r = prefixlen % 8;
	plen = prefixlen / 8;

	if( (r && ((addr0[plen] & mask[plen]) != (addr1[plen] & mask[plen]))) ||
			memcmp(addr0,addr1,plen)){
		return 0;
	}

	return 1;
}

int rhp_ip_network_addr(int addr_family,u8* addr,int prefixlen,
		rhp_ip_addr* network_addr_r)
{
	if( addr_family == AF_INET ){

		network_addr_r->addr_family = AF_INET;
  	network_addr_r->prefixlen = prefixlen;
  	network_addr_r->netmask.v4 = rhp_ipv4_prefixlen_to_netmask(prefixlen);
  	network_addr_r->addr.v4 = (*((u32*)addr) & network_addr_r->netmask.v4);

  	return 0;

	}else if( addr_family == AF_INET6 ){

		int plen, r;

		r = prefixlen % 8;
		plen = prefixlen / 8;

		network_addr_r->addr_family = AF_INET6;
  	network_addr_r->prefixlen = prefixlen;
  	rhp_ipv6_prefixlen_to_netmask(prefixlen,network_addr_r->netmask.v6);

  	memcpy(network_addr_r->addr.v6,addr,plen);
  	if( r ){
  		network_addr_r->addr.v6[plen] = (addr[plen] & network_addr_r->netmask.v6[plen]);
  	}

  	return 0;
	}

	RHP_BUG("%d",addr_family);
	return -EINVAL;
}

int rhp_ip_same_subnet2(int addr_family,u8* addr0,u8* addr1,int prefixlen)
{
	if( addr_family == AF_INET ){
		return rhp_ip_same_subnet_v4(*((u32*)addr0),*((u32*)addr1),prefixlen);
  }else if( addr_family == AF_INET6 ){
  	return rhp_ip_same_subnet_v6(addr0,addr1,prefixlen);
	}
	return 0;
}


void rhp_ip_gen_multicast_mac(int addr_family,u8* ip,u8* mac_r)
{
  if( addr_family == AF_INET ){

		mac_r[0] = 0x01;
		mac_r[1] = 0x00;
		mac_r[2] = 0x5E;
		mac_r[3] = ip[1] & 0x80;
		mac_r[4] = ip[2];
		mac_r[5] = ip[3];

  }else if( addr_family == AF_INET6 ){

		mac_r[0] = 0x33;
		mac_r[1] = 0x33;
		mac_r[2] = ip[12];
		mac_r[3] = ip[13];
		mac_r[4] = ip[14];
		mac_r[5] = ip[15];
  }

  return;
}

void rhp_ipv6_gen_solicited_node_multicast(u8* ipv6,u8* maddr_r)
{
	maddr_r[0] = 0xFF;
	maddr_r[1] = 0x02;
	maddr_r[2] = 0;
	maddr_r[3] = 0;
	maddr_r[4] = 0;
	maddr_r[5] = 0;
	maddr_r[6] = 0;
	maddr_r[7] = 0;
	maddr_r[8] = 0;
	maddr_r[9] = 0;
	maddr_r[10] = 0;
	maddr_r[11] = 0x01;
	maddr_r[12] = 0xff;
	maddr_r[13] = ipv6[13];
	maddr_r[14] = ipv6[14];
	maddr_r[15] = ipv6[15];
}

int rhp_ipv6_is_solicited_node_multicast(u8* ipv6)
{
	if( ipv6[0] == 0xFF &&
			ipv6[1] == 0x02 &&
			ipv6[2] == 0 &&
			ipv6[3] == 0 &&
			ipv6[4] == 0 &&
			ipv6[5] == 0 &&
			ipv6[6] == 0 &&
			ipv6[7] == 0 &&
			ipv6[8] == 0 &&
			ipv6[9] == 0 &&
			ipv6[10] == 0 &&
			ipv6[11] == 0x01 &&
			ipv6[12] == 0xff ){

		return 1;
	}
	return 0;
}


int rhp_ip_addr_cmp(rhp_ip_addr* addr0,rhp_ip_addr* addr1)
{
  if( addr0 == NULL || addr1 == NULL ){
    return -1;
  }

  if( addr0->addr_family != addr1->addr_family ){
    return -1;
  }

  if( memcmp(addr0->addr.raw,addr1->addr.raw,16) ){
    return -1;
  }

  if( addr0->port && addr1->port && addr0->port != addr1->port ){
    return -1;
  }

  if( addr0->prefixlen &&
      addr1->prefixlen &&
      addr0->prefixlen != addr1->prefixlen ){
    return -1;
  }
  return 0;
}

int rhp_ip_addr_gt_ip(rhp_ip_addr* addr0,rhp_ip_addr* addr1)
{
  if( addr0 == NULL || addr1 == NULL ){
    return -1;
  }

  if( addr0->addr_family != addr1->addr_family ){
    return -1;
  }

  if( addr0->addr_family == AF_INET ){

    u32 v4_0,v4_1;

    v4_0 = ntohl(addr0->addr.v4);
    v4_1 = ntohl(addr1->addr.v4);

    if( v4_0 > v4_1 ){
      return 0;
    }

  }else if( addr0->addr_family == AF_INET6 ){

  	u8 *v6_0,*v6_1;
  	int i;

  	v6_0 = addr0->addr.v6;
  	v6_1 = addr1->addr.v6;

  	for( i = 0; i < 16; i++ ){

  		if( v6_0[i] > v6_1[i] ){
  			return 0;
  		}else	if( v6_0[i] < v6_1[i] ){
  			return -1;
  		}
  	}

  }else{
    return -1;
  }

  return -1;
}

int rhp_ip_addr_lt_ip(rhp_ip_addr* addr0,rhp_ip_addr* addr1)
{
  return rhp_ip_addr_gt_ip(addr1,addr0);
}

int rhp_ip_addr_gt_ipv4(rhp_ip_addr* addr0,u32 addr1)
{
  u32 v4_0,v4_1;

  if( addr0 == NULL ){
    return -1;
  }

  if( addr0->addr_family != AF_INET ){
    return -1;
  }


  v4_0 = ntohl(addr0->addr.v4);
  v4_1 = ntohl(addr1);

  if( v4_0 > v4_1 ){
    return 0;
  }

  return -1;
}

int rhp_ip_addr_gt_ipv6(rhp_ip_addr* addr0,u8* addr1)
{
	u8* v6_0;
	int i;

	v6_0 = addr0->addr.v6;

	for( i = 0; i < 16; i++ ){

		if( v6_0[i] > addr1[i] ){
			return 0;
		}else	if( v6_0[i] < addr1[i] ){
			return -1;
		}
	}

  return -1;
}

int rhp_ip_addr_gt_iphdr(rhp_ip_addr* addr0,int addr_family,u8* iphdr,
		int src_or_dst/* 0: Src, 1: Dst */)
{
	if( addr_family == AF_INET ){
		rhp_proto_ip_v4* iph = (rhp_proto_ip_v4*)iphdr;
		return rhp_ip_addr_gt_ipv4(addr0,(src_or_dst ? iph->dst_addr : iph->src_addr));
	}else if( addr_family == AF_INET6 ){
		rhp_proto_ip_v6* ip6h = (rhp_proto_ip_v6*)iphdr;
		return rhp_ip_addr_gt_ipv6(addr0,(src_or_dst ? ip6h->dst_addr : ip6h->src_addr));
	}
	return -1;
}

int rhp_ip_addr_lt_ipv4(rhp_ip_addr* addr0,u32 addr1)
{
  u32 v4_0,v4_1;

  if( addr0 == NULL ){
    return -1;
  }

  if( addr0->addr_family != AF_INET ){
    return -1;
  }

  v4_0 = ntohl(addr0->addr.v4);
  v4_1 = ntohl(addr1);

  if( v4_0 < v4_1 ){
    return 0;
  }

  return -1;
}

int rhp_ip_addr_lt_ipv6(rhp_ip_addr* addr0,u8* addr1)
{
	u8* v6_0;
	int i;

	v6_0 = addr0->addr.v6;

	for( i = 0; i < 16; i++ ){

		if( v6_0[i] > addr1[i] ){
			return -1;
		}else	if( v6_0[i] < addr1[i] ){
			return 0;
		}
	}

  return -1;
}

int rhp_ip_addr_lt_iphdr(rhp_ip_addr* addr0,int addr_family,u8* iphdr,
		int src_or_dst/* 0: Src, 1: Dst */)
{
	if( addr_family == AF_INET ){
		rhp_proto_ip_v4* iph = (rhp_proto_ip_v4*)iphdr;
		return rhp_ip_addr_lt_ipv4(addr0,(src_or_dst ? iph->dst_addr : iph->src_addr));
	}else if( addr_family == AF_INET6 ){
		rhp_proto_ip_v6* ip6h = (rhp_proto_ip_v6*)iphdr;
		return rhp_ip_addr_lt_ipv6(addr0,(src_or_dst ? ip6h->dst_addr : ip6h->src_addr));
	}
	return -1;
}

int rhp_ip_addr_gteq_ip(rhp_ip_addr* addr0,rhp_ip_addr* addr1)
{
  if( addr0 == NULL || addr1 == NULL ){
    return -1;
  }

  if( addr0->addr_family != addr1->addr_family ){
    return -1;
  }

  if( addr0->addr_family == AF_INET ){

    u32 v4_0,v4_1;

    v4_0 = ntohl(addr0->addr.v4);
    v4_1 = ntohl(addr1->addr.v4);

    if( v4_0 >= v4_1 ){
      return 0;
    }

  }else if( addr0->addr_family == AF_INET6 ){

  	u8 *v6_0,*v6_1;
  	int i;

  	v6_0 = addr0->addr.v6;
  	v6_1 = addr1->addr.v6;

  	for( i = 0; i < 16; i++ ){

  		if( v6_0[i] > v6_1[i] ){
  			return 0;
  		}else	if( v6_0[i] < v6_1[i] ){
  			return -1;
  		}
  	}

  	return 0;

  }else{
    return -1;
  }

  return -1;
}

int rhp_ip_addr_lteq_ip(rhp_ip_addr* addr0,rhp_ip_addr* addr1)
{
  return rhp_ip_addr_gteq_ip(addr1,addr0);
}

int rhp_ip_addr_eq_ip(rhp_ip_addr* addr0,rhp_ip_addr* addr1)
{
  if( addr0 == NULL || addr1 == NULL ){
    return -1;
  }

  if( addr0->addr_family != addr1->addr_family ){
    return -1;
  }

  if( addr0->addr_family == AF_INET ){

    if( addr0->addr.v4 == addr1->addr.v4 ){
      return 0;
    }

  }else if( addr0->addr_family == AF_INET6 ){

  	if( !memcmp(addr0->addr.v6,addr1->addr.v6,16) ){
  		return 0;
  	}

  }else{
    return -1;
  }

  return -1;
}

// -1 : not matched , 0 : equal , 1 : addr0 < addr1 , 2 : addr0 > addr1
int rhp_ip_addr_cmp_ip_only(rhp_ip_addr* addr0,rhp_ip_addr* addr1)
{
	rhp_ip_addr_dump("rhp_ip_addr_cmp_ip_only.addr0",addr0);
	rhp_ip_addr_dump("rhp_ip_addr_cmp_ip_only.addr1",addr1);

	if( addr0 == NULL || addr1 == NULL ){
    return -1;
  }

  if( addr0->addr_family != addr1->addr_family ){
    return -1;
  }

  if( addr0->addr_family == AF_INET ){

    u32 v4_0,v4_1;

    v4_0 = ntohl(addr0->addr.v4);
    v4_1 = ntohl(addr1->addr.v4);

    if( v4_0 == v4_1 ){
      return 0;
    }else if( v4_0 < v4_1 ){
      return 1;
    }else{
      return 2;
    }

  }else if( addr0->addr_family == AF_INET6 ){

  	u8 *v6_0,*v6_1;
  	int i;

  	v6_0 = addr0->addr.v6;
  	v6_1 = addr1->addr.v6;

  	for( i = 0; i < 16; i++ ){

  		if( v6_0[i] > v6_1[i] ){
  			return 2;
  		}else	if( v6_0[i] < v6_1[i] ){
  			return 1;
  		}
  	}

  	return 0;

  }else{
    return -1;
  }

  return -1;
}

// -1 : not matched , 0 : equal , 1 : addr0 < addr1 , 2 : addr0 > addr1
int rhp_ip_addr_cmp_value(rhp_ip_addr* addr0,int addr1_len,u8* addr1)
{
  if( addr0 == NULL || addr1 == NULL ){
    return -1;
  }

  if( (addr0->addr_family == AF_INET && addr1_len != 4) ||
  		(addr0->addr_family == AF_INET6 && addr1_len != 16) ){
    return -1;
  }

  if( addr0->addr_family == AF_INET ){

    u32 v4_0,v4_1;

    v4_0 = ntohl(addr0->addr.v4);
    v4_1 = ntohl(*((u32*)addr1));

    if( v4_0 == v4_1 ){
      return 0;
    }else if( v4_0 < v4_1 ){
      return 1;
    }else{
      return 2;
    }

  }else if( addr0->addr_family == AF_INET6 ){

  	u8* v6_0;
  	int i;

  	v6_0 = addr0->addr.v6;

  	for( i = 0; i < 16; i++ ){

  		if( v6_0[i] > addr1[i] ){
  			return 2;
  		}else	if( v6_0[i] < addr1[i] ){
  			return 1;
  		}
  	}

  	return 0;

  }else{
    return -1;
  }

  return -1;
}

int rhp_ipv6_is_same_addr(u8* addr0,u8* addr1)
{
	u64 *a0 = (u64*)addr0, *a1 = (u64*)addr1;

	if( a0 == NULL || a1 == NULL ){
		return 0;
	}

	if( a0[0] == a1[0] && a0[1] == a1[1] ){
		return 1;
	}

	return 0;
}

void rhp_ipv4_subnet_addr_range(u32 subnet_addr,u32 subnet_mask,u32* start_r,u32* end_r)
{
	u32 end;

	end = (subnet_addr | (0xFFFFFFFF & ~(subnet_mask)));

	if( start_r ){
		*start_r = subnet_addr;
	}
	if( end_r ){
		*end_r = end;
	}

	return;
}

void rhp_ipv4_subnet_addr_range2(u32 subnet_addr,int prefix_len,u32* start_r,u32* end_r)
{
	u32 end;
	u32 subnet_mask;

	if( prefix_len <= 0 ){

		if( start_r ){
			*start_r = 0;
		}
		if( end_r ){
			*end_r = 0xFFFFFFFF;
		}

		return;

	}else if( prefix_len >= 128 ){

		if( start_r ){
			*start_r = subnet_addr;
		}
		if( end_r ){
			*end_r = subnet_addr;
		}
		return;
	}

	subnet_mask = rhp_ipv4_prefixlen_to_netmask(prefix_len);

	return rhp_ipv4_subnet_addr_range(subnet_addr,subnet_mask,start_r,end_r);
}

void rhp_ipv6_subnet_addr_range(u8* subnet_addr,int prefix_len,u8* start_r,u8* end_r)
{
	int nb = prefix_len / 8;
	int rb = prefix_len % 8;
	u8 end[16];
	int r;

	if( prefix_len <= 0 ){

		if( start_r ){
			memset(start_r,0,16);
		}
		if( end_r ){
			memset(end_r,0xFF,16);
		}

		return;

	}else if( prefix_len >= 128 ){

		if( start_r ){
			memcpy(start_r,subnet_addr,16);
		}
		if( end_r ){
			memcpy(end_r,subnet_addr,16);
		}
		return;
	}


	memcpy(end,subnet_addr,nb);
	r = 16 - nb;

	if( rb ){
		end[nb] = (subnet_addr[nb] & (0xFF << (8 - rb))) | (0xFF >> rb);
		r--;
		nb++;
	}

	if( r ){
		memset(&(end[nb]),0xFF,r);
	}

	if( start_r ){
		memcpy(start_r,subnet_addr,16);
	}
	if( end_r ){
		memcpy(end_r,end,16);
	}

	return;
}


extern int rhp_vpn_gen_or_add_local_mac(u8* added_mac,u8* mac_addr_r);

// if_id: MAC address(48bits) or NULL.
// id_r: 64bits
int rhp_eui64_id_gen(u8* if_id,rhp_eui64_id* id_r)
{
	int err = -EINVAL;
	u8 mac[6];

	err = rhp_vpn_gen_or_add_local_mac(if_id,mac);
	if( err ){
		RHP_BUG("%d",err);
		goto error;
	}

	if( mac[0] & 0x02 ){
		mac[0] |= 0x02; // Local address
		id_r->gen_by_global_id = 1;
	}else{
		id_r->gen_by_global_id = 0;
	}

	id_r->id[0] = mac[0];
	id_r->id[1] = mac[1];
	id_r->id[2] = mac[2];
	id_r->id[3] = 0xFF;
	id_r->id[4] = 0xFE;
	id_r->id[5] = mac[3];
	id_r->id[6] = mac[4];
	id_r->id[7] = mac[5];

	return 0;

error:
	return err;
}

extern void rhp_vpn_clear_local_mac(u8* mac_addr);

void rhp_eui64_id_clear(rhp_eui64_id* id)
{
	u8 mac[6];

	mac[0] = id->id[0];
	mac[1] = id->id[1];
	mac[2] = id->id[2];
	mac[3] = id->id[5];
	mac[4] = id->id[6];
	mac[5] = id->id[7];

	if( id->gen_by_global_id ){
		mac[0] &= 0xFE;
	}

	rhp_vpn_clear_local_mac(mac);

	return;
}


void rhp_ikev2_id_dump(char* label,rhp_ikev2_id* id)
{

	_RHP_TRC_FLG_UPDATE(_rhp_trc_user_id());
  if( !_RHP_TRC_COND(_rhp_trc_user_id(),0) ){
    return;
  }

  if( id == NULL ){
    RHP_TRC(0,RHPTRCID_IKEV2_ID_DUMP_NULL,"s",label);
    return;
  }

  switch( id->type ){

  case RHP_PROTO_IKE_ID_FQDN:

  	RHP_TRC(0,RHPTRCID_IKEV2_ID_DUMP__FQDN,"sxLdLdsdx",label,id,"PROTO_IKE_ID",id->type,"PROTO_IKE_ID",id->cert_sub_type,id->string,id->dn_der_len,id->dn_der);
 	  break;

  case RHP_PROTO_IKE_ID_RFC822_ADDR:

 	  RHP_TRC(0,RHPTRCID_IKEV2_ID_DUMP__RFC822_ADDR_EMAIL,"sxLdLdsdx",label,id,"PROTO_IKE_ID",id->type,"PROTO_IKE_ID",id->cert_sub_type,id->string,id->dn_der_len,id->dn_der);
 	  break;

  case RHP_PROTO_IKE_ID_DER_ASN1_DN:

 	  RHP_TRC(0,RHPTRCID_IKEV2_ID_DUMP_ANS1_DN,"sxLdLdxp",label,id,"PROTO_IKE_ID",id->type,"PROTO_IKE_ID",id->cert_sub_type,id->string,id->dn_der_len,id->dn_der);
 	  break;

  case RHP_PROTO_IKE_ID_PRIVATE_SUBJECTALTNAME:

  	if( id->cert_sub_type == RHP_PROTO_IKE_ID_FQDN ){
  		RHP_TRC(0,RHPTRCID_IKEV2_ID_DUMP_SUBJECTALTNAME_FQDN,"sxLdLdsdx",label,id,"PROTO_IKE_ID",id->type,"PROTO_IKE_ID",id->cert_sub_type,id->string,id->dn_der_len,id->dn_der);
  	}else if( id->cert_sub_type == RHP_PROTO_IKE_ID_RFC822_ADDR ){
  		RHP_TRC(0,RHPTRCID_IKEV2_ID_DUMP_SUBJECTALTNAME_RFC822_ADDR_EMAIL,"sxLdLdsdx",label,id,"PROTO_IKE_ID",id->type,"PROTO_IKE_ID",id->cert_sub_type,id->string,id->dn_der_len,id->dn_der);
  	}else{
  		RHP_TRC(0,RHPTRCID_IKEV2_ID_DUMP_SUBJECTALTNAME_UNKNOWN,"sxLdLd",label,id,"PROTO_IKE_ID",id->type,"PROTO_IKE_ID",id->cert_sub_type);
  		goto unknown_type;
    }
  	break;

  case RHP_PROTO_IKE_ID_PRIVATE_CERT_AUTO:

  	if( id->cert_sub_type == RHP_PROTO_IKE_ID_FQDN ){
  		RHP_TRC(0,RHPTRCID_IKEV2_ID_DUMP_CERT_AUTO_FQDN,"sxLdLdsdx",label,id,"PROTO_IKE_ID",id->type,"PROTO_IKE_ID",id->cert_sub_type,id->string,id->dn_der_len,id->dn_der);
  	}else if( id->cert_sub_type == RHP_PROTO_IKE_ID_RFC822_ADDR ){
  		RHP_TRC(0,RHPTRCID_IKEV2_ID_DUMP_CERT_AUTO_RFC822_ADDR_EMAIL,"sxLdLdsdx",label,id,"PROTO_IKE_ID",id->type,"PROTO_IKE_ID",id->cert_sub_type,id->string,id->dn_der_len,id->dn_der);
  	}else if( id->cert_sub_type == RHP_PROTO_IKE_ID_DER_ASN1_DN ){
  		RHP_TRC(0,RHPTRCID_IKEV2_ID_DUMP_DER_ASN1_DN,"sxLdLdxp",label,id,"PROTO_IKE_ID",id->type,"PROTO_IKE_ID",id->cert_sub_type,id->string,id->dn_der_len,id->dn_der);
  	}else{
   		RHP_TRC(0,RHPTRCID_IKEV2_ID_DUMP_CERT_AUTO_UNKNOWN,"sxLdLd",label,id,"PROTO_IKE_ID",id->type,"PROTO_IKE_ID",id->cert_sub_type);
   		goto unknown_type;
  	}
  	break;

  case RHP_PROTO_IKE_ID_IPV4_ADDR:

  	RHP_TRC(0,RHPTRCID_IKEV2_ID_DUMP_IS_IPV4_ID,"sxLdLd4",label,id,"PROTO_IKE_ID",id->type,"PROTO_IKE_ID",id->cert_sub_type,id->addr.addr.v4);
  	break;

  case RHP_PROTO_IKE_ID_IPV6_ADDR:

  	RHP_TRC(0,RHPTRCID_IKEV2_ID_DUMP_IS_IPV6_ID,"sxLdLd6",label,id,"PROTO_IKE_ID",id->type,"PROTO_IKE_ID",id->cert_sub_type,id->addr.addr.v6);
  	break;

  case RHP_PROTO_IKE_ID_ANY:

  	RHP_TRC(0,RHPTRCID_IKEV2_ID_DUMP_IS_ANY_ID,"sxLdLd",label,id,"PROTO_IKE_ID",id->type,"PROTO_IKE_ID",id->cert_sub_type);
  	break;

  case RHP_PROTO_IKE_ID_NULL_ID:

		RHP_TRC(0,RHPTRCID_IKEV2_ID_DUMP_IS_NULL_ID,"sxLds",label,id,"PROTO_IKE_ID",id->type,id->conn_name_for_null_id);
  	break;

  case RHP_PROTO_IKE_ID_PRIVATE_NULL_ID_WITH_ADDR:

  	if( id->addr.addr_family == AF_INET ){
  		RHP_TRC(0,RHPTRCID_IKEV2_ID_DUMP_IS_NULL_ID_WITH_ADDR_V4,"sxLd4Ws",label,id,"PROTO_IKE_ID",id->type,id->addr.addr.v4,id->addr.port,id->conn_name_for_null_id);
  	}else if( id->addr.addr_family == AF_INET6 ){
  		RHP_TRC(0,RHPTRCID_IKEV2_ID_DUMP_IS_NULL_ID_WITH_ADDR_V6,"sxLd6Ws",label,id,"PROTO_IKE_ID",id->type,id->addr.addr.v6,id->addr.port,id->conn_name_for_null_id);
  	}else{
  		RHP_TRC(0,RHPTRCID_IKEV2_ID_DUMP_IS_NULL_ID_WITH_ADDR_UNKNOWN_AF,"sxLdpWs",label,id,"PROTO_IKE_ID",id->type,16,id->addr.addr.raw,id->addr.port,id->conn_name_for_null_id);
  	}
  	break;

  default:
  	RHP_TRC(0,RHPTRCID_IKEV2_ID_DUMP_UNKNOWN_ID,"sxLdLd",label,id,"PROTO_IKE_ID",id->type,"PROTO_IKE_ID",id->cert_sub_type);
  	break;
  }

  if( id->alt_id ){

  	rhp_ikev2_id_dump("id->alt_id",id->alt_id);
  }

unknown_type:
  return;
}


void rhp_eap_id_dump(char* label,rhp_eap_id* id)
{

	_RHP_TRC_FLG_UPDATE(_rhp_trc_user_id());
  if( !_RHP_TRC_COND(_rhp_trc_user_id(),0) ){
    return;
  }

  if( id == NULL ){
    RHP_TRC(0,RHPTRCID_IKEV2_EAP_ID_DUMP_NULL,"s",label);
    return;
  }

  if( id->method != RHP_PROTO_EAP_TYPE_PRIV_RADIUS ){
  	RHP_TRC(0,RHPTRCID_EAP_ID_DUMP,"sxLdpd",label,id,"EAP_TYPE",id->method,id->identity_len,id->identity,id->for_xauth);
  }else{
  	RHP_TRC(0,RHPTRCID_EAP_ID_DUMP_RADIUS,"sxLdpLdskd",label,id,"EAP_TYPE",id->method,id->identity_len,id->identity,"EAP_TYPE",id->radius.eap_method,id->radius.user_index,id->radius.salt,id->for_xauth);
  	rhp_ip_addr_dump("radius.assigned_addr_v4",id->radius.assigned_addr_v4);
  	rhp_ip_addr_dump("radius.assigned_addr_v6",id->radius.assigned_addr_v6);
  }
  return;
}

int rhp_ikev2_id_to_string(rhp_ikev2_id* id,char** id_type_r,char** id_str_r)
{
	int err = -EINVAL;
	char *id_type = NULL,*id_str = NULL;
	char id_type_str[128];
	int id_type_str_len = 0;
	char* id_str_o = NULL;
	char* id_any_str = "any";
	char* id_null_str = "Null";
	char* id_str_o_unknown = "unknown";
	char* id_str_o_invalid = "invalid";
	int id_str_o_dyn = 0;
	char id_str_ip[48];

	RHP_TRC(0,RHPTRCID_IKEV2_ID_TO_STRING,"xLdLdspxx",id,"PROTO_IKE_ID",id->type,"PROTO_IKE_ID",id->cert_sub_type,id->string,id->dn_der_len,id->dn_der,id_type_r,id_str_r);

	if( id == NULL ){
		RHP_BUG("");
  	return -EINVAL;
  }

	id_type_str[0] = '\0';

  switch( id->type ){

  case RHP_PROTO_IKE_ID_FQDN:

  	id_type_str_len = strlen("fqdn") + 1;
  	strcpy(id_type_str,"fqdn");
  	break;

  case RHP_PROTO_IKE_ID_RFC822_ADDR:

  	id_type_str_len = strlen("email") + 1;
  	strcpy(id_type_str,"email");
  	break;

  case RHP_PROTO_IKE_ID_DER_ASN1_DN:

  	id_type_str_len = strlen("dn") + 1;
  	strcpy(id_type_str,"dn");
  	break;

  case RHP_PROTO_IKE_ID_PRIVATE_SUBJECTALTNAME:

  	if( id->cert_sub_type == RHP_PROTO_IKE_ID_FQDN ){

  		id_type_str_len = strlen("subjectaltname:fqdn") + 1;
    	strcpy(id_type_str,"subjectaltname:fqdn");

  	}else if( id->cert_sub_type == RHP_PROTO_IKE_ID_RFC822_ADDR ){

  		id_type_str_len = strlen("subjectaltname:email") + 1;
    	strcpy(id_type_str,"subjectaltname:email");

  	}else{

  		id_type_str_len = strlen("subjectaltname:unknown") + 1;
    	strcpy(id_type_str,"subjectaltname:unknown");
  	}
  	break;

  case RHP_PROTO_IKE_ID_PRIVATE_CERT_AUTO:

  	if( id->cert_sub_type == RHP_PROTO_IKE_ID_FQDN ){

  		id_type_str_len = strlen("subjectaltname:fqdn") + 1;
    	strcpy(id_type_str,"subjectaltname:fqdn");

  	}else if( id->cert_sub_type == RHP_PROTO_IKE_ID_RFC822_ADDR ){

  		id_type_str_len = strlen("subjectaltname:email") + 1;
    	strcpy(id_type_str,"subjectaltname:email");

  	}else if( id->cert_sub_type == RHP_PROTO_IKE_ID_DER_ASN1_DN ){

    	id_type_str_len = strlen("dn") + 1;
    	strcpy(id_type_str,"dn");

  	}else{
  		id_type_str_len = strlen("subjectaltname:unknown") + 1;
    	strcpy(id_type_str,"subjectaltname:unknown");
  	}
  	break;

  case RHP_PROTO_IKE_ID_IPV4_ADDR:

		id_type_str_len = strlen("ipv4") + 1;
  	strcpy(id_type_str,"ipv4");
  	break;

  case RHP_PROTO_IKE_ID_IPV6_ADDR:

		id_type_str_len = strlen("ipv6") + 1;
  	strcpy(id_type_str,"ipv6");
  	break;

  case RHP_PROTO_IKE_ID_NULL_ID:
  case RHP_PROTO_IKE_ID_PRIVATE_NULL_ID_WITH_ADDR:

		id_type_str_len = strlen("null-id") + 1;
  	strcpy(id_type_str,"null-id");
  	break;

  case RHP_PROTO_IKE_ID_ANY:

		id_type_str_len = strlen("any") + 1;
  	strcpy(id_type_str,"any");
  	break;

  default:
		id_type_str_len = strlen("unknown") + 1;
  	strcpy(id_type_str,"unknown");
  	break;
  }

  if( id->type == RHP_PROTO_IKE_ID_ANY ){

  	id_str_o = id_any_str;

  }else if( id->type == RHP_PROTO_IKE_ID_NULL_ID ){

  	if( id->conn_name_for_null_id ){
  		id_str_o = id->conn_name_for_null_id;
  	}else{
  		id_str_o = id_null_str;
  	}

  }else if( id->type == RHP_PROTO_IKE_ID_PRIVATE_NULL_ID_WITH_ADDR ){

  	err = rhp_ikev2_id_value_str(id,(u8**)&id_str_o,NULL,NULL);
  	if( err ){
  		RHP_BUG("%d",err);
  		goto error;
  	}

  	id_str_o_dyn = 1;

  }else{

  	if( id->string ){

  		id_str_o = id->string;

  	}else if( id->dn_der && id->dn_der_len ){

  		rhp_cert_dn* dn = rhp_cert_dn_alloc_by_DER(id->dn_der,id->dn_der_len);
  		if( dn == NULL ){

  			id_str_o = id_str_o_invalid;

  		}else{

  			id_str_o = dn->to_text(dn);
  			id_str_o_dyn = 1;
  			rhp_cert_dn_free(dn);
  		}

  	}else if( id->type == RHP_PROTO_IKE_ID_IPV4_ADDR ){

  		id_str_ip[0] = '\0';
  		snprintf(id_str_ip,48,"%d.%d.%d.%d",id->addr.addr.raw[0],id->addr.addr.raw[1],id->addr.addr.raw[2],id->addr.addr.raw[3]);
  		id_str_o = id_str_ip;

  	}else if( id->type == RHP_PROTO_IKE_ID_IPV6_ADDR ){

  		id_str_ip[0] = '\0';
  		snprintf(id_str_ip,48,"%s",rhp_ipv6_string(id->addr.addr.v6));

  		id_str_o = id_str_ip;
  	}
  }

  if( id_str_o == NULL ){
		id_str_o = id_str_o_unknown;
  }

	id_type = (char*)_rhp_malloc(id_type_str_len);
	if( id_type == NULL ){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	id_type[0] = '\0';

	id_str = (char*)_rhp_malloc(strlen(id_str_o) + 1);
	if( id_type == NULL ){
		err = -ENOMEM;
		RHP_BUG("");
		goto error;
	}
	id_str[0] = '\0';

	strcpy(id_type,id_type_str);
	strcpy(id_str,id_str_o);

  *id_type_r = id_type;
  *id_str_r = id_str;

  if( id_str_o_dyn ){
  	_rhp_free(id_str_o);
  }

	RHP_TRC(0,RHPTRCID_IKEV2_ID_TO_STRING_RTRN,"xLds",id,"PROTO_IKE_ID",*id_type_r,*id_str_r);
  return 0;

error:
	if( id_type ){
		_rhp_free(id_type);
	}
	if( id_str ){
		_rhp_free(id_str);
	}
  if( id_str_o_dyn ){
  	_rhp_free(id_str_o);
  }
	RHP_TRC(0,RHPTRCID_IKEV2_ID_TO_STRING_ERR,"xLd",id,"PROTO_IKE_ID",id->type);
  return err;
}

int rhp_ikev2_is_null_auth_id(int id_type)
{
	if( id_type == RHP_PROTO_IKE_ID_NULL_ID ||
			id_type == RHP_PROTO_IKE_ID_PRIVATE_NULL_ID_WITH_ADDR ){
		return 1;
	}
	return 0;
}

int rhp_ikev2_id_is_null_auth_id(rhp_ikev2_id* id)
{
	return rhp_ikev2_is_null_auth_id(id->type);
}

int rhp_ikev2_to_null_auth_id(int id_type)
{
	if( id_type == RHP_PROTO_IKE_ID_NULL_ID ||
			id_type == RHP_PROTO_IKE_ID_PRIVATE_NULL_ID_WITH_ADDR ){
		return RHP_PROTO_IKE_ID_NULL_ID;
	}
	return id_type;
}


extern char* rhp_eap_method2str_def(int method);

int rhp_eap_id_to_string(rhp_eap_id* eap_id,char** eap_id_method_r,char** eap_id_str_r)
{
	int err = -EINVAL;
	char* eap_id_method_str = NULL;
	char* eap_id_str = NULL;

	if( rhp_eap_id_is_null(eap_id) ){
		RHP_BUG("");
		return -EINVAL;
	}

	eap_id_method_str = rhp_eap_method2str_def(eap_id->method);
	if( eap_id_method_str == NULL ){

		eap_id_method_str = (char*)_rhp_malloc(strlen("unknown") + 1);
		if( eap_id_method_str == NULL ){
			RHP_BUG("");
			err = -ENOMEM;
			goto error;
		}

		eap_id_method_str[0] = '\0';
		strcpy(eap_id_method_str,"unknown");
	}

	eap_id_str = (char*)_rhp_malloc(eap_id->identity_len + 1);
	if( eap_id_str == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}

	memcpy(eap_id_str,eap_id->identity,eap_id->identity_len + 1);


	if( eap_id_method_r ){
		*eap_id_method_r = eap_id_method_str;
	}else{
		_rhp_free(eap_id_method_str);
	}

	if( eap_id_str_r ){
		*eap_id_str_r = eap_id_str;
	}else{
		_rhp_free(eap_id_str);
	}

	return 0;

error:
	if( eap_id_method_str ){
		_rhp_free(eap_id_method_str);
	}
	if( eap_id_str ){
		_rhp_free(eap_id_str);
	}
	return err;
}


void rhp_ip_addr_dump(char* label,rhp_ip_addr* addr)
{
	_RHP_TRC_FLG_UPDATE(_rhp_trc_user_id());
  if( !_RHP_TRC_COND(_rhp_trc_user_id(),0) ){
    return;
  }

  if( addr == NULL ){
    RHP_TRC(0,RHPTRCID_IP_ADDR_DUMP_NULL,"s",label);
    return;
  }

  if( addr->addr_family == AF_INET ){
    RHP_TRC(0,RHPTRCID_IP_ADDR_DUMP_AF_INET,"sx44dWd",label,addr,addr->addr.v4,addr->netmask.v4,addr->prefixlen,addr->port,addr->tag);
  }else if( addr->addr_family == AF_INET6 ){
    RHP_TRC(0,RHPTRCID_IP_ADDR_DUMP_AF_INET6,"sx66dWud",label,addr,addr->addr.v6,addr->netmask.v6,addr->prefixlen,addr->port,addr->ipv6_scope_id,addr->tag);
  }else{
    RHP_TRC(0,RHPTRCID_IP_ADDR_DUMP_UNKOWN_ADDR_FAMILY,"sxdW",label,addr,addr->tag,addr->port);
  }

  return;
}

void rhp_if_entry_dump(char* label,rhp_if_entry* if_ent)
{
	_RHP_TRC_FLG_UPDATE(_rhp_trc_user_id());
  if( !_RHP_TRC_COND(_rhp_trc_user_id(),0) ){
    return;
  }

  if( if_ent == NULL ){
    RHP_TRC(0,RHPTRCID_IF_ENTRY_DUMP_NULL,"s",label);
    return;
  }

  if( if_ent->addr_family == AF_INET ){
    RHP_TRC(0,RHPTRCID_IF_ENTRY_DUMP_AF_INET,"sxsMdxd4d",label,if_ent,if_ent->if_name,if_ent->mac,if_ent->if_index,if_ent->if_flags,if_ent->mtu,if_ent->addr.v4,if_ent->prefixlen);
  }else if( if_ent->addr_family == AF_INET6 ){
    RHP_TRC(0,RHPTRCID_IF_ENTRY_DUMP_AF_INET6,"sxsMdxd6d",label,if_ent,if_ent->if_name,if_ent->mac,if_ent->if_index,if_ent->if_flags,if_ent->mtu,if_ent->addr.v6,if_ent->prefixlen);
  }else{
    RHP_TRC(0,RHPTRCID_IF_ENTRY_DUMP_UNKOWN_ADDR_FAMILY,"sxsMdxdpd",label,if_ent,if_ent->if_name,if_ent->mac,if_ent->if_index,if_ent->if_flags,if_ent->mtu,16,if_ent->addr.raw,if_ent->prefixlen);
  }

	return;
}

int rhp_if_entry_cmp(rhp_if_entry* if_ent0,rhp_if_entry* if_ent1)
{
	if( if_ent0 == NULL || if_ent1 == NULL ){
		return -1;
	}
	return memcmp(if_ent0,if_ent1,sizeof(rhp_if_entry));
/*
	RHP_TRC(0,RHPTRCID_IF_ENTRY_CMP,"xx",if_ent0,if_ent1);
	rhp_if_entry_dump("if_ent0",if_ent0);
	rhp_if_entry_dump("if_ent1",if_ent1);

	if( if_ent0->if_index != if_ent1->if_index ){
		goto error;
	}

	if( if_ent0->addr_family != if_ent1->addr_family ){
		goto error;
	}

	if( if_ent0->addr_family == AF_INET ){
		if( if_ent0->addr.v4 != if_ent1->addr.v4 ){
			goto error;
		}
	}else if( if_ent0->addr_family == AF_INET6 ){
		if( memcmp(if_ent0->addr.v6,if_ent1->addr.v6,16) ){
			goto error;
		}
	}

	if( (if_ent0->if_flags & IFF_UP) != (if_ent1->if_flags & IFF_UP) ){
		goto error;
	}

	if( memcmp(if_ent0->mac,if_ent1->mac,6) ){
		goto error;
	}

	RHP_TRC(0,RHPTRCID_IF_ENTRY_CMP_SAME,"xx",if_ent0,if_ent1);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_IF_ENTRY_CMP_NOT_SAME,"xx",if_ent0,if_ent1);
	return -1;
*/
}

void rhp_rtmap_entry_dump(char* label,rhp_rt_map_entry* rtmap_ent)
{
	_RHP_TRC_FLG_UPDATE(_rhp_trc_user_id());
  if( !_RHP_TRC_COND(_rhp_trc_user_id(),0) ){
    return;
  }

  if( rtmap_ent == NULL ){
    RHP_TRC(0,RHPTRCID_RTMAP_ENTRY_DUMP_NULL,"s",label);
    return;
  }

  if( rtmap_ent->addr_family == AF_INET ){
    RHP_TRC(0,RHPTRCID_RTMAP_ENTRY_DUMP_AF_INET,"sxLdsd44d4d",label,rtmap_ent,"RTMAP_TYPE",rtmap_ent->type,rtmap_ent->oif_name,rtmap_ent->oif_index,rtmap_ent->dest_network.addr.v4,rtmap_ent->dest_network.netmask.v4,rtmap_ent->dest_network.prefixlen,rtmap_ent->gateway_addr.addr.v4,rtmap_ent->metric);
  }else if( rtmap_ent->addr_family == AF_INET6 ){
    RHP_TRC(0,RHPTRCID_RTMAP_ENTRY_DUMP_AF_INET6,"sxLdsd66d6d",label,rtmap_ent,"RTMAP_TYPE",rtmap_ent->type,rtmap_ent->oif_name,rtmap_ent->oif_index,rtmap_ent->dest_network.addr.v6,rtmap_ent->dest_network.netmask.v6,rtmap_ent->dest_network.prefixlen,rtmap_ent->gateway_addr.addr.v6,rtmap_ent->metric);
  }else{
    RHP_TRC(0,RHPTRCID_RTMAP_ENTRY_DUMP_UNKNOWN_ADDR_FAMILY,"sxLdsdppdpd",label,rtmap_ent,"RTMAP_TYPE",rtmap_ent->type,rtmap_ent->oif_name,rtmap_ent->oif_index,16,rtmap_ent->dest_network.addr.raw,16,rtmap_ent->dest_network.netmask.raw,rtmap_ent->dest_network.prefixlen,16,rtmap_ent->gateway_addr.addr.raw,rtmap_ent->metric);
  }

	return;
}


void rhp_rtmap_dump(char* label,rhp_route_map* rtmap)
{
	_RHP_TRC_FLG_UPDATE(_rhp_trc_user_id());
  if( !_RHP_TRC_COND(_rhp_trc_user_id(),0) ){
    return;
  }

  if( rtmap == NULL ){
    RHP_TRC(0,RHPTRCID_RTMAP_DUMP_NULL,"s",label);
    return;
  }

  RHP_TRC(0,RHPTRCID_RTMAP_DUMP,"sxxsud",label,rtmap,rtmap->next,rtmap->tx_interface,rtmap->metric,rtmap->ikev2_cfg);
  rhp_ip_addr_dump("rtmap->dest_addr",&(rtmap->dest_addr));
  rhp_ip_addr_dump("rtmap->gateway_addr",&(rtmap->gateway_addr));
  rhp_ikev2_id_dump("rtmap->gateway_peer_id",&(rtmap->gateway_peer_id));

	return;
}


static rhp_cmd_tlv* _rhp_cmd_tlv_alloc(int type,char* name,int value_len,void* value)
{
	rhp_cmd_tlv* tlv = (rhp_cmd_tlv*)_rhp_malloc(sizeof(rhp_cmd_tlv));

	if( tlv == NULL ){
		RHP_BUG("");
		return NULL;
	}

  RHP_TRC(0,RHPTRCID_CMD_TLV_ALLOC,"dsp",type,name,value_len,value);

	memset(tlv,0,sizeof(rhp_cmd_tlv));

	tlv->tag[0] = '#';
	tlv->tag[1] = 'C';
	tlv->tag[2] = 'L';
	tlv->tag[3] = 'V';

	tlv->type = type;
	tlv->name = (char*)_rhp_malloc(strlen(name) + 1);
	tlv->value = (void*)_rhp_malloc(value_len);

	if( tlv->name == NULL || tlv->value == NULL ){
		RHP_BUG("");
		goto error;
	}

	tlv->name[0] = '\0';
	strcpy(tlv->name,name);

	tlv->value_len = value_len;
  memcpy(tlv->value,value,value_len);

  RHP_TRC(0,RHPTRCID_CMD_TLV_ALLOC_RTRN,"dspx",type,name,value_len,value,tlv);
  return tlv;

error:
	if( tlv->name ){
		_rhp_free(tlv->name);
	}
	if( tlv->value ){
		_rhp_free(tlv->value);
	}
	_rhp_free(tlv);

	RHP_TRC(0,RHPTRCID_CMD_TLV_ALLOC_ERR,"dsp",type,name,value_len,value);
	return NULL;
}

void rhp_cmd_tlv_clear(rhp_cmd_tlv_list* list)
{
	rhp_cmd_tlv *tlv,*tlv_tmp;

  RHP_TRC(0,RHPTRCID_CMD_TLV_CLEAR,"x",list);

	tlv = list->head;
	while( tlv ){

		tlv_tmp = tlv->next;

		if( tlv->name ){
			_rhp_free(tlv->name);
		}
		if( tlv->value ){
			_rhp_free(tlv->value);
		}
		_rhp_free(tlv);

	  RHP_TRC(0,RHPTRCID_CMD_TLV_CLEAR_TLV_ENTRY,"xx",list,tlv);

		tlv = tlv_tmp;
	}

  RHP_TRC(0,RHPTRCID_CMD_TLV_RTRN,"x",list);
	return;
}

int rhp_cmd_tlv_add(rhp_cmd_tlv_list* list,int type,char* name,unsigned long value_len,void* value)
{
	rhp_cmd_tlv* tlv = _rhp_cmd_tlv_alloc(type,name,value_len,value);

  RHP_TRC(0,RHPTRCID_CMD_TLV_ADD,"xxxdsp",list,tlv,tlv->next,type,name,value_len,value);

	if( tlv == NULL ){
		RHP_BUG("");
		return -ENOMEM;
	}

	if( list->head == NULL ){
		list->head = tlv;
	}else{
		list->tail->next = tlv;
	}
	list->tail = tlv;

  RHP_TRC(0,RHPTRCID_CMD_TLV_ADD_RTRN,"xxxdspx",list,tlv,tlv->next,type,name,value_len,value,tlv);
	return 0;
}


static rhp_mutex_t _rhp_cmd_exec_lock;

struct _rhp_cmd_wait_ctx {

	u8 tag[4]; // '#cmd'

	struct _rhp_cmd_wait_ctx* next;

	pid_t sync_wait_pid;
	rhp_cond_t sync_evt;
	int exit_status;
};
typedef struct _rhp_cmd_wait_ctx	rhp_cmd_wait_ctx;

static rhp_cmd_wait_ctx* _rhp_cmd_wait_ctx_head = NULL;
static rhp_cmd_wait_ctx* _rhp_cmd_wait_ctx_tail = NULL;


#define RHP_CMD_EXEC_ENV_MAX		256

int rhp_cmd_exec(char* cmd,rhp_cmd_tlv_list* env_tlvs,int sync_flag)
{
	int err = -EINVAL;
	rhp_cmd_tlv* tlv;
	int i = 0;
	char* argv[2];
	char* env[RHP_CMD_EXEC_ENV_MAX];
	int pid;
	rhp_cmd_wait_ctx wait_ctx;

  RHP_TRC(0,RHPTRCID_CMD_EXEC,"sxd",cmd,env_tlvs,sync_flag);

	if( cmd == NULL ){
		RHP_BUG("");
		return -EINVAL;
	}

	memset(argv,0,sizeof(char*)*2);
	memset(env,0,sizeof(char*)*RHP_CMD_EXEC_ENV_MAX);

	if( sync_flag ){

		memset(&wait_ctx,0,sizeof(rhp_cmd_wait_ctx));

		wait_ctx.tag[0] = '#';
		wait_ctx.tag[1] = 'C';
		wait_ctx.tag[2] = 'M';
		wait_ctx.tag[3] = 'D';

		_rhp_cond_init(&(wait_ctx.sync_evt));
		wait_ctx.exit_status = -EINVAL;
	}

	RHP_LOCK(&_rhp_cmd_exec_lock);

	tlv = env_tlvs->head;
	while( tlv ){

#define RHP_CMD_EXEC_VAL_LEN		512
		char value_str[RHP_CMD_EXEC_VAL_LEN];
		char* value_str2 = NULL;
		rhp_ip_addr* addr;
		u32 mask;

		value_str[0] = '\0';

		switch( tlv->type ){

		case RHP_CMD_TLV_INT:

			err = snprintf(value_str,RHP_CMD_EXEC_VAL_LEN,"%d",*((int*)tlv->value));
			if( err < 0 ){
				RHP_BUG("%d",err);
				err = -EINVAL;
				goto error;
			}else if( err >= RHP_CMD_EXEC_VAL_LEN ){
				RHP_BUG("%d",err);
				err = -EINVAL;
				goto error;
			}
			err = 0;
			break;

		case RHP_CMD_TLV_UINT:

			err = snprintf(value_str,RHP_CMD_EXEC_VAL_LEN,"%u",*((unsigned int*)tlv->value));
			if( err < 0 ){
				RHP_BUG("%d",err);
				err = -EINVAL;
				goto error;
			}else if( err >= RHP_CMD_EXEC_VAL_LEN ){
				RHP_BUG("%d",err);
				err = -EINVAL;
				goto error;
			}
			err = 0;
			break;

		case RHP_CMD_TLV_LONG:

			err = snprintf(value_str,RHP_CMD_EXEC_VAL_LEN,"%ld",*((long*)tlv->value));
			if( err < 0 ){
				RHP_BUG("%d",err);
				err = -EINVAL;
				goto error;
			}else if( err >= RHP_CMD_EXEC_VAL_LEN ){
				RHP_BUG("%d",err);
				err = -EINVAL;
				goto error;
			}
			err = 0;
			break;

		case RHP_CMD_TLV_ULONG:

			err = snprintf(value_str,RHP_CMD_EXEC_VAL_LEN,"%lu",*((unsigned long*)tlv->value));
			if( err < 0 ){
				RHP_BUG("%d",err);
				err = -EINVAL;
				goto error;
			}else if( err >= RHP_CMD_EXEC_VAL_LEN ){
				RHP_BUG("%d",err);
				err = -EINVAL;
				goto error;
			}
			err = 0;
			break;

		case RHP_CMD_TLV_IPV4:

			addr = (rhp_ip_addr*)tlv->value;

			err = snprintf(value_str,RHP_CMD_EXEC_VAL_LEN,"%d.%d.%d.%d",
					(int)(addr->addr.raw[0]),(int)(addr->addr.raw[1]),(int)(addr->addr.raw[2]),(int)(addr->addr.raw[3]));

			if( err < 0 ){
				RHP_BUG("%d",err);
				err = -EINVAL;
				goto error;
			}else if( err >= RHP_CMD_EXEC_VAL_LEN ){
				RHP_BUG("%d",err);
				err = -EINVAL;
				goto error;
			}
			err = 0;
			break;

		case RHP_CMD_TLV_PORT:

			err = snprintf(value_str,RHP_CMD_EXEC_VAL_LEN,"%d",(int)*((u16*)tlv->value));
			if( err < 0 ){
				RHP_BUG("%d",err);
				err = -EINVAL;
				goto error;
			}else if( err >= RHP_CMD_EXEC_VAL_LEN ){
				RHP_BUG("%d",err);
				err = -EINVAL;
				goto error;
			}
			err = 0;
			break;

		case RHP_CMD_TLV_STRING:

			value_str2 = (char*)tlv->value;
			break;

		case RHP_CMD_TLV_IPV4_SUBNET_PREFIX:

			addr = (rhp_ip_addr*)tlv->value;

			err = snprintf(value_str,RHP_CMD_EXEC_VAL_LEN,"%d.%d.%d.%d/%d",
					(int)(addr->addr.raw[0]),(int)(addr->addr.raw[1]),(int)(addr->addr.raw[2]),(int)(addr->addr.raw[3]),(int)(addr->prefixlen));

			if( err < 0 ){
				RHP_BUG("%d",err);
				err = -EINVAL;
				goto error;
			}else if( err >= RHP_CMD_EXEC_VAL_LEN ){
				RHP_BUG("%d",err);
				err = -EINVAL;
				goto error;
			}
			err = 0;
			break;

		case RHP_CMD_TLV_IPV4_SUBNET_MASK:

			addr = (rhp_ip_addr*)tlv->value;

			if( addr->prefixlen ){
		  	mask = rhp_ipv4_prefixlen_to_netmask(addr->prefixlen);
			}else{
				mask = addr->netmask.v4;
			}

			err = snprintf(value_str,RHP_CMD_EXEC_VAL_LEN,"%d.%d.%d.%d",((u8*)&mask)[0],((u8*)&mask)[1],((u8*)&mask)[2],((u8*)&mask)[3]);
			if( err < 0 ){
				RHP_BUG("%d",err);
				err = -EINVAL;
				goto error;
			}else if( err >= RHP_CMD_EXEC_VAL_LEN ){
				RHP_BUG("%d",err);
				err = -EINVAL;
				goto error;
			}
			err = 0;
			break;

		case RHP_CMD_TLV_IPV6:

			addr = (rhp_ip_addr*)tlv->value;

			err = snprintf(value_str,RHP_CMD_EXEC_VAL_LEN,"%s",rhp_ipv6_string(addr->addr.v6));
			if( err < 0 ){
				RHP_BUG("%d",err);
				err = -EINVAL;
				goto error;
			}else if( err >= RHP_CMD_EXEC_VAL_LEN ){
				RHP_BUG("%d",err);
				err = -EINVAL;
				goto error;
			}
			err = 0;
			break;

		case RHP_CMD_TLV_IPV6_SUBNET_PREFIX:

			addr = (rhp_ip_addr*)tlv->value;

			err = snprintf(value_str,RHP_CMD_EXEC_VAL_LEN,"%s/%d",
							rhp_ipv6_string(addr->addr.v6),(int)(addr->prefixlen));
			if( err < 0 ){
				RHP_BUG("%d",err);
				err = -EINVAL;
				goto error;
			}else if( err >= RHP_CMD_EXEC_VAL_LEN ){
				RHP_BUG("%d",err);
				err = -EINVAL;
				goto error;
			}
			err = 0;
			break;

		default:
			RHP_BUG("%d",tlv->type);
			goto ignore;
		}

		env[i] = (char*)_rhp_malloc(strlen(tlv->name) + 1 + strlen((value_str2 ? value_str2 : value_str)) + 1);
		if( env[i] == NULL ){
			err = -ENOMEM;
			goto error;
		}

		env[i][0] = '\0';
		err = sprintf(env[i],"%s=%s",tlv->name,(value_str2 ? value_str2 : value_str));
		if( err < 0 ){
			RHP_BUG("%d",err);
			err = -EINVAL;
			goto error;
		}

	  RHP_TRC(0,RHPTRCID_CMD_EXEC_ENV,"dxxs",i,tlv,tlv->next,env[i]);

ignore:
		tlv = tlv->next;
		i++;

		if( i >= RHP_CMD_EXEC_ENV_MAX ){
			RHP_BUG("i >= RHP_CMD_EXEC_ENV_MAX : i=%d",i);
			break;
		}
	}

	argv[0] = cmd;
	argv[1] = NULL;

  RHP_TRC(0,RHPTRCID_CMD_EXEC_FORK,"sxx",cmd,argv,env);

	pid = fork();

	if( pid < 0 ){

		RHP_BUG("%d",pid);

		err = -EINVAL;
		goto error;

	}else if( pid ){

		// Caller process...

		if( sync_flag && RHP_PROCESS_IS_ACTIVE() ){

			wait_ctx.sync_wait_pid = pid;

			if( _rhp_cmd_wait_ctx_head == NULL ){
				_rhp_cmd_wait_ctx_head = &wait_ctx;
			}else{
				_rhp_cmd_wait_ctx_tail->next = &wait_ctx;
			}
			_rhp_cmd_wait_ctx_tail = &wait_ctx;


			RHP_TRC(0,RHPTRCID_CMD_EXEC_CALLER_SYNC_START,"sxxd",cmd,argv,env,pid);
			
			err = _rhp_wait_event(&(wait_ctx.sync_evt),&_rhp_cmd_exec_lock,0);
			if( err ){
				RHP_BUG("%d",err);
			}

			wait_ctx.sync_wait_pid = 0;

			err = wait_ctx.exit_status;

			RHP_TRC(0,RHPTRCID_CMD_EXEC_CALLER_SYNC_END,"sxxdE",cmd,argv,env,pid,err);

		}else{

			err = 0;
		}

  	RHP_LOG_D(RHP_LOG_SRC_NETMNG,0,RHP_LOG_ID_CFG_SYS,"sssssssssssssE",cmd,env[0],env[1],env[2],env[3],env[4],env[5],env[6],env[7],env[8],env[9],env[10],env[11],err);
		
		RHP_TRC(0,RHPTRCID_CMD_EXEC_CALLER_FINISHED,"sxxE",cmd,argv,env,err);

	}else{

		int c_err;

		// Script process... Don't write event log and debug trace(direct_file_mode)!

		rhp_trace_pid = getpid();
		rhp_trace_tid = gettid();

		if( !rhp_gcfg_dbg_direct_file_trace ){
			RHP_TRC(0,RHPTRCID_CMD_EXEC_EXECVE,"sxx",cmd,argv,env);
		}

		c_err = execve(cmd,argv,env);

		if( !rhp_gcfg_dbg_direct_file_trace ){
			RHP_TRC(0,RHPTRCID_CMD_EXEC_EXECVE_ERR,"sdE",cmd,c_err,-errno);
		}

		exit(0);
	}

error:

	if( sync_flag ){

		rhp_cmd_wait_ctx *tmp_ctx0, *tmp_ctx1;

		tmp_ctx0 = _rhp_cmd_wait_ctx_head;
		tmp_ctx1 = NULL;
		while( tmp_ctx0 ){

			if( tmp_ctx0 == &wait_ctx ){
				break;
			}

			tmp_ctx1 = tmp_ctx0;
			tmp_ctx0 = tmp_ctx0->next;
		}

		if( tmp_ctx0 ){

			if( tmp_ctx1 == NULL ){
				_rhp_cmd_wait_ctx_head = tmp_ctx0->next;
			}else{
				tmp_ctx1->next = tmp_ctx0->next;
				if( _rhp_cmd_wait_ctx_tail == tmp_ctx0 ){
					_rhp_cmd_wait_ctx_tail = tmp_ctx1;
				}
			}

			_rhp_cond_destroy(&(wait_ctx.sync_evt));
			// wait_ctx is on stack. Don't free!

		}else{
			RHP_BUG("%s",cmd);
		}
	}

	tlv = env_tlvs->head;
	i = 0;
	while( tlv && env[i] ){

		if( env[i] ){
			_rhp_free(env[i]);
		}

		tlv = tlv->next;
		i++;
	}

	RHP_UNLOCK(&_rhp_cmd_exec_lock);

	RHP_TRC(0,RHPTRCID_CMD_EXEC_RTRN,"sxxxE",cmd,env_tlvs,argv,env,err);
  return err;
}

void rhp_cmd_exec_sync(pid_t pid,int exit_status)
{
	rhp_cmd_wait_ctx *wait_ctx;

	RHP_LOCK(&_rhp_cmd_exec_lock);

	wait_ctx = _rhp_cmd_wait_ctx_head;
	while( wait_ctx ){

		if( pid == 0 ){

			RHP_TRC(0,RHPTRCID_CMD_EXEC_SYNC_ALL,"dd",pid,wait_ctx->sync_wait_pid);

			wait_ctx->exit_status = -exit_status;

			RHP_EVT_NOTIFY(&(wait_ctx->sync_evt));

		}else if( wait_ctx->sync_wait_pid == pid ){

			RHP_TRC(0,RHPTRCID_CMD_EXEC_SYNC,"dE",pid,exit_status);

			wait_ctx->exit_status = -exit_status;

			RHP_EVT_NOTIFY(&(wait_ctx->sync_evt));
			break;
		}

		wait_ctx = wait_ctx->next;
	}

	if( pid && (wait_ctx == NULL) ){
		RHP_TRC(0,RHPTRCID_CMD_EXEC_SYNC_NOT_INTERESTED,"d",pid);
	}
	
	RHP_UNLOCK(&_rhp_cmd_exec_lock);
	return;
}

int rhp_cmd_exec_init()
{
  _rhp_mutex_init("CEX",&(_rhp_cmd_exec_lock));

	RHP_TRC(0,RHPTRCID_CMD_EXEC_INIT,"");
  return 0;
}

int rhp_cmd_exec_cleanup()
{
  _rhp_mutex_destroy(&(_rhp_cmd_exec_lock));
	RHP_TRC(0,RHPTRCID_CMD_EXEC_CLEANUP,"");
  return 0;
}

int rhp_file_read_line(int fd,char** line_r)
{
	int err = -EINVAL;
#define RHP_DNS_PXY_READ_LEN		4
	int n = 0;
	char *line = NULL,*p,*endp;
	int line_len;

	line = (char*)_rhp_malloc(RHP_DNS_PXY_READ_LEN);
	if( line == NULL ){
		RHP_BUG("");
		return -ENOMEM;
	}
	memset(line,0,RHP_DNS_PXY_READ_LEN);
	p = line;
	endp = p + RHP_DNS_PXY_READ_LEN;
	line_len = RHP_DNS_PXY_READ_LEN;

	while( 1 ){

		int n2;

		if( p >= endp ){

			char* tmp = line;

			line = (char*)_rhp_malloc(line_len*2);
			if( line == NULL ){
				RHP_BUG("");
				err = -ENOMEM;
				goto error;
			}

			memset(line,0,line_len*2);
			memcpy(line,tmp,line_len);

			p = line + line_len;
			line_len = line_len*2;
			endp = line + line_len;

			_rhp_free(tmp);
		}

		n2 = read(fd,p,1);
		if( n2 < 0 ){

			err = -errno;
			goto error;

		}else if( n2 == 0 ){

			*p = '\0';
			n++;
			*line_r = line;
			line = NULL;

			err = RHP_STATUS_EOF;
			goto error;
		}

		if( *p == '\n' ){
			*p = '\0';
			n++;
			break;
		}

		p++;
		n++;
	}

	*line_r = line;

	return n;

error:
	if( line ){
		_rhp_free(line);
	}
	return err;
}

int rhp_file_read_data(char* file_path_name,int buf_len,u8* buf)
{
	int err = -EINVAL;
	int fd = -1;
	ssize_t n = 0, n2 = 0;
	u8* p = buf;

	fd = open(file_path_name,O_RDONLY);
	if( fd < 0 ){
		err = -errno;
		goto error;
	}

	while( 1 ){

		n = read(fd,p,(buf_len - n2));
		if( n < 0 ){

			err = -errno;
			goto error;

		}else if( n == 0 ){
			break;
		}

		n2 += n;
		if( n2 >= buf_len ){
			break;
		}

		p += n;
	}

	if( n2 != buf_len ){
		err = -EMSGSIZE;
		goto error;
	}

	close(fd);

	return 0;

error:
	if( fd >= 0 ){
		close(fd);
	}
	return err;
}

int rhp_file_exists(char* file_path_name)
{
	int fd = -1;

	fd = open(file_path_name,O_RDONLY);
	if( fd < 0 ){
		return -errno;
	}

	close(fd);
	return 0;
}

int rhp_file_copy(char* src_file_path_name,char* dst_file_path_name,mode_t dst_mode)
{
	int err = -EINVAL;
	int src_fd = -1,dst_fd = -1;
	int n = 0;

  RHP_TRC(0,RHPTRCID_FILE_COPY,"ss",src_file_path_name,dst_file_path_name);

  if( !strcmp(src_file_path_name,dst_file_path_name) ){
  	RHP_BUG("");
  	return -EINVAL;
  }

	src_fd = open(src_file_path_name,O_RDONLY);
	if( src_fd < 0 ){
		err = -errno;
		RHP_BUG("%d",err);
		goto error;
	}

	dst_fd = open(dst_file_path_name,(O_WRONLY | O_CREAT),dst_mode);
	if( dst_fd < 0 ){
		err = -errno;
		RHP_BUG("%d",err);
		goto error;
	}

	{
#define RHP_FILE_COPY_READ_SIZE		512
		u8 r_buf[RHP_FILE_COPY_READ_SIZE];

		while( (n = read(src_fd,r_buf,RHP_FILE_COPY_READ_SIZE)) > 0 ){

			u8* fpt = r_buf;

			while( n > 0 ){

				int c = write(dst_fd,fpt,n);
				if( c < 0 ){
					err = -errno;
					RHP_BUG("%d",err);
					goto error;
				}

				n -= c;
				fpt += c;
			}
		}
	}

	close(dst_fd);
	close(src_fd);

  RHP_TRC(0,RHPTRCID_FILE_COPY_RTRN,"ss",src_file_path_name,dst_file_path_name);
	return 0;

error:
	if( dst_fd > -1 ){
		close(dst_fd);
	}
	if( src_fd > -1 ){
		close(src_fd);
	}
  unlink(dst_file_path_name);
  RHP_TRC(0,RHPTRCID_FILE_COPY_ERR,"ssE",src_file_path_name,dst_file_path_name,err);
	return err;
}

int rhp_file_write(char* file_path,u8* buf,int buf_len, mode_t fmode)
{
	int err = -EINVAL;
	int dst_fd = -1;
	u8* fpt = buf;
	int n = buf_len;

  RHP_TRC(0,RHPTRCID_FILE_WRITE,"sxd",file_path,buf,buf_len);

  unlink(file_path);

	dst_fd = open(file_path,(O_WRONLY | O_CREAT),fmode);
	if( dst_fd < 0 ){
		err = -errno;
		RHP_BUG("%d",err);
		goto error;
	}

	while( n > 0 ){

		int c = write(dst_fd,fpt,n);
		if( c < 0 ){
			err = -errno;
			RHP_BUG("%d",err);
			goto error;
		}

		n -= c;
		fpt += c;
	}

	fchmod(dst_fd,fmode);

	close(dst_fd);

  RHP_TRC(0,RHPTRCID_FILE_WRITE_RTRN,"sxd",file_path,buf,buf_len);
	return 0;

error:
	if( dst_fd > -1 ){
		close(dst_fd);
	}
  unlink(file_path);

  RHP_TRC(0,RHPTRCID_FILE_WRITE_ERR,"sxdE",file_path,buf,buf_len,err);
	return err;
}

int rhp_str_to_vpn_unique_id(char* str,u8* unique_id_r)
{
	int slen = strlen(str);
  char* endp;
  char bc[3];
  int i;

  RHP_TRC(0,RHPTRCID_STR_TO_VPN_UNIQUE_ID,"sx",str,unique_id_r);

	if( slen == 34 ){

		if( str[0] != '0' || str[1] != 'x' ){
			goto error;
		}
		str += 2;

	}else if( slen == 32 ){
		// OK
	}else{
		goto error;
	}

	for( i = 0; i < 16; i++ ){

		bc[0] = *str;
		bc[1] = *(str + 1);
		bc[2] = '\0';

		unique_id_r[i] = (u8)strtol(bc,&endp,16);
		if( *endp != '\0' ){
			goto error;
		}

		str += 2;
	}

  RHP_TRC(0,RHPTRCID_STR_TO_VPN_UNIQUE_ID_RTRN,"sp",str,16,unique_id_r);
	return 0;

error:
	RHP_TRC(0,RHPTRCID_STR_TO_VPN_UNIQUE_ID_ERR,"sx",str,unique_id_r);
	return -EINVAL;
}

int rhp_str_to_mac(char* str,u8* mac_r)
{
	int slen = strlen(str);
  char* endp;
  char bc[3];
  int i;

	if( slen != 17 ){
		goto error;
	}

	for( i = 0; i < 6 ; i++ ){

		bc[0] = *str;
		bc[1] = *(str + 1);
		bc[2] = '\0';

		mac_r[i] = (u8)strtol(bc,&endp,16);
		if( *endp != '\0' ){
			goto error;
		}

		str += 3;
	}

	return 0;

error:
	return -EINVAL;
}

u8* rhp_bin_pattern(u8* buf,int buf_len,u8* pattern,int pattern_len)
{
	u8* p = (u8*)buf;
	u8* end_p = buf + buf_len;
	u8 *b, *pt;
	u8* pt_end_p = pattern + pattern_len;

	if( !pattern_len ){
		return buf;
	}

	while( p < end_p ){

		b = p;
		pt = pattern;

		while( (b < end_p) && (pt < pt_end_p) ){

			if( *b != *pt ){
				break;
			}

			b++;
			pt++;
		}

		if( pt == pt_end_p ){
			return p;
		}

		p++;
	}

	return NULL;
}



#define RHP_HTTP_URL_PRS_INIT					0
#define RHP_HTTP_URL_PRS_HOSTNAME			1
#define RHP_HTTP_URL_PRS_PORT					2
#define RHP_HTTP_URL_PRS_PATH					3
#define RHP_HTTP_URL_PRS_END					4
#define RHP_HTTP_URL_PRS_HOSTNAME_V6	5
int rhp_http_url_parse(char* url,char** hostname_r,char** port_r,char** path_r)
{
	int err = -EINVAL;
	size_t url_len = strlen(url);
	char *p,*p2,*hostname = NULL,*port = NULL,*path = NULL;
	size_t i;
	int state = RHP_HTTP_URL_PRS_INIT;
	size_t head_len = strlen("http://");
	int err_pos = -1;

	if( url_len <= head_len ){
		err_pos = 1;
		err = -EINVAL;
		goto error;
	}

	if( url[0] != 'h' || url[1] != 't' || url[2] != 't' || url[3] != 'p' ||
			url[4] != ':' || url[5] != '/' || url[6] != '/' ){
		err_pos = 2;
		err = -EINVAL;
		goto error;
	}

	p = url + head_len;
	url_len -= head_len;
	p2 = p;
	state = RHP_HTTP_URL_PRS_HOSTNAME;

	for( i = 0; i < (url_len + 1); i++ ){

		size_t p_len = 0;

		if( *p == ']' ){

			if( state != RHP_HTTP_URL_PRS_HOSTNAME_V6 ){
				err = -EINVAL;
				err_pos = 3;
				goto error;
			}

			state = RHP_HTTP_URL_PRS_HOSTNAME;

		}else if( state == RHP_HTTP_URL_PRS_HOSTNAME_V6 ){

			if( !(*p >= '0' && *p <= '9') && (*p != ':') &&
					!(*p >= 'a' && *p <= 'f') && !(*p >= 'A' && *p <= 'F') ){
				err = -EINVAL;
				err_pos = 4;
				goto error;
			}

		}else if( *p == '['){

			if( state != RHP_HTTP_URL_PRS_HOSTNAME ){
				err = -EINVAL;
				err_pos = 5;
				goto error;
			}

			state = RHP_HTTP_URL_PRS_HOSTNAME_V6;

		}else if( *p == ':' ){

			if( state != RHP_HTTP_URL_PRS_HOSTNAME ){
				err = -EINVAL;
				err_pos = 6;
				goto error;
			}

			p_len = p - p2 + 1;

			if( p_len <= 1 ){
				err = -EINVAL;
				err_pos = 7;
				goto error;
			}

			hostname = (char*)_rhp_malloc(p_len);
			hostname = (char*)_rhp_malloc(p_len);
			if( hostname == NULL ){
				err = -ENOMEM;
				err_pos = 8;
				goto error;
			}

			hostname[p_len - 1] = '\0';
			memcpy(hostname,p2,(p_len - 1));

			state = RHP_HTTP_URL_PRS_PORT;
			p2 = p + 1;

		}else if( *p == '/' || *p == '\0' ){

			if( state != RHP_HTTP_URL_PRS_HOSTNAME && state != RHP_HTTP_URL_PRS_PORT ){
				err_pos = 9;
				err = -EINVAL;
				goto error;
			}

			p_len = p - p2 + 1;

			if( p_len <= 1 ){
				err = -EINVAL;
				err_pos = 10;
				goto error;
			}

			if( state == RHP_HTTP_URL_PRS_HOSTNAME ){

				hostname = (char*)_rhp_malloc(p_len);
				if( hostname == NULL ){
					err = -ENOMEM;
					err_pos = 11;
					goto error;
				}

				hostname[p_len - 1] = '\0';
				memcpy(hostname,p2,(p_len - 1));

			}else if( state == RHP_HTTP_URL_PRS_PORT ){

				port = (char*)_rhp_malloc(p_len);
				if( port == NULL ){
					err = -ENOMEM;
					err_pos = 12;
					goto error;
				}

				port[p_len - 1] = '\0';
				memcpy(port,p2,(p_len - 1));
			}

			{
				p_len = (url + url_len + head_len) - p;

				if( p_len > 1 ){

					p2 = p;

					p_len++;

					path = (char*)_rhp_malloc(p_len);
					if( path == NULL ){
						err = -ENOMEM;
						err_pos = 13;
						goto error;
					}

					path[p_len - 1] = '\0';
					memcpy(path,p2,(p_len - 1));
				}
			}

			state = RHP_HTTP_URL_PRS_END;
			break;
		}

		p++;
	}

	if( state != RHP_HTTP_URL_PRS_END ){
		err_pos = 14;
		err = -EINVAL;
		goto error;
	}

	if( hostname == NULL ){

		err = -EINVAL;
		err_pos = 15;
		goto error;

	}else if( hostname[0] == '[' ){

		size_t ht_len = strlen(hostname);

		if( ht_len <= 1 || hostname[ht_len -1] != ']' ){
			err = -EINVAL;
			err_pos = 16;
			goto error;
		}

		hostname[ht_len - 1] = '\0';
		memmove(hostname,(hostname + 1),(ht_len - 1)); // including '\0'.
	}

	if( path == NULL ){

		path = (char*)_rhp_malloc(2);
		if( path == NULL ){
			err = -ENOMEM;
			err_pos = 17;
			goto error;
		}

		path[0] = '/';
		path[1] = '\0';
	}

	if( port ){

		size_t pt_len = strlen(port);

		if( port[0] == '0' ){
			err = -EINVAL;
			err_pos = 18;
			goto error;
		}

		for(i = 0; i < pt_len; i++){
			if( port[i] < '0' || port[i] > '9' ){
				err = -EINVAL;
				err_pos = 19;
				goto error;
			}
		}
	}


  RHP_TRC(0,RHPTRCID_HTTP_URL_PARSE_OK,"ssss",url,hostname,port,path);

  if( hostname_r && port_r && path_r ){

		*hostname_r = hostname;
		*port_r = port;
		*path_r = path;

	}else{

		_rhp_free(hostname);

		if( port ){
			_rhp_free(port);
		}

		_rhp_free(path);
	}

	return 0;

error:
	if( hostname ){
		_rhp_free(hostname);
	}
	if( port ){
		_rhp_free(port);
	}
	if( path ){
		_rhp_free(path);
	}

  RHP_TRC(0,RHPTRCID_HTTP_URL_PARSE_ERR,"sd",url,err_pos);
	return err;
}



struct _rhp_dns_rslv_ctx {

	u8 tag[4]; // '#DNV'

	char* peer_fqdn;

	int addr_family;

	void (*callback)(void* cb_ctx0,void* cb_ctx1,int err,int res_addrs_num,rhp_ip_addr* res_addrs);
	void* cb_ctx0;
	void* cb_ctx1;
};
typedef struct _rhp_dns_rslv_ctx	rhp_dns_rslv_ctx;

static rhp_atomic_t _rhp_dns_rslv_pend_num;

long rhp_dns_resolve_pend_num()
{
	long pend_num =	_rhp_atomic_read(&_rhp_dns_rslv_pend_num);
  RHP_TRC(0,RHPTRCID_DNS_RESOLVE_PEND_NUM,"f",pend_num);
	return pend_num;
}

static void rhp_dns_rslv_task(int worker_index,void *cb_ctx)
{
	int err = -EINVAL;
	rhp_dns_rslv_ctx* task_ctx = (rhp_dns_rslv_ctx*)cb_ctx;
	struct addrinfo hints;
	struct addrinfo *result = NULL,*rp = NULL;
#define RHP_DNS_RSLV_RES_NUM	4
	rhp_ip_addr peer_res_addr[RHP_DNS_RSLV_RES_NUM];
	int res_nums = 0;
	int n = 0;

	RHP_TRC(0,RHPTRCID_DNS_RSLV_TASK,"xs",task_ctx,task_ctx->peer_fqdn);

	memset(peer_res_addr,0,sizeof(rhp_ip_addr)*RHP_DNS_RSLV_RES_NUM);

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = 0;
	hints.ai_protocol = 0;

	err = getaddrinfo(task_ctx->peer_fqdn,NULL,&hints,&result);
	if( err != 0 ){

		// err : EAI_XXXX. see man getaddrinfo and gai_strerror.

		RHP_TRC(0,RHPTRCID_DNS_RSLV_TASK_RES_FAILED,"xdsE",task_ctx,err,gai_strerror(err),-errno);
		err = -ENOENT;
		goto error;
	}

	for( rp = result; rp != NULL; rp = rp->ai_next ){

		if( n < RHP_DNS_RSLV_RES_NUM ){

			rhp_ip_addr* peer_fqdn_addr = &(peer_res_addr[n]);

			memset(peer_fqdn_addr,0,sizeof(rhp_ip_addr));

			if( rp->ai_family == task_ctx->addr_family ||
					task_ctx->addr_family == AF_UNSPEC ){

				peer_fqdn_addr->addr_family = rp->ai_family;

				if( rp->ai_family == AF_INET ){

					peer_fqdn_addr->addr.v4 = ((struct sockaddr_in*)rp->ai_addr)->sin_addr.s_addr;

				}else if( !rhp_gcfg_ipv6_disabled && rp->ai_family == AF_INET6 ){

					memcpy(peer_fqdn_addr->addr.v6,
							((struct sockaddr_in6*)rp->ai_addr)->sin6_addr.s6_addr,16);

				}else{
					RHP_TRC(0,RHPTRCID_DNS_RSLV_TASK_RES_FAILED_ADDR_FAMILY_UNKNOWN,"xd",task_ctx,rp->ai_family);
					continue;
				}

			}else{
				RHP_TRC(0,RHPTRCID_DNS_RSLV_TASK_RES_FAILED_ADDR_FAMILY_NOT_MATCHED,"xd",task_ctx,rp->ai_family);
				continue;
			}

			res_nums++;

		}else{

			if( rp->ai_family == AF_INET ){
				RHP_TRC(0,RHPTRCID_DNS_RSLV_TASK_RES_EXTRA_IPV4,"x4",task_ctx,((struct sockaddr_in*)rp->ai_addr)->sin_addr.s_addr);
			}else if( rp->ai_family == AF_INET6 ){
				RHP_TRC(0,RHPTRCID_DNS_RSLV_TASK_RES_EXTRA_IPV6,"x6",task_ctx,((struct sockaddr_in6*)rp->ai_addr)->sin6_addr.s6_addr);
			}
		}

		n++;
	}

	freeaddrinfo(result);

	if( res_nums == 0 ){
		err = -ENOENT;
		goto error;
	}


	task_ctx->callback(task_ctx->cb_ctx0,task_ctx->cb_ctx1,0,res_nums,peer_res_addr);


	RHP_TRC(0,RHPTRCID_DNS_RSLV_TASK_RTRN,"xsdd",task_ctx,task_ctx->peer_fqdn,res_nums,n);
	{
		int i;
		for( i = 0; i < RHP_DNS_RSLV_RES_NUM; i++){
			rhp_ip_addr_dump("peer_res_addr[i]",&(peer_res_addr[i]));
		}
	}

	if( task_ctx->peer_fqdn ){
		_rhp_free(task_ctx->peer_fqdn);
	}
	_rhp_free(task_ctx);

	_rhp_atomic_dec(&_rhp_dns_rslv_pend_num);

	return;

error:

	task_ctx->callback(task_ctx->cb_ctx0,task_ctx->cb_ctx1,err,0,NULL);

	if( task_ctx->peer_fqdn ){
		_rhp_free(task_ctx->peer_fqdn);
	}
	_rhp_free(task_ctx);

	_rhp_atomic_dec(&_rhp_dns_rslv_pend_num);

	RHP_TRC(0,RHPTRCID_DNS_RSLV_TASK_ERR,"xdE",task_ctx,n,err);
	return;
}

int rhp_dns_resolve(int disp_priority,char* peer_fqdn,int addr_family,
	void (*callback)(void* cb_ctx0,void* cb_ctx1,int err,int res_addrs_num,rhp_ip_addr* res_addrs),
	void* cb_ctx0,void* cb_ctx1)
{
	int err = -EINVAL;
	rhp_dns_rslv_ctx* task_ctx = NULL;
	int peer_fqdn_len;
	long pend_num;

  RHP_TRC(0,RHPTRCID_DNS_RESOLVE,"LddsYxx","WTS_DISP_LEVEL_FLAG",disp_priority,addr_family,peer_fqdn,callback,cb_ctx0,cb_ctx1);

  if( addr_family != AF_INET && addr_family != AF_INET6 &&
  		addr_family != AF_UNSPEC ){
  	RHP_BUG("%d",addr_family);
  	return -EINVAL;
  }

	if( RHP_MY_PROCESS->role != RHP_PROCESS_ROLE_MAIN ){
		RHP_BUG("");
  	err = -EINVAL;
  	goto error;
  }

	if( (pend_num =	_rhp_atomic_read(&_rhp_dns_rslv_pend_num))
			>= rhp_gcfg_dns_resolve_max_tasks ){
	  RHP_TRC(0,RHPTRCID_DNS_RESOLVE_MAX_TASKS,"sxxfd",peer_fqdn,cb_ctx0,cb_ctx1,pend_num,rhp_gcfg_dns_resolve_max_tasks);
  	err = RHP_STATUS_DNS_RSLV_MAX_TASKS_REACHED;
  	goto error;
	}

	task_ctx = (rhp_dns_rslv_ctx*)_rhp_malloc(sizeof(rhp_dns_rslv_ctx));
	if( task_ctx == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}

	memset(task_ctx,0,sizeof(rhp_dns_rslv_ctx));

	task_ctx->tag[0] = '#';
	task_ctx->tag[1] = 'D';
	task_ctx->tag[2] = 'N';
	task_ctx->tag[3] = 'V';

	peer_fqdn_len = strlen(peer_fqdn);
	task_ctx->peer_fqdn = (char*)_rhp_malloc(peer_fqdn_len + 1);
	if( task_ctx->peer_fqdn == NULL ){
		RHP_BUG("");
		err = -ENOMEM;
		goto error;
	}
	memcpy(task_ctx->peer_fqdn,peer_fqdn,peer_fqdn_len);
	task_ctx->peer_fqdn[peer_fqdn_len] = '\0';

	task_ctx->addr_family = addr_family;

	task_ctx->callback = callback;
	task_ctx->cb_ctx0 = cb_ctx0;
	task_ctx->cb_ctx1 = cb_ctx1;

	_rhp_atomic_inc(&_rhp_dns_rslv_pend_num);

	err = rhp_wts_add_task(RHP_WTS_DISP_RULE_MISC_BLOCKING,
					disp_priority,NULL,rhp_dns_rslv_task,(void*)task_ctx);

	if( err ){
		RHP_BUG("%d",err);
		_rhp_atomic_dec(&_rhp_dns_rslv_pend_num);
		goto error;
	}


  RHP_TRC(0,RHPTRCID_DNS_RESOLVE_RTRN,"sxx",peer_fqdn,cb_ctx0,cb_ctx1);
	return 0;

error:
	if( task_ctx ){
		if( task_ctx->peer_fqdn ){
			_rhp_free(task_ctx->peer_fqdn);
		}
		_rhp_free(task_ctx);
	}
  RHP_TRC(0,RHPTRCID_DNS_RESOLVE_ERR,"sxxE",peer_fqdn,cb_ctx0,cb_ctx1,err);
	return err;
}

int rhp_dns_resolve_init()
{
	_rhp_atomic_init(&_rhp_dns_rslv_pend_num);
	return 0;
}

int rhp_dns_resolve_cleanup()
{
	_rhp_atomic_destroy(&_rhp_dns_rslv_pend_num);
	return 0;
}



static __thread char _rhp_ipv6_string_buf[INET6_ADDRSTRLEN + 1];

char* rhp_ipv6_string(u8* addr)
{
	struct in6_addr sin6;

	memset(_rhp_ipv6_string_buf,'\0',(INET6_ADDRSTRLEN + 1));
	memcpy(sin6.s6_addr,addr,16);

	inet_ntop(AF_INET6,(const void*)&sin6,_rhp_ipv6_string_buf,INET6_ADDRSTRLEN);

	return _rhp_ipv6_string_buf;
}

char* rhp_ipv6_string2(u8* addr,char* str_r)
{
	struct in6_addr sin6;

	memset(str_r,'\0',(INET6_ADDRSTRLEN + 1));
	memcpy(sin6.s6_addr,addr,16);

	inet_ntop(AF_INET6,(const void*)&sin6,str_r,INET6_ADDRSTRLEN);

	return str_r;
}

char* rhp_ip_port_string(rhp_ip_addr* ip_addr)
{
	int ret_len;
	char* ret;

	if( ip_addr->addr_family == AF_INET ){

		ret_len = strlen("255.255.255.255:65535") + 1;
		ret = (char*)_rhp_malloc(ret_len);
		if( ret == NULL ){
			RHP_BUG("");
			return NULL;
		}
		memset(ret,0,ret_len);

	  snprintf(ret,ret_len,"%d.%d.%d.%d:%d",
	  		ip_addr->addr.raw[0],ip_addr->addr.raw[1],ip_addr->addr.raw[2],ip_addr->addr.raw[3],
	  		ntohs(ip_addr->port));

	}else if( ip_addr->addr_family == AF_INET6 ){

		int v6_addr_len;

		ret_len = INET6_ADDRSTRLEN + strlen(".65535") + 1;
		ret = (char*)_rhp_malloc(ret_len);
		if( ret == NULL ){
			RHP_BUG("");
			return NULL;
		}
		memset(ret,0,ret_len);

		if( rhp_ipv6_string2(ip_addr->addr.v6,ret) == NULL ){
			RHP_BUG("");
			return NULL;
		}

		v6_addr_len = strlen(ret);

	  snprintf((ret + v6_addr_len),(ret_len - v6_addr_len),".%d",ntohs(ip_addr->port));

	}else{

		return NULL;
	}

	return ret;
}

int rhp_ip_str2addr(int addr_family,char* ip_addr_str,rhp_ip_addr* ip_r)
{
	int err = -EINVAL;
	int if_index = 0;
	union {
		struct in_addr 	v4_addr;
		struct in6_addr v6_addr;
	} v_addr;
	char* linklocal_ifname = NULL;

	if( inet_pton(AF_INET,(const char*)ip_addr_str,(void*)&(v_addr.v4_addr)) != 1 ){

		if( addr_family == AF_INET ){
			err = -EINVAL;
			goto error;
		}

		linklocal_ifname = strstr((const char*)ip_addr_str,"%");
		if( linklocal_ifname ){

			*linklocal_ifname = '\0';

			if_index = if_nametoindex(linklocal_ifname + 1);
		}

		if( inet_pton(AF_INET6,(const char*)ip_addr_str,(void*)&(v_addr.v6_addr)) != 1 ){
			err = -EINVAL;
			goto error;
		}

		ip_r->addr_family = AF_INET6;
		memcpy((u8*)(ip_r->addr.v6),(u8*)(v_addr.v6_addr.s6_addr),16);
		if( rhp_ipv6_is_linklocal((u8*)(v_addr.v6_addr.s6_addr)) ){
			ip_r->ipv6_scope_id = (u32)if_index;
		}else{
			ip_r->ipv6_scope_id = 0;
		}

	}else{

		if( addr_family == AF_INET6 ){
			err = -EINVAL;
			goto error;
		}

		ip_r->addr_family = AF_INET;
		ip_r->addr.v4 = v_addr.v4_addr.s_addr;
	}

	err = 0;

error:
	if( linklocal_ifname ){
		*linklocal_ifname = '%';
	}

  RHP_TRC(0,RHPTRCID_IP_STR2ADDR,"LdsxE","AF",addr_family,ip_addr_str,ip_r,err);
  rhp_ip_addr_dump("ip_r",ip_r);
  return err;
}

#define RHP_BIN2STR_MAX_LEN		512
// res_len_r: including '\0'.
int rhp_bin2str_dump(int bin_len,u8* bin,int scale,int* res_len_r,char** res_r)
{
	int err = -EINVAL;
  int i, n = 0;
  int res_len = 0,res_rem = RHP_BIN2STR_MAX_LEN;
  char *res = NULL,*p;
  u8* d = bin;

  res = (char*)_rhp_malloc(RHP_BIN2STR_MAX_LEN);
  if( res == NULL ){
  	RHP_BUG("");
  	err = -ENOMEM;
  	goto error;
  }
  memset(res,0,RHP_BIN2STR_MAX_LEN);
  p = res;

  if( scale ){

    n = snprintf(p,res_rem,"*0 *1 *2 *3 *4 *5 *6 *7 *8 *9 *A *B *C *D *E *F\n");
		if( n >= res_rem ){
			goto end;
		}
    res_rem -= n;
    res_len += n;
    p += n;
  }

  if( bin_len <= 0 || bin == NULL ){
  	n = snprintf(p,res_rem,"--NO DATA--\n");
		if( n >= res_rem ){
			goto end;
		}
    res_rem -= n;
    res_len += n;
    p += n;
    goto end;
  }

  for(i = 0; i < bin_len; i++){

    int pd;

    if( i && (i % 16) == 0 ){

  		n = snprintf(p,res_rem,"\n");
  		if( n >= res_rem ){
  			goto end;
  		}
      res_rem -= n;
      res_len += n;
      p += n;
    }

    pd = ((*(int *) d) & 0x000000FF);

		n = snprintf(p,res_rem,"%02x:",pd);
		if( n >= res_rem ){
			goto end;
		}
    res_rem -= n;
    res_len += n;
    p += n;

    d++;
  }

end:
	*res_r = res;
	*res_len_r = res_len + 1;

  return 0;

error:
	return err;
}


u8* rhp_proto_ip_v6_upper_layer(rhp_proto_ip_v6* ip6h,u8* end,
		int protos_num,u8* protos,u8* proto_r)
{
	u8* p = (u8*)(ip6h + 1);
	rhp_proto_ip_v6_exthdr* exthdr = (rhp_proto_ip_v6_exthdr*)p;
	u8 next_hdr;
	u8* tail = p + ntohs(ip6h->payload_len);
	int i;

	if( p >= end || tail > end ){
		RHP_TRC_FREQ(0,RHPTRCID_PROTO_IP_V6_UPPER_LAYER_ERR_1,"bpxxx",ip6h->next_header,sizeof(rhp_proto_ip_v6),ip6h,p,tail,end);
		return NULL;
	}

	next_hdr = ip6h->next_header;

	while( p <= tail ){

		for( i = 0; i < protos_num; i++ ){

			if( next_hdr == protos[i] ){

				if( proto_r ){
					*proto_r = next_hdr;
				}

				RHP_TRC_FREQ(0,RHPTRCID_PROTO_IP_V6_UPPER_LAYER_SPECIFIED_FOUND,"bpxxx",next_hdr,sizeof(rhp_proto_ip_v6),ip6h,p,tail,end);
				return p;
			}
		}

		switch( next_hdr ){

		case RHP_PROTO_IP_IPV6_HOP_BY_HOP:
		case RHP_PROTO_IP_IPV6_ROUTE:
		case RHP_PROTO_IP_IPV6_OPTS:
		case RHP_PROTO_IP_IPV6_SHIM6:
		case RHP_PROTO_IP_IPV6_HIP:

			if( (u8*)(exthdr + 1) >= tail ){
				RHP_TRC_FREQ(0,RHPTRCID_PROTO_IP_V6_UPPER_LAYER_ERR_2,"bpxxx",next_hdr,sizeof(rhp_proto_ip_v6),ip6h,p,tail,end);
				return NULL;
			}

			p = ((u8*)exthdr) + 8 + exthdr->len*8;
			if( p > tail ){
				RHP_TRC_FREQ(0,RHPTRCID_PROTO_IP_V6_UPPER_LAYER_ERR_3,"bpxxx",next_hdr,sizeof(rhp_proto_ip_v6),ip6h,p,tail,end);
				return NULL;
			}

			next_hdr = exthdr->next_header;

			break;

/*
		case RHP_PROTO_IP_IPV6_FRAG:
		case RHP_PROTO_IP_NO_NEXT_HDR:
		case RHP_PROTO_IP_ESP:
		case RHP_PROTO_IP_AH:
*/
		default:

			if( protos_num == 0 ){

				if( proto_r ){
					*proto_r = next_hdr;
				}

				RHP_TRC_FREQ(0,RHPTRCID_PROTO_IP_V6_UPPER_LAYER_FOUND,"bpxxx",next_hdr,sizeof(rhp_proto_ip_v6),ip6h,p,tail,end);
				return p;
			}

			RHP_TRC_FREQ(0,RHPTRCID_PROTO_IP_V6_UPPER_LAYER_SPECIFIED_NO_ENT,"pxxx",sizeof(rhp_proto_ip_v6),ip6h,p,tail,end);
			return NULL;
		}
	}

	RHP_TRC_FREQ(0,RHPTRCID_PROTO_IP_V6_UPPER_LAYER_NO_ENT,"pxxx",sizeof(rhp_proto_ip_v6),ip6h,p,tail,end);
	return NULL;
}

int rhp_proto_ip_v6_frag(rhp_proto_ip_v6* ip6h,u8* end,u8* proto_r,u8** frag_data)
{
	u8* p = (u8*)(ip6h + 1);
	rhp_proto_ip_v6_exthdr* exthdr = (rhp_proto_ip_v6_exthdr*)p;
	u8 next_hdr;
	u8* tail = p + ntohs(ip6h->payload_len);

	if( p >= end || tail > end ){
		return 0;
	}

	next_hdr = ip6h->next_header;

	while( p <= tail ){

		switch( next_hdr ){

		case RHP_PROTO_IP_IPV6_FRAG:
		{
			rhp_proto_ip_v6_fraghdr* fraghdr = (rhp_proto_ip_v6_fraghdr*)p;

			if( (u8*)(fraghdr + 1) >= tail ){
				return 0;
			}

			if( proto_r ){
				*proto_r = fraghdr->next_header;
			}

			if( frag_data ){
				*frag_data = (u8*)(fraghdr + 1);
			}

			return 1;
		}

		case RHP_PROTO_IP_IPV6_HOP_BY_HOP:
		case RHP_PROTO_IP_IPV6_ROUTE:
		case RHP_PROTO_IP_IPV6_OPTS:
		case RHP_PROTO_IP_IPV6_SHIM6:
		case RHP_PROTO_IP_IPV6_HIP:

			if( (u8*)(exthdr + 1) >= tail ){
				return 0;
			}

			p = ((u8*)exthdr) + 8 + exthdr->len*8;
			if( p > tail ){
				return 0;
			}

			next_hdr = exthdr->next_header;

			break;

		default:
			return 0;
		}
	}

	return 0;
}

