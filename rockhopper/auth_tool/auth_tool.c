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
#include <asm/types.h>

#include "rhp_trace.h"
#include "rhp_version.h"
#include "rhp_misc.h"
#include "rhp_crypto.h"
#include "rhp_auth_tool.h"
#include "rhp_protocol.h"

// Dummy object for "rhp_trace.h" that is referenced 
// by librhpcrypto.so(OpenSSL version). RHP_PROCESS_ROLE_XXX
int rhp_process_my_role = 0; 

struct __auth_tool_args {

#define RHP_AUTH_TOOL_TYPE_IKEV2_PSK					1	
#define RHP_AUTH_TOOL_TYPE_ADMIN_KEY					2	
	int type;
	
  char* raw_password;
  char* id;

  int xml;
  char* rlm_id;
};
static struct __auth_tool_args _auth_tool_args;


static void _print_usage()
{
  printf(" Usage: auth_tool [-h] -t type -p password [-n id] [-v]\n");
}

static void _print_usage_detail()
{
  if( !_auth_tool_args.xml ){
		printf(
				"[ Usage ]\n"
				" auth_tool [-h] -t type -p password [-n id] [-v]\n"
				"   -t type : Generated key type. \"ikev2_psk\" or \"rockhopper\". \n"
				"   -p password : Raw PSK or password.\n"
				"   -n id : User ID or name, if needed.\n"
				"   -v : Show version.\n"
				"   -x : Output XML format.\n"
				"   -r : Realm ID for -x.\n"
				"   -h : Show help infomation.\n");
  }
}

static char* _auth_tool_args_rlm_id_def = "any";

static int _parse_args(int argc, char *argv[])
{
  int c;
  extern char *optarg;

  memset(&_auth_tool_args,0,sizeof(_auth_tool_args));
  _auth_tool_args.type = 0;
  _auth_tool_args.raw_password = NULL;
	_auth_tool_args.xml = 0;
	_auth_tool_args.rlm_id = _auth_tool_args_rlm_id_def;

  while( 1 ){

    c = getopt(argc,argv,"ht:p:n:vxr:");

    if( c == -1 ){
      break;
    }

    switch( c ){

    case 'h':
    	_print_usage_detail();
    	goto out;

    case 'v':
    	_rhp_print_version(stdout,NULL,1);
    	goto out;
        
    case 'p':
    	_auth_tool_args.raw_password = optarg;
    	break;

    case 'n':
    	_auth_tool_args.id = optarg;
    	break;
        
    case 't':

    	if( !strcmp(optarg,"ikev2_psk") ){
    		_auth_tool_args.type = RHP_AUTH_TOOL_TYPE_IKEV2_PSK;
    	}else if( !strcmp(optarg,"rockhopper") ){
    		_auth_tool_args.type = RHP_AUTH_TOOL_TYPE_ADMIN_KEY;
    	}else{
    		printf("-t : Unknown option(%s). \n",optarg);
     		goto error;
     	}

    	break;

    case 'x':
    	_auth_tool_args.xml = 1;
    	break;
    
    case 'r':
    	_auth_tool_args.rlm_id = optarg;
    	break;

    default:
    	goto error;
    }
  }

  if( _auth_tool_args.type == 0 ){
    printf("-t Generated key type not specified.\n");
    goto error;
  }
  
  if( _auth_tool_args.raw_password == NULL ){
    printf("-p password not specified.\n");
    goto error;
  }

  if( _auth_tool_args.type == RHP_AUTH_TOOL_TYPE_ADMIN_KEY &&
  		_auth_tool_args.id == NULL ){
    printf("-n id not specified.\n");
    goto error;
  }
  
  return 0;

error:
    _print_usage();
out:
    return -EINVAL;
}

#define RHP_AUTH_TOOL_IKEV2_PSK_PRF_METHODS	3

static int _ikev2_psk_prf_method[RHP_AUTH_TOOL_IKEV2_PSK_PRF_METHODS] = {
		RHP_PROTO_IKE_TRANSFORM_ID_PRF_HMAC_MD5,
		RHP_PROTO_IKE_TRANSFORM_ID_PRF_HMAC_SHA1,
		RHP_PROTO_IKE_TRANSFORM_ID_PRF_AES128_CBC};

static char* _ikev2_psk_prf_method_str[RHP_AUTH_TOOL_IKEV2_PSK_PRF_METHODS] = {
		"hmac-md5",
		"hmac-sha1",
		"aes128-cbc"};

int main(int argc, char *argv[])
{
	int err;
	
	err = _parse_args(argc,argv);	
	if( err ){
		return err;
	}
	
	if( _auth_tool_args.type == RHP_AUTH_TOOL_TYPE_IKEV2_PSK ){

	  rhp_crypto_prf* prf = NULL;
	  u8* hashed_key = NULL;
	  int hashed_key_len = 0;
	  unsigned char* res_text = NULL;
	  int i;

	  if( !_auth_tool_args.xml ){
	  	printf(" ==IKEv2 PSK== : \n\n ");
	  }
	  
	  for( i = 0; i < RHP_AUTH_TOOL_IKEV2_PSK_PRF_METHODS;i++ ){
	  	
	  	prf  = rhp_crypto_prf_alloc(_ikev2_psk_prf_method[i]);
	  	if( prf == NULL ){
	  	  if( !_auth_tool_args.xml ){
	  	  	printf("Unkown PRF method : %d(%s)\n",_ikev2_psk_prf_method[i],_ikev2_psk_prf_method_str[i]);
	  	  }
	  		continue;
	  	}

	  	hashed_key_len = prf->get_output_len(prf);

	  	hashed_key = (u8*)_rhp_malloc(hashed_key_len);
	  	if( hashed_key == NULL ){
	  	  if( !_auth_tool_args.xml ){
	  	  	printf("No memory\n");
	  	  }
	  		rhp_crypto_prf_free(prf);
	  		continue;
	  	}

	  	if( prf->set_key(prf,(unsigned char*)_auth_tool_args.raw_password,strlen((char*)_auth_tool_args.raw_password)) ){
	  	  if( !_auth_tool_args.xml ){
	  	  	printf("prf->set_key() failed. %s\n",_ikev2_psk_prf_method_str[i]);
	  	  }
	  		rhp_crypto_prf_free(prf);
	  		_rhp_free(hashed_key);
	  		continue;
	  	}

	  	if( prf->compute(prf,(unsigned char*)RHP_PROTO_IKE_AUTH_KEYPAD,strlen(RHP_PROTO_IKE_AUTH_KEYPAD),
        hashed_key,hashed_key_len) ){
	  	  if( !_auth_tool_args.xml ){
	  	  	printf("prf->compute() failed. %s\n",_ikev2_psk_prf_method_str[i]);
	  	  }
	  		rhp_crypto_prf_free(prf);
	  		_rhp_free(hashed_key);
	  		continue;
	  	}

	  	err = rhp_base64_encode(hashed_key,hashed_key_len,&res_text);
	  	if( err ){
	  	  if( !_auth_tool_args.xml ){
	  	  	printf("rhp_base64_encode() failed. %d %s\n",err,_ikev2_psk_prf_method_str[i]);
	  	  }
	  	}else{
	  	  if( !_auth_tool_args.xml ){
	  	  	printf("\n%s : %s\n",_ikev2_psk_prf_method_str[i],res_text);
	  	  }else{
	  	  	printf("<my_psk prf_method=\"%s\" hashed_key=\"%s\"/>\n",_ikev2_psk_prf_method_str[i],res_text);
	  	  	printf("<peer_psk prf_method=\"%s\" hashed_key=\"%s\"/>\n\n",_ikev2_psk_prf_method_str[i],res_text);
	  	  }
	  	}
	  	
  		rhp_crypto_prf_free(prf);
  		_rhp_free(hashed_key);
  		_rhp_free(res_text);
	  }
	  
	}else if( _auth_tool_args.type == RHP_AUTH_TOOL_TYPE_ADMIN_KEY ){

	  rhp_crypto_prf* prf = NULL;
	  u8* hashed_key = NULL;
	  int hashed_key_len = 0;
	  unsigned char* res_text = NULL;
	  int i;

	  if( !_auth_tool_args.xml ){
	  	printf(" ==Admin Key== : \n\n ");
	  }
	  
	  for( i = 0; i < RHP_AUTH_TOOL_IKEV2_PSK_PRF_METHODS;i++ ){
	  	
	  	prf  = rhp_crypto_prf_alloc(_ikev2_psk_prf_method[i]);
	  	if( prf == NULL ){
	  	  if( !_auth_tool_args.xml ){
	  	  	printf("Unkown PRF method : %d(%s)\n",_ikev2_psk_prf_method[i],_ikev2_psk_prf_method_str[i]);
	  	  }
	  		continue;
	  	}

			err = _rhp_auth_hashed_auth_key(prf,(unsigned char*)_auth_tool_args.id,strlen(_auth_tool_args.id)+1,
						 (unsigned char*)_auth_tool_args.raw_password,strlen(_auth_tool_args.raw_password)+1,&hashed_key,&hashed_key_len);

	  	err = rhp_base64_encode(hashed_key,hashed_key_len,&res_text);
	  	if( err ){
	  	  if( !_auth_tool_args.xml ){
	  	  	printf("rhp_base64_encode() failed. %d %s\n",err,_ikev2_psk_prf_method_str[i]);
	  	  }
	  	}else{
	  	  if( !_auth_tool_args.xml ){
	  	  	printf("\n%s : %s\n",_ikev2_psk_prf_method_str[i],res_text);
	  	  }else{
	  	  	printf("<admin id=\"%s\" prf_method=\"%s\" hashed_key=\"%s\" vpn_realm=\"%s\"/>\n",
	  	  			_auth_tool_args.id,_ikev2_psk_prf_method_str[i],res_text,_auth_tool_args.rlm_id);
	  	  }
	  	}
	  	
  		rhp_crypto_prf_free(prf);
  		_rhp_free(hashed_key);
  		_rhp_free(res_text);
	  }
		
		
	}else{
    _print_usage();
    return -EINVAL;
	}
	
	return EXIT_SUCCESS;
}

#ifdef RHP_MEMORY_DBG

void* _rhp_malloc_dbg(size_t size,const char* file,int line)
{
	return malloc(size);
}

void _rhp_free_dbg(void *ptr,const char* file,int line)
{
	free(ptr);
}

void _rhp_free_zero_dbg(void *ptr,size_t size,const char* file,int line)
{
	free(ptr);
}

int rhp_mem_initialized = 0;

void rhp_mem_statistics_free(size_t size)
{
}

void rhp_mem_statistics_alloc(size_t size)
{
}

#else // RHP_MEMORY_DBG

int rhp_mem_initialized = 0;

void rhp_mem_statistics_free(size_t size)
{
}

void rhp_mem_statistics_alloc(size_t size)
{
}

#endif // RHP_MEMORY_DBG
