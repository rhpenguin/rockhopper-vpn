/*

	Copyright (C) 2009-2012 TETSUHARU HANADA <rhpenguine@gmail.com>
	All rights reserved.
	
	You can redistribute and/or modify this software under the 
	LESSER GPL version 2.1.
	See also LICENSE.txt and LICENSE_LGPL2.1.txt.

*/


#ifndef _RHP_VERSION_H_
#define _RHP_VERSION_H_

#define RHP_PRODUCT_NAME 		"Rockhopper"
#define RHP_DEV_CODE_NAME		"karakuribox"

#define RHP_VERSION_STR			"0.2"
#define RHP_VERSION					0
#define RHP_MINOR_VERSION		2

#define RHP_RELEALSE		"Nov 14, 2013"

static inline void _rhp_print_version(FILE* s,char* label,int ln)
{
	if( label ){
		fprintf(s,"%s  (%s v%s [%s:%s])%s",label,RHP_PRODUCT_NAME,RHP_VERSION_STR,RHP_DEV_CODE_NAME,RHP_RELEALSE,(ln ? "\n" : ""));
	}else{
		fprintf(s,"%s v%s [%s:%s]%s",RHP_PRODUCT_NAME,RHP_VERSION_STR,RHP_DEV_CODE_NAME,RHP_RELEALSE,(ln ? "\n" : ""));
	}
  return;
}

static inline int _rhp_print_version_mem(char* label,char* buf,int buf_len)
{
	int n;
	if( label ){
		n = snprintf(buf,buf_len,"%s  (%s v%s [%s])",label,RHP_PRODUCT_NAME,RHP_VERSION_STR,RHP_DEV_CODE_NAME);
	}else{
		n = snprintf(buf,buf_len,"%s v%s [%s]",RHP_PRODUCT_NAME,RHP_VERSION_STR,RHP_DEV_CODE_NAME);
	}
  return n;
}

#endif // _RHP_VERSION_H_

