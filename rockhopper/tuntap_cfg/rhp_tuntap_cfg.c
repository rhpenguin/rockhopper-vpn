/*

	Copyright (C) 2009-2014 TETSUHARU HANADA <rhpenguine@gmail.com>
	All rights reserved.

	You can redistribute and/or modify this software under the
	LESSER GPL version 2.1.
	See also LICENSE.txt and LICENSE_LGPL2.1.txt.

*/


/*

- /proc/sys/net/ipv6/conf/interface/... Variables:

   https://www.kernel.org/doc/Documentation/networking/ip-sysctl.txt


disable_ipv6 - BOOLEAN
	Disable IPv6 operation.  If accept_dad is set to 2, this value
	will be dynamically set to TRUE if DAD fails for the link-local
	address.
	Default: FALSE (enable IPv6 operation)

	When this value is changed from 1 to 0 (IPv6 is being enabled),
	it will dynamically create a link-local address on the given
	interface and start Duplicate Address Detection, if necessary.

	When this value is changed from 0 to 1 (IPv6 is being disabled),
	it will dynamically delete all address on the given interface.



autoconf - BOOLEAN
	Autoconfigure addresses using Prefix Information in Router
	Advertisements.

	Functional default: enabled if accept_ra_pinfo is enabled.
			    disabled if accept_ra_pinfo is disabled.



accept_ra - INTEGER
	Accept Router Advertisements; autoconfigure using them.

	It also determines whether or not to transmit Router
	Solicitations. If and only if the functional setting is to
	accept Router Advertisements, Router Solicitations will be
	transmitted.

	Possible values are:
		0 Do not accept Router Advertisements.
		1 Accept Router Advertisements if forwarding is disabled.
		2 Overrule forwarding behaviour. Accept Router Advertisements
		  even if forwarding is enabled.

	Functional default: enabled if local forwarding is disabled.
			    disabled if local forwarding is enabled.

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
#include <fcntl.h>

#include "rhp_version.h"
#include "rhp_misc2.h"

struct __v6_tool_scr2_args {

#define RHP_V6_TOOL_SCR2_V6_DISABLE							1
#define RHP_V6_TOOL_SCR2_V6_AUTOCONF						2
#define RHP_V6_TOOL_SCR2_V6_ACCEPT_RA						3
#define RHP_V6_TOOL_SCR2_V6_ACCEPT_RA_DEFRTR		4
#define RHP_V6_TOOL_SCR2_V6_ACCEPT_RA_PINFO			5
#define RHP_V6_TOOL_SCR2_V6_ACCEPT_RA_RTR_PREF	6
	int action;

#define RHP_V6_TOOL_SCR2_DISABLE		1
#define RHP_V6_TOOL_SCR2_ENABLE			2
	int v6_action;

  unsigned long vpn_realm_id;
  char* vpn_realm_id_str;
};
static struct __v6_tool_scr2_args _v6_tool_scr2_args;

static void _print_usage()
{
  printf(" Usage: rhp_tuntap_cfg [-h] -a cfg-name [-e] [-d] -i realm_id\n");
}

static void _print_usage_detail()
{
  printf(
      "[ Usage ]\n"
      " rhp_tuntap_cfg [-h] -a operation [-e] [-d] -i realm_id\n"
      "   -a cfg-name : config name. \n"
      "   -e : Enable config on rhpvifN. 'N' is a VPN realm ID.\n"
      "   -d : Disable config rhpvifN. \n"
      "   -i : VPN realm ID.\n"
      "   -v : Show version.\n"
      "   -h : Show help infomation.\n"
  		"\n"
  		"   cfg_name:\n"
  		"    - \"ipv6\"\n"
  		"    - \"ipv6_autoconf\"\n"
  		"    - \"ipv6_accept_ra_defrtr\"\n"
  		"    - \"ipv6_accept_ra_pinfo\"\n"
  		"    - \"ipv6_accept_ra_rtr_pref\"\n"
  		"    - \"ipv6_accept_ra\"\n");
}

static int _parse_args(int argc, char *argv[])
{
  int c;
  extern char *optarg;
  char* endp;

  memset(&_v6_tool_scr2_args,0,sizeof(_v6_tool_scr2_args));

  while( 1 ){

  	c = getopt(argc,argv,"ha:edi:v");

  	if( c == -1 ){
  		break;
    }

  	switch( c ){

  	case 'v':
    	_rhp_print_version(stdout,NULL,1);
  	 goto out;

  	case 'h':
    	_print_usage_detail();
    	goto out;

  	case 'a':

    	if( !strcmp(optarg,"ipv6") ){
    		_v6_tool_scr2_args.action = RHP_V6_TOOL_SCR2_V6_DISABLE;
    	}else if( !strcmp(optarg,"ipv6_autoconf") ){
    		_v6_tool_scr2_args.action = RHP_V6_TOOL_SCR2_V6_AUTOCONF;
    	}else if( !strcmp(optarg,"ipv6_accept_ra_defrtr") ){
    		_v6_tool_scr2_args.action = RHP_V6_TOOL_SCR2_V6_ACCEPT_RA_DEFRTR;
    	}else if( !strcmp(optarg,"ipv6_accept_ra_pinfo") ){
    		_v6_tool_scr2_args.action = RHP_V6_TOOL_SCR2_V6_ACCEPT_RA_PINFO;
    	}else if( !strcmp(optarg,"ipv6_accept_ra_rtr_pref") ){
    		_v6_tool_scr2_args.action = RHP_V6_TOOL_SCR2_V6_ACCEPT_RA_RTR_PREF;
    	}else if( !strcmp(optarg,"ipv6_accept_ra") ){
    		_v6_tool_scr2_args.action = RHP_V6_TOOL_SCR2_V6_ACCEPT_RA;
    	}else{
    		printf("-a : Unknown operation(%s). \n",optarg);
    		goto error;
    	}

    	break;

  	case 'e':
    	_v6_tool_scr2_args.v6_action = RHP_V6_TOOL_SCR2_ENABLE;
    	break;

  	case 'd':
    	_v6_tool_scr2_args.v6_action = RHP_V6_TOOL_SCR2_DISABLE;
    	break;

  	case 'i':

    	_v6_tool_scr2_args.vpn_realm_id = strtoull(optarg,&endp,0);

      if( _v6_tool_scr2_args.vpn_realm_id > RHP_VPN_REALM_ID_MAX ||
      		*endp != '\0' ){
      	goto error;
      }

      _v6_tool_scr2_args.vpn_realm_id_str = optarg;

    	break;

  	default:
    	goto error;
  	}
  }

  if( _v6_tool_scr2_args.action == 0 ){
    printf("-a cfg-name not specified.\n");
    goto error;
  }

  if( _v6_tool_scr2_args.v6_action == 0 ){
    printf("-e or -d not specified.\n");
    goto error;
  }

  if( _v6_tool_scr2_args.vpn_realm_id == 0 ){
    printf("-i vpn_realm_id not specified.\n");
    goto error;
  }

  return 0;

error:
	_print_usage();
out:
	return EINVAL;
}


#define RHP_V6_TOOL_SCR2_CNF_PATH_H 										"/proc/sys/net/ipv6/conf/rhpvif"
#define RHP_V6_TOOL_SCR2_CNF_PATH_T_DISABLE 						"/disable_ipv6"
#define RHP_V6_TOOL_SCR2_CNF_PATH_T_AUTOCONF 						"/autoconf"
#define RHP_V6_TOOL_SCR2_CNF_PATH_T_ACCEPT_RA 					"/accept_ra"
#define RHP_V6_TOOL_SCR2_CNF_PATH_T_ACCEPT_RA_DEFRTR 		"/accept_ra_defrtr"
#define RHP_V6_TOOL_SCR2_CNF_PATH_T_ACCEPT_RA_PINFO 		"/accept_ra_pinfo"
#define RHP_V6_TOOL_SCR2_CNF_PATH_T_ACCEPT_RA_RTR_PREF 	"/accept_ra_rtr_pref"


static int _rhp_vif_cfg_write_val(char* file_path,char* val,size_t n)
{
	int err;
	char *val2;
	int dst_fd = -1;

	dst_fd = open(file_path,O_WRONLY);
	if( dst_fd < 0 ){
		err = errno;
		goto error;
	}

	val2 = val;
	while( n > 0 ){

		int c = write(dst_fd,val2,n);
		if( c < 0 ){
			err = -errno;
			goto error;
		}

		n -= c;
		val2 += c;
	}

	close(dst_fd);

	return 0;

error:
	if( dst_fd > -1 ){
		close(dst_fd);
	}
	return err;
}

static int _rhp_vif_cfg_ipv6_disable()
{
	int err = EINVAL;
	char *val;
	size_t file_path_len = 0;
	char* file_path = NULL;
	int n = 0;

	file_path_len = strlen(RHP_V6_TOOL_SCR2_CNF_PATH_H)
									+ strlen(_v6_tool_scr2_args.vpn_realm_id_str)
									+ strlen(RHP_V6_TOOL_SCR2_CNF_PATH_T_DISABLE) + 1;

	file_path = (char*)malloc(file_path_len);
	if( file_path == NULL ){
		err = ENOMEM;
		goto error;
	}
	file_path[0] = '\0';
	file_path[file_path_len - 1] = '\0';

	if( snprintf(file_path,file_path_len,"%s%s%s",RHP_V6_TOOL_SCR2_CNF_PATH_H,
			_v6_tool_scr2_args.vpn_realm_id_str,RHP_V6_TOOL_SCR2_CNF_PATH_T_DISABLE) != (file_path_len - 1) ){
		err = EINVAL;
		goto error;
	}


	if( _v6_tool_scr2_args.v6_action == RHP_V6_TOOL_SCR2_ENABLE ){
		val = "0";
	}else{ // RHP_V6_TOOL_SCR2_DISABLE
		val = "1";
	}

	printf("IPv6-Disable: Writing %s to %s ",val,file_path);

	n = strlen(val); // '\0' not included.

	err = _rhp_vif_cfg_write_val(file_path,val,n);
	if( err ){
		goto error;
	}

	free(file_path);

	printf("... OK.\n");
	return 0;

error:
	if( file_path ){
		free(file_path);
	}
	printf("... Error[%s].\n",strerror(err));
	return err;
}

static int _rhp_vif_cfg_ipv6_autoconf()
{
	int err = EINVAL;
	char *val;
	size_t file_path_len = 0;
	char* file_path = NULL;
	int n = 0;

	file_path_len = strlen(RHP_V6_TOOL_SCR2_CNF_PATH_H)
									+ strlen(_v6_tool_scr2_args.vpn_realm_id_str)
									+ strlen(RHP_V6_TOOL_SCR2_CNF_PATH_T_AUTOCONF) + 1;

	file_path = (char*)malloc(file_path_len);
	if( file_path == NULL ){
		err = ENOMEM;
		goto error;
	}
	file_path[0] = '\0';
	file_path[file_path_len - 1] = '\0';

	if( snprintf(file_path,file_path_len,"%s%s%s",RHP_V6_TOOL_SCR2_CNF_PATH_H,
			_v6_tool_scr2_args.vpn_realm_id_str,RHP_V6_TOOL_SCR2_CNF_PATH_T_AUTOCONF) != (file_path_len - 1) ){
		err = EINVAL;
		goto error;
	}


	if( _v6_tool_scr2_args.v6_action == RHP_V6_TOOL_SCR2_ENABLE ){
		val = "1";
	}else{ // RHP_V6_TOOL_SCR2_DISABLE
		val = "0";
	}

	printf("IPv6-Autoconf: Writing %s to %s ",val,file_path);

	n = strlen(val); // '\0' not included.

	err = _rhp_vif_cfg_write_val(file_path,val,n);
	if( err ){
		goto error;
	}

	free(file_path);

	printf("... OK.\n");
	return 0;

error:
	if( file_path ){
		free(file_path);
	}
	printf("... Error[%s].\n",strerror(err));
	return err;
}

static int _rhp_vif_cfg_ipv6_accept_ra()
{
	int err = EINVAL;
	char *val;
	size_t file_path_len = 0;
	char* file_path = NULL;
	int n = 0;

	file_path_len = strlen(RHP_V6_TOOL_SCR2_CNF_PATH_H)
									+ strlen(_v6_tool_scr2_args.vpn_realm_id_str)
									+ strlen(RHP_V6_TOOL_SCR2_CNF_PATH_T_ACCEPT_RA) + 1;

	file_path = (char*)malloc(file_path_len);
	if( file_path == NULL ){
		err = ENOMEM;
		goto error;
	}
	file_path[0] = '\0';
	file_path[file_path_len - 1] = '\0';

	if( snprintf(file_path,file_path_len,"%s%s%s",RHP_V6_TOOL_SCR2_CNF_PATH_H,
			_v6_tool_scr2_args.vpn_realm_id_str,RHP_V6_TOOL_SCR2_CNF_PATH_T_ACCEPT_RA) != (file_path_len - 1) ){
		err = EINVAL;
		goto error;
	}


	if( _v6_tool_scr2_args.v6_action == RHP_V6_TOOL_SCR2_ENABLE ){
		val = "2";
	}else{ // RHP_V6_TOOL_SCR2_DISABLE
		val = "0";
	}

	printf("IPv6-Accept-RA: Writing %s to %s ",val,file_path);

	n = strlen(val); // '\0' not included.

	err = _rhp_vif_cfg_write_val(file_path,val,n);
	if( err ){
		goto error;
	}

	free(file_path);

	printf("... OK.\n");
	return 0;

error:
	if( file_path ){
		free(file_path);
	}
	printf("... Error[%s].\n",strerror(err));
	return err;
}

static int _rhp_vif_cfg_ipv6_accept_ra_defrtr()
{
	int err = EINVAL;
	char *val;
	size_t file_path_len = 0;
	char* file_path = NULL;
	int n = 0;

	file_path_len = strlen(RHP_V6_TOOL_SCR2_CNF_PATH_H)
									+ strlen(_v6_tool_scr2_args.vpn_realm_id_str)
									+ strlen(RHP_V6_TOOL_SCR2_CNF_PATH_T_ACCEPT_RA_DEFRTR) + 1;

	file_path = (char*)malloc(file_path_len);
	if( file_path == NULL ){
		err = ENOMEM;
		goto error;
	}
	file_path[0] = '\0';
	file_path[file_path_len - 1] = '\0';

	if( snprintf(file_path,file_path_len,"%s%s%s",RHP_V6_TOOL_SCR2_CNF_PATH_H,
			_v6_tool_scr2_args.vpn_realm_id_str,RHP_V6_TOOL_SCR2_CNF_PATH_T_ACCEPT_RA_DEFRTR) != (file_path_len - 1) ){
		err = EINVAL;
		goto error;
	}


	if( _v6_tool_scr2_args.v6_action == RHP_V6_TOOL_SCR2_ENABLE ){
		val = "1";
	}else{ // RHP_V6_TOOL_SCR2_DISABLE
		val = "0";
	}

	printf("IPv6-Accept-RA-DefRtr: Writing %s to %s ",val,file_path);

	n = strlen(val); // '\0' not included.

	err = _rhp_vif_cfg_write_val(file_path,val,n);
	if( err ){
		goto error;
	}

	free(file_path);

	printf("... OK.\n");
	return 0;

error:
	if( file_path ){
		free(file_path);
	}
	printf("... Error[%s].\n",strerror(err));
	return err;
}

static int _rhp_vif_cfg_ipv6_accept_ra_pinfo()
{
	int err = EINVAL;
	char *val;
	size_t file_path_len = 0;
	char* file_path = NULL;
	int n = 0;

	file_path_len = strlen(RHP_V6_TOOL_SCR2_CNF_PATH_H)
									+ strlen(_v6_tool_scr2_args.vpn_realm_id_str)
									+ strlen(RHP_V6_TOOL_SCR2_CNF_PATH_T_ACCEPT_RA_PINFO) + 1;

	file_path = (char*)malloc(file_path_len);
	if( file_path == NULL ){
		err = ENOMEM;
		goto error;
	}
	file_path[0] = '\0';
	file_path[file_path_len - 1] = '\0';

	if( snprintf(file_path,file_path_len,"%s%s%s",RHP_V6_TOOL_SCR2_CNF_PATH_H,
			_v6_tool_scr2_args.vpn_realm_id_str,RHP_V6_TOOL_SCR2_CNF_PATH_T_ACCEPT_RA_PINFO) != (file_path_len - 1) ){
		err = EINVAL;
		goto error;
	}


	if( _v6_tool_scr2_args.v6_action == RHP_V6_TOOL_SCR2_ENABLE ){
		val = "1";
	}else{ // RHP_V6_TOOL_SCR2_DISABLE
		val = "0";
	}

	printf("IPv6-Accept-RA-PInfo: Writing %s to %s ",val,file_path);

	n = strlen(val); // '\0' not included.

	err = _rhp_vif_cfg_write_val(file_path,val,n);
	if( err ){
		goto error;
	}

	free(file_path);

	printf("... OK.\n");
	return 0;

error:
	if( file_path ){
		free(file_path);
	}
	printf("... Error[%s].\n",strerror(err));
	return err;
}

static int _rhp_vif_cfg_ipv6_accept_ra_rtr_pref()
{
	int err = EINVAL;
	char *val;
	size_t file_path_len = 0;
	char* file_path = NULL;
	int n = 0;

	file_path_len = strlen(RHP_V6_TOOL_SCR2_CNF_PATH_H)
									+ strlen(_v6_tool_scr2_args.vpn_realm_id_str)
									+ strlen(RHP_V6_TOOL_SCR2_CNF_PATH_T_ACCEPT_RA_RTR_PREF) + 1;

	file_path = (char*)malloc(file_path_len);
	if( file_path == NULL ){
		err = ENOMEM;
		goto error;
	}
	file_path[0] = '\0';
	file_path[file_path_len - 1] = '\0';

	if( snprintf(file_path,file_path_len,"%s%s%s",RHP_V6_TOOL_SCR2_CNF_PATH_H,
			_v6_tool_scr2_args.vpn_realm_id_str,RHP_V6_TOOL_SCR2_CNF_PATH_T_ACCEPT_RA_RTR_PREF) != (file_path_len - 1) ){
		err = EINVAL;
		goto error;
	}


	if( _v6_tool_scr2_args.v6_action == RHP_V6_TOOL_SCR2_ENABLE ){
		val = "1";
	}else{ // RHP_V6_TOOL_SCR2_DISABLE
		val = "0";
	}

	printf("IPv6-Accept-RA-Rtr-Pref: Writing %s to %s ",val,file_path);

	n = strlen(val); // '\0' not included.

	err = _rhp_vif_cfg_write_val(file_path,val,n);
	if( err ){
		goto error;
	}

	free(file_path);

	printf("... OK.\n");
	return 0;

error:
	if( file_path ){
		free(file_path);
	}
	printf("... Error[%s].\n",strerror(err));
	return err;
}

int main(int argc, char *argv[])
{
	int err = EINVAL;

	err = _parse_args(argc,argv);
	if( err ){
		return err;
	}

	//
	//
	// Defining a function for each action is redundant and ugly. I know...
	// But, from the viewpoint of security, each action is hard-coded here.
	//
	//

	switch( _v6_tool_scr2_args.action ){

	case RHP_V6_TOOL_SCR2_V6_DISABLE:

		err = _rhp_vif_cfg_ipv6_disable();
		if( err ){
			goto error;
		}
		break;

	case RHP_V6_TOOL_SCR2_V6_AUTOCONF:

		err = _rhp_vif_cfg_ipv6_autoconf();
		if( err ){
			goto error;
		}
		break;

	case RHP_V6_TOOL_SCR2_V6_ACCEPT_RA_DEFRTR:

		err = _rhp_vif_cfg_ipv6_accept_ra_defrtr();
		if( err ){
			goto error;
		}
		break;

	case RHP_V6_TOOL_SCR2_V6_ACCEPT_RA_PINFO:

		err = _rhp_vif_cfg_ipv6_accept_ra_pinfo();
		if( err ){
			goto error;
		}
		break;

	case RHP_V6_TOOL_SCR2_V6_ACCEPT_RA_RTR_PREF:

		err = _rhp_vif_cfg_ipv6_accept_ra_rtr_pref();
		if( err ){
			goto error;
		}
		break;

	case RHP_V6_TOOL_SCR2_V6_ACCEPT_RA:

		err = _rhp_vif_cfg_ipv6_accept_ra();
		if( err ){
			goto error;
		}
		break;

	default:

		err = EINVAL;
		goto error;
	}

	return 0;

error:
	return err;
}
