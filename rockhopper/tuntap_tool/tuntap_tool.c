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
#include <asm/types.h>
#include <linux/types.h>
#include <asm/byteorder.h>
#include <unistd.h>
#include <sys/capability.h>
#include <sys/socket.h>
#include <time.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <fcntl.h>
#include <sys/ioctl.h>

#include "rhp_version.h"

int rhp_netmng_vif_delete(char* vif_name)
{
  int err = -EINVAL;
  int tunfd = -1;
  struct ifreq req;
  int flag;

  tunfd = open("/dev/net/tun",O_RDWR);
  if( tunfd < 0 ){
    err = -errno;
    printf("Fail to delete %s.(1)\n",vif_name);
    goto error;
  }

  memset(&req,0,sizeof(req));

  strcpy(req.ifr_name,vif_name);

  req.ifr_flags |= IFF_TAP;

  if( ioctl(tunfd,TUNSETIFF,(void*)&req) < 0 ){
    err = -errno;
    printf("Fail to delete %s.%d(2)\n",vif_name,err);
  }

  flag = 0;
  if( ioctl(tunfd,TUNSETPERSIST,flag) < 0 ){
    err = -errno;
    printf("Fail to delete %s.%d(3)\n",vif_name,err);
    goto error;
  }

  close(tunfd);

  return 0;

error:
  if( tunfd >= 0 ){
    close(tunfd);
  }
  return err;
}

struct __tuntap_tool_args {

#define RHP_TUNTAP_TOOL_ACTION_DELETE		1
	int action;

  char* if_name;
};
static struct __tuntap_tool_args _tuntap_tool_args;

static void _print_usage()
{
  printf(" Usage: rhp_tuntap_tool [-h] -a action -i if_name \"rhpvifN\"\n");
}

static void _print_usage_detail()
{
  printf(
      "[ Usage ]\n"
      " rhp_tuntap_tool [-h] -a action -i if_name\n"
      "   -a operation : Operation. \"delete\". \n"
      "   -i : Tuntap interface name. \"rhpvifN\"\n"
      "   -v : Show version.\n"
      "   -h : Show help infomation.\n");
}

static int _parse_args(int argc, char *argv[])
{
  int c;
  extern char *optarg;

  memset(&_tuntap_tool_args,0,sizeof(_tuntap_tool_args));
  _tuntap_tool_args.action = 0;
  _tuntap_tool_args.if_name = NULL;

  while( 1 ){

  	c = getopt(argc,argv,"ha:i:v");

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

  	case 'i':
    	_tuntap_tool_args.if_name = optarg;
    	break;

  	case 'a':

    	if( !strcmp(optarg,"delete") ){
    		_tuntap_tool_args.action = RHP_TUNTAP_TOOL_ACTION_DELETE;
    	}else{
    		printf("-a : Unknown operation(%s). \n",optarg);
    		goto error;
    	}

    	break;

  	default:
    	goto error;
  	}
  }

  if( _tuntap_tool_args.action == 0 ){
    printf("-a operation not specified.\n");
    goto error;
  }

  if( _tuntap_tool_args.if_name == NULL ){
    printf("-i if_name not specified.\n");
    goto error;
  }

  return 0;

error:
	_print_usage();
out:
	return EINVAL;
}


int main(int argc, char *argv[])
{
	int err;

	err = _parse_args(argc,argv);
	if( err ){
		return err;
	}

	if( _tuntap_tool_args.action == RHP_TUNTAP_TOOL_ACTION_DELETE ){
		rhp_netmng_vif_delete(_tuntap_tool_args.if_name);
	}

	return EXIT_SUCCESS;
}
