/*

 Copyright (C) 2009-2010 TETSUHARU HANADA <rhpenguine@gmail.com>
 All rights reserved.

 You can redistribute and/or modify this software under the
 LESSER GPL version 2.1.
 See also LICENSE.txt and LICENSE_LGPL2.1.txt.

 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>

#include "rhp_trace.h"

int main( int argc, char **argv )
{
  int err = 0;
  rhp_trace_setup setup;
  int devfd = -1;
  int opr = 0;

  if(argc == 2){
    if(!strcmp( argv[1], "stop" )){
      opr = 1;
    }else if(!strcmp( argv[1], "start" )){
      opr = 0;
    }else{
      err = EINVAL;
      printf( "%s\n", strerror( err ) );
      goto error;
    }
  }else if(argc > 2){
    err = EINVAL;
    printf( "%s\n", strerror( err ) );
    goto error;
  }

  memset( &setup, 0, sizeof(setup) );

  devfd = open( "/dev/rhp_trace", O_RDWR);
  if(devfd < 0){
    err = errno;
    printf( " Fail to open /dev/rhp_trace. %s. \n", strerror( err ) );
    goto error;
  }

  if(!opr){

    if(ioctl( devfd, RHP_TRC_IOCTRL_START_ID, &setup )){
      err = errno;
      printf( " Fail to start. %s \n", strerror( err ) );
      goto error;
    }

  }else{

    if(ioctl( devfd, RHP_TRC_IOCTRL_STOP_ID, &setup )){
      err = errno;
      printf( " Fail to stop. %s \n", strerror( err ) );
      goto error;
    }
  }

  error: if(devfd >= 0){
    close( devfd );
  }

  return err;
}
