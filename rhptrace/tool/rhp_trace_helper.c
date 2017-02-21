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
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <time.h>
#include <sys/shm.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "rhp_trace.h"

unsigned char* rhp_trace_flag = ((void*) -1);

int main( int argc, char *argv[], char *env[] )
{
  int err = 0;
  rhp_trace_helper_params params;
  int devfd = -1;

  memset( &params, 0, sizeof(params) );
  params.shm_id = -1;

  params.shm_id = shmget( IPC_PRIVATE, sizeof(unsigned char)
      * RHP_TRC_MAX_USERS, IPC_CREAT | 0644 );
  if(params.shm_id < 0){
    err = errno;
    printf( " Fail to shmget. %s \n", strerror( err ) );
    goto error;
  }

  rhp_trace_flag = (unsigned char*) shmat( params.shm_id, NULL, 0 );
  if(rhp_trace_flag == ((void*) -1)){
    err = errno;
    printf( " Fail to shmat. shm_id:%d , %s \n", params.shm_id, strerror( err ) );
    goto error;
  }

  devfd = open( "/dev/rhp_trace", O_RDWR);
  if(devfd < 0){
    err = errno;
    printf( " Fail to open /dev/rhp_trace. %s. \n", strerror( err ) );
    goto error;
  }

  if(ioctl( devfd, RHP_TRC_IOCTRL_START_HELPER_ID, &params )){
    err = errno;
    printf( " Fail to start. %s \n", strerror( err ) );
    goto error;
  }

  memcpy( rhp_trace_flag, params.trace_flag, sizeof(unsigned char)
      * RHP_TRC_MAX_USERS);

  while(1){
    int i;

    if(ioctl( devfd, RHP_TRC_IOCTRL_HELPER_ID, &params )){
      err = errno;

      if(err == -ENODEV){
        err = 0;
      }else if(err == -EINTR){
        continue;
      }else{
        printf( " Fail to RHP_TRC_IOCTRL_HELPER_ID. %s \n", strerror( err ) );
      }
      break;
    }

    memcpy( rhp_trace_flag, params.trace_flag, sizeof(unsigned char)
        * RHP_TRC_MAX_USERS);

    printf( " RHP_TRC_IOCTRL_HELPER_ID : \n" );
    for(i = 0; i < RHP_TRC_MAX_USERS; i++){
      printf( "rhp_trace_flag[%d] : 0x%x\n", i, rhp_trace_flag[i] );
    }
    printf( "\n" );
  }

  error: if(rhp_trace_flag != ((void*) -1)){
    shmdt( rhp_trace_flag );
    rhp_trace_flag = ((void*) -1);
  }
  if(params.shm_id != -1){
    shmctl( params.shm_id, IPC_RMID, 0 );
    params.shm_id = -1;
  }
  if(devfd >= 0){
    close( devfd );
  }
  return err;
}
