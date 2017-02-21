/*
	Copyright (C) 2009-2010 TETSUHARU HANADA <rhpenguine@gmail.com>
	All rights reserved.

	This library may be distributed, used, and modified under the terms of
	BSD license:

	Redistribution and use in source and binary forms, with or without
	modification, are permitted provided that the following conditions are
	met:

	1. Redistributions of source code must retain the above copyright
		 notice, this list of conditions and the following disclaimer.

	2. Redistributions in binary form must reproduce the above copyright
		 notice, this list of conditions and the following disclaimer in the
		 documentation and/or other materials provided with the distribution.

	3. Neither the name(s) of the above-listed copyright holder(s) nor the
		 names of its contributors may be used to endorse or promote products
		 derived from this software without specific prior written permission.

	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
	"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
	LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
	A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
	OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
	SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
	LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
	DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
	THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
	(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
	OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

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
#include <sys/time.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <time.h>
#include <sys/shm.h>
#include <stdarg.h>
#include <unistd.h>
#include <linux/unistd.h>
#include <byteswap.h>
#include <pthread.h>

#include "rhp_trace.h"

#ifdef RHP_TRACE_LIB_DEBUG
static void _rhp_bin_dump(unsigned char* d,unsigned long len)
{
  int i,j;
  unsigned char* mc = d;
  printf("len : %lu\n",len);
  printf("*0 *1 *2 *3 *4 *5 *6 *7 *8 *9 *A *B *C *D *E *F     0123456789ABCDEF\n");
  for( i = 0;i < len; i++ )
  {
    int pd;

    if( i && (i % 16) == 0 )
    {
      printf("    ");
      for( j = 0;j < 16; j++ )
      {
        if( *mc >= 33 && *mc <= 126 )
        {
          printf("%c",*mc);
        } else{
          printf(".");
        }
        mc++;
      }
      printf("\n");
    }

    pd = ((*(int*)d) & 0x000000FF);

    if( pd <= 0x0F ){
      printf("0");
    }
    printf("%x ",pd);
    d++;
  }

  {
    int k,k2;

    if( (i % 16) == 0 ){
      k = 0;
      k2 = 16;
    } else{
      k = 16 - (i % 16);
      k2 = (i % 16);
    }

    for( i = 0; i < k;i++ ){
      printf("   ");
    }

    printf("    ");

    for( j = 0;j < k2; j++ ){

      if( *mc >= 33 && *mc <= 126 ){
        printf("%c",*mc);
      } else{
        printf(".");
      }
      mc++;
    }
  }

  printf("\n");
}
#else // RHP_TRACE_LIB_DEBUG
static inline void _rhp_bin_dump( unsigned char* d, unsigned long len )
{
}
#endif // RHP_TRACE_LIB_DEBUG
static int _rhp_trc_devfd = -1;
unsigned char* rhp_trace_flag = ((void*) -1);
static int _rhp_shm_id = -1;

pid_t rhp_trace_pid = 0;
__thread pid_t rhp_trace_tid = 0;

__thread int rhp_trace_flag_c_n[RHP_TRC_MAX_USERS] = { RHP_TRC_FLAG_N,
    RHP_TRC_FLAG_N, RHP_TRC_FLAG_N, RHP_TRC_FLAG_N, RHP_TRC_FLAG_N,
    RHP_TRC_FLAG_N, RHP_TRC_FLAG_N, RHP_TRC_FLAG_N, RHP_TRC_FLAG_N, };

__thread unsigned char rhp_trace_flag_c[RHP_TRC_MAX_USERS] = { 0, 0, 0, 0, 0, 0, 0, 0, 0 };


#define RHP_TRC_F_FILE_HEADER_OFFSET	(sizeof(unsigned int)*2 + sizeof(rhp_trace_f_file_header))
static off_t _rhp_trc_f_record_head_pos = 0;
static off_t _rhp_trc_f_record_tail_pos = 0;
static long _rhp_trc_f_buffer_len = RHP_TRC_BUFFER_DEFAULT_SIZE;
static long _rhp_trc_f_current_len = 0;

static int _rhp_trc_f_fd = -1;
static pthread_mutex_t _rhp_trc_f_mutex;

__thread int rhp_trace_write_disabled = 0;


#define RHP_TRC_LIB_LOCAL_DATA 512
static int _rhp_trc_data_copy( unsigned char** cu, unsigned long* cu_len,
    unsigned char* data, int data_len, unsigned char **local_data_slow,
    int* local_data_slow_len, rhp_trace_record** cu_record )
{
  int len = *cu_len + data_len;

  if(len > RHP_TRC_LIB_LOCAL_DATA){

    int old_buf_len = *local_data_slow_len;

    if(len > old_buf_len){

      unsigned char* old_buf = *local_data_slow;
      unsigned char* new_buf;

      new_buf = malloc( len + 512 );
      if(new_buf == NULL){
        return -ENOMEM;
      }

      memcpy( new_buf, (*cu - *cu_len), *cu_len );
      *cu = (new_buf + *cu_len);
      *cu_record = (rhp_trace_record*) new_buf;

      *local_data_slow_len = len + 512;
      *local_data_slow = new_buf;

      if(old_buf){
        free( old_buf );
      }
    }
  }

  memcpy( *cu, data, data_len );

  *cu += data_len;
  *cu_len += data_len;

  return 0;
}

static ssize_t _rhp_trc_f_write(unsigned char* record_buf,int record_buf_len);


#define RHP_TRC_LIB_INVALID_DATA_LEN	16
char _rhp_dmy_invalid_data[RHP_TRC_LIB_INVALID_DATA_LEN];

static inline time_t _rhp_trace_get_realtime()
{
	struct timespec now;
	clock_gettime(CLOCK_REALTIME_COARSE,&now); // > 1ms(resolution)
	return now.tv_sec;
}

static inline time_t _rhp_trace_get_time()
{
	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC_COARSE,&now); // > 1ms(resolution)
	return now.tv_sec;
}

void rhp_trace( unsigned char userid, unsigned long record_id, ... )
{
  va_list args;
  rhp_trace_record *record;
  unsigned long record_len = sizeof(rhp_trace_record);
  int b;
  u_int16_t w;
  u_int32_t d;
  u_int64_t q;
  unsigned char* s;
  unsigned long ad;
  int32_t lm, a_iv_len, a_icv_len, a_proto_type;
  int a_next_payload;
  unsigned char* cu = NULL;
  unsigned char* bm = NULL;
  unsigned char dc = '\0';
  unsigned char local_data[RHP_TRC_LIB_LOCAL_DATA];
  unsigned char *local_data_slow = NULL;
  int local_data_slow_len = 0;
  ssize_t cnt;
  char *fmt, *fmt_start;
  unsigned long trace_user_id;
  time_t tt;
  int err;

  if(rhp_trace_flag == ((void*) -1)){
    return;
  }

  trace_user_id = (((unsigned long) (userid & 0x000000FF)) << 24) | (record_id
      & 0x00FFFFFF);

  record = (rhp_trace_record*) local_data;
  cu = (unsigned char*) (record + 1);

  record->len = 0;
  record->record_id = trace_user_id;
  record->pid = rhp_trace_pid;
  record->tid = rhp_trace_tid;

  va_start(args,record_id);
  fmt = va_arg(args,char*);
  fmt_start = fmt;

  if(*fmt == '\0'){
    goto no_data;
  }

  while(*fmt != '\0'){

    switch(*fmt){

    case 'b':

      b = (u_int8_t) va_arg(args,int);

      if(_rhp_trc_data_copy( &cu, &record_len,
          (unsigned char*) ((u_int8_t*) &b), sizeof(u_int8_t),
          &local_data_slow, &local_data_slow_len, &record )){
        printf( " rhp_trace : Failed b \n" );
        goto error;
      }

      break;

    case 'W':
#ifndef RHP_BIG_ENDIAN
      w = (u_int16_t) va_arg(args,int);
      w = bswap_16(w);

      if(_rhp_trc_data_copy( &cu, &record_len,
          (unsigned char*) ((u_int16_t*) &w), sizeof(u_int16_t),
          &local_data_slow, &local_data_slow_len, &record )){
        printf( " rhp_trace : Failed w \n" );
        goto error;
      }

      break;
#endif // RHP_BIG_ENDIAN
    case 'w':
      w = (u_int16_t) va_arg(args,int);
      if(_rhp_trc_data_copy( &cu, &record_len,
          (unsigned char*) ((u_int16_t*) &w), sizeof(u_int16_t),
          &local_data_slow, &local_data_slow_len, &record )){
        printf( " rhp_trace : Failed w \n" );
        goto error;
      }
      break;

    case 'J':
    case 'K':
    case 'D':
#ifndef RHP_BIG_ENDIAN
      d = va_arg(args,u_int32_t);
      d = bswap_32(d);

      if(_rhp_trc_data_copy( &cu, &record_len, (unsigned char*) &d, sizeof(d),
          &local_data_slow, &local_data_slow_len, &record )){
        printf( " rhp_trace : Failed d \n" );
        goto error;
      }

      break;
#endif // RHP_BIG_ENDIAN

    case 'U':
    case 'X':
#ifndef RHP_BIG_ENDIAN
    	ad = va_arg(args,unsigned long);

      if( sizeof(unsigned long) == 8 ){
      	ad = bswap_64(ad);
      }else{
      	ad = bswap_32(ad);
      }

      if(_rhp_trc_data_copy( &cu, &record_len, (unsigned char*) &d, sizeof(ad),
          &local_data_slow, &local_data_slow_len, &record )){
        printf( " rhp_trace : Failed d \n" );
        goto error;
      }

      break;
#endif // RHP_BIG_ENDIAN

    case 'j':
    case 'k':
    case 'd':
    case '4':
    case 'E':
    case 'H':

      d = va_arg(args,u_int32_t);

      if(_rhp_trc_data_copy( &cu, &record_len, (unsigned char*) &d, sizeof(d),
          &local_data_slow, &local_data_slow_len, &record )){
        printf( " rhp_trace : Failed d \n" );
        goto error;
      }

      break;

    case 'f':
    case 'F':
    case 'u':
    case 'x':
    case 'Y':

    	ad = va_arg(args,unsigned long);

      if(_rhp_trc_data_copy( &cu, &record_len, (unsigned char*) &ad, sizeof(ad),
          &local_data_slow, &local_data_slow_len, &record )){
        printf( " rhp_trace : Failed d \n" );
        goto error;
      }

      break;

    case 'Q':
#ifndef RHP_BIG_ENDIAN

      q = va_arg(args,u_int64_t);
      q = bswap_64(q);

      if(_rhp_trc_data_copy( &cu, &record_len, (unsigned char*) &q, sizeof(q),
          &local_data_slow, &local_data_slow_len, &record )){
        goto error;
        printf( " rhp_trace : Failed q \n" );
      }

      break;
#endif // RHP_BIG_ENDIAN
    case 'q':

      q = va_arg(args,u_int64_t);

      if(_rhp_trc_data_copy( &cu, &record_len, (unsigned char*) &q, sizeof(q),
          &local_data_slow, &local_data_slow_len, &record )){
        goto error;
        printf( " rhp_trace : Failed q \n" );
      }

      break;

    case 'L': // Dummy!

      s = va_arg(args,unsigned char *);
      break;

    case 's':

      s = va_arg(args,unsigned char *);

      if( s == NULL ){

        if(_rhp_trc_data_copy( &cu, &record_len, &dc, 1, &local_data_slow,
            &local_data_slow_len, &record )){
          printf( " rhp_trace : Failed s (1) \n" );
          goto error;
        }

      }else{

        int s_len = 0;
        unsigned char s_bk = '\0';

        for(s_len = 0; s_len < RHP_TRC_MAX_STRING_SIZE; s_len++){

          if(s[s_len] == '\0'){
            break;
          }
        }

        if( s_len < RHP_TRC_MAX_STRING_SIZE ){
          s_len++;
        }else{
        	s_bk = s[s_len - 1];
        	s[s_len - 1] = '\0';
        }

        err = _rhp_trc_data_copy( &cu, &record_len, (unsigned char*)s, s_len,
              &local_data_slow, &local_data_slow_len, &record );
        if( s_bk != '\0' ){
        	s[s_len - 1] = s_bk;
       }

        if( err ){
            printf( " rhp_trace : Failed s (3) \n" );
            goto error;
        }
      }
      break;

    case 'p':
    case 'B':

      lm = va_arg(args,int32_t);

      if(lm < 0){
        lm = RHP_TRC_LIB_INVALID_DATA_LEN;
        bm = (unsigned char*) _rhp_dmy_invalid_data;
      }else{
        bm = va_arg(args,unsigned char *);
        if(bm == NULL){
          lm = 0;
        }
      }

      if(*fmt == 'B'){

        if(lm == 3){
          lm = 2;
        }else if(lm > 4 && lm < 8){
          lm = 4;
        }else if(lm > 8){
          lm = 8;
        }else{
          lm = 0;
        }
      }

      if(_rhp_trc_data_copy( &cu, &record_len, (unsigned char*) &lm,
          sizeof(lm), &local_data_slow, &local_data_slow_len, &record )){
        printf( " rhp_trace : Failed p (1) \n" );
        goto error;
      }

      if(*fmt == 'p'){ // TODO : Driver's API

        u_int32_t pt_addr = (u_int32_t) bm;

        if(_rhp_trc_data_copy( &cu, &record_len, (unsigned char*) &pt_addr,
            sizeof(pt_addr), &local_data_slow, &local_data_slow_len, &record )){
          printf( " rhp_trace : Failed p (1) \n" );
          goto error;
        }
      }

      if(bm){

        if(_rhp_trc_data_copy( &cu, &record_len, bm, lm, &local_data_slow,
            &local_data_slow_len, &record )){
          printf( " rhp_trace : Failed p (2) \n" );
          goto error;
        }
      }

      break;

    case '6':

      bm = va_arg(args,unsigned char *);
      if(bm == NULL){
        lm = 0;
      }

      if(bm){

        if(_rhp_trc_data_copy( &cu, &record_len, bm, 16, &local_data_slow,
            &local_data_slow_len, &record )){
          printf( " rhp_trace : Failed 6 (1) \n" );
          goto error;
        }

      }else{

        unsigned char dummy_ipv6[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0 };

        if(_rhp_trc_data_copy( &cu, &record_len, dummy_ipv6, 16,
            &local_data_slow, &local_data_slow_len, &record )){
          printf( " rhp_trace : Failed 6 (2) \n" );
          goto error;
        }
      }
      break;

    case 'M':

      bm = va_arg(args,unsigned char *);
      if(bm == NULL){
        lm = 0;
      }

      if(bm){

        if(_rhp_trc_data_copy( &cu, &record_len, bm, 6, &local_data_slow,
            &local_data_slow_len, &record )){
          printf( " rhp_trace : Failed M (1) \n" );
          goto error;
        }

      }else{

        unsigned char dummy_mac[6] = { 0, 0, 0, 0, 0, 0 };

        if(_rhp_trc_data_copy( &cu, &record_len, dummy_mac, 6,
            &local_data_slow, &local_data_slow_len, &record )){
          printf( " rhp_trace : Failed M (2) \n" );
          goto error;
        }
      }
      break;

    case 'G':

      bm = va_arg(args,unsigned char *);
      if(bm == NULL){
        lm = 0;
      }

      if(bm){

        if(_rhp_trc_data_copy( &cu, &record_len, bm, 8, &local_data_slow,
            &local_data_slow_len, &record )){
          printf( " rhp_trace : Failed M (1) \n" );
          goto error;
        }

      }else{

        unsigned char dummy_ike_spi[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };

        if(_rhp_trc_data_copy( &cu, &record_len, dummy_ike_spi, 8,
            &local_data_slow, &local_data_slow_len, &record )){
          printf( " rhp_trace : Failed M (2) \n" );
          goto error;
        }
      }
      break;

    case 'a':

      lm = va_arg(args,int32_t);

      if(lm < 0){

        lm = RHP_TRC_LIB_INVALID_DATA_LEN;
        bm = (unsigned char*) _rhp_dmy_invalid_data;

      }else{


        a_proto_type = va_arg(args,int32_t);

        a_iv_len = va_arg(args,int32_t);

        a_icv_len = va_arg(args,int32_t);

        if( a_proto_type == RHP_TRC_FMT_A_IKEV2_PLAIN_PAYLOADS ){
        		a_next_payload = (u_int8_t)va_arg(args,int);
        }

        bm = va_arg(args,unsigned char *);
        if(bm == NULL){
          lm = 0;
        }
      }

      if(_rhp_trc_data_copy( &cu, &record_len, (unsigned char*) &lm,
          sizeof(lm), &local_data_slow, &local_data_slow_len, &record )){
        printf( " rhp_trace : Failed a (4) \n" );
        goto error;
      }

      if(_rhp_trc_data_copy( &cu, &record_len, (unsigned char*) &a_proto_type,
          sizeof(a_proto_type), &local_data_slow, &local_data_slow_len, &record )){
        printf( " rhp_trace : Failed a (1) \n" );
        goto error;
      }

      if(_rhp_trc_data_copy( &cu, &record_len, (unsigned char*) &a_iv_len,
          sizeof(a_iv_len), &local_data_slow, &local_data_slow_len, &record )){
        printf( " rhp_trace : Failed a (2) \n" );
        goto error;
      }

      if(_rhp_trc_data_copy( &cu, &record_len, (unsigned char*) &a_icv_len,
          sizeof(a_icv_len), &local_data_slow, &local_data_slow_len, &record )){
        printf( " rhp_trace : Failed a (3) \n" );
        goto error;
      }

      if( a_proto_type == RHP_TRC_FMT_A_IKEV2_PLAIN_PAYLOADS ){

        if(_rhp_trc_data_copy( &cu, &record_len,
          (unsigned char*) ((u_int8_t*) &a_next_payload), sizeof(u_int8_t),
          &local_data_slow, &local_data_slow_len, &record )){
          printf( " rhp_trace : Failed b \n" );
          goto error;
        }
      }

      if(bm){

        if(_rhp_trc_data_copy( &cu, &record_len, bm, lm, &local_data_slow,
            &local_data_slow_len, &record )){
          printf( " rhp_trace : Failed a (5) \n" );
          goto error;
        }
      }

      break;

    case 't':
    {
    	time_t rt;

    	tt = va_arg(args,time_t);
    	rt = _rhp_trace_get_realtime() + tt - _rhp_trace_get_time();

      if(_rhp_trc_data_copy( &cu, &record_len, (unsigned char*) &tt, sizeof(tt),
          &local_data_slow, &local_data_slow_len, &record )){
        printf( " rhp_trace : Failed d \n" );
        goto error;
      }

      if(_rhp_trc_data_copy( &cu, &record_len, (unsigned char*) &rt, sizeof(rt),
          &local_data_slow, &local_data_slow_len, &record )){
        printf( " rhp_trace : Failed d \n" );
        goto error;
      }
    }
      break;

    case 'T':

    	tt = va_arg(args,time_t);

      if(_rhp_trc_data_copy( &cu, &record_len, (unsigned char*) &tt, sizeof(tt),
          &local_data_slow, &local_data_slow_len, &record )){
        printf( " rhp_trace : Failed d \n" );
        goto error;
      }

      break;

    default:
      printf(
          " rhp_trace : Unknown format[%c(0x%d) in %s]... userid:%d , record_id:%lu \n",
          *fmt, *fmt, fmt_start, userid, record_id );
      goto error;
    }

    fmt++;
  }
  va_end(args);

no_data:

	record->len = record_len;

  if(((long) record->len) < sizeof(rhp_trace_record)){
    printf( " rhp_trace : Invalid record->len %lu < %d \n", record->len,sizeof(rhp_trace_record) );
    goto error;
  }

  if(record->record_id != trace_user_id){
    printf( " rhp_trace : Data broken? (trace_id) %lu != %lu \n",record->record_id, trace_user_id );
    goto error;
  }

  if(local_data_slow){

    _rhp_bin_dump( local_data_slow, record_len );

    if( _rhp_trc_devfd != -1 ){

    	cnt = write(_rhp_trc_devfd, local_data_slow, record_len);
			if(cnt <= 0){
				printf( " rhp_trace : Failed write(0) %lu,%lu,%lu,%d,%d : %d\n",
						record->len, ((record->record_id & 0xFF000000) >> 24),
						(record->record_id & 0x00FFFFFF), record->pid, record->tid, errno);
			}

    }else if( _rhp_trc_f_fd != -1 ){

    	_rhp_trc_f_write(local_data_slow,record_len);
    }

  }else{

    _rhp_bin_dump( local_data, record_len );

    if( _rhp_trc_devfd != -1 ){

    	cnt = write(_rhp_trc_devfd, local_data, record_len);
    	if(cnt <= 0){
    		printf( " rhp_trace : Failed write(1) %lu,%lu,%lu,%d,%d : %d\n",
          record->len, ((record->record_id & 0xFF000000) >> 24),
          (record->record_id & 0x00FFFFFF), record->pid, record->tid, errno);
    	}

    }else if( _rhp_trc_f_fd != -1 ){

    	_rhp_trc_f_write(local_data,record_len);
    }
  }

error:
  if(local_data_slow){
    free( local_data_slow );
  }

  return;
}

#define RHP_TRC_LIB_LOCAL_STR 512
void rhp_trace_string( unsigned char userid, unsigned long record_id,
    const char* file, int line, ... )
{
  int len;
  va_list args;
  char buf[RHP_TRC_LIB_LOCAL_STR];
  char* format;

  if(rhp_trace_flag == ((void*) -1)){
    return;
  }

  buf[0] = '\0';

  va_start(args,line);
  format = va_arg(args,char*);
  if(*format != '\0'){
    len = vsnprintf( buf, RHP_TRC_LIB_LOCAL_STR, format, args );
    if(len < 0){
      va_end(args);
      printf( "rhp_trace_string failed. %d\n", len );
      return;
    }
  }
  va_end(args);

  rhp_trace( userid, record_id, "ssd", buf, file, line );
  return;
}

int rhp_trace_save( char* output_file )
{
  int err = 0;
  FILE* ofd = NULL;
  size_t st;
  ssize_t st2;
  char d_buffer[RHP_TRC_READ_BUFFER_SIZE];
  unsigned long reading = 0;

  ofd = fopen( output_file, "w" );
  if(ofd == NULL){
    err = errno;
    printf( " Fail to open %s. %s \n", output_file, strerror( err ) );
    goto error;
  }

  {
    unsigned int magic;

    magic = RHP_TRC_FILE_MAGIC0;

    st = fwrite( (void*) &magic, sizeof(magic), 1, ofd );
    if(st < 1){
      err = ferror( ofd );
      printf( " Fail to write magic.(1) %s , %s \n", output_file,
          strerror( err ) );
      goto error;
    }

    magic = RHP_TRC_FILE_MAGIC1;

    st = fwrite( (void*) &magic, sizeof(magic), 1, ofd );
    if(st < 1){
      err = ferror( ofd );
      printf( " Fail to write magic.(2) %s , %s \n", output_file,
          strerror( err ) );
      goto error;
    }
  }

  reading = 1;
  if(ioctl( _rhp_trc_devfd, RHP_TRC_IOCTRL_READING_ID, reading )){
    err = errno;
    printf( " Fail to set READING flag %s. %s \n", output_file, strerror( err ) );
    goto error;
  }

  while((st2
      = read( _rhp_trc_devfd, (void*) d_buffer, RHP_TRC_READ_BUFFER_SIZE)) > 0){

    st = fwrite( (void*) d_buffer, st2, 1, ofd );
    if(st < 1){
      err = ferror( ofd );
      printf( " Fail to write buffer. %s , %s \n", output_file, strerror( err ) );
      goto error;
    }
  }

  if(st2 < 0){
    err = errno;
    printf( " Fail to read /dev/rhp_trace. %s \n", strerror( err ) );
    goto error;
  }

  error: {
    if(reading){

      reading = 0;

      if(ioctl( _rhp_trc_devfd, RHP_TRC_IOCTRL_READING_ID, reading )){
        err = errno;
        printf( " Fail to reset READING flag %s. %s \n", output_file, strerror(
            err ) );
      }
    }
  }

  if(ofd){
    fclose( ofd );
  }
  return err;
}

int rhp_trace_init()
{
  int err = 0;

  if( _rhp_trc_f_fd != -1 ){
  	return -EINVAL;
  }

  if( _rhp_trc_devfd != -1 ){
  	return -EINVAL;
  }

  _rhp_trc_devfd = open( "/dev/rhp_trace", O_RDWR);
  if(_rhp_trc_devfd < 0){
    err = errno;
    printf( " Fail to open /dev/rhp_trace. %s. \n", strerror( err ) );
    goto error;
  }

  if(ioctl( _rhp_trc_devfd, RHP_TRC_IOCTRL_GET_SHMID_ID, &_rhp_shm_id )){
    err = errno;
    printf( " Fail to get trace shm_id. %s \n", strerror( err ) );
    goto error;
  }

  if(_rhp_shm_id < 0){
    err = -ENOENT;
    printf( " Trace shm_id not initialized. \n" );
    goto error;
  }

  rhp_trace_flag = (unsigned char*) shmat( _rhp_shm_id, NULL, SHM_RDONLY );
  if(rhp_trace_flag == ((void*)-1)){
    err = errno;
    printf( " Fail to shmat. shm_id:%d , %s(%d) \n", _rhp_shm_id,
        strerror( err ), err );
    goto error;
  }

  memset( _rhp_dmy_invalid_data, 0, RHP_TRC_LIB_INVALID_DATA_LEN);
  _rhp_dmy_invalid_data[0] = 'I';
  _rhp_dmy_invalid_data[1] = 'N';
  _rhp_dmy_invalid_data[2] = 'V';
  _rhp_dmy_invalid_data[3] = 'A';
  _rhp_dmy_invalid_data[4] = 'L';
  _rhp_dmy_invalid_data[5] = 'I';
  _rhp_dmy_invalid_data[6] = 'D';
  _rhp_dmy_invalid_data[7] = ' ';
  _rhp_dmy_invalid_data[8] = 'D';
  _rhp_dmy_invalid_data[9] = 'A';
  _rhp_dmy_invalid_data[10] = 'T';
  _rhp_dmy_invalid_data[11] = 'A';
  _rhp_dmy_invalid_data[12] = '!';

  return 0;

error:
	if(rhp_trace_flag != ((void*) -1)){
    shmdt( rhp_trace_flag );
    rhp_trace_flag = ((void*) -1);
  }
  if(_rhp_trc_devfd >= 0){
    close( _rhp_trc_devfd );
    _rhp_trc_devfd = -1;
  }
  return -1;
}

void rhp_trace_cleanup()
{
  if( _rhp_trc_f_fd != -1 ){
  	return;
  }

  if( _rhp_trc_devfd == -1 ){
  	return;
  }


  if(rhp_trace_flag != ((void*)-1)){
    shmdt( rhp_trace_flag );
    rhp_trace_flag = ((void*)-1);
  }

  if(_rhp_trc_devfd >= 0){
    close( _rhp_trc_devfd );
    _rhp_trc_devfd = -1;
  }
}




static void _rhp_trace_f_record_len(off_t record_pos,unsigned long* len)
{
	off_t buffer_end_pos = _rhp_trc_f_buffer_len;

  if( record_pos + sizeof(unsigned long) <= buffer_end_pos ){

  	unsigned long record_len_buf;

  	lseek(_rhp_trc_f_fd,(record_pos + RHP_TRC_F_FILE_HEADER_OFFSET),SEEK_SET);
  	read(_rhp_trc_f_fd,&record_len_buf,sizeof(unsigned long));

  	*len = record_len_buf;

  }else{

    int i;
    unsigned char* lenp = (unsigned char*)len;

    for( i = 0; i < sizeof(unsigned long); i++ ){

      unsigned char record_len_buf;

      lseek(_rhp_trc_f_fd,(record_pos + RHP_TRC_F_FILE_HEADER_OFFSET),SEEK_SET);
      read(_rhp_trc_f_fd,&record_len_buf,sizeof(unsigned char));

      lenp[i] = record_len_buf;

      if( ++record_pos >= buffer_end_pos ){
      	record_pos = 0;
      }
    }
  }

  return;
}


static void _rhp_trace_f_write_data(unsigned char* data,unsigned long len,
    unsigned long* record_len,off_t* oldpos)
{
  unsigned long oldest_record_len;
  unsigned long oldest_record_pos;
	off_t buffer_end_pos = _rhp_trc_f_buffer_len;
  off_t record_end_pos;

  if( data == NULL || len == 0 || *record_len + len > _rhp_trc_f_buffer_len ){
    return;
  }

  while( _rhp_trc_f_current_len + len > _rhp_trc_f_buffer_len ){

    oldest_record_pos = _rhp_trc_f_record_head_pos;

    _rhp_trace_f_record_len(oldest_record_pos, &oldest_record_len);

    _rhp_trc_f_record_head_pos += oldest_record_len;

    if( _rhp_trc_f_record_head_pos >= buffer_end_pos ){
    	_rhp_trc_f_record_head_pos = (_rhp_trc_f_record_head_pos - buffer_end_pos);
    }

    _rhp_trc_f_current_len -= oldest_record_len;
  }

  if( oldpos ){
    *oldpos = _rhp_trc_f_record_tail_pos;
  }

  record_end_pos = _rhp_trc_f_record_tail_pos + len;
  if( record_end_pos >= buffer_end_pos ){

    unsigned long part_len = buffer_end_pos - _rhp_trc_f_record_tail_pos;
    unsigned long rem = len;

    lseek(_rhp_trc_f_fd,(_rhp_trc_f_record_tail_pos + RHP_TRC_F_FILE_HEADER_OFFSET),SEEK_SET);
    write(_rhp_trc_f_fd,data,part_len);
    data += part_len;
    rem -= part_len;

    _rhp_trc_f_record_tail_pos = 0;

    if(rem){
      lseek(_rhp_trc_f_fd,(_rhp_trc_f_record_tail_pos + RHP_TRC_F_FILE_HEADER_OFFSET),SEEK_SET);
      write(_rhp_trc_f_fd,data,rem);
      _rhp_trc_f_record_tail_pos += rem;
    }

  }else{

    lseek(_rhp_trc_f_fd,(_rhp_trc_f_record_tail_pos + RHP_TRC_F_FILE_HEADER_OFFSET),SEEK_SET);
    write(_rhp_trc_f_fd,data,len);
    _rhp_trc_f_record_tail_pos += len;
  }

  *record_len += len;
  _rhp_trc_f_current_len += len;

  return;
}

static ssize_t _rhp_trc_f_write(unsigned char* record_buf,int record_buf_len)
{
  rhp_trace_record* record = (rhp_trace_record*)record_buf;
  unsigned long record_len = 0;
  off_t record_head_pos = 0;
  off_t buffer_end_pos = _rhp_trc_f_buffer_len;
  rhp_trace_f_file_header f_header;


  if( record_buf_len < sizeof(rhp_trace_record) ){
    return -EMSGSIZE;
  }

  if( record_buf_len > RHP_TRC_READ_BUFFER_SIZE ){
    return -EMSGSIZE;
  }

  gettimeofday(&(record->timestamp),NULL);

  if( record->len < sizeof(rhp_trace_record) ){
    return -EMSGSIZE;
  }

  if( record->len > _rhp_trc_f_buffer_len ){
    return -EMSGSIZE;
  }

  if( record->len > RHP_TRC_READ_BUFFER_SIZE ){
    return -EMSGSIZE;
  }


 	pthread_mutex_lock(&_rhp_trc_f_mutex);

  _rhp_trace_f_write_data((unsigned char*)record,sizeof(rhp_trace_record),&record_len,(off_t*)&record_head_pos);
  if( record->len > sizeof(rhp_trace_record) ){
  	_rhp_trace_f_write_data((unsigned char*)(record + 1),(record->len - sizeof(rhp_trace_record)),&record_len,NULL);
  }

  if( record_head_pos + sizeof(unsigned long) <= buffer_end_pos ){

    lseek(_rhp_trc_f_fd,(record_head_pos + RHP_TRC_F_FILE_HEADER_OFFSET),SEEK_SET);
    write(_rhp_trc_f_fd,(void*)&record_len,sizeof(unsigned long));

  } else{

    int i;
    unsigned char* lenp = (unsigned char*)&record_len;

    for( i = 0; i < sizeof(unsigned long);i++ ){

      lseek(_rhp_trc_f_fd,(record_head_pos + RHP_TRC_F_FILE_HEADER_OFFSET),SEEK_SET);
      write(_rhp_trc_f_fd,(void*)&(lenp[i]),sizeof(unsigned char));

      if( ++record_head_pos >= buffer_end_pos ){
      	record_head_pos = 0;
      }
    }
  }


  f_header.record_head_pos = _rhp_trc_f_record_head_pos;
  f_header.record_tail_pos = _rhp_trc_f_record_tail_pos;
  f_header.buffer_len = _rhp_trc_f_buffer_len;
  f_header.current_len = _rhp_trc_f_current_len;

  lseek(_rhp_trc_f_fd,sizeof(unsigned int)*2,SEEK_SET); // unsigned int*2 : MAGIC Numbers
  write(_rhp_trc_f_fd,(void*)&f_header,sizeof(rhp_trace_f_file_header));


  pthread_mutex_unlock(&_rhp_trc_f_mutex);

  return record_buf_len;
}


int rhp_trace_f_init(char* trace_path,long max_file_size)
{
  int err = 0;
  rhp_trace_f_file_header f_header;

  if( _rhp_trc_devfd != -1 ){
  	return -EINVAL;
  }

  if( _rhp_trc_f_fd != -1 ){
  	return -EINVAL;
  }

  unlink(trace_path);

  _rhp_trc_f_fd = open(trace_path,(O_RDWR | O_CREAT | O_TRUNC),S_IRWXU);
  if(_rhp_trc_f_fd < 0){
    err = errno;
    printf("Fail to open %s. %s. \n", trace_path, strerror( err ));
    goto error;
  }

  if( max_file_size < RHP_TRC_F_MIN_FILE_SIZE ){
  	max_file_size = RHP_TRC_F_MIN_FILE_SIZE;
  }
  _rhp_trc_f_buffer_len = max_file_size;


  rhp_trace_flag = (unsigned char*)malloc(sizeof(unsigned char)*RHP_TRC_MAX_USERS);
  if(rhp_trace_flag == NULL){
    err = errno;
    printf( " Fail to alloc trace_flag buf. %s, %s(%d) \n",trace_path,strerror( err ),err);
    goto error;
  }

  memset(rhp_trace_flag,0xFF,sizeof(unsigned char)*RHP_TRC_MAX_USERS);


  {
    unsigned int magic;

    magic = RHP_TRC_FILE_MAGIC0;
    write(_rhp_trc_f_fd,(void*)&magic,sizeof(unsigned int));

    magic = RHP_TRC_FILE_MAGIC2;
    write(_rhp_trc_f_fd,(void*)&magic,sizeof(unsigned int));

    f_header.record_head_pos = _rhp_trc_f_record_head_pos;
    f_header.record_tail_pos = _rhp_trc_f_record_tail_pos;
    f_header.buffer_len = _rhp_trc_f_buffer_len;
    f_header.current_len = _rhp_trc_f_current_len;

    write(_rhp_trc_f_fd,(void*)&f_header,sizeof(rhp_trace_f_file_header));
  }


  memset( _rhp_dmy_invalid_data, 0, RHP_TRC_LIB_INVALID_DATA_LEN);
  _rhp_dmy_invalid_data[0] = 'I';
  _rhp_dmy_invalid_data[1] = 'N';
  _rhp_dmy_invalid_data[2] = 'V';
  _rhp_dmy_invalid_data[3] = 'A';
  _rhp_dmy_invalid_data[4] = 'L';
  _rhp_dmy_invalid_data[5] = 'I';
  _rhp_dmy_invalid_data[6] = 'D';
  _rhp_dmy_invalid_data[7] = ' ';
  _rhp_dmy_invalid_data[8] = 'D';
  _rhp_dmy_invalid_data[9] = 'A';
  _rhp_dmy_invalid_data[10] = 'T';
  _rhp_dmy_invalid_data[11] = 'A';
  _rhp_dmy_invalid_data[12] = '!';


  pthread_mutex_init(&_rhp_trc_f_mutex,NULL);

  return 0;

error:
	if(rhp_trace_flag){
		free(rhp_trace_flag);
    rhp_trace_flag = ((void*)-1);
  }
  if(_rhp_trc_f_fd >= 0){
    close( _rhp_trc_f_fd );
    _rhp_trc_f_fd = -1;
  }
  return -1;
}

void rhp_trace_f_cleanup()
{
  if( _rhp_trc_devfd != -1 ){
  	return;
  }

  if( _rhp_trc_f_fd == -1 ){
  	return;
  }

	if(rhp_trace_flag){
		free(rhp_trace_flag);
    rhp_trace_flag = ((void*)-1);
  }

  if(_rhp_trc_f_fd >= 0){
  	fsync(_rhp_trc_f_fd);
    close( _rhp_trc_f_fd );
    _rhp_trc_f_fd = -1;
  }

  pthread_mutex_destroy(&_rhp_trc_f_mutex);
}


int rhp_trace_write_to_dev(char* message)
{
	int fd;

	fd = open("/dev/rhp_file_trace",O_WRONLY);
	if( fd >= 0 ){
		write(fd,message,strlen(message)+1);
		close(fd);
		return 0;
	}

	return -EINVAL;
}



void rhp_trace_write_enable(int flag)
{
	if( !rhp_trace_write_disabled || !flag ){
		return;
	}
	rhp_trace_write_disabled = 0;
}

void rhp_trace_write_disable(int flag)
{
	if( rhp_trace_write_disabled || !flag ){
		return;
	}
	rhp_trace_write_disabled = 1;
}

