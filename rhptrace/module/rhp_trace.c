/*

 Copyright (C) 2010-2012 TETSUHARU HANADA <rhpenguine@gmail.com>
 All rights reserved.

 You can redistribute and/or modify this software under the
 LESSER GPL version 2.1.
 See also LICENSE.txt and LICENSE_LGPL2.1.txt.

 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <asm/uaccess.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/vmalloc.h>
#include <linux/kmod.h>
#include <linux/random.h>
#include <linux/semaphore.h>
#include <linux/sched.h>
#include <linux/miscdevice.h>

#include "rhp_trace.h"

MODULE_DESCRIPTION("Debug Trace module for Rockhopper.");
MODULE_AUTHOR("T.Hanada");
MODULE_LICENSE("GPL");

#ifdef RHP_TRACE_DEBUG
#define DBG(...) printk(__VA_ARGS__)
#else // RHP_TRACE_DEBUG
#define DBG(...) do{}while(0);
#endif // RHP_TRACE_DEBUG
#define ERR(...) printk(__VA_ARGS__)

#ifdef RHP_TRACE_DEBUG
static void _rhp_bin_dump(char* tag,char* d,int len)
{
  int i,j;
  char* mc = d;

  DBG("[%s] len : %d\n",tag,len);
  DBG("*0 *1 *2 *3 *4 *5 *6 *7 *8 *9 *A *B *C *D *E *F     0123456789ABCDEF\n");

  for( i = 0;i < len; i++ ){

    int pd;

    if( i && (i % 16) == 0 ){

      DBG("    ");
      for( j = 0;j < 16; j++ ){

        if( *mc >= 33 && *mc <= 126 ){
          DBG("%c",*mc);
        } else{
          DBG(".");
        }

        mc++;
      }

      DBG("\n");
    }

    pd = ((*(int*)d) & 0x000000FF);

    if( pd <= 0x0F ){
      DBG("0");
    }

    DBG("%x ",pd);
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
      DBG("   ");
    }

    DBG("    ");

    for( j = 0;j < k2; j++ ){

      if( *mc >= 33 && *mc <= 126 ){
        DBG("%c",*mc);
      } else{
        DBG(".");
      }

      mc++;
    }
  }

  DBG("\n");
  return;
}
#endif // RHP_TRACE_DEBUG
/*
 #define _rhp_spin_lock_bh(lock)\
{\
  DBG("LOCK-I:0x%x(%d,%s:%d)\n",(unsigned int)lock,current->pid,__FILE__,__LINE__);\
  spin_lock_bh(lock);\
  DBG("LOCK-O:0x%x(%d,%s:%d)\n",(unsigned int)lock,current->pid,__FILE__,__LINE__);\
}

 #define _rhp_spin_unlock_bh(lock) \
{\
  DBG("UNLOCK-I:0x%x(%d,%s:%d)\n",(unsigned int)lock,current->pid,__FILE__,__LINE__);\
  spin_unlock_bh(lock);\
  DBG("UNLOCK-O:0x%x(%d,%s:%d)\n",(unsigned int)lock,current->pid,__FILE__,__LINE__);\
}
 */

#define _rhp_spin_lock_bh(lock)\
{\
  spin_lock_bh((lock));\
}

#define _rhp_spin_unlock_bh(lock) \
{\
  spin_unlock_bh((lock));\
}

#if 0
static unsigned int _rhp_trc_buffer_order = 0;
#endif // 0
unsigned char* rhp_trc_buffer = NULL;
unsigned long rhp_trc_buffer_len = 0;
unsigned char* rhp_trc_record_head = NULL;
unsigned char* rhp_trc_record_tail = NULL;
static unsigned long _rhp_trc_current_len = 0;

static unsigned char* rhp_trc_read_p = NULL;
static unsigned long rhp_trc_read_len = 0;
static pid_t rhp_trc_reader_pid = 0;

static spinlock_t _rhp_trc_lock;

static rhp_trace_setup _rhp_trc_setup;
static atomic_t _rhp_trc_active;

static atomic_t _rhp_trc_heler_notification;

static atomic_t _rhp_trc_reading;

struct _rhp_trace_fd_priv {
  struct _rhp_trace_fd_priv* next;
  wait_queue_head_t wait;
  pid_t is_helper;
  char* file_buf;
  int file_buf_len;
};
typedef struct _rhp_trace_fd_priv rhp_trace_fd_priv;

static atomic_t _rhp_trc_users;
static rhp_trace_fd_priv* _rhp_trc_priv_head = NULL;

static unsigned char _rhp_trace_flag[RHP_TRC_MAX_USERS];
unsigned char *rhp_trace_flag = _rhp_trace_flag;

static int _rhp_trace_shm_id = -1;

static int no_caps_check = 0;
module_param( no_caps_check, int, S_IRUGO );

static inline int _rhp_trace_capable( void )
{
  if(no_caps_check){
    return 1;
  }

  if(!capable( CAP_SYS_ADMIN )){
    return 0;
  }

  return 1;
}

static inline int _rhp_trace_alloc_vmalloc( unsigned long size )
{
  unsigned char* new_buffer;
  unsigned char* old_buffer;

  if(size < RHP_TRC_BUFFER_MIN_SIZE){
    size = RHP_TRC_BUFFER_MIN_SIZE;
  }

  new_buffer = (unsigned char*) vmalloc( size );
  if(new_buffer == NULL){
    ERR("<RHP_TRACE>" "Fail to alloc trace buffer.\n");
    return -ENOMEM;
  }

  memset( new_buffer, 0, size );

  old_buffer = rhp_trc_buffer;

  _rhp_spin_lock_bh(&_rhp_trc_lock);

  rhp_trc_buffer = new_buffer;

  rhp_trc_buffer_len = size;

  rhp_trc_record_head = rhp_trc_buffer;
  rhp_trc_record_tail = rhp_trc_buffer;

  _rhp_trc_current_len = 0;

  _rhp_spin_unlock_bh(&_rhp_trc_lock);

  if(old_buffer){
    vfree( old_buffer );
  }

  return 0;
}

static void _rhp_trace_record_len( char* label, unsigned char* record, unsigned long* len )
{
  unsigned char* buffer_end = rhp_trc_buffer + rhp_trc_buffer_len;
  int pcase = 0;

  if(record + sizeof(unsigned long) <= buffer_end){
    *len = ((rhp_trace_record*) record)->len;
  }else{

    unsigned char* lenp = (unsigned char*) len;
    int i;

    pcase = 1;

    for(i = 0; i < sizeof(unsigned long); i++){

      lenp[i] = *record;

      if(++record >= buffer_end){
        record = rhp_trc_buffer;
      }
    }
  }

  if( *len < sizeof(rhp_trace_record) ){
    ERR("<RHP_TRACE>""_rhp_trace_record_len(%s:%d): Invalid buffer RecordLen: %lu, rhp_trace_record:%u \n",label,pcase,*len,sizeof(rhp_trace_record));
  }

  if( *len > RHP_TRC_READ_BUFFER_SIZE ){
  	ERR("<RHP_TRACE>""_rhp_trace_record_len(%s:%d): RecordLen too long %lu > %u(RHP_TRC_READ_BUFFER_SIZE) \n",label,pcase,*len,RHP_TRC_READ_BUFFER_SIZE);
  }

  if( *len > rhp_trc_buffer_len ){
  	ERR("<RHP_TRACE>""_rhp_trace_record_len(%s:%d) : RecordLen too long %lu > %lu \n",label,pcase,*len,rhp_trc_buffer_len);
  }

  return;
}

static ssize_t _rhp_trace_copy_record_to_user( unsigned char* record,
    unsigned long len, unsigned char* user_buf )
{
  int i;
  ssize_t ret = 0;
  unsigned char* buffer_end = rhp_trc_buffer + rhp_trc_buffer_len;

  for( i = 0; i < len; i++ ){

    if( copy_to_user( user_buf++, record++, sizeof(unsigned char) ) ){

      ERR("<RHP_TRACE>""_rhp_trace_copy_record_to_user : -EFAULT! record:0x%x , buffer_end:0x%x , ret:%d , rhp_trc_buffer:0x%x , rhp_trc_buffer_len:%d , user_buf:0x%x , i:%d . len:%lu\n",
          (unsigned long)record,(unsigned long)buffer_end,(unsigned int)ret,(unsigned long)rhp_trc_buffer,(unsigned int)rhp_trc_buffer_len,(unsigned long)user_buf,i,len);

      ret = -EFAULT;
      break;
    }

    if( record >= buffer_end ){
      DBG("<RHP_TRACE>""_rhp_trace_copy_record_to_user : record:0x%x > buffer_end:0x%x\n",(unsigned long)record,(unsigned long)buffer_end);
      record = rhp_trc_buffer;
    }

    ret++;
  }

  return ret;
}

static void _rhp_trace_write_data( unsigned char* data, unsigned long len,
    unsigned long* record_len, unsigned char** oldpos )
{
  unsigned long oldest_record_len;
  unsigned char* oldest_record;
  unsigned char* buffer_end = rhp_trc_buffer + rhp_trc_buffer_len;
  unsigned char* record_end;

#ifdef RHP_TRACE_DEBUG
  //  _rhp_bin_dump("data",data,len);
  //  _rhp_bin_dump("RHP_TRACE1",rhp_trc_buffer,512);
#endif // RHP_TRACE_DEBUG
  if(data == NULL || len == 0 || *record_len + len > rhp_trc_buffer_len){
    ERR("<RHP_TRACE>""_rhp_trace_write_data :  data:0x%lx, len: %lu, (*record_len + len):%lu > rhp_trc_buffer_len:%lu\n",(unsigned long)data,len,(*record_len + len),rhp_trc_buffer_len);
    return;
  }

  while(_rhp_trc_current_len + len > rhp_trc_buffer_len){

    oldest_record = (unsigned char*) rhp_trc_record_head;

    _rhp_trace_record_len( "W", oldest_record, &oldest_record_len );

    rhp_trc_record_head += oldest_record_len;

    if(rhp_trc_record_head >= buffer_end){
      rhp_trc_record_head = rhp_trc_buffer + (rhp_trc_record_head - buffer_end);
    }

    _rhp_trc_current_len -= oldest_record_len;
  }

  if(oldpos){
    *oldpos = rhp_trc_record_tail;
  }

  record_end = rhp_trc_record_tail + len;
  if(record_end >= buffer_end){

    unsigned long part_len = buffer_end - rhp_trc_record_tail;
    unsigned long rem = len;

    memcpy( rhp_trc_record_tail, data, part_len );
    data += part_len;
    rem -= part_len;
    rhp_trc_record_tail = rhp_trc_buffer;

    if(rem){
      memcpy( rhp_trc_record_tail, data, rem );
      rhp_trc_record_tail += rem;
    }

  }else{
    memcpy( rhp_trc_record_tail, data, len );
    rhp_trc_record_tail += len;
  }

  *record_len += len;
  _rhp_trc_current_len += len;

#ifdef RHP_TRACE_DEBUG
  //  _rhp_bin_dump("RHP_TRACE2",rhp_trc_buffer,256);
#endif // RHP_TRACE_DEBUG
  return;
}

void rhp_trace( unsigned char userid, unsigned long record_id, ... )
{
  va_list args;
  rhp_trace_record record;
  unsigned long record_len = 0;
  int b;
  int w;
  u32 d;
  u64 q;
  unsigned char* s;
  u32 lm;
  unsigned char* record_head;
  unsigned char* buffer_end = rhp_trc_buffer + rhp_trc_buffer_len;
  unsigned char* bm = NULL;
  unsigned char dc = '\0';
  char* fmt;

  if(!atomic_read( &_rhp_trc_active )){
    return;
  }

  if(atomic_read( &_rhp_trc_reading )){
    return;
  }

  _rhp_spin_lock_bh(&_rhp_trc_lock);

  record.len = 0;
  record.record_id = (((unsigned long) userid) << 24) | record_id;
  record.pid = current->pid;
  record.tid = 0;

  do_gettimeofday( &record.timestamp );

  _rhp_trace_write_data( (unsigned char*) &record, sizeof(record), &record_len,&record_head );

  va_start( args, record_id );
  fmt = va_arg(args,char*);
  while(*fmt != '\0'){

    switch(*fmt){

    case 'b':

      b = va_arg(args,int);
      _rhp_trace_write_data( (unsigned char*) ((u8*) &b), sizeof(u8),&record_len, NULL );

      break;

    case 'w':

      w = va_arg(args,int);
      _rhp_trace_write_data( (unsigned char*) ((u16*) &w), sizeof(u16),&record_len, NULL );

      break;

    case 'd':

      d = va_arg( args, u32 );
      _rhp_trace_write_data( (unsigned char*) &d, sizeof(d), &record_len, NULL );

      break;

    case 'q':

      q = va_arg( args, u64 );
      _rhp_trace_write_data( (unsigned char*) &q, sizeof(q), &record_len, NULL );

      break;

    case 's':

      s = va_arg(args,unsigned char *);
      if(s == NULL){
        _rhp_trace_write_data( &dc, 1, &record_len, NULL );
      }else{

        int s_len = 0;
        int s_err = 0;

        for(s_len = 0; s_len < RHP_TRC_MAX_STRING_SIZE; s_len++){

          if(s[s_len] == '\0'){
            break;
          }

          if(s[s_len] > 127){
            s_err = 1;
            break;
          }
        }

        if(s_len >= RHP_TRC_MAX_STRING_SIZE || s_err){
          _rhp_trace_write_data( &dc, 1, &record_len, NULL );
        }else{
          s_len++;
          _rhp_trace_write_data( (unsigned char*) s, s_len, &record_len, NULL );
        }
      }

      break;

    case 'p':

      lm = va_arg( args, u32 );
      bm = va_arg(args,unsigned char *);

      if(bm == NULL){
        lm = 0;
      }

      _rhp_trace_write_data( (unsigned char*) &lm, sizeof(lm), &record_len,
          NULL );

      if(bm){
        _rhp_trace_write_data( bm, lm, &record_len, NULL );
      }

      break;

    default:
      break;
    }

    fmt++;
  }
  va_end( args );

  if(record_head + sizeof(unsigned long) <= buffer_end){

    ((rhp_trace_record*) record_head)->len = record_len;

  }else{

    unsigned char* lenp = (unsigned char*) &record_len;
    int i;

    for(i = 0; i < sizeof(unsigned long); i++){

      *record_head = lenp[i];

      if(++record_head >= buffer_end){
        record_head = rhp_trc_buffer;
      }
    }
  }

  _rhp_spin_unlock_bh(&_rhp_trc_lock);
  return;
}

static int _rhp_trc_chrdev_open( struct inode* inodep, struct file* filep )
{
  rhp_trace_fd_priv* priv;

  if(rhp_trc_record_head == NULL){
    ERR("<RHP_TRACE>" "_rhp_trc_chrdev_open : No memory(1). \n");
    return -ENOMEM;
  }

  priv = (rhp_trace_fd_priv*) kmalloc( sizeof(rhp_trace_fd_priv), GFP_KERNEL );

  if(priv == NULL){
    ERR("<RHP_TRACE>" "_rhp_trc_chrdev_open : No memory(2). \n");
    return -ENOMEM;
  }

  memset( priv, 0, sizeof(rhp_trace_fd_priv) );

  init_waitqueue_head( &priv->wait );

  _rhp_spin_lock_bh(&_rhp_trc_lock);
  priv->next = _rhp_trc_priv_head;
  _rhp_trc_priv_head = priv;
  atomic_inc( &_rhp_trc_users );
  _rhp_spin_unlock_bh(&_rhp_trc_lock);

  filep->private_data = priv;

  DBG("<RHP_TRACE>""_rhp_trc_chrdev_open called. \n");

  return 0;
}

static int _rhp_trc_chrdev_release( struct inode* inodep, struct file* filep )
{
  int err = 0;
  rhp_trace_fd_priv* priv = (rhp_trace_fd_priv*) filep->private_data;

  _rhp_spin_lock_bh(&_rhp_trc_lock);
  {

    rhp_trace_fd_priv *tmp = _rhp_trc_priv_head, *tmp2 = NULL;

    while(tmp){

      if(tmp == priv){
        break;
      }

      tmp2 = tmp;
      tmp = tmp->next;
    }

    if(tmp == NULL){
      _rhp_spin_unlock_bh(&_rhp_trc_lock);
      err = -ENOENT;
      ERR("<RHP_TRACE>""_rhp_trc_chrdev_release : No priv found.");
      goto error;
    }

    if(tmp2){
      tmp2->next = tmp->next;
    }else{
      _rhp_trc_priv_head = tmp->next;
    }

    filep->private_data = NULL;
    kfree( tmp );

    atomic_dec( &_rhp_trc_users );
  }
  _rhp_spin_unlock_bh(&_rhp_trc_lock);

  DBG("<RHP_TRACE>""_rhp_trc_chrdev_release called. \n");

  error: return err;
}

static int _rhp_trc_chrdev_file_open( struct inode* inodep, struct file* filep )
{
  rhp_trace_fd_priv* priv;

  if(rhp_trc_record_head == NULL){
    ERR("<RHP_TRACE>" "_rhp_trc_chrdev_file_open : No memory(1). \n");
    return -ENOMEM;
  }

  priv = (rhp_trace_fd_priv*) kmalloc( sizeof(rhp_trace_fd_priv), GFP_KERNEL );

  if(priv == NULL){
    ERR("<RHP_TRACE>" "_rhp_trc_chrdev_file_open : No memory(2). \n");
    return -ENOMEM;
  }

  memset( priv, 0, sizeof(rhp_trace_fd_priv) );

  priv->file_buf = (char*) vmalloc( RHP_TRACE_FILE_BUF_LEN + 1 );
  if(priv->file_buf == NULL){
    kfree( priv );
    ERR("<RHP_TRACE>" "_rhp_trc_chrdev_file_open : No memory(3). \n");
    return -ENOMEM;
  }
  memset( priv->file_buf, '\0', RHP_TRACE_FILE_BUF_LEN + 1 );

  init_waitqueue_head( &priv->wait );

  _rhp_spin_lock_bh(&_rhp_trc_lock);
  priv->next = _rhp_trc_priv_head;
  _rhp_trc_priv_head = priv;
  atomic_inc( &_rhp_trc_users );
  _rhp_spin_unlock_bh(&_rhp_trc_lock);

  filep->private_data = priv;

  DBG("<RHP_TRACE>""_rhp_trc_chrdev_file_open called. \n");
  return 0;
}

static int _rhp_trc_chrdev_file_release( struct inode* inodep,
    struct file* filep )
{
  int err = 0;
  rhp_trace_fd_priv* priv = (rhp_trace_fd_priv*) filep->private_data;

  if(priv->file_buf_len){
    rhp_trace( RHP_TRC_USER_TRACE_FILE, 1, "p", priv->file_buf_len + 1,
        priv->file_buf );
  }

  vfree( priv->file_buf );

  priv->file_buf = NULL;
  priv->file_buf_len = 0;

  _rhp_spin_lock_bh(&_rhp_trc_lock);
  {
    rhp_trace_fd_priv *tmp = _rhp_trc_priv_head, *tmp2 = NULL;

    while(tmp){

      if(tmp == priv){
        break;
      }

      tmp2 = tmp;
      tmp = tmp->next;
    }

    if(tmp == NULL){
      _rhp_spin_unlock_bh(&_rhp_trc_lock);
      err = -ENOENT;
      ERR("<RHP_TRACE>" "_rhp_trc_chrdev_file_release: No priv found.\n");
      goto error;
    }

    if(tmp2){
      tmp2->next = tmp->next;
    }else{
      _rhp_trc_priv_head = tmp->next;
    }

    filep->private_data = NULL;
    kfree( tmp );

    atomic_dec( &_rhp_trc_users );
  }
  _rhp_spin_unlock_bh(&_rhp_trc_lock);

  DBG("<RHP_TRACE>""_rhp_trc_chrdev_file_release called. \n");

  error: return err;
}

static int _rhp_trc_handle_helper( int cmd, rhp_trace_fd_priv* priv,
    unsigned long arg )
{
  rhp_trace_helper_params params;

  ERR("<RHP_TRACE>""_rhp_trc_handle_helper called. \n");

  if(!_rhp_trace_capable()){
    ERR("<RHP_TRACE>""_rhp_trc_handle_helper : Not SYS_ADMIN \n");
    return -EPERM;
  }

  if(!atomic_read( &_rhp_trc_active )){
    ERR("<RHP_TRACE>""_rhp_trc_handle_helper : Not active... \n");
    return -EPERM;
  }

  if(copy_from_user( &params, (void*) arg, sizeof(rhp_trace_helper_params) )){
    ERR("<RHP_TRACE>""_rhp_trc_handle_helper : Fail to copy_from_user.. \n");
    return -EFAULT;
  }

  if(cmd == RHP_TRC_IOCTRL_HELPER){

    if(priv->is_helper == 0 || priv->is_helper != current->pid){
      ERR("<RHP_TRACE>""_rhp_trc_handle_helper : Invalid Helper PID... \n");
      return -EPERM;
    }

    while(atomic_read( &_rhp_trc_heler_notification ) == 0){

      if(wait_event_interruptible( priv->wait, (atomic_read(
          &_rhp_trc_heler_notification ) != 0) )){
        return -EINTR;
      }
    }

    if(!atomic_read( &_rhp_trc_active )){
      // while sleeping , state has changed...
      ERR("<RHP_TRACE>""_rhp_trc_handle_helper : Already disabled. \n");
      return -ENODEV;
    }

    _rhp_spin_lock_bh(&_rhp_trc_lock);

    memcpy( params.trace_flag, rhp_trace_flag, sizeof(unsigned char)
        * RHP_TRC_MAX_USERS);

    _rhp_spin_unlock_bh(&_rhp_trc_lock);

    if(copy_to_user( (void*) arg, &params, sizeof(rhp_trace_helper_params) )){
      ERR("<RHP_TRACE>""_rhp_trc_handle_helper : Fail to copy_to_user.. \n");
      return -EFAULT;
    }

    atomic_dec( &_rhp_trc_heler_notification );

  }else if(cmd == RHP_TRC_IOCTRL_START_HELPER){

    if(params.shm_id >= 0){

      rhp_trace_fd_priv* priv2;

      _rhp_spin_lock_bh(&_rhp_trc_lock);

      priv2 = _rhp_trc_priv_head;

      while(priv2){

        if(priv2->is_helper){
          _rhp_spin_unlock_bh(&_rhp_trc_lock);
          ERR("<RHP_TRACE>""_rhp_trc_handle_helper : Helper already exists \n");
          return -EPERM;
        }

        priv2 = priv2->next;
      }

      _rhp_trace_shm_id = params.shm_id;

      priv->is_helper = current->pid;

      memcpy( params.trace_flag, rhp_trace_flag, sizeof(unsigned char)
          * RHP_TRC_MAX_USERS);

      _rhp_spin_unlock_bh(&_rhp_trc_lock);

      if(copy_to_user( (void*) arg, &params, sizeof(rhp_trace_helper_params) )){
        ERR("<RHP_TRACE>""_rhp_trc_handle_helper : Fail to copy_to_user.. \n");
        return -EFAULT;
      }

    }else{
      ERR("<RHP_TRACE>""_rhp_trc_handle_helper : Invalid shm_id.. %d \n",params.shm_id);
      return -EINVAL;
    }
  }

  return 0;
}

static int _rhp_trc_handle_user( int cmd, rhp_trace_fd_priv* priv,
    unsigned long arg )
{

  if(!atomic_read( &_rhp_trc_active )){
    ERR("<RHP_TRACE>""_rhp_trc_handle_user : Not active,yet.\n");
    return -ENODEV;
  }

  if(cmd == RHP_TRC_IOCTRL_GET_SHMID){

    int* ret = (int*) arg;
    int shm_id;

    _rhp_spin_lock_bh(&_rhp_trc_lock);
    shm_id = _rhp_trace_shm_id;
    _rhp_spin_unlock_bh(&_rhp_trc_lock);

    if(shm_id >= 0){

      if(copy_to_user( ret, &shm_id, sizeof(_rhp_trace_shm_id) )){
        ERR("<RHP_TRACE>""_rhp_trc_handle_user : Bad user args.");
        return -EFAULT;
      }

    }else{
      ERR("<RHP_TRACE>""_rhp_trc_handle_user : Bad shm_id.");
      return -ENODEV;
    }

  }else{
    ERR("<RHP_TRACE>""_rhp_trc_handle_user : Invalid command.%d",cmd);
    return -EINVAL;
  }

  return 0;
}

#ifdef RHP_OBSOLETE_IOCTL
static int _rhp_trc_chrdev_ioctl( struct inode* inodep, struct file* filep,
    unsigned int code, unsigned long arg )
#else // RHP_OBSOLETE_IOCTL
static long _rhp_trc_chrdev_ioctl( struct file* filep,
    unsigned int code, unsigned long arg )
#endif // RHP_OBSOLETE_IOCTL
{
  int cmd = _IOC_NR( code );
  int err;
  rhp_trace_fd_priv* priv = (rhp_trace_fd_priv*) filep->private_data;
  rhp_trace_fd_priv* priv2 = NULL;

  DBG("<RHP_TRACE>""_rhp_trc_chrdev_ioctl called. cmd:%d , arg:0x%lu , pid:%d\n",cmd,arg,current->pid);

  if(priv == NULL){
    ERR("<RHP_TRACE>""_rhp_trc_chrdev_ioctl : priv == NULL \n");
    return -EINVAL;
  }

  if(cmd == RHP_TRC_IOCTRL_HELPER || cmd == RHP_TRC_IOCTRL_START_HELPER){
    return _rhp_trc_handle_helper( cmd, priv, arg );
  }

  if(cmd == RHP_TRC_IOCTRL_GET_SHMID){
    return _rhp_trc_handle_user( cmd, priv, arg );
  }

  if(!_rhp_trace_capable()){
    ERR("<RHP_TRACE>""_rhp_trc_chrdev_ioctl : Not SYS_ADMIN \n");
    return -EPERM;
  }

  if(cmd != RHP_TRC_IOCTRL_CLEAR && atomic_read( &_rhp_trc_reading )
      && current->pid != rhp_trc_reader_pid){
    ERR("<RHP_TRACE>""_rhp_trc_chrdev_ioctl : Now Busy... \n");
    return -EBUSY;
  }

  switch(cmd){

  case RHP_TRC_IOCTRL_START: {

    if(atomic_read( &_rhp_trc_active )){
      ERR("<RHP_TRACE>""_rhp_trc_chrdev_ioctl : [RHP_TRC_IOCTRL_START] Already active \n");
      return 0;
    }

    if(copy_from_user( &_rhp_trc_setup, (void*) arg, sizeof(_rhp_trc_setup) )){
      ERR("<RHP_TRACE>""_rhp_trc_chrdev_ioctl : [RHP_TRC_IOCTRL_START] Can't copy_from_user... \n");
      return -EFAULT;
    }

    atomic_set( &_rhp_trc_active, 1 );
    ERR("<RHP_TRACE>""_rhp_trc_chrdev_ioctl : [RHP_TRC_IOCTRL_START] \n");
  }
    break;

  case RHP_TRC_IOCTRL_STOP: {

    if(!atomic_read( &_rhp_trc_active )){
      ERR("<RHP_TRACE>""_rhp_trc_chrdev_ioctl : [RHP_TRC_IOCTRL_STOP] NOT active \n");
      return 0;
    }

    if(copy_from_user( &_rhp_trc_setup, (void*) arg, sizeof(_rhp_trc_setup) )){
      ERR("<RHP_TRACE>""_rhp_trc_chrdev_ioctl : [RHP_TRC_IOCTRL_STOP] Can't copy_from_user... \n");
      return -EFAULT;
    }

    atomic_set( &_rhp_trc_active, 0 );
    ERR("<RHP_TRACE>""_rhp_trc_chrdev_ioctl : [RHP_TRC_IOCTRL_END(1)] \n");

    _rhp_spin_lock_bh(&_rhp_trc_lock);

    priv2 = _rhp_trc_priv_head;
    while(priv2){

      if(priv2->is_helper){
        atomic_inc( &_rhp_trc_heler_notification );
        wake_up( &priv2->wait );
        break;
      }

      priv2 = priv2->next;
    }

    _rhp_spin_unlock_bh(&_rhp_trc_lock);
  }

    ERR("<RHP_TRACE>""_rhp_trc_chrdev_ioctl : [RHP_TRC_IOCTRL_END(2)] \n");
    break;

  case RHP_TRC_IOCTRL_SET: {

    unsigned char userid = (unsigned char) ((arg & 0x0000FF00) >> 8);
    unsigned char filter_mask = (unsigned char) (arg & 0x000000FF);

    if(userid >= RHP_TRC_MAX_USERS){
      ERR("<RHP_TRACE>""_rhp_trc_chrdev_ioctl : [RHP_TRC_IOCTRL_SET] Invalid userid:%d \n",userid);
      return -EFBIG;
    }

    rhp_trace_flag[userid] = (unsigned char) filter_mask;

    _rhp_spin_lock_bh(&_rhp_trc_lock);

    priv2 = _rhp_trc_priv_head;
    while(priv2){

      if(priv2->is_helper){
        atomic_inc( &_rhp_trc_heler_notification );
        wake_up( &priv2->wait );
        break;
      }

      priv2 = priv2->next;
    }

    _rhp_spin_unlock_bh(&_rhp_trc_lock);
  }
    break;

  case RHP_TRC_IOCTRL_READING:

    _rhp_spin_lock_bh(&_rhp_trc_lock);

    atomic_set( &_rhp_trc_reading, arg );

    if(arg){
      rhp_trc_read_p = rhp_trc_record_head;
      rhp_trc_read_len = 0;
      rhp_trc_reader_pid = current->pid;
    }else{
      rhp_trc_reader_pid = 0;
    }

    _rhp_spin_unlock_bh(&_rhp_trc_lock);
    break;

  case RHP_TRC_IOCTRL_CLEAR:

    _rhp_spin_lock_bh(&_rhp_trc_lock);

    rhp_trc_record_head = rhp_trc_buffer;
    rhp_trc_record_tail = rhp_trc_buffer;
    _rhp_trc_current_len = 0;

    atomic_set( &_rhp_trc_reading, 0 );
    rhp_trc_reader_pid = 0;

    _rhp_spin_unlock_bh(&_rhp_trc_lock);

    break;

  case RHP_TRC_IOCTRL_RESIZE: {
    unsigned long msize = arg;

    err = _rhp_trace_alloc_vmalloc( msize );
    if(err){
      ERR("<RHP_TRACE>""_rhp_trc_chrdev_ioctl : [RHP_TRC_IOCTRL_RESIZE] Alloc failed... \n");
      return err;
    }
  }
    break;

  case RHP_TRC_IOCTRL_INFO: {
    rhp_trace_info *info = (rhp_trace_info*) arg;
    unsigned char tmp_trace_flag[RHP_TRC_MAX_USERS];
    unsigned long tmp_buffer_len;
    unsigned long tmp_current_len;

    if(info == NULL){
      ERR("<RHP_TRACE>""_rhp_trc_chrdev_ioctl : [RHP_TRC_IOCTRL_INFO] Invalid arg \n");
      return -EINVAL;
    }

    _rhp_spin_lock_bh(&_rhp_trc_lock);
    memcpy( tmp_trace_flag, rhp_trace_flag, sizeof(unsigned char)
        * RHP_TRC_MAX_USERS);
    tmp_buffer_len = rhp_trc_buffer_len;
    tmp_current_len = _rhp_trc_current_len;
    _rhp_spin_unlock_bh(&_rhp_trc_lock);

    if(copy_to_user( info, tmp_trace_flag, sizeof(unsigned char)
        * RHP_TRC_MAX_USERS)){
      ERR("<RHP_TRACE>""_rhp_trc_chrdev_ioctl : [RHP_TRC_IOCTRL_INFO] EFAULT(1) \n");
      return -EFAULT;
    }

    if(copy_to_user( &info->trc_buffer_len, &tmp_buffer_len,
        sizeof(unsigned long) )){
      ERR("<RHP_TRACE>""_rhp_trc_chrdev_ioctl : [RHP_TRC_IOCTRL_INFO] EFAULT(2) \n");
      return -EFAULT;
    }

    if(copy_to_user( &info->trc_current_len, &tmp_current_len,
        sizeof(unsigned long) )){
      ERR("<RHP_TRACE>""_rhp_trc_chrdev_ioctl : [RHP_TRC_IOCTRL_INFO] EFAULT(3) \n");
      return -EFAULT;
    }
  }
    break;

  default:
    ERR("<RHP_TRACE>""_rhp_trc_chrdev_ioctl : [UNKNOW] \n");
    return -EINVAL;
  }

  return 0;
}

static ssize_t _rhp_trc_chrdev_read(struct file *filep, char __user *buf, size_t buf_len, loff_t *f_pos)
{
  ssize_t ret;
  unsigned long len;
  unsigned char* buffer_end = rhp_trc_buffer + rhp_trc_buffer_len;

  if( !atomic_read(&_rhp_trc_active) ){
    ERR("<RHP_TRACE>""_rhp_trc_chrdev_read : Not active... \n");
    return -EPERM;
  }

  if( !_rhp_trace_capable() ){
    ret = -EPERM;
    ERR("<RHP_TRACE>""_rhp_trc_chrdev_read : Not allowed... \n");
    goto error;
  }

  if( !atomic_read(&_rhp_trc_reading) ){
    ret = -EPERM;
    ERR("<RHP_TRACE>""_rhp_trc_chrdev_read : Not reading... \n");
    goto error;
  }

  if( current->pid != rhp_trc_reader_pid ){
    ret = -EPERM;
    ERR("<RHP_TRACE>""_rhp_trc_chrdev_read : Not allowed PID... \n");
    goto error;
  }

  if( rhp_trc_read_len >= _rhp_trc_current_len ){ // EOF
    ret = 0;
    goto error;
  }

  _rhp_trace_record_len("R",rhp_trc_read_p,&len);

#ifdef RHP_TRACE_DEBUG
  //  _rhp_bin_dump("_rhp_trc_chrdev_read(2)",rhp_trc_read_p,64);
#endif // RHP_TRACE_DEBUG
  if( len > buf_len ){
    ret = -EMSGSIZE;
    ERR("<RHP_TRACE>""_rhp_trc_chrdev_read : Not enough buffer length. len:%lu , buf_len: %d \n",len,buf_len);
    goto error;
  }

  // Don't lock! for copy_to_user()
  ret = _rhp_trace_copy_record_to_user(rhp_trc_read_p,len,buf);
  if( ret < 0 ){
    ERR("<RHP_TRACE>""_rhp_trc_chrdev_read : Fail to copy data. \n");
    goto error;
  }

  rhp_trc_read_p += ret;

  if( rhp_trc_read_p >= buffer_end ){
    rhp_trc_read_p = rhp_trc_buffer + (rhp_trc_read_p - buffer_end);
  }

  rhp_trc_read_len += ret;

  return ret;

  error:
  return ret;
}

#define RHP_TRC_SYS_WRITE_BUFFER_MIN  1024
static int _rhp_trc_sys_write_buffer_len = 0;
static char* _rhp_trc_sys_write_buffer = NULL;

#ifdef RHP_OBSOLETE_MUTEX
static DECLARE_MUTEX( _rhp_trc_sys_write_lock );
#else // RHP_OBSOLETE_MUTEX
static DEFINE_SEMAPHORE( _rhp_trc_sys_write_lock );
#endif // RHP_OBSOLETE_MUTEX

// If debug trace is enabled , this call never failed. Errors are ignored.
static ssize_t _rhp_trc_chrdev_write(struct file *filep, const char __user *buf,size_t buf_len, loff_t *f_pos)
{
  rhp_trace_record record;
  unsigned long record_len = 0;
  unsigned char* record_head;
  unsigned char* buffer_end = rhp_trc_buffer + rhp_trc_buffer_len;

  DBG("<RHP_TRACE>""_rhp_trc_chrdev_write : pid:%d \n",current->pid);

  if( !atomic_read(&_rhp_trc_active) ){
    DBG("<RHP_TRACE>""_rhp_trc_chrdev_write : Not active... \n");
    return -EPERM;
  }

  if( atomic_read(&_rhp_trc_reading) )
  {
    DBG("<RHP_TRACE>""_rhp_trc_chrdev_write : Now reading... \n");
    return -EPERM;
  }

  if( buf_len < sizeof(rhp_trace_record) ){
    ERR("<RHP_TRACE>""_rhp_trc_chrdev_write : Invalid buffer length... \n");
    return -EMSGSIZE;
  }

  if( buf_len > RHP_TRC_READ_BUFFER_SIZE ){
    ERR("<RHP_TRACE>""_rhp_trc_chrdev_write : Buffer too long %u > %u(RHP_TRC_READ_BUFFER_SIZE) \n",buf_len,RHP_TRC_READ_BUFFER_SIZE);
    return -EMSGSIZE;
  }

  if( copy_from_user(&record,buf,sizeof(rhp_trace_record) ) ){
    ERR("<RHP_TRACE>""_rhp_trc_chrdev_write : Fail to copy_from_user... \n");
    return -EPERM;
  }

  do_gettimeofday(&record.timestamp);

  if( down_interruptible(&_rhp_trc_sys_write_lock) ){
    DBG("<RHP_TRACE>""_rhp_trc_chrdev_write : Fail to get lock... \n");
    return -EPERM;
  }

  _rhp_spin_lock_bh(&_rhp_trc_lock);

  if( record.len < sizeof(rhp_trace_record) ){
    _rhp_spin_unlock_bh(&_rhp_trc_lock);
    up(&_rhp_trc_sys_write_lock);
    ERR("<RHP_TRACE>""_rhp_trc_chrdev_write : RecordLen too short... %lu\n",record.len);
    return -EMSGSIZE;
  }

  if( record.len > rhp_trc_buffer_len ){
    _rhp_spin_unlock_bh(&_rhp_trc_lock);
    up(&_rhp_trc_sys_write_lock);
    ERR("<RHP_TRACE>""_rhp_trc_chrdev_write : RecordLen too long... %lu > %lu\n",record.len,rhp_trc_buffer_len);
    return -EMSGSIZE;
  }

  if( record.len > RHP_TRC_READ_BUFFER_SIZE ){
    _rhp_spin_unlock_bh(&_rhp_trc_lock);
    up(&_rhp_trc_sys_write_lock);
    ERR("<RHP_TRACE>""_rhp_trc_chrdev_write : RecordLen too long... %lu > %u(RHP_TRC_READ_BUFFER_SIZE)\n",record.len,RHP_TRC_READ_BUFFER_SIZE);
    return -EMSGSIZE;
  }

  _rhp_spin_unlock_bh(&_rhp_trc_lock);

  if( record.len > _rhp_trc_sys_write_buffer_len ){

    char* new_buf;
    int new_buf_len = (record.len < RHP_TRC_SYS_WRITE_BUFFER_MIN) ? RHP_TRC_SYS_WRITE_BUFFER_MIN : record.len;

    new_buf = (char*)vmalloc(new_buf_len);

    if( new_buf == NULL ){
      up(&_rhp_trc_sys_write_lock);
      ERR("<RHP_TRACE>""_rhp_trc_chrdev_write : Fail to alloc memory... %d\n",new_buf_len);
      return -ENOMEM;
    }

    if( _rhp_trc_sys_write_buffer ){
      vfree(_rhp_trc_sys_write_buffer);
    }

    _rhp_trc_sys_write_buffer = new_buf;
    _rhp_trc_sys_write_buffer_len = new_buf_len;

    ERR("<RHP_TRACE>""_rhp_trc_chrdev_write : New write buffer length: %d, record.len: %lu\n",new_buf_len,record.len);
  }

  buf += sizeof(rhp_trace_record);

  if( copy_from_user(_rhp_trc_sys_write_buffer,buf,record.len ) ){
    up(&_rhp_trc_sys_write_lock);
    ERR("<RHP_TRACE>""_rhp_trc_chrdev_write : Fail to copy_from_user... \n");
    return -EPERM;
  }

  _rhp_spin_lock_bh(&_rhp_trc_lock);

  _rhp_trace_write_data((unsigned char*)&record,sizeof(record),&record_len,&record_head);
  if( record.len > sizeof(record) ){
  	_rhp_trace_write_data((unsigned char*)_rhp_trc_sys_write_buffer,(record.len - sizeof(record)),&record_len,NULL);
  }

  if( record_head + sizeof(unsigned long) <= buffer_end ){
    ((rhp_trace_record*)record_head)->len = record_len;
  } else{

    unsigned char* lenp = (unsigned char*)&record_len;
    int i;
    unsigned char ck_record_head[sizeof(unsigned long)];

    for( i = 0; i < sizeof(unsigned long);i++ ){

      *record_head = lenp[i];
      ck_record_head[i] = lenp[i];

      if( ++record_head >= buffer_end ){
        record_head = rhp_trc_buffer;
      }
    }

    {
    	unsigned long ck_len;
      unsigned char* ck_lenp = (unsigned char*)&ck_len;
      int i;

      for(i = 0; i < sizeof(unsigned long); i++){
      	ck_lenp[i] = ck_record_head[i];
      }

      if( ck_len < sizeof(rhp_trace_record) ){
        ERR("<RHP_TRACE>""_rhp_trc_chrdev_write(%s:%d): Invalid buffer RecordLen: %lu, rhp_trace_record:%u \n","HOGE",1,ck_len,sizeof(rhp_trace_record));
      }

      if( ck_len > RHP_TRC_READ_BUFFER_SIZE ){
      	ERR("<RHP_TRACE>""_rhp_trc_chrdev_write(%s:%d): RecordLen too long %lu > %u(RHP_TRC_READ_BUFFER_SIZE) \n","HOGE",1,ck_len,RHP_TRC_READ_BUFFER_SIZE);
      }

      if( ck_len > rhp_trc_buffer_len ){
      	ERR("<RHP_TRACE>""_rhp_trc_chrdev_write(%s:%d) : RecordLen too long %lu > %lu \n","HOGE",1,ck_len,rhp_trc_buffer_len);
      }
    }


  }



  up(&_rhp_trc_sys_write_lock);

  _rhp_spin_unlock_bh(&_rhp_trc_lock);

#ifdef RHP_TRACE_DEBUG
  //  _rhp_bin_dump("RHP_TRACE3",rhp_trc_buffer,256);
#endif // RHP_TRACE_DEBUG
  return buf_len;
}

// If debug trace is enabled , this call never failed. Errors are ignored.
static ssize_t _rhp_trc_chrdev_file_write(struct file *filep, const char __user *buf,size_t buf_len, loff_t *f_pos)
{
  rhp_trace_fd_priv* priv = (rhp_trace_fd_priv*)filep->private_data;

  DBG("<RHP_TRACE>""_rhp_trc_chrdev_file_write : pid:%d \n",current->pid);

  if( !atomic_read(&_rhp_trc_active) ){
    DBG("<RHP_TRACE>""_rhp_trc_chrdev_file_write : Not active... \n");
    return -EPERM;
  }

  if( atomic_read(&_rhp_trc_reading) ){
    DBG("<RHP_TRACE>""_rhp_trc_chrdev_file_write : Now reading... \n");
    return -EPERM;
  }

  if( (priv->file_buf_len + buf_len)> RHP_TRACE_FILE_BUF_LEN ){
    return buf_len;
  }

  if( down_interruptible(&_rhp_trc_sys_write_lock) ){
    ERR("<RHP_TRACE>""_rhp_trc_chrdev_file_write : Fail to get lock... \n");
    return -EPERM;
  }

  if( copy_from_user((priv->file_buf+priv->file_buf_len),buf,buf_len) ){
    ERR("<RHP_TRACE>""_rhp_trc_chrdev_file_write : Fail to copy_from_user... \n");
    return -EPERM;
  }

  priv->file_buf_len += buf_len;

  up(&_rhp_trc_sys_write_lock);

  return buf_len;
}

#define RHP_TRC_TXT_BUFFER_SZ 1024
static char _trcstr_f_buf[RHP_TRC_TXT_BUFFER_SZ];
static spinlock_t _rhp_trctxt_lock;

void rhp_trace_string( unsigned char userid, unsigned long record_id,
    const char* file, int line, ... )
{
  int len;
  va_list args;
  unsigned long flags;
  char* buf = _trcstr_f_buf;
  char* format;

  if(!atomic_read( &_rhp_trc_active )){
    return;
  }

  if(atomic_read( &_rhp_trc_reading )){
    return;
  }

  spin_lock_irqsave( &_rhp_trctxt_lock, flags );

  buf[0] = '\0';

  va_start( args, line );
  format = va_arg(args,char*);
  len = vsnprintf( buf, RHP_TRC_TXT_BUFFER_SZ, format, args );
  va_end( args );

  rhp_trace( userid, record_id, "ssd", buf, file, line );

  spin_unlock_irqrestore( &_rhp_trctxt_lock, flags );

  return;
}

static struct file_operations _rhp_trc_chrdev_ops = { .owner = THIS_MODULE,
    .llseek = NULL, .read = _rhp_trc_chrdev_read,
    .write = _rhp_trc_chrdev_write, .poll = NULL,
#ifdef RHP_OBSOLETE_IOCTL
    .ioctl = _rhp_trc_chrdev_ioctl,
#else // RHP_OBSOLETE_IOCTL
    .unlocked_ioctl = _rhp_trc_chrdev_ioctl,
#endif // RHP_OBSOLETE_IOCTL
    .open = _rhp_trc_chrdev_open,
    .release = _rhp_trc_chrdev_release, };

static struct miscdevice _rhp_trc_misc_ops = { .minor = MISC_DYNAMIC_MINOR,
    .name = "rhp_trace", .fops = &_rhp_trc_chrdev_ops, };

static struct file_operations _rhp_trc_chrdev_file_ops = {
    .owner = THIS_MODULE, .llseek = NULL, .read = _rhp_trc_chrdev_read,
    .write = _rhp_trc_chrdev_file_write, .poll = NULL,
#ifdef RHP_OBSOLETE_IOCTL
    .ioctl = _rhp_trc_chrdev_ioctl,
#else // RHP_OBSOLETE_IOCTL
    .unlocked_ioctl = _rhp_trc_chrdev_ioctl,
#endif // RHP_OBSOLETE_IOCTL
    .open = _rhp_trc_chrdev_file_open,
    .release = _rhp_trc_chrdev_file_release, };

static struct miscdevice _rhp_trc_misc_file_ops = {
    .minor = MISC_DYNAMIC_MINOR, .name = "rhp_file_trace",
    .fops = &_rhp_trc_chrdev_file_ops, };

int rhp_trace_init( void )
{
  int ret;

  spin_lock_init( &_rhp_trc_lock );
  spin_lock_init( &_rhp_trctxt_lock );

  atomic_set( &_rhp_trc_active, 0 );
  atomic_set( &_rhp_trc_reading, 0 );
  atomic_set( &_rhp_trc_users, 0 );
  atomic_set( &_rhp_trc_heler_notification, 0 );

  memset( rhp_trace_flag, 0, sizeof(unsigned char) * RHP_TRC_MAX_USERS);

  _rhp_trc_setup.uid = 0;

  ret = _rhp_trace_alloc_vmalloc( RHP_TRC_BUFFER_DEFAULT_SIZE );
  if(ret){
    goto error;
  }

  ret = misc_register( &_rhp_trc_misc_ops );
  if(ret < 0){
    ERR("<RHP_TRACE>" "register_chrdev() /dev/rhp_trace failed.\n");
    goto error;
  }

  ret = misc_register( &_rhp_trc_misc_file_ops );
  if(ret < 0){
    ERR("<RHP_TRACE>" "register_chrdev() /dev/rhp_trace_file failed.\n");
    misc_deregister( &_rhp_trc_misc_ops );
    goto error;
  }

  ERR("<RHP_TRACE>" "Loading... OK MAJOR(%d) , MINOR(%d)\n", MISC_MAJOR,_rhp_trc_misc_ops.minor);
  return 0;

  error: if(rhp_trc_buffer){
    vfree( rhp_trc_buffer );
    rhp_trc_buffer = NULL;
  }
  return -1;
}

void rhp_trace_cleanup( void )
{
  atomic_set( &_rhp_trc_active, 0 );

  if(atomic_read( &_rhp_trc_users )){

    rhp_trace_fd_priv *tmp = _rhp_trc_priv_head;
    int retry_cnt = 30;

    _rhp_spin_lock_bh(&_rhp_trc_lock);
    while(tmp){
      wake_up_interruptible_all( &tmp->wait );
      tmp = tmp->next;
    }
    _rhp_spin_unlock_bh(&_rhp_trc_lock);

    while(atomic_read( &_rhp_trc_users ) && --retry_cnt){
      set_current_state( TASK_UNINTERRUPTIBLE );
      schedule_timeout( HZ ); // 1 sec...
    }

    if(retry_cnt == 0){
      ERR("<RHP_TRACE>" " *ERROR* Fail to cleanup... %d users still exist. \n",atomic_read(&_rhp_trc_users));
    }
  }

  if(rhp_trc_buffer){
    vfree( rhp_trc_buffer );
  }
  misc_deregister( &_rhp_trc_misc_ops );

  return;
}

EXPORT_SYMBOL( rhp_trc_buffer );
EXPORT_SYMBOL( rhp_trc_record_head );
EXPORT_SYMBOL( rhp_trc_record_tail );

EXPORT_SYMBOL( rhp_trace );
EXPORT_SYMBOL( rhp_trace_string );
EXPORT_SYMBOL( rhp_trace_flag );

static int trace_init_module( void )
{
  return rhp_trace_init();
}

static void trace_exit_module( void )
{
  rhp_trace_cleanup();
}

module_init( trace_init_module );
module_exit( trace_exit_module );
