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
#include <time.h>
#include <byteswap.h>

#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

#include <arpa/inet.h>

#include "rhp_trace.h"

/*************************

 Private data types

 **************************/

typedef u_int64_t u64;
typedef u_int32_t u32;
typedef u_int16_t u16;
typedef u_int8_t u8;
#define RHP_TRUE    1
#define RHP_FALSE   0

#include "rhp_protocol.h"

static void _rhp_bin_dump_impl( char* tag, unsigned int ptr, unsigned char* d,
    int len, int scale )
{
  int i, j;
  unsigned char* mc = d;

  if(scale){

    printf( "\n" );

    if(tag){
      printf( "[%s] ", tag );
    }

    printf( "[0x%x]  %d(bytes)\n", ptr, len );
    printf(
        "*0 *1 *2 *3 *4 *5 *6 *7 *8 *9 *A *B *C *D *E *F     0123456789ABCDEF\n" );
  }

  if(len <= 0){
    printf( "--NO DATA--\n" );
    return;
  }

  for(i = 0; i < len; i++){

    int pd;

    if(i && (i % 16) == 0){

      printf( "    " );
      for(j = 0; j < 16; j++){

        if(*mc >= 33 && *mc <= 126){
          printf( "%c", *mc );
        }else{
          printf( "." );
        }
        mc++;
      }
      printf( "\n" );
    }

    pd = ((*(int *) d) & 0x000000FF);

    if(pd <= 0x0F){
      printf( "0" );
    }

    printf( "%x ", pd );
    d++;
  }

  {
    int k, k2;
    if((i % 16) == 0){
      k = 0;
      k2 = 16;
    }else{
      k = 16 - (i % 16);
      k2 = (i % 16);
    }

    for(i = 0; i < k; i++){
      printf( "   " );
    }

    printf( "    " );

    for(j = 0; j < k2; j++){

      if(*mc >= 33 && *mc <= 126){
        printf( "%c", *mc );
      }else{
        printf( "." );
      }
      mc++;
    }
  }

  printf( "\n" );
}

static void _rhp_bin_dump( char* tag, unsigned char* d, int len, int scale )
{
  _rhp_bin_dump_impl( tag, 0, d, len, scale );
}

static char _rhp_ipv6_string_buf[INET6_ADDRSTRLEN + 1];

static char* _rhp_ipv6_string(u8* addr)
{
	struct in6_addr sin6;

	memset(_rhp_ipv6_string_buf,'\0',(INET6_ADDRSTRLEN + 1));
	memcpy(sin6.s6_addr,addr,16);

	inet_ntop(AF_INET6,(const void*)&sin6,_rhp_ipv6_string_buf,INET6_ADDRSTRLEN);

	return _rhp_ipv6_string_buf;
}


#define RHP_TRC_TOOL_HASH_SIZE  1024

#define RHP_TRC_TOOL_CMD_ENABLE       1
#define RHP_TRC_TOOL_CMD_DISABLE      2
#define RHP_TRC_TOOL_CMD_SAVE         3
#define RHP_TRC_TOOL_CMD_TRANSLATE    4
#define RHP_TRC_TOOL_CMD_SET_SIZE     5
#define RHP_TRC_TOOL_CMD_RESET        6
#define RHP_TRC_TOOL_CMD_SHOW_INFO    7

struct message_tag {
  struct message_tag *hash_next;
  unsigned long id;
  xmlChar *id_str;
  xmlChar *tag;
  xmlChar *format;
};

struct label_item_tag {
  struct label_item_tag *next;
  xmlChar *label;
  xmlChar *value_str;
  long long value;
};

struct label_tag {
  struct label_tag *next;
  xmlChar *name;
  struct label_item_tag *item_list_head;
};

struct bit_item_tag {
  struct bit_item_tag *next;
  xmlChar *label;
  xmlChar *value_str;
  long long value;
};

struct bit_tag {
  struct bit_tag *next;
  xmlChar *name;
  struct bit_item_tag *item_list_head;
};

struct user_tag {
  struct user_tag *next;

  unsigned char id;
  xmlChar *id_str;
  xmlChar *name;

  xmlDocPtr doc;

  int message_tag_num;
  struct message_tag *message_hash_tab[RHP_TRC_TOOL_HASH_SIZE];

  int struct_tag_num;
  struct struct_tag *struct_list_head;

  int label_tag_num;
  struct label_tag *label_list_head;

  int bit_tag_num;
  struct bit_tag *bit_list_head;
};

void _free_message_tag( struct message_tag *tag )
{
  if(tag == NULL){
    return;
  }

  if(tag->id_str){
    xmlFree( tag->id_str );
  }

  if(tag->format){
    xmlFree( tag->format );
  }

  if(tag->tag){
    xmlFree( tag->tag );
  }

  free( tag );
}

void _free_label_tag( struct label_tag *tag )
{
  if(tag == NULL){
    return;
  }

  {
    struct label_item_tag *item = tag->item_list_head;

    while(item){

      struct label_item_tag *tmp = item->next;

      if(item->label){
        xmlFree( item->label );
      }

      free( item );
      item = tmp;
    }
  }

  if(tag->name){
    xmlFree( tag->name );
  }

  free( tag );
}

void _free_bit_tag( struct bit_tag *tag )
{
  if(tag == NULL){
    return;
  }

  {
    struct bit_item_tag *item = tag->item_list_head;

    while(item){

      struct bit_item_tag *tmp = item->next;

      if(item->label){
        xmlFree( item->label );
      }

      free( item );
      item = tmp;
    }
  }

  if(tag->name){
    xmlFree( tag->name );
  }

  free( tag );
}

static void _free_user_tag( struct user_tag *tag )
{

  if(tag == NULL){
    return;
  }

  if(tag->id_str){
    xmlFree( tag->id_str );
  }

  if(tag->name){
    xmlFree( tag->name );
  }

  {
    int i;

    for(i = 0; i < RHP_TRC_TOOL_HASH_SIZE; i++){

      struct message_tag *mesg_tag = tag->message_hash_tab[i];

      while(mesg_tag){
        struct message_tag *next = mesg_tag->hash_next;
        _free_message_tag( mesg_tag );
        mesg_tag = next;
      }
    }
  }

  {
    struct label_tag *lbl_tag = tag->label_list_head;

    while(lbl_tag){
      struct label_tag *next = lbl_tag->next;
      _free_label_tag( lbl_tag );
      lbl_tag = next;
    }
  }

  {
    struct bit_tag *bt_tag = tag->bit_list_head;

    while(bt_tag){
      struct bit_tag *next = bt_tag->next;
      _free_bit_tag( bt_tag );
      bt_tag = next;
    }
  }

  if(tag->doc){
    xmlFreeDoc( tag->doc );
  }

  free( tag );
}

static void _dump_user_tag( struct user_tag *root_tag )
{
  if(root_tag->name){
    printf( "user->name : %s\n", root_tag->name );
  }else{
    printf( "user->name : %s\n", "unknown" );
  }
  printf( "user->id : %d\n", root_tag->id );
}

static void _dump_message_tag( struct message_tag *tag )
{
  if(tag->id_str){
    printf( "message->id : %lu\n", tag->id );
  }

  if(tag->tag){
    printf( "message->tag : %s\n", tag->tag );
  }

  if(tag->format){
    printf( "message->format : %s\n", tag->format );
  }
}

static inline int _message_id_hash( unsigned long id )
{
  return (id % RHP_TRC_TOOL_HASH_SIZE);
}

static int _parse_message_tag( xmlDocPtr doc, xmlNodePtr cur,
    struct user_tag* root_tag )
{
  struct message_tag *tag;
  char* endp;
  int hash_val;

  tag = (struct message_tag*) malloc( sizeof(struct message_tag) );
  if(tag == NULL){
    printf( " _parse_message_tag : Fail to alloc mem.\n" );
    return -ENOMEM;
  }

  memset( tag, 0, sizeof(struct message_tag) );

  tag->id_str = xmlGetProp( cur, (const xmlChar*) "id" );
  if(tag->id_str == NULL){
    printf( " _parse_message_tag : \"id\" of \"message\" tag not found.\n" );
    goto error;
  }

  tag->id = strtoul( (char*) tag->id_str, &endp, 10 );
  if(tag->id == 0){
    printf(
        " _parse_message_tag : Fail to parse \"id\" of \"message\" tag. %s\n",
        tag->id_str );
    goto error;
  }

  tag->tag = xmlGetProp( cur, (const xmlChar *) "tag" );

  tag->format = xmlNodeListGetString( doc, cur->xmlChildrenNode, 1 );
  if(tag->format == NULL){
    printf(
        " _parse_message_tag : No format text found...  \"id(%s)\" of \"message\" tag.\n",
        tag->id_str );
  }

  hash_val = _message_id_hash( tag->id );
  if(root_tag->message_hash_tab[hash_val]){
    tag->hash_next = root_tag->message_hash_tab[hash_val];
  }
  root_tag->message_hash_tab[hash_val] = tag;

  root_tag->message_tag_num++;

  //_dump_message_tag(tag);

  return 0;

  error: _free_message_tag( tag );
  return -EINVAL;
}

static int _parse_label_tag( xmlDocPtr doc, xmlNodePtr label_tag,
    struct user_tag* root_tag )
{
  xmlNodePtr cur;
  struct label_tag *tag;
  char* endp;
  int err = 0;

  tag = (struct label_tag*) malloc( sizeof(struct label_tag) );
  if(tag == NULL){
    err = -ENOMEM;
    printf( " _parse_label_tag : Fail to alloc mem.\n" );
    goto error;
  }
  memset( tag, 0, sizeof(struct label_tag) );

  tag->name = xmlGetProp( label_tag, (const xmlChar*) "name" );
  if(tag->name == NULL){
    printf( " _parse_label_tag : \"name\" of \"label\" tag not found.\n" );
    err = -ENOENT;
    goto error;
  }

  cur = label_tag->xmlChildrenNode;

  while(cur != NULL){

    if((!xmlStrcmp( cur->name, (const xmlChar *) "label_item" ))){

      struct label_item_tag *item = (struct label_item_tag*) malloc(
          sizeof(struct label_item_tag) );

      if(item == NULL){
        err = -ENOMEM;
        printf( " _parse_label_tag : Fail to alloc mem.\n" );
        goto error;
      }

      memset( item, 0, sizeof(struct label_item_tag) );

      item->label = xmlGetProp( cur, (const xmlChar*) "label" );

      item->value_str = xmlGetProp( cur, (const xmlChar*) "value" );
      if(item->value_str == NULL){

        if(item->label){
          free( item->label );
        }

        free( item );
        printf( " _parse_label_tag : \"value\" of \"label\" tag not found.\n" );
        goto next;
      }

      item->value = strtoll( (char*) item->value_str, &endp, 10 );
      if(*endp != '\0'){

        if(item->label){
          free( item->label );
        }

        if(item->value_str){
          free( item->value_str );
        }

        free( item );
        printf(
            " _parse_label_tag(2) : Fail to parse \"value\" of \"label\" tag.\n" );
        goto next;
      }

      item->next = tag->item_list_head;
      tag->item_list_head = item;
    }

    next: cur = cur->next;
  }

  if(tag->item_list_head == NULL){
    err = -ENOENT;
    printf( " _parse_label_tag : No entry found. tag name:%s\n", tag->name );
    goto error;
  }

  root_tag->label_tag_num++;
  tag->next = root_tag->label_list_head;
  root_tag->label_list_head = tag;

  return 0;

  error: _free_label_tag( tag );
  return err;
}

static int _parse_bit_tag( xmlDocPtr doc, xmlNodePtr bt_tag,
    struct user_tag* root_tag )
{
  xmlNodePtr cur;
  struct bit_tag *tag;
  char* endp;
  int err = 0;

  tag = (struct bit_tag*) malloc( sizeof(struct bit_tag) );
  if(tag == NULL){
    err = -ENOMEM;
    printf( " _parse_bit_tag : Fail to alloc mem.\n" );
    goto error;
  }
  memset( tag, 0, sizeof(struct bit_tag) );

  tag->name = xmlGetProp( bt_tag, (const xmlChar*) "name" );
  if(tag->name == NULL){
    printf( " _parse_bit_tag : \"name\" of \"label\" tag not found.\n" );
    err = -ENOENT;
    goto error;
  }

  cur = bt_tag->xmlChildrenNode;

  while(cur != NULL){

    if((!xmlStrcmp( cur->name, (const xmlChar *) "bit_item" ))){

      struct bit_item_tag *item = (struct bit_item_tag*) malloc(
          sizeof(struct bit_item_tag) );

      if(item == NULL){
        err = -ENOMEM;
        printf( " _parse_bit_tag : Fail to alloc mem.\n" );
        goto error;
      }
      memset( item, 0, sizeof(struct bit_item_tag) );

      item->label = xmlGetProp( cur, (const xmlChar*) "label" );

      item->value_str = xmlGetProp( cur, (const xmlChar*) "value" );
      if(item->value_str == NULL){

        if(item->label){
          free( item->label );
        }

        free( item );
        printf( " _parse_bit_tag : \"value\" of \"label\" tag not found.\n" );
        goto next;
      }

      item->value = strtoll( (char*) item->value_str, &endp, 10 );
      if(item->value == 0){

        if(item->label){
          free( item->label );
        }

        if(item->value_str){
          free( item->value_str );
        }

        free( item );
        printf( " _parse_bit_tag : Fail to parse \"value\" of \"label\" tag.\n" );
        goto next;
      }

      item->next = tag->item_list_head;
      tag->item_list_head = item;
    }

    next: cur = cur->next;
  }

  if(tag->item_list_head == NULL){
    err = -ENOENT;
    goto error;
  }

  root_tag->bit_tag_num++;
  tag->next = root_tag->bit_list_head;
  root_tag->bit_list_head = tag;

  return 0;

  error: _free_bit_tag( tag );
  return err;
}

static struct user_tag*
_parse_user_tag( xmlDocPtr doc )
{
  struct user_tag* tag;
  xmlNodePtr root = xmlDocGetRootElement( doc );
  xmlNodePtr cur;
  char* endp;

  if(root == NULL){
    printf( " _parse_user_tag : No elements found.\n" );
    return NULL;
  }

  if(xmlStrcmp( root->name, (const xmlChar *) "user" )){
    printf( " _parse_user_tag : Unknown root element. %s\n", root->name );
    return NULL;
  }

  tag = (struct user_tag*) malloc( sizeof(struct user_tag) );
  if(tag == NULL){
    printf( " _parse_user_tag : Fail to alloc mem.\n" );
    return NULL;
  }
  memset( tag, 0, sizeof(struct user_tag) );

  tag->doc = doc;

  tag->id_str = xmlGetProp( root, (const xmlChar*) "id" );
  if(tag->id_str == NULL){
    printf( " _parse_user_tag : \"id\" of \"user\" tag not found.\n" );
    goto error;
  }

  tag->id = strtoul( (char*) tag->id_str, &endp, 10 );
  if(tag->id == 0){
    printf( " _parse_user_tag : Fail to parse \"id\" of \"user\" tag. %s\n",
        tag->id_str );
    goto error;
  }

  tag->name = xmlGetProp( root, (const xmlChar *) "name" );
  if(tag->name == NULL){
    printf( " _parse_user_tag : \"name\" of \"user\" tag not found.\n" );
    goto error;
  }

  cur = root->xmlChildrenNode;

  while(cur != NULL){

    if((!xmlStrcmp( cur->name, (const xmlChar *) "message" ))){
      if(_parse_message_tag( doc, cur, tag )){
        printf( " _parse_user_tag : Fail to parse \"message\" tag.\n" );
      }
    }

    if((!xmlStrcmp( cur->name, (const xmlChar *) "label" ))){
      if(_parse_label_tag( doc, cur, tag )){
        printf( " _parse_user_tag : Fail to parse \"label\" tag.\n" );
      }
    }

    if((!xmlStrcmp( cur->name, (const xmlChar *) "bit" ))){
      if(_parse_bit_tag( doc, cur, tag )){
        printf( " _parse_user_tag : Fail to parse \"bit\" tag.\n" );
      }
    }

    cur = cur->next;
  }

  return tag;

  error: _free_user_tag( tag );
  return NULL;
}

static struct user_tag*
_parseFile( char *filename )
{
  xmlDocPtr doc;
  struct user_tag* root_tag;

  xmlInitParser();

  doc = xmlParseFile( filename );
  if(doc == NULL){
    return NULL;
  }

  root_tag = _parse_user_tag( doc );
  if(root_tag == NULL){
    xmlFreeDoc( doc );
    return NULL;
  }

  return root_tag;
}


static int _save_trace( char* output_file )
{
  int err = 0;
  int devfd = -1;
  FILE* ofd = NULL;
  size_t st;
  ssize_t st2;
  char d_buffer[RHP_TRC_READ_BUFFER_SIZE];
  unsigned long reading = 0;

  devfd = open( "/dev/rhp_trace", O_RDONLY);
  if(devfd < 0){
    err = errno;
    printf( " Fail to open /dev/rhp_trace. %s. \n", strerror( err ) );
    goto error;
  }

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
  if(ioctl( devfd, RHP_TRC_IOCTRL_READING_ID, reading )){
    err = errno;
    printf( " Fail to set READING flag %s. %s \n", output_file, strerror( err ) );
    goto error;
  }

  while((st2 = read( devfd, (void*) d_buffer, RHP_TRC_READ_BUFFER_SIZE)) > 0){

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

error:
  if(devfd >= 0){
    if(reading){
      reading = 0;
      if(ioctl( devfd, RHP_TRC_IOCTRL_READING_ID, reading )){
        err = errno;
        printf( " Fail to reset READING flag %s. %s \n", output_file, strerror(
            err ) );
      }
    }
    close( devfd );
  }
  if(ofd){
    fclose( ofd );
  }
  return err;
}

static int _print_mac( u8* buf, int buf_len, int* data_len, int* smry_idx,
    char* smry, u16* protocol_r )
{
  rhp_proto_ether* mac = (rhp_proto_ether*) buf;

  printf( "\n==<MAC>==\n" );

  if(buf_len < sizeof(rhp_proto_ether)){
    printf( "Invalid MAC format.\n" );
    return -1;
  }

  printf( "dst_addr : %02x:%02x:%02x:%02x:%02x:%02x\n", mac->dst_addr[0],
      mac->dst_addr[1], mac->dst_addr[2], mac->dst_addr[3], mac->dst_addr[4],
      mac->dst_addr[5] );
  printf( "src_addr : %02x:%02x:%02x:%02x:%02x:%02x\n", mac->src_addr[0],
      mac->src_addr[1], mac->src_addr[2], mac->src_addr[3], mac->src_addr[4],
      mac->src_addr[5] );
  printf( "protocol : 0x%x (ARP:0x0806,IPv4:0x0800,IPv6:0x86DD,)\n", ntohs(
      mac->protocol ) );

  if(protocol_r){
    *protocol_r = mac->protocol;
  }

  /*
   {
   unsigned short eth_t = mac->protocol;

   switch( eth_t ){
   case RHP_PROTO_ETH_ARP:
   *smry_idx += sprintf((smry+*smry_idx),"(ARP)");
   break;
   case RHP_PROTO_ETH_IP:
   *smry_idx += sprintf((smry+*smry_idx),"(IPv4)");
   break;
   case RHP_PROTO_ETH_IPV6:
   *smry_idx += sprintf((smry+*smry_idx),"(IPv6)");
   break;
   default:
   *smry_idx += sprintf((smry+*smry_idx),"(0x%x)",ntohs(mac->protocol));
   break;
   }
   }
   */

  if(data_len){
    *data_len = sizeof(rhp_proto_ether);
  }

  return 0;
}

static int _print_ipv4( u8* buf, int buf_len, int* data_len, u8* protocol_r,
    int* smry_idx, char* smry )
{
  rhp_proto_ip_v4* ip = (rhp_proto_ip_v4*) buf;

  printf( "\n==<IPv4>==\n" );

  if(buf_len < sizeof(rhp_proto_ip_v4)){
    printf( "Invalid IPv4 format.\n" );
    return -1;
  }

  printf( "IHL : %d\n", ip->ihl );
  printf( "Version : %d\n", ip->ver );
  printf( "TOS : 0x%x\n", ip->tos );
  printf( "total_len : %d\n", ntohs( ip->total_len ) );
  printf( "id : %d\n", ntohs( ip->id ) );
  printf( "frag : 0x%x\n", ntohs( ip->frag ) );
  printf( "TTL : %d\n", ip->ttl );
  printf( "Protocol : %d (ICMP:1,UDP:17,TCP:6,ESP:50,AH:51)\n", ip->protocol );
  printf( "checksum : 0x%x\n", ntohs( ip->check_sum ) );
  printf( "src_addr : %d.%d.%d.%d\n", ((u8*) (&(ip->src_addr)))[0],
      ((u8*) (&(ip->src_addr)))[1], ((u8*) (&(ip->src_addr)))[2],
      ((u8*) (&(ip->src_addr)))[3] );
  printf( "dst_addr : %d.%d.%d.%d\n", ((u8*) (&(ip->dst_addr)))[0],
      ((u8*) (&(ip->dst_addr)))[1], ((u8*) (&(ip->dst_addr)))[2],
      ((u8*) (&(ip->dst_addr)))[3] );

  *smry_idx += sprintf( (smry + *smry_idx),
      " %d.%d.%d.%d >> %d.%d.%d.%d Len: %d", ((u8*) (&(ip->src_addr)))[0],
      ((u8*) (&(ip->src_addr)))[1], ((u8*) (&(ip->src_addr)))[2],
      ((u8*) (&(ip->src_addr)))[3], ((u8*) (&(ip->dst_addr)))[0],
      ((u8*) (&(ip->dst_addr)))[1], ((u8*) (&(ip->dst_addr)))[2],
      ((u8*) (&(ip->dst_addr)))[3], ntohs( ip->total_len ) );

  switch(ip->protocol){
  case 1:
    *smry_idx += sprintf( (smry + *smry_idx), ":ICMP" );
    break;
  case 17:
    *smry_idx += sprintf( (smry + *smry_idx), ":UDP" );
    break;
  case 6:
    *smry_idx += sprintf( (smry + *smry_idx), ":TCP" );
    break;
  case 50:
    *smry_idx += sprintf( (smry + *smry_idx), ":ESP" );
    break;
  case 51:
    *smry_idx += sprintf( (smry + *smry_idx), ":AH" );
    break;
  case 41:
    *smry_idx += sprintf( (smry + *smry_idx), ":IPv6" );
    break;
  default:
    *smry_idx += sprintf( (smry + *smry_idx), ":%d", ip->protocol );
    break;
  }

  if(data_len){
    int hdr_len = ip->ihl;
    *data_len = (hdr_len * 4);
  }

  if(protocol_r){
    *protocol_r = ip->protocol;
  }

  return 0;
}

static int _print_ipv6_opt(u8 next_hdr, u8* buf, int buf_len, int* data_len, u8* next_heder_r,
    int* smry_idx, char* smry)
{
	rhp_proto_ip_v6_exthdr* exthdr = (rhp_proto_ip_v6_exthdr*)buf;
	int plen = 0;

	while( (u8*)exthdr < (buf + buf_len) ){

		switch( next_hdr ){

		case RHP_PROTO_IP_IPV6_HOP_BY_HOP:

			printf( "\n==<IPv6-ExtOpt>==\n" );
		  printf( "ExtOpt : HOP_BY_HOP(%d)\n", next_hdr );
      _rhp_bin_dump( "HBH", (u8*)exthdr,(8 + exthdr->len*8),1);

      *smry_idx += sprintf( (smry + *smry_idx),
		      " HBH(%d)",next_hdr);

			next_hdr = exthdr->next_header;
			plen += (8 + exthdr->len*8);
			exthdr = (rhp_proto_ip_v6_exthdr*)(((u8*)exthdr) + plen);

			break;

		case RHP_PROTO_IP_IPV6_ROUTE:

			printf( "\n==<IPv6-ExtOpt>==\n" );
		  printf( "ExtOpt : ROUTE(%d)\n", next_hdr );
      _rhp_bin_dump( "RTR", (u8*)exthdr,(8 + exthdr->len*8),1);

      *smry_idx += sprintf( (smry + *smry_idx),
		      " RTR(%d)",next_hdr);

			next_hdr = exthdr->next_header;
			plen += (8 + exthdr->len*8);
			exthdr = (rhp_proto_ip_v6_exthdr*)(((u8*)exthdr) + plen);

			break;

		case RHP_PROTO_IP_IPV6_OPTS:

			printf( "\n==<IPv6-ExtOpt>==\n" );
		  printf( "ExtOpt : OPTS(%d)\n", next_hdr );
      _rhp_bin_dump( "OPTS", (u8*)exthdr,(8 + exthdr->len*8),1);

      *smry_idx += sprintf( (smry + *smry_idx),
		      " OPT(%d)",next_hdr);

			next_hdr = exthdr->next_header;
			plen += (8 + exthdr->len*8);
			exthdr = (rhp_proto_ip_v6_exthdr*)(((u8*)exthdr) + plen);

			break;

		case RHP_PROTO_IP_IPV6_SHIM6:

			printf( "\n==<IPv6-ExtOpt>==\n" );
		  printf( "ExtOpt : SHIM6(%d)\n", next_hdr );
      _rhp_bin_dump( "SHIM6", (u8*)exthdr,(8 + exthdr->len*8),1);

      *smry_idx += sprintf( (smry + *smry_idx),
		      " SHIM(%d)",next_hdr);

			next_hdr = exthdr->next_header;
			plen += (8 + exthdr->len*8);
			exthdr = (rhp_proto_ip_v6_exthdr*)(((u8*)exthdr) + plen);

			break;

		case RHP_PROTO_IP_IPV6_HIP:

			printf( "\n==<IPv6-ExtOpt>==\n" );
		  printf( "ExtOpt : HIP(%d)\n", next_hdr );
      _rhp_bin_dump( "HIP", (u8*)exthdr,(8 + exthdr->len*8),1);

      *smry_idx += sprintf( (smry + *smry_idx),
		      " HIP(%d)",next_hdr);

			next_hdr = exthdr->next_header;
			plen += (8 + exthdr->len*8);
			exthdr = (rhp_proto_ip_v6_exthdr*)(((u8*)exthdr) + plen);

			break;

		case RHP_PROTO_IP_IPV6_FRAG:
			printf( "\n==<IPv6-ExtOpt>==\n" );
		  printf( "ExtOpt : FRAG(%d)\n", next_hdr );

      *smry_idx += sprintf( (smry + *smry_idx),
		      " FRG(%d)",next_hdr);

      goto end;

		case RHP_PROTO_IP_ESP:
		case RHP_PROTO_IP_AH:
			goto end;

		case RHP_PROTO_IP_NO_NEXT_HDR:
			printf( "\n==<IPv6-ExtOpt>==\n" );
		  printf( "ExtOpt : NO_NEXT_HDR(%d)\n", next_hdr );

      *smry_idx += sprintf( (smry + *smry_idx),
		      " NO(%d)",next_hdr);

      goto end;

		default:
			goto end;
		}
	}

end:
  if(data_len){
    *data_len = plen;
  }

  if(next_heder_r){
    *next_heder_r = next_hdr;
  }

  return 0;
}

static int _print_ipv6( u8* buf, int buf_len, int* data_len, u8* next_heder_r,
    int* smry_idx, char* smry ,int *pld_len_r)
{
  rhp_proto_ip_v6* ipv6 = (rhp_proto_ip_v6*) buf;
  uint32_t fl;
  u8 tc;
  u8 nxt_hdr = 0;
  int data_len2 = 0;
  char tmp[64],tmp2[64];

  printf( "\n==<IPv6>==\n" );

  if(buf_len < sizeof(rhp_proto_ip_v6)){
    printf( "Invalid IPv6 format.\n" );
    return -1;
  }

  strcpy(tmp,_rhp_ipv6_string(ipv6->src_addr));
  strcpy(tmp2,_rhp_ipv6_string(ipv6->dst_addr));

  tc = RHP_IPV6_TC(ipv6);
  fl = RHP_IPV6_FLOW_LABEL(ipv6);

  printf( "Version : %d\n", ipv6->ver );
  printf( "TC : 0x%x - FLOW_LABEL : 0x%x (priority: 0x%02x, flow_label: 0x%02x-0x%02x-0x%02x)\n",
  		tc, fl, ipv6->priority, ipv6->flow_label[0], ipv6->flow_label[1], ipv6->flow_label[2] );
  printf( "Payload Len : %d (Total: %d)\n", ntohs( ipv6->payload_len ), ntohs( ipv6->payload_len ) + sizeof(rhp_proto_ip_v6) );
  printf( "Hop Limit : %d\n", ipv6->hop_limit );
  printf( "Next Header : %d (ICMP:1,UDP:17,TCP:6,ESP:50,AH:51,ICMPv6:58)\n", ipv6->next_header );
  printf( "src_addr : %s\n",tmp);
  printf( "dst_addr : %s\n",tmp2);

  *smry_idx += sprintf( (smry + *smry_idx),
      " %s >> %s PldLen: %d (Total: %d)",tmp,tmp2,
      ntohs( ipv6->payload_len ),ntohs( ipv6->payload_len ) + sizeof(rhp_proto_ip_v6) );


  if(data_len){
    *data_len = sizeof(rhp_proto_ip_v6);
  }

  if( pld_len_r ){
  	*pld_len_r = (int)ntohs( ipv6->payload_len );
  }

	nxt_hdr = ipv6->next_header;
  if(next_heder_r){
    *next_heder_r = ipv6->next_header;
  }

  switch(ipv6->next_header){

  case RHP_PROTO_IP_IPV6_HOP_BY_HOP:
	case RHP_PROTO_IP_IPV6_ROUTE:
	case RHP_PROTO_IP_IPV6_OPTS:
	case RHP_PROTO_IP_IPV6_SHIM6:
	case RHP_PROTO_IP_IPV6_HIP:

		_print_ipv6_opt(ipv6->next_header,(u8*)(ipv6 + 1),(buf_len - sizeof(rhp_proto_ip_v6)),
				&data_len2,&nxt_hdr,smry_idx,smry);

	  if( next_heder_r ){
	  	*next_heder_r = nxt_hdr;
	  }

	  if( data_len ){
	  	*data_len += data_len2;
	  }

	  if( pld_len_r ){
	  	*pld_len_r -= data_len2;
	  }

  default:
    break;
  }

  switch( nxt_hdr ){
  case 0:
    *smry_idx += sprintf( (smry + *smry_idx), " Nxt:HopOpt" );
    break;
  case 41:
    *smry_idx += sprintf( (smry + *smry_idx), " Nxt:IPv6" );
    break;
  case 4:
    *smry_idx += sprintf( (smry + *smry_idx), " Nxt:IPv4" );
    break;
  case 43:
    *smry_idx += sprintf( (smry + *smry_idx), " Nxt:IPv6-Route" );
    break;
  case 44:
    *smry_idx += sprintf( (smry + *smry_idx), " Nxt:IPv6-Frag" );
    break;
  case 50:
    *smry_idx += sprintf( (smry + *smry_idx), " Nxt:ESP" );
    break;
  case 51:
    *smry_idx += sprintf( (smry + *smry_idx), " Nxt:AH" );
    break;
  case 58:
    *smry_idx += sprintf( (smry + *smry_idx), " Nxt:ICMPv6" );
    break;
  case 59:
    *smry_idx += sprintf( (smry + *smry_idx), " Nxt:IPv6-NoNxt" );
    break;
  case 60:
    *smry_idx += sprintf( (smry + *smry_idx), " Nxt:IPv6-Opts" );
    break;
  case 135:
    *smry_idx += sprintf( (smry + *smry_idx), " Nxt:Mobile-IP-Hdr" );
    break;
  case 17:
    *smry_idx += sprintf( (smry + *smry_idx), " Nxt:UDP" );
    break;
  case 6:
    *smry_idx += sprintf( (smry + *smry_idx), " Nxt:TCP" );
    break;
  default:
    *smry_idx += sprintf( (smry + *smry_idx), " Nxt:%d", ipv6->next_header );
    break;
  }

  return 0;
}

static int _print_gre_nhrp( u8* buf, int buf_len, int* smry_idx, char* smry )
{
	rhp_proto_gre* greh = (rhp_proto_gre*)buf;
	rhp_proto_nhrp* nhrph;
	rhp_proto_nhrp_fixed* fixedh;
	char tmp[64],tmp2[64], tmp3[64], tmp4[64];
	char *pkt_type_label = NULL, *af_label = NULL;
  int gre_len = sizeof(rhp_proto_gre);
  int nhrp_len;
  u8* p;

  printf( "\n==<GRE/NHRP>==\n" );

  if(buf_len < sizeof(rhp_proto_gre)){
    printf( "Invalid GRE/NHRP format. (1)\n" );
    return -1;
  }

  if( greh->protocol_type != RHP_PROTO_ETH_NHRP ){
    printf( "Invalid GRE/NHRP format. Not NHRP packet. (2) : 0x%x\n",(int)ntohs(greh->protocol_type));
    return -1;
  }

  printf("== GRE ==\n");
  printf(" Flags : check_sum:%d, reserved:%d, key:%d, seq:%d, reserved:%d, reserved:%d, ver:%d\n",
  		greh->check_sum_flag,greh->reserved_flag0,greh->key_flag,greh->seq_flag,greh->reserved_flag1,greh->reserved_flag2,greh->ver);
  printf(" Protocol Type: 0x%x\n",(int)ntohs(greh->protocol_type));

  if( greh->check_sum_flag ){
  	gre_len += 4;
  }

  if( greh->key_flag ){
  	gre_len += 4;
  }

  if( greh->seq_flag ){
  	gre_len += 4;
  }

  if(buf_len <= gre_len){
    printf( "Invalid GRE/NHRP format. (3)\n" );
    return -1;
  }

  p = (u8*)(greh + 1);
	if( greh->check_sum_flag ){
	  printf(" Checksum: 0x%x, Reserved: 0x%x\n",(int)ntohs(*((u16*)p)),(int)ntohs(*((u16*)(p + 2))));
		p += 4; // Including Reserved1 field.
  }

	if( greh->key_flag ){
	  printf(" Key: 0x%x\n",ntohl(*((u32*)p)));
		p += 4;
	}

	if( greh->seq_flag ){
	  printf(" Key: %u\n",ntohl(*((u32*)p)));
		p += 4;
	}


  if(buf_len <= gre_len + sizeof(rhp_proto_nhrp)){
    printf( "Invalid GRE/NHRP format. (4)\n" );
    return -1;
  }

	nhrph = (rhp_proto_nhrp*)(((u8*)greh) + gre_len);

	nhrp_len = buf_len - gre_len;

  printf("== NHRP ==\n");
  {
  	fixedh = (rhp_proto_nhrp_fixed*)nhrph;

  	if( nhrp_len != (int)ntohs(fixedh->len) ){
  	  printf(" **** NHRP Invalid mesg length!!! **** nhrp_len:%d != fixedh->len:%d, buf_len: %d, gre_len:%d\n",nhrp_len,(int)ntohs(fixedh->len),buf_len,gre_len);
  	  return -1;
  	}

    if( fixedh->address_family_no == RHP_PROTO_NHRP_ADDR_FAMILY_IPV4 ){
			af_label = "IPv4";
		}else if( fixedh->address_family_no == RHP_PROTO_NHRP_ADDR_FAMILY_IPV6 ){
			af_label = "IPv6";
		}else{
			af_label = "Unknown";
		}

    if( fixedh->packet_type == RHP_PROTO_NHRP_PKT_RESOLUTION_REQ ){
	    pkt_type_label = "RESOLUTION_REQ";
    }else if( fixedh->packet_type == RHP_PROTO_NHRP_PKT_RESOLUTION_REP ){
	    pkt_type_label = "RESOLUTION_REP";
    }else if( fixedh->packet_type == RHP_PROTO_NHRP_PKT_REGISTRATION_REQ ){
	    pkt_type_label = "REGISTRATION_REQ";
  	}else if( fixedh->packet_type == RHP_PROTO_NHRP_PKT_REGISTRATION_REP ){
	    pkt_type_label = "REGISTRATION_REP";
		}else if( fixedh->packet_type == RHP_PROTO_NHRP_PKT_PURGE_REQ ){
	    pkt_type_label = "PURGE_REQ";
		}else if( fixedh->packet_type == RHP_PROTO_NHRP_PKT_PURGE_REP ){
	    pkt_type_label = "PURGE_REP";
		}else if( fixedh->packet_type == RHP_PROTO_NHRP_PKT_ERROR_INDICATION ){
	    pkt_type_label = "ERROR_INDICATION";
		}else if( fixedh->packet_type == RHP_PROTO_NHRP_PKT_TRAFFIC_INDICATION ){
	    pkt_type_label = "TRAFFIC_INDICATION";
		}else{
	    pkt_type_label = "Unknown";
		}

  	printf(" Fixed: address_family_no: %s(0x%x)\n",af_label,(int)ntohs(fixedh->address_family_no));
  	printf(" Fixed: protocol_type: 0x%x (IPv4: 0x0800, IPv6: 0x86dd)\n",(int)ntohs(fixedh->protocol_type));
  	printf(" Fixed: ptotocol_type_snap: 0x%x%x%x%x%x\n",fixedh->ptotocol_type_snap[0],fixedh->ptotocol_type_snap[1],fixedh->ptotocol_type_snap[2],fixedh->ptotocol_type_snap[3],fixedh->ptotocol_type_snap[4]);
  	printf(" Fixed: hop_count: %d\n",fixedh->hop_count);
  	printf(" Fixed: len: %d\n",(int)ntohs(fixedh->len));
  	printf(" Fixed: check_sum: 0x%x\n",(int)ntohs(fixedh->check_sum));
  	printf(" Fixed: extension_offset: %d\n",(int)ntohs(fixedh->extension_offset));
  	printf(" Fixed: version: %d\n",fixedh->version);
  	printf(" Fixed: packet_type: %s(%d)\n",pkt_type_label,fixedh->packet_type);
  	printf(" Fixed: src_nbma_addr_type_reserved: %d\n",fixedh->src_nbma_addr_type_reserved);
  	printf(" Fixed: src_nbma_addr_type_flag: %d\n",fixedh->src_nbma_addr_type_flag);
  	printf(" Fixed: src_nbma_addr_type_len: %d\n",fixedh->src_nbma_addr_type_len);
  	printf(" Fixed: src_nbma_saddr_type_reserved: %d\n",fixedh->src_nbma_saddr_type_reserved);
  	printf(" Fixed: src_nbma_saddr_type_flag: %d\n",fixedh->src_nbma_saddr_type_flag);
  	printf(" Fixed: src_nbma_saddr_type_len: %d\n\n",fixedh->src_nbma_saddr_type_len);

    printf( "==<DUMP>==" );
    _rhp_bin_dump( NULL, (u8*)fixedh, sizeof(rhp_proto_nhrp_fixed), 1 );
    printf( "\n" );
  }

  if( fixedh->packet_type == RHP_PROTO_NHRP_PKT_RESOLUTION_REQ ||
  		fixedh->packet_type == RHP_PROTO_NHRP_PKT_RESOLUTION_REP ||
  		fixedh->packet_type == RHP_PROTO_NHRP_PKT_REGISTRATION_REQ ||
  		fixedh->packet_type == RHP_PROTO_NHRP_PKT_REGISTRATION_REP ||
  		fixedh->packet_type == RHP_PROTO_NHRP_PKT_PURGE_REQ ||
  		fixedh->packet_type == RHP_PROTO_NHRP_PKT_PURGE_REP ){

  	rhp_proto_nhrp_mandatory* mandatoryh = (rhp_proto_nhrp_mandatory*)(fixedh + 1);
  	int ext_off_set = (int)ntohs(fixedh->extension_offset);
  	rhp_proto_nhrp_ext* exth
  		= (rhp_proto_nhrp_ext*)(((u8*)fixedh) + (ext_off_set ? ext_off_set : (int)ntohs(fixedh->len)));

  	printf(" MANDATORY: src_protocol_len: %d\n",mandatoryh->src_protocol_len);
  	printf(" MANDATORY: dst_protocol_len: %d\n",mandatoryh->dst_protocol_len);
  	printf(" MANDATORY: flags: 0x%x\n",mandatoryh->flags);
  	printf(" MANDATORY: request_id: %u\n",ntohl(mandatoryh->request_id));

    if( buf_len < gre_len + sizeof(rhp_proto_nhrp)
    		+ fixedh->src_nbma_addr_type_len + fixedh->src_nbma_saddr_type_len
    		+ mandatoryh->src_protocol_len + mandatoryh->dst_protocol_len ){
      printf( "Invalid GRE/NHRP format. (5)\n" );
      return -1;
    }

    if( (u8*)exth > ((u8*)fixedh) + nhrp_len ){
      printf( "Invalid GRE/NHRP format. (6)\n" );
      return -1;
    }

    p = (u8*)(mandatoryh + 1);

    tmp[0] = '\0';
    tmp2[0] = '\0';
    tmp3[0] = '\0';
    tmp4[0] = '\0';
    if( fixedh->src_nbma_addr_type_len == 4 ){
    	printf(" Src NBMA Addr v4: %d.%d.%d.%d\n",p[0],p[1],p[2],p[3]);
    	sprintf(tmp3,"%d.%d.%d.%d",p[0],p[1],p[2],p[3]);
    	p += 4;
    }else if( fixedh->src_nbma_addr_type_len == 16 ){
      strcpy(tmp3,_rhp_ipv6_string(p));
    	printf(" Src NBMA Addr v6: %s\n",tmp3);
    	p += 16;
    }else if( fixedh->src_nbma_addr_type_len != 0 ){
      printf( "Unknown fixedh->src_nbma_addr_type_len. %d\n",fixedh->src_nbma_addr_type_len);
      return -1;
    }else{
    	sprintf(tmp3,"N/A");
    }

    if( fixedh->src_nbma_saddr_type_len == 4 ){
    	printf(" Src NBMA SubAddr v4: %d.%d.%d.%d\n",p[0],p[1],p[2],p[3]);
    	sprintf(tmp4,"%d.%d.%d.%d",p[0],p[1],p[2],p[3]);
    	p += 4;
    }else if( fixedh->src_nbma_saddr_type_len == 16 ){
      strcpy(tmp4,_rhp_ipv6_string(p));
    	printf(" Src NBMA SubAddr v6: %s\n",tmp4);
    	p += 16;
    }else if( fixedh->src_nbma_saddr_type_len != 0 ){
      printf( "Unknown fixedh->src_nbma_saddr_type_len. %d\n",fixedh->src_nbma_saddr_type_len);
      return -1;
    }

    if( mandatoryh->src_protocol_len == 4 ){
    	printf(" Src Protocol Addr v4: %d.%d.%d.%d\n",p[0],p[1],p[2],p[3]);
    	sprintf(tmp,"%d.%d.%d.%d",p[0],p[1],p[2],p[3]);
    	p += 4;
    }else if( mandatoryh->src_protocol_len == 16 ){
      strcpy(tmp,_rhp_ipv6_string(p));
    	printf(" Src Protocol Addr v6: %s\n",tmp);
    	p += 16;
    }else if( mandatoryh->src_protocol_len != 0 ){
      printf( "Unknown mandatoryh->src_protocol_len. %d\n",mandatoryh->src_protocol_len);
      return -1;
    }

    if( mandatoryh->dst_protocol_len == 4 ){
    	printf(" Dst Protocol Addr v4: %d.%d.%d.%d\n",p[0],p[1],p[2],p[3]);
    	sprintf(tmp2,"%d.%d.%d.%d",p[0],p[1],p[2],p[3]);
    	p += 4;
    }else if( mandatoryh->dst_protocol_len == 16 ){
      strcpy(tmp2,_rhp_ipv6_string(p));
    	printf(" Dst Protocol Addr v6: %s\n",tmp2);
    	p += 16;
    }else if( mandatoryh->dst_protocol_len != 0 ){
      printf( "Unknown mandatoryh->dst_protocol_len. %d\n",mandatoryh->dst_protocol_len);
      return -1;
    }

    *smry_idx += sprintf( (smry + *smry_idx),
        "Src NBMA: %s Proto: %s >> %s AF:%s(%d)  %s(%d) ReqID:%u",tmp3,tmp,tmp2,
        af_label,(int)ntohs(fixedh->address_family_no),
        pkt_type_label,fixedh->packet_type,ntohl(mandatoryh->request_id));

    printf( "\n==<DUMP MANDATORY>==" );
    _rhp_bin_dump( NULL, (u8*)mandatoryh, sizeof(rhp_proto_nhrp_mandatory), 1 );
  	printf("\n");


    while( p < (u8*)exth ){

    	rhp_proto_nhrp_clt_info_entry* cie = (rhp_proto_nhrp_clt_info_entry*)p;

    	if( p + sizeof(rhp_proto_nhrp_clt_info_entry) > ((u8*)fixedh) + nhrp_len ){
        printf( "Invalid GRE/NHRP format. (7)\n" );
        return -1;
    	}

    	printf("  CIE: code: %d\n",cie->code);
    	printf("  CIE: prefix_len: %d\n",cie->prefix_len);
    	printf("  CIE: unused: %d\n",cie->unused);
    	printf("  CIE: mtu: %d\n",(int)ntohs(cie->mtu));
    	printf("  CIE: hold_time: %d\n",(int)ntohs(cie->hold_time));
    	printf("  CIE: clt_nbma_addr_type_len: %d\n",cie->clt_nbma_addr_type_len);
    	printf("  CIE: clt_nbma_saddr_type_len: %d\n",cie->clt_nbma_saddr_type_len);
    	printf("  CIE: clt_protocol_addr_len: %d\n",cie->clt_protocol_addr_len);
    	printf("  CIE: preference: 0x%x\n",cie->preference);

    	if( p + sizeof(rhp_proto_nhrp_clt_info_entry)
    			+ cie->clt_nbma_addr_type_len
    			+ cie->clt_nbma_saddr_type_len
    			+ cie->clt_protocol_addr_len > ((u8*)fixedh) + nhrp_len ){
        printf( "Invalid GRE/NHRP format. (7)\n" );
        return -1;
    	}


    	p = (u8*)(cie + 1);
    	if( cie->clt_nbma_addr_type_len == 4 ){
      	printf("  CIE: Client NBMA Addr v4: %d.%d.%d.%d\n",p[0],p[1],p[2],p[3]);
      	p += 4;
    	}else if( cie->clt_nbma_addr_type_len == 16 ){
        strcpy(tmp,_rhp_ipv6_string(p));
      	printf("  CIE: Client NBMA Addr v6: %s\n",tmp);
      	p += 16;
      }else if( cie->clt_nbma_addr_type_len != 0 ){
        printf( "Unknown cie->clt_nbma_addr_type_len. %d\n",cie->clt_nbma_addr_type_len);
        return -1;
    	}

    	if( cie->clt_nbma_saddr_type_len == 4 ){
      	printf("  CIE: Client NBMA SubAddr v4: %d.%d.%d.%d\n",p[0],p[1],p[2],p[3]);
      	p += 4;
    	}else if( cie->clt_nbma_saddr_type_len == 16 ){
        strcpy(tmp,_rhp_ipv6_string(p));
      	printf("  CIE: Client NBMA SubAddr v6: %s\n",tmp);
      	p += 16;
      }else if( cie->clt_nbma_saddr_type_len != 0 ){
        printf( "Unknown cie->clt_nbma_addr_type_len. %d\n",cie->clt_nbma_addr_type_len);
        return -1;
    	}

    	if( cie->clt_protocol_addr_len == 4 ){
      	printf("  CIE: Client Protocol Addr v4: %d.%d.%d.%d\n",p[0],p[1],p[2],p[3]);
      	p += 4;
    	}else if( cie->clt_protocol_addr_len == 16 ){
        strcpy(tmp,_rhp_ipv6_string(p));
      	printf("  CIE: Client Protocol Addr v6: %s\n",tmp);
      	p += 16;
      }else if( cie->clt_protocol_addr_len != 0 ){
        printf( "Unknown cie->clt_protocol_addr_len. %d\n",cie->clt_protocol_addr_len);
        return -1;
    	}

      printf( "\n==<DUMP MANDATORY-CIE>==" );
      _rhp_bin_dump( NULL, (u8*)cie, (p - (u8*)cie), 1 );

    	printf("\n");
    }

    if( fixedh->extension_offset ){

      while( p < ((u8*)fixedh) + nhrp_len ){

      	int ext_type;
      	int c_flag = 0;
      	int cies = 0;

    		exth = (rhp_proto_nhrp_ext*)p;

      	if( p + sizeof(rhp_proto_nhrp_ext) > ((u8*)fixedh) + nhrp_len ){
          printf( "Invalid GRE/NHRP format. (8)\n" );
          return -1;
      	}

      	p += sizeof(rhp_proto_nhrp_ext);

      	ext_type = ntohs(RHP_PROTO_NHRP_EXT_TYPE(exth->type));
      	c_flag = RHP_PROTO_NHRP_EXT_FLAG_IS_COMPULSORY(exth->type);

      	if( ext_type == RHP_PROTO_NHRP_EXT_TYPE_END ){

      		if( ntohs(exth->len) == 0 ){
        		printf(" Ext-END: len: %d\n",ntohs(exth->len));
      		}else{
      			printf( "Invalid GRE/NHRP format. (10)\n" );
            return -1;
      		}

      	}else if( ext_type == RHP_PROTO_NHRP_EXT_TYPE_RESPONDER_ADDRESS ){

      		printf(" Ext-RESPONDER-ADDRESS: compulsory:%d len: %d\n",c_flag,ntohs(exth->len));
      		cies = 1;

      	}else if( ext_type == RHP_PROTO_NHRP_EXT_TYPE_FORWARD_TRANSIT_NHS_RECORD ){

      		printf(" Ext-FORWARD-TRANSIT-NHS-RECORD: compulsory:%d len: %d\n",c_flag,ntohs(exth->len));
      		cies = 1;

      	}else if( ext_type == RHP_PROTO_NHRP_EXT_TYPE_REVERSE_TRANSIT_NHS_RECORD ){

      		printf(" Ext-REVERSE-TRANSIT-NHS-RECORD: compulsory:%d len: %d\n",c_flag,ntohs(exth->len));
      		cies = 1;

      	}else if( ext_type == RHP_PROTO_NHRP_EXT_TYPE_AUTHENTICATION ){

      		printf(" Ext-AUTHENTICATION: compulsory:%d len: %d\n",c_flag,ntohs(exth->len));

      	}else if( ext_type == RHP_PROTO_NHRP_EXT_TYPE_VENDOR_PRIVATE ){

      		printf(" Ext-VENDOR-PRIVATE: compulsory:%d len: %d\n",c_flag,ntohs(exth->len));

      	}else if( ext_type == RHP_PROTO_NHRP_EXT_TYPE_NAT_ADDRESS ){

      		printf(" Ext-NAT-ADDRESS: compulsory:%d len: %d\n",c_flag,ntohs(exth->len));
      		cies = 1;

      	}else{

      		printf(" Ext-UNKNOWN: compulsory:%d len: %d\n",ntohs(exth->len));
      	}

      	if( cies ){

      		u8* cie_p = (u8*)(exth + 1);

      		while( cie_p < ((u8*)exth) + ntohs(exth->len) ){

          	rhp_proto_nhrp_clt_info_entry* cie = (rhp_proto_nhrp_clt_info_entry*)cie_p;

          	if( cie_p + sizeof(rhp_proto_nhrp_clt_info_entry) > ((u8*)fixedh) + nhrp_len ){
              printf( "Invalid GRE/NHRP format. (11)\n" );
              return -1;
          	}

          	printf("  CIE: code: %d\n",cie->code);
          	printf("  CIE: prefix_len: %d\n",cie->prefix_len);
          	printf("  CIE: unused: %d\n",cie->unused);
          	printf("  CIE: mtu: %d\n",(int)ntohs(cie->mtu));
          	printf("  CIE: hold_time: %d\n",(int)ntohs(cie->hold_time));
          	printf("  CIE: clt_nbma_addr_type_len: %d\n",cie->clt_nbma_addr_type_len);
          	printf("  CIE: clt_nbma_saddr_type_len: %d\n",cie->clt_nbma_saddr_type_len);
          	printf("  CIE: clt_protocol_addr_len: %d\n",cie->clt_protocol_addr_len);
          	printf("  CIE: preference: 0x%x\n",cie->preference);

          	if( cie_p + sizeof(rhp_proto_nhrp_clt_info_entry)
          			+ cie->clt_nbma_addr_type_len
          			+ cie->clt_nbma_saddr_type_len
          			+ cie->clt_protocol_addr_len > ((u8*)fixedh) + nhrp_len ){
              printf( "Invalid GRE/NHRP format. (12)\n" );
              return -1;
          	}


          	cie_p = (u8*)(cie + 1);
          	if( cie->clt_nbma_addr_type_len == 4 ){
            	printf("  CIE: Client NBMA Addr v4: %d.%d.%d.%d\n",cie_p[0],cie_p[1],cie_p[2],cie_p[3]);
            	cie_p += 4;
          	}else if( cie->clt_nbma_addr_type_len == 16 ){
              strcpy(tmp,_rhp_ipv6_string(cie_p));
            	printf("  CIE: Client NBMA Addr v6: %s\n",tmp);
            	cie_p += 16;
            }else if( cie->clt_nbma_addr_type_len != 0 ){
              printf( "Unknown cie->clt_nbma_addr_type_len. %d\n",cie->clt_nbma_addr_type_len);
              return -1;
          	}

          	if( cie->clt_nbma_saddr_type_len == 4 ){
            	printf("  CIE: Client NBMA SubAddr v4: %d.%d.%d.%d\n",cie_p[0],cie_p[1],cie_p[2],cie_p[3]);
            	cie_p += 4;
          	}else if( cie->clt_nbma_saddr_type_len == 16 ){
              strcpy(tmp,_rhp_ipv6_string(cie_p));
            	printf("  CIE: Client NBMA SubAddr v6: %s\n",tmp);
            	cie_p += 16;
            }else if( cie->clt_nbma_saddr_type_len != 0 ){
              printf( "Unknown cie->clt_nbma_addr_type_len. %d\n",cie->clt_nbma_addr_type_len);
              return -1;
          	}

          	if( cie->clt_protocol_addr_len == 4 ){
            	printf("  CIE: Client Protocol Addr v4: %d.%d.%d.%d\n",cie_p[0],cie_p[1],cie_p[2],cie_p[3]);
            	cie_p += 4;
          	}else if( cie->clt_protocol_addr_len == 16 ){
              strcpy(tmp,_rhp_ipv6_string(cie_p));
            	printf("  CIE: Client Protocol Addr v6: %s\n",tmp);
            	cie_p += 16;
            }else if( cie->clt_protocol_addr_len != 0 ){
              printf( "Unknown cie->clt_protocol_addr_len. %d\n",cie->clt_protocol_addr_len);
              return -1;
          	}

            printf( "\n==<DUMP EXT-CIE>==" );
            _rhp_bin_dump( NULL, (u8*)cie, (cie_p - (u8*)cie), 1 );

          	printf("\n");
      		}
      	}

        printf( "\n==<DUMP EXT>==" );
        _rhp_bin_dump( NULL, (u8*)exth, sizeof(rhp_proto_nhrp_ext) + ntohs(exth->len), 1 );

      	printf("\n");

      	p += ntohs(exth->len);
      }
    }

  }else if( fixedh->packet_type == RHP_PROTO_NHRP_PKT_ERROR_INDICATION ){

  	rhp_proto_nhrp_error* errorh = (rhp_proto_nhrp_error*)(fixedh + 1);

  	printf(" ERROR_INDICATION: src_protocol_len: %d\n",errorh->src_protocol_len);
  	printf(" ERROR_INDICATION: dst_protocol_len: %d\n",errorh->dst_protocol_len);
  	printf(" ERROR_INDICATION: error_code: %d\n",ntohs(errorh->error_code));
  	printf(" ERROR_INDICATION: error_offset: %u\n",ntohs(errorh->error_offset));

    if( buf_len < gre_len + sizeof(rhp_proto_nhrp)
    		+ fixedh->src_nbma_addr_type_len + fixedh->src_nbma_saddr_type_len
    		+ errorh->src_protocol_len + errorh->dst_protocol_len ){
      printf( "Invalid GRE/NHRP format. (20)\n" );
      return -1;
    }

    p = (u8*)(errorh + 1);

    tmp[0] = '\0';
    tmp2[0] = '\0';
    tmp3[0] = '\0';
    tmp4[0] = '\0';
    if( fixedh->src_nbma_addr_type_len == 4 ){
    	printf(" Src NBMA Addr v4: %d.%d.%d.%d\n",p[0],p[1],p[2],p[3]);
    	sprintf(tmp3,"%d.%d.%d.%d",p[0],p[1],p[2],p[3]);
    	p += 4;
    }else if( fixedh->src_nbma_addr_type_len == 16 ){
      strcpy(tmp3,_rhp_ipv6_string(p));
    	printf(" Src NBMA Addr v6: %s\n",tmp3);
    	p += 16;
    }else if( fixedh->src_nbma_addr_type_len != 0 ){
      printf( "Unknown fixedh->src_nbma_addr_type_len. %d\n",fixedh->src_nbma_addr_type_len);
      return -1;
    }else{
    	sprintf(tmp3,"N/A");
    }

    if( fixedh->src_nbma_saddr_type_len == 4 ){
    	printf(" Src NBMA SubAddr v4: %d.%d.%d.%d\n",p[0],p[1],p[2],p[3]);
    	sprintf(tmp4,"%d.%d.%d.%d",p[0],p[1],p[2],p[3]);
    	p += 4;
    }else if( fixedh->src_nbma_saddr_type_len == 16 ){
      strcpy(tmp4,_rhp_ipv6_string(p));
    	printf(" Src NBMA SubAddr v6: %s\n",tmp);
    	p += 16;
    }else if( fixedh->src_nbma_saddr_type_len != 0 ){
      printf( "Unknown fixedh->src_nbma_saddr_type_len. %d\n",fixedh->src_nbma_saddr_type_len);
      return -1;
    }

    if( errorh->src_protocol_len == 4 ){
    	printf(" Src Protocol Addr v4: %d.%d.%d.%d\n",p[0],p[1],p[2],p[3]);
    	sprintf(tmp,"%d.%d.%d.%d",p[0],p[1],p[2],p[3]);
    	p += 4;
    }else if( errorh->src_protocol_len == 16 ){
      strcpy(tmp,_rhp_ipv6_string(p));
    	printf(" Src Protocol Addr v6: %s\n",tmp);
    	p += 16;
    }else if( errorh->src_protocol_len != 0 ){
      printf( "Unknown errorh->src_protocol_len. %d\n",errorh->src_protocol_len);
      return -1;
    }

    if( errorh->dst_protocol_len == 4 ){
    	printf(" Dst Protocol Addr v4: %d.%d.%d.%d\n",p[0],p[1],p[2],p[3]);
    	sprintf(tmp2,"%d.%d.%d.%d",p[0],p[1],p[2],p[3]);
    	p += 4;
    }else if( errorh->dst_protocol_len == 16 ){
      strcpy(tmp2,_rhp_ipv6_string(p));
    	printf(" Dst Protocol Addr v6: %s\n",tmp2);
    	p += 16;
    }else if( errorh->dst_protocol_len != 0 ){
      printf( "Unknown errorh->dst_protocol_len. %d\n",errorh->dst_protocol_len);
      return -1;
    }

    *smry_idx += sprintf( (smry + *smry_idx),
        "Src NBMA: %s Proto: %s >> %s AF:%s(%d)  %s(%d) ",tmp3,tmp,tmp2,
        af_label,(int)ntohs(fixedh->address_family_no),
        pkt_type_label,fixedh->packet_type);

    printf( "\n==<DUMP ERROR_INDICATION>==" );
    _rhp_bin_dump( NULL, (u8*)errorh, sizeof(rhp_proto_nhrp_error), 1);
  	printf("\n");

  	if( errorh->error_offset ){

      printf( "\n==<DUMP ERROR_INDICATION ORIG_PKT>==" );
      _rhp_bin_dump( NULL,(u8*)p,((((u8*)fixedh) + nhrp_len) - p),1);
    	printf("\n");
  	}

  }else if( fixedh->packet_type == RHP_PROTO_NHRP_PKT_TRAFFIC_INDICATION ){

  	rhp_proto_nhrp_traffic_indication* traffich
  		= (rhp_proto_nhrp_traffic_indication*)(fixedh + 1);

  	printf(" TRAFFIC_INDICATION: src_protocol_len: %d\n",traffich->src_protocol_len);
  	printf(" TRAFFIC_INDICATION: dst_protocol_len: %d\n",traffich->dst_protocol_len);
  	printf(" TRAFFIC_INDICATION: traffic_code: %d\n",ntohs(traffich->traffic_code));

    if( buf_len < gre_len + sizeof(rhp_proto_nhrp)
    		+ fixedh->src_nbma_addr_type_len + fixedh->src_nbma_saddr_type_len
    		+ traffich->src_protocol_len + traffich->dst_protocol_len ){
      printf( "Invalid GRE/NHRP format. (30)\n" );
      return -1;
    }

    p = (u8*)(traffich + 1);

    if( fixedh->src_nbma_addr_type_len == 4 ){
    	printf(" Src NBMA Addr v4: %d.%d.%d.%d\n",p[0],p[1],p[2],p[3]);
    	sprintf(tmp3,"%d.%d.%d.%d",p[0],p[1],p[2],p[3]);
    	p += 4;
    }else if( fixedh->src_nbma_addr_type_len == 16 ){
      strcpy(tmp3,_rhp_ipv6_string(p));
    	printf(" Src NBMA Addr v6: %s\n",tmp3);
    	p += 16;
    }else if( fixedh->src_nbma_addr_type_len != 0 ){
      printf( "Unknown fixedh->src_nbma_addr_type_len. %d\n",fixedh->src_nbma_addr_type_len);
      return -1;
    }else{
    	sprintf(tmp3,"N/A");
    }

    if( fixedh->src_nbma_saddr_type_len == 4 ){
    	printf(" Src NBMA SubAddr v4: %d.%d.%d.%d\n",p[0],p[1],p[2],p[3]);
    	p += 4;
    }else if( fixedh->src_nbma_saddr_type_len == 16 ){
      strcpy(tmp,_rhp_ipv6_string(p));
    	printf(" Src NBMA SubAddr v6: %s\n",tmp);
    	p += 16;
    }else if( fixedh->src_nbma_saddr_type_len != 0 ){
      printf( "Unknown fixedh->src_nbma_saddr_type_len. %d\n",fixedh->src_nbma_saddr_type_len);
      return -1;
    }

    if( traffich->src_protocol_len == 4 ){
    	printf(" Src Protocol Addr v4: %d.%d.%d.%d\n",p[0],p[1],p[2],p[3]);
    	sprintf(tmp,"%d.%d.%d.%d",p[0],p[1],p[2],p[3]);
    	p += 4;
    }else if( traffich->src_protocol_len == 16 ){
      strcpy(tmp,_rhp_ipv6_string(p));
    	printf(" Src Protocol Addr v6: %s\n",tmp);
    	p += 16;
    }else if( traffich->src_protocol_len != 0 ){
      printf( "Unknown traffich->src_protocol_len. %d\n",traffich->src_protocol_len);
      return -1;
    }

    if( traffich->dst_protocol_len == 4 ){
    	printf(" Dst Protocol Addr v4: %d.%d.%d.%d\n",p[0],p[1],p[2],p[3]);
    	sprintf(tmp2,"%d.%d.%d.%d",p[0],p[1],p[2],p[3]);
    	p += 4;
    }else if( traffich->dst_protocol_len == 16 ){
      strcpy(tmp2,_rhp_ipv6_string(p));
    	printf(" Dst Protocol Addr v6: %s\n",tmp2);
    	p += 16;
    }else if( traffich->dst_protocol_len != 0 ){
      printf( "Unknown traffich->dst_protocol_len. %d\n",traffich->dst_protocol_len);
      return -1;
    }

    *smry_idx += sprintf( (smry + *smry_idx),
        "Src NBMA: %s Proto: %s >> %s AF:%s(%d)  %s(%d) ",tmp3,tmp,tmp2,
        af_label,(int)ntohs(fixedh->address_family_no),
        pkt_type_label,fixedh->packet_type);

    printf( "\n==<DUMP TRAFFIC_INDICATION>==" );
    _rhp_bin_dump( NULL, (u8*)traffich, sizeof(rhp_proto_nhrp_error), 1 );
  	printf("\n");

  	if( nhrp_len > sizeof(rhp_proto_nhrp_traffic_indication) ){

  		int orig_pkt_len = ((((u8*)fixedh) + nhrp_len) - p);

  		if( orig_pkt_len >= sizeof(rhp_proto_ip_v4) ){

  			rhp_proto_ip_v4* ipv4h = (rhp_proto_ip_v4*)p;

  			if( ipv4h->ver == 4 ){
  		    *smry_idx += sprintf( (smry + *smry_idx)," Orig: ");
    			_print_ipv4(p,orig_pkt_len,NULL,NULL,smry_idx,smry);
  			}else if( ipv4h->ver == 6 ){
  		    *smry_idx += sprintf( (smry + *smry_idx)," Orig: ");
    			_print_ipv6(p,orig_pkt_len,NULL,NULL,smry_idx,smry,NULL);
  			}else{
    			printf( "Unknown IP version. %d\n",ipv4h->ver);
  			}

  		}else{

  			printf( "Invalid orig pkt len. %d\n",orig_pkt_len);
  		}

      printf( "\n==<DUMP TRAFFIC_INDICATION ORIG_PKT>==" );
      _rhp_bin_dump( NULL,(u8*)p,orig_pkt_len,1);
    	printf("\n");
  	}

  }else{
  	printf(" Unknown packet_type. \n");
  }

  return 0;
}



#define RHP_STATUS_INVALID_DNS_PKT									1
#define RHP_STATUS_DNS_PKT_NOT_INTERESTED		2
static int _rhp_dns_pxy_parse_dns_pkt( u8* rx_buf, int rx_buf_len,
    char** queried_domain_r )
{
  int err = -EINVAL;
  rhp_proto_dns* dnsh = (rhp_proto_dns*) rx_buf;
  u16 qnum;
#define RHP_DNS_PXY_PARSE_BUF_LEN		256
  char *queried_domain = NULL, *cur;
  u8 *pt;
  int rem, cur_len, cur_rem;

  if(rx_buf_len < (int) sizeof(rhp_proto_dns)){
    err = RHP_STATUS_INVALID_DNS_PKT;
    goto error;
  }

  qnum = ntohs( dnsh->qdcount );

  if(qnum == 0){
    err = RHP_STATUS_DNS_PKT_NOT_INTERESTED;
    goto error;
  }

  queried_domain = (char*) malloc( RHP_DNS_PXY_PARSE_BUF_LEN );
  if(queried_domain == NULL){
    err = -ENOMEM;
    goto error;
  }

  cur = queried_domain;
  cur_len = cur_rem = RHP_DNS_PXY_PARSE_BUF_LEN;

  pt = (u8*) (dnsh + 1);
  rem = rx_buf_len - sizeof(rhp_proto_dns);

  while(rem){

    u8 label_len = *pt;

    rem--;
    pt++;

    if(label_len == 0 || rem < 1){
      break;
    }

    rem -= label_len;
    if(rem < 1){
      err = RHP_STATUS_DNS_PKT_NOT_INTERESTED;
      goto error;
    }

    if(cur_rem < (label_len + 1)){

      char* tmp = queried_domain;
      int exp_len = (label_len + 1) + cur_len;

      queried_domain = (char*) malloc( cur_len + exp_len );
      if(queried_domain == NULL){
        err = -ENOMEM;
        queried_domain = tmp;
        goto error;
      }

      memcpy( queried_domain, tmp, cur_len );
      cur = queried_domain + cur_len;
      cur_rem = exp_len;
      cur_len = cur_len + exp_len;
      free( tmp );
    }

    memcpy( cur, pt, label_len );
    cur += label_len;
    *cur = '.';
    cur++;

    pt += label_len;
  }

  if(queried_domain == cur){
    err = RHP_STATUS_DNS_PKT_NOT_INTERESTED;
    goto error;
  }

  *(cur - 1) = '\0';
  *queried_domain_r = queried_domain;

  return 0;

  error: if(queried_domain){
    free( queried_domain );
  }
  return err;
}

static int _print_udp( u8* buf, int buf_len, int* data_len, int is_ipsec_mesg,
    int* smry_idx, char* smry )
{
  rhp_proto_udp* udp = (rhp_proto_udp*)buf;

  printf( "\n==<UDP>==\n" );

  if(buf_len < sizeof(rhp_proto_udp)){
    printf( "Invalid UDP format.\n" );
    return -1;
  }

  printf( "src_port : %d\n", ntohs( udp->src_port ) );
  printf( "dst_port : %d\n", ntohs( udp->dst_port ) );
  printf( "len : %d\n", ntohs( udp->len ) );
  printf( "checksum : %d\n", ntohs( udp->check_sum ) );

  *smry_idx += sprintf( (smry + *smry_idx), "[%d >> %d]",ntohs( udp->src_port ), ntohs( udp->dst_port ) );

  if(is_ipsec_mesg && ((ntohs( udp->src_port ) == 4500) || (ntohs(udp->dst_port ) == 4500))){

    if(buf_len >= sizeof(rhp_proto_udp) + RHP_PROTO_NON_ESP_MARKER_SZ
        && *((u32*) (udp + 1)) == RHP_PROTO_NON_ESP_MARKER){

      _rhp_bin_dump( "N ESP MKR", (u8*) (udp + 1),RHP_PROTO_NON_ESP_MARKER_SZ, 1 );

      if(data_len){
        *data_len = sizeof(rhp_proto_udp) + RHP_PROTO_NON_ESP_MARKER_SZ;
      }

    }else{

      if(data_len){
        *data_len = sizeof(rhp_proto_udp);
      }
    }

    *smry_idx += sprintf( (smry + *smry_idx), " NATT" );

  }else{

    if((ntohs( udp->dst_port ) == 53) || (ntohs( udp->src_port ) == 53)){

      char* dname = NULL;

      _rhp_dns_pxy_parse_dns_pkt( (u8*) (udp + 1), (int) ntohs( udp->len ),
          &dname );

      if(dname){
        printf( "DNS : %s\n", dname );
        *smry_idx += sprintf( (smry + *smry_idx), " DNS : %s", dname );
        free( dname );
      }else{
        printf( "DNS\n" );
        *smry_idx += sprintf( (smry + *smry_idx), " DNS" );
      }

    }else if( (ntohs( udp->dst_port ) == 1812) || (ntohs( udp->src_port ) == 1812) ||
    				  (ntohs( udp->dst_port ) == 1813) || (ntohs( udp->src_port ) == 1813) ){

    	rhp_proto_radius* radiush = (rhp_proto_radius*)(udp + 1);

      if( buf_len >= sizeof(rhp_proto_udp) + sizeof(rhp_proto_radius) ){

      	int radius_len = ntohs(radiush->len);

        printf( "\n  ==<RADIUS>==\n" );

        switch(radiush->code){
        case RHP_RADIUS_CODE_ACCESS_REQUEST:
          printf( "  code : ACCESS_REQUEST(%d)\n", radiush->code );
          *smry_idx += sprintf((smry + *smry_idx), " RADIUS : ACCESS_REQUEST id:%d", radiush->id);
          break;
        case RHP_RADIUS_CODE_ACCESS_ACCEPT:
          printf( "  code : ACCESS_ACCEPT(%d)\n", radiush->code );
          *smry_idx += sprintf((smry + *smry_idx), " RADIUS : ACCESS_ACCEPT id:%d", radiush->id);
          break;
        case RHP_RADIUS_CODE_ACCESS_REJECT:
          printf( "  code : ACCESS_REJECT(%d)\n", radiush->code );
          *smry_idx += sprintf((smry + *smry_idx), " RADIUS : ACCESS_REJECT id:%d", radiush->id);
          break;
        case RHP_RADIUS_CODE_ACCESS_CHALLENGE:
          printf( "  code : ACCESS_CHALLENGE(%d)\n", radiush->code );
          *smry_idx += sprintf((smry + *smry_idx), " RADIUS : ACCESS_CHALLENGE id:%d", radiush->id);
          break;
        case RHP_RADIUS_CODE_ACCT_REQUEST:
          printf( "  code : ACCT_REQUEST(%d)\n", radiush->code );
          *smry_idx += sprintf((smry + *smry_idx), " RADIUS : ACCT_REQUEST id:%d", radiush->id);
          break;
        case RHP_RADIUS_CODE_ACCT_RESPONSE:
          printf( "  code : ACCT_RESPONSE(%d)\n", radiush->code );
          *smry_idx += sprintf((smry + *smry_idx), " RADIUS : ACCT_RESPONSE id:%d", radiush->id);
          break;
        default:
          printf( "  code : %d\n", radiush->code );
          *smry_idx += sprintf((smry + *smry_idx), " RADIUS : code:%d id:%d",radiush->code, radiush->id);
          break;
        }
        printf( "  id : %d\n", radiush->id );
        printf( "  len : %d\n", radius_len );
        _rhp_bin_dump("authenticator",radiush->authenticator,RHP_RADIUS_AUTHENTICATOR_LEN,1);

      	if( buf_len >= sizeof(rhp_proto_udp) + radius_len ){

      		int rad_i = 1;
      		rhp_proto_radius_attr* radius_attrh = (rhp_proto_radius_attr*)(radiush + 1);
      		radius_len -= sizeof(rhp_proto_radius);

      		while( radius_len > 0 && (buf + buf_len) > (u8*)radius_attrh ){

      			printf("\n");

      			if( (radius_attrh + 1) > (buf + buf_len) ||
      					radius_attrh->len < sizeof(rhp_proto_radius_attr) ){
        			printf("    ATTR[%d] Invalid attribute found.",rad_i);
      				break;
      			}

      			switch(radius_attrh->type){
      			case RHP_RADIUS_ATTR_TYPE_USER_NAME:
        			printf("    ATTR[%d] type: USER_NAME(%d), len: %d",rad_i,radius_attrh->type,radius_attrh->len);
      				break;
      			case RHP_RADIUS_ATTR_TYPE_NAS_IP_ADDRESS:
        			printf("    ATTR[%d] type: NAS_IP_ADDRESS(%d), len: %d",rad_i,radius_attrh->type,radius_attrh->len);
        			if( radius_attrh->len == 4 + sizeof(rhp_proto_radius_attr) ){
        				printf("  %d.%d.%d.%d",((u8*)(radius_attrh + 1))[0],((u8*)(radius_attrh + 1))[1],((u8*)(radius_attrh + 1))[2],((u8*)(radius_attrh + 1))[3]);
        			}
    					break;
      			case RHP_RADIUS_ATTR_TYPE_NAS_IPV6_ADDRESS:
        			printf("    ATTR[%d] type: NAS_IPV6_ADDRESS(%d), len: %d",rad_i,radius_attrh->type,radius_attrh->len);
        			if( radius_attrh->len == 16 + sizeof(rhp_proto_radius_attr) ){
        				printf("  %s",_rhp_ipv6_string((u8*)(radius_attrh + 1)));
        			}
    					break;
      			case RHP_RADIUS_ATTR_TYPE_NAS_ID:
        			printf("    ATTR[%d] type: NAS_ID(%d), len: %d",rad_i,radius_attrh->type,radius_attrh->len);
    					break;
      			case RHP_RADIUS_ATTR_TYPE_FRAMED_MTU:
        			printf("    ATTR[%d] type: FRAMED_MTU(%d), len: %d",rad_i,radius_attrh->type,radius_attrh->len);
      				break;
      			case RHP_RADIUS_ATTR_TYPE_CALLED_STATION_ID:
        			printf("    ATTR[%d] type: CALLED_STATION_ID(%d), len: %d",rad_i,radius_attrh->type,radius_attrh->len);
      				break;
      			case RHP_RADIUS_ATTR_TYPE_CALLING_STATION_ID:
        			printf("    ATTR[%d] type: CALLING_STATION_ID(%d), len: %d",rad_i,radius_attrh->type,radius_attrh->len);
      				break;
      			case RHP_RADIUS_ATTR_TYPE_NAS_PORT_TYPE:
        			printf("    ATTR[%d] type: NAS_PORT_TYPE(%d), len: %d",rad_i,radius_attrh->type,radius_attrh->len);
      				break;
      			case RHP_RADIUS_ATTR_TYPE_EAP:
      			{
      				rhp_proto_eap* eaph = (rhp_proto_eap*)(radius_attrh + 1);
        			printf("    ATTR[%d] type: EAP(%d), len: %d\n",rad_i,radius_attrh->type,radius_attrh->len);
        			if( radius_attrh->len >= sizeof(rhp_proto_radius_attr) + sizeof(rhp_proto_eap) ){

        				int eap_len = ntohs(eaph->len);

        				switch( eaph->code ){
        				case RHP_PROTO_EAP_CODE_REQUEST:
        					printf("      EAP: REQUEST(%d) id: %d, len: %d", eaph->code,eaph->identifier,eap_len);
        					break;
        				case RHP_PROTO_EAP_CODE_RESPONSE:
        					printf("      EAP: RESPONSE(%d) id: %d, len: %d", eaph->code,eaph->identifier,eap_len);
        					break;
        				case RHP_PROTO_EAP_CODE_SUCCESS:
        					printf("      EAP: SUCCESS(%d) id: %d, len: %d", eaph->code,eaph->identifier,eap_len);
        					break;
        				case RHP_PROTO_EAP_CODE_FAILURE:
        					printf("      EAP: FAILURE(%d) id: %d, len: %d", eaph->code,eaph->identifier,eap_len);
        					break;
        				default:
        					printf("      EAP: code(%d) id: %d, len: %d", eaph->code,eaph->identifier,eap_len);
        					break;
        				}

        				if( eaph->code == RHP_PROTO_EAP_CODE_REQUEST || eaph->code == RHP_PROTO_EAP_CODE_RESPONSE ){

        					if( eap_len >= sizeof(rhp_proto_eap_request) ){

        						rhp_proto_eap_request* eaprh = (rhp_proto_eap_request*)eaph;

        						switch( eaprh->type ){
        						case RHP_PROTO_EAP_TYPE_IDENTITY:
            					printf(" type: IDENTITY(%d)",eaprh->type);
        							break;
        						case RHP_PROTO_EAP_TYPE_NOTIFICATION:
            					printf(" type: NOTIFICATION(%d)",eaprh->type);
        							break;
        						case RHP_PROTO_EAP_TYPE_NAK:
            					printf(" type: NAK(%d)",eaprh->type);
        							break;
        						case RHP_PROTO_EAP_TYPE_MD5_CHALLENGE:
            					printf(" type: MD5_CHALLENGE(%d)",eaprh->type);
        							break;
        						case RHP_PROTO_EAP_TYPE_ONE_TIME_PASSWORD:
            					printf(" type: ONE_TIME_PASSWORD(%d)",eaprh->type);
        							break;
        						case RHP_PROTO_EAP_TYPE_GENERIC_TOKEN_CARD:
            					printf(" type: GENERIC_TOKEN_CARD(%d)",eaprh->type);
        							break;
        						case RHP_PROTO_EAP_TYPE_EAP_TLS:
            					printf(" type: EAP_TLS(%d)",eaprh->type);
        							break;
        						case RHP_PROTO_EAP_TYPE_EAP_GSM_SIM:
            					printf(" type: EAP_GSM_SIM(%d)",eaprh->type);
        							break;
        						case RHP_PROTO_EAP_TYPE_EAP_TTLS:
            					printf(" type: EAP_TTLS(%d)",eaprh->type);
        							break;
        						case RHP_PROTO_EAP_TYPE_EAP_AKA:
            					printf(" type: EAP_AKA(%d)",eaprh->type);
        							break;
        						case RHP_PROTO_EAP_TYPE_PEAP:
            					printf(" type: PEAP(%d)",eaprh->type);
        							break;
        						case RHP_PROTO_EAP_TYPE_MS_CHAPV2:
            					printf(" type: GENERIC_TOKEN_CARD(%d)",eaprh->type);
        							break;
        						case RHP_PROTO_EAP_TYPE_PEAPV0_MS_CHAPV2:
            					printf(" type: PEAPV0_MS_CHAPV2(%d)",eaprh->type);
        							break;
        						case RHP_PROTO_EAP_TYPE_EAP_FAST:
            					printf(" type: EAP_FAST(%d)",eaprh->type);
        							break;
        						case RHP_PROTO_EAP_TYPE_EAP_PSK:
            					printf(" type: EAP_PSK(%d)",eaprh->type);
        							break;
        						case RHP_PROTO_EAP_TYPE_EAP_SAKE:
            					printf(" type: EAP_SAKE(%d)",eaprh->type);
        							break;
        						case RHP_PROTO_EAP_TYPE_EAP_IKEV2:
            					printf(" type: EAP_IKEV2(%d)",eaprh->type);
        							break;
        						case RHP_PROTO_EAP_TYPE_EAP_AKA_PRIME:
            					printf(" type: EAP_AKA_PRIME(%d)",eaprh->type);
        							break;
        						case RHP_PROTO_EAP_TYPE_EAP_GPSK:
            					printf(" type: EAP_GPSK(%d)",eaprh->type);
        							break;
        						case RHP_PROTO_EAP_TYPE_EAP_PWD:
            					printf(" type: EAP_PWD(%d)",eaprh->type);
        							break;
        						case RHP_PROTO_EAP_TYPE_EAP_EKE_V1:
            					printf(" type: EAP_EKE_V1(%d)",eaprh->type);
        							break;
        						case RHP_PROTO_EAP_TYPE_EAP_PT_EAP:
            					printf(" type: EAP_PT_EAP(%d)",eaprh->type);
        							break;
        						case RHP_PROTO_EAP_TYPE_TEAP:
            					printf(" type: TEAP(%d)",eaprh->type);
        							break;
        						default:
            					printf(" type: %d",eaprh->type);
        							break;
        						}
        					}
        				}
        			}
      			}
      				break;
      			case RHP_RADIUS_ATTR_TYPE_MESG_AUTH:
        			printf("    ATTR[%d] type: MESG_AUTH(%d), len: %d",rad_i,radius_attrh->type,radius_attrh->len);
      				break;
      			case RHP_RADIUS_ATTR_TYPE_NAS_PORT:
        			printf("    ATTR[%d] type: NAS_PORT(%d), len: %d",rad_i,radius_attrh->type,radius_attrh->len);
      				break;
      			case RHP_RADIUS_ATTR_TYPE_NAS_PORT_ID:
        			printf("    ATTR[%d] type: NAS_PORT_ID(%d), len: %d",rad_i,radius_attrh->type,radius_attrh->len);
      				break;
      			case RHP_RADIUS_ATTR_TYPE_CONNECT_INFO:
        			printf("    ATTR[%d] type: CONNECT_INFO(%d), len: %d",rad_i,radius_attrh->type,radius_attrh->len);
      				break;
      			case RHP_RADIUS_ATTR_TYPE_SESSION_TIMEOUT:
        			printf("    ATTR[%d] type: SESSION_TIMEOUT(%d), len: %d",rad_i,radius_attrh->type,radius_attrh->len);
      				break;
      			case RHP_RADIUS_ATTR_TYPE_REPLY_MESG:
        			printf("    ATTR[%d] type: REPLY_MESG(%d), len: %d",rad_i,radius_attrh->type,radius_attrh->len);
      				break;
      			case RHP_RADIUS_ATTR_TYPE_STATE:
        			printf("    ATTR[%d] type: STATE(%d), len: %d",rad_i,radius_attrh->type,radius_attrh->len);
      				break;
      			case RHP_RADIUS_ATTR_TYPE_VENDOR_SPECIFIC:
      			{
      				rhp_proto_radius_attr_vendor* vh = (rhp_proto_radius_attr_vendor*)radius_attrh;
        			printf("    ATTR[%d] type: VENDOR_SPECIFIC(%d), len: %d",rad_i,radius_attrh->type,radius_attrh->len);
        			if( radius_attrh->len >= sizeof(rhp_proto_radius_attr_vendor) ){

        				u32 vid = ntohl(vh->vendor_id);

        				switch( vid ){
        				case RHP_RADIUS_ATTR_TYPE_VENDOR_SPECIFIC_CISCO:
        					printf("  vendor_id: Cisco(%d)",vid);
        					break;
        				case RHP_RADIUS_ATTR_TYPE_VENDOR_SPECIFIC_MICROSOFT:
        				{
        					rhp_proto_radius_attr_vendor_ms* msv = (rhp_proto_radius_attr_vendor_ms*)(vh + 1);
        					printf("  vendor_id: Microsoft(%d)", vid);
        					if( radius_attrh->len >= sizeof(rhp_proto_radius_attr_vendor) + sizeof(rhp_proto_radius_attr_vendor_ms) ){

        						switch( msv->vendor_type ){
        						case RHP_RADIUS_VENDOR_MS_ATTR_TYPE_MPPE_SEND_KEY:
        							printf(" vendor_type: MPPE_SEND_KEY(%d)",msv->vendor_type);
        							break;
        						case RHP_RADIUS_VENDOR_MS_ATTR_TYPE_MPPE_RECV_KEY:
        							printf(" vendor_type: MPPE_RECV_KEY(%d)",msv->vendor_type);
        							break;
        						case RHP_RADIUS_VENDOR_MS_ATTR_TYPE_MPPE_ENCRYPTION_POLICY:
        							printf(" vendor_type: MPPE_ENCRYPTION_POLICY(%d)",msv->vendor_type);
        							break;
        						case RHP_RADIUS_VENDOR_MS_ATTR_TYPE_MPPE_ENCRYPTION_TYPES:
        							printf(" vendor_type: MPPE_ENCRYPTION_TYPES(%d)",msv->vendor_type);
        							break;
        						case RHP_RADIUS_VENDOR_MS_ATTR_TYPE_PRIMARY_DNS_SERVER:
        							printf(" vendor_type: PRIMARY_DNS_SERVER(%d)",msv->vendor_type);
        							break;
        						case RHP_RADIUS_VENDOR_MS_ATTR_TYPE_SECONDARY_DNS_SERVER:
        							printf(" vendor_type: SECONDARY_DNS_SERVER(%d)",msv->vendor_type);
        							break;
        						case RHP_RADIUS_VENDOR_MS_ATTR_TYPE_PRIMARY_NBNS_SERVER:
        							printf(" vendor_type: PRIMARY_NBNS_SERVER(%d)",msv->vendor_type);
        							break;
        						case RHP_RADIUS_VENDOR_MS_ATTR_TYPE_SECONDARY_NBNS_SERVER:
        							printf(" vendor_type: SECONDARY_NBNS_SERVER(%d)",msv->vendor_type);
        							break;
        						default:
        							printf(" vendor_type(%d)",msv->vendor_type);
        							break;
        						}

        						printf(" vendor_len: %d",msv->vendor_len);
      	            _rhp_bin_dump("ms_attr_value:",(u8*)(msv + 1),(int)(msv->vendor_len - sizeof(rhp_proto_radius_attr_vendor_ms)),1);
        					}
        				}
        					break;
        				default:
        					printf("  vendor_id: %d",vid);
        					break;
        				}

        			}
      			}
      				break;
      			case RHP_RADIUS_ATTR_TYPE_TERMINATION_ACTION:
        			printf("    ATTR[%d] type: TERMINATION_ACTION(%d), len: %d",rad_i,radius_attrh->type,radius_attrh->len);
      				break;
      			case RHP_RADIUS_ATTR_TYPE_FRAMED_IP_ADDRESS:
        			printf("    ATTR[%d] type: FRAMED_IP_ADDRESS(%d), len: %d",rad_i,radius_attrh->type,radius_attrh->len);
        			if( radius_attrh->len == 4 + sizeof(rhp_proto_radius_attr) ){
        				printf(" %d.%d.%d.%d",((u8*)(radius_attrh + 1))[0],((u8*)(radius_attrh + 1))[1],((u8*)(radius_attrh + 1))[2],((u8*)(radius_attrh + 1))[3]);
        			}
      				break;
      			case RHP_RADIUS_ATTR_TYPE_FRAMED_IP_NETMASK:
        			printf("    ATTR[%d] type: FRAMED_IP_NETMASK(%d), len: %d",rad_i,radius_attrh->type,radius_attrh->len);
        			if( radius_attrh->len == 4 + sizeof(rhp_proto_radius_attr) ){
        				printf("  %d.%d.%d.%d",((u8*)(radius_attrh + 1))[0],((u8*)(radius_attrh + 1))[1],((u8*)(radius_attrh + 1))[2],((u8*)(radius_attrh + 1))[3]);
        			}
      				break;
      			case RHP_RADIUS_ATTR_TYPE_FRAMED_IPV6_ADDRESS:
        			printf("    ATTR[%d] type: FRAMED_IPV6_ADDRESS(%d), len: %d",rad_i,radius_attrh->type,radius_attrh->len);
        			if( radius_attrh->len == 16 + sizeof(rhp_proto_radius_attr) ){
        				printf("  %s",_rhp_ipv6_string((u8*)(radius_attrh + 1)));
        			}
      				break;
      			case RHP_RADIUS_ATTR_TYPE_DNS_IPV6_ADDRESS:
        			printf("    ATTR[%d] type: DNS_IPV6_ADDRESS(%d), len: %d",rad_i,radius_attrh->type,radius_attrh->len);
        			if( radius_attrh->len == 16 + sizeof(rhp_proto_radius_attr) ){
        				printf(" %s",_rhp_ipv6_string((u8*)(radius_attrh + 1)));
        			}
      				break;
      			default:
        			printf("    ATTR[%d] type: %d, len: %d",rad_i,radius_attrh->type,radius_attrh->len);
      				break;
      			}

            _rhp_bin_dump("attr_value:",(u8*)(radius_attrh + 1),(int)(radius_attrh->len - sizeof(rhp_proto_radius_attr)),1);

      			radius_len -= radius_attrh->len;
      			radius_attrh = (rhp_proto_radius_attr*)(((u8*)radius_attrh) + radius_attrh->len);
      			rad_i++;
      		}

      	}else{
          printf( "  Invalid RADIUS format. (1)\n" );
      	}

      }else{
        printf( "Invalid RADIUS format. (2)\n" );
      }
    }

    if(data_len){
      *data_len = sizeof(rhp_proto_udp);
    }
  }

  return 0;
}


static int _print_ikev2_nat_t_keepalive(u8* buf, int buf_len, int* data_len, int is_ipsec_mesg,
    int* smry_idx, char* smry )
{
  u8* ka_data = (u8*)buf;

  printf( "\n==<NAT-T Keep-Alive>==\n" );

  if(buf_len < 1){
    printf( "Invalid Keep-Alive format.\n" );
    return -1;
  }

  if( *ka_data != 0xFF ){
  	printf( "Invalid Keep-Alive-Data : 0x%x\n", *ka_data );
    *smry_idx += sprintf( (smry + *smry_idx), "%s","BAD-KA");
  }else{
  	printf( "Keep-Alive-Data : 0x%x\n", *ka_data );
  }

  if(data_len){
  	*data_len = 1;
  }

  return 0;
}

static int _print_icmp( u8* buf, int buf_len, int* data_len, int* smry_idx,
    char* smry )
{
  rhp_proto_icmp* icmp = (rhp_proto_icmp*) buf;

  printf( "\n==<ICMP>==\n" );

  if(buf_len < sizeof(rhp_proto_icmp)){
    printf( "Invalid ICMP format.\n" );
    return -1;
  }

  switch(icmp->type){

  case RHP_PROTO_ICMP_TYPE_ECHO_REPLY:
    printf( "type : ECHO_REPLY(%d)\n", icmp->type );
    *smry_idx += sprintf( (smry + *smry_idx), "  ECHO REPLY(%d)  C: %d",
        icmp->type, icmp->code );
    break;
  case RHP_PROTO_ICMP_TYPE_DEST_UNREACH:
    printf( "type : DEST_UNREACH(%d)\n", icmp->type );
    *smry_idx += sprintf( (smry + *smry_idx), "  DEST UNREACH(%d)  C: %d",
        icmp->type, icmp->code );
    break;
  case RHP_PROTO_ICMP_TYPE_SOURCE_QUENCH:
    printf( "type : SOURCE_QUENCH(%d)\n", icmp->type );
    *smry_idx += sprintf( (smry + *smry_idx), "  SRC QUENCH(%d)  C: %d",
        icmp->type, icmp->code );
    break;
  case RHP_PROTO_ICMP_TYPE_REDIRECT:
    printf( "type : REDIRECT(%d)\n", icmp->type );
    *smry_idx += sprintf( (smry + *smry_idx), "  REDIRECT(%d)  C: %d",
        icmp->type, icmp->code );
    break;
  case RHP_PROTO_ICMP_TYPE_ECHO_REQUEST:
    printf( "type : ECHO_REQUEST(%d)\n", icmp->type );
    *smry_idx += sprintf( (smry + *smry_idx), "  ECHO REQ(%d)  C: %d",
        icmp->type, icmp->code );
    break;
  case RHP_PROTO_ICMP_TYPE_ROUTER_ADVERTISEMENT:
    printf( "type : ROUTER_ADVERTISEMENT(%d)\n", icmp->type );
    *smry_idx += sprintf( (smry + *smry_idx), "  ROUTER ADV(%d)  C: %d",
        icmp->type, icmp->code );
    break;
  case RHP_PROTO_ICMP_TYPE_ROUTER_SOLICITATION:
    printf( "type : ROUTER_SOLICITATION(%d)\n", icmp->type );
    *smry_idx += sprintf( (smry + *smry_idx), "  ROUTER SOL(%d)  C: %d",
        icmp->type, icmp->code );
    break;
  case RHP_PROTO_ICMP_TYPE_TIME_EXCEEDED:
    printf( "type : TIME_EXCEEDED(%d)\n", icmp->type );
    *smry_idx += sprintf( (smry + *smry_idx), "  TIME EXCEEDED(%d)  C: %d",
        icmp->type, icmp->code );
    break;
  case RHP_PROTO_ICMP_TYPE_PARAM_PROBLEM:
    printf( "type : PARAM_PROBLEM(%d)\n", icmp->type );
    *smry_idx += sprintf( (smry + *smry_idx), "  PARAM PROB(%d)  C: %d",
        icmp->type, icmp->code );
    break;
  default:
    printf( "type : %d\n", icmp->type );
    *smry_idx += sprintf( (smry + *smry_idx), "  T: %d  C: %d", icmp->type,
        icmp->code );
    break;
  }

  printf( "code : %d\n", icmp->code );

  if(icmp->type == RHP_PROTO_ICMP_TYPE_ECHO_REPLY || icmp->type
      == RHP_PROTO_ICMP_TYPE_ECHO_REQUEST){

    rhp_proto_icmp_echo* echo = (rhp_proto_icmp_echo*) (icmp + 1);

    printf( "id: %d(0x%x) seq: %d(0x%x)\n", ntohs( echo->id ),
        ntohs( echo->id ), ntohs( echo->seq ), ntohs( echo->seq ) );
    *smry_idx += sprintf( (smry + *smry_idx), "  ID: %d(0x%x) SEQ: %d(0x%x)",
        ntohs( echo->id ), ntohs( echo->id ), ntohs( echo->seq ), ntohs(
            echo->seq ) );
  }

  if(data_len){
    *data_len = sizeof(rhp_proto_icmp);
  }

  return 0;
}

static int _print_icmp6( u8* buf, int buf_len, int* data_len, int* smry_idx,
    char* smry, int pld_len )
{
	rhp_proto_icmp6* icmp = (rhp_proto_icmp6*) buf;
	int opt_len = 0;

  printf( "\n==<ICMPv6>==\n" );

  if(buf_len < sizeof(rhp_proto_icmp6)){
    printf( "Invalid ICMPv6 format.\n" );
    return -1;
  }


	printf( "len : %d\n", pld_len );

  switch(icmp->type){

  case RHP_PROTO_ICMP6_TYPE_DEST_UNREACH:

  	printf( "type : DEST_UNREACH(%d)\n", icmp->type );
    *smry_idx += sprintf( (smry + *smry_idx), "  DEST_UNREACH(%d)  C: %d",
        icmp->type, icmp->code );
    break;

  case RHP_PROTO_ICMP6_TYPE_PKT_TOO_BIG:

  	printf( "type : PKT_TOO_BIG(%d)\n", icmp->type );
    *smry_idx += sprintf( (smry + *smry_idx), "  PKT_TOO_BIG(%d)  C: %d",
        icmp->type, icmp->code );
    break;

  case RHP_PROTO_ICMP6_TYPE_TIME_EXCEEDED:

  	printf( "type : TIME_EXCEEDED(%d)\n", icmp->type );
    *smry_idx += sprintf( (smry + *smry_idx), "  TIME_EXCEEDED(%d)  C: %d",
        icmp->type, icmp->code );
    break;

  case RHP_PROTO_ICMP6_TYPE_PARAM_PROBLEM:

  	printf( "type : PARAM_PROBLEM(%d)\n", icmp->type );
    *smry_idx += sprintf( (smry + *smry_idx), "  PARAM_PROBLEM(%d)  C: %d",
        icmp->type, icmp->code );
    break;

  case RHP_PROTO_ICMP6_TYPE_ECHO_REQUEST:

  	printf( "type : ECHO_REQUEST(%d)\n", icmp->type );
    *smry_idx += sprintf( (smry + *smry_idx), "  ECHO_REQUEST(%d)  C: %d",
        icmp->type, icmp->code );
    break;

  case RHP_PROTO_ICMP6_TYPE_ECHO_REPLY:

  	printf( "type : ECHO_REPLY(%d)\n", icmp->type );
    *smry_idx += sprintf( (smry + *smry_idx), "  ECHO_REPLY(%d)  C: %d",
        icmp->type, icmp->code );
    break;

  case RHP_PROTO_ICMP6_TYPE_MLD_LISTENER_QUERY:

  	printf( "type : MLD_LISTENER_QUERY(%d)\n", icmp->type );
    *smry_idx += sprintf( (smry + *smry_idx), "  MLD_LISTENER_QUERY(%d)  C: %d",
        icmp->type, icmp->code );
    break;

  case RHP_PROTO_ICMP6_TYPE_MLD_LISTENER_REPORT:

  	printf( "type : MLD_LISTENER_REPORT(%d)\n", icmp->type );
    *smry_idx += sprintf( (smry + *smry_idx), "  MLD_LISTENER_REPORT(%d)  C: %d",
        icmp->type, icmp->code );
    break;

  case RHP_PROTO_ICMP6_TYPE_MLD2_LISTENER_REPORT:

  	printf( "type : MLD2_LISTENER_REPORT(%d)\n", icmp->type );
    *smry_idx += sprintf( (smry + *smry_idx), "  MLD2_LISTENER_REPORT(%d)  C: %d",
        icmp->type, icmp->code );
    break;

  case RHP_PROTO_ICMP6_TYPE_MLD_LISTENER_DONE:

  	printf( "type : MLD_LISTENER_DONE(%d)\n", icmp->type );
    *smry_idx += sprintf( (smry + *smry_idx), "  MLD_LISTENER_DONE(%d)  C: %d",
        icmp->type, icmp->code );
    break;

  case RHP_PROTO_ICMP6_TYPE_ROUTER_SOLICIT:

  	printf( "type : ROUTER_SOLICIT(%d)\n", icmp->type );
    *smry_idx += sprintf( (smry + *smry_idx), "  ROUTER_SOLICIT(%d)  C: %d",
        icmp->type, icmp->code );
    break;

  case RHP_PROTO_ICMP6_TYPE_ROUTER_ADV:

  	printf( "type : ROUTER_ADV(%d)\n", icmp->type );
    *smry_idx += sprintf( (smry + *smry_idx), "  ROUTER_ADV(%d)  C: %d",
        icmp->type, icmp->code );
    break;

  case RHP_PROTO_ICMP6_TYPE_NEIGHBOR_SOLICIT:

  	printf( "type : NEIGHBOR_SOLICIT(%d)\n", icmp->type );
    *smry_idx += sprintf( (smry + *smry_idx), "  NEIGHBOR_SOLICIT(%d)  C: %d",
        icmp->type, icmp->code );
    break;

  case RHP_PROTO_ICMP6_TYPE_NEIGHBOR_ADV:

  	printf( "type : NEIGHBOR_ADV(%d)\n", icmp->type );
    *smry_idx += sprintf( (smry + *smry_idx), "  NEIGHBOR_ADV(%d)  C: %d",
        icmp->type, icmp->code );
    break;

  case RHP_PROTO_ICMP6_TYPE_REDIRECT:

  	printf( "type : REDIRECT(%d)\n", icmp->type );
    *smry_idx += sprintf( (smry + *smry_idx), "  REDIRECT(%d)  C: %d",
        icmp->type, icmp->code );
    break;

  case RHP_PROTO_ICMP6_TYPE_ROUTER_RR:

    printf( "type : ROUTER_RR(%d)\n", icmp->type );
    *smry_idx += sprintf( (smry + *smry_idx), "  ROUTER_RR(%d)  C: %d",
        icmp->type, icmp->code );
    break;

  default:
    printf( "type : %d\n", icmp->type );
    *smry_idx += sprintf( (smry + *smry_idx), "  T: %d  C: %d", icmp->type,
        icmp->code );
    break;
  }

  printf( "code : %d\n", icmp->code );

  if(	icmp->type == RHP_PROTO_ICMP6_TYPE_ECHO_REPLY ||
  		icmp->type == RHP_PROTO_ICMP6_TYPE_ECHO_REQUEST){

    rhp_proto_icmp_echo* echo = (rhp_proto_icmp_echo*)(icmp + 1);

    printf( "id: %d(0x%x) seq: %d(0x%x)\n", ntohs( echo->id ),
        ntohs( echo->id ), ntohs( echo->seq ), ntohs( echo->seq ) );
    *smry_idx += sprintf( (smry + *smry_idx), "  ID: %d(0x%x) SEQ: %d(0x%x)",
        ntohs( echo->id ), ntohs( echo->id ), ntohs( echo->seq ), ntohs(
            echo->seq ) );

  }else if( icmp->type == RHP_PROTO_ICMP6_TYPE_NEIGHBOR_SOLICIT ){

  	rhp_proto_icmp6_nd_solict* sol = (rhp_proto_icmp6_nd_solict*)icmp;

    printf( "target_addr: %s\n",_rhp_ipv6_string(sol->target_addr));

    if( (opt_len = pld_len - sizeof(rhp_proto_icmp6_nd_solict)) == sizeof(rhp_proto_icmp6_nd_opt_link_addr) ){

    	rhp_proto_icmp6_nd_opt_link_addr* opt = (rhp_proto_icmp6_nd_opt_link_addr*)(sol + 1);

    	if( opt->type == RHP_PROTO_ICMP6_ND_OPT_LINK_ADDR_SRC ){

        printf( " Opt : LINK_ADDR_SRC(%d) Len: %d  mac: %02x:%02x:%02x:%02x:%02x:%02x\n",opt->type,(opt->len*8),
        		opt->mac[0],opt->mac[1],opt->mac[2],opt->mac[3],opt->mac[4],opt->mac[5]);

    	}else{
        printf( " Unknown opts: type: %d\n", opt->type);
        _rhp_bin_dump( "NEIGHBOR_SOLICIT OPTS",(u8*)(sol + 1),(pld_len - sizeof(rhp_proto_icmp6_nd_solict)),1);
    	}

    }else if( opt_len ){

      printf( " Unknown opts: \n");
      _rhp_bin_dump( "NEIGHBOR_SOLICIT OPTS",(u8*)(sol + 1),(pld_len - sizeof(rhp_proto_icmp6_nd_solict)),1);
    }

  }else if( icmp->type == RHP_PROTO_ICMP6_TYPE_NEIGHBOR_ADV ){

  	rhp_proto_icmp6_nd_adv* adv = (rhp_proto_icmp6_nd_adv*)icmp;

  	printf( "Flags: Router: %d, Solicited: %d, Override: %d\n",adv->router,adv->solicited,adv->override);
    printf( "target_addr: %s\n",_rhp_ipv6_string(adv->target_addr));

    if( (opt_len = pld_len - sizeof(rhp_proto_icmp6_nd_adv)) == sizeof(rhp_proto_icmp6_nd_opt_link_addr) ){

    	rhp_proto_icmp6_nd_opt_link_addr* opt = (rhp_proto_icmp6_nd_opt_link_addr*)(adv + 1);

    	if( opt->type == RHP_PROTO_ICMP6_ND_OPT_LINK_ADDR_TGT ){

        printf( " Opt : LINK_ADDR_TGT(%d) Len: %d  mac: %02x:%02x:%02x:%02x:%02x:%02x\n",opt->type,(opt->len*8),
        		opt->mac[0],opt->mac[1],opt->mac[2],opt->mac[3],opt->mac[4],opt->mac[5]);

    	}else{
        printf( " Unknown opts: type: %d\n", opt->type);
        _rhp_bin_dump( "NEIGHBOR_ADV OPTS",(u8*)(adv + 1),(pld_len - sizeof(rhp_proto_icmp6_nd_solict)),1);
    	}

    }else if( opt_len ){

      printf( " Unknown opts: \n");
      _rhp_bin_dump( "NEIGHBOR_ADV OPTS",(u8*)(adv + 1),(pld_len - sizeof(rhp_proto_icmp6_nd_solict)),1);
    }

  }else if( icmp->type == RHP_PROTO_ICMP6_TYPE_MLD_LISTENER_QUERY ){

  	rhp_proto_icmp6_mld2_query* mld = (rhp_proto_icmp6_mld2_query*)icmp;
  	int rnum = ntohs(mld->src_num);

  	printf("QRV: 0x%x, Suppress: %d, QQIC: 0x%x, SrcNum: %d\n",
  			mld->qrv,mld->suppress,mld->qqic,rnum);

  }else if( icmp->type == RHP_PROTO_ICMP6_TYPE_MLD2_LISTENER_REPORT ){

  	rhp_proto_icmp6_mld2_report* mld = (rhp_proto_icmp6_mld2_report*)icmp;
  	rhp_proto_icmp6_mld2_mc_addr_rec* rec;
  	int rnum = ntohs(mld->mc_addr_rec_num);
  	int j;

  	printf("MC Rec Num: %d\n",rnum);

  	rec = (rhp_proto_icmp6_mld2_mc_addr_rec*)(mld + 1);
  	for( j = 0; j < rnum; j++ ){

  		printf("  [%d] MC Addr Rec\n",(j+1));
    	printf("    Type: %d (IS_INC:1, IS_EXC:2, TO_INC:3, TO_EXC:4, ALW:5, BLK:6)\n",rec->type);
  		printf("    Aux_len: %d, SrcAddr Num: %d\n",rec->aux_len,rec->src_addr_num);
  		printf("    MC Addr: %s\n",_rhp_ipv6_string(rec->mc_addr));

  		rec = (rhp_proto_icmp6_mld2_mc_addr_rec*)(((u8*)(rec + 1)) + rec->aux_len + (rec->src_addr_num)*16);
  	}

  }else{

  	_rhp_bin_dump( "ICMPv6-Data", (u8*)(icmp + 1),(pld_len - sizeof(rhp_proto_icmp6)),1);
  }

  if(data_len){
    *data_len = sizeof(rhp_proto_icmp6);
  }

  return 0;
}

static int _print_tcp( u8* buf, int buf_len, int* data_len, int* smry_idx,
    char* smry )
{
  rhp_proto_tcp* tcp = (rhp_proto_tcp*) buf;

  printf( "\n==<TCP>==\n" );

  if(buf_len < sizeof(rhp_proto_udp)){
    printf( "Invalid TCP format.\n" );
    return -1;
  }

  printf( "src_port : %d\n", ntohs( tcp->src_port ) );
  printf( "dst_port : %d\n", ntohs( tcp->dst_port ) );

  *smry_idx += sprintf( (smry + *smry_idx), "[%d >> %d] ",ntohs( tcp->src_port ), ntohs( tcp->dst_port ) );

  if( tcp->fin ){
  	printf("F ");
    *smry_idx += sprintf( (smry + *smry_idx), " %s","F");
  }

  if( tcp->syn ){
  	printf("S ");
    *smry_idx += sprintf( (smry + *smry_idx), " %s","S");
  }

  if( tcp->rst ){
  	printf("R ");
    *smry_idx += sprintf( (smry + *smry_idx), " %s","R");
  }

  if( tcp->psh ){
  	printf("P ");
    *smry_idx += sprintf( (smry + *smry_idx), " %s","P");
  }

  if( tcp->ack ){
  	printf("A ");
    *smry_idx += sprintf( (smry + *smry_idx), " %s","A");
  }

  if( tcp->urg ){
  	printf("U ");
    *smry_idx += sprintf( (smry + *smry_idx), " %s","U");
  }

  if( tcp->ece ){
  	printf("E ");
    *smry_idx += sprintf( (smry + *smry_idx), " %s","E");
  }

  if( tcp->cwr ){
  	printf("C ");
    *smry_idx += sprintf( (smry + *smry_idx), " %s","C");
  }

  printf( "seq : %u  ack: %u\n", ntohl( tcp->seq ), ntohl( tcp->ack_seq ) );


  if(data_len){
    *data_len = sizeof(rhp_proto_tcp);
  }

  return 0;
}

static int _print_esp( u8* buf, int buf_len, int iv_len, int icv_len,
    int* data_len, int* smry_idx, char* smry )
{
  rhp_proto_esp* esp = (rhp_proto_esp*) buf;
  u8 *p, *tail;

  printf( "\n==<ESP>==\n" );

  if(buf_len < sizeof(rhp_proto_esp) + iv_len + icv_len){
    printf( "Invalid ESP format.(1)\n" );
    return -1;
  }

  printf( "spi : %u(0x%x)\n", ntohl( esp->spi ), ntohl( esp->spi ) );
  printf( "seq : %u\n", ntohl( esp->seq ) );

  *smry_idx += sprintf( (smry + *smry_idx),
      " [ESP]  SPI(%u, 0x%x) SEQ(%u) Len: %d", ntohl( esp->spi ),ntohl( esp->spi ), ntohl( esp->seq ), buf_len );

  p = buf + sizeof(rhp_proto_esp);
  tail = buf + buf_len;
  if(iv_len){

    int len;

    _rhp_bin_dump( "IV", p, iv_len, 1 );
    p += iv_len;

    if(p >= tail){
      printf( "Invalid ESP format.(2)\n" );
      return -1;
    }

    len = buf_len - sizeof(rhp_proto_esp) - iv_len - icv_len;
    _rhp_bin_dump( "Encrypted Data", p, len, 1 );
    p += len;

    if(p >= tail){
      printf( "Invalid ESP format.(3)\n" );
      return -1;
    }

    _rhp_bin_dump( "ICV", p, icv_len, 1 );

    if(p >= tail){
      printf( "Invalid ESP format.(4)\n" );
      return -1;
    }

  }else{
    _rhp_bin_dump( "IV UNKNOWN", p, buf_len - sizeof(rhp_proto_esp), 1 );
  }

  if(data_len){
    *data_len = buf_len;
  }

  return 0;
}

static int _print_arp( u8* buf, int buf_len, int* data_len, int* smry_idx,
    char* smry )
{
  rhp_proto_arp* arp = (rhp_proto_arp*) buf;

  printf( "\n==<ARP>==\n" );

  if(buf_len < sizeof(rhp_proto_arp)){
    printf( "Unknown ARP format.\n" );
    return -1;
  }

  if(arp->hw_type == RHP_PROTO_ARP_HW_TYPE_ETHER && arp->proto_type
      == RHP_PROTO_ETH_IP){

    printf( "hw_type: ETHER(%d)\n", ntohs( arp->hw_type ) );
    printf( "proto_type: IPv4(%d)\n", ntohs( arp->proto_type ) );
    printf( "hw_len: %d\n", arp->hw_len );
    printf( "proto_len: %d\n", arp->proto_len );

    *smry_idx += sprintf( (smry + *smry_idx), " ARP" );

    if(arp->operation == RHP_PROTO_ARP_OPR_REQUEST){

      printf( "operation: REQUEST(%d)\n", ntohs( arp->operation ) );
      *smry_idx += sprintf( (smry + *smry_idx), " REQ" );

    }else if(arp->operation == RHP_PROTO_ARP_OPR_REPLY){

      printf( "operation: REPLY(%d)\n", ntohs( arp->operation ) );
      *smry_idx += sprintf( (smry + *smry_idx), " REPLY" );

    }else{

      printf( "operation: UNKNOWN(%d)\n", ntohs( arp->operation ) );
      *smry_idx += sprintf( (smry + *smry_idx), " UNKNOWN" );
    }

    printf( "sender_mac: %02x:%02x:%02x:%02x:%02x:%02x\n", arp->sender_mac[0],
        arp->sender_mac[1], arp->sender_mac[2], arp->sender_mac[3],
        arp->sender_mac[4], arp->sender_mac[5] );
    printf( "sender_addr : %d.%d.%d.%d\n", ((u8*) (&(arp->sender_ipv4)))[0],
        ((u8*) (&(arp->sender_ipv4)))[1], ((u8*) (&(arp->sender_ipv4)))[2],
        ((u8*) (&(arp->sender_ipv4)))[3] );

    printf( "target_mac: %02x:%02x:%02x:%02x:%02x:%02x\n", arp->target_mac[0],
        arp->target_mac[1], arp->target_mac[2], arp->target_mac[3],
        arp->target_mac[4], arp->target_mac[5] );
    printf( "target_addr : %d.%d.%d.%d\n", ((u8*) (&(arp->target_ipv4)))[0],
        ((u8*) (&(arp->target_ipv4)))[1], ((u8*) (&(arp->target_ipv4)))[2],
        ((u8*) (&(arp->target_ipv4)))[3] );

    *smry_idx
        += sprintf(
            (smry + *smry_idx),
            " %d.%d.%d.%d (%02x:%02x:%02x:%02x:%02x:%02x) >> %d.%d.%d.%d (%02x:%02x:%02x:%02x:%02x:%02x)",
            ((u8*) (&(arp->sender_ipv4)))[0], ((u8*) (&(arp->sender_ipv4)))[1],
            ((u8*) (&(arp->sender_ipv4)))[2], ((u8*) (&(arp->sender_ipv4)))[3],
            arp->sender_mac[0], arp->sender_mac[1], arp->sender_mac[2],
            arp->sender_mac[3], arp->sender_mac[4], arp->sender_mac[5],
            ((u8*) (&(arp->target_ipv4)))[0], ((u8*) (&(arp->target_ipv4)))[1],
            ((u8*) (&(arp->target_ipv4)))[2], ((u8*) (&(arp->target_ipv4)))[3],
            arp->target_mac[0], arp->target_mac[1], arp->target_mac[2],
            arp->target_mac[3], arp->target_mac[4], arp->target_mac[5] );

    if(data_len){
      *data_len = sizeof(rhp_proto_arp);
    }

  }else{

    printf( "hw_type: %d\n", ntohs( arp->hw_type ) );
    printf( "proto_type: %d\n", ntohs( arp->proto_type ) );
    printf( "hw_len: %d\n", arp->hw_len );
    printf( "proto_len: %d\n", arp->proto_len );

    if(arp->operation == RHP_PROTO_ARP_OPR_REQUEST){
      printf( "operation: REQUEST(%d)\n", ntohs( arp->operation ) );
    }else if(arp->operation == RHP_PROTO_ARP_OPR_REPLY){
      printf( "operation: REPLY(%d)\n", ntohs( arp->operation ) );
    }else{
      printf( "operation: UNKNOWN(%d)\n", ntohs( arp->operation ) );
    }

    *smry_idx += sprintf( (smry + *smry_idx), " ARP (UNKNOWN PROTOCOL)" );

    if(data_len){
      *data_len = 8;
    }
  }

  return 0;
}

#define _IKEV2_PAYLOAD_TYPE_MAX 53
static char* _print_ikev2_payload_types[_IKEV2_PAYLOAD_TYPE_MAX + 1] = {
    "No Next Payload", "RESERVED", "RESERVED", "RESERVED", "RESERVED",
    "RESERVED", "RESERVED", "RESERVED", "RESERVED", "RESERVED", "RESERVED",
    "RESERVED", "RESERVED", "RESERVED", "RESERVED", "RESERVED", "RESERVED",
    "RESERVED", "RESERVED", "RESERVED", "RESERVED", "RESERVED", "RESERVED",
    "RESERVED", "RESERVED", "RESERVED", "RESERVED", "RESERVED", "RESERVED",
    "RESERVED", "RESERVED", "RESERVED", "RESERVED", "SA", "KE", "IDi", "IDr",
    "CERT", "CERTREQ", "AUTH", "Ni or Nr", "N", "D", "V", "TSi", "TSr", "E",
    "CP", "EAP", "GSPM", "IDG", "GSA", "KD", "SKF" };


#define _IKEV2_EXCHANGE_TYPE_MAX 38
static char* _print_ikev2_exchange_types[_IKEV2_EXCHANGE_TYPE_MAX + 1] = {
    "RESERVED", "RESERVED", "RESERVED", "RESERVED", "RESERVED", "RESERVED",
    "RESERVED", "RESERVED", "RESERVED", "RESERVED", "RESERVED", "RESERVED",
    "RESERVED", "RESERVED", "RESERVED", "RESERVED", "RESERVED", "RESERVED",
    "RESERVED", "RESERVED", "RESERVED", "RESERVED", "RESERVED", "RESERVED",
    "RESERVED", "RESERVED", "RESERVED", "RESERVED", "RESERVED", "RESERVED",
    "RESERVED", "RESERVED", "RESERVED", "RESERVED", "IKESA_INIT", "AUTH",
    "CREATE_CSA", "INFO", "SESS_RESUME" };

#define _IKEV2_NOTIFICATION_TYPE_MAX 200
static int _print_ikev2_notification_types[_IKEV2_NOTIFICATION_TYPE_MAX + 1] = {
        RHP_PROTO_IKE_NOTIFY_ERR_UNSUPPORTED_CRITICAL_PAYLOAD,
        RHP_PROTO_IKE_NOTIFY_ERR_INVALID_IKE_SPI,
        RHP_PROTO_IKE_NOTIFY_ERR_INVALID_MAJOR_VERSION,
        RHP_PROTO_IKE_NOTIFY_ERR_INVALID_SYNTAX,
        RHP_PROTO_IKE_NOTIFY_ERR_INVALID_MESSAGE_ID,
        RHP_PROTO_IKE_NOTIFY_ERR_INVALID_SPI,
        RHP_PROTO_IKE_NOTIFY_ERR_NO_PROPOSAL_CHOSEN,
        RHP_PROTO_IKE_NOTIFY_ERR_INVALID_KE_PAYLOAD,
        RHP_PROTO_IKE_NOTIFY_ERR_AUTHENTICATION_FAILED,
        RHP_PROTO_IKE_NOTIFY_ERR_SINGLE_PAIR_REQUIRED,
        RHP_PROTO_IKE_NOTIFY_ERR_NO_ADDITIONAL_SAS,
        RHP_PROTO_IKE_NOTIFY_ERR_INTERNAL_ADDRESS_FAILURE,
        RHP_PROTO_IKE_NOTIFY_ERR_FAILED_CP_REQUIRED,
        RHP_PROTO_IKE_NOTIFY_ERR_TS_UNACCEPTABLE,
        RHP_PROTO_IKE_NOTIFY_ERR_INVALID_SELECTORS,
        RHP_PROTO_IKE_NOTIFY_ERR_UNACCEPTABLE_ADDRESSES,
        RHP_PROTO_IKE_NOTIFY_ERR_UNEXPECTED_NAT_DETECTED,
        RHP_PROTO_IKE_NOTIFY_ST_INITIAL_CONTACT,
        RHP_PROTO_IKE_NOTIFY_ST_SET_WINDOW_SIZE,
        RHP_PROTO_IKE_NOTIFY_ST_ADDITIONAL_TS_POSSIBLE,
        RHP_PROTO_IKE_NOTIFY_ST_IPCOMP_SUPPORTED,
        RHP_PROTO_IKE_NOTIFY_ST_NAT_DETECTION_SOURCE_IP,
        RHP_PROTO_IKE_NOTIFY_ST_NAT_DETECTION_DESTINATION_IP,
        RHP_PROTO_IKE_NOTIFY_ST_COOKIE,
        RHP_PROTO_IKE_NOTIFY_ST_USE_TRANSPORT_MODE,
        RHP_PROTO_IKE_NOTIFY_ST_HTTP_CERT_LOOKUP_SUPPORTED,
        RHP_PROTO_IKE_NOTIFY_ST_REKEY_SA,
        RHP_PROTO_IKE_NOTIFY_ST_ESP_TFC_PADDING_NOT_SUPPORTED,
        RHP_PROTO_IKE_NOTIFY_ST_NON_FIRST_FRAGMENTS_ALSO,
        RHP_PROTO_IKE_NOTIFY_ST_MOBIKE_SUPPORTED,
        RHP_PROTO_IKE_NOTIFY_ST_ADDITIONAL_IP4_ADDRESS,
        RHP_PROTO_IKE_NOTIFY_ST_ADDITIONAL_IP6_ADDRESS,
        RHP_PROTO_IKE_NOTIFY_ST_NO_ADDITIONAL_ADDRESSES,
        RHP_PROTO_IKE_NOTIFY_ST_UPDATE_SA_ADDRESSES,
        RHP_PROTO_IKE_NOTIFY_ST_COOKIE2,
        RHP_PROTO_IKE_NOTIFY_ST_NO_NATS_ALLOWED,
        RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_INTERNAL_IP4_ADDRESS,
        RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_INTERNAL_IP6_ADDRESS,
        RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_INTERNAL_MAC_ADDRESS,
        RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_USE_ETHERIP_ENCAP,
        RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_INTERNAL_ACCESSPOINT,
        RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_INTERNAL_MESH_NODE,
        RHP_PROTO_IKE_NOTIFY_ST_QCD_TOKEN,
        RHP_PROTO_IKE_NOTIFY_ST_FRAG_SUPPORTED,
				RHP_PROTO_IKE_NOTIFY_ST_TICKET_LT_OPAQUE,
				RHP_PROTO_IKE_NOTIFY_ST_TICKET_REQUEST,
				RHP_PROTO_IKE_NOTIFY_ST_TICKET_ACK,
				RHP_PROTO_IKE_NOTIFY_ST_TICKET_NACK,
				RHP_PROTO_IKE_NOTIFY_ST_TICKET_OPAQUE,
				RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_REALM_ID,
				RHP_PROTO_IKE_NOTIFY_ST_PRIV_RHP_IPV6_AUTOCONF_REKEY_SA
	};

static char * _print_ikev2_notification_types_str[_IKEV2_NOTIFICATION_TYPE_MAX + 1]
= { "ERR_UNSUPPORTED_CRITICAL_PAYLOAD", "ERR_INVALID_IKE_SPI",
    "ERR_INVALID_MAJOR_VERSION", "ERR_INVALID_SYNTAX",
    "ERR_INVALID_MESSAGE_ID", "ERR_INVALID_SPI", "ERR_NO_PROPOSAL_CHOSEN",
    "ERR_INVALID_KE_PAYLOAD", "ERR_AUTHENTICATION_FAILED",
    "ERR_SINGLE_PAIR_REQUIRED", "ERR_NO_ADDITIONAL_SAS",
    "ERR_INTERNAL_ADDRESS_FAILURE", "ERR_FAILED_CP_REQUIRED",
    "ERR_TS_UNACCEPTABLE", "ERR_INVALID_SELECTORS",
    "ERR_UNACCEPTABLE_ADDRESSES", "ERR_UNEXPECTED_NAT_DTECTED",
    "ST_INITIAL_CONTACT", "ST_SET_WINDOW_SIZE", "ST_ADDITIONAL_TS_POSSIBLE",
    "ST_IPCOMP_SUPPORTED", "ST_NAT_DETECTION_SOURCE_IP",
    "ST_NAT_DETECTION_DESTINATION_IP", "ST_COOKIE", "ST_USE_TRANSPORT_MODE",
    "ST_HTTP_CERT_LOOKUP_SUPPORTED", "ST_REKEY_SA",
    "ST_ESP_TFC_PADDING_NOT_SUPPORTED", "ST_NON_FIRST_FRAGMENTS_ALSO",
    "ST_MOBIKE_SUPPORTED", "ST_ADDITIONAL_IP4_ADDRESS",
    "ST_ADDITIONAL_IP6_ADDRESS", "ST_NO_ADDITIONAL_ADDRESSES",
    "ST_UPDATE_SA_ADDRESSES", "ST_COOKIE2", "ST_NO_NATS_ALLOWED",
    "ST_PRIV_RHP_INTERNAL_IP4_ADDRESS", "ST_PRIV_RHP_INTERNAL_IP6_ADDRESS",
    "ST_PRIV_RHP_INTERNAL_MAC_ADDRESS", "ST_PRIV_RHP_USE_ETHERIP_ENCAP",
    "ST_PRIV_RHP_INTERNAL_ACCESSPOINT","ST_PRIV_RHP_INTERNAL_MESH_NODE",
    "ST_QCD_TOKEN",
    "ST_FRAG_SUPPORTED",
		"ST_TICKET_LT_OPAQUE",
		"ST_TICKET_REQUEST",
		"ST_TICKET_ACK",
		"ST_TICKET_NACK",
		"ST_TICKET_OPAQUE",
		"ST_PRIV_RHP_REALM_ID",
		"ST_PRIV_RHP_IPV6_AUTOCONF_REKEY_SA",
	};

static int _print_ikev2_payloads( u8* buf, int buf_len, int iv_len, int icv_len, u8 next_payload,
		rhp_proto_ike* ike,int is_plain, int* data_len, int* smry_idx, char* smry )
{
  rhp_proto_ike_payload* pld;
  u8* tail = buf + buf_len;

  printf("\n- next_payload: %d\n",next_payload);

  pld = (rhp_proto_ike_payload*)buf;

  while(next_payload != RHP_PROTO_IKE_NO_MORE_PAYLOADS && (u8*) pld < tail){

    int pld_len;
    u8* p;
    int data_len;
    int i;

    if(((u8*) pld) + sizeof(rhp_proto_ike_payload) >= tail){
      printf( "\n******* Invalid IKEv2 format(3) ******* .\n" );
      return -1;
    }

    pld_len = ntohs( pld->len );
    if(((u8*) pld) + pld_len > tail){
      printf( "\n******* Invalid IKEv2 format(4) ******* .pld_len: %d\n",
          pld_len );
      return -1;
    }

    if(pld_len > 0){
    	printf("\n");
      _rhp_bin_dump( "+++[ Payload ]+++", (u8*) pld, pld_len, 1 );
    }else{
      printf( "\n******* Invalid IKEv2 format(5) ******* pld_len:%d .\n",
          pld_len );
      return -1;
    }

    if(next_payload == RHP_PROTO_IKE_PAYLOAD_E){

      int pad_len = 0;

      printf( "\n  ==[E]==\n" );
      *smry_idx += sprintf( (smry + *smry_idx), " E" );

      if(pld->next_payload > _IKEV2_PAYLOAD_TYPE_MAX){
        printf( "next_payload : UNKNOWN(%d, 0x%x)\n", pld->next_payload, pld->next_payload);
      }else{
        printf( "next_payload : %s(%d, 0x%x)\n",
            _print_ikev2_payload_types[pld->next_payload], pld->next_payload, pld->next_payload);
      }
      printf( "critical_rsv : 0x%x(%s)\n", pld->critical_rsv,
          RHP_PROTO_IKE_PLD_CRITICAL(pld->critical_rsv) ? "CRITICAL"
              : "NOT CRITICAL" );
      printf( "len : %d\n", ntohs( pld->len ) );

      p = ((u8*) (pld + 1));

      if(p + iv_len > tail){
        printf( "Invalid IKEv2 format(5).\n" );
        return -1;
      }

      if(iv_len){
        _rhp_bin_dump( "IV", p, iv_len, 1 );
      }else{
        printf( "IV Length Unknown.\n" );
      }

      p += iv_len;

      data_len = pld_len - sizeof(rhp_proto_ike_enc_payload) - iv_len - icv_len;

      if(p + data_len > tail){
        printf( "Invalid IKEv2 format(6).\n" );
        return -1;
      }

      if(data_len < 1){
        printf( "Invalid IKEv2 format(7).\n" );
        return -1;
      }

      if(is_plain){
        _rhp_bin_dump( "Encrypted Data(NOT Encrypted format)", p, data_len, 1 );
      }else{
        _rhp_bin_dump( "Encrypted Data", p, data_len, 1 );
      }
      p += data_len;

      if(is_plain){

        pad_len = *(p - 1);

        if(data_len < pad_len + 1){
          printf( "Invalid IKEv2 format(8).\n" );
          return -1;
        }

        printf( "Pad Len : %d", pad_len );
        _rhp_bin_dump( "Pad", (p - pad_len - 1), pad_len, 1 );
      }

      if(p + icv_len > tail){
        printf( "Invalid IKEv2 format(9).\n" );
        return -1;
      }

      if(icv_len){
        _rhp_bin_dump( "ICV", p, icv_len, 1 );
      }else{
        printf( "\nICV Length Unknown.\n" );
      }

      if(is_plain){
        next_payload = pld->next_payload;
        pld = (rhp_proto_ike_payload*) (((u8*) pld)
            + sizeof(rhp_proto_ike_enc_payload) + iv_len);
        tail = ((u8*) pld) + data_len;
      }else{
        next_payload = RHP_PROTO_IKE_NO_MORE_PAYLOADS;
      }

      continue;

    }else if(next_payload == RHP_PROTO_IKE_PAYLOAD_SKF){

        int pad_len = 0;
        rhp_proto_ike_skf_payload* skf = (rhp_proto_ike_skf_payload*)pld;

        printf( "\n  ==[SKF]==\n" );
        *smry_idx += sprintf( (smry + *smry_idx), " SKF" );

        if( (skf + 1) > tail){
          printf( "Invalid IKEv2 SKF format(5).\n" );
          return -1;
        }

        if(pld->next_payload > _IKEV2_PAYLOAD_TYPE_MAX){
          printf( "next_payload : UNKNOWN(%d)\n", pld->next_payload );
        }else{
          printf( "next_payload : %s(%d)\n",
              _print_ikev2_payload_types[pld->next_payload], pld->next_payload );
        }
        printf( "critical_rsv : 0x%x(%s)\n", pld->critical_rsv,
            RHP_PROTO_IKE_PLD_CRITICAL(pld->critical_rsv) ? "CRITICAL"
                : "NOT CRITICAL" );
        printf( "len : %d\n", ntohs( pld->len ) );

        printf( "frag_num : %d\n", ntohs( skf->frag_num ) );
        printf( "total_frags : %d\n", ntohs( skf->total_frags ) );

        *smry_idx += sprintf( (smry + *smry_idx), "(%d/%d)", ntohs( skf->frag_num ), ntohs( skf->total_frags ) );


        p = (u8*)(skf + 1);

        if(p + iv_len > tail){
          printf( "Invalid IKEv2 SKF format(5).\n" );
          return -1;
        }

        if(iv_len){
          _rhp_bin_dump( "IV", p, iv_len, 1 );
        }else{
          printf( "IV Length Unknown.\n" );
        }

        p += iv_len;

        data_len = pld_len - sizeof(rhp_proto_ike_skf_payload) - iv_len - icv_len;

        if(p + data_len > tail){
          printf( "Invalid IKEv2 SKF format(6).\n" );
          return -1;
        }

        if(data_len < 1){
          printf( "Invalid IKEv2 SKF format(7).\n" );
          return -1;
        }

        if(is_plain){
          _rhp_bin_dump( "Fragmented Data(NOT Encrypted format)", p, data_len, 1 );
        }else{
          _rhp_bin_dump( "Fragmented Data(Encrypted format)", p, data_len, 1 );
        }
        p += data_len;

        if(is_plain){

          pad_len = *(p - 1);

          if(data_len < pad_len + 1){
            printf( "Invalid IKEv2 SKF format(8).\n" );
            return -1;
          }

          printf( "Pad Len : %d", pad_len );
          _rhp_bin_dump( "Pad", (p - pad_len - 1), pad_len, 1 );
        }

        if(p + icv_len > tail){
          printf( "Invalid IKEv2 SKF format(9). 0x%lx + %d > 0x%lx\n",(unsigned long)p,icv_len,(unsigned long)tail);
          return -1;
        }

        if(icv_len){
          _rhp_bin_dump( "ICV", p, icv_len, 1 );
        }else{
          printf( "\nICV Length Unknown.\n" );
        }

        next_payload = RHP_PROTO_IKE_NO_MORE_PAYLOADS; // Data may be fragmented.

        continue;

    }else if(next_payload == RHP_PROTO_IKE_PAYLOAD_SA){

      rhp_proto_ike_proposal* prop;
      rhp_proto_ike_transform* trans;

      printf( "\n  ==[SA]==\n" );
      *smry_idx += sprintf( (smry + *smry_idx), " SA" );

      if(pld->next_payload > _IKEV2_PAYLOAD_TYPE_MAX){
        printf( "next_payload : UNKNOWN(%d)\n", pld->next_payload );
      }else{
        printf( "next_payload : %s(%d)\n",
            _print_ikev2_payload_types[pld->next_payload], pld->next_payload );
      }
      printf( "critical_rsv : 0x%x(%s)\n", pld->critical_rsv,
          RHP_PROTO_IKE_PLD_CRITICAL(pld->critical_rsv) ? "CRITICAL"
              : "NOT CRITICAL" );
      printf( "len : %d", ntohs( pld->len ) );

      prop = (rhp_proto_ike_proposal*) (((rhp_proto_ike_sa_payload*) pld) + 1);

      if((u8*) prop >= tail){
        printf( "Invalid IKEv2 format(10).\n" );
        return -1;
      }

      while( 1 ){

				printf( "\n  ==Proposal==[%d]\n" ,prop->proposal_number);

				printf( "last_or_more : %d (LAST:0,MORE:2)\n", prop->last_or_more );
				printf( "reserved : 0x%x\n", prop->reserved );
				printf( "len : %d\n", ntohs( prop->len ) );
				printf( "proposal_number : %d\n", prop->proposal_number );
				printf( "protocol : %d (IKE:1,AH:2,ESP:3)\n", prop->protocol );

				if( ntohs( prop->len ) < sizeof(rhp_proto_ike_proposal) ){
	        printf( "Invalid IKEv2 format(10-2).\n" );
	        return -1;
				}

				{
					switch(prop->protocol){

					case 1:
						*smry_idx += sprintf( (smry + *smry_idx), "(IKE)" );
						break;

					case 2:
						*smry_idx += sprintf( (smry + *smry_idx), "(AH)" );
						break;

					case 3:
						*smry_idx += sprintf( (smry + *smry_idx), "(ESP)" );
						break;

					default:
						*smry_idx += sprintf( (smry + *smry_idx), "(%d)", prop->protocol );
						break;
					}
				}

				printf( "spi_len : %d\n", prop->spi_len );
				printf( "transform_num : %d\n", prop->transform_num );

				if(prop->spi_len){

					p = (u8*) (prop + 1);

					if(p + prop->spi_len >= tail){
						printf( "Invalid IKEv2 format(11).\n" );
						return -1;
					}

					if(prop->spi_len == 4){

						printf( "spi : %u(0x%x)\n", bswap_32(*((u32*)p)),
								bswap_32(*((u32*)p)));
						*smry_idx += sprintf( (smry + *smry_idx), "[%u(0x%x)]",
								bswap_32(*((u32*)p)), bswap_32(*((u32*)p)));

					}else if(prop->spi_len == 8){

						printf( "spi : %llu(0x%llx)\n", bswap_64(*((u64*)p)),
								bswap_64(*((u64*)p)));
						*smry_idx += sprintf( (smry + *smry_idx), "[%llu(0x%llx)]",
								bswap_64(*((u64*)p)), bswap_64(*((u64*)p)));

					}else{
						_rhp_bin_dump( "spi", p, prop->spi_len, 1 );
					}
				}

				trans = (rhp_proto_ike_transform*) (((u8*) (prop + 1)) + prop->spi_len);

				for(i = 0; i < prop->transform_num; i++){

					int trans_len;

					printf( "\n  ==Transform[%d]==\n", (i + 1) );

					if((u8*) trans >= tail){
						printf( "Invalid IKEv2 format(12).\n" );
						return -1;
					}

					if(((u8*) trans) + sizeof(rhp_proto_ike_transform) > tail){
						printf( "Invalid IKEv2 format(13).\n" );
						return -1;
					}

					trans_len = ntohs( trans->len );

					if( trans_len == 0 ){
						printf( "Invalid IKEv2 format(13-1).\n" );
						return -1;
					}

					printf( "last_or_more : %d(LAST:0,MORE:3)\n", trans->last_or_more );
					printf( "reserved1 : 0x%x\n", trans->reserved1 );
					printf( "len : %d\n", trans_len );
					printf("transform_type : %d (RESERVED:0,ENCR:1,PRF:2,INTEG:3,DH:4,ESN:5)\n",trans->transform_type );
					printf( "reserved2 : 0x%x\n", trans->reserved2 );
					printf( "transform_id : %d ", ntohs( trans->transform_id ) );

					if(trans->transform_type == 1){
						printf( "(3DES:3,NULL:11,AES_CBC:12,AES_CTR:13)\n" );
					}else if(trans->transform_type == 2){
						printf( "(HMAC_MD5:1,HMAC_SHA1:2,AES128_CBC:4)\n" );
					}else if(trans->transform_type == 3){
						printf( "(HMAC_MD5_96:1,HMAC_SHA1_96:2,AES_XCBC_96:5)\n" );
					}else{
						printf( "\n" );
					}

					if(trans_len > sizeof(rhp_proto_ike_transform)){

						rhp_proto_ike_attr* attr = (rhp_proto_ike_attr*) (trans + 1);

						if((u8*) attr >= tail){
							printf( "Invalid IKEv2 format(14).\n" );
							return -1;
						}

						if(((u8*) attr) + sizeof(rhp_proto_ike_attr) >= tail){
							printf( "Invalid IKEv2 format(15).\n" );
							return -1;
						}

						printf( "attr_type : %d(0x%x) (KEYLEN:14)",
								RHP_PROTO_IKE_ATTR_TYPE(attr->attr_type), ntohs( attr->attr_type ) );
						printf( "len_or_value : %d(0x%x)", ntohs( attr->len_or_value ),
								ntohs( attr->len_or_value ) );
					}

					printf( "\n" );

					trans = (rhp_proto_ike_transform*) (((u8*) trans) + trans_len);
				}

	      if( !prop->last_or_more ){
	      	break;
	      }

	      prop = (rhp_proto_ike_proposal*)(((u8*)prop) + ntohs(prop->len));

	      if((u8*) prop >= tail){
	        printf( "Invalid IKEv2 format(10-1).\n" );
	        return -1;
	      }
      }

    }else if(next_payload == RHP_PROTO_IKE_PAYLOAD_KE){

      rhp_proto_ike_ke_payload* ke = (rhp_proto_ike_ke_payload*) pld;

      printf( "\n  ==[KE]==\n" );
      *smry_idx += sprintf( (smry + *smry_idx), " KE" );

      if(pld->next_payload > _IKEV2_PAYLOAD_TYPE_MAX){
        printf( "next_payload : UNKNOWN(%d)\n", pld->next_payload );
      }else{
        printf( "next_payload : %s(%d)\n",
            _print_ikev2_payload_types[pld->next_payload], pld->next_payload );
      }
      printf( "critical_rsv : 0x%x(%s)\n", pld->critical_rsv,
          RHP_PROTO_IKE_PLD_CRITICAL(pld->critical_rsv) ? "CRITICAL"
              : "NOT CRITICAL" );
      printf( "len : %d\n", ntohs( pld->len ) );

      if(((u8*) pld) + sizeof(rhp_proto_ike_ke_payload) > tail){
        printf( "Invalid IKEv2 format(16).\n" );
        return -1;
      }

      printf( "dh_group : %d\n", ntohs( ke->dh_group ) );
      printf( "reserved2 : 0x%x\n", ntohs( ke->reserved2 ) );

      p = (u8*) (ke + 1);
      if(p > tail){
        printf( "Invalid IKEv2 format(17).\n" );
        return -1;
      }

      if(p + (pld_len - sizeof(rhp_proto_ike_ke_payload)) > tail){
        printf( "Invalid IKEv2 format(18).\n" );
        return -1;
      }

      _rhp_bin_dump( "Key Exchange Data", p, (pld_len
          - sizeof(rhp_proto_ike_ke_payload)), 1 );

    }else if( next_payload == RHP_PROTO_IKE_PAYLOAD_ID_I ||
    					next_payload == RHP_PROTO_IKE_PAYLOAD_ID_R){

      rhp_proto_ike_id_payload* id = (rhp_proto_ike_id_payload*) pld;

      if(next_payload == RHP_PROTO_IKE_PAYLOAD_ID_I){
        printf( "\n  ==[ID_I]==\n" );
        *smry_idx += sprintf( (smry + *smry_idx), " ID_I" );
      }else{
        printf( "\n  ==[ID_R]==\n" );
        *smry_idx += sprintf( (smry + *smry_idx), " ID_R" );
      }

      if(pld->next_payload > _IKEV2_PAYLOAD_TYPE_MAX){
        printf( "next_payload : UNKNOWN(%d)\n", pld->next_payload );
      }else{
        printf( "next_payload : %s(%d)\n",
            _print_ikev2_payload_types[pld->next_payload], pld->next_payload );
      }
      printf( "critical_rsv : 0x%x(%s)\n", pld->critical_rsv,
          RHP_PROTO_IKE_PLD_CRITICAL(pld->critical_rsv) ? "CRITICAL" : "NOT CRITICAL" );
      printf( "len : %d\n", ntohs( pld->len ) );

      if(((u8*) pld) + sizeof(rhp_proto_ike_id_payload) > tail){
        printf( "Invalid IKEv2 format(19).\n" );
        return -1;
      }

      printf(
          "id_type : %d (RESERVED:0,4,6-8,IPV4_ADDR:1,FQDN:2,RFC822_ADDR:3,IPV6_ADDR:5,DER_ASN1_DN:9,DER_ASN1_GN:10,KEY_ID:11)\n",
          id->id_type );
      printf( "reserved1 : 0x%x\n", id->reserved1 );
      printf( "reserved2 : 0x%x\n", ntohs( id->reserved2 ) );

      p = (u8*) (id + 1);
      if(p > tail){
        printf( "Invalid IKEv2 format(20).\n" );
        return -1;
      }

      if(p + (pld_len - sizeof(rhp_proto_ike_id_payload)) > tail){
        printf( "Invalid IKEv2 format(21).\n" );
        return -1;
      }

      _rhp_bin_dump( "Identification Data", p,
      		(pld_len - sizeof(rhp_proto_ike_id_payload)), 1 );

    }else if(next_payload == RHP_PROTO_IKE_PAYLOAD_CERT){

      rhp_proto_ike_cert_payload* cert = (rhp_proto_ike_cert_payload*) pld;

      printf( "\n  ==[CERT]==\n" );
      *smry_idx += sprintf( (smry + *smry_idx), " CERT" );

      if(pld->next_payload > _IKEV2_PAYLOAD_TYPE_MAX){
        printf( "next_payload : UNKNOWN(%d)\n", pld->next_payload );
      }else{
        printf( "next_payload : %s(%d)\n",
            _print_ikev2_payload_types[pld->next_payload], pld->next_payload );
      }
      printf( "critical_rsv : 0x%x(%s)\n", pld->critical_rsv,
          RHP_PROTO_IKE_PLD_CRITICAL(pld->critical_rsv) ? "CRITICAL"
              : "NOT CRITICAL" );
      printf( "len : %d\n", ntohs( pld->len ) );

      if(((u8*) pld) + sizeof(rhp_proto_ike_cert_payload) > tail){
        printf( "Invalid IKEv2 format(22).\n" );
        return -1;
      }

      printf( "cert_encoding : %d(X509_CERT_SIG:4,X509_CERT_HASH_URL:12)\n",
          cert->cert_encoding );

      p = (u8*) (cert + 1);
      if(p > tail){
        printf( "Invalid IKEv2 format(23).\n" );
        return -1;
      }

      if(p + (pld_len - sizeof(rhp_proto_ike_cert_payload)) > tail){
        printf( "Invalid IKEv2 format(24).\n" );
        return -1;
      }

      _rhp_bin_dump( "Certificate Data", p, (pld_len
          - sizeof(rhp_proto_ike_cert_payload)), 1 );

    }else if(next_payload == RHP_PROTO_IKE_PAYLOAD_CERTREQ){

      rhp_proto_ike_certreq_payload*
      certreq = (rhp_proto_ike_certreq_payload*) pld;

      printf( "\n  ==[CERTREQ]==\n" );
      *smry_idx += sprintf( (smry + *smry_idx), " CERTREQ" );

      if(pld->next_payload > _IKEV2_PAYLOAD_TYPE_MAX){
        printf( "next_payload : UNKNOWN(%d)\n", pld->next_payload );
      }else{
        printf( "next_payload : %s(%d)\n",
            _print_ikev2_payload_types[pld->next_payload], pld->next_payload );
      }
      printf( "critical_rsv : 0x%x(%s)\n", pld->critical_rsv,
          RHP_PROTO_IKE_PLD_CRITICAL(pld->critical_rsv) ? "CRITICAL" : "NOT CRITICAL" );
      printf( "len : %d\n", ntohs( pld->len ) );

      if(((u8*) pld) + sizeof(rhp_proto_ike_certreq_payload) > tail){
        printf( "Invalid IKEv2 format(25).\n" );
        return -1;
      }

      printf( "cert_encoding : %d (X509_CERT_SIG:4,X509_CERT_HASH_URL:12)\n",
          certreq->cert_encoding );

      p = (u8*) (certreq + 1);
      if(p > tail){
        printf( "Invalid IKEv2 format(26).\n" );
        return -1;
      }

      if(p + (pld_len - sizeof(rhp_proto_ike_certreq_payload)) > tail){
        printf( "Invalid IKEv2 format(27).\n" );
        return -1;
      }

      _rhp_bin_dump( "Certification Authority Data", p, (pld_len
          - sizeof(rhp_proto_ike_certreq_payload)), 1 );

    }else if(next_payload == RHP_PROTO_IKE_PAYLOAD_AUTH){

      rhp_proto_ike_auth_payload* auth = (rhp_proto_ike_auth_payload*) pld;

      printf( "\n  ==[AUTH]==\n" );
      *smry_idx += sprintf( (smry + *smry_idx), " AUTH" );

      if(pld->next_payload > _IKEV2_PAYLOAD_TYPE_MAX){
        printf( "next_payload : UNKNOWN(%d)\n", pld->next_payload );
      }else{
        printf( "next_payload : %s(%d)\n",
            _print_ikev2_payload_types[pld->next_payload], pld->next_payload );
      }
      printf( "critical_rsv : 0x%x(%s)\n", pld->critical_rsv,
          RHP_PROTO_IKE_PLD_CRITICAL(pld->critical_rsv) ? "CRITICAL"
              : "NOT CRITICAL" );
      printf( "len : %d\n", ntohs( pld->len ) );

      if(((u8*) pld) + sizeof(rhp_proto_ike_auth_payload) > tail){
        printf( "Invalid IKEv2 format(28).\n" );
        return -1;
      }

      printf( "auth_method : %d (RSA_SIG:1,SHARED_KYE:2,DSS_SIG:3)\n",
          auth->auth_method );
      printf( "reserved1 : 0x%x\n", auth->reserved1 );
      printf( "reserved2 : 0x%x\n", ntohs( auth->reserved2 ) );

      p = (u8*) (auth + 1);
      if(p > tail){
        printf( "Invalid IKEv2 format(29).\n" );
        return -1;
      }

      if(p + (pld_len - sizeof(rhp_proto_ike_auth_payload)) > tail){
        printf( "Invalid IKEv2 format(30).\n" );
        return -1;
      }

      _rhp_bin_dump( "Authentication Data", p, (pld_len
          - sizeof(rhp_proto_ike_auth_payload)), 1 );

    }else if(next_payload == RHP_PROTO_IKE_PAYLOAD_N_I_R){

      rhp_proto_ike_nonce_payload* n_i_r = (rhp_proto_ike_nonce_payload*) pld;

      printf( "\n  ==[N_I_R]==\n" );
      *smry_idx += sprintf( (smry + *smry_idx), " N_I_R" );

      if(pld->next_payload > _IKEV2_PAYLOAD_TYPE_MAX){
        printf( "next_payload : UNKNOWN(%d)\n", pld->next_payload );
      }else{
        printf( "next_payload : %s(%d)\n",
            _print_ikev2_payload_types[pld->next_payload], pld->next_payload );
      }
      printf( "critical_rsv : 0x%x(%s)\n", pld->critical_rsv,
          RHP_PROTO_IKE_PLD_CRITICAL(pld->critical_rsv) ? "CRITICAL"
              : "NOT CRITICAL" );
      printf( "len : %d\n", ntohs( pld->len ) );

      if(((u8*) pld) + sizeof(rhp_proto_ike_nonce_payload) > tail){
        printf( "Invalid IKEv2 format(31).\n" );
        return -1;
      }

      p = (u8*) (n_i_r + 1);
      if(p > tail){
        printf( "Invalid IKEv2 format(32).\n" );
        return -1;
      }

      if(p + (pld_len - sizeof(rhp_proto_ike_nonce_payload)) > tail){
        printf( "Invalid IKEv2 format(33).\n" );
        return -1;
      }

      _rhp_bin_dump( "Nonce Data", p, (pld_len
          - sizeof(rhp_proto_ike_nonce_payload)), 1 );

    }else if(next_payload == RHP_PROTO_IKE_PAYLOAD_V){

      rhp_proto_ike_vid_payload* v = (rhp_proto_ike_vid_payload*) pld;
      int v_len;
      u8 my_vid[20] = { 0xa9, 0xf0, 0xf0, 0xca, 0x1d, 0x92, 0xd2, 0xed, 0xda,
          0x8f, 0xb4, 0x4d, 0x43, 0x89, 0x36, 0x55, 0x22, 0x82, 0xed, 0x8f };

      printf( "\n  ==[V]==\n" );
      *smry_idx += sprintf( (smry + *smry_idx), " V" );

      if(pld->next_payload > _IKEV2_PAYLOAD_TYPE_MAX){
        printf( "next_payload : UNKNOWN(%d)\n", pld->next_payload );
      }else{
        printf( "next_payload : %s(%d)\n",
            _print_ikev2_payload_types[pld->next_payload], pld->next_payload );
      }
      printf( "critical_rsv : 0x%x(%s)\n", pld->critical_rsv,
          RHP_PROTO_IKE_PLD_CRITICAL(pld->critical_rsv) ? "CRITICAL"
              : "NOT CRITICAL" );
      printf( "len : %d\n", ntohs( pld->len ) );

      if(((u8*) pld) + sizeof(rhp_proto_ike_nonce_payload) > tail){
        printf( "Invalid IKEv2 format(34).\n" );
        return -1;
      }

      p = (u8*) (v + 1);
      if(p > tail){
        printf( "Invalid IKEv2 format(35).\n" );
        return -1;
      }

      if(p + (pld_len - sizeof(rhp_proto_ike_vid_payload)) > tail){
        printf( "Invalid IKEv2 format(36).\n" );
        return -1;
      }

      v_len = pld_len - sizeof(rhp_proto_ike_vid_payload);

      if(v_len == 21 && !memcmp( my_vid, (p + 1), 20 )){
        printf( "\nVendor ID : Rockhopper" );
        *smry_idx += sprintf( (smry + *smry_idx), "(Rockhopper)" );
      }

      _rhp_bin_dump( "Vendor ID Data", p, v_len, 1 );

    }else if( next_payload == RHP_PROTO_IKE_PAYLOAD_TS_I ||
    					next_payload == RHP_PROTO_IKE_PAYLOAD_TS_R){

      rhp_proto_ike_ts_payload* ts = (rhp_proto_ike_ts_payload*) pld;
      rhp_proto_ike_ts_selector* tsr;

      if(next_payload == RHP_PROTO_IKE_PAYLOAD_TS_I){
        printf( "\n  ==[TS_I]==\n" );
        *smry_idx += sprintf( (smry + *smry_idx), " TS_I" );
      }else{
        printf( "\n  ==[TS_R]==\n" );
        *smry_idx += sprintf( (smry + *smry_idx), " TS_R" );
      }
      if(pld->next_payload > _IKEV2_PAYLOAD_TYPE_MAX){
        printf( "next_payload : UNKNOWN(%d)\n", pld->next_payload );
      }else{
        printf( "next_payload : %s(%d)\n",
            _print_ikev2_payload_types[pld->next_payload], pld->next_payload );
      }
      printf( "critical_rsv : 0x%x(%s)\n", pld->critical_rsv,
          RHP_PROTO_IKE_PLD_CRITICAL(pld->critical_rsv) ? "CRITICAL" : "NOT CRITICAL" );
      printf( "len : %d\n", ntohs( pld->len ) );

      if(((u8*) pld) + sizeof(rhp_proto_ike_ts_payload) > tail){
        printf( "Invalid IKEv2 format(37).\n" );
        return -1;
      }

      printf( "ts_num : %d \n", ts->ts_num );
      printf( "reserved1 : 0x%x\n", ts->reserved1 );
      printf( "reserved2 : 0x%x\n", ntohs( ts->reserved2 ) );

      tsr = (rhp_proto_ike_ts_selector*) (ts + 1);

      for(i = 0; i < ts->ts_num; i++){

        int tsr_len;

        printf( "\n  ==Traffic Selector[%d]==\n", (i + 1) );

        if((u8*) tsr >= tail){
          printf( "Invalid IKEv2 format(38).\n" );
          return -1;
        }

        if(((u8*) tsr) + sizeof(rhp_proto_ike_transform) > tail){
          printf( "Invalid IKEv2 format(39).\n" );
          return -1;
        }

        tsr_len = ntohs( tsr->len );

        if(((u8*) tsr) + tsr_len > tail){
          printf( "Invalid IKEv2 format(40).\n" );
          return -1;
        }

        printf( "ts_type : %d (IPV4_ADDR_RANGE:7,IPV6_ADDR_RANGE:8)\n",
            tsr->ts_type );
        printf( "ip_protocol_id : %d\n", tsr->ip_protocol_id );
        printf( "len : %d\n", tsr_len );

        if(tsr->ip_protocol_id == 1){
          printf( "start_type : %d, code : %d\n", tsr->start_port.icmp.type,
              tsr->start_port.icmp.code );
        }else{
          printf( "start_port : %d\n", ntohs( tsr->start_port.port ) );
        }

        if(tsr->ip_protocol_id == 1){
          printf( "end_type : %d, code : %d\n", tsr->end_port.icmp.type,
              tsr->end_port.icmp.code );
        }else{
          printf( "end_port : %d\n", ntohs( tsr->end_port.port ) );
        }

        if( tsr->ts_type == RHP_PROTO_IKE_TS_IPV4_ADDR_RANGE &&
        		tsr_len == RHP_PROTO_IKE_TS_IPV4_SIZE){

          u8* start_addr = (u8*) (tsr + 1);
          u8* end_addr = (start_addr + 4);

          printf( "start_addr_v4 : %d.%d.%d.%d\n", start_addr[0], start_addr[1],
              start_addr[2], start_addr[3] );
          printf( "end_addr_v4   : %d.%d.%d.%d\n", end_addr[0], end_addr[1],
              end_addr[2], end_addr[3] );


        }else if( tsr->ts_type == RHP_PROTO_IKE_TS_IPV6_ADDR_RANGE &&
          				tsr_len == RHP_PROTO_IKE_TS_IPV6_SIZE){

        	u8* start_addr = (u8*) (tsr + 1);
          u8* end_addr = (start_addr + 16);

          printf( "start_addr_v6 : %s\n", _rhp_ipv6_string(start_addr));
          printf( "end_addr_v6   : %s\n", _rhp_ipv6_string(end_addr));

        }else{

          p = (u8*) (tsr + 1);
          if(p > tail){
            printf( "Invalid IKEv2 format(41).\n" );
            return -1;
          }

          if(p + (tsr_len - sizeof(rhp_proto_ike_ts_selector)) > tail){
            printf( "Invalid IKEv2 format(42).\n" );
            return -1;
          }

          _rhp_bin_dump( "Traffic Selector Dump", p, (tsr_len
              - sizeof(rhp_proto_ike_ts_selector)), 1 );
        }

        printf( "\n" );

        tsr = (rhp_proto_ike_ts_selector*) (((u8*) tsr) + tsr_len);
      }

    }else if(next_payload == RHP_PROTO_IKE_PAYLOAD_N){

      rhp_proto_ike_notify_payload* n_pld = (rhp_proto_ike_notify_payload*) pld;
      int n_data_len;
      u16 mesg_type = bswap_16(n_pld->notify_mesg_type);
      int aa;

      printf( "\n  ==[N]==\n" );
      *smry_idx += sprintf( (smry + *smry_idx), " N" );

      if(pld->next_payload > _IKEV2_PAYLOAD_TYPE_MAX){
        printf( "next_payload : UNKNOWN(%d)\n", pld->next_payload );
      }else{
        printf( "next_payload : %s(%d)\n",
            _print_ikev2_payload_types[pld->next_payload], pld->next_payload );
      }
      printf( "critical_rsv : 0x%x(%s)\n", pld->critical_rsv,
          RHP_PROTO_IKE_PLD_CRITICAL(pld->critical_rsv) ? "CRITICAL"
              : "NOT CRITICAL" );
      printf( "len : %d\n", ntohs( pld->len ) );

      printf( "protocol : %d (IKE:1,AH:2,ESP:3)\n", n_pld->protocol_id );

      {
        switch(n_pld->protocol_id){

        case 1:
          *smry_idx += sprintf( (smry + *smry_idx), "(IKE)" );
          break;

        case 2:
          *smry_idx += sprintf( (smry + *smry_idx), "(AH)" );
          break;

        case 3:
          *smry_idx += sprintf( (smry + *smry_idx), "(ESP)" );
          break;

        default:
          *smry_idx += sprintf( (smry + *smry_idx), "(%d)", n_pld->protocol_id );
          break;
        }
      }

      printf( "spi_len : %d\n", n_pld->spi_len );
      printf( "notify_mesg_type : %d, 0x%x (%s : ", mesg_type, mesg_type,
          (mesg_type <= 16383 ? "ERROR TYPES" : "STATUS TYPES") );

      for(aa = 0; aa < _IKEV2_NOTIFICATION_TYPE_MAX; aa++){

        if(_print_ikev2_notification_types[aa] == mesg_type){

          printf( "%s)\n", _print_ikev2_notification_types_str[aa] );

          if(mesg_type == RHP_PROTO_IKE_NOTIFY_ST_REKEY_SA){
            *smry_idx += sprintf( (smry + *smry_idx), "(REKEY)" );
          }else if(mesg_type <= 16383){
            *smry_idx += sprintf( (smry + *smry_idx), "(ERR)" );
          }else{
            *smry_idx += sprintf( (smry + *smry_idx), "(STAT)" );
          }

          break;
        }
      }

      if(aa >= _IKEV2_NOTIFICATION_TYPE_MAX){
        printf( "UNKNOWN TYPE)\n" );
      }

      p = (u8*) (n_pld + 1);

      if(n_pld->spi_len){

        if(n_pld->spi_len == 4){

          printf( "spi : %u(0x%x)\n", bswap_32(*((u32*)p)),
              bswap_32(*((u32*)p)));
          *smry_idx += sprintf( (smry + *smry_idx), "[%u(0x%x)]",
              bswap_32(*((u32*)p)), bswap_32(*((u32*)p)));

        }else{

          printf( "Invalid SPI len:%d\n", n_pld->spi_len );
          _rhp_bin_dump( "spi", p, n_pld->spi_len, 1 );
        }
        p += n_pld->spi_len;
      }

      n_data_len = pld_len - n_pld->spi_len
          - sizeof(rhp_proto_ike_notify_payload);
      if(n_data_len){
        _rhp_bin_dump( "Notification Data", (u8*) p, n_data_len, 1 );
      }

      //			_rhp_bin_dump("Payload Data", (u8*)pld, pld_len, 1);

    }else if(next_payload == RHP_PROTO_IKE_PAYLOAD_D){

      rhp_proto_ike_delete_payload* d_pld = (rhp_proto_ike_delete_payload*) pld;
      u8* d_pld_spi_p = NULL;

      printf( "\n  ==[D]==\n" );
      *smry_idx += sprintf( (smry + *smry_idx), " D" );

      if(pld->next_payload > _IKEV2_PAYLOAD_TYPE_MAX){
        printf( "next_payload : UNKNOWN(%d)\n", pld->next_payload );
      }else{
        printf( "next_payload : %s(%d)\n",
            _print_ikev2_payload_types[pld->next_payload], pld->next_payload );
      }
      printf( "critical_rsv : 0x%x(%s)\n", pld->critical_rsv,
          RHP_PROTO_IKE_PLD_CRITICAL(pld->critical_rsv) ? "CRITICAL"
              : "NOT CRITICAL" );
      printf( "len : %d\n", ntohs( pld->len ) );
      printf( "protocol : %d (IKE:1,AH:2,ESP:3)\n", d_pld->protocol_id );

      {
        switch(d_pld->protocol_id){

        case 1:
          *smry_idx += sprintf( (smry + *smry_idx),
              "(IKE)[I: %llu(0x%llx][R: %llu(0x%llx)]",
              (ike ? bswap_64(*((u64*)ike->init_spi)) : 0),
              (ike ? bswap_64(*((u64*)ike->init_spi)) : 0),
              (ike ? bswap_64(*((u64*)ike->resp_spi)) : 0),
              (ike ? bswap_64(*((u64*)ike->resp_spi)) : 0));
          break;

        case 2:
          *smry_idx += sprintf( (smry + *smry_idx), "(AH)" );
          break;

        case 3:
          *smry_idx += sprintf( (smry + *smry_idx), "(ESP)" );
          break;

        default:
          *smry_idx += sprintf( (smry + *smry_idx), "(%d)", d_pld->protocol_id );
          break;
        }
      }

      printf( "spi_len : %d\n", d_pld->spi_len );
      printf( "spi_num : %d\n", ntohs( d_pld->spi_num ) );

      d_pld_spi_p = ((u8*) pld) + sizeof(rhp_proto_ike_delete_payload);

      for(i = 0; i < ntohs( d_pld->spi_num ) && d_pld_spi_p < (((u8*) pld)
          + pld_len); i++){

        if(d_pld->spi_len == 4){

          printf( "spi : %u(0x%x)\n", bswap_32(*((u32*)d_pld_spi_p)),
              bswap_32(*((u32*)d_pld_spi_p)));
          *smry_idx += sprintf( (smry + *smry_idx), "[%u(0x%x)]",
              bswap_32(*((u32*)d_pld_spi_p)), bswap_32(*((u32*)d_pld_spi_p)));

        }else{

          printf( "Invalid SPI len:%d\n", d_pld->spi_len );
          _rhp_bin_dump( "Payload Data", (u8*) pld, pld_len, 1 );
          break;
        }

        d_pld_spi_p = d_pld_spi_p + d_pld->spi_len;
      }

    }else if(next_payload == RHP_PROTO_IKE_PAYLOAD_CP){

      rhp_proto_ike_cp_payload* cp_pld = (rhp_proto_ike_cp_payload*) pld;
      u8* cp_attr_p;
      int cp_attrs_len = ntohs( pld->len ) - sizeof(rhp_proto_ike_cp_payload);

      printf( "\n  ==[CP]==\n" );
      *smry_idx += sprintf( (smry + *smry_idx), " CP" );

      if(pld->next_payload > _IKEV2_PAYLOAD_TYPE_MAX){
        printf( "next_payload : UNKNOWN(%d)\n", pld->next_payload );
      }else{
        printf( "next_payload : %s(%d)\n",
            _print_ikev2_payload_types[pld->next_payload], pld->next_payload );
      }
      printf( "critical_rsv : 0x%x(%s)\n", pld->critical_rsv,
          RHP_PROTO_IKE_PLD_CRITICAL(pld->critical_rsv) ? "CRITICAL"
              : "NOT CRITICAL" );
      printf( "len : %d\n", ntohs( pld->len ) );
      printf( "cfg_type: %d (REQUEST:1, REPLY:2, SET:3, ACK:4)\n",
          cp_pld->cfg_type );

      cp_attr_p = ((u8*) pld) + sizeof(rhp_proto_ike_cp_payload);

      while(cp_attrs_len > 0){

        rhp_proto_ike_cfg_attr* cp_attr = (rhp_proto_ike_cfg_attr*)cp_attr_p;
        int attr_data_len = ntohs( cp_attr->len );
        u8* attr_data = (u8*) (cp_attr + 1);
        int ii = 0;

        printf( "\n =====[ CP_ATTR (type:%d, len: %d) : ", ntohs(
            RHP_PROTO_IKE_CFG_ATTR_TYPE(cp_attr->cfg_attr_type_rsv) ),
            attr_data_len );

        switch(ntohs( RHP_PROTO_IKE_CFG_ATTR_TYPE(cp_attr->cfg_attr_type_rsv) )){

        case RHP_PROTO_IKE_CFG_ATTR_INTERNAL_IP4_ADDRESS:
          printf( "INTERNAL_IP4_ADDRESS ]=====\n" );
          if(attr_data_len != 4 && attr_data_len != 0){
            printf( "INVALID ATTR_DATA_LEN\n" );
          }else if(attr_data_len == 4){
            printf( "%d.%d.%d.%d\n", attr_data[0], attr_data[1], attr_data[2],
                attr_data[3] );
          }
          break;

        case RHP_PROTO_IKE_CFG_ATTR_INTERNAL_IP4_NETMASK:
          printf( "INTERNAL_IP4_NETMASK ]=====\n" );
          if(attr_data_len != 4 && attr_data_len != 0){
            printf( "INVALID ATTR_DATA_LEN\n" );
          }else if(attr_data_len == 4){
            printf( "%d.%d.%d.%d\n", attr_data[0], attr_data[1], attr_data[2],
                attr_data[3] );
          }
          break;

        case RHP_PROTO_IKE_CFG_ATTR_INTERNAL_IP4_DNS:
          printf( "INTERNAL_IP4_DNS ]=====\n" );
          if(attr_data_len != 4 && attr_data_len != 0){
            printf( "INVALID ATTR_DATA_LEN\n" );
          }else if(attr_data_len == 4){
            printf( "%d.%d.%d.%d\n", attr_data[0], attr_data[1], attr_data[2],
                attr_data[3] );
          }
          break;

        case RHP_PROTO_IKE_CFG_ATTR_INTERNAL_IP4_NBNS:
          printf( "INTERNAL_IP4_NBNS ]=====\n" );
          if(attr_data_len != 4 && attr_data_len != 0){
            printf( "INVALID ATTR_DATA_LEN\n" );
          }else if(attr_data_len == 4){
            printf( "%d.%d.%d.%d\n", attr_data[0], attr_data[1], attr_data[2],
                attr_data[3] );
          }
          break;

        case RHP_PROTO_IKE_CFG_ATTR_INTERNAL_ADDRESS_EXPIRY:
          printf( "INTERNAL_ADDRESS_EXPIRY ]=====\n" );
          break;

        case RHP_PROTO_IKE_CFG_ATTR_INTERNAL_IP4_DHCP:
          printf( "INTERNAL_IP4_DHCP ]=====\n" );
          if(attr_data_len != 4 && attr_data_len != 0){
            printf( "INVALID ATTR_DATA_LEN\n" );
          }else if(attr_data_len == 4){
            printf( "%d.%d.%d.%d\n", attr_data[0], attr_data[1], attr_data[2],
                attr_data[3] );
          }
          break;

        case RHP_PROTO_IKE_CFG_ATTR_APPLICATION_VERSION:
          printf( "APPLICATION_VERSION ]=====\n" );
          break;

        case RHP_PROTO_IKE_CFG_ATTR_INTERNAL_IP6_ADDRESS:
          printf( "INTERNAL_IP6_ADDRESS ]=====\n" );
          if(attr_data_len != 17 && attr_data_len != 0){
            printf( "INVALID ATTR_DATA_LEN\n" );
          }else if(attr_data_len == 17){
            printf( "%s/%d\n", _rhp_ipv6_string(attr_data),(int)(attr_data[16]));
          }
          break;

        case RHP_PROTO_IKE_CFG_ATTR_INTERNAL_IP6_DNS:
          printf( "INTERNAL_IP6_DNS ]=====\n" );
          if(attr_data_len != 16 && attr_data_len != 0){
            printf( "INVALID ATTR_DATA_LEN\n" );
          }else if(attr_data_len == 16){
            printf( "%s\n", _rhp_ipv6_string(attr_data));
          }
          break;

        case RHP_PROTO_IKE_CFG_ATTR_INTERNAL_IP6_NBNS:
          printf( "INTERNAL_IP6_NBNS ]=====\n" );
          if(attr_data_len != 16 && attr_data_len != 0){
            printf( "INVALID ATTR_DATA_LEN\n" );
          }else if(attr_data_len == 16){
            printf( "%s\n", _rhp_ipv6_string(attr_data));
          }
          break;

        case RHP_PROTO_IKE_CFG_ATTR_INTERNAL_IP6_DHCP:
          printf( "INTERNAL_IP6_DHCP ]=====\n" );
          if(attr_data_len != 16 && attr_data_len != 0){
            printf( "INVALID ATTR_DATA_LEN\n" );
          }else if(attr_data_len == 16){
            printf( "%s\n", _rhp_ipv6_string(attr_data));
          }
          break;

        case RHP_PROTO_IKE_CFG_ATTR_INTERNAL_IP4_SUBNET:
          printf( "INTERNAL_IP4_SUBNET ]=====\n" );
          if(attr_data_len != 8 && attr_data_len != 0){
            printf( "INVALID ATTR_DATA_LEN\n" );
          }else if(attr_data_len == 8){
            printf( "%d.%d.%d.%d / %d.%d.%d.%d\n", attr_data[0], attr_data[1],
                attr_data[2], attr_data[3], attr_data[4], attr_data[5],
                attr_data[6], attr_data[7] );
          }
          break;

        case RHP_PROTO_IKE_CFG_ATTR_SUPPORTED_ATTRIBUTES:
          printf( "SUPPORTED_ATTRIBUTES ]=====\n" );
          break;

        case RHP_PROTO_IKE_CFG_ATTR_INTERNAL_IP6_SUBNET:
          printf( "INTERNAL_IP6_SUBNET ]=====\n" );
          if(attr_data_len != 17 && attr_data_len != 0){
            printf( "INVALID ATTR_DATA_LEN\n" );
          }else if(attr_data_len == 17){
            printf( "%s/%d\n", _rhp_ipv6_string(attr_data),attr_data[16]);
          }
          break;

        case RHP_PROTO_IKE_CFG_ATTR_RHP_DNS_SFX:
          printf( "RHP_DNS_SFX ]=====\n" );
          for(ii = 0; ii < attr_data_len; ii++){
            printf( "%c", attr_data[ii] );
          }
          printf( "\n" );
          break;

        case RHP_PROTO_IKE_CFG_ATTR_RHP_IPV4_GATEWAY:
          printf( "RHP_IPV4_GATEWAY ]=====\n" );
          if(attr_data_len != 4 && attr_data_len != 0){
            printf( "INVALID ATTR_DATA_LEN\n" );
          }else if(attr_data_len == 4){
            printf( "%d.%d.%d.%d\n", attr_data[0], attr_data[1], attr_data[2],
                attr_data[3] );
          }
          break;

        case RHP_PROTO_IKE_CFG_ATTR_RHP_IPV6_GATEWAY:
          printf( "RHP_IPV6_GATEWAY ]=====\n" );
          if(attr_data_len != 16 && attr_data_len != 0){
            printf( "INVALID ATTR_DATA_LEN\n" );
          }else if(attr_data_len == 16){
            printf( "%s\n", _rhp_ipv6_string(attr_data));
          }
          break;

        default:
          printf( "UNKNOWN(%d) ]=====\n", ntohs(
              RHP_PROTO_IKE_CFG_ATTR_TYPE(cp_attr->cfg_attr_type_rsv) ) );
          break;
        }

        cp_attr_p += ntohs( cp_attr->len ) + sizeof(rhp_proto_ike_cfg_attr);
        cp_attrs_len -= ntohs( cp_attr->len ) + sizeof(rhp_proto_ike_cfg_attr);
      }


    }else if(next_payload == RHP_PROTO_IKE_PAYLOAD_EAP){

    	rhp_proto_ike_eap_payload* eap_pld = (rhp_proto_ike_eap_payload*) pld;
    	rhp_proto_ike_eap_payload_request* eap_req = NULL;

      printf( "\n  ==[EAP]==\n" );
      *smry_idx += sprintf( (smry + *smry_idx), " EAP(" );

      if(pld->next_payload > _IKEV2_PAYLOAD_TYPE_MAX){
        printf( "next_payload : UNKNOWN(%d)\n", pld->next_payload );
      }else{
        printf( "next_payload : %s(%d)\n",
            _print_ikev2_payload_types[pld->next_payload], pld->next_payload );
      }
      printf( "critical_rsv : 0x%x(%s)\n", pld->critical_rsv,
          RHP_PROTO_IKE_PLD_CRITICAL(pld->critical_rsv) ? "CRITICAL"
              : "NOT CRITICAL" );
      printf( "len : %d\n", ntohs( pld->len ) );

      switch( eap_pld->eap_code ){

      case RHP_PROTO_EAP_CODE_REQUEST:

        printf("eap_code: REQUEST(%d)\n",eap_pld->eap_code);
        *smry_idx += sprintf( (smry + *smry_idx), "REQ:" );
      	break;

      case RHP_PROTO_EAP_CODE_RESPONSE:

        printf("eap_code: RESPONSE(%d)\n",eap_pld->eap_code);
        *smry_idx += sprintf( (smry + *smry_idx), "RESP:" );
      	break;

      case RHP_PROTO_EAP_CODE_SUCCESS:

        printf("eap_code: SUCCESS(%d)\n",eap_pld->eap_code);
        *smry_idx += sprintf( (smry + *smry_idx), "SUCCESS:" );
      	break;

      case RHP_PROTO_EAP_CODE_FAILURE:

        printf("eap_code: FAILURE(%d)\n",eap_pld->eap_code);
        *smry_idx += sprintf( (smry + *smry_idx), "FAIL:" );
      	break;

      default:

      	printf("eap_code: Unknown\n");
        *smry_idx += sprintf( (smry + *smry_idx), "UNKNOWN:" );
      	break;
      }

      printf("eap_identifier: 0x%x\n",eap_pld->eap_identifier);
      printf("eap_len: %d\n",ntohs(eap_pld->eap_len));


      switch( eap_pld->eap_code ){

      case RHP_PROTO_EAP_CODE_REQUEST:
      case RHP_PROTO_EAP_CODE_RESPONSE:
      {
      	eap_req = (rhp_proto_ike_eap_payload_request*)eap_pld;

      	switch( eap_req->eap_type ){
      	case RHP_PROTO_EAP_TYPE_IDENTITY:
        	printf("EAP type: IDENTITY(%d)\n",eap_pld->eap_code);
          *smry_idx += sprintf( (smry + *smry_idx), " IDENT" );
      		break;
      	case RHP_PROTO_EAP_TYPE_NOTIFICATION:
        	printf("EAP type: NOTIFICATION(%d)\n",eap_pld->eap_code);
          *smry_idx += sprintf( (smry + *smry_idx), " NOTIFY" );
      		break;
      	case RHP_PROTO_EAP_TYPE_NAK:
        	printf("EAP type: NAK(%d)\n",eap_pld->eap_code);
          *smry_idx += sprintf( (smry + *smry_idx), " NAK" );
      		break;
      	case RHP_PROTO_EAP_TYPE_MD5_CHALLENGE:
        	printf("EAP type: MD5-CHALLENGE(%d)\n",eap_pld->eap_code);
          *smry_idx += sprintf( (smry + *smry_idx), " MD5" );
      		break;
      	case RHP_PROTO_EAP_TYPE_ONE_TIME_PASSWORD:
        	printf("EAP type: ONE-TIME-PASSWORD(%d)\n",eap_pld->eap_code);
          *smry_idx += sprintf( (smry + *smry_idx), " OTP" );
      		break;
      	case RHP_PROTO_EAP_TYPE_GENERIC_TOKEN_CARD:
        	printf("EAP type: GENERIC-TOKEN-CARD(%d)\n",eap_pld->eap_code);
          *smry_idx += sprintf( (smry + *smry_idx), " GTC" );
      		break;
      	case RHP_PROTO_EAP_TYPE_MS_CHAPV2:
      		printf("EAP type: MS-CHAPv2(%d)\n",eap_pld->eap_code);
          *smry_idx += sprintf( (smry + *smry_idx), " MS-CHAPv2" );
      		break;
      	default:
        	printf("EAP type: Unknown(%d)\n",eap_pld->eap_code);
          *smry_idx += sprintf( (smry + *smry_idx), " UNKNOWN" );
      		break;
      	}

        _rhp_bin_dump( "++++ EAP-Type-Data ++++", (u8*) (eap_req + 1),
        		(ntohs(eap_pld->len) - sizeof(rhp_proto_ike_eap_payload_request)), 1 );
        printf("\n");

      	break;
      }

      default:
      	break;
      }

      if( eap_req && eap_req->eap_type == RHP_PROTO_EAP_TYPE_MS_CHAPV2 ){

      	rhp_proto_ms_chapv2* mschap = (rhp_proto_ms_chapv2*)(eap_req + 1);

        _rhp_bin_dump( "++++ MS-CHAPv2-Type-Data ++++", (u8*) (mschap + 1),
        		(ntohs(mschap->ms_len) - sizeof(rhp_proto_ms_chapv2)), 1 );
        printf("\n");

      	switch( mschap->ms_code ){

      	case RHP_PROTO_MS_CHAPV2_CODE_CHALLENGE:
        	printf("MS-CHAPv2 code: CHALLENGE(%d)\n",mschap->ms_code);
          *smry_idx += sprintf( (smry + *smry_idx), " [CHALLENGE" );
        	printf("MS-CHAPv2 identifier: 0x%x\n",mschap->ms_identifier);
        	printf("MS-CHAPv2 len: %d\n",ntohs(mschap->ms_len));

        	{
        		rhp_proto_ms_chapv2_challenge* challenge = (rhp_proto_ms_chapv2_challenge*)mschap;

            _rhp_bin_dump( "challenge", challenge->ms_challenge,challenge->ms_challenge_size, 1 );
            _rhp_bin_dump( "name", (u8*)(challenge + 1),ntohs(mschap->ms_len) - sizeof(rhp_proto_ms_chapv2_challenge), 1 );
        	}

      		break;
      	case RHP_PROTO_MS_CHAPV2_CODE_RESPONSE:
        	printf("MS-CHAPv2 code: RESPONSE(%d)\n",mschap->ms_code);
          *smry_idx += sprintf( (smry + *smry_idx), " [RESP" );
        	printf("MS-CHAPv2 identifier: 0x%x\n",mschap->ms_identifier);
        	printf("MS-CHAPv2 len: %d\n",ntohs(mschap->ms_len));

        	{
        		rhp_proto_ms_chapv2_response* resp = (rhp_proto_ms_chapv2_response*)mschap;

          	printf("  resp_size: %d\n",resp->ms_response_size);

            _rhp_bin_dump( "peer-challenge",resp->ms_peer_challenge,16, 1 );
            _rhp_bin_dump( "reserved",resp->ms_reserved,8, 1 );
            _rhp_bin_dump( "nt_response",resp->ms_nt_response,24, 1 );

            printf("  ms_flags: %d\n",resp->ms_flags);

            _rhp_bin_dump( "name",(u8*)(resp + 1),
            		ntohs(resp->ms_len) - sizeof(rhp_proto_ms_chapv2_response), 1 );
        	}
        	break;
      	case RHP_PROTO_MS_CHAPV2_CODE_SUCCESS:
        	printf("MS-CHAPv2 code: SUCCESS(%d)\n",mschap->ms_code);
          *smry_idx += sprintf( (smry + *smry_idx), " [SUCCESS" );
        	printf("MS-CHAPv2 identifier: 0x%x\n",mschap->ms_identifier);
        	printf("MS-CHAPv2 len: %d\n",ntohs(mschap->ms_len));

        	_rhp_bin_dump( "message",(u8*)(mschap + 1),
        			ntohs(mschap->ms_len) - sizeof(rhp_proto_ms_chapv2_success) ,1 );

        	break;
      	case RHP_PROTO_MS_CHAPV2_CODE_FAILURE:
        	printf("MS-CHAPv2 code: FAILURE(%d)\n",mschap->ms_code);
          *smry_idx += sprintf( (smry + *smry_idx), " [FAIL" );
        	printf("MS-CHAPv2 identifier: 0x%x\n",mschap->ms_identifier);
        	printf("MS-CHAPv2 len: %d\n",ntohs(mschap->ms_len));

        	_rhp_bin_dump( "message",(u8*)(mschap + 1),
        			ntohs(mschap->ms_len) - sizeof(rhp_proto_ms_chapv2_failure) ,1 );

        	printf("\n  ErrorCode(E=xxx):\n   ERROR_RESTRICTED_LOGON_HOURS(646)\n   ERROR_ACCT_DISABLED(647)\n   ERROR_PASSWD_EXPIRED(648)\n   ERROR_NO_DIALIN_PERMISSION(649)\n   ERROR_AUTHENTICATION_FAILURE(691)\n   ERROR_CHANGING_PASSWORD(709)\n\n");

        	break;
      	case RHP_PROTO_MS_CHAPV2_CODE_CHANGE_PASSWORD:
        	printf("MS-CHAPv2 code: CHANGE_PASSWORD(%d)\n",mschap->ms_code);
          *smry_idx += sprintf( (smry + *smry_idx), " [CHG-PW" );
        	printf("MS-CHAPv2 identifier: 0x%x\n",mschap->ms_identifier);
        	printf("MS-CHAPv2 len: %d\n",ntohs(mschap->ms_len));
      		break;
      	default:
        	printf("MS-CHAPv2 code: UNKNOWN(%d)\n",mschap->ms_code);
          *smry_idx += sprintf( (smry + *smry_idx), " [UNKNOWN" );
        	printf("MS-CHAPv2 identifier: 0x%x\n",mschap->ms_identifier);
        	printf("MS-CHAPv2 len: %d\n",ntohs(mschap->ms_len));
      		break;
      	}
        *smry_idx += sprintf( (smry + *smry_idx), "]" );
      }
      *smry_idx += sprintf( (smry + *smry_idx), ")" );

    }else{

      printf( "\n  ==[Unknown Payload]==\n" );
      *smry_idx += sprintf( (smry + *smry_idx), " ?(%d)", next_payload );

      if(pld->next_payload > _IKEV2_PAYLOAD_TYPE_MAX){
        printf( "next_payload : UNKNOWN(%d)\n", pld->next_payload );
      }else{
        printf( "next_payload : %s(%d)\n",
            _print_ikev2_payload_types[pld->next_payload], pld->next_payload );
      }
      printf( "critical_rsv : 0x%x(%s)\n", pld->critical_rsv,
          RHP_PROTO_IKE_PLD_CRITICAL(pld->critical_rsv) ? "CRITICAL"
              : "NOT CRITICAL" );
      printf( "len : %d", ntohs( pld->len ) );

      _rhp_bin_dump( "Payload Data", (u8*) pld, pld_len, 1 );
    }

    next_payload = pld->next_payload;
    pld = (rhp_proto_ike_payload*) (((u8*) pld) + pld_len);
  }

  if(next_payload != RHP_PROTO_IKE_NO_MORE_PAYLOADS){
    printf( "Invalid IKEv2 format(43).\n" );
  }

  return 0;
}


static int _print_ikev2( u8* buf, int buf_len, int iv_len, int icv_len,
    int is_plain, int* data_len, int* smry_idx, char* smry, int no_payloads_print)
{
  rhp_proto_ike* ike = (rhp_proto_ike*) buf;

  if( no_payloads_print ){
  	printf( "\n==<IKEv2-RAW>==\n" );
  }else{
    printf( "\n==<IKEv2>==\n" );
  }

  if(buf_len < sizeof(rhp_proto_ike)){
    printf( "\n******* Invalid IKEv2 format(1) ******* .\n" );
    return -1;
  }

  if(ike->ver_major != 2){
    printf( "NOT IKEv2\n" );
    *smry_idx += sprintf( (smry + *smry_idx), " NOT IKEv2" );
    return 0;
  }

  printf( "init_spi : %llu(0x%02x%02x%02x%02x%02x%02x%02x%02x)\n",
      bswap_64(*((u64*)ike->init_spi)), (((unsigned char*) ike->init_spi)[0]),
      (((unsigned char*) ike->init_spi)[1]),
      (((unsigned char*) ike->init_spi)[2]),
      (((unsigned char*) ike->init_spi)[3]),
      (((unsigned char*) ike->init_spi)[4]),
      (((unsigned char*) ike->init_spi)[5]),
      (((unsigned char*) ike->init_spi)[6]),
      (((unsigned char*) ike->init_spi)[7]) );
  /*
   *smry_idx += sprintf((smry+*smry_idx)," I_SPI: %llu(0x%02x%02x%02x%02x%02x%02x%02x%02x)", bswap_64(*((u64*)ike->init_spi)),
   (((unsigned char*)ike->init_spi)[0]), (((unsigned char*)ike->init_spi)[1]), (((unsigned char*)ike->init_spi)[2]), (((unsigned char*)ike->init_spi)[3]), (((unsigned char*)ike->init_spi)[4]),
   (((unsigned char*)ike->init_spi)[5]), (((unsigned char*)ike->init_spi)[6]), (((unsigned char*)ike->init_spi)[7]));
   */
  if( no_payloads_print ){
  	*smry_idx += sprintf( (smry + *smry_idx), " [IKEv2-RAW] I_SPI: %llu(0x%llx)",
      bswap_64(*((u64*)ike->init_spi)), bswap_64(*((u64*)ike->init_spi)));
  }else{
  	*smry_idx += sprintf( (smry + *smry_idx), " [IKEv2] I_SPI: %llu(0x%llx)",
      bswap_64(*((u64*)ike->init_spi)), bswap_64(*((u64*)ike->init_spi)));
  }

  printf( "resp_spi : %llu(0x%02x%02x%02x%02x%02x%02x%02x%02x)\n",
      bswap_64(*((u64*)ike->resp_spi)), (((unsigned char*) ike->resp_spi)[0]),
      (((unsigned char*) ike->resp_spi)[1]),
      (((unsigned char*) ike->resp_spi)[2]),
      (((unsigned char*) ike->resp_spi)[3]),
      (((unsigned char*) ike->resp_spi)[4]),
      (((unsigned char*) ike->resp_spi)[5]),
      (((unsigned char*) ike->resp_spi)[6]),
      (((unsigned char*) ike->resp_spi)[7]) );
  /*
   *smry_idx += sprintf((smry+*smry_idx)," R_SPI: %llu(0x%02x%02x%02x%02x%02x%02x%02x%02x)", bswap_64(*((u64*)ike->resp_spi)),
   (((unsigned char*)ike->resp_spi)[0]), (((unsigned char*)ike->resp_spi)[1]), (((unsigned char*)ike->resp_spi)[2]), (((unsigned char*)ike->resp_spi)[3]), (((unsigned char*)ike->resp_spi)[4]),
   (((unsigned char*)ike->resp_spi)[5]), (((unsigned char*)ike->resp_spi)[6]), (((unsigned char*)ike->resp_spi)[7]));
   */
  *smry_idx += sprintf( (smry + *smry_idx), " R_SPI: %llu(0x%llx)",
      bswap_64(*((u64*)ike->resp_spi)), bswap_64(*((u64*)ike->resp_spi)));

  if(ike->next_payload > _IKEV2_PAYLOAD_TYPE_MAX){
    printf( "next_payload : UNKNOWN(%d)\n", ike->next_payload );
  }else{
    printf( "next_payload : %s(%d)\n",
        _print_ikev2_payload_types[ike->next_payload], ike->next_payload );
  }

  printf( "ver_major : %d , ver_minor : %d\n", ike->ver_major, ike->ver_minor );

  if(ike->exchange_type > _IKEV2_EXCHANGE_TYPE_MAX){
    printf( "exchange_type : UNKNOWN(%d)\n", ike->exchange_type );
    *smry_idx += sprintf( (smry + *smry_idx), " [UNKNOWN:%d]",
        ike->exchange_type );
  }else{
    printf( "exchange_type : %s(%d)\n",
        _print_ikev2_exchange_types[ike->exchange_type], ike->exchange_type );
    *smry_idx += sprintf( (smry + *smry_idx), " [%s]",
        _print_ikev2_exchange_types[ike->exchange_type] );
  }

  printf( "flag : 0x%x [%s] [%s]\n", ike->flag,
      RHP_PROTO_IKE_HDR_INITIATOR(ike->flag) ? "Initiator" : "Responder",
      !RHP_PROTO_IKE_HDR_RESPONSE(ike->flag) ? "Request" : "Response" );
  *smry_idx += sprintf( (smry + *smry_idx), " [%s: %s]",
      RHP_PROTO_IKE_HDR_INITIATOR(ike->flag) ? "I" : "R",
      !RHP_PROTO_IKE_HDR_RESPONSE(ike->flag) ? "REQ" : "RESP" );

  printf( "message_id : %u\n", htonl( ike->message_id ) );
  *smry_idx
      += sprintf( (smry + *smry_idx), " mid:%u", htonl( ike->message_id ) );

  printf( "len : %d\n", htonl( ike->len ) );

  if( !no_payloads_print && buf_len < htonl( ike->len )){
    printf( "\n******* Invalid IKEv2 format(2) ******* .\n" );
    return -1;
  }

  if( !no_payloads_print ){

  	return _print_ikev2_payloads((u8*)(ike + 1),(buf_len - sizeof(rhp_proto_ike)),
  		iv_len,icv_len,ike->next_payload,ike,is_plain,data_len,smry_idx,smry);
  }

  return 0;
}

static int _print_udp_nat_t_sk_raw_data( u8* buf, int buf_len, int* data_len,int* smry_idx, char* smry )
{

  printf( "\n==<IKEv2 NAT-T-SK RAW DATA>==\n" );

  if( buf_len >= RHP_PROTO_NON_ESP_MARKER_SZ ){

    _rhp_bin_dump( "N ESP MKR", buf,RHP_PROTO_NON_ESP_MARKER_SZ, 1 );

    if( *((u32*)buf) == RHP_PROTO_NON_ESP_MARKER ){

    	if( buf_len >= RHP_PROTO_NON_ESP_MARKER_SZ ){

        _print_ikev2( (buf + RHP_PROTO_NON_ESP_MARKER_SZ),
        		(buf_len - RHP_PROTO_NON_ESP_MARKER_SZ), 0, 0, 0, NULL,smry_idx, smry, 1);

    	}else{
    		goto unknown_fmt;
    	}

    }else if( buf_len >= sizeof(rhp_proto_esp) ){

    	rhp_proto_esp* esph = (rhp_proto_esp*)buf;

      printf( " NATT [ESP-SK] SPI:%u(0x%x) SEQ:%u\n",ntohl(esph->spi),ntohl(esph->spi),ntohl(esph->seq));
      *smry_idx += sprintf( (smry + *smry_idx), " NATT [ESP-SK] SPI:%u(0x%x) SEQ:%u\n",ntohl(esph->spi),ntohl(esph->spi),ntohl(esph->seq));

    }else{
  		goto unknown_fmt;
    }

  }else if( buf_len == 1 && *buf == 0xFF ){	// NAT-T Keep alive

    printf( " NATT [IKEv2-SK] NAT-T Keep-Alive\n" );
    *smry_idx += sprintf( (smry + *smry_idx), " NATT [IKEv2-RAW] NAT-T Keep-Alive buf_len:%d",buf_len);

  }else{

unknown_fmt:
  	printf( " NATT [IKEv2-SK] Unknown packet format.\n" );
    *smry_idx += sprintf( (smry + *smry_idx), " NATT [IKEv2-RAW] Unknown packet format. buf_len:%d", buf_len);
  }

  if(data_len){
    *data_len += buf_len;
  }

  return 0;
}


static int _print_udp_sk_raw_data( u8* buf, int buf_len, int* data_len,int* smry_idx, char* smry )
{

  printf( "\n==<IKEv2 SK RAW DATA>==\n" );

  if( buf_len >= sizeof(rhp_proto_ike) ){

  	_print_ikev2( buf, buf_len, 0, 0, 0, NULL,smry_idx, smry, 1);

  }else if( buf_len == 1 && *buf == 0xFF ){	// NAT-T Keep alive

    printf( " [IKEv2-SK] NAT-T Keep-Alive\n" );
    *smry_idx += sprintf( (smry + *smry_idx), " [IKEv2-SK] NAT-T Keep-Alive buf_len:%d",buf_len);

  }else{

  	printf( " [IKEv2-SK] Unknown packet format.\n" );
    *smry_idx += sprintf( (smry + *smry_idx), " [IKEv2-SK] Unknown packet format. buf_len:%d", buf_len);
  }

  if(data_len){
    *data_len += buf_len;
  }

  return 0;
}

static int _print_esp_sk_raw_data( u8* buf, int buf_len, int* data_len,int* smry_idx, char* smry )
{

  printf( "\n==<ESP SK RAW DATA>==\n" );

  if( buf_len >= sizeof(rhp_proto_esp) ){

  	rhp_proto_esp* esph = (rhp_proto_esp*)buf;

    printf( " [ESP-SK] SPI:%u(0x%x) SEQ:%u\n",ntohl(esph->spi),ntohl(esph->spi),ntohl(esph->seq));
    *smry_idx += sprintf( (smry + *smry_idx), " [ESP-SK] SPI:%u(0x%x) SEQ:%u\n",ntohl(esph->spi),ntohl(esph->spi),ntohl(esph->seq));

  }else{

  	printf( " [ESP-SK] Unknown packet format.\n" );
    *smry_idx += sprintf( (smry + *smry_idx), " [ESP-SK] Unknown packet format. buf_len:%d", buf_len);
  }

  if(data_len){
    *data_len += buf_len;
  }

  return 0;
}


#define RHP_TRC_TKN_UNKNOWN 					0
#define RHP_TRC_TKN_X       					1
#define RHP_TRC_TKN_D       					2
#define RHP_TRC_TKN_U       					3
#define RHP_TRC_TKN_P       					4
#define RHP_TRC_TKN_M       					5
#define RHP_TRC_TKN_S       					6
#define RHP_TRC_TKN_A									7
#define RHP_TRC_TKN_B_Y								8
#define RHP_TRC_TKN_4									9
#define RHP_TRC_TKN_6									10
#define RHP_TRC_TKN_B_E								11
#define RHP_TRC_TKN_B_M								12
#define RHP_TRC_TKN_B_B								13
#define RHP_TRC_TKN_G									14
#define RHP_TRC_TKN_H									15
#define RHP_TRC_TKN_T									16
#define RHP_TRC_TKN_T_EPOC						17


static char _fmt_a_smry_fmt[2048];


static int _translate_trace_token( struct user_tag *u_tag, xmlChar **f,
    unsigned char **b, unsigned long *b_len, unsigned char* record,
    unsigned char* record_end, char* fmt_hdr )
{
  xmlChar *c = *f;
  unsigned char *d = *b;
  unsigned long d_len = *b_len;
  unsigned int token_t = RHP_TRC_TKN_UNKNOWN;
  unsigned int token_n = 0;
  unsigned int token_t_tmp = RHP_TRC_TKN_UNKNOWN;
  xmlChar *tkn_sym_head = NULL, *tkn_sym_tail = NULL;
  int badchar_flag = 0;
  int i;

  c++; // '%'

  while(*c != '\0' && token_t == RHP_TRC_TKN_UNKNOWN){

    if(token_t_tmp != RHP_TRC_TKN_M && token_t_tmp != RHP_TRC_TKN_B_B
        && token_t_tmp != RHP_TRC_TKN_A){

      if(*c == 's'){

        token_t = RHP_TRC_TKN_S;

      }else if(*c == 'p'){

        if(d_len < (sizeof(unsigned int) + sizeof(unsigned int))){
          goto error;
        }

        token_n = sizeof(unsigned int) + sizeof(unsigned int)
            + *((unsigned int*) d);
        token_t = RHP_TRC_TKN_P;

      }else if(*c == 'b'){
        token_n = 1;
      }else if(*c == 'w'){
        token_n = 2;
      }else if(*c == 'd'){
        token_n = 4;
      }else if(*c == 'q'){
        token_n = 8;
      }else if(*c == 'l'){
        token_n = sizeof(unsigned long);
      }else if(*c == 'x'){

        if(token_n == 0){
          token_n = sizeof(unsigned long);
        }
        token_t = RHP_TRC_TKN_X;

      }else if(*c == 'i'){

        if(token_n == 0){
          token_n = 4;
        }
        token_t = RHP_TRC_TKN_D;

      }else if(*c == 'u'){

        if(token_n == 0){
          token_n = sizeof(unsigned long);
        }
        token_t = RHP_TRC_TKN_U;

      }else if(*c == 'm'){

        if(token_n == 0){
          token_n = sizeof(unsigned long);
        }
        token_t_tmp = RHP_TRC_TKN_M;

      }else if(*c == 'B'){

        if(d_len < sizeof(unsigned int)){
          goto error;
        }
        token_n = sizeof(unsigned int) + *((unsigned int*) d);
        token_t_tmp = RHP_TRC_TKN_B_B;

      }else if(*c == 'Y'){

        token_n = sizeof(unsigned long);
        token_t = RHP_TRC_TKN_B_Y;

      }else if(*c == '4'){

        token_n = 4;
        token_t = RHP_TRC_TKN_4;

      }else if(*c == '6'){

        token_n = 16;
        token_t = RHP_TRC_TKN_6;

      }else if(*c == 'E'){

        token_n = 4;
        token_t = RHP_TRC_TKN_B_E;

      }else if(*c == 'M'){

        token_n = 6;
        token_t = RHP_TRC_TKN_B_M;

      }else if(*c == 'G'){

        token_n = 8;
        token_t = RHP_TRC_TKN_G;

      }else if(*c == 'H'){

        token_n = 4;
        token_t = RHP_TRC_TKN_H;

      }else if(*c == 't'){

        token_n = sizeof(time_t)*2;
        token_t = RHP_TRC_TKN_T;

      }else if(*c == 'T'){

        token_n = sizeof(time_t);
        token_t = RHP_TRC_TKN_T_EPOC;

      }else if(*c == 'a'){

        if(d_len < sizeof(unsigned int) + sizeof(unsigned int)
            + sizeof(unsigned int) + sizeof(unsigned int)){
          goto error;
        }
        token_n = sizeof(unsigned int) + sizeof(unsigned int)
            + sizeof(unsigned int) + sizeof(unsigned int)
            + *((unsigned int*) d);

        if( *(((unsigned int*)d) + 1) == RHP_TRC_FMT_A_IKEV2_PLAIN_PAYLOADS ){
        	token_n += sizeof(unsigned char);
        }

        token_t = RHP_TRC_TKN_A;

      }else{
        goto ignore;
      }

    }else{

      if(*c == '['){

        if((token_t_tmp == RHP_TRC_TKN_M || token_t_tmp == RHP_TRC_TKN_B_B)
            && token_n > 0){
          tkn_sym_head = c;
        }else{
          goto ignore;
        }

      }else if(*c == ']'){

        if(tkn_sym_head && (tkn_sym_head + 1) != c && token_n > 0){

          if(token_t_tmp == RHP_TRC_TKN_M){

            tkn_sym_tail = c;
            token_t = RHP_TRC_TKN_M;

          }else if(token_t_tmp == RHP_TRC_TKN_B_B){

            tkn_sym_tail = c;
            token_t = RHP_TRC_TKN_B_B;

          }else{
            goto ignore;
          }

        }else{
          goto ignore;
        }

      }else{
        goto next;
      }
    }

    next: c++;
  }

  if(token_t == RHP_TRC_TKN_UNKNOWN){
    goto ignore;
  }

  if(d_len < token_n){
    printf( "Bad Token length(1) : %lu , %d\n", d_len, token_n );
    _rhp_bin_dump("Bad Token length(1)",d,(d_len > token_n ? d_len : token_n),1);
    goto error;
  }

  if((d + token_n) > record_end || record > (d + token_n)){
    printf( "Bad Token length(2) : %lu , %d\n", d_len, token_n );
    _rhp_bin_dump("Bad Token length(2)",d,(d_len > token_n ? d_len : token_n),1);
    goto error;
  }

  switch(token_t){

  case RHP_TRC_TKN_S:

    badchar_flag = 0;
    while(d_len && *d != '\0'){

    	if( *d == '\t' ){
        printf( "[\\t]");
    	}else if( *d == '\r' ){
        printf( "[\\r]");
    	}else if( *d == '\n' ){
        printf( "[\\n]");
    	}else if( *d == '\0' ){
        printf( "[\\0]");
    	}else if( *d == '\f' ){
        printf( "[\\f]");
    	}

      if((*d >= 32 && *d <= 126) || *d == '\n' || *d == '\0' || *d == '\r'
          || *d == '\t' || *d == '\f' ){
        printf( "%c", *((unsigned char*) d) );
      }else{
        printf( "[0x%x]", (*d & 0x000000FF) );
        badchar_flag++;
      }

      d_len--;
      d++;
    }

    if(badchar_flag){
      printf( "  ##Bad char code?## %d found. ", badchar_flag );
    }

    d_len--; // For '\0'
    d++;
    break;

  case RHP_TRC_TKN_X:

    if(token_n == 1){
      printf( "0x%x", (*((unsigned int*) d) & 0x000000FF) );
    }else if(token_n == 2){
      printf( "0x%hx", (*((unsigned short*) d) & 0x0000FFFF) );
    }else if( token_n == 4 || token_n == sizeof(unsigned long) ){
      printf( "0x%x", (*((unsigned int*) d) & 0xFFFFFFFF) );
    }else if(token_n == 8){
      printf( "0x%llx", *((unsigned long long*) d) );
    }else{
      goto error;
    }

    d += token_n;
    d_len -= token_n;
    break;

  case RHP_TRC_TKN_B_Y:

    if( token_n == sizeof(unsigned long) ){
      printf( "##FUNC_ADDR_START##0x%x##FUNC_ADDR_END##", (*((unsigned int*) d)
          & 0xFFFFFFFF) );
    }else{
      goto error;
    }

    d += token_n;
    d_len -= token_n;
    break;

  case RHP_TRC_TKN_B_E:

    if(token_n == 4){

      int err = (*((int*) d) & 0xFFFFFFFF);
      char* mm_tkn;
      struct label_tag *label = NULL;
      struct label_item_tag * item = NULL;

#define RHP_TRC_UTIL_TKN_B_E_ERROR			"ERROR"
#define RHP_TRC_UTIL_TKN_B_E_RHP_ERROR	"RHP_ERROR"

      if(err < 0){
        mm_tkn = RHP_TRC_UTIL_TKN_B_E_ERROR;
      }else{
        mm_tkn = RHP_TRC_UTIL_TKN_B_E_RHP_ERROR;
      }

      label = u_tag->label_list_head;
      while(label){

        if((!xmlStrcmp( label->name, (const xmlChar *) mm_tkn ))){
          break;
        }

        label = label->next;
      }

      if(label){

        item = label->item_list_head;

        while(item){

          int err2 = (err < 0 ? -err : err);

          if((item->value & 0xFFFFFFFF) == err2 && item->label){
            break;
          }

          item = item->next;
        }
      }

      if(item){
        if(err < 0){
          printf( "%d(%s : %s)", err, item->label, strerror( -err ) );
        }else{
          printf( "%d(%s)", err, item->label );
        }
      }else{
        if(err < 0){
          printf( "%d(%s : %s)", err, "UNKNOWN", strerror( -err ) );
        }else{
          printf( "%d(%s)", err, "UNKNOWN" );
        }
      }

    }else{
      printf( "UNKNOWN ERROR VALUE : %d(Bad Length??? : %d)", (*((int*) d)
          & 0xFFFFFFFF), token_n );
    }

    d += token_n;
    d_len -= token_n;
    break;

  case RHP_TRC_TKN_4:

    if(token_n == 4){
      printf( "%d.%d.%d.%d", (((unsigned char*) d)[0]),
          (((unsigned char*) d)[1]), (((unsigned char*) d)[2]),
          (((unsigned char*) d)[3]) );
    }else{
      goto error;
    }

    d += token_n;
    d_len -= token_n;
    break;

  case RHP_TRC_TKN_6:
    if(token_n == 16){
/*
      printf(
          "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
          (((unsigned char*) d)[0]), (((unsigned char*) d)[1]),
          (((unsigned char*) d)[2]), (((unsigned char*) d)[3]),
          (((unsigned char*) d)[4]), (((unsigned char*) d)[5]),
          (((unsigned char*) d)[6]), (((unsigned char*) d)[7]),
          (((unsigned char*) d)[8]), (((unsigned char*) d)[9]),
          (((unsigned char*) d)[10]), (((unsigned char*) d)[11]),
          (((unsigned char*) d)[12]), (((unsigned char*) d)[13]),
          (((unsigned char*) d)[14]), (((unsigned char*) d)[15]) );
*/

      printf("%s",_rhp_ipv6_string((unsigned char*)d));

    }else{
      goto error;
    }

    d += token_n;
    d_len -= token_n;
    break;

  case RHP_TRC_TKN_G:

    if(token_n == 8){
      /*
       printf("%llu(0x%02x%02x%02x%02x%02x%02x%02x%02x, (LE)%llu, %llx)",
       bswap_64(*(u64*)d),
       (((unsigned char*)d)[0]), (((unsigned char*)d)[1]), (((unsigned char*)d)[2]), (((unsigned char*)d)[3]), (((unsigned char*)d)[4]),
       (((unsigned char*)d)[5]), (((unsigned char*)d)[6]), (((unsigned char*)d)[7]),
       *((u64*)d),*((u64*)d));
       */
      printf( "%llu(0x%02x%02x%02x%02x%02x%02x%02x%02x)", bswap_64(*(u64*)d),
          (((unsigned char*) d)[0]), (((unsigned char*) d)[1]),
          (((unsigned char*) d)[2]), (((unsigned char*) d)[3]),
          (((unsigned char*) d)[4]), (((unsigned char*) d)[5]),
          (((unsigned char*) d)[6]), (((unsigned char*) d)[7]) );
    }else{
      goto error;
    }

    d += token_n;
    d_len -= token_n;
    break;

  case RHP_TRC_TKN_H:

    if(token_n == 4){
      /*
       printf("%u(0x%02x%02x%02x%02x, (LE)%u, 0x%x)",ntohl(*((u32*)d)),
       (((unsigned char*)d)[0]), (((unsigned char*)d)[1]), (((unsigned char*)d)[2]), (((unsigned char*)d)[3]),
       *((u32*)d),*((u32*)d));
       */
      printf( "%u(0x%02x%02x%02x%02x)", ntohl( *((u32*) d) ),
          (((unsigned char*) d)[0]), (((unsigned char*) d)[1]),
          (((unsigned char*) d)[2]), (((unsigned char*) d)[3]) );
    }else{
      goto error;
    }

    d += token_n;
    d_len -= token_n;
    break;

  case RHP_TRC_TKN_T:

  	if(token_n == sizeof(time_t)*2 ){

  		time_t rt = *((time_t*)(d + sizeof(time_t)));
			struct tm ts;
			char time_epoc_str[64];

			time_epoc_str[0] = '\0';
			localtime_r(&rt,&ts);

			snprintf(time_epoc_str,64,"%d-%02d-%02d %02d:%02d:%02d",
					ts.tm_year + 1900,ts.tm_mon + 1, ts.tm_mday, ts.tm_hour, ts.tm_min, ts.tm_sec);

			if(token_n == 8 ){
				printf( "%d(RT: %d - %s)", *((time_t*)d),rt,time_epoc_str);
			}else if(token_n == 16 ){
				printf( "%ld(RT: %ld - %s)", *((time_t*)d),rt,time_epoc_str);
			}else{
				goto error;
			}

  	}else{
      goto error;
  	}

		d += token_n;
		d_len -= token_n;
  	break;

  case RHP_TRC_TKN_T_EPOC:

  	if(token_n == sizeof(time_t)){

			struct tm ts;
			char time_epoc_str[64];

			time_epoc_str[0] = '\0';
			localtime_r((time_t*)d,&ts);

			snprintf(time_epoc_str,64,"%d-%02d-%02d %02d:%02d:%02d",
					ts.tm_year + 1900,ts.tm_mon + 1, ts.tm_mday, ts.tm_hour, ts.tm_min, ts.tm_sec);

	    if(token_n == 4 ){
	    	printf( "%d(%s)", *((time_t*)d),time_epoc_str);
	    }else if(token_n == 8 ){
	    	printf( "%ld(%s)", *((time_t*)d),time_epoc_str);
	    }

		}else{
      goto error;
    }

    d += token_n;
    d_len -= token_n;
    break;

  case RHP_TRC_TKN_B_M:

    if(token_n == 6){
      printf( "%02x:%02x:%02x:%02x:%02x:%02x", (((unsigned char*) d)[0]),
          (((unsigned char*) d)[1]), (((unsigned char*) d)[2]),
          (((unsigned char*) d)[3]), (((unsigned char*) d)[4]),
          (((unsigned char*) d)[5]) );
    }else{
      goto error;
    }

    d += token_n;
    d_len -= token_n;
    break;

  case RHP_TRC_TKN_D:

    if(token_n == 1){
      printf( "%d", (*((unsigned int*) d) & 0x000000FF) );
    }else if(token_n == 2){
      printf( "%hd", (*((unsigned short*) d) & 0x0000FFFF) );
    }else if(token_n == 4){
      printf( "%d", (*((unsigned int*) d) & 0xFFFFFFFF) );
    }else if(token_n == 8){
      printf( "%lld", *((unsigned long long*) d) );
    }else{
      goto error;
    }

    d += token_n;
    d_len -= token_n;
    break;

  case RHP_TRC_TKN_U:

    if(token_n == 1){
      printf( "%u", (*((unsigned int*) d) & 0x000000FF) );
    }else if(token_n == 2){
      printf( "%hu", (*((unsigned short*) d) & 0x0000FFFF) );
    }else if(token_n == 4){
      printf( "%u", (*((unsigned int*) d) & 0xFFFFFFFF) );
    }else if(token_n == 8){
      printf( "%llu", *((unsigned long long*) d) );
    }else{
      goto error;
    }

    d += token_n;
    d_len -= token_n;
    break;

  case RHP_TRC_TKN_P:

  {
    unsigned int ptr = *((unsigned int*) (d + sizeof(unsigned int))); // TODO : Driver's API

    _rhp_bin_dump_impl( NULL, ptr, (d + sizeof(unsigned int)
        + sizeof(unsigned int)), (token_n - sizeof(unsigned int)
        - sizeof(unsigned int)), 1 );

    d += token_n;
    d_len -= token_n;
  }
    break;

  case RHP_TRC_TKN_M: {
    struct label_tag *label = NULL;
    struct label_item_tag * item = NULL;

    if(tkn_sym_head == NULL || tkn_sym_tail == NULL){
      goto error;
    }

    *tkn_sym_tail = '\0';
    tkn_sym_head++;

    label = u_tag->label_list_head;
    while(label){

      if((!xmlStrcmp( label->name, (const xmlChar *) tkn_sym_head ))){
        break;
      }

      label = label->next;
    }

    if(label){

      item = label->item_list_head;

      while(item){

        if(token_n == 1){

          if((item->value & 0x000000FF) == *((u8*) d) && item->label){
            printf( "%s(%d)", item->label, (*((u8*) d) & 0x000000FF) );
            break;
          }

        }else if(token_n == 2){

          if((item->value & 0x0000FFFF) == *((u16*) d) && item->label){
            printf( "%s(%hd)", item->label, *((u8*) d) );
            break;
          }

        }else if(token_n == 4){

          if((item->value & 0xFFFFFFFF) == *((u32*) d) && item->label){
            printf( "%s(%d)", item->label, *((u32*) d) );
            break;
          }

        }else if(token_n == 8){

          if(item->value == *((u64*) d) && item->label){
            printf( "%s(%lld)", item->label, *((u64*) d) );
            break;
          }
        }

        item = item->next;
      }
    }

    if(label == NULL || item == NULL){

      if(token_n == 1){
        printf( "%d", (*((unsigned int*) d) & 0x000000FF) );
      }else if(token_n == 2){
        printf( "%hd", (*((unsigned short*) d) & 0x0000FFFF) );
      }else if(token_n == 4){
        printf( "%d", (*((unsigned int*) d) & 0xFFFFFFFF) );
      }else if(token_n == 8){
        printf( "%lld", *((unsigned long long*) d) );
      }else{
        goto error;
      }
    }

    d += token_n;
    d_len -= token_n;
  }

    *tkn_sym_tail = ']';
    tkn_sym_head--;

    break;

  case RHP_TRC_TKN_B_B: {
    struct bit_tag *bit = NULL;
    struct bit_item_tag * bit_item = NULL;

    if(tkn_sym_head == NULL || tkn_sym_tail == NULL){
      goto error;
    }

    *tkn_sym_tail = '\0';
    tkn_sym_head++;

    bit = u_tag->bit_list_head;
    while(bit){

      if((!xmlStrcmp( bit->name, (const xmlChar *) tkn_sym_head ))){
        break;
      }

      bit = bit->next;
    }

    if(token_n == 1){

      printf( "0x%x", (*((u8*) d) & 0x000000FF) );

      printf( "[" );
      for(i = 1; i <= token_n * 8; i++){
        printf( "%d", (*((u8*) d) & (u8) (1 << (i - 1)) ? 1 : 0) );
      }
      printf( "](2)\n" );

    }else if(token_n == 2){

      printf( "0x%hx", (*((u16*) d) & 0x0000FFFF) );

      printf( "[" );
      for(i = 1; i <= token_n * 8; i++){
        printf( "%d", (*((u16*) d) & (u16) (1 << (i - 1)) ? 1 : 0) );
      }
      printf( "](2)\n" );

    }else if(token_n == 4){

      printf( "0x%x", (*((u32*) d) & 0xFFFFFFFF) );

      printf( "[" );
      for(i = 1; i <= token_n * 8; i++){
        printf( "%d", (*((u32*) d) & (u32) (1 << (i - 1)) ? 1 : 0) );
      }
      printf( "](2)\n" );

    }else if(token_n == 8){

      printf( "0x%llx", *((u64*) d) );

      printf( "[" );
      for(i = 1; i <= token_n * 8; i++){
        printf( "%d", (*((u64*) d) & (u64) (1 << (i - 1)) ? 1 : 0) );
      }
      printf( "](2)\n" );

    }else{
      goto error;
    }

    for(i = 1; i <= token_n * 8; i++){

      if(bit){

        bit_item = bit->item_list_head;
        int defined = 0;

        while(bit_item){

          if(token_n == 1){

            if((bit_item->value & 0x000000FF) == i){

              if(bit_item->label){
                printf( "[%d] %s(%d)\n", i, bit_item->label, (*((u8*) d)
                    & (u8) (1 << (i - 1)) ? 1 : 0) );
              }else{
                printf( "[%d] NOT_DEFINED(%d)\n", i, (*((u8*) d) & (u8) (1
                    << (i - 1)) ? 1 : 0) );
              }
              defined = 1;
              break;
            }

          }else if(token_n == 2){

            if((bit_item->value & 0x0000FFFF) == i){
              if(bit_item->label){
                printf( "[%d] %s(%d)\n", i, bit_item->label, (*((u16*) d)
                    & (u16) (1 << (i - 1)) ? 1 : 0) );
              }else{
                printf( "[%d] NOT_DEFINED(%d)\n", i, (*((u16*) d) & (u16) (1
                    << (i - 1)) ? 1 : 0) );
              }
              defined = 1;
              break;
            }

          }else if(token_n == 4){

            if((bit_item->value & 0xFFFFFFFF) == i){

              if(bit_item->label){
                printf( "[%d] %s(%d)\n", i, bit_item->label, (*((u32*) d)
                    & (u32) (1 << (i - 1)) ? 1 : 0) );
              }else{
                printf( "[%d] NOT_DEFINED(%d)\n", i, (*((u32*) d) & (u32) (1
                    << (i - 1)) ? 1 : 0) );
              }
              defined = 1;
              break;
            }

          }else if(token_n == 8){

            if(bit_item->value == i){

              if(bit_item->label){
                printf( "[%d] %s(%d)\n", i, bit_item->label, (*((u64*) d)
                    & (u64) (1 << (i - 1)) ? 1 : 0) );
              }else{
                printf( "[%d] NOT_DEFINED(%d)\n", i, (*((u64*) d) & (u64) (1
                    << (i - 1)) ? 1 : 0) );
              }
              defined = 1;
              break;
            }
          }

          bit_item = bit_item->next;
        }

        if(!defined){
          goto not_defined;
        }

      }else{

        not_defined: if(token_n == 1){
          printf( "[%d] NOT_DEFINED(%d)\n", i, (*((u8*) d)
              & (u8) (1 << (i - 1)) ? 1 : 0) );
        }else if(token_n == 2){
          printf( "[%d] NOT_DEFINED(%d)\n", i, (*((u16*) d) & (u16) (1 << (i
              - 1)) ? 1 : 0) );
        }else if(token_n == 4){
          printf( "[%d] NOT_DEFINED(%d)\n", i, (*((u32*) d) & (u32) (1 << (i
              - 1)) ? 1 : 0) );
        }else if(token_n == 8){
          printf( "[%d] NOT_DEFINED(%d)\n", i, (*((u64*) d) & (u64) (1 << (i
              - 1)) ? 1 : 0) );
        }
      }
    }

    d += token_n;
    d_len -= token_n;

    *tkn_sym_tail = ']';
    tkn_sym_head--;
  }

    break;

  case RHP_TRC_TKN_A:
  {
    unsigned char *a_sp, *a_sp2;
    int a_sp_len, a_iv_len, a_icv_len, a_sp_len2, rem, a_proto_type;
    char* smry_fmt = _fmt_a_smry_fmt;
    int smry_fmt_idx;
    unsigned char next_payload = 0;
    int a_apdx_len = 0;

    a_proto_type = *((int*) (d + sizeof(unsigned int)));
    a_iv_len = *((int*) (d + sizeof(unsigned int) + sizeof(unsigned int)));
    a_icv_len = *((int*) (d + sizeof(unsigned int) + sizeof(unsigned int) + sizeof(unsigned int)));

    if( a_proto_type == RHP_TRC_FMT_A_IKEV2_PLAIN_PAYLOADS ){
    	next_payload = *((int*) (d + sizeof(unsigned int) + sizeof(unsigned int) + sizeof(unsigned int) + sizeof(unsigned int)));
    	a_apdx_len += sizeof(unsigned char);
    }

    a_sp = (d + sizeof(unsigned int) + sizeof(unsigned int) + sizeof(unsigned int) + sizeof(unsigned int) + a_apdx_len);
    a_sp_len = (token_n - sizeof(unsigned int) - sizeof(unsigned int) - sizeof(unsigned int) - sizeof(unsigned int) - a_apdx_len);

    printf( "PROTO: %d , IV LEN:%d , ICV LEN:%d , DATA LEN:%d\n", a_proto_type,a_iv_len, a_icv_len, a_sp_len );

    switch(a_proto_type){

    case RHP_TRC_FMT_A_MAC:

      smry_fmt[0] = '\0';
      smry_fmt_idx = 0;

      _print_mac( a_sp, a_sp_len, NULL, &smry_fmt_idx, smry_fmt, NULL);
      break;

    case RHP_TRC_FMT_A_IPV4:

      smry_fmt[0] = '\0';
      smry_fmt_idx = 0;

      _print_ipv4( a_sp, a_sp_len, NULL, NULL, &smry_fmt_idx, smry_fmt );
      break;

    case RHP_TRC_FMT_A_UDP:

      smry_fmt[0] = '\0';
      smry_fmt_idx = 0;

      _print_udp( a_sp, a_sp_len, NULL, 0, &smry_fmt_idx, smry_fmt );
      break;

    case RHP_TRC_FMT_A_ESP:

      smry_fmt[0] = '\0';
      smry_fmt_idx = 0;

      _print_esp( a_sp, a_sp_len, a_iv_len, a_icv_len, NULL, &smry_fmt_idx,
          smry_fmt );
      break;

    case RHP_TRC_FMT_A_IKEV2:

      smry_fmt[0] = '\0';
      smry_fmt_idx = 0;

      _print_ikev2( a_sp, a_sp_len, a_iv_len, a_icv_len, 0, NULL,
          &smry_fmt_idx, smry_fmt, 0 );
      break;

    case RHP_TRC_FMT_A_IKEV2_PLAIN:

      smry_fmt[0] = '\0';
      smry_fmt_idx = 0;

      _print_ikev2( a_sp, a_sp_len, a_iv_len, a_icv_len, 1, NULL,
          &smry_fmt_idx, smry_fmt, 0 );
      break;

    case RHP_TRC_FMT_A_IKEV2_PLAIN_PAYLOADS:

      smry_fmt[0] = '\0';
      smry_fmt_idx = 0;

      _print_ikev2_payloads( a_sp, a_sp_len, a_iv_len, a_icv_len,next_payload,NULL,1, NULL, &smry_fmt_idx, smry_fmt );

      printf( "\n[TRF](IKEv2 Payloads) %s  %s\n", fmt_hdr, smry_fmt );
      break;

    case RHP_TRC_FMT_A_FROM_MAC_RAW: {
      u16 ether_type = 0;
      u8 protocol = 0;
      a_sp2 = a_sp;
      rem = a_sp_len;

      smry_fmt[0] = '\0';
      smry_fmt_idx = 0;

      _print_mac( a_sp2, rem, &a_sp_len2, &smry_fmt_idx, smry_fmt, &ether_type );
      a_sp2 += a_sp_len2;
      rem -= a_sp_len2;

      if(ether_type == RHP_PROTO_ETH_IP){

        _print_ipv4( a_sp2, rem, &a_sp_len2, &protocol, &smry_fmt_idx, smry_fmt );
        a_sp2 += a_sp_len2;
        rem -= a_sp_len2;

        switch(protocol){

        case RHP_PROTO_IP_ICMP:

          _print_icmp( a_sp2, rem, &a_sp_len2, &smry_fmt_idx, smry_fmt );
          a_sp2 += a_sp_len2;
          rem -= a_sp_len2;
          break;

        case RHP_PROTO_IP_UDP:
        case RHP_PROTO_IP_UDPLITE:

          _print_udp( a_sp2, rem, &a_sp_len2, 0, &smry_fmt_idx, smry_fmt );
          a_sp2 += a_sp_len2;
          rem -= a_sp_len2;
          break;

        case RHP_PROTO_IP_TCP:

          _print_tcp( a_sp2, rem, &a_sp_len2, &smry_fmt_idx, smry_fmt );
          a_sp2 += a_sp_len2;
          rem -= a_sp_len2;
          break;

        default:
          break;
        }

      }else if(ether_type == RHP_PROTO_ETH_ARP){

        _print_arp( a_sp2, rem, &a_sp_len2, &smry_fmt_idx, smry_fmt );
        a_sp2 += a_sp_len2;
        rem -= a_sp_len2;

      }else if(ether_type == RHP_PROTO_ETH_IPV6){

      	int pld_len = 0;

        _print_ipv6( a_sp2, rem, &a_sp_len2, &protocol, &smry_fmt_idx, smry_fmt, &pld_len );
        a_sp2 += a_sp_len2;
        rem -= a_sp_len2;

        switch(protocol){

        case RHP_PROTO_IP_IPV6_ICMP:

          _print_icmp6( a_sp2, rem, &a_sp_len2, &smry_fmt_idx, smry_fmt, pld_len );
          a_sp2 += a_sp_len2;
          rem -= a_sp_len2;
          break;

        case RHP_PROTO_IP_UDP:
        case RHP_PROTO_IP_UDPLITE:

          _print_udp( a_sp2, rem, &a_sp_len2, 0, &smry_fmt_idx, smry_fmt );
          a_sp2 += a_sp_len2;
          rem -= a_sp_len2;
          break;

        case RHP_PROTO_IP_TCP:

          _print_tcp( a_sp2, rem, &a_sp_len2, &smry_fmt_idx, smry_fmt );
          a_sp2 += a_sp_len2;
          rem -= a_sp_len2;
          break;

        default:
          break;
        }

      }else{

        smry_fmt_idx += sprintf( (smry_fmt + smry_fmt_idx),
            " EtherType: %d, 0x%x", ether_type, ether_type );
      }

      printf( "\n[TRF](RAW) %s  %s\n", fmt_hdr, smry_fmt );
    }
      break;

    case RHP_TRC_FMT_A_MAC_IPV4_ESP:
    {
      u8 protocol = 0;
      a_sp2 = a_sp;
      rem = a_sp_len;

      smry_fmt[0] = '\0';
      smry_fmt_idx = 0;

      _print_mac( a_sp2, rem, &a_sp_len2, &smry_fmt_idx, smry_fmt, NULL);
      a_sp2 += a_sp_len2;
      rem -= a_sp_len2;

      _print_ipv4( a_sp2, rem, &a_sp_len2, &protocol, &smry_fmt_idx, smry_fmt );
      a_sp2 += a_sp_len2;
      rem -= a_sp_len2;

      if(protocol == RHP_PROTO_IP_UDP){
        _print_udp( a_sp2, rem, &a_sp_len2, 1, &smry_fmt_idx, smry_fmt );
        a_sp2 += a_sp_len2;
        rem -= a_sp_len2;
      }

      _print_esp( a_sp2, rem, a_iv_len, a_icv_len, NULL, &smry_fmt_idx,smry_fmt );

      printf( "\n[TRF](ESP) %s  %s\n", fmt_hdr, smry_fmt );
    }
      break;

    case RHP_TRC_FMT_A_MAC_IPV4_IKEV2:
    {
      a_sp2 = a_sp;
      rem = a_sp_len;

      smry_fmt[0] = '\0';
      smry_fmt_idx = 0;

      _print_mac( a_sp2, rem, &a_sp_len2, &smry_fmt_idx, smry_fmt, NULL);
      a_sp2 += a_sp_len2;
      rem -= a_sp_len2;

      _print_ipv4( a_sp2, rem, &a_sp_len2, NULL, &smry_fmt_idx, smry_fmt );
      a_sp2 += a_sp_len2;
      rem -= a_sp_len2;

      _print_udp( a_sp2, rem, &a_sp_len2, 1, &smry_fmt_idx, smry_fmt );
      a_sp2 += a_sp_len2;
      rem -= a_sp_len2;

      _print_ikev2( a_sp2, rem, a_iv_len, a_icv_len, 0, NULL, &smry_fmt_idx,
          smry_fmt, 0 );

      printf( "\n[TRF](IKEv2) %s  %s\n", fmt_hdr, smry_fmt );
    }
      break;

    case RHP_TRC_FMT_A_MAC_IPV4_IKEV2_PLAIN:
    {
      a_sp2 = a_sp;
      rem = a_sp_len;

      smry_fmt[0] = '\0';
      smry_fmt_idx = 0;

      _print_mac( a_sp2, rem, &a_sp_len2, &smry_fmt_idx, smry_fmt, NULL);
      a_sp2 += a_sp_len2;
      rem -= a_sp_len2;

      _print_ipv4( a_sp2, rem, &a_sp_len2, NULL, &smry_fmt_idx, smry_fmt );
      a_sp2 += a_sp_len2;
      rem -= a_sp_len2;

      _print_udp( a_sp2, rem, &a_sp_len2, 1, &smry_fmt_idx, smry_fmt );
      a_sp2 += a_sp_len2;
      rem -= a_sp_len2;

      _print_ikev2( a_sp2, rem, a_iv_len, a_icv_len, 1, NULL, &smry_fmt_idx,
          smry_fmt, 0 );

      printf( "\n[TRF](IKEv2_P) %s  %s\n", fmt_hdr, smry_fmt );
    }
      break;


    case RHP_TRC_FMT_A_MAC_IPV4_NAT_T_KEEPALIVE:
    {
      a_sp2 = a_sp;
      rem = a_sp_len;

      smry_fmt[0] = '\0';
      smry_fmt_idx = 0;

      _print_mac( a_sp2, rem, &a_sp_len2, &smry_fmt_idx, smry_fmt, NULL);
      a_sp2 += a_sp_len2;
      rem -= a_sp_len2;

      _print_ipv4( a_sp2, rem, &a_sp_len2, NULL, &smry_fmt_idx, smry_fmt );
      a_sp2 += a_sp_len2;
      rem -= a_sp_len2;

      _print_udp( a_sp2, rem, &a_sp_len2, 1, &smry_fmt_idx, smry_fmt );
      a_sp2 += a_sp_len2;
      rem -= a_sp_len2;

      _print_ikev2_nat_t_keepalive( a_sp2, rem, &a_sp_len2, 1, &smry_fmt_idx, smry_fmt );

      printf( "\n[TRF](NAT-T-KA) %s  %s\n", fmt_hdr, smry_fmt );
    }
      break;

    case RHP_TRC_FMT_A_IKEV2_UDP_SK: {
      a_sp2 = a_sp;
      rem = a_sp_len;

      smry_fmt[0] = '\0';
      smry_fmt_idx = 0;

      _print_udp_sk_raw_data( a_sp2, rem, &a_sp_len2, &smry_fmt_idx, smry_fmt );

      printf( "\n[TRF](SK-IKEv2) %s  %s\n", fmt_hdr, smry_fmt );
    }
      break;

    case RHP_TRC_FMT_A_IKEV2_NAT_T_UDP_SK: {
      a_sp2 = a_sp;
      rem = a_sp_len;

      smry_fmt[0] = '\0';
      smry_fmt_idx = 0;

      _print_udp_nat_t_sk_raw_data( a_sp2, rem, &a_sp_len2, &smry_fmt_idx, smry_fmt );

      printf( "\n[TRF](SK-IKEv2-NAT-T) %s  %s\n", fmt_hdr, smry_fmt );
    }
      break;

    case RHP_TRC_FMT_A_ESP_RAW_SK: {
      a_sp2 = a_sp;
      rem = a_sp_len;

      smry_fmt[0] = '\0';
      smry_fmt_idx = 0;

      _print_esp_sk_raw_data( a_sp2, rem, &a_sp_len2, &smry_fmt_idx, smry_fmt );

      printf( "\n[TRF](SK-ESP) %s  %s\n", fmt_hdr, smry_fmt );
    }
      break;

    case RHP_TRC_FMT_A_IPV6:

      smry_fmt[0] = '\0';
      smry_fmt_idx = 0;

      _print_ipv6( a_sp, a_sp_len, NULL, NULL, &smry_fmt_idx, smry_fmt, NULL );

      break;

    case RHP_TRC_FMT_A_MAC_IPV6_ESP:
    {
      u8 protocol = 0;
      a_sp2 = a_sp;
      rem = a_sp_len;

      smry_fmt[0] = '\0';
      smry_fmt_idx = 0;

      _print_mac( a_sp2, rem, &a_sp_len2, &smry_fmt_idx, smry_fmt, NULL);
      a_sp2 += a_sp_len2;
      rem -= a_sp_len2;

      _print_ipv6( a_sp2, rem, &a_sp_len2, &protocol, &smry_fmt_idx, smry_fmt, NULL );
      a_sp2 += a_sp_len2;
      rem -= a_sp_len2;

      if(protocol == RHP_PROTO_IP_UDP){
        _print_udp( a_sp2, rem, &a_sp_len2, 1, &smry_fmt_idx, smry_fmt );
        a_sp2 += a_sp_len2;
        rem -= a_sp_len2;
      }

      _print_esp( a_sp2, rem, a_iv_len, a_icv_len, NULL, &smry_fmt_idx,smry_fmt );

      printf( "\n[TRF](ESP) %s  %s\n", fmt_hdr, smry_fmt );
    }
      break;

    case RHP_TRC_FMT_A_MAC_IPV6_IKEV2:
    {
      a_sp2 = a_sp;
      rem = a_sp_len;

      smry_fmt[0] = '\0';
      smry_fmt_idx = 0;

      _print_mac( a_sp2, rem, &a_sp_len2, &smry_fmt_idx, smry_fmt, NULL);
      a_sp2 += a_sp_len2;
      rem -= a_sp_len2;

      _print_ipv6( a_sp2, rem, &a_sp_len2, NULL, &smry_fmt_idx, smry_fmt, NULL );
      a_sp2 += a_sp_len2;
      rem -= a_sp_len2;

      _print_udp( a_sp2, rem, &a_sp_len2, 1, &smry_fmt_idx, smry_fmt );
      a_sp2 += a_sp_len2;
      rem -= a_sp_len2;

      _print_ikev2( a_sp2, rem, a_iv_len, a_icv_len, 0, NULL, &smry_fmt_idx,
          smry_fmt, 0 );

      printf( "\n[TRF](IKEv2) %s  %s\n", fmt_hdr, smry_fmt );
    }
      break;

    case RHP_TRC_FMT_A_MAC_IPV6_IKEV2_PLAIN:
    {
      a_sp2 = a_sp;
      rem = a_sp_len;

      smry_fmt[0] = '\0';
      smry_fmt_idx = 0;

      _print_mac( a_sp2, rem, &a_sp_len2, &smry_fmt_idx, smry_fmt, NULL);
      a_sp2 += a_sp_len2;
      rem -= a_sp_len2;

      _print_ipv6( a_sp2, rem, &a_sp_len2, NULL, &smry_fmt_idx, smry_fmt, NULL );
      a_sp2 += a_sp_len2;
      rem -= a_sp_len2;

      _print_udp( a_sp2, rem, &a_sp_len2, 1, &smry_fmt_idx, smry_fmt );
      a_sp2 += a_sp_len2;
      rem -= a_sp_len2;

      _print_ikev2( a_sp2, rem, a_iv_len, a_icv_len, 1, NULL, &smry_fmt_idx,
          smry_fmt, 0 );

      printf( "\n[TRF](IKEv2_P) %s  %s\n", fmt_hdr, smry_fmt );
    }
      break;

    case RHP_TRC_FMT_A_MAC_IPV6_NAT_T_KEEPALIVE:
    {
      a_sp2 = a_sp;
      rem = a_sp_len;

      smry_fmt[0] = '\0';
      smry_fmt_idx = 0;

      _print_mac( a_sp2, rem, &a_sp_len2, &smry_fmt_idx, smry_fmt, NULL);
      a_sp2 += a_sp_len2;
      rem -= a_sp_len2;

      _print_ipv6( a_sp2, rem, &a_sp_len2, NULL, &smry_fmt_idx, smry_fmt, NULL );
      a_sp2 += a_sp_len2;
      rem -= a_sp_len2;

      _print_udp( a_sp2, rem, &a_sp_len2, 1, &smry_fmt_idx, smry_fmt );
      a_sp2 += a_sp_len2;
      rem -= a_sp_len2;

      _print_ikev2_nat_t_keepalive( a_sp2, rem, &a_sp_len2, 1, &smry_fmt_idx, smry_fmt );

      printf( "\n[TRF](NAT-T-KA) %s  %s\n", fmt_hdr, smry_fmt );
    }
      break;

    case RHP_TRC_FMT_A_GRE_NHRP:

      smry_fmt[0] = '\0';
      smry_fmt_idx = 0;

      _print_gre_nhrp( a_sp, a_sp_len, &smry_fmt_idx, smry_fmt );

      printf( "\n[TRF](GRE/NHRP) %s  %s\n", fmt_hdr, smry_fmt );
      break;

    default:
      printf( "\n[TRF](NOT-DEFINED-PACKET-FMT(%s))\n", tkn_sym_head );
      break;
    }

    printf( "\n==<DUMP>==\n" );
    _rhp_bin_dump( NULL, a_sp, a_sp_len, 1 );

    d += token_n;
    d_len -= token_n;
  }

    break;

  default:
    printf( "Unknown token : %d\n", token_t );
    goto error;
  }

out:
	*b_len = d_len;
  *b = d;
  *f = c;

  return 0;

ignore:
	goto out;

error:
	return -1;
}

static int _translate_trace_format( unsigned long seq, struct user_tag *u_tag,
    struct message_tag *m_tag, rhp_trace_record *record,
    unsigned char *o_buffer, unsigned long o_buffer_len )
{
  xmlChar *f = m_tag->format;
  unsigned char *b = o_buffer;
  unsigned long b_len = o_buffer_len;
  struct tm ts;
  int psp = 0;
  int invalid_token_fmt = 0;
  char fmt_hdr[512];
  int fmt_hdr_idx = 0;

  localtime_r( &record->timestamp.tv_sec, &ts );

  fmt_hdr[0] = '\0';

  printf( "\n(%lu) %d/%02d/%02d %02d:%02d:%02d-%ld", seq, ts.tm_year + 1900,
      ts.tm_mon + 1, ts.tm_mday, ts.tm_hour, ts.tm_min, ts.tm_sec,
      record->timestamp.tv_usec );
  fmt_hdr_idx += sprintf( fmt_hdr + fmt_hdr_idx, " %02d:%02d:%02d-%ld",
      ts.tm_hour, ts.tm_min, ts.tm_sec, record->timestamp.tv_usec );

  printf( " [%s] %s-%s p:%u,t:%u ", u_tag->name, u_tag->id_str, m_tag->id_str, record->pid, record->tid );
  fmt_hdr_idx += sprintf( fmt_hdr + fmt_hdr_idx, " p:%u,t:%u ", record->pid, record->tid );

  if(m_tag->tag && m_tag->tag[0] != '\0'){
    printf( "(%s) ", m_tag->tag );
  }

  if(b_len == 0){
    goto no_data;
  }

  if(*f == '\n'){
    f++;
  }

  while(*f != '\0'){

    if(*f == '%' && b_len > 0){

      if(_translate_trace_token( u_tag, &f, &b, &b_len, o_buffer, o_buffer + o_buffer_len, fmt_hdr )){
        goto error;
      }

    }else{

      if(*f == ' ' || *f == '\t'){

        if(!psp){
          goto next;
        }

      }else{
        psp = 1;
      }

      if(*f != '%'){
        printf( "%c", *f );
      }else{
        invalid_token_fmt++;
      }

      next: f++;
    }
  }
  if(invalid_token_fmt){
    printf( " (Invalid Token format found. (%d))", invalid_token_fmt );
  }
  printf( "\n" );

  if(*f == '\0' && b_len){
    printf( " --REMAIN_DATA--\n" );
    _rhp_bin_dump( NULL, b, b_len, 1 );
    printf( "\n" );
  }

  no_data: while(*f != '\0'){
    printf( "%c", *f );
    f++;
  }

  return 0;

error:
  return -1;
}

static char dmy_msg_tag_id_str[32];
static struct message_tag dmy_msg_tag = {
    .format = (xmlChar*)"--MESG NOT DEFINED--\n",
    .id_str = (xmlChar*)dmy_msg_tag_id_str, };

static int _translate_trace_record( unsigned long seq,
    struct user_tag *root_tag, rhp_trace_record *record,
    unsigned char *o_buffer, unsigned long o_buffer_len )
{
  struct user_tag *u_tag = root_tag;
  struct message_tag *m_tag = NULL;
  unsigned char userid = (unsigned char) ((record->record_id >> 24)
      & 0x000000FF);
  unsigned long mesgid = (record->record_id & 0x00FFFFFF);

  while(u_tag){

    if(u_tag->id == userid){
      break;
    }

    u_tag = u_tag->next;
  }

  if(u_tag == NULL){

    struct tm ts;

    localtime_r( &record->timestamp.tv_sec, &ts );

    printf( "\n(%lu) %d/%02d/%02d %02d:%02d:%02d-%ld", seq, ts.tm_year + 1900,
        ts.tm_mon + 1, ts.tm_mday, ts.tm_hour, ts.tm_min, ts.tm_sec,
        record->timestamp.tv_usec );
    printf( " [%s] %d-%lu p:%u,t:%u ", "???", userid, mesgid, record->pid,
        record->tid );

    _rhp_bin_dump( NULL, (unsigned char*) record, record->len, 1 );

    goto skip;
  }

  m_tag = u_tag->message_hash_tab[_message_id_hash( mesgid )];

  while(m_tag){

    if(m_tag->id == mesgid){
      break;
    }

    m_tag = m_tag->hash_next;
  }

  if(m_tag == NULL){

    dmy_msg_tag_id_str[0] = '\0';
    sprintf( dmy_msg_tag_id_str, "%lu", mesgid );
    dmy_msg_tag.id = mesgid;
    m_tag = &dmy_msg_tag;
  }

  return _translate_trace_format( seq, u_tag, m_tag, record, o_buffer,o_buffer_len );

skip:
  return 0;
}

static int _translate_trace_f(char* path,FILE** ofd_r)
{
	int err = 0;
  rhp_trace_f_file_header f_header;
  int ifd = -1, ofd = -1;
	ssize_t rlen,wlen,rd_tot_len = 0;
	unsigned char rbuf[64];
	int rbuf_len = 64;


  unlink("./rokhoper_trace_f.tmp");

  ofd = open("./rokhoper_trace_f.tmp",(O_WRONLY | O_CREAT | O_TRUNC),S_IRWXU);
  if(ofd < 0){
    err = errno;
    printf("Fail to open ./rokhoper_trace_f.tmp. %s. \n", strerror( err ));
    goto error;
  }

  {
    unsigned int magic;

    magic = RHP_TRC_FILE_MAGIC0;

		wlen = write(ofd,(void*) &magic, sizeof(magic));
    if(wlen < 1){
      err = errno;
      printf( " Fail to write magic.(1) ./rokhoper_trace_f.tmp. %s \n",strerror( err ) );
      goto error;
    }

    magic = RHP_TRC_FILE_MAGIC1;

		wlen = write(ofd,(void*) &magic, sizeof(magic));
    if(wlen < 1){
      err = errno;
      printf( " Fail to write magic.(2) ./rokhoper_trace_f.tmp. %s \n",strerror( err ) );
      goto error;
    }
  }


  ifd = open(path,O_RDONLY);
  if(ifd < 0){
    err = errno;
    printf("Fail to open %s. %s. \n",path,strerror( err ));
    goto error;
  }

  if( lseek(ifd,sizeof(unsigned int)*2,SEEK_SET) < 0 ){
  	err = errno;
    printf("Fail to lseek ./rokhoper_trace_f.tmp. (1) %s. \n", strerror( err ));
    goto error;
  }

  rlen = read(ifd,(void*)&f_header, sizeof(rhp_trace_f_file_header));
  if(rlen < 1){
    err = errno;
    printf( " Fail to read trace_f or EOF.(1) %s , %s \n", path, strerror(err));
    goto error;
  }

  printf("f_header.record_head_pos: %lu\n",f_header.record_head_pos);
  printf("f_header.record_tail_pos: %lu\n",f_header.record_tail_pos);
  printf("f_header.buffer_len: %lu\n",f_header.buffer_len);
  printf("f_header.current_len: %lu\n\n",f_header.current_len);

  if( lseek(ifd,sizeof(unsigned int)*2 + sizeof(rhp_trace_f_file_header) + f_header.record_head_pos,SEEK_SET) < 0 ){
  	err = errno;
    printf("Fail to lseek ./rokhoper_trace_f.tmp. (1) %s. \n", strerror( err ));
    goto error;
  }

  while( rd_tot_len < f_header.current_len && rd_tot_len < f_header.buffer_len ){

  	if( (rlen = read(ifd,(void*)rbuf,rbuf_len)) < 0 ){
  		err = errno;
      printf("Fail to read %s. (1) %s. \n",path, strerror( err ));
  		goto error;
  	}

  	if( rlen == 0 ){ // EOF
  		break;
  	}

  	wlen = write(ofd,(void*)rbuf,rlen);
  	if( wlen < rlen ){
      printf("Fail to write ./rokhoper_trace_f.tmp. (1) %s. \n",strerror( err ));
      goto error;
  	}

  	rd_tot_len += wlen;
  }


  if( lseek(ifd,sizeof(unsigned int)*2 + sizeof(rhp_trace_f_file_header),SEEK_SET) < 0 ){
  	err = errno;
    printf("Fail to lseek ./rokhoper_trace_f.tmp. (2) %s. \n", strerror( err ));
    goto error;
  }

  while( rd_tot_len < f_header.current_len && rd_tot_len < f_header.buffer_len ){

  	if( (rlen = read(ifd,(void*)rbuf,rbuf_len)) <= 0 ){
  		err = errno;
      printf("Fail to read %s. (1) %s. \n",path, strerror( err ));
  		goto error;
  	}

  	wlen = write(ofd,(void*)rbuf,rlen);
  	if( wlen < rlen ){
      printf("Fail to write ./rokhoper_trace_f.tmp. (2) %s. \n",strerror( err ));
      goto error;
  	}

  	rd_tot_len += wlen;
  }


  close(ifd);
  ifd = -1;
  close(ofd);
  ofd = -1;

  *ofd_r = fopen("./rokhoper_trace_f.tmp","r");
  if(*ofd_r == NULL){
    err = errno;
    printf( " Fail to open ./rokhoper_trace_f.tmp. %s \n",strerror( err ));
    goto error;
  }

  return 0;

error:
	if( ifd != -1 ){
		close(ifd);
	}
	if( ofd != -1 ){
		close(ofd);
	}
	return err;
}


static int _translate_trace( int argc, char **argv )
{
  int i;
  int err = 0;
  struct user_tag* root_tag = NULL;
  FILE* ofd = NULL;
  size_t st;
  rhp_trace_record record;
  unsigned char* o_buffer = NULL;
  unsigned long seq = 1;
  int f_flag = 0;

  memset( &record, 0, sizeof(record) );

  ofd = fopen( argv[1], "r" );
  if(ofd == NULL){
    err = errno;
    printf( " Fail to open %s. %s \n", argv[1], strerror( err ) );
    goto error;
  }

  {
    unsigned int magic;

read_again:
    st = fread( (void*) &magic, sizeof(magic), 1, ofd );
    if(st < 1){
      err = ferror( ofd );
      printf( " Fail to read magic or EOF.(1) %s , %s \n", argv[1], strerror(
          err ) );
      goto error;
    }

    if(magic != RHP_TRC_FILE_MAGIC0){
      printf( " Unknown file format.(1) %s \n", argv[1] );
      goto error;
    }

    st = fread( (void*) &magic, sizeof(magic), 1, ofd );
    if(st < 1){
      err = ferror( ofd );
      printf( " Fail to read magic or EOF.(2) %s , %s \n", argv[1], strerror(err ) );
      goto error;
    }

    if( magic == RHP_TRC_FILE_MAGIC2 && !f_flag ){

    	f_flag = 1;

    	fclose( ofd );
      ofd = NULL;

    	err = _translate_trace_f(argv[1],&ofd);
    	if(err){
        printf( " Fail to read trace_f file. %s , %s \n", argv[1], strerror(err));
        goto error;
    	}

    	goto read_again;

    }else if(magic != RHP_TRC_FILE_MAGIC1){
      printf( " Unknown file format.(2) %s \n", argv[1] );
      goto error;
    }
  }

  for(i = 2; i < argc; i++){

    struct user_tag* tmp = _parseFile( argv[i] );

    if(tmp){
      //    _dump_user_tag(tmp);
      tmp->next = root_tag;
      root_tag = tmp;

    }else{
      printf( " Fail to parse %s. \n", argv[i] );
    }
  }

  if(root_tag == NULL){
    printf( " No Valid XML file found.\n" );
    goto error;
  }

  while(1){

    unsigned long old_len = record.len;

    st = fread( (void*) &record, sizeof(record), 1, ofd );
    if(st < 1){

      if(feof( ofd )){
        break;
      }

      err = ferror( ofd );
      printf( " Fail to read record. %s , %s \n", argv[1], strerror( err ) );
      goto error;
    }

    /*
     printf("RECORD : len(%lu) , userid(%d) record_id(%d) , pid(%d) , tid(%d)\n",
     record.len,((record.record_id >> 24) & 0x000000FF),
     (record.record_id & 0x00FFFFFF),record.pid,record.tid);
     */

    //  _rhp_bin_dump("RECORD",&record,sizeof(record),1);
    //  printf("RECORD->len : %d\n",record.len);

    if(old_len < record.len && o_buffer){
      free( o_buffer );
      o_buffer = NULL;
    }

    if(o_buffer == NULL){

      o_buffer = (unsigned char*) malloc( record.len );
      if(o_buffer == NULL){
        err = errno;
        printf( " Fail to alloc record buffer. %s %lu , %s \n", argv[1],
            record.len, strerror( err ) );
        goto error;
      }
    }

    if(record.len > sizeof(record)){

      st = fread( (void*) o_buffer, record.len - sizeof(record), 1, ofd );
      if(st < 1){
        err = ferror( ofd );
        printf( " Fail to read record or EOF. %s , %s \n", argv[1], strerror(
            err ) );
        goto error;
      }

      //      _rhp_bin_dump("RECORD-DATA",o_buffer,record.len-sizeof(record),1);
    }

    err = _translate_trace_record( seq++, root_tag, &record, o_buffer,
        record.len - sizeof(record) );

    if(err){
      printf( " Fail to tlanslate record. %s , %s \n", argv[1], strerror( -err ) );
      err = 0;
      //    goto error;
    }

  }

error:
	if(o_buffer){
    free( o_buffer );
  }

  if(root_tag){
    struct user_tag* tmp = root_tag;
    while(tmp){
      root_tag = tmp->next;
      _free_user_tag( tmp );
      tmp = root_tag;
    }
  }

  if(ofd){
    fclose( ofd );
  }

  return err;
}

static char * _print_user_str[RHP_TRC_MAX_USERS] = {
		"reserved     ",
		"common     ",
		"syspxy     ",
		"main       ",
		"func       ",
		"trace_file ",
		"main_freq  ",
		"syspxy_freq",
		"reserved   ",
};

static int _show_info_trace()
{
  int err = 0;
  int devfd = -1;
  rhp_trace_info info;
  int i;

  memset( &info, 0, sizeof(rhp_trace_info) );

  devfd = open( "/dev/rhp_trace", O_RDWR);
  if(devfd < 0){
    err = errno;
    printf( " Fail to open /dev/rhp_trace. %s. \n", strerror( err ) );
    goto error;
  }

  if(ioctl( devfd, RHP_TRC_IOCTRL_INFO_ID, &info )){
    err = errno;
    printf( " Fail to get trace info. %s \n", strerror( err ) );
    goto error;
  }

  printf( " Buffer: %lu bytes / %lu bytes (used / total). \n",
      info.trc_current_len, info.trc_buffer_len );

  for(i = 1; i < RHP_TRC_MAX_USERS; i++){

    if(info.trace_flag[i]){
      printf( "  [%u] %s : mask[%u]  : ENABLED \n",i,_print_user_str[i],info.trace_flag[i] );
    }else{
      printf( "  [%u] %s : mask[%u]  : - \n",i,_print_user_str[i],info.trace_flag[i] );
    }
  }

  printf("\n");

  error: if(devfd >= 0){
    close( devfd );
  }
  return err;
}

static int _enable_trace( int action, int argc, char** argv )
{
  int err = 0;
  int devfd = -1;
  unsigned long flag = 0;
  unsigned long userid = 0;
  unsigned long filter_mask = 0;
  char* endp;

  userid = strtoul( argv[1], &endp, 10 );
  if(userid == 0 || userid > RHP_TRC_MAX_USERS){
    printf( " _enable_trace : Fail to parse user_id. %s\n", argv[1] );
    goto error;
  }

  if(action == RHP_TRC_TOOL_CMD_ENABLE){

    if(argc == 2){
      filter_mask = 0x000000FF;
    }else if(argc == 3){

      filter_mask = strtoul( argv[2], &endp, 10 );

      if(filter_mask == 0 || filter_mask > 255){
        printf( " _enable_trace : Fail to parse filter_mask. %s\n", argv[2] );
        goto error;
      }
    }
  }

  flag = (((userid << 8) & 0x0000FF00) | filter_mask) & 0x0000FFFF;

  devfd = open( "/dev/rhp_trace", O_RDWR);
  if(devfd < 0){
    err = errno;
    printf( " Fail to open /dev/rhp_trace. %s. \n", strerror( err ) );
    goto error;
  }

  if(ioctl( devfd, RHP_TRC_IOCTRL_SET_ID, flag )){
    err = errno;
    printf( " Fail to set SET flag. %s \n", strerror( err ) );
    goto error;
  }

  error: if(devfd >= 0){
    close( devfd );
  }
  return err;
}

static int _set_size_trace( int argc, char** argv )
{
  int err = 0;
  int devfd = -1;
  char* endp;
  int size = 0;

  size = strtol( argv[1], &endp, 10 );
  if(size == 0){
    printf( " _set_size_trace : Fail to parse size. %s\n", argv[1] );
    goto error;
  }

  devfd = open( "/dev/rhp_trace", O_RDWR);
  if(devfd < 0){
    err = errno;
    printf( " Fail to open /dev/rhp_trace. %s. \n", strerror( err ) );
    goto error;
  }

  if(ioctl( devfd, RHP_TRC_IOCTRL_RESIZE_ID, size )){
    err = errno;
    printf( " Fail to set SET SIZE. %s \n", strerror( err ) );
    goto error;
  }

  error: if(devfd >= 0){
    close( devfd );
  }
  return err;
}

static int _reset_trace()
{
  int err = 0;
  int devfd = -1;

  devfd = open( "/dev/rhp_trace", O_RDWR);
  if(devfd < 0){
    err = errno;
    printf( " Fail to open /dev/rhp_trace. %s. \n", strerror( err ) );
    goto error;
  }

  if(ioctl( devfd, RHP_TRC_IOCTRL_CLEAR_ID, 0 )){
    err = errno;
    printf( " Fail to set CLEAR. %s \n", strerror( err ) );
    goto error;
  }

  error: if(devfd >= 0){
    close( devfd );
  }
  return err;
}

static void _print_usage()
{
  printf( "  -e user_id [filter_mask] : enable trace\n"
    "  -d user_id : disable trace\n"
    "  -s output_file : save trace\n"
    "  -t output_file xml_file ... : translate trace\n"
    "  -z size : set trace size(byte)\n"
    "  -r : reset trace\n"
    "  -i : show trace configuration\n" );
}

static int _opt_tag( char** argv, int argc )
{
  int len;
  char* optname = argv[0];

  if((len = strlen( optname )) < 1){
    return -EINVAL;
  }

  if(len == 2 && optname[0] == '-'){

    if(optname[1] == 's'){

      if(argc != 2){
        return -EINVAL;
      }

      return RHP_TRC_TOOL_CMD_SAVE;

    }else if(optname[1] == 't'){

      if(argc < 3){
        return -EINVAL;
      }

      return RHP_TRC_TOOL_CMD_TRANSLATE;

    }else if(optname[1] == 'e'){

      if(argc != 2 && argc != 3){
        return -EINVAL;
      }

      return RHP_TRC_TOOL_CMD_ENABLE;

    }else if(optname[1] == 'd'){

      if(argc != 2){
        return -EINVAL;
      }

      return RHP_TRC_TOOL_CMD_DISABLE;

    }else if(optname[1] == 'z'){

      if(argc != 2){
        return -EINVAL;
      }

      return RHP_TRC_TOOL_CMD_SET_SIZE;

    }else if(optname[1] == 'r'){

      if(argc != 1){
        return -EINVAL;
      }

      return RHP_TRC_TOOL_CMD_RESET;

    }else if(optname[1] == 'i'){

      if(argc != 1){
        return -EINVAL;
      }

      return RHP_TRC_TOOL_CMD_SHOW_INFO;

    }else{
      return -EINVAL;
    }
  }

  return -EINVAL;
}

int main( int argc, char **argv )
{
  int opt;

  if(argc < 2){
    goto usage;
  }

  if((opt = _opt_tag( (++argv), --argc )) < 0){
    goto usage;
  }

  switch(opt){

  case RHP_TRC_TOOL_CMD_SAVE:

    if(_save_trace( argv[1] )){
      goto usage;
    }
    break;

  case RHP_TRC_TOOL_CMD_TRANSLATE:

    if(_translate_trace( argc, argv )){
      goto usage;
    }
    break;

  case RHP_TRC_TOOL_CMD_ENABLE:
  case RHP_TRC_TOOL_CMD_DISABLE:

    if(_enable_trace( opt, argc, argv )){
      goto usage;
    }
    break;

  case RHP_TRC_TOOL_CMD_SHOW_INFO:

    if(_show_info_trace()){
      goto usage;
    }
    break;

  case RHP_TRC_TOOL_CMD_SET_SIZE:

    if(_set_size_trace( argc, argv )){
      goto usage;
    }
    break;

  case RHP_TRC_TOOL_CMD_RESET:

    if(_reset_trace()){
      goto usage;
    }
    break;

  default:
    goto usage;
  }

  xmlCleanupParser();

  return EXIT_SUCCESS;

usage:
  _print_usage();
  return EXIT_SUCCESS;
}

