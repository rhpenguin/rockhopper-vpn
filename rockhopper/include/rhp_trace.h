/*

 Copyright (C) 2009-2010 TETSUHARU HANADA <rhpenguine@gmail.com>
 All rights reserved.

 You can redistribute and/or modify this software under the
 LESSER GPL version 2.1.
 See also LICENSE.txt and LICENSE_LGPL2.1.txt.

 */

//
// librhptrace.so
//

#ifndef _RHP_TRACE_H_
#define _RHP_TRACE_H_

#define RHP_TRC_MAX_USERS     			9 // [CAUTION] When changing this value, update rhp_trace_flag_c[] and rhp_trace_flag_c_n[](rhp_trace_lib.c), too.
#define RHP_TRC_USER_FUNCTRC				4 // (ex) For __cyg_profile_func_enter()/exit() hooks.
#define RHP_TRC_USER_TRACE_FILE			5 // (ex) For libSegFault.so.

extern unsigned char* rhp_trace_flag;   // sizeof(unsigned char)*RHP_TRC_MAX_USERS
extern __thread int rhp_trace_flag_c_n[RHP_TRC_MAX_USERS];
extern __thread unsigned char rhp_trace_flag_c[RHP_TRC_MAX_USERS];

#ifndef __KERNEL__

/*
 rhp_trace_init : Initialize debug trace lib.

 */
extern int rhp_trace_init();

/*
 rhp_trace_cleanup : Clean up debug trace lib.

 */
extern void rhp_trace_cleanup();

/*
 After initializing trace lib with rhp_trace_init(), the following variables should be set
 in each process and each thread like this.

   rhp_trace_pid = getpid();
   rhp_trace_tid = gettid();

 These variables are already declared in trace lib.

 */
extern pid_t rhp_trace_pid;
extern __thread pid_t rhp_trace_tid; // TLS
extern __thread int rhp_trace_write_disabled;

#endif // __KERNEL__

#ifndef RHP_TRC_FMT_A_MAC
#define RHP_TRC_FMT_A_MAC												0
#define RHP_TRC_FMT_A_IPV4								  		1
#define RHP_TRC_FMT_A_UDP												2
#define RHP_TRC_FMT_A_ESP												3
#define RHP_TRC_FMT_A_IKEV2											4
#define RHP_TRC_FMT_A_IKEV2_PLAIN								5
#define RHP_TRC_FMT_A_MAC_IPV4_ESP							6
#define RHP_TRC_FMT_A_MAC_IPV4_IKEV2						7
#define RHP_TRC_FMT_A_MAC_IPV4_IKEV2_PLAIN			8
#define RHP_TRC_FMT_A_FROM_MAC_RAW							9
#define RHP_TRC_FMT_A_IKEV2_PLAIN_PAYLOADS			10 // NOT including Enc payload's header, IV, and ICV fields.
#define RHP_TRC_FMT_A_MAC_IPV4_NAT_T_KEEPALIVE	11
#define RHP_TRC_FMT_A_IKEV2_UDP_SK							12
#define RHP_TRC_FMT_A_IKEV2_NAT_T_UDP_SK				13
#define RHP_TRC_FMT_A_ESP_RAW_SK								14
#define RHP_TRC_FMT_A_IPV6								  		15
#define RHP_TRC_FMT_A_MAC_IPV6_ESP							16
#define RHP_TRC_FMT_A_MAC_IPV6_IKEV2						17
#define RHP_TRC_FMT_A_MAC_IPV6_IKEV2_PLAIN			18
#define RHP_TRC_FMT_A_MAC_IPV6_NAT_T_KEEPALIVE	19
#define RHP_TRC_FMT_A_GRE_NHRP									20

#endif // RHP_TRC_FMT_A_MAC

/*

 rhp_trace : Write debug trace data via /dev/rhp_trace.

 userid  : Unique ID for Trace 1.._RHP_TRC_MAX_USERS.
 RHP_TRC_USER_FUNCTRC(4) and RHP_TRC_USER_TRACE_FILE(5) are reserved.

 [CAUTION]
  When rhp_trace_f_init() is used, don't call this function from a
  child process. Or the trace record's file(binary format) will
  be broken.


 record_id : Unique ID for Trace record. 1..10 are reserved.

 format  :

 [ common ]

 'b' : 1B data. (char,unsigned char)
 'w' : 2B data. (short,unsigned short)
 'W' : 2B data. (short,unsigned short) For user land app.(BE(swapped))
 'd' : 4B data. (int,long(32bits),unsigned int,unsigned long(32bits))
 'D' : 4B data. (int,long(32bits),unsigned int,unsigned long(32bits)) For user land app.(BE(swapped))
 'f' : long data. (long,unsigned long)
 'q' : 8B data. (long long,unsigned long long)
 'Q' : 8B data. (long long,unsigned long long) For user land app.(BE(swapped))
 's' : String.  (with '\0' terminated.)
 'p' : pointer. (Dump data)
       (ex) rhp_trace(1,12,"p",32,buf);//Len of 'buf' is 32B.
 'B' : pointer. (Bit flags) 1B , 2B , 4B or 8B data. For user land app.
       (ex) rhp_trace(1,12,"B",1,&mask); //'mask' is u8(Len of 'mask' is 1B).
             rhp_trace(1,12,"B",2,&mask); //'mask' is u16(Len of 'mask' is 2B).
             rhp_trace(1,12,"B",4,&mask); //'mask' is u32(Len of 'mask' is 4B).
             rhp_trace(1,12,"B",8,&mask); //'mask' is u64(Len of 'mask' is 8B).
 '4' : IPv4 address. 4B data. For user land app.
 '6' : IPv6 address. 16B data(pointer). For user land app.
 'M' : MAC address. 6B data(pointer). For user land app.

 'a', 'u', 'F', 'U', 'x', 'X', 'Y', 'E', 'G', 'H' 'J', 'j', 'k', K' 'L', 't' and 'T' are reserved.
 See rockhopper/include/rhp_misc2.h for more details.

 args    : Traced data.

 */
extern void rhp_trace( unsigned char userid, unsigned long record_id, /*char* format,(top of va_args)*/ ... );



#define RHP_TRACE_FILE_BUF_LEN  (100*1024)

#ifndef __KERNEL__
/*
 rhp_trace_string : Write debug text via /dev/rhp_trace.

 userid  			: Unique ID for Trace USER. RHP_TRC_USER_RHP(1)..RHP_TRC_MAX_USERS(9)
                  RHP_TRC_USER_FUNCTRC(4) and RHP_TRC_USER_TRACE_FILE(5) are reserved.
 record_id  	: Unique ID for Trace record. 1..10 are reserved.
 file    				: Name of file. (ex) __FILE__
 file    				: Num of line. (ex) __LINE__
 format  		: The same one as printf() or sprintf(). (ex) %d,%u,%s,...
 args    			: The same ones as printf() or sprintf().
 */
extern void rhp_trace_string( unsigned char userid, unsigned long record_id, const char* file, int line,/*char* format,(top of va_args)*/... );

/*
 rhp_trace_save : Save debug trace as a file. For user land app.

 output_file  : File name to save debug trace.
 */
extern int rhp_trace_save( char* output_file );

/*

 /dev/rhp_file_trace : Write debug text directly. For API user, /dev/rhp_file_trace looks
 like a file. Max text size to be written is RHP_TRACE_FILE_BUF_LEN
 (bytes). Supported file operations are open() , close() and write() only.

 - Usage(1) :

	{
		int fd;
		char* text1 = "Error occured!\n";
		char* text2 = "Be careful!\n";

		fd = open("/dev/rhp_file_trace",O_WRONLY);
		write(fd,text1,strlen(text1)+1); // Trace module writes "text1" into internal temp buffer.
		write(fd,text2,strlen(text2)+1);
		...
		close(fd); // Trace module flushes and copies "text1" and "text2" into real trace buffer.
	}


 - Usage(2) :

	# echo "Error occured!" > /dev/rhp_file_trace

	# ifconfig eth0 ... 2> /dev/rhp_file_trace



 (Usage sample) Writing SegFault stack trace into trace buffer.
  ==> Link libSegFault.so(Or set env params LD_PRELOAD=/lib/libSegFault.so)
  and set env params SEGFAULT_OUTPUT_NAME=/dev/rhp_file_trace with 'export'
  command in case of Bash.

 */

/*
 rhp_trace_write_to_dev : Write a text message to /dev/rhp_file_trace.

 message  : A null-terminated text message (characters).
 */
extern int rhp_trace_write_to_dev(char* message);


extern void rhp_trace_write_enable(int flag);
extern void rhp_trace_write_disable(int flag);

#endif // __KERNEL__




#define RHP_TRC_FLAG_N		100

#define _RHP_TRC_COND_1(userid)  								( (userid) && ((userid) < RHP_TRC_MAX_USERS) && (rhp_trace_flag != ((void*)-1)) )
#define _RHP_TRC_COND_2(userid,filter_mask)  ( (rhp_trace_flag[(userid)] == 0xFF) || (rhp_trace_flag[(userid)] & (filter_mask)) )
#define _RHP_TRC_COND(userid,filter_mask)  		( _RHP_TRC_COND_1((userid)) && _RHP_TRC_COND_2((userid),(filter_mask)) )

#define _RHP_TRC_FLG_UPDATE(userid) \
({\
	int __ret__;\
	if( _RHP_TRC_COND_1((userid)) ){\
		__ret__ = 1;\
		if( rhp_trace_flag_c_n[(userid)]++ == RHP_TRC_FLAG_N ){\
			rhp_trace_flag_c_n[(userid)] = 0;\
			rhp_trace_flag_c[(userid)] = rhp_trace_flag[(userid)];\
		}\
	}else{\
		__ret__ = 0;\
	}\
	__ret__;\
})

#ifdef __KERNEL__
#define _RHP_TRC_COND_LIMIT(userid,filter_mask) ( _RHP_TRC_COND((userid),(filter_mask)) && net_ratelimit() )
#endif // __KERNEL__

#define _RHP_TRC(userid,filter_mask,record_id,...)\
do{\
	int _RHP_TRC_FLAG_ = _RHP_TRC_FLG_UPDATE((userid));\
  if( _RHP_TRC_FLAG_ && _RHP_TRC_COND_2(((userid)),(filter_mask)) && !(rhp_trace_write_disabled) ){rhp_trace((unsigned char)((userid)),(record_id),__VA_ARGS__);}\
}while(0)

#define _RHP_TRCSTR(userid,filter_mask,...)\
do{\
	int _RHP_TRC_FLAG_ = _RHP_TRC_FLG_UPDATE((userid));\
  if( _RHP_TRC_FLAG_ && _RHP_TRC_COND_2((userid),(filter_mask)) && !(rhp_trace_write_disabled)){rhp_trace_string((unsigned char)(userid),2,__FILE__,__LINE__,__VA_ARGS__);}\
}while(0)

#define _RHP_TRCF(userid,record_id,...)\
do{\
  rhp_trace((unsigned char)(userid),(record_id),__VA_ARGS__);\
}while(0)

#define _RHP_TRCSTRF(userid,...)\
do{\
  rhp_trace_string((unsigned char)(userid),2,__FILE__,__LINE__,__VA_ARGS__);\
}while(0)

#define _RHP_BUG(userid,...)\
do{\
  rhp_trace_string((unsigned char)(userid),1,__FILE__,__LINE__,__VA_ARGS__);\
}while(0)

#define _RHP_LINE(userid,...)\
do{\
	int _RHP_TRC_FLAG_ = _RHP_TRC_FLG_UPDATE((userid));\
  if( _RHP_TRC_FLAG_ && _RHP_TRC_COND_2((userid),0) && !(rhp_trace_write_disabled)){rhp_trace_string((unsigned char)(userid),3,__FILE__,__LINE__,__VA_ARGS__);}\
}while(0)

#define _RHP_LINEF(userid,...)\
do{\
	rhp_trace_string((unsigned char)(userid),3,__FILE__,__LINE__,__VA_ARGS__);\
}while(0)

#ifdef __KERNEL__
#define _RHP_LIMIT_TRC(userid,filter_mask,record_id,...) \
do{\
  if( _RHP_TRC_COND_LIMIT((userid),(filter_mask)) ){rhp_trace((unsigned char)(userid),(record_id),__VA_ARGS__);}\
}while(0)
#endif // __KERNEL__

#define RHP_TRC_FILE_MAGIC0 0xA19B637C
#define RHP_TRC_FILE_MAGIC1 0xB5D188F0
#define RHP_TRC_FILE_MAGIC2 0xB5D188F1

struct _rhp_trace_record {
  unsigned long len; // Must be top of members.
  unsigned long record_id;
  pid_t pid;
  pid_t tid;
  struct timeval timestamp;
};
typedef struct _rhp_trace_record rhp_trace_record;

#define RHP_TRC_IOCTRL_MAGIC                      0xE5
#define RHP_TRC_IOCTRL_SET                        1
#define RHP_TRC_IOCTRL_SET_ID           			 		_IO(RHP_TRC_IOCTRL_MAGIC,RHP_TRC_IOCTRL_SET)
#define RHP_TRC_IOCTRL_READING          		     	2
#define RHP_TRC_IOCTRL_READING_ID      		     		_IO(RHP_TRC_IOCTRL_MAGIC,RHP_TRC_IOCTRL_READING)
#define RHP_TRC_IOCTRL_CLEAR            		     	3
#define RHP_TRC_IOCTRL_CLEAR_ID         		     	_IO(RHP_TRC_IOCTRL_MAGIC,RHP_TRC_IOCTRL_CLEAR)
#define RHP_TRC_IOCTRL_RESIZE           			 		4
#define RHP_TRC_IOCTRL_RESIZE_ID        			 		_IO(RHP_TRC_IOCTRL_MAGIC,RHP_TRC_IOCTRL_RESIZE)
#define RHP_TRC_IOCTRL_INFO             				 	5
#define RHP_TRC_IOCTRL_INFO_ID          			 		_IO(RHP_TRC_IOCTRL_MAGIC,RHP_TRC_IOCTRL_INFO)
#define RHP_TRC_IOCTRL_START            			 		6
#define RHP_TRC_IOCTRL_START_ID         		     	_IO(RHP_TRC_IOCTRL_MAGIC,RHP_TRC_IOCTRL_START)
#define RHP_TRC_IOCTRL_HELPER           			 		7
#define RHP_TRC_IOCTRL_HELPER_ID        		     	_IO(RHP_TRC_IOCTRL_MAGIC,RHP_TRC_IOCTRL_HELPER)
#define RHP_TRC_IOCTRL_GET_SHMID        		    	8
#define RHP_TRC_IOCTRL_GET_SHMID_ID     	    		_IO(RHP_TRC_IOCTRL_MAGIC,RHP_TRC_IOCTRL_GET_SHMID)
#define RHP_TRC_IOCTRL_START_HELPER          			9
#define RHP_TRC_IOCTRL_START_HELPER_ID     				_IO(RHP_TRC_IOCTRL_MAGIC,RHP_TRC_IOCTRL_START_HELPER)
#define RHP_TRC_IOCTRL_STOP												10
#define RHP_TRC_IOCTRL_STOP_ID										_IO(RHP_TRC_IOCTRL_MAGIC,RHP_TRC_IOCTRL_STOP)

#define RHP_TRC_BUFFER_MIN_SIZE         			(1024*512)
#define RHP_TRC_BUFFER_DEFAULT_SIZE     	    (4096*1024)

#define RHP_TRC_MAX_STRING_SIZE   4096 // also including '\0'.

struct _rhp_trace_info {
  unsigned char trace_flag[RHP_TRC_MAX_USERS];
  unsigned long trc_buffer_len;
  unsigned long trc_current_len;
};
typedef struct _rhp_trace_info rhp_trace_info;

struct _rhp_trace_setup {
  uid_t uid;
};
typedef struct _rhp_trace_setup rhp_trace_setup;

struct _rhp_trace_helper_params {
  unsigned int cookie;
  unsigned char trace_flag[RHP_TRC_MAX_USERS];
  int shm_id;
};
typedef struct _rhp_trace_helper_params rhp_trace_helper_params;


#define RHP_TRC_READ_BUFFER_SIZE  (1024*1024)




/*

  Directly write trace records to a file('trace_path'). Slow! The trace file
  is created by each process in rhp_trace_f_init(). This file's contents are
  also written in binary format.

  'rhp_trace.ko' module is NOT needed for this mode, but cross-process trace
  records are NOT available, of course.

  You can use only the 'rhp_trace -t' option to format the trace file into
  a text file.

 */
#ifndef __KERNEL__

extern int rhp_trace_f_init(char* trace_path,long max_file_size);
extern void rhp_trace_f_cleanup();

struct _rhp_trace_f_file_header {
	unsigned long record_head_pos;
	unsigned long record_tail_pos;
	unsigned long buffer_len;
	unsigned long current_len;
};
typedef struct _rhp_trace_f_file_header	rhp_trace_f_file_header;

#define RHP_TRC_F_MIN_FILE_SIZE				500000
#define RHP_TRC_F_DEF_MAX_FILE_SIZE		20000000

#endif // __KERNEL__

#endif // _RHP_TRACE_H_

