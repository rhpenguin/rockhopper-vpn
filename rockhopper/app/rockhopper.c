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
#include <signal.h>
#include <pwd.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/unistd.h>
#include <fcntl.h>

#include "rhp_trace.h"
#include "rhp_main_traceid.h"
#include "rhp_version.h"
#include "rhp_misc.h"
#include "rhp_process.h"
#include "rhp_config.h"

extern int rhp_gcfg_log_level_debug;

extern int rhp_cfg_global_load(char* conf_xml_path);

struct __rhp_args {
  uid_t uid;
  gid_t gid;
  uid_t syspxy_uid;
  gid_t syspxy_gid;
  char* main_conf_path;
  char* syspxy_conf_path;
  int debug;
  char* debug_opt;
  int core_dump;
  char* main_user_name;
  char* syspxy_user_name;
  char* pid_file_dir;
};
static struct __rhp_args _rhp_args;


int rhp_debug_flag = 0;
char* rhp_main_conf_path = NULL;
char* rhp_syspxy_conf_path = NULL;

static int _rhp_is_parent = 0;

static void _rhp_print_usage()
{
  printf(
      "[ Usage ]\n"
      " rockhopperd [-h] -m conf_file -p protected_conf_file \n"
	    "             -u user_name [-s user_name] [-i pid_file_dir]\n\n");
}

static void _rhp_print_usage_detail()
{
  printf(
      "[ Usage ]\n"
      " rockhopperd [-h] -m conf_file -p auth_conf_file \n"
	    "             -u user_name [-s user_name] [-i pid_file_dir] [-v]\n"
      "   -m main_conf_file : Conf file path for main service.\n"
      "   -p protected_conf_file : Conf file path for protected service.\n"
      "   -u user_name : User name for main service.\n"
      "   -s user_name : User name for protected service.\n"
  		"   -i : pid-file dir.\n"
      "   -d \"default\" or \"main_foreground\" : Debug mode. Not daemonized.\n"
      "   -c : Enable core dump. Specified with \"-d\". \n"
      "   -v : Show version.\n"
      "   -h : Show help infomation.\n"
  		"\n");
}

static int _rhp_parse_args(int argc, char *argv[])
{
  int c;
  extern char *optarg;

  memset(&_rhp_args,0,sizeof(_rhp_args));
  _rhp_args.uid = (uid_t)-1;
  _rhp_args.syspxy_uid = (uid_t)-1;
  _rhp_args.syspxy_gid = (gid_t)-1;
  _rhp_args.main_conf_path = NULL;
  _rhp_args.pid_file_dir = NULL;

  while( 1 ){

    c = getopt(argc,argv,"hvm:p:r:u:s:i:cd:");

    if( c == -1 ){
      break;
    }

    switch( c ){

    case 'h':
    	_rhp_print_usage_detail();
    	goto out;

    case 'v':
    	_rhp_print_version(stdout,NULL,1);
    	goto out;

    case 'm':
    	_rhp_args.main_conf_path = optarg;
    	break;

    case 'p':
    	_rhp_args.syspxy_conf_path = optarg;
    	break;

    case 'u':
    	{
    		struct passwd *pw = NULL;
    		if ( (pw = getpwnam(optarg)) == NULL ){
    			printf("-u : Fail to get %s's info. \n",optarg);
    			goto error;
        }
    		_rhp_args.uid = pw->pw_uid;
    		_rhp_args.gid = pw->pw_gid;
    		_rhp_args.main_user_name = optarg;
    	}
    	break;

    case 's':
    	{
    		struct passwd *pw = NULL;
    		if ( (pw = getpwnam(optarg)) == NULL ){
    			printf("-s : Fail to get %s's info. \n",optarg);
    			goto error;
        }
    		_rhp_args.syspxy_uid = pw->pw_uid;
    		_rhp_args.syspxy_gid = pw->pw_gid;
    		_rhp_args.syspxy_user_name = optarg;
      }
    	break;

    case 'i':

    	_rhp_args.pid_file_dir = optarg;
    	break;

    case 'd':

    	if( strcmp(optarg,"default") && strcmp(optarg,"main_foreground") ){ // "main_foreground" : For debugging rhp_main_run() with gdb.
    		printf("-d : Unknown option(%s). \n",optarg);
    		goto error;
    	}

    	_rhp_args.debug = 1;
    	_rhp_args.debug_opt = optarg;
    	break;

    case 'c':
    	_rhp_args.core_dump = 1;
    	break;

    default:
    	goto error;
    }
  }

  if( _rhp_args.uid == (uid_t)-1 ){
    printf("-u user_name not found.\n");
    goto error;
  }

  if( _rhp_args.syspxy_uid == (uid_t)-1 ){
    _rhp_args.syspxy_uid = _rhp_args.uid;
  }

  if( _rhp_args.syspxy_gid == (gid_t)-1 ){
    _rhp_args.syspxy_gid = _rhp_args.gid;
  }

  if( _rhp_args.main_conf_path == NULL ){
    printf("-m main_conf_file not specified.\n");
    goto error;
  }

  if( _rhp_args.syspxy_conf_path == NULL ){
    printf("-a protected_conf_file not specified.\n");
    goto error;
  }

  return 0;

error:
    _rhp_print_usage();
out:
    return -EINVAL;
}

extern void rhp_main_pre_cleanup();

static void _rhp_sig_recv(siginfo_t* info)
{
  switch( info->si_signo ){

  case SIGCHLD:
  {
  	pid_t pid;
  	int s;

		RHP_TRCSTR(0,"SIGCHLD,%d",info->si_signo);

		while( (pid = waitpid(-1,&s,WNOHANG)) > 0 ){

			if( RHP_PEER_PROCESS->pid == pid ){

				RHP_TRCSTR(0,"SIGCHLD, DIACTIVATE : %d, pid:%d",info->si_signo,pid);
				_rhp_atomic_set(&rhp_process_is_active,0);

				rhp_cmd_exec_sync(0,EINTR);

			}else{
				
				rhp_cmd_exec_sync(pid,WEXITSTATUS(s));
			}
		}
  }
  	break;

  case SIGHUP:
  	RHP_TRCSTR(0,"SIGHUP,%d",info->si_signo);
  	goto exit;

  case SIGINT:
  	RHP_TRCSTR(0,"SIGINT,%d",info->si_signo);
  	goto exit;

  case SIGQUIT:
  	RHP_TRCSTR(0,"SIGQUIT,%d",info->si_signo);
  	goto exit;

  case SIGTERM:
  	RHP_TRCSTR(0,"SIGTERM,%d",info->si_signo);
  	goto exit;

  case SIGPIPE: // Do nothing...
  	RHP_TRCSTR(0,"SIGPIPE,%d",info->si_signo);
  	break;

  default:
  	RHP_BUG("NOT SUPPORTED SIGNAL:%d");
  	break;
  }

  return;

exit:

	if( RHP_MY_PROCESS->role == RHP_PROCESS_ROLE_MAIN ){

		rhp_main_pre_cleanup();
	}

	if( !_rhp_is_parent ){
		_rhp_atomic_set(&rhp_process_is_active,0);
	}

	return;
}

#define RHP_WATCHED_SIGNALS_NUM   6
static int _rhp_signals[RHP_WATCHED_SIGNALS_NUM] = {SIGCHLD,SIGHUP,SIGTERM,SIGINT,SIGQUIT,SIGPIPE};

static void* _rhp_sig_handler_run(void* arg)
{
  sigset_t ss;
  siginfo_t info;
  int i;

  rhp_trace_tid = gettid();

  sigemptyset(&ss);

  for( i = 0; i < RHP_WATCHED_SIGNALS_NUM ;i++ ){
    sigaddset(&ss,_rhp_signals[i]);
  }

  while( 1 ){

    if( sigwaitinfo(&ss,&info) > 0 ){

      _rhp_sig_recv(&info);

      if( !RHP_PROCESS_IS_ACTIVE() ){
        break;
      }
    }
  }

  return NULL;
}

int rhp_sig_clear()
{
  sigset_t ss;
  int i;

  sigemptyset(&ss);

  for( i = 0; i < RHP_WATCHED_SIGNALS_NUM ;i++ ){
    sigaddset(&ss,_rhp_signals[i]);
  }

  sigprocmask(SIG_BLOCK,&ss,NULL);

  return 0;
}

static int _rhp_sig_start_watching()
{
  int err;
  err = _rhp_thread_create(&(RHP_MY_PROCESS->sig_th),_rhp_sig_handler_run,NULL);
  return err;
}

static void _rhp_write_pid_file(const char* file_name)
{
	int path_len;
	char* path = NULL;
	int fd = -1;
	char pid[32];

	if( _rhp_args.pid_file_dir == NULL ){
		return;
	}

	path_len = strlen(_rhp_args.pid_file_dir) + strlen(file_name) + 8;

	path = (char*)malloc(path_len);
	if( path == NULL ){
		RHP_BUG("");
		return;
	}

	path[0] = '\0';
	if( snprintf(path,path_len,"%s/%s",_rhp_args.pid_file_dir,file_name) >= path_len ){
		RHP_BUG("");
		goto error;
	}

	pid[0] = '\0';
	snprintf(pid,sizeof(pid),"%d",getpid());

	fd = open(path,(O_CREAT | O_WRONLY | O_TRUNC),00644);
	if( fd < 0 ){
		RHP_BUG("%d",errno);
		goto error;
	}

	if( write(fd,pid,strlen(pid)) < 0 ){
		RHP_BUG("%d",errno);
		goto error;
	}

error:
	if( fd >= 0 ){
		close(fd);
	}
	if(path){
		free(path);
	}
	return;
}

//
// [CAUTION]
//  Caller DON'T use rhp_free() to release return value! Use free().
//
char* rhp_dbg_trace_file_name(int process_role,char* tag)
{
	char* ret;
	char* fname = NULL;

	if( process_role == RHP_PROCESS_ROLE_MAIN ){
		fname = rhp_gcfg_dbg_f_trace_main_path;
	}else if( process_role == RHP_PROCESS_ROLE_SYSPXY ){
		fname = rhp_gcfg_dbg_f_trace_syspxy_path;
	}else{
		return NULL;
	}

	if( fname == NULL ){
		if( process_role == RHP_PROCESS_ROLE_MAIN ){
			fname = "/home/rhpmain/rockhopper";
		}else if( process_role == RHP_PROCESS_ROLE_SYSPXY ){
			fname = "/home/rhpprotected/rockhopper";
		}
	}

	ret = (char*)malloc(strlen(fname) + strlen(tag) + 8);
	if( ret == NULL ){
		return NULL;
	}

	ret[0] = '\0';
	sprintf(ret,"%s_%s.trc",fname,tag);

	return ret;
}

static int _rhp_exec_main()
{
	int err;

	//
	// [CAUTION]
	// Don't use _rhp_malloc()/_rhp_free()
	//

  if( (err = rhp_sig_clear()) ){
    printf("Error(%s) : %s[%d]\n",strerror(abs(err)),__FILE__,__LINE__);
    goto error;
  }

	if( (err = _rhp_sig_start_watching()) ){
		printf("Error(%s) : %s[%d]\n",strerror(abs(err)),__FILE__,__LINE__);
		goto error;
	}

	if( !rhp_gcfg_dbg_direct_file_trace ){
		rhp_trace_init();
	}
	rhp_trace_pid = getpid();
	rhp_trace_tid = gettid();

	rhp_process_my_role = RHP_PROCESS_ROLE_MAIN;

	_rhp_write_pid_file("rockhopper_main.pid");

	rhp_log_init(RHP_PROCESS_ROLE_MAIN);

	_rhp_atomic_set(&rhp_process_is_active,1);

	rhp_main_run();

	rhp_log_cleanup(RHP_PROCESS_ROLE_MAIN);


	if( !rhp_gcfg_dbg_direct_file_trace ){
		rhp_trace_cleanup();
	}else{
		rhp_trace_f_cleanup();
	}

	return 0;

error:
	return err;
}

static int _rhp_exec_syspxy()
{
	int err;

	//
	// [CAUTION]
	// Don't use _rhp_malloc()/_rhp_free()
	//

  if( (err = rhp_sig_clear()) ){
    printf("Error(%s) : %s[%d]\n",strerror(abs(err)),__FILE__,__LINE__);
    goto error;
  }

	if( (err = _rhp_sig_start_watching()) ){
		printf("Error(%s) : %s[%d]\n",strerror(abs(err)),__FILE__,__LINE__);
		goto error;
	}

	if( !rhp_gcfg_dbg_direct_file_trace ){
		rhp_trace_init();
	}
	rhp_trace_pid = getpid();
	rhp_trace_tid = gettid();

	_rhp_write_pid_file("rockhopper_protected.pid");

	rhp_log_init(RHP_PROCESS_ROLE_SYSPXY);

	_rhp_atomic_set(&rhp_process_is_active,1);

	rhp_syspxy_run();

	if( !rhp_gcfg_dbg_direct_file_trace ){
		rhp_trace_cleanup();
	}else{
		rhp_trace_f_cleanup();
	}

	return 0;

error:
	return err;
}


int main(int argc, char *argv[])
{
  int err;
  pid_t child;


	//
	// [CAUTION]
	// Don't use _rhp_malloc()/_rhp_free()
	//

  err = _rhp_parse_args(argc,argv);
  if( err ){
    goto error;
  }

  rhp_debug_flag = _rhp_args.debug;

  rhp_main_conf_path = (char*)_rhp_malloc(strlen(_rhp_args.main_conf_path)+1);
  if( rhp_main_conf_path == NULL ){
    printf("Error : %s[%d]\n",__FILE__,__LINE__);
    goto error;
  }
  rhp_main_conf_path[0] = '\0';
  strcpy(rhp_main_conf_path,_rhp_args.main_conf_path);

  rhp_syspxy_conf_path = (char*)_rhp_malloc(strlen(_rhp_args.syspxy_conf_path)+1);
  if( rhp_syspxy_conf_path == NULL ){
    printf("Error : %s[%d]\n",__FILE__,__LINE__);
    goto error;
  }
  rhp_syspxy_conf_path[0] = '\0';
  strcpy(rhp_syspxy_conf_path,_rhp_args.syspxy_conf_path);


  if( !rhp_debug_flag ){

  	//
  	// Internally forked this process here.
  	//
  	// "Type=forking" is specified for systemd's
  	// service configuration (rockhopper.service[Service]).
  	//
    if( daemon(0,0) < 0 ){
      err = -errno;
      printf("Error(%s) : %s[%d]\n",strerror(abs(err)),__FILE__,__LINE__);
      goto error;
    }
  }

  rhp_cfg_global_load(rhp_main_conf_path);


  rhp_log_enable_debug_level(rhp_gcfg_log_level_debug);
  rhp_log_disable(rhp_gcfg_log_disabled);


  if( (err = rhp_process_init(_rhp_args.uid,_rhp_args.gid,_rhp_args.syspxy_uid,_rhp_args.syspxy_gid,
       _rhp_args.debug,_rhp_args.core_dump,_rhp_args.main_user_name,_rhp_args.syspxy_user_name)) ){
    printf("Error(%s) : %s[%d]\n",strerror(abs(err)),__FILE__,__LINE__);
    goto error;
  }

  // TODO : Think about "chroot()" for security.

  if( !rhp_debug_flag ){

syspxy_foreground:

		if( (child = fork()) == 0 ){

			rhp_process_info[RHP_PROCESS_ROLE_MAIN].pid = getpid();

			_rhp_exec_main();

		}else{

			if( child == -1 ){
				err = -errno;
				printf("Error(%s) : %s[%d]\n",strerror(abs(err)),__FILE__,__LINE__);
				goto error;
			}

			rhp_process_info[RHP_PROCESS_ROLE_MAIN].pid = child;
			_rhp_is_parent = 1;

			_rhp_exec_syspxy();
    }

  }else{

  	if( strcmp(_rhp_args.debug_opt,"main_foreground") ){
      goto syspxy_foreground;
  	}

  	if( (child = fork()) == 0 ){

  		rhp_process_info[RHP_PROCESS_ROLE_SYSPXY].pid = getpid();

			_rhp_exec_syspxy();

  	}else{

  		if( child == -1 ){
  			err = -errno;
  			printf("Error(%s) : %s[%d]\n",strerror(abs(err)),__FILE__,__LINE__);
  			goto error;
  		}

  		rhp_process_info[RHP_PROCESS_ROLE_SYSPXY].pid = child;
			_rhp_is_parent = 1;

  		_rhp_exec_main();
  	}
  }

  return EXIT_SUCCESS;

error:
  if( rhp_main_conf_path ){
    _rhp_free(rhp_main_conf_path);
  }
  return err;
}




#ifdef RHP_DBG_FUNC_TRC

//
// gcc option '-finstrument-functions' must be specified.
//

void __cyg_profile_func_enter( void *, void * )
	__attribute__ ((no_instrument_function));

void __cyg_profile_func_exit( void *, void * )
	__attribute__ ((no_instrument_function));

__thread void* rhp_func_trc_call_stack[RHP_DBG_FUNC_TRC_CALL_STACK_MAX];
__thread int rhp_func_trc_call_stack_idx = -1;

void* rhp_func_trc_current()
{
	void* p;
	if( rhp_func_trc_call_stack_idx <= 0 ){
		return NULL;
	}
	p = rhp_func_trc_call_stack[rhp_func_trc_call_stack_idx-1];

  RHP_TRC(0,RHPTRCID_FUNC_TRC_CURRENT,"Y",p);

	return p;
}

void __cyg_profile_func_enter(void *this,void *callsite)
{
	{
		if( rhp_func_trc_call_stack_idx >= RHP_DBG_FUNC_TRC_CALL_STACK_MAX ){
			goto ignore;
		}
		rhp_func_trc_call_stack[++rhp_func_trc_call_stack_idx] = this;
	}
ignore:

	RHP_TRC_FUNC_ENTER(this,rhp_func_trc_call_stack_idx);
	return;
}

void __cyg_profile_func_exit(void *this,void *callsite)
{
	{
		if( rhp_func_trc_call_stack_idx < 0 ){
			goto ignore;
		}
		if( rhp_func_trc_call_stack[rhp_func_trc_call_stack_idx] != this ){
			goto ignore;
		}
		rhp_func_trc_call_stack[rhp_func_trc_call_stack_idx--] = NULL;
	}
ignore:

	RHP_TRC_FUNC_EXIT(this,(rhp_func_trc_call_stack_idx + 1));
	return;
}

#else // RHP_DBG_FUNC_TRC

void* rhp_func_trc_current()
{
	return NULL;
}
#endif // RHP_DBG_FUNC_TRC
