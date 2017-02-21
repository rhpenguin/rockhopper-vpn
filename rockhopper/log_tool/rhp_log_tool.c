
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
#include <sys/time.h>
#include <time.h>
#include "sqlite3.h"

#include "rhp_version.h"
#include "rhp_log.h"


struct __tool_arg {

#define RHP_LOG_TOOL_CREATE_DB		1
#define RHP_LOG_TOOL_DEBUG				2
#define RHP_LOG_TOOL_VACUUM				3
#define RHP_LOG_TOOL_PRINT_ALL		4
#define RHP_LOG_TOOL_DELETE				5
	int action;

	char* file_name;
	char* time_stamp;
};
static struct __tool_arg _tool_arg;

static void _print_usage()
{
  printf(" Usage: rhp_logtool [-h] [-c file_name] [-r file_name] [-p file_name]\n");
}

static void _print_usage_detail()
{
  printf(
      "[ Usage ]\n"
      " rhp_logtool [-h] [-v] [-c file_name] [-r file_name] [-p file_name]\n"
      "   -c file_name : Create a new DB file.\n"
      "   -r file_name : Vacuum a DB file.\n"
      "   -p file_name : Print all records.\n"
      "   -v : Show version.\n"
      "   -h : Show help infomation.\n");
}

#define RHP_LOG_TOOL_SQL_CREATE_TABLE\
	"create table event_log( timestamp TEXT, event_source INTEGER, realm_id INTEGER, level INTEGER, event_id INTEGER, message TEXT);"

#define RHP_LOG_TOOL_SQL_CREATE_TABLE_META\
	"create table event_log_meta( id INTEGER, record_num INTEGER);"

#define RHP_LOG_TOOL_SQL_INSERT_EVENT\
		"insert into event_log(timestamp,event_source,realm_id, level,event_id,message) values(?,?,?,?,?,?);"

#define RHP_LOG_TOOL_SQL_INDEX_TIMESTAMP\
		"create index idx_timestamp on event_log(timestamp);"

#define RHP_LOG_TOOL_SQL_DBG_ENUM_ALL\
		"select * from event_log order by timestamp asc;"

#define RHP_LOG_TOOL_SQL_DBG_ENUM_LIMIT\
		"select * from event_log order by timestamp asc  limit ?;"

#define RHP_LOG_TOOL_SQL_DBG_DEL_REC\
		"delete from event_log where timestamp = ?;"

/*
static int _rhp_ltool_insert(char* file_name,char* timestamp,int event_source,
		int realm_id,int level,int event_id,char* message)
{
	sqlite3* db = NULL;
	sqlite3_stmt* cmd_insert = NULL;
	int err;

	err = sqlite3_open(file_name, &db);
	if( err != SQLITE_OK ){
		printf("open error: %s\n",sqlite3_errmsg(db));
		goto error;
	}

	sqlite3_prepare(db,
				RHP_LOG_TOOL_SQL_INSERT_EVENT, strlen(RHP_LOG_TOOL_SQL_INSERT_EVENT),
				&cmd_insert, NULL);

	sqlite3_exec(db, "begin;", NULL, NULL, NULL);

	sqlite3_reset(cmd_insert);
	sqlite3_bind_text(cmd_insert,1,timestamp,strlen(timestamp),SQLITE_TRANSIENT);
	sqlite3_bind_int(cmd_insert, 2, event_source);
	sqlite3_bind_int(cmd_insert, 3, realm_id);
	sqlite3_bind_int(cmd_insert, 4, level);
	sqlite3_bind_int(cmd_insert, 5, event_id);
	sqlite3_bind_text(cmd_insert,6,message,strlen(message),SQLITE_TRANSIENT);

	err = sqlite3_step(cmd_insert);
	if (err != SQLITE_DONE){
		printf("step error: %s\n",sqlite3_errmsg(db));
	}

	sqlite3_exec(db, "commit;", NULL, NULL, NULL);

	sqlite3_finalize(cmd_insert);

error:
	if( db ){
		err = sqlite3_close(db);
	}

	return err;
}

int rhp_ltool_insert(char* file_name,int event_source,int realm_id,int level,int event_id,char* message)
{
  struct timeval timestamp;
  struct tm ts;
  char buf0[64];

	buf0[0] = '\0';

  gettimeofday(&timestamp,NULL);
  localtime_r(&(timestamp.tv_sec),&ts);

  snprintf(buf0,64,
  		"%d-%02d-%02d %02d:%02d:%02d.%06ld",
  		ts.tm_year + 1900,ts.tm_mon + 1, ts.tm_mday, ts.tm_hour, ts.tm_min, ts.tm_sec,
  		timestamp.tv_usec);

  return _rhp_ltool_insert(file_name,buf0,event_source,realm_id,level,event_id,message);
}
*/

static int _rhp_ltool_delete(char* file_name,char* timestamp)
{
	sqlite3* db = NULL;
	sqlite3_stmt* cmd_delete = NULL;
	int err;

	err = sqlite3_open(file_name, &db);
	if( err != SQLITE_OK ){
		printf("open error: %s\n",sqlite3_errmsg(db));
		goto error;
	}

	sqlite3_prepare(db,
			RHP_LOG_TOOL_SQL_DBG_DEL_REC, strlen(RHP_LOG_TOOL_SQL_DBG_DEL_REC),
				&cmd_delete, NULL);

	sqlite3_exec(db, "begin;", NULL, NULL, NULL);

	sqlite3_reset(cmd_delete);
	sqlite3_bind_text(cmd_delete,1,timestamp,strlen(timestamp),SQLITE_TRANSIENT);

	err = sqlite3_step(cmd_delete);
	if (err != SQLITE_DONE){
		printf("step error: %s\n",sqlite3_errmsg(db));
	}

	sqlite3_exec(db, "commit;", NULL, NULL, NULL);

	sqlite3_finalize(cmd_delete);

error:
	if( db ){
		err = sqlite3_close(db);
	}

	return err;
}


static int _rhp_ltool_create_db(char* file_name)
{
	sqlite3* db = NULL;
	int err;

	err = sqlite3_open(file_name, &db);
	if( err != SQLITE_OK ){
		printf("%s",sqlite3_errmsg(db));
		goto error;
	}

	err = sqlite3_exec(db,RHP_LOG_TOOL_SQL_CREATE_TABLE,NULL,0,0);
	if (err != SQLITE_OK){
		printf("Failed to create table. : %s",sqlite3_errmsg(db));
		goto error;
	}

	err = sqlite3_exec(db,RHP_LOG_TOOL_SQL_CREATE_TABLE_META,NULL,0,0);
	if (err != SQLITE_OK){
		printf("Failed to create table(meta). : %s",sqlite3_errmsg(db));
		goto error;
	}

	err = sqlite3_exec(db,RHP_LOG_TOOL_SQL_INDEX_TIMESTAMP,NULL,0,0);
	if (err != SQLITE_OK){
		printf("Failed to create index of timestamp. : %s",sqlite3_errmsg(db));
		goto error;
	}

	err = sqlite3_exec(db,"insert into event_log_meta values(0,0)",NULL,0,0);
	if (err != SQLITE_OK){
		printf("Failed to create table. : %s",sqlite3_errmsg(db));
		goto error;
	}

error:
	if( db ){
		err = sqlite3_close(db);
	}
	return err;
}

static int _rhp_ltool_vacuum_db(char* file_name)
{
	sqlite3* db = NULL;
	int err;

	err = sqlite3_open(file_name, &db);
	if( err != SQLITE_OK ){
		printf("%s",sqlite3_errmsg(db));
		goto error;
	}

	err = sqlite3_exec(db,"vacuum;",NULL,0,0);
	if (err != SQLITE_OK){
		printf("Failed to vacuum db file. : %s",sqlite3_errmsg(db));
		goto error;
	}

error:
	if( db ){
		err = sqlite3_close(db);
	}
	return err;
}

static char _rhp_ltool_to_src_buf[64];
static char* _rhp_ltool_to_src(int src_id)
{
	switch(src_id){
	case RHP_LOG_SRC_NONE:
		return "none";
	case RHP_LOG_SRC_MAIN:
		return "main process";
	case RHP_LOG_SRC_SYSPXY:
		return "protected process";
	case RHP_LOG_SRC_IKEV2:
		return "ikev2";
	case RHP_LOG_SRC_UI:
		return "ui";
	case RHP_LOG_SRC_VPNMNG:
		return "vpnmng";
	case RHP_LOG_SRC_CFG:
		return "cfg";
	case RHP_LOG_SRC_AUTHCFG:
		return "authcfg";
	case RHP_LOG_SRC_AUTH:
		return "auth";
	case RHP_LOG_SRC_NETMNG:
		return "netmng";
	}

	_rhp_ltool_to_src_buf[0] = '\0';
	snprintf(_rhp_ltool_to_src_buf,64,"%d",src_id);
	return _rhp_ltool_to_src_buf;
}

static char _rhp_ltool_to_label_buf[64];
static char* _rhp_ltool_to_level(int src_id)
{
	switch(src_id){
	case RHP_LOG_LV_DEBUG:
		return "DEBUG";
	case RHP_LOG_LV_ERR:
		return "ERROR";
	case RHP_LOG_LV_WARN:
		return "WARNING";
	case RHP_LOG_LV_NOTICE:
		return "NOTICE";
	case RHP_LOG_LV_INFO:
		return "INFO";
	case RHP_LOG_LV_DBGERR:
		return "ERROR(DEBUG)";
	}

	_rhp_ltool_to_label_buf[0] = '\0';
	snprintf(_rhp_ltool_to_label_buf,64,"%d",src_id);
	return _rhp_ltool_to_label_buf;
}

static int _rhp_ltool_print_all(char* file_name)
{
	sqlite3* db = NULL;
	sqlite3_stmt* cmd_select = NULL;
	int err;
	int i = 0;

	err = sqlite3_open(file_name, &db);
	if( err != SQLITE_OK ){
		printf("open: %s\n",sqlite3_errmsg(db));
		goto error;
	}

	sqlite3_prepare(db,
			RHP_LOG_TOOL_SQL_DBG_ENUM_ALL, strlen(RHP_LOG_TOOL_SQL_DBG_ENUM_ALL),
				&cmd_select, NULL);

	sqlite3_reset(cmd_select);

	i = 0;
	while( (err = sqlite3_step(cmd_select)) == SQLITE_ROW ){

		printf(" [%d] %s %s RLM(%d) %s %d  \"%s\"\n",
			(i + 1),
			sqlite3_column_text(cmd_select, 0),
			_rhp_ltool_to_src(sqlite3_column_int(cmd_select,1)),
			sqlite3_column_int(cmd_select,2),
			_rhp_ltool_to_level(sqlite3_column_int(cmd_select,3)),
			sqlite3_column_int(cmd_select,4),
			sqlite3_column_text(cmd_select,5)
		);

		i++;
	}

	if (err != SQLITE_DONE){
		printf("Failed to select records. %s\n",sqlite3_errmsg(db));
	}

	sqlite3_finalize(cmd_select);

error:
	if( db ){
		err = sqlite3_close(db);
	}

	return err;
}

#ifdef RHP_LOG_TOOL_DBG_TP
void _rhp_ltool_dbg(char* file_name)
{
	int i;

	for( i = 0; i < 20; i++ ){

	  struct timeval timestamp;
	  struct tm ts;
	  char buf0[64];
		char buf1[256];

		buf0[0] = '\0';
		buf1[0] = '\0';

	  gettimeofday(&timestamp,NULL);
	  localtime_r(&(timestamp.tv_sec),&ts);

	  snprintf(buf0,64,
	  		"%d-%02d-%02d %02d:%02d:%02d.%06ld",
	  		ts.tm_year + 1900,ts.tm_mon + 1, ts.tm_mday, ts.tm_hour, ts.tm_min, ts.tm_sec,
	  		timestamp.tv_usec);

		_rhp_ltool_insert(file_name,buf0,1,2,3,i,buf1);
	}

	_rhp_ltool_print_all(file_name);

	printf("isThreadSafe: %d\n",sqlite3_threadsafe());

	return;
}
#endif // RHP_LOG_TOOL_DBG_TP


static int _parse_args(int argc, char *argv[])
{
  int c;
  extern char *optarg;

  memset(&_tool_arg,0,sizeof(_tool_arg));
  _tool_arg.action = 0;

  while( 1 ){

  	c = getopt(argc,argv,"hc:r:p:vd:x:t:");

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

  	case 'c':
  		_tool_arg.action = RHP_LOG_TOOL_CREATE_DB;
    	_tool_arg.file_name = optarg;

      if( _tool_arg.file_name == NULL ){
        printf("-c file_name not specified.\n");
        goto error;
      }

    	break;

  	case 'r':
  		_tool_arg.action = RHP_LOG_TOOL_VACUUM;
    	_tool_arg.file_name = optarg;

      if( _tool_arg.file_name == NULL ){
        printf("-r file_name not specified.\n");
        goto error;
      }

    	break;

  	case 'p':
  		_tool_arg.action = RHP_LOG_TOOL_PRINT_ALL;
    	_tool_arg.file_name = optarg;

      if( _tool_arg.file_name == NULL ){
        printf("-p file_name not specified.\n");
        goto error;
      }

    	break;

  	case 'd':
  		_tool_arg.action = RHP_LOG_TOOL_DEBUG;
    	_tool_arg.file_name = optarg;

      if( _tool_arg.file_name == NULL ){
        printf("-d file_name not specified.\n");
        goto error;
      }

    	break;

  	case 'x':
  		_tool_arg.action = RHP_LOG_TOOL_DELETE;
    	_tool_arg.file_name = optarg;

      if( _tool_arg.file_name == NULL ){
        printf("-x file_name not specified.\n");
        goto error;
      }

    	break;

  	case 't':
    	_tool_arg.time_stamp = optarg;

      if( _tool_arg.time_stamp == NULL ){
        printf("-t time_stamp not specified.\n");
        goto error;
      }

    	break;

  	default:
    	goto error;
  	}
  }

  if( _tool_arg.action == 0 ){
    printf("Unknown option was specified.\n");
    goto error;
  }

  return 0;

error:
	_print_usage();
out:
	return -EINVAL;
}


int main(int argc, char *argv[])
{
	int err;

	err = _parse_args(argc,argv);
	if( err ){
		return err;
	}

	if( _tool_arg.action == RHP_LOG_TOOL_CREATE_DB ){

		_rhp_ltool_create_db(_tool_arg.file_name);

	}else if( _tool_arg.action == RHP_LOG_TOOL_VACUUM ){

		_rhp_ltool_vacuum_db(_tool_arg.file_name);

	}else if( _tool_arg.action == RHP_LOG_TOOL_PRINT_ALL ){

		_rhp_ltool_print_all(_tool_arg.file_name);

	}else if( _tool_arg.action == RHP_LOG_TOOL_DELETE ){

		if( _tool_arg.time_stamp == NULL ){
			printf("No time_stamp was specified.\n");
			return -EINVAL;
		}

		_rhp_ltool_delete(_tool_arg.file_name,_tool_arg.time_stamp);

#ifdef RHP_LOG_TOOL_DBG_TP
	}else if( _tool_arg.action == RHP_LOG_TOOL_DEBUG ){
		_rhp_ltool_dbg(_tool_arg.file_name);
#endif // RHP_LOG_TOOL_DBG_TP
	}

	return EXIT_SUCCESS;
}
