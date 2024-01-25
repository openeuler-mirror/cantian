/*
 * Copyright Notice:
 *      Copyright  1998-2014, Huawei Technologies Co., Ltd.  ALL Rights Reserved.
*/

#ifndef DP_LOG_H
#define DP_LOG_H
#if defined(__KAPI__) || defined(__KAPI_USR__)
#elif !defined(__LINUX_USR__)
#define __LINUX_USR__
#endif
#ifdef __cplusplus
#if __cplusplus
extern "C"{
#endif
#endif /* __cplusplus */


#include <syslog.h>
#define LOG_BUTT 8
#define MAX_LOG_PID_NUM 4096

#define DP_LOG_MAX_LENGTH 384

#define DP_LOG_SWITCH_ON 1
#define DP_LOG_SWITCH_OFF 0
#define DP_LOG_ERROR -1
#define DP_LOG_OK 0
#define DP_LOG_INVAL 2
#define DP_LOG_GID_NOTEXIST 3
#define DP_LOG_STRATEGY_NOT_EXIST 4
#define DP_LOG_NOT_SUPPORT 5

#define DP_LOG_MAX_STRATEGY_NUM 5


#define DP_LL_EMERG   LOG_EMERG,__FILE__,__LINE__,__func__ 

#define DP_LL_ALERT   LOG_ALERT,__FILE__,__LINE__,__func__ 

#define DP_LL_CRIT   LOG_CRIT,__FILE__,__LINE__,__func__

#define DP_LL_ERROR    LOG_ERR,__FILE__,__LINE__,__func__ 

#define DP_LL_WARN     LOG_WARNING,__FILE__,__LINE__,__func__ 

#define DP_LL_NOTICE   LOG_NOTICE,__FILE__,__LINE__,__func__    

#define DP_LL_INFO     LOG_INFO,__FILE__,__LINE__,__func__    

#define DP_LL_DEBUG    LOG_DEBUG,__FILE__,__LINE__,__func__     

struct gid_config_info{
    unsigned int gid;
    unsigned int lognum;
    unsigned int interval;
    unsigned int burst;
    unsigned int resume;
    unsigned int enhance_switch;
};

struct pid_config_info{
        unsigned int pid;
        unsigned char log_level;
};

int dplog_level_check(int mod_id, int log_level);

int dplog(const int mod_id, const int log_level, char *file_name, const int f_line,const char *func_name,
         const long log_id, const char *format, ...);

void dplog_standard(unsigned int mod_id, int log_level, const char *func_name,
        int f_line, unsigned int log_id, const char *format, ...);
 
#define dplog_emerg(modId,logId,format,...) \
        dplog(modId,DP_LL_EMERG,logId,format,## __VA_ARGS__)
  
#define dplog_alert(modId,logId,format,...) \
        dplog(modId,DP_LL_ALERT,logId,format,## __VA_ARGS__)
 
#define dplog_crit(modId,logId,format,...) \
        dplog(modId,DP_LL_CRIT,logId,format,## __VA_ARGS__)
   
#define dplog_error(modId,logId,format,...) \
        dplog(modId,DP_LL_ERROR,logId,format,## __VA_ARGS__)
   
#define dplog_warning(modId,logId,format,...) \
        dplog(modId,DP_LL_WARN,logId,format,## __VA_ARGS__)

#define dplog_notice(modId,logId,format,...) \
        dplog(modId,DP_LL_NOTICE,logId,format,## __VA_ARGS__)

#define dplog_info(modId,logId,format,...) \
        dplog(modId,DP_LL_INFO,logId,format,## __VA_ARGS__)

#define dplog_debug(modId,logId,format,...) \
        dplog(modId,DP_LL_DEBUG,logId,format,## __VA_ARGS__)

unsigned int  dplog_get_group_id(const int mod_id);

int dplog_loglevel_set(const int mod_id, const int log_level);

int dplog_loglevel_get(int mod_id);

unsigned int dplog_get_num_of_gid(void);

unsigned int dplog_get_num_of_pid(void);

int dplog_get_log_config(unsigned int gid, struct gid_config_info* array, int len);

int dplog_set_log_burst (unsigned int gid, unsigned int multiple);

int dplog_get_all_pid_level(struct pid_config_info *array, unsigned int len);

int dplog_save_loglevel(void);

int dplog_save_log_ratelimit(void);

int dplog_ratelimit_set(const int g_id,const unsigned int interval,const unsigned int num);

int dplog_set_log_resume (unsigned int gid, unsigned int multiple);

int dplog_limit_switch_off(void);

int dplog_limit_switch_on(void);

int dplog_set_enhance_switch_off(void);

int dplog_set_enhance_switch_on(void);

int dplog_set_mod_enhance_switch_on(unsigned int gid);

int dplog_set_mod_enhance_switch_off(unsigned int gid);

int dplog_get_mod_enhance_switch(int gid, unsigned int* enhance_switch);

int dplog_get_enhance_switch(unsigned int* enhance_switch);

int dplog_ratelimit_get(const int g_id, unsigned int *interval, unsigned int *num);

int dplog_driftlimit_set(const int g_id, const unsigned int drift_resume,const unsigned int drift_burst);

int dplog_driftlimit_get(const int g_id, unsigned int *drift_resume, unsigned int *drift_burst);

int dplog_limit_reset(const int g_id);

int dplog_limit_reset_all(void);

int dplog_linelimit_get(const int g_id,
                        int strategy,
                        unsigned int* threshold,
                        unsigned int* limit,
                        unsigned int* interval);

int dplog_init(void);

int dplog_destroy(void);

int dplog_flush_signal_safe(void);

int dplog_set_proc_id(unsigned id);

int dplog_set_file_path(char* pFilePath);

int dplog_set_file_path_ext(char *pCurPath, char *pBakPath);

int dplog_set_backup_num(unsigned int backupNum);

int dplog_inst_try_flush_all(void);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif

