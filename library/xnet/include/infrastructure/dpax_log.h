/*
 * Copyright Notice:
 * Copyright(C), 2014 - 2014, Huawei Tech. Co., Ltd. ALL RIGHTS RESERVED. \n
 */

#ifndef __DPAX_LOG_H__
#define __DPAX_LOG_H__

#include <string.h>

#include "dpax_typedef.h"
#ifndef WIN32
#include "dplog.h"
#else
#include "lvos_debug.h"
#endif
#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

#define DPLOG_LVL_EMERGE          LOG_EMERG

#define DPLOG_LVL_ALERT           LOG_ALERT

#define DPLOG_LVL_CRIT            LOG_CRIT

#define DPLOG_LVL_ERROR           LOG_ERR

#define DPLOG_LVL_WARN            LOG_WARNING

#define DPLOG_LVL_NOTICE          LOG_NOTICE

#define DPLOG_LVL_INFO            LOG_INFO

#define DPLOG_LVL_DEBUG           LOG_DEBUG


#ifndef __FILENAME__
#ifdef __LLT__
#define __FILENAME__ ""
#else
#define __FILENAME__ (strrchr(__FILE__, '/') ? (strrchr(__FILE__, '/') + 1) : __FILE__)
#endif
#endif


#define DEFAULT_LOG_ID 0L

#ifndef WIN32
#if defined(__LLT__) || defined(__DPAX_LOG_DIRECT__)
#define dpax_log(siLevel, pscFormat...) \
    dplog((const int)MY_PID, siLevel, (char*)__FILENAME__, __LINE__, __func__, DEFAULT_LOG_ID, ##pscFormat)
#else
#define dpax_log(siLevel, pscFormat...) ({ \
    if (dplog_level_check((int)MY_PID, siLevel) == 0) \
        dplog((const int)MY_PID,siLevel, (char*)__FILENAME__,__LINE__,__func__,DEFAULT_LOG_ID,##pscFormat); \
})
#endif


s32 dpax_log_level_set(const int imodeId, const int siLevel);

s32 dpax_log_level_get(const int imodeId);

#define dpax_log_get_num_of_gid dplog_get_num_of_gid

#define dpax_log_get_num_of_pid dplog_get_num_of_pid

#define dpax_get_log_config dplog_get_log_config

#define dpax_set_log_burst dplog_set_log_burst

#define dpax_get_all_pid_level dplog_get_all_pid_level

#define dpax_save_loglevel dplog_save_loglevel

#define dpax_save_log_ratelimit dplog_save_log_ratelimit

#define dpax_set_log_resume dplog_set_log_resume

s32 dpax_ratelimit_set(const int imodeId, const u32 uiInterval,const u32 uiNum);

#define dpax_limit_reset_all() dplog_limit_reset_all()

#define dpax_log_limit_switch_off  dplog_limit_switch_off
 
#define dpax_log_limit_switch_on  dplog_limit_switch_on


#define dpax_ratelimit_get(mod_id, interval, num)   \
    dplog_ratelimit_get((s32)dplog_get_group_id(mod_id), interval, num); 




#define dpax_driftlimit_set(mod_id, drift_resume, drift_burst) \
    dplog_driftlimit_set((s32)dplog_get_group_id(mod_id), drift_resume, drift_burst)





#define dpax_driftlimit_get(mod_id, resume, burst)   \
    dplog_driftlimit_get((s32)dplog_get_group_id(mod_id), resume, burst); 



#define dpax_limit_reset(mod_id) \
    dplog_limit_reset((s32)dplog_get_group_id(mod_id))

#define dpax_set_enhance_switch_on dplog_set_enhance_switch_on

#define dpax_set_enhance_switch_off dplog_set_enhance_switch_off

#define dpax_set_mod_enhance_switch_on(gid) \
    dplog_set_mod_enhance_switch_on(gid)

#define dpax_set_mod_enhance_switch_off(gid) \
    dplog_set_mod_enhance_switch_off(gid)

#define dpax_log_get_mod_line_switch(mod_id, enhance_switch) \
    dplog_get_mod_enhance_switch(gid, enhance_switch)

#define dpax_log_get_line_switch(enhance_switch) \
    dplog_get_enhance_switch(enhance_switch)

#define DPAX_MAX_STRATEGY_NUM DP_LOG_MAX_STRATEGY_NUM
#define dpax_line_limit_get(mod_id, strategy, threshold, limit, interval) \
    dplog_linelimit_get((s32)dplog_get_group_id(mod_id), strategy, threshold, limit, interval)

#define dpax_log_procId_set(procId) dplog_set_proc_id(procId)

#define dpax_log_filePath_set(pFilePath) dplog_set_file_path(pFilePath)

#define dpax_log_file_path_set_ext(pFilePath) dplog_set_file_path_ext(pFilePath, pFilePath)

#define dpax_log_backup_num_set(backupNum) dplog_set_backup_num(backupNum)

s32 dpax_log_init(void);

s32 dpax_log_destroy(void);


#else
 
#define  LOG_EMERG 1

#define  LOG_ALERT 1

#define  LOG_CRIT 2

#define  LOG_ERR  2

#define  LOG_WARNING 3

#define  LOG_INFO 4

#define  LOG_NOTICE 5

#define  LOG_DEBUG 5


#define dpax_log(siLevel,pscFormat,...) \
	DBG_Log(0, siLevel, __FUNCTION__, __LINE__, 0, #pscFormat, __VA_ARGS__)
#define dpax_log_init() 	0
#define dpax_log_destroy()  0

#endif

#define INFRA_LOG_UNLIMIT(level, format, ...) \
        dplog(0, level, (char*)__FILENAME__, __LINE__, __func__, 0L, "[Infra]" format, ##__VA_ARGS__)

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif /* __DPAX_LOG_H__ */
