/* -------------------------------------------------------------------------
 *  This file is part of the Cantian project.
 * Copyright (c) 2024 Huawei Technologies Co.,Ltd.
 *
 * Cantian is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 *          http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 * -------------------------------------------------------------------------
 *
 * tms_sig_calltrace.c
 *
 *
 * IDENTIFICATION
 * src/tms/tms_sig_calltrace.c
 *
 * -------------------------------------------------------------------------
 */
#include <signal.h>
#include <sys/syscall.h>
#include "tms_module.h"
#include "cm_context_pool.h"
#include "cm_signal.h"
#include "cm_atomic.h"
#include "tms_sig_calltrace.h"

#define SIGANAL_NOT_INITED       0
#define SIAGNAL_INITED           1
#define TMS_DEFAUT_STACK_DEPTH (uint32)30

#ifndef TMS_TGKILL
#define TMS_TGKILL __NR_tgkill
#endif

void tms_print_call_link(uint32 stack_depth)
{
#ifndef WIN32
    void *array[CT_MAX_BLACK_BOX_DEPTH] = { 0 };
    size_t size;

    size = backtrace(array, stack_depth);
    CT_LOG_RUN_WAR("Stack information when timeout");
    log_file_handle_t *log_file_handle = cm_log_logger_file(LOG_RUN);
    backtrace_symbols_fd(array, size, log_file_handle->file_handle);
#endif
}

atomic_t g_tms_sign_mutex = 0;
void tms_proc_sign_func(int32 signum, siginfo_t *siginfo, void *context)
{
    sigset_t sign_old_mask;
    sigset_t sign_mask;

    if (cm_atomic_get(&g_tms_sign_mutex) != 0) {
        return;
    }
    cm_atomic_set(&g_tms_sign_mutex, 1);

    (void)sigprocmask(0, NULL, &sign_old_mask);
    (void)sigfillset(&sign_mask);
    (void)sigprocmask(SIG_SETMASK, &sign_mask, NULL);

    tms_print_call_link(TMS_DEFAUT_STACK_DEPTH);
    cm_atomic_set(&g_tms_sign_mutex, 0);
    
    (void)sigprocmask(SIG_SETMASK, &sign_old_mask, NULL);
    cm_fync_logfile();
    return;
}

status_t tms_dump_thread_stack_sig(pid_t dwPid, pid_t dwTid)
{
    errno_t ret;

    CT_LOG_RUN_INF("Show task context by signal: pid=%d, tid=%d.", dwPid, dwTid);
    ret = syscall((errno_t)TMS_TGKILL, dwPid, dwTid, SIGTASKTRACK);
    CT_LOG_RUN_INF("Show task context by signal end: pid=%d, tid=%d, ret=%d.", dwPid, dwTid, ret);
    
    return ret;
}

status_t tms_regist_signal(int32 sig_num, void (*handle)(int, siginfo_t *, void *))
{
    errno_t ret;
    struct sigaction sa;

    ret = memset_sp(&sa, sizeof(sa), 0, sizeof(sa));
    MEMS_RETURN_IFERR(ret);

    if (sigemptyset(&sa.sa_mask) != 0) {
        return CT_ERROR;
    }

    sa.sa_flags = SA_RESTART | SA_ONSTACK | SA_SIGINFO;
    sa.sa_sigaction = handle;
    if (sigaction(sig_num, &sa, NULL) < 0) {
        CT_LOG_RUN_ERR("resiger signal %d failed", sig_num);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t tms_sigcap_reg_proc(int32 sig_num)
{
    if (tms_regist_signal(sig_num, tms_proc_sign_func) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Register the signal cap failed:%d", sig_num);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}
