/* -------------------------------------------------------------------------
 *  This file is part of the Cantian project.
 * Copyright (c) 2023 Huawei Technologies Co.,Ltd.
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
 * cm_signal.c
 *
 *
 * IDENTIFICATION
 * src/common/cm_signal.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_signal.h"
#include "cm_log.h"
#include "cm_error.h"
#ifdef WIN32
#else
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifndef WIN32
status_t cm_regist_signal_ex(int32 signo, void (*handle)(int, siginfo_t *, void *))
{
    struct sigaction act;
    MEMS_RETURN_IFERR(memset_sp(&act, sizeof(struct sigaction), 0, sizeof(struct sigaction)));
    if (sigemptyset(&act.sa_mask) != 0) {
        return GS_ERROR;
    }

    act.sa_flags = (int)(SA_RESETHAND | SA_SIGINFO);
    act.sa_sigaction = handle;
    if (sigaction(signo, &act, NULL) < 0) {
        GS_LOG_RUN_ERR("resiger signal %d failed, os errno %d", signo, cm_get_os_error());
        return GS_ERROR;
    }

    return GS_SUCCESS;
}
#endif

status_t cm_regist_signal(int32 signo, signal_proc func)
{
#if !defined(HAVE_POSIX_SIGNALS)
    if (signal(signo, func) < 0) {
        return GS_ERROR;
    }

#else
    struct sigaction act;
    struct sigaction oact;

    MEMS_RETURN_IFERR(memset_sp(&act, sizeof(struct sigaction), 0, sizeof(struct sigaction)));

    if (sigemptyset(&act.sa_mask) != 0) {
        return GS_ERROR;
    }
    act.sa_flags = 0;
    act.sa_handler = func;

    if (sigaction(signo, &act, &oact) < 0) {
        return GS_ERROR;
    }
#endif
    return GS_SUCCESS;
}

#ifdef __cplusplus
}
#endif
