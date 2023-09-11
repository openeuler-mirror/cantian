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
 * cm_signal.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_signal.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_SIGNAL_H__
#define __CM_SIGNAL_H__

#include <signal.h>
#include "cm_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef WIN32

#define SIGQUIT 3
#define SIGUSR1 30
#define SIGCHLD 20

#endif

typedef void (*signal_proc)(int32);

#ifndef WIN32
status_t cm_regist_signal_ex(int32 signo, void (*handle)(int, siginfo_t *, void *));
#endif

status_t cm_regist_signal(int32 signo, signal_proc func);

#ifdef __cplusplus
}
#endif

#endif
