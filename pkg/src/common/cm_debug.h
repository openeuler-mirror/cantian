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
 * cm_debug.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_debug.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_DEBUG_H_
#define __CM_DEBUG_H_

#include <stdio.h>
#include <assert.h>
#include <memory.h>
#include "cm_types.h"

#include "cm_log.h"
#include <stdlib.h>
#include <signal.h>

#if defined(_DEBUG) || defined(PCLINT)
#define CM_CHECK_PTR(expr)                                                        \
    {                                                                             \
        if ((expr)) {                                                             \
            printf("warning: null pointer found, %s, %d.\n", __FILE__, __LINE__); \
        }                                                                         \
    }
#define CM_POINTER(p1) CM_CHECK_PTR((p1) == NULL)
#define CM_POINTER2(p1, p2) CM_CHECK_PTR((p1) == NULL || (p2) == NULL)
#define CM_POINTER3(p1, p2, p3) CM_CHECK_PTR((p1) == NULL || (p2) == NULL || (p3) == NULL)
#define CM_POINTER4(p1, p2, p3, p4) CM_CHECK_PTR((p1) == NULL || (p2) == NULL || (p3) == NULL || (p4) == NULL)
#define CM_POINTER5(p1, p2, p3, p4, p5) \
    CM_CHECK_PTR((p1) == NULL || (p2) == NULL || (p3) == NULL || (p4) == NULL || (p5) == NULL)
#else
#define CM_POINTER(p1)                  {}
#define CM_POINTER2(p1, p2)             {}
#define CM_POINTER3(p1, p2, p3)         {}
#define CM_POINTER4(p1, p2, p3, p4)     {}
#define CM_POINTER5(p1, p2, p3, p4, p5) {}
#endif

static inline void cm_assert(bool32 condition)
{
    if (!condition) {
        *((uint32 *)NULL) = 1;
    }
}

#ifdef DB_DEBUG_VERSION
#define CM_ASSERT(expr) cm_assert((bool32)(expr))
#else
#define CM_ASSERT(expr) ((void)(expr))
#endif

/* Assert that this command is never executed. */
#define CM_NEVER CM_ASSERT(CT_FALSE)

static inline void cm_exit(int32 exitcode)
{
    _exit(exitcode);
}

#ifndef CMS_UT_TEST
static inline void cm_panic(bool32 condition)
{
    if (SECUREC_UNLIKELY(!condition)) {
        *((uint32 *)NULL) = 1;
    }
}
#else
static inline void cm_panic(bool32 condition)
{
    if (SECUREC_UNLIKELY(!condition)) {
        raise(SIGABRT);
    }
}
#endif

void cm_set_hook_pre_exit(void (*hook_pre_exit)(void));
void cm_pre_exit(void);
bool8 cm_is_debug_env(void);

static inline void cm_action(void)
{
    if (cm_is_debug_env()) {
        cm_panic(0);
    } else {
        cm_pre_exit();
        cm_exit(-1);
    }
}

#define CM_ACTION_PANIC 0
#define CM_ACTION_EXIT 1
#define CM_ABORT_INTER(action, format, ...)                                                                        \
    do {                                                                                                           \
        if (LOG_RUN_ERR_ON) {                                                                                      \
            cm_write_normal_log(LOG_RUN, LEVEL_ERROR, (char *)__FILE__, (uint32)__LINE__, (int)MODULE_ID, CT_TRUE, \
                                format, ##__VA_ARGS__);                                                            \
        }                                                                                                          \
        cm_print_call_link(CT_DEFAUT_BLACK_BOX_DEPTH);                                                             \
        cm_fync_logfile();                                                                                         \
        if (action == CM_ACTION_PANIC) {                                                                           \
            cm_panic(0);                                                                                           \
        } else if (action == CM_ACTION_EXIT) {                                                                     \
            cm_action();                                                                                           \
        }                                                                                                          \
    } while (0);

#define CM_ABORT_REASONABLE(condition, format, ...) \
    do {                                                                                                             \
        if (SECUREC_UNLIKELY(!(condition))) {                                                                        \
            CM_ABORT_INTER(CM_ACTION_EXIT, format, ##__VA_ARGS__);                                                   \
        }                                                                                                            \
    } while (0);

#define CM_ABORT(condition, format, ...) \
    do {                                                                                                             \
        if (SECUREC_UNLIKELY(!(condition))) {                                                                        \
            CM_ABORT_INTER(CM_ACTION_PANIC, format, ##__VA_ARGS__);                                                  \
        }                                                                                                            \
    } while (0);

#ifdef DB_DEBUG_VERSION
#define CM_MAGIC_DECLARE    uint32    cm_magic;
#define CM_MAGIC_SET(obj_declare, obj_struct) ((obj_declare)->cm_magic = obj_struct##_MAGIC)
#define CM_MAGIC_CHECK(obj_declare, obj_struct)                                         \
    do {                                                                                \
        if ((obj_declare) == NULL || ((obj_declare)->cm_magic != obj_struct##_MAGIC)) { \
            CT_LOG_RUN_ERR("[FATAL] Cantiand Halt!");                                    \
            CM_NEVER;                                                                   \
        }                                                                               \
    } while (0);

#define CM_MAGIC_CHECK_EX(obj_declare, obj_struct)                                      \
    do {                                                                                \
        if ((obj_declare) != NULL && ((obj_declare)->cm_magic != obj_struct##_MAGIC)) { \
            CT_LOG_RUN_ERR("[FATAL] Cantiand Halt!");                                    \
            CM_NEVER;                                                                   \
        }                                                                               \
    } while (0);
#else
#define CM_MAGIC_DECLARE
#define CM_MAGIC_SET(obj_declare, obj_struct) {}
#define CM_MAGIC_CHECK(obj_declare, obj_struct) {}
#define CM_MAGIC_CHECK_EX(obj_declare, obj_struct) {}
#endif

#endif
