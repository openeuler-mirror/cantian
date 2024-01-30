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
 * dsw_typedef.h
 *
 *
 * IDENTIFICATION
 * src/tse/message_queue/dsw_typedef.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef dsw_typedef_pub_h__
#define dsw_typedef_pub_h__

#include <stdint.h>
#include <errno.h>
#include <assert.h>
#include <pthread.h>
#include "cm_debug.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cpluscplus */


#define PACKFLAG __attribute__((__packed__))

#define DSW_TYPEOF(x) typeof((x))

#define DSW_ASSERT(x)               \
    {                               \
        CM_ASSERT(x);               \
    }

#define DSW_ASSERT_INNER(x)         \
    {                               \
        CM_ASSERT(x);               \
    }


#define DSW_THREAD_MUTEX_INIT(mutex, attr)                      \
    do {                                                        \
        int inner_retval = pthread_mutex_init((mutex), (attr)); \
        if ((0 != inner_retval) && (EBUSY != inner_retval)) {   \
            DSW_ASSERT_INNER(0);                                \
        }                                                       \
    } while (0)

#define DSW_THREAD_MUTEX_LOCK(mutex)                            \
    do {                                                        \
        int inner_retval = pthread_mutex_lock((mutex));         \
        if ((0 != inner_retval) && (EDEADLK != inner_retval)) { \
            DSW_ASSERT_INNER(0);                                \
        }                                                       \
    } while (0)

#define DSW_THREAD_MUTEX_UNLOCK(mutex)                        \
    do {                                                      \
        int inner_retval = pthread_mutex_unlock((mutex));     \
        if ((0 != inner_retval) && (EPERM != inner_retval)) { \
            DSW_ASSERT_INNER(0);                              \
        }                                                     \
    } while (0)

#ifdef __cplusplus
}
#endif /* __cpluscplus */

#endif // dsw_typedef_pub_h__
