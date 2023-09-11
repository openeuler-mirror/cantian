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
 * cm_thread.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_thread.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_THREAD_H__
#define __CM_THREAD_H__

#include "cm_defs.h"
#include "cm_debug.h"
#include "cm_atomic.h"
#include "cm_epoll.h"

#ifdef WIN32
#else
#include <pthread.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <sched.h>
#include <sys/eventfd.h>
#endif

// include file and define of gittid()
#ifndef WIN32
#include <sys/types.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifdef WIN32
typedef CRITICAL_SECTION thread_lock_t;
#else
typedef pthread_mutex_t thread_lock_t;
#endif

typedef struct st_cm_thread_eventfd {
    atomic_t wait_session_cnt;
    int32 epfd;
    int32 efd;
} cm_thread_eventfd_t;

typedef struct st_cm_thread_id {
    uint32 thread_id;
    bool32 has_get;
} cm_thread_id_t;

void cm_init_eventfd(cm_thread_eventfd_t *etfd);
void cm_timedwait_eventfd(cm_thread_eventfd_t *etfd, int32 timeout_ms);
void cm_wakeup_eventfd(cm_thread_eventfd_t *etfd);
void cm_release_eventfd(cm_thread_eventfd_t *etfd);

typedef struct st_cm_thread_cond {
#ifdef WIN32
    HANDLE sem;
    atomic32_t count;
#else
    pthread_mutex_t lock;
    pthread_cond_t cond;
    pthread_condattr_t attr;
#endif
} cm_thread_cond_t;

void cm_init_cond(cm_thread_cond_t *cond);
bool32 cm_wait_cond(cm_thread_cond_t *cond, uint32 ms);
bool32 cm_wait_cond_no_timeout(cm_thread_cond_t *cond);
void cm_release_cond(cm_thread_cond_t *cond);
void cm_release_cond_signal(cm_thread_cond_t *cond);
void cm_destory_cond(cm_thread_cond_t *cond);
/* thread lock */
void cm_init_thread_lock(thread_lock_t *lock);
void cm_thread_lock(thread_lock_t *lock);
void cm_thread_unlock(thread_lock_t *lock);
void cm_destroy_thread_lock(thread_lock_t *lock);

/* thread */
typedef struct st_thread {
#ifdef WIN32
    DWORD id;
    HANDLE handle;
#else
    pthread_t id;
#endif

    volatile bool32 closed;
    void *entry;
    void *argument;
    int32 result;
    uint32 stack_size;
    void *reg_data;
    char *stack_base; /* the start stack address of this thread */
} thread_t;

typedef void (*thread_entry_t)(thread_t *thread);

status_t cm_create_thread(thread_entry_t entry, uint32 stack_size, void *argument, thread_t *thread);
void cm_close_thread(thread_t *thread);
void cm_close_thread_nowait(thread_t *thread);

uint32 cm_get_current_thread_id(void);
#define CM_THREAD_ID cm_get_current_thread_id()

bool32 cm_is_current_thread_closed(void);
void cm_release_thread(thread_t *thread);
long cm_get_os_thread_stack_rlimit(void);
void cm_switch_stack_base(thread_t *thread, char *stack_base, char **org_base);

#ifdef __linux
#define cm_set_thread_name(x) prctl(PR_SET_NAME, x)
#else
#define cm_set_thread_name(x)
#endif

#ifdef WIN32
typedef DWORD cpu_set_t;
#endif

/*****Thread variable defined begin.*****/
#define DB_MAX_THV_OBJ_NUM 3

typedef enum tag_thv_type {
    GLOBAL_THV_OBJ0 = 0, // had been occupied by gss connection
    GLOBAL_THV_OBJ1 = 1,
    GLOBAL_THV_OBJ2 = 2,
    // add more here, notice modify DB_MAX_THV_OBJ_NUM
    MAX_THV_TYPE
} thv_type_e;

typedef handle_t (*init_thv_func)(void);
typedef status_t (*create_thv_func)(pointer_t *result);
typedef void (*release_thv_func)(pointer_t thv_addr);

typedef struct tag_thv_ctrl {
    //It will be called one time for a process.
    init_thv_func init;
    //It will be called one time for per thread when use it.
    create_thv_func create;
    //It will be called when thread_var_addr isn't null and the thread whill exit.
    release_thv_func release;
} thv_ctrl_t;

// create thread variant storages
// NOTICE: all release operation will mount in release_thv_func
status_t cm_create_thv_ctrl(void);

status_t cm_set_thv_args_by_id(thv_type_e var_type,
                               init_thv_func init,
                               create_thv_func create,
                               release_thv_func release);
// initialize all thread variant，call it after cm_set_thv_args_by_id
void cm_init_thv(void);

status_t cm_get_thv(thv_type_e var_type, pointer_t *result);
/*****Thread variable defined end.*****/


#ifdef __cplusplus
}
#endif

#endif
