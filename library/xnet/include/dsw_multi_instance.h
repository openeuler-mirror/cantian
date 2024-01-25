/**
 *          Copyright 2011 - 2018, Huawei Tech. Co., Ltd.
 *                      ALL RIGHTS RESERVED
 *
 * dsw_multi_instance.h
 *

 * @create: 2018-03-16
 *
 */

#ifndef __DSW_MULTI_INSTANCE_H__
#define __DSW_MULTI_INSTANCE_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cpluscplus */

#include <sys/syscall.h>
#include <pthread.h>
#include "dsw_typedef.h"

#define MAX_OSD_NUM                 (72)
#define OSD_INST_STAT_IDLE          ((dsw_u8)255)
#define OSD_INST_STAT_RUNNING       ((dsw_u8)0)
#define OSD_INST_STAT_EXITING       ((dsw_u8)1)


#define OSD_INST_RUN_STAT_INIT              ((dsw_u8)255)
#define OSD_INST_RUN_STAT_LOOP              ((dsw_u8)0)
#define OSD_INST_RUN_STAT_FINISH            ((dsw_u8)1)

#define DSW_HAS_INITED (1)
#define DSW_NOT_INITED (0)

#define __NULL_OP()

#ifdef __USE_MULTI_INSTANCE__

//#define __CLONE(expr, times)    __CLONE_WRAP(expr, times)

//#define __CLONE_WRAP(expr, times)   __CLONE_##times(expr)

//#define __CLONE_WORK(expr, times)  (__CLONE(expr, times - 1), __CLONE(expr, times - 1))
dsw_int dsw_start_new_osd();

dsw_u8 dsw_multi_instance_get_state(dsw_u32 osd_idx);
dsw_u8 dsw_multi_instance_get_my_state(void);
dsw_u8 dsw_multi_instance_get_run_state(dsw_u32 osd_idx);

void dsw_multi_instance_set_state(dsw_u32 osd_idx, dsw_u8 state);
void dsw_multi_instance_set_my_state(dsw_u8 state);
void dsw_multi_instance_set_run_state(dsw_u32 osd_idx, dsw_u8 state);
void dsw_multi_instance_set_server_type(dsw_u8 type);
dsw_u8 dsw_multi_instance_get_server_type(void);

void dsw_multi_instance_init_osd_state(dsw_u8 state);

void dsw_reg_multi_instance_var(void *start_addr, size_t elem_len, void *init_elem);

void dsw_reg_multi_instance_lock(dsw_multi_auto_init_t* dsw_lock, size_t num);

void dsw_init_multi_instance_vars(void);


#define __CLONE_1(expr)  expr(), expr()

#define __CLONE_2(expr)  __CLONE_1(expr), __CLONE_1(expr)

#define __CLONE_3(expr)  __CLONE_2(expr), __CLONE_2(expr)

#define __CLONE_4(expr)  __CLONE_3(expr), __CLONE_3(expr)

#define __CLONE_5(expr)  __CLONE_4(expr), __CLONE_4(expr)

#define __CLONE_6(expr)  __CLONE_5(expr), __CLONE_5(expr)

#define DEFINE_OSD_VAR_NO_CLEAN(type, name)                                         \
    type name##_array[MAX_OSD_NUM];                                                 \

#define DEFINE_OSD_VAR(type, name)                                                  \
    type name##_array[MAX_OSD_NUM];                                                 \
    __attribute__((constructor)) static void __reg_multi_var_##name##_func(void)    \
    {                                                                               \
        dsw_reg_multi_instance_var((void *)name##_array, sizeof(name##_array[0]), NULL);    \
    }

#define DECLARE_OSD_VAR(type, name) \
    extern type name##_array[MAX_OSD_NUM]

/*lint -emacro(123, DEFINE_OSD_VAR_AND_INIT)*/
#define DEFINE_OSD_VAR_AND_INIT(type, name, initial_expr)                           \
    type name##_array[MAX_OSD_NUM];                                                 \
    static type __dsw_multi_var_##name##_init = initial_expr();                     \
    __attribute__((constructor)) static void __reg_multi_var_##name(void)           \
    {                                                                               \
        dsw_reg_multi_instance_var((void *)name##_array, sizeof(name##_array[0]),   \
                                   &(__dsw_multi_var_##name##_init));               \
    }

/*lint -emacro(123, DEFINE_OSD_VAR_AND_INIT_NO_CLEAN)*/
#define DEFINE_OSD_VAR_AND_INIT_NO_CLEAN(type, name, initial_expr)                  \
    type name##_array[MAX_OSD_NUM] = {__CLONE_5(initial_expr), __CLONE_2(initial_expr)}

/*lint -emacro(123, DEFINE_OSD_VAR_AND_INIT_CONST)*/
#define DEFINE_OSD_VAR_AND_INIT_CONST(type, name, initial_expr)                     \
    type name##_array[MAX_OSD_NUM];                                                 \
    static type __dsw_multi_var_##name##_init = initial_expr;                       \
    __attribute__((constructor)) static void __reg_multi_var_##name(void)           \
    {                                                                               \
        dsw_reg_multi_instance_var((void *)name##_array, sizeof(name##_array[0]),   \
                                   &(__dsw_multi_var_##name##_init));               \
    }

#define DEFINE_OSD_ARRAY_AUTO_INIT_LOCK(name)                               \
    static dsw_multi_auto_init_t name##_array[MAX_OSD_NUM];                                      \
    __attribute__((constructor)) static void __reg_multi_array_lock_##name(void)     \
    {                                                                               \
        dsw_reg_multi_instance_lock(name##_array, MAX_OSD_NUM);    \
    }

#define DEFINE_OSD_ARRAY_VAR(type, name, array_param)                               \
    type name##_array[MAX_OSD_NUM]array_param;                                      \
    __attribute__((constructor)) static void __reg_multi_array_var_##name(void)     \
    {                                                                               \
        dsw_reg_multi_instance_var((void *)name##_array, sizeof(name##_array[0]), NULL);    \
    }


#define DECLARE_OSD_ARRAY_VAR(type, name, array_param) \
    extern type name##_array[MAX_OSD_NUM]array_param

/*lint -emacro(123, DEFINE_OSD_ARRAY_VAR_AND_INIT)*/
#define DEFINE_OSD_ARRAY_VAR_AND_INIT(type, name, array_param, initial_expr)        \
    type name##_array[MAX_OSD_NUM]array_param;                                      \
    static type __dsw_multi_array_var_##name##_init array_param = initial_expr();   \
    __attribute__((constructor)) static void __reg_multi_array_var_##name(void)     \
    {                                                                               \
        dsw_reg_multi_instance_var((void *)name##_array, sizeof(name##_array[0]),   \
                                   __dsw_multi_array_var_##name##_init);            \
    }

#define OSD_VAR(name) \
    (name##_array[__get_osd_index()])

#define OSD_IDX_VAR(name, idx) \
    (name##_array[idx])

#define dsw_multi_instance_get_pid() (pid_t)syscall(SYS_gettid)

#define dsw_for_multi_instance_each_var(idx, name, ptr)                     \
    for (idx = 0, ptr = name##_array; idx < MAX_OSD_NUM; idx++, ptr++)

#define dsw_for_multi_instance_each_running_var(idx, name, ptr)             \
    for (idx = 0, ptr = &(name##_array[0]); idx < MAX_OSD_NUM; idx++, ptr++)    \
        if (OSD_INST_STAT_RUNNING == dsw_multi_instance_get_state(idx))

extern __thread dsw_u32 g_osd_index;
static inline dsw_u32 __get_osd_index()
{
    return g_osd_index;
}

static inline void __set_osd_index(dsw_u32 osd_idx)
{
    g_osd_index = osd_idx;
}

#else

#define OSD_VAR(name)                            name##_single
#define OSD_IDX_VAR(name, idx)                   name##_single
#define DEFINE_OSD_VAR(type, name)          type name##_single
#define DEFINE_OSD_VAR_NO_CLEAN(type, name) type name##_single
#define DECLARE_OSD_VAR(type, name)  extern type name##_single

#define DEFINE_OSD_VAR_AND_INIT(type, name, initial_expr) \
            type name##_single = initial_expr()
            
#define DEFINE_OSD_VAR_AND_INIT_NO_CLEAN(type, name, initial_expr) \
            type name##_single = initial_expr()

#define DEFINE_OSD_VAR_AND_INIT_CONST(type, name, initial_expr) \
            type name##_single = initial_expr __NULL_OP()

#define DEFINE_OSD_ARRAY_VAR(type, name, array_param) \
            type name##_single array_param

#define DECLARE_OSD_ARRAY_VAR(type, name, array_param) \
            extern type name##_single array_param

#define DEFINE_OSD_ARRAY_VAR_AND_INIT(type, name, array_param, initial_expr) \
            type name##_single array_param = initial_expr()

#define DEFINE_OSD_ARRAY_AUTO_INIT_LOCK(name)                               \
    static dsw_multi_auto_init_t name##_single = {                          \
            .initLock = PTHREAD_MUTEX_INITIALIZER,                          \
            .inited = DSW_NOT_INITED                                            \
        };                                                                  \


#define dsw_for_multi_instance_each_var(idx, name, ptr)                     \
    for (idx = 0, ptr = &name##_single; idx < 1; idx++)
        
#define dsw_for_multi_instance_each_running_var(idx, name, ptr)             \
    for (idx = 0, ptr = &name##_single; idx < 1; idx++)

#define __get_osd_index() 0
#define __set_osd_index(idx)  ((void)(idx))
#define dsw_multi_instance_get_my_state()   OSD_INST_STAT_RUNNING
#define dsw_multi_instance_get_state(idx)   OSD_INST_STAT_RUNNING
#define dsw_multi_instance_get_run_state(idx)   OSD_INST_RUN_STAT_LOOP

#define dsw_multi_instance_get_pid() getpid()
#endif

void *dsw_multi_instance_malloc(size_t size);
void *dsw_multi_instance_realloc_no_copy(void *old_mem, size_t size);
void dsw_multi_instance_release_all_mem(void);

#ifdef __cplusplus
}
#endif /* __cpluscplus */

#endif /* __DSW_NET_CONN_H__ */


