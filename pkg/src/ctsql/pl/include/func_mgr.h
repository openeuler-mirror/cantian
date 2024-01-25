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
 * func_mgr.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/include/func_mgr.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __FUNC_MRG_H__
#define __FUNC_MRG_H__

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#pragma pack(4)
typedef struct st_ctext {
    char *str;
    unsigned int len;
} ctext_t;

typedef struct st_cbinary {
    unsigned char *bytes;
    unsigned int size;
} cbinary_t;

#pragma pack()

#ifdef WIN32
typedef __int64 oid_t;
#else
typedef long long oid_t;
#endif


/*
 * This struct is the data actually passed to an fmgr-called function.
 * Please do not change the data structure in the following.
 */

#define FUNC_MAX_ARGS (unsigned int)100
typedef struct st_func_callinfo_data *func_call_info;

typedef uintptr_t (*langc_func_t)(func_call_info fcinfo);

typedef struct st_fmgr_info {
    oid_t oid;            /* function/ proc oid, hash key must be first */
    langc_func_t fn_addr; /* the function's address */
    void *lib_handle;     /* lib handle */
} fmgr_info_t;


typedef void *(*fmgr_alloc_t)(void *owner, unsigned int size);

typedef struct st_func_callinfo_data {
    fmgr_info_t flinfo;      /* ptr to lookup info used for this call */
    void *context;           /* pass info about context of call */
    fmgr_alloc_t alloc;      /* memory alloc function ptr */
    unsigned short args_num; /* arguments actually passed */
    bool is_null;            /* function must set true if result is NULL */
    bool reserved;
    void *args[FUNC_MAX_ARGS];     /* Arguments passed to function */
    bool args_null[FUNC_MAX_ARGS]; /* T if arg[i] is actually NULL */
} func_callinfo_data_t;

/*
 * Get number of arguments passed to function.
 */
#define FMGR_NARGS() (fcinfo->args_num)

#define FUNCTION_ARGS func_call_info fcinfo

#define FMGR_GET_ARG_VALUE(n, TYPE) (*(TYPE *)(FMGR_GET_ARG_DATA(n)))
#define FMGR_GET_ARG_PTR(n, TYPE) ((TYPE *)(FMGR_GET_ARG_DATA(n)))

#define FMGR_ALLOC(size) fcinfo->alloc(fcinfo->context, size)

#define FMGR_RETURN(x) return (uintptr_t)(x);

#define FMGR_GET_RETURN_VALUE(TYPE, x) ((TYPE)(x))
#define FMGR_GET_RETURN_PTR(TYPE, x) ((TYPE *)(x))

#define FMGR_RETURN_NULL        \
    do {                        \
        fcinfo->is_null = true; \
        return (uintptr_t)0;    \
    } while (0)

#define FMGR_RETURN_VOID return (uintptr_t)0

typedef union st_return_union {
    double value;
    uintptr_t retval;
} return_union_t;

/* define return double type, consider floating point numbers and integer implicit conversions */
#define FMGR_RETURN_DOUBLE(x)                                                            \
    do {                                                                                 \
        return_union_t *my_union = (return_union_t *)FMGR_ALLOC(sizeof(return_union_t)); \
        if (my_union == NULL) {                                                          \
            FMGR_RETURN_NULL;                                                            \
        }                                                                                \
        my_union->value = (x);                                                           \
        return (uintptr_t)my_union;                                                      \
    } while (0)


/*
 * If function is not marked "proisstrict" in pg_proc, it must check for
 * null arguments using this macro.  Do not try to GETARG a null argument!
 */
#define FMGR_ARG_IS_NULL(n) (fcinfo->args_null[n])

#define FMGR_GET_ARG_DATA(n) (fcinfo->args[n])

#define FMGR_SET_ARG_PTR(n, x) (FMGR_GET_ARG_DATA(n) = (void *)(x))
#define FMGR_SET_ARG_VALUE(n, TYPE, x) (*(TYPE *)FMGR_GET_ARG_DATA(n) = (x));


#define FUNCTION_CALL_INVOKE(fcinfo) ((fcinfo)->flinfo.fn_addr(fcinfo))

#ifdef __cplusplus
}
#endif

#endif
