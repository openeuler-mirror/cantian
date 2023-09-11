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
 * var_func.h
 *
 *
 * IDENTIFICATION
 * src/common/variant/var_func.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __VAR_FUNCTION_H__
#define __VAR_FUNCTION_H__

#include "cm_defs.h"
#include "cm_text.h"

typedef struct st_var_func {
    uint32 func_id; // function id
    uint32 pack_id; // package id,  buildin function is GS_INVALID_32
    bool32 is_proc; // stored procedure
    uint32 arg_cnt; // the number of arguments
    bool32 is_winsort_func; // window function
    int32 aggr_ref_count; // for aggr func
#ifdef Z_SHARDING
    uint32 orig_func_id;  // save original function id before transform for sharding
#endif
} var_func_t;

typedef struct st_var_udo {
    bool8  name_sensitive; // GS_TRUE: name like "xxx", GS_FALSE: name like xxx
    bool8  pack_sensitive; // GS_TRUE: pack like "xxx", GS_FALSE: pack like xxx
    bool8  user_explicit;  // GS_TRUE: user is explicitly specified
    uint8  unused;
    text_t user;           // user name
    text_t pack;           // package name
    text_t name;           // object name
} var_udo_t;

static inline bool32 var_udo_text_equal(var_udo_t *obj1, var_udo_t *obj2)
{
    if (obj1 == NULL && obj2 == NULL) {
        return GS_TRUE;
    }

    if (obj1 == NULL || obj2 == NULL) {
        return GS_FALSE;
    }

    if (cm_text_equal(&obj1->user, &obj2->user) &&
        cm_text_equal(&obj1->pack, &obj2->pack) &&
        cm_text_equal(&obj1->name, &obj2->name)) {
        return GS_TRUE;
    }

    return GS_FALSE;
}

#endif