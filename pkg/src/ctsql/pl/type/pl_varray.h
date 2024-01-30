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
 * pl_varray.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/type/pl_varray.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __PL_VARRAY_H__
#define __PL_VARRAY_H__

#include "pl_collection.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_mtrl_array_head {
    mtrl_ctrl_t ctrl;
    mtrl_rowid_t array[0];
} mtrl_array_head_t;


void udt_reg_varray_method(void);

#ifdef __cplusplus
}
#endif

#endif
