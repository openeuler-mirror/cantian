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
 * typedef.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/ast/typedef.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __TYPEDEF_H__
#define __TYPEDEF_H__

#include "cursor.h"
#include "pl_record.h"
#include "pl_collection.h"
#include "pl_object.h"

typedef struct st_plv_array {
    typmode_t type;
} plv_array_t;

typedef struct st_plv_typdef {
    uint32 type; // plv_type_t
    union {
        plv_record_t record;
        plv_collection_t collection;
        plv_object_t object;
    };
} plv_typdef_t;
#endif
