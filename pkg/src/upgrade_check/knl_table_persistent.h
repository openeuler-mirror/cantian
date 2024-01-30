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
 * knl_table_persistent.h
 *
 *
 * IDENTIFICATION
 * src/upgrade_check/knl_table_persistent.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_TABLE_PERSISTENT_H__
#define __KNL_TABLE_PERSISTENT_H__

#ifdef __cplusplus
extern "C" {
#endif
typedef struct st_rd_view {
    uint32 op_type;
    uint32 uid;
    uint32 oid;
    char obj_name[CT_NAME_BUFFER_SIZE];
} rd_view_t;

typedef struct st_rd_synonym {
    uint32 op_type;
    uint32 uid;
    uint32 id;
} rd_synonym_t;
#ifdef __cplusplus
}
#endif

#endif