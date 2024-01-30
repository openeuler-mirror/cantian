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
 * knl_tenant_persist.h
 *
 *
 * IDENTIFICATION
 * src/upgrade_check/knl_tenant_persist.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_TENANT_PERSIST_H__
#define __KNL_TENANT_PERSIST_H__
 
#ifdef __cplusplus
extern "C" {
#endif
 
typedef struct st_rd_tenant {
    logic_op_t op_type;
    uint32 tid;
    char name[CT_TENANT_BUFFER_SIZE];

    CM_MAGIC_DECLARE
} rd_tenant_t;
 
#ifdef __cplusplus
}
#endif
 
#endif