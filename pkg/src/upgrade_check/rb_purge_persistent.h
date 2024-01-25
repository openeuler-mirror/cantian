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
 * rb_purge_persistent.h
 *
 *
 * IDENTIFICATION
 * src/upgrade_check/rb_purge_persistent.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __RD_PURGE_PERSISTENT_H__
#define __RD_PURGE_PERSISTENT_H__

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_rd_flashback_drop {
    uint32 op_type;
    uint32 uid;
    uint32 table_id;
    char new_name[CT_NAME_BUFFER_SIZE];
} rd_flashback_drop_t;

#ifdef __cplusplus
}
#endif

#endif