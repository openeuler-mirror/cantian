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
 * knl_sequence_persistent.h
 *
 *
 * IDENTIFICATION
 * src/upgrade_check/knl_sequence_persistent.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_SEQUENCE_PERSISTENT_H__
#define __KNL_SEQUENCE_PERSISTENT_H__

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_rd_seq {
    uint32 op_type;
    uint32 id;
    uint32 uid;
    char seq_name[CT_NAME_BUFFER_SIZE];
    char user_name[CT_NAME_BUFFER_SIZE];
} rd_seq_t;

#ifdef __cplusplus
}
#endif

#endif