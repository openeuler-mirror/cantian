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
 * knl_alter_space_persist.h
 *
 *
 * IDENTIFICATION
 * src/upgrade_check/knl_alter_space_persist.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_ALTER_SPACE_PERSIST_H__
#define __KNL_ALTER_SPACE_PERSIST_H__
 
#ifdef __cplusplus
extern "C" {
#endif
#pragma pack(4)
typedef struct st_rd_set_space_autoextend {
    uint32 space_id;
    bool32 auto_extend;
    int64 auto_extend_size;
    int64 auto_extend_maxsize;
} rd_set_space_autoextend_t;

typedef struct st_rd_set_space_flag {
    uint32 space_id;
    uint16 flags;
} rd_set_space_flag_t;

typedef struct st_rd_rename_space {
    uint32 space_id;
    char name[CT_NAME_BUFFER_SIZE];
} rd_rename_space_t;

typedef struct st_rd_set_space_autoextend_daac {
    uint32 op_type;
    rd_set_space_autoextend_t rd;
} rd_set_space_autoextend_daac_t;

typedef struct st_rd_set_space_flag_daac {
    uint32 op_type;
    rd_set_space_flag_t rd;
} rd_set_space_flag_daac_t;

typedef struct st_rd_rename_space_daac {
    uint32 op_type;
    rd_rename_space_t rd;
} rd_rename_space_daac_t;

#pragma pack()
#ifdef __cplusplus
}
#endif
 
#endif