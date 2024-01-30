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
 * knl_datafile_persistent.h
 *
 *
 * IDENTIFICATION
 * src/upgrade_check/knl_datafile_persistent.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_DATAFILE_PERSISTENT_H__
#define __KNL_DATAFILE_PERSISTENT_H__
 
#ifdef __cplusplus
extern "C" {
#endif

#define DF_MAP_GROUP_RESERVED     3
typedef struct st_datafile_ctrl {
    uint32 id;
    bool32 used;
    char name[CT_FILE_NAME_BUFFER_SIZE];
    int64 size;
    uint16 block_size;
    uint16 flag;
    device_type_t type;
    int64 auto_extend_size;
    int64 auto_extend_maxsize;
    uint32 create_version;    // datafile creation times for this file id
    uint8 punched : 1;
    uint8 unused : 7;
    uint8 reserved[27];
} datafile_ctrl_t;

typedef struct st_datafile_header {
    uint32 rst_id;
    uint16 block_size;
    uint16 spc_id;
} datafile_header_t;

#pragma pack(4)
typedef struct rd_extend_datafile {
    uint32 id;
    int64 size;
} rd_extend_datafile_t;

typedef struct rd_truncate_datafile {
    uint32 id;
    int64 size;
} rd_truncate_datafile_t;

typedef struct rd_extend_datafile_daac {
    uint32 op_type;
    rd_extend_datafile_t datafile;
} rd_extend_datafile_daac_t;

typedef struct rd_truncate_datafile_daac {
    uint32 op_type;
    rd_truncate_datafile_t datafile;
} rd_truncate_datafile_daac_t;

typedef struct st_rd_add_bitmap_group {
    page_id_t begin_page;
    uint8 page_count;
    uint8 reserved[DF_MAP_GROUP_RESERVED];
} rd_df_add_map_group_t;

typedef struct st_rd_change_bimap {
    uint16 start;
    uint16 size;
    uint16 is_set;
    uint16 reserved;
} rd_df_change_map_t;

typedef struct st_rd_set_df_autoextend {
    uint32 id;
    bool32 auto_extend;
    int64 auto_extend_size;
    int64 auto_extend_maxsize;
} rd_set_df_autoextend_t;

typedef struct st_rd_set_df_autoextend_daac {
    uint32 op_type;
    rd_set_df_autoextend_t rd;
} rd_set_df_autoextend_daac_t;

#pragma pack()


#ifdef __cplusplus
}
#endif

#endif