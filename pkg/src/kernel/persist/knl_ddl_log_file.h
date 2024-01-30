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
 * knl_ddl_log_file.h
 *
 *
 * IDENTIFICATION
 * src/kernel/persist/knl_ddl_log_file.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_DDL_LOG_FILE_H__
#define __KNL_DDL_LOG_FILE_H__
#include "knl_log.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_logic_op_ddl_write_file_buffer {
    char *ddl_data_buffer;
} logic_ddl_file_buffer_t;

typedef struct st_logic_ddl_file {
    char name[CT_FILE_NAME_BUFFER_SIZE];  // file name
    int32 handle;                         // file handle
    device_type_t type;
    int64 size;                           // uncomprss file size
} logic_ddl_local_file_t;

typedef struct st_logic_op_ddl_file_mgr {
    logic_ddl_local_file_t data_file;
    logic_ddl_file_buffer_t file_buffer;
    char path[CT_FILE_NAME_BUFFER_SIZE];
    uint32 file_flags;
    uint32 buffer_offset;
    uint64 file_offset;
} logic_ddl_file_mgr;

#define LOG_DDL_DATA_FILE_NAME_PREPIX ("DDL_DATA")

status_t log_ddl_generate_file(logic_ddl_file_mgr *mgr, logic_ddl_local_file_t *local_file, char* name_prefix);
status_t log_ddl_write_file_local(logic_ddl_local_file_t *local, const void *buf, int32 size, int64 offset);
void log_ddl_close_file(logic_ddl_local_file_t *local_file);
status_t log_ddl_open_file(logic_ddl_local_file_t *local_file, uint32 flags);
void log_ddl_init_path(knl_session_t *session, logic_ddl_file_mgr *mgr);
void log_ddl_write_init_info(logic_ddl_file_mgr *file_mgr, logic_rep_ddl_head_t *sql_head,
                             char *sql_text, uint32 sql_len);
#ifdef __cplusplus
}
#endif

#endif