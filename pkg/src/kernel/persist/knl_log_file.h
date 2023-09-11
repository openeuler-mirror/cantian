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
 * knl_log_file.h
 *
 *
 * IDENTIFICATION
 * src/kernel/persist/knl_log_file.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_LOG_FILE_H__
#define __KNL_LOG_FILE_H__
#include "knl_log.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_rd_altdb_logfile {
    logic_op_t op_type;
    uint32 slot;
    int64 size;
    int32 block_size;
    char name[GS_FILE_NAME_BUFFER_SIZE];
    bool32 hole_found;
    uint32 node_id;
} rd_altdb_logfile_t;


status_t db_alter_add_logfile(knl_session_t *session, knl_alterdb_def_t *def);
status_t db_alter_drop_logfile(knl_session_t *session, knl_alterdb_def_t *def);
status_t db_alter_archive_logfile(knl_session_t *session, knl_alterdb_def_t *def);
    
void rd_alter_add_logfile(knl_session_t *session, log_entry_t *log);
void rd_alter_drop_logfile(knl_session_t *session, log_entry_t *log);

void print_alter_add_logfile(log_entry_t *log);
void print_alter_drop_logfile(log_entry_t *log);

#ifdef __cplusplus
}
#endif

#endif
