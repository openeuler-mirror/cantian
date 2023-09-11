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
 * knl_sequence.h
 *
 *
 * IDENTIFICATION
 * src/kernel/sequence/knl_sequence.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_SEQUENCE_H__
#define __KNL_SEQUENCE_H__

#include "cm_defs.h"
#include "knl_interface.h"
#include "knl_session.h"
#include "knl_log.h"

typedef struct st_rd_seq {
    uint32 op_type;
    uint32 id;
    uint32 uid;
    char seq_name[GS_NAME_BUFFER_SIZE];
    char user_name[GS_NAME_BUFFER_SIZE];
} rd_seq_t;

status_t db_create_sequence(knl_session_t *session, knl_handle_t stmt, knl_sequence_def_t *def);
status_t db_get_seq_dist_data(knl_session_t *session, text_t *user, text_t *name, binary_t **dist_data);
status_t db_get_sequence_id(knl_session_t *session, text_t *user, text_t *name, uint32 *id);
status_t db_set_cn_seq_currval(knl_session_t *session, text_t *user, text_t *name, int64 nextval);
status_t db_current_seq_value(knl_session_t *session, text_t *user, text_t *name, int64 *currval);
status_t db_next_seq_value(knl_session_t *session, text_t *user, text_t *name, int64 *nextval);
status_t db_get_nextval_for_cn(knl_session_t *session, text_t *user, text_t *name, int64 *value);
status_t db_multi_seq_value(knl_session_t *session, knl_sequence_def_t *def,
    uint32 group_order, uint32 group_cnt, uint32 count);
status_t db_alter_seq_nextval(knl_session_t *session, knl_sequence_def_t *def, int64 value);
status_t db_get_seq_def(knl_session_t *session, text_t *user, text_t *name, knl_sequence_def_t *def);
status_t db_drop_sequence(knl_session_t *session, knl_handle_t stmt, knl_dictionary_t *dc, bool32 *exists);
status_t db_alter_sequence(knl_session_t *session, knl_handle_t stmt, knl_sequence_def_t *def);
status_t db_drop_sequence_by_user(knl_session_t *session, text_t *user, uint32 uid);

void rd_create_sequence(knl_session_t *session, log_entry_t *log);
void rd_drop_sequence(knl_session_t *session, log_entry_t *log);
void rd_alter_sequence(knl_session_t *session, log_entry_t *log);
void print_create_sequence(log_entry_t *log);
void print_drop_sequence(log_entry_t *log);
void print_alter_sequence(log_entry_t *log);

#endif