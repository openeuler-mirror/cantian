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
 * rb_purge.h
 *
 *
 * IDENTIFICATION
 * src/kernel/flashback/rb_purge.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef _RB_PURGE_H_
#define _RB_PURGE_H_

#include "rb_truncate.h"
#include "cm_defs.h"
#include "knl_interface.h"
#include "knl_session.h"
#include "knl_part_output.h"
#include "knl_log.h"
#include "rb_purge_persistent.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum en_rb_object_type {
    RB_TABLE_OBJECT = 0,
    RB_INDEX_OBJECT = 1,
    RB_LOB_OBJECT = 2,
    RB_TABLE_PART_OBJECT = 3,
    RB_INDEX_PART_OBJECT = 4,
    RB_LOB_PART_OBJECT = 5,
    RB_TABLE_SUBPART_OBJECT = 6,
    RB_INDEX_SUBPART_OBJECT = 7,
    RB_LOB_SUBPART_OBJECT = 8,
} rb_object_type_t;

// recycle bin purge interface
status_t rb_purge(knl_session_t *session, knl_rb_desc_t *desc);
status_t rb_purge_table(knl_session_t *session, knl_rb_desc_t *desc);
status_t rb_purge_index(knl_session_t *session, knl_rb_desc_t *desc);
status_t rb_purge_table_part(knl_session_t *session, knl_rb_desc_t *desc);
status_t rb_purge_space(knl_session_t *session, uint32 space_id);
status_t rb_purge_recyclebin(knl_session_t *session);
status_t rb_purge_drop_related(knl_session_t *session, uint32 uid, uint32 oid);
status_t rb_purge_user(knl_session_t *session, uint32 uid);
status_t rb_purge_fetch_space(knl_session_t *session, uint32 space_id, knl_rb_desc_t *desc, bool32 *found);
status_t rb_purge_fetch_object(knl_session_t *session, knl_purge_def_t *def, rb_object_type_t type,
                               knl_rb_desc_t *desc);
status_t rb_purge_fetch_name(knl_session_t *session, knl_purge_def_t *def,
                             rb_object_type_t type, knl_rb_desc_t *desc);

// recycle bin flashback interface
status_t rb_flashback_drop_table(knl_session_t *session, knl_flashback_def_t *def);
status_t rb_flashback_truncate_table(knl_session_t *session, knl_dictionary_t *dc, bool32 is_force);
status_t rb_flashback_truncate_tabpart(knl_session_t *session, knl_dictionary_t *dc, text_t *part_name,
    bool32 is_force);
status_t rb_flashback_truncate_tabsubpart(knl_session_t *session, knl_dictionary_t *dc, text_t *part_name,
    bool32 is_force);

void rd_flashback_drop_table(knl_session_t *session, log_entry_t *log);
void print_flashback_drop_table(log_entry_t *log);

#ifdef __cplusplus
}
#endif

#endif
