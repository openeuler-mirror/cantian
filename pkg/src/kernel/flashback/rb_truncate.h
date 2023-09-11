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
 * rb_truncate.h
 *
 *
 * IDENTIFICATION
 * src/kernel/flashback/rb_truncate.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef _RB_TRUNCATE_H_
#define _RB_TRUNCATE_H_

#include "cm_defs.h"
#include "knl_interface.h"
#include "knl_session.h"
#include "knl_part_output.h"
#include "knl_log.h"

#ifdef __cplusplus
extern "C" {
#endif

/* recycle bin operation */
typedef enum en_rb_oper_type {
    RB_OPER_TRUNCATE = 0,
    RB_OPER_DROP = 1,
} rb_oper_type_t;

typedef struct st_knl_rb_desc {
    uint64 id;                            // recycle bin object id
    char name[GS_NAME_BUFFER_SIZE];       // recycle bin object name
    uint32 uid;                           // owner user_id
    uint32 table_id;                      // table_id of current object
    char org_name[GS_NAME_BUFFER_SIZE];   // original object name
    char part_name[GS_NAME_BUFFER_SIZE];  // object partition name, NULL otherwise
    uint32 type;                          // object type
    uint32 oper;                          // operation carried out
    uint32 space_id;                      // table space
    page_id_t entry;                      // segment entry page_id
    uint64 org_scn;                       // object original scn
    uint64 rec_scn;                       // object recycled scn
    uint64 tchg_scn;                      // table change scn
    uint64 base_id;                       // base object when recycled
    uint64 purge_id;                      // object to purge when purging this

    union {
        uint32 flags;  // flags for flashback and purge
        struct {
            uint32 can_flashback : 1;  // object can be flashed back or not
            uint32 can_purge : 1;      // object can be purged or not
            uint32 is_cons : 1;        // index object is constraint or not
            uint32 is_encode : 1;      // index name is encoded, deprecated field
            uint32 is_invalid : 1;     // index object is invalid or not
            uint32 unused : 28;
        };
    };
} knl_rb_desc_t;

void rb_convert_desc(knl_cursor_t *cursor, knl_rb_desc_t *desc);
status_t rb_drop_table(knl_session_t *session, knl_handle_t stmt, knl_dictionary_t *dc);
status_t rb_truncate_table(knl_session_t *session, knl_dictionary_t *dc);
status_t rb_truncate_table_part(knl_session_t *session, knl_dictionary_t *dc, table_part_t *table_part);
status_t rb_truncate_table_subpart(knl_session_t *session, knl_dictionary_t *dc, table_part_t *subpart,
    uint32 compart_no);
#ifdef __cplusplus
}
#endif

#endif
