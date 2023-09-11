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
 * rb_truncate.c
 *
 *
 * IDENTIFICATION
 * src/kernel/flashback/rb_truncate.c
 *
 * -------------------------------------------------------------------------
 */
#include "rb_truncate.h"
#include "knl_context.h"
#include "knl_table.h"
#include "knl_ctlg.h"
#include "dc_log.h"

/*
 * convert cursor to RB description
 */
void rb_convert_desc(knl_cursor_t *cursor, knl_rb_desc_t *desc)
{
    text_t text;
    errno_t ret;

    desc->id = *(uint64 *)CURSOR_COLUMN_DATA(cursor, SYS_RECYCLEBIN_COL_ID);
    text.str = CURSOR_COLUMN_DATA(cursor, SYS_RECYCLEBIN_COL_NAME);
    text.len = CURSOR_COLUMN_SIZE(cursor, SYS_RECYCLEBIN_COL_NAME);
    (void)cm_text2str(&text, desc->name, GS_NAME_BUFFER_SIZE);
    ret = sscanf_s(desc->name, "BIN$%u[^$]", &desc->table_id);
    knl_securec_check_ss(ret);

    desc->uid = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_RECYCLEBIN_COL_USR_ID);

    text.str = CURSOR_COLUMN_DATA(cursor, SYS_RECYCLEBIN_COL_ORG_NAME);
    text.len = CURSOR_COLUMN_SIZE(cursor, SYS_RECYCLEBIN_COL_ORG_NAME);
    (void)cm_text2str(&text, desc->org_name, GS_NAME_BUFFER_SIZE);

    if (CURSOR_COLUMN_SIZE(cursor, SYS_RECYCLEBIN_COL_PARTITION_NAME) != GS_NULL_VALUE_LEN) {
        text.str = CURSOR_COLUMN_DATA(cursor, SYS_RECYCLEBIN_COL_PARTITION_NAME);
        text.len = CURSOR_COLUMN_SIZE(cursor, SYS_RECYCLEBIN_COL_PARTITION_NAME);
        (void)cm_text2str(&text, desc->part_name, GS_NAME_BUFFER_SIZE);
    } else {
        desc->part_name[0] = '\0';
    }

    desc->type = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_RECYCLEBIN_COL_TYPE_ID);
    desc->oper = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_RECYCLEBIN_COL_OPERATION_ID);
    desc->space_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_RECYCLEBIN_COL_SPACE_ID);

    if (CURSOR_COLUMN_SIZE(cursor, SYS_RECYCLEBIN_COL_ENTRY) != GS_NULL_VALUE_LEN) {
        desc->entry = *(page_id_t *)CURSOR_COLUMN_DATA(cursor, SYS_RECYCLEBIN_COL_ENTRY);
    } else {
        desc->entry = INVALID_PAGID;
    }

    desc->flags = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_RECYCLEBIN_COL_FLAGS);
    desc->org_scn = *(knl_scn_t *)CURSOR_COLUMN_DATA(cursor, SYS_RECYCLEBIN_COL_ORG_SCN);
    desc->rec_scn = *(knl_scn_t *)CURSOR_COLUMN_DATA(cursor, SYS_RECYCLEBIN_COL_REC_SCN);

    if (CURSOR_COLUMN_SIZE(cursor, SYS_RECYCLEBIN_COL_TCHG_SCN) != GS_NULL_VALUE_LEN) {
        desc->tchg_scn = *(knl_scn_t *)CURSOR_COLUMN_DATA(cursor, SYS_RECYCLEBIN_COL_TCHG_SCN);
    } else {
        desc->tchg_scn = GS_INVALID_ID64;
    }

    desc->base_id = *(uint64 *)CURSOR_COLUMN_DATA(cursor, SYS_RECYCLEBIN_COL_BASE_ID);
    desc->purge_id = *(uint64 *)CURSOR_COLUMN_DATA(cursor, SYS_RECYCLEBIN_COL_PURGE_ID);
}

/*
 * init table RB description
 */
static void rb_init_table_desc(knl_session_t *session, knl_table_desc_t *table_desc, knl_rb_desc_t *desc)
{
    size_t name_len;
    errno_t ret;

    desc->id = session->curr_lsn;
    ret = snprintf_s(desc->name, GS_NAME_BUFFER_SIZE, GS_NAME_BUFFER_SIZE - 1,
                     "BIN$%u$%llX==$0", table_desc->id, desc->id);
    knl_securec_check_ss(ret);
    name_len = strlen(table_desc->name);
    ret = strncpy_s(desc->org_name, GS_NAME_BUFFER_SIZE, table_desc->name, name_len);
    knl_securec_check(ret);
    desc->part_name[0] = '\0';

    desc->type = RB_TABLE_OBJECT;
    desc->space_id = table_desc->space_id;
    desc->entry = table_desc->entry;

    desc->flags = 0;
    desc->org_scn = table_desc->org_scn;
    desc->rec_scn = db_inc_scn(session);
    desc->tchg_scn = table_desc->chg_scn;
    desc->purge_id = desc->base_id;

    desc->can_flashback = (desc->id == desc->base_id) ? 1 : 0;
    desc->can_purge = (desc->id == desc->purge_id) ? 1 : 0;
}

/*
 * init table part RB description
 */
static void rb_init_table_part_desc(knl_session_t *session, table_t *table,
                                    knl_table_part_desc_t *part_desc, knl_rb_desc_t *desc)
{
    size_t name_len;
    errno_t ret;

    desc->id = session->curr_lsn;
    ret = snprintf_s(desc->name, GS_NAME_BUFFER_SIZE, GS_NAME_BUFFER_SIZE - 1,
                     "BIN$%u$%llX==$0", part_desc->table_id, desc->id);
    knl_securec_check_ss(ret);

    name_len = strlen(table->desc.name);
    ret = strncpy_s(desc->org_name, GS_NAME_BUFFER_SIZE, table->desc.name, name_len);
    knl_securec_check(ret);
    name_len = strlen(part_desc->name);
    ret = strncpy_s(desc->part_name, GS_NAME_BUFFER_SIZE, part_desc->name, name_len);
    knl_securec_check(ret);

    knl_panic_log(desc->oper == RB_OPER_TRUNCATE, "curr oper is abnormal, panic info: table %s rb_table %s oper %u",
                  table->desc.name, desc->name, desc->oper);
    desc->type = IS_SUB_TABPART(part_desc) ? RB_TABLE_SUBPART_OBJECT : RB_TABLE_PART_OBJECT;
    desc->space_id = part_desc->space_id;
    desc->entry = part_desc->entry;

    desc->flags = 0;
    desc->org_scn = part_desc->org_scn;
    desc->rec_scn = db_inc_scn(session);
    desc->tchg_scn = table->desc.chg_scn;
    desc->purge_id = desc->base_id;

    desc->can_flashback = (desc->id == desc->base_id) ? 1 : 0;
    desc->can_purge = (desc->id == desc->purge_id) ? 1 : 0;
}

/*
 * init index RB description
 */
static void rb_init_index_desc(knl_session_t *session, knl_index_desc_t *index_desc, knl_rb_desc_t *desc)
{
    errno_t ret;
    desc->id = session->curr_lsn;
    ret = snprintf_s(desc->name, GS_NAME_BUFFER_SIZE, GS_NAME_BUFFER_SIZE - 1,
                     "BIN$%u$%llX==$0", index_desc->table_id, desc->id);
    knl_securec_check_ss(ret);

    knl_get_index_name(index_desc, desc->org_name, GS_NAME_BUFFER_SIZE);
    /* for index object, partition name should be empty */
    desc->part_name[0] = '\0';

    desc->type = RB_INDEX_OBJECT;
    desc->space_id = index_desc->space_id;
    desc->entry = index_desc->entry;

    desc->flags = 0;
    desc->org_scn = index_desc->org_scn;
    desc->rec_scn = db_inc_scn(session);
    desc->tchg_scn = GS_INVALID_ID64;
    desc->purge_id = (desc->oper == RB_OPER_TRUNCATE) ? desc->base_id : desc->id;

    desc->can_flashback = (desc->id == desc->base_id) ? 1 : 0;
    desc->can_purge = (desc->id == desc->purge_id) ? 1 : 0;
    desc->is_cons = index_desc->is_enforced;
    desc->is_invalid = index_desc->is_invalid;
}

/*
 * init index part RB description
 */
static void rb_init_index_part_desc(knl_session_t *session, index_t *index, knl_index_part_desc_t *part_desc,
                                    uint32 part_no, knl_rb_desc_t *desc)
{
    desc->id = session->curr_lsn;
    errno_t ret = snprintf_s(desc->name, GS_NAME_BUFFER_SIZE, GS_NAME_BUFFER_SIZE - 1,
                             "BIN$%u$%llX==$0", part_desc->table_id, desc->id);
    knl_securec_check_ss(ret);

    knl_get_index_name(&index->desc, desc->org_name, GS_NAME_BUFFER_SIZE);
    if (IS_SUB_IDXPART(part_desc)) {
        index_part_t *index_compart = subpart_get_parent_idx_part(index, part_desc->parent_partid);
        knl_panic_log(index_compart != NULL, "the index_compart is NULL, panic info: rb_table %s index %s",
                      desc->name, index->desc.name);
        ret = snprintf_s(desc->part_name, GS_NAME_BUFFER_SIZE, GS_NAME_BUFFER_SIZE - 1,
                         "INDEX%uP%uSUBP%u", part_desc->index_id, index_compart->part_no, part_no);
    } else {
        ret = snprintf_s(desc->part_name, GS_NAME_BUFFER_SIZE, GS_NAME_BUFFER_SIZE - 1,
                         "INDEX%uP%u", part_desc->index_id, part_no);
    }
    knl_securec_check_ss(ret);

    knl_panic_log(desc->oper == RB_OPER_TRUNCATE, "curr oper is abnormal, panic info: rb_table %s index %s oper %u",
                  desc->name, index->desc.name, desc->oper);
    desc->type = IS_SUB_IDXPART(part_desc) ? RB_INDEX_SUBPART_OBJECT : RB_INDEX_PART_OBJECT;
    desc->space_id = part_desc->space_id;
    desc->entry = part_desc->entry;

    desc->flags = 0;
    desc->org_scn = part_desc->org_scn;
    desc->rec_scn = db_inc_scn(session);
    desc->tchg_scn = GS_INVALID_ID64;
    desc->purge_id = desc->base_id;

    desc->can_flashback = (desc->id == desc->base_id) ? 1 : 0;
    desc->can_purge = (desc->id == desc->purge_id) ? 1 : 0;
    desc->is_invalid = part_desc->is_invalid;
}

/*
 * init lob RB description
 */
static void rb_init_lob_desc(knl_session_t *session, knl_lob_desc_t *lob_desc, knl_rb_desc_t *desc)
{
    errno_t ret;

    desc->id = session->curr_lsn;
    ret = snprintf_s(desc->name, GS_NAME_BUFFER_SIZE, GS_NAME_BUFFER_SIZE - 1,
                     "BIN$%u$%llX==$0", lob_desc->table_id, desc->id);
    knl_securec_check_ss(ret);

    ret = snprintf_s(desc->org_name, GS_NAME_BUFFER_SIZE, GS_NAME_BUFFER_SIZE - 1,
                     "LOB%uC%u", lob_desc->table_id, lob_desc->column_id);
    knl_securec_check_ss(ret);
    desc->part_name[0] = '\0';

    knl_panic_log(desc->oper == RB_OPER_TRUNCATE, "curr oper is abnormal, panic info: rb_table %s oper %u",
                  desc->name, desc->oper);
    desc->type = RB_LOB_OBJECT;
    desc->space_id = lob_desc->space_id;
    desc->entry = lob_desc->entry;

    desc->flags = 0;
    desc->org_scn = lob_desc->org_scn;
    desc->rec_scn = db_inc_scn(session);
    desc->tchg_scn = GS_INVALID_ID64;
    desc->purge_id = desc->base_id;

    desc->can_flashback = (desc->id == desc->base_id) ? 1 : 0;
    desc->can_purge = (desc->id == desc->purge_id) ? 1 : 0;
}

/*
 * init lob part RB description
 */
static void rb_init_lob_part_desc(knl_session_t *session, table_t *table, knl_lob_part_desc_t *part_desc,
                                  uint32 part_no, knl_rb_desc_t *desc)
{
    errno_t ret;

    desc->id = session->curr_lsn;
    ret = snprintf_s(desc->name, GS_NAME_BUFFER_SIZE, GS_NAME_BUFFER_SIZE - 1,
                     "BIN$%u$%llX==$0", part_desc->table_id, desc->id);
    knl_securec_check_ss(ret);

    ret = snprintf_s(desc->org_name, GS_NAME_BUFFER_SIZE, GS_NAME_BUFFER_SIZE - 1,
                     "LOB%uC%u", part_desc->table_id, part_desc->column_id);
    knl_securec_check_ss(ret);

    if (IS_SUB_LOBPART(part_desc)) {
        table_part_t *compart = subpart_get_parent_tabpart(table->part_table, part_desc->parent_partid);
        knl_panic_log(compart != NULL, "the compart is NULL, panic info: table %s rb_table %s", table->desc.name,
                      desc->name);
        ret = snprintf_s(desc->part_name, GS_NAME_BUFFER_SIZE, GS_NAME_BUFFER_SIZE - 1,
                         "LOB%uC%uP%uSUBP%u", part_desc->table_id, part_desc->column_id, compart->part_no, part_no);
    } else {
        ret = snprintf_s(desc->part_name, GS_NAME_BUFFER_SIZE, GS_NAME_BUFFER_SIZE - 1,
                         "LOB%uC%uP%u", part_desc->table_id, part_desc->column_id, part_no);
    }
    knl_securec_check_ss(ret);

    knl_panic_log(desc->oper == RB_OPER_TRUNCATE, "curr oper is abnormal, panic info: table %s rb_table %s oper %u",
                  table->desc.name, desc->name, desc->oper);
    desc->type = IS_SUB_LOBPART(part_desc) ? RB_LOB_SUBPART_OBJECT : RB_LOB_PART_OBJECT;
    desc->space_id = part_desc->space_id;
    desc->entry = part_desc->entry;

    desc->flags = 0;
    desc->org_scn = part_desc->org_scn;
    desc->rec_scn = db_inc_scn(session);
    desc->tchg_scn = GS_INVALID_ID64;
    desc->purge_id = desc->base_id;

    desc->can_flashback = (desc->id == desc->base_id) ? 1 : 0;
    desc->can_purge = (desc->id == desc->purge_id) ? 1 : 0;
}

/*
 * drop index into recycle bin
 * @param kernel session, table, base object id
 */
static status_t rb_drop_index(knl_session_t *session, table_t *table, knl_rb_desc_t *desc)
{
    index_t *index = NULL;
    text_t text;
    uint32 i;

    for (i = 0; i < table->index_set.total_count; i++) {
        index = table->index_set.items[i];
        rb_init_index_desc(session, &index->desc, desc);

        if (db_write_sysrb(session, desc) != GS_SUCCESS) {
            return GS_ERROR;
        }

        /* update the origin index name to recycle bin object name in index$ */
        cm_str2text(desc->name, &text);
        if (db_update_index_name(session, index->desc.uid, index->desc.table_id, desc->org_name, &text) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

/*
* drop constraints into recycle bin
* @param kernel session, table, base object id
*/
static status_t rb_drop_all_cons(knl_session_t *session, knl_dictionary_t *dc)
{
    table_t *table = DC_TABLE(dc);
    uint32 type;
    row_assist_t ra;
    uint32 name_buf_size;
    errno_t ret;

    /* drop foreign key, rename primary/unique constraint */
    if (db_drop_all_cons(session, table->desc.uid, table->desc.id, GS_TRUE) != GS_SUCCESS) {
        return GS_ERROR;
    }

    CM_SAVE_STACK(session->stack);
    char *buf = (char *)cm_push(session->stack, GS_NAME_BUFFER_SIZE);
    knl_cursor_t *cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_CONSDEF_ID, IX_SYS_CONSDEF001_ID);
    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
                     &table->desc.uid, sizeof(uint32), IX_COL_SYS_CONSDEF001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
                     &table->desc.id, sizeof(uint32), IX_COL_SYS_CONSDEF001_TABLE_ID);
    knl_update_info_t *ua = &cursor->update_info;

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    while (!cursor->eof) {
        type = *(uint32 *)CURSOR_COLUMN_DATA(cursor, CONSDEF_COL_TYPE);
        if (type != CONS_TYPE_REFERENCE) {
            name_buf_size = GS_NAME_BUFFER_SIZE;
            ret = memset_sp(buf, name_buf_size, 0, name_buf_size);
            knl_securec_check(ret);
            ret = snprintf_s(buf, name_buf_size, GS_NAME_BUFFER_SIZE - 1,
                             "BIN$%u$%llX==$0", table->desc.id, session->curr_lsn);
            knl_securec_check_ss(ret);

            row_init(&ra, ua->data, GS_MAX_ROW_SIZE, 1);
            (void)row_put_str(&ra, buf);
            ua->count = 1;
            ua->columns[0] = CONSDEF_COL_NAME;
            cm_decode_row(ua->data, ua->offsets, ua->lens, NULL);

            if (knl_internal_update(session, cursor) != GS_SUCCESS) {
                CM_RESTORE_STACK(session->stack);
                return GS_ERROR;
            }
        }

        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);

    return GS_SUCCESS;
}

/*
 * drop table into recycle bin
 * Drop table and its indexes and partitions into recycle bin, using table
 * id and segment entry to generate an unique object name and purge id.
 * @param kernel session, kernel dictionary
 * @note caller should hold the table exclusive lock, indexes and partitions
 * share the same base id, so they can be purged or restored at the same time.
 */
status_t rb_drop_table(knl_session_t *session, knl_handle_t stmt, knl_dictionary_t *dc)
{
    char *buf = NULL;
    table_t *table;
    knl_rb_desc_t desc;
    text_t text;
    rd_drop_table_t redo;
    size_t name_len;
    errno_t ret;
    obj_info_t obj_addr;

    table = DC_TABLE(dc);
    desc.uid = table->desc.uid;
    desc.base_id = session->curr_lsn;
    desc.oper = RB_OPER_DROP;

    CM_SAVE_STACK(session->stack);
    rb_init_table_desc(session, &table->desc, &desc);
    buf = (char *)cm_push(session->stack, GS_NAME_BUFFER_SIZE);
    name_len = strlen(desc.name);
    ret = strncpy_s(buf, GS_NAME_BUFFER_SIZE, desc.name, name_len);
    knl_securec_check(ret);

    if (db_write_sysrb(session, &desc) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    cm_str2text(buf, &text);
    if (db_update_table_name(session, table->desc.uid, table->desc.name, &text, GS_TRUE) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (rb_drop_index(session, table, &desc) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (rb_drop_all_cons(session, dc) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (db_check_policies_before_delete(session, table->desc.name, table->desc.uid) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    /* drop all the table privilege granted to users and roles */
    if (db_drop_object_privs(session, table->desc.uid, table->desc.name, OBJ_TYPE_TABLE) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    obj_addr.oid = dc->oid;
    obj_addr.uid = dc->uid;
    obj_addr.tid = OBJ_TYPE_TABLE;
    if (g_knl_callback.update_depender(session, &obj_addr) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (g_knl_callback.pl_db_drop_triggers(session, dc) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    if (GS_SUCCESS != stats_drop_hists(session, table->desc.uid, table->desc.id,
        IS_NOLOGGING_BY_TABLE_TYPE(table->desc.type))) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    redo.op_type = RD_DROP_TABLE;
    redo.purge = GS_FALSE;
    redo.uid = table->desc.uid;
    redo.oid = table->desc.id;
    redo.org_scn = table->desc.org_scn;
    ret = strcpy_sp(redo.name, GS_NAME_BUFFER_SIZE, table->desc.name);
    knl_securec_check(ret);
    log_put(session, RD_LOGIC_OPERATION, &redo, sizeof(rd_drop_table_t), LOG_ENTRY_FLAG_NONE);

    knl_commit(session);
    // Send rd log to drop trigger
    g_knl_callback.pl_drop_triggers_entry(session, dc);

    dc_drop_object_privs(&session->kernel->dc_ctx, table->desc.uid, table->desc.name, OBJ_TYPE_TABLE);
    dc_remove(session, DC_ENTITY(dc), &text);
    db_unreside_table_segments(session, dc);

    CM_RESTORE_STACK(session->stack);

    session->stat->table_drops++;
    return GS_SUCCESS;
}

/*
 * truncate table segment into recycle bin
 * @param kernel session, table
 * @note we set the table entry and heap segment to invalid directly instead
 * of init a new segment to it 'causing we support post-build storage now.
 */
static status_t rb_truncate_table_segment(knl_session_t *session, table_t *table)
{
    if (db_update_table_entry(session, &table->desc, INVALID_PAGID) != GS_SUCCESS) {
        return GS_ERROR;
    }

    buf_unreside_page(session, table->desc.entry);

    return GS_SUCCESS;
}

/*
 * truncate table part segment into recycle bin
 * @param kernel session, table part
 * @note we set the table part entry and segment to invalid directly instead
 * of init a new segment to it 'causing we support post-build storage now.
 */
static status_t rb_truncate_table_part_segment(knl_session_t *session, table_part_t *table_part)
{
    if (db_update_table_part_entry(session, &table_part->desc, INVALID_PAGID) != GS_SUCCESS) {
        return GS_ERROR;
    }

    buf_unreside_page(session, table_part->desc.entry);

    return GS_SUCCESS;
}

/*
 * truncate index segment into recycle bin
 * @param kernel session, index
 * @note we set the index entry and segment to invalid directly instead
 * of init a new segment to it 'causing we support post-build storage now.
 */
static status_t rb_truncate_index_segment(knl_session_t *session, index_t *index)
{
    if (db_update_index_entry(session, &index->desc, INVALID_PAGID) != GS_SUCCESS) {
        return GS_ERROR;
    }

    buf_unreside_page(session, index->desc.entry);

    return GS_SUCCESS;
}

/*
 * truncate index part segment into recycle bin
 * @param kernel session, index part
 * @note we set the index part entry and segment to invalid directly instead
 * of init a new segment to it 'causing we support post-build storage now.
 */
static status_t rb_truncate_index_part_segment(knl_session_t *session, index_part_t *index_part)
{
    bool32 is_changed = GS_FALSE;

    if (db_update_idxpart_status(session, index_part, GS_FALSE, &is_changed) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (db_upd_idx_part_entry(session, &index_part->desc, INVALID_PAGID) != GS_SUCCESS) {
        return GS_ERROR;
    }

    buf_unreside_page(session, index_part->desc.entry);

    return GS_SUCCESS;
}

/*
 * truncate lob segment into recycle bin
 * @param kernel session, lob
 * @note we set the lob entry and segment to invalid directly instead
 * of init a new segment to it 'causing we support post-build storage now.
 */
static status_t rb_truncate_lob_segment(knl_session_t *session, lob_t *lob)
{
    if (db_update_lob_entry(session, &lob->desc, INVALID_PAGID) != GS_SUCCESS) {
        return GS_ERROR;
    }

    buf_unreside_page(session, lob->desc.entry);

    return GS_SUCCESS;
}

/*
 * truncate lob part segment into recycle bin
 * @param kernel session, lob part
 * @note we set the lob part entry and segment to invalid directly instead
 * of init a new segment to it 'causing we support post-build storage now.
 */
static status_t rb_truncate_lob_part_segment(knl_session_t *session, lob_part_t *lob_part)
{
    if (db_update_lob_part_entry(session, &lob_part->desc, INVALID_PAGID) != GS_SUCCESS) {
        return GS_ERROR;
    }

    buf_unreside_page(session, lob_part->desc.entry);

    return GS_SUCCESS;
}

static status_t rb_truncate_table_subpart_segment(knl_session_t *session, table_part_t *table_subpart)
{
    if (db_update_subtabpart_entry(session, &table_subpart->desc, INVALID_PAGID) != GS_SUCCESS) {
        return GS_ERROR;
    }

    buf_unreside_page(session, table_subpart->desc.entry);

    return GS_SUCCESS;
}

static status_t rb_truncate_index_subpart_segment(knl_session_t *session, index_part_t *index_subpart)
{
    bool32 is_changed = GS_FALSE;

    if (db_update_sub_idxpart_status(session, index_subpart, GS_FALSE, &is_changed) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (db_upd_sub_idx_part_entry(session, &index_subpart->desc, INVALID_PAGID) != GS_SUCCESS) {
        return GS_ERROR;
    }

    buf_unreside_page(session, index_subpart->desc.entry);

    return GS_SUCCESS;
}

static status_t rb_truncate_lob_subpart_segment(knl_session_t *session, lob_part_t *lob_subpart)
{
    if (db_update_sublobpart_entry(session, &lob_subpart->desc, INVALID_PAGID) != GS_SUCCESS) {
        return GS_ERROR;
    }

    buf_unreside_page(session, lob_subpart->desc.entry);

    return GS_SUCCESS;
}

static status_t rb_truncate_lob_parts(knl_session_t *session, table_t *table, lob_t *lob, knl_rb_desc_t *desc)
{
    lob_part_t *lob_part = NULL;
    table_part_t *table_part = NULL;

    for (uint32 i = 0; i < table->part_table->desc.partcnt; i++) {
        lob_part = LOB_GET_PART(lob, i);
        table_part = TABLE_GET_PART(table, i);
        if (!IS_READY_PART(table_part) || lob_part == NULL || !db_lobpart_has_segment(lob->part_lob, lob_part)) {
            continue;
        }

        rb_init_lob_part_desc(session, table, &lob_part->desc, i, desc);
        if (db_write_sysrb(session, desc) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (rb_truncate_lob_part_segment(session, lob_part) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (!IS_PARENT_LOBPART(&lob_part->desc)) {
            continue;
        }

        lob_part_t *lob_subpart = NULL;
        for (uint32 j = 0; j < lob_part->desc.subpart_cnt; j++) {
            lob_subpart = PART_GET_SUBENTITY(lob->part_lob, lob_part->subparts[j]);
            if (lob_subpart == NULL || lob_subpart->lob_entity.segment == NULL) {
                continue;
            }

            rb_init_lob_part_desc(session, table, &lob_subpart->desc, j, desc);
            if (db_write_sysrb(session, desc) != GS_SUCCESS) {
                return GS_ERROR;
            }

            if (rb_truncate_lob_subpart_segment(session, lob_subpart) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
    }

    return GS_SUCCESS;
}

/*
 * truncate table lobs into recycle bin
 * @param kernel session, dc entity, table, base object id
 * @note inner interface, not expose to user
 */
static status_t rb_truncate_lobs(knl_session_t *session, dc_entity_t *entity, table_t *table, knl_rb_desc_t *desc)
{
    knl_column_t *column = NULL;
    lob_t *lob = NULL;

    for (uint32 i = 0; i < entity->column_count; i++) {
        column = dc_get_column(entity, i);
        if (!COLUMN_IS_LOB(column)) {
            continue;
        }

        lob = (lob_t *)column->lob;
        rb_init_lob_desc(session, &lob->desc, desc);
        if (db_write_sysrb(session, desc) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (!IS_PART_TABLE(table)) {
            if (rb_truncate_lob_segment(session, lob) != GS_SUCCESS) {
                return GS_ERROR;
            }

            continue;
        }

        if (rb_truncate_lob_parts(session, table, lob, desc) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t rb_truncate_part_index(knl_session_t *session, index_t *index, knl_rb_desc_t *desc)
{
    index_part_t *index_part = NULL;
    index_part_t *index_subpart = NULL;
    table_part_t *table_part = NULL;
    table_t *table = &index->entity->table;

    for (uint32 i = 0; i < index->part_index->desc.partcnt; i++) {
        index_part = INDEX_GET_PART(index, i);
        table_part = TABLE_GET_PART(table, i);
        if (!IS_READY_PART(table_part) || index_part == NULL) {
            continue;
        }

        rb_init_index_part_desc(session, index, &index_part->desc, i, desc);
        if (db_write_sysrb(session, desc) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (!IS_PARENT_IDXPART(&index_part->desc)) {
            if (rb_truncate_index_part_segment(session, index_part) != GS_SUCCESS) {
                return GS_ERROR;
            }

            continue;
        }

        for (uint32 j = 0; j < index_part->desc.subpart_cnt; j++) {
            index_subpart = PART_GET_SUBENTITY(index->part_index, index_part->subparts[j]);
            if (index_subpart == NULL) {
                continue;
            }

            rb_init_index_part_desc(session, index, &index_subpart->desc, j, desc);
            if (db_write_sysrb(session, desc) != GS_SUCCESS) {
                return GS_ERROR;
            }

            if (rb_truncate_index_subpart_segment(session, index_subpart) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
    }

    return GS_SUCCESS;
}

/*
 * truncate table indexes into recycle bin
 * @param kernel session, table, base object id
 * @note inner interface, not expose to user
 */
static status_t rb_truncate_index(knl_session_t *session, table_t *table, knl_rb_desc_t *desc)
{
    index_t *index = NULL;
    bool32 is_changed = GS_FALSE;

    for (uint32 i = 0; i < table->index_set.total_count; i++) {
        index = table->index_set.items[i];
        rb_init_index_desc(session, &index->desc, desc);
        if (db_write_sysrb(session, desc) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (!IS_PART_INDEX(index)) {
            if (db_update_index_status(session, index, GS_FALSE, &is_changed) != GS_SUCCESS) {
                return GS_ERROR;
            }

            if (rb_truncate_index_segment(session, index) != GS_SUCCESS) {
                return GS_ERROR;
            }
            continue;
        }

        if (rb_truncate_part_index(session, index, desc) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t rb_truncate_part_table(knl_session_t *session, table_t *table, knl_rb_desc_t *desc)
{
    table_part_t *table_part = NULL;

    for (uint32 i = 0; i < table->part_table->desc.partcnt; i++) {
        table_part = TABLE_GET_PART(table, i);
        if (!IS_READY_PART(table_part) || !db_tabpart_has_segment(table->part_table, table_part)) {
            continue;
        }

        rb_init_table_part_desc(session, table, &table_part->desc, desc);
        if (db_write_sysrb(session, desc) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (!IS_PARENT_TABPART(&table_part->desc)) {
            if (rb_truncate_table_part_segment(session, table_part) != GS_SUCCESS) {
                return GS_ERROR;
            }

            continue;
        }

        table_part_t *table_subpart = NULL;
        for (uint32 j = 0; j < table_part->desc.subpart_cnt; j++) {
            table_subpart = PART_GET_SUBENTITY(table->part_table, table_part->subparts[j]);
            if (table_subpart == NULL || table_subpart->heap.segment == NULL) {
                continue;
            }

            rb_init_table_part_desc(session, table, &table_subpart->desc, desc);
            if (db_write_sysrb(session, desc) != GS_SUCCESS) {
                return GS_ERROR;
            }

            if (rb_truncate_table_subpart_segment(session, table_subpart) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
    }

    return GS_SUCCESS;
}

/*
 * truncate table to recycle bin
 * Truncate table segments, index segments and lob segments to recycle bin.
 * This is different with drop table into recycle bin, we do not change the table
 * name, only change the segment entries. To generate unique object name, here we
 * use table id with session lsn.
 * For table partitions, we only truncate partition which has storage entities
 * into recycle bin.
 * @param kernel session, kernel dictionary
 * @note once we change the entry and segment in dc pool, we should invalidate the
 * entity so that the following access of this table would reload the entity.
 */
status_t rb_truncate_table(knl_session_t *session, knl_dictionary_t *dc)
{
    knl_rb_desc_t desc;
    dc_entity_t *entity = DC_ENTITY(dc);
    table_t *table = &entity->table;

    desc.uid = table->desc.uid;
    desc.base_id = session->curr_lsn;
    desc.oper = RB_OPER_TRUNCATE;
    rb_init_table_desc(session, &table->desc, &desc);

    knl_panic_log(dc->type == DICT_TYPE_TABLE, "dc type is abnormal, panic info: table %s", table->desc.name);
    if (db_write_sysrb(session, &desc) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (rb_truncate_table_segment(session, table) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (IS_PART_TABLE(table)) {
        if (rb_truncate_part_table(session, table, &desc) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    if (rb_truncate_index(session, table, &desc) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (entity->contain_lob) {
        if (rb_truncate_lobs(session, entity, table, &desc) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t rb_truncate_index_part(knl_session_t *session, knl_dictionary_t *dc, table_part_t *table_part,
    knl_rb_desc_t *desc)
{
    index_t *index = NULL;
    index_part_t *index_part = NULL;
    table_t *table = DC_TABLE(dc);
    bool32 is_changed = GS_FALSE;
    bool32 need_invalidate_index = GS_FALSE;

    if (db_need_invalidate_index(session, dc, table, table_part, &need_invalidate_index) != GS_SUCCESS) {
        return GS_ERROR;
    }

    for (uint32 i = 0; i < table->index_set.total_count; i++) {
        index = table->index_set.items[i];

        if (IS_PART_INDEX(index)) {
            index_part = INDEX_GET_PART(index, table_part->part_no);
            if (!IS_PARENT_IDXPART(&index_part->desc)) {
                rb_init_index_part_desc(session, index, &index_part->desc, index_part->part_no, desc);

                if (db_write_sysrb(session, desc) != GS_SUCCESS) {
                    return GS_ERROR;
                }

                if (rb_truncate_index_part_segment(session, index_part) != GS_SUCCESS) {
                    return GS_ERROR;
                }

                continue;
            }

            index_part_t *subpart = NULL;
            for (uint32 j = 0; j < index_part->desc.subpart_cnt; j++) {
                subpart = PART_GET_SUBENTITY(index->part_index, index_part->subparts[j]);
                if (subpart == NULL) {
                    continue;
                }

                rb_init_index_part_desc(session, index, &subpart->desc, subpart->part_no, desc);
                if (db_write_sysrb(session, desc) != GS_SUCCESS) {
                    return GS_ERROR;
                }

                if (rb_truncate_index_subpart_segment(session, subpart) != GS_SUCCESS) {
                    return GS_ERROR;
                }
            }
            continue;
        }

        if (need_invalidate_index) {
            if (db_update_index_status(session, index, GS_TRUE, &is_changed) != GS_SUCCESS) {
                return GS_ERROR;
            }
            if (btree_segment_prepare(session, index, GS_FALSE, BTREE_DROP_SEGMENT) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
    }

    return GS_SUCCESS;
}

static status_t rb_truncate_lob_part(knl_session_t *session, knl_dictionary_t *dc, table_part_t *table_part,
    knl_rb_desc_t *desc)
{
    lob_t *lob = NULL;
    lob_part_t *lob_part = NULL;
    knl_column_t *column = NULL;
    dc_entity_t *entity = DC_ENTITY(dc);

    for (uint32 i = 0; i < entity->column_count; i++) {
        column = dc_get_column(entity, i);
        if (!COLUMN_IS_LOB(column)) {
            continue;
        }

        lob = (lob_t *)column->lob;
        lob_part = LOB_GET_PART(lob, table_part->part_no);
        if (IS_PARENT_LOBPART(&lob_part->desc)) {
            lob_part_t *subpart = NULL;
            for (uint32 j = 0; j < lob_part->desc.subpart_cnt; j++) {
                subpart = PART_GET_SUBENTITY(lob->part_lob, lob_part->subparts[j]);
                if (subpart == NULL || subpart->lob_entity.segment == NULL) {
                    continue;
                }

                rb_init_lob_part_desc(session, &entity->table, &subpart->desc, j, desc);
                if (db_write_sysrb(session, desc) != GS_SUCCESS) {
                    return GS_ERROR;
                }

                if (rb_truncate_lob_subpart_segment(session, subpart) != GS_SUCCESS) {
                    return GS_ERROR;
                }
            }
        } else {
            rb_init_lob_part_desc(session, &entity->table, &lob_part->desc, table_part->part_no, desc);
            if (db_write_sysrb(session, desc) != GS_SUCCESS) {
                return GS_ERROR;
            }

            if (rb_truncate_lob_part_segment(session, lob_part) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
    }

    return GS_SUCCESS;
}

/*
 * truncate table part to recycle bin
 * Truncate table part segments, index part segments, lob part segments to
 * recycle bin.
 * For global indexes, we should invalidate them.
 * @param kernel session, dictionary, table partition
 */
status_t rb_truncate_table_part(knl_session_t *session, knl_dictionary_t *dc, table_part_t *table_part)
{
    knl_rb_desc_t desc;
    dc_entity_t *entity = DC_ENTITY(dc);
    table_t *table = &entity->table;
    desc.uid = table_part->desc.uid;
    desc.base_id = session->curr_lsn;
    desc.oper = RB_OPER_TRUNCATE;
    rb_init_table_part_desc(session, table, &table_part->desc, &desc);

    knl_panic_log(dc->type == DICT_TYPE_TABLE, "dc type is abnormal, panic info: table %s", table->desc.name);
    if (db_write_sysrb(session, &desc) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (IS_PARENT_TABPART(&table_part->desc)) {
        table_part_t *subpart = NULL;
        for (uint32 i = 0; i < table_part->desc.subpart_cnt; i++) {
            subpart = PART_GET_SUBENTITY(table->part_table, table_part->subparts[i]);
            if (subpart == NULL || subpart->heap.segment == NULL) {
                continue;
            }

            rb_init_table_part_desc(session, table, &subpart->desc, &desc);
            if (db_write_sysrb(session, &desc) != GS_SUCCESS) {
                return GS_ERROR;
            }

            if (rb_truncate_table_subpart_segment(session, subpart) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
    } else {
        if (rb_truncate_table_part_segment(session, table_part) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    if (rb_truncate_index_part(session, dc, table_part, &desc) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (entity->contain_lob) {
        if (rb_truncate_lob_part(session, dc, table_part, &desc) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t rb_truncate_index_subpart(knl_session_t *session, knl_dictionary_t *dc, table_part_t *subpart,
    knl_rb_desc_t *desc, uint32 compart_no)
{
    table_t *table = DC_TABLE(dc);
    bool32 need_invalidate_index = GS_FALSE;

    if (db_need_invalidate_index(session, dc, table, (table_part_t *)subpart, &need_invalidate_index) != GS_SUCCESS) {
        return GS_ERROR;
    }

    index_t *index = NULL;
    index_part_t *index_compart = NULL;
    index_part_t *index_subpart = NULL;
    bool32 is_changed = GS_FALSE;
    for (uint32 i = 0; i < table->index_set.total_count; i++) {
        index = table->index_set.items[i];
        if (IS_PART_INDEX(index)) {
            index_compart = INDEX_GET_PART(index, compart_no);
            index_subpart = PART_GET_SUBENTITY(index->part_index, index_compart->subparts[subpart->part_no]);
            rb_init_index_part_desc(session, index, &index_subpart->desc, index_subpart->part_no, desc);

            if (db_write_sysrb(session, desc) != GS_SUCCESS) {
                return GS_ERROR;
            }

            if (rb_truncate_index_subpart_segment(session, index_subpart) != GS_SUCCESS) {
                return GS_ERROR;
            }
            continue;
        }

        if (need_invalidate_index) {
            if (db_update_index_status(session, index, GS_TRUE, &is_changed) != GS_SUCCESS) {
                return GS_ERROR;
            }

            if (btree_segment_prepare(session, index, GS_FALSE, BTREE_DROP_SEGMENT) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
    }

    return GS_SUCCESS;
}

static status_t rb_truncate_lob_subpart(knl_session_t *session, knl_dictionary_t *dc, table_part_t *subpart,
    knl_rb_desc_t *desc, uint32 compart_no)
{
    lob_t *lob = NULL;
    lob_part_t *lob_part = NULL;
    knl_column_t *column = NULL;
    lob_part_t *lob_subpart = NULL;
    dc_entity_t *entity = DC_ENTITY(dc);

    for (uint32 i = 0; i < entity->column_count; i++) {
        column = dc_get_column(entity, i);
        if (!COLUMN_IS_LOB(column)) {
            continue;
        }

        lob = (lob_t *)column->lob;
        lob_part = LOB_GET_PART(lob, compart_no);
        lob_subpart = PART_GET_SUBENTITY(lob->part_lob, lob_part->subparts[subpart->part_no]);
        rb_init_lob_part_desc(session, &entity->table, &lob_subpart->desc, subpart->part_no, desc);

        if (db_write_sysrb(session, desc) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (rb_truncate_lob_subpart_segment(session, lob_subpart) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

status_t rb_truncate_table_subpart(knl_session_t *session, knl_dictionary_t *dc, table_part_t *subpart,
    uint32 compart_no)
{
    knl_rb_desc_t desc;
    table_t *table = DC_TABLE(dc);
    dc_entity_t *entity = DC_ENTITY(dc);

    desc.uid = subpart->desc.uid;
    desc.base_id = session->curr_lsn;
    desc.oper = RB_OPER_TRUNCATE;

    rb_init_table_part_desc(session, table, &subpart->desc, &desc);
    knl_panic_log(dc->type == DICT_TYPE_TABLE, "dc type is abnormal, panic info: table %s", table->desc.name);
    if (db_write_sysrb(session, &desc) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (rb_truncate_table_subpart_segment(session, subpart) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (rb_truncate_index_subpart(session, dc, subpart, &desc, compart_no) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (entity->contain_lob) {
        if (rb_truncate_lob_subpart(session, dc, subpart, &desc, compart_no) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

