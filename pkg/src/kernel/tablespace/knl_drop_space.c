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
 * knl_drop_space.c
 *
 *
 * IDENTIFICATION
 * src/kernel/tablespace/knl_drop_space.c
 *
 * -------------------------------------------------------------------------
 */

#include "knl_drop_space.h"
#include "knl_context.h"
#include "knl_sys_part_defs.h"
#include "knl_table.h"
#include "dtc_ckpt.h"
#include "dtc_dc.h"
#include "dtc_dls.h"
#include "knl_space_manage.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef status_t (*spc_check_func)(knl_session_t *session, knl_cursor_t *cursor, space_t *space, uint32 options);
typedef struct st_spc_obj_fetch {
    uint16 sys_tbl_id;  // relevant system table id
    uint16 spc_col_id;  // column id in system table of space id
    spc_check_func check_func;  // check objects relation in space
} spc_obj_fetch_t;

status_t spc_check_systable_objects(knl_session_t *session, knl_cursor_t *cursor, space_t *space, uint32 options);
status_t spc_check_sysindex_objects(knl_session_t *session, knl_cursor_t *cursor, space_t *space, uint32 options);
status_t spc_check_syslob_objects(knl_session_t *session, knl_cursor_t *cursor, space_t *space, uint32 options);
status_t spc_check_sys_tablepart_objects(knl_session_t *session, knl_cursor_t *cursor, space_t *space, uint32 options);
status_t spc_check_sys_indexpart_objects(knl_session_t *session, knl_cursor_t *cursor, space_t *space, uint32 options);
status_t spc_check_sys_lobpart_objects(knl_session_t *session, knl_cursor_t *cursor, space_t *space, uint32 options);
status_t spc_check_shadow_index_objects(knl_session_t *session, knl_cursor_t *cursor, space_t *space, uint32 options);
status_t spc_check_shadow_index_part_objects(knl_session_t *session, knl_cursor_t *cursor, space_t *space,
    uint32 options);
status_t spc_check_sys_partstore_objects(knl_session_t *session, knl_cursor_t *cursor, space_t *space, uint32 options);

static spc_obj_fetch_t g_spc_obj_fetch_list[] = {
    { SYS_TABLE_ID,            SYS_TABLE_COL_SPACE_ID, spc_check_systable_objects},
    { SYS_INDEX_ID,            SYS_INDEX_COLUMN_ID_SPACE, spc_check_sysindex_objects},
    { SYS_LOB_ID,              SYS_LOB_COL_SPACE_ID, spc_check_syslob_objects},
    { SYS_TABLEPART_ID,        SYS_TABLEPART_COL_SPACE_ID, spc_check_sys_tablepart_objects},
    { SYS_INDEXPART_ID,        SYS_INDEXPART_COL_SPACE_ID, spc_check_sys_indexpart_objects},
    { SYS_LOBPART_ID,          SYS_LOBPART_COL_SPACE_ID, spc_check_sys_lobpart_objects},
    { SYS_SHADOW_INDEX_ID,     SYS_SHADOW_INDEX_COL_SPACE_ID, spc_check_shadow_index_objects},
    { SYS_SHADOW_INDEXPART_ID, SYS_SHADOW_INDEXPART_COL_SPACE_ID, spc_check_shadow_index_part_objects},
    { SYS_PARTSTORE_ID,        SYS_PARTSTORE_COL_SPACE_ID, spc_check_sys_partstore_objects},
    { SYS_RB_ID,               SYS_RECYCLEBIN_COL_SPACE_ID, NULL},
    { SYS_SUB_TABLE_PARTS_ID,  SYS_TABLESUBPART_COL_SPACE_ID, spc_check_sys_tablepart_objects},
    { SYS_SUB_INDEX_PARTS_ID,  SYS_INDEXSUBPART_COL_SPACE_ID, spc_check_sys_indexpart_objects},
    { SYS_SUB_LOB_PARTS_ID,    SYS_LOBSUBPART_COL_SPACE_ID,   spc_check_sys_lobpart_objects}
};

#define SPC_OBJ_TYPE_COUNT (uint32)(sizeof(g_spc_obj_fetch_list) / sizeof(spc_obj_fetch_t))

/*
 * get space id of given user id and object id
 * @param kernel session, user id , object id , space id (return)
 */
status_t spc_get_table_space_id(knl_session_t *session, uint32 uid, uint32 oid, uint32 *space_id)
{
    knl_cursor_t *cursor = NULL;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_TABLE_ID, IX_SYS_TABLE_002_ID);
    cursor->isolevel = ISOLATION_CURR_COMMITTED;

    knl_init_index_scan(cursor, GS_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
                     (void *)&uid, sizeof(uint32), 0);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, GS_TYPE_INTEGER,
                     (void *)&oid, sizeof(uint32), 1);

    if (knl_fetch(session, cursor) != GS_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return GS_ERROR;
    }

    knl_panic_log(!cursor->eof, "data is not found, panic info: page %u-%u type %u table %s", cursor->rowid.file,
                  cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, ((table_t *)cursor->table)->desc.name);

    *space_id = (*(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_TABLE_COL_SPACE_ID));
    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

status_t spc_check_systable_objects(knl_session_t *session, knl_cursor_t *cursor, space_t *space, uint32 options)
{
    knl_table_desc_t desc;
    knl_dictionary_t dc;
    table_t *table = NULL;
    knl_drop_def_t def;
    bool32 is_found = GS_FALSE;
    errno_t ret;

    dc_convert_table_desc(cursor, &desc);
    if (desc.space_id == space->ctrl->id) {
        ret = memset_sp(&def, sizeof(knl_drop_def_t), 0, sizeof(knl_drop_def_t));
        knl_securec_check(ret);
        knl_get_user_name(session, desc.uid, &def.owner);
        cm_str2text(desc.name, &def.name);
        if (knl_open_dc_if_exists(session, &def.owner, &def.name, &dc, &is_found) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (is_found) {
            table = DC_TABLE(&dc);
            bool32 is_referenced = db_table_is_referenced(session, table, GS_FALSE);
            if (is_referenced && !SPC_DROP_CASCADE(options)) {
                GS_THROW_ERROR(ERR_DROP_SPACE_CHECK_FAILED, space->ctrl->name, "table in the space is referenced");
                knl_close_dc(&dc);
                return GS_ERROR;
            }
            knl_close_dc(&dc);
        }
    }
    return GS_SUCCESS;
}

status_t spc_check_sysindex_objects(knl_session_t *session, knl_cursor_t *cursor, space_t *space, uint32 options)
{
    uint32 table_space_id;
    knl_index_desc_t desc;

    dc_convert_index(session, cursor, &desc);
    if (desc.space_id == space->ctrl->id) {
        if (spc_get_table_space_id(session, desc.uid, desc.table_id, &table_space_id) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (table_space_id != space->ctrl->id) {
            GS_THROW_ERROR(ERR_DROP_SPACE_CHECK_FAILED, space->ctrl->name,
                           "index of table in the space was created in other space");
            return GS_ERROR;
        }
    }
    return GS_SUCCESS;
}

status_t spc_check_syslob_objects(knl_session_t *session, knl_cursor_t *cursor, space_t *space, uint32 options)
{
    knl_lob_desc_t desc;
    uint32 table_space_id;

    dc_convert_lob_desc(cursor, &desc);
    if (desc.space_id == space->ctrl->id) {
        if (spc_get_table_space_id(session, desc.uid, desc.table_id, &table_space_id) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (table_space_id != space->ctrl->id) {
            GS_THROW_ERROR(ERR_DROP_SPACE_CHECK_FAILED, space->ctrl->name,
                           "parent table of lob column is not in the same tablespace");
            return GS_ERROR;
        }
    }
    return GS_SUCCESS;
}

status_t spc_check_sys_tablepart_objects(knl_session_t *session, knl_cursor_t *cursor, space_t *space, uint32 options)
{
    knl_table_part_desc_t desc;
    uint32 table_space_id;

    dc_convert_table_part_desc(cursor, &desc);
    if (desc.space_id == space->ctrl->id) {
        if (spc_get_table_space_id(session, desc.uid, desc.table_id, &table_space_id) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (table_space_id != space->ctrl->id) {
            GS_THROW_ERROR(ERR_DROP_SPACE_CHECK_FAILED, space->ctrl->name,
                           "parent table of (sub)partition is not in the same tablespace");
            return GS_ERROR;
        }
    }
    return GS_SUCCESS;
}

status_t spc_check_sys_indexpart_objects(knl_session_t *session, knl_cursor_t *cursor, space_t *space, uint32 options)
{
    knl_index_part_desc_t desc;
    uint32 table_space_id;

    dc_convert_index_part_desc(cursor, &desc);
    if (desc.space_id == space->ctrl->id) {
        if (spc_get_table_space_id(session, desc.uid, desc.table_id, &table_space_id) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (table_space_id != space->ctrl->id) {
            GS_THROW_ERROR(ERR_DROP_SPACE_CHECK_FAILED, space->ctrl->name,
                           "parent table of index (sub)partition is not in the same tablespace");
            return GS_ERROR;
        }
    }
    return GS_SUCCESS;
}

status_t spc_check_sys_lobpart_objects(knl_session_t *session, knl_cursor_t *cursor, space_t *space, uint32 options)
{
    knl_lob_part_desc_t desc;
    uint32 table_space_id;

    dc_convert_lob_part_desc(cursor, &desc);
    if (desc.space_id == space->ctrl->id) {
        if (spc_get_table_space_id(session, desc.uid, desc.table_id, &table_space_id) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (table_space_id != space->ctrl->id) {
            GS_THROW_ERROR(ERR_DROP_SPACE_CHECK_FAILED, space->ctrl->name,
                           "parent table of lob column is not in the same tablespace");
            return GS_ERROR;
        }
    }
    return GS_SUCCESS;
}

status_t spc_check_sys_partstore_objects(knl_session_t *session, knl_cursor_t *cursor, space_t *space, uint32 options)
{
    knl_part_store_desc_t desc;
    uint32 table_space_id;

    dc_convert_part_store_desc(cursor, &desc);
    if (desc.space_id == space->ctrl->id) {
        if (spc_get_table_space_id(session, desc.uid, desc.table_id, &table_space_id) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (table_space_id != space->ctrl->id) {
            GS_THROW_ERROR(ERR_DROP_SPACE_CHECK_FAILED, space->ctrl->name,
                           "parent table of pos id is not in the same tablespace");
            return GS_ERROR;
        }
    }
    return GS_SUCCESS;
}

status_t spc_check_shadow_index_objects(knl_session_t *session, knl_cursor_t *cursor, space_t *space, uint32 options)
{
    knl_index_desc_t desc;
    uint32 table_space_id;

    dc_convert_index(session, cursor, &desc);
    if (desc.space_id == space->ctrl->id) {
        if (spc_get_table_space_id(session, desc.uid, desc.table_id, &table_space_id) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (table_space_id != space->ctrl->id) {
            GS_THROW_ERROR(ERR_DROP_SPACE_CHECK_FAILED, space->ctrl->name,
                           "parent table of shadow index is not in the same tablespace");
            return GS_ERROR;
        }
    }
    return GS_SUCCESS;
}

status_t spc_check_shadow_index_part_objects(knl_session_t *session, knl_cursor_t *cursor, space_t *space,
    uint32 options)
{
    knl_index_part_desc_t desc;
    uint32 table_space_id;

    dc_convert_index_part_desc(cursor, &desc);
    if (desc.space_id == space->ctrl->id) {
        if (spc_get_table_space_id(session, desc.uid, desc.table_id, &table_space_id) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (table_space_id != space->ctrl->id) {
            GS_THROW_ERROR(ERR_DROP_SPACE_CHECK_FAILED, space->ctrl->name,
                           "parent table of shadow index (sub)part is not in the same tablespace");
            return GS_ERROR;
        }
    }
    return GS_SUCCESS;
}

/*
 * check whether exists objects in space or not when dropping space online
 * see spc_fetch_obj_list to obtain all object types to be checked
 */
status_t spc_check_object_exist(knl_session_t *session, space_t *space)
{
    uint32 space_id;

    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);
    for (uint32 i = 0; i < SPC_OBJ_TYPE_COUNT; i++) {
        knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, g_spc_obj_fetch_list[i].sys_tbl_id, GS_INVALID_ID32);
        cursor->isolevel = ISOLATION_CURR_COMMITTED;

        for (;;) {
            if (knl_fetch(session, cursor) != GS_SUCCESS) {
                CM_RESTORE_STACK(session->stack);
                return GS_ERROR;
            }

            if (cursor->eof) {
                break;
            }

            space_id = (*(uint32 *)CURSOR_COLUMN_DATA(cursor, g_spc_obj_fetch_list[i].spc_col_id));
            if (space_id == space->ctrl->id) {
                CM_RESTORE_STACK(session->stack);
                return GS_ERROR;
            }
        }
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

uint32 spc_get_encrypt_space_count(knl_session_t *session)
{
    uint32 count = 0;
    space_t *space = NULL;

    for (uint32 i = 0; i < GS_MAX_SPACES; i++) {
        space = SPACE_GET(session, i);
        if (space->ctrl->used && SPACE_IS_ONLINE(space) && SPACE_IS_ENCRYPT(space)) {
            count++;
        }
    }

    return count;
}

status_t spc_try_inactive_swap_encrypt(knl_session_t *session)
{
    encrypt_context_t *encrypt_ctx = &session->kernel->encrypt_ctx;
    if (!encrypt_ctx->swap_encrypt_flg) {
        return GS_SUCCESS;
    }

    // has other encryption space except swap space
    if (spc_get_encrypt_space_count(session) > 0) {
        return GS_SUCCESS;
    }

    session->kernel->encrypt_ctx.swap_encrypt_flg = GS_FALSE;
    return GS_SUCCESS;
}

status_t spc_drop_sys_table_objects(knl_session_t *session, space_t *space, uint32 options)
{
    knl_cursor_t *cursor = NULL;
    uint32 space_id;
    knl_drop_def_t def;
    knl_table_desc_t desc;
    errno_t ret;

    knl_set_session_scn(session, GS_INVALID_ID64);
    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_TABLE_ID, GS_INVALID_ID32);
    cursor->isolevel = ISOLATION_CURR_COMMITTED;

    for (;;) {
        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }

        if (cursor->eof) {
            break;
        }

        space_id = (*(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_TABLE_COL_SPACE_ID));
        if (space_id == space->ctrl->id) {
            ret = memset_sp(&def, sizeof(knl_drop_def_t), 0, sizeof(knl_drop_def_t));
            knl_securec_check(ret);
            dc_convert_table_desc(cursor, &desc);
            def.purge = GS_TRUE;

            if (SPC_DROP_CASCADE(options)) {
                def.options |= DROP_CASCADE_CONS;
            }

            if (knl_get_user_name(session, desc.uid, &def.owner) != GS_SUCCESS) {
                CM_RESTORE_STACK(session->stack);
                return GS_ERROR;
            }
            cm_str2text(desc.name, &def.name);
            if (knl_internal_drop_table(session, NULL, &def) != GS_SUCCESS) {
                int code = cm_get_error_code();
                if (code == ERR_TABLE_OR_VIEW_NOT_EXIST) {
                    cm_reset_error();  // table dropped by other session, continue drop table space
                } else {
                    CM_RESTORE_STACK(session->stack);
                    GS_THROW_ERROR(ERR_TABLESPACES_IS_NOT_EMPTY, space->ctrl->name, "failed to drop object");
                    return GS_ERROR;
                }
            }
        }
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

status_t spc_drop_sys_rb_objects(knl_session_t *session, space_t *space)
{
    return rb_purge_space(session, space->ctrl->id);
}

static inline bool32 spc_contain_datafile(space_ctrl_t *ctrl, uint32 file_id)
{
    for (uint32 i = 0; i < ctrl->file_hwm; ++i) {
        if (file_id == ctrl->files[i]) {
            return GS_TRUE;
        }
    }
    return GS_FALSE;
}

void spc_remove_datafile_info(knl_session_t *session, datafile_t *df, uint32 id)
{
    df->space_id = GS_INVALID_ID32;
    df->ctrl->size = 0;
    df->ctrl->name[0] = '\0';
    df->file_no = GS_INVALID_ID32;

    if (db_save_datafile_ctrl(session, id) != GS_SUCCESS) {
        CM_ABORT(0, "[SPACE] ABORT INFO: failed to save whole control datafile ctrl when remove datafile");
    }
}

status_t spc_remove_datafile(knl_session_t *session, space_t *space, uint32 id, bool32 drop_datafile)
{
    database_t *db = &session->kernel->db;
    datafile_t *df = DATAFILE_GET(session, id);

    if (DATAFILE_IS_ONLINE(df) &&
        (space->ctrl->file_hwm == 0 || !df->ctrl->used || space->ctrl->files[df->file_no] != id)) {
        GS_LOG_RUN_ERR("[SPACE] space %s remove datafile %s failed, id=%u is not exist.", space->ctrl->name,
                       df->ctrl->name, id);
        GS_THROW_ERROR(ERR_DATAFILE_NUMBER_NOT_EXIST, id);
        return GS_ERROR;
    }

    ckpt_disable(session);
    rd_remove_datafile_daac_t *daac_redo = (rd_remove_datafile_daac_t *)cm_push(session->stack,
                                                                                sizeof(rd_remove_datafile_daac_t));
    knl_panic(daac_redo != NULL);
    daac_redo->op_type = RD_SPC_REMOVE_DATAFILE_DAAC;
    rd_remove_datafile_t *redo = &daac_redo->datafile;
    redo->id = id;
    redo->file_no = df->file_no;
    redo->space_id = df->space_id;

    log_atomic_op_begin(session);

    buf_enter_page(session, space->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);
    space->head->datafile_count--;
    space->head->hwms[df->file_no] = 0;
    log_put(session, RD_SPC_REMOVE_DATAFILE, redo, sizeof(rd_remove_datafile_t), LOG_ENTRY_FLAG_NONE);
    buf_leave_page(session, GS_TRUE);

    if (DB_IS_CLUSTER(session)) {
        log_put(session, RD_LOGIC_OPERATION, daac_redo, sizeof(rd_remove_datafile_daac_t), LOG_ENTRY_FLAG_NONE);
    }
    cm_pop(session->stack);

    SYNC_POINT_GLOBAL_START(CANTIAN_DDL_REMOVE_DATAFILE_BEFORE_LOGPUT_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;
    log_atomic_op_end(session);
    log_commit(session);

    SYNC_POINT_GLOBAL_START(CANTIAN_DDL_REMOVE_DATAFILE_AFTER_LOGPUT_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;
    space->ctrl->files[df->file_no] = GS_INVALID_ID32;
    db->ctrl.core.device_count--;

    status_t sp_ret = GS_SUCCESS;
    SYNC_POINT_GLOBAL_START(CANTIAN_DDL_REMOVE_DATAFILE_SAVE_SPC_CTRL_FAIL, &sp_ret, GS_ERROR);
    sp_ret = db_save_space_ctrl(session, space->ctrl->id);
    SYNC_POINT_GLOBAL_END;
    if (sp_ret != GS_SUCCESS) {
        CM_ABORT(0, "[SPACE] ABORT INFO: failed to save control space ctrl when remove datafile");
    }
    SYNC_POINT_GLOBAL_START(CANTIAN_DDL_REMOVE_DATAFILE_AFTER_WRITE_SPACECTRL_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;

    DATAFILE_UNSET_ONLINE(df);
    df->ctrl->used = GS_FALSE;

    SYNC_POINT_GLOBAL_START(CANTIAN_DDL_REMOVE_DATAFILE_SAVE_DF_CTRL_FAIL, &sp_ret, GS_ERROR);
    sp_ret = db_save_datafile_ctrl(session, id);
    SYNC_POINT_GLOBAL_END;
    if (sp_ret != GS_SUCCESS) {
        CM_ABORT(0, "[SPACE] ABORT INFO: failed to save the part of control datafile ctrl when remove datafile");
    }

    spc_invalidate_datafile(session, df, GS_FALSE);

    if (drop_datafile) {
        SYNC_POINT_GLOBAL_START(CANTIAN_DDL_REMOVE_DATAFILE_FAIL, &sp_ret, GS_ERROR);
        sp_ret = cm_remove_device(df->ctrl->type, df->ctrl->name);
        SYNC_POINT_GLOBAL_END;
        if (sp_ret != GS_SUCCESS) {
            ckpt_enable(session);
            GS_LOG_RUN_ERR("[DB] failed to remove datafile %s from space %s", df->ctrl->name, space->ctrl->name);
            return GS_ERROR;
        }
    }

    spc_remove_datafile_info(session, df, id);

    SYNC_POINT_GLOBAL_START(CANTIAN_DDL_REMOVE_DATAFILE_BEFORE_SYNC_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;
    if (DB_IS_CLUSTER(session)) {
        tx_copy_logic_log(session);
        if (session->logic_log_size > 0 || session->rm->logic_log_size > 0) {
            if (db_write_ddl_op(session) != GS_SUCCESS) {
                knl_panic_log(0, "[DDL]can't record logical log for session(%d)", session->id);
            }
            dtc_sync_ddl(session);
        }
    }

    SYNC_POINT_GLOBAL_START(CANTIAN_DDL_REMOVE_DATAFILE_AFTER_SYNC_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;
    ckpt_enable(session);
    GS_LOG_RUN_INF("[SPACE] space %s remove datafile %s success", space->ctrl->name, df->ctrl->name);
    return GS_SUCCESS;
}

status_t spc_drop_datafile(knl_session_t *session, space_t *space, knl_device_def_t *def)
{
    datafile_t *df = NULL;
    uint32 i;
    uint32 empty_hwm;

    for (i = 0; i < GS_MAX_DATA_FILES; i++) {
        df = DATAFILE_GET(session, i);
        if (df->ctrl->used && cm_text_str_equal(&def->name, df->ctrl->name) &&
            spc_contain_datafile(space->ctrl, i)) {
            break;
        }
    }

    if (i == GS_MAX_DATA_FILES || df == NULL) {
        GS_THROW_ERROR(ERR_FILE_NOT_EXIST, "data", T2S(&def->name));
        return GS_ERROR;
    }

    if (!DATAFILE_IS_ONLINE(df)) {
        GS_THROW_ERROR(ERR_SPACE_OFFLINE, space->ctrl->name, "remove datafile failed");
        return GS_ERROR;
    }

    empty_hwm = SPACE_IS_BITMAPMANAGED(space) ? DF_MAP_HWM_START : DF_HWM_START;
    if (df->file_no != 0 && SPACE_HEAD_RESIDENT(session, space)->hwms[df->file_no] == empty_hwm) {
        if (spc_remove_datafile(session, space, df->ctrl->id, GS_TRUE) != GS_SUCCESS) {
            return GS_ERROR;
        }
    } else {
        GS_THROW_ERROR(ERR_DATAFILE_HAS_BEEN_USED, T2S(&def->name), space->ctrl->name);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t spc_offline_datafile(knl_session_t *session, space_t *space, knl_device_def_t *def)
{
    datafile_t *df = NULL;
    rmon_t *rmon_ctx = &session->kernel->rmon_ctx;
    uint32 file_id;
    uint32 i;

    for (i = 0; i < space->ctrl->file_hwm; i++) {
        file_id = space->ctrl->files[i];
        if (GS_INVALID_ID32 == file_id) {
            continue;
        }

        df = DATAFILE_GET(session, file_id);
        if (!cm_text_str_equal(&def->name, df->ctrl->name)) {
            continue;
        }
        GS_LOG_RUN_INF("[SPACE] set datafile %s offline, space is %s ", df->ctrl->name, space->ctrl->name);
        DATAFILE_UNSET_ONLINE(df);
        if (db_save_datafile_ctrl(session, df->ctrl->id) != GS_SUCCESS) {
            CM_ABORT(0, "[SPACE] ABORT INFO: failed to save whole control file when space offline datafiles");
        }

        /* remove datafile from resource monitor */
        if (cm_exist_device(df->ctrl->type, df->ctrl->name)) {
            if (cm_rm_device_watch(df->ctrl->type, rmon_ctx->watch_fd, &df->wd) != GS_SUCCESS) {
                GS_LOG_RUN_WAR("[RMON]: failed to remove monitor of datafile %s", df->ctrl->name);
            }
        }

        return GS_SUCCESS;
    }

    GS_THROW_ERROR(ERR_OFFLINE_DATAFILE_NOT_EXIST, T2S(&def->name), space->ctrl->name);
    return GS_ERROR;
}

status_t spc_offline_datafiles(knl_session_t *session, space_t *space, galist_t *datafiles)
{
    knl_device_def_t *file = NULL;

    if (!cm_spin_try_lock(&session->kernel->lock)) {
        GS_THROW_ERROR(ERR_DB_START_IN_PROGRESS);
        return GS_ERROR;
    }

    if (session->kernel->db.status != DB_STATUS_MOUNT) {
        cm_spin_unlock(&session->kernel->lock);
        GS_THROW_ERROR(ERR_DATABASE_NOT_MOUNT, "offline datafile");
        return GS_ERROR;
    }

    if (SPACE_IS_DEFAULT(space)) {
        cm_spin_unlock(&session->kernel->lock);
        GS_THROW_ERROR(ERR_OFFLINE_WRONG_SPACE, space->ctrl->name);
        return GS_ERROR;
    }

    for (uint32 i = 0; i < datafiles->count; i++) {
        file = (knl_device_def_t *)cm_galist_get(datafiles, i);
        if (spc_offline_datafile(session, space, file) != GS_SUCCESS) {
            cm_spin_unlock(&session->kernel->lock);
            return GS_ERROR;
        }
    }

    cm_spin_unlock(&session->kernel->lock);
    return GS_SUCCESS;
}

status_t spc_drop_datafiles(knl_session_t *session, space_t *space, galist_t *datafiles)
{
    knl_device_def_t *file = NULL;

    if (session->kernel->db.status != DB_STATUS_OPEN) {
        GS_THROW_ERROR(ERR_DATABASE_NOT_OPEN, "drop datafile");
        return GS_ERROR;
    }

    if (!SPACE_IS_ONLINE(space)) {
        GS_THROW_ERROR(ERR_SPACE_OFFLINE, space->ctrl->name, "drop datafile failed");
        return GS_ERROR;
    }

    dcs_ckpt_trigger4drop(session, GS_TRUE, CKPT_TRIGGER_FULL);

    dls_spin_lock(session, &space->lock, &session->stat->spin_stat.stat_space);

    for (uint32 i = 0; i < datafiles->count; i++) {
        file = (knl_device_def_t *)cm_galist_get(datafiles, i);
        if (spc_drop_datafile(session, space, file) != GS_SUCCESS) {
            dls_spin_unlock(session, &space->lock);
            return GS_ERROR;
        }
    }

    dls_spin_unlock(session, &space->lock);

    dcs_ckpt_trigger4drop(session, GS_TRUE, CKPT_TRIGGER_FULL);

    return GS_SUCCESS;
}

static inline bool32 spc_datafile_exist(space_t *space, datafile_t *df, uint32 id)
{
    if (!DATAFILE_IS_ONLINE(df)) {
        return GS_TRUE;
    }

    if (!df->ctrl->used) {
        return GS_FALSE;
    }

    if (space->ctrl->file_hwm == 0 || (!DF_FILENO_IS_INVAILD(df) && space->ctrl->files[df->file_no] != id)) {
        return GS_FALSE;
    }

    return GS_TRUE;
}

status_t spc_remove_mount_datafile(knl_session_t *session, space_t *space, uint32 id, uint32 options)
{
    datafile_t *df = NULL;

    df = DATAFILE_GET(session, id);
    if (!DAAC_REPLAY_NODE(session) && !spc_datafile_exist(space, df, id)) {
        GS_THROW_ERROR(ERR_DATAFILE_NUMBER_NOT_EXIST, id);
        return GS_ERROR;
    }

    if (!DF_FILENO_IS_INVAILD(df)) {
        space->ctrl->files[df->file_no] = GS_INVALID_ID32;
    }

    if (DATAFILE_IS_ONLINE(df)) {
        spc_invalidate_datafile(session, df, GS_FALSE);

        if (!DAAC_REPLAY_NODE(session) && SPC_DROP_DATAFILE(options)) {
            if (cm_remove_device(df->ctrl->type, df->ctrl->name) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
    } else {
        if (SPC_DROP_DATAFILE(options)) {
            GS_LOG_RUN_INF("[SPACE] datafile %s is offline, skip drop the file in disk", df->ctrl->name);
        }
    }

    DATAFILE_UNSET_ONLINE(df);
    df->space_id = GS_INVALID_ID32;
    df->ctrl->size = 0;
    df->ctrl->name[0] = '\0';
    df->ctrl->used = GS_FALSE;
    df->file_no = GS_INVALID_ID32;
    df->ctrl->flag = 0;

    if (!DAAC_REPLAY_NODE(session) && db_save_datafile_ctrl(session, id) != GS_SUCCESS) {
        CM_ABORT(0, "[SPACE] ABORT INFO: failed to save control file when remove datafiles");
    }
    session->kernel->db.ctrl.core.device_count--;
    GS_LOG_RUN_INF("[SPACE] space %s remove mount datafile %s success", space->ctrl->name, df->ctrl->name);
    return GS_SUCCESS;
}

void spc_remove_datafile_device(knl_session_t *session, datafile_t *df)
{
    errno_t ret;
    if (cm_file_exist(df->ctrl->name)) {
        spc_invalidate_datafile(session, df, GS_TRUE);
        if (GS_SUCCESS != cm_remove_device(df->ctrl->type, df->ctrl->name)) {
            CM_ABORT(0, "[SPACE] ABORT INFO: failed to remove device when remove datafile");
        }
    } else {
        ret = sprintf_s(df->ctrl->name, GS_FILE_NAME_BUFFER_SIZE, "%s.delete", df->ctrl->name);
        knl_securec_check_ss(ret);
        if (cm_file_exist(df->ctrl->name)) {
            if (GS_SUCCESS != cm_remove_device(df->ctrl->type, df->ctrl->name)) {
                CM_ABORT(0, "[SPACE] ABORT INFO: failed to remove device when remove datafile");
            }
        }
    }
}

static void spc_wait_buffer_loaded(knl_session_t *session, space_t *space, buf_ctrl_t *ctrl)
{
    datafile_t *df = NULL;
    uint32 times = 0;

    df = DATAFILE_GET(session, ctrl->page_id.file);
    if (df->space_id == space->ctrl->id) {
        /* wait for page to be released */
        while (ctrl->load_status == (uint8)BUF_NEED_LOAD) {
            knl_try_begin_session_wait(session, READ_BY_OTHER_SESSION, GS_TRUE);
            times++;
            if (times > GS_SPIN_COUNT) {
                times = 0;
                SPIN_STAT_INC(&session->stat_page, r_sleeps);
                cm_spin_sleep();
            }
        }
        knl_try_end_session_wait(session, READ_BY_OTHER_SESSION);
    }
}

/*
 * wait for loading of space page in data buffer
 * so that we can close fd correctly in the following
 * @note caller must guarantee the space has been offlined.
 * @param kernel session , space to be removed
 */
void spc_wait_data_buffer(knl_session_t *session, space_t *space)
{
    buf_context_t *ctx = &session->kernel->buf_ctx;
    buf_set_t *buf_set = NULL;
    buf_ctrl_t *buf_ctrl = NULL;
    uint32 i, j;

    for (i = 0; i < ctx->buf_set_count; i++) {
        buf_set = &ctx->buf_set[i];
        for (j = 0; j < buf_set->hwm; j++) {
            buf_ctrl = &buf_set->ctrls[j];
            spc_wait_buffer_loaded(session, space, buf_ctrl);
        }
    }
}

void spc_reset_space(knl_session_t *session, space_t *space)
{
    errno_t ret;
    buf_expire_page(session, space->entry);
    space->is_empty = GS_FALSE;
    space->alarm_enabled = GS_FALSE;
    space->allow_extend = GS_FALSE;
    space->entry = INVALID_PAGID;
    space->swap_bitmap = GS_FALSE;
    space->head = NULL;
    space->ctrl->file_hwm = 0;
    space->ctrl->name[0] = '\0';
    space->ctrl->used = GS_FALSE;
    space->ctrl->org_scn = GS_INVALID_ID64;
    space->ctrl->flag = 0;
    space->ctrl->encrypt_version = NO_ENCRYPT;
    space->ctrl->cipher_reserve_size = 0;
    ret = memset_sp(space->ctrl->files, GS_MAX_SPACE_FILES * sizeof(uint32), 0xFF, GS_MAX_SPACE_FILES * sizeof(uint32));
    knl_securec_check(ret);
}

/*
 * space remove space
 * 1.wait for completion of visit of space page in data buffer
 * 2.remove datafiles and reset relevant info in space
 * 3.reset relevant space info
 */
status_t spc_remove_space(knl_session_t *session, space_t *space, uint32 options, bool32 ignore_error)
{
    database_t *db = &session->kernel->db;
    uint32 i;
    
    for (i = 0; i < GS_MAX_SPACE_FILES; i++) {
        if (GS_INVALID_ID32 == space->ctrl->files[i]) {
            continue;
        }

        if (spc_remove_mount_datafile(session, space, space->ctrl->files[i], options) != GS_SUCCESS) {
            if (!ignore_error) {
                return GS_ERROR;
            }
        }
    }

    spc_reset_space(session, space);

    /* if ignore_error == true, means it's remove garbage space, so the space_count has not been added */
    if (!ignore_error) {
        db->ctrl.core.space_count--;
    }

    return GS_SUCCESS;
}

status_t spc_remove_space_online(knl_session_t *session, space_t *space, uint32 options)
{
    rd_remove_space_daac_t *daac_redo = NULL;
    rd_remove_space_t *redo = NULL;

    space->is_empty = GS_TRUE;

    spc_wait_data_buffer(session, space);
    dcs_ckpt_trigger4drop(session, GS_TRUE, CKPT_TRIGGER_FULL);

    log_atomic_op_begin(session);

    daac_redo = (rd_remove_space_daac_t *)cm_push(session->stack, sizeof(rd_remove_space_daac_t));
    knl_panic(daac_redo != NULL);
    daac_redo->op_type = RD_SPC_REMOVE_SPACE_DAAC;
    redo = &daac_redo->space;
    redo->space_id = space->ctrl->id;
    redo->options = options;
    redo->org_scn = space->ctrl->org_scn;

    log_put(session, RD_SPC_REMOVE_SPACE, redo, sizeof(rd_remove_space_t), LOG_ENTRY_FLAG_NONE);
    if (DB_IS_CLUSTER(session)) {
        log_put(session, RD_LOGIC_OPERATION, daac_redo, sizeof(rd_remove_space_daac_t), LOG_ENTRY_FLAG_NONE);
    }
    cm_pop(session->stack);

    SYNC_POINT_GLOBAL_START(CANTIAN_DDL_DROP_SPACE_BEFORE_LOGPUT_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;

    ckpt_disable(session);
    log_atomic_op_end(session);
    log_commit(session);

    SYNC_POINT_GLOBAL_START(CANTIAN_DDL_DROP_SPACE_AFTER_LOGPUT_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;

    status_t status = GS_SUCCESS;
    SYNC_POINT_GLOBAL_START(CANTIAN_DDL_DROP_SPACE_FAIL, &status, GS_ERROR);
    status = spc_remove_space(session, space, options, GS_FALSE);
    SYNC_POINT_GLOBAL_END;
    if (status != GS_SUCCESS) {
        ckpt_enable(session);
        GS_LOG_RUN_ERR("[SPACE] failed to drop tablespace %s", space->ctrl->name);
        return status;
    }
    SYNC_POINT_GLOBAL_START(CANTIAN_DDL_DROP_SPACE_BEFORE_WRITE_CTRL_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;
    SYNC_POINT_GLOBAL_START(CANTIAN_DDL_DROP_SPACE_SAVE_CTRL_FAIL, &status, GS_ERROR);
    status = db_save_space_ctrl(session, space->ctrl->id);
    SYNC_POINT_GLOBAL_END;
    if (status != GS_SUCCESS) {
        CM_ABORT(0, "[SPACE] ABORT INFO: failed to save whole control file when drop tablespace");
    }
    SYNC_POINT_GLOBAL_START(CANTIAN_DDL_DROP_SPACE_AFTER_WRITE_CTRL_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;
    if (DB_IS_CLUSTER(session)) {
        tx_copy_logic_log(session);
        if (session->logic_log_size > 0 || session->rm->logic_log_size > 0) {
            if (db_write_ddl_op(session) != GS_SUCCESS) {
                knl_panic_log(0, "[DDL]can't record logical log for session(%d)", session->id);
            }
            dtc_sync_ddl(session);
        }
    }
    SYNC_POINT_GLOBAL_START(CANTIAN_DDL_DROP_SPACE_AFTER_SYNC_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;
    ckpt_enable(session);
    ckpt_trigger(session, GS_TRUE, CKPT_TRIGGER_FULL);
    return status;
}

status_t spc_drop_offlined_space(knl_session_t *session, space_t *space, uint32 options)
{
    char spc_name[GS_NAME_BUFFER_SIZE];
    uint32 name_len = GS_NAME_BUFFER_SIZE - 1;
    errno_t ret;

    ret = strncpy_s(spc_name, GS_NAME_BUFFER_SIZE, space->ctrl->name, name_len);
    knl_securec_check(ret);

    dls_spin_lock(session, &space->lock, &session->stat->spin_stat.stat_space);

    if (spc_check_object_exist(session, space) != GS_SUCCESS) {
        dls_spin_unlock(session, &space->lock);
        GS_THROW_ERROR(ERR_TABLESPACES_IS_NOT_EMPTY, space->ctrl->name,
                       "failed to check if object exists for offlined tablespace.");
        return GS_ERROR;
    }

    /* clean garbage segment no matter contents */
    if (db_clean_tablespace_garbage_seg(session, space->ctrl->id) != GS_SUCCESS) {
        dls_spin_unlock(session, &space->lock);
        return GS_ERROR;
    }

    if (spc_remove_space_online(session, space, options) != GS_SUCCESS) {
        dls_spin_unlock(session, &space->lock);
        return GS_ERROR;
    }

    dls_spin_unlock(session, &space->lock);

    if (db_save_space_ctrl(session, space->ctrl->id) != GS_SUCCESS) {
        CM_ABORT(0, "[SPACE] ABORT INFO: failed to save whole control file when drop offlined space");
    }

    GS_LOG_RUN_INF("[SPACE] succeed to drop offlined tablespace %s", spc_name);
    return GS_SUCCESS;
}

/*
 * check objects in space when dropping with including options
 * see spc_fetch_obj_list to obtain all object types to be checked
 * @param kernel session, space to be dropped, options
 */
bool32 spc_check_object_relation(knl_session_t *session, space_t *space, uint32 options)
{
    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);

    for (uint32 i = 0; i < SPC_OBJ_TYPE_COUNT; i++) {
        knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, g_spc_obj_fetch_list[i].sys_tbl_id, GS_INVALID_ID32);
        cursor->isolevel = ISOLATION_CURR_COMMITTED;

        for (;;) {
            if (knl_fetch(session, cursor) != GS_SUCCESS) {
                CM_RESTORE_STACK(session->stack);
                return GS_FALSE;
            }

            if (cursor->eof) {
                break;
            }

            if (g_spc_obj_fetch_list[i].check_func == NULL) {
                continue;
            }

            if (g_spc_obj_fetch_list[i].check_func(session, cursor, space, options) != GS_SUCCESS) {
                CM_RESTORE_STACK(session->stack);
                return GS_FALSE;
            }
        }
    }
    
    CM_RESTORE_STACK(session->stack);
    return GS_TRUE;
}

/*
 * check whether space to be dropped is user's default tablespace or tenant's usable tablespace
 */
status_t spc_check_default_tablespace(knl_session_t *session, space_t *space)
{
    knl_cursor_t *cursor = NULL;
    knl_user_desc_t desc;
    knl_tenant_desc_t tenant_desc;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_USER_ID, GS_INVALID_ID32);
    cursor->isolevel = ISOLATION_CURR_COMMITTED;

    for (;;) {
        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }

        if (cursor->eof) {
            break;
        }

        dc_convert_user_desc(cursor, &desc);
        if (desc.data_space_id == space->ctrl->id) {
            CM_RESTORE_STACK(session->stack);
            GS_THROW_ERROR(ERR_DROP_SPACE_CHECK_FAILED, space->ctrl->name, "it's the default tablespace for user");
            return GS_ERROR;
        }
    }

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_TENANTS_ID, GS_INVALID_ID32);
    cursor->isolevel = ISOLATION_CURR_COMMITTED;

    CM_MAGIC_SET(&tenant_desc, knl_tenant_desc_t);
    while (!cursor->eof) {
        if (knl_fetch(session, cursor) != GS_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return GS_ERROR;
        }

        if (cursor->eof) {
            break;
        }

        dc_convert_tenant_desc(cursor, &tenant_desc);
        if (tenant_desc.id != SYS_TENANTROOT_ID) {
            if (dc_get_tenant_tablespace_bitmap(&tenant_desc, space->ctrl->id)) {
                CM_RESTORE_STACK(session->stack);
                GS_THROW_ERROR(ERR_DROP_SPACE_CHECK_FAILED, space->ctrl->name, "it's the usable tablespace for tenant");
                return GS_ERROR;
            }
        }
    }

    CM_RESTORE_STACK(session->stack);
    return GS_SUCCESS;
}

status_t spc_drop_space_remove_objects(knl_session_t *session, space_t *space, uint32 options)
{
    if (spc_drop_sys_table_objects(session, space, options) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (spc_drop_sys_rb_objects(session, space) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t spc_drop_online_space(knl_session_t *session, space_t *space, uint32 options)
{
    char spc_name[GS_NAME_BUFFER_SIZE];
    errno_t ret;

    ret = strncpy_s(spc_name, GS_NAME_BUFFER_SIZE, space->ctrl->name, strlen(space->ctrl->name) + 1);
    knl_securec_check(ret);

    if (spc_check_default_tablespace(session, space) != GS_SUCCESS) {
        return GS_ERROR;
    }

    /* if with drop contents option, we need to check objects in space and remove them if possible */
    if (SPC_DROP_CONTENTS(options)) {
        if (!spc_check_object_relation(session, space, options)) {
            return GS_ERROR;
        }

        if (spc_drop_space_remove_objects(session, space, options) != GS_SUCCESS) {
            GS_THROW_ERROR(ERR_TABLESPACES_IS_NOT_EMPTY, space->ctrl->name, "failed to drop object");
            return GS_ERROR;
        }
    }

    /* after dropping objects in space or without drop contents option, we must guaratee space to be dropped is empty */
    if (spc_check_object_exist(session, space) != GS_SUCCESS) {
        GS_THROW_ERROR(ERR_TABLESPACES_IS_NOT_EMPTY, space->ctrl->name, "exists object");
        return GS_ERROR;
    }

    dls_spin_lock(session, &space->lock, &session->stat->spin_stat.stat_space);

    /* clean garbage segment no matter contents */
    if (db_clean_tablespace_garbage_seg(session, space->ctrl->id) != GS_SUCCESS) {
        dls_spin_unlock(session, &space->lock);
        return GS_ERROR;
    }

    if (spc_is_punching(session, space, "drop space")) {
        dls_spin_unlock(session, &space->lock);
        return GS_ERROR;
    }

    GS_LOG_RUN_INF("[SPACE] drop online space, set space %s offline", space->ctrl->name);
    SPACE_UNSET_ONLINE(space);
    /* everything is ready up to now, remove it */
    if (spc_remove_space_online(session, space, options) != GS_SUCCESS) {
        dls_spin_unlock(session, &space->lock);
        return GS_ERROR;
    }

    dls_spin_unlock(session, &space->lock);
    GS_LOG_RUN_INF("[SPACE] succeed to drop tablespace %s", spc_name);
    SYNC_POINT_GLOBAL_START(CANTIAN_DDL_DROP_SPACE_BEFORE_SYNC_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;
    return GS_SUCCESS;
}

/*
 * reset nologging tablespace's head when db restart, no matter start as primary or standby
 *
 * Notes:
 *  caller should gurantee there's no one would change spc head concurrently.
 */
static void spc_nologging_reset_head(knl_session_t *session, space_t *space)
{
    knl_instance_t *kernel = (knl_instance_t *)session->kernel;
    database_t *db = &kernel->db;
    uint32 dw_file_id = db->ctrl.core.dw_file_id;
    datafile_t *df = DATAFILE_GET(session, space->ctrl->files[0]);

    /* must be a nologging tablespace */
    knl_panic(SPACE_IS_LOGGING(space) == GS_FALSE);

    /*
     * space->head is already loaded during db_load_tablespaces and it's resident, so change it directly,
     * because we do this no matter it's master or standby, so buf_xxx interface can not be used.
     */
    knl_panic(space->head != NULL);

    SPC_UNPROTECT_HEAD(space);
    space->head->segment_count = 0;
    space->head->free_extents.count = 0;
    space->head->free_extents.first = INVALID_PAGID;
    space->head->free_extents.last = INVALID_PAGID;

    /* hwm of the first datafile starts with 2 because of including space head */
    space->head->hwms[0] = (DATAFILE_CONTAINS_DW(df, dw_file_id)) ? DW_SPC_HWM_START : DF_FIRST_HWM_START;

    for (uint32 i = 1; i < space->ctrl->file_hwm; i++) {
        space->head->hwms[i] = 1;
    }

    SPC_PROTECT_HEAD(space);
}

/*
 * 1. drop tables in it if needed;
 */
status_t spc_drop_nologging_table(knl_session_t *session)
{
    space_t *space = NULL;

    if (DB_IS_READONLY(session) || DB_IS_MAINTENANCE(session)) {
        return GS_SUCCESS;
    }

    /* drop table after undo complete, otherwise we cannot lock_table_directly when knl_internal_drop_table */
    while (DB_IN_BG_ROLLBACK(session)) {
        if (session->canceled) {
            GS_THROW_ERROR(ERR_OPERATION_CANCELED);
            return GS_ERROR;
        }

        if (session->killed) {
            GS_THROW_ERROR(ERR_OPERATION_KILLED);
            return GS_ERROR;
        }

        cm_sleep(100);
    }

    /* skip built-in tablespace */
    for (uint32 i = 0; i < GS_MAX_SPACES; i++) {
        space = SPACE_GET(session, i);
        if (!spc_need_clean(space)) {
            continue;
        }

        /* set bootstrap flag to pass dc_is_ready_for_access check */
        session->bootstrap = GS_TRUE;
        if (spc_drop_space_remove_objects(session, space, TABALESPACE_CASCADE) != GS_SUCCESS) {
            session->bootstrap = GS_FALSE;
            GS_THROW_ERROR(ERR_TABLESPACES_IS_NOT_EMPTY, space->ctrl->name, "failed to drop object");
            return GS_ERROR;
        }

        session->bootstrap = GS_FALSE;
    }

    return GS_SUCCESS;
}

/* only called when db restart, no matter restart as primary or standby */
void spc_clean_nologging_data(knl_session_t *session)
{
    space_t *space = NULL;

    /* skip built-in tablespace */
    for (uint32 i = 0; i < GS_MAX_SPACES; i++) {
        space = SPACE_GET(session, i);
        if (!spc_need_clean(space)) {
            continue;
        }

        spc_nologging_reset_head(session, space);
    }
}

#ifdef __cplusplus
}
#endif

