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
 * knl_spm.c
 *
 *
 * IDENTIFICATION
 * src/kernel/catalog/knl_spm.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_db_module.h"
#include "knl_spm.h"
#include "cm_row.h"
#include "dc_util.h"
#include "knl_context.h"
#include "knl_table.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CT_SPM_BUCKETS_COUNT (uint32)1009

#define IX_SYS_SPM_001_ID 0
#define IX_COL_SYS_SPM_001_SCHEMA 0
#define IX_COL_SYS_SPM_001_SQL_ID 1
#define IX_COL_SYS_SPM_001_SIGNATURE 2

#define IX_SYS_SPM_002_ID 1
#define IX_COL_SYS_SPM_002_PROF_NAME 0

#define IX_SYS_SPM_003_ID 2
#define IX_COL_SYS_SPM_003_SCHEMA 0
#define IX_COL_SYS_SPM_003_SQL_ID 1
#define IX_COL_SYS_SPM_003_SQL_SIGN 2

#define IX_SYS_SPM_SQLS_001_ID 0
#define IX_COL_SYS_SPM_SQLS_001_SCHEMA 0
#define IX_COL_SYS_SPM_SQLS_001_SQL_ID 1
#define IX_COL_SYS_SPM_SQLS_001_SQL_SIGN 2

#define CT_SPM_UPD_COLUMN_COUNT 9

// signature len should be buffer size
status_t spm_calculate_md5_signature(text_t *text, text_t *signature)
{
    uchar digest[CT_MD5_HASH_SIZE];
    binary_t bin;
    bin.bytes = digest;
    bin.size = CT_MD5_HASH_SIZE;
    cm_calc_md5((const uchar *)text->str, text->len, digest, &bin.size);
    return cm_bin2text(&bin, CT_FALSE, signature);
}

static inline status_t sys_spm_r_set_schema(knl_session_t *sess, row_assist_t *ra, uint32 uid)
{
    text_t schema;
    if (knl_get_user_name(sess, uid, &schema) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return row_put_text(ra, &schema);
}

static inline status_t sys_spm_r_set_sqlid(row_assist_t *ra, uint32 sql_id)
{
    char buf[CT_MAX_UINT32_STRLEN + 1] = { 0 };
    if (snprintf_s(buf, (CT_MAX_UINT32_STRLEN + 1), CT_MAX_UINT32_STRLEN, "%010u", sql_id) == -1) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, -1);
        return CT_ERROR;
    }
    return row_put_str(ra, buf);
}

static inline status_t sys_spm_r_set_txt(row_assist_t *ra, text_t *text)
{
    if (text->len > 0) {
        return row_put_text(ra, text);
    }
    return row_put_null(ra);
}

static inline status_t sys_spm_r_set_cost(row_assist_t *ra, double cost)
{
    dec8_t num;
    cm_real_to_dec8(cost, &num);
    return row_put_dec4(ra, &num);
}

static inline void knl_spm_open_sql_scan_curs(knl_session_t *session, knl_cursor_t *cursor, text_t *schema,
                                                text_t *sql_id, text_t *sql_sign, knl_cursor_action_t action)
{
    knl_set_session_scn(session, CT_INVALID_ID64);
    knl_open_sys_cursor(session, cursor, action, SYS_SPM_SQLS_ID, IX_SYS_SPM_SQLS_001_ID);
    knl_init_index_scan(cursor, CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_STRING, (void *)schema->str,
                     schema->len, IX_COL_SYS_SPM_SQLS_001_SCHEMA);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_STRING, (void *)sql_id->str,
                     sql_id->len, IX_COL_SYS_SPM_SQLS_001_SQL_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_STRING, (void *)sql_sign->str,
                     sql_sign->len, IX_COL_SYS_SPM_SQLS_001_SQL_SIGN);
}

status_t knl_spm_get_sql_txt(knl_session_t *session, text_t *schema, text_t *sql_id, text_t *sql_sign,
    text_t *sql_text)
{
    status_t status = CT_ERROR;
    knl_cursor_t *cursor = NULL;

    CM_SAVE_STACK(session->stack);
    cursor = knl_push_cursor(session);
    knl_spm_open_sql_scan_curs(session, cursor, schema, sql_id, sql_sign, CURSOR_ACTION_SELECT);

    do {
        if (knl_fetch(session, cursor) != CT_SUCCESS) {
            break;
        }
        if (cursor->eof) {
            CT_THROW_ERROR_EX(ERR_SPM_NOT_FOUND, "sql text (sql_sign: \'%s\')", T2S(sql_sign));
            break;
        }
        status = knl_spm_rd_col_lob(session, cursor, SYS_SPM_SQLS_COL_SQL_TEXT, sql_text);
    } while (0);

    CM_RESTORE_STACK(session->stack);
    return status;
}

status_t knl_spm_rd_col_lob(knl_session_t *session, knl_cursor_t *cursor, uint32 col_id, text_t *dst_text)
{
    if (dst_text->str == NULL) {
        return CT_SUCCESS;
    }

    lob_locator_t *sql_lob = (lob_locator_t *)CURSOR_COLUMN_DATA(cursor, col_id);
    uint32 lob_size = knl_lob_size(sql_lob);
    if (lob_size == 0) {
        dst_text->len = 0;
        return CT_SUCCESS;
    } else if (lob_size > dst_text->len - 1) {
        CT_THROW_ERROR(ERR_SIZE_ERROR, lob_size, dst_text->len - 1, "SPM lob column");
        return CT_ERROR;
    }
    if (knl_read_lob(session, sql_lob, 0, dst_text->str, dst_text->len, NULL, NULL) != CT_SUCCESS) {
        return CT_ERROR;
    }
    dst_text->len = lob_size;
    return CT_SUCCESS;
}

static status_t knl_ins_sys_spm_sql(knl_session_t *session, knl_spm_def_t *spm_def)
{
    knl_column_t *lob_column = NULL;
    row_assist_t ra;
    status_t status = CT_ERROR;

    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);
    cursor->scn = DB_CURR_SCN(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_INSERT, SYS_SPM_SQLS_ID, CT_INVALID_ID32);

    row_init(&ra, cursor->buf, PCRH_MAX_ROW_SIZE(session) - CT_MAX_UINT8, SYS_SPM_SQLS_COL_COLUMN_COUNT);
    do {
        if (sys_spm_r_set_schema(session, &ra, spm_def->uid) != CT_SUCCESS) {
            break;
        }
        if (sys_spm_r_set_sqlid(&ra, spm_def->sql_id) != CT_SUCCESS) {
            break;
        }
        if (sys_spm_r_set_txt(&ra, &spm_def->sql_sign) != CT_SUCCESS) {
            break;
        }
        if (row_put_date(&ra, g_timer()->now) != CT_SUCCESS) {
            break;
        }
        lob_column = knl_get_column(cursor->dc_entity, SYS_SPM_SQLS_COL_SQL_TEXT);
        if (knl_row_put_lob(session, cursor, lob_column, &spm_def->sql_text, &ra) != CT_SUCCESS) {
            break;
        }
        status = knl_internal_insert(session, cursor);
    } while (0);

    CM_RESTORE_STACK(session->stack);
    return status;
}

static status_t knl_find_sys_spm_sql(knl_session_t *session, text_t *schema, text_t *sql_id, text_t *sql_sign,
                                     bool32 *found_sql)
{
    knl_cursor_t *cursor = NULL;
    CM_SAVE_STACK(session->stack);
    cursor = knl_push_cursor(session);
    knl_set_session_scn(session, CT_INVALID_ID64);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_SPM_ID, IX_SYS_SPM_003_ID);
    knl_init_index_scan(cursor, CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_STRING, (void *)schema->str,
                     schema->len, IX_COL_SYS_SPM_003_SCHEMA);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_STRING, (void *)sql_id->str,
                     sql_id->len, IX_COL_SYS_SPM_003_SQL_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_STRING, (void *)sql_sign->str,
                     sql_sign->len, IX_COL_SYS_SPM_003_SQL_SIGN);
    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }
    *found_sql = !cursor->eof;
    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}

static status_t knl_del_sys_spm_sql(knl_session_t *session, text_t *schema, text_t *sql_id, text_t *sql_sign)
{
    knl_cursor_t *cursor = NULL;

    CM_SAVE_STACK(session->stack);
    cursor = knl_push_cursor(session);
    knl_spm_open_sql_scan_curs(session, cursor, schema, sql_id, sql_sign, CURSOR_ACTION_DELETE);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }
    if (cursor->eof) {
        CT_THROW_ERROR_EX(ERR_SPM_NOT_FOUND, "sql (sql_sign: \'%s\')", T2S(sql_sign));
        return CT_ERROR;
    }
    status_t status = knl_internal_delete(session, cursor);
    CM_RESTORE_STACK(session->stack);
    return status;
}

status_t knl_ins_sys_spm_plan(knl_session_t *session, knl_spm_def_t *spm_def)
{
    knl_column_t *lob_column = NULL;
    date_t cur_time = g_timer()->now;
    row_assist_t ra;
    status_t status = CT_ERROR;

    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);
    cursor->scn = DB_CURR_SCN(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_INSERT, SYS_SPM_ID, CT_INVALID_ID32);

    row_init(&ra, cursor->buf, PCRH_MAX_ROW_SIZE(session) - CT_MAX_UINT8, SYS_SPM_COL_COLUMN_COUNT);
    do {
        if (sys_spm_r_set_schema(session, &ra, spm_def->uid) != CT_SUCCESS) {
            break;
        }
        if (sys_spm_r_set_sqlid(&ra, spm_def->sql_id) != CT_SUCCESS) {
            break;
        }
        if (sys_spm_r_set_txt(&ra, &spm_def->sql_sign) != CT_SUCCESS) {
            break;
        }
        if (sys_spm_r_set_txt(&ra, &spm_def->signature) != CT_SUCCESS) {
            break;
        }
        (void)row_put_int32(&ra, spm_def->plan_src);
        (void)row_put_int32(&ra, spm_def->status);
        (void)row_put_int32(&ra, spm_def->last_status);
        (void)row_put_date(&ra, cur_time);
        (void)row_put_date(&ra, cur_time);
        (void)sys_spm_r_set_cost(&ra, spm_def->cost);
        (void)row_put_int32(&ra, spm_def->exec_time);
        (void)row_put_int32(&ra, spm_def->evolution);
        if (sys_spm_r_set_txt(&ra, &spm_def->prof_name) != CT_SUCCESS) {
            break;
        }
        if (sys_spm_r_set_txt(&ra, &spm_def->profile) != CT_SUCCESS) {
            break;
        }
        lob_column = knl_get_column(cursor->dc_entity, SYS_SPM_COL_OUTLINE);
        if (knl_row_put_lob(session, cursor, lob_column, &spm_def->outline, &ra) != CT_SUCCESS) {
            break;
        }
        status = knl_internal_insert(session, cursor);
    } while (0);

    CM_RESTORE_STACK(session->stack);
    return status;
}

status_t knl_ins_sys_spm(knl_session_t *session, knl_spm_def_t *spm_def)
{
    knl_savepoint_t save_point;
    knl_savepoint(session, &save_point);
    if (knl_ins_sys_spm_plan(session, spm_def) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (knl_ins_sys_spm_sql(session, spm_def) != CT_SUCCESS) {
        int32 err = cm_get_error_code();
        if (err != ERR_DUPLICATE_KEY) {
            knl_rollback(session, &save_point);
            return CT_ERROR;
        }
        cm_reset_error();
    }
    return CT_SUCCESS;
}

static inline void knl_spm_pre_plan_key_scan(knl_session_t *session, knl_cursor_t *cursor, text_t *schema,
                                                 text_t *sql_id, text_t *sign, knl_cursor_action_t action)
{
    knl_open_sys_cursor(session, cursor, action, SYS_SPM_ID, IX_SYS_SPM_001_ID);
    knl_init_index_scan(cursor, CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_STRING, (void *)schema->str,
                     schema->len, IX_COL_SYS_SPM_001_SCHEMA);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_STRING, (void *)sql_id->str,
                     sql_id->len, IX_COL_SYS_SPM_001_SQL_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_STRING, (void *)sign->str,
                     sign->len, IX_COL_SYS_SPM_001_SIGNATURE);
}

static inline void knl_spm_pre_profile_index_scan(knl_session_t *session, knl_cursor_t *cursor, text_t *prof_name,
                                                    knl_cursor_action_t action)
{
    knl_open_sys_cursor(session, cursor, action, SYS_SPM_ID, IX_SYS_SPM_002_ID);
    knl_init_index_scan(cursor, CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_STRING, (void *)prof_name->str,
                     prof_name->len, IX_COL_SYS_SPM_002_PROF_NAME);
}

static status_t knl_search_sys_spm_r(knl_session_t *session, knl_cursor_t *cursor, text_t *schema, text_t *sql_id,
                                      text_t *signature, knl_cursor_action_t action)
{
    knl_set_session_scn(session, CT_INVALID_ID64);
    knl_spm_pre_plan_key_scan(session, cursor, schema, sql_id, signature, action);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (cursor->eof) {
        CT_THROW_ERROR_EX(ERR_SPM_NOT_FOUND, "plan (signature: \'%s\')", T2S(signature));
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t knl_get_sys_spm_prof(knl_session_t *session, knl_cursor_t *cursor, text_t *prof_name,
                                          knl_cursor_action_t action)
{
    knl_set_session_scn(session, CT_INVALID_ID64);
    knl_spm_pre_profile_index_scan(session, cursor, prof_name, action);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (cursor->eof) {
        CT_THROW_ERROR_EX(ERR_SPM_NOT_FOUND, "profile (profile_name: \'%s\')", T2S(prof_name));
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t knl_upd_sys_spm(knl_session_t *session, knl_cursor_t *cursor, knl_spm_def_t *spm_def)
{
    row_assist_t ra;
    knl_update_info_t *ui = &cursor->update_info;

    row_init(&ra, ui->data, PCRH_MAX_ROW_SIZE(session) - CT_MAX_UINT8, CT_SPM_UPD_COLUMN_COUNT);
    if (sys_spm_r_set_txt(&ra, &spm_def->signature) != CT_SUCCESS) {
        return CT_ERROR;
    }
    (void)row_put_int32(&ra, spm_def->status);
    (void)row_put_int32(&ra, spm_def->last_status);
    (void)row_put_date(&ra, g_timer()->now);
    (void)sys_spm_r_set_cost(&ra, spm_def->cost);
    (void)row_put_int32(&ra, spm_def->exec_time);
    (void)row_put_int32(&ra, spm_def->evolution);
    if (sys_spm_r_set_txt(&ra, &spm_def->profile) != CT_SUCCESS) {
        return CT_ERROR;
    }
    knl_column_t *lob_column = knl_get_column(cursor->dc_entity, SYS_SPM_COL_OUTLINE);
    if (knl_row_put_lob(session, cursor, lob_column, &spm_def->outline, &ra) != CT_SUCCESS) {
        return CT_ERROR;
    }

    ui->count = 0;
    ui->columns[ui->count++] = SYS_SPM_COL_SIGNATURE;
    ui->columns[ui->count++] = SYS_SPM_COL_STATUS;
    ui->columns[ui->count++] = SYS_SPM_COL_LAST_STATUS;
    ui->columns[ui->count++] = SYS_SPM_COL_MODIFY_TIME;
    ui->columns[ui->count++] = SYS_SPM_COL_COST;
    ui->columns[ui->count++] = SYS_SPM_COL_EXEC_TIME;
    ui->columns[ui->count++] = SYS_SPM_COL_EVOLUTION;
    ui->columns[ui->count++] = SYS_SPM_COL_PROFILE;
    ui->columns[ui->count++] = SYS_SPM_COL_OUTLINE;
    cm_decode_row(ui->data, ui->offsets, ui->lens, NULL);
    return knl_internal_update(session, cursor);
}

status_t knl_upd_sys_spm_prof(knl_session_t *session, knl_spm_def_t *spm_def)
{
    knl_cursor_t *cursor = NULL;
    status_t status = CT_ERROR;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);
    do {
        if (knl_get_sys_spm_prof(session, cursor, &spm_def->prof_name, CURSOR_ACTION_UPDATE) != CT_SUCCESS) {
            break;
        }
        spm_def->last_status = *(int32 *)CURSOR_COLUMN_DATA(cursor, SYS_SPM_COL_STATUS);
        if (spm_def->last_status == SPM_STATUS_FIXED || spm_def->last_status == SPM_STATUS_ACCEPTED) {
            CT_THROW_ERROR(ERR_SPM_STATUS_NOT_ALLOWED, "alter or accept profile", "fixed or accepted");
            break;
        }
        status = knl_upd_sys_spm(session, cursor, spm_def);
    } while (0);

    CM_RESTORE_STACK(session->stack);
    return status;
}

status_t knl_spm_rd_col_txt(knl_cursor_t *cursor, uint32 col_id, text_t *dst_txt)
{
    if (dst_txt->str == NULL) {
        return CT_SUCCESS;
    }
    text_t text;
    text.str = CURSOR_COLUMN_DATA(cursor, col_id);
    text.len = CURSOR_COLUMN_SIZE(cursor, col_id);
    errno_t err = strncpy_sp(dst_txt->str, dst_txt->len, text.str, text.len);
    if (SECUREC_UNLIKELY(err != EOK)) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, err);
        return CT_ERROR;
    }
    dst_txt->len = text.len;
    return CT_SUCCESS;
}

status_t knl_spm_get_sql_sign(knl_session_t *session, text_t *schema, text_t *sql_id, text_t *plansign,
                             text_t *sqlsign)
{
    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);
    if (knl_search_sys_spm_r(session, cursor, schema, sql_id, plansign, CURSOR_ACTION_SELECT) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }
    status_t status = knl_spm_rd_col_txt(cursor, SYS_SPM_COL_SQL_SIGN, sqlsign);
    CM_RESTORE_STACK(session->stack);
    return status;
}

static status_t knl_spm_rd_plan_keys(knl_session_t *session, knl_cursor_t *cursor, knl_spm_def_t *spm_def, bool32 get_sql)
{
    text_t schema, sql_id;
    schema.str = CURSOR_COLUMN_DATA(cursor, SYS_SPM_COL_SCHEMA);
    schema.len = CURSOR_COLUMN_SIZE(cursor, SYS_SPM_COL_SCHEMA);
    if (!knl_get_user_id(session, &schema, &spm_def->uid)) {
        CT_THROW_ERROR(ERR_USER_NOT_EXIST, T2S(&schema));
        return CT_ERROR;
    }
    sql_id.str = CURSOR_COLUMN_DATA(cursor, SYS_SPM_COL_SQL_ID);
    sql_id.len = CURSOR_COLUMN_SIZE(cursor, SYS_SPM_COL_SQL_ID);
    if (cm_text2uint32(&sql_id, &spm_def->sql_id) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (knl_spm_rd_col_txt(cursor, SYS_SPM_COL_SQL_SIGN, &spm_def->sql_sign) != CT_SUCCESS) {
        return CT_ERROR;
    }

    spm_def->status = *(int32 *)CURSOR_COLUMN_DATA(cursor, SYS_SPM_COL_STATUS);
    if (spm_def->status == SPM_STATUS_ACCEPTED || spm_def->status == SPM_STATUS_FIXED) {
        if (knl_spm_rd_col_txt(cursor, SYS_SPM_COL_SIGNATURE, &spm_def->signature) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } else {
        spm_def->signature.len = 0;
    }

    if (get_sql) {
        return knl_spm_get_sql_txt(session, &schema, &sql_id, &spm_def->sql_sign, &spm_def->sql_text);
    }
    return CT_SUCCESS;
}

status_t knl_spm_fetch_prof_for_alt(knl_session_t *session, knl_spm_def_t *def)
{
    knl_cursor_t *cursor = NULL;
    status_t status = CT_SUCCESS;
    CM_SAVE_STACK(session->stack);
    cursor = knl_push_cursor(session);
    if (knl_get_sys_spm_prof(session, cursor, &def->prof_name, CURSOR_ACTION_SELECT) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }
    status = knl_spm_rd_plan_keys(session, cursor, def, CT_TRUE);
    CM_RESTORE_STACK(session->stack);
    return status;
}

status_t knl_spm_fetch_prof_for_accept(knl_session_t *session, knl_spm_def_t *def)
{
    knl_cursor_t *cursor = NULL;
    status_t status = CT_SUCCESS;
    CM_SAVE_STACK(session->stack);
    cursor = knl_push_cursor(session);
    if (knl_get_sys_spm_prof(session, cursor, &def->prof_name, CURSOR_ACTION_SELECT) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }
    if (knl_spm_rd_col_txt(cursor, SYS_SPM_COL_PROFILE, &def->profile) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }
    status = knl_spm_rd_plan_keys(session, cursor, def, CT_TRUE);
    CM_RESTORE_STACK(session->stack);
    return status;
}

status_t knl_spm_fetch_prof_for_delete(knl_session_t *session, knl_spm_def_t *def)
{
    knl_cursor_t *cursor = NULL;
    status_t status = CT_SUCCESS;
    CM_SAVE_STACK(session->stack);
    cursor = knl_push_cursor(session);
    if (knl_get_sys_spm_prof(session, cursor, &def->prof_name, CURSOR_ACTION_SELECT) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }
    status = knl_spm_rd_plan_keys(session, cursor, def, CT_FALSE);
    CM_RESTORE_STACK(session->stack);
    return status;
}

status_t knl_spm_fetch_prof_txt(knl_session_t *session, text_t *prof_name, text_t *profile)
{
    knl_cursor_t *cursor = NULL;
    CM_SAVE_STACK(session->stack);
    cursor = knl_push_cursor(session);
    if (knl_get_sys_spm_prof(session, cursor, prof_name, CURSOR_ACTION_SELECT) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }
    status_t status = knl_spm_rd_col_txt(cursor, SYS_SPM_COL_PROFILE, profile);
    CM_RESTORE_STACK(session->stack);
    return status;
}

static status_t knl_del_sys_spm_by_profile(knl_session_t *session, text_t *prof_name)
{
    knl_cursor_t *cursor = NULL;
    status_t status = CT_SUCCESS;
    CM_SAVE_STACK(session->stack);
    cursor = knl_push_cursor(session);
    if (knl_get_sys_spm_prof(session, cursor, prof_name, CURSOR_ACTION_DELETE) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }
    status = knl_internal_delete(session, cursor);
    CM_RESTORE_STACK(session->stack);
    return status;
}

static status_t knl_try_del_sys_spm_sql(knl_session_t *session, text_t *schema, text_t *sql_id, text_t *sql_sign)
{
    bool32 found_sql = CT_FALSE;
    knl_savepoint_t save_point;

    knl_savepoint(session, &save_point);
    if (knl_find_sys_spm_sql(session, schema, sql_id, sql_sign, &found_sql) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (!found_sql) {
        if (knl_del_sys_spm_sql(session, schema, sql_id, sql_sign) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
    if (knl_find_sys_spm_sql(session, schema, sql_id, sql_sign, &found_sql) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (found_sql) {
        knl_rollback(session, &save_point);
    }
    return CT_SUCCESS;
}

status_t knl_del_sys_spm_prof(knl_session_t *session, knl_spm_def_t *def)
{
    char buf[CT_MAX_UINT32_STRLEN + 1] = { 0 };
    knl_savepoint_t save_point;
    text_t schema, sql_id_txt;

    sql_id_txt.str = buf;
    sql_id_txt.len = CT_MAX_UINT32_STRLEN;
    if (snprintf_s(sql_id_txt.str, (CT_MAX_UINT32_STRLEN + 1), CT_MAX_UINT32_STRLEN, "%010u", def->sql_id) == -1) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, -1);
        return CT_ERROR;
    }

    if (knl_get_user_name(session, def->uid, &schema) != CT_SUCCESS) {
        return CT_ERROR;
    }

    knl_savepoint(session, &save_point);
    if (knl_del_sys_spm_by_profile(session, &def->prof_name) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (knl_try_del_sys_spm_sql(session, &schema, &sql_id_txt, &def->sql_sign) != CT_SUCCESS) {
        knl_rollback(session, &save_point);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t knl_deactivate_sys_spm_plan(knl_session_t *session, knl_cursor_t *cursor, int32 last_status)
{
    knl_column_t *lob_column = NULL;
    text_t null_outline = { 0 };
    knl_update_info_t *ui = &cursor->update_info;
    row_assist_t ra;
    row_init(&ra, ui->data, PCRH_MAX_ROW_SIZE(session) - CT_MAX_UINT8, 5);

    if (row_put_null(&ra) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (row_put_int32(&ra, SPM_STATUS_DISCARD) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (row_put_int32(&ra, last_status) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (row_put_date(&ra, g_timer()->now) != CT_SUCCESS) {
        return CT_ERROR;
    }
    lob_column = knl_get_column(cursor->dc_entity, SYS_SPM_COL_OUTLINE);
    if (knl_row_put_lob(session, cursor, lob_column, &null_outline, &ra) != CT_SUCCESS) {
        return CT_ERROR;
    }
    ui->count = 0;
    ui->columns[ui->count++] = SYS_SPM_COL_SIGNATURE;
    ui->columns[ui->count++] = SYS_SPM_COL_STATUS;
    ui->columns[ui->count++] = SYS_SPM_COL_LAST_STATUS;
    ui->columns[ui->count++] = SYS_SPM_COL_MODIFY_TIME;
    ui->columns[ui->count++] = SYS_SPM_COL_OUTLINE;
    cm_decode_row(ui->data, ui->offsets, ui->lens, NULL);
    return knl_internal_update(session, cursor);
}

status_t knl_deactivate_sys_spm(knl_session_t *session, text_t *schema, text_t *sql_id, text_t *signature)
{
    knl_cursor_t *cursor = NULL;

    CM_SAVE_STACK(session->stack);
    cursor = knl_push_cursor(session);
    if (knl_search_sys_spm_r(session, cursor, schema, sql_id, signature, CURSOR_ACTION_UPDATE) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }
    status_t status = knl_deactivate_sys_spm_plan(session, cursor, *(int32 *)CURSOR_COLUMN_DATA(cursor, SYS_SPM_COL_STATUS));
    CM_RESTORE_STACK(session->stack);
    return status;
}

status_t knl_del_sys_spm_plan(knl_session_t *session, text_t *schema, text_t *sql_id, text_t *signature)
{
    knl_cursor_t *cursor = NULL;
    CM_SAVE_STACK(session->stack);
    cursor = knl_push_cursor(session);
    if (knl_search_sys_spm_r(session, cursor, schema, sql_id, signature, CURSOR_ACTION_DELETE) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }
    status_t status = knl_internal_delete(session, cursor);
    CM_RESTORE_STACK(session->stack);
    return status;
}

status_t knl_del_sys_spm(knl_session_t *session, text_t *schema, text_t *sql_id, text_t *sql_sign, text_t *signature)
{
    knl_savepoint_t save_point;
    knl_savepoint(session, &save_point);
    if (knl_del_sys_spm_plan(session, schema, sql_id, signature) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (knl_try_del_sys_spm_sql(session, schema, sql_id, sql_sign) != CT_SUCCESS) {
        knl_rollback(session, &save_point);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t knl_spm_clean_schmpcr_sqls(knl_session_t *session, text_t *schema)
{
    knl_cursor_t *cursor = knl_push_cursor(session);
    knl_set_session_scn(session, CT_INVALID_ID64);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_SPM_SQLS_ID, IX_SYS_SPM_SQLS_001_ID);
    knl_init_index_scan(cursor, CT_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_STRING, (void *)schema->str,
                     schema->len, IX_COL_SYS_SPM_SQLS_001_SCHEMA);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_SPM_SQLS_001_SQL_ID);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_SPM_SQLS_001_SQL_SIGN);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_STRING, (void *)schema->str,
                     schema->len, IX_COL_SYS_SPM_SQLS_001_SCHEMA);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_SPM_SQLS_001_SQL_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_SPM_SQLS_001_SQL_SIGN);
    do {
        if (knl_fetch(session, cursor) != CT_SUCCESS) {
            return CT_ERROR;
        }
        if (cursor->eof) {
            break;
        }
        if (knl_internal_delete(session, cursor) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } while (CT_TRUE);

    return CT_SUCCESS;
}

status_t knl_clean_sys_spm_schmpcr(knl_session_t *session, text_t *schema)
{
    knl_cursor_t *cursor = NULL;
    knl_savepoint_t savepoint;
    knl_savepoint(session, &savepoint);

    CM_SAVE_STACK(session->stack);
    cursor = knl_push_cursor(session);
    knl_set_session_scn(session, CT_INVALID_ID64);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_SPM_ID, IX_SYS_SPM_001_ID);
    knl_init_index_scan(cursor, CT_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_STRING, (void *)schema->str,
                     schema->len, IX_COL_SYS_SPM_001_SCHEMA);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_SPM_001_SQL_ID);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_SPM_001_SIGNATURE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_STRING, (void *)schema->str,
                     schema->len, IX_COL_SYS_SPM_001_SCHEMA);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_SPM_001_SQL_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_SPM_001_SIGNATURE);
    do {
        if (knl_fetch(session, cursor) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            knl_rollback(session, &savepoint);
            return CT_ERROR;
        }
        if (cursor->eof) {
            break;
        }
        if (knl_internal_delete(session, cursor) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            knl_rollback(session, &savepoint);
            return CT_ERROR;
        }
    } while (CT_TRUE);

    if (knl_spm_clean_schmpcr_sqls(session, schema) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        knl_rollback(session, &savepoint);
        return CT_ERROR;
    }
    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}

void knl_spm_open_load_curs(knl_session_t *session, knl_cursor_t *cursor, text_t *schema)
{
    knl_set_session_scn(session, CT_INVALID_ID64);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_SPM_ID, IX_SYS_SPM_003_ID);
    knl_init_index_scan(cursor, CT_FALSE);
    if (schema == NULL) {
        knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_SPM_003_SCHEMA);
        knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_SPM_003_SCHEMA);
    } else {
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_STRING, (void *)schema->str,
                         schema->len, IX_COL_SYS_SPM_003_SCHEMA);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_STRING, (void *)schema->str,
                         schema->len, IX_COL_SYS_SPM_003_SCHEMA);
    }
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_SPM_003_SQL_ID);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_SPM_003_SQL_SIGN);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_SPM_003_SQL_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_SPM_003_SQL_SIGN);
}

// //////////////////////////////////////////////////////////////////////// dc_spm
status_t dc_creat_spm_context(dc_context_t *ctx)
{
    errno_t err;
    dc_spm_t *dc_spm = NULL;
    uint32 spm_size = OFFSET_OF(dc_spm_t, buckets) + sizeof(spm_bucket_t) * CT_SPM_BUCKETS_COUNT;
    if (mctx_alloc(ctx->memory, spm_size, (void **)&dc_spm) != CT_SUCCESS) {
        return CT_ERROR;
    }
    ctx->dc_spm = dc_spm;
    err = memset_sp(dc_spm, spm_size, 0, spm_size);
    if (SECUREC_UNLIKELY(err != EOK)) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, err);
        return CT_ERROR;
    }
    dc_spm->bucket_count = CT_SPM_BUCKETS_COUNT;
    return dc_create_memory_context(ctx, &dc_spm->mem_ctx);
}

status_t dc_spm_creat_plan(dc_spm_t *baseline, text_t *signature, dc_spm_plan_t **plan)
{
    *plan = (dc_spm_plan_t *)dc_list_remove(&baseline->free_list);
    if (*plan == NULL) {
        if (mctx_alloc(baseline->mem_ctx, sizeof(dc_spm_plan_t), (void **)plan) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    errno_t err = memset_sp(*plan, sizeof(dc_spm_plan_t), 0, sizeof(dc_spm_plan_t));
    if (SECUREC_UNLIKELY(err != EOK)) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, err);
        dc_list_add(&baseline->free_list, &(*plan)->ctrl.free_node);
        return CT_ERROR;
    }
    (*plan)->ctrl.hash_value = cm_hash_text(signature, INFINITE_HASH_RANGE);
    err = strncpy_sp((*plan)->plan_sign, CT_SIGN_BUF_SIZE, signature->str, signature->len);
    if (SECUREC_UNLIKELY(err != EOK)) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, err);
        dc_list_add(&baseline->free_list, &(*plan)->ctrl.free_node);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static inline status_t dc_spm_initialize_sql(dc_context_t *ctx, dc_spm_sql_t *sql, uint32 uid, uint32 sql_id,
                                       text_t *sql_sign)
{
    errno_t err = memcpy_sp(sql->sql_sign, CT_SIGN_BUF_SIZE, sql_sign->str, sql_sign->len);
    if (SECUREC_UNLIKELY(err != EOK)) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, err);
        return CT_ERROR;
    }
    sql->ctrl.hash_value = sql_id;
    sql->uid = uid;
    sql->baseline.bucket_count = CT_MAX_PLAN_VERSIONS;
    return dc_create_memory_context(ctx, &sql->baseline.mem_ctx);
}

status_t dc_spm_creat_sql(dc_context_t *ctx, uint32 uid, uint32 sql_id, text_t *sql_sign, dc_spm_sql_t **sql)
{
    errno_t err;
    dc_spm_t *dc_spm = (dc_spm_t *)ctx->dc_spm;
    uint32 spm_sql_size = OFFSET_OF(dc_spm_sql_t, baseline) + OFFSET_OF(dc_spm_t, buckets) +
                          sizeof(spm_bucket_t) * CT_MAX_PLAN_VERSIONS;

    *sql = (dc_spm_sql_t *)dc_list_remove(&dc_spm->free_list);
    if (*sql == NULL) {
        if (mctx_alloc(dc_spm->mem_ctx, spm_sql_size, (void **)sql) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
    err = memset_sp(*sql, spm_sql_size, 0, spm_sql_size);
    if (SECUREC_UNLIKELY(err != EOK)) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, err);
        return CT_ERROR;
    }
    if (dc_spm_initialize_sql(ctx, *sql, uid, sql_id, sql_sign) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

// must unlock spm_sql after used
dc_spm_sql_t *dc_spm_discover_sql(knl_session_t *session, uint32 uid, uint32 sql_id, text_t *sql_sign)
{
    dc_spm_t *spm = (dc_spm_t *)session->kernel->dc_ctx.dc_spm;
    spm_bucket_t *bucket = NULL;
    dc_spm_sql_t *spm_sql = NULL;

    bucket = &spm->buckets[sql_id % spm->bucket_count];

    cm_spin_lock(&bucket->lock, NULL);
    spm_sql = (dc_spm_sql_t *)bucket->first;

    while (spm_sql != NULL) {
        if (spm_sql->ctrl.hash_value == sql_id && spm_sql->uid == uid &&
            cm_text_str_equal(sql_sign, spm_sql->sql_sign)) {
            cm_spin_lock(&spm_sql->lock, NULL);
            if (spm_sql->invalid) {
                cm_spin_unlock(&spm_sql->lock);
                spm_sql = (dc_spm_sql_t *)spm_sql->ctrl.hash_next;
                continue;
            }
            cm_spin_unlock(&bucket->lock);
            return spm_sql; // spm_sql is locked
        }
        spm_sql = (dc_spm_sql_t *)spm_sql->ctrl.hash_next;
    }

    cm_spin_unlock(&bucket->lock);
    return spm_sql;
}

dc_spm_plan_t *dc_spm_discover_plan(dc_spm_t *baseline, text_t *signature)
{
    if (baseline->item_count == 0) {
        return NULL;
    }
    spm_bucket_t *bucket = NULL;
    dc_spm_plan_t *spm_plan = NULL;
    uint32 hash_value = cm_hash_text(signature, INFINITE_HASH_RANGE);

    bucket = &baseline->buckets[hash_value % baseline->bucket_count];

    cm_spin_lock(&bucket->lock, NULL);
    spm_plan = (dc_spm_plan_t *)bucket->first;

    while (spm_plan != NULL) {
        if (spm_plan->ctrl.hash_value == hash_value && cm_text_str_equal(signature, spm_plan->plan_sign)) {
            cm_spin_unlock(&bucket->lock);
            return spm_plan;
        }
        spm_plan = (dc_spm_plan_t *)spm_plan->ctrl.hash_next;
    }

    cm_spin_unlock(&bucket->lock);
    return spm_plan;
}

dc_spm_plan_t *dc_spm_discover_prof(dc_spm_t *baseline, text_t *prof_name)
{
    if (baseline->item_count == 0) {
        return NULL;
    }
    spm_bucket_t *bucket = NULL;
    dc_spm_plan_t *spm_plan = NULL;

    for (uint32 i = 0; i < baseline->bucket_count; i++) {
        bucket = &baseline->buckets[i];
        cm_spin_lock(&bucket->lock, NULL);
        spm_plan = (dc_spm_plan_t *)bucket->first;
        while (spm_plan != NULL) {
            if (cm_text_str_equal(prof_name, spm_plan->plan_info.prof_name)) {
                cm_spin_unlock(&bucket->lock);
                return spm_plan;
            }
            spm_plan = (dc_spm_plan_t *)spm_plan->ctrl.hash_next;
        }

        cm_spin_unlock(&bucket->lock);
    }

    return spm_plan;
}

status_t dc_spm_cache_scheme(dc_spm_sql_t *sql, dc_spm_plan_t *new_plan)
{
    dc_spm_t *baseline = &sql->baseline;
    spm_bucket_t *bucket = NULL;
    dc_spm_plan_t *cached_plan = NULL;
    uint32 hash_value = new_plan->ctrl.hash_value;

    bucket = &baseline->buckets[hash_value % baseline->bucket_count];

    cm_spin_lock(&bucket->lock, NULL);
    cached_plan = (dc_spm_plan_t *)bucket->first;

    while (cached_plan != NULL) {
        if (cached_plan->ctrl.hash_value == hash_value && cm_str_equal(new_plan->plan_sign, cached_plan->plan_sign)) {
            cm_spin_unlock(&bucket->lock);
            CT_THROW_ERROR(ERR_SPM_DUPLICATE_PLAN, new_plan->plan_sign);
            dc_spm_abandoned_plan(sql, new_plan);
            return CT_ERROR;
        }
        cached_plan = (dc_spm_plan_t *)cached_plan->ctrl.hash_next;
    }
    HASH_BUCKET_INSERT(bucket, &new_plan->ctrl);
    baseline->item_count++;
    new_plan->parent = sql;
    cm_spin_unlock(&bucket->lock);
    return CT_SUCCESS;
}

dc_spm_sql_t *dc_spm_get_cache_sql(dc_spm_t *spm, dc_spm_sql_t *new_sql)
{
    spm_bucket_t *bucket = NULL;
    dc_spm_sql_t *cached_sql = NULL;
    uint32 hash_value = new_sql->ctrl.hash_value;

    bucket = &spm->buckets[hash_value % spm->bucket_count];

    cm_spin_lock(&bucket->lock, NULL);
    cached_sql = (dc_spm_sql_t *)bucket->first;

    while (cached_sql != NULL) {
        if (cached_sql->uid == new_sql->uid && cached_sql->ctrl.hash_value == hash_value &&
            cm_str_equal(new_sql->sql_sign, cached_sql->sql_sign)) {
            cm_spin_lock(&cached_sql->lock, NULL);
            if (cached_sql->invalid) {
                cm_spin_unlock(&cached_sql->lock);
                cached_sql = (dc_spm_sql_t *)cached_sql->ctrl.hash_next;
                continue;
            }
            cm_spin_unlock(&bucket->lock);
            dc_spm_abandoned_sql(spm, new_sql);
            return cached_sql; // cached_sql is locked
        }
        cached_sql = (dc_spm_sql_t *)cached_sql->ctrl.hash_next;
    }
    cm_spin_lock(&new_sql->lock, NULL);
    HASH_BUCKET_INSERT(bucket, &new_sql->ctrl);
    spm->item_count++;
    new_sql->parent = spm;
    cm_spin_unlock(&bucket->lock);
    return new_sql; // new_sql is locked
}

void dc_spm_del_sql(dc_spm_sql_t *spm_sql)
{
    dc_spm_t *dc_spm = spm_sql->parent;
    spm_bucket_t *bucket = &dc_spm->buckets[spm_sql->ctrl.hash_value % dc_spm->bucket_count];
    cm_spin_lock(&bucket->lock, NULL);
    HASH_BUCKET_REMOVE(bucket, &spm_sql->ctrl);
    dc_spm->item_count--;
    cm_spin_unlock(&bucket->lock);
    spm_sql->parent = NULL;
    dc_spm_abandoned_sql(dc_spm, spm_sql);
}

void dc_spm_del_plan(dc_spm_plan_t *plan)
{
    dc_spm_sql_t *sql = plan->parent;
    spm_bucket_t *bucket = &sql->baseline.buckets[plan->ctrl.hash_value % sql->baseline.bucket_count];
    cm_spin_lock(&bucket->lock, NULL);
    HASH_BUCKET_REMOVE(bucket, &plan->ctrl);
    sql->baseline.item_count--;
    cm_spin_unlock(&bucket->lock);
    plan->parent = NULL;
    dc_spm_abandoned_plan(sql, plan);
}

dc_spm_plan_t *dc_spm_discover_fixed_plan(dc_spm_t *baseline)
{
    spm_bucket_t *bucket = NULL;
    dc_spm_plan_t *spm_plan = NULL;
    for (uint32 i = 0; i < baseline->bucket_count; i++) {
        bucket = &baseline->buckets[i];
        spm_plan = (dc_spm_plan_t *)bucket->first;
        cm_spin_lock(&bucket->lock, NULL);
        while (spm_plan != NULL) {
            if (spm_plan->plan_info.status == SPM_STATUS_FIXED) {
                cm_spin_unlock(&bucket->lock);
                return spm_plan;
            }
            spm_plan = (dc_spm_plan_t *)spm_plan->ctrl.hash_next;
        }
        cm_spin_unlock(&bucket->lock);
    }
    return NULL;
}

dc_spm_plan_t *dc_spm_get_optimal_plan(dc_spm_t *baseline)
{
    spm_bucket_t *bucket = NULL;
    dc_spm_plan_t *spm_plan = NULL;
    dc_spm_plan_t *opt_plan = NULL;
    double min_cost = CT_MAX_REAL;

    for (uint32 i = 0; i < baseline->bucket_count; i++) {
        bucket = &baseline->buckets[i];
        spm_plan = (dc_spm_plan_t *)bucket->first;
        cm_spin_lock(&bucket->lock, NULL);
        while (spm_plan != NULL) {
            if (spm_plan->plan_info.cost < min_cost) {
                min_cost = spm_plan->plan_info.cost;
                opt_plan = spm_plan;
            }
            spm_plan = (dc_spm_plan_t *)spm_plan->ctrl.hash_next;
        }
        cm_spin_unlock(&bucket->lock);
    }
    return opt_plan;
}

// must unlock spm_sql after used
status_t dc_spm_fetch_sql(knl_session_t *knl_session, uint32 uid, uint32 sql_id, text_t *sql_sign, dc_spm_sql_t **sql)
{
    dc_spm_sql_t *spm_sql = dc_spm_discover_sql(knl_session, uid, sql_id, sql_sign);
    if (spm_sql != NULL) {
        *sql = spm_sql; // spm_sql is locked
        return CT_SUCCESS;
    }
    if (dc_spm_creat_sql(&knl_session->kernel->dc_ctx, uid, sql_id, sql_sign, &spm_sql) != CT_SUCCESS) {
        return CT_ERROR;
    }
    *sql = dc_spm_get_cache_sql(knl_session->kernel->dc_ctx.dc_spm, spm_sql); // *sql is locked
    return CT_SUCCESS;
}

void dc_spm_make_clean(knl_session_t *session)
{
    dc_spm_t *spm = (dc_spm_t *)session->kernel->dc_ctx.dc_spm;
    if (spm->item_count == 0) {
        return;
    }
    for (uint32 i = 0; i < spm->bucket_count; i++) {
        spm_bucket_t *bucket = &spm->buckets[i];
        cm_spin_lock(&bucket->lock, NULL);
        dc_spm_sql_t *sql = (dc_spm_sql_t *)bucket->first;
        dc_spm_sql_t *next = NULL;
        while (sql != NULL) {
            next = (dc_spm_sql_t *)sql->ctrl.hash_next;
            cm_spin_lock(&sql->lock, NULL);
            if (sql->invalid) {
                cm_spin_unlock(&sql->lock);
                sql = next;
                continue;
            }
            sql->invalid = CT_TRUE;
            cm_spin_unlock(&sql->lock);

            HASH_BUCKET_REMOVE(bucket, &sql->ctrl);
            spm->item_count--;
            sql->parent = NULL;
            dc_spm_abandoned_sql(spm, sql);
            sql = next;
        }
        cm_spin_unlock(&bucket->lock);
    }
}

#ifdef __cplusplus
}
#endif
