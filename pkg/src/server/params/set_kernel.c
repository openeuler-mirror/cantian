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
 * set_kernel.c
 *
 *
 * IDENTIFICATION
 * src/server/params/set_kernel.c
 *
 * -------------------------------------------------------------------------
 */
#include "srv_module.h"
#include "srv_param.h"
#include "srv_instance.h"
#include "srv_param_common.h"
#include "cm_io_record.h"
#include "cm_log.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t sql_verify_als_page_size(void *se, void *lex, void *def)
{
    uint32 match_id;
    char *match_word[] = { "8K", "16K", "32K" };
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;
    if (lex_expected_fetch_1of3(lex, match_word[0], match_word[1], match_word[2], &match_id) != CT_SUCCESS) {
        return CT_ERROR;
    }

    PRTS_RETURN_IFERR(
        snprintf_s(sys_def->value, CT_PARAM_BUFFER_SIZE, CT_PARAM_BUFFER_SIZE - 1, "%s", match_word[match_id]));
    return CT_SUCCESS;
}

// verify the column count parameter when execute alter system set COLUMN_COUNT clause
status_t sql_verify_als_max_column_count(void *se, void *lex, void *def)
{
    uint32 match_id;
    int iret_sprintf;
    uint32 param_value;
    char *match_word[] = { "1024", "2048", "3072", "4096" };
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;
    if (lex_expected_fetch_1ofn(lex, &match_id, 4, match_word[0], match_word[1], match_word[2], match_word[3]) !=
        CT_SUCCESS) {
        return CT_ERROR;
    }

    iret_sprintf =
        snprintf_s(sys_def->value, CT_PARAM_BUFFER_SIZE, CT_PARAM_BUFFER_SIZE - 1, "%s", match_word[match_id]);
    if (iret_sprintf == -1) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, iret_sprintf);
        return CT_ERROR;
    }

    if (cm_str2uint32(sys_def->value, &param_value) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, sys_def->value);
        return CT_ERROR;
    }

    if (g_instance->kernel.attr.max_column_count > param_value) {
        CT_THROW_ERROR(ERR_UPDATE_PARAMETER_FAIL, sys_def->param, "new value should be larger than the current value");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_verify_als_ini_trans(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (num > CT_MAX_TRANS || num < 1) {
        CT_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "INI_TRANS", (int64)1, (int64)CT_MAX_TRANS);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_verify_als_cr_mode(void *se, void *lex, void *def)
{
    uint32 match_id;
    int iret_sprintf;
    char *match_word[] = { "PAGE", "ROW" };
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;
    if (lex_expected_fetch_1of2(lex, match_word[0], match_word[1], &match_id) != CT_SUCCESS) {
        return CT_ERROR;
    }

    iret_sprintf = sprintf_s(sys_def->value, CT_PARAM_BUFFER_SIZE, "%s", match_word[match_id]);
    if (iret_sprintf == -1) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, iret_sprintf);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_verify_als_row_format(void *se, void *lex, void *def)
{
    uint32 match_id;
    int iret_sprintf;
    char *match_word[] = { "ASF", "CSF" };
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;
    if (lex_expected_fetch_1of2(lex, match_word[0], match_word[1], &match_id) != CT_SUCCESS) {
        return CT_ERROR;
    }

    iret_sprintf = sprintf_s(sys_def->value, CT_PARAM_BUFFER_SIZE, "%s", match_word[match_id]);
    if (iret_sprintf == -1) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, iret_sprintf);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_verify_als_undo_segments(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (num < CT_MIN_UNDO_SEGMENT || num > CT_MAX_UNDO_SEGMENT) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "_UNDO_SEGMENTS");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t sql_verify_als_active_undo_segments(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (num > g_instance->kernel.attr.undo_segments || num < CT_MIN_UNDO_SEGMENT || num > CT_MAX_UNDO_SEGMENT) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "_UNDO_ACTIVE_SEGMENTS");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t sql_verify_als_undo_prefetch_pages(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (num < CT_MIN_UNDO_PREFETCH_PAGES) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "UNDO_PREFETCH_PAGE_NUM", (uint32)CT_MIN_UNDO_PREFETCH_PAGES);
        return CT_ERROR;
    }
    if (num > CT_MAX_UNDO_PREFETCH_PAGES) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "UNDO_PREFETCH_PAGE_NUM", (uint32)CT_MAX_UNDO_PREFETCH_PAGES);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_verify_als_auton_trans_segments(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (num >= g_instance->kernel.attr.undo_segments || num < CT_MIN_AUTON_TRANS_SEGMENT ||
        num >= CT_MAX_UNDO_SEGMENT) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "_UNDO_AUTON_TRANS_SEGMENTS");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t sql_notify_als_active_undo_segments(void *se, void *item, char *value)
{
    uint32 active_undo_segments = 0;
    uint32 old_active_segments = g_instance->kernel.attr.undo_active_segments;
    knl_session_t *session = (knl_session_t *)se;

    if (cm_str2uint32(value, &active_undo_segments) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (active_undo_segments > g_instance->kernel.attr.undo_segments) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "_UNDO_ACTIVE_SEGMENTS", (int64)g_instance->kernel.attr.undo_segments);
        return CT_ERROR;
    }

    if (active_undo_segments < CT_MIN_UNDO_SEGMENT) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "_UNDO_ACTIVE_SEGMENTS", (int64)CT_MIN_UNDO_SEGMENT);
        return CT_ERROR;
    }

    g_instance->kernel.attr.undo_active_segments = active_undo_segments;
    if ((active_undo_segments < old_active_segments) && g_instance->kernel.attr.undo_auto_shrink_inactive) {
        session->kernel->smon_ctx.shrink_inactive = CT_TRUE;
    }

    return CT_SUCCESS;
}

status_t sql_notify_als_auton_trans_segments(void *se, void *item, char *value)
{
    uint32 auton_trans_segments;

    if (cm_str2uint32(value, &auton_trans_segments) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (auton_trans_segments >= g_instance->kernel.attr.undo_segments) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "_UNDO_AUTON_TRANS_SEGMENTS",
            (int64)g_instance->kernel.attr.undo_segments - 1);
        return CT_ERROR;
    }

    if (auton_trans_segments < CT_MIN_AUTON_TRANS_SEGMENT) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "_UNDO_AUTON_TRANS_SEGMENTS", (int64)CT_MIN_AUTON_TRANS_SEGMENT);
        return CT_ERROR;
    }

    g_instance->kernel.attr.undo_auton_trans_segments = auton_trans_segments;
    return CT_SUCCESS;
}

status_t sql_notify_als_undo_auton_bind_own_seg(void *se, void *item, char *value)
{
    g_instance->kernel.attr.undo_auton_bind_own = (bool32)value[0];
    return sql_notify_als_bool(se, item, value);
}

status_t sql_notify_als_undo_auto_shrink(void *se, void *item, char *value)
{
    g_instance->kernel.attr.undo_auto_shrink = (bool32)value[0];
    // restore value for alter config.
    return sql_notify_als_bool(se, item, value);
}

status_t sql_notify_als_undo_auto_shrink_inactive(void *se, void *item, char *value)
{
    knl_session_t *session = (knl_session_t *)se;
    g_instance->kernel.attr.undo_auto_shrink_inactive = (bool32)value[0];
    if (g_instance->kernel.attr.undo_auto_shrink_inactive) {
        session->kernel->smon_ctx.shrink_inactive = CT_TRUE;
    }

    return sql_notify_als_bool(se, item, value);
}

status_t sql_notify_als_undo_prefetch_pages(void *se, void *item, char *value)
{
    uint32 undo_prefetch_page_num = 0;
    CT_RETURN_IFERR(cm_str2uint32(value, &undo_prefetch_page_num));
    g_instance->kernel.attr.undo_prefetch_page_num = (uint32)undo_prefetch_page_num;
    return CT_SUCCESS;
}

status_t sql_verify_als_rollback_proc_num(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (num < CT_MIN_ROLLBACK_PROC || num > CT_MAX_ROLLBACK_PROC) {
        CT_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "_TX_ROLLBACK_PROC_NUM", (int64)CT_MIN_ROLLBACK_PROC,
            (int64)CT_MAX_ROLLBACK_PROC);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t sql_verify_als_data_buffer_size(void *se, void *lex, void *def)
{
    return sql_verify_pool_size(lex, def, CT_MIN_DATA_BUFFER_SIZE, CT_MAX_SGA_BUF_SIZE);
}

status_t sql_verify_als_page_clean_period(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t sql_notify_als_page_clean_period(void *se, void *item, char *value)
{
    uint32 period = 0;
    CT_RETURN_IFERR(cm_str2uint32(value, &period));
    g_instance->kernel.attr.page_clean_period = (uint32)period;
    return CT_SUCCESS;
}

status_t sql_verify_als_page_clean_ratio(void *se, void *lex, void *def)
{
    double num;
    word_t word;
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;

    if (lex_expected_fetch((lex_t *)lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (word.type == WORD_TYPE_STRING) {
        sql_remove_quota(&word.text.value);
        cm_trim_text(&word.text.value);
    }

    if (word.type == WORD_TYPE_DQ_STRING) {
        cm_trim_text(&word.text.value);
    }

    if (word.text.len == 0) {
        CT_SRC_THROW_ERROR(word.loc, ERR_EMPTY_STRING_NOT_ALLOWED);
        return CT_ERROR;
    }

    if (cm_text2real((text_t *)&word.text, &num)) {
        return CT_ERROR;
    }

    cm_text2str((text_t *)&word.text, sys_def->value, CT_PARAM_BUFFER_SIZE);

    if (num > CT_MAX_PAGE_CLEAN_RATIO || num < CT_MIN_PAGE_CLEAN_RATIO) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "BUFFER_PAGE_CLEAN_RATIO");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_notify_als_page_clean_ratio(void *se, void *item, char *value)
{
    if (cm_str2real(value, &g_instance->kernel.attr.page_clean_ratio) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t sql_verify_als_lru_search_threshold(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (num > CT_MAX_LRU_SEARCH_THRESHOLD || num < CT_MIN_LRU_SEARCH_THRESHOLD) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "BUFFER_LRU_SEARCH_THRE");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_notify_als_lru_search_threshold(void *se, void *item, char *value)
{
    uint32 ratio = 1;
    CT_RETURN_IFERR(cm_str2uint32(value, &ratio));
    g_instance->kernel.attr.lru_search_threshold = (uint32)ratio;
    return CT_SUCCESS;
}

status_t sql_notify_als_delay_cleanout(void *se, void *item, char *value)
{
    g_instance->kernel.attr.delay_cleanout = (bool32)value[0];
    return sql_notify_als_bool(se, item, value);
}

status_t sql_verify_als_cr_pool_size(void *se, void *lex, void *def)
{
    return sql_verify_pool_size(lex, def, CT_MIN_CR_POOL_SIZE, CT_MAX_SGA_BUF_SIZE);
}

status_t sql_verify_als_cr_pool_count(void *se, void *lex, void *def)
{
    uint32 value;
    if (sql_verify_uint32(lex, def, &value) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (value > CT_MAX_CR_POOL_COUNT || value < 1) {
        CT_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "CR_POOL_COUNT", (int64)1, (int64)CT_MAX_CR_POOL_COUNT);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_verify_als_buf_pool_num(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (num > CT_MAX_BUF_POOL_NUM || num < 1) {
        CT_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "BUFFER_POOL_NUMBER", (int64)1, (int64)CT_MAX_BUF_POOL_NUM);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_verify_als_default_extents(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (num != 8 && num != 16 && num != 32 && num != 64 && num != 128) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "DEFAULT_EXTENTS");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_notify_als_default_extents(void *se, void *item, char *value)
{
    uint32 val;
    if (cm_str2uint32(value, &val) != CT_SUCCESS) {
        return CT_ERROR;
    }

    g_instance->kernel.attr.default_extents = val;
    return CT_SUCCESS;
}

status_t sql_verify_als_default_space_type(void *se, void *lex, void *def)
{
    uint32 match_id;
    int iret_sprintf;
    char *match_word[] = { "NORMAL", "BITMAP" };
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;

    if (lex_expected_fetch_1of2(lex, match_word[0], match_word[1], &match_id) != CT_SUCCESS) {
        return CT_ERROR;
    }

    iret_sprintf = sprintf_s(sys_def->value, CT_PARAM_BUFFER_SIZE, "%s", match_word[match_id]);
    if (iret_sprintf == -1) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, iret_sprintf);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_verify_als_tablespace_alarm_threshold(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "TABLESPACE_USAGE_ALARM_THRESHOLD");
        return CT_ERROR;
    }

    if (num > CT_MAX_SPC_ALARM_THRESHOLD) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "TABLESPACE_USAGE_ALARM_THRESHOLD");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_verify_als_undo_alarm_threshold(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "UNDO_USAGE_ALARM_THRESHOLD");
        return CT_ERROR;
    }

    if (num > CT_MAX_UNDO_ALARM_THRESHOLD) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "UNDO_USAGE_ALARM_THRESHOLD", (int64)CT_MAX_UNDO_ALARM_THRESHOLD);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_verify_als_txn_undo_alarm_threshold(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "TXN_UNDO_USAGE_ALARM_THRESHOLD");
        return CT_ERROR;
    }

    if (num > CT_MAX_TXN_UNDO_ALARM_THRESHOLD) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "TXN_UNDO_USAGE_ALARM_THRESHOLD",
            (int64)CT_MAX_TXN_UNDO_ALARM_THRESHOLD);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_verify_als_systime_increase_threshold(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "_SYSTIME_INCREASE_THREASHOLD");
        return CT_ERROR;
    }

    if (num > CT_MAX_SYSTIME_INC_THRE) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "_SYSTIME_INCREASE_THREASHOLD");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_notify_als_tablespace_alarm_threshold(void *se, void *item, char *value)
{
    uint32 val;
    knl_session_t *session = (knl_session_t *)se;
    if (cm_str2uint32(value, &val) != CT_SUCCESS) {
        return CT_ERROR;
    }
    session->kernel->attr.spc_usage_alarm_threshold = val;
    return CT_SUCCESS;
}

status_t sql_notify_als_undo_alarm_threshold(void *se, void *item, char *value)
{
    uint32 val;
    knl_session_t *session = (knl_session_t *)se;
    if (cm_str2uint32(value, &val) != CT_SUCCESS) {
        return CT_ERROR;
    }
    session->kernel->attr.undo_usage_alarm_threshold = val;
    return CT_SUCCESS;
}

status_t sql_notify_als_txn_undo_alarm_threshold(void *se, void *item, char *value)
{
    uint32 val;
    knl_session_t *session = (knl_session_t *)se;
    if (cm_str2uint32(value, &val) != CT_SUCCESS) {
        return CT_ERROR;
    }
    session->kernel->attr.txn_undo_usage_alarm_threshold = val;
    return CT_SUCCESS;
}

status_t sql_notify_als_systime_increase_threshold(void *se, void *item, char *value)
{
    uint32 val;
    knl_session_t *session = (knl_session_t *)se;
    if (cm_str2uint32(value, &val) != CT_SUCCESS) {
        return CT_ERROR;
    }
    session->kernel->attr.systime_inc_threshold = (uint64)DAY2SECONDS(val);
    return CT_SUCCESS;
}

status_t sql_notify_als_vmp_caches(void *se, void *item, char *value)
{
    return cm_str2uint32(value, &g_instance->kernel.attr.vmp_cache_pages);
}

status_t sql_verify_als_vma_size(void *se, void *lex, void *def)
{
    return sql_verify_pool_size(lex, def, CT_MIN_VMA_SIZE, CT_MAX_SGA_BUF_SIZE);
}

status_t sql_verify_als_large_vma_size(void *se, void *lex, void *def)
{
    return sql_verify_pool_size(lex, def, CT_MIN_LARGE_VMA_SIZE, CT_MAX_SGA_BUF_SIZE);
}

status_t sql_verify_als_shared_pool_size(void *se, void *lex, void *def)
{
    return sql_verify_pool_size(lex, def, CT_MIN_SHARED_POOL_SIZE, CT_MAX_SGA_BUF_SIZE);
}

status_t sql_verify_als_sql_pool_fat(void *se, void *lex, void *def)
{
    double num;
    word_t word;
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;

    if (lex_expected_fetch((lex_t *)lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (word.type == WORD_TYPE_STRING) {
        sql_remove_quota(&word.text.value);
    }

    if (word.type == WORD_TYPE_DQ_STRING) {
        cm_trim_text(&word.text.value);
    }

    if (word.text.len == 0) {
        CT_SRC_THROW_ERROR(word.loc, ERR_EMPTY_STRING_NOT_ALLOWED);
        return CT_ERROR;
    }

    if (cm_text2real((text_t *)&word.text, &num)) {
        return CT_ERROR;
    }

    CT_RETURN_IFERR(cm_text2str((text_t *)&word.text, sys_def->value, CT_PARAM_BUFFER_SIZE));

    if (num > CT_MAX_SQL_POOL_FACTOR || num < CT_MIN_SQL_POOL_FACTOR) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "_SQL_POOL_FACTOR");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_verify_als_large_pool_size(void *se, void *lex, void *def)
{
    return sql_verify_pool_size(lex, def, CT_MIN_LARGE_POOL_SIZE, CT_MAX_SGA_BUF_SIZE);
}

status_t sql_verify_als_log_buffer_size(void *se, void *lex, void *def)
{
    return sql_verify_pool_size(lex, def, CT_MIN_LOG_BUFFER_SIZE, CT_MAX_LOG_BUFFER_SIZE);
}

status_t sql_verify_als_log_buffer_count(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (num > CT_MAX_LOG_BUFFERS) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "LOG_BUFFER_COUNT", (int64)CT_MAX_LOG_BUFFERS);
        return CT_ERROR;
    }

    if (num <= 0) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "LOG_BUFFER_COUNT", (int64)CT_MIN_LOG_BUFFERS);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_verify_als_temp_buffer_size(void *se, void *lex, void *def)
{
    return sql_verify_pool_size(lex, def, CT_MIN_TEMP_BUFFER_SIZE, CT_MAX_TEMP_BUFFER_SIZE);
}

status_t sql_verify_als_max_temp_tables(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (num < CT_RESERVED_TEMP_TABLES) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "MAX_TEMP_TABLES", (int64)CT_RESERVED_TEMP_TABLES);
        return CT_ERROR;
    }

    if (num > CT_MAX_TEMP_TABLES) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "MAX_TEMP_TABLES", (int64)CT_MAX_TEMP_TABLES);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t sql_verify_als_temp_pool_num(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (num > CT_MAX_TEMP_POOL_NUM || num < 1) {
        CT_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "TEMP_POOL_NUM", (int64)1, (int64)CT_MAX_TEMP_POOL_NUM);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t sql_notify_als_vm_func_stack_count(void *se, void *item, char *value)
{
    uint32 count;
    knl_session_t *knl_sess = se;

    CT_RETURN_IFERR(cm_str2uint32(value, &count));
    if (g_vm_max_stack_count == count) {
        return CT_SUCCESS;
    }

    vm_pool_t *pool = knl_sess->temp_pool;
    cm_spin_lock(&pool->lock, NULL);
    if (pool->func_stacks == NULL) {
        g_vm_max_stack_count = count;
        cm_spin_unlock(&pool->lock);
        return CT_SUCCESS;
    }

    for (uint32 i = 0; i < g_vm_max_stack_count; i++) {
        vm_func_stack_t *func_stack = pool->func_stacks[i];
        if (func_stack != NULL) {
            free(func_stack);
            continue;
        }
    }

    free(pool->func_stacks);
    pool->func_stacks = NULL;
    g_vm_max_stack_count = count;
    cm_spin_unlock(&pool->lock);
    return CT_SUCCESS;
}

status_t sql_verify_als_max_link_tables(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (num > CT_MAX_LINK_TABLES) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "MAX_LINK_TABLES", (int64)CT_MAX_LINK_TABLES);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t sql_verify_als_index_buffer_size(void *se, void *lex, void *def)
{
    return sql_verify_pool_size(lex, def, CT_MIN_INDEX_CACHE_SIZE, CT_MAX_SGA_BUF_SIZE);
}

status_t sql_verify_als_checkpoint_interval(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (num == 0) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "CHECKPOINT_PAGES", (int64)1);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_verify_als_checkpoint_timeout(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (num == 0) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "CHECKPOINT_PERIOD", (int64)1);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_verify_als_checkpoint_io_capacity(void *se, void *lex, void *def)
{
    knl_session_t *session = (knl_session_t *)se;
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (num == 0) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "CHECKPOINT_IO_CAPACITY", (int64)1);
        return CT_ERROR;
    }

    if (num > CT_CKPT_GROUP_SIZE(session)) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "CHECKPOINT_IO_CAPACITY", (int64)CT_CKPT_GROUP_SIZE(session));
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_notify_als_ckpt_period(void *se, void *item, char *value)
{
    uint32 period = 0;
    CT_RETURN_IFERR(cm_str2uint32(value, &period));
    g_instance->kernel.attr.ckpt_timeout = (uint32)period;
    return CT_SUCCESS;
}

status_t sql_notify_als_ckpt_pages(void *se, void *item, char *value)
{
    uint32 page_count = 0;
    CT_RETURN_IFERR(cm_str2uint32(value, &page_count));
    g_instance->kernel.attr.ckpt_interval = (uint32)page_count;
    return CT_SUCCESS;
}

status_t sql_notify_als_ckpt_io_capacity(void *se, void *item, char *value)
{
    uint32 io_capacity = 0;
    CT_RETURN_IFERR(cm_str2uint32(value, &io_capacity));
    g_instance->kernel.attr.ckpt_io_capacity = (uint32)io_capacity;
    return CT_SUCCESS;
}

status_t sql_notify_als_ckpt_merge_io(void *se, void *item, char *value)
{
    g_instance->kernel.attr.ckpt_flush_neighbors = value[0];
    return sql_notify_als_bool(se, item, value);
}

status_t sql_notify_als_ini_trans(void *se, void *item, char *value)
{
    uint32 val;
    if (cm_str2uint32(value, &val) != CT_SUCCESS) {
        return CT_ERROR;
    }

    g_instance->kernel.attr.initrans = val;
    return CT_SUCCESS;
}

status_t sql_verify_als_auto_index_recycle(void *se, void *lex, void *def)
{
    uint32 match_id;
    char *match_word[] = { "ON", "OFF" };
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;
    if (lex_expected_fetch_1of2(lex, match_word[0], match_word[1], &match_id) != CT_SUCCESS) {
        return CT_ERROR;
    }

    PRTS_RETURN_IFERR(
        snprintf_s(sys_def->value, CT_PARAM_BUFFER_SIZE, CT_PARAM_BUFFER_SIZE - 1, "%s", match_word[match_id]));
    return CT_SUCCESS;
}

status_t sql_verify_als_index_recycle_percent(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (num > CT_MAX_INDEX_RECYCLE_PERCENT) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "_INDEX_RECYCLE_PERCENT", (int64)CT_MAX_INDEX_RECYCLE_PERCENT);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_verify_als_force_index_recycle(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (num > CT_MAX_INDEX_FORCE_RECYCLE) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "_FORCE_INDEX_RECYCLE", (int64)CT_MAX_INDEX_FORCE_RECYCLE);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_verify_als_index_auto_rebuild_start_time(void *se, void *lex, void *def)
{
    CT_RETURN_IFERR(sql_verify_als_comm(se, lex, def));
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;
    knl_session_t *session = (knl_session_t *)se;
    CT_RETURN_IFERR(srv_get_index_auto_rebuild(sys_def->value, &session->kernel->attr));
    return CT_SUCCESS;
}

status_t sql_notify_als_index_auto_rebuild(void *se, void *item, char *value)
{
    knl_session_t *session = (knl_session_t *)se;
    struct st_knl_instance *kernel = session->kernel;
    knl_session_t *rebuild_session = kernel->sessions[SESSION_ID_IDX_REBUILD];

    CT_LOG_RUN_INF("index auto rebuild swicth from state %u to %u", kernel->attr.idx_auto_rebuild, (bool32)value[0]);

    if (kernel->attr.idx_auto_rebuild && !(bool32)value[0]) {
        rebuild_session->canceled = CT_TRUE;
    }
    session->kernel->attr.idx_auto_rebuild = (bool32)value[0];
    return sql_notify_als_bool(se, item, value);
}

status_t sql_verify_als_index_recycle_reuse(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (num > CT_MAX_INDEX_RECYCLE_REUSE) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "_INDEX_RECYCLE_REUSE", (int64)CT_MAX_INDEX_RECYCLE_REUSE);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_verify_als_index_rebuild_keep_storage(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (num > CT_MAX_INDEX_REBUILD_STORAGE) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "_INDEX_REBUILD_KEEP_STORAGE", (int64)CT_MAX_INDEX_REBUILD_STORAGE);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_verify_als_index_recycle_size(void *se, void *lex, void *def)
{
    return sql_verify_pool_size(lex, def, CT_MIN_INDEX_RECYCLE_SIZE, CT_MAX_INDEX_RECYCLE_SIZE);
}

status_t sql_notify_als_auto_index_recycle(void *se, void *item, char *value)
{
    knl_session_t *session = (knl_session_t *)se;
    knl_attr_t *attr = &session->kernel->attr;
    if (cm_str_equal_ins(value, "ON")) {
        attr->idx_auto_recycle = CT_TRUE;
    } else if (cm_str_equal_ins(value, "OFF")) {
        attr->idx_auto_recycle = CT_FALSE;
    } else {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "_AUTO_INDEX_RECYCLE");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_notify_als_index_recycle_percent(void *se, void *item, char *value)
{
    uint32 val;
    knl_session_t *session = (knl_session_t *)se;
    if (cm_str2uint32(value, &val) != CT_SUCCESS) {
        return CT_ERROR;
    }
    session->kernel->attr.idx_recycle_percent = val;
    return CT_SUCCESS;
}

status_t sql_notify_als_index_recycle_size(void *se, void *item, char *value)
{
    int64 val;
    knl_session_t *session = (knl_session_t *)se;
    if (cm_str2size(value, &val) != CT_SUCCESS) {
        return CT_ERROR;
    }
    session->kernel->attr.idx_recycle_size = (uint64)val;
    return CT_SUCCESS;
}

status_t sql_notify_als_index_recycle_reuse(void *se, void *item, char *value)
{
    uint32 val;
    knl_session_t *session = (knl_session_t *)se;
    if (cm_str2uint32(value, &val) != CT_SUCCESS) {
        return CT_ERROR;
    }
    session->kernel->attr.idx_recycle_reuse_time = val;
    return CT_SUCCESS;
}

status_t sql_notify_als_force_index_recycle(void *se, void *item, char *value)
{
    uint32 val;
    knl_session_t *session = (knl_session_t *)se;
    if (cm_str2uint32(value, &val) != CT_SUCCESS) {
        return CT_ERROR;
    }
    session->kernel->attr.idx_force_recycle_time = val;
    return CT_SUCCESS;
}

status_t sql_notify_als_index_rebuild_keep_storage(void *se, void *item, char *value)
{
    uint32 val;
    knl_session_t *session = (knl_session_t *)se;
    if (cm_str2uint32(value, &val) != CT_SUCCESS) {
        return CT_ERROR;
    }
    session->kernel->attr.idx_rebuild_keep_storage_time = val;
    return CT_SUCCESS;
}

status_t sql_notify_als_backup_log_parallel(void *se, void *item, char *value)
{
    g_instance->kernel.attr.backup_log_prealloc = (bool32)value[0];
    return sql_notify_als_bool(se, item, value);
}

status_t sql_notify_als_lsnd_wait_time(void *se, void *item, char *value)
{
    uint32 val;
    knl_session_t *session = (knl_session_t *)se;
    if (cm_str2uint32(value, &val) != CT_SUCCESS) {
        return CT_ERROR;
    }
    session->kernel->attr.lsnd_wait_time = val;
    return CT_SUCCESS;
}

status_t sql_verify_als_private_key_locks(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (num < CT_MIN_PRIVATE_LOCKS) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "_PRIVATE_KEY_LOCKS", (int64)CT_MIN_PRIVATE_LOCKS);
        return CT_ERROR;
    }

    if (num > CT_MAX_PRIVATE_LOCKS) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "_PRIVATE_KEY_LOCKS", (int64)CT_MAX_PRIVATE_LOCKS);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_notify_als_private_key_locks(void *se, void *item, char *value)
{
    uint32 num;
    if (cm_str2uint32(value, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }

    g_instance->kernel.attr.private_key_locks = (uint8)num;
    return CT_SUCCESS;
}

status_t sql_verify_als_private_row_locks(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (num < CT_MIN_PRIVATE_LOCKS) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "_PRIVATE_ROW_LOCKS", (int64)CT_MIN_PRIVATE_LOCKS);
        return CT_ERROR;
    }

    if (num > CT_MAX_PRIVATE_LOCKS) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "_PRIVATE_ROW_LOCKS", (int64)CT_MAX_PRIVATE_LOCKS);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_notify_als_private_row_locks(void *se, void *item, char *value)
{
    uint32 num;
    if (cm_str2uint32(value, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }

    g_instance->kernel.attr.private_row_locks = (uint8)num;
    return CT_SUCCESS;
}

status_t sql_verify_als_commit_logging(void *se, void *lex, void *def)
{
    uint32 match_id;
    char *match_word[] = { "IMMEDIATE", "BATCH" };
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;

    if (lex_expected_fetch_1of2(lex, match_word[0], match_word[1], &match_id) != CT_SUCCESS) {
        return CT_ERROR;
    }

    PRTS_RETURN_IFERR(
        snprintf_s(sys_def->value, CT_PARAM_BUFFER_SIZE, CT_PARAM_BUFFER_SIZE - 1, "%s", match_word[match_id]));
    return CT_SUCCESS;
}

status_t sql_notify_als_commit_mode(void *se, void *item, char *value)
{
    knl_session_t *session = (knl_session_t *)se;

    if (cm_str_equal_ins(value, "BATCH")) {
        g_instance->kernel.attr.commit_batch = CT_TRUE;
        session->commit_batch = CT_TRUE;
    } else if (cm_str_equal_ins(value, "IMMEDIATE")) {
        g_instance->kernel.attr.commit_batch = CT_FALSE;
        session->commit_batch = CT_FALSE;
    } else {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER_ENUM, "COMMIT_MODE", value);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t sql_verify_als_commit_wait(void *se, void *lex, void *def)
{
    uint32 match_id;
    char *match_word[] = { "WAIT", "NOWAIT" };
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;

    if (lex_expected_fetch_1of2(lex, match_word[0], match_word[1], &match_id) != CT_SUCCESS) {
        return CT_ERROR;
    }

    PRTS_RETURN_IFERR(
        snprintf_s(sys_def->value, CT_PARAM_BUFFER_SIZE, CT_PARAM_BUFFER_SIZE - 1, "%s", match_word[match_id]));
    return CT_SUCCESS;
}

status_t sql_notify_als_commit_wait_logging(void *se, void *item, char *value)
{
    knl_session_t *session = (knl_session_t *)se;

    if (cm_str_equal_ins(value, "NOWAIT")) {
        g_instance->kernel.attr.commit_nowait = CT_TRUE;
        session->commit_nowait = CT_TRUE;
    } else if (cm_str_equal_ins(value, "WAIT")) {
        g_instance->kernel.attr.commit_nowait = CT_FALSE;
        session->commit_nowait = CT_FALSE;
    } else {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER_ENUM, "COMMIT_WAIT_LOGGING", value);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t sql_verify_als_dbwr_processes(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (!(num > 0 && num <= CT_MAX_DBWR_PROCESS)) {
        CT_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "DBWR_PROCESSES", (int64)1, (int64)CT_MAX_DBWR_PROCESS);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_verify_als_rcy_params(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (num > CT_MAX_PARAL_RCY || num < CT_DEFAULT_PARAL_RCY) {
        CT_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "LOG_REPLAY_PROCESSES", (int64)CT_DEFAULT_PARAL_RCY,
            (int64)CT_MAX_PARAL_RCY);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t sql_verify_als_rcy_preload_process(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (num > CT_MAX_PARAL_RCY) {
        CT_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "REPLAY_PRELOAD_PROCESSES", 0, (int64)CT_MAX_PARAL_RCY);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t sql_verify_als_rcy_sleep_interval(void *se, void *lex, void *def)
{
    uint32 interval;
    if (sql_verify_uint32(lex, def, &interval) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (interval < CT_MIN_RCY_SLEEP_INTERVAL || interval > CT_MAX_RCY_SLEEP_INTERVAL) {
        CT_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "_RCY_SLEEP_INTERVAL", (int64)CT_MIN_RCY_SLEEP_INTERVAL,
            (int64)CT_MAX_RCY_SLEEP_INTERVAL);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_notify_als_rcy_sleep_interval(void *se, void *item, char *value)
{
    uint32 interval;
    CT_RETURN_IFERR(cm_str2uint32(value, &interval));
    g_instance->kernel.attr.rcy_sleep_interval = interval;
    return CT_SUCCESS;
}

status_t sql_verify_als_cpu_node_bind(void *se, void *lex, void *def)
{
    bool32 is_string = CT_FALSE;
    word_t word;
    uint32 lo_num, hi_num, nprocs;
    lex_t *lexer = (lex_t *)lex;
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;

    CT_RETURN_IFERR(lex_expected_fetch(lexer, &word));
    if (word.type == WORD_TYPE_STRING) {
        sql_remove_quota(&word.text.value);
        cm_trim_text(&word.text.value);
        CT_RETURN_IFERR(lex_push(lexer, &word.text));
        is_string = CT_TRUE;
        CT_RETURN_IFERR(lex_expected_fetch(lexer, &word));
    }

    if (word.text.len == 0) {
        CT_SRC_THROW_ERROR(word.loc, ERR_EMPTY_STRING_NOT_ALLOWED);
        return CT_ERROR;
    }
    CT_RETURN_IFERR(cm_text2uint32(&word.text.value, &lo_num));
    CT_RETURN_IFERR(lex_expected_fetch(lexer, &word));
    if (word.text.len == 0) {
        CT_SRC_THROW_ERROR(word.loc, ERR_EMPTY_STRING_NOT_ALLOWED);
        return CT_ERROR;
    }

    CT_RETURN_IFERR(cm_text2uint32(&word.text.value, &hi_num));
    if (is_string) {
        lex_pop(lexer);
    }

    nprocs = cm_sys_get_nprocs() - 1;
    if (hi_num > nprocs || hi_num < lo_num) {
        CT_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "CPU_NODE_BIND", (int64)0, (int64)nprocs);
        return CT_ERROR;
    }

    *(uint32 *)sys_def->value = lo_num;
    *(uint32 *)(sys_def->value + sizeof(uint32)) = hi_num;
    return CT_SUCCESS;
}

status_t sql_notify_als_cpu_node_bind(void *se, void *item, char *value)
{
    uint32 cpu_lo, cpu_hi;
    cpu_lo = *(uint32 *)value;
    cpu_hi = *(uint32 *)(value + sizeof(uint32));
    g_instance->kernel.attr.cpu_bind_lo = cpu_lo;
    g_instance->kernel.attr.cpu_bind_hi = cpu_hi;
    g_instance->kernel.attr.cpu_count = cpu_hi - cpu_lo + 1;
    PRTS_RETURN_IFERR(snprintf_s(value, CT_PARAM_BUFFER_SIZE, CT_PARAM_BUFFER_SIZE - 1, "%u %u", cpu_lo, cpu_hi));
    return rsrc_calc_cpuset(cpu_lo, cpu_hi, GET_RSRC_MGR->plan);
}

status_t sql_verify_als_qos_ctrl_fat(void *se, void *lex, void *def)
{
    double num;
    word_t word;
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;
    if (lex_expected_fetch((lex_t *)lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (word.type == WORD_TYPE_STRING) {
        sql_remove_quota(&word.text.value);
        cm_trim_text(&word.text.value);
    }

    if (word.type == WORD_TYPE_DQ_STRING) {
        cm_trim_text(&word.text.value);
    }

    if (word.text.len == 0) {
        CT_SRC_THROW_ERROR(word.loc, ERR_EMPTY_STRING_NOT_ALLOWED);
        return CT_ERROR;
    }

    if (cm_text2real((text_t *)&word.text, &num)) {
        return CT_ERROR;
    }

    CT_RETURN_IFERR(cm_text2str((text_t *)&word.text, sys_def->value, CT_PARAM_BUFFER_SIZE));
    if (num > CT_MAX_QOS_CTRL_FACTOR || num <= CT_MIN_QOS_CTRL_FACTOR) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "_QOS_CTRL_FACTOR");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_verify_als_qos_slee_time(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (num == 0) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "_QOS_SLEEP_TIME");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_verify_als_qos_rand_range(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (num == 0) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "_QOS_RANDOM_RANGE");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_notify_als_enable_qos(void *se, void *item, char *value)
{
    // match id specified by ddl_parser.c:sql_parse_alsys_set
    g_instance->kernel.attr.enable_qos = (bool32)value[0];
    // restore value for alter config.
    return sql_notify_als_bool(se, item, value);
}

status_t sql_notify_als_qos_ctrl(void *se, void *item, char *value)
{
    if (cm_str2real(value, &g_instance->kernel.attr.qos_factor) != CT_SUCCESS) {
        return CT_ERROR;
    }

    g_instance->kernel.attr.qos_threshold =
        (uint32)(int32)(g_instance->kernel.attr.cpu_count * g_instance->kernel.attr.qos_factor);
    return CT_SUCCESS;
}

status_t sql_notify_als_qos_sleep_time(void *se, void *item, char *value)
{
    return cm_str2uint32(value, &g_instance->kernel.attr.qos_sleep_time);
}

status_t sql_notify_als_qos_random_range(void *se, void *item, char *value)
{
    return cm_str2uint32(value, &g_instance->kernel.attr.qos_random_range);
}

status_t sql_notify_als_disable_soft_parse(void *se, void *item, char *value)
{
    // _DISABLE_SOFT_PARSE only effect in config file.
#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
    // match id specified by ddl_parser.c:sql_parse_alsys_set
    g_instance->kernel.attr.disable_soft_parse = (bool32)value[0];
#endif
    // restore value for alter config.
    return sql_notify_als_bool(se, item, value);
}

status_t sql_verify_als_db_block_checksum(void *se, void *lex, void *def)
{
    uint32 match_id;
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;
    if (lex_expected_fetch_1of3((lex_t *)lex, "OFF", "TYPICAL", "FULL", &match_id) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (match_id == 0) {
        PRTS_RETURN_IFERR(snprintf_s(sys_def->value, CT_PARAM_BUFFER_SIZE, CT_PARAM_BUFFER_SIZE - 1, "OFF"));
    } else if (match_id == 1) {
        PRTS_RETURN_IFERR(snprintf_s(sys_def->value, CT_PARAM_BUFFER_SIZE, CT_PARAM_BUFFER_SIZE - 1, "TYPICAL"));
    } else {
        PRTS_RETURN_IFERR(snprintf_s(sys_def->value, CT_PARAM_BUFFER_SIZE, CT_PARAM_BUFFER_SIZE - 1, "FULL"));
    }
    return CT_SUCCESS;
}

status_t sql_verify_als_db_isolevel(void *se, void *lex, void *def)
{
    uint32 match_id;
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;
    if (lex_expected_fetch_1of2((lex_t *)lex, "RC", "CC", &match_id) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (match_id == 0) {
        sys_def->value[0] = (char)ISOLATION_READ_COMMITTED;
    } else {
        sys_def->value[0] = (char)ISOLATION_CURR_COMMITTED;
    }
    return CT_SUCCESS;
}

status_t sql_notify_als_db_isolevel_value(void *se, void *item, char *value)
{
    int iret_snprintf;
    if ((uint8)value[0] == (uint8)ISOLATION_READ_COMMITTED) {
        iret_snprintf = snprintf_s(value, CT_PARAM_BUFFER_SIZE, CT_PARAM_BUFFER_SIZE - 1, "RC");
    } else {
        iret_snprintf = snprintf_s(value, CT_PARAM_BUFFER_SIZE, CT_PARAM_BUFFER_SIZE - 1, "CC");
    }

    if (iret_snprintf == -1) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, (iret_snprintf));
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t sql_notify_als_db_isolevel(void *se, void *item, char *value)
{
    g_instance->kernel.attr.db_isolevel = (uint8)value[0];
    return sql_notify_als_db_isolevel_value(se, item, value);
}

status_t sql_verify_als_thread_stack_size(void *se, void *lex, void *def)
{
    return sql_verify_pool_size(lex, def, CT_MIN_THREAD_STACK_SIZE, CT_MAX_THREAD_STACK_SIZE - CT_STACK_DEPTH_SLOP);
}

status_t sql_verify_als_undo_reserve_size(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (num < CT_UNDO_MIN_RESERVE_SIZE) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "UNDO_RESERVE_SIZE", (int64)CT_UNDO_MIN_RESERVE_SIZE);
        return CT_ERROR;
    } else if (num > CT_UNDO_MAX_RESERVE_SIZE) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "UNDO_RESERVE_SIZE", (int64)CT_UNDO_MAX_RESERVE_SIZE);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_verify_als_undo_retention_time(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (num < 1) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "UNDO_RETENTION_TIME", (int64)1);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_notify_als_undo_reserve_size(void *se, void *item, char *value)
{
    uint32 reserve_size;
    if (cm_str2uint32(value, &reserve_size) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (reserve_size < CT_UNDO_MIN_RESERVE_SIZE) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "UNDO_RESERVE_SIZE", (int64)CT_UNDO_MIN_RESERVE_SIZE);
        return CT_ERROR;
    } else if (reserve_size > CT_UNDO_MAX_RESERVE_SIZE) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "UNDO_RESERVE_SIZE", (int64)CT_UNDO_MAX_RESERVE_SIZE);
        return CT_ERROR;
    }

    g_instance->kernel.attr.undo_reserve_size = reserve_size;
    return CT_SUCCESS;
}

status_t sql_notify_als_undo_retention_time(void *se, void *item, char *value)
{
    uint32 retention_time;
    if (cm_str2uint32(value, &retention_time) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (retention_time < 1) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "UNDO_RETENTION_TIME", (int64)1);
        return CT_ERROR;
    }

    g_instance->kernel.attr.undo_retention_time = retention_time;
    g_instance->kernel.undo_ctx.retention = retention_time;
    return CT_SUCCESS;
}

status_t sql_notify_als_index_defer_recycle_time(void *se, void *item, char *value)
{
    uint32 val;
    if (cm_str2uint32(value, &val) != CT_SUCCESS) {
        return CT_ERROR;
    }

    g_instance->kernel.attr.index_defer_recycle_time = val;

    return CT_SUCCESS;
}

status_t sql_verify_als_xa_suspend_timeout(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (num < 1) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "XA_SUSPEND_TIMEOUT", (int64)1);
        return CT_ERROR;
    }

    if (num > CT_MAX_SUSPEND_TIMEOUT) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "XA_SUSPEND_TIMEOUT", (int64)CT_MAX_SUSPEND_TIMEOUT);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_notify_als_xa_suspend_timeout(void *se, void *item, char *value)
{
    uint32 timeout;
    if (cm_str2uint32(value, &timeout) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (timeout < 1) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "XA_SUSPEND_TIMEOUT", (int64)1);
        return CT_ERROR;
    }

    if (timeout > CT_MAX_SUSPEND_TIMEOUT) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "XA_SUSPEND_TIMEOUT", (int64)CT_MAX_SUSPEND_TIMEOUT);
        return CT_ERROR;
    }

    g_instance->kernel.attr.xa_suspend_timeout = timeout;
    return CT_SUCCESS;
}

status_t sql_notify_als_lock_wait_timeout(void *se, void *item, char *value)
{
    uint32 val;
    if (cm_str2uint32(value, &val) != CT_SUCCESS) {
        return CT_ERROR;
    }

    g_instance->kernel.attr.lock_wait_timeout = val;
    return CT_SUCCESS;
}

status_t sql_notify_als_double_write(void *se, void *item, char *value)
{
    knl_session_t *session = (knl_session_t *)se;
    ckpt_context_t *ctx = &session->kernel->ckpt_ctx;
    // match id specified by ddl_parser.c:sql_parse_alsys_set
    ctx->double_write = (bool32)value[0];
    // restore value for alter config.
    return sql_notify_als_bool(se, item, value);
}

status_t sql_notify_als_build_timeout(void *se, void *item, char *value)
{
    uint32 val;
    if (cm_str2uint32(value, &val) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (val < CT_BUILD_MIN_WAIT_TIME) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "BUILD_KEEP_ALIVE_TIMEOUT", (int64)CT_BUILD_MIN_WAIT_TIME);
        return CT_ERROR;
    }

    g_instance->kernel.attr.build_keep_alive_timeout = val;
    return CT_SUCCESS;
}

status_t sql_verify_als_repl_wait_timeout(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (num < CT_REPL_MIN_WAIT_TIME) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "REPL_WAIT_TIMEOUT", (int64)CT_REPL_MIN_WAIT_TIME);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_notify_als_repl_timeout(void *se, void *item, char *value)
{
    uint32 val;
    if (cm_str2uint32(value, &val) != CT_SUCCESS) {
        return CT_ERROR;
    }

    g_instance->kernel.attr.repl_wait_timeout = val;
    knl_set_repl_timeout(se, val);
    return CT_SUCCESS;
}

status_t sql_verify_als_repl_max_pkg_size(void *se, void *lex, void *def)
{
    word_t word;
    int64 size;
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;
    if (lex_expected_fetch((lex_t *)lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (word.type == WORD_TYPE_STRING) {
        sql_remove_quota(&word.text.value);
        cm_trim_text(&word.text.value);
    }

    if (word.type == WORD_TYPE_DQ_STRING) {
        cm_trim_text(&word.text.value);
    }

    if (word.text.len == 0) {
        CT_SRC_THROW_ERROR(word.loc, ERR_EMPTY_STRING_NOT_ALLOWED);
        return CT_ERROR;
    }

    CT_RETURN_IFERR(lex_push(lex, &word.text));
    if (lex_expected_fetch_size(lex, &size, CT_INVALID_INT64, CT_INVALID_INT64) != CT_SUCCESS) {
        lex_pop(lex);
        return CT_ERROR;
    }

    lex_pop(lex);
    if (size > 0) {
        if (size < CT_MIN_REPL_PKG_SIZE) {
            CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "_REPL_MAX_PKG_SIZE", CT_MIN_REPL_PKG_SIZE);
            return CT_ERROR;
        }

        if (size > CT_MAX_REPL_PKG_SIZE) {
            CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "_REPL_MAX_PKG_SIZE", CT_MAX_REPL_PKG_SIZE);
            return CT_ERROR;
        }
    }

    cm_text2str((text_t *)&word.text, sys_def->value, CT_PARAM_BUFFER_SIZE);
    return CT_SUCCESS;
}

status_t sql_notify_als_repl_max_pkg_size(void *se, void *item, char *value)
{
    int64 size = 0;
    CT_RETURN_IFERR(cm_str2size(value, &size));
    (void)cm_atomic_set(&g_instance->kernel.attr.repl_pkg_size, size);
    return CT_SUCCESS;
}

status_t sql_notify_als_repl_host(void *se, void *item, char *value)
{
    errno_t errcode;
    errcode = strncpy_s(g_instance->kernel.attr.repl_trust_host, CT_HOST_NAME_BUFFER_SIZE * CT_MAX_LSNR_HOST_COUNT,
        value, strlen(value));
    if (errcode != EOK) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_verify_als_filesystemio_options(void *se, void *lex, void *def)
{
    uint32 match_id;
    char *match_word[] = { "NONE", "DIRECTIO", "FULLDIRECTIO", "ASYNCH", "DSYNC", "FDATASYNC", "SETALL" };
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;
    if (lex_expected_fetch_1ofn(lex, &match_id, 7, match_word[0], match_word[1], match_word[2], match_word[3],
        match_word[4], match_word[5], match_word[6]) != CT_SUCCESS) {
        return CT_ERROR;
    }

    PRTS_RETURN_IFERR(
        snprintf_s(sys_def->value, CT_PARAM_BUFFER_SIZE, CT_PARAM_BUFFER_SIZE - 1, "%s", match_word[match_id]));

    return CT_SUCCESS;
}

status_t sql_notify_als_rcy_check_pcn(void *se, void *item, char *value)
{
    g_instance->kernel.attr.rcy_check_pcn = (bool32)value[0];
    return sql_notify_als_bool(se, item, value);
}

status_t sql_notify_als_local_tmp_tbl_enabled(void *se, void *item, char *value)
{
    g_instance->kernel.attr.enable_ltt = (bool32)value[0];
    return sql_notify_als_bool(se, item, value);
}

status_t sql_notify_als_upper_case_table_names(void *se, void *item, char *value)
{
    // enable online modify for debug version only
#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
    g_instance->kernel.attr.enable_upper_case_names = (bool32)value[0];
    return sql_notify_als_bool(se, item, value);
#else
    CT_THROW_ERROR(ERR_NOT_COMPATIBLE, "UPPER_CASE_TABLE_NAMES");
    return CT_ERROR;
#endif
}

status_t sql_notify_als_cbo(void *se, void *item, char *value)
{
    return sql_notify_als_onoff(se, item, value);
}

status_t sql_notify_als_resource_limit(void *se, void *item, char *value)
{
    knl_session_t *session = (knl_session_t *)se;
    session->kernel->attr.enable_resource_limit = (bool32)value[0];
    return sql_notify_als_bool(se, item, value);
}

status_t sql_notify_drop_nologging(void *se, void *item, char *value)
{
    // match id specified by ddl_parser.c:sql_parse_alsys_set
    g_instance->kernel.attr.drop_nologging = (bool32)value[0];
    // restore value for alter config.
    return sql_notify_als_bool(se, item, value);
}

status_t sql_notify_recyclebin(void *se, void *item, char *value)
{
    // match id specified by ddl_parser.c:sql_parse_alsys_set
    g_instance->kernel.attr.recyclebin = (bool32)value[0];
    // restore value for alter config.
    return sql_notify_als_bool(se, item, value);
}

status_t sql_notify_als_auto_inherit(void *se, void *item, char *value)
{
    if (g_instance->kernel.attr.enable_auto_inherit != (bool32)value[0]) {
        g_instance->kernel.attr.enable_auto_inherit = (bool32)value[0];
    }

    return sql_notify_als_onoff(se, item, value);
}

status_t sql_notify_password_verify(void *se, void *item, char *value)
{
    g_instance->kernel.attr.password_verify = (bool32)value[0];
    return sql_notify_als_bool(se, item, value);
}

status_t sql_verify_als_idx_duplicate_enable(void *se, void *lex, void *def)
{
    CT_SRC_THROW_ERROR(((lex_t *)lex)->loc, ERR_CAPABILITY_NOT_SUPPORT, "index and contraint duplicate name");
    return CT_ERROR;
}

status_t sql_notify_als_idx_duplicate(void *se, void *item, char *value)
{
    CT_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "index and contraint duplicate name");
    return CT_ERROR;
}

status_t sql_notify_idx_key_len_check(void *se, void *item, char *value)
{
    knl_session_t *session = (knl_session_t *)se;
    session->kernel->attr.enable_idx_key_len_check = (bool32)value[0];
    return sql_notify_als_bool(se, item, value);
}

status_t sql_notify_als_tc_level(void *se, void *item, char *value)
{
    uint32 val;
    CT_RETURN_IFERR(cm_str2uint32(value, &val));
    g_instance->kernel.attr.tc_level = val;
    return CT_SUCCESS;
}

status_t sql_verify_als_ddl_lock_timeout(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (num < CT_MIN_DDL_LOCK_TIMEOUT || num > CT_MAX_DDL_LOCK_TIMEOUT) {
        CT_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "DDL_LOCK_TIMEOUT", (int64)CT_MIN_DDL_LOCK_TIMEOUT,
            (int64)CT_MAX_DDL_LOCK_TIMEOUT);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_notify_als_ddl_lock_timeout(void *se, void *item, char *value)
{
    uint32 num;
    if (cm_str2uint32(value, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }

    g_instance->kernel.attr.ddl_lock_timeout = (num == 0) ? LOCK_INF_WAIT : num;
    return CT_SUCCESS;
}

status_t sql_verify_als_max_rm_count(void *se, void *lex, void *def)
{
    uint32 max_sessions = g_instance->session_pool.expanded_max_sessions;
    uint32 num = 0;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        cm_reset_error();
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "_MAX_RM_COUNT");
        return CT_ERROR;
    }

    if (num != 0) {
        if (CM_CALC_ALIGN(num, CT_EXTEND_RMS) < max_sessions) {
            CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "_MAX_RM_COUNT", (int64)max_sessions);
            return CT_ERROR;
        }

        if (CM_CALC_ALIGN(num, CT_EXTEND_RMS) > CM_CALC_ALIGN_FLOOR(CT_MAX_RM_COUNT, CT_EXTEND_RMS)) {
            CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "_MAX_RM_COUNT",
                (int64)CM_CALC_ALIGN_FLOOR(CT_MAX_RM_COUNT, CT_EXTEND_RMS));
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

status_t sql_verify_als_ashrink_wait_time(void *se, void *lex, void *def)
{
    uint32 num = 0;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        cm_reset_error();
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "_ASHRINK_WAIT_TIME");
        return CT_ERROR;
    }

    if (num < CT_MIN_ASHRINK_WAIT_TIME) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "_ASHRINK_WAIT_TIME", (int64)CT_MIN_ASHRINK_WAIT_TIME);
        return CT_ERROR;
    }

    if (num > CT_MAX_ASHRINK_WAIT_TIME) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "_ASHRINK_WAIT_TIME", (int64)CT_MAX_ASHRINK_WAIT_TIME);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_notify_als_ashrink_wait_time(void *se, void *item, char *value)
{
    uint32 num = 0;
    if (cm_str2uint32(value, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (num < CT_MIN_ASHRINK_WAIT_TIME) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "_ASHRINK_WAIT_TIME", (int64)CT_MIN_ASHRINK_WAIT_TIME);
        return CT_ERROR;
    }

    if (num > CT_MAX_ASHRINK_WAIT_TIME) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "_ASHRINK_WAIT_TIME", (int64)CT_MAX_ASHRINK_WAIT_TIME);
        return CT_ERROR;
    }

    g_instance->kernel.attr.ashrink_wait_time = num;
    return CT_SUCCESS;
}

status_t sql_verify_als_shrink_wait_recycled_pages(void *se, void *lex, void *def)
{
    uint32 num = 0;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        cm_reset_error();
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "_SHRINK_WAIT_RECYCLED_PAGES");
        return CT_ERROR;
    }

    if (num < CT_MIN_SHRINK_WAIT_RECYCLED_PAGES) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "_SHRINK_WAIT_RECYCLED_PAGES",
            (int64)CT_MIN_SHRINK_WAIT_RECYCLED_PAGES);
        return CT_ERROR;
    }

    if (num > CT_MAX_SHRINK_WAIT_RECYCLED_PAGES) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "_SHRINK_WAIT_RECYCLED_PAGES",
            (int64)CT_MAX_SHRINK_WAIT_RECYCLED_PAGES);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t sql_notify_als_shrink_wait_recycled_pages(void *se, void *item, char *value)
{
    uint32 num = 0;
    if (cm_str2uint32(value, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (num < CT_MIN_SHRINK_WAIT_RECYCLED_PAGES) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "_SHRINK_WAIT_RECYCLED_PAGES",
            (int64)CT_MIN_SHRINK_WAIT_RECYCLED_PAGES);
        return CT_ERROR;
    }

    if (num > CT_MAX_SHRINK_WAIT_RECYCLED_PAGES) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "_SHRINK_WAIT_RECYCLED_PAGES",
            (int64)CT_MAX_SHRINK_WAIT_RECYCLED_PAGES);
        return CT_ERROR;
    }

    g_instance->kernel.attr.shrink_wait_recycled_pages = num;
    return CT_SUCCESS;
}

status_t sql_notify_als_temptable_support_batch(void *se, void *item, char *value)
{
    g_instance->kernel.attr.temptable_support_batch = (bool32)value[0];
    return sql_notify_als_bool(se, item, value);
}

status_t sql_verify_als_small_table_sampling_threshold(void *se, void *lex, void *def)
{
    uint32 num = 0;
    return sql_verify_uint32(lex, def, &num);
}

status_t sql_notify_als_small_table_sampling_threshold(void *se, void *item, char *value)
{
    return cm_str2uint32(value, &g_instance->kernel.attr.small_table_sampling_threshold);
}

status_t sql_notify_als_block_repair_enable(void *se, void *item, char *value)
{
    g_instance->kernel.attr.enable_abr = (bool32)value[0];
    // restore value for alter config.
    return sql_notify_als_bool(se, item, value);
}

status_t sql_notify_als_block_repair_timeout(void *se, void *item, char *value)
{
    uint32 abr_timeout;
    if (cm_str2uint32(value, &abr_timeout) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (abr_timeout < 1) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "BLOCK_REPAIR_TIMEOUT", (int64)1);
        return CT_ERROR;
    }

    if (abr_timeout > ABR_MAX_TIMEOUT) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "BLOCK_REPAIR_TIMEOUT", (int64)ABR_MAX_TIMEOUT);
        return CT_ERROR;
    }

    g_instance->kernel.attr.abr_timeout = abr_timeout;
    return CT_SUCCESS;
}

status_t sql_verify_als_block_repair_timeout(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (num < 1) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "BLOCK_REPAIR_TIMEOUT", (int64)1);
        return CT_ERROR;
    }

    if (num > ABR_MAX_TIMEOUT) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "BLOCK_REPAIR_TIMEOUT", (int64)ABR_MAX_TIMEOUT);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_verify_als_nbu_backup_timeout(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (num < CT_NBU_BACKUP_MIN_WAIT_TIME) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "NBU_BACKUP_TIMEOUT", (int64)CT_NBU_BACKUP_MIN_WAIT_TIME);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_notify_als_nbu_backup_timeout(void *se, void *item, char *value)
{
    uint32 val;
    if (cm_str2uint32(value, &val) != CT_SUCCESS) {
        return CT_ERROR;
    }
    g_instance->kernel.attr.nbu_backup_timeout = val;
    return CT_SUCCESS;
}

status_t sql_notify_degrade_search(void *se, void *item, char *value)
{
    // match id specified by ddl_parser.c:sql_parse_alsys_set
    g_instance->kernel.attr.enable_degrade_search = (bool32)value[0];
    // restore value for alter config.
    return sql_notify_als_bool(se, item, value);
}

status_t sql_verify_als_lob_reuse_threshold(void *se, void *lex, void *def)
{
    return sql_verify_pool_size(lex, def, CT_MIN_LOB_REUSE_SIZE, CT_INVALID_ID32);
}

status_t sql_notify_als_lob_reuse_threshold(void *se, void *item, char *value)
{
    int64 val_int64;
    if (cm_str2size(value, &val_int64) != CT_SUCCESS) {
        return CT_ERROR;
    }

    g_instance->kernel.attr.lob_reuse_threshold = (uint64)val_int64;
    return CT_SUCCESS;
}

status_t sql_notify_build_datafile_paral(void *se, void *item, char *value)
{
    g_instance->kernel.attr.build_datafile_parallel = (bool32)value[0];
    // restore value for alter config.
    return sql_notify_als_bool(se, item, value);
}

status_t sql_verify_init_lockpool_pages(void *se, void *lex, void *def)
{
    uint32 value;
    if (sql_verify_uint32(lex, def, &value) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (value < CT_MIN_LOCK_PAGES) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "INIT_LOCK_POOL_PAGES", (int64)CT_MIN_LOCK_PAGES);
        return CT_ERROR;
    }
    if (value > CT_MAX_LOCK_PAGES) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "INIT_LOCK_POOL_PAGES", (int64)CT_MAX_LOCK_PAGES);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t sql_notify_init_lockpool_pages(void *se, void *item, char *value)
{
    uint32 init_lockpool_pages;
    if (cm_str2uint32(value, &init_lockpool_pages) != CT_SUCCESS) {
        return CT_ERROR;
    }

    g_instance->kernel.attr.init_lockpool_pages = init_lockpool_pages;
    return CT_SUCCESS;
}

status_t sql_notify_build_datafile_prealloc(void *se, void *item, char *value)
{
    g_instance->kernel.attr.build_datafile_prealloc = (bool32)value[0];
    // restore value for alter config.
    return sql_notify_als_bool(se, item, value);
}

status_t sql_verify_als_ctrllog_backup_level(void *se, void *lex, void *def)
{
    uint32 match_id;
    const char *match_word[] = { "NONE", "TYPICAL", "FULL" };
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;

    if (lex_expected_fetch_1of3(lex, match_word[0], match_word[1], match_word[2], &match_id) != CT_SUCCESS) {
        return CT_ERROR;
    }

    MEMS_RETURN_IFERR(strcpy_s(sys_def->value, CT_PARAM_BUFFER_SIZE, match_word[match_id]));
    return CT_SUCCESS;
}

status_t sql_notify_ctrllog_backup_level(void *se, void *item, char *value)
{
    if (cm_str_equal_ins(value, "NONE")) {
        g_instance->kernel.attr.ctrllog_backup_level = CTRLLOG_BACKUP_LEVEL_NONE;
    } else if (cm_str_equal_ins(value, "TYPICAL")) {
        g_instance->kernel.attr.ctrllog_backup_level = CTRLLOG_BACKUP_LEVEL_TYPICAL;
    } else if (cm_str_equal_ins(value, "FULL")) {
        g_instance->kernel.attr.ctrllog_backup_level = CTRLLOG_BACKUP_LEVEL_FULL;
    } else {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER_ENUM, "CTRLLOG_BACKUP_LEVEL", value);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_verify_als_compress_algo(void *se, void *lex, void *def)
{
    uint32 match_id;
    const char *match_word[] = { "NONE", "ZSTD" };
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;
    if (lex_expected_fetch_1of2(lex, match_word[0], match_word[1], &match_id) != CT_SUCCESS) {
        return CT_ERROR;
    }

    MEMS_RETURN_IFERR(strcpy_s(sys_def->value, CT_PARAM_BUFFER_SIZE, match_word[match_id]));
    return CT_SUCCESS;
}

status_t sql_notify_als_compress_algo(void *se, void *item, char *value)
{
    if (cm_str_equal_ins(value, "NONE")) {
        g_instance->kernel.attr.default_compress_algo = COMPRESS_NONE;
    } else if (cm_str_equal_ins(value, "ZSTD")) {
        g_instance->kernel.attr.default_compress_algo = COMPRESS_ZSTD;
    } else {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER_ENUM, "_TABLE_COMPRESS_ALGO", value);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_verify_als_compress_buf_size(void *se, void *lex, void *def)
{
    knl_attr_t *attr = &g_instance->kernel.attr;
    if (sql_verify_pool_size(lex, def, (int64)CT_MIN_TAB_COMPRESS_BUF_SIZE,
        MIN(attr->temp_buf_size, (int64)CT_MAX_TAB_COMPRESS_BUF_SIZE)) != CT_SUCCESS) {
        CT_THROW_ERROR((int64)ERR_PARAMETER_OVER_RANGE, "_TABLE_COMPRESS_BUFFER_SIZE ",
            (int64)CT_MIN_TAB_COMPRESS_BUF_SIZE, MIN(attr->temp_buf_size, (int64)CT_MAX_TAB_COMPRESS_BUF_SIZE));
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t sql_notify_als_compress_buf_size(void *se, void *item, char *value)
{
    int64 val_int64;
    if (cm_str2size(value, &val_int64) != CT_SUCCESS) {
        return CT_ERROR;
    }

    g_instance->kernel.attr.tab_compress_buf_size = (uint64)val_int64;
    return CT_SUCCESS;
}

status_t sql_notify_als_compress_enable_buf(void *se, void *item, char *value)
{
    g_instance->kernel.attr.tab_compress_enable_buf = (bool32)value[0];
    // restore value for alter config.
    return sql_notify_als_bool(se, item, value);
}

status_t sql_verify_als_page_clean_wait_timeout(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t sql_notify_als_page_clean_wait_timeout(void *se, void *item, char *value)
{
    uint32 timeout = 0;
    CT_RETURN_IFERR(cm_str2uint32(value, &timeout));
    g_instance->kernel.attr.page_clean_wait_timeout = (uint32)timeout;
    return CT_SUCCESS;
}

status_t sql_notify_als_ckpt_wait_timeout(void *se, void *item, char *value)
{
    uint32 timeout = 0;
    CT_RETURN_IFERR(cm_str2uint32(value, &timeout));
    g_instance->kernel.attr.ckpt_timed_task_delay = (uint32)timeout;
    return CT_SUCCESS;
}

status_t sql_notify_io_record(void *se, void *item, char *value)
{
    bool32 open_record = (bool32)value[0];
    if (g_cm_io_record_open == CT_FALSE && open_record == CT_TRUE) {
        tse_record_io_state_reset();
    }
    set_iorecord_status(open_record);
    return CT_SUCCESS;
}

status_t sql_verify_als_page_clean_mode(void *se, void *lex, void *def)
{
    uint32 match_id;
    char *match_word[] = { "SINGLE", "ALL" };
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;

    if (lex_expected_fetch_1of2(lex, match_word[0], match_word[1], &match_id) != CT_SUCCESS) {
        return CT_ERROR;
    }

    PRTS_RETURN_IFERR(
        snprintf_s(sys_def->value, CT_PARAM_BUFFER_SIZE, CT_PARAM_BUFFER_SIZE - 1, "%s", match_word[match_id]));
    return CT_SUCCESS;
}

status_t sql_notify_als_page_clean_mode(void *se, void *item, char *value)
{
    if (cm_str_equal_ins(value, "SINGLE")) {
        g_instance->kernel.attr.page_clean_mode = PAGE_CLEAN_MODE_SINGLESET;
    } else if (cm_str_equal_ins(value, "ALL")) {
        g_instance->kernel.attr.page_clean_mode = PAGE_CLEAN_MODE_ALLSET;
    } else {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER_ENUM, "PAGE_CLEAN_MODE", value);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t sql_verify_als_batch_flush_capacity(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (num < CT_MIN_BATCH_FLUSH_CAPACITY || num > CT_MAX_BATCH_FLUSH_CAPACITY) {
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t sql_notify_enable_broadcast_on_commit(void *se, void *item, char *value)
{
    g_instance->kernel.attr.enable_boc = (bool32)value[0];
    // restore value for alter config.
    return sql_notify_als_bool(se, item, value);
}

status_t sql_notify_enable_enable_check_security_log(void *se, void *item, char *value)
{
    g_filter_enable = (bool32)value[0];
    // restore value for alter config.
    return sql_notify_als_bool(se, item, value);
}

status_t sql_verify_als_ckpt_group_size(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (num < CT_MIN_CKPT_GROUP_SIZE || num > CT_MAX_CKPT_GROUP_SIZE) {
        return CT_ERROR;
    }
    return CT_SUCCESS;
}
#ifdef __cplusplus
}
#endif
