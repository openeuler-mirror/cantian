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
 * srv_params_raft_and_log.c
 *
 *
 * IDENTIFICATION
 * src/server/params/srv_params_raft_and_log.c
 *
 * -------------------------------------------------------------------------
 */
#include "srv_module.h"
#include "srv_params_raft_and_log.h"
#include "srv_param_common.h"
#include "srv_instance.h"

#ifdef __cplusplus
extern "C" {
#endif

const log_mode_map_t g_log_map_set[] = {
    { { (char *)"LONGSQL_LOG_MODE", 16 }, { (char *)"ON",           2 },  LONGSQL_ON },
    { { (char *)"LONGSQL_LOG_MODE", 16 }, { (char *)"OFF",          3 },  LONGSQL_OFF },
    { { (char *)"_LOG_LEVEL_MODE",  15 }, { (char *)"FATAL",        5 },  LOG_LEVEL_FATAL },
    { { (char *)"_LOG_LEVEL_MODE",  15 }, { (char *)"DEBUG",        5 },  LOG_LEVEL_DEBUG },
    { { (char *)"_LOG_LEVEL_MODE",  15 }, { (char *)"WARN",         4 },  LOG_LEVEL_WARN },
    { { (char *)"_LOG_LEVEL_MODE",  15 }, { (char *)"ERROR",        5 },  LOG_LEVEL_ERROR },
    { { (char *)"_LOG_LEVEL_MODE",  15 }, { (char *)"RUN",          3 },  LOG_LEVEL_RUN },
    { { (char *)"_LOG_LEVEL_MODE",  15 }, { (char *)"USER_DEFINE", 11 },  LOG_LEVEL_USER_DEFINE },
};

status_t sql_verify_als_black_box_depth(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (num < CT_INIT_BLACK_BOX_DEPTH || num > CT_MAX_BLACK_BOX_DEPTH) {
        CT_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "_BLACK_BOX_DEPTH", (int64)CT_INIT_BLACK_BOX_DEPTH,
            (int64)CT_MAX_BLACK_BOX_DEPTH);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

// check value is "a folder that already exists and has readable and writable permissions"
status_t sql_verify_als_file_dir(void *se, void *lex, void *def)
{
    word_t word;
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;

    if (lex_expected_fetch((lex_t *)lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (word.type == WORD_TYPE_STRING) {
        sql_remove_quota(&word.text.value);
    }
    if (word.text.len >= CT_MAX_LOG_HOME_LEN) {
        CT_SRC_THROW_ERROR(word.text.loc, ERR_FILE_PATH_TOO_LONG, CT_MAX_LOG_HOME_LEN - 1);
        return CT_ERROR;
    }
    char *file_path = W2S(&word);
    if (!cm_dir_exist(file_path)) {
        CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "%s is not an existing folder", file_path);
        return CT_ERROR;
    }
    char real_path[CT_FILE_NAME_BUFFER_SIZE] = { 0x00 };
    CT_RETURN_IFERR(realpath_file(file_path, real_path, CT_FILE_NAME_BUFFER_SIZE));
    if (access(real_path, W_OK | R_OK) != 0) {
        CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "%s is not an readable or writable folder",
            file_path);
        return CT_ERROR;
    }
    return cm_text2str((text_t *)&word.text, sys_def->value, CT_PARAM_BUFFER_SIZE);
}

status_t sql_verify_als_audit_level(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (num > DDL_AUDIT_ALL) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "AUDIT_LEVEL");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_notify_als_audit_level(void *se, void *item, char *value)
{
    return cm_str2uint32(value, &cm_log_param_instance()->audit_param.audit_level);
}

status_t sql_verify_als_audit_trail_mode(void *se, void *lex, void *def)
{
    word_t word;
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;

    if (lex_expected_fetch((lex_t *)lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (word.type == WORD_TYPE_STRING) {
        sql_remove_quota(&word.text.value);
    }

    if (cm_text_str_equal_ins(&word.text.value, "ALL") || cm_text_str_equal_ins(&word.text.value, "FILE") ||
        cm_text_str_equal_ins(&word.text.value, "DB") || cm_text_str_equal_ins(&word.text.value, "SYSLOG") ||
        cm_text_str_equal_ins(&word.text.value, "NONE")) {
        cm_text2str_with_upper((text_t *)&word.text, sys_def->value, CT_PARAM_BUFFER_SIZE);
        return CT_SUCCESS;
    }

    CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_INVALID_PARAMETER, "%s", W2S(&word));
    return CT_ERROR;
}

status_t sql_notify_als_audit_trail_mode(void *se, void *item, char *value)
{
    log_param_t *log_param = cm_log_param_instance();
    audit_log_param_t old_audit_param = log_param->audit_param;
    CT_RETURN_IFERR(sql_parse_audit_trail_mode(value, &(log_param->audit_param.audit_trail_mode)));
    sql_auditlog_reinit(&old_audit_param, &log_param->audit_param);
    return CT_SUCCESS;
}

status_t sql_verify_als_audit_syslog_level(void *se, void *lex, void *def)
{
    word_t word;
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;
    audit_log_param_t audit_log_param;

    if (lex_expected_fetch((lex_t *)lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (word.type != WORD_TYPE_STRING) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "expected quota string but %s found", W2S(&word));
        return CT_ERROR;
    }

    sql_remove_quota(&word.text.value);
    cm_text2str_with_upper((text_t *)&word.text, sys_def->value, CT_PARAM_BUFFER_SIZE);
    return sql_parse_audit_syslog(sys_def->value, &audit_log_param);
}

status_t sql_notify_als_audit_syslog_level(void *se, void *item, char *value)
{
    log_param_t *log_param = cm_log_param_instance();
    audit_log_param_t old_audit_param = log_param->audit_param;
    CT_RETURN_IFERR(sql_parse_audit_syslog(value, &log_param->audit_param));
    sql_auditlog_reinit(&old_audit_param, &log_param->audit_param);
    return CT_SUCCESS;
}

status_t sql_verify_als_log_backup_file_count(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (num > CT_MAX_LOG_FILE_COUNT) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "_LOG_BACKUP_FILE_COUNT", (int64)CT_MAX_LOG_FILE_COUNT);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_notify_als_log_backup_file_count(void *se, void *item, char *value)
{
    return cm_str2uint32(value, &cm_log_param_instance()->log_backup_file_count);
}

status_t sql_verify_als_audit_backup_file_count(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (num > CT_MAX_LOG_FILE_COUNT) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "_AUDIT_BACKUP_FILE_COUNT", (int64)CT_MAX_LOG_FILE_COUNT);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_verify_log_file_size(void *se, void *lex, void *def)
{
    return sql_verify_pool_size(lex, def, CT_MIN_LOG_FILE_SIZE, CT_MAX_LOG_FILE_SIZE);
}

status_t sql_notify_als_log_max_file_size(void *se, void *item, char *value)
{
    int64 val_int64;

    if (cm_str2size(value, &val_int64) != CT_SUCCESS) {
        return CT_ERROR;
    }

    cm_log_param_instance()->max_log_file_size = (uint64)val_int64;

    return CT_SUCCESS;
}

status_t sql_verify_audit_file_size(void *se, void *lex, void *def)
{
    return sql_verify_pool_size(lex, def, CT_MIN_LOG_FILE_SIZE, CT_MAX_LOG_FILE_SIZE);
}

status_t sql_notify_als_audit_max_file_size(void *se, void *item, char *value)
{
    int64 val_int64;

    if (cm_str2size(value, &val_int64) != CT_SUCCESS) {
        return CT_ERROR;
    }

    cm_log_param_instance()->max_audit_file_size = (uint64)val_int64;

    return CT_SUCCESS;
}

status_t sql_verify_pbl_file_size(void *se, void *lex, void *def)
{
    return sql_verify_pool_size(lex, def, CT_MIN_PBL_FILE_SIZE, CT_MAX_PBL_FILE_SIZE);
}

status_t sql_verify_als_log_mode_value(lex_t *lex, knl_alter_sys_def_t *def)
{
    word_t word;
    knl_alter_sys_def_t *sys_def = def;
    if (lex_expected_fetch((lex_t *)lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (word.type == WORD_TYPE_STRING) {
        sql_remove_quota(&word.text.value);
    }

    if (IS_LONGSQL_LOG_MODE(sys_def->param)) {
        if (cm_text_str_equal_ins(&word.text.value, "ON") || cm_text_str_equal_ins(&word.text.value, "OFF")) {
            cm_text2str_with_upper((text_t *)&word.text, sys_def->value, CT_PARAM_BUFFER_SIZE);
            return CT_SUCCESS;
        }
    } else if (IS_LOG_LEVEL_MODE(sys_def->param)) {
        if (cm_text_str_equal_ins(&word.text.value, "DEBUG") || cm_text_str_equal_ins(&word.text.value, "WARN") ||
            cm_text_str_equal_ins(&word.text.value, "ERROR") || cm_text_str_equal_ins(&word.text.value, "RUN") ||
            cm_text_str_equal_ins(&word.text.value, "FATAL")) {
            cm_text2str_with_upper((text_t *)&word.text, sys_def->value, CT_PARAM_BUFFER_SIZE);
            return CT_SUCCESS;
        }
    }
    CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_INVALID_PARAMETER, "%s", W2S(&word));
    return CT_ERROR;
}

status_t cm_find_log_mode_method(const log_mode_map_t *log_map_set, text_t name, text_t value, uint32 *result)
{
    for (size_t i = 0; i < LOG_MODE_MAP_LENGTH; i++) {
        if (!cm_compare_text_ins(&name, &log_map_set[i].name) && !cm_compare_text_ins(&value, &log_map_set[i].value)) {
            *result = log_map_set[i].method;
            return CT_SUCCESS;
        }
    }
    CT_THROW_ERROR(ERR_INVALID_PARAMETER, name);
    return CT_ERROR;
}

status_t cm_set_log_level_value_int(uint32 method, uint32 *log_level_value_int, const char *value)
{
    switch (method) {
        case LONGSQL_ON:
            SET_LOG_LONGSQL_VALUE_ON(*log_level_value_int);
            break;
        case LONGSQL_OFF:
            SET_LOG_LONGSQL_VALUE_OFF(*log_level_value_int);
            break;
        case LOG_LEVEL_FATAL:
            SET_LOG_FATAL_ON(*log_level_value_int);
            break;
        case LOG_LEVEL_DEBUG:
            SET_LOG_DEBUG_ON(*log_level_value_int);
            break;
        case LOG_LEVEL_WARN:
            SET_LOG_WARN_ON(*log_level_value_int);
            break;
        case LOG_LEVEL_ERROR:
            SET_LOG_ERROR_ON(*log_level_value_int);
            break;
        case LOG_LEVEL_RUN:
            SET_LOG_RUN_ON(*log_level_value_int);
            break;
        default:
            CT_THROW_ERROR(ERR_INVALID_PARAMETER, value);
            return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t cm_set_def_param(knl_alter_sys_def_t *def, const char *name)
{
    char temp[CT_VALUE_BUFFER_SIZE];
    text_t name_text;
    name_text.str = temp;
    name_text.len = 0;
    cm_str2text((char *)name, &name_text);
    return cm_text2str(&name_text, ((knl_alter_sys_def_t *)def)->param, name_text.len + 1);
}

status_t cm_set_def_value(knl_alter_sys_def_t *def, uint32 value)
{
    char temp[CT_VALUE_BUFFER_SIZE];
    text_t value_text;
    value_text.str = temp;
    value_text.len = 0;
    cm_uint32_to_text(value, &value_text);
    return cm_text2str(&value_text, def->value, value_text.len + 1);
}

status_t cm_set_log_level_value(knl_alter_sys_def_t *def)
{
    knl_alter_sys_def_t *sys_def = def;
    // get _LOG_LEVEL item value
    text_t name = {
        .str = "_LOG_LEVEL",
        .len = (uint32)strlen("_LOG_LEVEL")
    };
    config_item_t *item = cm_get_config_item(GET_CONFIG, &name, CT_FALSE);
    uint32 log_level_value_int;
    cm_str2uint32(item->is_default ? item->default_value : item->value, &log_level_value_int);

    // translate into _LOG_LEVEL value
    text_t name_text;
    text_t value_text;
    uint32 method;
    cm_str2text(sys_def->param, &name_text);
    cm_str2text(sys_def->value, &value_text);
    CT_RETURN_IFERR(cm_find_log_mode_method(g_log_map_set, name_text, value_text, &method));
    CT_RETURN_IFERR(cm_set_log_level_value_int(method, &log_level_value_int, sys_def->value));

    // set def
    CT_RETURN_IFERR(cm_set_def_value(def, log_level_value_int));
    CT_RETURN_IFERR(cm_set_def_param(def, "_LOG_LEVEL"));
    return CT_SUCCESS;
}

status_t sql_verify_als_log_level_value(lex_t *lex, knl_alter_sys_def_t *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (num > MAX_LOG_LEVEL) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "_LOG_LEVEL");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t sql_verify_als_log_level(void *se, void *lex, void *def)
{
    if (IS_LOG_MODE(((knl_alter_sys_def_t *)def)->param)) {
        CT_RETURN_IFERR(sql_verify_als_log_mode_value((lex_t *)lex, (knl_alter_sys_def_t *)def));

        CT_RETURN_IFERR(cm_set_log_level_value((knl_alter_sys_def_t *)def));
    } else {
        CT_RETURN_IFERR(sql_verify_als_log_level_value((lex_t *)lex, (knl_alter_sys_def_t *)def));
    }
    return CT_SUCCESS;
}

status_t sql_notify_als_pbl_max_file_size(void *se, void *item, char *value)
{
    int64 val_int64;

    if (cm_str2size(value, &val_int64) != CT_SUCCESS) {
        return CT_ERROR;
    }
    cm_log_param_instance()->max_pbl_file_size = (uint64)val_int64;
    return CT_SUCCESS;
}

status_t sql_notify_als_log_level(void *se, void *item, char *value)
{
    CT_RETURN_IFERR(cm_str2uint32(value, &cm_log_param_instance()->log_level));
    return CT_SUCCESS;
}

status_t sql_notify_als_audit_backup_file_count(void *se, void *item, char *value)
{
    return cm_str2uint32(value, &cm_log_param_instance()->audit_backup_file_count);
}

status_t sql_verify_als_log_file(void *se, void *lex, void *def)
{
    uint32 num;
    uint32 usr_perm;
    uint32 grp_perm;
    uint32 oth_perm;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }

    usr_perm = (num / 100) % 10;
    grp_perm = (num / 10) % 10;
    oth_perm = num % 10;

    if (usr_perm > CT_MAX_LOG_USER_PERMISSION || grp_perm > CT_MAX_LOG_USER_PERMISSION ||
        oth_perm > CT_MAX_LOG_USER_PERMISSION) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "_LOG_FILE_PERMISSIONS");
        return CT_ERROR;
    }

    if (num < CT_DEF_LOG_FILE_PERMISSIONS || num > CT_MAX_LOG_PERMISSIONS) {
        CT_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "_LOG_FILE_PERMISSIONS", (int64)CT_DEF_LOG_FILE_PERMISSIONS,
            (int64)CT_MAX_LOG_PERMISSIONS);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_verify_als_log_path(void *se, void *lex, void *def)
{
    uint32 num;
    uint32 usr_perm;
    uint32 grp_perm;
    uint32 oth_perm;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }

    usr_perm = (num / 100) % 10;
    grp_perm = (num / 10) % 10;
    oth_perm = num % 10;

    if (usr_perm > CT_MAX_LOG_USER_PERMISSION || grp_perm > CT_MAX_LOG_USER_PERMISSION ||
        oth_perm > CT_MAX_LOG_USER_PERMISSION) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "_LOG_PATH_PERMISSIONS");
        return CT_ERROR;
    }

    if (num < CT_DEF_LOG_PATH_PERMISSIONS || num > CT_MAX_LOG_PERMISSIONS) {
        CT_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "_LOG_PATH_PERMISSIONS", (int64)CT_DEF_LOG_PATH_PERMISSIONS,
            (int64)CT_MAX_LOG_PERMISSIONS);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_notify_als_log_file_permissions(void *se, void *item, char *value)
{
    uint16 val;
    if (cm_str2uint16(value, &val) != CT_SUCCESS) {
        return CT_ERROR;
    }

    cm_log_set_file_permissions(val);
    return CT_SUCCESS;
}

status_t sql_notify_als_log_path_permissions(void *se, void *item, char *value)
{
    uint16 val;
    if (cm_str2uint16(value, &val) != CT_SUCCESS) {
        return CT_ERROR;
    }

    cm_log_set_path_permissions(val);
    return CT_SUCCESS;
}

status_t sql_notify_enable_longsql_print(void *se, void *item, char *value)
{
    cm_log_param_instance()->longsql_print_enable = (bool32)value[0];
    // restore value for alter config.
    return sql_notify_als_bool(se, item, value);
}

status_t sql_verify_als_longsql_timeout(void *se, void *lex, void *def)
{
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

    return cm_text2str((text_t *)&word.text, sys_def->value, CT_PARAM_BUFFER_SIZE);
}

status_t sql_notify_als_longsql_timeout(void *se, void *item, char *value)
{
    uint64 timeout;
    CT_RETURN_IFERR(cm_str2microsecond(value, &timeout));
    cm_log_param_instance()->longsql_timeout = timeout; // convert s to micro-seconds
    return CT_SUCCESS;
}

status_t sql_verify_als_size(void *se, void *lex, void *def)
{
    return sql_verify_pool_size(lex, def, 0, CT_MAX_ARCH_FILES_SIZE);
}

status_t sql_verify_als_arch_size(void *se, void *lex, void *def)
{
    return sql_verify_pool_size(lex, def, 0, CT_MAX_BACKUP_BUF_SIZE);
}

status_t sql_verify_als_arch_file_size(void *se, void *lex, void *def)
{
    return sql_verify_pool_size(lex, def, 0, BUDDY_MEM_POOL_MAX_SIZE);
}

status_t sql_verify_als_time(void *se, void *lex, void *def)
{
    return sql_verify_pool_size(lex, def, CT_MIN_ARCH_TIME, CT_MAX_ARCH_TIME);
}

status_t sql_notify_als_arch_size(void *se, void *item, char *value)
{
    int64 val_int64;

    if (cm_str2size(value, &val_int64) != CT_SUCCESS) {
        return CT_ERROR;
    }

    g_instance->kernel.attr.max_arch_files_size = (uint64)val_int64;
    return CT_SUCCESS;
}

status_t sql_notify_als_need_arch_file_size(void *se, void *item, char *value)
{
    int64 val_int64;

    if (cm_str2size(value, &val_int64) != CT_SUCCESS) {
        return CT_ERROR;
    }

    g_instance->kernel.arch_ctx.arch_file_size = (uint64)val_int64;
    return CT_SUCCESS;
}

status_t sql_notify_als_need_arch_size(void *se, void *item, char *value)
{
    int64 val_int64;

    if (cm_str2size(value, &val_int64) != CT_SUCCESS) {
        return CT_ERROR;
    }

    g_instance->kernel.arch_ctx.arch_size = (uint64)val_int64;
    return CT_SUCCESS;
}

status_t sql_notify_als_need_arch_time(void *se, void *item, char *value)
{
    uint64 val_uint64;

    if (cm_str2uint64(value, &val_uint64) != CT_SUCCESS) {
        return CT_ERROR;
    }

    g_instance->kernel.arch_ctx.arch_time = val_uint64;
    return CT_SUCCESS;
}

status_t sql_notify_als_ignore_backup(void *se, void *item, char *value)
{
    g_instance->kernel.attr.arch_ignore_backup = value[0];

    return sql_notify_als_bool(se, item, value);
}

status_t sql_notify_als_ignore_standby(void *se, void *item, char *value)
{
    g_instance->kernel.attr.arch_ignore_standby = value[0];

    return sql_notify_als_bool(se, item, value);
}

status_t sql_verify_als_log_archive_dest_n(void *se, void *lex, void *def)
{
    word_t word;
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;
    if (CT_SUCCESS != lex_expected_fetch((lex_t *)lex, &word)) {
        return CT_ERROR;
    }
    if (word.type != WORD_TYPE_STRING) {
        CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, ", expected string type, but %s found", W2S(&word));
        return CT_ERROR;
    }
    LEX_REMOVE_WRAP(&word);
    return cm_text2str((text_t *)&word.text, sys_def->value, CT_PARAM_BUFFER_SIZE);
}

status_t sql_verify_als_log_archive_dest_state_n(void *se, void *lex, void *def)
{
    word_t word;
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;
    if (CT_SUCCESS != lex_expected_fetch((lex_t *)lex, &word)) {
        return CT_ERROR;
    }
    if (word.type != WORD_TYPE_STRING && word.type != WORD_TYPE_VARIANT && word.type != WORD_TYPE_DQ_STRING &&
        word.type != WORD_TYPE_KEYWORD) {
        CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, ", expected string type, but %s found", W2S(&word));
        return CT_ERROR;
    }
    if (word.type == WORD_TYPE_STRING) {
        LEX_REMOVE_WRAP(&word);
    }
    return cm_text2str((text_t *)&word.text, sys_def->value, CT_PARAM_BUFFER_SIZE);
}

status_t sql_notify_als_archive_dest_n(void *se, void *item, char *value)
{
    config_item_t *it = (config_item_t *)item;
    knl_session_t *session = (knl_session_t *)se;
    arch_context_t *ctx = &session->kernel->arch_ctx;
    uint32 param_id = it->id - PARAM_LOG_ARCHIVE_DEST_1;
    arch_attr_t arch_attr;

    CT_RETURN_IFERR(srv_alter_arch_dest(&arch_attr, param_id, value));
    if (arch_attr.dest_mode == LOG_ARCH_DEST_LOCATION) {
        CT_RETURN_IFERR(arch_set_dest(ctx, value + strlen("location="), param_id));
    }
    g_instance->kernel.attr.arch_attr[param_id] = arch_attr;

    return CT_SUCCESS;
}

status_t sql_notify_als_archive_dest_state_n(void *se, void *item, char *value)
{
    config_item_t *it = (config_item_t *)item;
    knl_session_t *session = (knl_session_t *)se;
    uint32 param_id = it->id - PARAM_LOG_ARCHIVE_DEST_STATE_1;

    return arch_set_dest_state(session, value, param_id, CT_TRUE);
}

status_t sql_notify_als_archive_format(void *se, void *item, char *value)
{
    knl_session_t *session = (knl_session_t *)se;
    arch_context_t *ctx = &session->kernel->arch_ctx;

    // need to ensure the format has asn/rst_id filed.
    return arch_set_format(ctx, value);
}

status_t sql_notify_als_archive_format_with_lsn(void *se, void *item, char *value)
{
    knl_session_t *session = (knl_session_t *)se;
    arch_context_t *ctx = &session->kernel->arch_ctx;
    return arch_set_format(ctx, value);
}

status_t sql_verify_als_raft_start_mode(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (num > CT_MAX_RAFT_START_MODE) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "RAFT_START_MODE", CT_MAX_RAFT_START_MODE);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_verify_als_raft_node_id(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (num < 1) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "RAFT_NODE_ID", (int64)1);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_verify_als_raft_log_level(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (num > CT_MAX_RAFT_LOG_LEVELE) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "RAFT_LOG_LEVEL", (int64)CT_MAX_RAFT_LOG_LEVELE);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_verify_als_raft_log_async_buf_num(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (num > CT_MAX_RAFT_LOG_ASYNC_BUF || num < 1) {
        CT_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "RAFT_LOG_ASYNC_BUF_NUM", (int64)1, (int64)CT_MAX_RAFT_LOG_ASYNC_BUF);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_verify_als_raft_priority_type(void *se, void *lex, void *def)
{
    word_t word;
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;
    if (CT_SUCCESS != lex_expected_fetch((lex_t *)lex, &word)) {
        return CT_ERROR;
    }
    if (word.type != WORD_TYPE_STRING) {
        CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "expected string type, but %s found", W2S(&word));
        return CT_ERROR;
    }

    sql_remove_quota(&word.text.value);
    if (strncmp(word.text.str, "AZFirst", word.text.len) && strncmp(word.text.str, "External", word.text.len) &&
        strncmp(word.text.str, "Static", word.text.len) && strncmp(word.text.str, "Random", word.text.len)) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "Priority Type");
        return CT_ERROR;
    }

    return cm_text2str((text_t *)&word.text, sys_def->value, CT_PARAM_BUFFER_SIZE);
}

status_t sql_verify_als_varchar_type_uint32(void *lex, void *def, uint32 *num)
{
    word_t word;
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;
    if (lex_expected_fetch((lex_t *)lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (word.type != WORD_TYPE_STRING) {
        CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, ", expected string type, but %s found", W2S(&word));
        return CT_ERROR;
    }

    sql_remove_quota(&word.text.value);

    if (word.text.len == 0) {
        CT_SRC_THROW_ERROR(word.loc, ERR_EMPTY_STRING_NOT_ALLOWED);
        return CT_ERROR;
    }

    if (cm_text2uint32((text_t *)&word.text, num)) {
        return CT_ERROR;
    }

    PRTS_RETURN_IFERR(snprintf_s(sys_def->value, CT_PARAM_BUFFER_SIZE, CT_PARAM_BUFFER_SIZE - 1, "%u", *num));
    return CT_SUCCESS;
}

status_t sql_verify_als_raft_priority_level(void *se, void *lex, void *def)
{
    uint32 level;
    if (sql_verify_als_varchar_type_uint32(lex, def, &level) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (level > CT_MAX_RAFT_PRIORITY_LEVEL) {
        CT_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "RAFT_PRIORITY_LEVEL", (int64)0, (int64)CT_MAX_RAFT_PRIORITY_LEVEL);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_verify_als_raft_pending_cmds_buffer_size(void *se, void *lex, void *def)
{
    uint32 size;
    if (sql_verify_uint32(lex, def, &size) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (size == 0) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "RAFT_PENDING_CMDS_BUFFER_SIZE", (int64)1);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_verify_als_raft_send_buffer_size(void *se, void *lex, void *def)
{
    uint32 size;
    if (sql_verify_uint32(lex, def, &size) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (size > CT_MAX_RAFT_SEND_BUFFER_SIZE || size < 1) {
        CT_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "RAFT_SEND_BUFFER_SIZE", (int64)1,
            (int64)CT_MAX_RAFT_SEND_BUFFER_SIZE);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_verify_als_raft_receive_buffer_size(void *se, void *lex, void *def)
{
    uint32 size;
    if (sql_verify_uint32(lex, def, &size) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (size > CT_MAX_RAFT_RECEIVE_BUFFER_SIZE || size < 1) {
        CT_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "RAFT_RECEIVE_BUFFER_SIZE", (int64)1,
            (int64)CT_MAX_RAFT_RECEIVE_BUFFER_SIZE);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_verify_als_raft_entry_cache_memory_size(void *se, void *lex, void *def)
{
    uint32 size;
    if (sql_verify_als_varchar_type_uint32(lex, def, &size) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (size == 0) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "RAFT_RAFT_ENTRY_CACHE_MEMORY_SIZE", (int64)1);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_verify_als_raft_max_size_per_msg(void *se, void *lex, void *def)
{
    uint32 size;
    if (sql_verify_als_varchar_type_uint32(lex, def, &size) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (size < CT_MIN_RAFT_PER_MSG_SIZE) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "RAFT_MAX_SIZE_PER_MSG", (int64)CT_MIN_RAFT_PER_MSG_SIZE);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_verify_als_raft_failover_lib_timeout(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (num < CT_MIN_RAFT_FAILOVER_WAIT_TIME) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "RAFT_FAILOVER_LIB_TIMEOUT", (int64)CT_MIN_RAFT_FAILOVER_WAIT_TIME);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_verify_als_raft_election_timeout(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (num < CT_MIN_RAFT_ELECTION_TIMEOUT) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "RAFT_ELECTION_TIMEOUT", (int64)CT_MIN_RAFT_ELECTION_TIMEOUT);
        return CT_ERROR;
    }

    if (num > CT_MAX_RAFT_ELECTION_TIMEOUT) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "RAFT_ELECTION_TIMEOUT", (int64)CT_MAX_RAFT_ELECTION_TIMEOUT);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_verify_als_raft_tls_dir(void *se, void *lex, void *def)
{
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;
    word_t word;
    if (lex_expected_fetch((lex_t *)lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (word.type != WORD_TYPE_STRING) {
        CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, ", expected string type, but %s found", W2S(&word));
        return CT_ERROR;
    }
    LEX_REMOVE_WRAP(&word);
    CT_RETURN_IFERR(cm_text2str((text_t *)&word.text, sys_def->value, CT_PARAM_BUFFER_SIZE));
    return verify_file_path((const char *)sys_def->value);
}

status_t sql_verify_als_raft_token_verify(void *se, void *lex, void *def)
{
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;
    word_t word;
    if (lex_expected_fetch((lex_t *)lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (word.type != WORD_TYPE_STRING) {
        CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, ", expected string type, but %s found", W2S(&word));
        return CT_ERROR;
    }
    LEX_REMOVE_WRAP(&word);
    CT_RETURN_IFERR(cm_text2str((text_t *)&word.text, sys_def->value, CT_PARAM_BUFFER_SIZE));
    if (strcmp((const char *)sys_def->value, "TRUE") == 0 || strcmp((const char *)sys_def->value, "FALSE") == 0) {
        return CT_SUCCESS;
    }
    CT_THROW_ERROR(ERR_INVALID_PARAMETER, "RAFT_TOKEN_VERIFY");
    return CT_ERROR;
}

status_t sql_notify_als_entry_cache_memory_size(void *se, void *item, char *value)
{
    int64 val_int64;
    if (cm_str2size(value, &val_int64) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "RAFT_RAFT_ENTRY_CACHE_MEMORY_SIZE");
        return CT_ERROR;
    }

    if (val_int64 == 0) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "RAFT_RAFT_ENTRY_CACHE_MEMORY_SIZE", (int64)1);
        return CT_ERROR;
    }

    int iret =
        sprintf_s(g_instance->kernel.attr.raft_entry_cache_memory_size, CT_MAX_NAME_LEN, "%llu", (uint64)val_int64);
    if (iret == -1) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, iret);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t sql_notify_als_max_size_per_msg(void *se, void *item, char *value)
{
    int64 val_int64;
    if (cm_str2size(value, &val_int64) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "RAFT_MAX_SIZE_PER_MSG");
        return CT_ERROR;
    }

    if (val_int64 < CT_MIN_RAFT_PER_MSG_SIZE) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "RAFT_MAX_SIZE_PER_MSG", (int64)CT_MIN_RAFT_PER_MSG_SIZE);
        return CT_ERROR;
    }

    int iret = sprintf_s(g_instance->kernel.attr.raft_max_size_per_msg, CT_MAX_NAME_LEN, "%llu", (uint64)val_int64);
    if (iret == -1) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, iret);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t sql_notify_als_raft_election_timeout(void *se, void *item, char *value)
{
    uint32 num;
    if (cm_str2uint32(value, &num) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "RAFT_ELECTION_TIMEOUT");
        return CT_ERROR;
    }

    if (num < CT_MIN_RAFT_ELECTION_TIMEOUT) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "RAFT_ELECTION_TIMEOUT", (int64)CT_MIN_RAFT_ELECTION_TIMEOUT);
        return CT_ERROR;
    }

    if (num > CT_MAX_RAFT_ELECTION_TIMEOUT) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "RAFT_ELECTION_TIMEOUT", (int64)CT_MAX_RAFT_ELECTION_TIMEOUT);
        return CT_ERROR;
    }

    int iret = sprintf_s(g_instance->kernel.attr.raft_election_timeout, CT_MAX_NAME_LEN, "%u", (uint32)num);
    if (iret == -1) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, iret);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t sql_notify_als_raft_mem_threshold(void *se, void *item, char *value)
{
    int64 val_int64;
    if (cm_str2size(value, &val_int64) != CT_SUCCESS || val_int64 < 0) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "RAFT_MEMORY_THRESHOLD");
        return CT_ERROR;
    }

    int iret = sprintf_s(g_instance->kernel.attr.raft_mem_threshold, CT_MAX_NAME_LEN, "%llu", (uint64)val_int64);
    if (iret == -1) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, iret);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

#ifdef __cplusplus
}
#endif
