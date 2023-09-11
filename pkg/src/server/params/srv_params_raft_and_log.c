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
 * srv_params_raft_and_log.c
 *
 *
 * IDENTIFICATION
 * src/server/params/srv_params_raft_and_log.c
 *
 * -------------------------------------------------------------------------
 */
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
    if (sql_verify_uint32(lex, def, &num) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (num < GS_INIT_BLACK_BOX_DEPTH || num > GS_MAX_BLACK_BOX_DEPTH) {
        GS_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "_BLACK_BOX_DEPTH", (int64)GS_INIT_BLACK_BOX_DEPTH,
            (int64)GS_MAX_BLACK_BOX_DEPTH);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

// check value is "a folder that already exists and has readable and writable permissions"
status_t sql_verify_als_file_dir(void *se, void *lex, void *def)
{
    word_t word;
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;

    if (lex_expected_fetch((lex_t *)lex, &word) != GS_SUCCESS) {
        return GS_ERROR;
    }
    if (word.type == WORD_TYPE_STRING) {
        sql_remove_quota(&word.text.value);
    }
    if (word.text.len >= GS_MAX_LOG_HOME_LEN) {
        GS_SRC_THROW_ERROR(word.text.loc, ERR_FILE_PATH_TOO_LONG, GS_MAX_LOG_HOME_LEN - 1);
        return GS_ERROR;
    }
    char *file_path = W2S(&word);
    if (!cm_dir_exist(file_path)) {
        GS_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "%s is not an existing folder", file_path);
        return GS_ERROR;
    }
    char real_path[GS_FILE_NAME_BUFFER_SIZE] = { 0x00 };
    GS_RETURN_IFERR(realpath_file(file_path, real_path, GS_FILE_NAME_BUFFER_SIZE));
    if (access(real_path, W_OK | R_OK) != 0) {
        GS_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "%s is not an readable or writable folder",
            file_path);
        return GS_ERROR;
    }
    return cm_text2str((text_t *)&word.text, sys_def->value, GS_PARAM_BUFFER_SIZE);
}

status_t sql_verify_als_log_backup_file_count(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (num > GS_MAX_LOG_FILE_COUNT) {
        GS_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "_LOG_BACKUP_FILE_COUNT", (int64)GS_MAX_LOG_FILE_COUNT);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t sql_notify_als_log_backup_file_count(void *se, void *item, char *value)
{
    return cm_str2uint32(value, &cm_log_param_instance()->log_backup_file_count);
}

status_t sql_verify_log_file_size(void *se, void *lex, void *def)
{
    return sql_verify_pool_size(lex, def, GS_MIN_LOG_FILE_SIZE, GS_MAX_LOG_FILE_SIZE);
}

status_t sql_notify_als_log_max_file_size(void *se, void *item, char *value)
{
    int64 val_int64;

    if (cm_str2size(value, &val_int64) != GS_SUCCESS) {
        return GS_ERROR;
    }

    cm_log_param_instance()->max_log_file_size = (uint64)val_int64;

    return GS_SUCCESS;
}

status_t sql_verify_pbl_file_size(void *se, void *lex, void *def)
{
    return sql_verify_pool_size(lex, def, GS_MIN_PBL_FILE_SIZE, GS_MAX_PBL_FILE_SIZE);
}

status_t sql_verify_als_log_mode_value(lex_t *lex, knl_alter_sys_def_t *def)
{
    word_t word;
    knl_alter_sys_def_t *sys_def = def;
    if (lex_expected_fetch((lex_t *)lex, &word) != GS_SUCCESS) {
        return GS_ERROR;
    }
    if (word.type == WORD_TYPE_STRING) {
        sql_remove_quota(&word.text.value);
    }

    if (IS_LONGSQL_LOG_MODE(sys_def->param)) {
        if (cm_text_str_equal_ins(&word.text.value, "ON") || cm_text_str_equal_ins(&word.text.value, "OFF")) {
            cm_text2str_with_upper((text_t *)&word.text, sys_def->value, GS_PARAM_BUFFER_SIZE);
            return GS_SUCCESS;
        }
    } else if (IS_LOG_LEVEL_MODE(sys_def->param)) {
        if (cm_text_str_equal_ins(&word.text.value, "DEBUG") || cm_text_str_equal_ins(&word.text.value, "WARN") ||
            cm_text_str_equal_ins(&word.text.value, "ERROR") || cm_text_str_equal_ins(&word.text.value, "RUN") ||
            cm_text_str_equal_ins(&word.text.value, "FATAL")) {
            cm_text2str_with_upper((text_t *)&word.text, sys_def->value, GS_PARAM_BUFFER_SIZE);
            return GS_SUCCESS;
        }
    }
    GS_SRC_THROW_ERROR_EX(word.text.loc, ERR_INVALID_PARAMETER, "%s", W2S(&word));
    return GS_ERROR;
}

status_t cm_find_log_mode_method(const log_mode_map_t *log_map, text_t name, text_t value, uint32 *result)
{
    for (size_t i = 0; i < LOG_MODE_MAP_LENGTH; i++) {
        if (!cm_compare_text_ins(&name, &log_map[i].name) && !cm_compare_text_ins(&value, &log_map[i].value)) {
            *result = log_map[i].method;
            return GS_SUCCESS;
        }
    }
    GS_THROW_ERROR(ERR_INVALID_PARAMETER, name);
    return GS_ERROR;
}

status_t cm_set_log_level_int_value(uint32 method, uint32 *log_level_value_int, const char *val)
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
            GS_THROW_ERROR(ERR_INVALID_PARAMETER, val);
            return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t cm_set_def_param(knl_alter_sys_def_t *def, const char *name)
{
    char temp[GS_VALUE_BUFFER_SIZE];
    text_t name_text;
    name_text.str = temp;
    name_text.len = 0;
    cm_str2text((char *)name, &name_text);
    return cm_text2str(&name_text, ((knl_alter_sys_def_t *)def)->param, name_text.len + 1);
}

status_t cm_set_def_value(knl_alter_sys_def_t *def, uint32 value)
{
    char temp[GS_VALUE_BUFFER_SIZE];
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
    config_item_t *item = cm_get_config_item(GET_CONFIG, &name, GS_FALSE);
    uint32 log_level_value_int;
    cm_str2uint32(item->is_default ? item->default_value : item->value, &log_level_value_int);

    // translate into _LOG_LEVEL value
    text_t name_text;
    text_t value_text;
    uint32 method;
    cm_str2text(sys_def->param, &name_text);
    cm_str2text(sys_def->value, &value_text);
    GS_RETURN_IFERR(cm_find_log_mode_method(g_log_map_set, name_text, value_text, &method));
    GS_RETURN_IFERR(cm_set_log_level_int_value(method, &log_level_value_int, sys_def->value));

    // set def
    GS_RETURN_IFERR(cm_set_def_value(def, log_level_value_int));
    GS_RETURN_IFERR(cm_set_def_param(def, "_LOG_LEVEL"));
    return GS_SUCCESS;
}

status_t sql_verify_als_log_level_value(lex_t *lex, knl_alter_sys_def_t *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (num > MAX_LOG_LEVEL) {
        GS_THROW_ERROR(ERR_INVALID_PARAMETER, "_LOG_LEVEL");
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

status_t sql_verify_als_log_level(void *se, void *lex, void *def)
{
    if (IS_LOG_MODE(((knl_alter_sys_def_t *)def)->param)) {
        GS_RETURN_IFERR(sql_verify_als_log_mode_value((lex_t *)lex, (knl_alter_sys_def_t *)def));

        GS_RETURN_IFERR(cm_set_log_level_value((knl_alter_sys_def_t *)def));
    } else {
        GS_RETURN_IFERR(sql_verify_als_log_level_value((lex_t *)lex, (knl_alter_sys_def_t *)def));
    }
    return GS_SUCCESS;
}

status_t sql_notify_als_pbl_max_file_size(void *se, void *item, char *value)
{
    int64 val_int64;

    if (cm_str2size(value, &val_int64) != GS_SUCCESS) {
        return GS_ERROR;
    }
    cm_log_param_instance()->max_pbl_file_size = (uint64)val_int64;
    return GS_SUCCESS;
}

status_t sql_notify_als_log_level(void *se, void *item, char *value)
{
    GS_RETURN_IFERR(cm_str2uint32(value, &cm_log_param_instance()->log_level));
    return GS_SUCCESS;
}

status_t sql_verify_als_log_file(void *se, void *lex, void *def)
{
    uint32 num;
    uint32 usr_perm;
    uint32 grp_perm;
    uint32 oth_perm;
    if (sql_verify_uint32(lex, def, &num) != GS_SUCCESS) {
        return GS_ERROR;
    }

    usr_perm = (num / 100) % 10;
    grp_perm = (num / 10) % 10;
    oth_perm = num % 10;

    if (usr_perm > GS_MAX_LOG_USER_PERMISSION || grp_perm > GS_MAX_LOG_USER_PERMISSION ||
        oth_perm > GS_MAX_LOG_USER_PERMISSION) {
        GS_THROW_ERROR(ERR_INVALID_PARAMETER, "_LOG_FILE_PERMISSIONS");
        return GS_ERROR;
    }

    if (num < GS_DEF_LOG_FILE_PERMISSIONS || num > GS_MAX_LOG_PERMISSIONS) {
        GS_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "_LOG_FILE_PERMISSIONS", (int64)GS_DEF_LOG_FILE_PERMISSIONS,
            (int64)GS_MAX_LOG_PERMISSIONS);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t sql_verify_als_log_path(void *se, void *lex, void *def)
{
    uint32 num;
    uint32 usr_perm;
    uint32 grp_perm;
    uint32 oth_perm;
    if (sql_verify_uint32(lex, def, &num) != GS_SUCCESS) {
        return GS_ERROR;
    }

    usr_perm = (num / 100) % 10;
    grp_perm = (num / 10) % 10;
    oth_perm = num % 10;

    if (usr_perm > GS_MAX_LOG_USER_PERMISSION || grp_perm > GS_MAX_LOG_USER_PERMISSION ||
        oth_perm > GS_MAX_LOG_USER_PERMISSION) {
        GS_THROW_ERROR(ERR_INVALID_PARAMETER, "_LOG_PATH_PERMISSIONS");
        return GS_ERROR;
    }

    if (num < GS_DEF_LOG_PATH_PERMISSIONS || num > GS_MAX_LOG_PERMISSIONS) {
        GS_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "_LOG_PATH_PERMISSIONS", (int64)GS_DEF_LOG_PATH_PERMISSIONS,
            (int64)GS_MAX_LOG_PERMISSIONS);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t sql_notify_als_log_file_permissions(void *se, void *item, char *value)
{
    uint16 val;
    if (cm_str2uint16(value, &val) != GS_SUCCESS) {
        return GS_ERROR;
    }

    cm_log_set_file_permissions(val);
    return GS_SUCCESS;
}

status_t sql_notify_als_log_path_permissions(void *se, void *item, char *value)
{
    uint16 val;
    if (cm_str2uint16(value, &val) != GS_SUCCESS) {
        return GS_ERROR;
    }

    cm_log_set_path_permissions(val);
    return GS_SUCCESS;
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
    if (lex_expected_fetch((lex_t *)lex, &word) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (word.type == WORD_TYPE_STRING) {
        sql_remove_quota(&word.text.value);
        cm_trim_text(&word.text.value);
    }

    if (word.type == WORD_TYPE_DQ_STRING) {
        cm_trim_text(&word.text.value);
    }

    if (word.text.len == 0) {
        GS_SRC_THROW_ERROR(word.loc, ERR_EMPTY_STRING_NOT_ALLOWED);
        return GS_ERROR;
    }

    return cm_text2str((text_t *)&word.text, sys_def->value, GS_PARAM_BUFFER_SIZE);
}

status_t sql_notify_als_longsql_timeout(void *se, void *item, char *value)
{
    uint64 timeout;
    GS_RETURN_IFERR(cm_str2microsecond(value, &timeout));
    cm_log_param_instance()->longsql_timeout = timeout; // convert s to micro-seconds
    return GS_SUCCESS;
}

status_t sql_verify_als_size(void *se, void *lex, void *def)
{
    return sql_verify_pool_size(lex, def, 0, GS_MAX_ARCH_FILES_SIZE);
}

status_t sql_verify_als_arch_size(void *se, void *lex, void *def)
{
    return sql_verify_pool_size(lex, def, 0, GS_MAX_BACKUP_BUF_SIZE);
}

status_t sql_verify_als_arch_file_size(void *se, void *lex, void *def)
{
    return sql_verify_pool_size(lex, def, 0, BUDDY_MEM_POOL_MAX_SIZE);
}

status_t sql_verify_als_time(void *se, void *lex, void *def)
{
    return sql_verify_pool_size(lex, def, GS_MIN_ARCH_TIME, GS_MAX_ARCH_TIME);
}

status_t sql_notify_als_arch_size(void *se, void *item, char *value)
{
    int64 val_int64;

    if (cm_str2size(value, &val_int64) != GS_SUCCESS) {
        return GS_ERROR;
    }

    g_instance->kernel.attr.max_arch_files_size = (uint64)val_int64;
    return GS_SUCCESS;
}

status_t sql_notify_als_need_arch_file_size(void *se, void *item, char *value)
{
    int64 val_int64;

    if (cm_str2size(value, &val_int64) != GS_SUCCESS) {
        return GS_ERROR;
    }

    g_instance->kernel.arch_ctx.arch_file_size = (uint64)val_int64;
    return GS_SUCCESS;
}

status_t sql_notify_als_need_arch_size(void *se, void *item, char *value)
{
    int64 val_int64;

    if (cm_str2size(value, &val_int64) != GS_SUCCESS) {
        return GS_ERROR;
    }

    g_instance->kernel.arch_ctx.arch_size = (uint64)val_int64;
    return GS_SUCCESS;
}

status_t sql_notify_als_need_arch_time(void *se, void *item, char *value)
{
    uint64 val_uint64;

    if (cm_str2uint64(value, &val_uint64) != GS_SUCCESS) {
        return GS_ERROR;
    }

    g_instance->kernel.arch_ctx.arch_time = val_uint64;
    return GS_SUCCESS;
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
    if (GS_SUCCESS != lex_expected_fetch((lex_t *)lex, &word)) {
        return GS_ERROR;
    }
    if (word.type != WORD_TYPE_STRING) {
        GS_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, ", expected string type, but %s found", W2S(&word));
        return GS_ERROR;
    }
    LEX_REMOVE_WRAP(&word);
    return cm_text2str((text_t *)&word.text, sys_def->value, GS_PARAM_BUFFER_SIZE);
}

status_t sql_verify_als_log_archive_dest_state_n(void *se, void *lex, void *def)
{
    word_t word;
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;
    if (GS_SUCCESS != lex_expected_fetch((lex_t *)lex, &word)) {
        return GS_ERROR;
    }
    if (word.type != WORD_TYPE_STRING && word.type != WORD_TYPE_VARIANT && word.type != WORD_TYPE_DQ_STRING &&
        word.type != WORD_TYPE_KEYWORD) {
        GS_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, ", expected string type, but %s found", W2S(&word));
        return GS_ERROR;
    }
    if (word.type == WORD_TYPE_STRING) {
        LEX_REMOVE_WRAP(&word);
    }
    return cm_text2str((text_t *)&word.text, sys_def->value, GS_PARAM_BUFFER_SIZE);
}

status_t sql_notify_als_archive_dest_n(void *se, void *item, char *value)
{
    config_item_t *it = (config_item_t *)item;
    knl_session_t *session = (knl_session_t *)se;
    arch_context_t *ctx = &session->kernel->arch_ctx;
    uint32 param_id = it->id - PARAM_LOG_ARCHIVE_DEST_1;
    arch_attr_t arch_attr;

    GS_RETURN_IFERR(server_alter_arch_dest(&arch_attr, param_id, value));
    if (arch_attr.dest_mode == LOG_ARCH_DEST_LOCATION) {
        GS_RETURN_IFERR(arch_set_dest(ctx, value + strlen("location="), param_id));
    }
    g_instance->kernel.attr.arch_attr[param_id] = arch_attr;

    return GS_SUCCESS;
}

status_t sql_notify_als_archive_dest_state_n(void *se, void *item, char *value)
{
    config_item_t *it = (config_item_t *)item;
    knl_session_t *session = (knl_session_t *)se;
    uint32 param_id = it->id - PARAM_LOG_ARCHIVE_DEST_STATE_1;

    return arch_set_dest_state(session, value, param_id, GS_TRUE);
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

status_t sql_verify_als_varchar_type_uint32(void *lex, void *def, uint32 *num)
{
    word_t word;
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;
    if (lex_expected_fetch((lex_t *)lex, &word) != GS_SUCCESS) {
        return GS_ERROR;
    }
    if (word.type != WORD_TYPE_STRING) {
        GS_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, ", expected string type, but %s found", W2S(&word));
        return GS_ERROR;
    }

    sql_remove_quota(&word.text.value);

    if (word.text.len == 0) {
        GS_SRC_THROW_ERROR(word.loc, ERR_EMPTY_STRING_NOT_ALLOWED);
        return GS_ERROR;
    }

    if (cm_text2uint32((text_t *)&word.text, num)) {
        return GS_ERROR;
    }

    PRTS_RETURN_IFERR(snprintf_s(sys_def->value, GS_PARAM_BUFFER_SIZE, GS_PARAM_BUFFER_SIZE - 1, "%u", *num));
    return GS_SUCCESS;
}

#ifdef __cplusplus
}
#endif
