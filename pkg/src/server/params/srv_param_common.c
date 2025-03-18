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
 * srv_param_common.c
 *
 *
 * IDENTIFICATION
 * src/server/params/srv_param_common.c
 *
 * -------------------------------------------------------------------------
 */
#include "srv_module.h"
#include "srv_instance.h"
#include "srv_param_common.h"

#ifdef __cplusplus
extern "C" {
#endif

// ADD CONFIG VERIFY-NOTIFY FUNC HERE
status_t sql_verify_als_comm(void *se, void *lex, void *def)
{
    word_t word;
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;
    if (lex_expected_fetch((lex_t *)lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (word.type == WORD_TYPE_STRING) {
        sql_remove_quota(&word.text.value);
    }

    if (word.text.value.len >= CT_PARAM_BUFFER_SIZE) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, sys_def->param, (int64)CT_PARAM_BUFFER_SIZE - 1);
        return CT_ERROR;
    }

    return cm_text2str((text_t *)&word.text, sys_def->value, CT_PARAM_BUFFER_SIZE);
}

status_t sql_verify_als_onoff(void *se, void *lex, void *def)
{
    uint32 match_id;
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;
    if (lex_expected_fetch_1of2((lex_t *)lex, "OFF", "ON", &match_id) != CT_SUCCESS) {
        return CT_ERROR;
    }
    sys_def->value[0] = (char)match_id;
    return CT_SUCCESS;
}

status_t sql_verify_als_uint32(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t sql_verify_uint32(void *lex, void *def, uint32 *num)
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

    if (cm_text2uint32((text_t *)&word.text, num)) {
        return CT_ERROR;
    }

    PRTS_RETURN_IFERR(
        snprintf_s(sys_def->value, CT_PARAM_BUFFER_SIZE, CT_PARAM_BUFFER_SIZE - 1, PRINT_FMT_UINT32, *num));
    return CT_SUCCESS;
}

status_t sql_verify_als_bool(void *se, void *lex, void *def)
{
    uint32 match_id;
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;
    // match_id matched with CT_FALSE/CT_TRUE
    if (lex_expected_fetch_1of2((lex_t *)lex, "FALSE", "TRUE", &match_id) != CT_SUCCESS) {
        return CT_ERROR;
    }
    sys_def->value[0] = (char)match_id;
    return CT_SUCCESS;
}

status_t sql_notify_als_bool(void *se, void *item, char *value)
{
    if ((bool32)value[0] == CT_TRUE) {
        PRTS_RETURN_IFERR(snprintf_s(value, CT_PARAM_BUFFER_SIZE, CT_PARAM_BUFFER_SIZE - 1, "TRUE"));
    } else {
        PRTS_RETURN_IFERR(snprintf_s(value, CT_PARAM_BUFFER_SIZE, CT_PARAM_BUFFER_SIZE - 1, "FALSE"));
    }

    return CT_SUCCESS;
}

status_t sql_notify_prevent_backup_recycle(void *se, void *item, char *value)
{
    knl_session_t *session = (knl_session_t *)se;
    if (session == NULL) {
        CT_THROW_ERROR(ERR_SESSION_CLOSED, "session is null");
        CT_LOG_RUN_ERR("prevent log recycle failed, session is null");
        return CT_ERROR;
    }
    bool32 is_prevent = (bool32)value[0];
    CT_LOG_RUN_INF("notify prevent value, value %u", is_prevent);

    // 防止对端节点并发发起创建快照
    if (session->kernel->attr.prevent_create_snapshot) {
        CT_THROW_ERROR(ERR_CLT_CLUSTER_INVALID, "other node is creating snapshot");
        CT_LOG_RUN_ERR("prevent log recycle failed, prevent_create_snapshot is true");
        return CT_ERROR;
    }

    if (session->kernel->attr.prevent_snapshot_backup_recycle_redo == CT_TRUE && is_prevent == CT_TRUE) {
        CT_THROW_ERROR(ERR_CLT_CLUSTER_INVALID, "node is creating snapshot");
        CT_LOG_RUN_ERR("prevent log recycle failed, is creating snapshot");
        return CT_ERROR;
    }

    if (bak_precheck(session) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_CLT_CLUSTER_INVALID, "backup precheck failed");
        CT_LOG_RUN_ERR("prevent log recycle failed, bak_precheck failed");
        return CT_ERROR;
    }

    uint32 prevent_timeout = session->kernel->attr.prevent_snapshot_backup_recycle_redo_timeout;
    mes_prevent_snapshot_recycle_redo_t msg = {.timeout = prevent_timeout, .is_prevent = is_prevent};
    mes_init_send_head(&msg.head, MES_CMD_SNAPSHOT_PREVENT_RECYCLE_REDO, sizeof(mes_prevent_snapshot_recycle_redo_t), CT_INVALID_ID32,
                       session->kernel->id, CT_INVALID_ID8, session->id, CT_INVALID_ID16);

    status_t ret = mes_broadcast_data_and_wait_with_retry(session->id, MES_BROADCAST_ALL_INST, &msg, LOG_BROADCAST_PREVENT_TIMEOUT, LOG_BROADCAST_PREVENT_RETRYTIME);

    if (ret != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_CLT_CLUSTER_INVALID, "message broadcast failed");
        CT_LOG_RUN_ERR("prevent log recycle failed, ret %d", ret);
        return CT_ERROR;
    }

    SYNC_POINT_GLOBAL_START(CTC_BACKUP_STOP_REDO_RECYCLE_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;

    CT_RETURN_IFERR(sql_notify_als_bool(se, item, value));
    return cm_str2bool(value, &g_instance->kernel.attr.prevent_snapshot_backup_recycle_redo);
}

status_t sql_notify_als_onoff(void *se, void *item, char *value)
{
    int iret_snprintf;
    if ((bool32)value[0] == CT_TRUE) {
        iret_snprintf = snprintf_s(value, CT_PARAM_BUFFER_SIZE, CT_PARAM_BUFFER_SIZE - 1, "ON");
    } else {
        iret_snprintf = snprintf_s(value, CT_PARAM_BUFFER_SIZE, CT_PARAM_BUFFER_SIZE - 1, "OFF");
    }
    if (iret_snprintf == -1) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, (iret_snprintf));
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

char *srv_get_param(const char *name)
{
    return cm_get_config_value(&g_instance->config, name);
}

status_t srv_get_param_bool32(char *param_name, bool32 *param_value)
{
    char *value = srv_get_param(param_name);
    if (cm_str_equal_ins(value, "TRUE")) {
        *param_value = CT_TRUE;
    } else if (cm_str_equal_ins(value, "FALSE")) {
        *param_value = CT_FALSE;
    } else {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, param_name);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t srv_get_param_onoff(char *param_name, bool32 *param_value)
{
    char *value = srv_get_param(param_name);
    if (cm_str_equal_ins(value, "ON")) {
        *param_value = CT_TRUE;
    } else if (cm_str_equal_ins(value, "OFF")) {
        *param_value = CT_FALSE;
    } else {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, param_name);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t srv_get_param_uint16(char *param_name, uint16 *param_value)
{
    char *value = srv_get_param(param_name);
    if (value == NULL || strlen(value) == 0) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, param_name);
        return CT_ERROR;
    }

    if (cm_str2uint16(value, param_value) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, param_name);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t srv_get_param_uint32(char *param_name, uint32 *param_value)
{
    char *value = srv_get_param(param_name);
    if (value == NULL || strlen(value) == 0) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, param_name);
        return CT_ERROR;
    }

    if (cm_str2uint32(value, param_value) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, param_name);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t srv_get_param_uint64(char *param_name, uint64 *param_value)
{
    char *value = srv_get_param(param_name);
    if (value == NULL || strlen(value) == 0) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, param_name);
        return CT_ERROR;
    }

    if (cm_str2uint64(value, param_value) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, param_name);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t srv_get_param_second(char *param_name, uint64 *param_value)
{
    char *value = srv_get_param(param_name);
    if (value == NULL || strlen(value) == 0) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, param_name);
        return CT_ERROR;
    }

    if (cm_str2microsecond(value, param_value) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t srv_get_param_double(char *param_name, double *param_value)
{
    char *value = srv_get_param(param_name);
    if (value == NULL || strlen(value) == 0) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, param_name);
        return CT_ERROR;
    }

    if (cm_str2real(value, param_value) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, param_name);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t srv_get_param_size_uint32(char *param_name, uint32 *param_value)
{
    char *value = srv_get_param(param_name);
    int64 val_int64 = 0;

    if (value == NULL || strlen(value) == 0) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, param_name);
        return CT_ERROR;
    }

    if (cm_str2size(value, &val_int64) != CT_SUCCESS || val_int64 < 0 || val_int64 > UINT_MAX) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, param_name);
        return CT_ERROR;
    }

    *param_value = (uint32)val_int64;
    return CT_SUCCESS;
}

status_t srv_get_param_size_uint64(char *param_name, uint64 *param_value)
{
    char *value = srv_get_param(param_name);
    int64 val_int64 = 0;

    if (value == NULL || strlen(value) == 0) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, param_name);
        return CT_ERROR;
    }

    if (cm_str2size(value, &val_int64) != CT_SUCCESS || val_int64 < 0) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, param_name);
        return CT_ERROR;
    }

    *param_value = (uint64)val_int64;
    return CT_SUCCESS;
}

status_t srv_verf_param_uint64(char *param_name, uint64 param_value, uint64 min_value, uint64 max_value)
{
    if (param_value < min_value) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, param_name, (int64)min_value);
        return CT_ERROR;
    }
    if (param_value > max_value) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, param_name, (int64)max_value);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t sql_verify_pool_size(void *lex, void *def, int64 min_size, int64 max_size)
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
    if (lex_expected_fetch_size(lex, &size, min_size, max_size) != CT_SUCCESS) {
        lex_pop(lex);
        return CT_ERROR;
    }
    lex_pop(lex);

    return cm_text2str((text_t *)&word.text, sys_def->value, CT_PARAM_BUFFER_SIZE);
}

#define HOUR_MAX 23
#define MINUTE_MAX 59
#define SECOND_MAX 59
#define TIME_MIN 0
status_t srv_get_index_auto_rebuild(char *time_str, knl_attr_t *attr)
{
    text_t time_text;
    uint32 hour, minute, second;
    cm_str2text(time_str, &time_text);
    cm_trim_text(&time_text);

    if (time_text.len == 0) {
        attr->idx_auto_rebuild_start_date = CT_INVALID_ID32;
        return CT_SUCCESS;
    }

    if (cm_fetch_date_field(&time_text, TIME_MIN, HOUR_MAX, ':', &hour) != CT_SUCCESS ||
        cm_fetch_date_field(&time_text, TIME_MIN, MINUTE_MAX, ':', &minute) != CT_SUCCESS ||
        cm_fetch_date_field(&time_text, TIME_MIN, SECOND_MAX, '\0', &second) != CT_SUCCESS || time_text.len != 0) {
        cm_reset_error();
        CT_THROW_ERROR(ERR_TEXT_FORMAT_ERROR, "time");
        return CT_ERROR;
    }

    attr->idx_auto_rebuild_start_date = hour * SECONDS_PER_HOUR + minute * SECONDS_PER_MIN + second;
    return CT_SUCCESS;
}

#ifdef __cplusplus
}
#endif