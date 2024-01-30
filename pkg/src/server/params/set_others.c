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
 * set_others.c
 *
 *
 * IDENTIFICATION
 * src/server/params/set_others.c
 *
 * -------------------------------------------------------------------------
 */
#include "srv_module.h"
#include "srv_instance.h"
#include "cbo_base.h"
#include "pl_executor.h"
#include "srv_param_common.h"
#include "set_others.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t sql_verify_ip_address(lex_t *lex, char *ipstr, uint32 len)
{
    uint32 ip_len = 0;
    uint32 ip_count = 0;
    char *ip = ipstr;
    char *pos = NULL;

    /*
     * This routine is shared by LSNR_ADDR and REPL_TRUST_HOST, LSNR_ADDR is not allowed to set empty,
     * but REPL_TRUST_HOST is ok.
     */
    if (len == 0 && cm_strnstri(lex->text.str, lex->text.len, "LSNR_ADDR", (uint32)strlen("LSNR_ADDR")) != NULL) {
        CT_SRC_THROW_ERROR(LEX_LOC, ERR_TCP_INVALID_IPADDRESS, "");
        return CT_ERROR;
    }
    uint32 tmp_len = len;
    for (pos = ipstr; tmp_len > 0; tmp_len--) {
        if (*pos != ',') {
            ip_len++;
            pos++;
            continue;
        }

        if (ip_count >= CT_MAX_LSNR_HOST_COUNT) {
            CT_SRC_THROW_ERROR(LEX_LOC, ERR_IPADDRESS_NUM_EXCEED, (uint32)CT_MAX_LSNR_HOST_COUNT);
            return CT_ERROR;
        }

        *pos = '\0';
        if (tmp_len == 1 || !cm_check_ip_valid(ip)) {
            CT_SRC_THROW_ERROR(LEX_LOC, ERR_TCP_INVALID_IPADDRESS, (tmp_len == 1) ? "" : ip);
            return CT_ERROR;
        }

        *pos = ',';
        ip += (ip_len + 1);
        ip_count++;
        ip_len = 0;
        pos = ip;
    }

    if (ip_len > 0) {
        if (ip_count >= CT_MAX_LSNR_HOST_COUNT) {
            CT_SRC_THROW_ERROR(LEX_LOC, ERR_IPADDRESS_NUM_EXCEED, (uint32)CT_MAX_LSNR_HOST_COUNT);
            return CT_ERROR;
        }

        if (!cm_check_ip_valid(ip)) {
            CT_SRC_THROW_ERROR(LEX_LOC, ERR_TCP_INVALID_IPADDRESS, ip);
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

status_t sql_verify_als_ip(void *se, void *lex, void *def)
{
    word_t word;
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;

    if (lex_expected_fetch((lex_t *)lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (word.type == WORD_TYPE_STRING) {
        sql_remove_quota(&word.text.value);
    }

    cm_trim_text((text_t *)&word.text);
    CT_RETURN_IFERR(cm_text2str((text_t *)&word.text, sys_def->value, CT_PARAM_BUFFER_SIZE));

    /* check if the ip address specified is valid */
    return sql_verify_ip_address((lex_t *)lex, sys_def->value, (uint32)strlen(sys_def->value));
}

status_t sql_verify_param_port(void *lex, void *def, const char *port_name)
{
    word_t word;
    uint16 port;
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;
    if (lex_expected_fetch((lex_t *)lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (word.type == WORD_TYPE_STRING) {
        CM_REMOVE_ENCLOSED_CHAR(&(word.text));
    }

    if (word.type == WORD_TYPE_DQ_STRING) {
        cm_trim_text(&word.text.value);
    }

    if (word.text.len == 0) {
        CT_SRC_THROW_ERROR(word.loc, ERR_EMPTY_STRING_NOT_ALLOWED);
        return CT_ERROR;
    }
    CT_RETURN_IFERR(cm_text2str((text_t *)&word.text, sys_def->value, CT_PARAM_BUFFER_SIZE));

    /* check if the port specified is valid */
    if (cm_str2uint16(sys_def->value, &port) != CT_SUCCESS) {
        cm_reset_error();
        CT_SRC_THROW_ERROR(((lex_t *)lex)->loc, ERR_INVALID_PARAMETER, port_name);
        return CT_ERROR;
    }

    if (port < CT_MIN_PORT) {
        CT_SRC_THROW_ERROR(((lex_t *)lex)->loc, ERR_PARAMETER_TOO_SMALL, port_name, (int64)CT_MIN_PORT);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_verify_als_port(void *se, void *lex, void *def)
{
    return sql_verify_param_port(lex, def, "port");
}

status_t sql_verify_als_worker_threads(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (num < CT_MIN_WORKER_THREADS || num > CT_MAX_WORKER_THREADS) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "WORKER_THREADS");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t sql_verify_als_sql_compat(void *se, void *lex, void *def)
{
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;
    // match_id matched with sql_style_t
    if (lex_expected_fetch_word((lex_t *)lex, "CTDB") != CT_SUCCESS) {
        return CT_ERROR;
    }
    sys_def->value[0] = (char)SQL_STYLE_CT;
    return CT_SUCCESS;
}

status_t sql_notify_als_sql_compat(void *se, void *item, char *value)
{
    PRTS_RETURN_IFERR(snprintf_s(value, CT_PARAM_BUFFER_SIZE, CT_PARAM_BUFFER_SIZE - 1, "CTDB"));
    return CT_SUCCESS;
}

status_t sql_verify_als_pma_buf_size(void *se, void *lex, void *def)
{
    return sql_verify_pool_size(lex, def, 0, PMA_MAX_SIZE);
}

status_t sql_verify_als_hash_area_size(void *se, void *lex, void *def)
{
    return sql_verify_pool_size(lex, def, 0, PMA_MAX_SIZE);
}

status_t sql_notify_als_hash_area_size(void *se, void *item, char *value)
{
    int64 hash_area_size;
    if (cm_str2size(value, &hash_area_size) != CT_SUCCESS) {
        return CT_ERROR;
    }
    g_instance->sql.hash_area_size = CM_CALC_ALIGN((uint64)hash_area_size, PMA_PAGE_SIZE);
    return CT_SUCCESS;
}

status_t sql_notify_als__hint_force(void *se, void *item, char *value)
{
    return cm_str2uint32(value, &g_instance->attr.hint_force);
}

status_t sql_verify_als_stack_size(void *se, void *lex, void *def)
{
    return sql_verify_pool_size(lex, def, CT_MIN_STACK_SIZE, CT_INVALID_ID32);
}

status_t sql_verify_als_lob_max_exec_size(void *se, void *lex, void *def)
{
    word_t word;
    int64 size;
    int64 stack_size = 0;
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
    char *value = srv_get_param("_AGENT_STACK_SIZE");
    if (cm_str2size(value, &stack_size) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "_AGENT_STACK_SIZE");
        return CT_ERROR;
    }
    if (lex_expected_fetch_size(lex, &size, 0, stack_size) != CT_SUCCESS) {
        lex_pop(lex);
        return CT_ERROR;
    }
    lex_pop(lex);

    return cm_text2str((text_t *)&word.text, sys_def->value, CT_PARAM_BUFFER_SIZE);
}

status_t sql_verify_als_variant_size(void *se, void *lex, void *def)
{
    return sql_verify_pool_size(lex, def, CT_MIN_VARIANT_SIZE, CT_MAX_VARIANT_SIZE);
}

status_t sql_verify_als_init_cursors(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (num > CT_MAX_INIT_CURSORS) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "_INIT_CURSORS", (int64)CT_MAX_INIT_CURSORS);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t sql_verify_als_autonomous_sessions(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (num > CT_MAX_AUTON_SESSIONS) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "AUTONOMOUS_SESSIONS", (int64)CT_MAX_AUTON_SESSIONS);
        return CT_ERROR;
    }
    if (num < 1) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "AUTONOMOUS_SESSIONS", (int64)1);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_verify_als_open_curs(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (num < CT_MIN_OPEN_CURSORS) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "OPEN_CURSORS", (int64)CT_MIN_OPEN_CURSORS);
        return CT_ERROR;
    }
    if (num > CT_MAX_OPEN_CURSORS) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "OPEN_CURSORS", (int64)CT_MAX_OPEN_CURSORS);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t sql_notify_als_open_curs(void *se, void *item, char *value)
{
    uint32 val;
    if (cm_str2uint32(value, &val) != CT_SUCCESS) {
        return CT_ERROR;
    }
    g_instance->attr.open_cursors = val;
    return CT_SUCCESS;
}

static status_t sql_verify_als_log_archive_send_cfg(void *lex, bool32 *is_parse, bool32 *is_more)
{
    if (*is_parse) {
        CT_THROW_ERROR(ERR_LOG_ARCHIVE_CONFIG_TOO_MANY, "send");
        return CT_ERROR;
    }

    *is_parse = CT_TRUE;
    CT_RETURN_IFERR(lex_try_fetch_char(lex, ',', is_more));
    if (*is_more == CT_FALSE) {
        CT_RETURN_IFERR(lex_expected_end(lex));
    }

    return CT_SUCCESS;
}

static status_t sql_verify_als_log_archive_receive_cfg(void *lex, bool32 *is_parse, bool32 *is_more)
{
    if (*is_parse) {
        CT_THROW_ERROR(ERR_LOG_ARCHIVE_CONFIG_TOO_MANY, "receive");
        return CT_ERROR;
    }
    *is_parse = CT_TRUE;

    CT_RETURN_IFERR(lex_try_fetch_char(lex, ',', is_more));
    if (*is_more == CT_FALSE) {
        CT_RETURN_IFERR(lex_expected_end(lex));
    }

    return CT_SUCCESS;
}

static status_t sql_verify_als_log_archive_db_cfg(void *lex, bool32 *is_parse, bool32 *is_more, uint32 matched_id)
{
    word_t word;

    if (*is_parse) {
        CT_THROW_ERROR(ERR_LOG_ARCHIVE_CONFIG_TOO_MANY, "dg");
        return CT_ERROR;
    }
    *is_parse = CT_TRUE;

    if (matched_id == 0) {
        CT_RETURN_IFERR(lex_expected_fetch_word(lex, "="));
        CT_RETURN_IFERR(lex_expected_fetch_bracket(lex, &word));
    }
    CT_RETURN_IFERR(lex_try_fetch_char(lex, ',', is_more));
    if (*is_more == CT_FALSE) {
        CT_RETURN_IFERR(lex_expected_end(lex));
    }
    return CT_SUCCESS;
}

status_t sql_verify_als_log_archive_config(void *se, void *lex, void *def)
{
    bool32 is_receive = CT_FALSE;
    bool32 is_dgcfg = CT_FALSE;
    bool32 is_send = CT_FALSE;
    bool32 is_more;
    word_t word;
    uint32 matched_id;
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;

    CT_RETURN_IFERR(lex_expected_fetch_string((lex_t *)lex, &word));
    CT_RETURN_IFERR(cm_text2str((text_t *)&word.text, sys_def->value, CT_PARAM_BUFFER_SIZE));
    CT_RETURN_IFERR(lex_push(lex, &word.text));

    for (;;) {
        is_more = CT_FALSE;
        if (lex_expected_fetch_1ofn(lex, &matched_id, 6, "SEND", "NOSEND", "RECEIVE", "NORECIVE", "DG_CONFIG",
            "NODG_CONFIG") != CT_SUCCESS) {
            lex_pop(lex);
            return CT_ERROR;
        }
        if (matched_id == CT_INVALID_ID32) {
            lex_pop(lex);
            CT_THROW_ERROR(ERR_INVALID_PARAMETER, "LOG_ARCHIVE_CONFIG");
            return CT_ERROR;
        }

        if (matched_id < 2) {
            if (sql_verify_als_log_archive_send_cfg(lex, &is_send, &is_more) != CT_SUCCESS) {
                lex_pop(lex);
                return CT_ERROR;
            }
            CT_BREAK_IF_TRUE(!is_more);
            continue;
        }

        if (matched_id < 4) {
            if (sql_verify_als_log_archive_receive_cfg(lex, &is_receive, &is_more) != CT_SUCCESS) {
                lex_pop(lex);
                return CT_ERROR;
            }
            CT_BREAK_IF_TRUE(!is_more);
            continue;
        }
        if (sql_verify_als_log_archive_db_cfg(lex, &is_dgcfg, &is_more, matched_id - 4) != CT_SUCCESS) {
            lex_pop(lex);
            return CT_ERROR;
        }
        CT_BREAK_IF_TRUE(!is_more);
    }
    lex_pop(lex);
    return CT_SUCCESS;
}

status_t sql_verify_als_log_archive_max_min(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t sql_notify_als_archive_max_processes(void *se, void *item, char *value)
{
    knl_session_t *session = (knl_session_t *)se;
    return arch_set_max_processes(session, value);
}

status_t sql_notify_als_archive_min_succeed(void *se, void *item, char *value)
{
    knl_session_t *session = (knl_session_t *)se;
    arch_context_t *ctx = &session->kernel->arch_ctx;
    return arch_set_min_succeed(ctx, value);
}

status_t sql_notify_als_archive_trace(void *se, void *item, char *value)
{
    knl_session_t *session = (knl_session_t *)se;
    arch_context_t *ctx = &session->kernel->arch_ctx;
    return arch_set_trace(value, &ctx->arch_trace);
}

status_t sql_verify_als_quorum_any(void *se, void *lex, void *def)
{
    uint32 num;

    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (num > g_instance->kernel.lsnd_ctx.standby_num) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "QUORUM_ANY", (int64)g_instance->kernel.lsnd_ctx.standby_num);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_notify_als_quorum_any(void *se, void *item, char *value)
{
    uint32 val;

    if (cm_str2uint32(value, &val) != CT_SUCCESS) {
        return CT_ERROR;
    }

    g_instance->kernel.attr.quorum_any = val;
    return CT_SUCCESS;
}

status_t sql_verify_als_statistics_level(void *se, void *lex, void *def)
{
    uint32 match_id;
    char *match_word[] = { "ALL", "TYPICAL", "BASIC" };
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;

    if (lex_expected_fetch_1of3(lex, match_word[0], match_word[1], match_word[2], &match_id) != CT_SUCCESS) {
        return CT_ERROR;
    }

    PRTS_RETURN_IFERR(
        snprintf_s(sys_def->value, CT_PARAM_BUFFER_SIZE, CT_PARAM_BUFFER_SIZE - 1, "%s", match_word[match_id]));
    return CT_SUCCESS;
}

status_t sql_notify_als_stats_level(void *se, void *item, char *value)
{
    if (cm_str_equal_ins(value, "ALL") || cm_str_equal_ins(value, "TYPICAL")) {
        g_instance->kernel.attr.enable_table_stat = CT_TRUE;
    } else if (cm_str_equal_ins(value, "BASIC")) {
        g_instance->kernel.attr.enable_table_stat = CT_FALSE;
    } else {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER_ENUM, "STATS_LEVEL", value);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t sql_notify_als_sql_stat(void *se, void *item, char *value)
{
    // match id specified by ddl_parser.c:sql_parse_alsys_set
    g_instance->sql.enable_stat = (bool32)value[0];
    // restore value for alter config.
    return sql_notify_als_bool(se, item, value);
}

status_t sql_verify_als_repl_port(void *se, void *lex, void *def)
{
    word_t word;
    uint16 port;
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

    CT_RETURN_IFERR(cm_text2str((text_t *)&word.text, sys_def->value, CT_PARAM_BUFFER_SIZE));

    /* check if the port specified is valid */
    if (cm_str2uint16(sys_def->value, &port) != CT_SUCCESS) {
        cm_reset_error();
        CT_SRC_THROW_ERROR(((lex_t *)lex)->loc, ERR_INVALID_PARAMETER, "port");
        return CT_ERROR;
    }

    if ((port < CT_MIN_PORT) && (port != 0)) {
        CT_SRC_THROW_ERROR(((lex_t *)lex)->loc, ERR_PARAMETER_TOO_SMALL, "port", (int64)CT_MIN_PORT);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_notify_als_restore_arch_compressed(void *se, void *item, char *value)
{
    g_instance->kernel.attr.restore_keep_arch_compressed = (bool32)value[0];

    return sql_notify_als_bool(se, item, value);
}

status_t sql_notify_als_enable_arch_compressed(void *se, void *item, char *value)
{
    bool32 enabled = (bool32)value[0];
    if (g_instance->lsnr.tcp_replica.port != 0) {
        if (enabled) {
            CT_THROW_ERROR(ERR_INVALID_OPERATION, ", forbid to set ENABLE_ARCH_COMPRESS to TRUE in HA mode");
            return CT_ERROR;
        }
    }
    g_instance->kernel.attr.enable_arch_compress = enabled;
    return sql_notify_als_bool(se, item, value);
}

status_t sql_notify_als_valid_node_checking(void *se, void *item, char *value)
{
    white_context_t *ctx = GET_WHITE_CTX;
    cm_spin_lock(&ctx->lock, NULL);

    if (value[0] == CT_TRUE && ctx->ip_black_list.count == 0 && ctx->ip_white_list.count == 0) {
        cm_spin_unlock(&ctx->lock);
        CT_THROW_ERROR(ERR_TCP_VALID_NODE_CHECKING);
        return CT_ERROR;
    }

    ctx->iwl_enabled = value[0];
    cm_spin_unlock(&ctx->lock);

    return sql_notify_als_bool(se, item, value);
}

static status_t sql_notify_als_ip_whitelist_core(const char *conf_name, char *value)
{
    white_context_t *ctx = GET_WHITE_CTX;
    list_t *old_list = NULL;
    list_t new_list;
    text_t cidr_texts;
    list_t *rest_list = NULL;

    cm_str2text(value, &cidr_texts);
    cm_create_list(&new_list, sizeof(cidr_t));
    if (cm_parse_cidrs(&cidr_texts, &new_list) != CT_SUCCESS) {
        cm_destroy_list(&new_list);

        CT_THROW_ERROR(ERR_INVALID_PARAMETER, conf_name);
        return CT_ERROR;
    }

    if (cm_str_equal(conf_name, "TCP_INVITED_NODES")) {
        old_list = &ctx->ip_white_list;
        rest_list = &ctx->ip_black_list;
    } else {
        old_list = &ctx->ip_black_list;
        rest_list = &ctx->ip_white_list;
    }

    cm_spin_lock(&ctx->lock, NULL);
    if (ctx->iwl_enabled == CT_TRUE && rest_list->count == 0 && new_list.count == 0) {
        cm_spin_unlock(&ctx->lock);
        CT_THROW_ERROR(ERR_TCP_NODE_EMPTY_CONFIG);
        return CT_ERROR;
    }

    cm_destroy_list(old_list);
    *old_list = new_list;
    cm_spin_unlock(&ctx->lock);
    return CT_SUCCESS;
}

status_t sql_notify_als_invited_nodes(void *se, void *item, char *value)
{
    return sql_notify_als_ip_whitelist_core("TCP_INVITED_NODES", value);
}

status_t sql_notify_als_excluded_nodes(void *se, void *item, char *value)
{
    return sql_notify_als_ip_whitelist_core("TCP_EXCLUDED_NODES", value);
}

status_t sql_verify_als_merge_batch_size(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (num < CT_MIN_MERGE_SORT_BATCH_SIZE) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "MERGE_SORT_BATCH_SIZE");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t sql_notify_als_merge_sort_batch_size(void *se, void *item, char *value)
{
    return cm_str2uint32(value, &g_instance->attr.merge_sort_batch_size);
}

status_t sql_verify_als_convert(void *se, void *lex, void *def)
{
    word_t word;
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;
    if (CT_SUCCESS != lex_expected_fetch_string((lex_t *)lex, &word)) {
        return CT_ERROR;
    }
    if (word.type != WORD_TYPE_STRING) {
        CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, ", expected string type, but %s found", W2S(&word));
        return CT_ERROR;
    }

    if (word.text.len >= CT_PARAM_BUFFER_SIZE) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, sys_def->param, (int64)CT_PARAM_BUFFER_SIZE - 1);
        return CT_ERROR;
    }

    CT_RETURN_IFERR(cm_text2str((text_t *)&word.text, sys_def->value, CT_PARAM_BUFFER_SIZE));

    if (cm_check_exist_special_char(sys_def->value, (uint32)strlen(sys_def->value))) {
        CT_THROW_ERROR(ERR_INVALID_DIR, sys_def->value);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_notify_als_datefile_convert(void *se, void *item, char *value)
{
    knl_session_t *session = (knl_session_t *)se;
    knl_attr_t *attr = &session->kernel->attr;
    config_item_t *config_item = (config_item_t *)item;

    CM_POINTER(config_item);
    return knl_get_convert_params(config_item->name, value, &attr->data_file_convert, g_instance->home);
}

status_t sql_notify_als_logfile_convert(void *se, void *item, char *value)
{
    knl_session_t *session = (knl_session_t *)se;
    knl_attr_t *attr = &session->kernel->attr;
    config_item_t *config_item = (config_item_t *)item;

    CM_POINTER(config_item);
    return knl_get_convert_params(config_item->name, value, &attr->log_file_convert, g_instance->home);
}

status_t sql_notify_als_func_index_scan(void *se, void *item, char *value)
{
    return sql_notify_als_bool(se, item, value);
}

status_t sql_notify_als_index_cond_pruning(void *se, void *item, char *value)
{
    g_instance->sql.enable_index_cond_pruning = (bool32)value[0];
    return sql_notify_als_bool(se, item, value);
}

status_t sql_notify_als_outer_join_opt(void *se, void *item, char *value)
{
    g_instance->sql.enable_outer_join_opt = (bool32)value[0];
    return sql_notify_als_onoff(se, item, value);
}

status_t sql_notify_als_distinct_pruning(void *se, void *item, char *value)
{
    g_instance->sql.enable_distinct_pruning = (bool32)value[0];
    return sql_notify_als_onoff(se, item, value);
}

status_t sql_notify_als_predicate(void *se, void *item, char *value)
{
    g_instance->sql.enable_predicate = (bool32)value[0];
    if (g_instance->sql.enable_predicate) {
        CT_BIT_SET(g_instance->sql.plan_display_format, PLAN_FORMAT_PREDICATE);
    } else {
        CT_BIT_RESET(g_instance->sql.plan_display_format, PLAN_FORMAT_PREDICATE);
    }
    return sql_notify_als_bool(se, item, value);
}

status_t sql_notify_als_topn_threshold(void *se, void *item, char *value)
{
    uint32 topn_threshold;
    if (cm_str2uint32(value, &topn_threshold) != CT_SUCCESS) {
        return CT_ERROR;
    }

    g_instance->sql.topn_threshold = topn_threshold;
    return CT_SUCCESS;
}

status_t sql_notify_als_connect_by_mtrl(void *se, void *item, char *value)
{
    g_instance->sql.enable_cb_mtrl = (bool32)value[0];
    return sql_notify_als_bool(se, item, value);
}

status_t sql_notify_als_or_expansion(void *se, void *item, char *value)
{
    g_instance->sql.enable_or_expand = (bool32)value[0];
    return sql_notify_als_bool(se, item, value);
}

status_t sql_notify_als_hash_pages_hold(void *se, void *item, char *value)
{
    uint32 hash_pages_hold;
    if (cm_str2uint32(value, &hash_pages_hold) != CT_SUCCESS) {
        return CT_ERROR;
    }

    g_instance->sql.hash_pages_hold = hash_pages_hold;
    return CT_SUCCESS;
}

status_t sql_notify_als_seg_pages_hold(void *se, void *item, char *value)
{
    uint32 seg_pages_hold;
    if (cm_str2uint32(value, &seg_pages_hold) != CT_SUCCESS) {
        return CT_ERROR;
    }

    g_instance->sql.segment_pages_hold = seg_pages_hold;
    return CT_SUCCESS;
}

status_t sql_notify_als_parall_max_threads(void *se, void *item, char *value)
{
    uint32 max_thread_num;
    if (cm_str2uint32(value, &max_thread_num) != CT_SUCCESS) {
        return CT_ERROR;
    }

    g_instance->sql_par_pool.max_sessions = max_thread_num;
    return CT_SUCCESS;
}

status_t sql_notify_als_timed_stat(void *se, void *item, char *value)
{
    // match id specified by ddl_parser.c:sql_parse_alsys_set
    g_instance->kernel.attr.enable_timed_stat = (bool32)value[0];
    // restore value for alter config.
    return sql_notify_als_bool(se, item, value);
}

status_t sql_notify_als_coverage_enable(void *se, void *item, char *value)
{
#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
    bool8 coverage_enable = (bool8)value[0];

    if ((coverage_enable == CT_TRUE) && (ple_try_create_coverage_table(se) != CT_SUCCESS)) {
        CT_LOG_RUN_ERR("create SYS.COVERAGE table fail when set COVERAGE_ENABLE = TRUE");
        return CT_ERROR;
    }
    g_instance->sql.coverage_enable = coverage_enable;
#endif
    return sql_notify_als_bool(se, item, value);
}

status_t sql_notify_als_aggr_placement(void *se, void *item, char *value)
{
    g_instance->sql.enable_aggr_placement = (bool32)value[0];
    return sql_notify_als_bool(se, item, value);
}

status_t sql_notify_als_distinct_elimination(void *se, void *item, char *value)
{
    g_instance->sql.enable_distinct_elimination = (bool32)value[0];
    return sql_notify_als_bool(se, item, value);
}

status_t sql_notify_als_project_list_pruning(void *se, void *item, char *value)
{
    g_instance->sql.enable_project_list_pruning = (bool32)value[0];
    return sql_notify_als_bool(se, item, value);
}

status_t sql_notify_als_pred_move_around(void *se, void *item, char *value)
{
    g_instance->sql.enable_pred_move_around = (bool32)value[0];
    return sql_notify_als_bool(se, item, value);
}

status_t sql_notify_als_hash_mtrl(void *se, void *item, char *value)
{
    g_instance->sql.enable_hash_mtrl = (bool32)value[0];
    return sql_notify_als_bool(se, item, value);
}

status_t sql_notify_als_winmagic_rewrite(void *se, void *item, char *value)
{
    g_instance->sql.enable_winmagic_rewrite = (bool32)value[0];
    return sql_notify_als_bool(se, item, value);
}

status_t sql_notify_als_pred_reorder(void *se, void *item, char *value)
{
    g_instance->sql.enable_pred_reorder = (bool32)value[0];
    return sql_notify_als_bool(se, item, value);
}

status_t sql_notify_als_order_by_placement(void *se, void *item, char *value)
{
    g_instance->sql.enable_order_by_placement = (bool32)value[0];
    return sql_notify_als_bool(se, item, value);
}

status_t sql_notify_als_subquery_elimination(void *se, void *item, char *value)
{
    g_instance->sql.enable_subquery_elimination = (bool32)value[0];
    return sql_notify_als_bool(se, item, value);
}

status_t sql_notify_als_join_elimination(void *se, void *item, char *value)
{
    g_instance->sql.enable_join_elimination = (bool32)value[0];
    return sql_notify_als_bool(se, item, value);
}

status_t sql_notify_als_connect_by_placement(void *se, void *item, char *value)
{
    g_instance->sql.enable_connect_by_placement = (bool32)value[0];
    return sql_notify_als_bool(se, item, value);
}

status_t sql_notify_als_group_by_elimination(void *se, void *item, char *value)
{
    g_instance->sql.enable_group_by_elimination = (bool32)value[0];
    return sql_notify_als_bool(se, item, value);
}

status_t sql_notify_als_optim_any_transform(void *se, void *item, char *value)
{
    g_instance->sql.enable_any_transform = (bool32)value[0];
    return sql_notify_als_bool(se, item, value);
}

status_t sql_notify_als_optim_all_transform(void *se, void *item, char *value)
{
    g_instance->sql.enable_all_transform = (bool32)value[0];
    return sql_notify_als_bool(se, item, value);
}

status_t sql_notify_als_multi_index_scan(void *se, void *item, char *value)
{
    g_instance->sql.enable_multi_index_scan = (bool32)value[0];
    return sql_notify_als_bool(se, item, value);
}

status_t sql_notify_als_join_pred_pushdown(void *se, void *item, char *value)
{
    g_instance->sql.enable_join_pred_pushdown = (bool32)value[0];
    return sql_notify_als_bool(se, item, value);
}

status_t sql_notify_als_filter_pushdown(void *se, void *item, char *value)
{
    g_instance->sql.enable_filter_pushdown = (bool32)value[0];
    return sql_notify_als_bool(se, item, value);
}

status_t sql_notify_als_multi_parts_scan(void *se, void *item, char *value)
{
    return cm_str2uint32(value, &g_instance->sql.optim_index_scan_max_parts);
}

status_t sql_notify_als_order_by_elimination(void *se, void *item, char *value)
{
    g_instance->sql.enable_order_by_elimination = (bool32)value[0];
    return sql_notify_als_bool(se, item, value);
}

status_t sql_notify_als_unnest_set_subquery(void *se, void *item, char *value)
{
    g_instance->sql.enable_unnest_set_subq = (bool32)value[0];
    return sql_notify_als_bool(se, item, value);
}

status_t sql_notify_als_enable_right_semijoin(void *se, void *item, char *value)
{
    g_instance->sql.enable_right_semijoin = (bool32)value[0];
    return sql_notify_als_bool(se, item, value);
}

status_t sql_notify_als_enable_right_antijoin(void *se, void *item, char *value)
{
    g_instance->sql.enable_right_antijoin = (bool32)value[0];
    return sql_notify_als_bool(se, item, value);
}

status_t sql_notify_als_enable_right_leftjoin(void *se, void *item, char *value)
{
    g_instance->sql.enable_right_leftjoin = (bool32)value[0];
    return sql_notify_als_bool(se, item, value);
}

status_t sql_notify_als_simplify_exists_subq(void *se, void *item, char *value)
{
    g_instance->sql.enable_exists_transform = (bool32)value[0];
    return sql_notify_als_bool(se, item, value);
}

status_t sql_notify_als_sample_size(void *se, void *item, char *value)
{
    int64 val_int64;

    if (cm_str2size(value, &val_int64) != CT_SUCCESS) {
        return CT_ERROR;
    }

    g_instance->kernel.attr.stats_sample_size = (uint64)val_int64;
    return CT_SUCCESS;
}

status_t sql_notify_als_cost_limit(void *se, void *item, char *value)
{
    uint32 val_int32;

    if (cm_str2uint32(value, &val_int32) != CT_SUCCESS) {
        return CT_ERROR;
    }

    g_instance->kernel.attr.stats_cost_limit = val_int32;
    return CT_SUCCESS;
}

status_t sql_notify_als_bucket_size(void *se, void *item, char *value)
{
    uint16 val_int16;

    if (cm_str2uint16(value, &val_int16) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (val_int16 > STATS_HISTGRAM_MAX_SIZE || val_int16 < STATS_HISTGRAM_DEFAULT_SIZE) {
        CT_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "STATS_MAX_BUCKET_SIZE", (int64)STATS_HISTGRAM_DEFAULT_SIZE,
            (int64)STATS_HISTGRAM_MAX_SIZE);
        return CT_ERROR;
    }

    g_instance->kernel.attr.stats_max_buckets = val_int16;

    return CT_SUCCESS;
}

status_t sql_notify_als_cost_delay(void *se, void *item, char *value)
{
    uint32 val_int32;

    if (cm_str2uint32(value, &val_int32) != CT_SUCCESS) {
        return CT_ERROR;
    }

    g_instance->kernel.attr.stats_cost_delay = val_int32;
    return CT_SUCCESS;
}

status_t sql_notify_als_enable_sample_limit(void *se, void *item, char *value)
{
    g_instance->kernel.attr.enable_sample_limit = (bool32)value[0];
    // restore value for alter config.
    return sql_notify_als_bool(se, item, value);
}

status_t sql_notify_als_enable_raft(void *se, void *item, char *value)
{
    if ((bool32)value[0]) {
        PRTS_RETURN_IFERR(snprintf_s(value, CT_PARAM_BUFFER_SIZE, CT_PARAM_BUFFER_SIZE - 1, "TRUE"));
    } else {
        PRTS_RETURN_IFERR(snprintf_s(value, CT_PARAM_BUFFER_SIZE, CT_PARAM_BUFFER_SIZE - 1, "FALSE"));
    }

    return CT_SUCCESS;
}

status_t sql_notify_als_row_format(void *se, void *item, char *value)
{
    if (cm_str_equal_ins(value, "CSF")) {
        g_instance->kernel.attr.row_format = ROW_FORMAT_CSF;
    } else if (cm_str_equal_ins(value, "ASF")) {
        g_instance->kernel.attr.row_format = ROW_FORMAT_ASF;
    } else {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER_ENUM, "ROW_FORMAT", value);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t sql_notify_als_stats_parall_threads(void *se, void *item, char *value)
{
    uint32 val_int32;

    if (cm_str2uint32(value, &val_int32) != CT_SUCCESS) {
        return CT_ERROR;
    }

    g_instance->kernel.attr.stats_paraller_threads = val_int32;
    return CT_SUCCESS;
}

status_t sql_notify_als_stats_enable_parall(void *se, void *item, char *value)
{
    g_instance->kernel.attr.stats_enable_parall = (bool32)value[0];

    return sql_notify_als_bool(se, item, value);
}

status_t sql_notify_als_max_remote_params(void *se, void *item, char *value)
{
    uint32 val;
    if (cm_str2uint32(value, &val) != CT_SUCCESS) {
        return CT_ERROR;
    }
    g_instance->attr.max_remote_params = val;
    return CT_SUCCESS;
}

status_t sql_notify_als_sql_cursors_each_sess(void *se, void *item, char *value)
{
    uint32 val;
    if (cm_str2uint32(value, &val) != CT_SUCCESS) {
        return CT_ERROR;
    }
    g_instance->attr.sql_cursors_each_sess = val;
    return CT_SUCCESS;
}

status_t sql_notify_als_reserved_sql_cursors(void *se, void *item, char *value)
{
    uint32 val;
    if (cm_str2uint32(value, &val) != CT_SUCCESS) {
        return CT_ERROR;
    }
    g_instance->attr.reserved_sql_cursors = val;
    return CT_SUCCESS;
}

status_t sql_notify_als_resource_plan(void *se, void *item, char *value)
{
    if (rsrc_reload_plan(se, value) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t sql_notify_als_undo_space(void *se, void *item, char *value)
{
    char buf[CT_NAME_BUFFER_SIZE] = { '\0' };
    text_t spc_name;
    spc_name.str = buf;
    spc_name.len = 0;

    cm_str2text(value, &spc_name);
    cm_str_upper(spc_name.str);

    if (knl_alter_switch_undo_space(se, &spc_name) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_notify_als_cbo_index_caching(void *se, void *item, char *value)
{
    uint32 val;
    if (cm_str2uint32(value, &val) != CT_SUCCESS) {
        return CT_ERROR;
    }
    g_instance->sql.cbo_index_caching = val;
    return CT_SUCCESS;
}

status_t sql_notify_als_cbo_index_cost_adj(void *se, void *item, char *value)
{
    uint32 val;
    if (cm_str2uint32(value, &val) != CT_SUCCESS) {
        return CT_ERROR;
    }
    g_instance->sql.cbo_index_cost_adj = val;
    return CT_SUCCESS;
}

status_t sql_notify_als_cbo_path_caching(void *se, void *item, char *value)
{
    uint32 val;
    if (cm_str2uint32(value, &val) != CT_SUCCESS) {
        return CT_ERROR;
    }
    g_instance->sql.cbo_path_caching = val;
    return CT_SUCCESS;
}

status_t sql_notify_als_withas_subquery(void *se, void *item, char *value)
{
    if (cm_compare_str_ins(value, "INLINE") == 0) {
        g_instance->sql.withas_subquery = WITHAS_INLINE;
    } else if (cm_compare_str_ins(value, "MATERIALIZE") == 0) {
        g_instance->sql.withas_subquery = WITHAS_MATERIALIZE;
    } else {
        g_instance->sql.withas_subquery = WITHAS_OPTIMIZER;
    }
    return CT_SUCCESS;
}

status_t sql_verify_als_multi_parts_scan(void *se, void *lex, void *def)
{
    uint32 num;

    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (num > CT_MAX_MULTI_PARTS_NUM) {
        CT_SRC_THROW_ERROR(((lex_t *)lex)->loc, ERR_PARAMETER_TOO_LARGE, "_OPTIM_INDEX_SCAN_MAX_PARTS",
            (int64)CT_MAX_MULTI_PARTS_NUM);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_verify_als_agent_extend_step(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (num > CT_MAX_OPTIMIZED_WORKER_COUNT) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "WORKER_THREADS_EXTEND_STEP");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t sql_verify_als_ckpt_wait_timeout(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_verify_als_max_remote_params(void *se, void *lex, void *def)
{
    uint32 num;

    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (num > CT_MAX_SQL_PARAM_COUNT) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "MAX_REMOTE_PARAMS", (int64)CT_MAX_SQL_PARAM_COUNT);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_verify_als_mem_pool_init_size(void *se, void *lex, void *def)
{
    return sql_verify_pool_size(lex, def, BUDDY_MIN_BLOCK_SIZE, BUDDY_MAX_BLOCK_SIZE);
}

status_t sql_verify_als_mem_pool_max_size(void *se, void *lex, void *def)
{
    return sql_verify_pool_size(lex, def, BUDDY_MEM_POOL_MIN_SIZE, BUDDY_MEM_POOL_MAX_SIZE);
}

status_t sql_verify_als_stats_sample_size(void *se, void *lex, void *def)
{
    return sql_verify_pool_size(lex, def, CT_MIN_SAMPLE_SIZE, CT_INVALID_ID32);
}

status_t sql_verify_als_ssl_file(void *se, void *lex, void *def)
{
    status_t ret = CT_ERROR;
    word_t word;
    bool32 in_bracket = CT_FALSE;
    bool32 in_home;
    bool32 is_comma = CT_FALSE;
    uint32 size, home_len, len;
    text_t text, file_name;
    char buf[CT_PARAM_BUFFER_SIZE];
    char file_path[CT_FILE_NAME_BUFFER_SIZE];
    char real_path[CT_FILE_NAME_BUFFER_SIZE];

    text.str = buf;
    text.len = 0;

    lex_t *lexer = (lex_t *)lex;
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;

    if (lex_try_fetch_bracket(lexer, &word, &in_bracket) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (in_bracket) {
        CT_RETURN_IFERR(lex_push(lexer, &word.text));
        CM_TEXT_APPEND(&text, '(');
    }

    home_len = (uint32)strlen(g_instance->home);

    while (CT_TRUE) {
        if (lex_expected_fetch_string(lexer, &word) != CT_SUCCESS) {
            break;
        }
        file_name = word.text.value;
        if (CM_TEXT_FIRST(&file_name) == '?') {
            CM_REMOVE_FIRST(&file_name);
            size = home_len + file_name.len;
            in_home = CT_TRUE;
        } else {
            size = file_name.len;
            in_home = CT_FALSE;
        }

        if (size > CT_MAX_FILE_NAME_LEN) {
            CT_THROW_ERROR(ERR_INVALID_FILE_NAME, "als ssl", (uint32)CT_MAX_FILE_NAME_LEN);
            break;
        }

        len = text.len;
        if (in_home) {
            CT_RETURN_IFERR(cm_concat_string(&text, CT_PARAM_BUFFER_SIZE, g_instance->home));
        }

        if (text.len + file_name.len >= CT_PARAM_BUFFER_SIZE) {
            CT_THROW_ERROR(ERR_BUFFER_OVERFLOW, text.len + file_name.len, CT_PARAM_BUFFER_SIZE - 1);
            return CT_ERROR;
        }
        cm_concat_text(&text, CT_PARAM_BUFFER_SIZE, &file_name);

        // verify file existence
        if (size != 0) {
            MEMS_RETURN_IFERR(memcpy_s(file_path, CT_FILE_NAME_BUFFER_SIZE, text.str + len, size));
            file_path[size] = '\0';
            CT_RETURN_IFERR(realpath_file(file_path, real_path, CT_FILE_NAME_BUFFER_SIZE));
            if (!cm_file_exist(real_path)) {
                CT_THROW_ERROR(ERR_FILE_NOT_EXIST, "certificate", file_path);
                break;
            }

            if (cm_access_file(real_path, R_OK) != CT_SUCCESS) {
                CT_THROW_ERROR(ERR_READ_FILE, file_path, cm_get_os_error());
                break;
            }
        }

        if (lex_try_fetch_char(lexer, ',', &is_comma) != CT_SUCCESS) {
            break;
        }
        if (!is_comma) {
            ret = CT_SUCCESS;
            break;
        }
        CM_TEXT_APPEND(&text, ',');
    }
    if (in_bracket) {
        lex_pop(lexer);
        CM_TEXT_APPEND(&text, ')');
    }
    if (ret == CT_SUCCESS) {
        return cm_text2str(&text, sys_def->value, sizeof(sys_def->value));
    } else {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, sys_def->param);
        return ret;
    }
}

status_t sql_verify_ssl_alt_threshold(void *se, void *lex, void *def)
{
    uint32 num;
    int32 detect_day;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (!(num >= CT_MIN_SSL_EXPIRE_THRESHOLD && num <= CT_MAX_SSL_EXPIRE_THRESHOLD)) {
        CT_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "SSL_EXPIRE_ALERT_THRESHOLD", (int64)CT_MIN_SSL_EXPIRE_THRESHOLD,
            (int64)CT_MAX_SSL_EXPIRE_THRESHOLD);
        return CT_ERROR;
    }

    if (CT_SUCCESS != cm_str2int(cm_get_config_value(&g_instance->config, "SSL_PERIOD_DETECTION"), &detect_day)) {
        return CT_ERROR;
    }

    if (detect_day > (int32)num) {
        CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "the value of SSL_EXPIRE_ALERT_THRESHOLD "
            "should be bigger than the value of SSL_PERIOD_DETECTION");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_verify_ssl_period_detection(void *se, void *lex, void *def)
{
    uint32 num;
    int32 alert_day;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (!(num >= CT_MIN_SSL_PERIOD_DETECTION && num <= CT_MAX_SSL_PERIOD_DETECTION)) {
        CT_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "SSL_PERIOD_DETECTION", (int64)CT_MIN_SSL_PERIOD_DETECTION,
            (int64)CT_MAX_SSL_PERIOD_DETECTION);
        return CT_ERROR;
    }

    if (CT_SUCCESS != cm_str2int(cm_get_config_value(&g_instance->config, "SSL_EXPIRE_ALERT_THRESHOLD"), &alert_day)) {
        return CT_ERROR;
    }

    if ((int32)num > alert_day) {
        CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "the value of SSL_PERIOD_DETECTION "
            "should not be bigger than the value of SSL_EXPIRE_ALERT_THRESHOLD");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_verify_als_ssl_cipher(void *se, void *lex, void *def)
{
    uint32 i, j;
    const char **cipher_list = NULL;
    const char **cipher_list_tls13 = NULL;
    text_t text, left, right;
    word_t word;
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;
    if (lex_expected_fetch((lex_t *)lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (word.type == WORD_TYPE_STRING) {
        sql_remove_quota(&word.text.value);
    }
    text = word.text.value;
    cm_text_upper(&text);
    cm_split_text(&text, ':', '\0', &left, &right);

    cipher_list = cs_ssl_get_default_cipher_list();
    cipher_list_tls13 = cs_ssl_tls13_get_default_cipher_list();

    while (text.len > 0) {
        cm_split_text(&text, ':', '\0', &left, &right);
        text = right;

        for (i = 0; cipher_list[i] != NULL; ++i) {
            if (cm_text_str_equal(&left, cipher_list[i])) {
                break;
            }
        }

        if (cipher_list[i] == NULL) {
            for (j = 0; cipher_list_tls13[j] != NULL; ++j) {
                if (cm_text_str_equal(&left, cipher_list_tls13[j])) {
                    break;
                }
            }
            if (cipher_list_tls13[j] == NULL) {
                CT_THROW_ERROR(ERR_CIPHER_NOT_SUPPORT, T2S(&left));
                return CT_ERROR;
            }
        }
    }
    return cm_text2str((text_t *)&word.text, sys_def->value, CT_PARAM_BUFFER_SIZE);
}

status_t sql_verify_als_have_ssl(void *se, void *lex, void *def)
{
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;
    CT_THROW_ERROR(ERR_ALTER_READONLY_PARAMETER, sys_def->param);
    return CT_ERROR;
}

status_t sql_verify_als_topn_threshold(void *se, void *lex, void *def)
{
    uint32 value;
    if (sql_verify_uint32(lex, def, &value) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (value > CT_MAX_TOPN_THRESHOLD) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "_QUERY_TOPN_THRESHOLD", (int64)CT_MAX_TOPN_THRESHOLD);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t sql_verify_als_hash_pages_hold(void *se, void *lex, void *def)
{
    uint32 value;
    if (sql_verify_uint32(lex, def, &value) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (value > CT_MAX_HASH_PAGES_HOLD) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "HASH_TABLE_PAGES_HOLD", (int64)CT_MAX_HASH_PAGES_HOLD);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t sql_verify_als_seg_pages_hold(void *se, void *lex, void *def)
{
    uint32 value;
    if (sql_verify_uint32(lex, def, &value) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (value > CT_MAX_SEGMENT_PAGES_HOLD) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "SEGMENT_PAGES_HOLD", (int64)CT_MAX_SEGMENT_PAGES_HOLD);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t sql_verify_als_sql_cursors_each_sess(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (num > CT_MAX_SQL_CURSORS_EACH_SESSION) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "_SQL_CURSORS_EACH_SESSION", (int64)CT_MAX_SQL_CURSORS_EACH_SESSION);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_verify_als_reserved_sql_cursors(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }

    // can only expand, can't decrease
    if (num < g_instance->attr.reserved_sql_cursors) {
        CT_THROW_ERROR(ERR_RESERV_SQL_CURSORS_DECREASE);
        return CT_ERROR;
    }

    if (num > CT_MAX_RESERVED_SQL_CURSORS) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "_RESERVED_SQL_CURSORS", (int64)CT_MAX_RESERVED_SQL_CURSORS);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_verify_als_parall_max_threads(void *se, void *lex, void *def)
{
    uint32 value;
    if (sql_verify_uint32(lex, def, &value) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (value > CT_PARALLEL_MAX_THREADS) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "PARALLEL_MAX_THREADS", (int64)CT_PARALLEL_MAX_THREADS);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t sql_verify_als_node_lock_status(void *se, void *lex, void *def)
{
    uint32 match_id;
    char *match_word[] = { "NOLOCK", "SHARE", "EXCLUSIVE" };
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;

    if (lex_expected_fetch_1of3(lex, match_word[0], match_word[1], match_word[2], &match_id) != CT_SUCCESS) {
        return CT_ERROR;
    }

    PRTS_RETURN_IFERR(
        snprintf_s(sys_def->value, CT_PARAM_BUFFER_SIZE, CT_PARAM_BUFFER_SIZE - 1, "%s", match_word[match_id]));

    return CT_SUCCESS;
}

status_t sql_verify_als_ext_pool_size(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (num < CT_MES_MIN_POOL_SIZE) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "EXT_PROC_POOL_SIZE", (int64)CT_MES_MIN_POOL_SIZE);
        return CT_ERROR;
    } else if (num > CT_MES_MAX_POOL_SIZE) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "EXT_PROC_POOL_SIZE", (int64)CT_MES_MAX_POOL_SIZE);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_verify_als_ext_work_thread_num(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (num < CT_MES_MIN_THREAD_NUM) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "EXT_PROC_WORK_THREAD_NUM", (int64)CT_MES_MIN_THREAD_NUM);
        return CT_ERROR;
    } else if (num > CT_MES_MAX_THREAD_NUM) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "EXT_PROC_WORK_THREAD_NUM", (int64)CT_MES_MAX_THREAD_NUM);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_verify_als_ext_channel_num(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (num < CT_MES_MIN_CHANNEL_NUM) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "EXT_PROC_CHANNEL_NUM", (int64)CT_MES_MIN_CHANNEL_NUM);
        return CT_ERROR;
    } else if (num > CT_MES_MAX_CHANNEL_NUM) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "EXT_PROC_CHANNEL_NUM", (int64)CT_MES_MAX_CHANNEL_NUM);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_verify_als_stats_parall_threads(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (num < CT_MIN_STATS_PARALL_THREADS) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "STATS_PARALL_THREADS", (int64)CT_MIN_STATS_PARALL_THREADS);
        return CT_ERROR;
    } else if (num > CT_MAX_STATS_PARALL_THREADS) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "STATS_PARALL_THREADS", (int64)CT_MAX_STATS_PARALL_THREADS);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_verify_als_cbo_index_caching(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (num > CBO_MAX_INDEX_CACHING) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "CBO_INDEX_CACHING", (int64)CBO_MAX_INDEX_CACHING);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t sql_verify_als_cbo_index_cost_adj(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (num < CBO_MIN_INDEX_COST_ADJ) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "CBO_INDEX_COST_ADJ", (int64)CBO_MIN_INDEX_COST_ADJ);
        return CT_ERROR;
    } else if (num > CBO_MAX_INDEX_COST_ADJ) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "CBO_INDEX_COST_ADJ", (int64)CBO_MAX_INDEX_COST_ADJ);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t sql_verify_als_cbo_path_caching(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (num < CBO_MIN_PATH_CACHING) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "CBO_PATH_CACHING", (int64)CBO_MIN_PATH_CACHING);
        return CT_ERROR;
    } else if (num > CBO_MAX_PATH_CACHING) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "CBO_PATH_CACHING", (int64)CBO_MIN_PATH_CACHING);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_verify_als_withas_subquery(void *se, void *lex, void *def)
{
    uint32 match_id;
    const char *match_word[] = { "OPTIMIZER", "MATERIALIZE", "INLINE" };
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;

    if (lex_expected_fetch_1of3(lex, match_word[0], match_word[1], match_word[2], &match_id) != CT_SUCCESS) {
        return CT_ERROR;
    }

    MEMS_RETURN_IFERR(strcpy_s(sys_def->value, CT_PARAM_BUFFER_SIZE, match_word[match_id]));
    return CT_SUCCESS;
}

status_t sql_verify_als_lrpl_res_logsize(void *se, void *lex, void *def)
{
    return sql_verify_pool_size(lex, def, 0, CT_MAX_SGA_BUF_SIZE);
}

status_t sql_notify_als_lrpl_res_logsize(void *se, void *item, char *value)
{
    int64 val_int64;
    if (cm_str2size(value, &val_int64) != CT_SUCCESS) {
        return CT_ERROR;
    }

    g_instance->kernel.gbp_attr.lrpl_res_logsize = (uint64)val_int64;
    return CT_SUCCESS;
}

status_t sql_verify_als_arch_upper_limit(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (num < CT_MIN_ARCH_CLEAN_UL_PERCENT || num > CT_MAX_ARCH_CLEAN_PERCENT) {
        CT_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "ARCH_CLEAN_UPPER_LIMIT", (int64)CT_MIN_ARCH_CLEAN_UL_PERCENT,
            (int64)CT_MAX_ARCH_CLEAN_PERCENT);
        return CT_ERROR;
    }

    if (num < g_instance->kernel.attr.arch_lower_limit) {
        CT_THROW_ERROR_EX(ERR_INVALID_ARCHIVE_PARAMETER,
            "the value of ARCH_CLEAN_UPPER_LIMIT(%u) can not be "
            "smaller than the value of ARCH_CLEAN_LOWER_LIMIT(%u)",
            num, g_instance->kernel.attr.arch_lower_limit);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_verify_als_arch_lower_limit(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (num < CT_MIN_ARCH_CLEAN_LL_PERCENT || num > CT_MAX_ARCH_CLEAN_PERCENT) {
        CT_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "ARCH_CELAN_LOWER_LIMIT", (int64)CT_MIN_ARCH_CLEAN_LL_PERCENT,
            (int64)CT_MAX_ARCH_CLEAN_PERCENT);
        return CT_ERROR;
    }

    if (num > g_instance->kernel.attr.arch_upper_limit) {
        CT_THROW_ERROR_EX(ERR_INVALID_ARCHIVE_PARAMETER,
            "the value of ARCH_CLEAN_UPPER_LIMIT(%u) can not be "
            "smaller than the value of ARCH_CLEAN_LOWER_LIMIT(%u)",
            g_instance->kernel.attr.arch_upper_limit, num);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t sql_notify_als_arch_upper_limit(void *se, void *item, char *value)
{
    uint32 val_int32;
    if (cm_str2uint32(value, &val_int32) != CT_SUCCESS) {
        return CT_ERROR;
    }

    g_instance->kernel.attr.arch_upper_limit = val_int32;
    return CT_SUCCESS;
}

status_t sql_notify_als_arch_lower_limit(void *se, void *item, char *value)
{
    uint32 val_int32;
    if (cm_str2uint32(value, &val_int32) != CT_SUCCESS) {
        return CT_ERROR;
    }

    g_instance->kernel.attr.arch_lower_limit = val_int32;
    return CT_SUCCESS;
}

status_t sql_notify_als_nl_full_opt(void *se, void *item, char *value)
{
    g_instance->sql.enable_nl_full_opt = (bool32)value[0];
    return sql_notify_als_bool(se, item, value);
}

status_t sql_verify_als_backup_buf_size(void *se, void *lex, void *def)
{
    return sql_verify_pool_size(lex, def, CT_MIN_BACKUP_BUF_SIZE, CT_MAX_BACKUP_BUF_SIZE);
}

status_t sql_notify_als_backup_buf_size(void *se, void *item, char *value)
{
    int64 val_int64;

    if (cm_str2size(value, &val_int64) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (val_int64 % (uint32)SIZE_M(8) != 0) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "buffer size (%llu) is not an integral multiple of 8M.", val_int64);
        return CT_ERROR;
    }
    g_instance->kernel.attr.backup_buf_size = (uint64)val_int64;

    return CT_SUCCESS;
}

status_t sql_notify_als_enable_cbo_hint(void *se, void *item, char *value)
{
    g_instance->sql.enable_cbo_hint = (bool32)value[0];
    return sql_notify_als_bool(se, item, value);
}

status_t sql_verify_als_cbo_dyn_sampling(void *se, void *lex, void *def)
{
    uint32 value;
    if (sql_verify_uint32(lex, def, &value) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (value > CBO_MAX_DYN_SAMPLING_LEVEL) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "CBO_DYNAMIC_SAMPLING", (int64)CBO_MAX_DYN_SAMPLING_LEVEL);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t sql_notify_als_cbo_dyn_sampling(void *se, void *item, char *value)
{
    uint32 level;
    if (cm_str2uint32(value, &level) != CT_SUCCESS) {
        return CT_ERROR;
    }

    g_instance->sql.cbo_dyn_sampling = level;
    return CT_SUCCESS;
}

status_t sql_notify_als_strict_case_datatype(void *se, void *item, char *value)
{
    g_instance->sql.strict_case_datatype = (bool32)value[0];
    return sql_notify_als_bool(se, item, value);
}

#ifdef __cplusplus
}
#endif
