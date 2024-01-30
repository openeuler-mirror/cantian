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
 * load_others.c
 *
 *
 * IDENTIFICATION
 * src/server/params/load_others.c
 *
 * -------------------------------------------------------------------------
 */
#include "srv_module.h"
#include "ddl_parser.h"
#include "cbo_base.h"
#include "srv_param_common.h"
#include "load_server.h"
#include "load_kernel.h"
#include "load_others.h"

#ifdef __cplusplus
extern "C" {
#endif

static char *g_config_file = "cantiand.ini";

status_t srv_param_change_notify(const char *name, const char *value)
{
    return CT_SUCCESS;
}

status_t srv_save_factor_key_file(const char *file_name, const char *value)
{
    status_t ret;
    int32 handle, file_size;
    uchar file_buf[CT_AESBLOCKSIZE + CT_HMAC256MAXSIZE + 4];
    uint32 cipher_len;

    // decode key
    cipher_len = cm_base64_decode((char *)value, (uint32)strlen(value), file_buf, sizeof(file_buf));
    CT_RETVALUE_IFTRUE(cipher_len == 0, CT_ERROR);
    file_size = CT_AESBLOCKSIZE;

    // calculate hmac
    cipher_len = sizeof(file_buf) - CT_AESBLOCKSIZE;
    CT_RETURN_IFERR(cm_encrypt_HMAC(file_buf, CT_AESBLOCKSIZE, file_buf, CT_AESBLOCKSIZE,
        (uchar *)(file_buf + CT_AESBLOCKSIZE), &cipher_len));
    file_size += cipher_len;

    // remove file
    if (access(file_name, R_OK | F_OK) == 0) {
        (void)chmod(file_name, S_IRUSR | S_IWUSR);
        CT_RETURN_IFERR(cm_remove_file(file_name));
    }

    // key file format: key(16) + salt(16) + hmac(32)
    CT_RETURN_IFERR(
        cm_open_file_ex(file_name, O_SYNC | O_CREAT | O_RDWR | O_TRUNC | O_BINARY, S_IRUSR | S_IWUSR, &handle));
    ret = cm_write_file(handle, file_buf, file_size);
    cm_close_file(handle);
    return ret;
}

bool32 srv_have_ssl(void)
{
    return (bool32)IS_SSL_ENABLED;
}

/* status_t srv_load_ext_proc_params()
{
    pl_manager_t *mngr = GET_PL_MGR;
    uint32 ext_pool_size;
    uint32 ext_work_thread_num;
    uint32 ext_channel_num;
    mes_profile_t *profile = &mngr->profile;
    mes_addr_t inst_arr[EXT_PROC_MAX_INSTANCES];

    char realfile[CT_UNIX_PATH_MAX];
    PRTS_RETURN_IFERR(snprintf_s(inst_arr[0].u_addr.path, CT_UNIX_PATH_MAX, CT_UNIX_PATH_MAX - 1,
        "%s/protect/%s", g_instance->home, UDS_EXT_INST_0));
    CT_RETURN_IFERR(realpath_file(inst_arr[0].u_addr.path, realfile, CT_UNIX_PATH_MAX));
    if (cm_file_exist((const char *)realfile)) {
        CT_RETURN_IFERR(cm_remove_file((const char *)realfile));
    }
    inst_arr[0].u_addr.permissions = S_IWUSR | S_IRUSR;

    PRTS_RETURN_IFERR(snprintf_s(inst_arr[1].u_addr.path, CT_UNIX_PATH_MAX, CT_UNIX_PATH_MAX - 1,
        "%s/protect/%s", g_instance->home, UDS_EXT_INST_1));
    CT_RETURN_IFERR(realpath_file(inst_arr[1].u_addr.path, realfile, CT_UNIX_PATH_MAX));
    if (cm_file_exist((const char *)realfile)) {
        CT_RETURN_IFERR(cm_remove_file((const char *)realfile));
    }
    inst_arr[1].u_addr.permissions = S_IWUSR | S_IRUSR;

    profile->module = MES_MOD_EXTPROC;
    profile->pipe_type = CS_TYPE_DOMAIN_SCOKET;
    profile->conn_by_profile = CT_TRUE;
    mes_set_instance_info(0, EXT_PROC_MAX_INSTANCES, inst_arr, profile);

    CT_RETURN_IFERR(srv_get_param_uint32("EXT_PROC_POOL_SIZE", &ext_pool_size));
    mes_set_pool_size(ext_pool_size, profile);

    CT_RETURN_IFERR(srv_get_param_uint32("EXT_PROC_WORK_THREAD_NUM", &ext_work_thread_num));
    mes_set_work_thread_num(ext_work_thread_num, profile);

    CT_RETURN_IFERR(srv_get_param_uint32("EXT_PROC_CHANNEL_NUM", &ext_channel_num));
    mes_set_channel_num(ext_channel_num, profile);

    return srv_get_param_bool32("EXT_PROC_STARTUP", (bool32 *)&mngr->bootstrap);
}
*/

static status_t srv_get_cbo_param(sql_instance_t *sql)
{
    CT_RETURN_IFERR(srv_get_param_uint32("CBO_INDEX_CACHING", &sql->cbo_index_caching));
    if (sql->cbo_index_caching > CBO_MAX_INDEX_CACHING) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "CBO_INDEX_CACHING", (int64)CBO_MAX_INDEX_CACHING);
        return CT_ERROR;
    }

    CT_RETURN_IFERR(srv_get_param_uint32("CBO_INDEX_COST_ADJ", &sql->cbo_index_cost_adj));
    if (sql->cbo_index_cost_adj > CBO_MAX_INDEX_COST_ADJ) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "CBO_INDEX_COST_ADJ", (int64)CBO_MAX_INDEX_COST_ADJ);
        return CT_ERROR;
    } else if (sql->cbo_index_cost_adj < CBO_MIN_INDEX_COST_ADJ) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "CBO_INDEX_COST_ADJ", (int64)CBO_MIN_INDEX_COST_ADJ);
        return CT_ERROR;
    }

    CT_RETURN_IFERR(srv_get_param_uint32("CBO_PATH_CACHING", &sql->cbo_path_caching));
    if (sql->cbo_path_caching > CBO_MAX_PATH_CACHING) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "CBO_PATH_CACHING", (int64)CBO_MAX_PATH_CACHING);
        return CT_ERROR;
    } else if (sql->cbo_path_caching < CBO_MIN_PATH_CACHING) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "CBO_PATH_CACHING", (int64)CBO_MIN_PATH_CACHING);
        return CT_ERROR;
    }

    CT_RETURN_IFERR(srv_get_param_uint32("CBO_DYNAMIC_SAMPLING", &sql->cbo_dyn_sampling));
    if (sql->cbo_dyn_sampling > CBO_MAX_DYN_SAMPLING_LEVEL) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "CBO_DYNAMIC_SAMPLING", (int64)CBO_MAX_DYN_SAMPLING_LEVEL);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t srv_get_withas_subquery_param(sql_instance_t *sql)
{
    char *value = srv_get_param("_WITHAS_SUBQUERY");
    if (value == NULL || strlen(value) == 0) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "_WITHAS_SUBQUERY");
        return CT_ERROR;
    }

    if (cm_str_equal_ins(value, "OPTIMIZER")) {
        sql->withas_subquery = WITHAS_OPTIMIZER;
    } else if (cm_str_equal_ins(value, "MATERIALIZE")) {
        sql->withas_subquery = WITHAS_MATERIALIZE;
    } else if (cm_str_equal_ins(value, "INLINE")) {
        sql->withas_subquery = WITHAS_INLINE;
    } else {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "_WITHAS_SUBQUERY");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t srv_load_optim_params(void)
{
    sql_instance_t *sql = &g_instance->sql;
    // parameters related to the optimizer
    CT_RETURN_IFERR(srv_get_param_onoff("_OUTER_JOIN_OPTIMIZATION", &sql->enable_outer_join_opt));
    CT_RETURN_IFERR(srv_get_param_onoff("_DISTINCT_PRUNING", &sql->enable_distinct_pruning));
    CT_RETURN_IFERR(srv_get_param_bool32("_CONNECT_BY_MATERIALIZE", &sql->enable_cb_mtrl));
    CT_RETURN_IFERR(srv_get_param_bool32("_OPTIMIZER_AGGR_PLACEMENT", &sql->enable_aggr_placement));
    CT_RETURN_IFERR(srv_get_param_bool32("_OPTIM_OR_EXPANSION", &sql->enable_or_expand));
    CT_RETURN_IFERR(srv_get_param_bool32("_OPTIM_PROJECT_LIST_PRUNING", &sql->enable_project_list_pruning));
    CT_RETURN_IFERR(srv_get_param_bool32("_OPTIM_PRED_MOVE_AROUND", &sql->enable_pred_move_around));
    CT_RETURN_IFERR(srv_get_param_bool32("_OPTIM_HASH_MATERIALIZE", &sql->enable_hash_mtrl));
    CT_RETURN_IFERR(srv_get_param_bool32("_OPTIM_WINMAGIC_REWRITE", &sql->enable_winmagic_rewrite));
    CT_RETURN_IFERR(srv_get_param_bool32("_OPTIM_PRED_REORDER", &sql->enable_pred_reorder));
    CT_RETURN_IFERR(srv_get_param_bool32("_OPTIM_ORDER_BY_PLACEMENT", &sql->enable_order_by_placement));
    CT_RETURN_IFERR(srv_get_param_bool32("_OPTIM_SUBQUERY_ELIMINATION", &sql->enable_subquery_elimination));
    CT_RETURN_IFERR(srv_get_param_bool32("_OPTIM_JOIN_ELIMINATION", &sql->enable_join_elimination));
    CT_RETURN_IFERR(srv_get_param_bool32("_OPTIM_CONNECT_BY_PLACEMENT", &sql->enable_connect_by_placement));
    CT_RETURN_IFERR(srv_get_param_bool32("_OPTIM_GROUP_BY_ELIMINATION", &sql->enable_group_by_elimination));
    CT_RETURN_IFERR(srv_get_param_bool32("_OPTIM_DISTINCT_ELIMINATION", &sql->enable_distinct_elimination));
    CT_RETURN_IFERR(srv_get_param_bool32("_OPTIM_ANY_TRANSFORM", &sql->enable_any_transform));
    CT_RETURN_IFERR(srv_get_param_bool32("_OPTIM_ALL_TRANSFORM", &sql->enable_all_transform));
    CT_RETURN_IFERR(srv_get_param_bool32("_ENABLE_MULTI_INDEX_SCAN", &sql->enable_multi_index_scan));
    CT_RETURN_IFERR(srv_get_param_bool32("_OPTIM_JOIN_PRED_PUSHDOWN", &sql->enable_join_pred_pushdown));
    CT_RETURN_IFERR(srv_get_param_bool32("_OPTIM_FILTER_PUSHDOWN", &sql->enable_filter_pushdown));
    CT_RETURN_IFERR(srv_get_param_bool32("_OPTIM_ORDER_BY_ELIMINATION", &sql->enable_order_by_elimination));
    CT_RETURN_IFERR(srv_get_param_bool32("_OPTIM_UNNEST_SET_SUBQUERY", &sql->enable_unnest_set_subq));
    CT_RETURN_IFERR(srv_get_param_bool32("_OPTIM_ENABLE_RIGHT_SEMIJOIN", &sql->enable_right_semijoin));
    CT_RETURN_IFERR(srv_get_param_bool32("_OPTIM_ENABLE_RIGHT_ANTIJOIN", &sql->enable_right_antijoin));
    CT_RETURN_IFERR(srv_get_param_bool32("_OPTIM_ENABLE_RIGHT_LEFTJOIN", &sql->enable_right_leftjoin));
    CT_RETURN_IFERR(srv_get_param_bool32("_OPTIM_FUNC_INDEX_SCAN_ONLY", &sql->enable_func_idx_only));
    CT_RETURN_IFERR(srv_get_param_bool32("_OPTIM_INDEX_COND_PRUNING", &sql->enable_index_cond_pruning));
    CT_RETURN_IFERR(srv_get_param_bool32("_OPTIM_SIMPLIFY_EXISTS_SUBQ", &sql->enable_exists_transform));
    CT_RETURN_IFERR(srv_get_param_bool32("_OPTIM_ADAPTIVE_FULL_OUTER_JOIN", &sql->enable_nl_full_opt));
    CT_RETURN_IFERR(srv_get_param_bool32("CBO_HINT_ENABLED", &g_instance->sql.enable_cbo_hint));
    CT_RETURN_IFERR(srv_get_cbo_param(sql));
    CT_RETURN_IFERR(srv_get_withas_subquery_param(sql));
    CT_RETURN_IFERR(srv_get_param_uint32("_QUERY_TOPN_THRESHOLD", &sql->topn_threshold));
    CT_RETURN_IFERR(srv_verf_param_uint64("_QUERY_TOPN_THRESHOLD", sql->topn_threshold, 0, CT_MAX_TOPN_THRESHOLD));
    CT_RETURN_IFERR(srv_get_param_uint32("SEGMENT_PAGES_HOLD", &sql->segment_pages_hold));
    CT_RETURN_IFERR(srv_verf_param_uint64("SEGMENT_PAGES_HOLD", sql->segment_pages_hold, 0, CT_MAX_SEGMENT_PAGES_HOLD));
    CT_RETURN_IFERR(srv_get_param_uint32("HASH_TABLE_PAGES_HOLD", &sql->hash_pages_hold));
    CT_RETURN_IFERR(srv_verf_param_uint64("HASH_TABLE_PAGES_HOLD", sql->hash_pages_hold, 0, CT_MAX_HASH_PAGES_HOLD));

    return CT_SUCCESS;
}

static status_t srv_load_agent_cursor_params(instance_attr_t *attr)
{
    CT_RETURN_IFERR(srv_get_param_uint32("_INIT_CURSORS", &attr->init_cursors));
    if (attr->init_cursors > CT_MAX_INIT_CURSORS) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "_INIT_CURSORS", (int64)CT_MAX_INIT_CURSORS);
        return CT_ERROR;
    }
    CT_RETURN_IFERR(srv_get_param_uint32("_SQL_CURSORS_EACH_SESSION", &attr->sql_cursors_each_sess));
    if (attr->sql_cursors_each_sess > CT_MAX_SQL_CURSORS_EACH_SESSION) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "_SQL_CURSORS_EACH_SESSION", (int64)CT_MAX_SQL_CURSORS_EACH_SESSION);
        return CT_ERROR;
    }
    CT_RETURN_IFERR(srv_get_param_uint32("_RESERVED_SQL_CURSORS", &attr->reserved_sql_cursors));
    if (attr->reserved_sql_cursors > CT_MAX_RESERVED_SQL_CURSORS) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "_RESERVED_SQL_CURSORS", (int64)CT_MAX_RESERVED_SQL_CURSORS);
        return CT_ERROR;
    }
    CT_RETURN_IFERR(srv_get_param_uint32("OPEN_CURSORS", &attr->open_cursors));
    if (attr->open_cursors < CT_MIN_OPEN_CURSORS) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "OPEN_CURSORS", (int64)CT_MIN_OPEN_CURSORS);
        return CT_ERROR;
    }
    if (attr->open_cursors > CT_MAX_OPEN_CURSORS) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "OPEN_CURSORS", (int64)CT_MAX_OPEN_CURSORS);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t srv_load_agent_params(void)
{
    uint32 stack_size = 0;
    char *value = NULL;
    instance_attr_t *attr = &g_instance->attr;

    CT_RETURN_IFERR(srv_get_param_size_uint32("_AGENT_STACK_SIZE", &stack_size));
    if (stack_size < CT_MIN_STACK_SIZE) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "_AGENT_STACK_SIZE");
        return CT_ERROR;
    }
    attr->stack_size = stack_size + CT_MIN_KERNEL_RESERVE_SIZE;

    CT_RETURN_IFERR(srv_get_param_size_uint32("_LOB_MAX_EXEC_SIZE", &attr->lob_max_exec_size));
    if (attr->lob_max_exec_size > stack_size) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "_LOB_MAX_EXEC_SIZE", (int64)stack_size);
        return CT_ERROR;
    }
    attr->lob_max_exec_size = stack_size;

    CT_RETURN_IFERR(srv_load_agent_cursor_params(attr));

    value = srv_get_param("USE_NATIVE_DATATYPE");
    if (cm_str_equal_ins(value, "TRUE")) {
        attr->using_naive_datatype = CT_TRUE;
    } else if (cm_str_equal_ins(value, "FALSE")) {
        attr->using_naive_datatype = CT_FALSE;
    } else {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "USE_NATIVE_DATATYPE");
        return CT_ERROR;
    }

    CT_RETURN_IFERR(srv_get_param_uint32("MAX_REMOTE_PARAMS", &attr->max_remote_params));
    if (attr->max_remote_params > CT_MAX_SQL_PARAM_COUNT) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "MAX_REMOTE_PARAMS", (int64)CT_MAX_SQL_PARAM_COUNT);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t srv_load_stat_params_core(void)
{
    char *value = srv_get_param("COVERAGE_ENABLE");
    if (cm_str_equal_ins(value, "TRUE")) {
        CT_LOG_RUN_INF("COVERAGE_ENABLE must start with FALSE");
        g_instance->sql.coverage_enable = CT_FALSE;
#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
        CT_RETURN_IFERR(cm_alter_config(&g_instance->config, "COVERAGE_ENABLE", "FALSE", CONFIG_SCOPE_BOTH, CT_TRUE));
#endif
    } else if (cm_str_equal_ins(value, "FALSE")) {
        g_instance->sql.coverage_enable = CT_FALSE;
    } else {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "COVERAGE_ENABLE");
        return CT_ERROR;
    }

    CT_RETURN_IFERR(srv_get_param_uint32("STATS_COST_LIMIT", &g_instance->kernel.attr.stats_cost_limit));
    if (g_instance->kernel.attr.stats_cost_limit > CT_INVALID_ID32) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "STATS_COST_LIMIT", (int64)CT_INVALID_ID32);
        return CT_ERROR;
    }

    CT_RETURN_IFERR(srv_get_param_uint32("STATS_COST_DELAY", &g_instance->kernel.attr.stats_cost_delay));

    if (g_instance->kernel.attr.stats_cost_delay > CT_INVALID_ID32) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "STATS_COST_DELAY", (int64)CT_INVALID_ID32);
        return CT_ERROR;
    }

    CT_RETURN_IFERR(srv_get_param_bool32("ENABLE_SAMPLE_LIMIT", &g_instance->kernel.attr.enable_sample_limit));

    CT_RETURN_IFERR(srv_get_param_uint16("STATS_MAX_BUCKET_SIZE", &g_instance->kernel.attr.stats_max_buckets));

    if (g_instance->kernel.attr.stats_max_buckets > STATS_HISTGRAM_MAX_SIZE ||
        g_instance->kernel.attr.stats_max_buckets < STATS_HISTGRAM_DEFAULT_SIZE) {
        CT_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "STATS_MAX_BUCKET_SIZE", (int64)STATS_HISTGRAM_DEFAULT_SIZE,
            (int64)STATS_HISTGRAM_MAX_SIZE);
        return CT_ERROR;
    }

    CT_RETURN_IFERR(srv_get_param_uint32("STATS_PARALL_THREADS", &g_instance->kernel.attr.stats_paraller_threads));

    if (g_instance->kernel.attr.stats_paraller_threads > CT_MAX_STATS_PARALL_THREADS ||
        g_instance->kernel.attr.stats_paraller_threads < CT_MIN_STATS_PARALL_THREADS) {
        CT_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "STATS_PARALL_THREADS", (int64)CT_MIN_STATS_PARALL_THREADS,
            (int64)CT_MAX_STATS_PARALL_THREADS);
        return CT_ERROR;
    }

    CT_RETURN_IFERR(srv_get_param_bool32("STATS_ENABLE_PARALL", &g_instance->kernel.attr.stats_enable_parall));
    return CT_SUCCESS;
}

status_t srv_load_stat_params(void)
{
    CT_RETURN_IFERR(srv_get_param_bool32("SQL_STAT", &g_instance->sql.enable_stat));

    CT_RETURN_IFERR(srv_get_param_bool32("TIMED_STATS", &g_instance->kernel.attr.enable_timed_stat));

    CT_RETURN_IFERR(srv_get_param_size_uint64("STATISTICS_SAMPLE_SIZE", &g_instance->kernel.attr.stats_sample_size));
    if (g_instance->kernel.attr.stats_sample_size > CT_INVALID_ID32) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "STATISTICS_SAMPLE_SIZE", (int64)CT_INVALID_ID32);
        return CT_ERROR;
    }

    char *value = srv_get_param("STATS_LEVEL");
    if (cm_str_equal_ins(value, "ALL") || cm_str_equal_ins(value, "TYPICAL")) {
        g_instance->kernel.attr.enable_table_stat = CT_TRUE;
    } else if (cm_str_equal_ins(value, "BASIC")) {
        g_instance->kernel.attr.enable_table_stat = CT_FALSE;
    } else {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER_ENUM, "STATS_LEVEL", value);
        return CT_ERROR;
    }

    CT_RETURN_IFERR(srv_load_stat_params_core());
    return CT_SUCCESS;
}

status_t srv_load_executor_params(void)
{
    char *value = srv_get_param("MERGE_SORT_BATCH_SIZE");
    if (cm_str2uint32(value, &g_instance->attr.merge_sort_batch_size) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "MERGE_SORT_BATCH_SIZE");
        return CT_ERROR;
    }
    if (g_instance->attr.merge_sort_batch_size < CT_MIN_MERGE_SORT_BATCH_SIZE) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "MERGE_SORT_BATCH_SIZE");
        return CT_ERROR;
    }

    value = srv_get_param("_HINT_FORCE");
    if (cm_str2uint32(value, &g_instance->attr.hint_force) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "_HINT_FORCE");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

void srv_print_params(void)
{
    uint32 i;
    config_item_t *item = NULL;

    for (i = 0; i < g_instance->config.item_count; i++) {
        item = &g_instance->config.items[i];
        if (item->name[0] == '_' || item->value == NULL) {
            continue;
        }
        // base on security, not print local_key and ssl_key_pwd
        if (cm_compare_str(item->name, (const char *)"LOCAL_KEY") == 0 ||
            cm_compare_str(item->name, (const char *)"SSL_KEY_PASSWORD") == 0 ||
            cm_compare_str(item->name, (const char *)"MES_SSL_KEY_PWD") == 0) {
            continue;
        }

        CT_LOG_RUN_INF("[PARAM] %-20s = %s", item->name, item->value);
    }
}

static inline status_t srv_set_single_default_arch(arch_attr_t *log_attr, int slot)
{
    if (!log_attr->used) {
        return CT_SUCCESS;
    }

    if (log_attr->dest_mode == LOG_ARCH_DEST_DEFAULT) {
        CT_THROW_ERROR(ERR_PARAMETER_CANNOT_IGNORE, "ARCHIVE_DEST_n");
        return CT_ERROR;
    }

    if (log_attr->affirm_mode == LOG_ARCH_DEFAULT) {
        log_attr->affirm_mode = LOG_ARCH_NOAFFIRM;
    }

    if (log_attr->net_mode == LOG_NET_TRANS_MODE_DEFAULT) {
        if (log_attr->role_valid == VALID_FOR_STANDBY_ROLE) {
            log_attr->net_mode = LOG_NET_TRANS_MODE_ASYNC;
        } else {
            log_attr->net_mode = LOG_NET_TRANS_MODE_SYNC;
        }
    }

    if (log_attr->trans_mode == LOG_TRANS_MODE_DEFAULT) {
        log_attr->trans_mode = LOG_TRANS_MODE_ARCH;
    }

    if (log_attr->role_valid == VALID_FOR_DEFAULT) {
        log_attr->role_valid = VALID_FOR_ALL_ROLES;
    }

    CT_RETURN_IFERR(arch_check_dest_service(&g_instance->kernel.attr, log_attr, slot));
    return CT_SUCCESS;
}

static status_t srv_set_default_arch_params(void)
{
    knl_attr_t *attr = &g_instance->kernel.attr;

    for (uint32 i = 0; i < CT_MAX_PHYSICAL_STANDBY + 1; i++) {
        CT_RETURN_IFERR(srv_set_single_default_arch(&attr->arch_attr[i], i));
    }

    return CT_SUCCESS;
}

static status_t srv_load_arch_params_location(arch_attr_t *arch_attr, text_t *inner_right)
{
    char buf[CT_MAX_FILE_NAME_LEN] = { 0 };
    char real_buf[CT_MAX_FILE_NAME_LEN] = { 0 };
    errno_t errcode;

    CT_RETURN_IFERR(cm_text2str(inner_right, buf, CT_MAX_FILE_NAME_LEN));
    CT_RETURN_IFERR(realpath_file(buf, real_buf, CT_MAX_FILE_NAME_LEN));
    errcode = strncpy_s(arch_attr->local_path, CT_MAX_FILE_NAME_LEN, buf, strlen(buf));
    if (errcode != EOK) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
        return CT_ERROR;
    }

    if (arch_attr->dest_mode != LOG_ARCH_DEST_DEFAULT) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "ARCHIVE_DEST_n");
        return CT_ERROR;
    }

    arch_attr->dest_mode = LOG_ARCH_DEST_LOCATION;
    return CT_SUCCESS;
}

static status_t srv_load_arch_params_service(arch_attr_t *arch_attr, text_t *inner_right)
{
    char buf[CT_MAX_FILE_NAME_LEN] = { 0 };
    text_t host, port;
    errno_t errcode;

    (void)cm_split_rtext(inner_right, ':', '\0', &host, &port);
    CT_RETURN_IFERR(cm_text2str(&host, buf, CT_HOST_NAME_BUFFER_SIZE));
    errcode = strncpy_s(arch_attr->service.host, CT_HOST_NAME_BUFFER_SIZE, buf, CT_MAX_FILE_NAME_LEN);
    if (errcode != EOK) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
        return CT_ERROR;
    }

    CT_RETURN_IFERR(cm_text2uint16(&port, &arch_attr->service.port));

    if (arch_attr->dest_mode != LOG_ARCH_DEST_DEFAULT) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "ARCHIVE_DEST_n");
        return CT_ERROR;
    }

    arch_attr->dest_mode = LOG_ARCH_DEST_SERVICE;
    return CT_SUCCESS;
}

static status_t srv_load_arch_params_host(arch_attr_t *arch_attr, text_t *inner_right)
{
    errno_t errcode;

    if (arch_attr->local_host[0] != '\0') {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "ARCHIVE_DEST_n");
        return CT_ERROR;
    }

    errcode = strncpy_s(arch_attr->local_host, CT_HOST_NAME_BUFFER_SIZE, inner_right->str, inner_right->len);
    if (errcode != EOK) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t srv_load_arch_params_right(arch_attr_t *arch_attr, text_t *inner_left, text_t *inner_right)
{
    if (cm_text_str_equal_ins(inner_left, "location")) {
        CT_RETURN_IFERR(srv_load_arch_params_location(arch_attr, inner_right));
    } else if (cm_text_str_equal_ins(inner_left, "service")) {
        CT_RETURN_IFERR(srv_load_arch_params_service(arch_attr, inner_right));
    } else if (cm_text_str_equal_ins(inner_left, "local_host")) {
        CT_RETURN_IFERR(srv_load_arch_params_host(arch_attr, inner_right));
    } else {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "ARCHIVE_DEST_n");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t srv_load_arch_params_get_mode(text_t *left, arch_attr_t *arch_attr)
{
    if (cm_text_str_equal_ins(left, "affirm")) {
        arch_attr->affirm_mode = LOG_ARCH_AFFIRM;
    } else if (cm_text_str_equal_ins(left, "noaffirm")) {
        arch_attr->affirm_mode = LOG_ARCH_NOAFFIRM;
    } else if (cm_text_str_equal_ins(left, "lgwr")) {
        arch_attr->trans_mode = LOG_TRANS_MODE_LGWR;
    } else if (cm_text_str_equal_ins(left, "arch")) {
        arch_attr->trans_mode = LOG_TRANS_MODE_ARCH;
    } else if (cm_text_str_equal_ins(left, "sync")) {
        arch_attr->net_mode = LOG_NET_TRANS_MODE_SYNC;
    } else if (cm_text_str_equal_ins(left, "async")) {
        arch_attr->net_mode = LOG_NET_TRANS_MODE_ASYNC;
    } else if (cm_text_str_equal_ins(left, "all_roles")) {
        arch_attr->role_valid = VALID_FOR_ALL_ROLES;
    } else if (cm_text_str_equal_ins(left, "primary_role")) {
        arch_attr->role_valid = VALID_FOR_PRIMARY_ROLE;
    } else if (cm_text_str_equal_ins(left, "standby_role")) {
        arch_attr->role_valid = VALID_FOR_STANDBY_ROLE;
    } else if (cm_text_str_equal_ins(left, "zstd")) {
        arch_attr->compress_alg = COMPRESS_ZSTD;
    } else if (cm_text_str_equal_ins(left, "lz4")) {
        arch_attr->compress_alg = COMPRESS_LZ4;
    } else if (left->len == 0) {
        return CT_SUCCESS;
    } else {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "ARCHIVE_DEST_n");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t srv_load_arch_params_left(arch_attr_t *arch_attr, text_t *left)
{
    arch_attr_t arch;
    bool32 invalid_param = CT_FALSE;
    MEMS_RETURN_IFERR(memset_s(&arch, sizeof(arch_attr_t), 0, sizeof(arch_attr_t)));
    CT_RETURN_IFERR(srv_load_arch_params_get_mode(left, &arch));

    if (arch.affirm_mode != LOG_ARCH_DEFAULT) {
        if (arch_attr->affirm_mode != LOG_ARCH_DEFAULT) {
            invalid_param = CT_TRUE;
        } else {
            arch_attr->affirm_mode = arch.affirm_mode;
        }
    }

    if (arch.trans_mode != LOG_TRANS_MODE_DEFAULT) {
        if (arch_attr->trans_mode != LOG_TRANS_MODE_DEFAULT) {
            invalid_param = CT_TRUE;
        } else {
            arch_attr->trans_mode = arch.trans_mode;
        }
    }

    if (arch.net_mode != LOG_NET_TRANS_MODE_DEFAULT) {
        if (arch_attr->net_mode != LOG_NET_TRANS_MODE_DEFAULT) {
            invalid_param = CT_TRUE;
        } else {
            arch_attr->net_mode = arch.net_mode;
        }
    }

    if (arch.role_valid != VALID_FOR_DEFAULT) {
        if (arch_attr->role_valid != VALID_FOR_DEFAULT) {
            invalid_param = CT_TRUE;
        } else {
            arch_attr->role_valid = arch.role_valid;
        }
    }

    if (arch.compress_alg != COMPRESS_NONE) {
        if (arch_attr->compress_alg != COMPRESS_NONE) {
            invalid_param = CT_TRUE;
        } else {
            arch_attr->compress_alg = arch.compress_alg;
        }
    }

    if (invalid_param) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "ARCHIVE_DEST_n");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t srv_arch_params_valid_check(arch_attr_t *arch_attr)
{
    if (arch_attr->role_valid == VALID_FOR_STANDBY_ROLE && arch_attr->net_mode == LOG_NET_TRANS_MODE_SYNC) {
        CT_THROW_ERROR(ERR_ASYNC_ONLY_PARAMETER, "cascading standby");
        return CT_ERROR;
    }

    if (arch_attr->dest_mode == LOG_ARCH_DEST_LOCATION && (arch_attr->local_host[0] != '\0' ||
        arch_attr->affirm_mode != LOG_ARCH_DEFAULT || arch_attr->trans_mode != LOG_TRANS_MODE_DEFAULT ||
        arch_attr->net_mode != LOG_NET_TRANS_MODE_DEFAULT || arch_attr->role_valid != VALID_FOR_DEFAULT)) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "ARCHIVE_DEST_n");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t srv_load_arch_single_dest(arch_attr_t *arch_attr, int slot, char *new_value)
{
    char *value = new_value;
    char param[ARCHIVE_DEST_N_LEN + 1] = { '\0' };
    text_t text, left, right, inner_left, inner_right;
    bool32 parse_done;
    char dest_stat[CT_MAX_NAME_LEN];

    MEMS_RETURN_IFERR(memset_s(arch_attr, sizeof(arch_attr_t), 0, sizeof(arch_attr_t)));

    if (value == NULL) {
        PRTS_RETURN_IFERR(snprintf_s(param, sizeof(param), ARCHIVE_DEST_N_LEN, "ARCHIVE_DEST_%d", slot + 1));
        value = srv_get_param(param);
    }

    cm_str2text(value, &text);
    cm_trim_text(&text);
    if (text.len == 0) {
        arch_attr->used = CT_FALSE;
        arch_attr->enable = CT_FALSE;
        return CT_SUCCESS;
    }

    parse_done = CT_FALSE;
    arch_attr->used = CT_TRUE;

    arch_attr->enable = CT_FALSE;
    if (new_value == NULL) {
        MEMS_RETURN_IFERR(memset_s(dest_stat, sizeof(dest_stat), 0, sizeof(dest_stat)));
        PRTS_RETURN_IFERR(
            snprintf_s(dest_stat, sizeof(dest_stat), sizeof(dest_stat) - 1, "ARCHIVE_DEST_STATE_%d", slot + 1));
        value = srv_get_param(dest_stat);
        arch_attr->enable = cm_str_equal_ins(value, "ENABLE");
    }

    while (!parse_done) {
        cm_split_text(&text, ' ', '\0', &left, &right);
        if (right.len == 0) {
            parse_done = CT_TRUE;
        }
        cm_split_text(&left, '=', '\0', &inner_left, &inner_right);
        if (inner_right.len != 0) {
            CT_RETURN_IFERR(srv_load_arch_params_right(arch_attr, &inner_left, &inner_right));
        } else {
            CT_RETURN_IFERR(srv_load_arch_params_left(arch_attr, &left));
        }

        text = right;
    }

    CT_RETURN_IFERR(srv_arch_params_valid_check(arch_attr));

    return CT_SUCCESS;
}

static status_t srv_load_arch_limit_params(void)
{
    knl_attr_t *attr = &g_instance->kernel.attr;
    CT_RETURN_IFERR(srv_get_param_size_uint32("ARCH_CLEAN_UPPER_LIMIT", &attr->arch_upper_limit));
    if (attr->arch_upper_limit < CT_MIN_ARCH_CLEAN_UL_PERCENT || attr->arch_upper_limit > CT_MAX_ARCH_CLEAN_PERCENT) {
        CT_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "ARCH_CLEAN_UPPER_LIMIT", (int64)CT_MIN_ARCH_CLEAN_UL_PERCENT,
            (int64)CT_MAX_ARCH_CLEAN_PERCENT);
        return CT_ERROR;
    }

    CT_RETURN_IFERR(srv_get_param_size_uint32("ARCH_CLEAN_LOWER_LIMIT", &attr->arch_lower_limit));
    if (attr->arch_lower_limit < CT_MIN_ARCH_CLEAN_LL_PERCENT || attr->arch_lower_limit > CT_MAX_ARCH_CLEAN_PERCENT) {
        CT_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "ARCH_CLEAN_LOWER_LIMIT", (int64)CT_MIN_ARCH_CLEAN_LL_PERCENT,
            (int64)CT_MAX_ARCH_CLEAN_PERCENT);
        return CT_ERROR;
    }

    if (attr->arch_upper_limit < attr->arch_lower_limit) {
        CT_THROW_ERROR_EX(ERR_INVALID_ARCHIVE_PARAMETER,
            "the value of ARCH_CLEAN_UPPER_LIMIT(%u) can not be "
            "smaller than the value of ARCH_CLEAN_LOWER_LIMIT(%u)",
            attr->arch_upper_limit, attr->arch_lower_limit);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t srv_load_arch_params()
{
    knl_attr_t *attr = &g_instance->kernel.attr;
    text_t db_version, left, right, left2;

    for (uint32 i = 0; i < CT_MAX_PHYSICAL_STANDBY + 1; i++) {
        CT_RETURN_IFERR(srv_load_arch_single_dest(&attr->arch_attr[i], i, NULL));
    }

    // max archive files
    CT_RETURN_IFERR(srv_get_param_size_uint64("MAX_ARCH_FILES_SIZE", &attr->max_arch_files_size));
    if (attr->max_arch_files_size > CT_MAX_ARCH_FILES_SIZE) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "MAX_ARCH_FILES_SIZE", CT_MAX_ARCH_FILES_SIZE);
        return CT_ERROR;
    }
    CT_RETURN_IFERR(srv_get_param_bool32("ARCH_LOG_CHECK", &attr->arch_log_check));
    CT_RETURN_IFERR(srv_get_param_bool32("ARCH_CLEAN_IGNORE_BACKUP", &attr->arch_ignore_backup));
    CT_RETURN_IFERR(srv_get_param_bool32("ARCH_CLEAN_IGNORE_STANDBY", &attr->arch_ignore_standby));

    if (srv_get_param_uint32("QUORUM_ANY", &g_instance->kernel.attr.quorum_any) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (g_instance->kernel.attr.quorum_any > CT_MAX_PHYSICAL_STANDBY) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "QUORUM_ANY", (int64)CT_MAX_PHYSICAL_STANDBY);
        return CT_ERROR;
    }

    CT_RETURN_IFERR(srv_get_param_size_uint64("BACKUP_BUFFER_SIZE", &attr->backup_buf_size));
    if (attr->backup_buf_size < CT_MIN_BACKUP_BUF_SIZE || attr->backup_buf_size > CT_MAX_BACKUP_BUF_SIZE) {
        CT_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "BACKUP_BUFFER_SIZE", (int64)CT_MIN_BACKUP_BUF_SIZE,
            (int64)CT_MAX_BACKUP_BUF_SIZE);
        return CT_ERROR;
    }
    if (attr->backup_buf_size % (uint32)SIZE_M(8) != 0) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "buffer size (%llu) is not an integral multiple of 8M.",
            attr->backup_buf_size);
        return CT_ERROR;
    }

    CT_RETURN_IFERR(srv_get_param_bool32("RESTORE_ARCH_COMPRESSED", &attr->restore_keep_arch_compressed));
    CT_RETURN_IFERR(srv_get_param_bool32("ENABLE_ARCH_COMPRESS", &attr->enable_arch_compress));
    if (g_instance->lsnr.tcp_replica.port != 0 && attr->enable_arch_compress) {
        CT_THROW_ERROR(ERR_INVALID_OPERATION, ", forbid to set ENABLE_ARCH_COMPRESS to TRUE in HA mode");
        return CT_ERROR;
    }

    CT_RETURN_IFERR(srv_get_param_bool32("_RESTORE_CHECK_VERSION", &attr->restore_check_version));
    if (srv_load_arch_limit_params() != CT_SUCCESS) {
        return CT_ERROR;
    }
    cm_str2text(cantiand_get_dbversion(), &db_version);
    (void)cm_split_rtext(&db_version, ' ', 0, &left, &right);
    (void)cm_split_rtext(&left, ' ', 0, &left2, &right);
    CT_LOG_RUN_INF("[DB] database version: %s, version number: %s", cantiand_get_dbversion(), T2S(&right));
    CT_RETURN_IFERR(cm_text2str(&right, attr->db_version, CT_DB_NAME_LEN));

    return srv_set_default_arch_params();
}

status_t srv_load_file_convert_params(void)
{
    knl_attr_t *attr = &g_instance->kernel.attr;
    char *value = NULL;

    MEMS_RETURN_IFERR(memset_s(&attr->data_file_convert, sizeof(file_convert_t), 0, sizeof(file_convert_t)));
    MEMS_RETURN_IFERR(memset_s(&attr->log_file_convert, sizeof(file_convert_t), 0, sizeof(file_convert_t)));

    value = srv_get_param("DB_FILE_NAME_CONVERT");
    CT_RETURN_IFERR(knl_get_convert_params("DB_FILE_NAME_CONVERT", value, &attr->data_file_convert, g_instance->home));

    value = srv_get_param("LOG_FILE_NAME_CONVERT");
    CT_RETURN_IFERR(knl_get_convert_params("LOG_FILE_NAME_CONVERT", value, &attr->log_file_convert, g_instance->home));

    return CT_SUCCESS;
}

status_t srv_load_lsnr_params(void)
{
    white_context_t *ctx = GET_WHITE_CTX;
    text_t invited_nodes;
    text_t excluded_nodes;

    CT_RETURN_IFERR(srv_get_param_bool32("TCP_VALID_NODE_CHECKING", &ctx->iwl_enabled));
    cm_str2text(srv_get_param("TCP_INVITED_NODES"), &invited_nodes);
    cm_str2text(srv_get_param("TCP_EXCLUDED_NODES"), &excluded_nodes);

    // Alarm if TCP_VALID_NODE_CHECKING disabled, but white/black ip list configured.
    if (!ctx->iwl_enabled && (!CM_IS_EMPTY(&invited_nodes) || !CM_IS_EMPTY(&excluded_nodes))) {
        CT_LOG_RUN_WAR("IP whitelist function is not enable, but invited nodes or excluded nodes is not empty");
    }

    // ERROR if TCP_VALID_NODE_CHECKING is enabled, but white/black ip list both not configured
    if (ctx->iwl_enabled && (CM_IS_EMPTY(&invited_nodes)) && (CM_IS_EMPTY(&excluded_nodes))) {
        CT_THROW_ERROR(ERR_TCP_VALID_NODE_CHECKING);
        return CT_ERROR;
    }

    if (cm_parse_cidrs(&excluded_nodes, &ctx->ip_black_list) != CT_SUCCESS) {
        cm_reset_list(&ctx->ip_black_list);

        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "TCP_EXCLUDED_NODES");
        return CT_ERROR;
    }

    if (cm_parse_cidrs(&invited_nodes, &ctx->ip_white_list) != CT_SUCCESS) {
        cm_reset_list(&ctx->ip_white_list);

        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "TCP_INVITED_NODES");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t srv_load_other_params(void)
{
    CT_RETURN_IFERR(srv_get_param_bool32("BACKUP_RETRY", &g_instance->kernel.attr.backup_retry));
    return CT_SUCCESS;
}

static status_t init_run_log(const char *file_name)
{
    cm_log_init(LOG_RUN, file_name);
    log_file_handle_t *log_file = cm_log_logger_file(LOG_RUN);
    if (!cm_file_exist(file_name)) {
        cm_log_open_file(log_file);
    }

    log_param_t *log_param = cm_log_param_instance();
    log_param->log_level = 1;
    log_param->max_log_file_size = CT_MIN_LOG_FILE_SIZE;
    log_param->log_file_permissions = S_IRUSR | S_IWUSR | S_IRGRP;
    log_param->log_bak_file_permissions = S_IRUSR;
    log_param->log_path_permissions = S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IXGRP;

    return CT_SUCCESS;
}

static status_t verify_run_log_path(void)
{
    char *path = NULL;
    char file_name[CT_FILE_NAME_BUFFER_SIZE] = { '\0' };
    // 1 get $CANTIANLOG
    path = getenv("CANTIANLOG");
    // 2 get $CTDB_HOME
    if (path == NULL) {
        path = getenv(CT_ENV_HOME);
    }

    if (path != NULL) {
        if (cm_dir_exist(path)) {
            PRTS_RETURN_IFERR(snprintf_s(file_name, CT_FILE_NAME_BUFFER_SIZE, CT_MAX_FILE_NAME_LEN, "%s/log/run/%s",
                path, "cantiand.rlog"));
            CT_RETURN_IFERR(init_run_log(file_name));
            return CT_SUCCESS;
        }
    }

    return CT_ERROR;
}
status_t srv_alter_arch_dest(void *arch_attr, int slot, char *value)
{
    knl_attr_t *attr = &g_instance->kernel.attr;

    if (attr->arch_attr[slot].enable) {
        CT_THROW_ERROR(ERR_LOG_ARCH_DEST_IN_USE);
        CT_LOG_RUN_ERR("ARCHIVE_DEST is in use, please disable it firstly");
        return CT_ERROR;
    }

    CT_RETURN_IFERR(srv_load_arch_single_dest((arch_attr_t *)arch_attr, slot, value));
    CT_RETURN_IFERR(srv_set_single_default_arch((arch_attr_t *)arch_attr, slot));

    return CT_SUCCESS;
}

status_t srv_load_params(void)
{
    config_item_t *params = NULL;
    uint32 param_count;
    char file_name[CT_FILE_NAME_BUFFER_SIZE] = { 0 };
    // get config info
    PRTS_RETURN_IFERR(snprintf_s(file_name, CT_FILE_NAME_BUFFER_SIZE, CT_FILE_NAME_BUFFER_SIZE - 1, "%s/cfg/%s",
        g_instance->home, g_config_file));

    srv_get_config_info(&params, &param_count);
    if (cm_load_config(params, param_count, file_name, &g_instance->config, CT_TRUE) != CT_SUCCESS) {
        if (verify_run_log_path() != CT_SUCCESS) {
            printf("Fail to get the environment variable.");
            return CT_ERROR;
        }
        return CT_ERROR;
    }

    CT_RETURN_IFERR(srv_load_server_params());

    CT_RETURN_IFERR(srv_load_kernel_params());

    CT_RETURN_IFERR(srv_load_agent_params());

    CT_RETURN_IFERR(srv_load_stat_params());

    CT_RETURN_IFERR(srv_load_arch_params());

    CT_RETURN_IFERR(srv_load_lsnr_params());

    CT_RETURN_IFERR(srv_load_executor_params());

    CT_RETURN_IFERR(srv_load_file_convert_params());

    //    CT_RETURN_IFERR(srv_load_ext_proc_params());

    CT_RETURN_IFERR(srv_load_optim_params());

    CT_RETURN_IFERR(srv_load_cluster_params());

    CT_RETURN_IFERR(srv_load_gdv_params());

    CT_RETURN_IFERR(srv_load_other_params());

    init_runtime_params();

    return CT_SUCCESS;
}

#ifdef __cplusplus
}
#endif
