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
 * set_server.h
 *
 *
 * IDENTIFICATION
 * src/server/params/set_server.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SRV_SET_SERVER_PARAMS_H__
#define __SRV_SET_SERVER_PARAMS_H__

#include "cm_config.h"

#ifdef __cplusplus
extern "C" {
#endif

// params verify
status_t sql_verify_als_uds_file_path(void *se, void *lex, void *def);
status_t sql_verify_als_uds_file_permissions(void *se, void *lex, void *def);
status_t sql_verify_als_bool_only_sys_allowed(void *se, void *lex, void *def);
status_t sql_verify_als_optimized_worker_threads(void *se, void *lex, void *def);
status_t sql_verify_als_max_worker_threads(void *se, void *lex, void *def);
status_t sql_verify_als_agent_shrink_threshold(void *se, void *lex, void *def);
status_t sql_verify_als_db_tz(void *se, void *lex, void *def);
status_t sql_verify_als_reactor_threads(void *se, void *lex, void *def);
status_t sql_verify_super_user_sessions(void *se, void *lex, void *def);
status_t sql_verify_normal_emerge_sess_factor(void *se, void *lex, void *def);
status_t sql_verify_als_sessions(void *se, void *lex, void *def);
status_t sql_verify_als_prefetch_rows(void *se, void *lex, void *def);
status_t sql_verify_json_dyn_buf_size(void *se, void *lex, void *def);
status_t sql_verify_als_encryption_alg(void *se, void *lex, void *def);
status_t sql_verify_als_sys_password(void *se, void *lex, void *def);
status_t sql_verify_als_encrypt_iteration(void *se, void *lex, void *def);
status_t sql_verify_als_factor_key(void *se, void *lex, void *def);
status_t sql_verify_als_local_key(void *se, void *lex, void *def);
status_t sql_verify_als_range_cache(void *se, void *lex, void *def);
status_t sql_verify_als_max_allowed_packet(void *se, void *lex, void *def);
status_t sql_verify_als_interactive_timeout(void *se, void *lex, void *def);
status_t sql_verify_als_sql_map_buckets(void *se, void *lex, void *def);
status_t sql_verify_als_max_sql_map_per_user(void *se, void *lex, void *def);
status_t sql_verify_als_sga_core_dump_config(void *se, void *lex, void *def);
status_t sql_verify_als_job_queue_processes(void *se, void *lex, void *def);
status_t sql_verify_als_xa_format_id(void *se, void *lex, void *def);
status_t sql_verify_als_shard_refusesql_level(void *se, void *lex, void *def);
status_t sql_verify_als_shard_refusetrans_level(void *se, void *lex, void *def);

// params notify
status_t sql_notify_als_shard_restricted_feature(void *se, void *item, char *value);
status_t sql_notify_als_access_dc_enable_bool(void *se, void *item, char *value);
status_t sql_notify_als_view_access_dc_bool(void *se, void *item, char *value);
status_t sql_notify_als_shard_error_force_rollback(void *se, void *item, char *value);
status_t sql_notify_als_normal_emerge_sess_factor(void *se, void *item, char *value);
status_t sql_notify_als_prefetch_rows(void *se, void *item, char *value);
status_t sql_notify_als_enable_arr_store_opt(void *se, void *item, char *value);
status_t sql_notify_als_sys_password(void *se, void *item, char *value);
status_t sql_notify_als_encrypt_iteration(void *se, void *item, char *value);
status_t sql_notify_als_local_key(void *se, void *item, char *value);
status_t sql_notify_als_factor_key(void *se, void *item, char *value);
status_t sql_notify_als_login_as_sysdba(void *se, void *item, char *value);
status_t sql_notify_als_sys_remote_login(void *se, void *item, char *value);
status_t sql_notify_als_sysdba_remote_login(void *se, void *item, char *value);
status_t sql_notify_als_commit_on_disconn(void *se, void *item, char *value);
status_t sql_notify_als_max_connect_by_level(void *se, void *item, char *value);
status_t sql_notify_als_min_range_cache(void *se, void *item, char *value);
status_t sql_notify_als_vm_view_mtrl(void *se, void *item, char *value);
status_t sql_notify_als_enable_password_cipher(void *se, void *item, char *value);
status_t sql_notify_als_max_allowed_packet(void *se, void *item, char *value);
status_t sql_notify_als_parallel_policy(void *se, void *item, char *value);
status_t sql_notify_als_interactive_timeout(void *se, void *item, char *value);
status_t sql_notify_zero_divisor_accepted(void *se, void *item, char *value);
status_t sql_notify_string_as_hex_binary(void *se, void *item, char *value);
status_t sql_notify_als_enable_err_superposed(void *se, void *item, char *value);
status_t sql_notify_als_unauth_session_expire_time(void *se, void *item, char *value);
status_t sql_notify_empty_string_null(void *se, void *item, char *value);
status_t sql_notify_als_enable_sql_map(void *se, void *item, char *value);
status_t sql_notify_als_max_sql_map_per_user(void *se, void *item, char *value);
status_t sql_notify_als_sga_core_dump_config(void *se, void *item, char *value);
status_t sql_notify_als_shard_serial_execution(void *se, void *item, char *value);
status_t sql_notify_als_shard_check_unique(void *se, void *item, char *value);
status_t sql_notify_als_shard_refusesql_level(void *se, void *item, char *value);
status_t sql_notify_als_shard_refusetrans_level(void *se, void *item, char *value);
status_t sql_notify_als_shard_retry_times(void *se, void *item, char *value);
status_t sql_notify_als_shard_retry_interval(void *se, void *item, char *value);
status_t sql_notify_als_shard_connect_timeout(void *se, void *item, char *value);
status_t sql_notify_als_shard_socket_timeout(void *se, void *item, char *value);
status_t sql_notify_als_shard_heartbeat_timeout(void *se, void *item, char *value);
status_t sql_notify_als_shard_ptrans_clean_timeout(void *se, void *item, char *value);
status_t sql_notify_enable_local_infile(void *se, void *item, char *value);
status_t sql_notify_als_enable_permissive_unicode(void *se, void *item, char *value);
status_t sql_notify_als_disable_var_peek(void *se, void *item, char *value);
status_t sql_notify_als_enable_cursor_sharing(void *se, void *item, char *value);
status_t sql_notify_als_enable_use_spm(void *se, void *item, char *value);
status_t sql_notify_als_compatible_mysql(void *se, void *item, char *value);
#ifdef Z_SHARDING
status_t sql_verify_als_cache_size(void *se, void *lex, void *def);
status_t sql_verify_als_node_heartbeat_timeout(void *se, void *lex, void *def);
status_t sql_verify_als_ptrans_timeout(void *se, void *lex, void *def);
status_t sql_verify_als_dn_groups_before_expand(void *se, void *lex, void *def);
status_t shd_verify_als_priv_connection(void *se, void *lex, void *def);
status_t shd_verify_als_priv_session(void *se, void *lex, void *def);
status_t shd_verify_als_priv_agent(void *se, void *lex, void *def);

status_t sql_notify_als_seq_cache_size(void *se, void *item, char *value);
status_t shd_notify_als_strong_cons(void *se, void *item, char *value);
status_t shd_notify_als_ptrans_clean_interval(void *se, void *item, char *value);
status_t shd_notify_als_node_heartbeat_timeout(void *se, void *item, char *value);
status_t shd_notify_als_ptrans_timeout(void *se, void *item, char *value);
status_t sql_notify_als_dn_groups_before_expand(void *se, void *item, char *value);
status_t sql_notify_als_shard_check_db_role(void *se, void *item, char *value);

#endif
status_t sql_notify_json_dyn_buf_size(void *se, void *item, char *value);

status_t sql_verify_als_interconnect_port(void *se, void *lex, void *def);
status_t sql_verify_als_interconnect_type(void *se, void *lex, void *def);
status_t sql_verify_als_remote_access_limit(void *se, void *lex, void *def);
status_t sql_verify_als_deadlock_detect_interval(void *se, void *lex, void *def);
status_t sql_verify_als_auto_undo_retention(void *se, void *lex, void *def);
status_t sql_verify_als_compatible_mysql(void *se, void *lex, void *def);


status_t sql_notify_als_mes_elapsed_switch(void *se, void *item, char *value);
status_t sql_notify_als_enable_rmo_cr(void *se, void *item, char *value);
status_t sql_notify_als_enable_tx_free_page_list(void *se, void *item, char *value);
status_t sql_notify_als_remote_access_limit(void *se, void *item, char *value);
status_t sql_notify_als_gdv_sess_tmout(void *se, void *item, char *value);
status_t sql_notify_als_deadlock_detect_interval(void *se, void *item, char *value);
status_t sql_notify_als_auto_undo_retention(void *se, void *item, char *value);

status_t sql_verify_als_mes_task_ratio(void *se, void *lex, void *def);
#ifdef __cplusplus
}
#endif

#endif
