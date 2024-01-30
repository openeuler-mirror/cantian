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
 * set_others.h
 *
 *
 * IDENTIFICATION
 * src/server/params/set_others.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SRV_SET_OTHER_PARAM_H__
#define __SRV_SET_OTHER_PARAM_H__

#include "cm_defs.h"
#include "cm_config.h"

#ifdef __cplusplus
extern "C" {
#endif

// verify
status_t sql_verify_als_ip(void *se, void *lex, void *def);
status_t sql_verify_als_port(void *se, void *lex, void *def);
status_t sql_verify_als_worker_threads(void *se, void *lex, void *def);
status_t sql_verify_als_sql_compat(void *se, void *lex, void *def);
status_t sql_verify_als_pma_buf_size(void *se, void *lex, void *def);
status_t sql_verify_als_hash_area_size(void *se, void *lex, void *def);
status_t sql_verify_als_stack_size(void *se, void *lex, void *def);
status_t sql_verify_als_lob_max_exec_size(void *se, void *lex, void *def);
status_t sql_verify_als_variant_size(void *se, void *lex, void *def);
status_t sql_verify_als_init_cursors(void *se, void *lex, void *def);
status_t sql_verify_als_autonomous_sessions(void *se, void *lex, void *def);
status_t sql_verify_als_open_curs(void *se, void *lex, void *def);
status_t sql_verify_als_log_archive_config(void *se, void *lex, void *def);
status_t sql_verify_als_log_archive_max_min(void *se, void *lex, void *def);
status_t sql_verify_als_quorum_any(void *se, void *lex, void *def);
status_t sql_verify_als_statistics_level(void *se, void *lex, void *def);
status_t sql_verify_als_repl_port(void *se, void *lex, void *def);
status_t sql_verify_als_merge_batch_size(void *se, void *lex, void *def);
status_t sql_verify_als_convert(void *se, void *lex, void *def);
status_t sql_verify_als_ckpt_wait_timeout(void *se, void *lex, void *def);
status_t sql_verify_als_mem_pool_init_size(void *se, void *lex, void *def);
status_t sql_verify_als_mem_pool_max_size(void *se, void *lex, void *def);
status_t sql_verify_als_gbp_ip(void *se, void *lex, void *def);
status_t sql_verify_als_gbp_port(void *se, void *lex, void *def);
status_t sql_verify_als_local_gbp_host(void *se, void *lex, void *def);
status_t sql_verify_als_ssl_file(void *se, void *lex, void *def);
status_t sql_verify_ssl_alt_threshold(void *se, void *lex, void *def);
status_t sql_verify_ssl_period_detection(void *se, void *lex, void *def);
status_t sql_verify_als_ssl_cipher(void *se, void *lex, void *def);
status_t sql_verify_als_have_ssl(void *se, void *lex, void *def);
status_t sql_verify_als_stats_sample_size(void *se, void *lex, void *def);
status_t sql_verify_als_sql_cursors_each_sess(void *se, void *lex, void *def);
status_t sql_verify_als_reserved_sql_cursors(void *se, void *lex, void *def);
status_t sql_verify_als_max_remote_params(void *se, void *lex, void *def);
status_t sql_verify_als_gbp_trans_type(void *se, void *lex, void *def);
status_t sql_verify_als_node_lock_status(void *se, void *lex, void *def);
status_t sql_verify_als_ext_pool_size(void *se, void *lex, void *def);
status_t sql_verify_als_ext_work_thread_num(void *se, void *lex, void *def);
status_t sql_verify_als_ext_channel_num(void *se, void *lex, void *def);
status_t sql_verify_als_stats_parall_threads(void *se, void *lex, void *def);
status_t sql_verify_als_cbo_index_caching(void *se, void *lex, void *def);
status_t sql_verify_als_cbo_index_cost_adj(void *se, void *lex, void *def);
status_t sql_verify_als_cbo_path_caching(void *se, void *lex, void *def);
status_t sql_verify_als_cbo_dyn_sampling(void *se, void *lex, void *def);
status_t sql_verify_als_topn_threshold(void *se, void *lex, void *def);
status_t sql_verify_als_withas_subquery(void *se, void *lex, void *def);
status_t sql_verify_als_seg_pages_hold(void *se, void *lex, void *def);
status_t sql_verify_als_hash_pages_hold(void *se, void *lex, void *def);
status_t sql_verify_als_parall_max_threads(void *se, void *lex, void *def);
status_t sql_verify_als_multi_parts_scan(void *se, void *lex, void *def);
status_t sql_verify_als_arch_upper_limit(void *se, void *lex, void *def);
status_t sql_verify_als_arch_lower_limit(void *se, void *lex, void *def);
status_t sql_verify_als_backup_buf_size(void *se, void *lex, void *def);

// PARAM NOTIFY
status_t sql_notify_als_restore_arch_compressed(void *se, void *item, char *value);
status_t sql_notify_als_backup_buf_size(void *se, void *item, char *value);
status_t sql_notify_als_lrpl_res_logsize(void *se, void *item, char *value);
status_t sql_notify_als_sql_compat(void *se, void *item, char *value);
status_t sql_notify_als_hash_area_size(void *se, void *item, char *value);
status_t sql_notify_als__hint_force(void *se, void *item, char *value);
status_t sql_notify_als_open_curs(void *se, void *item, char *value);
status_t sql_notify_als_archive_max_processes(void *se, void *item, char *value);
status_t sql_notify_als_archive_min_succeed(void *se, void *item, char *value);
status_t sql_notify_als_archive_trace(void *se, void *item, char *value);
status_t sql_notify_als_quorum_any(void *se, void *item, char *value);
status_t sql_notify_als_stats_level(void *se, void *item, char *value);
status_t sql_notify_als_sql_stat(void *se, void *item, char *value);
status_t sql_notify_als_valid_node_checking(void *se, void *item, char *value);
status_t sql_notify_als_invited_nodes(void *se, void *item, char *value);
status_t sql_notify_als_excluded_nodes(void *se, void *item, char *value);
status_t sql_notify_als_merge_sort_batch_size(void *se, void *item, char *value);
status_t sql_notify_als_datefile_convert(void *se, void *item, char *value);
status_t sql_notify_als_logfile_convert(void *se, void *item, char *value);
status_t sql_notify_als_row_format(void *se, void *item, char *value);
status_t sql_verify_als_agent_extend_step(void *se, void *lex, void *def);
status_t sql_notify_als_timed_stat(void *se, void *item, char *value);
status_t sql_notify_als_coverage_enable(void *se, void *item, char *value);
status_t sql_notify_als_enable_raft(void *se, void *item, char *value);
status_t sql_notify_shard_enable_read_sync_slave(void *se, void *item, char *value);
status_t sql_notify_als_shard_max_replay_lag(void *se, void *item, char *value);
status_t sql_notify_als_sql_cursors_each_sess(void *se, void *item, char *value);
status_t sql_notify_als_reserved_sql_cursors(void *se, void *item, char *value);
status_t sql_notify_als_sample_size(void *se, void *item, char *value);
status_t sql_notify_als_max_remote_params(void *se, void *item, char *value);
status_t sql_verify_als_lrpl_res_logsize(void *se, void *lex, void *def);
status_t sql_notify_als_cost_limit(void *se, void *item, char *value);
status_t sql_notify_als_cost_delay(void *se, void *item, char *value);
status_t sql_notify_als_enable_sample_limit(void *se, void *item, char *value);
status_t sql_notify_als_master_backup_synctime(void *se, void *item, char *value);
status_t sql_notify_als_resource_plan(void *se, void *item, char *value);
status_t sql_notify_als_use_gbp(void *se, void *item, char *value);
status_t sql_notify_als_gbp_rcy_check(void *se, void *item, char *value);
status_t sql_notify_als_gbp_ip(void *se, void *item, char *value);
status_t sql_notify_als_stats_parall_threads(void *se, void *item, char *value);
status_t sql_notify_als_stats_enable_parall(void *se, void *item, char *value);
status_t sql_notify_als_bucket_size(void *se, void *item, char *value);
status_t sql_notify_als_undo_space(void *se, void *item, char *value);
status_t sql_notify_als_predicate(void *se, void *item, char *value);
status_t sql_notify_als_outer_join_opt(void *se, void *item, char *value);
status_t sql_notify_als_cbo_index_caching(void *se, void *item, char *value);
status_t sql_notify_als_cbo_index_cost_adj(void *se, void *item, char *value);
status_t sql_notify_als_cbo_path_caching(void *se, void *item, char *value);
status_t sql_notify_als_cbo_dyn_sampling(void *se, void *item, char *value);
status_t sql_notify_als_distinct_pruning(void *se, void *item, char *value);
status_t sql_notify_als_topn_threshold(void *se, void *item, char *value);
status_t sql_notify_als_withas_subquery(void *se, void *item, char *value);
status_t sql_notify_als_connect_by_mtrl(void *se, void *item, char *value);
status_t sql_notify_als_aggr_placement(void *se, void *item, char *value);
status_t sql_notify_als_or_expansion(void *se, void *item, char *value);
status_t sql_notify_als_distinct_elimination(void *se, void *item, char *value);
status_t sql_notify_als_project_list_pruning(void *se, void *item, char *value);
status_t sql_notify_als_pred_move_around(void *se, void *item, char *value);
status_t sql_notify_als_hash_mtrl(void *se, void *item, char *value);
status_t sql_notify_als_winmagic_rewrite(void *se, void *item, char *value);
status_t sql_notify_als_pred_reorder(void *se, void *item, char *value);
status_t sql_notify_als_order_by_placement(void *se, void *item, char *value);
status_t sql_notify_als_subquery_elimination(void *se, void *item, char *value);
status_t sql_notify_als_join_elimination(void *se, void *item, char *value);
status_t sql_notify_als_connect_by_placement(void *se, void *item, char *value);
status_t sql_notify_als_group_by_elimination(void *se, void *item, char *value);
status_t sql_notify_als_optim_any_transform(void *se, void *item, char *value);
status_t sql_notify_als_optim_all_transform(void *se, void *item, char *value);
status_t sql_notify_als_multi_index_scan(void *se, void *item, char *value);
status_t sql_notify_als_join_pred_pushdown(void *se, void *item, char *value);
status_t sql_notify_als_filter_pushdown(void *se, void *item, char *value);
status_t sql_notify_als_multi_parts_scan(void *se, void *item, char *value);
status_t sql_notify_als_order_by_elimination(void *se, void *item, char *value);
status_t sql_notify_als_unnest_set_subquery(void *se, void *item, char *value);
status_t sql_notify_als_enable_right_semijoin(void *se, void *item, char *value);
status_t sql_notify_als_enable_right_antijoin(void *se, void *item, char *value);
status_t sql_notify_als_enable_right_leftjoin(void *se, void *item, char *value);
status_t sql_notify_als_seg_pages_hold(void *se, void *item, char *value);
status_t sql_notify_als_hash_pages_hold(void *se, void *item, char *value);
status_t sql_notify_als_func_index_scan(void *se, void *item, char *value);
status_t sql_notify_als_index_cond_pruning(void *se, void *item, char *value);
status_t sql_notify_als_simplify_exists_subq(void *se, void *item, char *value);
status_t sql_notify_als_parall_max_threads(void *se, void *item, char *value);
status_t sql_notify_als_arch_upper_limit(void *se, void *item, char *value);
status_t sql_notify_als_arch_lower_limit(void *se, void *item, char *value);
status_t sql_notify_als_nl_full_opt(void *se, void *item, char *value);
status_t sql_notify_als_enable_arch_compressed(void *se, void *item, char *value);
status_t sql_notify_als_enable_cbo_hint(void *se, void *item, char *value);
status_t sql_notify_als_strict_case_datatype(void *se, void *item, char *value);

#ifdef Z_SHARDING
status_t shd_verify_als_scn_interval_threshold(void *se, void *lex, void *def);
status_t shd_notify_als_scn_interval_threshold(void *se, void *item, char *value);
#endif

#ifdef __cplusplus
}
#endif

#endif