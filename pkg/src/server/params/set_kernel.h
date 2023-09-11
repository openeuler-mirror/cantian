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
 * set_kernel.h
 *
 *
 * IDENTIFICATION
 * src/server/params/set_kernel.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SRV_SET_KERNEL_PARAMS_H__
#define __SRV_SET_KERNEL_PARAMS_H__

#include "cm_config.h"

#ifdef __cplusplus
extern "C" {
#endif

// kernel params verify
status_t sql_verify_als_page_size(void *se, void *lex, void *def);
status_t sql_verify_als_max_col_count(void *se, void *lex, void *def);
status_t sql_verify_als_init_trans(void *se, void *lex, void *def);
status_t sql_verify_als_cr_mode(void *se, void *lex, void *def);
status_t sql_verify_als_row_format(void *se, void *lex, void *def);
status_t sql_verify_als_undo_segs(void *se, void *lex, void *def);
status_t sql_verify_als_active_undo_segs(void *se, void *lex, void *def);
status_t sql_verify_als_auton_trans_segs(void *se, void *lex, void *def);
status_t sql_verify_als_rollback_proc_num(void *se, void *lex, void *def);
status_t sql_verify_als_data_buf_size(void *se, void *lex, void *def);
status_t sql_verify_als_page_clean_time(void *se, void *lex, void *def);
status_t sql_verify_als_page_clean_ratio(void *se, void *lex, void *def);
status_t sql_verify_als_lru_search_threshold(void *se, void *lex, void *def);
status_t sql_verify_als_cr_pool_size(void *se, void *lex, void *def);
status_t sql_verify_als_cr_pool_cnt(void *se, void *lex, void *def);
status_t sql_verify_als_buf_pool_num(void *se, void *lex, void *def);
status_t sql_verify_als_default_exts(void *se, void *lex, void *def);
status_t sql_verify_als_default_spc_type(void *se, void *lex, void *def);
status_t sql_verify_als_table_spc_alarm_threshold(void *se, void *lex, void *def);
status_t sql_verify_als_systime_growth_threshold(void *se, void *lex, void *def);
status_t sql_verify_als_undo_alarm_threshold(void *se, void *lex, void *def);
status_t sql_verify_als_txn_undo_alarm_threshold(void *se, void *lex, void *def);
status_t sql_verify_als_vma_size(void *se, void *lex, void *def);
status_t sql_verify_als_large_vma_size(void *se, void *lex, void *def);
status_t sql_verify_als_shared_pool_size(void *se, void *lex, void *def);
status_t sql_verify_als_sql_pool_fat(void *se, void *lex, void *def);
status_t sql_verify_als_large_pool_size(void *se, void *lex, void *def);
status_t sql_verify_als_log_buf_size(void *se, void *lex, void *def);
status_t sql_verify_als_log_buf_count(void *se, void *lex, void *def);
status_t sql_verify_als_temp_buf_size(void *se, void *lex, void *def);
status_t sql_verify_als_max_tmp_tables(void *se, void *lex, void *def);
status_t sql_verify_als_tmp_pool_num(void *se, void *lex, void *def);
status_t sql_verify_als_max_link_tables(void *se, void *lex, void *def);
status_t sql_verify_als_index_buf_size(void *se, void *lex, void *def);
status_t sql_verify_als_checkpoint_interval(void *se, void *lex, void *def);
status_t sql_verify_als_checkpoint_timeout(void *se, void *lex, void *def);
status_t sql_verify_als_checkpoint_io_capacity(void *se, void *lex, void *def);
status_t sql_verify_als_commit_logging(void *se, void *lex, void *def);
status_t sql_verify_als_commit_wait(void *se, void *lex, void *def);
status_t sql_verify_als_dbwr_procedure(void *se, void *lex, void *def);
status_t sql_verify_als_rcy_params(void *se, void *lex, void *def);
status_t sql_verify_als_rcy_preload_process(void *se, void *lex, void *def);
status_t sql_verify_als_rcy_sleep_interval(void *se, void *lex, void *def);
status_t sql_verify_als_cpu_node_bind(void *se, void *lex, void *def);
status_t sql_verify_als_qos_ctrl_fat(void *se, void *lex, void *def);
status_t sql_verify_als_qos_sleep_time(void *se, void *lex, void *def);
status_t sql_verify_als_qos_rand_range(void *se, void *lex, void *def);
status_t sql_verify_als_db_block_checksum(void *se, void *lex, void *def);
status_t sql_verify_als_db_isolevel(void *se, void *lex, void *def);
status_t sql_verify_als_thread_stack_size(void *se, void *lex, void *def);
status_t sql_verify_als_undo_reserve_size(void *se, void *lex, void *def);
status_t sql_verify_als_undo_retention_time(void *se, void *lex, void *def);
status_t sql_verify_als_undo_prefetch_pages(void *se, void *lex, void *def);
status_t sql_verify_als_xa_suspend_timeout(void *se, void *lex, void *def);
status_t sql_verify_als_repl_wait_timeout(void *se, void *lex, void *def);
status_t sql_verify_als_repl_max_pkg_size(void *se, void *lex, void *def);
status_t sql_verify_als_filesystemio_options(void *se, void *lex, void *def);
status_t sql_verify_als_idx_duplicate_enable(void *se, void *lex, void *def);
status_t sql_verify_als_ddl_lock_timeout(void *se, void *lex, void *def);
status_t sql_verify_als_max_rm_count(void *se, void *lex, void *def);
status_t sql_verify_als_ashrink_wait_time(void *se, void *lex, void *def);
status_t sql_verify_als_shrink_wait_recycled_pages(void *se, void *lex, void *def);
status_t sql_verify_als_small_table_sampling_threshold(void *se, void *lex, void *def);
status_t sql_verify_als_block_repair_timeout(void *se, void *lex, void *def);
status_t sql_verify_als_nbu_backup_timeout(void *se, void *lex, void *def);
status_t sql_verify_als_lob_reuse_threshold(void *se, void *lex, void *def);
status_t sql_verify_init_lockpool_pages(void *se, void *lex, void *def);
status_t sql_verify_als_ctrllog_backup_level(void *se, void *lex, void *def);
status_t sql_verify_als_compress_algo(void *se, void *lex, void *def);
status_t sql_verify_als_compress_buf_size(void *se, void *lex, void *def);
status_t sql_verify_als_page_clean_wait_timeout(void *se, void *lex, void *def);
status_t sql_verify_als_auto_index_rec(void *se, void *lex, void *def);
status_t sql_verify_als_index_rec_percent(void *se, void *lex, void *def);
status_t sql_verify_als_idx_recycle_size(void *se, void *lex, void *def);
status_t sql_verify_als_idx_recycle_reuse(void *se, void *lex, void *def);
status_t sql_verify_als_idx_rebuild_keep_storage(void *se, void *lex, void *def);
status_t sql_verify_als_force_index_rec(void *se, void *lex, void *def);
status_t sql_verify_als_private_row_locks(void *se, void *lex, void *def);
status_t sql_verify_als_lsnd_wait_time(void *se, void *lex, void *def);
status_t sql_verify_als_idx_auto_rebuild_start_time(void *se, void *lex, void *def);
status_t sql_verify_als_page_clean_mode(void *se, void *lex, void *def);
status_t sql_verify_als_batch_flush_capacity(void *se, void *lex, void *def);
// kernel params notify
status_t sql_notify_als_bkup_log_parallel(void *se, void *item, char *value);
status_t sql_verify_als_idx_auto_rebuild(void *se, void *item, char *value);
status_t sql_notify_als_ini_trans(void *se, void *item, char *value);
status_t sql_notify_als_active_undo_segs(void *se, void *item, char *value);
status_t sql_notify_als_auton_trans_segs(void *se, void *item, char *value);
status_t sql_notify_als_undo_auton_bind_own_seg(void *se, void *item, char *value);
status_t sql_notify_als_undo_auto_shrink(void *se, void *item, char *value);
status_t sql_notify_als_undo_auto_shrink_passive(void *se, void *item, char *value);
status_t sql_notify_als_undo_prefetch_pages(void *se, void *item, char *value);
status_t sql_notify_als_page_clean_time(void *se, void *item, char *value);
status_t sql_notify_als_page_clean_ratio(void *se, void *item, char *value);
status_t sql_notify_als_lru_search_threshold(void *se, void *item, char *value);
status_t sql_notify_als_delay_cleanout(void *se, void *item, char *value);
status_t sql_notify_als_default_exts(void *se, void *item, char *value);
status_t sql_notify_als_table_spc_alarm_threshold(void *se, void *item, char *value);
status_t sql_notify_als_undo_alarm_threshold(void *se, void *item, char *value);
status_t sql_notify_als_txn_undo_alarm_threshold(void *se, void *item, char *value);
status_t sql_notify_als_systime_growth_threshold(void *se, void *item, char *value);
status_t sql_notify_als_vmp_caches(void *se, void *item, char *value);
status_t sql_notify_als_vm_func_stack_cnt(void *se, void *item, char *value);
status_t sql_notify_als_ckpt_period(void *se, void *item, char *value);
status_t sql_notify_als_ckpt_pages(void *se, void *item, char *value);
status_t sql_notify_als_ckpt_io_capacity(void *se, void *item, char *value);
status_t sql_notify_als_ckpt_merge_io(void *se, void *item, char *value);
status_t sql_notify_als_commit_logging(void *se, void *item, char *value);
status_t sql_notify_als_commit_wait_logging(void *se, void *item, char *value);
status_t sql_notify_als_rcy_sleep_interval(void *se, void *item, char *value);
status_t sql_notify_als_cpu_node_bind(void *se, void *item, char *value);
status_t sql_notify_als_enable_qos(void *se, void *item, char *value);
status_t sql_notify_als_qos_ctrl(void *se, void *item, char *value);
status_t sql_notify_als_qos_sleep_time(void *se, void *item, char *value);
status_t sql_notify_als_qos_random_range(void *se, void *item, char *value);
status_t sql_notify_als_disable_soft_parse(void *se, void *item, char *value);
status_t sql_notify_als_db_isolevel(void *se, void *item, char *value);
status_t sql_notify_als_db_isolevel_value(void *se, void *item, char *value);
status_t sql_notify_als_undo_retention_time(void *se, void *item, char *value);
status_t sql_notify_als_undo_reserve_size(void *se, void *item, char *value);
status_t sql_notify_als_index_defer_recycle_time(void *se, void *item, char *value);
status_t sql_notify_als_xa_suspend_timeout(void *se, void *item, char *value);
status_t sql_notify_als_lock_wait_timeout(void *se, void *item, char *value);
status_t sql_notify_als_double_write(void *se, void *item, char *value);
status_t sql_notify_als_build_timeout(void *se, void *item, char *value);
status_t sql_notify_als_repl_timeout(void *se, void *item, char *value);
status_t sql_notify_als_repl_max_pkg_size(void *se, void *item, char *value);
status_t sql_notify_als_repl_host(void *se, void *item, char *value);
status_t sql_notify_als_rcy_check_pcn(void *se, void *item, char *value);
status_t sql_notify_als_local_tmp_tbl_enabled(void *se, void *item, char *value);
status_t sql_notify_als_upper_case_table_names(void *se, void *item, char *value);
status_t sql_notify_als_cbo(void *se, void *item, char *value);
status_t sql_notify_als_resource_limit(void *se, void *item, char *value);
status_t sql_notify_drop_nologging(void *se, void *item, char *value);
status_t sql_notify_recyclebin(void *se, void *item, char *value);
status_t sql_notify_als_auto_inherit(void *se, void *item, char *value);
status_t sql_notify_als_idx_duplicate(void *se, void *item, char *value);
status_t sql_notify_idx_key_len_check(void *se, void *item, char *value);
status_t sql_notify_als_tc_level(void *se, void *item, char *value);
status_t sql_notify_als_ddl_lock_timeout(void *se, void *item, char *value);
status_t sql_notify_als_ashrink_wait_time(void *se, void *item, char *value);
status_t sql_notify_als_shrink_wait_recycled_pages(void *se, void *item, char *value);
status_t sql_notify_als_temptable_support_batch(void *se, void *item, char *value);
status_t sql_notify_als_small_table_sampling_threshold(void *se, void *item, char *value);
status_t sql_notify_als_block_repair_enable(void *se, void *item, char *value);
status_t sql_notify_als_block_repair_timeout(void *se, void *item, char *value);
status_t sql_notify_als_nbu_backup_timeout(void *se, void *item, char *value);
status_t sql_notify_degrade_search(void *se, void *item, char *value);
status_t sql_notify_als_lob_reuse_threshold(void *se, void *item, char *value);
status_t sql_notify_build_datafile_paral(void *se, void *item, char *value);
status_t sql_notify_init_lockpool_pages(void *se, void *item, char *value);
status_t sql_notify_build_datafile_prealloc(void *se, void *item, char *value);
status_t sql_notify_ctrllog_backup_level(void *se, void *item, char *value);
status_t sql_notify_als_compress_algo(void *se, void *item, char *value);
status_t sql_notify_als_compress_buf_size(void *se, void *item, char *value);
status_t sql_notify_als_compress_enable_buf(void *se, void *item, char *value);
status_t sql_notify_als_auto_idx_recycle(void *se, void *item, char *value);
status_t sql_notify_als_idx_recycle_percent(void *se, void *item, char *value);
status_t sql_notify_als_idx_recycle_size(void *se, void *item, char *value);
status_t sql_notify_als_force_idx_recycle(void *se, void *item, char *value);
status_t sql_notify_als_idx_recycle_reuse(void *se, void *item, char *value);
status_t sql_notify_als_idx_rebuild_keep_storage(void *se, void *item, char *value);
status_t sql_notify_als_lsnd_wait_time(void *se, void *item, char *value);
status_t sql_notify_als_private_row_locks(void *se, void *item, char *value);
status_t sql_notify_als_private_key_locks(void *se, void *item, char *value);
status_t sql_notify_als_page_clean_wait_timeout(void *se, void *item, char *value);
status_t sql_notify_als_ckpt_wait_timeout(void *se, void *item, char *value);
status_t sql_notify_password_verify(void *se, void *item, char *value);
status_t sql_notify_io_record(void *se, void *item, char *value);
status_t sql_notify_als_page_clean_mode(void *se, void *item, char *value);
#ifdef __cplusplus
}
#endif

#endif
