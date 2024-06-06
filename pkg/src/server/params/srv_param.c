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
 * srv_param.c
 *
 *
 * IDENTIFICATION
 * src/server/params/srv_param.c
 *
 * -------------------------------------------------------------------------
 */
#include "srv_module.h"
#include "srv_param.h"
#include "srv_instance.h"
#include "srv_param_common.h"
#include "set_kernel.h"
#include "set_server.h"
#include "set_others.h"
#include "srv_params_raft_and_log.h"
#include "ddl_parser.h"

#ifdef __cplusplus
extern "C" {
#endif

// CAUTION !!! if add/del/modify g_parameter in srv_param.c,please reorder the id in srv_param_def.h
config_item_t g_parameters[] = {
    // name (30B)                    isdefault attr  defaultvalue     value runtime_value description range datatype
    // comment
    // -------------                 --------- ----  ------------     ----- ------------- ----------- ----- --------
    // -------
    { "LSNR_ADDR", CT_TRUE, ATTR_NONE, "127.0.0.1", NULL, NULL, "-", "-", "CT_TYPE_VARCHAR", NULL, PARAM_LSNR_ADDR,
      EFFECT_REBOOT, CFG_INS, sql_verify_als_ip, NULL, NULL, NULL },
    { "LSNR_PORT", CT_TRUE, ATTR_NONE, "1611", NULL, NULL, "-", "[1024,65535]", "CT_TYPE_INTEGER", NULL,
      PARAM_LSNR_PORT, EFFECT_REBOOT, CFG_INS, sql_verify_als_port, NULL, NULL, NULL },
    { "WORKER_THREADS", CT_TRUE, ATTR_HIDDEN, "100", NULL, NULL, "-", "[0,10000)", "CT_TYPE_INTEGER", NULL,
      PARAM_WORKER_THREADS, EFFECT_REBOOT, CFG_INS, sql_verify_als_worker_threads, NULL, NULL, NULL },
    { "OPTIMIZED_WORKER_THREADS", CT_TRUE, ATTR_NONE, "100", NULL, NULL, "-", "[2,10000]", "CT_TYPE_INTEGER", NULL,
      PARAM_OPTIMIZED_WORKER_THREADS, EFFECT_REBOOT, CFG_INS, sql_verify_als_optimized_worker_threads, NULL, NULL,
      NULL },
    { "MAX_WORKER_THREADS", CT_TRUE, ATTR_NONE, "100", NULL, NULL, "-", "[2,10000]", "CT_TYPE_INTEGER", NULL,
      PARAM_MAX_WORKER_THREADS, EFFECT_REBOOT, CFG_INS, sql_verify_als_max_worker_threads, NULL, NULL, NULL },
    { "REACTOR_THREADS", CT_TRUE, ATTR_NONE, "2", NULL, NULL, "-", "[1,10000]", "CT_TYPE_INTEGER", NULL,
      PARAM_REACTOR_THREADS, EFFECT_REBOOT, CFG_INS, sql_verify_als_reactor_threads, NULL, NULL, NULL },
    { "SQL_COMPAT", CT_TRUE, ATTR_NONE, "CTDB", NULL, NULL, "-", "CTDB", "CT_TYPE_VARCHAR", NULL, PARAM_SQL_COMPAT,
      EFFECT_REBOOT, CFG_INS, sql_verify_als_sql_compat, sql_notify_als_sql_compat, sql_notify_als_sql_compat, NULL },
    { "DATA_BUFFER_SIZE", CT_TRUE, ATTR_NONE, "128M", NULL, NULL, "-", "[64M,32T]", "CT_TYPE_INTEGER", NULL,
      PARAM_DATA_BUFFER_SIZE, EFFECT_REBOOT, CFG_INS, sql_verify_als_data_buffer_size, NULL, NULL, NULL },
    { "VARIANT_MEMORY_AREA_SIZE", CT_TRUE, ATTR_NONE, "32M", NULL, NULL, "-", "[4M,32T]", "CT_TYPE_INTEGER", NULL,
      PARAM_VMA_SIZE, EFFECT_REBOOT, CFG_INS, sql_verify_als_vma_size, NULL, NULL, NULL },
    { "LARGE_VARIANT_MEMORY_AREA_SIZE", CT_TRUE, ATTR_NONE, "32M", NULL, NULL, "-", "[1M,32T]", "CT_TYPE_INTEGER", NULL,
      PARAM_LARGE_VMA_SIZE, EFFECT_REBOOT, CFG_INS, sql_verify_als_large_vma_size, NULL, NULL, NULL },
    { "_VMP_CACHES_EACH_SESSION", CT_TRUE, ATTR_NONE, "8", NULL, NULL, "-", "[0,4294967295]", "CT_TYPE_UINT32", NULL,
      PARAM__VMP_CACHES_EACH_SESS, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_uint32, sql_notify_als_vmp_caches, NULL,
      NULL },
    { "_VMA_MEM_CHECK", CT_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_VMA_MEM_CHECK, EFFECT_REBOOT, CFG_INS, sql_verify_als_bool, sql_notify_als_bool, sql_notify_als_bool,
      NULL },
    { "PMA_BUFFER_SIZE", CT_TRUE, ATTR_NONE, "128M", NULL, NULL, "-", "[0,1T]", "CT_TYPE_INTEGER", NULL, PARAM_PMA_SIZE,
      EFFECT_REBOOT, CFG_INS, sql_verify_als_pma_buf_size, NULL, NULL, NULL },
    { "HASH_AREA_SIZE", CT_TRUE, ATTR_NONE, "4M", NULL, NULL, "-", "[0,1T]", "CT_TYPE_INTEGER", NULL,
      PARAM_HASH_AREA_SIZE, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_hash_area_size, sql_notify_als_hash_area_size,
      NULL, NULL },
    { "SHARED_POOL_SIZE", CT_TRUE, ATTR_NONE, "192M", NULL, NULL, "-", "[82M,32T]", "CT_TYPE_INTEGER", NULL,
      PARAM_SHARED_POOL_SIZE, EFFECT_REBOOT, CFG_INS, sql_verify_als_shared_pool_size, NULL, NULL, NULL },
    { "_SQL_POOL_FACTOR", CT_TRUE, ATTR_NONE, "0.5", NULL, NULL, "-", "[0.001,0.999]", "CT_TYPE_REAL", NULL,
      PARAM_SQL_POOL_FACTOR, EFFECT_REBOOT, CFG_INS, sql_verify_als_sql_pool_fat, NULL, NULL, NULL },
    { "LARGE_POOL_SIZE", CT_TRUE, ATTR_NONE, "32M", NULL, NULL, "-", "[4M,32T]", "CT_TYPE_INTEGER", NULL,
      PARAM_LARGE_POOL_SIZE, EFFECT_REBOOT, CFG_INS, sql_verify_als_large_pool_size, NULL, NULL, NULL },
    { "LOG_BUFFER_SIZE", CT_TRUE, ATTR_NONE, "4M", NULL, NULL, "-", "[1M,110M]", "CT_TYPE_INTEGER", NULL,
      PARAM_LOG_BUFFER_SIZE, EFFECT_REBOOT, CFG_INS, sql_verify_als_log_buffer_size, NULL, NULL, NULL },
    { "LOG_BUFFER_COUNT", CT_TRUE, ATTR_NONE, "4", NULL, NULL, "-", "(0,16]", "CT_TYPE_INTEGER", NULL,
      PARAM_LOG_BUFFER_COUNT, EFFECT_REBOOT, CFG_INS, sql_verify_als_log_buffer_count, NULL, NULL, NULL },
    { "TEMP_BUFFER_SIZE", CT_TRUE, ATTR_NONE, "32M", NULL, NULL, "-", "[32M,4T]", "CT_TYPE_INTEGER", NULL,
      PARAM_TEMP_BUFFER_SIZE, EFFECT_REBOOT, CFG_INS, sql_verify_als_temp_buffer_size, NULL, NULL, NULL },
    { "USE_LARGE_PAGES", CT_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_USE_LARGE_PAGES, EFFECT_REBOOT, CFG_INS, sql_verify_als_bool, sql_notify_als_bool, sql_notify_als_bool,
      NULL },
    { "USE_NATIVE_DATATYPE", CT_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_USE_NATIVE_DATATYPE, EFFECT_REBOOT, CFG_INS, sql_verify_als_bool, sql_notify_als_bool, sql_notify_als_bool,
      NULL },
    { "JOB_THREADS", CT_TRUE, ATTR_NONE, "100", NULL, NULL, "-", "[0,200]", "CT_TYPE_INTEGER", NULL,
      PARAM_JOB_QUEUE_PROCESSES, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_job_queue_processes, NULL, NULL,
      "JOB_QUEUE_PROCESSES" },
    { "CR_POOL_SIZE", CT_TRUE, ATTR_NONE, "32M", NULL, NULL, "-", "[16M,32T]", "CT_TYPE_INTEGER", NULL,
      PARAM_CR_POOL_SIZE, EFFECT_REBOOT, CFG_INS, sql_verify_als_cr_pool_size, NULL, NULL, NULL },
    { "CR_POOL_COUNT", CT_TRUE, ATTR_NONE, "1", NULL, NULL, "-", "[1,256]", "CT_TYPE_INTEGER", NULL,
      PARAM_CR_POOL_COUNT, EFFECT_REBOOT, CFG_INS, sql_verify_als_cr_pool_count, NULL, NULL, NULL },
    { "DEFAULT_TABLESPACE_TYPE", CT_TRUE, ATTR_NONE, "NORMAL", NULL, NULL, "-", "NORMAL,BITMAP", "CT_TYPE_VARCHAR",
      NULL, PARAM_DEFAULT_SPACE_TYPE, EFFECT_REBOOT, CFG_INS, sql_verify_als_default_space_type, NULL, NULL, NULL },
    { "BUFFER_PAGE_CLEAN_PERIOD", CT_TRUE, ATTR_NONE, "0", NULL, NULL, "-", "[0,4294967295]", "CT_TYPE_INTEGER", NULL,
      PARAM_BUFFER_PAGE_CLEAN_PERIOD, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_page_clean_period,
      sql_notify_als_page_clean_period, NULL, NULL },
    { "BUFFER_LRU_SEARCH_THRE", CT_TRUE, ATTR_NONE, "60", NULL, NULL, "-", "[1,100]", "CT_TYPE_INTEGER", NULL,
      PARAM_BUFFER_LRU_SEARCH_THRE, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_lru_search_threshold,
      sql_notify_als_lru_search_threshold, NULL, NULL },
    { "BUFFER_PAGE_CLEAN_RATIO", CT_TRUE, ATTR_NONE, "0.4", NULL, NULL, "-", "[0.0001,1]", "CT_TYPE_REAL", NULL,
      PARAM_BUFFER_PAGE_CLEAN_RATIO, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_page_clean_ratio,
      sql_notify_als_page_clean_ratio, NULL, NULL },
    { "_BUFFER_PAGE_CLEAN_WAIT_TIMEOUT", CT_TRUE, ATTR_NONE, "0", NULL, NULL, "-", "[0,4294967295]", "CT_TYPE_INTEGER",
      NULL, PARAM_BUFFER_PAGE_CLEAN_WAIT_TIMEOUT, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_page_clean_wait_timeout,
      sql_notify_als_page_clean_wait_timeout, NULL, NULL },
    { "_CHECKPOINT_TIMED_TASK_DELAY", CT_TRUE, ATTR_NONE, "100", NULL, NULL, "-", "[0,4294967295]", "CT_TYPE_INTEGER",
      NULL, PARAM_CKPT_WAIT_TIMEOUT, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_page_clean_wait_timeout,
      sql_notify_als_ckpt_wait_timeout, NULL, NULL },
    // hidden parameter
    { "_SPIN_COUNT", CT_TRUE, ATTR_NONE, "1000", NULL, NULL, "-", "[0,4294967295]", "CT_TYPE_INTEGER", NULL,
      PARAM__SPIN_COUNT, EFFECT_REBOOT, CFG_INS, sql_verify_als_uint32, NULL, NULL, NULL },
    { "_ENABLE_QOS", CT_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM__ENABLE_QOS, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_enable_qos,
      sql_notify_als_bool, NULL },
    { "_QOS_CTRL_FACTOR", CT_TRUE, ATTR_NONE, "0.75", NULL, NULL, "-", "(0,5]", "CT_TYPE_REAL", NULL,
      PARAM__QOS_CTRL_FACTOR, EFFECT_REBOOT, CFG_INS, sql_verify_als_qos_ctrl_fat, sql_notify_als_qos_ctrl, NULL,
      NULL },
    { "_QOS_SLEEP_TIME", CT_TRUE, ATTR_NONE, "20", NULL, NULL, "-", "[1,4294967295]", "CT_TYPE_INTEGER", NULL,
      PARAM__QOS_SLEEP_TIME, EFFECT_REBOOT, CFG_INS, sql_verify_als_qos_slee_time, sql_notify_als_qos_sleep_time, NULL,
      NULL },
    { "_QOS_RANDOM_RANGE", CT_TRUE, ATTR_NONE, "64", NULL, NULL, "-", "[1,4294967295]", "CT_TYPE_INTEGER", NULL,
      PARAM__QOS_RANDOM_RANGE, EFFECT_REBOOT, CFG_INS, sql_verify_als_qos_rand_range, sql_notify_als_qos_random_range,
      NULL, NULL },
    { "_INDEX_BUFFER_SIZE", CT_TRUE, ATTR_NONE, "8M", NULL, NULL, "-", "[16K,32T]", "CT_TYPE_INTEGER", NULL,
      PARAM__INDEX_BUFFER_SIZE, EFFECT_REBOOT, CFG_INS, sql_verify_als_index_buffer_size, NULL, NULL, NULL },
    { "_INDEX_AUTO_REBUILD", CT_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "_", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM__INDEX_AUTO_REBUILD, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_index_auto_rebuild,
      NULL, NULL },
    { "_INDEX_AUTO_REBUILD_START_TIME", CT_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "CT_TYPE_VARCHAR", NULL,
      PARAM__INDEX_AUTO_REBUILD_START_TIME, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_index_auto_rebuild_start_time,
      NULL, NULL, NULL },
    { "_AUTO_INDEX_RECYCLE", CT_TRUE, ATTR_NONE, "ON", NULL, NULL, "_", "OFF,ON", "CT_TYPE_VARCHAR", NULL,
      PARAM__AUTO_INDEX_RECYCLE, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_auto_index_recycle,
      sql_notify_als_auto_index_recycle, NULL, NULL },
    { "_INDEX_RECYCLE_PERCENT", CT_TRUE, ATTR_NONE, "20", NULL, NULL, "-", "[0,100]", "CT_TYPE_INTEGER", NULL,
      PARAM__INDEX_RECYCLE_PERCENT, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_index_recycle_percent,
      sql_notify_als_index_recycle_percent, NULL, NULL },
    { "_INDEX_RECYCLE_SIZE", CT_TRUE, ATTR_NONE, "2G", NULL, NULL, "_", "[4M,1T]", "CT_TYPE_INTEGER", NULL,
      PARAM__INDEX_RECYCLE_SIZE, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_index_recycle_size,
      sql_notify_als_index_recycle_size, NULL, NULL },
    { "_FORCE_INDEX_RECYCLE", CT_TRUE, ATTR_NONE, "14400", NULL, NULL, "_", "[0,172800]", "CT_TYPE_INTEGER", NULL,
      PARAM__FORCE_INDEX_RECYCLE, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_force_index_recycle,
      sql_notify_als_force_index_recycle, NULL, NULL },
    { "_INDEX_RECYCLE_REUSE", CT_TRUE, ATTR_NONE, "512", NULL, NULL, "_", "[0,172800000]", "CT_TYPE_INTEGER", NULL,
      PARAM__INDEX_RECYCLE_REUSE, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_index_recycle_reuse,
      sql_notify_als_index_recycle_reuse, NULL, NULL },
    { "_INDEX_REBUILD_KEEP_STORAGE", CT_TRUE, ATTR_NONE, "43200", NULL, NULL, "_", "[0,172800]", "CT_TYPE_INTEGER",
      NULL, PARAM__INDEX_REBUILD_KEEP_STORAGE, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_index_rebuild_keep_storage,
      sql_notify_als_index_rebuild_keep_storage, NULL, NULL },
    { "_DOUBLEWRITE", CT_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM__DOUBLEWRITE, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_double_write,
      sql_notify_als_bool, NULL },
    { "_THREAD_STACK_SIZE", CT_TRUE, ATTR_NONE, "512K", NULL, NULL, "-", "[256K,7.5M]", "CT_TYPE_INTEGER", NULL,
      PARAM__THREAD_STACK_SIZE, EFFECT_REBOOT, CFG_INS, sql_verify_als_thread_stack_size, NULL, NULL, NULL },
    { "_BLACKBOX_STACK_DEPTH", CT_TRUE, ATTR_NONE, "30", NULL, NULL, "-", "[2, 40]", "CT_TYPE_INTEGER", NULL,
      PARAM__BLACK_BOX_DEPTH, EFFECT_REBOOT, CFG_INS, sql_verify_als_black_box_depth, NULL, NULL, NULL },
    { "_HINT_FORCE", CT_TRUE, ATTR_NONE, "0", NULL, NULL, "-",
      "0 disables, [1,2,4,8]=[ORDERED,USE_NL,USE_MERGE,USE_HASH]", "CT_TYPE_INTEGER", NULL, PARAM__FORCE_HINT,
      EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_uint32, sql_notify_als__hint_force, NULL, NULL },
    { "_RCY_CHECK_PCN", CT_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM__RCY_CHECK_PCN, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_rcy_check_pcn,
      sql_notify_als_bool, NULL },
    { "_SGA_CORE_DUMP_CONFIG", CT_TRUE, ATTR_NONE, "0", NULL, NULL, "-", "[0,65535]", "CT_TYPE_INTEGER", NULL,
      PARAM__SGA_CORE_DUMP_CONFIG, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_sga_core_dump_config,
      sql_notify_als_sga_core_dump_config, NULL, NULL },
    { "_MAX_RM_COUNT", CT_TRUE, ATTR_NONE, "0", NULL, NULL, "-", "[0,24480]", "CT_TYPE_INTEGER", NULL,
      PARAM__MAX_RM_COUNT, EFFECT_REBOOT, CFG_INS, sql_verify_als_max_rm_count, NULL, NULL, NULL },
    { "_SMALL_TABLE_SAMPLING_THRESHOLD", CT_TRUE, ATTR_NONE, "10000", NULL, NULL, "-", "[0,100000]", "CT_TYPE_INTEGER",
      NULL, PARAM__SMALL_TABLE_SAMPLING_THRESHOLD, EFFECT_IMMEDIATELY, CFG_INS,
      sql_verify_als_small_table_sampling_threshold, sql_notify_als_small_table_sampling_threshold, NULL, NULL },
    { "_ASHRINK_WAIT_TIME", CT_TRUE, ATTR_NONE, "21600", NULL, NULL, "-", "[1,172800]", "CT_TYPE_INTEGER", NULL,
      PARAM__ASHRINK_WAIT_TIME, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_ashrink_wait_time,
      sql_notify_als_ashrink_wait_time, NULL, NULL },
    { "_SHRINK_WAIT_RECYCLED_PAGES", CT_TRUE, ATTR_NONE, "1024", NULL, NULL, "-", "[0,13107200]", "CT_TYPE_INTEGER",
      NULL, PARAM__SHRINK_WAIT_RECYCLED_PAGES, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_shrink_wait_recycled_pages,
      sql_notify_als_shrink_wait_recycled_pages, NULL, NULL },
    { "_TEMPTABLE_SUPPORT_BATCH_INSERT", CT_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN",
      NULL, PARAM__TEMPTABLE_SUPPORT_BATCH_INSERT, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool,
      sql_notify_als_temptable_support_batch, sql_notify_als_bool, NULL },
    /* *************************************************************************
    agent parameters,
    private area size = (_AGENT_STACK_SIZE
    + PLOG_PAGES * PAGE_SIZE(8K) + _VARIANT_AREA_SIZE + _INIT_SQL_CURSORS * 1K
    + _INIT_TABLE_CURSORS * (2 * PAGE_SIZE(8K) + 12K))
    if page size is 8K, about 2M
    ************************************************************************* */
    { "_AGENT_STACK_SIZE", CT_TRUE, ATTR_NONE, "2M", NULL, NULL, "-", "[512K,4G)", "CT_TYPE_INTEGER", NULL,
      PARAM__AGENT_STACK_SIZE, EFFECT_REBOOT, CFG_INS, sql_verify_als_stack_size, NULL, NULL, NULL },
    { "_LOB_MAX_EXEC_SIZE", CT_TRUE, ATTR_NONE, "65534", NULL, NULL, "-", "[0,4G)", "CT_TYPE_INTEGER", NULL,
      PARAM__LOB_MAX_EXEC_SIZE, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_lob_max_exec_size, NULL, NULL, NULL },
    // parameter/scan_range variants for stmt which have pending result set
    { "_VARIANT_AREA_SIZE", CT_TRUE, ATTR_NONE, "256K", NULL, NULL, "-", "[256K,64M]", "CT_TYPE_INTEGER", NULL,
      PARAM__VARIANT_AREA_SIZE, EFFECT_REBOOT, CFG_INS, sql_verify_als_variant_size, NULL, NULL, NULL },
    // cached knl_cursor
    { "_INIT_CURSORS", CT_TRUE, ATTR_NONE, "32", NULL, NULL, "-", "[0,256]", "CT_TYPE_INTEGER", NULL,
      PARAM__INIT_CURSORS, EFFECT_REBOOT, CFG_INS, sql_verify_als_init_cursors, NULL, NULL, NULL },
    { "_DISABLE_SOFT_PARSE", CT_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM__DISABLE_SOFT_PARSE, EFFECT_REBOOT, CFG_INS, sql_verify_als_bool, sql_notify_als_disable_soft_parse,
      sql_notify_als_bool, NULL },
    /* limitations */
    { "SESSIONS", CT_TRUE, ATTR_NONE, "200", NULL, NULL, "-", "[59,19380]", "CT_TYPE_INTEGER", NULL, PARAM_SESSIONS,
      EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_sessions, NULL, NULL, NULL },
    { "KNL_AUTONOMOUS_SESSIONS", CT_TRUE, ATTR_NONE, "8", NULL, NULL, "-", "(0,256]", "CT_TYPE_INTEGER", NULL,
      PARAM_KNL_AUTONOMOUS_SESSIONS, EFFECT_REBOOT, CFG_INS, sql_verify_als_autonomous_sessions, NULL, NULL, NULL },
    { "AUTONOMOUS_SESSIONS", CT_TRUE, ATTR_NONE, "8", NULL, NULL, "-", "(0,256]", "CT_TYPE_INTEGER", NULL,
      PARAM_AUTONOMOUS_SESSIONS, EFFECT_REBOOT, CFG_INS, sql_verify_als_autonomous_sessions, NULL, NULL, NULL },
    { "SUPER_USER_RESERVED_SESSIONS", CT_TRUE, ATTR_NONE, "10", NULL, NULL, "-", "[1,32]", "CT_TYPE_INTEGER", NULL,
      PARAM_SUPER_USER_RESERVED_SESSIONS, EFFECT_REBOOT, CFG_INS, sql_verify_super_user_sessions, NULL },
    { "NORMAL_USER_RESERVED_SESSIONS_FACTOR", CT_TRUE, ATTR_NONE, "1", NULL, NULL, "-", "[0,1]", "CT_TYPE_REAL", NULL,
      PARAM_NORMAL_USER_RESERVED_SESSION_FACTOR, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_normal_emerge_sess_factor,
      sql_notify_als_normal_emerge_sess_factor, NULL, NULL },
    // same with oracle, max statements per session
    { "OPEN_CURSORS", CT_TRUE, ATTR_NONE, "2000", NULL, NULL, "-", "[1,16384]", "CT_TYPE_INTEGER", NULL,
      PARAM_OPEN_CURSORS, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_open_curs, sql_notify_als_open_curs, NULL, NULL },
    { "_PREFETCH_ROWS", CT_TRUE, ATTR_NONE, "100", NULL, NULL, "-", "[1,4294967295]", "CT_TYPE_UINT32", NULL,
      PARAM_PREFETCH_ROWS, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_prefetch_rows, sql_notify_als_prefetch_rows,
      NULL, NULL },
    /* database */
    { "PAGE_SIZE", CT_TRUE, ATTR_READONLY, "8K", NULL, NULL, "-", "8K,16K,32K", "CT_TYPE_VARCHAR", NULL,
      PARAM_PAGE_SIZE, EFFECT_REBOOT, CFG_DB, sql_verify_als_page_size, NULL, NULL, NULL }, // read only, must be same
                                                                                            // with the page size which
                                                                                            // d
    { "COMMIT_MODE", CT_TRUE, ATTR_NONE, "IMMEDIATE", NULL, NULL, "-", "BATCH,IMMEDIATE", "CT_TYPE_VARCHAR", NULL,
      PARAM_COMMIT_LOGGING, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_commit_logging, sql_notify_als_commit_mode,
      NULL, "COMMIT_LOGGING" }, // same with oracle, IMMEDIATE | BATCH
    { "COMMIT_WAIT_LOGGING", CT_TRUE, ATTR_NONE, "WAIT", NULL, NULL, "-", "WAIT,NOWAIT", "CT_TYPE_VARCHAR", NULL,
      PARAM_COMMIT_WAIT, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_commit_wait, sql_notify_als_commit_wait_logging,
      NULL, "COMMIT_WAIT" }, // same with oracle, WAIT | NOWAIT
    { "CONTROL_FILES", CT_TRUE, ATTR_READONLY, "", NULL, NULL, "-", "-", "CT_TYPE_VARCHAR", NULL, PARAM_CONTROL_FILES,
      EFFECT_REBOOT, CFG_DB, sql_verify_als_comm, NULL, NULL, NULL },
    { "MYSQL_METADATA_IN_CANTIAN", CT_TRUE, ATTR_READONLY, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN",
      NULL, PARAM_MYSQL_METADATA_IN_CANTIAN, EFFECT_REBOOT, CFG_DB, sql_verify_als_bool, sql_notify_als_bool,
      sql_notify_als_bool, NULL },
    { "KMC_KEY_FILES", CT_TRUE, ATTR_READONLY, "", NULL, NULL, "-", "-", "CT_TYPE_VARCHAR", NULL, PARAM_KMC_KEY_FILES,
      EFFECT_REBOOT, CFG_DB, sql_verify_als_comm, NULL, NULL, NULL },
    { "PAGE_CHECKSUM", CT_TRUE, ATTR_NONE, "TYPICAL", NULL, NULL, "-", "OFF,TYPICAL,FULL", "CT_TYPE_VARCHAR", NULL,
      PARAM_DB_BLOCK_CHECKSUM, EFFECT_REBOOT, CFG_INS, sql_verify_als_db_block_checksum, NULL, NULL,
      "DB_BLOCK_CHECKSUM" }, // OFF | TYPICAL | FULL
    { "DB_ISOLEVEL", CT_TRUE, ATTR_NONE, "RC", NULL, NULL, "-", "RC,CC", "CT_TYPE_VARCHAR", NULL, PARAM_DB_ISOLEVEL,
      EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_db_isolevel, sql_notify_als_db_isolevel,
      sql_notify_als_db_isolevel_value, NULL },
    { "_SERIALIZED_COMMIT", CT_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM__SERIALIZED_COMMIT, EFFECT_REBOOT, CFG_INS, sql_verify_als_bool, sql_notify_als_bool, sql_notify_als_bool,
      NULL },
    { "ARCHIVE_CONFIG", CT_TRUE, ATTR_READONLY, "SEND,RECEIVE,NODG_CONFIG", NULL, NULL, "-", "-", "CT_TYPE_VARCHAR",
      NULL, PARAM_LOG_ARCHIVE_CONFIG, EFFECT_REBOOT, CFG_DB, sql_verify_als_log_archive_config, NULL, NULL,
      "LOG_ARCHIVE_CONFIG" },
    { "ARCHIVE_DEST_1", CT_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "CT_TYPE_VARCHAR", NULL, PARAM_LOG_ARCHIVE_DEST_1,
      EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_log_archive_dest_n, sql_notify_als_archive_dest_n, NULL,
      "LOG_ARCHIVE_DEST_1" },
    { "ARCHIVE_DEST_2", CT_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "CT_TYPE_VARCHAR", NULL, PARAM_LOG_ARCHIVE_DEST_2,
      EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_log_archive_dest_n, sql_notify_als_archive_dest_n, NULL,
      "LOG_ARCHIVE_DEST_2" },
    { "ARCHIVE_DEST_3", CT_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "CT_TYPE_VARCHAR", NULL, PARAM_LOG_ARCHIVE_DEST_3,
      EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_log_archive_dest_n, sql_notify_als_archive_dest_n, NULL,
      "LOG_ARCHIVE_DEST_3" },
    { "ARCHIVE_DEST_4", CT_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "CT_TYPE_VARCHAR", NULL, PARAM_LOG_ARCHIVE_DEST_4,
      EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_log_archive_dest_n, sql_notify_als_archive_dest_n, NULL,
      "LOG_ARCHIVE_DEST_4" },
    { "ARCHIVE_DEST_5", CT_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "CT_TYPE_VARCHAR", NULL, PARAM_LOG_ARCHIVE_DEST_5,
      EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_log_archive_dest_n, sql_notify_als_archive_dest_n, NULL,
      "LOG_ARCHIVE_DEST_5" },
    { "ARCHIVE_DEST_6", CT_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "CT_TYPE_VARCHAR", NULL, PARAM_LOG_ARCHIVE_DEST_6,
      EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_log_archive_dest_n, sql_notify_als_archive_dest_n, NULL,
      "LOG_ARCHIVE_DEST_6" },
    { "ARCHIVE_DEST_7", CT_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "CT_TYPE_VARCHAR", NULL, PARAM_LOG_ARCHIVE_DEST_7,
      EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_log_archive_dest_n, sql_notify_als_archive_dest_n, NULL,
      "LOG_ARCHIVE_DEST_7" },
    { "ARCHIVE_DEST_8", CT_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "CT_TYPE_VARCHAR", NULL, PARAM_LOG_ARCHIVE_DEST_8,
      EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_log_archive_dest_n, sql_notify_als_archive_dest_n, NULL,
      "LOG_ARCHIVE_DEST_8" },
    { "ARCHIVE_DEST_9", CT_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "CT_TYPE_VARCHAR", NULL, PARAM_LOG_ARCHIVE_DEST_9,
      EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_log_archive_dest_n, sql_notify_als_archive_dest_n, NULL,
      "LOG_ARCHIVE_DEST_9" },
    { "ARCHIVE_DEST_10", CT_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "CT_TYPE_VARCHAR", NULL,
      PARAM_LOG_ARCHIVE_DEST_10, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_log_archive_dest_n,
      sql_notify_als_archive_dest_n, NULL, "LOG_ARCHIVE_DEST_10" },
    { "ARCHIVE_DEST_STATE_1", CT_TRUE, ATTR_NONE, "ENABLE", NULL, NULL, "-", "ENABLE,DEFER,ALTERNATE",
      "CT_TYPE_VARCHAR", NULL, PARAM_LOG_ARCHIVE_DEST_STATE_1, EFFECT_IMMEDIATELY, CFG_INS,
      sql_verify_als_log_archive_dest_state_n, sql_notify_als_archive_dest_state_n, NULL, "LOG_ARCHIVE_DEST_STATE_1" },
    { "ARCHIVE_DEST_STATE_2", CT_TRUE, ATTR_NONE, "ENABLE", NULL, NULL, "-", "ENABLE,DEFER,ALTERNATE",
      "CT_TYPE_VARCHAR", NULL, PARAM_LOG_ARCHIVE_DEST_STATE_2, EFFECT_IMMEDIATELY, CFG_INS,
      sql_verify_als_log_archive_dest_state_n, sql_notify_als_archive_dest_state_n, NULL, "LOG_ARCHIVE_DEST_STATE_2" },
    { "ARCHIVE_DEST_STATE_3", CT_TRUE, ATTR_NONE, "ENABLE", NULL, NULL, "-", "ENABLE,DEFER,ALTERNATE",
      "CT_TYPE_VARCHAR", NULL, PARAM_LOG_ARCHIVE_DEST_STATE_3, EFFECT_IMMEDIATELY, CFG_INS,
      sql_verify_als_log_archive_dest_state_n, sql_notify_als_archive_dest_state_n, NULL, "LOG_ARCHIVE_DEST_STATE_3" },
    { "ARCHIVE_DEST_STATE_4", CT_TRUE, ATTR_NONE, "ENABLE", NULL, NULL, "-", "ENABLE,DEFER,ALTERNATE",
      "CT_TYPE_VARCHAR", NULL, PARAM_LOG_ARCHIVE_DEST_STATE_4, EFFECT_IMMEDIATELY, CFG_INS,
      sql_verify_als_log_archive_dest_state_n, sql_notify_als_archive_dest_state_n, NULL, "LOG_ARCHIVE_DEST_STATE_4" },
    { "ARCHIVE_DEST_STATE_5", CT_TRUE, ATTR_NONE, "ENABLE", NULL, NULL, "-", "ENABLE,DEFER,ALTERNATE",
      "CT_TYPE_VARCHAR", NULL, PARAM_LOG_ARCHIVE_DEST_STATE_5, EFFECT_IMMEDIATELY, CFG_INS,
      sql_verify_als_log_archive_dest_state_n, sql_notify_als_archive_dest_state_n, NULL, "LOG_ARCHIVE_DEST_STATE_5" },
    { "ARCHIVE_DEST_STATE_6", CT_TRUE, ATTR_NONE, "ENABLE", NULL, NULL, "-", "ENABLE,DEFER,ALTERNATE",
      "CT_TYPE_VARCHAR", NULL, PARAM_LOG_ARCHIVE_DEST_STATE_6, EFFECT_IMMEDIATELY, CFG_INS,
      sql_verify_als_log_archive_dest_state_n, sql_notify_als_archive_dest_state_n, NULL, "LOG_ARCHIVE_DEST_STATE_6" },
    { "ARCHIVE_DEST_STATE_7", CT_TRUE, ATTR_NONE, "ENABLE", NULL, NULL, "-", "ENABLE,DEFER,ALTERNATE",
      "CT_TYPE_VARCHAR", NULL, PARAM_LOG_ARCHIVE_DEST_STATE_7, EFFECT_IMMEDIATELY, CFG_INS,
      sql_verify_als_log_archive_dest_state_n, sql_notify_als_archive_dest_state_n, NULL, "LOG_ARCHIVE_DEST_STATE_7" },
    { "ARCHIVE_DEST_STATE_8", CT_TRUE, ATTR_NONE, "ENABLE", NULL, NULL, "-", "ENABLE,DEFER,ALTERNATE",
      "CT_TYPE_VARCHAR", NULL, PARAM_LOG_ARCHIVE_DEST_STATE_8, EFFECT_IMMEDIATELY, CFG_INS,
      sql_verify_als_log_archive_dest_state_n, sql_notify_als_archive_dest_state_n, NULL, "LOG_ARCHIVE_DEST_STATE_8" },
    { "ARCHIVE_DEST_STATE_9", CT_TRUE, ATTR_NONE, "ENABLE", NULL, NULL, "-", "ENABLE,DEFER,ALTERNATE",
      "CT_TYPE_VARCHAR", NULL, PARAM_LOG_ARCHIVE_DEST_STATE_9, EFFECT_IMMEDIATELY, CFG_INS,
      sql_verify_als_log_archive_dest_state_n, sql_notify_als_archive_dest_state_n, NULL, "LOG_ARCHIVE_DEST_STATE_9" },
    { "ARCHIVE_DEST_STATE_10", CT_TRUE, ATTR_NONE, "ENABLE", NULL, NULL, "-", "ENABLE,DEFER,ALTERNATE",
      "CT_TYPE_VARCHAR", NULL, PARAM_LOG_ARCHIVE_DEST_STATE_10, EFFECT_IMMEDIATELY, CFG_INS,
      sql_verify_als_log_archive_dest_state_n, sql_notify_als_archive_dest_state_n, NULL, "LOG_ARCHIVE_DEST_STATE_10" },
    { "ARCHIVE_FORMAT", CT_TRUE, ATTR_NONE, "arch_%t_%r_%s.arc", NULL, NULL, "-", "-", "CT_TYPE_VARCHAR", NULL,
      PARAM_LOG_ARCHIVE_FORMAT, EFFECT_REBOOT, CFG_INS, sql_verify_als_comm, sql_notify_als_archive_format, NULL,
      "LOG_ARCHIVE_FORMAT" },
    { "ARCHIVE_FORMAT_WITH_LSN", CT_TRUE, ATTR_NONE, "arch_%t_%r_%s_%d_%e.arc", NULL, NULL, "-", "-",
      "CT_TYPE_VARCHAR", NULL, PARAM_LOG_ARCHIVE_FORMAT_WITH_LSN, EFFECT_REBOOT, CFG_INS, sql_verify_als_comm,
      sql_notify_als_archive_format_with_lsn, NULL, "LOG_ARCHIVE_FORMAT"},
    { "ARCHIVE_MAX_THREADS", CT_TRUE, ATTR_READONLY, "1", NULL, NULL, "-", "-", "CT_TYPE_INTEGER", NULL,
      PARAM_LOG_ARCHIVE_MAX_PROCESSES, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_log_archive_max_min,
      sql_notify_als_archive_max_processes, NULL, "LOG_ARCHIVE_MAX_PROCESSES" },
    { "ARCHIVE_MIN_SUCCEED_DEST", CT_TRUE, ATTR_READONLY, "1", NULL, NULL, "-", "-", "CT_TYPE_INTEGER", NULL,
      PARAM_LOG_ARCHIVE_MIN_SUCCEED_DEST, EFFECT_REBOOT, CFG_INS, sql_verify_als_log_archive_max_min,
      sql_notify_als_archive_min_succeed, NULL, "LOG_ARCHIVE_MIN_SUCCEED_DEST" },
    { "ARCHIVE_TRACE", CT_TRUE, ATTR_READONLY, "0", NULL, NULL, "-", "-", "CT_TYPE_INTEGER", NULL,
      PARAM_LOG_ARCHIVE_TRACE, EFFECT_REBOOT, CFG_INS, sql_verify_als_uint32, sql_notify_als_archive_trace, NULL,
      "LOG_ARCHIVE_TRACE" },
    { "ENABLE_ARCH_COMPRESS", CT_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_ENABLE_ARCH_COMPRESS, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool,
      sql_notify_als_enable_arch_compressed, sql_notify_als_enable_arch_compressed, NULL },
    { "QUORUM_ANY", CT_TRUE, ATTR_NONE, "0", NULL, NULL, "_", "[0, 9]", "CT_TYPE_INTEGER", NULL, PARAM_QUORUM_ANY,
      EFFECT_REBOOT, CFG_INS, sql_verify_als_quorum_any, sql_notify_als_quorum_any, NULL, NULL },
    /* checkpoint */
    { "CHECKPOINT_PERIOD", CT_TRUE, ATTR_NONE, "300", NULL, NULL, "-", "[1,4294967295]", "CT_TYPE_INTEGER", NULL,
      PARAM_CHECKPOINT_TIMEOUT, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_checkpoint_timeout,
      sql_notify_als_ckpt_period, NULL, "CHECKPOINT_TIMEOUT" }, // awake checkpoint thread if interval reached
    { "CHECKPOINT_PAGES", CT_TRUE, ATTR_NONE, "100000", NULL, NULL, "-", "[1,4294967295]", "CT_TYPE_INTEGER", NULL,
      PARAM_CHECKPOINT_INTERVAL, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_checkpoint_interval,
      sql_notify_als_ckpt_pages, NULL, "CHECKPOINT_INTERVAL" }, // awake checkpoint thread if dirty page count reached
    { "CHECKPOINT_IO_CAPACITY", CT_TRUE, ATTR_NONE, "1024", NULL, NULL, "-", "[1,4096]", "CT_TYPE_INTEGER", NULL,
      PARAM_CHECKPOINT_IO_CAPACITY, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_checkpoint_io_capacity,
      sql_notify_als_ckpt_io_capacity, NULL, NULL },
    { "_CHECKPOINT_MERGE_IO", CT_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM__CHECKPOINT_MERGE_IO, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_ckpt_merge_io,
      sql_notify_als_bool, NULL },
    { "CHECKPOINT_GROUP_SIZE", CT_TRUE, ATTR_NONE, "4096", NULL, NULL, "-", "[1,8192]", "CT_TYPE_INTEGER", NULL,
      PARAM_CHECKPOINT_GROUP_SIZE, EFFECT_REBOOT, CFG_INS, sql_verify_als_ckpt_group_size,
      NULL, NULL, NULL },
    { "LOG_REPLAY_PROCESSES", CT_TRUE, ATTR_NONE, "1", NULL, NULL, "-", "[1,128]", "CT_TYPE_INTEGER", NULL,
      PARAM_LOG_REPLAY_PROCESSES, EFFECT_REBOOT, CFG_INS, sql_verify_als_rcy_params, NULL, NULL, NULL },
    { "REPLAY_PRELOAD_PROCESSES", CT_TRUE, ATTR_NONE, "0", NULL, NULL, "-", "[0,128]", "CT_TYPE_INTEGER", NULL,
      PARAM_REPLAY_PRELOAD_PROCESSES, EFFECT_REBOOT, CFG_INS, sql_verify_als_rcy_preload_process, NULL, NULL, NULL },
    { "_RCY_SLEEP_INTERVAL", CT_TRUE, ATTR_NONE, "32", NULL, NULL, "-", "[1,1024]", "CT_TYPE_INTEGER", NULL,
      PARAM__RCY_SLEEP_INTERVAL, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_rcy_sleep_interval,
      sql_notify_als_rcy_sleep_interval, NULL, NULL },
    { "TIMED_STATS", CT_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_TIMED_STATISTICS, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_timed_stat,
      sql_notify_als_bool, "TIMED_STATISTICS" }, // same with oracle
    { "STATS_LEVEL", CT_TRUE, ATTR_NONE, "TYPICAL", NULL, NULL, "-", "ALL,TYPICAL,BASIC", "CT_TYPE_VARCHAR", NULL,
      PARAM_STATISTICS_LEVEL, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_statistics_level, sql_notify_als_stats_level,
      NULL, "STATISTICS_LEVEL" }, // same with oracle
    { "DBWR_PROCESSES", CT_TRUE, ATTR_NONE, "8", NULL, NULL, "-", "[1,36]", "CT_TYPE_INTEGER", NULL,
      PARAM_DBWR_PROCESSES, EFFECT_REBOOT, CFG_INS, sql_verify_als_dbwr_processes, NULL, NULL, NULL },
    { "SQL_STAT", CT_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL, PARAM_SQL_STAT,
      EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_sql_stat, sql_notify_als_bool, NULL },
    { "INSTANCE_NAME", CT_TRUE, ATTR_NONE, "cantian", NULL, NULL, "-", "-", "CT_TYPE_VARCHAR", NULL, PARAM_INSTANCE_NAME,
      EFFECT_REBOOT, CFG_INS, sql_verify_als_comm, NULL, NULL, NULL },
    { "ALARM_LOG_DIR", CT_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "CT_TYPE_VARCHAR", NULL, PARAM_ALARM_LOG_DIR,
      EFFECT_REBOOT, CFG_INS, sql_verify_als_file_dir, NULL, NULL, NULL },
    { "REPL_ADDR", CT_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "CT_TYPE_VARCHAR", NULL, PARAM_REPL_ADDR,
      EFFECT_REBOOT, CFG_INS, sql_verify_als_ip, NULL, NULL, NULL },
    { "REPL_PORT", CT_TRUE, ATTR_NONE, "0", NULL, NULL, "-", "0,[1024,65535]", "CT_TYPE_INTEGER", NULL, PARAM_REPL_PORT,
      EFFECT_REBOOT, CFG_INS, sql_verify_als_repl_port, NULL, NULL, NULL },
    { "REPL_TRUST_HOST", CT_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "CT_TYPE_VARCHAR", NULL, PARAM_REPL_TRUST_HOST,
      EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_ip, sql_notify_als_repl_host, NULL, NULL },
    { "REPL_AUTH", CT_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL, PARAM_REPL_AUTH,
      EFFECT_REBOOT, CFG_INS, sql_verify_als_bool, sql_notify_als_bool, sql_notify_als_bool, NULL },
    { "REPL_SCRAM_AUTH", CT_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_REPL_SCRAM_AUTH, EFFECT_REBOOT, CFG_INS, sql_verify_als_bool, sql_notify_als_bool, sql_notify_als_bool,
      NULL },
    { "_REPL_MAX_PKG_SIZE", CT_TRUE, ATTR_NONE, "0", NULL, NULL, "-", "0,[512K,8M]", "CT_TYPE_INTEGER", NULL,
      PARAM__REPL_MAX_PKG_SIZE, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_repl_max_pkg_size,
      sql_notify_als_repl_max_pkg_size, NULL, NULL },
    /* file & space */
    { "FILE_OPTIONS", CT_TRUE, ATTR_NONE, "NONE", NULL, NULL, "",
      "NONE,DIRECTIO,FULLDIRECTIO,ASYNCH,DSYNC,FDATASYNC,SETALL", "CT_TYPE_VARCHAR", NULL, PARAM_FILESYSTEMIO_OPTIONS,
      EFFECT_REBOOT, CFG_INS, sql_verify_als_filesystemio_options, NULL, NULL, "FILESYSTEMIO_OPTIONS" },
    { "BUILD_DATAFILE_PARALLEL", CT_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_BUILD_DATAFILE_PARALLEL, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_build_datafile_paral,
      sql_notify_als_bool, NULL },
    { "ENABLE_TEMP_SPACE_BITMAP", CT_TRUE, ATTR_READONLY, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN",
      NULL, PARAM_ENABLE_TEMP_SPACE_BITMAP, EFFECT_REBOOT, CFG_DB, sql_verify_als_bool, sql_notify_als_bool,
      sql_notify_als_bool, NULL },
    { "BUILD_DATAFILE_PREALLOCATE", CT_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_BUILD_DATAFILE_PREALLOCATE, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool,
      sql_notify_build_datafile_prealloc, sql_notify_als_bool, NULL },
    /* auth */
    { "_ENCRYPTION_ALG", CT_TRUE, ATTR_NONE, "SCRAM_SHA256", NULL, NULL, "-", "SCRAM_SHA256", "CT_TYPE_VARCHAR", NULL,
      PARAM_ENCRYPTION_ALG, EFFECT_REBOOT, CFG_INS, sql_verify_als_encryption_alg, NULL, NULL, NULL },
    { "_SYS_PASSWORD", CT_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "CT_TYPE_VARCHAR", NULL, PARAM_SYS_PASSWORD,
      EFFECT_REBOOT, CFG_INS, sql_verify_als_sys_password, sql_notify_als_sys_password, NULL, NULL },
    { "TC_LEVEL", CT_TRUE, ATTR_NONE, "1", NULL, NULL, "-", "[0,4294967295]", "CT_TYPE_INTEGER", NULL, PARAM_TC_LEVEL,
      EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_uint32, sql_notify_als_tc_level, NULL, NULL },
    /* audit */
    { "AUDIT_LEVEL", CT_TRUE, ATTR_NONE, "3", NULL, NULL, "-", "[0,255]", "CT_TYPE_INTEGER", NULL, PARAM_AUDIT_LEVEL,
      EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_audit_level, sql_notify_als_audit_level, NULL, NULL },
    { "AUDIT_TRAIL_MODE", CT_TRUE, ATTR_NONE, "FILE", NULL, NULL, "-", "ALL,FILE,DB,SYSLOG,NONE", "CT_TYPE_VARCHAR",
      NULL, PARAM_AUDIT_TRAIL_MODE, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_audit_trail_mode,
      sql_notify_als_audit_trail_mode, NULL, NULL },
    { "AUDIT_SYSLOG_LEVEL", CT_TRUE, ATTR_NONE, "LOCAL0.DEBUG", NULL, NULL, "-", "", "CT_TYPE_VARCHAR", NULL,
      PARAM_AUDIT_SYSLOG_LEVEL, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_audit_syslog_level,
      sql_notify_als_audit_syslog_level, NULL, NULL },
    { "LOG_HOME", CT_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "CT_TYPE_VARCHAR", NULL, PARAM_LOG_HOME, EFFECT_REBOOT,
      CFG_INS, sql_verify_als_file_dir, NULL, NULL, NULL },
    { "_LOG_BACKUP_FILE_COUNT", CT_TRUE, ATTR_NONE, "10", NULL, NULL, "-", "[0,128]", "CT_TYPE_INTEGER", NULL,
      PARAM_LOG_BACKUP_FILE_COUNT, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_log_backup_file_count,
      sql_notify_als_log_backup_file_count, NULL, NULL },
    { "_AUDIT_BACKUP_FILE_COUNT", CT_TRUE, ATTR_NONE, "10", NULL, NULL, "-", "[0,128]", "CT_TYPE_INTEGER", NULL,
      PARAM_AUDIT_BACKUP_FILE_COUNT, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_audit_backup_file_count,
      sql_notify_als_audit_backup_file_count, NULL, NULL },
    { "_LOG_MAX_FILE_SIZE", CT_TRUE, ATTR_NONE, "10M", NULL, NULL, "-", "[1M,4G]", "CT_TYPE_INTEGER", NULL,
      PARAM_LOG_MAX_FILE_SIZE, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_log_file_size, sql_notify_als_log_max_file_size,
      NULL, NULL },
    { "_AUDIT_MAX_FILE_SIZE", CT_TRUE, ATTR_NONE, "10M", NULL, NULL, "-", "[1M,4G]", "CT_TYPE_INTEGER", NULL,
      PARAM_AUDIT_MAX_FILE_SIZE, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_audit_file_size,
      sql_notify_als_audit_max_file_size, NULL, NULL },
    { "_LOG_LEVEL", CT_TRUE, ATTR_NONE, "7", NULL, NULL, "-", "[0,16712567]", "CT_TYPE_INTEGER", NULL, PARAM_LOG_LEVEL,
      EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_log_level, sql_notify_als_log_level, NULL, NULL },
    { "_LOG_FILE_PERMISSIONS", CT_TRUE, ATTR_NONE, "640", NULL, NULL, "-", "[600-777]", "CT_TYPE_INTEGER", NULL,
      PARAM_LOG_FILE_PERMISSIONS, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_log_file,
      sql_notify_als_log_file_permissions, NULL, NULL },
    { "_LOG_PATH_PERMISSIONS", CT_TRUE, ATTR_NONE, "750", NULL, NULL, "-", "[700-777]", "CT_TYPE_INTEGER", NULL,
      PARAM_LOG_PATH_PERMISSIONS, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_log_path,
      sql_notify_als_log_path_permissions, NULL, NULL },
    { "UNDO_RESERVE_SIZE", CT_TRUE, ATTR_NONE, "1024", NULL, NULL, "-", "[64,1024]", "CT_TYPE_INTEGER", NULL,
      PARAM_UNDO_RESERVE_SIZE, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_undo_reserve_size,
      sql_notify_als_undo_reserve_size, NULL, NULL },
    { "UNDO_RETENTION_TIME", CT_TRUE, ATTR_NONE, "100", NULL, NULL, "-", "(0,4294967295]", "CT_TYPE_INTEGER", NULL,
      PARAM_UNDO_RETENTION_TIME, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_undo_retention_time,
      sql_notify_als_undo_retention_time, NULL, NULL },
    { "INDEX_DEFER_RECYCLE_TIME", CT_TRUE, ATTR_NONE, "0", NULL, NULL, "-", "[0, -)", "CT_TYPE_INTEGER", NULL,
      PARAM_INDEX_DEFER_RECYCLE_TIME, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_uint32,
      sql_notify_als_index_defer_recycle_time, NULL, NULL },
    { "_UNDO_SEGMENTS", CT_TRUE, ATTR_READONLY, "32", NULL, NULL, "-", "(1, 1024]", "CT_TYPE_INTEGER", NULL,
      PARAM_UNDO_SEGMENTS, EFFECT_REBOOT, CFG_DB, sql_verify_als_undo_segments, NULL, NULL, NULL },
    { "_UNDO_ACTIVE_SEGMENTS", CT_TRUE, ATTR_NONE, "32", NULL, NULL, "-", "(1, 1024]", "CT_TYPE_INTEGER", NULL,
      PARAM_ACTIVE_UNDO_SEGMENTS, EFFECT_IMMEDIATELY, CFG_DB, sql_verify_als_active_undo_segments,
      sql_notify_als_active_undo_segments, NULL, NULL },
    { "_UNDO_AUTON_TRANS_SEGMENTS", CT_TRUE, ATTR_NONE, "1", NULL, NULL, "-", "[1, 1024)", "CT_TYPE_INTEGER", NULL,
      PARAM_UNDO_AUTON_TRANS_SEGMENTS, EFFECT_IMMEDIATELY, CFG_DB, sql_verify_als_auton_trans_segments,
      sql_notify_als_auton_trans_segments, NULL, NULL },
    { "_UNDO_AUTON_BIND_OWN_SEGMENT", CT_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN",
      NULL, PARAM_UNDO_AUTON_BIND_OWN_SEGMENT, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool,
      sql_notify_als_undo_auton_bind_own_seg, sql_notify_als_bool, NULL },
    { "_UNDO_AUTO_SHRINK", CT_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_UNDO_AUTO_SHRINK, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_undo_auto_shrink,
      sql_notify_als_bool, NULL },
    { "_UNDO_AUTO_SHRINK_INACTIVE", CT_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_UNDO_AUTO_SHRINK_INACTIVE, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool,
      sql_notify_als_undo_auto_shrink_inactive, sql_notify_als_bool, NULL },
    { "UNDO_PREFETCH_PAGE_NUM", CT_TRUE, ATTR_NONE, "1", NULL, NULL, "-", "(0,128]", "CT_TYPE_INTEGER", NULL,
      PARAM_UNDO_PREFETCH_PAGE_NUM, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_undo_prefetch_pages,
      sql_notify_als_undo_prefetch_pages, NULL, NULL },
    { "_TX_ROLLBACK_PROC_NUM", CT_TRUE, ATTR_NONE, "2", NULL, NULL, "-", "[1, 2]", "CT_TYPE_INTEGER", NULL,
      PARAM_TX_ROLLBACK_PROC, EFFECT_REBOOT, CFG_INS, sql_verify_als_rollback_proc_num, NULL, NULL, NULL },
    { "REPL_WAIT_TIMEOUT", CT_TRUE, ATTR_NONE, "10", NULL, NULL, "-", "[3, -)", "CT_TYPE_INTEGER", NULL,
      PARAM_REPL_WAIT_TIMEOUT, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_repl_wait_timeout,
      sql_notify_als_repl_timeout, NULL, NULL },
    { "COMMIT_ON_DISCONNECT", CT_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_COMMIT_ON_DISCONN, EFFECT_REBOOT, CFG_INS, sql_verify_als_bool, sql_notify_als_commit_on_disconn,
      sql_notify_als_bool, NULL },
    { "_MAX_CONNECT_BY_LEVEL", CT_TRUE, ATTR_NONE, "256", NULL, NULL, "-", "[0,4294967295]", "CT_TYPE_UINT32", NULL,
      PARAM_MAX_CONNECT_BY_LEVEL, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_uint32,
      sql_notify_als_max_connect_by_level, NULL, NULL },
    { "BACKUP_BUFFER_SIZE", CT_TRUE, ATTR_NONE, "128M", NULL, NULL, "-", "[8M,512M]", "CT_TYPE_INTEGER", NULL,
      PARAM_BACKUP_BUFFER_SIZE, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_backup_buf_size,
      sql_notify_als_backup_buf_size, NULL, NULL },
    { "RESTORE_ARCH_COMPRESSED", CT_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_RESTORE_ARCH_COMPRESSED, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool,
      sql_notify_als_restore_arch_compressed, sql_notify_als_bool, NULL },
    { "_INDEX_SCAN_RANGE_CACHE", CT_TRUE, ATTR_NONE, "100", NULL, NULL, "-", "[0,2000]", "CT_TYPE_INTEGER", NULL,
      PARAM_INDEX_SCAN_RANGE_CACHE, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_range_cache,
      sql_notify_als_min_range_cache, NULL, NULL },

    { "_RESTORE_CHECK_VERSION", CT_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_RESTORE_CHECK_VERSION, EFFECT_REBOOT, CFG_INS, sql_verify_als_bool, sql_notify_als_bool,
      sql_notify_als_bool, NULL },
    { "RESTOR_ARCH_PREFER_BAK_SET", CT_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_RESTOR_ARCH_PREFER_BAK_SET, EFFECT_REBOOT, CFG_INS, sql_verify_als_bool, sql_notify_als_bool,
      sql_notify_als_bool, NULL },
    { "NBU_BACKUP_TIMEOUT", CT_TRUE, ATTR_NONE, "90", NULL, NULL, "-", "[1,4294967295]", "CT_TYPE_INTEGER", NULL,
      PARAM_NBU_BACKUP_TIMEOUT, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_nbu_backup_timeout,
      sql_notify_als_nbu_backup_timeout, NULL, NULL },
    { "_CHECK_SYSDATA_VERSION", CT_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_CHECK_SYSDATA_VERSION, EFFECT_REBOOT, CFG_INS, sql_verify_als_bool, sql_notify_als_bool,
      sql_notify_als_bool, NULL },
    { "MAX_ARCH_FILES_SIZE", CT_TRUE, ATTR_NONE, "60G", NULL, NULL, "-", "[0,32T]", "CT_TYPE_INTEGER", NULL,
      PARAM_MAX_ARCHIVE_FILES_SIZE, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_size, sql_notify_als_arch_size, NULL,
      NULL },
    { "ARCH_LOG_CHECK", CT_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_ARCH_LOG_CHECK, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_bool,
      sql_notify_als_bool, NULL },
    { "ARCH_FILE_SIZE", CT_TRUE, ATTR_NONE, "10G", NULL, NULL, "-", "[512M,10G]", "CT_TYPE_INTEGER", NULL,
      PARAM_ARCHIVE_FILE_SIZE, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_arch_file_size,
      sql_notify_als_need_arch_file_size, NULL, NULL },
    { "ARCH_SIZE", CT_TRUE, ATTR_NONE, "512M", NULL, NULL, "-", "[0,512MB]", "CT_TYPE_INTEGER", NULL,
      PARAM_ARCHIVE_SIZE, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_arch_size, sql_notify_als_need_arch_size, NULL,
      NULL },
    { "ARCH_TIME", CT_TRUE, ATTR_NONE, "60000000", NULL, NULL, "-", "[100000,300000000]", "CT_TYPE_INTEGER", NULL,
      PARAM_ARCHIVE_TIME, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_time, sql_notify_als_need_arch_time, NULL, NULL },
    { "ARCH_CLEAN_UPPER_LIMIT", CT_TRUE, ATTR_NONE, "85", NULL, NULL, "-", "[1,100]", "CT_TYPE_INTEGER", NULL,
      PARAM_ARCH_CLEAN_UPPER_LIMIT, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_arch_upper_limit,
      sql_notify_als_arch_upper_limit, NULL, NULL },
    { "ARCH_CLEAN_LOWER_LIMIT", CT_TRUE, ATTR_NONE, "30", NULL, NULL, "-", "[0,100]", "CT_TYPE_INTEGER", NULL,
      PARAM_ARCH_CLEAN_LOWER_LIMIT, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_arch_lower_limit,
      sql_notify_als_arch_lower_limit, NULL, NULL },
    { "ARCH_CLEAN_IGNORE_BACKUP", CT_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_ARCH_CLEAN_IGNORE_BACKUP, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_ignore_backup,
      sql_notify_als_bool, NULL },
    { "ARCH_CLEAN_IGNORE_STANDBY", CT_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_ARCH_CLEAN_IGNORE_STANDBY, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_ignore_standby,
      sql_notify_als_bool, NULL },
    { "XA_SUSPEND_TIMEOUT", CT_TRUE, ATTR_NONE, "60", NULL, NULL, "-", "(0,3600]", "CT_TYPE_INTEGER", NULL,
      PARAM_XA_SUSPEND_TIMEOUT, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_xa_suspend_timeout,
      sql_notify_als_xa_suspend_timeout, NULL, NULL },
    { "BUILD_KEEP_ALIVE_TIMEOUT", CT_TRUE, ATTR_NONE, "30", NULL, NULL, "-", "[3, -)", "CT_TYPE_INTEGER", NULL,
      PARAM_KEEP_ALIVE_TIMEOUT, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_uint32, sql_notify_als_build_timeout, NULL,
      NULL },
    { "_BACKUP_LOG_PARALLEL", CT_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_BACKUP_LOG_PARALLEL, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_backup_log_parallel,
      sql_notify_als_bool, NULL },
    /* ip whitelist */
    { "TCP_VALID_NODE_CHECKING", CT_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_TCP_VALID_NODE_CHECKING, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool,
      sql_notify_als_valid_node_checking, sql_notify_als_bool, NULL },
    { "TCP_INVITED_NODES", CT_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "CT_TYPE_VARCHAR", NULL,
      PARAM_TCP_INVITED_NODES, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_comm, sql_notify_als_invited_nodes, NULL,
      NULL },
    { "TCP_EXCLUDED_NODES", CT_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "CT_TYPE_VARCHAR", NULL,
      PARAM_TCP_EXCLUDED_NODES, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_comm, sql_notify_als_excluded_nodes, NULL,
      NULL },
    { "LOCK_WAIT_TIMEOUT", CT_TRUE, ATTR_NONE, "0", NULL, NULL, "-", "[0,4294967295]", "CT_TYPE_INTEGER", NULL,
      PARAM_LOCK_WAIT_TIMEOUT, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_uint32, sql_notify_als_lock_wait_timeout,
      NULL, NULL },
    { "ENABLE_RAFT", CT_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL, PARAM_RAFT,
      EFFECT_REBOOT, CFG_INS, sql_verify_als_bool, sql_notify_als_bool, sql_notify_als_bool, NULL },
    { "RAFT_START_MODE", CT_TRUE, ATTR_NONE, "0", NULL, NULL, "-", "[0,3]", "CT_TYPE_INTEGER", NULL,
      PARAM_RAFT_START_MODE, EFFECT_REBOOT, CFG_INS, sql_verify_als_raft_start_mode, NULL, NULL, NULL },
    { "RAFT_NODE_ID", CT_TRUE, ATTR_NONE, "", NULL, NULL, "-", "[1,-)", "CT_TYPE_INTEGER", NULL, PARAM_RAFT_NODE_ID,
      EFFECT_REBOOT, CFG_INS, sql_verify_als_raft_node_id, NULL, NULL, NULL },
    { "RAFT_PEER_IDS", CT_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "CT_TYPE_VARCHAR", NULL, PARAM_RAFT_PEER_IDS,
      EFFECT_REBOOT, CFG_INS, sql_verify_als_comm, NULL, NULL, NULL },
    { "RAFT_LOCAL_ADDR", CT_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "CT_TYPE_VARCHAR", NULL, PARAM_RAFT_LOCAL_ADDR,
      EFFECT_REBOOT, CFG_INS, sql_verify_als_comm, NULL, NULL, NULL },
    { "RAFT_PEER_ADDRS", CT_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "CT_TYPE_VARCHAR", NULL, PARAM_RAFT_PEER_ADDRS,
      EFFECT_REBOOT, CFG_INS, sql_verify_als_comm, NULL, NULL, NULL },
    { "RAFT_LOG_LEVEL", CT_TRUE, ATTR_NONE, "2", NULL, NULL, "-", "[0,6]", "CT_TYPE_INTEGER", NULL,
      PARAM_RAFT_LOG_LEVEL, EFFECT_REBOOT, CFG_INS, sql_verify_als_raft_log_level, NULL, NULL, NULL },
    { "RAFT_KUDU_DIR", CT_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "CT_TYPE_VARCHAR", NULL, PARAM_RAFT_KUDU_DIR,
      EFFECT_REBOOT, CFG_INS, sql_verify_als_comm, NULL, NULL, NULL },
    { "RAFT_PRIORITY_TYPE", CT_TRUE, ATTR_NONE, "External", NULL, NULL, "-", "External,Random,Static,AZFirst",
      "CT_TYPE_VARCHAR", NULL, PARAM_RAFT_PRIORITY_TYPE, EFFECT_REBOOT, CFG_INS, sql_verify_als_raft_priority_type,
      NULL, NULL, NULL },
    { "RAFT_PRIORITY_LEVEL", CT_TRUE, ATTR_NONE, "0", NULL, NULL, "-", "[0,16]", "CT_TYPE_VARCHAR", NULL,
      PARAM_RAFT_PRIORITY_LEVEL, EFFECT_REBOOT, CFG_INS, sql_verify_als_raft_priority_level, NULL, NULL, NULL },
    { "RAFT_LAYOUT_INFO", CT_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "CT_TYPE_VARCHAR", NULL, PARAM_RAFT_LAYOUT_INFO,
      EFFECT_REBOOT, CFG_INS, sql_verify_als_comm, NULL, NULL, NULL },
    { "RAFT_PENDING_CMDS_BUFFER_SIZE", CT_TRUE, ATTR_NONE, "1000", NULL, NULL, "-", "[1,-)", "CT_TYPE_INTEGER", NULL,
      PARAM_RAFT_PENDING_CMDS_BUFFER_SIZE, EFFECT_REBOOT, CFG_INS, sql_verify_als_raft_pending_cmds_buffer_size, NULL,
      NULL, NULL },
    { "RAFT_SEND_BUFFER_SIZE", CT_TRUE, ATTR_NONE, "100", NULL, NULL, "-", "[1,10000]", "CT_TYPE_INTEGER", NULL,
      PARAM_RAFT_SEND_BUFFER_SIZE, EFFECT_REBOOT, CFG_INS, sql_verify_als_raft_send_buffer_size, NULL, NULL, NULL },
    { "RAFT_RECEIVE_BUFFER_SIZE", CT_TRUE, ATTR_NONE, "100", NULL, NULL, "-", "[1,10000]", "CT_TYPE_INTEGER", NULL,
      PARAM_RAFT_RECEIVE_BUFFER_SIZE, EFFECT_REBOOT, CFG_INS, sql_verify_als_raft_receive_buffer_size, NULL, NULL,
      NULL },
    { "RAFT_RAFT_ENTRY_CACHE_MEMORY_SIZE", CT_TRUE, ATTR_NONE, "2G", NULL, NULL, "-", "[1,-)", "CT_TYPE_INTEGER", NULL,
      PARAM_RAFT_RAFT_ENTRY_CACHE_MEMORY_SIZE, EFFECT_REBOOT, CFG_INS, sql_verify_als_comm,
      sql_notify_als_entry_cache_memory_size, NULL, NULL },
    { "RAFT_MAX_SIZE_PER_MSG", CT_TRUE, ATTR_NONE, "128M", NULL, NULL, "-", "[64M,-)", "CT_TYPE_INTEGER", NULL,
      PARAM_RAFT_MAX_SIZE_PER_MSG, EFFECT_REBOOT, CFG_INS, sql_verify_als_comm, sql_notify_als_max_size_per_msg, NULL,
      NULL },
    { "RAFT_ELECTION_TIMEOUT", CT_TRUE, ATTR_NONE, "5", NULL, NULL, "-", "[3,60]", "CT_TYPE_INTEGER", NULL,
      PARAM_RAFT_ELECTION_TIMEOUT, EFFECT_REBOOT, CFG_INS, sql_verify_als_raft_election_timeout,
      sql_notify_als_raft_election_timeout, NULL, NULL },
    { "RAFT_MEMORY_THRESHOLD", CT_TRUE, ATTR_NONE, "5G", NULL, NULL, "-", "-", "CT_TYPE_INTEGER", NULL,
      PARAM_RAFT_MEM_THRESHOLD, EFFECT_REBOOT, CFG_INS, sql_verify_als_comm, sql_notify_als_raft_mem_threshold, NULL,
      NULL },
    { "RAFT_LOG_ASYNC_BUF_NUM", CT_TRUE, ATTR_NONE, "16", NULL, NULL, "-", "[1,128]", "CT_TYPE_INTEGER", NULL,
      PARAM_RAFT_LOG_ASYNC_BUF_NUM, EFFECT_REBOOT, CFG_INS, sql_verify_als_raft_log_async_buf_num, NULL, NULL, NULL },
    { "RAFT_FAILOVER_LIB_TIMEOUT", CT_TRUE, ATTR_NONE, "600", NULL, NULL, "-", "[5,-)", "CT_TYPE_INTEGER", NULL,
      PARAM_RAFT_FAILOVER_LIB_TIMEOUT, EFFECT_REBOOT, CFG_INS, sql_verify_als_raft_failover_lib_timeout, NULL, NULL,
      NULL },
    { "RAFT_TLS_DIR", CT_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "CT_TYPE_VARCHAR", NULL, PARAM_RAFT_TLS_DIR,
      EFFECT_REBOOT, CFG_INS, sql_verify_als_raft_tls_dir, NULL, NULL, NULL },
    { "RAFT_TOKEN_VERIFY", CT_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "-", "CT_TYPE_VARCHAR", NULL,
      PARAM_RAFT_TOKEN_VERIFY, EFFECT_REBOOT, CFG_INS, sql_verify_als_raft_token_verify, NULL, NULL, NULL },
    { "LOCAL_KEY", CT_TRUE, ATTR_NONE, "", NULL, NULL, "-", "88", "CT_TYPE_VARCHAR", NULL, PARAM_LOCAL_KEY,
      EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_local_key, sql_notify_als_local_key, NULL, NULL },
    { "BUF_POOL_NUM", CT_TRUE, ATTR_NONE, "1", NULL, NULL, "-", "[1,128]", "CT_TYPE_INTEGER", NULL, PARAM_BUF_POOL_NUM,
      EFFECT_REBOOT, CFG_INS, sql_verify_als_buf_pool_num, NULL, NULL, NULL },
    { "DEFAULT_EXTENTS", CT_TRUE, ATTR_NONE, "8", NULL, NULL, "-", "8, 16, 32, 64, 128", "CT_TYPE_INTEGER", NULL,
      PARAM_DEFAULT_EXTENTS, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_default_extents,
      sql_notify_als_default_extents, NULL, NULL },
    { "_MAX_VM_FUNC_STACK_COUNT", CT_TRUE, ATTR_NONE, "0", NULL, NULL, "-", "[0,4294967295]", "CT_TYPE_UINT32", NULL,
      PARAM_MAX_VM_FUNC_STACK_COUNT, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_uint32,
      sql_notify_als_vm_func_stack_count, NULL, NULL },
    { "TEMP_POOL_NUM", CT_TRUE, ATTR_NONE, "1", NULL, NULL, "-", "[1, 128]", "CT_TYPE_INTEGER", NULL,
      PARAM_TEMP_POOL_NUM, EFFECT_REBOOT, CFG_INS, sql_verify_als_temp_pool_num, NULL, NULL, NULL },

    /* merge join */
    { "MERGE_SORT_BATCH_SIZE", CT_TRUE, ATTR_NONE, "100000", NULL, NULL, "-", "[100000,4294967295]", "CT_TYPE_UINT32",
      NULL, PARAM_MERGE_SORT_BATCH_SIZE, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_merge_batch_size,
      sql_notify_als_merge_sort_batch_size, NULL, NULL },
    { "MAX_ALLOWED_PACKET", CT_TRUE, ATTR_NONE, "64M", NULL, NULL, "-", "[96K, 64M]", "CT_TYPE_INTEGER", NULL,
      PARAM_MAX_ALLOWED_PACKET, EFFECT_REBOOT, CFG_INS, sql_verify_als_max_allowed_packet,
      sql_notify_als_max_allowed_packet, NULL, NULL },
    { "DB_FILE_NAME_CONVERT", CT_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "CT_TYPE_VARCHAR", NULL,
      PARAM_DB_FILE_NAME_CONVERT, EFFECT_REBOOT, CFG_INS, sql_verify_als_convert, sql_notify_als_datefile_convert, NULL,
      NULL },
    { "LOG_FILE_NAME_CONVERT", CT_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "CT_TYPE_VARCHAR", NULL,
      PARAM_LOG_FILE_NAME_CONVERT, EFFECT_REBOOT, CFG_INS, sql_verify_als_convert, sql_notify_als_logfile_convert, NULL,
      NULL },
    { "INTERACTIVE_TIMEOUT", CT_TRUE, ATTR_NONE, "1800", NULL, NULL, "-", "[1,4294967295]", "CT_TYPE_UINT32", NULL,
      PARAM_INTERACTIVE_TIMEOUT, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_interactive_timeout,
      sql_notify_als_interactive_timeout, NULL, NULL },
    { "LONGSQL_TIMEOUT", CT_TRUE, ATTR_NONE, "10", NULL, NULL, "-", "[0s,(2^32-1)s]", "CT_TYPE_INTEGER", NULL,
      PARAM_LONGSQL_TIMEOUT, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_longsql_timeout,
      sql_notify_als_longsql_timeout, NULL, NULL },
    /* ssl */
    { "SSL_CA", CT_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "CT_TYPE_VARCHAR", NULL, PARAM_SSL_CA, EFFECT_REBOOT,
      CFG_INS, sql_verify_als_ssl_file, NULL, NULL, NULL },
    { "SSL_CERT", CT_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "CT_TYPE_VARCHAR", NULL, PARAM_SSL_CERT, EFFECT_REBOOT,
      CFG_INS, sql_verify_als_ssl_file, NULL, NULL, NULL },
    { "SSL_KEY", CT_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "CT_TYPE_VARCHAR", NULL, PARAM_SSL_KEY, EFFECT_REBOOT,
      CFG_INS, sql_verify_als_ssl_file, NULL, NULL, NULL },
    { "SSL_CRL", CT_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "CT_TYPE_VARCHAR", NULL, PARAM_SSL_CRL, EFFECT_REBOOT,
      CFG_INS, sql_verify_als_ssl_file, NULL, NULL, NULL },
    { "SSL_VERIFY_PEER", CT_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_SSL_VERIFY_PEER, EFFECT_REBOOT, CFG_INS, sql_verify_als_bool, sql_notify_als_bool, sql_notify_als_bool,
      NULL },
    { "SSL_KEY_PASSWORD", CT_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "CT_TYPE_VARCHAR", NULL, PARAM_SSL_KEY_PASSWORD,
      EFFECT_REBOOT, CFG_INS, sql_verify_als_comm, NULL, NULL, NULL },
    { "SSL_CIPHER", CT_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "CT_TYPE_VARCHAR", NULL, PARAM_SSL_CIPHER,
      EFFECT_REBOOT, CFG_INS, sql_verify_als_ssl_cipher, NULL, NULL, NULL },
    { "SSL_EXPIRE_ALERT_THRESHOLD", CT_TRUE, ATTR_NONE, "90", NULL, NULL, "-", "[7,180]", "CT_TYPE_INTEGER", NULL,
      PARAM_SSL_EXPIRE_ALERT_THRESHOLD, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_ssl_alt_threshold, NULL, NULL, NULL },
    { "SSL_PERIOD_DETECTION", CT_TRUE, ATTR_NONE, "7", NULL, NULL, "-", "[1,180]", "CT_TYPE_INTEGER", NULL,
      PARAM_SSL_PERIOD_DETECTION, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_ssl_period_detection, NULL, NULL, NULL },
    { "LOCAL_TEMPORARY_TABLE_ENABLED", CT_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN",
      NULL, PARAM_LOCAL_TEMPORARY_TABLE_ENABLED, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool,
      sql_notify_als_local_tmp_tbl_enabled, sql_notify_als_bool, NULL },
    { "UPPER_CASE_TABLE_NAMES", CT_TRUE, ATTR_READONLY, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_UPPER_CASE_TABLE_NAMES, EFFECT_REBOOT, CFG_INS, sql_verify_als_bool, sql_notify_als_upper_case_table_names,
      sql_notify_als_bool, NULL },
    { "UNAUTH_SESSION_EXPIRE_TIME", CT_TRUE, ATTR_NONE, "60", NULL, NULL, "-", "[0,4294967295]", "CT_TYPE_UINT32", NULL,
      PARAM_UNAUTH_SESSION_EXPIRE_TIME, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_uint32,
      sql_notify_als_unauth_session_expire_time, NULL, NULL },
    { "ENABLE_SYSDBA_LOGIN", CT_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_ENABLE_SYSDBA_LOGIN, EFFECT_REBOOT, CFG_INS, sql_verify_als_bool_only_sys_allowed,
      sql_notify_als_login_as_sysdba, sql_notify_als_bool, NULL },
    { "ENABLE_SYS_REMOTE_LOGIN", CT_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_ENABLE_SYS_REMOTE_LOGIN, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool_only_sys_allowed,
      sql_notify_als_sys_remote_login, sql_notify_als_bool, NULL },
    { "ENABLE_SYSDBA_REMOTE_LOGIN", CT_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_ENABLE_SYSDBA_REMOTE_LOGIN, EFFECT_REBOOT, CFG_INS, sql_verify_als_bool_only_sys_allowed,
      sql_notify_als_sysdba_remote_login, sql_notify_als_bool, NULL },
    { "RESOURCE_LIMIT", CT_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_RESOURCE_LIMIT, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_resource_limit,
      sql_notify_als_bool, NULL },
    { "_FACTOR_KEY", CT_TRUE, ATTR_NONE, "", NULL, NULL, "-", "24", "CT_TYPE_VARCHAR", NULL, PARAM__FACTOR_KEY,
      EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_factor_key, sql_notify_als_factor_key, NULL, NULL },
    /* err superposed switch */
    { "ENABLE_ERR_SUPERPOSED", CT_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_ENABLE_ERR_SUPERPOSED, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool,
      sql_notify_als_enable_err_superposed, sql_notify_als_bool, NULL },
    { "EMPTY_STRING_AS_NULL", CT_TRUE, ATTR_READONLY, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_EMPTY_STRING_AS_NULL, EFFECT_REBOOT, CFG_INS, sql_verify_als_bool, sql_notify_empty_string_null,
      sql_notify_als_bool, NULL },
    { "ZERO_DIVISOR_ACCEPTED", CT_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_ZERO_DIVISOR_ACCEPTED, EFFECT_REBOOT, CFG_INS, sql_verify_als_bool, sql_notify_zero_divisor_accepted,
      sql_notify_als_bool, NULL },
    { "STRING_AS_HEX_FOR_BINARY", CT_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_STRING_AS_HEX_BINARY, EFFECT_REBOOT, CFG_INS, sql_verify_als_bool, sql_notify_string_as_hex_binary,
      sql_notify_als_bool, NULL },
    { "DROP_NOLOGGING", CT_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_DROP_NOLOGGING, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_drop_nologging,
      sql_notify_als_bool, NULL },
    { "RECYCLEBIN", CT_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_RECYCLEBIN, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_recyclebin, sql_notify_als_bool,
      NULL },
    { "HAVE_SSL", CT_TRUE, ATTR_READONLY, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_HAVE_SSL, EFFECT_REBOOT, CFG_INS, sql_verify_als_have_ssl, NULL, NULL, NULL },
#ifdef _DEBUG
    { "_ENCRYPTION_ITERATION", CT_TRUE, ATTR_NONE, "10000", NULL, NULL, "-", "[1000,10000000]", "CT_TYPE_INTEGER", NULL,
      PARAM_ENCRYPTION_ITER, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_encrypt_iteration,
      sql_notify_als_encrypt_iteration, sql_notify_als_encrypt_iteration, NULL },
#else
    { "_ENCRYPTION_ITERATION", CT_TRUE, ATTR_NONE, "1000000", NULL, NULL, "-", "[10000000,20000000]", "CT_TYPE_INTEGER", NULL,
      PARAM_ENCRYPTION_ITER, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_encrypt_iteration,
      sql_notify_als_encrypt_iteration, sql_notify_als_encrypt_iteration, NULL },
#endif
    { "MAX_TEMP_TABLES", CT_TRUE, ATTR_NONE, "256", NULL, NULL, "-", "[64,8192]", "CT_TYPE_INTEGER", NULL,
      PARAM_MAX_TEMP_TABLES, EFFECT_REBOOT, CFG_INS, sql_verify_als_max_temp_tables, NULL, NULL, NULL },
    { "ENABLE_IDX_CONFS_NAME_DUPL", CT_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_ENABLE_IDX_CONFS_NAME_DUPL, EFFECT_REBOOT, CFG_INS, sql_verify_als_idx_duplicate_enable,
      sql_notify_als_idx_duplicate, sql_notify_als_idx_duplicate, NULL },
    { "ENABLE_IDX_KEY_LEN_CHECK", CT_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_ENABLE_IDX_KEY_LEN_CHECK, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_idx_key_len_check,
      sql_notify_als_bool, NULL },
    { "CBO", CT_TRUE, ATTR_NONE, "ON", NULL, NULL, "-", "OFF,ON", "CT_TYPE_VARCHAR", NULL, PARAM_CBO,
      EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_onoff, sql_notify_als_cbo, sql_notify_als_onoff, NULL },
    { "MAX_COLUMN_COUNT", CT_TRUE, ATTR_NONE, "1024", NULL, NULL, "-", "1024,2048,3072,4096", "CT_TYPE_INTEGER", NULL,
      PARAM_MAX_COLUMN_COUNT, EFFECT_REBOOT, CFG_DB, sql_verify_als_max_column_count, NULL, NULL, NULL },
    { "STATISTICS_SAMPLE_SIZE", CT_TRUE, ATTR_NONE, "128M", NULL, NULL, "-", "[32M,4G)", "CT_TYPE_INTEGER", NULL,
      PARAM_SAMPLE_SIZE, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_stats_sample_size, sql_notify_als_sample_size,
      NULL, NULL },
    // initial sql_cursors for each session
    { "_SQL_CURSORS_EACH_SESSION", CT_TRUE, ATTR_NONE, "8", NULL, NULL, "-", "[0,300]", "CT_TYPE_INTEGER", NULL,
      PARAM__SQL_CURSORS_EACH_SESSION, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_sql_cursors_each_sess,
      sql_notify_als_sql_cursors_each_sess, NULL, NULL },
    // reserved sql_cursors for all sessions
    { "_RESERVED_SQL_CURSORS", CT_TRUE, ATTR_NONE, "80", NULL, NULL, "-", "[0,1000]", "CT_TYPE_INTEGER", NULL,
      PARAM__RESERVED_SQL_CURSORS, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_reserved_sql_cursors,
      sql_notify_als_reserved_sql_cursors, NULL, NULL },
    { "COVERAGE_ENABLE", CT_TRUE, ATTR_READONLY, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_COVERAGE_ENABLE, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_coverage_enable,
      sql_notify_als_bool, NULL },
    { "TYPE_MAP_FILE", CT_TRUE, ATTR_READONLY, "", NULL, NULL, "-", "-", "CT_TYPE_VARCHAR", NULL, PARAM_TYPE_MAP_FILE,
      EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL },
    { "INI_TRANS", CT_TRUE, ATTR_NONE, "2", NULL, NULL, "-", "[1, 255]", "CT_TYPE_INTEGER", NULL, PARAM_INI_TRANS,
      EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_ini_trans, sql_notify_als_ini_trans, NULL, NULL },
    { "CR_MODE", CT_TRUE, ATTR_NONE, "PAGE", NULL, NULL, "-", "PAGE,ROW", "CT_TYPE_VARCHAR", NULL, PARAM_CR_MODE,
      EFFECT_REBOOT, CFG_INS, sql_verify_als_cr_mode, NULL, NULL, NULL },
    { "ROW_FORMAT", CT_TRUE, ATTR_NONE, "ASF", NULL, NULL, "-", "ASF,CSF", "CT_TYPE_VARCHAR", NULL, PARAM_ROW_FORMAT,
      EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_row_format, sql_notify_als_row_format, NULL, NULL },
    { "_LNS_WAIT_TIME", CT_TRUE, ATTR_NONE, "3", NULL, NULL, "-", "[0,4294967295]", "CT_TYPE_INTEGER", NULL,
      PARAM__LSND_WAIT_TIME, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_uint32, sql_notify_als_lsnd_wait_time, NULL,
      NULL },
    { "_PRIVATE_KEY_LOCKS", CT_TRUE, ATTR_NONE, "8", NULL, NULL, "_", "[8, 128]", "CT_TYPE_INTEGER", NULL,
      PARAM_PRIVATE_KEY_LOCKS, EFFECT_REBOOT, CFG_INS, sql_verify_als_private_key_locks,
      sql_notify_als_private_key_locks, NULL, NULL },
    { "_PRIVATE_ROW_LOCKS", CT_TRUE, ATTR_NONE, "8", NULL, NULL, "_", "[8, 128]", "CT_TYPE_INTEGER", NULL,
      PARAM_PRIVATE_ROW_LOCKS, EFFECT_REBOOT, CFG_INS, sql_verify_als_private_row_locks,
      sql_notify_als_private_row_locks, NULL, NULL },
    { "DDL_LOCK_TIMEOUT", CT_TRUE, ATTR_NONE, "30", NULL, NULL, "_", "[0, 1000000]", "CT_TYPE_INTEGER", NULL,
      PARAM_DDL_LOCK_TIMEOUT, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_ddl_lock_timeout,
      sql_notify_als_ddl_lock_timeout, NULL, NULL },
    { "MAX_REMOTE_PARAMS", CT_TRUE, ATTR_NONE, "300", NULL, NULL, "_", "[0, 32768]", "CT_TYPE_INTEGER", NULL,
      PARAM_MAX_REMOTE_PARAMS, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_max_remote_params,
      sql_notify_als_max_remote_params, NULL, NULL },
    { "DB_TIMEZONE", CT_TRUE, ATTR_READONLY, "+00:00", NULL, NULL, "-", "[-12:00,[+]14:00]", "CT_TYPE_VARCHAR", NULL,
      PARAM_DB_TIMEZONE, EFFECT_REBOOT, CFG_DB, sql_verify_als_db_tz, NULL, NULL, NULL },
    // alarm
    { "TABLESPACE_USAGE_ALARM_THRESHOLD", CT_TRUE, ATTR_NONE, "80", NULL, NULL, "_", "[0, 100]", "CT_TYPE_INTEGER",
      NULL, PARAM_TABLESPACE_ALARM_THRESHOLD, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_tablespace_alarm_threshold,
      sql_notify_als_tablespace_alarm_threshold, NULL, NULL },
    { "UNDO_USAGE_ALARM_THRESHOLD", CT_TRUE, ATTR_NONE, "0", NULL, NULL, "_", "[0, 100]", "CT_TYPE_INTEGER", NULL,
      PARAM_UNDO_ALARM_THRESHOLD, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_undo_alarm_threshold,
      sql_notify_als_undo_alarm_threshold, NULL, NULL },
    { "TXN_UNDO_USAGE_ALARM_THRESHOLD", CT_TRUE, ATTR_NONE, "0", NULL, NULL, "_", "[0, 100]", "CT_TYPE_INTEGER", NULL,
      PARAM_TXN_UNDO_ALARM_THRESHOLD, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_txn_undo_alarm_threshold,
      sql_notify_als_txn_undo_alarm_threshold, NULL, NULL },
    { "_SYSTIME_INCREASE_THREASHOLD", CT_TRUE, ATTR_NONE, "365", NULL, NULL, "_", "[0, 3600]", "CT_TYPE_INTEGER", NULL,
      PARAM_SYSTIME_INCREASE_THREASHOLD, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_systime_increase_threshold,
      sql_notify_als_systime_increase_threshold, NULL, NULL },
    /* auto block repair */
    { "BLOCK_REPAIR_ENABLE", CT_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_BLOCK_REPAIR_ENABLE, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_block_repair_enable,
      sql_notify_als_bool, NULL },
    { "BLOCK_REPAIR_TIMEOUT", CT_TRUE, ATTR_NONE, "60", NULL, NULL, "-", "[1,3600]", "CT_TYPE_INTEGER", NULL,
      PARAM_BLOCK_REPAIR_TIMEOUT, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_block_repair_timeout,
      sql_notify_als_block_repair_timeout, NULL, NULL },
    { "UDS_FILE_PATH", CT_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "CT_TYPE_VARCHAR", NULL, PARAM_UDS_FILE_PATH,
      EFFECT_REBOOT, CFG_INS, sql_verify_als_uds_file_path, NULL, NULL, NULL },
    { "UDS_FILE_PERMISSIONS", CT_TRUE, ATTR_NONE, "600", NULL, NULL, "-", "[600-777]", "CT_TYPE_INTEGER", NULL,
      PARAM_UDS_FILE_PERMISSIONS, EFFECT_REBOOT, CFG_INS, sql_verify_als_uds_file_permissions, NULL, NULL, NULL },
    { "STATS_COST_LIMIT", CT_TRUE, ATTR_NONE, "0", NULL, NULL, "-", "[0,4294967295]", "CT_TYPE_INTEGER", NULL,
      PARAM_STATS_COST_LIMIT, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_uint32, sql_notify_als_cost_limit, NULL,
      NULL },
    { "STATS_COST_DELAY", CT_TRUE, ATTR_NONE, "0", NULL, NULL, "-", "[0,4294967295]", "CT_TYPE_INTEGER", NULL,
      PARAM_STATS_COST_DELAY, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_uint32, sql_notify_als_cost_delay, NULL,
      NULL },
    { "ENABLE_SAMPLE_LIMIT", CT_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_ENABLE_SAMPLE_LIMIT, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_enable_sample_limit,
      sql_notify_als_bool, NULL },
    /* parameters between master and slave */
    { "MASTER_SLAVE_DIFFTIME", CT_TRUE, ATTR_NONE, "10", NULL, NULL, "-", "[0,4294967295]", "CT_TYPE_INTEGER", NULL,
      PARAM_MASTER_SLAVE_DIFFTIME, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_uint32,
      sql_notify_als_master_backup_synctime, NULL, NULL },
    { "WORKER_THREADS_SHRINK_THRESHOLD", CT_TRUE, ATTR_NONE, "1800", NULL, NULL, "-", "[0,4000000]", "CT_TYPE_INTEGER",
      NULL, PARAM_WORKER_THREADS_SHRINK_THRESHOLD, EFFECT_REBOOT, CFG_INS, sql_verify_als_agent_shrink_threshold, NULL,
      NULL, NULL },
    /* XA */
    { "XA_FORMAT_ID", CT_TRUE, ATTR_READONLY, "247", NULL, NULL, "-", "[0-9223372036854775807]", "CT_TYPE_BIGINT", NULL,
      PARAM_XA_FORMAT_ID, EFFECT_REBOOT, CFG_INS, sql_verify_als_xa_format_id, NULL, NULL, NULL },
    { "DEGRADE_SEARCH_MAP", CT_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_DEGRADE_SEARCH_MAP, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_degrade_search,
      sql_notify_als_bool, NULL },
    /* bind CPUs resource manager can use */
    { "CPU_NODE_BIND", CT_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "CT_TYPE_VARCHAR", NULL, PARAM_CPU_NODE_BIND,
      EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_cpu_node_bind, sql_notify_als_cpu_node_bind, NULL, NULL },
    /* resource management plan */
    { "RESOURCE_PLAN", CT_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "CT_TYPE_VARCHAR", NULL, PARAM_RESOURCE_PLAN,
      EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_comm, sql_notify_als_resource_plan, NULL, NULL },
    { "STATS_MAX_BUCKET_SIZE", CT_TRUE, ATTR_NONE, "254", NULL, NULL, "-", "[75,254]", "CT_TYPE_INTEGER", NULL,
      PARAM_STATS_MAX_BUCKET_SIZE, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_uint32, sql_notify_als_bucket_size, NULL,
      NULL },

    { "PARALLEL_POLICY", CT_TRUE, ATTR_NONE, "ON", NULL, NULL, "-", "OFF,ON", "CT_TYPE_VARCHAR", NULL,
      PARAM_PARALLEL_POLICY, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_onoff, sql_notify_als_parallel_policy,
      sql_notify_als_onoff, NULL },
    { "DELAY_CLEANOUT", CT_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_DELAY_CLEANOUT, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_delay_cleanout,
      sql_notify_als_bool, NULL },
    { "ENABLE_ACCESS_DC", CT_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_ENABLE_ACCESS_DC, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool_only_sys_allowed,
      sql_notify_als_access_dc_enable_bool, sql_notify_als_bool, NULL },
    { "_VIEW_ACCESS_DC", CT_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_VIEW_ACCESS_DC, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool_only_sys_allowed,
      sql_notify_als_view_access_dc_bool, sql_notify_als_bool, NULL },
    /* shard force rollback when execute IDU sql in trans failed */

    { "NODE_LOCK_STATUS", CT_TRUE, ATTR_READONLY, "NOLOCK", NULL, NULL, "-", "NOLOCK,SHARE,EXCLUSIVE",
      "CT_TYPE_VARCHAR", NULL, PARAM_NODE_LOCK_STATUS, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_node_lock_status,
      NULL, NULL, NULL },
    { "UNDO_TABLESPACE", CT_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "CT_TYPE_VARCHAR", NULL, PARAM_UNDO_TABLESPACE,
      EFFECT_REBOOT, CFG_INS, sql_verify_als_comm, sql_notify_als_undo_space, NULL, NULL },
    { "LOB_REUSE_THRESHOLD", CT_TRUE, ATTR_NONE, "80M", NULL, NULL, "-", "[4M,4G)", "CT_TYPE_INTEGER", NULL,
      PARAM_LOB_REUSE_THRESHOLD, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_lob_reuse_threshold,
      sql_notify_als_lob_reuse_threshold, NULL, NULL },
    { "ENABLE_LOCAL_INFILE", CT_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_ENABLE_LOCAL_INFILE, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_enable_local_infile, NULL,
      NULL },


    // array datatype
    { "ARRAY_STORAGE_OPTIMIZATION", CT_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_ARRAY_STORAGE_OPTIMIZATION, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool,
      sql_notify_als_enable_arr_store_opt, sql_notify_als_bool, NULL },

    // JSON
    { "_MAX_JSON_DYNAMIC_BUFFER_SIZE", CT_TRUE, ATTR_NONE, "1G", NULL, NULL, "-", "[1M,32T]", "CT_TYPE_INTEGER", NULL,
      PARAM_MAX_JSON_DYNAMIC_BUFFER_SIZE, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_json_dyn_buf_size,
      sql_notify_json_dyn_buf_size, NULL, NULL },
    { "STATS_PARALL_THREADS", CT_TRUE, ATTR_NONE, "2", NULL, NULL, "-", "[2,8]", "CT_TYPE_INTEGER", NULL,
      PARAM_STATS_PARALL_THREADS, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_stats_parall_threads,
      sql_notify_als_stats_parall_threads, NULL, NULL },
    { "STATS_ENABLE_PARALL", CT_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_STATS_ENABLE_PARALL, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_stats_enable_parall,
      NULL, NULL },
    { "_OUTER_JOIN_OPTIMIZATION", CT_TRUE, ATTR_NONE, "OFF", NULL, NULL, "-", "OFF,ON", "CT_TYPE_VARCHAR", NULL,
      PARAM_OUTER_JOIN_OPTIMIZATION, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_onoff, sql_notify_als_outer_join_opt,
      sql_notify_als_onoff, NULL },
    { "CBO_INDEX_CACHING", CT_TRUE, ATTR_NONE, "0", NULL, NULL, "-", "[0,100]", "CT_TYPE_INTEGER", NULL,
      PARAM_CBO_INDEX_CACHING, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_cbo_index_caching,
      sql_notify_als_cbo_index_caching, NULL, NULL },
    { "CBO_INDEX_COST_ADJ", CT_TRUE, ATTR_NONE, "100", NULL, NULL, "-", "[1,10000]", "CT_TYPE_INTEGER", NULL,
      PARAM_CBO_INDEX_COST_ADJ, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_cbo_index_cost_adj,
      sql_notify_als_cbo_index_cost_adj, NULL, NULL },
    { "CBO_PATH_CACHING", CT_TRUE, ATTR_NONE, "3", NULL, NULL, "-", "[1,16]", "CT_TYPE_INTEGER", NULL,
      PARAM_CBO_PATH_CACHING, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_cbo_path_caching,
      sql_notify_als_cbo_path_caching, NULL, NULL },
    { "_WITHAS_SUBQUERY", CT_TRUE, ATTR_NONE, "OPTIMIZER", NULL, NULL, "-", "OPTIMIZER,MATERIALIZE,INLINE",
      "CT_TYPE_VARCHAR", NULL, PARAM__WITHAS_SUBQUERY, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_withas_subquery,
      sql_notify_als_withas_subquery, NULL, NULL },
    { "MAX_PBL_FILE_SIZE", CT_TRUE, ATTR_NONE, "10M", NULL, NULL, "-", "[10M,100M]", "CT_TYPE_INTEGER", NULL,
      PARAM_PBL_FILE_SIZE, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_pbl_file_size, sql_notify_als_pbl_max_file_size,
      NULL, NULL },
    { "_DISTINCT_PRUNING", CT_TRUE, ATTR_NONE, "ON", NULL, NULL, "-", "OFF,ON", "CT_TYPE_VARCHAR", NULL,
      PARAM_DISTINCT_PRUNING, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_onoff, sql_notify_als_distinct_pruning,
      sql_notify_als_onoff, NULL },
    { "_QUERY_TOPN_THRESHOLD", CT_TRUE, ATTR_NONE, "1000", NULL, NULL, "-", "[0,10000]", "CT_TYPE_INTEGER", NULL,
      PARAM_QUERY_TOPN_THRESHOLD, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_topn_threshold,
      sql_notify_als_topn_threshold, NULL, NULL },
    { "_CONNECT_BY_MATERIALIZE", CT_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_OPTIM_CONNECT_BY_MTRL, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_connect_by_mtrl,
      sql_notify_als_bool, NULL },
    { "INIT_LOCK_POOL_PAGES", CT_TRUE, ATTR_NONE, "1024", NULL, NULL, "-", "[128,32K]", "CT_TYPE_INTEGER", NULL,
      PARAM_INIT_LOCKPOOL_PAGES, EFFECT_REBOOT, CFG_INS, sql_verify_init_lockpool_pages, sql_notify_init_lockpool_pages,
      NULL, NULL },
    { "_OPTIMIZER_AGGR_PLACEMENT", CT_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_OPTIM_AGGR_PLACEMENT, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_aggr_placement,
      sql_notify_als_bool, NULL },
    { "_OPTIM_OR_EXPANSION", CT_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_OPTIM_OR_EXPANSION, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_or_expansion,
      sql_notify_als_bool, NULL },
    { "_OPTIM_DISTINCT_ELIMINATION", CT_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_OPTIM_DISTINCT_ELIMINATION, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool,
      sql_notify_als_distinct_elimination, sql_notify_als_bool, NULL },
    { "_OPTIM_PROJECT_LIST_PRUNING", CT_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_OPTIM_PROJECT_LIST_PRUNING, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool,
      sql_notify_als_project_list_pruning, sql_notify_als_bool, NULL },
    { "_OPTIM_PRED_MOVE_AROUND", CT_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_OPTIM_PRED_MOVE_AROUND, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_pred_move_around,
      sql_notify_als_bool, NULL },
    { "_OPTIM_HASH_MATERIALIZE", CT_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_OPTIM_HASH_MTRL, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_hash_mtrl,
      sql_notify_als_bool, NULL },
    { "_OPTIM_WINMAGIC_REWRITE", CT_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_OPTIM_WINMAGIC_REWRITE, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_winmagic_rewrite,
      sql_notify_als_bool, NULL },
    { "_OPTIM_PRED_REORDER", CT_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_OPTIM_PRED_REORDER, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_pred_reorder,
      sql_notify_als_bool, NULL },
    { "_OPTIM_ORDER_BY_PLACEMENT", CT_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_OPTIM_ORDER_BY_PLACEMENT, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool,
      sql_notify_als_order_by_placement, sql_notify_als_bool, NULL },
    { "_OPTIM_SUBQUERY_ELIMINATION", CT_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_OPTIM_SUBQUERY_ELIMINATION, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool,
      sql_notify_als_subquery_elimination, sql_notify_als_bool, NULL },
    { "_OPTIM_JOIN_ELIMINATION", CT_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_OPTIM_JOIN_ELIMINATION, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_join_elimination,
      sql_notify_als_bool, NULL },
    { "_OPTIM_CONNECT_BY_PLACEMENT", CT_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_OPTIM_CONNECT_BY_PLACEMENT, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool,
      sql_notify_als_connect_by_placement, sql_notify_als_bool, NULL },
    { "_OPTIM_GROUP_BY_ELIMINATION", CT_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_OPTIM_GROUP_BY_ELIMINATION, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool,
      sql_notify_als_group_by_elimination, sql_notify_als_bool, NULL },
    { "_OPTIM_ANY_TRANSFORM", CT_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_OPTIM_ANY_TRANSFORM, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_optim_any_transform,
      sql_notify_als_bool, NULL },
    { "_OPTIM_ALL_TRANSFORM", CT_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_OPTIM_ALL_TRANSFORM, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_optim_all_transform,
      sql_notify_als_bool, NULL },
    { "_ENABLE_MULTI_INDEX_SCAN", CT_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_ENABLE_MULTI_INDEX_SCAN, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_multi_index_scan,
      sql_notify_als_bool, NULL },
    { "_OPTIM_JOIN_PRED_PUSHDOWN", CT_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_OPTIM_JOIN_PRED_PUSHDOWN, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool,
      sql_notify_als_join_pred_pushdown, sql_notify_als_bool, NULL },
    { "_OPTIM_FILTER_PUSHDOWN", CT_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_OPTIM_FILTER_PUSHDOWN, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_filter_pushdown,
      sql_notify_als_bool, NULL },
    { "_OPTIM_INDEX_SCAN_MAX_PARTS", CT_TRUE, ATTR_NONE, "200", NULL, NULL, "-", "[0, 900]", "CT_TYPE_INTEGER", NULL,
      PARAM_OPTIM_INDEX_SCAN_MAX_PARTS, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_multi_parts_scan,
      sql_notify_als_multi_parts_scan, NULL, NULL },
    { "_OPTIM_ORDER_BY_ELIMINATION", CT_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_OPTIM_ORDER_BY_ELIMINATION, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool,
      sql_notify_als_order_by_elimination, sql_notify_als_bool, NULL },
    { "_OPTIM_UNNEST_SET_SUBQUERY", CT_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_OPTIM_UNNEST_SET_SUBQ, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_unnest_set_subquery,
      sql_notify_als_bool, NULL },
    { "_OPTIM_ENABLE_RIGHT_SEMIJOIN", CT_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN",
      NULL, PARAM_OPTIM_ENABLE_RIGHT_SEMIJOIN, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool,
      sql_notify_als_enable_right_semijoin, sql_notify_als_bool, NULL },
    { "_OPTIM_ENABLE_RIGHT_ANTIJOIN", CT_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN",
      NULL, PARAM_OPTIM_ENABLE_RIGHT_ANTIJOIN, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool,
      sql_notify_als_enable_right_antijoin, sql_notify_als_bool, NULL },
    { "_OPTIM_ENABLE_RIGHT_LEFTJOIN", CT_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN",
      NULL, PARAM_OPTIM_ENABLE_RIGHT_LEFTJOIN, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool,
      sql_notify_als_enable_right_leftjoin, sql_notify_als_bool, NULL },
    { "SEGMENT_PAGES_HOLD", CT_TRUE, ATTR_NONE, "0", NULL, NULL, "-", "[0,10000]", "CT_TYPE_INTEGER", NULL,
      PARAM_SEGMENT_PAGES_HOLD, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_seg_pages_hold,
      sql_notify_als_seg_pages_hold, NULL, NULL },
    { "HASH_TABLE_PAGES_HOLD", CT_TRUE, ATTR_NONE, "128", NULL, NULL, "-", "[0,10000]", "CT_TYPE_INTEGER", NULL,
      PARAM_HASH_PAGES_HOLD, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_hash_pages_hold,
      sql_notify_als_hash_pages_hold, NULL, NULL },
    { "_OPTIM_SIMPLIFY_EXISTS_SUBQ", CT_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_OPTIM_SIMPLIFY_EXISTS_SUBQ, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool,
      sql_notify_als_simplify_exists_subq, sql_notify_als_bool, NULL },
    // ctrl info backup parameter
    { "CTRLLOG_BACKUP_LEVEL", CT_TRUE, ATTR_NONE, "NONE", NULL, NULL, "-", "NONE,TYPICAL,FULL", "CT_TYPE_VARCHAR",
      NULL, PARAM_CTRLLOG_BACKUP_LEVEL, EFFECT_REBOOT, CFG_INS, sql_verify_als_ctrllog_backup_level,
      sql_notify_ctrllog_backup_level, NULL, NULL },
    { "_OPTIM_FUNC_INDEX_SCAN_ONLY", CT_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_ENABLE_FUNC_INDEX_SCAN_ONLY, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool,
      sql_notify_als_func_index_scan, sql_notify_als_bool, NULL },
    { "_OPTIM_INDEX_COND_PRUNING", CT_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_ENABLE_INDEX_COND_PRUNING, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool,
      sql_notify_als_index_cond_pruning, sql_notify_als_bool, NULL },
    { "_OPTIM_VM_VIEW_ENABLED", CT_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_OPTIM_VM_VIEW_ENABLED, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_vm_view_mtrl,
      sql_notify_als_bool, NULL },
    { "_OPTIM_ADAPTIVE_FULL_OUTER_JOIN", CT_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN",
      NULL, PARAM_ENABLE_NL_FULL_OPTIMIZATION, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool,
      sql_notify_als_nl_full_opt, sql_notify_als_bool, NULL },
    { "_TABLE_COMPRESS_ALGO", CT_TRUE, ATTR_NONE, "NONE", NULL, NULL, "-", "NONE,ZSTD", "CT_TYPE_VARCHAR", NULL,
      PARAM_TABLE_COMPRESS_ALGO, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_compress_algo,
      sql_notify_als_compress_algo, NULL, NULL },
    { "_TABLE_COMPRESS_BUFFER_SIZE", CT_TRUE, ATTR_NONE, "16M", NULL, NULL, "-", "[16M,1G]", "CT_TYPE_INTEGER", NULL,
      PARAM_TABLE_COMPRESS_BUF_SIZE, EFFECT_REBOOT, CFG_INS, sql_verify_als_compress_buf_size,
      sql_notify_als_compress_buf_size, NULL, NULL },
    { "_TABLE_COMPRESS_ENABLE_BUFFER", CT_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN",
      NULL, PARAM_TABLE_COMPRESS_ENABLE_BUF, EFFECT_REBOOT, CFG_INS, sql_verify_als_bool,
      sql_notify_als_compress_enable_buf, NULL, NULL },
    { "ENABLE_PASSWORD_CIPHER", CT_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE, TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_ENABLE_PASSWORD_CIPHER, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool,
      sql_notify_als_enable_password_cipher, sql_notify_als_bool, NULL },
    { "CBO_HINT_ENABLED", CT_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE, TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_ENABLE_CBO_HINT, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_enable_cbo_hint,
      sql_notify_als_bool, NULL },
    { "PARALLEL_MAX_THREADS", CT_TRUE, ATTR_NONE, "16", NULL, NULL, "-", "[0,4096]", "CT_TYPE_INTEGER", NULL,
      PARAM_PARALLEL_MAX_THREADS, EFFECT_REBOOT, CFG_INS, sql_verify_als_parall_max_threads,
      sql_notify_als_parall_max_threads, NULL, NULL },
    { "CBO_DYNAMIC_SAMPLING", CT_TRUE, ATTR_NONE, "1", NULL, NULL, "-", "[0,9]", "CT_TYPE_INTEGER", NULL,
      PARAM_CBO_DYNAMIC_SAMPLING, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_cbo_dyn_sampling,
      sql_notify_als_cbo_dyn_sampling, NULL, NULL },
    { "_STRICT_CASE_DATATYPE", CT_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE, TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_STRICT_CASE_DATATYPE, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_strict_case_datatype,
      sql_notify_als_bool, NULL },

    // dblink
    { "MAX_LINK_TABLES", CT_TRUE, ATTR_NONE, "32", NULL, NULL, "-", "[0,1024]", "CT_TYPE_INTEGER", NULL,
      PARAM_MAX_LINK_TABLES, EFFECT_REBOOT, CFG_INS, sql_verify_als_max_link_tables, NULL, NULL, NULL },
    // priv
    { "AUTO_INHERIT_USER", CT_TRUE, ATTR_NONE, "OFF", NULL, NULL, "-", "OFF,ON", "CT_TYPE_VARCHAR", NULL,
      PARAM_AUTO_INHERIT, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_onoff, sql_notify_als_auto_inherit,
      sql_notify_als_onoff, NULL },
    { "REPLACE_PASSWORD_VERIFY", CT_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE, TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_REPLACE_PASSWORD_VERIFY, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_password_verify, NULL,
      NULL },

    // DTC
    { "CLUSTER_DATABASE", CT_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_CLUSTER_DATABASE, EFFECT_REBOOT, CFG_INS, sql_verify_als_bool, sql_notify_als_bool, sql_notify_als_bool,
      NULL },
    { "INTERCONNECT_ADDR", CT_TRUE, ATTR_NONE, "127.0.0.1", NULL, NULL, "-", "-", "CT_TYPE_VARCHAR", NULL,
      PARAM_INTERCONNECT_ADDR, EFFECT_REBOOT, CFG_INS, sql_verify_als_ip, NULL, NULL, NULL },
    { "INTERCONNECT_PORT", CT_TRUE, ATTR_NONE, "1611", NULL, NULL, "-", "[1024,65535]", "CT_TYPE_INTEGER", NULL,
      PARAM_INTERCONNECT_PORT, EFFECT_REBOOT, CFG_INS, sql_verify_als_interconnect_port, NULL, NULL, NULL },
    { "INTERCONNECT_TYPE", CT_TRUE, ATTR_NONE, "TCP", NULL, NULL, "-", "TCP,UC,UC_RDMA", "CT_TYPE_VARCHAR", NULL,
      PARAM_INTERCONNECT_TYPE, EFFECT_REBOOT, CFG_INS, sql_verify_als_interconnect_type, NULL, NULL, NULL },
    { "INTERCONNECT_CHANNEL_NUM", CT_TRUE, ATTR_NONE, "1", NULL, NULL, "-", "[1,32]", "CT_TYPE_INTEGER", NULL,
      PARAM_INTERCONNECT_CHANNEL_NUM, EFFECT_REBOOT, CFG_INS, sql_verify_als_uint32, NULL, NULL, NULL },
    { "REACTOR_THREAD_NUM", CT_TRUE, ATTR_NONE, "2", NULL, NULL, "-", "[1,32]", "CT_TYPE_INTEGER", NULL,
      PARAM_REACTOR_THREAD_NUM, EFFECT_REBOOT, CFG_INS, sql_verify_als_uint32, NULL, NULL, NULL },
    { "ENABLE_TX_FREE_PAGE_LIST", CT_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_TX_FREE_PAGE_LIST, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool,
      sql_notify_als_enable_tx_free_page_list, sql_notify_als_bool, NULL},
    { "DAAC_TASK_NUM", CT_TRUE, ATTR_NONE, "16", NULL, NULL, "-", "[1,500]", "CT_TYPE_INTEGER", NULL,
      PARAM_DAAC_TASK_NUM, EFFECT_REBOOT, CFG_INS, sql_verify_als_uint32, NULL, NULL, NULL },
    { "INSTANCE_ID", CT_TRUE, ATTR_NONE, "0", NULL, NULL, "-", "[0,63]", "CT_TYPE_INTEGER", NULL, PARAM_INSTANCE_ID,
      EFFECT_REBOOT, CFG_INS, sql_verify_als_uint32, NULL, NULL, NULL },
    { "MES_POOL_SIZE", CT_TRUE, ATTR_NONE, "256", NULL, NULL, "-", "[256,16384]", "CT_TYPE_INTEGER", NULL,
      PARAM_MES_POOL_SIZE, EFFECT_REBOOT, CFG_INS, sql_verify_als_uint32, NULL, NULL, NULL },
    { "CTSTORE_INST_PATH", CT_TRUE, ATTR_NONE, "UDS:/tmp/.ctstore_unix_d_socket", NULL, NULL, "-", "-", "CT_TYPE_VARCHAR", NULL,
      PARAM_CTSTORE_INST_PATH, EFFECT_REBOOT, CFG_INS, sql_verify_als_uds_file_path, NULL, NULL, NULL },
    { "INTERCONNECT_BY_PROFILE", CT_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_INTERCONNECT_BY_PROFILE, EFFECT_REBOOT, CFG_INS, sql_verify_als_bool, NULL, NULL, NULL },
    { "MES_ELAPSED_SWITCH", CT_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_MES_ELAPSED_SWITCH, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_mes_elapsed_switch,
      sql_notify_als_bool, NULL },
    { "MES_CRC_CHECK_SWITCH", CT_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_MES_CRC_CHECK_SWITCH, EFFECT_REBOOT, CFG_INS, sql_verify_als_bool, sql_notify_als_bool, sql_notify_als_bool, NULL },
    { "CTSTORE_MAX_OPEN_FILES", CT_TRUE, ATTR_NONE, "1024", NULL, NULL, "-", "(0, 1000000]", "CT_TYPE_INTEGER", NULL,
      PARAM_CTSTORE_MAX_OPEN_FILES, EFFECT_REBOOT, CFG_INS, sql_verify_als_uint32, NULL, NULL, NULL },
    { "_ENABLE_RMO_CR", CT_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_ENABLE_RMO_CR, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_enable_rmo_cr,
      sql_notify_als_bool, NULL },
    { "_REMOTE_ACCESS_LIMIT", CT_TRUE, ATTR_NONE, "4", NULL, NULL, "-", "[0, 255]", "CT_TYPE_INTEGER", NULL,
      PARAM_REMOTE_ACCESS_LIMIT, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_remote_access_limit,
      sql_notify_als_remote_access_limit, NULL, NULL },
    { "CT_GDV_SQL_SESS_TMOUT", CT_TRUE, ATTR_NONE, "10", NULL, NULL, "-", "[0, 1000]", "CT_TYPE_INTEGER", NULL,
      PARAM_GDV_SQL_SESS_TMOUT, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_uint32, sql_notify_als_gdv_sess_tmout,
      sql_notify_als_bool, NULL },
    { "DTC_CKPT_NOTIFY_TASK_RATIO", CT_TRUE, ATTR_NONE, "0.125", NULL, NULL, "-", "[0.001,0.999]", "CT_TYPE_REAL", NULL,
      PARAM_DTC_CKPT_NOTIFY_TASK_RATIO, EFFECT_REBOOT, CFG_INS, sql_verify_als_mes_task_ratio, NULL, NULL, NULL },
    { "DTC_CLEAN_EDP_TASK_RATIO", CT_TRUE, ATTR_NONE, "0.125", NULL, NULL, "-", "[0.001,0.999]", "CT_TYPE_REAL", NULL,
      PARAM_DTC_CLEAN_EDP_TASK_RATIO, EFFECT_REBOOT, CFG_INS, sql_verify_als_mes_task_ratio, NULL, NULL, NULL },
    { "DTC_TXN_INFO_TASK_RATIO", CT_TRUE, ATTR_NONE, "0.25", NULL, NULL, "-", "[0.001,0.999]", "CT_TYPE_REAL", NULL,
      PARAM_DTC_TXN_INFO_TASK_RATIO, EFFECT_REBOOT, CFG_INS, sql_verify_als_mes_task_ratio, NULL, NULL, NULL },
    { "RCY_NODE_READ_BUF_SIZE", CT_TRUE, ATTR_NONE, "4", NULL, NULL, "-", "[2,10]", "CT_TYPE_INTEGER", NULL,
    PARAM_RCY_NODE_READ_BUF_SIZE, EFFECT_REBOOT, CFG_INS, sql_verify_rcy_read_buf_size, NULL,
    NULL, NULL },
    /* SHM MQ */
    { "SHM_MQ_MSG_RECV_THD_NUM",    CT_TRUE, ATTR_NONE,     "200",     NULL, NULL, "-", "[1, 1024]",          "CT_TYPE_INTEGER", NULL, PARAM_SHM_MQ_MSG_RECV_THD_NUM,     EFFECT_REBOOT,      CFG_INS, sql_verify_als_mq_thd_num,    NULL, NULL, NULL },
    { "SHM_MQ_MSG_QUEUE_NUM",       CT_TRUE, ATTR_NONE,     "8",      NULL, NULL, "-", "[1, 64]",            "CT_TYPE_INTEGER", NULL, PARAM_SHM_MQ_MSG_QUEUE_NUM,        EFFECT_REBOOT,      CFG_INS, sql_verify_als_mq_queue_num,  NULL, NULL, NULL },
    { "SHM_MQ_MSG_THD_COOL_TIME_US",       CT_TRUE, ATTR_NONE,     "100000",      NULL, NULL, "-", "[0, -)",            "CT_TYPE_INTEGER", NULL, PARAM_SHM_MQ_MSG_THD_COOL_TIME_US,        EFFECT_REBOOT,      CFG_INS, sql_verify_als_mq_thd_cool_time,  NULL, NULL, NULL },
    { "SHM_CPU_GROUP_INFO",     CT_TRUE, ATTR_NONE, "0", NULL, NULL, "-", "-", "CT_TYPE_VARCHAR", NULL, PARAM_SHM_CPU_GROUP_INFO, EFFECT_REBOOT, CFG_INS, sql_verify_als_cpu_inf_str, NULL, NULL, NULL },
    { "SHM_MYSQL_CPU_GROUP_INFO",     CT_TRUE, ATTR_NONE, "0", NULL, NULL, "-", "-", "CT_TYPE_VARCHAR", NULL, PARAM_SHM_MYSQL_CPU_GROUP_INFO, EFFECT_REBOOT, CFG_INS, sql_verify_als_cpu_inf_str, NULL, NULL, NULL },
    /* CTC */
    { "CTC_MAX_INST_PER_NODE", CT_TRUE, ATTR_NONE, "6", NULL, NULL, "-", "[1, 64]", "CT_TYPE_INTEGER", NULL, PARAM_CTC_MAX_INST_PER_NODE, EFFECT_REBOOT, CFG_INS, sql_verify_als_ctc_inst_num, NULL, NULL, NULL},

    /* deadlock */
    { "_DEADLOCK_DETECT_INTERVAL",    CT_TRUE, ATTR_NONE,     "1000",    NULL, NULL, "-", "1,10,100,1000",    "CT_TYPE_INTEGER", NULL, PARAM_DEADLOCK_DETECT_INTERVAL,     EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_deadlock_detect_interval,   sql_notify_als_deadlock_detect_interval,   NULL, NULL },

    { "_AUTO_UNDO_RETENTION",    CT_TRUE, ATTR_NONE,     "3",    NULL, NULL, "-", "[0, -)",    "CT_TYPE_INTEGER", NULL,
      PARAM_AUTO_UNDO_RETENTION,     EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_auto_undo_retention,
      sql_notify_als_auto_undo_retention,   NULL, NULL },

    { "SHARED_PATH",            CT_TRUE, ATTR_READONLY, "",     NULL, NULL, "-", "-",                      "CT_TYPE_VARCHAR", NULL, PARAM_SHARED_PATH, EFFECT_REBOOT, CFG_DB,  sql_verify_als_comm,                    NULL,                        NULL, NULL },
    /* dbstor */
    { "ENABLE_DBSTOR", CT_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_ENABLE_DBSTORE, EFFECT_REBOOT, CFG_INS, sql_verify_als_bool, NULL, NULL, NULL },
    { "DBSTOR_NAMESPACE", CT_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "CT_TYPE_VARCHAR", NULL,
      PARAM_DBSTORE_NAMESPACE, EFFECT_REBOOT, CFG_INS, sql_verify_als_comm, NULL, NULL, NULL },
    { "COMPATIBLE_MYSQL",    CT_TRUE, ATTR_READONLY,     "1",    NULL, NULL, "-", "[0, 1]",    "CT_TYPE_INTEGER", NULL,
      PARAM_COMPATIBLE_MYSQL,     EFFECT_REBOOT, CFG_INS, sql_verify_als_compatible_mysql,
      sql_notify_als_compatible_mysql,   NULL, NULL },
    { "ENABLE_IO_RECORD", CT_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_ENABLE_IO_RECORD, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_io_record,
      sql_notify_als_bool, NULL },
    { "PAGE_CLEAN_MODE", CT_TRUE, ATTR_NONE, "SINGLE", NULL, NULL, "-", "SINGLE,ALL", "CT_TYPE_VARCHAR", NULL,
      PARAM_PAGE_CLEAN_MODE, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_page_clean_mode, sql_notify_als_page_clean_mode,
      NULL, NULL },
    { "ENABLE_DBSTOR_BATCH_FLUSH", CT_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_ENABLE_DBSTOR_BATCH_FLUSH, EFFECT_REBOOT, CFG_INS, sql_verify_als_bool, NULL,
      NULL, NULL },
    { "CLUSTER_ID", CT_TRUE, ATTR_NONE, "0", NULL, NULL, "-", "[0,65535]", "CT_TYPE_INTEGER", NULL,
      PARAM_CLUSTER_ID, EFFECT_REBOOT, CFG_INS, sql_verify_als_uint32, NULL, NULL, NULL},
    { "BACKUP_RETRY", CT_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_BACKUP_RETRY, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool, sql_notify_als_bool,
      sql_notify_als_bool, NULL },
    { "BATCH_FLUSH_CAPACITY", CT_TRUE, ATTR_NONE, "160", NULL, NULL, "-", "[1,4096]", "CT_TYPE_INTEGER", NULL,
      PARAM_BATCH_FLUSH_CAPACITY, EFFECT_REBOOT, CFG_INS, sql_verify_als_batch_flush_capacity,
      NULL, NULL, NULL },
    { "ENABLE_HWN_CHANGE", CT_TRUE, ATTR_READONLY, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_ENABLE_HWN_CHANGE, EFFECT_REBOOT, CFG_INS, sql_verify_als_bool, NULL, NULL, NULL },
    { "MES_CHANNEL_UPGRADE_TIME_MS", CT_TRUE, ATTR_NONE, "0", NULL, NULL, "-", "-", "CT_TYPE_INTEGER", NULL,
      PARAM_MES_CHANNEL_UPGRADE_TIME_MS, EFFECT_REBOOT, CFG_INS, sql_verify_als_uint32, NULL, NULL, NULL },
    { "MES_CHANNEL_DEGRADE_TIME_MS", CT_TRUE, ATTR_NONE, "0", NULL, NULL, "-", "-", "CT_TYPE_INTEGER", NULL,
      PARAM_MES_CHANNEL_DEGRADE_TIME_MS, EFFECT_REBOOT, CFG_INS, sql_verify_als_uint32, NULL, NULL, NULL },
    { "ENABLE_FDSA", CT_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_ENABLE_FDSA, EFFECT_REBOOT, CFG_INS, sql_verify_als_bool, sql_notify_als_bool, sql_notify_als_bool, NULL },
    { "ENABLE_BROADCAST_ON_COMMIT", CT_TRUE, ATTR_NONE, "TRUE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_ENABLE_BROADCAST_ON_COMMIT, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool,
      sql_notify_enable_broadcast_on_commit, sql_notify_als_bool, NULL },
    /* if you need add param here, position must keep pace with enum param_global_t */
    { "MES_SSL_SWITCH", CT_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_MES_SSL_SWITCH, EFFECT_REBOOT, CFG_INS, sql_verify_als_bool, NULL, NULL, NULL },
    { "MES_SSL_CRT_KEY_PATH", CT_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "CT_TYPE_VARCHAR", NULL,
      PARAM_MES_SSL_CRT_KEY_PATH, EFFECT_REBOOT, CFG_INS, sql_verify_als_file_dir, NULL, NULL, NULL },
    { "MES_SSL_KEY_PWD", CT_TRUE, ATTR_NONE, "", NULL, NULL, "-", "-", "CT_TYPE_VARCHAR", NULL, PARAM_MES_SSL_KEY_PWD,
      EFFECT_REBOOT, CFG_INS, sql_verify_als_comm, NULL, NULL, NULL },
    { "ENABLE_CHECK_SECURITY_LOG", CT_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "CT_TYPE_BOOLEAN", NULL,
      PARAM_ENABLE_CHECK_SECURITY_LOG, EFFECT_IMMEDIATELY, CFG_INS, sql_verify_als_bool,
      sql_notify_enable_enable_check_security_log, sql_notify_als_bool, NULL },
    { "MYSQL_DEPLOY_GROUP_ID", CT_TRUE, ATTR_NONE, "5000", NULL, NULL, "-", NULL, "GS_TYPE_VARCHAR", NULL,
      PARAM_MYSQL_DEPLOY_GROUP_ID, EFFECT_REBOOT, CFG_INS, sql_verify_als_uint32, NULL, NULL, NULL },
    { "ENABLE_SYS_CRC_CHECK", CT_TRUE, ATTR_NONE, "FALSE", NULL, NULL, "-", "FALSE,TRUE", "GS_TYPE_BOOLEAN", NULL,
      PARAM_ENABLE_CHECK_SECURITY_LOG, EFFECT_REBOOT, CFG_INS, sql_verify_als_bool,
      sql_notify_enable_crc_check, sql_notify_als_bool, NULL },
};

void srv_get_config_info(config_item_t **params, uint32 *count)
{
    *params = g_parameters;
    *count = sizeof(g_parameters) / sizeof(config_item_t);
}

void init_runtime_params(void)
{
    config_t g_instance_conf = g_instance->config;
    config_item_t *item = NULL;
    int params_size = sizeof(g_parameters) / sizeof(config_item_t);

    for (int i = 0; i < params_size; ++i) {
        item = &g_instance_conf.items[i];
        if (item == NULL) {
            continue;
        }

        if (item->is_default) {
            item->runtime_value = item->default_value;
        }
    }
}

/* these parameters are only used for testing, effect immediately and do not write config file. */
debug_config_item_t g_debug_parameters[] = {
        /* name                  default value    current value    range           type                  verify notify
         */
    { "_MRP_RES_LOGSIZE",    "0",             "0",             "[0,32T]",      "CT_TYPE_INTEGER",    sql_verify_als_lrpl_res_logsize,    sql_notify_als_lrpl_res_logsize },
};

void srv_get_debug_config_info(debug_config_item_t **params, uint32 *count)
{
    *params = g_debug_parameters;
    *count = sizeof(g_debug_parameters) / sizeof(debug_config_item_t);
}

status_t sql_verify_rcy_read_buf_size(void *se, void *lex, void *def)
{
    uint32 num;
    if (sql_verify_uint32(lex, def, &num) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (num < CT_MIN_RCY_NODE_BUF_SIZE) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "RCY_NODE_READ_BUF_SIZE", (int64)CT_MIN_RCY_NODE_BUF_SIZE);
        return CT_ERROR;
    }
    if (num > CT_MAX_RCY_NODE_BUF_SIZE) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "RCY_NODE_READ_BUF_SIZE", (int64)CT_MAX_RCY_NODE_BUF_SIZE);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t verify_uds_temp_path(const char *path, char *input_path, char *temp_path, uint32 len)
{
    char dir_path[CT_UNIX_PATH_MAX];
    if (temp_path[1] == ' ') {
        CT_THROW_ERROR(ERR_INVALID_DIR, input_path);
        return CT_ERROR;
    }
    if (strlen(temp_path) == 2 && (temp_path[1] == '.' || temp_path[1] == '\t')) {
        CT_THROW_ERROR(ERR_INVALID_DIR, path);
        return CT_ERROR;
    }

    if (strlen(temp_path) == len) {
        if (access("/", W_OK | R_OK) != 0) {
            CT_THROW_ERROR(ERR_PATH_NOT_ACCESSABLE, temp_path);
            return CT_ERROR;
        }
    } else {
        MEMS_RETURN_IFERR(strncpy_s(dir_path, CT_UNIX_PATH_MAX, path, len - strlen(temp_path)));

        if (!cm_dir_exist(dir_path)) {
            CT_THROW_ERROR(ERR_PATH_NOT_EXIST, dir_path);
            return CT_ERROR;
        }
        char buffer_path[CT_UNIX_PATH_MAX];
        CT_RETURN_IFERR(realpath_file(dir_path, buffer_path, CT_UNIX_PATH_MAX));
        if (access(buffer_path, W_OK | R_OK) != 0) {
            CT_THROW_ERROR(ERR_PATH_NOT_ACCESSABLE, dir_path);
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

status_t verify_uds_file_path(const char *path)
{
    char realfile[CT_UNIX_PATH_MAX];
    char input_path_buffer[CT_UNIX_PATH_MAX];
    char *input_path;
    uint32 len;
    len = (uint32)strlen(path);
    CT_RETSUC_IFTRUE(len == 0);
    if (len >= CT_UNIX_PATH_MAX) {
        CT_THROW_ERROR(ERR_INVALID_FILE_NAME, path, CT_UNIX_PATH_MAX);
        return CT_ERROR;
    }

    if (len == 1 && (path[0] == '.' || path[0] == '\t')) {
        CT_THROW_ERROR(ERR_INVALID_DIR, path);
        return CT_ERROR;
    }

    input_path = input_path_buffer;
    MEMS_RETURN_IFERR(strcpy_s(input_path, CT_UNIX_PATH_MAX, path));
    if (len > 1 && (CM_IS_QUOTE_STRING(input_path[0], input_path[len - 1]))) {
        input_path++;
        len -= 2;
    }

    if (len == 0 || input_path[0] == ' ' || input_path[len - 1] == '/') {
        CT_THROW_ERROR(ERR_INVALID_DIR, path);
        return CT_ERROR;
    }

    input_path[len] = '\0';
    if (cm_check_uds_path_special_char(input_path, len)) {
        CT_THROW_ERROR(ERR_INVALID_DIR, input_path);
        return CT_ERROR;
    }

    CT_RETURN_IFERR(realpath_file(input_path, realfile, CT_UNIX_PATH_MAX));
    if (cm_file_exist((const char *)realfile)) {
        CT_THROW_ERROR(ERR_FILE_HAS_EXIST, realfile);
        return CT_ERROR;
    }

    char *temp_path = strrchr(input_path, '/');
    if (temp_path != NULL) {
        CT_RETURN_IFERR(verify_uds_temp_path(path, input_path, temp_path, len));
    }
    return CT_SUCCESS;
}

status_t verify_uds_file_permission(uint16 permission)
{
    uint16 num = permission;
    uint16 usr_perm;
    uint16 grp_perm;
    uint16 oth_perm;
    usr_perm = (num / 100) % 10;
    grp_perm = (num / 10) % 10;
    oth_perm = num % 10;
    if (usr_perm > CT_MAX_LOG_USER_PERMISSION || grp_perm > CT_MAX_LOG_USER_PERMISSION ||
        oth_perm > CT_MAX_LOG_USER_PERMISSION) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "UDS_FILE_PERMISSIONS");
        return CT_ERROR;
    }

    if (num < CT_DEF_UDS_FILE_PERMISSIONS || num > CT_MAX_UDS_FILE_PERMISSIONS) {
        CT_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "UDS_FILE_PERMISSIONS", (int64)CT_DEF_UDS_FILE_PERMISSIONS,
            (int64)CT_MAX_UDS_FILE_PERMISSIONS);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t verify_file_path(const char *path)
{
    char input_path_buffer[CT_FILE_NAME_BUFFER_SIZE];
    char *input_path = NULL;
    uint32 len;
    len = (uint32)strlen(path);
    if (len == 0 || len >= CT_FILE_NAME_BUFFER_SIZE) {
        CT_THROW_ERROR(ERR_INVALID_FILE_NAME, path, CT_FILE_NAME_BUFFER_SIZE);
        return CT_ERROR;
    }

    if (len == 1 && (path[0] == '.' || path[0] == '\t')) {
        CT_THROW_ERROR(ERR_INVALID_DIR, path);
        return CT_ERROR;
    }

    input_path = input_path_buffer;
    MEMS_RETURN_IFERR(strcpy_s(input_path, CT_FILE_NAME_BUFFER_SIZE, path));
    if (len > 1 && (CM_IS_QUOTE_STRING(input_path[0], input_path[len - 1]))) {
        input_path++;
        len -= CM_SINGLE_QUOTE_LEN;
    }

    if (len == 0 || input_path[0] == ' ') {
        CT_THROW_ERROR(ERR_INVALID_DIR, path);
        return CT_ERROR;
    }

    input_path[len] = '\0';
    if (cm_check_exist_special_char(input_path, len)) {
        CT_THROW_ERROR(ERR_INVALID_DIR, input_path);
        return CT_ERROR;
    }

    char buffer_path[CT_FILE_NAME_BUFFER_SIZE];
    CT_RETURN_IFERR(realpath_file(input_path, buffer_path, CT_FILE_NAME_BUFFER_SIZE));
    if (!cm_dir_exist(input_path) || (access(buffer_path, W_OK | R_OK) != 0)) {
        CT_THROW_ERROR(ERR_PATH_NOT_EXIST_OR_ACCESSABLE, input_path);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

plan_format_t g_plan_format_tab[] = {
    { { (char *)"BASIC", 5 }, PLAN_FORMAT_BASIC },
    { { (char *)"TYPICAL", 7 }, PLAN_FORMAT_TYPICAL },
    { { (char *)"ALL", 3 }, PLAN_FORMAT_ALL },
};

plan_format_t g_plan_option_tab[] = {
    { { (char *)"PREDICATE", 9 }, PLAN_FORMAT_PREDICATE },
    { { (char *)"QUERY_BLOCK", 11 }, PLAN_FORMAT_QUERY_BLOCK },
    { { (char *)"OUTLINE", 7 }, PLAN_FORMAT_OUTLINE },
};

#define PLAN_DISPLAY_FORMAT_COUNT ELEMENT_COUNT(g_plan_format_tab)
#define PLAN_DISPLAY_OPTION_COUNT ELEMENT_COUNT(g_plan_option_tab)

status_t sql_notify_als_plan_display_format(void *se, void *item, char *value)
{
    sql_set_plan_display_format(value, &g_instance->sql.plan_display_format);
    return CT_SUCCESS;
}

status_t sql_verify_als_plan_display_format(void *se, void *lex, void *def)
{
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;
    uint32 format_index = CT_INVALID_ID32;
    // 3 is PLAN_DISPLAY_OPTION_COUNT
    bool32 option_flag[3] = { CT_FALSE };
    CT_RETURN_IFERR(sql_get_plan_display_format_info(lex, &format_index, option_flag, PLAN_DISPLAY_OPTION_COUNT));
    CT_RETURN_IFERR(sql_normalize_plan_display_format_value(sys_def->value, CT_PARAM_BUFFER_SIZE, format_index,
        option_flag, PLAN_DISPLAY_OPTION_COUNT));
    return CT_SUCCESS;
}

void sql_set_plan_display_format(char *str, uint32 *value)
{
    text_t text;
    cm_str2text(str, &text);
    text_t left = { 0 };
    text_t right = { 0 };

    *value = 0;

    cm_split_text(&text, ',', '\0', &left, &right);
    for (uint32 i = 0; i < PLAN_DISPLAY_FORMAT_COUNT; i++) {
        if (cm_text_equal_ins(&left, &g_plan_format_tab[i].text)) {
            CT_BIT_SET(*value, g_plan_format_tab[i].mask);
            cm_text_skip(&text, g_plan_format_tab[i].text.len);
            break;
        }
    }

    if (text.len == 0) {
        return;
    }

    cm_text_skip(&text, 1);

    for (;;) {
        cm_split_text(&text, ',', '\0', &left, &right);
        for (uint32 i = 0; i < PLAN_DISPLAY_OPTION_COUNT; i++) {
            if (cm_text_equal_ins(&left, &g_plan_option_tab[i].text)) {
                CT_BIT_SET(*value, g_plan_option_tab[i].mask);
                cm_text_skip(&text, g_plan_option_tab[i].text.len);
                break;
            }
        }

        if (right.len == 0) {
            break;
        }

        cm_text_skip(&text, 1);
    }
}

static status_t sql_get_plan_format_index(text_t *left, uint32 *format_index, bool32 *format_mismatch)
{
    uint32 i;
    for (i = 0; i < PLAN_DISPLAY_FORMAT_COUNT; i++) {
        if (!cm_text_equal_ins(left, &g_plan_format_tab[i].text)) {
            continue;
        }
        if (*format_index != CT_INVALID_ID32 && *format_index != i) {
            CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "%s and %s cannot be set at the same time",
                g_plan_format_tab[i].text.str, g_plan_format_tab[*format_index].text.str);
            return CT_ERROR;
        }
        *format_index = i;
        break;
    }
    if (i == PLAN_DISPLAY_FORMAT_COUNT) {
        *format_mismatch = CT_TRUE;
    }
    return CT_SUCCESS;
}

static status_t sql_get_plan_option_flag(text_t *left, bool32 *option_flag, uint32 flag_count, bool32 *option_mismatch)
{
    uint32 i;
    for (i = 0; i < PLAN_DISPLAY_OPTION_COUNT; i++) {
        if (cm_text_equal_ins(left, &g_plan_option_tab[i].text)) {
            option_flag[i] = CT_TRUE;
            break;
        }
    }
    if (i == PLAN_DISPLAY_OPTION_COUNT) {
        *option_mismatch = CT_TRUE;
    }
    return CT_SUCCESS;
}

static status_t get_plan_display_format_value_len(lex_t *lex, uint32 *len)
{
    word_t word;
    LEX_SAVE(lex);
    for (;;) {
        if (lex_fetch(lex, &word) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (word.type == WORD_TYPE_VARIANT && cm_text_str_equal_ins(&word.text.value, "SCOPE")) {
            break;
        }

        if (word.type == WORD_TYPE_EOF) {
            break;
        }
    }
    LEX_RESTORE(lex);
    *len = (uint32)(word.text.str - lex->curr_text->str);
    return CT_SUCCESS;
}

status_t sql_get_plan_display_format_info(void *lex_in, uint32 *format_index, bool32 *option_flag, uint32 flag_count)
{
    text_t left = { 0 };
    text_t right = { 0 };
    lex_t *lex = (lex_t *)lex_in;
    word_t word;
    uint32 value_len;
    lex_trim(lex->curr_text);
    word.text.str = lex->curr_text->str;
    if (LEX_CURR(lex) == '\'') {
        CT_RETURN_IFERR(lex_fetch_string(lex, &word));
        CM_REMOVE_ENCLOSED_CHAR(&word.text.value);
    } else {
        CT_RETURN_IFERR(get_plan_display_format_value_len(lex, &value_len));
        word.text.len = value_len;
        lex_skip(lex, value_len);
    }

    for (;;) {
        bool32 format_mismatch = CT_FALSE;
        bool32 option_mismatch = CT_FALSE;
        cm_ltrim_text(&word.text.value);
        if (word.text.len == 0) {
            CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "Invalid value for PLAN_DISPLAY_FORMAT");
            return CT_ERROR;
        }

        cm_split_text(&word.text.value, ',', '\0', &left, &right);
        cm_text_skip(&word.text.value, left.len);
        cm_rtrim_text(&left);
        if ((left.len == 0 && right.len != 0) || (right.len == 0 && word.text.len != 0)) {
            CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "Invalid value for PLAN_DISPLAY_FORMAT");
            return CT_ERROR;
        }

        CT_RETURN_IFERR(sql_get_plan_format_index(&left, format_index, &format_mismatch));
        CT_RETURN_IFERR(sql_get_plan_option_flag(&left, option_flag, flag_count, &option_mismatch));
        if (format_mismatch && option_mismatch) {
            CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "Invalid value %s for PLAN_DISPLAY_FORMAT", T2S(&left));
            return CT_ERROR;
        }

        if (right.len == 0) {
            break;
        }

        cm_text_skip(&word.text.value, 1);
    }
    return CT_SUCCESS;
}

status_t sql_normalize_plan_display_format_value(char *value, uint32 max_szie, uint32 format_index, bool32 *option_flag,
    uint32 flag_count)
{
    uint32 len = 0;
    if (format_index == CT_INVALID_ID32) {
        len = g_plan_format_tab[0].text.len;
        MEMS_RETURN_IFERR(memcpy_s(value, CT_PARAM_BUFFER_SIZE, g_plan_format_tab[0].text.str, len));
    } else {
        len = g_plan_format_tab[format_index].text.len;
        MEMS_RETURN_IFERR(memcpy_s(value, CT_PARAM_BUFFER_SIZE, g_plan_format_tab[format_index].text.str, len));
    }

    if (format_index == PLAN_DISPLAY_FORMAT_COUNT - 1) {
        value[len++] = '\0';
        return CT_SUCCESS;
    }

    for (uint32 i = 0; i < PLAN_DISPLAY_OPTION_COUNT; i++) {
        if (!option_flag[i]) {
            continue;
        }
        if (i == 0 && format_index == 1) {
            continue;
        }
        MEMS_RETURN_IFERR(memcpy_s(value + len, CT_PARAM_BUFFER_SIZE, ",", 1));
        len += 1;
        MEMS_RETURN_IFERR(
            memcpy_s(value + len, CT_PARAM_BUFFER_SIZE, g_plan_option_tab[i].text.str, g_plan_option_tab[i].text.len));
        len += g_plan_option_tab[i].text.len;
    }

    value[len++] = '\0';
    return CT_SUCCESS;
}

#ifdef __cplusplus
}
#endif
