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
 * ctsql_service.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/ctsql_service.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SQL_SERVICE_H__
#define __SQL_SERVICE_H__

#include "cm_defs.h"
#include "srv_session.h"
#include "pl/pl_manager.h"
#include "json/ctsql_json.h"

#ifdef __cplusplus
extern "C" {
#endif

EXTER_ATTACK status_t sql_process_free_stmt(session_t *session);
EXTER_ATTACK status_t sql_process_prepare(session_t *session);
EXTER_ATTACK status_t sql_process_execute(session_t *session);
EXTER_ATTACK status_t sql_process_fetch(session_t *session);
EXTER_ATTACK status_t sql_process_commit(session_t *session);
EXTER_ATTACK status_t sql_process_rollback(session_t *session);

EXTER_ATTACK status_t sql_process_query(session_t *session);
EXTER_ATTACK status_t sql_process_prep_and_exec(session_t *session);
EXTER_ATTACK status_t sql_process_lob_read(session_t *session);
EXTER_ATTACK status_t sql_process_lob_write(session_t *session);
status_t sql_process_lob_read_local(session_t *session, lob_read_req_t *read_req, lob_read_ack_t *ack);

EXTER_ATTACK status_t sql_process_xa_start(session_t *session);
EXTER_ATTACK status_t sql_process_xa_end(session_t *session);
EXTER_ATTACK status_t sql_process_xa_prepare(session_t *session);
EXTER_ATTACK status_t sql_process_xa_commit(session_t *session);
EXTER_ATTACK status_t sql_process_xa_rollback(session_t *session);
EXTER_ATTACK status_t sql_process_xa_status(session_t *session);
status_t sql_get_stmt(session_t *session, uint32 stmt_id);

EXTER_ATTACK status_t sql_process_gts(session_t *session);           /* added for z_sharding */
EXTER_ATTACK status_t sql_process_stmt_rollback(session_t *session); /* added for z_sharding */
void init_gts(bool32 need_read_persit_time);
status_t sql_get_uuid(char *buf, uint32 in_len);
EXTER_ATTACK status_t sql_process_sequence(session_t *session); /* added for z_sharding */
status_t sql_convert_gts_2_local_scn(session_t *session, knl_scn_t *gts_scn, knl_scn_t *local_scn);
status_t sql_convert_local_2_gts_scn(session_t *session, knl_scn_t *gts_scn, knl_scn_t *local_scn);
status_t sql_gts_create_scn(uint64 *scn);

EXTER_ATTACK status_t sql_process_load(session_t *session);
status_t check_version_and_local_infile(void);
status_t generate_load_full_file_name(session_t *session, char *full_file_name);
status_t sql_load_try_remove_file(char *file_name);

EXTER_ATTACK status_t sql_process_pre_exec_multi_sql(session_t *session);
status_t sql_try_send_backup_warning(sql_stmt_t *stmt);
status_t sql_process_alter_set(session_t *session);
typedef struct st_sql_type_map {
    bool32 do_typemap;
    char file_name[CT_FILE_NAME_BUFFER_SIZE];
    list_t type_maps; /* sql_user_typemap_t */
} sql_type_map_t;

// for online update
#ifdef Z_SHARDING
typedef enum en_shd_set_stauts {
    SHD_SET_STATUS_NORMAL = 0,   /* normal */
    SHD_SET_STATUS_MODIFING = 1, /* WAIT */
} shd_set_stauts_t;

typedef enum en_shd_rw_split {
    SHD_RW_SPLIT_NONE = 0, // shard rw split not set
    SHD_RW_SPLIT_RW,       // read and write
    SHD_RW_SPLIT_ROS,      // read on slave dn
    SHD_RW_SPLIT_ROA,      // read on master dn or slave dn
} shd_rw_split_t;
#endif
typedef enum en_load_data_local_phase {
    LOAD_DATA_LOCAL_GET_SQL = 1,
    LOAD_DATA_LOCAL_GET_DATA = 2,
    LOAD_DATA_LOCAL_EXE_CTSQL = 3
} load_data_local_t;
#define POPEN_GET_BUF_MAX_LEN (uint32)1024
#define LOAD_MAX_FULL_FILE_NAME_LEN (uint32)512 // path + file_name
#define LOAD_FEATURE_INNER_VERSION 1
#define MAX_DEL_RETRY_TIMES 5
#define LOAD_BY_CTSQL_MAX_STR_LEN (uint32)32768
#define LOAD_MAX_SQL_SUFFIX_LEN (uint32)10000
#define LOAD_MAX_RAW_SQL_LEN (uint32)20000

typedef struct st_sql_instance {
    context_pool_t *pool;
    bool32 enable_stat;
    bool32 commit_on_disconn;
    ack_sender_t pl_sender;
    ack_sender_t sender;
    ack_sender_t gdv_sender;
    pl_manager_t pl_mngr;
    sql_stat_t stat;
    uint32 interactive_timeout;
    uint32 sql_lob_locator_size;
    bool32 enable_empty_string_null; /* String: '' as null like oracle, as '' like MYSQL */
    bool32 string_as_hex_binary;     /* String: '' as null like oracle, as '' like MYSQL */
    list_t self_func_list;           // high priority user function.
    sql_type_map_t type_map;
    uint32 max_connect_by_level;
    uint32 index_scan_range_cache;
    uint32 prefetch_rows;
    uint32 max_sql_map_per_user;
    bool32 enable_predicate;
    uint32 plan_display_format;
    bool32 enable_outer_join_opt;
    uint32 cbo_index_caching;  // parameter CBO_INDEX_CACHING
    uint32 cbo_index_cost_adj; // parameter CBO_INDEX_COST_ADJ
    uint32 cbo_path_caching;   // parameter CBO_PATH_CACHING
    uint32 cbo_dyn_sampling;
    bool32 enable_distinct_pruning; // parameter _DISTINCT_PRUNING
    uint32 topn_threshold;
    uint32 withas_subquery; // 0: optimizer(default), 1: materialize, 2: inline
    bool32 enable_cb_mtrl;
    bool32 enable_aggr_placement;
    bool32 enable_or_expand;
    bool32 enable_project_list_pruning;
    bool32 enable_pred_move_around;
    bool32 enable_hash_mtrl;
    bool32 enable_winmagic_rewrite;
    bool32 enable_pred_reorder;
    bool32 enable_order_by_placement;
    bool32 enable_subquery_elimination;
    bool32 enable_join_elimination;
    bool32 enable_connect_by_placement;
    bool32 enable_group_by_elimination;
    bool32 enable_distinct_elimination;
    bool32 enable_multi_index_scan;
    bool32 enable_join_pred_pushdown;
    bool32 enable_filter_pushdown;
    uint32 optim_index_scan_max_parts;
    bool32 enable_order_by_elimination;
    bool32 enable_any_transform;
    bool32 enable_all_transform;
    bool32 enable_unnest_set_subq;
    bool32 enable_right_semijoin;
    bool32 enable_right_antijoin;
    bool32 enable_right_leftjoin;
    bool32 vm_view_enabled;
    bool32 enable_password_cipher;
    bool32 enable_cbo_hint;
    uint32 segment_pages_hold;
    uint32 hash_pages_hold;
    uint64 hash_area_size;
    bool32 enable_func_idx_only;
    bool32 enable_index_cond_pruning;
    bool32 enable_nl_full_opt;
    bool32 enable_arr_store_opt; // default value is FALSE, and when set to TRUE, forbidden to set back to FALSE
    bool32 enable_exists_transform;
#ifdef Z_SHARDING
    bool32 shard_serial_exec;       // whether to execute serially in shard situation
    bool32 shard_check_unique;      // open the switch of check distribution cloumn list in unique idx cloumn list
    uint32 shard_refusesql_level;   // open the switch to refuse unsinkable sql
    uint32 shard_refusetrans_level; // open the switch to refuse transation
    bool32 shard_retry_times;       // cn dml retry times when dml execte faild by switchover
    bool32 shard_retry_interval;    // cn dml retry interval when dml execte faild by switchover

    uint32 shard_connect_timeout;      // CN connect other node timeout(s)
    uint32 shard_socket_timeout;       // CN socket timeout(s)
    uint32 shard_heartbeat_timeout;    // CN connection pool health check timeout (s)
    uint32 shard_ptrans_clean_timeout; // CN pending transactions clean timeout (s)
    bool32 shard_check_db_role;        // CN check DN conn is primary as expected

    bool32 shard_enable_read_sync_slave; // client only read synced slave node
    uint32 shard_max_replay_lag;         // max replay lag for master to slave(s)

    uint32 shard_scn_interval_threshold;
    // for online update
    atomic_t ddl_cnt;
    spinlock_t lock_node;
    shd_set_stauts_t set_status;
    shd_lock_node_def_t lock_node_def;
    uint32 dn_groups_before_exp;
#endif
    bool32 parallel_policy;
    bool32 strict_case_datatype;
    bool8 coverage_enable;
    uint8 res[7];
    sql_json_mem_pool_t json_mpool;
} sql_instance_t;
#ifdef __cplusplus
}
#endif

#endif
