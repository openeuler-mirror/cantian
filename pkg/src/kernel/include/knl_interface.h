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
 * knl_interface.h
 *
 *
 * IDENTIFICATION
 * src/kernel/include/knl_interface.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_INTERFACE_H__
#define __KNL_INTERFACE_H__

#include "knl_defs.h"
#include "xact_defs.h"
#include "ddl_defs.h"
#include "index_defs.h"
#include "dcl_defs.h"
#include "obj_defs.h"
#include "dml_defs.h"
#include "repl_defs.h"
#include "sharding_defs.h"
#include "persist_defs.h"
#include "sysdba_defs.h"
#include "db_defs.h"
#include "stats_defs.h"
#include "session_defs.h"
#include "temp_defs.h"
#include "alck_defs.h"

#ifdef __cplusplus
extern "C" {
#endif
    
// log replication mode
typedef enum en_lrep_mode {
    LOG_REPLICATION_OFF = 0,  // logic replication off
    LOG_REPLICATION_ON = 1,   // logic replication on
} lrep_mode_t;

typedef enum en_object_status {
    OBJ_STATUS_INVALID = 0,
    OBJ_STATUS_VALID = 1,
    OBJ_STATUS_UNKONWN = 2
} object_status_t;

typedef struct st_knl_view_def {
    uint32 uid;
    text_t name;
    text_t user;
    galist_t columns;
    text_t sub_sql;
    sql_style_t sql_tpye;
    bool32 is_replace;
    object_status_t status;
    galist_t *ref_objects;
    void *select;
} knl_view_def_t;

typedef struct st_knl_rebuild_ctrlfile_def {
    text_t charset;
    archive_mode_t arch_mode;
    galist_t logfiles;
    galist_t datafiles;
} knl_rebuild_ctrlfile_def_t;


typedef enum en_policy_stmt_type {
    STMT_NONE = 0,
    STMT_SELECT = 0x1,
    STMT_INSERT = 0x2,
    STMT_UPDATE = 0x4,
    STMT_DELETE = 0x8,
    STMT_CEIL = 0x32768
} policy_stmt_type_t;

typedef struct st_policy_def_t {
    text_t object_owner;
    uint32 object_owner_id;
    text_t object_name;
    text_t policy_name;
    text_t function_owner;
    text_t function;
    uint32 stmt_types;
    uint32 ptype;
    uint32 check_option;
    uint32 enable;
    uint32 long_predicate;
} policy_def_t;

typedef struct st_policy_set {
    policy_def_t *policies[CT_MAX_POLICIES];
    uint32 plcy_count;
} policy_set_t;

typedef enum en_sort_mode {
    SORT_MODE_NONE = 0,
    SORT_MODE_ASC = 1,
    SORT_MODE_DESC = 2,
} sort_direction_t;

/* order by XXX [nulls first | nulls last]
* Specify whether returned result sets with null values should occur first or last
* in the ordering sequence. */
typedef enum en_sort_nulls {
    SORT_NULLS_DEFAULT = 0,
    SORT_NULLS_FIRST = 1,
    SORT_NULLS_LAST = 2,
} sort_nulls_t;

typedef enum en_win_sort_type {
    WINSORT_PART = 0x1,
    WINSORT_ORDER = 0x2,
    WINSORT_WIN = 0x4,
} win_sort_type_t;

typedef struct st_knl_index_col_def {
    text_t name;
    sort_direction_t mode;
    bool32 is_func;
    bool32 nullable;
    ct_type_t datatype;
    uint32 size;
    text_t func_text;    // function index text
    void *func_expr;
} knl_index_col_def_t;

typedef struct st_knl_ext_desc {
    knl_ext_type_t external_type;
    char directory[CT_FILE_NAME_BUFFER_SIZE];
    char location[CT_MAX_NAME_LEN];
    char records_delimiter;
    char fields_terminator;
} knl_ext_desc_t;

typedef struct st_knl_storage_desc {
    uint32 initial;
    uint32 max_pages;
} knl_storage_desc_t;

typedef enum en_table_flag_type {
    TABLE_FLAG_TYPE_STORAGED,
    TABLE_FLAG_TYPE_ENABLE_NOLOGGING,
    TABLE_FLAG_TYPE_DISABLE_NOLOGGING,
} table_flag_type_e;

typedef enum en_part_flag_type {
    PART_FLAG_TYPE_NOTREADY,
    PART_FLAG_TYPE_STORAGED,
    PART_FLAG_TYPE_ENABLE_NOLOGGING,
    PART_FLAG_TYPE_DISABLE_NOLOGGING,
} part_flag_type_e;
/*
 * caution!! new member must be added in tail or be initialized in the definition of g_sys_tables
 */
typedef struct st_knl_table_desc {
    uint32 id;                       // table id
    char name[CT_NAME_BUFFER_SIZE];  // table name
    uint32 uid;                      // user id
    uint32 space_id;                 // table space
    uint32 oid;                      // object id
    knl_scn_t org_scn;               // original scn
    knl_scn_t chg_scn;               // scn when changed by DDL(alter)
    knl_scn_t seg_scn;               // segment scn
    table_type_t type;               // table type
    uint32 column_count;             // column count
    uint32 index_count;              // index count
    uint32 parted;                   // table is partitioned
    page_id_t entry;                 // the entry of table (page id)
    uint32 initrans;                 // init trans
    uint32 pctfree;                  // pct free
    uint32 appendonly;               // appendonly
    uint8 cr_mode;                   // consistent read mode
    bool8 recycled;                 // table in recycle bin
    union {
        uint32 flags;
        struct {
            uint32 is_csf : 1;    // << table row format is compact
            uint32 storaged : 1;    // specified storage parameter
            uint32 is_nologging : 1;    // table insert is nologging
            uint32 compress : 1;   // specified compress parameter
            uint32 has_trig : 1;    // table has trig
            uint32 is_intrinsic : 1;    // is mysql internal tmp table
            uint32 unused_flag : 26;
        };
    };
    knl_storage_desc_t storage_desc;
    knl_ext_desc_t *external_desc;   // external table definition
    uint64 serial_start;              // init auto increment value
#ifdef Z_SHARDING
    uint32 distribute_type;
    text_t distribute_text;      // distribute info
    binary_t distribute_data;  // distribute
    binary_t distribute_buckets;
    uint32 slice_count;
    uint32 group_count;
#endif
    uint32 estimate_len;             // estimate row length according to definition
    uint32 version;
    int32 csf_dec_rowlen;             // estimate csf row decrease length according to definition
    uint8 compress_algo;
} knl_table_desc_t;

#define USER_PASSWORD_MASK     0x00000001
#define USER_DATA_SPACE_MASK   0x00000002
#define USER_TEMP_SPACE_MASK   0x00000004
#define USER_PROFILE_MASK      0x00000008
#define USER_EXPIRE_MASK       0x00000010
#define USER_EXPIRE_GRACE_MASK 0x00000020
#define USER_LOCK_MASK         0x00000040
#define USER_LOCK_TIMED_MASK   0x00000080
#define USER_LCOUNT_MASK       0x00000100


#define UPDATE_PASSWORD_COLUMM   0x00000001
#define UPDATE_DATA_SPACE_COLUMN 0x00000002
#define UPDATE_TEMP_SPACE_COLUMN 0x00000004
#define UPDATE_CTIME_COLUMN      0x00000008
#define UPDATE_PTIME_COLUMN      0x00000010
#define UPDATE_EXPTIME_COLUMN    0x00000020
#define UPDATE_LTIME_COLUMN      0x00000040
#define UPDATE_PROFILE_COLUMN    0x00000080
#define UPDATE_ASTATUS_COLUMN    0x00000100
#define UPDATE_LCOUNT_COLUMN     0x00000200

#define CHECK_UPDATE_COLUMN(update_flag, update_column) (((update_flag) & (update_column)) != 0)


#define STATE_NULL                (uint8)0x00
#define STATE_DEFERRABLE          (uint8)0x01
#define STATE_NOT_DEFERRABLE      (uint8)0x02
#define STATE_RELY                (uint8)0x01
#define STATE_NO_RELY             (uint8)0x02
#define STATE_INITIALLY_IMMEDIATE (uint8)0x01
#define STATE_INITIALLY_DEFERRED  (uint8)0x02

//  The status of user locked or unlocked  needs to be recorded in the audit log
#define USER_LOCKED       (uint32)0x01
#define USER_UNLOCK       (uint32)0x02

#define INDEX_IS_CONS_MASK     0x00000001
#define INDEX_IS_DISABLED_MASK 0x00000002
#define INDEX_IS_INVALID_MASK  0x00000004
#define INDEX_IS_STORED_MASK   0x00000008

/* kernel partition key */
typedef struct st_knl_part_key {
    part_key_t *key;                         // current part key
    part_decode_key_t decoder;               // used for decode part key
    uint16 offsets[CT_MAX_PARTKEY_COLUMNS];  // column offsets
    uint16 lens[CT_MAX_PARTKEY_COLUMNS];     // column lens
    bool32 closed[CT_MAX_PARTKEY_COLUMNS];   // column include equal or not
} knl_part_key_t;

typedef struct st_knl_index_paral_range {
    uint32 workers;
    knl_scan_range_t  *index_range[CT_MAX_PARAL_QUERY];
}knl_index_paral_range_t;

#define KNL_SCAN_KEY_SIZE (sizeof(knl_scan_key_t) + CT_KEY_BUF_SIZE)

typedef enum en_bak_stage {
    BACKUP_START = 0,
    BACKUP_CTRL_STAGE = 1,
    BACKUP_HEAD_STAGE = 2,
    BACKUP_DATA_STAGE = 3,
    BACKUP_LOG_STAGE = 4,
    BACKUP_PARAM_STAGE = 5,
    BACKUP_BUILD_STAGE = 6,
    BACKUP_READ_FINISHED = 7,
    BACKUP_WRITE_FINISHED = 8,
    BACKUP_END = 9,
    BACKUP_MAX_STAGE_NUM = 10,
} bak_stage_t;

typedef enum en_build_stage {
    BUILD_START = 0,
    BUILD_PARAM_STAGE = 1,
    BUILD_CTRL_STAGE = 2,
    BUILD_DATA_STAGE = 3,
    BUILD_LOG_STAGE = 4,
    BUILD_HEAD_STAGE = 5,
    BUILD_SYNC_FINISHED = 6,
    BUILD_BUILD_STAGE = 7,
} build_stage_t;

typedef struct st_build_progress {
    bak_stage_t stage;
    uint32 file_id;
    uint64 data_offset;
    uint32 asn;
    uint32 curr_file_index;
    uint32 last_file_index;
    int32 start_time;
} build_progress_t;

typedef void (*knl_xact_end_t)(knl_handle_t handle);
typedef status_t (*knl_match_cond_t)(void *stmt, bool32 *match);
typedef status_t (*knl_exec_default_t)(void *stmt, void *expr_node, variant_t *value);
typedef status_t (*knl_alloc_rm_t)(uint16 *rmid);
typedef void (*knl_release_rm_t)(uint16 rmid);
typedef status_t (*knl_alloc_auton_rm_t)(knl_handle_t handle);
typedef status_t (*knl_release_auton_rm_t)(knl_handle_t handle);
typedef void (*knl_clean_open_cursor)(knl_handle_t handle, uint64);
typedef void (*knl_clean_open_temp_cursor)(knl_handle_t handle, knl_handle_t temp_cache);
typedef void (*knl_keep_stack_variant)(void *stmt, variant_t *value);
typedef status_t (*knl_decode_cond_t)(memory_context_t *mem, void *data, void **expr);
typedef status_t (*knl_match_cond_tree_t) (void *stmt, void *cond, cond_result_t *match);
typedef void (*knl_dc_recycle_external)(void);
typedef status_t (*knl_execute_check_t)(knl_handle_t handle, text_t *sql, bool32 *exist);
typedef status_t (*knl_logic_log_replay_t)(knl_handle_t session, uint32 type, void *data);

typedef void (*knl_invalidate_space_t)(uint32);
typedef status_t(*knl_func_idx_exec_t)(knl_handle_t session, knl_handle_t knl_cursor, ct_type_t datatype,
                                       void *expr, variant_t *result, bool32 is_new);
typedef status_t (*knl_func_idx_init_t)(knl_handle_t session, knl_handle_t cursor);
typedef void (*knl_func_idx_free_t)(knl_handle_t session);
typedef status_t (*knl_parse_check_from_text_t)(knl_handle_t handle, text_t *cond_text,
                                                knl_handle_t entity, memory_context_t *mem, void **cond_tree);
typedef status_t (*knl_parse_default_from_text_t)(knl_handle_t handle, knl_handle_t entity,
    knl_handle_t column, memory_context_t *mem, void **expr_tree, void **expr_update_tree, text_t parse_text);
typedef status_t (*knl_verify_default_from_text_t)(knl_handle_t handle, knl_handle_t column, text_t parse_text);
typedef status_t(*knl_parse_dmm_from_text_t)(knl_handle_t handle, knl_handle_t entity,
                                             knl_handle_t column, memory_context_t *mem,
                                             void **expr_tree);
// init sql_text first before get sql
typedef status_t (*knl_get_sql_text_t)(uint32 sessionid, text_t *sql);
typedef void (*knl_set_min_scn_t)(knl_handle_t session);
typedef uint16 (*knl_get_xa_xid_t)(knl_xa_xid_t *xa_xid);
typedef bool32 (*knl_add_xa_xid_t)(knl_xa_xid_t *xa_xid, uint16 dst_rmid, uint8 status);
typedef void (*knl_delete_xa_xid_t)(knl_xa_xid_t *xa_xid);
typedef bool32 (*knl_attach_suspend_rm_t)(knl_handle_t handle, knl_xa_xid_t *xa_xid, uint8 status, bool8 release);
typedef void (*knl_detach_suspend_rm_t)(knl_handle_t handle, uint16 new_rmid);
typedef void (*knl_detach_pending_rm_t)(knl_handle_t handle, uint16 new_rmid);
typedef bool32 (*knl_attach_pending_rm_t)(knl_handle_t handle, knl_xa_xid_t *xa_xid);
typedef void (*knl_shrink_xa_rms_t)(knl_handle_t handle, bool32 force);
typedef status_t (*knl_begin_check_t)(knl_handle_t handle, knl_handle_t cursor);
typedef status_t (*knl_end_check_t)(knl_handle_t handle, knl_handle_t cursor);

typedef union un_knl_tree_info {
    atomic_t value;
    struct {
        pagid_data_t root;  // tree root page_id
        uint16 level;       // tree level
    };
} knl_tree_info_t;


typedef struct st_knl_temp_dc {
    void *ctx;
    void **entries;
} knl_temp_dc_t;

typedef struct st_knl_lnk_tab_dc {
    void *ctx;
    void **entries;
} knl_lnk_tab_dc_t;

typedef struct st_knl_lnk_dc_callback {
    // input data
    memory_context_t *ctx; // dblink memory context
    uint32 node_id;        // dblink node id
    char *tab_user;        // dblink table user
    char *tab_name;        // dblink table node

    // callback data
    uint32 group_id;       // dblink node group id
    uint32 col_cnt;        // dblink table column count
    knl_column_t **cols;   // dblink table column info
} knl_lnk_dc_callback_t;

bool8 knl_is_llt_by_name(char first_char);
bool8 knl_is_llt_by_name2(char first_char);

#define IS_LTT_BY_NAME(name) (knl_is_llt_by_name2((name)[0]))         /* LTT = Local Temporary Table */
#define IS_LTT_BY_NAME2(name) (knl_is_llt_by_name2((name)[0]))       /* LTT = Local Temporary Table for sql */
#define IS_LTT_BY_ID(id)     ((id) >= CT_LTT_ID_OFFSET && (id) < CT_DBLINK_ENTRY_START_ID) /* LTT = Local Temporary Table */
#define IS_DBLINK_TABLE_BY_ID(id) ((id) >= CT_DBLINK_ENTRY_START_ID)

#define INVALID_INDEX_SLOT (uint8)(0xFF)
#define IS_AUTO_REBUILD(lock_timeout) (((lock_timeout) != 0) && ((lock_timeout) != LOCK_INF_WAIT))

typedef enum en_page_cache_type {
    NO_PAGE_CACHE = 0,
    GLOBAL_PAGE_CACHE = 1,
    LOCAL_PAGE_CACHE = 2
} page_cache_type_t;

#define IS_INDEX_ONLY_SCAN(cursor)               \
    ((cursor)->action == CURSOR_ACTION_SELECT && \
        (cursor)->scan_mode == SCAN_MODE_INDEX && (cursor)->index_only)

extern init_cursor_t g_init_cursor;

#define KNL_INIT_CURSOR(cursor)                \
    do {                                       \
        (cursor)->init_cursor = g_init_cursor; \
        (cursor)->table = NULL;                \
        (cursor)->dc_type = DICT_TYPE_UNKNOWN; \
        (cursor)->vnc_column = NULL;           \
        (cursor)->skip_lock = 0;               \
        (cursor)->is_cascade = 0;              \
        (cursor)->is_create_select = 0;        \
    } while (0)

// Function type, use to open a dynamic view
typedef status_t (*dynview_open_t)(knl_handle_t session, knl_cursor_t *cursor);

// Function type, use to fetch row from a dynamic view
typedef status_t (*dynview_fetch_t)(knl_handle_t session, knl_cursor_t *cursor);

typedef struct st_dynview_desc {
    char *user;  // user name
    char *name;
    uint32 column_count;
    struct st_knl_column *columns;
    dynview_open_t dopen;
    dynview_fetch_t fetch;
} dynview_desc_t;

// Function type, use to describe a dynamic view
typedef dynview_desc_t *(*dynview_describe_t)(uint32 id);

// Dynamic view type
typedef struct st_dynamic_view {
    uint32 id;
    dynview_describe_t describe;
} knl_dynview_t;

// Function type, Register a dynamic view
typedef status_t (*register_dynamic_view_t)(knl_dynview_t *views, uint32 count);

// view type
typedef struct st_view_t {
    uint32 id;                       // table id
    char name[CT_NAME_BUFFER_SIZE];  // table name
    uint32 uid;                      // user id
    knl_scn_t org_scn;               // original scn
    knl_scn_t chg_scn;               // scn when changed by DDL(alter)
    uint32 column_count;             // column count
    uint32 flags;
    void *lob;
    text_t sub_sql;        // subquery sql
    sql_style_t sql_type;  // subquery sql is oracle or postgresql
} knl_view_t;

typedef enum en_io_type {
    IO_TYPE_READ,
    IO_TYPE_COMMIT,
} io_type_t;

typedef status_t (*knl_load_scripts_t)(knl_handle_t session, const char *file, bool8 is_necessary);
typedef status_t (*knl_pl_init_t)(knl_handle_t session);
typedef status_t (*knl_pl_db_drop_triggers_t)(knl_handle_t knl_session, knl_dictionary_t *dc);
typedef void (*knl_pl_enable_trigger_t)(knl_handle_t knl_session, void *entry);
typedef void (*knl_pl_disable_trigger_t)(knl_handle_t knl_session, void *entry);
typedef status_t (*knl_init_shard_resource_t)(knl_handle_t knl_session);
typedef void (*knl_kill_session_t)(knl_handle_t knl_session, bool32 force, uint32 serial_id);
typedef status_t (*knl_exec_sql_t)(knl_handle_t knl_session, text_t *sql);
typedef status_t (*knl_init_sql_maps_t)(knl_handle_t session);
typedef  void (*knl_before_commit_t)(knl_handle_t knl_session);
typedef status_t (*knl_set_vm_lob_to_knl_t)(void *stmt, knl_cursor_t *knl_cur, knl_column_t *column,
    variant_t *value, char *locator);

typedef void(*knl_set_stmt_check_t)(void *stmt, knl_cursor_t *cursor, bool32 is_check);
typedef status_t (*knl_alloc_session_t)(bool32 knl_reserved, knl_handle_t *knl_session);
typedef void (*knl_release_session_t)(knl_handle_t sess);
typedef status_t (*knl_update_depender_status_t)(knl_handle_t sess, obj_info_t *obj_addr);
typedef void(*knl_accumate_io_t)(knl_handle_t sess, io_type_t type);
typedef status_t (*knl_init_resmgr_t)(knl_handle_t sess);
typedef status_t(*knl_import_rows_t)(void *stmt, uint32 count);
typedef status_t(*knl_get_ddl_sql_t)(void *stmt, text_t *sql, vmc_t *vmc, bool8 *need_free);
typedef status_t(*knl_srv_sysdba_privilege_t)(void);
typedef status_t(*knl_backup_keyfile_t)(char *event);
typedef status_t(*knl_update_server_masterkey_t)(void);
typedef bool32(*knl_have_ssl_t)(void);
typedef status_t (*knl_clear_sym_cache_t)(knl_handle_t se, uint32 lib_uid, char *name, char *lib_path);
typedef status_t (*knl_get_func_index_size_t)(knl_handle_t session, text_t *func_text, typmode_t *typmode);
typedef bool32 (*knl_compare_index_expr_t)(knl_handle_t sessin, text_t *func_text1, text_t *func_text2);
typedef bool32 (*knl_whether_login_with_user_t)(text_t *username);
typedef status_t(*knl_pl_drop_synonym_by_user)(knl_handle_t knl_session, uint32 uid, text_t *syn_name);
typedef status_t (*knl_pl_drop_object_t)(knl_handle_t knl_session, uint32 uid);
typedef status_t(*knl_pl_update_tab_from_proc_t)(knl_handle_t knl_session, knl_dictionary_t* dc,
    text_t *name, text_t *new_name);
typedef void(*knl_pl_free_trig_entity_by_tab_t)(knl_handle_t knl_session, knl_dictionary_t* dc);
typedef void(*knl_pl_drop_triggers_entry_t)(knl_handle_t knl_session, knl_dictionary_t* dc);
typedef void (*knl_mtrl_init_vmc_t)(knl_handle_t *mtrl);
typedef status_t(*knl_load_lnk_tab_dc_t)(knl_handle_t se, knl_lnk_dc_callback_t *callback_data);
typedef status_t(*knl_convert_char_t)(knl_handle_t session, text_t *text, uint32 def_size, bool32 is_char);
typedef status_t (*knl_raw_device_init)(const char *conn_path);
typedef status_t (*cc_execute_replay_lock_table_t)(knl_handle_t session, void *lock_info);
typedef status_t (*cc_execute_replay_unlock_table_t)(knl_handle_t session, void *lock_info);
typedef status_t (*cc_execute_replay_invalid_dd_t)(knl_handle_t session, void *invalid_info);
typedef status_t (*cc_execute_replay_ddl_t)(knl_handle_t knl_session, char *sql_text, uint32 sql_len);
typedef status_t (*cc_execute_replay_unlock_mdl_key_t)(knl_handle_t knl_session);

typedef struct st_knl_callback {
    knl_set_vm_lob_to_knl_t set_vm_lob_to_knl;
    knl_exec_default_t exec_default;
    knl_keep_stack_variant keep_stack_variant;
    knl_alloc_rm_t alloc_rm;
    knl_release_rm_t release_rm;
    knl_alloc_auton_rm_t alloc_auton_rm;
    knl_release_auton_rm_t release_auton_rm;
    knl_get_xa_xid_t get_xa_xid;
    knl_add_xa_xid_t add_xa_xid;
    knl_delete_xa_xid_t delete_xa_xid;
    knl_attach_suspend_rm_t attach_suspend_rm;
    knl_detach_suspend_rm_t detach_suspend_rm;
    knl_attach_pending_rm_t attach_pending_rm;
    knl_detach_pending_rm_t detach_pending_rm;
    knl_shrink_xa_rms_t shrink_xa_rms;
    knl_load_scripts_t load_scripts;
    knl_exec_sql_t exec_sql;
    knl_clean_open_cursor invalidate_cursor;
    knl_clean_open_temp_cursor invalidate_temp_cursor;
    knl_pl_db_drop_triggers_t pl_db_drop_triggers;
    knl_pl_update_tab_from_proc_t pl_update_tab_from_sysproc;
    knl_pl_enable_trigger_t pl_enable_trigger;
    knl_pl_disable_trigger_t pl_disable_trigger;
    knl_pl_free_trig_entity_by_tab_t pl_free_trig_entity_by_tab;
    knl_pl_drop_triggers_entry_t pl_drop_triggers_entry;

    knl_logic_log_replay_t pl_logic_log_replay;
    knl_execute_check_t exec_check;
#ifdef Z_SHARDING
    knl_init_shard_resource_t init_shard_resource;
    knl_parse_distribute_info_t parse_distribute_info;
    knl_parse_distribute_bkts_t parse_distribute_bkts;
    knl_parse_distribute_from_text_t parse_distribute_from_text;
#endif
    knl_decode_cond_t decode_check_cond;
    knl_match_cond_tree_t match_cond_tree;
    knl_dc_recycle_external dc_recycle_external;
    knl_invalidate_space_t invalidate_space;
    knl_func_idx_exec_t func_idx_exec;
    knl_kill_session_t kill_session;
    knl_init_sql_maps_t init_sql_maps;
    knl_get_sql_text_t get_sql_text;
    knl_set_min_scn_t set_min_scn;
    knl_set_stmt_check_t set_stmt_check;
    knl_before_commit_t before_commit;
    knl_alloc_session_t alloc_knl_session;
    knl_release_session_t release_knl_session;
    knl_parse_check_from_text_t parse_check_from_text;
    knl_parse_default_from_text_t parse_default_from_text;
    knl_verify_default_from_text_t verify_default_from_text;
    knl_update_depender_status_t update_depender;
    knl_accumate_io_t accumate_io;
    knl_init_resmgr_t init_resmgr;
    knl_import_rows_t import_rows;
    knl_srv_sysdba_privilege_t sysdba_privilege;
    knl_backup_keyfile_t backup_keyfile;
    knl_update_server_masterkey_t update_server_masterkey;
    knl_have_ssl_t have_ssl;
    knl_clear_sym_cache_t clear_sym_cache;
    knl_get_func_index_size_t get_func_index_size;
    knl_compare_index_expr_t compare_index_expr;
    knl_whether_login_with_user_t whether_login_with_user;
    knl_pl_init_t pl_init;
    knl_pl_drop_object_t pl_drop_object;
    knl_pl_drop_synonym_by_user pl_drop_synonym_by_user;
    knl_mtrl_init_vmc_t init_vmc;
    knl_load_lnk_tab_dc_t load_lnk_tab_dc;
    knl_get_ddl_sql_t get_ddl_sql;
    knl_convert_char_t convert_char;
    knl_raw_device_init device_init;
    cc_execute_replay_lock_table_t cc_execute_replay_lock_table;
    cc_execute_replay_unlock_table_t cc_execute_replay_unlock_table;
    cc_execute_replay_invalid_dd_t cc_execute_replay_invalid_dd;
    cc_execute_replay_ddl_t cc_execute_replay_ddl;
    cc_execute_replay_unlock_mdl_key_t cc_execute_replay_unlock_mdl_key;
} knl_callback_t;

extern knl_callback_t g_knl_callback;


#define CURSOR_UPDATE_COLUMN_DATA(cursor, id) ((char *)(cursor)->update_info.data + (cursor)->update_info.offsets[id])
#define CURSOR_UPDATE_COLUMN_SIZE(cursor, id) \
    ((id) >= (uint32)ROW_COLUMN_COUNT((cursor)->row) ? CT_NULL_VALUE_LEN : (cursor)->update_info.lens[id])

#define CURSOR_COLUMN_DATA(cursor, id) ((char *)(cursor)->row + (cursor)->offsets[id])
#define CURSOR_COLUMN_SIZE(cursor, id) \
    ((uint32)(id) >= (uint32)ROW_COLUMN_COUNT((cursor)->row) ? CT_NULL_VALUE_LEN : (cursor)->lens[id])


/* Kernel set current schema definition */
typedef struct st_knl_schema_def {
    text_t schema_name;
} knl_schema_def_t;

#ifdef DB_DEBUG_VERSION
/* syncpoint section */
typedef struct st_syncpoint_def {
    uint32 raise_count;
    text_t enable;
    text_t signal;
    text_t wait_for;
    text_t syncpoint_name;
} syncpoint_def_t;
#endif /* DB_DEBUG_VERSION */

#define DEADLOCK_DETECT_TIME 10
#define LOCK_INF_WAIT (uint32)0xFFFFFFFF
#define BATCH_COMMIT_COUNT 10000

typedef struct st_wait_table {
    union {
        atomic_t value;
        struct {
            uint32 oid;
            uint32 uid;
        };
    };
    bool32 is_locking;
} lock_twait_t;

#define IS_SYS_SESSION(session)     (((knl_session_t *)(session))->id < CT_SYS_SESSIONS)
#define KNL_IN_XATRAN(session)      (((knl_session_t *)(session))->rm->gtid[0] != '\0')
#define KNL_IS_DATABASE_OPEN(session) (((knl_session_t *)(session))->kernel->db.status == DB_STATUS_OPEN)
#define KNL_IS_DB_OPEN_NORMAL(session) (((knl_session_t *)(session))->kernel->db.status == DB_STATUS_OPEN && \
                                        ((knl_session_t *)(session))->kernel->db.open_status < DB_OPEN_STATUS_UPGRADE)
#define SMALL_TABLE_SAMPLING_THRD(session) \
    (((knl_session_t *)(session))->kernel->attr.small_table_sampling_threshold)
typedef struct st_ddm_def {
    uint32 uid;
    uint32 oid;
    uint32 column_id;
    char rulename[CT_MAX_NAME_LEN + 1];
    char ddmtype[CT_MAX_NAME_LEN];
    char param[CT_MAX_DDM_LEN];
} knl_ddm_def_t;

typedef struct st_seg_desc {
    uint32 uid;
    uint32 oid;
    uint32 index_id;
    uint32 column_id;
    uint32 space_id;
    page_id_t entry;
    knl_scn_t org_scn;
    knl_scn_t seg_scn;
    uint32 initrans;
    uint32 pctfree;
    uint32 op_type;
    bool32 reuse;
    uint64 serial;
} knl_seg_desc_t;

typedef enum en_checksum_level {
    CKS_OFF = 0,
    CKS_TYPICAL = 1,
    CKS_FULL = 2,
} checksum_level_e;

typedef struct st_knl_add_update_column {
    knl_update_info_t *old_info;
    knl_update_info_t *new_info;
    uint16 *add_columns;
    uint16 add_count;
} knl_add_update_column_t;

typedef struct st_knl_idx_paral_info {
    uint32 index_slot;
    knl_part_locate_t part_loc;
    uint32 workers;
    bool8 is_dsc;
    bool8 is_index_full;
    knl_scan_range_t *org_range;
} knl_idx_paral_info_t;

typedef struct st_knl_corrupt_info {
    page_id_t page_id;
    char datafile_name[CT_FILE_NAME_BUFFER_SIZE];
    char space_name[CT_NAME_BUFFER_SIZE];
} knl_corrupt_info_t;

typedef struct st_knl_space_info {
    int64 total;
    int64 used;
    int64 normal_total;
    int64 normal_used;
    int64 compress_total;
    int64 compress_used;
} knl_space_info_t;

void knl_init_index_conflicts(knl_handle_t session, uint64 *conflicts);
status_t knl_check_index_conflicts(knl_handle_t session, uint64 conflicts);
void knl_reset_index_conflicts(knl_handle_t session);
void knl_set_logbuf_stack(knl_handle_t kernel, uint32 sid, char *plog_buf, cm_stack_t *stack);
void knl_logic_log_put(knl_handle_t session, uint32 type, const void *data, uint32 size);
status_t knl_tx_enabled(knl_handle_t session);
status_t knl_get_serial_cached_value(knl_handle_t session, knl_handle_t dc_entity, int64 *value);
status_t knl_get_serial_value(knl_handle_t handle, knl_handle_t dc_entity, uint64 *value);
status_t knl_get_serial_value_4mysql(knl_handle_t handle, knl_handle_t dc_entity, uint64 *value,
                                     uint16 auto_inc_step, uint16 auto_inc_offset);
void knl_first_serial_value_4mysql(uint64 *curr_id, uint64 start_val, uint16 step, uint16 offset);
void knl_cal_serial_value_4mysql(uint64 prev_id, uint64 *curr_id, uint64 start_val, uint16 step, uint16 offset);
knl_table_desc_t *knl_get_table(knl_dictionary_t *dc);
uint32 knl_get_index_count(knl_handle_t dc_entity);
knl_index_desc_t *knl_get_index(knl_handle_t dc_entity, uint32 index_id);
uint32 knl_get_index_vcol_count(knl_index_desc_t *desc);
bool32 knl_has_update_default_col(knl_handle_t handle);
bool32 knl_batch_insert_enabled(knl_handle_t session, knl_dictionary_t *dc, uint8 trig_disable);
status_t knl_open_cursor(knl_handle_t handle, knl_cursor_t *cursor, knl_dictionary_t *dc);
status_t knl_reopen_cursor(knl_handle_t session, knl_cursor_t *cursor, knl_dictionary_t *dc);
void knl_close_cursor(knl_handle_t session, knl_cursor_t *cursor);
void knl_init_cursor_buf(knl_handle_t handle, knl_cursor_t *cursor);
knl_cursor_t *knl_push_cursor(knl_handle_t handle);
status_t sql_push_knl_cursor(knl_handle_t handle, knl_cursor_t **cursor);
void knl_pop_cursor(knl_handle_t handle);
uint32 knl_get_update_info_size(knl_handle_t handle);
void knl_bind_update_info(knl_handle_t handle, char *buf);
void knl_set_table_scan_range(knl_handle_t handle, knl_cursor_t *cursor, page_id_t left, page_id_t right);
status_t knl_cursor_use_vm(knl_handle_t handle, knl_cursor_t *cursor, bool32 replace_row);
status_t knl_update_trig_table_flag(knl_handle_t session, knl_table_desc_t *desc, bool32 has_trig);

void knl_get_system_name(knl_handle_t session, constraint_type_t type, char *name, uint32 name_len);
status_t knl_match_cond(knl_handle_t session, knl_cursor_t *cursor, bool32 *matched);
status_t knl_flush_table_monitor(knl_handle_t session);
status_t knl_get_index_par_schedule(knl_handle_t handle, knl_dictionary_t *dc, knl_idx_paral_info_t paral_info,
    knl_index_paral_range_t *sub_ranges);
status_t knl_write_sysddm(knl_handle_t *session, knl_ddm_def_t *def);
status_t knl_drop_ddm_rule_by_name(knl_handle_t *session, text_t ownname, text_t tabname, text_t rulename);
status_t knl_check_ddm_rule(knl_handle_t *session, text_t ownname, text_t tabname, text_t rulename);
void knl_set_index_scan_range(knl_cursor_t *cursor, knl_scan_range_t *sub_range);
bool32 knl_is_table_csf(knl_handle_t dc_entity, knl_part_locate_t part_loc);
uint32 knl_table_max_row_len(knl_handle_t dc_entity, uint32 max_col_size, knl_part_locate_t part_loc);
status_t knl_ddl_latch_s(drlatch_t *latch, knl_handle_t session, latch_statis_t *stat);
status_t knl_ddl_latch_x(knl_handle_t session, latch_statis_t *stat);
status_t knl_ddl_latch_sx(knl_handle_t session, latch_statis_t *stat);
void knl_ddl_unlatch_x(knl_handle_t session);
status_t knl_verify_index_by_name(knl_handle_t session, knl_dictionary_t *dc, text_t *index_name,
    knl_corrupt_info_t *info);
status_t knl_verify_table(knl_handle_t session, knl_dictionary_t *dc, knl_corrupt_info_t *corrupt_info);
status_t knl_repair_catalog(knl_handle_t session);
status_t knl_database_has_nolog_object(knl_handle_t se, bool32 *has_nolog);

// VPD
status_t knl_write_sys_policy(knl_handle_t session, policy_def_t *plcy_def);
status_t knl_modify_sys_policy(knl_handle_t session, policy_def_t *plcy_def, knl_cursor_action_t action);

// VIEW
status_t knl_create_view(knl_handle_t session, knl_handle_t stmt, knl_view_def_t *def);
status_t knl_create_or_replace_view(knl_handle_t session, knl_handle_t stmt, knl_view_def_t *def);
status_t knl_get_dfname_by_number(knl_handle_t session, int32 filenumber, char **filename);
status_t knl_get_view_sub_sql(knl_handle_t session, knl_dictionary_t *dc, text_t *sql, uint32 *page_id);
dynview_desc_t *knl_get_dynview(knl_dictionary_t *dc);

// DBLINK
status_t knl_load_dblinks(knl_handle_t session);
status_t knl_check_dblink_exist(knl_handle_t session, text_t *name);
status_t knl_create_dblink(knl_handle_t session, knl_dblink_def_t *def);
status_t knl_drop_dblink(knl_handle_t session, knl_dblink_def_t *def);
status_t knl_drop_dblink_by_id(knl_handle_t session, uint32 id);
status_t knl_open_lnk_tab_dc(knl_handle_t session, text_t *lnk_name, sql_text_t *tab_user, text_t *tab_name,
    knl_dictionary_t *dc);
void knl_free_lnk_tab_dc(knl_handle_t session);
bool32 knl_find_lnk_tab_dc(knl_handle_t session, text_t *lnk_name, text_t *tab_name);

// PART
bool32 knl_is_part_table(knl_handle_t dc_entity);
part_type_t knl_part_table_type(knl_handle_t dc_entity);
uint32 knl_part_count(knl_handle_t dc_entity);
uint32 knl_subpart_count(knl_handle_t dc_entity, uint32 part_no);
uint32 knl_total_subpart_count(knl_handle_t dc_entity);
uint32 knl_real_part_count(knl_handle_t dc_entity);
uint16 knl_part_key_count(knl_handle_t dc_entity);
uint16 knl_part_key_column_id(knl_handle_t dc_entity, uint16 id);
uint32 knl_locate_part_key(knl_handle_t dc_entity, part_key_t *key);
int32 knl_compare_defined_key(galist_t *part_keys, part_key_t *key1, part_key_t *key2);
uint32 knl_locate_part_border(knl_handle_t session, knl_handle_t dc_entity, knl_part_key_t *locate_key,
    bool32 is_left);
uint32 knl_locate_subpart_border(knl_handle_t session, knl_handle_t dc_entity, knl_part_key_t *locate_key,
    uint32 compart_no, bool32 is_left);
status_t knl_create_interval_part(knl_handle_t session, knl_dictionary_t *dc, uint32 part_no,
    part_key_t *part_key);
void knl_set_table_part(knl_cursor_t *cursor, knl_part_locate_t part_loc);
status_t knl_find_table_part_by_name(knl_handle_t dc_entity, text_t *name, uint32 *part_no);
status_t knl_find_subpart_by_name(knl_handle_t dc_entity, text_t *name, uint32 *compart_no, uint32 *subpart_no);
bool32 knl_verify_interval_part(knl_handle_t entity, uint32 part_id);
void knl_decode_part_key(part_key_t *key, knl_part_key_t *part_key);
uint32 knl_locate_subpart_key(knl_handle_t dc_entity, uint32 compart_no, part_key_t *key);
bool32 knl_is_parent_part(knl_handle_t dc_entity, uint32 part_no);
knl_handle_t knl_get_parent_part(knl_handle_t dc_entity, uint32 part_no);
uint16 knl_subpart_key_count(knl_handle_t dc_entity);
uint16 knl_subpart_key_column_id(knl_handle_t dc_entity, uint16 id);
bool32 knl_is_compart_table(knl_handle_t dc_entity);
part_type_t knl_subpart_table_type(knl_handle_t dc_entity);
void dc_recycle_all(knl_handle_t session);
status_t knl_recycle_lob_insert_pages(knl_handle_t session, knl_cursor_t *cursor);
status_t knl_recycle_lob_update_pages(knl_handle_t session, knl_cursor_t *cursor);
status_t knl_recycle_lob_column_pages(knl_handle_t session, knl_cursor_t *cursor, knl_column_t *column, char *lob);
void knl_init_table_scan(knl_handle_t handle, knl_cursor_t *cursor);
bool32 knl_table_nologging_enabled(knl_handle_t dc_entity);
bool32 knl_part_nologging_enabled(knl_handle_t dc_entity, knl_part_locate_t part_loc);
status_t knl_reset_serial_value(knl_handle_t handle, knl_handle_t dc_entity);
bool32 knl_table_nologging_force_undo(knl_handle_t dc_entity);
bool32 knl_part_nologging_force_undo(knl_handle_t dc_entity, knl_part_locate_t part_loc);
status_t knl_get_table_idx_size(knl_handle_t se, knl_dictionary_t *dc, seg_size_type_t type,
                               text_t *idx_name, int64 *result_size);
status_t knl_purge(knl_handle_t session, knl_purge_def_t *def);
status_t knl_lock_tables(knl_handle_t session, lock_tables_def_t *def);
bool32 knl_chk_seq_entry(knl_handle_t session, knl_scn_t scn, uint32 uid, uint32 oid);
status_t knl_put_ddl_sql(knl_handle_t session, knl_handle_t stmt);
status_t knl_do_force_archive(knl_handle_t session);

#define CHECK_SESSION_VALID_FOR_RETURN(knl_session)      \
    do {                                                 \
        if (SECUREC_UNLIKELY((knl_session)->killed)) {   \
            CT_THROW_ERROR(ERR_OPERATION_KILLED);        \
            return CT_ERROR;                             \
        }                                                \
        if (SECUREC_UNLIKELY((knl_session)->canceled)) { \
            CT_THROW_ERROR(ERR_OPERATION_CANCELED);      \
            return CT_ERROR;                             \
        }                                                \
    } while (0)

#define AUTO_INCREMENT_VALUE(start, offset, step)                       \
        (((start) - (offset)) % (step) == 0 ?                           \
        ((offset) + (((start) - (offset)) / (step)) * (step)) :         \
        ((offset) + (((start) - (offset)) / (step) + 1) * (step)))      \

#ifdef DB_DEBUG_VERSION
/* syncpoint interface */
status_t knl_add_syncpoint(knl_handle_t session, syncpoint_def_t *def);
status_t knl_reset_syncpoint(knl_handle_t session);
void knl_clear_syncpoint_action(knl_handle_t session);
status_t knl_exec_syncpoint(knl_handle_t session, const char *syncpoint_name);
status_t knl_set_global_syncpoint(syncpoint_def_t *def);
status_t knl_exec_global_syncpoint(uint32 sp_id, int32* user_param, int32 ret);
bool32 knl_get_global_syncpoint_flag(uint32 sp_id);
uint32 knl_get_global_syncpoint_count(uint32 sp_id);
const char* knl_get_global_syncpoint_name(uint32 sp_id);
uint32 knl_get_global_syncpoint_total_count(void);
#define SYNC_POINT(session, syncpoint_name)          \
    do {                                             \
        knl_exec_syncpoint(session, syncpoint_name); \
    } while (0)
#define SYNC_POINT_GLOBAL_START(sp_id, user_param, ret)        \
    do {                                                       \
        if (knl_get_global_syncpoint_flag(sp_id)) {            \
            knl_exec_global_syncpoint(sp_id, user_param, ret); \
        } else {
#define SYNC_POINT_GLOBAL_END \
        }                     \
    } while (0)
#else
#define SYNC_POINT(session, syncpoint_name)
#define SYNC_POINT_GLOBAL_START(sp_id, user_param, ret)
#define SYNC_POINT_GLOBAL_END
#endif /* DB_DEBUG_VERSION */


status_t knl_rebuild_ctrlfile(knl_handle_t session, knl_rebuild_ctrlfile_def_t *def);

bool32 knl_dbs_is_enable_dbs(void);
status_t knl_db_open_dbstor_ns(knl_handle_t session);

status_t knl_get_tableid(knl_handle_t handle, text_t *user_name, text_t *table_name, uint32 *tableid);


// for mysql alter table
status_t knl_alter_table4mysql(knl_handle_t se,
                               knl_handle_t stmt,
                               knl_altable_def_t *def,
                               uint32 def_count,
                               knl_dictionary_t *dc,
                               bool32 is_lrep_log);
void knl_rename_table_log_put(knl_handle_t session, knl_handle_t stmt, knl_dictionary_t *dc, knl_altable_def_t *def,
                              bool32 is_lrep_log);
void knl_alter_table_log_put(knl_handle_t session, knl_handle_t stmt, knl_dictionary_t *dc, bool32 is_lrep_log);
void knl_alter_table_after_commit4mysql(knl_handle_t session, knl_dictionary_t *dc);
void knl_alter_table_commit(knl_handle_t session, knl_handle_t stmt,
                            knl_dictionary_t *dc, bool32 is_lrep_log);
void knl_commit4mysql(knl_handle_t session);
void knl_rollback4mysql(knl_handle_t session);

void knl_alter_table_rollback(knl_handle_t session, knl_dictionary_t *dc, bool32 is_lrep_log);

status_t knl_lock_table_self_parent_child_directly(knl_handle_t session, knl_dictionary_t *dc);

void knl_alter_table_unlock_table(knl_handle_t session);
void knl_alter_table_invalidate_dc(knl_handle_t session, knl_dictionary_t *dc);
status_t knl_alter_table_update_dc(knl_handle_t se, knl_dictionary_t *dc);
bool32 knl_alter_table_is_add_hashpart(knl_dictionary_t *dc, knl_altable_def_t *def);

// for mysql rename table
void knl_rename_table_write_logical(knl_handle_t se, knl_altable_def_t *def, knl_dictionary_t *dc);
status_t knl_fill_fk_name_from_sys4mysql(knl_handle_t se, char *fk_name, uint32_t ref_uid,
                                         uint32_t ref_oid, knl_dictionary_t *dc);
status_t knl_update_ref_syscons4mysql(knl_handle_t se, knl_dictionary_t *old_dc, knl_dictionary_t *new_dc);
status_t knl_update_comment4mysql(knl_handle_t se, knl_dictionary_t *old_dc, knl_dictionary_t *new_dc);
bool32 is_sys_col_ref(knl_cursor_t *cursor);
bool32 is_sys_fk(knl_cursor_t *cursor, uint32_t ref_uid, uint32_t ref_oid);
bool32 is_fetch_success(knl_handle_t se, knl_cursor_t *cursor);
status_t knl_set_ctrl_core_version(void *item_ptr);
status_t knl_schema_exists4mysql(knl_handle_t session, text_t *schema_name, bool32 *exist);
status_t knl_object_exists4mysql(knl_handle_t session, text_t *schema_name, text_t *object_name, bool32 *exist);
status_t knl_is_daac_cluster_ready(bool32 *is_ready);

status_t knl_unlock_users4mysql(knl_handle_t session);

void knl_set_db_status_4mysql_init(bool32 open);
status_t knl_get_serial_value_tmp_table(knl_handle_t se, knl_handle_t dc_entity, uint64 *value,
    uint16 auto_inc_step, uint16 auto_inc_offset, bool32 is_change);
status_t knl_set_arch_param(knl_handle_t handle, knl_alter_sys_def_t *def);
uint8 knl_get_initrans(void);
void knl_set_sql_server_initializing_status(knl_handle_t session, bool32 status);

void knl_lock_info_log_put4mysql(knl_handle_t session, void *lock_info);
void knl_invalid_dd_log_put4mysql(knl_handle_t session, void *invalid_info);
uint32 knl_db_node_count(knl_handle_t session);

/* @} */
#ifdef __cplusplus
}
#endif

#endif

