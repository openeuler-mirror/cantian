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
 * sysdba_defs.h
 *
 *
 * IDENTIFICATION
 * src/kernel/include/sysdba_defs.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_SYSDBA_DEFS_H__
#define __KNL_SYSDBA_DEFS_H__

#include "knl_defs.h"

#ifdef __cplusplus
extern "C" {
#endif
    
#define PARAM_UNLIMITED 0
#define DEFAULT_PROFILE_ID   0
#define DEFAULT_PROFILE_NAME "DEFAULT"
#define PLAN_TYPE_USER 0
#define PLAN_TYPE_TENANT 1

typedef enum en_resource_type {
    KERNEL_RES = 0,  // kernel related type
    PASSWORD_RES,    // pwd related type
    RESOURCE_TYPE_END
} resource_type_t;

typedef enum en_resource_param {
    // Specify the number of failed attempts to log in to the user account before the account is locked
    FAILED_LOGIN_ATTEMPTS = 0,
    // Specify the number of days the same pwd can be used for authentication.
    // The pwd expires if it is not changed within this period, and further connections are rejected.
    PASSWORD_LIFE_TIME,
    // Specify the number of days before which a pwd cannot be reused.
    // If you set PWD_REUSE_TIME to an integer value, then you must set PWD_REUSE_MAX to UNLIMITED.
    PASSWORD_REUSE_TIME,
    // Specify the number of pwd changes required before the current pwd can be reused.
    // If you set PWD_REUSE_MAX to an integer value, then you must set PWD_REUSE_TIME to UNLIMITED.
    PASSWORD_REUSE_MAX,
    // Specify the number of days an account will be locked
    // after the specified number of consecutive failed login attempts.
    PASSWORD_LOCK_TIME,
    // Specify the number of days after the grace period begins during which a warning is issued and login is allowed.
    // If the pwd is not changed during the grace period, the pwd expires.
    PASSWORD_GRACE_TIME,
    // Specify the number of concurrent sessions to which you want to limit the user
    SESSIONS_PER_USER,
    PASSWORD_MIN_LEN,
    RESOURCE_PARAM_END
} resource_param_t;
    
typedef enum en_value_type {
    VALUE_DEFAULT,
    VALUE_UNLIMITED,
    VALUE_NORMAL
} value_type_t;

typedef struct limit_value {
    value_type_t type;
    uint64 value;
} limit_value_t;

typedef struct st_knl_profile_def {
    text_t name;
    uint32 mask;
    bool32 is_replace;
    limit_value_t limit[RESOURCE_PARAM_END];
} knl_profile_def_t;

typedef struct st_knl_directory_def {
    bool32 is_replace;
    text_t name;
    text_t path;
} knl_directory_def_t;

status_t knl_create_profile(knl_handle_t session, knl_profile_def_t *def);
status_t knl_drop_profile(knl_handle_t session, knl_drop_def_t *def);
status_t knl_alter_profile(knl_handle_t session, knl_profile_def_t *def);
status_t knl_create_directory(knl_handle_t session, knl_directory_def_t *def);
status_t knl_drop_directory(knl_handle_t session, knl_drop_def_t *def);

#define SYNONYM_EXIST(dc)        ((dc)->is_sysnonym && NULL != (dc)->syn_handle)
#define SYNONYM_NOT_EXIST(dc)    (!(dc)->is_sysnonym || NULL == (dc)->syn_handle)
#define SYNONYM_OBJECT_EXIST(dc) (NULL != (dc)->handle)

typedef enum en_comment_on_type {
    COMMENT_ON_TABLE = 0, /* TABLE */
    COMMENT_ON_COLUMN,    /* COLUMN */
} comment_on_type_t;

typedef struct st_knl_comment_def {
    comment_on_type_t type;
    text_t owner;
    text_t name;
    text_t column;
    text_t comment;
    uint32 uid;
    uint32 id;
    uint32 column_id;
} knl_comment_def_t;

status_t knl_comment_on(knl_handle_t session, knl_handle_t stmt, knl_comment_def_t *def);

typedef struct st_knl_alttrig_def {
    text_t user;
    text_t name;
    bool32 enable;
} knl_alttrig_def_t;

typedef struct st_trigger_set {
    void *next;      // !!! must be the first memeber of structure
    uint8 *count;    // which points to entry->trig_count
    void *items[CT_MAX_TRIGGER_COUNT];
} trigger_set_t;


typedef struct st_knl_job_def {
    int64 job_id;
    text_t what; /* the content to execute of this job */
    int64 next_date;
    text_t interval;
    bool32 no_parse; /* true: not parse the job when submit; false: should parse job when submit */
    int32 instance;
    text_t lowner; /* the user name who submitted the job. */
} knl_job_def_t;

typedef enum en_job_update_type {
    JOB_TYPE_RUN = 0,
    JOB_TYPE_BROKEN,
    JOB_TYPE_REMOVE,
    JOB_TYPE_START,
    JOB_TYPE_FINISH,
} job_update_type_t;

typedef struct st_knl_job_node {
    job_update_type_t node_type;
    int64 job_id;
    int64 this_date;
    int64 next_date;
    bool32 is_broken;
    int32 failures;
    bool32 is_success;
    text_t user; /* operator */
} knl_job_node_t;

status_t knl_submit_job(knl_handle_t session, knl_job_def_t *def);
status_t knl_update_job(knl_handle_t session, text_t *user, knl_job_node_t *job, bool32 should_exist);
status_t knl_delete_job(knl_handle_t session, text_t *user, const int64 jobno, bool32 should_exist);

/* interface for resource manager */
typedef struct st_sql_map_text_t {
    text_t text;
    bool32 is_cut;
} sql_map_text_t;

typedef struct st_knl_sql_map {
    uint32 user_id;
    uint32 options;
    uint32 src_hash_code;
    sql_map_text_t src_text;
    sql_map_text_t dst_text;
    memory_context_t *memory;
} knl_sql_map_t;
status_t knl_alter_sql_map(knl_handle_t session, knl_sql_map_t *sql_map);
status_t knl_drop_sql_map(knl_handle_t session, knl_sql_map_t *sql_map);
status_t knl_refresh_sql_map_hash(knl_handle_t session, knl_cursor_t *cursor, uint32 hash_value);

typedef struct st_knl_rsrc_plan {
    uint32 oid;
    uint32 num_rules;
    char name[CT_NAME_BUFFER_SIZE];
    char description[CT_COMMENT_BUFFER_SIZE];
    uint32 type;
}knl_rsrc_plan_t;

typedef struct st_knl_rsrc_plan_rule {
    char plan_name[CT_NAME_BUFFER_SIZE];
    char group_name[CT_NAME_BUFFER_SIZE];
    uint32 max_cpu_limit;
    uint32 max_sessions;
    uint32 max_active_sess;
    uint32 max_queue_time;
    uint32 max_exec_time;
    uint32 max_temp_pool;
    uint32 max_iops;
    uint32 max_commits;
    char description[CT_COMMENT_BUFFER_SIZE];
}knl_rsrc_plan_rule_t;

typedef struct st_knl_rsrc_group {
    uint32 oid;
    char name[CT_NAME_BUFFER_SIZE];
    char description[CT_COMMENT_BUFFER_SIZE];
}knl_rsrc_group_t;

typedef struct st_knl_rsrc_group_mapping {
    char attribute[CT_NAME_BUFFER_SIZE];
    char value[CT_VALUE_BUFFER_SIZE];
    char group_name[CT_NAME_BUFFER_SIZE];
}knl_rsrc_group_mapping_t;

typedef struct st_knl_rsrc_plan_rule_def {
    knl_rsrc_plan_rule_t rule;
    union {
        struct {
            bool32 is_update : 1;
            bool32 is_comment_set : 1;
            bool32 is_cpu_set : 1;
            bool32 is_sessions_set : 1;
            bool32 is_active_sess_set : 1;
            bool32 is_queue_time_set : 1;
            bool32 is_exec_time_set : 1;
            bool32 is_temp_pool_set : 1;
            bool32 is_iops_set : 1;
            bool32 is_commits_set : 1;
            bool32 unused : 22;
        };
        bool32 is_option_set;
    };
}knl_rsrc_plan_rule_def_t;

status_t knl_create_control_group(knl_handle_t session, knl_rsrc_group_t *group);
status_t knl_delete_control_group(knl_handle_t session, text_t *group_name);
status_t knl_update_control_group(knl_handle_t session, knl_rsrc_group_t *group);
status_t knl_create_rsrc_plan(knl_handle_t session, knl_rsrc_plan_t *plan);
status_t knl_delete_rsrc_plan(knl_handle_t session, text_t *plan_name);
status_t knl_update_rsrc_plan(knl_handle_t session, knl_rsrc_plan_t *plan);
status_t knl_create_rsrc_plan_rule(knl_handle_t session, knl_rsrc_plan_rule_def_t *def);
status_t knl_delete_rsrc_plan_rule(knl_handle_t session, text_t *plan_name, text_t *group_name);
status_t knl_update_rsrc_plan_rule(knl_handle_t session, knl_rsrc_plan_rule_def_t *def);
status_t knl_set_cgroup_mapping(knl_handle_t session, knl_rsrc_group_mapping_t *mapping);


typedef struct st_object_address {
    object_type_t tid;              /* type Id for object */
    uint32 uid;                     /* owner user id */
    uint64 oid;                     /* ID of the object */
    knl_scn_t scn;                  /* last scn of this object */
    char name[CT_NAME_BUFFER_SIZE]; /* object name */
} object_address_t;

status_t knl_insert_dependency_list(knl_handle_t session, object_address_t *depender, galist_t *referenced_list);
status_t knl_delete_dependency(knl_handle_t session, uint32 uid, int64 oid, uint32 tid);
status_t knl_insert_dependency(knl_handle_t *session, object_address_t *depender, object_address_t *ref_obj,
    uint32 order);

typedef enum en_seg_size_type {
    SEG_BYTES = 0,
    SEG_PAGES = 1,
    SEG_EXTENTS = 2,
} seg_size_type_t;

/* for dba functions, views */
status_t knl_get_segment_size_by_cursor(knl_handle_t se, knl_cursor_t *knl_cur, uint32 *extents, uint32 *pages,
    uint32 *page_size);
status_t knl_get_segment_size(knl_handle_t se, page_id_t entry, uint32 *extents, uint32 *pages, uint32 *page_size);
status_t knl_get_partitioned_lobsize(knl_handle_t session, knl_dictionary_t *dc, seg_size_type_t type,
    int32 col_id, int64 *result);
status_t knl_get_partitioned_tabsize(knl_handle_t session, knl_dictionary_t *dc, seg_size_type_t type,
    int64 *result);
status_t knl_get_table_partsize(knl_handle_t session, knl_dictionary_t *dc, seg_size_type_t type, text_t *part_name,
    int64 *result);
status_t knl_get_table_size(knl_handle_t session, knl_dictionary_t *dc, seg_size_type_t type, int64 *result);
status_t knl_get_partitioned_indsize(knl_handle_t session, knl_dictionary_t *dc, seg_size_type_t type,
    text_t *index_name, int64 *result);
status_t knl_get_free_extent(knl_handle_t se, uint32 file_id, page_id_t start, uint32 *extent,
    uint64 *page_count, bool32 *is_last);
void knl_calc_seg_size(seg_size_type_t type, uint32 pages, uint32 page_size, uint32 extents, int64 *result);

status_t knl_get_table_name(knl_handle_t se, uint32 fileid, uint32 pageid, text_t* table_name);
uint32 knl_get_bucket_by_variant(variant_t *data, uint32 part_cnt);
status_t knl_get_lob_recycle_pages(knl_handle_t se, page_id_t entry, uint32 *extents, uint32 *pages, uint32 *page_size);

#ifdef __cplusplus
}
#endif

#endif