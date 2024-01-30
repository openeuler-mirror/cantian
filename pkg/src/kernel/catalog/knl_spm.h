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
 * knl_spm.h
 *
 *
 * IDENTIFICATION
 * src/kernel/catalog/knl_spm.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_SPM_H__
#define __KNL_SPM_H__

#include "dc_util.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum st_sys_spm_sqls_column {
    SYS_SPM_SQLS_COL_SCHEMA = 0,
    SYS_SPM_SQLS_COL_SQL_ID,
    SYS_SPM_SQLS_COL_SQL_SIGN,
    SYS_SPM_SQLS_COL_CREATE_TIME,
    SYS_SPM_SQLS_COL_SQL_TEXT,
    SYS_SPM_SQLS_COL_COLUMN_COUNT
} sys_spm_sqls_column_t;

typedef enum st_sys_spm_column {
    SYS_SPM_COL_SCHEMA = 0,
    SYS_SPM_COL_SQL_ID,
    SYS_SPM_COL_SQL_SIGN,
    SYS_SPM_COL_SIGNATURE,
    SYS_SPM_COL_PLAN_SRC,
    SYS_SPM_COL_STATUS,
    SYS_SPM_COL_LAST_STATUS,
    SYS_SPM_COL_CREATE_TIME,
    SYS_SPM_COL_MODIFY_TIME,
    SYS_SPM_COL_COST,
    SYS_SPM_COL_EXEC_TIME,
    SYS_SPM_COL_EVOLUTION,
    SYS_SPM_COL_PROF_NAME,
    SYS_SPM_COL_PROFILE,
    SYS_SPM_COL_OUTLINE,
    SYS_SPM_COL_COLUMN_COUNT
} sys_spm_column_t;

typedef struct st_knl_spm_plan {
    char signature[CT_SIGN_BUF_SIZE];
    char prof_name[CT_NAME_BUFFER_SIZE];
    int32 status;
    int32 exec_time;
    double cost;
} knl_spm_plan_t;

typedef enum st_spm_plan_status {
    SPM_STATUS_READY = 0,
    SPM_STATUS_ACCEPTED,
    SPM_STATUS_FIXED,
    SPM_STATUS_DISCARD
} spm_plan_status_t;

typedef enum st_spm_plan_src {
    SPM_PLAN_SRC_CBO = 0,
    SPM_PLAN_SRC_DBA,
    SPM_PLAN_SRC_IMP
} spm_plan_src_t;

typedef struct st_knl_spm_def {
    uint32 uid;
    uint32 sql_id;
    text_t sql_text;
    text_t sql_sign;
    text_t signature;
    text_t outline;
    text_t prof_name;
    text_t profile;
    double cost;
    int32 plan_src;
    int32 status;
    int32 last_status;
    int32 exec_time;
    int32 evolution;
} knl_spm_def_t;

typedef struct st_dc_spm_ctrl {
    dc_list_node_t free_node;  // !!!this member must be the first one
    struct st_dc_spm_ctrl *hash_prev;
    struct st_dc_spm_ctrl *hash_next;
    uint32 hash_value;
} dc_spm_ctrl_t;

typedef struct st_spm_bucket {
    spinlock_t lock;
    dc_spm_ctrl_t *first;
} spm_bucket_t;

typedef struct st_dc_spm {
    uint32 bucket_count;
    uint32 item_count;
    memory_context_t *mem_ctx;
    dc_list_t free_list;
    spm_bucket_t buckets[1];
} dc_spm_t;

typedef struct st_dc_spm_sql {
    dc_spm_ctrl_t ctrl;  // !!!this member must be the first one
    spinlock_t lock;
    bool32 invalid;
    dc_spm_t *parent;
    uint32 uid;
    char sql_sign[CT_SIGN_BUF_SIZE];
    struct st_dc_spm baseline;
} dc_spm_sql_t;

typedef struct st_dc_spm_plan {
    dc_spm_ctrl_t ctrl;  // !!!this member must be the first one
    dc_spm_sql_t *parent;
    char plan_sign[CT_SIGN_BUF_SIZE];  // for hash value
    knl_spm_plan_t plan_info;
} dc_spm_plan_t;

status_t spm_calculate_md5_signature(text_t *text, text_t *signature);
static inline void dc_spm_abandoned_plan(dc_spm_sql_t *sql, dc_spm_plan_t *plan)
{
    dc_list_add(&sql->baseline.free_list, &plan->ctrl.free_node);
}

static inline void dc_spm_abandoned_sql(dc_spm_t *dc_spm, dc_spm_sql_t *spm_sql)
{
    mctx_destroy(spm_sql->baseline.mem_ctx);
    dc_list_add(&dc_spm->free_list, &spm_sql->ctrl.free_node);
}
dc_spm_plan_t *dc_spm_get_optimal_plan(dc_spm_t *baseline);
dc_spm_sql_t *dc_spm_discover_sql(knl_session_t *session, uint32 uid, uint32 sql_id, text_t *sql_sign);
dc_spm_plan_t *dc_spm_discover_plan(dc_spm_t *baseline, text_t *signature);
dc_spm_plan_t *dc_spm_discover_prof(dc_spm_t *baseline, text_t *prof_name);
dc_spm_plan_t *dc_spm_discover_fixed_plan(dc_spm_t *baseline);
status_t dc_spm_fetch_sql(knl_session_t *knl_session, uint32 uid, uint32 sql_id, text_t *sql_sign, dc_spm_sql_t **sql);
status_t dc_spm_creat_plan(dc_spm_t *baseline, text_t *signature, dc_spm_plan_t **plan);
status_t dc_creat_spm_context(dc_context_t *ctx);
status_t dc_spm_cache_scheme(dc_spm_sql_t *sql, dc_spm_plan_t *new_plan);
void dc_spm_del_sql(dc_spm_sql_t *spm_sql);
void dc_spm_del_plan(dc_spm_plan_t *plan);
void dc_spm_make_clean(knl_session_t *session);

status_t knl_spm_rd_col_txt(knl_cursor_t *cursor, uint32 col_id, text_t *dst_txt);
status_t knl_spm_rd_col_lob(knl_session_t *session, knl_cursor_t *cursor, uint32 col_id, text_t *dst_text);
status_t knl_spm_fetch_prof_for_alt(knl_session_t *session, knl_spm_def_t *def);
status_t knl_spm_fetch_prof_for_accept(knl_session_t *session, knl_spm_def_t *def);
status_t knl_spm_fetch_prof_for_delete(knl_session_t *session, knl_spm_def_t *def);
status_t knl_spm_get_sql_sign(knl_session_t *session, text_t *schema, text_t *sql_id, text_t *plansign, text_t *sqlsign);
status_t knl_spm_fetch_prof_txt(knl_session_t *session, text_t *prof_name, text_t *profile);
status_t knl_spm_get_sql_txt(knl_session_t *session, text_t *schema, text_t *sql_id, text_t *sql_sign, text_t *sql_text);

status_t knl_ins_sys_spm(knl_session_t *session, knl_spm_def_t *spm_def);
status_t knl_upd_sys_spm_prof(knl_session_t *session, knl_spm_def_t *spm_def);
status_t knl_deactivate_sys_spm(knl_session_t *session, text_t *schema, text_t *sql_id, text_t *signature);
status_t knl_del_sys_spm(knl_session_t *session, text_t *schema, text_t *sql_id, text_t *sql_sign, text_t *signature);
status_t knl_del_sys_spm_prof(knl_session_t *session, knl_spm_def_t *def);
status_t knl_clean_sys_spm_schmpcr(knl_session_t *session, text_t *schema);
void knl_spm_open_load_curs(knl_session_t *session, knl_cursor_t *cursor, text_t *schema);
#ifdef __cplusplus
}
#endif

#endif
