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
 * rc_reform.h
 *
 *
 * IDENTIFICATION
 * src/rc/rc_reform.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __RC_REFORM_H__
#define __RC_REFORM_H__

//RC = Reform cluster
#include <semaphore.h>
#include "cms_interface.h"
#include "cm_thread.h"
#include "cm_encrypt.h"
#include "cm_utils.h"
#include "cm_date.h"
#include "cm_latch.h"
#include "knl_log.h"
#include "mes_func.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DTC_RUN_WITH_REFORM

#define RC_WAIT_DB_OPEN_TIME (10)  // ms
#define CKPT_LOG_REDO_STAT_COUNT (500)

typedef struct st_instance_list {
    uint8 inst_id_list[CT_MAX_INSTANCES];
    uint8 inst_id_count;
    uint8 reserve[3];
} instance_list_t;


typedef enum e_reform_type_list {
    REFORM_LIST_BEFORE      = 0,   // instance set before reform
    REFORM_LIST_AFTER       = 1,   // instance set after reform
    REFORM_LIST_JOIN        = 2,   // instance new join cluster
    REFORM_LIST_LEAVE       = 3,   // instance leaving cluster
    REFORM_LIST_ABORT       = 4,   // instance aborted cluster
    REFORM_LIST_FAIL        = 5,   // instance join or leaving cluster but failed in last reform
    REFORM_LIST_TYPE_COUNT  = 6,   // enum end for type count
} reform_list_type_t;

#define RC_REFORM_LIST_COUNT(reform_info, type) ((reform_info)->reform_list[type].inst_id_count)
#define RC_REFORM_LIST(reform_info, type) ((reform_info)->reform_list[type])

typedef enum e_reform_role {
    REFORM_ROLE_STAY   = 0,
    REFORM_ROLE_JOIN   = 1,
    REFORM_ROLE_LEAVE  = 2,
    REFORM_ROLE_ABORT  = 3,
    REFORM_ROLE_FAIL   = 4,
} reform_role_t;

typedef struct st_reform_info {
    instance_list_t reform_list[REFORM_LIST_TYPE_COUNT];
    uint64          version;
    uint64          next_version;
    uint64          trigger_version;
    reform_role_t   role;
    volatile uint64 alive_bitmap;

    uint8           master_id;      // master instance is in charge of remaster and dtc recovery in case of reform cluster
    bool8           master_changed;
    volatile uint8  fetch_cms_time;
    bool8           full_restart;

    bool8           cluster_steady;
    bool8           have_error;
    volatile uint32 failed_reform_status;
} reform_info_t;


typedef enum e_reform_mode {
    REFORM_MODE_NONE        = 0,
    REFORM_MODE_PLANED      = 1,
    REFORM_MODE_OUT_OF_PLAN = 2,
} reform_mode_t;

typedef enum e_reform_status {
    REFORM_PREPARE = 0,   // prepare to reform, wait open reform/ leaving reform done
    REFORM_FROZEN,        // begin   to reform, frozen and not accessable
    REFORM_MOUNTING,      // mount in full restart
    REFORM_RECOVERING,    // remaster or recover in progress
    REFORM_RECOVER_DONE,  // recover done, page can be caccessed
    REFORM_OPEN,          // can accept read request
    REFORM_DONE,          // reform is done
} reform_status_t;

typedef enum e_reform_cms_state {
    RC_CMS_ONLINE          = 0,
    RC_CMS_OFFLINE         = 1,  // mapping cms unknown/ offline state
    RC_CMS_STATE_COUNT     = 2,  // enum end for cms state count
} reform_cms_state_t;

typedef enum e_reform_step_state {
    RC_NOT_RUN          = 0,
    RC_STEP_RUNNING     = 1,
    RC_STEP_FINISH      = 2,
    RC_STEP_FAILED      = -1,
} reform_step_state_t;
 
#define RC_REFORM_IN_PROGRESS (g_rc_ctx->status < REFORM_DONE && g_rc_ctx->status > REFORM_PREPARE)
#define RC_REFORM_RECOVERY_IN_PROGRESS (g_rc_ctx->status < REFORM_RECOVER_DONE && g_rc_ctx->status > REFORM_PREPARE)
#define RC_REFORM_NOT_IN_PROGRESS (g_rc_ctx->status == REFORM_DONE || g_rc_ctx->status == REFORM_PREPARE)


#define RC_MODE_STR_LENGTH       12          // RC Mode string max lengh, refresh it when update the string
#define RC_MODE_PLANED_STR       "planed"
#define RC_MODE_OUT_OF_PLAN_STR  "out of plan"


#define RC_WAIT_CMS_NOTIFY_TIME   10000 // wait 10s, do one active-fetch
#define RC_TRY_FETCH_CMS          10    // try 10 times, after notified
#define RC_RETRY_SLEEP            1000
#define RC_REFORM_PROC_WAIT_TIMEOUT        5 // ms
#define RC_TRIGGER_MUTEX_WAIT_TIMEOUT        (5 * 1000) // 5s
#define RC_BCAST_CHANGE_STATUS_TIMEOUT (5 * 1000) // 5s
#define REFORM_SLEEP_INTERVAL 5         // 5 ms
#define REFORM_SEND_MSG_RETRY_TIMES 3   // retry 3 times
typedef struct st_cluster_view {
    latch_t latch;
    bool32 is_joining;           // have node living and have node joining
    volatile bool32 is_stable;   // no reform happen, and no reform will trig at current
    uint64 bitmap;               // view of cluster node info
    uint64 version;              // version of cluseter res list
    uint64 reform_bitmap;        // view of cluster node for reform, including JOINING and LEAVING node
} cluster_view_t;

typedef struct st_reform_action_info {
    reform_list_type_t  enque_list[REFORM_LIST_TYPE_COUNT];
    uint8               enque_count;
    bool8               member_change;
    bool8               happen_assert; // This situation seems impossible, is not properly handled, need assert here
} reform_action_info_t;

typedef struct st_reform_step_stat {
    uint64_t cost_time;
    timeval_t start_time;
    timeval_t finish_time;
    reform_step_state_t run_stat;
} reform_step_t;

typedef struct st_reform_stat {
    uint64 build_channel_elapsed;   // build MES channel time consuming
    uint64 remaster_elapsed;        // remaster time consuming
    uint64 recovery_elapsed;        // recovery time consuming
    uint64 deposit_elapsed;         // deposit undo && transactions time consuming
} reform_stat_t;

typedef struct st_reform_detail {
    reform_step_t build_channel_elapsed;        // build MES channel time consuming
    reform_step_t remaster_elapsed;             // remaster time consuming
    reform_step_t remaster_prepare_elapsed;     // remaster time consuming
    reform_step_t remaster_assign_task_elapsed; // remaster time consuming
    reform_step_t remaster_migrate_elapsed;     // remaster time consuming
    reform_step_t remaster_recovery_elapsed;    // remaster time consuming
    reform_step_t remaster_publish_elapsed;     // remaster time consuming
    reform_step_t recovery_elapsed;             // recovery time consuming
    reform_step_t recovery_set_create_elapsed;  // partial recovery set create time consuming
    reform_step_t recovery_set_revise_elapsed;  // partial recovery ask master and revise rcy set time consuming
    reform_step_t recovery_replay_elapsed;      // recovery replay time consuming
    reform_step_t deposit_elapsed;              // deposit undo && transactions time consuming
    reform_step_t ckpt_elapsed;                 // flush all replayed pages
    reform_step_t clean_ddp_elapsed;            // clean ddl
} reform_detail_t;
 
typedef struct st_reform_rcy_node {
    uint8 node_id;
    uint8 reserved[3];
    log_point_t rcy_point;
    log_point_t rcy_point_saved;
    atomic_t lsn;
} reform_rcy_node_t;

typedef struct st_rc_redo_stat_list {
    uint64 time_interval;
    uint64 redo_generate_size;
    uint64 redo_recycle_size;
    uint64 redo_recovery_size;
    double redo_generate_speed;
    double redo_recycle_speed;
    page_id_t ckpt_queue_first_page;
    date_t end_time;
} rc_redo_stat_list_t;

typedef struct st_rc_redo_stat {
    spinlock_t lock;
    uint8 ckpt_num;
    uint32 redo_stat_cnt;
    uint32 redo_stat_start_ind;
    rc_redo_stat_list_t stat_list[CKPT_LOG_REDO_STAT_COUNT];
} rc_redo_stat_t;

typedef struct st_reform_ctx {
    uint8              self_id;
    bool8              started;
    volatile bool8     is_blocked;      // blocked at first init from joinning 2 joined
    volatile bool8     in_view_sync;

    void              *session;
    thread_t           thread;
    thread_t           trigger_thread;
    mes_mutex_t        trigger_mutex; // used for stop/restart trigger proc

    char               res_type[CMS_MAX_RES_TYPE_LEN];

    struct st_cms_res_status_list_t *clu_stat[2];
    uint32             current_idx;

    reform_info_t      info;

    reform_mode_t      mode;
    volatile uint32    status;
    mes_mutex_t        reform_mutex;  // wake up reform_proc
    log_point_t        prcy_trunc_point;     // check whether the prcy ckpt is complete based on prcy_trunkc_point

    reform_stat_t      reform_stat;
    reform_detail_t    reform_detail;
    rc_redo_stat_t     redo_stat;
} reform_ctx_t;

typedef struct st_rc_reform_status_notify {
    mes_message_head_t head;
    uint32 change_status;
    uint64 reform_trigger_version;
}rc_reform_status_notify_t;

extern reform_ctx_t *g_rc_ctx;
typedef status_t (*rc_cb_start_new_reform)(reform_mode_t mode);
typedef void (*rc_cb_lock)(void);
typedef void (*rc_cb_unlock)(void);
typedef status_t (*rc_cb_build_channel)(reform_info_t *info);
typedef void (*rc_cb_release_channel)(reform_info_t *info);
typedef bool32 (*rc_cb_finished)(void);
typedef void (*rc_cb_stop_cur_reform)(void);
typedef bool32 (*rc_cb_reform_canceled)(void);
typedef status_t (*rc_cb_promote_role)(knl_session_t *session);

extern const uint8_t g_bitcnt[256];

typedef struct st_reform_callback {
    rc_cb_start_new_reform start_new_reform;
    rc_cb_lock lock;
    rc_cb_unlock unlock;
    rc_cb_build_channel build_channel;
    rc_cb_release_channel release_channel;
    rc_cb_finished finished;
    rc_cb_stop_cur_reform stop_cur_reform;
    rc_cb_reform_canceled rc_reform_cancled;
    rc_cb_promote_role rc_promote_role;
} reform_callback_t;

typedef struct st_reform_init {
    uint8               self_id;
    void                *session;
    char                res_type[CMS_MAX_RES_TYPE_LEN];
    reform_callback_t   callback;
} reform_init_t;

status_t init_cms_rc(reform_ctx_t *rf_ctx, reform_init_t *init_st);
void free_cms_rc(bool32 force);
bool32 rc_is_master(void);
bool32 rc_is_full_restart(void);

static inline void rc_bitmap64_set(uint64 *bitmap, uint8 num)
{
    uint64 position;
    CM_ASSERT(num < CT_MAX_INSTANCES);

    position = (uint64)1 << num;

    *bitmap |= position;
}

static inline void rc_bitmap64_clear(uint64 *bitmap, uint8 num)
{
    uint64 position;
    CM_ASSERT(num < CT_MAX_INSTANCES);

    position = ~((uint64)1 << num);

    *bitmap &= position;
}

static inline bool32 rc_bitmap64_exist(uint64 *bitmap, uint8 num)
{
    uint64 position;
    CM_ASSERT(num < CT_MAX_INSTANCES);

    position = (uint64)1 << num;

    position = *bitmap & position;

    return 0 != position;
}

#define ELAPSED_BEGIN(elapsed_begin) ((void)cm_gettimeofday(&(elapsed_begin)))
#define ELAPSED_END(elapsed_begin, target) \
    do { \
        timeval_t elapsed_end; \
        (void)cm_gettimeofday(&(elapsed_end)); \
        (target) = TIMEVAL_DIFF_US(&(elapsed_begin), &(elapsed_end)); \
    } while (0)

#define RC_STEP_BEGIN(step) \
    do {                    \
        (void)cm_gettimeofday(&((step).start_time)); \
        ((step).run_stat) = RC_STEP_RUNNING;           \
    } while (0)
 
#define RC_STEP_END(step, step_status)                                            \
    do {                                                                          \
        (void)cm_gettimeofday(&((step).finish_time));                                 \
        ((step).cost_time) = TIMEVAL_DIFF_US(&((step).start_time), &((step).finish_time)); \
        ((step).run_stat) = (step_status);                                              \
    } while (0)
 
// internal implementations
void rc_reform_trigger_proc(thread_t *thread);
void rc_reform_proc(thread_t *thread);

reform_role_t rc_get_role(reform_info_t *info, uint8 id);

status_t rc_build_channel(reform_info_t *info);
status_t rc_reform_build_channel(reform_detail_t *detail);
void rc_release_channel(reform_info_t *info);
void rc_release_abort_channel(reform_info_t *info);
void rc_refresh_cms_abort_ref_map(uint64 alive_bitmap);
void rc_set_cms_abort_ref_map(uint8 inst_id, reform_work_state_t state);

bool32 check_id_in_list(uint8 inst_id, instance_list_t *list);
void add_id_to_list(uint8 inst_id, instance_list_t *list);

void rc_notify_cluster_change(struct st_cms_res_status_list_t *res_list);
status_t rc_change_role(uint8 oper);   // 1: upgrade to master; 2:downgrade from master
void rc_reset_reform_stat(void);
void rc_sleep_random(uint32 range);

#define RC_RETRY_IF_ERROR(func)           \
    while (func) {                         \
        rc_sleep_random(RC_RETRY_SLEEP);  \
        rc_check_abort_in_loop();         \
    }

void rc_init_inst_list(instance_list_t *list);
bool32 check_id_in_list(uint8 inst_id, instance_list_t *list);
void add_id_to_list(uint8 inst_id, instance_list_t *list);
reform_role_t rc_get_role(reform_info_t *info, uint8 id);
void rc_log_instance_list(instance_list_t *list, char *list_name);
bool32 rc_get_check_inst_alive(uint32_t inst_id);
bool32 rc_detect_reform_triggered(void);
bool32 rc_cluster_stat_changed(void);
status_t rc_mes_send_data_with_retry(const char *msg, uint64 interval, uint64 retry_time);
void rc_release_tse_resources(reform_info_t *info);
reform_mode_t rc_get_change_mode(void);
void rc_current_stat_step_forward(void);
bool32 reform_mutex_timed_lock(mes_mutex_t *mutex, uint32 timeout);
status_t rc_start_reform(reform_mode_t mode);
status_t rc_broadcast_change_status(knl_session_t *session, reform_info_t *rc_info, bool32 status);

// support get the latest cluster view for any node in the cluster
void rc_get_cluster_view(cluster_view_t *view, bool32 need_stable);

// get the cluster view during reform, including joining and leaving node
void rc_get_cluster_view4reform(cluster_view_t *view);

// decide whether the cluster has changed by a basic cluster_view
bool32 rc_is_cluster_changed(cluster_view_t *prev_view);

// allow reform to set workstat, and expose this node to the cluseter view
void rc_allow_reform_finish(void);

uint64 get_alive_bitmap_by_reform_info(reform_info_t *reform_info);

EXTER_ATTACK void rc_accept_status_change(void *sess, mes_message_t *receive_msg);

status_t rc_notify_reform_status(knl_session_t *session, reform_info_t *rc_info, uint32 status);

status_t rc_set_redo_replay_done(knl_session_t *session, reform_info_t *rc_info, bool32 full_recovery);

bool32 rc_reform_trigger_disable(void);
void rc_reform_trigger_enable(void);
cms_res_status_list_t *rc_get_current_stat(void);
cms_res_status_list_t *rc_get_target_stat(void);

#ifdef __cplusplus
}
#endif

#endif
