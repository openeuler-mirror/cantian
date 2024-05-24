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
 * dtc_drc.c
 *
 *
 * IDENTIFICATION
 * src/cluster/dtc_drc.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_cluster_module.h"
#include "cm_defs.h"
#include "dtc_drc.h"
#include "dtc_context.h"
#include "knl_buflatch.h"
#include "mes_func.h"
#include "dtc_dcs.h"
#include "dtc_ckpt.h"
#include "dtc_trace.h"
#include "dtc_drc_stat.h"
#include "cm_malloc.h"
#include "cm_date.h"
#include "rc_reform.h"
#include "knl_cluster_module.h"
#include "cm_io_record.h"
#include "cantian_fdsa.h"
extern bool32 g_enable_fdsa;
drc_res_ctx_t g_drc_res_ctx;  // need to put it to global DTC instance structure later
//buf_lock_mode string
char *g_buf_lock_mode_str[DRC_LOCK_MODE_MAX] = { "NULL", "SHARE", "EXCLUSIVE" };

// cache lock res for recovery before send to remote
drc_lock_batch_buf_t g_drc_lock_batch_buf;

#define DRC_LOCK_CONTEXT (&g_drc_lock_batch_buf)
uint8 g_mode_compatible_matrix[DRC_LOCK_MODE_MAX][DRC_LOCK_MODE_MAX] = {
    { 1, 1, 1 },
    { 1, 1, 0 },
    { 1, 0, 0 },
};

char * const g_drc_lock_mode_str[] = { "NULL", "SH", "EX", "MAX" };

const drc_req_info_t g_invalid_req_info = { .inst_id = CT_INVALID_ID8,
                                            .inst_sid = CT_INVALID_ID16,
                                            .req_mode = DRC_LOCK_NULL,
                                            .curr_mode = DRC_LOCK_NULL,
                                            .rsn = CT_INVALID_ID32,
                                            .req_owner_result = 0,
                                            .req_time = 0,
                                            .req_version = 0,
                                            .lsn = 0 };

#define BUF_RES_RECYCLE_WINDOW 60000000  // 60s, access interval larger than BUF_RES_RECYCLE_WINDOW can be recycled
#define BUF_RES_IS_OLD(buf_res, now) ((now) - (buf_res)->converting.req_info.req_time > BUF_RES_RECYCLE_WINDOW)

// add for remaster opt
#define DRC_FREE_RES_SLEEP_TIME (3)
#define DRC_FREE_MIG_RES_MAX_THREAD_NUM (8)
#if defined(__arm__) || defined(__aarch64__)
#define DRC_REMASTER_RCY_MAX_THREAD_NUM (32)
#else
#define DRC_REMASTER_RCY_MAX_THREAD_NUM (16)
#endif
#define DRC_COLLECT_SLEEP_TIME (3)
#define DCS_CLEAN_OWNER_MAX_THREAD_NUM (16)
#define DRC_WAIT_MGRT_END_SLEEP_TIME   (1)
typedef struct st_drc_free_mig_res_param {
    uint16 start_task_idx;
    uint32 cnt_per_thread;
    atomic_t *job_num;
    drc_remaster_mngr_t *remaster_mngr;
    drc_global_res_t* buf_res;
    drc_global_res_t* lock_res;
} drc_free_mig_res_param_t;
#define DRC_PART_MNGR (&g_drc_res_ctx.part_mngr)
#define DRC_PART_REMASTER_MNGR (&g_drc_res_ctx.part_mngr.remaster_mngr)
#define DRC_SELF_INST_ID (g_drc_res_ctx.kernel->dtc_attr.inst_id)
#define DRC_PART_MASTER_ID(part_id) (g_drc_res_ctx.part_mngr.part_map[(part_id)].inst_id)
#define DRC_PART_REMASTER_ID(part_id) (g_drc_res_ctx.part_mngr.remaster_mngr.target_part_map[(part_id)].inst_id)

#define DRC_MASTER_INFO_STAT(stat_id) ((g_drc_res_ctx.stat.stat_info + (stat_id))->cnt)

bool32 dtc_is_in_rcy(void)
{
    drc_part_mngr_t *part_mngr = (&g_drc_res_ctx.part_mngr);
    return (part_mngr->remaster_status < REMASTER_DONE); /* make out new mes early out condition */
}

typedef struct st_dcs_cache_page_param {
    uint8 self_id;
    uint32 id;
} dcs_cache_page_param_t;

typedef struct st_dcs_collect_param {
    uint32 start;
    uint32 count_per_thread;
    atomic_t* job_num;
    dcs_cache_page_param_t cache_param;
    uint8 inst_id;
    buf_context_t* ctx;
    knl_session_t *session;
} dcs_collect_param_t;

typedef struct st_drc_clean_owner_param {
    uint16 start_part_id;
    uint32 count_per_thread;
    atomic_t *job_num;
    uint8 inst_id;
    buf_context_t *buf_ctx;
    knl_session_t *session;
} drc_clean_owner_param_t;

void drc_clean_page_owner_internal(drc_global_res_t *g_buf_res, drc_buf_res_t *buf_res, drc_res_bucket_t *bucket);

static uint64 drc_cal_dls_res_count(uint64 dc_pool_size, uint64 drc_buf_res)
{
    uint32 single_part_table_size =
        sizeof(table_part_t) + sizeof(lob_part_t) + (sizeof(index_part_t) * CT_MAX_TABLE_INDEXES);
    uint32 single_table_size =
        sizeof(index_t) + sizeof(lob_entity_t) + sizeof(lob_t) + sizeof(dc_entity_t);
    uint32 table_size =
        CM_ALIGN_ANY(CT_SIMPLE_PART_NUM * single_part_table_size + single_table_size, CT_SHARED_PAGE_SIZE) +
        (14 * CT_SHARED_PAGE_SIZE) + sizeof(dc_entry_t); // one part table has 14 group for manage partion
    uint64 total_load_table = dc_pool_size / table_size;
    uint64 total_table_dls_count =
        total_load_table * (CT_SIMPLE_PART_NUM * CT_MAX_TABLE_INDEXES + CT_SIMPLE_PART_NUM + 3);
    uint32 other_dls_count = CT_MAX_USERS * 4 + CT_MAX_SPACES;
    uint64 total_dls_res_count = total_table_dls_count * (1 - CT_SEGMENT_DLS_RATIO) +
        MIN(drc_buf_res, total_table_dls_count * CT_SEGMENT_DLS_RATIO) + other_dls_count;
    CT_LOG_RUN_INF("[DRC] dc pool size %llu, buf res count %llu, calculate dls res count %llu", dc_pool_size, drc_buf_res, total_dls_res_count);
    return total_dls_res_count;
}

void drc_deposit_map_init(void)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    for (uint32 i = 0; i < CT_MAX_INSTANCES; i++) {
        ctx->drc_deposit_map[i].deposit_id = i;
        CT_INIT_SPIN_LOCK(ctx->drc_deposit_map[i].lock);
    }
}

uint8 drc_get_deposit_id(uint8 inst_id)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    uint8 deposit_id = CT_INVALID_ID8;
    if (inst_id < CT_MAX_INSTANCES) {
        cm_spin_lock(&ctx->drc_deposit_map[inst_id].lock, NULL);
        deposit_id = (uint8)ctx->drc_deposit_map[inst_id].deposit_id;
        cm_spin_unlock(&ctx->drc_deposit_map[inst_id].lock);
    }
    return deposit_id;
}

void drc_set_deposit_id(uint8 inst_id, uint8 deposit_id)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    cm_spin_lock(&ctx->drc_deposit_map[inst_id].lock, NULL);
    ctx->drc_deposit_map[inst_id].deposit_id = (uint32)deposit_id;
    cm_spin_unlock(&ctx->drc_deposit_map[inst_id].lock);
}

void drc_remaster_inst_list(reform_info_t *reform_info)
{
    uint32 id;
    // set deposit instance id
    for (id = 0; id < reform_info->reform_list[REFORM_LIST_LEAVE].inst_id_count; id++) {
        drc_set_deposit_id(reform_info->reform_list[REFORM_LIST_LEAVE].inst_id_list[id], reform_info->master_id);
        CT_LOG_RUN_INF("[REFORM_LIST_LEAVE] set deposit_id=%u for inst_id=%u", reform_info->master_id,
            reform_info->reform_list[REFORM_LIST_LEAVE].inst_id_list[id]);
    }

    for (id = 0; id < reform_info->reform_list[REFORM_LIST_ABORT].inst_id_count; id++) {
        drc_set_deposit_id(reform_info->reform_list[REFORM_LIST_ABORT].inst_id_list[id], reform_info->master_id);
        CT_LOG_RUN_INF("[REFORM_LIST_ABORT] set deposit_id=%u for inst_id=%u", reform_info->master_id,
            reform_info->reform_list[REFORM_LIST_ABORT].inst_id_list[id]);
    }

    // need recover join instance id
    for (id = 0; id < reform_info->reform_list[REFORM_LIST_JOIN].inst_id_count; id++) {
        drc_set_deposit_id(reform_info->reform_list[REFORM_LIST_JOIN].inst_id_list[id], reform_info->reform_list[REFORM_LIST_JOIN].inst_id_list[id]);
        CT_LOG_RUN_INF("[REFORM_LIST_JOIN] set deposit_id=%u for inst_id=%u",
            reform_info->reform_list[REFORM_LIST_JOIN].inst_id_list[id],
            reform_info->reform_list[REFORM_LIST_JOIN].inst_id_list[id]);
    }

    // set deposit instance id for reform fail id
    for (id = 0; id < reform_info->reform_list[REFORM_LIST_FAIL].inst_id_count; id++) {
        drc_set_deposit_id(reform_info->reform_list[REFORM_LIST_FAIL].inst_id_list[id], reform_info->master_id);
        CT_LOG_RUN_INF("[REFORM_LIST_FAIL] set deposit_id=%u for inst_id=%u", reform_info->master_id,
            reform_info->reform_list[REFORM_LIST_FAIL].inst_id_list[id]);
    }
}

static inline bool32 is_same_io(char *res_id, void *res)
{
    drc_local_io *local_io = (drc_local_io *)res;
    io_id_t *io_id = (io_id_t*)res_id;

    if ((local_io->io_id.fdsa_type == io_id->fdsa_type) && (local_io->io_id.io_no == io_id->io_no)) {
        return CT_TRUE;
    }
    return CT_FALSE;
}

static inline bool32 is_same_page(char *res_id, void *res)
{
    drc_buf_res_t *buf_res = (drc_buf_res_t*)res;
    page_id_t *pagid = (page_id_t*)res_id;

    if ((buf_res->page_id.file == pagid->file) && (buf_res->page_id.page == pagid->page)) {
        return CT_TRUE;
    }
    return CT_FALSE;
}

static inline bool32 is_same_lock(char *res_id, void *res)
{
    drc_master_res_t *lock_res = (drc_master_res_t*)res;
    drid_t *lock_id = (drid_t*)res_id;

    if (lock_res->res_id.key1 == lock_id->key1 && lock_res->res_id.key2 == lock_id->key2 &&
        lock_res->res_id.key3 == lock_id->key3 && lock_res->res_id.key4 == lock_id->key4) {
        return CT_TRUE;
    }
    return CT_FALSE;
}

static inline bool32 is_same_local_lock(char *res_id, void *res)
{
    drc_local_lock_res_t *local_lock = (drc_local_lock_res_t*)res;
    drid_t *lock_id = (drid_t*)res_id;

    if (local_lock->res_id.key1 == lock_id->key1 && local_lock->res_id.key2 == lock_id->key2 &&
        local_lock->res_id.key3 == lock_id->key3 && local_lock->res_id.key4 == lock_id->key4) {  // todo
        return CT_TRUE;
    }
    return CT_FALSE;
}

static inline bool32 is_same_txn(char *res_id, void *res)
{
    drc_txn_res_t *txn = (drc_txn_res_t*)res;
    xid_t *xid = (xid_t*)res_id;

    if (txn->res_id.value == xid->value) {
        return CT_TRUE;
    }
    return CT_FALSE;
}

void drc_update_remaster_local_status(drc_remaster_status_e status)
{
    drc_part_mngr_t *part_mngr = DRC_PART_MNGR;
    cm_spin_lock(&part_mngr->lock, NULL);
    if (part_mngr->remaster_status != REMASTER_FAIL) {
        part_mngr->remaster_status = status;
        if (status > REMASTER_PREPARE) {
            part_mngr->is_reentrant = CT_FALSE;
        }
        if (status == REMASTER_DONE) {
            part_mngr->mgrt_fail_list = CT_TRUE;
        }
    } else {
        CT_LOG_RUN_ERR("[DRC] remaster update status %d failed", status);
    }
    cm_spin_unlock(&part_mngr->lock);
}

status_t drc_master_update_inst_remaster_status(uint8 inst_id, drc_remaster_status_e remaster_status)
{
    drc_remaster_mngr_t *remaster_mngr = DRC_PART_REMASTER_MNGR;
    if (remaster_mngr->inst_drm_info[inst_id].remaster_status < remaster_status) {
        remaster_mngr->inst_drm_info[inst_id].remaster_status = remaster_status;
    }
    return CT_SUCCESS;
}

bool8 drc_remaster_is_ready(reform_info_t *reform_info, drc_remaster_status_e status)
{
    uint32 i;
    drc_remaster_mngr_t *remaster_mngr = DRC_PART_REMASTER_MNGR;
    uint8 *inst_id_list = NULL;

    inst_id_list = RC_REFORM_LIST(reform_info, REFORM_LIST_AFTER).inst_id_list;
    for (i = 0; i < RC_REFORM_LIST_COUNT(reform_info, REFORM_LIST_AFTER); i++) {
        if (remaster_mngr->inst_drm_info[inst_id_list[i]].remaster_status != status) {
            return CT_FALSE;
        }
    }

    inst_id_list = RC_REFORM_LIST(reform_info, REFORM_LIST_LEAVE).inst_id_list;
    for (i = 0; i < RC_REFORM_LIST_COUNT(reform_info, REFORM_LIST_LEAVE); i++) {
        if (remaster_mngr->inst_drm_info[inst_id_list[i]].remaster_status != status) {
            return CT_FALSE;
        }
    }
    return CT_TRUE;
}

status_t drc_remaster_wait_all_node_ready(reform_info_t *reform_info, uint64 timeout,
                                          drc_remaster_status_e status)
{
    uint64 elapsed = 0;
    drc_part_mngr_t *part_mngr = DRC_PART_MNGR;
    while (drc_remaster_is_ready(reform_info, status) != CT_TRUE) {
        if (part_mngr->remaster_status == REMASTER_FAIL) {
            CT_LOG_RUN_ERR("[DRC] Other node process failed, wait status(%u), stop waiting.", status);
            return CT_ERROR;
        }
        if (elapsed >= timeout) {
            CT_LOG_RUN_ERR("[DRC] remaster wait all node ready timeout(%llu/%llu), ,wait status(%u), stop waiting.",
                           elapsed, timeout, status);
            return CT_ERROR;
        }
        cm_sleep(REMASTER_SLEEP_INTERVAL);
        elapsed += REMASTER_SLEEP_INTERVAL;
    }
    return CT_SUCCESS;
}

void drc_part_init(uint8 *inst_id_array, uint8 inst_num, drc_part_mngr_t *part_mngr)
{
    uint32 i;

    if ((0 == inst_num) || (part_mngr->inited)) {
        return;
    }

    for (i = 0; i < DRC_MAX_PART_NUM; i++) {
        uint32 array_idx = i % inst_num;
        uint8 inst_id;

        inst_id = inst_id_array[array_idx];

        part_mngr->part_map[i].inst_id = inst_id;
        part_mngr->part_map[i].status = PART_INIT;
        if (0 == part_mngr->inst_part_tbl[inst_id].count) {
            part_mngr->inst_part_tbl[inst_id].first = i;
            part_mngr->inst_part_tbl[inst_id].is_used = CT_TRUE;
        } else {
            part_mngr->part_map[part_mngr->inst_part_tbl[inst_id].last].next = i;
        }

        part_mngr->inst_part_tbl[inst_id].last = i;
        part_mngr->inst_part_tbl[inst_id].count++;
        part_mngr->part_map[i].next = CT_INVALID_ID8;
    }
    part_mngr->lock = 0;
    part_mngr->inst_num = inst_num;
    part_mngr->version = 1;
    part_mngr->remaster_status = REMASTER_DONE;
    part_mngr->is_reentrant = CT_TRUE;
    part_mngr->mgrt_fail_list = CT_FALSE;

    for (i = 0; i < CT_MAX_INSTANCES; i++) {
        if (CT_TRUE == part_mngr->inst_part_tbl[i].is_used) {
            part_mngr->inst_part_tbl[i].expected_num = part_mngr->inst_part_tbl[i].count;
        }
    }
    part_mngr->inited = CT_TRUE;
}

#define DRC_RES_RECYCLE_SLEEP_TIME (2)
void drc_res_recycle_proc(thread_t *thread)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    knl_session_t *session = (knl_session_t *)thread->argument;
    uint32 buf_res_idx;
    drc_global_res_t *g_buf_res = &(ctx->global_buf_res);
    drc_res_pool_t *pool = &g_buf_res->res_map.res_pool;
    bool32 recycle_limits = MAX(pool->item_num / 16, 8192);

    cm_set_thread_name("drc_buf_res_recycle");
    CT_LOG_RUN_INF("drc buf res recycle thread started");
    KNL_SESSION_SET_CURR_THREADID(session, cm_get_current_thread_id());
    session->dtc_session_type = DTC_WORKER;

    while (!thread->closed) {
        if (session->kernel->db.status != DB_STATUS_OPEN) {
            session->status = SESSION_INACTIVE;
            cm_sleep(200);
            continue;
        }

        if (session->status == SESSION_INACTIVE) {
            session->status = SESSION_ACTIVE;
        }

        if (pool->item_num - pool->used_num >= recycle_limits) {
            cm_sleep(10);
            continue;
        }

        buf_res_idx = drc_recycle_items(session, CT_TRUE);
        if (buf_res_idx == CT_INVALID_ID32) {
            ckpt_trigger(session, CT_FALSE, CKPT_TRIGGER_CLEAN);
            cm_sleep(1);
        } else {
            cm_sleep(DRC_RES_RECYCLE_SLEEP_TIME);
        }
    }

    CT_LOG_RUN_INF("drc buf res recycle thread closed");
    KNL_SESSION_CLEAR_THREADID(session);
}

status_t drc_init(void)
{
    status_t  ret;
    drc_res_ctx_t *ctx = DRC_RES_CTX;

    ret = memset_s(ctx, sizeof(drc_res_ctx_t), 0, sizeof(drc_res_ctx_t));
    knl_securec_check(ret);

    ctx->kernel = g_dtc->kernel;
    ctx->lock = 0;

    uint32 item_num;

    //why *2: 1 is for page lock item, 1 is for global lock item
    item_num = ctx->kernel->attr.max_sessions * g_dtc->profile.node_count * 2;
    ret = drc_res_pool_init(&ctx->lock_item_pool, sizeof(drc_lock_item_t), item_num);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[DRC]lock item pool init fail,return error:%u", ret);
        return CT_ERROR;
    }
    knl_panic(DRC_DEFAULT_BUF_RES_NUM * 2 < CT_INVALID_ID32);  /* global memory is smaller than 8T, because bucket_num of type uint32 is the double of pool size. */
    ret = drc_global_res_init(&ctx->global_buf_res, (uint32)DRC_DEFAULT_BUF_RES_NUM, sizeof(drc_buf_res_t), is_same_page);//global page resource
    if (ret != CT_SUCCESS) {
        drc_destroy();
        CT_LOG_RUN_ERR("[DRC]global page resource pool init fail,return error:%u", ret);
        return CT_ERROR;
    }

    if (cm_dbs_is_enable_dbs() && g_enable_fdsa) {
        uint64 max_io_num = ctx->kernel->attr.max_sessions;
        ret = drc_res_map_init(&ctx->local_io_map, max_io_num, sizeof(drc_local_io), is_same_io);
        if (ret != CT_SUCCESS) {
            drc_destroy();
            CT_LOG_RUN_ERR("[DRC] local io resource pool init fail,return error:%u", ret);
            return CT_ERROR;
        }
        ret = InitCantianFdsa();
        if (ret != CT_SUCCESS) {
            drc_destroy();
            CT_LOG_RUN_ERR("[DRC] cantian fdas init fail,return error:%u", ret);
            return CT_ERROR;
        }
    }

    uint64 dc_pool_size = (uint64)g_dtc->kernel->dc_ctx.pool.opt_count * (uint64)g_dtc->kernel->dc_ctx.pool.page_size;
    uint64 local_dls_res_count = drc_cal_dls_res_count(dc_pool_size, DRC_DEFAULT_BUF_RES_NUM);
    uint64 global_dls_res_count = local_dls_res_count * g_dtc->profile.node_count;
    ret = drc_global_res_init(&ctx->global_lock_res, global_dls_res_count, sizeof(drc_master_res_t), is_same_lock);//non-page resource map
    if (ret != CT_SUCCESS) {
        drc_destroy();
        CT_LOG_RUN_ERR("[DRC]global lock resource pool init fail,return error:%u", ret);
        return CT_ERROR;
    }

    ret = drc_res_map_init(&ctx->local_lock_map, local_dls_res_count, sizeof(drc_local_lock_res_t), is_same_local_lock);
    if (ret != CT_SUCCESS) {
        drc_destroy();
        CT_LOG_RUN_ERR("[DRC]local lock resource pool init fail,return error:%u", ret);
        return CT_ERROR;
    }

    item_num = ctx->kernel->attr.max_sessions * g_dtc->profile.node_count;
    ret = drc_res_map_init(&ctx->txn_res_map, item_num, sizeof(drc_txn_res_t), is_same_txn);
    if (ret != CT_SUCCESS) {
        drc_destroy();
        CT_LOG_RUN_ERR("[DRC]txn resource pool init fail,return error:%u", ret);
        return CT_ERROR;
    }

    ret = drc_res_map_init(&ctx->local_txn_map, item_num, sizeof(drc_txn_res_t), is_same_txn);
    if (ret != CT_SUCCESS) {
        drc_destroy();
        CT_LOG_RUN_ERR("[DRC]local txn resource pool init fail,return error:%u", ret);
        return CT_ERROR;
    }

    drc_deposit_map_init();

    ret = drc_stat_init();
    if (ret != CT_SUCCESS) {
        drc_destroy();
        CT_LOG_RUN_ERR("[DRC]drc stat init fail,return error:%u", ret);
        return CT_ERROR;
    }

    //if run without reform cluster, set all of part in instance 0
#ifndef DTC_RUN_WITH_REFORM
    uint8 inst_id = 0;
    drc_part_init((uint8*)&inst_id, 1, &ctx->part_mngr);
#endif

    if (cm_create_thread(drc_res_recycle_proc, 0, ctx->kernel->sessions[SESSION_ID_RES_PROCESS], &ctx->gc_thread) !=
        CT_SUCCESS) {
        CT_LOG_RUN_ERR("[DRC]create buf res recycle thread fails");
        return CT_ERROR;
    }

    CT_LOG_RUN_INF("[DRC]instance(%u),drc init success", DRC_SELF_INST_ID);

    return CT_SUCCESS;
}
// start one master, init instance list
void drc_onemaster_inst_list(uint8 master_id, uint32 inst_count)
{
    for (uint8 inst_id = 0; inst_id < (uint8)inst_count; inst_id++) {
        drc_set_deposit_id(inst_id, master_id);
    }
}

void drc_start_one_master(void)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    uint8 inst_id = DRC_SELF_INST_ID;
    reform_detail_t *rf_detail = &g_rc_ctx->reform_detail;

    CT_LOG_RUN_INF("[DRC]the first node start as one master,inst_id:%u", inst_id);
    RC_STEP_BEGIN(rf_detail->remaster_elapsed);
    //the first instance start
    ctx->instance_num = 1;
    drc_part_init((uint8*)&inst_id, ctx->instance_num, &ctx->part_mngr);

    drc_onemaster_inst_list(inst_id, g_dtc->profile.node_count);
    RC_STEP_END(rf_detail->remaster_elapsed, RC_STEP_FINISH);
}

uint8 drc_select_one_instance_from_readonly_copy(uint64 readonly_copy)
{
    for (uint8 index = 0; index < CT_MAX_INSTANCES; index++) {
        if (drc_bitmap64_exist(&readonly_copy, index)) {
            return index;
        }
    }

    return CT_INVALID_ID8;
}

static inline uint32 drc_page_partid(page_id_t pagid)
{
    uint32 ext_no;
    drc_res_ctx_t *ctx = DRC_RES_CTX;

    ext_no = pagid.page / DRC_FILE_EXTENT_PAGE_NUM(ctx);
    return cm_hash_uint32(ext_no, DRC_MAX_PART_NUM);
}

status_t drc_get_page_master_id(page_id_t pagid, uint8 *id)
{
    uint8  inst_id;
    uint32 part_id;

    part_id = drc_page_partid(pagid);
    inst_id = DRC_PART_MASTER_ID(part_id);
    if (CT_INVALID_ID8 == inst_id) {
        CT_LOG_RUN_ERR("[DRC]inst_id is invalid");
        return CT_ERROR;
    }

    *id = inst_id;

    return CT_SUCCESS;
}

drc_buf_res_t *drc_get_buf_res_by_pageid(knl_session_t *session, page_id_t pagid)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_res_bucket_t *bucket = drc_get_buf_map_bucket(&ctx->global_buf_res.res_map, pagid.file, pagid.page);

    cm_spin_lock(&bucket->lock, NULL);
    drc_buf_res_t *buf_res = (drc_buf_res_t*)drc_res_map_lookup(&ctx->global_buf_res.res_map, bucket, (char*)&pagid);
    cm_spin_unlock(&bucket->lock);

    return buf_res;
}

void drc_clean_buf_res(drc_buf_res_t *buf_res)
{
    knl_panic(buf_res->claimed_owner == CT_INVALID_ID8);
    if (buf_res->readonly_copies) {
        buf_res->claimed_owner = drc_select_one_instance_from_readonly_copy(buf_res->readonly_copies);
        buf_res->pending = DRC_RES_SHARE_ACTION;
        knl_panic(buf_res->mode == DRC_LOCK_SHARE);
        drc_bitmap64_clear(&buf_res->readonly_copies, buf_res->claimed_owner);
    } else if (buf_res->edp_map != 0) {
        buf_res->claimed_owner = buf_res->latest_edp; /* collect latest edp on crashed node. */
        knl_panic(buf_res->claimed_owner != CT_INVALID_ID8);
        buf_res->pending = DRC_RES_EXCLUSIVE_ACTION;
        knl_panic(buf_res->mode != DRC_LOCK_SHARE);  // clear edp map, and find latest_edp
    } else {
        // edp has been cleaned by ckpt
    }
    DTC_DRC_DEBUG_INF("[DRC][%u-%u][clean buf res, curr_mode=%u, edp map=%llu, readonly copies=%llu, pending acton:%d",
                      buf_res->page_id.file, buf_res->page_id.page, buf_res->mode, buf_res->edp_map,
                      buf_res->readonly_copies, buf_res->pending);
}

status_t drc_get_page_owner_id(knl_session_t *session, page_id_t pagid, uint8 *id, drc_res_action_e *action)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_res_bucket_t *bucket;
    drc_buf_res_t *buf_res;

    bucket = drc_get_buf_map_bucket(&ctx->global_buf_res.res_map, pagid.file, pagid.page);

    cm_spin_lock(&bucket->lock, NULL);
    buf_res = (drc_buf_res_t*)drc_res_map_lookup(&ctx->global_buf_res.res_map, bucket, (char*)&pagid);
    if (NULL == buf_res) {
        cm_spin_unlock(&bucket->lock);
        *id = CT_INVALID_ID8;
        return CT_ERROR;
    }

    if ((buf_res->claimed_owner == CT_INVALID_ID8) && (g_rc_ctx->status >= REFORM_RECOVER_DONE)) {
        knl_panic(!DAAC_PARTIAL_RECOVER_SESSION(session));
        drc_clean_buf_res(buf_res);
    }

    *id = buf_res->claimed_owner;
    if (action) {
        *action = buf_res->pending;
    }

    cm_spin_unlock(&bucket->lock);

    return CT_SUCCESS;
}

recycle_pages g_recycle_page_records[4] = { 0 };

status_t drc_send_master_recycled(knl_session_t *session, uint8 master_id, page_id_t page_id)
{
    recycle_pages *page_records = &g_recycle_page_records[master_id];
    cm_spin_lock(&page_records->lock, NULL);

    page_records->pages[page_records->count] = page_id;
    page_records->req_start_times[page_records->count] = KNL_NOW(session);
    DTC_DCS_DEBUG_INF(
        "[DCS][%u-%u]: master_id:[%d], page_records count:[%u], add page to page_records, ask master to recycle buf_res later, req_time:%lld",
        page_id.file, page_id.page, master_id, page_records->count, page_records->req_start_times[page_records->count]);
    page_records->count = page_records->count + 1;

    if (page_records->count < RECYCLE_PAGE_NUM) {
        cm_spin_unlock(&page_records->lock);
        return CT_SUCCESS;
    }
    status_t ret;
    msg_recycle_owner_req_t req;
    ret = memcpy_s(req.pageids, sizeof(req.pageids), page_records->pages, sizeof(page_records->pages));
    knl_securec_check(ret);
    ret = memcpy_s(req.req_start_times, sizeof(req.req_start_times), page_records->req_start_times,
                   sizeof(page_records->req_start_times));
    knl_securec_check(ret);
    page_records->count = 0;
    cm_spin_unlock(&page_records->lock);

    mes_init_send_head(&req.head, MES_CMD_RECYCLE_OWNER_REQ, sizeof(msg_recycle_owner_req_t), CT_INVALID_ID32,
                       DCS_SELF_INSTID(session), master_id, DCS_SELF_SID(session), CT_INVALID_ID16);
    req.owner_lsn = DB_CURR_LSN(session);
    req.owner_scn = DB_CURR_SCN(session);
    req.req_version = DRC_GET_CURR_REFORM_VERSION;

    knl_begin_session_wait(session, DCS_RECYCLE_OWNER, CT_TRUE);
    SYNC_POINT_GLOBAL_START(CANTIAN_DCS_RECYCLE_OWNER_SEND_FAIL, &ret, CT_ERROR);
    ret = mes_send_data((void *)&req);
    SYNC_POINT_GLOBAL_END;
    knl_end_session_wait(session, DCS_RECYCLE_OWNER);

    DTC_DCS_DEBUG_INF(
        "[DCS][%u-%u][%s]: ask master to recycle buf_res, src_id=%u, src_sid=%u, dest_id=%u, dest_sid=%u, owner_lsn=%llu, owner_scn=%llu, result=%u",
        page_id.file, page_id.page, MES_CMD2NAME(req.head.cmd), req.head.src_inst, req.head.src_sid, req.head.dst_inst,
        req.head.dst_sid, req.owner_lsn, req.owner_scn, ret);
    return ret;
}

static inline bool32 buf_res_has_readonly_copies(drc_buf_res_t *buf_res, uint32 owner_id)
{
    uint64 readonly_copies = buf_res->readonly_copies;
    drc_bitmap64_clear(&readonly_copies, owner_id);
    return (readonly_copies != 0);
}

static inline bool32 buf_res_is_recyclable(drc_buf_res_t *buf_res, uint32 inst_id)
{
    return ((buf_res->converting.req_info.inst_id == CT_INVALID_ID8) && (buf_res->edp_map == 0));
}

void drc_buf_res_recycle(knl_session_t *session, uint32 inst_id, date_t time, page_id_t page_id, uint64 req_version)
{
    if (inst_id >= CT_MAX_INSTANCES) {
        CT_LOG_RUN_ERR("[DRC] buf res recycle failed, invalid inst_id %u", inst_id);
        return;
    }
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_global_res_t *g_buf_res = &(ctx->global_buf_res);
    if (SECUREC_UNLIKELY(IS_INVALID_PAGID(page_id)) || inst_id >= g_dtc->profile.node_count) {
        CT_LOG_RUN_ERR("invalid param page_file: %d, inst_id: %d", page_id.file, inst_id);
        return;
    }
    drc_res_bucket_t *bucket = drc_get_buf_map_bucket(&g_buf_res->res_map, page_id.file, page_id.page);
    uint32 idx = CT_INVALID_ID32;
    status_t ret;
    uint32 part_id = drc_page_partid(page_id);
    cm_spin_lock(&g_buf_res->res_part_stat_lock[part_id], NULL);
    cm_spin_lock(&bucket->lock, NULL);
    // if reforming, stop recycle
    SYNC_POINT_GLOBAL_START(CANTIAN_DCS_RECYCLE_MASTER_OTHER_ABORT, (int32 *)session, 0);
    SYNC_POINT_GLOBAL_END;
    if (DRC_STOP_DCS_IO_FOR_REFORMING(req_version, session)) {
        cm_spin_unlock(&bucket->lock);
        cm_spin_unlock(&g_buf_res->res_part_stat_lock[part_id]);
        CT_LOG_RUN_ERR("[DRC][%u-%u]reforming, buf res recycle failed, req_version=%llu, cur_version=%llu",
            page_id.file, page_id.page, req_version, DRC_GET_CURR_REFORM_VERSION);
        return;
    }

    drc_buf_res_t *buf_res = (drc_buf_res_t *)drc_res_map_lookup(&g_buf_res->res_map, bucket, (char *)&page_id);
    if ((buf_res != NULL) && (buf_res->claimed_owner == inst_id)) {
        if ((buf_res->pending != DRC_RES_INVALID_ACTION) || !buf_res->is_used) {
            cm_spin_unlock(&bucket->lock);
            cm_spin_unlock(&g_buf_res->res_part_stat_lock[part_id]);
            DTC_DRC_DEBUG_INF("[DRC][%u-%u] buf_res is being recycled, return", page_id.file, page_id.page);
            return;
        }

        /* no new request after recycle message from the same node. */
        if (buf_res->converting.req_info.req_time < time) {
            if (buf_res_is_recyclable(buf_res, inst_id)) {
                buf_res->pending = DRC_RES_PENDING_ACTION;
                if (buf_res_has_readonly_copies(buf_res, buf_res->claimed_owner)) {
                    cm_spin_unlock(&bucket->lock);
                    cm_spin_unlock(&g_buf_res->res_part_stat_lock[part_id]);
                    ret = dcs_invalidate_readonly_copy(session, page_id, buf_res->readonly_copies, inst_id,
                                                       req_version);
                    if (ret == CT_SUCCESS) {
                        ret = dcs_invalidate_page_owner(session, buf_res->page_id, buf_res->claimed_owner, req_version);
                    }
                    cm_spin_lock(&g_buf_res->res_part_stat_lock[part_id], NULL);
                    cm_spin_lock(&bucket->lock, NULL);
                    // find again, for remaster code quality reinforcement
                    if (drc_res_map_lookup(&g_buf_res->res_map, bucket, (char *)&page_id) == NULL) {
                        CT_LOG_RUN_WAR("[DRC]buf_res[%u-%u]: has been recycled.", page_id.file, page_id.page);
                        cm_spin_unlock(&bucket->lock);
                        cm_spin_unlock(&g_buf_res->res_part_stat_lock[part_id]);
                        return;
                    }
                    if (ret != CT_SUCCESS) {
                        CT_LOG_RUN_ERR("[DRC][%u-%u]: failed to invalidate, ignore recycle this buf_res",
                                       page_id.file, page_id.page);
                        buf_res->pending = DRC_RES_INVALID_ACTION;
                        return;
                    }
                    buf_res->readonly_copies = 0;
                }
                idx = buf_res->idx;
                buf_res->pending = DRC_RES_INVALID_ACTION;
                drc_clean_page_owner_internal(g_buf_res, buf_res, bucket);
            }
        }
    }
    cm_spin_unlock(&bucket->lock);
    cm_spin_unlock(&g_buf_res->res_part_stat_lock[part_id]);

    if (idx != CT_INVALID_ID32) {
        drc_res_pool_free_item(&g_buf_res->res_map.res_pool, idx);
    }

    DTC_DRC_DEBUG_INF("[DRC][%u-%u] buf_res recycle, recycled idx= %d", page_id.file, page_id.page, idx);
}

void drc_buf_res_try_recycle(knl_session_t *session, page_id_t page_id)
{
    uint8 master_id = CT_INVALID_ID8;
    (void)drc_get_page_master_id(page_id, &master_id);

    drc_send_master_recycled(session, master_id, page_id);
}

static inline bool32 drc_is_user_page(knl_session_t *session, page_id_t page_id)
{
    datafile_t *df = DATAFILE_GET(session, page_id.file);
    space_t *space = SPACE_GET(session, df->space_id);
    return (space->ctrl->type & SPACE_TYPE_USERS);
}

uint32 drc_recycle_items(knl_session_t *session, bool32 is_batch)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_global_res_t *g_buf_res = &(ctx->global_buf_res);
    drc_res_pool_t *pool = &g_buf_res->res_map.res_pool;

    uint32 count;
    uint32 idx = CT_INVALID_ID32;
    date_t now = KNL_NOW(session);
    status_t ret;
    uint64 readonly_copies;
    uint8 owner;
    page_id_t page_id;

    count = is_batch ? 1024 : pool->item_num;

    for (uint32 i = 0; i < count; i++) {
        cm_spin_lock(&pool->lock, NULL);
        pool->recycle_pos = (pool->recycle_pos + 1) % pool->item_num;
        drc_buf_res_t *buf_res = (drc_buf_res_t *)DRC_GET_RES_ADDR_BY_ID(pool, pool->recycle_pos);
        cm_spin_unlock(&pool->lock);

        if (!is_batch && pool->free_list != CT_INVALID_ID32) {
            idx = drc_res_pool_alloc_item(pool);
            if (idx != CT_INVALID_ID32) {
                return idx;
            }
        }

        if (!BUF_RES_IS_OLD(buf_res, now)) {
            continue;
        }

        if (!buf_res_is_recyclable(buf_res, buf_res->claimed_owner)) {
            continue;
        }
        uint32 part_id = drc_page_partid(page_id);
        drc_res_bucket_t *bucket = drc_get_buf_map_bucket(&ctx->global_buf_res.res_map, buf_res->page_id.file,
                                                          buf_res->page_id.page);
        cm_spin_lock(&g_buf_res->res_part_stat_lock[part_id], NULL);
        cm_spin_lock(&bucket->lock, NULL);
        if (buf_res->pending != DRC_RES_INVALID_ACTION || !buf_res->is_used) {
            cm_spin_unlock(&bucket->lock);
            cm_spin_unlock(&g_buf_res->res_part_stat_lock[part_id]);
            continue;
        }

        if (!buf_res_is_recyclable(buf_res, buf_res->claimed_owner)) {
            cm_spin_unlock(&bucket->lock);
            cm_spin_unlock(&g_buf_res->res_part_stat_lock[part_id]);
            continue;
        }

        // if reforming, stop recycle buf res
        uint64 req_version = DRC_GET_CURR_REFORM_VERSION;
        SYNC_POINT_GLOBAL_START(CANTIAN_DCS_RECYCLE_ITEM_OTHER_ABORT, (int32 *)session, 0);
        SYNC_POINT_GLOBAL_END;
        if (DRC_STOP_DCS_IO_FOR_REFORMING(req_version, session)) {
            CT_LOG_RUN_ERR("[DRC][%u-%u]: reforming, recycle buf res failed",
                buf_res->page_id.file, buf_res->page_id.page);
            cm_spin_unlock(&bucket->lock);
            cm_spin_unlock(&g_buf_res->res_part_stat_lock[part_id]);
            break;
        }

        buf_res->pending = DRC_RES_PENDING_ACTION;
        readonly_copies = buf_res->readonly_copies;
        owner = buf_res->claimed_owner;
        page_id = buf_res->page_id;
        cm_spin_unlock(&bucket->lock);
        cm_spin_unlock(&g_buf_res->res_part_stat_lock[part_id]);
        ret = dcs_invalidate_readonly_copy(session, buf_res->page_id, buf_res->readonly_copies, buf_res->claimed_owner,
                                           req_version);
        if (ret == CT_SUCCESS) {
            ret = dcs_invalidate_page_owner(session, buf_res->page_id, buf_res->claimed_owner, req_version);
        }

        cm_spin_lock(&g_buf_res->res_part_stat_lock[part_id], NULL);
        cm_spin_lock(&bucket->lock, NULL);
        // find again, for remaster code quality reinforcement
        if (drc_res_map_lookup(&g_buf_res->res_map, bucket, (char *)&page_id) == NULL) {
            CT_LOG_RUN_WAR("[DRC]buf_res[%u-%u]: has been recycled.", page_id.file, page_id.page);
            cm_spin_unlock(&bucket->lock);
            cm_spin_unlock(&g_buf_res->res_part_stat_lock[part_id]);
            continue;
        }
        // if reforming, stop recycle buf res
        SYNC_POINT_GLOBAL_START(CANTIAN_DCS_RECYCLE_ITEM_PENDING_OTHER_ABORT, (int32 *)session, 0);
        SYNC_POINT_GLOBAL_END;
        if (DRC_STOP_DCS_IO_FOR_REFORMING(req_version, session)) {
            CT_LOG_RUN_ERR("[DRC][%u-%u]: reforming, recycle buf res failed",
                buf_res->page_id.file, buf_res->page_id.page);
            buf_res->pending = DRC_RES_INVALID_ACTION;
            cm_spin_unlock(&bucket->lock);
            cm_spin_unlock(&g_buf_res->res_part_stat_lock[part_id]);
            break;
        }
        if ((!buf_res->is_used) || (buf_res->page_id.file != page_id.file || buf_res->page_id.page != page_id.page)) {
            cm_spin_unlock(&bucket->lock);
            cm_spin_unlock(&g_buf_res->res_part_stat_lock[part_id]);
            continue;
        }
        knl_panic((buf_res->pending == DRC_RES_PENDING_ACTION) &&
                  buf_res_is_recyclable(buf_res, buf_res->claimed_owner) &&
                  readonly_copies == buf_res->readonly_copies && owner == buf_res->claimed_owner);
        buf_res->pending = DRC_RES_INVALID_ACTION;
        if (ret != CT_SUCCESS) {
            DTC_DRC_DEBUG_ERR(
                "[DRC][%u-%u]: failed to invalidate, readonly_copies=%llu, owner=%d, ignore recycle this buf_res, \
                idx=%d, is_batch=%d", buf_res->page_id.file, buf_res->page_id.page, buf_res->readonly_copies,
                buf_res->claimed_owner, idx, is_batch);
            cm_spin_unlock(&bucket->lock);
            cm_spin_unlock(&g_buf_res->res_part_stat_lock[part_id]);
            continue;
        }
        buf_res->readonly_copies = 0;
        idx = buf_res->idx;
        drc_clean_page_owner_internal(g_buf_res, buf_res, bucket);
        cm_spin_unlock(&bucket->lock);
        cm_spin_unlock(&g_buf_res->res_part_stat_lock[part_id]);

        DTC_DRC_DEBUG_INF(
            "[DRC][%u-%u]recycle, count=%d, idx=%d, recycle_pos=%d, is_batch=%d, readonly_copies=%llu, owner=%d",
            buf_res->page_id.file, buf_res->page_id.page, i, idx, pool->recycle_pos, is_batch, readonly_copies, owner);

        if (!is_batch) {
            return idx;
        }
        drc_res_pool_free_item(&g_buf_res->res_map.res_pool, idx);
    }

    if (!is_batch) {
        idx = drc_res_pool_alloc_item(pool);
    }

    DTC_DRC_DEBUG_INF("[DRC]recycle none page, idx=%d, recycle_pos=%d, is_batch=%d", idx, pool->recycle_pos, is_batch);
    return idx;
}

status_t drc_check_new_req(page_id_t pagid, drc_req_info_t *req_info, drc_buf_res_t *buf_res)
{
    if ((buf_res->converting.req_info.inst_id == buf_res->claimed_owner) &&
        (buf_res->mode == DRC_LOCK_SHARE && buf_res->converting.req_info.req_mode == DRC_LOCK_EXCLUSIVE) &&
        (req_info->inst_id != buf_res->claimed_owner)) {
        // converting is current owner, the scenario is S->X
        // requester will invalidate readonly copy on other instances.
        // so, need to reject all requests from these instances, don't let them wait.
        // otherwise, requester can not invalidate readonly because local latch can not be added.
        // current owner may be recycled out of memory and be reloaded later

        if (drc_bitmap64_exist(&buf_res->readonly_copies, req_info->inst_id)) {
            DTC_DRC_DEBUG_ERR(
                "[DRC][%u-%u][req converting]: failed, conflicted with owner, "
                "req_id=%u, req_sid=%u, req_rsn=%u, req_mode=%u, curr_mode=%u, cvt_copy_insts=%llu, "
                "curr owner=%d, curr mode=%d, converting mode=%d",
                pagid.file, pagid.page, req_info->inst_id, req_info->inst_sid, req_info->rsn, req_info->req_mode,
                req_info->curr_mode, buf_res->readonly_copies, buf_res->claimed_owner, buf_res->mode,
                buf_res->converting.req_info.req_mode);

            DRC_MASTER_INFO_STAT(R_PO_CONFLICT_TOTAL)++;
            return CT_ERROR;
        } else {
            DTC_DRC_DEBUG_INF(
                "[DRC][%u-%u][req converting]: not conflict scenario"
                "req_id=%u, req_sid=%u, req_rsn=%u, req_mode=%u, curr_mode=%u, cvt_copy_insts=%llu, "
                "curr owner=%d, curr mode=%d, converting mode=%d",
                pagid.file, pagid.page, req_info->inst_id, req_info->inst_sid, req_info->rsn, req_info->req_mode,
                req_info->curr_mode, buf_res->readonly_copies, buf_res->claimed_owner, buf_res->mode,
                buf_res->converting.req_info.req_mode);
        }
    }

    if ((req_info->inst_id == buf_res->claimed_owner) && (req_info->inst_id != buf_res->converting.req_info.inst_id)) {
        /* for example: owner:0, converting:1, new request inst:0 */
        DTC_DRC_DEBUG_ERR("[DRC][%u-%u][req converting]: failed, conflicted with other requester, "
            "req_id=%u, req_sid=%u, req_rsn=%u, req_mode=%u, curr_mode=%u, copy_insts=%llu, converting=%d",
            pagid.file, pagid.page, req_info->inst_id, req_info->inst_sid, req_info->rsn,
            req_info->req_mode, req_info->curr_mode, buf_res->readonly_copies,
            buf_res->converting.req_info.inst_id);
        DRC_MASTER_INFO_STAT(R_PO_CONFLICT_TOTAL)++;
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

void drc_claim_new_page_owner(knl_session_t *session, claim_info_t *claim_info, drc_buf_res_t *buf_res)
{
    page_id_t pagid = claim_info->page_id;
    uint8 cur_owner = buf_res->claimed_owner;
    drc_req_info_t *converting_req = &(buf_res->converting.req_info);

    knl_panic(converting_req->req_mode == claim_info->mode);
    knl_panic(buf_res->pending == DRC_RES_INVALID_ACTION || buf_res->pending == DRC_RES_SHARE_ACTION ||
              buf_res->pending == DRC_RES_EXCLUSIVE_ACTION);
    buf_res->pending = DRC_RES_INVALID_ACTION;
    // CM_ASSERT(!claim_info->has_edp || claim_info->mode == DRC_LOCK_EXCLUSIVE);

    if (claim_info->mode <= buf_res->mode && buf_res->claimed_owner == claim_info->new_id) {  // already owner
        return;
    }
    if (claim_info->mode == DRC_LOCK_SHARE) {
        knl_panic(buf_res->claimed_owner != CT_INVALID_ID8);
        buf_res->mode = DRC_LOCK_SHARE;
        drc_bitmap64_set(&buf_res->readonly_copies, claim_info->new_id);
        DTC_DRC_DEBUG_INF(
            "[DRC][%u-%u][no owner convert]: old_owner=%u, q_count=%u, mode=%u, readonly_copies=%llu, req id=%d",
            pagid.file, pagid.page, cur_owner, buf_res->convert_q.count, buf_res->mode, buf_res->readonly_copies,
            claim_info->new_id);
    } else {
#ifdef DB_DEBUG_VERSION
        uint64 readonly_copies = buf_res->readonly_copies;
        drc_bitmap64_clear(&readonly_copies, claim_info->new_id);
        drc_bitmap64_clear(&readonly_copies, buf_res->claimed_owner);
        knl_panic(readonly_copies == 0);
#endif
        buf_res->claimed_owner = claim_info->new_id;
        buf_res->mode = claim_info->mode;
        buf_res->readonly_copies = 0;
        drc_bitmap64_clear(&buf_res->edp_map, claim_info->new_id);
        DRC_MASTER_INFO_STAT(R_PO_CONVETED)++;

        DTC_DRC_DEBUG_INF("[DRC][%u-%u][owner convert]: new_ownerid=%u, mode=%u, old_owner=%u, q_count=%u",
            pagid.file, pagid.page, buf_res->claimed_owner,
            buf_res->mode, cur_owner, buf_res->convert_q.count);

        if (claim_info->has_edp) {
            knl_panic(claim_info->mode == DRC_LOCK_EXCLUSIVE);
            drc_bitmap64_set(&buf_res->edp_map, cur_owner);

            // record the latest edp
            knl_panic(claim_info->lsn != 0);
            buf_res->latest_edp = cur_owner;
            buf_res->latest_edp_lsn = claim_info->lsn;
            DTC_DRC_DEBUG_INF("[DRC][%u-%u][record edp]: edp_map=%llu, latest_edp=%u", pagid.file, pagid.page,
                              buf_res->edp_map, buf_res->latest_edp);
        }
    }

    if (claim_info->lsn > 0) {
        knl_panic(claim_info->lsn >= buf_res->lsn);
        buf_res->lsn = claim_info->lsn;
    }
}

void drc_trace_convert_queue(drc_buf_res_t *buf_res)
{
    if (LOG_DEBUG_INF_ON) {
        // for debug info
        drc_res_ctx_t *ctx = DRC_RES_CTX;
        page_id_t page_id = buf_res->page_id;
        uint32 item_id = buf_res->convert_q.first;
        while (item_id != CT_INVALID_ID32) {
            drc_lock_item_t *lock_item = (drc_lock_item_t*)DRC_GET_RES_ADDR_BY_ID((&ctx->lock_item_pool), item_id);
            DTC_DRC_DEBUG_INF("[DRC][%u-%u][convert_q]: inst_id=%u, inst_sid=%u, mode=%u",
                page_id.file, page_id.page, lock_item->req_info.inst_id,
                lock_item->req_info.inst_sid, lock_item->req_info.req_mode);
            item_id = lock_item->next;
        }
    }
}

uint32 drc_check_first_req_in_convert_queue(drc_buf_res_t *buf_res)
{
    if (buf_res->convert_q.count) {
        drc_res_ctx_t *ctx = DRC_RES_CTX;
        uint32 lock_item_id = buf_res->convert_q.first;
        drc_lock_item_t *lock_item = (drc_lock_item_t *)DRC_GET_RES_ADDR_BY_ID((&ctx->lock_item_pool), lock_item_id);
        drc_req_info_t *req_info = &lock_item->req_info;
        page_id_t page_id = buf_res->page_id;
        status_t ret = drc_check_new_req(page_id, req_info, buf_res);
        if (ret != CT_SUCCESS) {
            DTC_DRC_DEBUG_ERR("[DRC][%u-%u][check first req in convert q in convert page owner, conflicted with owner, "
                "remove it from q, req_id=%u, req_sid=%u, req_rsn=%u, req_mode=%u, curr_mode=%u, cvt_copy_insts=%llu",
                page_id.file, page_id.page, req_info->inst_id, req_info->inst_sid, req_info->rsn, req_info->req_mode,
                req_info->curr_mode, buf_res->readonly_copies);

            buf_res->convert_q.first = lock_item->next;
            buf_res->convert_q.count--;
            return lock_item_id;
        }
    }
    return CT_INVALID_ID32;
}

uint32 drc_convert_next_request(knl_session_t *session, drc_buf_res_t *buf_res, cvt_info_t *cvt_info)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    page_id_t page_id = buf_res->page_id;
    drc_req_info_t *converting_req = &(buf_res->converting.req_info);
    cvt_info->readonly_copies = 0;
    cvt_info->pageid = page_id;
    cvt_info->owner_id = buf_res->claimed_owner;

    DTC_DRC_DEBUG_INF("[DRC][%u-%u][convert_q]: count=%u, edp_map=%llu, latest_edp=%u, readonly_copies=%llu",
                      page_id.file, page_id.page, buf_res->convert_q.count, buf_res->edp_map, buf_res->latest_edp,
                      buf_res->readonly_copies);

    drc_lock_item_t *lock_item = NULL;
    uint32 lock_item_id = 0;
    for (;;) {
        if (buf_res->convert_q.count == 0) {
            // converting already became owner, invalidate it.
            converting_req->inst_id = CT_INVALID_ID8;
            converting_req->req_mode = DRC_LOCK_NULL;
            converting_req->inst_sid = CT_INVALID_ID16;

            DTC_DRC_DEBUG_INF("[DRC][%u-%u][invalidate converting]: id=%u", page_id.file, page_id.page,
                converting_req->inst_id);
            DRC_MASTER_INFO_STAT(R_PO_CVTING_CURR)--;
            return CT_INVALID_ID32;
        }

        drc_trace_convert_queue(buf_res);

        lock_item_id = buf_res->convert_q.first;
        knl_panic(lock_item_id != CT_INVALID_ID32);

        lock_item = (drc_lock_item_t*)DRC_GET_RES_ADDR_BY_ID((&ctx->lock_item_pool), lock_item_id);

        buf_res->convert_q.first = lock_item->next;
        buf_res->convert_q.count--;
        buf_res->converting = *lock_item;

        drc_res_pool_free_item(&ctx->lock_item_pool, lock_item_id);

        if (converting_req->req_time + DCS_WAIT_MSG_TIMEOUT * MICROSECS_PER_MILLISEC <= KNL_NOW(session)) {
            /* the time between master and requester may be different. */
            CT_LOG_RUN_WAR("[DRC][%u-%u] req timedout, ignore process this request, inst_id=%u, inst_sid=%u, mode=%u",
                page_id.file, page_id.page, converting_req->inst_id,
                converting_req->inst_sid, converting_req->req_mode);
            continue;
        }
        break;
    }

    cvt_info->req_id = converting_req->inst_id;
    cvt_info->req_sid = converting_req->inst_sid;
    cvt_info->req_rsn = converting_req->rsn;
    cvt_info->req_mode = converting_req->req_mode;
    cvt_info->curr_mode = converting_req->curr_mode;
    cvt_info->req_version = converting_req->req_version;
    cvt_info->lsn = converting_req->lsn;
    cvt_info->pageid = page_id;
    cvt_info->owner_id = buf_res->claimed_owner;
    cvt_info->readonly_copies = buf_res->readonly_copies;
    drc_bitmap64_clear(&cvt_info->readonly_copies, cvt_info->req_id);
    drc_bitmap64_clear(&cvt_info->readonly_copies, cvt_info->owner_id);
    DRC_MASTER_INFO_STAT(R_PO_CVTQ_CURR)--;

    return drc_check_first_req_in_convert_queue(buf_res);
}

static inline bool32 drc_is_retry_request(drc_req_info_t *l_val, drc_req_info_t *r_val)
{
    return ((l_val->inst_id == r_val->inst_id) && (l_val->req_mode != r_val->curr_mode));
}

static inline bool32 drc_is_same_claim_request(drc_req_info_t *converting_req, claim_info_t *claim_info)
{
    return (converting_req->inst_id == claim_info->new_id && converting_req->inst_sid == claim_info->inst_sid &&
            converting_req->req_mode == claim_info->mode);
}

bool32 drc_claim_info_is_invalid(claim_info_t *claim_info, drc_buf_res_t *buf_res)
{
    if (claim_info->mode == DRC_LOCK_SHARE) {
        if (SECUREC_UNLIKELY(buf_res->claimed_owner == CT_INVALID_ID8)) {
            CT_LOG_RUN_WAR("[DCS]: claim info is invalid, claim_info->mode=%d, buf_res->claimed_owner=%d",
                claim_info->mode, buf_res->claimed_owner);
            return CT_TRUE;
        }
    } else {
        if (claim_info->has_edp) {
            if (SECUREC_UNLIKELY(!((claim_info->mode == DRC_LOCK_EXCLUSIVE) && (claim_info->lsn != 0)))) {
                CT_LOG_RUN_WAR("[DCS]: claim info is invalid, claim_info->mode=%d, claim_info->lsn=%llu",
                    claim_info->mode, claim_info->lsn);
                return CT_TRUE;
            }
        }
    }

    if (claim_info->lsn > 0) {
        if (SECUREC_UNLIKELY(claim_info->lsn < buf_res->lsn)) {
            CT_LOG_RUN_WAR("[DCS]: claim info is invalid, claim_info->lsn=%llu, buf_res->lsn=%llu",
                claim_info->lsn, buf_res->lsn);
            return CT_TRUE;
        }
    }
    return CT_FALSE;
}

static inline drc_lock_item_t *drc_search_item_by_reqid(drc_lock_q_t *convert_q, drc_req_info_t *req_info)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;

    uint32 item_id = convert_q->first;
    while (item_id != CT_INVALID_ID32) {
        drc_lock_item_t *item = (drc_lock_item_t*)DRC_GET_RES_ADDR_BY_ID((&ctx->lock_item_pool), item_id);
        if (drc_is_retry_request(&item->req_info, req_info)) {
            return item;
        }
        item_id = item->next;
    }

    return NULL;
}

status_t drc_keep_requester_wait(page_id_t pagid, drc_req_info_t *req_info, drc_buf_res_t *buf_res, bool32 is_try,
                                 bool32 *converting, bool32 *is_retry)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    status_t ret;
    drc_req_info_t *converting_req = &(buf_res->converting.req_info);
    *converting = CT_FALSE;

    if (converting_req->inst_id == CT_INVALID_ID8) {
        if (is_try && (buf_res->claimed_owner != req_info->inst_id)) { /* only prefetch for page of granted or already
                                                                          owner */
            return CT_SUCCESS;
        }

        knl_panic(buf_res->convert_q.count == 0);
        // no waiting, and no converting, buf_res is just for saving edp
        *converting_req = *req_info;
        buf_res->converting.next = CT_INVALID_ID32;

        *converting = CT_TRUE;

        DTC_DRC_DEBUG_INF(
            "[DRC][%u-%u][no converting, satisfied]: req_id=%u, req_sid=%u, req_rsn=%u, req_mode=%u, curr_mode=%u, copy_insts=%llu",
            pagid.file, pagid.page, converting_req->inst_id, converting_req->inst_sid, converting_req->rsn,
            converting_req->req_mode, converting_req->curr_mode, buf_res->readonly_copies);

        DRC_MASTER_INFO_STAT(R_PO_CVTING_TOTAL)++;
        DRC_MASTER_INFO_STAT(R_PO_CVTING_CURR)++;

        return CT_SUCCESS;
    }

    if (is_try) {
        return CT_SUCCESS;  // request to prefetch can't be put into queue.
    }

    ret = drc_check_new_req(pagid, req_info, buf_res);
    if (ret != CT_SUCCESS) {
        DTC_DRC_DEBUG_ERR("[DRC][%u-%u][drc_check_new_req failed]: req_id=%u, req_sid=%u, "
                          "req_rsn_old=%u, req_rsn_new=%u, req_mode=%u, curr_mode=%u, copy_insts=%llu",
                          pagid.file, pagid.page, req_info->inst_id, req_info->inst_sid, converting_req->rsn,
                          req_info->rsn, req_info->req_mode, req_info->curr_mode, buf_res->readonly_copies);
        return ret;
    }

    if (drc_is_retry_request(&buf_res->converting.req_info, req_info)) {
        // claim not come: 1) swap out and in, owner not changed, can request page from old owner and claim again
        //                 2) retry message: old retry message can be ignored with error but new one can be processed.
        //                 3) claim msg come after new request: put in queue
        CT_LOG_RUN_WAR(
            "[DRC][%u-%u][req converting retry]: req_id=%u, req_sid=%u, "
            "req_rsn_old=%u, req_rsn_new=%u, req_mode_old=%u, req_mode=%u, curr_mode=%u, req_time_old=%llu, req_time_new=%llu",
            pagid.file, pagid.page, req_info->inst_id, req_info->inst_sid, converting_req->rsn, req_info->rsn,
            converting_req->req_mode, req_info->req_mode, req_info->curr_mode, converting_req->req_time,
            req_info->req_time);
        if (converting_req->req_time <= req_info->req_time) {
            req_info->req_mode = MAX(converting_req->req_mode, req_info->req_mode); /* the old owner may have already
                                                                                       convert its lock mode. */
            *converting_req = *req_info;
            *converting = CT_TRUE;
            *is_retry = CT_TRUE;
            ctx->stat.converting_page_cnt++;
            return CT_SUCCESS;
        } else {
            *converting = CT_FALSE;
            return CT_ERROR;
        }
    }

    if (buf_res->convert_q.count > 0) {
        drc_lock_item_t *item = drc_search_item_by_reqid(&buf_res->convert_q, req_info);
        if (item != NULL) {
            DTC_DRC_DEBUG_INF("[DRC][%u-%u][req waiting retry]: req_id=%u, req_sid=%u, req_rsn_old=%u, "
                "rq_rsn_new=%u, q_count=%u, req_mode=%u, curr_mode=%u",
                pagid.file, pagid.page, req_info->inst_id, req_info->inst_sid, item->req_info.rsn,
                req_info->rsn, buf_res->convert_q.count, req_info->req_mode, req_info->curr_mode);

            if (item->req_info.lsn != req_info->lsn) {
                CT_LOG_RUN_ERR("[DRC][%u-%u]: invalid lsn, convert_q lsn %llu, req_info lsn %llu", pagid.file,
                    pagid.page, item->req_info.lsn, req_info->lsn);
                return CT_ERROR;
            }
            item->req_info = *req_info;
            *converting = CT_FALSE;
            return CT_SUCCESS;
        }
    }

    uint32 lock_item_id = drc_res_pool_alloc_item(&ctx->lock_item_pool);
    if (CT_INVALID_ID32 == lock_item_id) {
        CT_LOG_RUN_ERR("[DRC][%u-%u]: failed to allocate lock item", pagid.file, pagid.page);
        return CT_ERROR;
    }

    drc_lock_item_t *lock_item = (drc_lock_item_t*)DRC_GET_RES_ADDR_BY_ID((&ctx->lock_item_pool), lock_item_id);
    lock_item->next = CT_INVALID_ID32;
    lock_item->req_info = *req_info;

    if (buf_res->convert_q.count == 0) {
        buf_res->convert_q.first = lock_item_id;
        buf_res->convert_q.last = lock_item_id;
    } else {
        drc_lock_item_t *tail = (drc_lock_item_t*)DRC_GET_RES_ADDR_BY_ID((&ctx->lock_item_pool), buf_res->convert_q.last);
        tail->next = lock_item_id;
        buf_res->convert_q.last = lock_item_id;
    }

    buf_res->convert_q.count++;
    *converting = CT_FALSE;

    DTC_DRC_DEBUG_INF("[DRC][%u-%u][req waiting]: req_id=%u, req_sid=%u, req_rsn=%u, req_mode=%u, curr_mode=%u, "
                      "claimed_owner=%d, curr mode=%d, q_count=%u, converting_instid=%d, converting_req_mode=%d",
                      pagid.file, pagid.page, req_info->inst_id, req_info->inst_sid, req_info->rsn, req_info->req_mode,
                      req_info->curr_mode, buf_res->claimed_owner, buf_res->mode, buf_res->convert_q.count,
                      converting_req->inst_id, converting_req->req_mode);
    DRC_MASTER_INFO_STAT(R_PO_CVTQ_TOTAL)++;
    DRC_MASTER_INFO_STAT(R_PO_CVTQ_CURR)++;
    return CT_SUCCESS;
}

status_t drc_request_page_owner(knl_session_t *session, page_id_t pagid, drc_req_info_t *req_info, bool32 is_try,
                                drc_req_owner_result_t *result)
{
    status_t ret;
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_global_res_t *g_buf_res = &(ctx->global_buf_res);
    drc_part_mngr_t *part_mngr = DRC_PART_MNGR;
    drc_res_bucket_t *bucket;
    drc_buf_res_t *buf_res;
    bool32 free_slot = CT_FALSE;
    uint32 idx = CT_INVALID_ID32;
    drc_res_pool_t *buf_res_pool = NULL;
    result->type = DRC_REQ_OWNER_INVALID;
    result->action = DRC_RES_INVALID_ACTION;
    result->is_retry = CT_FALSE;
    result->req_mode = req_info->req_mode;
    req_info->req_owner_result = DRC_REQ_OWNER_WAITING;

    if (req_info->inst_id >= CT_MAX_INSTANCES || IS_INVALID_PAGID(pagid)) {
        CT_LOG_RUN_ERR("[DRC] invalid page id %u-%u or req inst %u", pagid.file, pagid.page, req_info->inst_id);
        return CT_ERROR;
    }

    SYNC_POINT_GLOBAL_START(CANTIAN_DCS_REQUEST_PAGE_OWNER_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;

    if (!dtc_dcs_readable(session)) {
        CT_LOG_RUN_ERR("[DRC][%u-%u]: request page fail, remaster status(%u) is in progress or in g_rc status (%u)",
                       pagid.file, pagid.page, part_mngr->remaster_status, g_rc_ctx->status);
        return CT_ERROR;
    }

    bucket = drc_get_buf_map_bucket(&ctx->global_buf_res.res_map, pagid.file, pagid.page);
    uint32 part_id = drc_page_partid(pagid);
    cm_spin_lock(&g_buf_res->res_part_stat_lock[part_id], NULL);
    cm_spin_lock(&bucket->lock, NULL);
    if (DRC_STOP_DCS_IO_FOR_REFORMING(req_info->req_version, session)) {
        CT_LOG_RUN_ERR("[DCS][%u-%u]reforming, request page owner failed, req_rsn=%u, "
            "req_version=%llu, cur_version=%llu",
            pagid.file, pagid.page, req_info->rsn, req_info->req_version, DRC_GET_CURR_REFORM_VERSION);
        cm_spin_unlock(&bucket->lock);
        cm_spin_unlock(&g_buf_res->res_part_stat_lock[part_id]);
        return CT_ERROR;
    }
    buf_res = (drc_buf_res_t*)drc_res_map_lookup(&ctx->global_buf_res.res_map, bucket, (char*)&pagid);
    DRC_MASTER_INFO_STAT(R_PO_TOTAL)++;

    if (buf_res == NULL) {
        cm_spin_unlock(&bucket->lock);
        cm_spin_unlock(&g_buf_res->res_part_stat_lock[part_id]);
        buf_res_pool = &ctx->global_buf_res.res_map.res_pool;
        idx = drc_res_pool_alloc_item(buf_res_pool);
        if (idx == CT_INVALID_ID32) {
            idx = drc_recycle_items(session, CT_FALSE);
            if (idx == CT_INVALID_ID32) {
                CT_LOG_RUN_ERR("[DRC][%u-%u]: req_rsn=%u, failed to allocate drc resource item",
                    pagid.file, pagid.page, req_info->rsn);
                return CT_ERROR;
            }
        }

        cm_spin_lock(&g_buf_res->res_part_stat_lock[part_id], NULL);
        cm_spin_lock(&bucket->lock, NULL);
        buf_res = (drc_buf_res_t *)drc_res_map_lookup(&ctx->global_buf_res.res_map, bucket, (char *)&pagid);
        if (buf_res) {
            free_slot = CT_TRUE;
            DTC_DRC_DEBUG_ERR("[DRC][%u-%u]: another request allocated the buf_res, recycle the item(%d)", pagid.file,
                              pagid.page, idx);
            goto allocated;
        }

        if (DRC_STOP_DCS_IO_FOR_REFORMING(req_info->req_version, session)) {
            CT_LOG_RUN_ERR("[DCS][%u-%u]reforming, request page owner failed, req_version=%llu, cur_version=%llu "
                "req_rsn=%u",
                pagid.file, pagid.page, req_info->req_version, DRC_GET_CURR_REFORM_VERSION, req_info->rsn);
            drc_res_pool_free_item(buf_res_pool, idx);
            cm_spin_unlock(&bucket->lock);
            cm_spin_unlock(&g_buf_res->res_part_stat_lock[part_id]);
            return CT_ERROR;
        }

        buf_res = (drc_buf_res_t*)DRC_GET_RES_ADDR_BY_ID(buf_res_pool, idx);
        buf_res->claimed_owner = req_info->inst_id;
        buf_res->page_id = pagid;
        buf_res->idx = idx;
        buf_res->is_used = CT_TRUE;
        buf_res->lock = 0;
        buf_res->mode = req_info->req_mode;
        buf_res->latest_edp = CT_INVALID_ID8;
        buf_res->latest_edp_lsn = 0;
        buf_res->lsn = 0;
        buf_res->readonly_copies = 0;
        buf_res->edp_map = 0;

        buf_res->converting.req_info = g_invalid_req_info;
        buf_res->converting.req_info.req_time = req_info->req_time;
        buf_res->converting.next = CT_INVALID_ID32;
        buf_res->pending = DRC_RES_INVALID_ACTION;

        DRC_LIST_INIT(&buf_res->convert_q);

        drc_res_map_add(bucket, idx, &buf_res->next);

        buf_res->part_id = drc_page_partid(pagid);
        buf_res->node.idx = idx;

        drc_list_t *list = &ctx->global_buf_res.res_parts[buf_res->part_id];
        spinlock_t *lock = &ctx->global_buf_res.res_part_lock[buf_res->part_id];
        drc_list_node_t *node = &buf_res->node;
        drc_buf_res_t *head_buf = NULL;
        drc_list_node_t *head = NULL;

        cm_spin_lock(lock, NULL);

        // if remaster has already scanned, stop DRC_REQ_OWNER_GRANTED
        if (DRC_STOP_DCS_IO_FOR_REFORMING(req_info->req_version, session)) {
            CT_LOG_RUN_ERR("[DCS][%u-%u]reforming, request page owner failed, req_version=%llu, cur_version=%llu "
                "req_rsn=%u",
                pagid.file, pagid.page, req_info->req_version, DRC_GET_CURR_REFORM_VERSION, req_info->rsn);
            drc_res_map_remove(&ctx->global_buf_res.res_map, bucket, (char*)&pagid);
            ret = memset_s(buf_res, sizeof(drc_buf_res_t), 0, sizeof(drc_buf_res_t));
            knl_securec_check(ret);
            drc_res_pool_free_item(buf_res_pool, idx);
            cm_spin_unlock(lock);
            cm_spin_unlock(&bucket->lock);
            cm_spin_unlock(&g_buf_res->res_part_stat_lock[part_id]);
            return CT_ERROR;
        }

        if (list->count != 0) {
            head_buf = (drc_buf_res_t*)DRC_GET_RES_ADDR_BY_ID(&ctx->global_buf_res.res_map.res_pool, list->first);
            head = &head_buf->node;
        }
        drc_add_list_node(list, node, head);

        cm_spin_unlock(lock);

        result->type = DRC_REQ_OWNER_GRANTED;
        result->curr_owner_id = req_info->inst_id;
        result->readonly_copies = 0;

        DTC_DRC_DEBUG_INF(
            "[DRC][%u-%u][req owner converting]:  buf_res null, req_id=%u, req_sid=%u, req_rsn=%u, "
            "req_mode=%u, curr_mode=%u, req_version=%llu, cur_version=%llu",
            pagid.file, pagid.page, req_info->inst_id, req_info->inst_sid, req_info->rsn, req_info->req_mode,
            req_info->curr_mode, req_info->req_version, DRC_GET_CURR_REFORM_VERSION);

        cm_spin_unlock(&bucket->lock);
        cm_spin_unlock(&g_buf_res->res_part_stat_lock[part_id]);

        DRC_MASTER_INFO_STAT(R_PO_FIRST)++;
        return CT_SUCCESS;
    }

allocated:
    if (buf_res->pending == DRC_RES_PENDING_ACTION) {
        cm_spin_unlock(&bucket->lock);
        cm_spin_unlock(&g_buf_res->res_part_stat_lock[part_id]);
        DTC_DRC_DEBUG_ERR("[DRC][%u-%u]: this buf res is being recycled, skip this request", pagid.file, pagid.page);
        if (free_slot) {
            drc_res_pool_free_item(buf_res_pool, idx);
        }
        cm_sleep(5);
        return CT_ERROR;
    }

    if (buf_res->claimed_owner == CT_INVALID_ID8) {
        if (DAAC_SESSION_IN_RECOVERY(session) || g_rc_ctx->status >= REFORM_RECOVER_DONE) {
            drc_clean_buf_res(buf_res);
        } else {
            cm_spin_unlock(&bucket->lock);
            cm_spin_unlock(&g_buf_res->res_part_stat_lock[part_id]);
            CT_LOG_DEBUG_ERR("[DRC][%u-%u]: failed to clean buf res, recovery is not done.", pagid.file, pagid.page);

            if (free_slot) {
                drc_res_pool_free_item(buf_res_pool, idx);
            }
            return CT_ERROR;
        }
    }

    if (buf_res->claimed_owner == CT_INVALID_ID8) {
        buf_res->claimed_owner = req_info->inst_id;
        buf_res->mode = req_info->req_mode;
        result->type = DRC_REQ_OWNER_GRANTED;
        result->curr_owner_id = req_info->inst_id;
        buf_res->converting.req_info.req_owner_result = result->type;
        CM_ASSERT(buf_res->readonly_copies == 0);

        DTC_DRC_DEBUG_INF(
            "[DRC][%u-%u][req owner converting]: claim owner directly, req_id=%u, req_sid=%u, req_rsn=%u, req_mode=%u, curr_mode=%u, edp map=%llu, readonly copies=%llu",
            pagid.file, pagid.page, req_info->inst_id, req_info->inst_sid, req_info->rsn, req_info->req_mode,
            req_info->curr_mode, buf_res->edp_map, buf_res->readonly_copies);

        cm_spin_unlock(&bucket->lock);
        cm_spin_unlock(&g_buf_res->res_part_stat_lock[part_id]);

        if (free_slot) {
            drc_res_pool_free_item(buf_res_pool, idx);
        }

        return CT_SUCCESS;
    }

    // page has owner, requester must be put into converting or queue.
    bool32 can_cvt = CT_FALSE;
    bool32 is_retry = CT_FALSE;
    ret = drc_keep_requester_wait(pagid, req_info, buf_res, is_try, &can_cvt, &is_retry);
    if (SECUREC_UNLIKELY(ret != CT_SUCCESS)) {
        cm_spin_unlock(&bucket->lock);
        cm_spin_unlock(&g_buf_res->res_part_stat_lock[part_id]);
        CT_LOG_DEBUG_ERR("[DRC][%u-%u]: failed to enqueue requester, "
            "req_id=%u, req_sid=%u, req_rsn=%u, req_mode=%u, curr_mode=%u",
            pagid.file, pagid.page,
            req_info->inst_id, req_info->inst_sid, req_info->rsn, req_info->req_mode, req_info->curr_mode);

        if (free_slot) {
            drc_res_pool_free_item(buf_res_pool, idx);
        }
        return CT_ERROR;
    }

    if (can_cvt) {
        // now there is one claimed owner, who can process page request, and requester can be converted
        // return owner id, let upper logic transfer request to it.
        result->type = (buf_res->claimed_owner == req_info->inst_id) ? DRC_REQ_OWNER_ALREADY_OWNER
                                                                     : DRC_REQ_OWNER_CONVERTING;
        result->is_retry = is_retry;
        result->curr_owner_id = buf_res->claimed_owner;
        result->readonly_copies = buf_res->readonly_copies;
        result->action = buf_res->pending;
        result->req_mode = req_info->req_mode; /* req mode may be changed when retry message comes. */
        buf_res->converting.req_info.req_owner_result = result->type;
        drc_bitmap64_clear(&result->readonly_copies, req_info->inst_id);
        drc_bitmap64_clear(&result->readonly_copies, result->curr_owner_id);
        DRC_MASTER_INFO_STAT(R_PO_CONVETED)++;
        DTC_DRC_DEBUG_INF(
            "[DRC][%u-%u][req owner can do converting]: req_id=%u, req_sid=%u, req_rsn=%u, req_mode=%u, curr_mode=%u, "
            " readonly_copies=%lld, edp_map=%lld, pending action=%d",
            pagid.file, pagid.page, req_info->inst_id, req_info->inst_sid, req_info->rsn, req_info->req_mode,
            req_info->curr_mode, result->readonly_copies, buf_res->edp_map, buf_res->pending);
    } else {
        result->type = DRC_REQ_OWNER_WAITING;
        result->curr_owner_id = buf_res->claimed_owner;
    }
    knl_panic(!is_try || result->type != DRC_REQ_OWNER_CONVERTING);

    cm_spin_unlock(&bucket->lock);
    cm_spin_unlock(&g_buf_res->res_part_stat_lock[part_id]);

    if (can_cvt && result->readonly_copies && req_info->req_mode == DRC_LOCK_EXCLUSIVE) {
#ifdef DB_DEBUG_VERSION
        knl_panic(!is_try);
        if (drc_bitmap64_exist(&result->readonly_copies, DCS_SELF_INSTID(session))) {
            CM_ASSERT(DAAC_REPLAY_NODE(session));
        }
#endif
        ret = dcs_invalidate_readonly_copy(session, pagid, result->readonly_copies, req_info->inst_id,
                                           req_info->req_version);
        DTC_DRC_DEBUG_INF(
            "[DRC][%u-%u][req owner converting]: invalidate page for new request, request id=%d, "
            "readonly_copies=%llu, ret=%d",
            pagid.file, pagid.page, req_info->inst_id, result->readonly_copies, ret);

        if (ret == CT_SUCCESS) {
            /* converting buf_res won't be recycled. */
            cm_spin_lock(&g_buf_res->res_part_stat_lock[part_id], NULL);
            cm_spin_lock(&bucket->lock, NULL);
            CM_ASSERT(IS_SAME_PAGID(buf_res->page_id, pagid));
            buf_res->readonly_copies = 0;
            cm_spin_unlock(&bucket->lock);
            cm_spin_unlock(&g_buf_res->res_part_stat_lock[part_id]);
        }
    }

    if (free_slot) {
        drc_res_pool_free_item(buf_res_pool, idx);
    }
    return ret;
}

status_t drc_get_edp_info(page_id_t pagid, drc_edp_info_t *edp_info)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_res_bucket_t *bucket;
    drc_buf_res_t *buf_res;

    bucket = drc_get_buf_map_bucket(&ctx->global_buf_res.res_map, pagid.file, pagid.page);

    cm_spin_lock(&bucket->lock, NULL);
    buf_res = (drc_buf_res_t*)drc_res_map_lookup(&ctx->global_buf_res.res_map, bucket, (char*)&pagid);
    if (NULL == buf_res) {
        cm_spin_unlock(&bucket->lock);
        CT_LOG_RUN_ERR("[DRC][%u-%u][clean edp]: failed to find edp info on master", pagid.file, pagid.page);
        return CT_ERROR;
    }

    edp_info->edp_map = buf_res->edp_map;
    edp_info->latest_edp = buf_res->latest_edp;
    edp_info->readonly_copies = buf_res->readonly_copies;
    edp_info->lsn = buf_res->lsn;

    cm_spin_unlock(&bucket->lock);

    return CT_SUCCESS;
}

status_t drc_clean_edp_info(edp_page_info_t page)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_res_bucket_t *bucket;
    drc_buf_res_t *buf_res;
    page_id_t page_id = page.page;
    uint32 part_id = drc_page_partid(page_id);
    drc_global_res_t *g_buf_res = &(ctx->global_buf_res);

    bucket = drc_get_buf_map_bucket(&ctx->global_buf_res.res_map, page_id.file, page_id.page);
    cm_spin_lock(&g_buf_res->res_part_stat_lock[part_id], NULL);
    cm_spin_lock(&bucket->lock, NULL);
    buf_res = (drc_buf_res_t*)drc_res_map_lookup(&ctx->global_buf_res.res_map, bucket, (char*)&page_id);
    if (NULL == buf_res) {
        cm_spin_unlock(&bucket->lock);
        cm_spin_unlock(&g_buf_res->res_part_stat_lock[part_id]);
        CT_LOG_RUN_WAR("[DRC][%u-%u][clean edp]: failed to find edp info on master", page_id.file, page_id.page);
        return CT_ERROR;
    }

    if (page.lsn >= buf_res->lsn) {
        buf_res->edp_map = 0;
        buf_res->latest_edp = CT_INVALID_ID8;
        buf_res->latest_edp_lsn = 0;
    } else {
        CT_LOG_RUN_WAR("[DRC][%u-%u][drc clean buf edp]: drc ignore clean edp info, drc has larger lsn, page lsn=%lld, drc edp lsn=%lld",
            page_id.file, page_id.page, page.lsn, buf_res->lsn);
    }
    cm_spin_unlock(&bucket->lock);
    cm_spin_unlock(&g_buf_res->res_part_stat_lock[part_id]);

    return CT_SUCCESS;
}

void drc_claim_page_owner(knl_session_t *session, claim_info_t *claim_info, cvt_info_t *cvt_info, uint64 req_version)
{
    page_id_t pagid = claim_info->page_id;
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_res_bucket_t *bucket;
    drc_global_res_t *g_buf_res = &(ctx->global_buf_res);
    uint32 part_id = drc_page_partid(pagid);
    cvt_info->req_id = CT_INVALID_ID8;

    DTC_DRC_DEBUG_INF("[DRC][%u-%u][claim owner]: new_id=%u, has_edp=%u, req mode=%d, page lsn=%llu", pagid.file,
                      pagid.page, claim_info->new_id, claim_info->has_edp, claim_info->mode, claim_info->lsn);

    SYNC_POINT_GLOBAL_START(CANTIAN_DCS_MASTER_BEFORE_CLAIM_ABORT, NULL, 0);
    SYNC_POINT_GLOBAL_END;

    bucket = drc_get_buf_map_bucket(&ctx->global_buf_res.res_map, pagid.file, pagid.page);

    cm_spin_lock(&g_buf_res->res_part_stat_lock[part_id], NULL);
    cm_spin_lock(&bucket->lock, NULL);

    drc_buf_res_t *buf_res = (drc_buf_res_t*)drc_res_map_lookup(&ctx->global_buf_res.res_map, bucket, (char*)&pagid);

    if (buf_res == NULL || buf_res->converting.req_info.inst_id == CT_INVALID_ID8) {
        CT_LOG_RUN_WAR("[DCS][%u-%u]: claim page owner failed, req_version=%llu, cur_version=%llu",
            pagid.file, pagid.page, req_version, DRC_GET_CURR_REFORM_VERSION);
        cm_spin_unlock(&bucket->lock);
        cm_spin_unlock(&g_buf_res->res_part_stat_lock[part_id]);
        return;
    }

    drc_req_info_t *converting_req = &(buf_res->converting.req_info);
    if (!drc_is_same_claim_request(converting_req, claim_info)) {
        CT_LOG_RUN_WAR("[DRC][%u-%u][claim owner error]: claim info doesn't match converting info, claim id=%u, "
            "sid=%u, mode=%d, converting id=%u, sid=%u, mode=%d",
            pagid.file, pagid.page, claim_info->new_id, claim_info->inst_sid, claim_info->mode, converting_req->inst_id,
            converting_req->inst_sid, converting_req->req_mode);
        cm_spin_unlock(&bucket->lock);
        cm_spin_unlock(&g_buf_res->res_part_stat_lock[part_id]);
        return;
    }

    if (drc_claim_info_is_invalid(claim_info, buf_res)) {
        CT_LOG_RUN_WAR("[DCS][%u-%u]: claim info is invalid", pagid.file, pagid.page);
        cm_spin_unlock(&bucket->lock);
        cm_spin_unlock(&g_buf_res->res_part_stat_lock[part_id]);
        return;
    }

    drc_claim_new_page_owner(session, claim_info, buf_res);
    uint32 conflict_req_id = drc_convert_next_request(session, buf_res, cvt_info);

    cm_spin_unlock(&bucket->lock);
    cm_spin_unlock(&g_buf_res->res_part_stat_lock[part_id]);

    if (conflict_req_id != CT_INVALID_ID32) {
        mes_message_head_t head;
        drc_lock_item_t *lock_item = (drc_lock_item_t *)DRC_GET_RES_ADDR_BY_ID((&ctx->lock_item_pool), conflict_req_id);
        drc_req_info_t *req_info = &lock_item->req_info;
        head.src_inst = req_info->inst_id;
        head.src_sid = req_info->inst_sid;
        head.dst_inst = DCS_SELF_INSTID(session);
        head.dst_sid = session->id;
        head.rsn = req_info->rsn;
        (void)mes_send_error_msg(&head);  // error handle
        drc_res_pool_free_item(&ctx->lock_item_pool, conflict_req_id);
    }

    if ((cvt_info->req_id != CT_INVALID_ID8) && cvt_info->readonly_copies &&
        (cvt_info->req_mode == DRC_LOCK_EXCLUSIVE)) {
        DTC_DRC_DEBUG_INF(
            "[DRC][%u-%u][claim owner]: invalidate page for converting page, request id=%d, readonly_copies=%llu",
            pagid.file, pagid.page, claim_info->new_id, cvt_info->readonly_copies);
#ifdef LOG_DIAG
        if (drc_bitmap64_exist(&cvt_info->readonly_copies, DCS_SELF_INSTID(session))) {
            CM_ASSERT(DAAC_REPLAY_NODE(session));
        }
#endif
        status_t ret = dcs_invalidate_readonly_copy(session, pagid, cvt_info->readonly_copies, cvt_info->req_id,
                                                    cvt_info->req_version);
        if (ret == CT_SUCCESS) {
            /* converting buf_res won't be recycled. */
            cm_spin_lock(&g_buf_res->res_part_stat_lock[part_id], NULL);
            cm_spin_lock(&bucket->lock, NULL);
            CM_ASSERT(IS_SAME_PAGID(buf_res->page_id, pagid));
            buf_res->readonly_copies = 0;
            cm_spin_unlock(&bucket->lock);
            cm_spin_unlock(&g_buf_res->res_part_stat_lock[part_id]);
        } else {
            // knl_panic_log(0, "[DRC][%u-%u] failed to invalidate readonly copy, readonly_copies=%llu, requester
            // id:%d", pagid.file, pagid.page, cvt_info->readonly_copies, cvt_info->req_id);
            CT_LOG_RUN_ERR("[DRC][%u-%u] failed to invalidate readonly copy, readonly_copies=%llu, requester id:%d",
                           pagid.file, pagid.page, cvt_info->readonly_copies, cvt_info->req_id);
        }
    }
}

status_t drc_release_page_owner(uint8 old_id, page_id_t pagid, bool32 *released)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_res_bucket_t *bucket;
    drc_buf_res_t *buf_res;
    status_t ret;
    uint32 part_id = drc_page_partid(pagid);
    drc_global_res_t *g_buf_res = &(ctx->global_buf_res);

    *released = CT_FALSE;
    bucket = drc_get_buf_map_bucket(&ctx->global_buf_res.res_map, pagid.file, pagid.page);

    cm_spin_lock(&g_buf_res->res_part_stat_lock[part_id], NULL);
    cm_spin_lock(&bucket->lock, NULL);
    buf_res = (drc_buf_res_t *)drc_res_map_lookup(&ctx->global_buf_res.res_map, bucket, (char *)&pagid);
    if (SECUREC_UNLIKELY(NULL == buf_res)) {
        cm_spin_unlock(&bucket->lock);
        cm_spin_unlock(&g_buf_res->res_part_stat_lock[part_id]);
        knl_panic_log(0, "[DRC][%u-%u][release owner]: drc status error, buf res not found, req_id=%u",
            pagid.file, pagid.page,  old_id);
        return CT_ERROR;
    }

    if (SECUREC_UNLIKELY(old_id != buf_res->claimed_owner)) {
        cm_spin_unlock(&bucket->lock);
        cm_spin_unlock(&g_buf_res->res_part_stat_lock[part_id]);
        // Note: in some cases, such as: shutdown, it is possible.
        // Print debug err msg here in case any bug, but still return CT_SUCCESS.

        if (old_id == buf_res->converting.req_info.inst_id) {
            DTC_DRC_DEBUG_INF("[DRC][%u-%u][release owner]: still converting, owner can't be released, req_id=%u, curr_owner_id=%u",
                pagid.file, pagid.page, old_id, buf_res->claimed_owner);
            *released = CT_FALSE;
        } else {
            DTC_DRC_DEBUG_INF("[DRC][%u-%u][release owner]: not owner of page, ignored, req_id=%u, curr_owner_id=%u",
                pagid.file, pagid.page, old_id, buf_res->claimed_owner);
            *released = CT_TRUE;
        }

        return CT_SUCCESS;
    }

    if ((buf_res->converting.req_info.inst_id != CT_INVALID_ID8) || (buf_res->edp_map != 0)) {
        // if any instance is converting/waiting, or edp exists, postpone owner release
        DTC_DRC_DEBUG_INF("[DRC][%u-%u][release owner]: conflicted with other requester or edp exists, release postphoned"
            "converting=%u, edp_map=%llu", pagid.file, pagid.page, buf_res->converting.req_info.inst_id, buf_res->edp_map);

        cm_spin_unlock(&bucket->lock);
        cm_spin_unlock(&g_buf_res->res_part_stat_lock[part_id]);
        *released = CT_FALSE;
        return CT_SUCCESS;
    }

    drc_list_t *list = &ctx->global_buf_res.res_parts[buf_res->part_id];
    spinlock_t *lock = &ctx->global_buf_res.res_part_lock[buf_res->part_id];
    drc_buf_res_t *prev_buf = NULL;
    drc_buf_res_t *next_buf = NULL;
    drc_list_node_t *prev_node = NULL;
    drc_list_node_t *next_node = NULL;

    cm_spin_lock(lock, NULL);

    if (buf_res->node.prev != CT_INVALID_ID32) {
        prev_buf = (drc_buf_res_t*)DRC_GET_RES_ADDR_BY_ID(&ctx->global_buf_res.res_map.res_pool, buf_res->node.prev);
        prev_node = &prev_buf->node;
    }

    if (buf_res->node.next != CT_INVALID_ID32) {
        next_buf = (drc_buf_res_t*)DRC_GET_RES_ADDR_BY_ID(&ctx->global_buf_res.res_map.res_pool, buf_res->node.next);
        next_node = &next_buf->node;
    }

    drc_delete_list_node(list, &buf_res->node, prev_node, next_node);

    cm_spin_unlock(lock);

    drc_res_map_remove(&ctx->global_buf_res.res_map, bucket, (char*)&pagid);

    uint32 idx = buf_res->idx;
    ret = memset_s(buf_res, sizeof(drc_buf_res_t), 0, sizeof(drc_buf_res_t));
    knl_securec_check(ret);
    drc_res_pool_free_item(&ctx->global_buf_res.res_map.res_pool, idx);

    cm_spin_unlock(&bucket->lock);
    cm_spin_unlock(&g_buf_res->res_part_stat_lock[part_id]);

    *released = CT_TRUE;

    DTC_DRC_DEBUG_INF("[DRC][%u-%u][release owner]: succeeded", pagid.file, pagid.page);
    return CT_SUCCESS;
}

void drc_clean_page_from_res_part(drc_global_res_t *g_buf_res, drc_buf_res_t *buf_res, drc_res_bucket_t *bucket)
{
    drc_res_map_t *res_map = &(g_buf_res->res_map);
    drc_list_t *list = &g_buf_res->res_parts[buf_res->part_id];
    spinlock_t *lock = &g_buf_res->res_part_lock[buf_res->part_id];
    drc_list_node_t *prev_node = NULL;
    drc_list_node_t *next_node = NULL;
    cm_spin_lock(lock, NULL);
    if (buf_res->node.prev != CT_INVALID_ID32) {
        drc_buf_res_t *prev_buf = (drc_buf_res_t *)DRC_GET_RES_ADDR_BY_ID(&res_map->res_pool, buf_res->node.prev);
        prev_node = &prev_buf->node;
    }

    if (buf_res->node.next != CT_INVALID_ID32) {
        drc_buf_res_t *next_buf = (drc_buf_res_t *)DRC_GET_RES_ADDR_BY_ID(&res_map->res_pool, buf_res->node.next);
        next_node = &next_buf->node;
    }
    drc_delete_list_node(list, &buf_res->node, prev_node, next_node);
    cm_spin_unlock(lock);
}

void drc_clean_page_owner_internal(drc_global_res_t *g_buf_res, drc_buf_res_t *buf_res, drc_res_bucket_t *bucket)
{
    drc_res_map_t *res_map = &(g_buf_res->res_map);

    drc_res_map_remove(res_map, bucket, (char *)&buf_res->page_id);

    drc_clean_page_from_res_part(g_buf_res, buf_res, bucket);

    status_t ret = memset_s(buf_res, sizeof(drc_buf_res_t), 0, sizeof(drc_buf_res_t));
    knl_securec_check(ret);
}

void drc_clean_convert_q(uint8 inst_id, drc_lock_q_t *convert_q)
{
    if (convert_q->count == 0) {
        return;
    }

    drc_res_ctx_t *ctx = DRC_RES_CTX;
    uint32 item_id = convert_q->first;
    uint32 temp_item_id;
    uint32 count = convert_q->count;
    int64 clean_cnt = 0;

    for (int i = 0; i < count; i++) {
        drc_lock_item_t *item = (drc_lock_item_t*)DRC_GET_RES_ADDR_BY_ID((&ctx->lock_item_pool), item_id);
        temp_item_id = item->next;
        // Send an error message if the request belongs to a non-faulty instance
        if (item->req_info.inst_id != inst_id) {
            mes_message_head_t req_head;
            req_head.src_inst = item->req_info.inst_id;
            req_head.src_sid = item->req_info.inst_sid;
            req_head.dst_inst = DRC_SELF_INST_ID;
            req_head.dst_sid = 0;

            req_head.rsn = item->req_info.rsn;
            (void)mes_send_error_msg(&req_head);  // error handle
            CT_LOG_DEBUG_INF("[DRC]After clean convert owner(%u) non abort req_info[inst_id(%d) req_mode(%d) "
                             "curr_mode(%d) inst_sid(%d) rsn(%u) req_time(%lld)]",
                             inst_id, item->req_info.inst_id, item->req_info.req_mode, item->req_info.curr_mode,
                             item->req_info.inst_sid, item->req_info.rsn, item->req_info.req_time);
        } else {
            CT_LOG_DEBUG_INF("[DRC]After clean convert owner(%u) abort req_info[inst_id(%d) req_mode(%d) curr_mode(%d)"
                             " inst_sid(%d) rsn(%u) req_time(%lld)]",
                             inst_id, item->req_info.inst_id, item->req_info.req_mode, item->req_info.curr_mode,
                             item->req_info.inst_sid, item->req_info.rsn, item->req_info.req_time);
        }
        convert_q->count--;
        drc_res_pool_free_item(&ctx->lock_item_pool, item_id);
        item_id = temp_item_id;
        clean_cnt++;
    }

    if (convert_q->count == 0) {
        DRC_LIST_INIT(convert_q);
    }
    (void)cm_atomic_add(&ctx->stat.clean_convert_cnt, clean_cnt);
}

static inline void drc_init_page_converting(drc_buf_res_t *buf_res)
{
    buf_res->converting.req_info = g_invalid_req_info;
    buf_res->converting.next = CT_INVALID_ID32;
}

// clean converting page which owner is abort
static void drc_revert_converting_page_abort_owner(knl_session_t *session, drc_buf_res_t *buf_res)
{
    buf_bucket_t *bucket = buf_find_bucket(session, buf_res->page_id);

    cm_spin_lock(&bucket->lock, &session->stat->spin_stat.stat_bucket);
    buf_ctrl_t* ctrl = buf_find_from_bucket(bucket, buf_res->page_id);
    if (ctrl != NULL) { // local page did't held the lock
        buf_res->mode = ctrl->lock_mode;
        if (ctrl->lock_mode == DRC_LOCK_NULL) {
            drc_bitmap64_clear(&buf_res->readonly_copies, DRC_SELF_INST_ID);
            buf_res->claimed_owner = CT_INVALID_ID8;
        }
        if (ctrl->is_edp) {
            drc_bitmap64_set(&buf_res->edp_map, DRC_SELF_INST_ID);  // TODO: 4 node
            buf_res->latest_edp = DRC_SELF_INST_ID;
            buf_res->latest_edp_lsn = ctrl->page->lsn;
        }
    }
    cm_spin_unlock(&bucket->lock);
}

// clean converting page which owner is not abort
static void drc_revert_converting_page_non_abort_owner(knl_session_t *session, drc_buf_res_t *buf_res)
{
    buf_bucket_t *bucket = buf_find_bucket(session, buf_res->page_id);

    drc_lock_item_t *tmp_item = &buf_res->converting;
    cm_spin_lock(&bucket->lock, &session->stat->spin_stat.stat_bucket);
    buf_ctrl_t* ctrl = buf_find_from_bucket(bucket, buf_res->page_id);
    if (ctrl != NULL) {
        if (ctrl->lock_mode == DRC_LOCK_NULL) {
            mes_message_head_t req_head;
            req_head.src_inst = tmp_item->req_info.inst_id;
            req_head.src_sid = tmp_item->req_info.inst_sid;
            req_head.dst_inst = DRC_SELF_INST_ID;
            req_head.dst_sid = 0;
            req_head.rsn = tmp_item->req_info.rsn;
            mes_send_error_msg(&req_head);  // error handle
        } else if (ctrl->lock_mode == DRC_LOCK_EXCLUSIVE) {
            buf_res->claimed_owner = tmp_item->req_info.inst_id;
        }
    }
    cm_spin_unlock(&bucket->lock);
    drc_init_page_converting(buf_res);
}

void drc_clean_page_converting(uint8 inst_id, drc_buf_res_t *buf_res, knl_session_t *session)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    if (buf_res->converting.req_info.inst_id == inst_id) {
        CT_LOG_DEBUG_INF("[DRC][%u-%u]Before clean converting owner(%u) abort req_info[inst_id(%d) req_mode(%d)"
                         "curr_mode(%d) inst_sid(%d) rsn(%u) req_time(%lld)] claim owner(%d) mode(%u)",
                         buf_res->page_id.file, buf_res->page_id.page, inst_id, buf_res->converting.req_info.inst_id,
                         buf_res->converting.req_info.req_mode, buf_res->converting.req_info.curr_mode,
                         buf_res->converting.req_info.inst_sid, buf_res->converting.req_info.rsn,
                         buf_res->converting.req_info.req_time, buf_res->claimed_owner, buf_res->mode);
        if (buf_res->convert_q.count == 0) {
            drc_init_page_converting(buf_res);
        } else {
            // would not enter here
            uint32 buf_item_id = buf_res->convert_q.first;
            drc_lock_item_t *tmp_item = (drc_lock_item_t*)DRC_GET_RES_ADDR_BY_ID((&ctx->lock_item_pool), buf_item_id);
            buf_res->converting = *tmp_item;
            buf_res->convert_q.count--;
            buf_res->convert_q.first = tmp_item->next;
            drc_res_pool_free_item(&ctx->lock_item_pool, buf_item_id);
            if (0 == buf_res->convert_q.count) {
                DRC_LIST_INIT(&buf_res->convert_q);
            }
        }
        drc_revert_converting_page_abort_owner(session, buf_res);

        CT_LOG_DEBUG_INF("[DRC][%u-%u]After clean converting owner(%u) abort req_info[inst_id(%d) req_mode(%d)"
                         "curr_mode(%d) inst_sid(%d) rsn(%u) req_time(%lld)] claim owner(%d)  mode(%u)",
                         buf_res->page_id.file, buf_res->page_id.page, inst_id, buf_res->converting.req_info.inst_id,
                         buf_res->converting.req_info.req_mode, buf_res->converting.req_info.curr_mode,
                         buf_res->converting.req_info.inst_sid, buf_res->converting.req_info.rsn,
                         buf_res->converting.req_info.req_time, buf_res->claimed_owner, buf_res->mode);
        return;
    }

    if (buf_res->converting.req_info.inst_id != CT_INVALID_ID8) {
        CT_LOG_DEBUG_INF("[DRC][%u-%u]Before clean converting owner(%u) abort req_info[inst_id(%d) req_mode(%d)"
                         "curr_mode(%d) inst_sid(%d) rsn(%u) req_time(%lld)] claim owner(%d) mode(%u)",
                         buf_res->page_id.file, buf_res->page_id.page, inst_id, buf_res->converting.req_info.inst_id,
                         buf_res->converting.req_info.req_mode, buf_res->converting.req_info.curr_mode,
                         buf_res->converting.req_info.inst_sid, buf_res->converting.req_info.rsn,
                         buf_res->converting.req_info.req_time, buf_res->claimed_owner, buf_res->mode);
        drc_revert_converting_page_non_abort_owner(session, buf_res);
        CT_LOG_DEBUG_INF("[DRC][%u-%u]After clean converting owner(%u) abort req_info[inst_id(%d) req_mode(%d)"
                         "curr_mode(%d) inst_sid(%d) rsn(%u) req_time(%lld)] claim owner(%d) mode(%u)",
                         buf_res->page_id.file, buf_res->page_id.page, inst_id, buf_res->converting.req_info.inst_id,
                         buf_res->converting.req_info.req_mode, buf_res->converting.req_info.curr_mode,
                         buf_res->converting.req_info.inst_sid, buf_res->converting.req_info.rsn,
                         buf_res->converting.req_info.req_time, buf_res->claimed_owner, buf_res->mode);
    }
    return;
}

void drc_clean_page_owner_by_part(uint8 inst_id, drc_list_t *part_list, knl_session_t *session)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_buf_res_t *buf_res = NULL;
    uint32 buf_idx = part_list->first;
    uint32 list_count = part_list->count;
    drc_global_res_t* g_buf_res = &(ctx->global_buf_res);
    drc_res_pool_t *res_pool = &g_buf_res->res_map.res_pool;

    int64 count = 0;
    uint32 *idx;
    idx = cm_malloc(sizeof(uint32) * list_count);
    if (idx == NULL) {
        CT_LOG_RUN_ERR("alloc memory failed.");
        drc_update_remaster_local_status(REMASTER_FAIL);
        return;
    }
    drc_part_mngr_t *part_mngr = DRC_PART_MNGR;
    CT_LOG_DEBUG_INF("[DRC]drc_clean_page_owner_by_part clean owner(%u) start list_count(%u)", inst_id, list_count);
    for (uint32 i = 0; i < list_count; i++) {
        if (part_mngr->remaster_status == REMASTER_FAIL) {
            drc_res_pool_free_batch_item(res_pool, idx, count);
            cm_free(idx);
            (void)cm_atomic_add(&ctx->stat.clean_page_cnt, count);
            CT_LOG_RUN_ERR("[DRC] remaster already failed");
            return;
        }
        buf_res = (drc_buf_res_t*)DRC_GET_RES_ADDR_BY_ID(res_pool, buf_idx);
        drc_res_bucket_t *bucket = drc_get_buf_map_bucket(&ctx->global_buf_res.res_map, buf_res->page_id.file,
                                                          buf_res->page_id.page);
        cm_spin_lock(&bucket->lock, NULL);
        buf_idx = buf_res->node.next;
        CT_LOG_DEBUG_INF("[DRC][%u-%u]Before clean page owner(%u), claimed_owner(%u), lsn(%llu) "
                         "convert_q(%u), converting inst id(%u), edp map(%llu), readonly_copies(%llu)",
                         buf_res->page_id.file, buf_res->page_id.page, inst_id, buf_res->claimed_owner, buf_res->lsn,
                         buf_res->convert_q.count, buf_res->converting.req_info.inst_id, buf_res->edp_map,
                         buf_res->readonly_copies);
        // TODO: 4 node
        drc_clean_convert_q(inst_id, &buf_res->convert_q);
        drc_clean_page_converting(inst_id, buf_res, session);
        drc_bitmap64_clear(&buf_res->edp_map, inst_id);
        buf_res->readonly_copies = buf_res->readonly_copies & (~((uint64)0x1 << inst_id));
        if (buf_res->latest_edp == inst_id) {
            buf_res->latest_edp = CT_INVALID_ID8; /* find the next latest edp */
            buf_res->latest_edp_lsn = 0;
        }
        if (buf_res->claimed_owner != CT_INVALID_ID8 && buf_res->claimed_owner != inst_id) {
            cm_spin_unlock(&bucket->lock);
            continue;
        }

        buf_res->claimed_owner = CT_INVALID_ID8;
        buf_res->pending = DRC_RES_INVALID_ACTION;
        if (buf_res->readonly_copies != 0 || buf_res->edp_map != 0) {
            CT_LOG_DEBUG_INF(
                "[DRC][%u-%u]Before clean page owner(%u), claimed_owner(%u), lsn(%llu) "
                "edp map(%llu), readonly_copies(%llu), owner is on crashed node, postpone process to new page requst",
                buf_res->page_id.file, buf_res->page_id.page, inst_id, buf_res->claimed_owner, buf_res->lsn,
                buf_res->edp_map, buf_res->readonly_copies);
            cm_spin_unlock(&bucket->lock);
            continue;
        }

        idx[count] = buf_res->idx;
        DTC_DRC_DEBUG_INF("[DRC][%u-%u][clean page owner], mode(%d), claimed_owner(%d)",
            buf_res->page_id.file, buf_res->page_id.page, buf_res->mode, buf_res->claimed_owner);
        drc_clean_page_owner_internal(g_buf_res, buf_res, bucket);
        cm_spin_unlock(&bucket->lock);
        count++;
    }

    drc_res_pool_free_batch_item(res_pool, idx, count);
    cm_free(idx);
    (void)cm_atomic_add(&ctx->stat.clean_page_cnt, count);
    CT_LOG_DEBUG_INF("[DRC]drc_clean_page_owner_by_part clean owner(%u) end list_count(%u) count(%llu)", inst_id,
                     list_count, count);
}

void drc_destroy(void)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;

    drc_res_map_destroy(&ctx->local_txn_map);
    drc_res_map_destroy(&ctx->txn_res_map);
    drc_res_map_destroy(&ctx->local_lock_map);
    drc_global_res_destroy(&ctx->global_lock_res);
    drc_global_res_destroy(&ctx->global_buf_res);
    drc_res_pool_destroy(&ctx->lock_item_pool);
    drc_stat_res_destroy();
    ctx->lock = 0;
    ctx->kernel = NULL;
}

void drc_get_lock_master_id(drid_t *lock_id, uint8 *master_id)
{
    uint16 part_id;

    part_id = drc_resource_id_hash((char*)lock_id, sizeof(drid_t), DRC_MAX_PART_NUM);
    *master_id = DRC_PART_MASTER_ID(part_id);
}

status_t drc_create_lock_res(drid_t *lock_id, drc_res_bucket_t *bucket)
{
    uint32   item_idx;
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_master_res_t *lock_res;

    item_idx = drc_res_pool_alloc_item(&ctx->global_lock_res.res_map.res_pool);
    if (CT_INVALID_ID32 == item_idx) {
        CT_LOG_RUN_ERR("item_idx is invalid.");
        return CT_ERROR;
    }

    lock_res = (drc_master_res_t*)DRC_GET_RES_ADDR_BY_ID((&ctx->global_lock_res.res_map.res_pool), item_idx);
    lock_res->lock = 0;
    lock_res->idx = item_idx;
    lock_res->mode = DRC_LOCK_NULL;
    lock_res->res_id = *lock_id;
    lock_res->next = CT_INVALID_ID32;
    lock_res->converting.req_info = g_invalid_req_info;
    lock_res->converting.next = CT_INVALID_ID32;
    lock_res->granted_map = 0;
    DRC_LIST_INIT(&lock_res->convert_q);

    DTC_DRC_DEBUG_INF("[DRC][%u/%u/%u/%u/%u][create lock res]:res index:%u, curr mode=%u, "
                      "granted map:%llu, converting id:%u, converting mode:%u, q count:%u, first:%u, item_idx:%u",
                      lock_res->res_id.type, lock_res->res_id.uid, lock_res->res_id.id, lock_res->res_id.idx,
                      lock_res->res_id.part, lock_res->idx, lock_res->mode, lock_res->granted_map,
                      lock_res->converting.req_info.inst_id, lock_res->converting.req_info.req_mode,
                      lock_res->convert_q.count, lock_res->convert_q.first, item_idx);

    drc_res_map_add(bucket, item_idx, &lock_res->next);

    lock_res->part_id = drc_resource_id_hash((char*)lock_id, sizeof(drid_t), DRC_MAX_PART_NUM);
    lock_res->node.idx = item_idx;

    drc_list_t *list = &ctx->global_lock_res.res_parts[lock_res->part_id];
    spinlock_t *lock = &ctx->global_lock_res.res_part_lock[lock_res->part_id];
    drc_list_node_t *node = &lock_res->node;
    drc_master_res_t *head_lock = NULL;
    drc_list_node_t *head = NULL;

    cm_spin_lock(lock, NULL);

    if (list->count != 0) {
        head_lock = (drc_master_res_t*)DRC_GET_RES_ADDR_BY_ID(&ctx->global_lock_res.res_map.res_pool, list->first);
        head = &head_lock->node;
    }
    drc_add_list_node(list, node, head);

    cm_spin_unlock(lock);

    return CT_SUCCESS;
}

status_t drc_release_lock_res(drc_master_res_t *lock_res)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    status_t ret;

    if ((lock_res->converting.req_info.inst_id != CT_INVALID_ID8) || (lock_res->granted_map > 0)) {
        return CT_ERROR;
    }

    drc_list_t *list = &ctx->global_lock_res.res_parts[lock_res->part_id];
    spinlock_t *lock = &ctx->global_lock_res.res_part_lock[lock_res->part_id];
    drc_master_res_t *prev_buf = NULL;
    drc_master_res_t *next_buf = NULL;
    drc_list_node_t *prev_node = NULL;
    drc_list_node_t *next_node = NULL;

    cm_spin_lock(lock, NULL);

    if (lock_res->node.prev != CT_INVALID_ID32) {
        prev_buf = (drc_master_res_t*)DRC_GET_RES_ADDR_BY_ID(&ctx->global_lock_res.res_map.res_pool, lock_res->node.prev);
        prev_node = &prev_buf->node;
    }

    if (lock_res->node.next != CT_INVALID_ID32) {
        next_buf = (drc_master_res_t*)DRC_GET_RES_ADDR_BY_ID(&ctx->global_lock_res.res_map.res_pool, lock_res->node.next);
        next_node = &next_buf->node;
    }

    drc_delete_list_node(list, &lock_res->node, prev_node, next_node);

    cm_spin_unlock(lock);

    uint32 idx = lock_res->idx;
    ret = memset_s(lock_res, sizeof(drc_master_res_t), 0, sizeof(drc_master_res_t));
    knl_securec_check(ret);

    drc_res_pool_free_item(&ctx->global_lock_res.res_map.res_pool, idx);

    return CT_SUCCESS;
}

void dls_clear_granted_map_for_inst(drid_t *lock_id, int32 inst_id)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_res_bucket_t *bucket = drc_get_res_map_bucket(&ctx->global_lock_res.res_map, (char *)lock_id, sizeof(drid_t));
    uint32 part_id = drc_resource_id_hash((char *)lock_id, sizeof(drid_t), DRC_MAX_PART_NUM);
    spinlock_t *res_part_stat_lock = &ctx->global_lock_res.res_part_stat_lock[part_id];
    cm_spin_lock(res_part_stat_lock, NULL);
    cm_spin_lock(&bucket->lock, NULL);
    drc_master_res_t *lock_res = (drc_master_res_t*)drc_res_map_lookup(&ctx->global_lock_res.res_map,
                                                                       bucket, (char*)lock_id);
    if (NULL == lock_res) {
        CT_LOG_RUN_ERR("[DRC][%u/%u/%u/%u/%u]clear granted_map fail, lock does not exist, inst_id=%d",
                       lock_id->type, lock_id->uid, lock_id->id, lock_id->idx, lock_id->part, inst_id);
        drc_unlock_bucket_and_stat(bucket, res_part_stat_lock);
        return;
    }

    drc_bitmap64_clear(&lock_res->granted_map, inst_id);
    if (lock_res->granted_map == 0) {
        lock_res->mode = DRC_LOCK_NULL;
    }

    DTC_DRC_DEBUG_INF("[DRC][%u/%u/%u/%u/%u][clear granted_map]:res index:%u, curr mode=%u,"
                      "granted map:%llu, q count:%u, converting:%u",
                      lock_id->type, lock_id->uid, lock_id->id, lock_id->idx, lock_id->part, lock_res->idx,
                      lock_res->mode, lock_res->granted_map, lock_res->convert_q.count,
                      lock_res->converting.req_info.inst_id);
    drc_unlock_bucket_and_stat(bucket, res_part_stat_lock);
}

status_t drc_request_lock_owner_add_req_into_cvt_q(drc_master_res_t *lock_res, drc_req_info_t *req_info,
                                                   drid_t *lock_id)
{
    uint32  item_idx;
    drc_lock_item_t *lock_item;
    drc_res_ctx_t *ctx = DRC_RES_CTX;

    item_idx = drc_res_pool_alloc_item(&ctx->lock_item_pool);
    if (CT_INVALID_ID32 == item_idx) {
        CT_LOG_RUN_ERR("[DRC]drc_res_pool_alloc_item failed!");
        return CT_ERROR;
    }
    lock_item = (drc_lock_item_t*)DRC_GET_RES_ADDR_BY_ID((&ctx->lock_item_pool), item_idx);

    lock_item->req_info = *req_info;
    lock_item->next = CT_INVALID_ID32;

    if (0 == lock_res->convert_q.count) {
        lock_res->convert_q.first = item_idx;
        lock_res->convert_q.last = item_idx;
    } else {
        drc_lock_item_t *tmp_item = (drc_lock_item_t *)DRC_GET_RES_ADDR_BY_ID((&ctx->lock_item_pool),
                                                                              lock_res->convert_q.last);
        tmp_item->next = item_idx;
        lock_res->convert_q.last = item_idx;
    }
    lock_res->convert_q.count++;

    DTC_DRC_DEBUG_INF("[DRC][%u/%u/%u/%u/%u][add into converter q]:res index:%u, curr mode=%u, req mode=%u,"
                      "granted map:%llu, from %d, sid:%d, q count:%u, converting:%u",
                      lock_id->type, lock_id->uid, lock_id->id, lock_id->idx, lock_id->part, lock_res->idx,
                      lock_res->mode, req_info->req_mode, lock_res->granted_map, req_info->inst_id, req_info->inst_sid,
                      lock_res->convert_q.count, lock_res->converting.req_info.inst_id);
    return CT_SUCCESS;
}

status_t drc_request_lock_owner(knl_session_t *session, drid_t *lock_id, drc_req_info_t *req_info, bool32 *is_granted,
                                uint64 *old_owner_map, uint64 req_version)
{
    status_t ret;
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_master_res_t *lock_res;
    drc_res_bucket_t *bucket;
    uint32 part_id;
    spinlock_t *res_part_stat_lock = NULL;

    bucket = drc_get_res_map_bucket(&ctx->global_lock_res.res_map, (char*)lock_id, sizeof(drid_t));
    part_id = drc_resource_id_hash((char*)lock_id, sizeof(drid_t), DRC_MAX_PART_NUM);
    res_part_stat_lock = &ctx->global_lock_res.res_part_stat_lock[part_id];
    cm_spin_lock(res_part_stat_lock, NULL);
    cm_spin_lock(&bucket->lock, NULL);
    if (DRC_STOP_DLS_REQ_FOR_REFORMING(req_version, session)) {
        CT_LOG_DEBUG_ERR("[DLS]reforming, request lock owner failed, req_version=%llu, cur_version=%llu",
            req_version, DRC_GET_CURR_REFORM_VERSION);
        cm_spin_unlock(&bucket->lock);
        cm_spin_unlock(res_part_stat_lock);
        return CT_ERROR;
    }

    DTC_DRC_DEBUG_INF("[DRC][%u/%u/%u/%u/%u][request lock res]: req mode=%u, from %d, sid:%d", lock_id->type,
                      lock_id->uid, lock_id->id, lock_id->idx, lock_id->part, req_info->req_mode, req_info->inst_id,
                      req_info->inst_sid);

    lock_res = (drc_master_res_t*)drc_res_map_lookup(&ctx->global_lock_res.res_map, bucket, (char*)lock_id);
    if (NULL == lock_res) {
        ret = drc_create_lock_res(lock_id, bucket);
        if (ret != CT_SUCCESS) {
            cm_spin_unlock(&bucket->lock);
            cm_spin_unlock(res_part_stat_lock);
            CT_LOG_RUN_ERR("[DRC]drc_create_lock_res failed!");
            knl_panic(0);
            return CT_ERROR;
        }
        lock_res = (drc_master_res_t *)drc_res_map_lookup(&ctx->global_lock_res.res_map, bucket, (char *)lock_id);
        lock_res->converting.req_info = *req_info;
        cm_spin_unlock(&bucket->lock);
        cm_spin_unlock(res_part_stat_lock);

        *is_granted = CT_TRUE;
        *old_owner_map = 0;
        DTC_DRC_DEBUG_INF("[DRC][%u/%u/%u/%u/%u][create convert lock res]:res index:%u, curr mode=%u, req mode=%u,"
                          "granted map:%llu, from %d, sid:%d, q count:%u, granted:%d, old_owner_map:%llu",
                          lock_id->type, lock_id->uid, lock_id->id, lock_id->idx, lock_id->part, lock_res->idx,
                          lock_res->mode, req_info->req_mode, lock_res->granted_map, req_info->inst_id,
                          req_info->inst_sid, lock_res->convert_q.count, *is_granted, *old_owner_map);

        return CT_SUCCESS;
    }

    if (lock_res->mode > DRC_LOCK_EXCLUSIVE) {
        cm_spin_unlock(&bucket->lock);
        cm_spin_unlock(res_part_stat_lock);
        CT_LOG_RUN_ERR("[DRC][%u/%u/%u/%u/%u] invalid lock mode %d", lock_id->type,
                       lock_id->uid, lock_id->id, lock_id->idx, lock_id->part, lock_res->mode);
        return CT_ERROR;
    }

    drc_req_info_t *converting_req = &(lock_res->converting.req_info);
    if (converting_req->inst_id == CT_INVALID_ID8) {
        if (1 == g_mode_compatible_matrix[req_info->req_mode][lock_res->mode]) {
            *is_granted = CT_TRUE;
            *old_owner_map = 0;
        } else {
            *is_granted = CT_FALSE;
            *old_owner_map = lock_res->granted_map;
        }

        knl_panic(lock_res->convert_q.count == 0);
        lock_res->converting.req_info = *req_info;

        cm_spin_unlock(&bucket->lock);
        cm_spin_unlock(res_part_stat_lock);

        DTC_DRC_DEBUG_INF("[DRC][%u/%u/%u/%u/%u][can convert lock res]:res index:%u, curr mode=%u, req mode=%u,"
                          "granted map:%llu, from %d, sid:%d, q count:%u, granted:%d, old_owner_map:%llu",
                          lock_id->type, lock_id->uid, lock_id->id, lock_id->idx, lock_id->part, lock_res->idx,
                          lock_res->mode, req_info->req_mode, lock_res->granted_map, req_info->inst_id,
                          req_info->inst_sid, lock_res->convert_q.count, *is_granted, *old_owner_map);

        return CT_SUCCESS;
    }

    if (drc_bitmap64_exist(&lock_res->granted_map, req_info->inst_id)) {
        // 1. new request comes: release lock, and the request from same node comes again
        // 2. lock upgrade from s->x
        cm_spin_unlock(&bucket->lock);
        cm_spin_unlock(res_part_stat_lock);
        DTC_DRC_DEBUG_ERR(
            "[DRC][%u/%u/%u/%u/%u][already be the owner], may have conflict, return error to avoid deadlock:res index:%u, curr mode=%u, req mode=%u,"
            "granted map:%llu, from %d, sid:%d, q count:%u",
            lock_id->type, lock_id->uid, lock_id->id, lock_id->idx, lock_id->part, lock_res->idx, lock_res->mode,
            req_info->req_mode, lock_res->granted_map, req_info->inst_id, req_info->inst_sid,
            lock_res->convert_q.count);

        *is_granted = CT_FALSE;
        return CT_ERROR;
    }

    if (drc_request_lock_owner_add_req_into_cvt_q(lock_res, req_info, lock_id) != CT_SUCCESS) {
        cm_spin_unlock(&bucket->lock);
        cm_spin_unlock(res_part_stat_lock);
        CT_LOG_RUN_ERR("[DRC][%u/%u/%u/%u/%u]add dls req into cvt_q failed!",
            lock_id->type, lock_id->uid, lock_id->id, lock_id->idx, lock_id->part);
        return CT_ERROR;
    }

    do {
        cm_spin_unlock(&bucket->lock);
        cm_spin_unlock(res_part_stat_lock);
        cm_sleep(5);  // 5 ms
        cm_spin_lock(res_part_stat_lock, NULL);
        cm_spin_lock(&bucket->lock, NULL);

        if (DRC_STOP_DLS_REQ_FOR_REFORMING(req_version, session)) {
            CT_LOG_RUN_ERR("[DLS]reforming, request lock owner failed, req_version=%llu, cur_version=%llu",
                req_version, DRC_GET_CURR_REFORM_VERSION);
            cm_spin_unlock(&bucket->lock);
            cm_spin_unlock(res_part_stat_lock);
            return CT_ERROR;
        }

        knl_panic(lock_res->converting.req_info.inst_id != CT_INVALID_ID8);
        if (req_info->inst_id == lock_res->converting.req_info.inst_id) {
            if (1 == g_mode_compatible_matrix[req_info->req_mode][lock_res->mode]) {
                *is_granted = CT_TRUE;
                *old_owner_map = 0;
            } else {
                *is_granted = CT_FALSE;
                *old_owner_map = lock_res->granted_map;
            }
            break;
        }
    } while (CT_TRUE);

    cm_spin_unlock(&bucket->lock);
    cm_spin_unlock(res_part_stat_lock);

    DTC_DRC_DEBUG_INF("[DRC][%u/%u/%u/%u/%u][can convert at last]:res index:%u, curr mode=%u, req mode=%u,"
                      "granted map:%llu, from %d, sid:%d, q count:%u, converting:%u, granted:%d, old_owner_map:%llu",
                      lock_id->type, lock_id->uid, lock_id->id, lock_id->idx, lock_id->part, lock_res->idx,
                      lock_res->mode, req_info->req_mode, lock_res->granted_map, req_info->inst_id, req_info->inst_sid,
                      lock_res->convert_q.count, converting_req->inst_id, *is_granted, *old_owner_map);

    return CT_SUCCESS;
}

status_t drc_try_request_lock_owner(knl_session_t *session, drid_t *lock_id, drc_req_info_t *req_info,
                                    bool32 *is_granted, uint64 *old_owner_map, uint64 req_version)
{
    status_t ret;
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_part_mngr_t *part_mngr = DRC_PART_MNGR;
    drc_master_res_t *lock_res;
    drc_res_bucket_t *bucket;
    uint32 part_id;
    spinlock_t *res_part_stat_lock = NULL;

    if (part_mngr->remaster_status < REMASTER_DONE) {
        DTC_DRC_DEBUG_INF("[DRC][%u/%u/%u/%u/%u][request lock failed]:remaster status(%u) is in progress",
                          lock_id->type, lock_id->uid, lock_id->id, lock_id->idx, lock_id->part,
                          part_mngr->remaster_status);
        return CT_ERROR;
    }

    bucket = drc_get_res_map_bucket(&ctx->global_lock_res.res_map, (char *)lock_id, sizeof(drid_t));
    part_id = drc_resource_id_hash((char*)lock_id, sizeof(drid_t), DRC_MAX_PART_NUM);
    res_part_stat_lock = &ctx->global_lock_res.res_part_stat_lock[part_id];
    cm_spin_lock(res_part_stat_lock, NULL);
    cm_spin_lock(&bucket->lock, NULL);
    if (DRC_STOP_DLS_REQ_FOR_REFORMING(req_version, session)) {
        CT_LOG_RUN_ERR("[DLS]reforming, try request lock owner failed, req_version=%llu, cur_version=%llu",
            req_version, DRC_GET_CURR_REFORM_VERSION);
        cm_spin_unlock(&bucket->lock);
        cm_spin_unlock(res_part_stat_lock);
        return CT_ERROR;
    }
    lock_res = (drc_master_res_t *)drc_res_map_lookup(&ctx->global_lock_res.res_map, bucket, (char *)lock_id);
    if (NULL == lock_res) {
        ret = drc_create_lock_res(lock_id, bucket);
        if (ret != CT_SUCCESS) {
            cm_spin_unlock(&bucket->lock);
            cm_spin_unlock(res_part_stat_lock);
            CT_LOG_RUN_ERR("[DRC]drc_create_lock_res failed!");
            return CT_ERROR;
        }
        lock_res = (drc_master_res_t *)drc_res_map_lookup(&ctx->global_lock_res.res_map, bucket, (char *)lock_id);
        lock_res->converting.req_info = *req_info;
        cm_spin_unlock(&bucket->lock);
        cm_spin_unlock(res_part_stat_lock);
        *is_granted = CT_TRUE;
        *old_owner_map = 0;
        return CT_SUCCESS;
    }

    if (lock_res->mode > DRC_LOCK_EXCLUSIVE) {
        cm_spin_unlock(&bucket->lock);
        cm_spin_unlock(res_part_stat_lock);
        CT_LOG_RUN_ERR("[DRC][%u/%u/%u/%u/%u] invalid lock mode %d", lock_id->type,
                       lock_id->uid, lock_id->id, lock_id->idx, lock_id->part, lock_res->mode);
        return CT_ERROR;
    }

    if (lock_res->converting.req_info.inst_id == CT_INVALID_ID8) {
        if (1 == g_mode_compatible_matrix[req_info->req_mode][lock_res->mode]) {
            *old_owner_map = lock_res->granted_map;
            *is_granted = CT_TRUE;
        } else {
            *is_granted = CT_FALSE;
            *old_owner_map = lock_res->granted_map;
        }
        knl_panic(lock_res->convert_q.count == 0);
        lock_res->converting.req_info = *req_info;
        cm_spin_unlock(&bucket->lock);
        cm_spin_unlock(res_part_stat_lock);
        DTC_DRC_DEBUG_INF(
            "[DRC][%u/%u/%u/%u/%u][can convert lock res for try request]:res index:%u, curr mode=%u, req mode=%u,"
            "granted map:%llu, from %d, sid:%d, q count:%u, granted:%d, old_owner_map:%llu",
            lock_id->type, lock_id->uid, lock_id->id, lock_id->idx, lock_id->part, lock_res->idx, lock_res->mode,
            req_info->req_mode, lock_res->granted_map, req_info->inst_id, req_info->inst_sid, lock_res->convert_q.count,
            *is_granted, *old_owner_map);

        return CT_SUCCESS;
    }

    cm_spin_unlock(&bucket->lock);
    cm_spin_unlock(res_part_stat_lock);

    DTC_DRC_DEBUG_INF("[DRC][%u/%u/%u/%u/%u][try request failed]:res index:%u, curr mode=%u, req mode=%u,"
                      "granted map:%llu, from %d, sid:%d, q count:%u",
                      lock_id->type, lock_id->uid, lock_id->id, lock_id->idx, lock_id->part, lock_res->idx,
                      lock_res->mode, req_info->req_mode, lock_res->granted_map, req_info->inst_id, req_info->inst_sid,
                      lock_res->convert_q.count);

    return CT_ERROR;
}

void drc_convert_lock_owner(drc_master_res_t *lock_res)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;

    if (lock_res->convert_q.count == 0) {
        lock_res->converting.req_info.inst_id = CT_INVALID_ID8;
        return;
    }

    uint32 item_idx = lock_res->convert_q.first;
    knl_panic(item_idx != CT_INVALID_ID32);
    drc_lock_item_t *lock_item = (drc_lock_item_t *)DRC_GET_RES_ADDR_BY_ID((&ctx->lock_item_pool), item_idx);

    lock_res->converting = *lock_item;
    lock_res->convert_q.first = lock_item->next;
    lock_res->convert_q.count--;
    drc_res_pool_free_item(&ctx->lock_item_pool, item_idx);

    knl_panic(lock_res->converting.req_info.inst_id != CT_INVALID_ID8);

    DTC_DRC_DEBUG_INF("[DRC][%u/%u/%u/%u/%u][convert finish]:res index:%u, curr mode=%u,"
                      "granted map:%llu, converting id:%u, converting mode:%u, q count:%u, first:%u, item_idx:%u",
                      lock_res->res_id.type, lock_res->res_id.uid, lock_res->res_id.id, lock_res->res_id.idx,
                      lock_res->res_id.part, lock_res->idx, lock_res->mode, lock_res->granted_map,
                      lock_res->converting.req_info.inst_id, lock_res->converting.req_info.req_mode,
                      lock_res->convert_q.count, lock_res->convert_q.first, item_idx);
}

static status_t drc_cancel_lock_owner_request_nolock_part(uint8 inst_id, drid_t *lock_id, drc_res_bucket_t *bucket)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_master_res_t *lock_res;

    lock_res = (drc_master_res_t*)drc_res_map_lookup(&ctx->global_lock_res.res_map, bucket, (char*)lock_id);
    if (NULL == lock_res) {
        DTC_DRC_DEBUG_ERR(
            "[DRC][%u/%u/%u/%u/%u]instance(%u) cancel lock_owner request fail, lock does not exist",
            lock_id->type, lock_id->uid, lock_id->id, lock_id->idx, lock_id->part, inst_id);
        return CT_ERROR;
    }

    drc_req_info_t *converting_req = &lock_res->converting.req_info;
    DTC_DRC_DEBUG_INF(
        "[DRC][%u-%u][cancel_lock_owner_request]:res index:%u, req_id=%u, granted map:%llu, cancel converting node:%d, session id:%d, mode:%d",
        lock_id->type, lock_id->id, lock_res->idx, inst_id, lock_res->granted_map, converting_req->inst_id,
        converting_req->inst_sid, converting_req->curr_mode);

    // knl_panic(converting_req->inst_id == inst_id);
    if (converting_req->inst_id != inst_id) {
        CT_LOG_RUN_WAR("[DRC][%u/%u/%u/%u/%u]cvting changed, req_inst_id=%u, inst_id=%u",
            lock_id->type, lock_id->uid, lock_id->id, lock_id->idx, lock_id->part, converting_req->inst_id, inst_id);
        return CT_SUCCESS;
    }
    drc_convert_lock_owner(lock_res);
    return CT_SUCCESS;
}

status_t drc_cancel_lock_owner_request(uint8 inst_id, drid_t *lock_id)
{
    status_t ret;
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_res_bucket_t *bucket;
    uint32 part_id = drc_resource_id_hash((char *)lock_id, sizeof(drid_t), DRC_MAX_PART_NUM);
    spinlock_t *res_part_stat_lock = &ctx->global_lock_res.res_part_stat_lock[part_id];
    bucket = drc_get_res_map_bucket(&ctx->global_lock_res.res_map, (char*)lock_id, sizeof(drid_t));
    cm_spin_lock(res_part_stat_lock, NULL);
    cm_spin_lock(&bucket->lock, NULL);
    ret = drc_cancel_lock_owner_request_nolock_part(inst_id, lock_id, bucket);
    cm_spin_unlock(&bucket->lock);
    cm_spin_unlock(res_part_stat_lock);
    return ret;
}

static status_t drc_cancel_lock_owner_request_nolock(uint8 inst_id, drid_t *lock_id)
{
    status_t ret;
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_res_bucket_t *bucket;
    bucket = drc_get_res_map_bucket(&ctx->global_lock_res.res_map, (char*)lock_id, sizeof(drid_t));
    ret = drc_cancel_lock_owner_request_nolock_part(inst_id, lock_id, bucket);
    return ret;
}

status_t drc_claim_lock_owner(knl_session_t *session, drid_t *lock_id, lock_claim_info_t *claim_info,
                              uint64 req_version, bool32 is_remaster)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_master_res_t *lock_res;
    drc_res_bucket_t *bucket = NULL;
    spinlock_t *res_part_stat_lock = NULL;
    if (drc_lock_bucket_and_stat_with_version_check(session, lock_id, &bucket, &res_part_stat_lock, req_version,
        is_remaster) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[DLS]reforming, claim lock(%u/%u/%u/%u/%u) owner failed, req_version=%llu, cur_version=%llu",
            lock_id->type, lock_id->uid, lock_id->id, lock_id->idx, lock_id->part, req_version,
            DRC_GET_CURR_REFORM_VERSION);
        return CT_ERROR;
    }
    lock_res = (drc_master_res_t*)drc_res_map_lookup(&ctx->global_lock_res.res_map, bucket, (char*)lock_id);
    if (NULL == lock_res) {
        CT_LOG_RUN_ERR("[DRC][%u/%u/%u/%u/%u][claim fail, lock does not exist]: claim mode=%u, from %d, sid:%d",
            lock_id->type, lock_id->uid, lock_id->id, lock_id->idx, lock_id->part, claim_info->mode,
            claim_info->new_id, claim_info->inst_sid);
        drc_unlock_bucket_and_stat(bucket, res_part_stat_lock);
        knl_panic(0);
        return CT_ERROR;
    }

    DTC_DRC_DEBUG_INF("[DRC][%u/%u/%u/%u/%u][start claim]:res index:%u, curr mode=%u, claim mode=%u,"
                      "granted map:%llu, from %d, sid:%d, q count:%u, converting:%u",
                      lock_id->type, lock_id->uid, lock_id->id, lock_id->idx, lock_id->part, lock_res->idx,
                      lock_res->mode, claim_info->mode, lock_res->granted_map, claim_info->new_id, claim_info->inst_sid,
                      lock_res->convert_q.count, lock_res->converting.req_info.inst_id);

    knl_panic((claim_info->new_id == lock_res->converting.req_info.inst_id) &&
              (claim_info->mode == lock_res->converting.req_info.req_mode));

    if (claim_info->mode == DRC_LOCK_EXCLUSIVE) {
        lock_res->granted_map = 0;
    }
    // for table lock, master lock res not recycle, so master records grand_map is not correct
    knl_panic(!drc_bitmap64_exist(&lock_res->granted_map, claim_info->new_id) ||
        lock_res->res_id.type == DR_TYPE_TABLE);
    drc_bitmap64_set(&lock_res->granted_map, claim_info->new_id);
    lock_res->mode = lock_res->converting.req_info.req_mode;

    DTC_DRC_DEBUG_INF("[DRC][%u/%u/%u/%u/%u][after claim]:res index:%u, curr mode=%u, claim mode=%u,"
                      "granted map:%llu, from %d, sid:%d, q count:%u, converting:%u",
                      lock_id->type, lock_id->uid, lock_id->id, lock_id->idx, lock_id->part, lock_res->idx,
                      lock_res->mode, claim_info->mode, lock_res->granted_map, claim_info->new_id, claim_info->inst_sid,
                      lock_res->convert_q.count, lock_res->converting.req_info.inst_id);

    drc_convert_lock_owner(lock_res);

    drc_unlock_bucket_and_stat(bucket, res_part_stat_lock);

    return CT_SUCCESS;
}

status_t drc_release_lock_owner(uint8 old_id, drid_t *lock_id)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_master_res_t *lock_res;
    drc_res_bucket_t *bucket;

    bucket = drc_get_res_map_bucket(&ctx->global_lock_res.res_map, (char*)lock_id, sizeof(drid_t));
    lock_res = (drc_master_res_t*)drc_res_map_lookup(&ctx->global_lock_res.res_map, bucket, (char*)lock_id);
    if (NULL == lock_res) {
        DTC_DRC_DEBUG_ERR("[DRC][%u/%u/%u/%u/%u][release lock_owner fail, lock does not exist]:from %d", lock_id->type,
                          lock_id->uid, lock_id->id, lock_id->idx, lock_id->part, old_id);

        return CT_ERROR;
    }

    if (CT_FALSE == drc_bitmap64_exist(&lock_res->granted_map, old_id)) {
        DTC_DRC_DEBUG_ERR(
            "[DRC][drc_release_lock_owner] instance(%u) didn't own the lock(%u/%u/%u/%u/%u), granted map(%llu)",
            old_id, lock_id->type, lock_id->uid, lock_id->id, lock_id->idx, lock_id->part, lock_res->granted_map);
        return CT_ERROR;
    }

    drc_bitmap64_clear(&lock_res->granted_map, old_id);
    if (lock_res->granted_map == 0) {
        lock_res->mode = DRC_LOCK_NULL;
    }

    if ((lock_res->granted_map > 0) || (lock_res->converting.req_info.inst_id != CT_INVALID_ID8)) {
        return CT_SUCCESS;
    }

    if (lock_res->converting.req_info.inst_id == CT_INVALID_ID8) {
        drc_res_map_remove(&ctx->global_lock_res.res_map, bucket, (char*)lock_id);
        (void)drc_release_lock_res(lock_res);
        return CT_SUCCESS;
    }
    return CT_SUCCESS;
}

void drc_clean_lock_owner_by_part(uint8 inst_id, drc_list_t *part_list)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_master_res_t *lock_res = NULL;
    uint32 lock_idx = part_list->first;
    uint32 list_count = part_list->count;
    uint32 i;
    drc_res_bucket_t *bucket;

    drc_part_mngr_t *part_mngr = DRC_PART_MNGR;
    for (i = 0; i < list_count; i++) {
        if (part_mngr->remaster_status == REMASTER_FAIL) {
            (void)cm_atomic_add(&ctx->stat.clean_lock_cnt, (int64)i);
            CT_LOG_RUN_ERR("[DRC] remaster already failed");
            return;
        }
        lock_res = (drc_master_res_t*)DRC_GET_RES_ADDR_BY_ID(&ctx->global_lock_res.res_map.res_pool, lock_idx);
        bucket = drc_get_res_map_bucket(&ctx->global_lock_res.res_map, (char*)(&lock_res->res_id), sizeof(drid_t));
        cm_spin_lock(&bucket->lock, NULL);
        lock_idx = lock_res->node.next;

        DTC_DRC_DEBUG_INF("[DRC]begin clean lock res[%u-%u-%u-%u-%u-%u], lock mode[%u], "
                          "granted[%llu], partid[%u].",
                          lock_res->res_id.type, lock_res->res_id.id, lock_res->res_id.uid, lock_res->res_id.idx,
                          lock_res->res_id.part, lock_res->res_id.parentpart, lock_res->mode, lock_res->granted_map,
                          lock_res->part_id);

        drc_clean_convert_q(inst_id, &lock_res->convert_q);
        if (lock_res->converting.req_info.inst_id == inst_id) {
            (void)drc_cancel_lock_owner_request_nolock(inst_id, &lock_res->res_id);
        }
        if (drc_bitmap64_exist(&lock_res->granted_map, inst_id) == CT_TRUE) {
            (void)drc_release_lock_owner(inst_id, &lock_res->res_id);
        } else {
            //only for code specification
        }

        DTC_DRC_DEBUG_INF("[DRC]end clean lock res[%u-%u-%u-%u-%u-%u], lock mode[%u], granted[%llu], partid[%u].",
                          lock_res->res_id.type, lock_res->res_id.id, lock_res->res_id.uid, lock_res->res_id.idx,
                          lock_res->res_id.part, lock_res->res_id.parentpart, lock_res->mode, lock_res->granted_map,
                          lock_res->part_id);
        cm_spin_unlock(&bucket->lock);
    }
    (void)cm_atomic_add(&ctx->stat.clean_lock_cnt, (int64)list_count);
}

drc_local_lock_res_t* drc_create_local_lock_res(drid_t *lock_id)
{
    uint32   item_idx;
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_local_lock_res_t *lock_res;
    drc_res_bucket_t *bucket;

    item_idx = drc_res_pool_alloc_item(&ctx->local_lock_map.res_pool);
    if (CT_INVALID_ID32 == item_idx) {
        return NULL;
    }
    lock_res = (drc_local_lock_res_t*)DRC_GET_RES_ADDR_BY_ID((&ctx->local_lock_map.res_pool), item_idx);
    lock_res->idx = item_idx;
    lock_res->res_id = *lock_id;
    lock_res->is_locked = CT_FALSE;
    lock_res->is_owner = CT_FALSE;
    lock_res->count = 0;
    lock_res->lock = 0;
    lock_res->lockc = 0;
    lock_res->latch_stat.lock_mode = DRC_LOCK_NULL;
    lock_res->latch_stat.shared_count = 0;
    lock_res->latch_stat.stat = LATCH_STATUS_IDLE;
    lock_res->latch_stat.sid = 0;
    lock_res->next = CT_INVALID_ID32;

    bucket = drc_get_res_map_bucket(&ctx->local_lock_map, (char*)lock_id, sizeof(drid_t));

    drc_res_map_add(bucket, item_idx, &lock_res->next);
    CT_LOG_DEBUG_INF("[DRC] dls_lock_res_local(%u/%u/%u/%u/%u) created",
        lock_id->type, lock_id->uid, lock_id->id, lock_id->idx, lock_id->part);
    return lock_res;
}

status_t drc_release_local_lock_res(drc_local_lock_res_t *lock_res)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    status_t    ret;
    uint32 idx = lock_res->idx;

    ret = memset_s(lock_res, sizeof(drc_local_lock_res_t), 0, sizeof(drc_local_lock_res_t));
    knl_securec_check(ret);

    drc_res_pool_free_item(&ctx->local_lock_map.res_pool, idx);

    return CT_SUCCESS;
}

status_t drc_lock_local_lock_res_by_id_for_recycle(knl_session_t *session, drid_t *lock_id, uint64 req_version, bool8 *is_found)
{
    drc_local_lock_res_t *lock_res = NULL;
    drc_local_latch *latch_stat;
    if (DRC_STOP_DLS_REQ_FOR_REFORMING(req_version, session)) {
        CT_LOG_RUN_ERR("[DRC] reforming, recycle lock(%u/%u/%u/%u/%u) failed",
            lock_id->type, lock_id->uid, lock_id->id, lock_id->idx, lock_id->part);
        return CT_ERROR;
    }
    lock_res = drc_get_local_resx_without_create(lock_id);
    if (lock_res == NULL) {
        *is_found = CT_FALSE;
        CT_LOG_DEBUG_WAR("[DRC] dls_lock_res_local(%u/%u/%u/%u/%u) is NULL",
            lock_id->type, lock_id->uid, lock_id->id, lock_id->idx, lock_id->part);
        return CT_SUCCESS;
    }
    if (!drc_try_lock_local_resx(lock_res)) {
        CT_LOG_RUN_WAR("[DRC] dls_lock_res_local(%u/%u/%u/%u/%u) is locked",
            lock_id->type, lock_id->uid, lock_id->id, lock_id->idx, lock_id->part);
        return CT_ERROR;
    }
    drc_get_local_latch_statx(lock_res, &latch_stat);
    if (lock_res->is_locked || latch_stat->stat != LATCH_STATUS_IDLE) {
        CT_LOG_RUN_WAR("[DRC] dls_lock_res_local(%u/%u/%u/%u/%u) is locked, stat %u",
            lock_id->type, lock_id->uid, lock_id->id, lock_id->idx, lock_id->part, latch_stat->stat);
        drc_unlock_local_resx(lock_res);
        return CT_ERROR;
    }
    lock_res->is_locked = CT_TRUE;
    latch_stat->stat = LATCH_STATUS_X;
    drc_unlock_local_resx(lock_res);
    return CT_SUCCESS;
}

status_t drc_unlock_local_lock_res_by_id_for_recycle(drid_t *lock_id)
{
    drc_local_lock_res_t *lock_res = NULL;
    drc_local_latch *latch_stat;
    lock_res = drc_get_local_resx_without_create(lock_id);
    if (lock_res == NULL) {
        CT_LOG_DEBUG_WAR("[DRC] dls_lock_res_local(%u/%u/%u/%u/%u) is NULL",
            lock_id->type, lock_id->uid, lock_id->id, lock_id->idx, lock_id->part);
        return CT_SUCCESS;
    }
    drc_lock_local_resx(lock_res);
    drc_get_local_latch_statx(lock_res, &latch_stat);
    lock_res->is_locked = CT_FALSE;
    latch_stat->stat = LATCH_STATUS_IDLE;
    drc_unlock_local_resx(lock_res);
    return CT_SUCCESS;
}

void drc_release_local_lock_res_by_id(knl_session_t *session, drid_t *lock_id)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_local_lock_res_t *lock_res = NULL;
    drc_res_bucket_t *bucket = drc_get_res_map_bucket(&ctx->local_lock_map, (char *)lock_id, sizeof(drid_t));
    lock_res = drc_get_local_resx_without_create(lock_id);
    if (lock_res == NULL) {
        CT_LOG_DEBUG_WAR("[DRC] dls_lock_res_local(%u/%u/%u/%u/%u) is NULL",
            lock_id->type, lock_id->uid, lock_id->id, lock_id->idx, lock_id->part);
        return;
    }
    cm_spin_lock(&bucket->lock, NULL);
    drc_res_map_remove(&ctx->local_lock_map, bucket, (char *)lock_id);
    cm_spin_unlock(&bucket->lock);

    drc_release_local_lock_res(lock_res);
    CT_LOG_RUN_WAR("[DRC] dls_lock_res_local(%u/%u/%u/%u/%u) released",
        lock_id->type, lock_id->uid, lock_id->id, lock_id->idx, lock_id->part);
    return;
}

status_t drc_recycle_dls_master(knl_session_t *session, drid_t *lock_id, uint64 req_version, uint8 inst_id)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_res_bucket_t *bucket = drc_get_res_map_bucket(&ctx->global_lock_res.res_map, (char *)lock_id, sizeof(drid_t));
    uint32 part_id = drc_resource_id_hash((char *)lock_id, sizeof(drid_t), DRC_MAX_PART_NUM);
    spinlock_t *res_part_stat_lock = &ctx->global_lock_res.res_part_stat_lock[part_id];
    cm_spin_lock(res_part_stat_lock, NULL);
    cm_spin_lock(&bucket->lock, NULL);
    if (DRC_STOP_DLS_REQ_FOR_REFORMING(req_version, session)) {
        DTC_DLS_DEBUG_ERR("[DLS]reforming, recycle lock(%u/%u/%u/%u/%u) failed, "
            "req_version=%llu, cur_version=%llu",
            lock_id->type, lock_id->uid, lock_id->id, lock_id->idx, lock_id->part, req_version,
            DRC_GET_CURR_REFORM_VERSION);
        cm_spin_unlock(&bucket->lock);
        cm_spin_unlock(res_part_stat_lock);
        return CT_ERROR;
    }
    drc_master_res_t *lock_res =
        (drc_master_res_t *)drc_res_map_lookup(&ctx->global_lock_res.res_map, bucket, (char *)lock_id);
    if (lock_res == NULL) {
        CT_LOG_DEBUG_WAR("[DRC] dls_lock_res_global(%u/%u/%u/%u/%u) is NULL", lock_id->type, lock_id->uid, lock_id->id,
            lock_id->idx, lock_id->part);
        cm_spin_unlock(&bucket->lock);
        cm_spin_unlock(res_part_stat_lock);
        return CT_SUCCESS;
    }
    drc_bitmap64_clear(&lock_res->granted_map, inst_id);
    if (lock_res->converting.req_info.inst_id == CT_INVALID_ID8 && lock_res->granted_map == 0) {
        drc_res_map_remove(&ctx->global_lock_res.res_map, bucket, (char *)lock_id);
        (void)drc_release_lock_res(lock_res);
        CT_LOG_RUN_WAR("[DRC] dls_lock_res_global(%u/%u/%u/%u/%u) released", lock_id->type, lock_id->uid, lock_id->id,
            lock_id->idx, lock_id->part);
    }
    cm_spin_unlock(&bucket->lock);
    cm_spin_unlock(res_part_stat_lock);
    return CT_SUCCESS;
}

void drc_process_recycle_lock_master(void *sess, mes_message_t *receive_msg)
{
    if (sizeof(dls_recycle_msg_t) != receive_msg->head->size) {
        CT_LOG_RUN_ERR("msg is invalid, msg size %u.", receive_msg->head->size);
        mes_release_message_buf(receive_msg->buffer);
        return;
    }
    drid_t *lock_id = (drid_t *)(receive_msg->buffer + sizeof(mes_message_head_t));
    uint64 req_version = DRC_GET_CURR_REFORM_VERSION;
    status_t ret = drc_recycle_dls_master(sess, lock_id, req_version, receive_msg->head->src_inst);
    mes_message_head_t head;
    mes_init_ack_head(receive_msg->head, &head, MES_CMD_RECYCLE_DLS_MASTER_ACK, sizeof(mes_message_head_t),
        ((knl_session_t *)sess)->id);
    head.status = ret;
    mes_release_message_buf(receive_msg->buffer);
    drc_mes_send_data_with_retry((const char *)&head, DCS_RESEND_MSG_INTERVAL, DCS_MAX_RETRY_TIEMS);
}

status_t drc_recycle_lock_res(knl_session_t *session, drid_t *lock_id, uint64 req_version)
{
    uint8 master_id = CT_INVALID_ID8;
    uint8 self_id = session->kernel->dtc_attr.inst_id;
    bool8 is_found = CT_TRUE;
    drc_get_lock_master_id(lock_id, &master_id);
    if (drc_lock_local_lock_res_by_id_for_recycle(session, lock_id, req_version, &is_found) == CT_ERROR) {
        return CT_ERROR;
    }
    if (!is_found) {
        return CT_SUCCESS;
    }
    if (master_id == self_id) {
        if (drc_recycle_dls_master(session, lock_id, req_version, self_id) != CT_SUCCESS) {
            drc_unlock_local_lock_res_by_id_for_recycle(lock_id);
            return CT_ERROR;
        }
    } else {
        dls_recycle_msg_t recycle_msg = { 0 };
        recycle_msg.lock_id = *lock_id;
        mes_init_send_head(&recycle_msg.head, MES_CMD_RECYCLE_DLS_MASTER, sizeof(dls_recycle_msg_t), CT_INVALID_ID32,
            session->kernel->id, master_id, session->id, CT_INVALID_ID16);
        if (drc_mes_send_data_with_retry((const char *)&recycle_msg, DCS_RESEND_MSG_INTERVAL, DCS_MAX_RETRY_TIEMS) !=
            CT_SUCCESS) {
            drc_unlock_local_lock_res_by_id_for_recycle(lock_id);
            return CT_ERROR;
        }

        mes_message_t msg;
        if (mes_recv(session->id, &msg, CT_FALSE, CT_INVALID_ID32, CT_INVALID_ID32) != CT_SUCCESS) {
            drc_unlock_local_lock_res_by_id_for_recycle(lock_id);
            return CT_ERROR;
        }

        if (msg.head->status != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[DRC] dls_lock_res_global(%u/%u/%u/%u/%u) failed", lock_id->type, lock_id->uid, lock_id->id,
                lock_id->idx, lock_id->part);
            mes_release_message_buf(msg.buffer);
            drc_unlock_local_lock_res_by_id_for_recycle(lock_id);
            return CT_ERROR;
        }
        mes_release_message_buf(msg.buffer);
    }
    drc_release_local_lock_res_by_id(session, lock_id);
    return CT_SUCCESS;
}

void drc_lock_local_res(drid_t *lock_id)
{
    drc_res_bucket_t *bucket;
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_local_lock_res_t *lock_res;

    bucket = drc_get_res_map_bucket(&ctx->local_lock_map, (char *)lock_id, sizeof(drid_t));

    cm_spin_lock(&bucket->lock, NULL);
    lock_res = (drc_local_lock_res_t*)drc_res_map_lookup(&ctx->local_lock_map, bucket, (char*)lock_id);
    if (NULL == lock_res) {
        lock_res = drc_create_local_lock_res(lock_id);
        if (NULL == lock_res) {
            CT_LOG_RUN_ERR("[DRC][lock_local_res]create lock local res failed!");
            knl_panic(0);
            cm_spin_unlock(&bucket->lock);
            return;
        }
    }
    cm_spin_unlock(&bucket->lock);
    cm_spin_lock(&lock_res->lock, NULL);
}

bool32 drc_try_lock_local_res(drid_t *lock_id)
{
    drc_res_bucket_t *bucket;
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_local_lock_res_t *lock_res;

    bucket = drc_get_res_map_bucket(&ctx->local_lock_map, (char*)lock_id, sizeof(drid_t));

    cm_spin_lock(&bucket->lock, NULL);
    lock_res = (drc_local_lock_res_t*)drc_res_map_lookup(&ctx->local_lock_map, bucket, (char*)lock_id);
    if (NULL == lock_res) {
        lock_res = drc_create_local_lock_res(lock_id);
        if (NULL == lock_res) {
            CT_LOG_RUN_ERR("[DRC][try_lock_local_res]create lock local res failed!");
            knl_panic(0);
            cm_spin_unlock(&bucket->lock);
            return CT_FALSE;
        }
    }
    cm_spin_unlock(&bucket->lock);
    return cm_spin_try_lock(&lock_res->lock);
}

void drc_unlock_local_res(drid_t *lock_id)
{
    drc_res_bucket_t *bucket;
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_local_lock_res_t *lock_res;

    bucket = drc_get_res_map_bucket(&ctx->local_lock_map, (char*)lock_id, sizeof(drid_t));

    cm_spin_lock(&bucket->lock, NULL);
    lock_res = (drc_local_lock_res_t*)drc_res_map_lookup(&ctx->local_lock_map, bucket, (char*)lock_id);
    if (NULL == lock_res) {
        CT_LOG_RUN_ERR("[DRC][%u/%u/%u/%u/%u][unlock local res fail, lock does not exist]", lock_id->type, lock_id->uid,
                       lock_id->id, lock_id->idx, lock_id->part);

        knl_panic(0);
        cm_spin_unlock(&bucket->lock);
        return;
    }
    cm_spin_unlock(&bucket->lock);
    cm_spin_unlock(&lock_res->lock);
}

void drc_get_local_lock_stat(drid_t *lock_id, bool8* is_locked, bool8* is_owner)
{
    drc_res_bucket_t *bucket;
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_local_lock_res_t *lock_res;

    bucket = drc_get_res_map_bucket(&ctx->local_lock_map, (char*)lock_id, sizeof(drid_t));

    lock_res = (drc_local_lock_res_t*)drc_res_map_lookup(&ctx->local_lock_map, bucket, (char*)lock_id);
    if (NULL == lock_res) {
        lock_res = drc_create_local_lock_res(lock_id);
        if (NULL == lock_res) {
            CT_LOG_RUN_ERR("[DRC][get local lock stat]create lock local res failed!");
            knl_panic(0);
            return;
        }
    }

    *is_locked = lock_res->is_locked;
    *is_owner = lock_res->is_owner;

    return;
}

void drc_set_local_lock_stat(drid_t *lock_id, bool8 is_locked, bool8 is_owner)
{
    drc_res_bucket_t *bucket;
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_local_lock_res_t *lock_res;

    bucket = drc_get_res_map_bucket(&ctx->local_lock_map, (char*)lock_id, sizeof(drid_t));

    lock_res = (drc_local_lock_res_t*)drc_res_map_lookup(&ctx->local_lock_map, bucket, (char*)lock_id);
    if (NULL == lock_res) {
        lock_res = drc_create_local_lock_res(lock_id);
        if (NULL == lock_res) {
            CT_LOG_RUN_ERR("[DRC][set local lock stat]create lock local res failed!");
            knl_panic(0);
            return;
        }
    }

    lock_res->is_locked = is_locked;
    lock_res->is_owner = is_owner;
    if (!lock_res->is_owner) {
        //todo: recyle local resource
        //drc_res_map_remove(bucket, (char*)lock_id, DRC_RES_LOCAL_LOCK_TYPE);
        //drc_release_local_lock_res(lock_res);
    }
    return;
}

drc_local_lock_res_t* drc_get_local_resx_without_create(drid_t* lock_id)
{
    drc_res_bucket_t *bucket;
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_local_lock_res_t *lock_res;

    bucket = drc_get_res_map_bucket(&ctx->local_lock_map, (char *)lock_id, sizeof(drid_t));

    cm_spin_lock(&bucket->lock, NULL);
    lock_res = (drc_local_lock_res_t*)drc_res_map_lookup(&ctx->local_lock_map, bucket, (char*)lock_id);
    cm_spin_unlock(&bucket->lock);
    return lock_res;
}

drc_local_lock_res_t* drc_get_local_resx(drid_t* lock_id)
{
    drc_res_bucket_t *bucket;
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_local_lock_res_t *lock_res;

    bucket = drc_get_res_map_bucket(&ctx->local_lock_map, (char *)lock_id, sizeof(drid_t));

    cm_spin_lock(&bucket->lock, NULL);
    lock_res = (drc_local_lock_res_t*)drc_res_map_lookup(&ctx->local_lock_map, bucket, (char*)lock_id);
    if (NULL == lock_res) {
        lock_res = drc_create_local_lock_res(lock_id);
        if (NULL == lock_res) {
            CT_LOG_RUN_ERR("[DRC][get local resx]create lock local res failed!");
            knl_panic(0);
            cm_spin_unlock(&bucket->lock);
            return NULL;
        }
    }
    cm_spin_unlock(&bucket->lock);
    return lock_res;
}

bool32 drc_try_lock_local_resx(drc_local_lock_res_t* lock_res)
{
    return cm_spin_try_lock(&lock_res->lock);
}

void drc_lock_local_resx(drc_local_lock_res_t* lock_res)
{
    cm_spin_lock(&lock_res->lock, NULL);
}

void drc_unlock_local_resx(drc_local_lock_res_t* lock_res)
{
    cm_spin_unlock(&lock_res->lock);
}

void drc_lock_local_res_count(drc_local_lock_res_t* lock_res)
{
    cm_spin_lock(&lock_res->lockc, NULL);
}

void drc_unlock_local_res_count(drc_local_lock_res_t* lock_res)
{
    cm_spin_unlock(&lock_res->lockc);
}

void drc_get_local_lock_statx(drc_local_lock_res_t* lock_res, bool8* is_locked, bool8* is_owner)
{
    *is_locked = lock_res->is_locked;
    *is_owner = lock_res->is_owner;
}

void drc_set_local_lock_statx(drc_local_lock_res_t* lock_res, bool8 is_locked, bool8 is_owner)
{
    lock_res->is_locked = is_locked;
    lock_res->is_owner = is_owner;
    if (!lock_res->is_owner) {
        //todo: recycle local resource
        //drc_res_map_remove(bucket, (char*)lock_id, DRC_RES_LOCAL_LOCK_TYPE);
        //drc_release_local_lock_res(lock_res);
    }
}

void drc_get_local_latch_statx(drc_local_lock_res_t* lock_res, drc_local_latch** latch_stat)
{
    *latch_stat = &lock_res->latch_stat;
}

void drc_get_global_lock_res_parts(uint16 part_id, drc_list_t **part_list)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    *part_list = &ctx->global_lock_res.res_parts[part_id];
}

drc_master_res_t *drc_get_global_lock_resx_by_id(uint32 lock_idx)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    return (drc_master_res_t*)DRC_GET_RES_ADDR_BY_ID(&ctx->global_lock_res.res_map.res_pool, lock_idx);
}

char *drc_get_lock_mode_str(drc_master_res_t *lock_res)
{
    return g_drc_lock_mode_str[lock_res->mode - DRC_LOCK_NULL];
}

//buf_lock_mode to string
char *drc_get_buf_lock_mode_str(uint8 lock_mode)
{
    return (lock_mode < DRC_LOCK_MODE_MAX) ? g_buf_lock_mode_str[lock_mode - DRC_LOCK_NULL] : "INVALID";
}

void drc_clean_local_lock_res(drc_local_lock_res_t *lock_res)
{
    cm_spin_lock(&lock_res->lock, NULL);
    lock_res->is_owner = CT_FALSE;
    lock_res->is_locked = CT_FALSE;
    lock_res->latch_stat.lock_mode = DRC_LOCK_NULL;
    lock_res->latch_stat.shared_count = 0;
    lock_res->latch_stat.stat = LATCH_STATUS_IDLE;
    lock_res->latch_stat.sid = 0;
    cm_spin_unlock(&lock_res->lock);
}

drc_txn_res_t* drc_create_txn_res(xid_t *xid, drc_res_type_e type)
{
    uint32   item_idx;
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_txn_res_t *txn_res;
    drc_res_bucket_t *bucket;
    drc_res_map_t*  res_map = &ctx->txn_res_map;

    if (type == DRC_RES_LOCAL_TXN_TYPE) {
        res_map =  &ctx->local_txn_map;
    }

    item_idx = drc_res_pool_alloc_item(&(res_map->res_pool));
    if (CT_INVALID_ID32 == item_idx) {
        return NULL;
    }
    txn_res = (drc_txn_res_t*)DRC_GET_RES_ADDR_BY_ID((&res_map->res_pool), item_idx);
    txn_res->idx = item_idx;
    txn_res->res_id = *xid;
    txn_res->ins_map = 0;
    if (!txn_res->is_cond_inited) {
        cm_init_cond(&txn_res->cond);
        txn_res->is_cond_inited = CT_TRUE;
    }

    bucket = drc_get_res_map_bucket(res_map, (char*)xid, sizeof(xid_t));

    drc_res_map_add(bucket, item_idx, &txn_res->next);

    return txn_res;
}

status_t drc_release_txn_res(drc_txn_res_t *txn_res)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    status_t    ret;
    uint32 idx = txn_res->idx;

    ret = memset_s(txn_res, sizeof(drc_txn_res_t), 0, sizeof(drc_txn_res_t));
    knl_securec_check(ret);

    drc_res_pool_free_item(&ctx->txn_res_map.res_pool, idx);

    return CT_SUCCESS;
}

status_t drc_release_local_txn_res(drc_txn_res_t *txn_res)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    uint32 idx = txn_res->idx;

    txn_res->ins_map = 0;
    drc_res_pool_free_item(&ctx->local_txn_map.res_pool, idx);

    return CT_SUCCESS;
}

void drc_enqueue_txn(xid_t *xid, uint8 ins_id)
{
    drc_res_bucket_t *bucket;
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_txn_res_t *txn_res;

    bucket = drc_get_res_map_bucket(&ctx->txn_res_map, (char*)xid, sizeof(xid_t));

    cm_spin_lock(&bucket->lock, NULL);
    txn_res = (drc_txn_res_t*)drc_res_map_lookup(&ctx->txn_res_map, bucket, (char*)xid);
    if (NULL == txn_res) {
        txn_res = drc_create_txn_res(xid, DRC_RES_TXN_TYPE);
        if (NULL == txn_res) {
            CT_LOG_RUN_ERR("[DRC][drc_enqueue_txn]create txn res failed!");
            knl_panic(0);
            cm_spin_unlock(&bucket->lock);
            return;
        }
    }
    //set instance id map
    drc_bitmap64_set(&txn_res->ins_map, ins_id);
    cm_spin_unlock(&bucket->lock);
    return;
}

void drc_release_txn(knl_session_t *session, xid_t *xid, knl_scn_t scn, drc_send_txn_msg func)
{
    drc_res_bucket_t *bucket;
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_txn_res_t *txn_res;

    bucket = drc_get_res_map_bucket(&ctx->txn_res_map, (char*)xid, sizeof(xid_t));

    cm_spin_lock(&bucket->lock, NULL);
    txn_res = (drc_txn_res_t*)drc_res_map_lookup(&ctx->txn_res_map, bucket, (char*)xid);
    if (NULL == txn_res) {
        // not found
        DTC_DRC_DEBUG_ERR("[DRC]release txn fail, txn does not exist:txn %llu scn %llu", xid->value, scn);
        cm_spin_unlock(&bucket->lock);
        return;
    }

    for (uint8 i = 0; i < CT_MAX_INSTANCES; i++) {
        if (drc_bitmap64_exist(&txn_res->ins_map, i)) {
            if (DRC_SELF_INST_ID == i) {
                continue; // self id
            }
            // send message to all guests to wake up by wait hash queue
            func(session, xid, scn, i, MES_CMD_AWAKE_TXN);
            CT_LOG_DEBUG_INF("[DLS] wake up txn %llu scn %llu send to instance %u", xid->value, scn, i);
        }
    }
    drc_res_map_remove(&ctx->txn_res_map, bucket, (char*)xid);
    drc_release_txn_res(txn_res);

    cm_spin_unlock(&bucket->lock);
    return;
}


bool32 drc_local_txn_wait(xid_t *xid)
{
    drc_res_bucket_t *bucket;
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_txn_res_t *txn_res;

    bucket = drc_get_res_map_bucket(&ctx->local_txn_map, (char*)xid, sizeof(xid_t));

    cm_spin_lock(&bucket->lock, NULL);
    txn_res = (drc_txn_res_t*)drc_res_map_lookup(&ctx->local_txn_map, bucket, (char*)xid);
    if (NULL == txn_res) {
        txn_res = drc_create_txn_res(xid, DRC_RES_LOCAL_TXN_TYPE);
        if (NULL == txn_res) {
            CT_LOG_RUN_ERR("[DRC][drc_local_txn_wait]create txn res failed!");
            knl_panic(0);
            cm_spin_unlock(&bucket->lock);
            return CT_FALSE;
        }
    }
    //set instance id map
    cm_spin_unlock(&bucket->lock);

    return cm_wait_cond(&txn_res->cond, TX_WAIT_INTERVEL);
}

void drc_local_txn_recyle(xid_t *xid)
{
    drc_res_bucket_t *bucket;
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_txn_res_t *txn_res;

    bucket = drc_get_res_map_bucket(&ctx->local_txn_map, (char*)xid, sizeof(xid_t));

    cm_spin_lock(&bucket->lock, NULL);
    txn_res = (drc_txn_res_t*)drc_res_map_lookup(&ctx->local_txn_map, bucket, (char*)xid);
    if (NULL == txn_res) {
        cm_spin_unlock(&bucket->lock);
        return;
    }

    drc_res_map_remove(&ctx->local_txn_map, bucket, (char*)xid);
    drc_release_local_txn_res(txn_res);
    cm_spin_unlock(&bucket->lock);
    return;
}

void drc_local_txn_awake(xid_t *xid)
{
    drc_res_bucket_t *bucket;
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_txn_res_t *txn_res;

    bucket = drc_get_res_map_bucket(&ctx->local_txn_map, (char*)xid, sizeof(xid_t));

    cm_spin_lock(&bucket->lock, NULL);
    txn_res = (drc_txn_res_t*)drc_res_map_lookup(&ctx->local_txn_map, bucket, (char*)xid);
    if (NULL == txn_res) {
        //knl_panic(0);
        DTC_DRC_DEBUG_ERR("[DRC]awake local txn fail, txn does not exist:txn %llu", xid->value);
        cm_spin_unlock(&bucket->lock);
        return;
    }

    cm_release_cond(&txn_res->cond);
    cm_spin_unlock(&bucket->lock);
    return;
}

status_t drc_scaleout_remaster(uint8* new_id_array, uint8 new_num, drc_part_mngr_t *part_mngr)
{
    uint32 i;
    uint32 inst_num;
    uint32 avg_part_num;
    uint32 remain_part;

    if (0 == new_num) {
        return CT_SUCCESS;
    }

    for (i = 0; i < new_num; i++) {
        if (CT_TRUE == part_mngr->inst_part_tbl[new_id_array[i]].is_used) {
            knl_panic_log(0, "[DRC]add new node error, this node exists already");
            return CT_ERROR;
        }
    }

    inst_num = new_num + part_mngr->inst_num;

    avg_part_num = DRC_MAX_PART_NUM / inst_num;
    remain_part = DRC_MAX_PART_NUM % inst_num;

    drc_inst_part_t *inst_part_entry = part_mngr->remaster_mngr.target_inst_part_tbl;

    for (i = 0; i < new_num; i++) {
        inst_part_entry[new_id_array[i]].is_used = CT_TRUE;
        inst_part_entry[new_id_array[i]].count = 0;
    }

    uint32 loop = 0;
    uint32 inst_loop_seq = 0;

    for (i = 0; i < CT_MAX_INSTANCES; i++) {
        if (CT_TRUE == inst_part_entry[i].is_used) {
            if (inst_loop_seq < remain_part) {
                inst_part_entry[i].expected_num = avg_part_num + 1;
            } else {
                inst_part_entry[i].expected_num = avg_part_num;
            }
            inst_loop_seq++;

            if (inst_part_entry[i].count > inst_part_entry[i].expected_num) {
                uint16 current = inst_part_entry[i].first;
                uint32 mgrt_num = inst_part_entry[i].count - inst_part_entry[i].expected_num;

                for (loop = 0; loop < mgrt_num; loop++) {
                    part_mngr->remaster_mngr.remaster_task_set[part_mngr->remaster_mngr.task_num].part_id = current;
                    part_mngr->remaster_mngr.remaster_task_set[part_mngr->remaster_mngr.task_num].export_inst = i;
                    current = part_mngr->remaster_mngr.target_part_map[current].next;
                    part_mngr->remaster_mngr.task_num++;
                }
                inst_part_entry[i].first = current;
                inst_part_entry[i].count = inst_part_entry[i].expected_num;
            }
        }
    }

    loop = 0;
    uint16 part_id = 0;
    for (i = 0; i < part_mngr->remaster_mngr.task_num; i++) {
        if (inst_part_entry[new_id_array[loop]].count >= inst_part_entry[new_id_array[loop]].expected_num) {
            loop++;
        }

        part_mngr->remaster_mngr.remaster_task_set[i].import_inst = new_id_array[loop];
        part_mngr->remaster_mngr.remaster_task_set[i].status = PART_WAIT_MIGRATE;

        part_id = part_mngr->remaster_mngr.remaster_task_set[i].part_id;

        part_mngr->remaster_mngr.target_part_map[part_id].inst_id = new_id_array[loop];
        part_mngr->remaster_mngr.target_part_map[part_id].status = PART_WAIT_MIGRATE;
        part_mngr->remaster_mngr.target_part_map[part_id].next = inst_part_entry[new_id_array[loop]].first;
        inst_part_entry[new_id_array[loop]].first = part_id;
        if (0 == inst_part_entry[new_id_array[loop]].count) {
            inst_part_entry[new_id_array[loop]].last = part_id;
        }
        inst_part_entry[new_id_array[loop]].count++;
    }

    part_mngr->inst_num = inst_num;

    return CT_SUCCESS;
}

status_t drc_scalein_remaster(uint8 *delete_id_array, uint8 delete_num, drc_part_mngr_t *part_mngr, bool32 is_abort)
{
    uint32 i;
    uint32 inst_num;
    uint32 avg_part_num;
    uint32 remain_part;

    if ((0 == delete_num) || (delete_num >= part_mngr->inst_num)) {
        knl_panic_log(0, "[DRC]scalein remaster info is invalid delete_num[%d] inst_num[%d]", delete_num,
                      part_mngr->inst_num);
        return CT_ERROR;
    }

    for (i = 0; i < delete_num; i++) {
        if (CT_FALSE == part_mngr->inst_part_tbl[delete_id_array[i]].is_used) {
            knl_panic_log(0, "[DRC]scalein remaster info is invalid as delete_num[%d] has already been scaled in",
                          delete_num);
            return CT_ERROR;
        }
    }
    inst_num = part_mngr->inst_num - delete_num;

    avg_part_num = DRC_MAX_PART_NUM / inst_num;
    remain_part = DRC_MAX_PART_NUM % inst_num;

    drc_inst_part_t *inst_part_entry = part_mngr->remaster_mngr.target_inst_part_tbl;

    for (i = 0; i < delete_num; i++) {
        inst_part_entry[delete_id_array[i]].is_used = CT_FALSE;
        inst_part_entry[delete_id_array[i]].expected_num = 0;
    }

    uint32 start_task_num = part_mngr->remaster_mngr.task_num;
    uint32 inst_loop_seq = 0;
    uint32 loop = 0;
    for (i = 0; i < CT_MAX_INSTANCES; i++) {
        if (CT_TRUE == inst_part_entry[i].is_used) {
            if (inst_loop_seq < remain_part) {
                inst_part_entry[i].expected_num = avg_part_num + 1;
            } else {
                inst_part_entry[i].expected_num = avg_part_num;
            }
            inst_loop_seq++;
        } else {
            if (inst_part_entry[i].count > 0) {
                uint32 mgrt_num = inst_part_entry[i].count;
                uint16 current = inst_part_entry[i].first;
                for (loop = 0; loop < mgrt_num; loop++) {
                    part_mngr->remaster_mngr.remaster_task_set[part_mngr->remaster_mngr.task_num].part_id = current;
                    part_mngr->remaster_mngr.remaster_task_set[part_mngr->remaster_mngr.task_num].export_inst = i;
                    current = part_mngr->part_map[current].next;
                    part_mngr->remaster_mngr.task_num++;
                }
                inst_part_entry[i].count = 0;
            }
        }
    }

    loop = 0;
    uint16 part_id = 0;
    for (i = start_task_num; i < part_mngr->remaster_mngr.task_num; i++) {
        while ((CT_FALSE == inst_part_entry[loop].is_used) ||
               (inst_part_entry[loop].count >= inst_part_entry[loop].expected_num)) {
            loop++;
        }

        part_mngr->remaster_mngr.remaster_task_set[i].import_inst = loop;
        part_mngr->remaster_mngr.remaster_task_set[i].status = (is_abort == CT_FALSE) ? PART_WAIT_MIGRATE
                                                                                      : PART_WAIT_RECOVERY;

        part_id = part_mngr->remaster_mngr.remaster_task_set[i].part_id;
        part_mngr->remaster_mngr.target_part_map[part_id].inst_id = loop;
        part_mngr->remaster_mngr.target_part_map[part_id].status = (is_abort == CT_FALSE) ? PART_WAIT_MIGRATE
                                                                                          : PART_WAIT_RECOVERY;
        part_mngr->remaster_mngr.target_part_map[part_id].next = inst_part_entry[loop].first;
        inst_part_entry[loop].first = part_id;
        if (0 == inst_part_entry[loop].count) {
            inst_part_entry[loop].last = part_id;
        }
        inst_part_entry[loop].count++;
    }

    part_mngr->inst_num = inst_num;

    if (is_abort) {
        part_mngr->remaster_mngr.task_num = start_task_num; /* no migrate for abort inst */
    }

    return CT_SUCCESS;
}

static inline void drc_init_res_master_msg(knl_session_t *session, drc_res_master_msg_t *msg,
                                           drc_remaster_task_t *remaster_task, uint8 res_type)
{
    mes_init_send_head(&msg->head, MES_CMD_MGRT_MASTER_DATA, msg->head.size, CT_INVALID_ID32, session->kernel->id,
                       remaster_task->import_inst, session->id, CT_INVALID_ID16);
    msg->part_id = remaster_task->part_id;
    msg->res_num = 0;
    msg->is_part_end = CT_FALSE;
    msg->res_type = res_type;
    msg->reform_trigger_version = CT_INVALID_ID64;
}

void drc_set_le_msg(uint8 *le_msg_addr, uint32 le_num, drc_lock_item_t *converting, drc_lock_q_t *convert_q)
{
    uint32 loop;
    drc_lock_item_t *le = NULL;
    drc_le_msg_t *le_msg = NULL;
    drc_res_ctx_t *ctx = DRC_RES_CTX;

    for (loop = 0; loop < le_num; loop++) {
        le_msg = (drc_le_msg_t*)((uint8*)le_msg_addr + loop * sizeof(drc_le_msg_t));
        if (0 == loop) {
            le = converting;
        } else {
            if (1 == loop) {
                le = (drc_lock_item_t*)DRC_GET_RES_ADDR_BY_ID(&ctx->lock_item_pool, convert_q->first);
            } else {
                le = (drc_lock_item_t*)DRC_GET_RES_ADDR_BY_ID(&ctx->lock_item_pool, le->next);
            }
        }
        le_msg->inst_id = le->req_info.inst_id;
        le_msg->inst_sid = le->req_info.inst_sid;
        le_msg->mode = le->req_info.req_mode;
    }
}

void drc_get_le_msg(uint8 *le_msg_addr, uint32 q_num, drc_lock_q_t *convert_q)
{
    uint32 loop;
    uint32 le_idx;
    drc_le_msg_t *le_msg = NULL;
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_lock_item_t *lock_item = NULL;

    for (loop = 0; loop < q_num; loop++) {
        le_msg = (drc_le_msg_t*)(le_msg_addr + loop * sizeof(drc_le_msg_t));

        le_idx = drc_res_pool_alloc_item(&ctx->lock_item_pool);
        if (CT_INVALID_ID32 == le_idx) {
            CT_LOG_RUN_ERR("[DRC][get le msg]le_idx is invalid");
            return;
        }

        lock_item = (drc_lock_item_t*)DRC_GET_RES_ADDR_BY_ID((&ctx->lock_item_pool), le_idx);
        DRC_LE_SET(lock_item, le_msg->inst_id, le_msg->mode, le_msg->inst_sid, CT_INVALID_ID32);

        if (convert_q->count == 0) {
            convert_q->first = le_idx;
            convert_q->last = le_idx;
        } else {
            drc_lock_item_t *tail = (drc_lock_item_t*)DRC_GET_RES_ADDR_BY_ID((&ctx->lock_item_pool), convert_q->last);
            tail->next = le_idx;
            convert_q->last = le_idx;
        }
        convert_q->count++;
    }
}

status_t drc_mes_send_data_with_retry(const char *msg, uint64 interval, uint64 retry_time)
{
    const mes_message_head_t *head = (const mes_message_head_t *)msg;
    uint8 dst_inst = head->dst_inst;
    if (dst_inst >= CT_MAX_INSTANCES) {
        CT_LOG_RUN_ERR("[DRC] The dst instance(%u) is invalid.", dst_inst);
        return CT_ERROR;
    }
    uint64 alive_bitmap = 0;
    uint64 retry = 0;
    while (retry < retry_time) {
        if (mes_send_data(msg) == CT_SUCCESS) {
            return CT_SUCCESS;
        }
        cluster_view_t view;
        rc_get_cluster_view4reform(&view);
        alive_bitmap = view.bitmap;
        CT_LOG_RUN_WAR("[DRC] mes send data failed, cmd(%u), cluster view for reform(%llu), retry",
                       head->cmd, alive_bitmap);
        if (!rc_bitmap64_exist(&alive_bitmap, dst_inst)) {
            CT_LOG_RUN_ERR("[DRC] The dst instance(%u) is not alive(%llu).", dst_inst, alive_bitmap);
            return CT_ERROR;
        }
        cm_sleep(interval);
        retry++;
    }
    CT_LOG_RUN_ERR("[DRC] Failed to send message(%u --> %u).", head->src_inst, dst_inst);
    return CT_ERROR;
}

status_t drc_notify_remaster_status(knl_session_t *session, drc_remaster_status_e remaster_status)
{
    drc_remaster_status_notify_t msg;
    drc_part_mngr_t *part_mngr = DRC_PART_MNGR;
    drc_remaster_mngr_t *remaster_mngr = DRC_PART_REMASTER_MNGR;
    uint8 remaster_id = part_mngr->remaster_inst;
    uint8 self_id = DRC_SELF_INST_ID;

    if (remaster_id == self_id) {
        remaster_mngr->inst_drm_info[self_id].remaster_status = remaster_status;
        return CT_SUCCESS;
    }

    mes_init_send_head(&msg.head, MES_CMD_NOTIFY_REMASTER_STATUS, sizeof(drc_remaster_status_notify_t), CT_INVALID_ID32,
                       self_id, remaster_id, session->id, CT_INVALID_ID16);
    msg.remaster_status = remaster_status;
    msg.reform_trigger_version = remaster_mngr->reform_info.trigger_version;
    if (drc_mes_send_data_with_retry((const char*)&msg, REMASTER_SLEEP_INTERVAL, REMASTER_SEND_MSG_RETRY_TIMES) !=
        CT_SUCCESS) {
        CT_LOG_RUN_ERR("[DRC]send remaster status notification fail,myid:%u", self_id);
        return CT_ERROR;
    }
    CT_LOG_RUN_INF("[DRC] inst(%u) send remaster status notification", self_id);
    return CT_SUCCESS;
}

void drc_process_remaster_status_notify(void *sess, mes_message_t *receive_msg)
{
    drc_part_mngr_t *part_mngr = DRC_PART_MNGR;
    drc_remaster_mngr_t *remaster_mngr = DRC_PART_REMASTER_MNGR;
    if (sizeof(drc_remaster_status_notify_t) != receive_msg->head->size) {
        CT_LOG_RUN_ERR("msg is invalid, msg size %u.", receive_msg->head->size);
        mes_release_message_buf(receive_msg->buffer);
        return;
    }
    drc_remaster_status_notify_t *msg = (drc_remaster_status_notify_t*)receive_msg->buffer;
    uint8 src_id = receive_msg->head->src_inst;

    if (g_rc_ctx->status >= REFORM_RECOVER_DONE || g_rc_ctx->status < REFORM_FROZEN ||
        msg->reform_trigger_version != remaster_mngr->reform_info.trigger_version) {
        CT_LOG_RUN_WAR("[DRC] master(%u) get inst(%u) notify remaster status(%u), local reform trigger version(%llu), "
                       "reform trigger verion(%llu) in msg, remaster status(%u), reform status(%u)",
                       remaster_mngr->reform_info.master_id, receive_msg->head->src_inst, msg->remaster_status,
                       remaster_mngr->reform_info.trigger_version, msg->reform_trigger_version,
                       part_mngr->remaster_status, g_rc_ctx->status);
        mes_release_message_buf(receive_msg->buffer);
        return;
    }

    if (src_id >= CT_MAX_INSTANCES) {
        CT_LOG_RUN_ERR("drc_process_remaster_status_notify failed, invalid src_id %u", src_id);
        mes_release_message_buf(receive_msg->buffer);
        return;
    }

    if (remaster_mngr->inst_drm_info[src_id].remaster_status != msg->remaster_status) {
        remaster_mngr->inst_drm_info[src_id].remaster_status = msg->remaster_status;
    }
    if (msg->remaster_status == REMASTER_FAIL) {
        drc_update_remaster_local_status(REMASTER_FAIL);
    }

    CT_LOG_RUN_INF("[DRC] master(%u) get inst(%u) notify remaster status(%u), local reform trigger version(%llu), msg "
                   "reform trigger version(%llu)", remaster_mngr->reform_info.master_id,
                   receive_msg->head->src_inst, msg->remaster_status, remaster_mngr->reform_info.trigger_version,
                   msg->reform_trigger_version);
    mes_release_message_buf(receive_msg->buffer);
}

status_t drc_send_remaster_task_msg(knl_session_t *session, void* body, uint32 task_num, uint8 src_inst, uint8 dest_inst)
{
    drc_remaster_mngr_t *remaster_mngr = DRC_PART_REMASTER_MNGR;

    if (src_inst == dest_inst) {
        return CT_SUCCESS;
    }

    uint8 *msg_buf = (uint8*)cm_push(session->stack, MES_MESSAGE_BUFFER_SIZE);
    drc_remaster_task_msg_t *msg_head = (drc_remaster_task_msg_t*)msg_buf;
    uint32 offset = sizeof(drc_remaster_task_msg_t);

    mes_init_send_head(&msg_head->head, MES_CMD_DRC_REMASTER_TASK, 0, CT_INVALID_ID32, src_inst, dest_inst, session->id,
                       CT_INVALID_ID16);
    msg_head->task_num = task_num;
    msg_head->task_buffer_len = task_num * sizeof(drc_remaster_task_t);
    msg_head->reform_trigger_version = remaster_mngr->reform_info.trigger_version;

    uint8 *cur_addr = (uint8*)(msg_buf + offset);

    // copy target_part_map
    uint32 part_size = DRC_MAX_PART_NUM * sizeof(drc_part_t);
    status_t ret = memcpy_s(cur_addr, part_size, (uint8*)remaster_mngr->target_part_map, part_size);
    knl_securec_check(ret);

    offset += part_size;
    cur_addr = (uint8*)(msg_buf + offset);

    // copy target_inst_part_tbl
    uint32 inst_part_size = CT_MAX_INSTANCES * sizeof(drc_inst_part_t);
    ret = memcpy_s(cur_addr, inst_part_size, (uint8*)remaster_mngr->target_inst_part_tbl, inst_part_size);
    knl_securec_check(ret);

    offset += inst_part_size;
    cur_addr = (uint8*)(msg_buf + offset);

    // copy remaster_task_set
    uint32 remaster_task_set_size = DRC_MAX_PART_NUM * sizeof(drc_remaster_task_t);
    ret = memcpy_s(cur_addr, remaster_task_set_size, (uint8*)remaster_mngr->remaster_task_set, remaster_task_set_size);
    knl_securec_check(ret);

    offset += remaster_task_set_size;
    cur_addr = (uint8*)(msg_buf + offset);

    // copy export task, send to export inst[copy to local_task_set in dst node]
    if (task_num > 0) {
        uint32 task_size = sizeof(drc_remaster_task_t) * task_num;
        ret = memcpy_s(cur_addr, task_size, body, task_size);
        knl_securec_check(ret);

        offset += task_size;
    }

    msg_head->head.size = offset;
    SYNC_POINT_GLOBAL_START(CANTIAN_REMASTER_SEND_TASK_FAIL, &ret, CT_ERROR);
    ret = drc_mes_send_data_with_retry((const char*)msg_buf, REMASTER_SLEEP_INTERVAL, REMASTER_SEND_MSG_RETRY_TIMES);
    SYNC_POINT_GLOBAL_END;
    if (ret != CT_SUCCESS) {
        cm_pop(session->stack);
        return ret;
    }
    mes_message_t msg;
    if (mes_recv_no_quick_stop(session->id, &msg, CT_FALSE, CT_INVALID_ID32, REMASTER_ASSIGN_TASK_TIMEOUT) !=
        CT_SUCCESS) {
        cm_pop(session->stack);
        return CT_ERROR;
    }
    mes_release_message_buf(msg.buffer);
    cm_pop(session->stack);
    CT_LOG_RUN_RET_INFO(ret, "[DRC] send remaster task msg to instance(%u) by instance(%u), task num(%u), reform "
                        "version(%llu)", dest_inst, src_inst, task_num, msg_head->reform_trigger_version);
    return ret;
}

static inline uint8 drc_get_task_owner(drc_remaster_task_t *task)
{
    if (task->status == PART_WAIT_MIGRATE) {
        return task->export_inst;
    } else {
        return task->import_inst;
    }
}

status_t drc_assign_remaster_task(knl_session_t *session, drc_remaster_mngr_t *remaster_mngr)
{
    uint32 i;
    uint32 inst_part_num;
    uint8 cur_inst;
    status_t ret;
    void *body = NULL;
    uint8 src_inst = DRC_SELF_INST_ID;
    uint32 cur_pos;

    if (remaster_mngr->task_num > 0) {
        bool32 is_self = CT_FALSE;

        cur_inst = remaster_mngr->remaster_task_set[0].export_inst;
        cur_pos = 0;
        inst_part_num = 1;

        is_self = (cur_inst == src_inst) ? CT_TRUE : CT_FALSE;

        for (i = 1; i < remaster_mngr->task_num; i++) {
            if (cur_inst != remaster_mngr->remaster_task_set[i].export_inst) {
                if (CT_FALSE == is_self) {
                    body = (void *)&remaster_mngr->remaster_task_set[cur_pos];
                    ret = drc_send_remaster_task_msg(session, body, inst_part_num, src_inst, cur_inst);
                    if (ret != CT_SUCCESS) {
                        CT_LOG_RUN_ERR("[DRC]send assign task msg fail,return:%u,source id:%u,destination id:%u", ret,
                                       src_inst, cur_inst);
                        return ret;
                    }
                    remaster_mngr->inst_drm_info[cur_inst].task_num = inst_part_num;
                } else {
                    remaster_mngr->local_task_set[remaster_mngr->local_task_num] =
                        remaster_mngr->remaster_task_set[cur_pos];
                    remaster_mngr->local_task_num++;
                }

                cur_pos += inst_part_num;
                //cur_inst = remaster_mngr->remaster_task_set[i].export_inst;
                cur_inst = remaster_mngr->remaster_task_set[i].export_inst;
                is_self = (cur_inst == src_inst) ? CT_TRUE : CT_FALSE;
                inst_part_num = 1;
            } else {
                if (is_self) {
                    remaster_mngr->local_task_set[remaster_mngr->local_task_num] =
                        remaster_mngr->remaster_task_set[cur_pos];
                    remaster_mngr->local_task_num++;
                    // cur_inst = remaster_mngr->remaster_task_set[i].export_inst;
                    cur_inst = remaster_mngr->remaster_task_set[i].export_inst;
                    cur_pos += inst_part_num;
                    inst_part_num = 1;
                } else {
                    inst_part_num++;
                }
            }
        }

        if (CT_FALSE == is_self) {
            body = (void *)&remaster_mngr->remaster_task_set[cur_pos];
            ret = drc_send_remaster_task_msg(session, body, inst_part_num, src_inst, cur_inst);
            if (ret != CT_SUCCESS) {
                CT_LOG_RUN_ERR("[DRC]send assign task msg fail,return:%u,source id:%u,destination id:%u", ret, src_inst,
                               cur_inst);
                return ret;
            }
            remaster_mngr->inst_drm_info[cur_inst].task_num = inst_part_num;
        } else {
            remaster_mngr->local_task_set[remaster_mngr->local_task_num] = remaster_mngr->remaster_task_set[cur_pos];
            remaster_mngr->local_task_num++;
        }
    }
    remaster_mngr->inst_drm_info[src_inst].task_num = remaster_mngr->local_task_num;

    uint8 *inst_id_list = RC_REFORM_LIST((&remaster_mngr->reform_info), REFORM_LIST_AFTER).inst_id_list;
    for (i = 0; i < RC_REFORM_LIST_COUNT((&remaster_mngr->reform_info), REFORM_LIST_AFTER); i++) {
        if (0 == remaster_mngr->inst_drm_info[inst_id_list[i]].task_num) {
            ret = drc_send_remaster_task_msg(session, NULL, 0, src_inst, inst_id_list[i]);
            if (ret != CT_SUCCESS) {
                CT_LOG_RUN_ERR("[DRC]send assign task msg fail,return:%u,source id:%u,destination id:%u", ret, src_inst,
                               inst_id_list[i]);
                return ret;
            }
        }
    }

    inst_id_list = RC_REFORM_LIST((&remaster_mngr->reform_info), REFORM_LIST_LEAVE).inst_id_list;
    for (i = 0; i < RC_REFORM_LIST_COUNT((&remaster_mngr->reform_info), REFORM_LIST_LEAVE); i++) {
        if (0 == remaster_mngr->inst_drm_info[inst_id_list[i]].task_num) {
            ret = drc_send_remaster_task_msg(session, NULL, 0, src_inst, inst_id_list[i]);
            if (ret != CT_SUCCESS) {
                CT_LOG_RUN_ERR("[DRC]send assign task msg fail,return:%u,source id:%u,destination id:%u", ret, src_inst,
                               inst_id_list[i]);
                return ret;
            }
        }
    }

    return CT_SUCCESS;
}

status_t drc_accept_remaster_task_parameter_check(drc_remaster_task_msg_t *msg)
{
    drc_part_mngr_t *part_mngr = DRC_PART_MNGR;
    drc_remaster_mngr_t *remaster_mngr = DRC_PART_REMASTER_MNGR;
    if (part_mngr->remaster_status == REMASTER_DONE || g_rc_ctx->status >= REFORM_RECOVER_DONE ||
        g_rc_ctx->status < REFORM_FROZEN || msg->task_buffer_len != msg->task_num * sizeof(drc_remaster_task_t) ||
        msg->reform_trigger_version != remaster_mngr->reform_info.trigger_version || msg->task_num > DRC_MAX_PART_NUM) {
        CT_LOG_RUN_ERR("[DRC] receive master task, task num(%u), task buffer len(%u), msg reform version(%llu), local "
                       "reform trigger verions(%llu), remaster status(%u), reform status(%u)", msg->task_num,
                       msg->task_buffer_len, msg->reform_trigger_version, remaster_mngr->reform_info.trigger_version,
                       part_mngr->remaster_status, g_rc_ctx->status);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static void drc_accept_remaster_task_ack(void *sess, mes_message_t *msg)
{
    mes_message_head_t ack_head;
    status_t ret = CT_SUCCESS;
    knl_session_t *session = (knl_session_t *)sess;
    mes_init_ack_head(msg->head, &ack_head, MES_CMD_ACCEPT_REMASTER_TASK_ACK, sizeof(mes_message_head_t), session->id);
    ack_head.status = CT_SUCCESS;
    mes_release_message_buf(msg->buffer);
    ret = drc_mes_send_data_with_retry((const char *)&ack_head, REMASTER_SLEEP_INTERVAL, REMASTER_SEND_MSG_RETRY_TIMES);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[DRC] accept remaster task send ack failed");
    }
}

static status_t drc_check_accept_remaster_task_msg(mes_message_t * msg)
{
    if (sizeof(drc_remaster_task_msg_t) > msg->head->size) {
        return CT_ERROR;
    }
    drc_remaster_task_msg_t *request = (drc_remaster_task_msg_t *)msg->buffer;
    uint32 part_size = DRC_MAX_PART_NUM * sizeof(drc_part_t);
    uint32 remaster_task_set_size = DRC_MAX_PART_NUM * sizeof(drc_remaster_task_t);
    uint32 inst_part_size = CT_MAX_INSTANCES * sizeof(drc_inst_part_t);
    if ((sizeof(drc_remaster_task_msg_t) + part_size + remaster_task_set_size + inst_part_size +
        request->task_num * sizeof(drc_remaster_task_t)) != msg->head->size) {
        CT_LOG_RUN_ERR("msg is invalid, msg size %u.", msg->head->size);
        return CT_ERROR;
    }
    if (drc_accept_remaster_task_parameter_check(request) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[DRC] instance(%u) accept remaster task parameter check failed", DRC_SELF_INST_ID);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

void drc_accept_remaster_task(void *sess, mes_message_t *msg)
{
    drc_part_mngr_t *part_mngr = DRC_PART_MNGR;
    drc_remaster_mngr_t *remaster_mngr = DRC_PART_REMASTER_MNGR;
    uint32 part_size = DRC_MAX_PART_NUM * sizeof(drc_part_t);
    uint32 inst_part_size = CT_MAX_INSTANCES * sizeof(drc_inst_part_t);
    uint32 remaster_task_set_size = DRC_MAX_PART_NUM * sizeof(drc_remaster_task_t);
    uint32 offset = sizeof(drc_remaster_task_msg_t);
    status_t ret;

    if (drc_check_accept_remaster_task_msg(msg) != CT_SUCCESS) {
        mes_release_message_buf(msg->buffer);
        return;
    }
    drc_remaster_task_msg_t *msg_head = (drc_remaster_task_msg_t *)(msg->buffer);
    cm_spin_lock(&remaster_mngr->lock, NULL);
    remaster_mngr->local_task_num = msg_head->task_num;
    if (part_mngr->remaster_status != REMASTER_ASSIGN_TASK) {
        cm_spin_unlock(&remaster_mngr->lock);
        CT_LOG_RUN_INF("[DRC] remaster status(%u) is not expected, do not update", part_mngr->remaster_status);
        drc_accept_remaster_task_ack(sess, msg);
        return;
    }
    drc_update_remaster_local_status(REMASTER_MIGRATE);

    uint32 task_size = msg_head->task_num * sizeof(drc_remaster_task_t);
    offset += part_size;
    offset += inst_part_size;
    uint8 *cur_addr = (uint8*)(msg->buffer + offset);
    // copy remaster_task_set to remaster_mngr->remaster_task_set
    ret = memcpy_s((uint8*)remaster_mngr->remaster_task_set, remaster_task_set_size, cur_addr, remaster_task_set_size);
    knl_securec_check(ret);

    if (0 == msg_head->task_num) {
        cm_spin_unlock(&remaster_mngr->lock);
        CT_LOG_RUN_INF("[DRC] instance(%u) accept remaster task, task num(%u), msg reform version(%llu), local reform "
                       "version(%llu)", DRC_SELF_INST_ID, msg_head->task_num, msg_head->reform_trigger_version,
                       remaster_mngr->reform_info.trigger_version);
        drc_accept_remaster_task_ack(sess, msg);
        return;
    }

    // local_task_set update, self id is the export inst
    offset += remaster_task_set_size;
    cur_addr = (uint8*)(msg->buffer + offset);
    ret = memcpy_s((uint8*)remaster_mngr->local_task_set, task_size, cur_addr, task_size);
    knl_securec_check(ret);
    cm_spin_unlock(&remaster_mngr->lock);

    CT_LOG_RUN_INF("[DRC] instance(%u) accept remaster task, task num(%u), msg reform version(%llu), local reform "
                   "version(%llu)", DRC_SELF_INST_ID, msg_head->task_num, msg_head->reform_trigger_version,
                   remaster_mngr->reform_info.trigger_version);
    drc_accept_remaster_task_ack(sess, msg);
}

status_t drc_remaster_task_ack(uint32 id, status_t task_status)
{
    drc_remaster_task_ack_t msg;
    drc_part_mngr_t *part_mngr = DRC_PART_MNGR;
    drc_remaster_mngr_t *remaster_mngr = DRC_PART_REMASTER_MNGR;
    uint8 remaster_id = part_mngr->remaster_inst;

    if (DRC_SELF_INST_ID == remaster_id) {
        cm_atomic_inc(&remaster_mngr->complete_num);
        drc_master_update_inst_remaster_status(remaster_id, REMASTER_PUBLISH);
        return CT_SUCCESS;
    }
    mes_init_send_head(&msg.head, MES_CMD_DRC_REMASTER_TASK_ACK, sizeof(drc_remaster_task_ack_t), CT_INVALID_ID32,
                       DRC_SELF_INST_ID, remaster_id, id, CT_INVALID_ID16);
    msg.task_status = task_status;
    msg.reform_trigger_version = remaster_mngr->reform_info.trigger_version;

    if (drc_mes_send_data_with_retry((const char*)&msg, REMASTER_SLEEP_INTERVAL, REMASTER_SEND_MSG_RETRY_TIMES) !=
        CT_SUCCESS) {
        CT_LOG_RUN_ERR("[DRC] inst(%u) send remaster task ack failed, remaster status(%u), reform version(%llu)",
            DRC_SELF_INST_ID, part_mngr->remaster_status, remaster_mngr->reform_info.trigger_version);
        return CT_ERROR;
    }
    CT_LOG_RUN_INF("[DRC] inst(%u) send remaster task ack successfully, remaster status(%u), reform version(%llu)",
                   DRC_SELF_INST_ID, part_mngr->remaster_status, remaster_mngr->reform_info.trigger_version);
    return CT_SUCCESS;
}

void drc_process_remaster_task_ack(void *sess, mes_message_t *receive_msg)
{
    drc_part_mngr_t *part_mngr = DRC_PART_MNGR;
    drc_remaster_mngr_t *remaster_mngr = DRC_PART_REMASTER_MNGR;
    if (sizeof(drc_remaster_task_ack_t) != receive_msg->head->size) {
        CT_LOG_RUN_ERR("msg is invalid, msg size %u.", receive_msg->head->size);
        mes_release_message_buf(receive_msg->buffer);
        return;
    }
    drc_remaster_task_ack_t *msg = (drc_remaster_task_ack_t*)receive_msg->buffer;
    if (part_mngr->remaster_status == REMASTER_DONE || g_rc_ctx->status < REFORM_FROZEN ||
        g_rc_ctx->status >= REFORM_RECOVER_DONE || msg->head.src_inst > g_dtc->profile.node_count ||
        msg->reform_trigger_version != remaster_mngr->reform_info.trigger_version) {
        CT_LOG_RUN_ERR("[DRC] receive instance(%u) task ack, task status(%u), msg reform version(%llu), local reform "
                       "version(%llu), remaster status(%u), reform status(%u)", msg->head.src_inst,  msg->task_status,
                       msg->reform_trigger_version, remaster_mngr->reform_info.trigger_version,
                       part_mngr->remaster_status, g_rc_ctx->status);
        mes_release_message_buf(receive_msg->buffer);
        return;
    }

    if (CT_SUCCESS == msg->task_status &&
        remaster_mngr->inst_drm_info[msg->head.src_inst].remaster_status != REMASTER_PUBLISH) {
        cm_atomic_inc(&remaster_mngr->complete_num);
        drc_master_update_inst_remaster_status(msg->head.src_inst, REMASTER_PUBLISH);
    }

    CT_LOG_RUN_INF("[DRC] receive instance(%u) task ack successfully, task status(%u), msg reform version(%llu), local"
                   " reform version(%llu)", DRC_SELF_INST_ID, msg->task_status, msg->reform_trigger_version,
                   remaster_mngr->reform_info.trigger_version);
    mes_release_message_buf(receive_msg->buffer);
}

// send the migrate part end message after the final migrate res
status_t drc_send_mgrt_part_end(uint32 id, drc_res_master_msg_t *msg, uint32 buf_res_cnt, uint32 lock_res_cnt)
{
    uint32 rsn;
    uint32 offset = sizeof(drc_res_master_msg_t);

    DRC_MGRT_MSG_SET_RES_CNT(msg, offset, buf_res_cnt, lock_res_cnt);

    DTC_DRC_DEBUG_INF("[DRC] send end of migration message, part id:%u, buff res num:%u, lock res num:%u", msg->part_id,
                      buf_res_cnt, lock_res_cnt);

    rsn = mes_get_rsn(id);
    msg->head.rsn = rsn;
    msg->head.size = offset;
    msg->res_num = 0;
    msg->is_part_end = CT_TRUE;
    return drc_mes_send_data_with_retry((const char*)msg, REMASTER_SLEEP_INTERVAL, REMASTER_SEND_MSG_RETRY_TIMES);
}

void drc_update_remaster_task_status(uint32 part_id, uint8 status, uint8 export_inst)
{
    drc_remaster_mngr_t *remaster_mngr = DRC_PART_REMASTER_MNGR;
    uint32 i;

    for (i = 0; i < DRC_MAX_PART_NUM; i++) {
        if (remaster_mngr->remaster_task_set[i].part_id == part_id &&
            remaster_mngr->remaster_task_set[i].export_inst == export_inst &&
            remaster_mngr->remaster_task_set[i].import_inst == DRC_SELF_INST_ID) {
            remaster_mngr->remaster_task_set[i].status = status;
            break;
        }
    }
    return;
}

void remaster_part_proc(thread_t *thread)
{
    drc_remaster_mngr_t *remaster_mngr = DRC_PART_REMASTER_MNGR;
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    rc_part_info_t *part_info = NULL;
    drc_list_t *buf_res_list = NULL;
    drc_list_t *lock_res_list = NULL;
    uint32_t part_id;

    while (!thread->closed) {
        // wait all migrate res end
        for (uint32_t i = 0; i < DRC_MAX_PART_NUM; i++) {
            if (!((remaster_mngr->remaster_task_set[i].import_inst == DRC_SELF_INST_ID) &&
                remaster_mngr->remaster_task_set[i].export_inst != DRC_SELF_INST_ID)) {
                continue;
            }
            if (remaster_mngr->remaster_task_set[i].status != PART_MIGRATING) {
                continue;
            }
            part_id = remaster_mngr->remaster_task_set[i].part_id;
            part_info = &remaster_mngr->mgrt_part_info[part_id];
            buf_res_list = &ctx->global_buf_res.res_parts[part_id];
            lock_res_list = &ctx->global_lock_res.res_parts[part_id];
            CT_LOG_DEBUG_INF(
                "[DRC] part id(%u) wait for the end of immigration, target buf res num(%u), cur buf res num(%u), "
                "target lock res num(%u), cur lock res num(%u), migrate status(%u)",
                part_id, part_info->res_cnt[DRC_MGRT_RES_PAGE_TYPE], buf_res_list->count,
                part_info->res_cnt[DRC_MGRT_RES_LOCK_TYPE], lock_res_list->count,
                remaster_mngr->remaster_task_set[part_id].status);

            if (part_info->res_cnt[DRC_MGRT_RES_PAGE_TYPE] != buf_res_list->count ||
                part_info->res_cnt[DRC_MGRT_RES_LOCK_TYPE] != lock_res_list->count) {
                CT_LOG_DEBUG_WAR(
                    "[DRC] part id(%u) immigration unfinished, target buf res num(%u), cur buf res num(%u), "
                    "target lock res num(%u), cur lock res num(%u)",
                    part_id, part_info->res_cnt[DRC_MGRT_RES_PAGE_TYPE], buf_res_list->count,
                    part_info->res_cnt[DRC_MGRT_RES_LOCK_TYPE], lock_res_list->count);
                cm_sleep(DRC_WAIT_MGRT_END_SLEEP_TIME);
            } else {
                drc_update_remaster_task_status(part_id, PART_MIGRATE_COMPLETE, part_info->src_inst);
                CT_LOG_RUN_INF(
                    "[DRC] part id(%u) end of resource immigration, target buf res num(%u), cur buf res num(%u)"
                    ", target lock res num(%u), cur lock res num(%u), status (%u)",
                    part_id, part_info->res_cnt[DRC_MGRT_RES_PAGE_TYPE], buf_res_list->count,
                    part_info->res_cnt[DRC_MGRT_RES_LOCK_TYPE], lock_res_list->count, remaster_mngr->remaster_task_set[part_id].status);
            }
        }
    }
}

status_t drc_process_mgrt_part_end(uint32 id, drc_res_master_msg_t *msg, uint32 part_id, uint32 offset)
{
    drc_remaster_mngr_t *remaster_mngr = DRC_PART_REMASTER_MNGR;

    DRC_MGRT_MSG_GET_RES_CNT(msg, offset, remaster_mngr->mgrt_part_info[part_id].res_cnt[DRC_MGRT_RES_PAGE_TYPE], remaster_mngr->mgrt_part_info[part_id].res_cnt[DRC_MGRT_RES_LOCK_TYPE]);
    remaster_mngr->mgrt_part_info[part_id].src_inst = msg->head.src_inst;
    drc_update_remaster_task_status(part_id, PART_MIGRATING, msg->head.src_inst);
    return CT_SUCCESS;
}

status_t drc_send_buf_master_blk(knl_session_t *session, drc_remaster_task_t *remaster_task, uint32 *res_count)
{
    status_t ret;
    uint32 i;
    uint32 id = session->id;
    uint32 msg_sent_cnt = 0;
    drc_remaster_mngr_t *remaster_mngr = DRC_PART_REMASTER_MNGR;
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_res_pool_t* res_pool = &(ctx->global_buf_res.res_map.res_pool);
    drc_global_res_t *g_buf_res = &(ctx->global_buf_res);
    drc_list_t *res_list = &ctx->global_buf_res.res_parts[remaster_task->part_id];
    if (0 == res_list->count) {
        *res_count = 0;
        return CT_SUCCESS;
    }

    drc_res_master_msg_t *msg = (drc_res_master_msg_t *)malloc(MES_MESSAGE_BUFFER_SIZE);
    if (msg == NULL) {
        return CT_ERROR;
    }
    error_t status = memset_sp(msg, MES_MESSAGE_BUFFER_SIZE, 0, MES_MESSAGE_BUFFER_SIZE);
    knl_securec_check(status);

    drc_init_res_master_msg(session, msg, remaster_task, DRC_RES_PAGE_TYPE);

    drc_buf_res_t *buf_res = NULL;
    drc_buf_res_msg_t *res_msg = NULL;
    uint32 le_num = 0;
    uint32 offset = sizeof(drc_res_master_msg_t);
    cm_spin_lock(&g_buf_res->res_part_stat_lock[remaster_task->part_id], NULL);
    uint32 buf_idx = res_list->first;
    *res_count = res_list->count;
    msg->reform_trigger_version = remaster_mngr->reform_info.trigger_version;

    for (i = 0; i < res_list->count; i++) {
        CM_ASSERT(buf_idx != CT_INVALID_ID32);
        buf_res = (drc_buf_res_t*)DRC_GET_RES_ADDR_BY_ID(res_pool, buf_idx);
        while (buf_res->converting.req_info.inst_id != CT_INVALID_ID8) {
            DTC_DRC_DEBUG_INF("[DRC][%u-%u]: migrate buf res, waitting for converting",
                              buf_res->page_id.file, buf_res->page_id.page);
            cm_sleep(3);
        }

        le_num = (CT_INVALID_ID8 == buf_res->converting.req_info.inst_id) ? 0 : (1 + buf_res->convert_q.count);
        if ((offset + sizeof(drc_buf_res_msg_t) + sizeof(drc_le_msg_t) * le_num) > MES_MESSAGE_BUFFER_SIZE) {
            //send current msg, then reset the msg packt
            msg->head.size = offset;
            SYNC_POINT_GLOBAL_START(CANTIAN_REMASTER_SEND_MIGRATE_BUF_RES_FAIL, &ret, CT_ERROR);
            ret = drc_mes_send_data_with_retry((const char*)msg, REMASTER_SLEEP_INTERVAL,
                                               REMASTER_SEND_MSG_RETRY_TIMES);
            SYNC_POINT_GLOBAL_END;
            if (ret != CT_SUCCESS) {
                CT_LOG_RUN_ERR("[DRC] send buf res from inst(%u) to inst(%u), ret(%u)",
                               DRC_SELF_INST_ID, remaster_task->import_inst, ret);
                cm_spin_unlock(&g_buf_res->res_part_stat_lock[remaster_task->part_id]);
                free(msg);
                return ret;
            }
            CT_LOG_DEBUG_INF("[DRC] send buf res from inst(%u) to inst(%u), msg size(%u), part id(%u), res num(%u), "
                "rsn(%u), res list count(%u)", DRC_SELF_INST_ID, remaster_task->import_inst, msg->head.size,
                remaster_task->part_id, msg->res_num, msg->head.rsn, res_list->count);
            offset = sizeof(drc_res_master_msg_t);
            msg->res_num = 0;
            msg->head.rsn = mes_get_rsn(id);
            msg_sent_cnt++;
        }
        res_msg = (drc_buf_res_msg_t*)((uint8*)msg + offset);
        res_msg->claimed_owner = buf_res->claimed_owner;
        res_msg->edp_map = buf_res->edp_map;
        res_msg->readonly_copies = buf_res->readonly_copies;
        res_msg->latest_edp = buf_res->latest_edp;
        res_msg->latest_edp_lsn = buf_res->latest_edp_lsn;
        res_msg->lsn = buf_res->lsn;
        res_msg->le_num = le_num;
        res_msg->mode = buf_res->mode;
        res_msg->page_id = buf_res->page_id;

        if (le_num > 0) {
            drc_set_le_msg((uint8 *)res_msg + sizeof(drc_buf_res_msg_t), le_num, &buf_res->converting, &buf_res->convert_q);
        }

        offset += sizeof(drc_buf_res_msg_t) + sizeof(drc_le_msg_t) * le_num;
        msg->res_num++;
        buf_idx = buf_res->node.next;
    }
    cm_spin_unlock(&g_buf_res->res_part_stat_lock[remaster_task->part_id]);

    msg->head.size = offset;
    msg->is_part_end = CT_FALSE;
    SYNC_POINT_GLOBAL_START(CANTIAN_REMASTER_SEND_MIGRATE_BUF_RES_FAIL, &ret, CT_ERROR);
    ret = drc_mes_send_data_with_retry((const void*)msg, REMASTER_SLEEP_INTERVAL, REMASTER_SEND_MSG_RETRY_TIMES);
    SYNC_POINT_GLOBAL_END;
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[DRC] send buf res from inst(%u) to inst(%u), ret(%u)",
                       DRC_SELF_INST_ID, remaster_task->import_inst, ret);
        free(msg);
        return ret;
    }
    msg_sent_cnt++;
    cm_atomic_add(&ctx->stat.mig_buf_msg_sent_cnt, msg_sent_cnt);
    CT_LOG_DEBUG_INF("[DRC] send buf res from inst(%u) to inst(%u), msg size(%u), part id(%u), res num(%u), rsn(%u), "
        "res list count(%u)", DRC_SELF_INST_ID, remaster_task->import_inst, msg->head.size,
        remaster_task->part_id, msg->res_num, msg->head.rsn, res_list->count);
    free(msg);
    cm_atomic_add(&ctx->stat.mig_buf_cnt, (int64)res_list->count);
    return CT_SUCCESS;
}

static void drc_init_buf_res(drc_buf_res_t *buf_res, drc_buf_res_msg_t *res_msg, uint32 id)
{
    uint32 le_num = res_msg->le_num;

    buf_res->claimed_owner = res_msg->claimed_owner;
    buf_res->mode = res_msg->mode;
    buf_res->page_id = res_msg->page_id;
    buf_res->latest_edp = res_msg->latest_edp;
    buf_res->latest_edp_lsn = res_msg->latest_edp_lsn;
    buf_res->lsn = res_msg->lsn;
    buf_res->edp_map = res_msg->edp_map;
    buf_res->readonly_copies = res_msg->readonly_copies;
    buf_res->idx = id;
    buf_res->pending = DRC_RES_INVALID_ACTION;
    buf_res->is_used = CT_TRUE;
    buf_res->lock = 0;
    buf_res->part_id = drc_page_partid(buf_res->page_id);
    buf_res->node.idx = id;
    if (0 == le_num) {
        DRC_LE_SET(&buf_res->converting, CT_INVALID_ID8, DRC_LOCK_NULL, CT_INVALID_ID16, CT_INVALID_ID32);
        DRC_LIST_INIT(&buf_res->convert_q);
    } else {
        drc_le_msg_t *le_msg = (drc_le_msg_t*)((uint8*)res_msg + sizeof(drc_buf_res_msg_t));
        DRC_LE_SET(&buf_res->converting, le_msg->inst_id, le_msg->mode, le_msg->inst_sid, CT_INVALID_ID32);

        if (le_num > 1) {
            le_msg = (drc_le_msg_t*)((uint8 *)le_msg + sizeof(drc_le_msg_t));
            drc_get_le_msg((uint8 *)le_msg, le_num - 1, &buf_res->convert_q);
        }
    }
}

status_t drc_check_migrate_buf_res_info(drc_buf_res_t *buf_res, drc_buf_res_msg_t *res_msg)
{
    if (buf_res->claimed_owner != res_msg->claimed_owner || buf_res->mode != res_msg->mode ||
        buf_res->latest_edp != res_msg->latest_edp || buf_res->latest_edp_lsn != res_msg->latest_edp_lsn ||
        buf_res->lsn != res_msg->lsn || buf_res->edp_map != res_msg->edp_map ||
        buf_res->readonly_copies != res_msg->readonly_copies) {
        CT_LOG_RUN_ERR("[DRC] remaster migrate buf_res failed, buf_res->claimed_owner(%d), "
            "res_msg->claimed_owner(%d); buf_res->mode(%d), res_msg->mode(%d); buf_res->latest_edp(%d), "
            "res_msg->latest_edp(%d); buf_res->latest_edp_lsn(%llu), res_msg->latest_edp_lsn(%llu); "
            "buf_res->lsn(%llu), res_msg->lsn(%llu); buf_res->edp_map(%llu), res_msg->edp_map(%llu); "
            "buf_res->readonly_copies(%llu), res_msg->readonly_copies(%llu)",
            buf_res->claimed_owner, res_msg->claimed_owner, buf_res->mode, res_msg->mode, buf_res->latest_edp,
            res_msg->latest_edp, buf_res->latest_edp_lsn, res_msg->latest_edp_lsn, buf_res->lsn, res_msg->lsn,
            buf_res->edp_map, res_msg->edp_map, buf_res->readonly_copies, res_msg->readonly_copies);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t drc_migrate_buf_res_l(drc_res_pool_t* res_pool, mes_message_t *msg, uint32* idx,
    uint32 res_num, uint32 *real_add_res_num)
{
    drc_res_master_msg_t *msg_blk = (drc_res_master_msg_t*)msg->buffer;
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_res_map_t* res_map = &(ctx->global_buf_res.res_map);
    drc_list_t* res_parts = ctx->global_buf_res.res_parts;
    spinlock_t* res_part_lock = ctx->global_buf_res.res_part_lock;
    drc_global_res_t *g_buf_res = &(ctx->global_buf_res);
    uint32 offset = sizeof(drc_res_master_msg_t);
    uint16 part_id = msg_blk->part_id;
    for (uint32 i = 0; i < res_num; i++) {
        CM_ASSERT(offset <= msg_blk->head.size);

        drc_buf_res_msg_t *res_msg = (drc_buf_res_msg_t*)((uint8*)msg->buffer + offset);
        page_id_t page_id = res_msg->page_id;
        part_id = drc_page_partid(page_id);

        drc_res_bucket_t *bucket = drc_get_buf_map_bucket(res_map, page_id.file, page_id.page);
        cm_spin_lock(&g_buf_res->res_part_stat_lock[part_id], NULL);
        cm_spin_lock(&bucket->lock, NULL);

        drc_buf_res_t *buf_res = (drc_buf_res_t *)drc_res_map_lookup(&ctx->global_buf_res.res_map,
                                                                     bucket, (char*)&page_id);
        if (buf_res != NULL) {
            if (drc_check_migrate_buf_res_info(buf_res, res_msg) == CT_ERROR) {
                cm_spin_unlock(&bucket->lock);
                cm_spin_unlock(&g_buf_res->res_part_stat_lock[part_id]);
                return CT_ERROR;
            }
            CT_LOG_DEBUG_INF("[DRC][%u-%u] buf res is exist, skip migration", page_id.file, page_id.page);
            drc_res_pool_free_item(res_pool, idx[i]);    // free alloced res
        } else {
            buf_res = (drc_buf_res_t*)DRC_GET_RES_ADDR_BY_ID(res_pool, idx[i]);
            drc_init_buf_res(buf_res, res_msg, idx[i]);
            drc_res_map_add(bucket, idx[i], &buf_res->next);

            drc_list_t *list = &res_parts[buf_res->part_id];
            spinlock_t *lock = &res_part_lock[buf_res->part_id];
            drc_list_node_t *head = NULL;

            cm_spin_lock(lock, NULL);
            if (list->count != 0) {
                drc_buf_res_t *head_buf = (drc_buf_res_t*)DRC_GET_RES_ADDR_BY_ID(res_pool, list->first);
                head = &head_buf->node;
            }
            drc_add_list_node(list, &buf_res->node, head);
            cm_spin_unlock(lock);
            (*real_add_res_num)++;
        }

        cm_spin_unlock(&bucket->lock);
        cm_spin_unlock(&g_buf_res->res_part_stat_lock[part_id]);
        offset += sizeof(drc_buf_res_msg_t) + res_msg->le_num * sizeof(drc_le_msg_t);
    }
    CT_LOG_DEBUG_INF("[DRC] immigrate res finished, part id(%u), buf res num(%u)", part_id, res_parts[part_id].count);

    return CT_SUCCESS;
}

status_t drc_process_buf_master_blk(mes_message_t *msg)
{
    drc_res_master_msg_t *msg_blk = (drc_res_master_msg_t*)msg->buffer;
    uint32 res_num = msg_blk->res_num;
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_res_map_t* res_map = &(ctx->global_buf_res.res_map);
    drc_res_pool_t* res_pool = &(res_map->res_pool);
    drc_remaster_mngr_t *remaster_mngr = DRC_PART_REMASTER_MNGR;
    uint32 real_add_res_num = 0;

    CT_LOG_DEBUG_INF("[DRC] start process buf res immigration, msg size(%u), part id(%u), res num(%u), part end(%u), "
        "rsn(%u)",
        msg->head->size, msg_blk->part_id, res_num, msg_blk->is_part_end, msg->head->rsn);

    if (msg_blk->res_num > REMASTER_MIG_MAX_BUF_RES_NUM || msg_blk->part_id >= DRC_MAX_PART_NUM ||
        msg_blk->reform_trigger_version != remaster_mngr->reform_info.trigger_version) {
        CT_LOG_RUN_ERR("[DRC] immigrate buf res num(%u), max immigrate buf res num(%lu), part id(%u), msg reform "
                       "trigger version(%llu), local reform trigger version(%llu)", msg_blk->res_num,
                       REMASTER_MIG_MAX_BUF_RES_NUM, msg_blk->part_id, msg_blk->reform_trigger_version,
                       remaster_mngr->reform_info.trigger_version);
        return CT_ERROR;
    }

    // if msg has no more res,mark the partition imigration finished
    if (res_num == 0) {
        return CT_SUCCESS;
    }

    uint32* idx = (uint32*)cm_malloc(sizeof(uint32) * res_num);
    if (idx == NULL) {
        return CT_ERROR;
    }
    status_t status = drc_res_pool_alloc_batch_item(res_pool, idx, res_num);
    if (status != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[DRC]Alloc batch item failed, num(%u).", res_num);
        cm_free(idx);
        return CT_ERROR;
    }

    status = drc_migrate_buf_res_l(res_pool, msg, idx, res_num, &real_add_res_num);
    if (status != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[DRC]migrate buf res failed.");
        cm_free(idx);
        return CT_ERROR;
    }
    cm_atomic32_add(&(remaster_mngr->mgrt_part_res_cnt[msg_blk->part_id].res_cnt[DRC_MGRT_RES_PAGE_TYPE]),
                    real_add_res_num);
    cm_free(idx);
    CT_LOG_DEBUG_INF("[DRC] finish process buf res immigration, msg size(%u), rsn(%u), part id(%u), res num(%u), real "
        "add res num(%u), part end(%u), part migrated res cnt(%u)",
        msg->head->size, msg->head->rsn, msg_blk->part_id, res_num, real_add_res_num, msg_blk->is_part_end,
        remaster_mngr->mgrt_part_res_cnt[msg_blk->part_id].res_cnt[DRC_MGRT_RES_PAGE_TYPE]);
    return CT_SUCCESS;
}

status_t drc_send_lock_master_blk(knl_session_t *session, drc_remaster_task_t *remaster_task, uint32 buf_res_cnt,
                                  uint32 *lock_res_cnt)
{
    status_t ret;
    uint32 i;
    drc_list_t *res_list = NULL;
    uint32 msg_sent_cnt = 0;
    drc_remaster_mngr_t *remaster_mngr = DRC_PART_REMASTER_MNGR;
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_res_pool_t* res_pool = &(ctx->global_lock_res.res_map.res_pool);
    uint32 id = session->id;
    spinlock_t *res_part_stat_lock = NULL;

    CT_LOG_DEBUG_INF("[DRC] inst(%u) migrate lock res start, part id:%u", DRC_SELF_INST_ID, remaster_task->part_id);

    drc_res_master_msg_t *msg = (drc_res_master_msg_t *)malloc(MES_MESSAGE_BUFFER_SIZE);
    if (msg == NULL) {
        return CT_ERROR;
    }
    error_t status = memset_sp(msg, MES_MESSAGE_BUFFER_SIZE, 0, MES_MESSAGE_BUFFER_SIZE);
    knl_securec_check(status);

    drc_init_res_master_msg(session, msg, remaster_task, DRC_RES_LOCK_TYPE);
    msg->reform_trigger_version = remaster_mngr->reform_info.trigger_version;

    res_list = &ctx->global_lock_res.res_parts[remaster_task->part_id];
    res_part_stat_lock = &ctx->global_lock_res.res_part_stat_lock[remaster_task->part_id];
    drc_master_res_t *lock_res = NULL;
    drc_lock_res_msg_t *res_msg;
    uint32 le_num = 0;
    uint32 offset = sizeof(drc_res_master_msg_t);
    cm_spin_lock(res_part_stat_lock, NULL);
    if (res_list->count > 0) {
        lock_res = (drc_master_res_t*)DRC_GET_RES_ADDR_BY_ID(res_pool, res_list->first);
    }

    for (i = 0; i < res_list->count; i++) {
        while (lock_res->converting.req_info.inst_id != CT_INVALID_ID8) {
            DTC_DRC_DEBUG_INF("[DRC][%u-%u]: migrate lock res, waitting for converting", lock_res->res_id.type, lock_res->res_id.id);
            cm_sleep(3);
        }

        le_num = (lock_res->converting.req_info.inst_id == CT_INVALID_ID8) ? 0 : (1 + lock_res->convert_q.count);
        if ((offset + sizeof(drc_lock_res_msg_t) + sizeof(drc_le_msg_t) * le_num) > MES_MESSAGE_BUFFER_SIZE) {
            //send current msg, then reset the msg pack
            msg->head.size = offset;
            msg->head.rsn = mes_get_rsn(id);
            SYNC_POINT_GLOBAL_START(CANTIAN_REMASTER_SEND_MIGRATE_LOCK_RES_FAIL, &ret, CT_ERROR);
            ret = drc_mes_send_data_with_retry((const char*)msg, REMASTER_SLEEP_INTERVAL,
                                               REMASTER_SEND_MSG_RETRY_TIMES);
            SYNC_POINT_GLOBAL_END;
            if (ret != CT_SUCCESS) {
                CT_LOG_RUN_ERR("[DRC] migrate lock res from inst(%u) to inst(%u), ret(%u)",
                               DRC_SELF_INST_ID, remaster_task->import_inst, ret);
                cm_spin_unlock(res_part_stat_lock);
                free(msg);
                return ret;
            }
            CT_LOG_DEBUG_INF("[DRC] migrate lock res from inst(%u) to inst(%u), msg size(%u), part id(%u), res num(%u)"
                "rsn(%u), res list count(%u)",
                DRC_SELF_INST_ID, remaster_task->import_inst, msg->head.size, remaster_task->part_id, msg->res_num,
                msg->head.rsn, res_list->count);
            offset = sizeof(drc_res_master_msg_t);
            msg->res_num = 0;
            msg_sent_cnt++;
        }
        res_msg = (drc_lock_res_msg_t*)((uint8*)msg + offset);
        res_msg->granted_map = lock_res->granted_map;
        res_msg->le_num = (lock_res->converting.req_info.inst_id == CT_INVALID_ID8) ? 0
                                                                                    : (1 + lock_res->convert_q.count);
        res_msg->mode = lock_res->mode;
        res_msg->res_id = lock_res->res_id;

        if (le_num > 0) {
            drc_set_le_msg((uint8 *)res_msg + sizeof(drc_lock_res_msg_t), le_num, &lock_res->converting,
                           &lock_res->convert_q);
        }

        DTC_DRC_DEBUG_INF("[DRC]send lock res[%u-%u-%u-%u-%u-%u] to inst[%u], lock mode[%u],"
            " granted[%llu], partid[%u], le_num[%u].",
            lock_res->res_id.type, lock_res->res_id.id, lock_res->res_id.uid, lock_res->res_id.idx,
            lock_res->res_id.part, lock_res->res_id.parentpart, remaster_task->import_inst, lock_res->mode,
            lock_res->granted_map, lock_res->part_id, le_num);

        offset += sizeof(drc_lock_res_msg_t) + sizeof(drc_le_msg_t) * le_num;
        msg->res_num++;
        lock_res = (drc_master_res_t*)DRC_GET_RES_ADDR_BY_ID(res_pool, lock_res->node.next);
    }
    cm_spin_unlock(res_part_stat_lock);

    if ((offset + sizeof(uint32) + sizeof(uint32)) <= MES_MESSAGE_BUFFER_SIZE) {
        DTC_DRC_DEBUG_INF(
            "[DRC] last message by the way send end of migration message, part id:%u, buff res num:%u, lock res num:%u",
            remaster_task->part_id, buf_res_cnt, res_list->count);

        // carry res count with final msg
        DRC_MGRT_MSG_SET_RES_CNT(msg, offset, buf_res_cnt, res_list->count);

        msg->head.rsn = mes_get_rsn(id);
        msg->head.size = offset;
        msg->is_part_end = CT_TRUE;
        SYNC_POINT_GLOBAL_START(CANTIAN_REMASTER_SEND_MIGRATE_LOCK_RES_FAIL, &ret, CT_ERROR);
        ret = drc_mes_send_data_with_retry((const char*)msg, REMASTER_SLEEP_INTERVAL, REMASTER_SEND_MSG_RETRY_TIMES);
        SYNC_POINT_GLOBAL_END;
        if (ret != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[DRC]send lock master info by instance(%u),return error:%u", DRC_SELF_INST_ID, ret);
            free(msg);
            return ret;
        }
        msg_sent_cnt++;
        CT_LOG_DEBUG_INF(
            "[DRC] migrate lock res from inst(%u) to inst(%u), msg size(%u), part id(%u), res num(%u), part"
            " end(%u), rsn(%u), res list count(%u)",
            DRC_SELF_INST_ID, remaster_task->import_inst, msg->head.size, remaster_task->part_id, msg->res_num,
            msg->is_part_end, msg->head.rsn, res_list->count);
    } else {
        msg->head.rsn = mes_get_rsn(id);
        msg->head.size = offset;
        SYNC_POINT_GLOBAL_START(CANTIAN_REMASTER_SEND_MIGRATE_LOCK_RES_FAIL, &ret, CT_ERROR);
        ret = drc_mes_send_data_with_retry((const char*)msg, REMASTER_SLEEP_INTERVAL, REMASTER_SEND_MSG_RETRY_TIMES);
        SYNC_POINT_GLOBAL_END;
        if (ret != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[DRC] migrate lock res from inst(%u) to inst(%u), ret(%u)",
                           DRC_SELF_INST_ID, remaster_task->import_inst, ret);
            free(msg);
            return ret;
        }
        msg_sent_cnt++;
        CT_LOG_DEBUG_INF("[DRC] migrate lock res from inst(%u) to inst(%u), msg size(%u), part id(%u), res num(%u), "
            "rsn(%u), res list count(%u)", DRC_SELF_INST_ID, remaster_task->import_inst, msg->head.size,
            remaster_task->part_id, msg->res_num, msg->head.rsn, res_list->count);

        // send the res count
        SYNC_POINT_GLOBAL_START(CANTIAN_REMASTER_SEND_MIGRATE_LOCK_RES_FAIL, &ret, CT_ERROR);
        ret = drc_send_mgrt_part_end(id, msg, buf_res_cnt, res_list->count);
        SYNC_POINT_GLOBAL_END;
        if (ret != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[DRC] migrate lock res end by inst(%u), ret(%u)", DRC_SELF_INST_ID, ret);
            free(msg);
            return ret;
        }
        msg_sent_cnt++;
        CT_LOG_DEBUG_INF("[DRC] migrate lock res from inst(%u) to inst(%u), msg size(%u), part id(%u), res num(%u),"
            " part end(%u), rsn(%u), res list count(%u)", DRC_SELF_INST_ID, remaster_task->import_inst,
            msg->head.size, remaster_task->part_id, msg->res_num, msg->is_part_end, msg->head.rsn, res_list->count);
    }

    *lock_res_cnt = res_list->count;
    free(msg);
    cm_atomic_add(&ctx->stat.mig_lock_cnt, (int64)res_list->count);
    cm_atomic_add(&ctx->stat.mig_buf_cnt, (int64)buf_res_cnt);
    cm_atomic_add(&ctx->stat.mig_lock_msg_sent_cnt, msg_sent_cnt);
    CT_LOG_DEBUG_INF("[DRC] migrate lock res finish, part id(%u), res list lock res num(%u), stack size(%u)",
        remaster_task->part_id, res_list->count, session->stack->size);
    return CT_SUCCESS;
}

void dtc_init_lock_res(drc_master_res_t *lock_res, drc_lock_res_msg_t *res_msg, uint32 id)
{
    drc_le_msg_t *le_msg;
    uint32 le_num = res_msg->le_num;

    lock_res->granted_map = res_msg->granted_map;
    lock_res->mode = res_msg->mode;
    lock_res->res_id = res_msg->res_id;
    lock_res->lock = 0;
    lock_res->idx = id;
    lock_res->next = CT_INVALID_ID32;
    DRC_LIST_INIT(&lock_res->convert_q);

    DTC_DRC_DEBUG_INF("[DRC]recv lock res[%u-%u-%u-%u-%u-%u], lock mode[%u], granted[%llu].",
                      lock_res->res_id.type, lock_res->res_id.id, lock_res->res_id.uid, lock_res->res_id.idx,
                      lock_res->res_id.part, lock_res->res_id.parentpart, lock_res->mode, lock_res->granted_map);

    if (0 == le_num) {
        lock_res->converting.req_info.inst_id = CT_INVALID_ID8;
    } else {
        le_msg = (drc_le_msg_t *)((uint8 *)res_msg + sizeof(drc_lock_res_msg_t));

        DRC_LE_SET(&lock_res->converting, le_msg->inst_id, le_msg->mode, le_msg->inst_sid, CT_INVALID_ID32);

        if (le_num > 1) {
            le_msg = (drc_le_msg_t*)((uint8 *)le_msg + sizeof(drc_le_msg_t));
            drc_get_le_msg((uint8 *)le_msg, le_num - 1, &lock_res->convert_q);
        }
    }
    lock_res->part_id = drc_resource_id_hash((char*)&lock_res->res_id, sizeof(drid_t), DRC_MAX_PART_NUM);
    lock_res->node.idx = id;
}

uint32 drc_migrate_lock_res_l(drc_res_pool_t* res_pool, mes_message_t *msg, uint32* idx, uint32 res_num,
                              uint32 *real_add_res_num)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_res_map_t *res_map = &(ctx->global_lock_res.res_map);
    drc_list_t* res_parts = ctx->global_lock_res.res_parts;
    spinlock_t* res_part_lock = ctx->global_lock_res.res_part_lock;
    drc_res_master_msg_t *msg_blk = (drc_res_master_msg_t*)msg->buffer;
    uint32 offset = sizeof(drc_res_master_msg_t);
    uint32 le_num = 0;
    uint16 part_id = msg_blk->part_id;
    //if resource num is 0, goto send ACK to master directly
    for (uint32 i = 0; i < res_num; i++) {
        CM_ASSERT(offset <= msg_blk->head.size);

        drc_lock_res_msg_t *res_msg = (drc_lock_res_msg_t*)((uint8*)(msg->buffer) + offset);
        drid_t res_id = res_msg->res_id;
        part_id = drc_resource_id_hash((char*)&res_id, sizeof(drid_t), DRC_MAX_PART_NUM);

        drc_res_bucket_t *bucket = drc_get_res_map_bucket(res_map, (char *)&res_id, sizeof(drid_t));
        spinlock_t *res_part_stat_lock = &ctx->global_lock_res.res_part_stat_lock[part_id];
        cm_spin_lock(res_part_stat_lock, NULL);
        cm_spin_lock(&bucket->lock, NULL);

        drc_master_res_t *lock_res = (drc_master_res_t *)drc_res_map_lookup(&ctx->global_lock_res.res_map,
                                                                            bucket, (char *)&res_id);
        if (lock_res != NULL) {
            drc_res_pool_free_item(res_pool, idx[i]);    // free alloced lock res
        } else {
            lock_res = (drc_master_res_t*)DRC_GET_RES_ADDR_BY_ID(res_pool, idx[i]);
            dtc_init_lock_res(lock_res, res_msg, idx[i]);
            drc_res_map_add(bucket, idx[i], &lock_res->next);
            drc_list_t *list = &res_parts[lock_res->part_id];
            spinlock_t *lock = &res_part_lock[lock_res->part_id];
            drc_list_node_t *node = &lock_res->node;
            drc_master_res_t *head_lock = NULL;
            drc_list_node_t *head = NULL;

            cm_spin_lock(lock, NULL);
            if (list->count != 0) {
                head_lock = (drc_master_res_t*)DRC_GET_RES_ADDR_BY_ID(res_pool, list->first);
                head = &head_lock->node;
            }
            drc_add_list_node(list, node, head);
            cm_spin_unlock(lock);
            (*real_add_res_num)++;
        }
        cm_spin_unlock(&bucket->lock);
        cm_spin_unlock(res_part_stat_lock);
        offset += sizeof(drc_lock_res_msg_t) + le_num * sizeof(drc_le_msg_t);
    }

    CT_LOG_DEBUG_INF("[DRC] immigrate res finished, part id(%u), lock res num(%u)", part_id, res_parts[part_id].count);

    return offset;
}

status_t drc_process_lock_master_blk(uint32 id, mes_message_t *msg)
{
    drc_res_master_msg_t *msg_blk = (drc_res_master_msg_t*)msg->buffer;
    uint32 res_num = msg_blk->res_num;
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_res_map_t *res_map = &(ctx->global_lock_res.res_map);
    drc_res_pool_t *res_pool = &(res_map->res_pool);
    drc_remaster_mngr_t *remaster_mngr = DRC_PART_REMASTER_MNGR;
    uint32 real_add_res_num = 0;
    uint32 offset;

    CT_LOG_DEBUG_INF("[DRC] start process lock res immigration, msg size(%u), part id(%u), res num(%u), part end(%u), "
        "rsn(%u)",
        msg->head->size, msg_blk->part_id, res_num, msg_blk->is_part_end, msg->head->rsn);
    if (msg_blk->res_num > REMASTER_MIG_MAX_LOCK_RES_NUM || msg_blk->part_id >= DRC_MAX_PART_NUM ||
        msg_blk->reform_trigger_version != remaster_mngr->reform_info.trigger_version) {
        CT_LOG_RUN_ERR("[DRC] immigrate lock res num(%u) is invalid, max immigrate lock res num(%lu), part id(%u), "
                       "msg reform trigger version(%llu), local reform trigger version(%llu)", msg_blk->res_num,
                       REMASTER_MIG_MAX_LOCK_RES_NUM, msg_blk->part_id, msg_blk->reform_trigger_version,
                       remaster_mngr->reform_info.trigger_version);
        return CT_ERROR;
    }

    uint32* idx = (uint32*)cm_malloc(sizeof(uint32) * res_num);
    if (idx == NULL) {
        CT_LOG_RUN_ERR("[DRC]Malloc idx mem failed! res_num(%u).", res_num);
        return CT_ERROR;
    }
    status_t status = drc_res_pool_alloc_batch_item(res_pool, idx, res_num);
    if (status != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[DRC]Alloc batch item failed,num(%u).", res_num);
        cm_free(idx);
        return CT_ERROR;
    }
    offset = drc_migrate_lock_res_l(res_pool, msg, idx, res_num, &real_add_res_num);
    cm_atomic32_add(&(remaster_mngr->mgrt_part_res_cnt[msg_blk->part_id].res_cnt[DRC_MGRT_RES_LOCK_TYPE]),
                    real_add_res_num);
    cm_free(idx);

    CT_LOG_DEBUG_INF("[DRC] finish process lock res immigration, msg size(%u), rsn(%u), part id(%u), res num(%u), real "
        "add res num(%u), part end(%u), part migrated res cnt(%u)",
        msg->head->size, msg->head->rsn, msg_blk->part_id, res_num, real_add_res_num, msg_blk->is_part_end,
        remaster_mngr->mgrt_part_res_cnt[msg_blk->part_id].res_cnt[DRC_MGRT_RES_LOCK_TYPE]);
    //if msg has no more res,mark the part migration finished
    if (CT_TRUE == msg_blk->is_part_end) {
        return drc_process_mgrt_part_end(id, msg_blk, msg_blk->part_id, offset);
    }

    return CT_SUCCESS;
}

static status_t drc_check_mgrt_data_msg(mes_message_t * msg)
{
    if (sizeof(drc_res_master_msg_t) > msg->head->size) {
        return CT_ERROR;
    }
    drc_res_master_msg_t *request = (drc_res_master_msg_t *)msg->buffer;
    if (request->res_type == DRC_RES_PAGE_TYPE && sizeof(drc_res_master_msg_t) +
        request->res_num * sizeof(drc_buf_res_msg_t) > msg->head->size) {
        return CT_ERROR;
    }
    if (request->res_type == DRC_RES_LOCK_TYPE && sizeof(drc_res_master_msg_t) +
        request->res_num * sizeof(drc_lock_res_msg_t) > msg->head->size) {
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

void drc_process_mgrt_data(void *sess, mes_message_t *receive_msg)
{
    if (drc_check_mgrt_data_msg(receive_msg) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("msg is invalid, msg size %u.", receive_msg->head->size);
        mes_release_message_buf(receive_msg->buffer);
        return;
    }
    drc_res_master_msg_t *msg_blk = (drc_res_master_msg_t*)receive_msg->buffer;
    knl_session_t *session = (knl_session_t *)sess;
    drc_part_mngr_t *part_mngr = DRC_PART_MNGR;
 
    if (part_mngr->remaster_status == REMASTER_DONE || g_rc_ctx->status >= REFORM_RECOVER_DONE ||
        g_rc_ctx->status < REFORM_FROZEN) {
        CT_LOG_RUN_ERR("[DRC] process immigrate data, remaster status(%u), reform status(%u)",
                       part_mngr->remaster_status, g_rc_ctx->status);
        mes_release_message_buf(receive_msg->buffer);
        return;
    }

    switch (msg_blk->res_type) {
        case DRC_RES_PAGE_TYPE:
            drc_process_buf_master_blk(receive_msg);
            break;
        case DRC_RES_LOCK_TYPE:
            drc_process_lock_master_blk(session->id, receive_msg);
            break;
        default:
            break;
    }

    mes_release_message_buf(receive_msg->buffer);
}

void drc_free_buf_res_by_part(drc_list_t *part_list)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_res_bucket_t *bucket;
    drc_buf_res_t *buf_res;
    uint32 buf_idx;
    uint32 i;
    status_t ret;

    if (part_list->count == 0) {
        return;
    }

    uint32* ids = (uint32*)cm_malloc(sizeof(uint32) * part_list->count);
    if (ids == NULL) {
        CT_LOG_RUN_ERR("[DRC]Malloc idx mem failed! res_num(%u).", part_list->count);
        return;
    }
    buf_idx = part_list->first;
    drc_res_map_t* res_map = &ctx->global_buf_res.res_map;
    for (i = 0; i < part_list->count; i++) {
        buf_res = (drc_buf_res_t*)DRC_GET_RES_ADDR_BY_ID(&res_map->res_pool, buf_idx);

        bucket = drc_get_buf_map_bucket(res_map, buf_res->page_id.file, buf_res->page_id.page);

        cm_spin_lock(&bucket->lock, NULL);

        drc_res_map_remove(res_map, bucket, (char*)&buf_res->page_id);
        cm_spin_unlock(&bucket->lock);

        ids[i] = buf_idx;
        buf_idx = buf_res->node.next;
        ret = memset_sp(buf_res, sizeof(drc_buf_res_t), 0, sizeof(drc_buf_res_t));
        knl_securec_check(ret);
    }

    drc_res_pool_free_batch_item(&(res_map->res_pool), ids, part_list->count);
    cm_free(ids);
    DRC_LIST_INIT(part_list);
}

void drc_free_lock_res_by_part(drc_list_t *part_list)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_res_bucket_t *bucket;
    uint32 lock_idx;
    drc_master_res_t *lock_res;
    uint32 i;
    status_t ret;

    if (part_list->count == 0) {
        return;
    }

    uint32* ids = (uint32*)cm_malloc(sizeof(uint32) * part_list->count);
    if (ids == NULL) {
        CT_LOG_RUN_ERR("[DRC]Malloc idx mem failed! res_num(%u).", part_list->count);
        return;
    }

    lock_idx = part_list->first;
    drc_res_map_t* res_map = &ctx->global_lock_res.res_map;
    for (i = 0; i < part_list->count; i++) {
        lock_res = (drc_master_res_t*)DRC_GET_RES_ADDR_BY_ID(&res_map->res_pool, lock_idx);
        bucket = drc_get_res_map_bucket(res_map, (char*)(&lock_res->res_id), sizeof(drid_t));

        cm_spin_lock(&bucket->lock, NULL);
        drc_res_map_remove(res_map, bucket, (char*)&lock_res->res_id);
        cm_spin_unlock(&bucket->lock);

        ids[i] = lock_idx;
        lock_idx = lock_res->node.next;
        ret = memset_sp(lock_res, sizeof(drc_master_res_t), 0, sizeof(drc_master_res_t));
        knl_securec_check(ret);
    }

    drc_res_pool_free_batch_item(&(res_map->res_pool), ids, part_list->count);
    cm_free(ids);
    DRC_LIST_INIT(part_list);
}

static void drc_free_migrated_res_proc(thread_t* thread)
{
    drc_free_mig_res_param_t* param = (drc_free_mig_res_param_t*)(thread->argument);
    drc_remaster_mngr_t *remaster_mngr = param->remaster_mngr;
    drc_global_res_t* buf_res = param->buf_res;
    drc_global_res_t* lock_res = param->lock_res;
    drc_list_t *part_list = NULL;
    uint16 part_id;

    for (uint32 i = param->start_task_idx; i < param->start_task_idx + param->cnt_per_thread; i++) {
        drc_remaster_task_t* remaster_task = &(remaster_mngr->local_task_set[i]);
        if (remaster_task->export_inst != DRC_SELF_INST_ID) {
            continue;
        }
        part_id = remaster_task->part_id;
        
        part_list = &(buf_res->res_parts[part_id]);
        drc_free_buf_res_by_part(part_list);

        part_list = &(lock_res->res_parts[part_id]);
        drc_free_lock_res_by_part(part_list);
    }

    (void)cm_atomic_dec(param->job_num);
    return;
}

void drc_free_migrated_res(void)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_remaster_mngr_t *remaster_mngr = DRC_PART_REMASTER_MNGR;

    uint32 local_task_num = remaster_mngr->local_task_num;
    drc_global_res_t* buf_res = &(ctx->global_buf_res);
    drc_global_res_t* lock_res = &(ctx->global_lock_res);
    
    CT_LOG_RUN_INF("[DRC]drc_free_migrated_res start, local tasks:%u.", local_task_num);
    atomic_t job_num;
    cm_atomic_set(&job_num, (int64)DRC_FREE_MIG_RES_MAX_THREAD_NUM);
    
    thread_t thread[DRC_FREE_MIG_RES_MAX_THREAD_NUM];
    drc_free_mig_res_param_t param[DRC_FREE_MIG_RES_MAX_THREAD_NUM];
    uint32 count_per_thread = local_task_num / DRC_FREE_MIG_RES_MAX_THREAD_NUM;
    for (uint32 i = 0; i < DRC_FREE_MIG_RES_MAX_THREAD_NUM; i++) {
        param[i].start_task_idx = i * count_per_thread;
        param[i].cnt_per_thread = count_per_thread;
        param[i].buf_res       = buf_res;
        param[i].lock_res      = lock_res;
        param[i].remaster_mngr = remaster_mngr;
        param[i].job_num       = &job_num;
        if (i == DRC_FREE_MIG_RES_MAX_THREAD_NUM - 1) {
            param[i].cnt_per_thread += local_task_num % DRC_FREE_MIG_RES_MAX_THREAD_NUM;
        }

        status_t status = cm_create_thread(drc_free_migrated_res_proc, 0, &param[i], &thread[i]);
        if (status != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[DCS]cm_create_thread(%u): failed, task_count=%u", i, count_per_thread);
            cm_atomic_dec(&job_num);
        }
    }

    while (cm_atomic_get(&job_num) != 0) {
        cm_sleep(DRC_FREE_RES_SLEEP_TIME);
    }
    CT_LOG_RUN_INF("[DRC]drc_free_migrated_res finished, local tasks:%u.", local_task_num);
}

status_t drc_broadcast_target_part(knl_session_t *session, status_t status, uint64 alive_bitmap)
{
    drc_remaster_mngr_t *remaster_mngr = DRC_PART_REMASTER_MNGR;
    CT_LOG_RUN_INF("[DRC]master(%d) start broadcast new version of part, alive_bitmap(%llu).", status, alive_bitmap);
    uint8 *msg_buffer = (uint8*)cm_push(session->stack, MES_MESSAGE_BUFFER_SIZE);
    if (NULL == msg_buffer) {
        CT_LOG_RUN_ERR("[DRC] remaster failed to malloc memory");
        return CT_ERROR;
    }

    drc_remaster_target_part_msg_t *msg = (drc_remaster_target_part_msg_t *)msg_buffer;
    mes_message_head_t *head = &msg->head;
    mes_init_send_head(head, MES_CMD_BROADCAST_TARGET_PART, sizeof(drc_remaster_target_part_msg_t), CT_INVALID_ID32,
                       DRC_SELF_INST_ID, 0, session->id, CT_INVALID_ID16);

    msg->status = status;
    msg->reform_trigger_version = remaster_mngr->reform_info.trigger_version;
    if (status != CT_SUCCESS) {
        mes_broadcast(session->id, alive_bitmap, (const void *)msg, NULL);
        cm_pop(session->stack);
        return CT_SUCCESS;
    }
    uint32 part_size = DRC_MAX_PART_NUM * sizeof(drc_part_t);
    uint32 inst_part_size = CT_MAX_INSTANCES * sizeof(drc_inst_part_t);
    status_t ret;
    ret = memcpy_s((uint8*)msg->target_part_map, part_size, (uint8*)remaster_mngr->target_part_map, part_size);
    knl_securec_check(ret);

    ret = memcpy_s((uint8*)msg->target_inst_part_tbl, inst_part_size,
                   (uint8*)remaster_mngr->target_inst_part_tbl, inst_part_size);
    knl_securec_check(ret);
    msg->buffer_len = part_size + inst_part_size;

    // broadcast new version of part
    ret = mes_broadcast_data_and_wait_with_retry(session->id, alive_bitmap, (const void *)msg,
                                                 REMASTER_BROADCAST_TARGET_PART_TIMEOUT, REMASTER_SEND_MSG_RETRY_TIMES);
    CT_LOG_RUN_INF("[DRC]broadcast new version of part finish, ret(%d)", ret);

    cm_pop(session->stack);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[DRC] broadcast new version of part failed, ret=%d.", ret);
        return ret;
    }
    return ret;
}

void drc_get_page_remaster_id(page_id_t pagid, uint8 *id)
{
    uint8  inst_id;
    uint32 part_id;

    part_id = drc_page_partid(pagid);
    inst_id = DRC_PART_REMASTER_ID(part_id);

    *id = inst_id;
}

void drc_get_lock_remaster_id(drid_t *lock_id, uint8 *master_id)
{
    uint16 part_id;

    part_id = drc_resource_id_hash((char*)lock_id, sizeof(drid_t), DRC_MAX_PART_NUM);
    *master_id = DRC_PART_REMASTER_ID(part_id);
}

status_t drc_update_target_part(drc_remaster_target_part_msg_t *msg)
{
    status_t ret;
    uint32 part_size = DRC_MAX_PART_NUM * sizeof(drc_part_t);
    uint32 inst_part_size = CT_MAX_INSTANCES * sizeof(drc_inst_part_t);
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_part_mngr_t *part_mngr = &ctx->part_mngr;

    CT_LOG_RUN_INF("[DRC]remaster get the broadcast target partition, size(%u)", msg->head.size);

    ret = memcpy_s((uint8*)part_mngr->part_map, part_size, (uint8*)msg->target_part_map, part_size);
    knl_securec_check(ret);

    ret = memcpy_s((uint8*)part_mngr->inst_part_tbl, inst_part_size,
                   (uint8*)msg->target_inst_part_tbl, inst_part_size);
    knl_securec_check(ret);

    return ret;
}

status_t drc_accept_target_part_parameter_check(knl_session_t *session, drc_remaster_target_part_msg_t *msg)
{
    mes_message_head_t ack_head = { 0 };
    drc_remaster_mngr_t *remaster_mngr = DRC_PART_REMASTER_MNGR;
    drc_part_mngr_t *part_mngr = DRC_PART_MNGR;
    uint32 target_part_size = DRC_MAX_PART_NUM * sizeof(drc_part_t) + CT_MAX_INSTANCES * sizeof(drc_inst_part_t);
    if (part_mngr->remaster_status == REMASTER_DONE || g_rc_ctx->status >= REFORM_RECOVER_DONE ||
        g_rc_ctx->status < REFORM_FROZEN || msg->buffer_len != target_part_size ||
        msg->reform_trigger_version != remaster_mngr->reform_info.trigger_version) {
        CT_LOG_RUN_ERR("[DRC] receive msg target part buffer len(%u), target part size(%u), msg reform version(%llu), "
                       "local reform version(%llu), remaster status(%u), reform status(%u)", msg->buffer_len,
                       target_part_size, msg->reform_trigger_version, remaster_mngr->reform_info.trigger_version,
                       part_mngr->remaster_status, g_rc_ctx->status);
        mes_init_ack_head(&msg->head, &ack_head, MES_CMD_BROADCAST_ACK, sizeof(mes_message_head_t), session->id);
        ack_head.status = CT_ERROR;
        status_t ret = drc_mes_send_data_with_retry((const char*)&ack_head, REMASTER_SLEEP_INTERVAL,
                                                    REMASTER_SEND_MSG_RETRY_TIMES);
        CT_LOG_RUN_INF("[DRC] send ack to master, ret(%d)", ret);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

void drc_accept_target_part(void *sess, mes_message_t *receive_msg)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_part_mngr_t *part_mngr = &ctx->part_mngr;
    drc_remaster_mngr_t *remaster_mngr = DRC_PART_REMASTER_MNGR;
    mes_message_head_t ack_head = {0};
    knl_session_t *session = (knl_session_t *)sess;
    reform_info_t *reform_info = &remaster_mngr->reform_info;

    CT_LOG_RUN_INF("[DRC] process broadcast target part msg start");
    cm_spin_lock(&part_mngr->lock, NULL);
    if (part_mngr->remaster_status == REMASTER_FAIL) {
        mes_release_message_buf(receive_msg->buffer);
        cm_spin_unlock(&part_mngr->lock);
        CT_LOG_RUN_ERR("[DRC] remaster already failed");
        return;
    }
    cm_spin_unlock(&part_mngr->lock);
    if (sizeof(drc_remaster_target_part_msg_t) != receive_msg->head->size) {
        CT_LOG_RUN_ERR("msg is invalid, msg size %u.", receive_msg->head->size);
        mes_release_message_buf(receive_msg->buffer);
        return;
    }
    drc_remaster_target_part_msg_t *msg = (drc_remaster_target_part_msg_t *)receive_msg->buffer;
    int32 msg_status = msg->status;
    if (msg_status != CT_SUCCESS) {
        drc_update_remaster_local_status(REMASTER_FAIL);
        mes_release_message_buf(receive_msg->buffer);
        CT_LOG_RUN_ERR("[DRC] remaster already failed");
        return;
    }

    if (drc_accept_target_part_parameter_check(session, msg) != CT_SUCCESS) {
        mes_release_message_buf(receive_msg->buffer);
        return;
    }
    
    status_t ret = drc_update_target_part(msg);
    drc_remaster_inst_list(reform_info);

    mes_init_ack_head(&msg->head, &ack_head, MES_CMD_BROADCAST_ACK, sizeof(mes_message_head_t), session->id);
    ack_head.status = ret;
    ret = drc_mes_send_data_with_retry((const char*)&ack_head, REMASTER_SLEEP_INTERVAL, REMASTER_SEND_MSG_RETRY_TIMES);
    CT_LOG_RUN_INF("[DRC] remaster send partition ack, inst_id(%d), sid(%u), dst_inst(%d), dst_sid(%u), "
                   "status(%d), rsn(%u), ret(%d)", ack_head.src_inst, ack_head.src_sid, ack_head.dst_inst,
                   ack_head.dst_sid, ack_head.status, ack_head.rsn, ret);

    mes_release_message_buf(receive_msg->buffer);
    //  collect and send pages info without owner but have edp map to reformer under the multi-node scenario
    return;
}

void drc_accept_remaster_done(void *sess, mes_message_t *receive_msg)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_part_mngr_t *part_mngr = &ctx->part_mngr;
    drc_remaster_mngr_t *remaster_mngr = DRC_PART_REMASTER_MNGR;
    if (sizeof(drc_remaster_status_notify_t) != receive_msg->head->size) {
        CT_LOG_RUN_ERR("msg is invalid, msg size %u.", receive_msg->head->size);
        mes_release_message_buf(receive_msg->buffer);
        return;
    }
    drc_remaster_status_notify_t *msg = (drc_remaster_status_notify_t*)receive_msg->buffer;
    uint8 src_id = receive_msg->head->src_inst;

    CT_LOG_RUN_INF("[DRC] process broadcast remaster done status msg start");
    if (part_mngr->remaster_status == REMASTER_DONE || g_rc_ctx->status >= REFORM_RECOVER_DONE ||
        g_rc_ctx->status < REFORM_FROZEN || msg->reform_trigger_version != remaster_mngr->reform_info.trigger_version) {
        CT_LOG_RUN_WAR("[DRC] receive master(%u) broadcast remaster done msg, msg reform version(%llu), local reform "
                       "version(%llu), remaster status(%u), reform status(%u)", src_id, msg->reform_trigger_version,
                       remaster_mngr->reform_info.trigger_version, part_mngr->remaster_status, g_rc_ctx->status);
        mes_release_message_buf(receive_msg->buffer);
        return;
    }

    cm_spin_lock(&part_mngr->lock, NULL);
    if (part_mngr->remaster_status == REMASTER_FAIL) {
        mes_release_message_buf(receive_msg->buffer);
        cm_spin_unlock(&part_mngr->lock);
        CT_LOG_RUN_ERR("[DRC] remaster already failed");
        return;
    }
    
    if (part_mngr->remaster_status != REMASTER_PUBLISH) {
        mes_release_message_buf(receive_msg->buffer);
        cm_spin_unlock(&part_mngr->lock);
        CT_LOG_RUN_ERR("[DRC] remaster status(%u) is not expected, not update", part_mngr->remaster_status);
        return;
    }
    cm_spin_unlock(&part_mngr->lock);
    drc_update_remaster_local_status(REMASTER_DONE);

    status_t ret = CT_SUCCESS;
    mes_message_head_t ack_head = {0};
    knl_session_t *session = (knl_session_t *)sess;
    mes_init_ack_head(receive_msg->head, &ack_head, MES_CMD_BROADCAST_ACK, sizeof(mes_message_head_t), session->id);
    ack_head.status = ret;
    ret = drc_mes_send_data_with_retry((const char*)&ack_head, REMASTER_SLEEP_INTERVAL, REMASTER_SEND_MSG_RETRY_TIMES);

    CT_LOG_RUN_INF("[DRC] send remaster done ack success, inst_id=%d, sid=%u, dst_inst=%d, dst_sid=%u, status=%d, "
                   "rsn=%u, ret=%d", ack_head.src_inst, ack_head.src_sid, ack_head.dst_inst, ack_head.dst_sid,
                   ack_head.status, ack_head.rsn, ret);

    mes_release_message_buf(receive_msg->buffer);
    return;
}

uint16 drc_get_part_id(drc_part_mngr_t *part_mngr, drc_inst_part_t *inst_part, uint32 start_count, uint32 count,
                       uint16 *tmp_part_id)
{
    uint16 res = (start_count == 0) ? inst_part->first : *tmp_part_id;
    uint16 part_id = res;
    for (uint32 i = 0; i < count; i++) {
        part_id = part_mngr->part_map[part_id].next;
    }
    *tmp_part_id = part_id;
    return res;
}

static void drc_clean_res_owner_proc(thread_t *thread)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_part_mngr_t *part_mngr = DRC_PART_MNGR;
    drc_clean_owner_param_t *param = (drc_clean_owner_param_t *)thread->argument;
    uint32 part_id;
    spinlock_t *res_part_stat_lock = NULL;
    spinlock_t *res_part_stat_lock_buf = NULL;
    part_id = param->start_part_id;
    CT_LOG_RUN_INF("[DRC]instance(%u) thread(%lu) remaster clean owner(%u) start, start_part_id(%u), count_per_thread(%u)",
        DRC_SELF_INST_ID, thread->id, param->inst_id, part_id, param->count_per_thread);

    for (uint32 i = 0; i < param->count_per_thread; i++) {
        if (part_mngr->remaster_status == REMASTER_FAIL) {
            CT_LOG_RUN_ERR("[DRC] remaster already failed");
            break;
        }
        res_part_stat_lock = &ctx->global_lock_res.res_part_stat_lock[part_id];
        cm_spin_lock(res_part_stat_lock, NULL);
        drc_clean_lock_owner_by_part(param->inst_id, &ctx->global_lock_res.res_parts[part_id]);
        cm_spin_unlock(res_part_stat_lock);

        res_part_stat_lock_buf = &ctx->global_buf_res.res_part_stat_lock[part_id];
        cm_spin_lock(res_part_stat_lock_buf, NULL);
        drc_clean_page_owner_by_part(param->inst_id, &ctx->global_buf_res.res_parts[part_id], param->session);
        cm_spin_unlock(res_part_stat_lock_buf);

        part_id = part_mngr->part_map[part_id].next;
    }

    (void)cm_atomic_dec(param->job_num);

    return;
}

void drc_clean_res_owner_by_inst(uint8 inst_id, knl_session_t *session)
{
    atomic_t job_num;
    thread_t thread[DCS_CLEAN_OWNER_MAX_THREAD_NUM];
    drc_clean_owner_param_t param[DCS_CLEAN_OWNER_MAX_THREAD_NUM];
    drc_part_mngr_t *part_mngr = DRC_PART_MNGR;
    drc_inst_part_t *inst_part = &part_mngr->inst_part_tbl[DRC_SELF_INST_ID];

    uint32 count_per_thread = inst_part->count / DCS_CLEAN_OWNER_MAX_THREAD_NUM;
    uint16 tmp_part_id = 0;
    cm_atomic_set(&job_num, (int64)(DCS_CLEAN_OWNER_MAX_THREAD_NUM));
    for (uint32 i = 0; i < DCS_CLEAN_OWNER_MAX_THREAD_NUM; i++) {
        param[i].job_num = &job_num;
        param[i].count_per_thread = count_per_thread;
        param[i].inst_id = inst_id;
        param[i].session = session;
        if (i == DCS_CLEAN_OWNER_MAX_THREAD_NUM - 1) {
            param[i].count_per_thread += inst_part->count % DCS_CLEAN_OWNER_MAX_THREAD_NUM;
        }
        param[i].start_part_id = drc_get_part_id(part_mngr, inst_part, count_per_thread * i,
                                                 param[i].count_per_thread, &tmp_part_id);
        status_t status = cm_create_thread(drc_clean_res_owner_proc, 0, &param[i], &thread[i]);
        if (status != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[DCS]cm_create_thread(%i): failed, inst_id=%u, count=%u",
                i, DRC_SELF_INST_ID, inst_part->count);
            cm_atomic_dec(&job_num);
        }
    }
    while (cm_atomic_get(&job_num) != 0) {
        cm_sleep(DRC_COLLECT_SLEEP_TIME);
    }
    CT_LOG_RUN_INF("[DRC]instance(%u) remaster clean owner(%u) end, count(%u)",
        DRC_SELF_INST_ID, inst_id, inst_part->count);
}

void drc_prepare_remaster(knl_session_t *session, reform_info_t *reform_info)
{
    reform_detail_t *detail = &g_rc_ctx->reform_detail;
    RC_STEP_BEGIN(detail->remaster_prepare_elapsed);
    drc_part_mngr_t *part_mngr = DRC_PART_MNGR;
    drc_remaster_mngr_t *remaster_mngr = DRC_PART_REMASTER_MNGR;
    uint8 self_id = DRC_SELF_INST_ID;

    /**
     * Notify reformer that current node is ready for remaster
     * If successful, change status to REMASTER_ASSIGN_TASK
     * Otherwise, change status to REMASTER_FAIL
     * */
    if (drc_notify_remaster_status(session, REMASTER_ASSIGN_TASK) == CT_SUCCESS) {
        drc_update_remaster_local_status(REMASTER_ASSIGN_TASK);
        CT_LOG_RUN_INF("[DRC] Instance[%u] prepared end, notify status[%u] to reformer[%u] successfully, reform "
                       "trigger version[%llu].", self_id, part_mngr->remaster_status, part_mngr->remaster_inst,
                       remaster_mngr->reform_info.trigger_version);
    } else {
        drc_update_remaster_local_status(REMASTER_FAIL);
        CT_LOG_RUN_ERR("[DRC] Instance[%u] prepared end, notify status to reformer[%u] failed, change status to[%u], "
                       "reform trigger version[%llu].", self_id, part_mngr->remaster_inst, part_mngr->remaster_status,
                       remaster_mngr->reform_info.trigger_version);
    }
    RC_STEP_END(detail->remaster_prepare_elapsed, RC_STEP_FINISH);
}

status_t drc_int_remaster_target(drc_part_mngr_t *part_mngr)
{
    drc_remaster_mngr_t *remaster_mngr = DRC_PART_REMASTER_MNGR;
    status_t ret;
    uint32 inst_part_size = sizeof(drc_inst_part_t) * CT_MAX_INSTANCES;

    ret = memcpy_s((uint8*)remaster_mngr->target_inst_part_tbl, inst_part_size,
                   (uint8*)part_mngr->inst_part_tbl, inst_part_size);
    MEMS_RETURN_IFERR(ret);

    // copy the inst_part_tbl for remaster reentrant, reset when recovery done, together with free migrate res
    ret = memcpy_s((uint8*)remaster_mngr->tmp_inst_part_tbl, inst_part_size,
                   (uint8*)part_mngr->inst_part_tbl, inst_part_size);
    MEMS_RETURN_IFERR(ret);

    uint32 part_size = sizeof(drc_part_t) * DRC_MAX_PART_NUM;
    ret = memcpy_s((uint8*)remaster_mngr->target_part_map, part_size, (uint8*)part_mngr->part_map, part_size);
    MEMS_RETURN_IFERR(ret);

    // copy the part_map for remaster reentrant, reset when recovery done, together with free migrate res
    ret = memcpy_s((uint8*)remaster_mngr->tmp_part_map, part_size, (uint8*)part_mngr->part_map, part_size);
    MEMS_RETURN_IFERR(ret);

    part_mngr->remaster_mngr.task_num = 0;
    part_mngr->remaster_mngr.tmp_part_map_reform_version = g_rc_ctx->info.version;

    return CT_SUCCESS;
}

status_t drc_execute_remaster(knl_session_t *session, reform_info_t *reform_info)
{
    status_t ret;
    drc_part_mngr_t *part_mngr = DRC_PART_MNGR;
    drc_remaster_mngr_t *remaster_mngr = DRC_PART_REMASTER_MNGR;
    CT_LOG_RUN_INF("[DRC]master assigned remaster tasks,jNum(%u),lNum(%u),aNum(%u),fNum(%u).",
        reform_info->reform_list[REFORM_LIST_JOIN].inst_id_count,
        reform_info->reform_list[REFORM_LIST_LEAVE].inst_id_count,
        reform_info->reform_list[REFORM_LIST_ABORT].inst_id_count,
        reform_info->reform_list[REFORM_LIST_FAIL].inst_id_count);

    cm_spin_lock(&part_mngr->lock, NULL);
    ret = drc_int_remaster_target(part_mngr);
    if (ret != CT_SUCCESS) {
        cm_spin_unlock(&part_mngr->lock);
        return ret;
    }

    //step 1:remaster instance rebalance the resource distribution
    if (reform_info->reform_list[REFORM_LIST_JOIN].inst_id_count > 0) {
        ret = drc_scaleout_remaster(reform_info->reform_list[REFORM_LIST_JOIN].inst_id_list, reform_info->reform_list[REFORM_LIST_JOIN].inst_id_count, part_mngr);
        if (ret != CT_SUCCESS) {
            cm_spin_unlock(&part_mngr->lock);
            CT_LOG_RUN_ERR("[DRC]scale out remaster error,return error:%d", ret);
            return ret;
        }
    }

    if (reform_info->reform_list[REFORM_LIST_LEAVE].inst_id_count > 0) {
        ret = drc_scalein_remaster(reform_info->reform_list[REFORM_LIST_LEAVE].inst_id_list, reform_info->reform_list[REFORM_LIST_LEAVE].inst_id_count, part_mngr, CT_FALSE);
        if (ret != CT_SUCCESS) {
            cm_spin_unlock(&part_mngr->lock);
            CT_LOG_RUN_ERR("[DRC]scale in remaster error,return error: %d", ret);
            return ret;
        }
    }

    if (reform_info->reform_list[REFORM_LIST_ABORT].inst_id_count > 0) {
        ret = drc_scalein_remaster(reform_info->reform_list[REFORM_LIST_ABORT].inst_id_list, reform_info->reform_list[REFORM_LIST_ABORT].inst_id_count, part_mngr, CT_TRUE);
        if (ret != CT_SUCCESS) {
            cm_spin_unlock(&part_mngr->lock);
            CT_LOG_RUN_ERR("[DRC]scale in remaster error,return error: %d", ret);
            return ret;
        }
    }

    if (part_mngr->mgrt_fail_list == CT_TRUE && reform_info->reform_list[REFORM_LIST_FAIL].inst_id_count > 0) {
        ret = drc_scalein_remaster(reform_info->reform_list[REFORM_LIST_FAIL].inst_id_list,
                                   reform_info->reform_list[REFORM_LIST_FAIL].inst_id_count, part_mngr, CT_TRUE);
        if (ret != CT_SUCCESS) {
            cm_spin_unlock(&part_mngr->lock);
            CT_LOG_RUN_ERR("[DRC]scale in remaster error,return error: %d", ret);
            return ret;
        }
    }
    cm_spin_unlock(&part_mngr->lock);

    //step 2:remaster instance assign the remaster tasks to others
    ret = drc_assign_remaster_task(session, remaster_mngr);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[DRC]assign remaster task error,return error:%d", ret);
        return ret;
    }

    drc_update_remaster_local_status(REMASTER_MIGRATE);
    part_mngr->remaster_finish_step = REMASTER_ASSIGN_TASK;

    CT_LOG_RUN_INF("[DRC] master assigned remaster tasks,task num[%u], finished step[%u]",
                   remaster_mngr->task_num, part_mngr->remaster_finish_step);

    return CT_SUCCESS;
}

status_t drc_remaster_step_assign_task(knl_session_t *session, reform_info_t *reform_info)
{
    drc_part_mngr_t *part_mngr = DRC_PART_MNGR;
    drc_remaster_mngr_t *remaster_mngr = DRC_PART_REMASTER_MNGR;
    if (remaster_mngr->is_master == CT_FALSE) {
        cm_sleep(REMASTER_SLEEP_INTERVAL);
        return CT_SUCCESS;
    }
    reform_detail_t *detail = &g_rc_ctx->reform_detail;
    RC_STEP_BEGIN(detail->remaster_assign_task_elapsed);
    if (drc_remaster_wait_all_node_ready(reform_info, REMASTER_WAIT_ALL_NODE_READY_TIMEOUT,
        REMASTER_ASSIGN_TASK) != CT_SUCCESS) {
        RC_STEP_END(detail->remaster_assign_task_elapsed, RC_STEP_FAILED);
        return CT_ERROR;
    }
    part_mngr->remaster_finish_step = REMASTER_PREPARE;
    CT_LOG_RUN_INF("[DRC] remaster finished step[%u]", part_mngr->remaster_finish_step);

    status_t ret = drc_execute_remaster(session, reform_info);
    RC_STEP_END(detail->remaster_assign_task_elapsed, RC_STEP_FINISH);
    return ret;
}

status_t drc_migrate_master_blk(knl_session_t *session, drc_remaster_task_t *remaster_task)
{
    status_t ret = CT_SUCCESS;
    uint32 buf_res_cnt = 0;
    uint32 lock_res_cnt = 0;

    CT_LOG_DEBUG_INF("[DRC] remaster migrate buf res start, partId(%u), from (%d) to (%d).", remaster_task->part_id,
        remaster_task->export_inst, remaster_task->import_inst);
    knl_panic(remaster_task->status == PART_WAIT_MIGRATE);
    ret = drc_send_buf_master_blk(session, remaster_task, &buf_res_cnt);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[DRC]send page resource info error,return error:%u, partId(%u), bufResCnt(%u).",
            ret, remaster_task->part_id, buf_res_cnt);
        return ret;
    }
    CT_LOG_DEBUG_INF("[DRC] remaster migrate buf res end, partId(%u), bufResCnt(%u).", remaster_task->part_id,
        buf_res_cnt);

    // The last resource is responsible for sending the end message
    ret = drc_send_lock_master_blk(session, remaster_task, buf_res_cnt, &lock_res_cnt);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[DRC]send lock resource info error,return error:%u, partId(%u), bufResCnt(%u), lockResCnt(%u).",
            ret, remaster_task->part_id, buf_res_cnt, lock_res_cnt);
        return ret;
    }
    CT_LOG_DEBUG_INF("[DRC] remaster migrate lock res end, partId(%u), bufResCnt(%u), lockResCnt(%u).",
        remaster_task->part_id, buf_res_cnt, lock_res_cnt);

    return CT_SUCCESS;
}

static void drc_reset_remaster_stat(drc_stat_t *stat)
{
    cm_atomic_set(&stat->clean_page_cnt, 0);
    cm_atomic_set(&stat->clean_lock_cnt, 0);
    cm_atomic_set(&stat->clean_convert_cnt, 0);
    cm_atomic_set(&stat->rcy_page_cnt, 0);
    cm_atomic_set(&stat->rcy_lock_cnt, 0);
    cm_atomic_set(&stat->mig_buf_cnt, 0);
    cm_atomic_set(&stat->mig_lock_cnt, 0);
}

status_t drc_remaster_wait_migrate_finish(uint64 timeout)
{
    drc_remaster_mngr_t *remaster_mngr = DRC_PART_REMASTER_MNGR;
    drc_part_mngr_t *part_mngr = DRC_PART_MNGR;
    uint32 i;
    uint64 elapsed = 0;

    if (CT_SUCCESS != cm_create_thread(remaster_part_proc, 0, NULL, &remaster_mngr->mgrt_part_thread)) {
        CT_LOG_RUN_ERR("creat remaster_part_proc faild");
        return CT_ERROR;
    }

    for (i = 0; i < DRC_MAX_PART_NUM; i++) {
        while ((remaster_mngr->remaster_task_set[i].import_inst == DRC_SELF_INST_ID) &&
                remaster_mngr->remaster_task_set[i].export_inst != DRC_SELF_INST_ID) {
            if (part_mngr->remaster_status == REMASTER_FAIL) {
                cm_close_thread(&remaster_mngr->mgrt_part_thread);
                CT_LOG_RUN_ERR("[DRC] remaster failed, stop waiting migrate finish.");
                return CT_ERROR;
            }
            if (remaster_mngr->remaster_task_set[i].status == PART_MIGRATE_COMPLETE) {
                CT_LOG_RUN_INF("[DRC] inst(%u) immigrate res of part id(%u) finished, task status(%u), import inst(%u)",
                               DRC_SELF_INST_ID, remaster_mngr->remaster_task_set[i].part_id,
                               remaster_mngr->remaster_task_set[i].status,
                               remaster_mngr->remaster_task_set[i].import_inst);
                break;
            }
            if (elapsed >= timeout) {
                CT_LOG_RUN_ERR("[DRC] inst(%u) wait migrate res finish timeout(%llu/%llu), top waiting.",
                               DRC_SELF_INST_ID, elapsed, timeout);
                cm_close_thread(&remaster_mngr->mgrt_part_thread);
                return CT_ERROR;
            }
            cm_sleep(REMASTER_SLEEP_INTERVAL);
            elapsed += REMASTER_SLEEP_INTERVAL;
        }
    }
    cm_close_thread(&remaster_mngr->mgrt_part_thread);
    return CT_SUCCESS;
}

void drc_remaster_migrate_res(thread_t *thread)
{
    drc_remaster_migrate_param_t *param = (drc_remaster_migrate_param_t *)(thread->argument);
    drc_remaster_mngr_t *remaster_mngr = DRC_PART_REMASTER_MNGR;
    drc_part_mngr_t *part_mngr = DRC_PART_MNGR;
    drc_remaster_task_t *remaster_task = NULL;
    knl_session_t *session = (knl_session_t *)param->session;

    for (uint32 j = param->start; j < param->start + param->count_per_thread; j++) {
        if (part_mngr->remaster_status == REMASTER_FAIL) {
            (void)cm_atomic_dec(param->job_num);
            return;
        }
        remaster_task = &remaster_mngr->local_task_set[j];
        if (drc_migrate_master_blk(session, remaster_task) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[DRC] migrate master blk failed");
            (void)cm_atomic_dec(param->job_num);
            drc_update_remaster_local_status(REMASTER_FAIL);
            return;
        }
        cm_atomic_inc(&remaster_mngr->local_task_complete_num);
    }
    (void)cm_atomic_dec(param->job_num);
    CT_LOG_RUN_INF("[DRC] thread(%lu) finish migrate res, local task start idx(%u), start part id(%u), end idx(%u), "
                   "end part id(%u)", thread->id, param->start, remaster_mngr->local_task_set[param->start].part_id,
                   param->start + param->count_per_thread,
                   remaster_mngr->local_task_set[param->start + param->count_per_thread].part_id);
    return;
}

status_t drc_remaster_migrate(knl_session_t *session)
{
    status_t ret = CT_SUCCESS;
    drc_part_mngr_t *part_mngr = DRC_PART_MNGR;
    drc_remaster_mngr_t *remaster_mngr = DRC_PART_REMASTER_MNGR;
    uint32 local_task_num = remaster_mngr->local_task_num;

    if (local_task_num == 0) {
        CT_LOG_RUN_INF("[DRC] remaster migrate finish, local task num(%u)", local_task_num);
        return CT_SUCCESS;
    }
    atomic_t job_num;
    cm_atomic_set(&job_num, (int64)(DRC_REMASTER_MIGRATE_RES_MAX_THREAD_NUM));

    thread_t thread[DRC_REMASTER_MIGRATE_RES_MAX_THREAD_NUM];
    drc_remaster_migrate_param_t param[DRC_REMASTER_MIGRATE_RES_MAX_THREAD_NUM];
    uint32 count_per_thread = local_task_num / DRC_REMASTER_MIGRATE_RES_MAX_THREAD_NUM;
    for (uint32 i = 0; i < DRC_REMASTER_MIGRATE_RES_MAX_THREAD_NUM; i++) {
        param[i].start = i * count_per_thread;
        param[i].count_per_thread = count_per_thread;
        param[i].job_num = &job_num;
        param[i].session = session;
        if (i == DRC_REMASTER_MIGRATE_RES_MAX_THREAD_NUM - 1) {
            param[i].count_per_thread += local_task_num % DRC_REMASTER_MIGRATE_RES_MAX_THREAD_NUM;
        }

        if (cm_create_thread(drc_remaster_migrate_res, 0, &param[i], &thread[i]) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[DRC] remaster migrate cm create thread(%u) failed, start(%u), count per thread(%u)", i,
                           param[i].start, param[i].count_per_thread);
            cm_atomic_add(&job_num, (int64)(i) - DRC_REMASTER_MIGRATE_RES_MAX_THREAD_NUM);
            drc_update_remaster_local_status(REMASTER_FAIL);
            ret = CT_ERROR;
            break;
        }
    }

    while (cm_atomic_get(&job_num) != 0) {
        cm_sleep(REMASTER_SLEEP_INTERVAL);
    }
    CT_LOG_RUN_INF("[DRC] remaster migrate res finish, task num(%u), start part_id(%u)",
        local_task_num, param[0].start);
    ret = part_mngr->remaster_status == REMASTER_FAIL ? CT_ERROR : ret;
    return ret;
}

void drc_remaster_migrate_clean_res_owner(knl_session_t *session, reform_info_t *reform_info)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    uint8 self_id = DRC_SELF_INST_ID;
    uint32 j;

    CT_LOG_RUN_INF("[DRC] inst(%u) remaster step migrate, start clean res before migration.", self_id);
    for (j = 0; j < reform_info->reform_list[REFORM_LIST_LEAVE].inst_id_count; j++) {
        uint8 leave_id = reform_info->reform_list[REFORM_LIST_LEAVE].inst_id_list[j];
        CT_LOG_RUN_INF("[DRC] inst(%u) remaster clean res for LEAVE node inst(%u) start", self_id, leave_id);
        drc_clean_res_owner_by_inst(leave_id, session);
        CT_LOG_RUN_INF("[DRC] inst(%u) remaster clean res for LEAVE node inst(%u) end", self_id, leave_id);
    }

    CT_LOG_RUN_INF("[DRC] inst(%u) remaster clean LEAVE node res before migration success, clean page cnt(%lld), clean"
                   " lock cnt(%lld), rcy page cnt(%lld), recovery lock cnt(%llu), clean convert cnt(%lld).", self_id,
                   cm_atomic_get(&ctx->stat.clean_page_cnt), cm_atomic_get(&ctx->stat.clean_lock_cnt),
                   cm_atomic_get(&ctx->stat.rcy_page_cnt), cm_atomic_get(&ctx->stat.rcy_lock_cnt),
                   cm_atomic_get(&ctx->stat.clean_convert_cnt));

    for (j = 0; j < reform_info->reform_list[REFORM_LIST_ABORT].inst_id_count; j++) {
        uint8 abort_id = reform_info->reform_list[REFORM_LIST_ABORT].inst_id_list[j];
        CT_LOG_RUN_INF("[DRC] inst(%u) remaster clean res for ABORT inst(%u) start", self_id, abort_id);
        drc_clean_res_owner_by_inst(abort_id, session);
        CT_LOG_RUN_INF("[DRC] inst(%u) remaster clean res for ABORT inst(%u) end", self_id, abort_id);
    }

    CT_LOG_RUN_INF("[DRC] inst(%u) remaster clean ABORT node res before migration success, clean page cnt(%lld), clean"
                   " lock cnt(%lld), rcy page cnt(%lld), recovery lock cnt(%llu), clean convert cnt(%lld).", self_id,
                   cm_atomic_get(&ctx->stat.clean_page_cnt), cm_atomic_get(&ctx->stat.clean_lock_cnt),
                   cm_atomic_get(&ctx->stat.rcy_page_cnt), cm_atomic_get(&ctx->stat.rcy_lock_cnt),
                   cm_atomic_get(&ctx->stat.clean_convert_cnt));
    return;
}

status_t drc_remaster_step_migrate(knl_session_t *session, reform_info_t *reform_info)
{
    drc_part_mngr_t *part_mngr = DRC_PART_MNGR;
    drc_remaster_mngr_t *remaster_mngr = DRC_PART_REMASTER_MNGR;
    reform_detail_t *detail = &g_rc_ctx->reform_detail;
    RC_STEP_BEGIN(detail->remaster_migrate_elapsed);
    CT_LOG_RUN_INF("[DRC] remaster step migrate start, local_task_num(%u).", remaster_mngr->local_task_num);
    drc_res_ctx_t *ctx = DRC_RES_CTX;

    // clean local resource first, then migrate resource
    uint8 self_id = DRC_SELF_INST_ID;
    uint32 i;

    cm_spin_lock(&remaster_mngr->lock, NULL);
    for (i = 0; i < reform_info->reform_list[REFORM_LIST_JOIN].inst_id_count; i++) {
        uint8 join_id = reform_info->reform_list[REFORM_LIST_JOIN].inst_id_list[i];
        if (join_id == self_id) {
            knl_panic(remaster_mngr->local_task_num == 0);
            if (drc_remaster_wait_migrate_finish(REMASTER_WAIT_MIGRATE_FINISH_TIMEOUT) != CT_SUCCESS) {
                drc_update_remaster_local_status(REMASTER_FAIL);
                CT_LOG_RUN_ERR("[DRC] inst(%u) wait migrate finish failed", self_id);
                cm_spin_unlock(&remaster_mngr->lock);
                RC_STEP_END(detail->remaster_migrate_elapsed, RC_STEP_FAILED);
                return CT_ERROR;
            }
            CT_LOG_RUN_INF("[DRC] inst(%u) remaster status update to publish for new node", self_id);
            if (drc_remaster_task_ack(session->id, CT_SUCCESS) != CT_SUCCESS) {
                drc_update_remaster_local_status(REMASTER_FAIL);
                CT_LOG_RUN_ERR("[DRC] inst(%u) send task ack to master failed, remaster status(%u)",
                               self_id, part_mngr->remaster_status);
                cm_spin_unlock(&remaster_mngr->lock);
                RC_STEP_END(detail->remaster_migrate_elapsed, RC_STEP_FAILED);
                return CT_ERROR;
            }
            drc_update_remaster_local_status(REMASTER_PUBLISH);
            cm_spin_unlock(&remaster_mngr->lock);
            RC_STEP_END(detail->remaster_migrate_elapsed, RC_STEP_FINISH);
            return CT_SUCCESS;
        }
    }

    drc_remaster_migrate_clean_res_owner(session, reform_info);

    if ((drc_remaster_migrate(session) != CT_SUCCESS) ||
        (remaster_mngr->local_task_num != remaster_mngr->local_task_complete_num)) {
        cm_spin_unlock(&remaster_mngr->lock);
        CT_LOG_RUN_ERR("[DRC] remaster migrate res failed, local task num(%u), local task complete num(%u)",
                       remaster_mngr->local_task_num, (uint32)remaster_mngr->local_task_complete_num);
        RC_STEP_END(detail->remaster_migrate_elapsed, RC_STEP_FAILED);
        return CT_ERROR;
    }

    drc_update_remaster_local_status(REMASTER_RECOVERY);
    CT_LOG_RUN_INF("[DRC] remaster migrate res end, task_num(%u), send buf cnt(%lld), msg cnt(%lld), send lock "
                   "cnt(%lld), msg cnt(%lld)", remaster_mngr->local_task_num, cm_atomic_get(&ctx->stat.mig_buf_cnt),
                   cm_atomic_get(&ctx->stat.mig_lock_cnt), cm_atomic_get(&ctx->stat.mig_buf_msg_sent_cnt),
                   cm_atomic_get(&ctx->stat.mig_lock_msg_sent_cnt));

    for (i = 0; i < reform_info->reform_list[REFORM_LIST_LEAVE].inst_id_count; i++) {
        uint8 leave_id = reform_info->reform_list[REFORM_LIST_LEAVE].inst_id_list[i];
        // knl_panic(reform_info->master_id != leave_id); // need to be added later when cms is ready
        if (leave_id == self_id) {
            CT_LOG_RUN_INF("[DRC] inst(%u) remaster step to publish after migrate its drc resource", self_id);
            if (drc_remaster_task_ack(session->id, CT_SUCCESS)) {
                drc_update_remaster_local_status(REMASTER_FAIL);
                CT_LOG_RUN_ERR("[DRC] inst(%u) send task ack to master failed, remaster status(%u)",
                               self_id, part_mngr->remaster_status);
                cm_spin_unlock(&remaster_mngr->lock);
                RC_STEP_END(detail->remaster_migrate_elapsed, RC_STEP_FAILED);
                return CT_ERROR;
            }
            drc_update_remaster_local_status(REMASTER_PUBLISH);
            break;
        }
    }
    
    cm_spin_unlock(&remaster_mngr->lock);
    RC_STEP_END(detail->remaster_migrate_elapsed, RC_STEP_FINISH);
    CT_LOG_RUN_INF("[DRC] remaster step migrate finish, local_task_num(%u).", remaster_mngr->local_task_num);
    return CT_SUCCESS;
}

void drc_reset_remaster_info(void)
{
    drc_part_mngr_t *part_mngr = DRC_PART_MNGR;
    drc_remaster_mngr_t *remaster_mngr = DRC_PART_REMASTER_MNGR;

    part_mngr->remaster_status = REMASTER_DONE;
    part_mngr->is_reentrant = CT_TRUE;
    part_mngr->remaster_inst = CT_INVALID_ID8;

    remaster_mngr->is_master = CT_FALSE;
    cm_atomic_set(&remaster_mngr->complete_num, 0);
    remaster_mngr->local_task_num = 0;
    cm_atomic_set(&remaster_mngr->local_task_complete_num, 0);
    remaster_mngr->task_num = 0;
    remaster_mngr->stopped = CT_TRUE;

    status_t ret;
    ret = memset_s(remaster_mngr->inst_drm_info, sizeof(inst_drm_info_t) * CT_MAX_INSTANCES, 0, sizeof(inst_drm_info_t) * CT_MAX_INSTANCES);
    knl_securec_check(ret);

    uint32 inst_part_size = sizeof(drc_inst_part_t) * CT_MAX_INSTANCES;
    ret = memcpy_s((uint8*)remaster_mngr->tmp_inst_part_tbl, inst_part_size,
                   (uint8*)part_mngr->inst_part_tbl, inst_part_size);
    knl_securec_check(ret);

    uint32 part_size = sizeof(drc_part_t) * DRC_MAX_PART_NUM;
    ret = memcpy_s((uint8*)remaster_mngr->tmp_part_map, part_size, (uint8*)part_mngr->part_map, part_size);
    knl_securec_check(ret);

    uint32 remaster_task_set_size = sizeof(drc_remaster_task_t) * DRC_MAX_PART_NUM;
    ret = memset_s(remaster_mngr->remaster_task_set, remaster_task_set_size, 0, remaster_task_set_size);
    knl_securec_check(ret);

    uint32 mgrt_part_res_size = sizeof(drc_mgrt_res_cnt_t) * DRC_MAX_PART_NUM;
    ret = memset_s(remaster_mngr->mgrt_part_res_cnt, mgrt_part_res_size, 0, mgrt_part_res_size);
    knl_securec_check(ret);
}

void drc_clean_remaster_res(void)
{
    // clean migrated global buf/lock res for remaster reentrant
    drc_free_migrated_res();
    drc_reset_remaster_info();
}

void drc_remaster_fail(knl_session_t   *session, status_t ret)
{
    drc_part_mngr_t *part_mngr = DRC_PART_MNGR;
    drc_remaster_mngr_t *remaster_mngr = DRC_PART_REMASTER_MNGR;
    if (remaster_mngr->is_master == CT_FALSE) {
        // notify master
        drc_notify_remaster_status(session, part_mngr->remaster_status);
    }
    CT_LOG_RUN_ERR("[DRC]remaster failed, return error[%d]", ret);
}

void drc_update_page_info(drc_buf_res_t *buf_res, page_info_t *page_info, uint8 inst_id)
{
    if (page_info->is_edp) {
        if (page_info->lsn > buf_res->latest_edp_lsn) {
            buf_res->latest_edp = inst_id;
            buf_res->latest_edp_lsn = page_info->lsn;
        }
        drc_bitmap64_set(&buf_res->edp_map, inst_id);
    }

    if (page_info->lock_mode != DRC_LOCK_NULL) {
        buf_res->mode = page_info->lock_mode;
        if (page_info->lock_mode == DRC_LOCK_EXCLUSIVE) {
            if (buf_res->claimed_owner != CT_INVALID_ID8) {
                CT_LOG_RUN_ERR("buf res claimed_owner[%u] is not NULL, page_id[%u-%u], part id[%u]",
                    buf_res->claimed_owner, page_info->page_id.file, page_info->page_id.page, buf_res->part_id);
                CM_ASSERT(0);
                return;
            }
            buf_res->claimed_owner = inst_id;
        } else if (page_info->lock_mode == DRC_LOCK_SHARE) {
            drc_bitmap64_set(&buf_res->readonly_copies, inst_id);
        }
    }
    CT_LOG_DEBUG_INF(
        "[DRC][%u-%u] Recover and update rcy page owner(%u) claimed_owner(%u), mode(%d), lsn(%llu), latest edp(%d), "
        " edp_map(%llu), readonly_copies(%llu). source rcy_pinfo->lock_mode=%d, rcy_pinfo->is_edp=%d",
        buf_res->page_id.file, buf_res->page_id.page, inst_id, buf_res->claimed_owner, buf_res->mode, buf_res->lsn,
        buf_res->latest_edp, buf_res->edp_map, buf_res->readonly_copies, page_info->lock_mode, page_info->is_edp);
}

void drc_rcy_page_info(void* page_info, uint8 inst_id, uint32 item_idx, uint32 *alloc_index)
{
    drc_buf_res_t  *buf_res;
    page_info_t *rcy_pinfo = (page_info_t *)page_info;
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    uint32 part_id = drc_page_partid(rcy_pinfo->page_id);
    drc_global_res_t *g_buf_res = &(ctx->global_buf_res);

    drc_res_bucket_t *bucket = drc_get_buf_map_bucket(&ctx->global_buf_res.res_map, rcy_pinfo->page_id.file,
                                                      rcy_pinfo->page_id.page);
    cm_spin_lock(&g_buf_res->res_part_stat_lock[part_id], NULL);
    cm_spin_lock(&bucket->lock, NULL);
    buf_res = (drc_buf_res_t *)drc_res_map_lookup(&ctx->global_buf_res.res_map, bucket, (char*)&rcy_pinfo->page_id);
    if (buf_res != NULL) {
        drc_update_page_info(buf_res, rcy_pinfo, inst_id);
        cm_spin_unlock(&bucket->lock);
        cm_spin_unlock(&g_buf_res->res_part_stat_lock[part_id]);
        return;
    }
    buf_res = (drc_buf_res_t*)DRC_GET_RES_ADDR_BY_ID(&ctx->global_buf_res.res_map.res_pool, item_idx);
    (*alloc_index)++;
    buf_res->page_id = rcy_pinfo->page_id;
    buf_res->idx = item_idx;
    buf_res->is_used = CT_TRUE;
    buf_res->lock = 0;
    buf_res->mode = rcy_pinfo->lock_mode;
    buf_res->lsn = 0;
    buf_res->readonly_copies = 0;
    buf_res->pending = DRC_RES_INVALID_ACTION;
    buf_res->claimed_owner = CT_INVALID_ID8;
    if (rcy_pinfo->lock_mode == DRC_LOCK_EXCLUSIVE) {
        buf_res->claimed_owner = inst_id;
    } else if (rcy_pinfo->lock_mode == DRC_LOCK_SHARE) {
        drc_bitmap64_set(&buf_res->readonly_copies, inst_id);
    }

    buf_res->edp_map = 0;
    if (rcy_pinfo->is_edp) {
        buf_res->latest_edp = inst_id;
        buf_res->latest_edp_lsn = rcy_pinfo->lsn;
        drc_bitmap64_set(&buf_res->edp_map, inst_id);
    } else {
        buf_res->latest_edp = CT_INVALID_ID8;
        buf_res->latest_edp_lsn = 0;
    }

    buf_res->converting.req_info = g_invalid_req_info;
    buf_res->converting.next = CT_INVALID_ID32;

    DRC_LIST_INIT(&buf_res->convert_q);

    drc_res_map_add(bucket, item_idx, &buf_res->next);

    buf_res->part_id = drc_page_partid(buf_res->page_id);
    buf_res->node.idx = item_idx;

    drc_list_t *list = &ctx->global_buf_res.res_parts[buf_res->part_id];
    spinlock_t *lock = &ctx->global_buf_res.res_part_lock[buf_res->part_id];
    drc_buf_res_t *head_buf = NULL;
    drc_list_node_t *head = NULL;

    cm_spin_lock(lock, NULL);

    if (list->count != 0) {
        head_buf = (drc_buf_res_t*)DRC_GET_RES_ADDR_BY_ID(&ctx->global_buf_res.res_map.res_pool, list->first);
        head = &head_buf->node;
    }
    drc_add_list_node(list, &buf_res->node, head);

    cm_spin_unlock(lock);

    cm_spin_unlock(&bucket->lock);

    cm_spin_unlock(&g_buf_res->res_part_stat_lock[part_id]);
    CT_LOG_DEBUG_INF("[DRC][%u-%u] Recover rcy page owner(%u) claimed_owner(%u), mode(%d), lsn(%llu), latest edp(%d), "
                     " edp_map(%llu), readonly_copies(%llu). source rcy_pinfo->lock_mode=%d, rcy_pinfo->is_edp=%d",
                     buf_res->page_id.file, buf_res->page_id.page, inst_id, buf_res->claimed_owner, buf_res->mode,
                     buf_res->lsn, buf_res->latest_edp, buf_res->edp_map, buf_res->readonly_copies,
                     rcy_pinfo->lock_mode, rcy_pinfo->is_edp);
}

status_t drc_send_lock_info(knl_session_t *session, uint8 new_master)
{
    uint8 self_id = DRC_SELF_INST_ID;
    drc_lock_batch_buf_t *ctx = DRC_LOCK_CONTEXT;
    drc_recovery_lock_res_msg_t recovery_lock_res_msg;
    drc_remaster_mngr_t *remaster_mngr = DRC_PART_REMASTER_MNGR;
    uint16 msg_size = sizeof(drc_recovery_lock_res_msg_t) + sizeof(drc_recovery_lock_res_t) * ctx->count[new_master];

    mes_init_send_head(&recovery_lock_res_msg.head, MES_CMD_RECOVERY_LOCK_RES, msg_size, CT_INVALID_ID32, self_id,
                       new_master, session->id, CT_INVALID_ID16);
    recovery_lock_res_msg.count = ctx->count[new_master];
    recovery_lock_res_msg.buffer_len = recovery_lock_res_msg.count * sizeof(drc_recovery_lock_res_t);

    status_t ret = mes_send_data3(&recovery_lock_res_msg.head, sizeof(drc_recovery_lock_res_msg_t),
        ctx->buffers[new_master]);
    if (SECUREC_UNLIKELY(ret != CT_SUCCESS)) {
        CT_LOG_RUN_ERR("[DRC][send lock info batch]: failed, new_master_id=%u, count=%u",
            new_master, recovery_lock_res_msg.count);
        return CT_ERROR;
    }

    cm_atomic_inc(&remaster_mngr->recovery_task_num);

    CT_LOG_DEBUG_INF("[DRC][send lock info batch]: succeeded, new_master_id=%u, count=%u",
        new_master, recovery_lock_res_msg.count);
    return CT_SUCCESS;
}

status_t drc_send_last_lock_info(knl_session_t *session)
{
    drc_lock_batch_buf_t *ctx = DRC_LOCK_CONTEXT;

    for (int i = 0; i < CT_MAX_INSTANCES; i++) {
        if (ctx->count[i] == 0) {
            continue;
        }

        if (drc_send_lock_info(session, i)) {
            CT_LOG_RUN_ERR("[DRC]drc_send_last_lock_info: failed, inst_id=%u", i);
            return CT_ERROR;
        }
    }
    
    return CT_SUCCESS;
}

status_t drc_collect_and_send_lock_info(knl_session_t *session, drc_local_lock_res_t *lock_res, uint8 new_master)
{
    drc_lock_batch_buf_t *ctx = DRC_LOCK_CONTEXT;
    drc_recovery_lock_res_t *lock_info = (drc_recovery_lock_res_t *)ctx->buffers[new_master];

    uint8 lock_mode = lock_res->latch_stat.lock_mode;
    if (lock_res->is_owner && lock_mode == DRC_LOCK_NULL) {
        lock_mode = DRC_LOCK_EXCLUSIVE;
    }

    if (lock_mode == DRC_LOCK_NULL) {
        DTC_DRC_DEBUG_INF("[DRC]no need to recovery lock res[%u-%u-%u-%u-%u-%u], is_owner[%u]," \
            " is_locked[%u], lock_mode[%u], stat[%u].", lock_res->res_id.type, lock_res->res_id.id,
            lock_res->res_id.uid, lock_res->res_id.idx, lock_res->res_id.part, lock_res->res_id.parentpart,
            lock_res->is_owner, lock_res->is_locked, lock_res->latch_stat.lock_mode,
            lock_res->latch_stat.stat);
        return CT_SUCCESS;
    }

    lock_info[ctx->count[new_master]].res_id = lock_res->res_id;
    lock_info[ctx->count[new_master]].lock_mode = lock_mode;
    ctx->count[new_master]++;

    // if max, then send to remote node
    if (ctx->count[new_master] >= ctx->max_count) {
        if (drc_send_lock_info(session, new_master)) {
            CT_LOG_RUN_ERR("[DRC]drc_collect_and_send_lock_info: failed, inst_id=%u", new_master);
            return CT_ERROR;
        }
        ctx->count[new_master] = 0;
    }

    return CT_SUCCESS;
}

void drc_recovery_lockinfo(knl_session_t *session, drc_local_lock_res_t *lock_res, uint8 new_master)
{
    uint8 self_id = DRC_SELF_INST_ID;
    drc_res_ctx_t *ctx = DRC_RES_CTX;

    if (self_id == new_master) {
        drc_res_bucket_t *bucket = drc_get_res_map_bucket(&ctx->global_lock_res.res_map, (char*)&lock_res->res_id, sizeof(drid_t));
        cm_spin_lock(&bucket->lock, NULL);
        uint8 lock_mode = lock_res->latch_stat.lock_mode;

        if (lock_mode == DRC_LOCK_NULL) {
            cm_spin_unlock(&bucket->lock);
            DTC_DRC_DEBUG_INF("[DRC]no need to recovery lock res[%u-%u-%u-%u-%u-%u], is_owner[%u]," \
                " is_locked[%u], lock_mode[%u], stat[%u].", lock_res->res_id.type, lock_res->res_id.id,
                lock_res->res_id.uid, lock_res->res_id.idx, lock_res->res_id.part, lock_res->res_id.parentpart,
                lock_res->is_owner, lock_res->is_locked, lock_res->latch_stat.lock_mode,
                lock_res->latch_stat.stat);
            return;
        }

        (void)drc_create_lock_res(&lock_res->res_id, bucket);
        drc_master_res_t *global_lock_res = (drc_master_res_t *)drc_res_map_lookup(&ctx->global_lock_res.res_map,
                                                                                   bucket, (char *)&lock_res->res_id);
        drc_req_info_t *req_info = &global_lock_res->converting.req_info;
        req_info->inst_id = self_id;
        req_info->inst_sid = session->id;
        req_info->req_mode = lock_mode;
        req_info->curr_mode = DRC_LOCK_MODE_MAX;
        req_info->rsn = mes_get_rsn(session->id);
        req_info->req_time = KNL_NOW(session);
        req_info->req_version = DRC_GET_CURR_REFORM_VERSION;
        req_info->lsn = CT_INVALID_ID64;
        cm_spin_unlock(&bucket->lock);

        lock_claim_info_t claim_info;
        claim_info.new_id = self_id;
        claim_info.inst_sid = session->id;
        claim_info.mode = lock_mode;
        (void)drc_claim_lock_owner(session, &lock_res->res_id, &claim_info, DRC_GET_CURR_REFORM_VERSION, CT_TRUE);
        return;
    } else {
        drc_collect_and_send_lock_info(session, lock_res, new_master);
    }
}

void drc_reset_lock_batch_buf(void)
{
    drc_lock_batch_buf_t *ctx = DRC_LOCK_CONTEXT;
    memset_sp(&ctx->count, CT_MAX_INSTANCES * sizeof(uint32), 0, CT_MAX_INSTANCES * sizeof(uint32));
    ctx->max_count = DRC_BATCH_BUF_SIZE / sizeof(drc_recovery_lock_res_t);
}

void drc_lock_res_recovery(thread_t *thread)
{
    dcs_collect_param_t* param = (dcs_collect_param_t*)(thread->argument);
    knl_session_t *session = param->session;
    uint8 abort_id = param->inst_id;
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_res_bucket_t *bucket;
    drc_res_pool_t *res_pool;
    drc_local_lock_res_t *lock_res;
    uint8 master_id;
    uint32 rcy_lock_cnt = 0;

    drc_reset_lock_batch_buf();
    drc_part_mngr_t *part_mngr = DRC_PART_MNGR;
    for (uint32 i = param->start; i < param->start + param->count_per_thread; i++) {
        if (part_mngr->remaster_status == REMASTER_FAIL) {
            CT_LOG_RUN_ERR("[DRC] remaster already failed");
            (void)cm_atomic_dec(param->job_num);
            return;
        }
        bucket = &ctx->local_lock_map.buckets[i];
        cm_spin_lock(&bucket->lock, NULL);
        res_pool = &ctx->local_lock_map.res_pool;
        lock_res = (drc_local_lock_res_t*)DRC_GET_RES_ADDR_BY_ID(res_pool, bucket->first);
        for (uint32 j = 0; j < bucket->count; j++) {
            drc_get_lock_master_id(&lock_res->res_id, &master_id);
            if (master_id == abort_id) {
                DTC_DRC_DEBUG_INF("[DRC]recovery lock res[%u-%u-%u-%u-%u-%u], is_owner[%u]," \
                    " is_locked[%u], lock_mode[%u], stat[%u].", lock_res->res_id.type, lock_res->res_id.id,
                    lock_res->res_id.uid, lock_res->res_id.idx, lock_res->res_id.part, lock_res->res_id.parentpart,
                    lock_res->is_owner, lock_res->is_locked, lock_res->latch_stat.lock_mode,
                    lock_res->latch_stat.stat);

                //get the new master id, and send the lock into to recovery
                drc_get_lock_remaster_id(&lock_res->res_id, &master_id);
                drc_recovery_lockinfo(session, lock_res, master_id);
                rcy_lock_cnt++;
            }

            lock_res = (drc_local_lock_res_t*)DRC_GET_RES_ADDR_BY_ID(res_pool, lock_res->next);
        }
        cm_spin_unlock(&bucket->lock);
    }

    drc_send_last_lock_info(session);
    (void)cm_atomic_dec(param->job_num);
    cm_atomic_add(&ctx->stat.rcy_lock_cnt, rcy_lock_cnt);
}

status_t drc_handle_lock_res_recovery(knl_session_t *session, uint8 inst_id)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    uint32 bucket_num = ctx->local_lock_map.bucket_num;

    atomic_t job_num;
    cm_atomic_set(&job_num, (int64)(DRC_REMASTER_RCY_MAX_THREAD_NUM));

    // Cache collected pages concurrently
    thread_t thread[DRC_REMASTER_RCY_MAX_THREAD_NUM];
    dcs_collect_param_t param[DRC_REMASTER_RCY_MAX_THREAD_NUM];
    uint32 count_per_thread = bucket_num / DRC_REMASTER_RCY_MAX_THREAD_NUM;
    status_t status = CT_SUCCESS;
    for (uint32 i = 0; i < DRC_REMASTER_RCY_MAX_THREAD_NUM; i++) {
        param[i].inst_id    = inst_id;
        param[i].start      = i * count_per_thread;
        param[i].job_num    = &job_num;
        param[i].count_per_thread    = count_per_thread;
        param[i].session = session;
        if (i == DRC_REMASTER_RCY_MAX_THREAD_NUM - 1) {
            param[i].count_per_thread += bucket_num % DRC_REMASTER_RCY_MAX_THREAD_NUM;
        }

        status = cm_create_thread(drc_lock_res_recovery, 0, &param[i], &thread[i]);
        if (status != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[DCS]cm_create_thread(%u): failed, inst_id=%u, count=%u", i, inst_id, count_per_thread);
            cm_atomic_add(&job_num, (int64)(i) - DRC_REMASTER_RCY_MAX_THREAD_NUM);
            drc_update_remaster_local_status(REMASTER_FAIL);
            break;
        }
    }

    while (cm_atomic_get(&job_num) != 0) {
        cm_sleep(DRC_COLLECT_SLEEP_TIME);
    }
    return status;
}

void drc_get_page_owner_id_for_rcy(knl_session_t *session, page_id_t pagid, uint8 *id)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_res_bucket_t *bucket;
    drc_buf_res_t *buf_res;

    bucket = drc_get_buf_map_bucket(&ctx->global_buf_res.res_map, pagid.file, pagid.page);

    cm_spin_lock(&bucket->lock, NULL);
    buf_res = (drc_buf_res_t*)drc_res_map_lookup(&ctx->global_buf_res.res_map, bucket, (char*)&pagid);
    if (NULL == buf_res) {
        cm_spin_unlock(&bucket->lock);
        *id = CT_INVALID_ID8;
        return;
    }

    if (CT_INVALID_ID8 == buf_res->claimed_owner) {
        drc_clean_buf_res(buf_res);
    }

    if (buf_res->pending == DRC_RES_EXCLUSIVE_ACTION) {
        *id = CT_INVALID_ID8;
    } else {
        *id = buf_res->claimed_owner;
    }
    cm_spin_unlock(&bucket->lock);

    return;
}

bool32 drc_page_need_recover(knl_session_t *session, page_id_t *pagid)
{
    uint8 id;
    drc_get_page_owner_id_for_rcy(session, *pagid, &id);
    if (id != CT_INVALID_ID8) {
        // TODO: this is only for 2 nodes cluster, need change
        CM_ASSERT(id == DRC_SELF_INST_ID);
        return CT_FALSE;
    }
    return CT_TRUE;
}

static void drc_rcy_page_info_l(uint8 self_id, char *buf, uint32 count, uint32 *idx)
{
    page_info_t *pinfos = (page_info_t*)buf;

    DTC_DCS_DEBUG_INF("[DRC]DCS rcy page info start, inst id(%u) count(%u).", self_id, count);

    status_t status = drc_res_pool_alloc_batch_item(&(g_drc_res_ctx.global_buf_res.res_map.res_pool), idx, count);
    if (status != CT_SUCCESS) {
        drc_update_remaster_local_status(REMASTER_FAIL);
        CT_LOG_RUN_ERR("[DRC]Alloc batch item failed,num(%u).", count);
        return;
    }

    uint32 alloc_index = 0;
    for (uint32 i = 0; i < count; i++) {
        drc_rcy_page_info((void*)&pinfos[i], self_id, idx[alloc_index], &alloc_index);
    }

    if (alloc_index < count) {
        drc_res_pool_free_batch_item(&(g_drc_res_ctx.global_buf_res.res_map.res_pool), &idx[alloc_index], count - alloc_index);
    }
}

static status_t drc_send_page_info2master(dcs_cache_page_param_t* cache_param, uint8 new_master_id,
    char *buf, uint32 count, uint32 *idx)
{
    uint8 self_id = cache_param->self_id;
    drc_res_ctx_t *ctx = DRC_RES_CTX;

    (void)cm_atomic_add(&ctx->stat.rcy_page_cnt, (int64)count);
    drc_remaster_mngr_t *remaster_mngr = DRC_PART_REMASTER_MNGR;

    if (self_id == new_master_id) {
        drc_rcy_page_info_l(self_id, buf, count, idx);
        return CT_SUCCESS;
    }

    msg_page_info_t pinfo_req;
    uint16 msg_size = sizeof(msg_page_info_t) + sizeof(page_info_t) * count;
    mes_init_send_head(&pinfo_req.head, MES_CMD_SEND_PAGE_INFO, msg_size, CT_INVALID_ID32, self_id, new_master_id,
                       cache_param->id, CT_INVALID_ID16);
    pinfo_req.count = count;
    pinfo_req.buffer_len = count * sizeof(page_info_t);

    status_t ret = mes_send_data3(&pinfo_req.head, sizeof(msg_page_info_t), buf);
    if (SECUREC_UNLIKELY(ret != CT_SUCCESS)) {
        drc_update_remaster_local_status(REMASTER_FAIL);
        CT_LOG_RUN_ERR("[DCS][send owner info batch]: failed, new_master_id=%u, count=%u", new_master_id, count);
        return CT_ERROR;
    }

    cm_atomic_inc(&remaster_mngr->recovery_task_num);

    CT_LOG_RUN_INF("[DCS][send owner info]: succeeded, new_master_id=%u, count=%u", new_master_id, count);
    return CT_SUCCESS;
}

static status_t drc_cache_page_info(dcs_cache_page_param_t* cache_param, uint8 master_id,
    buf_ctrl_t *ctrl, drc_page_batch_buf_t* batch_buf)
{
    char *buf = batch_buf->buffers[master_id];
    uint32 *count = &(batch_buf->count[master_id]);
    page_info_t *pinfo = (page_info_t *)(buf + sizeof(page_info_t) * (*count));
    pinfo->page_id = ctrl->page_id;
    pinfo->lock_mode = ctrl->lock_mode;
    pinfo->is_edp = ctrl->is_edp;
    pinfo->lsn = ctrl->page->lsn;
    (*count)++;

    if (*count == DRC_PAGE_CACHE_INFO_BATCH_CNT) {
        status_t ret = drc_send_page_info2master(cache_param, master_id, buf, *count, batch_buf->idx);
        if (ret != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[DCS][send page info]: failed, dest_id=%u, count=%u", master_id, *count);
            knl_panic(0);
            return CT_ERROR;
        }
        *count = 0;
    }

    return CT_SUCCESS;
}

static status_t drc_init_batch_buf(drc_page_batch_buf_t** batch_buf)
{
    uint32 buf_size = sizeof(drc_page_batch_buf_t);
    drc_page_batch_buf_t* tmp_batch_buf = (drc_page_batch_buf_t*)cm_malloc(buf_size);
    if (tmp_batch_buf == NULL) {
        CT_LOG_RUN_ERR("[DCS]Alloc batch buf faild, size(%u).", buf_size);
        return CT_ERROR;
    }
    memset_sp(tmp_batch_buf->count, sizeof(tmp_batch_buf->count), 0, sizeof(tmp_batch_buf->count));
    *batch_buf = tmp_batch_buf;
    return CT_SUCCESS;
}

static inline void drc_deinit_batch_buf(drc_page_batch_buf_t* batch_buf)
{
    if (batch_buf != NULL) {
        cm_free(batch_buf);
    }
    return;
}

static status_t drc_send_rest_page_info(dcs_cache_page_param_t* param, drc_page_batch_buf_t* batch_buf)
{
    for (uint8 instid = 0; instid < CT_MAX_INSTANCES; ++instid) {
        if (batch_buf->count[instid] == 0) {
            continue;
        }

        (void)drc_send_page_info2master(param, instid, batch_buf->buffers[instid], batch_buf->count[instid],
                                        batch_buf->idx);
        batch_buf->count[instid] = 0;
    }
    return CT_SUCCESS;
}

/* record flying page requests when reform is happening. */
page_id_t page_reqs[CT_MAX_SESSIONS];
int32 page_req_count = 0;
spinlock_t page_spin = 0;

static void drc_collect_page_info(thread_t *thread)
{
    dcs_collect_param_t* param = (dcs_collect_param_t*)(thread->argument);
    dcs_cache_page_param_t* cache_param = &(param->cache_param);
    uint32 inst_id = param->inst_id;

    drc_page_batch_buf_t* batch_buf = NULL;
    if (drc_init_batch_buf(&batch_buf) != CT_SUCCESS) {
        drc_update_remaster_local_status(REMASTER_FAIL);
        (void)cm_atomic_dec(param->job_num);
        return;
    }
    drc_part_mngr_t *part_mngr = DRC_PART_MNGR;
    timeval_t tv_begin;
    for (uint32 j = param->start; j < param->start + param->count_per_thread; j++) {
        // page beyond hwm must not be readonly copy from aborted instance, nor be mastered on aborted instance.
        // because during recovery, new requests related to aborted instance are blocked.
        buf_set_t* buf_set = &(param->ctx->buf_set[j]);
        cm_spin_lock(&buf_set->lock, &param->session->stat->spin_stat.stat_bucket);
        uint32 hwm = buf_set->hwm;
        for (uint32 i = 0; i < hwm; i++) {
            if (part_mngr->remaster_status == REMASTER_FAIL) {
                cm_spin_unlock(&buf_set->lock);
                drc_deinit_batch_buf(batch_buf);
                (void)cm_atomic_dec(param->job_num);
                CT_LOG_RUN_ERR("[DRC] remaster already failed");
                return;
            }

            // recover drc, whose master is on abort instance:
            // 1. owner/readonly copy
            // 2. edp
            buf_ctrl_t* ctrl = &(buf_set->ctrls[i]);
            if (ctrl->bucket_id == CT_INVALID_ID32) {
                continue;
            }
            buf_bucket_t *bucket = buf_find_bucket(param->session, ctrl->page_id);
            cm_spin_lock(&bucket->lock, &param->session->stat->spin_stat.stat_bucket);
            volatile uint8 lock_mode = ctrl->lock_mode;
            volatile uint8 is_edp = ctrl->is_edp;
            if (ctrl->transfer_status == BUF_TRANS_TRY_REMOTE) {
                CT_LOG_RUN_INF("[RC][%u-%u] page is trying to request remote node, lock_mode:%u", ctrl->page_id.file,
                               ctrl->page_id.page, ctrl->lock_mode);
                cm_spin_lock(&page_spin, NULL);
                page_reqs[page_req_count++] = ctrl->page_id;
                cm_spin_unlock(&page_spin);
            }

            if (lock_mode == DRC_LOCK_NULL && !is_edp) {
                cm_spin_unlock(&bucket->lock);
                continue;
            }

            page_id_t page_id = ctrl->page_id;

            // and collect latest edp is on crashed node.
            uint8 old_master_id;
            (void)drc_get_page_master_id(page_id, &old_master_id);
            if (old_master_id != inst_id) {
                cm_spin_unlock(&bucket->lock);
                continue;
            }

            uint8 new_master_id;
            (void)drc_get_page_remaster_id(page_id, &new_master_id);
            cantian_record_io_stat_begin(IO_RECORD_EVENT_DRC_REMASTER_RECOVER_REBUILD, &tv_begin);
            (void)drc_cache_page_info(cache_param, new_master_id, ctrl, batch_buf);
            cantian_record_io_stat_end(IO_RECORD_EVENT_DRC_REMASTER_RECOVER_REBUILD, &tv_begin, IO_STAT_SUCCESS);
            cm_spin_unlock(&bucket->lock);
        }
        cm_spin_unlock(&buf_set->lock);
    }
    cantian_record_io_stat_begin(IO_RECORD_EVENT_DRC_REMASTER_RECOVER_REBUILD, &tv_begin);
    (void)drc_send_rest_page_info(cache_param, batch_buf);
    cantian_record_io_stat_end(IO_RECORD_EVENT_DRC_REMASTER_RECOVER_REBUILD, &tv_begin, IO_STAT_SUCCESS);
    drc_deinit_batch_buf(batch_buf);

    (void)cm_atomic_dec(param->job_num);
    return;
}

status_t drc_handle_buf_res_recovery(knl_session_t *session, uint8 inst_id)
{
    buf_context_t *ctx = &session->kernel->buf_ctx;
    uint32 buf_set_count = ctx->buf_set_count;
    uint32 id = DCS_SELF_SID(session);
    uint32 self_id = DCS_SELF_INSTID(session);

    atomic_t job_num;
    cm_atomic_set(&job_num, (int64)(DRC_REMASTER_RCY_MAX_THREAD_NUM));

    // Cache collected pages concurrently
    thread_t thread[DRC_REMASTER_RCY_MAX_THREAD_NUM];
    dcs_collect_param_t param[DRC_REMASTER_RCY_MAX_THREAD_NUM];
    uint32 count_per_thread = buf_set_count / DRC_REMASTER_RCY_MAX_THREAD_NUM;
    status_t status = CT_SUCCESS;
    for (uint32 i = 0; i < DRC_REMASTER_RCY_MAX_THREAD_NUM; i++) {
        param[i].ctx        = ctx;
        param[i].inst_id    = inst_id;
        param[i].start      = i * count_per_thread;
        param[i].job_num    = &job_num;
        param[i].count_per_thread    = count_per_thread;
        param[i].cache_param.id      = id;
        param[i].cache_param.self_id = self_id;
        param[i].session = session;
        if (i == DRC_REMASTER_RCY_MAX_THREAD_NUM - 1) {
            param[i].count_per_thread += buf_set_count % DRC_REMASTER_RCY_MAX_THREAD_NUM;
        }

        status = cm_create_thread(drc_collect_page_info, 0, &param[i], &thread[i]);
        if (status != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[DCS]cm_create_thread(%u): failed, inst_id=%u, count=%u", i, inst_id, count_per_thread);
            cm_atomic_add(&job_num, (int64)(i) - DRC_REMASTER_RCY_MAX_THREAD_NUM);
            drc_update_remaster_local_status(REMASTER_FAIL);
            break;
        }
    }

    while (cm_atomic_get(&job_num) != 0) {
        cm_sleep(DRC_COLLECT_SLEEP_TIME);
    }
    return status;
}

status_t drc_remaster_recovery(knl_session_t *session, reform_info_t *reform_info)
{
    uint8 self_id = DRC_SELF_INST_ID;
    uint32 i;
    uint8 abort_id;
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_part_mngr_t *part_mngr = DRC_PART_MNGR;
    status_t ret = CT_SUCCESS;
    // reovery drc resource for abort instance
    for (i = 0; i < reform_info->reform_list[REFORM_LIST_ABORT].inst_id_count; i++) {
        if (part_mngr->remaster_status == REMASTER_FAIL) {
            CT_LOG_RUN_ERR("[DRC] remaster already failed");
            return CT_ERROR;
        }
        abort_id = reform_info->reform_list[REFORM_LIST_ABORT].inst_id_list[i];

        CT_LOG_RUN_INF("[DRC]instance(%u) remaster recovery lock res inst(%u) start", self_id, abort_id);
        ret = drc_handle_lock_res_recovery(session, abort_id);
        CT_LOG_RUN_INF("[DRC]instance(%u) remaster recovery lock res inst(%u) end", self_id, abort_id);

        CT_LOG_RUN_INF("[DRC]instance(%u) remaster handle abort inst(%u) start", self_id, abort_id);
        ret = drc_handle_buf_res_recovery(session, abort_id);
        CT_LOG_RUN_INF("[DRC]instance(%u) remaster handle abort inst(%u) end, ret=%d", self_id, abort_id, ret);
    }

    CT_LOG_RUN_INF("[DRC]instance(%u) remaster clean and recovery success, clean page cnt(%lld) clean lock cnt(%lld) "
                   "rcy page cnt(%lld) recovery lock cnt(%llu) clean convert cnt(%lld).", self_id,
                   cm_atomic_get(&ctx->stat.clean_page_cnt), cm_atomic_get(&ctx->stat.clean_lock_cnt),
                   cm_atomic_get(&ctx->stat.rcy_page_cnt), cm_atomic_get(&ctx->stat.rcy_lock_cnt),
                   cm_atomic_get(&ctx->stat.clean_convert_cnt));
    return ret;
}

void drc_reset_remaster_recovery_task_num(drc_remaster_mngr_t *remaster_mngr)
{
    cm_atomic_set(&remaster_mngr->recovery_task_num, 0);
    cm_atomic_set(&remaster_mngr->recovery_complete_task_num, 0);
}

bool32 drc_remaster_recovery_is_complete(drc_remaster_mngr_t *remaster_mngr)
{
    return cm_atomic_get(&remaster_mngr->recovery_complete_task_num) >= cm_atomic_get(&remaster_mngr->recovery_task_num);
}

status_t drc_remaster_step_recover(knl_session_t *session, reform_info_t *reform_info)
{
    drc_remaster_mngr_t *remaster_mngr = DRC_PART_REMASTER_MNGR;
    drc_part_mngr_t *part_mngr = DRC_PART_MNGR;
    reform_detail_t *detail = &g_rc_ctx->reform_detail;
    RC_STEP_BEGIN(detail->remaster_recovery_elapsed);
    drc_reset_remaster_recovery_task_num(remaster_mngr);
    CT_LOG_RUN_INF("[DRC] remaster step recover start");
    if (drc_remaster_recovery(session, reform_info) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[DRC] remaster recovery failed");
        drc_update_remaster_local_status(REMASTER_FAIL);
        RC_STEP_END(detail->remaster_recovery_elapsed, RC_STEP_FAILED);
        return CT_ERROR;
    }
    
    uint64 wait_time = 0;
    while (!drc_remaster_recovery_is_complete(remaster_mngr)) {
        if (wait_time >= REMASTER_RECOVER_TIMEOUT || part_mngr->remaster_status == REMASTER_FAIL) {
            CT_LOG_RUN_ERR("remaster recovery task timeout, remaster status(%u)", part_mngr->remaster_status);
            drc_update_remaster_local_status(REMASTER_FAIL);
            drc_remaster_task_ack(session->id, CT_ERROR);
            RC_STEP_END(detail->remaster_recovery_elapsed, RC_STEP_FAILED);
            return CT_ERROR;
        }
        cm_sleep(REMASTER_SLEEP_INTERVAL);
        wait_time += REMASTER_SLEEP_INTERVAL;
    }
    if (drc_remaster_task_ack(session->id, CT_SUCCESS) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[DRC] instance(%u) send task ack to master failed, remaster status(%u), remaster recovery",
                       DRC_SELF_INST_ID, part_mngr->remaster_status);
        drc_update_remaster_local_status(REMASTER_FAIL);
        RC_STEP_END(detail->remaster_recovery_elapsed, RC_STEP_FAILED);
        return CT_ERROR;
    }
    drc_update_remaster_local_status(REMASTER_PUBLISH);
    RC_STEP_END(detail->remaster_recovery_elapsed, RC_STEP_FINISH);
    CT_LOG_RUN_INF("[DRC] remaster step recover start");
    return CT_SUCCESS;
}

void drc_destroy_edp_pages_list(ptlist_t* list)
{
    for (uint32 i = 0; i < list->count; i++) {
        col_edp_page_info_t *p_info = (col_edp_page_info_t *)cm_ptlist_get(list, i);
        cm_free(p_info);
    }
    cm_destroy_ptlist(list);
}

static status_t drc_remaster_step_publish(knl_session_t *session, reform_info_t *reform_info)
{
    drc_remaster_mngr_t *remaster_mngr = DRC_PART_REMASTER_MNGR;
    drc_part_mngr_t *part_mngr = DRC_PART_MNGR;
    if (remaster_mngr->is_master == CT_FALSE) {
        cm_sleep(REMASTER_SLEEP_INTERVAL);
        return CT_SUCCESS;
    }

    CT_LOG_RUN_INF("[DRC] remaster step publish start");
    reform_detail_t *detail = &g_rc_ctx->reform_detail;
    status_t ret = CT_SUCCESS;
    RC_STEP_BEGIN(detail->remaster_publish_elapsed);
    //check the migration progress
    //uint64 wait_time = 0ULL;

    if (drc_remaster_wait_all_node_ready(reform_info, REMASTER_WAIT_ALL_NODE_READY_PUBLISH_TIMEOUT,
        REMASTER_PUBLISH) != CT_SUCCESS) {
        // wait remaster task all back, if already REMASTER_FAIL, stop waiting
        RC_STEP_END(detail->remaster_publish_elapsed, RC_STEP_FAILED);
        CT_LOG_RUN_ERR("remaster publish wait task timeout");
        return CT_ERROR;
    }
    part_mngr->remaster_finish_step = REMASTER_RECOVERY;
    CT_LOG_RUN_INF("[DRC] remaster finished step[%u]", part_mngr->remaster_finish_step);

    uint64 alive_bitmap = get_alive_bitmap_by_reform_info(&(remaster_mngr->reform_info));
    rc_bitmap64_clear(&alive_bitmap, DRC_SELF_INST_ID);
    SYNC_POINT_GLOBAL_START(CANTIAN_REMASTER_BCAST_TARGET_PART_FAIL, &ret, CT_ERROR);
    ret = drc_broadcast_target_part(session, CT_SUCCESS, alive_bitmap);
    SYNC_POINT_GLOBAL_END;
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[DRC] broadcast remaster new part table failed, ret=%d.", ret);
        RC_STEP_END(detail->remaster_publish_elapsed, RC_STEP_FINISH);
        return ret;
    }
    CT_LOG_RUN_INF("[DRC] broadcast remaster new part table successfully");

    uint32 part_size = DRC_MAX_PART_NUM * sizeof(drc_part_t);
    ret = memcpy_s((uint8*)part_mngr->part_map, part_size, (uint8*)remaster_mngr->target_part_map, part_size);
    knl_securec_check(ret);
    uint32 inst_part_size = CT_MAX_INSTANCES * sizeof(drc_inst_part_t);
    ret = memcpy_s((uint8*)part_mngr->inst_part_tbl, inst_part_size,
                   (uint8*)remaster_mngr->target_inst_part_tbl, inst_part_size);
    knl_securec_check(ret);

    // broadcast nodes to be REMASTER_DONE
    drc_remaster_status_notify_t remaster_done_msg;
    mes_init_send_head(&remaster_done_msg.head, MES_CMD_BROADCAST_REMASTER_DONE, sizeof(drc_remaster_status_notify_t),
                       CT_INVALID_ID32, DRC_SELF_INST_ID, 0, session->id, CT_INVALID_ID16);
    remaster_done_msg.remaster_status = part_mngr->remaster_status;
    remaster_done_msg.reform_trigger_version = remaster_mngr->reform_info.trigger_version;
    SYNC_POINT_GLOBAL_START(CANTIAN_REMASTER_BCAST_REMASTER_DONE_FAIL, &ret, CT_ERROR);
    ret = mes_broadcast_data_and_wait_with_retry(session->id, alive_bitmap, (const void *)&remaster_done_msg,
                                                 REMASTER_BROADCAST_DONE_TIMEOUT, REMASTER_SEND_MSG_RETRY_TIMES);
    SYNC_POINT_GLOBAL_END;
    CT_LOG_RUN_INF("[DRC]broadcast remaster done finish, ret(%d), alive_bitmap(%llu)", ret, alive_bitmap);
    if (ret == CT_SUCCESS) {
        drc_remaster_inst_list(reform_info);
        drc_update_remaster_local_status(REMASTER_DONE);
        part_mngr->remaster_finish_step = REMASTER_PUBLISH;
        CT_LOG_RUN_INF("[DRC] remaster finished step[%u]", part_mngr->remaster_finish_step);
    }
    RC_STEP_END(detail->remaster_publish_elapsed, RC_STEP_FINISH);
    CT_LOG_RUN_INF("[DRC] remaster step publish finish");
    return ret;
}

void drc_remaster_proc(thread_t *thread)
{
    knl_session_t *session = (knl_session_t*)thread->argument;
    drc_part_mngr_t *part_mngr = DRC_PART_MNGR;
    drc_remaster_mngr_t *remaster_mngr = DRC_PART_REMASTER_MNGR;
    reform_info_t *reform_info = &remaster_mngr->reform_info;
    uint8 self_id = DRC_SELF_INST_ID;
    status_t ret = CT_SUCCESS;
    cm_set_thread_name("remaster");
    KNL_SESSION_SET_CURR_THREADID(session, cm_get_current_thread_id());
    remaster_mngr->stopped = CT_FALSE;

    CT_LOG_RUN_INF("[DRC]remaster start, remaster stauts[%u], my inst id[%u], master id[%u], remaster stopped[%u]",
                   part_mngr->remaster_status, self_id, reform_info->master_id, remaster_mngr->stopped);

    remaster_mngr->is_master = (self_id == reform_info->master_id) ? CT_TRUE : CT_FALSE;
    cm_atomic_set(&remaster_mngr->complete_num, 0);

    bool8 is_first_fail = CT_TRUE;
    //remaster FSM transfer flow
    while (!thread->closed) {
        switch (part_mngr->remaster_status) {
            case REMASTER_PREPARE: {
                drc_prepare_remaster(session, reform_info);
                break;
            }
            case REMASTER_ASSIGN_TASK: {
                SYNC_POINT_GLOBAL_START(CANTIAN_REMASTER_STEP_ASSIGN_TASK_FAIL, &ret, CT_ERROR);
                ret = drc_remaster_step_assign_task(session, reform_info);
                SYNC_POINT_GLOBAL_END;
                break;
            }
            case REMASTER_MIGRATE: {
                SYNC_POINT_GLOBAL_START(CANTIAN_REMASTER_STEP_MIGRATE_FAIL, &ret, CT_ERROR);
                ret = drc_remaster_step_migrate(session, reform_info);
                SYNC_POINT_GLOBAL_END;
                if (ret == CT_SUCCESS) {
                    part_mngr->remaster_finish_step = REMASTER_MIGRATE;
                    CT_LOG_RUN_INF("[DRC] remaster finished step[%u]", part_mngr->remaster_finish_step);
                }
                break;
            }
            case REMASTER_RECOVERY: {
                SYNC_POINT_GLOBAL_START(CANTIAN_REMASTER_STEP_RECOVERY_FAIL, &ret, CT_ERROR);
                ret = drc_remaster_step_recover(session, reform_info);
                SYNC_POINT_GLOBAL_END;
                break;
            }
            case REMASTER_PUBLISH: {
                SYNC_POINT_GLOBAL_START(CANTIAN_REMASTER_STEP_PUBLISH_FAIL, &ret, CT_ERROR);
                ret = drc_remaster_step_publish(session, reform_info);
                SYNC_POINT_GLOBAL_END;
                break;
            }
            case REMASTER_FAIL: {
                if (is_first_fail) {
                    drc_remaster_fail(session, ret);
                    is_first_fail = CT_FALSE;
                }
                cm_sleep(REMASTER_FAIL_SLEEP_INTERVAL);
                break;
            }
            case REMASTER_DONE:
                break;
            default:
                break;
        }

        if (ret != CT_SUCCESS && part_mngr->remaster_status != REMASTER_FAIL) {
            CT_LOG_RUN_ERR("[DRC] remaster fail by master[%u],return error[%d]", self_id, ret);
            drc_update_remaster_local_status(REMASTER_FAIL);
            continue;
        }

        if (REMASTER_DONE == part_mngr->remaster_status) {
            part_mngr->remaster_finish_step = REMASTER_DONE;
            CT_LOG_RUN_INF("[DRC] remaster finished step[%u]", part_mngr->remaster_finish_step);
            break;
        }
    }
    if (part_mngr->remaster_status == REMASTER_FAIL) {
        remaster_mngr->stopped = CT_TRUE;
        KNL_SESSION_CLEAR_THREADID(session);
        CT_LOG_RUN_INF("[DRC] instance[%u] remaster stopped, remaster status[%u]",
                       self_id, part_mngr->remaster_status);
        return;
    }

    CT_LOG_RUN_INF("[DRC] instance[%u] remaster success, complete local tasks[%u], inst num[%u], thread closed",
                   self_id, remaster_mngr->local_task_num, part_mngr->inst_num);
    part_mngr->inst_num = RC_REFORM_LIST_COUNT(reform_info, REFORM_LIST_AFTER);

    KNL_SESSION_CLEAR_THREADID(session);
}

status_t drc_check_reform_info(reform_info_t *reform_info)
{
    if (NULL == reform_info) {
        CT_LOG_RUN_ERR("[DRC]reform info pointer is null,inst id:%u", DRC_SELF_INST_ID);
        return CT_ERROR;
    }

    if (0 == RC_REFORM_LIST_COUNT(reform_info, REFORM_LIST_BEFORE)) {
        CT_LOG_RUN_ERR("[DRC]current instance list num(%u) is 0, reform error", \
            RC_REFORM_LIST_COUNT(reform_info, REFORM_LIST_BEFORE));
        return CT_ERROR;
    }

    if (1 == RC_REFORM_LIST_COUNT(reform_info, REFORM_LIST_BEFORE) &&
        1 == RC_REFORM_LIST_COUNT(reform_info, REFORM_LIST_LEAVE)) {
        CM_ASSERT(RC_REFORM_LIST(reform_info, REFORM_LIST_BEFORE).inst_id_list[0] ==
                  RC_REFORM_LIST(reform_info, REFORM_LIST_LEAVE).inst_id_list[0]);
        CT_LOG_RUN_INF("[DRC]shutdown the last instance(%u), no need remaster", DRC_SELF_INST_ID);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

void dtc_remaster_init(reform_info_t *reform_info)
{
    drc_remaster_mngr_t *remaster_mngr = DRC_PART_REMASTER_MNGR;
    drc_res_ctx_t *ctx = DRC_RES_CTX;

    status_t ret = memcpy_s((uint8*)&remaster_mngr->reform_info, sizeof(reform_info_t), (uint8*)reform_info, sizeof(reform_info_t));
    knl_securec_check(ret);

    ret = memset_s(remaster_mngr->mgrt_part_res_cnt, sizeof(drc_mgrt_res_cnt_t) * DRC_MAX_PART_NUM, 0, sizeof(drc_mgrt_res_cnt_t) * DRC_MAX_PART_NUM);
    knl_securec_check(ret);

    uint32 remaster_task_set_size = sizeof(drc_remaster_task_t) * DRC_MAX_PART_NUM;
    ret = memset_s(remaster_mngr->remaster_task_set, remaster_task_set_size, 0, remaster_task_set_size);
    knl_securec_check(ret);

    drc_reset_remaster_stat(&ctx->stat);
}

void drc_start_remaster(reform_info_t *reform_info)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    knl_instance_t *kernel = ctx->kernel;
    drc_part_mngr_t *part_mngr = DRC_PART_MNGR;
    drc_remaster_mngr_t *remaster_mngr = DRC_PART_REMASTER_MNGR;

    if (NULL == reform_info) {
        CT_LOG_RUN_ERR("[DRC] reform info pointer is null, inst id[%u]", DRC_SELF_INST_ID);
        return;
    }

    if (0 == RC_REFORM_LIST_COUNT(reform_info, REFORM_LIST_BEFORE)) {
        CT_LOG_RUN_ERR("[DRC]current instance list is empty,before num:%u, after num:%u,join num:%u,leave num:%u,abort num:%u,fail num:%u",\
            RC_REFORM_LIST_COUNT(reform_info, REFORM_LIST_BEFORE), RC_REFORM_LIST_COUNT(reform_info, REFORM_LIST_AFTER),
            RC_REFORM_LIST_COUNT(reform_info, REFORM_LIST_JOIN), RC_REFORM_LIST_COUNT(reform_info, REFORM_LIST_LEAVE),
            RC_REFORM_LIST_COUNT(reform_info, REFORM_LIST_ABORT), RC_REFORM_LIST_COUNT(reform_info, REFORM_LIST_FAIL));
        return;
    }

    if (1 == RC_REFORM_LIST_COUNT(reform_info, REFORM_LIST_BEFORE) &&
        1 == RC_REFORM_LIST_COUNT(reform_info, REFORM_LIST_LEAVE)) {
        CM_ASSERT(RC_REFORM_LIST(reform_info, REFORM_LIST_BEFORE).inst_id_list[0] == RC_REFORM_LIST(reform_info, REFORM_LIST_LEAVE).inst_id_list[0]);
        CT_LOG_RUN_INF("[DRC] shutdown the last instance[%u], no need remaster", DRC_SELF_INST_ID);
        return;
    }

    knl_session_t *session = kernel->sessions[SESSION_ID_DRC_REMASTER];
    part_mngr->remaster_inst = reform_info->master_id;
    drc_update_remaster_local_status(REMASTER_PREPARE);

    if (cm_create_thread(drc_remaster_proc, 0, session, &remaster_mngr->remaster_thread) != CT_SUCCESS) {
        part_mngr->remaster_inst = CT_INVALID_ID8;
        drc_update_remaster_local_status(REMASTER_FAIL);
        CT_LOG_RUN_ERR("[DRC] create remaster thread failed");
    }

    CT_LOG_RUN_INF(
        "[DRC]start remaster, before num:%u, after num:%u, join num:%u,leave num:%u,abort num:%u,fail num:%u",
        RC_REFORM_LIST_COUNT(reform_info, REFORM_LIST_BEFORE), RC_REFORM_LIST_COUNT(reform_info, REFORM_LIST_AFTER),
        RC_REFORM_LIST_COUNT(reform_info, REFORM_LIST_JOIN), RC_REFORM_LIST_COUNT(reform_info, REFORM_LIST_LEAVE),
        RC_REFORM_LIST_COUNT(reform_info, REFORM_LIST_ABORT), RC_REFORM_LIST_COUNT(reform_info, REFORM_LIST_FAIL));
}

void drc_stat_converting_page_count(uint32 *cnt)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    *cnt = ctx->stat.converting_page_cnt;
}

// free immigrated res for reentrant
void drc_free_immigrated_res(void)
{
    drc_remaster_mngr_t *remaster_mngr = DRC_PART_REMASTER_MNGR;
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_global_res_t* buf_res = &(ctx->global_buf_res);
    drc_global_res_t* lock_res = &(ctx->global_lock_res);
    drc_list_t *part_list = NULL;
    uint16 part_id;

    CT_LOG_RUN_INF("[DRC] start free immigrated res");
    for (uint32 i = 0; i < DRC_MAX_PART_NUM; i++) {
        part_id = i;
        // free buf/lock res in target_part_map but not in tmp_part_map
        if (remaster_mngr->target_part_map[part_id].inst_id == DRC_SELF_INST_ID
            && remaster_mngr->tmp_part_map[part_id].inst_id != DRC_SELF_INST_ID) {
        CT_LOG_RUN_INF("[DRC] free immigrated res of part id[%u], target_part_map->inst_id[%u], "
                       "tmp_part_map->inst_id[%u]", part_id, remaster_mngr->target_part_map[part_id].inst_id,
                       remaster_mngr->tmp_part_map[part_id].inst_id);
        part_list = &(buf_res->res_parts[part_id]);
        spinlock_t *buf_res_part_lock = &(ctx->global_buf_res.res_part_lock[part_id]);
        cm_spin_lock(buf_res_part_lock, NULL);
        drc_free_buf_res_by_part(part_list);
        cm_spin_unlock(buf_res_part_lock);

        part_list = &(lock_res->res_parts[part_id]);
        spinlock_t *lock_res_part_lock = &(ctx->global_lock_res.res_part_lock[part_id]);
        cm_spin_lock(lock_res_part_lock, NULL);
        drc_free_lock_res_by_part(part_list);
        cm_spin_unlock(lock_res_part_lock);
        }
        CT_LOG_RUN_INF("[DRC] no need to free immigrated res of part id[%u], target_part_map->inst_id[%u], "
                       "tmp_part_map->inst_id[%u]", part_id, remaster_mngr->target_part_map[part_id].inst_id,
                       remaster_mngr->tmp_part_map[part_id].inst_id);
    }
    CT_LOG_RUN_INF("[DRC] finish free immigrated res");
    return;
}

/* reset part_mngr part_map/inst_pat_tbl */
status_t drc_reset_target_part(void)
{
    drc_part_mngr_t *part_mngr = DRC_PART_MNGR;
    drc_remaster_mngr_t *remaster_mngr = DRC_PART_REMASTER_MNGR;
    status_t ret;
    uint32 inst_part_size = sizeof(drc_inst_part_t) * CT_MAX_INSTANCES;

    ret = memcpy_s((uint8*)part_mngr->inst_part_tbl, inst_part_size,
                   (uint8*)remaster_mngr->tmp_inst_part_tbl, inst_part_size);
    MEMS_RETURN_IFERR(ret);

    uint32 part_size = sizeof(drc_part_t) * DRC_MAX_PART_NUM;
    ret = memcpy_s((uint8*)part_mngr->part_map, part_size, (uint8*)remaster_mngr->tmp_part_map, part_size);
    MEMS_RETURN_IFERR(ret);

    CT_LOG_RUN_INF("[DRC] reset part_map and inst_part_tbl to last stable reform version");

    return ret;
}

status_t drc_stop_remaster(void)
{
    drc_part_mngr_t *part_mngr = DRC_PART_MNGR;
    drc_remaster_mngr_t *remaster_mngr = DRC_PART_REMASTER_MNGR;
    reform_info_t *reform_info = &remaster_mngr->reform_info;
    uint8 remaster_terminate_status = part_mngr->remaster_finish_step;
    CT_LOG_RUN_INF("[DRC] stop current remaster start, remaster termintate status[%u], remaster status[%u], reform "
                   "trigger version[%llu]", remaster_terminate_status, part_mngr->remaster_status,
                   remaster_mngr->reform_info.trigger_version);

    drc_update_remaster_local_status(REMASTER_FAIL); // cancel last remaster
    cm_close_thread(&remaster_mngr->remaster_thread);
    while (remaster_mngr->stopped != CT_TRUE) {
        cm_sleep(5);
    }
    if (remaster_terminate_status >= REMASTER_ASSIGN_TASK && remaster_terminate_status <= REMASTER_DONE) {
        // clean migrated gloabl buf/lock res
        drc_free_immigrated_res();
        // reset target part_map/inst_pat_tbl
        status_t ret = drc_reset_target_part();
        if (ret != CT_SUCCESS) {
            CT_LOG_RUN_INF("[DRC] stop current remaster failed, remaster status[%u], reform version[%llu]",
                           part_mngr->remaster_status, remaster_mngr->reform_info.trigger_version);
            return ret;
        }
    }
    drc_reset_remaster_info();
    part_mngr->inst_num = RC_REFORM_LIST_COUNT(reform_info, REFORM_LIST_BEFORE);

    CT_LOG_RUN_INF("[DRC] stop current remaster successfully, remaster status[%u], reform version[%llu]",
                   part_mngr->remaster_status, remaster_mngr->reform_info.trigger_version);
    return CT_SUCCESS;
}

bool32 drc_remaster_in_progress(void)
{
    drc_part_mngr_t *part_mngr = DRC_PART_MNGR;
    if (part_mngr->remaster_status == REMASTER_DONE || part_mngr->remaster_status == REMASTER_FAIL) {
        return CT_FALSE;
    } else {
        return CT_TRUE;
    }
}

bool32 drc_remaster_need_stop(void)
{
    drc_part_mngr_t *part_mngr = DRC_PART_MNGR;
    if (REMASTER_DONE != part_mngr->remaster_status) {
        part_mngr->mgrt_fail_list = CT_FALSE;
        return CT_TRUE;
    } else {
        if (g_rc_ctx->info.failed_reform_status <= REFORM_RECOVERING) {
            part_mngr->mgrt_fail_list = CT_FALSE;
        }
        return CT_FALSE;
    }
}

uint8 drc_get_remaster_status(void)
{
    drc_part_mngr_t *part_mngr = DRC_PART_MNGR;
    return part_mngr->remaster_status;
}

void drc_get_res_num(drc_res_type_e type, uint32 *used_num, uint32 *item_num)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    *used_num = 0;
    *item_num = 0;
    drc_res_pool_t *pool = NULL;

    switch (type) {
        case DRC_RES_PAGE_TYPE:
            pool = &ctx->global_buf_res.res_map.res_pool;
            break;
        case DRC_RES_LOCAL_LOCK_TYPE:
            pool = &ctx->local_lock_map.res_pool;
            break;
        case DRC_RES_LOCK_TYPE:
            pool = &ctx->global_lock_res.res_map.res_pool;
            break;
        case DRC_RES_LOCAL_TXN_TYPE:
            pool = &ctx->local_txn_map.res_pool;
            break;
        case DRC_RES_TXN_TYPE:
            pool = &ctx->txn_res_map.res_pool;
            break;
        case DRC_RES_LOCK_ITEM_TYPE:
            pool = &ctx->lock_item_pool;
            break;
        default:
            break;
    }

    if (pool != NULL) {
        *used_num = pool->used_num;
        *item_num = pool->item_num;
    }
    return;
}

void drc_lock_remaster_mngr(void)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    cm_spin_lock(&ctx->part_mngr.remaster_mngr.lock, NULL);
}

void drc_unlock_remaster_mngr(void)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    cm_spin_unlock(&ctx->part_mngr.remaster_mngr.lock);
}

status_t drc_rcy_lock_res_info(knl_session_t *session, drc_recovery_lock_res_t* lock_res_info, uint8 inst_id)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_res_bucket_t *bucket = drc_get_res_map_bucket(&ctx->global_lock_res.res_map, (char*)&lock_res_info->res_id, sizeof(drid_t));

    cm_spin_lock(&bucket->lock, NULL);
    drc_master_res_t *lock_res = (drc_master_res_t*)drc_res_map_lookup(&ctx->global_lock_res.res_map, bucket, (char*)&lock_res_info->res_id);
    if (NULL == lock_res) {
        status_t ret = drc_create_lock_res(&lock_res_info->res_id, bucket);
        if (ret != CT_SUCCESS) {
            cm_spin_unlock(&bucket->lock);
            return CT_ERROR;
        }
        lock_res = (drc_master_res_t *)drc_res_map_lookup(&ctx->global_lock_res.res_map, bucket,
                                                          (char *)&lock_res_info->res_id);
    } else {
        CM_ASSERT(!drc_bitmap64_exist(&lock_res->granted_map, inst_id) &&
                  (g_mode_compatible_matrix[lock_res_info->lock_mode][lock_res->mode] == 1));
        if (drc_bitmap64_exist(&lock_res->granted_map, inst_id) ||
            (g_mode_compatible_matrix[lock_res_info->lock_mode][lock_res->mode] != 1)) {
            CT_LOG_RUN_ERR("[DRC]: lock res check failed, granted map:%llu, inst_id:%d, lock_mode:%d, mode:%d",
                lock_res->granted_map, inst_id, lock_res_info->lock_mode, lock_res->mode);
            cm_spin_unlock(&bucket->lock);
            return CT_ERROR;
        }
    }
    if (lock_res == NULL) {
        CT_LOG_RUN_ERR("[DRC] lock_res is NULL!");
        cm_spin_unlock(&bucket->lock);
        return CT_ERROR;
    }
    drc_req_info_t *req_info = &lock_res->converting.req_info;
    req_info->inst_id = inst_id;
    req_info->inst_sid = CT_INVALID_ID16;
    req_info->req_mode = lock_res_info->lock_mode;
    req_info->curr_mode = DRC_LOCK_MODE_MAX;
    req_info->rsn = 0;
    req_info->req_time = 0;
    req_info->req_version = DRC_GET_CURR_REFORM_VERSION;
    req_info->lsn = CT_INVALID_ID64;
    cm_spin_unlock(&bucket->lock);
    lock_claim_info_t claim_info;
    claim_info.new_id = inst_id;
    claim_info.inst_sid = CT_INVALID_ID16;
    claim_info.mode = lock_res_info->lock_mode;

    (void)drc_claim_lock_owner(session, &lock_res_info->res_id, &claim_info, DRC_GET_CURR_REFORM_VERSION, CT_TRUE);
    return CT_SUCCESS;
}

static status_t drc_check_recovery_lock_res_msg(mes_message_t * msg)
{
    if (sizeof(drc_recovery_lock_res_msg_t) > msg->head->size) {
        return CT_ERROR;
    }
    drc_recovery_lock_res_msg_t *request = (drc_recovery_lock_res_msg_t *)msg->buffer;
    if ((sizeof(drc_recovery_lock_res_msg_t) + request->count * sizeof(drc_recovery_lock_res_t)) != msg->head->size) {
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

void drc_process_recovery_lock_res(void *sess, mes_message_t *msg)
{
    drc_lock_batch_buf_t *ctx = DRC_LOCK_CONTEXT;
    knl_session_t *session = (knl_session_t *)sess;
    if (drc_check_recovery_lock_res_msg(msg) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("msg is invalid, msg size %u.", msg->head->size);
        mes_release_message_buf(msg->buffer);
        return;
    }
    drc_recovery_lock_res_msg_t *req = (drc_recovery_lock_res_msg_t *)msg->buffer;
    uint32 count = req->count;

    if (count > ctx->max_count || g_dtc->profile.node_count <= 2) {   // node count 2
        CT_LOG_RUN_WAR("[DRC] receive recovery lock res msg with count(%u), max count(%u), node count(%u)",
                       count, ctx->max_count, g_dtc->profile.node_count);
        mes_release_message_buf(msg->buffer);
        return;
    }

    if (req->buffer_len != count * sizeof(drc_recovery_lock_res_t) ||
        req->head.size != sizeof(drc_recovery_lock_res_msg_t) + sizeof(drc_recovery_lock_res_t) * count) {
        CT_LOG_RUN_ERR ("[DRC] receive recovery lock res invalid req, count: %d, buffer_len: %d, size: %d",
            count, req->buffer_len, req->head.size);
        mes_release_message_buf(msg->buffer);
        return;
    }

    drc_recovery_lock_res_t *linfo = (drc_recovery_lock_res_t *)(msg->buffer + sizeof(drc_recovery_lock_res_msg_t));
    for (uint32 i = 0; i < count; ++i) {
        drc_rcy_lock_res_info(session, (void*)linfo, msg->head->src_inst);
        linfo++;
    }

    DTC_DCS_DEBUG_INF("[DRC][%s]: succeeded, count=%u", MES_CMD2NAME(req->head.cmd), count);

    mes_message_head_t ack;
    mes_init_ack_head(&req->head, &ack, MES_CMD_RECOVERY_LOCK_RES_ACK, sizeof(mes_message_head_t), DCS_SELF_SID(session));
    mes_release_message_buf(msg->buffer);

    if (mes_send_data(&ack) == CT_SUCCESS) {
        DTC_DRC_DEBUG_INF("[DRC][drc_process_recovery_lock_res]: ack sent");
    } else {
        CT_LOG_RUN_ERR("[DRC][drc_process_recovery_lock_res]: failed to send ack");
    }
}

void drc_process_remaster_recovery_task_ack(void *sess, mes_message_t *receive_msg)
{
    drc_remaster_mngr_t *remaster_mngr = DRC_PART_REMASTER_MNGR;
    drc_part_mngr_t *part_mngr = DRC_PART_MNGR;
    if (g_dtc->profile.node_count <= 2) {   // node count 2
        CT_LOG_RUN_WAR("[DRC] this process is not involved in cluster with 2 nodes");
        mes_release_message_buf(receive_msg->buffer);
        return;
    }
    if (part_mngr->remaster_status == REMASTER_DONE || g_rc_ctx->status < REFORM_FROZEN ||
        g_rc_ctx->status >= REFORM_RECOVER_DONE) {
        CT_LOG_RUN_ERR("[DRC] receive instance(%u) recovery lock task ack, remaster status(%u), reform status(%u)",
                       receive_msg->head->src_inst, part_mngr->remaster_status, g_rc_ctx->status);
        mes_release_message_buf(receive_msg->buffer);
        return;
    }
    cm_atomic_inc(&remaster_mngr->recovery_complete_task_num);
    mes_release_message_buf(receive_msg->buffer);
}

static status_t dtc_check_send_page_info_msg(mes_message_t * msg)
{
    if (sizeof(msg_page_info_t) > msg->head->size) {
        return CT_ERROR;
    }
    msg_page_info_t *request = (msg_page_info_t *)msg->buffer;
    if (sizeof(msg_page_info_t) + request->count * sizeof(page_info_t) != msg->head->size) {
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

void drc_process_send_page_info(void *sess, mes_message_t *msg)
{
    if (dtc_check_send_page_info_msg(msg) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("msg is invalid, msg size %u.", msg->head->size);
        mes_release_message_buf(msg->buffer);
        return;
    }
    drc_part_mngr_t *part_mngr = DRC_PART_MNGR;
    knl_session_t *session = (knl_session_t *)sess;
    msg_page_info_t *req = (msg_page_info_t *)msg->buffer;
    uint32 count = req->count;

    if (g_dtc->profile.node_count <= 2) {  // node count 2
        CT_LOG_RUN_WAR("[DRC] this process is not involved in cluster with 2 nodes");
        mes_release_message_buf(msg->buffer);
        return;
    }
    if (part_mngr->remaster_status == REMASTER_DONE || g_rc_ctx->status < REFORM_FROZEN ||
        g_rc_ctx->status >= REFORM_RECOVER_DONE || count > DRC_PAGE_CACHE_INFO_BATCH_CNT ||
        req->head.src_inst >= g_dtc->profile.node_count || req->buffer_len != count * sizeof(page_info_t) ||
        req->head.size != sizeof(msg_page_info_t) + sizeof(page_info_t) * count) {
        CT_LOG_RUN_ERR("[DRC] receive instance(%u) recovery page task ack, remaster status(%u), reform status(%u), "
            "req count(%u), msg size(%u)",
            msg->head->src_inst, part_mngr->remaster_status, g_rc_ctx->status, count, req->head.size);
        mes_release_message_buf(msg->buffer);
        return;
    }

    uint32 *idx = cm_malloc(sizeof(uint32) * count);
    if (idx == NULL) {
        CT_LOG_RUN_ERR("alloc memory faild.");
        mes_release_message_buf(msg->buffer);
        return;
    }

    drc_rcy_page_info_l(msg->head->src_inst, msg->buffer + sizeof(msg_page_info_t), count, idx);

    cm_free(idx);

    DTC_DCS_DEBUG_INF("[DCS][%s]: succeeded, count=%u", MES_CMD2NAME(req->head.cmd), count);

    mes_message_head_t ack;
    mes_init_ack_head(&req->head, &ack, MES_CMD_SEND_PAGE_INFO_ACK, sizeof(mes_message_head_t), DCS_SELF_SID(session));
    mes_release_message_buf(msg->buffer);

    if (mes_send_data(&ack) == CT_SUCCESS) {
        DTC_DCS_DEBUG_INF("[DCS][dcs_process_send_page_info]: ack sent");
    } else {
        CT_LOG_RUN_ERR("[DCS][dcs_process_send_page_info]: failed to send ack");
    }
}

status_t drc_mes_send_connect_ready_msg(knl_session_t *session, uint8 dst_id)
{
    uint8 src_id = DRC_SELF_INST_ID;
    mes_message_head_t ack = {0};
    uint32 msg_size = sizeof(mes_message_head_t);
    mes_init_send_head(&ack, MES_CMD_BAK_RUNNING, msg_size, CT_INVALID_ID32,
        src_id, dst_id, session->id, CT_INVALID_ID16);
    if (mes_send_data(&ack) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[DRC] self id %d send ack to dst id %d failed, session id %d.", src_id, dst_id, session->id);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t drc_mes_recv_connect_ready_msg(knl_session_t *session)
{
    mes_message_t msg = {0};
    if (mes_recv_no_quick_stop(session->id, &msg, CT_FALSE, CT_INVALID_ID32, DRC_CHECK_FULL_CONNECT_SLEEP_INTERVAL) !=
        CT_SUCCESS) {
        CT_LOG_RUN_ERR("[DRC] failed to recv ack from session id %d.", session->id);
        return CT_ERROR;
    }

    if (SECUREC_UNLIKELY(msg.head->cmd != MES_CMD_BAK_RUNNING_ACK)) {
        CT_LOG_RUN_ERR("[DRC]node %d recv node %d ack cmd error", msg.head->src_inst, msg.head->dst_inst);
        mes_release_message_buf(msg.buffer);
        return CT_ERROR;
    }
    bool32 is_running = *(bool32 *)(msg.buffer + sizeof(mes_message_head_t));
    CT_LOG_RUN_INF("[DRC] recv ack data %d.", is_running);
    mes_release_message_buf(msg.buffer);
    return CT_SUCCESS;
}

status_t drc_mes_check_full_connection(uint8 instId)
{
    status_t ret = CT_ERROR;
    uint32 wait_times = 0;
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    knl_instance_t *kernel = ctx->kernel;
    knl_session_t *session = kernel->sessions[SESSION_ID_DRC_REMASTER];
    do {
        ret = drc_mes_send_connect_ready_msg(session, instId);
        if (ret != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[DRC] send msg to node %d failed, wait times %d ms.", instId, wait_times);
            cm_sleep(DRC_CHECK_FULL_CONNECT_SLEEP_INTERVAL);
            wait_times += DRC_CHECK_FULL_CONNECT_SLEEP_INTERVAL;
            continue;
        }

        ret = drc_mes_recv_connect_ready_msg(session);
        if (ret != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[DRC] recv msg from node %d failed, wait times %d ms.", instId, wait_times);
            cm_sleep(DRC_CHECK_FULL_CONNECT_SLEEP_INTERVAL);
            wait_times += DRC_CHECK_FULL_CONNECT_SLEEP_INTERVAL;
            continue;
        }
    } while (wait_times < DRC_CHECK_FULL_CONNECT_RETRY_TIMEOUT && ret != CT_SUCCESS);
    return ret;
}

status_t drc_lock_bucket_and_stat_with_version_check(knl_session_t *session, drid_t *lock_id, drc_res_bucket_t **bucket,
    spinlock_t **res_part_stat_lock, uint64 req_version, bool32 is_remaster)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    *bucket = drc_get_res_map_bucket(&ctx->global_lock_res.res_map, (char *)lock_id, sizeof(drid_t));
    uint32 part_id = drc_resource_id_hash((char *)lock_id, sizeof(drid_t), DRC_MAX_PART_NUM);
    *res_part_stat_lock = &ctx->global_lock_res.res_part_stat_lock[part_id];
    cm_spin_lock(*res_part_stat_lock, NULL);
    cm_spin_lock(&(*bucket)->lock, NULL);
    if (DRC_STOP_DLS_REQ_FOR_REFORMING(req_version, session) && !is_remaster) {
        drc_unlock_bucket_and_stat(*bucket, *res_part_stat_lock);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

void drc_unlock_bucket_and_stat(drc_res_bucket_t *bucket, spinlock_t *res_part_stat_lock)
{
    cm_spin_unlock(&bucket->lock);
    cm_spin_unlock(res_part_stat_lock);
}
