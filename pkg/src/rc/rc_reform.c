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
 * rc_reform.c
 *
 *
 * IDENTIFICATION
 * src/rc/rc_reform.c
 *
 * -------------------------------------------------------------------------
 */
#include "repl_log_replay.h"
#include "rc_module.h"
#include "rc_reform.h"
#include "cm_log.h"
#include "knl_database.h"
#include "knl_context.h"

reform_ctx_t *g_rc_ctx = NULL;
static cluster_view_t g_cluster_view = { .is_stable = CT_TRUE };
reform_callback_t g_rc_callback = {NULL, NULL, NULL, NULL, NULL, NULL};

void rc_update_cluster_view(cms_res_status_list_t *res_list)
{
    uint64 bit_map = 0;
    uint64 reform_bitmap = 0;
    for (uint8 ins_id = 0; ins_id < res_list->inst_count; ins_id++) {
        cms_res_status_t* cms_res = &res_list->inst_list[ins_id];
        if (cms_res != NULL && cms_res->stat == CMS_RES_ONLINE) {
            // not include leaving instance
            if (cms_res->work_stat == RC_JOINED) {
                rc_bitmap64_set(&bit_map, cms_res->inst_id);
            }
            // for reform, including joining and leaving node
            rc_bitmap64_set(&reform_bitmap, cms_res->inst_id);
        }
    }
    g_cluster_view.bitmap = bit_map;
    g_cluster_view.reform_bitmap = reform_bitmap;
    CT_LOG_DEBUG_INF("[RC] update cluster view(%llu), cluster view for reform (%llu)",
        g_cluster_view.bitmap, g_cluster_view.reform_bitmap);
    return;
}

// cms register functions
void rc_notify_cluster_change(cms_res_status_list_t *res_list)
{
    g_rc_ctx->info.fetch_cms_time = RC_TRY_FETCH_CMS;
    CT_LOG_RUN_INF_LIMIT(LOG_PRINT_INTERVAL_SECOND_20, "[RC] cms notify cluster change");
}

status_t rc_change_role(uint8 oper)
{
    // 1: upgrade to master; 2:downgrade from master
    return CT_SUCCESS;
}

// inner-use helper functions
bool32 check_id_in_list(uint8 inst_id, instance_list_t *list)
{
    for (uint8 i = 0; i < list->inst_id_count; i++) {
        if (inst_id == list->inst_id_list[i]) {
            return CT_TRUE;
        }
    }
    return CT_FALSE;
}

void add_id_to_list(uint8 inst_id, instance_list_t *list)
{
    list->inst_id_list[list->inst_id_count] = inst_id;
    list->inst_id_count++;
}

void rc_sprint_inst_list(char *dest, size_t dest_max, instance_list_t *list)
{
    for (uint8 i = 0; i < list->inst_id_count; i++) {
        sprintf_s(dest + 4 * i, dest_max - 4 * i, "%03d ", (int32)list->inst_id_list[i]);
    }
}

void rc_log_reform_info(reform_mode_t mode)
{
    char lists[REFORM_LIST_TYPE_COUNT][4 * CT_MAX_INSTANCES];
    char modestr[RC_MODE_STR_LENGTH];

    for (uint8 type = 0; type < REFORM_LIST_TYPE_COUNT; type++) {
        MEMS_RETVOID_IFERR(memset_sp(lists[type], 4 * CT_MAX_INSTANCES, 0, 4 * CT_MAX_INSTANCES));
        rc_sprint_inst_list(lists[type], 4 * CT_MAX_INSTANCES, &g_rc_ctx->info.reform_list[type]);
    }

    if (mode == REFORM_MODE_PLANED) {
        sprintf_s(modestr, RC_MODE_STR_LENGTH, RC_MODE_PLANED_STR);
    } else {
        sprintf_s(modestr, RC_MODE_STR_LENGTH, RC_MODE_OUT_OF_PLAN_STR);
    }

    CT_LOG_RUN_INF("[RC] start reform %s, current version:%lld, target version:%lld."
        "\n    current instance list:%s\n    target instance list:%s\n    join instance list:%s"
        "\n    leave instance list:%s\n    abort instance list:%s\n    fail instance list:%s"
        "\n", modestr, g_rc_ctx->info.version, g_rc_ctx->info.next_version, lists[REFORM_LIST_BEFORE],
        lists[REFORM_LIST_AFTER], lists[REFORM_LIST_JOIN], lists[REFORM_LIST_LEAVE], lists[REFORM_LIST_ABORT], lists[REFORM_LIST_FAIL]);
}

void rc_log_instance_list(instance_list_t *list, char *list_name)
{
    char list_str[4 * CT_MAX_INSTANCES];
    MEMS_RETVOID_IFERR(memset_sp(list_str, 4 * CT_MAX_INSTANCES, 0, 4 * CT_MAX_INSTANCES));
    rc_sprint_inst_list(list_str, 4 * CT_MAX_INSTANCES, list);
    CT_LOG_RUN_INF("[RC] %s instance list:%s", list_name, list_str);
}

void rc_init_inst_list(instance_list_t *list)
{
    list->inst_id_count = 0;
}

cms_res_status_list_t *rc_get_current_stat(void)
{
    return g_rc_ctx->clu_stat[g_rc_ctx->current_idx];
}

cms_res_status_list_t *rc_get_target_stat(void)
{
    return g_rc_ctx->clu_stat[1 - g_rc_ctx->current_idx];
}

cms_res_status_t *get_res_stat_by_inst_id(cms_res_status_list_t *list, uint8 inst_id)
{
    for (uint8 i = 0; i < list->inst_count; i++) {
        if (list->inst_list[i].inst_id == inst_id) {
            return &list->inst_list[i];
        }
    }
    return NULL;
}

reform_role_t rc_get_role(reform_info_t *info, uint8 id)
{
    if (check_id_in_list(id, &info->reform_list[REFORM_LIST_ABORT])) {
        return REFORM_ROLE_ABORT;
    } else if (check_id_in_list(id, &info->reform_list[REFORM_LIST_FAIL])) {
        return REFORM_ROLE_FAIL;
    } else if (check_id_in_list(id, &info->reform_list[REFORM_LIST_LEAVE])) {
        return REFORM_ROLE_LEAVE;
    } else if (check_id_in_list(id, &info->reform_list[REFORM_LIST_JOIN])) {
        return REFORM_ROLE_JOIN;
    } else {
        return REFORM_ROLE_STAY;
    }
}

reform_mode_t rc_get_change_mode(void)
{
    if (g_rc_ctx->info.reform_list[REFORM_LIST_ABORT].inst_id_count != 0 ||
        g_rc_ctx->info.reform_list[REFORM_LIST_FAIL].inst_id_count != 0) {
        return REFORM_MODE_OUT_OF_PLAN;
    }
    return REFORM_MODE_PLANED;
}

void rc_sleep_random(uint32 range)
{
    cm_sleep(cm_random(range));
}

void rc_reset_reform_stat()
{
    reform_stat_t *stat = &g_rc_ctx->reform_stat;

    stat->build_channel_elapsed = 0;
    stat->remaster_elapsed = 0;
    stat->recovery_elapsed = 0;
    stat->deposit_elapsed = 0;
    reform_detail_t *reform_detail = &g_rc_ctx->reform_detail;
    (void)memset_sp(reform_detail, sizeof(reform_detail_t), 0, sizeof(reform_detail_t));
}

// interaction with CMS, control functions
void rc_check_abort_in_loop(void)
{
    // this instance kick-out from cluster
    cms_res_status_list_t tmp_current_stat;

    if (cms_get_res_stat_list1(g_rc_ctx->res_type, &tmp_current_stat) == CT_SUCCESS) {
        cms_res_status_t *self_stat = get_res_stat_by_inst_id(&tmp_current_stat, g_rc_ctx->self_id);

        if (self_stat == NULL || self_stat->stat != CMS_RES_ONLINE) {
            CM_ABORT_REASONABLE(0,
                "[RC] ABORT INFO: self abort, notified by CMS kick-out from cluster, version is %llu.",
                tmp_current_stat.version);
        }
    }
}

bool32 rc_refresh_alive_bitmap(cms_res_status_list_t *res_list)
{
    uint64 bit_map = 0;
    uint64 old_map = g_rc_ctx->info.alive_bitmap;

    for (uint8 ins_id = 0; ins_id < res_list->inst_count; ins_id++) {
        cms_res_status_t* cms_res = &res_list->inst_list[ins_id];
        if (cms_res != NULL && cms_res->stat == CMS_RES_ONLINE) {
            // not include leaving instance
            if (cms_res->work_stat == RC_JOINED) {
                rc_bitmap64_set(&bit_map, cms_res->inst_id);
            }
        }
    }

    g_rc_ctx->info.alive_bitmap = bit_map;

    return old_map != bit_map;
}

bool32 rc_wait_reformer_trigger(void)
{
    uint64 trigger_version = 0;
    if (CT_SUCCESS == cms_get_res_data(RC_REFORM_TRIGGER_VERSION, (char*)&trigger_version, sizeof(uint64), NULL)) {
        if (trigger_version > g_rc_ctx->info.trigger_version) {
            // JOIN/LEAVE node receive new reform trigger during REFORM_IN_PROGRESS, exit
            if (RC_REFORM_IN_PROGRESS && g_rc_ctx->info.role == REFORM_ROLE_JOIN) {
                CM_ABORT_REASONABLE(0, "ABORT INFO: receive reformer trigger, trigger verion(%llu), reform is failed during "
                               "current JOIN reform", trigger_version);
            }
            if (g_rc_ctx->info.role == REFORM_ROLE_LEAVE) {
                CM_ABORT_REASONABLE(0, "ABORT INFO: receive reformer trigger, trigger version(%llu), reform is failed during "
                               "current LEAVE reform", trigger_version);
            }

            g_rc_ctx->info.trigger_version = trigger_version;
            CT_LOG_RUN_INF("[RC] inst %u receive reformer trigger, trigger_version %llu", g_rc_ctx->self_id,
                g_rc_ctx->info.trigger_version);
            return CT_TRUE;
        }
    }
    return CT_FALSE;
}

void rc_reformer_trigger(void)
{
    if (!rc_is_master()) {
        return;
    }
    CT_LOG_RUN_INF("[RC] reformer %u current trigger_version=%llu",
        g_rc_ctx->self_id, g_rc_ctx->info.trigger_version);
    reform_mode_t mode = rc_get_change_mode();
    if (mode == REFORM_MODE_OUT_OF_PLAN) {
        if (g_rc_ctx->info.role == REFORM_ROLE_JOIN) {
            CM_ABORT_REASONABLE(0, "ABORT INFO: other node abort during the reformer joining process");
        }
        if (g_rc_ctx->info.role == REFORM_ROLE_LEAVE) {
            CM_ABORT_REASONABLE(0, "ABORT INFO: other node abort during the reformer leaving process");
        }
    }
    g_rc_ctx->info.trigger_version += 1;
    RC_RETRY_IF_ERROR(cms_set_res_data(RC_REFORM_TRIGGER_VERSION, (char*)&g_rc_ctx->info.trigger_version, sizeof(uint64)));
    CT_LOG_RUN_INF("[RC] reformer %u send trigger, trigger_version %llu",
        g_rc_ctx->self_id, g_rc_ctx->info.trigger_version);
}

bool32 rc_master_stat_changed(void)
{
    if (RC_REFORM_IN_PROGRESS) {
        CT_LOG_DEBUG_INF("[RC] reform in progress");
        return CT_FALSE;
    }

    if (cms_get_res_data(RC_CMS_REMOTE_CURRENT, (char*)rc_get_current_stat(), sizeof(cms_res_status_list_t), NULL)) {
        rc_sleep_random(RC_RETRY_SLEEP);
        return CT_FALSE;
    }

    if (cms_get_res_stat_list(rc_get_target_stat()) != CT_SUCCESS) {
        rc_sleep_random(RC_RETRY_SLEEP);
        return CT_FALSE;
    }

    if (rc_refresh_alive_bitmap(rc_get_target_stat())) {
        rc_refresh_cms_abort_ref_map(g_rc_ctx->info.alive_bitmap);
    }

    // TODO:  cluster is quiet, but not steady
    if (g_rc_ctx->info.have_error ||
        (RC_REFORM_NOT_IN_PROGRESS && !g_rc_ctx->info.cluster_steady && g_rc_ctx->info.fetch_cms_time == 0)) {
        CT_LOG_RUN_INF("[RC] cluster stat changed, have_error(%u), reform status(%u), cluster_steady(%u), "
                       "fetch_cms_time(%u)", g_rc_ctx->info.have_error, g_rc_ctx->status,
                       g_rc_ctx->info.cluster_steady, g_rc_ctx->info.fetch_cms_time);
        RC_RETRY_IF_ERROR(
            cms_set_res_data(RC_CMS_REMOTE_TARGET, (char *)rc_get_target_stat(), sizeof(cms_res_status_list_t)));
        g_rc_ctx->info.have_error = CT_FALSE;
        return CT_TRUE;
    }

    if (RC_REFORM_IN_PROGRESS) {
        if (rc_get_target_stat()->version <= g_rc_ctx->info.version) {
            return CT_FALSE;
        }
    }

    if (rc_get_target_stat()->version <= rc_get_current_stat()->version) {
        return CT_FALSE;
    }

    RC_RETRY_IF_ERROR(cms_set_res_data(RC_CMS_REMOTE_TARGET, (char*)rc_get_target_stat(), sizeof(cms_res_status_list_t)));
    return CT_TRUE;
}

bool32 rc_follower_stat_changed(void)
{
    // wait here
    if (!rc_wait_reformer_trigger()) {
        return CT_FALSE;
    }
 
    if (cms_get_res_data(RC_CMS_REMOTE_CURRENT, (char*)rc_get_current_stat(), sizeof(cms_res_status_list_t), NULL)) {
        rc_sleep_random(RC_RETRY_SLEEP);
        g_rc_ctx->info.trigger_version = 0;
        return CT_FALSE;
    }
 
    if (cms_get_res_data(RC_CMS_REMOTE_TARGET, (char*)rc_get_target_stat(), sizeof(cms_res_status_list_t), NULL)) {
        rc_sleep_random(RC_RETRY_SLEEP);
        g_rc_ctx->info.trigger_version = 0;
        return CT_FALSE;
    }
 
    if (rc_get_target_stat()->version < rc_get_current_stat()->version) {
        return CT_FALSE;
    }
    return CT_TRUE;
}

bool32 rc_cluster_stat_changed(void)
{
    bool32 is_master = rc_is_master();
    if (!is_master) {
        return rc_follower_stat_changed();
    }
    return rc_master_stat_changed();
}

void rc_refresh_cluster_info(void)
{
    cms_res_status_list_t tmp_current_stat;

    // refresh master info from cms, instead of master_node(which maybe gone)
    for (;;) {
        // TODO: optimise with CMS, reduce the traffic load
        if (cms_get_res_stat_list1(g_rc_ctx->res_type, &tmp_current_stat)) {
            cm_sleep(10);
            continue;
        }

        // got correct master
        if (tmp_current_stat.master_inst_id != CT_INVALID_ID8) {
            break;
        }

        // this instance kick-out from cluster, and no other suitable instance can be master
        cms_res_status_t *self_stat = get_res_stat_by_inst_id(&tmp_current_stat, g_rc_ctx->self_id);

        if (self_stat == NULL || self_stat->stat != CMS_RES_ONLINE) {
            CM_ABORT_REASONABLE(0,
                "[RC] ABORT INFO: self abort, notified by CMS kick-out from cluster, version is %llu.",
                tmp_current_stat.version);
        }

        // cluster voting one master now, loop wait
        cm_sleep(10);
    }

    g_rc_ctx->info.master_changed = (g_rc_ctx->info.master_id == tmp_current_stat.master_inst_id) ?
                                    g_rc_ctx->info.master_changed : CT_TRUE;
    if (RC_REFORM_IN_PROGRESS) {
        if (g_rc_ctx->info.master_id != tmp_current_stat.master_inst_id) {
            CM_ABORT_REASONABLE(0, "ABORT INFO: res reformer changed in refrom progress, old reformer %d, new reformer %d",
                tmp_current_stat.master_inst_id, g_rc_ctx->info.master_id);
        }
    }
    if (g_rc_ctx->info.master_changed) {
        g_rc_ctx->info.standby_get_txn = CT_FALSE;
    }
    g_rc_ctx->info.master_id = tmp_current_stat.master_inst_id;

    // refresh self info from cms
    bool8 full_restart = CT_TRUE;
    bool8 kill_self = CT_TRUE;
    for (uint8 i = 0; i < tmp_current_stat.inst_count; i++) {
        if (tmp_current_stat.inst_list[i].stat == CMS_RES_ONLINE && tmp_current_stat.inst_list[i].work_stat ==
            RC_JOINED) {
            full_restart = CT_FALSE;
        }
        if (g_rc_ctx->self_id == tmp_current_stat.inst_list[i].inst_id && tmp_current_stat.inst_list[i].stat ==
            CMS_RES_ONLINE) {
            kill_self = CT_FALSE;
        }
    }

    if (kill_self) {
        CM_ABORT_REASONABLE(0, "[RC] ABORT INFO: self abort, notified by CMS kick-out from cluster, version is %llu.",
            tmp_current_stat.version);
    }

    g_rc_ctx->info.full_restart = full_restart;
}

bool32 rc_is_master(void)
{
#ifndef DTC_RUN_WITH_REFORM
        return (g_rc_ctx->self_id == 0) ? CT_TRUE : CT_FALSE;
#endif

    // wait if not get master_id info yet
    while (CT_INVALID_ID8 == g_rc_ctx->info.master_id) {
        cm_sleep(10);
    }

    return (g_rc_ctx->info.master_id == g_rc_ctx->self_id);
}

bool32 rc_is_full_restart(void)
{
    return g_rc_ctx->info.full_restart;
}

// reform run-time functions
void reset_reform_info(bool32 init)
{
    for (uint8 type = 0; type < REFORM_LIST_TYPE_COUNT; type++) {
        rc_init_inst_list(&g_rc_ctx->info.reform_list[type]);
    }

    if (init) {
        g_rc_ctx->info.version = 0;
        g_rc_ctx->info.next_version = 0;
        g_rc_ctx->info.trigger_version = 0;
        g_rc_ctx->info.alive_bitmap = 0;

        g_rc_ctx->info.master_id = CT_INVALID_ID8;
        g_rc_ctx->info.fetch_cms_time = 0;

        g_rc_ctx->info.master_changed = CT_TRUE;
        g_rc_ctx->info.full_restart = CT_FALSE;
        g_rc_ctx->info.cluster_steady = CT_TRUE;
        g_rc_ctx->info.have_error = CT_FALSE;
        g_rc_ctx->info.standby_get_txn = CT_FALSE;
    }
}

status_t reform_mutex_create(mes_mutex_t *mutex)
{
    if (0 != pthread_mutex_init(mutex, NULL)) {
        CT_THROW_ERROR_EX(ERR_MES_CREATE_MUTEX, "errno: %d", (int32)errno);
        return CT_ERROR;
    }
 
    (void)pthread_mutex_lock(mutex);
    return CT_SUCCESS;
}
 
void reform_mutex_unlock(mes_mutex_t *mutex)
{
    (void)pthread_mutex_unlock(mutex);
}
 
void reform_get_timespec(struct timespec *timespec, uint32 timeout)
{
    struct timespec cur_time;
    (void)clock_gettime(CLOCK_REALTIME, &cur_time);
 
    timespec->tv_sec = cur_time.tv_sec + timeout / MILLISECS_PER_SECOND;
    timespec->tv_nsec = cur_time.tv_nsec + ((long)timeout % MILLISECS_PER_SECOND) * MICROSECS_PER_SECOND;
    if (timespec->tv_nsec >= NANOSECS_PER_SECOND) {
        timespec->tv_sec++;
        timespec->tv_nsec -= NANOSECS_PER_SECOND;
    }
}

bool32 reform_mutex_timed_lock(mes_mutex_t *mutex, uint32 timeout)
{
    struct timespec ts;
    reform_get_timespec(&ts, timeout);
    return (pthread_mutex_timedlock(mutex, &ts) == 0);
}

status_t rc_reset_cms_cluster_info(void)
{
    CT_LOG_RUN_INF("[RC] cluster full restart, reset cms cluster info");

    // reset abort ref map
    uint64 bitmap = 0;
    CT_RETURN_IFERR(cms_set_res_data(RC_CMS_ABORT_REF_MAP, (char *)&bitmap, sizeof(bitmap)));

    // get latest
    CT_RETURN_IFERR(cms_get_res_stat_list1(g_rc_ctx->res_type, rc_get_current_stat()));

    // reset remote_current/ remote_target area
    CT_RETURN_IFERR(
        cms_set_res_data(RC_CMS_REMOTE_CURRENT, (char *)rc_get_current_stat(), sizeof(cms_res_status_list_t)));
    CT_RETURN_IFERR(
        cms_set_res_data(RC_CMS_REMOTE_TARGET, (char *)rc_get_current_stat(), sizeof(cms_res_status_list_t)));

    uint64 version = 0;
    CT_RETURN_IFERR(cms_set_res_data(RC_REFORM_TRIGGER_VERSION, (char *)&version, sizeof(version)));

    return CT_SUCCESS;
}

void rc_init_redo_stat(void)
{
    rc_redo_stat_t *redo_stat = &g_rc_ctx->redo_stat;

    CT_INIT_SPIN_LOCK(redo_stat->lock);
    redo_stat->ckpt_num = 0;
    redo_stat->redo_stat_cnt = 0;
    redo_stat->redo_stat_start_ind = 0;

    uint64 reset_size = sizeof(rc_redo_stat_list_t) * CKPT_LOG_REDO_STAT_COUNT;
    MEMS_RETVOID_IFERR(memset_s(redo_stat->stat_list, reset_size, 0, reset_size));
}

static status_t init_reform_ctx(reform_init_t *init_st)
{
    g_rc_ctx->started = CT_FALSE;
    reset_reform_info(CT_TRUE);
    char *buf;
    buf = (char *)malloc(2 * sizeof(struct st_cms_res_status_list_t));
    if (buf == NULL) {
        CT_LOG_RUN_ERR("init_reform_ctx malloc buf failed.");
        return CT_ERROR;
    }
    g_rc_ctx->clu_stat[0] = (cms_res_status_list_t *)buf;
    g_rc_ctx->clu_stat[1] = (cms_res_status_list_t *)(buf + sizeof(struct st_cms_res_status_list_t));
    g_rc_ctx->session = init_st->session;
    g_rc_ctx->self_id = init_st->self_id;
    if (sprintf_s(g_rc_ctx->res_type, CMS_MAX_RES_TYPE_LEN, init_st->res_type) == CT_ERROR) {
        CT_LOG_RUN_ERR("init_reform_ctx sprintf_s res_type failed.");
        return CT_ERROR;
    }
    g_rc_ctx->status = REFORM_PREPARE;
    g_rc_ctx->mode = REFORM_MODE_NONE;
    g_rc_ctx->current_idx = 0;

    rc_init_redo_stat();
    return CT_SUCCESS;
}

status_t init_cms_rc(reform_ctx_t *rf_ctx, reform_init_t *init_st)
{
    // here is g_rc_ctx first use
    g_rc_ctx = rf_ctx;
    if (init_reform_ctx(init_st) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("init_reform_ctx failed.");
        return CT_ERROR;
    }
    if (reform_mutex_create(&g_rc_ctx->reform_mutex) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("reform_mutex_create failed.");
        return CT_ERROR;
    }

    if (0 != pthread_mutex_init(&g_rc_ctx->trigger_mutex, NULL)) {
        CT_LOG_RUN_ERR("trigger_mutex_create failed. errno: %d", (int32)errno);
        return CT_ERROR;
    }
    g_rc_callback = init_st->callback;

#ifndef DTC_RUN_WITH_REFORM
    return CT_SUCCESS;
#endif
    res_init_info_t res_init_info;
    CT_RETURN_IFERR(cms_cli_init());
    CT_RETURN_IFERR(cms_res_inst_register(g_rc_ctx->res_type, g_rc_ctx->self_id, &res_init_info,
        (cms_notify_func_t)rc_notify_cluster_change, (cms_master_op_t)rc_change_role));

    rc_refresh_cluster_info();

    if (rc_is_full_restart()) {
        // cluster full restart, master set all instance work stat as joining��reset remote_current/ remote_target
        // area
        if (rc_is_master()) {
            RC_RETRY_IF_ERROR(rc_reset_cms_cluster_info());
        } else {
            CT_LOG_RUN_ERR("Multiple nodes cannot be added to the CMS at the same time without a master node.");
            return CT_ERROR;
        }
    } else {
        g_rc_ctx->is_blocked = CT_TRUE;
        g_rc_ctx->info.trigger_version = res_init_info.trigger_version;
        errno_t ret = memcpy_s((char *)rc_get_current_stat(), sizeof(cms_res_status_list_t),
            (char *)&res_init_info.res_stat, sizeof(cms_res_status_list_t));
        MEMS_RETURN_IFERR(ret);
    }
    CT_LOG_RUN_INF("g_rc_ctx->info.trigger_version=%llu", g_rc_ctx->info.trigger_version);
    if (CT_SUCCESS != cm_create_thread(rc_reform_trigger_proc, 0, g_rc_ctx->session, &g_rc_ctx->trigger_thread)) {
        return CT_ERROR;
    }

    if (CT_SUCCESS != cm_create_thread(rc_reform_proc, 0, g_rc_ctx->session, &g_rc_ctx->thread)) {
        cm_close_thread(&g_rc_ctx->trigger_thread);
        return CT_ERROR;
    }

    g_rc_ctx->started = CT_TRUE;
    // triger reform start
    RC_RETRY_IF_ERROR(cms_set_res_work_stat(RC_JOINING));

    return CT_SUCCESS;
}

void free_cms_rc(bool32 force)
{
    if (g_rc_ctx == NULL || g_rc_ctx->started == CT_FALSE) {
        return;
    }

    if (!force) {
        // TODO another node abort when current node shutdown normal
        uint64_t current_version = g_rc_ctx->info.next_version;
        RC_RETRY_IF_ERROR(cms_set_res_work_stat(RC_LEAVING));

        while ((current_version == g_rc_ctx->info.next_version) ||
               (g_rc_ctx->info.version != g_rc_ctx->info.next_version) ||
               (g_rc_ctx->status < REFORM_DONE)) {
            cm_sleep(10);
            continue;
        }
    }

    // close thread before unregister, avoid check abort assert
    cm_close_thread(&g_rc_ctx->trigger_thread);
    cm_close_thread(&g_rc_ctx->thread);
}

void rc_current_stat_step_forward(void)
{
    g_rc_ctx->current_idx = 1 - g_rc_ctx->current_idx;

    if (rc_is_master()) {
        RC_RETRY_IF_ERROR(cms_set_res_data(RC_CMS_REMOTE_CURRENT, (char*)rc_get_current_stat(), sizeof(struct st_cms_res_status_list_t)));
    }
}

// reform state-machine, [CMS_STATE_PRIOR][CMS_STATE_NEXT][RC_WORK_STATE_PRIOR][RC_WORK_STATE_NEXT]
reform_action_info_t g_reform_sm[RC_CMS_STATE_COUNT][RC_CMS_STATE_COUNT][RC_WORK_STATE_COUNT][RC_WORK_STATE_COUNT] = {
    { // from: ONLINE
        { // from: ONLINE to: ONLINE
            { // from: ONLINE JONING   to: ONLINE
                {{REFORM_LIST_AFTER,  REFORM_LIST_JOIN},  2, CT_TRUE,  CT_FALSE}, // from: ONLINE JOINING to: ONLINE JOINING
                {{REFORM_LIST_BEFORE, REFORM_LIST_AFTER}, 2, CT_FALSE, CT_FALSE}, // from: ONLINE JOINING to: ONLINE JOINED
                {{}, 0, CT_FALSE, CT_TRUE},                                       // from: ONLINE JOINING to: ONLINE LEAVING, can not happen
                {{}, 0, CT_FALSE, CT_TRUE}                                        // from: ONLINE JOINING to: ONLINE LEFT,    can not happen
            },
            { // from: ONLINE JOINED   to: ONLINE
                {{REFORM_LIST_BEFORE, REFORM_LIST_ABORT}, 2, CT_TRUE,  CT_FALSE}, // from: ONLINE JOINED  to: ONLINE JOINING, abort and restart
                {{REFORM_LIST_BEFORE, REFORM_LIST_AFTER}, 2, CT_FALSE, CT_FALSE}, // from: ONLINE JOINED  to: ONLINE JOINED
                {{REFORM_LIST_BEFORE, REFORM_LIST_LEAVE}, 2, CT_TRUE,  CT_FALSE}, // from: ONLINE JOINED  to: ONLINE LEAVING
                {{}, 0, CT_FALSE, CT_TRUE}                                        // from: ONLINE JOINED  to: ONLINE LEFT,    can not happen
            },
            { // from: ONLINE LEAVING  to: ONLINE
                {{REFORM_LIST_BEFORE, REFORM_LIST_ABORT}, 2, CT_TRUE,  CT_FALSE}, // from: ONLINE LEAVING to: ONLINE JOINING, abort and restart
                {{REFORM_LIST_AFTER}, 1, CT_FALSE, CT_FALSE},                     // from: ONLINE LEAVING to: ONLINE JOINED,  reform happend
                {{REFORM_LIST_BEFORE, REFORM_LIST_LEAVE}, 2, CT_TRUE,  CT_FALSE}, // from: ONLINE LEAVING to: ONLINE LEAVING
                {{REFORM_LIST_BEFORE}, 1, CT_FALSE, CT_FALSE}                     // from: ONLINE LEAVING to: ONLINE LEFT
            },
            { // from: ONLINE LEFT     to: ONLINE
                {{REFORM_LIST_JOIN,   REFORM_LIST_AFTER}, 2, CT_TRUE, CT_FALSE},  // from: ONLINE LEFT    to: ONLINE JOINING
                {{REFORM_LIST_AFTER}, 1, CT_FALSE, CT_FALSE},                     // from: ONLINE LEFT    to: ONLINE JOINED,  reform happend
                {{}, 0, CT_FALSE, CT_TRUE},                                       // from: ONLINE LEFT    to: ONLINE LEAVING, can not happen
                {{ REFORM_LIST_BEFORE}, 1, CT_FALSE, CT_FALSE}                    // from: ONLINE LEFT    to: ONLINE LEFT
            }
        },
        { // from: ONLINE to: OFFLINE
            { // from: ONLINE JONING   to: OFFLINE
                {{REFORM_LIST_FAIL},  1, CT_TRUE,  CT_FALSE},                     // from: ONLINE JOINING to: OFFLINE JOINING
                {{}, 0, CT_FALSE, CT_TRUE},                                       // from: ONLINE JOINING to: OFFLINE JOINED,  can not happen
                {{}, 0, CT_FALSE, CT_TRUE},                                       // from: ONLINE JOINING to: OFFLINE LEAVING, can not happen
                {{}, 0, CT_FALSE, CT_TRUE}                                        // from: ONLINE JOINING to: OFFLINE LEFT,    can not happen
            },
            { // from: ONLINE JOINED   to: OFFLINE
                {{REFORM_LIST_BEFORE, REFORM_LIST_ABORT}, 2, CT_TRUE, CT_FALSE},  // from: ONLINE JOINED  to: OFFLINE JOINING
                {{}, 0, CT_FALSE, CT_TRUE},                                       // from: ONLINE JOINED  to: OFFLINE JOINED,  can not happen
                {{}, 0, CT_FALSE, CT_TRUE},                                       // from: ONLINE JOINED  to: OFFLINE LEAVING, can not happen
                {{}, 0, CT_FALSE, CT_TRUE}                                        // from: ONLINE JOINED  to: OFFLINE LEFT,    can not happen
            },
            { // from: ONLINE LEAVING  to: OFFLINE
                {{REFORM_LIST_BEFORE, REFORM_LIST_ABORT}, 2, CT_TRUE, CT_FALSE},  // from: ONLINE LEAVING to: OFFLINE JOINING
                {{}, 0, CT_FALSE, CT_TRUE},                                       // from: ONLINE LEAVING to: OFFLINE JOINED,  can not happen
                {{}, 0, CT_FALSE, CT_TRUE},                                       // from: ONLINE LEAVING to: OFFLINE LEAVING, can not happen
                {{}, 0, CT_FALSE, CT_TRUE}                                        // from: ONLINE LEAVING to: OFFLINE LEFT,    can not happen
            },
            { // from: ONLINE LEFT     to: OFFLINE
                {{}, 0, CT_FALSE, CT_FALSE},                                      // from: ONLINE LEFT    to: OFFLINE JOINING
                {{}, 0, CT_FALSE, CT_TRUE},                                       // from: ONLINE LEFT    to: OFFLINE JOINED,  can not happen
                {{}, 0, CT_FALSE, CT_TRUE},                                       // from: ONLINE LEFT    to: OFFLINE LEAVING, can not happen
                {{}, 0, CT_FALSE, CT_TRUE}                                        // from: ONLINE LEFT    to: OFFLINE LEFT,    can not happen
            }
        }
    },
    { // from: OFFLINE
        { // from: OFFLINE to: ONLINE
            { // from: OFFLINE JOINING  to: ONLINE
                {{REFORM_LIST_AFTER, REFORM_LIST_JOIN}, 2, CT_TRUE,  CT_FALSE},   // from: OFFLINE JOINING to: ONLINE JOINING
                {{REFORM_LIST_AFTER}, 1, CT_FALSE, CT_FALSE},                     // from: OFFLINE JOINING to: ONLINE JOINED,  reform happend
                {{}, 0, CT_FALSE, CT_TRUE},                                       // from: OFFLINE JOINING to: ONLINE LEAVING, can not happen
                {{}, 0, CT_FALSE, CT_TRUE}                                        // from: OFFLINE JOINING to: ONLINE LEFT,    can not happen
            },
            { // from: OFFLINE JOINED   to: ONLINE
                {{}, 0, CT_FALSE, CT_TRUE},                                       // from: OFFLINE JOINED  to: ONLINE JOINING, can not happen
                {{}, 0, CT_FALSE, CT_TRUE},                                       // from: OFFLINE JOINED  to: ONLINE JOINED , can not happen
                {{}, 0, CT_FALSE, CT_TRUE},                                       // from: OFFLINE JOINED  to: ONLINE LEAVING, can not happen
                {{}, 0, CT_FALSE, CT_TRUE}                                        // from: OFFLINE JOINED  to: ONLINE LEFT,    can not happen
            },
            { // from: OFFLINE LEAVING  to: ONLINE
                {{}, 0, CT_FALSE, CT_TRUE},                                       // from: OFFLINE LEAVING to: ONLINE JOINING, can not happen
                {{}, 0, CT_FALSE, CT_TRUE},                                       // from: OFFLINE LEAVING to: ONLINE JOINED,  can not happen
                {{}, 0, CT_FALSE, CT_TRUE},                                       // from: OFFLINE LEAVING to: ONLINE LEAVING, can not happen
                {{}, 0, CT_FALSE, CT_TRUE}                                        // from: OFFLINE LEAVING to: ONLINE LEFT,    can not happen
            },
            { // from: OFFLINE LEFT     to: ONLINE
                {{}, 0, CT_FALSE, CT_TRUE},                                       // from: OFFLINE LEFT    to: ONLINE JOINING, can not happen
                {{}, 0, CT_FALSE, CT_TRUE},                                       // from: OFFLINE LEFT    to: ONLINE JOINED,  can not happen
                {{}, 0, CT_FALSE, CT_TRUE},                                       // from: OFFLINE LEFT    to: ONLINE LEAVING, can not happen
                {{}, 0, CT_FALSE, CT_TRUE}                                        // from: OFFLINE LEFT    to: ONLINE LEFT,    can not happen
            }
        },
        { // from: OFFLINE to: OFFLINE
            { // from: OFFLINE JOINING  to: OFFLINE
                {{}, 0, CT_FALSE, CT_FALSE},                                      // from: OFFLINE JOINING to: OFFLINE JOINING
                {{}, 0, CT_FALSE, CT_TRUE},                                       // from: OFFLINE JOINING to: OFFLINE JOINED,  can not happen
                {{}, 0, CT_FALSE, CT_TRUE},                                       // from: OFFLINE JOINING to: OFFLINE LEAVING, can not happen
                {{}, 0, CT_FALSE, CT_TRUE}                                        // from: OFFLINE JOINING to: OFFLINE LEFT,    can not happen
            },
            { // from: OFFLINE JOINED   to: OFFLINE
                {{}, 0, CT_FALSE, CT_TRUE},                                       // from: OFFLINE JOINED  to: OFFLINE JOINING, can not happen
                {{}, 0, CT_FALSE, CT_TRUE},                                       // from: OFFLINE JOINED  to: OFFLINE JOINED,  can not happen
                {{}, 0, CT_FALSE, CT_TRUE},                                       // from: OFFLINE JOINED  to: OFFLINE LEAVING, can not happen
                {{}, 0, CT_FALSE, CT_TRUE}                                        // from: OFFLINE JOINED  to: OFFLINE LEFT,    can not happen
            },
            { // from: OFFLINE LEAVING  to: OFFLINE
                {{}, 0, CT_FALSE, CT_TRUE},                                       // from: OFFLINE LEAVING to: OFFLINE JOINING, can not happen
                {{}, 0, CT_FALSE, CT_TRUE},                                       // from: OFFLINE LEAVING to: OFFLINE JOINED,  can not happen
                {{}, 0, CT_FALSE, CT_TRUE},                                       // from: OFFLINE LEAVING to: OFFLINE LEAVING, can not happen
                {{}, 0, CT_FALSE, CT_TRUE}                                        // from: OFFLINE LEAVING to: OFFLINE LEFT,    can not happen
            },
            { // from: OFFLINE LEFT     to: OFFLINE
                {{}, 0, CT_FALSE, CT_TRUE},                                       // from: OFFLINE LEFT    to: OFFLINE JOINING, can not happen
                {{}, 0, CT_FALSE, CT_TRUE},                                       // from: OFFLINE LEFT    to: OFFLINE JOINED,  can not happen
                {{}, 0, CT_FALSE, CT_TRUE},                                       // from: OFFLINE LEFT    to: OFFLINE LEAVING, can not happen
                {{}, 0, CT_FALSE, CT_TRUE}                                        // from: OFFLINE LEFT    to: OFFLINE LEFT,    can not happen
            }
        }
    }
};

void rc_repair_leaving_state(uint8 inst_id, reform_cms_state_t *pre_cms_state,  reform_work_state_t *pre_wk_state,
                             reform_cms_state_t *next_cms_state, reform_work_state_t *next_wk_state);


bool32 rc_get_reform_info(void)
{
    bool32 member_change = CT_FALSE;
    uint8 inst_count = rc_get_target_stat()->inst_count > rc_get_current_stat()->inst_count ? rc_get_target_stat()->inst_count : rc_get_current_stat()->inst_count;

    reset_reform_info(CT_FALSE);
    cms_res_status_t *pre_stat, *next_stat;

    for (uint8 ins_id = 0; ins_id < inst_count; ins_id++) {
        pre_stat = get_res_stat_by_inst_id(rc_get_current_stat(), ins_id);
        next_stat  = get_res_stat_by_inst_id(rc_get_target_stat(),  ins_id);
        if (pre_stat == NULL && next_stat == NULL) {
            continue;
        }

        reform_cms_state_t pre_cms_state   = (pre_stat  == NULL ? RC_CMS_OFFLINE : (pre_stat->stat  == CMS_RES_ONLINE ? RC_CMS_ONLINE : RC_CMS_OFFLINE));
        reform_cms_state_t next_cms_state  = (next_stat == NULL ? RC_CMS_OFFLINE : (next_stat->stat == CMS_RES_ONLINE ? RC_CMS_ONLINE : RC_CMS_OFFLINE));

        reform_work_state_t pre_wk_state  = pre_stat  == NULL ? RC_JOINING : pre_stat->work_stat;
        reform_work_state_t next_wk_state = next_stat == NULL ? RC_JOINING : next_stat->work_stat;

        rc_repair_leaving_state(ins_id, &pre_cms_state, &pre_wk_state, &next_cms_state, &next_wk_state);

        reform_action_info_t action = g_reform_sm[pre_cms_state][next_cms_state][pre_wk_state][next_wk_state];

        if (action.happen_assert) {
            CT_LOG_RUN_ERR("[RC] get an impossible state to handle, p_cms_state is %d, n_cms_state is %d, p_wk_state is %d, n_wk_state is %d \n",
                           pre_cms_state, next_cms_state, pre_wk_state, next_wk_state);
        }

        member_change = action.member_change ? CT_TRUE : member_change;

        for (uint8 list_idx = 0; list_idx < action.enque_count; list_idx++) {
            reform_list_type_t list = action.enque_list[list_idx];
            add_id_to_list(ins_id, &g_rc_ctx->info.reform_list[list]);
        }
    }

    g_rc_ctx->info.version      = rc_get_current_stat()->version;
    g_rc_ctx->info.next_version = rc_get_target_stat()->version;
    g_rc_ctx->info.role = rc_get_role(&g_rc_ctx->info, g_rc_ctx->self_id);
    g_rc_ctx->info.cluster_steady = !member_change;

    return member_change;
}

void rc_set_cms_abort_ref_map(uint8 inst_id, reform_work_state_t state)
{
    uint64 bit_map = 0;
    if (state != RC_JOINED && state != RC_LEFT) {
        return;
    }

    uint64 version = 0;
    status_t err = CT_SUCCESS;

    for (;;) {
        err = cms_get_res_data_new(RC_CMS_ABORT_REF_MAP, (char*)&bit_map, sizeof(uint64), NULL, &version);
        if (err != CT_SUCCESS) {
            rc_sleep_random(RC_RETRY_SLEEP);
            rc_check_abort_in_loop();
            continue;
        }

        if (state == RC_JOINED) {
            rc_bitmap64_set(&bit_map, inst_id);
        }
        if (state == RC_LEFT) {
            rc_bitmap64_clear(&bit_map, inst_id);
        }

        err = cms_set_res_data_new(RC_CMS_ABORT_REF_MAP, (char*)&bit_map, sizeof(uint64), version);
        if (err != CT_SUCCESS) {
            CT_LOG_RUN_INF("[RC] set cms_abort_ref_map faild, version is %llu", version);
            rc_sleep_random(RC_RETRY_SLEEP);
            rc_check_abort_in_loop();
            continue;
        }

        CT_LOG_RUN_INF("[RC] instance %d changed, set RC_CMS_ABORT_REF_MAP to %llu", inst_id, bit_map);
        return;
    }
}

void rc_refresh_cms_abort_ref_map(uint64 alive_bitmap)
{
    uint64 abort_bitmap = 0;
    if (CT_SUCCESS == cms_get_res_data(RC_CMS_ABORT_REF_MAP, (char*)&abort_bitmap, sizeof(uint64), NULL)) {
        // alive_bitmap is cms real-time detect joined instances, abort_bitmap may remain leaving-abort instance
        // rc_set_cms_abort_ref_map have no concurrency control protect, set-left lost is ok, but set-joined lost bring bug
        if (alive_bitmap ^ abort_bitmap) {
            uint64 tmp_bitmap = abort_bitmap;
            // append joined bit to rc_set_cms_abort_ref_map, make up lost set-joined actions
            abort_bitmap |= alive_bitmap;
            cms_set_res_data(RC_CMS_ABORT_REF_MAP, (char*)&abort_bitmap, sizeof(uint64));
            CT_LOG_RUN_WAR("[RC] repaired RC_CMS_ABORT_REF_MAP, alive_bitmap is %llu, abort_bitmap before is %llu after is %llu", alive_bitmap, tmp_bitmap, abort_bitmap);
        }
    }
}

void rc_repair_leaving_state(uint8 inst_id, reform_cms_state_t *pre_cms_state, reform_work_state_t *pre_wk_state,
                             reform_cms_state_t *next_cms_state, reform_work_state_t *next_wk_state)
{
    if (*pre_cms_state != RC_CMS_ONLINE || *pre_wk_state != RC_LEAVING) {
        return;
    }

    if (*next_cms_state != RC_CMS_OFFLINE || *next_wk_state != RC_JOINING) {
        return;
    }

    uint64 abort_bitmap = 0;
    if (CT_SUCCESS == cms_get_res_data(RC_CMS_ABORT_REF_MAP, (char*)&abort_bitmap, sizeof(uint64), NULL)) {
        if (!rc_bitmap64_exist(&abort_bitmap, inst_id)) {
            // instace have set-left
            *pre_wk_state = RC_LEFT;
        }
    }
}

static void wait_alive_bitmap_stable(void)
{
    bool32 has_joining;
    cms_res_status_list_t target_res_stat;
    do {
        has_joining = CT_FALSE;
        RC_RETRY_IF_ERROR(cms_get_res_stat_list(&target_res_stat));
        for (int i = 0; i < target_res_stat.inst_count; i++) {
            if (target_res_stat.inst_list[i].stat == CMS_RES_ONLINE &&
                target_res_stat.inst_list[i].work_stat == RC_JOINING) {
                has_joining = CT_TRUE;
                break;
            }
        }
    } while (has_joining);
    cm_latch_x(&g_cluster_view.latch, 0, NULL);
    g_cluster_view.is_stable = CT_TRUE;
    g_cluster_view.is_joining = CT_FALSE;
    rc_update_cluster_view(&target_res_stat);
    CT_LOG_RUN_INF("[RC] wait bitmap stable: update cluster view, bitmap:%llu, reform_bitmap:%llu, version:%llu, "
        " is_joining:%d, is_stable:%d", g_cluster_view.bitmap, g_cluster_view.reform_bitmap, g_cluster_view.version,
        g_cluster_view.is_joining, g_cluster_view.is_stable);
    cm_unlatch(&g_cluster_view.latch, NULL);
}

void rc_sync_cluster_view(knl_session_t *session)
{
    // in 4 nodes, need extra work to finish
    if (g_rc_ctx->info.role == REFORM_ROLE_STAY) {
        wait_alive_bitmap_stable();
        rc_notify_reform_status(session, &g_rc_ctx->info, REFORM_DONE);
        return;
    }

    if (!rc_is_master() && g_rc_ctx->info.role == REFORM_ROLE_JOIN) {
        wait_alive_bitmap_stable();
        while (g_rc_ctx->in_view_sync) {
            cm_sleep(10); // check status every 10ms
        }
        return;
    }
    wait_alive_bitmap_stable();
}

void rc_check_finished(thread_t *thread)
{
    if (!g_rc_callback.finished()) {
        return;
    }

    if (g_rc_callback.release_channel != NULL) {
        g_rc_callback.release_channel(&g_rc_ctx->info);
    }
    while (g_rc_ctx->is_blocked) {
        if (thread->closed) {
            return;
        }
        cm_sleep(10);  // check status every 10ms
    }
    switch (g_rc_ctx->info.role) {
        case REFORM_ROLE_JOIN:
            g_rc_ctx->in_view_sync = rc_is_master() ? CT_FALSE : CT_TRUE;
            RC_RETRY_IF_ERROR(cms_set_res_work_stat(RC_JOINED));
            rc_set_cms_abort_ref_map(g_rc_ctx->self_id, RC_JOINED);
            break;
        case REFORM_ROLE_LEAVE:
            cms_set_res_work_stat(RC_LEFT);
            rc_set_cms_abort_ref_map(g_rc_ctx->self_id, RC_LEFT);
            break;
        default:
            break;
    }
    knl_session_t *session = (knl_session_t *)thread->argument;
    rc_sync_cluster_view(session);
    rc_current_stat_step_forward();

    if (!DB_IS_PRIMARY(&session->kernel->db) && g_rc_callback.rc_start_lrpl_proc != NULL) {
        g_rc_callback.rc_start_lrpl_proc(session);
    }

    g_rc_ctx->status = REFORM_DONE;
    CT_LOG_RUN_INF("[RC] finish reform, reform status:%u, mode:%u, master_changed:%u,", g_rc_ctx->status,
        g_rc_ctx->mode, g_rc_ctx->info.master_changed);
    g_rc_ctx->mode = REFORM_MODE_NONE;
    g_rc_ctx->info.master_changed = CT_FALSE;
}

void rc_wait_cms_notify(void)
{
    if (RC_REFORM_IN_PROGRESS) {
        // reduce RTO, no sleep
        return;
    }

    // triggerd once, cluster is not steady, may change soon
    if (SECUREC_UNLIKELY(g_rc_ctx->info.fetch_cms_time > 0) && SECUREC_UNLIKELY(g_rc_ctx->info.fetch_cms_time != RC_TRY_FETCH_CMS)) {
        cm_sleep(1000);
        g_rc_ctx->info.fetch_cms_time -= 1;
        return;
    }

    int64 remain_wait_time = RC_WAIT_CMS_NOTIFY_TIME;

    while (SECUREC_LIKELY(g_rc_ctx->info.fetch_cms_time == 0) && SECUREC_LIKELY(remain_wait_time >= 0)) {
        cm_sleep(10);
        remain_wait_time -= 10;
    }
}

status_t rc_start_reform(reform_mode_t mode)
{
    rc_log_reform_info(mode);
    CT_LOG_RUN_INF("[RC] start reform, reform status:%u, current version:%llu, next version:%llu.",
                   g_rc_ctx->status, g_rc_ctx->info.version, g_rc_ctx->info.next_version);

    CT_RETURN_IFERR(g_rc_callback.start_new_reform(mode));
    g_rc_ctx->mode = mode;
    g_rc_ctx->info.version = g_rc_ctx->info.next_version;
    CT_LOG_RUN_INF("[RC] reform successfully, reform mode:%u, reform status:%u, current version:%llu.",
                   mode, g_rc_ctx->status, g_rc_ctx->info.version);
    return CT_SUCCESS;
}

bool32 rc_get_check_inst_alive(uint32_t inst_id)
{
    uint32_t current_version = rc_get_current_stat()->version;
    uint32_t target_version = rc_get_target_stat()->version;
    if (current_version >= target_version) {
        return rc_get_current_stat()->inst_list[inst_id].stat == CMS_RES_ONLINE;
    } else {
        return rc_get_target_stat()->inst_list[inst_id].stat == CMS_RES_ONLINE;
    }
}

void rc_reform_trigger_enable(void)
{
    reform_mutex_unlock(&g_rc_ctx->trigger_mutex);
    CT_LOG_RUN_INF("[RC] reform trigger stat changed to enable");
    return;
}

bool32 rc_reform_trigger_disable(void)
{
    bool32 ret = CT_FALSE;
    do {
        if (!reform_mutex_timed_lock(&g_rc_ctx->trigger_mutex, RC_TRIGGER_MUTEX_WAIT_TIMEOUT)) {
            break;
        }

        if (RC_REFORM_IN_PROGRESS || (rc_get_target_stat()->version > rc_get_current_stat()->version)) {
            rc_reform_trigger_enable();
            break;
        }
        ret = CT_TRUE;
    } while (0);
    CT_LOG_RUN_INF("[RC] cluster trigger disable, ret = %d, reform status:%u, current_version:%llu, next_version:%llu,"
                   " trigger_version=%llu", ret, g_rc_ctx->status, g_rc_ctx->info.version, g_rc_ctx->info.next_version,
                   g_rc_ctx->info.trigger_version);
    return ret;
}

bool32 rc_detect_reform_triggered(void)
{
    if (rc_cluster_stat_changed()) {
        if (RC_REFORM_IN_PROGRESS) {
            CT_LOG_RUN_INF("[RC] cluster stat changed, reform in progress, reform status:%u, "
                           "g_rc_ctx->info.version:%llu", g_rc_ctx->status, g_rc_ctx->info.version);
            return CT_FALSE;
        }
        if (!rc_get_reform_info()) {
            rc_current_stat_step_forward();
            return CT_FALSE;
        }

        rc_reformer_trigger();
        cm_latch_x(&g_cluster_view.latch, 0, NULL);
        g_cluster_view.is_stable = CT_FALSE;
        g_cluster_view.version = rc_get_target_stat()->version;
        rc_update_cluster_view(rc_get_target_stat());
        if (g_rc_ctx->info.reform_list[REFORM_LIST_BEFORE].inst_id_count != 0 &&
            g_rc_ctx->info.reform_list[REFORM_LIST_JOIN].inst_id_count != 0) {
            g_cluster_view.is_joining = CT_TRUE;
            // have node living and have node joining, bitmap is not stable
        }
        CT_LOG_RUN_INF("[RC] detect reform triggerred: update cluster view, bitmap:%llu, reform bitmap:%llu, "
            "version:%llu, is_joining:%d, is_stable:%d", g_cluster_view.bitmap, g_cluster_view.reform_bitmap,
            g_cluster_view.version, g_cluster_view.is_joining, g_cluster_view.is_stable);
        cm_unlatch(&g_cluster_view.latch, NULL);
        reform_mutex_unlock(&g_rc_ctx->reform_mutex);
    }
    return CT_TRUE;
}

void rc_reform_trigger_proc(thread_t *thread)
{
    while (!thread->closed) {
        rc_refresh_cluster_info();
        if (g_rc_ctx->info.have_error) {
            g_rc_callback.stop_cur_reform();
        }
        if (!reform_mutex_timed_lock(&g_rc_ctx->trigger_mutex, RC_TRIGGER_MUTEX_WAIT_TIMEOUT)) {
            CT_LOG_RUN_WAR("[RC] reform trigger stat is disable");
            continue;
        }
        if (!rc_detect_reform_triggered()) {
            reform_mutex_unlock(&g_rc_ctx->trigger_mutex);
            continue;
        }
        reform_mutex_unlock(&g_rc_ctx->trigger_mutex);
        rc_wait_cms_notify();
    }
    CT_LOG_RUN_INF("[RC] reform trigger thread is closed");
}

void rc_reform_proc(thread_t *thread)
{
    status_t ret = CT_SUCCESS;
    uint32 fail_count = 0;
    knl_session_t *session = (knl_session_t *)thread->argument;
    while (!thread->closed) {
        if (!reform_mutex_timed_lock(&g_rc_ctx->reform_mutex, RC_REFORM_PROC_WAIT_TIMEOUT)) {
            continue;
        }
        reform_mode_t mode = rc_get_change_mode();
        while ((mode == REFORM_MODE_OUT_OF_PLAN) && !DB_IS_OPEN(session)) {
            cm_sleep(RC_WAIT_DB_OPEN_TIME);
            CT_LOG_RUN_INF("[RC] db is not open, db_status:%u, refrom status:%u", session->kernel->db.status,
                g_rc_ctx->status);
        }
        ret = rc_start_reform(mode);
        if (ret == CT_SUCCESS) {
            fail_count = 0;
            rc_check_finished(thread);
            g_rc_ctx->info.have_error = CT_FALSE;
        } else if (ret == CT_ERROR) {
            fail_count++;
            CT_LOG_RUN_ERR("[RC] reform failed, reform status:%d, fail_cout:%u",
                           g_rc_ctx->status, fail_count);
            if (g_rc_callback.rc_reform_cancled()) {
                CT_LOG_RUN_ERR("[RC] reform failed, rc reform cancled");
                break;
            }
            if (mode == REFORM_MODE_PLANED && rc_is_master()) {
                rc_current_stat_step_forward();
                // offline joining->online joining, next reform online joining->online joining
                // online joined->online leaving, next reform online leaving->online leaving
                CT_LOG_RUN_INF("[RC] reform failed, current stat step forward");
            }
            // JOIN/LEAVE node reform have error, exit
            if (g_rc_ctx->info.role == REFORM_ROLE_JOIN) {
                CM_ABORT_REASONABLE(0, "ABORT INFO: current JOIN reform is failed");
            }
            if (g_rc_ctx->info.role == REFORM_ROLE_LEAVE) {
                CM_ABORT_REASONABLE(0, "ABORT INFO: current LEAVE reform is failed");
            }
            g_rc_ctx->info.have_error = CT_TRUE;
        }
    }
    CT_LOG_RUN_INF("[RC] reform thread is closed");
}

void rc_get_cluster_view(cluster_view_t *view, bool32 need_stable)
{
#ifndef DTC_RUN_WITH_REFORM
    view->version = 0;
    view->bitmap = 0;
    view->is_stable = CT_TRUE;
    return;
#endif
    while (need_stable && g_cluster_view.is_joining) {
        cm_sleep(RC_RETRY_SLEEP);
    }
    cm_latch_s(&g_cluster_view.latch, 0, CT_FALSE, NULL);
    view->version = g_cluster_view.version;
    view->is_stable = g_cluster_view.is_stable;
    view->bitmap = g_cluster_view.bitmap;
    cm_unlatch(&g_cluster_view.latch, NULL);
    return;
}

void rc_get_cluster_view4reform(cluster_view_t *view)
{
#ifndef DTC_RUN_WITH_REFORM
    view->version = 0;
    view->bitmap = 0;
    view->is_stable = CT_TRUE;
    return;
#endif
    cm_latch_s(&g_cluster_view.latch, 0, CT_FALSE, NULL);
    view->version = g_cluster_view.version;
    view->is_stable = g_cluster_view.is_stable;
    view->bitmap = g_cluster_view.reform_bitmap;
    cm_unlatch(&g_cluster_view.latch, NULL);
    return;
}

bool32 rc_is_cluster_changed(cluster_view_t *prev_view)
{
    CT_RETVALUE_IFTRUE((prev_view == NULL), CT_TRUE);
    // cluster status has changed
    if (prev_view->version < g_cluster_view.version) {
        CT_LOG_RUN_WAR("prev_ver=%llu, curr_ver=%llu", prev_view->version, g_cluster_view.version);
        return CT_TRUE;
    }

    if (prev_view->bitmap != g_cluster_view.bitmap) {
        CT_LOG_RUN_WAR("prev_view=%llu, curr_view=%llu", prev_view->bitmap, g_cluster_view.bitmap);
        return CT_TRUE;
    }
    return CT_FALSE;
}

void rc_allow_reform_finish(void)
{
    // is_blocked is used to block "set workstat" operation, to
    // avoid other node to see this node in cluster view;
    // is_blocked will be set only at first join, and not full restart;
    // when allowed to update workstat, other node may see this node soon;
    g_rc_ctx->is_blocked = CT_FALSE;
}

uint64 get_alive_bitmap_by_reform_info(reform_info_t *reform_info)
{
    uint64 alive_bitmap = 0;
    uint8 *inst_id_list = RC_REFORM_LIST(reform_info, REFORM_LIST_AFTER).inst_id_list;
    uint32 task_num = RC_REFORM_LIST_COUNT(reform_info, REFORM_LIST_AFTER);
    for (uint32 i = 0; i < task_num; i++) {
        rc_bitmap64_set(&alive_bitmap, inst_id_list[i]);
    }
    inst_id_list = RC_REFORM_LIST(reform_info, REFORM_LIST_LEAVE).inst_id_list;
    task_num = RC_REFORM_LIST_COUNT(reform_info, REFORM_LIST_LEAVE);
    for (uint32 i = 0; i < task_num; i++) {
        rc_bitmap64_set(&alive_bitmap, inst_id_list[i]);
    }
    return alive_bitmap;
}

status_t rc_broadcast_change_status(knl_session_t *session, reform_info_t *rc_info, bool32 status)
{
    if (!DB_IS_CLUSTER(session)) {
        return CT_ERROR;
    }
    status_t ret;
    rc_reform_status_notify_t msg;
    uint64 alive_bitmap = get_alive_bitmap_by_reform_info(rc_info);

    mes_init_send_head(&msg.head, MES_CMD_BROADCAST_CHANGE_STATUS, sizeof(rc_reform_status_notify_t), CT_INVALID_ID32,
                       g_rc_ctx->self_id, 0, session->id, CT_INVALID_ID16);
    msg.change_status = status;
    msg.reform_trigger_version = rc_info->trigger_version;

    CT_LOG_RUN_INF("[RC] start boradcast reform status[%u] to inst bitmap[%llu]", status, alive_bitmap);
    ret = mes_broadcast_data_and_wait_with_retry_allow_send_fail(session->id, alive_bitmap, (const void *)&msg,
        RC_BCAST_CHANGE_STATUS_TIMEOUT, REFORM_SEND_MSG_RETRY_TIMES);
    CT_LOG_RUN_INF("[RC] broadcast reform status[%u] finish, ret(%d), alive_bitmap(%llu)", status, ret, alive_bitmap);

    return ret;
}

status_t rc_mes_send_data_with_retry(const char *msg, uint64 interval, uint64 retry_time)
{
    const mes_message_head_t *head = (const mes_message_head_t *)msg;
    uint8 dst_inst = head->dst_inst;
    if (dst_inst >= CT_MAX_INSTANCES) {
        CT_LOG_RUN_ERR("[RC] The dst instance(%u) is invalid.", dst_inst);
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
        if (!rc_bitmap64_exist(&alive_bitmap, dst_inst)) {
            CT_LOG_RUN_ERR("[RC] The dst instance(%u) is not alive(%llu).", dst_inst, alive_bitmap);
            return CT_ERROR;
        }
        cm_sleep(interval);
        retry++;
    }
    CT_LOG_RUN_ERR("[RC] Failed to send message(%u --> %u).", head->src_inst, dst_inst);
    return CT_ERROR;
}

void rc_accept_status_change(void *sess, mes_message_t *receive_msg)
{
    if (sizeof(rc_reform_status_notify_t) != receive_msg->head->size) {
        CT_LOG_RUN_ERR("msg is invalid, msg size %u.", receive_msg->head->size);
        mes_release_message_buf(receive_msg->buffer);
        return;
    }
    rc_reform_status_notify_t *notify = (rc_reform_status_notify_t*)receive_msg->buffer;
    uint32 cur_status = g_rc_ctx->status;
    status_t ret = CT_SUCCESS;
    if (notify->reform_trigger_version < g_rc_ctx->info.trigger_version) {
        ret = CT_ERROR;
        CT_LOG_RUN_INF("[RC] receive bcast reform status, do not update, curr status=%u, notify status=%u, curr reform"
                       " trigger version=%llu, notify reform trigger version=%llu, ret=%d", cur_status,
                       notify->change_status, g_rc_ctx->info.trigger_version, notify->reform_trigger_version, ret);
    } else if (notify->change_status <= g_rc_ctx->status) {
        CT_LOG_RUN_INF("[RC] receive bcast reform status, current status already updated, curr status=%u, notify "
                       "status=%u, curr reform trigger version=%llu, notify reform trigger version=%llu", cur_status,
                       notify->change_status, g_rc_ctx->info.trigger_version, notify->reform_trigger_version);
    } else {
        switch (notify->change_status) {
            case REFORM_RECOVER_DONE:
                g_rc_ctx->status = REFORM_RECOVER_DONE;
                break;
            case REFORM_DONE:
                if (!g_rc_ctx->in_view_sync || g_rc_ctx->status >= REFORM_DONE) {
                    CT_LOG_RUN_ERR("[RC] accept status change failed, in_view_sync(%d), reform status(%d)",
                        g_rc_ctx->in_view_sync, g_rc_ctx->status);
                }
                g_rc_ctx->in_view_sync = CT_FALSE;
                ret = CT_ERROR;
                break;
            default:
                CT_LOG_RUN_ERR("[RC] unexpected status=%u", notify->change_status);
                ret = CT_ERROR;
                break;
        }
    }
    CT_LOG_RUN_INF("[RC] process broadcast reform status proc, curr=%u, next:%u, notify=%u, ret=%d",
                   cur_status, g_rc_ctx->status, notify->change_status, ret);

    mes_message_head_t ack_head = {0};
    knl_session_t *session = (knl_session_t *)sess;
    mes_init_ack_head(receive_msg->head, &ack_head, MES_CMD_BROADCAST_ACK, sizeof(mes_message_head_t), session->id);
    ack_head.status = ret;
    ret = rc_mes_send_data_with_retry((const char*)&ack_head, REFORM_SLEEP_INTERVAL, REFORM_SEND_MSG_RETRY_TIMES);

    CT_LOG_RUN_INF("[DRC] send process broadcast reform status ack success, inst_id=%d, sid=%u, dst_inst=%d, "
                   "dst_sid=%u, status=%d, rsn=%u, ret=%d", ack_head.src_inst, ack_head.src_sid, ack_head.dst_inst,
                   ack_head.dst_sid, ack_head.status, ack_head.rsn, ret);

    mes_release_message_buf(receive_msg->buffer);
}

status_t rc_notify_reform_status(knl_session_t *session, reform_info_t *rc_info, uint32 status)
{
    knl_panic(status <= REFORM_DONE);
    status_t ret = rc_broadcast_change_status((knl_session_t*)session, rc_info, status);
    CT_LOG_RUN_INF("[RC] drc_broadcast_change_status ret=%d, curr=%u, notify=%u", ret, g_rc_ctx->status, status);
    return ret;
}

status_t rc_set_redo_replay_done(knl_session_t *session, reform_info_t *rc_info, bool32 full_recovery)
{
    if (!DB_IS_PRIMARY(&session->kernel->db) && full_recovery && !DB_NOT_READY(session)) {
        return CT_SUCCESS;
    }
    knl_panic(g_rc_ctx->status < REFORM_RECOVER_DONE);
    g_rc_ctx->status = REFORM_RECOVER_DONE;
    return rc_notify_reform_status(session, rc_info, REFORM_RECOVER_DONE);
}

