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
 * cms_instance.c
 *
 *
 * IDENTIFICATION
 * src/cms/cms/cms_instance.c
 *
 * -------------------------------------------------------------------------
 */

#include "cms_instance.h"
#include "cms_defs.h"
#include "cm_config.h"
#include "cms_gcc.h"
#include "cs_tcp.h"
#include "cms_msg_def.h"
#include "cms_uds_server.h"
#include "cms_work.h"
#include "cms_param.h"
#include "cms_comm.h"
#include "cms_stat.h"
#include "cm_file.h"
#include "cms_vote.h"
#include "cms_msgque.h"
#include "cms_blackbox.h"
#include "cm_io_record.h"
#include "cms_mes.h"
#include "cm_dbs_intf.h"
#include "mes_config.h"
#include "cms_log.h"
#include "cm_dbstore.h"

static cms_instance_t g_cms_instance = {.is_server = GS_FALSE};

cms_instance_t *g_cms_inst = &g_cms_instance;
static const char *g_cms_lock_file = "cms_server.lck";
cms_que_t g_hb_aync_gap_que = {0};

static status_t cms_init_queue_and_sync(void)
{
    if (cms_init_que(&g_cms_inst->recv_que) != GS_SUCCESS) {
        CMS_LOG_ERR("cms init recv que faild");
        return GS_ERROR;
    }
    if (cms_init_que(&g_cms_inst->send_que) != GS_SUCCESS) {
        CMS_LOG_ERR("cms init send que faild");
        return GS_ERROR;
    }
    if (cms_init_que(&g_cms_inst->cli_recv_que) != GS_SUCCESS) {
        CMS_LOG_ERR("cms init cli recv que faild");
        return GS_ERROR;
    }
    if (cms_init_que(&g_cms_inst->cli_send_que) != GS_SUCCESS) {
        CMS_LOG_ERR("cms init cli recv que faild");
        return GS_ERROR;
    }
    if (cms_init_que(&g_cms_inst->aync_write_que) != GS_SUCCESS) {
        CMS_LOG_ERR("cms init aync write que faild");
        return GS_ERROR;
    }
    if (cms_init_que(&g_cms_inst->cmd_recv_que) != GS_SUCCESS) {
        CMS_LOG_ERR("cms init cmd recv que faild");
        return GS_ERROR;
    }
    if (cms_init_que(&g_hb_aync_gap_que) != GS_SUCCESS) {
        CMS_LOG_ERR("cms init hb aync gap que faild");
        return GS_ERROR;
    }
    if (cms_sync_init(&g_cms_inst->try_master_sync) != GS_SUCCESS) {
        CMS_LOG_ERR("cms init try master sync faild");
        return GS_ERROR;
    }
    if (cm_event_init(&g_cms_inst->voting_sync) != GS_SUCCESS) {
        CMS_LOG_ERR("cms init voting sync faild");
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

status_t cms_instance_init(void)
{
    if (cms_node_is_invalid(g_cms_param->node_id)) {
        GS_THROW_ERROR(ERR_CMS_GCC_NODE_UNREGISTERED);
        CMS_LOG_ERR("cms node(%d) is invalid", g_cms_param->node_id);
        return GS_ERROR;
    }

    GS_RETURN_IFERR(cms_init_queue_and_sync());
    GS_RETURN_IFERR(cms_init_stat());

    return GS_SUCCESS;
}

static status_t cms_create_uds_threads(void)
{
    if (cm_create_thread(cms_uds_srv_listen_entry, GS_DFLT_THREAD_STACK_SIZE, NULL,
        &g_cms_inst->uds_listen_thread) != GS_SUCCESS) {
        CMS_LOG_ERR("cms create uds listen entry thread failed");
        return GS_ERROR;
    }

    if (cm_create_thread(cms_uds_srv_recv_entry, GS_DFLT_THREAD_STACK_SIZE, NULL,
        &g_cms_inst->uds_recv_thread) != GS_SUCCESS) {
        CMS_LOG_ERR("cms create uds recv entry thread failed");
        return GS_ERROR;
    }

    if (cm_create_thread(cms_uds_srv_send_entry, GS_DFLT_THREAD_STACK_SIZE, NULL,
        &g_cms_inst->uds_send_thread) != GS_SUCCESS) {
        CMS_LOG_ERR("cms create uds send entry thread failed");
        return GS_ERROR;
    }

    for (uint32 i = 0; i < g_cms_param->uds_worker_thread_count; i++) {
        if (cm_create_thread(cms_uds_worker_entry, GS_DFLT_THREAD_STACK_SIZE, NULL,
            &g_cms_inst->uds_work_thread[i]) != GS_SUCCESS) {
            CMS_LOG_ERR("cms create uds worker entry thread failed");
            return GS_ERROR;
        }
    }

    CMS_LOG_INF("cms create uds work entry success.");

    if (cm_create_thread(cms_uds_hb_entry, GS_DFLT_THREAD_STACK_SIZE, NULL,
        &g_cms_inst->uds_hb_thread) != GS_SUCCESS) {
        CMS_LOG_ERR("cms create hb worker entry thread failed");
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t cms_init_dbs_client(void)
{
    GS_RETURN_IFERR(dbs_init_lib());
    cm_dbs_cfg_s *cfg = cm_dbs_get_cfg();
    if (!cfg->enable) {
        GS_LOG_RUN_INF("dbstore is not enabled");
        return GS_SUCCESS;
    }

    const char* uuid = get_config_uuid(g_cms_param->node_id);
    uint32 lsid = get_config_lsid(g_cms_param->node_id);
    cm_set_dbs_uuid_lsid(uuid, lsid);

    GS_RETURN_IFERR(cm_dbs_init(g_cms_param->cms_home));
    return GS_SUCCESS;
}

static status_t cms_create_voting_threads(void)
{
    if (cm_dbs_is_enable_dbs() == GS_TRUE) {
        GS_RETURN_IFERR(cms_init_dbs_client());
    }
    GS_RETURN_IFERR(cms_vote_disk_init());
    if (g_cms_param->split_brain == CMS_OPEN_WITH_SPLIT_BRAIN) {
        if (cm_create_thread(cms_voting_entry, GS_DFLT_THREAD_STACK_SIZE, NULL,
            &g_cms_inst->voting_thread) != GS_SUCCESS) {
            CMS_LOG_ERR("cms create voting entry thread failed");
            return GS_ERROR;
        }

        if (cm_create_thread(cms_detect_voting_entry, GS_DFLT_THREAD_STACK_SIZE, NULL,
            &g_cms_inst->detect_voting_thread) != GS_SUCCESS) {
            CMS_LOG_ERR("cms create detect voting entry thread failed");
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t cms_create_check_disk_threads(void)
{
    if (cm_create_thread(cms_detect_disk_error_entry, GS_DFLT_THREAD_STACK_SIZE, NULL,
        &g_cms_inst->detect_disk_error_thread) != GS_SUCCESS) {
        CMS_LOG_ERR("cms create detect disk error entry thread failed");
        return GS_ERROR;
    }
    if (cm_create_thread(cms_judge_disk_error_entry, GS_DFLT_THREAD_STACK_SIZE, NULL,
        &g_cms_inst->judge_disk_error_thread) != GS_SUCCESS) {
        CMS_LOG_ERR("cms create judge disk error entry thread failed");
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

status_t cms_create_aync_write_thread(void)
{
    cms_res_stat_t *res_stat_disk;
    res_stat_disk = cm_malloc_align(CMS_BLOCK_SIZE, sizeof(cms_res_stat_t));
    if (res_stat_disk == NULL) {
        GS_THROW_ERROR(ERR_ALLOC_MEMORY, sizeof(cms_res_stat_t), "cms create stat aync write entry");
        return GS_ERROR;
    }
    if (cm_create_thread(cms_stat_aync_write_entry, GS_DFLT_THREAD_STACK_SIZE, res_stat_disk,
        &g_cms_inst->stat_aync_write_thread) != GS_SUCCESS) {
        CMS_LOG_ERR("cms create stat aync write entry thread failed");
        CM_FREE_PTR(res_stat_disk);
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

static status_t cms_create_threads(void)
{
    if (cm_create_thread(cms_mes_send_entry, GS_DFLT_THREAD_STACK_SIZE, NULL,
        &g_cms_inst->send_thread) != GS_SUCCESS) {
        CMS_LOG_ERR("cms create send entry thread failed");
        return GS_ERROR;
    }

    for (uint32 i = 0; i < g_cms_param->worker_thread_count; i++) {
        if (cm_create_thread(cms_worker_entry, GS_DFLT_THREAD_STACK_SIZE, NULL,
            &g_cms_inst->work_thread[i]) != GS_SUCCESS) {
            CMS_LOG_ERR("cms create worker entry thread failed");
            return GS_ERROR;
        }
    }

    if (cm_create_thread(cms_worker_entry, GS_DFLT_THREAD_STACK_SIZE, CMS_HB_WORKER_FLAG,
        &g_cms_inst->hb_worker_thread) != GS_SUCCESS) {
        CMS_LOG_ERR("cms create hb worker entry thread failed");
        return GS_ERROR;
    }

    if (cms_create_uds_threads() != GS_SUCCESS) {
        CMS_LOG_ERR("cms create uds threads failed");
        return GS_ERROR;
    }

    if (cm_create_thread(cmd_handle_entry, GS_DFLT_THREAD_STACK_SIZE, NULL,
        &g_cms_inst->cmd_handle_thread) != GS_SUCCESS) {
        CMS_LOG_ERR("cms create cmd worker entry thread failed");
        return GS_ERROR;
    }

    if (cm_create_thread(cms_hb_timer_entry, GS_DFLT_THREAD_STACK_SIZE, NULL,
        &g_cms_inst->hb_timer_thread) != GS_SUCCESS) {
        CMS_LOG_ERR("cms create hb timer entry thread failed");
        return GS_ERROR;
    }

    if (cm_create_thread(cms_res_check_timer_entry, GS_DFLT_THREAD_STACK_SIZE, NULL,
        &g_cms_inst->res_check_timer_thread) != GS_SUCCESS) {
        CMS_LOG_ERR("cms create res check timer entry thread failed");
        return GS_ERROR;
    }

    if (cm_create_thread(cms_gcc_loader_entry, GS_DFLT_THREAD_STACK_SIZE, NULL,
        &g_cms_inst->gcc_loader_thread) != GS_SUCCESS) {
        CMS_LOG_ERR("cms create gcc loader entry thread failed");
        return GS_ERROR;
    }

    if (cm_create_thread(cms_gcc_backup_entry, GS_DFLT_THREAD_STACK_SIZE, NULL,
        &g_cms_inst->gcc_backup_thread) != GS_SUCCESS) {
        CMS_LOG_ERR("cms create gcc backup entry thread failed");
        return GS_ERROR;
    }

    if (cms_create_aync_write_thread() != GS_SUCCESS) {
        CMS_LOG_ERR("cms create stat aync write entry thread failed");
        return GS_ERROR;
    }

    if (cms_create_voting_threads() != GS_SUCCESS) {
        CMS_LOG_ERR("cms create voting threads failed");
        return GS_ERROR;
    }

    if (cms_create_check_disk_threads() != GS_SUCCESS) {
        CMS_LOG_ERR("cms create check disk threads failed");
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t cms_close_threads(void)
{
    cm_close_thread(&g_cms_inst->send_thread);
    for (int32 i = 0; i < CMS_MAX_WORKER_THREAD_COUNT; i++) {
        cm_close_thread(&g_cms_inst->work_thread[i]);
    }
    cm_close_thread(&g_cms_inst->cmd_handle_thread);
    cm_close_thread(&g_cms_inst->hb_timer_thread);
    cm_close_thread(&g_cms_inst->res_check_timer_thread);
    cm_close_thread(&g_cms_inst->hb_worker_thread);
    cm_close_thread(&g_cms_inst->uds_send_thread);
    cm_close_thread(&g_cms_inst->uds_recv_thread);
    cm_close_thread(&g_cms_inst->uds_listen_thread);
    for (int32 i = 0; i < CMS_MAX_WORKER_THREAD_COUNT; i++) {
        cm_close_thread(&g_cms_inst->uds_work_thread[i]);
    }
    cm_close_thread(&g_cms_inst->uds_hb_thread);
    cm_close_thread(&g_cms_inst->gcc_loader_thread);
    cm_close_thread(&g_cms_inst->gcc_backup_thread);
    if (g_cms_param->split_brain == CMS_OPEN_WITH_SPLIT_BRAIN) {
        cm_close_thread(&g_cms_inst->voting_thread);
        cm_close_thread(&g_cms_inst->detect_voting_thread);
    }
    
    return GS_SUCCESS;
}

static status_t cms_lock_server(void)
{
    char file_name[CMS_FILE_NAME_BUFFER_SIZE] = { 0 };
    int32 ret;

    ret = snprintf_s(file_name, CMS_FILE_NAME_BUFFER_SIZE, CMS_MAX_FILE_NAME_LEN, "%s/%s",
        g_cms_param->cms_home, g_cms_lock_file);
    PRTS_RETURN_IFERR(ret);

    if (cm_open_file(file_name, O_CREAT | O_RDWR | O_BINARY | O_CLOEXEC | O_SYNC | O_DIRECT,
        &g_cms_inst->server_lock_fd) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return cm_lockw_file_fd(g_cms_inst->server_lock_fd);
}

static status_t cms_server_loop(void)
{
    g_cms_inst->server_loop = GS_TRUE;
    cms_trigger_voting();
    while (g_cms_inst->server_loop) {
        cms_try_be_master();
        cms_sync_wait(&g_cms_inst->try_master_sync, CMS_INST_TRY_MASTER_WAIT_TIME);
    }
    cm_sleep(CMS_INST_SERVER_SLEEP_TIME);
    return GS_SUCCESS;
}

void cms_do_try_master(void)
{
    cms_sync_notify(&g_cms_inst->try_master_sync);
}

static status_t cms_update_local_cfg(void)
{
    char port[8] = { 0 };
    errno_t ret;
    cms_node_def_t node_def;

    GS_RETURN_IFERR(cms_get_node_by_id(g_cms_param->node_id, &node_def));

    ret = sprintf_s(port, sizeof(port), "%u", node_def.port);
    PRTS_RETURN_IFERR(ret);

    GS_RETURN_IFERR(cms_update_param("_IP", node_def.ip));
    GS_RETURN_IFERR(cms_update_param("_PORT", port));

    return GS_SUCCESS;
}

status_t cms_startup(void)
{
    if (cms_lock_server() != GS_SUCCESS) {
        cm_reset_error();
        CMS_LOG_ERR("Another cms server is running");
        GS_THROW_ERROR(ERR_CMS_SERVER_RUNNING);
        return GS_ERROR;
    }

    g_cms_inst->is_server = GS_TRUE;
    GS_RETURN_IFERR(signal_cap_handle_reg());
    GS_RETURN_IFERR(cms_load_gcc());
    GS_RETURN_IFERR(cms_update_local_cfg());
    GS_RETURN_IFERR(cms_update_local_gcc());
    GS_RETURN_IFERR(cms_instance_init());
    GS_RETURN_IFERR(inc_stat_version());
    GS_RETURN_IFERR(record_io_stat_init());
    GS_RETURN_IFERR(cms_uds_srv_init());
    GS_RETURN_IFERR(cms_startup_mes());
    GS_RETURN_IFERR(cms_create_threads());
    GS_RETURN_IFERR(cms_server_loop());
    GS_RETURN_IFERR(cms_close_threads());
    return GS_SUCCESS;
}

void cms_shutdown(void)
{
    g_cms_inst->disk_thread.closed = GS_TRUE;
    g_cms_inst->send_thread.closed = GS_TRUE;
    for (int32 i = 0; i < CMS_MAX_WORKER_THREAD_COUNT; i++) {
        g_cms_inst->work_thread[i].closed = GS_TRUE;
    }
    g_cms_inst->cmd_handle_thread.closed = GS_TRUE;
    if (g_cms_param->split_brain == CMS_OPEN_WITH_SPLIT_BRAIN) {
        g_cms_inst->voting_thread.closed = GS_TRUE;
        g_cms_inst->detect_voting_thread.closed = GS_TRUE;
    }
    g_cms_inst->judge_disk_error_thread.closed = GS_TRUE;
    g_cms_inst->detect_disk_error_thread.closed = GS_TRUE;
}

static pthread_key_t        g_inst_local_var;
static pthread_once_t       g_inst_once = PTHREAD_ONCE_INIT;

static void inst_once_init()
{
    (void)pthread_key_create(&g_inst_local_var, NULL);
}

status_t cms_get_local_ctx(cms_local_ctx_t** ctx)
{
    (void)pthread_once(&g_inst_once, inst_once_init);

    cms_local_ctx_t* _ctx = (cms_local_ctx_t*)pthread_getspecific(g_inst_local_var);
    if (_ctx == NULL) {
        _ctx = (cms_local_ctx_t*)malloc(sizeof(cms_local_ctx_t));
        if (_ctx == NULL) {
            CMS_LOG_ERR("alloc memory failed. error code:%d,%s", errno, strerror(errno));
            return GS_ERROR;
        }

        _ctx->gcc_handle = -1;
        (void)pthread_setspecific(g_inst_local_var, _ctx);
    }

    if (_ctx->gcc_handle == -1) {
        GS_RETURN_IFERR(cm_open_disk(g_cms_param->gcc_home, &_ctx->gcc_handle));
        GS_LOG_DEBUG_INF("thread id %u, gcc handle %d, gcc %s", cm_get_current_thread_id(),
            _ctx->gcc_handle, g_cms_param->gcc_home);
    }

    *ctx = _ctx;
    return GS_SUCCESS;
}

status_t cms_send_srv_msg_to(uint16 node_id, cms_packet_head_t* msg)
{
    biqueue_node_t* node = cms_que_alloc_node(msg->msg_size);
    cms_packet_head_t* send_msg = (cms_packet_head_t*)cms_que_node_data(node);
    errno_t ret = memcpy_s(send_msg, msg->msg_size, msg, msg->msg_size);
    if (ret != EOK) {
        CMS_LOG_ERR("cms memcpy failed, src msg size %u, errno %d[%s]", msg->msg_size, cm_get_os_error(),
            strerror(errno));
        cms_que_free_node(node);
        return GS_ERROR;
    }
    send_msg->src_node = msg->dest_node;
    send_msg->dest_node = node_id;
    cms_enque(&g_cms_inst->send_que, node);
    return GS_SUCCESS;
}

status_t cms_broadcast_srv_msg(cms_packet_head_t* msg)
{
    status_t ret = GS_SUCCESS;
    uint32 node_count = cms_get_gcc_node_count();
    for (uint32 i = 0; i < node_count; i++) {
        if (cms_node_is_invalid(i)) {
            continue;
        }
        ret = cms_send_srv_msg_to(i, msg);
        if (ret != GS_SUCCESS) {
            CMS_LOG_ERR("cms send srv msg failed, ret %d, node id %u, msg type %u, msg seq %llu", ret,
                i, msg->msg_type, msg->msg_seq);
            return ret;
        }
    }
    return GS_SUCCESS;
}
