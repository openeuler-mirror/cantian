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
 * cms_instance.c
 *
 *
 * IDENTIFICATION
 * src/cms/cms/cms_instance.c
 *
 * -------------------------------------------------------------------------
 */
#include "cms_log_module.h"
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

static cms_instance_t g_cms_instance = {.is_server = CT_FALSE, .is_dbstor_cli_init = CT_FALSE};

cms_instance_t *g_cms_inst = &g_cms_instance;
static const char *g_cms_lock_file = "cms_server.lck";
cms_que_t g_hb_aync_gap_que = {0};

static status_t cms_init_queue_and_sync(void)
{
    if (cms_init_que(&g_cms_inst->recv_que) != CT_SUCCESS) {
        CMS_LOG_ERR("cms init recv que faild");
        return CT_ERROR;
    }
    if (cms_init_que(&g_cms_inst->send_que) != CT_SUCCESS) {
        CMS_LOG_ERR("cms init send que faild");
        return CT_ERROR;
    }
    if (cms_init_que(&g_cms_inst->cli_recv_que) != CT_SUCCESS) {
        CMS_LOG_ERR("cms init cli recv que faild");
        return CT_ERROR;
    }
    if (cms_init_que(&g_cms_inst->cli_send_que) != CT_SUCCESS) {
        CMS_LOG_ERR("cms init cli recv que faild");
        return CT_ERROR;
    }
    if (cms_init_que(&g_cms_inst->aync_write_que) != CT_SUCCESS) {
        CMS_LOG_ERR("cms init aync write que faild");
        return CT_ERROR;
    }
    if (cms_init_que(&g_cms_inst->cmd_recv_que) != CT_SUCCESS) {
        CMS_LOG_ERR("cms init cmd recv que faild");
        return CT_ERROR;
    }
    if (cms_init_que(&g_hb_aync_gap_que) != CT_SUCCESS) {
        CMS_LOG_ERR("cms init hb aync gap que faild");
        return CT_ERROR;
    }
    if (cms_sync_init(&g_cms_inst->try_master_sync) != CT_SUCCESS) {
        CMS_LOG_ERR("cms init try master sync faild");
        return CT_ERROR;
    }
    if (cm_event_init(&g_cms_inst->voting_sync) != CT_SUCCESS) {
        CMS_LOG_ERR("cms init voting sync faild");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t cms_instance_init(void)
{
    if (cms_node_is_invalid(g_cms_param->node_id)) {
        CT_THROW_ERROR(ERR_CMS_GCC_NODE_UNREGISTERED);
        CMS_LOG_ERR("cms node(%d) is invalid", g_cms_param->node_id);
        return CT_ERROR;
    }

    CT_RETURN_IFERR(cms_init_queue_and_sync());
    CT_RETURN_IFERR(cms_init_stat());

    return CT_SUCCESS;
}

static status_t cms_create_uds_threads(void)
{
    if (cm_create_thread(cms_uds_srv_listen_entry, CT_DFLT_THREAD_STACK_SIZE, NULL,
        &g_cms_inst->uds_listen_thread) != CT_SUCCESS) {
        CMS_LOG_ERR("cms create uds listen entry thread failed");
        return CT_ERROR;
    }

    if (cm_create_thread(cms_uds_srv_recv_entry, CT_DFLT_THREAD_STACK_SIZE, NULL,
        &g_cms_inst->uds_recv_thread) != CT_SUCCESS) {
        CMS_LOG_ERR("cms create uds recv entry thread failed");
        return CT_ERROR;
    }

    if (cm_create_thread(cms_uds_srv_send_entry, CT_DFLT_THREAD_STACK_SIZE, NULL,
        &g_cms_inst->uds_send_thread) != CT_SUCCESS) {
        CMS_LOG_ERR("cms create uds send entry thread failed");
        return CT_ERROR;
    }

    for (uint32 i = 0; i < g_cms_param->uds_worker_thread_count; i++) {
        if (cm_create_thread(cms_uds_worker_entry, CT_DFLT_THREAD_STACK_SIZE, NULL,
            &g_cms_inst->uds_work_thread[i]) != CT_SUCCESS) {
            CMS_LOG_ERR("cms create uds worker entry thread failed");
            return CT_ERROR;
        }
    }

    CMS_LOG_INF("cms create uds work entry success.");

    if (cm_create_thread(cms_uds_hb_entry, CT_DFLT_THREAD_STACK_SIZE, NULL,
        &g_cms_inst->uds_hb_thread) != CT_SUCCESS) {
        CMS_LOG_ERR("cms create hb worker entry thread failed");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t cms_get_uuid_lsid_from_config(char* cfg_name, uint32* lsid, char* uuid)
{
    char file_path[CMS_FILE_NAME_BUFFER_SIZE];
    char line[CMS_DBS_CONFIG_MAX_PARAM];
    errno_t ret = sprintf_s(file_path, CMS_FILE_NAME_BUFFER_SIZE, "%s/dbstor/conf/dbs/%s",
                            g_cms_param->cms_home, cfg_name);
    PRTS_RETURN_IFERR(ret);
    FILE* fp = fopen(file_path, "r");
    if (fp == NULL) {
        CT_LOG_RUN_ERR("Failed to open file %s\n", file_path);
        return CT_ERROR;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        char *context = NULL;
        if (strstr(line, "INST_ID") != NULL) {
            text_t lsid_t;
            lsid_t.str = strtok_s(line, "=", &context);
            lsid_t.str = strtok_s(NULL, "\n", &context);
            lsid_t.len = strlen(lsid_t.str);
            cm_trim_text(&lsid_t);
            CT_RETURN_IFERR(cm_str2uint32((const char *)lsid_t.str, lsid));
        } else if (strstr(line, "CMS_TOOL_UUID") != NULL) {
            text_t uuid_t;
            uuid_t.str = strtok_s(line, "=", &context);
            uuid_t.str = strtok_s(NULL, "\n", &context);
            uuid_t.len = strlen(uuid_t.str);
            cm_trim_text(&uuid_t);
            MEMS_RETURN_IFERR(strcpy_s(uuid, CMS_CLUSTER_UUID_LEN, uuid_t.str));
        }
    }
    fclose(fp);
    return CT_SUCCESS;
}

status_t cms_init_dbs_client(char* cfg_name, dbs_init_mode init_mode)
{
    int64_t start_time = cm_now();
    CT_RETURN_IFERR(dbs_init_lib());
    cm_dbs_cfg_s *cfg = cm_dbs_get_cfg();
    if (!cfg->enable) {
        CT_LOG_RUN_INF("dbstore is not enabled");
        return CT_SUCCESS;
    }

    uint32 lsid;
    char uuid[CMS_CLUSTER_UUID_LEN] = { 0 };

    CT_LOG_RUN_INF("dbstor client is inited by config file %s", cfg_name);
    if (strstr(cfg_name, "tool") != NULL) {
        if (cms_get_uuid_lsid_from_config(cfg_name, &lsid, uuid) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("cms get uuid lsid from config(%s) failed.\n", cfg_name);
            return CT_ERROR;
        }
    } else {
        MEMS_RETURN_IFERR(strcpy_s(uuid, CMS_CLUSTER_UUID_LEN, get_config_uuid(g_cms_param->node_id)));
        lsid = get_config_lsid(g_cms_param->node_id);
    }

    cm_set_dbs_uuid_lsid((const char*)uuid, lsid);
    CT_RETURN_IFERR(cm_dbs_init(g_cms_param->cms_home, cfg_name, init_mode));
    g_cms_inst->is_dbstor_cli_init = CT_TRUE;
    int64_t end_time = cm_now();
    CT_LOG_RUN_INF("dbstor client init time %ld (ns)", end_time - start_time);
    return CT_SUCCESS;
}

static status_t cms_create_voting_threads(void)
{
    if (cm_dbs_is_enable_dbs() == CT_TRUE && g_cms_param->gcc_type != CMS_DEV_TYPE_DBS) {
        CT_RETURN_IFERR(cms_init_dbs_client(DBS_CONFIG_NAME, DBS_RUN_CMS_SERVER_NFS));
    }
    CT_RETURN_IFERR(cms_vote_disk_init());
    if (g_cms_param->split_brain == CMS_OPEN_WITH_SPLIT_BRAIN) {
        if (cm_create_thread(cms_voting_entry, CT_DFLT_THREAD_STACK_SIZE, NULL,
            &g_cms_inst->voting_thread) != CT_SUCCESS) {
            CMS_LOG_ERR("cms create voting entry thread failed");
            return CT_ERROR;
        }

        if (cm_create_thread(cms_detect_voting_entry, CT_DFLT_THREAD_STACK_SIZE, NULL,
            &g_cms_inst->detect_voting_thread) != CT_SUCCESS) {
            CMS_LOG_ERR("cms create detect voting entry thread failed");
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static status_t cms_create_check_disk_threads(void)
{
    if (cm_create_thread(cms_detect_disk_error_entry, CT_DFLT_THREAD_STACK_SIZE, NULL,
        &g_cms_inst->detect_disk_error_thread) != CT_SUCCESS) {
        CMS_LOG_ERR("cms create detect disk error entry thread failed");
        return CT_ERROR;
    }
    if (cm_create_thread(cms_judge_disk_error_entry, CT_DFLT_THREAD_STACK_SIZE, NULL,
        &g_cms_inst->judge_disk_error_thread) != CT_SUCCESS) {
        CMS_LOG_ERR("cms create judge disk error entry thread failed");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t cms_create_aync_write_thread(void)
{
    cms_res_stat_t *res_stat_disk;
    res_stat_disk = cm_malloc_align(CMS_BLOCK_SIZE, sizeof(cms_res_stat_t));
    if (res_stat_disk == NULL) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, sizeof(cms_res_stat_t), "cms create stat aync write entry");
        return CT_ERROR;
    }
    if (cm_create_thread(cms_stat_aync_write_entry, CT_DFLT_THREAD_STACK_SIZE, res_stat_disk,
        &g_cms_inst->stat_aync_write_thread) != CT_SUCCESS) {
        CMS_LOG_ERR("cms create stat aync write entry thread failed");
        CM_FREE_PTR(res_stat_disk);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t cms_create_threads(void)
{
    if (cm_create_thread(cms_mes_send_entry, CT_DFLT_THREAD_STACK_SIZE, NULL,
        &g_cms_inst->send_thread) != CT_SUCCESS) {
        CMS_LOG_ERR("cms create send entry thread failed");
        return CT_ERROR;
    }

    for (uint32 i = 0; i < g_cms_param->worker_thread_count; i++) {
        if (cm_create_thread(cms_worker_entry, CT_DFLT_THREAD_STACK_SIZE, NULL,
            &g_cms_inst->work_thread[i]) != CT_SUCCESS) {
            CMS_LOG_ERR("cms create worker entry thread failed");
            return CT_ERROR;
        }
    }

    if (cm_create_thread(cms_worker_entry, CT_DFLT_THREAD_STACK_SIZE, CMS_HB_WORKER_FLAG,
        &g_cms_inst->hb_worker_thread) != CT_SUCCESS) {
        CMS_LOG_ERR("cms create hb worker entry thread failed");
        return CT_ERROR;
    }

    if (cms_create_uds_threads() != CT_SUCCESS) {
        CMS_LOG_ERR("cms create uds threads failed");
        return CT_ERROR;
    }

    if (cm_create_thread(cmd_handle_entry, CT_DFLT_THREAD_STACK_SIZE, NULL,
        &g_cms_inst->cmd_handle_thread) != CT_SUCCESS) {
        CMS_LOG_ERR("cms create cmd worker entry thread failed");
        return CT_ERROR;
    }

    if (cm_create_thread(cms_hb_timer_entry, CT_DFLT_THREAD_STACK_SIZE, NULL,
        &g_cms_inst->hb_timer_thread) != CT_SUCCESS) {
        CMS_LOG_ERR("cms create hb timer entry thread failed");
        return CT_ERROR;
    }

    if (cm_create_thread(cms_res_check_timer_entry, CT_DFLT_THREAD_STACK_SIZE, NULL,
        &g_cms_inst->res_check_timer_thread) != CT_SUCCESS) {
        CMS_LOG_ERR("cms create res check timer entry thread failed");
        return CT_ERROR;
    }

    if (cm_create_thread(cms_gcc_loader_entry, CT_DFLT_THREAD_STACK_SIZE, NULL,
        &g_cms_inst->gcc_loader_thread) != CT_SUCCESS) {
        CMS_LOG_ERR("cms create gcc loader entry thread failed");
        return CT_ERROR;
    }

    if (cm_create_thread(cms_gcc_backup_entry, CT_DFLT_THREAD_STACK_SIZE, NULL,
        &g_cms_inst->gcc_backup_thread) != CT_SUCCESS) {
        CMS_LOG_ERR("cms create gcc backup entry thread failed");
        return CT_ERROR;
    }

    if (cms_create_aync_write_thread() != CT_SUCCESS) {
        CMS_LOG_ERR("cms create stat aync write entry thread failed");
        return CT_ERROR;
    }

    if (cms_create_voting_threads() != CT_SUCCESS) {
        CMS_LOG_ERR("cms create voting threads failed");
        return CT_ERROR;
    }

    if (cms_create_check_disk_threads() != CT_SUCCESS) {
        CMS_LOG_ERR("cms create check disk threads failed");
        return CT_ERROR;
    }

    return CT_SUCCESS;
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
    
    return CT_SUCCESS;
}

status_t cms_lock_server(void)
{
    char file_name[CMS_FILE_NAME_BUFFER_SIZE] = { 0 };
    int32 ret;

    ret = snprintf_s(file_name, CMS_FILE_NAME_BUFFER_SIZE, CMS_MAX_FILE_NAME_LEN, "%s/%s",
        g_cms_param->cms_home, g_cms_lock_file);
    PRTS_RETURN_IFERR(ret);

    if (cm_open_file(file_name, O_CREAT | O_RDWR | O_BINARY | O_CLOEXEC | O_SYNC | O_DIRECT,
        &g_cms_inst->server_lock_fd) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return cm_lockw_file_fd(g_cms_inst->server_lock_fd);
}

status_t cms_force_unlock_server(void)
{
    if (cm_unlock_file_fd(g_cms_inst->server_lock_fd) != CT_SUCCESS) {
        CMS_LOG_ERR("cms unlock server fd failed.");
    }
    cm_close_file(g_cms_inst->server_lock_fd);
    return CT_SUCCESS;
}

static status_t cms_server_loop(void)
{
    g_cms_inst->server_loop = CT_TRUE;
    cms_trigger_voting();
    while (g_cms_inst->server_loop) {
        cms_try_be_master();
        cms_sync_wait(&g_cms_inst->try_master_sync, CMS_INST_TRY_MASTER_WAIT_TIME);
    }
    cm_sleep(CMS_INST_SERVER_SLEEP_TIME);
    return CT_SUCCESS;
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

    CT_RETURN_IFERR(cms_get_node_by_id(g_cms_param->node_id, &node_def));

    ret = sprintf_s(port, sizeof(port), "%u", node_def.port);
    PRTS_RETURN_IFERR(ret);

    CT_RETURN_IFERR(cms_update_param("_IP", node_def.ip));
    CT_RETURN_IFERR(cms_update_param("_PORT", port));

    return CT_SUCCESS;
}

void cms_get_dbversion(upgrade_version_t *cms_version)
{
    text_t db_version = { 0 };
    text_t left = { 0 };
    text_t right = { 0 };
    text_t right2 = { 0 };
    text_t version_main = { 0 };
    text_t version_major = { 0 };
    text_t version_revision = { 0 };
    uint32 main_n = 0;
    uint32 major_n = 0;
    uint32 revision_n = 0;
    char *version = (char *)cantiand_get_dbversion();
    cm_str2text(version, &db_version);
    // for release package the dbversion is like "Cantian Release 2.0.0"
    // for debug package the dbversion is like "Cantian Debug 2.0.0 c11fdca072"
    (void)cm_split_text(&db_version, ' ', 0, &left, &right);
    (void)cm_split_text(&right, ' ', 0, &left, &right2);
    (void)cm_split_text(&right2, ' ', 0, &left, &right);
    (void)cm_split_text(&left, '.', 0, &version_main, &right);
    (void)cm_split_text(&right, '.', 0, &version_major, &version_revision);
    (void)cm_text2int(&version_main, (int32 *)&main_n);
    (void)cm_text2int(&version_major, (int32 *)&major_n);
    (void)cm_text2int(&version_revision, (int32 *)&revision_n);
    cms_version->main = (uint16)main_n;
    cms_version->major = (uint16)major_n;
    cms_version->revision = (uint16)revision_n;
    cms_version->inner = CMS_DEFAULT_INNNER_VERSION;
    return;
}

status_t cms_update_version(void)
{
    status_t ret = CT_ERROR;
    bool32 all_restart = CT_FALSE;
    bool32 cmp_result = CT_FALSE;
    upgrade_version_t cms_version = { 0 };
    (void)cms_get_dbversion(&cms_version);
    CMS_LOG_INF("get dbversion finished, main=%u, major=%u, revision=%u, inner=%u.", cms_version.main,
        cms_version.major, cms_version.revision, cms_version.inner);
 
    cms_gcc_t* resident_gcc = (cms_gcc_t *)cm_malloc_align(CMS_BLOCK_SIZE, sizeof(cms_gcc_t));
    if (resident_gcc == NULL) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, sizeof(cms_gcc_t), "loading gcc");
        return CT_ERROR;
    }
    (void)memset_sp(resident_gcc, sizeof(cms_gcc_t), 0, sizeof(cms_gcc_t));
    if (cms_gcc_read_disk_direct(resident_gcc) != CT_SUCCESS) {
        CM_FREE_PTR(resident_gcc);
        CMS_LOG_ERR("read disk failed when load gcc.");
        return CT_ERROR;
    }
    CMS_LOG_INF("get cms gcc version finished, main=%u, major=%u, revision=%u, inner=%u.",
        resident_gcc->head.ver_main, resident_gcc->head.ver_major, resident_gcc->head.ver_revision,
        resident_gcc->head.ver_inner);
    
    cmp_result = cms_dbversion_cmp(&cms_version, resident_gcc);
    if (cmp_result == CT_TRUE) {
        CM_FREE_PTR(resident_gcc);
        CMS_LOG_ERR("cms gcc version bigger than db version, cmp_result = %d.", cmp_result);
        return CT_ERROR;
    }
    CM_FREE_PTR(resident_gcc);
 
    // 如果是fullstart，则更新gcc
    CT_RETURN_IFERR(cms_is_all_restart(&all_restart));
    if (!all_restart) {
        CMS_LOG_INF("cms gcc version not need update.");
        // 更新内存gcc
        (void)cms_notify_load_gcc();
        return CT_SUCCESS;
    }
 
    ret = cms_update_gcc_ver(cms_version.main, cms_version.major, cms_version.revision, cms_version.inner);
    if (ret != CT_SUCCESS) {
        CMS_LOG_ERR("update cms gcc version failed.");
        return CT_ERROR;
    }
    // 更新内存gcc
    (void)cms_notify_load_gcc();
    return CT_SUCCESS;
}

status_t cms_startup(void)
{
    if (g_cms_param->gcc_type != CMS_DEV_TYPE_DBS && cms_lock_server() != CT_SUCCESS) {
        cm_reset_error();
        CMS_LOG_ERR("Another cms server is running");
        CT_THROW_ERROR(ERR_CMS_SERVER_RUNNING);
        return CT_ERROR;
    }

    g_cms_inst->is_server = CT_TRUE;
    CMS_LOG_INF("[cms srv init] cms startup begin.");
    CT_RETURN_IFERR(cms_load_keyfiles());
    CMS_LOG_INF("[cms srv init] cms load keyfiles succ");
    CT_RETURN_IFERR(sigcap_handle_reg());
    CMS_LOG_INF("[cms srv init] cms sigcap handle reg succ");
    CT_RETURN_IFERR(cms_load_gcc());
    CMS_LOG_INF("[cms srv init] cms load gcc succ");
    CT_RETURN_IFERR(cms_update_local_cfg());
    CMS_LOG_INF("[cms srv init] cms update local cfg succ");
    CT_RETURN_IFERR(cms_update_local_gcc());
    CMS_LOG_INF("[cms srv init] cms update local gcc succ");
    CT_RETURN_IFERR(cms_instance_init());
    CMS_LOG_INF("[cms srv init] cms instance init succ");
    CT_RETURN_IFERR(inc_stat_version());
    CMS_LOG_INF("[cms srv init] cms inc stat ver succ");
    CT_RETURN_IFERR(record_io_stat_init());
    CMS_LOG_INF("[cms srv init] cms record io stat init succ");
    CT_RETURN_IFERR(cms_uds_srv_init());
    CMS_LOG_INF("[cms srv init] cms cms uds srv_init succ");
    CT_RETURN_IFERR(cms_init_mes_channel_version());
    CMS_LOG_INF("[cms srv init] cms init mes channel version succ");
    CT_RETURN_IFERR(cms_startup_mes());
    CMS_LOG_INF("[cms srv init] cms startup mes succ");
    CT_RETURN_IFERR(cms_create_threads());
    CMS_LOG_INF("[cms srv init] cms create threads succ");
    CT_RETURN_IFERR(cms_update_version());
    CMS_LOG_INF("[cms srv init] cms update version succ");
    CT_RETURN_IFERR(cms_server_loop());
    CT_RETURN_IFERR(cms_close_threads());
    return CT_SUCCESS;
}

void cms_shutdown(void)
{
    g_cms_inst->disk_thread.closed = CT_TRUE;
    g_cms_inst->send_thread.closed = CT_TRUE;
    for (int32 i = 0; i < CMS_MAX_WORKER_THREAD_COUNT; i++) {
        g_cms_inst->work_thread[i].closed = CT_TRUE;
    }
    g_cms_inst->cmd_handle_thread.closed = CT_TRUE;
    if (g_cms_param->split_brain == CMS_OPEN_WITH_SPLIT_BRAIN) {
        g_cms_inst->voting_thread.closed = CT_TRUE;
        g_cms_inst->detect_voting_thread.closed = CT_TRUE;
    }
    g_cms_inst->judge_disk_error_thread.closed = CT_TRUE;
    g_cms_inst->detect_disk_error_thread.closed = CT_TRUE;
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
            return CT_ERROR;
        }

        _ctx->gcc_handle = -1;
        _ctx->handle_valid = -1;
        (void)pthread_setspecific(g_inst_local_var, _ctx);
    }

    if (_ctx->handle_valid == -1) {
        if (g_cms_param->gcc_type == CMS_DEV_TYPE_DBS) {
            CT_RETURN_IFERR(cm_get_dbs_last_dir_handle(g_cms_param->gcc_dir, &_ctx->gcc_dbs_handle));
        } else {
            CT_RETURN_IFERR(cm_open_disk(g_cms_param->gcc_home, &_ctx->gcc_handle));
            CT_LOG_DEBUG_INF("thread id %u, gcc handle %d, gcc %s", cm_get_current_thread_id(),
                _ctx->gcc_handle, g_cms_param->gcc_home);
        }
        _ctx->handle_valid = 1;
    }

    *ctx = _ctx;
    return CT_SUCCESS;
}

status_t cms_send_srv_msg_to(uint16 node_id, cms_packet_head_t* msg)
{
    biqueue_node_t* node = cms_que_alloc_node(msg->msg_size);
    if (node == NULL) {
        CMS_LOG_ERR("cms malloc msg size %u failed.", msg->msg_size);
        return CT_ERROR;
    }
    cms_packet_head_t* send_msg = (cms_packet_head_t*)cms_que_node_data(node);
    errno_t ret = memcpy_s(send_msg, msg->msg_size, msg, msg->msg_size);
    if (ret != EOK) {
        CMS_LOG_ERR("cms memcpy failed, src msg size %u, errno %d[%s]", msg->msg_size, cm_get_os_error(),
            strerror(errno));
        cms_que_free_node(node);
        return CT_ERROR;
    }
    send_msg->src_node = msg->dest_node;
    send_msg->dest_node = node_id;
    cms_enque(&g_cms_inst->send_que, node);
    return CT_SUCCESS;
}

status_t cms_broadcast_srv_msg(cms_packet_head_t* msg)
{
    status_t ret = CT_SUCCESS;
    uint32 node_count = cms_get_gcc_node_count();
    for (uint32 i = 0; i < node_count; i++) {
        if (cms_node_is_invalid(i)) {
            continue;
        }
        ret = cms_send_srv_msg_to(i, msg);
        if (ret != CT_SUCCESS) {
            CMS_LOG_ERR("cms send srv msg failed, ret %d, node id %u, msg type %u, msg seq %llu", ret,
                i, msg->msg_type, msg->msg_seq);
            return ret;
        }
    }
    return CT_SUCCESS;
}
