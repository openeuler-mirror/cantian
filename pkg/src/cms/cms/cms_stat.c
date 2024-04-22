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
 * cms_stat.c
 *
 *
 * IDENTIFICATION
 * src/cms/cms/cms_stat.c
 *
 * -------------------------------------------------------------------------
 */

#include <time.h>
#include "cms_log_module.h"
#include "cm_disk.h"
#include "cms_param.h"
#include "cms_gcc.h"
#include "cm_date.h"
#include "cms_client.h"
#include "cms_msgque.h"
#include "cms_instance.h"
#include "cms_msg_def.h"
#include "cms_uds_server.h"
#include "cms_uds_client.h"
#include "cm_dlock.h"
#include "cm_file.h"
#include "cms_comm.h"
#include "cms_socket.h"
#include "cm_malloc.h"
#include "cms_vote.h"
#include "cms_log.h"
#include "cms_cmd_upgrade.h"
#include "cms_stat.h"

void cms_date2str(date_t date, char* str, uint32 max_size);

typedef struct st_cms_stat_buffer {
    uint64 buff[CMS_BLOCK_SIZE / sizeof(uint64)][((sizeof(cms_cluster_stat_t) / CMS_BLOCK_SIZE) + 1)];
}cms_stat_buff_t;

static cms_stat_buff_t g_cms_stat_buff;
cms_cluster_stat_t* g_stat = NULL;
cms_res_session_t g_res_session[CMS_MAX_UDS_SESSION_COUNT];
uint32 g_tool_session_count = CMS_MAX_RESOURCE_COUNT;
thread_lock_t g_session_lock;
thread_lock_t g_node_lock[CMS_MAX_NODE_COUNT];
cms_channel_info_t *g_channel_info = NULL;

#define CMS_NODE_DISK_HB_POS(node_id) (CMS_CLUSTER_STAT_OFFSET + \
    ((size_t) &(((cms_cluster_stat_t*)NULL)->node_inf[node_id].node_disk_hb)))
#define CMS_RES_STAT_POS(node_id, res_id) (CMS_CLUSTER_STAT_OFFSET + \
    ((size_t) &(((cms_cluster_stat_t*)NULL)->node_inf[node_id].res_stat[res_id])))
#define CMS_CUR_RES_STAT_POS(res_id) (CMS_CLUSTER_STAT_OFFSET + \
    ((size_t) &(((cms_cluster_stat_t*)NULL)->node_inf[g_cms_param->node_id].res_stat[res_id])))
#define CMS_SYNC_CUR_RES_STAT(res_id, res_stat) (stat_write(CMS_RES_STAT_POS(g_cms_param->node_id, (res_id)), \
    (char*)(res_stat), sizeof(cms_res_stat_t)))
#define CMS_MASTER_LOCK_POS (CMS_CLUSTER_STAT_OFFSET + OFFSET_OF(cms_cluster_stat_t, cms_lock))
#define CMS_STAT_LOCK_POS (CMS_CLUSTER_STAT_OFFSET + OFFSET_OF(cms_cluster_stat_t, stat_lock))
#define CMS_RES_LOCK_POS(res_id) (CMS_CLUSTER_STAT_OFFSET + \
    ((size_t) &(((cms_cluster_stat_t*)NULL)->res_lock[res_id])))
#define CMS_RES_DATA_LOCK_POS(res_id, slot_id) (CMS_CLUSTER_STAT_OFFSET + \
    ((size_t)&(((cms_cluster_stat_t*)NULL)->res_data_lock[res_id][slot_id])))
#define CMS_VOTE_DATA_LOCK_POS(node_id, slot_id) (CMS_CLUSTER_STAT_OFFSET + \
    ((size_t) &(((cms_cluster_stat_t *)NULL)->vote_data_lock[node_id][slot_id])))
#define CMS_VOTE_RES_LOCK_POS (CMS_CLUSTER_STAT_OFFSET + OFFSET_OF(cms_cluster_stat_t, vote_result_lock))
#define CMS_RES_START_LOCK_POS (CMS_CLUSTER_STAT_OFFSET + OFFSET_OF(cms_cluster_stat_t, res_start_lock))
#define CMS_VOTE_INFO_LOCK_POS (CMS_CLUSTER_STAT_OFFSET + OFFSET_OF(cms_cluster_stat_t, vote_info_lock))
#define CMS_STAT_HEAD_POS (CMS_CLUSTER_STAT_OFFSET)
#define CMS_CUR_RES_STAT(res_id) (&g_stat->node_inf[g_cms_param->node_id].res_stat[(res_id)])
#define CMS_RES_STAT(node_id, res_id) (&g_stat->node_inf[(node_id)].res_stat[(res_id)])
#define CMS_RES_OFFLINE_RESET_TIMEOUT (15000 * MICROSECS_PER_MILLISEC)
#define CMS_STAT_IS_REGISTER(stat) ((stat).session_id != 0 && (stat).session_id != CT_INVALID_ID64)
#define CMS_NODE_STAT_POS(node_id) (CMS_CLUSTER_STAT_OFFSET + \
    ((size_t) &(((cms_cluster_stat_t*)NULL)->node_inf[node_id].node_stat[node_id])))
#define CMS_CUR_NODE_STAT (&g_stat->node_inf[g_cms_param->node_id].node_stat[g_cms_param->node_id])
#define CMS_NODE_STAT(node_id) (&g_stat->node_inf[g_cms_param->node_id].node_stat[node_id])
#define CMS_RES_STAT_LOCK_POS(node_id, res_id) (CMS_RES_LOCK_OFFSET + \
    ((size_t)&(((cms_cluster_res_lock_t*)NULL)->res_stat_lock[node_id][res_id])))
#define CMS_MES_CHANNEL_POS (CMS_MES_CHANNEL_OFFSET + \
    ((size_t)&(((cms_mes_channel_t*)NULL)->channel_info[g_cms_param->node_id])))

static inline status_t stat_read(uint64 offset, char* data, uint32 size)
{
    cms_local_ctx_t* ctx;
    CT_RETURN_IFERR(cms_get_local_ctx(&ctx));
    if (g_cms_param->gcc_type != CMS_DEV_TYPE_DBS) {
        return cm_read_disk(ctx->gcc_handle, offset, data, size);
    }
    if (cm_read_dbs_file(&ctx->gcc_dbs_handle, offset, data, size) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static inline status_t stat_write(uint64 offset, char* data, uint32 size)
{
    cms_local_ctx_t* ctx;
    CT_RETURN_IFERR(cms_get_local_ctx(&ctx));
    if (g_cms_param->gcc_type != CMS_DEV_TYPE_DBS) {
        return cm_write_disk(ctx->gcc_handle, offset, data, size);
    }
    return cm_write_dbs_file(&ctx->gcc_dbs_handle, offset, data, size);
}

static status_t res_data_read(cms_local_ctx_t* ctx, uint64 offset, char* data, uint32 size)
{
    if (g_cms_param->gcc_type != CMS_DEV_TYPE_DBS) {
        return cm_read_disk(ctx->gcc_handle, offset, data, size);
    }
    if (cm_read_dbs_file(&ctx->gcc_dbs_handle, offset, data, size) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return CT_SUCCESS;
}
 
static status_t res_data_write(cms_local_ctx_t* ctx, uint64 offset, char* data, uint32 size)
{
    if (g_cms_param->gcc_type != CMS_DEV_TYPE_DBS) {
        return cm_write_disk(ctx->gcc_handle, offset, data, size);
    }
    return cm_write_dbs_file(&ctx->gcc_dbs_handle, offset, data, size);
}

static bool32 res_is_active(cms_disk_lock_t* lock, uint64 inst_id)
{
    cms_res_t res;

    if (cms_node_is_invalid(inst_id)) {
        return CT_FALSE;
    }

    if (cms_get_res_by_id((uint32)lock->int64_param1, &res) != CT_SUCCESS) {
        CMS_LOG_DEBUG_ERR("get res failed, res_id=%lld", lock->int64_param1);
        return CT_TRUE;
    }

    cms_res_stat_t stat;
    if (get_res_stat((uint32)inst_id, (uint32)lock->int64_param1, &stat) != CT_SUCCESS) {
        CMS_LOG_DEBUG_ERR("get res stat failed, inst_id=%lld, res_id=%lld", inst_id, lock->int64_param1);
        return CT_TRUE;
    }

    return (cm_now() <= stat.hb_time + res.hb_timeout * MICROSECS_PER_MILLISEC);
}

static status_t cms_get_node_stat(uint32 node_id, char *node_stat)
{
    if (stat_read(CMS_NODE_STAT_POS(node_id), node_stat, sizeof(cms_node_stat_t)) != CT_SUCCESS) {
        CMS_LOG_ERR("cms read node state fail, node_id=%u", node_id);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t cms_sync_cur_res_stat(uint32 res_id, cms_res_stat_t* res_stat)
{
    if (cms_disk_lock(&g_cms_inst->res_stat_lock[g_cms_param->node_id][res_id], DISK_LOCK_WAIT_TIMEOUT,
        DISK_LOCK_WRITE) != CT_SUCCESS) {
        CMS_LOG_ERR("cms_disk_lock timeout, node_id = %u, res_id = %u.", g_cms_param->node_id, res_id);
        return CT_ERROR;
    }
    if (stat_write(CMS_RES_STAT_POS(g_cms_param->node_id, (res_id)), (char*)(res_stat),
        sizeof(cms_res_stat_t)) != CT_SUCCESS) {
        CMS_LOG_ERR("sync cur res stat failed. node_id = %u, res_id = %u.", g_cms_param->node_id, res_id);
        cms_disk_unlock(&g_cms_inst->res_stat_lock[g_cms_param->node_id][res_id], DISK_LOCK_WRITE);
        return CT_ERROR;
    }

    cms_disk_unlock(&g_cms_inst->res_stat_lock[g_cms_param->node_id][res_id], DISK_LOCK_WRITE);
    return CT_SUCCESS;
}

status_t cms_is_all_restart(bool32 *all_restart)
{
    uint32 node_count = cms_get_gcc_node_count();
    cms_node_stat_t *node_stat;
    uint32 detect_timemout = g_cms_param->detect_disk_timeout;
    char disk_hb[32], now_str[32];
    
    for (uint32 node_id = 0; node_id < node_count; node_id++) {
        if (cms_node_is_invalid(node_id) || (node_id == g_cms_param->node_id)) {
            continue;
        }
        node_stat = CMS_NODE_STAT(node_id);
        CT_RETURN_IFERR(cms_get_node_stat(node_id, (char *)node_stat));
        
        uint64_t now_time = cm_now();
        cms_date2str(node_stat->disk_hb, disk_hb, sizeof(disk_hb));
        cms_date2str(now_time, now_str, sizeof(now_str));
        if (g_cms_param->gcc_type == CMS_DEV_TYPE_DBS) {
            detect_timemout = CMS_DBS_DETECT_TIMEOUT;
        }

        if (node_stat->disk_hb + detect_timemout * CMS_SECOND_TRANS_MICROSECOND > cm_now()) {
            CMS_LOG_INF("node %u cms is online, last disk_hb %s, now time %s", node_id, disk_hb, now_str);
            *all_restart = CT_FALSE;
            return CT_SUCCESS;
        }
        CMS_LOG_INF("node %u cms is offline, last disk_hb %s, now time %s", node_id, disk_hb, now_str);
    }
    *all_restart = CT_TRUE;
    CMS_LOG_INF("cms is full retart");
    return CT_SUCCESS;
}

bool32 cms_try_be_new_master(void)
{
    if (cms_disk_try_lock(&g_cms_inst->master_lock, DISK_LOCK_WRITE) != CT_SUCCESS) {
        CMS_LOG_INF("cms is not master node");
        return CT_FALSE;
    }
    return CT_TRUE;
}

status_t cms_init_vote_info(void)
{
    bool32 all_restart = CT_FALSE;
    bool32 vote_done = CT_FALSE;
    cms_node_stat_t* node_stat = CMS_CUR_NODE_STAT;
    node_stat->vote_info_status = CMS_INITING_VOTE_INFO;

    if (cms_disk_lock(&g_cms_inst->vote_info_lock, 0, DISK_LOCK_WRITE) != CT_SUCCESS) {
        CMS_LOG_ERR("cms_disk_lock timeout.");
        return CT_ERROR;
    }
    
    for (;;) {
        CT_RETURN_IFERR(cms_is_all_restart(&all_restart));
        if (all_restart) {
            if (cms_try_be_new_master()) {
                CMS_LOG_INF("cms is full restart, cms master begin to init vote file");
                CT_RETURN_IFERR(cms_init_cluster_vote_info());
                CMS_LOG_INF("vote file init succeed");
                break;
            } else {
                continue;
            }
        }
        CT_RETURN_IFERR(cms_is_vote_done(&vote_done));
        if (vote_done) {
            CMS_LOG_INF("cms is not full restart, begin to init vote round");
            cms_init_vote_round();
            break;
        }
        cm_sleep(CMS_INIT_VTINFO_RETRY_INTERNAL);
    }
    return CT_SUCCESS;
}

status_t cms_vote_info_lock_init(void)
{
    // init vote info lock
    CT_RETURN_IFERR(cms_disk_lock_init(g_cms_param->gcc_type, g_cms_param->gcc_home, "_vote_info_lock",
        CMS_VOTE_INFO_LOCK_POS, CMS_RLOCK_VOTE_INFO_LOCK_START, CMS_RLOCK_VOTE_INFO_LOCK_LEN, g_cms_param->node_id,
        &g_cms_inst->vote_info_lock, NULL, 0, CT_FALSE));
    return CT_SUCCESS;
}

status_t cms_vote_file_init(void)
{
     // init vote_file_fd
    if ((g_cms_param->gcc_type == CMS_DEV_TYPE_FILE) || (g_cms_param->gcc_type == CMS_DEV_TYPE_NFS)) {
        char file_name[CMS_FILE_NAME_BUFFER_SIZE] = { 0 };
        int ret = snprintf_s(file_name, CMS_FILE_NAME_BUFFER_SIZE, CMS_MAX_FILE_NAME_LEN, "%s_vote_file",
            g_cms_param->gcc_home);
        PRTS_RETURN_IFERR(ret);
        if (cm_open_file(file_name, O_CREAT | O_RDWR | O_BINARY | O_CLOEXEC | O_SYNC | O_DIRECT,
            &g_cms_inst->vote_file_fd) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } else if (g_cms_param->gcc_type == CMS_DEV_TYPE_SD) {
        CT_RETURN_IFERR(cm_open_disk(g_cms_param->gcc_home, &g_cms_inst->vote_file_fd));
    } else if (g_cms_param->gcc_type == CMS_DEV_TYPE_DBS) {
        char file_path[CMS_FILE_NAME_BUFFER_SIZE] = { 0 };
        int ret = snprintf_s(file_path, CMS_FILE_NAME_BUFFER_SIZE, CMS_MAX_FILE_NAME_LEN, "%s_vote_file",
            g_cms_param->gcc_home);
        PRTS_RETURN_IFERR(ret);
        CT_RETURN_IFERR(cm_get_dbs_last_file_handle(file_path, &g_cms_inst->vote_file_handle)); // create file
    } else {
        CMS_LOG_ERR("invalid device type:%d", g_cms_param->gcc_type);
        return CT_ERROR;
    }

    // init vote result lock
    CT_RETURN_IFERR(cms_disk_lock_init(g_cms_param->gcc_type, g_cms_param->gcc_home, "_vote_file",
        CMS_VOTE_RES_LOCK_POS, CMS_RLOCK_VOTE_RESULT_LOCK_START, CMS_RLOCK_VOTE_RESULT_LOCK_LEN, g_cms_param->node_id,
        &g_cms_inst->vote_result_lock, NULL, 0, CT_FALSE));

    // init vote_lock
    for (int node_id = 0; node_id < CMS_MAX_NODE_COUNT; node_id++) {
        if (cms_node_is_invalid(node_id)) {
            continue;
        }
        for (int slot_id = 0; slot_id < CMS_MAX_VOTE_SLOT_COUNT; slot_id++) {
            CT_RETURN_IFERR(cms_disk_lock_init(g_cms_param->gcc_type, g_cms_param->gcc_home, "_vote_file",
                CMS_VOTE_DATA_LOCK_POS(node_id, slot_id), CMS_RLOCK_VOTE_DATA_LOCK_START(node_id, slot_id),
                CMS_RLOCK_VOTE_DATA_LOCK_LEN, g_cms_param->node_id,
                &g_cms_inst->vote_data_lock[node_id][slot_id], NULL, 0, CT_FALSE));
            cms_disk_unlock(&g_cms_inst->vote_data_lock[node_id][slot_id], DISK_LOCK_READ);
        }
    }
    return CT_SUCCESS;
}

status_t cms_vote_disk_init(void)
{
    if (g_cms_param->split_brain == CMS_OPEN_WITHOUT_SPLIT_BRAIN) {
        CMS_LOG_INF("cms run without split-brain process");
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(cms_vote_info_lock_init());
    CT_RETURN_IFERR(cms_vote_file_init());
    CT_RETURN_IFERR(cms_init_vote_info());
    return CT_SUCCESS;
}

status_t cms_res_lock_init(void)
{
    // init res start lock
    CT_RETURN_IFERR(cms_disk_lock_init(g_cms_param->gcc_type, g_cms_param->gcc_home, "", CMS_RES_START_LOCK_POS,
        CMS_RLOCK_RES_START_LOCK_START, CMS_RLOCK_RES_START_LOCK_LEN, g_cms_param->node_id,
        &g_cms_inst->res_start_lock, NULL, CMS_DLOCK_THREAD, CT_FALSE));
    cms_disk_unlock(&g_cms_inst->res_start_lock, DISK_LOCK_READ);
    // init res stat lock
    for (int32 node_id = 0; node_id < CMS_MAX_NODE_COUNT; node_id++) {
        if (cms_node_is_invalid(node_id)) {
            continue;
        }
        for (int32 res_id = 0; res_id < CMS_RES_STAT_MAX_RESOURCE_COUNT; res_id++) {
            CT_RETURN_IFERR(cms_disk_lock_init(g_cms_param->gcc_type, g_cms_param->gcc_home, "",
                CMS_RES_STAT_LOCK_POS(node_id, res_id), CMS_RLOCK_RES_STAT_LOCK_START(node_id, res_id),
                CMS_RLOCK_RES_STAT_LOCK_LEN, g_cms_param->node_id,
                &g_cms_inst->res_stat_lock[node_id][res_id], NULL, 0, CT_FALSE));
            cms_disk_unlock(&g_cms_inst->res_stat_lock[node_id][res_id], DISK_LOCK_READ);
        }
        cm_init_thread_lock(&g_node_lock[node_id]);
    }
    // init res data lock
    for (int32 res_id = 0; res_id < CMS_MAX_RESOURCE_COUNT; res_id++) {
        if (cms_res_is_invalid(res_id)) {
            continue;
        }
        CT_RETURN_IFERR(stat_read(CMS_RES_STAT_POS(g_cms_param->node_id, res_id), (char *)CMS_CUR_RES_STAT(res_id),
            sizeof(cms_res_stat_t)));
        CMS_CUR_RES_STAT(res_id)->checking = 0;
        for (int32 slot_id = 0; slot_id < CMS_MAX_RES_SLOT_COUNT; slot_id++) {
            CT_RETURN_IFERR(cms_disk_lock_init(g_cms_param->gcc_type, g_cms_param->gcc_home, "",
                CMS_RES_DATA_LOCK_POS(res_id, slot_id), CMS_RLOCK_RES_DATA_LOCK_START(res_id, slot_id),
                CMS_RLOCK_RES_DATA_LOCK_LEN, g_cms_param->node_id, &g_cms_inst->res_data_lock[res_id][slot_id],
                res_is_active, 0, CT_FALSE));
            g_cms_inst->res_data_lock[res_id][slot_id].int64_param1 = res_id;
            cms_disk_unlock(&g_cms_inst->res_data_lock[res_id][slot_id], DISK_LOCK_READ);
        }
    }
    return CT_SUCCESS;
}

status_t cms_init_stat_for_dbs(void)
{
    g_stat = (cms_cluster_stat_t*)(CMS_ALIGN_ADDR_512(&g_cms_stat_buff));
    CM_ASSERT((char*)g_stat + sizeof(cms_cluster_stat_t) < (char*)(&g_cms_stat_buff) + sizeof(cms_stat_buff_t));
    return CT_SUCCESS;
}

status_t cms_init_stat(void)
{
    g_stat = (cms_cluster_stat_t*)(CMS_ALIGN_ADDR_512(&g_cms_stat_buff));
    CM_ASSERT((char*)g_stat + sizeof(cms_cluster_stat_t) < (char*)(&g_cms_stat_buff) + sizeof(cms_stat_buff_t));

    // init master lock
    CT_RETURN_IFERR(cms_disk_lock_init(g_cms_param->gcc_type, g_cms_param->gcc_home, "_master_lock",
        CMS_MASTER_LOCK_POS, CMS_RLOCK_MASTER_LOCK_START, CMS_RLOCK_MASTER_LOCK_LEN,
        g_cms_param->node_id, &g_cms_inst->master_lock, NULL, 0, CT_TRUE));
    // init cluster stat head lock
    CT_RETURN_IFERR(cms_disk_lock_init(g_cms_param->gcc_type, g_cms_param->gcc_home, "", CMS_STAT_LOCK_POS,
        CMS_RLOCK_STAT_LOCK_START, CMS_RLOCK_STAT_LOCK_LEN, g_cms_param->node_id, &g_cms_inst->stat_lock,
        NULL, CMS_DLOCK_THREAD, CT_FALSE));
    cms_disk_unlock(&g_cms_inst->stat_lock, DISK_LOCK_READ);

    CT_RETURN_IFERR(cms_res_lock_init());

    cm_init_thread_lock(&g_session_lock);
    g_tool_session_count = CMS_MAX_RESOURCE_COUNT;
    for (int32 i = 0; i < CMS_MAX_UDS_SESSION_COUNT; i++) {
        cm_init_thread_lock(&g_res_session[i].lock);
        cm_init_thread_lock(&g_res_session[i].uds_lock);
        g_res_session[i].uds_sock = CMS_IO_INVALID_SOCKET;
    }
    return CT_SUCCESS;
}

status_t cms_lock_stat(uint8 lock_type)
{
    if (cms_disk_lock(&g_cms_inst->stat_lock, STAT_LOCK_WAIT_TIMEOUT, lock_type) != CT_SUCCESS) {
        CMS_LOG_ERR("cms_disk_lock timeout.");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t cms_unlock_stat(uint8 lock_type)
{
    return cms_disk_unlock(&g_cms_inst->stat_lock, lock_type);
}

status_t inc_stat_version(void)
{
    status_t ret;
    CT_RETURN_IFERR(cms_lock_stat(DISK_LOCK_WRITE));

    ret = stat_read(CMS_STAT_HEAD_POS, (char*)(&g_stat->head), sizeof(cms_cluster_stat_head_t));
    if (ret != CT_SUCCESS) {
        CMS_LOG_ERR("cms read g_stat head failed, g_stat->head.stat_ver = %llu", g_stat->head.stat_ver);
        (void)cms_unlock_stat(DISK_LOCK_WRITE);
        return CT_ERROR;
    }

    g_stat->head.data_ver++;
    g_stat->head.stat_ver++;
    g_stat->head.magic = CMS_STAT_HEAD_MAGIC;

    ret = stat_write(CMS_STAT_HEAD_POS, (char*)(&g_stat->head), sizeof(cms_cluster_stat_head_t));
    if (ret != CT_SUCCESS) {
        CMS_LOG_ERR("cms write g_stat head failed, g_stat->head.stat_ver = %llu", g_stat->head.stat_ver);
        (void)cms_unlock_stat(DISK_LOCK_WRITE);
        return CT_ERROR;
    }

    (void)cms_unlock_stat(DISK_LOCK_WRITE);
    return ret;
}

status_t cms_get_stat_version(uint64* version)
{
    __TODO__; // refresh stat's version aysnc
    *version = g_stat->head.stat_ver;

    return CT_SUCCESS;
}

void cms_stat_set(cms_res_stat_t* res_stat, cms_stat_t new_stat, bool32* isChanged);

void cms_exec_res_script_print_log(const char* arg, char *cmd)
{
    if (strcmp(arg, "-check") == 0) {
        CMS_LOG_TIMER("exec script, cmd=%s", cmd);
    } else if (strcmp(arg, "-init_exit_file") == 0) {
        CMS_LOG_DEBUG_INF("exec script, cmd=%s", cmd);
    } else {
        CMS_LOG_INF("exec script, cmd=%s", cmd);
    }
}

status_t cms_exec_res_script(const char* script, const char* arg, uint32 timeout_ms, status_t* result)
{
    CMS_LOG_INF("begin cms exec res script.");
    char cmd[CMS_CMD_BUFFER_SIZE] = {0};
    *result = CT_ERROR;
    errno_t ret = EOK;
    if (cm_verify_file_host((char *)script) != CT_SUCCESS) {
        CMS_LOG_ERR("script host is invaild");
        return CT_ERROR;
    }
    if (strncmp(arg, "disable", CMS_MAX_FILE_NAME) == 0) {
        ret = sprintf_s(cmd, CMS_CMD_BUFFER_SIZE,
            "echo 'script begin';timeout %.2f %s %s;echo $?;echo 'script end\n';",
            (float)timeout_ms / CMS_TRANS_MS_TO_SECOND_FLOAT, script, arg);
    } else {
        ret = sprintf_s(cmd, CMS_CMD_BUFFER_SIZE,
            "echo 'script begin';timeout %.2f %s %s %d;echo $?;echo 'script end\n';",
            (float)timeout_ms / CMS_TRANS_MS_TO_SECOND_FLOAT, script, arg, (int32)g_cms_param->node_id);
    }
    PRTS_RETURN_IFERR(ret);
    FILE* fp = popen(cmd, "r");
    if (fp == NULL) {
        CMS_LOG_ERR("popen failed, cmd=%s", cmd);
        return CT_ERROR;
    }

    cms_exec_res_script_print_log(arg, cmd);

    char cmd_out[CMS_CMD_OUT_BUFFER_SIZE];
    size_t size = 0;
    size = fread(cmd_out, 1, CMS_MAX_CMD_OUT_LEN, fp);
    (void)pclose(fp);

    if (size == 0 || size >= sizeof(cmd_out)) {
        CMS_LOG_ERR("fread failed, cmd=%s, size=%lu", cmd, size);
        return CT_ERROR;
    }

    cmd_out[size] = 0;
    if (strstr(cmd_out, "RES_SUCCESS") != NULL) {
        *result = CT_SUCCESS;
    } else {
        CMS_LOG_WAR("script %s, output %s", cmd, cmd_out);
        if (strstr(cmd_out, "124") != NULL) {
            *result = CT_TIMEDOUT;
        } else {
            *result = CT_ERROR;
        }
    }
    CMS_LOG_INF("end cms exec res script.");
    return CT_SUCCESS;
}

status_t cms_res_init(uint32 res_id, uint32 timeout_ms)
{
    status_t ret;
    status_t result;
    cms_res_t res;
    cms_res_stat_t res_stat;

    CT_RETURN_IFERR(cms_get_res_by_id(res_id, &res));

    get_cur_res_stat(res_id, &res_stat);
    if (res_stat.cur_stat == CMS_RES_ONLINE) {
        CMS_LOG_ERR("resource is ONLINE, no need to init, res_name=%s, res_id=%u", res.name, res_id);
        return CT_ERROR;
    }

    ret = cms_exec_res_script(res.script, "-init", res.start_timeout, &result);
    if (ret == CT_SUCCESS) {
        if (result == CT_SUCCESS) {
            CMS_LOG_INF("exec init script succeed, script=%s, res_id=%u", res.script, res_id);
            ret = cms_res_started(res_id);
        } else {
            CMS_LOG_ERR("exec init script succeed, but result is failed, script=%s, res_id %u", res.script, res_id);
        }
    } else {
        CMS_LOG_ERR("exec init script failed, script=%s, res_id=%u", res.script, res_id);
    }

    return ret;
}

static bool32 is_cur_res_offline(cms_res_status_t *res_stat)
{
    // cur res stat in RC_CMS_REMOTE_CURRENT should be [offline, joining]
    // Otherwise, wait until the offline process ends.
    if (res_stat->stat == CMS_RES_OFFLINE && (res_stat->work_stat == RC_JOINING)) {
        return CT_TRUE;
    }
    CMS_LOG_INF("cur res stat is not [offline joining], res stat[%s, %d]", cms_stat_str(res_stat->stat),
        res_stat->work_stat);
    return CT_FALSE;
}

static bool32 cms_res_stat_steady(cms_res_status_list_t *res_stat_list, cms_res_t *res)
{
    cms_res_status_t *res_stat = NULL;
    uint8 inst_id = 0;
    
    // Prevents the cantian from being started too quickly and the target view remains unchanged.
    if (is_cur_res_offline(&res_stat_list->inst_list[g_cms_param->node_id]) == CT_FALSE) {
        return CT_FALSE;
    }

    for (inst_id = 0; inst_id < res_stat_list->inst_count; inst_id++) {
        res_stat = &res_stat_list->inst_list[inst_id];
        if (res_stat->stat == CMS_RES_ONLINE && (res_stat->work_stat != RC_JOINED)) {
            CMS_LOG_INF("reform is in process, inst %d is not steady, stat %s, work_stat %d", inst_id,
                cms_stat_str(res_stat->stat), res_stat->work_stat);
            return CT_FALSE;
        }
        if (res_stat->stat == CMS_RES_OFFLINE && (res_stat->work_stat != RC_JOINING)) {
            CMS_LOG_INF("reform is in process, inst %d is not steady, stat %s, work_stat %d", inst_id,
                cms_stat_str(res_stat->stat), res_stat->work_stat);
            return CT_FALSE;
        }
    }
    return CT_TRUE;
}

static status_t cms_check_cluster_reform_stat(uint32 res_id, bool32 *reform_done)
{
    cms_res_status_list_t cur_res_stat;
    cms_res_status_list_t target_res_stat;
    uint32 data_size = 0;
    uint64 data_version = 0;
    cms_res_t res;
    CT_RETURN_IFERR(cms_get_res_by_id(res_id, &res));
    if (cms_stat_get_res_data(res.type, RC_CMS_REMOTE_CURRENT, (char *)&cur_res_stat, sizeof(cms_res_status_list_t),
        &data_size, &data_version) != CT_SUCCESS) {
        CMS_LOG_ERR("cms get res cur cluster stat failed, res_id %u", res_id);
        return CT_ERROR;
    }

    if (cms_stat_get_res_data(res.type, RC_CMS_REMOTE_TARGET, (char *)&target_res_stat, sizeof(cms_res_status_list_t),
        &data_size, &data_version) != CT_SUCCESS) {
        CMS_LOG_ERR("cms get res target cluster stat failed, res_id %u", res_id);
        return CT_ERROR;
    }

    if (cur_res_stat.version < target_res_stat.version) {
        *reform_done = CT_FALSE;
        CMS_LOG_INF("cms cur version %llu less than target version %llu, reform is in process", cur_res_stat.version,
            target_res_stat.version);
        return CT_SUCCESS;
    }

    if (!cms_res_stat_steady(&cur_res_stat, &res)) {
        *reform_done = CT_FALSE;
        CMS_LOG_INF("cms cur res stat is not steady, reform is in process");
        return CT_SUCCESS;
    }

    *reform_done = CT_TRUE;
    return CT_SUCCESS;
}

status_t cms_get_cluster_res_list(uint32 res_id, cms_res_status_list_t *stat)
{
    uint32 node_count = cms_get_gcc_node_count();

    for (uint32 node_id = 0; node_id < node_count; node_id++) {
        cms_node_def_t node_def;
        if (cms_get_node_by_id(node_id, &node_def) != CT_SUCCESS) {
            continue;
        }

        cms_res_stat_t res_stat;
        if (get_res_stat(node_id, res_id, &res_stat) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (res_stat.cur_stat == CMS_RES_OFFLINE) {
            stat->inst_list[stat->inst_count].inst_id = (uint8)0xff;
        } else {
            stat->inst_list[stat->inst_count].inst_id = (uint8)res_stat.inst_id;
        }
        stat->inst_list[stat->inst_count].node_id = node_id;
        stat->inst_list[stat->inst_count].stat = res_stat.cur_stat;
        stat->inst_list[stat->inst_count].work_stat = res_stat.work_stat;
        stat->inst_list[stat->inst_count].hb_time = res_stat.hb_time;
        stat->inst_list[stat->inst_count].session_id = res_stat.session_id;
        errno_t ret = strcpy_s(stat->inst_list[stat->inst_count].node_ip, CM_MAX_IP_LEN, node_def.ip);
        MEMS_RETURN_IFERR(ret);
        stat->inst_count++;
    }
    return CT_SUCCESS;
}

#define RETRY_SLEEP_TIME 10
static bool32 res_is_full_restart(uint32 res_id)
{
    cms_res_status_list_t stat;
    errno_t err = memset_s(&stat, sizeof(cms_res_status_list_t), 0, sizeof(cms_res_status_list_t));
    if (err != EOK) {
        CMS_LOG_INF("memset_s failed, ret %d, errno %d[%s]", err, errno, strerror(errno));
        return CT_FALSE;
    }

    for (;;) {
        if (cms_get_cluster_res_list(res_id, &stat) != CT_SUCCESS) {
            cm_sleep(RETRY_SLEEP_TIME);
            continue;
        }
        break;
    }
    CMS_LOG_INF("successfully get cluster stat");

    bool32 full_restart = CT_TRUE;
    char hb_str[32];
    for (uint8 i = 0; i < stat.inst_count; i++) {
        cms_date2str(stat.inst_list[i].hb_time, hb_str, sizeof(hb_str));
        if (stat.inst_list[i].stat == CMS_RES_ONLINE &&
            stat.inst_list[i].hb_time + g_cms_param->detect_disk_timeout * MICROSECS_PER_SECOND >= cm_now() &&
            stat.inst_list[i].work_stat == RC_JOINED) {
            CMS_LOG_INF("res(%d) in node(%d) have been jioned to the cluster, res hb_time %s", res_id,
                stat.inst_list[i].node_id, hb_str);
            full_restart = CT_FALSE;
            break;
        }
        CMS_LOG_INF("res(%d) in node(%d) is offline, res stat %s, work_stat %d, hb_time %s", res_id,
            stat.inst_list[i].node_id, cms_stat_str(stat.inst_list[i].stat), stat.inst_list[i].work_stat, hb_str);
    }

    return full_restart;
}

status_t wait_for_cluster_reform_done(uint32 res_id)
{
    bool32 reform_done = CT_TRUE;

    for (;;) {
        if (res_is_full_restart(res_id)) {
            CMS_LOG_INF("res %u is full restart, no need to check reform stat", res_id);
            return CT_SUCCESS;
        }

        if (cms_check_cluster_reform_stat(res_id, &reform_done) != CT_SUCCESS) {
            CMS_LOG_ERR("cms check cluster reform stat failed, res_id %u", res_id);
            return CT_ERROR;
        }

        if (reform_done == CT_FALSE) {
            cm_sleep(CMS_WAIT_REFORM_DONE_INTERNAL);
            continue;
        } else {
            break;
        }
    }
    return CT_SUCCESS;
}

status_t cms_get_start_lock(cms_disk_lock_t *lock, bool32 *cms_get_lock)
{
    uint64 inst_id = CT_INVALID_ID64;
    uint16 node_id = CT_INVALID_ID16;
    if (cms_disk_lock_get_inst(lock, &inst_id) != CT_SUCCESS) {
        CMS_LOG_ERR("cms get lock inst_id failed");
        return CT_ERROR;
    }
    if (inst_id == CT_INVALID_ID64) {
        node_id = CT_INVALID_ID16;
        CMS_LOG_INF("res start lock inst_id %d", node_id);
    } else {
        node_id = (uint16)inst_id;
        CMS_LOG_INF("res start lock locked by node %u", node_id);
    }
    if (node_id == g_cms_param->node_id) {
        *cms_get_lock = CT_TRUE;
    }

    return CT_SUCCESS;
}

void try_lock_start_lock(void)
{
    status_t ret;
    do {
        ret = cms_disk_try_lock(&g_cms_inst->res_start_lock, DISK_LOCK_WRITE);
        cm_sleep(CMS_START_RES_RETRY_INTERNAL);
    } while (ret != CT_SUCCESS);
}

status_t cms_get_res_start_lock(uint32 res_id)
{
    try_lock_start_lock();
    return CT_SUCCESS;
}

void cms_release_res_start_lock(uint32 res_id)
{
    cms_disk_unlock(&g_cms_inst->res_start_lock, DISK_LOCK_WRITE);
}

status_t cms_clear_restart_count(uint32 res_id)
{
    if (cms_res_is_invalid(res_id)) {
        CMS_LOG_ERR("invalid resource, res_id=%u", res_id);
        return CT_ERROR;
    }
    cms_res_stat_t* res_stat = CMS_CUR_RES_STAT(res_id);
    res_stat->restart_count = 0;
    CMS_LOG_INF("clear restart count success, the restart count is (%d).", res_stat->restart_count);
    return CT_SUCCESS;
}

static status_t wait_for_node_joined(uint32 res_id, uint32 timeout_ms)
{
    cms_res_stat_t res_stat;
    uint64 begin_time = cm_now();
    uint64 now_time = cm_now();

    for (;;) {
        get_cur_res_stat(res_id, &res_stat);
        if (res_stat.cur_stat == CMS_RES_ONLINE && res_stat.work_stat == RC_JOINED) {
            if (cms_clear_restart_count(res_id) != CT_SUCCESS) {
                CMS_LOG_ERR("res %u start failed, clear the restart count failed", res_id);
                return CT_ERROR;
            }
            CMS_LOG_INF("cms start res succeed");
            break;
        }

        CMS_LOG_INF("cms waiting for res jioned");
        cm_sleep(CMS_WAIT_RES_JOINED_INTERNAL);
        now_time = cm_now();
        if (now_time - begin_time > timeout_ms * MICROSECS_PER_MILLISEC) {
            if (res_stat.cur_stat == CMS_RES_OFFLINE) {
                CMS_LOG_ERR("res %u start failed, cur_stat is offline, work_stat %u", res_id, res_stat.work_stat);
                return CT_ERROR;
            }
        }
    }
    return CT_SUCCESS;
}

status_t cms_wait_res_started(uint32 res_id, uint32 timeout_ms)
{
    if (cms_res_started(res_id) != CT_SUCCESS) {
        CMS_LOG_ERR("cms update res target stat online failed");
        return CT_ERROR;
    }
    CMS_LOG_INF("cms update res target stat online succeed");
    return wait_for_node_joined(res_id, timeout_ms);
}

status_t cms_check_res_running(uint32 res_id)
{
    bool32 res_running = CT_TRUE;
    uint64 res_check_count = 0;
    while (res_running == CT_TRUE) {
        if (res_check_count > CMS_CHECK_RES_RUNING_TIMES) {
            CMS_LOG_WAR("cms check res %u is running, no need to start", res_id);
            cms_stat_reset_restart_attr(res_id);
            return CT_ERROR;
        }
        cms_res_check(res_id, &res_running);
        res_check_count++;
        cm_sleep(CMS_START_RES_RETRY_INTERNAL);
    }
    return CT_SUCCESS;
}

status_t cms_res_start(uint32 res_id, uint32 timeout_ms)
{
    status_t ret;
    status_t result;
    cms_res_t res;
    cms_res_stat_t res_stat;

    CT_RETURN_IFERR(cms_get_res_by_id(res_id, &res));

    CMS_LOG_INF("begin start res, res_id=%u", res_id);

    CMS_LOG_INF("begin to get start lock, res_id=%u", res_id);
    if (cms_get_res_start_lock(res_id) != CT_SUCCESS) {
        CMS_LOG_ERR("cms check res start condition failed, res_name=%s, res_id=%u", res.name, res_id);
        return CT_ERROR;
    }
    
    get_cur_res_stat(res_id, &res_stat);
    if (res_stat.cur_stat == CMS_RES_ONLINE) {
        CMS_LOG_ERR("resource is ONLINE, no need to start, res_name=%s, res_id=%u", res.name, res_id);
        cms_release_res_start_lock(res_id);
        return CT_SUCCESS;
    }

    if (wait_for_cluster_reform_done(res_id) != CT_SUCCESS) {
        CMS_LOG_ERR("cms wait cluster reform done failed");
        cms_release_res_start_lock(res_id);
        return CT_ERROR;
    }
    CMS_LOG_INF("cms cluster reform done");
    if (cms_check_res_running(res_id) != CT_SUCCESS) {
        cms_release_res_start_lock(res_id);
        return CT_ERROR;
    }

    CMS_LOG_INF("begin to exec start script, res_id=%u", res_id);
    ret = cms_exec_res_script(res.script, "-start", res.start_timeout, &result);
    if (ret == CT_SUCCESS) {
        if (result == CT_SUCCESS) {
            CMS_LOG_INF("exec start script succeed, script=%s, res_id=%u", res.script, res_id);
            ret = cms_wait_res_started(res_id, timeout_ms);
        } else {
            CMS_LOG_ERR("exec start script succeed, but result %u is failed, script=%s, res_id=%u", result, res.script,
                res_id);
            cms_release_res_start_lock(res_id);
            return result;
        }
    } else {
        CMS_LOG_ERR("exec start script failed, script=%s, res_id=%u", res.script, res_id);
    }

    cms_release_res_start_lock(res_id);
    CMS_LOG_INF("end start res, res_id=%u, ret = %d", res_id, ret);

    return ret;
}

status_t cms_res_stop_by_force(uint32 res_id, uint8 need_write_disk)
{
    CMS_LOG_INF("begin exec res stop by force, res_id=%u, need_write_disk=%u.", res_id, need_write_disk);
    status_t ret;
    status_t result;
    cms_res_t res;

    CT_RETURN_IFERR(cms_get_res_by_id(res_id, &res));

    ret = cms_exec_res_script(res.script, "-stop_force", res.stop_timeout, &result);
    if (ret == CT_SUCCESS) {
        if (result == CT_SUCCESS) {
            CMS_LOG_INF("exec stop by force script succeed, script=%s, res_id=%u", res.script, res_id);
            if (need_write_disk == CT_TRUE) {
                ret = cms_res_stopped(res_id);
            }
        } else {
            CMS_LOG_ERR("exec stop by force script succeed, but result is failed, script=%s, res_id=%u", res.script, res_id);
            return result;
        }
    } else {
        CMS_LOG_ERR("exec stop by force script failed, script=%s", res.script);
    }
    CMS_LOG_INF("end exec res stop by force succeed, res_id=%u, ret=%d", res_id, ret);
    return ret;
}

status_t cms_res_stop(uint32 res_id, uint8 need_write_disk)
{
    CMS_LOG_INF("begin exec res stop, res_id=%u, need_write_disk=%u.", res_id, need_write_disk);
    status_t ret;
    status_t result;
    cms_res_t res;

    CT_RETURN_IFERR(cms_get_res_by_id(res_id, &res));

    ret = cms_exec_res_script(res.script, "-stop", res.stop_timeout, &result);
    if (ret == CT_SUCCESS) {
        if (result == CT_SUCCESS) {
            CMS_LOG_INF("exec stop script succeed, script=%s, res_id=%u", res.script, res_id);
            if (need_write_disk == CT_TRUE) {
                ret = cms_res_stopped(res_id);
            }
        } else {
            CMS_LOG_ERR("exec stop script succeed, but result is failed, script=%s, res_id=%u", res.script, res_id);
            return result;
        }
    } else {
        CMS_LOG_ERR("exec stop script failed, script=%s", res.script);
    }
    CMS_LOG_INF("end exec res stop succeed, res_id=%u, ret=%d", res_id, ret);
    return ret;
}

status_t cms_res_check(uint32 res_id, bool32 *res_running)
{
    status_t ret = CT_SUCCESS;
    status_t result;
    cms_res_t res;

    CT_RETURN_IFERR(cms_get_res_by_id(res_id, &res));
    cms_res_stat_t* res_stat = CMS_CUR_RES_STAT(res_id);

    if (cm_atomic32_inc(&res_stat->checking) != 1) {
        cm_atomic32_dec(&res_stat->checking);
        CMS_LOG_WAR("resource is being checked, res_id=%u, checking=%d", res_id, cm_atomic32_get(&res_stat->checking));
        return CT_SUCCESS;
    }

    ret = cms_exec_res_script(res.script, "-check", res.check_timeout, &result);
    cm_atomic32_dec(&res_stat->checking);

    if (ret == CT_SUCCESS) {
        if (result == CT_SUCCESS) {
            CMS_LOG_TIMER("exec check script succeed, script=%s, res_id=%u", res.script, res_id);
            *res_running = CT_TRUE;
        } else {
            CMS_LOG_TIMER("exec check script succeed, but result is failed, script=%s, res_id=%u", res.script, res_id);
            *res_running = CT_FALSE;
        }
    } else {
        CMS_LOG_TIMER("exec check script failed, script=%s, res_id=%u", res.script, res_id);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t cms_res_reset(uint32 res_id)
{
    status_t ret = CT_SUCCESS;
    status_t result;
    cms_res_t res;

    CT_RETURN_IFERR(cms_get_res_by_id(res_id, &res));

    ret = cms_exec_res_script(res.script, "-reset", res.stop_timeout, &result);
    if (ret == CT_SUCCESS) {
        if (result == CT_SUCCESS) {
            CMS_LOG_INF("exec reset script succeed, res id %u", res_id);
        } else {
            CMS_LOG_ERR("exec reset script succeed, but result is failed, script=%s, res_id=%u", res.script, res_id);
        }
    } else {
        CMS_LOG_ERR("exec reset script failed, script=%s, res_id=%u", res.script, res_id);
    }

    return ret;
}

status_t update_res_target_stat(uint32 res_id, cms_stat_t target_stat)
{
    if (cms_res_is_invalid(res_id)) {
        CMS_LOG_ERR("invalid resource, res_id=%u", res_id);
        return CT_ERROR;
    }

    cms_res_stat_t* res_stat = CMS_CUR_RES_STAT(res_id);

    cm_thread_lock(&g_res_session[res_id].lock);
    res_stat->target_stat = target_stat;
    if (cms_sync_cur_res_stat(res_id, res_stat) != CT_SUCCESS) {
        cm_thread_unlock(&g_res_session[res_id].lock);
        return CT_ERROR;
    }

    cm_thread_unlock(&g_res_session[res_id].lock);

    return CT_SUCCESS;
}

status_t cms_res_started(uint32 res_id)
{
    return update_res_target_stat(res_id, CMS_RES_ONLINE);
}

status_t cms_res_stopped(uint32 res_id)
{
    return update_res_target_stat(res_id, CMS_RES_OFFLINE);
}

status_t cms_res_hb(uint32 res_id)
{
    if (cms_res_is_invalid(res_id)) {
        CMS_LOG_ERR("invalid resource, res_id %u", res_id);
        return CT_ERROR;
    }

    cms_res_stat_t* res_stat = CMS_CUR_RES_STAT(res_id);
    res_stat->hb_time = cm_now(); // cluster time
    res_stat->last_check = res_stat->hb_time;

    biqueue_node_t *node = cms_que_alloc_node(sizeof(cms_packet_aync_write_t));
    if (node == NULL) {
        CMS_LOG_ERR("cms malloc msg cms_packet_aync_write_t failed.");
        return CT_ERROR;
    }
    cms_packet_aync_write_t *msg = (cms_packet_aync_write_t *)cms_que_node_data(node);
    biqueue_node_t *node_hb_aync = cms_que_alloc_node(sizeof(cms_hb_aync_start_t));
    if (node_hb_aync == NULL) {
        CMS_LOG_ERR("cms malloc msg cms_hb_aync_start_t failed.");
        cms_que_free_node(node);
        return CT_ERROR;
    }
    cms_hb_aync_start_t *msg_hb_aync = (cms_hb_aync_start_t *)cms_que_node_data(node_hb_aync);
    msg->res_id = res_id;
    (void)cm_gettimeofday(&(msg_hb_aync->hb_time_aync_start));
    cms_enque(&g_hb_aync_gap_que, node_hb_aync);
    cms_enque(&g_cms_inst->aync_write_que, node);

    return CT_SUCCESS;
}

status_t cms_res_detect_online(uint32 res_id, cms_res_stat_t *old_stat)
{
    bool32 is_changed;
    cms_res_t res;
    if (cms_get_res_by_id(res_id, &res) != CT_SUCCESS) {
        CMS_LOG_ERR("invalid resource, res_id=%u", res_id);
        return CT_ERROR;
    }

    cms_res_stat_t* res_stat = CMS_CUR_RES_STAT(res_id);

    cm_thread_lock(&g_res_session[res_id].lock);
    if (old_stat != NULL && res_stat->cur_stat != old_stat->cur_stat) {
        CMS_LOG_INF("res stat has been changed, res_stat = %d, old_stat = %d", res_stat->cur_stat, old_stat->cur_stat);
        cm_thread_unlock(&g_res_session[res_id].lock);
        return CT_ERROR;
    }
    cms_stat_set(res_stat, CMS_RES_ONLINE, &is_changed);
    if (!(is_changed)) {
        cm_thread_unlock(&g_res_session[res_id].lock);
        return CT_SUCCESS;
    }

    CMS_LOG_INF("cms_res_detect_online, res name=%s", res.name);
    if (cms_sync_cur_res_stat(res_id, res_stat) != CT_SUCCESS) {
        cm_thread_unlock(&g_res_session[res_id].lock);
        return CT_ERROR;
    }

    if (inc_stat_version() != CT_SUCCESS) {
        CMS_LOG_ERR("cms inc stat version fialed, g_stat->head.stat_ver = %llu", g_stat->head.stat_ver);
        cm_thread_unlock(&g_res_session[res_id].lock);
        return CT_ERROR;
    }

    uint64 version = g_stat->head.stat_ver;

    cm_thread_unlock(&g_res_session[res_id].lock);

    cms_do_try_master();

    cms_stat_chg_notify_to_cms(res_id, version);

    return CT_SUCCESS;
}

uint32 cms_online_res_count(uint32 res_id, iofence_type_t iofence_type)
{
    uint32 online_node_count = 0;
    uint32 node_count = cms_get_gcc_node_count();

    for (uint32 node_id = 0; node_id < node_count; node_id++) {
        if (node_id == g_cms_param->node_id) {
            if (iofence_type == IOFENCE_BY_DETECT_OFFLINE) {
                continue;
            }
            if (g_stat->node_inf[node_id].res_stat[(res_id)].cur_stat == CMS_RES_ONLINE) {
                online_node_count++;
                continue;
            }
        }

        CMS_RETRY_IF_ERR(stat_read(CMS_RES_STAT_POS(node_id, res_id), (char *)CMS_RES_STAT(node_id, res_id),
            sizeof(cms_res_stat_t)));
        if (g_stat->node_inf[node_id].res_stat[(res_id)].cur_stat == CMS_RES_ONLINE) {
            online_node_count++;
        }
    }
    return online_node_count;
}

status_t cms_res_detect_offline(uint32 res_id, cms_res_stat_t *old_stat)
{
    bool32 is_changed;
    cms_res_t res;
    if (cms_get_res_by_id(res_id, &res) != CT_SUCCESS) {
        CMS_LOG_ERR("invalid resource, res_id %u", res_id);
        return CT_ERROR;
    }

    cms_res_stat_t* res_stat = CMS_CUR_RES_STAT(res_id);
    cm_thread_lock(&g_res_session[res_id].lock);
    if (old_stat != NULL && res_stat->cur_stat != old_stat->cur_stat) {
        CMS_LOG_INF("res stat has been changed, res_stat %d, old_stat %d", res_stat->cur_stat, old_stat->cur_stat);
        cm_thread_unlock(&g_res_session[res_id].lock);
        return CT_ERROR;
    }

    cm_thread_lock(&g_res_session[res_id].uds_lock);
    if (g_res_session[res_id].uds_sock != CMS_IO_INVALID_SOCKET) {
        CMS_LOG_INF("close uds sock, sock %d, res id %u, res name %s", g_res_session[res_id].uds_sock,
            res_id, res.name);
        cms_socket_close(g_res_session[res_id].uds_sock);
        g_res_session[res_id].uds_sock = CMS_IO_INVALID_SOCKET;
    }
    cm_thread_unlock(&g_res_session[res_id].uds_lock);

    CMS_SYNC_POINT_GLOBAL_START(CMS_RES_LOCAL_TO_OFFLINE_ABORT, NULL, 0);
    CMS_SYNC_POINT_GLOBAL_END;

    if (res_stat->cur_stat == CMS_RES_OFFLINE) {
        cm_thread_unlock(&g_res_session[res_id].lock);
        return CT_SUCCESS;
    }

    try_cms_kick_node(g_cms_param->node_id, res_id, IOFENCE_BY_DETECT_OFFLINE);

    cms_stat_set(res_stat, CMS_RES_OFFLINE, &is_changed);
    res_stat->restart_count = res.restart_times;
    if (cms_sync_cur_res_stat(res_id, res_stat) != CT_SUCCESS) {
        CMS_LOG_ERR("sync curr res stat failed, res id %u, res stat %d", res_id, res_stat->cur_stat);
        cm_thread_unlock(&g_res_session[res_id].lock);
        return CT_ERROR;
    }
    // The g_res_session[res_id].lock may not be released due to the iofence failure.
    cm_thread_unlock(&g_res_session[res_id].lock);
    CMS_SYNC_POINT_GLOBAL_START(CMS_DETECT_OFFLINE_BEFORE_INCVER_ABORT, NULL, 0);
    CMS_SYNC_POINT_GLOBAL_END;

    cm_thread_lock(&g_res_session[res_id].lock);
    if (inc_stat_version() != CT_SUCCESS) {
        CMS_LOG_ERR("cms inc stat version fialed, g_stat->head.stat_ver = %llu", g_stat->head.stat_ver);
        cm_thread_unlock(&g_res_session[res_id].lock);
        return CT_ERROR;
    }
    uint64 version = g_stat->head.stat_ver;
    CMS_LOG_WAR("cms detect res offline, res id %u, res name %s stat ver %llu", res_id, res.name, version);
    cm_thread_unlock(&g_res_session[res_id].lock);

    cms_do_try_master();
    if (res_stat->pre_stat != CMS_RES_UNKNOWN && res_stat->last_check +
        res.hb_timeout * MICROSECS_PER_MILLISEC > cm_now()) {
        // cms_stat_chg_offline_reset_res(res); TODO open after resource online/offline is complete
    }
    cms_stat_chg_notify_to_cms(res_id, version);

    return CT_SUCCESS;
}

void cms_tool_detect_offline(uint32 session_id)
{
    cm_thread_lock(&g_session_lock);
    if (g_res_session[session_id].uds_sock != CMS_IO_INVALID_SOCKET) {
        cms_socket_close(g_res_session[session_id].uds_sock);
        g_res_session[session_id].uds_sock = CMS_IO_INVALID_SOCKET;
        g_tool_session_count--;
    }
    cm_thread_unlock(&g_session_lock);
    return;
}

void cms_stat_update_restart_attr(uint32 res_id)
{
    cms_res_stat_t* res_stat = CMS_CUR_RES_STAT(res_id);
    if (res_stat->restart_count != -1 && res_stat->restart_count > 0) {
        res_stat->restart_count = res_stat->restart_count - 1;
    }
    res_stat->restart_time = cm_now();
}

void cms_stat_reset_restart_attr(uint32 res_id)
{
    cms_res_t res;
    if (cms_get_res_by_id(res_id, &res) != CT_SUCCESS) {
        CMS_LOG_ERR("invalid resource, res_id %u", res_id);
        return;
    }

    cms_res_stat_t* res_stat = CMS_CUR_RES_STAT(res_id);
    res_stat->restart_count = res.restart_times;
    CMS_LOG_INF("reset restart count success, the restart count is (%d).", res_stat->restart_count);
}

status_t cms_res_no_hb(uint32 res_id)
{
    if (cms_res_is_invalid(res_id)) {
        CMS_LOG_ERR("invalid resource, res_id=%u", res_id);
        return CT_ERROR;
    }

    cms_res_stat_t* res_stat = CMS_CUR_RES_STAT(res_id);
    res_stat->last_check = cm_now(); // cluster time

    biqueue_node_t *node = cms_que_alloc_node(sizeof(cms_packet_aync_write_t));
    if (node == NULL) {
        CMS_LOG_ERR("cms malloc msg cms_packet_aync_write_t failed.");
        return CT_ERROR;
    }
    cms_packet_aync_write_t* msg = (cms_packet_aync_write_t*)cms_que_node_data(node);
    msg->res_id = res_id;
    cms_enque(&g_cms_inst->aync_write_que, node);

    return CT_SUCCESS;
}

status_t get_res_stat(uint32 node_id, uint32 res_id, cms_res_stat_t* res_stat)
{
    status_t ret;

    if (cms_node_is_invalid(node_id)) {
        CMS_LOG_ERR("invalid node id, node_id=%u", node_id);
        return CT_ERROR;
    }

    cms_res_stat_t* res_stat_new = CMS_RES_STAT(node_id, res_id);
    uint32 size = CM_ALIGN_512(sizeof(cms_res_stat_t));
    cms_res_stat_t* res_cur_stat = (cms_res_stat_t*)cm_malloc_align(CMS_BLOCK_SIZE, size);
    if (res_cur_stat == NULL) {
        CMS_LOG_ERR("cm_malloc_align failed, alloc_size=%u", size);
        return CT_ERROR;
    }
    if (g_cms_inst->is_server && node_id == g_cms_param->node_id) {
        res_stat_new = res_cur_stat;
    }

    cm_thread_lock(&g_node_lock[node_id]);
    if (cms_disk_lock(&g_cms_inst->res_stat_lock[node_id][res_id], DISK_LOCK_WAIT_TIMEOUT, DISK_LOCK_READ) !=
        CT_SUCCESS) {
        CM_FREE_PTR(res_cur_stat);
        CMS_LOG_ERR("cms_disk_lock timeout.");
        cm_thread_unlock(&g_node_lock[node_id]);
        return CT_ERROR;
    }

    ret = stat_read(CMS_RES_STAT_POS(node_id, res_id), (char *)res_stat_new, sizeof(cms_res_stat_t));
    cms_disk_unlock(&g_cms_inst->res_stat_lock[node_id][res_id], DISK_LOCK_READ);
    if (ret != CT_SUCCESS) {
        CM_FREE_PTR(res_cur_stat);
        CMS_LOG_ERR("stat read failed");
        cm_thread_unlock(&g_node_lock[node_id]);
        return CT_ERROR;
    }

    errno_t err = memcpy_s(res_stat, sizeof(cms_res_stat_t), res_stat_new, sizeof(cms_res_stat_t));
    CM_FREE_PTR(res_cur_stat);
    cm_thread_unlock(&g_node_lock[node_id]);
    MEMS_RETURN_IFERR(err);

    return CT_SUCCESS;
}

void get_cur_res_stat(uint32 res_id, cms_res_stat_t* res_stat)
{
    cm_thread_lock(&g_res_session[res_id].lock);
    errno_t ret = memcpy_s(res_stat, sizeof(cms_res_stat_t), CMS_CUR_RES_STAT(res_id), sizeof(cms_res_stat_t));
    cm_thread_unlock(&g_res_session[res_id].lock);
    MEMS_RETVOID_IFERR(ret);
}

void cms_stat_set(cms_res_stat_t* res_stat, cms_stat_t new_stat, bool32* isChanged)
{
    char hb_time[32], last_check[32];

    if (res_stat->cur_stat != new_stat) {
        res_stat->pre_stat = res_stat->cur_stat;
        res_stat->cur_stat = new_stat;
        res_stat->last_stat_change = cm_now(); // cluster time
        if (new_stat == CMS_RES_OFFLINE) {
            res_stat->inst_id = CT_INVALID_ID64;
            res_stat->session_id = CT_INVALID_ID64;
            res_stat->work_stat = 0;
            res_stat->hb_time = 0;
            res_stat->restart_time = cm_now();
        }

        cms_date2str(res_stat->hb_time, hb_time, sizeof(hb_time));
        cms_date2str(res_stat->last_check, last_check, sizeof(last_check));

        CMS_LOG_INF("resource state changed, version=%lld, res_type=%s, session_id=%lld, inst_id=%lld,"
                    "cur_stat=%s, work_stat=%d, pre_stat=%s, target_stat=%s, hb_time=%s, last_check=%s",
                    g_stat->head.stat_ver,
                    res_stat->res_type,
                    res_stat->session_id,
                    res_stat->inst_id,
                    cms_stat_str(res_stat->cur_stat),
                    (int)res_stat->work_stat,
                    cms_stat_str(res_stat->pre_stat),
                    cms_stat_str(res_stat->target_stat),
                    hb_time, last_check);
        *isChanged = CT_TRUE;
    } else {
        *isChanged = CT_FALSE;
    }
}

static void cms_get_res_init_info(const char *res_type, uint32 res_id, res_init_info_t *res_info)
{
    uint32 data_size;
    uint64 data_version;

    bool32 full_restart = res_is_full_restart(res_id);
    if (!full_restart) {
        CMS_LOG_INF("res is not full restart");
        for (;;) {
            if (cms_stat_get_res_data(res_type, RC_REFORM_TRIGGER_VERSION, (char *)&res_info->trigger_version,
                sizeof(uint64), &data_size, &data_version) != CT_SUCCESS) {
                cm_sleep(RETRY_SLEEP_TIME);
                continue;
            }
            break;
        }
        CMS_LOG_INF("cms get trigger_version = %lld", res_info->trigger_version);
        for (;;) {
            if (cms_stat_get_res_data(res_type, RC_CMS_REMOTE_CURRENT, (char *)&res_info->res_stat,
                sizeof(cms_res_status_list_t), &data_size, &data_version) != CT_SUCCESS) {
                cm_sleep(RETRY_SLEEP_TIME);
                continue;
            }
            break;
        }
    }
}

static status_t cms_res_register_conn(socket_t sock, cms_cli_msg_req_conn_t *req, uint32 res_id, cms_res_stat_t *res_stat, uint64 *version)
{
    bool32 is_changed;
    cm_thread_lock(&g_res_session[res_id].lock);
    res_stat->inst_id = req->inst_id;
    res_stat->hb_time = cm_now(); // cluster time
    res_stat->target_stat = CMS_RES_ONLINE;
    res_stat->last_check = res_stat->hb_time;
    cms_stat_set(res_stat, CMS_RES_ONLINE, &is_changed);
    res_stat->session_id = res_id;
    res_stat->work_stat = 0;
    errno_t err = strcpy_s(res_stat->res_type, sizeof(res_stat->res_type), req->res_type);
    if (err != EOK) {
        cm_thread_unlock(&g_res_session[res_id].lock);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, err);
        return CT_ERROR;
    }
    if (cms_sync_cur_res_stat(res_id, res_stat) != CT_SUCCESS) {
        CMS_LOG_ERR("cms sync cur res stat failed");
        cm_thread_unlock(&g_res_session[res_id].lock);
        return CT_ERROR;
    }
    CMS_SYNC_POINT_GLOBAL_START(CMS_REG_ONLINE_BEFORE_INCVER_ABORT, NULL, 0);
    CMS_SYNC_POINT_GLOBAL_END;

    if (inc_stat_version() != CT_SUCCESS) {
        CMS_LOG_ERR("cms inc stat version failed");
        cm_thread_unlock(&g_res_session[res_id].lock);
        return CT_ERROR;
    }

    *version = g_stat->head.stat_ver;
    g_res_session[res_id].uds_sock = sock;
    g_res_session[res_id].type = CMS_CLI_RES;
    cm_thread_unlock(&g_res_session[res_id].lock);
    return CT_SUCCESS;
}

status_t cms_res_connect(socket_t sock, cms_cli_msg_req_conn_t *req, cms_cli_msg_res_conn_t *res)
{
    uint32 res_id;
    cms_res_stat_t *res_stat;
    uint64 version = 0;
    
    CMS_LOG_INF("process resource connect, res_type %s, inst_id %u", req->res_type, req->inst_id);
    // find resource
    if (cms_get_res_id_by_type(req->res_type, &res_id) != CT_SUCCESS) {
        CMS_LOG_ERR("cms get res id failed, res_type %s", req->res_type);
        return CT_ERROR;
    }
    if (req->is_retry_conn) {
        CMS_LOG_INF("cli retry connect, res id %u, inst_id %u", res_id, req->inst_id);
        res_stat = CMS_CUR_RES_STAT(res_id);
        cm_thread_lock(&g_res_session[res_id].lock);
        res_stat->hb_time = cm_now(); // cluster time
        res_stat->last_check = res_stat->hb_time;
        res_stat->session_id = res_id;
        g_res_session[res_id].uds_sock = sock;
        g_res_session[res_id].type = CMS_CLI_RES;
        version = g_stat->head.stat_ver;
        cm_thread_unlock(&g_res_session[res_id].lock);
    } else {
        // get trigger_version and cur res_stat before set CMS_RES_ONLINE
        cms_get_res_init_info(req->res_type, res_id, &res->res_init_info);
        res_stat = CMS_CUR_RES_STAT(res_id);

        CMS_SYNC_POINT_GLOBAL_START(CMS_RES_OFFLINE_TO_ONLINE_ABORT, NULL, 0);
        CMS_SYNC_POINT_GLOBAL_END;
        if (cms_res_register_conn(sock, req, res_id, res_stat, &version) != CT_SUCCESS) {
            CMS_LOG_ERR("cms resgister conn failed, res_id %u", res_id);
            return CT_ERROR;
        }
        cms_do_try_master();
        cms_stat_chg_notify_to_cms(res_id, version);
    }

    res->head.msg_size = sizeof(cms_cli_msg_res_conn_t);
    res->head.msg_type = CMS_CLI_MSG_RES_CONNECT;
    res->head.msg_version = CMS_MSG_VERSION;
    res->head.msg_seq = cm_now();
    res->head.src_msg_seq = req->head.msg_seq;
    res->session_id = res_stat->session_id;
    res->result = CT_SUCCESS;
    CMS_LOG_INF("resource connected and state changed, version %llu, res_type %s, session_id %llu, inst_id %llu,"
        "cur_stat %s, work_stat %d, pre_stat %s, target_stat %s", version, res_stat->res_type, res_stat->session_id,
        res_stat->inst_id, cms_stat_str(res_stat->cur_stat), (int32)res_stat->work_stat,
        cms_stat_str(res_stat->pre_stat), cms_stat_str(res_stat->target_stat));
    CMS_SYNC_POINT_GLOBAL_START(CMS_RES_CONN_SLEEP, NULL, 0);
    CMS_SYNC_POINT_GLOBAL_END;
    return CT_SUCCESS;
}

status_t cms_tool_connect(socket_t sock, cms_cli_msg_req_conn_t *req, cms_cli_msg_res_conn_t *res)
{
    cm_thread_lock(&g_session_lock);
    if (g_tool_session_count >= CMS_MAX_UDS_SESSION_COUNT) {
        CMS_LOG_ERR("tool session count exceed max count, cli session count %u", g_tool_session_count);
        cm_thread_unlock(&g_session_lock);
        return CT_ERROR;
    }

    for (int32 i = CMS_MAX_RESOURCE_COUNT; i < CMS_MAX_UDS_SESSION_COUNT; i++) {
        if (g_res_session[i].uds_sock == CMS_IO_INVALID_SOCKET) {
            g_res_session[i].uds_sock = sock;
            g_res_session[i].type = CMS_CLI_TOOL;
            res->head.msg_size = sizeof(cms_cli_msg_res_conn_t);
            res->head.msg_type = CMS_CLI_MSG_RES_CONNECT;
            res->head.msg_version = CMS_MSG_VERSION;
            res->head.msg_seq = cm_now();
            res->head.src_msg_seq = req->head.msg_seq;
            res->session_id = i;
            res->master_id = (g_cms_inst->is_dbstor_cli_init == CT_FALSE ? CT_INVALID_ID64 : 0);
            res->result = CT_SUCCESS;
            g_tool_session_count++;
            cm_thread_unlock(&g_session_lock);
            return CT_SUCCESS;
        }
    }
    CMS_LOG_WAR("tool connect failed, can't get avaliable session, res_type %s, inst_id %u, session count %u",
        req->res_type, req->inst_id, g_tool_session_count);
    cm_thread_unlock(&g_session_lock);
    return CT_ERROR;
}

status_t cms_stat_get_uds(uint64 session_id, socket_t *uds_sock)
{
    if (session_id >= CMS_MAX_UDS_SESSION_COUNT) {
        return CT_ERROR;
    }
    cm_thread_lock(&g_res_session[session_id].uds_lock);
    *uds_sock = g_res_session[session_id].uds_sock;
    cm_thread_unlock(&g_res_session[session_id].uds_lock);
    return CT_SUCCESS;
}

status_t cms_res_dis_conn(const char* res_type, uint32 inst_id)
{
    bool32 is_changed = CT_FALSE;
    uint32 res_id = -1;
    status_t ret = CT_SUCCESS;
    errno_t err = EOK;

    CMS_LOG_INF("begin res disconnect, res_type %s, inst_id %u", res_type, inst_id);
    ret = cms_get_res_id_by_type(res_type, &res_id);
    if (ret != CT_SUCCESS) {
        CMS_LOG_ERR("get res id by type failed, res type %s", res_type);
        return ret;
    }
    cms_res_stat_t* res_stat = CMS_CUR_RES_STAT(res_id);
    cm_thread_lock(&g_res_session[res_id].lock);
    res_stat->target_stat = CMS_RES_OFFLINE;
    cms_stat_set(res_stat, CMS_RES_OFFLINE, &is_changed);
    res_stat->inst_id = CT_INVALID_ID64;
    res_stat->session_id = CT_INVALID_ID64;
    res_stat->work_stat = 0;
    err = strcpy_s(res_stat->res_type, sizeof(res_stat->res_type), res_type);
    if (err != EOK) {
        CMS_LOG_ERR("strcpy_s failed, ret %d, errno %d[%s]", err, errno, strerror(errno));
        cm_thread_unlock(&g_res_session[res_id].lock);
        return CT_ERROR;
    }
    
    ret = cms_sync_cur_res_stat(res_id, res_stat);
    if (ret != CT_SUCCESS) {
        CMS_LOG_ERR("sync curr res stat failed, ret %d, res id %u", ret, res_id);
        cm_thread_unlock(&g_res_session[res_id].lock);
        return CT_ERROR;
    }

    ret = inc_stat_version();
    if (ret != CT_SUCCESS) {
        CMS_LOG_ERR("inc stat version failed, ret %d", ret);
        cm_thread_unlock(&g_res_session[res_id].lock);
        return CT_ERROR;
    }

    uint64 version = g_stat->head.stat_ver;
    cm_thread_unlock(&g_res_session[res_id].lock);
    cms_do_try_master();

    CMS_LOG_INF("res disconnect succ, state changed, version %lld, res_type %s, session_id %lld, inst_id %lld, "
        "cur_stat %s, work_stat %d, pre_stat %s, target_stat %s", version, res_stat->res_type, res_stat->session_id,
        res_stat->inst_id, cms_stat_str(res_stat->cur_stat), (int32)res_stat->work_stat,
        cms_stat_str(res_stat->pre_stat), cms_stat_str(res_stat->target_stat));

    cms_stat_chg_notify_to_cms(res_id, version);
    return CT_SUCCESS;
}

status_t cms_res_set_workstat(const char* res_type, uint32 inst_id, uint8 work_stat)
{
    bool32 is_changed;
    uint32 res_id;
    // find resource
    CT_RETURN_IFERR(cms_get_res_id_by_type(res_type, &res_id));

    cms_res_stat_t* res_stat = CMS_CUR_RES_STAT(res_id);
    cm_thread_lock(&g_res_session[res_id].lock);
    res_stat->last_stat_change = cm_now(); // cluster time
    res_stat->work_stat = work_stat;
    res_stat->hb_time = cm_now(); // cluster time
    cms_stat_set(res_stat, CMS_RES_ONLINE, &is_changed);
    if (cms_sync_cur_res_stat(res_id, res_stat) != CT_SUCCESS) {
        cm_thread_unlock(&g_res_session[res_id].lock);
        return CT_ERROR;
    }
    if (work_stat == 1) {
        CMS_SYNC_POINT_GLOBAL_START(CMS_SET_JOINED_BEFORE_INCVER_ABORT, NULL, 0);
        CMS_SYNC_POINT_GLOBAL_END;
    }

    if (inc_stat_version() != CT_SUCCESS) {
        CMS_LOG_ERR("cms inc stat version fialed, g_stat->head.stat_ver = %llu", g_stat->head.stat_ver);
        cm_thread_unlock(&g_res_session[res_id].lock);
        return CT_ERROR;
    }

    uint64 version = g_stat->head.stat_ver;
    cm_thread_unlock(&g_res_session[res_id].lock);

    CMS_LOG_INF("resource setworkstat, state changed, version=%lld, session_id=%lld, inst_id=%lld, "
        "cur_stat=%s, work_stat=%d, pre_stat=%s, target_stat=%s", version, res_stat->session_id,
        res_stat->inst_id, cms_stat_str(res_stat->cur_stat), (int32)res_stat->work_stat,
        cms_stat_str(res_stat->pre_stat), cms_stat_str(res_stat->target_stat));

    cms_stat_chg_notify_to_cms(res_id, version);
    cms_do_try_master();
    return CT_SUCCESS;
}

status_t cms_stat_chg_notify_to_cms(uint32 res_id, uint64 version)
{
#ifdef DB_DEBUG_VERSION
    cms_version_t fake_local_version = { 1, 0, 0, 1 };
    cms_version_t cluster_version;
    cms_get_gcc_ver(&cluster_version.main_ver, &cluster_version.major_ver,
        &cluster_version.revision, &cluster_version.inner);
    CMS_LOG_INF_LIMIT(LOG_PRINT_INTERVAL_SECOND_20, "The cluster version is %d.%d.%d.%d",
        cluster_version.main_ver, cluster_version.major_ver, cluster_version.revision, cluster_version.inner);
    if (cms_cur_version_is_higher_or_equal(cluster_version, fake_local_version)) {
        cms_msg_req_stat_chg_new_t stat_chg_new;
        memset_s(&stat_chg_new, sizeof(stat_chg_new), 0, sizeof(cms_msg_req_stat_chg_new_t));
        stat_chg_new.head.dest_node = g_cms_param->node_id;
        stat_chg_new.head.src_node = -1;
        stat_chg_new.head.msg_size = sizeof(cms_msg_req_stat_chg_new_t);
        stat_chg_new.head.msg_type = CMS_MSG_REQ_STAT_CHG_NEW;
        stat_chg_new.head.msg_version = CMS_MSG_VERSION;
        stat_chg_new.head.src_msg_seq = 0;
        stat_chg_new.head.msg_seq = cm_now();
        stat_chg_new.res_id = res_id;
        stat_chg_new.version = version;
        stat_chg_new.fake_flag = 1;
        CMS_LOG_INF_LIMIT(LOG_PRINT_INTERVAL_SECOND_20, "cms is trying to send the CMS_MSG_REQ_STAT_CHG_NEW");
        cms_broadcast_srv_msg(&stat_chg_new.head);
        CMS_LOG_INF_LIMIT(LOG_PRINT_INTERVAL_SECOND_20, "cms broad cast srv msg stat change, res id %u, version %llu",
            res_id, version);
        return CT_SUCCESS;
    }
#endif
    cms_msg_req_stat_chg_t stat_chg;
    memset_s(&stat_chg, sizeof(stat_chg), 0, sizeof(cms_msg_req_stat_chg_t));
    stat_chg.head.dest_node = g_cms_param->node_id;
    stat_chg.head.src_node = -1;
    stat_chg.head.msg_size = sizeof(cms_msg_req_stat_chg_t);
    stat_chg.head.msg_type = CMS_MSG_REQ_STAT_CHG;
    stat_chg.head.msg_version = CMS_MSG_VERSION;
    stat_chg.head.src_msg_seq = 0;
    stat_chg.head.msg_seq = cm_now();
    stat_chg.res_id = res_id;
    stat_chg.version = version;
    cms_broadcast_srv_msg(&stat_chg.head);
    CMS_LOG_INF_LIMIT(LOG_PRINT_INTERVAL_SECOND_20, "cms broad cast srv msg stat change, res id %u, version %llu",
        res_id, version);
    return CT_SUCCESS;
}

status_t cms_get_stat_version_ex(uint64 version, cms_res_status_list_t* stat)
{
    status_t ret;

    ret = cms_lock_stat(DISK_LOCK_READ);
    if (ret != CT_SUCCESS) {
        CMS_LOG_ERR("lock stat failed");
        return ret;
    }

    ret = stat_read(CMS_STAT_HEAD_POS, (char*)(&g_stat->head), sizeof(cms_cluster_stat_head_t));
    if (ret != CT_SUCCESS) {
        CMS_LOG_ERR("stat read failed");
        (void)cms_unlock_stat(DISK_LOCK_READ);
        return CT_ERROR;
    }
    stat->version = g_stat->head.stat_ver;
    (void)cms_unlock_stat(DISK_LOCK_READ);

    return CT_SUCCESS;
}

status_t cms_get_cluster_stat(uint32 res_id, uint64 version, cms_res_status_list_t* stat_list)
{
    status_t ret = CT_SUCCESS;
    uint8 master_node_id = -1;
    CMS_LOG_DEBUG_INF("begin get cluster stat, res id %u, version %llu", res_id, version);
    if (cms_res_is_invalid(res_id)) {
        CMS_LOG_ERR("invalid resource, res_id %u", res_id);
        return CT_ERROR;
    }

    ret = cms_get_res_master(res_id, &master_node_id);
    if (ret != CT_SUCCESS) {
        CMS_LOG_ERR("get res master failed, ret %d, res_id %u", ret, res_id);
        return ret;
    }
    stat_list->master_inst_id = master_node_id;

    ret = cms_get_stat_version_ex(version, stat_list);
    if (ret != CT_SUCCESS) {
        CMS_LOG_ERR("get cluster stat version failed, ret %d, res_id %u, version %llu", ret, res_id, version);
        return ret;
    }

    ret = cms_get_cluster_res_list(res_id, stat_list);
    if (ret != CT_SUCCESS) {
        CMS_LOG_ERR("get cluster stat failed, ret %d, res_id %u", ret, res_id);
        return ret;
    }

    CMS_LOG_DEBUG_INF("get cluster stat succ, res id %u, stat version %llu, reformer %u", res_id, stat_list->version,
        stat_list->master_inst_id);
    return CT_SUCCESS;
}

status_t cms_get_cluster_stat_bytype(const char* res_type, uint64 version, cms_res_status_list_t* stat_list)
{
    status_t ret = CT_SUCCESS;
    uint32 res_id = -1;
    CMS_LOG_DEBUG_INF("begin get cluster stat by type, version %llu", version);
    ret = cms_get_res_id_by_type(res_type, &res_id);
    if (ret != CT_SUCCESS) {
        CMS_LOG_ERR("get res id by type failed,not found ret %d.", ret);
        return CT_ERROR;
    }

    ret = cms_get_cluster_stat(res_id, version, stat_list);
    if (ret != CT_SUCCESS) {
        CMS_LOG_ERR("get cluster stat failed, res id %u, version %llu", res_id, version);
        return ret;
    }

    CMS_LOG_DEBUG_INF("get cluster stat by type succ, stat version %llu, reformer %u",
        stat_list->version, stat_list->master_inst_id);
    return CT_SUCCESS;
}

static status_t cms_stat_set_res_data_inner(uint32 res_id, uint32 slot_id, char* data,
    uint32 data_size, uint64 old_version)
{
    if (slot_id >= CMS_MAX_RES_SLOT_COUNT) {
        CMS_LOG_ERR("invalid slot id, slot_id=%u", slot_id);
        return CT_ERROR;
    }

    cms_local_ctx_t* ctx;
    CT_RETURN_IFERR(cms_get_local_ctx(&ctx));

    uint64 offset = CMS_RES_DATA_GCC_OFFSET(res_id, slot_id);
    uint32 write_size = data_size + OFFSET_OF(cms_res_data_t, data);
    uint32 align_size = CM_ALIGN_512(write_size);
    cms_res_data_t *res_data = (cms_res_data_t*)cm_malloc_align(CMS_BLOCK_SIZE, align_size);
    if (res_data == NULL) {
        CMS_LOG_ERR("cm_malloc_align failed, alloc_size=%u", align_size);
        return CT_ERROR;
    }
    errno_t err = memset_s(res_data, align_size, 0, align_size);
    if (err != EOK) {
        CM_FREE_PTR(res_data);
        return CT_ERROR;
    }

    if (res_data_read(ctx, offset, (char *)res_data, CMS_BLOCK_SIZE) != CT_SUCCESS) {
        CM_FREE_PTR(res_data);
        return CT_ERROR;
    }

    if (res_data->magic == CMS_RES_DATA_MAGIC) {
        if (old_version != CT_INVALID_ID64 && res_data->version != old_version) {
            CMS_LOG_ERR("set resource data failed, version mismatch, data version=%lld, expect version=%lld",
                        res_data->version, old_version);
            CM_FREE_PTR(res_data);
            return CT_ERROR;
        }
        res_data->version++;
    } else {
        res_data->magic = CMS_RES_DATA_MAGIC;
        res_data->version = 1;
    }

    res_data->data_size = data_size;
    errno_t ret = memcpy_s(res_data->data, sizeof(res_data->data) - OFFSET_OF(cms_res_data_t, data), data, data_size);
    if (ret != EOK) {
        CM_FREE_PTR(res_data);
        return CT_ERROR;
    }

    if (res_data_write(ctx, offset, (char *)res_data, align_size) != CT_SUCCESS) {
        CM_FREE_PTR(res_data);
        return CT_ERROR;
    }

    CM_FREE_PTR(res_data);

    return CT_SUCCESS;
}

status_t cms_stat_set_res_data(const char* res_type, uint32 slot_id, char* data, uint32 data_size, uint64 old_version)
{
    uint32 res_id;
    if (slot_id >= CMS_MAX_RES_SLOT_COUNT) {
        CMS_LOG_ERR("invalid slot_id:%u", slot_id);
        return CT_ERROR;
    }
    CT_RETURN_IFERR(cms_get_res_id_by_type(res_type, &res_id));

    if (cms_disk_lock(&g_cms_inst->res_data_lock[res_id][slot_id], STAT_LOCK_WAIT_TIMEOUT, DISK_LOCK_WRITE) !=
        CT_SUCCESS) {
        CMS_LOG_ERR("cms_disk_lock timeout");
        return CT_ERROR;
    }

    if (data_size > CMS_MAX_RES_DATA_SIZE) {
        CMS_LOG_ERR("invalid data size, data size = %u", data_size);
        cms_disk_unlock(&g_cms_inst->res_data_lock[res_id][slot_id], DISK_LOCK_WRITE);
        return CT_ERROR;
    }

    if (cms_stat_set_res_data_inner(res_id, slot_id, data, data_size, old_version) != CT_SUCCESS) {
        cms_disk_unlock(&g_cms_inst->res_data_lock[res_id][slot_id], DISK_LOCK_WRITE);
        return CT_ERROR;
    }

    cms_disk_unlock(&g_cms_inst->res_data_lock[res_id][slot_id], DISK_LOCK_WRITE);

    CMS_LOG_DEBUG_INF("resource set data succeed, notify to all instances, slot=%u, old_version=%lld",
        slot_id, old_version);
    cms_stat_chg_notify_to_cms(res_id, 0);

    return CT_SUCCESS;
}

static status_t cms_stat_get_res_data_inner(uint32 res_id, uint32 slot_id, char* data, uint32 max_size,
    uint32* data_size, uint64* data_version)
{
    if (slot_id >= CMS_MAX_RES_SLOT_COUNT) {
        CMS_LOG_ERR("invalid slot_id:%u", slot_id);
        return CT_ERROR;
    }

    uint32 size = CM_ALIGN_512(sizeof(cms_res_data_t));
    cms_res_data_t *res_data = (cms_res_data_t*)cm_malloc_align(CMS_BLOCK_SIZE, size);
    if (res_data == NULL) {
        CMS_LOG_ERR("cm_malloc_align failed, alloc_size=%u", size);
        return CT_ERROR;
    }

    cms_local_ctx_t* ctx;
    if (cms_get_local_ctx(&ctx) != CT_SUCCESS) {
        CM_FREE_PTR(res_data);
        return CT_ERROR;
    }

    uint64 offset = CMS_RES_DATA_GCC_OFFSET(res_id, slot_id);
    if (res_data_read(ctx, offset, (char *)res_data, CMS_BLOCK_SIZE) != CT_SUCCESS) {
        CM_FREE_PTR(res_data);
        return CT_ERROR;
    }

    if (res_data->magic != CMS_RES_DATA_MAGIC) {
        CMS_LOG_ERR("resource data not exists, res_id=%u, slot_id=%u", res_id, slot_id);
        CM_FREE_PTR(res_data);
        return CT_ERROR;
    }

    uint32 total_size = res_data->data_size + OFFSET_OF(cms_res_data_t, data);
    total_size = CM_ALIGN_512(total_size);
    if (total_size > CMS_BLOCK_SIZE) {
        if (res_data_read(ctx, offset + CMS_BLOCK_SIZE, (char *)res_data + CMS_BLOCK_SIZE,
                          total_size - CMS_BLOCK_SIZE) != CT_SUCCESS) {
            CM_FREE_PTR(res_data);
            return CT_ERROR;
        }
    }

    *data_size = res_data->data_size;
    *data_version = res_data->version;
    errno_t ret = memcpy_s(data, max_size, res_data->data, res_data->data_size);
    CM_FREE_PTR(res_data);
    MEMS_RETURN_IFERR(ret);

    return CT_SUCCESS;
}

status_t cms_stat_get_res_data(const char* res_type, uint32 slot_id, char* data, uint32 max_size,
    uint32* data_size, uint64* data_version)
{
    uint32 res_id;
    if (slot_id >= CMS_MAX_RES_SLOT_COUNT) {
        CMS_LOG_ERR("invalid slot_id:%u", slot_id);
        return CT_ERROR;
    }
    CT_RETURN_IFERR(cms_get_res_id_by_type(res_type, &res_id));

    if (cms_disk_lock(&g_cms_inst->res_data_lock[res_id][slot_id], STAT_LOCK_WAIT_TIMEOUT,
        DISK_LOCK_READ) != CT_SUCCESS) {
        CMS_LOG_ERR("cms_disk_lock timeout");

        return CT_ERROR;
    }

    if (cms_stat_get_res_data_inner(res_id, slot_id, data, max_size, data_size, data_version) != CT_SUCCESS) {
        cms_disk_unlock(&g_cms_inst->res_data_lock[res_id][slot_id], DISK_LOCK_READ);
        return CT_ERROR;
    }

    cms_disk_unlock(&g_cms_inst->res_data_lock[res_id][slot_id], DISK_LOCK_READ);

    return CT_SUCCESS;
}

status_t cms_elect_res_reformer(uint32 res_id, uint8 reformer, uint8* new_reformer)
{
    cms_res_stat_t res_stat;
    bool32 do_elect = CT_FALSE;

    if (reformer == CT_INVALID_ID8) {
        do_elect = CT_TRUE;
    } else if (cms_node_is_invalid(reformer)) {
        do_elect = CT_TRUE;
        CMS_LOG_DEBUG_INF("resource's reformer is invalid, do elect, res_id=%u, reformer=%u", res_id, reformer);
    } else {
        if (get_res_stat(reformer, res_id, &res_stat) != CT_SUCCESS) {
            CMS_LOG_ERR("get resource's reformer stat failed, res_id=%u, reformer=%u", res_id, reformer);
            return CT_ERROR;
        }

        if (res_stat.cur_stat != CMS_RES_ONLINE) {
            CMS_LOG_INF("stat of resource's reformer is not online, do elect, res_id=%u, reformer=%u",
                res_id, reformer);
            do_elect = CT_TRUE;
        }
    }

    if (!do_elect) {
        return CT_SUCCESS;
    }

    *new_reformer = CT_INVALID_ID8;
    for (uint32 node_id = 0; node_id < CMS_MAX_NODE_COUNT; node_id++) {
        if (cms_node_is_invalid(node_id)) {
            continue;
        }

        if (get_res_stat(node_id, res_id, &res_stat) != CT_SUCCESS) {
            continue;
        }

        // resource is online and joined
        if (res_stat.cur_stat == CMS_RES_ONLINE && res_stat.work_stat == 1) {
            *new_reformer = node_id;
            CMS_LOG_INF("resource's reformer elect, res_id=%u, new reformer=%u", res_id, (uint32)(*new_reformer));
            return CT_SUCCESS;
        }

        // resource is online and joining
        if (res_stat.cur_stat == CMS_RES_ONLINE && res_stat.work_stat == 0) {
            if (*new_reformer == CT_INVALID_ID8) {
                *new_reformer = node_id;
                CMS_LOG_INF("resource's tmp reformer elect, res_id=%u, new reformer=%u", res_id,
                            (uint32)(*new_reformer));
            };
        }
    }
    if (*new_reformer != CT_INVALID_ID8) {
        CMS_LOG_INF("resource's reformer elect, res_id=%u, new_reformer=%u", res_id, (uint32)(*new_reformer));
    }
    return CT_SUCCESS;
}

status_t cms_try_be_master(void)
{
    cms_res_reformer_t reformers;
    timeval_t tv_begin;
    cantian_record_io_stat_begin(CMS_IO_RECORD_TRY_BE_MASTER, &tv_begin);
    CT_RETURN_IFERR(cms_disk_lock_get_data(&g_cms_inst->master_lock, (char *)&reformers, sizeof(cms_res_reformer_t)));

    for (uint32 res_id = 0; res_id < CMS_MAX_RESOURCE_COUNT; res_id++) {
        if (cms_res_is_invalid(res_id)) {
            continue;
        }

        if (reformers.magic == CMS_REFORMER_MAGIC) {
            (void)cms_elect_res_reformer(res_id, reformers.reformer[res_id], &reformers.reformer[res_id]);
        } else {
            (void)cms_elect_res_reformer(res_id, CT_INVALID_ID8, &reformers.reformer[res_id]);
        }
    }

    reformers.magic = CMS_REFORMER_MAGIC;

    CT_RETURN_IFERR(cms_disk_lock_set_data(&g_cms_inst->master_lock, (char *)&reformers, sizeof(cms_res_reformer_t)));

    uint64 inst_id = CT_INVALID_ID64;
    if (cms_disk_lock_get_inst(&g_cms_inst->master_lock, &inst_id) != CT_SUCCESS) {
        CMS_LOG_WAR("cms get server master failed");
    }
    if (cms_disk_try_lock(&g_cms_inst->master_lock, DISK_LOCK_WRITE) == CT_SUCCESS &&
        (inst_id != g_cms_param->node_id)) {
        CMS_LOG_INF("cms master changed, old master %llu, new master %u", inst_id, g_cms_param->node_id);
    }
    cantian_record_io_stat_end(CMS_IO_RECORD_TRY_BE_MASTER, &tv_begin, IO_STAT_SUCCESS);
    return CT_SUCCESS;
}

status_t cms_get_master_id_with_dbs(cms_disk_lock_t* master_lock)
{
    uint64 inst_id = CT_INVALID_ID64;
    if (cms_uds_cli_get_server_master_id(&inst_id) != CT_SUCCESS) {
        CMS_LOG_INF("check master status: srv not exist.");
        master_lock->inst_id = -1;
    } else {
        master_lock->inst_id = (int64)inst_id;
    }
    master_lock->type = CMS_DEV_TYPE_DBS;
    return  CT_SUCCESS;
}

status_t cms_check_master_lock_status(cms_disk_lock_t* master_lock)
{
    if (g_cms_param->gcc_type == CMS_DEV_TYPE_DBS) {
        return cms_get_master_id_with_dbs(master_lock);
    }
    CT_RETURN_IFERR(cms_disk_lock_init(g_cms_param->gcc_type, g_cms_param->gcc_home, "", CMS_MASTER_LOCK_POS,
        CMS_RLOCK_MASTER_LOCK_START, CMS_RLOCK_MASTER_LOCK_LEN, g_cms_param->node_id, master_lock, NULL, 0, CT_FALSE));
    uint64 inst_id = CT_INVALID_ID64;
    if (cms_disk_lock_get_inst(master_lock, &inst_id) != CT_SUCCESS) {
        CMS_LOG_ERR("cms get server master failed");
        return CT_ERROR;
    }
    if (inst_id == CT_INVALID_ID64) {
        master_lock->inst_id = -1;
    } else {
        master_lock->inst_id = (int64)inst_id;
    }
    return CT_SUCCESS;
}

status_t cms_get_master_node(uint16* node_id)
{
    uint64 inst_id = CT_INVALID_ID64;
    CT_RETURN_IFERR(cms_disk_lock_get_inst(&g_cms_inst->master_lock, &inst_id));
    if (inst_id == CT_INVALID_ID64) {
        *node_id = CT_INVALID_ID16;
    } else {
        *node_id = (uint16)inst_id;
    }
    return CT_SUCCESS;
}

status_t cms_get_res_master(uint32 res_id, uint8* node_id)
{
    cms_res_reformer_t reformers;
    CT_RETURN_IFERR(cms_disk_lock_get_data(&g_cms_inst->master_lock, (char *)&reformers, sizeof(cms_res_reformer_t)));
    if (reformers.magic == CMS_REFORMER_MAGIC) {
        *node_id = reformers.reformer[res_id];
    }

    return CT_SUCCESS;
}

status_t cms_is_master(bool32* is_master)
{
    uint16 node_id;
    if (cms_get_master_node(&node_id) != CT_SUCCESS) {
        CMS_LOG_ERR("cms get master node failed");
        return CT_ERROR;
    }
    if (node_id >= CMS_MAX_NODE_COUNT) {
        CMS_LOG_ERR("cms get master node failed, master node %d", node_id);
        return CT_ERROR;
    }

    *is_master = (node_id == g_cms_param->node_id);

    return CT_SUCCESS;
}

status_t cms_get_res_session(cms_res_session_t* sessions, uint32 size)
{
    errno_t ret = memcpy_s(sessions, size, g_res_session, sizeof(g_res_session));
    MEMS_RETURN_IFERR(ret);
    return CT_SUCCESS;
}

void cms_record_io_aync_hb_gap_end(biqueue_node_t *node_hb_aync, io_record_stat_t stat)
{
    if (node_hb_aync != NULL) {
        cm_atomic_inc(&(g_io_record_event_wait[CMS_IO_RECORD_HB_AYNC_TIME_GAP].detail.start));
        cms_hb_aync_start_t *hb_write_aync = (cms_hb_aync_start_t *)cms_que_node_data(node_hb_aync);
        cantian_record_io_stat_end(CMS_IO_RECORD_HB_AYNC_TIME_GAP, &(hb_write_aync->hb_time_aync_start), stat);
        cms_que_free_node(node_hb_aync);
    }
}

status_t cms_aync_update_res_hb(cms_res_stat_t *res_stat_disk, uint32 res_id)
{
    cms_res_stat_t *res_stat = CMS_CUR_RES_STAT(res_id);
    biqueue_node_t *node_hb_aync = cms_deque(&g_hb_aync_gap_que);
    cm_thread_lock(&g_res_session[res_id].lock);

    if (cms_disk_lock(&g_cms_inst->res_stat_lock[g_cms_param->node_id][res_id], DISK_LOCK_WAIT_TIMEOUT,
        DISK_LOCK_WRITE) != CT_SUCCESS) {
        CMS_LOG_ERR("cms_disk_lock timeout, node_id = %u, res_id = %u.", g_cms_param->node_id, res_id);
        cm_thread_unlock(&g_res_session[res_id].lock);
        return CT_ERROR;
    }
    if (stat_read(CMS_CUR_RES_STAT_POS(res_id), (char *)res_stat_disk, sizeof(cms_res_stat_t)) != CT_SUCCESS) {
        CMS_LOG_ERR("read state fail, node_id=%u, res_id=%u", g_cms_param->node_id, res_id);
        cms_disk_unlock(&g_cms_inst->res_stat_lock[g_cms_param->node_id][res_id], DISK_LOCK_WRITE);
        cm_thread_unlock(&g_res_session[res_id].lock);
        cms_record_io_aync_hb_gap_end(node_hb_aync, IO_STAT_FAILED);
        return CT_ERROR;
    }
    res_stat_disk->hb_time = res_stat->hb_time;
    res_stat_disk->last_check = res_stat->last_check;
    // In this function, we simply update the hb_time and last_check.
    if (stat_write(CMS_CUR_RES_STAT_POS(res_id), (char *)res_stat_disk, sizeof(cms_res_stat_t)) != CT_SUCCESS) {
        CMS_LOG_ERR("aync_write res failed, res_id=%u", res_id);
        cms_disk_unlock(&g_cms_inst->res_stat_lock[g_cms_param->node_id][res_id], DISK_LOCK_WRITE);
        cm_thread_unlock(&g_res_session[res_id].lock);
        cms_record_io_aync_hb_gap_end(node_hb_aync, IO_STAT_FAILED);
        return CT_ERROR;
    }
    cms_disk_unlock(&g_cms_inst->res_stat_lock[g_cms_param->node_id][res_id], DISK_LOCK_WRITE);
    cm_thread_unlock(&g_res_session[res_id].lock);
    cms_record_io_aync_hb_gap_end(node_hb_aync, IO_STAT_SUCCESS);
    return CT_SUCCESS;
}

void cms_stat_aync_write_entry(thread_t * thread)
{
    cms_res_stat_t *res_stat_disk = (cms_res_stat_t *)thread->argument;
    uint64 last_check = cm_now();

    while (!thread->closed) {
        biqueue_node_t *node = cms_deque(&g_cms_inst->aync_write_que);
        if (node == NULL) {
            continue;
        }

        uint64 now_time = cm_now();
        uint64 hb_aync_update_internal = cm_now() - last_check;
        if (hb_aync_update_internal > CMS_HB_AYNC_UPDATE_INTERNAL * MICROSECS_PER_MILLISEC) {
            CMS_LOG_WAR("cms update hb internal elapsed %llu(ms)", (hb_aync_update_internal / MICROSECS_PER_MILLISEC));
        }
        last_check = now_time;

        cms_packet_aync_write_t *aync_wr = (cms_packet_aync_write_t *)cms_que_node_data(node);
        uint32 res_id = aync_wr->res_id;
        if (cms_aync_update_res_hb(res_stat_disk, res_id) != CT_SUCCESS) {
            CMS_LOG_ERR("cms update res hb failed, res_id %u", res_id);
        }
        cms_que_free_node(node);
    }
    CM_FREE_PTR(res_stat_disk);
}

status_t cms_stat_read_from_disk(uint32 node_id, uint32 res_id, cms_res_stat_t **resRef)
{
    cms_res_stat_t *stat = CMS_RES_STAT(node_id, res_id);
    if (stat_read(CMS_RES_STAT_POS(node_id, res_id), (char*)(stat), sizeof(cms_res_stat_t)) != CT_SUCCESS) {
        CMS_LOG_ERR("read state fail, node_id=%u, res_id=%u", node_id, res_id);
        return CT_ERROR;
    }
    CMS_LOG_INF("read res stat succ, node_id %u, res_id %u, target_stat %d, curr_stat %d",
        node_id, res_id, stat->target_stat, stat->cur_stat);
    *resRef = stat;
    return CT_SUCCESS;
}

status_t cms_stat_write_to_disk(uint32 node_id, uint32 res_id, cms_res_stat_t *stat)
{
    if (stat_write(CMS_RES_STAT_POS(node_id, res_id), (char*)(stat), sizeof(cms_res_stat_t)) != CT_SUCCESS) {
        CMS_LOG_ERR("write state fail, node_id=%u, res_id=%u", node_id, res_id);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t cms_update_disk_hb(void)
{
    cms_node_stat_t* node_stat = CMS_CUR_NODE_STAT;
    node_stat->status = ONLINE;
    node_stat->disk_hb = cm_now(); // cluster time

    if (stat_write(CMS_NODE_STAT_POS(g_cms_param->node_id), (char *)node_stat, sizeof(cms_node_stat_t)) != CT_SUCCESS) {
        CMS_LOG_ERR("update cms disk hb failed, node_id=%u", g_cms_param->node_id);
        return CT_ERROR;
    }
    if (node_stat->vote_info_status == CMS_INITING_VOTE_INFO) {
        cms_disk_unlock(&g_cms_inst->vote_info_lock, DISK_LOCK_WRITE);
        node_stat->vote_info_status = CMS_INIT_VOTE_INFO_DONE;
    }
    return CT_SUCCESS;
}

status_t cms_server_stat(uint32 node_id, bool32* cms_online)
{
    cms_node_stat_t *node_stat;
    char disk_hb[32], now_str[32];
    node_stat = CMS_NODE_STAT(node_id);
    CT_RETURN_IFERR(cms_get_node_stat(node_id, (char *)node_stat));

    uint64_t now_time = cm_now();
    cms_date2str(node_stat->disk_hb, disk_hb, sizeof(disk_hb));
    cms_date2str(now_time, now_str, sizeof(now_str));
    if (node_stat->disk_hb + g_cms_param->detect_disk_timeout * CMS_SECOND_TRANS_MICROSECOND > cm_now()) {
        CMS_LOG_INF("node %u cms is online, last disk_hb %s, now time %s", node_id, disk_hb, now_str);
        *cms_online = CT_TRUE;
        return CT_SUCCESS;
    }
    *cms_online = CT_FALSE;
    CMS_LOG_INF("node %u cms is offline, last disk_hb %s, now time %s", node_id, disk_hb, now_str);
    return CT_SUCCESS;
}

status_t cms_get_node_view(uint64* cms_online_bitmap)
{
    uint32 node_count = cms_get_gcc_node_count();
    bool32 cms_online = CT_FALSE;

    for (uint32 node_id = 0; node_id < node_count; node_id++) {
        if (cms_node_is_invalid(node_id)) {
            continue;
        }
        CT_RETURN_IFERR(cms_server_stat(node_id, &cms_online));
        if (cms_online) {
            // update online bitmap
            *cms_online_bitmap |= ((uint64)1 << node_id);
        }
    }
    return CT_SUCCESS;
}

status_t cms_init_mes_channel_version(void)
{
    status_t ret;
    cms_local_ctx_t* ctx;
    g_channel_info = (cms_channel_info_t*)cm_malloc_align(CMS_BLOCK_SIZE, sizeof(cms_channel_info_t));
    if (g_channel_info == NULL) {
        CMS_LOG_ERR("[CMS] cms allocate memory failed.");
        return CT_ERROR;
    }
    CT_RETURN_IFERR(cms_get_local_ctx(&ctx));
    ret = res_data_read(ctx, CMS_MES_CHANNEL_POS, (char*)g_channel_info, sizeof(cms_channel_info_t));
    if (ret != CT_SUCCESS) {
        CMS_LOG_ERR("cms read mes channel info failed, ret %d.", ret);
        return CT_ERROR;
    }
    g_channel_info->channel_version++;
    g_channel_info->magic = CMS_CHANNEL_VERSION_MAGIC;

    ret = res_data_write(ctx, CMS_MES_CHANNEL_POS, (char*)g_channel_info, sizeof(cms_channel_info_t));
    if (ret != CT_SUCCESS) {
        CMS_LOG_ERR("cms write mes channel info failed, ret %d.", ret);
        return CT_ERROR;
    }
    CMS_LOG_INF("cms init mes channel info success, curr version %llu.", g_channel_info->channel_version);
    return ret;
}

status_t cms_get_mes_channel_version(uint64* version)
{
    *version = g_channel_info->channel_version;
    return CT_SUCCESS;
}

status_t cms_get_cluster_res_list_4tool(uint32 res_id, cms_tool_res_stat_list_t *res_stat_list)
{
    status_t ret = CT_SUCCESS;
    CMS_LOG_DEBUG_INF("begin get cluster stat by type");
    uint8 master_node_id;
    ret = cms_get_res_master(res_id, &master_node_id);
    if (ret != CT_SUCCESS) {
        CMS_LOG_ERR("get res master failed, ret %d, res_id %u", ret, res_id);
        return ret;
    }
    res_stat_list->master_inst_id = master_node_id;
    uint32 node_count = cms_get_gcc_node_count();
    res_stat_list->inst_count = node_count;
    for (uint32 node_id = 0; node_id < node_count; node_id++) {
        cms_res_stat_t res_stat;
        if (get_res_stat(node_id, res_id, &res_stat) != CT_SUCCESS) {
            CMS_LOG_ERR("get res stat failed, node_id %d, res_id %u", node_id, res_id);
            return CT_ERROR;
        }

        res_stat_list->stat_list[node_id].session_id = res_stat.session_id;
        res_stat_list->stat_list[node_id].inst_id = res_stat.inst_id;
        res_stat_list->stat_list[node_id].hb_time = res_stat.hb_time;
        res_stat_list->stat_list[node_id].last_check = res_stat.last_check;
        res_stat_list->stat_list[node_id].last_stat_change = res_stat.last_stat_change;
        res_stat_list->stat_list[node_id].pre_stat = res_stat.pre_stat;
        res_stat_list->stat_list[node_id].cur_stat = res_stat.cur_stat;
        res_stat_list->stat_list[node_id].target_stat = res_stat.target_stat;
        res_stat_list->stat_list[node_id].work_stat = res_stat.work_stat;
    }

    CMS_LOG_DEBUG_INF("get cluster stat by type succ, reformer %u", res_stat_list->master_inst_id);
    return CT_SUCCESS;
}

status_t cms_res_list_info_copy(const cms_gcc_t* gcc, cms_tool_msg_res_get_gcc_t* gcc_info)
{
    errno_t err = EOK;
    uint32 res_cnt = 0;
    for (uint32 res_id = 0; res_id < CMS_MAX_RESOURCE_COUNT; res_id++) {
        const cms_res_t* gcc_res = &gcc->res[res_id];
        if (gcc_res->magic != CMS_GCC_RES_MAGIC) {
            continue;
        }
        gcc_info->res_list[res_cnt].magic = gcc_res->magic;
        gcc_info->res_list[res_cnt].hb_timeout = gcc_res->hb_timeout;
        gcc_info->res_list[res_cnt].res_id = res_id;
        err = strncpy_sp(gcc_info->res_list[res_cnt].name, CMS_NAME_BUFFER_SIZE, gcc_res->name, CMS_NAME_BUFFER_SIZE);
        if (err != EOK) {
            CMS_LOG_ERR("cms get gcc info 4tool res strncpy_sp res name failed.");
            return CT_ERROR;
        }
        if ((++res_cnt) >= CMS_RESOURCE_COUNT) {
            CMS_LOG_WAR("cms get gcc info 4tool res number(%u) over max number.", res_cnt);
            break;
        }
    }
    gcc_info->res_count = res_cnt;
    return CT_SUCCESS;
}

status_t cms_get_gcc_info_4tool(cms_tool_msg_res_get_gcc_t* gcc_info)
{
    uint16 master_node_id;
    if (cms_get_master_node(&master_node_id) != CT_SUCCESS) {
        CMS_LOG_ERR("cms get master node failed");
        return CT_ERROR;
    }
    gcc_info->master_node_id = master_node_id;
    
    const cms_gcc_t* gcc = cms_get_read_gcc();
    if (cms_res_list_info_copy(gcc, gcc_info) != CT_SUCCESS) {
        cms_release_gcc(&gcc);
        return CT_ERROR;
    }
    uint32 node_count = 0;
    errno_t err = EOK;
    for (uint32 node_id = 0; node_id < gcc->head.node_count; node_id++) {
        const cms_node_def_t* node_def = &gcc->node_def[node_id];
        if (node_def->magic != CMS_GCC_NODE_MAGIC) {
            continue;
        }
        gcc_info->node_def_list[node_count].magic = CMS_GCC_NODE_MAGIC;
        err = strncpy_sp(gcc_info->node_def_list[node_count].name, CMS_NAME_BUFFER_SIZE,
                         node_def->name, CMS_NAME_BUFFER_SIZE);
        if (err != EOK) {
            CMS_LOG_ERR("cms get gcc info 4tool res strncpy_sp node name failed.");
            cms_release_gcc(&gcc);
            return CT_ERROR;
        }
        if ((++node_count) >= CMS_NODES_COUNT) {
            CMS_LOG_WAR("cms get gcc info 4tool node number(%u) over max number.", node_count);
            break;
        }
    }
    gcc_info->node_count = node_count;
    cms_release_gcc(&gcc);
    return CT_SUCCESS;
}