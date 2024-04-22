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
 * cms_vote.c
 *
 *
 * IDENTIFICATION
 * src/cms/cms/cms_vote.c
 *
 * -------------------------------------------------------------------------
 */
#include "cms_log_module.h"
#include "cms_vote.h"
#include "cms_instance.h"
#include "cms_param.h"
#include "cms_node_fault.h"
#include "cm_malloc.h"
#include "cms_stat.h"
#include "cms_mes.h"
#include "cms_cmd_imp.h"
#include "cms_log.h"

static vote_ctx_t g_vote_context;
static vote_ctx_t *g_vote_ctx = &g_vote_context;

vote_result_ctx_t *get_current_vote_result(void)
{
    return &g_vote_context.vote_result;
}

static uint64 cms_get_vote_data_offset(uint16 node_id, uint32 slot_id)
{
    return (uint64)(&(((cms_cluster_vote_data_t *)NULL)->vote_data[node_id][slot_id]));
}

static status_t vote_data_read(uint64 offset, char* data, uint32 size)
{
    if (g_cms_param->gcc_type != CMS_DEV_TYPE_DBS) {
        return cm_read_disk(g_cms_inst->vote_file_fd, offset, data, size);
    }
    if (cm_read_dbs_file(&g_cms_inst->vote_file_handle, offset, data, size) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return CT_SUCCESS;
}
 
static status_t vote_data_write(uint64 offset, char* data, uint32 size)
{
    if (g_cms_param->gcc_type != CMS_DEV_TYPE_DBS) {
        return cm_write_disk(g_cms_inst->vote_file_fd, offset, data, size);
    }
    return cm_write_dbs_file(&g_cms_inst->vote_file_handle, offset, data, size);
}

static status_t cms_set_vote_data_inner(uint16 node_id, uint32 slot_id, char *data, uint32 data_size,
    uint64 old_version)
{
    if (slot_id >= CMS_MAX_VOTE_SLOT_COUNT) {
        CMS_LOG_ERR("invalid slot_id:%u", slot_id);
        return CT_ERROR;
    }

    uint64 offset = cms_get_vote_data_offset(node_id, slot_id);
    if (g_cms_param->gcc_type == CMS_DEV_TYPE_SD) {
        offset += CMS_VOTE_DATA_GCC_OFFSET;
    }
    uint32 write_size = data_size + OFFSET_OF(cms_vote_data_t, data);
    uint32 align_size = CM_ALIGN_512(write_size);
    cms_vote_data_t *vote_data = (cms_vote_data_t *)cm_malloc_align(CMS_BLOCK_SIZE, align_size);
    if (vote_data == NULL) {
        CMS_LOG_ERR("cm_malloc_align failed:alloc size=%u", align_size);
        return CT_ERROR;
    }
    CMS_LOG_DEBUG_INF("begin to read disk, offset = %llu, write_size = %u", offset, write_size);

    if (vote_data_read(offset, (char *)vote_data, CMS_BLOCK_SIZE) != CT_SUCCESS) {
        CMS_LOG_ERR("failed to read disk, offset = %llu, write_size = %u", offset, write_size);
        CM_FREE_PTR(vote_data);
        return CT_ERROR;
    }

    if (vote_data->magic == CMS_VOTE_DATA_MAGIC) {
        if (old_version != CT_INVALID_ID64 && (vote_data->version != old_version)) {
            CMS_LOG_ERR("set voting data failed:version mismatch:data version=%lld,expect version=%lld",
                vote_data->version, old_version);
            CM_FREE_PTR(vote_data);
            return CT_ERROR;
        }
        vote_data->version++;
    } else {
        vote_data->magic = CMS_VOTE_DATA_MAGIC;
        vote_data->version = 1;
    }

    vote_data->data_size = data_size;

    if (memcpy_s(vote_data->data, sizeof(vote_data->data) - OFFSET_OF(cms_vote_data_t, data), data, data_size) != EOK) {
        CM_FREE_PTR(vote_data);
        CMS_LOG_ERR("vote_data memcpy failed, error code:%d,%s", errno, strerror(errno));
        return CT_ERROR;
    }

    if (vote_data_write(offset, (char *)vote_data, align_size) != CT_SUCCESS) {
        CMS_LOG_ERR("set voting data cm_write_disk failed: offset = %llu, align_size = %u.", offset, align_size);
        CM_FREE_PTR(vote_data);
        return CT_ERROR;
    }

    CM_FREE_PTR(vote_data);
    return CT_SUCCESS;
}

status_t cms_read_vote_data(cms_vote_data_t *vote_data, uint16 node_id, uint64 offset)
{
    if (vote_data_read(offset, (char *)vote_data, sizeof(cms_vote_data_t)) != CT_SUCCESS) {
        CMS_LOG_ERR("cm_read_disk failed: offset = %llu", offset);
        return CT_ERROR;
    }

    if (vote_data->magic != CMS_VOTE_DATA_MAGIC) {
        CMS_LOG_ERR("vote data not exists:node_id=%u, offset = %llu, magic = %llu", node_id, offset, vote_data->magic);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t cms_get_vote_data_inner(uint16 node_id, uint32 slot_id, char *data, uint32 max_size, uint32 *data_size)
{
    if (slot_id >= CMS_MAX_VOTE_SLOT_COUNT) {
        CMS_LOG_ERR("invalid slot_id:%u", slot_id);
        return CT_ERROR;
    }
    CT_RETURN_IFERR(cms_node_is_invalid(node_id));

    uint32 size = CM_ALIGN_512(sizeof(cms_vote_data_t));
    cms_vote_data_t *vote_data = (cms_vote_data_t *)cm_malloc_align(CMS_BLOCK_SIZE, size);
    if (vote_data == NULL) {
        CMS_LOG_ERR("cm_malloc_align failed:alloc size=%u", size);
        return CT_ERROR;
    }

    uint64 offset = cms_get_vote_data_offset(node_id, slot_id);
    if (g_cms_param->gcc_type == CMS_DEV_TYPE_SD) {
        offset += CMS_VOTE_DATA_GCC_OFFSET;
    }

    if (cms_read_vote_data(vote_data, node_id, offset) != CT_SUCCESS) {
        CMS_LOG_ERR("cms read vote data failed: offset = %llu", offset);
        CM_FREE_PTR(vote_data);
        return CT_ERROR;
    }

    if (data_size != NULL) {
        *data_size = vote_data->data_size;
    }
    errno_t ret;
    if (vote_data->data_size == 0) {
        ret = memset_s(data, max_size, 0, max_size);
    } else {
        ret = memcpy_s(data, max_size, vote_data->data, vote_data->data_size);
    }
    CM_FREE_PTR(vote_data);
    MEMS_RETURN_IFERR(ret);

    return CT_SUCCESS;
}

status_t cms_set_vote_data(uint16 node_id, uint32 slot_id, char *data, uint32 data_size, uint64 old_version)
{
    if (cms_disk_lock(&g_cms_inst->vote_data_lock[node_id][slot_id], DISK_LOCK_WAIT_TIMEOUT, DISK_LOCK_WRITE) !=
        CT_SUCCESS) {
        CMS_LOG_ERR("cms_disk_lock timeout.");
        return CT_ERROR;
    }

    if (cms_set_vote_data_inner(node_id, slot_id, data, data_size, old_version) != CT_SUCCESS) {
        cms_disk_unlock(&g_cms_inst->vote_data_lock[node_id][slot_id], DISK_LOCK_WRITE);
        return CT_ERROR;
    }

    cms_disk_unlock(&g_cms_inst->vote_data_lock[node_id][slot_id], DISK_LOCK_WRITE);

    return CT_SUCCESS;
}

status_t cms_get_vote_data(uint16 node_id, uint32 slot_id, char *data, uint32 max_size, uint32 *data_size)
{
    if (cms_disk_lock(&g_cms_inst->vote_data_lock[node_id][slot_id], DISK_LOCK_WAIT_TIMEOUT, DISK_LOCK_READ) !=
        CT_SUCCESS) {
        CMS_LOG_ERR("cms_disk_lock timeout.");
        return CT_ERROR;
    }

    if (cms_get_vote_data_inner(node_id, slot_id, data, max_size, data_size) != CT_SUCCESS) {
        cms_disk_unlock(&g_cms_inst->vote_data_lock[node_id][slot_id], DISK_LOCK_READ);
        return CT_ERROR;
    }

    cms_disk_unlock(&g_cms_inst->vote_data_lock[node_id][slot_id], DISK_LOCK_READ);

    return CT_SUCCESS;
}

status_t cms_set_vote_result(vote_result_ctx_t *vote_result)
{
    if (cms_disk_lock(&g_cms_inst->vote_result_lock, DISK_LOCK_WAIT_TIMEOUT, DISK_LOCK_WRITE) != CT_SUCCESS) {
        CMS_LOG_ERR("cms_disk_lock timeout.");
        return CT_ERROR;
    }
    uint64 offset = 0;
    if (g_cms_param->gcc_type == CMS_DEV_TYPE_SD) {
        offset += CMS_VOTE_DATA_GCC_OFFSET;
    }

    vote_result_ctx_t *new_vote_result =
        (vote_result_ctx_t *)cm_malloc_align(CMS_BLOCK_SIZE, sizeof(vote_result_ctx_t));
    if (new_vote_result == NULL) {
        cms_disk_unlock(&g_cms_inst->vote_result_lock, DISK_LOCK_WRITE);
        CMS_LOG_ERR("cms set vote result malloc err, size %lu, error code:%d,%s", sizeof(vote_result_ctx_t), errno,
            strerror(errno));
        return CT_ERROR;
    }

    if (vote_result->magic != CMS_VOTE_RES_MAGIC) {
        cms_disk_unlock(&g_cms_inst->vote_result_lock, DISK_LOCK_WRITE);
        CM_FREE_PTR(new_vote_result);
        CMS_LOG_ERR("vote_result magic err");
        return CT_ERROR;
    }
    status_t ret = memcpy_sp(new_vote_result, sizeof(vote_result_ctx_t), vote_result, sizeof(vote_result_ctx_t));
    if (ret != CT_SUCCESS) {
        cms_disk_unlock(&g_cms_inst->vote_result_lock, DISK_LOCK_WRITE);
        CM_FREE_PTR(new_vote_result);
        CMS_LOG_ERR("memset vote result err, error code:%d,%s", errno, strerror(errno));
        return ret;
    }

    if (vote_data_write(offset, (char *)new_vote_result, CMS_BLOCK_SIZE) != CT_SUCCESS) {
        cms_disk_unlock(&g_cms_inst->vote_result_lock, DISK_LOCK_WRITE);
        CM_FREE_PTR(new_vote_result);
        CMS_LOG_ERR("write vote result failed");
        return CT_ERROR;
    }

    CM_FREE_PTR(new_vote_result);
    cms_disk_unlock(&g_cms_inst->vote_result_lock, DISK_LOCK_WRITE);
    return CT_SUCCESS;
}

status_t cms_get_vote_result(vote_result_ctx_t *vote_result)
{
    if (cms_disk_lock(&g_cms_inst->vote_result_lock, DISK_LOCK_WAIT_TIMEOUT, DISK_LOCK_READ) != CT_SUCCESS) {
        CMS_LOG_ERR("cms_disk_lock timeout.");
        return CT_ERROR;
    }

    vote_result_ctx_t *new_vote_result =
        (vote_result_ctx_t *)cm_malloc_align(CMS_BLOCK_SIZE, sizeof(vote_result_ctx_t));
    if (new_vote_result == NULL) {
        cms_disk_unlock(&g_cms_inst->vote_result_lock, DISK_LOCK_READ);
        CMS_LOG_ERR("cms get vote result malloc err, size %lu", sizeof(vote_result_ctx_t));
        return CT_ERROR;
    }
    
    uint64 offset = 0;
    if (g_cms_param->gcc_type == CMS_DEV_TYPE_SD) {
        offset += CMS_VOTE_DATA_GCC_OFFSET;
    }
    CMS_LOG_DEBUG_INF("cms result offset = %llu, sizeof(result) = %lu", offset, sizeof(vote_result_ctx_t));

    if (vote_data_read(offset, (char *)new_vote_result, sizeof(vote_result_ctx_t)) != CT_SUCCESS) {
        cms_disk_unlock(&g_cms_inst->vote_result_lock, DISK_LOCK_READ);
        CM_FREE_PTR(new_vote_result);
        CMS_LOG_ERR("read vote result failed");
        return CT_ERROR;
    }

    cms_disk_unlock(&g_cms_inst->vote_result_lock, DISK_LOCK_READ);
    if (new_vote_result->magic != CMS_VOTE_RES_MAGIC) {
        CMS_LOG_ERR("vote result not exists: magic(%llu) err", new_vote_result->magic);
        CM_FREE_PTR(new_vote_result);
        return CMS_RES_MAGIC_ERR;
    }

    status_t ret = memcpy_sp(vote_result, sizeof(vote_result_ctx_t), new_vote_result, sizeof(vote_result_ctx_t));
    if (ret != CT_SUCCESS) {
        CM_FREE_PTR(new_vote_result);
        CMS_LOG_ERR("memset vote result err, error code:%d,%s", errno, strerror(errno));
        return ret;
    }
    CM_FREE_PTR(new_vote_result);
    return CT_SUCCESS;
}

static void cms_update_vote_info(void)
{
    for (uint16 i = 0; i < CMS_MAX_NODE_COUNT; i++) {
        if (i == g_cms_param->node_id) {
            g_vote_ctx->vote_data.vote_info[i] = NODE_CONNECT_GOOD;
            continue;
        }
        if (cms_node_is_invalid(i)) {
            g_vote_ctx->vote_data.vote_info[i] = NODE_CONNECT_BAD;
            continue;
        }
        cms_hb_stat_t *stat = &g_cms_hb_manager->stat[i];

        if (stat->lost_cnt <= g_cms_param->cms_node_fault_thr) {
            g_vote_ctx->vote_data.vote_info[i] = NODE_CONNECT_GOOD;
            continue;
        } else {
            g_vote_ctx->vote_data.vote_info[i] = NODE_CONNECT_BAD;
            CMS_LOG_ERR("Detected node:%d lost heartbeat %lld times, send:%lld, recv:%lld, last_recv:%lld", i,
                stat->lost_cnt, stat->send_cnt, stat->recv_cnt, stat->last_recv);
        }
    }
}

status_t cms_start_new_voting(void)
{
    vote_result_ctx_t *vote_result = &g_vote_ctx->vote_result;
    if (vote_result->vote_stat == VOTE_FROZEN) {
        CMS_LOG_INF("Split-brain arbitration is being performed in the cluster, vote_round(%llu).",
            g_vote_ctx->vote_data.vote_round);
        return CT_SUCCESS;
    }

    g_vote_ctx->vote_data.vote_round += 1;
    CMS_LOG_INF("cms trigger new voting, vote_round(%llu)", g_vote_ctx->vote_data.vote_round);
    // update vote_round and vote_stat in vote_result
    vote_result->vote_stat = VOTE_FROZEN;
    vote_result->vote_round = g_vote_ctx->vote_data.vote_round;
    vote_result->vote_count_done = CT_FALSE;
    bool32 is_master = CT_FALSE;
    CMS_RETRY_IF_ERR(cms_is_master(&is_master));

    if (is_master) {
        CT_RETURN_IFERR(cms_set_vote_result(vote_result));
        CMS_LOG_INF("cms master set vote_stat = VOTE_FROZEN");
    }

    CMS_RETRY_IF_ERR(cms_set_vote_data(g_cms_param->node_id, CMS_VOTE_TRIGGER_ROUND,
        (char *)&g_vote_ctx->vote_data.vote_round, sizeof(uint64_t), CT_INVALID_ID64));
    CMS_LOG_INF("cms set new trigger round succeed");
    g_vote_ctx->vote_data.vote_time = cm_now();
    char vote_time[32];
    cms_date2str(g_vote_ctx->vote_data.vote_time, vote_time, sizeof(vote_time));
    status_t s = CT_ERROR;
    status_t ret;
    // The voting lasts for 5s.
    while ((s != CT_SUCCESS) ||
        (cm_now() - g_vote_ctx->vote_data.vote_time < (CMS_VOTE_VALID_PERIOD * MICROSECS_PER_MILLISEC))) {
        CMS_SYNC_POINT_GLOBAL_START(CMS_SPLIT_BRAIN_BEBFORE_VOTING_ABORT, NULL, 0);
        CMS_SYNC_POINT_GLOBAL_END;
        // cms updates node connectivity information in a cluster
        cms_update_vote_info();
        CMS_SYNC_POINT_GLOBAL_START(CMS_SET_VOTE_DATA_FAIL, &ret, CT_ERROR);
        ret = cms_set_vote_data(g_cms_param->node_id, CMS_VOTE_INFO, (char *)(&g_vote_ctx->vote_data),
            sizeof(one_vote_data_t), CT_INVALID_ID64);
        CMS_SYNC_POINT_GLOBAL_END;
        if (ret == CT_SUCCESS) {
            s = CT_SUCCESS;
        }

        cm_sleep(CMS_REVOTE_INTERNAL);
        CMS_SYNC_POINT_GLOBAL_START(CMS_SPLIT_BRAIN_VOTING_ABORT, NULL, 0);
        CMS_SYNC_POINT_GLOBAL_END;
    }
    CMS_SYNC_POINT_GLOBAL_START(CMS_SPLIT_BRAIN_AFTER_VOTING_ABORT, NULL, 0);
    CMS_SYNC_POINT_GLOBAL_END;

    CMS_LOG_INF("cms set vote data successed:vote_time(%s), vote_round(%llu).", vote_time,
        g_vote_ctx->vote_data.vote_round);
    return CT_SUCCESS;
}

static status_t detect_new_vote_round(void)
{
    for (uint16 i = 0; i < CMS_MAX_NODE_COUNT; i++) {
        if (i == g_cms_param->node_id || cms_node_is_invalid(i)) {
            continue;
        }
        uint64 detect_vote_round = 0;
        status_t ret;

        CMS_SYNC_POINT_GLOBAL_START(CMS_DETECT_NEW_VOTE_ROUND_FAIL, &ret, CT_ERROR);
        ret = cms_get_vote_data(i, CMS_VOTE_TRIGGER_ROUND, (char *)(&detect_vote_round), sizeof(uint64), NULL);
        CMS_SYNC_POINT_GLOBAL_END;
        if (ret != CT_SUCCESS) {
            CMS_LOG_ERR("cms read node(%u) vote data failed.", i);
            continue;
        }

        if (detect_vote_round > g_vote_ctx->vote_data.vote_round) {
            if (detect_vote_round == (g_vote_ctx->vote_data.vote_round + 1)) {
                g_vote_ctx->detect_vote_round = detect_vote_round;
                CMS_LOG_INF("cms detect new vote_round(%llu) in node(%u)", detect_vote_round, i);
                return CT_SUCCESS;
            }
            CMS_LOG_ERR("cms missed vote, detect node %u vote round %llu, local node vote round %llu", i,
                detect_vote_round, g_vote_ctx->vote_data.vote_round);
            if (cms_daemon_stop_pull() != CT_SUCCESS) {
                CMS_LOG_ERR("stop cms daemon process failed.");
            }
            CM_ABORT_REASONABLE(0, "[CMS] ABORT INFO: Based on the detect_vote_round, the node is removed from the cluster.");
        }
    }
    return CT_ERROR;
}

int64 cms_get_round_start_time(uint64 new_round)
{
    int64 tmp_start_time = 0;
    for (uint32 i = 0; i < CMS_MAX_NODE_COUNT; i++) {
        if (cms_node_is_invalid(i)) {
            continue;
        }
        one_vote_data_t vote_ctx;
        vote_ctx.vote_round = 0;
        vote_ctx.vote_time = 0;
        while (cms_get_vote_data(i, CMS_VOTE_INFO, (char *)(&vote_ctx), sizeof(one_vote_data_t), NULL) != CT_SUCCESS) {
            CMS_LOG_ERR("cms read node(%u) vote data failed.", i);
            cm_sleep(CMS_RETRY_SLEEP_TIME);
        }

        if (vote_ctx.vote_round == new_round) {
            if (tmp_start_time == 0) {
                tmp_start_time = vote_ctx.vote_time;
                continue;
            }
            if (vote_ctx.vote_time < tmp_start_time) {
                tmp_start_time = vote_ctx.vote_time;
            }
        }
    }
    return tmp_start_time;
}

static void cms_join_node_set_inner(max_clique_t *clique_struct, uint32 *adjacency_matrix,
    uint32 *tmp_conclude_edge_ij_res, bool32 *add_new_node, uint32 m)
{
    for (uint32 tmp_detect_index = 0; tmp_detect_index < clique_struct->node_count; tmp_detect_index++) {
        if (tmp_conclude_edge_ij_res[tmp_detect_index] == 1) {
            if ((*(uint32 *)(adjacency_matrix + tmp_detect_index * clique_struct->node_count + m)) == 0) {
                *add_new_node = CT_FALSE;
            }
        }
    }
}

static void cms_join_node_set(max_clique_t *clique_struct, uint32 *adjacency_matrix, uint32 *tmp_conclude_edge_ij_res,
    uint32 j)
{
    bool32 add_new_node = CT_TRUE;
    for (uint32 m = j + 1; m < clique_struct->node_count; m++) {
        add_new_node = 1;
        cms_join_node_set_inner(clique_struct, adjacency_matrix, tmp_conclude_edge_ij_res, &add_new_node, m);
        if (add_new_node) {
            tmp_conclude_edge_ij_res[m] = 1;
        }
    }
}

static void cms_bitmap64_set(vote_result_ctx_t *vote_result, uint8 num)
{
    uint64 position;
    CM_ASSERT(num < CT_MAX_INSTANCES);
    position = (uint64)1 << num;
    vote_result->new_cluster_bitmap |= position;
}

status_t cms_get_online_joined_node_set(uint8 *online_node_arr, uint8 *online_joined_node_arr, uint8 max_node_count)
{
    cms_res_status_list_t stat_list = { 0 };
    status_t ret = CT_SUCCESS;
    ret = cms_get_cluster_stat_bytype("db", 0, &stat_list);
    if (ret != CT_SUCCESS) {
        CMS_LOG_ERR("get all res stat failed, ret %d", ret);
        return CT_ERROR;
    }
    for (uint32 i = 0; i < stat_list.inst_count; i++) {
        if (stat_list.inst_list[i].stat == CMS_RES_ONLINE && i < max_node_count) {
            online_node_arr[i] = CT_TRUE;
            CMS_LOG_INF("get all res stat, node %d stat is online", i);
        }
        if (stat_list.inst_list[i].stat == CMS_RES_ONLINE && stat_list.inst_list[i].work_stat == RC_JOINED &&
            i < max_node_count) {
            online_joined_node_arr[i] = CT_TRUE;
            CMS_LOG_INF("get all res stat, node %d stat is online joined", i);
        }
    }
    return CT_SUCCESS;
}

bool8 cms_have_multiple_max_group(max_clique_t *clique, int32 *node_num_array, uint32 *node_index)
{
    uint32 i;
    uint32 max_group_node_num = 0;
    uint32 max_group_index = 0;
    uint32 max_group_count = 0;
    // 统计最大团数量
    for (i = 0; i < clique->node_count; i++) {
        if (i == 0) {
            max_group_index = 0;
            max_group_node_num = node_num_array[0];
            max_group_count = 1;
        } else if (node_num_array[i] == max_group_node_num) {
            max_group_count++;
        } else {
            if (node_num_array[i] > max_group_node_num) {
                // 更新为最大团
                max_group_index = i;
                max_group_node_num = node_num_array[i];
                max_group_count = 1;
            }
        }
    }
    *node_index = max_group_index;
    CMS_LOG_INF("cms vote max group index = %d, max group count = %u, max group node num = %u", *node_index,
        max_group_count, max_group_node_num);
    // 有唯一最大团
    if (max_group_count == 1) {
        return CT_FALSE;
    }
    // 没有唯一最大团，只保留最大团
    for (i = 0; i < clique->node_count; i++) {
        if (node_num_array[i] != max_group_node_num) {
            node_num_array[i] = 0;
        }
    }
    return CT_TRUE;
}

bool8 cms_get_max_node_group_index(max_clique_t *clique, int32 *max_clique_num_arr, uint32 *max_node_index)
{
    uint32 i;
    // 获取联通array
    for (i = 0; i < clique->node_count; i++) {
        max_clique_num_arr[i] = clique->specify_node_clique_num[i];
    }
    // 选取最大团
    if (cms_have_multiple_max_group(clique, max_clique_num_arr, max_node_index) != CT_TRUE) {
        clique->max_clique_num_index = *max_node_index;
        CMS_LOG_INF("cms vote get max node group index = %u", *max_node_index);
        return CT_TRUE;
    }
    return CT_FALSE;
}

bool8 cms_get_max_online_node_group_index(max_clique_t *clique, int32 *max_clique_num_arr,
    uint32 *max_node_index, uint8 *online_node_set)
{
    uint32 i;
    uint32 j;
    // 去除非online的节点
    for (i = 0; i < clique->node_count; i++) {
        for (j = 0; j < clique->node_count; j++) {
            if (max_clique_num_arr[i] > 0 && clique->contain_specify_node_clique[i][j] == 1 &&
                online_node_set[j] == 0) {
                max_clique_num_arr[i]--;
            }
        }
    }
    // 选取最大团
    if (cms_have_multiple_max_group(clique, max_clique_num_arr, max_node_index) != CT_TRUE) {
        clique->max_clique_num_index = *max_node_index;
        CMS_LOG_INF("cms vote get max online node group index = %u", *max_node_index);
        return CT_TRUE;
    }
    return CT_FALSE;
}

bool8 cms_get_max_online_joined_node_group_index(max_clique_t *clique, int32 *max_clique_num_arr,
    uint32 *max_node_index, uint8 *online_node_set, uint8 *online_joined_node_set)
{
    uint32 i;
    uint32 j;
    // 去除online非joined的节点
    for (i = 0; i < clique->node_count; i++) {
        for (j = 0; j < clique->node_count; j++) {
            if (max_clique_num_arr[i] > 0 && clique->contain_specify_node_clique[i][j] == 1 &&
                online_node_set[j] == 1 && online_joined_node_set[j] == 0) {
                max_clique_num_arr[i]--;
            }
        }
    }
    // 选取最大团
    if (cms_have_multiple_max_group(clique, max_clique_num_arr, max_node_index) != CT_TRUE) {
        clique->max_clique_num_index = *max_node_index;
        CMS_LOG_INF("cms vote get max online joined node group index = %u", *max_node_index);
        return CT_TRUE;
    }
    return CT_FALSE;
}

void cms_get_max_num_index(max_clique_t *clique, uint8 *online_node_set, uint8 *online_joined_node_set)
{
    uint32 i;
    uint32 max_node_index = 0;
    int32 max_clique_num_arr[CMS_MAX_NODE_COUNT] = {0};

    // 1、先选取node最多的团
    if (cms_get_max_node_group_index(clique, max_clique_num_arr, &max_node_index)) {
        CMS_LOG_INF("cms vote max node group index success.");
        return;
    }
    // 2、node最多的团相等，选取online最多的团
    max_node_index = 0;
    if (cms_get_max_online_node_group_index(clique, max_clique_num_arr, &max_node_index, online_node_set)) {
        CMS_LOG_INF("cms vote max node group index success.");
        return;
    }
    // 3、online最多的团相等，选取online joined最多的团
    max_node_index = 0;
    if (cms_get_max_online_joined_node_group_index(clique, max_clique_num_arr, &max_node_index,
        online_node_set, online_joined_node_set)) {
        CMS_LOG_INF("cms vote max node group index success.");
        return;
    }
    // 4、都相同的话,选择序列号最小的最大团
    for (i = 0; i < clique->node_count; i++) {
        if (i == 0) {
            clique->max_clique_num_index = 0;
        } else {
            if (clique->specify_node_clique_num[i] > clique->specify_node_clique_num[clique->max_clique_num_index]) {
                clique->max_clique_num_index = i;
            }
        }
    }
    CMS_LOG_INF("cms vote get min node id group index = %d", clique->max_clique_num_index);
    return;
}

static void cms_get_final_vote_res(vote_result_ctx_t *vote_result, uint32 *adjacency_matrix,
    max_clique_t *clique_struct)
{
    status_t ret = CT_ERROR;
    uint8 retry_num = 0;
    uint8 online_node_arr[CMS_MAX_NODE_COUNT] = {CT_FALSE};
    uint8 online_joined_node_arr[CMS_MAX_NODE_COUNT] = {CT_FALSE};
    do {
        ret = cms_get_online_joined_node_set(online_node_arr, online_joined_node_arr, CMS_MAX_NODE_COUNT);
        if (ret != CT_SUCCESS) {
            CMS_LOG_ERR("cms get online node set failed, ret = %d, retry_num = %d", ret, retry_num);
        }
        retry_num++;
    } while (ret != CT_SUCCESS && retry_num <= CMS_RETRY_GET_STAT_NUM);
    if (retry_num > CMS_RETRY_GET_STAT_NUM) {
        for (uint8 i = 0; i < CMS_MAX_NODE_COUNT; i++) {
            online_node_arr[i] = CT_TRUE;
        }
    }
    cms_get_max_num_index(clique_struct, online_node_arr, online_joined_node_arr);

    vote_result->new_cluster_bitmap = 0;
    for (uint32 i = 0; i < clique_struct->node_count; i++) {
        if (clique_struct->contain_specify_node_clique[clique_struct->max_clique_num_index][i] == 1) {
            cms_bitmap64_set(vote_result, i);
        }
    }
    CMS_LOG_INF("the final res of vote_result is %llu, vote round is %llu", vote_result->new_cluster_bitmap,
        g_vote_ctx->vote_data.vote_round);
}

static void cms_solve_max_clique_inner(max_clique_t *clique_struct, uint32 *adjacency_matrix,
    uint32 *tmp_conclude_edge_ij_res, uint32 i, uint32 j)
{
    for (uint32 p = 0; p < clique_struct->node_count; p++) {
        tmp_conclude_edge_ij_res[p] = 0;
    }
    tmp_conclude_edge_ij_res[i] = 1;
    tmp_conclude_edge_ij_res[j] = 1;
    cms_join_node_set(clique_struct, adjacency_matrix, tmp_conclude_edge_ij_res, j);
    uint32 tmp_clique_num = 0;
    for (uint32 k = 0; k < clique_struct->node_count; k++) {
        if (tmp_conclude_edge_ij_res[k] == 1) {
            tmp_clique_num++;
        }
    }
    if (tmp_clique_num > clique_struct->specify_node_clique_num[i]) {
        for (uint32 k = 0; k < clique_struct->node_count; k++) {
            clique_struct->contain_specify_node_clique[i][k] = tmp_conclude_edge_ij_res[k];
        }
        clique_struct->specify_node_clique_num[i] = tmp_clique_num;
    }
}

static void cms_solve_max_clique(vote_result_ctx_t *vote_result, uint32 *adjacency_matrix, max_clique_t *clique_struct)
{
    uint32 tmp_conclude_edge_ij_res[CMS_MAX_NODE_COUNT] = {0};
    for (uint32 i = 0; i < clique_struct->node_count; i++) {
        uint32 all_node_isolate = 1;
        for (uint32 j = 0; j < clique_struct->node_count; j++) {
            if ((*(uint32 *)(adjacency_matrix + i * clique_struct->node_count + j)) == 1) {
                all_node_isolate = 0;
                cms_solve_max_clique_inner(clique_struct, adjacency_matrix, tmp_conclude_edge_ij_res, i, j);
            }
        }
        if (all_node_isolate) {
            if ((*(uint32 *)(adjacency_matrix + i * clique_struct->node_count + i)) == 1) {
                clique_struct->specify_node_clique_num[i] = 1;
            } else {
                clique_struct->specify_node_clique_num[i] = 0;
            }
        }
    }
    cms_get_final_vote_res(vote_result, adjacency_matrix, clique_struct);
}

status_t cms_get_max_full_connect(vote_result_ctx_t *vote_result, uint32 *all_nodes_vote_msg, const uint32 node_count)
{
    uint32 save_tmp_res_arr[node_count][node_count];
    for (uint32 i = 0; i < node_count; i++) {
        for (uint32 j = 0; j < node_count; j++) {
            if ((*(uint32 *)(all_nodes_vote_msg + i * node_count + j)) == 1 &&
                (*(uint32 *)(all_nodes_vote_msg + j * node_count + i)) == 1) {
                save_tmp_res_arr[i][j] = 1;
                save_tmp_res_arr[j][i] = 1;
            } else {
                save_tmp_res_arr[i][j] = 0;
                save_tmp_res_arr[j][i] = 0;
            }
        }
    }
    max_clique_t clique_back_track = { node_count, 0, { { 0 } }, { 0 } };
    cms_solve_max_clique(vote_result, &save_tmp_res_arr[0][0], &clique_back_track);
    return CT_SUCCESS;
}

status_t cms_get_votes_count_res(vote_result_ctx_t *vote_result, uint64 new_round, int64 new_round_start_time)
{
    const uint32 node_count = cms_get_gcc_node_count();
    uint32 all_nodes_vote_msg[node_count][node_count];
    char start_time[32];
    char end_time[32];
    char node_vote_time[32];
    for (uint32 i = 0; i < node_count; i++) {
        if (cms_node_is_invalid(i)) {
            continue;
        }
        one_vote_data_t vote_ctx;
        errno_t err = memset_s(&vote_ctx, sizeof(one_vote_data_t), 0, sizeof(one_vote_data_t));
        MEMS_RETURN_IFERR(err);
        while (cms_get_vote_data(i, CMS_VOTE_INFO, (char *)(&vote_ctx), sizeof(one_vote_data_t), NULL) != CT_SUCCESS) {
            CMS_LOG_ERR("cms read node(%u) vote data failed.", i);
            cm_sleep(CMS_RETRY_SLEEP_TIME);
        }

        int64 new_round_end_time = new_round_start_time + (CMS_VOTE_VALID_PERIOD * MICROSECS_PER_MILLISEC);
        cms_date2str(new_round_start_time, start_time, sizeof(start_time));
        cms_date2str(new_round_end_time, end_time, sizeof(end_time));
        cms_date2str(vote_ctx.vote_time, node_vote_time, sizeof(node_vote_time));
        CMS_LOG_INF("cms node[%u] vote time is %s, curr round start time is = %s, end time is = %s", i,
            node_vote_time, start_time, end_time);
        if (vote_ctx.vote_round != new_round || vote_ctx.vote_time < new_round_start_time ||
            vote_ctx.vote_time > new_round_end_time) {
            for (uint32 j = 0; j < node_count; j++) {
                all_nodes_vote_msg[i][j] = 0;
            }
        } else {
            for (uint32 j = 0; j < node_count; j++) {
                all_nodes_vote_msg[i][j] = vote_ctx.vote_info[j];
            }
        }
        for (uint32 j = 0; j < node_count; j++) {
            CMS_LOG_INF("cms get vote count res from disk, vote_ctx[%u] = %u", j, vote_ctx.vote_info[j]);
            CMS_LOG_INF("cms adjacency matrix of directed graph is adj_mat[%u][%u] = %u", i, j,
                        all_nodes_vote_msg[i][j]);
        }
    }
    if (cms_get_max_full_connect(vote_result, &all_nodes_vote_msg[0][0], node_count) != CT_SUCCESS) {
        CMS_LOG_ERR("cms get max full connect subset failed.");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

bool32 cms_bitmap64_exist(vote_result_ctx_t *vote_result, uint8 num)
{
    uint64 position;
    bool32 is_exist = CT_FALSE;
    CM_ASSERT(num < CT_MAX_INSTANCES);
    position = (uint64)1 << num;
    position = vote_result->new_cluster_bitmap & position;
    is_exist = (0 == position) ? CT_FALSE : CT_TRUE;
    return is_exist;
}

status_t cms_count_votes(vote_result_ctx_t *vote_result)
{
    uint64 new_round = g_vote_ctx->vote_data.vote_round;
    vote_result->vote_round = new_round;
    int64 new_round_start_time = cms_get_round_start_time(new_round);
    if (cms_get_votes_count_res(vote_result, new_round, new_round_start_time) != CT_SUCCESS) {
        CMS_LOG_ERR("cms get votes count res failed. vote round : %llu", new_round);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t cms_get_new_vote_result(vote_result_ctx_t *vote_result)
{
    bool32 is_master = CT_FALSE;
    status_t ret = CT_ERROR;
    vote_result_ctx_t disk_vote_result;
    do {
        CMS_SYNC_POINT_GLOBAL_START(CMS_SPLIT_BRAIN_BEFORE_GET_VOTE_ABORT, NULL, 0);
        CMS_SYNC_POINT_GLOBAL_END;
        CMS_RETRY_IF_ERR(cms_is_master(&is_master));
        if (is_master) {
            if (cms_count_votes(vote_result) == CT_SUCCESS) {
                vote_result->vote_count_done = CT_TRUE;
                ret = cms_set_vote_result(vote_result);
                CMS_SYNC_POINT_GLOBAL_START(CMS_SPLIT_BRAIN_AFTER_SET_VOTE_ABORT, NULL, 0);
                CMS_SYNC_POINT_GLOBAL_END;
                CMS_LOG_INF("cms is master, ret value is %d, vote result is %llu, vote res round is %llu", ret,
                    vote_result->new_cluster_bitmap, g_vote_ctx->vote_data.vote_round);
            }
        } else {
            cm_sleep(SLEEP_ONE_SECOND);
            ret = cms_get_vote_result(&disk_vote_result);
            CMS_SYNC_POINT_GLOBAL_START(CMS_SPLIT_BRAIN_AFTER_GET_VOTE_ABORT, NULL, 0);
            CMS_SYNC_POINT_GLOBAL_END;
            uint64 new_round = g_vote_ctx->vote_data.vote_round;
            if (disk_vote_result.vote_round < new_round || (disk_vote_result.vote_count_done == CT_FALSE)) {
                ret = CT_ERROR;
                CMS_LOG_INF("cms can not get the latest results. new round is %llu, cms get round is %llu.", new_round,
                    disk_vote_result.vote_round);
            } else {
                vote_result->new_cluster_bitmap = disk_vote_result.new_cluster_bitmap;
                vote_result->vote_count_done = CT_TRUE;
            }
            CMS_LOG_INF("cms not is master, cms get vote result is %llu, ret value is %d.",
                disk_vote_result.new_cluster_bitmap, ret);
        }
    } while (ret != CT_SUCCESS);
    return CT_SUCCESS;
}

void cms_kill_self_by_vote_result(vote_result_ctx_t *vote_result)
{
    bool32 is_master = CT_FALSE;
    CMS_RETRY_IF_ERR(cms_is_master(&is_master));
    status_t ret;
    if (!cms_bitmap64_exist(vote_result, g_cms_param->node_id)) {
        if (is_master) {
            cms_disk_unlock(&g_cms_inst->master_lock, DISK_LOCK_WRITE);
        }
        CMS_SYNC_POINT_GLOBAL_START(CMS_DEAMON_STOP_PULL_FAIL, &ret, CT_ERROR);
        ret = cms_daemon_stop_pull();
        CMS_SYNC_POINT_GLOBAL_END;
        if (ret != CT_SUCCESS) {
            CMS_LOG_ERR("stop cms daemon process failed.");
        }
        CM_ABORT_REASONABLE(0, "[CMS] ABORT INFO: Based on the vote, the node is removed from the cluster.");
    }
}

status_t cms_execute_io_fence(vote_result_ctx_t *vote_result)
{
    CMS_LOG_INF("begin execute io fence");
    uint32 node_count = cms_get_gcc_node_count();
    uint32 res_id = 0;
    CT_RETURN_IFERR(cms_get_res_id_by_name(CMS_RES_TYPE_DB, &res_id));

    for (uint32 i = 0; i < node_count; i++) {
        if (i == g_cms_param->node_id || cms_node_is_invalid(i)) {
            continue;
        }

        if (!cms_bitmap64_exist(vote_result, i)) {
            CMS_SYNC_POINT_GLOBAL_START(CMS_BEFORE_IO_FENCE_ABORT, NULL, 0);
            CMS_SYNC_POINT_GLOBAL_END;
            try_cms_kick_node(i, res_id, IOFENCE_BY_VOTING);
            CMS_SYNC_POINT_GLOBAL_START(CMS_AFTER_IO_FENCE_ABORT, NULL, 0);
            CMS_SYNC_POINT_GLOBAL_END;
        }
    }

    CMS_LOG_INF("execute io fence succ");
    return CT_SUCCESS;
}

status_t cms_refresh_new_cluster_info(vote_result_ctx_t *vote_result)
{
    uint32 node_count = cms_get_gcc_node_count();
    for (uint32 i = 0; i < node_count; i++) {
        if (cms_node_is_invalid(i)) {
            continue;
        }
        if (!cms_bitmap64_exist(vote_result, i)) {
            bool32 stat_changed = CT_FALSE;
            if (cms_node_all_res_offline(i, &stat_changed) != CT_SUCCESS) {
                CMS_LOG_ERR("Update node offline stat fail.");
                return CT_ERROR;
            }
            if (stat_changed) {
                CMS_SYNC_POINT_GLOBAL_START(CMS_BEFORE_BROADCAST_OFFLINE_ABORT, NULL, 0);
                CMS_SYNC_POINT_GLOBAL_END;
                cms_res_offline_broadcast(i);
                CMS_SYNC_POINT_GLOBAL_START(CMS_AFTER_BROADCAST_OFFLINE_ABORT, NULL, 0);
                CMS_SYNC_POINT_GLOBAL_END;
            }
        }
    }
    vote_result->vote_stat = VOTE_DONE;
    CT_RETURN_IFERR(cms_set_vote_result(vote_result));
    return CT_SUCCESS;
}

status_t wait_for_vote_done(void)
{
    CMS_LOG_INF("begin wait for vote done");
    vote_result_ctx_t *vote_result = &g_vote_ctx->vote_result;
    cms_kill_self_by_vote_result(vote_result);
    do {
        cms_get_vote_result(vote_result);
        if (vote_result->vote_stat == VOTE_ERR) {
            CMS_LOG_WAR("This round(%llu) of arbitration has failed, wait for new round", vote_result->vote_round);
            return CT_ERROR;
        }
        if (vote_result->vote_round == (g_vote_ctx->vote_data.vote_round + 1)) {
            vote_result->vote_stat = VOTE_ERR;
            CMS_LOG_WAR("This round %llu of arbitration has been finished, new round %llu has been triggered",
                        g_vote_ctx->vote_data.vote_round, vote_result->vote_round);
            return CT_ERROR;
        }
        bool32 is_master = CT_FALSE;
        CMS_RETRY_IF_ERR(cms_is_master(&is_master));

        if (is_master) {
            if (cms_master_execute_result(vote_result) != CT_SUCCESS) {
                CMS_LOG_ERR("cms master execute result failed, trigger new voting");
                return CT_ERROR;
            }
        }
        cm_sleep(CMS_WAIT_VOTE_DONE_INTERNAL);
    } while (vote_result->vote_stat != VOTE_DONE);

    CMS_LOG_INF("wait for vote done succ");
    return CT_SUCCESS;
}

status_t cms_master_execute_result(vote_result_ctx_t *vote_result)
{
    CMS_LOG_INF("master begin execute the vote result");
    // cms master execute IOFence.If the execution fails, the current round of arbitration ends.
    status_t ret;
    CMS_SYNC_POINT_GLOBAL_START(CMS_EXECUTE_IOFENCE_FAIL, &ret, CT_ERROR);
    ret = cms_execute_io_fence(vote_result);
    CMS_SYNC_POINT_GLOBAL_END;
    if (ret != CT_SUCCESS) {
        vote_result->vote_stat = VOTE_ERR;
        if (cms_set_vote_result(vote_result) != CT_SUCCESS) {
            CMS_LOG_ERR("cms set vote reslut failed");
        }
        CMS_LOG_ERR("cms execute io fence failed, trigger new voting");
        return CT_ERROR;
    }

    // After the arbitration is complete, the CMS master updates the cluster status to trigger reform.
    CMS_SYNC_POINT_GLOBAL_START(CMS_REFRESH_NEW_CLUSTER_INFO_FAIL, &ret, CT_ERROR);
    ret = cms_refresh_new_cluster_info(vote_result);
    CMS_SYNC_POINT_GLOBAL_END;
    if (ret != CT_SUCCESS) {
        vote_result->vote_stat = VOTE_ERR;
        if (cms_set_vote_result(vote_result) != CT_SUCCESS) {
            CMS_LOG_ERR("cms set vote reslut failed");
        }
        CMS_LOG_ERR("cms refresh cluster info failed");
    } else {
        CMS_LOG_INF("master execute the vote result succ");
    }
    cms_kill_self_by_vote_result(vote_result);
    return ret;
}

void cms_voting_entry(thread_t *thread)
{
    const uint32 timeout_ms = CT_MAX_UINT32;
    while (!thread->closed) {
        cm_event_timedwait(&g_cms_inst->voting_sync, timeout_ms);
        CMS_LOG_INF("cms voting entry wake up");

        if (cms_start_new_voting() != CT_SUCCESS) {
            CMS_LOG_ERR("cms voting failed");
        }

        vote_result_ctx_t *vote_result = &g_vote_ctx->vote_result;
        if (cms_get_new_vote_result(vote_result) != CT_SUCCESS) {
            CMS_LOG_ERR("cms get new vote result failed");
        }

        bool32 is_master = CT_FALSE;
        CMS_RETRY_IF_ERR(cms_is_master(&is_master));
        if (is_master) {
            if (cms_master_execute_result(vote_result) != CT_SUCCESS) {
                CMS_LOG_ERR("cms master execute result failed, trigger new voting");
                continue;
            }
        } else {
            (void)wait_for_vote_done();
        }

        if (vote_result->vote_stat == VOTE_DONE) {
            CMS_LOG_INF("cms split-brain voting succeed, vote_round = %llu", g_vote_ctx->vote_data.vote_round);
        }
    }
}

void cms_trigger_voting(void)
{
    CMS_LOG_INF("cms trigger new voting");
    if (g_cms_param->split_brain == CMS_OPEN_WITHOUT_SPLIT_BRAIN) {
        CMS_LOG_INF("cms run without split-brain process");
        return;
    }
    if (g_vote_ctx->vote_result.vote_stat != VOTE_FROZEN) {
        CMS_LOG_INF("cms begin to trigger voting");
        cm_event_notify(&g_cms_inst->voting_sync);
    }
}

void cms_detect_voting_entry(thread_t *thread)
{
    while (!thread->closed) {
        if (g_vote_ctx->vote_result.vote_stat == VOTE_ERR) {
            CMS_LOG_INF("The last round(%llu) of arbitration failed, trigger new vote round",
                g_vote_ctx->vote_data.vote_round);
            cms_trigger_voting();
        }

        if (g_vote_ctx->vote_result.vote_stat != VOTE_FROZEN && detect_new_vote_round() == CT_SUCCESS) {
            cms_trigger_voting();
        }
        cm_sleep(SLEEP_ONE_SECOND);
    }
}

static void cms_init_vote_result(vote_result_ctx_t *vote_result)
{
    vote_result->magic = CMS_VOTE_RES_MAGIC;
    vote_result->vote_round = 0;
    vote_result->new_cluster_bitmap = UINT64_MAX;
    vote_result->vote_count_done = CT_FALSE;
    vote_result->vote_stat = VOTE_PREPARE;
}

status_t cms_init_cluster_vote_info(void)
{
    uint64 offset = 0;
    if (g_cms_param->gcc_type == CMS_DEV_TYPE_SD) {
        offset += CMS_VOTE_DATA_GCC_OFFSET;
    }

    cms_cluster_vote_data_t *cluster_vote_data =
        (cms_cluster_vote_data_t *)cm_malloc_align(CMS_BLOCK_SIZE, sizeof(cms_cluster_vote_data_t));
    if (cluster_vote_data == NULL) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, sizeof(cms_cluster_vote_data_t), "init vote disk");
        return CT_ERROR;
    }
    status_t ret = memset_s(cluster_vote_data, sizeof(cms_cluster_vote_data_t), 0, sizeof(cms_cluster_vote_data_t));
    if (ret != CT_SUCCESS) {
        CM_FREE_PTR(cluster_vote_data);
        CMS_LOG_ERR("memset cluster vote data err, error code:%d,%s", errno, strerror(errno));
        return ret;
    }
    vote_result_ctx_t *vote_result = &cluster_vote_data->vote_result;
    cms_init_vote_result(vote_result);

    for (uint16 node_id = 0; node_id < CMS_MAX_NODE_COUNT; node_id++) {
        for (uint16 slot_id = 0; slot_id < CMS_MAX_VOTE_SLOT_COUNT; slot_id++) {
            cms_vote_data_t *vote_data = &cluster_vote_data->vote_data[node_id][slot_id];
            vote_data->magic = CMS_VOTE_DATA_MAGIC;
            if (memset_s(vote_data->data, CMS_MAX_VOTE_DATA_SIZE, 0, CMS_MAX_VOTE_DATA_SIZE) != CT_SUCCESS) {
                CM_FREE_PTR(cluster_vote_data);
                CMS_LOG_ERR("memset vote_data err, error code:%d,%s", errno, strerror(errno));
                return CT_ERROR;
            }
        }
    }
    
    if (vote_data_write(offset, (char *)cluster_vote_data, sizeof(cms_cluster_vote_data_t)) != CT_SUCCESS) {
        CM_FREE_PTR(cluster_vote_data);
        CMS_LOG_ERR("write disk failed");
        return CT_ERROR;
    }
    CM_FREE_PTR(cluster_vote_data);
    cms_init_vote_result(&g_vote_ctx->vote_result);
    CMS_LOG_INF("cms init vote result succeed, vote_round = %llu", g_vote_ctx->vote_result.vote_round);
    return CT_SUCCESS;
}

void cms_init_vote_round(void)
{
    g_vote_ctx->vote_data.vote_round = g_vote_ctx->vote_result.vote_round;
    CMS_LOG_INF("cms init vote round succeed, vote_round = %llu", g_vote_ctx->vote_data.vote_round);
    return;
}

status_t cms_is_vote_done(bool32 *vote_done)
{
    vote_result_ctx_t *vote_result = &g_vote_ctx->vote_result;
    // When a new node is added, the node can be added only after the split-brain arbitration ends.
    CT_RETURN_IFERR(cms_get_vote_result(vote_result));
    if (vote_result->vote_stat == VOTE_PREPARE || vote_result->vote_stat == VOTE_DONE) {
        *vote_done = CT_TRUE;
        return CT_SUCCESS;
    }
    CMS_LOG_INF("cms is in voting process, vote_stat %d", vote_result->vote_stat);
    *vote_done = CT_FALSE;
    return CT_SUCCESS;
}

bool32 cms_cluster_is_voting(void)
{
    if (g_vote_ctx->vote_result.vote_stat == VOTE_FROZEN) {
        return CT_TRUE;
    }
    return CT_FALSE;
}