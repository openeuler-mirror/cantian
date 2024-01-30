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
 * cms_vote.h
 *
 *
 * IDENTIFICATION
 * src/cms/cms/cms_vote.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef CMS_VOTE_H
#define CMS_VOTE_H

#include "cm_thread.h"
#include "cms_defs.h"
#include "cms_detect_error.h"
#include "cms_msg_def.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CMS_MAX_VOTE_DATA_SIZE 1000
#define CMS_MAX_VOTE_DATA_BUFFER SIZE_K(1)
#define CMS_VOTE_DATA_DISK_SIZE SIZE_M(10)
#define CMS_VOTE_DATA_MAGIC (*((uint64 *)"VOTE_DATA"))
#define CMS_VOTE_RES_MAGIC (*((uint64 *)"VOTE_RES"))
#define CMS_VOTE_INIT_MAGIC (*((uint64 *)"VOTE_INIT"))
#define CMS_VOTE_RESULT_OFFSET  (OFFSET_OF(vote_result_ctx_t, vote_round))
#define CMS_VOTE_VALID_PERIOD 5000
// reserve 100 blocks
#define CMS_VOTE_DATA_GCC_OFFSET (CMS_MES_CHANNEL_OFFSET + sizeof(cms_mes_channel_t) + CMS_RESERVED_BLOCKS_SIZE)

#define CMS_VOTE_INFO 0 // slot id, persist the vote_ctx info
#define CMS_VOTE_TRIGGER_ROUND 1 // slot id, persist the new vote_round

#define CMS_RES_MAGIC_ERR (-2)
#define DISK_LOCK_WAIT_TIMEOUT 5000
#define SLEEP_ONE_SECOND 1000
#define NODE_CONNECT_GOOD 1
#define NODE_CONNECT_BAD 0
#define CMS_REVOTE_INTERNAL 500
#define CMS_WAIT_VOTE_DONE_INTERNAL 200
#define CMS_RETRY_GET_STAT_NUM 5

typedef enum e_vote_status {
    VOTE_PREPARE = 0, // prepare to vote, waiting for triggering voting
    VOTE_FROZEN = 1,  // begin to vote, frozen and not accessable
    VOTE_DONE = 2,    // vote is done
    VOTE_ERR = 3,     // vote err,trigger new voting
} vote_status_t;

typedef union st_vote_result_ctx {
    struct {
        uint64 magic;
        uint64 vote_round;
        uint64 new_cluster_bitmap;
        bool32 vote_count_done;
        volatile vote_status_t vote_stat;
    };
    char placeholder[CMS_BLOCK_SIZE];
} vote_result_ctx_t;

typedef struct st_one_vote_data_t {
    uint64 vote_round;
    int64 vote_time;
    uint8 vote_info[CMS_MAX_NODE_COUNT];
} one_vote_data_t;

typedef struct st_vote_ctx {
    vote_status_t vote_stat;
    volatile uint64 detect_vote_round;
    one_vote_data_t vote_data;
    vote_result_ctx_t vote_result;
} vote_ctx_t;

typedef union st_cms_vote_data_t {
    struct {
        uint64 magic;
        uint64 version;
        uint32 data_size;
        char data[CMS_MAX_VOTE_DATA_SIZE];
    };
    char placeholder[CMS_MAX_VOTE_DATA_BUFFER];
} cms_vote_data_t;

CM_STATIC_ASSERT(CMS_MAX_VOTE_DATA_BUFFER == sizeof(cms_vote_data_t));

typedef struct st_cms_cluster_vote_data_t {
    vote_result_ctx_t vote_result;
    cms_vote_data_t vote_data[CMS_MAX_NODE_COUNT][CMS_MAX_VOTE_SLOT_COUNT];
} cms_cluster_vote_data_t;

typedef struct st_max_clique_ctx {
    uint32 node_count;
    uint32 max_clique_num_index; // get max clique index in contain_specify_node_clique and specify_node_clique_num
    uint32 contain_specify_node_clique[CMS_MAX_NODE_COUNT][CMS_MAX_NODE_COUNT]; // store which nodes make up max clique
                                                                                // containing node x.
    uint32 specify_node_clique_num[CMS_MAX_NODE_COUNT]; // hold the number of nodes in max clique containing node x.
} max_clique_t;

CM_STATIC_ASSERT(CMS_VOTE_DATA_DISK_SIZE > sizeof(cms_cluster_vote_data_t));

void cms_voting_entry(thread_t *thread);
void cms_detect_voting_entry(thread_t *thread);
void cms_trigger_voting(void);
status_t cms_init_cluster_vote_info(void);
void cms_init_vote_round(void);
status_t cms_is_vote_done(bool32 *vote_done);
status_t cms_get_vote_data(uint16 node_id, uint32 slot_id, char *data, uint32 max_size, uint32 *data_size);
status_t cms_get_vote_data_inner(uint16 node_id, uint32 slot_id, char *data, uint32 max_size, uint32 *data_size);
status_t cms_read_vote_data(cms_vote_data_t *vote_data, uint16 node_id, uint64 offset);
int64 cms_get_round_start_time(uint64 new_round);
status_t cms_get_vote_result(vote_result_ctx_t *vote_result);
status_t cms_get_votes_count_res(vote_result_ctx_t *vote_result, uint64 new_round, int64 new_round_start_time);
status_t wait_for_vote_done(void);
status_t cms_start_new_voting(void);
status_t cms_get_new_vote_result(vote_result_ctx_t *vote_result);
status_t cms_execute_io_fence(vote_result_ctx_t *vote_result);
status_t cms_refresh_new_cluster_info(vote_result_ctx_t *vote_result);
status_t cms_set_vote_data(uint16 node_id, uint32 slot_id, char *data, uint32 data_size, uint64 old_version);
status_t cms_count_votes(vote_result_ctx_t *vote_result);
bool32 cms_bitmap64_exist(vote_result_ctx_t *vote_result, uint8 num);
status_t cms_set_vote_result(vote_result_ctx_t *vote_result);
vote_result_ctx_t *get_current_vote_result(void);
bool32 cms_cluster_is_voting(void);
status_t cms_master_execute_result(vote_result_ctx_t *vote_result);
status_t cms_get_online_joined_node_set(uint8 *online_node_arr, uint8 *online_joined_node_arr, uint8 max_node_count);
void cms_get_max_num_index(max_clique_t *clique, uint8 *online_node_set, uint8 *online_joined_node_set);

#ifdef __cplusplus
}
#endif
#endif