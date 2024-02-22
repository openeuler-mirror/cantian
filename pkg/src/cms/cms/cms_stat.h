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
 * cms_stat.h
 *
 *
 * IDENTIFICATION
 * src/cms/cms/cms_stat.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef CMS_STAT_H
#define CMS_STAT_H

#include "cm_thread.h"
#include "cm_ip.h"
#include "cms_defs.h"
#include "cms_interface.h"
#include "cms_gcc.h"
#include "cms_client.h"
#include "cms_disk_lock.h"
#include "cms_msg_def.h"
#include "cm_atomic.h"
#include "cms_instance.h"
#include "cms_syncpoint_inject.h"
#include "cms_iofence.h"

#ifdef __cplusplus
extern "C" {
#endif
typedef struct st_cms_res_session {
    thread_lock_t       lock;
    thread_lock_t       uds_lock;
    socket_t            uds_sock;
    cms_cli_type_t      type;
}cms_res_session_t;

typedef struct st_cms_packet_aync_write_t {
    uint32      res_id;
}cms_packet_aync_write_t;

typedef struct st_cms_hb_aync_start_t {
    timeval_t hb_time_aync_start;
} cms_hb_aync_start_t;

// reserve one gcc and 100 blocks
#define CMS_CLUSTER_STAT_OFFSET     (sizeof(cms_gcc_storage_t) + sizeof(cms_gcc_t) + CMS_RESERVED_BLOCKS_SIZE)
#define CMS_CLUSTER_STAT_DISK_SIZE  SIZE_M(32)
// reserve 100 blocks
#define CMS_RES_DATA_OFFSET         (CMS_CLUSTER_STAT_OFFSET + sizeof(cms_cluster_stat_t) + CMS_RESERVED_BLOCKS_SIZE)
#define CMS_RES_DATA_DISK_SIZE      SIZE_M(32)

#define CMS_RES_LOCK_OFFSET         (CMS_RES_DATA_OFFSET + sizeof(cms_cluster_res_data_t) + CMS_RESERVED_BLOCKS_SIZE)
#define CMS_MES_CHANNEL_OFFSET      (CMS_RES_LOCK_OFFSET + sizeof(cms_cluster_res_lock_t))
#define CMS_RES_LOCK_DISK_SIZE      SIZE_M(32)

#define CMS_STAT_HEAD_MAGIC         (*((uint64*)"STATHEAD"))
#define CMS_RES_DATA_MAGIC          (*((uint64*)"RES_DATA"))
#define CMS_RES_STAT_MAGIC          (*((uint64*)"RES_STAT"))
#define CMS_REFORMER_MAGIC          (*((uint64*)"REFORMER"))
#define CMS_CHANNEL_VERSION_MAGIC   (*((uint64*)"CHANNEL_VER"))

#define STAT_LOCK_WAIT_TIMEOUT    5000
#define CMS_WAIT_RES_JOINED_INTERNAL 1000
#define CMS_START_RES_RETRY_INTERNAL 1000
#define CMS_CHECK_REFORM_STAT_INTERNAL 1000
#define CMS_WAIT_REFORM_DONE_INTERNAL 1000
#define CMS_TRANS_MS_TO_SECOND_FLOAT 1000.0
#define CMS_MAX_FILE_NAME 256
#define CMS_INIT_VTINFO_RETRY_INTERNAL 1000
#define CMS_RETRY_SLEEP_TIME 100
#define CMS_HB_AYNC_UPDATE_INTERNAL 5000
#define CMS_CHECK_RES_RUNING_TIMES 10

// range lock defs for nfs
#define CMS_RLOCK_VOTE_RESULT_LOCK_START    (0)
#define CMS_RLOCK_VOTE_RESULT_LOCK_LEN      (sizeof(vote_result_ctx_t))
#define CMS_RLOCK_VOTE_INFO_LOCK_START      (0)
#define CMS_RLOCK_VOTE_INFO_LOCK_LEN        (0)
#define CMS_VOTE_DATA_ADDR(node_id, slot_id) \
    ((uint64)(&(((cms_cluster_vote_data_t*)NULL)->vote_data[node_id][slot_id])))
#define CMS_RLOCK_VOTE_DATA_LOCK_START(node_id, slot_id) CMS_VOTE_DATA_ADDR(node_id, slot_id)
#define CMS_RLOCK_VOTE_DATA_LOCK_LEN        (sizeof(cms_vote_data_t))

#define CMS_ERROR_DETECT_START                          0
#define CMS_RLOCK_MASTER_LOCK_START                     0
#define CMS_RLOCK_MASTER_LOCK_LEN                       CMS_BLOCK_SIZE
#define CMS_RLOCK_STAT_LOCK_START                       CMS_CLUSTER_STAT_OFFSET
#define CMS_RLOCK_STAT_LOCK_LEN                         (sizeof(cms_cluster_stat_head_t))
#define CMS_RLOCK_RES_START_LOCK_START                  CMS_RES_START_LOCK_POS
#define CMS_RLOCK_RES_START_LOCK_LEN                    CMS_BLOCK_SIZE
#define CMS_RLOCK_RES_DATA_LOCK_START(res_id, slot_id)  CMS_RES_DATA_GCC_OFFSET(res_id, slot_id)
#define CMS_RLOCK_RES_DATA_LOCK_LEN                     sizeof(cms_res_data_t)
#define CMS_RLOCK_RES_STAT_LOCK_START(node_id, res_id)  CMS_RES_STAT_POS(node_id, res_id)
#define CMS_RLOCK_RES_STAT_LOCK_LEN                     (sizeof(cms_res_stat_t))

#define CMS_RETRY_IF_ERR(func)          \
    while (func) {                      \
        cm_sleep(CMS_RETRY_SLEEP_TIME); \
    }

typedef union u_cms_res_stat_t {
    struct {
        uint64              magic;
        uint64              session_id;
        uint64              inst_id;
        char                res_type[CMS_MAX_RES_TYPE_LEN];
        int64               hb_time;
        int64               last_check;
        int64               last_stat_change;
        cms_stat_t          pre_stat;
        cms_stat_t          cur_stat;
        cms_stat_t          target_stat;
        uint8               work_stat;
        int32               restart_count;
        int64               restart_time;
        atomic32_t          checking;
    };
    char                placeholder[CMS_BLOCK_SIZE];
}cms_res_stat_t;

CM_STATIC_ASSERT(CMS_BLOCK_SIZE == sizeof(cms_res_stat_t));

typedef enum e_node_status_t {
    OFFLINE,
    ONLINE
}node_status_t;

typedef enum e_vote_info_status_t {
    CMS_INITING_VOTE_INFO,
    CMS_INIT_VOTE_INFO_DONE
}vote_info_status_t;

typedef union st_cms_node_stat_t {
    struct {
        uint64                    magic;
        node_status_t             status;
        vote_info_status_t        vote_info_status;
        uint64                    net_hb;
        uint64                    disk_hb;
        uint32                    net_error_count;
        uint32                    disk_error_count;
    };
    char                placeholder[CMS_BLOCK_SIZE];
}cms_node_stat_t;

CM_STATIC_ASSERT(CMS_BLOCK_SIZE == sizeof(cms_node_stat_t));


typedef union st_cms_node_disk_hb_t {
    struct {
        uint64                    magic;
        int64                     disk_hb;
    };
    char                placeholder[CMS_BLOCK_SIZE];
}cms_node_disk_hb_t;

CM_STATIC_ASSERT(CMS_BLOCK_SIZE == sizeof(cms_node_disk_hb_t));

typedef struct st_cms_node_inf_t {
    cms_res_stat_t      res_stat[CMS_MAX_RESOURCE_COUNT];
    cms_node_stat_t     node_stat[CMS_MAX_NODE_COUNT];
}cms_node_inf_t;

typedef union st_cms_res_reformer {
    struct {
        uint64              magic;
        uint8               reformer[CMS_MAX_RESOURCE_COUNT];
    };
}cms_res_reformer_t;
CM_STATIC_ASSERT(DISK_LOCK_BODY_LEN >= sizeof(cms_res_reformer_t));

typedef union st_cms_cluster_stat_head {
    struct {
        uint64              magic;
        uint64              not_used;
        uint64              data_ver;
        uint64              stat_ver;
    };
    char                placeholder[CMS_BLOCK_SIZE];
}cms_cluster_stat_head_t;

CM_STATIC_ASSERT(CMS_BLOCK_SIZE == sizeof(cms_cluster_stat_head_t));

typedef struct st_cms_cluster_stat_t {
    cms_cluster_stat_head_t head;
    char                    stat_lock[CMS_BLOCK_SIZE];
    char                    cms_lock[CMS_BLOCK_SIZE];
    char                    res_data_lock[CMS_MAX_RESOURCE_COUNT][CMS_MAX_RES_SLOT_COUNT][CMS_BLOCK_SIZE];
    char                    vote_data_lock[CMS_MAX_NODE_COUNT][CMS_MAX_VOTE_SLOT_COUNT][CMS_BLOCK_SIZE];
    char                    vote_result_lock[CMS_BLOCK_SIZE];
    char                    res_start_lock[CMS_BLOCK_SIZE];
    char                    vote_info_lock[CMS_BLOCK_SIZE];
    cms_node_inf_t          node_inf[CMS_MAX_NODE_COUNT];
}cms_cluster_stat_t;

CM_STATIC_ASSERT(CMS_CLUSTER_STAT_DISK_SIZE > sizeof(cms_cluster_stat_t));

typedef struct st_cms_cluster_res_lock_t {
    char                    res_stat_lock[CMS_MAX_NODE_COUNT][CMS_RES_STAT_MAX_RESOURCE_COUNT][CMS_BLOCK_SIZE];
}cms_cluster_res_lock_t;
CM_STATIC_ASSERT(CMS_RES_DATA_DISK_SIZE > sizeof(cms_cluster_res_lock_t));

typedef union st_cms_res_data_t {
    struct {
        uint64      magic;
        uint64      version;
        uint32      data_size;
        char        data[CMS_MAX_RES_DATA_SIZE];
    };
    char    placeholder[CMS_MAX_RES_DATA_BUFFER];
}cms_res_data_t;

CM_STATIC_ASSERT(CMS_MAX_RES_DATA_BUFFER == sizeof(cms_res_data_t));

typedef union st_cms_cluster_res_data_t {
    cms_res_data_t  res_data[CMS_MAX_RESOURCE_COUNT][CMS_MAX_RES_SLOT_COUNT];
}cms_cluster_res_data_t;

CM_STATIC_ASSERT(CMS_RES_DATA_DISK_SIZE > sizeof(cms_cluster_res_data_t));

#define CMS_RES_DATA_ADDR(res_id, slot_id) ((uint64)(&(((cms_cluster_res_data_t*)NULL)->res_data[res_id][slot_id])))
#define CMS_RES_DATA_GCC_OFFSET(res_id, slot_id) (CMS_RES_DATA_OFFSET + CMS_RES_DATA_ADDR(res_id, slot_id))

typedef union st_channel_info_t {
    struct {
        uint64      magic;
        uint64      channel_version;
    };
    char    placeholder[CMS_BLOCK_SIZE];
}cms_channel_info_t;

typedef struct st_cms_mes_channel_t {
    cms_channel_info_t  channel_info[CMS_MAX_NODE_COUNT];
}cms_mes_channel_t;

extern thread_lock_t g_node_lock[CMS_MAX_NODE_COUNT];
extern cms_res_session_t g_res_session[CMS_MAX_UDS_SESSION_COUNT];
status_t cms_init_stat(void);
status_t cms_init_stat_for_dbs(void);
status_t cms_lock_stat(uint8 lock_type);
status_t cms_unlock_stat(uint8 lock_type);

status_t cms_res_init(uint32 res_id, uint32 timeout_ms);
status_t cms_res_start(uint32 res_id, uint32 timeout_ms);
status_t cms_res_stop(uint32 res_id, uint8 need_write_disk);
status_t cms_res_stop_by_force(uint32 res_id, uint8 need_write_disk);
status_t cms_res_check(uint32 res_id, bool32 *res_running);
status_t cms_res_reset(uint32 res_id);

status_t cms_res_started(uint32 res_id);
status_t cms_res_stopped(uint32 res_id);
status_t cms_res_connect(socket_t sock, cms_cli_msg_req_conn_t *req, cms_cli_msg_res_conn_t *res);
status_t cms_tool_connect(socket_t sock, cms_cli_msg_req_conn_t *req, cms_cli_msg_res_conn_t *res);
status_t cms_res_dis_conn(const char* res_type, uint32 inst_id);
status_t cms_res_set_workstat(const char* res_type, uint32 inst_id, uint8 work_stat);
status_t cms_res_hb(uint32 res_id);
status_t cms_res_no_hb(uint32 res_id);
status_t cms_res_detect_online(uint32 res_id, cms_res_stat_t *old_stat);
status_t cms_res_detect_offline(uint32 res_id, cms_res_stat_t *old_stat);
void cms_tool_detect_offline(uint32 session_id);
status_t cms_get_res_session(cms_res_session_t* sessions, uint32 size);
status_t cms_get_stat_version(uint64* version);
status_t get_res_stat(uint32 node_id, uint32 res_id, cms_res_stat_t* res_stat);
void get_cur_res_stat(uint32 res_id, cms_res_stat_t* res_stat);
status_t cms_stat_chg_notify_to_cms(uint32 res_id, uint64 version);
status_t cms_get_cluster_stat_bytype(const char* res_type, uint64 version, cms_res_status_list_t* stat_list);
status_t cms_get_cluster_stat(uint32 res_id, uint64 version, cms_res_status_list_t* stat_list);
status_t cms_stat_get_res_data(const char* res_type, uint32 slot_id, char* data, uint32 max_size,
    uint32* data_size, uint64* data_version);
status_t cms_stat_set_res_data(const char* res_type, uint32 slot_id, char* data, uint32 data_size, uint64 old_version);
void cms_stat_update_restart_attr(uint32 res_id);
void cms_stat_reset_restart_attr(uint32 res_id);
status_t cms_get_stat_version_ex(uint64 version, cms_res_status_list_t* stat);
status_t cms_get_cluster_res_list(uint32 res_id, cms_res_status_list_t *stat);

status_t cms_try_be_master(void);
status_t cms_get_master_node(uint16* node_id);
status_t cms_is_master(bool32* is_master);
status_t cms_get_res_master(uint32 res_id, uint8* node_id);
status_t cms_check_master_lock_status(cms_disk_lock_t* master_lock);
status_t wait_for_cluster_reform_done(uint32 res_id);
status_t cms_wait_res_started(uint32 res_id, uint32 timeout_ms);

void cms_stat_aync_write_entry(thread_t* thread);
status_t cms_stat_read_from_disk(uint32 node_id, uint32 res_id, cms_res_stat_t** resRef);
status_t cms_stat_write_to_disk(uint32 node_id, uint32 res_id, cms_res_stat_t* stat);
void cms_stat_set(cms_res_stat_t* res_stat, cms_stat_t new_stat, bool32* isChanged);
status_t inc_stat_version(void);
status_t cms_vote_disk_init(void);
status_t cms_exec_res_script(const char* script, const char* arg, uint32 timeout_ms, status_t* result);
status_t cms_aync_update_res_hb(cms_res_stat_t *res_stat_disk, uint32 res_id);
status_t cms_update_disk_hb(void);
status_t cms_is_all_restart(bool32 *all_restart);
status_t cms_init_vote_info(void);
bool32 cms_try_be_new_master(void);
status_t cms_vote_file_init(void);
status_t cms_res_lock_init(void);
status_t cms_get_start_lock(cms_disk_lock_t *lock, bool32 *cms_get_lock);
void cms_record_io_aync_hb_gap_end(biqueue_node_t *node_hb_aync, io_record_stat_t stat);
status_t cms_get_res_start_lock(uint32 res_id);
void cms_release_res_start_lock(uint32 res_id);
void try_lock_start_lock(void);
uint32 cms_online_res_count(uint32 res_id, iofence_type_t iofence_type);
status_t cms_stat_get_uds(uint64 session_id, socket_t *uds_sock);
status_t cms_server_stat(uint32 node_id, bool32* cms_online);
status_t cms_get_node_view(uint64* cms_online_bitmap);
status_t cms_check_res_running(uint32 res_id);

status_t cms_init_mes_channel_version(void);
status_t cms_get_mes_channel_version(uint64* version);
status_t cms_get_cluster_res_list_4tool(uint32 res_id, cms_tool_res_stat_list_t *res_list);
status_t cms_get_gcc_info_4tool(cms_tool_msg_res_get_gcc_t* gcc_info);
#ifdef __cplusplus
}
#endif

#endif
