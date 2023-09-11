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
 * cms_instance.h
 *
 *
 * IDENTIFICATION
 * src/cms/cms/cms_instance.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef CMS_INSTANCE_H
#define CMS_INSTANCE_H

#include "cm_ip.h"
#include "cm_date.h"
#include "cm_thread.h"
#include "cm_defs.h"
#include "cms_defs.h"
#include "cms_msgque.h"
#include "cm_disk.h"
#include "cms_disk_lock.h"
#include "cms_interface.h"
#include "cms_gcc.h"
#include "cms_detect_error.h"
#include "cm_sync.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CMS_INST_TRY_MASTER_WAIT_TIME 1000
#define CMS_INST_SERVER_SLEEP_TIME 1000
#define CMS_RES_STAT_MAX_RESOURCE_COUNT 2

typedef struct st_cms_instance {
    int32                   server_lock_fd;
    disk_handle_t           vote_file_fd;
    date_t                  time_gap;
    thread_t                send_thread;
    thread_t                work_thread[CMS_MAX_WORKER_THREAD_COUNT];
    thread_t                hb_timer_thread;
    thread_t                hb_worker_thread;
    thread_t                res_check_timer_thread;
    thread_t                disk_thread;
    thread_t                uds_listen_thread;
    thread_t                uds_recv_thread;
    thread_t                uds_send_thread;
    thread_t                uds_hb_thread;
    thread_t                uds_work_thread[CMS_MAX_WORKER_THREAD_COUNT];
    thread_t                gcc_loader_thread;
    thread_t                gcc_backup_thread;
    thread_t                stat_aync_write_thread;
    thread_t                cmd_handle_thread;
    thread_t                voting_thread;
    thread_t                detect_voting_thread;
    thread_t                detect_disk_error_thread;
    thread_t                judge_disk_error_thread;
    socket_t                uds_server;
    cms_que_t               recv_que;
    cms_que_t               send_que;
    cms_que_t               cli_recv_que;
    cms_que_t               cli_send_que;
    cms_que_t               aync_write_que;
    cms_que_t               cmd_recv_que;
    cms_disk_lock_t         master_lock;
    cms_disk_lock_t         stat_lock;
    cms_disk_lock_t         res_data_lock[CMS_MAX_RESOURCE_COUNT][CMS_MAX_RES_SLOT_COUNT];
    cms_disk_lock_t         vote_data_lock[CMS_MAX_NODE_COUNT][CMS_MAX_VOTE_SLOT_COUNT];
    cms_disk_lock_t         vote_result_lock;
    cms_disk_lock_t         gcc_lock;
    cms_disk_lock_t         res_start_lock;
    cms_disk_lock_t         vote_info_lock;
    cms_disk_lock_t         res_stat_lock[CMS_MAX_NODE_COUNT][CMS_RES_STAT_MAX_RESOURCE_COUNT];
    bool32                  is_server;
    cms_gcc_auto_bak_t      gcc_auto_bak;
    bool32                  server_loop;
    cms_sync_t              try_master_sync;
    cm_event_t              voting_sync;
}cms_instance_t;

typedef struct st_cms_local_ctx_t {
    disk_handle_t   gcc_handle;
}cms_local_ctx_t;

extern cms_instance_t* g_cms_inst;
extern cms_que_t g_hb_aync_gap_que;
status_t cms_instance_init(void);
status_t cms_startup(void);
status_t cms_get_local_ctx(cms_local_ctx_t** ctx);
void    cms_do_try_master(void);
void cms_shutdown(void);
status_t cms_create_aync_write_thread(void);
status_t cms_broadcast_srv_msg(cms_packet_head_t* msg);
status_t cms_init_dbs_client(void);

#ifdef __cplusplus
}
#endif
#endif