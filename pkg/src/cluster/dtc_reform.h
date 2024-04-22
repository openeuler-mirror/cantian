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
 * dtc_reform.h
 *
 *
 * IDENTIFICATION
 * src/cluster/dtc_reform.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef DTC_RC_H
#define DTC_RC_H

//RC = Reform cluster
#include "knl_session.h"
#include "knl_context.h"
#include "mes_func.h"
#include "rc_reform.h"
#include "knl_archive.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DTC_REFORM_WAIT_TIME (5) //mill-seconds
#define DTC_REFORM_MES_CONNECT_TIMEOUT (90000) // mill-seconds
#define DTC_MAX_NODE_COUNT 4
#define DTC_REFORM_WAIT_ARCH_LOG (100)
#define DTC_REFORM_CREATE_ARCH_TMP_MAX_RETRY_TIMES 3
#define DTC_REFORM_CREATE_ARCH_TMP_WAIT_TIME_MS 3000

status_t init_dtc_rc(void);
void free_dtc_rc(void);


bool32 rc_instance_accessible(uint8 id);


// init deposit tx for instance in list
status_t rc_tx_area_init(instance_list_t *list);
status_t rc_undo_init(instance_list_t *list);
status_t rc_rollback_close(instance_list_t *list);

status_t rc_start_new_reform(reform_mode_t mode);
bool32 rc_finished(void);
void rc_stop_cur_reform(void);
status_t dtc_slave_load_my_undo(void);
status_t dtc_rollback_node(void);
status_t rc_master_clean_ddl_op(reform_detail_t *detail);
status_t rc_master_partial_recovery(reform_mode_t mode, reform_detail_t *detail);
status_t dtc_partial_recovery(instance_list_t *recover_list);
status_t rc_master_start_remaster(reform_detail_t *detail);
status_t rc_master_rollback_node(reform_detail_t *detail);
status_t rc_master_reform(reform_mode_t mode, reform_detail_t *detail);
status_t rc_master_wait_ckpt_finish(reform_mode_t mode);

//TODO: multi node
void rc_save_prcy_nodes_info(reform_rcy_node_t *rcy_node);
bool32 rc_reform_cancled(void);
status_t rc_start_lrpl_proc(knl_session_t *session);
status_t rc_notify_reform_status(knl_session_t *session, reform_info_t *rc_info, uint32 status);

// force arch redo log for offline node
status_t rc_arch_handle_tmp_file(arch_proc_context_t *proc_ctx, uint32 node_id);
status_t rc_arch_init_proc_ctx(arch_proc_context_t *proc_ctx, uint32 node_id);
status_t rc_arch_update_node_ctrl(uint32 node_id);
status_t rc_archive_log_offline_node(arch_proc_context_t *proc_ctx, uint32 node_id);
bool32 rc_need_archive_log(void);
status_t rc_archive_log(arch_proc_context_t *arch_proc_ctx);
void rc_end_archive_log(arch_proc_context_t *arch_proc_ctx);
status_t rc_wait_archive_log_finish(arch_proc_context_t *arch_proc_ctx);
status_t rc_tx_area_load(instance_list_t *list);

#ifdef __cplusplus
}
#endif


#endif
