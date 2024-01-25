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
 * knl_db_ctrl.h
 *
 *
 * IDENTIFICATION
 * src/kernel/knl_db_ctrl.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_DB_CTRL_H__
#define __KNL_DB_CTRL_H__

#include "cm_defs.h"
#include "cm_latch.h"
#include "cm_utils.h"
#include "knl_log.h"
#include "knl_datafile.h"
#include "knl_interface.h"
#include "knl_session.h"
#include "knl_heap.h"
#include "knl_dc.h"
#include "knl_archive.h"
#include "knl_db_ctrl_persistent.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t db_generate_ctrlitems(knl_session_t *session);
status_t db_create_ctrl_file(knl_session_t *session);
status_t db_save_core_ctrl(knl_session_t *session);
status_t db_save_node_ctrl(knl_session_t *session);
status_t db_save_log_ctrl(knl_session_t *session, uint32 id, uint32 node_id);
status_t db_save_datafile_ctrl(knl_session_t *session, uint32 id);
status_t db_save_space_ctrl(knl_session_t *session, uint32 id);
status_t db_save_arch_ctrl(knl_session_t *session, uint32 id, uint32 node_id);
status_t db_load_logfiles(knl_session_t *session);
arch_ctrl_t *db_get_arch_ctrl(knl_session_t *session, uint32 id, uint32 node_id);
void db_init_logfile_ctrl(knl_session_t *session, uint32 *offset);
void db_init_space_ctrl(knl_session_t *session, uint32 *offset);
void db_init_datafile_ctrl(knl_session_t *session, uint32 *offset);
status_t db_load_ctrlspace(knl_session_t *session, text_t *files);
status_t db_check(knl_session_t *session, text_t *ctrlfiles, bool32 *is_found);
void db_update_sysdata_version(knl_session_t *session);
void rd_update_sysdata_version(knl_session_t *session, log_entry_t *log);
void print_update_sysdata_version(log_entry_t *log);
bool32 db_sysdata_version_is_equal(knl_session_t *session, bool32 is_upgrade);
uint32 dbc_generate_dbid(knl_session_t *session);
bool32 db_cur_ctrl_version_is_higher(knl_session_t *session, ctrl_version_t version);
bool32 db_equal_to_cur_ctrl_version(knl_session_t *session, ctrl_version_t version);

static inline char *db_get_ctrl_item(ctrl_page_t *pages, uint32 id, uint32 item_size, uint32 offset)
{
    uint32 count = CTRL_MAX_BUF_SIZE / item_size;
    uint32 page_id = offset + id / count;
    uint16 slot = id % count;
    ctrl_page_t *page = pages + page_id;

    return page->buf + slot * item_size;
}

static inline char *db_get_log_ctrl_item(ctrl_page_t *pages, uint32 id, uint32 item_size, uint32 offset, uint32 node_id)
{
    uint32 count = CTRL_MAX_BUF_SIZE / item_size;
    uint32 pages_per_inst = (CT_MAX_LOG_FILES - 1) / count + 1;
    uint32 page_id = offset + pages_per_inst * node_id + id / count;
    uint16 slot = id % count;
    ctrl_page_t *page = pages + page_id;
    return page->buf + slot * item_size;
}

static inline uint32 db_get_log_ctrl_pageid(uint32 id, uint32 offset, uint32 node_id)
{
    uint32 count = CTRL_MAX_BUF_SIZE / sizeof(log_file_ctrl_t);
    uint32 pages_per_inst = (CT_MAX_LOG_FILES - 1) / count + 1;
    uint32 page_id = offset + pages_per_inst * node_id + id / count;
    return page_id;
}

#ifdef __cplusplus
}
#endif

#endif

