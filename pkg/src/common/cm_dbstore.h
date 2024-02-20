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
 * cm_dbstore.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_dbstore.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __CM_DBSTORE_H__
#define __CM_DBSTORE_H__

#include "cm_dbs_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

// libdbstoreClient.so
// namespace
typedef int (*create_namespace_t)(char *, NameSpaceAttr *);
typedef int (*open_namespace_t)(char *, NameSpaceAttr *);
typedef int (*set_term_access_mode_for_ns_t)(char *, TermAccessAttr *);

// dbs
typedef int (*dbs_client_set_uuid_lsid_t)(const char *, uint32_t);
typedef int (*dbs_client_lib_init_t)(const char *);
typedef int (*dbs_client_flush_log_t)(void);
typedef int (*dbs_link_down_event_reg_t)(void (*dbs_link_down_exit)(void));
typedef int (*reg_role_info_callback_t)(regCallback);

//pagepool
typedef int (*create_pagepool_t)(char *, PagePoolAttr *, PagePoolId *);
typedef int (*destroy_pagepool_t)(char *, PagePoolAttr *);
typedef int (*open_pagepool_t)(char *, PagePoolAttr *, PagePoolId *);
typedef int (*close_pagepool_t)(PagePoolId *);
typedef int (*dbs_put_page_async_t)(PagePoolId *, DbsPageId, DbsPageOption *, PageValue *, uint32_t);
typedef int (*sync_page_by_part_index_t)(PagePoolId *, uint32_t);
typedef int (*dbs_mput_continue_pages_t)(PagePoolId *, DbsPageId, uint32_t, DbsPageOption *, PageValue *);
typedef int (*dbs_mget_page_t)(PagePoolId *, DbsPageId, uint32_t, DbsPageOption *, PageValue *);
typedef int (*get_pagepool_logic_capacity_t)(PagePoolId *, PagePoolAttr *, uint64_t *);
typedef int (*expand_pagepool_logic_capacity_t)(PagePoolId *, PagePoolAttr *, uint64_t, uint64_t);
typedef int (*rename_pagepool_t)(char *, char *, PagePoolAttr *);

// ulog
typedef int (*create_ulog_t)(char *, UlogAttr *, UlogId *);
typedef int (*destroy_ulog_t)(char *, UlogAttr *);
typedef int (*open_ulog_t)(char *, UlogAttr *, UlogId *);
typedef int (*append_ulog_record_t)(UlogId *, AppendOption *, LogRecord *, AppendResult *);
typedef int (*truncate_ulog_t)(UlogId *, TruncLogOption *, TruncResult*);
typedef int (*read_ulog_record_list_t)(UlogId *, ReadBatchLogOption *, LogRecordList *, ReadResult *);
typedef int (*get_ulog_used_cap_t)(UlogId *, UlogAttr *, LogLsn, uint32_t, uint32_t *);
typedef int (*get_ulog_init_capacity_t)(uint64_t *);

// libdbstor_tool.so
typedef int32_t (*get_curr_log_offset_t)(char*, uint32_t, uint32_t*, uint32_t*, uint64_t*);
typedef int32_t (*get_correct_page_id_t)(uint32_t, uint32_t, uint32_t, uint64_t);

typedef struct st_dbs_interface {
    void *dbs_handle;
    // namespace
    create_namespace_t   create_namespace;
    open_namespace_t open_namespace;
    set_term_access_mode_for_ns_t set_term_access_mode_for_ns;

    // dbs
    dbs_client_set_uuid_lsid_t dbs_client_set_uuid_lsid;
    dbs_client_lib_init_t dbs_client_lib_init;
    dbs_client_flush_log_t dbs_client_flush_log;
    reg_role_info_callback_t reg_role_info_callback;
    dbs_link_down_event_reg_t dbs_link_down_event_reg;

    // pagepool
    create_pagepool_t create_pagepool;
    destroy_pagepool_t destroy_pagepool;
    open_pagepool_t open_pagepool;
    close_pagepool_t close_pagepool;
    dbs_put_page_async_t dbs_put_page_async;
    sync_page_by_part_index_t sync_page_by_part_index;
    dbs_mput_continue_pages_t dbs_mput_continue_pages;
    dbs_mget_page_t dbs_mget_page;
    get_pagepool_logic_capacity_t get_pagepool_logic_capacity;
    expand_pagepool_logic_capacity_t expand_pagepool_logic_capacity;
    rename_pagepool_t rename_pagepool;

    // ulog
    create_ulog_t create_ulog;
    destroy_ulog_t destroy_ulog;
    open_ulog_t open_ulog;
    append_ulog_record_t append_ulog_record;
    truncate_ulog_t truncate_ulog;
    read_ulog_record_list_t read_ulog_record_list;
    get_ulog_used_cap_t get_ulog_used_cap;
    get_ulog_init_capacity_t get_ulog_init_capacity;
} dbs_interface_t;

typedef struct st_dbs_tool_interface {
    void *dbs_tool_handle;
    get_curr_log_offset_t get_curr_log_offset;
    get_correct_page_id_t get_correct_page_id;
} dbs_tool_interface_t;

dbs_interface_t *dbs_global_handle(void);
dbs_tool_interface_t *dbs_tool_global_handle(void);
status_t dbs_init_lib(void);
status_t dbs_tool_init_lib(void);
void dbs_close_lib(void);
void dbs_tool_close_lib(void);

#ifdef __cplusplus
}
#endif

#endif // __CM_DBSTORE_H__