/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2023. All rights reserved.
 * Description: Sockect interface of library rdmacm.
 * Author: mazhihong m00455966
 * Create: 2019-6-22
 */

#ifndef __CM_DBSTORE_H__
#define __CM_DBSTORE_H__

#include "cm_dbs_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

// libdbstoreClient.so
typedef int (*create_namespace_t)(char *, NameSpaceAttr *, NameSpaceId *);
typedef int (*open_namespace_t)(char *, NameSpaceAttr *, NameSpaceId *);
typedef int (*dbs_client_set_uuid_lsid_t)(const char *, uint32_t);
typedef int (*dbs_client_lib_init_t)(const char *);
typedef int (*set_term_access_mode_for_ns_t)(NameSpaceId *, TermAccessAttr *);
typedef int (*set_term_access_mode_for_ns_cms_t)(char *, TermAccessAttr *);
typedef int (*get_pagepool_logic_capacity_t)(PagePoolId *, PagePoolAttr *, uint64_t *);
typedef int (*create_pagepool_t)(char *, PagePoolAttr *, PagePoolId *);
typedef int (*open_pagepool_t)(char *, PagePoolAttr *, PagePoolId *);
typedef int (*destroy_pagepool_t)(char *, PagePoolAttr *);
typedef int (*close_pagepool_t)(PagePoolId *);
typedef int (*dbs_mget_page_t)(PagePoolId *, DbsPageId, uint32_t, DbsPageOption *, PageValue *);
typedef int (*dbs_mput_continue_pages_t)(PagePoolId *, DbsPageId, uint32_t, DbsPageOption *, PageValue *);
typedef int (*dbs_put_page_async_t)(PagePoolId *, DbsPageId, DbsPageOption *, PageValue *, uint32_t);
typedef int (*sync_page_by_part_index_t)(PagePoolId *, uint32_t);
typedef int (*expand_pagepool_logic_capacity_t)(PagePoolId *, PagePoolAttr *, uint64_t, uint64_t);
typedef int (*rename_pagepool_t)(char *, char *, PagePoolAttr *);
typedef int (*create_ulog_t)(char *, UlogAttr *, UlogId *);
typedef int (*destroy_ulog_t)(char *, UlogAttr *);
typedef int (*open_ulog_t)(char *, UlogAttr *, UlogId *);
typedef int (*get_ulog_used_cap_t)(UlogId *, UlogAttr *, LogLsn, uint32_t, uint32_t *);
typedef int (*get_ulog_init_capacity_t)(uint64_t *);
typedef int (*read_ulog_record_list_t)(UlogId *, ReadBatchLogOption *, LogRecordList *, ReadResult *);
typedef int (*append_ulog_record_t)(UlogId *, AppendOption *, LogRecord *, AppendResult *);
typedef int (*truncate_ulog_t)(UlogId *, TruncLogOption *, TruncResult*);
typedef int (*dbs_client_flush_log_t)(void);
// libdbstor_tool.so
typedef int32_t (*get_curr_log_offset_t)(char*, uint32_t, uint32_t*, uint32_t*, uint64_t*);
typedef int32_t (*get_correct_page_id_t)(uint32_t, uint32_t, uint32_t, uint64_t);

typedef struct st_dbs_interface {
    void *dbs_handle;
    void *dbs_tool_handle;
    create_namespace_t   create_namespace;
    open_namespace_t open_namespace;
    dbs_client_set_uuid_lsid_t dbs_client_set_uuid_lsid;
    dbs_client_lib_init_t dbs_client_lib_init;
    set_term_access_mode_for_ns_t set_term_access_mode_for_ns;
    set_term_access_mode_for_ns_cms_t set_term_access_mode_for_ns_cms;
    get_pagepool_logic_capacity_t get_pagepool_logic_capacity;
    create_pagepool_t create_pagepool;
    open_pagepool_t open_pagepool;
    destroy_pagepool_t destroy_pagepool;
    close_pagepool_t close_pagepool;
    dbs_mget_page_t dbs_mget_page;
    dbs_mput_continue_pages_t dbs_mput_continue_pages;
    dbs_put_page_async_t dbs_put_page_async;
    sync_page_by_part_index_t sync_page_by_part_index;
    expand_pagepool_logic_capacity_t expand_pagepool_logic_capacity;
    rename_pagepool_t rename_pagepool;
    create_ulog_t create_ulog;
    destroy_ulog_t destroy_ulog;
    open_ulog_t open_ulog;
    get_ulog_used_cap_t get_ulog_used_cap;
    get_ulog_init_capacity_t get_ulog_init_capacity;
    read_ulog_record_list_t read_ulog_record_list;
    append_ulog_record_t append_ulog_record;
    truncate_ulog_t truncate_ulog;
    dbs_client_flush_log_t dbs_client_flush_log;
    get_curr_log_offset_t get_curr_log_offset;
    get_correct_page_id_t get_correct_page_id;
} dbs_interface_t;

dbs_interface_t *dbs_global_handle(void);
status_t dbs_init_lib(void);
void dbs_close_lib(void);

#ifdef __cplusplus
}
#endif

#endif // __CM_DBSTORE_H__