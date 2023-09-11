/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2023. All rights reserved.
 * Description: Sockect interface of library rdmacm.
 * Author: mazhihong m00455966
 * Create: 2019-6-22
 */

#include <dlfcn.h>
#include "cm_log.h"
#include "cm_error.h"
#include "cm_dbstore.h"

#ifdef __cplusplus
extern "C" {
#endif

static dbs_interface_t g_dbs_interface = { .dbs_handle = NULL, .dbs_tool_handle = NULL };

dbs_interface_t *dbs_global_handle(void)
{
    return &g_dbs_interface;
}

static status_t dbs_load_symbol(void *lib_handle, char *symbol, void **sym_lib_handle)
{
    const char *dlsym_err = NULL;

    *sym_lib_handle = dlsym(lib_handle, symbol);
    dlsym_err = dlerror();
    if (dlsym_err != NULL) {
        GS_THROW_ERROR(ERR_LOAD_SYMBOL, symbol, dlsym_err);
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

status_t dbs_init_lib(void)
{
    dbs_interface_t *intf = dbs_global_handle();
    intf->dbs_handle = dlopen("libdbstoreClient.so", RTLD_LAZY);
    const char *dlopen_err = NULL;
    dlopen_err = dlerror();
    if (intf->dbs_handle == NULL) {
        GS_LOG_RUN_WAR("failed to load libdbstoreClient.so, maybe lib path error , errno %s", dlopen_err);
        return GS_ERROR;
    }

    GS_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "CreateNameSpace",                (void **)(&intf->create_namespace)));
    GS_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "OpenNameSpace",                  (void **)(&intf->open_namespace)));
    GS_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "DbsClientSetUuidLsid",           (void **)(&intf->dbs_client_set_uuid_lsid)));
    GS_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "DbsClientLibInit",               (void **)(&intf->dbs_client_lib_init)));
    GS_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "SetTermAccessModeForNs",         (void **)(&intf->set_term_access_mode_for_ns)));
    GS_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "SetTermAccessModeForNsCms",      (void **)(&intf->set_term_access_mode_for_ns_cms)));
    GS_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "GetPagePoolLogicCapacity",       (void **)(&intf->get_pagepool_logic_capacity)));
    GS_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "CreatePagePool",                 (void **)(&intf->create_pagepool)));
    GS_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "OpenPagePool",                   (void **)(&intf->open_pagepool)));
    GS_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "DestroyPagePool",                (void **)(&intf->destroy_pagepool)));
    GS_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "ClosePagePool",                  (void **)(&intf->close_pagepool)));
    GS_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "DbsMGetPage",                    (void **)(&intf->dbs_mget_page)));
    GS_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "DbsMputContinuePages",           (void **)(&intf->dbs_mput_continue_pages)));
    GS_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "DbsPutPageAysnc",                (void **)(&intf->dbs_put_page_async)));
    GS_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "SyncPageByPartIndex",            (void **)(&intf->sync_page_by_part_index)));
    GS_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "ExpandPagePoolLogicCapacity",    (void **)(&intf->expand_pagepool_logic_capacity)));
    GS_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "RenamePagePool",                 (void **)(&intf->rename_pagepool)));
    GS_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "CreateUlog",                     (void **)(&intf->create_ulog)));
    GS_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "DestroyUlog",                    (void **)(&intf->destroy_ulog)));
    GS_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "OpenUlog",                       (void **)(&intf->open_ulog)));
    GS_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "GetUlogUsedCap",                 (void **)(&intf->get_ulog_used_cap)));
    GS_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "GetUlogInitCapacity",            (void **)(&intf->get_ulog_init_capacity)));
    GS_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "ReadUlogRecordList",             (void **)(&intf->read_ulog_record_list)));
    GS_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "AppendUlogRecord",               (void **)(&intf->append_ulog_record)));
    GS_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "TruncateUlog",                   (void **)(&intf->truncate_ulog)));
    GS_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "DbsClientFlushLog",              (void **)(&intf->dbs_client_flush_log)));
    GS_LOG_RUN_INF("load libdbstoreClient.so done");

    intf->dbs_tool_handle = dlopen("libdbstor_tool.so", RTLD_LAZY);
    if (intf->dbs_tool_handle == NULL) {
        GS_LOG_RUN_WAR("failed to load libdbstor_tool.so, maybe lib path error");
        return GS_ERROR;
    }
    GS_RETURN_IFERR(dbs_load_symbol(intf->dbs_tool_handle, "get_curr_log_offset",       (void **)(&intf->get_curr_log_offset)));
    GS_RETURN_IFERR(dbs_load_symbol(intf->dbs_tool_handle, "get_correct_page_id",       (void **)(&intf->get_correct_page_id)));
    GS_LOG_RUN_INF("load libdbstor_tool.so done");

    return GS_SUCCESS;
}

void dbs_close_lib(void)
{
    dbs_interface_t *intf = dbs_global_handle();
    if (intf->dbs_handle != NULL) {
        (void)dlclose(intf->dbs_handle);
    }
    if (intf->dbs_tool_handle != NULL) {
        (void)dlclose(intf->dbs_tool_handle);
    }
}

#ifdef __cplusplus
}
#endif
