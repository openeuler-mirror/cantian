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
 * cm_dbstore.c
 *
 *
 * IDENTIFICATION
 * src/common/cm_dbstore.c
 *
 * -------------------------------------------------------------------------
 */

#include <dlfcn.h>
#include "cm_log.h"
#include "cm_error.h"
#include "cm_dbstore.h"
#include "cm_dbs_module.h"

#ifdef __cplusplus
extern "C" {
#endif

static dbs_interface_t g_dbs_interface = { .dbs_handle = NULL, };
static dbs_tool_interface_t g_dbs_tool_interface = { .dbs_tool_handle = NULL };

dbs_interface_t *dbs_global_handle(void)
{
    return &g_dbs_interface;
}

dbs_tool_interface_t *dbs_tool_global_handle(void)
{
    return &g_dbs_tool_interface;
}

static status_t dbs_load_symbol(void *lib_handle, char *symbol, void **sym_lib_handle)
{
    const char *dlsym_err = NULL;

    *sym_lib_handle = dlsym(lib_handle, symbol);
    dlsym_err = dlerror();
    if (dlsym_err != NULL) {
        CT_THROW_ERROR(ERR_LOAD_SYMBOL, symbol, dlsym_err);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t dbs_init_lib(void)
{
    dbs_interface_t *intf = dbs_global_handle();
    intf->dbs_handle = dlopen("libdbstoreClient.so", RTLD_LAZY);
    const char *dlopen_err = NULL;
    dlopen_err = dlerror();
    if (intf->dbs_handle == NULL) {
        CT_LOG_RUN_WAR("failed to load libdbstoreClient.so, maybe lib path error, errno %s", dlopen_err);
        return CT_ERROR;
    }

    // namespace
    CT_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "CreateNameSpace",                (void **)(&intf->create_namespace)));
    CT_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "OpenNameSpace",                  (void **)(&intf->open_namespace)));
    CT_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "SetTermAccessModeForNs",         (void **)(&intf->set_term_access_mode_for_ns)));

    // dbs
    CT_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "DbsClientSetUuidLsid",           (void **)(&intf->dbs_client_set_uuid_lsid)));
    CT_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "DbsClientLibInit",               (void **)(&intf->dbs_client_lib_init)));
    CT_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "DbsClientFlushLog",              (void **)(&intf->dbs_client_flush_log)));
    CT_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "RegisterRoleInfoCallBack",       (void **)(&intf->reg_role_info_callback)));
    CT_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "DbsLinkDownEventReg",            (void **)(&intf->dbs_link_down_event_reg)));

    // pagepool
    CT_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "CreatePagePool",                 (void **)(&intf->create_pagepool)));
    CT_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "DestroyPagePool",                (void **)(&intf->destroy_pagepool)));
    CT_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "OpenPagePool",                   (void **)(&intf->open_pagepool)));
    CT_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "ClosePagePool",                  (void **)(&intf->close_pagepool)));
    CT_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "DbsPutPageAysnc",                (void **)(&intf->dbs_put_page_async)));
    CT_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "SyncPageByPartIndex",            (void **)(&intf->sync_page_by_part_index)));
    CT_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "DbsMputContinuePages",           (void **)(&intf->dbs_mput_continue_pages)));
    CT_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "DbsMGetPage",                    (void **)(&intf->dbs_mget_page)));
    CT_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "GetPagePoolLogicCapacity",       (void **)(&intf->get_pagepool_logic_capacity)));
    CT_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "ExpandPagePoolLogicCapacity",    (void **)(&intf->expand_pagepool_logic_capacity)));
    CT_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "RenamePagePool",                 (void **)(&intf->rename_pagepool)));

    // ulog
    CT_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "CreateUlog",                     (void **)(&intf->create_ulog)));
    CT_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "DestroyUlog",                    (void **)(&intf->destroy_ulog)));
    CT_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "OpenUlog",                       (void **)(&intf->open_ulog)));
    CT_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "AppendUlogRecord",               (void **)(&intf->append_ulog_record)));
    CT_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "TruncateUlog",                   (void **)(&intf->truncate_ulog)));
    CT_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "ReadUlogRecordList",             (void **)(&intf->read_ulog_record_list)));
    CT_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "GetUlogUsedCap",                 (void **)(&intf->get_ulog_used_cap)));
    CT_RETURN_IFERR(dbs_load_symbol(intf->dbs_handle, "GetUlogInitCapacity",            (void **)(&intf->get_ulog_init_capacity)));
    CT_LOG_RUN_INF("load libdbstoreClient.so done");

    return CT_SUCCESS;
}

status_t dbs_tool_init_lib(void)
{
    dbs_tool_interface_t *intf = dbs_tool_global_handle();
    intf->dbs_tool_handle = dlopen("libdbstor_tool.so", RTLD_LAZY);
    const char *dlopen_err = NULL;
    dlopen_err = dlerror();
    if (intf->dbs_tool_handle == NULL) {
        CT_LOG_RUN_WAR("failed to load libdbstor_tool.so, maybe lib path error, errno %s", dlopen_err);
        return CT_ERROR;
    }
    CT_RETURN_IFERR(dbs_load_symbol(intf->dbs_tool_handle, "get_curr_log_offset",       (void **)(&intf->get_curr_log_offset)));
    CT_RETURN_IFERR(dbs_load_symbol(intf->dbs_tool_handle, "get_correct_page_id",       (void **)(&intf->get_correct_page_id)));
    CT_LOG_RUN_INF("load libdbstor_tool.so done");

    return CT_SUCCESS;
}

void dbs_close_lib(void)
{
    dbs_interface_t *intf = dbs_global_handle();
    if (intf->dbs_handle != NULL) {
        (void)dlclose(intf->dbs_handle);
    }
}

void dbs_tool_close_lib(void)
{
    dbs_tool_interface_t *intf = dbs_tool_global_handle();
    if (intf->dbs_tool_handle != NULL) {
        (void)dlclose(intf->dbs_tool_handle);
    }
}

#ifdef __cplusplus
}
#endif