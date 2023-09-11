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
 * cm_raft.c
 *
 *
 * IDENTIFICATION
 * src/common/cm_raft.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_raft.h"
#include "cm_error.h"
#include "cm_log.h"

#ifndef WIN32
#include "dlfcn.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifndef WIN32
static status_t raft_load_symbol(void *lib_handle, char *symbol, void **sym_lib_handle)
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

status_t raft_load_lib(raft_procs_t *procs)
{
    procs->lib_handle = dlopen("libconsistency.so", RTLD_LAZY);
    if (procs->lib_handle == NULL) {
        GS_THROW_ERROR(ERR_LOAD_LIBRARY, "libconsistency.so", cm_get_os_error());
        return GS_ERROR;
    }

    if (raft_load_symbol(procs->lib_handle, "InitConsistency", (void **)(&procs->init_consistency)) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (raft_load_symbol(procs->lib_handle, "QueryInfo", (void **)(&procs->query_info)) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (raft_load_symbol(procs->lib_handle, "AddMember", (void **)(&procs->add_member)) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (raft_load_symbol(procs->lib_handle, "DeleteMember", (void **)(&procs->delete_member)) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (raft_load_symbol(procs->lib_handle, "InitDBEngines", (void **)(&procs->init_db_engines)) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (raft_load_symbol(procs->lib_handle, "Register", (void **)(&procs->register_callback)) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (raft_load_symbol(procs->lib_handle, "SendMessage", (void **)(&procs->send_message)) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (raft_load_symbol(procs->lib_handle, "ExecWriteLogCmd", (void **)(&procs->exec_writelog_cmd)) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (raft_load_symbol(procs->lib_handle, "PromoteLeader", (void **)(&procs->promote_leader)) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (raft_load_symbol(procs->lib_handle, "StopConsistency", (void **)(&procs->stop_consistency)) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (raft_load_symbol(procs->lib_handle, "GetVersion", (void **)(&procs->get_version)) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (raft_load_symbol(procs->lib_handle, "SetParam", (void **)(&procs->set_param)) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (raft_load_symbol(procs->lib_handle, "Monitor", (void **)(&procs->monitor)) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

void raft_close_lib(raft_procs_t *procs)
{
    if (procs->lib_handle != NULL) {
        (void)dlclose(procs->lib_handle);
    }

    MEMS_RETVOID_IFERR(memset_sp(procs, sizeof(raft_procs_t), 0, sizeof(raft_procs_t)));
}

void raft_lib_check_loaded(raft_procs_t *procs)
{
    if (procs->lib_handle == NULL) {
        GS_THROW_ERROR(ERR_LOAD_LIBRARY, "libconsistency.so", cm_get_os_error());
        exit(-1);
    }
}

int64 raft_lib_init_consistency(raft_procs_t *procs, uint64 p0, char *p1, char *p2, char *p3, char *p4, void *p5,
                                int32 p6)
{
    raft_lib_check_loaded(procs);
    return procs->init_consistency(p0, p1, p2, p3, p4, p5, p6);
}

char *raft_lib_query_info(raft_procs_t *procs, char *type)
{
    raft_lib_check_loaded(procs);
    return procs->query_info(type);
}

int64 raft_lib_add_member(raft_procs_t *procs, uint64 p0, char *p1, uint64 p2, int64 p3)
{
    raft_lib_check_loaded(procs);
    return procs->add_member(p0, p1, p2, p3);
}

int64 raft_lib_delete_member(raft_procs_t *procs, uint64 p0, uint64 p1)
{
    raft_lib_check_loaded(procs);
    return procs->delete_member(p0, p1);
}

int64 raft_lib_initDBEngines(raft_procs_t *procs, int32 p0)
{
    raft_lib_check_loaded(procs);
    return procs->init_db_engines(p0);
}

int64 raft_lib_register(raft_procs_t *procs, char *p0, void *p1)
{
    raft_lib_check_loaded(procs);
    return procs->register_callback(p0, p1);
}

int64 raft_lib_sendmessage(raft_procs_t *procs, uint64 p0, void *p1, int32 p2)
{
    raft_lib_check_loaded(procs);
    return procs->send_message(p0, p1, p2);
}

int64 raft_lib_exec_writelog_cmd(raft_procs_t *procs, uint64 p0, void *p1, uint64 p2)
{
    return procs->exec_writelog_cmd(p0, p1, p2);
}

int64 raft_lib_promote_leader(raft_procs_t *procs, uint64 p0, uint64 p1)
{
    raft_lib_check_loaded(procs);
    return procs->promote_leader(p0, p1);
}

void raft_lib_stop_consistency(raft_procs_t *procs)
{
    raft_lib_check_loaded(procs);
    procs->stop_consistency();
}

char *raft_lib_get_version(raft_procs_t *procs)
{
    raft_lib_check_loaded(procs);
    return procs->get_version();
}

int32 raft_lib_set_param(raft_procs_t *procs, char *p0, void *p1)
{
    raft_lib_check_loaded(procs);
    return procs->set_param(p0, p1);
}

char *raft_lib_monitor(raft_procs_t *procs)
{
    raft_lib_check_loaded(procs);
    return procs->monitor();
}
#else
status_t raft_load_lib(raft_procs_t *procs)
{
    GS_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "raft");
    return GS_ERROR;
}

void raft_close_lib(raft_procs_t *procs)
{
    return;
}

void raft_lib_check_loaded(raft_procs_t *procs)
{
    return;
}

int64 raft_lib_init_consistency(raft_procs_t *procs, uint64 p0, char *p1, char *p2, char *p3, char *p4, void *p5,
                                int32 p6)
{
    return -1;
}

char *raft_lib_query_info(raft_procs_t *procs, char *type)
{
    return NULL;
}

int64 raft_lib_add_member(raft_procs_t *procs, uint64 p0, char *p1, uint64 p2, int64 p3)
{
    return -1;
}

int64 raft_lib_delete_member(raft_procs_t *procs, uint64 p0, uint64 p1)
{
    return -1;
}

int64 raft_lib_initDBEngines(raft_procs_t *procs, int32 p0)
{
    return -1;
}

int64 raft_lib_register(raft_procs_t *procs, char *p0, void *p1)
{
    return -1;
}

int64 raft_lib_sendmessage(raft_procs_t *procs, uint64 p0, void *p1, int32 p2)
{
    return -1;
}

int64 raft_lib_exec_writelog_cmd(raft_procs_t *procs, uint64 p0, void *p1, uint64 p2)
{
    return -1;
}

int64 raft_lib_promote_leader(raft_procs_t *procs, uint64 p0, uint64 p1)
{
    return -1;
}

void raft_lib_stop_consistency(raft_procs_t *procs)
{
    return;
}

char *raft_lib_get_version(raft_procs_t *procs)
{
    return NULL;
}

int32 raft_lib_set_param(raft_procs_t *procs, char *p0, void *p1)
{
    return -1;
}

char *raft_lib_monitor(raft_procs_t *procs)
{
    return NULL;
}
#endif

#ifdef __cplusplus
}
#endif
