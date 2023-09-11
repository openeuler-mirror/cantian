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
 * cm_rdma.c
 *
 *
 * IDENTIFICATION
 * src/common/cm_rdma.c
 *
 * -------------------------------------------------------------------------
 */

#include "cm_rdma.h"
#include "cm_log.h"
#include "cm_error.h"
#ifndef WIN32
#include <dlfcn.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifndef WIN32

static rdma_socket_procs_t g_rdma_lib_handle = { .rdma_useble = GS_FALSE, .rdma_handle = NULL };

rdma_socket_procs_t *rdma_global_handle(void)
{
    return &g_rdma_lib_handle;
}

static status_t rdma_load_symbol(void *lib_handle, char *symbol, void **sym_lib_handle)
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

status_t rdma_init_lib(void)
{
    rdma_socket_procs_t *procs = rdma_global_handle();
    procs->rdma_handle = dlopen("librdmacm.so", RTLD_LAZY);
    if (procs->rdma_handle == NULL) {
        GS_LOG_RUN_WAR("failed to load librdmacm.so, maybe no rdma driver, or lib path error");
        return GS_ERROR;
    }

    GS_RETURN_IFERR(rdma_load_symbol(procs->rdma_handle, "rsocket",      (void **)(&procs->socket)));
    GS_RETURN_IFERR(rdma_load_symbol(procs->rdma_handle, "rbind",        (void **)(&procs->bind)));
    GS_RETURN_IFERR(rdma_load_symbol(procs->rdma_handle, "rlisten",      (void **)(&procs->listen)));
    GS_RETURN_IFERR(rdma_load_symbol(procs->rdma_handle, "raccept",      (void **)(&procs->accept)));
    GS_RETURN_IFERR(rdma_load_symbol(procs->rdma_handle, "rconnect",     (void **)(&procs->connect)));
    GS_RETURN_IFERR(rdma_load_symbol(procs->rdma_handle, "rshutdown",    (void **)(&procs->shutdown)));
    GS_RETURN_IFERR(rdma_load_symbol(procs->rdma_handle, "rclose",       (void **)(&procs->close)));

    GS_RETURN_IFERR(rdma_load_symbol(procs->rdma_handle, "rrecv",        (void **)(&procs->recv)));
    GS_RETURN_IFERR(rdma_load_symbol(procs->rdma_handle, "rrecvfrom",    (void **)(&procs->recvfrom)));
    GS_RETURN_IFERR(rdma_load_symbol(procs->rdma_handle, "rrecvmsg",     (void **)(&procs->recvmsg)));
    GS_RETURN_IFERR(rdma_load_symbol(procs->rdma_handle, "rsend",        (void **)(&procs->send)));
    GS_RETURN_IFERR(rdma_load_symbol(procs->rdma_handle, "rsendto",      (void **)(&procs->sendto)));
    GS_RETURN_IFERR(rdma_load_symbol(procs->rdma_handle, "rsendmsg",     (void **)(&procs->sendmsg)));

    GS_RETURN_IFERR(rdma_load_symbol(procs->rdma_handle, "rread",        (void **)(&procs->read)));
    GS_RETURN_IFERR(rdma_load_symbol(procs->rdma_handle, "rreadv",       (void **)(&procs->readv)));
    GS_RETURN_IFERR(rdma_load_symbol(procs->rdma_handle, "rwrite",       (void **)(&procs->write)));
    GS_RETURN_IFERR(rdma_load_symbol(procs->rdma_handle, "rwritev",      (void **)(&procs->writev)));

    GS_RETURN_IFERR(rdma_load_symbol(procs->rdma_handle, "rpoll",        (void **)(&procs->poll)));
    GS_RETURN_IFERR(rdma_load_symbol(procs->rdma_handle, "rselect",      (void **)(&procs->select)));
    GS_RETURN_IFERR(rdma_load_symbol(procs->rdma_handle, "rgetpeername", (void **)(&procs->getpeername)));
    GS_RETURN_IFERR(rdma_load_symbol(procs->rdma_handle, "rgetsockname", (void **)(&procs->getsockname)));
    GS_RETURN_IFERR(rdma_load_symbol(procs->rdma_handle, "rsetsockopt",  (void **)(&procs->setsockopt)));
    GS_RETURN_IFERR(rdma_load_symbol(procs->rdma_handle, "rgetsockopt",  (void **)(&procs->getsockopt)));
    GS_RETURN_IFERR(rdma_load_symbol(procs->rdma_handle, "rfcntl",       (void **)(&procs->fcntl)));

    GS_RETURN_IFERR(rdma_load_symbol(procs->rdma_handle, "riomap",       (void **)(&procs->iomap)));
    GS_RETURN_IFERR(rdma_load_symbol(procs->rdma_handle, "riounmap",     (void **)(&procs->iounmap)));
    GS_RETURN_IFERR(rdma_load_symbol(procs->rdma_handle, "riowrite",     (void **)(&procs->iowrite)));

    procs->rdma_useble = GS_TRUE;
    GS_LOG_RUN_INF("load librdmacm.so done");

    return GS_SUCCESS;
}

void rdma_close_lib(void)
{
    rdma_socket_procs_t *rdma_procs = rdma_global_handle();
    if (rdma_is_inited(rdma_procs)) {
        (void)dlclose(rdma_procs->rdma_handle);
        MEMS_RETVOID_IFERR(memset_s(rdma_procs, sizeof(rdma_socket_procs_t), 0, sizeof(rdma_socket_procs_t)));
    }
}

#else

status_t rdma_init_lib()
{
    return GS_SUCCESS;
}

void rdma_close_lib()
{
    return;
}

#endif      // win32

#ifdef __cplusplus
}
#endif
