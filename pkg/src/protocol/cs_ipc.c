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
 * cs_ipc.c
 *
 *
 * IDENTIFICATION
 * src/protocol/cs_ipc.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_base.h"
#include "cm_system.h"
#include "cs_ipc.h"
#include "cs_pipe.h"
#include "cm_hash.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef WIN32
char *g_sem_prefix = "gsipc_sem";
uint32 g_sem_id = 0;
char *g_shm_prefix = "gsipc_shm";
uint32 g_shm_id = 0;
#endif


spinlock_t g_ipc_lock = 0;
ipc_context_t g_ipc_context = {0};

static status_t cs_get_ipc_link_id(uint32 *id)
{
    uint32 i;
    CM_POINTER(id);

    for (i = 0; i < g_ipc_context.links.count; i++) {
        if (cm_list_get(&g_ipc_context.links, i) == NULL) {
            *id = i;
            return CT_SUCCESS;
        }
    }

    *id = g_ipc_context.links.count;

    if (cm_list_new(&g_ipc_context.links, NULL) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t cs_add_ipc_link(ipc_link_t *link)
{
    CM_POINTER(link);

    cm_spin_lock(&g_ipc_context.lock, NULL);

    if (cs_get_ipc_link_id(&link->id) != CT_SUCCESS) {
        cm_spin_unlock(&g_ipc_context.lock);
        return CT_ERROR;
    }

    cm_list_set(&g_ipc_context.links, link->id, link);
    g_ipc_context.link_count++;
    cm_spin_unlock(&g_ipc_context.lock);
    return CT_SUCCESS;
}

void cs_remove_ipc_link(ipc_link_t *link)
{
    CM_POINTER(link);
    cm_spin_lock(&g_ipc_context.lock, NULL);
    cm_list_set(&g_ipc_context.links, link->id, NULL);
    g_ipc_context.link_count--;
    cm_spin_unlock(&g_ipc_context.lock);

    link->id = CT_INVALID_ID32;
}

static uint64 g_client_pid = 0;

status_t cs_request_ipc_lsnr(ipc_lsnr_request_t *req, ipc_token_t *token)
{
    ipc_lsnr_ctrl_t *ctrl = NULL;
    uint32 wait_time = 0;
    errno_t errcode;

    CM_POINTER2(req, token);

    ctrl = g_ipc_context.lsnr_ctrl;

    if (g_ipc_context.server_pid == 0 || !ctrl->ready) {
        CT_THROW_ERROR(ERR_IPC_LSNR_CLOSED);
        return CT_ERROR;
    }

    if (g_client_pid == 0) {
        g_client_pid = cm_sys_pid();
    }

    req->client_info.start_time = g_ipc_context.start_time;

    /* the server will reset the lock force if the client is not exists */
    if (!cm_spin_timed_lock(&ctrl->lock, CT_CONNECT_TIMEOUT)) {
        CT_THROW_ERROR(ERR_IPC_CONNECT_ERROR, "listener busy");
        return CT_ERROR;
    }

    ctrl->request = *req;
    ctrl->lock_ticks = ctrl->server_ticks;

    cs_sem_v(&ctrl->lsnr_sem, IPC_SIDE_CLIENT);

    while (!cs_sem_timed_p(&ctrl->ntfy_sem, IPC_SIDE_CLIENT, IPC_NOTIFY_TIMEOUT)) {
        wait_time += IPC_NOTIFY_TIMEOUT;

        /* if the server downs, return error, otherwise continue wait */
        if (!cm_sys_process_alived(!g_ipc_context.server_pid, !g_ipc_context.start_time)) {
            cm_spin_unlock(&ctrl->lock);
            g_ipc_context.server_pid = 0;
            CT_THROW_ERROR(ERR_IPC_LSNR_CLOSED);
            return CT_ERROR;
        }

        if (wait_time < CT_CONNECT_TIMEOUT) {
            continue;
        } else {
            cm_spin_unlock(&ctrl->lock);
            CT_THROW_ERROR(ERR_IPC_CONNECT_ERROR, "listener no response");
            return CT_ERROR;
        }
    }

    errcode = memcpy_s(token, sizeof(ipc_token_t), &ctrl->token, sizeof(ipc_token_t));
    MEMS_RETURN_IFERR(errcode);
    cm_spin_unlock(&ctrl->lock);

    if (token->code != 0) {
        CT_THROW_ERROR(ERR_IPC_CONNECT_ERROR, token->message);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

void cs_close_ipc_context()
{
    uint32 i, busy_count, try_times;
    ipc_link_t *link = NULL;
    cs_packet_head_t *pack_head = NULL;
    ipc_token_t token;
    ipc_lsnr_request_t req;

    cm_spin_lock(&g_ipc_context.lock, NULL);

    if (!g_ipc_context.initialized) {
        cm_spin_unlock(&g_ipc_context.lock);
        return;
    }

    for (i = 0; i < g_ipc_context.links.count; i++) {
        link = (ipc_link_t *)cm_list_get(&g_ipc_context.links, i);
        link->status = IPC_STATUS_CLOSED;
        pack_head = (cs_packet_head_t *)link->room->buf;
        pack_head->cmd = 0;
        pack_head->flags |= CS_FLAG_PEER_CLOSED;
        pack_head->result = 1;
        pack_head->size = sizeof(cs_packet_head_t);
        cs_sem_v(&link->room->client_sem, IPC_SIDE_CLIENT);
    }

    req.cmd = IPC_LSNR_UNREG_APP;
    req.app_id = g_ipc_context.app_id;
    (void)cs_request_ipc_lsnr(&req, &token);
    cs_detach_sem(&g_ipc_context.lsnr_ctrl->lsnr_sem, IPC_SIDE_CLIENT);
    cs_detach_sem(&g_ipc_context.lsnr_ctrl->ntfy_sem, IPC_SIDE_CLIENT);

    g_ipc_context.server_pid = 0;
    g_ipc_context.initialized = CT_FALSE;
    cm_spin_unlock(&g_ipc_context.lock);

    for (try_times = 0; try_times < 3; try_times++) {
        busy_count = 0;
        cm_spin_lock(&g_ipc_context.lock, NULL);
        for (i = 0; i < g_ipc_context.links.count; i++) {
            link = (ipc_link_t *)cm_list_get(&g_ipc_context.links, i);
            if (link->status == IPC_STATUS_BUSY) {
                busy_count++;
            }
        }

        cm_spin_unlock(&g_ipc_context.lock);

        if (busy_count == 0) {
            break;
        }

        cm_sleep(3000);
    }
}

status_t cs_ipc_heart_beat(bool32 is_reset)
{
    uint32 diff;
    static uint32 local_ticks = 0;
    static uint32 last_peer_ticks = 0;

    cm_spin_lock(&g_ipc_context.lock, NULL);

    if (!g_ipc_context.initialized) {
        cm_spin_unlock(&g_ipc_context.lock);
        CT_THROW_ERROR(ERR_IPC_UNINITIALIZED);
        return CT_ERROR;
    }

    if (is_reset) {
        last_peer_ticks = g_ipc_context.lsnr_ctrl->server_ticks;
        local_ticks = 0;
        cm_spin_unlock(&g_ipc_context.lock);
        return CT_SUCCESS;
    }

    g_ipc_context.app->curr_ticks++;

    local_ticks++;
    if (local_ticks < IPC_CHECK_TICKS) {
        cm_spin_unlock(&g_ipc_context.lock);
        return CT_SUCCESS;
    }

    local_ticks = 0;

    diff = g_ipc_context.lsnr_ctrl->server_ticks - last_peer_ticks;

    if (diff < IPC_EXPECTED_PEER_TICKS) {
        if (!cm_sys_process_alived(g_ipc_context.server_pid, g_ipc_context.start_time)) {
            cm_spin_unlock(&g_ipc_context.lock);
            CT_THROW_ERROR(ERR_IPC_PROCESS_NOT_EXISTS);
            return CT_ERROR;
        }
    }

    last_peer_ticks = g_ipc_context.lsnr_ctrl->server_ticks;

    cm_spin_unlock(&g_ipc_context.lock);
    return CT_SUCCESS;
}

status_t cs_wait_server_ready(void)
{
    int32 count = 0;
    while (!g_ipc_context.lsnr_ctrl->ready) {
        if (count >= 300) {
            /* the server start timeout(3s), or the shm block is invalid */
            cs_detach_shm(&g_ipc_context.lsnr_shm);
            CT_THROW_ERROR(ERR_IPC_STARTUP);
            return CT_ERROR;
        }

        cm_sleep(10);
        count++;
    }
    return CT_SUCCESS;
}

void cs_detach_memory(void)
{
    cs_detach_sem(&g_ipc_context.lsnr_ctrl->lsnr_sem, IPC_SIDE_CLIENT);
    cs_detach_sem(&g_ipc_context.lsnr_ctrl->ntfy_sem, IPC_SIDE_CLIENT);
    cs_detach_shm(&g_ipc_context.lsnr_shm);
    cm_destroy_list(&g_ipc_context.links);
}

status_t cs_init_ipc_context(const char *ipc_name)
{
    int32 code;
    ipc_token_t token;
    ipc_lsnr_request_t req;
    errno_t errcode;

    if (g_ipc_context.initialized) {
        return CT_SUCCESS;
    }

    if (cs_attach_shm(&g_ipc_context.lsnr_shm, ipc_name) != CT_SUCCESS) {
        return CT_ERROR;
    }

    g_ipc_context.lsnr_ctrl = (ipc_lsnr_ctrl_t *)g_ipc_context.lsnr_shm.addr;
   
    if (cs_wait_server_ready() != CT_SUCCESS) {
        return CT_ERROR;
    }

    /* check whether the server is ok, maybe has been killed */
    g_ipc_context.server_pid = g_ipc_context.lsnr_ctrl->server_info.pid;
    if (!cm_sys_process_alived(g_ipc_context.server_pid, g_ipc_context.start_time)) {
        cs_detach_shm(&g_ipc_context.lsnr_shm);
        CT_THROW_ERROR(ERR_IPC_PROCESS_NOT_EXISTS);
        return CT_ERROR;
    }

    if (cs_attach_sem(&g_ipc_context.lsnr_ctrl->lsnr_sem, IPC_SIDE_CLIENT) != CT_SUCCESS) {
        cs_detach_shm(&g_ipc_context.lsnr_shm);
        return CT_ERROR;
    }

    if (cs_attach_sem(&g_ipc_context.lsnr_ctrl->ntfy_sem, IPC_SIDE_CLIENT) != CT_SUCCESS) {
        cs_detach_sem(&g_ipc_context.lsnr_ctrl->lsnr_sem, IPC_SIDE_CLIENT);
        cs_detach_shm(&g_ipc_context.lsnr_shm);
        return CT_ERROR;
    }

    cm_create_list(&g_ipc_context.links, sizeof(ipc_link_t));

    req.cmd = IPC_LSNR_REG_APP;
    req.app_id = CT_INVALID_ID32;
    req.client_info.pid = cm_sys_pid();
    errcode = strncpy_s(req.client_info.name, CT_FILE_NAME_BUFFER_SIZE, "IPC client", strlen("IPC client"));
    if (errcode != EOK) {
        cs_detach_memory();
        CT_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
        return CT_ERROR;
    }

    g_ipc_context.start_time = cm_sys_process_start_time(req.client_info.pid);

    code = cs_request_ipc_lsnr(&req, &token);
    if (code != CT_SUCCESS) {
        cs_detach_memory();
        return code;
    }

    g_ipc_context.app_id = token.room_id;
    g_ipc_context.app = (ipc_app_t *)(g_ipc_context.lsnr_shm.addr + token.offset);
    g_ipc_context.initialized = CT_TRUE;
    return CT_SUCCESS;
}

void cs_try_release_ipc_context(bool32 init_flag)
{
    ipc_lsnr_request_t req;
    ipc_token_t token;

    if (!g_ipc_context.initialized || !init_flag) {
        return;
    }

    req.cmd = IPC_LSNR_UNREG_APP;
    req.app_id = g_ipc_context.app_id;
    (void)cs_request_ipc_lsnr(&req, &token);
    cs_detach_sem(&g_ipc_context.lsnr_ctrl->lsnr_sem, IPC_SIDE_CLIENT);
    cs_detach_sem(&g_ipc_context.lsnr_ctrl->ntfy_sem, IPC_SIDE_CLIENT);

    g_ipc_context.server_pid = 0;
    g_ipc_context.initialized = CT_FALSE;
}

status_t cs_wait_for_ipc_ready(ipc_link_t *link)
{
    int32 count = 0;
    CM_POINTER2(link, link->room);

    while (link->room->status != IPC_STATUS_BUSY) {
        /* the server abnormal, maybe it shutdown, switch mode, or been killed, and so on */
        if (!cm_sys_process_alived(g_ipc_context.server_pid, g_ipc_context.start_time)) {
            CT_THROW_ERROR(ERR_IPC_PROCESS_NOT_EXISTS);
            return CT_ERROR;
        }

        /* the service thread alloc session failed, and the pipe room is release */
        if (link->room->status == IPC_STATUS_CLOSED) {
            CT_THROW_ERROR(ERR_PEER_CLOSED, "IPC");
            return CT_ERROR;
        }

        cm_sleep(10);
        count++;
        if (count == 300) {
            /* connect to server timeout(3s) */
            CT_THROW_ERROR(ERR_TCP_TIMEOUT, "connect to server");
            return CT_ERROR;
        }
    }

    /* the link is valid, but the link already alloc to another connection */
    if (link->room->gpid != link->gpid) {
        CT_THROW_ERROR(ERR_PEER_CLOSED, "IPC");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t cs_ipc_connect(ipc_link_t *link, const char *ipc_name)
{
    ipc_token_t token;
    ipc_lsnr_request_t req;
    bool32 init_flag = CT_FALSE;

    CM_POINTER(link);

    cm_spin_lock(&g_ipc_context.lock, NULL);

    if (!g_ipc_context.initialized) {
        if (cs_init_ipc_context(ipc_name) != CT_SUCCESS) {
            cm_spin_unlock(&g_ipc_context.lock);
            return CT_ERROR;
        }

        init_flag = CT_TRUE;
    }

    cm_spin_unlock(&g_ipc_context.lock);

    req.cmd = IPC_LSNR_ALLOC_LINK;
    req.app_id = g_ipc_context.app_id;

    if (cs_request_ipc_lsnr(&req, &token) != CT_SUCCESS) {
        cs_try_release_ipc_context(init_flag);
        return CT_ERROR;
    }

    /* maybe alloc pipe failed in the server side */
    if (token.code != 0) {
        cs_try_release_ipc_context(init_flag);
        return CT_ERROR;
    }

    link->room = (ipc_room_t *)(g_ipc_context.lsnr_shm.addr + token.offset);
    link->gpid = token.gpid;
    link->side = IPC_SIDE_CLIENT;
    link->status = IPC_STATUS_IDLE;

    if (cs_wait_for_ipc_ready(link) != CT_SUCCESS) {
        cs_try_release_ipc_context(init_flag);
        return CT_ERROR;
    }

    if (cs_attach_sem(&link->room->client_sem, IPC_SIDE_CLIENT) != CT_SUCCESS) {
        cs_try_release_ipc_context(init_flag);
        return CT_ERROR;
    }

    if (cs_attach_sem(&link->room->server_sem, IPC_SIDE_CLIENT) != CT_SUCCESS) {
        cs_try_release_ipc_context(init_flag);
        return CT_ERROR;
    }

    if (CT_SUCCESS != cs_add_ipc_link(link)) {
        cs_try_release_ipc_context(init_flag);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t cs_ipc_p_for_read_pack_server(ipc_link_t *link)
{
    for (;;) {
        if (cs_sem_timed_p(&link->room->server_sem, IPC_SIDE_SERVER, IPC_NOTIFY_TIMEOUT)) {
            break;
        }

        if (link->room->is_timeout || link->room->gpid != link->gpid || link->room->status == IPC_STATUS_CLOSED) {
            CT_THROW_ERROR(ERR_PEER_CLOSED, "IPC");
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static status_t cs_ipc_p_for_read_pack_client(ipc_link_t *link)
{
    if (!g_ipc_context.server_pid) {
        CT_THROW_ERROR(ERR_PEER_CLOSED, "IPC");
        return CT_ERROR;
    }

    for (;;) {
        if (link->room->gpid != link->gpid || link->room->status == IPC_STATUS_CLOSED) {
            link->status = IPC_STATUS_CLOSED;
            return CT_ERROR;
        }

        if (cs_sem_timed_p(&link->room->client_sem, IPC_SIDE_CLIENT, IPC_NOTIFY_TIMEOUT)) {
            break;
        }

        if (!cm_sys_process_alived(g_ipc_context.server_pid, g_ipc_context.start_time)) {
            g_ipc_context.server_pid = 0;
            link->status = IPC_STATUS_CLOSED;
            CT_THROW_ERROR(ERR_PEER_CLOSED, "IPC");
            return CT_ERROR;
        }
    }

    if (link->room->is_timeout || link->room->status == IPC_STATUS_CLOSED) {
        /* change status to be closed */
        link->status = IPC_STATUS_CLOSED;
        CT_THROW_ERROR(ERR_PEER_CLOSED, "IPC");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t cs_ipc_p_for_read_pack(ipc_link_t *link)
{
    CM_POINTER(link);

    if (link->side == IPC_SIDE_SERVER) {
        return cs_ipc_p_for_read_pack_server(link);
    } else {
        return cs_ipc_p_for_read_pack_client(link);
    }
}

status_t cs_ipc_read_pack(ipc_link_t *link, cs_packet_t *pack, uint32 timeout)
{
    cs_packet_head_t *pack_head = NULL;
    CM_POINTER2(link, pack);
    CM_POINTER(link->room);

    if (link->status == IPC_STATUS_CLOSED || link->room->gpid != link->gpid) {
        CT_THROW_ERROR(ERR_PEER_CLOSED, "IPC");
        return CT_ERROR;
    }

    if (CT_SUCCESS != cs_ipc_p_for_read_pack(link)) {
        return CT_ERROR;
    }

    pack_head = (cs_packet_head_t *)link->room->buf;

    if ((pack_head->flags & CS_FLAG_PEER_CLOSED) != 0) {
        CT_THROW_ERROR(ERR_PEER_CLOSED, "IPC");
        return CT_ERROR;
    }
    if (pack_head->size != 0) {
        MEMS_RETURN_IFERR(memcpy_s(pack->buf, CT_MAX_PACKET_SIZE, link->room->buf, pack_head->size));
    }
    return CT_SUCCESS;
}

status_t cs_ipc_write_pack(ipc_link_t *link, cs_packet_t *pack, uint32 timeout)
{
    CM_POINTER3(link, link->room, pack);

    if (link->status == IPC_STATUS_CLOSED || link->room->gpid != link->gpid) {
        CT_THROW_ERROR(ERR_PEER_CLOSED, "IPC");
        return CT_ERROR;
    }
    if (pack->head->size != 0) {
        MEMS_RETURN_IFERR(memcpy_s(link->room->buf, CT_MAX_PACKET_SIZE, pack->buf, pack->head->size));
    }

    if (link->side == IPC_SIDE_SERVER) {
        cs_sem_v(&link->room->client_sem, IPC_SIDE_SERVER);
    } else {
        cs_sem_v(&link->room->server_sem, IPC_SIDE_CLIENT);
    }

    return CT_SUCCESS;
}

void cs_ipc_close_notify(ipc_link_t *link)
{
    cs_packet_head_t *pack_head = NULL;
    CM_POINTER2(link, link->room);

    pack_head = (cs_packet_head_t *)link->room->buf;
    pack_head->cmd = 0;
    pack_head->size = sizeof(cs_packet_head_t);
    pack_head->flags = CS_FLAG_PEER_CLOSED;

    if (link->side == IPC_SIDE_SERVER) {
        cs_sem_v(&link->room->client_sem, IPC_SIDE_SERVER);
    } else {
        cs_sem_v(&link->room->server_sem, IPC_SIDE_CLIENT);
    }
}

void cs_ipc_disconnect(ipc_link_t *link)
{
    CM_POINTER(link);
    if (link->status == IPC_STATUS_CLOSED) {
        return;
    }

    link->status = IPC_STATUS_CLOSED;

    if (link->room->gpid == link->gpid && link->side == IPC_SIDE_CLIENT) {
        cs_ipc_close_notify(link);
        CM_POINTER(link->room);
        cs_detach_sem(&link->room->client_sem, IPC_SIDE_CLIENT);
        cs_detach_sem(&link->room->server_sem, IPC_SIDE_CLIENT);
    }

    cs_remove_ipc_link(link);
}

status_t cs_create_sem(ipc_sem_t *sem, ipc_side_t side)
{
#ifdef WIN32
    char sem_name[CT_MAX_NAME_LEN];
    uint32 sem_id;

    CM_POINTER(sem);

    cm_spin_lock(&g_ipc_lock, NULL);
    sem_id = g_sem_id;
    g_sem_id++;
    cm_spin_unlock(&g_ipc_lock);

    PRTS_RETURN_IFERR(snprintf_s(sem_name, sizeof(sem_name), sizeof(sem_name) - 1, "%s_%u", g_sem_prefix, sem_id));
    sem->handles[side] = CreateSemaphore(NULL, 0, 1, sem_name);
    if (sem->handles[side] == INVALID_HANDLE_VALUE) {
        sem->id = CT_INVALID_ID32;
        CT_THROW_ERROR(ERR_CREATE_SEMAPORE);
        return CT_ERROR;
    } else {
        sem->id = sem_id;
        return CT_SUCCESS;
    }
#else
    pthread_mutexattr_t attr;

    (void)side;
    CM_POINTER(sem);

    (void)pthread_mutexattr_init(&attr);
    (void)pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);

    if (0 != pthread_mutex_init(&sem->mutex, &attr)) {
        CT_THROW_ERROR(ERR_CREATE_SEMAPORE);
        (void)pthread_mutexattr_destroy(&attr);
        return CT_ERROR;
    }

    (void)pthread_mutex_lock(&sem->mutex);
    (void)pthread_mutexattr_destroy(&attr);
    return CT_SUCCESS;
#endif
}

void cs_destroy_sem(ipc_sem_t *sem, ipc_side_t side)
{
    CM_POINTER(sem);
#ifdef WIN32
    CloseHandle(sem->handles[side]);
    sem->id = CT_INVALID_ID32;
#else
    (void)side;

    (void)pthread_mutex_unlock(&sem->mutex);
    (void)pthread_mutex_destroy(&sem->mutex);
#endif
}

status_t cs_attach_sem(ipc_sem_t *sem, ipc_side_t side)
{
#ifdef WIN32
    char sem_name[CT_MAX_NAME_LEN];
    CM_POINTER(sem);
    PRTS_RETURN_IFERR(snprintf_s(sem_name, sizeof(sem_name), sizeof(sem_name) - 1, "%s_%u", g_sem_prefix, sem->id));
    char *psem_name = sem_name;
    sem->handles[side] = OpenSemaphore(SEMAPHORE_ALL_ACCESS, CT_FALSE, psem_name);
    if (sem->handles[side] == INVALID_HANDLE_VALUE) {
        CT_THROW_ERROR(ERR_ATTACH_SEMAPORE);
        return CT_ERROR;
    }
#else
    (void)sem;
    (void)side;
#endif

    return CT_SUCCESS;
}

void cs_detach_sem(ipc_sem_t *sem, ipc_side_t side)
{
    CM_POINTER(sem);
#ifdef WIN32
    CloseHandle(sem->handles[side]);
    sem->handles[side] = INVALID_HANDLE_VALUE;
#else
    (void)side;
#endif
}

void cs_sem_v(ipc_sem_t *sem, ipc_side_t side)
{
    CM_POINTER(sem);
#ifdef WIN32
    ReleaseSemaphore(sem->handles[side], 1, NULL);
#else
    (void)side;
    (void)pthread_mutex_unlock(&sem->mutex);
#endif
}

bool32 cs_sem_timed_p(ipc_sem_t *sem, ipc_side_t side, uint32 timeout)
{
#ifdef WIN32
    CM_POINTER(sem);
    if (WAIT_TIMEOUT == WaitForSingleObject(sem->handles[side], timeout * CT_TIME_THOUSAND_UN)) {
        return CT_FALSE;
    }
#else
    struct timespec tm;
    time_t cur_time;

    CM_POINTER(sem);
    (void)side;

    cur_time = time(NULL);
    if (cur_time == -1) {
        return CT_FALSE;
    }

    tm.tv_sec = cur_time + timeout;
    tm.tv_nsec = 0;

    if (pthread_mutex_timedlock(&sem->mutex, &tm) != 0) {
        return CT_FALSE;
    }
#endif

    return CT_TRUE;
}

void cs_sem_p(ipc_sem_t *sem, ipc_side_t side)
{
    CM_POINTER(sem);
#ifdef WIN32
    WaitForSingleObject(sem->handles[side], INFINITE);
#else
    (void)side;
    (void)pthread_mutex_lock(&sem->mutex);
#endif
}

static uint32 cs_make_shm_key(const char *name)
{
    uint32 hash_id = cm_hash_string(name, 0xFFFF);
    return (hash_id << 16) + IPC_SHM_ID;
}

status_t cs_create_shm(ipc_shm_t *shm, const char *ipc_name)
{
    uint32 size, shm_key;
    size = sizeof(ipc_lsnr_ctrl_t);
    size += CT_MAX_SESSIONS * (sizeof(ipc_room_t));
    shm_key = cs_make_shm_key(ipc_name);

#ifdef WIN32
    char name[CT_MAX_NAME_LEN];
    PRTS_RETURN_IFERR(snprintf_s(name, sizeof(name), sizeof(name) - 1, "CTDB_CS_%u", shm_key));
    char *pname = name;
    shm->addr = OpenFileMapping(FILE_MAP_ALL_ACCESS, CT_FALSE, pname);
    shm->id = 0;

    if (shm->addr == NULL) {
        CT_THROW_ERROR(ERR_CREATE_SHARED_MEMORY);
        return CT_ERROR;
    }
#else
    int32 id = shmget((key_t)shm_key, size, (IPC_CREAT | IPC_EXCL | S_IRUSR | S_IWUSR | S_IRGRP));
    if (id == -1) {
        CT_THROW_ERROR(ERR_CREATE_SHARED_MEMORY);
        return CT_ERROR;
    }

    shm->addr = shmat(id, NULL, 0);
    shm->id = id;
#endif
    return CT_SUCCESS;
}

status_t cs_attach_shm(ipc_shm_t *shm, const char *ipc_name)
{
    uint32 shm_key = cs_make_shm_key(ipc_name);
    CM_POINTER(shm);

#ifdef WIN32
    char name[CT_MAX_NAME_LEN];
    PRTS_RETURN_IFERR(snprintf_s(name, sizeof(name), sizeof(name) - 1, "CTDB_CS_%u", shm_key));
    char *pname = name;
    shm->addr = OpenFileMapping(FILE_MAP_ALL_ACCESS, CT_FALSE, pname);
    shm->id = 0;

    if (shm->addr == NULL) {
        CT_THROW_ERROR(ERR_CREATE_SHARED_MEMORY);
        return CT_ERROR;
    }

#else
    int32 id = shmget((key_t)shm_key, 0, 0);
    if (id == -1) {
        CT_THROW_ERROR(ERR_CREATE_SHARED_MEMORY);
        return CT_ERROR;
    }

    shm->addr = shmat(id, NULL, 0);
    shm->id = id;

#endif

    return CT_SUCCESS;
}

void cs_detach_shm(ipc_shm_t *shm)
{
    CM_POINTER(shm);
#ifdef WIN32
    UnmapViewOfFile(shm->addr);
#else
    (void)shmdt(shm->addr);
#endif
    shm->id = -1;
    shm->addr = NULL;
}

void cs_destroy_shm(ipc_shm_t *shm)
{
    CM_POINTER(shm);
#ifdef WIN32
    UnmapViewOfFile(shm->addr);
#else
    (void)shmdt(shm->addr);
#endif

    shm->id = -1;
    shm->addr = NULL;
}

#ifdef __cplusplus
}
#endif
