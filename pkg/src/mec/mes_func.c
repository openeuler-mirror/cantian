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
 * mes_func.c
 *
 *
 * IDENTIFICATION
 * src/mec/mes_func.c
 *
 * -------------------------------------------------------------------------
 */
#include "mes_log_module.h"
#include "cm_ip.h"
#include "cm_memory.h"
#include "cm_spinlock.h"
#include "cm_sync.h"
#include "cs_tcp.h"
#include "dtc_trace.h"
#include "rc_reform.h"
#include "mes_uc.h"
#include "mes_tcp.h"
#include "mes_func.h"

mes_instance_t g_mes;

mes_stat_t g_mes_stat[MES_CMD_CEIL];
mes_elapsed_stat_t g_mes_elapsed_stat;

message_timeout_check_func g_message_need_timeout_early = NULL;

uint64 g_start_time;
int64 g_get_count = 0;
int64 g_release_count = 0;

mes_connect_t g_connect_func;
mes_disconnect_t g_disconnect_func;
mes_async_disconnect_t g_disconnect_async_func;
mes_send_data_t g_send_func;
mes_send_data_t g_cms_send_func;
mes_send_bufflist_t g_send_bufflist_func;
mes_release_buf_t g_release_buf_func;
mes_connection_ready_t g_conn_ready_func;
mes_alloc_msgitem_t g_alloc_msgitem_func;

bool32 g_enable_dbstor = CT_FALSE;

ssl_auth_file_t g_mes_ssl_auth_file = {0};

#define MES_CONNECT(inst_id) g_connect_func(inst_id)
#define MES_DISCONNECT(inst_id) g_disconnect_func(inst_id)
#define MES_DISCONNECT_ASYNC(inst_id) g_disconnect_async_func(inst_id)
#define MES_SEND_DATA(data) g_send_func(data)
#define MES_CMS_SEND_DATA(data) g_cms_send_func(data)
#define MES_SEND_BUFFLIST(buff_list) g_send_bufflist_func(buff_list)
#define MES_RELEASE_BUFFER(buffer) g_release_buf_func(buffer)
#define MES_CONNETION_READY(inst_id) g_conn_ready_func(inst_id)
#define MES_ALLOC_MSGITEM(queue) g_alloc_msgitem_func(queue)

#define MES_FORMAT_LOG_LENGTH (1024)
#define MES_GET_BUF_TRY_TIMES (50)

#define MES_SESSION_TO_CHANNEL_ID(sid) (uint8)((sid) % g_mes.profile.channel_num)

mes_instance_t *get_g_mes(void)
{
    return &g_mes;
}
mes_stat_t *get_g_mes_stat(void)
{
    return g_mes_stat;
}

bool32 mes_message_need_timeout(void)
{
    if (g_message_need_timeout_early == NULL) {
        return CT_FALSE;
    }

    return g_message_need_timeout_early();
}

void mes_set_message_timeout_check_func(message_timeout_check_func func)
{
    CT_LOG_DEBUG_INF("[mes] set message timeout check function successful.");
    g_message_need_timeout_early = func;
}

static inline status_t mes_log_format_buf(char *buf, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    PRTS_RETURN_IFERR(snprintf_s(buf, MES_FORMAT_LOG_LENGTH, MES_FORMAT_LOG_LENGTH - 1, format, args));
    va_end(args);
    return CT_SUCCESS;
}

#define MES_LOG_WAR_HEAD_EXX(head, format, ...)                                                                    \
    do {                                                                                                           \
        char buf[MES_FORMAT_LOG_LENGTH];                                                                           \
        mes_log_format_buf(buf, format, ##__VA_ARGS__);                                                            \
        CT_LOG_RUN_WAR("[mes] %s: %s. cmd=%u, rsn=%u, src_inst=%u, dst_inst=%u, src_sid=%u, dst_sid=%u.",          \
                       (char *)__func__, buf, head->cmd, head->rsn, head->src_inst, head->dst_inst, head->src_sid, \
                       head->dst_sid);                                                                             \
    } while (0);

#define MES_STAT_SEND(head)       \
    do {                          \
        mes_send_stat((head)->cmd); \
        MES_LOG_HEAD(head);       \
    } while (0);

#define MES_STAT_SEND_FAIL(head)       \
    do {                               \
        mes_send_fail_stat((head)->cmd); \
        MES_LOG_HEAD_FAIL(head);       \
    } while (0);

void mes_consume_time_init(void)
{
    for (int j = 0; j < MES_CMD_CEIL; j++) {
        g_mes_elapsed_stat.time_consume_stat[j].cmd = j;
        g_mes_elapsed_stat.time_consume_stat[j].group_id = 0;
        for (int i = 0; i < MES_TIME_CEIL; i++) {
            g_mes_elapsed_stat.time_consume_stat[j].time[i] = 0;
            g_mes_elapsed_stat.time_consume_stat[j].count[i] = 0;
            g_mes_elapsed_stat.time_consume_stat[j].non_empty = CT_FALSE;
        }
    }
    return;
}

void mes_init_stat(void)
{
    for (int i = 0; i < MES_CMD_CEIL; i++) {
        g_mes_stat[i].cmd = i;
        g_mes_stat[i].send_count = 0;
        g_mes_stat[i].send_fail_count = 0;
        g_mes_stat[i].recv_count = 0;
        g_mes_stat[i].local_count = 0;
        g_mes_stat[i].dealing_count = 0;
        g_mes_stat[i].non_empty = CT_FALSE;
    }

    for (int i = 0; i < MES_LOGGING_CEIL; i++) {
        g_mes.mes_ctx.logging_time[i] = 0;
    }

    mes_consume_time_init();

    return;
}

static inline void mes_send_stat(mes_command_t cmd)
{
    cm_atomic_inc(&(g_mes_stat[cmd].send_count));
}

static inline void mes_send_fail_stat(mes_command_t cmd)
{
    cm_atomic_inc(&(g_mes_stat[cmd].send_fail_count));
}

static inline void mes_local_stat(mes_command_t cmd)
{
    cm_atomic_inc(&(g_mes_stat[cmd].local_count));
}

static inline void mes_add_dealing_count(mes_command_t cmd)
{
    cm_atomic32_inc(&(g_mes_stat[cmd].dealing_count));
}

void mes_dec_dealing_count(mes_command_t cmd)
{
    if (cmd >= MES_CMD_CEIL) {
        CT_LOG_RUN_ERR("index out of MES_CMD_CEI!");
        return;
    }
    cm_atomic32_dec(&(g_mes_stat[cmd].dealing_count));
}

void mes_release_message_buf(const char *msg_buf)
{
    CM_POINTER(msg_buf);
    mes_message_head_t *head = (mes_message_head_t *)msg_buf;
    if (head->cmd < MES_CMD_CEIL) {
        mes_release_buf_stat(msg_buf);
        mes_dec_dealing_count(head->cmd);
    }
    mes_free_buf_item((char *)msg_buf);
    return;
}

void mes_get_message_buf(mes_message_t *msg, mes_message_head_t *head)
{
    char *msg_buf;
    uint64 stat_time = 0;

    mes_get_consume_time_start(&stat_time);

    msg_buf = mes_alloc_buf_item(head->size);

    MES_MESSAGE_ATTACH(msg, msg_buf);

    mes_consume_with_time(head->cmd, MES_TIME_GET_BUF, stat_time);

    return;
}

static inline void mes_recv_message_stat(mes_message_t *msg)
{
    cm_atomic_inc(&(g_mes_stat[msg->head->cmd].recv_count));
    MES_LOG_WITH_MSG(msg);
}

void mes_process_message(dtc_msgqueue_t *my_queue, uint32 recv_idx, mes_message_t *msg, uint64 start_time)
{
    dtc_msgitem_t *msgitem;

    mes_recv_message_stat(msg);
    mes_add_dealing_count(msg->head->cmd);

    if (g_mes.is_enqueue[msg->head->cmd]) {
        msgitem = MES_ALLOC_MSGITEM(my_queue);
        if (msgitem == NULL) {
            mes_release_message_buf(msg->buffer);
            CT_LOG_RUN_ERR("[mes]: alloc msgitem failed.");
            return;
        }

        msgitem->msg.head = msg->head;
        msgitem->msg.buffer = msg->buffer;
        msgitem->start_time = start_time;

        mes_put_msgitem(msgitem);

        mes_consume_with_time(msg->head->cmd, MES_TIME_PUT_QUEUE, start_time);

        return;
    }

    g_mes.proc((g_mes.profile.work_thread_num + recv_idx), msg);

    mes_consume_with_time(msg->head->cmd, MES_TIME_PROC_FUN, start_time);

    return;
}

status_t mes_set_addr(uint32 inst_id, char *ip, uint16 port)
{
    errno_t ret;

    if (inst_id >= CT_MAX_INSTANCES) {
        CT_THROW_ERROR_EX(ERR_MES_PARAMETER, "node_id %u is invalid.", inst_id);
        return CT_ERROR;
    }

    ret = strncpy_s(g_mes.profile.inst_arr[inst_id].ip, CT_MAX_INST_IP_LEN, ip, strlen(ip));
    if (ret != EOK) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, (ret));
        return CT_ERROR;
    }
    g_mes.profile.inst_arr[inst_id].port = port;
    return CT_SUCCESS;
}

void mes_clear_addr(uint32 node_id)
{
    if (node_id >= CT_MAX_INSTANCES) {
        return;
    }

    g_mes.profile.inst_arr[node_id].ip[0] = '\0';
    g_mes.profile.inst_arr[node_id].port = 0;

    return;
}

status_t mes_connect(uint32 inst_id, char *ip, uint16 port)
{
    mes_conn_t *conn;

    if ((inst_id == g_mes.profile.inst_id) || (inst_id >= CT_MAX_INSTANCES)) {
        CT_THROW_ERROR_EX(ERR_MES_PARAMETER, "[mes]: connect inst_id %u failed, current inst_id %u.", inst_id,
                          g_mes.profile.inst_id);
        return CT_ERROR;
    }

    conn = &g_mes.mes_ctx.conn_arr[inst_id];

    cm_thread_lock(&conn->lock);
    if (g_mes.mes_ctx.conn_arr[inst_id].is_connect) {
        cm_thread_unlock(&conn->lock);
        CT_THROW_ERROR_EX(ERR_MES_ALREADY_CONNECT, "[mes]: dst instance %u.", inst_id);
        return CT_ERROR;
    }

    if (mes_set_addr(inst_id, ip, port) != CT_SUCCESS) {
        cm_thread_unlock(&conn->lock);
        CT_LOG_RUN_ERR("[mes]: mes_set_addr failed.");
        return CT_ERROR;
    }

    if (MES_CONNECT(inst_id) != CT_SUCCESS) {
        cm_thread_unlock(&conn->lock);
        CT_LOG_RUN_ERR("[mes]: MES_CONNECT failed.");
        return CT_ERROR;
    }

    g_mes.mes_ctx.conn_arr[inst_id].is_connect = CT_TRUE;
    cm_thread_unlock(&conn->lock);

    CT_LOG_RUN_INF("[mes] connect to instance %u, %s:%u.", inst_id, ip, port);

    return CT_SUCCESS;
}

bool32 mes_connection_ready(uint32 inst_id)
{
    if ((inst_id >= CT_MAX_INSTANCES) || (inst_id == g_mes.profile.inst_id)) {
        CT_THROW_ERROR_EX(ERR_MES_PARAMETER, "[mes] connect inst_id %u is invalid, current inst_id %u.", inst_id,
                          g_mes.profile.inst_id);
        return CT_FALSE;
    }

    return MES_CONNETION_READY(inst_id);
}

static inline void mes_wakeup(uint16 sid)
{
    if (sid >= CT_MAX_MES_ROOMS) {
        return;
    }
    mes_waiting_room_t *room = &g_mes.mes_ctx.waiting_rooms[sid];
    cm_spin_lock(&room->lock, NULL);
    (void)cm_atomic_set(&room->timeout, 0);
    cm_spin_unlock(&room->lock);
}

void mes_wakeup_rooms(void)
{
    CT_LOG_RUN_WAR("[mes] start wakeup all rooms.");
    for (uint32 i = 0; i < CT_MAX_MES_ROOMS; i++) {
        mes_wakeup(i);
    }
    CT_LOG_RUN_WAR("[mes] finish wakeup all rooms.");
}

status_t mes_disconnect(uint32 inst_id, bool32 isSync)
{
    mes_conn_t *conn;

    if (inst_id >= CT_MAX_INSTANCES || inst_id == g_mes.profile.inst_id) {
        CT_THROW_ERROR_EX(ERR_MES_PARAMETER, "[mes]: mes_disconnect: inst_id %u is illegal.", inst_id);
        return CT_ERROR;
    }

    conn = &g_mes.mes_ctx.conn_arr[inst_id];
    cm_thread_lock(&conn->lock);
    if (!g_mes.mes_ctx.conn_arr[inst_id].is_connect) {
        cm_thread_unlock(&conn->lock);
        CT_LOG_RUN_INF("[mes] target node %u is not connect, no need disconnect.", inst_id);
        return CT_SUCCESS;
    }

    if (isSync) {
        MES_DISCONNECT(inst_id);
    } else {
        MES_DISCONNECT_ASYNC(inst_id);
    }

    mes_clear_addr(inst_id);

    g_mes.mes_ctx.conn_arr[inst_id].is_connect = CT_FALSE;

    cm_thread_unlock(&conn->lock);

    CT_LOG_RUN_INF("[mes] success disconnect node %u.", inst_id);

    return CT_SUCCESS;
}

status_t mes_connect_by_profile(void)
{
    uint32 i;

    if (!g_mes.profile.conn_by_profile) {
        return CT_SUCCESS;
    }

    // channel connect
    for (i = 0; i < g_mes.profile.inst_count; i++) {
        if (i == g_mes.profile.inst_id) {
            continue;
        }
        if (mes_connect(i, g_mes.profile.inst_arr[i].ip, g_mes.profile.inst_arr[i].port) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[mes] conncect to instance %d failed.", i);
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

void mes_disconnect_by_profile(void)
{
    uint32 i;
    // channel disconnect
    for (i = 0; i < g_mes.profile.inst_count; i++) {
        if ((i != g_mes.profile.inst_id) && g_mes.mes_ctx.conn_arr[i].is_connect) {
            mes_disconnect(i, CT_TRUE);
        }
    }

    return;
}

static void mes_clean_session_mutex(uint32 ceil)
{
    uint32 i;
    for (i = 0; i < ceil; i++) {
        mes_mutex_destroy(&g_mes.mes_ctx.waiting_rooms[i].mutex);
        mes_mutex_destroy(&g_mes.mes_ctx.waiting_rooms[i].broadcast_mutex);
    }
}

static status_t mes_init_session_room()
{
    uint32 i;
    mes_waiting_room_t *room = NULL;

    for (i = 0; i < CT_MAX_MES_ROOMS; i++) {
        room = &g_mes.mes_ctx.waiting_rooms[i];

        if (mes_mutex_create(&room->mutex) != CT_SUCCESS) {
            mes_clean_session_mutex(i);
            CT_LOG_RUN_ERR("mes_mutex_create %u failed.", i);
            return CT_ERROR;
        }

        if (mes_mutex_create(&room->broadcast_mutex) != CT_SUCCESS) {
            mes_clean_session_mutex(i);
            CT_LOG_RUN_ERR("mes_mutex_create %u failed.", i);
            return CT_ERROR;
        }

        CT_INIT_SPIN_LOCK(room->lock);

        room->rsn = cm_random(CT_INVALID_ID32);
        room->check_rsn = room->rsn;
        (void)cm_atomic_set(&room->timeout, 0);
    }

    return CT_SUCCESS;
}

void mes_init_conn(void)
{
    uint32 i;
    mes_conn_t *conn;

    for (i = 0; i < CT_MAX_INSTANCES; i++) {
        conn = &g_mes.mes_ctx.conn_arr[i];
        conn->is_connect = CT_FALSE;
        cm_init_thread_lock(&conn->lock);
    }

    return;
}

status_t mes_register_func(void)
{
    if (g_mes.profile.pipe_type == CS_TYPE_TCP) {
        g_connect_func = mes_tcp_connect;
        g_disconnect_func = mes_tcp_disconnect;
        g_disconnect_async_func = mes_tcp_disconnect_async;
        g_send_func = mes_tcp_send_data;
        g_cms_send_func = mes_cms_tcp_send_data;
        g_send_bufflist_func = mes_tcp_send_bufflist;
        if (!g_mes.profile.use_ssl) {
            g_conn_ready_func = mes_tcp_connection_ready;
        } else {
            g_conn_ready_func = mes_ssl_connection_ready;
        }
        g_alloc_msgitem_func = mes_alloc_msgitem_nolock;
    } else if (g_mes.profile.pipe_type == CS_TYPE_UC || g_mes.profile.pipe_type == CS_TYPE_UC_RDMA) {
        g_cms_send_func = mes_uc_send_data;
        g_connect_func = mes_uc_connect;
        g_disconnect_func = mes_uc_disconnect;
        g_disconnect_async_func = mes_uc_disconnect_async;
        g_send_func = mes_uc_send_data;
        g_send_bufflist_func = mes_uc_send_bufflist;
        g_conn_ready_func = mes_uc_connection_ready;
        g_alloc_msgitem_func = mes_alloc_msgitem_nolock;
    } else {
        CT_THROW_ERROR_EX(ERR_MES_PARAMETER, "pipe_type %u is invalid", g_mes.profile.pipe_type);
        return CT_ERROR;
    }

    mes_init_send_recv_buf_pool();

    return CT_SUCCESS;
}

status_t mes_init_pipe(void)
{
    if (g_mes.profile.pipe_type == CS_TYPE_TCP) {
        if (mes_init_tcp() != CT_SUCCESS) {
            CT_LOG_RUN_ERR("mes_init_tcp failed.");
            return CT_ERROR;
        }
    } else if (g_mes.profile.pipe_type == CS_TYPE_UC || g_mes.profile.pipe_type == CS_TYPE_UC_RDMA) {
        if (mes_init_uc() != CT_SUCCESS) {
            CT_LOG_RUN_ERR("mes_init_uc failed.");
            return CT_ERROR;
        }
    } else {
        CT_THROW_ERROR_EX(ERR_MES_PARAMETER, "pipe_type %u is invalid", g_mes.profile.pipe_type);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

void mes_destroy_pipe(void)
{
    if (g_mes.profile.pipe_type == CS_TYPE_TCP) {
        mes_destroy_tcp();
    } else if (g_mes.profile.pipe_type == CS_TYPE_UC || g_mes.profile.pipe_type == CS_TYPE_UC_RDMA) {
        mes_destroy_uc();
    } else {
        CT_THROW_ERROR_EX(ERR_MES_PARAMETER, "pipe_type %u is invalid", g_mes.profile.pipe_type);
    }
    return;
}

status_t mes_init_resource(void)
{
    mes_init_stat();

    mes_init_conn();

    if (mes_init_session_room() != CT_SUCCESS) {
        CT_LOG_RUN_ERR("mes_init_session_room failed.");
        return CT_ERROR;
    }

    if (init_dtc_mq_instance() != CT_SUCCESS) {
        CT_LOG_RUN_ERR("init_dtc_mq_instance failed.");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

void mes_destroy_resource(void)
{
    free_dtc_mq_instance();

    mes_clean_session_mutex(CT_MAX_MES_ROOMS);

    return;
}

static status_t mes_init(void)
{
    // register tcp/rdma func
    if (mes_register_func() != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[mes]: mes_register_func failed.");
        return CT_ERROR;
    }

    if (mes_init_resource() != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[mes]: init resource failed.");
        return CT_ERROR;
    }

    if (mes_init_pipe() != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[mes]: mes_init_pipe failed.");
        return CT_ERROR;
    }

    if (mes_connect_by_profile() != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[mes]: mes_connect_by_profile failed.");
        return CT_ERROR;
    }

    CT_LOG_RUN_INF("[mes] mes_init success.");

    return CT_SUCCESS;
}

void mes_clean(void)
{
    mes_disconnect_by_profile();

    mes_destroy_resource();

    mes_destroy_pipe();

    CT_LOG_RUN_INF("[mes] mes_clean.");

    return;
}

status_t mes_set_process_lsid(mes_profile_t *profile)
{
    if (profile->inst_count >= CT_MAX_INSTANCES) {
        CT_THROW_ERROR_EX(ERR_MES_PARAMETER, "instinst_count_id %u is invalid, exceed max instance num %u.", profile->inst_count,
                          CT_MAX_INSTANCES);
        return CT_ERROR;
    }

    for (int i = 0; i < profile->inst_count; i++) {
        g_mes.profile.inst_lsid[i] = profile->inst_lsid[i];
    }

    return CT_SUCCESS;
}

status_t mes_set_instance_info(uint32 inst_id, uint32 inst_count, mes_addr_t *inst_arr)
{
    errno_t ret;

    if (inst_id >= CT_MAX_INSTANCES) {
        CT_THROW_ERROR_EX(ERR_MES_PARAMETER, "inst_id %u is invalid, exceed max instance num %u.", inst_id,
                          CT_MAX_INSTANCES);
        return CT_ERROR;
    }

    if (inst_count >= CT_MAX_INSTANCES) {
        CT_THROW_ERROR_EX(ERR_MES_PARAMETER, "instinst_count_id %u is invalid, exceed max instance num %u.", inst_count,
                          CT_MAX_INSTANCES);
        return CT_ERROR;
    }

    g_mes.profile.inst_id = inst_id;
    g_mes.profile.inst_count = inst_count;

    ret = memset_sp(g_mes.profile.inst_arr, (sizeof(mes_addr_t) * CT_MAX_INSTANCES), 0,
                    (sizeof(mes_addr_t) * CT_MAX_INSTANCES));
    MEMS_RETURN_IFERR(ret);

    for (int i = 0; i < inst_count; i++) {
        if (mes_set_addr(i, inst_arr[i].ip, inst_arr[i].port) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("mes_set_addr node(%d) ip(%s) port(%u) failed.", i, inst_arr[i].ip, inst_arr[i].port);
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

void mes_set_pool_size(uint32 mes_pool_size)
{
    if (mes_pool_size < CT_MES_MIN_POOL_SIZE) {
        g_mes.profile.pool_size = CT_MES_MIN_POOL_SIZE;
        CT_LOG_RUN_WAR("[mes] min pool size is %u.", CT_MES_MIN_POOL_SIZE);
    } else if (mes_pool_size > CT_MES_MAX_POOL_SIZE) {
        g_mes.profile.pool_size = CT_MES_MAX_POOL_SIZE;
        CT_LOG_RUN_WAR("[mes] max pool size is %u.", CT_MES_MAX_POOL_SIZE);
    } else {
        g_mes.profile.pool_size = mes_pool_size;
    }
    CT_LOG_DEBUG_INF("[mes] set pool size %u.", g_mes.profile.pool_size);
    return;
}

void mes_set_channel_num(uint32 channel_num)
{
    if (channel_num < CT_MES_MIN_CHANNEL_NUM) {
        g_mes.profile.channel_num = CT_MES_MIN_CHANNEL_NUM;
        CT_LOG_RUN_WAR("[mes] min channel num is %u.", CT_MES_MIN_CHANNEL_NUM);
    } else if (channel_num > CT_MES_MAX_CHANNEL_NUM) {
        g_mes.profile.channel_num = CT_MES_MAX_CHANNEL_NUM;
        CT_LOG_RUN_WAR("[mes] max channel num is %u.", CT_MES_MAX_CHANNEL_NUM);
    } else {
        g_mes.profile.channel_num = channel_num;
    }
    CT_LOG_DEBUG_INF("[mes] set channel num %u.", g_mes.profile.channel_num);
    return;
}

void mes_set_reactor_thread_num(uint32 reactor_thread_num)
{
    g_mes.profile.reactor_thread_num = reactor_thread_num;
    CT_LOG_DEBUG_INF("[mes] set reactor thread num %u.", g_mes.profile.reactor_thread_num);
}

void mes_set_work_thread_num(uint32 thread_num)
{
    if (thread_num < MES_MIN_TASK_NUM) {
        g_mes.profile.work_thread_num = MES_MIN_TASK_NUM;
        CT_LOG_RUN_WAR("[mes] min work thread num is %u.", MES_MIN_TASK_NUM);
    } else if (thread_num > MES_MAX_TASK_NUM) {
        g_mes.profile.work_thread_num = MES_MAX_TASK_NUM;
        CT_LOG_RUN_WAR("[mes] max work thread num is %u.", MES_MAX_TASK_NUM);
    } else {
        g_mes.profile.work_thread_num = thread_num;
    }
    CT_LOG_DEBUG_INF("[mes] set work thread num %u.", g_mes.profile.work_thread_num);
    return;
}

status_t mes_set_buffer_pool(mes_profile_t *profile)
{
    uint32 pool_count = profile->buffer_pool_attr.pool_count;
    if ((pool_count == 0) || (pool_count > MES_MAX_BUFFER_STEP_NUM)) {
        CT_THROW_ERROR_EX(ERR_MES_PARAMETER, "[mes] pool_count %u is invalid, legal scope is [1, %u].", pool_count,
                          MES_MAX_BUFFER_STEP_NUM);
        return CT_ERROR;
    }

    g_mes.profile.buffer_pool_attr.pool_count = pool_count;
    for (uint32 i = 0; i < pool_count; i++) {
        g_mes.profile.buffer_pool_attr.buf_attr[i] = profile->buffer_pool_attr.buf_attr[i];
    }
    return CT_SUCCESS;
}

status_t mes_set_profile(mes_profile_t *profile)
{
    CM_POINTER(profile);
    if (mes_set_instance_info(profile->inst_id, profile->inst_count, profile->inst_arr) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[mes]: mes_set_instance_info failed.");
        return CT_ERROR;
    }

    if (mes_set_buffer_pool(profile) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[mes]: set buffer pool failed.");
        return CT_ERROR;
    }

    if (mes_set_process_lsid(profile) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[mes]: set process lsid failed.");
        return CT_ERROR;
    }

    g_mes.profile.pipe_type = profile->pipe_type;
    mes_set_pool_size(profile->pool_size);
    mes_set_channel_num(profile->channel_num);
    mes_set_reactor_thread_num(profile->reactor_thread_num);
    mes_set_work_thread_num(profile->work_thread_num);
    g_mes.profile.conn_by_profile = profile->conn_by_profile;
    g_mes.profile.channel_version = profile->channel_version;
    g_mes.profile.upgrade_time_ms = profile->upgrade_time_ms;
    g_mes.profile.degrade_time_ms = profile->degrade_time_ms;

    // mq
    g_mes.mq_ctx.task_num = g_mes.profile.work_thread_num;
    g_mes.mq_ctx.group.assign_task_idx = 0;

    g_mes.profile.is_init = CT_TRUE;

    CT_LOG_RUN_INF("[mes] set profile finish.");

    return CT_SUCCESS;
}

status_t mes_set_uc_dpumm_config_path(const char *home_path)
{
    if (home_path == NULL) {
        CT_LOG_RUN_ERR("[mes]: dpumm config path is null.");
        return CT_ERROR;
    }
    int32 ret = sprintf_s(g_mes.profile.dpumm_config_path, sizeof(g_mes.profile.dpumm_config_path),
        "%s/dbstor/conf/infra", home_path);
    if (ret == -1) {
        CT_LOG_RUN_ERR("[mes]: set dpumm config path failed.");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t mes_startup(void)
{
    if (mes_init() != CT_SUCCESS) {
        mes_clean();
        CT_LOG_RUN_ERR("mes_init failed.");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static inline void mes_set_bufflist(mes_bufflist_t *buff_list, uint32 idx, const void *buff, uint32 len)
{
    buff_list->buffers[idx].buf = (char *)buff;
    buff_list->buffers[idx].len = len;
}

static inline void mes_append_bufflist(mes_bufflist_t *buff_list, const void *buff, uint32 len)
{
    buff_list->buffers[buff_list->cnt].buf = (char *)buff;
    buff_list->buffers[buff_list->cnt].len = len;
    buff_list->cnt = buff_list->cnt + 1;
}

status_t mes_check_msg_head(mes_message_head_t *head)
{
    if (SECUREC_UNLIKELY(head->cmd >= MES_CMD_CEIL)) {
        CT_THROW_ERROR_EX(ERR_MES_INVALID_CMD, "[mes][%s] cmd %u is illegal.", (char *)__func__, head->cmd);
        MES_LOG_ERR_HEAD_EX(head, "cmd is illegal");
        return CT_ERROR;
    }

    if (SECUREC_UNLIKELY(head->size > MES_128K_MESSAGE_BUFFER_SIZE)) {
        CT_THROW_ERROR_EX(ERR_MES_ILEGAL_MESSAGE, "[mes][%s] size %u is excced.", (char *)__func__, head->size);
        MES_LOG_ERR_HEAD_EX(head, "message length excced");
        return CT_ERROR;
    }

    if (SECUREC_UNLIKELY(head->size < sizeof(mes_message_head_t))) {
        CT_THROW_ERROR_EX(ERR_MES_ILEGAL_MESSAGE, "[mes][%s] size %u is too small.", (char *)__func__, head->size);
        MES_LOG_ERR_HEAD_EX(head, "message length too small");
        return CT_ERROR;
    }

    if (SECUREC_UNLIKELY(head->src_inst >= g_mes.profile.inst_count)) {
        CT_THROW_ERROR_EX(ERR_MES_PARAMETER, "[mes][%s] src_inst %u is illegal.", (char *)__func__, head->src_inst);
        MES_LOG_ERR_HEAD_EX(head, "src inst id is illegal");
        return CT_ERROR;
    }

    if (SECUREC_UNLIKELY(head->dst_inst >= g_mes.profile.inst_count)) {
        CT_THROW_ERROR_EX(ERR_MES_PARAMETER, "[mes][%s] dst_inst %u is illegal.", (char *)__func__, head->dst_inst);
        MES_LOG_ERR_HEAD_EX(head, "dst inst id is illegal");
        return CT_ERROR;
    }

    if (SECUREC_UNLIKELY((head->src_sid > CT_MAX_MES_ROOMS) && (head->src_sid != CT_INVALID_ID16))) {
        CT_THROW_ERROR_EX(ERR_MES_PARAMETER, "[mes][%s] src_sid %u is illegal.", (char *)__func__, head->src_sid);
        MES_LOG_ERR_HEAD_EX(head, "src session id is illegal");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t mes_send_inter_buffer_list(mes_bufflist_t *buff_list)
{
    errno_t err;
    mes_message_t msg;
    char *buffer;
    uint32 pos = 0;

    buffer = mes_alloc_buf_item(MES_MESSAGE_BUFFER_SIZE);
    if (buffer == NULL) {
        CT_LOG_RUN_ERR("[mes] mes_alloc_buf_item failed.");
        return CT_ERROR;
    }
    for (int i = 0; i < buff_list->cnt; i++) {
        err = memcpy_sp(buffer + pos, MES_MESSAGE_BUFFER_SIZE - pos, buff_list->buffers[i].buf,
                        buff_list->buffers[i].len);
        if (err != EOK) {
            mes_release_recv_buf(buffer);
            CT_THROW_ERROR(ERR_SYSTEM_CALL, err);
            return CT_ERROR;
        }
        pos += buff_list->buffers[i].len;
    }

    MES_MESSAGE_ATTACH(&msg, buffer);

    if (mes_put_inter_msg(&msg) != CT_SUCCESS) {
        mes_release_recv_buf(buffer);
        MES_STAT_SEND_FAIL(msg.head);
        CT_LOG_RUN_ERR("[mes] mes_put_inter_msg failed.");
        return CT_ERROR;
    }

    mes_local_stat(msg.head->cmd);
    mes_add_dealing_count(msg.head->cmd);
    return CT_SUCCESS;
}

static status_t mes_send_inter_msg(const void *msg_data)
{
    errno_t err;
    mes_message_t msg;
    char *buffer;

    buffer = mes_alloc_buf_item(MES_MESSAGE_BUFFER_SIZE);
    if (buffer == NULL) {
        CT_LOG_RUN_ERR("buffer allocation failed.");
        return CT_ERROR;
    }
    err = memcpy_sp(buffer, MES_MESSAGE_BUFFER_SIZE, msg_data, ((mes_message_head_t *)msg_data)->size);
    if (err != EOK) {
        mes_release_recv_buf(buffer);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, err);
        return CT_ERROR;
    }

    MES_MESSAGE_ATTACH(&msg, buffer);

    if (mes_put_inter_msg(&msg) != CT_SUCCESS) {
        mes_release_recv_buf(buffer);
        MES_STAT_SEND_FAIL(msg.head);
        CT_LOG_RUN_ERR("[mes] mes_put_inter_msg failed.");
        return CT_ERROR;
    }

    mes_local_stat(msg.head->cmd);
    mes_add_dealing_count(msg.head->cmd);
    return CT_SUCCESS;
}

status_t mes_cms_send_data(const void *msg_data)
{
    uint64 start_stat_time = 0;
    mes_message_head_t *head = (mes_message_head_t *)msg_data;
    if (mes_check_msg_head(head) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[mes] mes check msg head failed.");
        return CT_ERROR;
    }

    head->extend_size = 0;
    if (g_mes.crc_check_switch) {
        char *body = (char *)msg_data + sizeof(mes_message_head_t);
        head->body_cks = mes_calc_cks(body, head->size - sizeof(mes_message_head_t));
        head->head_cks = mes_calc_cks((char *)head + sizeof(head->head_cks), sizeof(mes_message_head_t) -
            sizeof(head->head_cks));
    }

    if (head->dst_inst == g_mes.profile.inst_id) {
        return mes_send_inter_msg(msg_data);
    }

    mes_get_consume_time_start(&start_stat_time);

    MES_STAT_SEND(head);

    if (MES_CMS_SEND_DATA(msg_data) != CT_SUCCESS) {
        MES_LOGGING(MES_LOGGING_SEND, "send data from %u to %u failed, cmd=%u, rsn=%u.",
            head->src_inst, head->dst_inst, head->cmd, head->rsn);
        MES_STAT_SEND_FAIL(head);
        return CT_ERROR;
    }

    mes_consume_with_time(head->cmd, MES_TIME_TEST_SEND, start_stat_time);

    return CT_SUCCESS;
}

status_t mes_send_data(const void *msg_data)
{
    uint64 start_stat_time = 0;
    mes_message_head_t *head = (mes_message_head_t *)msg_data;
    if (mes_check_msg_head(head) != CT_SUCCESS) {
        return CT_ERROR;
    }

    head->extend_size = 0;
    if (g_mes.crc_check_switch) {
        char *body = (char *)msg_data + sizeof(mes_message_head_t);
        head->body_cks = mes_calc_cks(body, head->size - sizeof(mes_message_head_t));
        head->head_cks = mes_calc_cks((char *)head + sizeof(head->head_cks), sizeof(mes_message_head_t) -
            sizeof(head->head_cks));
    }

    if (head->dst_inst == g_mes.profile.inst_id) {
        return mes_send_inter_msg(msg_data);
    }

    mes_get_consume_time_start(&start_stat_time);

    MES_STAT_SEND(head);

    if (MES_SEND_DATA(msg_data) != CT_SUCCESS) {
        MES_LOGGING(MES_LOGGING_SEND, "send data from %u to %u failed, cmd=%u, rsn=%u.",
            head->src_inst, head->dst_inst, head->cmd, head->rsn);
        MES_STAT_SEND_FAIL(head);
        return CT_ERROR;
    }

    mes_consume_with_time(head->cmd, MES_TIME_TEST_SEND, start_stat_time);

    return CT_SUCCESS;
}

status_t mes_send_data2(mes_message_head_t *head, const void *body)
{
    uint64 start_stat_time = 0;
    mes_bufflist_t buff_list;
    if (mes_check_msg_head(head) != CT_SUCCESS) {
        return CT_ERROR;
    }

    head->extend_size = 0;
    if (g_mes.crc_check_switch) {
        head->body_cks = mes_calc_cks((char *)body, head->size - sizeof(mes_message_head_t));
        head->head_cks = mes_calc_cks((char *)head + sizeof(head->head_cks), sizeof(mes_message_head_t) -
            sizeof(head->head_cks));
    }

    buff_list.cnt = 0;
    mes_append_bufflist(&buff_list, head, sizeof(mes_message_head_t));
    mes_append_bufflist(&buff_list, body, head->size - sizeof(mes_message_head_t));

    if (head->dst_inst == g_mes.profile.inst_id) {
        return mes_send_inter_buffer_list(&buff_list);
    }

    mes_get_consume_time_start(&start_stat_time);

    MES_STAT_SEND(head);

    if (MES_SEND_BUFFLIST(&buff_list) != CT_SUCCESS) {
        MES_LOGGING(MES_LOGGING_SEND, "send data from %u to %u failed, cmd=%u, rsn=%u.",
            head->src_inst, head->dst_inst, head->cmd, head->rsn);
        MES_STAT_SEND_FAIL(head);
        return CT_ERROR;
    }

    mes_consume_with_time(head->cmd, MES_TIME_TEST_SEND, start_stat_time);

    return CT_SUCCESS;
}

status_t mes_send_data3(mes_message_head_t *head, uint32 head_size, const void *body)
{
    uint64 start_stat_time = 0;
    mes_bufflist_t buff_list;
    if (mes_check_msg_head(head) != CT_SUCCESS) {
        return CT_ERROR;
    }

    head->extend_size = head_size - sizeof(mes_message_head_t);
    if (g_mes.crc_check_switch) {
        char *msg = (char *)body;
        head->body_cks = mes_calc_cks(msg, head->size - head_size);
        head->head_cks = mes_calc_cks((char *)head + sizeof(head->head_cks),  head_size - sizeof(head->head_cks));
    }

    buff_list.cnt = 0;
    mes_append_bufflist(&buff_list, head, head_size);
    mes_append_bufflist(&buff_list, body, head->size - head_size);

    if (head->dst_inst == g_mes.profile.inst_id) {
        return mes_send_inter_buffer_list(&buff_list);
    }

    mes_get_consume_time_start(&start_stat_time);

    MES_STAT_SEND(head);

    if (MES_SEND_BUFFLIST(&buff_list) != CT_SUCCESS) {
        MES_LOGGING(MES_LOGGING_SEND, "send data from %u to %u failed, cmd=%u, rsn=%u.",
            head->src_inst, head->dst_inst, head->cmd, head->rsn);
        MES_STAT_SEND_FAIL(head);
        return CT_ERROR;
    }

    mes_consume_with_time(head->cmd, MES_TIME_TEST_SEND, start_stat_time);

    return CT_SUCCESS;
}

static inline void mes_protect_when_timeout(mes_waiting_room_t *room)
{
    cm_spin_lock(&room->lock, NULL);
    (void)cm_atomic32_inc((atomic32_t *)(&room->rsn));
    if (pthread_mutex_trylock(&room->mutex) == 0) {  // trylock to avoid mutex has been unlocked.
        mes_release_message_buf(room->msg_buf);
        DTC_MES_LOG_INF("[mes]%s: mutex has unlock, rsn=%u, room rsn=%u.", (char *)__func__,
                        ((mes_message_head_t *)room->msg_buf)->rsn, room->rsn);
    }
    cm_spin_unlock(&room->lock);
}

status_t mes_check_connect_ready(void)
{
    for (uint32 idx = 0; idx < g_mes.profile.inst_count; idx++) {
        if (idx == g_mes.profile.inst_id) {
            continue;
        }
        if (!MES_CONNETION_READY(idx)) {
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

status_t mes_recv_impl(uint32 sid, mes_message_t *msg, bool32 check_rsn, uint32 expect_rsn, uint32 timeout,
                       bool8 quick_stop_check)
{
    uint32 timeout_time = 0;
    uint64 start_stat_time = 0;
    mes_get_consume_time_start(&start_stat_time);
    mes_check_sid(sid);
    mes_waiting_room_t *room = &g_mes.mes_ctx.waiting_rooms[sid];

    cm_spin_lock(&room->lock, NULL);
    (void)cm_atomic_set(&room->timeout, timeout);
    cm_spin_unlock(&room->lock);

    for (;;) {
        if (mes_check_connect_ready() != CT_SUCCESS) {
            MES_LOGGING_WAR(MES_LOGGING_UNMATCH_MSG, "[mes]%s:Network connection interrupted.", (char *)__func__);
            return CT_ERROR;
        }

        if (!mes_mutex_timed_lock(&room->mutex, MES_WAIT_TIMEOUT)) {
            timeout_time = (uint32)cm_atomic_get(&room->timeout);
            if ((timeout_time == 0) || ((quick_stop_check == CT_TRUE) && (mes_message_need_timeout()))) {
                // when timeout the ack msg may reach, so need do some check and protect.
                mes_protect_when_timeout(room);
                CT_THROW_ERROR_EX(ERR_TCP_TIMEOUT, "sid(%u) recv timeout, rsn=%u, expect_rsn=%u, timeou=%u.",
                    sid, room->rsn, expect_rsn, timeout);
                return CT_ERROR;
            }
            // if tm has been modified concurrently, will return timeout in next loop
            uint32 new_timeout_time = timeout_time > MES_WAIT_TIMEOUT ? timeout_time - MES_WAIT_TIMEOUT : 0;
            (void)cm_atomic_cas(&room->timeout, timeout_time, new_timeout_time);
            continue;
        }

        MES_MESSAGE_ATTACH(msg, room->msg_buf);

        if (SECUREC_UNLIKELY(room->rsn != msg->head->rsn)) {  // this situation should not happen, keep this code to
                                                              // observe some time.
            // rsn not match, ignore this message
            mes_message_head_t *msg_head = (mes_message_head_t *)msg->buffer;
            MES_LOGGING_WAR(MES_LOGGING_UNMATCH_MSG,
                "[mes]%s: sid %u receive unmatch msg, rsn=%u, room rsn=%u, cmd=%u.",
                (char *)__func__, sid, msg_head->rsn, room->rsn, msg_head->cmd);
            mes_release_message_buf(msg->buffer);
            MES_MESSAGE_DETACH(msg);
            continue;
        }

        break;
    }

    mes_consume_with_time(msg->head->cmd, MES_TIME_TEST_RECV, start_stat_time);

    return CT_SUCCESS;
}

status_t mes_recv(uint32 sid, mes_message_t *msg, bool32 check_rsn, uint32 expect_rsn, uint32 timeout)
{
    return mes_recv_impl(sid, msg, check_rsn, expect_rsn, timeout, CT_TRUE);
}

status_t mes_recv_no_quick_stop(uint32 sid, mes_message_t *msg, bool32 check_rsn, uint32 expect_rsn, uint32 timeout)
{
    return mes_recv_impl(sid, msg, check_rsn, expect_rsn, timeout, CT_FALSE);
}

void mes_process_msg_ack(void *session, mes_message_t *msg)
{
    if (msg->head->dst_sid >= CT_MAX_MES_ROOMS) {
        CT_LOG_RUN_ERR("session id(%u) err, larger than %u", msg->head->dst_sid, CT_MAX_MES_ROOMS);
        mes_release_message_buf(msg->buffer);
        return;
    }

    mes_waiting_room_t *room = &g_mes.mes_ctx.waiting_rooms[msg->head->dst_sid];

    mes_consume_with_time(0, MES_TIME_MES_ACK, msg->head->req_start_time);
    cm_spin_lock(&room->lock, NULL);
    if (room->rsn == msg->head->rsn) {
        MES_LOG_HEAD(msg->head);
        room->msg_buf = msg->buffer;
        mes_mutex_unlock(&room->mutex);
        cm_spin_unlock(&room->lock);
    } else {
        cm_spin_unlock(&room->lock);
        MES_LOGGING_WAR(MES_LOGGING_UNMATCH_MSG,
            "[mes]%s: sid %u receive unmatch msg, rsn=%u, room rsn=%u, cmd=%u.",
            (char *)__func__, msg->head->dst_sid, msg->head->rsn, room->rsn, msg->head->cmd);
        mes_release_message_buf(msg->buffer);
    }

    return;
}

status_t mes_wait_acks(uint32 sid, uint32 timeout)
{
    uint32 timeout_time = 0;
    mes_check_sid(sid);
    mes_waiting_room_t *room = &g_mes.mes_ctx.waiting_rooms[sid];

    cm_spin_lock(&room->lock, NULL);
    (void)cm_atomic_set(&room->timeout, timeout);
    cm_spin_unlock(&room->lock);

    for (;;) {
        if (room->req_count == 0) {
            break;
        }
        if (!mes_mutex_timed_lock(&room->broadcast_mutex, MES_WAIT_TIMEOUT)) {
            timeout_time = (uint32)cm_atomic_get(&room->timeout);
            if (timeout_time == 0) {
                room->ack_count = 0; // invalid broadcast ack
                CT_THROW_ERROR_EX(ERR_TCP_TIMEOUT, "sid %u wait rsn=%u timeout, cmd=%u, timeou=%u.",
                    sid, room->rsn, room->cmd, timeout);
                DTC_MES_LOG_INF("[mes]%s: sid %u wait rsn=%u timeout, check rsn=%u, cmd=%u, timeou=%u.",
                    (char *)__func__, sid, room->rsn, room->check_rsn, room->cmd, timeout);
                return CT_ERROR;
            }
            // if tm has been modified concurrently, will return timeout in next loop
            uint32 new_timeout_time = timeout_time > MES_WAIT_TIMEOUT ? timeout_time - MES_WAIT_TIMEOUT : 0;
            (void)cm_atomic_cas(&room->timeout, timeout_time, new_timeout_time);
            continue;
        }

        cm_spin_lock(&room->lock, NULL);
        if (room->ack_count >= room->req_count) {
            cm_spin_unlock(&room->lock);
            break;
        }
        cm_spin_unlock(&room->lock);
    }

    return CT_SUCCESS;
}

static uint64 mes_get_alive_bitmap(void)
{
    cluster_view_t view;
    rc_get_cluster_view(&view, CT_FALSE);
    return view.bitmap;
}

static uint64 mes_get_resend_bitmap(uint32 sid)
{
    mes_waiting_room_t *room = &g_mes.mes_ctx.waiting_rooms[sid];
    uint64 alive_inst = mes_get_alive_bitmap();
    uint64 resend_bitmap = 0;
    for (uint32 i = 0; i < g_mes.profile.inst_count; i++) {
        if (i == g_mes.profile.inst_id) {
            continue;
        }
        if ((rc_bitmap64_exist(&room->req_bitmap, i)) && (!rc_bitmap64_exist(&room->ack_bitmap, i))) {
            if (!rc_bitmap64_exist(&alive_inst, i)) {
                continue;
            }
            rc_bitmap64_set(&resend_bitmap, i);
        }
    }
    CT_LOG_RUN_WAR("[mes]req_bit=%llu, ack_bit=%llu, alive_inst=%llu, resend_bit=%llu, rsn=%u", room->req_bitmap,
                   room->ack_bitmap, alive_inst, resend_bitmap, room->rsn);
    return resend_bitmap;
}

status_t mes_wait_acks_new(uint32 sid, uint32 timeout, uint64 *resend_bits)
{
    uint32 timeout_time = 0;
    mes_check_sid(sid);
    mes_waiting_room_t *room = &g_mes.mes_ctx.waiting_rooms[sid];

    cm_spin_lock(&room->lock, NULL);
    (void)cm_atomic_set(&room->timeout, timeout);
    cm_spin_unlock(&room->lock);

    for (;;) {
        if (room->req_count == 0) {
            break;
        }

        if (!mes_mutex_timed_lock(&room->broadcast_mutex, MES_WAIT_TIMEOUT)) {
            timeout_time = (uint32)cm_atomic_get(&room->timeout);
            if (timeout_time == 0) {
                *resend_bits = mes_get_resend_bitmap(sid);
                if (*resend_bits == 0) {  // fail inst is already down
                    break;
                }
                room->ack_count = 0;  // invalid broadcast ack
                room->ack_bitmap = 0;
                CT_LOG_RUN_WAR("[mes] sid %u wait cmd=%u acks timeout, rsn=%u, check rsn=%u, start_time=%llu",
                    sid, room->cmd, room->rsn, room->check_rsn, room->req_start_time);
                return CT_ERROR;
            }
            // if tm has been modified concurrently, will return timeout in next loop
            uint32 new_timeout_time = timeout_time > MES_WAIT_TIMEOUT ? timeout_time - MES_WAIT_TIMEOUT : 0;
            (void)cm_atomic_cas(&room->timeout, timeout_time, new_timeout_time);
            continue;
        }

        cm_spin_lock(&room->lock, NULL);
        if (room->ack_count >= room->req_count) {
            cm_spin_unlock(&room->lock);
            break;
        }
        cm_spin_unlock(&room->lock);
    }

    return CT_SUCCESS;
}

status_t mes_broadcast_bufflist_and_wait_with_retry(uint32 sid, uint64 target_bits,
    mes_message_head_t *head, uint16 head_size, const void *body, uint32 timeout, uint32 retry_threshold)
{
    uint64 resend_bits = 0;
    uint32 retry_times = 0;
    status_t ret = CT_ERROR;
    mes_check_sid(sid);
    mes_waiting_room_t *room = &g_mes.mes_ctx.waiting_rooms[sid];

    room->err_code = CT_SUCCESS;
    mes_broadcast_bufflist_with_retry(sid, target_bits, head, head_size, body);
    ret = mes_wait_acks_new(sid, timeout, &resend_bits);

    while (ret != CT_SUCCESS) {
        if (retry_times >= retry_threshold) {
            CT_LOG_RUN_ERR("[mes]broadcast and wait exceeds threshold %u.", retry_threshold);
            return CT_ERROR;
        }

        head->rsn = mes_get_rsn(sid);  // the rsn is filled by upper-layer services for the first time.
                                       // In other cases, the rsn needs to be updated
        CT_LOG_RUN_WAR("[mes]need retry broadcast, resend bits %llu, retry_times %u, cmd %u, rsn %u",
            resend_bits, retry_times, head->cmd, head->rsn);
        mes_broadcast_bufflist_with_retry(sid, resend_bits, head, head_size, body);
        ret = mes_wait_acks_new(sid, timeout, &resend_bits);
        retry_times++;
    }

    if (room->err_code != CT_SUCCESS) {
        MES_LOGGING(MES_LOGGING_MESSAGE_STATUS_ERR, "[mes] dst node return false, cmd=%u.", head->cmd);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

void mes_process_broadcast_ack(void *session, mes_message_t *msg)
{
    if (msg->head->dst_sid >= CT_MAX_MES_ROOMS) {
        CT_LOG_RUN_ERR("session id(%u) err, larger than %u", msg->head->dst_sid, CT_MAX_MES_ROOMS);
        mes_release_message_buf(msg->buffer);
        return;
    }
    
    mes_waiting_room_t *room = &g_mes.mes_ctx.waiting_rooms[msg->head->dst_sid];

    cm_spin_lock(&room->lock, NULL);
    if (room->rsn == msg->head->rsn) {
        // TODO: multi nodes, deal with the ret_code in acks
        if (msg->head->status != CT_SUCCESS) {
            room->err_code = msg->head->status;
        }
        (void)cm_atomic32_inc(&room->ack_count);
        rc_bitmap64_set(&room->ack_bitmap, msg->head->src_inst);
        if (room->ack_count >= room->req_count) {
            room->check_rsn = msg->head->rsn;
            mes_mutex_unlock(&room->broadcast_mutex);
        }
        cm_spin_unlock(&room->lock);
    } else {
        cm_spin_unlock(&room->lock);
        MES_LOGGING_WAR(MES_LOGGING_UNMATCH_MSG,
            "[mes]%s: sid %u receive unmatch msg, rsn=%u, room rsn=%u, cmd=%u.",
            (char *)__func__, msg->head->dst_sid, msg->head->rsn, room->rsn, msg->head->cmd);
    }
    mes_release_message_buf(msg->buffer);

    return;
}

static inline void mes_set_inst_bits(uint64 *success_inst, uint64 send_inst)
{
    if (success_inst != NULL) {
        *success_inst = send_inst;
    }
}

static void mes_init_waiting_room(mes_waiting_room_t *room, mes_message_head_t *head, uint64 target_bits)
{
    cm_spin_lock(&room->lock, NULL);
    room->req_count = g_mes.profile.inst_count - 1;
    room->req_bitmap = MES_GET_INST_BITMAP(g_mes.profile.inst_count);
    room->ack_count = 0;
    room->ack_bitmap = 0;
    room->cmd = head->cmd;
    room->req_start_time = head->req_start_time;
    for (uint32 i = 0; i < g_mes.profile.inst_count; i++) {
        if (SECUREC_UNLIKELY(i == g_mes.profile.inst_id)) {
            rc_bitmap64_clear(&(room->req_bitmap), i);
            continue;
        }

        if (!MES_IS_INST_SEND(target_bits, i)) {
            (void)cm_atomic32_dec(&room->req_count);
            rc_bitmap64_clear(&(room->req_bitmap), i);
        }
    }
    cm_spin_unlock(&room->lock);
}

void mes_broadcast(uint32 sid, uint64 inst_bits, const void *msg_data, uint64 *success_inst)
{
    uint64 start_stat_time = 0;
    uint32 i;
    uint64 send_inst = 0;
    mes_check_sid(sid);
    mes_message_head_t *head = (mes_message_head_t *)msg_data;
    mes_waiting_room_t *room = &g_mes.mes_ctx.waiting_rooms[sid];

    cm_spin_lock(&room->lock, NULL);
    room->req_count = g_mes.profile.inst_count - 1;
    room->ack_count = 0;
    room->cmd = head->cmd;
    room->req_start_time = head->req_start_time;
    for (i = 0; i < g_mes.profile.inst_count; i++) {
        if (SECUREC_UNLIKELY(i == g_mes.profile.inst_id)) {
            continue;
        }

        if (!MES_IS_INST_SEND(inst_bits, i)) {
            (void)cm_atomic32_dec(&room->req_count);
        }
    }
    cm_spin_unlock(&room->lock);

    mes_get_consume_time_start(&start_stat_time);

    for (i = 0; i < g_mes.profile.inst_count; i++) {
        if (SECUREC_UNLIKELY(i == g_mes.profile.inst_id)) {
            continue;
        }

        if (MES_IS_INST_SEND(inst_bits, i)) {
            head->dst_inst = i;
            if (mes_send_data(msg_data) != CT_SUCCESS) {
                (void)cm_atomic32_dec(&room->req_count);
                MES_LOGGING_WAR(MES_LOGGING_BROADCAST, "[mes]: multicast to instance %d failed", i);
                // TODO when database is remastering, need cancel current multicasting
                continue;
            }

            MES_INST_SENT_SUCCESS(send_inst, i);
            MES_STAT_SEND(head);
        }
    }

    mes_set_inst_bits(success_inst, send_inst);

    mes_consume_with_time(head->cmd, MES_TIME_TEST_MULTICAST, start_stat_time);

    return;
}

void mes_broadcast_data_with_retry(uint32 sid, uint64 target_bits, const void *msg_data, bool8 allow_send_fail)
{
    uint64 start_stat_time = 0;
    status_t ret = CT_ERROR;
    mes_check_sid(sid);
    mes_message_head_t *head = (mes_message_head_t *)msg_data;
    mes_waiting_room_t *room = &g_mes.mes_ctx.waiting_rooms[sid];
    mes_init_waiting_room(room, head, target_bits);
    mes_get_consume_time_start(&start_stat_time);

    for (uint32 i = 0; i < g_mes.profile.inst_count; i++) {
        if (SECUREC_UNLIKELY(i == g_mes.profile.inst_id)) {
            continue;
        }

        if (!MES_IS_INST_SEND(target_bits, i)) {
            continue;
        }

        head->dst_inst = i;
        do {
            ret = mes_send_data(msg_data);
            if (ret == CT_SUCCESS) {
                MES_STAT_SEND(head);
                break;
            }
            uint64 alive_inst = mes_get_alive_bitmap();
            if (!rc_bitmap64_exist(&alive_inst, i)) {
                (void)cm_atomic32_dec(&room->req_count);
                rc_bitmap64_clear(&(room->req_bitmap), i);
                MES_LOGGING(MES_LOGGING_BROADCAST, "[mes] dst inst %d is not alive, alive_bit %llu, cmd=%u, rsn=%u",
                    i, alive_inst, head->cmd, head->rsn);
                break;
            }
            if (allow_send_fail && !MES_CONNETION_READY(i)) {
                MES_LOGGING(MES_LOGGING_BROADCAST, "[mes] dst inst %d is not connected, cmd=%u, rsn=%u",
                    i, head->cmd, head->rsn);
                break;
            }
            MES_LOGGING(MES_LOGGING_BROADCAST, "[mes] dst inst %u is alive, need retry, alive_bit=%llu, cmd=%u, rsn=%u",
                i, alive_inst, head->cmd, head->rsn);
            cm_sleep(MES_BROADCAST_SEND_TIME_INTERVAL);  // sleep 1s between each retry
        } while (CT_TRUE);
    }

    mes_consume_with_time(head->cmd, MES_TIME_TEST_MULTICAST, start_stat_time);
    return;
}


status_t mes_broadcast_and_wait(uint32 sid, uint64 inst_bits, const void *msg_data, uint32 timeout,
                                uint64 *success_inst)
{
    uint64 start_stat_time = 0;
    mes_get_consume_time_start(&start_stat_time);
    mes_check_sid(sid);
    mes_waiting_room_t *room = &g_mes.mes_ctx.waiting_rooms[sid];

    room->err_code = CT_SUCCESS;
    mes_broadcast(sid, inst_bits, msg_data, success_inst);
    if (mes_wait_acks(sid, timeout) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[mes]mes_wait_acks failed.");
        return CT_ERROR;
    }
    if (room->err_code != CT_SUCCESS) {
        MES_LOGGING(MES_LOGGING_MESSAGE_STATUS_ERR, "[mes] dst node return false, cmd=%u.", ((mes_message_head_t *)msg_data)->cmd);
        return CT_ERROR;
    }
    mes_consume_with_time(((mes_message_head_t *)msg_data)->cmd, MES_TIME_TEST_MULTICAST_AND_WAIT, start_stat_time);

    return CT_SUCCESS;
}

status_t mes_broadcast_data_with_retry_impl(uint32 sid, uint64 target_bits,
    const void *msg_data, uint32 timeout, uint32 retry_threshold, bool8 allow_send_fail)
{
    status_t ret = CT_ERROR;
    uint64 resend_bits = 0;
    uint32 retry_times = 0;
    mes_check_sid(sid);
    mes_waiting_room_t *room = &g_mes.mes_ctx.waiting_rooms[sid];
    mes_message_head_t *head = (mes_message_head_t *)msg_data;

    room->err_code = CT_SUCCESS;
    mes_broadcast_data_with_retry(sid, target_bits, msg_data, allow_send_fail);
    ret = mes_wait_acks_new(sid, timeout, &resend_bits);

    while (ret != CT_SUCCESS) {
        if (retry_times >= retry_threshold) {
            CT_LOG_RUN_ERR("[mes]broadcast and wait exceeds threshold %u.", retry_threshold);
            return CT_ERROR;
        }

        head->rsn = mes_get_rsn(sid);  // the rsn is filled by upper-layer services for the first time.
                                       // In other cases, the rsn needs to be updated
        CT_LOG_RUN_WAR("[mes]need retry broadcast data, resend bits %llu, retry_times %u, cmd %u, rsn %u",
            resend_bits, retry_times, head->cmd, head->rsn);

        mes_broadcast_data_with_retry(sid, target_bits, msg_data, allow_send_fail);
        ret = mes_wait_acks_new(sid, timeout, &resend_bits);
        retry_times++;
    }

    if (room->err_code != CT_SUCCESS) {
        MES_LOGGING(MES_LOGGING_MESSAGE_STATUS_ERR, "[mes] dst node return false, cmd=%u.", head->cmd);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t mes_broadcast_data_and_wait_with_retry(uint32 sid, uint64 target_bits, const void *msg_data, uint32 timeout,
    uint32 retry_threshold)
{
    return mes_broadcast_data_with_retry_impl(sid, target_bits, msg_data, timeout, retry_threshold, CT_FALSE);
}

status_t mes_broadcast_data_and_wait_with_retry_allow_send_fail(uint32 sid, uint64 target_bits, const void *msg_data,
    uint32 timeout, uint32 retry_threshold)
{
    return mes_broadcast_data_with_retry_impl(sid, target_bits, msg_data, timeout, retry_threshold, CT_TRUE);
}

void mes_broadcast_data3(uint32 sid, mes_message_head_t *head, uint32 head_size, const void *body)
{
    uint64 start_stat_time = 0;
    mes_check_sid(sid);
    mes_waiting_room_t *room = &g_mes.mes_ctx.waiting_rooms[sid];

    cm_spin_lock(&room->lock, NULL);
    room->req_count = g_mes.profile.inst_count - 1;
    room->req_bitmap = 0;
    room->ack_count = 0;
    room->ack_bitmap = 0;
    cm_spin_unlock(&room->lock);

    mes_get_consume_time_start(&start_stat_time);

    for (uint32 i = 0; i < g_mes.profile.inst_count; i++) {
        if (i == g_mes.profile.inst_id) {
            continue;
        }

        head->dst_inst = i;

        if (mes_send_data3(head, head_size, body) != CT_SUCCESS) {
            cm_reset_error();
            (void)cm_atomic32_dec(&room->req_count);
            MES_LOGGING(MES_LOGGING_BROADCAST, "MES broadcast to instance %d failed", i);
            continue;
        }
        rc_bitmap64_set(&(room->req_bitmap), i);
        MES_STAT_SEND(head);
    }

    mes_consume_with_time(head->cmd, MES_TIME_TEST_BROADCAST, start_stat_time);

    return;
}

void mes_broadcast_bufflist_with_retry(uint32 sid, uint64 target_bits, mes_message_head_t *head,
    uint16 head_size, const void *body)
{
    uint32 i;
    status_t ret = CT_ERROR;
    mes_check_sid(sid);
    mes_waiting_room_t *room = &g_mes.mes_ctx.waiting_rooms[sid];
    mes_init_waiting_room(room, head, target_bits);

    for (i = 0; i < g_mes.profile.inst_count; i++) {
        if (i == g_mes.profile.inst_id) {
            continue;
        }
        if (!MES_IS_INST_SEND(target_bits, i)) {
            continue;
        }

        head->dst_inst = i;
        do {
            ret = mes_send_data3(head, head_size, body);
            if (ret == CT_SUCCESS) {
                MES_STAT_SEND(head);
                break;
            }
            uint64 alive_inst = mes_get_alive_bitmap();
            if (!rc_bitmap64_exist(&alive_inst, i)) {
                (void)cm_atomic32_dec(&room->req_count);
                rc_bitmap64_clear(&(room->req_bitmap), i);
                MES_LOGGING(MES_LOGGING_BROADCAST, "[mes] dst inst %d is not alive, alive_bit %llu, cmd=%u, rsn=%u",
                    i, alive_inst, head->cmd, head->rsn);
                break;
            }
            MES_LOGGING(MES_LOGGING_BROADCAST, "[mes] dst inst %u is alive, need retry, alive_bit=%llu, cmd=%u, rsn=%u",
                i, alive_inst, head->cmd, head->rsn);
            cm_sleep(MES_BROADCAST_SEND_TIME_INTERVAL);  // sleep 1s between each retry
        } while (CT_TRUE);
    }
    return;
}

status_t mes_message_vertify_cks(mes_message_t *msg)
{
    if (msg == NULL) {
        CT_LOG_RUN_ERR("mes vertify cks input msg is null");
        return CT_ERROR;
    }

    uint16 cks;
    uint16 headSize = sizeof(mes_message_head_t) + msg->head->extend_size;
    if (!mes_verify_cks(msg->head->head_cks, (char *)msg->head + sizeof(msg->head->head_cks), headSize -
        sizeof(msg->head->head_cks), &cks)) {
        mes_release_message_buf(msg->buffer);
        CT_LOG_RUN_ERR("[mes] check head cks failed, cks=%u, old cks=%u, msg_size=%u, ext_size=%u, "
            "cmd=%u, rsn=%u, src_inst=%u, dst_inst=%u, src_sid=%u, dst_sid=%u", cks, msg->head->head_cks,
            msg->head->size, msg->head->extend_size, msg->head->cmd, msg->head->rsn, msg->head->src_inst,
            msg->head->dst_inst, msg->head->src_sid, msg->head->dst_sid);
        return CT_ERROR;
    }

    char *body = msg->buffer + headSize;
    if (!mes_verify_cks(msg->head->body_cks, body, msg->head->size - headSize, &cks)) {
        mes_release_message_buf(msg->buffer);
        CT_LOG_RUN_ERR("[mes] check cks failed, cks=%u, old cks=%u, msg_size=%u, ext_size=%u, "
            "cmd=%u, rsn=%u, src_inst=%u, dst_inst=%u, src_sid=%u, dst_sid=%u", cks, msg->head->body_cks,
            msg->head->size, msg->head->extend_size, msg->head->cmd, msg->head->rsn, msg->head->src_inst,
            msg->head->dst_inst, msg->head->src_sid, msg->head->dst_sid);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

// add function
status_t mes_register_proc_func(mes_message_proc_t proc)
{
    g_mes.proc = proc;

    return CT_SUCCESS;
}

void mes_set_msg_enqueue(mes_command_t command, bool32 is_enqueue)
{
    g_mes.is_enqueue[command] = is_enqueue;

    return;
}

bool32 mes_get_msg_enqueue(mes_command_t command)
{
    return g_mes.is_enqueue[command];
}

uint32 mes_get_msg_queue_length(uint8 group_id)
{
    return g_mes.mq_ctx.group.task_group[group_id].queue.count;
}

uint32 mes_get_msg_task_queue_length(uint32 task_index)
{
    return g_mes.mq_ctx.tasks[task_index].queue.count;
}

mes_channel_stat_t mes_get_channel_state(uint8 inst_id)
{
    if (g_mes.profile.pipe_type == CS_TYPE_TCP) {
        return mes_tcp_get_channel_state(inst_id);
    } else if (g_mes.profile.pipe_type == CS_TYPE_UC || g_mes.profile.pipe_type == CS_TYPE_UC_RDMA) {
        return mes_uc_get_channel_state(inst_id);
    }
    return MES_CHANNEL_CEIL;
}

thread_t* mes_get_msg_task_thread(uint32 task_index)
{
    return &(g_mes.mq_ctx.tasks[task_index].thread);
}

uint32 mes_get_rsn(uint32 sid)
{
    uint32 rsn;
    mes_check_sid(sid);
    mes_waiting_room_t *room = &g_mes.mes_ctx.waiting_rooms[sid];

    cm_spin_lock(&room->lock, NULL);
    rsn = cm_atomic32_inc((atomic32_t *)(&room->rsn));
    cm_spin_unlock(&room->lock);

    return rsn;
}

uint32 mes_get_current_rsn(uint32 sid)
{
    uint32 rsn;
    mes_check_sid(sid);
    mes_waiting_room_t *room = &g_mes.mes_ctx.waiting_rooms[sid];

    cm_spin_lock(&room->lock, NULL);
    rsn = room->rsn;
    cm_spin_unlock(&room->lock);

    return rsn;
}
#ifdef WIN32
void mes_mutex_destroy(mes_mutex_t *mutex)
{
    (void)CloseHandle(*mutex);
}

status_t mes_mutex_create(mes_mutex_t *mutex)
{
    *mutex = CreateSemaphore(NULL, 0, CT_MAX_MES_ROOMS, NULL);
    if (*mutex == NULL) {
        CT_THROW_ERROR_EX(ERR_MES_CREATE_MUTEX, "errno: %d", GetLastError());
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

void mes_mutex_lock(mes_mutex_t *mutex)
{
    (void)WaitForSingleObject(*mutex, INFINITE);
}

bool32 mes_mutex_timed_lock(mes_mutex_t *mutex, uint32 timeout)
{
    uint32 code = WaitForSingleObject(*mutex, timeout);
    return (code == WAIT_OBJECT_0);
}

void mes_mutex_unlock(mes_mutex_t *mutex)
{
    ReleaseSemaphore(*mutex, 1, NULL);
}

#else
void mes_mutex_destroy(mes_mutex_t *mutex)
{
    (void)pthread_mutex_destroy(mutex);
}

status_t mes_mutex_create(mes_mutex_t *mutex)
{
    if (0 != pthread_mutex_init(mutex, NULL)) {
        CT_THROW_ERROR_EX(ERR_MES_CREATE_MUTEX, "errno: %d", (int32)errno);
        return CT_ERROR;
    }

    (void)pthread_mutex_lock(mutex);
    return CT_SUCCESS;
}

void mes_mutex_lock(mes_mutex_t *mutex)
{
    (void)pthread_mutex_lock(mutex);
}

void mes_get_timespec(struct timespec *tim, uint32 timeout)
{
    struct timespec tv;
    (void)clock_gettime(CLOCK_REALTIME, &tv);

    tim->tv_sec = tv.tv_sec + timeout / 1000;
    tim->tv_nsec = tv.tv_nsec + ((long)timeout % 1000) * 1000000;
    if (tim->tv_nsec >= 1000000000) {
        tim->tv_sec++;
        tim->tv_nsec -= 1000000000;
    }
}

bool32 mes_mutex_timed_lock(mes_mutex_t *mutex, uint32 timeout)
{
    struct timespec ts;
    // cm_get_timespec(&ts, timeout);
    mes_get_timespec(&ts, timeout);

    return (pthread_mutex_timedlock(mutex, &ts) == 0);
}

void mes_mutex_unlock(mes_mutex_t *mutex)
{
    (void)pthread_mutex_unlock(mutex);
}
#endif

void cm_get_time_of_day(cm_timeval *tv)
{
    int ret;

    ret = cm_gettimeofday(tv);
    if (ret != 0) {
        perror("[Time Error]cm_get_time_of_day error");
    }
}

uint64 cm_get_time_usec(void)
{
    if (g_mes_elapsed_stat.mes_elapsed_switch) {
        cm_timeval now;
        uint64 now_usec;

        cm_get_time_of_day(&now);

        now_usec = (uint64)now.tv_sec * (uint64)(1000 * 1000) + (uint64)now.tv_usec;
        return now_usec;
    }
    return 0;
}

void mes_send_error_msg(mes_message_head_t *head)
{
    mes_error_msg_t error_msg;

    mes_init_ack_head(head, &error_msg.head, MES_CMD_ERROR_MSG, sizeof(mes_error_msg_t) + CT_MESSAGE_BUFFER_SIZE,
                      CT_INVALID_ID16);
    error_msg.code = g_tls_error.code;
    error_msg.loc = g_tls_error.loc;

    if (mes_send_data3(&error_msg.head, sizeof(mes_error_msg_t), g_tls_error.message) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("send error msg to instance %d failed.", head->src_inst);
    }

    cm_reset_error();
}

void mes_handle_error_msg(const void *msg_data)
{
    mes_error_msg_t *error_msg = (mes_error_msg_t *)msg_data;
    char *message = (char *)error_msg + sizeof(mes_error_msg_t);
    errno_t ret;

    if (g_tls_error.is_ignored) {
        return;
    }

    g_tls_error.code = error_msg->code;
    g_tls_error.loc = error_msg->loc;
    ret = memcpy_sp(g_tls_error.message, CT_MESSAGE_BUFFER_SIZE, message, CT_MESSAGE_BUFFER_SIZE);
    MEMS_RETVOID_IFERR(ret);
}

int64 mes_get_stat_send_count(mes_command_t cmd)
{
    return g_mes_stat[cmd].send_count;
}
int64 mes_get_stat_send_fail_count(mes_command_t cmd)
{
    return g_mes_stat[cmd].send_fail_count;
}

int64 mes_get_stat_recv_count(mes_command_t cmd)
{
    return g_mes_stat[cmd].recv_count;
}

int64 mes_get_stat_local_count(mes_command_t cmd)
{
    return g_mes_stat[cmd].local_count;
}

atomic32_t mes_get_stat_dealing_count(mes_command_t cmd)
{
    return g_mes_stat[cmd].dealing_count;
}

bool8 mes_get_stat_non_empty(mes_command_t cmd)
{
    return g_mes_stat[cmd].non_empty;
}

bool8 mes_get_elapsed_switch(void)
{
    return g_mes_elapsed_stat.mes_elapsed_switch;
}

void mes_set_elapsed_switch(bool8 elapsed_switch)
{
    g_mes_elapsed_stat.mes_elapsed_switch = elapsed_switch;
    CT_LOG_RUN_INF("mes elapsed switch = %d.", g_mes_elapsed_stat.mes_elapsed_switch);
}

void mes_set_crc_check_switch(bool8 crc_check_switch)
{
    g_mes.crc_check_switch = crc_check_switch;
    CT_LOG_RUN_INF("mes crc check switch = %d.", g_mes.crc_check_switch);
}

void mes_set_ssl_switch(bool8 use_ssl)
{
    g_mes.profile.use_ssl = use_ssl;
    CT_LOG_RUN_INF("[mes] ssl switch = %d.", g_mes.profile.use_ssl);
}

status_t mes_set_ssl_crt_file(const char *cert_dir, const char *ca_file, const char *cert_file, const char *key_file, const char* crl_file, const char* pass_file)
{
    if (cert_dir == NULL || ca_file == NULL || cert_dir == NULL || key_file == NULL || crl_file == NULL || pass_file == NULL) {
        return CT_ERROR;
    }
    MEMS_RETURN_IFERR(memcpy_sp(g_mes_ssl_auth_file.cert_dir, CT_FILE_NAME_BUFFER_SIZE, cert_dir, CT_FILE_NAME_BUFFER_SIZE));
    MEMS_RETURN_IFERR(memcpy_sp(g_mes_ssl_auth_file.ca_file, CT_FILE_NAME_BUFFER_SIZE, ca_file, CT_FILE_NAME_BUFFER_SIZE));
    MEMS_RETURN_IFERR(memcpy_sp(g_mes_ssl_auth_file.cert_file, CT_FILE_NAME_BUFFER_SIZE, cert_file, CT_FILE_NAME_BUFFER_SIZE));
    MEMS_RETURN_IFERR(memcpy_sp(g_mes_ssl_auth_file.key_file, CT_FILE_NAME_BUFFER_SIZE, key_file, CT_FILE_NAME_BUFFER_SIZE));
    MEMS_RETURN_IFERR(memcpy_sp(g_mes_ssl_auth_file.pass_file, CT_FILE_NAME_BUFFER_SIZE, pass_file, CT_FILE_NAME_BUFFER_SIZE));
    if (cm_file_exist(crl_file)) {
        MEMS_RETURN_IFERR(memcpy_sp(g_mes_ssl_auth_file.crl_file, CT_FILE_NAME_BUFFER_SIZE, crl_file, CT_FILE_NAME_BUFFER_SIZE));
    } else {
        MEMS_RETURN_IFERR(memset_sp(g_mes_ssl_auth_file.crl_file, CT_FILE_NAME_BUFFER_SIZE, 0, CT_FILE_NAME_BUFFER_SIZE));
    }
    
    return CT_SUCCESS;
}

status_t mes_set_ssl_key_pwd(const char *enc_pwd)
{
    if (enc_pwd != NULL) {
        MEMS_RETURN_IFERR(memcpy_sp(g_mes_ssl_auth_file.key_pwd, CT_PASSWORD_BUFFER_SIZE, enc_pwd, strlen(enc_pwd)));
    } else {
        MEMS_RETURN_IFERR(memset_sp(g_mes_ssl_auth_file.key_pwd, CT_PASSWORD_BUFFER_SIZE, 0, CT_PASSWORD_BUFFER_SIZE));
    }

    return CT_SUCCESS;
}

void mes_set_ssl_verify_peer(bool32 verify_peer)
{
    g_mes.profile.ssl_verify_peer = verify_peer;
}

ssl_auth_file_t *mes_get_ssl_auth_file(void)
{
    return &g_mes_ssl_auth_file;
}

void mes_set_dbstor_enable(bool32 enable)
{
    g_enable_dbstor = enable;
}

uint64 mes_get_elapsed_time(mes_command_t cmd, mes_time_stat_t type)
{
    return g_mes_elapsed_stat.time_consume_stat[cmd].time[type];
}

int64 mes_get_elapsed_count(mes_command_t cmd, mes_time_stat_t type)
{
    return g_mes_elapsed_stat.time_consume_stat[cmd].count[type];
}

bool8 mes_get_elapsed_non_empty(mes_command_t cmd)
{
    return g_mes_elapsed_stat.time_consume_stat[cmd].non_empty;
}

bool8 mes_is_inst_connect(uint32 inst_id)
{
    return g_mes.mes_ctx.conn_arr[inst_id].is_connect;
}
uint8 mes_get_cmd_group(mes_command_t cmd)
{
    return g_mes.mq_ctx.command_attr[cmd].group_id;
}

void mes_init_mq_local_queue(void)
{
    init_msgqueue(&g_mes.mq_ctx.local_queue);
}

status_t mes_set_process_config(void)
{
    return mes_uc_set_process_config();
}