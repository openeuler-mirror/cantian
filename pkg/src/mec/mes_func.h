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
 * mes_func.h
 *
 *
 * IDENTIFICATION
 * src/mec/mes_func.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef DTC_MEC_MES_H__
#define DTC_MEC_MES_H__

#include "cm_defs.h"
#include "cm_thread.h"
#include "cm_timer.h"
#include "cs_pipe.h"
#include "cs_listener.h"
#include "cm_checksum.h"
#include "knl_common.h"
#include "mes_queue.h"
#include "mes_tcp.h"
#include "mes_config.h"
#include "mes_uc.h"
#include "mes_msg_pool.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MES_CONNECT_TIMEOUT (5000)  // mill-seconds
#define MES_BROADCAST_ALL_INST (0xFFFFFFFFFFFFFFFF)

#define MES_INSTANCE_ID(id) (uint8)((id) >> 8)
#define MES_CHANNEL_ID(id) (uint8)((id) & 0x00FF)

#define MES_URL_BUFFER_SIZE (GS_HOST_NAME_BUFFER_SIZE + 16)
#define MSE_MESSAGE_SHORT_BUFFER_SIZE (64)
#define MES_SHORT_POOL_SIZE_PARA (512)
#define MES_MESSAGE_TINY_SIZE (64) /* buf_id 4 + head 12 + body 48 */
#define MES_MESSAGE_BUFFER_SIZE \
    (uint32)(SIZE_K(32) + MES_MESSAGE_TINY_SIZE) /* biggest: pcr page ack: head + ack + page */
#define MES_128K_MESSAGE_BUFFER_SIZE (uint32)SIZE_K(128)
#define MES_LOGGING_INTERVAL (60000)             // ms
#define MES_WAIT_TIMEOUT (5)                     // ms
#define MES_WAIT_MAX_TIME (0xFFFFFFFF)           // ms
#define MES_MSG_RETRY_TIME (100)                 // ms
#define MES_DEFALT_THREAD_NUM (16)
#define MES_RECV_THREAD_IDX (0)
#define MES_MAX_BUFFERLIST (4) /* Number of buffers supported by the bufferlist */
#define MES_POOL_FLAG_SIZE (1)
#define MES_MESSAGE_HEAD_SIZE (sizeof(mes_message_head_t))
#define MES_MIN_TASK_NUM (1)
#define MES_MAX_TASK_NUM (1000)
#define MES_GET_BITMAP_TIME_INTERVAL  (1000)  // ms
#define MES_BROADCAST_SEND_TIME_INTERVAL  (1000)  // ms

#define MES_GET_INST_BITMAP(inst_count) (((0x1) << (inst_count)) - 1)
#define MES_IS_INST_SEND(bits, id) (((bits) >> (id)) & 0x1)
#define MES_INST_SENT_SUCCESS(bits, id) (bits) |= (0x1 << (id))
#define MEG_GET_BUF_ID(msg_buf) (*(uint32 *)((char *)(msg_buf) - sizeof(uint32)))
typedef bool32 (*message_timeout_check_func)(void);
void mes_set_message_timeout_check_func(message_timeout_check_func func);

#define MES_LOGGING(id, fmt, ...)                                                            \
    do {                                                                                     \
        if (g_mes.mes_ctx.logging_time[id] + MES_LOGGING_INTERVAL * 1000 < g_timer()->now) { \
            GS_LOG_RUN_ERR(fmt, ##__VA_ARGS__);                                              \
            g_mes.mes_ctx.logging_time[id] = g_timer()->now;                                 \
        }                                                                                    \
    } while (0)


#define MES_LOGGING_WAR(id, fmt, ...)                                                        \
    do {                                                                                     \
        if (g_mes.mes_ctx.logging_time[id] + MES_LOGGING_INTERVAL * 1000 < g_timer()->now) { \
            GS_LOG_RUN_WAR(fmt, ##__VA_ARGS__);                                              \
            g_mes.mes_ctx.logging_time[id] = g_timer()->now;                                 \
        }                                                                                    \
    } while (0)


#define DTC_MES_LOG_INF(format, ...)                                                                             \
    do {                                                                                                         \
        if (DTC_MES_LOG_INF_ON) {                                                                                \
            cm_write_normal_log(LOG_DEBUG, LEVEL_INFO, (char *)__FILE__, (uint32)__LINE__, MODULE_NAME, GS_TRUE, \
                                format, ##__VA_ARGS__);                                                          \
        }                                                                                                        \
    } while (0)

#define DTC_MES_LOG_ERR(format, ...)                                                                              \
    do {                                                                                                          \
        if (DTC_MES_LOG_ERR_ON) {                                                                                 \
            cm_write_normal_log(LOG_DEBUG, LEVEL_ERROR, (char *)__FILE__, (uint32)__LINE__, MODULE_NAME, GS_TRUE, \
                                format, ##__VA_ARGS__);                                                           \
        }                                                                                                         \
    } while (0)

#define MES_LOG_DEBUG(cmd, fmt, ...)             \
    do {                                         \
        if (cmd != MES_CMD_SCN_BROADCAST) {      \
            DTC_MES_LOG_INF(fmt, ##__VA_ARGS__); \
        }                                        \
    } while (0)

#define MES_LOG_WITH_MSG(msg)                                                                                       \
    do {                                                                                                            \
        MES_LOG_DEBUG((msg)->head->cmd, "[mes]%s: cmd=%u, rsn=%u, src_inst=%u, dst_inst=%u, src_sid=%u, "           \
            "dst_sid=%u, ext_size=%u, head_cks=%u, body_cks=%u, buf_id=%u", (char *)__func__,            \
            (msg)->head->cmd, (msg)->head->rsn, (msg)->head->src_inst, (msg)->head->dst_inst, (msg)->head->src_sid, \
            (msg)->head->dst_sid, (msg)->head->extend_size, (msg)->head->head_cks, (msg)->head->body_cks,           \
            MEG_GET_BUF_ID((msg)->buffer));                                                          \
    } while (0);

#define MES_LOG_HEAD_BUF(head, buffer)                                                                              \
    do {                                                                                                            \
        MES_LOG_DEBUG((head)->cmd, "[mes]%s: cmd=%u, rsn=%u, src_inst=%u, dst_inst=%u, src_sid=%u, dst_sid=%u, "    \
            "ext_size=%u, head_cks=%u, body_cks=%u, buf_id=%u.", (char *)__func__, (head)->cmd,          \
            (head)->rsn, (head)->src_inst, (head)->dst_inst, (head)->src_sid, (head)->dst_sid, (head)->extend_size, \
            (head)->head_cks, (head)->body_cks, MEG_GET_BUF_ID(buffer));                                    \
    } while (0);

#define MES_LOG_HEAD(head)                                                                                          \
    do {                                                                                                            \
        MES_LOG_DEBUG((head)->cmd, "[mes]%s: cmd=%u, rsn=%u, src_inst=%u, dst_inst=%u, src_sid=%u, dst_sid=%u, "    \
            "ext_size=%u, head_cks=%u, body_cks=%u.", (char *)__func__, (head)->cmd, (head)->rsn, (head)->src_inst, \
            (head)->dst_inst, (head)->src_sid, (head)->dst_sid, (head)->extend_size, (head)->head_cks,              \
            (head)->body_cks);                                                                                      \
    } while (0);

#define MES_LOG_HEAD_AND_PIPE(head, pipe)                                                                           \
    do {                                                                                                            \
        MES_LOG_DEBUG((head)->cmd, "[mes]%s: cmd=%u, head_size=%u, rsn=%u, src_inst=%u, dst_inst=%u, src_sid=%u, "  \
            "dst_sid=%u, ext_size=%u, head_cks=%u, body_cks=%u, pipe socket %d, closed %d.", (char *)__func__,      \
            (head)->cmd, (head)->size, (head)->rsn, (head)->src_inst, (head)->dst_inst, (head)->src_sid,            \
            (head)->dst_sid, (head)->extend_size, (head)->head_cks, (head)->body_cks, (pipe)->link.tcp.sock,        \
            (pipe)->link.tcp.closed);                                                                               \
    } while (0);
 
// for send fail message
#define MES_LOG_HEAD_FAIL(head)                                                                                     \
    do {                                                                                                            \
        MES_LOG_DEBUG((head)->cmd, "[mes]%s: send fail message, cmd=%u, rsn=%u, src_inst=%u, dst_inst=%u, "         \
            "src_sid=%u,dst_sid=%u, ext_size=%u, head_cks=%u, body_cks=%u.", (char *)__func__, (head)->cmd,         \
            (head)->rsn, (head)->src_inst, (head)->dst_inst, (head)->src_sid, (head)->dst_sid, (head)->extend_size, \
            (head)->head_cks, (head)->body_cks);                                                                    \
    } while (0);

#define MES_LOG_HEAD_EX(head, message)                                                                               \
    do {                                                                                                             \
        MES_LOG_DEBUG((head)->cmd, "[mes]%s: %s. cmd=%u, rsn=%u, src_inst=%u, dst_inst=%u, src_sid=%u, dst_sid=%u, " \
            "ext_size=%u, head_cks=%u, body_cks=%u.", (char *)__func__, message, (head)->cmd, (head)->rsn,           \
            (head)->src_inst, (head)->dst_inst, (head)->src_sid, (head)->dst_sid, (head)->extend_size,               \
            (head)->head_cks, (head)->body_cks);                                                                     \
    } while (0);

#define MES_LOG_WAR_HEAD_EX(head, message)                                                                           \
    do {                                                                                                             \
        GS_LOG_RUN_WAR("[mes]%s: %s. cmd=%u, rsn=%u, src_inst=%u, dst_inst=%u, src_sid=%u, dst_sid=%u, "             \
            "ext_size=%u, head_cks=%u, body_cks=%u.", (char *)__func__, message, (head)->cmd, (head)->rsn,           \
            (head)->src_inst, (head)->dst_inst, (head)->src_sid, (head)->dst_sid, (head)->extend_size,               \
            (head)->head_cks, (head)->body_cks);                                                                     \
    } while (0);

#define MES_LOG_ERR_HEAD_EX(head, message)                                                                           \
    do {                                                                                                             \
        GS_LOG_RUN_ERR("[mes]%s: %s. cmd=%u, rsn=%u, src_inst=%u, dst_inst=%u, src_sid=%u, dst_sid=%u, "             \
            "ext_size=%u, head_cks=%u, body_cks=%u.", (char *)__func__, message, (head)->cmd, (head)->rsn,           \
            (head)->src_inst, (head)->dst_inst, (head)->src_sid, (head)->dst_sid, (head)->extend_size,               \
            (head)->head_cks, (head)->body_cks);                                                                     \
    } while (0);

typedef enum en_mes_time_stat {
    MES_TIME_TEST_SEND = 0,
    MES_TIME_SEND_IO,
    MES_TIME_TEST_SEND_ACK,
    MES_TIME_TEST_RECV,
    MES_TIME_TEST_BROADCAST,
    MES_TIME_TEST_BROADCAST_AND_WAIT,
    MES_TIME_TEST_MULTICAST,
    MES_TIME_TEST_MULTICAST_AND_WAIT,
    MES_TIME_MES_ACK,
    MES_TIME_MES_WACKUP,
    MES_TIME_GET_BUF,  // from send to this proc, record the real consume time of every proc
    MES_TIME_READ_MES,
    MES_TIME_PUT_QUEUE,
    MES_TIME_GET_QUEUE,
    MES_TIME_QUEUE_PROC,  // from read_mes to here, record the sum consume time until ervery proc
    MES_TIME_PROC_FUN,
    MES_TIME_ACK_SEND,
    MES_TIME_PUT_BUF,
    MES_TIME_TEST_CHECK,
    MES_TIME_CEIL
} mes_time_stat_t;

typedef struct st_mes_time_consume {
    uint32 cmd;  // command
    uint8 group_id;
    uint64 time[MES_TIME_CEIL];
    int64 count[MES_TIME_CEIL];
    bool8 non_empty;
} mes_time_consume_t;

typedef struct st_mes_elapsed_stat {
    bool32 mes_elapsed_switch;
    mes_time_consume_t time_consume_stat[MES_CMD_CEIL];
} mes_elapsed_stat_t;

typedef struct st_mes_stat {
    uint32 cmd;
    int64 send_count;
    int64 send_fail_count;
    int64 send_callback;
    int64 send_callback_fail;
    int64 recv_count;
    int64 local_count;
    atomic32_t dealing_count;
    bool8 non_empty;
} mes_stat_t;

typedef struct st_mes_queue_t {
    uint8 group_id;
    uint32 queue_len;
    bool8 non_empty;
} mes_queue_t;

typedef struct st_mes_task_queue_t {
    uint32 task_index;
    uint32 queue_len;
    bool8 non_empty;
} mes_task_queue_t;

typedef enum en_mes_logging_id {
    MES_LOGGING_CONNECT = 0,
    MES_LOGGING_SEND,
    MES_LOGGING_RECV,
    MES_LOGGING_BROADCAST,
    MES_LOGGING_GET_QUEUE,
    MES_LOGGING_GET_BUF,
    MES_LOGGING_MESSAGE_STATUS_ERR,
    MES_LOGGING_UNMATCH_MSG,
    MES_LOGGING_CEIL,
} mes_logging_id_t;

#ifdef WIN32
typedef HANDLE mes_mutex_t;
#else
typedef pthread_mutex_t mes_mutex_t;
#endif

#define MES_MESSAGE_ATTACH(msg, buf)             \
    do {                                            \
        (msg)->buffer = buf;                     \
        (msg)->head = (mes_message_head_t *)(buf); \
    } while (0)

#define MES_MESSAGE_DETACH(msg) \
    do {                           \
        (msg)->buffer = NULL;   \
        (msg)->head = NULL;     \
    } while (0)

#define MES_MESSAGE_BODY(msg) ((msg)->buffer + sizeof(mes_message_head_t))

typedef void (*mes_message_proc_t)(uint32 work_thread, mes_message_t *message);

typedef status_t (*mes_connect_t)(uint32 inst_id);

typedef void (*mes_disconnect_t)(uint32 inst_id);

typedef void (*mes_async_disconnect_t)(uint32 inst_id);

typedef status_t (*mes_send_data_t)(const void *msg_data);

typedef status_t (*mes_send_bufflist_t)(mes_bufflist_t *buff_list);

typedef void (*mes_release_buf_t)(const char *buffer);

typedef bool32 (*mes_connection_ready_t)(uint32 inst_id);

typedef dtc_msgitem_t *(*mes_alloc_msgitem_t)(dtc_msgqueue_t *queue);

typedef struct st_mes_lsnr {
    tcp_lsnr_t tcp;
} mes_lsnr_t;

typedef struct st_mes_waiting_room {
    mes_mutex_t mutex;            // msg ack wake up mes_recv
    mes_mutex_t broadcast_mutex;  // broadcast acks wake up mes_wait_acks
    spinlock_t lock;              // protect rsn
    void *msg_buf;
    uint32 err_code;
    atomic_t timeout;
    atomic32_t req_count;
    atomic32_t ack_count;
    uint64 req_bitmap;
    uint64 ack_bitmap;
    volatile uint32 rsn;  // requestion sequence number
    volatile uint32 check_rsn;
    uint8      cmd;
    uint64     req_start_time;
} mes_waiting_room_t;

typedef struct st_mes_conn {
    thread_lock_t lock;
    bool8 is_connect;
} mes_conn_t;

typedef struct st_mes_context {
    mes_lsnr_t lsnr;
    mes_channel_t **channels;
    mes_pool_t msg_pool;
    mes_conn_t conn_arr[GS_MAX_INSTANCES];
    mes_waiting_room_t waiting_rooms[GS_MAX_MES_ROOMS];
    date_t logging_time[MES_LOGGING_CEIL];
    uint32 work_thread_idx[GS_DTC_MAX_TASK_NUM];
    ssl_ctx_t *send_ctx;
    ssl_ctx_t *recv_ctx;
} mes_context_t;

typedef struct st_mes_addr {
    char ip[CM_MAX_IP_LEN];
    uint16 port;
    uint8 reserved[2];
} mes_addr_t;

typedef struct st_mes_profile {
    bool32 is_init;
    uint32 inst_id;
    uint32 inst_count;
    cs_pipe_type_t pipe_type;
    uint32 pool_size;
    uint32 channel_num;
    mes_buffer_pool_attr_t buffer_pool_attr;
    uint32 work_thread_num;
    uint32 reactor_thread_num;
    mes_addr_t inst_arr[GS_MAX_INSTANCES];
    uint32 inst_lsid[GS_MAX_INSTANCES];
    mes_message_proc_t proc;  // to compile extproc
    char dpumm_config_path[GS_FILE_NAME_BUFFER_SIZE];
    uint64 channel_version;   // used by UC
    bool32 conn_by_profile;
    bool8 need_mq_thread;     // to compile extproc
    ssl_config_t ssl_config;
    bool8 use_ssl;
    uint8 unused[2];          // reserved 3 bytes
} mes_profile_t;

typedef struct st_mes_instance {
    mes_profile_t profile;
    mes_context_t mes_ctx;
    mq_context_t mq_ctx;
    mes_message_proc_t proc;
    bool32 is_enqueue[MES_CMD_CEIL];
    bool8 crc_check_switch;
} mes_instance_t;

typedef struct st_mes_error_msg {
    mes_message_head_t head;
    int32 code;
    source_location_t loc;
} mes_error_msg_t;

typedef struct timeval cm_timeval;

static __inline uint64 db_rdtsc(void)
{
#ifdef WIN32
    return __rdtsc();
#else
    /*lint -save -e530 */
    uint32 lo, hi;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return (((uint64)hi << 32) | lo);
#endif
}

extern mes_time_consume_t g_elapsed_stat[];
extern uint64 g_start_time;
extern mes_elapsed_stat_t g_mes_elapsed_stat;

extern mes_instance_t g_mes;
extern mes_stat_t g_mes_stat[MES_CMD_CEIL];

extern bool32 g_enable_dbstor;

uint64 cm_get_time_usec(void);

static inline void mes_consume_time(mes_command_t cmd, mes_time_stat_t type)
{
    if (g_mes_elapsed_stat.mes_elapsed_switch) {
        g_mes_elapsed_stat.time_consume_stat[cmd].time[type] += cm_get_time_usec() - g_start_time;
        // g_elapsed_stat[type].count++;
        cm_atomic_inc(&(g_mes_elapsed_stat.time_consume_stat[cmd].count[type]));
    }
    return;
}

static inline void mes_get_consume_time_start(uint64 *stat_time)
{
    if (g_mes_elapsed_stat.mes_elapsed_switch) {
        *stat_time = cm_get_time_usec();
    }

    return;
}

static inline void mes_consume_with_time(mes_command_t cmd, mes_time_stat_t type, uint64 start_time)
{
    if (g_mes_elapsed_stat.mes_elapsed_switch) {
        if (start_time == 0) {  // avoid open mes_elapsed_switch in running status
            return;
        }
        g_mes_elapsed_stat.time_consume_stat[cmd].time[type] += cm_get_time_usec() - start_time;
        cm_atomic_inc(&(g_mes_elapsed_stat.time_consume_stat[cmd].count[type]));
    }
    return;
}

static inline void mes_elapsed_stat(mes_command_t cmd, mes_time_stat_t type)
{
    if (g_mes_elapsed_stat.mes_elapsed_switch) {
        cm_atomic_inc(&(g_mes_elapsed_stat.time_consume_stat[cmd].count[type]));
    }
    return;
}
static inline void mes_check_sid(uint32 sid)
{
    if (SECUREC_UNLIKELY(sid >= GS_MAX_MES_ROOMS)) {
        GS_THROW_ERROR_EX(ERR_MES_PARAMETER, "[mes][%s]: sid %u is illegal.", (char *)__func__, sid);
        knl_panic_log(0, "[mes][%s]: sid %u is illegal.", (char *)__func__, sid);
    }
    return;
}

static inline uint16 mes_calc_cks(void *msg_data, uint16 msg_size)
{
    uint32 cks = cm_get_checksum(msg_data, msg_size);
    return REDUCE_CKS2UINT16(cks);
}

static inline bool8 mes_verify_cks(uint16 old_cks, void *msg_data, uint16 msg_size, uint16 *new_cks)
{
    *new_cks = mes_calc_cks(msg_data, msg_size);
    return (old_cks == *new_cks);
}

mes_instance_t *get_g_mes(void);
mes_stat_t *get_g_mes_stat(void);
status_t mes_set_profile(mes_profile_t *profile);
status_t mes_set_uc_dpumm_config_path(const char *home_path);
status_t mes_startup(void);
void mes_clean(void);
void mes_init_stat(void);

status_t mes_connect(uint32 inst_id, char *ip, uint16 port);
bool32 mes_connection_ready(uint32 inst_id);
status_t mes_disconnect(uint32 inst_id, bool32 isSync);  // FALSE means async, only dtc abort process need now
void mes_wakeup_rooms(void);

status_t mes_cms_send_data(const void *msg_data);
status_t mes_send_data(const void *msg_data);
status_t mes_send_data2(mes_message_head_t *head, const void *body);
status_t mes_send_data3(mes_message_head_t *head, uint32 head_size, const void *body);
status_t mes_recv(uint32 sid, mes_message_t *msg, bool32 check_rsn, uint32 expect_rsn, uint32 timeout);
status_t mes_recv_no_quick_stop(uint32 sid, mes_message_t *msg, bool32 check_rsn, uint32 expect_rsn, uint32 timeout);
EXTER_ATTACK void mes_process_msg_ack(void *session, mes_message_t *msg);
void mes_release_message_buf(const char *msg_buf);
void mes_broadcast_data3(uint32 sid, mes_message_head_t *head, uint32 head_size, const void *body);
EXTER_ATTACK void mes_process_broadcast_ack(void *session, mes_message_t *msg);

status_t mes_wait_acks(uint32 sid, uint32 timeout);

status_t mes_wait_acks_new(uint32 sid, uint32 timeout, uint64 *resend_bits);

void mes_broadcast(uint32 sid, uint64 inst_bits, const void *msg_data, uint64 *success_inst);

void mes_broadcast_data_with_retry(uint32 sid, uint64 target_bits, const void *msg_data);

status_t mes_broadcast_and_wait(uint32 sid, uint64 inst_bits, const void *msg_data,
    uint32 timeout, uint64 *success_inst);

status_t mes_broadcast_data_and_wait_with_retry(uint32 sid, uint64 target_bits,
    const void *msg_data, uint32 timeout, uint32 retry_threshold);

void mes_broadcast_bufflist_with_retry(uint32 sid, uint64 target_bits, mes_message_head_t *head,
    uint16 head_size, const void *body);

status_t mes_broadcast_bufflist_and_wait_with_retry(uint32 sid, uint64 target_bits,
    mes_message_head_t *head, uint16 head_size, const void *body, uint32 timeout, uint32 retry_threshold);

void mes_send_error_msg(mes_message_head_t *head);
void mes_handle_error_msg(const void *msg_data);

status_t mes_mutex_create(mes_mutex_t *mutex);
void mes_mutex_lock(mes_mutex_t *mutex);
bool32 mes_mutex_timed_lock(mes_mutex_t *mutex, uint32 timeout);
void mes_mutex_unlock(mes_mutex_t *mutex);
void mes_mutex_destroy(mes_mutex_t *mutex);

status_t mes_register_proc_func(mes_message_proc_t proc);
void mes_set_msg_enqueue(mes_command_t command, bool32 is_enqueue);
bool32 mes_get_msg_enqueue(mes_command_t command);

void mes_get_message_buf(mes_message_t *msg, mes_message_head_t *head);
uint32 mes_get_rsn(uint32 sid);
uint32 mes_get_current_rsn(uint32 sid);

int64 mes_get_stat_send_count(mes_command_t cmd);
int64 mes_get_stat_send_fail_count(mes_command_t cmd);
int64 mes_get_stat_recv_count(mes_command_t cmd);
int64 mes_get_stat_local_count(mes_command_t cmd);
atomic32_t mes_get_stat_dealing_count(mes_command_t cmd);
bool8 mes_get_stat_non_empty(mes_command_t cmd);

bool8 mes_get_elapsed_switch(void);
void mes_set_elapsed_switch(bool8 elapsed_switch);
void mes_set_crc_check_switch(bool8 crc_check_switch);
void mes_set_ssl_switch(bool8 use_ssl);
status_t mes_set_ssl_crt_file(const char *ca_file, const char *cert_file, const char *key_file);
char *mes_get_ssl_key_pwd(void);
status_t mes_set_ssl_key_pwd(const char *enc_pwd);
void mes_set_ssl_verify_peer(bool32 verify_peer, bool8 is_client);
void mes_set_dbstor_enable(bool32 enable);
status_t mes_set_process_lsid(mes_profile_t *profile);

uint64 mes_get_elapsed_time(mes_command_t cmd, mes_time_stat_t type);

int64 mes_get_elapsed_count(mes_command_t cmd, mes_time_stat_t type);
bool8 mes_get_elapsed_non_empty(mes_command_t cmd);
bool8 mes_is_inst_connect(uint32 inst_id);
void mes_dec_dealing_count(mes_command_t cmd);

void mes_process_message(dtc_msgqueue_t *my_queue, uint32 recv_idx, mes_message_t *msg, uint64 start_time);

uint8 mes_get_cmd_group(mes_command_t cmd);
uint32 mes_get_msg_queue_length(uint8 group_id);
uint32 mes_get_msg_task_queue_length(uint32 task_index);
thread_t* mes_get_msg_task_thread(uint32 task_index);

status_t mes_check_msg_head(mes_message_head_t *head);
status_t mes_message_vertify_cks(mes_message_t *msg);
void mes_init_mq_local_queue(void);
status_t mes_message_vertify_cks(mes_message_t *msg);

static inline void mes_init_send_head(mes_message_head_t *head, uint8 cmd, uint32 size, uint32 rsn, uint8 src_inst,
                                      uint8 dst_inst, uint16 src_sid, uint16 dst_sid)
{
    head->version = MES_VERSION;
    head->cmd = cmd;
    head->size = size;
    head->src_inst = src_inst;
    head->dst_inst = dst_inst;
    head->src_sid = src_sid;
    head->dst_sid = dst_sid;
    head->rsn = (rsn != GS_INVALID_ID32) ? rsn : mes_get_rsn(src_sid);
    head->req_start_time = g_timer()->now;
    head->flags = 0;
    head->unused = 0;
    head->extend_size = 0;
    head->body_cks = 0;
    head->head_cks = 0;
}

static inline void mes_init_ack_head(mes_message_head_t *req_head, mes_message_head_t *ack_head, mes_command_t cmd,
                                     uint32 size, uint32 src_sid)
{
    ack_head->version = MES_VERSION;
    ack_head->cmd = cmd;
    ack_head->src_inst = req_head->dst_inst;
    ack_head->dst_inst = req_head->src_inst;
    ack_head->src_sid = (uint16)src_sid;
    ack_head->dst_sid = req_head->src_sid;
    ack_head->rsn = req_head->rsn;
    ack_head->size = size;
    ack_head->flags = 0;
    ack_head->unused = 0;
    ack_head->req_start_time = g_timer()->now;
    ack_head->extend_size = 0;
    ack_head->body_cks = 0;
    ack_head->head_cks = 0;
}

typedef struct st_create_obj_info {
    uint32 uid;
    uint32 name_len;
    bool32 is_creating;
} create_obj_info_t;

#ifdef __cplusplus
}
#endif

#endif
