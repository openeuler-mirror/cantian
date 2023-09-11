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
 * mes_uc.c
 *
 *
 * IDENTIFICATION
 * src/mec/mes_uc.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_ip.h"
#include "cm_memory.h"
#include "cm_timer.h"
#include "cm_spinlock.h"
#include "cm_sync.h"
#include "cs_tcp.h"
#include "mes_func.h"
#include "mes_msg_pool.h"
#include "rc_reform.h"
#include "mes_tcp.h"

#include "lvos_list.h"
#include "dpax_errno.h"
#include "dpuc_api.h"
#include "dpumm_cmm.h"
#include "dsw_boot.h"
#include "external_return.h"
#include "mes_queue.h"
#include "dplog.h"
#include "dpax_log.h"

// mes的pid，需要和dbstor区分，当前dbstor是347
static uint32_t MY_PID = 400;

#define MES_UC_MAX_MSG_CTRL_LEN 512
#define MES_UC_BYTE_PER_PAGE_PI 8320
#define MES_UC_REACTOR_NUM 6
#define MES_UC_MAX_USER_DATA_LEN 512
#define MES_UC_MAX_REACTOR_THREAD_NUM 32
#define DPLOG_MAX_NUM 20
#define DPUC_DATA_MSG_RESERVE 1024
#define DPUC_DATA_MSG_MAX 2048

bool32 g_is_connect_ready = GS_FALSE;
bool32 g_allow_msg_transfer = GS_FALSE;

#define MES_UC_ALLOC_PAGES_SYNC(page_num, sgl_ptr) \
    ALLOCATE_MULTI_PAGES_SYNC((page_num), (sgl_ptr), (MY_PID), __FUNCTION__, __LINE__)

#define MES_UC_FREE_PAGES(sgl_ptr) FREE_MULTI_PAGES((sgl_ptr), __FUNCTION__, __LINE__)

#define MES_HOST_NAME(id) ((char *)g_mes.profile.inst_arr[id].ip)

// return DP_ERROR if error occurs
#define MES_UC_RETURN_IFERR(ret)           \
    do {                               \
        int32_t _status_ = (ret);     \
        if (SECUREC_UNLIKELY(_status_ != DP_OK)) { \
            return _status_;          \
        }                             \
    } while (0)

typedef struct st_mes_uc_config {
    uint32 lsid;
    dpuc_comm_mgr *com_mgr;
    dpuc_eid_obj *eid_obj;
    dpuc_eid_t eid;
    dpuc_eid_t dst_eid[GS_MAX_INSTANCES];
} mes_uc_config_t;

typedef struct {
    uint64 start_time;
    uint32 cmd;
} mes_uc_send_context;

typedef struct st_mes_uc_recv_thread {
    bool8 thread_ready;
    dtc_msgqueue_t msg_queue;
    thread_lock_t lock;
} mes_uc_recv_thread_t;

mes_uc_config_t g_mes_uc_config;

mes_uc_recv_thread_t g_mes_uc_recv_thead[MES_UC_MAX_REACTOR_THREAD_NUM];

spinlock_t g_thread_queue_id_lock;
uint8 g_thread_id = 0;
// 唯一标识UC的处理线程
__thread uint8 g_thread_queue_id = 0xFF;

void mes_destroy_uc(void)
{
    uint32 i;
    for (i = 0; i < g_mes.profile.reactor_thread_num; ++i) {
        cm_thread_lock(&g_mes_uc_recv_thead[i].lock);
        g_mes_uc_recv_thead[i].thread_ready = GS_FALSE;
    }
    mes_destory_message_pool();
    for (i = 0; i < g_mes.profile.reactor_thread_num; ++i) {
        cm_thread_unlock(&g_mes_uc_recv_thead[i].lock);
    }
}

dpuc_msg* mes_uc_alloc_uc_msg(u32 msgLen)
{
    dpuc_msg_alloc_param msg_param = { 0 };

    msg_param.pEidObj = g_mes_uc_config.eid_obj;
    msg_param.pMsgTemplate = NULL;
    msg_param.uiSize = msgLen;
    msg_param.ucDataType = DPUC_DATA;
    msg_param.ucMsgType = DPUC_TYPE_POST;

    return DPUC_MSG_ALLOC(&msg_param);
}

void mes_uc_free_uc_msg_sgl(dpuc_msg* ucMsg)
{
    SGL_S *sgl = NULL;
    if (ucMsg != NULL) {
        sgl = DPUC_SGL_ADDR_GET(ucMsg);
        if (sgl != NULL) {
            MES_UC_FREE_PAGES(sgl);
        }
    }
    return;
}

void mes_uc_free_uc_msg(dpuc_msg* ucMsg)
{
    if (ucMsg != NULL) {
        (void)DPUC_MSG_FREE(ucMsg);
    }
    return;
}

void mes_modify_last_entry_len(SGL_S* sgl, int len)
{
    SGL_S* lastSgl = NULL;
    uint32_t entryIdx = 0;
    SGL_ENTRY_S* entry = NULL;
    getLastSgl(sgl, &lastSgl, &entryIdx);
    entry = &(lastSgl->entrys[entryIdx]);
    entry->len = len;
    return;
}

status_t mes_uc_add_data_to_msg(dpuc_msg *mes_uc_msg, mes_message_head_t *head)
{
    SGL_S *sgl = NULL;
    uint32_t page_num;

    page_num = (head->size + (MES_UC_BYTE_PER_PAGE_PI - 1)) / MES_UC_BYTE_PER_PAGE_PI;
    MES_UC_ALLOC_PAGES_SYNC(page_num, &sgl);
    if (sgl == NULL) {
        MES_LOGGING(MES_LOGGING_SEND, "mes alloc sgl failed, page num %u", page_num);
        return GS_ERROR;
    }

    if (COPY_DATA_FROM_BUF_TO_SGL(sgl, 0, (char *)head, head->size) != RETURN_OK) {
        MES_LOGGING(MES_LOGGING_SEND, "mes copy data to sgl failed, page num %u, size %u", page_num, head->size);
        MES_UC_FREE_PAGES(sgl);
        return GS_ERROR;
    }
    
    mes_modify_last_entry_len(sgl, (head->size - (page_num - 1) * MES_UC_BYTE_PER_PAGE_PI));
    // 按圆整后的长度发送
    if (DPUC_SGL_ADDR_SET(mes_uc_msg, sgl, head->size) != DP_OK) {
        MES_LOGGING(MES_LOGGING_SEND, "mes set sgl to uc failed, page num %u", page_num);
        MES_UC_FREE_PAGES(sgl);
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

status_t mes_uc_add_buf_list_to_msg(dpuc_msg *mes_uc_msg, mes_message_head_t *head, mes_bufflist_t *buff_list)
{
    SGL_S *sgl = NULL;
    uint32_t page_num;
    uint32_t index;
    uint32_t sgl_offset = 0;

    page_num = (head->size + (MES_UC_BYTE_PER_PAGE_PI - 1)) / MES_UC_BYTE_PER_PAGE_PI;
    MES_UC_ALLOC_PAGES_SYNC(page_num, &sgl);
    if (sgl == NULL) {
        MES_LOGGING(MES_LOGGING_SEND, "mes alloc sgl failed, page num %u", page_num);
        return GS_ERROR;
    }

    for (index = 0; index < buff_list->cnt; index++) {
        if (COPY_DATA_FROM_BUF_TO_SGL(sgl, sgl_offset, buff_list->buffers[index].buf,
                buff_list->buffers[index].len) != RETURN_OK) {
            GS_LOG_RUN_ERR("mes copy data to sgl failed, page num %u, size %u, index %u",
                page_num, head->size, index);
            MES_UC_FREE_PAGES(sgl);
            return GS_ERROR;
        }
        sgl_offset += buff_list->buffers[index].len;
    }

    mes_modify_last_entry_len(sgl, (head->size - (page_num - 1) * MES_UC_BYTE_PER_PAGE_PI));
    // 按圆整后的长度发送
    if (DPUC_SGL_ADDR_SET(mes_uc_msg, sgl, head->size) != DP_OK) {
        MES_LOGGING(MES_LOGGING_SEND, "mes set sgl to uc failed, page num %u", page_num);
        MES_UC_FREE_PAGES(sgl);
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

status_t mes_uc_add_buf_list_to_msg_head(dpuc_msg *mes_uc_msg, mes_message_head_t *head, mes_bufflist_t *buff_list)
{
    uint32_t index;
    errno_t err;
    uint32_t data_offset = 0;
    char* user_data = NULL;

    user_data = (char*)DPUC_DATA_ADDR_GET(mes_uc_msg);
    if (user_data == NULL) {
        MES_LOGGING(MES_LOGGING_SEND, "mes get dpuc data addr failed");
        return GS_ERROR;
    }

    for (index = 0; index < buff_list->cnt; index++) {
        err = memcpy_sp(user_data + data_offset, MES_UC_MAX_USER_DATA_LEN - data_offset, buff_list->buffers[index].buf,
            buff_list->buffers[index].len);
        MEMS_RETURN_IFERR(err);
        data_offset += buff_list->buffers[index].len;
    }
    return GS_SUCCESS;
}

int32_t mes_uc_send_msg_ack_callback(int32_t result, dpuc_msg_param_s *msg_param, void *context)
{
    if (msg_param == NULL) {
        MES_LOGGING(MES_LOGGING_SEND, "mes uc ack param is null, ret %d", result);
        return RETURN_ERROR;
    }

    if (msg_param->pMsg == NULL) {
        MES_LOGGING(MES_LOGGING_SEND, "mes uc ack param msg is null, ret %d", result);
        return RETURN_ERROR;
    }
    mes_uc_send_context* pContext = (mes_uc_send_context *)context;
    mes_consume_with_time(pContext->cmd, MES_TIME_TEST_SEND_ACK, pContext->start_time);

    if (pContext != NULL) {
        free(pContext);
    }

    mes_uc_free_uc_msg_sgl(msg_param->pMsg);
    mes_uc_free_uc_msg(msg_param->pMsg);
    return RETURN_OK;
}

static inline void mes_uc_free_mem(mes_uc_send_context *context, dpuc_msg *msg)
{
    free(context);
    mes_uc_free_uc_msg_sgl(msg);
    mes_uc_free_uc_msg(msg);
}

status_t mes_uc_alloc_msg(mes_message_head_t *head, dpuc_msg **mes_uc_msg)
{
    errno_t err;
    char *user_data = NULL;
    if (head->size <= MES_UC_MAX_USER_DATA_LEN) {
        *mes_uc_msg = mes_uc_alloc_uc_msg(head->size);
        if (*mes_uc_msg == NULL) {
            GS_LOG_RUN_ERR("mes alloc uc msg failed, cmd %u", head->cmd);
            return GS_ERROR;
        }
        user_data = (char*)DPUC_DATA_ADDR_GET(*mes_uc_msg);
        if (user_data == NULL) {
            GS_LOG_RUN_ERR("mes get data addr failed, cmd %u", head->cmd);
            return GS_ERROR;
        }
        err = memcpy_sp(user_data, MES_UC_MAX_USER_DATA_LEN, head, head->size);
        MEMS_RETURN_IFERR(err);
    } else {
        *mes_uc_msg = mes_uc_alloc_uc_msg(0);
        if (*mes_uc_msg == NULL) {
            GS_LOG_RUN_ERR("mes alloc uc msg failed, cmd %u", head->cmd);
            return GS_ERROR;
        }
        if (mes_uc_add_data_to_msg(*mes_uc_msg, head) != GS_SUCCESS) {
            MES_LOGGING(MES_LOGGING_SEND, "mes add data to msg failed, cmd %u", head->cmd);
            mes_uc_free_uc_msg(*mes_uc_msg);
            return GS_ERROR;
        }
    }
    return GS_SUCCESS;
}

status_t mes_uc_send_data(const void *msg_data)
{
    int32_t ret;
    uint64 stat_time = 0;
    uint64 start_ack_time = 0;
    mes_message_head_t *head = (mes_message_head_t *)msg_data;
    dpuc_msg *mes_uc_msg = NULL;
    uint8 dst_inst = head->dst_inst;
    mes_uc_send_context *pContext = NULL;

    if (g_allow_msg_transfer != GS_TRUE || g_is_connect_ready != GS_TRUE) {
        MES_LOGGING_WAR(MES_LOGGING_SEND, "uc connection from %u to %u is not ready, cmd=%u, rsn=%u, src_sid=%u,"
            "dst_sid=%u", head->src_inst, head->dst_inst, head->cmd, head->rsn, head->src_sid, head->dst_sid);
        return GS_ERROR;
    }

    mes_get_consume_time_start(&stat_time);

    GS_RETURN_IFERR(mes_uc_alloc_msg(head, &mes_uc_msg));

    ret = DPUC_MSGPARAM_SET(mes_uc_msg, g_mes_uc_config.eid, g_mes_uc_config.dst_eid[dst_inst], head->cmd);
    if (ret != DP_OK) {
        MES_LOGGING(MES_LOGGING_SEND, "mes set uc msg param failed, src_eid 0x%lx, dst_eid 0x%lx, cmd %u",
            g_mes_uc_config.eid, g_mes_uc_config.dst_eid[dst_inst], head->cmd);
        mes_uc_free_uc_msg(mes_uc_msg);
        return GS_ERROR;
    }

    // 增加时延统计 回ACK时间
    pContext = (mes_uc_send_context*)malloc(sizeof(mes_uc_send_context));
    if (pContext == NULL) {
        MES_LOGGING(MES_LOGGING_SEND, "mes set uc send context failed, src_eid 0x%lx, dst_eid 0x%lx, cmd %u",
            g_mes_uc_config.eid, g_mes_uc_config.dst_eid[dst_inst], head->cmd);
        return GS_ERROR;
    }
    pContext->cmd = head->cmd;
    mes_get_consume_time_start(&start_ack_time);
    pContext->start_time = start_ack_time;

    ret = DPUC_MSG_SEND(mes_uc_msg, mes_uc_send_msg_ack_callback, pContext);
    if (ret != DP_OK) {
        MES_LOGGING(MES_LOGGING_SEND, "mes send post msg failed, src_eid 0x%lx, dst_eid 0x%lx, cmd %u, ret %d",
            g_mes_uc_config.eid, g_mes_uc_config.dst_eid[head->dst_inst], head->cmd, ret);
        mes_uc_free_mem(pContext, mes_uc_msg);
        return GS_ERROR;
    }

    mes_consume_with_time(head->cmd, MES_TIME_SEND_IO, stat_time);

    return GS_SUCCESS;
}

status_t mes_uc_alloc_buff_msg(mes_bufflist_t *buff_list, mes_message_head_t *head, dpuc_msg **mes_uc_msg)
{
    if (head->size <= MES_UC_MAX_USER_DATA_LEN) {
        *mes_uc_msg = mes_uc_alloc_uc_msg(head->size);
        if (*mes_uc_msg == NULL) {
            GS_LOG_RUN_ERR("mes alloc uc msg failed, cmd %u", head->cmd);
            return GS_ERROR;
        }
        if (mes_uc_add_buf_list_to_msg_head(*mes_uc_msg, head, buff_list) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("mes add bufflist to msg head failed, cmd %u", head->cmd);
            mes_uc_free_uc_msg(*mes_uc_msg);
            return GS_ERROR;
        }
    } else {
        *mes_uc_msg = mes_uc_alloc_uc_msg(0);
        if (*mes_uc_msg == NULL) {
            GS_LOG_RUN_ERR("mes alloc uc msg failed, cmd %u", head->cmd);
            return GS_ERROR;
        }
        if (mes_uc_add_buf_list_to_msg(*mes_uc_msg, head, buff_list) != GS_SUCCESS) {
            GS_LOG_RUN_ERR("mes add bufflist to msg failed, cmd %u", head->cmd);
            mes_uc_free_uc_msg(*mes_uc_msg);
            return GS_ERROR;
        }
    }
    return GS_SUCCESS;
}

status_t mes_uc_send_bufflist(mes_bufflist_t *buff_list)
{
    int32_t ret;
    uint64 stat_time = 0;
    uint64 start_ack_time = 0;
    mes_message_head_t *head = (mes_message_head_t *)(buff_list->buffers[0].buf);
    dpuc_msg *mes_uc_msg = NULL;
    uint8 dst_inst = head->dst_inst;
    mes_uc_send_context *pContext = NULL;

    if (g_allow_msg_transfer != GS_TRUE || g_is_connect_ready != GS_TRUE) {
        MES_LOGGING(MES_LOGGING_SEND, "uc connection from %u to %u is not ready, cmd=%u, rsn=%u, src_sid=%u,"
            "dst_sid=%u", head->src_inst, head->dst_inst, head->cmd, head->rsn, head->src_sid, head->dst_sid);
        return GS_ERROR;
    }

    mes_get_consume_time_start(&stat_time);
    GS_RETURN_IFERR(mes_uc_alloc_buff_msg(buff_list, head, &mes_uc_msg));

    ret = DPUC_MSGPARAM_SET(mes_uc_msg, g_mes_uc_config.eid, g_mes_uc_config.dst_eid[dst_inst], head->cmd);
    if (ret != DP_OK) {
        MES_LOGGING(MES_LOGGING_SEND, "mes set uc msg param failed, src_eid 0x%lx, dst_eid 0x%lx, cmd %u",
            g_mes_uc_config.eid, g_mes_uc_config.dst_eid[dst_inst], head->cmd);
        mes_uc_free_uc_msg(mes_uc_msg);
        return GS_ERROR;
    }

    // 增加时延统计 回ACK时间
    pContext = (mes_uc_send_context*)malloc(sizeof(mes_uc_send_context));
    if (pContext == NULL) {
        MES_LOGGING(MES_LOGGING_SEND, "mes set uc send context failed, src_eid 0x%lx, dst_eid 0x%lx, cmd %u",
            g_mes_uc_config.eid, g_mes_uc_config.dst_eid[dst_inst], head->cmd);
        return GS_ERROR;
    }
    pContext->cmd = head->cmd;
    mes_get_consume_time_start(&start_ack_time);
    pContext->start_time = start_ack_time;

    ret = DPUC_MSG_SEND(mes_uc_msg, mes_uc_send_msg_ack_callback, pContext);
    if (ret != DP_OK) {
        MES_LOGGING(MES_LOGGING_SEND, "mes send post msg failed, src_eid 0x%lx, dst_eid 0x%lx, cmd %u, ret %d",
            g_mes_uc_config.eid, g_mes_uc_config.dst_eid[head->dst_inst], head->cmd, ret);
        mes_uc_free_mem(pContext, mes_uc_msg);
        return GS_ERROR;
    }

    mes_consume_with_time(head->cmd, MES_TIME_SEND_IO, stat_time);

    return GS_SUCCESS;
}

status_t mes_uc_get_mes_msg_from_uc_head(dpuc_msg *uc_msg, mes_message_t *mes_msg)
{
    errno_t err;
    char *user_data = NULL;
    mes_message_head_t *head = NULL;

    user_data = (char*)DPUC_DATA_ADDR_GET(uc_msg);
    if (user_data == NULL) {
        MES_LOGGING(MES_LOGGING_SEND, "mes recv uc msg head failed");
        return GS_ERROR;
    }

    head = (mes_message_head_t *)user_data;
    if (mes_check_msg_head(head) != GS_SUCCESS) {
        GS_THROW_ERROR_EX(ERR_MES_ILEGAL_MESSAGE, "mes message length=%u, cmd=%u, rsn=%u, src_inst=%u, dst_inst=%u, "
            "src_sid=%u, dst_sid=%u, thead id=%d", head->size, head->cmd, head->rsn, head->src_inst, head->dst_inst,
            head->src_sid, head->dst_sid, g_thread_queue_id);
        return GS_ERROR;
    }

    mes_get_message_buf(mes_msg, head);
    if ((mes_msg->buffer == NULL) || (mes_msg->head == NULL)) {
        MES_LOGGING(MES_LOGGING_SEND, "mes get msg buf failed");
        return GS_ERROR;
    }
    err = memcpy_s(mes_msg->buffer, head->size, head, head->size);
    MEMS_RETURN_IFERR(err);
    return GS_SUCCESS;
}

status_t mes_uc_get_mes_msg_from_uc_msg(dpuc_msg *uc_msg, mes_message_t *mes_msg)
{
    SGL_S *uc_msg_data = NULL;
    mes_message_head_t *head = NULL;

    uc_msg_data = DPUC_SGL_ADDR_GET(uc_msg);
    // sgl有效的entry是从第一个开始
    if ((uc_msg_data == NULL) || (uc_msg_data->entrys[0].len < sizeof(mes_message_head_t))) {
        mes_uc_free_uc_msg_sgl(uc_msg);
        MES_LOGGING(MES_LOGGING_SEND, "mes recv uc msg sgl failed");
        return GS_ERROR;
    }

    head = (mes_message_head_t *)uc_msg_data->entrys[0].buf;
    if (mes_check_msg_head(head) != GS_SUCCESS) {
        mes_uc_free_uc_msg_sgl(uc_msg);
        GS_THROW_ERROR_EX(ERR_MES_ILEGAL_MESSAGE, "mes message length=%u, cmd=%u, rsn=%u, src_inst=%u, dst_inst=%u, "
            "src_sid=%u, dst_sid=%u, thead id=%d", head->size, head->cmd, head->rsn, head->src_inst, head->dst_inst,
            head->src_sid, head->dst_sid, g_thread_queue_id);
        return GS_ERROR;
    }

    mes_get_message_buf(mes_msg, head);
    if ((mes_msg->buffer == NULL) || (mes_msg->head == NULL)) {
        MES_LOGGING(MES_LOGGING_SEND, "mes get msg buf failed");
        mes_uc_free_uc_msg_sgl(uc_msg);
        return GS_ERROR;
    }

    // sgl有效数据从头开始
    if (COPY_DATA_FROM_SGL_TO_BUF(uc_msg_data, 0, mes_msg->buffer, head->size) != RETURN_OK) {
        MES_LOGGING(MES_LOGGING_SEND, "mes copy data from sgl to buf failed, size %u", head->size);
        mes_free_buf_item(mes_msg->buffer);
        mes_uc_free_uc_msg_sgl(uc_msg);
        return GS_ERROR;
    }
    mes_uc_free_uc_msg_sgl(uc_msg);
    return GS_SUCCESS;
}

void mes_get_thread_id(void)
{
    if (g_thread_queue_id == GS_INVALID_ID8) {
        cm_spin_lock(&g_thread_queue_id_lock, NULL);
        g_thread_queue_id = g_thread_id % MES_UC_MAX_REACTOR_THREAD_NUM;
        g_thread_id++;
        cm_spin_unlock(&g_thread_queue_id_lock);
        GS_LOG_DEBUG_INF("set thread queue id = %d.", g_thread_queue_id);
    }
}

int32_t mes_uc_msg_recv_func(dpuc_msg *uc_msg, dpuc_msg_mem_free_mode_e *freeMode)
{
    uint32 uc_msg_len;
    mes_message_t mes_msg = {NULL, NULL};
    uint64 stat_time = 0;
    status_t ret = GS_ERROR;

    mes_get_consume_time_start(&stat_time);

    if (uc_msg == NULL) {
        MES_LOGGING(MES_LOGGING_SEND, "mes recv uc msg is invalid");
        return RETURN_ERROR;
    }

    if (freeMode != NULL) {
        *freeMode = DPUC_AUTO_FREE;
    }

    if (g_allow_msg_transfer != GS_TRUE) {
        MES_LOGGING(MES_LOGGING_SEND, "mes not allow msg transfer");
        return RETURN_ERROR;
    }

    mes_get_thread_id();
    cm_thread_lock(&g_mes_uc_recv_thead[g_thread_queue_id].lock);
    if (!g_mes_uc_recv_thead[g_thread_queue_id].thread_ready) {
        MES_LOGGING(MES_LOGGING_SEND, "get mes msg failed, recv thread is not ready");
        cm_thread_unlock(&g_mes_uc_recv_thead[g_thread_queue_id].lock);
        return RETURN_ERROR;
    }

    uc_msg_len = DPUC_MSGLEN_GET(uc_msg);
    if (uc_msg_len >= sizeof(mes_message_head_t)) {
        ret = mes_uc_get_mes_msg_from_uc_head(uc_msg, &mes_msg);
    } else if (uc_msg_len == 0) {
        ret = mes_uc_get_mes_msg_from_uc_msg(uc_msg, &mes_msg);
    } else {
        GS_LOG_RUN_ERR("[mes] mes uc recv message len is invalid");
    }
    if (ret != GS_SUCCESS) {
        MES_LOGGING(MES_LOGGING_SEND, "get mes msg from uc failed");
        cm_thread_unlock(&g_mes_uc_recv_thead[g_thread_queue_id].lock);
        return RETURN_ERROR;
    }
    mes_consume_with_time(mes_msg.head->cmd, MES_TIME_READ_MES, stat_time);

    if (g_mes.crc_check_switch) {
        if (mes_message_vertify_cks(&mes_msg) != GS_SUCCESS) {
            cm_thread_unlock(&g_mes_uc_recv_thead[g_thread_queue_id].lock);
            GS_LOG_RUN_ERR("[mes] check cks failed, cmd=%u, rsn=%u, src_inst=%u, dst_inst=%u", mes_msg.head->cmd,
                mes_msg.head->rsn, mes_msg.head->src_inst, mes_msg.head->dst_sid);
            return RETURN_ERROR;
        }
    }

    mes_process_message(&g_mes_uc_recv_thead[g_thread_queue_id].msg_queue, 0, &mes_msg, stat_time);
    cm_thread_unlock(&g_mes_uc_recv_thead[g_thread_queue_id].lock);
    return RETURN_OK;
}

// initialize dpuc log path
int32_t init_dpuc_log(char *running_log_path)
{
    int32_t ret = DP_ERROR;

    ret = dplog_init();
    if (ret != DP_OK) {
        GS_LOG_RUN_ERR("Init dplog failed (%d).", ret);
        return ret;
    }
    GS_LOG_RUN_INF("Init dplog success.");

    // dpax log store path
    ret = dpax_log_file_path_set_ext((char *)running_log_path);
    if (ret != DP_OK) {
        GS_LOG_RUN_ERR("Set dplog path failed(%d).", ret);
        return ret;
    }
    GS_LOG_RUN_INF("Set dplog path success.");

    ret = dplog_set_backup_num(DPLOG_MAX_NUM);
    if (ret != DP_OK) {
        GS_LOG_RUN_ERR("Set dplog backup num failed(%d).", ret);
        return ret;
    }
    GS_LOG_RUN_INF("Set dplog backup num success.");

    return DP_OK;
}

// check create link status
int32_t create_link_callback(u32 uiDstlsId, dpuc_qlink_event qlinkEvent, dpuc_plane_type_e planeType, dupc_qlink_cause_t qlinkCause)
{
    GS_LOG_DEBUG_INF("Destination link (0x%x), status (%d), plane type (%d), reason (%d).", uiDstlsId, qlinkEvent, planeType, qlinkCause);
    uint32 dst_lsid = g_mes.profile.inst_id == 0 ? g_mes.profile.inst_lsid[1] : g_mes.profile.inst_lsid[0];
    if (uiDstlsId == dst_lsid && qlinkEvent == DPUC_QLINK_UP) {
        g_is_connect_ready = GS_TRUE;
        GS_LOG_RUN_INF("create link success.");
    }

    if (uiDstlsId == dst_lsid && qlinkEvent == DPUC_QLINK_DOWN) {
        g_is_connect_ready = GS_FALSE;
        GS_LOG_RUN_INF("uc link down.");
    }
    return DP_OK;
}

int32_t link_state_change_callback(u32 uiDstlsId, dpuc_link_state_event_t qlinkEvent, dpuc_plane_type_e planeType,
    void *param)
{
    if (qlinkEvent == DPUC_LINK_STATE_EVENT_SUBHEALTH_ORIGIN) {
        dpuc_subhealth_info_t *subhealth_info = (dpuc_subhealth_info_t*)param;
        GS_LOG_RUN_WAR("slow event occur, dst lsid (0x%x), local ip (%s), remote ip (%s)", uiDstlsId,
            subhealth_info->local_ip, subhealth_info->remote_ip);
    }
    if (qlinkEvent == DPUC_LINK_STATE_EVENT_SUBHEALTH_CLEAR) {
        dpuc_subhealth_info_t *subhealth_info = (dpuc_subhealth_info_t*)param;
        GS_LOG_RUN_WAR("slow event recover, dst lsid (0x%x), local ip (%s), remote ip (%s)", uiDstlsId,
            subhealth_info->local_ip, subhealth_info->remote_ip);
    }
    return DP_OK;
}

// mes uc create eid and register eid
int32_t create_and_reg_eid(mes_uc_config_t *uc_config, dpuc_msg_recv_s *msg_recv_func)
{
    int32_t ret = DP_ERROR;
    // 生成进程使用的eid，外部传入
    ret = DPUC_EID_MAKE(NORMAL_TYPE, MY_PID, 0, uc_config->lsid, &uc_config->eid);
    if (ret != DP_OK) {
        GS_LOG_RUN_ERR("Generate eid failed.");
        return ret;
    }
    GS_LOG_DEBUG_INF("Generate eid success.");

    // 注册进程使用的eid
    ret = DPUC_EID_REG(uc_config->com_mgr, uc_config->eid, msg_recv_func, &uc_config->eid_obj);
    if (ret != DP_OK) {
        GS_LOG_RUN_ERR("Reg src eid failed, eid=0x%lx.", uc_config->eid);
        return ret;
    }
    GS_LOG_DEBUG_INF("Reg src eid success, eid=0x%lx.", uc_config->eid);

    // 创建建链回调函数
    dpucLinkEventOps link_event = {create_link_callback, link_state_change_callback, NULL};
    ret = DPUC_REGIST_LINK_EVENT(uc_config->eid, &link_event);
    if (ret != DP_OK) {
        GS_LOG_RUN_ERR("Reg create link status func failed.");
        return ret;
    }
    GS_LOG_DEBUG_INF("Reg create link status func successs");
    return ret;
}

// mes uc create reactor
int32_t create_reactor(mes_uc_config_t *uc_config)
{
    int32_t ret = DP_ERROR;
    // 创建reactor
    uint32_t threadNum = g_mes.profile.reactor_thread_num;
    GS_LOG_DEBUG_INF("Set reacot thread num = %d.", threadNum);
    if (threadNum > MES_UC_MAX_REACTOR_THREAD_NUM) {
        GS_LOG_RUN_ERR("reator threadNum is excced, threadNum = %d", threadNum);
        return DP_ERROR;
    }

    dpuc_xnet_thread_info_s threadInfo[threadNum];
    uint32_t i;
    for (i = 0; i < threadNum; i++) {
        threadInfo[i].pri = 0;
        CPU_ZERO(&(threadInfo[i].cpu_set));
    }
    dpuc_sched_conf_info_s cfgInfo = { 0, 0, threadInfo, threadNum};
    ret = DPUC_SET_EID_REACTOR(uc_config->eid_obj, "mes_cfg_xnet", &cfgInfo);
    if (ret != DP_OK) {
        GS_LOG_RUN_ERR("Generate reactor failed (%d).", ret);
        return ret;
    }
    GS_LOG_DEBUG_INF("Generate reactor success.");
    return ret;
}

// initialize function
int32_t init_xnet_dpuc(mes_uc_config_t *uc_config)
{
    int32_t ret = DP_ERROR;

    // 注册post消息接收函数，目前只有post类型
    dpuc_msg_recv_s msg_recv_func = {mes_uc_msg_recv_func, NULL};

    dpuc_comm_mgr_param commMgrParam = {2048, 2048, MY_PID, uc_config->lsid, 0};

    // 区分计算云
    // 物理机上dbstor会调用umm初始化sgl、req的分区
    if (!g_enable_dbstor) {
        ret = DPUMM_SET_CONFIG_PATH("/home/regress/CantianKernel/pkg/test/mes_test/");
    } else {
        ret = DPUMM_SET_CONFIG_PATH(g_mes.profile.dpumm_config_path);
    }
    if (ret != DP_OK) {
        GS_LOG_RUN_ERR("umm set failed (%d).", ret);
        return DP_ERROR;
    }
    GS_LOG_DEBUG_INF("umm set success.");

    if (dsw_core_init(NULL, 0, NULL) != 0) {
        GS_LOG_RUN_ERR("[mes] dsw_core_init failed");
        return GS_ERROR;
    }

    if (g_mes.profile.channel_version != GS_INVALID_ID64) {
        (void)DPUC_XNET_SET_PROCESS_VER(g_mes.profile.channel_version);
        GS_LOG_RUN_INF("mes set channel version=%lld.", g_mes.profile.channel_version);
    }
    // 初始化通信模块
    uc_config->com_mgr = DPUC_ALL_INIT(&commMgrParam);
    if (uc_config->com_mgr == NULL) {
        GS_LOG_RUN_ERR("Init dpuc failed, pid=%d, lsid=0x%x.", commMgrParam.usPid, commMgrParam.uiServiceId);
        return DP_ERROR;
    }
    GS_LOG_DEBUG_INF("Init dpuc success, pid=%d, lsid=0x%x.", commMgrParam.usPid, commMgrParam.uiServiceId);
    
    MES_UC_RETURN_IFERR(create_and_reg_eid(uc_config, &msg_recv_func));

    // 注册EID的消息并发
    dpuc_datamsg_mem_ops data_ops;
    data_ops.pfnReqAllocMsgMem = NULL;
    data_ops.pfnRspAllocMsgMem = NULL;
    data_ops.pfnFreeMsgMem = NULL;
    data_ops.uiSendDataMsgNumReserve = DPUC_DATA_MSG_RESERVE;
    data_ops.uiSendDatamsgNumMax     = DPUC_DATA_MSG_MAX;
    data_ops.uiRecvDataMsgNumReserve = DPUC_DATA_MSG_RESERVE;
    data_ops.uiRecvDatamsgNumMax     = DPUC_DATA_MSG_MAX;

    ret = DPUC_MSGMEM_REG_INTEGRATE(uc_config->eid_obj, NULL, &data_ops);
    if (ret != DP_OK) {
        GS_LOG_RUN_ERR("Set concurrent info failed.");
        return ret;
    }
    GS_LOG_DEBUG_INF("Set concurrent info success.");

    MES_UC_RETURN_IFERR(create_reactor(uc_config));

    return DP_OK;
}

// initialize server identifier
int32_t mes_uc_server(mes_uc_config_t *uc_config, char *ip, uint16 port)
{
    int32_t ret;
    // 设置server监听端口
    dpuc_addr eid_addr;
    eid_addr.AddrFamily = DPUC_ADDR_FAMILY_IPV4;
    eid_addr.PlaneType = DPUC_DATA_PLANE;
    PRTS_RETURN_IFERR(sprintf_s(eid_addr.Url, DPUC_URL_LEN, "%s:%u", ip, port));

    ret = DPUC_SET_SRC_EID_ADDR(uc_config->eid_obj, &eid_addr, 1, DPUC_ADDR_SERVER);
    if (ret != DP_OK) {
        GS_LOG_RUN_ERR("Set src server eid addr failed, eid=0x%lx, url=%s.", uc_config->eid, eid_addr.Url);
        return ret;
    }
    GS_LOG_DEBUG_INF("Set src server eid addr success, eid=0x%lx, url=%s.", uc_config->eid, eid_addr.Url);
    GS_LOG_DEBUG_INF("Initialized server identifier success.");
    return GS_SUCCESS;
}

// uc connect interface
status_t mes_uc_connect(uint32 inst_id)
{
    if (inst_id == g_mes.profile.inst_id || inst_id >= GS_MAX_INSTANCES) {
        GS_LOG_RUN_ERR("connect id is invalid %d", inst_id);
        return GS_ERROR;
    }
    uint32 lsid = g_mes.profile.inst_lsid[inst_id];

    // set dst eid
    int32_t ret = DPUC_EID_MAKE(NORMAL_TYPE, MY_PID, 0, lsid, &g_mes_uc_config.dst_eid[inst_id]);
    if (ret != DP_OK) {
        GS_LOG_RUN_ERR("Set dst eid failed (%d).", ret);
        return GS_ERROR;
    }

    // 设置本地的ip和地址
    dpuc_addr client_eid_addr;
    client_eid_addr.AddrFamily = DPUC_ADDR_FAMILY_IPV4;
    client_eid_addr.PlaneType = DPUC_DATA_PLANE;
    PRTS_RETURN_IFERR(sprintf_s(client_eid_addr.Url, DPUC_URL_LEN, "%s:%u", \
        g_mes.profile.inst_arr[g_mes.profile.inst_id].ip, g_mes.profile.inst_arr[g_mes.profile.inst_id].port));

    // 设置需要连接的server的ip和地址
    dpuc_addr server_eid_addr;
    server_eid_addr.AddrFamily = DPUC_ADDR_FAMILY_IPV4;
    server_eid_addr.PlaneType = DPUC_DATA_PLANE;
    PRTS_RETURN_IFERR(sprintf_s(server_eid_addr.Url, DPUC_URL_LEN, "%s:%u", g_mes.profile.inst_arr[inst_id].ip, \
        g_mes.profile.inst_arr[inst_id].port));

    // 设置需要连接的server的eid
    ret = DPUC_SET_DST_EID_ADDR(g_mes_uc_config.com_mgr, g_mes_uc_config.dst_eid[inst_id], &server_eid_addr, \
        DPUC_ADDR_SERVER);
    GS_LOG_RUN_INF("Instance %d eid=0x%lx, url=%s to connect instance %d, eid=0x%lx, url=%s.", g_mes.profile.inst_id, \
        g_mes_uc_config.eid, client_eid_addr.Url, inst_id, g_mes_uc_config.dst_eid[inst_id], server_eid_addr.Url);
    if (ret != DP_OK) {
        GS_LOG_RUN_ERR("Set server addr failed.");
        return GS_ERROR;
    }

    // 进行建链
    dpuc_conn_params_t con_param = { 0 };
    con_param.pri = 0;
    con_param.hop = 0;
    con_param.time_out = 0;
    con_param.runMode = DPUC_PERSISTENT_CONN;
    con_param.recovery_pri = DPUC_CONN_RECVOERY_L;
    con_param.pSrcAddr = &client_eid_addr;
    con_param.pDstAddr = &server_eid_addr;
    for (uint32 i = 0; i < g_mes.profile.channel_num; i++) {
        ret = DPUC_LINK_CREATE_WITH_ADDR(g_mes_uc_config.eid_obj, g_mes_uc_config.dst_eid[inst_id], &con_param);
        if (ret != DP_OK) {
            GS_LOG_RUN_ERR("To intance %d create link failed.", inst_id);
            return GS_ERROR;
        }
    }

    g_allow_msg_transfer = GS_TRUE;
    GS_LOG_RUN_INF("Call create link success.");
    return GS_SUCCESS;
}

// sync disconnect
void mes_uc_disconnect(uint32 inst_id)
{
    if (inst_id >= GS_MAX_INSTANCES) {
        GS_LOG_RUN_ERR("inst_id out of range GS_MAX_INSTANCES.");
        return;
    }
    g_allow_msg_transfer = GS_FALSE;
    uint32 lsid = g_mes.profile.inst_lsid[inst_id];
    int32_t ret = DP_ERROR;
    ret = DPUC_QLINK_CLOSE(lsid, DPUC_DESTROY_LINK, DPUC_DATA_PLANE);
    if (ret != DP_OK) {
        GS_LOG_RUN_ERR("Disconnect dst_lsid 0x%x failed.", lsid);
        return;
    }
    GS_LOG_RUN_INF("Disconnect dst_lsid 0x%x success.", lsid);
}

// asysnc disconnect
void mes_uc_disconnect_async(uint32 inst_id)
{
    mes_uc_disconnect(inst_id);
}

// check inst_id is or not connect
bool32 mes_uc_connection_ready(uint32 inst_id)
{
    return (g_allow_msg_transfer == GS_TRUE && g_is_connect_ready == GS_TRUE);
}

// uc try accept
status_t mes_uc_lsnr(void)
{
    char *lsnr_host = MES_HOST_NAME(g_mes.profile.inst_id);
    uint16 port = g_mes.profile.inst_arr[g_mes.profile.inst_id].port;
    if (mes_uc_server(&g_mes_uc_config, lsnr_host, port) != DP_OK) {
        GS_LOG_RUN_ERR("mes_start_lsnr failed.");
        return GS_ERROR;
    }
    GS_LOG_DEBUG_INF("mes_start_lsnr suceess.");
    return GS_SUCCESS;
}

// mes uc init
status_t mes_init_uc(void)
{
    uint32 i;
    for (i = 0; i < MES_UC_MAX_REACTOR_THREAD_NUM; i++) {
        init_msgqueue(&g_mes_uc_recv_thead[i].msg_queue);
        cm_init_thread_lock(&g_mes_uc_recv_thead[i].lock);
        g_mes_uc_recv_thead[i].thread_ready = GS_TRUE;
    }
    mes_init_mq_local_queue();
    GS_RETURN_IFERR(mes_init_message_pool());

    // set dpax log path
    if (!g_enable_dbstor) {
        char log_path[GS_MAX_PATH_LEN];
        sprintf_s(log_path, GS_MAX_PATH_LEN, "%s", "/home/cantiandba");
        if (init_dpuc_log((char *)log_path) != DP_OK) {
            GS_LOG_RUN_ERR("uc log initialize failed.");
            return GS_ERROR;
        }
        GS_LOG_RUN_INF("uc log initialize successs.");
    }

    g_mes_uc_config.lsid = g_mes.profile.inst_lsid[g_mes.profile.inst_id];
    GS_LOG_DEBUG_INF("mes uc config lsid = 0x%x", g_mes_uc_config.lsid);

    if (init_xnet_dpuc(&g_mes_uc_config) != DP_OK) {
        GS_LOG_RUN_ERR("UC config initialize failed.");
        return GS_ERROR;
    }
    GS_LOG_DEBUG_INF("UC config initialize success.");

    GS_RETURN_IFERR(mes_uc_lsnr());
    return GS_SUCCESS;
}
