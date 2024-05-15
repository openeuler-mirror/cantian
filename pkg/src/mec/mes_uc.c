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
 * mes_uc.c
 *
 *
 * IDENTIFICATION
 * src/mec/mes_uc.c
 *
 * -------------------------------------------------------------------------
 */
#include <dlfcn.h>
#include "mes_log_module.h"
#include "cm_ip.h"
#include "cm_memory.h"
#include "cm_timer.h"
#include "cm_spinlock.h"
#include "cm_sync.h"
#include "cs_tcp.h"
#include "rc_reform.h"
#include "mes_uc_interface.h"
#include "mes_msg_pool.h"
#include "mes_queue.h"
#include "mes_uc.h"

// mes的pid，需要和dbstor区分，当前dbstor是347
static uint32_t MY_PID = 400;

#define MES_UC_BYTE_PER_PAGE_PI 8320
#define MES_UC_MAX_USER_DATA_LEN 512
#define MES_UC_MAX_REACTOR_THREAD_NUM 32
#define DPLOG_MAX_NUM 20
#define DPUC_DATA_MSG_RESERVE 1024
#define DPUC_DATA_MSG_MAX 2048
#define NS_PER_MS 1000000
#define MES_UC_XNET_TIMEOUT_TIMES 11 // s

#ifndef RETURN_OK
 #define RETURN_OK 0
#endif

#ifndef RETURN_ERROR
 #define RETURN_ERROR (-1)
#endif

#define MES_UC_ALLOC_PAGES_SYNC(page_num, sgl_ptr) \
    mes_global_handle()->allocate_multi_pages_sync((page_num), (sgl_ptr), (MY_PID), __FUNCTION__, __LINE__)

#define MES_UC_FREE_PAGES(sgl_ptr) mes_global_handle()->free_multi_pages((sgl_ptr), (MY_PID), __FUNCTION__, __LINE__)

#define MES_HOST_NAME(id) ((char *)g_mes.profile.inst_arr[id].ip)
#define MES_SHOULD_RECONN(bits, id) (((bits) >> (id)) & 0x1)
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
    dpuc_eid_t dst_eid[CT_MAX_INSTANCES];
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
mes_uc_conn_t g_mes_uc_channel_status[CT_MAX_INSTANCES];

spinlock_t g_thread_queue_id_lock;
uint8 g_thread_id = 0;
// 唯一标识UC的处理线程
__thread uint8 g_thread_queue_id = 0xFF;
static mes_interface_t g_mes_interface = { .uc_handle = NULL};

thread_t g_mes_channel_check_thread;
uint64 g_channel_reconn_bits;
cm_thread_cond_t g_reconn_thread_cond;

mes_interface_t *mes_global_handle(void)
{
    return &g_mes_interface;
}

static status_t mes_load_symbol(void *lib_handle, char *symbol, void **sym_lib_handle)
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

status_t uc_init_lib(void)
{
    mes_interface_t *intf = &g_mes_interface;
    intf->uc_handle = dlopen("libdbstoreClient.so", RTLD_LAZY);
    const char *dlopen_err = NULL;
    dlopen_err = dlerror();

    if (intf->uc_handle == NULL) {
        CT_LOG_RUN_ERR("fail to load libdbstoreClient.so, maybe lib path error, errno %s", dlopen_err);
        return CT_ERROR;
    }

    CT_RETURN_IFERR(mes_load_symbol(intf->uc_handle, "dpuc_msg_alloc", (void **)(&intf->dpuc_msg_alloc)));
    CT_RETURN_IFERR(mes_load_symbol(intf->uc_handle, "dpuc_msg_free", (void **)(&intf->dpuc_msg_free)));
    CT_RETURN_IFERR(mes_load_symbol(intf->uc_handle, "dpuc_msgparam_set", (void **)(&intf->dpuc_msgparam_set)));
    CT_RETURN_IFERR(mes_load_symbol(intf->uc_handle, "dpuc_msgmem_reg_integrate", (void **)(&intf->dpuc_msgmem_reg_integrate)));
    CT_RETURN_IFERR(mes_load_symbol(intf->uc_handle, "dpuc_msg_send", (void **)(&intf->dpuc_msg_send)));
    CT_RETURN_IFERR(mes_load_symbol(intf->uc_handle, "dpuc_msglen_get", (void **)(&intf->dpuc_msglen_get)));
    CT_RETURN_IFERR(mes_load_symbol(intf->uc_handle, "dpuc_sgl_addr_set", (void **)(&intf->dpuc_sgl_addr_set)));
    CT_RETURN_IFERR(mes_load_symbol(intf->uc_handle, "dpuc_sgl_addr_get", (void **)(&intf->dpuc_sgl_addr_get)));
    CT_RETURN_IFERR(mes_load_symbol(intf->uc_handle, "dpuc_data_addr_get", (void **)(&intf->dpuc_data_addr_get)));
    CT_RETURN_IFERR(mes_load_symbol(intf->uc_handle, "dpuc_eid_make", (void **)(&intf->dpuc_eid_make)));
    CT_RETURN_IFERR(mes_load_symbol(intf->uc_handle, "dpuc_eid_reg", (void **)(&intf->dpuc_eid_reg)));
    CT_RETURN_IFERR(mes_load_symbol(intf->uc_handle, "dpuc_set_src_eid_addr", (void **)(&intf->dpuc_set_src_eid_addr)));
    CT_RETURN_IFERR(mes_load_symbol(intf->uc_handle, "dpuc_set_dst_eid_addr", (void **)(&intf->dpuc_set_dst_eid_addr)));
    CT_RETURN_IFERR(mes_load_symbol(intf->uc_handle, "dpuc_set_sched_info", (void **)(&intf->dpuc_set_eid_reactor)));
    CT_RETURN_IFERR(mes_load_symbol(intf->uc_handle, "dpuc_set_subhealth_threshold", (void **)(&intf->dpuc_set_subhealth_threshold)));
    CT_RETURN_IFERR(mes_load_symbol(intf->uc_handle, "dpuc_process_set_config", (void **)(&intf->dpuc_process_set_config)));
    CT_RETURN_IFERR(mes_load_symbol(intf->uc_handle, "dpuc_xnet_set_process_ver", (void **)(&intf->dpuc_xnet_set_process_ver)));
    CT_RETURN_IFERR(mes_load_symbol(intf->uc_handle, "dpuc_all_init", (void **)(&intf->dpuc_all_init)));
    CT_RETURN_IFERR(mes_load_symbol(intf->uc_handle, "dpuc_regist_link_event", (void **)(&intf->dpuc_regist_link_event)));
    CT_RETURN_IFERR(mes_load_symbol(intf->uc_handle, "dpuc_link_create_with_addr", (void **)(&intf->dpuc_link_create_with_addr)));
    CT_RETURN_IFERR(mes_load_symbol(intf->uc_handle, "dpuc_qlink_close", (void **)(&intf->dpuc_qlink_close)));
    CT_RETURN_IFERR(mes_load_symbol(intf->uc_handle, "dpuc_set_security_cert_info", (void **)(&intf->dpuc_set_security_cert_info)));
    CT_LOG_RUN_INF("load uc from libdbstoreClient.so done");

    return CT_SUCCESS;
}

status_t dsw_init_lib(void)
{
    mes_interface_t *intf = &g_mes_interface;
    intf->dsw_handle = dlopen("libdswcore_mem.so", RTLD_LAZY);
    const char * dlopen_err = NULL;
    dlopen_err = dlerror();
    if (intf->dsw_handle == NULL) {
        CT_LOG_RUN_ERR("fail to load libdswcore_mem.so, maybe lib path error, errno %s", dlopen_err);
        return CT_ERROR;
    }

    CT_RETURN_IFERR(mes_load_symbol(intf->dsw_handle, "dsw_core_init", (void **)(&intf->dsw_core_init)));
    CT_LOG_RUN_INF("load libdswcore_mem.so done");

    return CT_SUCCESS;
}

status_t umm_init_lib(void)
{
    mes_interface_t *intf = &g_mes_interface;
    intf->umm_handle = dlopen("libdpumm_cmm.so", RTLD_LAZY);
    const char * dlopen_err = NULL;
    dlopen_err = dlerror();

    if (intf->umm_handle == NULL) {
        CT_LOG_RUN_ERR("fail to load libdpumm_cmm.so, maybe lib path error, errno %s", dlopen_err);
        return CT_ERROR;
    }

    CT_RETURN_IFERR(mes_load_symbol(intf->umm_handle, "allocMultiPagesSync", (void **)(&intf->allocate_multi_pages_sync)));
    CT_RETURN_IFERR(mes_load_symbol(intf->umm_handle, "freeMultiPages", (void **)(&intf->free_multi_pages)));
    CT_RETURN_IFERR(mes_load_symbol(intf->umm_handle, "copyDataFromBufferToSgl", (void **)(&intf->copy_data_from_buf_to_sgl)));
    CT_RETURN_IFERR(mes_load_symbol(intf->umm_handle, "copyDataFromSglToBuffer", (void **)(&intf->copy_data_from_sgl_to_buf)));
    CT_RETURN_IFERR(mes_load_symbol(intf->umm_handle, "dpumm_set_config_path", (void **)(&intf->dpumm_set_config_path)));
    CT_RETURN_IFERR(mes_load_symbol(intf->umm_handle, "getLastSgl", (void **)(&intf->get_last_sgl)));
    CT_LOG_RUN_INF("load libdpumm_cmm.so done");

    return CT_SUCCESS;
}

status_t dplog_init_lib(void)
{
    mes_interface_t *intf = &g_mes_interface;
    intf->dplog_handle = dlopen("libdplog.so", RTLD_LAZY);
    const char *dlopen_err = NULL;
    dlopen_err = dlerror();

    if (intf->dplog_handle == NULL) {
        CT_LOG_RUN_ERR("fail to load libdplog.so, maybe lib path error, errno %s", dlopen_err);
        return CT_ERROR;
    }

    CT_RETURN_IFERR(mes_load_symbol(intf->dplog_handle, "dplog_init", (void **)(&intf->dplog_init)));
    CT_RETURN_IFERR(mes_load_symbol(intf->dplog_handle, "dplog_set_backup_num", (void **)(&intf->dplog_set_backup_num)));
    CT_RETURN_IFERR(mes_load_symbol(intf->dplog_handle, "dplog_set_file_path_ext", (void **)(&intf->dplog_set_file_path_ext)));
    CT_LOG_RUN_INF("load libdplog.so done");

    return CT_SUCCESS;
}

void mes_close_lib(void)
{
    mes_interface_t *intf = &g_mes_interface;
    if (intf->uc_handle != NULL) {
        (void)dlclose(intf->uc_handle);
    }
    if (intf->dsw_handle != NULL) {
        (void)dlclose(intf->dsw_handle);
    }
    if (intf->umm_handle != NULL) {
        (void)dlclose(intf->umm_handle);
    }
    if (intf->dplog_handle != NULL) {
        (void)dlclose(intf->dplog_handle);
    }
}

void mes_destroy_uc(void)
{
    uint32 i;
    for (i = 0; i < g_mes.profile.reactor_thread_num; ++i) {
        cm_thread_lock(&g_mes_uc_recv_thead[i].lock);
        g_mes_uc_recv_thead[i].thread_ready = CT_FALSE;
    }
    mes_destory_message_pool();
    for (i = 0; i < g_mes.profile.reactor_thread_num; ++i) {
        cm_thread_unlock(&g_mes_uc_recv_thead[i].lock);
    }

    mes_close_lib();
}

dpuc_msg* mes_uc_alloc_uc_msg(u32 msgLen)
{
    dpuc_msg_alloc_param msg_param = { 0 };

    msg_param.pEidObj = g_mes_uc_config.eid_obj;
    msg_param.pMsgTemplate = NULL;
    msg_param.uiSize = msgLen;
    msg_param.ucDataType = DPUC_DATA;
    msg_param.ucMsgType = DPUC_TYPE_POST;

    return mes_global_handle()->dpuc_msg_alloc(&msg_param, __FUNCTION__);
}

void mes_uc_free_uc_msg_sgl(dpuc_msg* ucMsg)
{
    SGL_S *sgl = NULL;
    if (ucMsg != NULL) {
        sgl = mes_global_handle()->dpuc_sgl_addr_get(ucMsg, __FUNCTION__);
        if (sgl != NULL) {
            MES_UC_FREE_PAGES(sgl);
        }
    }
    return;
}

void mes_uc_free_uc_msg(dpuc_msg* ucMsg)
{
    if (ucMsg != NULL) {
        (void)mes_global_handle()->dpuc_msg_free(ucMsg, __FUNCTION__);
    }
    return;
}

void mes_modify_last_entry_len(SGL_S* sgl, int len)
{
    SGL_S* lastSgl = NULL;
    uint32_t entryIdx = 0;
    SGL_ENTRY_S* entry = NULL;
    mes_global_handle()->get_last_sgl(sgl, &lastSgl, &entryIdx);
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
        return CT_ERROR;
    }

    if (mes_global_handle()->copy_data_from_buf_to_sgl(sgl, 0, (char *)head, head->size) != RETURN_OK) {
        MES_LOGGING(MES_LOGGING_SEND, "mes copy data to sgl failed, page num %u, size %u", page_num, head->size);
        MES_UC_FREE_PAGES(sgl);
        return CT_ERROR;
    }
    
    mes_modify_last_entry_len(sgl, (head->size - (page_num - 1) * MES_UC_BYTE_PER_PAGE_PI));
    // 按圆整后的长度发送
    if (mes_global_handle()->dpuc_sgl_addr_set(mes_uc_msg, sgl, head->size, __FUNCTION__) != DP_OK) {
        MES_LOGGING(MES_LOGGING_SEND, "mes set sgl to uc failed, page num %u", page_num);
        MES_UC_FREE_PAGES(sgl);
        return CT_ERROR;
    }
    return CT_SUCCESS;
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
        return CT_ERROR;
    }

    for (index = 0; index < buff_list->cnt; index++) {
        if (mes_global_handle()->copy_data_from_buf_to_sgl(sgl, sgl_offset, buff_list->buffers[index].buf,
                buff_list->buffers[index].len) != RETURN_OK) {
            CT_LOG_RUN_ERR("mes copy data to sgl failed, page num %u, size %u, index %u",
                page_num, head->size, index);
            MES_UC_FREE_PAGES(sgl);
            return CT_ERROR;
        }
        sgl_offset += buff_list->buffers[index].len;
    }

    mes_modify_last_entry_len(sgl, (head->size - (page_num - 1) * MES_UC_BYTE_PER_PAGE_PI));
    // 按圆整后的长度发送
    if (mes_global_handle()->dpuc_sgl_addr_set(mes_uc_msg, sgl, head->size, __FUNCTION__) != DP_OK) {
        MES_LOGGING(MES_LOGGING_SEND, "mes set sgl to uc failed, page num %u", page_num);
        MES_UC_FREE_PAGES(sgl);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t mes_uc_add_buf_list_to_msg_head(dpuc_msg *mes_uc_msg, mes_message_head_t *head, mes_bufflist_t *buff_list)
{
    uint32_t index;
    errno_t err;
    uint32_t data_offset = 0;
    char* user_data = NULL;

    user_data = (char*)mes_global_handle()->dpuc_data_addr_get(mes_uc_msg, __FUNCTION__);
    if (user_data == NULL) {
        MES_LOGGING(MES_LOGGING_SEND, "mes get dpuc data addr failed");
        return CT_ERROR;
    }

    for (index = 0; index < buff_list->cnt; index++) {
        err = memcpy_sp(user_data + data_offset, MES_UC_MAX_USER_DATA_LEN - data_offset, buff_list->buffers[index].buf,
            buff_list->buffers[index].len);
        MEMS_RETURN_IFERR(err);
        data_offset += buff_list->buffers[index].len;
    }
    return CT_SUCCESS;
}

int32_t mes_uc_send_msg_ack_callback(int32_t result, dpuc_msg_param_s *msg_param, void *context)
{
    if (result != RETURN_OK) {
        MES_LOGGING(MES_LOGGING_SEND, "mes uc send failed, ret %d, eid(0x%lx -> 0x%lx) opcode %u",
                    result, msg_param->sendEid, msg_param->recvEid, msg_param->uiOpcode);
    }

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
            CT_LOG_RUN_ERR("mes alloc uc msg failed, cmd %u", head->cmd);
            return CT_ERROR;
        }
        user_data = (char*)mes_global_handle()->dpuc_data_addr_get(*mes_uc_msg, __FUNCTION__);
        if (user_data == NULL) {
            CT_LOG_RUN_ERR("mes get data addr failed, cmd %u", head->cmd);
            return CT_ERROR;
        }
        err = memcpy_sp(user_data, MES_UC_MAX_USER_DATA_LEN, head, head->size);
        MEMS_RETURN_IFERR(err);
    } else {
        *mes_uc_msg = mes_uc_alloc_uc_msg(0);
        if (*mes_uc_msg == NULL) {
            CT_LOG_RUN_ERR("mes alloc uc msg failed, cmd %u", head->cmd);
            return CT_ERROR;
        }
        if (mes_uc_add_data_to_msg(*mes_uc_msg, head) != CT_SUCCESS) {
            MES_LOGGING(MES_LOGGING_SEND, "mes add data to msg failed, cmd %u", head->cmd);
            mes_uc_free_uc_msg(*mes_uc_msg);
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
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

    if (mes_uc_connection_ready(dst_inst) != CT_TRUE) {
        MES_LOGGING_WAR(MES_LOGGING_SEND, "uc connection from %u to %u is not ready, cmd=%u, rsn=%u, src_sid=%u,"
            "dst_sid=%u", head->src_inst, head->dst_inst, head->cmd, head->rsn, head->src_sid, head->dst_sid);
        return CT_ERROR;
    }

    mes_get_consume_time_start(&stat_time);

    CT_RETURN_IFERR(mes_uc_alloc_msg(head, &mes_uc_msg));

    ret = mes_global_handle()->dpuc_msgparam_set(mes_uc_msg, g_mes_uc_config.eid, g_mes_uc_config.dst_eid[dst_inst], head->cmd, __FUNCTION__);
    if (ret != DP_OK) {
        MES_LOGGING(MES_LOGGING_SEND, "mes set uc msg param failed, src_eid 0x%lx, dst_eid 0x%lx, cmd %u",
            g_mes_uc_config.eid, g_mes_uc_config.dst_eid[dst_inst], head->cmd);
        mes_uc_free_uc_msg(mes_uc_msg);
        return CT_ERROR;
    }

    // 增加时延统计 回ACK时间
    pContext = (mes_uc_send_context*)malloc(sizeof(mes_uc_send_context));
    if (pContext == NULL) {
        MES_LOGGING(MES_LOGGING_SEND, "mes set uc send context failed, src_eid 0x%lx, dst_eid 0x%lx, cmd %u",
            g_mes_uc_config.eid, g_mes_uc_config.dst_eid[dst_inst], head->cmd);
        return CT_ERROR;
    }
    pContext->cmd = head->cmd;
    mes_get_consume_time_start(&start_ack_time);
    pContext->start_time = start_ack_time;

    ret = mes_global_handle()->dpuc_msg_send(mes_uc_msg, mes_uc_send_msg_ack_callback, pContext, __FUNCTION__);
    if (ret != DP_OK) {
        MES_LOGGING(MES_LOGGING_SEND, "mes send post msg failed, src_eid 0x%lx, dst_eid 0x%lx, cmd %u, ret %d",
            g_mes_uc_config.eid, g_mes_uc_config.dst_eid[head->dst_inst], head->cmd, ret);
        mes_uc_free_mem(pContext, mes_uc_msg);
        return CT_ERROR;
    }

    mes_consume_with_time(head->cmd, MES_TIME_SEND_IO, stat_time);

    return CT_SUCCESS;
}

status_t mes_uc_alloc_buff_msg(mes_bufflist_t *buff_list, mes_message_head_t *head, dpuc_msg **mes_uc_msg)
{
    if (head->size <= MES_UC_MAX_USER_DATA_LEN) {
        *mes_uc_msg = mes_uc_alloc_uc_msg(head->size);
        if (*mes_uc_msg == NULL) {
            CT_LOG_RUN_ERR("mes alloc uc msg failed, cmd %u", head->cmd);
            return CT_ERROR;
        }
        if (mes_uc_add_buf_list_to_msg_head(*mes_uc_msg, head, buff_list) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("mes add bufflist to msg head failed, cmd %u", head->cmd);
            mes_uc_free_uc_msg(*mes_uc_msg);
            return CT_ERROR;
        }
    } else {
        *mes_uc_msg = mes_uc_alloc_uc_msg(0);
        if (*mes_uc_msg == NULL) {
            CT_LOG_RUN_ERR("mes alloc uc msg failed, cmd %u", head->cmd);
            return CT_ERROR;
        }
        if (mes_uc_add_buf_list_to_msg(*mes_uc_msg, head, buff_list) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("mes add bufflist to msg failed, cmd %u", head->cmd);
            mes_uc_free_uc_msg(*mes_uc_msg);
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
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

    if (mes_uc_connection_ready(dst_inst) != CT_TRUE) {
        MES_LOGGING_WAR(MES_LOGGING_SEND, "uc connection from %u to %u is not ready, cmd=%u, rsn=%u, src_sid=%u,"
            "dst_sid=%u", head->src_inst, head->dst_inst, head->cmd, head->rsn, head->src_sid, head->dst_sid);
        return CT_ERROR;
    }

    mes_get_consume_time_start(&stat_time);
    CT_RETURN_IFERR(mes_uc_alloc_buff_msg(buff_list, head, &mes_uc_msg));

    ret = mes_global_handle()->dpuc_msgparam_set(mes_uc_msg, g_mes_uc_config.eid, g_mes_uc_config.dst_eid[dst_inst], head->cmd, __FUNCTION__);
    if (ret != DP_OK) {
        MES_LOGGING(MES_LOGGING_SEND, "mes set uc msg param failed, src_eid 0x%lx, dst_eid 0x%lx, cmd %u",
            g_mes_uc_config.eid, g_mes_uc_config.dst_eid[dst_inst], head->cmd);
        mes_uc_free_uc_msg(mes_uc_msg);
        return CT_ERROR;
    }

    // 增加时延统计 回ACK时间
    pContext = (mes_uc_send_context*)malloc(sizeof(mes_uc_send_context));
    if (pContext == NULL) {
        MES_LOGGING(MES_LOGGING_SEND, "mes set uc send context failed, src_eid 0x%lx, dst_eid 0x%lx, cmd %u",
            g_mes_uc_config.eid, g_mes_uc_config.dst_eid[dst_inst], head->cmd);
        return CT_ERROR;
    }
    pContext->cmd = head->cmd;
    mes_get_consume_time_start(&start_ack_time);
    pContext->start_time = start_ack_time;

    ret = mes_global_handle()->dpuc_msg_send(mes_uc_msg, mes_uc_send_msg_ack_callback, pContext, __FUNCTION__);
    if (ret != DP_OK) {
        MES_LOGGING(MES_LOGGING_SEND, "mes send post msg failed, src_eid 0x%lx, dst_eid 0x%lx, cmd %u, ret %d",
            g_mes_uc_config.eid, g_mes_uc_config.dst_eid[head->dst_inst], head->cmd, ret);
        mes_uc_free_mem(pContext, mes_uc_msg);
        return CT_ERROR;
    }

    mes_consume_with_time(head->cmd, MES_TIME_SEND_IO, stat_time);

    return CT_SUCCESS;
}

status_t mes_uc_get_mes_msg_from_uc_head(dpuc_msg *uc_msg, mes_message_t *mes_msg)
{
    errno_t err;
    char *user_data = NULL;
    mes_message_head_t *head = NULL;

    user_data = (char*)mes_global_handle()->dpuc_data_addr_get(uc_msg, __FUNCTION__);
    if (user_data == NULL) {
        MES_LOGGING(MES_LOGGING_SEND, "mes recv uc msg head failed");
        return CT_ERROR;
    }

    head = (mes_message_head_t *)user_data;
    if (mes_check_msg_head(head) != CT_SUCCESS) {
        CT_THROW_ERROR_EX(ERR_MES_ILEGAL_MESSAGE, "mes message length=%u, cmd=%u, rsn=%u, src_inst=%u, dst_inst=%u, "
            "src_sid=%u, dst_sid=%u, thead id=%d", head->size, head->cmd, head->rsn, head->src_inst, head->dst_inst,
            head->src_sid, head->dst_sid, g_thread_queue_id);
        return CT_ERROR;
    }

    mes_get_message_buf(mes_msg, head);
    if ((mes_msg->buffer == NULL) || (mes_msg->head == NULL)) {
        MES_LOGGING(MES_LOGGING_SEND, "mes get msg buf failed");
        return CT_ERROR;
    }
    err = memcpy_s(mes_msg->buffer, head->size, head, head->size);
    MEMS_RETURN_IFERR(err);
    return CT_SUCCESS;
}

status_t mes_uc_get_mes_msg_from_uc_msg(dpuc_msg *uc_msg, mes_message_t *mes_msg)
{
    SGL_S *uc_msg_data = NULL;
    mes_message_head_t *head = NULL;

    uc_msg_data = mes_global_handle()->dpuc_sgl_addr_get(uc_msg, __FUNCTION__);
    // sgl有效的entry是从第一个开始
    if ((uc_msg_data == NULL) || (uc_msg_data->entrys[0].len < sizeof(mes_message_head_t))) {
        mes_uc_free_uc_msg_sgl(uc_msg);
        MES_LOGGING(MES_LOGGING_SEND, "mes recv uc msg sgl failed");
        return CT_ERROR;
    }

    head = (mes_message_head_t *)uc_msg_data->entrys[0].buf;
    if (mes_check_msg_head(head) != CT_SUCCESS) {
        mes_uc_free_uc_msg_sgl(uc_msg);
        CT_THROW_ERROR_EX(ERR_MES_ILEGAL_MESSAGE, "mes message length=%u, cmd=%u, rsn=%u, src_inst=%u, dst_inst=%u, "
            "src_sid=%u, dst_sid=%u, thead id=%d", head->size, head->cmd, head->rsn, head->src_inst, head->dst_inst,
            head->src_sid, head->dst_sid, g_thread_queue_id);
        return CT_ERROR;
    }

    mes_get_message_buf(mes_msg, head);
    if ((mes_msg->buffer == NULL) || (mes_msg->head == NULL)) {
        MES_LOGGING(MES_LOGGING_SEND, "mes get msg buf failed");
        mes_uc_free_uc_msg_sgl(uc_msg);
        return CT_ERROR;
    }

    // sgl有效数据从头开始
    if (mes_global_handle()->copy_data_from_sgl_to_buf(uc_msg_data, 0, mes_msg->buffer, head->size) != RETURN_OK) {
        MES_LOGGING(MES_LOGGING_SEND, "mes copy data from sgl to buf failed, size %u", head->size);
        mes_free_buf_item(mes_msg->buffer);
        mes_uc_free_uc_msg_sgl(uc_msg);
        return CT_ERROR;
    }
    mes_uc_free_uc_msg_sgl(uc_msg);
    return CT_SUCCESS;
}

void mes_get_thread_id(void)
{
    if (g_thread_queue_id == CT_INVALID_ID8) {
        cm_spin_lock(&g_thread_queue_id_lock, NULL);
        g_thread_queue_id = g_thread_id % MES_UC_MAX_REACTOR_THREAD_NUM;
        g_thread_id++;
        cm_spin_unlock(&g_thread_queue_id_lock);
        CT_LOG_DEBUG_INF("set thread queue id = %d.", g_thread_queue_id);
    }
}

int32_t mes_uc_msg_recv_func(dpuc_msg *uc_msg, dpuc_msg_mem_free_mode_e *freeMode)
{
    mes_message_t mes_msg = {NULL, NULL};
    uint64 stat_time = 0;
    status_t ret = CT_ERROR;

    mes_get_consume_time_start(&stat_time);

    if (uc_msg == NULL) {
        MES_LOGGING(MES_LOGGING_SEND, "mes recv uc msg is invalid");
        return RETURN_ERROR;
    }

    if (freeMode != NULL) {
        *freeMode = DPUC_AUTO_FREE;
    }

    mes_get_thread_id();
    cm_thread_lock(&g_mes_uc_recv_thead[g_thread_queue_id].lock);
    if (!g_mes_uc_recv_thead[g_thread_queue_id].thread_ready) {
        MES_LOGGING(MES_LOGGING_SEND, "get mes msg failed, recv thread is not ready");
        cm_thread_unlock(&g_mes_uc_recv_thead[g_thread_queue_id].lock);
        return RETURN_ERROR;
    }

    uint32 uc_msg_len = mes_global_handle()->dpuc_msglen_get(uc_msg, __FUNCTION__);
    if (uc_msg_len >= sizeof(mes_message_head_t)) {
        ret = mes_uc_get_mes_msg_from_uc_head(uc_msg, &mes_msg);
    } else if (uc_msg_len == 0) {
        ret = mes_uc_get_mes_msg_from_uc_msg(uc_msg, &mes_msg);
    } else {
        CT_LOG_RUN_ERR("[mes] mes uc recv message len is invalid");
    }
    if (ret != CT_SUCCESS) {
        MES_LOGGING(MES_LOGGING_RECV, "get mes msg from uc failed");
        cm_thread_unlock(&g_mes_uc_recv_thead[g_thread_queue_id].lock);
        return RETURN_ERROR;
    }

    if (g_mes_uc_channel_status[mes_msg.head->src_inst].is_allow_msg_transfer != CT_TRUE) {
        MES_LOGGING(MES_LOGGING_RECV, "mes not allow msg transfer, src_inst=%u.", mes_msg.head->src_inst);
        cm_thread_unlock(&g_mes_uc_recv_thead[g_thread_queue_id].lock);
        return RETURN_ERROR;
    }
    mes_consume_with_time(mes_msg.head->cmd, MES_TIME_READ_MES, stat_time);

    if (g_mes.crc_check_switch) {
        if (mes_message_vertify_cks(&mes_msg) != CT_SUCCESS) {
            cm_thread_unlock(&g_mes_uc_recv_thead[g_thread_queue_id].lock);
            CT_LOG_RUN_ERR("[mes] check cks failed, cmd=%u, rsn=%u, src_inst=%u, dst_inst=%u", mes_msg.head->cmd,
                mes_msg.head->rsn, mes_msg.head->src_inst, mes_msg.head->dst_inst);
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
    CT_RETURN_IFERR(dplog_init_lib());

    ret = mes_global_handle()->dplog_init();
    if (ret != DP_OK) {
        CT_LOG_RUN_ERR("Init dplog failed (%d).", ret);
        return ret;
    }
    CT_LOG_RUN_INF("Init dplog success.");

    // dpax log store path
    ret = mes_global_handle()->dplog_set_file_path_ext((char *)running_log_path, (char *)running_log_path);
    if (ret != DP_OK) {
        CT_LOG_RUN_ERR("Set dplog path failed(%d).", ret);
        return ret;
    }
    CT_LOG_RUN_INF("Set dplog path success.");

    ret = mes_global_handle()->dplog_set_backup_num(DPLOG_MAX_NUM);
    if (ret != DP_OK) {
        CT_LOG_RUN_ERR("Set dplog backup num failed(%d).", ret);
        return ret;
    }
    CT_LOG_RUN_INF("Set dplog backup num success.");

    return DP_OK;
}

uint8 lsid_to_inst_id(u32 uiDstlsId)
{
    uint8 i;
    for (i = 0; i < g_mes.profile.inst_count; i++) {
        if (uiDstlsId == g_mes.profile.inst_lsid[i]) {
            return i;
        }
    }
    return CT_INVALID_ID8;
}

// check create link status
int32_t create_link_callback(u32 uiDstlsId, dpuc_qlink_event qlinkEvent, dpuc_plane_type_e planeType, dupc_qlink_cause_t qlinkCause)
{
    CT_LOG_DEBUG_INF("Destination link (0x%x), status (%d), plane type (%d), reason (%d).", uiDstlsId, qlinkEvent, planeType, qlinkCause);

    uint8 inst_id = lsid_to_inst_id(uiDstlsId);
    if (inst_id == CT_INVALID_ID8) {
        CT_LOG_RUN_ERR("Not find valid inst id");
        return DP_FAIL;
    }
    CT_LOG_RUN_INF("UC link %s, dst lsid=(0x%x)", (qlinkEvent == DPUC_QLINK_UP ? "up" : "down"), uiDstlsId);
    if (inst_id == g_mes.profile.inst_id) {
        CT_LOG_RUN_INF("other inst create link to own inst");
        return DP_OK;
    }

    mes_uc_conn_t *conn = &g_mes_uc_channel_status[inst_id];
    mes_channel_stat_t pre_status = conn->uc_channel_state;
    cm_thread_lock(&conn->lock);
    if (qlinkEvent == DPUC_QLINK_UP) {
        conn->uc_channel_state = MES_CHANNEL_CONNECTED;
        CT_LOG_RUN_INF("channel status covert to CONNECTED.");
    } else if ((qlinkEvent == DPUC_QLINK_DOWN) && (conn->uc_channel_state == MES_CHANNEL_CONNECTED)) {
        conn->uc_channel_state = MES_CHANNEL_UNCONNECTED;
        CT_LOG_RUN_INF("channel status covert to UNCONNECTED.");
        rc_bitmap64_set(&g_channel_reconn_bits, inst_id);
        cm_release_cond_signal(&g_reconn_thread_cond);
        CT_LOG_RUN_INF("cm realse cond signal success.");
    } else {
        CT_LOG_RUN_WAR("qlinkEvent is invalid");
    }
    cm_thread_unlock(&conn->lock);

    CT_LOG_RUN_INF("UC link %s, dst lsid=(0x%x), inst id=%d, pre_status=%d, cur_status=%d", (qlinkEvent == DPUC_QLINK_UP ? "up" : "down"),
        uiDstlsId, inst_id, pre_status, conn->uc_channel_state);
    return DP_OK;
}

int32_t link_state_change_callback(u32 uiDstlsId, dpuc_link_state_event_t qlinkEvent, dpuc_plane_type_e planeType,
    void *param)
{
    if ((qlinkEvent != DPUC_LINK_STATE_EVENT_SUBHEALTH_ORIGIN) &&
        (qlinkEvent != DPUC_LINK_STATE_EVENT_SUBHEALTH_CLEAR)) {
        CT_LOG_RUN_WAR("link state change, qlinkEvent (%d), dst lsid (0x%x)", qlinkEvent, uiDstlsId);
        return DP_OK;
    }

    uint8 inst_id = lsid_to_inst_id(uiDstlsId);
    if (inst_id == CT_INVALID_ID8) {
        CT_LOG_RUN_ERR("Not find valid inst id");
        return DP_FAIL;
    }
    if (inst_id == g_mes.profile.inst_id) {
        CT_LOG_RUN_INF("link state change, dst inst is own inst.");
        return DP_OK;
    }

    mes_uc_conn_t *conn = &g_mes_uc_channel_status[inst_id];
    conn->uc_channel_state = (qlinkEvent == DPUC_LINK_STATE_EVENT_SUBHEALTH_ORIGIN ?
        MES_CHANNEL_SUBHEALTH : MES_CHANNEL_CONNECTED);

    if (param == NULL) {
        CT_LOG_RUN_ERR("link state change, param is null.");
        return DP_FAIL;
    }
    dpuc_subhealth_info_t *subhealth_info = (dpuc_subhealth_info_t*)param;
    CT_LOG_RUN_WAR("slow event %s, dst lsid (0x%x), local ip (%s), remote ip (%s)",
        (qlinkEvent == DPUC_LINK_STATE_EVENT_SUBHEALTH_ORIGIN ? "occur" : "recover"), uiDstlsId,
        subhealth_info->local_ip, subhealth_info->remote_ip);
    return DP_OK;
}

// mes uc create eid and register eid
int32_t create_and_reg_eid(mes_uc_config_t *uc_config, dpuc_msg_recv_s *msg_recv_func)
{
    int32_t ret = DP_ERROR;
    // 生成进程使用的eid，外部传入
    ret = mes_global_handle()->dpuc_eid_make(NORMAL_TYPE, MY_PID, 0, uc_config->lsid, &uc_config->eid, __FUNCTION__);
    if (ret != DP_OK) {
        CT_LOG_RUN_ERR("Generate eid failed.");
        return ret;
    }
    CT_LOG_DEBUG_INF("Generate eid success.");

    // 注册进程使用的eid
    ret = mes_global_handle()->dpuc_eid_reg(uc_config->com_mgr, uc_config->eid, msg_recv_func, &uc_config->eid_obj, __FUNCTION__);
    if (ret != DP_OK) {
        CT_LOG_RUN_ERR("Reg src eid failed, eid=0x%lx.", uc_config->eid);
        return ret;
    }
    CT_LOG_DEBUG_INF("Reg src eid success, eid=0x%lx.", uc_config->eid);

    // 创建建链回调函数
    dpucLinkEventOps link_event = {create_link_callback, link_state_change_callback, NULL};
    ret = mes_global_handle()->dpuc_regist_link_event(uc_config->eid, &link_event, __FUNCTION__);
    if (ret != DP_OK) {
        CT_LOG_RUN_ERR("Reg create link status func failed.");
        return ret;
    }
    CT_LOG_DEBUG_INF("Reg create link status func successs");
    return ret;
}

// mes uc create reactor
int32_t create_reactor(mes_uc_config_t *uc_config)
{
    int32_t ret = DP_ERROR;
    // 创建reactor
    const uint32_t threadNum = g_mes.profile.reactor_thread_num;
    CT_LOG_DEBUG_INF("Set reacot thread num = %d.", threadNum);
    if (threadNum > MES_UC_MAX_REACTOR_THREAD_NUM) {
        CT_LOG_RUN_ERR("reator threadNum is excced, threadNum = %d", threadNum);
        return DP_ERROR;
    }

    dpuc_xnet_thread_info_s threadInfo[threadNum];
    uint32_t i;
    for (i = 0; i < threadNum; i++) {
        threadInfo[i].pri = 0;
        CPU_ZERO(&(threadInfo[i].cpu_set));
    }
    dpuc_sched_conf_info_s cfgInfo = { 0, 0, threadInfo, threadNum};
    ret = mes_global_handle()->dpuc_set_eid_reactor(uc_config->eid_obj, "mes_cfg_xnet", &cfgInfo, __FUNCTION__);
    if (ret != DP_OK) {
        CT_LOG_RUN_ERR("Generate reactor failed (%d).", ret);
        return ret;
    }
    CT_LOG_DEBUG_INF("Generate reactor success.");
    return ret;
}

int32_t set_subhealth_threshold(void)
{
    if (g_mes.profile.upgrade_time_ms == 0 || g_mes.profile.degrade_time_ms == 0) {
        CT_LOG_RUN_INF("Use default subhealth threshold, upgrade time (%u ms), degrade time (%u ms).",
            g_mes.profile.upgrade_time_ms, g_mes.profile.degrade_time_ms);
        return DP_OK;
    }
    dpuc_subhealth_threshold subhealth_threshold = {0};
    subhealth_threshold.type = DPUC_XNET_TCP;
    subhealth_threshold.plane = DPUC_DATA_PLANE;
    subhealth_threshold.hop = 0;
    subhealth_threshold.upgradeTimeNs = (uint64_t)g_mes.profile.upgrade_time_ms * NS_PER_MS;
    subhealth_threshold.degradeTimeNs = (uint64_t)g_mes.profile.degrade_time_ms * NS_PER_MS;
    int32_t ret = mes_global_handle()->dpuc_set_subhealth_threshold(subhealth_threshold, __FUNCTION__);
    if (ret != DP_OK) {
        CT_LOG_RUN_ERR("Set subhealth threshhold failed (%d).", ret);
        return ret;
    }
    CT_LOG_RUN_INF("Set subhealth threshhold success, upgrade time (%lu ns), degrade time (%lu ns).",
        subhealth_threshold.upgradeTimeNs, subhealth_threshold.degradeTimeNs);
    return DP_OK;
}

status_t mes_uc_set_process_config(void)
{
    dpuc_necessary_config_param_t dpuc_config_para = {1024, 64, 0, 10240, 10240, 1024, 1024, 1024, 1024};
    int32 ret = mes_global_handle()->dpuc_process_set_config(&dpuc_config_para, NULL, __FUNCTION__);
    if (ret != DP_OK) {
        CT_LOG_RUN_ERR("Set dpuc process config failed (%d).", ret);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

int32_t mes_uc_decode_kmc_pwd(char *pass, uint32 pass_len, char *plain, uint32_t max_key_len, uint32 *plain_len)
{
    aes_and_kmc_t aes_kmc = { 0 };
    cm_kmc_set_kmc(&aes_kmc, CT_KMC_SERVER_DOMAIN, KMC_ALGID_AES256_CBC);
    cm_kmc_set_buf(&aes_kmc, plain, max_key_len - 1, pass, pass_len);
    if (cm_kmc_decrypt_pwd(&aes_kmc) != CT_SUCCESS) {
        return CT_ERROR;
    }
    plain[aes_kmc.plain_len] = '\0';
    *plain_len = aes_kmc.plain_len;
    return CT_SUCCESS;
}

int32_t mes_uc_get_crt_file_path(uint32_t inst_id, char *pub_key_file, uint32_t *pub_key_file_len)
{
    if (inst_id >= CT_MAX_INSTANCES) {
        CT_LOG_RUN_ERR("[mes]: crt inst_id is invalid %u", inst_id);
        return CT_ERROR;
    }
    PRTS_RETURN_IFERR(snprintf_s(pub_key_file, DPUC_MAX_FILE_NAME_LEN, DPUC_MAX_FILE_NAME_LEN, "%s/mes.crt",
        mes_get_ssl_auth_file()->cert_dir));
    *pub_key_file_len = DPUC_MAX_FILE_NAME_LEN;
    return CT_SUCCESS;
}

// initialize function
int32_t init_xnet_dpuc(mes_uc_config_t *uc_config)
{
    //动态加载uc相关so
    CT_RETURN_IFERR(uc_init_lib());
    CT_RETURN_IFERR(dsw_init_lib());
    CT_RETURN_IFERR(umm_init_lib());

    int32_t ret = DP_ERROR;
    // 注册post消息接收函数，目前只有post类型
    dpuc_msg_recv_s msg_recv_func = {mes_uc_msg_recv_func, NULL};

    dpuc_comm_mgr_param commMgrParam = {2048, 2048, MY_PID, uc_config->lsid, 0};

    // 区分计算云
    // 物理机上dbstor会调用umm初始化sgl、req的分区
    if (!g_enable_dbstor) {
        ret = mes_global_handle()->dpumm_set_config_path("/home/regress/CantianKernel/pkg/test/mes_test/", __FUNCTION__, __LINE__);
    } else {
        ret = mes_global_handle()->dpumm_set_config_path(g_mes.profile.dpumm_config_path, __FUNCTION__, __LINE__);
    }
    if (ret != DP_OK) {
        CT_LOG_RUN_ERR("umm set failed (%d).", ret);
        return DP_ERROR;
    }
    CT_LOG_DEBUG_INF("umm set success.");

    if (mes_global_handle()->dsw_core_init(NULL, 0, NULL) != 0) {
        CT_LOG_RUN_ERR("[mes] dsw_core_init failed");
        return CT_ERROR;
    }

    if (g_mes.profile.channel_version != CT_INVALID_ID64) {
        (void)mes_global_handle()->dpuc_xnet_set_process_ver(g_mes.profile.channel_version);
        CT_LOG_RUN_INF("mes set channel version=%lld.", g_mes.profile.channel_version);
    }

    // UC鉴权认证初始化设置
    dpuc_security_cert_info_t dpuc_link_cert_info;
    dpuc_link_cert_info.security_cert_switch = g_mes.profile.use_ssl;
    dpuc_link_cert_info.user_id = (uint32_t)g_mes.profile.inst_id;
    PRTS_RETURN_IFERR(snprintf_s(dpuc_link_cert_info.pri_key_file, DPUC_MAX_FILE_NAME_LEN, DPUC_MAX_FILE_NAME_LEN,
        mes_get_ssl_auth_file()->key_file));
    PRTS_RETURN_IFERR(snprintf_s(dpuc_link_cert_info.pub_key_file, DPUC_MAX_FILE_NAME_LEN, DPUC_MAX_FILE_NAME_LEN,
        mes_get_ssl_auth_file()->cert_file));
    PRTS_RETURN_IFERR(snprintf_s(dpuc_link_cert_info.pri_key_pass_file, DPUC_MAX_FILE_NAME_LEN, DPUC_MAX_FILE_NAME_LEN,
        mes_get_ssl_auth_file()->pass_file));
    dpuc_link_cert_info.get_pub_key_func = mes_uc_get_crt_file_path;
    dpuc_link_cert_info.kmca_decrypt_func = mes_uc_decode_kmc_pwd;
    mes_global_handle()->dpuc_set_security_cert_info(&dpuc_link_cert_info, __FUNCTION__, MY_PID);

    // 初始化通信模块
    uc_config->com_mgr = mes_global_handle()->dpuc_all_init(&commMgrParam, __FUNCTION__);
    if (uc_config->com_mgr == NULL) {
        CT_LOG_RUN_ERR("Init dpuc failed, pid=%d, lsid=0x%x.", commMgrParam.usPid, commMgrParam.uiServiceId);
        return DP_ERROR;
    }
    CT_LOG_RUN_INF("Init dpuc success, pid=%d, lsid=0x%x.", commMgrParam.usPid, commMgrParam.uiServiceId);
    MES_UC_RETURN_IFERR(create_and_reg_eid(uc_config, &msg_recv_func));
    MES_UC_RETURN_IFERR(set_subhealth_threshold());

    // 注册EID的消息并发
    dpuc_datamsg_mem_ops data_ops;
    data_ops.pfnReqAllocMsgMem = NULL;
    data_ops.pfnRspAllocMsgMem = NULL;
    data_ops.pfnFreeMsgMem = NULL;
    data_ops.uiSendDataMsgNumReserve = DPUC_DATA_MSG_RESERVE;
    data_ops.uiSendDatamsgNumMax     = DPUC_DATA_MSG_MAX;
    data_ops.uiRecvDataMsgNumReserve = DPUC_DATA_MSG_RESERVE;
    data_ops.uiRecvDatamsgNumMax     = DPUC_DATA_MSG_MAX;

    ret = mes_global_handle()->dpuc_msgmem_reg_integrate(uc_config->eid_obj, NULL, &data_ops, __FUNCTION__);
    if (ret != DP_OK) {
        CT_LOG_RUN_ERR("Set concurrent info failed.");
        return ret;
    }
    CT_LOG_DEBUG_INF("Set concurrent info success.");

    MES_UC_RETURN_IFERR(create_reactor(uc_config));

    return DP_OK;
}

status_t mes_uc_connect_init_addr(dpuc_addr eid_addr[], char *ip, uint16 port, uint32* eid_num)
{
    uint32 ip_cnt = 0;
    char ip_addrs[CM_INST_MAX_IP_NUM][CM_MAX_IP_LEN] = {{0}};
    if (cm_parse_lsnr_addr(ip, (uint32)strlen(ip), &ip_cnt, ip_addrs) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("mes uc connectinit addr failed, ip=%s, port=%u, ip_cnt=%u.", ip, port, ip_cnt);
        return CT_ERROR;
    }
    *eid_num = ip_cnt;

    for (int i = 0; i < ip_cnt; i++) {
        eid_addr[i].AddrFamily = (g_mes.profile.pipe_type == CS_TYPE_UC ? DPUC_ADDR_FAMILY_IPV4 :
            DPUC_ADDR_FAMILY_IPV4_RDMA);
        eid_addr[i].PlaneType = DPUC_DATA_PLANE;
        char listen_ip[CM_MAX_IP_LEN] = {0};
        if (cm_domain_to_ip(ip_addrs[i], listen_ip) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("mes get listen ip failed.");
            return CT_ERROR;
        }
        CT_LOG_RUN_INF("domain to ip success, listen ip %s", listen_ip);
        PRTS_RETURN_IFERR(sprintf_s(eid_addr[i].Url, DPUC_URL_LEN, "%s:%u", listen_ip, port));
    }
    return CT_SUCCESS;
}

// initialize server identifier
int32_t mes_uc_server(mes_uc_config_t *uc_config, char *ip, uint16 port)
{
    uint32 ip_cnt = 0;
    dpuc_addr eid_addr[CM_INST_MAX_IP_NUM];
    if (mes_uc_connect_init_addr(eid_addr, ip, port, &ip_cnt) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("init client eid addr failed ip(%s) ip_cnt(%u) port(%d).", ip, ip_cnt, port);
        return CT_ERROR;
    }
    // 设置server(本地)监听的ip和端口
    int32_t ret = mes_global_handle()->dpuc_set_src_eid_addr(uc_config->eid_obj, eid_addr,
        ip_cnt, DPUC_ADDR_SERVER, __FUNCTION__);
    if (ret != DP_OK) {
        CT_LOG_RUN_ERR("mes set src eid addr failed, eid=0x%lx url=%s ip_cnt=%u.",
                       uc_config->eid, eid_addr[0].Url, ip_cnt);
        return ret;
    }
    CT_LOG_RUN_INF("mes set src server eid addr success, eid=0x%lx, ip_cnt=%u.", uc_config->eid, ip_cnt);
    return CT_SUCCESS;
}

status_t mes_uc_create_link(uint32 inst_id, dpuc_addr *client_eid_addr, dpuc_addr *server_eid_addr)
{
    int32_t ret;
    CT_LOG_RUN_INF("Instance %d eid=0x%lx, url=%s to connect instance %d, eid=0x%lx, url=%s.",
        g_mes.profile.inst_id, g_mes_uc_config.eid, client_eid_addr->Url,
        inst_id, g_mes_uc_config.dst_eid[inst_id], server_eid_addr->Url);
    // 进行建链
    dpuc_conn_params_t con_param = { 0 };
    con_param.pri = 0;
    con_param.hop = 0;
    con_param.time_out = 0;
    con_param.runMode = DPUC_PERSISTENT_CONN;
    con_param.recovery_pri = DPUC_CONN_RECVOERY_L;
    con_param.pSrcAddr = client_eid_addr;
    con_param.pDstAddr = server_eid_addr;
    con_param.kaInterval = 1; // xnet heart beat judge interval, 0: use default values 10s;
    con_param.kaTimeoutTimes = MES_UC_XNET_TIMEOUT_TIMES; // xnet heart beat timeout disconnect.
    for (uint32 i = 0; i < g_mes.profile.channel_num; i++) {
        ret = mes_global_handle()->dpuc_link_create_with_addr(g_mes_uc_config.eid_obj, 
            g_mes_uc_config.dst_eid[inst_id], &con_param, __FUNCTION__);
        if (ret != DP_OK) {
            CT_LOG_RUN_ERR("To intance %d create link failed.", inst_id);
            return CT_ERROR;
        }
    }
    g_mes_uc_channel_status[inst_id].is_allow_msg_transfer = CT_TRUE;
    CT_LOG_RUN_INF("Call create link success.");
    return CT_SUCCESS;
}
// uc connect interface
status_t mes_uc_connect(uint32 inst_id)
{
    if (inst_id == g_mes.profile.inst_id || inst_id >= CT_MAX_INSTANCES) {
        CT_LOG_RUN_ERR("connect id is invalid %d", inst_id);
        return CT_ERROR;
    }
    uint32 lsid = g_mes.profile.inst_lsid[inst_id];

    // set dst eid
    int32_t ret = mes_global_handle()->dpuc_eid_make(NORMAL_TYPE, MY_PID, 0, lsid,
        &g_mes_uc_config.dst_eid[inst_id], __FUNCTION__);
    if (ret != DP_OK) {
        CT_LOG_RUN_ERR("Set dst eid failed (%d).", ret);
        return CT_ERROR;
    }

    // 设置本地的ip和地址
    dpuc_addr client_eid_addr[CM_INST_MAX_IP_NUM];
    char *lsnr_host = MES_HOST_NAME(g_mes.profile.inst_id);
    uint16 port = g_mes.profile.inst_arr[g_mes.profile.inst_id].port;
    uint32 client_ip_cnt = 0;
    if (mes_uc_connect_init_addr(client_eid_addr, lsnr_host, port, &client_ip_cnt) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("init client eid addr failed ip(%s) ip_cnt(%u).", lsnr_host, client_ip_cnt);
        return CT_ERROR;
    }

    // 设置需要连接的server的eid, ip和地址
    dpuc_addr server_eid_addr[CM_INST_MAX_IP_NUM];
    lsnr_host = MES_HOST_NAME(inst_id);
    port = g_mes.profile.inst_arr[inst_id].port;
    uint32 server_ip_cnt = 0;
    if (mes_uc_connect_init_addr(server_eid_addr, lsnr_host, port, &server_ip_cnt) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("init server eid addr failed ip(%s) ip_cnt(%u).", lsnr_host, server_ip_cnt);
        return CT_ERROR;
    }
    ret = mes_global_handle()->dpuc_set_dst_eid_addr(g_mes_uc_config.com_mgr, g_mes_uc_config.dst_eid[inst_id],
                                server_eid_addr, server_ip_cnt, __FUNCTION__);
    if (ret != DP_OK) {
        CT_LOG_RUN_ERR("mes set dst inst_id(%d) eid addr failed=%d, ip_cnt=%u.", inst_id, ret, server_ip_cnt);
        return CT_ERROR;
    }
    // 校验client和server解析出的ip对数是否相等
    if (client_ip_cnt != server_ip_cnt) {
        CT_LOG_RUN_WAR("mes uc connect parse ip abnormal, ip cnt info[%u - %u].", client_ip_cnt, server_ip_cnt);
    }
    // 建链
    for (int i = 0; i < MIN(server_ip_cnt, client_ip_cnt); i++) {
        if (mes_uc_create_link(inst_id, &client_eid_addr[i], &server_eid_addr[i]) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("mes connect to inst(%u) create link(%u) failed.", inst_id, i);
            return CT_ERROR;
        }
    }
        
    // 发起建链后，更改链路状态
    mes_uc_conn_t *conn = &g_mes_uc_channel_status[inst_id];
    cm_thread_lock(&conn->lock);
    if (conn->uc_channel_state == MES_CHANNEL_CLOSED) {
        conn->uc_channel_state = MES_CHANNEL_UNCONNECTED;
    }
    cm_thread_unlock(&conn->lock);

    CT_LOG_RUN_INF("mes uc inst(%u) connect to inst(%u) create (%u:%u) link success.",
                   g_mes.profile.inst_id, inst_id, server_ip_cnt, client_ip_cnt);
    return CT_SUCCESS;
}

// sync disconnect
void mes_uc_disconnect(uint32 inst_id)
{
    if (inst_id >= CT_MAX_INSTANCES) {
        CT_LOG_RUN_ERR("inst_id out of range CT_MAX_INSTANCES.");
        return;
    }
    g_mes_uc_channel_status[inst_id].is_allow_msg_transfer = CT_FALSE;
    uint32 lsid = g_mes.profile.inst_lsid[inst_id];
    int32_t ret = DP_ERROR;
    ret = mes_global_handle()->dpuc_qlink_close(lsid, DPUC_DESTROY_LINK, DPUC_DATA_PLANE, __FUNCTION__);
    if (ret != DP_OK) {
        CT_LOG_RUN_ERR("Disconnect dst_lsid 0x%x failed.", lsid);
        return;
    }
    mes_uc_conn_t *conn = &g_mes_uc_channel_status[inst_id];
    cm_thread_lock(&conn->lock);
    conn->uc_channel_state = MES_CHANNEL_CLOSED;
    cm_thread_unlock(&conn->lock);
    CT_LOG_RUN_INF("Disconnect dst_lsid 0x%x success.", lsid);
}

// asysnc disconnect
void mes_uc_disconnect_async(uint32 inst_id)
{
    mes_uc_disconnect(inst_id);
}

// check inst_id is or not connect
bool32 mes_uc_connection_ready(uint32 inst_id)
{
    mes_uc_conn_t *conn = &g_mes_uc_channel_status[inst_id];
    return ((conn->uc_channel_state != MES_CHANNEL_UNCONNECTED) && (conn->is_allow_msg_transfer == CT_TRUE));
}

mes_channel_stat_t mes_uc_get_channel_state(uint32 inst_id)
{
    return g_mes_uc_channel_status[inst_id].uc_channel_state;
}

// uc try accept
status_t mes_uc_lsnr(void)
{
    char *lsnr_host = MES_HOST_NAME(g_mes.profile.inst_id);
    uint16 port = g_mes.profile.inst_arr[g_mes.profile.inst_id].port;
    if (mes_uc_server(&g_mes_uc_config, lsnr_host, port) != DP_OK) {
        CT_LOG_RUN_ERR("mes_start_lsnr failed.");
        return CT_ERROR;
    }
    CT_LOG_DEBUG_INF("mes_start_lsnr suceess.");
    return CT_SUCCESS;
}

void mes_init_uc_channel_status(void)
{
    uint32 i;
    mes_uc_conn_t *conn;
    for (i = 0; i < CT_MAX_INSTANCES; i++) {
        conn = &g_mes_uc_channel_status[i];
        conn->uc_channel_state = MES_CHANNEL_CLOSED;
        conn->is_allow_msg_transfer = CT_FALSE;
        cm_init_thread_lock(&conn->lock);
    }
    // 本节点消息
    g_mes_uc_channel_status[g_mes.profile.inst_id].is_allow_msg_transfer = CT_TRUE;
}

static uint64 mes_uc_get_reconn_bitmap()
{
    uint64 reconn_bitmap = 0;
    for (uint32 i = 0; i < g_mes.profile.inst_count; i++) {
        if (i == g_mes.profile.inst_id) {
            continue;
        }
        if (rc_bitmap64_exist(&g_channel_reconn_bits, i)) {
            rc_bitmap64_set(&reconn_bitmap, i);
            rc_bitmap64_clear(&g_channel_reconn_bits, i);
        }
    }
    CT_LOG_RUN_INF("mes uc should reconnect, reconn_bitmap = %llu", reconn_bitmap);
    return reconn_bitmap;
}

void mes_channel_check_thread(thread_t *thread)
{
    while (!thread->closed) {
        CT_LOG_RUN_INF("mes channel check is running.");
        uint64 reconn_bitmap = mes_uc_get_reconn_bitmap();
        if (reconn_bitmap == 0) {
            cm_wait_cond_no_timeout(&g_reconn_thread_cond);
            CT_LOG_RUN_INF("cm wait cond no timeout success.");
            continue;
        }

        for (uint32 i = 0; i < g_mes.profile.inst_count; ++i) {
            if (i == g_mes.profile.inst_id) {
                continue;
            }
            if (!MES_SHOULD_RECONN(reconn_bitmap, i)) {
                continue;
            }

            //断掉原来的链路
            mes_uc_disconnect(i);
            CT_LOG_RUN_INF("disconnect success, inst_id = %d", i);
            //重新建链
            if (mes_uc_connect(i) != CT_SUCCESS) {
                CT_LOG_RUN_ERR("reconnect failed, inst_id = %d", i);
                continue;
            }
            CT_LOG_RUN_INF("reconnect success, inst_id = %d", i);
        }
    }
}

// mes uc init
status_t mes_init_uc(void)
{
    uint32 i;
    for (i = 0; i < MES_UC_MAX_REACTOR_THREAD_NUM; i++) {
        init_msgqueue(&g_mes_uc_recv_thead[i].msg_queue);
        cm_init_thread_lock(&g_mes_uc_recv_thead[i].lock);
        g_mes_uc_recv_thead[i].thread_ready = CT_TRUE;
    }
    mes_init_uc_channel_status();
    mes_init_mq_local_queue();
    CT_RETURN_IFERR(mes_init_message_pool());

    // set dpax log path
    if (!g_enable_dbstor) {
        char log_path[CT_MAX_PATH_LEN];
        sprintf_s(log_path, CT_MAX_PATH_LEN, "%s", "/home/cantiandba");
        if (init_dpuc_log((char *)log_path) != DP_OK) {
            CT_LOG_RUN_ERR("uc log initialize failed.");
            return CT_ERROR;
        }
        CT_LOG_RUN_INF("uc log initialize successs.");
    }

    g_mes_uc_config.lsid = g_mes.profile.inst_lsid[g_mes.profile.inst_id];
    CT_LOG_DEBUG_INF("mes uc config lsid = 0x%x", g_mes_uc_config.lsid);

    if (init_xnet_dpuc(&g_mes_uc_config) != DP_OK) {
        CT_LOG_RUN_ERR("UC config initialize failed.");
        return CT_ERROR;
    }
    CT_LOG_DEBUG_INF("UC config initialize success.");

    CT_RETURN_IFERR(mes_uc_lsnr());
    
    // 开启线程，监听链路变化，重新解析域名
    cm_init_cond(&g_reconn_thread_cond);
    g_channel_reconn_bits = 0;
    if (cm_create_thread(mes_channel_check_thread, 0, NULL, &g_mes_channel_check_thread) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("mes create channel check thread failed.");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}