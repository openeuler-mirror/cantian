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
 * cms_mes.c
 *
 *
 * IDENTIFICATION
 * src/cms/cms/cms_mes.c
 *
 * -------------------------------------------------------------------------
 */
#include "cms_log_module.h"
#include "cm_malloc.h"
#include "cms_instance.h"
#include "mes_queue.h"
#include "mes_func.h"
#include "mes_config.h"
#include "cms_comm.h"
#include "cms_mes.h"
#include "cms_node_fault.h"
#include "cms_log.h"
#include "cms_stat.h"

cms_processor_t             g_cms_processors[CMS_MES_CMD_CEIL] = {0};
cms_session_ctrl_t          g_cms_session_ctrl = {0, 0, 0, NULL};

#define REACTOR_THREAD_NUM 2

status_t cms_init_session(void)
{
    uint32 max_session_num = g_cms_param->cms_mes_max_session_num;
    g_cms_session_ctrl.sessions = (cms_session_t *)cm_malloc(max_session_num * sizeof(cms_session_t));
    if (g_cms_session_ctrl.sessions == NULL) {
        CMS_LOG_ERR("cms instance failed to get instance object address!");
        return CT_ERROR;
    }

    uint32 cms_session_size = max_session_num * sizeof(cms_session_t);
    errno_t err = memset_s(g_cms_session_ctrl.sessions, cms_session_size, 0, cms_session_size);
    if (err != EOK) {
        CM_FREE_PTR(g_cms_session_ctrl.sessions);
        return CT_ERROR;
    }

    for (uint32 i = 0; i < max_session_num; ++i) {
        g_cms_session_ctrl.sessions[i].id = i;
        g_cms_session_ctrl.sessions[i].is_closed = CT_TRUE;
    }

    g_cms_session_ctrl.used_count = 0;
    g_cms_session_ctrl.total = max_session_num;

    return CT_SUCCESS;
}

status_t cms_create_session(cms_session_t **session)
{
    *session = NULL;
    uint32 id = CT_INVALID_ID32;
    cm_spin_lock(&g_cms_session_ctrl.lock, NULL);
    for (uint32 i = 0; i < g_cms_session_ctrl.total; i++) {
        if (g_cms_session_ctrl.sessions[i].is_closed == CT_TRUE) {
            id = i;
            break;
        }
    }

    if (id == CT_INVALID_ID32) {
        cm_spin_unlock(&g_cms_session_ctrl.lock);
        CMS_LOG_ERR("there is no unused session");
        return CT_ERROR;
    }
    g_cms_session_ctrl.sessions[id].is_closed = CT_FALSE;
    g_cms_session_ctrl.used_count++;
    cm_spin_unlock(&g_cms_session_ctrl.lock);
    *session = &g_cms_session_ctrl.sessions[id];
    return CT_SUCCESS;
}

void cms_destroy_session(cms_session_t *session)
{
    uint32 id = session->id;
    cm_spin_lock(&g_cms_session_ctrl.lock, NULL);
    g_cms_session_ctrl.sessions[id].is_closed = CT_TRUE;
    g_cms_session_ctrl.used_count--;
    cm_spin_unlock(&g_cms_session_ctrl.lock);
}

void cms_free_mes_session(void)
{
    CM_FREE_PTR(g_cms_session_ctrl.sessions);
    g_cms_session_ctrl.sessions = NULL;
    g_cms_session_ctrl.lock = 0;
    g_cms_session_ctrl.total = 0;
    g_cms_session_ctrl.used_count = 0;
}

/*
    cms_msg: cms req/res massage
    sid: session id
    request_ack: if cms request massage needs ack, request_ack equals to GA_TRUE, or equals to GA_FALSE
    mes_msg: mes massage with cms massage
*/
status_t init_mes_send_msg(cms_packet_head_t* cms_msg, uint32 sid, bool32 request_ack, cms_mes_msg_t *mes_msg)
{
    if (cms_msg->msg_size > CMS_MSG_MAX_LEN) {
        CMS_LOG_ERR("msg size exceed max mag len, msg size: %u", cms_msg->msg_size);
        return CT_ERROR;
    }

    uint8 cmd;
    // if the res msg is ack, cms_msg->is_ack equals to CT_TRUE
    if (cms_msg->is_ack == CT_TRUE) {
        cmd = CMS_MES_MSG_WITH_ACK;
    } else {
        cms_msg->sid = CT_INVALID_ID16;
        cmd = CMS_MES_MSG;
    }
    mes_init_send_head(&mes_msg->head, cmd, sizeof(mes_message_head_t) + cms_msg->msg_size, CT_INVALID_ID32,
        g_mes.profile.inst_id, cms_msg->dest_node, sid, cms_msg->sid);
    // for res msg
    if (cms_msg->is_ack == CT_TRUE) {
        cms_msg->need_ack = CT_FALSE;
        mes_msg->head.rsn = cms_msg->rsn;
        mes_msg->head.dst_sid = cms_msg->sid;
    }

    // for req msg, if req msg need ack, request_ack equals to CT_TRUE
    if (request_ack == CT_TRUE) {
        cms_msg->need_ack = CT_TRUE;
        cms_msg->rsn = mes_msg->head.rsn;
        cms_msg->sid = mes_msg->head.src_sid;
    }
    errno_t ret = EOK;
    ret = memcpy_s(mes_msg->cms_msg, CMS_MSG_MAX_LEN, (const void *)cms_msg, cms_msg->msg_size);
    MEMS_RETURN_IFERR(ret);
    return CT_SUCCESS;
}

status_t creat_mes_recv_msg(mes_message_t *mes_res, cms_packet_head_t* res)
{
    cms_mes_msg_t *recv_msg = (cms_mes_msg_t*)(mes_res->buffer);
    errno_t ret = EOK;
    cms_packet_head_t *cms_msg = (cms_packet_head_t *)recv_msg->cms_msg;
    ret = memcpy_s(res, CMS_MSG_MAX_LEN, (const void *)recv_msg->cms_msg, cms_msg->msg_size);
    MEMS_RETURN_IFERR(ret);
    mes_release_message_buf(mes_res->buffer);
    return CT_SUCCESS;
}

status_t cms_mes_send_data(cms_packet_head_t* cms_msg, cms_packet_head_t* res, cms_session_t *session,
    uint32 timeout_ms, bool32 request_ack)
{
    if (!CMS_IS_TIMER_MSG(cms_msg->msg_type)) {
        CMS_LOG_DEBUG_INF("begin to send msg to node %u, msg type %u.", cms_msg->dest_node, cms_msg->msg_type);
    }
    
    cms_mes_msg_t mes_msg;
    status_t ret = init_mes_send_msg(cms_msg, session->id, request_ack, &mes_msg);
    if (ret != CT_SUCCESS) {
        CMS_LOG_ERR("Failed to init mes send msg.");
        return CT_ERROR;
    }
    if (mes_cms_send_data((void*)&mes_msg) != CT_SUCCESS) {
        CMS_LOG_WAR_LIMIT(LOG_PRINT_INTERVAL_SECOND_20,
                          "send msg to node %u err, msg type %u.", cms_msg->dest_node, cms_msg->msg_type);
        return CT_ERROR;
    }

    if (!request_ack) {
        return CT_SUCCESS;
    }

    mes_message_t mes_res;
    if (mes_recv(session->id, &mes_res, CT_FALSE, CT_INVALID_ID32, timeout_ms) != CT_SUCCESS) {
        CMS_LOG_ERR("recv msg from node %u err, msg type %u.", cms_msg->dest_node, cms_msg->msg_type + 1);
        return CT_ERROR;
    }
    ret = creat_mes_recv_msg(&mes_res, res);
    if (ret != CT_SUCCESS) {
        CMS_LOG_ERR("Failed to creat mes recv msg.");
    }

    if (!CMS_IS_TIMER_MSG(cms_msg->msg_type)) {
        CMS_LOG_DEBUG_INF("recv msg from node %u succ, msg type %u.", res->src_node, res->msg_type);
    }
    return ret;
}

void cms_msg_enque(cms_packet_head_t *head)
{
    if (head->msg_type == CMS_MSG_REQ_HB) {
        cms_msg_req_hb_t* req_hb = (cms_msg_req_hb_t*)head;
        req_hb->req_receive_time = cm_now();
    }

    if (head->msg_type == CMS_MSG_RES_HB) {
        cms_msg_res_hb_t* res_hb = (cms_msg_res_hb_t*)head;
        res_hb->res_receive_time = cm_now();
    }
    biqueue_node_t* node = cms_que_alloc_node_ex((char*)head, head->msg_size);
    if (node == NULL) {
        CMS_LOG_ERR("cms que alloc node err");
        return;
    }
    cms_packet_head_t* msg = ((cms_packet_head_t*)cms_que_node_data(node));

    if (CMS_IS_TIMER_MSG(head->msg_type)) {
        CMS_LOG_MSG(CMS_LOG_TIMER, "recv msg succeed", head);
    } else {
        CMS_LOG_MSG(CMS_LOG_DEBUG_INF, "recv msg succeed", head);
    }

    if (msg->msg_type == CMS_MSG_REQ_HB) {
        cms_enque_ex(&g_cms_inst->recv_que, node, CMS_QUE_PRIORITY_HIGH);
    } else if (msg->msg_type >= CMS_MSG_REQ_ADD_RES && msg->msg_type <= CMS_MSG_RES_DEL_NODE) {
        cms_enque(&g_cms_inst->cmd_recv_que, node);
    } else {
        cms_enque(&g_cms_inst->recv_que, node);
    }
}

status_t cms_mes_request(cms_packet_head_t* req, cms_packet_head_t* res, uint32 timeout_ms)
{
    status_t ret = CT_SUCCESS;
    cms_session_t *session = NULL;
    if (cms_create_session(&session) != CT_SUCCESS) {
        CMS_LOG_ERR("creat session failed");
        return CT_ERROR;
    }
    ret = cms_mes_send_data(req, res, session, timeout_ms, CT_TRUE);
    cms_destroy_session(session);
    return ret;
}

status_t cms_mes_send_to(cms_packet_head_t* cms_msg)
{
    status_t ret = CT_SUCCESS;
    cms_session_t *session = NULL;
    if (cms_create_session(&session) != CT_SUCCESS) {
        CMS_LOG_ERR("creat session failed");
        return CT_ERROR;
    }
    ret = cms_mes_send_data(cms_msg, NULL, session, CMS_MES_WAIT_MAX_TIME, CT_FALSE);
    cms_destroy_session(session);
    return ret;
}

status_t cms_mes_send_cmd_to_other(cms_packet_head_t* req, cms_packet_head_t* res, uint16 node_id)
{
    req->src_node = g_cms_param->node_id;
    req->dest_node = node_id;
    status_t ret = cms_mes_request(req, res, CMS_CMD_RECV_TMOUT_MS);
    return ret;
}

void cms_mes_wakeup_rooms(void)
{
    CT_LOG_RUN_WAR("[mes] start wakeup all rooms.");
    mes_instance_t *mes_param = get_g_mes();
    for (uint32 i = 0; i < g_cms_param->cms_mes_max_session_num; i++) {
        mes_waiting_room_t *room = &mes_param->mes_ctx.waiting_rooms[i];
        cm_spin_lock(&room->lock, NULL);
        (void)cm_atomic_set(&room->timeout, 0);
        cm_spin_unlock(&room->lock);
    }
    CT_LOG_RUN_WAR("[mes] finish wakeup all rooms.");
}

void mes_proc_recv_msg(mes_message_t *mes_msg)
{
    cms_mes_msg_t *recv_msg = (cms_mes_msg_t*)(mes_msg->buffer);
    cms_packet_head_t* head = (cms_packet_head_t*)recv_msg->cms_msg;
    if (head->msg_size > CMS_MSG_MAX_LEN) {
        CT_LOG_RUN_ERR("invalid msg size: %d", head->msg_size);
    } else {
        cms_msg_enque(head);
    }
    cms_hb_counter_update(head);
    mes_release_message_buf(mes_msg->buffer);
}

void cms_mes_process_msg_ack(mes_message_t *msg)
{
    if (SECUREC_UNLIKELY(msg->head->dst_sid >= CT_MAX_MES_ROOMS)) {
        CT_LOG_RUN_ERR("[cms] invalid msg dst_inst: %u", msg->head->dst_sid);
        return;
    }
    mes_instance_t *mes_param = get_g_mes();
    mes_waiting_room_t *room = &mes_param->mes_ctx.waiting_rooms[msg->head->dst_sid];
    mes_consume_with_time(0, MES_TIME_MES_ACK, msg->head->req_start_time);
    cm_spin_lock(&room->lock, NULL);
    if (room->rsn == msg->head->rsn) {
        MES_LOG_HEAD(msg->head);
        room->msg_buf = msg->buffer;
        mes_mutex_unlock(&room->mutex);
        cm_spin_unlock(&room->lock);
    } else {
        cm_spin_unlock(&room->lock);
        MES_LOG_WAR_HEAD_EX(msg->head, "receive unmatch msg");
        mes_release_message_buf(msg->buffer);
    }
    return;
}

void cms_process_message(uint32 work_idx, mes_message_t *msg)
{
    if (SECUREC_UNLIKELY(msg->head->cmd >= CMS_MES_CMD_CEIL)) {
        CT_LOG_RUN_ERR("[cms] invalid msg cmd: %u", msg->head->cmd);
        return;
    }
    cms_processor_t *processor = &g_cms_processors[msg->head->cmd];
    if (processor->proc == NULL) {
        CT_LOG_RUN_ERR("The processing function of this message is NULL, cmd=%u", msg->head->cmd);
        return;
    }
    processor->proc(msg);
    return;
}

status_t cms_register_proc_func(cms_mes_command_t command_type, cms_message_proc_t proc, bool32 is_enqueue,
                                const char *func_name)
{
    errno_t ret;
    if (command_type >= CMS_MES_CMD_CEIL) {
        CT_THROW_ERROR_EX(ERR_MES_INVALID_CMD, "register mes command type(%d) is invalid.", command_type);
        return CT_ERROR;
    }

    g_cms_processors[command_type].proc = proc;
    g_cms_processors[command_type].is_enqueue = is_enqueue;
    ret = strncpy_s(g_cms_processors[command_type].name, CT_MAX_NAME_LEN, func_name, strlen(func_name));
    if (ret != EOK) {
        CT_THROW_ERROR_EX(ERR_MES_INVALID_CMD, "register func name (%s) is invalid.", func_name);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t cms_register_proc(void)
{
    CT_RETURN_IFERR(cms_register_proc_func(CMS_MES_MSG, mes_proc_recv_msg, CT_TRUE, "cms mes recv msg"));
    CT_RETURN_IFERR(cms_register_proc_func(CMS_MES_MSG_WITH_ACK, cms_mes_process_msg_ack, CT_TRUE,
        "cms mes recv msg with ack"));

    mes_register_proc_func(cms_process_message);
    return CT_SUCCESS;
}

status_t cms_init_mes_profile_attr(mes_profile_t *profile)
{
    profile->pool_size = MES_MESSAGE_POOL_SIZE;
    profile->buffer_pool_attr.pool_count = g_cms_param->cms_mes_msg_pool_count;
    profile->buffer_pool_attr.buf_attr[0].queue_count = g_cms_param->cms_mes_msg_queue_count;
    profile->buffer_pool_attr.buf_attr[0].size = MES_MESSAGE_BUFFER_SIZE;
    profile->buffer_pool_attr.buf_attr[0].count = g_cms_param->cms_mes_msg_buff_count;
    profile->inst_id = g_cms_param->node_id;
    profile->pipe_type = g_cms_param->cms_mes_pipe_type;
    profile->channel_num = g_cms_param->cms_mes_msg_channel_num;
    profile->work_thread_num = g_cms_param->cms_mes_thread_num;
    profile->reactor_thread_num = REACTOR_THREAD_NUM;
    profile->conn_by_profile = CT_TRUE;
    profile->inst_count = cms_get_gcc_node_count();
    return (profile->inst_count >= CT_MAX_INSTANCES ? CT_ERROR : CT_SUCCESS);
}

status_t cms_init_mes_profile_ip(mes_profile_t *profile)
{
    errno_t ret;
    cms_node_def_t node_def;
    for (uint32 i = 0; i < profile->inst_count; i++) {
        // set lsid
        profile->inst_lsid[i] = get_config_lsid(i);
        CT_LOG_RUN_INF("cms instance %d get lsid 0x%x", i, profile->inst_lsid[i]);
        if (cms_get_node_by_id(i, &node_def) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("node def is invalid ,node_id:%u", i);
            return CT_ERROR;
        }
        ret = strncpy_s(profile->inst_arr[i].ip, CT_MAX_INST_IP_LEN,
            node_def.ip, strnlen(node_def.ip, CT_MAX_INST_IP_LEN - 1));
        if (ret != EOK) {
            CT_LOG_RUN_ERR("cms_init_mes_profile_ip failed,node_id:%u, ip:%s", i, node_def.ip);
            return CT_ERROR;
        }
        profile->inst_arr[i].port = node_def.port;
        CT_LOG_RUN_INF("cms init node(%u) profile ip_addrs[%s] port[%u].",
            i, profile->inst_arr[i].ip, profile->inst_arr[i].port);
    }
    return CT_SUCCESS;
}

status_t cms_init_mes_profile(mes_profile_t *profile)
{
    if (profile == NULL) {
        CT_LOG_RUN_ERR("cms_init_mes_profile failed, profile is NULL");
        return CT_ERROR;
    }

    if (cms_init_mes_profile_attr(profile) == CT_ERROR) {
        CT_LOG_RUN_ERR("cms_init_mes_profile_attr failed, inst count(%u).", profile->inst_count);
        return CT_ERROR;
    }

    CT_RETURN_IFERR(cms_get_mes_channel_version(&(profile->channel_version)));

    if (cms_init_mes_profile_ip(profile) == CT_ERROR) {
        CT_LOG_RUN_ERR("cms_init_mes_profile_ip failed.");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t cms_set_mes_profile(void)
{
    mes_profile_t profile;
    MEMS_RETURN_IFERR(memset_sp(&profile, sizeof(mes_profile_t), 0, sizeof(mes_profile_t)));

    if (cms_init_mes_profile(&profile) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("cms_init_mes_profile failed.");
        return CT_ERROR;
    }

    if (profile.inst_count >= CT_MAX_INSTANCES) {
        CT_LOG_RUN_ERR("inst_count %u is invalid.", profile.inst_count);
        return CT_ERROR;
    }

    if (mes_set_profile(&profile) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("mes_set_profile failed.");
        return CT_ERROR;
    }

    if (mes_set_uc_dpumm_config_path(g_cms_param->cms_home) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("mes_set_uc_dpumm_config_path failed.");
        return CT_ERROR;
    }

    if (mes_set_group_task_num(0, CMS_MES_THREAD_NUM) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[mes]: mes_set_group_task_num %u failed.", 0);
        return CT_ERROR;
    }
    mes_set_crc_check_switch(g_cms_param->cms_mes_crc_check_switch);
    return CT_SUCCESS;
}

cms_session_ctrl_t *get_session_ctrl(void)
{
    return &g_cms_session_ctrl;
}

cms_processor_t *get_g_cms_processors(void)
{
    return g_cms_processors;
}

status_t cms_startup_mes(void)
{
    if (cms_register_proc() != CT_SUCCESS) {
        CT_LOG_RUN_ERR("cms_register_proc failed.");
        return CT_ERROR;
    }
 
    if (cms_set_mes_profile() != CT_SUCCESS) {
        CT_LOG_RUN_ERR("cms_set_mes_profile failed.");
        return CT_ERROR;
    }

    if (cms_init_session() != CT_SUCCESS) {
        CT_LOG_RUN_ERR("cms_init_session failed.");
        cms_free_mes_session();
        return CT_ERROR;
    }

    if (mes_startup() != CT_SUCCESS) {
        CT_LOG_RUN_ERR("mes_startup failed.");
        cms_free_mes_session();
        return CT_ERROR;
    }

    CT_LOG_RUN_INF("mes startup success");
    return CT_SUCCESS;
}

void cms_mes_send_entry(thread_t* thread)
{
    status_t ret = 0;
    
    while (!thread->closed) {
        CMS_LOG_TIMER("message count in send que:%lld", g_cms_inst->send_que.count);
        biqueue_node_t *node = cms_deque(&g_cms_inst->send_que);
        if (node == NULL) {
            continue;
        }

        cms_packet_head_t* msg = (cms_packet_head_t*)cms_que_node_data(node);
        if (msg->msg_type == CMS_MSG_REQ_HB) {
            cms_msg_req_hb_t* req_hb = (cms_msg_req_hb_t*)msg;
            req_hb->req_send_time = cm_now();
        }

        if (msg->msg_type == CMS_MSG_RES_HB) {
            cms_msg_res_hb_t* res_hb = (cms_msg_res_hb_t*)msg;
            res_hb->res_send_time = cm_now();
        }

        ret = cms_mes_send_to(msg);
        if (ret != CT_SUCCESS) {
            CMS_LOG_MSG(CT_LOG_DEBUG_ERR, "send msg faild", msg);
        } else {
            if (CMS_IS_TIMER_MSG(msg->msg_type)) {
                CMS_LOG_MSG(CMS_LOG_TIMER, "send msg succeed", msg);
            } else {
                CMS_LOG_MSG(CMS_LOG_DEBUG_INF, "send msg succeed", msg);
            }
        }
        cms_que_free_node(node);
    }

    return;
}
