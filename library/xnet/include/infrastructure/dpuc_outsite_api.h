/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: The head file of the uniform communication api

 * Create: 2020-08-11
 * Notes: NA
 * History: 2020-08-11: zhangzhanzhong: Create the head file.
 *
 */

#ifndef DPUC_OUTSITE_API_H
#define DPUC_OUTSITE_API_H

#include "dpuc_api_def.h"

#ifdef __cplusplus
#if __cplusplus
extern "C"{
#endif
#endif /* __cplusplus */

typedef enum tagDpucEngineType {
    DPUC_ENGINE_XNET = 0,
    DPUC_ENGINE_NGW,
    DPUC_ENGINE_DPSHM,
    DPUC_ENGINE_CGW,
    DPUC_ENGINE_BUTT
}dpuc_engine_type_e;

typedef enum tagDpucEngineOpsType {
    DPUC_OPS_TYPE_MSG_SEND_FUNC = 0,
    DPUC_OPS_TYPE_GET_LINK_STATUS,

    DPUC_OPS_TYPE_INVALID_OPS = 0xFF
}dpuc_engine_ops_type_e;

typedef int32_t (*dpuc_user_reg_func)(void* arg);

typedef int32_t (*dpuc_msg_send_cb_func)(int send_result, void* ctx, uint32_t ngw_recv_lsid);

typedef struct tagDpucUserSendFuncParam {
    dpuc_msg*            send_msg;
    void*                  ctx;
    dpuc_msg_send_cb_func  uc_send_cb;
}dpuc_user_send_func_param_t;	

int32_t dpuc_set_engine_ops_func(dpuc_engine_type_e engine_type, 
    dpuc_engine_ops_type_e ops_type, dpuc_user_reg_func func, void *arg, const char* func_name);
#define DPUC_SET_ENGINE_OPS_FUNC(engine_type, func_type, func, arg) \
    dpuc_set_engine_ops_func(engine_type, func_type, func, arg, __FUNCTION__)

void* dpuc_get_uc_head_addr(dpuc_msg* msg, const char* func_name);
#define DPUC_GET_UC_HEAD_ADDR(msg) \
    dpuc_get_uc_head_addr(msg, __FUNCTION__)

uint32_t dpuc_get_uc_head_len(const char* func_name);
#define DPUC_GET_UC_HEAD_LEN() \
    dpuc_get_uc_head_len(__FUNCTION__)

uint32_t dpuc_get_uc_private_data_len(const char* func_name);
#define DPUC_GET_UC_PRIVATE_DATA_LEN() \
    dpuc_get_uc_private_data_len(__FUNCTION__)

dpuc_msg* dpuc_make_uc_msg(void* head, void* sgl, void* buff, uint32_t buff_len, const char* func_name);
#define DPUC_MAKE_UC_MSG(head, sgl, buff, buff_len) \
    dpuc_make_uc_msg(head, sgl, buff, buff_len, __FUNCTION__)
	
int32_t dpuc_msg_recv_func(dpuc_msg* msg, const char* func_name);
#define DPUC_MSG_RECV_FUNC(msg) \
    dpuc_msg_recv_func(msg, __FUNCTION__)

void* dpuc_msg_ctrl_buff_alloc(void* head, uint32_t len, const char* func_name);
#define DPUC_MSG_CTRL_BUFF_ALLOC(head, len) \
    dpuc_msg_ctrl_buff_alloc(head, len, __FUNCTION__)
	
void dpuc_msg_ctrl_buff_free(const void* head, void* ctrl_buff, const char* func_name);
#define DPUC_MSG_CTRL_BUFF_FREE(head, ctrl_buff) \
    dpuc_msg_ctrl_buff_free(head, ctrl_buff, __FUNCTION__)

typedef struct tagDpucLinkEventInfo {
    uint32_t link_dst_lsid;
}dpuc_link_event_info_s;	

int32_t dpuc_link_event_notify(dpuc_qlink_event event_type, dpuc_link_event_info_s* event_info, const char* func_name);
#define DPUC_LINK_EVENT_NOTIFY(event_type, event_info) \
    dpuc_link_event_notify(event_type, event_info, __FUNCTION__)

uint8_t dpuc_get_siteid_from_eid(dpuc_eid_t eid, const char* func_name);
#define DPUC_GET_SITEID_FROM_EID(Eid) \
    dpuc_get_siteid_from_eid((Eid), __FUNCTION__)

uint32_t dpuc_timeout_get(dpuc_msg* msg, const char* func_name);
#define DPUC_TIMEOUT_GET(msg) \
    dpuc_timeout_get((msg), __FUNCTION__)

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cpluscplus */
#endif /* __cpluscplus */


#endif