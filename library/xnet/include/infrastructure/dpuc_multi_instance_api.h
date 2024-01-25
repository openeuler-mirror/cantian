/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: The head file of the multi instance communication api

 * Create: 2020-10-22
 * Notes: NA
 * History: 2020-10-22: zhangzhanzhong: Create the head file.
 *
 */

#ifndef DPUC_MULTI_INSTANCE_API_H
#define DPUC_MULTI_INSTANCE_API_H

#include "dpuc_api_def.h"

#ifdef __cplusplus
#if __cplusplus
extern "C"{
#endif
#endif /* __cplusplus */

typedef dpuc_comm_mgr dpuc_instance_t;

typedef struct tagDpucInstanceParam {
    uint32_t recv_queue_size;
    uint32_t rst_queue_size;
    uint16_t usr_mid;
    uint32_t service_id;
    uint8_t  mode;
    uint8_t  eid_type;
    uint8_t reserve_mem;
} dpuc_instance_para_t;

dpuc_instance_t* dpuc_reg_instance(dpuc_necessary_config_param_t* need_config,
    dpuc_optional_config_param_t *optional_config, dpuc_instance_para_t* instance_param, const char* func_name);
#define DPUC_REG_INSTANCE(need_config, optional_config, instance_param) \
    dpuc_reg_instance(need_config, optional_config, instance_param, __FUNCTION__)

typedef enum {
    DPUC_MGR_THRD_HEAL_TIME = 0,
    DPUC_INSTANCE_ATTR_BUTT = 0xFF
} dpuc_instance_attr_e;

int32_t dpuc_instance_attr_set(dpuc_instance_t *instance, dpuc_instance_attr_e attr_type, void *attr_value,
    const char *func_name);
#define DPUC_INSTANCE_ATTR_SET(instance, attr_type, instance_attr_value) \
    dpuc_instance_attr_set((instance), (attr_type), (instance_attr_value), __FUNCTION__)

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cpluscplus */
#endif /* __cpluscplus */

#endif