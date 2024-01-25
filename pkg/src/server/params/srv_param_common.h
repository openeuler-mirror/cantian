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
 * srv_param_common.h
 *
 *
 * IDENTIFICATION
 * src/server/params/srv_param_common.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SRV_PARAM_COMMON_H__
#define __SRV_PARAM_COMMON_H__

#include "cm_config.h"
#include "knl_context.h"

#ifdef __cplusplus
extern "C"
#endif

status_t sql_verify_uint32(void *lex, void *def, uint32 *num);
status_t sql_verify_als_comm(void *se, void *lex, void *def);
status_t sql_verify_als_onoff(void *se, void *lex, void *def);
status_t sql_verify_als_uint32(void *se, void *lex, void *def);
status_t sql_verify_als_bool(void *se, void *lex, void *def);
status_t sql_notify_als_bool(void *se, void *item, char *value);
status_t sql_notify_als_onoff(void *se, void *item, char *value);
char *srv_get_param(const char *name);
status_t srv_get_param_bool32(char *param_name, bool32 *param_value);
status_t srv_get_param_onoff(char *param_name, bool32 *param_value);
status_t srv_get_param_uint16(char *param_name, uint16 *param_value);
status_t srv_get_param_uint32(char *param_name, uint32 *param_value);
status_t srv_get_param_uint64(char *param_name, uint64 *param_value);
status_t srv_get_param_second(char *param_name, uint64 *param_value);
status_t srv_get_param_double(char *param_name, double *param_value);
status_t srv_get_param_size_uint32(char *param_name, uint32 *param_value);
status_t srv_get_param_size_uint64(char *param_name, uint64 *param_value);
status_t srv_verf_param_uint64(char *param_name, uint64 param_value, uint64 min_value, uint64 max_value);
status_t sql_verify_pool_size(void *lex, void *def, int64 min_size, int64 max_size);
status_t srv_get_index_auto_rebuild(char *time_str, knl_attr_t *attr);

#ifdef __cplusplus
}
#endif

#endif
