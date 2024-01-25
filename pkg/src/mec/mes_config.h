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
 * mes_config.h
 *
 *
 * IDENTIFICATION
 * src/mec/mes_config.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __MES_CONFIG_H__
#define __MES_CONFIG_H__

#ifdef __cplusplus
extern "C" {
#endif

void mes_set_cluster_id(uint16 cluster_id);
uint32 get_config_cluster_id(void);
uint32 get_config_lsid(uint32 inst_id);
char* get_config_uuid(uint32 inst_id);
status_t set_all_inst_lsid(uint16 cluster_id, uint16 pid);
status_t mes_set_inst_lsid(uint16 cluster_id, uint16 pid, uint32 inst_id);

#ifdef __cplusplus
}
#endif

#endif
