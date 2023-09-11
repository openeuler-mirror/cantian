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
 * mes_uc.h
 *
 *
 * IDENTIFICATION
 * src/mec/mes_uc.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __MES_UC_H__
#define __MES_UC_H__

#ifdef __cplusplus
extern "C" {
#endif

status_t mes_uc_send_data(const void *msg_data);
status_t mes_uc_send_bufflist(mes_bufflist_t *buff_list);
status_t mes_uc_connect(uint32 inst_id);
void mes_uc_disconnect(uint32 inst_id);
void mes_uc_disconnect_async(uint32 inst_id);
bool32 mes_uc_connection_ready(uint32 inst_id);
status_t mes_init_uc(void);
void mes_destroy_uc(void);

#ifdef __cplusplus
}
#endif

#endif

