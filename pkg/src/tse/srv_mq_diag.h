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
 * srv_mq_diag.h
 *
 *
 * IDENTIFICATION
 * src/tse/srv_mq_diag.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __SRV_MQ_DIAG_H__
#define __SRV_MQ_DIAG_H__

#include "cm_list.h"
#include "cm_spinlock.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cpluscplus */


int get_seg_used_shm_size(int seg_id, int proc_id, char *info);
int get_mysql_used_shm_size(int proc_id, char *info);
int get_mysql_free_shm_size(int proc_id, char *info);
int get_seg_free_shm_size(int seg_id, char *info);
int get_seg_remaining_message_to_be_processed(int seg_id, char *info);

#ifdef __cplusplus
}
#endif /* __cpluscplus */
#endif