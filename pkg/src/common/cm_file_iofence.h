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
 * cm_file_iofence.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_file_iofence.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __CM_FILE_IO_FENCE_H__
#define __CM_FILE_IO_FENCE_H__

#include "cm_defs.h"
#include "cm_thread.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t cm_set_file_iof_cfg(uint32 cluster_id, uint32 termid, const char* file_path);
status_t cm_file_iof_register(uint32 inst_id, thread_t *file_iof_thd);
status_t cm_file_iof_kick_by_inst_id(uint32 inst_id);

#ifdef __cplusplus
}
#endif

#endif