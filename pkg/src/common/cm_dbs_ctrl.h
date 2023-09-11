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
 * cm_dbs_ctrl.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_dbs_ctrl.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef CM_DBSTOR_CTRL_H
#define CM_DBSTOR_CTRL_H
#include <sys/types.h>
#include "cm_defs.h"
#include "cm_device.h"
#include "cm_dbs_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t cm_dbs_get_ns_id(device_type_t type, NameSpaceId *nsId);

#ifdef __cplusplus
}
#endif
#endif
