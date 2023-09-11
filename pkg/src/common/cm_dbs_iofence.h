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
 * cm_dbs_iofence.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_dbs_iofence.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __CM_DBS_IO_FENCE_H__
#define __CM_DBS_IO_FENCE_H__

#include "cm_defs.h"
#include "cm_dbs_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_iof_info {
    uint32 nodeid;
    NameSpaceId nsid;   // dbstore name space id
    uint32 termid;      // ctd process id
    uint64 sn;          // serial num for dbstor iof request
}iof_info_t;

int32 cm_dbs_iof_register(iof_info_t* iof_info);
int32 cm_dbs_iof_kick(iof_info_t* iof_info);
int32 cm_dbs_iof_kick_by_ns(iof_info_t* iof_info);

#ifdef __cplusplus
}
#endif

#endif
