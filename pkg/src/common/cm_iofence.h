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
 * cm_iofence.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_iofence.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_IO_FENCE_H__
#define __CM_IO_FENCE_H__

#include "cm_scsi.h"
#include "cm_list.h"

#define CM_IOF_ERR_DUP_OP (-2)

typedef struct st_iof_reg_out {
    int64 rk;      //unique register key for each host
    int64 rk_kick; //The rk of the host to be kicked
    char* dev;     //scsi device path
}iof_reg_out_t;

typedef struct st_iof_reg_in {
    int64 resk;                           //reservation key
    uint32 generation;                    //pr generation
    int64 reg_keys[CM_MAX_RKEY_COUNT];    //all register keys
    int32 key_count;                      //actual read key count
    char* dev;                            //scsi device path
} iof_reg_in_t;

int32 cm_iof_register(iof_reg_out_t* iof_out);
int32 cm_iof_unregister(iof_reg_out_t* iof_out);
status_t cm_iof_kick(iof_reg_out_t* iof_out);
status_t cm_iof_clear(iof_reg_out_t* iof_out);
status_t cm_iof_inql(iof_reg_in_t* iof_in);

#endif

