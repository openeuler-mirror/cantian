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
 * cm_scsi.c
 *
 *
 * IDENTIFICATION
 * src/common/cm_scsi.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_scsi.h"
#include "cm_log.h"
#include "cm_error.h"
#include "cm_binary.h"
#ifdef WIN32
#else
#include <sys/ioctl.h>
#include <arpa/inet.h>
#endif

#ifdef WIN32

#else

// scsi3 register/reserve/release/clear/preempt
int32 cm_scsi3_register(int32 fd, int64 sark)
{
    return GS_SUCCESS;
}

int32 cm_scsi3_unregister(int32 fd, int64 rk)
{
    return GS_SUCCESS;
}

status_t cm_scsi3_reserve(int32 fd, int64 rk)
{
    return GS_SUCCESS;
}

status_t cm_scsi3_release(int32 fd, int64 rk)
{
    return GS_SUCCESS;
}

status_t cm_scsi3_clear(int32 fd, int64 rk)
{
    return GS_SUCCESS;
}

status_t cm_scsi3_preempt(int32 fd, int64 rk, int64 sark)
{
    return GS_SUCCESS;
}

// scsi3 vaai compare and write, just support 1 block now
int32 cm_scsi3_caw(int32 fd, int64 block_addr, char *buff, int32 buff_len)
{
    return GS_SUCCESS;
}
status_t cm_scsi3_inql(int32 fd, inquiry_data_t *inquiry_data)
{
    return GS_SUCCESS;
}

status_t cm_scsi3_rkeys(int32 fd, int64 *reg_keys, int32 *key_count, uint32 *generation)
{
    return GS_SUCCESS;
}

status_t cm_scsi3_rres(int32 fd, int64 *rk, uint32 *generation)
{
    return GS_SUCCESS;
}
#endif
