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
 * knl_punch_space.h
 *
 *
 * IDENTIFICATION
 * src/kernel/tablespace/knl_punch_space.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_PUNCH_SPACE_H__
#define __KNL_PUNCH_SPACE_H__

#include "knl_space_base.h"

#ifdef __cplusplus
extern "C" {
#endif

#pragma pack(4)

typedef struct st_rd_punch_page {
    page_id_t page_id;
    char reverse[4];
} rd_punch_page_t;

typedef struct st_spc_punch_info {
    int64 do_punch_size;
    int64 real_punch_size;
} spc_punch_info_t;

#pragma pack()

status_t spc_punch_hole(knl_session_t *session, space_t *space, int64 punch_size);
void spc_set_datafile_ctrl_punched(knl_session_t *session, uint16 file_id);

#ifdef __cplusplus
}
#endif

#endif

