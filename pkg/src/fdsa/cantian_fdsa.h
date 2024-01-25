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
 * cantian_fdsa.h
 *
 *
 * IDENTIFICATION
 * src/fdsa/cantian_fdsa.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef CANTIAN_FDSA_H
#define CANTIAN_FDSA_H

#ifdef __cplusplus
extern "C" {
#endif

#define CANTIAN_IO_TIME_OUT_ONCE (600000000) // 600s 单次IO自愈超时时间
#define CANTIAN_IO_TIME_OUT (180000000) // 180s 认定此IO已超时
#define CANTIAN_FDSA_CHECK_CYCLE_TIME (5)
#define CANTIAN_IO_TIME_OUT_LIMIT_MAX_NUM (16)
#define CANTIAN_FDSA_HEAL_TASK "cantian_Fdsa_heal_task"

typedef enum en_fdsa_type {
    FDSA_KNL_COMMIT,
    FDSA_END
} CANTIAN_FDSA_TYPE;

typedef struct st_io_id {
    uint16 fdsa_type;
    uint32 io_no;
} io_id_t;

typedef struct st_drc_local_io {
    uint32           next;  // should be the first field
    io_id_t          io_id;
    uint64           start_time;
    uint32           idx;
} drc_local_io;

status_t InitCantianFdsa(void);
status_t DeInitCantianFdsa(void);
status_t AddIo2FdsaHashTable(io_id_t io_id);
status_t RemovetIoFromFdsaHashtable(io_id_t io_id);
uint32 GetFdsaIoNo(void);

#ifdef __cplusplus
}
#endif
#endif