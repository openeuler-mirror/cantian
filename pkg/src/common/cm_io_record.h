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
 * cm_io_record.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_io_record.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef CM_IO_RECORD_H
#define CM_IO_RECORD_H

#include "cm_defs.h"
#include "cm_types.h"
#include "cm_date.h"
#include "cm_atomic.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef enum {
    IO_RECORD_EVENT_DRC_REMASTER_RECOVER_CKPT = 0,
    IO_RECORD_EVENT_DRC_REMASTER_RECOVER_REBUILD,

    IO_RECORD_EVENT_CMS_UDS_GET_STAT_LIST1,
    IO_RECORD_EVENT_CMS_UDS_SET_DATA_NEW,
    IO_RECORD_EVENT_CMS_UDS_GET_DATA_NEW,
    IO_RECORD_EVENT_CMS_UDS_CLI_HB,
    IO_RECORD_EVENT_CMS_UDS_IOF_KICK_RES,
    IO_RECORD_EVENT_CMS_UDS_UNREGISTER,
    IO_RECORD_EVENT_CMS_UDS_SET_WORK_STAT,

    // 记录创表（函数：knl_create_table）的时间
    IO_RECORD_EVENT_KNL_CREATE_TABLE,
    // 记录修改表定义（函数：knl_alter_table）的时间
    IO_RECORD_EVENT_KNL_ALTER_TABLE,
    // 记录删表（函数：knl_drop_table）的时间
    IO_RECORD_EVENT_KNL_DROP_TABLE,
    IO_RECORD_EVENT_KNL_TRUNCATE_TABLE,
    IO_RECORD_EVENT_KNL_CREATE_SPACE,
    IO_RECORD_EVENT_KNL_ALTER_SPACE,
    IO_RECORD_EVENT_KNL_DROP_SPACE,
    // 记录创建用户（函数：knl_create_user_internal）的时间
    IO_RECORD_EVENT_KNL_CREATE_USER,
    // 记录删除用户（函数：knl_drop_user_internal）的时间
    IO_RECORD_EVENT_KNL_DROP_USER,
    // 记录insert操作（函数：knl_insert）的时间
    IO_RECORD_EVENT_KNL_INSERT,
    // 记录delete操作（函数：knl_internal_delete）的时间
    IO_RECORD_EVENT_KNL_INTERNAL_DELETE,
    // 记录update插入操作（函数：knl_internal_update）的时间
    IO_RECORD_EVENT_KNL_INTERNAL_UPDATE,
    // 记录查索引（函数：pcrb_fetch）的时间
    IO_RECORD_EVENT_PCRB_FETCH,
    // 记录查heap（函数：pcrh_fetch_inter）的时间
    IO_RECORD_EVENT_PCRH_FETCH,
    // 记录得到特定一批row id（函数：pcrh_fetch_by_rid）的时间
    IO_RECORD_EVENT_KNL_FETCH_BY_ROWID,

    // 记录插入heap（函数：pcrh_insert）的时间
    IO_RECORD_EVENT_KNL_PCRH_INSERT,
    // 记录插入索引（函数：pcrb_insert）的时间
    IO_RECORD_EVENT_KNL_PCRB_INSERT,
    // 记录修改heap（函数：pcrh_update）的时间
    IO_RECORD_EVENT_KNL_PCRH_UPDATE,
    // 记录删除heap（函数：pcrh_delete）的时间
    IO_RECORD_EVENT_KNL_PCRH_DELETE,
    // 记录删除索引（函数：pcrb_delete）的时间
    IO_RECORD_EVENT_KNL_PCRB_DELETE,

    IO_RECORD_EVENT_RECOVERY_READ_ONLINE_LOG,
    IO_RECORD_EVENT_NS_BATCH_READ_ULOG,

    IO_RECORD_EVENT_NS_CREATE_PG_POOL,
    IO_RECORD_EVENT_NS_OPEN_PG_POOL,
    IO_RECORD_EVENT_NS_CLOSE_PG_POOL,
    IO_RECORD_EVENT_NS_EXTENT_PG_POOL,
    IO_RECORD_EVENT_NS_WRITE_PG_POOL,
    IO_RECORD_EVENT_NS_READ_PG_POOL,
    IO_RECORD_EVENT_NS_CREATE_ULOG,
    IO_RECORD_EVENT_NS_OPEN_ULOG,
    IO_RECORD_EVENT_NS_READ_ULOG,
    IO_RECORD_EVENT_NS_WRITE_ULOG,
    IO_RECORD_EVENT_NS_TRUNCATE_ULOG,
    IO_RECORD_EVENT_NS_CLOSE_ULOG,
    IO_RECORD_EVENT_NS_PUT_PAGE,
    IO_RECORD_EVENT_NS_SYNC_PAGE,

    IO_RECORD_EVENT_BAK_READ_DATA,
    IO_RECORD_EVENT_BAK_CHECKSUM,
    IO_RECORD_EVENT_BAK_FILTER,
    IO_RECORD_EVENT_BAK_WRITE_LOCAL,
    IO_RECORD_EVENT_BAK_READ_LOG,
    IO_RECORD_EVENT_BAK_FSYNC,

    IO_RECORD_EVENT_ARCH_GET_CAP,
    IO_RECORD_EVENT_ARCH_READ_LOG,
    IO_RECORD_EVENT_ARCH_WRITE_LOCAL,

    IO_RECORD_EVENT_COUNT,
} io_record_event_t;

typedef enum {
    IO_STAT_SUCCESS      = 0,
    IO_STAT_FAILED       = 1,
} io_record_stat_t;

#define IO_RECORD_STAT_RET(status) ((status) == CT_SUCCESS ? IO_STAT_SUCCESS : IO_STAT_FAILED)

typedef struct {
    atomic_t start;
    atomic_t back_good;
    atomic_t back_bad;

    atomic_t total_time;
    atomic_t total_good_time;
    atomic_t total_bad_time;
    atomic_t max_time;
    atomic_t min_time;
} io_record_detail_t;

typedef struct {
    io_record_detail_t detail;
} io_record_wait_t;

typedef struct {
    char name[CT_MAX_NAME_LEN];
    char desc[CT_MAX_NAME_LEN];
} io_record_event_desc_t;

extern io_record_wait_t g_io_record_event_wait[IO_RECORD_EVENT_COUNT];
extern io_record_event_desc_t g_io_record_event_desc[IO_RECORD_EVENT_COUNT];
extern volatile bool32 g_cm_io_record_open;

status_t record_io_stat_reset(void);
status_t record_io_stat_init(void);

void record_io_stat_begin(timeval_t *tv_begin, atomic_t *start);
static inline void cantian_record_io_stat_begin(io_record_event_t event, timeval_t *tv_begin)
{
#ifdef DB_DEBUG_VERSION
    atomic_t *start = &(g_io_record_event_wait[event].detail.start);
    record_io_stat_begin(tv_begin, start);
#endif
}

void record_io_stat_end(timeval_t *tv_begin, int stat, io_record_detail_t *detail);

static inline void cantian_record_io_stat_end(io_record_event_t event, timeval_t *tv_begin, io_record_stat_t stat)
{
#ifdef DB_DEBUG_VERSION
    io_record_detail_t *detail = &(g_io_record_event_wait[event].detail);
    record_io_stat_end(tv_begin, stat, detail);
#endif
}

void record_io_stat_print(void);

volatile bool32 get_iorecord_status(void);
void set_iorecord_status(bool32 is_open);
#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // CM_IO_RECORD_H
