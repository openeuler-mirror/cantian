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
 * cm_dbs_pgpool.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_dbs_pgpool.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef CM_DBSTOR_PAGEPOOL_H
#define CM_DBSTOR_PAGEPOOL_H
#include <sys/types.h>
#include "cm_types.h"
#include "cm_defs.h"
#ifdef __cplusplus
extern "C" {
#endif

int64 cm_dbs_pg_seek(int32 handle, int64 offset, int32 origin);
status_t cm_dbs_pg_create(const char *name, int64 size, uint32 flags, int32 *handle);
status_t cm_dbs_pg_destroy(const char *name);
status_t cm_dbs_pg_open(const char *name, int32 *handle);
void cm_dbs_pg_close(int32 handle);
status_t cm_dbs_pg_read(int32 handle, int64 offset, void *buf, int32 size, int32 *read_size);
status_t cm_dbs_pg_write(int32 handle, int64 offset, const void *buf, int32 size);
status_t cm_dbs_pg_asyn_write(int32 handle, int64 offset, const void *buf, int32 size, uint32 partid);
status_t cm_dbs_pg_extend(int32 handle, int64 offset, int64 size);
status_t cm_dbs_pg_truncate(int32 handle, int64 keep_size);
status_t cm_dbs_pg_rename(const char* src_name, const char* dst_name);
bool32 cm_dbs_pg_exist(const char *name);
status_t cm_dbs_sync_page(int32 handle, uint32 partid);
status_t cm_dbs_pg_cal_part_id(uint64 pgid, uint32 pageSize, uint32 *partid);

#ifdef __cplusplus
}
#endif
#endif
