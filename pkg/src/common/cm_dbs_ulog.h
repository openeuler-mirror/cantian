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
 * cm_dbs_ulog.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_dbs_ulog.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef CM_DBSTOR_ULOG_H
#define CM_DBSTOR_ULOG_H
#include <sys/types.h>
#include "cm_types.h"
#include "cm_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

int64 cm_dbs_ulog_seek(int32 handle, int64 offset, int32 origin);
status_t cm_dbs_ulog_create(const char *name, int64 size, uint32 flags, int32 *handle);
status_t cm_dbs_ulog_destroy(const char *name);
status_t cm_dbs_ulog_open(const char *name, int32 *handle, uint8 is_retry);
void cm_dbs_ulog_close(int32 handle);
status_t cm_dbs_ulog_read(int32 handle, int64 startLsn, void *buf, int32 size, int32 *r_size);
status_t cm_dbs_ulog_write(int32 handle, int64 lsn, const void *buf, int32 size, uint64 *free_size);
status_t cm_dbs_get_used_cap(int32 handle, uint64_t startLsn, uint32_t *sizeKb, uint8 is_retry);
status_t cm_dbs_ulog_capacity(int64 *capacity);
int32 cm_dbs_ulog_align_size(int32 space_size);
status_t cm_dbs_ulog_batch_read(int32 handle, uint64 startLsn, uint64 endLsn, void *buf,
                                int32 size, int32 *r_size, uint64 *outLsn);
bool32 cm_dbs_ulog_is_lsn_valid(int32 handle, uint64 lsn);
bool32 cm_dbs_log_recycled(void);

#ifdef __cplusplus
}
#endif
#endif
