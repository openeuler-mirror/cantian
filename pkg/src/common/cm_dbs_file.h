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
 * cm_dbs_file.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_dbs_file.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef CM_DBSTOR_FILE_H
#define CM_DBSTOR_FILE_H
#include <sys/types.h>
#include "cm_types.h"
#include "cm_defs.h"
#include "cm_dbs_defs.h"
#include "cm_types.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t cm_dbs_open_fs(const char *name, int32 *root_handle);
status_t cm_dbs_create_file(const char *name, int32 *handle);
status_t cm_dbs_create_dir(const char *name, int32 *handle);
status_t cm_dbs_open_file(const char *name, int32 *handle);
status_t cm_dbs_open_dir(const char *name, int32 *handle);
void cm_dbs_close_file(int32 handle);
status_t cm_dbs_remove_file(const char *name);
status_t cm_dbs_remove_dir(const char *name);
status_t cm_dbs_read_file(int32 handle, int64 offset, const void *buf, int32 size, int32 *read_size);
status_t cm_dbs_write_file(int32 handle, int64 offset, const void *buf, int32 size);
status_t cm_dbs_rename_file(const char *src_name, const char *dst_name);
bool32 cm_dbs_exist_file(const char *name, uint32 file_type);
status_t cm_dbs_access_file(const char *name, int32 *handle);
status_t cm_dbs_query_dir(const char *name, void *file_list, uint32 *file_num);
status_t cm_dbs_get_file_size(int32 handle, int64 *file_size);
status_t cm_dbs_ulog_archive(int32 src_file, int32 dst_file, uint64 offset, uint64 start_lsn,
                             uint64 arch_size, uint64 *real_arch_size, uint64 *last_lsn);
status_t cm_check_file_path(const char *file_path);
void cm_remove_extra_delim(char *file_path, const char delim);

// for a share file system whose vstore id is not zero
status_t cm_dbs_query_dir_vstore_id(uint32 vstore_id, const char *name, void *file_list, uint32 *file_num);
status_t cm_dbs_remove_file_vstore_id(uint32 vstore_id, const char *name);

#ifdef __cplusplus
}
#endif
#endif
