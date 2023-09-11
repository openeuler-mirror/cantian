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
 * cm_dbs_map.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_dbs_map.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef CM_DBSTOR_MAP_H
#define CM_DBSTOR_MAP_H

#include "cm_types.h"
#include "cm_defs.h"
#include "cm_dbs_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CM_DBS_INVALID_HANDLE (-1)

typedef struct {
    NameSpaceId ns_id;
    object_id_t obj_id;
    union {
        struct {
            uint32 page_size;
        } pagepool;
        struct {
            LsnId curr_lsn;
            LsnId trun_lsn;
        } ulog;
    };
} cm_dbs_map_item_s;

void cm_dbs_map_init(void);
void cm_dbs_map_deinit(void);
status_t cm_dbs_map_set(const char *name, cm_dbs_map_item_s *item, int32 *handle);
status_t cm_dbs_map_get(int32 handle, cm_dbs_map_item_s *item);
void cm_dbs_map_remove(int32 handle);
bool32 cm_dbs_map_exist(const char *name);
void cm_dbs_map_update(int32 handle, cm_dbs_map_item_s *item);
void cm_dbs_map_get_name(int32 handle, char *name, int32 size);

#ifdef __cplusplus
}
#endif
#endif
