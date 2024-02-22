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
 * cm_dbs_intf.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_dbs_intf.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef CM_DBSTOR_INTF_H
#define CM_DBSTOR_INTF_H
#include <sys/types.h>
#include "cm_types.h"
#include "cm_defs.h"
#include "cm_device.h"
#include "cm_dbs_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CANTIAN_VERSION 1
#define DBS_NS_MAX_NAME_LEN 256

typedef struct {
    bool32 enable;
    uint32 dataFilePgSize;
    uint32 ctrlFilePgSize;
    uint32 partition_num;
    bool32 enable_batch_flush;
    char ns[DBS_NS_MAX_NAME_LEN];
} cm_dbs_cfg_s;

cm_dbs_cfg_s *cm_dbs_get_cfg(void);
status_t cm_dbs_set_cfg(bool32 enable, uint32 dataPgSize, uint32 ctrlPgSize, const char *ns_name, uint32 partition_num,
    bool32 enable_batch_flush);
status_t cm_dbs_create_all_ns(void);
status_t cm_dbs_open_all_ns(void);
bool32 cm_dbs_is_enable_dbs(void);
uint64 cm_dbs_ulog_recycle(int32 handle, uint64 lsn);
status_t cm_dbs_ulog_get_maxLsn(const char *name, uint64 *lsn);
status_t cm_dbs_init(const char *home_path, char *cfg_name, dbs_init_mode init_mode);
status_t cm_dbs_iof_reg_all_ns(uint32 inst_id);
uint32 cm_dbs_get_part_num(void);
bool32 cm_dbs_is_enable_batch_flush(void);
void cm_set_dbs_uuid_lsid(const char* uuid, uint32 lsid);
#ifdef __cplusplus
}
#endif
#endif
