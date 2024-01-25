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
 * cms_cmd_upgrade.h
 *
 *
 * IDENTIFICATION
 * src/cms/cms/cms_cmd_upgrade.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef CMS_CMD_UPGRADE_H
#define CMS_CMD_UPGRADE_H

#include "cms_cmd_imp.h"

#ifdef __cplusplus
extern "C" {
#endif

EXTER_ATTACK int32 cms_upgrade(int32 argc, char* argv[]);
EXTER_ATTACK int32 cms_get_version(int32 argc, char* argv[]);
EXTER_ATTACK int32 cms_degrade_force(int32 argc, char* argv[]);

#ifdef DB_DEBUG_VERSION
typedef struct st_cms_version {
    uint16 main_ver;
    uint16 major_ver;
    uint16 revision;
    uint16 inner;
} cms_version_t;

bool32 cms_cur_version_is_higher_or_equal(cms_version_t cur_version, cms_version_t local_version);
#endif

#ifdef __cplusplus
}
#endif

#endif