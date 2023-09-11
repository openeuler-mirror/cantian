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
 * cm_license.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_license.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef LICENSE_CM_LICENSE_H
#define LICENSE_CM_LICENSE_H

#include "cm_defs.h"
#include "cm_file.h"
#include "cm_date.h"
#include "cm_thread.h"
#include "cm_utils.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    LICENSE_VALIDITY_TIME = 0,
    LICENSE_PARTITION = 1,
    LICENSE_TYPE_END
} license_item;

#ifndef WIN32
typedef enum {
    LICENSE_STATUS_INVALID = 0,
    LICENSE_STATUS_VALID = 1,
    LICENSE_STATUS_PERMANENT = 2,
    LICENSE_STATUS_END
} license_status;

typedef struct {
    time_t validity_time;
    license_status status;
} lic_item_t;

typedef struct {
    time_t mod_time;
    lic_item_t item[LICENSE_TYPE_END];
    char lic_conf_path[GS_FILE_NAME_BUFFER_SIZE];
} lic_cfg_t;

#define LICENSE_VAILD_TIME_STR (char *)"GASS10010A00"
#define LICENSE_PARTITION_100  (char *)"GASS10010B06"
#define LICENSE_PARTITION_T110 (char *)"GASS100SA005"
#define LICENSE_PARTITION_T130 (char *)"GASS100DA005"
#define GS_LIC_FILE_PATH_ENV   (char *)"GAUSSHOME"
#define GS_LIC_DEADLINE_PERM   (char *)"PERMANENT"
#define GS_LIC_CONF_LINE_BUF   (uint32)100
#define GS_LIC_SLEEP_TIME      (uint32)5000

#define GS_CONTINUE_IF_ERROR(ret) \
    if ((ret) != GS_SUCCESS) { \
        continue;                 \
    }

#define SSC_CONTINUE_IF_ERR(ret, err_info)        \
    if ((ret) == -1) {                            \
        GS_LOG_RUN_ERR("[LICENSE]%s", err_info);  \
        continue;                                    \
    }

status_t cm_lic_init(void);
status_t cm_lic_check(license_item item_num);
#else
static status_t cm_lic_init()
{
    return GS_SUCCESS;
}
static status_t cm_lic_check(license_item item_num)
{
    return GS_SUCCESS;
}
#endif

#ifdef __cplusplus
}
#endif
#endif
