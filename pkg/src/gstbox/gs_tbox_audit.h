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
 * gs_tbox_audit.h
 *
 *
 * IDENTIFICATION
 * src/gstbox/gs_tbox_audit.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __GS_TBOX_AUDIT_H__
#define __GS_TBOX_AUDIT_H__

#include "cm_defs.h"
#include "cm_text.h"
#include "cm_log.h"
#include "cm_file.h"
#include "cs_pipe.h"
#include "gs_page.h"

#define TBOX_LOG_FILE_PERMISSIONS 600
#define TBOX_LOG_PATH_PERMISSIONS 700
#define TBOX_LOG_FILE_PERMISSIONS_640 640
#define TBOX_LOG_PATH_PERMISSIONS_750 750
#define TBOX_LOG_MAX_SIZE 10240
#define TBOX_LOG_BACKUP_FILE_COUNT 10

#define TBOX_LOG_AUDIT(format, ...) cm_write_audit_log(format, ##__VA_ARGS__)

// for snprintf_s/sprintf_s..., return CT_ERROR if error
#define PRTS_PRINT_RETURN_IFERR(func)                        \
    do {                                               \
        int32 __code__ = (func);                       \
        if (SECUREC_UNLIKELY(__code__ == -1)) {        \
            printf("system error occured, snprintf error, exit\n");   \
            CT_THROW_ERROR(ERR_SYSTEM_CALL, __code__); \
            return CT_ERROR;                           \
        }                                              \
    } while (0)

// for snprintf_s/sprintf_s..., return CT_ERROR if error
#define PRTS_PRINT_RETVOID_IFERR(func)                        \
    do {                                               \
        int32 __code__ = (func);                       \
        if (SECUREC_UNLIKELY(__code__ == -1)) {        \
            printf("system error occured, snprintf error, exit\n");   \
            CT_THROW_ERROR(ERR_SYSTEM_CALL, __code__); \
            return;                                    \
        }                                              \
    } while (0)


// securec memory function check
#define MEMS_PRINT_RETURN_IFERR(func)                        \
    do {                                               \
        int32 __code__ = (func);                       \
        if (SECUREC_UNLIKELY(__code__ != EOK)) {       \
            printf("system error occured, memory function error, exit\n");    \
            CT_THROW_ERROR(ERR_SYSTEM_CALL, __code__); \
            return CT_ERROR;                           \
        }                                              \
    } while (0)

// securec memory function check
#define MEMS_PRINT_RETVOID_IFERR(func)                                    \
    do {                                                                 \
        int32 __code__ = (func);                                         \
        if (SECUREC_UNLIKELY(__code__ != EOK)) {                         \
            printf("system error occured, memory function error, exit\n"); \
            CT_THROW_ERROR(ERR_SYSTEM_CALL, __code__);                   \
            return;                                                      \
        }                                                                \
    } while (0)


status_t tbox_init_audit_log(const char *path);
status_t tbox_verify_log_path(const char *input_path, repair_page_def_t *page_input);
void tbox_write_audit_log(int argc, char *argv[], int32 err_code);


#endif
