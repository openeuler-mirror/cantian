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
 * dc_dump.h
 *
 *
 * IDENTIFICATION
 * src/kernel/catalog/dc_dump.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __KNL_DC_DUMP_H__
#define __KNL_DC_DUMP_H__

#include "cm_file.h"
#include "knl_interface.h"
#include "knl_context.h"


#ifdef __cplusplus
extern "C" {
#endif

status_t dc_dump_prepare(cm_dump_t *dump, dc_dump_info_t *info, char *file_name, uint32 name_size);
status_t dc_dump_table(knl_session_t *session, cm_dump_t *dump, dc_dump_info_t info);
status_t dc_dump_user(knl_session_t *session, cm_dump_t *dump, dc_dump_info_t info);


#ifdef __cplusplus
}
#endif

#endif