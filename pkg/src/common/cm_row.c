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
 * cm_row.c
 *
 *
 * IDENTIFICATION
 * src/common/cm_row.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_row.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef WIN32
__declspec(thread) uint8 g_row_offset[2] = {0, 8};   /** 8 = sizeof(rowid_t) */
#else
__thread uint8 g_row_offset[2] = {0, 8};
#endif

#ifdef __cplusplus
}
#endif
