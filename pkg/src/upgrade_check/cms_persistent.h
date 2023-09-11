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
 * cms_persistent.h
 *
 *
 * IDENTIFICATION
 * src/upgrade_check/cms_persistent.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CMS_PERSISTENT_H__
#define __CMS_PERSISTENT_H__

#include "cms_gcc.h"
#include "cms_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CMS_GCC_STORAGE_T_SIZE    177152
CM_STATIC_ASSERT(sizeof(cms_gcc_storage_t) == CMS_GCC_STORAGE_T_SIZE);

#ifdef __cplusplus
}
#endif

#endif