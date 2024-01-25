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
 * cm_malloc.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_malloc.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_MALLOC_H__
#define __CM_MALLOC_H__

#include <stdlib.h>
#include <stdio.h>
#include "cm_types.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define cm_malloc(size)     (cm_malloc_ex(size, __LINE__, __FILE__))

static inline void *cm_malloc_ex(uint32 size, uint32 line, char *file)
{
    uint8 *p = NULL;
    // To do some je_malloc
    p = (uint8 *)malloc(size);
    if (NULL == p) {
        return NULL;
    }
    return p;
}

#define cm_free free

static inline void *cm_malloc_align(uint32 alignment, uint32 size)
{
#ifndef WIN32
    int ret;
    void *memptr;
    ret = posix_memalign(&memptr, alignment, size);
    if (ret == 0) {
        return memptr;
    } else {
        return NULL;
    }
#else
    return cm_malloc(size);
#endif
}

#ifdef __cplusplus
}
#endif
#endif
