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
 * cm_checksum.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_checksum.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_CHECKSUM_H__
#define __CM_CHECKSUM_H__

#include "cm_defs.h"

#if defined(__arm__) || defined(__aarch64__)
#ifdef __has_include
#if __has_include(<arm_acle.h>)
#include <arm_acle.h>
#define HAVE_ARM_ACLE
#endif
#endif
#elif defined(WIN32)
#include <nmmintrin.h>
#define DB_HAVE_SSE4_2
#include <intrin.h>
#define DB_HAVE__CPUID
#else
#include <nmmintrin.h>
#define DB_HAVE_SSE4_2
#include <cpuid.h>
#define DB_HAVE__GET_CPUID
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define REDUCE_CKS2UINT16(cks) (((cks) >> 16) ^ ((cks)&0xFFFF))

static inline uint32 swap32(uint32 val)
{
    return ((val << 24) & 0xff000000) |
           ((val << 8) & 0x00ff0000) |
           ((val >> 8) & 0x0000ff00) |
           ((val >> 24) & 0x000000ff);
}

static inline bool32 cm_crc32c_sse42_available(void)
{
    uint32 arr[4] = { 0, 0, 0, 0 };

#if defined(DB_HAVE__GET_CPUID)
    __get_cpuid(1, &arr[0], &arr[1], &arr[2], &arr[3]);
#elif defined(DB_HAVE__CPUID)
    __cpuid(arr, 1);
#else
    return GS_FALSE;
#endif

    return (arr[2] & (1 << 20)) != 0;
}

static inline void cm_init_crc32c(uint32 *crc)
{
    (*crc) = 0xFFFFFFFF;
}

static inline void cm_final_crc32c(uint32  *crc)
{
    (*crc) ^= 0xFFFFFFFF;
}

static inline void cm_final_crc32c_bendian(uint32 *crc)
{
    (*crc) = swap32(*crc) ^ 0xFFFFFFFF;
}

uint32 cm_crc32c_sse42(const void *data, uint32 len, uint32 crc_input);
uint32 cm_crc32c_sb8(const void *data, uint32 len, uint32 crc_input);

#if defined(HAVE_ARM_ACLE)
uint32 cm_crc32c_aarch(const void *data, uint32 len, uint32 crc);
bool32 cm_crc32c_aarch_available(void);

static inline uint32 cm_get_crc32c_aarch(const void *data, uint32 len)
{
    uint32 crc;

    cm_init_crc32c(&crc);
    crc = cm_crc32c_aarch(data, len, crc);
    cm_final_crc32c(&crc);
    return crc;
}
#endif

static inline uint32 cm_get_crc32_sse42(const void *data, uint32 len)
{
    uint32 crc;

    cm_init_crc32c(&crc);
    crc = cm_crc32c_sse42(data, len, crc);
    cm_final_crc32c(&crc);
    return crc;
}

static inline uint32 cm_get_crc32_sb8(const void *data, uint32 len)
{
    uint32 crc;

    cm_init_crc32c(&crc);
    crc = cm_crc32c_sb8(data, len, crc);
    if (!IS_BIG_ENDIAN) {
        cm_final_crc32c(&crc);
    } else {
        cm_final_crc32c_bendian(&crc);
    }

    return crc;
}

static inline uint32 cm_get_checksum(const void *data, uint32 len)
{
#if defined(HAVE_ARM_ACLE)
    if (cm_crc32c_aarch_available()) {
        return cm_get_crc32c_aarch(data, len);
    }
#else
    if (cm_crc32c_sse42_available()) {
        return cm_get_crc32_sse42(data, len);
    }
#endif

    return cm_get_crc32_sb8(data, len);
}

#ifdef __cplusplus
}
#endif

#endif

