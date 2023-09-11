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
 * cm_entropy.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_entropy.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_ENTROPY_H__
#define __CM_ENTROPY_H__

#include "cm_defs.h"
#include "openssl/rand_drbg.h"
#include "openssl/evp.h"

#ifdef __cplusplus
extern "C" {
#endif

size_t cm_get_nonce(RAND_DRBG *dctx, unsigned char **pout, int entropy, size_t minLen, size_t maxLen);
size_t cm_get_entropy(RAND_DRBG *dctx, unsigned char **pout, int entropy, size_t minLen, size_t maxLen,
    int predictionResistance);
#ifdef __cplusplus
}
#endif

#endif