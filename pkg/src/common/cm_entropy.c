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
 * cm_entropy.c
 *
 *
 * IDENTIFICATION
 * src/common/cm_entropy.c
 *
 * -------------------------------------------------------------------------
 */

#include "cm_entropy.h"

#define ENTROPY_BUFF_LEN        220
#define CACHELINE_SIZE          32
#define L1CACHE_SIZE            SIZE_K(1)

typedef struct st_entropy {
    uint64_t data;
    uint32_t prev_time;
    uint32_t last_delta;
    int32_t last_delta2;
    uint32_t n;
    double sum;
} entropy_t;


typedef struct st_entropy_ctx {
    unsigned char buff[ENTROPY_BUFF_LEN];
    int64 entropy_cnt;
    int64 nonce_cnt;
} entropy_ctx_t;


#ifdef WIN32
__declspec(thread) entropy_ctx_t g_entropy_ctx = {0};
#else
__thread entropy_ctx_t g_entropy_ctx = {0};
#endif

static uint32_t entropy_gettick(void)
{
#ifdef WIN32
    LARGE_INTEGER a;
    QueryPerformanceCounter(&a);
    return a.LowPart;
#else
    struct timespec time;
    clock_gettime(CLOCK_REALTIME, &time);
    return time.tv_nsec;
#endif
}

static void entropy_time_consumer(void)
{
#ifndef WIN32
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#endif
    volatile uint8_t data[L1CACHE_SIZE + CACHELINE_SIZE];
    volatile uint8_t data2[L1CACHE_SIZE + CACHELINE_SIZE];

    int i;
    uint8_t xor = 0;
    static uint32 j = 0;

    j++;

    for (i = 0; i < sizeof(data); i += CACHELINE_SIZE) {
        if (j & 1) {
            xor ^= data[i];
        } else {
            xor ^= data2[i];
        }
    }
#ifndef WIN32
#pragma GCC diagnostic pop
#endif
}

static void cm_entropy_init(entropy_t *e)
{
    e->data = 0;
    e->last_delta = 0;
    e->last_delta2 = 0;
    e->prev_time = 0;
    e->sum = 0;
    e->n = 0;
}

static uint32_t entropy_jitter_measure(entropy_t *e)
{
    uint32_t tick;
    uint32_t delta;
    int32_t delta2;
    uint32_t bit;
    int retry = 1;

    while (retry) {
        /* spend some time */
        entropy_time_consumer();

        /* get tick count */
        tick = entropy_gettick();
        /* calculate the time between two measures */
        delta = tick - e->prev_time;
        if (tick < e->prev_time) {
            delta += 0xffffffff;
        }

        /* calculate the time difference between two measures */
        delta2 = delta - e->last_delta;

        if (delta2 != 0) {
            /* if delta2 is 0, try again */
            retry = 0;
        } else {
            /* in case of dead loop */
            retry = (retry + 1) % 100;
        }

        /* save data */
        e->prev_time = tick;
        e->last_delta2 = delta2;
        e->last_delta = delta;
    }
    bit = (delta2 < 0);
    return bit;
}

static uint64_t cm_entropy_bitmixer(uint64_t data)
{
    uint64 sha256[4];
    int    hmacLength = 32;

    if (!EVP_Digest((unsigned char *)&data, sizeof(data), (unsigned char *)sha256, (unsigned int *)&hmacLength,
                    EVP_sha256(), NULL)) {
        return 0;
    }

    return sha256[0] ^ sha256[1] ^ sha256[2] ^ sha256[3];
}

static uint64_t rol64(uint64_t word, uint32 shift)
{
    return (word << shift) | (word >> (64 - shift));
}

static void cm_entropy_harvest(entropy_t *e)
{
    uint32_t bits = 0;
    uint32_t bit;
    const uint32_t entropybits = sizeof(e->data) * 8;
    uint64_t data;

    data = e->data;
    bit = entropy_jitter_measure(e);
    while (bits < entropybits) {
        bit = entropy_jitter_measure(e);
        data ^= bit;
        data = rol64(data, 1);
        bits++;
    }
    data = cm_entropy_bitmixer(data);
    e->data = data;
}

static void cm_entropy_read(uint8 *data, int length)
{
    entropy_t e;
    const int enTropySize = sizeof(e.data);
    uint8 *p = (uint8 *)&e.data;
    uint8 byte;
    int i = enTropySize;

    cm_entropy_init(&e);
    cm_entropy_harvest(&e);

    /* init byte to be the last byte of previous harvest */
    byte = p[enTropySize - 1];
    int len = length;
    while (len > 0) {
        if (i >= enTropySize) {
            cm_entropy_harvest(&e);
            i = 0;
        }

        /* repeat test */
        if (byte != p[i]) {
            data[0] = p[i];
            data++;
            len--;
        }

        byte = p[i];
        i++;
    }
    return;
}

size_t cm_get_entropy(RAND_DRBG *dctx, unsigned char **pout, int entropy, size_t minLen, size_t maxLen,
    int predictionResistance)
{
    size_t entLen = 0;
    errno_t rc;

    /*
     * The callbacks get_entropy and get_nonce request "entropy" bits of entropy
     * in a buffer of between min_len and max_len bytes. The function should set
     * *pout to the buffer containing the entropy and return the length in bytes of the buffer.
     * If the source of entropy or nonce is unable to satisfy the request it MUST
     * return zero. This will place the DRBG in an error condition due to the source failure.
     */
    rc = memset_s(g_entropy_ctx.buff, ENTROPY_BUFF_LEN, 0, ENTROPY_BUFF_LEN);
    if (rc != EOK) {
        *pout = NULL;
        return entLen;
    }

    cm_entropy_read((uint8*)g_entropy_ctx.buff, ENTROPY_BUFF_LEN);
    g_entropy_ctx.entropy_cnt++;
    *pout = (uint8*)g_entropy_ctx.buff;
    entLen = ENTROPY_BUFF_LEN;

    /* Return entropy length */
    return entLen;
}

size_t cm_get_nonce(RAND_DRBG *dctx, unsigned char **pout, int entropy, size_t minLen, size_t maxLen)
{
    size_t nonceLen = 0;
    errno_t rc;

    rc = memset_s(g_entropy_ctx.buff, ENTROPY_BUFF_LEN, 0, ENTROPY_BUFF_LEN);
    if (rc != EOK) {
        *pout = NULL;
        return nonceLen;
    }

    cm_entropy_read((uint8*)g_entropy_ctx.buff, ENTROPY_BUFF_LEN);
    g_entropy_ctx.nonce_cnt++;
    *pout = (uint8*)g_entropy_ctx.buff;
    nonceLen = ENTROPY_BUFF_LEN;

    /* Return nonce length */
    return nonceLen;
}

