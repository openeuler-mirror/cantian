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
 * knl_compress.h
 *
 *
 * IDENTIFICATION
 * src/kernel/common/knl_compress.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_COMPRESS_H__
#define __KNL_COMPRESS_H__

#include "cm_utils.h"
#include "knl_common.h"
#include "lz4.h"
#include "lz4frame.h"
#include "zlib.h"
#include "zstd.h"
#include "repl_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_bak_lz4f_buf {
    char *src;
    size_t size;
    size_t pos;
} bak_lz4f_buf_t;

typedef struct st_bak_compress {
    union {
        // for zlib
        z_stream stream;

        // for zstd
        struct {
            union {
                ZSTD_CStream *zstd_cstream;
                ZSTD_DStream *zstd_dstream;
            };
            ZSTD_inBuffer zstd_in_buf;
        };

        // for lz4
        struct {
            union {
                LZ4F_cctx *lz4f_cstream;
                LZ4F_dctx *lz4f_dstream;
            };
            bak_lz4f_buf_t lz4f_in_buf;
        };
    };

    uint32 write_len;
    uint32 compress_level;
    uint32 last_left_size;
    bool32 finished;
    aligned_buf_t compress_buf;
} knl_compress_t;

typedef enum st_group_count {
    GROUP_COUNT_DEFAULT = 0,
    GROUP_COUNT_8,
    GROUP_COUNT_16,
    GROUP_COUNT_32,
    GROUP_COUNT_64,
    GROUP_COUNT_128,
    GROUP_COUNT_256,
    GROUP_COUNT_512,
    GROUP_COUNT_1024,
} group_count_t;

#define ZSTD_DEFAULT_COMPRESS_LEVEL 9

status_t knl_compress_alloc(compress_algo_e compress, knl_compress_t *ctx, bool32 is_compress);
status_t knl_compress_init(compress_algo_e compress, knl_compress_t *ctx, bool32 is_compress);
void knl_compress_set_input(compress_algo_e compress, knl_compress_t *ctx,
    char *read_buf, uint32 buf_len);
status_t knl_compress(compress_algo_e compress, knl_compress_t *ctx, bool32 stream_end,
    char *write_buf, uint32 buf_len);
status_t knl_decompress(compress_algo_e compress, knl_compress_t *ctx, bool32 end_stream,
    char *write_buf, uint32 buf_len);
void knl_compress_end(compress_algo_e compress, knl_compress_t *ctx, bool32 is_compress);
void knl_compress_free(compress_algo_e compress, knl_compress_t *ctx, bool32 is_compress);

#ifdef __cplusplus
}
#endif

#endif
