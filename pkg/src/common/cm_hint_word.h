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
 * cm_hint_word.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_hint_word.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_HINT_KEY_WORD_H__
#define __CM_HINT_KEY_WORD_H__

#ifdef __cplusplus
extern "C" {
#endif

typedef enum en_index_hint_key_wid {
    HINT_KEY_WORD_FULL = 0x00000001,
    HINT_KEY_WORD_INDEX = 0x00000002,
    HINT_KEY_WORD_NO_INDEX = 0x00000004,
    HINT_KEY_WORD_INDEX_ASC = 0x00000008,
    HINT_KEY_WORD_INDEX_DESC = 0x00000010,
    HINT_KEY_WORD_INDEX_FFS = 0x00000020,
    HINT_KEY_WORD_NO_INDEX_FFS = 0x00000040,
    HINT_KEY_WORD_INDEX_SS = 0x00000080,
    HINT_KEY_WORD_NO_INDEX_SS = 0x00000100,
    HINT_KEY_WORD_USE_CONCAT = 0x00000200,
    HINT_KEY_WORD_ROWID = 0x00000400,
} index_hint_key_wid_t;

typedef enum en_join_hint_key_wid {
    // join order
    HINT_KEY_WORD_LEADING = 0x00000001,
    HINT_KEY_WORD_ORDERED = 0x00000002,
    // join method
    HINT_KEY_WORD_USE_NL = 0x00000004,
    HINT_KEY_WORD_USE_MERGE = 0x00000008,
    HINT_KEY_WORD_USE_HASH = 0x00000010,
    // nl full optimizer
    HINT_KEY_WORD_NL_FULL_MTRL = 0x00000020,
    HINT_KEY_WORD_NL_FULL_OPT = 0x00000040,
    HINT_KEY_WORD_HASH_TABLE = 0x00000080,
    HINT_KEY_WORD_NO_HASH_TABLE = 0x00000100,
    HINT_KEY_WORD_NL_BATCH = 0x00000200,
} join_hint_key_wid_t;

typedef enum en_optim_hint_key_wid {
    HINT_KEY_WORD_CB_MTRL = 0x00000001,               // connect by
    HINT_KEY_WORD_HASH_AJ = 0x00000002,               // not in/not exists
    HINT_KEY_WORD_HASH_BUCKET_SIZE = 0x00000004,
    HINT_KEY_WORD_HASH_SJ = 0x00000010,
    HINT_KEY_WORD_INLINE = 0x00000020,                // withas hints
    HINT_KEY_WORD_MATERIALIZE = 0x00000040,
    HINT_KEY_WORD_NO_CB_MTRL = 0x00000080,
    HINT_KEY_WORD_NO_PUSH_PRED = 0x00000200,
    HINT_KEY_WORD_NO_OR_EXPAND = 0x00000400,          // or expand hints
    HINT_KEY_WORD_NO_UNNEST = 0x00000800,
    HINT_KEY_WORD_OR_EXPAND = 0x00001000,
    HINT_KEY_WORD_PARALLEL = 0x00002000,
    HINT_KEY_WORD_RULE = 0x00008000,                  // rbo
    HINT_KEY_WORD_SEMI_TO_INNER = 0x00010000,
    HINT_KEY_WORD_THROW_DUPLICATE = 0x00020000,       // insert/replace hints
    HINT_KEY_WORD_UNNEST = 0x00040000,
    HINT_KEY_WORD_OPT_PARAM = 0x00080000,
    HINT_KEY_WORD_OPT_ESTIMATE = 0x00100000,
} optim_hint_key_wid_t;

typedef enum en_shard_hint_key_wid {
    // from subquery pullup
    HINT_KEY_WORD_SQL_WHITELIST = 0x00000001,
    HINT_KEY_WORD_SHD_READ_MASTER = 0x00000002,
} shard_hint_key_wid_t;

typedef enum en_outline_hint_key_wid {
    HINT_KEY_WORD_DB_VERSION = 0x00000001,
    HINT_KEY_WORD_FEATURES_ENABLE = 0x00000002,
    HINT_KEY_WORD_OPTIM_MODE = 0x00000004
} outline_hint_key_wid_t;

    // the value must be the same as the sequence of g_hints.
typedef enum en_hint_id {
    ID_HINT_DB_VERSION = 0,
    ID_HINT_FEATURES_ENABLE,
    ID_HINT_FULL,
    ID_HINT_INDEX,
    ID_HINT_INDEX_ASC,
    ID_HINT_INDEX_DESC,
    ID_HINT_INDEX_FFS,
    ID_HINT_INDEX_SS,
    ID_HINT_LEADING,
    ID_HINT_NL_BATCH,
    ID_HINT_NO_INDEX,
    ID_HINT_NO_INDEX_FFS,
    ID_HINT_NO_INDEX_SS,
    ID_HINT_OPTIM_MODE,
    ID_HINT_OR_EXPAND,
    MAX_HINT_WITH_TABLE_ARGS,
    // the hint with parameters needs to be added to args in hint_info and placed above MAX_HINT_WITH_TABLE_ARGS.
    // otherwise, it must be placed under MAX_HINT_WITH_TABLE_ARGS.
    ID_HINT_CB_MTRL,
    ID_HINT_HASH_AJ,
    ID_HINT_HASH_BUCKET_SIZE,  // stmt->context->hash_bucket_size
    ID_HINT_HASH_SJ,
    ID_HINT_HASH_TABLE,
    ID_HINT_INLINE,
    ID_HINT_MATERIALIZE,
    ID_HINT_NL_FULL_MTRL,
    ID_HINT_NL_FULL_OPT,
    ID_HINT_NO_CB_MTRL,
    ID_HINT_NO_HASH_TABLE,
    ID_HINT_NO_OR_EXPAND,
    ID_HINT_NO_PUSH_PRED,
    ID_HINT_NO_UNNEST,
    ID_HINT_OPT_ESTIMATE,
    ID_HINT_OPT_PARAM,
    ID_HINT_ORDERED,           // use the same arg as leading
    ID_HINT_PARALLEL,          // stmt->context->parallel
    ID_HINT_ROWID,
    ID_HINT_RULE,              // the max number of hint with parameters
    ID_HINT_SEMI_TO_INNER,
#ifdef Z_SHARDING
    ID_HINT_SHD_READ_MASTER,
    ID_HINT_SQL_WHITELIST,
#endif
    ID_HINT_THROW_DUPLICATE,
    ID_HINT_UNNEST,
    ID_HINT_USE_CONCAT,
    ID_HINT_USE_HASH,
    ID_HINT_USE_MERGE,
    ID_HINT_USE_NL,
} hint_id_t;

typedef enum en_hint_type {
    INDEX_HINT = 0,
    JOIN_HINT,
    OPTIM_HINT,
    OUTLINE_HINT,
    SHARD_HINT,
    MAX_HINT_TYPE,
} hint_type_t;

#ifdef __cplusplus
}
#endif

#endif
