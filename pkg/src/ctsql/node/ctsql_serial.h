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
 * ctsql_serial.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/node/ctsql_serial.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SQL_SERIAL_H__
#define __SQL_SERIAL_H__
#include "cm_base.h"
#include "ctsql_cond.h"
#include "ctsql_expr.h"

/*
serialize expression or condition
for default column value and check constraint
constant's datatype must in (CT_TYPE_STRING, CT_TYPE_INTEGER, CT_TYPE_BIGINT, CT_TYPE_NUMBER, CT_TYPE_REAL)
*/
typedef struct st_serializer {
    char *buf;
    uint32 size;
    uint32 pos;
} serializer_t;

#define SR_NULL 0xFFFFFFFF

typedef struct st_sr_expr_node {
    expr_node_type_t type;
    ct_type_t datatype;
    int8 unary;
    uint8 unused[1];
    uint8 ext_args;
    uint32 args;
    uint32 value;
    union {
        uint32 left;
        uint32 cond_arg; /* if function */
    };
    uint32 right;

    // sr json sql func attr
    bool32 format_json;              // for json expr
    json_func_attr_t json_func_attr; // for json_value/json_query
} sr_expr_node_t;

typedef struct st_sr_expr_tree {
    uint32 root;
    uint32 next;
} sr_expr_tree_t;

typedef struct st_sr_case_expr {
    bool32 is_cond;
    uint32 expr;
    uint32 pairs;
    uint32 default_expr;
} sr_case_expr_t;

typedef struct st_sr_case_pair {
    union {
        uint32 when_cond;
        uint32 when_expr;
    };
    uint32 value;
} sr_case_pair_t;

typedef struct st_sr_list {
    uint32 count;
    uint32 cell[0];
} sr_list_t;

typedef struct st_sr_cmp_node {
    int32 join_type;
    cmp_type_t type;
    uint32 left;
    uint32 right;
    bool32 has_escape;
    char escape;
    uchar reserved[3];
} sr_cmp_node_t;

typedef struct sr_sr_bool_node {
    uint32 expr;
    bool32 is_not;
} sr_bool_node_t;

typedef struct st_sr_cond_node {
    cond_node_type_t type;
    uint32 left;
    uint32 right;
    uint32 prev;
    uint32 next;
    union {
        uint32 cmp;
        uint32 bool_node;
    };
} sr_cond_node_t;

typedef struct st_sr_cond_tree {
    uint32 root;
    uint32 rownum_upper;
    source_location_t loc;
} sr_cond_tree_t;

typedef status_t (*sr_encode_cell_t)(sql_stmt_t *stmt, serializer_t *sr, void *context, uint32 *offset);
typedef status_t (*sr_decode_cell_t)(memory_context_t *ctx, char *sr_data, uint32 offset, galist_t *list);

static inline status_t sr_push(serializer_t *sr, uint32 size, void **ptr)
{
    uint32 cost_size = CM_ALIGN4(size);
    if (sr->pos + cost_size > sr->size) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)cost_size, "serializing");
        return CT_ERROR;
    }

    *ptr = sr->buf + sr->pos;
    if (cost_size != 0) {
        CT_RETURN_IFERR(memset_s(*ptr, cost_size, 0, cost_size));
    }
    sr->pos += cost_size;
    return CT_SUCCESS;
}

#define SR_PUT_FIXED(sr, type, val)                                             \
    do {                                                                        \
        uint32 cost_size = CM_ALIGN4(sizeof(type));                             \
        if ((sr)->pos + cost_size > (sr)->size) {                               \
            CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)cost_size, "serializing"); \
            return CT_ERROR;                                                    \
        }                                                                       \
        *(type *)((sr)->buf + (sr)->pos) = (type)(val);                           \
        (sr)->pos += cost_size;                                                 \
    } while (0)

#define SR_PUT_DATA(sr, data, len)                                                                 \
    do {                                                                                           \
        uint32 cost_size = CM_ALIGN4(len);                                                         \
        if ((sr)->pos + cost_size > (sr)->size) {                                                  \
            CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)cost_size, "serializing");                    \
            return CT_ERROR;                                                                       \
        }                                                                                          \
        if ((len) != 0) {                                                                            \
            MEMS_RETURN_IFERR(memcpy_s((sr)->buf + (sr)->pos, (sr)->size - (sr)->pos, data, len)); \
        }                                                                                          \
        (sr)->pos += cost_size;                                                                    \
    } while (0)

#define SR_PUT_VARLEN(sr, data, len)   \
    do {                               \
        SR_PUT_FIXED(sr, uint32, len); \
        SR_PUT_DATA(sr, data, len);    \
    } while (0)

#define SR_CHECK_OBJECT(sr, obj, offset) \
    do {                                 \
        if ((obj) == NULL) {               \
            *(offset) = SR_NULL;           \
            return CT_SUCCESS;           \
        }                                \
        *(offset) = (sr)->pos;             \
    } while (0)

#define SR_CHECK_OBJECT_LIST(sr, num, offset) \
    do {                                      \
        if ((num) == 0) {                       \
            *(offset) = SR_NULL;                \
            return CT_SUCCESS;                \
        }                                     \
        *(offset) = (sr)->pos;                  \
    } while (0)

#define SR_MOVE_STEP(move_sr, sr)                 \
    do {                                          \
        (move_sr)->buf = (sr)->buf + (sr)->pos;   \
        (move_sr)->size = (sr)->size - (sr)->pos; \
        (move_sr)->pos = 0;                       \
    } while (0)

static inline void sr_init(serializer_t *sr, char *buf, uint32 size)
{
    sr->buf = buf;
    sr->size = size;
    sr->pos = 0;
}

status_t sr_encode_expr(sql_stmt_t *stmt, serializer_t *sr, expr_tree_t *expr, uint32 *offset);
status_t sr_encode_expr_list(sql_stmt_t *stmt, serializer_t *sr, uint32 *offset, int num, ...);
status_t sr_decode_expr(memory_context_t *mem_ctx, void *data, void **expr);
status_t sr_decode_expr_list(memory_context_t *mem_ctx, void *data, uint32 offset, uint32 num, ...);
status_t sr_encode_cond(sql_stmt_t *stmt, serializer_t *sr, cond_tree_t *cond, uint32 *offset);
status_t sr_decode_cond(memory_context_t *context, void *data, void **expr);

status_t sr_encode_variant(sql_stmt_t *stmt, serializer_t *sr, variant_t *var, uint32 *offset);

status_t sr_decode_variant(char *sr_data, uint32 temp_offset, variant_t *var);

status_t sr_encode_expr_node(sql_stmt_t *stmt, serializer_t *sr, expr_node_t *node, uint32 *offset);
status_t sr_decode_expr_node(memory_context_t *mem_ctx, char *sr_data, uint32 offset, expr_node_t **node);

#ifdef Z_SHARDING
status_t sr_decode_expr_node_shard(void *ctx, char *sr_data, uint32 offset, expr_node_t **node);
status_t sr_decode_expr_shard(void *ctx, void *data, void **expr);
#endif

#endif
