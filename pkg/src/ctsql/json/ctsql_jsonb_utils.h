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
 * ctsql_jsonb_utils.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/json/ctsql_jsonb_utils.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SQL_JSONB_UTILS_H__
#define __SQL_JSONB_UTILS_H__

#include "srv_instance.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ==========================================================================================
 * jsonb version defination
 * ==========================================================================================
 */
#define JSONB_VERSION 0x1

/*
 * ==========================================================================================
 * jsonb head defination
 * ==========================================================================================
 */
typedef enum en_jsonb_head_bytes {
    JSONB_HEAD_BYTES_1 = 1,
    JSONB_HEAD_BYTES_2,
    JSONB_HEAD_BYTES_3,
    JSONB_HEAD_BYTES_4,

    JSONB_HEAD_BYTES_MAX, /* no use */
} jsonb_head_bytes_t;

#define JSONB_HEAD_4B_COUNT_MASK 0x7FFFFFFF /* mask for count field */
#define JSONB_HEAD_4B_ISARRAY 0x00000000
#define JSONB_HEAD_4B_ISOBJECT 0x80000000                  /* the highest bit is 1: object, 0: array */
#define JSONB_HEAD_4B_TYPE_MASK (~(JSONB_HEAD_4B_COUNT_MASK)) /* mask for count field */

#define JSONB_HEAD_3B_COUNT_MASK 0x007FFFFF /* mask for count field */
#define JSONB_HEAD_3B_ISARRAY 0x00000000
#define JSONB_HEAD_3B_ISOBJECT 0x00800000                  /* the highest bit is 1: object, 0: array */
#define JSONB_HEAD_3B_TYPE_MASK (~(JSONB_HEAD_3B_COUNT_MASK)) /* mask for count field */

#define JSONB_HEAD_2B_COUNT_MASK 0x00007FFF /* mask for count field */
#define JSONB_HEAD_2B_ISARRAY 0x00000000
#define JSONB_HEAD_2B_ISOBJECT 0x00008000                  /* the highest bit is 1: object, 0: array */
#define JSONB_HEAD_2B_TYPE_MASK (~(JSONB_HEAD_2B_COUNT_MASK)) /* mask for count field */

#define JSONB_HEAD_1B_COUNT_MASK 0x0000007F /* mask for count field */
#define JSONB_HEAD_1B_ISARRAY 0x00000000
#define JSONB_HEAD_1B_ISOBJECT 0x00000080                  /* the highest bit is 1: object, 0: array */
#define JSONB_HEAD_1B_TYPE_MASK (~(JSONB_HEAD_1B_COUNT_MASK)) /* mask for count field */

#define JSONB_HEAD_ISARRAY 0x00
#define JSONB_HEAD_ISOBJECT 0x80 /* the highest bit is 1: object, 0: array */

#define JSONB_HEAD_1B_MAX_NUM JSONB_HEAD_1B_COUNT_MASK
#define JSONB_HEAD_2B_MAX_NUM JSONB_HEAD_2B_COUNT_MASK
#define JSONB_HEAD_3B_MAX_NUM JSONB_HEAD_3B_COUNT_MASK
#define JSONB_HEAD_4B_MAX_NUM JSONB_HEAD_4B_COUNT_MASK

/*
 * ==========================================================================================
 * jsonb type defination
 * ==========================================================================================
 */
/*
 * every 4-bits reprsent a type for its corresponding entey.
 * therefor each uint8 can store two types
 * for an array with n elements, we need ((n/2)+(n%2)) uint8 to store.
 *
 * for an object with n pairs, we also need ((n/2)+(n%2)) uint8 to store vals, no need to store keys types,
 * key is absolutely is JSON_VAL_STRING.
 */
typedef uint8 JBType;

#define JBT_NUM_EACH_UINT8 (2)
#define JBT_MASK_LEN (UINT8_BITS / JBT_NUM_EACH_UINT8)
#define JBT_HIGN_4BIT_MASK (0xF0)
#define JBT_LOW_4BIT_MASK (0x0F)

/* JB types */
#define JBT_NULL (0x00)
#define JBT_BOOL_FALSE (0x01)
#define JBT_BOOL_TRUE (0x02)
#define JBT_STRING (0x03)
#define JBT_NUMBER (0x04)
#define JBT_BOX (0x05) /* represent array or object */

#define JBT_ISNULL(jbt_) ((jbt_) == JBT_NULL)
#define JBT_ISBOOL_TRUE(jbt_) ((jbt_) == JBT_BOOL_TRUE)
#define JBT_ISBOOL_FALSE(jbt_) ((jbt_) == JBT_BOOL_FALSE)
#define JBT_ISBOOL(jbt_) (JBT_ISBOOL_TRUE(jbt_) || JBT_ISBOOL_FALSE(jbt_))
#define JBT_MEANS_NODATA(jbt_) (JBT_ISBOOL(jbt_) || JBT_ISNULL(jbt_))
#define JBT_ISSTRING(jbt_) ((jbt_) == JBT_STRING)
#define JBT_ISNUMERIC(jbt_) ((jbt_) == JBT_NUMBER)
#define JBT_ISBOX(jbt_) ((jbt_) == JBT_BOX)
#define JBT_ISSCALER(jbt_) (!(JBT_ISBOX((jbt_))))

/*
 * ==========================================================================================
 * jsonb entry defination
 * ==========================================================================================
 */
typedef enum en_jsonb_entry_bytes {
    JSONB_ENTRY_BYTES_1 = 1,
    JSONB_ENTRY_BYTES_2,
    JSONB_ENTRY_BYTES_3,
    JSONB_ENTRY_BYTES_4,

    JSONB_ENTRY_BYTES_MAX, /* no use */
} jsonb_entry_bytes_t;

#define JBE_OFFSET_4B_MAX_LEN 0xFFFFFFFF
#define JBE_OFFSET_3B_MAX_LEN 0x00FFFFFF
#define JBE_OFFSET_2B_MAX_LEN 0x0000FFFF
#define JBE_OFFSET_1B_MAX_LEN 0x000000FF

/*
 * ==========================================================================================
 * jsonb struct defination
 * ==========================================================================================
 */
/*
 * jsonb_box_t: has object or array
 *
 * array: every element is in original order.
 *
 * object: each element has two node, we stor the keys first and then store values.
 * keys is in asc order, and then its values, it is for query fast.
 */
typedef struct jsonb_box_t {
#ifndef WIN32
    /* show the total number of elements in array or object pairs in object, and flag */
    /* the header is variable length. */
    uint8 header[0];

    JBType type[0]; /* show type and type of node. */

    /* show offset and type of node. the entry is variable length. */
    uint8 entry[0];
#endif
    /* the real data for each node follows. */
    uint8 data[0];
} jsonb_box_t;

/* the format is for storing in disk */
typedef struct jsonb_value_t {
    uint32 length;          /* Total length of Jsonb data */
    uint8 version;          /* for any possible change in the future */
    uint8 head_entry_bytes; /* HEAD and ENTRY bits, high 4 bits for HEAD bytes,
                               and low 4 bits for ENTRY bytes */
    jsonb_box_t data;       /* jsonb data starts */
} jsonb_value_t;

#define JSONB_HEAD_NUM_BYTES_MASK 0xF0
#define JSONB_ENTRY_NUM_BYTES_MASK 0x0F

/* get the number of HEAD bytes */
#define JsonbHeadBytesNum(numBytes) (((numBytes) & JSONB_HEAD_NUM_BYTES_MASK) >> 4)
#define JsonbEntryBytesNum(numBytes) ((numBytes) & JSONB_ENTRY_NUM_BYTES_MASK) /* get the number of ENTRY bytes */
#define JsonbMakeHeadEntryBytesNum(h, e) ((uint8)(((h) << 4) | (e)))

#define JSONB_BEGIN_LENTH (6) /* sizeof(uint32) + sizeof(uint8) + sizeof(uint8) */
#define JSONB_MIN_LENTH (7)   /* JSONB_BEGIN_LENTH + sizeof(uint8) <empty array or empty object> */

/*
 * ==========================================================================================
 * some jsonb operations and macros defination
 * ==========================================================================================
 */
#define JSONB_OP_BYTES_2 2
#define JSONB_OP_BITS_8 8
#define JSONB_OP_BITS_16 16
#define JSONB_OP_BITS_24 24
#define JSONB_OBJ_ENTRY_COUNT_TIMES 2

static inline uint32 jsonb_box_get_count(uint8 *base_ptr, uint8 headBytesNum)
{
    switch (headBytesNum) {
        case JSONB_HEAD_BYTES_1:
            return (uint32)((*((uint8 *)base_ptr)) & JSONB_HEAD_1B_COUNT_MASK);
        case JSONB_HEAD_BYTES_2:
            return (uint32)((*((uint16 *)base_ptr)) & JSONB_HEAD_2B_COUNT_MASK);
        case JSONB_HEAD_BYTES_3:
            return (uint32)((((*(uint16 *)base_ptr) << JSONB_OP_BITS_8) | (*((uint8 *)(base_ptr + JSONB_OP_BYTES_2)))) &
                JSONB_HEAD_3B_COUNT_MASK);
        case JSONB_HEAD_BYTES_4:
            return (*((uint32 *)base_ptr)) & JSONB_HEAD_4B_COUNT_MASK;
        default:
            CM_ASSERT(CT_FALSE); /* nerver reach here. */
            return 0;
    }
}

static inline uint8 jsonb_box_get_type(uint8 *base_ptr, uint8 headBytesNum)
{
    switch (headBytesNum) {
        case JSONB_HEAD_BYTES_1:
            return (*((uint8 *)base_ptr)) & JSONB_HEAD_1B_TYPE_MASK;
        case JSONB_HEAD_BYTES_2:
            return ((*((uint16 *)base_ptr)) & JSONB_HEAD_2B_TYPE_MASK) >> JSONB_OP_BITS_8;
        case JSONB_HEAD_BYTES_3:
            return ((((*(uint16 *)base_ptr) << JSONB_OP_BITS_8) | (*((uint8 *)(base_ptr + JSONB_OP_BYTES_2)))) &
                JSONB_HEAD_3B_TYPE_MASK) >>
                JSONB_OP_BITS_16;
        case JSONB_HEAD_BYTES_4:
            return ((*((uint32 *)base_ptr)) & JSONB_HEAD_4B_TYPE_MASK) >> JSONB_OP_BITS_24;
        default:
            CM_ASSERT(CT_FALSE); /* nerver reach here. */
            return 0;
    }
}

// head
#define JSONB_GET_HEADER_LEN(headBytesNum) (sizeof(uint8) * (headBytesNum)) // one head len
#define JSONB_GET_HEADER_ELEM_COUNT(base_ptr, headBytesNum) (jsonb_box_get_count((uint8 *)(base_ptr), headBytesNum))
#define JSONB_GET_HEAD_TYPE(base_ptr, headBytesNum) (jsonb_box_get_type((uint8 *)(base_ptr), headBytesNum))
#define JSONB_HEAD_IS_ARRAY(base_ptr, headBytesNum) ((JSONB_GET_HEAD_TYPE(base_ptr, headBytesNum)) == JSONB_HEAD_ISARRAY)
#define JSONB_HEAD_IS_OBJECT(base_ptr, headBytesNum) ((JSONB_GET_HEAD_TYPE(base_ptr, headBytesNum)) == JSONB_HEAD_ISOBJECT)

// type
// get type count, need how many bytes
#define JSONB_GET_TYPE_COUNT(n_elems) (((n_elems) / 2) + ((n_elems) % 2))

// get total type length
#define JSONB_GET_TYPE_LEN(n_elems) (sizeof(JBType) * (JSONB_GET_TYPE_COUNT(n_elems)))
#define JSONB_GET_TYPE_LEN_BY_PTR(base_ptr, headBytesNum) \
    (JSONB_GET_TYPE_LEN(JSONB_GET_HEADER_ELEM_COUNT((uint8 *)(base_ptr), headBytesNum)))

// entry
#define JSONB_GET_ENTRY_LEN(entryBytesNum) (sizeof(uint8) * (entryBytesNum)) // one entry len

#define JSONB_ARRAY_GET_ENTRY_LEN(n_elems, entryBytesNum) (JSONB_GET_ENTRY_LEN(entryBytesNum) * (n_elems))
#define JSONB_ARRAY_GET_HEADERS_LEN(n_elems, headBytesNum, entryBytesNum) \
    (JSONB_GET_HEADER_LEN(headBytesNum) + JSONB_GET_TYPE_LEN(n_elems) +   \
        JSONB_ARRAY_GET_ENTRY_LEN(n_elems, entryBytesNum))

#define JSONB_OBJECT_GET_ENTRY_LEN(n_elems, entryBytesNum) (JSONB_GET_ENTRY_LEN(entryBytesNum) * ((n_elems) * 2))
#define JSONB_OBJECT_GET_HEADERS_LEN(n_elems, headBytesNum, entryBytesNum) \
    (JSONB_GET_HEADER_LEN(headBytesNum) + JSONB_GET_TYPE_LEN(n_elems) +    \
        JSONB_OBJECT_GET_ENTRY_LEN(n_elems, entryBytesNum))

/*
 * ==========================================================================================
 * jsonb query results defination
 * ==========================================================================================
 */
typedef struct st_jsonb_assist_read {
    uint8 version; /* for any possible change in the future */
    union {
        struct {
            uint8 entry_bytes : 4; // shows the bytes number of each entry
            uint8 head_bytes : 4;  // shows the bytes number of each head
        };

        /* HEAD and ENTRY bits, high 4 bits for HEAD bytes, and low 4 bits for ENTRY bytes */
        uint8 head_entry_bytes;
    };
    uint32 mid; /* for binary search in object */

    // these two params is for Securely access to memory
    uint32 max_len;
    uint64 original_ptr_loc;
} jsonb_assist_read_t;

#define JSONB_ACCESS_MEM_SECURELY(jar, cur_loc) (((cur_loc) - ((jar)->original_ptr_loc)) <= ((jar)->max_len))

/* for query jsonb data, can be scaler or non-scaler */
typedef struct jsonb_result_elem_t {
    bool32 is_scaler; /* if this jbvalue is scaler?, if is_scaler is true,
                         we neeed use JSONB_GET_HEAD_TYPE() to know it is object or array. */
    uint8 type;       /* jsonb data type, please reference JBType */
    uint32 length;    /* Total length of Jsonb data */
    union {
        uint8 *data;       // for scaler
        jsonb_box_t *root; // for array and object node.
    };
} jsonb_result_elem_t; /* single result */

/* after retrieving according to the path, we get this list. */
typedef struct jsonb_results_t {
    galist_t *results; /* every elem is jsonb_result_elem_t */
} jsonb_results_t;     /* list of results */

#define JSONB_RESULT_ELEM_COUNT(jb_res_array) ((jb_res_array)->results->count)
#define JSONB_RESULT_GET_ITEM(jb_res_array, i) ((jsonb_result_elem_t *)cm_galist_get((jb_res_array)->results, (i)))

#define JSONB_OBJECT_MIN_BINARY_SEARCH (8)

/*
 * ==========================================================================================
 * jsonb interface func
 * ==========================================================================================
 */
status_t get_jsonb_from_jsonvalue(json_assist_t *json_ass, json_value_t *jv, variant_t *result, bool32 write_vm);
status_t jsonb_retrieve_core(json_assist_t *json_ass, expr_node_t *func, variant_t *result);
status_t jsonb_mergepatch_core(json_assist_t *json_ass, expr_node_t *func, variant_t *result);
status_t jsonb_set(json_assist_t *json_ass, expr_node_t *func, variant_t *result);
status_t jsonb_array_length_core(json_assist_t *json_ass, expr_node_t *func, variant_t *result);
status_t sql_exec_flatten_to_binary(json_assist_t *json_ass, variant_t *var);
status_t jsonb_format_valiate_core(json_assist_t *json_ass, variant_t *value);

#ifdef __cplusplus
}
#endif

#endif
