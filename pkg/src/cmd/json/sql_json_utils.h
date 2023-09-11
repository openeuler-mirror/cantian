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
 * sql_json_utils.h
 *
 *
 * IDENTIFICATION
 * src/cmd/json/sql_json_utils.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __SQL_JSON_UTILS_H__
#define __SQL_JSON_UTILS_H__

#include "srv_instance.h"

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// JSON MEMORY MANAGEMENT FOR:
//     - JSON SQL FUNCTION ARGUMENTS EVALUTION
//     - JSON PARSE
#define JSON_MAX_MEM_AREA_SIZE 1024
typedef struct st_json_dyna_area {
    int count;
    void *area[JSON_MAX_MEM_AREA_SIZE];
    uint64 used_dyn_buf; // record malloc memory for json object
} json_dyna_area_t;

typedef enum en_json_extract_policy {
    JEP_DELETE = 1,
    JEP_REPLACE_ONLY,
    JEP_REPLACE_OR_INSERT,
} json_extract_policy_e;

typedef struct st_json_large_area {
    int count;
    uint32 page_id[JSON_MAX_MEM_AREA_SIZE];
    uint32 free_bytes;
} json_large_area_t;

typedef json_large_area_t json_tree_area_t;
typedef json_large_area_t json_sort_area_t;

struct st_json_value;
struct st_json_path;
typedef struct st_json_assist {
    json_dyna_area_t jda;  // json dynamic memory area
    json_large_area_t jla; // json large page area
    json_tree_area_t jta;  // json tree area
    json_sort_area_t jsa;  // used for json sort area
    sql_stmt_t *stmt;
    struct st_json_value *jv;         // for filter
    struct st_json_path *filter_path; // for filter json tree where parse.
    struct st_json_value *parent_jv;  // for path level calculate
    vmc_t *vmc;
    bool32 is_overflow;
    bool32 is_json_retrieve;

    // for jsonb
    bool32 jsonb_result_is_list; // return jsonb value is single one? or a list?, used in wrapper cluse.
    struct st_json_analyse *janalys;
    uint8 version;
    uint8 head_entry_bytes;

    // for json set
    json_extract_policy_e policy;
    struct st_json_value *jv_new_val; // for replace
    bool32 need_sort;

    // these two params is for Securely access to memory
    uint32 max_len;
    uint64 original_ptr_loc;
} json_assist_t;

typedef enum en_json_mem_type {
    JSON_MEM_VMC,
    JSON_MEM_LARGE_POOL,
    JSON_MEM_LARGE_POOL_SORT
} json_mem_type_t;

status_t json_item_array_init(json_assist_t *ja, galist_t **galist, json_mem_type_t type);

static inline status_t json_malloc_dyna(uint64 size, char **ptr)
{
    sql_json_mem_pool_t *json_mpool = &g_instance->sql.json_mpool;

    cm_spin_lock(&(json_mpool->lock), NULL);
    if (size > JSON_MAX_SIZE - json_mpool->used_json_dyn_buf) {
        cm_spin_unlock(&(json_mpool->lock));
        GS_THROW_ERROR(ERR_ALLOC_MEMORY, size, "exceed json dyna memory area");
        return GS_ERROR;
    }
    json_mpool->used_json_dyn_buf += size;
    cm_spin_unlock(&(json_mpool->lock));

    *ptr = (char *)malloc((size_t)size);
    if (*ptr == NULL) {
        cm_spin_lock(&(json_mpool->lock), NULL);
        json_mpool->used_json_dyn_buf -= size;
        cm_spin_unlock(&(json_mpool->lock));
        GS_THROW_ERROR(ERR_ALLOC_MEMORY, size, "exceed json dynamic memory area");
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

static inline void json_free_dyna(uint32 size, char **ptr, uint32 ptr_cnt)
{
    for (uint32 i = 0; i < ptr_cnt; i++) {
        CM_FREE_PTR(ptr[i]);
    }
    cm_spin_lock(&g_instance->sql.json_mpool.lock, NULL);
    g_instance->sql.json_mpool.used_json_dyn_buf -= (uint64)size;
    cm_spin_unlock(&g_instance->sql.json_mpool.lock);
}

#define JSON_ASSIST_INIT(ja, stmt_input) \
    do {                                 \
        (ja)->jda.count = 0;             \
        (ja)->jda.used_dyn_buf = 0;      \
        (ja)->jta.count = 0;             \
        (ja)->jta.free_bytes = 0;        \
        (ja)->jla.count = 0;             \
        (ja)->jla.free_bytes = 0;        \
        (ja)->jsa.count = 0;             \
        (ja)->jsa.free_bytes = 0;        \
        (ja)->stmt = (stmt_input);       \
        (ja)->filter_path = NULL;        \
        (ja)->parent_jv = NULL;          \
        (ja)->is_overflow = GS_FALSE;    \
        (ja)->vmc = NULL;                \
    } while (0)
#define JSON_ASSIST_DESTORY(ja)                                                                     \
    do {                                                                                            \
        json_free_dyna((uint32)(ja)->jda.used_dyn_buf, (char **)((ja)->jda.area), (ja)->jda.count); \
        (ja)->jda.count = 0;                                                                        \
        (ja)->jda.used_dyn_buf = 0;                                                                 \
        JSON_FREE_LARGE(&((ja)->jta));                                                              \
        JSON_FREE_LARGE(&((ja)->jla));                                                              \
    } while (0)

static inline status_t JSON_ALLOC_DYNA(json_assist_t *ja, uint32 size, void **ptr)
{
    json_dyna_area_t *jda = &ja->jda;

    CM_ASSERT(size > 0);
    if (jda->count >= JSON_MAX_MEM_AREA_SIZE) {
        GS_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)size, "exceed json dyna memory area");
        return GS_ERROR;
    }

    GS_RETURN_IFERR(json_malloc_dyna(size, (char **)ptr));

    jda->used_dyn_buf += (uint64)size;
    jda->area[jda->count++] = *ptr;

    return GS_SUCCESS;
}

static inline void JSON_FREE_LARGE(json_large_area_t *jla)
{
    for (int i = 0; i < jla->count; i++) {
        mpool_free_page(&g_instance->sga.large_pool, jla->page_id[i]);
    }
    jla->count = 0;
    jla->free_bytes = 0;
}

static inline status_t JSON_ALLOC_LARGE(json_large_area_t *jla, uint32 size, void **ptr)
{
    uint32 large_page_id;

    CM_ASSERT(size > 0 && size <= GS_LARGE_PAGE_SIZE);
    if (size <= jla->free_bytes) {
        char *large_page_addr = mpool_page_addr(&g_instance->sga.large_pool, jla->page_id[jla->count - 1]);
        *ptr = large_page_addr + GS_LARGE_PAGE_SIZE - jla->free_bytes;
        jla->free_bytes -= size;
        return GS_SUCCESS;
    }

    if (jla->count >= JSON_MAX_MEM_AREA_SIZE) {
        GS_THROW_ERROR(ERR_ALLOC_MEMORY, size, "exceed json large area");
        return GS_ERROR;
    }
    GS_RETURN_IFERR(mpool_alloc_page_wait(&g_instance->sga.large_pool, &large_page_id, CM_MPOOL_ALLOC_WAIT_TIME));
    *ptr = mpool_page_addr(&g_instance->sga.large_pool, large_page_id);
    jla->page_id[jla->count] = large_page_id;
    jla->count++;
    jla->free_bytes = GS_LARGE_PAGE_SIZE - size;

    return GS_SUCCESS;
}

static inline status_t JSON_ALLOC(json_assist_t *ja, uint32 size, void **ptr)
{
    if (size <= MIN(GS_STRING_BUFFER_SIZE, GS_MAX_EXEC_LOB_SIZE)) {
        if (ja->vmc == NULL) {
            return sql_push(ja->stmt, size, ptr);
        } else {
            return vmc_alloc(ja->vmc, size, ptr);
        }
    } else if (size <= GS_LARGE_PAGE_SIZE) {
        return JSON_ALLOC_LARGE(&(ja->jla), size, ptr);
    }
    return JSON_ALLOC_DYNA(ja, size, ptr);
}

#define JSON_RETURN_ERROR_IF_STACK_OVERFLOW(ja, level)                                                    \
    do {                                                                                                  \
        if (sql_stack_safe((ja)->stmt) == GS_ERROR) {                                                     \
            (ja)->is_overflow = GS_TRUE;                                                                  \
            cm_reset_error();                                                                             \
            GS_THROW_ERROR_EX(ERR_JSON_INSUFFICIENT_MEMORY, "stack overflow(json level is %u)", (level)); \
            GS_LOG_DEBUG_INF("[JSON] CT-%05d, %s", cm_error_info()->code, cm_error_info()->message);      \
            return GS_ERROR;                                                                              \
        }                                                                                                 \
    } while (0)

#define SQL_EXEC_FUNC_ARG_EX3 SQL_EXEC_LENGTH_FUNC_ARG
extern status_t sql_exec_json_func_arg(json_assist_t *ja, expr_tree_t *arg, variant_t *var, variant_t *result);
extern status_t sql_exec_flatten_to_varchar(json_assist_t *ja, variant_t *var);

// ============================================================================
// JSON PARSE AND SERIALIZATION
typedef enum en_jv_type {
    JV_NULL = 0,
    JV_BOOL,
    JV_STRING,
    JV_NUMBER,
    JV_ARRAY,
    JV_OBJECT,

    // this jv is taged to be deleted, it can indicate whether the jv is valid or not. and it wastes no any space.
    JV_DELETED
} jv_type_t;
#define JV_IS_SCALAR(jv) ((jv)->type < JV_ARRAY)
#define JV_IS_OBJECT(jv) ((jv)->type == JV_OBJECT)
#define JV_IS_DELETED(jv) ((jv)->type == JV_DELETED)

#define JSON_TYPE_STR(type) g_json_type_str[type]

// json in-memory representation
typedef struct st_json_value {
    jv_type_t type;

    union {
        bool32 boolean;
        text_t string;
        text_t number;
        galist_t *array;  // json_value_t
        galist_t *object; // json_pair_t
    };
} json_value_t;

typedef struct st_json_pair {
    json_value_t key; // Must be a JV_STRING
    json_value_t val;
} json_pair_t;

#define JSON_ARRAY_SIZE(jv) ((jv)->array->count)
#define JSON_ARRAY_ITEM(jv, i) ((json_value_t *)cm_galist_get((jv)->array, i))
#define JSON_OBJECT_SIZE(jv) ((jv)->object->count)
#define JSON_OBJECT_ITEM(jv, i) ((json_pair_t *)cm_galist_get((jv)->object, i))

#define JSON_CHECK_MAX_SIZE(size)                                                                                  \
    do {                                                                                                           \
        if ((uint64)(size) > JSON_MAX_SIZE) {                                                                      \
            GS_THROW_ERROR_EX(ERR_JSON_INSUFFICIENT_MEMORY, "exceed json max allowed dynamic size(maximum: %llu)", \
                JSON_MAX_SIZE);                                                                                    \
            return GS_ERROR;                                                                                       \
        }                                                                                                          \
    } while (0)


#define JSON_TXTBUF_APPEND_CHAR(txtbuf, c)             \
    do {                                               \
        if ((txtbuf)->len + 1 > (txtbuf)->max_size) {  \
            GS_THROW_ERROR(ERR_JSON_OUTPUT_TOO_LARGE); \
            return GS_ERROR;                           \
        }                                              \
        CM_TEXT_APPEND((txtbuf), (c));                 \
    } while (0)

#define JSON_TXTBUF_APPEND_TEXT(text_buf, text)                     \
    do {                                                            \
        if ((text_buf)->len + (text)->len > (text_buf)->max_size) { \
            GS_THROW_ERROR(ERR_JSON_OUTPUT_TOO_LARGE);              \
            return GS_ERROR;                                        \
        }                                                           \
        for (uint32 i = 0; i < (text)->len; i++) {                  \
            CM_TEXT_APPEND((text_buf), (text)->str[i]);             \
        }                                                           \
    } while (0)

/* after analyse this json_value_t, we can get some information */
typedef struct st_json_analyse {
    uint32 array_count;  // total count of array node.
    uint32 object_count; // total count of object node.

    uint32 array_elems_count;  // total count of array elements.
    uint32 object_elems_count; // total count of object elements.
    uint32 max_elems_count;    // max count of array elements or object elements.
    uint32 odd_elems_count;    // odd count of array elements or object elements.

    uint64 string_number_len; // total len of string and number.
    uint64 last_elem_len;     // the len of last string and number.
} json_analyse_t;

status_t json_unescape_string(text_t *src, text_buf_t *unescaped_tbuf);
status_t json_escape_string(text_t *src, text_buf_t *escaped_tbuf);
status_t json_array_parse(json_assist_t *ja, text_t *src, json_value_t *jv, source_location_t loc);
status_t json_parse(json_assist_t *ja, text_t *src, json_value_t *jv, source_location_t loc);

status_t json_serialize_to_string_scalar(json_assist_t *ja, json_value_t *jv, variant_t *result);
status_t json_serialize_to_string(json_assist_t *ja, json_value_t *jv, variant_t *result);
status_t json_serialize_to_lob_normal_scalar(json_assist_t *ja, json_value_t *jv, variant_t *result);
status_t json_serialize_to_lob_vm(json_assist_t *ja, json_value_t *jv, variant_t *result);

status_t json_analyse(json_assist_t *ja, json_value_t *jv, json_analyse_t *analyse);

typedef struct st_json_quick_sort {
    uint32 left;
    uint32 right;
} json_quick_sort_t;

typedef struct st_json_assist_write json_assist_write_t;
typedef status_t (*json_write_t)(json_assist_write_t *jaw, char *str, uint32 len);
struct st_json_assist_write {
    // for both json and jsonb
    sql_stmt_t *stmt;
    json_write_t json_write;
    void *arg;
    bool32 is_scalar; // json string should not quoted if is_scalar TRUE

    // for jsonb only.
    uint8 *lob_buf;
    union {
        uint32 push_offset; // used in pushing
        uint32 real_size;   // user in the end
    };
    uint32 max_size; // max Estimated Length
    uint8 version;
    union {
        struct {
            uint8 entry_bytes : 4; // shows the bytes number of each entry
            uint8 head_bytes : 4;  // shows the bytes number of each head
        };
        uint8 head_entry_bytes;
    };

    // for jsonb deparse only.
    bool32 jsonb_result_is_list;

    // for jsonb combine to jsonb format.
    uint32 pure_data_size; /* only data total size */
    uint32 total_size;     /* all jsonb bytes size */

    // these two params is for Securely access to memory
    uint32 max_len;
    uint64 original_ptr_loc;
};

#define JSON_INIT_ASSIST_WRITE(jaw, _stmt, _json_write, _arg, _is_scalar) \
    do {                                                                  \
        (jaw)->stmt = (_stmt);                                            \
        (jaw)->json_write = (_json_write);                                \
        (jaw)->arg = (void *)(_arg);                                      \
        (jaw)->is_scalar = (_is_scalar);                                  \
    } while (0)

typedef struct st_json_vlob {
    vm_lob_t vlob;
    vm_page_t *last_page;
    int last_free_size;
} json_vlob_t;


#define JSON_INIT_VLOB(jlob)            \
    do {                                \
        cm_reset_vm_lob(&(jlob)->vlob); \
        (jlob)->last_page = NULL;       \
        (jlob)->last_free_size = 0;     \
    } while (0)

#define JSON_EXTEND_LOB_VMEM_IF_NEEDED(ja_vlob, stmt)                                                                  \
    do {                                                                                                               \
        json_vlob_t *_ja_vlob = (ja_vlob);                                                                             \
        id_list_t *_execute_vm_list = sql_get_exec_lob_list(stmt);                                                     \
        if (_ja_vlob->last_free_size == 0) {                                                                           \
            GS_RETURN_IFERR(sql_extend_lob_vmem((stmt), _execute_vm_list, &_ja_vlob->vlob));                           \
            GS_RETURN_IFERR(                                                                                           \
                vm_open((stmt)->session, (stmt)->mtrl.pool, _execute_vm_list->last, &_ja_vlob->last_page));            \
            _ja_vlob->last_free_size = GS_VMEM_PAGE_SIZE;                                                              \
        }                                                                                                              \
    } while (0)

status_t json_write_to_textbuf_unescaped(json_assist_write_t *jaw, char *str, uint32 len);
status_t json_write_to_textbuf(json_assist_write_t *jaw, char *str, uint32 len);


// ============================================================================
// JSON SQL FUNC PARSE, SUB CLAUSE HANDLE, RETRIEVE
typedef status_t (*json_invoke_func_t)(sql_stmt_t *stmt, json_value_t *jv);

typedef enum en_json_func_step_id {
    JFUNC_FUNC_STEP_INVALID,
    JFUNC_FUNC_STEP_TYPE
} json_func_step_id_t;

typedef struct st_json_func_step_item {
    char *name;
    uint32 len;
    json_func_step_id_t id;
    json_invoke_func_t invoke;
} json_func_step_item_t;

typedef enum en_json_func_att_id {
    JFUNC_ATT_INVALID = 0x00000000,

    JFUNC_ATT_RETURNING_VARCHAR2 = 0x00000001,
    JFUNC_ATT_RETURNING_CLOB = 0x00000002,
    JFUNC_ATT_RETURNING_JSONB = 0x00000004,

    JFUNC_ATT_NULL_ON_ERROR = 0x00000010,
    JFUNC_ATT_ERROR_ON_ERROR = 0x00000020,
    JFUNC_ATT_TRUE_ON_ERROR = 0x00000040,
    JFUNC_ATT_FALSE_ON_ERROR = 0x00000080,
    JFUNC_ATT_EMPTY_ON_ERROR = 0x00000100,
    JFUNC_ATT_EMPTY_ARRAY_ON_ERROR = 0x00000200,
    JFUNC_ATT_EMPTY_OBJECT_ON_ERROR = 0x00000400,

    JFUNC_ATT_NULL_ON_EMPTY = 0x00001000,
    JFUNC_ATT_ERROR_ON_EMPTY = 0x00002000,
    JFUNC_ATT_EMPTY_ON_EMPTY = 0x00010000,
    JFUNC_ATT_EMPTY_ARRAY_ON_EMPTY = 0x00020000,
    JFUNC_ATT_EMPTY_OBJECT_ON_EMPTY = 0x00040000,

    JFUNC_ATT_ABSENT_ON_NULL = 0x00100000,
    JFUNC_ATT_NULL_ON_NULL = 0x00200000,

    JFUNC_ATT_WITHOUT_WRAPPER = 0x01000000, // default
    JFUNC_ATT_WITH_WRAPPER = 0x02000000,
    JFUNC_ATT_WITH_CON_WRAPPER = 0x04000000
} json_func_att_id_t;

#define JFUNC_ATT_RETURNING_MASK 0x0000000F
#define JFUNC_ATT_ON_ERROR_MASK 0x00000FF0
#define JFUNC_ATT_ON_EMPTY_MASK 0x000FF000
#define JFUNC_ATT_ON_NULL_MASK 0x00F00000
#define JFUNC_ATT_WRAPPER_MASK 0x0F000000

#define JFUNC_ATT_GET_RETURNING(id) ((id) & JFUNC_ATT_RETURNING_MASK)
#define JFUNC_ATT_GET_ON_ERROR(id) ((id) & JFUNC_ATT_ON_ERROR_MASK)
#define JFUNC_ATT_GET_ON_EMPTY(id) ((id) & JFUNC_ATT_ON_EMPTY_MASK)
#define JFUNC_ATT_GET_ON_NULL(id) ((id) & JFUNC_ATT_ON_NULL_MASK)
#define JFUNC_ATT_GET_WRAPPER(id) ((id) & JFUNC_ATT_WRAPPER_MASK)

#define JFUNC_ATT_HAS_RETURNING(id) (JFUNC_ATT_GET_RETURNING(id) != JFUNC_ATT_INVALID)
#define JFUNC_ATT_HAS_ON_EMPTY(id) (JFUNC_ATT_GET_ON_EMPTY(id) != JFUNC_ATT_INVALID)
#define JFUNC_ATT_HAS_ON_NULL(id) (JFUNC_ATT_GET_ON_NULL(id) != JFUNC_ATT_INVALID)
#define JFUNC_ATT_HAS_ON_ERROR(id) (JFUNC_ATT_GET_ON_ERROR(id) != JFUNC_ATT_INVALID)
#define JFUNC_ATT_HAS_WRAPPER(id) (JFUNC_ATT_GET_WRAPPER(id) != JFUNC_ATT_INVALID)

#define JSON_MAX_PATH_EXPR_LEN 1024
#define JSON_FUNC_LEN_DEFAULT 3900

#define JSON_FUNC_ATT_INIT(att)                                              \
    do {                                                                     \
        (att)->ids = JFUNC_ATT_RETURNING_VARCHAR2 | JFUNC_ATT_NULL_ON_ERROR; \
        (att)->return_size = JSON_FUNC_LEN_DEFAULT;                          \
    } while (0)

void json_func_att_init(json_func_attr_t *attr);
status_t json_func_att_match(text_t *src, json_func_attr_t *attr);
status_t handle_on_error_clause(json_func_attr_t att, variant_t *result);
status_t handle_on_empty_clause(json_assist_t *ja, json_func_attr_t att, variant_t *result);
status_t handle_returning_clause(json_assist_t *ja, json_value_t *jv, json_func_attr_t json_func_attr,
    variant_t *result, bool32 scalar_retrieve);
status_t json_retrieve_core(json_assist_t *ja, expr_node_t *func, variant_t *result);

#define IS_JSON_ERR(err_code) ((err_code) >= 2501 && (err_code) <= 2599)

#define JSON_RETURN_IF_ON_ERROR_HANDLED(_status, ja, attr, result)         \
    do {                                                                   \
        if ((_status) != GS_SUCCESS) {                                     \
            int32 err_code;                                                \
            const char *err_msg;                                           \
            cm_get_error(&err_code, &err_msg, NULL);                       \
            if (IS_JSON_ERR(err_code)) {                                   \
                GS_LOG_DEBUG_INF("[JSON] CT-%05d, %s", err_code, err_msg); \
                if ((ja)->is_overflow == GS_TRUE) {                        \
                    return GS_ERROR;                                       \
                }                                                          \
                return handle_on_error_clause(attr, result);               \
            } else {                                                       \
                return GS_ERROR;                                           \
            }                                                              \
        }                                                                  \
    } while (0)


#define JSON_RETURN_IF_ON_EMPTY_HANDLED(_matched, ja, attr, result) \
    do {                                                            \
        if (!(_matched)) {                                          \
            return handle_on_empty_clause(ja, attr, result);        \
        }                                                           \
    } while (0);

// ============================================================================
// JSON PATH PARSE, COMPILE, EXTRACT
#define JSON_PATH_MIN_LEN (1)
#define JSON_PATH_CHR_BEGIN ('$')
#define JSON_PATH_CHR_DOT ('.')
#define JSON_PATH_CHR_SQBRACKET_L ('[')
#define JSON_PATH_CHR_SQBRACKET_R (']')
#define JSON_PATH_CHR_STAR ('*')
#define JSON_PATH_CHR_COMMA (',')
#define JSON_PATH_CHR_SPACE (' ')
#define JSON_PATH_CHR_QUESTION ('?')
#define JSON_PATH_CHR_BRACKET_L ('(')
#define JSON_PATH_CHR_BRACKET_R (')')

#define JSON_PATH_MAX_LEN (256)
#define JSON_PATH_MAX_LEVEL (32)
#define JSON_PATH_MAX_ARRAY_IDX_CNT (32)
#define JSON_PATH_MAX_STEP_NAME_LEN (68)

typedef enum en_json_path_step_type {
    // $, it must appears at the beginning of str,
    // it may has array index  ($[*] eg.), it appears only once
    JSON_PATH_STEP_HEAD = 1,

    // only for key, A.B.C.D  eg. has no array index
    JSON_PATH_STEP_KEYNAME,

    // only for array, A[X].B[X] eg.  must has array index
    JSON_PATH_STEP_ARRAY
} json_path_step_type_t;

typedef struct st_json_path_step_idx_pair {
    uint32 from_index;
    uint32 to_index;
} json_path_step_idx_pair_t;

// flags for json query path node
#define JSON_PATH_KEYNAME_IS_STAR (0x00000001)
#define JSON_PATH_INDEX_IS_STAR (0x00000001)

typedef struct st_json_select_expr_node {
    json_path_step_type_t type;

    // path node name
    uint32 keyname_flag;
    char keyname[JSON_PATH_MAX_STEP_NAME_LEN + 1];
    uint32 keyname_length;
    bool8 keyname_exists;

    // index pairs
    uint32 index_flag;
    uint32 index_pairs_count; // * can not exist with indexs
    json_path_step_idx_pair_t index_pairs_list[JSON_PATH_MAX_ARRAY_IDX_CNT];
} json_path_step_t;

struct st_json_pf_cond;
typedef struct st_json_path {
    // path nodes
    uint32 count;
    json_path_step_t steps[JSON_PATH_MAX_LEVEL];
    json_func_step_item_t *func;

    struct st_json_pf_cond *cond;
} json_path_t;

#define JSON_PATH_SIZE(path) ((path)->count)
#define JSON_PATH_ITEM(path, i) (&(path)->steps[(i)])
#define JSON_PATH_RESET(path)                                                                   \
    do {                                                                                        \
        MEMS_RETURN_IFERR(memset_s((void *)(path), sizeof(json_path_t), 0, sizeof(json_path_t))); \
    } while (0)


status_t json_path_compile(json_assist_t *ja, text_t *path_text, json_path_t *path, source_location_t loc);
status_t json_path_extract(json_value_t *jv, json_path_t *path, json_value_t *jv_result_array);
status_t json_merge_patch(json_assist_t *ja, json_value_t *jv_target, json_value_t *jv_patch, json_value_t **jv_result);

status_t json_set_core(json_assist_t *ja, json_value_t *jv_target, json_path_t *path, json_func_attr_t attr,
    variant_t *result);
status_t json_set_iteration(json_assist_t *ja, json_value_t *jv_target, json_path_t *path);

// ============================================================================
// JSON PATH FILTER: PARSE, EVAL
typedef enum en_json_pf_op_type {
    JSON_PF_OP_INVLID,

    // COND OP
    JSON_PF_OP_AND, // cond1 && cond2
    JSON_PF_OP_OR,  // cond1 || cond2
    JSON_PF_OP_NOT, // ! ( cond )

    // CMP OP
    JSON_PF_OP_EQ,          // ==
    JSON_PF_OP_NEQ,         // <>
    JSON_PF_OP_LT,          // <
    JSON_PF_OP_LEQ,         // <=
    JSON_PF_OP_GT,          // >
    JSON_PF_OP_GEQ,         // >=
    JSON_PF_OP_EXISTS,      // EXISTS (relative_path_expression)
    JSON_PF_OP_HAS_SUBSTR,  // relative_path_expression HAS SUBSTRING json string
    JSON_PF_OP_STARTS_WITH, // relative_path_expression STARTS WITH json string
    JSON_PF_OP_LIKE,        // relative_path_expression LIKE json string
    JSON_PF_OP_LIKE_REGEX,  // relative_path_expression LIKE_REGEX json string
    JSON_PF_OP_EQ_REGEX,    // relative_path_expression EQ_REGEX json string
    JSON_PF_OP_IN,          // relative_path_expression IN (scaler value list)
} json_pf_op_type_t;
#define JSON_PF_OP_IS_LOGIC(type) ((type) >= JSON_PF_OP_AND && (type) <= JSON_PF_OP_NOT)
#define JSON_PF_OP_IS_CMP(type) ((type) >= JSON_PF_OP_EQ && (type) <= JSON_PF_OP_IN)

typedef enum en_json_pf_expr_type {
    JSON_PF_EXPR_INVALID,
    JSON_PF_EXPR_RPATH,
    JSON_PF_EXPR_CONST,
    JSON_PF_EXPR_PARAM,
} json_pf_expr_type_t;
typedef struct st_json_pf_expr {
    json_pf_expr_type_t type1;
    union {
        json_path_t rpath;
        json_value_t constant;
        text_t param;
    };
} json_pf_expr_t;
#define JSON_PF_EXPR_TYPE(expr) ((expr)->type1)

typedef struct st_json_pf_cond {
    json_pf_op_type_t type;

    union {
        json_pf_expr_t *l_expr;
        struct st_json_pf_cond *l_cond;
    };
    union {
        json_pf_expr_t *r_expr;
        struct st_json_pf_cond *r_cond;
    };

    struct st_json_pf_cond *prev;
    struct st_json_pf_cond *next;
} json_pf_cond_t;
#define JSON_PF_COND_INIT(cond)                                                               \
    do {                                                                                      \
        MEMS_RETURN_IFERR(memset_s(cond, sizeof(json_pf_cond_t), 0, sizeof(json_pf_cond_t))); \
    } while (0)

typedef struct st_json_pf_cond_chain {
    json_pf_cond_t *first;
    json_pf_cond_t *last;
    uint32 count;
} json_pf_cond_chain_t;

typedef struct st_json_pf_cond_tree {
    json_pf_cond_t *root;
    json_pf_cond_chain_t chain;
} json_pf_cond_tree_t;

#define JSON_PF_COND_TREE_INIT(cond)                                                                    \
    do {                                                                                                \
        MEMS_RETURN_IFERR(memset_s(cond, sizeof(json_pf_cond_tree_t), 0, sizeof(json_pf_cond_tree_t))); \
    } while (0)

status_t json_pf_create_cond_from_text(json_assist_t *ja, text_t *text, json_pf_cond_t **cond, source_location_t loc);
status_t json_path_do_filter(json_assist_t *ja, json_pf_cond_t *cond, json_value_t *jv_array);
status_t json_path_execute_func(json_assist_t *ja, json_func_step_item_t *func, json_value_t *jv_array);
status_t json_func_att_match_returning(text_t *src, json_func_attr_t *attr);
status_t json_func_att_match_on_error(text_t *src, json_func_attr_t *attr);
status_t json_func_att_match_wrapper(text_t *src, json_func_attr_t *attr);
status_t json_func_get_result(json_assist_t *ja, expr_node_t *func, variant_t *result, json_path_t *path,
    json_value_t *jv);

#ifdef __cplusplus
}
#endif

#endif
