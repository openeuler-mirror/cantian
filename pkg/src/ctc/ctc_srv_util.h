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
 * ctc_srv_util.h
 *
 *
 * IDENTIFICATION
 * src/ctc/ctc_srv_util.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __CTC_SRV_UTIL_H__
#define __CTC_SRV_UTIL_H__

#include "cm_text.h"
#include "cm_stack.h"
#include "srv_session.h"
#include "knl_interface.h"
#include "ctc_srv.h"
#include "cm_charset.h"
#include "cm_malloc.h"
#include "var_defs.h"
#include "ctsql_stmt.h"
#include "knl_table.h"

#define LLONG_MAX_DOUBLE (9223372036854774784.0)
#define FLOAT_COL_MAX_VALUE (16777217)
#define DOUBLE_COL_MAX_VALUE (9007199254740993)
#define COL_MIN_VALUE (0)
#define CTC_THD_HASH_SIZE 5000
#define MAX_INDEXES 64U                          // change with "/mysql-source/bld_debug/include/config.h: MAX_INDEXES"
#define LOB_DATA_SIZE_8M (1024 * 1024 * 8) //LOB类型最大的buffer长度为8M

#define SMALL_RECORD_SIZE 128                    // 表名、库名等长度不会特别大，取128
#define CTC_MAGIC_NUM 0xB693AB82
#define INDEX_KEY_SIZE 4096                    // 索引查询条件的大小mysql限制为3072，取4096
#define INVALID_DUP_KEY_SLOT (-1)
#ifndef INVALID_VALUE64
#define INVALID_VALUE64 0xFFFFFFFFFFFFFFFFULL
#endif

typedef struct {
    int64 max_serial_col_value;
    bool is_uint64;
} serial_t;

#define CTC_RET_IF_CPR_ERR(ret)                                    \
    do {                                                           \
        if ((ret) == CPR_ERROR) {                                  \
            return (ret);                                          \
        }                                                          \
    } while (0)

#define CTC_RET_IF_CP_INVALID_COL(invalid_index_col)               \
    do {                                                           \
        if (invalid_index_col) {                                   \
            return (CPR_TRUE);                                     \
        }                                                          \
    } while (0)

#define CTC_LOG_RET_VAL_IF_NUL(val, ret, fmt, ...)                 \
    do {                                                           \
        if ((val) == NULL) {                                       \
            CT_LOG_RUN_ERR("%s:"fmt, __FUNCTION__, ##__VA_ARGS__); \
            return (ret);                                          \
        }                                                          \
    } while (0)

#define CTC_POP_CURSOR(knl_session)                                 \
    do {                                                            \
        CM_RESTORE_STACK((knl_session)->stack);                     \
        (((session_t *)(knl_session))->total_cursor_num_stack) = 0;   \
    } while (0)

#define CLOSE_CURSOR_RESTORE_STACK(knl_session, cursor)      \
    do {                                                     \
        ctc_close_cursor(knl_session, cursor);               \
        CTC_POP_CURSOR(knl_session);                         \
    } while (0)

#define IS_CANTIAN_SYS_DC(dc) ((((dc)->type) > DICT_TYPE_TABLE_EXTERNAL) || IS_SYS_DC(dc))
bool check_if_operation_unsupported(knl_dictionary_t *dc, char *operation);

#define RETURN_IF_OPERATION_UNSUPPORTED(dc, operation)                                                            \
    do {                                                                                                          \
        if (check_if_operation_unsupported(dc, operation)) {                                                      \
            knl_close_dc(dc);                                                                                     \
            return CT_ERROR;                                                                                      \
        }                                                                                                         \
    } while (0)

#define CTC_LOG_RET_NOT_SUPPORT(condition, operation, ret)                                                        \
    do {                                                                                                          \
        if (condition) {                                                                                          \
            CT_LOG_RUN_ERR("Operation %s is not supported on view, func, join table, "                            \
                           "json table, subqueries or system table", operation);                                  \
            return ret;                                                                                           \
        }                                                                                                         \
    } while (0)

/*
define flag Enumerated type according to mysql 'ha_rkey_function' Enumerated type
*/
typedef enum en_ctc_ha_rkey_function {
    CTC_HA_READ_KEY_EXACT,           /* Find first record else error */
    CTC_HA_READ_KEY_OR_NEXT,         /* Record or next record */
    CTC_HA_READ_KEY_OR_PREV,         /* Record or previous */
    CTC_HA_READ_AFTER_KEY,           /* Find next rec. after key-record */
    CTC_HA_READ_BEFORE_KEY,          /* Find next rec. before key-record */
    CTC_HA_READ_PREFIX,              /* Key which as same prefix */
    CTC_HA_READ_PREFIX_LAST,         /* Last key with the same prefix */
    CTC_HA_READ_PREFIX_LAST_OR_PREV, /* Last or prev key with the same prefix */
    CTC_HA_READ_MBR_CONTAIN,         /* Minimum Bounding Rectangle contains */
    CTC_HA_READ_MBR_INTERSECT,       /* Minimum Bounding Rectangle intersect */
    CTC_HA_READ_MBR_WITHIN,          /* Minimum Bounding Rectangle within */
    CTC_HA_READ_MBR_DISJOINT,        /* Minimum Bounding Rectangle disjoint */
    CTC_HA_READ_MBR_EQUAL,           /* Minimum Bounding Rectangle equal */
    CTC_HA_READ_INVALID = -1         /* Invalid enumeration value, always last. */
} ctc_ha_rkey_function_t;

typedef enum en_cond_pushdown_result {
    CPR_ERROR = -1,
    CPR_FALSE = 0,
    CPR_TRUE  = 1
} cond_pushdown_result_t;

typedef enum en_ctc_numeric_size {
    CTC_TINY_INT_SIZE = 1,
    CTC_SMALL_INT_SIZE = 2,
    CTC_MEDIUM_INT_SIZE = 3,
    CTC_INTEGER_SIZE = 4,
} en_ctc_numeric_size_t;

uint64_t ctc_calc_max_serial_value(knl_column_t *knl_column, uint64 *next_value);
void ctc_calc_max_serial_value_integer(knl_column_t *knl_column, uint64_t *limit_value);
void ctc_calc_max_serial_value_uint32(knl_column_t *knl_column, uint64_t *limit_value);
void ctc_calc_max_serial_value_real(knl_column_t *knl_column, uint64_t *limit_value);
void ctc_convert_serial_col_value_4int(uint32 size, char *column_data_buf, int64 *value);
void ctc_convert_serial_col_value_4uint(uint32 size, char *column_data_buf, int64 *value);
int64 convert_float_to_rint(char *ptr);
int64 convert_double_to_rint(char *ptr);
status_t ctc_get_curr_serial_value(knl_handle_t handle, knl_handle_t dc_entity, uint64 *value);
status_t ctc_get_curr_serial_value_auto_inc(knl_handle_t handle, knl_handle_t dc_entity, uint64 *value,
                                            uint16 auto_inc_step, uint16 auto_inc_offset);
void ctc_save_stack(ctc_context_t *ctc_context, cm_stack_t *stack);
void ctc_restore_stack(ctc_context_t *ctc_context, cm_stack_t *stack);
void ctc_free_session_cursor_impl(session_t *session, knl_cursor_t *cursor, char *func, int32_t line_no);
#define ctc_free_session_cursor(session, cursor) ctc_free_session_cursor_impl(session, cursor, __func__, __LINE__);
void ctc_free_handler_cursor(session_t *session, ctc_handler_t *tch);
void ctc_free_cursors(session_t *session, uint64_t *cursors, int32_t csize);
knl_cursor_t *ctc_alloc_session_cursor(session_t *session, uint32_t part_id, uint32_t subpart_id);
status_t ctc_try_reopen_dc(knl_session_t *knl_session, text_t *user, text_t *table, knl_dictionary_t *dc);
status_t ctc_open_cursor(knl_session_t* knl_session, knl_cursor_t* cursor,
                         ctc_context_t *ctc_context, uint8_t *sql_stat_start, bool is_select);
void ctc_close_cursor(knl_session_t* knl_session, knl_cursor_t* cursor);
knl_cursor_t *ctc_push_cursor(knl_session_t *knl_session);

status_t init_ctc_ctx(ctc_context_t **ctx, const char *table_name, const char *user_name);
status_t init_ctc_ctx_and_open_dc(session_t *session, ctc_context_t **ctc_context,
    const char *table_name, const char *user_name);
void free_ctc_ctx(ctc_context_t **ctx, bool delete_context);
ctc_context_t* ctc_get_ctx_by_addr(uint64_t addr);
bool32 ctc_alloc_stmt_context(session_t *session);
bool32 ctc_alloc_stmt(session_t *session);
int ctc_get_and_reset_err(void);
session_t* ctc_get_session_by_addr(uint64_t addr);
status_t ctc_get_new_session(session_t **session_ptr);
int ctc_get_or_new_session(session_t **session, ctc_handler_t *tch,
                           bool alloc_if_null, bool need_init, bool *is_new_session);
void ctc_free_session(session_t *session);

int ctc_index_only_row_fill_bitmap(knl_cursor_t *cursor, uint8_t *raw_row);

void ctc_fill_update_info(knl_update_info_t *ui, uint16_t new_record_len,
    const uint8_t *new_record, const uint16_t *upd_cols, uint16_t col_num);

int fetch_and_delete_all_rows(knl_session_t *knl_session, knl_cursor_t *cursor, dml_flag_t flag);

cond_pushdown_result_t update_cond_field_col(knl_cursor_t *cursor, ctc_cond_field *field_info);
bool check_column_field_is_null(knl_cursor_t *cursor, uint16_t col);
bool check_value_is_compare(ctc_func_type_t func_type, int32 cmp);
int32 compare_var_data_ins(char *data1, uint16 size1, char *data2, uint16 size2, ct_type_t type);
cond_pushdown_result_t check_cond_match_one_line(ctc_conds *cond, knl_cursor_t *cursor, uint32 charset_id);
int compute_cond_elements(ctc_conds *cond, knl_cursor_t *cursor, uint32 charset_id,
                          variant_t *left, variant_t *right, nlsparams_t *nls);
void ctc_init_index_scan(knl_cursor_t *cursor, bool32 is_equal, bool32 *need_init_index);
int ctc_get_index_info_and_set_scan_key(knl_cursor_t *cursor, const index_key_info_t *index_key_info);
int ctc_pq_set_scan_key(knl_cursor_t *cursor, ctc_scan_range_t scan_range, const index_key_info_t *index_key_info);

void ctc_pre_set_cursor_for_scan(uint32 index_set_count, knl_cursor_t *cursor, uint16_t active_index);
int ctc_count_rows(session_t *session, knl_dictionary_t *dc, knl_session_t *knl_session,
                   knl_cursor_t *cursor, uint64_t *rows);

void unlock_instance_for_bad_mysql(uint32_t inst_id);
int clean_up_for_bad_mysql(uint32_t inst_id);
int clean_up_for_bad_cantian(uint32_t cantian_inst_id);

char* sql_without_plaintext_password(bool contains_plaintext_password, char* sql_str, size_t sql_str_len);
status_t ctc_open_dc(char *user_name, char *table_name, sql_stmt_t *stmt, knl_dictionary_t *dc);
void ctc_set_no_use_other_sess4thd(session_t *session);

void ctc_get_index_from_name(knl_dictionary_t *dc, char *index_name, uint16_t *active_index);
status_t ctc_check_index_column_count(uint32_t column_cnt);
void ctc_sql_str_remove_escape_chars(char *str, size_t len);
void ctc_set_session_ssn_scn(knl_session_t *session, uint8_t *sql_stat_start);

#define CTC_HANDLE_KNL_FETCH_FAIL_LIMIT(session, tch)                                                    \
    do {                                                                                                    \
        CT_LOG_RUN_ERR_LIMIT(LOG_PRINT_INTERVAL_SECOND_20, "get_correct_pos_by_fetch: knl_fetch FAIL");     \
        ctc_free_handler_cursor(session, tch);                                                              \
        return ctc_get_and_reset_err();                                                                     \
    } while (0)

static inline void proto_str2text(char *str, text_t *text)
{
    text->str = (strlen(str) == 0) ? NULL : str;
    text->len = (str == NULL) ? 0 : (uint32)strlen(str);
}

/*
    如果会改text里面的内容不能使用proto_str2text那种方式;
    text_size为实际空间大小-1,text.str[text_size]的位置会自动填充0，请预留好位置
*/
static inline void proto_str2text_ex(char *str, text_t *text, uint32 text_size)
{
    knl_panic(text->str != NULL);
    uint32 str_len = str == NULL ? 0 : strlen(str);
    knl_panic(str_len < text_size);
    int ret = strncpy_s(text->str, text_size, str, str_len);
    knl_securec_check(ret);
    text->str[text_size] = 0;
    text->len = strlen(text->str);
}

#endif // __CTC_SRV_UTIL_H__
