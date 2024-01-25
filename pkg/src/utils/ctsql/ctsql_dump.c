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
 * ctsql_dump.c
 *
 *
 * IDENTIFICATION
 * src/utils/ctsql/ctsql_dump.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_base.h"
#include "ctsql_dump.h"
#include "cm_lex.h"
#include "ctsql_common.h"
#include "cm_encrypt.h"

#define MAX_DUMP_SQL_SIZE      SIZE_M(1)
#define MAX_DUMP_CONVERT_SIZE  SIZE_M(8)  // for less lob read times : modified SIZE_K(16) --> SIZE_M(4)
#define MAX_DUMP_FILE_BUF_SIZE SIZE_M(16) // for write file.
#define NEED_SPLIT_FILE(opt) ((opt)->file_size > 0)

#define CTSQL_DUMP_RETURN_IF_CLI_ERROR(ret)   \
    do {                                     \
        int _status_ = (ret);                \
        if (_status_ != CT_SUCCESS) {        \
            ctsql_print_error(NULL);          \
            return _status_;                 \
        }                                    \
    } while (0)

typedef enum {
    DUMP_TABLE,
    DUMP_QUERY
} dump_type_t;

typedef struct {
    bool32 enclosed_optionally;
    char fields_enclosed;
    char fields_terminated[TERMINATED_STR_ARRAY_SIZE];
    char lines_terminated[TERMINATED_STR_ARRAY_SIZE];
    char query_sql[MAX_DUMP_SQL_SIZE];
    uint32 max_filebuf_size;
    uint32 write_mode;
    uint64 file_size;
    uint32 charset_id;
    crypt_info_t crypt_info;
} dump_option_t;

static dump_option_t g_dump_opt = {
    .enclosed_optionally = CT_FALSE,
    .fields_enclosed = CTSQL_DEFAULT_ENCLOSED_CHAR,
    .fields_terminated = CTSQL_DEFAULT_FIELD_SEPARATOR_STR,
    .lines_terminated = CTSQL_DEFAULT_LINE_SEPARATOR_STR,
    .max_filebuf_size = MAX_DUMP_FILE_BUF_SIZE,
    .write_mode = CT_FALSE,
    .file_size = 0,  // default 0, don't split file
    .charset_id = CT_DEFAULT_LOCAL_CHARSET,
};

typedef struct {
    char *buffer;
    text_t txt;
    uint32 row_end_pos;
} dumper_buffer_t;

typedef struct dump_column_param {
    char enclosed_char;
    char *line_terminal;
    uint32 line_terminal_len;
    char *field_terminal;
    uint32 field_terminal_len;
} dump_param_t;

typedef struct {
    dump_type_t type;

    uint32 col_num;
#ifdef USE_CTSQL_COLUMN_DESC
    ctconn_inner_column_desc_t *col_desc;
#else
    ctconn_inner_column_desc_t col_desc[CT_MAX_COLUMNS];
#endif  // USE_CTSQL_COLUMN_DESC
    char dump_file[CT_MAX_FILE_PATH_LENGH];
    int32 encrypt_file;
    uint64 dumped_rows; /* The successfully loaded rows to server */

    dumper_buffer_t file_buf; /* the buffer to dump rows into file */
    char *conver_buf;         /* used for converting data into string */
    dump_param_t column_param;
    int32 file;
    int32 file_idx;
    int32 file_size;
    bool8 file_end;
} dumper_t;

static inline void ctsql_free_dumper(dumper_t *dumper);
static status_t ctsql_dump_write_str(dumper_t *dumper, char *str, uint16 len, bool32 row_end);
static status_t ctsql_dump_write_text(dumper_t *dumper, text_t *text, bool32 row_end);

static inline void ctsql_dump_enclosed_char(dumper_t *dumper, int datatype)
{
    char fields_enclosed[2] = { 0 };
    uint16 enclosed_len;
    fields_enclosed[0] = dumper->column_param.enclosed_char;
    fields_enclosed[1] = '\0';
    enclosed_len = strlen(fields_enclosed) == 0 ? 1 : (uint16)strlen(fields_enclosed);
    if (!CTSQL_HAS_ENCLOSED_CHAR(g_dump_opt.fields_enclosed)) {
        return;
    }

    if (g_dump_opt.enclosed_optionally) {  // merely string and binary type are enclosed
        if (CTSQL_IS_ENCLOSED_TYPE(datatype)) {
            (void)ctsql_dump_write_str(dumper, fields_enclosed, enclosed_len, CT_FALSE);
        }
    } else {  // all type are enclosed
        (void)ctsql_dump_write_str(dumper, fields_enclosed, enclosed_len, CT_FALSE);
    }
}

int ctsql_dump_add_escape(text_t *buf, uint32 buf_len, int datatype, char enclosed_char)
{
    char *temp = NULL;
    uint32 i = 0;
    uint32 j = 0;
    errno_t errcode = 0;
    if (!CTSQL_HAS_ENCLOSED_CHAR(enclosed_char) || !CTSQL_IS_ENCLOSED_TYPE(datatype)) {
        return CTCONN_SUCCESS;
    }

    if (buf == NULL || buf->str == NULL || buf->len == 0) {
        return CTCONN_SUCCESS;
    }

    temp = (char *)malloc(buf->len * 2);
    if (temp == NULL) {
        ctsql_printf("out of memory");
        return CTCONN_ERROR;
    }

    for (i = 0; i < buf->len; i++) {
        if (buf->str[i] == enclosed_char) {
            temp[j] = enclosed_char;
            temp[j + 1] = enclosed_char;

            j += 2;
        } else {
            temp[j] = buf->str[i];
            j += 1;
        }
    }

    if (j != 0) {
        errcode = memcpy_s(buf->str, buf_len, temp, j);
        if (errcode != EOK) {
            CM_FREE_PTR(temp);
            CT_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
            return CTCONN_ERROR;
        }
    }
    buf->len = j;

    CM_FREE_PTR(temp);
    return CTCONN_SUCCESS;
}

static inline int ctsql_dump_column_raw(const binary_t *bin, text_t *result)
{
    result->len = MAX_DUMP_CONVERT_SIZE;

    if (cm_bin2text(bin, CT_TRUE, result) != CT_SUCCESS) {
        ctsql_print_error(NULL);
        return CTCONN_ERROR;
    }

    return CTCONN_SUCCESS;
}

static inline int ctsql_dump_column_clob(dumper_t *dumper, uint32 col_id)
{
    uint32 offset = 0;
    bool32 eof = 0;
    uint32 nchars;
    uint32 nbytes;
    text_t result;

    do {
        CT_RETURN_IFERR(ctconn_read_clob_by_id(STMT, col_id, offset, dumper->conver_buf, MAX_DUMP_CONVERT_SIZE / 2,
                                            &nchars, &nbytes, &eof));
        offset += nbytes;

        if (nbytes > 0) {
            result.str = dumper->conver_buf;
            result.len = nchars;
            CT_RETURN_IFERR(ctsql_dump_add_escape(&result, MAX_DUMP_CONVERT_SIZE, dumper->col_desc[col_id].type,
                                                 g_dump_opt.fields_enclosed));
            CTSQL_DUMP_RETURN_IF_CLI_ERROR(ctsql_dump_write_text(dumper, &result, CT_FALSE));
        }
    } while (!eof);

    return CTCONN_SUCCESS;
}

static inline int ctsql_dump_column_blob(dumper_t *dumper, uint32 col_id)
{
    uint32 offset = 0;
    bool32 eof = 0;
    uint32 nbytes;
    text_t result;

    do {
        CT_RETURN_IFERR(ctconn_read_blob_by_id(STMT, col_id, offset, dumper->conver_buf, MAX_DUMP_CONVERT_SIZE / 2,
                                            &nbytes, &eof));
        offset += nbytes;

        if (nbytes > 0) {
            result.str = dumper->conver_buf;
            result.len = nbytes;
            CT_RETURN_IFERR(ctsql_dump_add_escape(&result, MAX_DUMP_CONVERT_SIZE, dumper->col_desc[col_id].type,
                                                 g_dump_opt.fields_enclosed));
            CTSQL_DUMP_RETURN_IF_CLI_ERROR(ctsql_dump_write_text(dumper, &result, CT_FALSE));
        }
    } while (!eof);

    return CTCONN_SUCCESS;
}

static inline int ctsql_dump_column_type_date(char *nlsbuf, text_t *fmt_text, char *data, text_t *result)
{
    CT_RETURN_IFERR(ctsql_nlsparam_geter(nlsbuf, NLS_DATE_FORMAT, fmt_text));
    if (cm_date2text(*(date_t *)data, fmt_text, result, MAX_DUMP_CONVERT_SIZE + 1) != CT_SUCCESS) {
        ctsql_print_error(NULL);
        return CTCONN_ERROR;
    }
    return CTCONN_SUCCESS;
}

static inline int ctsql_dump_column_type_timestamp_ltz(char *nlsbuf, text_t *fmt_text, char *data, text_t *result)
{
    CT_RETURN_IFERR(ctsql_nlsparam_geter(nlsbuf, NLS_TIMESTAMP_FORMAT, fmt_text));
    if (cm_timestamp2text(*(date_t *)data, fmt_text, result, MAX_DUMP_CONVERT_SIZE + 1) != CT_SUCCESS) {
        ctsql_print_error(NULL);
        return CTCONN_ERROR;
    }
    return CTCONN_SUCCESS;
}

static inline int ctsql_dump_column_type_timestamp_tz(char *nlsbuf, text_t *fmt_text, char *data, text_t *result)
{
    CT_RETURN_IFERR(ctsql_nlsparam_geter(nlsbuf, NLS_TIMESTAMP_TZ_FORMAT, fmt_text));
    if (cm_timestamp_tz2text((timestamp_tz_t *)data, fmt_text, result, MAX_DUMP_CONVERT_SIZE + 1) != CT_SUCCESS) {
        ctsql_print_error(NULL);
        return CTCONN_ERROR;
    }
    return CTCONN_SUCCESS;
}

static inline int ctsql_dump_column_type_varbinary(dumper_t *dumper, text_t *result, uint32 col_id, char *data, uint32 size)
{
    if (size >= MAX_DUMP_CONVERT_SIZE - 2) {
        CTSQL_PRINTF(ZSERR_DUMP, "assert raised, expect: size(%u) < MAX_DUMP_CONVERT_SIZE(%u) - 2", size,
            MAX_DUMP_CONVERT_SIZE);
        return CTCONN_ERROR;
    }

    MEMS_RETURN_IFERR(memcpy_s(result->str, MAX_DUMP_CONVERT_SIZE, data, size));

    result->len = size;
    CT_RETURN_IFERR(ctsql_dump_add_escape(result, MAX_DUMP_CONVERT_SIZE, dumper->col_desc[col_id].type,
        g_dump_opt.fields_enclosed));
    return CTCONN_SUCCESS;
}

static status_t ctsql_dump_column_data_core(dumper_t *dumper, uint32 col_id, char *data, uint32 size)
{
    text_t fmt_text;
    char nlsbuf[MAX_NLS_PARAM_LENGTH];
    text_t result = { .str = dumper->conver_buf, .len = 0 };
    int iret_snprintf = 0;

    switch (dumper->col_desc[col_id].type) {
        case CTCONN_TYPE_BIGINT:
            cm_bigint2text(*(int64 *)data, &result);
            break;

        case CTCONN_TYPE_INTEGER:
            cm_int2text(*(int32 *)data, &result);
            break;

        case CTCONN_TYPE_UINT32:
            cm_uint32_to_text(*(uint32 *)data, &result);
            break;
        case CTCONN_TYPE_REAL:
            cm_real2text(*(double *)data, &result);
            break;

        case CTCONN_TYPE_BOOLEAN:
            cm_bool2text(*(bool32 *)data, &result);
            break;

        case CTCONN_TYPE_DATE: {
            CT_RETURN_IFERR(ctsql_dump_column_type_date((char *)nlsbuf, &fmt_text, data, &result));
            break;
        }

        case CTCONN_TYPE_TIMESTAMP:
        case CTCONN_TYPE_TIMESTAMP_TZ_FAKE:
        case CTCONN_TYPE_TIMESTAMP_LTZ: {
            CT_RETURN_IFERR(ctsql_dump_column_type_timestamp_ltz((char *)nlsbuf, &fmt_text, data, &result));
            break;
        }

        case CTCONN_TYPE_TIMESTAMP_TZ: {
            CT_RETURN_IFERR(ctsql_dump_column_type_timestamp_tz((char *)nlsbuf, &fmt_text, data, &result));
            break;
        }

        case CTCONN_TYPE_INTERVAL_YM:
            (void)cm_yminterval2text(*(interval_ym_t *)data, &result);
            break;

        case CTCONN_TYPE_INTERVAL_DS:
            (void)cm_dsinterval2text(*(interval_ds_t *)data, &result);
            break;

        case CTCONN_TYPE_CHAR:
        case CTCONN_TYPE_VARCHAR:
        case CTCONN_TYPE_STRING:
        case CTCONN_TYPE_BINARY:
        case CTCONN_TYPE_VARBINARY:
            CT_RETURN_IFERR(ctsql_dump_column_type_varbinary(dumper, &result, col_id, data, size));
            break;

        case CTCONN_TYPE_NUMBER:
        case CTCONN_TYPE_DECIMAL: {
            CT_RETVALUE_IFTRUE(cm_dec4_to_text_all((dec4_t*)data, &result) != CTCONN_SUCCESS, CTCONN_ERROR);
            break;
        }

        case CTCONN_TYPE_NUMBER2: {
            dec2_t dec2;
            cm_dec2_copy_ex(&dec2, (const payload_t *)data, size);
            CT_RETVALUE_IFTRUE(cm_dec2_to_text(&dec2, CTCONN_NUMBER_BOUND_SIZE, &result) != CTCONN_SUCCESS, CTCONN_ERROR);
            break;
        }

        case CTCONN_TYPE_RAW: {
            binary_t bin = { .bytes = (uint8 *)data, .size = size };
            CT_RETVALUE_IFTRUE(ctsql_dump_column_raw(&bin, &result) != CTCONN_SUCCESS, CTCONN_ERROR);
            CT_RETURN_IFERR(ctsql_dump_add_escape(&result, MAX_DUMP_CONVERT_SIZE, dumper->col_desc[col_id].type,
                                                 g_dump_opt.fields_enclosed));
            break;
        }

        case CTCONN_TYPE_CLOB:
            CT_RETVALUE_IFTRUE(ctsql_dump_column_clob(dumper, col_id) != CTCONN_SUCCESS, CTCONN_ERROR);
            return CTCONN_SUCCESS; /* lob write to file in 'ctsql_dump_column_clob' */

        case CTCONN_TYPE_BLOB:
        case CTCONN_TYPE_IMAGE:
            CT_RETVALUE_IFTRUE(ctsql_dump_column_blob(dumper, col_id) != CTCONN_SUCCESS, CTCONN_ERROR);
            return CTCONN_SUCCESS; /* lob write to file in 'ctsql_dump_column_blob' */

        default:
            iret_snprintf = snprintf_s(CM_GET_TAIL(&result), MAX_DUMP_CONVERT_SIZE + 1, MAX_DUMP_CONVERT_SIZE,
                                       "<UNSUPPORTED DATA TYPE>");
            PRTS_RETURN_IFERR(iret_snprintf);
            result.len += iret_snprintf;
            break;
    }

    if (result.len > MAX_DUMP_CONVERT_SIZE) {
        CTSQL_PRINTF(ZSERR_DUMP, "the row buffer size is too small!");
        return CTCONN_ERROR;
    }

    /* after write txt , result buffer can be reuse */
    CTSQL_DUMP_RETURN_IF_CLI_ERROR(ctsql_dump_write_text(dumper, &result, CT_FALSE));
    return CTCONN_SUCCESS;
}

static int ctsql_dump_column_data(ctconn_stmt_t stmt, dumper_t *dumper, uint32 col_id)
{
    char *data = NULL;
    bool32 is_null = CT_FALSE;
    uint32 size;

    if (ctconn_get_column_by_id(stmt, col_id, (void **)&data, &size, &is_null) != CT_SUCCESS) {
        ctsql_print_error(CONN);
        return CTCONN_ERROR;
    }

    if (is_null) {
        return CTCONN_SUCCESS;
    }

    ctsql_dump_enclosed_char(dumper, dumper->col_desc[col_id].type);

    CT_RETURN_IFERR(ctsql_dump_column_data_core(dumper, col_id, data, size));

    ctsql_dump_enclosed_char(dumper, dumper->col_desc[col_id].type);
    return CTCONN_SUCCESS;
}

static int ctsql_dump_row(ctconn_stmt_t stmt, dumper_t *dumper)
{
    uint32 i;

    if (dumper->col_num == 0) {
        CTSQL_PRINTF(ZSERR_DUMP, "assert raised, expect: dumper->col_num(%u) > 0", dumper->col_num);
        return CTCONN_ERROR;
    }

    for (i = 0; i < dumper->col_num; i++) {
        if (i != 0) {
            CTSQL_DUMP_RETURN_IF_CLI_ERROR(ctsql_dump_write_str(dumper, dumper->column_param.field_terminal,
                                                   dumper->column_param.field_terminal_len, CT_FALSE));
        }

        if (ctsql_dump_column_data(stmt, dumper, i) != CTCONN_SUCCESS) {
            return CTCONN_ERROR;
        }
    }
    CTSQL_DUMP_RETURN_IF_CLI_ERROR(ctsql_dump_write_str(dumper, dumper->column_param.line_terminal,
                                           dumper->column_param.line_terminal_len, CT_TRUE));
    return CTCONN_SUCCESS;
}

static int ctsql_dump_column_desc(dumper_t *dumper, ctconn_stmt_t stmt)
{
    uint32 i;

    if (ctconn_get_stmt_attr(STMT, CTCONN_ATTR_COLUMN_COUNT, &dumper->col_num, sizeof(uint32), NULL) != CTCONN_SUCCESS) {
        ctsql_print_error(CONN);
        return CTCONN_ERROR;
    }

    for (i = 0; i < dumper->col_num; i++) {
        if (ctconn_desc_inner_column_by_id(stmt, i, &dumper->col_desc[i]) != CTCONN_SUCCESS) {
            ctsql_print_error(CONN);
            return CTCONN_ERROR;
        }
    }

    return CTCONN_SUCCESS;
}

static status_t ctsql_dump_new_file(dumper_t *dumper)
{
    char filename[CT_MAX_FILE_PATH_LENGH];
    int iret_sprintf = 0;
    crypt_file_t *encrypt_ctx = NULL;
    char encrypt_filename[CT_MAX_NAME_LEN] = { 0 };

    if (dumper->file_idx < 0) {  // first file.
        CT_RETURN_IFERR(cm_create_file(dumper->dump_file, O_RDWR | O_TRUNC | O_BINARY | O_CREAT, &(dumper->file)));

        (void)cm_chmod_file(FILE_PERM_OF_DATA, dumper->file);
        if (g_dump_opt.crypt_info.crypt_flag) {
            CT_RETURN_IFERR(cm_list_new(&g_dump_opt.crypt_info.crypt_list, (void *)&encrypt_ctx));
            CT_RETURN_IFERR(ctsql_encrypt_prepare(&encrypt_ctx->crypt_ctx, g_dump_opt.crypt_info.crypt_pwd));
            cm_trim_dir(dumper->dump_file, CT_MAX_NAME_LEN, encrypt_filename);
            MEMS_RETURN_IFERR(strncpy_s(encrypt_ctx->filename, CT_MAX_NAME_LEN, encrypt_filename, CT_MAX_NAME_LEN - 1));
            encrypt_ctx->fp = dumper->file;
        }
        dumper->file_size = 0;
        dumper->file_idx = 0;
        dumper->file_end = CT_FALSE;
    } else {
        cm_close_file(dumper->file);
        dumper->file = -1;
        dumper->file_idx++;

        iret_sprintf = sprintf_s(filename, CT_MAX_FILE_PATH_LENGH, "%s_%d", dumper->dump_file, dumper->file_idx);
        if (iret_sprintf == -1) {
            CT_THROW_ERROR(ERR_SYSTEM_CALL, iret_sprintf);
            return CT_ERROR;
        }

        CT_RETURN_IFERR(cm_create_file(filename, O_RDWR | O_TRUNC | O_BINARY | O_CREAT, &(dumper->file)));

        (void)cm_chmod_file(FILE_PERM_OF_DATA, dumper->file);

        if (g_dump_opt.crypt_info.crypt_flag) {
            CT_RETURN_IFERR(cm_list_new(&g_dump_opt.crypt_info.crypt_list, (void *)&encrypt_ctx));
            CT_RETURN_IFERR(ctsql_encrypt_prepare(&encrypt_ctx->crypt_ctx, g_dump_opt.crypt_info.crypt_pwd));
            cm_trim_dir(encrypt_filename, CT_MAX_NAME_LEN, (char *)filename);
            MEMS_RETURN_IFERR(strncpy_s(encrypt_ctx->filename, CT_MAX_NAME_LEN, filename, CT_MAX_NAME_LEN - 1));
            encrypt_ctx->fp = dumper->file;
        }

        dumper->file_size = 0;
        dumper->file_end = CT_FALSE;
    }
    return CT_SUCCESS;
}

static status_t ctsql_dump_write_file_core(dumper_t *dumper, char *write_str, bool32 row_end, uint32 len)
{
    CT_RETURN_IFERR(cm_write_file(dumper->file, write_str, len));

    // no need to split
    if (!NEED_SPLIT_FILE(&g_dump_opt)) {
        return CT_SUCCESS;
    }

    dumper->file_size += len;
    if (row_end && dumper->file_size >= g_dump_opt.file_size) {  // judge whether need to new file.
        dumper->file_end = CT_TRUE;
        dumper->file_size = 0;
    }

    return CT_SUCCESS;
}

static status_t ctsql_dump_encrypt_write_file(dumper_t *dumper, text_t *text, bool32 row_end, char *encrypt_buf)
{
    crypt_file_t *encrypt_file = NULL;

    CT_RETURN_IFERR(ctsql_get_encrypt_file(&g_dump_opt.crypt_info, &encrypt_file, dumper->file));
    CT_RETURN_IFERR(cm_encrypt_data_by_gcm(encrypt_file->crypt_ctx.gcm_ctx, encrypt_buf, text->str, text->len));
    CT_RETURN_IFERR(ctsql_dump_write_file_core(dumper, encrypt_buf, row_end, text->len));
    return CT_SUCCESS;
}

static status_t ctsql_dump_write_file(dumper_t *dumper, text_t *text, bool32 row_end)
{
    char *encrypt_buf = NULL;

    // print screen.
    if (cm_str_equal_ins(dumper->dump_file, "stdout")) {
        ctsql_printf("%.*s", text->len, text->str);
        return CTCONN_SUCCESS;
    }

    // need new a file.
    if (dumper->file_end) {
        CT_RETURN_IFERR(ctsql_dump_new_file(dumper));
    }

    if (g_dump_opt.crypt_info.crypt_flag) {
        encrypt_buf = (char *)malloc(SIZE_M(16));
        if (encrypt_buf == NULL) {
            ctsql_printf("can't allocate %u bytes for dump table\n", g_dump_opt.max_filebuf_size);
            return CTCONN_ERROR;
        }

        if (ctsql_dump_encrypt_write_file(dumper, text, row_end, encrypt_buf) != CT_SUCCESS) {
            CM_FREE_PTR(encrypt_buf);
            return CT_ERROR;
        }

        CM_FREE_PTR(encrypt_buf);
        return CT_SUCCESS;
    } else {
        return ctsql_dump_write_file_core(dumper, text->str, row_end, text->len);
    }
}

static status_t ctsql_dump_flush_file(dumper_t *dumper)
{
    text_t complete_row;
    complete_row.str = dumper->file_buf.txt.str;
    complete_row.len = dumper->file_buf.row_end_pos;

    if (dumper->file_buf.row_end_pos == 0) {
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(ctsql_dump_write_file(dumper, &complete_row, CT_TRUE));

    if (dumper->file_buf.row_end_pos < dumper->file_buf.txt.len) {
        MEMS_RETURN_IFERR(memmove_s(dumper->file_buf.txt.str, g_dump_opt.max_filebuf_size,
            dumper->file_buf.txt.str + dumper->file_buf.row_end_pos,
            dumper->file_buf.txt.len - dumper->file_buf.row_end_pos));
    }
    dumper->file_buf.txt.len -= dumper->file_buf.row_end_pos;
    dumper->file_buf.row_end_pos = 0;
    return CT_SUCCESS;
}

static status_t ctsql_dump_write_text(dumper_t *dumper, text_t *text, bool32 row_end)
{
    if (NEED_SPLIT_FILE(&g_dump_opt) && dumper->file_size + dumper->file_buf.row_end_pos >= g_dump_opt.file_size) {
        // buffer exceeds the specified file size and needs to be placed in disk
        CT_RETURN_IFERR(ctsql_dump_flush_file(dumper));
    }

    if (dumper->file_buf.txt.len + text->len <= g_dump_opt.max_filebuf_size) {
        cm_concat_text(&dumper->file_buf.txt, g_dump_opt.max_filebuf_size, text);
        if (row_end) {
            dumper->file_buf.row_end_pos = dumper->file_buf.txt.len;
        }
        return CT_SUCCESS;
    } else {
        if (dumper->file_buf.txt.len > 0) {
            if (dumper->file_buf.row_end_pos > 0) {
                /* have a complete row data in file buffer */
                CT_RETURN_IFERR(ctsql_dump_flush_file(dumper));
            } else { /* do not have a complete row data in file buffer */
                CT_RETURN_IFERR(ctsql_dump_write_file(dumper, &dumper->file_buf.txt, CT_FALSE));
                CM_TEXT_CLEAR(&dumper->file_buf.txt);
            }
            return ctsql_dump_write_text(dumper, text, row_end); /* continue to write fille buffer */
        } else {                                                /* text larger than file buffer */
            return ctsql_dump_write_file(dumper, text, row_end);
        }
    }
}

static status_t ctsql_dump_write_str(dumper_t *dumper, char *str, uint16 len, bool32 row_end)
{
    text_t txt = { .str = str, .len = len };
    return ctsql_dump_write_text(dumper, &txt, row_end);
}

static status_t ctsql_dump_rows(ctconn_stmt_t stmt, dumper_t *dumper)
{
    uint32 rows;

    if (ctsql_dump_column_desc(dumper, stmt) != CT_SUCCESS) {
        return CT_ERROR;
    }

    while (!CTSQL_CANCELING) {
        if (ctconn_fetch(STMT, &rows) != CT_SUCCESS) {
            ctsql_print_error(CONN);
            return CT_ERROR;
        }

        if (rows == 0) {
            break;
        }

        if (ctsql_dump_row(stmt, dumper) != CTCONN_SUCCESS) {
            return CT_ERROR;
        }
        dumper->dumped_rows++;

        if (dumper->dumped_rows % 5000 == 0) {  // print every 5000 lines
            ctsql_printf("%-llu rows dumped.\n", dumper->dumped_rows);
        }
    }

    if (CTSQL_CANCELING) {
        CT_THROW_ERROR(ERR_OPERATION_CANCELED);
        ctsql_print_error(NULL);
        return CTCONN_ERROR;
    }

    /* dump remain buffer to file */
    if (dumper->file_buf.txt.len > 0) {
        if (ctsql_dump_write_file(dumper, &dumper->file_buf.txt, CT_TRUE) != CT_SUCCESS) {
            ctsql_print_error(NULL);
            return CTCONN_ERROR;
        }
        ctsql_printf("%-llu rows dumped.\n", dumper->dumped_rows);
    }

    ctsql_printf("\nDump %s successfully:\n", (dumper->type == DUMP_TABLE) ? "TABLE" : "QUERY");
    ctsql_printf("  %-llu rows are totally dumped.\n\n", dumper->dumped_rows);
    return CT_SUCCESS;
}

static inline void ctsql_free_dumper_file_buf(dumper_t *dumper)
{
    free(dumper->file_buf.buffer);
    dumper->file_buf.buffer = NULL;
    dumper->file_buf.txt.str = NULL;
    dumper->file_buf.txt.len = 0;
    dumper->file_buf.row_end_pos = 0;
}

static inline void ctsql_free_dumper(dumper_t *dumper)
{
    char *filename = dumper->dump_file;
    ctsql_encrypt_end(&g_dump_opt.crypt_info, filename);
    ctsql_free_dumper_file_buf(dumper);

    free(dumper->conver_buf);
    dumper->conver_buf = NULL;

    cm_close_file(dumper->file);
}

static status_t ctsql_alloc_dumper_file_buf(dumper_t *dumper)
{
    dumper->file_buf.buffer = (char *)malloc(g_dump_opt.max_filebuf_size + 1);
    if (dumper->file_buf.buffer == NULL) {
        ctsql_printf("can't allocate %u bytes for dump table\n", g_dump_opt.max_filebuf_size);
        return CTCONN_ERROR;
    }
    dumper->file_buf.txt.str = dumper->file_buf.buffer;
    dumper->file_buf.txt.len = 0;
    dumper->file_buf.row_end_pos = 0;
    return CTCONN_SUCCESS;
}

static status_t ctsql_alloc_dumper(dumper_t *dumper)
{
    CT_RETURN_IFERR(ctsql_alloc_dumper_file_buf(dumper));

    dumper->conver_buf = (char *)malloc(MAX_DUMP_CONVERT_SIZE + 1);
    if (dumper->conver_buf == NULL) {
        ctsql_printf("can't allocate %u bytes for data conversion.\n", MAX_DUMP_CONVERT_SIZE);
        ctsql_free_dumper_file_buf(dumper);
        return CTCONN_ERROR;
    }

    return CTCONN_SUCCESS;
}

static status_t ctsql_dump_query(dumper_t *dumper)
{
    status_t status;

    if (!IS_CONN) {
        (void)ctsql_print_disconn_error();
        return CT_ERROR;
    }

    if (ctconn_prepare(STMT, g_dump_opt.query_sql) != CT_SUCCESS) {
        ctsql_print_error(CONN);
        return CT_ERROR;
    }

    /* Set the charset based on the charset parameter of dump cmd */
    if (ctsql_reset_charset(g_dump_opt.charset_id, g_local_config.charset_id) != CT_SUCCESS) {
        ctsql_print_error(CONN);
        return CT_ERROR;
    }

    if (ctconn_execute(STMT) != CT_SUCCESS) {
        ctsql_print_error(CONN);
        return CT_ERROR;
    }

    if (ctsql_alloc_dumper(dumper) != CT_SUCCESS) {
        return CT_ERROR;
    }

    status = ctsql_dump_rows(STMT, dumper);
    ctsql_free_dumper(dumper);
    
    /* Restore CTSQL Client Character Set */
    if (ctsql_reset_charset(g_local_config.charset_id, g_dump_opt.charset_id) != CT_SUCCESS) {
        ctsql_print_error(CONN);
        return CT_ERROR;
    }
    return status;
}

void ctsql_init_dumper(dumper_t *dumper)
{
#ifdef USE_CTSQL_COLUMN_DESC
    dumper->col_desc = g_columns;
#endif
    dumper->dumped_rows = 0;

    dumper->file = -1;
    dumper->file_idx = -1;
    dumper->file_size = 0;
    dumper->file_end = CT_TRUE;
    dumper->column_param.enclosed_char = g_dump_opt.fields_enclosed;
    dumper->column_param.field_terminal = g_dump_opt.fields_terminated;
    dumper->column_param.line_terminal = g_dump_opt.lines_terminated;
    dumper->column_param.field_terminal_len = ((uint32)strlen(g_dump_opt.fields_terminated) == 0 ?
                                               1 : (uint32)strlen(g_dump_opt.fields_terminated));
    dumper->column_param.line_terminal_len = ((uint32)strlen(g_dump_opt.lines_terminated) == 0 ?
                                              1 : (uint32)strlen(g_dump_opt.lines_terminated));
}

void ctsql_show_dumper_usage(void)
{
    ctsql_printf("The syntax of data dumper is: \n");
    ctsql_printf("DUMP {TABLE table_name | QUERY \"select_query\"}\n");
    ctsql_printf("    INTO FILE \"file_name\"\n");
    ctsql_printf("    [FILE SIZE 'uint64_file_size']\n");
    ctsql_printf("    [{FIELDS | COLUMNS} ENCLOSED BY 'ascii_char' [OPTIONALLY]]\n");
    ctsql_printf("    [{FIELDS | COLUMNS} TERMINATED BY 'string']\n");
    ctsql_printf("    [{LINES | ROWS} TERMINATED BY 'string']\n");
    ctsql_printf("    [CHARSET string]\n");
    ctsql_printf("    [ENCRYPT BY 'password'];\n");
    ctsql_printf("\n");
}

void ctsql_show_dumper_opts(dumper_t dumper)
{
    ctsql_printf("The global options for data dumper is: \n");
    if (CTSQL_HAS_ENCLOSED_CHAR(dumper.column_param.enclosed_char)) {
        if (g_dump_opt.enclosed_optionally) {
            ctsql_printf("    fields optionally enclosed char: '%s'\n",
                        C2V(dumper.column_param.enclosed_char));
        } else {
            ctsql_printf("    fields enclosed char: '%s'\n", C2V(dumper.column_param.enclosed_char));
        }
    }

    ctsql_printf("    fields terminated string: '");
    for (uint32 i = 0; i < dumper.column_param.field_terminal_len; i++) {
        ctsql_printf("%s", C2V(dumper.column_param.field_terminal[i]));
    }
    ctsql_printf("'\n");

    ctsql_printf("    lines terminated string: '");
    for (uint32 i = 0; i < dumper.column_param.line_terminal_len; i++) {
        ctsql_printf("%s", C2V(dumper.column_param.line_terminal[i]));
    }
    ctsql_printf("'\n");
    ctsql_printf("    maximal file buffer size: %u bytes\n", g_dump_opt.max_filebuf_size);
    ctsql_printf("    file size: %llu bytes\n", g_dump_opt.file_size);
    ctsql_printf("    current charset : %s\n",
                (char *)cm_get_charset_name((charset_type_t)g_dump_opt.charset_id));
    ctsql_printf("\n");
}

/**
* Syntax: [TABLE schema.table_name]|[QUERY "select_query"]
*/
static inline int ctsql_parse_dumping_object(lex_t *lex, dumper_t *dumper)
{
    uint32 matched_id;
    word_t word;
    char table[MAX_ENTITY_LEN + 1];
    text_buf_t tbl_name_buf;

    tbl_name_buf.max_size = MAX_ENTITY_LEN;
    tbl_name_buf.str = table;
    tbl_name_buf.len = 0;

    // The object can be a query or a table
    if (lex_expected_fetch_1of2(lex, "TABLE", "QUERY", &matched_id) != CT_SUCCESS) {
        return CTCONN_ERROR;
    }

    if (matched_id == 0) {
        dumper->type = DUMP_TABLE;
        if (lex_expected_fetch_tblname(lex, &word, &tbl_name_buf) != CT_SUCCESS) {
            return CTCONN_ERROR;
        }
        CM_NULL_TERM(&tbl_name_buf);

        PRTS_RETURN_IFERR(snprintf_s(g_dump_opt.query_sql, MAX_DUMP_SQL_SIZE, MAX_DUMP_SQL_SIZE - 1,
            "select * from %s", table));
    } else {
        text_t first;
        dumper->type = DUMP_QUERY;
        // the query must be enclosed by ""
        if (lex_expected_fetch_dqstring(lex, &word) != CT_SUCCESS) {
            return CTCONN_ERROR;
        }
        cm_trim_text(&word.text.value);
        CT_RETURN_IFERR(cm_text2str(&word.text.value, g_dump_opt.query_sql, MAX_DUMP_SQL_SIZE));

        // verify query
        (void)cm_fetch_text(&word.text.value, ' ', '\0', &first);
        if (!cm_text_str_equal_ins(&first, "SELECT")) {
            CTSQL_PRINTF(ZSERR_DUMP, "the query must be a SELECT statement");
            return CTCONN_ERROR;
        }
    }

    return CTCONN_SUCCESS;
}

/**
 * Syntax: INTO FILE 'file_path'
 */
static inline int ctsql_parse_dumping_file(lex_t *lex, dumper_t *dumper)
{
    word_t word;

    if (lex_expected_fetch_word2(lex, "INTO", "FILE") != CT_SUCCESS) {
        return CTCONN_ERROR;
    }
    if (lex_expected_fetch_enclosed_string(lex, &word) != CT_SUCCESS) {
        return CTCONN_ERROR;
    }

    return cm_text2str(&word.text.value, dumper->dump_file, CT_MAX_FILE_PATH_LENGH);
}

#define DOPT_FIELDS_ENCLOSED   0
#define DOPT_FIELDS_TERMINATED 10
#define DOPT_LINES_TERMINATED  20
#define DOPT_FILE_SIZE         30
#define DOPT_CHARSET           40
#define DOPT_ENCRYPT           50

/**
* Syntax: [ENCLOSE BY 'char']|[FIELDS TERMINATED 'char']|[LINES TERMINATED 'char']
*/
int ctsql_parse_dumping_options(lex_t *lex, dumper_t *dumper, dump_option_t *dump_opt)
{
    static const word_record_t opt_records[] = {
        { .id = DOPT_FIELDS_ENCLOSED,   .tuple = { 3, { "fields", "enclosed", "by" } } },
        { .id = DOPT_FIELDS_ENCLOSED,   .tuple = { 3, { "columns", "enclosed", "by" } } },
        { .id = DOPT_FIELDS_TERMINATED, .tuple = { 3, { "fields", "terminated", "by" } } },
        { .id = DOPT_FIELDS_TERMINATED, .tuple = { 3, { "columns", "terminated", "by" } } },
        { .id = DOPT_LINES_TERMINATED,  .tuple = { 3, { "lines", "terminated", "by" } } },
        { .id = DOPT_LINES_TERMINATED,  .tuple = { 3, { "rows", "terminated", "by" } } },
        { .id = DOPT_FILE_SIZE,         .tuple = { 2, { "file", "size" } } },
        { .id = DOPT_CHARSET,           .tuple = { 1, { "charset" } } },
        { .id = DOPT_ENCRYPT,           .tuple = { 2, { "encrypt", "by" } } },
    };
#define DP_OPT_SIZE (sizeof(opt_records) / sizeof(word_record_t))

    uint32 matched_id;
    char opt_char;
    char terminate_str[TERMINATED_STR_ARRAY_SIZE] = { 0 };
    status_t ret;
    char *key_word_info = NULL;
    bool32 equal_flag = CT_TRUE;

    do {
        if (lex_try_match_records(lex, opt_records, DP_OPT_SIZE, &matched_id) != CT_SUCCESS) {
            return CTCONN_ERROR;
        }

        switch (matched_id) {
            case DOPT_FIELDS_ENCLOSED:
                ret = lex_expected_fetch_asciichar(lex, &opt_char, CT_TRUE);
                CT_RETVALUE_IFTRUE(ret != CT_SUCCESS, CTCONN_ERROR);
                dump_opt->fields_enclosed = opt_char;
                ret = lex_try_fetch(lex, "OPTIONALLY", &dump_opt->enclosed_optionally);
                CT_RETVALUE_IFTRUE(ret != CT_SUCCESS, CTCONN_ERROR);
                break;

            case DOPT_FIELDS_TERMINATED:
                key_word_info = "Column terminated string";
                ret = lex_expected_fetch_str(lex, terminate_str, sizeof(terminate_str) / sizeof(char) - 1,
                                             key_word_info);
                CT_RETVALUE_IFTRUE(ret != CT_SUCCESS, CTCONN_ERROR);
                MEMS_RETURN_IFERR(strncpy_s(dump_opt->fields_terminated, TERMINATED_STR_ARRAY_SIZE, terminate_str,
                                            TERMINATED_STR_ARRAY_SIZE - 1));
                break;

            case DOPT_LINES_TERMINATED:
                key_word_info = "Line terminated string";
                ret = lex_expected_fetch_str(lex, terminate_str, sizeof(terminate_str) / sizeof(char) - 1,
                                             key_word_info);
                CT_RETVALUE_IFTRUE(ret != CT_SUCCESS, CTCONN_ERROR);
                MEMS_RETURN_IFERR(strncpy_s(dump_opt->lines_terminated, TERMINATED_STR_ARRAY_SIZE, terminate_str,
                                            TERMINATED_STR_ARRAY_SIZE - 1));
                break;

            case DOPT_FILE_SIZE: {
                word_t word;
                text_t text;
                int64 file_size = 0;
                ret = lex_expected_fetch_enclosed_string(lex, &word);
                CT_RETVALUE_IFTRUE(ret != CT_SUCCESS, CTCONN_ERROR);
                text.str = word.text.str;
                text.len = word.text.len;
                cm_trim_text(&text);
                if (cm_text2size(&text, &file_size) != CT_SUCCESS || file_size < 0) {
                    CT_SRC_THROW_ERROR(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "invalid file size value!");
                    return CTCONN_ERROR;
                }
                dump_opt->file_size = (uint64)file_size;
                break;
            }

            case DOPT_CHARSET: {
                CT_RETURN_IFERR(lex_try_fetch(lex, "=", &equal_flag));
                ret = lex_expected_fetch_1of2(lex, "UTF8", "GBK", &matched_id);
                CT_RETVALUE_IFTRUE(ret != CT_SUCCESS, CTCONN_ERROR);
                dump_opt->charset_id = (matched_id == 0) ? CHARSET_UTF8 : CHARSET_GBK;
                break;
            }

            case DOPT_ENCRYPT: {
                key_word_info = "Encrypt pwd string";
                CT_RETURN_IFERR(ctsql_get_crypt_pwd(lex, dump_opt->crypt_info.crypt_pwd, CT_PASSWD_MAX_LEN + 1, key_word_info));
                if (ctsql_gen_encrypt_hash(&dump_opt->crypt_info) != CT_SUCCESS) {
                    CTSQL_PRINTF(ZSERR_DUMP, "the encrypt pwd is not correct");
                    return CTCONN_ERROR;
                }
                dump_opt->crypt_info.crypt_flag = CT_TRUE;
                break;
            }

            default:
                if (strcmp(dump_opt->fields_terminated, dump_opt->lines_terminated) == 0) {
                    CT_SRC_THROW_ERROR(LEX_LOC, ERR_SQL_SYNTAX_ERROR,
                                       "fields terminated string is the same to line terminated!");
                    return CTCONN_ERROR;
                }

                if (strlen(dump_opt->lines_terminated) > 1 &&
                    CM_STR_BEGIN_WITH(dump_opt->fields_terminated, dump_opt->lines_terminated)) {
                    CT_SRC_THROW_ERROR(LEX_LOC, ERR_SQL_SYNTAX_ERROR,
                                       "fields terminated and line terminated are inclusive relationships!");
                    return CTCONN_ERROR;
                }

                if (strlen(dump_opt->fields_terminated) > 1 &&
                    CM_STR_BEGIN_WITH(dump_opt->lines_terminated, dump_opt->fields_terminated)) {
                    CT_SRC_THROW_ERROR(LEX_LOC, ERR_SQL_SYNTAX_ERROR,
                                       "line terminated and fields terminated are inclusive relationships!");
                    return CTCONN_ERROR;
                }

                dumper->column_param.enclosed_char = g_dump_opt.fields_enclosed;
                dumper->column_param.field_terminal = g_dump_opt.fields_terminated;
                dumper->column_param.line_terminal = g_dump_opt.lines_terminated;
                dumper->column_param.field_terminal_len = ((uint32)strlen(g_dump_opt.fields_terminated) == 0 ?
                                                           1 : (uint32)strlen(g_dump_opt.fields_terminated));
                dumper->column_param.line_terminal_len = ((uint32)strlen(g_dump_opt.lines_terminated) == 0 ?
                                                          1 : (uint32)strlen(g_dump_opt.lines_terminated));
                return CTCONN_SUCCESS;
        }
    } while (CT_TRUE);

    return CTCONN_SUCCESS;
}

static int ctsql_parse_dumper(lex_t *lex, dumper_t *dumper)
{
    if (ctsql_parse_dumping_object(lex, dumper) != CTCONN_SUCCESS) {
        return CTCONN_ERROR;
    }

    if (ctsql_parse_dumping_file(lex, dumper) != CTCONN_SUCCESS) {
        return CTCONN_ERROR;
    }

    if (ctsql_parse_dumping_options(lex, dumper, &g_dump_opt) != CTCONN_SUCCESS) {
        return CTCONN_ERROR;
    }

    return (lex_expected_end(lex) == CT_SUCCESS) ? CTCONN_SUCCESS : CTCONN_ERROR;
}

/* init some options before loading */
static inline int ctsql_reset_dumper_opts(void)
{
    errno_t errcode;
    g_dump_opt.enclosed_optionally = CT_FALSE;
    g_dump_opt.fields_enclosed = CTSQL_DEFAULT_ENCLOSED_CHAR;
    errcode = strncpy_s(g_dump_opt.fields_terminated, sizeof(g_dump_opt.fields_terminated),
                        CTSQL_DEFAULT_FIELD_SEPARATOR_STR, strlen(CTSQL_DEFAULT_FIELD_SEPARATOR_STR));
    if (errcode != EOK) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
        return CTCONN_ERROR;
    }

    errcode = strncpy_s(g_dump_opt.lines_terminated, sizeof(g_dump_opt.lines_terminated),
                        CTSQL_DEFAULT_LINE_SEPARATOR_STR, strlen(CTSQL_DEFAULT_LINE_SEPARATOR_STR));
    if (errcode != EOK) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
        return CTCONN_ERROR;
    }
    g_dump_opt.max_filebuf_size = MAX_DUMP_FILE_BUF_SIZE;
    g_dump_opt.write_mode = CT_FALSE;
    g_dump_opt.file_size = 0;  // default 0, don't split file
    g_dump_opt.charset_id = CT_DEFAULT_LOCAL_CHARSET;
    MEMS_RETURN_IFERR(memset_s(g_dump_opt.query_sql, MAX_DUMP_SQL_SIZE, 0, MAX_DUMP_SQL_SIZE));

    ctsql_reset_crypt_info(&g_dump_opt.crypt_info);

    return CTCONN_SUCCESS;
}

status_t ctsql_dump(text_t *cmd_text)
{
    uint32 matched_id;
    dumper_t dumper;
    lex_t lex;
    sql_text_t sql_text;
    sql_text.value = *cmd_text;
    sql_text.loc.line = 1;
    sql_text.loc.column = 1;

    ctsql_init_dumper(&dumper);

    lex_trim(&sql_text);
    lex_init(&lex, &sql_text);

    if (lex_expected_fetch_word(&lex, "DUMP") != CT_SUCCESS) {
        ctsql_print_error(NULL);
        return CT_ERROR;
    }

    if (lex_try_fetch_1ofn(&lex, &matched_id, 6, "-h", "-help", "help", "-u", "-usage", "usage") != CT_SUCCESS) {
        ctsql_print_error(NULL);
        return CT_ERROR;
    }
    if (matched_id != CT_INVALID_ID32) {
        ctsql_show_dumper_usage();
        return CT_ERROR;
    }

    if (lex_try_fetch_1of3(&lex, "-o", "-option", "option", &matched_id) != CT_SUCCESS) {
        ctsql_print_error(NULL);
        return CT_ERROR;
    }
    if (matched_id != CT_INVALID_ID32) {
        ctsql_show_dumper_opts(dumper);
        return CT_ERROR;
    }

    if (ctsql_reset_dumper_opts() != CTCONN_SUCCESS) {
        return CT_ERROR;
    }

    if (ctsql_parse_dumper(&lex, &dumper) != CT_SUCCESS) {
        ctsql_print_error(NULL);
        return CT_ERROR;
    }

    return ctsql_dump_query(&dumper);
}

