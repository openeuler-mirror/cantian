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
 * ctsql_load.c
 *
 *
 * IDENTIFICATION
 * src/utils/ctsql/ctsql_load.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_base.h"
#include "cm_thread.h"
#include "ctsql_load.h"
#include "cm_lex.h"
#include "cm_chan.h"
#include "cm_signal.h"
#include "cm_log.h"
#include "cm_utils.h"
#include "cm_memory.h"

#ifdef WIN32
#include <windows.h>
#include <stdio.h>
#endif
#include "ctsql_common.h"
#include "cm_queue.h"

char g_load_pswd[CT_PASSWORD_BUFFER_SIZE + 4];

typedef enum {
    LOADER_READ_ERR = -1,
    LOADER_READ_END = 0,
    LOADER_READ_OK = 1,
} EN_LOADER_READ_STATUS;

#define RAW_BUF_SIZE            SIZE_M(1)
#define LOAD_MAXALLOCSIZE       (0x3fffffff) /* 1 gigabyte - 1 */
#define MAX_LOAD_SQL_SIZE       SIZE_K(64)
#define MAX_TRUNCATED_FIELD_LEN 20u
#define MAX_CHAN_BLOCK_CNT      5
#define MAX_LOAD_PRINT_TEXT_LEN 10
#define WAIT_WORKER_THREAD_TIME 20000
#define MAX_LOAD_LOB_BATCH_CNT  SIZE_K(8)

/* include escape and enclosed */
#define MAX_LOAD_COLUMN_LEN(type) (uint64)(CTSQL_IS_LOB_TYPE(type) ? ((uint64)8192 * 1048576 + 2) : ((uint64)SIZE_K(16) + 2))

#define CURRENT_FILE_ROW(worker) ((worker)->start_line + (worker)->locat_info.curr_line_in_block)

#define GET_IND_PTR(loader, row, col) (loader)->col_ind[(col)] + (row);

#define LOAD_TYPE_NEED_PUT_SPACE(type) \
    (CTSQL_IS_STRING_TYPE_EX(type) || \
    CTSQL_IS_BINARY_TYPE_EX(type) || \
    CTSQL_IS_LOB_TYPE(type))

#define LOAD_RESET_COLUMN_CTX(ctx)                \
    do {                                          \
        (ctx)->col_id = 0;                        \
        (ctx)->is_first_chunk = CT_TRUE;          \
        (ctx)->is_enclosed = CT_FALSE;            \
        (ctx)->is_enclosed_begin = CT_FALSE;      \
        (ctx)->loaded_length = 0;                 \
        (ctx)->lob_writed_length = 0;             \
        (ctx)->field_terminal_matched_cnt = 0;    \
        (ctx)->line_terminal_matched_cnt = 0;     \
        (ctx)->reach_column_end = CT_FALSE;       \
        (ctx)->reach_line_end = CT_FALSE;         \
        (ctx)->need_skip_current_line = CT_FALSE; \
        (ctx)->fatal_error = CT_FALSE;            \
    } while (0)

/* make sure first block is full , set current_line_ctx.reach_line_end = CT_TRUE */
#define LOAD_RESET_BLOCK_CTX(ctx)                              \
    do {                                                       \
        (ctx)->is_complete_row = CT_FALSE;                     \
        (ctx)->current_line_ctx.is_enclosed = CT_FALSE;        \
        (ctx)->current_line_ctx.reach_line_end = CT_TRUE;      \
        (ctx)->current_line_ctx.line_terminal_matched_cnt = 0; \
        (ctx)->next_line_ctx.is_enclosed = CT_FALSE;           \
        (ctx)->next_line_ctx.reach_line_end = CT_FALSE;        \
        (ctx)->next_line_ctx.line_terminal_matched_cnt = 0;    \
    } while (0)

#define LOAD_RESET_LINE_CTX(ctx)              \
    do {                                      \
        (ctx)->is_enclosed = CT_FALSE;        \
        (ctx)->reach_line_end = CT_FALSE;     \
        (ctx)->line_terminal_matched_cnt = 0; \
    } while (0)

#define LOAD_TRY_RESET_LINE_CTX(ctx) \
    if ((ctx)->reach_line_end) {     \
        LOAD_RESET_LINE_CTX(ctx);    \
    }

#define LOADER_DEFAULT_THREADS 1

#define CTSQL_LOAD_DEBUG(fmt, ...)        \
    if (g_load_opts.debug_on) {          \
        ctsql_printf(fmt, ##__VA_ARGS__); \
        ctsql_printf("\n");               \
    }

#define LOAD_LOCAT_INFO_INC(worker)                 \
    do {                                           \
        (worker)->locat_info.read_rows++;          \
        (worker)->locat_info.curr_line_in_block++; \
    } while (0)

#define LOAD_OCCUR_ERROR(loader) (!ctsql_if_all_workers_ok(loader) || ctsql_if_reach_allowed_errors(loader))
#define LOAD_SERIAL (g_load_opts.threads == 1)

typedef struct loader_string_t {
    char *data;
    uint64 len;
    uint64 maxlen;
} loader_string_t;

typedef loader_string_t *loader_string_ptr_t;

typedef struct st_load_option {
    bool32 enclosed_optionally;
    char fields_enclosed;
    char fields_terminated[TERMINATED_STR_ARRAY_SIZE];
    char fields_escape;
    char lines_terminated[TERMINATED_STR_ARRAY_SIZE];
    char trailing_columns[MAX_LOAD_SQL_SIZE];
    list_t obj_list; /* list of column names to load data which you need */
    char set_columns[MAX_LOAD_SQL_SIZE];
    uint64 ignore_lines;
    uint32 max_databuf_size;
    uint32 max_filebuf_size;
    uint32 auto_commit_rows;
    uint32 charset_id;
    uint32 threads;
    uint32 allowed_batch_errs;
    bool32 nologging;
    bool8 debug_on;
    bool8 null2space;
    bool8 replace;
    bool8 convert_jsonb;  /* it shows that input-json-data is clob or string */
    bool8 ignore;
    bool8 set_flag;
    bool8 is_case_insensitive;
    crypt_info_t crypt_info;
} load_option_t;

/** The default options for loading data */
static load_option_t g_load_opts = {
    .enclosed_optionally = CT_FALSE,
    .fields_enclosed = CTSQL_DEFAULT_ENCLOSED_CHAR,
    .fields_terminated = CTSQL_DEFAULT_FIELD_SEPARATOR_STR,
    .fields_escape = '\\',
    .lines_terminated = CTSQL_DEFAULT_LINE_SEPARATOR_STR,
    .ignore_lines = 0,
    .max_databuf_size = SIZE_M(1),
    .max_filebuf_size = FILE_BUFFER_SIZE,
    .auto_commit_rows = CTSQL_AUTO_COMMIT,
    .charset_id = CT_DEFAULT_LOCAL_CHARSET,
    .threads = LOADER_DEFAULT_THREADS,
    .allowed_batch_errs = 0,
    .nologging = CT_FALSE,
    .debug_on = CT_FALSE,
    .null2space = CT_FALSE,
    .replace = CT_FALSE,
    .convert_jsonb = CT_FALSE,
    .ignore = CT_FALSE,
    .is_case_insensitive = CT_TRUE,
};

typedef enum {
    WORKER_STATUS_ERR = -1,
    WORKER_STATUS_INIT,
    WORKER_STATUS_RECV,
    WORKER_STATUS_LOAD,
    WORKER_STATUS_END,
} en_worker_status;

typedef enum {
    LOADER_STATUS_ERR = -1,  // load error
    LOADER_STATUS_OK
} en_loader_status;

typedef enum en_loader_EOL {
    LOADER_EOL_UNKNOWN,
    LOADER_EOL_NL,
    LOADER_EOL_CR,
    LOADER_EOL_CRNL
} en_loader_EOL;

typedef struct load_line_ctx {
    bool8 is_enclosed;    /* is between column enclosed char */
    bool8 reach_line_end; /* is a complete row */
    uint32 line_terminal_matched_cnt;
} load_line_ctx_t;

typedef struct load_block_ctx {
    bool8 is_complete_row;
    load_line_ctx_t current_line_ctx;
    load_line_ctx_t next_line_ctx;
} load_block_ctx_t;

typedef struct load_column_ctx {
    uint32 col_id;
    bool8 is_first_chunk;
    bool8 is_enclosed_begin;
    bool8 is_enclosed;
    uint32 field_terminal_matched_cnt;
    uint32 line_terminal_matched_cnt;
    uint64 loaded_length;         /* length of column in datafile include enclosed char. */
    uint64 lob_writed_length;     /* length of lob column write into ctconn. */
    bool8 reach_column_end;       /* is a complete column */
    bool8 reach_line_end;         /* reach line end. */
    bool8 need_skip_current_line; /* some column error , need skip curren line. */
    bool8 fatal_error;
    text_t column_data; /* store part column data */
} load_column_ctx_t;

typedef struct load_column_param {
    char enclosed_char;
    char *line_terminal;
    uint32 line_terminal_len;
    char *field_terminal;
    uint32 field_terminal_len;
} load_column_param_t;

typedef struct load_fetch_column {
    load_column_ctx_t *column_ctx;
    text_t column_txt;
} load_fetch_column_t;

typedef struct load_block {
    uint64 start_line;
    uint64 id;
    text_t buf;
} load_block_t;

typedef struct load_block_pool {
    char **buffer_list;
    uint32 idle_cnt;
    spinlock_t lock;
} load_block_pool_t;

typedef struct location_info {
    uint32 curr_row;  /* the current batching row, i.e., number of rows in loader */
    uint64 read_rows; /* count all rows */
    uint64 curr_line_in_block;
} location_info_t;

typedef struct {
    uint32 id; /* worker id */

    en_worker_status status;
    bool32 closed;

    chan_t *chan; /* channel used to recv data */
    load_block_t block;
    char *orig_block_buf;

    ctsql_conn_info_t conn_info; /* connection information */

    void *loader;

    char *table;
    uint16 *col_ind[CT_MAX_COLUMNS]; /* column indicators */
    void *col_data[CT_MAX_COLUMNS];  /* column data */
    char *col_data_buf;              /* the data buffer for all columns */
    uint16 max_batch_rows;           /* the maximal No. of rows in each batch */

    uint64 loaded_rows;             /* The successfully loaded rows to server */
    volatile uint64 committed_rows; /* The number of rows that have been committed into TABLE */
    uint64 error_rows;              /* The number of error rows in loader */
    uint32 allowed_batch_errs;      /* The number of allowed batch error rows in loader */
    uint32 actual_batch_errs;       /* The current number of batch error rows in loader */
    uint32 skip_rows;               /* The number of skip rows in loader */
    uint32 check_line_errs;         /* The number of line to check is error rows in loader */
    uint64 prev_loaded_rows;

    load_column_param_t *column_param;
    load_column_ctx_t column_ctx;
    location_info_t locat_info;
    uint64 start_line;
} worker_t;

typedef struct {
    en_loader_status status;
    chan_t **chan;
    thread_t *threads;
    worker_t *workers;

    fixed_memory_pool_t block_pool;
    load_column_param_t column_param;

    spinlock_t conn_lock; // control serial access to main connection.

    char load_file[CT_MAX_FILE_PATH_LENGH];
    FILE *fp;
    char table[MAX_ENTITY_LEN + 1];

    uint64 read_rows;
    uint64 committed_rows;
    uint64 loaded_rows;
    uint64 file_rows;
    uint64 ignored_lines;
    uint64 error_rows;
    uint32 allowed_batch_errs;
    uint32 actual_batch_errs;
    uint32 skip_rows;
    spinlock_t report_lock;

    char *raw_buf;
    uint64 raw_buf_len;
    uint64 raw_buf_index;
    bool8 eof;
    bool8 csv_mode;
    en_loader_EOL eol_type;

    uint64 start_line;
    loader_string_t line_buf;

    /* The shared information among all workers */
    ctconn_inner_column_desc_t *col_desc;
    char insert_sql[MAX_LOAD_SQL_SIZE];
    uint16 col_bndsz[CT_MAX_COLUMNS]; /* column binding size, it is times of 4 */
    uint16 col_bndtype[CT_MAX_COLUMNS];
    uint32 col_num;
    uint32 lob_col_num;
    uint32 row_size; /* the width of all columns in bytes */
    gcm_encrypt_t decrypt_ctx;
    FILE *encrypt_conf_fp;
    crypt_info_t crypt_info;
} loader_t;

#define GET_LOADER(worker) ((loader_t *)(worker)->loader)

static char *g_rand_local_key = NULL;
char *g_rand_factor_key = NULL;
char *g_cipher = NULL;
uint32 g_cipher_len;
char *g_current_user = NULL;
uint32 g_current_user_len = 0;

spinlock_t g_user_lock = 0;
spinlock_t g_pswd_lock = 0;

void loader_save_user(char *orig_user, uint32 orig_len)
{
    cm_spin_lock(&g_user_lock, NULL);

    do {
        if (g_current_user == NULL) {
            g_current_user = malloc(CT_NAME_BUFFER_SIZE * 2);
            CT_BREAK_IF_TRUE(g_current_user == NULL);
        }

        CT_BREAK_IF_TRUE(memset_s(g_current_user, CT_NAME_BUFFER_SIZE * 2, 0, CT_NAME_BUFFER_SIZE * 2) != EOK);

        CT_BREAK_IF_TRUE(orig_len > CT_NAME_BUFFER_SIZE + 4);

        CT_BREAK_IF_TRUE(memcpy_s(g_current_user, CT_NAME_BUFFER_SIZE * 2, orig_user, orig_len) != EOK);

        g_current_user_len = orig_len;
    } while (0);

    cm_spin_unlock(&g_user_lock);

    return;
}

status_t loader_save_pswd_do(char *orig_pswd, uint32 orig_len)
{
    if (g_rand_local_key == NULL) {
        g_rand_local_key = malloc(CT_MAX_LOCAL_KEY_STR_LEN_DOUBLE + 4);
        if (g_rand_local_key == NULL) {
            return CT_ERROR;
        }
        MEMS_RETURN_IFERR(memset_s(g_rand_local_key, CT_MAX_LOCAL_KEY_STR_LEN_DOUBLE + 4, 0,
                                   CT_MAX_LOCAL_KEY_STR_LEN_DOUBLE + 4));
    }

    if (g_rand_factor_key == NULL) {
        g_rand_factor_key = malloc(CT_MAX_FACTOR_KEY_STR_LEN + 4);
        if (g_rand_factor_key == NULL) {
            return CT_ERROR;
        }
        MEMS_RETURN_IFERR(memset_s(g_rand_factor_key, CT_MAX_FACTOR_KEY_STR_LEN + 4, 0,
                                   CT_MAX_FACTOR_KEY_STR_LEN + 4));
    }

    if (g_cipher == NULL) {
        g_cipher = malloc(CT_PASSWORD_BUFFER_SIZE * 2);
        if (g_cipher == NULL) {
            return CT_ERROR;
        }
    }

    if (orig_len > CT_PASSWORD_BUFFER_SIZE + 4) {
        return CT_ERROR;
    }

    if ((uint32)strlen(g_rand_factor_key) != CT_MAX_FACTOR_KEY_STR_LEN) {
        char rand_buf[CT_AES256KEYSIZE / 2 + 4];
        uint32 rand_len = CT_AES256KEYSIZE / 2;

        /* generate 128bit rand_buf and then base64 encode */
        CT_RETURN_IFERR(cm_rand((uchar *)rand_buf, rand_len));
        uint32 rand_factor_key_len = CT_MAX_FACTOR_KEY_STR_LEN + 4;
        CT_RETURN_IFERR(cm_base64_encode((uchar *)rand_buf, rand_len, g_rand_factor_key, &rand_factor_key_len));

        CT_RETURN_IFERR(cm_generate_work_key((const char *)g_rand_factor_key, g_rand_local_key, CT_MAX_LOCAL_KEY_STR_LEN_DOUBLE + 4));
    }
    
    if ((status_t)ctconn_encrypt_password(orig_pswd, orig_len, g_rand_local_key, g_rand_factor_key, g_cipher,
        &g_cipher_len) != CT_SUCCESS) {
        g_cipher_len = 0;
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t loader_save_pswd(char *orig_pswd, uint32 orig_len)
{
    cm_spin_lock(&g_pswd_lock, NULL);

    if (loader_save_pswd_do(orig_pswd, orig_len) != CT_SUCCESS) {
        CM_FREE_PTR(g_rand_local_key);
        CM_FREE_PTR(g_rand_factor_key);
        CM_FREE_PTR(g_cipher);
        cm_spin_unlock(&g_pswd_lock);
        return CT_ERROR;
    }

    cm_spin_unlock(&g_pswd_lock);

    return CT_SUCCESS;
}

status_t  ctsql_get_saved_pswd(char *pswd, uint32 len)
{
    cm_spin_lock(&g_pswd_lock, NULL);
    if ((status_t)ctconn_decrypt_password(pswd, len, g_rand_local_key, g_rand_factor_key, g_cipher,
        g_cipher_len) != CT_SUCCESS) {
        (void)memset_s(pswd, len, 0, len);
        cm_spin_unlock(&g_pswd_lock);
        return CT_ERROR;
    }
    cm_spin_unlock(&g_pswd_lock);
    return CT_SUCCESS;
}

void ctsql_get_saved_user(char *user, uint32 len)
{
    cm_spin_lock(&g_user_lock, NULL);
    errno_t errcode;

    if (user == NULL || len == 0 || g_current_user == NULL || g_current_user_len == 0) {
        cm_spin_unlock(&g_user_lock);
        return;
    }

    errcode = memset_s(user, len, 0, len);
    if (errcode == EOK) {
        errcode = memcpy_s(user, len, g_current_user, g_current_user_len);
    }
    if (errcode != EOK) {
        cm_spin_unlock(&g_user_lock);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return;
    }

    cm_spin_unlock(&g_user_lock);

    return;
}

void ctsql_free_user_pswd(void)
{
    if (g_current_user != NULL) {
        cm_spin_lock(&g_user_lock, NULL);
        CM_FREE_PTR(g_current_user);
        cm_spin_unlock(&g_user_lock);
    }
    
    cm_spin_lock(&g_pswd_lock, NULL);
    if (g_rand_local_key != NULL) {
        CM_FREE_PTR(g_rand_local_key);
    }

    if (g_rand_factor_key != NULL) {
        CM_FREE_PTR(g_rand_factor_key);
    }

    if (g_cipher != NULL) {
        CM_FREE_PTR(g_cipher);
    }
    cm_spin_unlock(&g_pswd_lock);
}

void ctsql_show_loader_usage(void)
{
    ctsql_printf("The syntax of data loader is: \n");
    ctsql_printf("LOAD DATA INFILE \"file_name\"\n");
    ctsql_printf("    INTO TABLE table_name\n");
    ctsql_printf("    [REPLACE | IGNORE]\n");
    ctsql_printf("    [{FIELDS | COLUMNS} ENCLOSED BY 'ascii_char' [OPTIONALLY]]\n");
    ctsql_printf("    [{FIELDS | COLUMNS} TERMINATED BY 'string']\n");
    ctsql_printf("    [{LINES | ROWS} TERMINATED BY 'string']\n");
    ctsql_printf("    [TRAILING COLUMNS(COLUMN1[, COLUMN2, ...])]\n");
    ctsql_printf("    [IGNORE uint64_num {LINES | ROWS}]\n");
    ctsql_printf("    [CHARSET string]\n");
    ctsql_printf("    [THREADS uint32_num]\n");
    ctsql_printf("    [ERRORS uint32_num]\n");
    ctsql_printf("    [NOLOGGING]\n");
    ctsql_printf("    [NULL2SPACE]\n");
    ctsql_printf("    [DECRYPT BY 'password']\n");
    ctsql_printf("    [SET col_name = expr,...];\n");
    ctsql_printf("\n");
}

void ctsql_show_loader_opts(void)
{
    uint16 fields_terminated_len = (strlen(g_load_opts.fields_terminated) == 0 ?
                                    1 : (uint16)strlen(g_load_opts.fields_terminated));
    uint16 lines_terminated_len = (strlen(g_load_opts.lines_terminated) == 0 ?
                                   1 : (uint16)strlen(g_load_opts.lines_terminated));

    ctsql_printf("The current options for data loading is: \n");
    if (CTSQL_HAS_ENCLOSED_CHAR(g_load_opts.fields_enclosed)) {
        if (g_load_opts.enclosed_optionally) {
            ctsql_printf("  fields optionally enclosed char: '%s'\n", C2V(g_load_opts.fields_enclosed));
        } else {
            ctsql_printf("      fields enclosed char: '%s'\n", C2V(g_load_opts.fields_enclosed));
        }
    }

    ctsql_printf("    fields terminated string: '");
    for (int i = 0; i < fields_terminated_len; i++) {
        ctsql_printf("%s", C2V(g_load_opts.fields_terminated[i]));
    }
    ctsql_printf("'\n");

    ctsql_printf("     lines terminated string: '");
    for (int i = 0; i < lines_terminated_len; i++) {
        ctsql_printf("%s", C2V(g_load_opts.lines_terminated[i]));
    }
    ctsql_printf("'\n");

    ctsql_printf("            ignoring lines: " PRINT_FMT_UINT64 "\n", g_load_opts.ignore_lines);
    ctsql_printf("  maximal data buffer size: %u bytes\n", g_load_opts.max_databuf_size);
    ctsql_printf("  maximal file buffer size: %u bytes\n", g_load_opts.max_filebuf_size);
    ctsql_printf("           current charset: %s\n",
                (char *)cm_get_charset_name((charset_type_t)g_load_opts.charset_id));
    ctsql_printf("         number of threads: %u\n", g_load_opts.threads);
    ctsql_printf("            allowed errors: %u\n", g_load_opts.allowed_batch_errs);
    ctsql_printf("                 nologging: %s\n", g_load_opts.nologging ? "on" : "off");
    if (ctconn_get_call_version(CONN) >= CS_VERSION_24) {
        ctsql_printf("          convert to jsonb: %s\n", g_load_opts.convert_jsonb ? "true" : "false");
    }
    ctsql_printf("\n");
}

void ctsql_load_report_current(loader_t *loader)
{
    cm_spin_lock(&loader->report_lock, NULL);
    {
        loader->committed_rows = 0;
        uint32 i = 0;

        for (i = 0; i < g_load_opts.threads; i++) {
            loader->committed_rows += loader->workers[i].committed_rows;
        }

        if (loader->committed_rows > 0) {
            ctsql_printf("%llu rows have been committed.\n", loader->committed_rows);
        }
    }
    cm_spin_unlock(&loader->report_lock);
}

void ctsql_load_report_summary(loader_t *loader)
{
    uint32 i = 0;

    loader->read_rows = 0;
    loader->loaded_rows = 0;
    loader->committed_rows = 0;
    loader->error_rows = 0;
    loader->skip_rows = 0;

    if (loader->status == LOADER_STATUS_OK) {
        ctsql_printf("\nComplete the data load.\n");
    } else {
        ctsql_printf("\nFailure happens and loading process is interrupted.\n");
    }

    for (i = 0; i < g_load_opts.threads; i++) {
        loader->read_rows += loader->workers[i].locat_info.read_rows;
        loader->loaded_rows += loader->workers[i].loaded_rows;
        loader->committed_rows += loader->workers[i].committed_rows;
        loader->error_rows += loader->workers[i].error_rows;
        loader->skip_rows += loader->workers[i].skip_rows;
    }

    ctsql_printf("totally read rows: %llu\n", loader->file_rows);
    ctsql_printf("     ignored rows: %llu\n", loader->ignored_lines);
    ctsql_printf("      loaded rows: %llu\n", loader->loaded_rows);
    ctsql_printf("   committed rows: %llu\n", loader->committed_rows);
    ctsql_printf("       error rows: %llu\n", loader->error_rows);
    ctsql_printf("        skip rows: %u\n", loader->skip_rows);
}

void ctsql_stop_workers(loader_t *loader)
{
    uint32 i = 0;

    for (i = 0; i < g_load_opts.threads; i++) {
        loader->workers[i].closed = CT_TRUE;
    }

    for (i = 0; i < g_load_opts.threads; i++) {
        cm_close_thread(&loader->threads[i]);
    }
}

/*
 * loader_init_string
 *
 * Initialize a loader_string_t struct to describe an empty string.
 */
status_t loader_init_linebuf(loader_string_ptr_t str)
{
    uint32 size = g_load_opts.max_filebuf_size;
    str->data = (char *)malloc(size);
    if (str->data == NULL) {
        return CT_ERROR;
    }
    str->maxlen = size;
    str->len = 0;
    return CT_SUCCESS;
}

void loader_free_string(loader_string_ptr_t str)
{
    if (str != NULL && str->data) {
        free(str->data);
        str->data = NULL;
        str->len = 0;
    }
}

/*
 * loader_append_linebuff
 *
 * Append file buffer data into line buffer
 *
 */
status_t loader_append_linebuff(loader_string_ptr_t str, const char *data, uint64 datalen, bool8 *reach_max_size)
{
    // check space is enough
    if (str->len + datalen > (uint64)g_load_opts.max_filebuf_size) {
        CTSQL_LOAD_DEBUG("[Loader-Thread] ensure more memory %llu exceeds max size %u, used size %llu.",
            datalen, g_load_opts.max_filebuf_size, str->len);
        *reach_max_size = CT_TRUE;
        return CT_ERROR;
    }

    /* OK, append the data */
    if (datalen != 0) {
        MEMS_RETURN_IFERR(memcpy_s(str->data + str->len, (size_t)(str->maxlen - str->len), data, (size_t)datalen));
    }
    str->len += datalen;

    return CT_SUCCESS;
}

static inline int ctsql_loader_prepare(loader_t *loader);

static int ctsql_loader_init_chan(loader_t *loader)
{
    loader->chan = (chan_t **)malloc(sizeof(chan_t *) * g_load_opts.threads);
    if (loader->chan == NULL) {
        CTSQL_PRINTF(ZSERR_LOAD, "out of memory, malloc chan");
        return CTCONN_ERROR;
    }

    for (uint32 i = 0; i < g_load_opts.threads; i++) {
        loader->chan[i] = cm_chan_new(MAX_CHAN_BLOCK_CNT, sizeof(load_block_t));
        if (loader->chan[i] == NULL) {
            for (uint32 j = 0; j < i; j++) {
                CM_FREE_PTR(loader->chan[j]->buf);
                CM_FREE_PTR(loader->chan[j]);
            }
            CM_FREE_PTR(loader->chan);
            CTSQL_PRINTF(ZSERR_LOAD, "create channel failed");
            return CTCONN_ERROR;
        }
    }
    return CTCONN_SUCCESS;
}

void ctsql_loader_free_file_buffer(loader_t *loader, char *buffer)
{
    /* BEGIN -->do buffer address check. */
    uint32 file_buff_size = g_load_opts.max_filebuf_size + 1;
    uint32 block_cnt = g_load_opts.threads * (MAX_CHAN_BLOCK_CNT + 3);

    /* END -->do buffer address check. */
    cm_spin_lock(&(loader->block_pool.lock), NULL);

    CTSQL_LOAD_DEBUG("[Memory Pool] free memory id : %u",
        (uint32)(buffer - (char *)loader->block_pool.buffer_list - sizeof(char *) * block_cnt) / file_buff_size);

    loader->block_pool.buffer_list[loader->block_pool.idle_cnt] = buffer;
    loader->block_pool.idle_cnt++;

    cm_spin_unlock(&(loader->block_pool.lock));
}

static status_t loader_init_thread_mem(loader_t *loader)
{
    loader->threads = (thread_t *)malloc(sizeof(thread_t) * g_load_opts.threads);
    if (loader->threads == NULL) {
        CTSQL_PRINTF(ZSERR_LOAD, "out of memory, malloc threads info");
        return CTCONN_ERROR;
    }

    MEMS_RETURN_IFERR(memset_s(loader->threads, sizeof(thread_t) * g_load_opts.threads, 0,
        sizeof(thread_t) * g_load_opts.threads));

    loader->workers = (worker_t *)malloc(sizeof(worker_t) * g_load_opts.threads);
    if (loader->workers == NULL) {
        CTSQL_PRINTF(ZSERR_LOAD, "out of memory, malloc workers info");
        return CTCONN_ERROR;
    }

    MEMS_RETURN_IFERR(memset_s(loader->workers, sizeof(worker_t) * g_load_opts.threads, 0,
        sizeof(worker_t) * g_load_opts.threads));

    return CT_SUCCESS;
}

static status_t loader_open_file(loader_t *loader, const char* path)
{
    loader->fp = fopen(path, "rb");

    if (loader->fp == NULL) {
        CTSQL_PRINTF(ZSERR_LOAD, "can not open file: %s", loader->load_file);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t loader_init_rawbuff(loader_t *loader)
{
    loader->raw_buf = (char *)malloc(RAW_BUF_SIZE + 1);
    if (loader->raw_buf == NULL) {
        CTSQL_PRINTF(ZSERR_LOAD, "Fail to allocate %u bytes for raw buffer", RAW_BUF_SIZE + 1);
        return CTCONN_ERROR;
    }

    MEMS_RETURN_IFERR(memset_s(loader->raw_buf, RAW_BUF_SIZE + 1, 0, RAW_BUF_SIZE + 1));

    loader->raw_buf_len = 0;
    loader->raw_buf_index = 0;
    return CT_SUCCESS;
}

static int ctsql_loader_init(loader_t *loader)
{
    char path[CT_FILE_NAME_BUFFER_SIZE] = { 0x00 };
    CT_RETURN_IFERR(realpath_file(loader->load_file, path, CT_FILE_NAME_BUFFER_SIZE));

    loader->conn_lock = 0;
    loader->loaded_rows = 0;
    loader->committed_rows = 0;
    loader->ignored_lines = 0;
    loader->read_rows = 0;
    loader->file_rows = 0;
    loader->error_rows = 0;
    loader->allowed_batch_errs = g_load_opts.allowed_batch_errs;
    loader->actual_batch_errs = 0;
    loader->skip_rows = 0;
    loader->status = LOADER_STATUS_OK;
    loader->report_lock = 0;
    loader->csv_mode = CT_TRUE;
    loader->eof = CT_FALSE;
    loader->column_param.enclosed_char = g_load_opts.fields_enclosed;
    loader->column_param.field_terminal = g_load_opts.fields_terminated;
    loader->column_param.line_terminal = g_load_opts.lines_terminated;
    loader->column_param.field_terminal_len = ((uint32)strlen(g_load_opts.fields_terminated) == 0 ?
        1 : (uint32)strlen(g_load_opts.fields_terminated));
    loader->column_param.line_terminal_len = ((uint32)strlen(g_load_opts.lines_terminated) == 0 ?
        1 : (uint32)strlen(g_load_opts.lines_terminated));

    if (ctsql_loader_init_chan(loader) != CTCONN_SUCCESS) {
        return CTCONN_ERROR;
    }

    // memory used in :
    // 1. in chan : MAX_CHAN_BLOCK_CNT
    // 2. in loader : 1
    // 3. in workter : 1
    // 4. store part column : 1
    if (ctconn_common_init_fixed_memory_pool(&loader->block_pool, (g_load_opts.max_filebuf_size + 1),
        g_load_opts.threads * (MAX_CHAN_BLOCK_CNT + 3)) != CTCONN_SUCCESS) {
        CTSQL_PRINTF(ZSERR_LOAD, "out of memory, malloc file buffer");
        return CTCONN_ERROR;
    }

    // init threads memory
    CT_RETURN_IFERR(loader_init_thread_mem(loader));

    // open file
    CT_RETURN_IFERR(loader_open_file(loader, path));
    CT_RETURN_IFERR(loader_init_rawbuff(loader));
    CT_RETURN_IFERR(loader_init_linebuf(&loader->line_buf));

    if (g_load_opts.crypt_info.crypt_flag) {
        if (ctsql_decrypt_prepare(&g_load_opts.crypt_info, path) != CT_SUCCESS) {
            CTSQL_PRINTF(ZSERR_LOAD, "Fail to parse %s or incorrect password", CTSQL_CRYPT_CFG_NAME);
            return CTCONN_ERROR;
        }

        CT_RETURN_IFERR(ctsql_set_encrpyt_fp(&g_load_opts.crypt_info, path, cm_fileno(loader->fp)));
    }

    return ctsql_loader_prepare(loader);
}

static void ctsql_loader_close_chan(loader_t *loader)
{
    for (uint32 i = 0; i < g_load_opts.threads; i++) {
        cm_chan_close(loader->chan[i]);
    }
}

static void ctsql_loader_free_chan(loader_t *loader)
{
    if (loader->chan != NULL) {
        for (uint32 i = 0; i < g_load_opts.threads; i++) {
            cm_chan_free(loader->chan[i]);
        }
        CM_FREE_PTR(loader->chan);
    }
}

static void ctsql_loader_free(loader_t *loader)
{
    ctsql_decrypt_end(&g_load_opts.crypt_info);

    ctsql_loader_free_chan(loader);

    if (loader->threads != NULL) {
        free(loader->threads);
        loader->threads = NULL;
    }

    if (loader->workers != NULL) {
        free(loader->workers);
        loader->workers = NULL;
    }

    if (loader->fp != NULL) {
        fclose(loader->fp);
    }

    if (loader->raw_buf != NULL) {
        free(loader->raw_buf);
        loader->raw_buf = NULL;
    }

    loader->raw_buf_len = 0;
    loader->raw_buf_index = 0;

    loader_free_string(&loader->line_buf);

    ctconn_common_uninit_fixed_memory_pool(&(loader->block_pool));
}

static status_t ctsql_loader_read_data(loader_t *loader, void *databuf, uint64 maxread, uint64 *datalen)
{
    int bytesread;
    char *decrypt_buf = NULL;
    crypt_file_t *decrypt_ctx = NULL;
    status_t ret;

    if (g_load_opts.crypt_info.crypt_flag) {
        CT_RETURN_IFERR(ctsql_get_encrypt_file(&g_load_opts.crypt_info, &decrypt_ctx, cm_fileno(loader->fp)));
        decrypt_buf = (char *)malloc(g_load_opts.max_filebuf_size);
        if (decrypt_buf == NULL) {
            ctsql_printf("can't allocate %u bytes for dump table\n", g_load_opts.max_filebuf_size);
            return CT_ERROR;
        }

        do {
            bytesread = (int)fread(decrypt_buf, 1, (size_t)maxread, loader->fp);
            if (ferror(loader->fp)) {
                CTSQL_PRINTF(ZSERR_LOAD, "reading data file");
                perror("The reason is ");
                ret = CT_ERROR;
                break;
            }

            ret = cm_decrypt_data_by_gcm(decrypt_ctx->crypt_ctx.gcm_ctx, databuf, decrypt_buf, bytesread);
            CT_BREAK_IF_ERROR(ret);
            *datalen = (uint64)bytesread;
        } while (0);

        CM_FREE_PTR(decrypt_buf);
        return ret;
    }

    bytesread = (int)fread(databuf, 1, (size_t)maxread, loader->fp);
    if (ferror(loader->fp)) {
        CTSQL_PRINTF(ZSERR_LOAD, "reading data file");
        perror("The reason is ");
        return CT_ERROR;
    }

    *datalen = (uint64)bytesread;
    return CT_SUCCESS;
}

static EN_LOADER_READ_STATUS ctsql_loader_get_raw_buf(loader_t *loader)
{
    uint64 nbytes = 0;
    uint64 inbytes;
    errno_t rc_memmove;
    if (loader->raw_buf_index < loader->raw_buf_len) {
        /* Copy down the unprocessed data */
        nbytes = loader->raw_buf_len - loader->raw_buf_index;
        rc_memmove = memmove_s(loader->raw_buf, RAW_BUF_SIZE, loader->raw_buf + loader->raw_buf_index,
                               (size_t)nbytes);
        if (rc_memmove != EOK) {
            CTSQL_PRINTF(ZSERR_LOAD, "move bin data failed.");
            return LOADER_READ_ERR;
        }
    } else {
        nbytes = 0; /* no data need be saved */
    }

    if (ctsql_loader_read_data(loader, loader->raw_buf + nbytes,
        RAW_BUF_SIZE - nbytes, &inbytes) != CT_SUCCESS) {
        return LOADER_READ_ERR;
    }

    nbytes += inbytes;
    loader->raw_buf[nbytes] = '\0';
    loader->raw_buf_index = 0;
    loader->raw_buf_len = nbytes;
    loader->eof = ((nbytes > 0) ? CT_FALSE : CT_TRUE);
    return LOADER_READ_OK;
}

EN_LOADER_READ_STATUS ctsql_loader_read_line(loader_t *loader, load_line_ctx_t *ctx)
{
    char enclose_char = g_load_opts.fields_enclosed;
    char *line_term = g_load_opts.lines_terminated;

    char *buf = loader->raw_buf;
    uint64 buf_idx = loader->raw_buf_index;
    uint64 ori_idx = loader->raw_buf_index;
    uint64 buf_len = loader->raw_buf_len;
    bool8 reach_max_size;
    bool8 is_enclosed = ctx->is_enclosed;
    uint32 line_terminal_matched_cnt = ctx->line_terminal_matched_cnt;

    CTSQL_LOAD_DEBUG("[Read Line] position at buff: (%llu/%llu) is %s enclosed.", buf_idx, buf_len,
                    ctx->is_enclosed ? "in" : "not in");

    while (CT_TRUE) {
        if (buf_idx >= buf_len) {
            if (buf_idx > ori_idx) {
                if (CT_SUCCESS != loader_append_linebuff(&loader->line_buf, buf + ori_idx,
                                                         buf_idx - ori_idx, &reach_max_size)) {
                    if (reach_max_size) {
                        ctx->reach_line_end = CT_FALSE;
                        return LOADER_READ_OK;
                    } else {
                        return LOADER_READ_ERR;
                    }
                }
                ctx->is_enclosed = is_enclosed;
                loader->raw_buf_index = buf_idx;
            }

            if (loader->eof) {
                if (loader->line_buf.len > 0) {
                    return LOADER_READ_OK;
                }

                return LOADER_READ_END;
            }

            if (ctsql_loader_get_raw_buf(loader) != LOADER_READ_OK) {
                return LOADER_READ_ERR;
            }

            buf = loader->raw_buf;
            ori_idx = loader->raw_buf_index;
            buf_idx = loader->raw_buf_index;
            buf_len = loader->raw_buf_len;
            continue;
        }

        if (buf[buf_idx] == enclose_char) {
            is_enclosed = !is_enclosed;
            buf_idx++;
            continue;
        }

        if (is_enclosed) {
            buf_idx++;
            continue;
        }

        if (buf[buf_idx] == line_term[ctx->line_terminal_matched_cnt]) {
            ctx->line_terminal_matched_cnt++;
            if (loader->column_param.line_terminal_len == ctx->line_terminal_matched_cnt) {
                CTSQL_LOAD_DEBUG("[Read Line] Hit Line end at position %llu.", buf_idx);
                buf_idx++;
                if (CT_SUCCESS != loader_append_linebuff(&loader->line_buf, buf + ori_idx, buf_idx - ori_idx,
                                                         &reach_max_size)) {
                    if (reach_max_size) {
                        ctx->line_terminal_matched_cnt = line_terminal_matched_cnt;
                        ctx->reach_line_end = CT_FALSE;
                        return LOADER_READ_OK;
                    } else {
                        return LOADER_READ_ERR;
                    }
                }
                ctx->is_enclosed = CT_FALSE;
                ctx->reach_line_end = CT_TRUE;
                loader->raw_buf_index = buf_idx;
                ctx->line_terminal_matched_cnt = 0;
                return LOADER_READ_OK;
            } else {
                buf_idx++;
                continue;
            }
        }

        buf_idx++;
    }
}

status_t ctsql_loader_append_line_to_block(loader_t *loader, text_t *block, uint64 max_size)
{
    if (max_size - block->len < loader->line_buf.len) {
        CTSQL_PRINTF(ZSERR_LOAD, "append line to block failed.");
        return CTCONN_ERROR;
    }

    CTSQL_LOAD_DEBUG("[Append Block] copy %llu bytes to block(used %u) max %llu.", loader->line_buf.len,
                    block->len, max_size);

    MEMS_RETURN_IFERR(memcpy_s(block->str + block->len, (size_t)(max_size - block->len), loader->line_buf.data,
                               (size_t)(loader->line_buf.len)));

    block->len += (uint32)loader->line_buf.len;
    loader->line_buf.len = 0;

    return CTCONN_SUCCESS;
}

status_t ctsql_loader_append_line_terminate(loader_t *loader, text_t *block, uint64 max_size,
    load_block_ctx_t *ctx)
{
    MEMS_RETURN_IFERR(memcpy_s(block->str + block->len, (uint32)(max_size - block->len),
        loader->column_param.line_terminal, loader->column_param.line_terminal_len));

    block->len += loader->column_param.line_terminal_len;
    ctx->current_line_ctx.reach_line_end = CT_TRUE;
    ctx->is_complete_row = CT_TRUE;
    loader->file_rows++;
    return CT_SUCCESS;
}

/*
below can be putted into block:
    1. multi row [ROW1,ROW2...]
    2. one row [ROW1]
    3. part row
*/
EN_LOADER_READ_STATUS ctsql_loader_read_block(loader_t *loader, text_t *block, uint64 max_size,
                                             load_block_ctx_t *ctx)
{
    EN_LOADER_READ_STATUS result = LOADER_READ_OK;
    bool8 need_stop_read = CT_FALSE;

    loader->start_line = loader->file_rows + 1;

    block->len = 0;

    if (loader->line_buf.len > 0) {
        CT_RETURN_IFERR(ctsql_loader_append_line_to_block(loader, block, max_size));
        if (ctx->next_line_ctx.reach_line_end) {
            loader->file_rows++;
            ctx->is_complete_row = CT_TRUE;
        } else {
            ctx->is_complete_row = CT_FALSE;
        }

        if (!ctx->current_line_ctx.reach_line_end) {  // last part of row
            need_stop_read = CT_TRUE;
        }

        ctx->current_line_ctx = ctx->next_line_ctx;
        LOAD_TRY_RESET_LINE_CTX(&(ctx->next_line_ctx));

        if (need_stop_read) {
            CTSQL_LOAD_DEBUG("[Read Block] block length %u, %s row.", block->len,
                            ctx->is_complete_row ? "complete" : "part");
            return LOADER_READ_OK;
        }
    }

    while (block->len < max_size) {
        result = ctsql_loader_read_line(loader, &ctx->next_line_ctx);
        if (result == LOADER_READ_ERR) {
            CTSQL_PRINTF(ZSERR_LOAD, "read line failed");
            return LOADER_READ_ERR;
        }

        if (result == LOADER_READ_END) {  // end of file
            if (block->len == 0 && loader->line_buf.len == 0) {
                if (!ctx->current_line_ctx.reach_line_end) {
                    CTSQL_LOAD_DEBUG("No terminal at end of file.try appent it.");
                    return ctsql_loader_append_line_terminate(loader, block, max_size, ctx) == CT_SUCCESS ?
                        LOADER_READ_OK : LOADER_READ_ERR;
                }
                CM_NULL_TERM(block);
                return LOADER_READ_END;
            }
        }

        if (loader->line_buf.len == 0) {
            break;
        }

        // no buffer in block to append the line
        if (max_size - block->len < loader->line_buf.len) {
            break;
        }

        CT_RETURN_IFERR(ctsql_loader_append_line_to_block(loader, block, max_size));

        if (ctx->next_line_ctx.reach_line_end) {
            loader->file_rows++;
        }

        if (!ctx->current_line_ctx.reach_line_end) {
            // part data or last part data this time.
            ctx->current_line_ctx = ctx->next_line_ctx;
            ctx->is_complete_row = ctx->next_line_ctx.reach_line_end;
            LOAD_TRY_RESET_LINE_CTX(&(ctx->next_line_ctx));
            break;
        }
        // update block info.
        ctx->current_line_ctx = ctx->next_line_ctx;
        ctx->is_complete_row = ctx->next_line_ctx.reach_line_end;
        LOAD_TRY_RESET_LINE_CTX(&(ctx->next_line_ctx));
    }

    CM_NULL_TERM(block);
    CTSQL_LOAD_DEBUG("[Read Block] block length %u, %s row.", block->len, ctx->is_complete_row ? "complete" : "part");
    return LOADER_READ_OK;
}

static inline void ctsql_set_field_indicator(worker_t *worker, uint32 row, uint32 col, uint16 val)
{
    uint16 *ind_ptr = NULL;
    ind_ptr = GET_IND_PTR(worker, row, col);
    *ind_ptr = val;
}

static inline void ctsql_put_field_null(worker_t *worker, uint32 row, uint32 col)
{
    ctsql_set_field_indicator(worker, row, col, CTCONN_NULL);
}

static inline int ctsql_put_field_uint32(worker_t *worker, text_t *field, uint32 row, uint32 col)
{
    uint32 val;
    char *field_ptr = NULL;
    num_errno_t nerr_no;

    nerr_no = cm_text2uint32_ex(field, &val);
    if (nerr_no != NERR_SUCCESS) {
        cm_truncate_text(field, MAX_TRUNCATED_FIELD_LEN);
        CTSQL_PRINTF(ZSERR_LOAD, "convert the field '%s' into uint32 failed"
                    " at line:" PRINT_FMT_UINT64 ", column:%u",
                    field->str, CURRENT_FILE_ROW(worker), col + 1);
        return CTCONN_ERROR;
    }

    field_ptr = (char *)worker->col_data[col] + sizeof(uint32) * row;
    *((uint32 *)field_ptr) = val;

    ctsql_set_field_indicator(worker, row, col, sizeof(uint32));
    return CTCONN_SUCCESS;
}

static inline int ctsql_put_field_int32(worker_t *worker, text_t *field, uint32 row, uint32 col)
{
    int32 val;
    char *field_ptr = NULL;
    num_errno_t nerr_no;

    nerr_no = cm_text2int_ex(field, &val);
    if (nerr_no != NERR_SUCCESS) {
        cm_truncate_text(field, MAX_TRUNCATED_FIELD_LEN);
        CTSQL_PRINTF(ZSERR_LOAD, "convert the field '%s' into int32 failed"
                    " at line:" PRINT_FMT_UINT64 ", column:%u",
                    field->str, CURRENT_FILE_ROW(worker), col + 1);
        return CTCONN_ERROR;
    }

    field_ptr = (char *)worker->col_data[col] + sizeof(int32) * row;
    *((int32 *)field_ptr) = val;

    ctsql_set_field_indicator(worker, row, col, sizeof(int32));
    return CTCONN_SUCCESS;
}

static inline int ctsql_put_field_int64(worker_t *worker, text_t *field, uint32 row, uint32 col)
{
    int64 val;
    char *field_ptr = NULL;

    if (cm_text2bigint_ex(field, &val) != NERR_SUCCESS) {
        cm_truncate_text(field, MAX_TRUNCATED_FIELD_LEN);
        CTSQL_PRINTF(ZSERR_LOAD, "convert the field '%s' into bigint failed at line:" PRINT_FMT_UINT64 ", column:%u",
                    field->str, CURRENT_FILE_ROW(worker), col + 1);
        return CTCONN_ERROR;
    }

    field_ptr = (char *)worker->col_data[col] + sizeof(int64) * row;
    *((int64 *)field_ptr) = val;
    ctsql_set_field_indicator(worker, row, col, sizeof(int64));

    return CTCONN_SUCCESS;
}

static inline int ctsql_put_field_real(worker_t *worker, text_t *field, uint32 row, uint32 col)
{
    double val;
    char *field_ptr = NULL;

    CM_NULL_TERM(field);
    if (!cm_str2real_ex(field->str, &val)) {
        cm_truncate_text(field, MAX_TRUNCATED_FIELD_LEN);
        CTSQL_PRINTF(ZSERR_LOAD, "convert the field '%s' into DOUBLE/REAL failed at line:" PRINT_FMT_UINT64 ", column:%u",
                    field->str, CURRENT_FILE_ROW(worker), col + 1);
        return CTCONN_ERROR;
    }

    field_ptr = (char *)worker->col_data[col] + sizeof(double) * row;
    *((double *)field_ptr) = val;
    ctsql_set_field_indicator(worker, row, col, sizeof(double));

    return CTCONN_SUCCESS;
}

static inline int ctsql_put_field_raw(worker_t *worker, text_t *field, uint32 row, uint32 col)
{
    binary_t bin;

    if (field->len > 2 && field->str[0] == '0' && UPPER(field->str[1]) == 'X') {
        CM_REMOVE_FIRST_N(field, 2);
    }

    if (field->len > (uint32)GET_LOADER(worker)->col_desc[col].size * 2) {
        uint32 field_len = field->len;
        cm_truncate_text(field, MAX_TRUNCATED_FIELD_LEN);
        CTSQL_PRINTF(ZSERR_LOAD, "the text field '%s' is too long at line:" PRINT_FMT_UINT64 ", column:%u,\n"
                    "the text length is %u larger than"
                    " the maximal allowed hex-string size (%u)",
                    field->str, CURRENT_FILE_ROW(worker), col + 1, field_len,
                    (uint32)GET_LOADER(worker)->col_desc[col].size * 2);
        return CTCONN_ERROR;
    }

    // put data
    bin.bytes = (uint8 *)worker->col_data[col] + row * GET_LOADER(worker)->col_bndsz[col];
    if (cm_text2bin(field, CT_FALSE, &bin, (uint32)(field->len + 1 / 2)) != CT_SUCCESS) {
        CTSQL_PRINTF(ZSERR_LOAD, "at line:" PRINT_FMT_UINT64 ", column:%u", CURRENT_FILE_ROW(worker), col + 1);
        ctsql_print_error(NULL);
        return CT_ERROR;
    }
    ctsql_set_field_indicator(worker, row, col, (uint16)bin.size);

    return CTCONN_SUCCESS;
}

static inline int ctsql_put_field_text(worker_t *worker, text_t *field, uint32 row, uint32 col)
{
    char *field_ptr = NULL;

    if (field->len > (uint32)GET_LOADER(worker)->col_bndsz[col]) {
        uint32 field_len = field->len;
        cm_truncate_text(field, MAX_TRUNCATED_FIELD_LEN);
        CTSQL_PRINTF(ZSERR_LOAD, "the text field '%s' is too long at line:" PRINT_FMT_UINT64 ", column:%u,\n"
                    "current field len %u byte(s) is larger than"
                    " the maximal allowed column size is %u %s",
                    field->str, CURRENT_FILE_ROW(worker), col + 1, field_len,
                    (uint32)GET_LOADER(worker)->col_desc[col].size,
                    GET_LOADER(worker)->col_desc[col].is_character ? "char(s)" : "byte(s)");
        return CTCONN_ERROR;
    }

    field_ptr = (char *)worker->col_data[col] + row * GET_LOADER(worker)->col_bndsz[col];
    // put data
    if (field->len != 0) {
        MEMS_RETURN_IFERR(memcpy_s(field_ptr, GET_LOADER(worker)->col_bndsz[col], field->str, field->len));
    }
    ctsql_set_field_indicator(worker, row, col, (uint16)field->len);

    return CTCONN_SUCCESS;
}

static inline int ctsql_put_field_clob(worker_t *worker, text_t *field, uint32 row, uint32 col)
{
    uint32 nchars;

    // put data
    if (field->len != 0) {
        CT_RETURN_IFERR(ctconn_write_batch_clob(worker->conn_info.stmt, col, row, field->str, field->len, &nchars));
    }
    ctsql_set_field_indicator(worker, row, col, sizeof(ctconn_lob_t));

    return CTCONN_SUCCESS;
}

static inline int ctsql_put_field_blob(worker_t *worker, text_t *field, uint32 row, uint32 col)
{
    // put data
    if (field->len != 0) {
        CT_RETURN_IFERR(ctconn_write_batch_blob(worker->conn_info.stmt, col, row, field->str, field->len));
    }
    ctsql_set_field_indicator(worker, row, col, sizeof(ctconn_lob_t));

    return CTCONN_SUCCESS;
}

bool32 ctsql_load_enclosed_match(const text_t *text, char enclosed_char)
{
    if (text->len < 1) {
        return CT_TRUE;
    }

    if (text->len == 1) {
        if (CM_TEXT_BEGIN(text) == enclosed_char) {
            return CT_FALSE;
        }

        return CT_TRUE;
    }

    if (CM_TEXT_BEGIN(text) == enclosed_char) {
        if (CM_TEXT_END(text) == enclosed_char) {
            return CT_TRUE;
        } else {
            return CT_FALSE;
        }
    }

    if (CM_TEXT_END(text) == enclosed_char) {
        if (CM_TEXT_BEGIN(text) == enclosed_char) {
            return CT_TRUE;
        } else {
            return CT_FALSE;
        }
    }

    return CT_TRUE;
}

int ctsql_load_text_replace(text_t *text, char enclosed_char)
{
    uint32 i = 0;
    uint32 w_pos = 0;

    for (i = 0; i < text->len; i++) {
        if (text->str[i] == enclosed_char) {
            if (i + 1 < text->len) {
                if (text->str[i + 1] == text->str[i]) {
                    text->str[w_pos++] = text->str[i];
                    i++;
                    continue;
                } else {
                    text->str[w_pos++] = text->str[i];
                }
            } else {
                text->str[w_pos++] = text->str[i];
            }
        } else {
            text->str[w_pos++] = text->str[i];
        }
    }

    text->len = w_pos;
    return CTCONN_SUCCESS;
}

int ctsql_load_remove_escape(text_t *text, char enclosed_char)
{
    if (text == NULL || text->str == NULL) {
        return CTCONN_SUCCESS;
    }

    uint32 len = text->len;
    char *data = text->str;

    if (len == 0) {
        return CTCONN_SUCCESS;
    }

    if (len == 1) {
        if (data[0] == enclosed_char) {
            return CTCONN_ERROR;
        } else {
            return CTCONN_SUCCESS;
        }
    }

    return ctsql_load_text_replace(text, enclosed_char);
}

static inline int ctsql_try_remove_field_enclosed(load_fetch_column_t *fetch_column, uint16 datatype)
{
    if (!CTSQL_HAS_ENCLOSED_CHAR(g_load_opts.fields_enclosed)) {
        return CTCONN_SUCCESS;
    }

    if (!g_load_opts.enclosed_optionally || CTSQL_IS_ENCLOSED_TYPE(datatype)) {
        // if is enclosed, remove the enclosed char
        if (!fetch_column->column_ctx->is_enclosed_begin &&
            (!CTSQL_IS_LOB_TYPE(datatype) || fetch_column->column_ctx->is_first_chunk)) {
            if (fetch_column->column_txt.str[0] == g_load_opts.fields_enclosed) {
                CM_REMOVE_FIRST_N(&(fetch_column->column_txt), 1);
            }
        }
        if (!fetch_column->column_ctx->is_enclosed) {
            if (fetch_column->column_txt.str[fetch_column->column_txt.len - 1] == g_load_opts.fields_enclosed) {
                CM_REMOVE_LAST(&(fetch_column->column_txt));
            }
        }

        // if enclosed char is inside the filed
        if (CTCONN_SUCCESS != ctsql_load_remove_escape(&(fetch_column->column_txt), g_load_opts.fields_enclosed)) {
            return CTCONN_ERROR;
        }
    }

    return CTCONN_SUCCESS;
}

static int ctsql_put_field_into_column_core(worker_t *worker, text_t *field, uint32 row, uint32 col)
{
    switch (GET_LOADER(worker)->col_bndtype[col]) {
        case CTCONN_TYPE_UINT32:
            return ctsql_put_field_uint32(worker, field, row, col);
        case CTCONN_TYPE_INTEGER:
            return ctsql_put_field_int32(worker, field, row, col);

        case CTCONN_TYPE_BIGINT:
            return ctsql_put_field_int64(worker, field, row, col);

        case CTCONN_TYPE_REAL:
            return ctsql_put_field_real(worker, field, row, col);

        case CTCONN_TYPE_BOOLEAN:
        case CTCONN_TYPE_DATE:
        case CTCONN_TYPE_TIMESTAMP:
        case CTCONN_TYPE_TIMESTAMP_LTZ:
        case CTCONN_TYPE_NUMBER:
        case CTCONN_TYPE_NUMBER2:
        case CTCONN_TYPE_DECIMAL:
        case CTCONN_TYPE_CHAR:
        case CTCONN_TYPE_VARCHAR:
        case CTCONN_TYPE_STRING:
        case CTCONN_TYPE_TIMESTAMP_TZ_FAKE:
        case CTCONN_TYPE_TIMESTAMP_TZ:
        case CTCONN_TYPE_BINARY:
        case CTCONN_TYPE_VARBINARY:
            return ctsql_put_field_text(worker, field, row, col);

        case CTCONN_TYPE_RAW:
            return ctsql_put_field_raw(worker, field, row, col);

        case CTCONN_TYPE_CLOB:
            return ctsql_put_field_clob(worker, field, row, col);

        case CTCONN_TYPE_BLOB:
        case CTCONN_TYPE_IMAGE:
            return ctsql_put_field_blob(worker, field, row, col);

        case CTCONN_TYPE_CURSOR:
        case CTCONN_TYPE_COLUMN:
        case CTCONN_TYPE_UNKNOWN:
        default:
            CM_NEVER;
            return CTCONN_ERROR;
    }
}

static int ctsql_put_field_into_column(worker_t *worker, load_fetch_column_t *fetch_column, uint32 row, uint32 col)
{
    uint16 type = GET_LOADER(worker)->col_desc[col].type;
    text_t *field = &(fetch_column->column_txt);

    CM_NULL_TERM(field);
    if (!CTSQL_IS_ENCLOSED_TYPE(type)) {
        cm_trim_text(field);
    }

    if (row >= worker->max_batch_rows) {
        CTSQL_PRINTF(ZSERR_LOAD, "assert raised, expect: row(%u) < worker->max_batch_rows(%u)", row,
                    worker->max_batch_rows);
        return CT_ERROR;
    }

    if (CM_IS_EMPTY(field)) {
        if (fetch_column->column_ctx->lob_writed_length == 0) {
            ctsql_put_field_null(worker, row, col);
        }
        return CTCONN_SUCCESS;
    }

    if (ctsql_try_remove_field_enclosed(fetch_column, GET_LOADER(worker)->col_desc[col].type) != CTCONN_SUCCESS) {
        cm_truncate_text(field, MAX_TRUNCATED_FIELD_LEN);
        CTSQL_PRINTF(ZSERR_LOAD, "the field '%s' is not enclosed at file line:" PRINT_FMT_UINT64 ", column:%u",
                    field->str, CURRENT_FILE_ROW(worker), col + 1);
        return CTCONN_ERROR;
    }

    if (CTSQL_IS_LOB_TYPE(type)) {
        fetch_column->column_ctx->lob_writed_length += field->len;
        if (fetch_column->column_ctx->lob_writed_length >= CT_MAX_LOB_SIZE) {
            CTSQL_PRINTF(ZSERR_LOAD, "lob size reach max size %llu at file line:" PRINT_FMT_UINT64 ", column:%u",
                        CT_MAX_LOB_SIZE, CURRENT_FILE_ROW(worker), col + 1);
            return CTCONN_ERROR;
        }
    }

    return ctsql_put_field_into_column_core(worker, field, row, col);
}

static void ctsql_print_debug_text(text_t *text)
{
    char print_buf[MAX_LOAD_PRINT_TEXT_LEN + 1];
    text_t print_text = { .str = print_buf, .len = 0 };
    cm_concat_text(&print_text, MAX_LOAD_PRINT_TEXT_LEN, text);
    CM_NULL_TERM(&print_text);
    CTSQL_LOAD_DEBUG("[Print Text] length %u , content %s.", text->len, print_text.str);
}

static int ctsql_put_field_into_column_ctx(worker_t *worker, load_fetch_column_t *fetch_column, uint32 row,
                                          uint32 col)
{
    uint16 type = GET_LOADER(worker)->col_desc[col].type;
    load_column_ctx_t *column_ctx = fetch_column->column_ctx;
    int32 ret = CTCONN_SUCCESS;
    fixed_memory_pool_t *pool = &(GET_LOADER(worker)->block_pool);

    ctsql_print_debug_text(&(fetch_column->column_txt));

    if (CTSQL_IS_LOB_TYPE(type) || (column_ctx->reach_column_end &&
                                   fetch_column->column_ctx->column_data.str == NULL)) {
        return ctsql_put_field_into_column(worker, fetch_column, row, col);
    }

    // not lob , not reach end
    if (column_ctx->column_data.str == NULL) {
        column_ctx->column_data.len = 0;

        column_ctx->column_data.str = ctconn_common_alloc_fixed_buffer(pool);
        if (column_ctx->column_data.str == NULL) {
            CTSQL_PRINTF(ZSERR_LOAD, "malloc memory for store column data failed.");
            return CTCONN_ERROR;
        }
    }
    cm_concat_text(&(column_ctx->column_data), pool->block_size, &(fetch_column->column_txt));
    if (column_ctx->reach_column_end) {
        fetch_column->column_txt = column_ctx->column_data;
        column_ctx->is_enclosed_begin = CT_FALSE;
        ret = ctsql_put_field_into_column(worker, fetch_column, row, col);
        ctconn_common_free_fixed_buffer(pool, column_ctx->column_data.str);
        column_ctx->column_data.str = NULL;
    }
    return ret;
}

status_t ctsql_fetch_column(worker_t *worker, text_t *text, load_column_ctx_t *ctx, load_column_param_t *param,
                           text_t *sub);

status_t ctsql_load_skip_current_line(text_t *text, worker_t *worker, bool8 *line_end, bool8 *fetch_end)
{
    load_column_param_t *param = worker->column_param;
    load_column_ctx_t *ctx = &(worker->column_ctx);
    text_t column_txt;

    if (!ctx->need_skip_current_line || ctx->reach_line_end) {
        LOAD_RESET_COLUMN_CTX(ctx);
        *line_end = CT_TRUE;
        LOAD_LOCAT_INFO_INC(worker);
        return CTCONN_SUCCESS;
    }

    CTSQL_LOAD_DEBUG("[Skip Line] begin to skip line %llu.",
        worker->locat_info.curr_line_in_block + worker->prev_loaded_rows);

    while (!ctx->reach_line_end && text->len > 0) {
        if (ctsql_fetch_column(worker, text, ctx, param, &column_txt) != CTCONN_SUCCESS) {
            CTSQL_LOAD_DEBUG("[Skip Line] failed to skip line %llu.",
                            worker->locat_info.curr_line_in_block + worker->prev_loaded_rows);
            return CTCONN_ERROR;
        }
    }

    if (text->len == 0) {
        *fetch_end = CT_TRUE;
    }
    if (ctx->reach_line_end) {
        CTSQL_LOAD_DEBUG("[Skip Line] end to skip line %llu.",
            worker->locat_info.curr_line_in_block + worker->prev_loaded_rows);
        LOAD_RESET_COLUMN_CTX(ctx);
        *line_end = CT_TRUE;
        LOAD_LOCAT_INFO_INC(worker);
    }
    return CTCONN_SUCCESS;
}

void ctsql_load_print_conn_error(worker_t *worker)
{
    int32 code;
    const char *msg = NULL;

    ctconn_get_error(worker->conn_info.conn, &code, &msg);
    if (code != CT_SUCCESS) {
        CTSQL_LOAD_DEBUG("[Print Error] %d : %s", code, msg);
        CTSQL_PRINTF(ZSERR_LOAD, "errcode = %d , errinfo = %s.", code, msg);
    }
}
status_t ctsql_load_line_check(worker_t *worker, load_column_ctx_t *ctx, bool8 *line_end)
{
    uint32 col_num = GET_LOADER(worker)->col_num;

    if (ctx->col_id == col_num) {
        if (ctx->reach_line_end) {
            // line reach end
            LOAD_RESET_COLUMN_CTX(ctx);
            worker->locat_info.curr_row++;
            *line_end = CT_TRUE;
            LOAD_LOCAT_INFO_INC(worker);
            CTSQL_LOAD_DEBUG("[Worker Thread]fetch line end.");
            return CTCONN_SUCCESS;
        } else {
            CTSQL_PRINTF(ZSERR_LOAD, "too much columns at line " PRINT_FMT_UINT64 "", CURRENT_FILE_ROW(worker));
            ctx->need_skip_current_line = CT_TRUE;
            worker->check_line_errs++;
            return CTCONN_ERROR;
        }
    }

    // Insufficient number of columns need supplemental null
    if (ctx->reach_line_end) {
        CTSQL_PRINTF(ZSERR_LOAD, "too less columns at line " PRINT_FMT_UINT64 "", CURRENT_FILE_ROW(worker));
        worker->check_line_errs++;
        LOAD_RESET_COLUMN_CTX(ctx);
        *line_end = CT_TRUE;
        LOAD_LOCAT_INFO_INC(worker);
        CTSQL_LOAD_DEBUG("[Worker Thread]fetch line end.");
        return CTCONN_ERROR;
    }

    return CTCONN_SUCCESS;
}

status_t ctsql_adjust_column_value(worker_t *worker)
{
    loader_t *loader = GET_LOADER(worker);
    load_column_ctx_t *ctx = &(worker->column_ctx);
    uint16 *ind = GET_IND_PTR(worker, worker->locat_info.curr_row, ctx->col_id);
    load_fetch_column_t fetch_column;
    char space_buf[CT_MAX_NAME_LEN];
    
    if (!g_load_opts.null2space) {
        return CT_SUCCESS;
    }
    
    if (LOAD_TYPE_NEED_PUT_SPACE(loader->col_desc[ctx->col_id].type) &&
        (!loader->col_desc[ctx->col_id].nullable) &&
        (*ind == CTCONN_NULL)) {
        fetch_column.column_txt.str = space_buf;
        fetch_column.column_txt.str[0] = ' ';
        fetch_column.column_txt.len = 1;
        fetch_column.column_ctx = ctx;

        return ctsql_put_field_into_column_ctx(worker, &fetch_column, worker->locat_info.curr_row, ctx->col_id);
    }

    return CT_SUCCESS;
}

status_t ctsql_fetch_line(text_t *text, worker_t *worker, bool8 *line_end, bool8 *fetch_end)
{
    load_column_param_t *param = worker->column_param;
    load_column_ctx_t *ctx = &(worker->column_ctx);
    load_fetch_column_t fetch_column;

    fetch_column.column_ctx = ctx;

    *fetch_end = CT_FALSE;

    if (text->len == 0) {
        *fetch_end = CT_TRUE;
        return CTCONN_SUCCESS;
    }

    *line_end = CT_FALSE;

    while (text->len > 0) {
        if (ctsql_fetch_column(worker, text, ctx, param, &(fetch_column.column_txt)) != CTCONN_SUCCESS) {
            ctx->fatal_error = CT_TRUE;
            return CTCONN_ERROR;
        }

        CTSQL_LOAD_DEBUG("[Put Column Data]put %s data len [%u] into row [%u] column [%s][%u].",
                        fetch_column.column_ctx->reach_column_end ? "complete" : "part",
                        fetch_column.column_txt.len,
                        worker->locat_info.curr_row,
                        GET_LOADER(worker)->col_desc[fetch_column.column_ctx->col_id].name,
                        fetch_column.column_ctx->col_id);

        if (ctsql_put_field_into_column_ctx(worker, &fetch_column, worker->locat_info.curr_row,
            ctx->col_id) != CTCONN_SUCCESS) {
            ctsql_load_print_conn_error(worker);
            ctx->need_skip_current_line = CT_TRUE;
            return CTCONN_ERROR;
        }

        if (ctx->reach_column_end) {
            // adjust column value based on config
            CT_RETURN_IFERR(ctsql_adjust_column_value(worker));
            ctx->col_id++;
            ctx->lob_writed_length = 0;
        }

        if (ctsql_load_line_check(worker, ctx, line_end) != CTCONN_SUCCESS) {
            return CTCONN_ERROR;
        }

        if (*line_end) {
            return CTCONN_SUCCESS;
        }
    }
    CTSQL_LOAD_DEBUG("[Worker Thread]fetch block end , line not end.");
    *fetch_end = CT_TRUE;
    *line_end = CT_FALSE;
    return CTCONN_SUCCESS;
}

bool8 ctsql_need_parser_enclosed(worker_t *worker)
{
    load_column_param_t *param = worker->column_param;

    if (!CM_IS_VALID_ENCLOSED_CHAR(param->enclosed_char)) {
        return CT_FALSE;
    }

    return CT_TRUE;
}

status_t ctsql_check_load_column(worker_t *worker, load_column_ctx_t *ctx)
{
    if (ctx->loaded_length > MAX_LOAD_COLUMN_LEN(GET_LOADER(worker)->col_desc[ctx->col_id].type)) {
        CTSQL_PRINTF(ZSERR_LOAD, "row %llu column %s size %llu exceeds max size %llu.",
                    CURRENT_FILE_ROW(worker), GET_LOADER(worker)->col_desc[ctx->col_id].name,
                    ctx->loaded_length,
                    MAX_LOAD_COLUMN_LEN(GET_LOADER(worker)->col_desc[ctx->col_id].type));
        return CTCONN_ERROR;
    }
    if (ctx->reach_column_end) {
        ctx->loaded_length = 0;
    }
    return CTCONN_SUCCESS;
}

status_t ctsql_fetch_column(worker_t *worker, text_t *text, load_column_ctx_t *ctx, load_column_param_t *param,
                           text_t *sub)
{
    char current_char;
    bool32 matched_flag = CT_FALSE;

    sub->str = text->str;
    ctx->is_enclosed_begin = ctx->is_enclosed; /* first char is enclosed ? */

    /* column is end , must NOT be enclosed */
    for (uint32 i = 0; i < text->len; i++) {
        current_char = text->str[i];
        matched_flag = CT_FALSE;

        /* enclosed char */
        if (ctsql_need_parser_enclosed(worker)) {
            if (current_char == param->enclosed_char) {
                ctx->is_enclosed = !ctx->is_enclosed;
                continue;
            }

            if (ctx->is_enclosed) {
                continue;
            }
        }

        /* reach line end */
        if (param->line_terminal[ctx->line_terminal_matched_cnt] == current_char) {
            ctx->line_terminal_matched_cnt++;
            matched_flag = CT_TRUE;
            if (param->line_terminal_len == ctx->line_terminal_matched_cnt) {
                sub->len = i + 1 - param->line_terminal_len;
                CM_REMOVE_FIRST_N(text, i + 1);
                ctx->reach_column_end = CT_TRUE;
                ctx->reach_line_end = CT_TRUE;
                ctx->line_terminal_matched_cnt = 0;
                ctx->field_terminal_matched_cnt = 0;
                ctx->is_first_chunk = (ctx->loaded_length == 0);
                ctx->loaded_length += sub->len;
                CT_RETURN_IFERR(ctsql_check_load_column(worker, ctx));
                return CTCONN_SUCCESS;
            }
        }

        /* check field terminal */
        if (param->field_terminal[ctx->field_terminal_matched_cnt] == current_char) {
            ctx->field_terminal_matched_cnt++;
            matched_flag = CT_TRUE;
            /* reach column end */
            if (param->field_terminal_len == ctx->field_terminal_matched_cnt) {
                sub->len = i + 1 - param->field_terminal_len;
                CM_REMOVE_FIRST_N(text, i + 1);
                ctx->reach_column_end = CT_TRUE;
                ctx->reach_line_end = CT_FALSE;
                ctx->line_terminal_matched_cnt = 0;
                ctx->field_terminal_matched_cnt = 0;
                ctx->is_first_chunk = (ctx->loaded_length == 0);
                ctx->loaded_length += sub->len;
                CT_RETURN_IFERR(ctsql_check_load_column(worker, ctx));
                return CTCONN_SUCCESS;
            }
        }

        if (matched_flag) {
            continue;
        }

        if (!ctsql_need_parser_enclosed(worker) || g_load_opts.enclosed_optionally) {
            continue;
        }

        /* field terminal check failed. */
        CTSQL_PRINTF(ZSERR_LOAD, "unexpected field terminal(ASCII:0x%x) at row %llu column %u end.",
                    (uint32)current_char, CURRENT_FILE_ROW(worker), ctx->col_id + 1);
        return CTCONN_ERROR;
    }

    sub->len = text->len;
    ctx->reach_column_end = CT_FALSE;
    ctx->reach_line_end = CT_FALSE;
    CM_TEXT_CLEAR(text);
    ctx->is_first_chunk = (ctx->loaded_length == 0);
    ctx->loaded_length += sub->len;
    CT_RETURN_IFERR(ctsql_check_load_column(worker, ctx));
    return CTCONN_SUCCESS;
}

static inline void ctsql_worker_error_info_output(ctconn_stmt_t stmt, worker_t *worker, uint32 actual_batch_errs,
                                                 uint32 *skip_rows)
{
    uint32 i, line, rows;
    char *err_message = NULL;
    int32 code;

    for (i = 0; i < actual_batch_errs; i++) {
        if (ctconn_get_batch_error2(stmt, &line, &code, &err_message, &rows) != CT_SUCCESS || rows == 0) {
            break;
        } else {
            if (g_load_opts.ignore && code == ERR_DUPLICATE_KEY) {
                (*skip_rows)++;
            }
        }

        ctsql_printf("line %llu:CT-%05d, %s\n",
            (uint64)(worker->locat_info.read_rows - worker->check_line_errs - worker->locat_info.curr_row + line + 1),
            code, err_message);
    }
}

static void load_post_nologging(loader_t *loader)
{
    char truncate_sql[CT_BUFLEN_256];
    int32 iret_snprintf;

    if (!g_load_opts.nologging) {
        return;
    }

    iret_snprintf = snprintf_s(truncate_sql, sizeof(truncate_sql), sizeof(truncate_sql) - 1, "truncate table %s",
        loader->table);
    if (iret_snprintf < 0) {
        ctsql_printf("make truncate sql failed.");
        return;
    }

    // do truncate when failed
    if (ctconn_query(CONN, (const char *)truncate_sql) != CT_SUCCESS) {
        ctsql_print_error(CONN);
    }
    return;
}

static void load_worker_post_nologging(worker_t *worker)
{
    if (!g_load_opts.nologging) {
        return;
    }
    // do rollback when failed
    if (ctconn_rollback(worker->conn_info.conn) != CT_SUCCESS) {
        ctsql_print_error(worker->conn_info.conn);
    }
    return;
}

static inline int ctsql_load_rows_to_db(ctconn_stmt_t stmt, worker_t *worker)
{
    int exec_status;
    uint32 affected_rows;
    uint32 actual_batch_errs = worker->actual_batch_errs;
    uint32 allowed_batch_errs = worker->allowed_batch_errs;
    uint32 skip_rows = 0;

    if (actual_batch_errs > allowed_batch_errs) {
        return CTCONN_SUCCESS;
    }
    allowed_batch_errs -= actual_batch_errs;

    if (g_load_opts.ignore) {
        (void)ctconn_set_stmt_attr(stmt, CTCONN_ATTR_ALLOWED_BATCH_ERRS, &worker->locat_info.curr_row, sizeof(uint32));
    } else {
        (void)ctconn_set_stmt_attr(stmt, CTCONN_ATTR_ALLOWED_BATCH_ERRS, &allowed_batch_errs, sizeof(uint32));
    }
    
    ctconn_set_paramset_size(stmt, worker->locat_info.curr_row);

    exec_status = ctconn_execute(stmt);

    affected_rows = ctconn_get_affected_rows(stmt);
    
    (void)ctconn_get_stmt_attr(stmt, CTCONN_ATTR_ACTUAL_BATCH_ERRS, (void *)&actual_batch_errs, sizeof(uint32), NULL);

    ctsql_worker_error_info_output(stmt, worker, actual_batch_errs, &skip_rows);

    if (g_load_opts.replace) {
        worker->loaded_rows += worker->locat_info.curr_row - actual_batch_errs;
        worker->error_rows += actual_batch_errs;
    } else {
        worker->loaded_rows += affected_rows;
        worker->error_rows += worker->locat_info.curr_row - affected_rows - skip_rows;
    }
    
    worker->actual_batch_errs += actual_batch_errs - skip_rows;
    worker->skip_rows += skip_rows;
    
    // when failed to execute output the error information
    if (exec_status != CTCONN_SUCCESS) {
        ctsql_print_error(worker->conn_info.conn);
        CTSQL_PRINTF(ZSERR_LOAD, "execute failed at line %llu in file",
                    worker->start_line + worker->loaded_rows - worker->prev_loaded_rows);
        (void)ctconn_rollback(worker->conn_info.conn);
        return CTCONN_ERROR;
    }

    worker->locat_info.curr_row = 0;
    worker->check_line_errs = 0;
    ctconn_set_paramset_size(stmt, worker->max_batch_rows);

    return CTCONN_SUCCESS;
}

status_t ctsql_worker_load(ctconn_stmt_t stmt, text_t *read_buf, worker_t *worker)
{
    load_column_ctx_t *column_ctx = &(worker->column_ctx);
    bool8 line_end = CT_FALSE;
    bool8 fetch_end = CT_FALSE;

    worker->locat_info.curr_line_in_block = 0;
    worker->prev_loaded_rows = worker->loaded_rows;
    worker->check_line_errs = 0;

    while (!worker->closed && !fetch_end && !CTSQL_CANCELING) {
        if (worker->locat_info.curr_row >= worker->max_batch_rows && line_end) {
            if (ctsql_load_rows_to_db(stmt, worker) != CTCONN_SUCCESS) {
                return CTCONN_ERROR;
            }
        }

        if (column_ctx->need_skip_current_line) {
            /* skip error line. */
            if (ctsql_load_skip_current_line(read_buf, worker, &line_end, &fetch_end) != CTCONN_SUCCESS) {
                return CTCONN_ERROR;
            }
        } else {
            if (ctsql_fetch_line(read_buf, worker, &line_end, &fetch_end) != CTCONN_SUCCESS) {
                worker->actual_batch_errs++;
                worker->error_rows++;
                if (column_ctx->fatal_error) {
                    return CTCONN_ERROR;
                }
            }
        }
        
        // if no rows in read_buff
        if (fetch_end) {
            if (worker->locat_info.curr_row > 0 && line_end) {
                if (ctsql_load_rows_to_db(stmt, worker) != CTCONN_SUCCESS) {
                    return CT_ERROR;
                }
            }

            return CT_SUCCESS;
        }

        if (worker->actual_batch_errs > worker->allowed_batch_errs) {
            return CT_SUCCESS;
        }
    }

    return CTCONN_SUCCESS;
}

static inline void ctsql_loader_ignore_lines(loader_t *loader)
{
    load_line_ctx_t ctx;

    loader->ignored_lines = 0;

    while (loader->ignored_lines < g_load_opts.ignore_lines) {
        ctx.is_enclosed = CT_FALSE;
        ctx.reach_line_end = CT_FALSE;
        ctx.line_terminal_matched_cnt = 0;

        do {
            EN_LOADER_READ_STATUS ret = ctsql_loader_read_line(loader, &ctx);
            if (ret == LOADER_READ_END) {
                loader->status = LOADER_STATUS_ERR;
                CTSQL_PRINTF(ZSERR_LOAD, "ignore lines(%llu) exceed the file lines", g_load_opts.ignore_lines);
                return;
            }

            loader->line_buf.len = 0;
        } while (!ctx.reach_line_end);

        ++loader->ignored_lines;
        ++loader->file_rows;
    }
}

status_t ctsql_worker_prepare(worker_t *worker);
status_t ctsql_worker_open_conn(worker_t *worker);

status_t load_prepare_conn(worker_t *worker)
{
    worker->conn_info = g_conn_info;
    if (LOAD_SERIAL) {
        return CT_SUCCESS;
    }

    worker->conn_info.stmt = NULL;
    MEMS_RETURN_IFERR(memcpy_s(worker->conn_info.passwd, CT_PASSWORD_BUFFER_SIZE + 4,
        g_load_pswd, CT_PASSWORD_BUFFER_SIZE + 4));

    return ctsql_worker_open_conn(worker);
}

status_t ctsql_worker_init(worker_t *worker)
{
    worker->locat_info.curr_row = 0;
    worker->locat_info.read_rows = 0;
    worker->loaded_rows = 0;
    worker->committed_rows = 0;
    worker->error_rows = 0;
    worker->skip_rows = 0;
    worker->check_line_errs = 0;

    worker->col_data_buf = NULL;

    worker->orig_block_buf = NULL;

    worker->block.id = 0;
    worker->block.start_line = 0;
    worker->block.buf.str = 0;
    worker->block.buf.len = 0;

    LOAD_RESET_COLUMN_CTX(&(worker->column_ctx));

    // prepare connection
    CT_RETURN_IFERR(load_prepare_conn(worker));
    // prepare sql and bind buffer
    CT_RETURN_IFERR(ctsql_worker_prepare(worker));

    return CT_SUCCESS;
}

void ctsql_worker_close_conn(worker_t *worker)
{
    if (worker->conn_info.stmt) {
        ctconn_free_stmt(worker->conn_info.stmt);
        worker->conn_info.stmt = NULL;
    }

    if (worker->conn_info.is_conn) {
        ctconn_disconnect(worker->conn_info.conn);
        worker->conn_info.is_conn = CT_FALSE;
    }

    if (worker->conn_info.conn) {
        ctconn_free_conn(worker->conn_info.conn);
        worker->conn_info.conn = NULL;
    }
}

void ctsql_worker_free(worker_t *worker)
{
    if (!LOAD_SERIAL) {
        ctsql_worker_close_conn(worker);
    }

    if (worker->col_data_buf != NULL) {
        free(worker->col_data_buf);
        worker->col_data_buf = NULL;
    }

    if (worker->orig_block_buf != NULL) {
        ctconn_common_free_fixed_buffer(&(GET_LOADER(worker)->block_pool), worker->orig_block_buf);
        worker->orig_block_buf = NULL;
    }

    worker->block.buf.str = NULL;
    worker->block.buf.len = 0;
}

status_t ctsql_loader_select_columns(char *select_columns)
{
    uint32 i;
    char *column_name = NULL;

    if (g_load_opts.obj_list.count > 0) {
        for (i = 0; i < g_load_opts.obj_list.count; i++) {
            column_name = cm_list_get(&g_load_opts.obj_list, i);
            MEMS_RETURN_IFERR(strncat_s(select_columns, MAX_LOAD_SQL_SIZE, "\"", strlen("\"")));
            MEMS_RETURN_IFERR(strncat_s(select_columns, MAX_LOAD_SQL_SIZE, column_name, strlen(column_name)));

            if (i < g_load_opts.obj_list.count - 1) {
                MEMS_RETURN_IFERR(strncat_s(select_columns, MAX_LOAD_SQL_SIZE, "\",", strlen("\",")));
            }
        }
        MEMS_RETURN_IFERR(strncat_s(select_columns, MAX_LOAD_SQL_SIZE, "\"", strlen("\"")));
        MEMS_RETURN_IFERR(strncpy_s(g_load_opts.trailing_columns, MAX_LOAD_SQL_SIZE, select_columns, strlen(select_columns)));
    } else {
        MEMS_RETURN_IFERR(strncpy_s(select_columns, MAX_LOAD_SQL_SIZE, "*", strlen("*")));
    }

    return CT_SUCCESS;
}

static status_t ctsql_loader_varstr_column_size(ctconn_conn_t conn, ctconn_inner_column_desc_t *col_desc, uint16 *bnd_size)
{
    char charset_name[CT_MAX_NAME_LEN];
    uint32 local_charlen, server_charlen;

    if (col_desc->is_character) {
        *bnd_size = CM_ALIGN4(col_desc->size * CT_CHAR_TO_BYTES_RATIO);
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(ctconn_get_conn_attr(conn, CTCONN_ATTR_NLS_CHARACTERSET, charset_name,
        sizeof(charset_name), NULL));
    server_charlen = CM_CHARSET_FUNC(cm_get_charset_id((const char *)charset_name)).max_bytes_per_char();
    CT_RETURN_IFERR(ctconn_get_conn_attr(conn, CTCONN_ATTR_CHARSET_TYPE, charset_name,
        sizeof(charset_name), NULL));
    local_charlen = CM_CHARSET_FUNC(cm_get_charset_id((const char *)charset_name)).max_bytes_per_char();
    /*
        if local charset length per character is
        larger than server charset length per character,
        bound size should be resized larger than column definition
    */
    if (server_charlen < local_charlen) {
        *bnd_size = CM_ALIGN4(col_desc->size * local_charlen / server_charlen);
    } else {
        *bnd_size = CM_ALIGN4(col_desc->size);
    }
    return CT_SUCCESS;
}

static inline int ctsql_loader_column_desc(loader_t *loader)
{
    uint32 i;
    char trailing_columns[MAX_LOAD_SQL_SIZE] = { 0 };
    char *trailing_string = trailing_columns;

    CT_RETURN_IFERR(ctsql_loader_select_columns(trailing_string));

    /* the value of loader->table already included char '"' or char '`' to express case_sensitive tablename */
    PRTS_RETURN_IFERR(snprintf_s(loader->insert_sql, MAX_LOAD_SQL_SIZE, MAX_LOAD_SQL_SIZE - 1, "select %s from %s limit 0",
        trailing_columns, loader->table));

    if (!IS_CONN) {
        (void)ctsql_print_disconn_error();
        return CT_ERROR;
    }

    if (ctconn_prepare(STMT, loader->insert_sql) != CTCONN_SUCCESS) {
        ctsql_print_error(CONN);
        return CTCONN_ERROR;
    }

    if (ctconn_get_column_count(STMT, &loader->col_num) != CTCONN_SUCCESS) {
        ctsql_print_error(CONN);
        return CTCONN_ERROR;
    }

    if (loader->col_num == 0) {
        CTSQL_PRINTF(ZSERR_LOAD, "assert raised, expect: loader->col_num(%u) > 0", loader->col_num);
        return CT_ERROR;
    }

    loader->row_size = 0;
    loader->lob_col_num = 0;

    loader->col_desc = g_columns;
    for (i = 0; i < loader->col_num; i++) {
        if (ctconn_desc_inner_column_by_id(STMT, i, &(loader->col_desc[i])) != CTCONN_SUCCESS) {
            ctsql_print_error(CONN);
            return CTCONN_ERROR;
        }

        loader->col_bndtype[i] = loader->col_desc[i].type;

        switch (loader->col_desc[i].type) {
            case CTCONN_TYPE_DATE:
            case CTCONN_TYPE_TIMESTAMP:
            case CTCONN_TYPE_TIMESTAMP_TZ_FAKE:
            case CTCONN_TYPE_TIMESTAMP_TZ:
            case CTCONN_TYPE_TIMESTAMP_LTZ:
                loader->col_bndtype[i] = CTCONN_TYPE_VARCHAR;
                loader->col_desc[i].size = loader->col_bndsz[i] = CM_ALIGN4(40);
                break;

            case CTCONN_TYPE_INTERVAL_DS:
                loader->col_bndtype[i] = CTCONN_TYPE_VARCHAR;
                loader->col_desc[i].size = loader->col_bndsz[i] = CM_ALIGN4(CT_MAX_DS_INTERVAL_STRLEN + 8);
                break;

            case CTCONN_TYPE_INTERVAL_YM:
                loader->col_bndtype[i] = CTCONN_TYPE_VARCHAR;
                loader->col_desc[i].size = loader->col_bndsz[i] = CM_ALIGN4(CT_MAX_YM_INTERVAL_STRLEN + 4);
                break;

            case CTCONN_TYPE_NUMBER:
            case CTCONN_TYPE_NUMBER2:
            case CTCONN_TYPE_DECIMAL:
                loader->col_bndtype[i] = CTCONN_TYPE_VARCHAR;
                loader->col_desc[i].size = loader->col_bndsz[i] = CM_ALIGN4(180);  // > 38 + 127
                break;

            case CTCONN_TYPE_BOOLEAN:
                loader->col_bndtype[i] = CTCONN_TYPE_STRING;
                loader->col_desc[i].size = loader->col_bndsz[i] = CM_ALIGN4(12);
                break;

            case CTCONN_TYPE_CHAR:
            case CTCONN_TYPE_VARCHAR:
            case CTCONN_TYPE_STRING:
                CT_RETURN_IFERR(ctsql_loader_varstr_column_size(CONN, &loader->col_desc[i], &loader->col_bndsz[i]));
                break;

            case CTCONN_TYPE_BINARY:
            case CTCONN_TYPE_VARBINARY:
            case CTCONN_TYPE_RAW:
            case CTCONN_TYPE_INTEGER:
            case CTCONN_TYPE_UINT32:
            case CTCONN_TYPE_BIGINT:
            case CTCONN_TYPE_REAL:
                loader->col_bndsz[i] = CM_ALIGN4(loader->col_desc[i].size);
                break;

            case CTCONN_TYPE_BLOB:
                if (ctconn_get_call_version(CONN) >= CS_VERSION_24 && loader->col_desc[i].is_jsonb &&
                    g_load_opts.convert_jsonb) {
                    loader->col_bndtype[i] = CTCONN_TYPE_CLOB;
                }
            /* fall through */
            case CTCONN_TYPE_CLOB:
            case CTCONN_TYPE_IMAGE:
                loader->col_bndsz[i] = CM_ALIGN4(sizeof(ctconn_lob_t));
                loader->lob_col_num++;
                break;

            default:
                CTSQL_PRINTF(ZSERR_LOAD, "the date type (%s) is not supported",
                            get_datatype_name_str(loader->col_desc[i].type + CT_TYPE_BASE));
                return CTCONN_ERROR;
        }  // end switch

        loader->row_size += loader->col_bndsz[i];
    }

    return CTCONN_SUCCESS;
}

static status_t ctsql_loader_make_replace_sql(loader_t *loader, text_t *sql_text, const char *hint_comment)
{
    int iret;
    uint32 i;

    iret = snprintf_s(sql_text->str, MAX_LOAD_SQL_SIZE, MAX_CMD_LEN - 1, "replace %s into %s set ",
                      hint_comment, loader->table);
    PRTS_RETURN_IFERR(iret);
    sql_text->len = iret;

    for (i = 0; i < loader->col_num; i++) {
        if (i != 0) {  // more than columns
            CM_TEXT_APPEND(sql_text, ',');
        }
                
        iret = snprintf_s(sql_text->str + sql_text->len, MAX_LOAD_SQL_SIZE - sql_text->len,
                          MAX_LOAD_SQL_SIZE - sql_text->len - 1, "\"%s\"=:%u", loader->col_desc[i].name, i);
        PRTS_RETURN_IFERR(iret);
        sql_text->len += iret;
    }

    if (g_load_opts.set_flag) {
        CM_TEXT_APPEND(sql_text, ',');
        iret = snprintf_s(sql_text->str + sql_text->len, MAX_LOAD_SQL_SIZE - sql_text->len,
                          strlen(g_load_opts.set_columns), "%s", g_load_opts.set_columns);
        PRTS_RETURN_IFERR(iret);
        sql_text->len += iret;
    }
    
    return CTCONN_SUCCESS;
}

static status_t ctsql_loader_make_insert_sql(loader_t *loader, text_t *sql_text, const char *hint_comment,
                                            const char *trailing_columns)
{
    int iret;
    uint32 i;

    iret = snprintf_s(sql_text->str, MAX_LOAD_SQL_SIZE, MAX_CMD_LEN - 1, "insert %s into %s %s values(",
                      hint_comment, loader->table, trailing_columns);
    PRTS_RETURN_IFERR(iret);
    sql_text->len = iret;

    for (i = 0; i < loader->col_num; i++) {
        if (i != 0) {  // more than columns
            CM_TEXT_APPEND(sql_text, ',');
        }

        iret = snprintf_s(sql_text->str + sql_text->len, MAX_LOAD_SQL_SIZE - sql_text->len, MAX_CMD_LEN, ":%u", i);
        PRTS_RETURN_IFERR(iret);
        sql_text->len += iret;
    }
    
    CM_TEXT_APPEND(sql_text, ')');

    return CTCONN_SUCCESS;
}

static status_t ctsql_loader_make_hint(char *hint_comment, size_t hint_len)
{
    if (!g_load_opts.replace && g_load_opts.set_flag) {
        MEMS_RETURN_IFERR(strncat_s(hint_comment, hint_len, "/*+ throw_duplicate */",
            strlen("/*+ throw_duplicate */")));
    }

    return CTCONN_SUCCESS;
}

static status_t ctsql_loader_make_sql(loader_t *loader)
{
    text_t sql_text = { .str = loader->insert_sql };
    char trailing_columns[MAX_LOAD_SQL_SIZE] = { 0 };
    char hint_comment[MAX_LOAD_SQL_SIZE] = { 0 };

    if (g_load_opts.obj_list.count > 0) {
        MEMS_RETURN_IFERR(strncat_s(trailing_columns, MAX_LOAD_SQL_SIZE, "(", 1));
        MEMS_RETURN_IFERR(strncat_s(trailing_columns, MAX_LOAD_SQL_SIZE, g_load_opts.trailing_columns, MAX_LOAD_SQL_SIZE - 1));
        MEMS_RETURN_IFERR(strncat_s(trailing_columns, MAX_LOAD_SQL_SIZE, ")", 1));
    }

    CT_RETURN_IFERR(ctsql_loader_make_hint(hint_comment, sizeof(hint_comment)));

    if (g_load_opts.replace || g_load_opts.set_flag) {
        CT_RETURN_IFERR(ctsql_loader_make_replace_sql(loader, &sql_text, hint_comment));
    } else {
        CT_RETURN_IFERR(ctsql_loader_make_insert_sql(loader, &sql_text, hint_comment, trailing_columns));
    }
    
    CM_NULL_TERM(&sql_text);
    return CTCONN_SUCCESS;
}

static uint16 load_estimate_batch_rows(worker_t *worker)
{
    uint16 max_batch_rows;
    uint32 bnd_row_size = GET_LOADER(worker)->row_size +
        GET_LOADER(worker)->col_num * sizeof(uint16);

    max_batch_rows = g_load_opts.max_databuf_size / bnd_row_size;

    if (GET_LOADER(worker)->lob_col_num > 0) {
        max_batch_rows = MIN(max_batch_rows,
            MAX_LOAD_LOB_BATCH_CNT / (GET_LOADER(worker)->lob_col_num * g_load_opts.threads));
    }

    // if databuf is insufficient, at least 2 records is ensured to load
    if (max_batch_rows == 0) {
        max_batch_rows = 2;   // 2 denotes max batch rows
    }

    return max_batch_rows;
}

static inline int ctsql_worker_alloc_column_mem(worker_t *worker)
{
    uint32 i;
    uint32 pos = 0;
    size_t size;
    uint32 bnd_row_size = GET_LOADER(worker)->row_size +
                          GET_LOADER(worker)->col_num * sizeof(uint16);

    worker->max_batch_rows = load_estimate_batch_rows(worker);

    size = worker->max_batch_rows * bnd_row_size;
    if (size == 0) {
        CTSQL_PRINTF(ZSERR_LOAD, "max databuf(%u) is smaller than row size(%d)", g_load_opts.max_databuf_size,
                    bnd_row_size);
        return CTCONN_ERROR;
    }

    worker->col_data_buf = (char *)malloc(size);
    if (worker->col_data_buf == NULL) {
        CTSQL_PRINTF(ZSERR_LOAD, "Fail to allocate %u bytes for data buffer", g_load_opts.max_databuf_size);
        return CTCONN_ERROR;
    }

    MEMS_RETURN_IFERR(memset_s(worker->col_data_buf, size, 0, size));

    for (i = 0; i < GET_LOADER(worker)->col_num; i++) {
        // allocate memory for col_data[i]
        worker->col_data[i] = worker->col_data_buf + pos;
        pos += worker->max_batch_rows * GET_LOADER(worker)->col_bndsz[i];

        // allocate memory for col_ind[i]
        worker->col_ind[i] = (uint16 *)(worker->col_data_buf + pos);
        pos += worker->max_batch_rows * sizeof(uint16);
    }

    return CTCONN_SUCCESS;
}

status_t ctsql_worker_open_conn(worker_t *worker)
{
    bool32 interactive_clt = CT_FALSE;
    uint32 remote_as_sysdba = CT_FALSE;
    status_t ret;

    worker->conn_info.conn = NULL;
    worker->conn_info.stmt = NULL;

    if (ctsql_alloc_conn(&worker->conn_info.conn) != CT_SUCCESS) {
        return CT_ERROR;
    }

    /* set session interactive check disable */
    cm_spin_lock(&GET_LOADER(worker)->conn_lock, NULL);
    (void)ctconn_get_conn_attr(g_conn_info.conn, CTCONN_ATTR_REMOTE_AS_SYSDBA, &remote_as_sysdba, sizeof(uint32), NULL);
    cm_spin_unlock(&GET_LOADER(worker)->conn_lock);
    (void)ctconn_set_conn_attr(worker->conn_info.conn, CTCONN_ATTR_INTERACTIVE_MODE, (void *)&interactive_clt, 0);
    (void)ctconn_set_conn_attr(worker->conn_info.conn, CTCONN_ATTR_REMOTE_AS_SYSDBA, &remote_as_sysdba, sizeof(int32));

    worker->conn_info.is_conn = CT_FALSE;

    (void)ctsql_switch_user(&worker->conn_info);

    if (ctsql_conn_to_server(&worker->conn_info, CT_FALSE, CT_TRUE) != CT_SUCCESS) {
        ctconn_free_conn(worker->conn_info.conn);
        worker->conn_info.conn = NULL;
        worker->conn_info.stmt = NULL;
        return CT_ERROR;
    }

    /* set nologging option */
    if (g_load_opts.nologging) {
        CT_RETURN_IFERR(ctconn_prepare(worker->conn_info.stmt, "ALTER SESSION ENABLE NOLOGGING"));
        CT_RETURN_IFERR(ctconn_execute(worker->conn_info.stmt));
    }

    /* set up nls attr */
    cm_spin_lock(&GET_LOADER(worker)->conn_lock, NULL);
    ret = ctsql_setup_conn_nls(&g_conn_info, &worker->conn_info);
    cm_spin_unlock(&GET_LOADER(worker)->conn_lock);
 
    return ret;
}

status_t ctsql_worker_prepare(worker_t *worker)
{
    const char *pcharset_name = NULL;

    if (ctsql_worker_alloc_column_mem(worker) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (!worker->conn_info.is_conn) {
        (void)ctsql_print_disconn_error();
        return CT_ERROR;
    }

    /* Step 1. Set the charset based on the charset parameter of dump cmd */
    pcharset_name = cm_get_charset_name((charset_type_t)g_load_opts.charset_id);
    if (pcharset_name == NULL) {
        CT_THROW_ERROR(ERR_CLT_OBJECT_IS_NULL, "charset");
        return CT_ERROR;
    }

    (void)ctconn_set_conn_attr(worker->conn_info.conn, CTCONN_ATTR_CHARSET_TYPE, pcharset_name, (uint32)strlen(pcharset_name));

    /* Step 2. Prepare insert SQL for the loader */
    (void)ctconn_set_stmt_attr(worker->conn_info.stmt, CTCONN_ATTR_ALLOWED_BATCH_ERRS, &worker->allowed_batch_errs,
                            sizeof(uint32));
    if (ctconn_prepare(worker->conn_info.stmt, ((loader_t *)(worker)->loader)->insert_sql) != CTCONN_SUCCESS) {
        ctsql_print_error(worker->conn_info.conn);
        return CT_ERROR;
    }

    /* Step 3. Binding parameters on insert SQL */
    ctconn_set_paramset_size(worker->conn_info.stmt, worker->max_batch_rows);
    for (uint32 i = 0; i < ((loader_t *)(worker)->loader)->col_num; i++) {
        if (ctconn_bind_by_pos(worker->conn_info.stmt, i, ((loader_t *)(worker)->loader)->col_bndtype[i],
                            worker->col_data[i], ((loader_t *)(worker)->loader)->col_bndsz[i],
                            worker->col_ind[i]) != CTCONN_SUCCESS) {
            ctsql_print_error(worker->conn_info.conn);
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

status_t ctsql_worker_commit(worker_t *worker, uint64 id)
{
    if (worker->actual_batch_errs > worker->allowed_batch_errs) {
        return CT_SUCCESS;
    }

    // commit the data that are loaded into table
    if (worker->locat_info.curr_line_in_block > 0) {
        /* complete row do commit */
        if (ctconn_commit(worker->conn_info.conn) != CTCONN_SUCCESS) {
            ctsql_print_error(worker->conn_info.conn);
            return CT_ERROR;
        }
        worker->committed_rows = worker->loaded_rows;
    }

    return CT_SUCCESS;
}

#define GET_NEXT_STATUS(ret, next, err) \
    (ret) == CT_SUCCESS ? (next) : (err)

void ctsql_worker_proc(thread_t *thread)
{
    worker_t *worker = (worker_t *)thread->argument;
    status_t ret = CT_SUCCESS;

    while (CT_TRUE) {
        if (worker->closed || CTSQL_CANCELING) {
            worker->status = WORKER_STATUS_END;
        }

        switch (worker->status) {
            case WORKER_STATUS_INIT: {
                ret = ctsql_worker_init(worker);
                worker->status = GET_NEXT_STATUS(ret, WORKER_STATUS_RECV, WORKER_STATUS_ERR);
                break;
            }

            case WORKER_STATUS_RECV: {
                // read buffer from chan
                ret = cm_chan_recv_timeout(worker->chan, &worker->block, 2);
                if (ret == CT_TIMEDOUT) {
                    continue;
                }

                if (ret == CT_SUCCESS) {
                    worker->orig_block_buf = worker->block.buf.str;
                    CTSQL_LOAD_DEBUG("[Worker-Thread] recv block [%llu] size [%u]",
                                    worker->block.id, worker->block.buf.len);
                }

                worker->status = GET_NEXT_STATUS(ret, WORKER_STATUS_LOAD, WORKER_STATUS_END);
                break;
            }

            case WORKER_STATUS_LOAD: {
                worker->start_line = worker->block.start_line;

                ctconn_set_paramset_size(worker->conn_info.stmt, worker->max_batch_rows);
                // process data buffer
                ret = ctsql_worker_load(worker->conn_info.stmt, &worker->block.buf, worker);
                if (ret == CT_SUCCESS) {
                    ret = ctsql_worker_commit(worker, worker->block.id);
                    if (ret == CT_SUCCESS && worker->locat_info.curr_line_in_block > 0) {
                        ctsql_load_report_current((loader_t *)worker->loader);
                    }

                    if (worker->orig_block_buf != NULL) {
                        ctconn_common_free_fixed_buffer(&(GET_LOADER(worker)->block_pool), worker->orig_block_buf);
                        worker->orig_block_buf = NULL;
                    }

                    worker->block.buf.str = NULL;
                    worker->block.buf.len = 0;
                    worker->status = GET_NEXT_STATUS(ret, WORKER_STATUS_RECV, WORKER_STATUS_ERR);
                } else {
                    load_worker_post_nologging(worker);
                    worker->status = WORKER_STATUS_ERR;
                }
                break;
            }

            case WORKER_STATUS_END:
            case WORKER_STATUS_ERR:
            default:
                ctsql_worker_free(worker);
                return;
        }
    }
}

// launch workers
status_t ctsql_launch_workers(loader_t *loader)
{
    uint32 i = 0;
    status_t status = CT_SUCCESS;

    for (i = 0; i < g_load_opts.threads; i++) {
        loader->workers[i].id = i;
        loader->workers[i].chan = loader->chan[i];
        loader->workers[i].table = loader->table;
        loader->workers[i].loader = loader;
        loader->workers[i].closed = CT_FALSE;
        loader->workers[i].status = WORKER_STATUS_INIT;
        loader->workers[i].locat_info.curr_row = 0;
        loader->workers[i].locat_info.read_rows = 0;
        loader->workers[i].loaded_rows = 0;
        loader->workers[i].committed_rows = 0;
        loader->workers[i].error_rows = 0;
        loader->workers[i].allowed_batch_errs = loader->allowed_batch_errs;
        loader->workers[i].actual_batch_errs = 0;
        loader->workers[i].column_param = &loader->column_param;
        loader->workers[i].skip_rows = 0;
    }

    for (i = 0; i < g_load_opts.threads; i++) {
        status = cm_create_thread(ctsql_worker_proc, 0, &loader->workers[i], &loader->threads[i]);
        if (status != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

bool32 ctsql_if_all_workers_ok(loader_t *loader)
{
    uint32 i = 0;

    for (i = 0; i < g_load_opts.threads; i++) {
        if (loader->workers[i].status == WORKER_STATUS_ERR) {
            return CT_FALSE;
        }
    }

    return CT_TRUE;
}

bool32 ctsql_if_reach_allowed_errors(loader_t *loader)
{
    uint32 i = 0;
    uint32 total_batch_errs = 0;

    for (i = 0; i < g_load_opts.threads; i++) {
        total_batch_errs += loader->workers[i].actual_batch_errs;
        if (total_batch_errs > loader->allowed_batch_errs) {
            return CT_TRUE;
        }
    }

    return CT_FALSE;
}

uint32 ctsql_finished_workers(loader_t *loader)
{
    uint32 i = 0;
    uint32 sum = 0;

    for (i = 0; i < g_load_opts.threads; i++) {
        if (loader->workers[i].status == WORKER_STATUS_ERR) {
            loader->status = LOADER_STATUS_ERR;
            sum += 1;
        } else if (loader->workers[i].status == WORKER_STATUS_END) {
            sum += 1;
        }
    }

    return sum;
}

int ctsql_loader_wait_workers(loader_t *loader)
{
    uint32 i = 0;
    uint32 sum = 0;
    uint32 loop = 0;

    while (CT_TRUE) {
        sum = 0;
        for (i = 0; i < g_load_opts.threads; i++) {
            if (loader->workers[i].status == WORKER_STATUS_ERR) {
                CTSQL_PRINTF(ZSERR_LOAD, "worker init failed")
                return CT_ERROR;
            }

            if (loader->workers[i].status == WORKER_STATUS_RECV) {
                sum += 1;
            }
        }

        if (sum == g_load_opts.threads) {
            break;
        }

        cm_sleep(1);
        loop += 1;

        if (loop > WAIT_WORKER_THREAD_TIME) {
            CTSQL_PRINTF(ZSERR_LOAD, "worker init timeout (%u ms)", WAIT_WORKER_THREAD_TIME)
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

status_t ctsql_start_loading_thread(loader_t *loader)
{
    status_t ret = CT_SUCCESS;
    CT_RETURN_IFERR(ctsql_get_saved_pswd(g_load_pswd, sizeof(g_load_pswd)));

    do {
        if (ctsql_launch_workers(loader) != CT_SUCCESS) {
            CTSQL_PRINTF(ZSERR_LOAD, "launch workers failed")
            loader->status = LOADER_STATUS_ERR;
            ret = CT_ERROR;
            break;
        }

        if (ctsql_loader_wait_workers(loader) != CT_SUCCESS) {
            loader->status = LOADER_STATUS_ERR;
            ret = CT_ERROR;
            break;
        }
    } while (0);
    
    MEMS_RETURN_IFERR(memset_s(g_load_pswd, sizeof(g_load_pswd), 0, sizeof(g_load_pswd)));
    return ret;
}

void ctsql_cancel_loading(loader_t *loader)
{
    for (uint32 i = 0; i < g_load_opts.threads; i++) {
        (void)ctsql_conn_cancel(&loader->workers[i].conn_info);
    }
}

void ctsql_join_loading_thread(loader_t *loader)
{
    // shutdown thread while cancel
    if (CTSQL_CANCELING) {
        ctsql_cancel_loading(loader);
        ctsql_stop_workers(loader);
        loader->status = LOADER_STATUS_ERR;
        return;
    }
    // shutdown thread while error occurs
    if (loader->status == LOADER_STATUS_ERR) {
        ctsql_stop_workers(loader);
        return;
    }
    // wait all workers to finish
    while (CT_TRUE) {
        if (LOAD_OCCUR_ERROR(loader)) {
            loader->status = LOADER_STATUS_ERR;
            ctsql_stop_workers(loader);
            break;
        }

        if (ctsql_finished_workers(loader) == g_load_opts.threads) {
            break;
        }

        cm_sleep(10);
    }

    ctsql_stop_workers(loader);
    return;
}

void ctsql_loader_working(loader_t *loader)
{
    const uint32 file_buf_size = g_load_opts.max_filebuf_size;
    load_block_t block = { 0 };
    uint64 block_id = 0;
    EN_LOADER_READ_STATUS ret = LOADER_READ_OK;
    uint32 chan_index = 0;
    load_block_ctx_t block_ctx;
    text_t text_block;

    loader->status = LOADER_STATUS_OK;
    LOAD_RESET_BLOCK_CTX(&block_ctx);
    while (loader->status == LOADER_STATUS_OK && !CTSQL_CANCELING) {
        // malloc buffer for data.
        char *file_block = ctconn_common_alloc_fixed_buffer(&(loader->block_pool));
        if (file_block == NULL) {
            CTSQL_PRINTF(ZSERR_LOAD, "malloc failed, %u", file_buf_size);
            loader->status = LOADER_STATUS_ERR;
            break;
        }
        MEMS_RETVOID_IFERR(memset_s(file_block, file_buf_size + 1, 0, file_buf_size + 1));

        text_block.str = file_block;
        text_block.len = 0;

        ret = ctsql_loader_read_block(loader, &text_block, file_buf_size, &block_ctx);
        // error
        if (ret == LOADER_READ_ERR) {
            loader->status = LOADER_STATUS_ERR;
            break;
        }
        // reach end
        CT_BREAK_IF_TRUE(ret == LOADER_READ_END);

        block.start_line = loader->start_line;
        block.id = block_id;
        block.buf = text_block;

        // send data to the channel
        CTSQL_LOAD_DEBUG("[Send Block] ID %llu size %u to chan %u , start line %llu, %s row.", block.id, text_block.len,
            (chan_index % g_load_opts.threads), block.start_line,
            (block_ctx.is_complete_row ? "complete" : "part"));
        // errors occurs, stop sender
        if (LOAD_OCCUR_ERROR(loader)) {
            loader->status = LOADER_STATUS_ERR;
            break;
        }
        while (CT_TIMEDOUT == cm_chan_send_timeout(loader->chan[chan_index % g_load_opts.threads], &block, 2)) {
            if (LOAD_OCCUR_ERROR(loader)) {
                loader->status = LOADER_STATUS_ERR;
                break;
            }
            CT_BREAK_IF_TRUE(CTSQL_CANCELING);
        }

        if (block_ctx.is_complete_row) {
            chan_index++;
        }
        block_id++;
    }
    return;
}

status_t ctsql_pre_loading(loader_t *loader)
{
    // commit the pending transaction in main connection
    if (ctconn_commit(g_conn_info.conn) != CTCONN_SUCCESS) {
        ctsql_print_error(g_conn_info.conn);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

void ctsql_start_loading(loader_t *loader)
{
    if (ctsql_pre_loading(loader) != CT_SUCCESS) {
        ctsql_stop_workers(loader);
        return;
    }

    if (ctsql_start_loading_thread(loader) != CT_SUCCESS) {
        ctsql_stop_workers(loader);
        return;
    }

    ctsql_loader_working(loader);

    // stop chan sender
    ctsql_loader_close_chan(loader);

    // wait all workers to finish
    ctsql_join_loading_thread(loader);

    return;
}

static inline int ctsql_loader_prepare(loader_t *loader)
{
    /* Set the charset based on the charset parameter of dump cmd */
    if (ctsql_reset_charset(g_load_opts.charset_id, g_local_config.charset_id) != CT_SUCCESS) {
        return CT_ERROR;
    }

    /* Get descriptions of columns of the table */
    if (ctsql_loader_column_desc(loader) != CTCONN_SUCCESS) {
        return CTCONN_ERROR;
    }

    /*  Generate the insert SQL for the loader */
    return ctsql_loader_make_sql(loader);
}

static int ctsql_load_file(loader_t *loader)
{
    en_loader_status status;

    if (g_load_opts.threads < 1 || g_load_opts.threads > 128) {
        g_load_opts.threads = LOADER_DEFAULT_THREADS;
        CTSQL_PRINTF(ZSERR_LOAD, "threads should be in [1, 128]")
        return CTCONN_ERROR;
    }

    if (ctsql_loader_init(loader) != CTCONN_SUCCESS) {
        ctsql_loader_free(loader);
        return CTCONN_ERROR;
    }

    ctsql_loader_ignore_lines(loader);
    status = loader->status;
    if (status != LOADER_STATUS_OK) {
        ctsql_loader_free(loader);
        return status;
    }

    ctsql_start_loading(loader);

    status = loader->status;

    ctsql_load_report_summary(loader);

    ctsql_loader_free(loader);

    /* Restore CTSQL Client Character Set */
    if (ctsql_reset_charset(g_local_config.charset_id, g_load_opts.charset_id) != CT_SUCCESS) {
        return CTCONN_ERROR;
    }

    if (CTSQL_CANCELING) {
        CT_THROW_ERROR(ERR_OPERATION_CANCELED);
        ctsql_print_error(NULL);
        return CT_ERROR;
    }

    return (int)status;
}

static inline int ctsql_parse_loading_file(lex_t *lex, loader_t *loader)
{
    word_t word;
    if (lex_expected_fetch_word2(lex, "DATA", "INFILE") != CT_SUCCESS) {
        return CTCONN_ERROR;
    }

    if (lex_expected_fetch_enclosed_string(lex, &word) != CT_SUCCESS) {
        return CTCONN_ERROR;
    }
    cm_trim_text(&word.text.value);
    return cm_text2str(&word.text.value, loader->load_file, MAX_ENTITY_LEN);
}

static inline int ctsql_parse_loading_object(lex_t *lex, loader_t *loader)
{
    word_t word;
    text_buf_t tbl_name_buf;

    tbl_name_buf.max_size = MAX_ENTITY_LEN;
    tbl_name_buf.str = loader->table;
    tbl_name_buf.len = 0;

    if (lex_expected_fetch_word2(lex, "INTO", "TABLE") != CT_SUCCESS) {
        return CTCONN_ERROR;
    }

    if (lex_expected_fetch_tblname(lex, &word, &tbl_name_buf) != CT_SUCCESS) {
        return CTCONN_ERROR;
    }
    CM_NULL_TERM(&tbl_name_buf);

    return CTCONN_SUCCESS;
}

static int ctsql_insert_load_columns(load_option_t *load_opt, const text_t *obj_name, bool32 to_upper)
{
    char obj_name_buf[CTSQL_MAX_OBJECT_LEN] = "";
    char *object_name = obj_name_buf;

    if (load_opt->obj_list.count > CT_MAX_COLUMNS) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "the columns number exceed the maximum(%u)", CT_MAX_COLUMNS);
        return CT_ERROR;
    }

    if (obj_name->len > CTSQL_MAX_OBJECT_LEN) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "the object name is too long");
        return CT_ERROR;
    }

    if (to_upper) {
        cm_text2str_with_upper(obj_name, obj_name_buf, CTSQL_MAX_OBJECT_LEN);
    } else {
        CT_RETURN_IFERR(cm_text2str(obj_name, obj_name_buf, CTSQL_MAX_OBJECT_LEN));
    }

    return ctsql_generate_obj(&load_opt->obj_list, object_name);
}

status_t ctsql_parse_trail_columns(lex_t *lex, loader_t *loader, load_option_t *load_opt)
{
    word_t word;
    bool32 star_flag = CT_FALSE;
    bool32 end_flag = CT_FALSE;
    bool32 has_next = CT_FALSE;

    CT_RETURN_IFERR(lex_try_fetch(lex, "(", &star_flag));

    if (!star_flag) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "tariling columns missing \"(\"");
        return CT_ERROR;
    }

    CT_RETURN_IFERR(lex_fetch(lex, &word));

    while (word.type != WORD_TYPE_EOF) {
        has_next = CT_FALSE;
        end_flag = CT_FALSE;
        if (!IS_VARIANT(&word)) {
            CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "invalid column name was found");
            return CT_ERROR;
        }

        if (ctsql_insert_load_columns(load_opt, &word.text.value,
            !IS_DQ_STRING(word.type) && load_opt->is_case_insensitive) != CT_SUCCESS) {
            cm_set_error_loc(word.loc);
            return CT_ERROR;
        }

        CT_RETURN_IFERR(lex_try_fetch(lex, ",", &has_next));

        if (!has_next) {
            CT_RETURN_IFERR(lex_try_fetch(lex, ")", &end_flag));
            if (!end_flag) {
                CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "tariling columns missing \")\"");
                return CT_ERROR;
            }
            break;
        }

        if (lex_fetch(lex, &word) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (load_opt->obj_list.count == 0) {
        CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "no columns needs to be load");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

#define LOPT_FIELDS_ENCLOSED   0
#define LOPT_FIELDS_TERMINATED 10
#define LOPT_LINES_TERMINATED  20
#define LOPT_IGNORE            30
#define LOPT_THREADS           40
#define LOPT_ERRORS            50
#define LOPT_NOLOGGING         60
#define LOPT_DEBUG_ON          70
#define LOPT_CHARSET           80
#define LOPT_TRAILING_COLUMNS  90
#define LOPT_NULL_SPACE        100
#define LOPT_REPLACE           110
#define LOPT_SET_COLUMN        120
#define LOPT_DECRYPT           130
#define LOPT_CONV_JSONB        140

static inline int ctsql_parse_loading_options_ignore(lex_t *lex, load_option_t *load_opt, uint32 *matched_id)
{
    status_t ret;

    ret = lex_expected_fetch_uint64(lex, &load_opt->ignore_lines);
    if (ret == CT_SUCCESS) {
        ret = lex_expected_fetch_1of2(lex, "ROWS", "LINES", matched_id);
        CT_RETVALUE_IFTRUE(ret != CT_SUCCESS, CTCONN_ERROR);
    } else {
        load_opt->ignore = CT_TRUE;
    }
    return CTCONN_SUCCESS;
}

int ctsql_parse_loading_options(lex_t *lex, loader_t *loader, load_option_t *load_opt)
{
    status_t ret;
    uint32 matched_id;
    char opt_char;
    char terminate_str[TERMINATED_STR_ARRAY_SIZE] = { 0 };
    char *key_word_info = NULL;
    bool32 equal_flag = CT_TRUE;

    static const word_record_t opt_records[] = {
        { .id = LOPT_FIELDS_ENCLOSED,   .tuple = { 3, { "fields", "enclosed", "by" } } },
        { .id = LOPT_FIELDS_ENCLOSED,   .tuple = { 3, { "columns", "enclosed", "by" } } },
        { .id = LOPT_FIELDS_TERMINATED, .tuple = { 3, { "fields", "terminated", "by" } } },
        { .id = LOPT_FIELDS_TERMINATED, .tuple = { 3, { "columns", "terminated", "by" } } },
        { .id = LOPT_LINES_TERMINATED,  .tuple = { 3, { "lines", "terminated", "by" } } },
        { .id = LOPT_LINES_TERMINATED,  .tuple = { 3, { "rows", "terminated", "by" } } },
        { .id = LOPT_DECRYPT,           .tuple = { 2, { "decrypt", "by" } } },
        { .id = LOPT_IGNORE,            .tuple = { 1, { "IGNORE" } } },
        { .id = LOPT_THREADS,           .tuple = { 1, { "THREADS" } } },
        { .id = LOPT_ERRORS,            .tuple = { 1, { "ERRORS" } } },
        { .id = LOPT_NOLOGGING,         .tuple = { 1, { "NOLOGGING" } } },
        { .id = LOPT_DEBUG_ON,          .tuple = { 1, { "debug" } } },
        { .id = LOPT_CHARSET,           .tuple = { 1, { "CHARSET" } } },
        { .id = LOPT_TRAILING_COLUMNS,  .tuple = { 2, { "TRAILING", "COLUMNS" } } },
        { .id = LOPT_NULL_SPACE,        .tuple = { 1, { "NULL2SPACE" } } },
        { .id = LOPT_REPLACE,           .tuple = { 1, { "REPLACE" } } },
        { .id = LOPT_SET_COLUMN,        .tuple = { 1, { "SET" } } },
        { .id = LOPT_CONV_JSONB,        .tuple = { 1, { "CONVERT_JSONB" } } },
    };

#define LD_OPT_SIZE (sizeof(opt_records) / sizeof(word_record_t))

    do {
        ret = lex_try_match_records(lex, opt_records, LD_OPT_SIZE, &matched_id);
        CT_RETVALUE_IFTRUE(ret != CT_SUCCESS, CTCONN_ERROR);

        switch (matched_id) {
            case LOPT_FIELDS_ENCLOSED:
                ret = lex_expected_fetch_asciichar(lex, &opt_char, CT_TRUE);
                CT_RETVALUE_IFTRUE(ret != CT_SUCCESS, CTCONN_ERROR);

                load_opt->fields_enclosed = opt_char;

                ret = lex_try_fetch(lex, "OPTIONALLY", &load_opt->enclosed_optionally);
                CT_RETVALUE_IFTRUE(ret != CT_SUCCESS, CTCONN_ERROR);
                break;

            case LOPT_FIELDS_TERMINATED:
                key_word_info = "Column terminated string";
                ret = lex_expected_fetch_str(lex, terminate_str, sizeof(terminate_str) / sizeof(char) - 1,
                                             key_word_info);
                CT_RETVALUE_IFTRUE(ret != CT_SUCCESS, CTCONN_ERROR);

                MEMS_RETURN_IFERR(strncpy_s(load_opt->fields_terminated, TERMINATED_STR_ARRAY_SIZE, terminate_str,
                                            TERMINATED_STR_ARRAY_SIZE - 1));
                break;

            case LOPT_LINES_TERMINATED:
                key_word_info = "Line terminated string";
                ret = lex_expected_fetch_str(lex, terminate_str, sizeof(terminate_str) / sizeof(char) - 1,
                                             key_word_info);
                CT_RETVALUE_IFTRUE(ret != CT_SUCCESS, CTCONN_ERROR);
                MEMS_RETURN_IFERR(strncpy_s(load_opt->lines_terminated, TERMINATED_STR_ARRAY_SIZE, terminate_str,
                                            TERMINATED_STR_ARRAY_SIZE - 1));
                break;

            case LOPT_DECRYPT:
                key_word_info = "Decrypt pwd string";
                CT_RETURN_IFERR(ctsql_get_crypt_pwd(lex, load_opt->crypt_info.crypt_pwd, CT_PASSWD_MAX_LEN + 1, key_word_info));
                load_opt->crypt_info.crypt_flag = CT_TRUE;
                break;

            case LOPT_IGNORE:
                CT_RETURN_IFERR(ctsql_parse_loading_options_ignore(lex, load_opt, &matched_id));
                break;

            case LOPT_THREADS:
                ret = lex_expected_fetch_uint32(lex, &load_opt->threads);
                CT_RETVALUE_IFTRUE(ret != CT_SUCCESS, CTCONN_ERROR);
                break;

            case LOPT_ERRORS:
                ret = lex_expected_fetch_uint32(lex, &load_opt->allowed_batch_errs);
                CT_RETVALUE_IFTRUE(ret != CT_SUCCESS, CTCONN_ERROR);
                break;

            case LOPT_NOLOGGING:
                ctsql_printf("nologging load need to manual check database not in HA mode and parameter _RCY_CHECK_PCN is false.\n");
                load_opt->nologging = CT_TRUE;
                break;

            case LOPT_DEBUG_ON:
                load_opt->debug_on = CT_TRUE;
                break;

            case LOPT_CHARSET:
                CT_RETURN_IFERR(lex_try_fetch(lex, "=", &equal_flag));
                ret = lex_expected_fetch_1of2(lex, "UTF8", "GBK", &matched_id);
                CT_RETVALUE_IFTRUE(ret != CT_SUCCESS, CTCONN_ERROR);
                load_opt->charset_id = (matched_id == 0) ? CHARSET_UTF8 : CHARSET_GBK;
                break;

            case LOPT_TRAILING_COLUMNS:
                CT_RETURN_IFERR(ctsql_parse_trail_columns(lex, loader, load_opt));
                break;

            case LOPT_NULL_SPACE:
                load_opt->null2space = CT_TRUE;
                break;

            case LOPT_REPLACE:
                load_opt->replace = CT_TRUE;
                break;

            case LOPT_SET_COLUMN:
                lex_trim(lex->curr_text);
                MEMS_RETURN_IFERR(strncpy_s(load_opt->set_columns, MAX_LOAD_SQL_SIZE, lex->curr_text->str,
                                            lex->curr_text->len));
    
                (void)lex_skip(lex, lex->curr_text->len);

                if (strlen(load_opt->set_columns) == 0) {
                    CT_SRC_THROW_ERROR(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "set content is empty!");
                    return CTCONN_ERROR;
                }

                load_opt->set_flag = CT_TRUE;
                break;

            case LOPT_CONV_JSONB:
                load_opt->convert_jsonb = CT_TRUE;
                break;

            default:
                return CTCONN_SUCCESS;
        }
    } while (CT_TRUE);
}

static status_t ctsql_verify_loading_options(load_option_t *load_opts)
{
    if (strcmp(load_opts->fields_terminated, load_opts->lines_terminated) == 0) {
        CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR,
            "fields terminated string is the same to line terminated!");
        return CT_ERROR;
    }

    if (strlen(load_opts->lines_terminated) > 1 &&
        CM_STR_BEGIN_WITH(load_opts->fields_terminated, load_opts->lines_terminated)) {
        CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR,
            "fields terminated and line terminated are inclusive relationships!");
        return CT_ERROR;
    }

    if (strlen(load_opts->fields_terminated) > 1 &&
        CM_STR_BEGIN_WITH(load_opts->lines_terminated, load_opts->fields_terminated)) {
        CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR,
            "line terminated and fields terminated are inclusive relationships!");
        return CT_ERROR;
    }

    if (load_opts->replace && load_opts->ignore) {
        CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR,
            "replace and ignore can not appear at the same time!");
        return CT_ERROR;
    }

    if ((load_opts->allowed_batch_errs > 0 || load_opts->ignore) && load_opts->nologging) {
        ctsql_printf("WARNING: ERRORS or IGNORE can not be used with NOLOGGING, reset ERRORS to 0\n");
        load_opts->allowed_batch_errs = 0;
        load_opts->ignore = CT_FALSE;
    }

    return CT_SUCCESS;
}

static int ctsql_parse_loader(lex_t *lex, loader_t *loader)
{
    if (ctsql_parse_loading_file(lex, loader) != CTCONN_SUCCESS) {
        return CTCONN_ERROR;
    }

    if (ctsql_parse_loading_object(lex, loader) != CTCONN_SUCCESS) {
        return CTCONN_ERROR;
    }

    if (ctsql_parse_loading_options(lex, loader, &g_load_opts) != CTCONN_SUCCESS) {
        return CTCONN_ERROR;
    }

    CT_RETURN_IFERR(ctsql_verify_loading_options(&g_load_opts));

    return (lex_expected_end(lex) == CT_SUCCESS) ? CTCONN_SUCCESS : CTCONN_ERROR;
}

static inline int ctsql_reset_loader_charset(void)
{
    uint32 attr_len;
    uint32 buffer_len = 10;
    if (ctconn_get_conn_attr(CONN, CTCONN_ATTR_CHARSET_TYPE,
                          (void *)&g_load_opts.charset_id, buffer_len, &attr_len) != CT_SUCCESS) {
        ctsql_print_error(CONN);
        return CTCONN_ERROR;
    }

    return CTCONN_SUCCESS;
}

/* init some options before loading */
static inline int ctsql_reset_loader_opts(void)
{
    errno_t errcode;
    if (ctsql_reset_loader_charset() != CTCONN_SUCCESS) {
        return CTCONN_ERROR;
    }

    g_load_opts.enclosed_optionally = CT_FALSE;
    g_load_opts.fields_enclosed = CTSQL_DEFAULT_ENCLOSED_CHAR;
    /* default fields terminal is less than size of 'g_load_opts.fields_terminated' */
    errcode = strncpy_s(g_load_opts.fields_terminated, sizeof(g_load_opts.fields_terminated),
                        CTSQL_DEFAULT_FIELD_SEPARATOR_STR, strlen(CTSQL_DEFAULT_FIELD_SEPARATOR_STR));
    if (errcode != EOK) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
        return CTCONN_ERROR;
    }
    g_load_opts.fields_escape = '\\';
    errcode = strncpy_s(g_load_opts.lines_terminated, sizeof(g_load_opts.lines_terminated),
                        CTSQL_DEFAULT_LINE_SEPARATOR_STR, strlen(CTSQL_DEFAULT_LINE_SEPARATOR_STR));
    if (errcode != EOK) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
        return CTCONN_ERROR;
    }
    g_load_opts.ignore_lines = 0;
    g_load_opts.max_databuf_size = SIZE_M(1);
    g_load_opts.max_filebuf_size = FILE_BUFFER_SIZE;
    g_load_opts.auto_commit_rows = CTSQL_AUTO_COMMIT;
    g_load_opts.charset_id = CT_DEFAULT_LOCAL_CHARSET;
    g_load_opts.threads = LOADER_DEFAULT_THREADS;
    g_load_opts.allowed_batch_errs = 0;
    g_load_opts.nologging = 0;
    g_load_opts.debug_on = CT_FALSE;
    cm_reset_list(&g_load_opts.obj_list);
    cm_create_list(&g_load_opts.obj_list, CTSQL_MAX_OBJECT_LEN);
    MEMS_RETURN_IFERR(memset_s(g_load_opts.trailing_columns, MAX_LOAD_SQL_SIZE, 0, MAX_LOAD_SQL_SIZE));
    g_load_opts.null2space = CT_FALSE;
    g_load_opts.replace = CT_FALSE;
    g_load_opts.convert_jsonb = CT_FALSE;
    g_load_opts.ignore = CT_FALSE;
    MEMS_RETURN_IFERR(memset_s(g_load_opts.set_columns, MAX_LOAD_SQL_SIZE, 0, MAX_LOAD_SQL_SIZE));
    g_load_opts.set_flag = CT_FALSE;
    
    if (ctsql_reset_case_insensitive(&g_load_opts.is_case_insensitive) != CTCONN_SUCCESS) {
        return CTCONN_ERROR;
    }

    ctsql_reset_crypt_info(&g_load_opts.crypt_info);
    return CTCONN_SUCCESS;
}

static status_t ctsql_parse_load_help(lex_t *lex, bool8 *is_match)
{
    uint32 matched_id;

    *is_match = CT_FALSE;

    // devil number '6' here means 6 help command behind
    if (lex_try_fetch_1ofn(lex, &matched_id, 6, "-h", "-help", "help", "-u", "-usage", "usage") != CT_SUCCESS) {
        ctsql_print_error(NULL);
        return CT_ERROR;
    }
    if (matched_id != CT_INVALID_ID32) {
        ctsql_show_loader_usage();
        *is_match = CT_TRUE;
    }
    return CT_SUCCESS;
}

static status_t ctsql_parse_show_option(lex_t *lex, bool8 *is_match)
{
    uint32 matched_id;

    *is_match = CT_FALSE;
    
    if (lex_try_fetch_1of3(lex, "-o", "-option", "option", &matched_id) != CT_SUCCESS) {
        ctsql_print_error(NULL);
        return CT_ERROR;
    }
    if (matched_id != CT_INVALID_ID32) {
        ctsql_show_loader_opts();
        *is_match = CT_TRUE;
    }
    return CT_SUCCESS;
}

status_t ctsql_load(text_t *cmd_text)
{
    bool8 is_match;
    loader_t loader;
    lex_t lex;
    sql_text_t sql_text;
    sql_text.value = *cmd_text;
    sql_text.loc.line = 1;
    sql_text.loc.column = 1;
    status_t ret;

    if (!IS_CONN) {
        CTSQL_PRINTF(ZSERR_LOAD, "connection is not established");
        return CT_ERROR;
    }

    cm_reset_error();

    lex_trim(&sql_text);
    lex_init(&lex, &sql_text);

    MEMS_RETURN_IFERR(memset_s(&loader, sizeof(loader_t), 0, sizeof(loader_t)));

    if (lex_expected_fetch_word(&lex, "LOAD") != CT_SUCCESS) {
        ctsql_print_error(NULL);
        return CT_ERROR;
    }

    ret = ctsql_parse_load_help(&lex, &is_match);
    if (ret != CT_SUCCESS || is_match) {
        return ret;
    }

    ret = ctsql_parse_show_option(&lex, &is_match);
    if (ret != CT_SUCCESS || is_match) {
        return ret;
    }

    CT_RETURN_IFERR(ctsql_reset_loader_opts());

    if (ctsql_parse_loader(&lex, &loader) != CTCONN_SUCCESS) {
        ctsql_print_error(NULL);
        return CT_ERROR;
    }

    if (ctsql_set_session_interactive_mode(CT_FALSE) != CTCONN_SUCCESS) {
        ctsql_print_error(NULL);
        return CT_ERROR;
    }

    if (ctsql_load_file(&loader) != CT_SUCCESS) {
        load_post_nologging(&loader);
        ret = CT_ERROR;
    }
    
    CT_RETURN_IFERR(ctsql_set_session_interactive_mode(CT_TRUE));
    return ret;
}
