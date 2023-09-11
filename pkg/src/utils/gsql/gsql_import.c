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
 * gsql_import.c
 *
 *
 * IDENTIFICATION
 * src/utils/gsql/gsql_import.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_base.h"
#include "cm_defs.h"
#include "cm_utils.h"
#include "cm_signal.h"
#include "cm_util.h"
#include "cm_lex.h"
#include "gsql_common.h"
#include "gsql_import.h"

#ifdef WIN32
#include <windows.h>
#include <stdio.h>
#endif

#define IMP_OBJECT_END_FLAG (uint32)0xdbdbdbdb
char g_timing_log_buf[MAX_SQL_SIZE + 1];

static FILE *g_imp_logfile = (FILE *)NULL;
static spinlock_t g_imp_loglock = 0;

#define DEFAULT_IMP_FILE         "EXPDAT.DMP"
#define WAIT_WORKER_THREADS_TIME 20000
#define IMP_DEBUG_ON (g_imp_logfile != NULL)

#define IMP_RETRUN_IF_CANCEL                     \
    if (GSQL_CANCELING) {                        \
        GS_THROW_ERROR(ERR_OPERATION_CANCELED);  \
        return GS_ERROR;                         \
    }

static import_bin_t g_import_bin = {
    .tableName = "\0",
    .subFileName = "\0",
    .binBufIndex = 0,
    .binBufLen = 0,
    .compress_flag = GS_FALSE,
};

static importer_t g_importer = {
    .imp_type = IMP_MAX,
    .file_type = FT_TXT,
    .import_file = DEFAULT_IMP_FILE,
    .ddl_workers = NULL,
    .ddl_threads = NULL,
    .dml_workers = NULL,
    .dml_threads = NULL,
    .ddl_error = NULL,
    .log_file = "\0",
    .targetObj = "\0",
    .show = GS_FALSE,
    .feedback = GSQL_FEEDBACK,
    .content = CT_ALL,
    .ignore = GS_FALSE,
    .fileRows = 0,
    .startLine = 0,
    .rawBufLen = 0,
    .rawBufIndex = 0,
    .eof = GS_FALSE,
    .tblMatch = GS_FALSE,
    .tblMatched = GS_FALSE,
    .schemaMatch = SCHEMA_NONE,
    .schemaNum = 0,
    .fileInsertNum = 0,
    .create_user = GS_FALSE,
    .parallel = 1,
    .ddl_parallel = 1,
    .sql_index = 0,
    .nologging = 0,
    .timing = GS_FALSE,
    .batchRowCnt = MAX_IMP_BATCH_ROW_CNT,
    .disable_trigger = GS_FALSE,
    .imp_file_path = { 0 },
    .imp_subfile_path = { 0 },
};

static status_t imp_par_proc_block_multi_sql(imp_ddl_worker_t *worker, import_ddl_block *block);
static status_t imp_par_proc_block_single_sql(imp_ddl_worker_t *worker, import_ddl_block *block);
static status_t imp_par_proc_block_table_name(imp_ddl_worker_t *worker, import_ddl_block *block);
static status_t imp_par_proc_block_sub_file(imp_ddl_worker_t *worker, import_ddl_block *block);
static status_t imp_par_proc_block_sub_file_end(imp_ddl_worker_t *worker, import_ddl_block *block);
static status_t imp_par_proc_parent_block(imp_ddl_worker_t *worker, import_ddl_block *block);
static status_t imp_par_proc_block_profile(imp_ddl_worker_t *worker, import_ddl_block *block);

static status_t imp_serial_proc_block_multi_sql(imp_ddl_ctx_t *ctx, import_ddl_block *block);
static status_t imp_serial_proc_block_single_sql(imp_ddl_ctx_t *ctx, import_ddl_block *block);

static imp_ddl_proc_func_map_t g_ddl_func_map[] = {
    { IMP_BLOCK_END,            NULL, NULL },
    { IMP_BLOCK_TABLE,          imp_par_proc_block_multi_sql, NULL },
    { IMP_BLOCK_DROP_TABLE,     NULL, imp_serial_proc_block_multi_sql },
    { IMP_BLOCK_TABLE_NAME,     imp_par_proc_block_table_name, NULL },
    { IMP_BLOCK_SUB_FILE_LIST,  imp_par_proc_parent_block, NULL },
    { IMP_BLOCK_SUB_FILE,       imp_par_proc_block_sub_file, NULL },
    { IMP_BLOCK_SUB_FILE_END,   imp_par_proc_block_sub_file_end, NULL },
    { IMP_BLOCK_TABLE_INDEX,    imp_par_proc_block_multi_sql, NULL },
    { IMP_BLOCK_COMPLETE_TABLE, imp_par_proc_parent_block, NULL },
    { IMP_BLOCK_EXTKEY,         NULL, imp_serial_proc_block_multi_sql },
    { IMP_BLOCK_VIEW,           NULL, imp_serial_proc_block_single_sql },
    { IMP_BLOCK_SEQ,            NULL, imp_serial_proc_block_multi_sql },
    { IMP_BLOCK_FUNC,           imp_par_proc_block_single_sql, NULL },
    { IMP_BLOCK_SYNONYM,        NULL, imp_serial_proc_block_single_sql },
    { IMP_BLOCK_PACKAGE,        NULL, imp_serial_proc_block_single_sql },
    { IMP_BLOCK_PROFILE,        imp_par_proc_block_profile, NULL },
    { IMP_BLOCK_TYPE,           NULL, imp_serial_proc_block_single_sql },
};

static inline void imp_reset_statistic(importer_stat_t* stat)
{
    stat->lock = 0;
    stat->seq_num = 0;
    stat->table_num = 0;
    stat->table_record_num = 0;
    stat->ext_key_num = 0;
    stat->object_num = 0;
    stat->view_num = 0;
    stat->synonym_num = 0;
    stat->package_num = 0;
    stat->profile_num = 0;
    stat->type_num = 0;
}

static inline void imp_do_statistic(importer_stat_t* stat, en_ddl_block_type type)
{
    if (stat == NULL) {
        return;
    }

    cm_spin_lock(&stat->lock, NULL);
    switch (type) {
        case IMP_BLOCK_COMPLETE_TABLE:
            stat->table_num++;
            break;
        case IMP_BLOCK_EXTKEY:
            stat->ext_key_num++;
            break;
        case IMP_BLOCK_VIEW:
            stat->view_num++;
            break;
        case IMP_BLOCK_SEQ:
            stat->seq_num++;
            break;
        case IMP_BLOCK_FUNC:
            stat->object_num++;
            break;
        case IMP_BLOCK_SYNONYM:
            stat->synonym_num++;
            break;
        case IMP_BLOCK_PACKAGE:
            stat->package_num++;
            break;
        case IMP_BLOCK_PROFILE:
            stat->profile_num++;
            break;
        case IMP_BLOCK_TYPE:
            stat->type_num++;
            break;
        default:
            break;
    }
    cm_spin_unlock(&stat->lock);
}

static inline void imp_init_lex(lex_t *lex, text_t *sql_txt)
{
    sql_text_t sql_text;
    sql_text.value = *sql_txt;
    sql_text.loc.line = 1;
    sql_text.loc.column = 1;

    lex_trim(&sql_text);
    lex_init(lex, &sql_text);
    lex->call_version = gsc_get_call_version(CONN);
    lex_init_keywords();
}

static en_imp_sql_type imp_sql_type(text_t *sql)
{
    bool32 matched;
    lex_t lex;
    imp_init_lex(&lex, sql);

    if (lex_try_fetch2(&lex, "INSERT", "INTO", &matched) == GS_SUCCESS && matched) {
        return IMP_SQL_INSERT;
    }

    if (lex_try_fetch2(&lex, "CREATE", "USER", &matched) == GS_SUCCESS && matched) {
        return IMP_SQL_CREATE_USER;
    }

    if (lex_try_fetch4(&lex, "CREATE", "OR", "REPLACE", "PROFILE", &matched) == GS_SUCCESS && matched) {
        return IMP_SQL_CREATE_PROFILE;
    }

    if (lex_try_fetch4(&lex, "ALTER", "SESSION", "SET", "CURRENT_SCHEMA", &matched) == GS_SUCCESS && matched) {
        return IMP_SQL_ALTER_SESSION_SET_SCHEMA;
    }

    if (lex_try_fetch2(&lex, "ALTER", "SESSION", &matched) == GS_SUCCESS && matched) {
        return IMP_SQL_ALTER_SESSION_OTHER;
    }

    return IMP_SQL_OTHER;
}

void gsql_display_import_usage(void)
{
    gsql_printf("The syntax of logic import is: \n\n");
    gsql_printf("     Format:  IMP KEYWORD=value or KEYWORD=value1,value2,...,valueN;\n");
    gsql_printf("     Example: IMP TABLES=EMP,DEPT,MGR;\n");
    gsql_printf("               or IMP USERS=USER_A,USER_B;\n\n");
    gsql_printf("Keyword                 Description (Default)\n");
    gsql_printf("---------------------------------------------------------------------------------------------------------------------------\n");
    gsql_printf("USERS                   List of schema names, use %% to import all users\n");
    gsql_printf("TABLES                  List of table names, use %% to import all tables\n");
    gsql_printf("FILE                    Input file (EXPDAT.DMP) \n");
    gsql_printf("FILETYPE                input file type: (TXT), BIN\n");
    gsql_printf("LOG                     Log file of screen output\n");
    gsql_printf("REMAP_SCHEMA            Objects from one schema are loaded into another schema.\n");
    gsql_printf("SHOW                    Just list file contents (N) \n");
    gsql_printf("FEEDBACK                Feedback row count, feedback once if set 0 (10000)\n");
    gsql_printf("CONTENT                 Specifies data to load where the valid keyword, values are: (ALL), DATA_ONLY, and METADATA_ONLY. \n");
    gsql_printf("IGNORE                  Ignore create errors (N) \n");
    gsql_printf("FULL                    Import everything from source (N). \n");
    gsql_printf("REMAP_TABLESPACE        Tablespace objects are remapped to another tablespace. \n");
    gsql_printf("CREATE_USER             Import user definition (N). \n");
    gsql_printf("PARALLEL                Table data import parallelism settings, range 1~32, The default value is 1.\n");
    gsql_printf("DDL_PARALLEL            metadata import parallelism settings, range 1~32, The default value is 1.\n");
    gsql_printf("NOLOGGING               Insert data without redo and undo log (N) \n");
    gsql_printf("TIMING                  Display the time of importing each object, values are: (OFF), ON.\n");
    gsql_printf("BATCH_COUNT             Batch rows while filetype is BIN , range 1~10000, The default value is 10000.\n");
    gsql_printf("DISABLE_TRIGGER         Disable triggers on tables when import data (Y).\n");
    gsql_printf("DECRYPT                 Files will be decrypted.\n");
    gsql_printf("\n");
}

typedef enum {
    IOPT_USERS,
    IOPT_TABLES,
    IOPT_FILE,
    IOPT_FILETYPE,
    IOPT_LOG,
    IOPT_REMAP_SCHEMA,
    IOPT_REMAP_TABLESPACE,
    IOPT_SHOW,
    IOPT_FEEDBACK,
    IOPT_CONTENT,
    IOPT_IGNORE,
    IOPT_FULL,
    IOPT_CREATE_USER,
    IOPT_PARALLEL,
    IOPT_DDL_PARALLEL,
    IOPT_NOLOGGING,
    IOPT_TIMING,
    IOPT_BATCH,
    IOPT_DISABLE_TRIGGER,
    IOPT_DECRYPT
} imp_item_t;

static const word_record_t iopt_records[] = {
    { .id = IOPT_USERS,            .tuple = { 1, { "USERS" } } },
    { .id = IOPT_TABLES,           .tuple = { 1, { "TABLES" } } },
    { .id = IOPT_FILE,             .tuple = { 1, { "FILE" } } },
    { .id = IOPT_FILETYPE,         .tuple = { 1, { "FILETYPE" } } },
    { .id = IOPT_LOG,              .tuple = { 1, { "LOG" } } },
    { .id = IOPT_REMAP_SCHEMA,     .tuple = { 1, { "REMAP_SCHEMA" } } },
    { .id = IOPT_REMAP_TABLESPACE, .tuple = { 1, { "REMAP_TABLESPACE" } } },
    { .id = IOPT_SHOW,             .tuple = { 1, { "SHOW" } } },
    { .id = IOPT_FEEDBACK,         .tuple = { 1, { "FEEDBACK" } } },
    { .id = IOPT_CONTENT,          .tuple = { 1, { "CONTENT" } } },
    { .id = IOPT_IGNORE,           .tuple = { 1, { "IGNORE" } } },
    { .id = IOPT_FULL,             .tuple = { 1, { "FULL" } } },
    { .id = IOPT_CREATE_USER,      .tuple = { 1, { "CREATE_USER" } } },
    { .id = IOPT_PARALLEL,         .tuple = { 1, { "PARALLEL" } } },
    { .id = IOPT_DDL_PARALLEL,     .tuple = { 1, { "DDL_PARALLEL" } } },
    { .id = IOPT_NOLOGGING,        .tuple = { 1, { "NOLOGGING" } } },
    { .id = IOPT_TIMING,           .tuple = { 1, { "TIMING" } } },
    { .id = IOPT_BATCH,            .tuple = { 1, { "BATCH_COUNT" } } },
    { .id = IOPT_DISABLE_TRIGGER,  .tuple = { 1, { "DISABLE_TRIGGER" } } },
    { .id = IOPT_DECRYPT,          .tuple = { 1, { "DECRYPT" } } },
};

#define IMP_OPT_SIZE ELEMENT_COUNT(iopt_records)

static inline status_t imp_shallow_copy_ddl_block(import_ddl_block *src_block, import_ddl_block *dst_block)
{
    MEMS_RETURN_IFERR(memcpy_s(dst_block->schema, sizeof(dst_block->schema), src_block->schema,
        sizeof(src_block->schema)));
    dst_block->statistic = src_block->statistic;
    dst_block->sql_txt = src_block->sql_txt;
    dst_block->max_size = src_block->max_size;
    dst_block->type = src_block->type;
    return GS_SUCCESS;
}

void imp_trim_filename(const char *file_name, uint32 size, char *buf)
{
    cm_trim_filename(file_name, size, buf);
    if (cm_str_equal(file_name, buf)) {
        buf[0] = '\0';
    }
}

status_t imp_make_data_file_name(const char *file_path, const char *file_name, char *df_name, uint32 filename_len,
                                 uint32 max_len)
{
    char sub_file_path[GS_MAX_FILE_PATH_LENGH];
    uint32 len = (uint32)strlen(file_path) + (uint32)strlen(file_name);
    if (max_len < len) {
        GS_THROW_ERROR(ERR_CLT_IMP_DATAFILE, "the fullpath file name is too long");
        return GS_ERROR;
    }
    // no need to concat file_path and file_name, if the path is included by file_name
    imp_trim_filename(file_name, filename_len + 1, sub_file_path);
    if (cm_str_equal(file_path, (const char *)sub_file_path)) {
        PRTS_RETURN_IFERR(sprintf_s(df_name, max_len, "%s", file_name));
        df_name[filename_len] = '\0';
        return GS_SUCCESS;
    }

    PRTS_RETURN_IFERR(sprintf_s(df_name, max_len, "%s%s", file_path, file_name));
    df_name[len] = '\0';
    return GS_SUCCESS;
}

static status_t imp_get_data_file(const char *file_path, const char *file_name, char *df_name, uint32 filename_len,
    uint32 max_len)
{
    GS_RETURN_IFERR(imp_make_data_file_name(file_path, file_name, df_name, filename_len, max_len));

    if (g_import_bin.fileHead.fixed_head.client_ver >= EXP_CLI_VERSION_1) {
        if (!cm_file_exist(df_name)) {
            GSQL_PRINTF(ZSERR_IMPORT, "file '%s' does not exist\n", df_name);
            return GS_ERROR;
        }
    } else {
        if (!cm_file_exist(df_name)) {
            gsql_printf("Waring: the file %s doesn't exsit, we will get it from the previous directory\n", file_name);
            GS_RETURN_IFERR(imp_make_data_file_name(g_importer.imp_file_path, file_name, df_name,
                                                    filename_len, max_len));
            return GS_SUCCESS;
        }
    }

    return GS_SUCCESS;
}

static int imp_open_file(FILE **fp, const char *filename, gsc_z_stream *zstream, bool8 compressed)
{
    if (filename == NULL) {
        *fp = NULL;  // null for write the content into cmd
        return GSC_ERROR;
    }

    char path[GS_MAX_FILE_PATH_LENGH] = { 0x00 };
    GS_RETURN_IFERR(realpath_file(filename, path, GS_MAX_FILE_PATH_LENGH));

    *fp = fopen(path, "rb");
    if (*fp == NULL) {
        GS_THROW_ERROR(ERR_OPEN_FILE, filename, errno);
        return GS_ERROR;
    }

    if (g_importer.crypt_info.crypt_flag) {
        GS_RETURN_IFERR(gsql_set_encrpyt_fp(&g_importer.crypt_info, filename, cm_fileno(*fp)));
    }

    if (compressed &&
        gsc_common_z_init_read(*fp, zstream) != GS_SUCCESS) {
        GS_THROW_ERROR(ERR_CLT_IMP_DATAFILE, "init compressed file", filename);
        return GS_ERROR;
    }

    return GSC_SUCCESS;
}

static void imp_close_file(FILE **fp, gsc_z_stream *zstream, bool8 compressed)
{
    if (*fp != NULL) {
        if (gsql_reset_crypfile(*fp, &g_importer.crypt_info) != GS_SUCCESS) {
            GSQL_PRINTF(ZSERR_IMPORT, "failed to reset decrypt file fp !");
        }

        if (compressed) {
            (void)gsc_common_z_uninit_read(zstream);
        }

        fclose(*fp);
        *fp = NULL;
    }
}

static int imp_open_logger(const char *logfile)
{
    if (CM_IS_EMPTY_STR(logfile)) {
        g_imp_logfile = NULL;
        return GS_SUCCESS;
    }
    char path[GS_MAX_FILE_PATH_LENGH] = { 0x00 };
    char file_name[GS_MAX_FILE_PATH_LENGH] = { 0x00 };

    cm_trim_filename(logfile, GS_MAX_FILE_PATH_LENGH, path);
    cm_trim_dir(logfile, sizeof(file_name), file_name);
    
    if (strlen(path) != strlen(logfile) && !cm_dir_exist((const char *)path)) {
        GS_THROW_ERROR(ERR_PATH_NOT_EXIST, path);
        return GS_ERROR;
    } else if (file_name[0] == '\0') {
        GS_THROW_ERROR(ERR_CLT_INVALID_ATTR, "file name", logfile);
        return GS_ERROR;
    }

    GS_RETURN_IFERR(realpath_file(logfile, path, GS_MAX_FILE_PATH_LENGH));
    GS_RETURN_IFERR(cm_fopen(path, "w+", FILE_PERM_OF_DATA, &g_imp_logfile));
    return GS_SUCCESS;
}

static void imp_close_logger(void)
{
    if (g_imp_logfile != NULL) {
        fclose(g_imp_logfile);
        g_imp_logfile = NULL;
    }
}

static const char *imp_now()
{
    static char date_str[GS_MAX_TIME_STRLEN];
    (void)cm_timestamp2str(cm_now(), "YYYY-MM-DD HH24:MI:SS.FF3", date_str, sizeof(date_str));
    return date_str;
}

static char *imp_get_timestamp(char *date_str, uint32 len, date_t timestamp)
{
    (void)cm_timestamp2str(timestamp, "HH24:MI:SS.FF3", date_str, len);
    return date_str;
}

void imp_debug_log(char *fmt, ...)
{
    va_list var_list;

    if (!IMP_DEBUG_ON) {
        return;
    }

    cm_spin_lock(&g_imp_loglock, NULL);

    fprintf(g_imp_logfile, "[%s][%u]", imp_now(), cm_get_current_thread_id());
    va_start(var_list, fmt);
    vfprintf(g_imp_logfile, fmt, var_list);
    va_end(var_list);

    cm_spin_unlock(&g_imp_loglock);
}

void imp_log_sql(const char* prefix, const text_t *sql)
{
    text_t output_sql;

    if (!IMP_DEBUG_ON) {
        return;
    }

    gsql_regular_match_sensitive(sql->str, sql->len, &output_sql);
    imp_debug_log("%s : %.*s.\n", prefix, output_sql.len, output_sql.str);
}

/* write data debug log , try to print bind data. */
#define GSQL_IMP_DATA_DEBUG(fmt, ...)

/* write debug log */
#define GSQL_IMP_DEBUG(fmt, ...) imp_debug_log(fmt "\n", ##__VA_ARGS__);

/** Write msg into cmd or log file */
#define imp_log(fmt, ...)                                               \
    do {                                                                \
        gsql_printf(fmt, ##__VA_ARGS__);                                \
        imp_debug_log(fmt, ##__VA_ARGS__);                              \
    } while (0)

static inline void imp_timing_log(bool32 timing, char *fmt, ...)
{
    if (!timing) {
        return;
    }
    int32 len;
    va_list var_list;
    va_start(var_list, fmt);
    len = vsnprintf_s(g_timing_log_buf, MAX_SQL_SIZE + 1, MAX_SQL_SIZE, fmt, var_list);
    va_end(var_list);
    if (len < 0) {
        gsql_printf("Copy var_list to g_timing_log_buf failed under using import tool.\n");
        return;
    }
    g_timing_log_buf[len] = '\0';
    gsql_printf("%s", g_timing_log_buf);
}

void imp_tmlog_conn_error(gsc_conn_t conn)
{
    int code = 0;
    const char *message = "";
    source_location_t loc;

    gsql_get_error(conn, &code, &message, &loc);
    if (loc.line == 0) {
        imp_log("CT-%05d, %s\n", code, message);
    } else {
        imp_log("CT-%05d, [%d:%d]%s\n", code, (int)loc.line, (int)loc.column, message);
    }

    cm_reset_error();
}

static inline void imp_tmlog_error(const char* flow, const char* detail)
{
    int code = 0;
    const char *message = NULL;

    GS_THROW_ERROR(ERR_CLT_IMP_DATAFILE, flow, detail);

    cm_get_error(&code, &message, NULL);
    imp_log("CT-%05d, %s\n", code, message);
}

static void imp_tmlog_error_ex(const char* flow, const char* detailfmt, ...)
{
    char detail_buf[IMP_MAX_DETAIL_ERR_LEN];
    va_list var_list;
    int32 len;
    const char *too_long_detail = "detail info too long";

    va_start(var_list, detailfmt);
    len = vsnprintf_s(detail_buf, sizeof(detail_buf), sizeof(detail_buf) - 1, detailfmt, var_list);
    va_end(var_list);

    if (len < 0) {
        gsql_printf("Copy var_list to detail_buf failed under using import tool.\n");
        MEMS_RETVOID_IFERR(strncpy_s(detail_buf, sizeof(detail_buf), too_long_detail, strlen(too_long_detail)));
    }

    imp_tmlog_error(flow, detail_buf);
}

static status_t imp_init_ddl_block(import_ddl_block *block, en_ddl_block_type type,
    const char *schema, uint32 schema_len, importer_stat_t* stat)
{
    // set type
    block->type = type;

    // set schema
    block->schema[0] = '\0';
    if (schema_len > 0 && schema != NULL) {
        MEMS_RETURN_IFERR(memcpy_s(block->schema, sizeof(block->schema), schema, schema_len));
        block->schema[schema_len] = '\0';
    }

    // set statistic info
    block->statistic = stat;

    return GS_SUCCESS;
}


static status_t imp_construct_ddl_block(importer_t *importer, import_ddl_block *block, en_ddl_block_type type,
    const char *schema, uint32 schema_len, importer_stat_t* stat)
{
    fixed_memory_pool_t *pool = NULL;

    GS_RETURN_IFERR(imp_init_ddl_block(block, type, schema, schema_len, stat));

    // alloc block buffer
    if (type == IMP_BLOCK_SUB_FILE) {
        pool = &importer->ddl_subfile_pool;
    } else {
        pool = &importer->ddl_sql_block_pool;
    }
    block->sql_txt.str = gsc_common_alloc_fixed_buffer(pool);
    if (block->sql_txt.str == NULL) {
        GS_THROW_ERROR(ERR_CLT_IMP_DATAFILE, "construct DDL block", "Failed to construct DDL block buffer");
        return GS_ERROR;
    }

    block->max_size = pool->block_size;

    block->sql_txt.str[0] = 0;
    block->sql_txt.len = 0;
    return GS_SUCCESS;
}

static status_t imp_construct_ddl_block_ex(importer_t *importer, import_ddl_block *block, en_ddl_block_type type,
    const char *schema, uint32 schema_len, importer_stat_t* stat, uint32 max_size)
{
    if (max_size <= IMP_MAX_NORMAL_BLOCK_SIZE) {
        return imp_construct_ddl_block(importer, block, type, schema, schema_len, stat);
    }

    if (max_size > IMP_MAX_LARGE_BLOCK_SIZE) {
        GS_THROW_ERROR(ERR_CLT_IMP_DATAFILE, "too large block", "Failed to construct large DDL block buffer (>20M)");
        return GS_ERROR;
    }

    GS_RETURN_IFERR(imp_init_ddl_block(block, type, schema, schema_len, stat));
    block->max_size = max_size;
    block->sql_txt.str = (char*)malloc(max_size);
    if (block->sql_txt.str == NULL) {
        GS_THROW_ERROR(ERR_CLT_IMP_DATAFILE, "construct DDL block", "Failed to construct large DDL block buffer");
        return GS_ERROR;
    }

    block->sql_txt.str[0] = 0;
    block->sql_txt.len = 0;
    return GS_SUCCESS;
}

static bool8 imp_check_append_block(import_ddl_block *main_block)
{
    return ((main_block->sql_txt.len + 1) * sizeof(import_ddl_block)) <= main_block->max_size;
}

static void imp_free_ddl_block(importer_t *importer, import_ddl_block *block)
{
    fixed_memory_pool_t *pool = NULL;

    if (block->max_size > IMP_MAX_NORMAL_BLOCK_SIZE) {
        free(block->sql_txt.str);
        block->sql_txt.str = NULL;
        return;
    }

    // free block buffer
    if (block->type == IMP_BLOCK_SUB_FILE) {
        pool = &importer->ddl_subfile_pool;
    } else {
        pool = &importer->ddl_sql_block_pool;
    }

    gsc_common_free_fixed_buffer(pool, block->sql_txt.str);
    return;
}

static void imp_destory_ddl_block(importer_t *importer, import_ddl_block *block)
{
    import_ddl_block *sub_blocks = NULL;

    if (!INCLUDE_SUB_DDL_BLOCK(block)) {
        imp_free_ddl_block(importer, block);
    } else {
        sub_blocks = (import_ddl_block *)block->sql_txt.str;
        for (uint32 i = 0; i < block->sql_txt.len; i++) {
            imp_destory_ddl_block(importer, &(sub_blocks[i]));
        }
        imp_free_ddl_block(importer, block);
    }
}

static status_t imp_append_ddl_block(import_ddl_block *main_block, import_ddl_block *sub_block)
{
    import_ddl_block *towrite_block = NULL;

    if (!INCLUDE_SUB_DDL_BLOCK(main_block)) {
        GSQL_PRINTF(ZSERR_IMPORT, "ddl block do not support appending !");
        return GS_ERROR;
    }

    towrite_block = (import_ddl_block *)main_block->sql_txt.str;
    MEMS_RETURN_IFERR(memcpy_s(&towrite_block[main_block->sql_txt.len], sizeof(import_ddl_block), sub_block,
        sizeof(import_ddl_block)));

    main_block->sql_txt.len++;
    return GS_SUCCESS;
}

static status_t imp_remove_ddl_block(importer_t *importer, import_ddl_block *main_block, uint32 index)
{
    import_ddl_block *sub_blocks = NULL;

    if (!INCLUDE_SUB_DDL_BLOCK(main_block)) {
        GSQL_PRINTF(ZSERR_IMPORT, "ddl block do not support remove !");
        return GS_ERROR;
    }

    if (index >= main_block->sql_txt.len) {
        GSQL_PRINTF(ZSERR_IMPORT, "ddl block remove index out of bound !");
        return GS_ERROR;
    }

    sub_blocks = (import_ddl_block *)main_block->sql_txt.str;

    imp_destory_ddl_block(importer, &sub_blocks[index]);
    // copy blocks behind
    if (index < main_block->sql_txt.len - 1) {
        MEMS_RETURN_IFERR(memmove_s(&sub_blocks[index],
            sizeof(import_ddl_block) * (main_block->sql_txt.len - index - 1),
            &sub_blocks[index + 1],
            sizeof(import_ddl_block) * (main_block->sql_txt.len - index - 1)));
    }
    main_block->sql_txt.len--;
    return GS_SUCCESS;
}

static int gsql_insert_import_obj(importer_t *importer, const text_t *obj_name, bool32 to_upper)
{
    char obj_name_buf[GSQL_MAX_OBJECT_LEN] = "";
    char *object_name = obj_name_buf;

    if (obj_name->len >= GSQL_MAX_OBJECT_LEN) {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "the object name is too long");
        return GS_ERROR;
    }

    // copy user name
    if (to_upper) {
        if (importer->imp_type == IMP_SCHEMA &&
            cm_text_str_equal_ins(obj_name, "SYS")) {
            GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "can not import SYS schema");
            return GS_ERROR;
        }
        cm_text2str_with_upper(obj_name, obj_name_buf, GSQL_MAX_OBJECT_LEN);
    } else {
        GS_RETURN_IFERR(cm_text2str(obj_name, obj_name_buf, GSQL_MAX_OBJECT_LEN));
    }

    return gsql_generate_obj(&importer->obj_list, object_name);
}

static int imp_parse_schema(lex_t *lex, importer_t *importer)
{
    word_t word;
    bool32 all_flag = GS_FALSE;

    if (importer->imp_type != IMP_MAX) {
        GS_SRC_THROW_ERROR_EX(lex->loc, ERR_SQL_SYNTAX_ERROR, "USERS or TABLES has been provided");
        return GS_ERROR;
    }

    GS_RETURN_IFERR(lex_try_fetch(lex, "%", &all_flag));

    if (all_flag) {
        importer->imp_type = IMP_ALL_SCHEMAS;
        return GS_SUCCESS;
    }

    importer->imp_type = IMP_SCHEMA;

    GS_RETURN_IFERR(lex_fetch(lex, &word));

    while (word.type != WORD_TYPE_EOF) {
        bool32 has_next = GS_FALSE;
        if (!IS_VARIANT(&word)) {
            GS_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "invalid schema name was found");
            return GS_ERROR;
        }

        if (gsql_insert_import_obj(importer, &word.text.value, word.type != WORD_TYPE_DQ_STRING) != GS_SUCCESS) {
            cm_set_error_loc(word.loc);
            return GS_ERROR;
        }
        GS_RETURN_IFERR(lex_try_fetch(lex, ",", &has_next));

        if (!has_next) {
            break;
        }

        if (lex_fetch(lex, &word) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    if (importer->obj_list.count == 0) {
        GS_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "no object needs to import");
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static int imp_parse_tables(lex_t *lex, importer_t *importer)
{
    word_t word;
    bool32 all_flag = GS_FALSE;

    if (importer->imp_type != IMP_MAX) {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "USERS or TABLES has been provided");
        return GS_ERROR;
    }

    GS_RETURN_IFERR(lex_try_fetch(lex, "%", &all_flag));

    if (all_flag) {
        importer->imp_type = IMP_ALL_TABLES;
        return GS_SUCCESS;
    }

    importer->imp_type = IMP_TABLE;

    GS_RETURN_IFERR(lex_fetch(lex, &word));

    while (word.type != WORD_TYPE_EOF) {
        bool32 has_next = GS_FALSE;
        if (!IS_VARIANT(&word)) {
            GS_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "invalid table name was found");
            return GS_ERROR;
        }

        if (gsql_insert_import_obj(importer, &word.text.value, word.type != WORD_TYPE_DQ_STRING) != GS_SUCCESS) {
            cm_set_error_loc(word.loc);
            return GS_ERROR;
        }

        GS_RETURN_IFERR(lex_try_fetch(lex, ",", &has_next));

        if (!has_next) {
            break;
        }

        if (lex_fetch(lex, &word) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    if (importer->obj_list.count == 0) {
        GS_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "no object needs to import");
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static int imp_parse_remap_schema(lex_t *lex, importer_t *importer)
{
    word_t word;

    if (importer->imp_type != IMP_MAX) {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "USERS has been provided");
        return GS_ERROR;
    }

    importer->imp_type = IMP_REMAP_SCHEMA;
    GS_RETURN_IFERR(lex_fetch(lex, &word));

    while (word.type != WORD_TYPE_EOF) {
        bool32 has_next = GS_FALSE;
        if (!IS_VARIANT(&word)) {
            GS_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "invalid schema name was found");
            return GS_ERROR;
        }

        if (gsql_insert_import_obj(importer, &word.text.value, word.type != WORD_TYPE_DQ_STRING) != GS_SUCCESS) {
            cm_set_error_loc(word.loc);
            return GS_ERROR;
        }
        GS_RETURN_IFERR(lex_try_fetch(lex, ",", &has_next));

        if (!has_next) {
            break;
        }

        if (lex_fetch(lex, &word) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    GS_RETURN_IFERR(lex_expected_fetch_word(lex, ":"));
    GS_RETURN_IFERR(lex_fetch(lex, &word));
    GS_RETURN_IFERR(cm_text2str(&word.text.value, importer->targetObj, GSQL_MAX_OBJECT_LEN));

    if (importer->obj_list.count == 0) {
        GS_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "no object needs to import");
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static int imp_parse_full(lex_t *lex, importer_t *importer)
{
    uint32 matched_id;
    if (importer->imp_type != IMP_MAX) {
        GS_SRC_THROW_ERROR_EX(lex->loc, ERR_SQL_SYNTAX_ERROR, "USERS or TABLES has been provided");
        return GS_ERROR;
    }
    GS_RETURN_IFERR(lex_expected_fetch_1of2(lex, "Y", "N", &matched_id));
    if (matched_id == 0) {
        importer->imp_type = IMP_FULL;
    }
    return GS_SUCCESS;
}

static int imp_parse_remap_tblspace(lex_t *lex, importer_t *importer)
{
    word_t word;
    bool32 has_next;
    re_map_t *tbl_space_map = NULL;
    char src_tabspace[GS_MAX_NAME_LEN + 1];
    char dst_tabspace[GS_MAX_NAME_LEN + 1];

    GS_RETURN_IFERR(lex_fetch(lex, &word));
    while (word.type != WORD_TYPE_EOF) {
        has_next = GS_FALSE;
        if (!IS_VARIANT(&word)) {
            GS_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "invalid source tablespace name %s was found",
                                  W2S(&word));
            return GS_ERROR;
        }

        MEMS_RETURN_IFERR(strncpy_s(src_tabspace, sizeof(src_tabspace), W2S(&word), word.text.len));

        if (find_remap(&importer->tblSpaceMaps, src_tabspace, dst_tabspace, sizeof(dst_tabspace))) {
            GS_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "duplicate source tablespace name %s was found",
                                  src_tabspace);
            return GS_ERROR;
        }

        GS_RETURN_IFERR(lex_expected_fetch_word(lex, ":"));
        GS_RETURN_IFERR(lex_fetch(lex, &word));
        if (!IS_VARIANT(&word)) {
            GS_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR,
                                  "invalid destination tablespace name %s was found", W2S(&word));
            return GS_ERROR;
        }

        MEMS_RETURN_IFERR(strncpy_s(dst_tabspace, sizeof(dst_tabspace), W2S(&word), word.text.len));
        GS_RETURN_IFERR(cm_list_new(&importer->tblSpaceMaps, (void *)&tbl_space_map));
        MEMS_RETURN_IFERR(strncpy_s(tbl_space_map->src, sizeof(tbl_space_map->src),
            src_tabspace, strlen(src_tabspace)));
        MEMS_RETURN_IFERR(strncpy_s(tbl_space_map->dest, sizeof(tbl_space_map->dest),
            dst_tabspace, strlen(dst_tabspace)));
        GS_RETURN_IFERR(lex_try_fetch(lex, ",", &has_next));
        if (!has_next) {
            break;
        }

        if (lex_fetch(lex, &word) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static void imp_print_remap_tblspace(importer_t *importer)
{
    if (importer->tblSpaceMaps.count > 0) {
        imp_log("-- REMAP TABLESPACE = ");
        uint32 i;
        re_map_t *tbl_space_map = NULL;
        for (i = 0; i < importer->tblSpaceMaps.count; i++) {
            if (i != 0) {
                imp_log(", ");
            }
            tbl_space_map = (re_map_t *)cm_list_get(&importer->tblSpaceMaps, i);
            imp_log("%s", tbl_space_map->src);
            imp_log(":");
            imp_log("%s", tbl_space_map->dest);
        }
        imp_log("\n");
    }
}
int imp_parse_opts(lex_t *lex, importer_t *importer)
{
    uint32 matched_id;
    word_t word;
    char *key_word_info = NULL;

    while (!lex_eof(lex)) {
        GS_RETURN_IFERR(lex_try_match_records(lex, iopt_records, IMP_OPT_SIZE, (uint32 *)&matched_id));

        if (matched_id == GS_INVALID_ID32) {
            GS_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "invalid option for IMPORT");
            return GS_ERROR;
        }

        GS_RETURN_IFERR(lex_expected_fetch_word(lex, "="));

        switch (matched_id) {
            case IOPT_USERS:
                GS_RETURN_IFERR(imp_parse_schema(lex, importer));
                break;

            case IOPT_TABLES:
                GS_RETURN_IFERR(imp_parse_tables(lex, importer));
                break;

            case IOPT_FILE:
                if (lex_expected_fetch_enclosed_string(lex, &word) != GS_SUCCESS) {
                    return GSC_ERROR;
                }
                GS_RETURN_IFERR(cm_text2str(&word.text.value, importer->import_file, GS_MAX_FILE_PATH_LENGH));
                break;

            case IOPT_FILETYPE:
                GS_RETURN_IFERR(lex_expected_fetch_1of2(lex, "BIN", "TXT", &matched_id));
                importer->file_type = (matched_id == 0) ? FT_BIN : FT_TXT;
                break;

            case IOPT_LOG:
                if (lex_expected_fetch_dqstring(lex, &word) != GS_SUCCESS) {
                    GS_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "use double quotes for LOG");
                    return GS_ERROR;
                }
                GS_RETURN_IFERR(cm_text2str(&word.text.value, importer->log_file, GS_MAX_FILE_PATH_LENGH));
                break;

            case IOPT_REMAP_SCHEMA:
                GS_RETURN_IFERR(imp_parse_remap_schema(lex, importer));
                break;

            case IOPT_SHOW:
                GS_RETURN_IFERR(lex_expected_fetch_1of2(lex, "Y", "N", &matched_id));
                importer->show = (matched_id == 0) ? GS_TRUE : GS_FALSE;
                break;

            case IOPT_FEEDBACK:
                GS_RETURN_IFERR(lex_expected_fetch_uint32(lex, &(importer->feedback)));
                break;
            case IOPT_CONTENT:
                GS_RETURN_IFERR(lex_expected_fetch_1of3(lex, "ALL", "DATA_ONLY", "METADATA_ONLY", &matched_id));
                importer->content = (matched_id == 0) ? CT_ALL : (matched_id == 1 ? CT_DATA_ONLY : CT_METADATA_ONLY);
                break;
            case IOPT_IGNORE:
                GS_RETURN_IFERR(lex_expected_fetch_1of2(lex, "Y", "N", &matched_id));
                importer->ignore = (matched_id == 0) ? GS_TRUE : GS_FALSE;
                break;
            case IOPT_FULL:
                GS_RETURN_IFERR(imp_parse_full(lex, importer));
                break;
            case IOPT_REMAP_TABLESPACE:
                GS_RETURN_IFERR(imp_parse_remap_tblspace(lex, importer));
                break;
            case IOPT_CREATE_USER:
                GS_RETURN_IFERR(lex_expected_fetch_1of2(lex, "Y", "N", &matched_id));
                importer->create_user = (matched_id == 0) ? GS_TRUE : GS_FALSE;
                break;
            case IOPT_PARALLEL:
                GS_RETURN_IFERR(lex_expected_fetch_uint32(lex, &(importer->parallel)));
                break;
            case IOPT_DDL_PARALLEL:
                GS_RETURN_IFERR(lex_expected_fetch_uint32(lex, &(importer->ddl_parallel)));
                break;
            case IOPT_NOLOGGING:
                GS_RETURN_IFERR(lex_expected_fetch_1of2(lex, "Y", "N", &matched_id));
                importer->nologging = (matched_id == 0) ? GS_TRUE : GS_FALSE;
                if (importer->nologging) {
                    gsql_printf("nologging load need to manual check database not in HA mode and parameter _RCY_CHECK_PCN is false.\n");
                }
                break;
            case IOPT_TIMING:
                GS_RETURN_IFERR(lex_expected_fetch_1of2(lex, "ON", "OFF", &matched_id));
                importer->timing = (matched_id == 0) ? GS_TRUE : GS_FALSE;
                break;
            case IOPT_BATCH:
                GS_RETURN_IFERR(lex_expected_fetch_uint32(lex, &(importer->batchRowCnt)));
                break;
            case IOPT_DISABLE_TRIGGER:
                GS_RETURN_IFERR(lex_expected_fetch_1of2(lex, "Y", "N", &matched_id));
                importer->disable_trigger = (matched_id == 0) ? GS_TRUE : GS_FALSE;
                break;
            case IOPT_DECRYPT: {
                key_word_info = "Decrypt pwd string";
                GS_RETURN_IFERR(gsql_get_crypt_pwd(lex, importer->crypt_info.crypt_pwd, GS_PASSWD_MAX_LEN + 1, key_word_info));
                importer->crypt_info.crypt_flag = GS_TRUE;
                break;
            }
            default:
                break;
        }
        GS_RETURN_IFERR(lex_skip_comments(lex, NULL));
    }

    return lex_expected_end(lex);
}

void imp_reset_opts(importer_t *importer)
{
    importer->imp_type = IMP_MAX;
    importer->file_type = FT_TXT;
    cm_reset_list(&importer->obj_list);
    cm_create_list(&importer->obj_list, GSQL_MAX_OBJECT_LEN);
    MEMS_RETVOID_IFERR(strncpy_s(importer->import_file, GS_MAX_FILE_PATH_LENGH, DEFAULT_IMP_FILE, strlen(DEFAULT_IMP_FILE)));

    MEMS_RETVOID_IFERR(memset_s(importer->log_file, GS_MAX_FILE_PATH_LENGH, 0, GS_MAX_FILE_PATH_LENGH));
    MEMS_RETVOID_IFERR(memset_s(importer->targetObj, GSQL_MAX_OBJECT_LEN, 0, GSQL_MAX_OBJECT_LEN));
    importer->show = GS_FALSE;
    importer->feedback = GSQL_FEEDBACK;
    importer->content = CT_ALL;
    importer->ignore = GS_FALSE;
    cm_reset_list(&importer->tblSpaceMaps);
    cm_create_list(&importer->tblSpaceMaps, sizeof(re_map_t));
    importer->fileRows = 0;
    importer->startLine = 0;
    importer->rawBufLen = 0;
    importer->rawBufIndex = 0;
    importer->eof = GS_FALSE;
    importer->tblMatch = GS_FALSE;
    importer->tblMatched = GS_FALSE;
    importer->schemaMatch = SCHEMA_NONE;
    importer->schemaNum = 0;
    importer->fileInsertNum = 0;
    importer->create_user = GS_FALSE;
    importer->parallel = 1;
    importer->ddl_parallel = 1;
    importer->sql_index = 0;
    importer->singleSchema[0] = '\0';
    importer->fatal_error = GS_FALSE;
    importer->nologging = GS_FALSE;
    importer->timing = GS_FALSE;
    importer->batchRowCnt = MAX_IMP_BATCH_ROW_CNT;
    importer->disable_trigger = GS_TRUE;
    importer->impfp = NULL;

    gsql_reset_crypt_info(&importer->crypt_info);
}

static inline void imp_reset_bin_opts(import_bin_t *imp_bin)
{
    MEMS_RETVOID_IFERR(memset_s(&imp_bin->fileHead, sizeof(imp_bin_fd_t), 0, sizeof(imp_bin_fd_t)));
    MEMS_RETVOID_IFERR(memset_s(&imp_bin->tableName, sizeof(imp_bin->tableName), 0, sizeof(imp_bin->tableName)));
    MEMS_RETVOID_IFERR(memset_s(&imp_bin->subFileName, sizeof(imp_bin->subFileName), 0, sizeof(imp_bin->subFileName)));

    imp_bin->schemaNum = 0;
    imp_bin->seqNum = 0;
    imp_bin->tableNum = 0;
    imp_bin->tableInfoLen = 0;
    imp_bin->tableNameLen = 0;
    imp_bin->recordNum = 0;
    imp_bin->fieldNum = 0;
    imp_bin->subFileNum = 0;
    imp_bin->fileNameLen = 0;
    imp_bin->indexLen = 0;
    imp_bin->extKeyLen = 0;
    imp_bin->viewLen = 0;
    imp_bin->funcLen = 0;
    imp_bin->binBufIndex = 0;
    imp_bin->binBufLen = 0;
    imp_bin->seqNum = 0;
    imp_bin->extKeyNum = 0;
    imp_bin->funcNum = 0;
    imp_bin->viewNum = 0;
    imp_bin->extKeyTotalLen = 0;
    imp_bin->viewTotalLen = 0;
    imp_bin->funcTotalLen = 0;
    imp_bin->seqTotalLen = 0;

    cm_reset_list(&imp_bin->fieldInfo);
    cm_create_list(&imp_bin->fieldInfo, sizeof(field_info_t));
}

static void gsql_import_print_options(importer_t *importer)
{
    char *impType[] = { "SCHEMA", "TABLE", "ALL_TABLES", "ALL_SCHEMAS", "REMAP_SCHEMA", "FULL", "NONE" };
    char *content_mode[] = { "DATA_ONLY", "METADATA_ONLY", "ALL" };

    char *str = impType[importer->imp_type];

    imp_log("-- IMPORT TYPE = %s\n", str);
    if (importer->imp_type == IMP_REMAP_SCHEMA) {
        imp_log("-- REMAP SCHEMA = ");
    } else {
        imp_log("-- IMPORT OBJECTS = ");
    }

    for (uint32 i = 0; i < importer->obj_list.count; i++) {
        if (i != 0) {
            imp_log(", ");
        }
        str = (char *)cm_list_get(&importer->obj_list, i);
        imp_log(str);
    }

    if (importer->imp_type == IMP_REMAP_SCHEMA) {
        imp_log(":%s", importer->targetObj);
    }
    imp_log("\n");
    imp_log("-- DUMP FILE = %s\n", importer->import_file);
    imp_log("-- LOG FILE = %s\n", importer->log_file);
    imp_print_remap_tblspace(importer);

    str = (importer->file_type == FT_TXT) ? "TXT" : "BIN";
    imp_log("-- FILE TYPE = %s\n", str);

    str = importer->show ? "Y" : "N";
    imp_log("-- SHOW = %s\n", str);
    imp_log("-- FEEDBACK = %u\n", importer->feedback);
    imp_log("-- PARALLEL = %u\n", importer->parallel);
    imp_log("-- DDL_PARALLEL = %u\n", importer->ddl_parallel);
    imp_log("-- CONTENT_MODE = %s\n", content_mode[importer->content - 1]);
    str = importer->ignore ? "Y" : "N";
    imp_log("-- IGNORE = %s\n", str);
    str = importer->create_user ? "Y" : "N";
    imp_log("-- CREATE_USER = %s\n", str);
    str = importer->timing ? "ON" : "OFF";
    imp_log("-- TIMING = %s\n", str);
    imp_log("-- BATCH_COUNT = %u\n", importer->batchRowCnt);
    str = importer->disable_trigger ? "Y" : "N";
    imp_log("-- DISABLE_TRIGGER = %s\n", str);
    str = importer->nologging ? "Y" : "N";
    imp_log("-- NOLOGGING = %s\n", str);
    imp_log("\n");
}

static inline int imp_verify_schema(list_t *user_list)
{
    for (uint32 i = 0; i < user_list->count; i++) {
        uint32 rows;
        char *user = (char *)cm_list_get(user_list, i);

        // if self user import self , verify success.
        if (cm_str_equal(user, USER_NAME)) {
            continue;
        }

        char *cmd_sql =
            (char *)"SELECT * "
            "FROM " IMP_USERS_AGENT " "
            "WHERE USERNAME = UPPER(:p1)";

        GS_RETURN_IFERR(gsc_prepare(STMT, cmd_sql));
        GS_RETURN_IFERR(gsc_bind_by_pos(STMT, 0, GSC_TYPE_STRING, user, (int32)strlen(user), NULL));
        GS_RETURN_IFERR(gsc_execute(STMT));
        GS_RETURN_IFERR(gsc_fetch(STMT, &rows));
        if (rows == 0) {
            GS_THROW_ERROR(ERR_OBJECT_NOT_EXISTS, "user", user);
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static inline int imp_verify_remap_schema(char *user)
{
    uint32 rows;
    char *cmd_sql =
        (char *)"SELECT * "
        "FROM " IMP_USERS_AGENT " "
        "WHERE USERNAME = UPPER(:p1)";

    GS_RETURN_IFERR(gsc_prepare(STMT, cmd_sql));
    GS_RETURN_IFERR(gsc_bind_by_pos(STMT, 0, GSC_TYPE_STRING, user, (int32)strlen(user), NULL));
    GS_RETURN_IFERR(gsc_execute(STMT));
    GS_RETURN_IFERR(gsc_fetch(STMT, &rows));

    if (rows == 0) {
        GS_THROW_ERROR(ERR_OBJECT_NOT_EXISTS, "user", user);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static int imp_verify_tables(list_t *tbl_list, const char* curr_schema)
{
    for (uint32 i = 0; i < tbl_list->count; i++) {
        uint32 rows;
        char *tbl_name = (char *)cm_list_get(tbl_list, i);
        char *cmd_sql =
            (char *)"SELECT 1 "
            "FROM " IMP_TABLES_AGENT " "
            "WHERE OWNER = UPPER(:p1) AND TABLE_NAME = :p2";

        GS_RETURN_IFERR(gsc_prepare(STMT, cmd_sql));
        GS_RETURN_IFERR(gsc_bind_by_pos(STMT, 0, GSC_TYPE_STRING, curr_schema, (int32)strlen(curr_schema), NULL));
        GS_RETURN_IFERR(gsc_bind_by_pos(STMT, 1, GSC_TYPE_STRING, tbl_name, (int32)strlen(tbl_name), NULL));
        GS_RETURN_IFERR(gsc_execute(STMT));
        GS_RETURN_IFERR(gsc_fetch(STMT, &rows));
        if (rows == 0) {
            GS_THROW_ERROR(ERR_OBJECT_NOT_EXISTS, "table", tbl_name);
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static int imp_check_privilege(importer_t *importer, const char* curr_schema)
{
    char *user = NULL;

    if (cm_str_equal("SYS", USER_NAME)) {
        return GS_SUCCESS;
    }

    // only import user or table need privilege check.
    if (importer->imp_type > IMP_ALL_SCHEMAS) {
        return GS_SUCCESS;
    }
    
    bool8 is_dba;
    GS_RETURN_IFERR(gsql_check_dba_user(&is_dba));
    if (is_dba) {
        return GS_SUCCESS;
    }

    // if normal user, can not import other user table data by alter session current_schema
    if (importer->imp_type == IMP_TABLE || importer->imp_type == IMP_ALL_TABLES) {
        if (!cm_str_equal(curr_schema, USER_NAME)) {
            GS_THROW_ERROR(ERR_INSUFFICIENT_PRIV);
            return GS_ERROR;
        }
        return GS_SUCCESS;
    }
    
    if (importer->imp_type == IMP_ALL_SCHEMAS) {
        GS_THROW_ERROR(ERR_INSUFFICIENT_PRIV);
        return GS_ERROR;
    }

    for (uint32 i = 0; i < importer->obj_list.count; i++) {
        user = (char *)cm_list_get(&importer->obj_list, i);
        if (!cm_str_equal(user, USER_NAME)) {
            GS_THROW_ERROR(ERR_INSUFFICIENT_PRIV);
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static int imp_verify_opts(importer_t *importer, const char* curr_schema)
{
    if (importer->parallel < 1 || importer->parallel > PAR_IMP_MAX_THREADS) {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "threads should be in [1, %u]", PAR_IMP_MAX_THREADS);
        return GS_ERROR;
    }

    if (importer->ddl_parallel < 1 || importer->ddl_parallel > PAR_IMP_MAX_THREADS) {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "threads should be in [1, %u]", PAR_IMP_MAX_THREADS);
        return GS_ERROR;
    }

    if (importer->batchRowCnt < 1 || importer->batchRowCnt > MAX_IMP_BATCH_ROW_CNT) {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "BATCH_COUNT should be in [1, %u]", MAX_IMP_BATCH_ROW_CNT);
        return GS_ERROR;
    }

    if (importer->imp_type == IMP_MAX) {
        text_t curr_user;

        imp_log(IMP_INDENT "default to import current schema: %s\n", USER_NAME);
        importer->imp_type = IMP_SCHEMA;
        cm_str2text(USER_NAME, &curr_user);
        GS_RETURN_IFERR(gsql_insert_import_obj(importer, &curr_user, GS_TRUE));
    } else if (importer->imp_type == IMP_TABLE) {
        imp_log(IMP_INDENT "verify tables ...\n");
        if (cm_str_equal_ins("SYS", curr_schema)) {
            GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "can not import SYS schema");
            return GS_ERROR;
        }
        if (importer->content == CT_DATA_ONLY) {
            GS_RETURN_IFERR(imp_verify_tables(&importer->obj_list, curr_schema));
        }
    } else if (importer->imp_type == IMP_ALL_TABLES) {
        imp_log(IMP_INDENT "verify tables ...\n");
        if (cm_str_equal_ins("SYS", curr_schema)) {
            GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "can not import SYS schema");
            return GS_ERROR;
        }
    } else if (importer->imp_type == IMP_SCHEMA) {
        imp_log(IMP_INDENT "verify schema ...\n");
        if (!importer->create_user) {
            GS_RETURN_IFERR(imp_verify_schema(&importer->obj_list));
        }
    } else if (importer->imp_type == IMP_REMAP_SCHEMA) {
        imp_log(IMP_INDENT "verify remap schema ...\n");
        if (!importer->create_user) {
            GS_RETURN_IFERR(imp_verify_remap_schema(importer->targetObj));
        }
    }

    // check privilege
    GS_RETURN_IFERR(imp_check_privilege(importer, curr_schema));

    return GS_SUCCESS;
}

void gsql_imp_feedback(importer_t *importer, imp_filetype_t file_type)
{
    if (file_type == FT_TXT) {
        if (importer->feedback != 0 && importer->fileInsertNum % importer->feedback == 0) {
            imp_log(IMP_INDENT2 "%llu rows are committed\n", importer->fileInsertNum);
        }
    }
}

#define GSQL_ENTRY_SYMBOL(c) ((c) == '\r' || (c) == '\n')

static bool32 imp_pre_proc_sql(text_t *sql)
{
    cm_trim_text(sql);

    if (sql->len > 3 && sql->str[0] == '@' && sql->str[1] == '@' && sql->str[2] == ' ') {
        CM_REMOVE_FIRST_N(sql, 3);
        sql->str[sql->len] = '\0';
        return GS_TRUE;
    }

    if (CM_TEXT_END(sql) == ';' || CM_TEXT_END(sql) == '/') {
        CM_TEXT_END(sql) = '\0';
        sql->len--;
    }

    return GS_FALSE;
}

static status_t imp_tables_data_drop_table(lex_t *lex, list_t *table_list, bool8 *matched)
{
    word_t word;
    bool32 result = GS_FALSE;
    text_buf_t tbl_buf;
    char tbl_name[MAX_ENTITY_LEN + 1] = { '\0' };

    tbl_buf.max_size = MAX_ENTITY_LEN;
    tbl_buf.str = tbl_name;
    tbl_buf.len = 0;

    GS_RETURN_IFERR(lex_try_fetch2(lex, "DROP", "TABLE", &result));
    if (result == GS_TRUE) {
        GS_RETURN_IFERR(lex_try_fetch2(lex, "IF", "EXISTS", &result));
        /* if this is a new DROP SQL, reset tblMatch flag, ensure CREATE INDEX be executed */
        *matched = GS_FALSE;
        if (lex_expected_fetch_tblname(lex, &word, &tbl_buf) != GS_SUCCESS) {
            return GS_ERROR;
        }
        CM_NULL_TERM(&tbl_buf);
        if (word.type == WORD_TYPE_DQ_STRING) {
            CM_REMOVE_ENCLOSED_CHAR(&tbl_buf);
            tbl_buf.str[tbl_buf.len] = '\0';
        }

        for (uint32 i = 0; i < table_list->count; i++) {
            if (cm_str_equal((char *)(tbl_buf.str), (char *)cm_list_get(table_list, i))) {
                *matched = GS_TRUE;
                return GS_SUCCESS;
            }
        }
    }

    return GS_SUCCESS;
}

static status_t imp_tables_data_create_table(lex_t *lex, list_t *table_list, bool8 *matched)
{
    word_t word;
    bool32 result = GS_FALSE;
    text_buf_t tbl_buf;
    char tbl_name[MAX_ENTITY_LEN + 1] = { '\0' };

    tbl_buf.max_size = MAX_ENTITY_LEN;
    tbl_buf.str = tbl_name;
    tbl_buf.len = 0;

    GS_RETURN_IFERR(lex_try_fetch2(lex, "CREATE", "TABLE", &result));
    if (!result) {
        GS_RETURN_IFERR(lex_try_fetch4(lex, "CREATE", "GLOBAL", "TEMPORARY", "TABLE", &result));
    }
    if (result) {
        /* if this is a new CREATE TABLE SQL, reset tblMatch flag, ensure CREATE INDEX be executed */
        *matched = GS_FALSE;
        if (lex_expected_fetch_tblname(lex, &word, &tbl_buf) != GS_SUCCESS) {
            return GS_ERROR;
        }
        CM_NULL_TERM(&tbl_buf);
        if (word.type == WORD_TYPE_DQ_STRING) {
            CM_REMOVE_ENCLOSED_CHAR(&tbl_buf);
            tbl_buf.str[tbl_buf.len] = '\0';
        }

        for (uint32 i = 0; i < table_list->count; i++) {
            if (cm_str_equal((char *)tbl_buf.str, (char *)cm_list_get(table_list, i))) {
                *matched = GS_TRUE;
                break;
            }
        }
    }
    return GS_SUCCESS;
}

static status_t imp_tables_data_insert_table(lex_t *lex, list_t *table_list, bool8 *matched)
{
    word_t word;
    bool32 result = GS_FALSE;
    text_buf_t tbl_buf;
    char tbl_name[MAX_ENTITY_LEN + 1] = { '\0' };

    tbl_buf.max_size = MAX_ENTITY_LEN;
    tbl_buf.str = tbl_name;
    tbl_buf.len = 0;

    /* reset tblMatch flag, DATAONLY mode just insert statement will be executed */
    *matched = GS_FALSE;

    GS_RETURN_IFERR(lex_try_fetch2(lex, "INSERT", "INTO", &result));
    if (result) {
        if (lex_expected_fetch_tblname(lex, &word, &tbl_buf) != GS_SUCCESS) {
            return GS_ERROR;
        }
        CM_NULL_TERM(&tbl_buf);
        if (word.type == WORD_TYPE_DQ_STRING) {
            CM_REMOVE_ENCLOSED_CHAR(&tbl_buf);
            tbl_buf.str[tbl_buf.len] = '\0';
        }

        for (uint32 i = 0; i < table_list->count; i++) {
            if (cm_str_equal((char *)tbl_buf.str, (char *)cm_list_get(table_list, i))) {
                *matched = GS_TRUE;
                break;
            }
        }
    }
    return GS_SUCCESS;
}

static status_t imp_tables_data(text_t *sql, list_t *table_list, bool8 *matched)
{
    lex_t lex;

    imp_init_lex(&lex, sql);

    do {
        // if drop table matched, this segment will be executed
        GS_RETURN_IFERR(imp_tables_data_drop_table(&lex, table_list, matched));
        GS_BREAK_IF_TRUE(*matched == GS_TRUE);

        // maybe exp file do not contain DROP TABLE SQL, try to judge segment with CREATE TABLE
        GS_RETURN_IFERR(imp_tables_data_create_table(&lex, table_list, matched));
        GS_BREAK_IF_TRUE(*matched == GS_TRUE);

        // maybe exp file do not contain any metadata information, try to judge INSERT
        GS_RETURN_IFERR(imp_tables_data_insert_table(&lex, table_list, matched));
    } while (0);

    return GS_SUCCESS;
}

static inline status_t imp_check_username(importer_t *importer, text_t *sql, const char *user)
{
    bool32 result = GS_FALSE;
    lex_t lex;

    imp_init_lex(&lex, sql);
    GS_RETURN_IFERR(lex_try_fetch4(&lex, "ALTER", "SESSION", "SET", "CURRENT_SCHEMA", &result));
    if (result == GS_TRUE) {
        GS_RETURN_IFERR(lex_expected_fetch_word(&lex, "="));
        importer->schemaMatch = SCHEMA_NOT_MATCH;

        text_t schema_buf = { lex.curr_text->str + 1, lex.curr_text->len - 1 };
        if (schema_buf.str[0] == '\"') {
            CM_REMOVE_ENCLOSED_CHAR(&schema_buf);
            schema_buf.str[schema_buf.len] = '\0';
        }

        if (cm_str_equal(schema_buf.str, user)) {
            importer->schemaMatch = SCHEMA_MATCH;
            importer->schemaNum++;
            return GS_SUCCESS;
        }
    }

    return GS_SUCCESS;
}

// true : need to execute, false : no need to execute
static bool32 imp_filter_txt_content(text_t *sql, uint32 content)
{
    en_imp_sql_type sql_type;

    if (content == CT_ALL) {
        return GS_TRUE;
    }
    
    sql_type = imp_sql_type(sql);
    if (IMP_SQL_IS_ALTER_SESSION(sql_type)) {
        return GS_TRUE;
    }

    if (sql_type == IMP_SQL_INSERT) {
        // insert SQL: data only need to execute
        return content == CT_DATA_ONLY;
    } else {
        // DDL sql: metadata only need to execute
        return content == CT_METADATA_ONLY;
    }
}

static bool32 imp_filter_txt_create_user(text_t *sql, bool32 create_user)
{
    if (imp_sql_type(sql) == IMP_SQL_CREATE_USER && !create_user) {
        return GS_FALSE;
    }
    return GS_TRUE;
}

static bool32 is_need_exec_sql(text_t *sql, importer_t *importer)
{
    // filter by CONTENT
    if (!imp_filter_txt_content(sql, importer->content)) {
        return GS_FALSE;
    }

    // filter by CREATE_USER
    if (!imp_filter_txt_create_user(sql, importer->create_user)) {
        return GS_FALSE;
    }

    return GS_TRUE;
}

static status_t remap_concat_tablespace(word_t word, list_t *tblSpaceMaps, text_t *temp_cmd,
                                        text_t *orig_cmd, uint32 orig_buf_size, int32 *lex_move_len)
{
    char dst_tabspace[GS_MAX_NAME_LEN + 1];
    char *cmd = orig_cmd->str;
    uint32 tablespace_pos;
    errno_t errcode;

    if (find_remap(tblSpaceMaps, W2S(&word), dst_tabspace, GS_MAX_NAME_LEN + 1)) {
        tablespace_pos = (uint32)(word.text.str - cmd);
        *lex_move_len = (int32)(strlen(dst_tabspace) - word.text.len);
        // backup info after TABLESPACE
        errcode = strncpy_s(temp_cmd->str, temp_cmd->len, word.text.str + word.text.len,
            (cmd + strlen(cmd) - (word.text.str + word.text.len)));
        if (errcode != EOK) {
            imp_tmlog_error_ex("remap tablespace", "backup information after tablespace failed: %s",
                word.text.str + word.text.len);
            return GS_ERROR;
        }

        // overwirte tablespace in cmd
        errcode = strncpy_s(cmd + tablespace_pos, orig_buf_size - tablespace_pos, dst_tabspace, strlen(dst_tabspace));
        if (errcode != EOK) {
            imp_tmlog_error_ex("remap tablespace", "overwrite tablespace failed: %s",
                dst_tabspace);
            return GS_ERROR;
        }

        // append info after TABLESPACE
        errcode = strncpy_s(cmd + strlen(dst_tabspace) + tablespace_pos, orig_buf_size - strlen(dst_tabspace) - tablespace_pos,
            temp_cmd->str, strlen(temp_cmd->str));
        if (errcode != EOK) {
            imp_tmlog_error_ex("remap tablespace", "append information after tablespace failed: %s", temp_cmd->str);
            return GS_ERROR;
        }
    }
    return GS_SUCCESS;
}

static status_t remap_partition_tablespace(lex_t *lex, list_t *tblSpaceMaps, sql_text_t *text, int32 *lex_move_total,
                                           text_t *temp_cmd, text_t *orig_cmd, uint32 orig_buf_size)
{
    word_t word;
    int32 lex_move_len = 0;

    GS_RETURN_IFERR(lex_push(lex, text));
    if (lex_fetch(lex, &word) != GS_SUCCESS) {
        lex_pop(lex);
        return GS_ERROR;
    }

    if (word.id != KEY_WORD_PARTITION) {
        lex_pop(lex);
        return GS_SUCCESS;
    }
    while (word.type != WORD_TYPE_EOF) {
        if (lex_fetch(lex, &word) != GS_SUCCESS) {
            return GS_ERROR;
        }
        if (word.id == KEY_WORD_TABLESPACE) {
            GS_RETURN_IFERR(lex_fetch(lex, &word));
            GS_RETURN_IFERR(remap_concat_tablespace(word, tblSpaceMaps, temp_cmd, orig_cmd, orig_buf_size, &lex_move_len));
            if (lex_move_len > 0) {
                lex->curr_text->str += lex_move_len;
                *lex_move_total += lex_move_len;
            } else if (lex_move_len < 0) {
                lex->curr_text->len += lex_move_len;
                *lex_move_total += lex_move_len;
            }

            MEMS_RETURN_IFERR(memset_s(temp_cmd->str, temp_cmd->len, 0, temp_cmd->len));
        }
    }
    lex_pop(lex);
    return GS_SUCCESS;
}

static status_t remap_tbl_change(lex_t *lex, list_t *tblSpaceMaps, char *sql_buf, uint32 orig_buf_size)
{
    word_t word;
    text_t temp_cmd;
    text_t orig_cmd = {.str = sql_buf, .len = (uint32)strlen(sql_buf)};
    status_t ret = GS_SUCCESS;
    int32 lex_move_len = 0;
    int32 lex_move_total = 0;

    GS_RETURN_IFERR(lex_fetch(lex, &word));

    temp_cmd.str = (char *)malloc(MAX_CMD_LEN + 2);
    if (temp_cmd.str == NULL) {
        GSQL_PRINTF(ZSERR_IMPORT, "malloc databuf failed!");
        return GS_ERROR;
    }
    temp_cmd.len = MAX_CMD_LEN + 2;

    while (word.type != WORD_TYPE_EOF) {
        if (word.type == WORD_TYPE_BRACKET) {
            if (remap_partition_tablespace(lex, tblSpaceMaps, &word.text, &lex_move_total, &temp_cmd,
                                           &orig_cmd, orig_buf_size) != GS_SUCCESS) {
                ret = GS_ERROR;
                break;
            }
            if (lex_move_total != 0) {
                lex->curr_text->str += lex_move_total;
            }
        }
        if (KEY_WORD_TABLESPACE == word.id) {
            if (lex_fetch(lex, &word) != GS_SUCCESS) {
                ret = GS_ERROR;
                break;
            }
            if (remap_concat_tablespace(word, tblSpaceMaps, &temp_cmd, &orig_cmd, orig_buf_size, &lex_move_len) != GS_SUCCESS) {
                ret = GS_ERROR;
            }
            break;
        }
        if (lex_fetch(lex, &word) != GS_SUCCESS) {
            ret = GS_ERROR;
            break;
        }
    }

    CM_FREE_PTR(temp_cmd.str);
    return ret;
}

static status_t remap_tblspace_tbl(lex_t *lex, list_t *tblSpaceMaps, char *sql_buf, uint32 orig_buf_size)
{
    word_t word;
    bool32 result = GS_FALSE;

    GS_RETURN_IFERR(lex_expected_fetch_variant(lex, &word));
    GS_RETURN_IFERR(lex_try_fetch_bracket(lex, &word, &result));
    if (!result) {
        return GS_SUCCESS;
    }
    GS_RETURN_IFERR(remap_tbl_change(lex, tblSpaceMaps, sql_buf, orig_buf_size));
    return GS_SUCCESS;
}

static status_t remap_tblspace_idx(lex_t *lex, list_t *tblSpaceMaps, char *sql_buf, uint32 orig_buf_size)
{
    word_t word;
    bool32 result = GS_FALSE;

    GS_RETURN_IFERR(lex_fetch(lex, &word));
    GS_RETURN_IFERR(lex_try_fetch(lex, "ON", &result));
    if (!result) {
        GSQL_PRINTF(ZSERR_IMPORT, "Incomplete statement for index creation.");
        return GS_ERROR;
    }
    GS_RETURN_IFERR(lex_fetch(lex, &word));
    GS_RETURN_IFERR(remap_tbl_change(lex, tblSpaceMaps, sql_buf, orig_buf_size));
    return GS_SUCCESS;
}

static status_t remap_table_space(list_t *tblSpaceMaps, text_t *sql, uint32 orig_buf_size)
{
    status_t ret;
    bool32 result = GS_FALSE;
    lex_t lex;

    imp_init_lex(&lex, sql);
    GS_RETURN_IFERR(lex_try_fetch2(&lex, "CREATE", "TABLE", &result));
    if (result) {
        ret = remap_tblspace_tbl(&lex, tblSpaceMaps, sql->str, orig_buf_size);
        sql->len = (uint32)strlen(sql->str);
        return ret;
    }

    GS_RETURN_IFERR(lex_try_fetch2(&lex, "CREATE", "INDEX", &result));
    if (result) {
        ret = remap_tblspace_idx(&lex, tblSpaceMaps, sql->str, orig_buf_size);
        sql->len = (uint32)strlen(sql->str);
        return ret;
    }

    GS_RETURN_IFERR(lex_try_fetch3(&lex, "CREATE", "UNIQUE", "INDEX", &result));
    if (result) {
        ret = remap_tblspace_idx(&lex, tblSpaceMaps, sql->str, orig_buf_size);
        sql->len = (uint32)strlen(sql->str);
        return ret;
    }

    return GS_SUCCESS;
}

static status_t imp_commit(importer_t *importer, gsc_conn_t conn, imp_filetype_t file_type)
{
    gsql_imp_feedback(importer, file_type);

    if (gsc_commit(conn) != GSC_SUCCESS) {
        imp_tmlog_conn_error(conn);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t imp_load_txtrow2db(importer_t *importer, gsc_conn_t conn, bool8 force)
{
    if (!force && importer->fileInsertNum % GSQL_COMMIT_BATCH != 0) {
        return GS_SUCCESS;
    }
    return imp_commit(importer, conn, FT_TXT);
}

static status_t imp_try_ignore(importer_t *importer, text_t *sql, int ret)
{
    imp_log_sql("execute SQL failed", sql);

    if (imp_sql_type(sql) == IMP_SQL_CREATE_PROFILE) {
        imp_log("Warning: profile can not been dropped or created\n");
        return GS_SUCCESS;
    }

    return importer->ignore ? GS_SUCCESS : ret;
}

static status_t imp_sql(importer_t *importer, text_t *sql, uint32 orig_buf_size)
{
    int ret;

    // filter sql by CONTENT and CREATE_USER
    if (!is_need_exec_sql(sql, importer)) {
        return GS_SUCCESS;
    }

    // do remap tablespace
    if (importer->tblSpaceMaps.count > 0) {
        GS_RETURN_IFERR(remap_table_space(&importer->tblSpaceMaps, sql, orig_buf_size));
    }

    // execute new_sql
    imp_log_sql("Begin to execute", sql);

    ret = gsc_query(CONN, sql->str);
    if (ret != GS_SUCCESS) {
        imp_tmlog_conn_error(g_conn_info.conn);
        return imp_try_ignore(importer, sql, ret);
    }

    if (imp_sql_type(sql) == IMP_SQL_INSERT) {  // if DML , do commit
        importer->fileInsertNum++;
        GS_RETURN_IFERR(imp_load_txtrow2db(importer, CONN, GS_FALSE));
    }

    return GS_SUCCESS;
}

static int gsql_imp_read_compress_data(void *databuf, int minread, int maxread, gsc_z_stream *stream,
                                       char *swap_buff, uint32 swap_len)
{
    bool8 eof = GS_FALSE;
    uint32 readed_len = 0;

    if (gsc_common_z_read_data(stream, (char *)databuf, maxread, &readed_len, &eof) != GS_SUCCESS) {
        GSQL_PRINTF(ZSERR_IMPORT, "read uncompress file data failed.");
        return 0;
    }

    if (readed_len == maxread) {
        return readed_len;
    }

    if (gsc_common_z_read_compress(stream, &g_importer.crypt_info, swap_buff, swap_len, &eof) != GS_SUCCESS) {
        GSQL_PRINTF(ZSERR_IMPORT, "read compress file data failed.");
        return 0;
    }

    if (eof) {
        return readed_len;
    } else {
        return readed_len + gsql_imp_read_compress_data((char *)databuf + readed_len,
                                                        MIN(minread, (int)(maxread - readed_len)),
                                                        maxread - readed_len, stream, swap_buff, swap_len);
    }
}

static int gsql_imp_read_decrypt_data(void *databuf, int minread, int maxread, FILE *fp)
{
    int bytesread;
    char *decrypt_buf = NULL;
    crypt_file_t *decrypt_ctx = NULL;

    GS_RETURN_IFERR(gsql_get_encrypt_file(&g_importer.crypt_info, &decrypt_ctx, cm_fileno(fp)));
    decrypt_buf = (char *)malloc(RAW_BUF_SIZE);
    if (decrypt_buf == NULL) {
        gsql_printf("can't allocate %u bytes for dump table\n", RAW_BUF_SIZE);
        return GSC_ERROR;
    }

    bytesread = (int)fread(decrypt_buf, (size_t)minread, (size_t)maxread, fp);
    if (ferror(fp)) {
        imp_tmlog_error_ex("read data", "read file failed, error code is %d", errno);
        CM_FREE_PTR(decrypt_buf);
        return GSC_ERROR;
    }

    if (cm_decrypt_data_by_gcm(decrypt_ctx->crypt_ctx.gcm_ctx, databuf, decrypt_buf, bytesread) != GS_SUCCESS) {
        CM_FREE_PTR(decrypt_buf);
        return GSC_ERROR;
    }

    CM_FREE_PTR(decrypt_buf);
    return bytesread;
}

static int gsql_imp_read_data(void *databuf, int minread, int maxread, FILE *fp)
{
    int bytesread;

    if (g_importer.crypt_info.crypt_flag) {
        bytesread = gsql_imp_read_decrypt_data(databuf, minread, maxread, fp);
    } else {
        bytesread = (int)fread(databuf, (size_t)minread, (size_t)maxread, fp);
        if (ferror(fp)) {
            imp_tmlog_error_ex("read data", "read file failed, error code is %d", errno);
            return GSC_ERROR;
        }
    }

    return bytesread;
}

static int gsql_imp_read_file_data(void *databuf, int minread, int maxread, imp_compress_file_t* compress_file, bool8 compressed)
{
    if (!compressed) {
        return gsql_imp_read_data(databuf, minread, maxread, compress_file->fp);
    } else {
        return gsql_imp_read_compress_data(databuf, minread, maxread,
            &compress_file->zstream, compress_file->swap_buffer, compress_file->swap_len);
    }
}

static int gsql_read_raw_bin_data(import_bin_t *imp_bin, FILE *fp, bool8 *eof);
static status_t imp_get_data_from_buffer(import_bin_t *imp_bin, void *buffer, uint32 buf_len, uint32 len, FILE *fp);
static status_t imp_get_uint16_from_buffer(import_bin_t *imp_bin, uint16 *value, FILE *fp)
{
    return imp_get_data_from_buffer(imp_bin, value, sizeof(uint16), sizeof(uint16), fp);
}

static status_t imp_get_uint32_from_buffer(import_bin_t *imp_bin, uint32 *value, FILE *fp)
{
    return imp_get_data_from_buffer(imp_bin, value, sizeof(uint32), sizeof(uint32), fp);
}

static status_t imp_get_uint64_from_buffer(import_bin_t *imp_bin, uint64 *value, FILE *fp)
{
    return imp_get_data_from_buffer(imp_bin, value, sizeof(uint64), sizeof(uint64), fp);
}

static inline void imp_inc_inqueue_cnt(ddl_block_queue_t* queue)
{
    queue->inque_cnt++;
}

static inline void imp_inc_outqueue_cnt(ddl_block_queue_t* queue)
{
    cm_spin_lock(&(queue->outqueue_lock), NULL);
    queue->outque_cnt++;
    cm_spin_unlock(&(queue->outqueue_lock));
}

static inline bool8 imp_invalid_length(uint32 len, uint32 min, uint32 max)
{
    if (len > max || len < min) {
        GSQL_PRINTF(ZSERR_IMPORT, "length is %u, valid is [%u,%u].", len, min, max);
        GS_THROW_ERROR(ERR_CLT_IMP_DATAFILE, "check length", "invalid length");
        return GS_TRUE;
    }
    return GS_FALSE;
}

static status_t gsql_bin_import_truncate_sql_end(text_t *sql_txt)
{
    for (uint32 i = sql_txt->len - 1; i > 0; i--) {
        if (sql_txt->str[i] == '\r' || sql_txt->str[i] == '\n') {
            continue;
        }
        if (sql_txt->str[i] == '/') {
            sql_txt->str[i] = '\0';
            return GS_SUCCESS;
        } else {
            return GS_SUCCESS;
        }
    }
    return GS_SUCCESS;
}

static status_t gsql_bin_import_transfer_one_ddl_sql(importer_t *importer, import_ddl_block *block)
{
    status_t ret;

    while (GS_TRUE) {
        // gsql is canceled
        IMP_RETRUN_IF_CANCEL;
        // fatal errors occurs
        if (importer->fatal_error) {
            GS_THROW_ERROR(ERR_CLT_IMP_DATAFILE, "check DDL thread", "DDL thread throws error");
            return GS_ERROR;
        }
        ret = cm_chan_send_timeout(importer->ddl_queue.chan, block, MAX_DDL_BLOCK_SEND_TIME);
        // if timeout then try again.
        if (ret == GS_TIMEDOUT) {
            cm_sleep(MAX_DDL_BLOCK_WAIT_TIME);
            continue;
        }
        // do in queue count.
        if (ret == GS_SUCCESS) {
            imp_inc_inqueue_cnt(&(importer->ddl_queue));
        }
        return ret;
    }
}

static status_t gsql_bin_import_one_sql_in_conn(importer_t *importer, gsc_conn_t conn, text_t *sql_txt,
                                                bool8 single_sql)
{
    status_t ret = GSC_SUCCESS;

    GS_RETURN_IFERR(gsql_bin_import_truncate_sql_end(sql_txt));
    imp_log_sql(single_sql ? "Begin to execute [Single]" : "Begin to execute [Multi]", sql_txt);
    if (single_sql) {
        ret = gsc_query(conn, sql_txt->str);
    } else {
        ret = gsc_query_multiple(conn, sql_txt->str);
    }
    if (ret != GS_SUCCESS) {
        imp_log_sql("execute SQL failed", sql_txt);
        if (importer->ignore) {  // reset error info.
            imp_tmlog_conn_error(conn);
            cm_reset_error();
        }
        return importer->ignore ? GS_SUCCESS : ret;
    }
    return GS_SUCCESS;
}

static status_t gsql_bin_import_one_sql(importer_t *importer, text_t *sql_txt, bool8 single_sql)
{
    return gsql_bin_import_one_sql_in_conn(importer, CONN, sql_txt, single_sql);
}

static status_t imp_get_data_from_buffer(import_bin_t *imp_bin, void *buffer, uint32 buf_len, uint32 len, FILE *fp)
{
    errno_t errcode;
    char *binBuf = imp_bin->binBuf + imp_bin->binBufIndex;
    uint64 bin_buf_len;
    bool8 eof = GS_FALSE;

    if (len == 0) {
        return GS_SUCCESS;
    }

    bin_buf_len = (imp_bin->binBufLen - imp_bin->binBufIndex);

    if (len <= bin_buf_len) {
        errcode = memcpy_s(buffer, buf_len, binBuf, len);
        if (errcode != EOK) {
            GSQL_PRINTF(ZSERR_IMPORT, "copy raw data buffer failed.");
            GS_THROW_ERROR(ERR_CLT_IMP_DATAFILE, "copy data", "copy buffer failed");
            return GS_ERROR;
        }
        imp_bin->binBufIndex += len;
        return GS_SUCCESS;
    } else {
        errcode = memcpy_s(buffer, buf_len, binBuf, (uint32)bin_buf_len);
        if (errcode != EOK) {
            GSQL_PRINTF(ZSERR_IMPORT, "copy raw data buffer failed.");
            GS_THROW_ERROR(ERR_CLT_IMP_DATAFILE, "copy data", "copy buffer failed");
            return GS_ERROR;
        }
        imp_bin->binBufIndex += bin_buf_len;

        GS_RETURN_IFERR(gsql_read_raw_bin_data(imp_bin, fp, &eof));
        if (eof) {
            GSQL_PRINTF(ZSERR_IMPORT, "try to read more data(%u B) from file failed.", len);
            GS_THROW_ERROR(ERR_CLT_IMP_DATAFILE, "read file", "file size too small");
            return GS_ERROR;
        }

        return imp_get_data_from_buffer(imp_bin, (char*)buffer + bin_buf_len, buf_len - (uint32)bin_buf_len,
                                        len - (uint32)bin_buf_len, fp);
    }
}

/* read SQL to 'importer->rawBuf' */
static status_t imp_get_block_from_buffer(importer_t *importer, import_bin_t *imp_bin, uint32 len, FILE *fp)
{
    char *buffer = importer->rawBuf;
    if (len <= RAW_BUF_SIZE - 1) {
        GS_RETURN_IFERR(imp_get_data_from_buffer(imp_bin, buffer, RAW_BUF_SIZE, len, fp));
        buffer[len] = '\0';
        importer->rawBufLen = len + 1;
        return GS_SUCCESS;
    }

    GSQL_PRINTF(ZSERR_IMPORT, "try to read len %u more than max size %u.", len, RAW_BUF_SIZE);
    GS_THROW_ERROR(ERR_CLT_IMP_DATAFILE, "read file", "buffer overflow");
    return GS_ERROR;
}

static status_t imp_get_block_to_buffer(importer_t *importer, import_bin_t *imp_bin, char *buffer, uint32 max_len,
                                        uint32 len, FILE *fp)
{
    if (len <= max_len - 1) {
        GS_RETURN_IFERR(imp_get_data_from_buffer(imp_bin, buffer, max_len, len, fp));
        buffer[len] = '\0';
        return GS_SUCCESS;
    }

    GSQL_PRINTF(ZSERR_IMPORT, "try to read len %u more than max size %u.", len, max_len);
    GS_THROW_ERROR(ERR_CLT_IMP_DATAFILE, "read file", "buffer overflow");
    return GS_ERROR;
}

static int gsql_read_raw_bin_data(import_bin_t *imp_bin, FILE *fp, bool8 *eof)
{
    int32 inbytes;
    uint64 nbytes = 0;
    if (imp_bin->binBufIndex < imp_bin->binBufLen) {
        nbytes = imp_bin->binBufLen - imp_bin->binBufIndex;
        errno_t err = memmove_s(imp_bin->binBuf, RAW_BUF_SIZE, imp_bin->binBuf + imp_bin->binBufIndex, (size_t)nbytes);
        if (err != EOK) {
            GSQL_PRINTF(ZSERR_IMPORT, "move bin data failed.");
            return GS_ERROR;
        }
    }

    if (imp_bin->compress_flag) {
        inbytes = gsql_imp_read_compress_data(imp_bin->binBuf + nbytes, 1, (int)(RAW_BUF_SIZE - nbytes),
            &imp_bin->df_handle.zstream, imp_bin->df_handle.swap_buffer, imp_bin->df_handle.swap_len);
    } else {
        inbytes = gsql_imp_read_data(imp_bin->binBuf + nbytes, 1, (int)(RAW_BUF_SIZE - nbytes), fp);
        if (inbytes < 0) {
            *eof = ((nbytes > 0) ? GS_FALSE : GS_TRUE);
            return GS_ERROR;
        }
    }
    nbytes += (uint32)inbytes;
    imp_bin->binBufIndex = 0;
    imp_bin->binBufLen = nbytes;
    *eof = ((nbytes > 0) ? GS_FALSE : GS_TRUE);
    return GS_SUCCESS;
}

static status_t imp_active_dml_thread(importer_t *importer, const char *filename, text_t *schema_buf,
                                      imp_dml_status_t *status, uint32 dml_thread_id)
{
    cm_spin_lock(&importer->dml_thread_lock, NULL);
    errno_t errcode;

    while (GS_TRUE) {
        for (uint32 i = 0; i < importer->parallel; i++) {
            if (importer->dml_workers[i].idle) {
                if (strlen(filename) >= GS_FILE_NAME_BUFFER_SIZE || schema_buf->len > GS_MAX_NAME_LEN) {
                    cm_spin_unlock(&importer->dml_thread_lock);
                    return GS_ERROR;
                }

                errcode = memcpy_s(importer->dml_workers[i].fileName, GS_FILE_NAME_BUFFER_SIZE, filename,
                    strlen(filename));
                if (errcode == EOK) {
                    importer->dml_workers[i].fileName[strlen(filename)] = '\0';
                    errcode = memcpy_s(importer->dml_workers[i].currentSchema, GS_MAX_NAME_LEN + 1, schema_buf->str,
                        schema_buf->len);
                }
                if (errcode != EOK) {
                    cm_spin_unlock(&importer->dml_thread_lock);
                    GS_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
                    return GS_ERROR;
                }

                importer->dml_workers[i].currentSchema[schema_buf->len] = '\0';
                importer->dml_workers[i].idle = GS_FALSE;
                importer->dml_workers[i].dml_status_param.end_tag = &status->dml_end_flag[dml_thread_id];
                importer->dml_workers[i].dml_status_param.record_count = &status->dml_record_count[dml_thread_id];
                importer->dml_workers[i].dml_status_param.return_code = &status->dml_return[dml_thread_id];
                cm_spin_unlock(&importer->dml_thread_lock);
                return GS_SUCCESS;
            }
            if (importer->dml_workers[i].closed) {
                GS_THROW_ERROR(ERR_CLT_IMP_DATAFILE, "check DML worker", "DML worker closed");
                cm_spin_unlock(&importer->dml_thread_lock);
                return GS_ERROR;
            }
        }
        cm_sleep(20);
    }
}

static status_t imp_worker_active(importer_t *importer, const char *sql_buf, const text_t *schema)
{
    while (GS_TRUE) {
        for (uint32 i = 0; i < importer->parallel; i++) {
            // find idle.
            if (importer->dml_workers[i].idle) {
                if (strlen(sql_buf) >= GS_FILE_NAME_BUFFER_SIZE || schema->len > GS_MAX_NAME_LEN) {
                    return GS_ERROR;
                }

                MEMS_RETURN_IFERR(memcpy_s(importer->dml_workers[i].fileName, GS_MAX_NAME_LEN + 1,
                    sql_buf, strlen(sql_buf)));
                importer->dml_workers[i].fileName[strlen(sql_buf)] = '\0';

                MEMS_RETURN_IFERR(memcpy_s(importer->dml_workers[i].currentSchema, GS_MAX_NAME_LEN + 1,
                    schema->str, schema->len));
   
                importer->dml_workers[i].currentSchema[schema->len] = '\0';
                importer->dml_workers[i].idle = GS_FALSE;
                importer->dml_workers[i].dml_status_param.end_tag = NULL;
                return GS_SUCCESS;
            }
            // thread abnormal
            if (importer->dml_workers[i].closed) {
                GS_THROW_ERROR(ERR_CLT_IMP_DATAFILE, "check DML worker", "DML worker closed");
                return GS_ERROR;
            }

            cm_sleep(IMP_THREAD_CHECK_TIME);
        }
    }

    return GS_SUCCESS;
}

static status_t imp_read_insert_sql(text_t *sql, imp_dml_worker_t *worker)
{
    status_t ret = GS_SUCCESS;
    importer_t *importer = (importer_t *)worker->importer;
    gsql_conn_info_t *conn_info = &(worker->conn_info);

    if (!conn_info->is_conn) {
        (void)gsql_print_disconn_error();
        return GS_ERROR;
    }

    CM_ASSERT(imp_pre_proc_sql(sql) == GS_FALSE);

    if (worker->show == GS_TRUE) {  // just show SQL
        imp_log(IMP_INDENT "%s\n", sql->str);
        return GS_SUCCESS;
    }

    // execute new_sql
    imp_log_sql("Begin to execute", sql);

    ret = gsc_query(conn_info->conn, sql->str);
    if (ret != GS_SUCCESS) {
        imp_log("Incorrect sql:\n%s\n", sql->str);
        imp_tmlog_conn_error(conn_info->conn);
        return worker->ignore ? GS_SUCCESS : ret;
    }

    importer->fileInsertNum++;
    GS_RETURN_IFERR(imp_load_txtrow2db(importer, conn_info->conn, GS_FALSE));
    return GS_SUCCESS;
}

static status_t imp_set_attr_nologging_and_trigger(gsc_conn_t conn)
{
    /* set nologging option */
    if (g_importer.nologging) {
        GS_RETURN_IFERR(gsc_query(conn, "ALTER SESSION DISABLE TRIGGERS"));
        GS_RETURN_IFERR(gsc_query(conn, "ALTER SESSION ENABLE NOLOGGING"));
    } else {
        GS_RETURN_IFERR(gsc_query(conn, "ALTER SESSION DISABLE NOLOGGING"));
    }

    /* set trigger option */
    if (g_importer.disable_trigger) {
        GS_RETURN_IFERR(gsc_query(conn, "ALTER SESSION DISABLE TRIGGERS"));
    } else {
        GS_RETURN_IFERR(gsc_query(conn, "ALTER SESSION ENABLE TRIGGERS"));
    }
    return GS_SUCCESS;
}

static status_t gsql_worker_open_conn(gsql_conn_info_t *conn_info)
{
    bool32 interactive_clt = GS_FALSE;
    uint32 remote_as_sysdba = GS_FALSE;
    conn_info->conn = NULL;
    conn_info->stmt = NULL;

    if (gsql_alloc_conn(&conn_info->conn) != GS_SUCCESS) {
        imp_log("parallel import failed, alloc connect failed\n");
        return GS_ERROR;
    }
    (void)gsc_get_conn_attr(g_conn_info.conn, GSC_ATTR_REMOTE_AS_SYSDBA, &remote_as_sysdba, sizeof(uint32), NULL);
    /* set session interactive check disable */
    (void)gsc_set_conn_attr(conn_info->conn, GSC_ATTR_INTERACTIVE_MODE, (void *)&interactive_clt, 0);
    (void)gsc_set_conn_attr(conn_info->conn, GSC_ATTR_REMOTE_AS_SYSDBA, &remote_as_sysdba, sizeof(int32));

    GS_RETURN_IFERR(gsql_get_saved_pswd(conn_info->passwd, GS_PASSWORD_BUFFER_SIZE + 4));
    // the user will changed by exp-tool under CN with GTS
    gsql_get_saved_user(conn_info->username, GS_NAME_BUFFER_SIZE + 4);

    conn_info->is_conn = GS_FALSE;
    (void)gsql_switch_user(conn_info);
    if (gsql_conn_to_server(conn_info, GS_FALSE, GS_TRUE) != GS_SUCCESS) {
        gsc_free_conn(conn_info->conn);
        conn_info->conn = NULL;
        conn_info->stmt = NULL;
        return GS_ERROR;
    }

    /* set charset follow ctclient main connection */
    GS_RETURN_IFERR(gsc_set_charset(conn_info->stmt, g_local_config.charset_id));

    /* set sub worker no session INTERACTIVE timeout. */
    GS_RETURN_IFERR(gsc_prepare(conn_info->stmt, "ALTER SESSION DISABLE INTERACTIVE TIMEOUT"));
    GS_RETURN_IFERR(gsc_execute(conn_info->stmt));

    GS_RETURN_IFERR(imp_set_attr_nologging_and_trigger(conn_info->conn));

    return GS_SUCCESS;
}

static status_t gsql_ddl_worker_init(imp_ddl_worker_t *worker)
{
    // create connection
    worker->conn_info = g_conn_info;
    worker->conn_info.stmt = NULL;
    worker->conn_info.connect_by_install_user = g_conn_info.connect_by_install_user;
    worker->conn_info.conn = NULL;

    if (gsql_worker_open_conn(&worker->conn_info) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t gsql_worker_init(imp_dml_worker_t *worker)
{
    worker->fileInsertNum = 0;
    worker->importer = (importer_t *)malloc(sizeof(importer_t));
    if (worker->importer == NULL) {
        GS_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)sizeof(importer_t), "initing worker");
        return GS_ERROR;
    }
    MEMS_RETURN_IFERR(memset_s(worker->importer, sizeof(importer_t), 0, sizeof(importer_t)));

    worker->bin_bind_info.data_buffer = (char *)malloc(ROW_MAX_SIZE);
    if (worker->bin_bind_info.data_buffer == NULL) {
        GSQL_PRINTF(ZSERR_IMPORT, "Fail to allocate %u bytes for data buffer.", ROW_MAX_SIZE);
        return GSC_ERROR;
    }

    // create connection
    worker->conn_info = g_conn_info;
    worker->conn_info.stmt = NULL;
    worker->conn_info.connect_by_install_user = g_conn_info.connect_by_install_user;
    worker->conn_info.conn = NULL;

    importer_t *importer = (importer_t *)worker->importer;
    importer->rawBuf = (char *)malloc(RAW_BUF_SIZE + 1);
    if (importer->rawBuf == NULL) {
        GS_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)(RAW_BUF_SIZE + 1), "initing importer");
        return GS_ERROR;
    }
    MEMS_RETURN_IFERR(memset_s(importer->rawBuf, RAW_BUF_SIZE + 1, 0, RAW_BUF_SIZE + 1));

    importer->file_type = worker->fileType;
    importer->startLine = 0;
    importer->fileRows = 0;
    importer->feedback = g_importer.feedback;
    importer->rawBufIndex = 0;
    importer->rawBufIndex = 0;
    importer->rawBufLen = 0;
    importer->eof = 0;
    importer->impfp = NULL;
    importer->tblMatch = GS_FALSE;
    importer->tblMatched = GS_FALSE;

    worker->impbin = (char *)malloc(sizeof(import_bin_t));
    if (worker->impbin == NULL) {
        GS_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)sizeof(import_bin_t), "initing worker");
        return GS_ERROR;
    }
    MEMS_RETURN_IFERR(memset_s(worker->impbin, sizeof(import_bin_t), 0, sizeof(import_bin_t)));
    import_bin_t *impbin = (import_bin_t *)worker->impbin;

    impbin->binBuf = (char *)malloc(RAW_BUF_SIZE + 1);
    if (impbin->binBuf == NULL) {
        GS_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)(RAW_BUF_SIZE + 1), "initing worker");
        return GS_ERROR;
    }
    MEMS_RETURN_IFERR(memset_s(impbin->binBuf, RAW_BUF_SIZE + 1, 0, RAW_BUF_SIZE + 1));
    impbin->binBufIndex = 0;
    impbin->binBufLen = 0;
    impbin->df_handle.swap_buffer = (char *)malloc(RAW_BUF_SIZE);
    if (impbin->df_handle.swap_buffer == NULL) {
        GS_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)(RAW_BUF_SIZE + 1), "initing worker swap buffer");
        return GS_ERROR;
    }
    impbin->df_handle.swap_len = RAW_BUF_SIZE;

    cm_create_list(&impbin->fieldInfo, sizeof(field_info_t));

    if (gsql_worker_open_conn(&worker->conn_info) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static void gsql_ddl_worker_free(imp_ddl_worker_t *worker)
{
    if (worker->conn_info.stmt) {
        gsc_free_stmt(worker->conn_info.stmt);
        worker->conn_info.stmt = NULL;
    }
    if (worker->conn_info.is_conn) {
        gsc_disconnect(worker->conn_info.conn);
        worker->conn_info.is_conn = GS_FALSE;
    }
    if (worker->conn_info.conn) {
        gsc_free_conn(worker->conn_info.conn);
        worker->conn_info.conn = NULL;
    }
}

static void gsql_worker_free(imp_dml_worker_t *worker)
{
    importer_t *importer = (importer_t *)worker->importer;
    import_bin_t *impbin = (import_bin_t *)worker->impbin;

    if (worker->conn_info.stmt) {
        gsc_free_stmt(worker->conn_info.stmt);
        worker->conn_info.stmt = NULL;
    }
    if (worker->conn_info.is_conn) {
        gsc_disconnect(worker->conn_info.conn);
        worker->conn_info.is_conn = GS_FALSE;
    }
    if (worker->conn_info.conn) {
        gsc_free_conn(worker->conn_info.conn);
        worker->conn_info.conn = NULL;
    }
    
    CM_FREE_PTR(worker->bin_bind_info.data_buffer);

    if (importer != NULL) {
        CM_FREE_PTR(importer->rawBuf);
        CM_FREE_PTR(worker->importer);
    }

    if (impbin != NULL) {
        CM_FREE_PTR(impbin->binBuf);
        cm_reset_list(&impbin->fieldInfo);
        CM_FREE_PTR(impbin->df_handle.swap_buffer);
        CM_FREE_PTR(worker->impbin);
    }
}

static status_t imp_read_sql(importer_t *importer, text_t *block, uint64 max_size, bool8 *eof);

static status_t imp_change_curr_schema(gsql_conn_info_t *conn_info, const char *schema)
{
    char sql_buffer[IMP_MAX_ALTER_SCHEMA_SQL_LEN];
    PRTS_RETURN_IFERR(snprintf_s(sql_buffer, sizeof(sql_buffer), sizeof(sql_buffer) - 1,
        "ALTER SESSION SET CURRENT_SCHEMA = \"%s\"", schema));

    if (gsc_query(conn_info->conn, (const char *)sql_buffer) != GS_SUCCESS) {
        imp_tmlog_conn_error(conn_info->conn);
        return GS_ERROR;
    }

    GSQL_IMP_DEBUG("change schema to '%s'", schema);
    return GS_SUCCESS;
}

static status_t imp_reset_curr_schema(gsql_conn_info_t *conn_info, const char *schema)
{
    char curr_schema[GS_MAX_NAME_LEN + 1];
    text_t schema_buf = { curr_schema, (uint32)strlen(USER_NAME) };
    // get current schema info
    if (gsql_get_curr_schema(&schema_buf) != GS_SUCCESS) {
        GS_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "failed to get current schema!");
        return GS_ERROR;
    }

    if (cm_str_equal(schema_buf.str, schema)) {
        return GS_SUCCESS;
    }

    GS_RETURN_IFERR(imp_change_curr_schema(conn_info, schema));

    return GS_SUCCESS;
}

static status_t imp_reset_root_tenant(gsql_conn_info_t *conn_info)
{
    char sql_buffer[GS_MAX_CMD_LEN] = { 0 };

    if (gsc_get_call_version(conn_info->conn) <= CS_VERSION_17) {
        return GS_SUCCESS;
    }

    PRTS_RETURN_IFERR(snprintf_s(sql_buffer, GS_MAX_CMD_LEN, GS_MAX_CMD_LEN - 1,
        "ALTER SESSION SET TENANT = TENANT$ROOT"));

    if (gsc_prepare(conn_info->stmt, (const char *)sql_buffer) != GS_SUCCESS) {
        imp_tmlog_conn_error(conn_info->conn);
        return GS_ERROR;
    }
    if (gsc_execute(conn_info->stmt) != GS_SUCCESS) {
        imp_tmlog_conn_error(conn_info->conn);
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

static status_t imp_text_subfile(importer_t *importer, imp_dml_worker_t *worker)
{
    status_t ret = GS_SUCCESS;
    bool8 eof = GS_FALSE;
    bool8 table_load_judged = GS_FALSE;
    lex_t lex;
    list_t *table_list = &(g_importer.obj_list);
    bool8 matched = GS_FALSE;
    char *sql_buffer = NULL;

    GS_RETURN_IFERR(imp_change_curr_schema(&worker->conn_info, worker->currentSchema));

    sql_buffer = (char *)malloc(IMP_MAX_LARGE_BLOCK_SIZE);
    if (sql_buffer == NULL) {
        GSQL_PRINTF(ZSERR_IMPORT, "malloc file block failed, size is %u.", IMP_MAX_LARGE_BLOCK_SIZE);
        return GS_ERROR;
    }

    while (GS_TRUE) {
        // break if canceled
        if (GSQL_CANCELING) {
            GS_THROW_ERROR(ERR_OPERATION_CANCELED);
            ret = GS_ERROR;
            gsql_print_error(NULL);
            break;
        }

        text_t sql = { sql_buffer, 0 };
        ret = imp_read_sql(importer, &sql, IMP_MAX_LARGE_BLOCK_SIZE, &eof);
        GS_BREAK_IF_ERROR(ret);
        GS_BREAK_IF_TRUE(eof);

        // judge this subfile need to do insert.
        if (!table_load_judged && g_importer.imp_type == IMP_TABLE) {
            imp_init_lex(&lex, &sql);
            ret = imp_tables_data_insert_table(&lex, table_list, &matched);
            GS_BREAK_IF_ERROR(ret);
            GS_BREAK_IF_TRUE(!matched);

            table_load_judged = GS_TRUE;
            importer->tblMatched = GS_TRUE;
        }

        ret = imp_read_insert_sql(&sql, worker);
    }

    CM_FREE_PTR(sql_buffer);
    return ret;
}

static status_t gsql_worker_make_insert_sql(imp_dml_worker_t *worker)
{
    uint32 i;
    text_buf_t sql_buff = { .str = ((importer_t *)worker->importer)->sql_cmd_buf,
        .len = 0,
        .max_size = MAX_CMD_LEN + 2 };
    import_bin_t *impbin = (import_bin_t *)worker->impbin;
    text_t text;
    field_info_t *columnInfo = NULL;

    if (impbin->fieldInfo.count <= 0) {
        GSQL_PRINTF(ZSERR_IMPORT, "assert raised, expect: impbin->fieldInfo.count(%u) > 0", impbin->fieldInfo.count);
        return GS_ERROR;
    }

    GS_RETURN_IFERR(cm_concat_string(&sql_buff.value, sql_buff.max_size, "insert into \""));
    GS_RETURN_IFERR(cm_concat_string(&sql_buff.value, sql_buff.max_size, impbin->tableName));
    GS_RETURN_IFERR(cm_concat_string(&sql_buff.value, sql_buff.max_size, "\"("));

    for (i = 0; i < impbin->fieldInfo.count; i++) {
        columnInfo = cm_list_get(&impbin->fieldInfo, i);
        if (i != 0) {  // more than columns
            GS_RETURN_IFERR(cm_concat_string(&sql_buff.value, sql_buff.max_size, ","));
        }
        GS_RETURN_IFERR(cm_concat_string(&sql_buff.value, sql_buff.max_size, "\""));
        text.str = columnInfo->name;
        text.len = (uint32)columnInfo->nameLen;
        cm_concat_text(&sql_buff.value, sql_buff.max_size, &text);
        GS_RETURN_IFERR(cm_concat_string(&sql_buff.value, sql_buff.max_size, "\""));
    }

    GS_RETURN_IFERR(cm_concat_string(&sql_buff.value, sql_buff.max_size, ") values("));

    for (i = 0; i < impbin->fieldInfo.count; i++) {
        if (i != 0) {  // more than columns
            GS_RETURN_IFERR(cm_concat_string(&sql_buff.value, sql_buff.max_size, ","));
        }
        GS_RETURN_IFERR(cm_concat_string(&sql_buff.value, sql_buff.max_size, ":"));
        cm_concat_int32(&sql_buff.value, sql_buff.max_size, i);
    }
    GS_RETURN_IFERR(cm_concat_string(&sql_buff.value, sql_buff.max_size, ")"));
    CM_NULL_TERM(&sql_buff.value);
    return GS_SUCCESS;
}

static status_t imp_seek_lob_file(FILE *fp, gsc_z_stream *zstream, bool8 compressed, char *swap_buff,
                                  uint32 swap_len, int64 offset)
{
    int64 ret_seek;
    if (!compressed) {
#ifndef WIN32
        ret_seek = fseeko64(fp, offset, SEEK_SET);
#else
        ret_seek = _fseeki64(fp, offset, SEEK_SET);
#endif
        if (ret_seek != 0) {
            return GS_ERROR;
        }
        return GS_SUCCESS;
    } else {
        return gsc_common_z_read_seek(zstream, &g_importer.crypt_info, offset, swap_buff, swap_len);
    }
}

static status_t imp_get_inline_lob_size(gsc_stmt_t stmt, char *locator, uint32 len, uint32 *size)
{
    uint32 outline, locator_size;

    if (gsc_get_locator_info(stmt, locator, &outline, size, &locator_size) != GS_SUCCESS) {
        GSQL_PRINTF(ZSERR_IMPORT, "get lob locater info failed.");
        return GS_ERROR;
    }

    if (*(uint32*)locator == GS_INVALID_ID32) { // outline lob
        if (SECUREC_UNLIKELY(locator_size != len)) {
            GSQL_PRINTF(ZSERR_IMPORT, "outline lob locator size mismatched.");
            return GS_ERROR;
        }
    } else { // inline lob
        if (SECUREC_UNLIKELY(outline || (*size) > len)) {
            GSQL_PRINTF(ZSERR_IMPORT, "inline lob flag is mismatch or actual len too large.");
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t imp_write_file_clob(gsc_stmt_t pstmt, char *bin_buf, int col_id, import_bin_t *impbin,
                                    uint64 fileOffset, uint32 row)
{
    int32 inbytes;
    char *databuf = NULL;
    uint32 total_size = 0;
    uint32 write_size = 0;
    uint32 write_piece_size = 0;
    uint32 nchars;

    if (imp_seek_lob_file(impbin->lf_handle.fp,
        &impbin->lf_handle.zstream, impbin->compress_flag,
        impbin->lf_handle.swap_buffer, impbin->lf_handle.swap_len, fileOffset) != GS_SUCCESS) {
        GSQL_PRINTF(ZSERR_IMPORT, "find clob column (id %d) failed when seek position %llu failed.", col_id, fileOffset);
        return GS_ERROR;
    }

    inbytes = gsql_imp_read_file_data(&total_size, 1, sizeof(uint32), &impbin->lf_handle, impbin->compress_flag);
    if (inbytes != (int32)sizeof(uint32)) {
        GSQL_PRINTF(ZSERR_IMPORT, "read clob length failed!");
        return GS_ERROR;
    }

    GSQL_IMP_DATA_DEBUG("[Bind Data] write %u filedata into clob column %u.", total_size, col_id);

    databuf = (char *)malloc(LOB_SWAP_BUF_SIZE);
    if (databuf == NULL) {
        GSQL_PRINTF(ZSERR_IMPORT, "malloc databuf failed!");
        return GS_ERROR;
    }

    while (write_size < total_size) {
        // write size this time
        write_piece_size = MIN((total_size - write_size), (uint32)LOB_SWAP_BUF_SIZE);

        inbytes = gsql_imp_read_file_data(databuf, 1, write_piece_size, &impbin->lf_handle, impbin->compress_flag);
        if (inbytes <= 0) {
            CM_FREE_PTR(databuf);
            GSQL_PRINTF(ZSERR_IMPORT, "clob column not complete , writed %u ,total %u!", write_size, total_size);
            return GS_ERROR;
        }

        if (gsc_write_batch_clob(pstmt, col_id, row, databuf, write_piece_size, &nchars) != GSC_SUCCESS) {
            CM_FREE_PTR(databuf);
            GSQL_PRINTF(ZSERR_IMPORT, "write clob failed!");
            return GS_ERROR;
        }
        write_size += write_piece_size;
    }

    CM_FREE_PTR(databuf);
    return GS_SUCCESS;
}

static status_t imp_write_clob(gsc_stmt_t pstmt, char *bin_buf, uint16 data_len, int col_id, uint32 row, import_bin_t *impbin)
{
    uint32 nchars = 0;
    imp_relob_head_t lob_head;
    char *col_data = bin_buf;
    uint32 really_size;
    char df_name[GS_MAX_FILE_PATH_LENGH];

    GS_RETURN_IFERR(imp_get_inline_lob_size(pstmt, col_data, data_len, &really_size));

    if (*(uint32 *)col_data == GS_INVALID_ID32) {
        col_data += sizeof(uint32);
        lob_head.fileOffset = *(uint64 *)col_data;
        col_data += sizeof(uint64);
        lob_head.nameSize = *((uint16 *)col_data);
        col_data += sizeof(uint16);
        MEMS_RETURN_IFERR(memcpy_s(lob_head.name, sizeof(lob_head.name), col_data, lob_head.nameSize));
        lob_head.name[lob_head.nameSize] = '\0';
        GS_RETURN_IFERR(imp_get_data_file(g_importer.imp_subfile_path, lob_head.name, df_name,
            (uint32)strlen(lob_head.name), GS_MAX_FILE_PATH_LENGH));

        if (impbin->lf_handle.fp == NULL &&
            imp_open_file(&impbin->lf_handle.fp, df_name, &impbin->lf_handle.zstream, impbin->compress_flag) != GS_SUCCESS) {
            GSQL_PRINTF(ZSERR_IMPORT, "open data file %s failed!", lob_head.name);
            return GS_ERROR;
        }

        GSQL_IMP_DATA_DEBUG("[Bind Data] write %s data offset %u into column %llu.", dfName, (int64)lobHead.fileOffset,
                            col_id);
        if (imp_write_file_clob(pstmt, bin_buf, col_id,
            impbin, (int64)lob_head.fileOffset, row) != GS_SUCCESS) {
            GSQL_PRINTF(ZSERR_IMPORT, "write clob failed!");
            return GS_ERROR;
        }
    } else {
        GSQL_IMP_DATA_DEBUG("[Bind Data] write %u data into column %u.", really_size, col_id);
        if (gsc_write_batch_clob(pstmt, col_id, row, bin_buf + 3 * sizeof(uint32),
                                 really_size, &nchars) != GSC_SUCCESS) {
            GSQL_PRINTF(ZSERR_IMPORT, "write clob failed!");
            return GS_ERROR;
        }
    }
    return GS_SUCCESS;
}

static status_t imp_write_file_blob(gsc_stmt_t pstmt, char *bin_buf, int col_id, import_bin_t *impbin,
                                    int64 fileOffset, uint32 row)
{
    int32 inbytes;
    char *databuf = NULL;
    uint32 total_size = 0;
    uint32 write_size = 0;
    uint32 write_piece_size = 0;

    if (imp_seek_lob_file(impbin->lf_handle.fp, &impbin->lf_handle.zstream,
        impbin->compress_flag, impbin->lf_handle.swap_buffer,
        impbin->lf_handle.swap_len, fileOffset) != GS_SUCCESS) {
        GSQL_PRINTF(ZSERR_IMPORT, "find blob column (id %d) failed when seek position %llu failed.", col_id, fileOffset);
        return GS_ERROR;
    }

    inbytes = gsql_imp_read_file_data(&total_size, 1, sizeof(uint32), &impbin->lf_handle, impbin->compress_flag);
    if (inbytes != (int32)sizeof(uint32)) {
        GSQL_PRINTF(ZSERR_IMPORT, "read blob length failed!");
        return GS_ERROR;
    }

    GSQL_IMP_DATA_DEBUG("[Bind Data] write %u filedata into blob column %u.", total_size, col_id);

    databuf = (char *)malloc(LOB_SWAP_BUF_SIZE);
    if (databuf == NULL) {
        GSQL_PRINTF(ZSERR_IMPORT, "malloc databuf failed!");
        return GS_ERROR;
    }

    while (write_size < total_size) {
        // write size this time
        write_piece_size = MIN((total_size - write_size), (uint32)LOB_SWAP_BUF_SIZE);

        inbytes = gsql_imp_read_file_data(databuf, 1, write_piece_size, &impbin->lf_handle, impbin->compress_flag);
        if (inbytes <= 0) {
            CM_FREE_PTR(databuf);
            GSQL_PRINTF(ZSERR_IMPORT, "blob column not complete , writed %u ,total %u!", write_size, total_size);
            return GS_ERROR;
        }

        if (gsc_write_batch_blob(pstmt, col_id, row, databuf, write_piece_size) != GSC_SUCCESS) {
            CM_FREE_PTR(databuf);
            GSQL_PRINTF(ZSERR_IMPORT, "write blob failed!");
            return GS_ERROR;
        }
        write_size += write_piece_size;
    }

    CM_FREE_PTR(databuf);
    return GS_SUCCESS;
}

static status_t imp_write_blob(gsc_stmt_t pstmt, char *bin_buf, uint16 data_len, int col_id, uint32 row, import_bin_t *impbin)
{
    imp_relob_head_t lob_head;
    char *col_data = bin_buf;
    uint32 really_size;
    char df_name[GS_MAX_FILE_PATH_LENGH];

    GS_RETURN_IFERR(imp_get_inline_lob_size(pstmt, col_data, data_len, &really_size));

    if (*(uint32 *)col_data == GS_INVALID_ID32) {
        col_data += sizeof(uint32);
        lob_head.fileOffset = *(uint64 *)col_data;
        col_data += sizeof(uint64);
        lob_head.nameSize = *((uint16 *)col_data);
        col_data += sizeof(uint16);
        MEMS_RETURN_IFERR(memcpy_s(lob_head.name, sizeof(lob_head.name), col_data, lob_head.nameSize));
        lob_head.name[lob_head.nameSize] = '\0';
        GS_RETURN_IFERR(imp_get_data_file(g_importer.imp_subfile_path, lob_head.name, df_name,
            (uint32)strlen(lob_head.name), GS_MAX_FILE_PATH_LENGH));

        if (impbin->lf_handle.fp == NULL &&
            imp_open_file(&impbin->lf_handle.fp, df_name, &impbin->lf_handle.zstream, impbin->compress_flag) != GS_SUCCESS) {
            GSQL_PRINTF(ZSERR_IMPORT, "open data file %s failed!", lob_head.name);
            return GS_ERROR;
        }

        GSQL_IMP_DATA_DEBUG("[Bind Data] write %s data offset %u into column %u.", dfName, (int64)lobHead.fileOffset,
                            col_id);
        if (imp_write_file_blob(pstmt, bin_buf, col_id,
            impbin, (int64)lob_head.fileOffset, row) != GS_SUCCESS) {
            GSQL_PRINTF(ZSERR_IMPORT, "write blob failed!");
            return GS_ERROR;
        }
    } else {
        GSQL_IMP_DATA_DEBUG("[Bind Data] write %u data into column %u.", really_size, col_id);
        if (gsc_write_batch_blob(pstmt, col_id, row, bin_buf + 3 * sizeof(uint32), really_size) != GSC_SUCCESS) {
            GSQL_PRINTF(ZSERR_IMPORT, "write blob failed!");
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static inline status_t imp_dec4_check_valid(const dec4_t *dec)
{
    if (DECIMAL_IS_ZERO(dec)) {
        return GS_SUCCESS;
    }
    for (uint8 i = 0; i < dec->ncells; i++) {
        if (dec->cells[i] > 0) {
            return GS_SUCCESS;
        }
    }
    return GS_ERROR;
}

// Tamper-resistant, such as ncells > 0, but cells are full of invalid values
// Therefore, if ncells > 0, at least one cell must be greater than 0
static inline status_t imp_dec2_check_valid(const dec2_t *dec)
{
    if (DECIMAL2_IS_ZERO(dec)) {
        return GS_SUCCESS;
    }
    for (uint8 i = 0; i < GET_CELLS_SIZE(dec); i++) {
        if (dec->cells[i] > 0) {
            return GS_SUCCESS;
        }
    }
    return GS_ERROR;
}

static status_t imp_print_column_data(field_info_t *field, const char *data, uint32 len)
{
    char print_buffer[MAX_IMP_DEBUG_PRINTSIZE];
    uint32 copy_len;

    switch (field->type) {
        case GSC_TYPE_BIGINT:
        case GSC_TYPE_NATIVE_DATE:
        case GSC_TYPE_TIMESTAMP:
        case GSC_TYPE_TIMESTAMP_TZ_FAKE:
        case GSC_TYPE_TIMESTAMP_LTZ:
        case GSC_TYPE_INTERVAL_DS:
            GSQL_IMP_DATA_DEBUG("[Bind Data] write %lld into column %s", *(int64 *)data, field->name);
            break;

        case GSC_TYPE_TIMESTAMP_TZ:
            GSQL_IMP_DATA_DEBUG("[Bind Data] write %lld into column %s", *(timestamp_tz_t *)data, field->name);
            break;

        case GSC_TYPE_INTERVAL_YM:
        case GSC_TYPE_INTEGER:
        case GSC_TYPE_BOOLEAN:
            GSQL_IMP_DATA_DEBUG("[Bind Data] write %d into column %s", *(int32 *)data, field->name);
            break;
        case GSC_TYPE_UINT32:
            GSQL_IMP_DATA_DEBUG("[Bind Data] write %u into column %s", *(uint32 *)data, field->name);
            break;

        case GSC_TYPE_REAL:
            GSQL_IMP_DATA_DEBUG("[Bind Data] write %lf into column %s", *(double *)data, field->name);
            break;

        case GSC_TYPE_NUMBER:
        case GSC_TYPE_DECIMAL:
            GS_RETURN_IFERR(imp_dec4_check_valid((dec4_t*)data));
            GS_RETURN_IFERR(cm_dec4_to_str((dec4_t*)data, (uint32)MAX_IMP_DEBUG_PRINTSIZE - 1, print_buffer));
            GSQL_IMP_DATA_DEBUG("[Bind Data] write %s into column %s", print_buffer, field->name);
            break;
        case GSC_TYPE_NUMBER2: {
            dec2_t dec2;
            cm_dec2_copy_ex(&dec2, (const payload_t *)data, len);
            GS_RETURN_IFERR(imp_dec2_check_valid(&dec2));
            GS_RETURN_IFERR(cm_dec2_to_str(&dec2, (uint32)MAX_IMP_DEBUG_PRINTSIZE, print_buffer));
            GSQL_IMP_DATA_DEBUG("[Bind Data] write %s into column %s", print_buffer, field->name);
            break;
        }
        case GSC_TYPE_BINARY:
        case GSC_TYPE_VARBINARY:
        case GSC_TYPE_CHAR:
        case GSC_TYPE_VARCHAR:
        case GSC_TYPE_STRING:
            copy_len = MIN((MAX_IMP_DEBUG_PRINTSIZE - 1), len);
            print_buffer[copy_len] = '\0';
            if (copy_len > 0) {
                print_buffer[MAX_IMP_DEBUG_PRINTSIZE - 1] = '\0';
                MEMS_RETURN_IFERR(memcpy_s(print_buffer, (MAX_IMP_DEBUG_PRINTSIZE - 1), data, copy_len));
                GSQL_IMP_DATA_DEBUG("[Bind Data] write %s into column %s", print_buffer, field->name);
            } else {
                GSQL_IMP_DATA_DEBUG("[Bind Data] write '' into column %s", field->name);
            }
            break;
        case GSC_TYPE_CLOB:
        case GSC_TYPE_BLOB:
        case GSC_TYPE_IMAGE:
            break;
        default:
            GSQL_IMP_DATA_DEBUG("[Bind Data] write data length(%u) into column %s", len, field->name);
            break;
    }

    return GS_SUCCESS;
}

#define GSC_IS_BINARY_TYPE(type) ((type) == GSC_TYPE_BINARY || (type) == GSC_TYPE_VARBINARY)
#define GSC_IS_LOB_TYPE(type)    ((type) == GSC_TYPE_CLOB || (type) == GSC_TYPE_BLOB || (type) == GSC_TYPE_IMAGE)

static status_t imp_read_checkrow(import_bin_t *impbin, char **row_data)
{
    char *row = NULL;
    uint16 row_len;

    // check row size
    row = (char*)(impbin->binBuf + impbin->binBufIndex);
    row_len = *(uint16 *)row;

    if (SECUREC_UNLIKELY(row_len == 0)) {
        GSQL_PRINTF(ZSERR_IMPORT, "row length should larger than 0.");
        return GS_ERROR;
    }

    if (SECUREC_UNLIKELY(impbin->binBufLen - impbin->binBufIndex < row_len ||
        row_len > GS_MAX_ROW_SIZE)) {
        GSQL_PRINTF(ZSERR_IMPORT, "row length %u large than buffer length %llu or %u.",
            row_len, impbin->binBufLen - impbin->binBufIndex, GS_MAX_ROW_SIZE);
        return GS_ERROR;
    }

    impbin->binBufIndex += row_len;
    *row_data = row;
    return GS_SUCCESS;
}

static status_t imp_decode_row(char *row_data, subfile_row_t *row_info, uint32 *col_cnt)
{
    uint16 size, col_size;
    uint32 colnum;
    row_head_t *row_head = (row_head_t *)row_data;

    row_info->rowTotalLen = *(uint16*)(row_data);
    if (SECUREC_UNLIKELY(IS_SPRS_ROW(row_head) && row_head->sprs_count < GS_SPRS_COLUMNS)) {
        GSQL_PRINTF(ZSERR_IMPORT, "column count at row head is incorrect.");
        return GS_ERROR;
    }

    if (SECUREC_UNLIKELY(ROW_COLUMN_COUNT(row_head) > GS_MAX_COLUMNS)) {
        GSQL_PRINTF(ZSERR_IMPORT, "column number %u too large.", ROW_COLUMN_COUNT(row_head));
        return GS_ERROR;
    }

    colnum = cm_decode_row_imp(row_data, row_info->offsets, row_info->lens, &size);

    if (SECUREC_UNLIKELY(size > row_info->rowTotalLen)) {
        GSQL_PRINTF(ZSERR_IMPORT, "row data length %u large than row total length %u.", size, row_info->rowTotalLen);
        return GS_ERROR;
    }

    for (uint32 i = 0; i < colnum; i++) {
        col_size = (row_info->lens[i] == GS_NULL_VALUE_LEN ? 0 : row_info->lens[i]);
        if (SECUREC_UNLIKELY(row_info->offsets[i] + col_size > size)) {
            GSQL_PRINTF(ZSERR_IMPORT, "column (%u) offset %u large than row total length %u.", i,
                row_info->offsets[i] + row_info->lens[i], row_info->rowTotalLen);
            return GS_ERROR;
        }
    }

    *col_cnt = colnum;
    return GS_SUCCESS;
}


static status_t imp_read_rowdata(gsc_stmt_t pstmt, imp_dml_worker_t *worker, uint32 row)
{
    uint16 offset, len;
    import_bin_t *impbin = (import_bin_t *)worker->impbin;
    char *row_data = NULL;
    uint32 fieldNum = impbin->fieldInfo.count;
    uint32 col_id, raw_cols;
    subfile_row_t row_info;
    field_info_t *field_list = NULL;
    char *field_ptr = NULL;
    text_t dec_txt;
    imp_bind_info_t *bind_info = &(worker->bin_bind_info);

    GS_RETURN_IFERR(imp_read_checkrow(impbin, &row_data));
    GS_RETURN_IFERR(imp_decode_row(row_data, &row_info, &raw_cols));

    for (col_id = 0; col_id < raw_cols; col_id++) {
        offset = row_info.offsets[col_id];
        len = row_info.lens[col_id];
        field_ptr = (char *)bind_info->col_data[col_id] + row * bind_info->bind_buf_len[col_id];
        field_list = (field_info_t *)cm_list_get(&impbin->fieldInfo, col_id);

        /* Binding parameters on insert SQL */
        if (len == GS_NULL_VALUE_LEN) {
            GSQL_IMP_DATA_DEBUG("[Bind Data] write NULL data length into column %s(%u).", field_list->name, col_id);
            bind_info->data_ind[col_id][row] = GSC_NULL;
            continue;
        }

        GS_RETURN_IFERR(imp_print_column_data(field_list, row_data + offset, len));

        switch (field_list->type) {
            case GSC_TYPE_BIGINT:
                IMP_VALUE (int64, field_ptr) = *(int64 *)(row_data + offset);
                bind_info->data_ind[col_id][row] = sizeof(int64);
                break;

            case GSC_TYPE_DATE:
            case GSC_TYPE_NATIVE_DATE:
            case GSC_TYPE_TIMESTAMP:
            case GSC_TYPE_TIMESTAMP_TZ_FAKE:
            case GSC_TYPE_TIMESTAMP_LTZ:
                IMP_VALUE (date_t, field_ptr) = *(date_t *)(row_data + offset);
                bind_info->data_ind[col_id][row] = sizeof(date_t);
                break;

            case GSC_TYPE_TIMESTAMP_TZ:
                IMP_VALUE (timestamp_tz_t, field_ptr) = *(timestamp_tz_t *)(row_data + offset);
                bind_info->data_ind[col_id][row] = sizeof(timestamp_tz_t);
                break;

            case GSC_TYPE_INTERVAL_DS:
                IMP_VALUE (interval_ds_t, field_ptr) = *(interval_ds_t *)(row_data + offset);
                bind_info->data_ind[col_id][row] = sizeof(interval_ds_t);
                break;

            case GSC_TYPE_INTERVAL_YM:
                IMP_VALUE (interval_ym_t, field_ptr) = *(interval_ym_t *)(row_data + offset);
                bind_info->data_ind[col_id][row] = sizeof(interval_ym_t);
                break;

            case GSC_TYPE_INTEGER:
                IMP_VALUE (int32, field_ptr) = *(int32 *)(row_data + offset);
                bind_info->data_ind[col_id][row] = sizeof(int32);
                break;
            case GSC_TYPE_UINT32:
                IMP_VALUE (uint32, field_ptr) = *(uint32 *)(row_data + offset);
                bind_info->data_ind[col_id][row] = sizeof(uint32);
                break;

            case GSC_TYPE_BOOLEAN:
                IMP_VALUE (bool32, field_ptr) = *(bool32 *)(row_data + offset);
                bind_info->data_ind[col_id][row] = sizeof(bool32);
                break;

            case GSC_TYPE_REAL:
                IMP_VALUE (double, field_ptr) = *(double *)(row_data + offset);
                bind_info->data_ind[col_id][row] = sizeof(double);
                break;

            case GSC_TYPE_NUMBER:
            case GSC_TYPE_DECIMAL:
                dec_txt.str = field_ptr;
                GS_RETURN_IFERR(imp_dec4_check_valid((dec4_t*)(row_data + offset)));
                GS_RETURN_IFERR(cm_dec4_to_text((dec4_t*)(row_data + offset),
                    (uint32)GSC_NUMBER_BOUND_SIZE, &dec_txt));
                bind_info->data_ind[col_id][row] = (uint16)dec_txt.len;
                break;
            case GSC_TYPE_NUMBER2: {
                dec_txt.str = field_ptr;
                dec2_t dec2;
                cm_dec2_copy_ex(&dec2, (const payload_t *)(row_data + offset), (uint8)len);
                GS_RETURN_IFERR(imp_dec2_check_valid(&dec2));
                GS_RETURN_IFERR(cm_dec2_to_text(&dec2, (uint32)GSC_NUMBER_BOUND_SIZE, &dec_txt));
                bind_info->data_ind[col_id][row] = (uint16)dec_txt.len;
                break;
            }
            case GSC_TYPE_BINARY:
            case GSC_TYPE_VARBINARY:
            case GSC_TYPE_CHAR:
            case GSC_TYPE_VARCHAR:
            case GSC_TYPE_STRING:
            case GSC_TYPE_RAW:
                MEMS_RETURN_IFERR(memcpy_s(field_ptr, bind_info->bind_buf_len[col_id], row_data + offset, len));
                bind_info->data_ind[col_id][row] = len;
                break;
            case GSC_TYPE_CLOB:
            case GSC_TYPE_ARRAY:
                GS_RETURN_IFERR(imp_write_clob(pstmt, row_data + offset, len, col_id, row, impbin));
                bind_info->data_ind[col_id][row] = sizeof(gsc_lob_t);
                break;
            case GSC_TYPE_BLOB:
            case GSC_TYPE_IMAGE:
                GS_RETURN_IFERR(imp_write_blob(pstmt, row_data + offset, len, col_id, row, impbin));
                bind_info->data_ind[col_id][row] = sizeof(gsc_lob_t);
                break;
            default:
                GSQL_PRINTF(ZSERR_IMPORT, "unknow data type(%u)!", field_list->type);
                return GS_ERROR;
        }
    }

    // if the number of columns got from DC is more than that of raw row,
    // then all left columns are bound by NULL value
    for (; col_id < fieldNum; col_id++) {
        bind_info->data_ind[col_id][row] = GSC_NULL;
    }

    return GS_SUCCESS;
}

static status_t imp_get_bind_buffer_length(field_info_t *field_info, uint16 *len)
{
    switch (field_info->type) {
        case GSC_TYPE_BIGINT:
            *len = (uint16)sizeof(int64);
            break;

        case GSC_TYPE_DATE:
        case GSC_TYPE_NATIVE_DATE:
        case GSC_TYPE_TIMESTAMP:
        case GSC_TYPE_TIMESTAMP_TZ_FAKE:
        case GSC_TYPE_TIMESTAMP_LTZ:
            *len = (uint16)sizeof(date_t);
            break;

        case GSC_TYPE_TIMESTAMP_TZ:
            *len = (uint16)sizeof(timestamp_tz_t);
            break;

        case GSC_TYPE_INTERVAL_DS:
            *len = (uint16)sizeof(interval_ds_t);
            break;

        case GSC_TYPE_INTERVAL_YM:
            *len = (uint16)sizeof(interval_ym_t);
            break;

        case GSC_TYPE_INTEGER:
            *len = (uint16)sizeof(int32);
            break;

        case GSC_TYPE_UINT32:
            *len = (uint16)sizeof(uint32);
            break;

        case GSC_TYPE_BOOLEAN:
            *len = (uint16)sizeof(bool32);
            break;

        case GSC_TYPE_REAL:
            *len = (uint16)sizeof(double);
            break;

        case GSC_TYPE_NUMBER:
        case GSC_TYPE_NUMBER2:
        case GSC_TYPE_DECIMAL:
            *len = (uint16)GSC_NUMBER_BOUND_SIZE;
            break;
        case GSC_TYPE_BINARY:
        case GSC_TYPE_VARBINARY:
        case GSC_TYPE_RAW:
            *len = (uint16)CM_ALIGN4(field_info->size);
            break;
        case GSC_TYPE_CHAR:
        case GSC_TYPE_VARCHAR:
        case GSC_TYPE_STRING:
            *len = (uint16)MIN(GS_MAX_COLUMN_SIZE, CM_ALIGN4(field_info->size * GS_CHAR_TO_BYTES_RATIO));
            break;
        case GSC_TYPE_CLOB:
        case GSC_TYPE_BLOB:
        case GSC_TYPE_IMAGE:
        case GSC_TYPE_ARRAY:
            *len = (uint16)sizeof(gsc_lob_t);
            break;
        default:
            GSQL_PRINTF(ZSERR_IMPORT, "unknow data type when get bind length!");
            return GS_ERROR;
    }
    return GS_SUCCESS;
}

static status_t imp_bind_bin_column(importer_t *importer, imp_dml_worker_t *worker)
{
    imp_bind_info_t *bind_info = &(worker->bin_bind_info);
    import_bin_t *impbin = (import_bin_t *)worker->impbin;
    field_info_t *field_info = NULL;
    gsql_conn_info_t *conn_info = &(worker->conn_info);
    gsc_stmt_t stmt = conn_info->stmt;

    for (uint32 i = 0; i < bind_info->column_cnt; i++) {
        field_info = (field_info_t *)cm_list_get(&impbin->fieldInfo, i);
        if (field_info->type == GSC_TYPE_DATE) {
            GS_RETURN_IFERR(gsc_bind_by_pos(stmt, i, GSC_TYPE_NATIVE_DATE, bind_info->col_data[i],
                                            bind_info->bind_buf_len[i], bind_info->data_ind[i]));
        } else {
            GS_RETURN_IFERR(gsc_bind_by_pos(stmt, i, field_info->type, bind_info->col_data[i],
                                            bind_info->bind_buf_len[i], bind_info->data_ind[i]));
        }
    }
    return GS_SUCCESS;
}

static bool32 imp_get_field_info_is_array(field_info_t *field_info)
{
    if (g_import_bin.fileHead.fixed_head.client_ver >= EXP_CLI_VERSION_3) {
        return field_info->is_array;
    }
    return GS_FALSE;
}

static status_t imp_prepare_bin_bind_info(importer_t *importer, imp_dml_worker_t *worker)
{
    import_bin_t *impbin = (import_bin_t *)worker->impbin;
    gsql_conn_info_t *conn_info = &(worker->conn_info);
    imp_bind_info_t *bind_info = &(worker->bin_bind_info);
    uint32 used_offset = 0;
    field_info_t *field_info = NULL;
    uint32 each_row_size = 0;
    bool8 contains_lob = GS_FALSE;

    uint32 lobBatchRowCnt = (uint32)(worker->batchRowCnt / 10) > 0 ? (uint32)(worker->batchRowCnt / 10) : 1;

    /*  Generate the insert SQL for the loader */
    if (gsql_worker_make_insert_sql(worker) != GS_SUCCESS) {
        // get placeholders
        imp_tmlog_conn_error(conn_info->conn);
        return GS_ERROR;
    }

    /*  Prepare insert SQL for the import */
    GS_RETURN_IFERR(gsc_prepare(conn_info->stmt, importer->sql_cmd_buf));

    /* get 'impbin' bind info */
    bind_info->column_cnt = (uint32)impbin->fieldNum;
    MEMS_RETURN_IFERR(memset_s(bind_info->col_data, sizeof(bind_info->col_data), 0, sizeof(bind_info->col_data)));

    // set 'bind_info->bind_buf_len'
    for (uint32 i = 0; i < bind_info->column_cnt; i++) {
        field_info = (field_info_t *)cm_list_get(&impbin->fieldInfo, i);
        if (GS_SUCCESS != imp_get_bind_buffer_length(field_info, &(bind_info->bind_buf_len[i]))) {
            GSQL_PRINTF(ZSERR_IMPORT, "get bind buffer length for table %s column %s !",
                impbin->tableName, field_info->name);
            return GS_ERROR;
        }
        if (GSC_IS_LOB_TYPE(field_info->type) || imp_get_field_info_is_array(field_info)) {
            contains_lob = GS_TRUE;
        }
        each_row_size += bind_info->bind_buf_len[i];
    }

    // set 'bind_info->max_batch_row'
    bind_info->max_batch_row = (ROW_MAX_SIZE - used_offset) / (each_row_size + sizeof(uint16) * bind_info->column_cnt);
    if (bind_info->max_batch_row == 0) {
        GSQL_PRINTF(ZSERR_IMPORT, "buffer can not container one row data.!");
        return GS_ERROR;
    }
    // MAX bind rows is : MAX_BATCH_ROW_CNT
    if (bind_info->max_batch_row > worker->batchRowCnt) {
        bind_info->max_batch_row = worker->batchRowCnt;
    }
    // table containes lob columns MAX bind rows is : lobBatchRowCnt
    if (contains_lob && bind_info->max_batch_row > lobBatchRowCnt) {
        bind_info->max_batch_row = lobBatchRowCnt;
    }

    // set 'bind_info->data_ind'
    for (uint32 i = 0; i < bind_info->column_cnt; i++) {
        bind_info->data_ind[i] = (uint16 *)(bind_info->data_buffer + used_offset);
        used_offset += sizeof(uint16) * bind_info->max_batch_row;
    }

    // set 'bind_info->col_data'
    for (uint32 i = 0; i < bind_info->column_cnt; i++) {
        bind_info->col_data[i] = bind_info->data_buffer + used_offset;
        used_offset += bind_info->max_batch_row * bind_info->bind_buf_len[i];
    }
    gsc_set_paramset_size(conn_info->stmt, worker->bin_bind_info.max_batch_row);
    return imp_bind_bin_column(importer, worker);
}

static status_t imp_load_binrow2db(importer_t *importer, imp_dml_worker_t *worker, uint32 row)
{
    status_t ret;
    gsql_conn_info_t *conn_info = &(worker->conn_info);

    gsc_set_paramset_size(conn_info->stmt, row);
    ret = gsc_execute(conn_info->stmt);
    if (ret != GS_SUCCESS) {
        imp_tmlog_conn_error(conn_info->conn);
        if (!worker->ignore) {
            return GS_ERROR;
        }
    } else {
        ret = imp_commit(importer, conn_info->conn, FT_BIN);
        if (ret != GS_SUCCESS) {
            return GS_ERROR;
        }
    }
    return GS_SUCCESS;
}

static status_t imp_try_load_binrow2db(importer_t *importer, imp_dml_worker_t *worker, uint32 *row)
{
    status_t ret = GS_SUCCESS;
    gsql_conn_info_t *conn_info = &(worker->conn_info);

    if (*row > 0) {
        ret = imp_load_binrow2db(importer, worker, *row);
        /* set paramset size for lob bind. */
        gsc_set_paramset_size(conn_info->stmt, worker->bin_bind_info.max_batch_row);
        *row = 0;
    }
    return ret;
}

static status_t imp_decode_column_info(importer_t *importer, import_bin_t *imp_bin,
    bool32 update_array_type)
{
    field_info_t *columnInfo = NULL;

    GS_RETURN_IFERR(imp_get_uint16_from_buffer(imp_bin, &imp_bin->fieldNum, importer->impfp));

    cm_reset_list(&imp_bin->fieldInfo);
    for (int j = 0; j < imp_bin->fieldNum; j++) {
        GS_RETURN_IFERR(cm_list_new(&imp_bin->fieldInfo, (void *)&columnInfo));
        GS_RETURN_IFERR(imp_get_uint16_from_buffer(imp_bin, &columnInfo->nameLen, importer->impfp));
        GS_RETURN_IFERR(imp_get_data_from_buffer(imp_bin, columnInfo->name, sizeof(columnInfo->name),
            columnInfo->nameLen, importer->impfp));
        GS_RETURN_IFERR(imp_get_uint16_from_buffer(imp_bin, &columnInfo->type, importer->impfp));
        GS_RETURN_IFERR(imp_get_uint16_from_buffer(imp_bin, &columnInfo->size, importer->impfp));

        if (g_import_bin.fileHead.fixed_head.client_ver >= EXP_CLI_VERSION_3) {
            GS_RETURN_IFERR(imp_get_data_from_buffer(imp_bin, &columnInfo->is_array, sizeof(uchar),
                sizeof(uchar), importer->impfp));
            if (columnInfo->is_array && update_array_type) {
                columnInfo->type = GSC_TYPE_ARRAY;
            }
        }
    }

    return GS_SUCCESS;
}

// decode table and column info from subfile head.
static status_t imp_decode_subfile_head(importer_t *importer, imp_dml_worker_t *worker)
{
    import_bin_t *impbin = (import_bin_t *)worker->impbin;

    // decode table name.
    GS_RETURN_IFERR(imp_get_uint16_from_buffer(impbin, &impbin->tableNameLen, importer->impfp));
    GS_RETURN_IFERR(imp_get_data_from_buffer(impbin, impbin->tableName, sizeof(impbin->tableName),
        (uint32)impbin->tableNameLen, importer->impfp));
    impbin->tableName[impbin->tableNameLen] = '\0';

    // decode columns info of the table.
    GS_RETURN_IFERR(imp_decode_column_info(importer, impbin, GS_TRUE));

    return GS_SUCCESS;
}

static status_t imp_bin_subfile(importer_t *importer, imp_dml_worker_t *worker)
{
    status_t ret = GS_SUCCESS;
    import_bin_t *impbin = (import_bin_t *)worker->impbin;
    uint32 current_batch_row = 0;
    gsql_conn_info_t *conn_info = &(worker->conn_info);
    bool8 eof = GS_FALSE;

    impbin->binBufIndex = 0;
    impbin->binBufLen = 0;

    if (!conn_info->is_conn) {
        (void)gsql_print_disconn_error();
        return GS_ERROR;
    }

    if (gsql_read_raw_bin_data(impbin, importer->impfp, &eof) != GS_SUCCESS || eof) {
        return GS_ERROR;
    }
    GS_RETURN_IFERR(imp_change_curr_schema(&worker->conn_info, worker->currentSchema));

    GS_RETURN_IFERR(imp_decode_subfile_head(importer, worker));
    GS_RETURN_IFERR(imp_prepare_bin_bind_info(importer, worker));
    gsc_set_paramset_size(conn_info->stmt, worker->bin_bind_info.max_batch_row);

    GSQL_IMP_DEBUG("Begin to load subfile '%s' data to table '%s'.", worker->fileName, impbin->tableName);

    while (GS_TRUE) {
        // break if cancel
        if (GSQL_CANCELING) {
            GS_THROW_ERROR(ERR_OPERATION_CANCELED);
            ret = GS_ERROR;
            gsql_print_error(NULL);
            break;
        }

        if (impbin->binBufLen != RAW_BUF_SIZE) {
            if (impbin->binBufIndex >= impbin->binBufLen) {
                /* reach end */
                break;
            }
        } else {
            if (impbin->binBufIndex + MAX_SQL_SIZE >= impbin->binBufLen) {
                if (gsql_read_raw_bin_data(impbin, importer->impfp, &eof) != GS_SUCCESS || eof) {
                    /* reach end */
                    break;
                }
            }
        }

        ret = imp_read_rowdata(conn_info->stmt, worker, current_batch_row);
        if (ret != GS_SUCCESS) {
            GSQL_PRINTF(ZSERR_IMPORT, "read row data failed!");
            break;
        }
        current_batch_row++;
        importer->fileInsertNum++;
        (*worker->dml_status_param.record_count)++;

        /* do one batch commit */
        if (current_batch_row == worker->bin_bind_info.max_batch_row) {
            if (imp_try_load_binrow2db(importer, worker, &current_batch_row) != GS_SUCCESS) {
                ret = GS_ERROR;
                break;
            }
        }
    }
    if (ret == GS_SUCCESS) {  // do last batch commit
        if (imp_try_load_binrow2db(importer, worker, &current_batch_row) != GS_SUCCESS) {
            ret = GS_ERROR;
        }
    }

    if (ret == GS_ERROR) {
        GSQL_IMP_DEBUG("Load subfile '%s' data table failed, table name: '%s'.",
            worker->fileName, impbin->tableName);
    } else {
        GSQL_IMP_DEBUG("Load subfile '%s' data table success, table name: '%s', record number: %llu.",
            worker->fileName, impbin->tableName,
            (*worker->dml_status_param.record_count));
    }
    return ret;
}

static status_t gsql_worker_import(importer_t *importer, imp_dml_worker_t *worker)
{
    status_t ret;
    char dfName[GS_MAX_FILE_PATH_LENGH];
    char fileName[GS_FILE_NAME_BUFFER_SIZE] = { 0 };
    import_bin_t *impbin = (import_bin_t *)worker->impbin;

    cm_trim_dir(worker->fileName, sizeof(fileName), fileName);

    GS_RETURN_IFERR(imp_get_data_file(g_importer.imp_subfile_path, fileName, dfName, (uint32)strlen(fileName),
        GS_MAX_FILE_PATH_LENGH));
            
    impbin->compress_flag = g_import_bin.fileHead.fixed_head.comp_flag;  // get datafile compress flag.

    ret = imp_open_file(&importer->impfp, dfName, &impbin->df_handle.zstream, impbin->compress_flag);
    if (ret != GS_SUCCESS) {
        imp_close_file(&importer->impfp, &impbin->df_handle.zstream, impbin->compress_flag);
        GSQL_PRINTF(ZSERR_IMPORT, "open data file %s failed!", worker->fileName);
        return ret;
    }
    // file buffer reseting
    importer->rawBufLen = 0;
    importer->rawBufIndex = 0;
    impbin->lf_handle.fp = NULL;
    impbin->lf_handle.swap_len = SIZE_K(4);
    impbin->lf_handle.swap_buffer = (char*)malloc(impbin->lf_handle.swap_len);
    if (impbin->lf_handle.swap_buffer == NULL) {
        GSQL_PRINTF(ZSERR_IMPORT, "failed to malloc compress memory for lob file !");
        return GS_ERROR;
    }

    if (worker->fileType == FT_TXT) {
        importer->eof = GS_FALSE;
        ret = imp_text_subfile(importer, worker);
    } else {
        ret = imp_bin_subfile(importer, worker);
    }

    worker->fileInsertNum = importer->fileInsertNum;

    imp_close_file(&importer->impfp, &impbin->df_handle.zstream, impbin->compress_flag);
    imp_close_file(&impbin->lf_handle.fp, &impbin->lf_handle.zstream, impbin->compress_flag);
    CM_FREE_PTR(impbin->lf_handle.swap_buffer);
    return ret;
}

static status_t imp_wait_dml_thread(imp_ddl_worker_t *worker)
{
    importer_t *importer = (importer_t *)worker->importer;
    imp_dml_status_t *status = &worker->dml_status;

    uint32 finish_thread_num = 0;
    while (GS_TRUE) {
        // if other DDL thread failed , return failed.
        if (importer->fatal_error) {
            return GS_ERROR;
        }

        for (uint32 i = 0; i < status->dml_parallel; i++) {
            if (status->dml_end_flag[i]) {
                if (status->dml_return[i] == WORKER_STATUS_ERR) {
                    return GS_ERROR;
                }
                finish_thread_num++;
            }
        }
        if (finish_thread_num == status->dml_parallel) {
            return GS_SUCCESS;
        }
        finish_thread_num = 0;
        cm_sleep(20);
    }
}

static status_t imp_proc_ddl_block_schema(imp_ddl_worker_t *worker, import_ddl_block *block)
{
    errno_t errcode;

    if (strcmp(worker->currentSchema, block->schema) == 0) {
        return GS_SUCCESS;
    }

    GS_RETURN_IFERR(imp_change_curr_schema(&worker->conn_info, block->schema));
    errcode = memcpy_s(worker->currentSchema, sizeof(worker->currentSchema), block->schema, strlen(block->schema) + 1);
    if (errcode != EOK) {
        GSQL_PRINTF(ZSERR_LOAD, "copy schema to DDL thread failed.");
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

static bool8 imp_find_object(list_t *all_objects, const char *object, bool8 case_sensitive)
{
    const char *one_object = NULL;

    for (uint32 i = 0; i < all_objects->count; i++) {
        one_object = cm_list_get(all_objects, i);
        if (case_sensitive) {
            GS_RETVALUE_IFTRUE(cm_str_equal(one_object, object), GS_TRUE);
        } else {
            GS_RETVALUE_IFTRUE(cm_str_equal_ins(one_object, object), GS_TRUE);
        }
    }
    return GS_FALSE;
}

static status_t imp_filter_trigger(importer_t *importer, import_ddl_block *block, bool8 *filtered)
{
    lex_t lex;
    bool32 result = GS_FALSE;
    word_t word;
    list_t *table_list = &importer->obj_list;
    char trig_name[GS_MAX_NAME_LEN + 1];

    if (block->type == IMP_BLOCK_FUNC &&
        cm_str_equal(block->schema, importer->singleSchema)) {
        imp_init_lex(&lex, &block->sql_txt);
        GS_RETURN_IFERR(lex_try_fetch4(&lex, "CREATE", "OR", "REPLACE", "TRIGGER", &result));
        if (result) {
            if (importer->imp_type == IMP_ALL_TABLES) {
                *filtered = GS_FALSE;
                return GS_SUCCESS;
            }

            GS_RETURN_IFERR(lex_fetch(&lex, &word));  // trigger name
            GS_RETURN_IFERR(lex_fetch(&lex, &word));  // before/after
            GS_RETURN_IFERR(lex_fetch(&lex, &word));  // insert/update/delete
            GS_RETURN_IFERR(lex_fetch(&lex, &word));  // on
            GS_RETURN_IFERR(lex_fetch(&lex, &word));  // table name
            MEMS_RETURN_IFERR(strncpy_s(trig_name, GS_MAX_NAME_LEN + 1, word.text.str, word.text.len));

            if (imp_find_object(table_list, trig_name, word.type == WORD_TYPE_DQ_STRING)) {
                *filtered = GS_FALSE;
            }
        }
    }
    return GS_SUCCESS;
}

static status_t imp_filter_special_table_content(importer_t *importer, import_ddl_block *block, bool8 *filtered)
{
    import_ddl_block *sub_blocks = (import_ddl_block *)block->sql_txt.str;
    list_t *table_list = &importer->obj_list;

    *filtered = GS_TRUE;

    for (uint32 i = 0; i < block->sql_txt.len; i++) {
        if (sub_blocks[i].type == IMP_BLOCK_TABLE_NAME) {
            if (imp_find_object(table_list, sub_blocks[i].sql_txt.str, GS_TRUE)) {
                *filtered = GS_FALSE;
                break;
            }
        }
    }

    return GS_SUCCESS;
}

static status_t imp_filter_special_table_nocontent(importer_t *importer, import_ddl_block *block, bool8 *filtered)
{
    import_ddl_block *sub_blocks = (import_ddl_block *)block->sql_txt.str;
    list_t *table_list = &importer->obj_list;
    bool8 matched = GS_FALSE;
    lex_t lex;

    *filtered = GS_TRUE;

    for (uint32 i = 0; i < block->sql_txt.len; i++) {
        if (sub_blocks[i].type == IMP_BLOCK_TABLE) {
            imp_init_lex(&lex, &sub_blocks[i].sql_txt);

            /* judge table is matched,if matched, setted to GS_TRUE  */
            if (imp_tables_data(&(sub_blocks[i].sql_txt), table_list, &matched) != GS_SUCCESS) {
                imp_timing_log(GS_TRUE, "Incorrect sql:\n%s\n", sub_blocks[i].sql_txt.str);
                return GS_ERROR;
            }
            *filtered = !matched;
            break;
        }
    }

    return GS_SUCCESS;
}

static status_t imp_filter_special_drop_table(importer_t *importer, import_ddl_block *block, bool8 *filtered)
{
    list_t *table_list = &importer->obj_list;
    lex_t lex;
    bool8 matched = GS_FALSE;

    *filtered = GS_TRUE;

    imp_init_lex(&lex, &block->sql_txt);
            
    // if drop table matched, this segment will be executed
    GS_RETURN_IFERR(imp_tables_data_drop_table(&lex, table_list, &matched));
    *filtered = !matched;

    return GS_SUCCESS;
}

static status_t imp_filter_special_table(importer_t *importer, import_ddl_block *block, bool8 *filtered)
{
    *filtered = GS_TRUE;

    if (block->type == IMP_BLOCK_COMPLETE_TABLE &&
        cm_str_equal(block->schema, importer->singleSchema)) {
        if (importer->exp_content & CT_DATA_ONLY) {
            GS_RETURN_IFERR(imp_filter_special_table_content(importer, block, filtered));
        } else {
            GS_RETURN_IFERR(imp_filter_special_table_nocontent(importer, block, filtered));
        }
    }

    if (block->type == IMP_BLOCK_DROP_TABLE &&
        cm_str_equal(block->schema, importer->singleSchema)) {
        GS_RETURN_IFERR(imp_filter_special_drop_table(importer, block, filtered));
    }

    GS_RETURN_IFERR(imp_filter_trigger(importer, block, filtered));
    return GS_SUCCESS;
}

static status_t imp_filter_tables(importer_t *importer, import_ddl_block *block, bool8 *filtered)
{
    *filtered = GS_TRUE;

    if ((block->type == IMP_BLOCK_COMPLETE_TABLE || block->type == IMP_BLOCK_DROP_TABLE) &&
        cm_str_equal(block->schema, importer->singleSchema)) {
        *filtered = GS_FALSE;
    }

    GS_RETURN_IFERR(imp_filter_trigger(importer, block, filtered));
    return GS_SUCCESS;
}

static status_t imp_filter_schema(importer_t *importer, import_ddl_block *block, bool8 *filtered)
{
    list_t *schema_list = &importer->obj_list;

    *filtered = GS_TRUE;

    if (imp_find_object(schema_list, block->schema, GS_TRUE)) {
        *filtered = GS_FALSE;
    }

    return GS_SUCCESS;
}

static bool8 imp_is_sql_end(text_t *line, char terminal_char, int32 *is_enclosed);
static bool8 imp_is_comment_line(text_t *line, imp_sql_parser_t *parser);

static void imp_judge_sql_end(imp_sql_parser_t *parser, text_t *line)
{
    if (parser->is_pl) {
        cm_trim_text(line);
        // try fetch '/' enclosed by '''
        if (line->len <= 1 && line->str[0] == '/' && imp_is_sql_end(line, '/', &(parser->in_enclosed_char))) {
            parser->got_sql = GS_TRUE;
        }
    } else {  // sql exp do not have comment.
        // try fetch ';' enclosed by '''
        if (imp_is_sql_end(line, ';', &(parser->in_enclosed_char))) {
            parser->got_sql = GS_TRUE;
        }
    }
}

static status_t imp_judge_sql_type(imp_sql_parser_t *parser, text_t *line)
{
    lex_t lex;
    bool32 is_pl = GS_FALSE;

    parser->got_sql = GS_FALSE;
    parser->is_pl = GS_FALSE;

    // try got @@ filename
    if (line->len > 3 && line->str[0] == '@' && line->str[1] == '@' && line->str[2] == ' ') {
        parser->got_sql = GS_TRUE;
        return GS_SUCCESS;
    }

    // try got / line
    cm_trim_text(line);
    if (line->len <= 2 && line->str[0] == '/') {
        parser->got_sql = GS_TRUE;
        return GS_SUCCESS;
    }

    // judge is PL
    imp_init_lex(&lex, line);
    GS_RETURN_IFERR(lex_try_fetch3(&lex, "CREATE", "OR", "REPLACE", &is_pl));
    parser->is_pl = (bool8)is_pl;
    return GS_SUCCESS;
}

static inline bool8 imp_parser_sql_complete(imp_sql_parser_t *parser)
{
    return parser->got_sql;
}

static inline bool8 imp_parser_enclosed(imp_sql_parser_t *parser)
{
    return parser->in_enclosed_char != -1;
}

static inline void imp_parser_clear_sql(imp_sql_parser_t *parser)
{
    parser->sql.str = NULL;
    parser->sql.len = 0;
}

static inline bool8 imp_parser_sql_cleared(imp_sql_parser_t *parser)
{
    return parser->sql.str == NULL;
}

static inline void imp_reset_parser(imp_sql_parser_t *parser)
{
    parser->is_block_comment = GS_FALSE;
    parser->is_pl = GS_FALSE;
    parser->first_line = GS_TRUE;
    parser->in_enclosed_char = -1;
    parser->got_sql = GS_FALSE;
    imp_parser_clear_sql(parser);
}

// return value indicate whether is a complete sql
static bool8 imp_parse_line(imp_sql_parser_t *parser, text_t *line)
{
    // setup parser's sql, when : 1. this is first line, 2. sql has been got by user
    if (parser->first_line || imp_parser_sql_cleared(parser)) {
        parser->sql = *line;
    } else {
        parser->sql.len += line->len;
    }

    // whether is a comment
    if (!imp_parser_enclosed(parser) && imp_is_comment_line(line, parser)) {
        return GS_FALSE;
    }

    if (parser->first_line) {
        while (GS_TRUE) {
            if (line->len > 0 && GSQL_ENTRY_SYMBOL(line->str[0])) {
                CM_REMOVE_FIRST(line);
                continue;
            }
            break;
        }

        if (line->len == 0) {
            return GS_FALSE;
        }

        GS_RETURN_IFERR(imp_judge_sql_type(parser, line));
        if (imp_parser_sql_complete(parser)) {
            imp_log_sql("fetch SQL", &(parser->sql));
            return GS_TRUE;
        }

        parser->first_line = GS_FALSE;
    }

    imp_judge_sql_end(parser, line);

    if (imp_parser_sql_complete(parser)) {
        imp_log_sql("fetch SQL", &(parser->sql));
        return GS_TRUE;
    }
    return GS_FALSE;
}

// read a complete SQL or PL
static status_t imp_fetch_sql(text_t *multi_block, text_t *block)
{
    text_t line;
    text_t remain;
    imp_sql_parser_t parser;

    imp_reset_parser(&parser);
    block->len = 0;

    /* line:
    1. -- comment
    2. SQL
    3. PL
    */
    while (GS_TRUE) {
        cm_split_text(multi_block, '\n', '\0', &line, &remain);
        *multi_block = remain;
        // include '\n'
        if (remain.str != NULL) {
            line.len++;
        }

        if (imp_parse_line(&parser, &line)) {
            *block = parser.sql;
            return GS_SUCCESS;
        }
        // last line
        if (remain.str == NULL) {
            break;
        }
    }

    if (!imp_parser_sql_complete(&parser) && parser.sql.len > 0) {
        GSQL_PRINTF(ZSERR_IMPORT, "sql not complete: %.*s", parser.sql.len, parser.sql.str);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static void imp_ddl_throw_error(imp_ddl_worker_t* worker, status_t ret)
{
    int code = ERR_ERRNO_BASE;
    const char *message = NULL;
    errno_t errcode;
    importer_t *importer = (importer_t *)worker->importer;

    gsql_get_error(worker->conn_info.conn, &code, &message, NULL);

    // set worker status & importer error flag
    worker->status = WORKER_STATUS_ERR;
    importer->fatal_error = GS_TRUE;

    // set worker error info
    worker->error_info->error_code = code;
    worker->error_info->error_msg[0] = 0;
    if (code != ERR_ERRNO_BASE) {
        errcode = strncpy_s(worker->error_info->error_msg,
            sizeof(worker->error_info->error_msg),
            message, strlen(message));
        if (errcode != EOK) {
            gsql_printf("remaining the error message '%s' is failed.\n", message);
        }
    }

    cm_reset_error();
}

static status_t imp_bin_remap_block_tablespace(importer_t *importer, import_ddl_block *block)
{
    import_ddl_block old_block;
    text_t block_sql;
    text_t single_sql;
    text_t last_sql;
    lex_t lex;

    GS_RETURN_IFERR(imp_shallow_copy_ddl_block(block, &old_block));
    GS_RETURN_IFERR(imp_construct_ddl_block(importer, block, block->type, old_block.schema,
                                            (uint32)strlen(old_block.schema), old_block.statistic));
    block_sql = old_block.sql_txt;
    do {
        GS_RETURN_IFERR(imp_fetch_sql(&block_sql, &single_sql));
        if (single_sql.len > 0) {
            cm_concat_text(&block->sql_txt, MAX_SQL_SIZE, &single_sql);
            CM_NULL_TERM(&block->sql_txt);
            last_sql.str = block->sql_txt.str + (block->sql_txt.len - single_sql.len);
            last_sql.len = single_sql.len;
            imp_init_lex(&lex, &last_sql);
            GS_RETURN_IFERR(remap_table_space(&importer->tblSpaceMaps, &last_sql,
                block->max_size - (uint32)(last_sql.str - block->sql_txt.str)));
            // re calc sql len
            block->sql_txt.len = (block->sql_txt.len - single_sql.len) + (uint32)strlen(last_sql.str);
        }
    } while (single_sql.len > 0);
    CM_NULL_TERM(&block->sql_txt);
    imp_destory_ddl_block(importer, &old_block);
    return GS_SUCCESS;
}

static status_t imp_bin_remap_tablespace(importer_t *importer, import_ddl_block *block, bool8 *filtered)
{
    import_ddl_block *sub_blocks = (import_ddl_block *)block->sql_txt.str;

    // tablespace remap list 'importer->tblSpaceMaps', if filtered , no need remap
    if (*filtered) {
        return GS_SUCCESS;
    }

    if (importer->tblSpaceMaps.count > 0) {
        if (block->type == IMP_BLOCK_COMPLETE_TABLE) {
            for (uint32 i = 0; i < SUB_DDL_BLOCK_COUNT(block); i++) {
                if (sub_blocks[i].type == IMP_BLOCK_TABLE || sub_blocks[i].type == IMP_BLOCK_TABLE_INDEX) {
                    GS_RETURN_IFERR(imp_bin_remap_block_tablespace(importer, &(sub_blocks[i])));
                }
            }
        }
    }

    return GS_SUCCESS;
}

static status_t imp_bin_remap_block_schema(importer_t *importer, import_ddl_block *block, bool8 *filtered)
{
    list_t *schema_list = &importer->obj_list;

    // block remap
    if (imp_find_object(schema_list, block->schema, GS_TRUE)) {
        GSQL_IMP_DEBUG("remap block schema info from '%s' to '%s'.", block->schema, importer->targetObj);
        MEMS_RETURN_IFERR(strncpy_s(block->schema, sizeof(block->schema), importer->targetObj, strlen(importer->targetObj)));
        *filtered = GS_FALSE;
    }

    // sub block remap
    if (INCLUDE_SUB_DDL_BLOCK(block)) {
        for (uint32 i = 0; i < SUB_DDL_BLOCK_COUNT(block); i++) {
            GS_RETURN_IFERR(imp_bin_remap_block_schema(importer, SUB_DDL_BLOCK_PTR(block, i), filtered));
        }
    }

    return GS_SUCCESS;
}

static status_t imp_bin_remap_schema(importer_t *importer, import_ddl_block *block, bool8 *filtered)
{
    text_t change_schema_sql;
    text_t block_sql;
    import_ddl_block old_block;
    lex_t lex;
    const char *change_schema_words[5] = { "ALTER", "SESSION", "SET", "CURRENT_SCHEMA", "=" };
    bool32 is_change_schema_sql = GS_FALSE;
    text_t change_schema_pre = { .str = "ALTER SESSION SET CURRENT_SCHEMA = ",
                                 .len = (uint32)strlen("ALTER SESSION SET CURRENT_SCHEMA = ") };

    // schema remap from 'importer->obj_list' to 'importer->targetOb'
    *filtered = GS_TRUE;

    // remap schema info at block.
    GS_RETURN_IFERR(imp_bin_remap_block_schema(importer, block, filtered));

    // remap alter session schema sql
    if (!(*filtered) && block->type == IMP_BLOCK_SEQ) {
        GS_RETURN_IFERR(imp_shallow_copy_ddl_block(block, &old_block));
        GS_RETURN_IFERR(imp_construct_ddl_block(importer, block, IMP_BLOCK_SEQ, old_block.schema,
                                                (uint32)strlen(old_block.schema), old_block.statistic));
        block_sql = old_block.sql_txt;
        do {
            GS_RETURN_IFERR(imp_fetch_sql(&block_sql, &change_schema_sql));
            if (change_schema_sql.len > 0) {
                imp_init_lex(&lex, &change_schema_sql);
                GS_RETURN_IFERR(lex_try_fetch_n(&lex, 5, change_schema_words, &is_change_schema_sql));
                if (is_change_schema_sql) {
                    cm_concat_text(&block->sql_txt, MAX_SQL_SIZE, &change_schema_pre);
                    cm_concat_string(&block->sql_txt, MAX_SQL_SIZE, block->schema);
                    CM_TEXT_APPEND(&block->sql_txt, ';');
                } else {
                    cm_concat_text(&block->sql_txt, MAX_SQL_SIZE, &change_schema_sql);
                }
            }
        } while (change_schema_sql.len > 0);
        CM_NULL_TERM(&block->sql_txt);
        imp_destory_ddl_block(importer, &old_block);
    }

    return GS_SUCCESS;
}

static status_t imp_filter_content_meta(importer_t *importer, import_ddl_block *block, bool8 *filtered)
{
    import_ddl_block *sub_blocks = NULL;

    *filtered = GS_FALSE;

    // export content do not contain metadata info, filter the block.
    if (!(importer->exp_content & CT_METADATA_ONLY)) {
        *filtered = GS_TRUE;
        return GS_SUCCESS;
    }

    if (block->type == IMP_BLOCK_COMPLETE_TABLE) {
        sub_blocks = (import_ddl_block *)block->sql_txt.str;

        for (uint32 i = 0; i < SUB_DDL_BLOCK_COUNT(block); i++) {
            if (IS_DATA_BLOCK(&sub_blocks[i])) {
                GS_RETURN_IFERR(imp_remove_ddl_block(importer, block, i));
                i--;
            }
        }
    }
    return GS_SUCCESS;
}

static status_t imp_filter_content_data(importer_t *importer, import_ddl_block *block, bool8 *filtered)
{
    import_ddl_block *sub_blocks = NULL;

    *filtered = GS_TRUE;

    // export content do not contain data info, filter the block.
    if (!(importer->exp_content & CT_DATA_ONLY)) {
        *filtered = GS_TRUE;
        return GS_SUCCESS;
    }

    if (block->type == IMP_BLOCK_SEQ) {
        *filtered = GS_FALSE;
        return GS_SUCCESS;
    }

    if (block->type == IMP_BLOCK_COMPLETE_TABLE) {
        *filtered = GS_FALSE;
        sub_blocks = (import_ddl_block *)block->sql_txt.str;

        for (uint32 i = 0; i < SUB_DDL_BLOCK_COUNT(block); i++) {
            if (!IS_DATA_BLOCK(&sub_blocks[i])) {
                GS_RETURN_IFERR(imp_remove_ddl_block(importer, block, i));
                i--;
            }
        }
    }
    return GS_SUCCESS;
}

static status_t imp_filter_content(importer_t *importer, import_ddl_block *block, bool8 *filtered)
{
    *filtered = GS_FALSE;

    switch (importer->content) {
        case CT_METADATA_ONLY:
            return imp_filter_content_meta(importer, block, filtered);
        case CT_DATA_ONLY:
            return imp_filter_content_data(importer, block, filtered);
        case CT_ALL:
        default:
            return GS_SUCCESS;
    }
}

static status_t imp_filter_create_user(importer_t *importer, import_ddl_block *block, bool8 *filtered)
{
    import_ddl_block old_block;
    text_t block_sql;
    text_t single_sql;

    *filtered = GS_FALSE;

    if (importer->create_user) {
        return GS_SUCCESS;
    }

    if (block->type != IMP_BLOCK_SEQ ||
        imp_sql_type(&(block->sql_txt)) != IMP_SQL_CREATE_USER) {
        return GS_SUCCESS;
    }
    // split create user SQL.
    GS_RETURN_IFERR(imp_shallow_copy_ddl_block(block, &old_block));
    GS_RETURN_IFERR(imp_construct_ddl_block(importer, block, block->type, old_block.schema,
        (uint32)strlen(old_block.schema), old_block.statistic));
    block_sql = old_block.sql_txt;
    do {
        GS_RETURN_IFERR(imp_fetch_sql(&block_sql, &single_sql));
        if (imp_sql_type(&single_sql) != IMP_SQL_CREATE_USER) {
            cm_concat_text(&block->sql_txt, MAX_SQL_SIZE, &single_sql);
        }
    } while (single_sql.len > 0);
    CM_NULL_TERM(&block->sql_txt);
    imp_destory_ddl_block(importer, &old_block);
    // if empty, filter this block.
    *filtered = (block->sql_txt.len == 0);
    return GS_SUCCESS;
}

static status_t imp_remap_ddl_block(importer_t *importer, import_ddl_block *block, bool8 *filtered)
{
    status_t ret = GS_SUCCESS;

    GS_RETURN_IFERR(imp_filter_create_user(importer, block, filtered));
    // if block is filterd , no need to load.
    GS_RETSUC_IFTRUE(*filtered);

    switch (importer->imp_type) {
        case IMP_TABLE:
            ret = imp_filter_special_table(importer, block, filtered);
            break;
        case IMP_ALL_TABLES:
            ret = imp_filter_tables(importer, block, filtered);
            break;
        case IMP_SCHEMA:
            ret = imp_filter_schema(importer, block, filtered);
            break;
        case IMP_REMAP_SCHEMA:
            ret = imp_bin_remap_schema(importer, block, filtered);
            break;
        case IMP_ALL_SCHEMAS:
        case IMP_FULL:
            *filtered = GS_FALSE;
            ret = GS_SUCCESS;
            break;
        default:
            GSQL_PRINTF(ZSERR_LOAD, "unsupport import type %u when in BIN mode.", importer->imp_type);
            return GS_ERROR;
    }

    GS_RETURN_IFERR(ret);
    // if block is filterd , no need to load.
    GS_RETSUC_IFTRUE(*filtered);

    GS_RETURN_IFERR(imp_filter_content(importer, block, filtered));
    // if block is filterd , no need to load.
    GS_RETSUC_IFTRUE(*filtered);

    return imp_bin_remap_tablespace(importer, block, filtered);
}

static status_t imp_call_proc_ddl_func(imp_ddl_ctx_param_t param, import_ddl_block *block, bool8 parallel)
{
    uint32 func_index = (uint32)block->type;
    uint32 func_cnt = sizeof(g_ddl_func_map) / sizeof(imp_ddl_proc_func_map_t);

    if (SECUREC_UNLIKELY(block->sql_txt.len == 0 && block->type != IMP_BLOCK_SUB_FILE_END)) {
        GSQL_PRINTF(ZSERR_IMPORT, "block length is illegal.");
        return GS_ERROR;
    }

    if (SECUREC_UNLIKELY(func_index >= func_cnt)) {
        GSQL_PRINTF(ZSERR_LOAD, "unsupported %s DDL block %u.", parallel ? "parallel" : "serial", block->type);
        return GS_ERROR;
    }

    if (SECUREC_UNLIKELY(g_ddl_func_map[func_index].type != block->type)) {
        GSQL_PRINTF(ZSERR_LOAD, "unmatched func type %u with DDL block %u.", g_ddl_func_map[func_index].type, block->type);
        return GS_ERROR;
    }

    if (parallel) {
        if (SECUREC_UNLIKELY(g_ddl_func_map[func_index].par_func == NULL)) {
            GSQL_PRINTF(ZSERR_LOAD, "unsupported parallel DDL block %u.", block->type);
            return GS_ERROR;
        }
        return g_ddl_func_map[func_index].par_func((imp_ddl_worker_t*)param, block);
    } else {
        if (SECUREC_UNLIKELY(g_ddl_func_map[func_index].serial_func == NULL)) {
            GSQL_PRINTF(ZSERR_LOAD, "unsupported serial DDL block %u.", block->type);
            return GS_ERROR;
        }
        return g_ddl_func_map[func_index].serial_func((imp_ddl_ctx_t*)param, block);
    }
}

static status_t imp_proc_ddl_block(imp_ddl_worker_t *worker, import_ddl_block *block)
{
    importer_t *importer = (importer_t *)worker->importer;
    status_t ret = GS_SUCCESS;

    GS_RETURN_IFERR(imp_proc_ddl_block_schema(worker, block));

    ret = imp_call_proc_ddl_func((imp_ddl_ctx_param_t)worker, block, GS_TRUE);

    imp_destory_ddl_block(importer, block);
    return ret;
}

static bool8 imp_has_idle_ddl_worker(importer_t *importer)
{
    for (uint32 i = 0; i < importer->ddl_parallel; i++) {
        if (importer->ddl_workers[i].idle) {
            return GS_TRUE;
        }
    }
    return GS_FALSE;
}

static bool8 imp_has_idle_dml_worker(importer_t *importer)
{
    for (uint32 i = 0; i < importer->parallel; i++) {
        if (importer->dml_workers[i].idle) {
            return GS_TRUE;
        }
    }
    return GS_FALSE;
}

static status_t imp_par_proc_block_single_sql(imp_ddl_worker_t *worker, import_ddl_block *block)
{
    importer_t *importer = (importer_t *)worker->importer;
    return gsql_bin_import_one_sql_in_conn(importer, worker->conn_info.conn, &(block->sql_txt), GS_TRUE);
}

static status_t imp_par_proc_block_multi_sql(imp_ddl_worker_t *worker, import_ddl_block *block)
{
    importer_t *importer = (importer_t *)worker->importer;
    return gsql_bin_import_one_sql_in_conn(importer, worker->conn_info.conn, &(block->sql_txt), GS_FALSE);
}

static status_t imp_par_proc_block_table_name(imp_ddl_worker_t *worker, import_ddl_block *block)
{
    errno_t errcode;
    errcode = memcpy_s(worker->current_table, sizeof(worker->current_table), block->sql_txt.str,
        block->sql_txt.len + 1);
    if (errcode != EOK) {
        GSQL_PRINTF(ZSERR_IMPORT, "copy table name to DDL thread failed.");
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

static status_t imp_par_proc_block_sub_file(imp_ddl_worker_t *worker, import_ddl_block *block)
{
    importer_t *importer = (importer_t *)worker->importer;
    text_t schema_txt;

    if (worker->dml_status.dml_parallel == worker->dml_status.max_dml_parallel) {
        GSQL_PRINTF(ZSERR_IMPORT, "sub file count more than maximum %u !",
            worker->dml_status.max_dml_parallel);
        return GS_ERROR;
    }

    /*
        1. if has idle DDL thread, can try active DML thread direct
        2. if all DDL thread is busy, has idle DML thread , can try active DML thread
        3. if all DDL/DML thread is busy, when current subfile finished try to active next DML task.
    */
    if (imp_has_idle_ddl_worker(importer) ||
        imp_has_idle_dml_worker(importer) ||
        imp_wait_dml_thread(worker) == GS_SUCCESS) {
        schema_txt.str = worker->currentSchema;
        schema_txt.len = (uint32)strlen(worker->currentSchema);
        worker->dml_status.dml_end_flag[worker->dml_status.dml_parallel] = GS_FALSE;
        worker->dml_status.dml_record_count[worker->dml_status.dml_parallel] = 0;
        worker->dml_status.dml_return[worker->dml_status.dml_parallel] = WORKER_STATUS_RECV;
        GS_RETURN_IFERR(imp_active_dml_thread(importer, block->sql_txt.str, &schema_txt,
            &worker->dml_status, worker->dml_status.dml_parallel));
        worker->dml_status.dml_parallel++;
    }

    return GS_SUCCESS;
}

static status_t imp_par_proc_block_sub_file_end(imp_ddl_worker_t *worker, import_ddl_block *block)
{
    uint64 record_num;

    if (imp_wait_dml_thread(worker) != GS_SUCCESS) {
        // sub file load failed.
        GSQL_PRINTF(ZSERR_IMPORT, "Load sub file failed !");
        return GS_ERROR;
    }
    record_num = 0;
    for (uint32 i = 0; i < worker->dml_status.dml_parallel; i++) {
        record_num += worker->dml_status.dml_record_count[i];
    }
    imp_log(IMP_INDENT2 "%-64s %-20llu\n", worker->current_table, record_num);
    worker->dml_status.dml_parallel = 0;
    return GS_SUCCESS;
}

static status_t imp_par_proc_parent_block(imp_ddl_worker_t *worker, import_ddl_block *block)
{
    status_t ret = GS_SUCCESS;
    import_ddl_block *sub_block = NULL;

    sub_block = (import_ddl_block *)block->sql_txt.str;
    for (uint32 i = 0; i < block->sql_txt.len; i++) {
        if (imp_proc_ddl_block(worker, &(sub_block[i])) != GS_SUCCESS) {
            ret = GS_ERROR;
            // free other blocks
            for (i = i + 1; i < block->sql_txt.len; i++) {
                imp_destory_ddl_block((importer_t *)worker->importer, &(sub_block[i]));
            }
            break;
        }
    }
    block->sql_txt.len = 0;  // sub block freed at 'imp_proc_ddl_block'
    return ret;
}

static status_t imp_par_proc_block_profile(imp_ddl_worker_t *worker, import_ddl_block *block)
{
    importer_t *importer = (importer_t *)worker->importer;
    status_t ret;

    ret = gsql_bin_import_one_sql_in_conn(importer, worker->conn_info.conn, &(block->sql_txt), GS_TRUE);
    if (ret != GS_SUCCESS) { // ignore execute create profile sql failed.
        imp_log("    Warning: profile can not been dropped or created.\n");
    }

    return GS_SUCCESS;
}

static status_t imp_serial_proc_block_multi_sql(imp_ddl_ctx_t *ctx, import_ddl_block *block)
{
    importer_t *importer = ctx->importer;
    return gsql_bin_import_one_sql_in_conn(importer, ctx->conn_info->conn, &(block->sql_txt), GS_FALSE);
}

static status_t imp_serial_proc_block_single_sql(imp_ddl_ctx_t *ctx, import_ddl_block *block)
{
    importer_t *importer = ctx->importer;
    return gsql_bin_import_one_sql_in_conn(importer, ctx->conn_info->conn, &(block->sql_txt), GS_TRUE);
}


static status_t gsql_proc_ddl(imp_ddl_worker_t *worker)
{
    chan_t *chan = worker->ddl_queue->chan;
    import_ddl_block block;
    importer_t *importer = (importer_t *)worker->importer;
    bool8 filterd = GS_FALSE;
    status_t ret = GS_SUCCESS;

    while (!worker->closed) {
        // stop ddl proc when cancel.
        IMP_RETRUN_IF_CANCEL;

        ret = cm_chan_recv_timeout(chan, &block, 10);
        if (ret != GS_SUCCESS) {
            if (ret == GS_TIMEDOUT) {
                continue;
            }
            break;
        }

        if (block.type == IMP_BLOCK_END) {
            ret = GS_SUCCESS;
            imp_destory_ddl_block(importer, &block);
            break;
        }

        worker->idle = GS_FALSE;

        if (block.sql_txt.len != 0) {
            ret = imp_remap_ddl_block(importer, &block, &filterd);
            if (ret != GS_SUCCESS) {
                break;
            }

            // if block need to be import
            if (!filterd) {
                // do statistic
                imp_do_statistic(block.statistic, block.type);

                ret = imp_proc_ddl_block(worker, &block);
                if (ret != GS_SUCCESS) {
                    break;
                }
            } else {  // just destory filter block
                imp_destory_ddl_block(importer, &block);
            }
        }

        imp_inc_outqueue_cnt(worker->ddl_queue);
        worker->idle = GS_TRUE;
    }
    return ret;
}

static void gsql_ddl_worker_proc(thread_t *thread)
{
    imp_ddl_worker_t *worker = (imp_ddl_worker_t *)thread->argument;
    status_t ret = GS_SUCCESS;
    cm_set_thread_name("metadata load");

    worker->status = WORKER_STATUS_RECV;
    ret = gsql_ddl_worker_init(worker);
    if (ret != GS_SUCCESS) {
        imp_ddl_throw_error(worker, ret); // transfer error information to main thread.
        return;
    }

    ret = gsql_proc_ddl(worker);
    if (ret != GS_SUCCESS) {
        imp_ddl_throw_error(worker, ret); // transfer error information to main thread.
    }

    worker->status = (ret == GS_SUCCESS ? WORKER_STATUS_END : WORKER_STATUS_ERR);
    gsql_ddl_worker_free(worker);
    worker->closed = GS_TRUE;
    worker->idle = GS_TRUE;
    return;
}

static void gsql_worker_proc(thread_t *thread)
{
    imp_dml_worker_t *worker = (imp_dml_worker_t *)thread->argument;
    status_t ret = GS_SUCCESS;
    importer_t *importer = NULL;

    cm_set_thread_name("data load");

    while (GS_TRUE) {
        /* when current task is done , 'idle' is setted, then status can be setted to END */
        if (worker->closed && worker->idle) {
            worker->status = WORKER_STATUS_END;
        } else if (worker->status != WORKER_STATUS_ERR) {
            /* no task setted into DML thread. */
            if (worker->idle) {
                cm_sleep(10);
                continue;
            }
        }

        switch (worker->status) {
            case WORKER_STATUS_INIT:
                ret = gsql_worker_init(worker);
                importer = (importer_t *)(worker->importer);
                worker->status = GET_NEXT_STATUS(ret, WORKER_STATUS_RECV, WORKER_STATUS_ERR);
                worker->idle = GS_TRUE;
                break;
            case WORKER_STATUS_RECV:
                ret = gsql_worker_import(importer, worker);
                // commit the data that are loaded into table
                if (gsc_commit(worker->conn_info.conn) != GSC_SUCCESS) {
                    gsql_print_error(worker->conn_info.conn);
                }
                if (g_importer.ignore) {
                    ret = GS_SUCCESS;
                }
                worker->status = GET_NEXT_STATUS(ret, WORKER_STATUS_RECV, WORKER_STATUS_ERR);
                if (worker->dml_status_param.end_tag) {
                    *worker->dml_status_param.end_tag = GS_TRUE;
                    worker->dml_status_param.end_tag = NULL;
                }
                if (worker->dml_status_param.return_code) {
                    *worker->dml_status_param.return_code = worker->status;
                }
                worker->idle = GS_TRUE;
                break;
            case WORKER_STATUS_END:
            case WORKER_STATUS_ERR:
            default:
                gsql_worker_free(worker);
                worker->closed = GS_TRUE;
                worker->idle = GS_TRUE;
                return;
        }
    }
}

static void imp_wait_exec_subfile(importer_t *importer)
{
    uint32 idle_thread_num = 0;
    while (GS_TRUE) {
        for (uint32 i = 0; i < importer->parallel; i++) {
            if (importer->dml_workers[i].idle) {
                idle_thread_num++;
            }
            if (importer->dml_workers[i].closed) {
                return;
            }
        }
        if (idle_thread_num == importer->parallel) {
            break;
        }
        idle_thread_num = 0;
        cm_sleep(10);
    }
}

static status_t imp_exec_sql(importer_t *importer, bool32 is_file, text_t* sql, const text_t* schema)
{
    text_t output_sql;
    if (importer->show == GS_TRUE) {
        imp_log(IMP_INDENT "%s\n", sql->str);
        return GS_SUCCESS;
    }

    if (is_file) {
        if (importer->content & CT_DATA_ONLY) {
            return imp_worker_active(importer, sql->str, schema);
        }
        return GS_SUCCESS;
    }
    // wait for dml worker finish works
    imp_wait_exec_subfile(importer);

    if (imp_sql(importer, sql, MAX_SQL_SIZE + 4) != GS_SUCCESS) {
        gsql_regular_match_sensitive(sql->str, sql->len, &output_sql);
        imp_log("Incorrect sql during execution :\n%.*s\n", output_sql.len, output_sql.str);
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

static status_t imp_table_scripts(importer_t *importer, text_t *sql)
{
    list_t *table_list = &importer->obj_list;
    bool32 is_file;
    char curr_schema[GS_MAX_NAME_LEN + 1];
    text_t schema = { curr_schema, (uint32)strlen(USER_NAME) };
    // get current schema info
    if (gsql_get_curr_schema(&schema) != GS_SUCCESS) {
        GS_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "failed to get current schema!");
        return GS_ERROR;
    }

    is_file = imp_pre_proc_sql(sql);
    GS_RETSUC_IFTRUE(sql->len == 0);

    GS_RETURN_IFERR(imp_check_username(importer, sql, schema.str));
    GS_RETSUC_IFTRUE(importer->schemaMatch == SCHEMA_NOT_MATCH);
    // only one schema can matched
    GS_RETSUC_IFTRUE(importer->schemaNum > 1);

    // show then original SQL
    if (importer->show == GS_TRUE &&
        imp_sql_type(sql) == IMP_SQL_ALTER_SESSION_SET_SCHEMA) {
        imp_log(IMP_INDENT "%.*s\n", sql->len, sql->str);
    }

    /* judge table is matched,if matched, setted to GS_TRUE  */
    if (imp_tables_data(sql, table_list, &importer->tblMatch) != GS_SUCCESS) {
        imp_timing_log(GS_TRUE, "Incorrect sql:\n%s\n", sql->str);
        return GS_ERROR;
    }

    if (importer->tblMatch != GS_TRUE && !is_file) {
        return GS_SUCCESS;
    }

    importer->tblMatched = GS_TRUE;

    GS_RETURN_IFERR(imp_exec_sql(importer, is_file, sql, &schema));
    return GS_SUCCESS;
}

static status_t imp_all_tables(importer_t *importer, text_t *sql)
{
    bool32 is_file;
    char curr_schema[GS_MAX_NAME_LEN + 1];
    text_t schema = { curr_schema, (uint32)strlen(USER_NAME) };
    if (gsql_get_curr_schema(&schema) != GS_SUCCESS) {
        GS_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "failed to get current schema!");
        return GS_ERROR;
    }

    is_file = imp_pre_proc_sql(sql);
    GS_RETSUC_IFTRUE(sql->len == 0);

    GS_RETURN_IFERR(imp_check_username(importer, sql, schema.str));
    GS_RETSUC_IFTRUE(importer->schemaMatch == SCHEMA_NOT_MATCH);
    GS_RETSUC_IFTRUE(importer->schemaNum > 1);

    GS_RETURN_IFERR(imp_exec_sql(importer, is_file, sql, &schema));
    return GS_SUCCESS;
}

static inline status_t imp_schema_verify_usrname(importer_t *importer, text_t *sql, list_t *schema_list)
{
    bool32 result = GS_FALSE;
    lex_t lex;
    char *schema = NULL;

    imp_init_lex(&lex, sql);

    GS_RETURN_IFERR(lex_try_fetch4(&lex, "ALTER", "SESSION", "SET", "CURRENT_SCHEMA", &result));
    if (result == GS_TRUE) {
        GS_RETURN_IFERR(lex_expected_fetch_word(&lex, "=")); {
            importer->schemaMatch = SCHEMA_NOT_MATCH;

            text_t schema_buf = { lex.curr_text->str + 1, lex.curr_text->len - 1 };
            if (schema_buf.str[0] == '\"') {
                CM_REMOVE_ENCLOSED_CHAR(&schema_buf);
            }

            for (uint32 i = 0; i < schema_list->count; i++) {
                schema = (char *)cm_list_get(schema_list, i);
                if (cm_text_str_equal_ins(&schema_buf, schema)) {
                    importer->schemaMatch = SCHEMA_MATCH;
                    importer->schemaNum++;
                    return GS_SUCCESS;
                }
            }
        }
    }

    return GS_SUCCESS;
}

static status_t imp_get_curr_schema(text_t *sql, text_t *schema_buf)
{
    errno_t errcode;
    const char *words[5] = { "ALTER", "SESSION", "SET", "CURRENT_SCHEMA", "=" };
    bool32 is_found = GS_FALSE;
    lex_t lex;

    imp_init_lex(&lex, sql);

    // devil number '5' means count of elements in 'words'
    if (lex_try_fetch_n(&lex, 5, (const char **)words, &is_found) != GS_SUCCESS) {
        return GS_ERROR;
    }
    if (is_found) {
        if (lex.curr_text->len <= 0) {
            GSQL_PRINTF(ZSERR_GSQL, "the length of currect schema is false.");
            return GS_ERROR;
        }
        errcode = strncpy_s(schema_buf->str, GS_MAX_NAME_LEN + 1, lex.curr_text->str + 1,
                            strlen(lex.curr_text->str + 1));
        if (errcode != EOK) {
            GS_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
            return GS_ERROR;
        }
        schema_buf->len = (uint32)strlen(lex.curr_text->str + 1);
    }

    return GS_SUCCESS;
}

static status_t imp_schema(importer_t *importer, text_t *sql)
{
    list_t *schema_list = &importer->obj_list;
    bool32 is_file;
    text_t schema = { importer->singleSchema, (uint32)strlen(importer->singleSchema) };

    is_file = imp_pre_proc_sql(sql);
    GS_RETSUC_IFTRUE(sql->len == 0);

    GS_RETURN_IFERR(imp_schema_verify_usrname(importer, sql, schema_list));
    GS_RETSUC_IFTRUE(importer->schemaMatch == SCHEMA_NOT_MATCH);
    GS_RETSUC_IFTRUE(importer->schemaNum > schema_list->count);

    GS_RETURN_IFERR(imp_get_curr_schema(sql, &schema));

    GS_RETURN_IFERR(imp_exec_sql(importer, is_file, sql, &schema));
    return GS_SUCCESS;
}

static status_t imp_all_schemas(importer_t *importer, text_t *sql)
{
    lex_t lex;
    bool32 is_file;
    text_t schema = { importer->singleSchema, (uint32)strlen(importer->singleSchema) };

    is_file = imp_pre_proc_sql(sql);
    GS_RETSUC_IFTRUE(sql->len == 0);

    imp_init_lex(&lex, sql);

    GS_RETURN_IFERR(imp_get_curr_schema(sql, &schema));

    GS_RETURN_IFERR(imp_exec_sql(importer, is_file, sql, &schema));
    return GS_SUCCESS;
}

static status_t imp_remap_schema(importer_t *importer, text_t *sql)
{
    list_t *source_list = &importer->obj_list;
    bool32 is_file;

    is_file = imp_pre_proc_sql(sql);
    GS_RETSUC_IFTRUE(sql->len == 0);

    GS_RETURN_IFERR(imp_schema_verify_usrname(importer, sql, source_list));
    GS_RETSUC_IFTRUE(importer->schemaMatch != SCHEMA_MATCH);
    GS_RETSUC_IFTRUE(importer->schemaNum > source_list->count);

    // do not need to alter original schema
    if (imp_sql_type(sql) == IMP_SQL_ALTER_SESSION_SET_SCHEMA) {
        return GS_SUCCESS;
    }

    text_t schemaName = { importer->targetObj, (uint32)strlen(importer->targetObj) };
    GS_RETURN_IFERR(imp_exec_sql(importer, is_file, sql, &schemaName));
    return GS_SUCCESS;
}

static status_t gsql_imp_parse_flexible_head(importer_t *importer, text_t *sql_txt)
{
    text_t line;
    text_t name;
    text_t value;
    sql_text_t sql_value;
    lex_t lex;
    uint32 matched_id;

    // 1. parse content
    while (cm_fetch_text(sql_txt, '\n', '\0', &line)) {
        if (line.len == 0) {
            continue;
        }

        if (cm_text_str_contain_equal_ins(&line, "--", (uint32)strlen("--"))) {
            CM_REMOVE_FIRST_N(&line, (uint32)strlen("--")); // remove exp comment at first
            cm_split_text(&line, '=', '\0', &name, &value);
            cm_text_upper(&name);
            cm_trim_text(&name);
            cm_trim_text(&value);

            if (cm_text_str_equal_ins(&name, "CONTENT_MODE")) {
                sql_value.value = value;
                lex_init(&lex, &sql_value);
                GS_RETURN_IFERR(lex_expected_fetch_1of3(&lex, "ALL", "DATA_ONLY", "METADATA_ONLY", &matched_id));
                    importer->exp_content = (matched_id == 0) ? CT_ALL : (matched_id == 1 ? CT_DATA_ONLY : CT_METADATA_ONLY);
            }
        }
    }
    return GS_SUCCESS;
}

static status_t gsql_imp_read_filehead(importer_t *importer, import_bin_t *imp_bin)
{
    bin_file_fixed_head_t *fixedHead = &imp_bin->fileHead.fixed_head;  //  imp_bin:read bin data    rawBuf: raw data
    uint32 *command_size = &imp_bin->fileHead.commandSize;
    uint32 *param_size = &imp_bin->fileHead.sessionParamSize;
    text_t sql_txt = { .str = importer->rawBuf, .len = 0 };

    // get file fixed head
    GS_RETURN_IFERR(imp_get_data_from_buffer(imp_bin, fixedHead, sizeof(bin_file_fixed_head_t),
        sizeof(bin_file_fixed_head_t), importer->impfp));

    // get file flexible head
    GS_RETURN_IFERR(imp_get_uint32_from_buffer(imp_bin, command_size, importer->impfp));
    GS_RETURN_IFERR(imp_get_block_from_buffer(importer, imp_bin, *command_size, importer->impfp));
    sql_txt.len = (uint32)importer->rawBufLen;
    GS_RETURN_IFERR(gsql_imp_parse_flexible_head(importer, &sql_txt));

    // 1. alter session nls format, 2. create role
    GS_RETURN_IFERR(imp_get_uint32_from_buffer(imp_bin, param_size, importer->impfp));
    GS_RETURN_IFERR(imp_get_block_from_buffer(importer, imp_bin, *param_size, importer->impfp));
    sql_txt.str = importer->rawBuf;
    sql_txt.len = (uint32)importer->rawBufLen;

    if (importer->content & CT_METADATA_ONLY) {
        // set metadata, need to execute
        return gsql_bin_import_one_sql(importer, &sql_txt, GS_FALSE);
    }
    return GS_SUCCESS;
}

static status_t gsql_execute_ddl_block(importer_t *importer, import_ddl_block *block)
{
    bool8 filterd = GS_FALSE;
    imp_ddl_ctx_t ctx;

    GS_RETURN_IFERR(imp_remap_ddl_block(importer, block, &filterd));
    if (filterd) {
        return GS_SUCCESS;
    }

    // do statistic
    imp_do_statistic(block->statistic, block->type);

    // execute block SQL
    ctx.conn_info = &g_conn_info;
    ctx.importer = importer;
    return imp_call_proc_ddl_func((imp_ddl_ctx_param_t)&ctx, block, GS_FALSE);
}

static status_t gsql_imp_transfer_subfile(importer_t *importer, import_bin_t *imp_bin,
                                          import_ddl_block *all_table_block)
{
    import_ddl_block subfile_list_block;
    import_ddl_block subfile_block;
    
    if (imp_bin->subFileNum == 0) {
        return GS_SUCCESS;
    }

    GS_RETURN_IFERR(imp_construct_ddl_block(importer, &subfile_list_block, IMP_BLOCK_SUB_FILE_LIST,
        importer->singleSchema, (uint32)strlen(importer->singleSchema), all_table_block->statistic));

    for (uint32 i = 0; i < imp_bin->subFileNum; i++) {
        GS_RETURN_IFERR(imp_get_uint16_from_buffer(imp_bin, &imp_bin->fileNameLen, importer->impfp));

        if (!imp_check_append_block(&subfile_list_block)) {
            // link 'subfile list block' and 'table block'
            GS_RETURN_IFERR(imp_append_ddl_block(all_table_block, &subfile_list_block));
            GS_RETURN_IFERR(imp_construct_ddl_block(importer, &subfile_list_block, IMP_BLOCK_SUB_FILE_LIST,
                                                    importer->singleSchema, (uint32)strlen(importer->singleSchema),
                                                    all_table_block->statistic));
        }

        GS_RETURN_IFERR(imp_construct_ddl_block(importer, &subfile_block, IMP_BLOCK_SUB_FILE, importer->singleSchema,
            (uint32)strlen(importer->singleSchema), all_table_block->statistic));
        GS_RETURN_IFERR(imp_get_block_to_buffer(importer, imp_bin, subfile_block.sql_txt.str, subfile_block.max_size,
                                                (uint32)imp_bin->fileNameLen, importer->impfp));
        subfile_block.sql_txt.len = (uint32)imp_bin->fileNameLen;

        if (imp_bin->fileNameLen > GS_MAX_NAME_LEN) {
            imp_destory_ddl_block(importer, &subfile_block);
            GSQL_PRINTF(ZSERR_IMPORT, "FileName (%s) length (%u) is too long",
                        imp_bin->subFileName, imp_bin->fileNameLen);
            return GS_ERROR;
        }
        GS_RETURN_IFERR(imp_append_ddl_block(&subfile_list_block, &subfile_block));
    }
    GS_RETURN_IFERR(imp_append_ddl_block(all_table_block, &subfile_list_block));
    GS_RETURN_IFERR(imp_construct_ddl_block(importer, &subfile_block, IMP_BLOCK_SUB_FILE_END, importer->singleSchema,
                                            (uint32)strlen(importer->singleSchema), all_table_block->statistic));
    GS_RETURN_IFERR(imp_append_ddl_block(all_table_block, &subfile_block));
    return GS_SUCCESS;
}

static status_t gsql_imp_bin_table(importer_t *importer, import_bin_t *imp_bin, import_ddl_block *all_table_block)
{
    import_ddl_block block;

    // process table struct
    GS_RETURN_IFERR(imp_get_uint32_from_buffer(imp_bin, &imp_bin->tableInfoLen, importer->impfp));

    if (importer->exp_content & CT_METADATA_ONLY) {
        GS_RETURN_IFERR(imp_construct_ddl_block_ex(importer, &block, IMP_BLOCK_TABLE, importer->singleSchema,
            (uint32)strlen(importer->singleSchema), all_table_block->statistic, imp_bin->tableInfoLen + 1));
        GS_RETURN_IFERR(imp_get_block_to_buffer(importer, imp_bin, block.sql_txt.str, block.max_size,
                                                imp_bin->tableInfoLen, importer->impfp));
        block.sql_txt.len = imp_bin->tableInfoLen;
        GS_RETURN_IFERR(imp_append_ddl_block(all_table_block, &block));
    }

    if (importer->exp_content & CT_DATA_ONLY) {
        GS_RETURN_IFERR(imp_get_uint16_from_buffer(imp_bin, &imp_bin->tableNameLen, importer->impfp));
        GS_RETURN_IFERR(imp_construct_ddl_block(importer, &block, IMP_BLOCK_TABLE_NAME, importer->singleSchema,
                                                (uint32)strlen(importer->singleSchema), all_table_block->statistic));
        GS_RETURN_IFERR(imp_get_block_to_buffer(importer, imp_bin, block.sql_txt.str, block.max_size,
                                                imp_bin->tableNameLen, importer->impfp));
        block.sql_txt.len = imp_bin->tableNameLen;
        GS_RETURN_IFERR(imp_append_ddl_block(all_table_block, &block));

        // get column information
        GS_RETURN_IFERR(imp_get_uint64_from_buffer(imp_bin, &imp_bin->recordNum, importer->impfp));
        GS_RETURN_IFERR(imp_decode_column_info(importer, imp_bin, GS_FALSE));
    }
    // process sub-files
    GS_RETURN_IFERR(imp_get_uint32_from_buffer(imp_bin, &imp_bin->subFileNum, importer->impfp));
    GS_RETURN_IFERR(gsql_imp_transfer_subfile(importer, imp_bin, all_table_block));

    // process index
    GS_RETURN_IFERR(imp_get_uint32_from_buffer(imp_bin, &imp_bin->indexLen, importer->impfp));
    if (imp_bin->indexLen > 0) {
        GS_RETURN_IFERR(imp_construct_ddl_block(importer, &block, IMP_BLOCK_TABLE_INDEX, importer->singleSchema,
                                                (uint32)strlen(importer->singleSchema), all_table_block->statistic));
        GS_RETURN_IFERR(imp_get_block_to_buffer(importer, imp_bin, block.sql_txt.str, block.max_size,
                                                imp_bin->indexLen, importer->impfp));
        block.sql_txt.len = imp_bin->indexLen;
        GS_RETURN_IFERR(imp_append_ddl_block(all_table_block, &block));
    }

    return GS_SUCCESS;
}

static status_t imp_split_block_drop_table(importer_t *importer, import_ddl_block *block)
{
    lex_t lex;
    import_ddl_block drop_table_block;
    text_t block_sql = block->sql_txt;
    text_t drop_sql;
    bool32 is_drop_sql;

    imp_init_lex(&lex, &block->sql_txt);
    GS_RETURN_IFERR(lex_try_fetch2(&lex, "DROP", "TABLE", &is_drop_sql));
    if (is_drop_sql == GS_TRUE) {
        GS_RETURN_IFERR(imp_construct_ddl_block(importer, &drop_table_block, IMP_BLOCK_DROP_TABLE, block->schema,
            (uint32)strlen(block->schema), block->statistic));

        GS_RETURN_IFERR(imp_fetch_sql(&block_sql, &drop_sql));
        if (drop_sql.len > 0) {
            cm_concat_text(&drop_table_block.sql_txt, drop_table_block.max_size, &drop_sql);
            CM_NULL_TERM(&drop_table_block.sql_txt);
            // over wirte 'drop table' in old block
            GS_RETURN_IFERR(memmove_s(block->sql_txt.str, block->max_size, block_sql.str, block_sql.len));
            block->sql_txt.len = block_sql.len;
            CM_NULL_TERM(&block->sql_txt);
            // execute 'drop table' block
            GS_RETURN_IFERR(gsql_execute_ddl_block(importer, &drop_table_block));
        }
        imp_destory_ddl_block(importer, &drop_table_block);
    }
    return GS_SUCCESS;
}

static status_t imp_split_drop_table(importer_t *importer, import_ddl_block *all_table_block)
{
    import_ddl_block *sub_block = NULL;

    // do not contain metadata
    if (!(importer->exp_content & CT_METADATA_ONLY)) {
        return GS_SUCCESS;
    }

    // split drop table
    sub_block = (import_ddl_block *)all_table_block->sql_txt.str;
    for (uint32 i = 0; i < all_table_block->sql_txt.len; i++) {
        if (sub_block->type == IMP_BLOCK_TABLE) {
            GS_RETURN_IFERR(imp_split_block_drop_table(importer, &(sub_block[i])));
            break;
        }
    }

    return GS_SUCCESS;
}

static status_t gsql_imp_bin_tables(importer_t *importer, import_bin_t *imp_bin, importer_stat_t *stat)
{
    import_ddl_block block;

    GS_RETURN_IFERR(imp_get_uint32_from_buffer(imp_bin, &imp_bin->tableNum, importer->impfp));
    imp_timing_log(GS_TRUE, "\n" IMP_INDENT "Importing tables of schema %s ,total number : %u ...\n",
        importer->singleSchema, imp_bin->tableNum);
    imp_log(IMP_INDENT2 "The order of importing table is:\n");
    imp_log(IMP_INDENT2 "%-64s %-14s\n", "TABLE NAME", "RECORD NUMBER");
    imp_log(IMP_INDENT2 "---------------------------------------------------------------- --------------\n");
    for (uint32 i = 0; i < imp_bin->tableNum; i++) {
        GS_RETURN_IFERR(imp_construct_ddl_block(importer, &block, IMP_BLOCK_COMPLETE_TABLE, importer->singleSchema,
            (uint32)strlen(importer->singleSchema), stat));
        GS_RETURN_IFERR(gsql_imp_bin_table(importer, imp_bin, &block));
        // 'drop table' should be executed serial, cause tables with foreign reference may cause 'dead lock'
        GS_RETURN_IFERR(imp_split_drop_table(importer, &block));
        GS_RETURN_IFERR(gsql_bin_import_transfer_one_ddl_sql(importer, &block));
    }
    return GS_SUCCESS;
}

static status_t gsql_imp_bin_extkey(importer_t *importer, import_bin_t *imp_bin, importer_stat_t *stat)
{
    import_ddl_block block;

    GS_RETURN_IFERR(imp_get_uint32_from_buffer(imp_bin, &imp_bin->extKeyTotalLen, importer->impfp));
    GS_RETURN_IFERR(imp_get_uint32_from_buffer(imp_bin, &imp_bin->extKeyNum, importer->impfp));
    imp_timing_log(GS_TRUE, "\n" IMP_INDENT "Importing foreign key of schema %s ...\n", importer->singleSchema);
    for (uint32 i = 0; i < imp_bin->extKeyNum; i++) {
        GS_RETURN_IFERR(imp_get_uint32_from_buffer(imp_bin, &imp_bin->extKeyLen, importer->impfp));
        GS_RETURN_IFERR(imp_construct_ddl_block(importer, &block, IMP_BLOCK_EXTKEY, importer->singleSchema,
                                                (uint32)strlen(importer->singleSchema), stat));
        GS_RETVALUE_IFTRUE(imp_invalid_length(imp_bin->extKeyLen, sizeof(uint32), MAX_SQL_SIZE), GS_ERROR);
        GS_RETURN_IFERR(imp_get_block_to_buffer(importer, imp_bin, block.sql_txt.str, block.max_size,
                                                imp_bin->extKeyLen - sizeof(uint32), importer->impfp));
        block.sql_txt.len = imp_bin->extKeyLen - sizeof(uint32);

        GS_RETURN_IFERR(gsql_execute_ddl_block(importer, &block));
        imp_destory_ddl_block(importer, &block);

        GS_RETURN_IFERR(imp_get_uint32_from_buffer(imp_bin, &imp_bin->verifyFlag, importer->impfp));
        if (imp_bin->verifyFlag != IMP_OBJECT_END_FLAG) {
            GSQL_PRINTF(ZSERR_IMPORT, "File format error: read extkey failed!");
            return GS_ERROR;
        }
    }
    return GS_SUCCESS;
}

static status_t gsql_imp_bin_view(importer_t *importer, import_bin_t *imp_bin, importer_stat_t *stat)
{
    import_ddl_block block;

    GS_RETURN_IFERR(imp_get_uint32_from_buffer(imp_bin, &imp_bin->viewTotalLen, importer->impfp));
    GS_RETURN_IFERR(imp_get_uint32_from_buffer(imp_bin, &imp_bin->viewNum, importer->impfp));
    imp_timing_log(GS_TRUE, IMP_INDENT "Importing view of schema %s ...\n", importer->singleSchema);
    for (uint32 i = 0; i < imp_bin->viewNum; i++) {
        if ((i > 0) && (i % GSQL_COMMIT_BATCH == 0)) {
            imp_timing_log(GS_TRUE, IMP_INDENT2 "%u view of schema %s has been readed.\n", i, importer->singleSchema);
        }
        GS_RETURN_IFERR(imp_get_uint32_from_buffer(imp_bin, &imp_bin->viewLen, importer->impfp));
        GS_RETURN_IFERR(imp_construct_ddl_block(importer, &block, IMP_BLOCK_VIEW, importer->singleSchema,
                                                (uint32)strlen(importer->singleSchema), stat));
        GS_RETVALUE_IFTRUE(imp_invalid_length(imp_bin->viewLen, sizeof(uint32), MAX_SQL_SIZE), GS_ERROR);
        GS_RETURN_IFERR(imp_get_block_to_buffer(importer, imp_bin, block.sql_txt.str, block.max_size,
                                                imp_bin->viewLen - sizeof(uint32), importer->impfp));
        block.sql_txt.len = imp_bin->viewLen - sizeof(uint32);

        GS_RETURN_IFERR(gsql_execute_ddl_block(importer, &block));
        imp_destory_ddl_block(importer, &block);

        // view do not support DDL parallel.
        GS_RETURN_IFERR(imp_get_uint32_from_buffer(imp_bin, &imp_bin->verifyFlag, importer->impfp));
        if (imp_bin->verifyFlag != IMP_OBJECT_END_FLAG) {
            GSQL_PRINTF(ZSERR_IMPORT, "File format error: read viewNum failed!");
            return GS_ERROR;
        }
    }
    imp_timing_log(GS_TRUE, IMP_INDENT2 "View importing success, %llu rows are loaded.\n\n", stat->view_num);
    return GS_SUCCESS;
}

static status_t gsql_imp_bin_package(importer_t *importer, import_bin_t *imp_bin, importer_stat_t *stat)
{
    import_ddl_block block;
    uint32 package_total_len;
    uint32 package_total_cnt;
    uint32 package_len;

    GS_RETURN_IFERR(imp_get_uint32_from_buffer(imp_bin, &package_total_len, importer->impfp));
    GS_RETURN_IFERR(imp_get_uint32_from_buffer(imp_bin, &package_total_cnt, importer->impfp));
    imp_timing_log(GS_TRUE, IMP_INDENT "Importing package of schema %s ...\n", importer->singleSchema);
    for (uint32 i = 0; i < package_total_cnt; i++) {
        if ((i > 0) && (i % GSQL_COMMIT_BATCH == 0)) {
            imp_timing_log(GS_TRUE, IMP_INDENT2 "%u package of schema %s has been readed.\n", i, importer->singleSchema);
        }
        GS_RETURN_IFERR(imp_get_uint32_from_buffer(imp_bin, &package_len, importer->impfp));
        GS_RETURN_IFERR(imp_construct_ddl_block(importer, &block, IMP_BLOCK_PACKAGE, importer->singleSchema,
            (uint32)strlen(importer->singleSchema), stat));
        GS_RETURN_IFERR(imp_get_block_to_buffer(importer, imp_bin, block.sql_txt.str, block.max_size,
            package_len - sizeof(uint32), importer->impfp));
        block.sql_txt.len = package_len - sizeof(uint32);

        GS_RETURN_IFERR(gsql_execute_ddl_block(importer, &block));
        imp_destory_ddl_block(importer, &block);

        // package do not support DDL parallel.
        GS_RETURN_IFERR(imp_get_uint32_from_buffer(imp_bin, &imp_bin->verifyFlag, importer->impfp));
        if (imp_bin->verifyFlag != IMP_OBJECT_END_FLAG) {
            GSQL_PRINTF(ZSERR_IMPORT, "File format error: read package failed!");
            return GS_ERROR;
        }
    }
    imp_timing_log(GS_TRUE, IMP_INDENT2 "Package importing success, %llu rows are loaded.\n\n", stat->package_num);
    return GS_SUCCESS;
}

static status_t gsql_imp_bin_profile(importer_t *importer, import_bin_t *imp_bin, importer_stat_t *stat)
{
    import_ddl_block block;
    uint32 profile_total_len;
    uint32 profile_total_cnt;
    uint32 profile_len;

    GS_RETURN_IFERR(imp_get_uint32_from_buffer(imp_bin, &profile_total_len, importer->impfp));
    GS_RETURN_IFERR(imp_get_uint32_from_buffer(imp_bin, &profile_total_cnt, importer->impfp));
    imp_timing_log(GS_TRUE, IMP_INDENT "Importing profile of schema %s ...\n", importer->singleSchema);
    for (uint32 i = 0; i < profile_total_cnt; i++) {
        if ((i > 0) && (i % GSQL_COMMIT_BATCH == 0)) {
            imp_timing_log(GS_TRUE, IMP_INDENT2 "%u profile of schema %s has been readed.\n", i, importer->singleSchema);
        }
        GS_RETURN_IFERR(imp_get_uint32_from_buffer(imp_bin, &profile_len, importer->impfp));
        GS_RETURN_IFERR(imp_construct_ddl_block(importer, &block, IMP_BLOCK_PROFILE, importer->singleSchema,
            (uint32)strlen(importer->singleSchema), stat));
        GS_RETURN_IFERR(imp_get_block_to_buffer(importer, imp_bin, block.sql_txt.str, block.max_size,
            profile_len - sizeof(uint32), importer->impfp));
        block.sql_txt.len = profile_len - sizeof(uint32);

        GS_RETURN_IFERR(gsql_bin_import_transfer_one_ddl_sql(importer, &block));

        // profile do not support DDL parallel.
        GS_RETURN_IFERR(imp_get_uint32_from_buffer(imp_bin, &imp_bin->verifyFlag, importer->impfp));
        if (imp_bin->verifyFlag != IMP_OBJECT_END_FLAG) {
            GSQL_PRINTF(ZSERR_IMPORT, "File format error: read profile failed!");
            return GS_ERROR;
        }
    }
    imp_timing_log(GS_TRUE, IMP_INDENT2 "Profile importing success, %llu rows are loaded.\n", stat->profile_num);
    return GS_SUCCESS;
}

static status_t gsql_imp_bin_type(importer_t *importer, import_bin_t *imp_bin, importer_stat_t *stat)
{
    import_ddl_block block;
    uint32 type_total_len;
    uint32 type_total_cnt;
    uint32 type_len;

    GS_RETURN_IFERR(imp_get_uint32_from_buffer(imp_bin, &type_total_len, importer->impfp));
    GS_RETURN_IFERR(imp_get_uint32_from_buffer(imp_bin, &type_total_cnt, importer->impfp));
    imp_timing_log(GS_TRUE, IMP_INDENT "Importing type of schema %s ...\n", importer->singleSchema);
    for (uint32 i = 0; i < type_total_cnt; i++) {
        if ((i > 0) && (i % GSQL_COMMIT_BATCH == 0)) {
            imp_timing_log(GS_TRUE, IMP_INDENT2 "%u type of schema %s has been readed.\n", i, importer->singleSchema);
        }
        GS_RETURN_IFERR(imp_get_uint32_from_buffer(imp_bin, &type_len, importer->impfp));
        GS_RETURN_IFERR(imp_construct_ddl_block(importer, &block, IMP_BLOCK_TYPE, importer->singleSchema,
            (uint32)strlen(importer->singleSchema), stat));
        GS_RETURN_IFERR(imp_get_block_to_buffer(importer, imp_bin, block.sql_txt.str, block.max_size,
            type_len - sizeof(uint32), importer->impfp));
        block.sql_txt.len = type_len - sizeof(uint32);

        GS_RETURN_IFERR(gsql_execute_ddl_block(importer, &block));
        imp_destory_ddl_block(importer, &block);

        // type do not support DDL parallel.
        GS_RETURN_IFERR(imp_get_uint32_from_buffer(imp_bin, &imp_bin->verifyFlag, importer->impfp));
        if (imp_bin->verifyFlag != IMP_OBJECT_END_FLAG) {
            GSQL_PRINTF(ZSERR_IMPORT, "File format error: read type failed!");
            return GS_ERROR;
        }
    }
    imp_timing_log(GS_TRUE, IMP_INDENT2 "Type importing success, %llu rows are loaded.\n", stat->type_num);
    return GS_SUCCESS;
}

static status_t gsql_imp_bin_synonym(importer_t *importer, import_bin_t *imp_bin, importer_stat_t *stat)
{
    import_ddl_block block;
    uint32 synonym_total_len;
    uint32 synonym_total_cnt;
    uint32 synonym_len;

    GS_RETURN_IFERR(imp_get_uint32_from_buffer(imp_bin, &synonym_total_len, importer->impfp));
    GS_RETURN_IFERR(imp_get_uint32_from_buffer(imp_bin, &synonym_total_cnt, importer->impfp));
    imp_timing_log(GS_TRUE, IMP_INDENT "Importing synonym of schema %s ...\n", importer->singleSchema);
    for (uint32 i = 0; i < synonym_total_cnt; i++) {
        if ((i > 0) && (i % GSQL_COMMIT_BATCH == 0)) {
            imp_timing_log(GS_TRUE, IMP_INDENT2 "%u synonym of schema %s has been readed.\n", i, importer->singleSchema);
        }
        GS_RETURN_IFERR(imp_get_uint32_from_buffer(imp_bin, &synonym_len, importer->impfp));
        GS_RETURN_IFERR(imp_construct_ddl_block(importer, &block, IMP_BLOCK_SYNONYM, importer->singleSchema,
            (uint32)strlen(importer->singleSchema), stat));
        GS_RETURN_IFERR(imp_get_block_to_buffer(importer, imp_bin, block.sql_txt.str, block.max_size,
            synonym_len - sizeof(uint32), importer->impfp));
        block.sql_txt.len = synonym_len - sizeof(uint32);

        GS_RETURN_IFERR(gsql_execute_ddl_block(importer, &block));
        imp_destory_ddl_block(importer, &block);

        // synonym do not support DDL parallel.
        GS_RETURN_IFERR(imp_get_uint32_from_buffer(imp_bin, &imp_bin->verifyFlag, importer->impfp));
        if (imp_bin->verifyFlag != IMP_OBJECT_END_FLAG) {
            GSQL_PRINTF(ZSERR_IMPORT, "File format error: read synonym failed!");
            return GS_ERROR;
        }
    }
    imp_timing_log(GS_TRUE, IMP_INDENT2 "Synonym importing success, %llu rows are loaded.\n\n", stat->synonym_num);
    return GS_SUCCESS;
}

static status_t gsql_imp_bin_func(importer_t *importer, import_bin_t *imp_bin, importer_stat_t* stat)
{
    import_ddl_block block;

    GS_RETURN_IFERR(imp_get_uint32_from_buffer(imp_bin, &imp_bin->funcTotalLen, importer->impfp));
    GS_RETURN_IFERR(imp_get_uint32_from_buffer(imp_bin, &imp_bin->funcNum, importer->impfp));
    imp_timing_log(GS_TRUE, "\n" IMP_INDENT "Importing fuction/procedure/trigger of schema %s ...\n",
                   importer->singleSchema);
    for (uint32 i = 0; i < imp_bin->funcNum; i++) {
        if ((i > 0) && (i % GSQL_COMMIT_BATCH == 0)) {
            imp_timing_log(GS_TRUE, IMP_INDENT2 "%u fuction/procedure/trigger of schema %s has been readed.\n", i,
                           importer->singleSchema);
        }
        GS_RETURN_IFERR(imp_get_uint32_from_buffer(imp_bin, &imp_bin->funcLen, importer->impfp));
        GS_RETURN_IFERR(imp_construct_ddl_block(importer, &block, IMP_BLOCK_FUNC, importer->singleSchema,
                                                (uint32)strlen(importer->singleSchema), stat));
        GS_RETVALUE_IFTRUE(imp_invalid_length(imp_bin->funcLen, sizeof(uint32), MAX_SQL_SIZE), GS_ERROR);
        GS_RETURN_IFERR(imp_get_block_to_buffer(importer, imp_bin, block.sql_txt.str, block.max_size,
                                                imp_bin->funcLen - sizeof(uint32), importer->impfp));
        block.sql_txt.len = imp_bin->funcLen - sizeof(uint32);
        GS_RETURN_IFERR(gsql_bin_import_transfer_one_ddl_sql(importer, &block));

        GS_RETURN_IFERR(imp_get_uint32_from_buffer(imp_bin, &imp_bin->verifyFlag, importer->impfp));

        if (imp_bin->verifyFlag != IMP_OBJECT_END_FLAG) {
            GSQL_PRINTF(ZSERR_IMPORT, "File format error : read funcNum failed!");
            return GS_ERROR;
        }
    }
    
    return GS_SUCCESS;
}

static status_t gsql_imp_bin_seq(importer_t *importer, import_bin_t *imp_bin, importer_stat_t *stat)
{
    import_ddl_block block;

    GS_RETURN_IFERR(imp_get_uint32_from_buffer(imp_bin, &imp_bin->seqTotalLen, importer->impfp));
    GS_RETURN_IFERR(imp_get_uint32_from_buffer(imp_bin, &imp_bin->seqNum, importer->impfp));
    imp_timing_log(GS_TRUE, IMP_INDENT "Importing sequence of schema %s ...\n", importer->singleSchema);
    for (uint32 i = 0; i < imp_bin->seqNum; i++) {
        GS_RETURN_IFERR(imp_get_uint32_from_buffer(imp_bin, &imp_bin->seqLen, importer->impfp));
        GS_RETURN_IFERR(imp_construct_ddl_block(importer, &block, IMP_BLOCK_SEQ, importer->singleSchema,
                                                (uint32)strlen(importer->singleSchema), stat));
        GS_RETVALUE_IFTRUE(imp_invalid_length(imp_bin->seqLen, sizeof(uint32), MAX_SQL_SIZE), GS_ERROR);
        GS_RETURN_IFERR(imp_get_block_to_buffer(importer, imp_bin, block.sql_txt.str, block.max_size,
                                                imp_bin->seqLen - sizeof(uint32), importer->impfp));
        block.sql_txt.len = imp_bin->seqLen - sizeof(uint32);

        GS_RETURN_IFERR(gsql_execute_ddl_block(importer, &block));
        imp_destory_ddl_block(importer, &block);

        GS_RETURN_IFERR(imp_get_uint32_from_buffer(imp_bin, &imp_bin->verifyFlag, importer->impfp));

        if (imp_bin->verifyFlag != IMP_OBJECT_END_FLAG) {
            GSQL_PRINTF(ZSERR_IMPORT, "File format error: read sequeue failed!");
            return GS_ERROR;
        }
    }
    /* export SQL in sequence include 2 parts :
        1. alter session,create user,grant (they are in one sql)
        2. create sequence
    so the sequence number need to minus */
    imp_timing_log(GS_TRUE, IMP_INDENT2 "Sequence importing success, %llu rows are loaded.\n",
        stat->seq_num > 0 ? stat->seq_num - 1 : 0);
    return GS_SUCCESS;
}

static status_t imp_notify_ddl_thread_stop(importer_t *importer)
{
    import_ddl_block block;

    GS_RETURN_IFERR(imp_construct_ddl_block(importer, &block, IMP_BLOCK_END, importer->singleSchema,
                                            (uint32)strlen(importer->singleSchema), NULL));

    for (uint32 i = 0; i < importer->ddl_parallel; i++) {
        if (cm_chan_send(importer->ddl_queue.chan, &block) != GS_SUCCESS) {
            GSQL_PRINTF(ZSERR_IMPORT, "Failed to send DDL block of change schema to DDL thread !");
            return GS_ERROR;
        }
    }
    return GS_SUCCESS;
}

static status_t gsql_wait_ddl_thread_finish(importer_t *importer)
{
    while (GS_TRUE) {
        // shutdown ddl thread immediate, no need to wait.
        if (importer->fatal_error) {
            GS_THROW_ERROR(ERR_CLT_IMP_DATAFILE, "check DDL thread", "DDL thread throws error");
            return GS_ERROR;
        }

        // DDL channel has no message
        if (importer->ddl_queue.chan->count == 0 &&
            importer->ddl_queue.inque_cnt == importer->ddl_queue.outque_cnt) {
            // all DDL thread finish work.
            return GS_SUCCESS;
        }
        cm_sleep(IMP_THREAD_CHECK_TIME);
    }
}

// judge need to do schema switch
static bool8 imp_change_schema_filterd(importer_t *importer)
{
    if (importer->imp_type == IMP_SCHEMA || importer->imp_type == IMP_REMAP_SCHEMA) {
        if (imp_find_object(&importer->obj_list, importer->singleSchema, GS_TRUE)) {
            return GS_FALSE;
        }
        return GS_TRUE;
    }
    return GS_FALSE;
}

static status_t imp_get_remap_schema(importer_t *importer, char *schema, uint32 max_len)
{
    if (importer->imp_type == IMP_REMAP_SCHEMA) {
        if (imp_find_object(&importer->obj_list, importer->singleSchema, GS_TRUE)) {
            MEMS_RETURN_IFERR(strncpy_s(schema, max_len, importer->targetObj, strlen(importer->targetObj)));
            return GS_SUCCESS;
        }
    }

    MEMS_RETURN_IFERR(strncpy_s(schema, max_len, importer->singleSchema, strlen(importer->singleSchema)));
    return GS_SUCCESS;
}

static status_t imp_one_schema_bin(importer_t *importer, import_bin_t *imp_bin)
{
    char schema[GS_MAX_NAME_LEN + 1];
    char date_str[GS_MAX_TIME_STRLEN];
    importer_stat_t stat; // each schema do statistic

    // reset statistic info
    imp_reset_statistic(&stat);

    // process schema/sequence
    stat.start_time = cm_now();
    GS_RETURN_IFERR(gsql_imp_bin_seq(importer, imp_bin, &stat));
    imp_timing_log(importer->timing, IMP_INDENT2 "The time of Importing sequence is: %s\n", imp_get_timestamp(date_str,
                   sizeof(date_str), cm_now() - stat.start_time));

    if (imp_bin->fileHead.fixed_head.client_ver >= EXP_CLI_VERSION_2) {
        stat.start_time = cm_now();
        // process profile
        GS_RETURN_IFERR(gsql_imp_bin_profile(importer, imp_bin, &stat));
        GS_RETURN_IFERR(gsql_wait_ddl_thread_finish(importer));
        imp_timing_log(importer->timing, IMP_INDENT2 "The time of Importing profile is: %s\n",
            imp_get_timestamp(date_str, sizeof(date_str), cm_now() - stat.start_time));

        stat.start_time = cm_now();
        // process type
        GS_RETURN_IFERR(gsql_imp_bin_type(importer, imp_bin, &stat));
        GS_RETURN_IFERR(gsql_wait_ddl_thread_finish(importer));
        imp_timing_log(importer->timing, IMP_INDENT2 "The time of Importing type is: %s\n",
            imp_get_timestamp(date_str, sizeof(date_str), cm_now() - stat.start_time));
    }

    // if switch schema failed at : gsql_imp_bin_seq, try change schema.
    if (imp_bin->schemaNum > 0 && !imp_change_schema_filterd(importer)) {
        GS_RETURN_IFERR(imp_get_remap_schema(importer, schema, sizeof(schema)));
        GS_RETURN_IFERR(imp_change_curr_schema(&g_conn_info, schema));
    }

    // process tables
    stat.start_time = cm_now();
    GS_RETURN_IFERR(gsql_imp_bin_tables(importer, imp_bin, &stat));
    GS_RETURN_IFERR(gsql_wait_ddl_thread_finish(importer));
    imp_timing_log(importer->timing, IMP_INDENT2 "The time of Importing tables and index is: %s\n",
                   imp_get_timestamp(date_str, sizeof(date_str), cm_now() - stat.start_time));

    // process ext_key
    stat.start_time = cm_now();
    GS_RETURN_IFERR(gsql_imp_bin_extkey(importer, imp_bin, &stat));
    GS_RETURN_IFERR(gsql_wait_ddl_thread_finish(importer));
    imp_timing_log(GS_TRUE, IMP_INDENT2 "Foreign key importing success, %llu rows are loaded.\n", stat.ext_key_num);
    imp_timing_log(importer->timing, IMP_INDENT2 "The time of Importing foreign key is: %s\n",
                   imp_get_timestamp(date_str, sizeof(date_str), cm_now() - stat.start_time));

    // process function
    stat.start_time = cm_now();
    GS_RETURN_IFERR(gsql_imp_bin_func(importer, imp_bin, &stat));
    GS_RETURN_IFERR(gsql_wait_ddl_thread_finish(importer));
    imp_timing_log(GS_TRUE, IMP_INDENT2 "Fuction/procedure/trigger importing success, %llu rows are loaded.\n\n",
        stat.object_num);
    imp_timing_log(importer->timing, IMP_INDENT2 "The time of Importing function is: %s\n", imp_get_timestamp(date_str,
                   sizeof(date_str), cm_now() - stat.start_time));

    // process viewNum
    stat.start_time = cm_now();
    GS_RETURN_IFERR(gsql_imp_bin_view(importer, imp_bin, &stat));
    GS_RETURN_IFERR(gsql_wait_ddl_thread_finish(importer));
    imp_timing_log(importer->timing, IMP_INDENT2 "The time of Importing view is: %s\n", imp_get_timestamp(date_str,
                   sizeof(date_str), cm_now() - stat.start_time));

    // process synonyms
    if (imp_bin->fileHead.fixed_head.client_ver >= EXP_CLI_VERSION_2) {
        stat.start_time = cm_now();
        GS_RETURN_IFERR(gsql_imp_bin_synonym(importer, imp_bin, &stat));
        GS_RETURN_IFERR(gsql_wait_ddl_thread_finish(importer));
        imp_timing_log(importer->timing, IMP_INDENT2 "The time of Importing synonym is: %s\n",
                       imp_get_timestamp(date_str, sizeof(date_str), cm_now() - stat.start_time));

        stat.start_time = cm_now();
        // process package
        GS_RETURN_IFERR(gsql_imp_bin_package(importer, imp_bin, &stat));
        GS_RETURN_IFERR(gsql_wait_ddl_thread_finish(importer));
        imp_timing_log(importer->timing, IMP_INDENT2 "The time of Importing package is: %s\n",
                       imp_get_timestamp(date_str, sizeof(date_str), cm_now() - stat.start_time));
    }

    return GS_SUCCESS;
}

static int gsql_imp_get_raw_buf(importer_t *importer, bool8* eof)
{
    uint64 nbytes = 0;
    int32 inbytes;

    if (importer->rawBufIndex < importer->rawBufLen) {
        /* Copy down the unprocessed data */
        nbytes = importer->rawBufLen - importer->rawBufIndex;
        MEMS_RETURN_IFERR(memmove_s(importer->rawBuf, RAW_BUF_SIZE, importer->rawBuf + importer->rawBufIndex,
                                    (size_t)nbytes));
    } else {
        nbytes = 0; /* no data need be saved */
    }

    inbytes = gsql_imp_read_data(importer->rawBuf + nbytes, 1, (int)(RAW_BUF_SIZE - nbytes), importer->impfp);
    if (inbytes < 0) {
        *eof = ((nbytes > 0) ? GS_FALSE : GS_TRUE);
        return GS_ERROR;
    }
    nbytes += inbytes;

    importer->rawBuf[nbytes] = '\0';
    importer->rawBufIndex = 0;
    importer->rawBufLen = nbytes;
    *eof = ((nbytes > 0) ? GS_FALSE : GS_TRUE);
    return GS_SUCCESS;
}

static bool8 imp_is_comment_line(text_t *line, imp_sql_parser_t *parser)
{
    for (uint32 i = 0; i < line->len; i++) {
        if (line->str[i] == ' ') {
            continue;
        }

        if (parser->is_block_comment) {  // detect ' /* '
            if (line->str[i] == '*' && i + 1 < line->len && line->str[i + 1] == '/') {
                i++;
                parser->is_block_comment = GS_FALSE;
            }
            continue;
        }

        if (line->str[i] == '-' && i + 1 < line->len && line->str[i + 1] == '-') {
            return GS_TRUE;
        }

        if (line->str[i] == '/' && i + 1 < line->len && line->str[i + 1] == '*') {
            i++;
            parser->is_block_comment = GS_TRUE;
            continue;
        }

        CM_REMOVE_FIRST_N(line, i);  // remove comment from line
        return GS_FALSE;
    }
    return GS_TRUE;
}

static bool8 imp_is_sql_end(text_t *line, char terminal_char, int32 *is_enclosed)
{
    for (uint32 i = 0; i < line->len; i++) {
        if (line->str[i] == '\'' || line->str[i] == '"' || line->str[i] == '`') {
            if (*is_enclosed == -1) {
                *is_enclosed = line->str[i];
            } else if (*is_enclosed == line->str[i]) {
                *is_enclosed = -1;
            }
        }

        if (*is_enclosed > 0) {
            continue;
        }

        if (line->str[i] == terminal_char) {
            line->len = i + 1;
            return GS_TRUE;
        }
    }
    return GS_FALSE;
}

static status_t imp_get_raw_buffer(importer_t *importer, text_t *raw_buf, uint64 max_size, bool8 *eof)
{
    if ((importer->rawBufLen - importer->rawBufIndex < max_size)) {
        GS_RETURN_IFERR(gsql_imp_get_raw_buf(importer, eof));

        /* file end */
        if (*eof) {
            importer->eof = GS_TRUE;
            return GS_SUCCESS;
        }
    }

    raw_buf->str = importer->rawBuf + importer->rawBufIndex;
    raw_buf->len = (uint32)(importer->rawBufLen - importer->rawBufIndex);
    return GS_SUCCESS;
}

// read a complete SQL or PL
static status_t imp_read_sql(importer_t *importer, text_t *block, uint64 max_size, bool8 *eof)
{
    text_t raw_buf;
    text_t line;
    text_t remain;
    imp_sql_parser_t parser;

    imp_reset_parser(&parser);
    block->len = 0;
    *eof = GS_FALSE;

    /* ensure buffer is larger than MAX_SQL_SIZE */
    GS_RETVALUE_IFTRUE(imp_get_raw_buffer(importer, &raw_buf, MAX_SQL_SIZE, eof) != GS_SUCCESS, GS_ERROR);

    /* file end */
    GS_RETVALUE_IFTRUE(*eof, GS_SUCCESS);

    /* line:
       1. -- comment
       2. SQL
       3. PL
    */
    while (GS_TRUE) {
        cm_split_text(&raw_buf, '\n', '\0', &line, &remain);
        raw_buf = remain;
        // include '\n'
        if (remain.str != NULL) {
            line.len++;
            importer->fileRows++;
        }
        importer->rawBufIndex += line.len;
        if (importer->rawBufLen < importer->rawBufIndex) {
            importer->eof = GS_TRUE;
            GSQL_PRINTF(ZSERR_IMPORT, "Not a legal import file");
            return GS_ERROR;
        }

        if (block->len + parser.sql.len + line.len > max_size) {
            GSQL_PRINTF(ZSERR_IMPORT, "line is too long at line:%llu", importer->fileRows + 1);
            return GS_ERROR;
        }

        if (imp_parse_line(&parser, &line)) {
            cm_concat_text(block, (uint32)max_size, &(parser.sql));
            return GS_SUCCESS;
        }

        // last line
        if (remain.str == NULL) {
            cm_concat_text(block, (uint32)max_size, &(parser.sql));
            imp_parser_clear_sql(&parser);
            // read more data...
            if (imp_get_raw_buffer(importer, &raw_buf, MAX_SQL_SIZE, eof) != GS_SUCCESS) {
                return GS_ERROR;
            }
            GS_BREAK_IF_TRUE(*eof);
            continue;
        }
    }

    if (!imp_parser_sql_complete(&parser) && (parser.sql.len + block->len > 0)) {
        GSQL_PRINTF(ZSERR_IMPORT, "line is too long at line:%llu", importer->fileRows + 1);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t imp_tables(importer_t *importer, text_t *sql)
{
    if (imp_table_scripts(importer, sql) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t imp_ddl_parallel_init_core(importer_t *importer)
{
    // init DDL thread object
    importer->ddl_threads = (thread_t *)malloc(sizeof(thread_t) * importer->ddl_parallel);
    if (importer->ddl_threads == NULL) {
        GSQL_PRINTF(ZSERR_IMPORT, "out of memory, malloc threads info.");
        return GS_ERROR;
    }
    MEMS_RETURN_IFERR(memset_s(importer->ddl_threads, sizeof(thread_t) * importer->ddl_parallel, 0,
        sizeof(thread_t) * importer->ddl_parallel));

    // init DDL worker object
    importer->ddl_workers = (imp_ddl_worker_t *)malloc(sizeof(imp_ddl_worker_t) * importer->ddl_parallel);
    if (importer->ddl_workers == NULL) {
        GSQL_PRINTF(ZSERR_IMPORT, "out of memory, malloc thread args failed");
        return GS_ERROR;
    }
    MEMS_RETURN_IFERR(memset_s(importer->ddl_workers, sizeof(imp_ddl_worker_t) * importer->ddl_parallel, 0,
        sizeof(imp_ddl_worker_t) * importer->ddl_parallel));

    // init DDL error info object
    importer->ddl_error = (importer_error_t *)malloc(sizeof(importer_error_t) * importer->ddl_parallel);
    if (importer->ddl_error == NULL) {
        GSQL_PRINTF(ZSERR_IMPORT, "out of memory, malloc ddl error info failed");
        return GS_ERROR;
    }
    MEMS_RETURN_IFERR(memset_s(importer->ddl_error, sizeof(importer_error_t) * importer->ddl_parallel, 0,
        sizeof(importer_error_t) * importer->ddl_parallel));
    return GS_SUCCESS;
}

static status_t imp_ddl_parallel_init(importer_t *importer)
{
    if (imp_ddl_parallel_init_core(importer) != GS_SUCCESS) {
        return GS_ERROR;
    }

    for (uint32 i = 0; i < importer->ddl_parallel; i++) {
        importer->ddl_workers[i].closed = GS_FALSE;
        importer->ddl_workers[i].idle = GS_TRUE;
        importer->ddl_workers[i].id = i;
        importer->ddl_workers[i].status = WORKER_STATUS_INIT;
        importer->ddl_workers[i].ddl_queue = &(importer->ddl_queue);
        importer->ddl_workers[i].error_info = &(importer->ddl_error[i]);
        importer->ddl_workers[i].importer = importer;
        importer->ddl_workers[i].dml_status.dml_end_flag = (bool8 *)malloc(sizeof(bool8) * PAR_IMP_MAX_THREADS *
                                                                           IMP_MAX_TABLE_PART_NUMBER);
        if (importer->ddl_workers[i].dml_status.dml_end_flag == NULL) {
            GSQL_PRINTF(ZSERR_IMPORT, "out of memory, malloc thread args failed");
            return GS_ERROR;
        }
        importer->ddl_workers[i].dml_status.dml_record_count = (uint64 *)malloc(sizeof(uint64) * PAR_IMP_MAX_THREADS *
                                                                                IMP_MAX_TABLE_PART_NUMBER);
        if (importer->ddl_workers[i].dml_status.dml_record_count == NULL) {
            GSQL_PRINTF(ZSERR_IMPORT, "out of memory, malloc thread args failed");
            return GS_ERROR;
        }
        importer->ddl_workers[i].dml_status.dml_return = (en_worker_status *)malloc(sizeof(en_worker_status) *
                                                         PAR_IMP_MAX_THREADS * IMP_MAX_TABLE_PART_NUMBER);
        if (importer->ddl_workers[i].dml_status.dml_return == NULL) {
            GSQL_PRINTF(ZSERR_IMPORT, "out of memory, malloc thread args failed");
            return GS_ERROR;
        }
        importer->ddl_workers[i].dml_status.max_dml_parallel = PAR_IMP_MAX_THREADS * IMP_MAX_TABLE_PART_NUMBER;
        importer->ddl_workers[i].dml_status.dml_parallel = 0;
    }

    return GS_SUCCESS;
}

static status_t imp_dml_parallel_init(importer_t *importer)
{
    importer->dml_thread_lock = 0;

    importer->dml_threads = (thread_t *)malloc(sizeof(thread_t) * importer->parallel);
    if (importer->dml_threads == NULL) {
        GSQL_PRINTF(ZSERR_IMPORT, "out of memory, malloc threads info.");
        return GS_ERROR;
    }
    MEMS_RETURN_IFERR(memset_s(importer->dml_threads, sizeof(thread_t) * importer->parallel, 0,
        sizeof(thread_t) * importer->parallel));

    importer->dml_workers = (imp_dml_worker_t *)malloc(sizeof(imp_dml_worker_t) * importer->parallel);
    if (importer->dml_workers == NULL) {
        GSQL_PRINTF(ZSERR_IMPORT, "out of memory, malloc thread args failed");
        return GS_ERROR;
    }
    MEMS_RETURN_IFERR(memset_s(importer->dml_workers, sizeof(imp_dml_worker_t) * importer->parallel, 0,
        sizeof(imp_dml_worker_t) * importer->parallel));
    return GS_SUCCESS;
}

static status_t imp_parallel_init(importer_t *importer)
{
    GS_RETURN_IFERR(imp_ddl_parallel_init(importer));
    return imp_dml_parallel_init(importer);
}

static int gsql_import_init(importer_t *importer)
{
    char realfile[GS_MAX_FILE_PATH_LENGH] = { 0x00 };
    char *realfile_ptr = NULL;
    imp_log("Preparing to import ...\n");

    /* open DUMP file and logfile (if specialed) */
    GS_RETURN_IFERR(realpath_file(importer->import_file, realfile, GS_MAX_FILE_PATH_LENGH));
    imp_trim_filename(realfile, GS_MAX_FILE_PATH_LENGH, g_importer.imp_file_path);
    PRTS_RETURN_IFERR(snprintf_s(g_importer.imp_subfile_path, GS_FILE_NAME_BUFFER_SIZE, GS_FILE_NAME_BUFFER_SIZE - 1,
        "%s%s/", g_importer.imp_file_path, GSQL_SEC_FILE_NAME));

    if (importer->crypt_info.crypt_flag) {
        realfile_ptr = realfile;
        if (gsql_decrypt_prepare(&importer->crypt_info, realfile_ptr) != GS_SUCCESS) {
            GSQL_PRINTF(ZSERR_IMPORT, "Fail to parse %s or incorrect password", GSQL_CRYPT_CFG_NAME);
            return GS_ERROR;
        }
    }

    GS_RETURN_IFERR(imp_open_file(&importer->impfp, importer->import_file, &g_import_bin.df_handle.zstream, GS_FALSE));
    GS_RETURN_IFERR(imp_open_logger(importer->log_file));

    /* alloc raw buffer for caching content from DUMP file. */
    importer->rawBuf = (char *)malloc(RAW_BUF_SIZE + 1);
    if (importer->rawBuf == NULL) {
        GSQL_PRINTF(ZSERR_IMPORT, "out of memory, malloc thread args failed");
        return GS_ERROR;
    }
    MEMS_RETURN_IFERR(memset_s(importer->rawBuf, RAW_BUF_SIZE + 1, 0, RAW_BUF_SIZE + 1));

    /* init schema name */
    MEMS_RETURN_IFERR(strncpy_s(importer->singleSchema, sizeof(importer->singleSchema), USER_NAME, (uint32)strlen(USER_NAME)));

    /* prepare bin object and bin buffer for BIN dump file. */
    if (importer->file_type == FT_BIN) {
        imp_reset_bin_opts(&g_import_bin);
        g_import_bin.binBuf = (char *)malloc(RAW_BUF_SIZE + 1);
        if (g_import_bin.binBuf == NULL) {
            GSQL_PRINTF(ZSERR_IMPORT, "out of memory, malloc thread args failed");
            return GS_ERROR;
        }

        MEMS_RETURN_IFERR(memset_s(g_import_bin.binBuf, RAW_BUF_SIZE + 1, 0, RAW_BUF_SIZE + 1));
    }

    /* init DDL queue for block transfer between main thread and DDL threads */
    // init chan for DDL thread.
    importer->ddl_queue.chan = cm_chan_new(MAX_DDL_CHAN_BLOCK_CNT, sizeof(import_ddl_block));
    importer->ddl_queue.inque_cnt = 0;
    importer->ddl_queue.outque_cnt = 0;
    importer->ddl_queue.outqueue_lock = 0;

    // in chan : MAX_DDL_CHAN_BLOCK_CNT
    // in ddl thread: importer->ddl_parallel *2 (when do remap importer->ddl_parallel*2)
    // in main thread : 2 (when do remap 1*2)
    uint32 parent_block_count = (MAX_DDL_CHAN_BLOCK_CNT + (importer->ddl_parallel + 1) * 2);
    // each block may include 13(9 subfile list block) sub block
    uint32 block_count = parent_block_count * 13;
    if (gsc_common_init_fixed_memory_pool(&importer->ddl_sql_block_pool, IMP_MAX_NORMAL_BLOCK_SIZE, block_count) !=
        GS_SUCCESS) {
        GSQL_PRINTF(ZSERR_LOAD, "out of memory, malloc sql buffer");
        return GS_ERROR;
    }
    
    block_count = parent_block_count * (PAR_IMP_MAX_THREADS * IMP_MAX_TABLE_PART_NUMBER);
    if (gsc_common_init_fixed_memory_pool(&importer->ddl_subfile_pool, (GS_MAX_NAME_LEN + 1), block_count) !=
        GS_SUCCESS) {
        GSQL_PRINTF(ZSERR_LOAD, "out of memory, malloc subfile buffer");
        return GS_ERROR;
    }

    /* init DDL/DML thread resource */
    GS_RETURN_IFERR(imp_parallel_init(importer));
        
    return GS_SUCCESS;
}

static void imp_ddl_parallel_uninit(importer_t *importer)
{
    // uninit DDL thread object
    if (importer->ddl_threads != NULL) {
        free(importer->ddl_threads);
        importer->ddl_threads = NULL;
    }

    // uninit DDL worker object
    if (importer->ddl_workers != NULL) {
        for (uint32 i = 0; i < importer->ddl_parallel; i++) {
            CM_FREE_PTR(importer->ddl_workers[i].dml_status.dml_end_flag);
            CM_FREE_PTR(importer->ddl_workers[i].dml_status.dml_record_count);
            CM_FREE_PTR(importer->ddl_workers[i].dml_status.dml_return);
        }
        free(importer->ddl_workers);
        importer->ddl_workers = NULL;
    }

    // uninit DDL error info object
    if (importer->ddl_error != NULL) {
        free(importer->ddl_error);
        importer->ddl_error = NULL;
    }
}

static void gsql_import_free(importer_t *importer)
{
    imp_close_file(&importer->impfp, &g_import_bin.df_handle.zstream, GS_FALSE);
    gsql_decrypt_end(&importer->crypt_info);
    imp_close_logger();
    cm_reset_list(&importer->obj_list);
    cm_reset_list(&importer->tblSpaceMaps);

    if (importer->dml_threads != NULL) {
        free(importer->dml_threads);
        importer->dml_threads = NULL;
    }

    if (importer->dml_workers != NULL) {
        free(importer->dml_workers);
        importer->dml_workers = NULL;
    }

    if (importer->rawBuf != NULL) {
        free(importer->rawBuf);
        importer->rawBuf = NULL;
    }

    if (g_import_bin.binBuf != NULL) {
        free(g_import_bin.binBuf);
        g_import_bin.binBuf = NULL;
    }

    gsc_common_uninit_fixed_memory_pool(&importer->ddl_sql_block_pool);
    gsc_common_uninit_fixed_memory_pool(&importer->ddl_subfile_pool);
}

static status_t gsql_launch_ddl_workers(importer_t *importer)
{
    status_t ret;

    for (uint32 i = 0; i < importer->ddl_parallel; i++) {
        ret = cm_create_thread(gsql_ddl_worker_proc, 0, &importer->ddl_workers[i], &importer->ddl_threads[i]);
        if (ret != GS_SUCCESS) {
            GSQL_PRINTF(ZSERR_IMPORT, "create ddl threads failed!");
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

// launch workers
static status_t gsql_launch_workers(importer_t *importer)
{
    status_t ret;

    for (uint32 i = 0; i < importer->parallel; i++) {
        importer->dml_workers[i].id = i;
        importer->dml_workers[i].idle = GS_FALSE;
        importer->dml_workers[i].closed = GS_FALSE;
        importer->dml_workers[i].status = WORKER_STATUS_INIT;
        importer->dml_workers[i].ignore = importer->ignore;
        importer->dml_workers[i].show = importer->show;
        importer->dml_workers[i].fileType = importer->file_type;
        importer->dml_workers[i].batchRowCnt = importer->batchRowCnt;
    }

    for (uint32 i = 0; i < importer->parallel; i++) {
        ret = cm_create_thread(gsql_worker_proc, 0, &importer->dml_workers[i], &importer->dml_threads[i]);
        if (ret != GS_SUCCESS) {
            GSQL_PRINTF(ZSERR_IMPORT, "create threads failed!");
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

int gsql_importer_wait_ddl_workers(importer_t *importer)
{
    uint32 i = 0;
    uint32 sum = 0;
    uint32 loop = 0;

    while (GS_TRUE) {
        sum = 0;
        for (i = 0; i < importer->ddl_parallel; i++) {
            if (importer->ddl_workers[i].status == WORKER_STATUS_RECV) {
                sum += 1;
            }
        }

        if (sum == importer->ddl_parallel) {
            break;
        }

        cm_sleep(1);
        loop += 1;

        if (loop > 10000) {  // wait ddl worker threads 10s
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

int gsql_importer_wait_workers(importer_t *importer)
{
    uint32 i = 0;
    uint32 sum = 0;
    uint32 loop = 0;

    while (GS_TRUE) {
        sum = 0;
        for (i = 0; i < importer->parallel; i++) {
            if (importer->dml_workers[i].status == WORKER_STATUS_RECV) {
                sum += 1;
            }
        }

        if (sum == importer->parallel) {
            break;
        }

        cm_sleep(1);
        loop += 1;

        if (loop > WAIT_WORKER_THREADS_TIME) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t gsql_start_ddl_parallel(importer_t *importer)
{
    if (importer->ddl_parallel == 0) {
        return GS_SUCCESS;
    }

    if (gsql_launch_ddl_workers(importer) != GS_SUCCESS) {
        GSQL_PRINTF(ZSERR_IMPORT, "launch workers failed");
        return GS_ERROR;
    }

    if (gsql_importer_wait_ddl_workers(importer) != GS_SUCCESS) {
        GS_THROW_ERROR(ERR_CLT_IMP_DATAFILE, "wait DDL worker", "DDL worker init timeout or failed");
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

static status_t gsql_start_dml_parallel(importer_t *importer)
{
    if (importer->parallel == 0) {
        return GS_SUCCESS;
    }

    if (gsql_launch_workers(importer) != GS_SUCCESS) {
        GSQL_PRINTF(ZSERR_IMPORT, "launch workers failed");
        return GS_ERROR;
    }

    if (gsql_importer_wait_workers(importer) != GS_SUCCESS) {
        GS_THROW_ERROR(ERR_CLT_IMP_DATAFILE, "wait DML worker", "DML worker init timeout or failed");
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

static status_t gsql_start_parallel(importer_t *importer)
{
    GS_RETURN_IFERR(gsql_start_ddl_parallel(importer));
    return gsql_start_dml_parallel(importer);
}

static void gsql_close_ddl_parallel(importer_t *importer, status_t *ret)
{
    // close the threads
    uint32 i;

    for (i = 0; i < importer->ddl_parallel; i++) {
        importer->ddl_workers[i].closed = GS_TRUE;
    }
    
    for (i = 0; i < importer->ddl_parallel; i++) {
        cm_close_thread(&importer->ddl_threads[i]);
    }
}

static void gsql_close_dml_parallel(importer_t *importer, status_t *ret)
{
    uint32 i = 0;

    for (i = 0; i < importer->parallel; i++) {
        importer->dml_workers[i].closed = GS_TRUE;
    }

    for (i = 0; i < importer->parallel; i++) {
        cm_close_thread(&importer->dml_threads[i]);
        /* collect insert record count of all worker(all table in subfile). */
        importer->fileInsertNum += importer->dml_workers[i].fileInsertNum;
        if (importer->dml_workers[i].status == WORKER_STATUS_ERR) {
            GS_THROW_ERROR(ERR_CLT_IMP_DATAFILE, "check DML return code", "DML worker throwed error");
            *ret = GS_ERROR;
        }
    }
}

static void gsql_close_parallel(importer_t *importer, status_t *ret)
{
    gsql_close_ddl_parallel(importer, ret);
    gsql_close_dml_parallel(importer, ret);
}

static status_t imp_one_sql(importer_t *importer, text_t *sql)
{
    switch (importer->imp_type) {
        case IMP_TABLE:
            return imp_tables(importer, sql);

        case IMP_ALL_TABLES:
            return imp_all_tables(importer, sql);

        case IMP_SCHEMA:
            return imp_schema(importer, sql);

        case IMP_ALL_SCHEMAS:
        case IMP_FULL:
            return imp_all_schemas(importer, sql);

        case IMP_REMAP_SCHEMA:
            return imp_remap_schema(importer, sql);

        default:
            GSQL_PRINTF(ZSERR_IMPORT, "the type of import is incorrect.");
            return GS_ERROR;
    }
}

static status_t imp_txt_change_schema(importer_t *importer)
{
    if (importer->imp_type == IMP_REMAP_SCHEMA) {
        GS_RETURN_IFERR(imp_change_curr_schema(&g_conn_info, importer->targetObj));
    }
    return GS_SUCCESS;
}

static int gsql_start_importing(importer_t *importer)
{
    status_t status = GSC_SUCCESS;
    bool8 eof = GS_FALSE;
    char *file_block = NULL;

    // change connection schema information
    GS_RETURN_IFERR(imp_txt_change_schema(importer));

    file_block = (char *)malloc(IMP_MAX_LARGE_BLOCK_SIZE);
    if (file_block == NULL) {
        GSQL_PRINTF(ZSERR_IMPORT, "malloc import sql buffer failed, %u", IMP_MAX_LARGE_BLOCK_SIZE);
        return GS_ERROR;
    }

    while (status == GSC_SUCCESS) {
        // break if canceled
        if (GSQL_CANCELING) {
            GS_THROW_ERROR(ERR_OPERATION_CANCELED);
            status = GS_ERROR;
            break;
        }

        text_t sql = { file_block, 0 };
        status = imp_read_sql(importer, &sql, IMP_MAX_LARGE_BLOCK_SIZE, &eof);
        if (status != GS_SUCCESS) {
            GS_THROW_ERROR(ERR_CLT_IMP_DATAFILE, "read file", "not a correct import file");
            break;
        }

        GS_BREAK_IF_TRUE(eof);

        status = imp_one_sql(importer, &sql);
        GS_BREAK_IF_ERROR(status);
    }

    if (importer->imp_type == IMP_TABLE && !importer->tblMatched) {
        GSQL_PRINTF(ZSERR_IMPORT, "the tables do not exist in the current schema or the import file is incorrect!");
        GS_THROW_ERROR(ERR_CLT_IMP_DATAFILE, "check loaded table number", "no table loaded");
        status = GS_ERROR;
    }

    CM_FREE_PTR(file_block);
    return status;
}

static int gsql_start_bin_importing(importer_t *importer)
{
    import_bin_t *imp_bin = &g_import_bin;

    // read BIN head;
    GS_RETURN_IFERR(gsql_imp_read_filehead(importer, imp_bin));

    // process schema
    GS_RETURN_IFERR(imp_get_uint32_from_buffer(imp_bin, &imp_bin->schemaNum, importer->impfp));
    if (imp_bin->schemaNum == 0) {
        text_t schema_buf = { importer->singleSchema, GS_MAX_NAME_LEN + 1 };
        if (gsql_get_curr_schema(&schema_buf) != GS_SUCCESS) {
            GS_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "failed to get current schema!");
            return GS_ERROR;
        }
        GS_RETURN_IFERR(imp_one_schema_bin(importer, imp_bin));
    } else {
        for (uint32 i = 0; i < imp_bin->schemaNum; i++) {
            uint32 schema_len;
            // process schema name
            GS_RETURN_IFERR(imp_get_uint32_from_buffer(imp_bin, &schema_len, importer->impfp));
            GS_RETURN_IFERR(imp_get_data_from_buffer(imp_bin, importer->singleSchema, sizeof(importer->singleSchema),
                                                     schema_len, importer->impfp));
            importer->singleSchema[schema_len] = '\0';
            imp_timing_log(GS_TRUE, "\nImporting schema %s ... \n", importer->singleSchema);

            GS_RETURN_IFERR(imp_one_schema_bin(importer, imp_bin));
        }
    }

    // notify DDL thread stop.
    GS_RETURN_IFERR(imp_notify_ddl_thread_stop(importer));
    return GS_SUCCESS;
}

static int gsql_import_file(importer_t *importer)
{
    int status;

    do {
        status = gsql_import_init(importer);
        if (status != GSC_SUCCESS) {
            gsql_import_free(importer);
            return status;
        }

        gsql_import_print_options(importer);

        status = imp_set_attr_nologging_and_trigger(CONN);
        GS_BREAK_IF_ERROR(status);

        status = gsql_start_parallel(importer);
        GS_BREAK_IF_ERROR(status);

        if (importer->file_type == FT_TXT) {
            status = gsql_start_importing(importer);
        } else {
            status = gsql_start_bin_importing(importer);
        }
    } while (0);

    gsql_close_parallel(importer, (status_t *)&status);

    if (status == GS_SUCCESS) {
        gsql_printf("data importing success, %llu rows are loaded.\n", importer->fileInsertNum);
    }

    gsql_import_free(importer);
    return status;
}

static void imp_print_ddl_error(importer_t* importer)
{
    if (importer->ddl_error == NULL) {
        return;
    }
    for (uint32 i = 0; i < importer->ddl_parallel; i++) {
        if (importer->ddl_error[i].error_code != ERR_ERRNO_BASE) {
            imp_log("thread %u : CT-%05d, %s\n", i + 1,
                importer->ddl_error[i].error_code,
                importer->ddl_error[i].error_msg);
        }
    }
}

status_t gsql_import(text_t *cmd_text)
{
    int status;
    uint32 matched_id;
    lex_t lex;
    sql_text_t sql_text;
    date_t start_time;
    char date_str[GS_MAX_TIME_STRLEN];

    start_time = cm_now();

    sql_text.value = *cmd_text;
    sql_text.loc.line = 1;
    sql_text.loc.column = 1;

    lex_trim(&sql_text);
    lex_init(&lex, &sql_text);
    lex_init_keywords();

    if (lex_expected_fetch_1of2(&lex, "IMP", "IMPORT", &matched_id) != GS_SUCCESS) {
        imp_tmlog_conn_error(NULL);
        return GS_ERROR;
    }

    if (lex_try_fetch_1ofn(&lex, &matched_id, 4, "help", "usage", "option", "-h") != GS_SUCCESS) {
        imp_tmlog_conn_error(NULL);
        return GS_ERROR;
    }

    if (matched_id != GS_INVALID_ID32) {
        gsql_display_import_usage();
        return GS_SUCCESS;
    }

    if (!IS_CONN) {
        imp_tmlog_error("check connection", "connection is not established");
        return GS_ERROR;
    }

    if (gsql_check_tenant() != GS_SUCCESS) {
        imp_tmlog_conn_error(NULL);
        return GS_ERROR;
    }

    imp_reset_opts(&g_importer);
    char curr_schema[GS_MAX_NAME_LEN + 1];
    text_t schema_buf = { curr_schema, GS_MAX_NAME_LEN + 1 };
    if (gsql_get_curr_schema(&schema_buf) != GS_SUCCESS) {
        GS_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "failed to get current schema!");
        return GS_ERROR;
    }
    do {
        imp_log("Parsing import options ... \n");
        if (imp_parse_opts(&lex, &g_importer) != GS_SUCCESS) {
            status = GS_ERROR;  // the lex error is in client
            break;
        }
        imp_timing_log(g_importer.timing, "Logical import starts at: %s\n", imp_now());
        imp_log("Verify options ...\n");
        status = imp_verify_opts(&g_importer, curr_schema);
        GS_BREAK_IF_ERROR(status);

        // gsql_import_file involving memory allocation, thus the errno cannot be
        // directly returned before imp_free
        imp_log("Starting import ...\n");
        /* reconnect to server, disable interactive check */
        status = gsql_set_session_interactive_mode(GS_FALSE);
        GS_BREAK_IF_ERROR(status);
        status = gsql_import_file(&g_importer);
        GS_BREAK_IF_ERROR(status);
        /* reconnect to server, enable interactive check */
        status = gsql_set_session_interactive_mode(GS_TRUE);
        GS_BREAK_IF_ERROR(status);
    } while (0);

    imp_timing_log(g_importer.timing, "\nLogical import ends at: %s\n", imp_now());
    imp_timing_log(g_importer.timing, "The total time of logical import is: %s\n",
                   imp_get_timestamp(date_str, sizeof(date_str), cm_now() - start_time));

    if (status != GSC_SUCCESS) {
        imp_log("\n");
        imp_print_ddl_error(&g_importer);
        imp_tmlog_conn_error(CONN);
        imp_log("Logical import failed.\n\n"); /* !! do not change, interface for other platform */
    } else {
        imp_log("Logical import succeeded.\n\n"); /* !! do not change, interface for other platform */
    }

    if (imp_reset_curr_schema(&g_conn_info, curr_schema) != GS_SUCCESS) {
        imp_tmlog_error("change back schema", curr_schema);
    }

    if (imp_reset_root_tenant(&g_conn_info) != GS_SUCCESS) {
        imp_tmlog_error("change back TENANT$ROOT", "failed");
    }

    imp_ddl_parallel_uninit(&g_importer);
    return status;
}
