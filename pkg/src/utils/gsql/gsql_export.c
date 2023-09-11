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
 * gsql_export.c
 *
 *
 * IDENTIFICATION
 * src/utils/gsql/gsql_export.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_base.h"
#include "gsql_common.h"
#include "gsql_export.h"
#include "cm_lex.h"
#include "cm_thread.h"
#include "gsql_exp_bin.h"
#include "cm_row.h"
#include "cm_log.h"
#include "cm_utils.h"
#include "cm_hash.h"
#include "cm_defs.h"
#include "cm_kmc.h"
#include "gsc_stmt.h"

typedef enum {
    EXP_NONE,
    EXP_SCHEMA,
    EXP_TABLE,
    EXP_DIST_RULES,
    EXP_ALL_DIST_RULES,
    EXP_ALL_TABLES,
    EXP_ALL_SCHEMAS
} export_type_t;

typedef enum {
    CT_EXP_DATA = 0x00000001,
    CT_EXP_META = 0x00000002,
    CT_EXP_ALL = CT_EXP_DATA | CT_EXP_META,
} exp_contenttype_t;

typedef enum {
    EXP_TABLE_FULL,
    EXP_TABLE_PARTITION,
} exp_tabletype_t;

#define MAX_EXP_QUERY_SIZE    SIZE_K(10)
#define MAX_EXP_SQL_SIZE      SIZE_K(5)
#define MAX_TAB_NAME_LEN      64
#define MAX_PWD_CHIPER_LEN    1000
#define MAX_EXP_LOB_BUFF_SIZE SIZE_M(4)
#define MAX_PARALLEL_VALUE    16

#define EXP_INDENT             "  "
#define EXP_INDENT2            "    "
#define EXP_INDENT3            "      "
#define EXP_TABLES_AGENT       "DB_TABLES"
#define EXP_TAB_COLS_AGENT     "DB_TAB_COLS"
#define EXP_TAB_COMMENTS_AGENT "DB_TAB_COMMENTS"
#define EXP_COL_COMMENTS_AGENT "DB_COL_COMMENTS"
/* INDEX AND CONSTRAINT SUPPORT SAME NAME BETWEEN DIFFERENT TABLE, SO ENABLE_IDX_CONFS_NAME_DUPL = TRUE, SHOULD DECODE
  INDEX OR CONSTRAINT NAME */
#define EXP_INDEXES_AGENT      "DB_INDEXES"
#define EXP_CONSTRAINTS_AGENT  "DB_CONSTRAINTS"
#define EXP_VIEWS_AGENT        "DB_VIEWS"
#define EXP_DEPENDENCIES_AGENT "DB_DEPENDENCIES"
#define EXP_VIEW_DEPENDENCIES_AGENT "DB_VIEW_DEPENDENCIES"
#define EXP_VIEW_COLS_AGENT    "DB_VIEW_COLUMNS"
#define EXP_PROCS_AGENT        "ADM_PROCEDURES"
#define EXP_MY_PROCS_AGENT     "MY_PROCEDURES"
#define EXP_USERS_AGENT        "DB_USERS"
#define EXP_SELF_USERS_AGENT   "MY_USERS"
#define EXP_SEQUENCE_AGENT     "DB_SEQUENCES"
#define EXP_SESSION_NLS_AGENT  "NLS_SESSION_PARAMETERS"
#define EXP_PARTITIONS_AGENT   "DB_TAB_PARTITIONS"
#define EXP_PARTTAB_AGENT      "DB_PART_TABLES"
#define EXP_DISTRIBUTE_AGENT   "DB_TAB_DISTRIBUTE"
#define EXP_DISTRIBUTE_RULE_AGENT   "DB_DISTRIBUTE_RULES"
#define EXP_DISTRIBUTE_RULE_COLS_AGENT   "DB_DIST_RULE_COLS"
#define EXP_TABLESPACES_DATAFILE_AGENT   "ADM_DATA_FILES"
#define EXP_DV_TABLESPACES               "DV_TABLESPACES"
#define EXP_TAB_AUTO_INCRE_AGENT     "DB_TAB_COLUMNS"
#define EXP_TRIGGERS_AGENT             "DB_TRIGGERS"
#define EXP_DATA_NODE_AGENT             "SYS_DATA_NODES"
#define EXP_DV_PARAM_AGENT             "DV_PARAMETERS"
#define EXP_DV_TENANT_TABLESPACES      "DV_TENANT_TABLESPACES"
#define EXP_DV_DATA_FILES_AGENT        "DV_DATA_FILES"
#define EXP_LOB_AGENT           "MY_LOBS"

#define EXP_MAX_FILE_BUF     SIZE_M(1)
#define EXP_MAX_LOB_FILE_BUF SIZE_M(16)

#define GS_STDOUT                     stdout
#define EXP_MAX_DDL_BUF_SZ            SIZE_K(2)  // 64 column name + 64 type + size + default 1K
// redirect flag: 4bytes(0xFFFFFFFF); lob file offset:8bytes; lob file name size:2bytes
#define EXP_LOB_LOCATOR_REDIRECT_SIZE 14
#define EXP_LOB_MAX_FILE_NAME_LEN     30
#define EXP_LOB_MAX_FILE_NAME_LEN2    24

#define EXP_COMPRESS_NONE 0
#define EXP_COMPRESS_MAX  9
#define EXP_WRITE_FMT_100 100
#define EXP_MAX_DN_NUM   (256)
#define EXP_MAX_ID_NUM   (16)
#define EXP_MAX_USERNAME (GS_NAME_BUFFER_SIZE + 4)
#define EXP_MAX_PASSWD (GS_PASSWORD_BUFFER_SIZE + 4)
#define EXP_MAX_URL (CM_UNIX_DOMAIN_PATH_LEN + 4UL)
#define EXP_MAX_PARAM_SIZE   (128)

static char *g_exp_fbuf = NULL;
static char *g_lob_fbuf = NULL;
static text_buf_t g_exp_txtbuf;
static FILE *g_lob_binfile = (FILE *)NULL;
static gsc_z_stream g_lf_zstream;  // used for lob file compress.
static FILE *g_exp_dpfile = (FILE *)NULL;
static FILE *g_exp_dpbinfile = (FILE *)NULL;
static gsc_z_stream g_df_zstream;  // used for data file compress.
static FILE *g_exp_logfile = (FILE *)NULL;
static uint64 g_exp_scn = GS_INVALID_ID64;
static uint64 g_exp_gts_scn = GS_INVALID_ID64;
/* used to read lob columns, malloc SIZE_M(4) */
static char *g_exp_lob_buff = NULL;

/** Used to generate an unique and global file id when parallel exporting datafiles */
static volatile uint32 g_file_no = 0;

/* export global error info */
typedef struct st_exp_err_info {
    error_info_t err_info;
    bool8        local_error;
} exp_err_info_t;

typedef struct st_exp_obj_info {
    char obj_name[GSQL_MAX_OBJECT_LEN];
    char obj_type[GSQL_MAX_OBJECT_TYPE_LEN];
} exp_obj_info_t;

#ifdef WIN32
static __declspec(thread) exp_err_info_t g_exp_err_info;
#else
static  __thread exp_err_info_t g_exp_err_info;
#endif

void exp_copy_error(void);

#define EXP_RESET_ERROR g_exp_err_info.local_error = GS_FALSE;

#define EXP_THROW_ERROR(err_no, ...)                                                                               \
    do {                                                                                                           \
        GS_THROW_ERROR(err_no, ##__VA_ARGS__);                                                                     \
        exp_copy_error();                                                                                          \
    } while (0)

#define EXP_THROW_ERROR_EX(err_no, format, ...)                                                                    \
    do {                                                                                                           \
        GS_THROW_ERROR_EX(err_no, format, ##__VA_ARGS__);                                                          \
        exp_copy_error();                                                                                          \
    } while (0)

#define EXP_SRC_THROW_ERROR_EX(src_loc, err_no, format, ...)                                                       \
    do {                                                                                                           \
        GS_SRC_THROW_ERROR_EX(src_loc, err_no, format, ##__VA_ARGS__);                                             \
        exp_copy_error();                                                                                          \
    } while (0)

#define EXP_SET_ERROR_LOC(src_loc)                 \
    do {                                           \
        if (g_exp_err_info.local_error) {          \
            g_exp_err_info.err_info.loc = src_loc; \
        } else {                                   \
            cm_set_error_loc(src_loc);             \
        }                                          \
    } while (0)

#define MEMS_EXP_RETURN_IFERR(func)        \
    do {                                                \
        int32 __code__ = (func);                       \
        if (SECUREC_UNLIKELY(__code__ != EOK)) {       \
            EXP_THROW_ERROR(ERR_SYSTEM_CALL, __code__); \
            return GS_ERROR;                           \
        }                                              \
    } while (0)

#define EXP_RETRUN_IF_CANCEL                     \
    if (GSQL_CANCELING) {                        \
        EXP_THROW_ERROR(ERR_OPERATION_CANCELED); \
        return GS_ERROR;                         \
    }

typedef struct st_exp_cn_gts_param {
    char gts_consist[EXP_MAX_PARAM_SIZE];
    char shd_fac_key[EXP_MAX_PARAM_SIZE];
    char shd_loc_key[EXP_MAX_PARAM_SIZE];
} exp_cn_gts_param_t;

typedef struct st_exp_par_conn {
    uint32_t par_num;
    gsc_conn_t conn[MAX_PARALLEL_VALUE];
    gsc_stmt_t stmt[MAX_PARALLEL_VALUE];
} exp_par_conn_t;

typedef struct st_exp_dn_info {
    gsql_conn_info_t dn_conn_info;
    uint32   dn_group_id;
    uint64   dn_scn;
    exp_par_conn_t dn_par_conn;
} exp_dn_info_t;

typedef struct st_exp_shd_info {
    uint32_t shd_node_type;  // the type of the current node connected by ctclient is or not CN

    list_t  dn_info_list;   // all dn nodes info
    gsql_conn_info_t gts_conn_info;
    exp_cn_gts_param_t gts_param_info;
    bool32 consistent;
} exp_shd_info_t;

typedef struct st_tab_dist_info {
    cs_distribute_type_t dist_type;  // distribute type: hash, list, range, replication
    uint32_t gid_num;
    uint32_t tab_gid[EXP_MAX_DN_NUM];
} exp_tab_dist_info_t;

// gen scn with given seq
#define TIMESEQ_TO_SCN(time_val, init_time, seq) \
    ((uint64)((time_val)->tv_sec - (init_time)) << 32 | (uint64)(time_val)->tv_usec << 12 | (seq))

#define SCN_TO_TIMESEQ(scn, time_val, seq, init_time)                                  \
    do {                                                                                   \
        (time_val)->tv_sec = (long)(((scn) >> 32 & 0x00000000ffffffffULL) + (init_time)); \
        (time_val)->tv_usec = (long)((scn) >> 12 & 0x00000000000fffffULL);                 \
        seq = (uint64)((scn) & 0x0000000000000fffULL);                                     \
    } while (0)

/* Single thread export binary file format variable description
opt->master_bin_mgr, g_exp_dpfile --master bin file
g_exp_txtbuf, g_exp_dpbinfile --data bin file
*/
typedef struct st_exp_table {
    uint8_t table_exp_type;
    list_t table_list;  /* table list */
    list_t partition_list;  /* partition list to export */
} exp_table_t;

typedef enum {
    EXP_EXCLUDE_TABLE = 0,
    EXP_MAX_EXCLUDE
} exp_exclude_type_t;

typedef struct st_exp_exclude_obj {
    exp_exclude_type_t type;
    text_t exclude_name;
    text_t exclude_cond;
} exp_exclude_obj_t;

// length means exclude name length ('TABLE' length:5)
static exp_exclude_obj_t g_expected_excludes[] = {
    { EXP_EXCLUDE_TABLE, { .str = "TABLE", .len =5 }, { .str = NULL, .len = 0 } }
};

typedef struct st_export_options {
    uint32 exp_type; /* refer to export_type_t */
    list_t exclude_list;
    list_t obj_list; /* user list */
    list_t tbs_list; /* list of tablespace names to filter data where you need */
    char dump_file[GS_MAX_FILE_PATH_LENGH];
    char dump_data_path[GS_MAX_FILE_PATH_LENGH];    // the path of all dump files
    // the bin_data_file_name, the bin data is located at dump_data_path/bin_data_file
    char bin_data_file[EXP_LOB_MAX_FILE_NAME_LEN];
    // the bin_data_file_name, the LOB data is located at dump_data_path/lob_file_name
    char lob_file_name[EXP_LOB_MAX_FILE_NAME_LEN];
    char log_file[GS_MAX_FILE_PATH_LENGH];
    // session schema name used when exp_type = EXP_TABLE or EXP_ALL_TABLES
    char schema_name[GS_MAX_NAME_LEN + 1];
    exp_filetype_t filetype;
    uint32 content;
    char query[MAX_EXP_QUERY_SIZE];
    bool32 compress;
    uint32 compress_level;
    bool32 consistent;
    bool32 skip_comments;
    bool32 force;
    bool32 skip_add_drop_table;
    bool32 skip_triggers;
    bool32 quote_names;
    bool8  is_case_insensitive;
    bool32 tablespace;
    uint32 commit_batch;
    uint32 insert_batch;
    uint32 feedback;
    uint32 parallel;  // Degree of parallelism
    bool32 tenant;
    bool32 create_user;
    bool32 exp_role;
    bool32 is_grant;
    bool32 with_cr_mode;
    bool32 with_format_csf;
    bool32 show_create_table;
    bool32 index_partitions;
    uint32 exp_status;
    bin_file_fixed_head_t *bin_meta_file_head;
    exp_bin_memory_mgr_t master_bin_mgr;
    exp_shd_info_t dn_info;
    crypt_info_t crypt_info;
    bool8 is_myself;
    bool8 is_dba;
    list_t table_maps;  /* tables map list */
    exp_table_t exp_tables;
} export_options_t;

typedef enum en_table_type {
    TABLE_TYPE_HEAP = 0,
    TABLE_TYPE_IOT = 1,
    TABLE_TYPE_TRANS_TEMP = 2,
    TABLE_TYPE_SESSION_TEMP = 3,
    TABLE_TYPE_NOLOGGING = 4,
    TABLE_TYPE_EXTERNAL = 5,
} table_type_t;

// context used by export tables in one schema
typedef struct {
    const char* user;
    list_t* tables;
    uint32* tab_cnt;
    
    export_options_t *exp_opts; // export options, tablespace filter,etc...

    gsc_stmt_t query_tab_column; // for query table column info, cached stmt, prepared first
    gsc_stmt_t query_func_indexes;
    gsc_stmt_t query_tab_has_intervalpart;
    gsc_stmt_t query_index_partitioning;
    gsc_stmt_t query_index_subpartition;
    gsc_stmt_t query_has_subpartition;

    bool32 reverse_index_available; // if server support reverse index
} exp_tabs_ctx_t;

typedef struct {
    exp_tabs_ctx_t *ctx; // tables context info, cached stmt reused

    /* below is table's info */
    const char* user;
    const char* table;
    table_type_t table_type;
    bool32 partitioned;
} exp_tab_info_t;

#define DEFAULT_DUMP_FILE "EXPDAT.DMP"
#define NULL_DUMP_FILE "stdout"

static export_options_t g_export_opts = {
    .exp_type = EXP_NONE,
    .dump_file = DEFAULT_DUMP_FILE,
    .filetype = FT_TXT,
    .log_file = "\0",
    .compress = GS_FALSE,
    .consistent = GS_FALSE,
    .index_partitions = GS_FALSE,
    .content = CT_EXP_ALL,
    .query = "\0",
    .skip_comments = GS_FALSE,
    .force = GS_FALSE,
    .skip_add_drop_table = GS_FALSE,
    .skip_triggers = GS_FALSE,
    .quote_names = GS_TRUE,
    .commit_batch = GSQL_COMMIT_BATCH,
    .insert_batch = 1,
    .feedback = GSQL_FEEDBACK,
    .is_myself = GS_FALSE
};

typedef struct {
    uint32 col_num;
    uint64 file_insert_num;
    uint64 *tab_record_total;
    gsc_inner_column_desc_t *col_desc;
    struct st_list lob_cols;
} exporter_t;

typedef struct st_exp_partition_info {
    char parent_partition_type[GS_MAX_NAME_LEN];
    char sub_partition_type[GS_MAX_NAME_LEN];
    bool8 has_sub_partition;
} exp_partition_info_t;

void exp_copy_error(void)
{
    const char* msg = NULL;
    gsql_get_error(NULL, &g_exp_err_info.err_info.code, &msg, &g_exp_err_info.err_info.loc);
    MEMS_RETVOID_IFERR(memcpy_sp(g_exp_err_info.err_info.message, GS_MESSAGE_BUFFER_SIZE, msg, GS_MESSAGE_BUFFER_SIZE));
    g_exp_err_info.local_error = GS_TRUE;
}

static void exp_get_error(gsc_conn_t conn, int32 *code, const char **msg, source_location_t *loc)
{
    if (g_exp_err_info.local_error) {
        *code = g_exp_err_info.err_info.code;
        *msg = g_exp_err_info.err_info.message;
        if (loc != NULL) {
            *loc = g_exp_err_info.err_info.loc;
        }
    } else {
        gsql_get_error(conn, code, msg, loc);
    }
}

static inline void inc_total(uint32 *total)
{
    if (total != NULL) {
        *total += 1;
    }
}

#define EXP_MAX_TABNAME_LEN 128

typedef enum en_exp_tabagent_type {
    EXP_TABAGENT_DB_SEQUENCES,
    EXP_TABAGENT_MY_LOBS,
    EXP_TABAGENT_DB_TABLES,
    EXP_TABAGENT_SYS_TABLES,
    EXP_TABAGENT_DB_PART_KEY_COLUMNS,
    EXP_TABAGENT_DB_SUBPART_KEY_COLUMNS,
    EXP_TABAGENT_DB_PART_STORE,
    EXP_TABAGENT_DB_PART_TABLES,
    EXP_TABAGENT_DB_TAB_PARTITIONS,
    EXP_TABAGENT_DB_TAB_SUBPARTITIONS,
    EXP_TABAGENT_DB_TAB_DISTRIBUTE,
    EXP_TABAGENT_DB_TAB_COMMENTS,
    EXP_TABAGENT_DB_INDEXES,
    EXP_TABAGENT_DB_IND_COLUMNS,
    EXP_TABAGENT_DB_IND_PARTITIONS,
    EXP_TABAGENT_DB_IND_SUBPARTITIONS,
    EXP_TABAGENT_DB_TAB_COLS,
    EXP_TABAGENT_DB_TAB_COLUMNS,
    EXP_TABAGENT_DB_COL_COMMENTS,
    EXP_TABAGENT_DB_CONSTRAINTS,
    EXP_TABAGENT_DB_VIEW_DEPENDENCIES,
    EXP_TABAGENT_DB_VIEWS,
    EXP_TABAGENT_DB_VIEW_COLUMNS,
    EXP_TABAGENT_TYPE_MAX
} exp_tabagent_type_t;

typedef struct st_exp_tabagent {
    exp_tabagent_type_t type;
    const char* table_name;
} exp_tabagent_t;

exp_tabagent_t g_exp_tabagents[EXP_TABAGENT_TYPE_MAX] = {
    { EXP_TABAGENT_DB_SEQUENCES,             "DB_SEQUENCES" },
    { EXP_TABAGENT_MY_LOBS,                  "MY_LOBS" },
    { EXP_TABAGENT_DB_TABLES,                "DB_TABLES" },
    { EXP_TABAGENT_SYS_TABLES,               "SYS.SYS_TABLES" },
    { EXP_TABAGENT_DB_PART_KEY_COLUMNS,      "DB_PART_KEY_COLUMNS" },
    { EXP_TABAGENT_DB_SUBPART_KEY_COLUMNS,   "DB_SUBPART_KEY_COLUMNS" },
    { EXP_TABAGENT_DB_PART_STORE,            "DB_PART_STORE" },
    { EXP_TABAGENT_DB_PART_TABLES,           "DB_PART_TABLES" },
    { EXP_TABAGENT_DB_TAB_PARTITIONS,        "DB_TAB_PARTITIONS" },
    { EXP_TABAGENT_DB_TAB_SUBPARTITIONS,     "DB_TAB_SUBPARTITIONS" },
    { EXP_TABAGENT_DB_TAB_DISTRIBUTE,        "DB_TAB_DISTRIBUTE" },
    { EXP_TABAGENT_DB_TAB_COMMENTS,          "DB_TAB_COMMENTS" },
    { EXP_TABAGENT_DB_INDEXES,               "DB_INDEXES" },
    { EXP_TABAGENT_DB_IND_COLUMNS,           "DB_IND_COLUMNS" },
    { EXP_TABAGENT_DB_IND_PARTITIONS,        "DB_IND_PARTITIONS" },
    { EXP_TABAGENT_DB_IND_SUBPARTITIONS,     "DB_IND_SUBPARTITIONS" },
    { EXP_TABAGENT_DB_TAB_COLS,              "DB_TAB_COLS" },
    { EXP_TABAGENT_DB_TAB_COLUMNS,           "DB_TAB_COLUMNS" },
    { EXP_TABAGENT_DB_COL_COMMENTS,          "DB_COL_COMMENTS" },
    { EXP_TABAGENT_DB_CONSTRAINTS,           "DB_CONSTRAINTS" },
    { EXP_TABAGENT_DB_VIEW_DEPENDENCIES,     "DB_VIEW_DEPENDENCIES" },
    { EXP_TABAGENT_DB_VIEWS,                 "DB_VIEWS" },
    { EXP_TABAGENT_DB_VIEW_COLUMNS,          "DB_VIEW_COLUMNS" },
};

static char* exp_tabname(bool32 consistent, exp_tabagent_type_t type)
{
    static char* buffer[EXP_TABAGENT_TYPE_MAX] = { 0 };

    CM_ASSERT(type < EXP_TABAGENT_TYPE_MAX);
    CM_ASSERT(type == g_exp_tabagents[type].type);

    if (buffer[type] == NULL) {
        buffer[type] = (char*)malloc(EXP_MAX_TABNAME_LEN);
        if (buffer[type] == NULL) {
            return NULL;
        }
    }

    // do not support consistent when export metadata, cause performance problem.
    errno_t errcode = strcpy_s(buffer[type], EXP_MAX_TABNAME_LEN, g_exp_tabagents[type].table_name);
    if (errcode != EOK) {
        CM_FREE_PTR(buffer[type]);
        return NULL;
    }

    return buffer[type];
}

static inline void clean_exp_bin_env(export_options_t *opt)
{
    crypt_file_t *crypt_file = NULL;
    if (opt->filetype == FT_TXT) {
        return;
    }

    if (opt->exp_status == GS_SUCCESS) {
        if (opt->crypt_info.crypt_flag) {
            (void)gsql_get_encrypt_file(&opt->crypt_info, &crypt_file, cm_fileno(g_exp_dpfile));
        }
        (void)mem_block_write_file(&opt->master_bin_mgr, g_exp_dpfile, crypt_file, opt->crypt_info.crypt_flag);
    }

    destroy_memory_mgr(&opt->master_bin_mgr);
}

static inline void init_exp_bin_env(export_options_t *opt)
{
    if (opt->filetype == FT_TXT) {
        return;
    }

    (void)init_exp_bin_memory_mgr(&opt->master_bin_mgr);
    init_bin_file_fixed_head(&opt->master_bin_mgr, &opt->bin_meta_file_head);
    opt->bin_meta_file_head->commit_batch = opt->commit_batch;
    opt->bin_meta_file_head->insert_batch = opt->insert_batch;
    opt->bin_meta_file_head->exp_type = opt->exp_type;
    opt->bin_meta_file_head->comp_flag = opt->compress;
    opt->bin_meta_file_head->client_ver = CLI_LOCAL_EXP_VERSION;
}

typedef struct st_exp_bin_file_ctx {
    text_buf_t bin_data_buf;
    text_buf_t bin_lob_buf;
    text_buf_t bin_lob_data_buf;  // buffer for read lob data.
    FILE *df_h;
    gsc_z_stream *df_zstream;
    FILE *lf_h;
    gsc_z_stream *lf_zstream;
    uint64 bin_file_size;
    char *tab_name;
    char df_name[EXP_LOB_MAX_FILE_NAME_LEN];
    char lf_name[EXP_LOB_MAX_FILE_NAME_LEN];

    uint16 offsets[GS_MAX_COLUMNS];
    uint16 lens[GS_MAX_COLUMNS];
    uint16 decode_count;
    bool32 wr_lob_flag;
} exp_bin_file_ctx_t;

typedef enum {
    PAR_EXP_IDLE,
    PAR_EXP_PROC
} exp_proc_status_t;

typedef struct st_tab_par_param {
    uint32 part_no;
    uint64 l_page;
    uint64 r_page;
    bool32 normal_tab;
} tab_par_param_t;

typedef struct st_par_exp_param {
    exp_cache_t *table_cache;
    char tab_name[GS_MAX_NAME_LEN + 1];
    char schema[GS_MAX_NAME_LEN + 1];
    uint64 scn;
    struct st_tab_par_param scan_param;
    gsc_conn_t conn;
    gsc_stmt_t stmt;
    bool32 is_coordinator;
} par_exp_param_t;

typedef struct st_exp_files_context {
    union un_text_buf exp_txtbuf;
    FILE *exp_dpfile;
    gsc_z_stream df_zstream;
    union un_text_buf bin_lob_buf;
    FILE *lf_h;
    gsc_z_stream lf_zstream;
    char *sql_buf;
    char *str_buf;  // for print a column data

    union un_text_buf lob_buf;  // for read lob data from server.
} exp_files_context_t;

typedef struct st_exp_cols {
    exporter_t exporter;
    bool32 init_cols;
} exp_cols_t;

typedef struct st_lob_col_desc {
    gsc_inner_column_desc_t col_desc;
    uint16 col_id;
} lob_col_desc_t;

static inline void exp_init_exporter(exporter_t *exporter)
{
    exporter->col_num = 0;
    exporter->col_desc = g_columns;
    exporter->file_insert_num = 0;
    exporter->tab_record_total = NULL;

    cm_create_list(&exporter->lob_cols, sizeof(lob_col_desc_t));
}

static inline void exp_destory_exporter(exporter_t *exporter)
{
    cm_destroy_list(&exporter->lob_cols);
}

static inline void exp_reset_exporter(exporter_t *exporter)
{
    cm_reset_list(&exporter->lob_cols);
}

typedef struct st_par_exp_thread_ctrl {
    thread_lock_t *lock_t;
    uint32 thread_no;
    int32 execute_ret;
    thread_t thread;
    exp_proc_status_t stat;
    struct st_export_options options;
    struct st_par_exp_param tab_param;
    struct st_exp_files_context files_context;
    struct st_gsql_conn_info_t conn_info;
    struct st_list exp_files;
    struct st_exp_cols *cols_def;
    uint64 *bin_rec_total_add;
} par_exp_thread_ctrl_t;

typedef struct st_par_exp_mgr {
    thread_lock_t lock_t;
    uint32 tab_par_param_offset;
    struct st_exp_cols exp_cols;
    struct st_par_exp_param par_proc_param;
    struct st_list tab_par_params;  // Get By Table function
    struct st_export_options options;
    struct st_par_exp_thread_ctrl thread_ctrls[GS_MAX_PAR_EXP_VALUE];
    uint64 *bin_rec_total_add;
} par_exp_mgr_t;

#define EXP_MAX_GROUPS  (GS_SHARED_PAGE_SIZE / sizeof(pointer_t))
#define EXP_MAX_OBJECTS (EXP_MAX_GROUPS * EXP_MAX_GROUPS * 64)


typedef struct st_exp_get_view_param {
    bool32 consistent;
} exp_get_view_param_t;

typedef struct st_exp_get_proc_param {
    export_options_t *exp_opts;
    const char* user;
} exp_get_proc_param_t;

typedef struct st_exp_get_roles_param {
    export_options_t *exp_opts;
} exp_get_roles_param_t;

typedef struct st_exp_get_synonyms_param {
    const char *user_name;
} exp_get_synonyms_param_t;

typedef struct st_exp_get_profile_param {
    const char *user_name;
} exp_get_profile_param_t;

typedef struct st_exp_get_type_param {
    const char *user_name;
} exp_get_type_param_t;

typedef struct st_exp_get_package_param {
    const char *user_name;
} exp_get_package_param_t;

typedef struct st_exp_get_partition_param {
    const char *user_name;
    const char *table_name;
    bool32 consistent;
    bool32 db_tab_partitions_has_flag;
} exp_get_partition_param_t;

typedef struct st_exp_comm_param {
    export_options_t *exp_opts;
} exp_comm_param_t;

typedef struct st_exp_get_db_tables_param {
    bool32 db_tables_has_flag;
} exp_get_db_tables_param_t;

typedef struct st_exp_get_user_table_param_t {
    const char *user_name;
    const char *table_name;
} exp_get_user_table_param_t;

typedef struct st_exp_prepare_sql_param {
    union {
        exp_get_view_param_t get_view_param;
        exp_get_proc_param_t get_proc_param;
        exp_get_roles_param_t get_role_param;
        exp_get_synonyms_param_t get_synonym_param;
        exp_get_profile_param_t get_profile_param;
        exp_get_type_param_t get_type_param;
        exp_get_package_param_t get_package_param;
        exp_get_partition_param_t get_partition_param;
        exp_comm_param_t comm_param;
        exp_get_db_tables_param_t get_db_tables_param;
        exp_get_user_table_param_t get_user_table_param;
    };
} exp_prepare_sql_param_t;

static status_t exp_get_user_views_sql(char *sql_buffer, uint32 buff_size, exp_prepare_sql_param_t *param)
{
    bool32 consistent = param->get_view_param.consistent;
    PRTS_RETURN_IFERR(sprintf_s(sql_buffer, buff_size,
        "SELECT * FROM (SELECT REFERENCED_NAME VIEW_NAME "
        " FROM %s"
        " WHERE REFERENCED_OWNER = UPPER(:3)"
        " GROUP BY REFERENCED_NAME ORDER BY MAX(REFERENCED_LEVEL) DESC,REFERENCED_NAME DESC)"
        " UNION ALL "
        " ("
        "  SELECT VIEW_NAME FROM %s WHERE OWNER = UPPER(:1) AND "
        "  VIEW_NAME NOT IN "
        "  (SELECT REFERENCED_NAME FROM %s WHERE OWNER = UPPER(:2)) "
        " )", exp_tabname(consistent, EXP_TABAGENT_DB_VIEW_DEPENDENCIES),
        exp_tabname(consistent, EXP_TABAGENT_DB_VIEWS),
        exp_tabname(consistent, EXP_TABAGENT_DB_VIEW_DEPENDENCIES)));
   
    return GS_SUCCESS;
}

static status_t exp_get_exclude_cond(exp_exclude_type_t type, export_options_t *exp_opts, text_t **cond)
{
    list_t *exclude_list = &exp_opts->exclude_list;
    exp_exclude_obj_t *obj = NULL;
    *cond = NULL;

    for (uint32 i = 0; i < exclude_list->count; i++) {
        obj = (exp_exclude_obj_t *)cm_list_get(exclude_list, i);
        if (obj->type == type) {
            *cond = &obj->exclude_cond;
            break;
        }
    }
    return GS_SUCCESS;
}

static status_t exp_get_user_procs_sql(char *sql_buffer, uint32 buff_size, exp_prepare_sql_param_t *param)
{
    exp_get_proc_param_t *exp_proc_param = (exp_get_proc_param_t *)(&param->get_proc_param);
    text_t *exclude_cond = NULL;

    // select columns
    PRTS_RETURN_IFERR(sprintf_s(sql_buffer, buff_size,
        "SELECT OBJECT_NAME, OBJECT_TYPE FROM "));

    // select table
    if (exp_proc_param->exp_opts->is_myself) {
        PRTS_RETURN_IFERR(sprintf_s(sql_buffer + strlen(sql_buffer), buff_size - strlen(sql_buffer),
            EXP_MY_PROCS_AGENT " WHERE "));
    } else {
        PRTS_RETURN_IFERR(sprintf_s(sql_buffer + strlen(sql_buffer), buff_size - strlen(sql_buffer),
            EXP_PROCS_AGENT " WHERE OWNER = UPPER('%s') AND ", exp_proc_param->user));
    }

    // object type condition
    if (exp_proc_param->exp_opts->skip_triggers) {
        PRTS_RETURN_IFERR(sprintf_s(sql_buffer + strlen(sql_buffer), buff_size - strlen(sql_buffer),
            "OBJECT_TYPE in('PROCEDURE', 'FUNCTION') "));
    } else {
        // exclude table condition
        GS_RETURN_IFERR(exp_get_exclude_cond(EXP_EXCLUDE_TABLE, exp_proc_param->exp_opts, &exclude_cond));
        if (exclude_cond == NULL) {
            PRTS_RETURN_IFERR(sprintf_s(sql_buffer + strlen(sql_buffer), buff_size - strlen(sql_buffer),
                "OBJECT_TYPE in('PROCEDURE', 'FUNCTION', 'TRIGGER') "));
        } else {
            PRTS_RETURN_IFERR(sprintf_s(sql_buffer + strlen(sql_buffer), buff_size - strlen(sql_buffer),
                "(OBJECT_TYPE in('PROCEDURE', 'FUNCTION') or (OBJECT_TYPE = 'TRIGGER' and "
                "OBJECT_NAME NOT IN (SELECT TRIGGER_NAME FROM " EXP_TRIGGERS_AGENT
                " WHERE TABLE_NAME %.*s))) ", exclude_cond->len, exclude_cond->str));
        }
    }

    // sort condition
    PRTS_RETURN_IFERR(sprintf_s(sql_buffer + strlen(sql_buffer), buff_size - strlen(sql_buffer),
        "ORDER BY OBJECT_ID"));

    return GS_SUCCESS;
}

static status_t exp_get_db_lob_storage_sql(char *sql_buffer, uint32 buff_size, exp_prepare_sql_param_t *param)
{
    exp_get_user_table_param_t* get_user_table_param = (exp_get_user_table_param_t*)&param->get_user_table_param;

    PRTS_RETURN_IFERR(sprintf_s(sql_buffer, buff_size,
        "SELECT COLUMN_NAME, TABLESPACE_NAME "
        "FROM %s "
        "WHERE OWNER = UPPER('%s') AND TABLE_NAME = '%s' AND TABLESPACE_NAME <> ( "
        "SELECT TABLESPACE_NAME FROM %s "
        "WHERE OWNER = UPPER('%s') AND TABLE_NAME = '%s' ) "
        "ORDER BY COLUMN_NAME",
        exp_tabname(g_export_opts.consistent, EXP_TABAGENT_MY_LOBS),
        get_user_table_param->user_name, get_user_table_param->table_name,
        exp_tabname(g_export_opts.consistent, EXP_TABAGENT_DB_TABLES),
        get_user_table_param->user_name, get_user_table_param->table_name));

    return GS_SUCCESS;
}

static status_t exp_get_db_tables_sql(char *sql_buffer, uint32 buff_size, exp_prepare_sql_param_t *param)
{
    exp_get_db_tables_param_t* get_db_tables_param = (exp_get_db_tables_param_t*)&param->get_db_tables_param;

    PRTS_RETURN_IFERR(sprintf_s(sql_buffer, buff_size,
        "SELECT TABLESPACE_NAME, INI_TRANS, MAX_TRANS, PCT_FREE, PARTITIONED, CR_MODE, APPENDONLY %s %s "
        "FROM %s "
        "WHERE OWNER = UPPER(:OWNER) AND TABLE_NAME = :TABLE_NAME",
        get_db_tables_param->db_tables_has_flag ? ", ROW_FORMAT" : " ",
        (gsc_get_call_version(CONN) >= CS_VERSION_22) ? ", COMPRESS_ALGO" : " ",
        exp_tabname(g_export_opts.consistent, EXP_TABAGENT_DB_TABLES)));

    return GS_SUCCESS;
}

static status_t exp_get_user_triggers_sql(char *sql_buffer, uint32 buff_size, exp_prepare_sql_param_t *param)
{
    exp_get_proc_param_t *exp_proc_param = (exp_get_proc_param_t *)(&param->get_proc_param);
    text_t *exclude_cond = NULL;

    if (exp_proc_param->exp_opts->is_myself) {
        PRTS_RETURN_IFERR(sprintf_s(sql_buffer, buff_size,
            "SELECT OBJECT_NAME FROM " EXP_MY_PROCS_AGENT " WHERE "));
    } else {
        PRTS_RETURN_IFERR(sprintf_s(sql_buffer, buff_size,
            "SELECT OBJECT_NAME FROM " EXP_PROCS_AGENT " "
            "WHERE OWNER = UPPER('%s') AND ", exp_proc_param->user));
    }

    PRTS_RETURN_IFERR(sprintf_s(sql_buffer + strlen(sql_buffer), buff_size - strlen(sql_buffer),
        "OBJECT_TYPE = 'TRIGGER' "));

    GS_RETURN_IFERR(exp_get_exclude_cond(EXP_EXCLUDE_TABLE, exp_proc_param->exp_opts, &exclude_cond));
    if (exclude_cond != NULL) {
        PRTS_RETURN_IFERR(sprintf_s(sql_buffer + strlen(sql_buffer), buff_size - strlen(sql_buffer),
            "AND OBJECT_NAME NOT IN (SELECT TRIGGER_NAME FROM " EXP_TRIGGERS_AGENT
            " WHERE TABLE_NAME %.*s) ", exclude_cond->len, exclude_cond->str));
    }

    PRTS_RETURN_IFERR(sprintf_s(sql_buffer + strlen(sql_buffer), buff_size - strlen(sql_buffer),
        "ORDER BY OBJECT_ID"));

    return GS_SUCCESS;
}

static status_t exp_get_partition_cols(exp_get_partition_param_t *exp_partition_param, char *column_names,
                                       size_t max_len)
{
    uint32 rows;
    char temp_column_name[MAX_COLUMN_WIDTH] = { 0 };
    char cmd_buf[GSQL_MAX_TEMP_SQL + 1];

    PRTS_RETURN_IFERR(sprintf_s(cmd_buf, GSQL_MAX_TEMP_SQL,
        "SELECT COLUMN_NAME FROM %s Y "
        "WHERE Y.OWNER = UPPER('%s') AND Y.NAME = '%s' "
        "AND OBJECT_TYPE = 'TABLE'  ORDER BY COLUMN_POSITION",
        exp_tabname(exp_partition_param->consistent, EXP_TABAGENT_DB_PART_KEY_COLUMNS),
        exp_partition_param->user_name, exp_partition_param->table_name));

    GS_RETURN_IFERR(gsc_prepare(STMT, (const char *)cmd_buf));
    GS_RETURN_IFERR(gsc_execute(STMT));

    bool8 is_first = GS_TRUE;
    do {
        GS_RETURN_IFERR(gsc_fetch(STMT, &rows));
        if (rows == 0) {
            break;
        }
        GS_RETURN_IFERR(gsc_column_as_string(STMT, 0, temp_column_name, MAX_COLUMN_WIDTH));
        if (!is_first) {
            MEMS_RETURN_IFERR(strcat_s(column_names, max_len, ","));
        }

        MEMS_RETURN_IFERR(strcat_s(column_names, max_len, temp_column_name));
        is_first = GS_FALSE;
    } while (GS_TRUE);

    return GS_SUCCESS;
}

static status_t exp_get_subpartition_cols(exp_get_partition_param_t *exp_partition_param, char *column_names,
                                          size_t max_len)
{
    uint32 rows;
    char temp_column_name[MAX_COLUMN_WIDTH] = { 0 };
    char cmd_buf[GSQL_MAX_TEMP_SQL + 1];

    PRTS_RETURN_IFERR(sprintf_s(cmd_buf, GSQL_MAX_TEMP_SQL,
        "SELECT COLUMN_NAME "
        "FROM %s "
        "WHERE OWNER = UPPER('%s') AND NAME = '%s' AND OBJECT_TYPE = 'TABLE' "
        "ORDER BY COLUMN_POSITION",
        exp_tabname(exp_partition_param->consistent, EXP_TABAGENT_DB_SUBPART_KEY_COLUMNS),
        exp_partition_param->user_name, exp_partition_param->table_name));

    GS_RETURN_IFERR(gsc_prepare(STMT, (const char *)cmd_buf));
    GS_RETURN_IFERR(gsc_execute(STMT));

    bool8 is_first = GS_TRUE;
    do {
        GS_RETURN_IFERR(gsc_fetch(STMT, &rows));
        if (rows == 0) {
            break;
        }
        GS_RETURN_IFERR(gsc_column_as_string(STMT, 0, temp_column_name, MAX_COLUMN_WIDTH));
        if (!is_first) {
            MEMS_RETURN_IFERR(strcat_s(column_names, max_len, ","));
        }

        MEMS_RETURN_IFERR(strcat_s(column_names, max_len, temp_column_name));
        is_first = GS_FALSE;
    } while (GS_TRUE);

    return GS_SUCCESS;
}

static status_t exp_get_partition_storeinfo(exp_get_partition_param_t *exp_partition_param, char *storeinfo,
                                            size_t max_len)
{
    uint32 rows;
    char temp_storeinfo[MAX_COLUMN_WIDTH] = { 0 };
    char cmd_buf[GSQL_MAX_TEMP_SQL + 1];

    PRTS_RETURN_IFERR(sprintf_s(cmd_buf, GSQL_MAX_TEMP_SQL,
        "SELECT TABLESPACE_NAME FROM  %s Z "
        "WHERE Z.OWNER = UPPER('%s') AND Z.NAME = '%s' "
        " AND OBJECT_TYPE = 'TABLE'  ORDER BY POSITION",
        exp_tabname(exp_partition_param->consistent, EXP_TABAGENT_DB_PART_STORE),
        exp_partition_param->user_name, exp_partition_param->table_name));

    GS_RETURN_IFERR(gsc_prepare(STMT, (const char *)cmd_buf));
    GS_RETURN_IFERR(gsc_execute(STMT));

    bool8 is_first = GS_TRUE;
    do {
        GS_RETURN_IFERR(gsc_fetch(STMT, &rows));
        if (rows == 0) {
            break;
        }
        GS_RETURN_IFERR(gsc_column_as_string(STMT, 0, temp_storeinfo, MAX_COLUMN_WIDTH));
        if (!is_first) {
            MEMS_RETURN_IFERR(strcat_s(storeinfo, max_len, ","));
        }
        MEMS_RETURN_IFERR(strcat_s(storeinfo, max_len, "TABLESPACE "));
        MEMS_RETURN_IFERR(strcat_s(storeinfo, max_len, temp_storeinfo));
        is_first = GS_FALSE;
    } while (GS_TRUE);

    return GS_SUCCESS;
}

// verify if DB_PART_TABLES has one column named flag which is new added
// notes: flag means the part table is csf or bitmap format
static status_t exp_verify_column_of_part_tables_agent(void)
{
    uint32 rows;
    char cmd_buf[GSQL_MAX_TEMP_SQL + 1];

    int iret_sprintf = sprintf_s(cmd_buf, GSQL_MAX_TEMP_SQL,
        "SELECT COLUMN_NAME FROM " EXP_VIEW_COLS_AGENT
        " WHERE VIEW_NAME = 'DB_TAB_PARTITIONS' AND COLUMN_NAME = 'ROW_FORMAT'");
    if (iret_sprintf == -1) {
        EXP_THROW_ERROR(ERR_SYSTEM_CALL, iret_sprintf);
        return GS_ERROR;
    }

    GS_RETURN_IFERR(gsc_prepare(STMT, (const char *)cmd_buf));
    GS_RETURN_IFERR(gsc_execute(STMT));
    GS_RETURN_IFERR(gsc_fetch(STMT, &rows));

    if (rows == 0) {
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

static status_t exp_get_old_partition_key_sql(char *sql_buffer, uint32 buff_size, exp_prepare_sql_param_t *param)
{
    char column_names[MAX_COLUMN_WIDTH] = { 0 };
    char storeinfo[MAX_COLUMN_WIDTH] = { 0 };
    exp_get_partition_param_t *exp_partition_param = (exp_get_partition_param_t *)(&param->get_proc_param);

    GS_RETURN_IFERR(exp_get_partition_cols(exp_partition_param, column_names, MAX_COLUMN_WIDTH));
    GS_RETURN_IFERR(exp_get_partition_storeinfo(exp_partition_param, storeinfo, MAX_COLUMN_WIDTH));

    PRTS_RETURN_IFERR(sprintf_s(sql_buffer, buff_size,
        "SELECT PARTITIONING_TYPE, PARENT_KEY_NAME, REPLACE(PARENT_KEY_NAME, ',', '\", \"'), "
        " INTERVAL, STOREINFO, REPLACE(STOREINFO, ',', '\", \"') "
        "FROM ("
        " SELECT X.PARTITIONING_TYPE, X.INTERVAL, "
        "  '%s' PARENT_KEY_NAME, "
        "  '%s' STOREINFO "
        " FROM %s X "
        " WHERE X.OWNER = UPPER('%s') AND X.TABLE_NAME = '%s' "
        " )", column_names, storeinfo,
        exp_tabname(exp_partition_param->consistent, EXP_TABAGENT_DB_PART_TABLES),
        exp_partition_param->user_name, exp_partition_param->table_name));

    return GS_SUCCESS;
}

static status_t exp_get_new_partition_key_sql(char *sql_buffer, uint32 buff_size, exp_prepare_sql_param_t *param)
{
    char parent_key_names[MAX_COLUMN_WIDTH] = { 0 };
    char sub_key_names[MAX_COLUMN_WIDTH] = { 0 };
    char storeinfo[MAX_COLUMN_WIDTH] = { 0 };
    exp_get_partition_param_t *exp_partition_param = (exp_get_partition_param_t *)(&param->get_proc_param);

    GS_RETURN_IFERR(exp_get_partition_cols(exp_partition_param, parent_key_names, MAX_COLUMN_WIDTH));
    GS_RETURN_IFERR(exp_get_partition_storeinfo(exp_partition_param, storeinfo, MAX_COLUMN_WIDTH));
    GS_RETURN_IFERR(exp_get_subpartition_cols(exp_partition_param, sub_key_names, MAX_COLUMN_WIDTH));

    PRTS_RETURN_IFERR(sprintf_s(sql_buffer, buff_size,
        "SELECT PARTITIONING_TYPE, PARENT_KEY_NAME, REPLACE(PARENT_KEY_NAME, ',', '\", \"'), "
        " INTERVAL, STOREINFO, REPLACE(STOREINFO, ',', '\", \"'), "
        " SUBPARTITION_TYPE, SUB_KEY_NAME, REPLACE(SUB_KEY_NAME, ',', '\", \"') "
        "FROM ( "
        " SELECT X.PARTITIONING_TYPE, X.PARTITION_COUNT, X.INTERVAL, X.SUBPARTITION_TYPE, "
        "  '%s' PARENT_KEY_NAME, "
        "  '%s' STOREINFO, "
        "  '%s' SUB_KEY_NAME "
        " FROM %s X "
        " WHERE X.OWNER = UPPER('%s') AND X.TABLE_NAME = '%s' "
        " )", parent_key_names, storeinfo, sub_key_names,
        exp_tabname(exp_partition_param->consistent, EXP_TABAGENT_DB_PART_TABLES),
        exp_partition_param->user_name, exp_partition_param->table_name));

    return GS_SUCCESS;
}

static status_t exp_get_partition_value_sql(char *sql_buffer, uint32 buff_size, exp_prepare_sql_param_t *param)
{
    exp_get_partition_param_t *exp_partition_param = (exp_get_partition_param_t *)(&param->get_proc_param);

    PRTS_RETURN_IFERR(sprintf_s(sql_buffer, buff_size,
        "SELECT X.PARTITION_NAME, X.HIGH_VALUE, X.TABLESPACE_NAME, X.INI_TRANS, X.PCT_FREE %s %s "
        " FROM %s X "
        " WHERE X.TABLE_OWNER = UPPER('%s') AND X.TABLE_NAME = '%s' AND X.INTERVAL = 'N' "
        " ORDER BY X.PARTITION_POSITION ",
        exp_partition_param->db_tab_partitions_has_flag ? ", X.ROW_FORMAT" : " ",
        (gsc_get_call_version(CONN) >= CS_VERSION_22) ? ", X.COMPRESS_ALGO" : " ",
        exp_tabname(exp_partition_param->consistent, EXP_TABAGENT_DB_TAB_PARTITIONS),
        exp_partition_param->user_name, exp_partition_param->table_name));

    return GS_SUCCESS;
}

static status_t exp_get_subpartition_value_sql(char *sql_buffer, uint32 buff_size, exp_prepare_sql_param_t *param)
{
    exp_get_partition_param_t *exp_partition_param = (exp_get_partition_param_t *)(&param->get_proc_param);

    PRTS_RETURN_IFERR(sprintf_s(sql_buffer, buff_size,
        "SELECT X.PARTITION_NAME, X.HIGH_VALUE, X.TABLESPACE_NAME, "
        "X.INI_TRANS, X.PCT_FREE %s %s, Z.SUB_PARTITION_VALUE "
        " FROM %s X, "
        " ( "
        "  SELECT DISTINCT(Y.PARENTPART_NAME), "
        "   GROUP_CONCAT(Y.SUB_PARTITION_STRING ORDER BY Y.PARTITION_POSITION ASC SEPARATOR ', \n        ')  "
        "   SUB_PARTITION_VALUE "
        "  FROM "
        "   (SELECT DISTINCT(O.PARTITION_NAME), O.PARENTPART_NAME, O.PARTITION_POSITION, 'SUBPARTITION ' || O.PARTITION_NAME || "
        "      CASE WHEN P.SUBPARTITION_TYPE = 'RANGE' THEN ' VALUES LESS THAN (' || O.HIGH_VALUE || ')' "
        "      WHEN P.SUBPARTITION_TYPE = 'LIST' THEN ' VALUES(' || O.HIGH_VALUE || ')' END || "
        "      ' TABLESPACE \"' || O.TABLESPACE_NAME || '\"' SUB_PARTITION_STRING "
        "    FROM %s O, %s P "
        "    WHERE O.TABLE_OWNER = UPPER('%s') AND O.TABLE_NAME = '%s' AND "
        "          O.TABLE_OWNER = P.OWNER AND O.TABLE_NAME = P.TABLE_NAME "
        "    ORDER BY O.PARENTPART_NAME ASC, O.PARTITION_NAME ASC, O.PARTITION_POSITION ASC "
        "    ) Y "
        "    GROUP BY Y.PARENTPART_NAME ORDER BY Y.PARENTPART_NAME "
        " ) Z "
        " WHERE X.TABLE_OWNER = UPPER('%s') AND X.TABLE_NAME = '%s' "
        " AND X.INTERVAL = 'N' AND X.PARTITION_NAME = Z.PARENTPART_NAME "
        " ORDER BY X.PARTITION_POSITION ",
        exp_partition_param->db_tab_partitions_has_flag ? ", X.ROW_FORMAT" : " ",
        (gsc_get_call_version(CONN) >= CS_VERSION_22) ? ", X.COMPRESS_ALGO" : " ",
        exp_tabname(exp_partition_param->consistent, EXP_TABAGENT_DB_TAB_PARTITIONS),
        exp_tabname(exp_partition_param->consistent, EXP_TABAGENT_DB_TAB_SUBPARTITIONS),
        exp_tabname(exp_partition_param->consistent, EXP_TABAGENT_DB_PART_TABLES),
        exp_partition_param->user_name,
        exp_partition_param->table_name, exp_partition_param->user_name, exp_partition_param->table_name));

    return GS_SUCCESS;
}

static status_t exp_append_users(char *sql_buffer, uint32 buff_size, list_t *user_list)
{
    char *user = NULL;

    for (uint32 i = 0; i < user_list->count; i++) {
        if (i > 0) {
            MEMS_RETURN_IFERR(strcat_s(sql_buffer, buff_size, ", "));
        }

        user = (char *)cm_list_get(user_list, i);
        MEMS_RETURN_IFERR(strcat_s(sql_buffer, buff_size, "UPPER('"));
        MEMS_RETURN_IFERR(strcat_s(sql_buffer, buff_size, user));
        MEMS_RETURN_IFERR(strcat_s(sql_buffer, buff_size, "')"));
    }
    return GS_SUCCESS;
}

static status_t exp_get_roles_sql(char *sql_buffer, uint32 buff_size, exp_prepare_sql_param_t *param)
{
    exp_get_roles_param_t *get_roles_param = (exp_get_roles_param_t *)(&param->get_role_param);

    if (get_roles_param->exp_opts->exp_type == EXP_ALL_SCHEMAS) {
        PRTS_RETURN_IFERR(sprintf_s(sql_buffer, buff_size,
            "SELECT 'CREATE ROLE \"' || NAME || '\"' || IF(LENGTH(PASSWORD) = 0 ,'', ' IDENTIFIED BY ''' || PASSWORD || '''' || ' ENCRYPTED') || ';' FROM SYS.SYS_ROLES "
            "WHERE NAME IN (SELECT GRANTED_ROLE FROM ADM_ROLE_PRIVS WHERE GRANTEE in (SELECT USERNAME FROM DB_USERS WHERE USERNAME <> 'SYS' AND USERNAME <> 'PUBLIC') "
            "AND GRANTED_ROLE NOT IN ('DBA','RESOURCE','CONNECT')) OR "
            "OWNER_UID IN (SELECT USER_ID FROM DB_USERS WHERE USERNAME NOT IN('SYS','PUBLIC')) ORDER BY NAME "));
    } else {
        PRTS_RETURN_IFERR(sprintf_s(sql_buffer, buff_size,
            "SELECT 'CREATE ROLE \"' || NAME || '\"' || IF(LENGTH(PASSWORD) = 0 ,'', ' IDENTIFIED BY ''' || PASSWORD || '''' || ' ENCRYPTED') || ';' FROM SYS.SYS_ROLES "
            "WHERE NAME IN (SELECT GRANTED_ROLE FROM ADM_ROLE_PRIVS WHERE GRANTEE in ("));

        GS_RETURN_IFERR(exp_append_users(sql_buffer, buff_size, &get_roles_param->exp_opts->obj_list));

        MEMS_RETURN_IFERR(strcat_s(sql_buffer, buff_size,
            ")  AND GRANTED_ROLE NOT IN ('DBA','RESOURCE','CONNECT')) OR "
            "OWNER_UID IN(SELECT USER_ID FROM DB_USERS WHERE USERNAME IN("));
        
        GS_RETURN_IFERR(exp_append_users(sql_buffer, buff_size, &get_roles_param->exp_opts->obj_list));

        MEMS_RETURN_IFERR(strcat_s(sql_buffer, buff_size, ")) ORDER BY NAME"));
    }

    return GS_SUCCESS;
}

static status_t exp_get_user_synonyms_sql(char *sql_buffer, uint32 buff_size, exp_prepare_sql_param_t *param)
{
    exp_get_synonyms_param_t *get_synonym_param = (exp_get_synonyms_param_t *)(&param->get_synonym_param);

    PRTS_RETURN_IFERR(sprintf_s(sql_buffer, buff_size,
        "(SELECT 'CREATE OR REPLACE SYNONYM \"' || SYNONYM_NAME || '\" FOR \"' || TABLE_NAME || '\"' FROM "
        "DB_SYNONYMS WHERE OWNER = '%s' AND TABLE_OWNER = '%s' ORDER BY SYNONYM_NAME) ",
        get_synonym_param->user_name, get_synonym_param->user_name));

    return GS_SUCCESS;
}

static status_t exp_get_user_profile_sql(char *sql_buffer, uint32 buff_size, exp_prepare_sql_param_t *param)
{
    exp_get_profile_param_t *get_profile_param = (exp_get_profile_param_t *)(&param->get_profile_param);

    PRTS_RETURN_IFERR(sprintf_s(sql_buffer, buff_size,
        "SELECT 'CREATE OR REPLACE PROFILE \"' || PROFILE || '\" LIMIT ' || "
        "GROUP_CONCAT(CONCAT_WS(' ', RESOURCE_NAME, THRESHOLD) "
        "ORDER BY RESOURCE_NAME SEPARATOR ' ') FROM DB_PROFILES WHERE OWNER = '%s' "
        "AND PROFILE NOT IN ('DEFAULT','SHARDING_DBA') GROUP BY PROFILE",
        get_profile_param->user_name));

    return GS_SUCCESS;
}

static status_t exp_get_user_package_sql(char *sql_buffer, uint32 buff_size, exp_prepare_sql_param_t *param)
{
    exp_get_package_param_t *get_package_param = (exp_get_package_param_t *)(&param->get_package_param);
    PRTS_RETURN_IFERR(sprintf_s(sql_buffer, buff_size,
        "(SELECT 'CREATE OR REPLACE PACKAGE \"' || P.OBJECT_NAME || '\" ' || P.SOURCE "
        "FROM DB_PROCEDURES P, DB_OBJECTS O "
        "WHERE P.OWNER = '%s' AND P.OBJECT_TYPE = 'PACKAGE SPEC' AND P.OBJECT_NAME = O.OBJECT_NAME AND "
        "P.OBJECT_TYPE = O.OBJECT_TYPE AND P.OWNER = O.OWNER ORDER BY O.CREATED ASC, P.OBJECT_NAME ASC) "
        "UNION ALL "
        "(SELECT 'CREATE OR REPLACE PACKAGE BODY \"' || P.OBJECT_NAME || '\" ' || P.SOURCE "
        "FROM DB_PROCEDURES P, DB_OBJECTS O "
        "WHERE P.OWNER = '%s' AND P.OBJECT_TYPE = 'PACKAGE BODY' AND P.OBJECT_NAME = O.OBJECT_NAME "
        "AND P.OBJECT_TYPE = O.OBJECT_TYPE AND P.OWNER = O.OWNER ORDER BY O.CREATED ASC, P.OBJECT_NAME ASC) ",
        get_package_param->user_name, get_package_param->user_name));

    return GS_SUCCESS;
}

static status_t exp_get_user_type_sql(char *sql_buffer, uint32 buff_size, exp_prepare_sql_param_t *param)
{
    exp_get_type_param_t *get_type_param = (exp_get_type_param_t *)(&param->get_type_param);
    PRTS_RETURN_IFERR(sprintf_s(sql_buffer, buff_size,
        "SELECT 'CREATE OR REPLACE TYPE \"' || P.OBJECT_NAME || '\" FORCE ' || P.SOURCE "
        "FROM DB_PROCEDURES P, DB_OBJECTS O "
        "WHERE P.OWNER = '%s' AND P.OBJECT_TYPE = 'TYPE SPEC' AND P.OBJECT_NAME = O.OBJECT_NAME "
        "AND P.OBJECT_TYPE = O.OBJECT_TYPE AND P.OWNER = O.OWNER "
        "ORDER BY O.CREATED ASC, P.OBJECT_NAME ASC ", get_type_param->user_name));
    return GS_SUCCESS;
}

status_t list2str(list_t *obj_list, char *obj_str, uint32 obj_len)
{
    uint32 tmp_len = 0;
    char *ptr = NULL;
    uint32 ptr_len = 0;

    if (obj_str == NULL) {
        return GS_ERROR;
    }

    for (uint32 i = 0; i < obj_list->count; i++) {
        ptr = (char *)cm_list_get(obj_list, i);
        ptr_len = (uint32)strlen(ptr);
        // obj_str is expected to link together like 'A','B','C'
        if (obj_len < tmp_len + ptr_len + 3) {
            return GS_ERROR;
        }

        obj_str[tmp_len] = '\'';
        tmp_len++;
        MEMS_EXP_RETURN_IFERR(strncpy_s(obj_str + tmp_len, obj_len - tmp_len, ptr, ptr_len));
        tmp_len += ptr_len;
        obj_str[tmp_len] = '\'';
        tmp_len++;

        if (i != obj_list->count - 1) {
            obj_str[tmp_len] = ',';
            tmp_len++;
        }
    }

    obj_str[tmp_len] = '\0';
    return GS_SUCCESS;
}

static status_t exp_get_user_tables_sql(char *sql_buffer, uint32 buff_size, exp_prepare_sql_param_t *param)
{
    export_options_t *exp_opts = param->comm_param.exp_opts;
    char tbs_name[GSQL_MAX_TEMP_SQL + 1] = { 0 };
    text_t *exclude_cond = NULL;

    PRTS_RETURN_IFERR(sprintf_s(sql_buffer, buff_size, "SELECT TABLE_NAME FROM %s ",
        exp_tabname(exp_opts->consistent, EXP_TABAGENT_DB_TABLES)));

    PRTS_RETURN_IFERR(sprintf_s(sql_buffer + strlen(sql_buffer), buff_size - strlen(sql_buffer),
        "WHERE OWNER = UPPER(:OWNER) "));

    if (exp_opts->tbs_list.count > 0) {
        GS_RETURN_IFERR(list2str(&exp_opts->tbs_list, tbs_name, GSQL_MAX_TEMP_SQL + 1));
        PRTS_RETURN_IFERR(sprintf_s(sql_buffer + strlen(sql_buffer), buff_size - strlen(sql_buffer),
            "AND TABLESPACE_NAME IN(%s) ", tbs_name));
    }

    GS_RETURN_IFERR(exp_get_exclude_cond(EXP_EXCLUDE_TABLE, exp_opts, &exclude_cond));
    if (exclude_cond != NULL) {
        PRTS_RETURN_IFERR(sprintf_s(sql_buffer + strlen(sql_buffer), buff_size - strlen(sql_buffer),
            "AND TABLE_NAME NOT IN (SELECT TABLE_NAME FROM %s WHERE TABLE_NAME %.*s) ",
            exp_tabname(exp_opts->consistent, EXP_TABAGENT_DB_TABLES),
            exclude_cond->len, exclude_cond->str));
    }

    PRTS_RETURN_IFERR(sprintf_s(sql_buffer + strlen(sql_buffer), buff_size - strlen(sql_buffer),
        "ORDER BY CREATED_TIME, TABLE_ID"));
    return GS_SUCCESS;
}

// each prepare SQL function can transfer it's control parameter by using 'param'
typedef status_t(*exp_prepare_sql_func_t)(char *sql_buffer, uint32 buff_size, exp_prepare_sql_param_t *param);

typedef enum en_exp_sql_id_t {
    EXP_GET_USER_VIEW_LIST = 0,
    EXP_GET_USER_PROC_LIST = 1,
    EXP_GET_ROLE_LIST = 2,
    EXP_GET_USER_SYNONYM_LIST = 3,
    EXP_GET_USER_PROFILE_LIST = 4,
    EXP_GET_USER_PACKAGE_LIST = 5,
    EXP_GET_USER_TYPE_LIST = 6,
    EXP_GET_USER_TABLE_LIST = 7,
    EXP_GET_USER_TRIGGERS_LIST = 8,
    EXP_GET_TABLE_OLD_PARTITION_KEY = 9,
    EXP_GET_TABLE_NEW_PARTITION_KEY = 10,
    EXP_GET_TABLE_PARTITION_VALUE = 11,
    EXP_GET_TABLE_SUBPARTITION_VALUE = 12,
    EXP_GET_DB_TABLES_LIST = 13,
    EXP_GET_DB_LOB_STORAGE = 14
} exp_sql_id_t;

exp_prepare_sql_func_t g_exp_sql_funcs[] = {
    exp_get_user_views_sql,
    exp_get_user_procs_sql,
    exp_get_roles_sql,
    exp_get_user_synonyms_sql,
    exp_get_user_profile_sql,
    exp_get_user_package_sql,
    exp_get_user_type_sql,
    exp_get_user_tables_sql,
    exp_get_user_triggers_sql,
    exp_get_old_partition_key_sql,
    exp_get_new_partition_key_sql,
    exp_get_partition_value_sql,
    exp_get_subpartition_value_sql,
    exp_get_db_tables_sql,
    exp_get_db_lob_storage_sql
};

#define EXP_PREPARE_SQL(sql_id, buffer, size, param) g_exp_sql_funcs[sql_id](buffer, size, param)

static inline void exp_create_objlist(list_t *objlist, uint32 item_size)
{
    // the list can accommodate EXP_MAX_OBJECTS objects
    cm_create_list2(objlist, LIST_EXTENT_SIZE, EXP_MAX_OBJECTS / LIST_EXTENT_SIZE, item_size);
}

static status_t get_current_scn(gsc_stmt_t stmt, uint64 *scn)
{
    char *get_par_sql = NULL;
    uint32 rows, size, is_null;
    void *data = NULL;
    int iret_sprintf;

    get_par_sql = (char *)malloc(GSQL_MAX_TEMP_SQL);
    if (get_par_sql == NULL) {
        GSQL_PRINTF(ZSERR_EXPORT, "malloc databuf failed!");
        return GS_ERROR;
    }

    iret_sprintf = sprintf_s(get_par_sql, GSQL_MAX_TEMP_SQL, "SELECT CURRENT_SCN FROM DV_DATABASE");
    if (iret_sprintf == -1) {
        CM_FREE_PTR(get_par_sql);
        EXP_THROW_ERROR(ERR_SYSTEM_CALL, iret_sprintf);
        return GS_ERROR;
    }

    if (gsc_prepare(stmt, get_par_sql) != GS_SUCCESS) {
        CM_FREE_PTR(get_par_sql);
        return GS_ERROR;
    }

    if (gsc_execute(stmt) != GS_SUCCESS) {
        CM_FREE_PTR(get_par_sql);
        return GS_ERROR;
    }

    do {
        if (gsc_fetch(stmt, &rows) != GS_SUCCESS) {
            CM_FREE_PTR(get_par_sql);
            return GS_ERROR;
        }

        if (rows == 0) {
            break;
        }

        if (gsc_get_column_by_id(stmt, 0, (void **)&data, &size, &is_null) != GS_SUCCESS) {
            CM_FREE_PTR(get_par_sql);
            return GS_ERROR;
        }

        *scn = *(uint64 *)data;
    } while (GS_TRUE);

    CM_FREE_PTR(get_par_sql);
    return GS_SUCCESS;
}

static status_t get_current_scn_core(export_options_t *exp_opts, uint64 *scn)
{
        return get_current_scn(STMT, scn);
}

static status_t exp_init_scn(export_options_t *exp_opts)
{
    if (exp_opts->consistent || exp_opts->parallel > 1 || exp_opts->filetype == FT_BIN) {
        if (get_current_scn_core(exp_opts, &g_exp_scn) != GS_SUCCESS) {
            EXP_THROW_ERROR(ERR_INSUFFICIENT_PRIV);
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

void exp_trim_filename(const char *file_name, uint32 size, char *buf)
{
    cm_trim_filename(file_name, size, buf);
    if (cm_str_equal(file_name, buf)) {
        buf[0] = '\0';
    }
}

static inline bool32 par_exp_get_init_cols(par_exp_thread_ctrl_t *ctrl)
{
    return ctrl->cols_def->init_cols;
}

static inline void par_exp_set_init_cols(par_exp_thread_ctrl_t *ctrl, bool32 flag)
{
    ctrl->cols_def->init_cols = flag;
}

void par_exp_init_thread_ctrl(par_exp_thread_ctrl_t *ctrl, export_options_t *opts, uint32 thread_no)
{
    ctrl->options = *opts;
    ctrl->thread_no = thread_no;
    ctrl->execute_ret = GS_SUCCESS;
    ctrl->stat = PAR_EXP_IDLE;
    ctrl->bin_rec_total_add = NULL;

    ctrl->files_context.exp_dpfile = NULL;
    ctrl->files_context.exp_txtbuf.str = NULL;
    ctrl->files_context.sql_buf = NULL;
    ctrl->files_context.str_buf = NULL;
    ctrl->files_context.exp_txtbuf.len = 0;
    ctrl->files_context.exp_txtbuf.max_size = 0;
    ctrl->files_context.lf_h = NULL;
    ctrl->files_context.bin_lob_buf.len = 0;
    ctrl->files_context.bin_lob_buf.str = NULL;
    ctrl->files_context.bin_lob_buf.max_size = 0;
    ctrl->files_context.lob_buf.len = 0;
    ctrl->files_context.lob_buf.str = NULL;
    ctrl->files_context.lob_buf.max_size = 0;

    ctrl->conn_info = g_conn_info;
    ctrl->conn_info.connect_by_install_user = g_conn_info.connect_by_install_user;
    ctrl->conn_info.conn = NULL;
    ctrl->conn_info.stmt = NULL;

    cm_create_list(&ctrl->exp_files, EXP_LOB_MAX_FILE_NAME_LEN);
}

static int32 exp_generate_filename(const char *tabname, const char *user, char *outname, uint32 max_size)
{
    char buf[GS_FILE_NAME_BUFFER_SIZE];
    char bin_buf[EXP_LOB_MAX_FILE_NAME_LEN2 + 1];

    text_t text;
    binary_t bin;

    uint32 file_no = g_file_no++;
    timestamp_t ts = cm_now();

    int ret_len = sprintf_s(buf, GS_FILE_NAME_BUFFER_SIZE, "%s%u%s%I64d", user, file_no, tabname, ts);
    PRTS_RETURN_IFERR(ret_len);

    *(uint64 *)&bin_buf[0] = ((uint64)cm_hash_raw((uint8 *)buf, ret_len) << 40) + (uint64)ts;  // restrict file name length
    *(uint16 *)&bin_buf[8] = (uint16)file_no;

    bin.bytes = (uint8 *)bin_buf;
    bin.size = 10;  // 10 byte length used for generating filename

    text.str = outname;
    text.len = max_size;

    GS_RETURN_IFERR(cm_bin2text(&bin, GS_FALSE, &text));

    CM_NULL_TERM(&text);

    return GS_SUCCESS;
}

static int32 exp_form_fullpath(const char *filepath, const char *filename, char *fullpath, uint32 max_path_len)
{
    char pathbuf[GS_MAX_FILE_PATH_LENGH];

    PRTS_RETURN_IFERR(sprintf_s(pathbuf, GS_MAX_FILE_PATH_LENGH, "%s%s",  filepath, filename));
    GS_RETURN_IFERR(realpath_file(pathbuf, fullpath, max_path_len));

    return GS_SUCCESS;
}

int par_exp_rename_file(par_exp_thread_ctrl_t *ctrl)
{
    char fname[EXP_LOB_MAX_FILE_NAME_LEN2 + 1];

    GS_RETURN_IFERR(exp_generate_filename(ctrl->tab_param.tab_name, ctrl->tab_param.schema, fname,
        EXP_LOB_MAX_FILE_NAME_LEN2));

    PRTS_RETURN_IFERR(sprintf_s(ctrl->options.bin_data_file, EXP_LOB_MAX_FILE_NAME_LEN, "_%s.D", fname));
    PRTS_RETURN_IFERR(sprintf_s(ctrl->options.lob_file_name, EXP_LOB_MAX_FILE_NAME_LEN, "_%s.L", fname));

    return GS_SUCCESS;
}

int par_exp_save_filenname(par_exp_thread_ctrl_t *ctrl, list_t *files)
{
    char *buf = NULL;
    const char *filename = ctrl->options.bin_data_file;

    GS_RETURN_IFERR(cm_list_new(files, (void **)&buf));
    PRTS_RETURN_IFERR(sprintf_s(buf, EXP_LOB_MAX_FILE_NAME_LEN, "%s", filename));
    return GS_SUCCESS;
}

status_t gsql_exp_generate_encrypt_info(crypt_info_t *crypt_info, char *file_name, uint32 max_len, int32 fp)
{
    crypt_file_t *encrypt_ctx = NULL;

    GS_RETURN_IFERR(cm_list_new(&crypt_info->crypt_list, (void *)&encrypt_ctx));
    GS_RETURN_IFERR(gsql_encrypt_prepare(&encrypt_ctx->crypt_ctx, crypt_info->crypt_pwd));
    MEMS_RETURN_IFERR(strncpy_s(encrypt_ctx->filename, GS_MAX_NAME_LEN, file_name, max_len));
    encrypt_ctx->fp = fp;
    return GS_SUCCESS;
}

status_t par_exp_dispatch_bin(par_exp_thread_ctrl_t *ctrl, char *path)
{
    if (ctrl->files_context.exp_dpfile != NULL) {
        if (g_export_opts.compress) {
            (void)gsc_common_z_uninit_write(&ctrl->files_context.df_zstream);
        }
        fclose(ctrl->files_context.exp_dpfile);
        ctrl->files_context.exp_dpfile = NULL;
    }

    GS_RETURN_IFERR(cm_fopen(path, "wb+", FILE_PERM_OF_DATA, &ctrl->files_context.exp_dpfile));

    if (g_export_opts.crypt_info.crypt_flag) {
        GS_RETURN_IFERR(gsql_exp_generate_encrypt_info(&g_export_opts.crypt_info, ctrl->options.bin_data_file,
            EXP_LOB_MAX_FILE_NAME_LEN, cm_fileno(ctrl->files_context.exp_dpfile)));
    }

    if (g_export_opts.compress &&
        gsc_common_z_init_write(ctrl->files_context.exp_dpfile, &ctrl->files_context.df_zstream,
            g_export_opts.compress_level) != GS_SUCCESS) {
        GSQL_PRINTF(ZSERR_EXPORT, "init compress file '%s' failed.\n", path);
        return GS_ERROR;
    }

    if (ctrl->files_context.lf_h != NULL) {
        if (g_export_opts.compress) {
            (void)gsc_common_z_uninit_write(&ctrl->files_context.lf_zstream);
        }
        fclose(ctrl->files_context.lf_h);
        ctrl->files_context.lf_h = NULL;
    }

    GS_RETURN_IFERR(exp_form_fullpath(ctrl->options.dump_data_path, ctrl->options.lob_file_name, path,
        GS_MAX_FILE_PATH_LENGH));
    GS_RETURN_IFERR(cm_fopen(path, "wb+", FILE_PERM_OF_DATA, &ctrl->files_context.lf_h));

    if (g_export_opts.crypt_info.crypt_flag) {
        GS_RETURN_IFERR(gsql_exp_generate_encrypt_info(&g_export_opts.crypt_info, ctrl->options.lob_file_name,
            EXP_LOB_MAX_FILE_NAME_LEN, cm_fileno(ctrl->files_context.lf_h)));
    }

    if (g_export_opts.compress &&
        gsc_common_z_init_write(ctrl->files_context.lf_h, &ctrl->files_context.lf_zstream,
            g_export_opts.compress_level) != GS_SUCCESS) {
        GSQL_PRINTF(ZSERR_EXPORT, "init compress file '%s' failed.\n", path);
        return GS_ERROR;
    }

    if (ctrl->files_context.bin_lob_buf.str == NULL) {
        ctrl->files_context.bin_lob_buf.str = (char *)malloc(EXP_MAX_LOB_FILE_BUF);
        if (ctrl->files_context.bin_lob_buf.str == NULL) {
            EXP_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)EXP_MAX_LOB_FILE_BUF,
                "func: par_exp_dispatch alloc lob file buffer");
            return GS_ERROR;
        }

        MEMS_RETURN_IFERR(memset_s(ctrl->files_context.bin_lob_buf.str, EXP_MAX_LOB_FILE_BUF, 0, EXP_MAX_LOB_FILE_BUF));
    }
    ctrl->files_context.bin_lob_buf.len = 0;
    ctrl->files_context.bin_lob_buf.max_size = EXP_MAX_LOB_FILE_BUF;

    if (ctrl->files_context.lob_buf.str == NULL) {
        ctrl->files_context.lob_buf.str = (char *)malloc(MAX_EXP_LOB_BUFF_SIZE);
        if (ctrl->files_context.lob_buf.str == NULL) {
            EXP_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)MAX_EXP_LOB_BUFF_SIZE,
                "func: par_exp_dispatch alloc lob buffer");
            return GS_ERROR;
        }

        MEMS_RETURN_IFERR(memset_s(ctrl->files_context.lob_buf.str, MAX_EXP_LOB_BUFF_SIZE, 0, MAX_EXP_LOB_BUFF_SIZE));
    }

    ctrl->files_context.lob_buf.len = 0;
    ctrl->files_context.lob_buf.max_size = MAX_EXP_LOB_BUFF_SIZE;

    return GS_SUCCESS;
}

status_t par_exp_dispatch(par_exp_thread_ctrl_t *ctrl, par_exp_param_t *param, uint64 *total_addr,
    exp_cols_t *exp_cols)
{
    char path[GS_MAX_FILE_PATH_LENGH] = { 0x00 };
    ctrl->tab_param = *param;
    ctrl->cols_def = exp_cols;
    ctrl->bin_rec_total_add = total_addr;

    // create export file handle
    if (ctrl->files_context.exp_txtbuf.str == NULL) {
        ctrl->files_context.exp_txtbuf.str = (char *)malloc(EXP_MAX_FILE_BUF);
        if (ctrl->files_context.exp_txtbuf.str == NULL) {
            EXP_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)EXP_MAX_FILE_BUF, "func: par_exp_dispatch");
            return GS_ERROR;
        }

        MEMS_RETURN_IFERR(memset_s(ctrl->files_context.exp_txtbuf.str, EXP_MAX_FILE_BUF, 0, EXP_MAX_FILE_BUF));
    }
    ctrl->files_context.exp_txtbuf.len = 0;
    ctrl->files_context.exp_txtbuf.max_size = EXP_MAX_FILE_BUF;

    GS_RETURN_IFERR(par_exp_rename_file(ctrl));

    GS_RETURN_IFERR(exp_form_fullpath(ctrl->options.dump_data_path, ctrl->options.bin_data_file, path,
        GS_MAX_FILE_PATH_LENGH));
    if (g_export_opts.filetype == FT_TXT) {
        if (ctrl->files_context.exp_dpfile != NULL) {
            fclose(ctrl->files_context.exp_dpfile);
            ctrl->files_context.exp_dpfile = NULL;
        }

        GS_RETURN_IFERR(cm_fopen(path, "w+", FILE_PERM_OF_DATA, &ctrl->files_context.exp_dpfile));

        if (g_export_opts.crypt_info.crypt_flag) {
            GS_RETURN_IFERR(gsql_exp_generate_encrypt_info(&g_export_opts.crypt_info, ctrl->options.bin_data_file,
                EXP_LOB_MAX_FILE_NAME_LEN, cm_fileno(ctrl->files_context.exp_dpfile)));
        }
    } else {
        GS_RETURN_IFERR(par_exp_dispatch_bin(ctrl, (char *)path));
    }

    if (ctrl->files_context.sql_buf == NULL) {
        ctrl->files_context.sql_buf = (char *)malloc(MAX_SQL_SIZE + 4);
        if (ctrl->files_context.sql_buf == NULL) {
            EXP_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)MAX_SQL_SIZE + 4, "func: par_exp_dispatch");
            return GS_ERROR;
        }

        MEMS_RETURN_IFERR(memset_s(ctrl->files_context.sql_buf, MAX_SQL_SIZE + 4, 0, MAX_SQL_SIZE + 4));
    }

    if (ctrl->files_context.str_buf == NULL) {
        ctrl->files_context.str_buf = (char *)malloc(GS_MAX_PACKET_SIZE + 1);
        if (ctrl->files_context.str_buf == NULL) {
            EXP_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)GS_MAX_PACKET_SIZE + 1, "func: par_exp_dispatch");
            return GS_ERROR;
        }

        MEMS_RETURN_IFERR(memset_s(ctrl->files_context.str_buf, GS_MAX_PACKET_SIZE + 1, 0, GS_MAX_PACKET_SIZE + 1));
    }

    // change stat after finish all setting
    ctrl->stat = PAR_EXP_PROC;

    return GS_SUCCESS;
}

status_t par_exp_dispatch_s(par_exp_thread_ctrl_t *ctrl, par_exp_param_t *param, uint64 *total_addr,
                            exp_cols_t *exp_cols)
{
    status_t ret;

    cm_thread_lock(ctrl->lock_t);
    ret = par_exp_dispatch(ctrl, param, total_addr, exp_cols);
    cm_thread_unlock(ctrl->lock_t);

    return ret;
}

void par_exp_release_thread_ctrl(par_exp_thread_ctrl_t *ctrl)
{
    if (ctrl->files_context.exp_txtbuf.str != NULL) {
        free(ctrl->files_context.exp_txtbuf.str);
        ctrl->files_context.exp_txtbuf.str = NULL;
    }

    if (ctrl->files_context.sql_buf) {
        free(ctrl->files_context.sql_buf);
        ctrl->files_context.sql_buf = NULL;
    }

    if (ctrl->files_context.str_buf) {
        free(ctrl->files_context.str_buf);
        ctrl->files_context.str_buf = NULL;
    }

    if (ctrl->files_context.exp_dpfile != NULL) {
        if (g_export_opts.compress) {
            (void)gsc_common_z_uninit_write(&ctrl->files_context.df_zstream);
        }
        fclose(ctrl->files_context.exp_dpfile);
        ctrl->files_context.exp_dpfile = NULL;
    }

    if (ctrl->conn_info.stmt) {
        gsc_free_stmt(ctrl->conn_info.stmt);
        ctrl->conn_info.stmt = NULL;
    }
    if (ctrl->conn_info.conn) {
        gsc_disconnect(ctrl->conn_info.conn);
        ctrl->conn_info.conn = NULL;
    }

    if (ctrl->files_context.bin_lob_buf.str != NULL) {
        free(ctrl->files_context.bin_lob_buf.str);
        ctrl->files_context.bin_lob_buf.str = NULL;
    }

    if (ctrl->files_context.lob_buf.str != NULL) {
        free(ctrl->files_context.lob_buf.str);
        ctrl->files_context.lob_buf.str = NULL;
    }

    if (ctrl->files_context.lf_h != NULL) {
        fclose(ctrl->files_context.lf_h);
        ctrl->files_context.lf_h = NULL;
    }

    cm_destroy_list(&ctrl->exp_files);
}

void par_exp_set_ctrl_stat(par_exp_thread_ctrl_t *ctrl, exp_proc_status_t proc_stat)
{
    cm_thread_lock(ctrl->lock_t);
    ctrl->stat = proc_stat;
    cm_thread_unlock(ctrl->lock_t);
}

exp_proc_status_t par_exp_get_ctrl_stat(par_exp_thread_ctrl_t *ctrl)
{
    exp_proc_status_t proc_stat;
    cm_thread_lock(ctrl->lock_t);
    proc_stat = ctrl->stat;
    cm_thread_unlock(ctrl->lock_t);

    return proc_stat;
}

void par_exp_stop_all_thread(par_exp_mgr_t *mgr)
{
    uint32 i;

    for (i = 0; i < mgr->options.parallel; i++) {
        cm_close_thread(&mgr->thread_ctrls[i].thread);
        par_exp_release_thread_ctrl(&mgr->thread_ctrls[i]);
    }

    cm_destroy_list(&mgr->tab_par_params);
}

void par_exp_init_mgr(par_exp_mgr_t *mgr, export_options_t *opts)
{
    uint32 i;

    exp_init_exporter(&mgr->exp_cols.exporter);

    cm_init_thread_lock(&mgr->lock_t);
    mgr->options = *opts;
    mgr->tab_par_param_offset = 0;
    for (i = 0; i < mgr->options.parallel; i++) {
        mgr->thread_ctrls[i].lock_t = &mgr->lock_t;
        par_exp_init_thread_ctrl(&mgr->thread_ctrls[i], opts, i);
    }
}

bool32 par_exp_check_thread_stat(par_exp_mgr_t *mgr, exp_par_conn_t* dn_par_conn, int32 *ret)
{
    uint32 i;
    bool32 is_end = GS_TRUE;

    cm_thread_lock(&mgr->lock_t);

    for (i = 0; i < mgr->options.parallel; i++) {
        if (mgr->thread_ctrls[i].execute_ret != GS_SUCCESS) {
            *ret = mgr->thread_ctrls[i].execute_ret;
        }

        if (mgr->thread_ctrls[i].stat == PAR_EXP_PROC) {
            is_end = GS_FALSE;
            continue;
        }

        if (mgr->tab_par_param_offset < mgr->tab_par_params.count) {
            is_end = GS_FALSE;

            if (mgr->par_proc_param.is_coordinator) {
                // Distributing every DN sub conn
                mgr->par_proc_param.conn = dn_par_conn->conn[i];
                mgr->par_proc_param.stmt = dn_par_conn->stmt[i];
            }
            tab_par_param_t *tab_par_param = (tab_par_param_t *)cm_list_get(&mgr->tab_par_params,
                mgr->tab_par_param_offset);
            mgr->par_proc_param.scan_param = *tab_par_param;
            mgr->tab_par_param_offset++;

            (void)par_exp_dispatch(&mgr->thread_ctrls[i], &mgr->par_proc_param, mgr->bin_rec_total_add,
                &mgr->exp_cols);
        }
    }
    cm_thread_unlock(&mgr->lock_t);
    return is_end;
}

static inline void exp_bin_reset_txtbuf(void)
{
    if (g_export_opts.filetype == FT_BIN) {
        g_exp_txtbuf.len = 0;
    }
}

static inline char *exp_bin_write_int64(exp_bin_memory_mgr_t *mem_mgr, uint64 number64)
{
    char *addr = NULL;

    if (g_export_opts.filetype != FT_BIN) {
        return NULL;
    }

    (void)get_mem_address(mem_mgr, &addr, sizeof(uint64));

    if (addr != NULL) {
        *(uint64 *)addr = number64;
    }

    return addr;
}

static inline char *exp_bin_write_int32(exp_bin_memory_mgr_t *mem_mgr, uint32 number32)
{
    char *addr = NULL;

    if (g_export_opts.filetype != FT_BIN) {
        return NULL;
    }

    (void)get_mem_address(mem_mgr, &addr, sizeof(uint32));

    if (addr != NULL) {
        *(uint32 *)addr = number32;
    }

    return addr;
}

static inline char *exp_bin_write_short(exp_bin_memory_mgr_t *mem_mgr, uint16 number16)
{
    char *addr = NULL;

    if (g_export_opts.filetype != FT_BIN) {
        return NULL;
    }

    (void)get_mem_address(mem_mgr, &addr, sizeof(uint16));

    if (addr != NULL) {
        *(uint16 *)addr = number16;
    }

    return addr;
}

static inline status_t exp_bin_write_shortstr(exp_bin_memory_mgr_t *mem_mgr, const char *str, uint16 size)
{
    short_bin_buffer_t bin_buffer;

    if (g_export_opts.filetype != FT_BIN) {
        return GS_SUCCESS;
    }

    GS_RETURN_IFERR(get_short_bin_bufer_addr(mem_mgr, &bin_buffer, size));
    MEMS_RETURN_IFERR(memcpy_s(bin_buffer.buffer, size, str, size));
    return GS_SUCCESS;
}

static inline status_t exp_bin_write_bytes(exp_bin_memory_mgr_t *mem_mgr, const char *str, uint32 size)
{
    char *addr = NULL;

    if (g_export_opts.filetype != FT_BIN) {
        return GS_SUCCESS;
    }

    if (size == 0) {
        GSQL_PRINTF(ZSERR_EXPORT, "no data need to write");
        return GS_ERROR;
    }

    GS_RETURN_IFERR(get_mem_address(mem_mgr, &addr, size));
    MEMS_RETURN_IFERR(memcpy_s(addr, size, str, size));
    return GS_SUCCESS;
}

static status_t exp_bin_write_str(exp_bin_memory_mgr_t *mem_mgr, const char *str, uint32 size)
{
    bin_buffer_t bin_buffer;

    if ((g_export_opts.filetype != FT_BIN) || (size == 0)) {
        return GS_SUCCESS;
    }

    GS_RETURN_IFERR(get_bin_bufer_addr(mem_mgr, &bin_buffer, size));
    MEMS_RETURN_IFERR(memcpy_s(bin_buffer.buffer, size, str, size));
    return GS_SUCCESS;
}

static inline void exp_bin_write_tab_ddl()
{
    char *buf = NULL;

    if (g_export_opts.filetype == FT_TXT) {
        return;
    }

    if (g_exp_txtbuf.len == 0) {
        (void)get_mem_address(&g_export_opts.master_bin_mgr, &buf, sizeof(uint32));

        if (buf != NULL) {
            *(uint32 *)buf = 0;
        }
    } else {
        (void)exp_bin_write_str(&g_export_opts.master_bin_mgr, g_exp_txtbuf.str, g_exp_txtbuf.len);
        exp_bin_reset_txtbuf();
    }
}

static void exp_bin_init_global_file(void)
{
    if (g_exp_dpbinfile != NULL) {
        fclose(g_exp_dpbinfile);
        g_exp_dpbinfile = NULL;
    }

    if (g_lob_binfile != NULL) {
        fclose(g_lob_binfile);
        g_lob_binfile = NULL;
    }
}

static status_t exp_bin_init_data_file(export_options_t *exp_opts, const char *table, const char *user)
{
    if (g_export_opts.filetype == FT_TXT) {
        return GS_SUCCESS;
    }

    char fname[EXP_LOB_MAX_FILE_NAME_LEN2 + 1];
    char file_path_buf[GS_MAX_FILE_PATH_LENGH];

    GS_RETURN_IFERR(exp_generate_filename(table, user, fname, EXP_LOB_MAX_FILE_NAME_LEN2));

    PRTS_RETURN_IFERR(sprintf_s(exp_opts->bin_data_file, EXP_LOB_MAX_FILE_NAME_LEN, "_%s.D",  fname));
    PRTS_RETURN_IFERR(sprintf_s(exp_opts->lob_file_name, EXP_LOB_MAX_FILE_NAME_LEN, "_%s.L", fname));

    exp_bin_init_global_file();

    GS_RETURN_IFERR(exp_form_fullpath(exp_opts->dump_data_path, exp_opts->bin_data_file, file_path_buf,
                                      GS_MAX_FILE_PATH_LENGH));
    
    if (cm_fopen(file_path_buf, "wb+", FILE_PERM_OF_DATA, &g_exp_dpbinfile) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (g_export_opts.crypt_info.crypt_flag) {
        GS_RETURN_IFERR(gsql_exp_generate_encrypt_info(&g_export_opts.crypt_info, exp_opts->bin_data_file,
            EXP_LOB_MAX_FILE_NAME_LEN, cm_fileno(g_exp_dpbinfile)));
    }

    if (exp_opts->compress &&
        gsc_common_z_init_write(g_exp_dpbinfile, &g_df_zstream, exp_opts->compress_level) != GS_SUCCESS) {
        GSQL_PRINTF(ZSERR_EXPORT, "init compress file '%s' failed.\n", file_path_buf);
        return GS_ERROR;
    }

    GS_RETURN_IFERR(exp_form_fullpath(exp_opts->dump_data_path, exp_opts->lob_file_name, file_path_buf,
                                      GS_MAX_FILE_PATH_LENGH));
    
    if (cm_fopen(file_path_buf, "wb+", FILE_PERM_OF_DATA, &g_lob_binfile) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (g_export_opts.crypt_info.crypt_flag) {
        GS_RETURN_IFERR(gsql_exp_generate_encrypt_info(&g_export_opts.crypt_info, exp_opts->lob_file_name,
            EXP_LOB_MAX_FILE_NAME_LEN, cm_fileno(g_lob_binfile)));
    }

    if (exp_opts->compress &&
        gsc_common_z_init_write(g_lob_binfile, &g_lf_zstream, exp_opts->compress_level) != GS_SUCCESS) {
        GSQL_PRINTF(ZSERR_EXPORT, "init compress file '%s' failed.\n", file_path_buf);
        return GS_ERROR;
    }

    if (g_lob_fbuf == NULL) {
        g_lob_fbuf = (char *)malloc(EXP_MAX_LOB_FILE_BUF);
        if (g_lob_fbuf == NULL) {
            EXP_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)EXP_MAX_LOB_FILE_BUF, "exporting file buf");
            return GS_ERROR;
        }

        MEMS_RETURN_IFERR(memset_s(g_lob_fbuf, EXP_MAX_LOB_FILE_BUF, 0, EXP_MAX_LOB_FILE_BUF));
    }

    return GS_SUCCESS;
}

status_t exp_bin_init_bin_file_ctx(exp_bin_file_ctx_t *ctx, char *data_buf, uint32 databuf_size, char *lob_buf,
                                   uint32 lob_buf_size, FILE *df_handler, FILE *lob_handler)
{
    ctx->bin_file_size = 0;

    ctx->bin_data_buf.len = 0;
    ctx->bin_data_buf.str = data_buf;
    ctx->bin_data_buf.max_size = databuf_size;

    ctx->bin_lob_buf.len = 0;
    ctx->bin_lob_buf.str = lob_buf;
    ctx->bin_lob_buf.max_size = lob_buf_size;

    ctx->bin_lob_data_buf.len = 0;
    ctx->bin_lob_data_buf.str = g_exp_lob_buff;
    ctx->bin_lob_data_buf.max_size = MAX_EXP_LOB_BUFF_SIZE;

    ctx->df_h = df_handler;
    ctx->lf_h = lob_handler;

    if (g_export_opts.compress) {
        ctx->df_zstream = &g_df_zstream;
        ctx->lf_zstream = &g_lf_zstream;
    } else {
        ctx->df_zstream = NULL;
        ctx->lf_zstream = NULL;
    }

    MEMS_RETURN_IFERR(strncpy_s(ctx->df_name, EXP_LOB_MAX_FILE_NAME_LEN, g_export_opts.bin_data_file,
        EXP_LOB_MAX_FILE_NAME_LEN - 1));
    MEMS_RETURN_IFERR(strncpy_s(ctx->lf_name, EXP_LOB_MAX_FILE_NAME_LEN, g_export_opts.lob_file_name,
        EXP_LOB_MAX_FILE_NAME_LEN - 1));

    return GS_SUCCESS;
}

void gsql_display_export_version_info(void)
{
    gsql_printf("\n");
    if (!IS_CONN) {
        gsql_printf("Connection is not established. "
            "Please make sure connect is ready then execute \"exp -v\" or \"exp version\"\n\n");
        return;
    }
    
    gsql_printf("New functions or features for EXP and IMP in this version:\n");
    gsql_printf("---------------------------------------------------------"
        "------------------------------------------------------------------\n");
    uint32 curr_negotiate_version = gsc_get_call_version(CONN);
    switch (curr_negotiate_version) {
        case CS_LOCAL_VERSION:
            gsql_printf("* support jsonb and support subpartion format csf for EXP and IMP\n");
        /* fall through */
        case CS_VERSION_23:
            gsql_printf("* support export and import compress attribution of table or partition table\n");
        /* fall through */
        case CS_VERSION_21:
            gsql_printf("* support binary format of array datatype\n");
        /* fall through */
        case CS_VERSION_20:
            gsql_printf("* support subpartition\n");
        /* fall through */
        case CS_VERSION_19:
            gsql_printf("* support create or replace force view\n");
        /* fall through */
        default:
            gsql_printf("\n");
    }
}

void gsql_display_export_usage(void)
{
    gsql_printf("The syntax of logic export is: \n\n");
    gsql_printf("     Format:  EXP KEYWORD=value or KEYWORD=value1,value2,...,valueN;\n");
    gsql_printf("     Example: EXP TABLES=EMP,DEPT,MGR;\n");
    gsql_printf("               or EXP USERS=USER_A,USER_B;\n");
    gsql_printf("               or EXP DIST_RULES=RULE_1,RULE_2;\n\n");
    gsql_printf("Keyword                 Description (Default)\n");
    gsql_printf("---------------------------------------------------------------------------------------------------------------------------\n");
    gsql_printf("USERS                   List of schema names. Specify a percent sign (%%) to export all users.\n");
    gsql_printf("TABLES                  List of table names. Specify a percent sign (%%) to export all tables.\n");
    gsql_printf("DIST_RULES              List of distribute rule names. Specify a percent sign (%%) to export all distribution rules. Supported only for sharding.\n");
    gsql_printf("TABLESPACE_FILTER       List of tablespace names, the data or objects in these tablespaces will be exported. Case-sensitive words enclosed by '`' or '\"'.\n");
    gsql_printf("FILE                    Output file (EXPDAT.DMP) \n");
    gsql_printf("FILETYPE                Output file type: (TXT), BIN\n");
    gsql_printf("LOG                     Log file of screen output\n");
    gsql_printf("COMPRESS                Compress output file (0), only for FILETYPE=BIN, value range: 0-9, the smaller the value, the faster the speed, 0: no compression.\n");
    gsql_printf("CONTENT                 Specifies data to unload where the valid keyword, values are: (ALL), DATA_ONLY, and METADATA_ONLY. \n");
    gsql_printf("QUERY                   Predicate clause used to export a subset of a table, eg. \"where rownum <= 10\" \n");
    gsql_printf("SKIP_COMMENTS           Do not add comments to dump file. (N)\n");
    gsql_printf("FORCE                   Continue even if an SQL error occurs during a table dump. (N)\n");
    gsql_printf("SKIP_ADD_DROP_TABLE     Do not add a DROP TABLE statement before each CREATE TABLE statement. (N)\n");
    gsql_printf("SKIP_TRIGGERS           Do not dump triggers. (N)\n");
    gsql_printf("QUOTE_NAMES             Quote identifiers. (Y)\n");
    gsql_printf("TABLESPACE              Default transport all tablespaces except for system reserved. (N)\n");
    gsql_printf("COMMIT_BATCH            Batch commit rows, commit once if set 0. (1000)\n");
    gsql_printf("INSERT_BATCH            Batch insert rows. (1)\n");
    gsql_printf("FEEDBACK                Feedback row count, feedback once if set 0 (10000)\n");
    gsql_printf("PARALLEL                Table data export parallelism settings, range 2~16, The default value is 0\n");
    gsql_printf("CONSISTENT              Cross - table consistency(N)\n");
    gsql_printf("CREATE_USER             Export user definition(N),Used in conjunction with USERS.\n");
    gsql_printf("ROLE                    Export user roles expect system preset roles (N),Used in conjunction with USERS.\n");
    gsql_printf("GRANT                   Grant role and permission to USER (N),Used in conjunction with USERS and ROLE.\n");
    gsql_printf("WITH_CR_MODE            Export tables and indexes with CR_MODE options (N)\n");
    gsql_printf("WITH_FORMAT_CSF         Export tables and part tables with FORMAT CSF option (Y)\n");
    gsql_printf("ENCRYPT                 Export files will be encrypted.\n");
    gsql_printf("REMAP_TABLES            Table's name will remapped to another tablename.\n");
    gsql_printf("PARTITIONS              Export tables's data within the input partition.\n");
    gsql_printf("EXCLUDE                 Export exclude objects.\n");
    gsql_printf("INDEX_PARTITIONS        Export index's partition informations (N).\n");

    gsql_printf("\n");
}

static int exp_open_writer(export_options_t *exp_opts)
{
    if (exp_opts->dump_file == NULL || cm_str_equal_ins(exp_opts->dump_file, "stdout")) {
        g_exp_dpfile = NULL;  // null for write the content into cmd
        return GSC_SUCCESS;
    }

    g_exp_dpbinfile = NULL;

    // Step 1. open the dump file
    char realfile[GS_MAX_FILE_PATH_LENGH] = { 0x00 };
    char dump_path[GS_MAX_FILE_PATH_LENGH] = { 0x00 };
    char dump_data_dir[GS_MAX_FILE_PATH_LENGH] = { 0x00 };
    char dump_file_name[GS_MAX_FILE_PATH_LENGH] = { 0x00 };

    cm_trim_filename(exp_opts->dump_file, GS_MAX_FILE_PATH_LENGH, dump_path);
    cm_trim_dir(exp_opts->dump_file, sizeof(dump_file_name), dump_file_name);
    if (strlen(dump_path) != strlen(exp_opts->dump_file) && !cm_dir_exist((const char *)dump_path)) {
        EXP_THROW_ERROR(ERR_PATH_NOT_EXIST, dump_path);
        return GS_ERROR;
    } else if (dump_file_name[0] == '\0') {
        EXP_THROW_ERROR(ERR_CLT_INVALID_ATTR, "file name", exp_opts->dump_file);
        return GS_ERROR;
    }

    GS_RETURN_IFERR(realpath_file(exp_opts->dump_file, realfile, GS_MAX_FILE_PATH_LENGH));
    
    if (cm_fopen(realfile, (exp_opts->filetype == FT_BIN) ? "wb+" : "w+", FILE_PERM_OF_DATA,
                 &g_exp_dpfile) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (g_export_opts.crypt_info.crypt_flag) {
        GS_RETURN_IFERR(gsql_exp_generate_encrypt_info(&g_export_opts.crypt_info, (char *)dump_file_name,
            GS_MAX_NAME_LEN - 1, cm_fileno(g_exp_dpfile)));
    }

    // Step 2. record the dump data path
    cm_trim_filename(realfile, GS_MAX_FILE_PATH_LENGH, dump_path);

    PRTS_RETURN_IFERR(snprintf_s(dump_data_dir, GS_MAX_FILE_PATH_LENGH, GS_MAX_FILE_PATH_LENGH - 1, "%s%s",
        dump_path, GSQL_SEC_FILE_NAME));

    if (!cm_dir_exist((const char *)dump_data_dir)) {
        if (cm_create_dir(dump_data_dir) != GS_SUCCESS) {
            GSQL_PRINTF(ZSERR_EXPORT, "failed to create dir %s, errno is %d.", dump_data_dir, cm_get_os_error());
            return GS_ERROR;
        }
    }

    PRTS_RETURN_IFERR(snprintf_s(exp_opts->dump_data_path, GS_FILE_NAME_BUFFER_SIZE, GS_FILE_NAME_BUFFER_SIZE - 1,
        "%s/", dump_data_dir));

    return GSC_SUCCESS;
}

static int exp_open_logger(const char *logfile)
{
    if (CM_IS_EMPTY_STR(logfile)) {
        g_exp_logfile = NULL;
        return GS_SUCCESS;
    }
    /* try get path of logfile and check whether it exists */
    char path[GS_MAX_FILE_PATH_LENGH] = { 0x00 };
    char file_name[GS_MAX_FILE_PATH_LENGH] = { 0x00 };
    cm_trim_filename(logfile, GS_MAX_FILE_PATH_LENGH, path);
    cm_trim_dir(logfile, sizeof(file_name), file_name);
    if (strlen(path) != strlen(logfile) && !cm_dir_exist((const char *)path)) {
        EXP_THROW_ERROR(ERR_PATH_NOT_EXIST, path);
        return GS_ERROR;
    } else if (file_name[0] == '\0') {
        EXP_THROW_ERROR(ERR_CLT_INVALID_ATTR, "file name", logfile);
        return GS_ERROR;
    }

    GS_RETURN_IFERR(realpath_file(logfile, path, GS_MAX_FILE_PATH_LENGH));

    if (cm_fopen(path, "w+", FILE_PERM_OF_DATA, &g_exp_logfile) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static void exp_close_writer()
{
    if (g_exp_dpfile != NULL) {
        fclose(g_exp_dpfile);
        g_exp_dpfile = NULL;
    }

    if (g_exp_dpbinfile != NULL) {
        if (g_export_opts.compress) {
            (void)gsc_common_z_uninit_write(&g_df_zstream);
        }

        fclose(g_exp_dpbinfile);
        g_exp_dpbinfile = NULL;
    }

    if (g_lob_binfile != NULL) {
        if (g_export_opts.compress) {
            (void)gsc_common_z_uninit_write(&g_lf_zstream);
        }

        fclose(g_lob_binfile);
        g_lob_binfile = NULL;
    }
}

static void exp_close_logger(void)
{
    if (g_exp_logfile != NULL) {
        fclose(g_exp_logfile);
        g_exp_logfile = NULL;
    }
}

static int exp_writer_compress_s(char *buf, uint32 size, gsc_z_stream *stream)
{
    char swap_buffer[SIZE_K(4)];

    if (stream == NULL) {
        gsql_printf("%s", buf);
        return GS_ERROR;
    } else {
        if (gsc_common_z_write(stream, &g_export_opts.crypt_info, swap_buffer, sizeof(swap_buffer), buf,
                               size, GS_FALSE) != GS_SUCCESS) {
            EXP_THROW_ERROR(ERR_CLT_WRITE_FILE_ERR, errno);
            return GS_ERROR;
        }
        return GS_SUCCESS;
    }
}

static int exp_flush_compress_s(text_buf_t *dst, gsc_z_stream *stream)
{
    char swap_buffer[SIZE_K(4)];

    if (stream == NULL) {
        gsql_printf("%s", dst->str);
        return GS_ERROR;
    } else {
        if (gsc_common_z_write(stream, &g_export_opts.crypt_info, swap_buffer, sizeof(swap_buffer), dst->str,
                               dst->len, GS_TRUE) != GS_SUCCESS) {
            EXP_THROW_ERROR(ERR_CLT_WRITE_FILE_ERR, errno);
            return GS_ERROR;
        }
        return GS_SUCCESS;
    }
}

static int exp_writer_data_compress_s(char *buf, uint32 size, text_buf_t *dst, gsc_z_stream *stream)
{
    text_t text = { .str = buf, .len = size };

    if (cm_buf_append_text(dst, &text)) {
        return GS_SUCCESS;
    }

    GS_RETURN_IFERR(exp_writer_compress_s(dst->str, dst->len, stream));

    dst->len = 0;
    if (text.len < dst->max_size) {
        (void)cm_buf_append_text(dst, &text);
        return GS_SUCCESS;
    }
    GS_RETURN_IFERR(exp_writer_compress_s(text.str, text.len, stream));
    return GS_SUCCESS;
}

static inline int exp_writer_encrypt_s(char *buf, uint32 size, FILE *filehand)
{
    char *encrypt_buf = NULL;
    crypt_file_t *encrypt_file = NULL;
    
    GS_RETURN_IFERR(gsql_get_encrypt_file(&g_export_opts.crypt_info, &encrypt_file, cm_fileno(filehand)));
    encrypt_buf = (char *)malloc(SIZE_M(16));
    if (encrypt_buf == NULL) {
        gsql_printf("can't allocate %u bytes for dump table\n", SIZE_M(16));
        return GS_ERROR;
    }

    if (cm_encrypt_data_by_gcm(encrypt_file->crypt_ctx.gcm_ctx, encrypt_buf, buf, size) != GS_SUCCESS) {
        CM_FREE_PTR(encrypt_buf);
        return GS_ERROR;
    }

    if (fwrite(encrypt_buf, 1, size, filehand) == 0) {
        EXP_THROW_ERROR(ERR_CLT_WRITE_FILE_ERR, errno);
        CM_FREE_PTR(encrypt_buf);
        return GS_ERROR;
    }

    CM_FREE_PTR(encrypt_buf);
    return GS_SUCCESS;
}

static inline int exp_writer_s(char *buf, uint32 size, FILE *filehand)
{
    if (filehand == NULL) {
        gsql_printf("%s", buf);
        return GS_SUCCESS;
    } else {
        if (g_export_opts.crypt_info.crypt_flag) {
            GS_RETURN_IFERR(exp_writer_encrypt_s(buf, size, filehand));
            return GS_SUCCESS;
        }

        if (fwrite(buf, 1, size, filehand) != (size_t)size) {
            EXP_THROW_ERROR(ERR_CLT_WRITE_FILE_ERR, errno);
            return GS_ERROR;
        }
        return GS_SUCCESS;
    }
}

static inline int exp_write_text_s(const text_t *text, text_buf_t *dst, FILE *filehand)
{
    if (cm_buf_append_text(dst, text)) {
        return GS_SUCCESS;
    }

    GS_RETURN_IFERR(exp_writer_s(dst->str, dst->len, filehand));

    dst->len = 0;
    if (text->len < dst->max_size) {
        (void)cm_buf_append_text(dst, text);
        return GS_SUCCESS;
    }
    GS_RETURN_IFERR(exp_writer_s(text->str, text->len, filehand));
    return GS_SUCCESS;
}

static inline int exp_flush_s(text_buf_t *dst, FILE *filehand)
{
    if (!CM_IS_EMPTY(dst)) {
        int ret = exp_writer_s(dst->str, dst->len, filehand);
        if (ret != GS_SUCCESS) {
            dst->len = 0;
            return ret;
        }
        dst->len = 0;
    }
    return GS_SUCCESS;
}

static const char *exp_now()
{
    static char date_str[GS_MAX_TIME_STRLEN];
    (void)cm_timestamp2str(cm_now(), "YYYY-MM-DD HH24:MI:SS.FF3", date_str, sizeof(date_str));
    return date_str;
}

static inline status_t exp_write_bin_s(const char *str, uint32 size, text_buf_t *dst, FILE *filehand)
{
    text_t text;
    text.str = (char *)str;
    text.len = (str == NULL) ? 0 : size;
    GS_RETURN_IFERR(exp_write_text_s(&text, dst, filehand));
    return GS_SUCCESS;
}

static int exp_writer_bin_data_s(char *buf, uint32 size, text_buf_t *dst, FILE *fp, gsc_z_stream *stream)
{
    if (stream != NULL) {
        return exp_writer_data_compress_s(buf, size, dst, stream);
    } else {
        return exp_write_bin_s(buf, size, dst, fp);
    }
}

static int exp_flush_bin_data_s(text_buf_t *dst, FILE *fp, gsc_z_stream *stream)
{
    if (stream != NULL) {
        return exp_flush_compress_s(dst, stream);
    } else {
        return exp_flush_s(dst, fp);
    }
}

static inline int exp_write_str_s(const char *str, text_buf_t *dst, FILE *filehand)
{
    text_t text;
    cm_str2text((char *)str, &text);
    GS_RETURN_IFERR(exp_write_text_s(&text, dst, filehand));
    return GS_SUCCESS;
}

static inline status_t exp_write_schema_com(const char *str, text_buf_t *dst, FILE *filehand)
{
    char *addr = NULL;
    uint32 size;

    if (g_export_opts.filetype == FT_BIN) {
        size = (uint32)strlen(str);
        GS_RETURN_IFERR(get_mem_address(&g_export_opts.master_bin_mgr, &addr, size));
        MEMS_RETURN_IFERR(memcpy_s(addr, size, str, size));
        return GS_SUCCESS;
    } else {
        return exp_write_str_s(str, dst, filehand);
    }
}

#define EXP_FMT_BUF_SZ MAX_SQL_SIZE
#define EXP_FMT_BUFER  g_sql_buf

static void exp_write_fmt(bool32 wr_bin_sch, uint32 max_fmt_sz, const char *fmt, ...)
{
    int32 len;
    text_t text;

    va_list var_list;
    va_start(var_list, fmt);
    len = vsnprintf_s(EXP_FMT_BUFER, MAX_SQL_SIZE, max_fmt_sz, fmt, var_list);
    va_end(var_list);
    if (len < 0) {
        gsql_printf("Copy var_list to EXP_FMT_BUFER failed under using export tool.\n");
        return;
    }
    text.str = EXP_FMT_BUFER;
    text.len = (uint32)len;
    if (wr_bin_sch == GS_FALSE) {
        (void)exp_write_text_s(&text, &g_exp_txtbuf, g_exp_dpfile);
    } else {
        (void)exp_write_schema_com(text.str, &g_exp_txtbuf, g_exp_dpfile);
    }
}

static bool8 exp_error_ignored(gsc_conn_t conn)
{
    int32 error_code = 0;
    const char *err_msg = "";

    exp_get_error(conn, &error_code, &err_msg, NULL);

    if (error_code == ERR_TABLE_OR_VIEW_NOT_EXIST ||
        error_code == ERR_TABLE_ID_NOT_EXIST ||
        error_code == ERR_OBJECT_ALREADY_DROPPED) {
        gsql_printf("Warning: CT-%05d, %s\n", error_code, err_msg);
        return GS_TRUE;
    }

    return GS_FALSE;
}

static inline status_t exp_ignore_error(gsc_conn_t conn)
{
    if (g_export_opts.force) {
        gsql_print_error(conn);
        return GS_SUCCESS;
    }

    return exp_error_ignored(conn) ? GS_SUCCESS : GS_ERROR;
}

/** Write msg into cmd or log file */
#define exp_log(fmt, ...)                               \
    do {                                                \
        gsql_printf(fmt, ##__VA_ARGS__);                \
        if (g_exp_logfile != NULL) {                    \
            fprintf(g_exp_logfile, fmt, ##__VA_ARGS__); \
        }                                               \
    } while (0)

/** Write msg into cmd or log file with time */
#define exp_tmlog(fmt, ...)                             \
    do {                                                \
        gsql_printf(fmt, ##__VA_ARGS__);                \
        if (g_exp_logfile != NULL) {                    \
            fprintf(g_exp_logfile, "[%s] ", exp_now()); \
            fprintf(g_exp_logfile, fmt, ##__VA_ARGS__); \
        }                                               \
    } while (0)

/** Write msg into log file with time */
#define exp_dlog(fmt, ...)                              \
    do {                                                \
        if (g_exp_logfile != NULL) {                    \
            fprintf(g_exp_logfile, "[%s] ", exp_now()); \
            fprintf(g_exp_logfile, fmt, ##__VA_ARGS__); \
        }                                               \
    } while (0)

/** Write msg into cmd or log file and dump file */
#define exp_write_dplog(bufsz, fmt, ...)                    \
    do {                                                    \
        exp_write_fmt(GS_FALSE, bufsz, fmt, ##__VA_ARGS__); \
        exp_log(fmt, ##__VA_ARGS__);                        \
    } while (0)

#define EXP_RETURN_IFERR(ret)                                                                           \
    do {                                                                                                \
        int _status_ = (ret);                                                                           \
        if (_status_ != GS_SUCCESS) {                                                                   \
            if (exp_ignore_error(CONN) != GS_SUCCESS) {                                                 \
                return _status_;                                                                        \
            }                                                                                           \
        }                                                                                               \
    } while (0)

#define EXP_BREAK_IFERR(ret)                                                                           \
    {                                                                                                  \
        int _status_ = (ret);                                                                          \
        if ((_status_) != GS_SUCCESS && exp_ignore_error(CONN) != GS_SUCCESS) {                        \
                break;                                                                                 \
        }                                                                                              \
    }

static inline void exp_concat_str_quote(text_t *text, const char *part)
{
    if (g_export_opts.quote_names) {
        cm_concat_fmt(text, GSQL_MAX_QUOTE_NAME_SIZE, "\"%s\"", part);
    } else {
        (void)cm_concat_string(text, GSQL_MAX_QUOTE_NAME_SIZE, part);
    }
}

static inline void exp_write_schema_quote(const char *str)
{
    if (g_export_opts.quote_names) {
        exp_write_fmt(GS_TRUE, EXP_FMT_BUF_SZ, "\"%s\"", str);
    } else {
        (void)exp_write_schema_com(str, &g_exp_txtbuf, g_exp_dpfile);
    }
}

static inline void exp_write_str_quote(const char *str)
{
    if (g_export_opts.quote_names) {
        exp_write_fmt(GS_FALSE, EXP_FMT_BUF_SZ, "\"%s\"", str);
    } else {
        (void)exp_write_str_s(str, &g_exp_txtbuf, g_exp_dpfile);
    }
}

static const char* exp_remap_table_name(list_t *remap_list, const char *src, char *dest, uint32 dest_len)
{
    static char remap_tabname[MAX_TAB_NAME_LEN + 1];
    char *dest_buf = (dest == NULL ? remap_tabname : dest);
    uint32 dest_buflen = (dest == NULL ? sizeof(remap_tabname) : dest_len);

    if (remap_list->count > 0) {
        if (find_remap(remap_list, src, dest_buf, dest_buflen)) {
            exp_dlog("table: %s remap as %s\n", src, dest_buf);
            return dest_buf;
        }
    }

    return src;
}

static inline int par_exp_init_bfile_ctx(exp_bin_file_ctx_t *bfile_ctx, par_exp_thread_ctrl_t *ctrl)
{
    bfile_ctx->bin_file_size = 0;
    bfile_ctx->bin_data_buf = ctrl->files_context.exp_txtbuf;
    bfile_ctx->df_h = ctrl->files_context.exp_dpfile;
    bfile_ctx->bin_lob_buf = ctrl->files_context.bin_lob_buf;
    bfile_ctx->lf_h = ctrl->files_context.lf_h;
    bfile_ctx->wr_lob_flag = GS_FALSE;
    bfile_ctx->bin_lob_data_buf = ctrl->files_context.lob_buf;

    PRTS_RETURN_IFERR(sprintf_s(bfile_ctx->df_name, EXP_LOB_MAX_FILE_NAME_LEN, ctrl->options.bin_data_file,
        EXP_LOB_MAX_FILE_NAME_LEN));
    PRTS_RETURN_IFERR(sprintf_s(bfile_ctx->lf_name, EXP_LOB_MAX_FILE_NAME_LEN, ctrl->options.lob_file_name,
        EXP_LOB_MAX_FILE_NAME_LEN));

    bfile_ctx->tab_name = (char*)exp_remap_table_name(&ctrl->options.table_maps, ctrl->tab_param.tab_name,
        ctrl->tab_param.tab_name, GS_MAX_NAME_LEN);
    return GS_SUCCESS;
}

static inline status_t exp_write_head(void)
{
    /* show create table option suppresses irrelevant info display */
    if (g_export_opts.filetype == FT_BIN ||
        g_export_opts.show_create_table) {
        return GS_SUCCESS;
    }

    GS_RETURN_IFERR(exp_write_str_s("--** The script is dumped by *CTCLIENT/EXP* tool, Zenith@Huawei Cantian Dept.\n",
        &g_exp_txtbuf, g_exp_dpfile));
    if (g_exp_dpfile != NULL) {
        exp_write_fmt(GS_FALSE, GSQL_MAX_QUOTE_NAME_SIZE, "--** Dumped time: %s\n", exp_now());
    }
    GS_RETURN_IFERR(exp_write_str_s("\n", &g_exp_txtbuf, g_exp_dpfile));

    return GS_SUCCESS;
}

void exp_tmlog_error(gsc_conn_t conn)
{
    int code = 0;
    const char *message = "";
    source_location_t loc;

    exp_get_error(conn, &code, &message, &loc);
    
    if (code != ERR_ERRNO_BASE) {
        if (loc.line == 0) {
            exp_tmlog("CT-%05d, %s\n", code, message);
        } else {
            exp_tmlog("CT-%05d, [%d:%d]%s\n", code, (int)loc.line, (int)loc.column, message);
        }
    }
}

static int gsql_insert_export_obj(export_options_t *exp_opts, const text_t *obj_name, bool32 to_upper)
{
    char obj_name_buf[GSQL_MAX_OBJECT_LEN] = "";
    char *object_name = obj_name_buf;

    if (obj_name->len >= GSQL_MAX_OBJECT_LEN) {
        EXP_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "the object name is too long");
        return GS_ERROR;
    }

    if (exp_opts->exp_type == EXP_SCHEMA &&
        cm_text_str_equal_ins(obj_name, "SYS")) {
        EXP_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "can not export SYS schema");
        return GS_ERROR;
    }

    // copy user name
    if (to_upper) {
        cm_text2str_with_upper(obj_name, obj_name_buf, GSQL_MAX_OBJECT_LEN);
    } else {
        GS_RETURN_IFERR(cm_text2str(obj_name, obj_name_buf, GSQL_MAX_OBJECT_LEN));
    }

    return gsql_generate_obj(&exp_opts->obj_list, object_name);
}

static int gsql_insert_export_table(export_options_t *exp_opts, const text_t *table_name, bool32 to_upper)
{
    char table_name_buf[GSQL_MAX_OBJECT_LEN] = "";
    char *table_name_tmp = table_name_buf;

    if (table_name->len >= GSQL_MAX_OBJECT_LEN) {
        EXP_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "the object name is too long");
        return GS_ERROR;
    }

    // copy table name
    if (to_upper) {
        cm_text2str_with_upper(table_name, table_name_buf, GSQL_MAX_OBJECT_LEN);
    } else {
        GS_RETURN_IFERR(cm_text2str(table_name, table_name_buf, GSQL_MAX_OBJECT_LEN));
    }

    return gsql_generate_obj(&exp_opts->exp_tables.table_list, table_name_tmp);
}

static int gsql_insert_export_tabspace(export_options_t *exp_opts, const text_t *obj_name, bool32 to_upper)
{
    char *ptr = NULL;
    char *ptr_name = NULL;
    char obj_name_buf[GSQL_MAX_OBJECT_LEN] = "";

    if (obj_name->len >= GSQL_MAX_OBJECT_LEN) {
        EXP_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "the tablespace name is too long");
        return GS_ERROR;
    }

    // copy tablespace name
    if (to_upper) {
        cm_text2str_with_upper(obj_name, obj_name_buf, GSQL_MAX_OBJECT_LEN);
    } else {
        GS_RETURN_IFERR(cm_text2str(obj_name, obj_name_buf, GSQL_MAX_OBJECT_LEN));
    }

    for (uint32 i = 0; i < exp_opts->tbs_list.count; i++) {
        ptr = cm_list_get(&exp_opts->tbs_list, i);
        ptr_name = obj_name_buf;
        if (cm_str_equal(ptr_name, ptr)) {
            EXP_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "tablespace name \"%s\" appears multiple times", obj_name_buf);
            return GS_ERROR;
        }
    }

    GS_RETURN_IFERR(cm_list_new(&exp_opts->tbs_list, (void **)&ptr));
    MEMS_EXP_RETURN_IFERR(strncpy_s(ptr, GSQL_MAX_OBJECT_LEN, obj_name_buf, GSQL_MAX_OBJECT_LEN - 1));

    return GS_SUCCESS;
}

static int exp_parse_self_schema(const char *user_name, bool8 *is_myself)
{
    uint32 rows;
    static const char *usr_exist_sql =
        "SELECT 1 "
        "FROM " EXP_SELF_USERS_AGENT " "
        "WHERE USERNAME = UPPER(:u) LIMIT 1";

    GS_RETURN_IFERR(gsc_prepare(STMT, usr_exist_sql));
    GS_RETURN_IFERR(gsc_bind_by_pos(STMT, 0, GSC_TYPE_STRING, user_name, (int32)strlen(user_name), NULL));
    GS_RETURN_IFERR(gsc_execute(STMT));
    GS_RETURN_IFERR(gsc_fetch(STMT, &rows));

    if (rows > 0) {
        *is_myself = GS_TRUE;
    }

    return GS_SUCCESS;
}

static int exp_parse_schema(lex_t *lex, export_options_t *exp_opts)
{
    word_t word;
    bool32 all_flag = GS_FALSE;
    char *ptr = NULL;

    if (exp_opts->exp_type != EXP_NONE) {
        EXP_SRC_THROW_ERROR_EX(lex->loc, ERR_SQL_SYNTAX_ERROR,
            "Too many export types have been provided, only one of USERS, TABLES and DIST_RULES is allowed");
        return GS_ERROR;
    }

    GS_RETURN_IFERR(lex_try_fetch(lex, "%", &all_flag));

    if (all_flag) {
        exp_opts->exp_type = EXP_ALL_SCHEMAS;
        return GS_SUCCESS;
    }

    exp_opts->exp_type = EXP_SCHEMA;

    GS_RETURN_IFERR(lex_fetch(lex, &word));

    while (word.type != WORD_TYPE_EOF) {
        bool32 has_next = GS_FALSE;
        if (!IS_VARIANT(&word)) {
            EXP_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "invalid schema name was found");
            return GS_ERROR;
        }

        if (gsql_insert_export_obj(exp_opts, &word.text.value, !IS_DQ_STRING(word.type)) != GS_SUCCESS) {
            EXP_SET_ERROR_LOC(word.loc);
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

    if (exp_opts->obj_list.count == 0) {
        EXP_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "no object needs to export");
        return GS_ERROR;
    }

    if (exp_opts->obj_list.count == 1) {
        ptr = cm_list_get(&exp_opts->obj_list, 0);
        GS_RETURN_IFERR(exp_parse_self_schema(ptr, &exp_opts->is_myself));
    }
    
    return GS_SUCCESS;
}

static int exp_parse_tablespace_filter(lex_t *lex, export_options_t *exp_opts)
{
    word_t word;
    GS_RETURN_IFERR(lex_fetch(lex, &word));
    while (word.type != WORD_TYPE_EOF) {
        bool32 has_next = GS_FALSE;
        if (!IS_VARIANT(&word)) {
            EXP_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "invalid tablespce name");
            return GS_ERROR;
        }

        if (gsql_insert_export_tabspace(exp_opts, &word.text.value,
            !IS_DQ_STRING(word.type) && exp_opts->is_case_insensitive) != GS_SUCCESS) {
            cm_set_error_loc(word.loc);
            return GS_ERROR;
        }
        GS_RETURN_IFERR(lex_try_fetch(lex, ",", &has_next));

        if (!has_next) {
            break;
        }

        if (lex_fetch(lex, &word) != GS_SUCCESS) {
            EXP_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "lex fetch failed for tablespace name");
            return GS_ERROR;
        }
    }
    // if exp_opts->obj_list.count == 0, it means no tablespace needs to filter. Don't care !
    return GS_SUCCESS;
}

static int exp_parse_tables(lex_t *lex, export_options_t *exp_opts)
{
    word_t word;
    bool32 all_flag = GS_FALSE;

    if (exp_opts->exp_type != EXP_NONE) {
        EXP_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR,
            "Too many export types have been provided, only one of USERS, TABLES and DIST_RULES is allowed");
        return GS_ERROR;
    }

    exp_opts->is_myself = GS_TRUE;

    GS_RETURN_IFERR(lex_try_fetch(lex, "%", &all_flag));

    if (all_flag) {
        exp_opts->exp_type = EXP_ALL_TABLES;
        return GS_SUCCESS;
    }

    exp_opts->exp_type = EXP_TABLE;

    GS_RETURN_IFERR(lex_fetch(lex, &word));

    while (word.type != WORD_TYPE_EOF) {
        bool32 has_next = GS_FALSE;
        if (!IS_VARIANT(&word)) {
            EXP_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "invalid table name was found");
            return GS_ERROR;
        }

        if (gsql_insert_export_table(exp_opts, &word.text.value,
            !IS_DQ_STRING(word.type) && exp_opts->is_case_insensitive) != GS_SUCCESS) {
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

    if (exp_opts->exp_tables.table_list.count == 0) {
        EXP_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "no object needs to export");
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

typedef enum {
    EOPT_USERS,
    EOPT_TABLES,
    EOPT_TABLESPACE_FILTER,
    EOPT_FILE,
    EOPT_FILETYPE,
    EOPT_LOG,
    EOPT_COMPRESS,
    EOPT_CONSISTENT,
    EOPT_CONTENT,
    EOPT_QUERY,
    EOPT_SKIP_COMMENTS,
    EOPT_FORCE,
    EOPT_SKIP_ADD_DROP_TABLE,
    EOPT_SKIP_TRIGGERS,
    EOPT_QUOTE_NAMES,
    EOPT_TABLESPACE,
    EOPT_COMMIT_BATCH,
    EOPT_INSERT_BATCH,
    EOPT_FEEDBACK,
    EOPT_PARALLEL,
    EOPT_TENANT,
    EOPT_CREATE_USER,
    EOPT_EXP_ROLE,
    EOPT_IS_GRANT,
    EOPT_WITH_CR_MODE,
    EOPT_WITH_FORMAT_CSF,
    EOPT_ENCRYPT,
    EOPT_SHOW_CREATE_TABLE,
    EOPT_EXCLUDE,
    EOPT_INDEX_PARTITIONS
} exp_item_t;

static const word_record_t eopt_records[] = {
    { .id = EOPT_USERS,               .tuple = { 1, { "USERS" } } },
    { .id = EOPT_TABLES,              .tuple = { 1, { "TABLES" } } },
    { .id = EOPT_TABLESPACE_FILTER,   .tuple = { 1, { "TABLESPACE_FILTER" } } },
    { .id = EOPT_FILE,                .tuple = { 1, { "FILE" } } },
    { .id = EOPT_FILETYPE,            .tuple = { 1, { "FILETYPE" } } },
    { .id = EOPT_LOG,                 .tuple = { 1, { "LOG" } } },
    { .id = EOPT_COMPRESS,            .tuple = { 1, { "COMPRESS" } } },
    { .id = EOPT_CONSISTENT,          .tuple = { 1, { "CONSISTENT" } } },
    { .id = EOPT_CONTENT,             .tuple = { 1, { "CONTENT" } } },
    { .id = EOPT_QUERY,               .tuple = { 1, { "QUERY" } } },
    { .id = EOPT_SKIP_COMMENTS,       .tuple = { 1, { "SKIP_COMMENTS" } } },
    { .id = EOPT_FORCE,               .tuple = { 1, { "FORCE" } } },
    { .id = EOPT_SKIP_ADD_DROP_TABLE, .tuple = { 1, { "SKIP_ADD_DROP_TABLE" } } },
    { .id = EOPT_SKIP_TRIGGERS,       .tuple = { 1, { "SKIP_TRIGGERS" } } },
    { .id = EOPT_QUOTE_NAMES,         .tuple = { 1, { "QUOTE_NAMES" } } },
    { .id = EOPT_TABLESPACE,          .tuple = { 1, { "TABLESPACE" } } },
    { .id = EOPT_COMMIT_BATCH,        .tuple = { 1, { "COMMIT_BATCH" } } },
    { .id = EOPT_INSERT_BATCH,        .tuple = { 1, { "INSERT_BATCH" } } },
    { .id = EOPT_FEEDBACK,            .tuple = { 1, { "FEEDBACK" } } },
    { .id = EOPT_PARALLEL,            .tuple = { 1, { "PARALLEL" } } },
    { .id = EOPT_CREATE_USER,         .tuple = { 1, { "CREATE_USER" } } },
    { .id = EOPT_EXP_ROLE,            .tuple = { 1, { "ROLE" } } },
    { .id = EOPT_IS_GRANT,            .tuple = { 1, { "GRANT" } } },
    { .id = EOPT_WITH_CR_MODE,        .tuple = { 1, { "WITH_CR_MODE" } } },
    { .id = EOPT_WITH_FORMAT_CSF,     .tuple = { 1, { "WITH_FORMAT_CSF" } } },
    { .id = EOPT_ENCRYPT,             .tuple = { 1, { "ENCRYPT" } } },
    { .id = EOPT_SHOW_CREATE_TABLE,   .tuple = { 1, { "SHOW_CREATE_TABLE" } } },
    { .id = EOPT_EXCLUDE,             .tuple = { 1, { "EXCLUDE" } } },
    { .id = EOPT_TENANT,              .tuple = { 1, { "TENANT" } } },
    { .id = EOPT_INDEX_PARTITIONS,    .tuple = { 1, { "INDEX_PARTITIONS" } } },
};

#define EXP_OPT_SIZE ELEMENT_COUNT(eopt_records)

static int exp_check_privilege(export_options_t *exp_opts)
{
    char *user = NULL;

    if (cm_str_equal("SYS", USER_NAME)) {
        return GS_SUCCESS;
    }
    
    bool8 is_dba;
    GS_RETURN_IFERR(gsql_check_dba_user(&is_dba));
    if (is_dba) {
        return GS_SUCCESS;
    }

    // if not dba user, normal user can't exp other user table by change schema
    if (exp_opts->exp_type == EXP_TABLE || exp_opts->exp_type == EXP_ALL_TABLES) {
        if (!cm_str_equal(exp_opts->schema_name, USER_NAME)) {
            EXP_THROW_ERROR(ERR_INSUFFICIENT_PRIV);
            return GS_ERROR;
        }
        return GS_SUCCESS;
    }
    
    if (exp_opts->exp_type == EXP_ALL_SCHEMAS) {
        EXP_THROW_ERROR(ERR_INSUFFICIENT_PRIV);
        return GS_ERROR;
    }

    for (uint32 i = 0; i < exp_opts->obj_list.count; i++) {
        user = (char *)cm_list_get(&exp_opts->obj_list, i);
        if (!cm_str_equal(user, USER_NAME)) {
            EXP_THROW_ERROR(ERR_INSUFFICIENT_PRIV);
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t exp_fetch_exclude(text_t *exclude, exp_exclude_obj_t *exclude_obj)
{
    lex_t lex;
    sql_text_t sql_text;
    word_t word;

    cm_ltrim_text(exclude);
    // parse exclude type
    exclude_obj->type = EXP_MAX_EXCLUDE;
    for (uint32 i = 0; i < EXP_MAX_EXCLUDE; i++) {
        if (g_expected_excludes[i].exclude_name.len <= exclude->len &&
            cm_text_str_contain_equal_ins(&g_expected_excludes[i].exclude_name, exclude->str,
                g_expected_excludes[i].exclude_name.len)) {
            exclude_obj->type = g_expected_excludes[i].type;
            exclude_obj->exclude_name = g_expected_excludes[i].exclude_name;
            CM_REMOVE_FIRST_N(exclude, g_expected_excludes[i].exclude_name.len);
            break;
        }
    }

    if (exclude_obj->type == EXP_MAX_EXCLUDE) {
        EXP_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "invalid exclude type expected.");
        return GS_ERROR;
    }

    cm_ltrim_text(exclude);
    // parse separate char
    if (exclude->len == 0 || exclude->str[0] != ':') {
        EXP_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "exclude ':' expected.");
        return GS_ERROR;
    }
    CM_REMOVE_FIRST(exclude);

    // parse condition
    cm_ltrim_text(exclude);
    sql_text.value = *exclude;
    sql_text.loc.line = 1;
    sql_text.loc.column = 1;

    lex_init(&lex, &sql_text);
    if (lex_fetch(&lex, &word) != GS_SUCCESS || word.type != WORD_TYPE_DQ_STRING) {
        EXP_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "exclude condition double quota expected.");
        return GS_ERROR;
    }

    exclude_obj->exclude_cond = word.text.value;
    CM_REMOVE_FIRST_N(exclude, ((word.text.value.str - exclude->str) + word.text.value.len + 1));

    return GS_SUCCESS;
}

static status_t exp_add_exclude(export_options_t *exp_opts, exp_exclude_obj_t *exclude_obj)
{
    exp_exclude_obj_t *obj = NULL;
    list_t *exclude_list = &exp_opts->exclude_list;
    // check duplicate
    for (uint32 i = 0; i < exclude_list->count; i++) {
        obj = (exp_exclude_obj_t *)cm_list_get(exclude_list, i);
        if (obj->type == exclude_obj->type) {
            EXP_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "duplicate exclude type.");
            return GS_ERROR;
        }
    }

    // add exclude object
    GS_RETURN_IFERR(cm_list_new(exclude_list, (void*)&obj));
    *obj = *exclude_obj;
    obj->exclude_cond.str = (char*)malloc(exclude_obj->exclude_cond.len);
    if (obj->exclude_cond.str == NULL) {
        GS_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)exclude_obj->exclude_cond.len, "exclude memory");
        return GS_ERROR;
    }
    MEMS_RETURN_IFERR(memcpy_s(obj->exclude_cond.str, exclude_obj->exclude_cond.len, exclude_obj->exclude_cond.str,
        exclude_obj->exclude_cond.len));
    return GS_SUCCESS;
}

static status_t exp_parse_one_exclude(export_options_t *exp_opts, text_t *exclude)
{
    exp_exclude_obj_t exclude_obj;

    GS_RETURN_IFERR(exp_fetch_exclude(exclude, &exclude_obj));
    GS_RETURN_IFERR(exp_add_exclude(exp_opts, &exclude_obj));

    return GS_SUCCESS;
}

static status_t exp_parse_exclude(lex_t *lex, export_options_t *exp_opts)
{
    text_t exclude;
    bool32 has_next = GS_FALSE;

    while (GS_TRUE) {
        has_next = GS_FALSE;
        // parse one exclude object
        exclude = lex->curr_text->value;
        GS_RETURN_IFERR(exp_parse_one_exclude(exp_opts, &exclude));

        lex->curr_text->value = exclude;
        GS_RETURN_IFERR(lex_try_fetch(lex, ",", &has_next));

        if (!has_next) {
            break;
        }
    }

    if (exp_opts->exclude_list.count == 0) {
        EXP_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "no object needs to exclude");
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

int exp_parse_opts(lex_t *lex, export_options_t *exp_opts)
{
    uint32 matched_id;
    word_t word;
    char *key_word_info = NULL;

    while (!lex_eof(lex)) {
        GS_RETURN_IFERR(lex_try_match_records(lex, eopt_records, EXP_OPT_SIZE, (uint32 *)&matched_id));

        if (matched_id == GS_INVALID_ID32) {
            EXP_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "invalid option for EXPORT");
            return GS_ERROR;
        }

        GS_RETURN_IFERR(lex_expected_fetch_word(lex, "="));

        switch (matched_id) {
            case EOPT_USERS:
                GS_RETURN_IFERR(exp_parse_schema(lex, exp_opts));
                break;

            case EOPT_TABLES:
                GS_RETURN_IFERR(exp_parse_tables(lex, exp_opts));
                break;

            case EOPT_TABLESPACE_FILTER:
                GS_RETURN_IFERR(exp_parse_tablespace_filter(lex, exp_opts));
                break;


            case EOPT_FILE:
                if (lex_expected_fetch_enclosed_string(lex, &word) != GS_SUCCESS) {
                    return GS_ERROR;
                }
                GS_RETURN_IFERR(cm_text2str(&word.text.value, exp_opts->dump_file, GS_MAX_FILE_PATH_LENGH));
                break;

            case EOPT_FILETYPE:
                GS_RETURN_IFERR(lex_expected_fetch_1of2(lex, "BIN", "TXT", &matched_id));
                exp_opts->filetype = (matched_id == 0) ? FT_BIN : FT_TXT;
                break;

            case EOPT_LOG:
                if (lex_expected_fetch_dqstring(lex, &word) != GS_SUCCESS) {
                    EXP_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "use double quotes for LOG");
                    return GS_ERROR;
                }
                GS_RETURN_IFERR(cm_text2str(&word.text.value, exp_opts->log_file, GS_MAX_FILE_PATH_LENGH));
                break;

            case EOPT_COMPRESS:
                GS_RETURN_IFERR(lex_expected_fetch_uint32(lex, &(exp_opts->compress_level)));
                if (exp_opts->compress_level > EXP_COMPRESS_MAX) {
                    EXP_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "compress_level should between 0 and 9.");
                    return GS_ERROR;
                }
                exp_opts->compress = (exp_opts->compress_level == EXP_COMPRESS_NONE) ? GS_FALSE : GS_TRUE;

                break;

            case EOPT_CONSISTENT:
                GS_RETURN_IFERR(lex_expected_fetch_1of2(lex, "Y", "N", &matched_id));
                exp_opts->consistent = (matched_id == 0) ? GS_TRUE : GS_FALSE;

                break;

            case EOPT_CONTENT:
                GS_RETURN_IFERR(lex_expected_fetch_1of3(lex, "ALL", "DATA_ONLY", "METADATA_ONLY", &matched_id));
                exp_opts->content = (matched_id == 0) ? CT_EXP_ALL : (matched_id == 1 ? CT_EXP_DATA : CT_EXP_META);
                break;

            case EOPT_QUERY:
                GS_RETURN_IFERR(lex_expected_fetch_dqstring(lex, &word));
                GS_RETURN_IFERR(cm_text2str(&word.text.value, exp_opts->query, MAX_EXP_QUERY_SIZE));
                break;

            case EOPT_SKIP_COMMENTS:
                GS_RETURN_IFERR(lex_expected_fetch_1of2(lex, "Y", "N", &matched_id));
                exp_opts->skip_comments = (matched_id == 0) ? GS_TRUE : GS_FALSE;
                break;

            case EOPT_FORCE:
                GS_RETURN_IFERR(lex_expected_fetch_1of2(lex, "Y", "N", &matched_id));
                exp_opts->force = (matched_id == 0) ? GS_TRUE : GS_FALSE;
                break;

            case EOPT_SKIP_ADD_DROP_TABLE:
                GS_RETURN_IFERR(lex_expected_fetch_1of2(lex, "Y", "N", &matched_id));
                exp_opts->skip_add_drop_table = (matched_id == 0) ? GS_TRUE : GS_FALSE;
                break;

            case EOPT_SKIP_TRIGGERS:
                GS_RETURN_IFERR(lex_expected_fetch_1of2(lex, "Y", "N", &matched_id));
                exp_opts->skip_triggers = (matched_id == 0) ? GS_TRUE : GS_FALSE;
                break;

            case EOPT_QUOTE_NAMES:
                GS_RETURN_IFERR(lex_expected_fetch_1of2(lex, "Y", "N", &matched_id));
                exp_opts->quote_names = (matched_id == 0) ? GS_TRUE : GS_FALSE;
                break;
            case EOPT_TABLESPACE:
                GS_RETURN_IFERR(lex_expected_fetch_1of2(lex, "Y", "N", &matched_id));
                exp_opts->tablespace = (matched_id == 0) ? GS_TRUE : GS_FALSE;
                break;
            case EOPT_COMMIT_BATCH:
                GS_RETURN_IFERR(lex_expected_fetch_uint32(lex, &(exp_opts->commit_batch)));
                break;
            case EOPT_INSERT_BATCH:
                GS_RETURN_IFERR(lex_expected_fetch_uint32(lex, &(exp_opts->insert_batch)));
                if (exp_opts->insert_batch == 0 || exp_opts->insert_batch > GSQL_INSERT_BATCH) {
                    EXP_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "insert_batch should between 1 and 10000.");
                    return GS_ERROR;
                }
                break;
            case EOPT_FEEDBACK:
                GS_RETURN_IFERR(lex_expected_fetch_uint32(lex, &(exp_opts->feedback)));
                break;
            case EOPT_PARALLEL:
                GS_RETURN_IFERR(lex_expected_fetch_uint32(lex, &(exp_opts->parallel)));
                exp_opts->parallel = MIN(exp_opts->parallel, GS_MAX_PAR_EXP_VALUE);
                break;
            case EOPT_CREATE_USER:
                GS_RETURN_IFERR(lex_expected_fetch_1of2(lex, "Y", "N", &matched_id));
                exp_opts->create_user = (matched_id == 0) ? GS_TRUE : GS_FALSE;
                break;
            case EOPT_EXP_ROLE:
                GS_RETURN_IFERR(lex_expected_fetch_1of2(lex, "Y", "N", &matched_id));
                exp_opts->exp_role = (matched_id == 0) ? GS_TRUE : GS_FALSE;
                break;
            case EOPT_IS_GRANT:
                GS_RETURN_IFERR(lex_expected_fetch_1of2(lex, "Y", "N", &matched_id));
                exp_opts->is_grant = (matched_id == 0) ? GS_TRUE : GS_FALSE;
                break;

            case EOPT_WITH_CR_MODE:
                GS_RETURN_IFERR(lex_expected_fetch_1of2(lex, "Y", "N", &matched_id));
                exp_opts->with_cr_mode = (matched_id == 0) ? GS_TRUE : GS_FALSE;
                break;

            case EOPT_WITH_FORMAT_CSF:
                GS_RETURN_IFERR(lex_expected_fetch_1of2(lex, "Y", "N", &matched_id));
                exp_opts->with_format_csf = (matched_id == 0) ? GS_TRUE : GS_FALSE;
                break;

            case EOPT_ENCRYPT: {
                key_word_info = "Encrypt pwd string";
                GS_RETURN_IFERR(gsql_get_crypt_pwd(lex, exp_opts->crypt_info.crypt_pwd,
                                                   GS_PASSWD_MAX_LEN + 1, key_word_info));
                GS_RETURN_IFERR(gsql_gen_encrypt_hash(&exp_opts->crypt_info));
                exp_opts->crypt_info.crypt_flag = GS_TRUE;
                break;
            }

            case EOPT_SHOW_CREATE_TABLE:
                GS_RETURN_IFERR(lex_expected_fetch_1of2(lex, "Y", "N", &matched_id));
                exp_opts->show_create_table = (matched_id == 0) ? GS_TRUE : GS_FALSE;
                /* prevent EXP from dumping file under 'show create table' option */
                MEMS_EXP_RETURN_IFERR(strncpy_s(exp_opts->dump_file,
                    GS_MAX_FILE_PATH_LENGH, NULL_DUMP_FILE, strlen(NULL_DUMP_FILE)));
                break;

            case EOPT_INDEX_PARTITIONS:
                GS_RETURN_IFERR(lex_expected_fetch_1of2(lex, "Y", "N", &matched_id));
                exp_opts->index_partitions = (matched_id == 0) ? GS_TRUE : GS_FALSE;
                break;

            case EOPT_EXCLUDE:
                GS_RETURN_IFERR(exp_parse_exclude(lex, exp_opts));
                break;

            case EOPT_TENANT:
                GS_RETURN_IFERR(lex_expected_fetch_1of2(lex, "Y", "N", &matched_id));
                exp_opts->tenant = (matched_id == 0) ? GS_TRUE : GS_FALSE;
                break;

            default:
                break;
        }
        GS_RETURN_IFERR(lex_skip_comments(lex, NULL));
    }

    return lex_expected_end(lex);
}

static status_t exp_reset_opts_from_server(export_options_t *exp_opts)
{
    if (!IS_CONN) {
        EXP_THROW_ERROR(ERR_CLT_CONN_CLOSE);
        return GS_ERROR;  // the connection is broken
    }
    return gsql_reset_case_insensitive(&exp_opts->is_case_insensitive);
}

static inline status_t exp_reset_part_opts(export_options_t *exp_opts)
{
    exp_opts->show_create_table = GS_FALSE;
    exp_opts->compress = GS_FALSE;
    exp_opts->consistent = GS_FALSE;
    exp_opts->content = CT_EXP_ALL;
    exp_opts->skip_comments = GS_FALSE;
    exp_opts->force = GS_FALSE;
    exp_opts->skip_add_drop_table = GS_FALSE;
    exp_opts->skip_triggers = GS_FALSE;
    exp_opts->quote_names = GS_TRUE;
    exp_opts->tablespace = GS_FALSE;
    exp_opts->commit_batch = GSQL_COMMIT_BATCH;
    exp_opts->insert_batch = 1;
    exp_opts->feedback = GSQL_FEEDBACK;
    exp_opts->parallel = 0;
    exp_opts->tenant = GS_FALSE;
    exp_opts->create_user = GS_FALSE;
    exp_opts->exp_role = GS_FALSE;
    exp_opts->is_grant = GS_FALSE;
    exp_opts->with_cr_mode = GS_FALSE;
    exp_opts->with_format_csf = GS_TRUE;
    MEMS_RETURN_IFERR(memset_s(&exp_opts->dn_info, sizeof(exp_shd_info_t), 0, sizeof(exp_shd_info_t)));
    exp_opts->dn_info.shd_node_type = gsc_get_shd_node_type(CONN);
    exp_opts->dn_info.consistent = GS_FALSE;
    exp_opts->is_myself = GS_FALSE;
    exp_opts->is_dba = GS_FALSE;
    return GS_SUCCESS;
}

static inline void exp_reset_exclude_list(list_t *exclude_list)
{
    exp_exclude_obj_t *obj = NULL;
    for (uint32 i = 0; i < exclude_list->count; i++) {
        obj = (exp_exclude_obj_t *)cm_list_get(exclude_list, i);
        if (obj->exclude_cond.str != NULL) {
            free(obj->exclude_cond.str);
        }
    }
    cm_reset_list(exclude_list);
}

status_t exp_reset_opts(export_options_t *exp_opts)
{
    exp_opts->exp_type = EXP_NONE;
    cm_reset_list(&exp_opts->obj_list);
    exp_create_objlist(&exp_opts->obj_list, GSQL_MAX_OBJECT_LEN);
    cm_reset_list(&exp_opts->tbs_list);
    exp_create_objlist(&exp_opts->tbs_list, GSQL_MAX_OBJECT_LEN);
    exp_opts->filetype = FT_TXT;
    MEMS_EXP_RETURN_IFERR(strncpy_s(exp_opts->dump_file, GS_MAX_FILE_PATH_LENGH, DEFAULT_DUMP_FILE,
        strlen(DEFAULT_DUMP_FILE)));
    MEMS_RETURN_IFERR(memset_s(exp_opts->log_file, GS_MAX_FILE_PATH_LENGH, 0, GS_MAX_FILE_PATH_LENGH));
    MEMS_RETURN_IFERR(memset_s(exp_opts->schema_name, sizeof(exp_opts->schema_name), 0, sizeof(exp_opts->schema_name)));
    MEMS_RETURN_IFERR(memset_s(exp_opts->query, MAX_EXP_QUERY_SIZE, 0, MAX_EXP_QUERY_SIZE));

    GS_RETURN_IFERR(exp_reset_part_opts(exp_opts));
    
    cm_reset_list(&exp_opts->table_maps);
    cm_create_list(&exp_opts->table_maps, sizeof(re_map_t));
    exp_opts->exp_tables.table_exp_type = EXP_TABLE_FULL;
    cm_reset_list(&exp_opts->exp_tables.table_list);
    exp_create_objlist(&exp_opts->exp_tables.table_list, GSQL_MAX_OBJECT_LEN);
    cm_reset_list(&exp_opts->exp_tables.partition_list);
    exp_create_objlist(&exp_opts->exp_tables.partition_list, GSQL_MAX_OBJECT_LEN);

    g_file_no = 0;
    g_exp_scn = GS_INVALID_ID64;
    g_exp_gts_scn = GS_INVALID_ID64;

    status_t status = exp_reset_opts_from_server(exp_opts);
    if (status != GS_SUCCESS) {
        gsql_print_error(CONN);
    }

    gsql_reset_crypt_info(&exp_opts->crypt_info);

    exp_reset_exclude_list(&exp_opts->exclude_list);
    cm_create_list(&exp_opts->exclude_list, sizeof(exp_exclude_obj_t));

    return status;
}

static void exp_print_exclude_info(export_options_t *exp_opts)
{
    list_t *exclude_list = &exp_opts->exclude_list;
    exp_exclude_obj_t *obj = NULL;
    for (uint32 i = 0; i < exclude_list->count; i++) {
        obj = (exp_exclude_obj_t *)cm_list_get(exclude_list, i);
        exp_write_dplog(100, "-- EXCLUDE = \"%.*s\"\n", obj->exclude_cond.len, obj->exclude_cond.str);
    }
}

static void exp_print_options_write_dplog(export_options_t *exp_opts, char *str)
{
    static char *content_mode[] = { "DATA_ONLY", "METADATA_ONLY", "ALL" };
    str = (exp_opts->filetype == FT_TXT) ? "TXT" : "BIN";
    exp_write_dplog(100, "-- FILE TYPE = %s\n", str);

    exp_write_dplog(GS_MAX_FILE_PATH_LENGH + 100, "-- DUMP FILE = %s\n", exp_opts->dump_file);
    exp_write_dplog(GS_MAX_FILE_PATH_LENGH + 100, "-- LOG FILE = %s\n", exp_opts->log_file);
    exp_write_dplog(MAX_EXP_QUERY_SIZE + 1, "-- QUERY = \"%s\"\n", exp_opts->query);

    str = exp_opts->compress ? "Y" : "N";
    exp_write_dplog(100, "-- COMPRESS = %s\n", str);

    if (exp_opts->dn_info.shd_node_type == CS_TYPE_CN) {
        str = exp_opts->dn_info.consistent ? "Y" : "N";
    } else {
        str = exp_opts->consistent ? "Y" : "N";
    }
    exp_write_dplog(100, "-- CONSISTENT = %s\n", str);

    exp_write_dplog(100, "-- CONTENT_MODE = %s\n", content_mode[exp_opts->content - 1]);

    str = exp_opts->skip_comments ? "Y" : "N";
    exp_write_dplog(100, "-- SKIP_COMMENTS = %s\n", str);

    str = exp_opts->force ? "Y" : "N";
    exp_write_dplog(100, "-- FORCE = %s\n", str);

    str = exp_opts->skip_add_drop_table ? "Y" : "N";
    exp_write_dplog(100, "-- SKIP_ADD_DROP_TABLE = %s\n", str);

    str = exp_opts->skip_triggers ? "Y" : "N";
    exp_write_dplog(100, "-- SKIP_TRIGGERS = %s\n", str);

    str = exp_opts->quote_names ? "Y" : "N";
    exp_write_dplog(100, "-- QUOTE_NAMES = %s\n", str);

    str = exp_opts->tablespace ? "Y" : "N";
    exp_write_dplog(100, "-- TABLESPACE = %s\n", str);

    exp_write_dplog(100, "-- COMMIT_BATCH = %u\n", exp_opts->commit_batch);
    exp_write_dplog(100, "-- INSERT_BATCH = %u\n", exp_opts->insert_batch);
    exp_write_dplog(100, "-- FEEDBACK = %u\n", exp_opts->feedback);
    exp_write_dplog(100, "-- PARALLEL = %u\n", exp_opts->parallel);

    str = exp_opts->tenant ? "Y" : "N";
    exp_write_dplog(100, "-- TENANT = %s\n", str);

    str = exp_opts->create_user ? "Y" : "N";
    exp_write_dplog(100, "-- CREATE_USER = %s\n", str);

    str = exp_opts->exp_role ? "Y" : "N";
    exp_write_dplog(100, "-- ROLE = %s\n", str);

    str = exp_opts->is_grant ? "Y" : "N";
    exp_write_dplog(100, "-- GRANT = %s\n", str);
    str = exp_opts->with_cr_mode ? "Y" : "N";
    exp_write_dplog(100, "-- WITH_CR_MODE = %s\n", str);
    str = exp_opts->with_format_csf ? "Y" : "N";
    exp_write_dplog(100, "-- WITH_FORMAT_CSF = %s\n", str);
    exp_print_exclude_info(exp_opts);
    exp_write_dplog(100, "-- INDEX_PARTITIONS = %s\n", exp_opts->index_partitions ? "Y" : "N");

    if (!g_export_opts.show_create_table) { /* show create table option suppresses irrelevant info display */
        exp_write_dplog(100, "\n");
    }
}

static void exp_print_options(export_options_t *exp_opts)
{
    static char *exp_type[] = { "NONE", "SCHEMA", "TABLE", "DIST_RULE", "ALL_DIST_RULES", "ALL_TABLES", "ALL_SCHEMAS" };
    char *str = exp_type[exp_opts->exp_type];

    exp_bin_reset_txtbuf();

    exp_write_dplog(100, "-- EXPORT TYPE = %s\n", str);
    exp_write_dplog(100, "-- EXPORT OBJECTS = ");

    if (exp_opts->obj_list.count > 0) {
        for (uint32 i = 0; i < exp_opts->obj_list.count; i++) {
            if (i != 0) {
                exp_write_dplog(100, ", ");
            }
            str = (char *)cm_list_get(&exp_opts->obj_list, i);
            exp_write_dplog(100, str);
        }
    } else if (exp_opts->exp_tables.table_list.count > 0) {
        for (uint32 i = 0; i < exp_opts->exp_tables.table_list.count; i++) {
            if (i != 0) {
                exp_write_dplog(100, ", ");
            }
            str = (char *)cm_list_get(&exp_opts->exp_tables.table_list, i);
            exp_write_dplog(100, str);
        }
    }
    if (!g_export_opts.show_create_table) { /* show create table option suppresses irrelevant info display */
        exp_write_dplog(100, "\n");
    }

    if (exp_opts->tbs_list.count > 0) {
        exp_write_dplog(100, "-- TABLESPACE FILTER = ");
        for (uint32 i = 0; i < exp_opts->tbs_list.count; i++) {
            if (i != 0) {
                exp_write_dplog(100, ", ");
            }
            str = (char *)cm_list_get(&exp_opts->tbs_list, i);
            exp_write_dplog(100, str);
        }
        if (!g_export_opts.show_create_table) { /* show create table option suppresses irrelevant info display */
            exp_write_dplog(100, "\n");
        }
    }

    exp_print_options_write_dplog(exp_opts, str);
    
    (void)exp_bin_write_str(&g_export_opts.master_bin_mgr, g_exp_txtbuf.str, g_exp_txtbuf.len);
    exp_bin_reset_txtbuf();
}

static status_t exp_set_dba_user(export_options_t *exp_opts)
{
    if (cm_str_equal("SYS", USER_NAME)) {
        exp_opts->is_dba = GS_TRUE;
        return GS_SUCCESS;
    }
     
    GS_RETURN_IFERR(gsql_check_dba_user(&exp_opts->is_dba));
    return GS_SUCCESS;
}

static status_t exp_verify_dist_rule(export_options_t *exp_opts)
{
    char *dist_rule_sql = NULL;
    GS_RETURN_IFERR(exp_set_dba_user(exp_opts));
    if (exp_opts->is_dba) {
        dist_rule_sql = "SELECT 1 "
            " FROM SYS.SYS_USERS U, SYS.SYS_DISTRIBUTE_RULES R "
            " WHERE U.ID = R.UID AND R.NAME = UPPER(:RULE_NAME) LIMIT 1";
    } else {
        dist_rule_sql = "SELECT 1 "
            " FROM " EXP_DISTRIBUTE_RULE_AGENT
            " WHERE NAME = :RULE_NAME LIMIT 1";
    }
    
    list_t *rule_list = &exp_opts->obj_list;
    GS_RETURN_IFERR(gsc_prepare(STMT, dist_rule_sql));
    for (uint32 i = 0; i < rule_list->count; i++) {
        uint32 rows;
        char *rule_name = (char *)cm_list_get(rule_list, i);
        GS_RETURN_IFERR(gsc_bind_by_pos(STMT, 0, GSC_TYPE_STRING, rule_name, (int32)strlen(rule_name), NULL));

        GS_RETURN_IFERR(gsc_execute(STMT));
        GS_RETURN_IFERR(gsc_fetch(STMT, &rows));
        if (rows == 0) {
            EXP_THROW_ERROR(ERR_DISTRIBUTE_RULE_NOT_EXIST, rule_name);
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static int exp_verify_schema(list_t *user_list)
{
    static const char *usr_exist_sql =
        "SELECT 1 "
        "FROM " EXP_USERS_AGENT " "
        "WHERE USERNAME = UPPER(:u) LIMIT 1";

    GS_RETURN_IFERR(gsc_prepare(STMT, usr_exist_sql));

    for (uint32 i = 0; i < user_list->count; i++) {
        uint32 rows;
        char *user = (char *)cm_list_get(user_list, i);
        GS_RETURN_IFERR(gsc_bind_by_pos(STMT, 0, GSC_TYPE_STRING, user, (int32)strlen(user), NULL));

        GS_RETURN_IFERR(gsc_execute(STMT));
        GS_RETURN_IFERR(gsc_fetch(STMT, &rows));
        if (rows == 0) {
            EXP_THROW_ERROR(ERR_USER_NOT_EXIST, user);
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static int exp_verify_tables(export_options_t *exp_opts)
{
    char *table_exist_sql =
        (char *)"SELECT 1 "
        "FROM " EXP_TABLES_AGENT " "
        "WHERE OWNER = UPPER(:O) AND TABLE_NAME = :T limit 1";

    GS_RETURN_IFERR(gsc_prepare(STMT, table_exist_sql));

    for (uint32 i = 0; i < exp_opts->exp_tables.table_list.count; i++) {
        uint32 rows;
        char *tbl_name = (char *)cm_list_get(&exp_opts->exp_tables.table_list, i);
        GS_RETURN_IFERR(gsc_bind_by_pos(STMT, 0, GSC_TYPE_STRING,
            exp_opts->schema_name, (int32)strlen(exp_opts->schema_name), NULL));
        GS_RETURN_IFERR(gsc_bind_by_pos(STMT, 1, GSC_TYPE_STRING, tbl_name, (int32)strlen(tbl_name), NULL));

        GS_RETURN_IFERR(gsc_execute(STMT));
        GS_RETURN_IFERR(gsc_fetch(STMT, &rows));
        if (rows == 0) {
            EXP_THROW_ERROR(ERR_USER_OBJECT_NOT_EXISTS, "table", exp_opts->schema_name, tbl_name);
            return GS_ERROR;
        }
    }

    if (exp_opts->exp_tables.table_exp_type == EXP_TABLE_PARTITION && exp_opts->parallel <= 1) {
        EXP_THROW_ERROR_EX(ERR_CAPABILITY_NOT_SUPPORT, "Export table partition without correct parallel");
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static int exp_verify_tbs_filter(list_t *tbs_list)
{
    static const char *tbs_exist_sql =
        "SELECT 1 "
        "FROM " EXP_DV_TABLESPACES " "
        "WHERE NAME = :T_T LIMIT 1";

    GS_RETURN_IFERR(gsc_prepare(STMT, tbs_exist_sql));

    for (uint32 i = 0; i < tbs_list->count; i++) {
        uint32 rows;
        char *tbs_name = (char *)cm_list_get(tbs_list, i);
        GS_RETURN_IFERR(gsc_bind_by_pos(STMT, 0, GSC_TYPE_STRING, tbs_name, (int32)strlen(tbs_name), NULL));

        GS_RETURN_IFERR(gsc_execute(STMT));
        GS_RETURN_IFERR(gsc_fetch(STMT, &rows));
        if (rows == 0) {
            EXP_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "The tablespace name %s does not exist.", tbs_name);
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static inline int exp_tablespace_filter(export_options_t *exp_opts, const char *user, const char *table)
{
    char *tablespace_filter_sql = NULL;

    if (user == NULL) {
        tablespace_filter_sql =
            (char *)"SELECT TABLESPACE_NAME "
            "FROM " EXP_TABLES_AGENT " "
            "WHERE TABLE_NAME = :TABLE_NAME AND TABLESPACE_NAME = :TABLESPACE_NAME";
    } else {
        tablespace_filter_sql =
            (char *)"SELECT TABLESPACE_NAME "
            "FROM " EXP_TABLES_AGENT " "
            "WHERE TABLE_NAME = :TABLE_NAME AND TABLESPACE_NAME = :TABLESPACE_NAME AND OWNER = UPPER(:OWNER) ";
    }

    GS_RETURN_IFERR(gsc_prepare(STMT, tablespace_filter_sql));

    for (uint32 i = 0; i < exp_opts->tbs_list.count; i++) {
        uint32 rows;
        char *tabspace = (char *)cm_list_get(&(exp_opts->tbs_list), i);

        GS_RETURN_IFERR(gsc_bind_by_pos(STMT, 0, GSC_TYPE_STRING, table, (int32)strlen(table), NULL));
        GS_RETURN_IFERR(gsc_bind_by_pos(STMT, 1, GSC_TYPE_STRING, tabspace, (int32)strlen(tabspace), NULL));

        if (user != NULL) {
            GS_RETURN_IFERR(gsc_bind_by_pos(STMT, 2, GSC_TYPE_STRING, user, (int32)strlen(user), NULL));
        }

        GS_RETURN_IFERR(gsc_execute(STMT));
        GS_RETURN_IFERR(gsc_fetch(STMT, &rows));
        if (rows != 0) {
            return GS_SUCCESS;
        }
    }

    if (user == NULL) {
        exp_tmlog("Warning: the table %s is not in specified tablespace filters.\n", table);
    } else {
        exp_tmlog("Warning: the user %s and table %s are not in specified tablespace filters.\n", user, table);
    }

    return GS_ERROR;
}

static inline int exp_verify_users_opts(export_options_t *exp_opts)
{
    if (exp_opts->exp_type != EXP_SCHEMA && exp_opts->exp_type != EXP_ALL_SCHEMAS && exp_opts->exp_type != EXP_NONE) {
        if (exp_opts->create_user || exp_opts->exp_role || exp_opts->is_grant) {
            gsql_display_export_usage();
            EXP_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "CREATE_USER or ROLE or GRANT parameter does not match");
            return GS_ERROR;
        }
    }
    return GSC_SUCCESS;
}

int exp_verify_partitions_opts(export_options_t *exp_opts)
{
    if (exp_opts->exp_tables.partition_list.count > 0) {
        if (exp_opts->exp_type != EXP_TABLE && exp_opts->exp_type != EXP_ALL_TABLES) {
            EXP_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR,
                "only support exp table partitions, please check the parameter");
            return GS_ERROR;
        }
    }
    return GSC_SUCCESS;
}

static status_t exp_verify_query_opts(export_options_t *exp_opts)
{
    if (exp_opts->query[0] != 0 && (exp_opts->parallel > 1 || exp_opts->filetype == FT_BIN)) {
        EXP_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR,
            "'query' option is not supported when filetype is BIN or parallel > 1");
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

static int exp_verify_opts(export_options_t *exp_opts)
{
    if (!IS_CONN) {
        EXP_THROW_ERROR(ERR_CLT_CONN_CLOSE);
        return GS_ERROR;  // the connection is broken
    }

    GS_RETURN_IFERR(exp_verify_query_opts(exp_opts));
    GS_RETURN_IFERR(exp_verify_users_opts(exp_opts));

    if (exp_opts->tbs_list.count > 0) {
        // verify tablespace name exist or not
        GS_RETURN_IFERR(exp_verify_tbs_filter(&exp_opts->tbs_list));
    }
    GS_RETURN_IFERR(exp_verify_partitions_opts(exp_opts));
    if (exp_opts->exp_type == EXP_NONE) {
        text_t curr_user;

        exp_log(EXP_INDENT "default to export current schema: %s\n", USER_NAME);
        exp_opts->exp_type = EXP_SCHEMA;
        cm_str2text(USER_NAME, &curr_user);
        GS_RETURN_IFERR(gsql_insert_export_obj(exp_opts, &curr_user, GS_TRUE));
    } else if (exp_opts->exp_type == EXP_TABLE) {
        /* 'show create table' option suppresses irrelevant info display */
        if (!g_export_opts.show_create_table) {
            exp_log(EXP_INDENT "verify tables ...\n");
        }
        /* EXP is prohibited in sys schema on DN, unless called by show create table */
        if (cm_str_equal_ins("SYS", exp_opts->schema_name) && !exp_opts->show_create_table) {
            EXP_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "can not export SYS schema");
            return GS_ERROR;
        }
        GS_RETURN_IFERR(exp_verify_tables(exp_opts));
    } else if (exp_opts->exp_type == EXP_ALL_TABLES) {
        /* 'show create table' option suppresses irrelevant info display */
        if (!g_export_opts.show_create_table) {
            exp_log(EXP_INDENT "verify tables ...\n");
        }
        if (cm_str_equal_ins("SYS", exp_opts->schema_name)) {
            EXP_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "can not export SYS schema");
            return GS_ERROR;
        }
    } else if (exp_opts->exp_type == EXP_SCHEMA) {
        exp_log(EXP_INDENT "verify schema ...\n");
        if (!exp_opts->is_myself) {
            GS_RETURN_IFERR(exp_verify_schema(&exp_opts->obj_list));
        }
    } else if (exp_opts->exp_type == EXP_DIST_RULES) {
        exp_log(EXP_INDENT "verify distribute rule ...\n");
        GS_RETURN_IFERR(exp_verify_dist_rule(exp_opts));
    }

    return GS_SUCCESS;
}

static inline void exp_free_filebuf(void)
{
    if (g_exp_fbuf != NULL) {
        free(g_exp_fbuf);
        g_exp_fbuf = NULL;
    }

    if (g_lob_fbuf != NULL) {
        free(g_lob_fbuf);
        g_lob_fbuf = NULL;
    }

    if (g_exp_lob_buff != NULL) {
        free(g_exp_lob_buff);
        g_exp_lob_buff = NULL;
    }
}

static void exp_free_dn_info(exp_shd_info_t *dn_info)
{
    exp_dn_info_t *node_info = NULL;

    // GTS
    if (dn_info->gts_conn_info.stmt != NULL) {
        gsc_free_stmt(dn_info->gts_conn_info.stmt);
        dn_info->gts_conn_info.stmt = NULL;
    }
    if (dn_info->gts_conn_info.conn != NULL) {
        gsc_free_conn(dn_info->gts_conn_info.conn);
        dn_info->gts_conn_info.conn = NULL;
    }

    // DN
    for (uint32 i = 0; i < dn_info->dn_info_list.count; i++) {
        node_info = (exp_dn_info_t *)cm_list_get(&dn_info->dn_info_list, i);

        for (uint32 j = 0; j < node_info->dn_par_conn.par_num; j++) {
            if (node_info->dn_par_conn.stmt[j] != NULL) {
                gsc_free_stmt(node_info->dn_par_conn.stmt[j]);
                node_info->dn_par_conn.stmt[j] = NULL;
            }
            if (node_info->dn_par_conn.conn[j] != NULL) {
                gsc_free_conn(node_info->dn_par_conn.conn[j]);
                node_info->dn_par_conn.conn[j] = NULL;
            }
        }
    }
    cm_reset_list(&dn_info->dn_info_list);
}

static inline void exp_free(export_options_t *exp_opts)
{
    char *filename = exp_opts->dump_file;
    gsql_encrypt_end(&exp_opts->crypt_info, filename);
    exp_close_writer();
    exp_close_logger();
    cm_reset_list(&exp_opts->obj_list);
    cm_reset_list(&exp_opts->tbs_list);
    cm_reset_list(&exp_opts->table_maps);
    cm_reset_list(&exp_opts->exp_tables.table_list);
    cm_reset_list(&exp_opts->exp_tables.partition_list);
    exp_free_filebuf();
    if (exp_opts->dn_info.shd_node_type == CS_TYPE_CN) {
        exp_free_dn_info(&exp_opts->dn_info);
    }
}

status_t gsql_exp_data_write_varchar_s(char *src, text_buf_t *dst, FILE *filehand)
{
    bool32 exist_flag = GS_FALSE;
    char local_buf[GS_MAX_PACKET_SIZE + 1] = { 0 };

    GS_RETURN_IFERR(exp_write_str_s("'", dst, filehand));
    GS_RETURN_IFERR(cm_replace_quotation(src, local_buf, GS_MAX_PACKET_SIZE + 1, &exist_flag));

    if (!exist_flag) {
        GS_RETURN_IFERR(exp_write_str_s(src, dst, filehand));
    } else {
        GS_RETURN_IFERR(exp_write_str_s(local_buf, dst, filehand));
    }
    GS_RETURN_IFERR(exp_write_str_s("'", dst, filehand));

    return GS_SUCCESS;
}

#define CLT_LOB_BUFFER_SIZE SIZE_K(32)

status_t gsql_exp_data_write_clob_s(uint32 column_id, gsc_stmt_t stmt, char *str_buf, text_buf_t *dst,
                                    FILE *filehand)
{
    bool32 exist_flag = GS_FALSE;
    bool32 first_batch = GS_TRUE;
    uint32 nchars = 0;
    uint32 nbytes = 0;
    uint32 eof = GS_FALSE;
    uint32 byte_offset = 0;
    char par_dest_buf[GS_MAX_PACKET_SIZE + 1] = { 0 };
    uint32 size = 0;

    GS_RETURN_IFERR(gsc_get_lob_size_by_id(stmt, column_id, &size));

    if (size > GS_MAX_COLUMN_SIZE) {
        EXP_THROW_ERROR_EX(ERR_LOB_SIZE_TOO_LARGE, "%u, clob column(%u) should use \"filetype=bin\" to export",
                          GS_MAX_COLUMN_SIZE, column_id);
        return GS_ERROR;
    }

    while (eof != GS_TRUE) {
        GS_RETURN_IFERR(gsc_read_clob_by_id(stmt, column_id, byte_offset, str_buf, CLT_LOB_BUFFER_SIZE, &nchars,
                                            &nbytes, &eof));
        str_buf[nbytes] = '\0';
        byte_offset = byte_offset + nbytes;

        if (first_batch) {
            if (nbytes == 0 && eof) {
                GS_RETURN_IFERR(exp_write_str_s("''", dst, filehand));
                return GS_SUCCESS;
            }
            first_batch = GS_FALSE;
            GS_RETURN_IFERR(exp_write_str_s("'", dst, filehand));
        }

        GS_RETURN_IFERR(cm_replace_quotation(str_buf, par_dest_buf, GS_MAX_PACKET_SIZE + 1, &exist_flag));

        GS_RETURN_IFERR(exp_write_str_s((exist_flag ? par_dest_buf : str_buf), dst, filehand));
    }

    GS_RETURN_IFERR(exp_write_str_s("'", dst, filehand));

    return GS_SUCCESS;
}

int gsql_exp_data_write_blob_core(uint32 column_id, gsc_stmt_t stmt, char *str_buf, text_buf_t *dst,
                                  FILE *filehand, uint8 *buf)
{
    uint32 byte_offset = 0;
    uint32 nbytes = 0;
    binary_t bin;
    int ret;
    uint32 eof = GS_FALSE;

    while (eof != GS_TRUE) {
        if (gsc_read_blob_by_id(stmt, column_id, byte_offset, buf, CLT_LOB_BUFFER_SIZE,
            &nbytes, &eof) != GS_SUCCESS) {
            return GS_ERROR;
        }

        bin.bytes = buf;
        bin.size = nbytes;

        if (cm_bin2str(&bin, GS_FALSE, str_buf, nbytes * 2 + 1) != GS_SUCCESS) {
            return GS_ERROR;
        }

        ret = exp_write_str_s(str_buf, dst, filehand);
        if (ret != GS_SUCCESS) {
            return ret;
        }

        byte_offset = byte_offset + nbytes;
    }
    return GS_SUCCESS;
}

int gsql_exp_data_write_blob_s(uint32 column_id, unsigned short col_type, gsc_stmt_t stmt, char *str_buf,
                               text_buf_t *dst, FILE *filehand)
{
    uint8 *buf = NULL;
    uint32 size = 0;
    int32 ret;

    buf = (uint8 *)malloc(CLT_LOB_BUFFER_SIZE);
    if (buf == NULL) {
        GSQL_PRINTF(ZSERR_EXPORT, "malloc databuf failed!");
        return GS_ERROR;
    }

    ret = exp_write_str_s((col_type == GSC_TYPE_BLOB) ? "'" : "X'", dst, filehand);
    if (ret != GS_SUCCESS) {
        CM_FREE_PTR(buf);
        return ret;
    }

    ret = gsc_get_lob_size_by_id(stmt, column_id, &size);
    if (ret != GS_SUCCESS) {
        CM_FREE_PTR(buf);
        return ret;
    }

    if (size > GS_MAX_COLUMN_SIZE) {
        CM_FREE_PTR(buf);
        EXP_THROW_ERROR_EX(ERR_LOB_SIZE_TOO_LARGE, "%u, blob column(%u) should use \"filetype=bin\" to export",
                          GS_MAX_COLUMN_SIZE, column_id);
        return GS_ERROR;
    }
    ret = gsql_exp_data_write_blob_core(column_id, stmt, str_buf, dst, filehand, buf);
    if (ret != GS_SUCCESS) {
        CM_FREE_PTR(buf);
        return ret;
    }

    CM_FREE_PTR(buf);
    GS_RETURN_IFERR(exp_write_str_s("'", dst, filehand));
    return GS_SUCCESS;
}

static status_t gsql_make_insert_sql_s(exporter_t *exporter, char *sql_buf, const char *table_name)
{
    uint32 i;
    int iret_snprintf;
    text_t sql_text = { .str = sql_buf };
    char table_name_s[GSQL_MAX_QUOTE_NAME_SIZE];
    char col_name_s[GSQL_MAX_QUOTE_NAME_SIZE];
    text_t table_name_t;
    text_t column_name_t;

    if (g_export_opts.filetype == FT_BIN) {
        return GS_SUCCESS;
    }

    table_name_t.str = table_name_s;
    table_name_t.len = 0;
    column_name_t.str = col_name_s;

    if (exporter->col_num == 0) {
        GSQL_PRINTF(ZSERR_EXPORT, "assert raised, expect: exporter->col_num(%u) > 0", exporter->col_num);
        return GS_ERROR;
    }

    (void)exp_concat_str_quote(&table_name_t, table_name);
    table_name_t.str[table_name_t.len] = '\0';
    iret_snprintf = snprintf_s(sql_text.str, MAX_SQL_SIZE, GSQL_MAX_TEMP_SQL, "INSERT INTO %s (",
        exp_remap_table_name(&g_export_opts.table_maps, table_name_t.str, NULL, 0));
    PRTS_RETURN_IFERR(iret_snprintf);
    sql_text.len = iret_snprintf;
    for (i = 0; i < exporter->col_num; i++) {
        if (i != 0) {  // more than columns
            CM_TEXT_APPEND(&sql_text, ',');
        }

        col_name_s[0] = '\0';
        column_name_t.len = 0;
        (void)exp_concat_str_quote(&column_name_t, exporter->col_desc[i].name);
        column_name_t.str[column_name_t.len] = '\0';
        iret_snprintf = snprintf_s(sql_text.str + sql_text.len, MAX_SQL_SIZE - sql_text.len,
                                   GSQL_MAX_TEMP_SQL, "%s", column_name_t.str);
        PRTS_RETURN_IFERR(iret_snprintf);
        sql_text.len += iret_snprintf;
    }

    iret_snprintf = snprintf_s(sql_text.str + sql_text.len, MAX_SQL_SIZE - sql_text.len,
                               GSQL_MAX_TEMP_SQL, ") values\n");
    PRTS_RETURN_IFERR(iret_snprintf);
    sql_text.len += iret_snprintf;

    return GS_SUCCESS;
}

static inline void exp_bin_inc_rec_total(uint64 *tab_record_total, uint64 file_insert_num, thread_lock_t *lock)
{
    if (lock != NULL) {  // parallel binary export
        cm_thread_lock(lock);
        *(tab_record_total) += file_insert_num;
        cm_thread_unlock(lock);

        return;
    } else {
        *(tab_record_total) = file_insert_num;
    }
}

static inline status_t exp_bin_write_tab_fields_df(exporter_t *exporter, text_buf_t *dst, FILE *filehand,
                                                   gsc_z_stream *stream)
{
    uint16 i, shrt_len;
    uint16 count = (uint16)exporter->col_num;

    // total of table fields
    GS_RETURN_IFERR(exp_writer_bin_data_s((char *)&count, sizeof(int16), dst, filehand, stream));
    for (i = 0; i < count; i++) {
        shrt_len = (uint16)strlen(exporter->col_desc[i].name);
        // field name len
        GS_RETURN_IFERR(exp_writer_bin_data_s((char *)&shrt_len, sizeof(uint16), dst, filehand, stream));
        // field name
        GS_RETURN_IFERR(exp_writer_bin_data_s(exporter->col_desc[i].name, shrt_len, dst, filehand, stream));
        // field type
        GS_RETURN_IFERR(exp_writer_bin_data_s((char *)&(exporter->col_desc[i].type), sizeof(int16),
                                              dst, filehand, stream));
        // field size
        GS_RETURN_IFERR(exp_writer_bin_data_s((char *)&(exporter->col_desc[i].size), sizeof(int16),
                                              dst, filehand, stream));
        // field is_array
        GS_RETURN_IFERR(exp_writer_bin_data_s((char *)&(exporter->col_desc[i].is_array), sizeof(uchar),
                                              dst, filehand, stream));
    }
    return GS_SUCCESS;
}

static int exp_init_columns(exporter_t *exporter, gsc_stmt_t stmt, exp_cache_t *table_cache)
{
    uint32 i;
    lob_col_desc_t *col_desc = NULL;
    exp_cache_column_info_t* column_info = NULL;

    GS_RETURN_IFERR(gsc_get_column_count(stmt, &exporter->col_num));

    GS_RETURN_IFERR(exp_start_cache_unit(table_cache, EXP_CACHE_COLUMN_INFO));

    for (i = 0; i < exporter->col_num; i++) {
        GS_RETURN_IFERR(gsc_desc_inner_column_by_id(stmt, i, &(exporter->col_desc[i])));

        if (g_export_opts.filetype == FT_BIN) {
            /* cache column info */
            GS_RETURN_IFERR(alloc_column_cache_info(table_cache, &column_info));
            MEMS_RETURN_IFERR(strncpy_s(column_info->name, sizeof(column_info->name),
                exporter->col_desc[i].name, strlen(exporter->col_desc[i].name)));

            column_info->size = exporter->col_desc[i].size;
            column_info->type = exporter->col_desc[i].type;
            column_info->is_array = exporter->col_desc[i].is_array;

            if (GSQL_IS_LOB_TYPE(exporter->col_desc[i].type) || exporter->col_desc[i].is_array) {
                GS_RETURN_IFERR(cm_list_new(&exporter->lob_cols, (void **)&col_desc));
                col_desc->col_desc = exporter->col_desc[i];
                col_desc->col_id = i;
            }
        }
    }

    return GS_SUCCESS;
}

static inline int exp_data_write_binary(binary_t *bin, char *str_buf, text_buf_t *exp_txtbuf, FILE *exp_dpfile)
{
    GS_RETURN_IFERR(cm_bin2str(bin, GS_TRUE, str_buf, GS_MAX_COLUMN_SIZE * 2 + 1));
    GS_RETURN_IFERR(exp_write_str_s(str_buf, exp_txtbuf, exp_dpfile));
    return GS_SUCCESS;
}

static inline int exp_table_txt_row(text_buf_t *exp_txtbuf,
                                    gsc_stmt_t stmt,
                                    char *sql_buf,
                                    char *str_buf,
                                    FILE *exp_dpfile,
                                    exporter_t *exporter)
{
    void *data = NULL;
    uint32 i, size;
    bool32 is_null = GS_FALSE;
    binary_t bin;
    clt_column_t *column = NULL;

    for (i = 0; i < exporter->col_num; i++) {
        if (i != 0) {
            GS_RETURN_IFERR(exp_write_str_s(",", exp_txtbuf, exp_dpfile));
        }

        (void)gsc_get_column_by_id(stmt, i, &data, &size, &is_null);
        if (is_null) {
            GS_RETURN_IFERR(exp_write_str_s("null", exp_txtbuf, exp_dpfile));
            continue;
        }
        if (size == 0) {
            GS_RETURN_IFERR(exp_write_str_s("''", exp_txtbuf, exp_dpfile));
            continue;
        }

        column = (clt_column_t *)cm_list_get(&((clt_stmt_t *)stmt)->columns, i);
        if (column->def.is_array) {
            GS_RETURN_IFERR(gsc_column_as_array(stmt, i, str_buf, GS_MAX_PACKET_SIZE));
            GS_RETURN_IFERR(exp_write_str_s(str_buf, exp_txtbuf, exp_dpfile));
            continue;
        }

        switch (exporter->col_desc[i].type) {
            case GSC_TYPE_BINARY:
                bin.bytes = (uint8 *)data;
                bin.size = size;
                cm_rtrim0_binary(&bin);
                GS_RETURN_IFERR(exp_data_write_binary(&bin, str_buf, exp_txtbuf, exp_dpfile));
                break;

            case GSC_TYPE_VARBINARY:
                bin.bytes = (uint8 *)data;
                bin.size = size;
                GS_RETURN_IFERR(exp_data_write_binary(&bin, str_buf, exp_txtbuf, exp_dpfile));
                break;

            case GSC_TYPE_CLOB:
                GS_RETURN_IFERR(gsql_exp_data_write_clob_s(i, stmt, str_buf, exp_txtbuf, exp_dpfile));
                break;

            case GSC_TYPE_BLOB:
            case GSC_TYPE_IMAGE:
                if (gsc_get_call_version(CONN) >= CS_VERSION_24 && column->def.is_jsonb) {
                    EXP_THROW_ERROR_EX(ERR_JSONB_EXP_ERROR, "jsonb column should use \"filetype=bin\" to export");
                    return GS_ERROR;
                }
                GS_RETURN_IFERR(gsql_exp_data_write_blob_s(i, exporter->col_desc[i].type, stmt, str_buf, exp_txtbuf,
                                                              exp_dpfile));
                break;

            case GSC_TYPE_VARCHAR:
            case GSC_TYPE_CHAR:
            case GSC_TYPE_STRING:
            case GSC_TYPE_DATE:
            case GSC_TYPE_TIMESTAMP:
            case GSC_TYPE_TIMESTAMP_TZ_FAKE:
            case GSC_TYPE_TIMESTAMP_TZ:
            case GSC_TYPE_TIMESTAMP_LTZ:
            case GSC_TYPE_RAW:
            case GSC_TYPE_INTERVAL:
            case GSC_TYPE_INTERVAL_DS:
            case GSC_TYPE_INTERVAL_YM:
                (void)gsc_column_as_string(stmt, i, str_buf, GS_MAX_PACKET_SIZE);
                GS_RETURN_IFERR(gsql_exp_data_write_varchar_s(str_buf, exp_txtbuf, exp_dpfile));
                break;

            default:
                (void)gsc_column_as_string(stmt, i, str_buf, GS_MAX_PACKET_SIZE);
                GS_RETURN_IFERR(exp_write_str_s(str_buf, exp_txtbuf, exp_dpfile));
                break;
        }
    }

    return GS_SUCCESS;
}

static int exp_write_txt_records(text_buf_t *exp_txtbuf,
                                 gsc_stmt_t stmt,
                                 char *sql_buf,
                                 char *str_buf,
                                 FILE *exp_dpfile,
                                 exporter_t *exporter,
                                 bool32 par_flag,
                                 uint64 *file_insert_num)
{
    uint32 rows;

    GS_RETURN_IFERR(gsc_fetch(stmt, &rows));
    while (rows > 0) {
        // if cancel, stop export
        EXP_RETRUN_IF_CANCEL;
        if (*file_insert_num % g_export_opts.insert_batch == 0) {
            GS_RETURN_IFERR(exp_write_str_s(sql_buf, exp_txtbuf, exp_dpfile));
            GS_RETURN_IFERR(exp_write_str_s(EXP_INDENT "(", exp_txtbuf, exp_dpfile));
        } else {
            GS_RETURN_IFERR(exp_write_str_s(",\n" EXP_INDENT "(", exp_txtbuf, exp_dpfile));
        }

        GS_RETURN_IFERR(exp_table_txt_row(exp_txtbuf, stmt, sql_buf, str_buf, exp_dpfile, exporter));

        GS_RETURN_IFERR(exp_write_str_s(")", exp_txtbuf, exp_dpfile));

        *file_insert_num += 1;

        if (*file_insert_num % g_export_opts.insert_batch == 0) {
            GS_RETURN_IFERR(exp_write_str_s(";\n", exp_txtbuf, exp_dpfile));
        }

        GS_RETURN_IFERR(gsc_fetch(stmt, &rows));

        if (g_export_opts.commit_batch != 0 &&
            *file_insert_num % (g_export_opts.commit_batch * g_export_opts.insert_batch) == 0) {
            GS_RETURN_IFERR(exp_write_str_s("COMMIT;\n", exp_txtbuf, exp_dpfile));
        }

        if (par_flag == GS_FALSE) {
            if (g_export_opts.feedback != 0 && *file_insert_num %
                (g_export_opts.feedback * g_export_opts.insert_batch) == 0) {
                exp_log(EXP_INDENT2 "%llu rows are dumped.\n", *file_insert_num);
            }
        }
    }

    return GS_SUCCESS;
}

static int exp_bin_write_clob(uint32 column_id, gsc_stmt_t stmt, char *locator, text_buf_t *dst,
                              exp_bin_file_ctx_t *file_ctx, text_buf_t *data_buffer)
{
    uint32 nchars = 0;
    uint32 nbytes = 0;
    uint32 eof = GS_FALSE;
    uint32 byte_offset = 0;
    char *dest_buf = NULL;
    int status = GS_SUCCESS;

    if (data_buffer != NULL) {
        dest_buf = data_buffer->str;
    }

    if (dest_buf == NULL) {
        GSQL_PRINTF(ZSERR_EXPORT, "exp clob buffer not init !");
        return GS_ERROR;
    }

    while (eof != GS_TRUE) {
        status = gsc_read_clob(stmt, (void *)locator, byte_offset, dest_buf, data_buffer->max_size, &nchars, &nbytes,
                               &eof);
        GS_BREAK_IF_ERROR(status);

        if (nbytes > 0) {
            status = exp_writer_bin_data_s(dest_buf, nbytes, dst, file_ctx->lf_h, file_ctx->lf_zstream);
            GS_BREAK_IF_ERROR(status);
            byte_offset = byte_offset + nbytes;
        }
    }

    return status;
}

static int exp_bin_write_blob(uint32 column_id, gsc_stmt_t stmt, char *locator, text_buf_t *dst,
                              exp_bin_file_ctx_t *file_ctx, text_buf_t *data_buffer)
{
    uint32 nbytes = 0;
    uint32 eof = GS_FALSE;
    uint32 byte_offset = 0;
    char *buf = NULL;
    int status = GS_SUCCESS;

    if (data_buffer != NULL) {
        buf = data_buffer->str;
    }

    if (buf == NULL) {
        GSQL_PRINTF(ZSERR_EXPORT, "exp blob buffer not init !");
        return GS_ERROR;
    }

    while (eof != GS_TRUE) {
        status = gsc_read_blob(stmt, (void *)locator, byte_offset, buf, data_buffer->max_size, &nbytes, &eof);
        GS_BREAK_IF_ERROR(status);

        if (nbytes > 0) {
            status = exp_writer_bin_data_s((char *)buf, nbytes, dst, file_ctx->lf_h, file_ctx->lf_zstream);
            GS_BREAK_IF_ERROR(status);
            byte_offset = byte_offset + nbytes;
        }
    }

    return status;
}

#define GSQL_MAX_LOCATOR_SIZE 128

static inline status_t exp_redirect_lob_locator(exp_bin_file_ctx_t *file_ctx,
                                                gsc_stmt_t stmt,
                                                lob_col_desc_t *clob_col,
                                                char *locator,
                                                uint32 loc_sz,
                                                uint32 really_sz)
{
    uint32 name_size;
    uint32 loc_offset = 0;
    char tmp_loc[GSQL_MAX_LOCATOR_SIZE];
    char *ptr_tmp = tmp_loc;
    int ret;
    if (loc_sz > GSQL_MAX_LOCATOR_SIZE) {
        EXP_THROW_ERROR(ERR_BUFFER_OVERFLOW, loc_sz, GSQL_MAX_LOCATOR_SIZE);
        return GS_ERROR;
    }

    MEMS_RETURN_IFERR(memcpy_s(tmp_loc, loc_sz, locator, loc_sz));

    *(uint32 *)locator = GS_INVALID_ID32;  // redirect flag:0xFFFFFFFF
    loc_offset += sizeof(uint32);
    *(uint64 *)(locator + loc_offset) = file_ctx->bin_file_size;  // lob file offset
    loc_offset += sizeof(uint64);
    name_size = (uint32)strlen(file_ctx->lf_name);
    *(uint16 *)(locator + loc_offset) = name_size;
    loc_offset += sizeof(uint16);

    MEMS_RETURN_IFERR(memcpy_s(locator + loc_offset, (loc_sz - loc_offset), file_ctx->lf_name, name_size));

    GS_RETURN_IFERR(exp_writer_bin_data_s((char *)&really_sz, sizeof(uint32), &file_ctx->bin_lob_buf,
                                          file_ctx->lf_h, file_ctx->lf_zstream));

    if (clob_col->col_desc.type == GSC_TYPE_CLOB || clob_col->col_desc.is_array) {
        ret = exp_bin_write_clob(clob_col->col_id, stmt, ptr_tmp, &file_ctx->bin_lob_buf, file_ctx,
                                 &file_ctx->bin_lob_data_buf);
    } else {
        ret = exp_bin_write_blob(clob_col->col_id, stmt, ptr_tmp, &file_ctx->bin_lob_buf, file_ctx,
                                 &file_ctx->bin_lob_data_buf);
    }

    if (ret != GSC_SUCCESS) {
        return ret;
    }
    file_ctx->bin_file_size += really_sz + sizeof(uint32);
    return GS_SUCCESS;
}

static int exp_bin_write_lob(exp_bin_file_ctx_t *bin_file_ctx, gsc_stmt_t stmt, exporter_t *exporter, char *row)
{
    uint16 size = 0;
    uint32 i;
    lob_col_desc_t *clob_col = NULL;
    void *locator = NULL;
    uint32 really_size, outline, locator_size, row_cols;

    bin_file_ctx->decode_count = exporter->col_num;
    row_cols = cm_decode_row_imp(row, bin_file_ctx->offsets, bin_file_ctx->lens, &size);

    for (i = 0; i < exporter->lob_cols.count; ++i) {
        clob_col = (lob_col_desc_t *)cm_list_get(&exporter->lob_cols, i);
        if ((clob_col->col_id >= row_cols) || bin_file_ctx->lens[clob_col->col_id] == GS_NULL_VALUE_LEN) {
            continue;
        }
        locator = (void *)(row + bin_file_ctx->offsets[clob_col->col_id]);
        (void)gsc_get_locator_info(stmt, locator, &outline, &really_size, &locator_size);
        if (!outline) {
            continue;
        }

        GS_RETURN_IFERR(exp_redirect_lob_locator(bin_file_ctx, stmt, clob_col, locator, locator_size, really_size));
        bin_file_ctx->wr_lob_flag = GS_TRUE;
    }

    return GS_SUCCESS;
}

static int exp_write_bin_records(exp_bin_file_ctx_t *bfile_ctx,
                                 gsc_stmt_t stmt,
                                 char *str_buf,
                                 exporter_t *exporter,
                                 thread_lock_t *lock,
                                 uint64 *file_insert_num)
{
    uint32 rows, size;
    void *data = NULL;
    uint16 shrt_len = (uint16)strlen(bfile_ctx->tab_name);

    GS_RETURN_IFERR(exp_writer_bin_data_s((char *)&shrt_len, sizeof(uint16), &bfile_ctx->bin_data_buf,
        bfile_ctx->df_h, bfile_ctx->df_zstream));  // table name len
    GS_RETURN_IFERR(exp_writer_bin_data_s(bfile_ctx->tab_name, shrt_len, &bfile_ctx->bin_data_buf,
        bfile_ctx->df_h, bfile_ctx->df_zstream));  // table name

    GS_RETURN_IFERR(exp_bin_write_tab_fields_df(exporter, &bfile_ctx->bin_data_buf,
        bfile_ctx->df_h, bfile_ctx->df_zstream));  // table fields

    GS_RETURN_IFERR(gsc_fetch_ori_row(stmt, &rows));
    while (rows > 0) {
        // if cancel, stop export
        EXP_RETRUN_IF_CANCEL;
        GS_RETURN_IFERR(gsc_read_ori_row(stmt, &data, &size));
        *file_insert_num += 1;
        if (exporter->lob_cols.count == 0) {
            GS_RETURN_IFERR(exp_writer_bin_data_s((char *)data, size, &bfile_ctx->bin_data_buf,
                                                  bfile_ctx->df_h, bfile_ctx->df_zstream));
        } else {
            MEMS_RETURN_IFERR(memcpy_s(str_buf, GS_MAX_PACKET_SIZE, data, size));
            GS_RETURN_IFERR(exp_bin_write_lob(bfile_ctx, stmt, exporter, str_buf));
            GS_RETURN_IFERR(exp_writer_bin_data_s((char *)str_buf, size, &bfile_ctx->bin_data_buf,
                                                  bfile_ctx->df_h, bfile_ctx->df_zstream));
        }

        GS_RETURN_IFERR(gsc_fetch_ori_row(stmt, &rows));

        if (lock == NULL) {
            if (g_export_opts.feedback != 0 && *file_insert_num %
                (g_export_opts.feedback * g_export_opts.insert_batch) == 0) {
                exp_log(EXP_INDENT2 "%llu rows are dumped.\n", *file_insert_num);
            }
        }
    }

    exp_bin_inc_rec_total(exporter->tab_record_total, *file_insert_num, lock);
    GS_RETURN_IFERR(exp_flush_bin_data_s(&bfile_ctx->bin_data_buf, bfile_ctx->df_h, bfile_ctx->df_zstream));

    if (gsql_reset_crypfile(bfile_ctx->df_h, &g_export_opts.crypt_info) != GS_SUCCESS) {
        GSQL_PRINTF(ZSERR_EXPORT, "failed to reset decrypt file fp !");
    }

    GS_RETURN_IFERR(exp_flush_bin_data_s(&bfile_ctx->bin_lob_buf, bfile_ctx->lf_h, bfile_ctx->lf_zstream));

    if (gsql_reset_crypfile(bfile_ctx->lf_h, &g_export_opts.crypt_info) != GS_SUCCESS) {
        GSQL_PRINTF(ZSERR_EXPORT, "failed to reset decrypt file fp !");
    }

    return GS_SUCCESS;
}

static inline int exp_pre_query_sql(gsc_stmt_t stmt, char *sql_buf, const char *schema_name, const char *table_name)
{
    int ret = 0;
    uint32 sql_len = 0;
    uint32 part_no = GS_INVALID_ID32;

    if (g_export_opts.filetype == FT_BIN) {
        ret = sprintf_s(sql_buf, MAX_SQL_SIZE,
                        "SELECT /*+full(%s)*/ * FROM table(get_tab_rows('\"%s\".\"%s\"', ?, ?, ?))",
                        table_name, schema_name, table_name);
        PRTS_RETURN_IFERR(ret);
        sql_len = ret;

        if (g_export_opts.query[0] != '\0') {
            ret = sprintf_s(sql_buf + sql_len, MAX_SQL_SIZE - sql_len, " %s", g_export_opts.query);
            PRTS_RETURN_IFERR(ret);
        }

        GS_RETURN_IFERR(gsc_prepare(stmt, sql_buf));

        GS_RETURN_IFERR(gsc_bind_by_pos(stmt, 0, GSC_TYPE_INTEGER, &part_no, sizeof(uint32), NULL));
        GS_RETURN_IFERR(gsc_bind_by_pos(stmt, 1, GSC_TYPE_BIGINT, &g_exp_scn, sizeof(uint64), NULL));
        GS_RETURN_IFERR(gsc_bind_by_pos(stmt, 2, GSC_TYPE_STRING, "NULL", 4, NULL));

        return GS_SUCCESS;
    }

    // the codes for TXT mode
    ret = sprintf_s(sql_buf, MAX_SQL_SIZE, "SELECT * FROM \"%s\".\"%s\"", schema_name, table_name);
    PRTS_RETURN_IFERR(ret);
    sql_len = ret;

    if (g_export_opts.consistent) {
        ret = sprintf_s(sql_buf + sql_len, MAX_SQL_SIZE - sql_len, " AS OF SCN(%llu)", g_exp_scn);
        PRTS_RETURN_IFERR(ret);
        sql_len += ret;
    }

    if (g_export_opts.query[0] != '\0') {
        ret = sprintf_s(sql_buf + sql_len, MAX_SQL_SIZE - sql_len, " %s", g_export_opts.query);
        PRTS_RETURN_IFERR(ret);
    }

    GS_RETURN_IFERR(gsc_prepare(stmt, sql_buf));

    return GS_SUCCESS;
}

static inline int par_exp_pre_query_sql_normaltab(par_exp_thread_ctrl_t *thread_ctrl, gsc_stmt_t stmt,
    char *sql_buf, char *schema_name, char *table_name)
{
    if (g_export_opts.filetype == FT_TXT) {
        PRTS_RETURN_IFERR(sprintf_s(sql_buf, MAX_SQL_SIZE, "SELECT /*+full(%s)*/ * FROM table(parallel_scan('\"%s\".\"%s\"', ?, ?, ?, ?))",
            table_name, schema_name, table_name));

        GS_RETURN_IFERR(gsc_prepare(stmt, sql_buf));

        GS_RETURN_IFERR(gsc_bind_by_pos(stmt, 0, GSC_TYPE_BIGINT,
            &thread_ctrl->tab_param.scn, sizeof(uint64), NULL));
        GS_RETURN_IFERR(gsc_bind_by_pos(stmt, 1, GSC_TYPE_BIGINT,
            &thread_ctrl->tab_param.scan_param.l_page, sizeof(uint64), NULL));
        GS_RETURN_IFERR(gsc_bind_by_pos(stmt, 2, GSC_TYPE_BIGINT,
            &thread_ctrl->tab_param.scan_param.r_page, sizeof(uint64), NULL));
        GS_RETURN_IFERR(gsc_bind_by_pos(stmt, 3, GSC_TYPE_INTEGER,
            &thread_ctrl->tab_param.scan_param.part_no, sizeof(uint32), NULL));
    } else {
        PRTS_RETURN_IFERR(sprintf_s(sql_buf, MAX_SQL_SIZE,
            "SELECT /*+full(%s)*/ * FROM table(get_tab_rows('\"%s\".\"%s\"', ?, ?, ?, ?, ?))",
            table_name, schema_name, table_name));

        GS_RETURN_IFERR(gsc_prepare(stmt, sql_buf));

        GS_RETURN_IFERR(gsc_bind_by_pos(stmt, 0, GSC_TYPE_INTEGER,
            &thread_ctrl->tab_param.scan_param.part_no, sizeof(uint32), NULL));
        GS_RETURN_IFERR(gsc_bind_by_pos(stmt, 1, GSC_TYPE_BIGINT,
            &thread_ctrl->tab_param.scn, sizeof(uint64), NULL));
        GS_RETURN_IFERR(gsc_bind_by_pos(stmt, 2, GSC_TYPE_STRING, "NULL", 4, NULL));
        GS_RETURN_IFERR(gsc_bind_by_pos(stmt, 3, GSC_TYPE_BIGINT,
            &thread_ctrl->tab_param.scan_param.l_page, sizeof(uint64), NULL));
        GS_RETURN_IFERR(gsc_bind_by_pos(stmt, 4, GSC_TYPE_BIGINT,
            &thread_ctrl->tab_param.scan_param.r_page, sizeof(uint64), NULL));
    }
    return GS_SUCCESS;
}

static inline int par_exp_pre_query_sql(par_exp_thread_ctrl_t *thread_ctrl)
{
    char *sql_buf = thread_ctrl->files_context.sql_buf;
    char *schema_name = thread_ctrl->tab_param.schema;
    char *table_name = thread_ctrl->tab_param.tab_name;
    uint32 part_no = GS_INVALID_ID32;
    gsc_stmt_t stmt;
    if (thread_ctrl->tab_param.is_coordinator) {
        stmt = thread_ctrl->tab_param.stmt;
    } else {
        stmt = thread_ctrl->conn_info.stmt;
    }

    if (thread_ctrl->tab_param.scan_param.normal_tab) {
        GS_RETURN_IFERR(par_exp_pre_query_sql_normaltab(thread_ctrl, stmt, sql_buf, schema_name, table_name));
    } else { /* Temporary tables, views */
        if (g_export_opts.filetype == FT_TXT) {
            PRTS_RETURN_IFERR(sprintf_s(sql_buf, MAX_SQL_SIZE, "SELECT * FROM \"%s\".\"%s\"", schema_name, table_name));
            GS_RETURN_IFERR(gsc_prepare(stmt, sql_buf));
        } else {
            PRTS_RETURN_IFERR(sprintf_s(sql_buf, MAX_SQL_SIZE,
                "SELECT /*+full(%s)*/ * FROM table(get_tab_rows('\"%s\".\"%s\"', ?, ?, ?))",
                table_name, schema_name, table_name));

            GS_RETURN_IFERR(gsc_prepare(stmt, sql_buf));

            GS_RETURN_IFERR(gsc_bind_by_pos(stmt, 0, GSC_TYPE_INTEGER, &part_no, sizeof(uint32), NULL));
            GS_RETURN_IFERR(gsc_bind_by_pos(stmt, 1, GSC_TYPE_BIGINT, &thread_ctrl->tab_param.scn,
                                            sizeof(uint64), NULL));
            GS_RETURN_IFERR(gsc_bind_by_pos(stmt, 2, GSC_TYPE_STRING, "NULL", 4, NULL));
        }
    }
    return GS_SUCCESS;
}

static int par_exp_table_records_core(par_exp_thread_ctrl_t *thread_ctrl, uint64 *file_insert_num,
    bool32 *wr_lob_flg, exporter_t *exporter, gsc_stmt_t stmt)
{
    char *sql_buf = thread_ctrl->files_context.sql_buf;
    char *str_buf = thread_ctrl->files_context.str_buf;
    exp_bin_file_ctx_t bin_file_ctx;

    if (g_export_opts.filetype == FT_TXT) {
        GS_RETURN_IFERR(gsql_make_insert_sql_s(exporter, thread_ctrl->files_context.sql_buf,
            exp_remap_table_name(&thread_ctrl->options.table_maps, thread_ctrl->tab_param.tab_name,
                thread_ctrl->tab_param.tab_name, sizeof(thread_ctrl->tab_param.tab_name))));
        GS_RETURN_IFERR(exp_write_txt_records(&thread_ctrl->files_context.exp_txtbuf,
                                              stmt,
                                              sql_buf,
                                              str_buf,
                                              thread_ctrl->files_context.exp_dpfile,
                                              exporter,
                                              GS_TRUE,
                                              file_insert_num));

        if (g_export_opts.commit_batch == 0 ||
            *file_insert_num % (g_export_opts.commit_batch * g_export_opts.insert_batch) != 0) {
            if (*file_insert_num % g_export_opts.insert_batch != 0) {
                GS_RETURN_IFERR(exp_write_str_s(";\n", &thread_ctrl->files_context.exp_txtbuf,
                    thread_ctrl->files_context.exp_dpfile));
            }
            GS_RETURN_IFERR(exp_write_str_s("COMMIT;\n", &thread_ctrl->files_context.exp_txtbuf,
                thread_ctrl->files_context.exp_dpfile));
        }
    } else {
        GS_RETURN_IFERR(par_exp_init_bfile_ctx(&bin_file_ctx, thread_ctrl));
        if (g_export_opts.compress) {
            bin_file_ctx.df_zstream = &thread_ctrl->files_context.df_zstream;
            bin_file_ctx.lf_zstream = &thread_ctrl->files_context.lf_zstream;
        } else {
            bin_file_ctx.df_zstream = NULL;
            bin_file_ctx.lf_zstream = NULL;
        }
        GS_RETURN_IFERR(exp_write_bin_records(&bin_file_ctx, stmt, str_buf, exporter, thread_ctrl->lock_t,
            file_insert_num));
        *wr_lob_flg = bin_file_ctx.wr_lob_flag;
    }

    return GS_SUCCESS;
}

static int par_exp_table_records(par_exp_thread_ctrl_t *thread_ctrl, uint64 *file_insert_num, bool32 *wr_lob_flg)
{
    uint32 prefetch_rows = 2000;
    gsc_stmt_t stmt;
    if (thread_ctrl->tab_param.is_coordinator) {
        stmt = thread_ctrl->tab_param.stmt;
    } else {
        if (!thread_ctrl->conn_info.is_conn) {
            (void)gsql_print_disconn_error();
            return GS_ERROR;
        }
        stmt = thread_ctrl->conn_info.stmt;
    }
    exporter_t *exporter = &thread_ctrl->cols_def->exporter;

    *file_insert_num = 0;
    *wr_lob_flg = GS_FALSE;

    GS_RETURN_IFERR(gsc_set_stmt_attr(stmt, GSC_ATTR_PREFETCH_ROWS, &prefetch_rows, 0));
    GS_RETURN_IFERR(par_exp_pre_query_sql(thread_ctrl));

    exporter->tab_record_total = thread_ctrl->bin_rec_total_add;

    GS_RETURN_IFERR(gsc_execute(stmt));

    if (par_exp_get_init_cols(thread_ctrl) == GS_FALSE) {
        cm_thread_lock(thread_ctrl->lock_t);
        if (par_exp_get_init_cols(thread_ctrl) == GS_FALSE) {
            if (exp_init_columns(exporter, stmt, thread_ctrl->tab_param.table_cache) != GS_SUCCESS) {
                cm_thread_unlock(thread_ctrl->lock_t);
                return GS_ERROR;
            }
        }
        par_exp_set_init_cols(thread_ctrl, GS_TRUE);
        cm_thread_unlock(thread_ctrl->lock_t);
    }

    return par_exp_table_records_core(thread_ctrl, file_insert_num, wr_lob_flg, exporter, stmt);
}

static inline status_t exp_table_records_deal(exporter_t *exporter)
{
    if (g_export_opts.filetype == FT_TXT) {
        if (g_export_opts.commit_batch == 0 ||
            exporter->file_insert_num % (g_export_opts.commit_batch * g_export_opts.insert_batch) != 0) {
            if (exporter->file_insert_num % g_export_opts.insert_batch != 0) {
                GS_RETURN_IFERR(exp_write_str_s(";\n", &g_exp_txtbuf, g_exp_dpfile));
            }
            GS_RETURN_IFERR(exp_write_str_s("COMMIT;\n", &g_exp_txtbuf, g_exp_dpfile));
        }
    }

    if (!g_export_opts.show_create_table) {
        exp_log(EXP_INDENT2 "data exporting success, %llu rows are dumped.\n", exporter->file_insert_num);
    }
    return GS_SUCCESS;
}

static int exp_table_records(export_options_t *exp_opts, const char *schema_name, const char *table_name,
                             exporter_t *exporter, exp_cache_t* table_cache)
{
    exp_bin_file_ctx_t bin_file_ctx;
    uint64 tmp_insert_num = 0;
    char* subfile = NULL;
    bool32 is_first = GS_TRUE;
    gsc_stmt_t stmt;
    exp_dn_info_t *node_info = NULL;

    exp_tab_dist_info_t tab_dist_info;

    MEMS_RETURN_IFERR(memset_s(&tab_dist_info, sizeof(exp_tab_dist_info_t), 0, sizeof(exp_tab_dist_info_t)));

    if (!IS_CONN) {
        (void)gsql_print_disconn_error();
        return GS_ERROR;
    }

    GS_RETURN_IFERR(exp_start_cache_unit(table_cache, EXP_CACHE_TABLE_NAME));
    GS_RETURN_IFERR(exp_cache_append_str(table_cache,
        exp_remap_table_name(&exp_opts->table_maps, table_name, NULL, 0))); // table name

    exporter->tab_record_total = &table_cache->record_cnt;  // table record total address

    /* 'show create table' option suppresses irrelevant info display */
    if (!g_export_opts.show_create_table) {
        exp_log(EXP_INDENT "exporting data of %s.%s ...\n", schema_name, table_name);
    }

    for (uint32 num = 0; num < exp_opts->dn_info.dn_info_list.count; num++) {
        node_info = (exp_dn_info_t *)cm_list_get(&exp_opts->dn_info.dn_info_list, num);
        if (node_info->dn_conn_info.conn == NULL) {
            (void)gsql_print_disconn_error();
            return GS_ERROR;
        }
        // using the DN stmt
        stmt = node_info->dn_conn_info.stmt;
        GS_RETURN_IFERR(exp_bin_init_data_file(exp_opts, table_name, schema_name));
        GS_RETURN_IFERR(exp_pre_query_sql(stmt, g_sql_buf, schema_name, table_name));
        GS_RETURN_IFERR(gsc_execute(stmt));

        // only once
        if (is_first) {
            is_first = GS_FALSE;
            GS_RETURN_IFERR(exp_init_columns(exporter, stmt, table_cache));
        }

        if (g_export_opts.filetype == FT_TXT) {
            GS_RETURN_IFERR(gsql_make_insert_sql_s(exporter, g_sql_buf,
                exp_remap_table_name(&exp_opts->table_maps, table_name, NULL, 0)));
            GS_RETURN_IFERR(exp_write_txt_records(&g_exp_txtbuf, stmt, g_sql_buf, g_str_buf, g_exp_dpfile, exporter,
                GS_FALSE, &exporter->file_insert_num));
        } else {
            GS_RETURN_IFERR(exp_bin_init_bin_file_ctx(&bin_file_ctx, g_exp_fbuf, EXP_MAX_FILE_BUF, g_lob_fbuf,
                EXP_MAX_LOB_FILE_BUF, g_exp_dpbinfile, g_lob_binfile));

            bin_file_ctx.tab_name = (char *)exp_remap_table_name(&exp_opts->table_maps, table_name, NULL, 0);

            GS_RETURN_IFERR(exp_write_bin_records(&bin_file_ctx, stmt, g_str_buf, exporter, NULL,
                &exporter->file_insert_num));

            if (exporter->file_insert_num - tmp_insert_num > 0) {
                subfile = NULL;
                GS_RETURN_IFERR(exp_start_cache_unit(table_cache, EXP_CACHE_SUB_FILE_NAME));
                GS_RETURN_IFERR(alloc_column_subfile_info(table_cache, &subfile));
                MEMS_RETURN_IFERR(strncpy_s(subfile, EXP_MAX_SUBFILE_NAME_LEN, exp_opts->bin_data_file,
                    strlen(exp_opts->bin_data_file))); // data file name
            }
            tmp_insert_num = exporter->file_insert_num;
        }
    }

    GS_RETURN_IFERR(exp_table_records_deal(exporter));

    return GS_SUCCESS;
}

static inline bool32 is_arr_type(void)
{
    uint32 len = (uint32)strlen(g_str_buf);
    uint32 len_of_bracket = (uint32)strlen("[]");
    // DB_TAB_COLS can make sure DATA_TYPE is end with "[]" if column is array type
    if (cm_compare_str(g_str_buf + len - len_of_bracket, "[]") == 0) {
        g_str_buf[len - len_of_bracket] = '\0'; // delete the last two characters("[]")
        return GS_TRUE;
    }

    return GS_FALSE;
}

#define STR_TRUE_LEN 4
static inline int gsql_make_column_def(gsc_stmt_t stmt, text_t *col_def)
{
    void *data = NULL;
    uint32 size;
    bool32 is_null = GS_FALSE;
    typmode_t col_type;
    bool32 is_arr;
    bool32 is_jsonb = GS_FALSE;

    // get the column name
    GS_RETURN_IFERR(gsc_column_as_string(stmt, 0, g_str_buf, GS_MAX_PACKET_SIZE));
    exp_concat_str_quote(col_def, g_str_buf);

    // get the datatype
    GS_RETURN_IFERR(gsc_column_as_string(stmt, 1, g_str_buf, GS_MAX_PACKET_SIZE));
    is_arr = is_arr_type();
    col_type.datatype = get_datatype_id(g_str_buf);

    if (gsc_get_call_version(CONN) >= CS_VERSION_24) {
        GS_RETURN_IFERR(gsc_get_column_by_id(stmt, 8, &data, &size, &is_null));
        is_jsonb = ((size == STR_TRUE_LEN) ? GS_TRUE : GS_FALSE);
    }

    GS_RETURN_IFERR(gsc_get_column_by_id(stmt, 2, &data, &size, &is_null));
    col_type.size = (uint16)(*(int32 *)data);

    GS_RETURN_IFERR(gsc_get_column_by_id(stmt, 3, &data, &size, &is_null));
    col_type.precision = is_null ? 0 : (uint8)(*(int32 *)data);

    GS_RETURN_IFERR(gsc_get_column_by_id(stmt, 4, &data, &size, &is_null));
    col_type.scale = is_null ? 0 : (int8)(*(int32 *)data);

    if (GS_IS_STRING_TYPE(col_type.datatype)) {
        GS_RETURN_IFERR(gsc_get_column_by_id(stmt, 7, &data, &size, &is_null));
        col_type.is_char = (((char *)data)[0] == 'C');
    }

    GS_RETURN_IFERR(cm_concat_string(col_def, EXP_MAX_DDL_BUF_SZ, " "));
    if (gsc_get_call_version(CONN) >= CS_VERSION_24 && is_jsonb) {
        GS_RETURN_IFERR(cm_concat_string(col_def, EXP_MAX_DDL_BUF_SZ, "JSONB"));
    } else {
        if (cm_typmode2text(&col_type, col_def, EXP_MAX_DDL_BUF_SZ) != GS_SUCCESS) {
            return GS_ERROR;
        }
       
        if (is_arr) {
            GS_RETURN_IFERR(cm_concat_string(col_def, EXP_MAX_DDL_BUF_SZ, "[]"));
            is_arr = GS_FALSE;
        }
    }

    // add nullable constants
    GS_RETURN_IFERR(gsc_column_as_string(stmt, 5, g_str_buf, GS_MAX_PACKET_SIZE));
    if (g_str_buf[0] == 'N') {
        GS_RETURN_IFERR(cm_concat_string(col_def, EXP_MAX_DDL_BUF_SZ, " NOT NULL"));
    }

    // add default text
    GS_RETURN_IFERR(gsc_column_as_string(stmt, 6, g_str_buf, GS_MAX_PACKET_SIZE));
    if (strlen(g_str_buf) > 0) {
        GS_RETURN_IFERR(cm_concat_string(col_def, EXP_MAX_DDL_BUF_SZ, " DEFAULT "));
        GS_RETURN_IFERR(cm_concat_string(col_def, EXP_MAX_DDL_BUF_SZ, g_str_buf));
    }
    return GS_SUCCESS;
}

static status_t exp_table_columns(exp_tab_info_t *tab_info, exp_cache_t *table_cache)
{
    char buf[EXP_MAX_DDL_BUF_SZ];
    uint32 rows;
    bool32 is_first = GS_TRUE;
    text_t col_def;
    uint32 total_columns = 0;

    GS_RETURN_IFERR(gsc_bind_by_pos(tab_info->ctx->query_tab_column, 0, GSC_TYPE_STRING, tab_info->user,
        (int32)strlen(tab_info->user), NULL));
    GS_RETURN_IFERR(gsc_bind_by_pos(tab_info->ctx->query_tab_column, 1, GSC_TYPE_STRING, tab_info->table,
        (int32)strlen(tab_info->table), NULL));

    GS_RETURN_IFERR(gsc_execute(tab_info->ctx->query_tab_column));

    do {
        GS_RETURN_IFERR(gsc_fetch(tab_info->ctx->query_tab_column, &rows));
        if (rows == 0) {
            break;
        }

        total_columns += rows;
        col_def.str = buf;
        col_def.len = 0;
        if (!is_first) {
            GS_RETURN_IFERR(cm_concat_string(&col_def, EXP_MAX_DDL_BUF_SZ, ",\n"));
        } else {
            is_first = GS_FALSE;
        }

        GS_RETURN_IFERR(cm_concat_string(&col_def, EXP_MAX_DDL_BUF_SZ, EXP_INDENT));
        GS_RETURN_IFERR(gsql_make_column_def(tab_info->ctx->query_tab_column, &col_def));
        GS_RETURN_IFERR(exp_cache_append_text(table_cache, &col_def));
    } while (GS_TRUE);

    if (total_columns == 0) {
        // if export columns , drop tables occurs, columns count may be 0, throw error.
        EXP_THROW_ERROR(ERR_TABLE_OR_VIEW_NOT_EXIST, tab_info->user, tab_info->table);
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

static int exp_table_constraints(exp_tabs_ctx_t *ctx, const char *table, exp_cache_t* table_cache, bool32 is_implicit)
{
    uint32 rows;
    char cmd_buf[GSQL_MAX_TEMP_SQL + 1];
    const char *user = ctx->user;

    PRTS_RETURN_IFERR(sprintf_s(cmd_buf, GSQL_MAX_TEMP_SQL,
        "SELECT C.CONSTRAINT_TYPE, C.CONS_COLS, C.REF_COLS, C.CONSTRAINT_NAME, C.TABLE_NAME, C.SEARCH_CONDITION, "
        "DECODE(R_OWNER, C.OWNER, R_TABLE_NAME, R_OWNER || '.' || R_TABLE_NAME) , R_CONSTRAINT_NAME, "
        "DECODE(DELETE_RULE, 'DELETE CASCADE', ' ON DELETE CASCADE', 'SET NULL', ' ON DELETE SET NULL'), "
        "REPLACE(C.CONS_COLS ,', ', '\", \"'), REPLACE(C.REF_COLS ,', ', '\", \"'), "
        "I.PARTITIONED %s"
        "FROM %s C LEFT JOIN %s I ON I.OWNER = C.OWNER AND I.INDEX_NAME = C.CONSTRAINT_NAME "
        "WHERE C.OWNER = UPPER(:OWNER) AND C.TABLE_NAME = :TABLE_NAME AND C.SYS_GENERATE = '%s' AND C.CONSTRAINT_TYPE != 'R' "
        "ORDER BY DECODE(CONSTRAINT_TYPE, 'P', 1, 'U', 2, 'C', 3, 99), CONSTRAINT_NAME",
        ctx->reverse_index_available ? ",I.IS_REVERSED " : " ",
        exp_tabname(g_export_opts.consistent, EXP_TABAGENT_DB_CONSTRAINTS),
        exp_tabname(g_export_opts.consistent, EXP_TABAGENT_DB_INDEXES), is_implicit ? "Y" : "N"));

    GS_RETURN_IFERR(gsc_prepare(STMT, (const char *)cmd_buf));

    GS_RETURN_IFERR(gsc_bind_by_pos(STMT, 0, GSC_TYPE_STRING, user, (int32)strlen(user), NULL));
    GS_RETURN_IFERR(gsc_bind_by_pos(STMT, 1, GSC_TYPE_STRING, table, (int32)strlen(table), NULL));

    GS_RETURN_IFERR(gsc_execute(STMT));

    do {
        GS_RETURN_IFERR(gsc_fetch(STMT, &rows));
        if (rows == 0) {
            break;
        }

        GS_RETURN_IFERR(exp_cache_append_str(table_cache, "ALTER TABLE "));
        GS_RETURN_IFERR(gsc_column_as_string(STMT, 4, g_str_buf, GS_MAX_PACKET_SIZE));
        GS_RETURN_IFERR(exp_cache_append_str_quote(table_cache,
            exp_remap_table_name(&g_export_opts.table_maps, g_str_buf, NULL, 0)));
        GS_RETURN_IFERR(exp_cache_append_str(table_cache, " ADD "));
        if (!is_implicit) {
            GS_RETURN_IFERR(exp_cache_append_str(table_cache, "CONSTRAINT "));
            GS_RETURN_IFERR(gsc_column_as_string(STMT, 3, g_str_buf, GS_MAX_PACKET_SIZE));
            GS_RETURN_IFERR(exp_cache_append_str_quote(table_cache, g_str_buf));
            GS_RETURN_IFERR(exp_cache_append_str(table_cache, " "));
        }

        GS_RETURN_IFERR(gsc_column_as_string(STMT, 0, g_str_buf, GS_MAX_PACKET_SIZE));

        if ((g_str_buf[0] == 'P') || (g_str_buf[0] == 'U')) {
            bool32 is_primary = (g_str_buf[0] == 'P');
            GS_RETURN_IFERR(exp_cache_append_str(table_cache, is_primary ? "PRIMARY KEY(" : "UNIQUE("));

            if (!g_export_opts.quote_names) {
                GS_RETURN_IFERR(gsc_column_as_string(STMT, 1, g_str_buf, GS_MAX_PACKET_SIZE));
            } else {
                GS_RETURN_IFERR(gsc_column_as_string(STMT, 9, g_str_buf, GS_MAX_PACKET_SIZE));
            }

            GS_RETURN_IFERR(exp_cache_append_str_quote(table_cache, g_str_buf));
            GS_RETURN_IFERR(exp_cache_append_str(table_cache, ")"));
            GS_RETURN_IFERR(gsc_column_as_string(STMT, 11, g_str_buf, GS_MAX_PACKET_SIZE));
            if (is_primary && g_str_buf[0] == 'Y') {
                GS_RETURN_IFERR(exp_cache_append_str(table_cache, " USING INDEX LOCAL"));
            }
            if (ctx->reverse_index_available) {
                GS_RETURN_IFERR(gsc_column_as_string(STMT, 12, g_str_buf, GS_MAX_PACKET_SIZE));
                if (g_str_buf[0] == 'Y') {
                    GS_RETURN_IFERR(exp_cache_append_str(table_cache, " REVERSE"));
                }
            }
        } else if (g_str_buf[0] == 'C') {
            GS_RETURN_IFERR(exp_cache_append_str(table_cache, "CHECK("));
            GS_RETURN_IFERR(gsc_column_as_string(STMT, 5, g_str_buf, GS_MAX_PACKET_SIZE));
            GS_RETURN_IFERR(exp_cache_append_str(table_cache, g_str_buf));
            GS_RETURN_IFERR(exp_cache_append_str(table_cache, ")"));
        } else {
            continue;
        }

        GS_RETURN_IFERR(exp_cache_append_str(table_cache, ";\n"));
    } while (GS_TRUE);

    return GS_SUCCESS;
}

static status_t exp_init_tab_info(const char *user, const char *table, exp_tabs_ctx_t *ctx, exp_tab_info_t *tab_info)
{
    uint32 rows;
    char cmd_buf[GSQL_MAX_TEMP_SQL + 1];

    PRTS_RETURN_IFERR(sprintf_s(cmd_buf, GSQL_MAX_TEMP_SQL,
        "SELECT decode(TABLE_TYPE, 'HEAP', 0, 'IOT', 1, 'TRANS_TEMP', 2, 'SESSION_TEMP', 3, 'NOLOGGING', 4, 'EXTERNAL', 5), PARTITIONED "
        "FROM %s "
        "WHERE OWNER = UPPER(:O) AND TABLE_NAME = :T",
        exp_tabname(g_export_opts.consistent, EXP_TABAGENT_DB_TABLES)));

    GS_RETURN_IFERR(gsc_prepare(STMT, (const char *)cmd_buf));

    GS_RETURN_IFERR(gsc_bind_by_pos(STMT, 0, GSC_TYPE_STRING, user, (int32)strlen(user), NULL));
    GS_RETURN_IFERR(gsc_bind_by_pos(STMT, 1, GSC_TYPE_STRING, table, (int32)strlen(table), NULL));

    GS_RETURN_IFERR(gsc_execute(STMT));
    GS_RETURN_IFERR(gsc_fetch(STMT, &rows));

    if (rows == 0) {
        EXP_THROW_ERROR(ERR_TABLE_OR_VIEW_NOT_EXIST, user, table);
        return GS_ERROR;
    }

    GS_RETURN_IFERR(gsc_column_as_string(STMT, 0, g_str_buf, GS_MAX_PACKET_SIZE));
    tab_info->table_type = (table_type_t)atoi(g_str_buf);

    GS_RETURN_IFERR(gsc_column_as_string(STMT, 1, g_str_buf, GS_MAX_PACKET_SIZE));
    tab_info->partitioned = (g_str_buf[0] == 'Y');

    tab_info->ctx = ctx;
    tab_info->user = user;
    tab_info->table = table;

    return GS_SUCCESS;
}

static status_t exp_append_parent_partition_key(exp_cache_t* table_cache, exp_partition_info_t *partition_info)
{
    GS_RETURN_IFERR(exp_cache_append_str(table_cache, "\nPARTITION BY "));
    GS_RETURN_IFERR(gsc_column_as_string(STMT, 0, partition_info->parent_partition_type, GS_MAX_NAME_LEN));
    GS_RETURN_IFERR(exp_cache_append_str(table_cache, partition_info->parent_partition_type));
    GS_RETURN_IFERR(exp_cache_append_str(table_cache, " ("));

    if (!g_export_opts.quote_names) {
        GS_RETURN_IFERR(gsc_column_as_string(STMT, 1, g_str_buf, GS_MAX_PACKET_SIZE));
    } else {
        GS_RETURN_IFERR(gsc_column_as_string(STMT, 2, g_str_buf, GS_MAX_PACKET_SIZE));
    }

    GS_RETURN_IFERR(exp_cache_append_str_quote(table_cache, g_str_buf));
    GS_RETURN_IFERR(exp_cache_append_str(table_cache, ")\n"));

    if (cm_str_equal(partition_info->parent_partition_type, "RANGE")) {
        GS_RETURN_IFERR(gsc_column_as_string(STMT, 3, g_str_buf, GS_MAX_PACKET_SIZE));

        if (g_str_buf[0] != '\0') {
            GS_RETURN_IFERR(exp_cache_append_str(table_cache, "INTERVAL("));
            GS_RETURN_IFERR(exp_cache_append_str(table_cache, g_str_buf));
            GS_RETURN_IFERR(exp_cache_append_str(table_cache, ")\n"));

            if (!g_export_opts.quote_names) {
                GS_RETURN_IFERR(gsc_column_as_string(STMT, 4, g_str_buf, GS_MAX_PACKET_SIZE));
            } else {
                GS_RETURN_IFERR(gsc_column_as_string(STMT, 5, g_str_buf, GS_MAX_PACKET_SIZE));
            }

            if (g_str_buf[0] != '\0') {
                GS_RETURN_IFERR(exp_cache_append_str(table_cache, "STORE IN("));
                GS_RETURN_IFERR(exp_cache_append_str_quote(table_cache, g_str_buf));
                GS_RETURN_IFERR(exp_cache_append_str(table_cache, ")\n"));
            }
        }
    }

    return GS_SUCCESS;
}

static status_t exp_append_sub_partition_key(exp_cache_t* table_cache, exp_partition_info_t *partition_info)
{
    if (gsc_get_call_version(CONN) < CS_VERSION_20) {
        return GS_SUCCESS;
    }

    GS_RETURN_IFERR(gsc_column_as_string(STMT, 6, partition_info->sub_partition_type, GS_MAX_NAME_LEN));
    partition_info->has_sub_partition = (cm_str_equal(partition_info->sub_partition_type, "RANGE") ||
        cm_str_equal(partition_info->sub_partition_type, "LIST") ||
        cm_str_equal(partition_info->sub_partition_type, "HASH"));

    if (partition_info->has_sub_partition) {
        GS_RETURN_IFERR(exp_cache_append_str(table_cache, "SUBPARTITION BY "));
        GS_RETURN_IFERR(exp_cache_append_str(table_cache, partition_info->sub_partition_type));
        GS_RETURN_IFERR(exp_cache_append_str(table_cache, " ("));
        if (!g_export_opts.quote_names) {
            GS_RETURN_IFERR(gsc_column_as_string(STMT, 7, g_str_buf, GS_MAX_PACKET_SIZE));
        } else {
            GS_RETURN_IFERR(gsc_column_as_string(STMT, 8, g_str_buf, GS_MAX_PACKET_SIZE));
        }
        GS_RETURN_IFERR(exp_cache_append_str_quote(table_cache, g_str_buf));
        GS_RETURN_IFERR(exp_cache_append_str(table_cache, ")\n"));
    }

    return GS_SUCCESS;
}

static status_t exp_table_partition_key(exp_cache_t* table_cache, exp_partition_info_t *partition_info,
                                        exp_prepare_sql_param_t param)
{
    uint32 rows;
    char cmd_buf[GSQL_MAX_TEMP_SQL + 1];

    if (gsc_get_call_version(CONN) >= CS_VERSION_20) {
        GS_RETURN_IFERR(EXP_PREPARE_SQL(EXP_GET_TABLE_NEW_PARTITION_KEY, cmd_buf, GSQL_MAX_TEMP_SQL, &param));
    } else {
        GS_RETURN_IFERR(EXP_PREPARE_SQL(EXP_GET_TABLE_OLD_PARTITION_KEY, cmd_buf, GSQL_MAX_TEMP_SQL, &param));
    }
    
    GS_RETURN_IFERR(gsc_prepare(STMT, (const char *)cmd_buf));
    GS_RETURN_IFERR(gsc_execute(STMT));
    GS_RETURN_IFERR(gsc_fetch(STMT, &rows));
    if (rows == 0) {
        EXP_THROW_ERROR(ERR_TABLE_OR_VIEW_NOT_EXIST, param.get_partition_param.user_name,
                        param.get_partition_param.table_name);
        return GS_ERROR;
    }

    GS_RETURN_IFERR(exp_append_parent_partition_key(table_cache, partition_info));
    GS_RETURN_IFERR(exp_append_sub_partition_key(table_cache, partition_info));

    return GS_SUCCESS;
}

static status_t exp_table_partition_value(exp_cache_t* table_cache, exp_partition_info_t partition_info,
                                          exp_prepare_sql_param_t param)
{
    uint32 rows;
    bool8  first_row = GS_TRUE;
    uint32 partition_cnt = 0;
    uint32 pos;
    char cmd_buf[GSQL_MAX_TEMP_SQL + 1];
    exp_get_partition_param_t *exp_partition_param = (exp_get_partition_param_t *)(&param.get_proc_param);

    GS_RETURN_IFERR(exp_cache_append_str(table_cache, "(\n"));
    if (!partition_info.has_sub_partition) {
        GS_RETURN_IFERR(EXP_PREPARE_SQL(EXP_GET_TABLE_PARTITION_VALUE, cmd_buf, GSQL_MAX_TEMP_SQL, &param));
    } else {
        GS_RETURN_IFERR(EXP_PREPARE_SQL(EXP_GET_TABLE_SUBPARTITION_VALUE, cmd_buf, GSQL_MAX_TEMP_SQL, &param));
    }

    GS_RETURN_IFERR(gsc_prepare(STMT, (const char *)cmd_buf));
    GS_RETURN_IFERR(gsc_execute(STMT));

    do {
        GS_RETURN_IFERR(gsc_fetch(STMT, &rows));
        if (rows == 0) {
            break;
        }
        pos = 0;
        partition_cnt += rows;

        if (first_row) {
            first_row = GS_FALSE;
        } else {
            GS_RETURN_IFERR(exp_cache_append_str(table_cache, ",\n"));
        }

        GS_RETURN_IFERR(exp_cache_append_str(table_cache, EXP_INDENT2));
        GS_RETURN_IFERR(exp_cache_append_str(table_cache, "PARTITION "));
        // pos 0 is partition name
        GS_RETURN_IFERR(gsc_column_as_string(STMT, pos++, g_str_buf, GS_MAX_PACKET_SIZE));
        GS_RETURN_IFERR(exp_cache_append_str(table_cache, g_str_buf));

        if (cm_str_equal(partition_info.parent_partition_type, "RANGE")) {
            GS_RETURN_IFERR(exp_cache_append_str(table_cache, " VALUES LESS THAN ("));
            // pos 1 is high value
            GS_RETURN_IFERR(gsc_column_as_string(STMT, pos, g_str_buf, GS_MAX_PACKET_SIZE));
            GS_RETURN_IFERR(exp_cache_append_str(table_cache, g_str_buf));
            GS_RETURN_IFERR(exp_cache_append_str(table_cache, ")"));
        } else if (cm_str_equal(partition_info.parent_partition_type, "LIST")) {
            GS_RETURN_IFERR(exp_cache_append_str(table_cache, " VALUES("));
            // pos 1 is high value
            GS_RETURN_IFERR(gsc_column_as_string(STMT, pos, g_str_buf, GS_MAX_PACKET_SIZE));
            GS_RETURN_IFERR(exp_cache_append_str(table_cache, g_str_buf));
            GS_RETURN_IFERR(exp_cache_append_str(table_cache, ")"));
        } else if (!cm_str_equal(partition_info.parent_partition_type, "HASH")) {
            EXP_THROW_ERROR(ERR_INVALID_PART_TYPE, partition_info.parent_partition_type);
            return GS_ERROR;
        }
        pos++;

        // pos 2 is tablespace name
        GS_RETURN_IFERR(gsc_column_as_string(STMT, pos++, g_str_buf, GS_MAX_PACKET_SIZE));
        GS_RETURN_IFERR(exp_cache_append_str(table_cache, " TABLESPACE "));
        GS_RETURN_IFERR(exp_cache_append_str_quote(table_cache, g_str_buf));
        // pos 3 is initrans
        GS_RETURN_IFERR(gsc_column_as_string(STMT, pos++, g_str_buf, GS_MAX_PACKET_SIZE));
        GS_RETURN_IFERR(exp_cache_append_str(table_cache, " INITRANS "));
        GS_RETURN_IFERR(exp_cache_append_str(table_cache, g_str_buf));
        // pos 4 is pctfree
        GS_RETURN_IFERR(gsc_column_as_string(STMT, pos++, g_str_buf, GS_MAX_PACKET_SIZE));
        GS_RETURN_IFERR(exp_cache_append_str(table_cache, " PCTFREE "));
        GS_RETURN_IFERR(exp_cache_append_str(table_cache, g_str_buf));

        if (exp_partition_param->db_tab_partitions_has_flag) {
            if (g_export_opts.with_format_csf) {
                // pos 5 may be partition flag which means csf or asf
                GS_RETURN_IFERR(gsc_column_as_string(STMT, pos, g_str_buf, GS_MAX_PACKET_SIZE));
                if (gsc_get_call_version(CONN) >= CS_VERSION_24 || cm_compare_str(g_str_buf, "CSF") == 0) {
                    GS_RETURN_IFERR(exp_cache_append_str(table_cache, " FORMAT "));
                    GS_RETURN_IFERR(exp_cache_append_str(table_cache, g_str_buf));
                }
            }
            pos++;
        }

        if (gsc_get_call_version(CONN) >= CS_VERSION_22) {
            // pos 6 may be partition flag which means compressed or uncompress
            GS_RETURN_IFERR(gsc_column_as_string(STMT, pos++, g_str_buf, GS_MAX_PACKET_SIZE));
            // 0 'NONE', 1 'ZLIB', 2 'ZSTD', 3 'LZ4', other 'NONE'
            if (cm_compare_str(g_str_buf, "NONE") != 0) {
                GS_RETURN_IFERR(exp_cache_append_str(table_cache, " COMPRESS"));
            }
        }

        if (partition_info.has_sub_partition) {
            GS_RETURN_IFERR(exp_cache_append_str(table_cache, "(\n        "));
            // pos 5 or pos 6 may be sub partition
            GS_RETURN_IFERR(gsc_column_as_string(STMT, pos, g_str_buf, GS_MAX_PACKET_SIZE));
            GS_RETURN_IFERR(exp_cache_append_str(table_cache, g_str_buf));
            GS_RETURN_IFERR(exp_cache_append_str(table_cache, "\n    )"));
        }
    } while (GS_TRUE);

    if (partition_cnt == 0) {
        // if export partition , drop tables occurs, partition count may be 0, throw error.
        EXP_THROW_ERROR(ERR_TABLE_OR_VIEW_NOT_EXIST, param.get_partition_param.user_name,
                        param.get_partition_param.table_name);
        return GS_ERROR;
    }

    GS_RETURN_IFERR(exp_cache_append_str(table_cache, "\n)"));

    return GS_SUCCESS;
}

static inline void exec_exp_verify_column_of_part_tables_agent(bool32* flag)
{
    if (exp_verify_column_of_part_tables_agent() == GS_SUCCESS) {
        *flag = GS_TRUE;
    } else {
        *flag = GS_FALSE;
    }
}

static int exp_lob_storage(const char *user, const char *table, exp_cache_t* table_cache)
{
    uint32 rows;
    char cmd_buf[GSQL_MAX_TEMP_SQL + 1];
    exp_prepare_sql_param_t param;
    param.get_user_table_param.user_name = user;
    param.get_user_table_param.table_name = table;

    GS_RETURN_IFERR(EXP_PREPARE_SQL(EXP_GET_DB_LOB_STORAGE, cmd_buf, GSQL_MAX_TEMP_SQL, &param));
    GS_RETURN_IFERR(gsc_prepare(STMT, (const char *)cmd_buf));
    GS_RETURN_IFERR(gsc_execute(STMT));

    do {
        GS_RETURN_IFERR(gsc_fetch(STMT, &rows));
        if (rows == 0) {
            break;
        }

        GS_RETURN_IFERR(exp_cache_append_str(table_cache, "\n"));
        GS_RETURN_IFERR(gsc_column_as_string(STMT, 0, cmd_buf, GSQL_MAX_TEMP_SQL));
        GS_RETURN_IFERR(exp_cache_append_str(table_cache, "LOB ("));
        GS_RETURN_IFERR(exp_cache_append_str_quote(table_cache, cmd_buf));
        GS_RETURN_IFERR(exp_cache_append_str(table_cache, ") STORE AS (\n"));
        GS_RETURN_IFERR(gsc_column_as_string(STMT, 1, cmd_buf, GSQL_MAX_TEMP_SQL));
        GS_RETURN_IFERR(exp_cache_append_str(table_cache, "    TABLESPACE "));
        GS_RETURN_IFERR(exp_cache_append_str_quote(table_cache, cmd_buf));
        GS_RETURN_IFERR(exp_cache_append_str(table_cache, "\n)"));
    } while (GS_TRUE);

    return GS_SUCCESS;
}

static inline int exp_table_partition(const char *user, const char *table, exp_cache_t* table_cache)
{
    exp_partition_info_t partition_info;
    exp_prepare_sql_param_t param;

    partition_info.has_sub_partition = GS_FALSE;
    param.get_partition_param.consistent = g_export_opts.consistent;
    param.get_partition_param.user_name = user;
    param.get_partition_param.table_name = table;
    exec_exp_verify_column_of_part_tables_agent(&param.get_partition_param.db_tab_partitions_has_flag);

    GS_RETURN_IFERR(exp_table_partition_key(table_cache, &partition_info, param));
    GS_RETURN_IFERR(exp_table_partition_value(table_cache, partition_info, param));

    return GS_SUCCESS;
}

static int exp_create_table(exp_tab_info_t *tab_info, exp_cache_t *table_cache)
{
    bool32 is_consist = GS_FALSE;

    if (tab_info->table_type == TABLE_TYPE_TRANS_TEMP || tab_info->table_type == TABLE_TYPE_SESSION_TEMP) {
        GS_RETURN_IFERR(exp_cache_append_str(table_cache, "CREATE GLOBAL TEMPORARY TABLE "));
    } else {
        GS_RETURN_IFERR(exp_cache_append_str(table_cache, "CREATE TABLE "));
    }

    GS_RETURN_IFERR(exp_cache_append_str_quote(table_cache,
        exp_remap_table_name(&g_export_opts.table_maps, tab_info->table, NULL, 0)));
    GS_RETURN_IFERR(exp_cache_append_str(table_cache, "\n(\n"));
    GS_RETURN_IFERR(exp_table_columns(tab_info, table_cache));
    GS_RETURN_IFERR(exp_cache_append_str(table_cache, "\n)"));

    if (gsc_get_call_version(CONN) >= CS_VERSION_23) {
        EXP_RETURN_IFERR(exp_lob_storage(tab_info->user, tab_info->table, table_cache));
    }

    if (tab_info->partitioned == 1 && !is_consist) {
        GS_RETURN_IFERR(exp_table_partition(tab_info->user, tab_info->table, table_cache));
    }

    if (tab_info->table_type == TABLE_TYPE_TRANS_TEMP) {
        GS_RETURN_IFERR(exp_cache_append_str(table_cache, "ON COMMIT DELETE ROWS"));
    } else if (tab_info->table_type == TABLE_TYPE_SESSION_TEMP) {
        GS_RETURN_IFERR(exp_cache_append_str(table_cache, "ON COMMIT PRESERVE ROWS"));
    } else if (tab_info->table_type == TABLE_TYPE_NOLOGGING) {
        GS_RETURN_IFERR(exp_cache_append_str(table_cache, "NOLOGGING"));
    }

    return GS_SUCCESS;
}

// verify if DB_TABLES has one column named flag which is new added
// notes: flag means the table is csf or bitmap format
static status_t exp_verify_column_of_tables_agent(void)
{
    uint32 rows;
    char cmd_buf[GSQL_MAX_TEMP_SQL + 1];

    int iret_sprintf = sprintf_s(cmd_buf, GSQL_MAX_TEMP_SQL,
        "SELECT COLUMN_NAME FROM " EXP_VIEW_COLS_AGENT
        " WHERE VIEW_NAME = 'DB_TABLES' AND COLUMN_NAME = 'ROW_FORMAT'");
    if (iret_sprintf == -1) {
        EXP_THROW_ERROR(ERR_SYSTEM_CALL, iret_sprintf);
        return GS_ERROR;
    }

    GS_RETURN_IFERR(gsc_prepare(STMT, (const char *)cmd_buf));
    GS_RETURN_IFERR(gsc_execute(STMT));
    GS_RETURN_IFERR(gsc_fetch(STMT, &rows));

    if (rows == 0) {
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

static inline int exp_table_attrs_core(exp_cache_t* table_cache, bool32 db_tables_has_flag)
{
    int pos = 0;
    // 0 TABLESPACE_NAME
    GS_RETURN_IFERR(gsc_column_as_string(STMT, pos++, g_str_buf, GS_MAX_PACKET_SIZE));
    if (strlen(g_str_buf) > 0) {
        GS_RETURN_IFERR(exp_cache_append_str(table_cache, "\nTABLESPACE "));
        GS_RETURN_IFERR(exp_cache_append_str_quote(table_cache, g_str_buf));
    }
    // 1 INI_TRANS
    GS_RETURN_IFERR(gsc_column_as_string(STMT, pos++, g_str_buf, GS_MAX_PACKET_SIZE));
    if (strlen(g_str_buf) > 0) {
        GS_RETURN_IFERR(exp_cache_append_str(table_cache, "\nINITRANS "));
        GS_RETURN_IFERR(exp_cache_append_str(table_cache, g_str_buf));
    }
    // 2 MAX_TRANS
    GS_RETURN_IFERR(gsc_column_as_string(STMT, pos++, g_str_buf, GS_MAX_PACKET_SIZE));
    if (strlen(g_str_buf) > 0) {
        GS_RETURN_IFERR(exp_cache_append_str(table_cache, "\nMAXTRANS "));
        GS_RETURN_IFERR(exp_cache_append_str(table_cache, g_str_buf));
    }
    // 3 PCT_FREE
    GS_RETURN_IFERR(gsc_column_as_string(STMT, pos++, g_str_buf, GS_MAX_PACKET_SIZE));
    if (strlen(g_str_buf) > 0) {
        GS_RETURN_IFERR(exp_cache_append_str(table_cache, "\nPCTFREE "));
        GS_RETURN_IFERR(exp_cache_append_str(table_cache, g_str_buf));
    }
    // 4 PARTITIONED
    pos++;
    // 5 CR_MODE
    if (g_export_opts.with_cr_mode) {
        GS_RETURN_IFERR(gsc_column_as_string(STMT, pos, g_str_buf, GS_MAX_PACKET_SIZE));
        if (strlen(g_str_buf) > 0) {
            GS_RETURN_IFERR(exp_cache_append_str(table_cache, "\nCRMODE "));
            GS_RETURN_IFERR(exp_cache_append_str(table_cache, g_str_buf));
        }
    }
    pos++;
    // 6 APPENDONLY
    GS_RETURN_IFERR(gsc_column_as_string(STMT, pos++, g_str_buf, GS_MAX_PACKET_SIZE));
    if (cm_compare_str(g_str_buf, "Y") == 0) {
        GS_RETURN_IFERR(exp_cache_append_str(table_cache, "\nAPPENDONLY ON"));
    }
    // 7 may be ROW_FORMAT
    if (db_tables_has_flag) {
        if (g_export_opts.with_format_csf) {
            GS_RETURN_IFERR(gsc_column_as_string(STMT, pos, g_str_buf, GS_MAX_PACKET_SIZE));
            if (gsc_get_call_version(CONN) >= CS_VERSION_24 || cm_compare_str(g_str_buf, "CSF") == 0) {
                GS_RETURN_IFERR(exp_cache_append_str(table_cache, "\nFORMAT "));
                GS_RETURN_IFERR(exp_cache_append_str(table_cache, g_str_buf));
            }
        }
        pos++;
    }
    // 7 or 8 may be COMPRESS_ALGO
    if (gsc_get_call_version(CONN) >= CS_VERSION_22) {
        GS_RETURN_IFERR(gsc_column_as_string(STMT, pos++, g_str_buf, GS_MAX_PACKET_SIZE));
        // 0 'NONE', 1 'ZLIB', 2 'ZSTD', 3 'LZ4', other 'NONE'
        if (cm_compare_str(g_str_buf, "NONE") != 0) {
            GS_RETURN_IFERR(exp_cache_append_str(table_cache, "\nCOMPRESS"));
        }
    }
    return GS_SUCCESS;
}

static int exp_table_attrs(const char *user, const char *table, exp_cache_t* table_cache)
{
    uint32 rows;
    char cmd_buf[GSQL_MAX_TEMP_SQL + 1];
    exp_prepare_sql_param_t param;

    if (exp_verify_column_of_tables_agent() == GS_SUCCESS) {
        param.get_db_tables_param.db_tables_has_flag = GS_TRUE;
    } else {
        param.get_db_tables_param.db_tables_has_flag = GS_FALSE;
    }

    GS_RETURN_IFERR(EXP_PREPARE_SQL(EXP_GET_DB_TABLES_LIST, cmd_buf, GSQL_MAX_TEMP_SQL, &param));

    GS_RETURN_IFERR(gsc_prepare(STMT, (const char *)cmd_buf));

    GS_RETURN_IFERR(gsc_bind_by_pos(STMT, 0, GSC_TYPE_STRING, user, (int32)strlen(user), NULL));
    GS_RETURN_IFERR(gsc_bind_by_pos(STMT, 1, GSC_TYPE_STRING, table, (int32)strlen(table), NULL));

    GS_RETURN_IFERR(gsc_execute(STMT));

    GS_RETURN_IFERR(gsc_fetch(STMT, &rows));
    if (rows == 0) {
        return GS_SUCCESS;
    }

    GS_RETURN_IFERR(exp_table_attrs_core(table_cache, param.get_db_tables_param.db_tables_has_flag));

    return GS_SUCCESS;
}

static int exp_table_comments(const char *user, const char *table, exp_cache_t* table_cache)
{
    uint32 rows;
    char cmd_buf[GSQL_MAX_TEMP_SQL + 1];

    PRTS_RETURN_IFERR(sprintf_s(cmd_buf, GSQL_MAX_TEMP_SQL,
        "SELECT TABLE_NAME, COMMENTS "
        "FROM %s "
        "WHERE OWNER = UPPER(:OWNER) AND TABLE_NAME = :TABLE_NAME AND COMMENTS IS NOT NULL ",
        exp_tabname(g_export_opts.consistent, EXP_TABAGENT_DB_TAB_COMMENTS)));

    GS_RETURN_IFERR(gsc_prepare(STMT, (const char *)cmd_buf));

    GS_RETURN_IFERR(gsc_bind_by_pos(STMT, 0, GSC_TYPE_STRING, user, (int32)strlen(user), NULL));
    GS_RETURN_IFERR(gsc_bind_by_pos(STMT, 1, GSC_TYPE_STRING, table, (int32)strlen(table), NULL));

    GS_RETURN_IFERR(gsc_execute(STMT));

    GS_RETURN_IFERR(gsc_fetch(STMT, &rows));
    if (rows > 0) {
        GS_RETURN_IFERR(gsc_column_as_string(STMT, 0, g_str_buf, GS_MAX_PACKET_SIZE));
        GS_RETURN_IFERR(exp_cache_append_str(table_cache, "COMMENT ON TABLE "));
        GS_RETURN_IFERR(exp_cache_append_str_quote(table_cache,
            exp_remap_table_name(&g_export_opts.table_maps, g_str_buf, NULL, 0)));
        GS_RETURN_IFERR(exp_cache_append_str(table_cache, " IS '"));

        GS_RETURN_IFERR(gsc_column_as_string(STMT, 1, g_str_buf, GS_MAX_PACKET_SIZE));
        GS_RETURN_IFERR(exp_cache_append_escape_str(table_cache, g_str_buf, '\''));
        GS_RETURN_IFERR(exp_cache_append_str(table_cache, "';\n"));
    }

    PRTS_RETURN_IFERR(sprintf_s(cmd_buf, GSQL_MAX_TEMP_SQL,
        "SELECT TABLE_NAME, COLUMN_NAME, COMMENTS "
        "FROM %s "
        "WHERE OWNER = UPPER(:OWNER) AND TABLE_NAME = :TABLE_NAME AND COMMENTS IS NOT NULL "
        "ORDER BY COLUMN_NAME",
        exp_tabname(g_export_opts.consistent, EXP_TABAGENT_DB_COL_COMMENTS)));

    GS_RETURN_IFERR(gsc_prepare(STMT, (const char *)cmd_buf));

    GS_RETURN_IFERR(gsc_bind_by_pos(STMT, 0, GSC_TYPE_STRING, user, (int32)strlen(user), NULL));
    GS_RETURN_IFERR(gsc_bind_by_pos(STMT, 1, GSC_TYPE_STRING, table, (int32)strlen(table), NULL));

    GS_RETURN_IFERR(gsc_execute(STMT));

    do {
        GS_RETURN_IFERR(gsc_fetch(STMT, &rows));
        if (rows == 0) {
            break;
        }

        GS_RETURN_IFERR(gsc_column_as_string(STMT, 0, g_str_buf, GS_MAX_PACKET_SIZE));
        GS_RETURN_IFERR(exp_cache_append_str(table_cache, "COMMENT ON COLUMN "));
        GS_RETURN_IFERR(exp_cache_append_str_quote(table_cache, g_str_buf));
        GS_RETURN_IFERR(exp_cache_append_str(table_cache, "."));
        GS_RETURN_IFERR(gsc_column_as_string(STMT, 1, g_str_buf, GS_MAX_PACKET_SIZE));
        GS_RETURN_IFERR(exp_cache_append_str_quote(table_cache, g_str_buf));
        GS_RETURN_IFERR(exp_cache_append_str(table_cache, " IS '"));
        GS_RETURN_IFERR(gsc_column_as_string(STMT, 2, g_str_buf, GS_MAX_PACKET_SIZE));
        GS_RETURN_IFERR(exp_cache_append_escape_str(table_cache, g_str_buf, '\''));
        GS_RETURN_IFERR(exp_cache_append_str(table_cache, "';\n"));
    } while (GS_TRUE);

    return GS_SUCCESS;
}

static inline int exp_table_index_check_tabspace(export_options_t *exp_opts, const char *tabspace)
{
    for (uint32 i = 0; i < exp_opts->tbs_list.count; i++) {
        char *list_member = (char *)cm_list_get(&(exp_opts->tbs_list), i);
        if (cm_str_equal(list_member, tabspace)) {
            return GS_SUCCESS;
        }
    }
    return GS_ERROR;
}

static int exp_table_func_indexes(exp_tabs_ctx_t *ctx, const char *table,
    const char *index_name, exp_cache_t* table_cache)
{
    uint32 total_columns = 0;
    uint32 rows;
    uint32 cursor = 0;
    gsc_stmt_t stmt = ctx->query_func_indexes;

    GS_RETURN_IFERR(gsc_bind_by_pos(stmt, 0, GSC_TYPE_STRING, ctx->user, (int32)strlen(ctx->user), NULL));
    GS_RETURN_IFERR(gsc_bind_by_pos(stmt, 1, GSC_TYPE_STRING, table, (int32)strlen(table), NULL));
    GS_RETURN_IFERR(gsc_bind_by_pos(stmt, 2, GSC_TYPE_STRING, index_name, (int32)strlen(index_name), NULL));

    GS_RETURN_IFERR(gsc_execute(stmt));

    do {
        GS_RETURN_IFERR(gsc_fetch(stmt, &rows));

        if (rows == 0) {
            break;
        }

        total_columns += rows;
        GS_RETURN_IFERR(gsc_column_as_string(stmt, 0, g_str_buf, GS_MAX_PACKET_SIZE));

        if (g_str_buf == NULL || strlen(g_str_buf) == 0) {
            EXP_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "The index is not correct.");
            return GS_ERROR;
        }

        if (cursor > 0) {
            GS_RETURN_IFERR(exp_cache_append_str(table_cache, ", "));
        }

        GS_RETURN_IFERR(exp_cache_append_str(table_cache, g_str_buf));

        cursor++;
    } while (GS_TRUE);

    if (total_columns == 0) {
        // if export func-index , drop tables occurs, func-index column count may be 0, throw error.
        EXP_THROW_ERROR(ERR_TABLE_OR_VIEW_NOT_EXIST, ctx->user, table);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static int exp_index_subpartition(exp_tabs_ctx_t *ctx, exp_cache_t* table_cache, const char *partition_name, const char *index_name)
{
    uint32 rows;
    uint32 cursor = 0;
    char cmd_buf[GSQL_MAX_TEMP_SQL + 1];
    gsc_stmt_t stmt = ctx->query_index_subpartition;

    GS_RETURN_IFERR(gsc_bind_by_pos(stmt, 0, GSC_TYPE_STRING, partition_name, (int32)strlen(partition_name), NULL));
    GS_RETURN_IFERR(gsc_bind_by_pos(stmt, 1, GSC_TYPE_STRING, index_name, (int32)strlen(index_name), NULL));
    GS_RETURN_IFERR(gsc_bind_by_pos(stmt, 2, GSC_TYPE_STRING, ctx->user, (int32)strlen(ctx->user), NULL));
    GS_RETURN_IFERR(gsc_execute(stmt));

    do {
        GS_RETURN_IFERR(gsc_fetch(stmt, &rows));

        if (rows == 0) {
            break;
        }

        if (cursor > 0) {
            GS_RETURN_IFERR(exp_cache_append_str(table_cache, ",\n"));
        } else {
            GS_RETURN_IFERR(exp_cache_append_str(table_cache, "(\n"));
        }

        GS_RETURN_IFERR(exp_cache_append_str(table_cache, "           SUBPARTITION "));
        GS_RETURN_IFERR(gsc_column_as_string(stmt, 0, cmd_buf, GSQL_MAX_TEMP_SQL));
        GS_RETURN_IFERR(exp_cache_append_str(table_cache, cmd_buf));

        GS_RETURN_IFERR(exp_cache_append_str(table_cache, " TABLESPACE "));
        GS_RETURN_IFERR(gsc_column_as_string(stmt, 1, cmd_buf, GSQL_MAX_TEMP_SQL));
        GS_RETURN_IFERR(exp_cache_append_str_quote(table_cache, cmd_buf));
        cursor++;
    } while (GS_TRUE);

    if (cursor > 0) {
        GS_RETURN_IFERR(exp_cache_append_str(table_cache, "\n        )"));
    }

    return GS_SUCCESS;
}

static int exp_has_sub_partition(gsc_stmt_t stmt, const char *user, const char *table, bool8 *has_sub_partition)
{
    uint32 rows;
    char cmd_buf[GSQL_MAX_TEMP_SQL + 1] = { 0 };

    GS_RETURN_IFERR(gsc_bind_by_pos(stmt, 0, GSC_TYPE_STRING, user, (int32)strlen(user), NULL));
    GS_RETURN_IFERR(gsc_bind_by_pos(stmt, 1, GSC_TYPE_STRING, table, (int32)strlen(table), NULL));
    GS_RETURN_IFERR(gsc_execute(stmt));

    GS_RETURN_IFERR(gsc_fetch(stmt, &rows));

    if (rows == 0) {
        return GS_SUCCESS;
    }

    GS_RETURN_IFERR(gsc_column_as_string(stmt, 0, cmd_buf, GS_MAX_NAME_LEN));
    *has_sub_partition = (cm_str_equal((const char *)cmd_buf, "RANGE")
                          || cm_str_equal((const char *)cmd_buf, "LIST")
                          || cm_str_equal((const char *)cmd_buf, "HASH"));

    return GS_SUCCESS;
}

static inline bool8 exp_need_index_partition(void)
{
    return g_export_opts.index_partitions &&
        gsc_get_call_version(CONN) >= CS_VERSION_23;
}

static int exp_index_partitioning(exp_tabs_ctx_t *ctx, exp_cache_t* table_cache, const char *table,
    const char *index_name, const char *tablespace_name)
{
    uint32 rows;
    uint32 cnt = 0;
    char partition_name[GSQL_MAX_OBJECT_LEN] = { 0 };
    char cmd_buf[GSQL_MAX_TEMP_SQL + 1];
    char partition_tbls[GSQL_MAX_OBJECT_LEN] = { 0 };
    bool8 has_sub_partition = 0;
    gsc_stmt_t stmt = ctx->query_index_partitioning;

    GS_RETURN_IFERR(exp_has_sub_partition(ctx->query_has_subpartition, ctx->user, table, &has_sub_partition));

    GS_RETURN_IFERR(gsc_bind_by_pos(stmt, 0, GSC_TYPE_STRING, index_name, (int32)strlen(index_name), NULL));
    GS_RETURN_IFERR(gsc_bind_by_pos(stmt, 1, GSC_TYPE_STRING, ctx->user, (int32)strlen(ctx->user), NULL));
    GS_RETURN_IFERR(gsc_execute(stmt));

    do {
        GS_RETURN_IFERR(gsc_fetch(stmt, &rows));

        if (rows == 0) {
            break;
        }

        GS_RETURN_IFERR(gsc_column_as_string(stmt, 0, partition_tbls, GSQL_MAX_OBJECT_LEN));

        if (cnt > 0) {
            GS_RETURN_IFERR(exp_cache_append_str(table_cache, ",\n"));
        } else {
            GS_RETURN_IFERR(exp_cache_append_str(table_cache, "      (\n"));
        }

        GS_RETURN_IFERR(exp_cache_append_str(table_cache, "       PARTITION "));
        GS_RETURN_IFERR(gsc_column_as_string(stmt, 0, cmd_buf, GSQL_MAX_TEMP_SQL));
        MEMS_RETURN_IFERR(memcpy_s(partition_name, GSQL_MAX_OBJECT_LEN, cmd_buf, GSQL_MAX_OBJECT_LEN));
        partition_name[strlen(partition_name)] = '\0';
        GS_RETURN_IFERR(exp_cache_append_str(table_cache, cmd_buf));

        GS_RETURN_IFERR(exp_cache_append_str(table_cache, " TABLESPACE "));
        GS_RETURN_IFERR(gsc_column_as_string(stmt, 1, cmd_buf, GSQL_MAX_OBJECT_LEN));
        GS_RETURN_IFERR(exp_cache_append_str_quote(table_cache, cmd_buf));

        GS_RETURN_IFERR(exp_cache_append_str(table_cache, " INITRANS "));
        GS_RETURN_IFERR(gsc_column_as_string(stmt, 2, cmd_buf, GSQL_MAX_TEMP_SQL));
        GS_RETURN_IFERR(exp_cache_append_str(table_cache, cmd_buf));

        GS_RETURN_IFERR(exp_cache_append_str(table_cache, " PCTFREE "));
        GS_RETURN_IFERR(gsc_column_as_string(stmt, 3, cmd_buf, GSQL_MAX_TEMP_SQL));
        GS_RETURN_IFERR(exp_cache_append_str(table_cache, cmd_buf));

        if (has_sub_partition) {
            GS_RETURN_IFERR(exp_index_subpartition(ctx, table_cache,
                partition_name, index_name));
        }
        cnt++;
    } while (GS_TRUE);

    if (cnt > 0) {
        GS_RETURN_IFERR(exp_cache_append_str(table_cache, "\n      )\n"));
    }

    return GS_SUCCESS;
}

static status_t exp_tab_has_interval_parts(exp_tabs_ctx_t *ctx, const char *table, bool8 *has_interval_part)
{
    gsc_stmt_t stmt = ctx->query_tab_has_intervalpart;
    uint32 rows = 0;
    uint64 cnt = 0;

    *has_interval_part = GS_FALSE;

    GS_RETURN_IFERR(gsc_bind_by_pos(stmt, 0, GSC_TYPE_STRING, ctx->user, (int32)strlen(ctx->user), NULL));
    GS_RETURN_IFERR(gsc_bind_by_pos(stmt, 1, GSC_TYPE_STRING, table, (int32)strlen(table), NULL));

    GS_RETURN_IFERR(gsc_bind_column(stmt, 0, GSC_TYPE_BIGINT, sizeof(cnt), &cnt, NULL));

    GS_RETURN_IFERR(gsc_execute(stmt));

    GS_RETURN_IFERR(gsc_fetch(stmt, &rows));
    if (rows == 0) {
        return GS_SUCCESS;
    }

    *has_interval_part = (cnt > 0);
    return GS_SUCCESS;
}

static int exp_table_indexes(exp_tabs_ctx_t *ctx, const char *table, exp_cache_t* table_cache)
{
    uint32 rows;
    char org_ind_name[GSQL_MAX_OBJECT_LEN] = { 0 };
    char cmd_buf[GSQL_MAX_TEMP_SQL + 1];
    char tablespace_name[GSQL_MAX_OBJECT_LEN] = { 0 };
    bool8 has_interval_part = GS_FALSE;

    PRTS_RETURN_IFERR(sprintf_s(cmd_buf, GSQL_MAX_TEMP_SQL,
        "SELECT IS_PRIMARY, IS_UNIQUE, IS_DUPLICATE, INDEX_NAME, "
        "       COLUMNS, TABLESPACE_NAME, INI_TRANS, MAX_TRANS, PCT_FREE, "
        "       PARTITIONED, CR_MODE %s %s "
        "FROM %s "
        "WHERE OWNER = UPPER(:OWNER) AND TABLE_NAME = :TABLE_NAME AND SYS_GENERATE = 0 "
        "ORDER BY INDEX_NAME", ctx->reverse_index_available ? ", IS_REVERSED " : " ",
        (gsc_get_call_version(CONN) >= CS_VERSION_25) ? ", IS_NOLOGGING" : " ",
        exp_tabname(g_export_opts.consistent, EXP_TABAGENT_DB_INDEXES)));

    GS_RETURN_IFERR(gsc_prepare(STMT, (const char *)cmd_buf));

    GS_RETURN_IFERR(gsc_bind_by_pos(STMT, 0, GSC_TYPE_STRING, ctx->user, (int32)strlen(ctx->user), NULL));
    GS_RETURN_IFERR(gsc_bind_by_pos(STMT, 1, GSC_TYPE_STRING, table, (int32)strlen(table), NULL));

    GS_RETURN_IFERR(gsc_execute(STMT));

    do {
        GS_RETURN_IFERR(gsc_fetch(STMT, &rows));
        if (rows == 0) {
            break;
        }
        // check tablespace filter
        GS_RETURN_IFERR(gsc_column_as_string(STMT, 5, g_str_buf, GS_MAX_PACKET_SIZE));
        if (ctx->exp_opts->tbs_list.count > 0 &&
            exp_table_index_check_tabspace(ctx->exp_opts, g_str_buf) != GS_SUCCESS) {
            continue;
        }

        GS_RETURN_IFERR(gsc_column_as_string(STMT, 1, g_str_buf, GS_MAX_PACKET_SIZE));

        if (g_str_buf[0] == 'Y') {
            GS_RETURN_IFERR(exp_cache_append_str(table_cache, "CREATE UNIQUE INDEX "));
        } else {
            GS_RETURN_IFERR(exp_cache_append_str(table_cache, "CREATE INDEX "));
        }
        
        GS_RETURN_IFERR(gsc_column_as_string(STMT, 3, g_str_buf, GS_MAX_PACKET_SIZE));
        MEMS_RETURN_IFERR(memcpy_s(org_ind_name, GSQL_MAX_OBJECT_LEN, g_str_buf, GSQL_MAX_OBJECT_LEN));
        org_ind_name[strlen(g_str_buf)] = '\0';

        GS_RETURN_IFERR(exp_cache_append_str_quote(table_cache, g_str_buf));
        GS_RETURN_IFERR(exp_cache_append_str(table_cache, " ON "));
        GS_RETURN_IFERR(exp_cache_append_str_quote(table_cache,
            exp_remap_table_name(&ctx->exp_opts->table_maps, table, NULL, 0)));
        GS_RETURN_IFERR(exp_cache_append_str(table_cache, "("));
        if (!g_export_opts.quote_names) {
            GS_RETURN_IFERR(gsc_column_as_string(STMT, 4, g_str_buf, GS_MAX_PACKET_SIZE));
            GS_RETURN_IFERR(exp_cache_append_str(table_cache, g_str_buf));
        } else {
            GS_RETURN_IFERR(exp_table_func_indexes(ctx, table, org_ind_name, table_cache));
        }

        GS_RETURN_IFERR(exp_cache_append_str(table_cache, ")\n"));

        GS_RETURN_IFERR(gsc_column_as_string(STMT, 9, g_str_buf, GS_MAX_PACKET_SIZE));

        if (g_str_buf[0] == 'Y') {
            GS_RETURN_IFERR(exp_cache_append_str(table_cache, "LOCAL\n"));
        }

        GS_RETURN_IFERR(gsc_column_as_string(STMT, 5, g_str_buf, GS_MAX_PACKET_SIZE));
        MEMS_RETURN_IFERR(memcpy_s(tablespace_name, GSQL_MAX_OBJECT_LEN, g_str_buf, GSQL_MAX_OBJECT_LEN));
        tablespace_name[strlen(tablespace_name)] = '\0';

        GS_RETURN_IFERR(exp_tab_has_interval_parts(ctx, table, &has_interval_part));
        if (exp_need_index_partition() && !has_interval_part) {
            GS_RETURN_IFERR(exp_index_partitioning(ctx, table_cache, table, org_ind_name, tablespace_name));
        }

        if (strncmp(g_str_buf, "TEMP", strlen("TEMP")) != 0) { /* do not append tablespace if in "TEMP" */
            GS_RETURN_IFERR(exp_cache_append_str(table_cache, "TABLESPACE "));
            GS_RETURN_IFERR(exp_cache_append_str_quote(table_cache, g_str_buf));
            GS_RETURN_IFERR(exp_cache_append_str(table_cache, "\n"));
        }

        GS_RETURN_IFERR(exp_cache_append_str(table_cache, "INITRANS "));
        GS_RETURN_IFERR(gsc_column_as_string(STMT, 6, g_str_buf, GS_MAX_PACKET_SIZE));
        GS_RETURN_IFERR(exp_cache_append_str(table_cache, g_str_buf));
        GS_RETURN_IFERR(exp_cache_append_str(table_cache, "\n"));

        GS_RETURN_IFERR(exp_cache_append_str(table_cache, "PCTFREE "));
        GS_RETURN_IFERR(gsc_column_as_string(STMT, 8, g_str_buf, GS_MAX_PACKET_SIZE));
        GS_RETURN_IFERR(exp_cache_append_str(table_cache, g_str_buf));

        if (ctx->exp_opts->with_cr_mode) {
            GS_RETURN_IFERR(gsc_column_as_string(STMT, 10, g_str_buf, GS_MAX_PACKET_SIZE));
            if (strlen(g_str_buf) > 0) {
                GS_RETURN_IFERR(exp_cache_append_str(table_cache, "\nCRMODE "));
                GS_RETURN_IFERR(exp_cache_append_str(table_cache, g_str_buf));
            }
        }

        if (ctx->reverse_index_available) {
            GS_RETURN_IFERR(gsc_column_as_string(STMT, 11, g_str_buf, GS_MAX_PACKET_SIZE));
            if (g_str_buf[0] == 'Y') {
                GS_RETURN_IFERR(exp_cache_append_str(table_cache, "\nREVERSE"));
            }
        }

        if (gsc_get_call_version(CONN) >= CS_VERSION_25) {
            GS_RETURN_IFERR(gsc_column_as_string(STMT, 12, g_str_buf, GS_MAX_PACKET_SIZE));
            if (g_str_buf[0] == 'Y') {
                GS_RETURN_IFERR(exp_cache_append_str(table_cache, "\nNOLOGGING"));
            }
        }
        GS_RETURN_IFERR(exp_cache_append_str(table_cache, ";\n"));
    } while (GS_TRUE);
    return GS_SUCCESS;
}

static int exp_table_auto_increment(const char *user, const char *table, exp_cache_t *table_cache)
{
    uint32 rows;
    char cmd_buf[GSQL_MAX_TEMP_SQL + 1];

    PRTS_RETURN_IFERR(sprintf_s(cmd_buf, GSQL_MAX_TEMP_SQL,
        "SELECT COLUMN_NAME "
        "FROM %s "
        "WHERE OWNER = UPPER(:OWNER) AND TABLE_NAME = :TABLE_NAME AND AUTO_INCREMENT = 'Y'",
        exp_tabname(g_export_opts.consistent, EXP_TABAGENT_DB_TAB_COLUMNS)));
    GS_RETURN_IFERR(gsc_prepare(STMT, (const char *)cmd_buf));
    GS_RETURN_IFERR(gsc_bind_by_pos(STMT, 0, GSC_TYPE_STRING, user, (int32)strlen(user), NULL));
    GS_RETURN_IFERR(gsc_bind_by_pos(STMT, 1, GSC_TYPE_STRING, table, (int32)strlen(table), NULL));
    GS_RETURN_IFERR(gsc_execute(STMT));
    GS_RETURN_IFERR(gsc_fetch(STMT, &rows));
    if (rows == 0) {
        return GS_SUCCESS;
    }
    if (!g_export_opts.show_create_table) {
        exp_log(EXP_INDENT "exporting auto_increment attr on %s.%s ...\n", user, table);
    }
    // ALTER TABLE "ABC" MODIFY "F2" auto_increment;
    GS_RETURN_IFERR(exp_cache_append_str(table_cache, "ALTER TABLE "));
    GS_RETURN_IFERR(exp_cache_append_str_quote(table_cache, table));
    GS_RETURN_IFERR(exp_cache_append_str(table_cache, " MODIFY "));
    GS_RETURN_IFERR(gsc_column_as_string(STMT, 0, g_str_buf, GS_MAX_PACKET_SIZE));
    GS_RETURN_IFERR(exp_cache_append_str_quote(table_cache, g_str_buf));
    GS_RETURN_IFERR(exp_cache_append_str(table_cache, " AUTO_INCREMENT"));
    GS_RETURN_IFERR(exp_cache_append_str(table_cache, ";\n"));
    PRTS_RETURN_IFERR(sprintf_s(cmd_buf, GSQL_MAX_TEMP_SQL,
        "SELECT  SERIAL_LASTVAL(UPPER(:USER),:TABLE) FROM SYS_DUMMY"));
    GS_RETURN_IFERR(gsc_prepare(STMT, (const char *)cmd_buf));
    GS_RETURN_IFERR(gsc_bind_by_pos(STMT, 0, GSC_TYPE_STRING, user, (int32)strlen(user), NULL));
    GS_RETURN_IFERR(gsc_bind_by_pos(STMT, 1, GSC_TYPE_STRING, table, (int32)strlen(table), NULL));
    GS_RETURN_IFERR(gsc_execute(STMT));
    GS_RETURN_IFERR(gsc_fetch(STMT, &rows));
    // ALTER TABLE "ABC" AUTO_INCREMENT = 1000;
    GS_RETURN_IFERR(exp_cache_append_str(table_cache, "ALTER TABLE "));
    GS_RETURN_IFERR(exp_cache_append_str_quote(table_cache, table));
    GS_RETURN_IFERR(exp_cache_append_str(table_cache, " AUTO_INCREMENT"));
    GS_RETURN_IFERR(exp_cache_append_str(table_cache, " = "));
    GS_RETURN_IFERR(gsc_column_as_string(STMT, 0, g_str_buf, GS_MAX_PACKET_SIZE));
    GS_RETURN_IFERR(exp_cache_append_str(table_cache, g_str_buf));
    GS_RETURN_IFERR(exp_cache_append_str(table_cache, ";\n"));
    return GS_SUCCESS;
}

static inline int exp_table_foreign_constraints(const char *user, const char *table)
{
    uint32 rows;
    char cmd_buf[GSQL_MAX_TEMP_SQL + 1];

    PRTS_RETURN_IFERR(sprintf_s(cmd_buf, GSQL_MAX_TEMP_SQL,
        "SELECT CONSTRAINT_TYPE, CONS_COLS, REF_COLS, CONSTRAINT_NAME, TABLE_NAME, SEARCH_CONDITION, "
        "DECODE(R_OWNER, OWNER, R_TABLE_NAME, R_OWNER || '.' || R_TABLE_NAME), R_CONSTRAINT_NAME, "
        "DECODE(DELETE_RULE, 'DELETE CASCADE', ' ON DELETE CASCADE', 'SET NULL', ' ON DELETE SET NULL'), "
        "REPLACE(CONS_COLS ,', ', '\", \"'), REPLACE(REF_COLS ,', ', '\", \"'), "
        "DECODE(R_OWNER, OWNER, R_TABLE_NAME, R_OWNER || '\".\"'|| R_TABLE_NAME), IS_DUPLICATE, SYS_GENERATE "
        "FROM %s "
        "WHERE OWNER = UPPER(:OWNER) AND TABLE_NAME = :TABLE_NAME AND CONSTRAINT_TYPE = 'R'"
        "ORDER BY CONSTRAINT_NAME",
        exp_tabname(g_export_opts.consistent, EXP_TABAGENT_DB_CONSTRAINTS)));

    GS_RETURN_IFERR(gsc_prepare(STMT, (const char *)cmd_buf));

    GS_RETURN_IFERR(gsc_bind_by_pos(STMT, 0, GSC_TYPE_STRING, user, (int32)strlen(user), NULL));
    GS_RETURN_IFERR(gsc_bind_by_pos(STMT, 1, GSC_TYPE_STRING, table, (int32)strlen(table), NULL));

    GS_RETURN_IFERR(gsc_execute(STMT));

    do {
        GS_RETURN_IFERR(gsc_fetch(STMT, &rows));
        if (rows == 0) {
            break;
        }

        GS_RETURN_IFERR(exp_write_str_s("ALTER TABLE ", &g_exp_txtbuf, g_exp_dpfile));
        GS_RETURN_IFERR(gsc_column_as_string(STMT, 4, g_str_buf, GS_MAX_PACKET_SIZE));
        exp_write_str_quote(g_str_buf);
        GS_RETURN_IFERR(gsc_column_as_string(STMT, 13, g_str_buf, GS_MAX_PACKET_SIZE));

        if (g_str_buf[0] == 'N') {
            GS_RETURN_IFERR(exp_write_str_s(" ADD CONSTRAINT ", &g_exp_txtbuf, g_exp_dpfile));
            GS_RETURN_IFERR(gsc_column_as_string(STMT, 3, g_str_buf, GS_MAX_PACKET_SIZE));
            exp_write_str_quote(g_str_buf);
        } else if (g_str_buf[0] == 'Y') {
            GS_RETURN_IFERR(exp_write_str_s(" ADD", &g_exp_txtbuf, g_exp_dpfile));
        } else {
            continue;
        }

        GS_RETURN_IFERR(exp_write_str_s(" ", &g_exp_txtbuf, g_exp_dpfile));

        GS_RETURN_IFERR(gsc_column_as_string(STMT, 0, g_str_buf, GS_MAX_PACKET_SIZE));

        if (g_str_buf[0] == 'R') {
            if (!g_export_opts.quote_names) {
                GS_RETURN_IFERR(gsc_column_as_string(STMT, 1, g_str_buf, GS_MAX_PACKET_SIZE));
            } else {
                GS_RETURN_IFERR(gsc_column_as_string(STMT, 9, g_str_buf, GS_MAX_PACKET_SIZE));
            }
            GS_RETURN_IFERR(exp_write_str_s("FOREIGN KEY(", &g_exp_txtbuf, g_exp_dpfile));
            exp_write_str_quote(g_str_buf);
            GS_RETURN_IFERR(exp_write_str_s(") REFERENCES ", &g_exp_txtbuf, g_exp_dpfile));
            if (!g_export_opts.quote_names) {
                GS_RETURN_IFERR(gsc_column_as_string(STMT, 6, g_str_buf, GS_MAX_PACKET_SIZE));
            } else {
                GS_RETURN_IFERR(gsc_column_as_string(STMT, 11, g_str_buf, GS_MAX_PACKET_SIZE));
            }
            exp_write_str_quote(g_str_buf);
            GS_RETURN_IFERR(exp_write_str_s("(", &g_exp_txtbuf, g_exp_dpfile));
            if (!g_export_opts.quote_names) {
                GS_RETURN_IFERR(gsc_column_as_string(STMT, 2, g_str_buf, GS_MAX_PACKET_SIZE));
            } else {
                GS_RETURN_IFERR(gsc_column_as_string(STMT, 10, g_str_buf, GS_MAX_PACKET_SIZE));
            }
            exp_write_str_quote(g_str_buf);
            GS_RETURN_IFERR(exp_write_str_s(")", &g_exp_txtbuf, g_exp_dpfile));
            GS_RETURN_IFERR(gsc_column_as_string(STMT, 8, g_str_buf, GS_MAX_PACKET_SIZE));
            GS_RETURN_IFERR(exp_write_str_s(g_str_buf, &g_exp_txtbuf, g_exp_dpfile));
        } else {
            continue;
        }
        GS_RETURN_IFERR(exp_write_str_s(";\n", &g_exp_txtbuf, g_exp_dpfile));
    } while (GS_TRUE);

    return GS_SUCCESS;
}

#define TABLE_IS_TEMP(tab_type) ((tab_type) == TABLE_TYPE_TRANS_TEMP || (tab_type) == TABLE_TYPE_SESSION_TEMP)

static status_t exp_tab_meta(export_options_t *exp_opts, exp_tab_info_t *tab_info, exp_cache_t *table_cache)
{
    /* allocate cache unit for create table SQL */
    GS_RETURN_IFERR(exp_start_cache_unit(table_cache, EXP_CACHE_CREATE_TABLE));

    /* 'show create table' option suppresses irrelevant info display */
    if (!g_export_opts.show_create_table) {
        exp_log(EXP_INDENT "exporting DDL of %s.%s ...\n", tab_info->user, tab_info->table);
    }

    /* 'show create table' option suppresses irrelevant info display */
    if (!exp_opts->skip_add_drop_table && !g_export_opts.show_create_table) {
        GS_RETURN_IFERR(exp_cache_append_str(table_cache, "DROP TABLE IF EXISTS "));
        GS_RETURN_IFERR(exp_cache_append_str_quote(table_cache,
            exp_remap_table_name(&exp_opts->table_maps, tab_info->table, NULL, 0)));
        GS_RETURN_IFERR(exp_cache_append_str(table_cache, " CASCADE CONSTRAINTS;\n"));
    }

    GS_RETURN_IFERR(exp_create_table(tab_info, table_cache));

    if (!TABLE_IS_TEMP(tab_info->table_type)) {
        GS_RETURN_IFERR(exp_table_attrs(tab_info->user, tab_info->table, table_cache));
    }
    GS_RETURN_IFERR(exp_cache_append_str(table_cache, ";\n"));

    if (!exp_opts->skip_comments) {
        EXP_RETURN_IFERR(exp_table_comments(tab_info->user, tab_info->table, table_cache));
    }

    return GS_SUCCESS;
}

static status_t exp_tab_indx_meta(exp_tabs_ctx_t *ctx, const char *table, exp_cache_t *table_cache)
{
    if (!g_export_opts.show_create_table) {
        exp_log(EXP_INDENT "exporting indexes on %s.%s ...\n", ctx->user, table);
    }
    GS_RETURN_IFERR(exp_table_indexes(ctx, table, table_cache));
    if (!g_export_opts.show_create_table) {
        exp_log(EXP_INDENT "exporting constraints on %s.%s ...\n", ctx->user, table);
    }
    GS_RETURN_IFERR(exp_table_constraints(ctx, table, table_cache, GS_FALSE));
    GS_RETURN_IFERR(exp_table_constraints(ctx, table, table_cache, GS_TRUE));
    if (!g_export_opts.show_create_table) {
        exp_log("\n");
    }

    return GS_SUCCESS;
}

static inline int exp_add_tblobj(gsc_stmt_t stmt, uint32 col_id, list_t *table_list)
{
    uint32 rows;
    char *ptr = NULL;
    uint32 i = 0;

    exp_log("\nThe order of exporting table is:\n");
    exp_log("%-64s %-10s\n", "TABLE NAME", "LEVEL");
    exp_log("---------------------------------------------------------------- ----------\n");

    do {
        GS_RETURN_IFERR(gsc_fetch(stmt, &rows));
        if (rows == 0) {
            break;
        }
        GS_RETURN_IFERR(gsc_column_as_string(STMT, col_id, g_str_buf, GS_MAX_PACKET_SIZE));
        if ((cm_list_new(table_list, (pointer_t *)&ptr) != GS_SUCCESS) || (ptr == NULL)) {
            return GS_ERROR;
        }
        MEMS_EXP_RETURN_IFERR(strncpy_s(ptr, GSQL_MAX_OBJECT_LEN, g_str_buf, GSQL_MAX_OBJECT_LEN - 1));
        i++;
        exp_log("%-64s ", ptr);
        exp_log("%-10u\n", i);
    } while (GS_TRUE);

    exp_log("\n");
    return GS_SUCCESS;
}

static inline int exp_get_user_tables(export_options_t *exp_opts, const char *user, list_t *table_list)
{
    char cmd_buf[GSQL_MAX_TEMP_SQL + 1];
    exp_prepare_sql_param_t param;

    param.comm_param.exp_opts = exp_opts;
    GS_RETURN_IFERR(EXP_PREPARE_SQL(EXP_GET_USER_TABLE_LIST, cmd_buf, GSQL_MAX_TEMP_SQL, &param));

    GS_RETURN_IFERR(gsc_prepare(STMT, (const char *)cmd_buf));

    GS_RETURN_IFERR(gsc_bind_by_pos(STMT, 0, GSC_TYPE_STRING, user, (int32)strlen(user), NULL));

    GS_RETURN_IFERR(gsc_execute(STMT));

    GS_RETURN_IFERR(exp_add_tblobj(STMT, 0, table_list));

    return GS_SUCCESS;
}

static inline int exp_get_users(export_options_t *exp_opts)
{
    uint32 rows;
    char *ptr = NULL;
    int iret_sprintf;
    char cmd_buf[GSQL_MAX_TEMP_SQL + 1];

    iret_sprintf = sprintf_s(cmd_buf, GSQL_MAX_TEMP_SQL,
                             "SELECT USERNAME "
                             "FROM " EXP_USERS_AGENT " "
                             "WHERE USERNAME <> 'SYS' AND USERNAME <> 'PUBLIC' ORDER BY USERNAME");
    if (iret_sprintf == -1) {
        EXP_THROW_ERROR(ERR_SYSTEM_CALL, iret_sprintf);
        return GS_ERROR;
    }

    GS_RETURN_IFERR(gsc_prepare(STMT, (const char *)cmd_buf));
    GS_RETURN_IFERR(gsc_execute(STMT));

    do {
        GS_RETURN_IFERR(gsc_fetch(STMT, &rows));
        if (rows == 0) {
            break;
        }
        GS_RETURN_IFERR(gsc_column_as_string(STMT, 0, g_str_buf, GS_MAX_PACKET_SIZE));
        if (cm_list_new(&exp_opts->obj_list, (pointer_t *)&ptr) != GS_SUCCESS) {
            return GS_ERROR;
        }
        MEMS_EXP_RETURN_IFERR(strncpy_s(ptr, GSQL_MAX_OBJECT_LEN, g_str_buf, GSQL_MAX_OBJECT_LEN - 1));
    } while (GS_TRUE);

    return GS_SUCCESS;
}

static status_t par_exp_connectdb(par_exp_thread_ctrl_t *ctrl)
{
    bool32 interactive_clt = GS_FALSE;
    uint32 new_num_width = (uint32)GS_MAX_DEC_OUTPUT_ALL_PREC;
    /* Re-establishing connections is not supported */
    if (ctrl->conn_info.conn == NULL) {
        ctrl->execute_ret = gsql_alloc_conn(&ctrl->conn_info.conn);
        if (ctrl->execute_ret != GS_SUCCESS) {
            exp_tmlog("parallel export table:%s failed, alloc connect failed\n", ctrl->tab_param.tab_name);
            gsql_print_error(NULL);
            return ctrl->execute_ret;
        }
        /* set session interactive check disable */
        (void)gsc_set_conn_attr(ctrl->conn_info.conn, GSC_ATTR_INTERACTIVE_MODE, (void *)&interactive_clt, 0);
        (void)gsc_set_conn_attr(ctrl->conn_info.conn, GSC_ATTR_NUM_WIDTH, (void *)&new_num_width, sizeof(uint32));
        GS_RETURN_IFERR(gsql_get_saved_pswd(ctrl->conn_info.passwd, GS_PASSWORD_BUFFER_SIZE + 4));

        (void)gsql_switch_user(&ctrl->conn_info);
        ctrl->execute_ret = gsql_conn_to_server(&ctrl->conn_info, GS_FALSE, GS_TRUE);
        if (ctrl->execute_ret != GS_SUCCESS) {
            exp_tmlog("parallel export table:%s failed, connect to server failed\n", ctrl->tab_param.tab_name);
            return ctrl->execute_ret;
        }
    }

    return GS_SUCCESS;
}

static int par_exp_clean_empty_files(par_exp_thread_ctrl_t *ctrl, uint64 file_insert_num, bool32 wr_lob_flg)
{
    char full_fpath[GS_MAX_FILE_PATH_LENGH];

    if ((wr_lob_flg == GS_FALSE) && (ctrl->files_context.lf_h != NULL)) {
        if (g_export_opts.compress && g_export_opts.filetype == FT_BIN) {
            (void)gsc_common_z_uninit_write(&ctrl->files_context.lf_zstream);
        }
        fclose(ctrl->files_context.lf_h);
        ctrl->files_context.lf_h = NULL;

        GS_RETURN_IFERR(exp_form_fullpath(ctrl->options.dump_data_path, ctrl->options.lob_file_name, full_fpath,
            GS_MAX_FILE_PATH_LENGH));
        GS_RETURN_IFERR(cm_remove_file((const char *)full_fpath));
    }

    if ((file_insert_num == 0) && (ctrl->files_context.exp_dpfile != NULL)) {
        if (g_export_opts.compress && g_export_opts.filetype == FT_BIN) {
            (void)gsc_common_z_uninit_write(&ctrl->files_context.df_zstream);
        }
        fclose(ctrl->files_context.exp_dpfile);
        ctrl->files_context.exp_dpfile = NULL;
        GS_RETURN_IFERR(exp_form_fullpath(ctrl->options.dump_data_path, ctrl->options.bin_data_file, full_fpath,
            GS_MAX_FILE_PATH_LENGH));
        GS_RETURN_IFERR(cm_remove_file((const char *)full_fpath));
    }

    return GS_SUCCESS;
}

static void par_exp_proc(thread_t *thread)
{
    uint64 file_insert_num;
    bool32 wr_lob_flg;
    par_exp_thread_ctrl_t *ctrl = (par_exp_thread_ctrl_t *)thread->argument;
    int32 ret = GS_SUCCESS;
    gsc_conn_t conn;

    ctrl->execute_ret = GS_SUCCESS;
    EXP_RESET_ERROR;

    while (!thread->closed) {
        if (par_exp_get_ctrl_stat(ctrl) == PAR_EXP_PROC) {
            if (!ctrl->tab_param.is_coordinator) {
                ctrl->execute_ret = par_exp_connectdb(ctrl);
                if (ctrl->execute_ret != GS_SUCCESS) {
                    par_exp_set_ctrl_stat(ctrl, PAR_EXP_IDLE);
                    continue;
                }
                conn = ctrl->conn_info.conn;
            } else {
                if (ctrl->tab_param.conn == NULL) {
                    ctrl->execute_ret = GS_ERROR;
                    exp_tmlog("parallel export table:%s failed, the connection is not established \n",
                        ctrl->tab_param.tab_name);
                    par_exp_set_ctrl_stat(ctrl, PAR_EXP_IDLE);
                    continue;
                }
                conn = ctrl->tab_param.conn;
            }

            file_insert_num = 0;
            wr_lob_flg = GS_FALSE;
            ret = par_exp_table_records(ctrl, &file_insert_num, &wr_lob_flg);
            if (ret != GS_SUCCESS) {
                exp_tmlog_error(conn);
                /* if 'table-not-exists', need to ignore it */
                ctrl->execute_ret = exp_ignore_error(conn);
            }
            (void)exp_flush_s(&ctrl->files_context.exp_txtbuf, ctrl->files_context.exp_dpfile);

            (void)gsql_reset_crypfile(ctrl->files_context.exp_dpfile, &g_export_opts.crypt_info);

            (void)par_exp_clean_empty_files(ctrl, file_insert_num, wr_lob_flg);
            if (file_insert_num != 0) {
                (void)par_exp_save_filenname(ctrl, &ctrl->exp_files);
            }

            par_exp_set_ctrl_stat(ctrl, PAR_EXP_IDLE);
        }

        cm_sleep(5);
    }
}

static status_t par_exp_start_thread(par_exp_thread_ctrl_t *thread_ctrl)
{
    return cm_create_thread(par_exp_proc, 0, thread_ctrl, &thread_ctrl->thread);
}

static status_t par_exp_start_all_thread(par_exp_mgr_t *mgr)
{
    uint32 i;
    int ret;
    cm_thread_lock(&mgr->lock_t);

    for (i = 0; i < mgr->options.parallel; i++) {
        mgr->thread_ctrls[i].stat = PAR_EXP_IDLE;
        ret = par_exp_start_thread(&mgr->thread_ctrls[i]);
        if (ret != GS_SUCCESS) {
            cm_thread_unlock(&mgr->lock_t);
            return ret;
        }
    }

    cm_thread_unlock(&mgr->lock_t);

    return GS_SUCCESS;
}

static status_t par_exp_get_partition_tab_params(export_options_t *exp_opts,
    exp_dn_info_t *node_info, par_exp_mgr_t *mgr, const char *user, const char *tab)
{
    char get_par_sql[GSQL_MAX_TEMP_SQL];
    gsc_stmt_t dn_stmt = mgr->par_proc_param.stmt;
    tab_par_param_t *tab_param = NULL;
    bool32 normal_tab = GS_FALSE;
    int32 ret_code = GS_SUCCESS;
    void *data = NULL;
    uint32 i, size, is_null, rows;
    for (i = 0; i < exp_opts->exp_tables.partition_list.count; i++) {
        const char *partition_name = (char *)cm_list_get(&exp_opts->exp_tables.partition_list, i);
        PRTS_RETURN_IFERR(sprintf_s(get_par_sql, GSQL_MAX_TEMP_SQL,
            "SELECT * from table(get_tab_parallel('\"%s\".\"%s\"', ?, ?))", user, tab));
        GS_RETURN_IFERR(gsc_prepare(dn_stmt, (const char *)get_par_sql));
        GS_RETURN_IFERR(gsc_bind_by_pos(dn_stmt, 0, GSC_TYPE_INTEGER,
            &mgr->options.parallel, sizeof(uint32), NULL));
        GS_RETURN_IFERR(gsc_bind_by_pos(dn_stmt, 1, GSC_TYPE_STRING,
            partition_name, (int)strlen(partition_name), NULL));
        ret_code = gsc_execute(dn_stmt);
        if (ret_code != GS_SUCCESS) {
            const char *message = "";
            int exp_partion_err_code = 0;
            gsc_get_error(mgr->par_proc_param.conn, &exp_partion_err_code, &message);
            if (exp_partion_err_code == ERR_PART_HAS_NO_DATA) {
                exp_tmlog("The partition %s of table %s has no data in dn(group_id=%u). \n",
                     partition_name, mgr->par_proc_param.tab_name, node_info->dn_group_id);
                continue;
            } else {
                exp_tmlog("CT-%05d, %s\n", exp_partion_err_code, message);
                return ret_code;
            }
        }

        do {
            GS_RETURN_IFERR(gsc_fetch(dn_stmt, &rows));
            if (rows == 0) {
                break;
            }

            normal_tab = GS_TRUE;
            GS_RETURN_IFERR(cm_list_new(&mgr->tab_par_params, (void **)&tab_param));

            GS_RETURN_IFERR(gsc_get_column_by_id(dn_stmt, 0, (void **)&data, &size, &is_null));
            tab_param->part_no = *(uint32 *)data;
            GS_RETURN_IFERR(gsc_get_column_by_id(dn_stmt, 1, (void **)&data, &size, &is_null));
            tab_param->l_page = *(uint64 *)data;
            GS_RETURN_IFERR(gsc_get_column_by_id(dn_stmt, 2, (void **)&data, &size, &is_null));
            tab_param->r_page = *(uint64 *)data;
            tab_param->normal_tab = normal_tab;
        } while (GS_TRUE);
    }

    return GS_SUCCESS;
}

static status_t par_exp_get_full_tab_params(export_options_t *exp_opts,
    exp_dn_info_t *node_info, par_exp_mgr_t *mgr, const char *user, const char *tab)
{
    char get_par_sql[GSQL_MAX_TEMP_SQL];
    tab_par_param_t *tab_param = NULL;
    void *data = NULL;
    uint32 size, is_null, rows;
    bool32 normal_tab = GS_FALSE;
    gsc_stmt_t dn_stmt = mgr->par_proc_param.stmt;
    PRTS_RETURN_IFERR(sprintf_s(get_par_sql, GSQL_MAX_TEMP_SQL,
        "SELECT * from table(get_tab_parallel('\"%s\".\"%s\"', ?))", user, tab));
    GS_RETURN_IFERR(gsc_prepare(dn_stmt, (const char *)get_par_sql));
    GS_RETURN_IFERR(gsc_bind_by_pos(dn_stmt, 0, GSC_TYPE_INTEGER, &mgr->options.parallel, sizeof(uint32), NULL));
    GS_RETURN_IFERR(gsc_execute(dn_stmt));
    
    do {
        GS_RETURN_IFERR(gsc_fetch(dn_stmt, &rows));
        if (rows == 0) {
            break;
        }

        normal_tab = GS_TRUE;
        GS_RETURN_IFERR(cm_list_new(&mgr->tab_par_params, (void **)&tab_param));

        GS_RETURN_IFERR(gsc_get_column_by_id(dn_stmt, 0, (void **)&data, &size, &is_null));
        tab_param->part_no = *(uint32 *)data;
        GS_RETURN_IFERR(gsc_get_column_by_id(dn_stmt, 1, (void **)&data, &size, &is_null));
        tab_param->l_page = *(uint64 *)data;
        GS_RETURN_IFERR(gsc_get_column_by_id(dn_stmt, 2, (void **)&data, &size, &is_null));
        tab_param->r_page = *(uint64 *)data;
        tab_param->normal_tab = normal_tab;
    } while (GS_TRUE);

    if (normal_tab == GS_FALSE) {
        /* Temporary tables, views */
        GS_RETURN_IFERR(cm_list_new(&mgr->tab_par_params, (void **)&tab_param));
        tab_param->part_no = GS_INVALID_ID32;
        tab_param->l_page = GS_INVALID_ID64;
        tab_param->r_page = GS_INVALID_ID64;
        tab_param->normal_tab = normal_tab;
    }
    return GS_SUCCESS;
}

static status_t par_exp_get_tab_params(export_options_t *exp_opts, exp_dn_info_t *node_info, par_exp_mgr_t *mgr, const char *user, const char *tab)
{
    MEMS_RETURN_IFERR(memcpy_s(mgr->par_proc_param.tab_name, sizeof(mgr->par_proc_param.tab_name), tab, strlen(tab)));
    MEMS_RETURN_IFERR(memcpy_s(mgr->par_proc_param.schema, sizeof(mgr->par_proc_param.schema), user, strlen(user)));
    mgr->par_proc_param.tab_name[strlen(tab)] = '\0';
    mgr->par_proc_param.schema[strlen(user)] = '\0';

    // 1.Get a single table degree of parallelism
    mgr->tab_par_param_offset = 0;
    cm_reset_list(&mgr->tab_par_params);
    if (exp_opts->exp_tables.table_exp_type == EXP_TABLE_PARTITION) {
        GS_RETURN_IFERR(par_exp_get_partition_tab_params(exp_opts, node_info, mgr, user, tab));
        if (mgr->tab_par_params.count == 0) {
            return GS_SUCCESS;
        }
    } else if (exp_opts->exp_tables.table_exp_type == EXP_TABLE_FULL) {
        GS_RETURN_IFERR(par_exp_get_full_tab_params(exp_opts, node_info, mgr, user, tab));
    }

    uint32 i;
    // 2.Distributing export tasks
    for (i = 0; i < mgr->options.parallel; i++) {
        if (mgr->tab_par_param_offset >= mgr->tab_par_params.count) {
            break;
        }
        if (mgr->par_proc_param.is_coordinator) {
            // Distributing every DN sub conn
            mgr->par_proc_param.conn = node_info->dn_par_conn.conn[i];
            mgr->par_proc_param.stmt = node_info->dn_par_conn.stmt[i];
        }
        mgr->par_proc_param.scan_param = *(tab_par_param_t *)cm_list_get(&mgr->tab_par_params,
                                                                         mgr->tab_par_param_offset);
        mgr->tab_par_param_offset++;
        GS_RETURN_IFERR(par_exp_dispatch_s(&mgr->thread_ctrls[i], &mgr->par_proc_param, mgr->bin_rec_total_add,
                                           &mgr->exp_cols));
    }
    return GS_SUCCESS;
}

static status_t par_exp_data_file_name(par_exp_mgr_t *mgr, exp_cache_t *table_cache)
{
    uint32 thread_no, filename_pos;
    char *file_name = NULL;
    char* subfile = NULL;

    if (g_export_opts.filetype == FT_BIN) {
        GS_RETURN_IFERR(exp_start_cache_unit(table_cache, EXP_CACHE_SUB_FILE_NAME));
        // print the number of all rows of the table
        for (thread_no = 0; thread_no < mgr->options.parallel; thread_no++) {
            for (filename_pos = 0; filename_pos < mgr->thread_ctrls[thread_no].exp_files.count; filename_pos++) {
                file_name = (char *)cm_list_get(&mgr->thread_ctrls[thread_no].exp_files, filename_pos);
                GS_RETURN_IFERR(alloc_column_subfile_info(table_cache, &subfile));
                // data file name
                MEMS_RETURN_IFERR(strncpy_s(subfile, EXP_MAX_SUBFILE_NAME_LEN, file_name, strlen(file_name)));
            }
            cm_destroy_list(&mgr->thread_ctrls[thread_no].exp_files);
        }
        exp_log(EXP_INDENT2 "data exporting success! %llu rows are dumped.\n", *mgr->bin_rec_total_add);
    } else {
        GS_RETURN_IFERR(exp_write_str_s("\n", &g_exp_txtbuf, g_exp_dpfile));
        for (thread_no = 0; thread_no < mgr->options.parallel; thread_no++) {
            for (filename_pos = 0; filename_pos < mgr->thread_ctrls[thread_no].exp_files.count; filename_pos++) {
                GS_RETURN_IFERR(exp_write_str_s("@@ ", &g_exp_txtbuf, g_exp_dpfile));
                GS_RETURN_IFERR(exp_write_str_s(GSQL_SEC_FILE_NAME, &g_exp_txtbuf, g_exp_dpfile));
                GS_RETURN_IFERR(exp_write_str_s("/", &g_exp_txtbuf, g_exp_dpfile));
                GS_RETURN_IFERR(exp_write_str_s((char *)cm_list_get(&mgr->thread_ctrls[thread_no].exp_files,
                    filename_pos), &g_exp_txtbuf, g_exp_dpfile));
                GS_RETURN_IFERR(exp_write_str_s("\n", &g_exp_txtbuf, g_exp_dpfile));
            }
            cm_destroy_list(&mgr->thread_ctrls[thread_no].exp_files);
        }
        GS_RETURN_IFERR(exp_write_str_s("\n", &g_exp_txtbuf, g_exp_dpfile));
    }
    return GS_SUCCESS;
}

static status_t exp_prepare_column_info(gsc_stmt_t *stmt)
{
    char cmd_buf[GSQL_MAX_TEMP_SQL + 1];

    PRTS_RETURN_IFERR(sprintf_s(cmd_buf, GSQL_MAX_TEMP_SQL,
        "SELECT COLUMN_NAME, DATA_TYPE, DATA_LENGTH, DATA_PRECISION, DATA_SCALE, "
        "       NULLABLE, DATA_DEFAULT, CHAR_USED %s "
        "FROM %s "
        "WHERE OWNER = UPPER(:O) AND TABLE_NAME = :T ORDER BY COLUMN_ID",
        (gsc_get_call_version(CONN) >= CS_VERSION_24) ? ", IS_JSONB" : " ",
        exp_tabname(g_export_opts.consistent, EXP_TABAGENT_DB_TAB_COLS)));

    GS_RETURN_IFERR(gsc_alloc_stmt(CONN, stmt));
    GS_RETURN_IFERR(gsc_prepare(*stmt, (const char *)cmd_buf));

    return GS_SUCCESS;
}

static status_t exp_prepare_table_func_indexes(gsc_stmt_t *stmt)
{
    char cmd_buf[GSQL_MAX_TEMP_SQL + 1];

    PRTS_RETURN_IFERR(sprintf_s(cmd_buf, GSQL_MAX_TEMP_SQL,
        "SELECT IF(ID < 60000, '\"' || COLUMN_NAME || '\"', DEFAULT_TEXT) "
        "FROM %s "
        "WHERE INDEX_OWNER = UPPER(:OWNER) AND TABLE_NAME = :TABLE_NAME AND INDEX_NAME = :INDEX_NAME "
        "ORDER BY COLUMN_POSITION", exp_tabname(g_export_opts.consistent, EXP_TABAGENT_DB_IND_COLUMNS)));

    GS_RETURN_IFERR(gsc_alloc_stmt(CONN, stmt));
    GS_RETURN_IFERR(gsc_prepare(*stmt, (const char *)cmd_buf));

    return GS_SUCCESS;
}

static status_t exp_prepare_table_has_intervalpart(gsc_stmt_t *stmt)
{
    char cmd_buf[GSQL_MAX_TEMP_SQL + 1];

    PRTS_RETURN_IFERR(sprintf_s(cmd_buf, GSQL_MAX_TEMP_SQL,
        "SELECT COUNT(1) "
        "FROM %s "
        "WHERE TABLE_OWNER = UPPER(:OWNER) AND TABLE_NAME = :TABLE_NAME AND INTERVAL = 'Y'",
        exp_tabname(g_export_opts.consistent, EXP_TABAGENT_DB_TAB_PARTITIONS)));

    GS_RETURN_IFERR(gsc_alloc_stmt(CONN, stmt));
    GS_RETURN_IFERR(gsc_prepare(*stmt, (const char *)cmd_buf));

    return GS_SUCCESS;
}

static status_t exp_prepare_index_partitioning(gsc_stmt_t *stmt)
{
    char cmd_buf[GSQL_MAX_TEMP_SQL + 1];

    PRTS_RETURN_IFERR(sprintf_s(cmd_buf, GSQL_MAX_TEMP_SQL,
        "SELECT X.PARTITION_NAME, X.TABLESPACE_NAME, X.INI_TRANS, X.PCT_FREE "
        "FROM %s X "
        "WHERE X.INDEX_NAME = :INDEX_NAME "
        "AND X.INDEX_OWNER = :OWNER "
        "ORDER BY X.PARTITION_POSITION ",
        exp_tabname(g_export_opts.consistent, EXP_TABAGENT_DB_IND_PARTITIONS)));

    GS_RETURN_IFERR(gsc_alloc_stmt(CONN, stmt));
    GS_RETURN_IFERR(gsc_prepare(*stmt, (const char *)cmd_buf));

    return GS_SUCCESS;
}

static status_t exp_prepare_index_subpartition(gsc_stmt_t *stmt)
{
    char cmd_buf[GSQL_MAX_TEMP_SQL + 1];

    PRTS_RETURN_IFERR(sprintf_s(cmd_buf, GSQL_MAX_TEMP_SQL,
        "SELECT PARTITION_NAME, TABLESPACE_NAME "
        "FROM %s "
        "WHERE PARENTPART_NAME = :PARTITION_NAME "
        "AND INDEX_NAME = :INDEX_NAME "
        "AND INDEX_OWNER = :OWNER "
        "ORDER BY PARTITION_NAME ",
        exp_tabname(g_export_opts.consistent, EXP_TABAGENT_DB_IND_SUBPARTITIONS)));

    GS_RETURN_IFERR(gsc_alloc_stmt(CONN, stmt));
    GS_RETURN_IFERR(gsc_prepare(*stmt, (const char *)cmd_buf));

    return GS_SUCCESS;
}

static int exp_prepare_has_subpartition(gsc_stmt_t *stmt)
{
    char cmd_buf[GSQL_MAX_TEMP_SQL + 1] = { 0 };

    PRTS_RETURN_IFERR(sprintf_s(cmd_buf, GSQL_MAX_TEMP_SQL,
        "SELECT SUBPARTITION_TYPE "
        "FROM %s "
        "WHERE OWNER = UPPER(:OWNER) AND TABLE_NAME = :TABLE_NAME ",
        exp_tabname(g_export_opts.consistent, EXP_TABAGENT_DB_PART_TABLES)));

    GS_RETURN_IFERR(gsc_alloc_stmt(CONN, stmt));
    GS_RETURN_IFERR(gsc_prepare(*stmt, (const char *)cmd_buf));

    return GS_SUCCESS;
}

status_t exp_shd_decrypt_pwd_with_key(exp_shd_info_t *dn_info)
{
    char *local_key = dn_info->gts_param_info.shd_loc_key;
    char *factor_key = dn_info->gts_param_info.shd_fac_key;
    char *cipher_str = dn_info->gts_conn_info.passwd;

    char passwd_buf[EXP_MAX_PASSWD] = {0};
    uint32 passwd_len = GS_PASSWORD_BUFFER_SIZE;
    status_t ret = GS_SUCCESS;

    GS_RETURN_IFERR(gsql_init_home());
    if (gsql_get_local_server_kmc_ksf(GS_HOME) != GS_SUCCESS) {
        return GS_ERROR;
    }

    aes_and_kmc_t aes_kmc = {0};
    cm_kmc_set_aes_key(&aes_kmc, factor_key, local_key);
    cm_kmc_set_kmc(&aes_kmc, GS_KMC_SERVER_DOMAIN, KMC_ALGID_AES256_CBC);
    cm_kmc_set_buf(&aes_kmc, passwd_buf, passwd_len,
        dn_info->gts_conn_info.passwd, (uint32)strlen(cipher_str));

    // encrypt cipher
    if (cm_decrypt_passwd_with_key_by_kmc(&aes_kmc) != GS_SUCCESS) {
        GSQL_PRINTF(ZSERR_GSQL, "exp failed");
        ret = GS_ERROR;
    }

    if (cm_kmc_finalize() != GS_SUCCESS) {
        GSQL_PRINTF(ZSERR_GSQL, "exp failed");
        ret = GS_ERROR;
    }

    if (ret != GS_SUCCESS) {
        MEMS_EXP_RETURN_IFERR(memset_s(dn_info->gts_conn_info.passwd, EXP_MAX_PASSWD, 0, EXP_MAX_PASSWD));
        MEMS_EXP_RETURN_IFERR(memset_s(passwd_buf, EXP_MAX_PASSWD, 0, EXP_MAX_PASSWD));
        return ret;
    }

    passwd_len = aes_kmc.plain_len;
	
    MEMS_EXP_RETURN_IFERR(memset_s(dn_info->gts_conn_info.passwd, EXP_MAX_PASSWD, 0, EXP_MAX_PASSWD));

    MEMS_EXP_RETURN_IFERR(strncpy_s(dn_info->gts_conn_info.passwd, EXP_MAX_PASSWD, passwd_buf, passwd_len));

    MEMS_EXP_RETURN_IFERR(memset_s(passwd_buf, EXP_MAX_PASSWD, 0, EXP_MAX_PASSWD));

    return GS_SUCCESS;
}

status_t exp_gts_get_user_pwd(exp_shd_info_t *dn_info)
{
    uint32_t tmp_len;

    // get username
    GS_RETURN_IFERR(gsc_column_as_string(STMT, 4, g_str_buf, GS_MAX_PACKET_SIZE));
    tmp_len = (uint32)strlen(g_str_buf);
    MEMS_EXP_RETURN_IFERR(strncpy_s(dn_info->gts_conn_info.username, EXP_MAX_USERNAME, g_str_buf, tmp_len));

    // get pwd
    GS_RETURN_IFERR(gsc_column_as_string(STMT, 5, g_str_buf, GS_MAX_PACKET_SIZE));
    tmp_len = (uint32)strlen(g_str_buf);
    MEMS_EXP_RETURN_IFERR(strncpy_s(dn_info->gts_conn_info.passwd, EXP_MAX_PASSWD, g_str_buf, tmp_len));

    // decrypt pwd
    return exp_shd_decrypt_pwd_with_key(dn_info);
}

status_t par_exp_create_dn_connectdb(gsql_conn_info_t *dn_conn_info, bool32 is_get_pwd)
{
    uint16 charset_id;
    int32 execute_ret;
    bool32 interactive_clt = GS_FALSE;
    bool32 flag_with_ts = GS_TRUE;
    uint32 new_num_width = (uint32)GS_MAX_DEC_OUTPUT_ALL_PREC;
    /* Re-establishing connections is not supported */
    if (dn_conn_info->conn == NULL) {
        execute_ret = gsql_alloc_conn(&dn_conn_info->conn);
        if (execute_ret != GS_SUCCESS) {
            exp_tmlog("Alloc connect failed\n");
            gsql_print_error(NULL);
            return execute_ret;
        }

        /* set session interactive check disable */
        (void)gsc_set_conn_attr(dn_conn_info->conn, GSC_ATTR_INTERACTIVE_MODE, (void *)&interactive_clt, 0);
        (void)gsc_set_conn_attr(dn_conn_info->conn, GSC_ATTR_FLAG_WITH_TS, (void *)&flag_with_ts, 0);
        (void)gsc_set_conn_attr(dn_conn_info->conn, GSC_ATTR_NUM_WIDTH, (void *)&new_num_width, sizeof(uint32));
        if (is_get_pwd) {
            // pwd , clean after conn_to_server
            GS_RETURN_IFERR(gsql_get_saved_pswd(dn_conn_info->passwd, EXP_MAX_PASSWD));
        }

        execute_ret = gsql_conn_to_server(dn_conn_info, GS_FALSE, GS_TRUE);
        if (execute_ret != GS_SUCCESS) {
            exp_tmlog("Connect to server failed\n");
            return execute_ret;
        }
        gsc_get_charset(STMT, &charset_id);
        GS_RETURN_IFERR(gsc_set_charset(dn_conn_info->stmt, charset_id));
    }

    return GS_SUCCESS;
}

status_t exp_clean_pwd_info(gsql_conn_info_t *dn_conn_info)
{
    // clear user and pwd
    MEMS_EXP_RETURN_IFERR(memset_s(dn_conn_info->username, EXP_MAX_USERNAME, 0, EXP_MAX_USERNAME));
    MEMS_EXP_RETURN_IFERR(memset_s(dn_conn_info->passwd, EXP_MAX_PASSWD, 0, EXP_MAX_PASSWD));

    return GS_SUCCESS;
}

static status_t exp_init_conn_info(export_options_t *opt)
{
    exp_dn_info_t *node_info = NULL;
    cm_create_list(&opt->dn_info.dn_info_list, sizeof(exp_dn_info_t));
    char login_username[GS_NAME_BUFFER_SIZE + GS_STR_RESERVED_LEN] = { 0 };
    gsql_get_saved_user(login_username, EXP_MAX_USERNAME);

    {
        // using local connected info
        GS_RETURN_IFERR(cm_list_new(&opt->dn_info.dn_info_list, (void **)&node_info));
        node_info->dn_scn = GS_INVALID_ID64;
        node_info->dn_conn_info.conn = CONN;
        node_info->dn_conn_info.stmt = STMT;
    }
    return GS_SUCCESS;
}

static status_t par_exp_table_dn_records(export_options_t *exp_opts, exp_tab_info_t* tab_info, par_exp_mgr_t *par_mgr,
    exp_cache_t* table_cache)
{
    int32 ret = GS_SUCCESS;
    exp_dn_info_t *node_info = NULL;

    exp_tab_dist_info_t tab_dist_info;
    MEMS_RETURN_IFERR(memset_s(&tab_dist_info, sizeof(exp_tab_dist_info_t), 0, sizeof(exp_tab_dist_info_t)));
    par_mgr->par_proc_param.is_coordinator = GS_FALSE;
    
    for (uint32 num = 0; num < exp_opts->dn_info.dn_info_list.count; num++) {
        node_info = (exp_dn_info_t *)cm_list_get(&exp_opts->dn_info.dn_info_list, num);

        // connect db by dn
        par_mgr->par_proc_param.conn = node_info->dn_conn_info.conn;
        par_mgr->par_proc_param.stmt = node_info->dn_conn_info.stmt;
 
        par_mgr->par_proc_param.scn = g_exp_scn;

        if (!TABLE_IS_TEMP(tab_info->table_type)) {
            // 2.Get Concurrency Export parameters
            ret = par_exp_get_tab_params(exp_opts, node_info, par_mgr, tab_info->user, tab_info->table);
            if (ret != GS_SUCCESS) {
                exp_tmlog("Failed to get table:%s parallel export parameter\n", tab_info->table);
                EXP_BREAK_IFERR(ret);
                continue;
            }
        }

        // 3.Wait for all threads to export table data
        while (par_exp_check_thread_stat(par_mgr, &node_info->dn_par_conn, &ret) == GS_FALSE) {
            if (ret != GS_SUCCESS) {
                break;
            }
            cm_sleep(5);
        }

        if (ret != GS_SUCCESS) {
            if (g_export_opts.force) {
                // do ignore, when error occurs exporting tables
                exp_tmlog("Error occur when exporting table %s,ignore it ...\n\n", tab_info->table);
                continue;
            }
            EXP_THROW_ERROR(ERR_CREATE_THREAD, "table export thread throw error.");
            ret = GS_ERROR;
            break;
        }

        // 4.Collects data file names for all threads that are exported in parallel
        GS_RETURN_IFERR(par_exp_data_file_name(par_mgr, table_cache));
    }

    return ret;
}

static status_t exp_single_table_parallel(exp_tabs_ctx_t *ctx, par_exp_mgr_t *par_mgr, const char *user,
    const char *table, exp_cache_t *table_cache)
{
    exp_tab_info_t tab_info;

    exp_tmlog("exporting table %s.%s ...\n", ctx->user, table);
    GS_RETURN_IFERR(exp_init_tab_info(ctx->user, table, ctx, &tab_info));

    // 1.Use global connect to export metadata
    if (ctx->exp_opts->content & CT_EXP_META) {
        GS_RETURN_IFERR(exp_tab_meta(ctx->exp_opts, &tab_info, table_cache));
        GS_RETURN_IFERR(table_cache_write_txt_tab_meta(table_cache));
    }

    GS_RETURN_IFERR(exp_start_cache_unit(table_cache, EXP_CACHE_TABLE_NAME));
    GS_RETURN_IFERR(exp_cache_append_str(table_cache,
        exp_remap_table_name(&ctx->exp_opts->table_maps, table, NULL, 0))); // table name

    par_mgr->bin_rec_total_add = &table_cache->record_cnt;  // table record total address

    if (par_mgr->exp_cols.init_cols == GS_TRUE) {
        exp_reset_exporter(&par_mgr->exp_cols.exporter);
    }
    par_mgr->exp_cols.init_cols = GS_FALSE;

    // 2.3.4 steps need to deal together
    GS_RETURN_IFERR(par_exp_table_dn_records(ctx->exp_opts, &tab_info, par_mgr, table_cache));

    // 5.Use global connect to export table index metadata
    if (ctx->exp_opts->content & CT_EXP_META) {
        GS_RETURN_IFERR(exp_start_cache_unit(table_cache, EXP_CACHE_TABLE_INDEX));
        GS_RETURN_IFERR(exp_table_auto_increment(ctx->user, table, table_cache));
        GS_RETURN_IFERR(exp_tab_indx_meta(ctx, table, table_cache));
        GS_RETURN_IFERR(table_cache_write_txt_tab_index_meta(table_cache));
    }

    return GS_SUCCESS;
}

static status_t exp_single_table_serial(exp_tabs_ctx_t *ctx, const char *user, const char *table, exp_cache_t *table_cache)
{
    exporter_t exporter;
    exp_tab_info_t tab_info;

    if (!g_export_opts.show_create_table) {
        exp_tmlog("exporting table %s.%s ...\n", user, table);
    }
    GS_RETURN_IFERR(exp_init_tab_info(user, table, ctx, &tab_info));

    exp_init_exporter(&exporter);

    /* content must contains "tab_meta + table_name + sub_file + field_info + record_num + index_len" */
    if (ctx->exp_opts->content & CT_EXP_META) {
        GS_RETURN_IFERR(exp_tab_meta(ctx->exp_opts, &tab_info, table_cache));
        GS_RETURN_IFERR(table_cache_write_txt_tab_meta(table_cache));
    }

    // table records
    if ((ctx->exp_opts->content & CT_EXP_DATA)) {
        // the data of temporary table is not necessary to export
        if (TABLE_IS_TEMP(tab_info.table_type)) {
            exp_log(EXP_INDENT "skipping to export the data of temporary table");
            GS_RETURN_IFERR(exp_start_cache_unit(table_cache, EXP_CACHE_TABLE_NAME));
            GS_RETURN_IFERR(exp_cache_append_str(table_cache,
                exp_remap_table_name(&ctx->exp_opts->table_maps, table, NULL, 0))); // table name
            table_cache->record_cnt = 0;
        } else {
            // every dn must have a subfile
            GS_RETURN_IFERR(exp_table_records(ctx->exp_opts, user, table, &exporter, table_cache));
        }
    }
    exp_destory_exporter(&exporter);
    if (!g_export_opts.show_create_table) {
        exp_log("\n");
    }

    // index_meta
    if (ctx->exp_opts->content & CT_EXP_META) {
        GS_RETURN_IFERR(exp_start_cache_unit(table_cache, EXP_CACHE_TABLE_INDEX));
        GS_RETURN_IFERR(exp_table_auto_increment(user, table, table_cache));
        GS_RETURN_IFERR(exp_tab_indx_meta(ctx, table, table_cache));
        GS_RETURN_IFERR(table_cache_write_txt_tab_index_meta(table_cache));
    }

    return GS_SUCCESS;
}

static int exp_tables_parallel(exp_tabs_ctx_t *ctx, exp_cache_t* table_cache)
{
    int32 ret = GS_SUCCESS;
    par_exp_mgr_t par_mgr;
    const char *table = NULL;
    uint64 local_scn;
    
    // init parallel manager
    cm_create_list(&par_mgr.tab_par_params, sizeof(tab_par_param_t));
    par_exp_init_mgr(&par_mgr, ctx->exp_opts);
    (void)par_exp_start_all_thread(&par_mgr);

    // set table cache object to param
    par_mgr.par_proc_param.table_cache = table_cache;

    for (uint32 i = 0; i < ctx->tables->count; i++) {
        // if cancel, stop export
        EXP_RETRUN_IF_CANCEL;
        table = (char *)cm_list_get(ctx->tables, i);

        // reset table cache info before exporting
        reset_exp_cache(table_cache);
        local_scn = g_exp_scn; // save global scn
        ret = exp_single_table_parallel(ctx, &par_mgr, ctx->user, table, table_cache);
        g_exp_scn = local_scn; // restore global scn
        if (ret != GS_SUCCESS) {
            EXP_BREAK_IFERR(ret);
        } else {
            // export single table success , then try to flush to DUMP file.
            ret = table_cache_write_file(table_cache);
            GS_BREAK_IF_ERROR(ret);
            inc_total(ctx->tab_cnt);
        }
    }

    par_exp_stop_all_thread(&par_mgr);
    exp_destory_exporter(&par_mgr.exp_cols.exporter);

    return ret;
}

static int exp_tables_serial(exp_tabs_ctx_t *ctx, exp_cache_t* table_cache)
{
    status_t ret = GS_SUCCESS;
    char *one_table = NULL;

    for (uint32 i = 0; i < ctx->tables->count; i++) {
        // if cancel, stop export
        EXP_RETRUN_IF_CANCEL;

        one_table = (char *)cm_list_get(ctx->tables, i);
        if (ctx->exp_opts->exp_type == EXP_TABLE &&
            ctx->exp_opts->tbs_list.count > 0 &&
            GS_SUCCESS != exp_tablespace_filter(ctx->exp_opts, ctx->user, one_table)) {
            continue;
        }
        /* reset before export table content. */
        reset_exp_cache(table_cache);
        ret = exp_single_table_serial(ctx, ctx->user, one_table, table_cache);
        if (ret != GS_SUCCESS) {
            EXP_BREAK_IFERR(ret);
        } else {
            // export single table success , then try to flush to DUMP file.
            ret = table_cache_write_file(table_cache);
            GS_BREAK_IF_ERROR(ret);
            inc_total(ctx->tab_cnt);
        }

        if (g_export_opts.filetype == FT_TXT) {
            GS_BREAK_IF_ERROR(exp_write_str_s("\n", &g_exp_txtbuf, g_exp_dpfile));
        }
    }
    return ret;
}

static status_t reverse_index_available(gsc_stmt_t stmt, bool32 *reverse_index_aval)
{
    uint32 rows;
    char *get_par_sql = (char *)malloc(GSQL_MAX_TEMP_SQL);

    if (get_par_sql == NULL) {
        GSQL_PRINTF(ZSERR_EXPORT, "malloc databuf failed!");
        return GS_ERROR;
    }

    int iret_sprintf = sprintf_s(get_par_sql, GSQL_MAX_TEMP_SQL,
        "SELECT COLUMN_NAME FROM DB_VIEW_COLUMNS WHERE VIEW_NAME='DB_INDEXES' AND COLUMN_NAME='IS_REVERSED'");
    if (iret_sprintf == -1) {
        CM_FREE_PTR(get_par_sql);
        EXP_THROW_ERROR(ERR_SYSTEM_CALL, iret_sprintf);
        return GS_ERROR;
    }

    if (gsc_prepare(stmt, get_par_sql) != GS_SUCCESS) {
        CM_FREE_PTR(get_par_sql);
        return GS_ERROR;
    }

    if (gsc_execute(stmt) != GS_SUCCESS) {
        CM_FREE_PTR(get_par_sql);
        return GS_ERROR;
    }

    if (gsc_fetch(stmt, &rows) != GS_SUCCESS) {
        CM_FREE_PTR(get_par_sql);
        return GS_ERROR;
    }

    *reverse_index_aval = (rows != 0);

    CM_FREE_PTR(get_par_sql);
    return GS_SUCCESS;
}

static status_t exp_init_tabs_ctx(const char *user, list_t *table_list, export_options_t *exp_opts, exp_tabs_ctx_t *ctx)
{
    ctx->user = user;
    ctx->tables = table_list;
    // Total number of binary file tables
    ctx->tab_cnt = (uint32 *)exp_bin_write_int32(&g_export_opts.master_bin_mgr, 0);
    ctx->exp_opts = exp_opts;
    ctx->query_tab_column = NULL;
    ctx->query_func_indexes = NULL;
    ctx->query_tab_has_intervalpart = NULL;
    ctx->query_index_partitioning = NULL;
    ctx->query_index_subpartition = NULL;
    ctx->query_has_subpartition = NULL;
    GS_RETURN_IFERR(reverse_index_available(STMT, &ctx->reverse_index_available));
    GS_RETURN_IFERR(exp_prepare_column_info(&ctx->query_tab_column));
    GS_RETURN_IFERR(exp_prepare_table_func_indexes(&ctx->query_func_indexes));
    GS_RETURN_IFERR(exp_prepare_table_has_intervalpart(&ctx->query_tab_has_intervalpart));
    if (exp_need_index_partition()) {
        GS_RETURN_IFERR(exp_prepare_index_partitioning(&ctx->query_index_partitioning));
        GS_RETURN_IFERR(exp_prepare_index_subpartition(&ctx->query_index_subpartition));
        GS_RETURN_IFERR(exp_prepare_has_subpartition(&ctx->query_has_subpartition));
    }
    return GS_SUCCESS;
}

static void exp_uninit_tabs_ctx(exp_tabs_ctx_t *ctx)
{
    gsc_free_stmt(ctx->query_tab_column);
    gsc_free_stmt(ctx->query_func_indexes);
    gsc_free_stmt(ctx->query_tab_has_intervalpart);
    if (exp_need_index_partition()) {
        gsc_free_stmt(ctx->query_index_partitioning);
        gsc_free_stmt(ctx->query_index_subpartition);
        gsc_free_stmt(ctx->query_has_subpartition);
    }
}

static status_t exp_table_scripts(export_options_t *exp_opts, const char *user, list_t *table_list)
{
    status_t ret;
    exp_tabs_ctx_t ctx;
    exp_cache_t table_cache;
    uint32 *fc_total = NULL;

    /*
        init 'table cache' for automatic table export cache
        table_cache is for table info cache when do export.
        if success : table_cache will be writed to disk
        if error   : table_cache will be all discarded
    */
    GS_RETURN_IFERR(init_exp_cache(&table_cache, EXP_MAX_UNIT_CNT_PER_TABLE + g_export_opts.dn_info.dn_info_list.count,
        EXP_CACHE_ALL_TABLE));

    // init context for all tables.
    if (exp_init_tabs_ctx(user, table_list, exp_opts, &ctx) != GS_SUCCESS) {
        exp_uninit_tabs_ctx(&ctx);
        return GS_ERROR;
    }

    // prompt
    if ((exp_opts->parallel > GS_MAX_PAR_EXP_VALUE) || (exp_opts->parallel == 1)) {
        exp_tmlog("Parallelism setting range is not between 2~%u, ignoring parallel execution parameters\n",
                  (uint32)GS_MAX_PAR_EXP_VALUE);
    }

    if ((exp_opts->content & CT_EXP_DATA) && (exp_opts->parallel > 1) &&
        (exp_opts->parallel <= GS_MAX_PAR_EXP_VALUE)) {
        ret = exp_tables_parallel(&ctx, &table_cache);
    } else {
        ret = exp_tables_serial(&ctx, &table_cache);
    }

    exp_uninit_tabs_ctx(&ctx);
    uninit_exp_cache(&table_cache);
    EXP_RETURN_IFERR(ret);

    /* export table's foreign constraints */
    (void)exp_bin_memory_mgr_begin(&g_export_opts.master_bin_mgr, g_export_opts.filetype);
    fc_total = (uint32 *)exp_bin_write_int32(&g_export_opts.master_bin_mgr, (uint32)0);  // cf total
    for (uint32 i = 0; i < table_list->count; i++) {
        exp_bin_reset_txtbuf();
        EXP_RETURN_IFERR(exp_table_foreign_constraints(user, (char *)cm_list_get(table_list, i)));
        if (g_exp_txtbuf.len) {
            (void)exp_bin_memory_mgr_sub_begin(&g_export_opts.master_bin_mgr, g_export_opts.filetype);
            (void)exp_bin_write_bytes(&g_export_opts.master_bin_mgr, g_exp_txtbuf.str, g_exp_txtbuf.len);
            (void)exp_bin_write_int32(&g_export_opts.master_bin_mgr, EXP_OBJECT_END_FLAG);
            exp_bin_memory_mgr_sub_end(&g_export_opts.master_bin_mgr, g_export_opts.filetype);
            inc_total(fc_total);
        }
    }
    exp_bin_memory_mgr_end(&g_export_opts.master_bin_mgr, g_export_opts.filetype);

    return GS_SUCCESS;
}

static inline int exp_user_tables(export_options_t *exp_opts, const char *user)
{
    int status;
    list_t user_tables;

    exp_create_objlist(&user_tables, GSQL_MAX_OBJECT_LEN);
    do {
        exp_tmlog("Reading table objects of %s\n", user);
        status = exp_get_user_tables(exp_opts, user, &user_tables);
        if (status != GS_SUCCESS) {
            break;
        }
        exp_tmlog("Exporting tables (scripts or data) of %s\n", user);

        status = exp_table_scripts(exp_opts, user, &user_tables);
    } while (GS_FALSE);
    cm_reset_list(&user_tables);
    return status;
}

static inline int exp_get_user_views(const char *user, list_t *user_views)
{
    char *ptr = NULL;
    uint32 rows;
    char cmd_buf[GSQL_MAX_TEMP_SQL + 1];
    exp_prepare_sql_param_t param;

    param.get_view_param.consistent = g_export_opts.consistent;

    GS_RETURN_IFERR(EXP_PREPARE_SQL(EXP_GET_USER_VIEW_LIST, cmd_buf, GSQL_MAX_TEMP_SQL, &param));

    GS_RETURN_IFERR(gsc_prepare(STMT, (const char *)cmd_buf));
    GS_RETURN_IFERR(gsc_bind_by_pos(STMT, 0, GSC_TYPE_STRING, user, (int32)strlen(user), NULL));
    GS_RETURN_IFERR(gsc_bind_by_pos(STMT, 1, GSC_TYPE_STRING, user, (int32)strlen(user), NULL));
    GS_RETURN_IFERR(gsc_bind_by_pos(STMT, 2, GSC_TYPE_STRING, user, (int32)strlen(user), NULL));

    GS_RETURN_IFERR(gsc_execute(STMT));

    do {
        GS_RETURN_IFERR(gsc_fetch(STMT, &rows));
        if (rows == 0) {
            return GS_SUCCESS;
        }
        GS_RETURN_IFERR(gsc_column_as_string(STMT, 0, g_str_buf, GS_MAX_PACKET_SIZE));
        if (cm_list_new(user_views, (pointer_t *)&ptr) != GS_SUCCESS) {
            return GS_ERROR;
        }
        MEMS_EXP_RETURN_IFERR(strncpy_s(ptr, GSQL_MAX_OBJECT_LEN, g_str_buf, GSQL_MAX_OBJECT_LEN - 1));
    } while (GS_TRUE);
}

static inline int exp_view_columns(const char *user, const char *view, exp_cache_t *view_cache)
{
    uint32 total_rows = 0;
    uint32 rows;
    bool32 is_first = GS_TRUE;
    char cmd_buf[GSQL_MAX_TEMP_SQL + 1];

    PRTS_RETURN_IFERR(sprintf_s(cmd_buf, GSQL_MAX_TEMP_SQL,
        "SELECT COLUMN_NAME "
        "FROM %s "
        "WHERE OWNER = UPPER(:o) AND VIEW_NAME = :v ORDER BY COLUMN_ID",
        exp_tabname(g_export_opts.consistent, EXP_TABAGENT_DB_VIEW_COLUMNS)));

    GS_RETURN_IFERR(gsc_prepare(STMT, (const char *)cmd_buf));

    GS_RETURN_IFERR(gsc_bind_by_pos(STMT, 0, GSC_TYPE_STRING, user, (int32)strlen(user), NULL));
    GS_RETURN_IFERR(gsc_bind_by_pos(STMT, 1, GSC_TYPE_STRING, view, (int32)strlen(view), NULL));

    GS_RETURN_IFERR(gsc_execute(STMT));

    GS_RETURN_IFERR(exp_cache_append_str(view_cache, "(\n"));
    do {
        GS_RETURN_IFERR(gsc_fetch(STMT, &rows));
        if (rows == 0) {
            break;
        }
        total_rows += rows;
        if (!is_first) {
            GS_RETURN_IFERR(exp_cache_append_str(view_cache, ",\n"));
        } else {
            is_first = GS_FALSE;
        }
        GS_RETURN_IFERR(exp_cache_append_str(view_cache, EXP_INDENT));
        GS_RETURN_IFERR(gsc_column_as_string(STMT, 0, g_str_buf, GS_MAX_PACKET_SIZE));
        GS_RETURN_IFERR(exp_cache_append_str_quote(view_cache, g_str_buf));
    } while (GS_TRUE);
    GS_RETURN_IFERR(exp_cache_append_str(view_cache, "\n)"));

    if (total_rows == 0) {
        EXP_THROW_ERROR(ERR_TABLE_OR_VIEW_NOT_EXIST, user, view);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static inline int exp_write_schema_lob(gsc_stmt_t stmt, int col_id, char *buf, uint32 buf_size, exp_cache_t *exp_cache)
{
    uint32 offset = 0;
    uint32 nchars = 0;
    uint32 nbytes;
    bool32 eof = GS_FALSE;
    text_t src_text = { .str = buf, .len = 0 };
    do {
        GS_RETURN_IFERR(gsc_read_clob_by_id(stmt, col_id, offset,
                                            (void *)buf, buf_size, &nchars, &nbytes, &eof));

        src_text.len = nbytes;
        CM_NULL_TERM(&src_text);
        if (exp_cache == NULL) {
            GS_RETURN_IFERR(exp_write_schema_com(buf, &g_exp_txtbuf, g_exp_dpfile));
        } else {
            GS_RETURN_IFERR(exp_cache_append_str(exp_cache, buf));
        }
        offset += nbytes;
    } while (!eof);

    cm_rtrim_text(&src_text);
    if (!CM_IS_EMPTY(&src_text) && CM_TEXT_END(&src_text) != '/') {
        if (exp_cache == NULL) {
            GS_RETURN_IFERR(exp_write_schema_com("\n/\n", &g_exp_txtbuf, g_exp_dpfile));
        } else {
            GS_RETURN_IFERR(exp_cache_append_str(exp_cache, "\n/\n"));
        }
    }

    return GS_SUCCESS;
}

static inline int exp_view_source(const char *user, const char *view, exp_cache_t *exp_cache)
{
    uint32 rows;
    char cmd_buf[GSQL_MAX_TEMP_SQL + 1];

    PRTS_RETURN_IFERR(sprintf_s(cmd_buf, GSQL_MAX_TEMP_SQL,
        "SELECT TEXT "
        "FROM %s "
        "WHERE OWNER = UPPER(:o) AND VIEW_NAME = :v",
        exp_tabname(g_export_opts.consistent, EXP_TABAGENT_DB_VIEWS)));

    GS_RETURN_IFERR(gsc_prepare(STMT, (const char *)cmd_buf));

    GS_RETURN_IFERR(gsc_bind_by_pos(STMT, 0, GSC_TYPE_STRING, user, (int32)strlen(user), NULL));
    GS_RETURN_IFERR(gsc_bind_by_pos(STMT, 1, GSC_TYPE_STRING, view, (int32)strlen(view), NULL));
    GS_RETURN_IFERR(gsc_execute(STMT));

    GS_RETURN_IFERR(gsc_fetch(STMT, &rows));
    if (rows == 0) {
        EXP_THROW_ERROR(ERR_TABLE_OR_VIEW_NOT_EXIST, user, view);
        return GS_ERROR;
    }

    return exp_write_schema_lob(STMT, 0, g_str_buf, CLT_LOB_BUFFER_SIZE, exp_cache);
}

static inline int exp_single_view(export_options_t *exp_opts, const char *user, const char *view, exp_cache_t *view_cache)
{
    exp_log(EXP_INDENT "exporting view %s.%s\n", user, view);
    // record view name
    GS_RETURN_IFERR(exp_start_cache_unit(view_cache, EXP_CACHE_VIEW_NAME));
    exp_cache_append_str_quote(view_cache, view);
    // record view columns
    GS_RETURN_IFERR(exp_start_cache_unit(view_cache, EXP_CACHE_VIEW_COLUMNS));
    GS_RETURN_IFERR(exp_view_columns(user, view, view_cache));
    // record view source
    GS_RETURN_IFERR(exp_start_cache_unit(view_cache, EXP_CACHE_VIEW_SRC));
    return exp_view_source(user, view, view_cache);
}

static inline int exp_view_scripts(export_options_t *exporter, const char *user, list_t *user_views)
{
    exp_cache_t view_cache;
    status_t ret = GS_SUCCESS;
    
    GS_RETURN_IFERR(init_exp_cache(&view_cache, EXP_MAX_UNIT_CNT_PER_VIEW, EXP_CACHE_VIEW));

    do {
        uint32 *view_total = (uint32 *)exp_bin_write_int32(&g_export_opts.master_bin_mgr, 0);  // set views total
        for (uint32 i = 0; i < user_views->count; i++) {
            reset_exp_cache(&view_cache);
            ret = exp_single_view(exporter, user, (char *)cm_list_get(user_views, i), &view_cache);
            if (ret == GS_SUCCESS) {
                ret = view_cache_write_file(&view_cache);
            }

            if (ret == GS_SUCCESS) {
                // inc view count.
                inc_total(view_total);
            }

            EXP_BREAK_IFERR(ret);
        }
    } while (0);

    uninit_exp_cache(&view_cache);
    return ret;
}

static inline int exp_user_views(export_options_t *exp_opts, const char *user)
{
    int status;
    list_t user_views;

    exp_create_objlist(&user_views, GSQL_MAX_OBJECT_LEN);
    do {
        status = exp_get_user_views(user, &user_views);
        if (status != GS_SUCCESS) {
            break;
        }
        status = exp_view_scripts(exp_opts, user, &user_views);
        if (status != GS_SUCCESS) {
            break;
        }
    } while (GS_FALSE);
    cm_reset_list(&user_views);
    return status;
}

static status_t exp_user_synonyms(export_options_t *exp_opts, const char *user)
{
    uint32 *synonyms_total = (uint32 *)exp_bin_write_int32(&exp_opts->master_bin_mgr, 0);  // set synonyms total
    uint32 rows;
    char cmd_buf[GSQL_MAX_TEMP_SQL + 1];
    exp_prepare_sql_param_t param;

    param.get_synonym_param.user_name = user;

    GS_RETURN_IFERR(EXP_PREPARE_SQL(EXP_GET_USER_SYNONYM_LIST, cmd_buf, GSQL_MAX_TEMP_SQL, &param));

    GS_RETURN_IFERR(gsc_prepare(STMT, (const char *)cmd_buf));
    GS_RETURN_IFERR(gsc_execute(STMT));

    do {
        GS_RETURN_IFERR(gsc_fetch(STMT, &rows));
        if (rows == 0) {
            return GS_SUCCESS;
        }
        GS_RETURN_IFERR(gsc_column_as_string(STMT, 0, g_str_buf, GS_MAX_PACKET_SIZE));
        (void)exp_bin_memory_mgr_sub_begin(&exp_opts->master_bin_mgr, g_export_opts.filetype);
        GS_RETURN_IFERR(exp_write_schema_com(g_str_buf, &g_exp_txtbuf, g_exp_dpfile));
        GS_RETURN_IFERR(exp_write_schema_com("\n/\n", &g_exp_txtbuf, g_exp_dpfile));
        (void)exp_bin_write_int32(&exp_opts->master_bin_mgr, EXP_OBJECT_END_FLAG);
        (void)exp_bin_memory_mgr_sub_end(&exp_opts->master_bin_mgr, g_export_opts.filetype);

        // inc synonyms count.
        inc_total(synonyms_total);
    } while (GS_TRUE);

    return GS_SUCCESS;
}

static inline int exp_get_user_procs(export_options_t *exp_opts, const char *user, list_t *user_procs)
{
    exp_obj_info_t *ptr = NULL;
    uint32 rows;
    exp_prepare_sql_param_t param;
    char *obj_name = NULL;
    char *obj_type = NULL;
    uint32 name_len, type_len;
    char cmd_buf[GSQL_MAX_TEMP_SQL + 1];

    param.get_proc_param.exp_opts = exp_opts;
    param.get_proc_param.user = user;

    GS_RETURN_IFERR(EXP_PREPARE_SQL(EXP_GET_USER_PROC_LIST, cmd_buf, GSQL_MAX_TEMP_SQL, &param));

    GS_RETURN_IFERR(gsc_prepare(STMT, (const char *)cmd_buf));
    GS_RETURN_IFERR(gsc_execute(STMT));

    do {
        GS_RETURN_IFERR(gsc_fetch(STMT, &rows));
        if (rows == 0) {
            break;
        }
        GS_RETURN_IFERR(gsc_get_column_by_id(STMT, 0, (void**)&obj_name, &name_len, NULL));
        GS_RETURN_IFERR(gsc_get_column_by_id(STMT, 1, (void**)&obj_type, &type_len, NULL));
        GS_RETURN_IFERR(cm_list_new(user_procs, (pointer_t *)&ptr));
        MEMS_EXP_RETURN_IFERR(strncpy_s(ptr->obj_name, sizeof(ptr->obj_name), obj_name, name_len));
        MEMS_EXP_RETURN_IFERR(strncpy_s(ptr->obj_type, sizeof(ptr->obj_type), obj_type, type_len));
    } while (GS_TRUE);

    return GS_SUCCESS;
}

static inline int exp_single_proc(export_options_t *exp_opts, const char *user, exp_obj_info_t *obj,
    exp_cache_t *obj_cache)
{
    uint32 rows;

    GS_RETURN_IFERR(gsc_bind_by_pos(STMT, 0, GSC_TYPE_STRING, obj->obj_name, (int32)strlen(obj->obj_name), NULL));
    GS_RETURN_IFERR(gsc_bind_by_pos(STMT, 1, GSC_TYPE_STRING, obj->obj_type, (int32)strlen(obj->obj_type), NULL));
    if (!exp_opts->is_myself) {
        // '2' means name bind position
        GS_RETURN_IFERR(gsc_bind_by_pos(STMT, 2, GSC_TYPE_STRING, user, (int32)strlen(user), NULL));
    }

    GS_RETURN_IFERR(gsc_execute(STMT));

    GS_RETURN_IFERR(gsc_fetch(STMT, &rows));
    if (rows == 0) {
        EXP_THROW_ERROR(ERR_TABLE_OR_VIEW_NOT_EXIST, user, obj->obj_name);
        return GS_ERROR;
    }
    GS_RETURN_IFERR(gsc_column_as_string(STMT, 0, g_str_buf, GS_MAX_PACKET_SIZE));
    GS_RETURN_IFERR(exp_start_cache_unit(obj_cache, EXP_CACHE_OBJ_TYPE));
    GS_RETURN_IFERR(exp_cache_append_str(obj_cache, g_str_buf));

    exp_log(EXP_INDENT "exporting %s %s.%s\n", g_str_buf, user, obj->obj_name);

    GS_RETURN_IFERR(gsc_column_as_string(STMT, 1, g_str_buf, GS_MAX_PACKET_SIZE));
    GS_RETURN_IFERR(exp_start_cache_unit(obj_cache, EXP_CACHE_OBJ_NAME));
    if (!CM_IS_EMPTY_STR(g_str_buf)) {
        GS_RETURN_IFERR(exp_cache_append_str_quote(obj_cache, g_str_buf));
        GS_RETURN_IFERR(exp_cache_append_str(obj_cache, "."));
    }
    GS_RETURN_IFERR(exp_cache_append_str_quote(obj_cache, obj->obj_name));

    GS_RETURN_IFERR(exp_start_cache_unit(obj_cache, EXP_CACHE_OBJ_SRC));
    GS_RETURN_IFERR(exp_write_schema_lob(STMT, 2, g_str_buf, CLT_LOB_BUFFER_SIZE, obj_cache));

    return GS_SUCCESS;
}

static status_t exp_proc_scripts(export_options_t *exp_opts, const char *user, list_t *user_procs)
{
    exp_cache_t obj_cache;
    status_t ret = GS_SUCCESS;
    uint32 *procs_total = NULL;

    GS_RETURN_IFERR(init_exp_cache(&obj_cache, EXP_MAX_UNIT_CNT_PER_OBJ, EXP_CACHE_OBJ));

    do {
        procs_total = (uint32 *)exp_bin_write_int32(&exp_opts->master_bin_mgr, (uint32)0);
        for (uint32 i = 0; i < user_procs->count; i++) {
            reset_exp_cache(&obj_cache);
            ret = exp_single_proc(exp_opts, user, (exp_obj_info_t *)cm_list_get(user_procs, i), &obj_cache);
            if (ret == GS_SUCCESS) {
                ret = obj_cache_write_file(&obj_cache);
            }

            if (ret == GS_SUCCESS) {
                // inc proc count.
                inc_total(procs_total);
            }
            EXP_BREAK_IFERR(ret);
        }
    } while (0);

    uninit_exp_cache(&obj_cache);
    return ret;
}

static int exp_prepare_proc_info(void)
{
    char cmd_buf[GSQL_MAX_TEMP_SQL + 1];
    if (g_export_opts.is_myself) {
        PRTS_RETURN_IFERR(sprintf_s(cmd_buf, GSQL_MAX_TEMP_SQL,
            "SELECT OBJECT_TYPE, PROCEDURE_NAME, SOURCE "
            "FROM " EXP_MY_PROCS_AGENT " "
            "WHERE OBJECT_NAME = :p AND OBJECT_TYPE = :t"));
    } else {
        PRTS_RETURN_IFERR(sprintf_s(cmd_buf, GSQL_MAX_TEMP_SQL,
            "SELECT OBJECT_TYPE, PROCEDURE_NAME, SOURCE "
            "FROM " EXP_PROCS_AGENT " "
            "WHERE OBJECT_NAME = :p AND OBJECT_TYPE = :t AND OWNER = UPPER(:o) "));
    }

    GS_RETURN_IFERR(gsc_prepare(STMT, (const char *)cmd_buf));
    return GS_SUCCESS;
}

static inline int exp_user_procs(export_options_t *exp_opts, const char *user)
{
    int status;
    list_t user_procs;

    exp_create_objlist(&user_procs, sizeof(exp_obj_info_t));
    do {
        status = exp_get_user_procs(exp_opts, user, &user_procs);
        if (status != GS_SUCCESS) {
            break;
        }

        if (user_procs.count == 0) {
            (void)exp_bin_write_int32(&exp_opts->master_bin_mgr, (uint32)0);
            break;
        }

        status = exp_prepare_proc_info();
        if (status != GS_SUCCESS) {
            break;
        }

        status = exp_proc_scripts(exp_opts, user, &user_procs);
        if (status != GS_SUCCESS) {
            break;
        }
    } while (GS_FALSE);
    cm_reset_list(&user_procs);
    return status;
}

typedef enum {
    SEQUENCE_NAME,
    MIN_VALUE,
    MAX_VALUE,
    LAST_NUMBER,
    INCREMENT_BY,
    CYCLE_FLAG,
    CACHE_SIZE,
    ORDER_FLAG
} export_sequence_t;

static inline int exp_grant_role(export_options_t *exp_opts, const char *schema_name)
{
    uint32 rows;
    int iret_sprintf;
    char cmd_buf[GSQL_MAX_TEMP_SQL + 1];

    iret_sprintf = sprintf_s(cmd_buf, GSQL_MAX_TEMP_SQL,
                             "SELECT 'GRANT ' || GRANTED_ROLE || ' TO \"'|| GRANTEE || '\"' || IF(ADMIN_OPTION = 'YES', ' WITH ADMIN OPTION;', ';') "
                             "FROM ADM_ROLE_PRIVS WHERE GRANTEE = UPPER(:o) ORDER BY GRANTED_ROLE");
    if (iret_sprintf == -1) {
        EXP_THROW_ERROR(ERR_SYSTEM_CALL, iret_sprintf);
        return GS_ERROR;
    }
    GS_RETURN_IFERR(gsc_prepare(STMT, (const char *)cmd_buf));

    GS_RETURN_IFERR(gsc_bind_by_pos(STMT, 0, GSC_TYPE_STRING, schema_name, (int32)strlen(schema_name), NULL));
    GS_RETURN_IFERR(gsc_execute(STMT));

    do {
        GS_RETURN_IFERR(gsc_fetch(STMT, &rows));
        if (rows == 0) {
            break;
        }
        GS_RETURN_IFERR(gsc_column_as_string(STMT, 0, g_str_buf, GS_MAX_PACKET_SIZE));
        GS_RETURN_IFERR(exp_write_schema_com(g_str_buf, &g_exp_txtbuf, g_exp_dpfile));
        GS_RETURN_IFERR(exp_write_schema_com("\n", &g_exp_txtbuf, g_exp_dpfile));
    } while (GS_TRUE);

    return GS_SUCCESS;
}

static inline int exp_grant_privilege2role(export_options_t *exp_opts)
{
    uint32 rows;
    int iret_sprintf = 0;
    char *user = NULL;
    char cmd_buf[GSQL_MAX_TEMP_SQL + 1];

    if (exp_opts->exp_type == EXP_ALL_SCHEMAS) {
        iret_sprintf = sprintf_s(cmd_buf, GSQL_MAX_TEMP_SQL,
            "SELECT 'GRANT ' || PRIVILEGE || ' TO \"'|| ROLE || '\"' ||"
            " IF(ADMIN_OPTION = 'YES', ' WITH ADMIN OPTION;', ';') FROM ROLE_SYS_PRIVS WHERE ROLE IN "
            "(SELECT GRANTED_ROLE FROM ADM_ROLE_PRIVS WHERE GRANTEE in "
            "(SELECT USERNAME FROM DB_USERS WHERE USERNAME <> 'SYS' AND USERNAME <> 'PUBLIC') "
            "AND GRANTED_ROLE NOT IN ('DBA','RESOURCE','CONNECT') ORDER BY GRANTED_ROLE) ORDER BY PRIVILEGE");
        if (iret_sprintf == -1) {
            EXP_THROW_ERROR(ERR_SYSTEM_CALL, iret_sprintf);
            return GS_ERROR;
        }
    } else {
        iret_sprintf = sprintf_s(cmd_buf, GSQL_MAX_TEMP_SQL,
            "SELECT 'GRANT ' || PRIVILEGE || ' TO \"'|| ROLE || '\"' ||"
            " IF(ADMIN_OPTION = 'YES', ' WITH ADMIN OPTION;', ';') "
            "FROM ROLE_SYS_PRIVS WHERE ROLE IN (SELECT GRANTED_ROLE FROM ADM_ROLE_PRIVS WHERE GRANTEE in (");
        if (iret_sprintf == -1) {
            EXP_THROW_ERROR(ERR_SYSTEM_CALL, iret_sprintf);
            return GS_ERROR;
        }

        for (uint32 i = 0; i < exp_opts->obj_list.count; i++) {
            if (i > 0) {
                MEMS_RETURN_IFERR(strcat_s(cmd_buf, GSQL_MAX_TEMP_SQL, ", "));
            }

            user = (char *)cm_list_get(&exp_opts->obj_list, i);
            MEMS_RETURN_IFERR(strcat_s(cmd_buf, GSQL_MAX_TEMP_SQL, "UPPER('"));
            MEMS_RETURN_IFERR(strcat_s(cmd_buf, GSQL_MAX_TEMP_SQL, user));
            MEMS_RETURN_IFERR(strcat_s(cmd_buf, GSQL_MAX_TEMP_SQL, "')"));
        }
        MEMS_RETURN_IFERR(strcat_s(cmd_buf, GSQL_MAX_TEMP_SQL,
            ")  AND GRANTED_ROLE NOT IN ('DBA','RESOURCE','CONNECT') ORDER BY GRANTED_ROLE) ORDER BY PRIVILEGE"));
    }

    GS_RETURN_IFERR(gsc_prepare(STMT, (const char *)cmd_buf));
    GS_RETURN_IFERR(gsc_execute(STMT));

    do {
        GS_RETURN_IFERR(gsc_fetch(STMT, &rows));
        if (rows == 0) {
            break;
        }
        GS_RETURN_IFERR(gsc_column_as_string(STMT, 0, g_str_buf, GS_MAX_PACKET_SIZE));
        GS_RETURN_IFERR(exp_write_str_s(g_str_buf, &g_exp_txtbuf, g_exp_dpfile));
        GS_RETURN_IFERR(exp_write_str_s("\n", &g_exp_txtbuf, g_exp_dpfile));
    } while (GS_TRUE);

    return GS_SUCCESS;
}

static inline int exp_grant_privilege2user(export_options_t *exp_opts, const char *schema_name)
{
    uint32 rows;
    int iret_sprintf;
    char cmd_buf[GSQL_MAX_TEMP_SQL + 1];

    iret_sprintf = sprintf_s(cmd_buf, GSQL_MAX_TEMP_SQL,
                             "SELECT 'GRANT ' || PRIVILEGE || ' TO \"'|| GRANTEE || '\"' || IF(ADMIN_OPTION = 'YES', ' WITH ADMIN OPTION;', ';') "
                             "FROM ADM_SYS_PRIVS WHERE GRANTEE = UPPER(:o) ORDER BY PRIVILEGE");
    if (iret_sprintf == -1) {
        EXP_THROW_ERROR(ERR_SYSTEM_CALL, iret_sprintf);
        return GS_ERROR;
    }
    GS_RETURN_IFERR(gsc_prepare(STMT, (const char *)cmd_buf));

    GS_RETURN_IFERR(gsc_bind_by_pos(STMT, 0, GSC_TYPE_STRING, schema_name, (int32)strlen(schema_name), NULL));
    GS_RETURN_IFERR(gsc_execute(STMT));

    do {
        GS_RETURN_IFERR(gsc_fetch(STMT, &rows));
        if (rows == 0) {
            break;
        }
        GS_RETURN_IFERR(gsc_column_as_string(STMT, 0, g_str_buf, GS_MAX_PACKET_SIZE));
        GS_RETURN_IFERR(exp_write_schema_com(g_str_buf, &g_exp_txtbuf, g_exp_dpfile));
        GS_RETURN_IFERR(exp_write_schema_com("\n", &g_exp_txtbuf, g_exp_dpfile));
    } while (GS_TRUE);
    return GS_SUCCESS;
}

static inline int exp_user_definition(export_options_t *exp_opts, const char *schema_name, bool32 *alter_tenant)
{
    uint32 rows;
    int iret_sprintf;
    text_t schema, tenant;
    char schema_buf[GS_NAME_BUFFER_SIZE];
    char tenant_buf[GS_TENANT_BUFFER_SIZE];
    char cmd_buf[GSQL_MAX_TEMP_SQL + 1];

    if (strchr(schema_name, '$') != NULL) {
        cm_str2text((char *)schema_name, &schema);
        (void)cm_fetch_text(&schema, '$', 0, &tenant);
        GS_RETURN_IFERR(cm_text2str(&schema, schema_buf, GS_NAME_BUFFER_SIZE));
        GS_RETURN_IFERR(cm_text2str(&tenant, tenant_buf, GS_TENANT_BUFFER_SIZE));
        GS_RETURN_IFERR(exp_write_schema_com("ALTER SESSION SET TENANT = ", &g_exp_txtbuf, g_exp_dpfile));
        exp_write_fmt(GS_TRUE, EXP_WRITE_FMT_100, "%s;\n", tenant_buf);
        *alter_tenant = GS_TRUE;
    } else {
        MEMS_RETURN_IFERR(strcpy_s(schema_buf, GS_NAME_BUFFER_SIZE, schema_name));
    }

    iret_sprintf = sprintf_s(cmd_buf, GSQL_MAX_TEMP_SQL,
                             "SELECT 'IDENTIFIED BY '''|| CAST(U.PASSWORD AS VARBINARY(%d)) || ''' ENCRYPTED' || DECODE(U.ASTATUS,  1, ' PASSWORD EXPIRE',  8, ' ACCOUNT LOCK',  9, ' PASSWORD EXPIRE ACCOUNT LOCK') || ' DEFAULT TABLESPACE \"' || T.NAME || '\";' "
                             "FROM SYS.SYS_USERS U, SYS.DV_TABLESPACES T WHERE U.DATA_SPACE#=T.ID and U.NAME = UPPER(:D)",
                             MAX_PWD_CHIPER_LEN);
    if (iret_sprintf == -1) {
        EXP_THROW_ERROR(ERR_SYSTEM_CALL, iret_sprintf);
        return GS_ERROR;
    }
    GS_RETURN_IFERR(gsc_prepare(STMT, (const char *)cmd_buf));
    GS_RETURN_IFERR(gsc_bind_by_pos(STMT, 0, GSC_TYPE_STRING, schema_name, (int32)strlen(schema_name), NULL));
    GS_RETURN_IFERR(gsc_execute(STMT));

    GS_RETURN_IFERR(gsc_fetch(STMT, &rows));
    if (rows == 0) {
        EXP_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "The user is not exist.");
        return GS_ERROR;
    }
    GS_RETURN_IFERR(gsc_column_as_string(STMT, 0, g_str_buf, GS_MAX_PACKET_SIZE));
    exp_write_fmt(GS_TRUE, EXP_WRITE_FMT_100, "CREATE USER \"%s\" ", schema_buf);
    GS_RETURN_IFERR(exp_write_schema_com(g_str_buf, &g_exp_txtbuf, g_exp_dpfile));
    GS_RETURN_IFERR(exp_write_schema_com("\n", &g_exp_txtbuf, g_exp_dpfile));

    return GS_SUCCESS;
}

static inline int exp_user_role(export_options_t *exp_opts)
{
    uint32 rows;
    char cmd_buf[GSQL_MAX_TEMP_SQL + 1];
    exp_prepare_sql_param_t param;

    param.get_role_param.exp_opts = exp_opts;

    GS_RETURN_IFERR(EXP_PREPARE_SQL(EXP_GET_ROLE_LIST, cmd_buf, GSQL_MAX_TEMP_SQL, &param));

    GS_RETURN_IFERR(gsc_prepare(STMT, (const char *)cmd_buf));
    GS_RETURN_IFERR(gsc_execute(STMT));

    do {
        GS_RETURN_IFERR(gsc_fetch(STMT, &rows));
        if (rows == 0) {
            break;
        }
        GS_RETURN_IFERR(gsc_column_as_string(STMT, 0, g_str_buf, GS_MAX_PACKET_SIZE));
        GS_RETURN_IFERR(exp_write_str_s(g_str_buf, &g_exp_txtbuf, g_exp_dpfile));
        GS_RETURN_IFERR(exp_write_str_s("\n", &g_exp_txtbuf, g_exp_dpfile));
    } while (GS_TRUE);

    return GS_SUCCESS;
}

static inline int exp_grant_user(export_options_t *exp_opts, const char *schema_name)
{
    // grant privilege to user
    exp_tmlog("Grant privilege to schema %s ...\n", schema_name);
    EXP_RETURN_IFERR(exp_grant_privilege2user(exp_opts, schema_name));

    // grant role to user
    exp_tmlog("Grant role to schema %s ...\n", schema_name);
    EXP_RETURN_IFERR(exp_grant_role(exp_opts, schema_name));

    return GS_SUCCESS;
}

static int exp_user_profile(export_options_t *exp_opts, const char *user)
{
    uint32 rows;
    char cmd_buf[GSQL_MAX_TEMP_SQL + 1];
    exp_prepare_sql_param_t param;
    uint32 *profile_total;

    profile_total = (uint32 *)exp_bin_write_int32(&exp_opts->master_bin_mgr, (uint32)0);
    param.get_profile_param.user_name = user;
    GS_RETURN_IFERR(EXP_PREPARE_SQL(EXP_GET_USER_PROFILE_LIST, cmd_buf, GSQL_MAX_TEMP_SQL, &param));

    GS_RETURN_IFERR(gsc_prepare(STMT, (const char *)cmd_buf));
    GS_RETURN_IFERR(gsc_execute(STMT));

    do {
        GS_RETURN_IFERR(gsc_fetch(STMT, &rows));
        if (rows == 0) {
            break;
        }

        GS_RETURN_IFERR(gsc_column_as_string(STMT, 0, g_str_buf, GS_MAX_PACKET_SIZE));
        (void)exp_bin_memory_mgr_sub_begin(&exp_opts->master_bin_mgr, exp_opts->filetype);
        GS_RETURN_IFERR(exp_write_schema_com(g_str_buf, &g_exp_txtbuf, g_exp_dpfile));
        GS_RETURN_IFERR(exp_write_schema_com("\n/\n", &g_exp_txtbuf, g_exp_dpfile));
        (void)exp_bin_write_int32(&exp_opts->master_bin_mgr, EXP_OBJECT_END_FLAG);
        (void)exp_bin_memory_mgr_sub_end(&exp_opts->master_bin_mgr, exp_opts->filetype);

        // inc profile count.
        inc_total(profile_total);
    } while (GS_TRUE);

    return GS_SUCCESS;
}

static int exp_user_package(export_options_t *exp_opts, const char *user)
{
    uint32 rows;
    uint32 *package_total;
    char cmd_buf[GSQL_MAX_TEMP_SQL + 1];
    exp_prepare_sql_param_t param;

    package_total = (uint32 *)exp_bin_write_int32(&exp_opts->master_bin_mgr, (uint32)0);
    param.get_package_param.user_name = user;
    GS_RETURN_IFERR(EXP_PREPARE_SQL(EXP_GET_USER_PACKAGE_LIST, cmd_buf, GSQL_MAX_TEMP_SQL, &param));

    GS_RETURN_IFERR(gsc_prepare(STMT, (const char *)cmd_buf));
    GS_RETURN_IFERR(gsc_execute(STMT));

    do {
        GS_RETURN_IFERR(gsc_fetch(STMT, &rows));
        if (rows == 0) {
            break;
        }

        (void)exp_bin_memory_mgr_sub_begin(&exp_opts->master_bin_mgr, exp_opts->filetype);
        GS_RETURN_IFERR(exp_write_schema_lob(STMT, 0, g_str_buf, CLT_LOB_BUFFER_SIZE, NULL));
        GS_RETURN_IFERR(exp_write_schema_com("\n", &g_exp_txtbuf, g_exp_dpfile));
        (void)exp_bin_write_int32(&exp_opts->master_bin_mgr, EXP_OBJECT_END_FLAG);
        (void)exp_bin_memory_mgr_sub_end(&exp_opts->master_bin_mgr, exp_opts->filetype);

        // inc package count.
        inc_total(package_total);
    } while (GS_TRUE);

    return GS_SUCCESS;
}

static int exp_user_type(export_options_t *exp_opts, const char *user)
{
    uint32 rows;
    uint32 *type_total;
    char cmd_buf[GSQL_MAX_TEMP_SQL + 1];
    exp_prepare_sql_param_t param;

    type_total = (uint32 *)exp_bin_write_int32(&exp_opts->master_bin_mgr, (uint32)0);
    param.get_type_param.user_name = user;
    GS_RETURN_IFERR(EXP_PREPARE_SQL(EXP_GET_USER_TYPE_LIST, cmd_buf, GSQL_MAX_TEMP_SQL, &param));
    GS_RETURN_IFERR(gsc_prepare(STMT, (const char *)cmd_buf));
    GS_RETURN_IFERR(gsc_execute(STMT));

    do {
        GS_RETURN_IFERR(gsc_fetch(STMT, &rows));
        if (rows == 0) {
            break;
        }

        (void)exp_bin_memory_mgr_sub_begin(&exp_opts->master_bin_mgr, exp_opts->filetype);
        GS_RETURN_IFERR(exp_write_schema_lob(STMT, 0, g_str_buf, CLT_LOB_BUFFER_SIZE, NULL));
        GS_RETURN_IFERR(exp_write_schema_com("\n", &g_exp_txtbuf, g_exp_dpfile));
        (void)exp_bin_write_int32(&exp_opts->master_bin_mgr, EXP_OBJECT_END_FLAG);
        (void)exp_bin_memory_mgr_sub_end(&exp_opts->master_bin_mgr, exp_opts->filetype);

        inc_total(type_total); // inc profile count.
    } while (GS_TRUE);

    return GS_SUCCESS;
}

status_t exp_sequence(export_options_t *exp_opts, const char *schema_name, uint32 *total)
{
    uint32 rows;
    int iret_sprintf;
    char cmd_buf[GSQL_MAX_TEMP_SQL + 1];

    PRTS_RETURN_IFERR(sprintf_s(cmd_buf, GSQL_MAX_TEMP_SQL,
        "select SEQUENCE_NAME, MIN_VALUE, MAX_VALUE, LAST_NUMBER, INCREMENT_BY, CYCLE_FLAG, CACHE_SIZE, ORDER_FLAG "
        "from %s where SEQUENCE_OWNER = upper(:o) order by SEQUENCE_NAME",
        exp_tabname(g_export_opts.consistent, EXP_TABAGENT_DB_SEQUENCES)));

    if (!IS_CONN) {
        (void)gsql_print_disconn_error();
        return GS_ERROR;
    }

    GS_RETURN_IFERR(gsc_prepare(STMT, (const char *)cmd_buf));

    GS_RETURN_IFERR(gsc_bind_by_pos(STMT, 0, GSC_TYPE_STRING, schema_name, (int32)strlen(schema_name), NULL));
    GS_RETURN_IFERR(gsc_execute(STMT));

    GS_RETURN_IFERR(gsc_fetch(STMT, &rows));

    while (rows > 0) {
        (void)exp_bin_memory_mgr_sub_begin(&exp_opts->master_bin_mgr, exp_opts->filetype);
        inc_total(total);
        (void)gsc_column_as_string(STMT, SEQUENCE_NAME, g_str_buf, GS_MAX_PACKET_SIZE);
        // write drop sequence
        GS_RETURN_IFERR(exp_write_schema_com("DROP SEQUENCE IF EXISTS ", &g_exp_txtbuf, g_exp_dpfile));
        exp_write_schema_quote(g_str_buf);
        GS_RETURN_IFERR(exp_write_schema_com(";\n", &g_exp_txtbuf, g_exp_dpfile));

        GS_RETURN_IFERR(exp_write_schema_com("CREATE SEQUENCE ", &g_exp_txtbuf, g_exp_dpfile));
        exp_write_schema_quote(g_str_buf);

        (void)gsc_column_as_string(STMT, MIN_VALUE, g_str_buf, GS_MAX_PACKET_SIZE);
        iret_sprintf = sprintf_s(cmd_buf, GSQL_MAX_TEMP_SQL, " MINVALUE %s ", g_str_buf);
        if (iret_sprintf == -1) {
            EXP_THROW_ERROR(ERR_SYSTEM_CALL, iret_sprintf);
            return GS_ERROR;
        }
        GS_RETURN_IFERR(exp_write_schema_com(cmd_buf, &g_exp_txtbuf, g_exp_dpfile));

        (void)gsc_column_as_string(STMT, MAX_VALUE, g_str_buf, GS_MAX_PACKET_SIZE);
        iret_sprintf = sprintf_s(cmd_buf, GSQL_MAX_TEMP_SQL, "MAXVALUE %s ", g_str_buf);
        if (iret_sprintf == -1) {
            EXP_THROW_ERROR(ERR_SYSTEM_CALL, iret_sprintf);
            return GS_ERROR;
        }
        GS_RETURN_IFERR(exp_write_schema_com(cmd_buf, &g_exp_txtbuf, g_exp_dpfile));

        (void)gsc_column_as_string(STMT, LAST_NUMBER, g_str_buf, GS_MAX_PACKET_SIZE);
        iret_sprintf = sprintf_s(cmd_buf, GSQL_MAX_TEMP_SQL, "START WITH %s ", g_str_buf);
        if (iret_sprintf == -1) {
            EXP_THROW_ERROR(ERR_SYSTEM_CALL, iret_sprintf);
            return GS_ERROR;
        }
        GS_RETURN_IFERR(exp_write_schema_com(cmd_buf, &g_exp_txtbuf, g_exp_dpfile));

        (void)gsc_column_as_string(STMT, INCREMENT_BY, g_str_buf, GS_MAX_PACKET_SIZE);
        iret_sprintf = sprintf_s(cmd_buf, GSQL_MAX_TEMP_SQL, "INCREMENT BY %s ", g_str_buf);
        if (iret_sprintf == -1) {
            EXP_THROW_ERROR(ERR_SYSTEM_CALL, iret_sprintf);
            return GS_ERROR;
        }
        GS_RETURN_IFERR(exp_write_schema_com(cmd_buf, &g_exp_txtbuf, g_exp_dpfile));

        (void)gsc_column_as_string(STMT, CYCLE_FLAG, g_str_buf, GS_MAX_PACKET_SIZE);

        if (g_str_buf[0] == '1') {
            iret_sprintf = sprintf_s(cmd_buf, GSQL_MAX_TEMP_SQL, "CYCLE ");
            if (iret_sprintf == -1) {
                EXP_THROW_ERROR(ERR_SYSTEM_CALL, iret_sprintf);
                return GS_ERROR;
            }
            GS_RETURN_IFERR(exp_write_schema_com(cmd_buf, &g_exp_txtbuf, g_exp_dpfile));
        }

        (void)gsc_column_as_string(STMT, CACHE_SIZE, g_str_buf, GS_MAX_PACKET_SIZE);

        if (g_str_buf[0] == '0') {
            iret_sprintf = sprintf_s(cmd_buf, GSQL_MAX_TEMP_SQL, "NOCACHE ");
        } else {
            iret_sprintf = sprintf_s(cmd_buf, GSQL_MAX_TEMP_SQL, "CACHE %s ", g_str_buf);
        }
        if (iret_sprintf == -1) {
            EXP_THROW_ERROR(ERR_SYSTEM_CALL, iret_sprintf);
            return GS_ERROR;
        }

        GS_RETURN_IFERR(exp_write_schema_com(cmd_buf, &g_exp_txtbuf, g_exp_dpfile));

        (void)gsc_column_as_string(STMT, ORDER_FLAG, g_str_buf, GS_MAX_PACKET_SIZE);

        if (g_str_buf[0] == '1') {
            iret_sprintf = sprintf_s(cmd_buf, GSQL_MAX_TEMP_SQL, "ORDER ");
            if (iret_sprintf == -1) {
                EXP_THROW_ERROR(ERR_SYSTEM_CALL, iret_sprintf);
                return GS_ERROR;
            }
            GS_RETURN_IFERR(exp_write_schema_com(cmd_buf, &g_exp_txtbuf, g_exp_dpfile));
        }

        GS_RETURN_IFERR(exp_write_schema_com(";\n", &g_exp_txtbuf, g_exp_dpfile));
        GS_RETURN_IFERR(exp_write_schema_com("\n", &g_exp_txtbuf, g_exp_dpfile));

        (void)exp_bin_write_int32(&exp_opts->master_bin_mgr, EXP_OBJECT_END_FLAG);
        (void)exp_bin_memory_mgr_sub_end(&exp_opts->master_bin_mgr, exp_opts->filetype);

        GS_RETURN_IFERR(gsc_fetch(STMT, &rows));
    }
    return GS_SUCCESS;
}

static inline int exp_get_all_dist_rules(export_options_t *exp_opts, const char *user)
{
    uint32 rows;
    char *ptr = NULL;
    int iret_sprintf;
    char cmd_buf[GSQL_MAX_TEMP_SQL + 1];

    if (exp_opts->is_dba) {
        iret_sprintf = sprintf_s(cmd_buf, GSQL_MAX_TEMP_SQL,
                                 "SELECT R.NAME "
                                 " FROM SYS.SYS_USERS U, SYS.SYS_DISTRIBUTE_RULES R "
                                 " WHERE U.ID = R.UID AND U.NAME = UPPER(:u) ORDER BY NAME");
    } else {
        iret_sprintf = sprintf_s(cmd_buf, GSQL_MAX_TEMP_SQL,
                                 "SELECT NAME "
                                 "FROM " EXP_DISTRIBUTE_RULE_AGENT " "
                                 "WHERE OWNER = UPPER(:u) ORDER BY NAME");
    }
    if (iret_sprintf == -1) {
        EXP_THROW_ERROR(ERR_SYSTEM_CALL, iret_sprintf);
        return GS_ERROR;
    }

    GS_RETURN_IFERR(gsc_prepare(STMT, (const char *)cmd_buf));
    GS_RETURN_IFERR(gsc_bind_by_pos(STMT, 0, GSC_TYPE_STRING, user, (int32)strlen(user), NULL));
    GS_RETURN_IFERR(gsc_execute(STMT));

    do {
        GS_RETURN_IFERR(gsc_fetch(STMT, &rows));
        if (rows == 0) {
            break;
        }
        GS_RETURN_IFERR(gsc_column_as_string(STMT, 0, g_str_buf, GS_MAX_PACKET_SIZE));
        if (cm_list_new(&exp_opts->obj_list, (pointer_t *)&ptr) != GS_SUCCESS) {
            return GS_ERROR;
        }
        MEMS_EXP_RETURN_IFERR(strncpy_s(ptr, GSQL_MAX_OBJECT_LEN, g_str_buf, GSQL_MAX_OBJECT_LEN - 1));
    } while (GS_TRUE);
    return GS_SUCCESS;
}

status_t exp_single_schema(export_options_t *exp_opts, const char *schema_name)
{
    uint32 *obj_total = NULL;
    bool32 alter_tenant = GS_FALSE;

    exp_tmlog("Exporting schema %s ...\n", schema_name);

    (void)exp_bin_write_str(&exp_opts->master_bin_mgr, schema_name, (uint32)strlen(schema_name));
    // export user definition & user roles & alter session & sequence
    GS_RETURN_IFERR(exp_bin_memory_mgr_begin(&exp_opts->master_bin_mgr, exp_opts->filetype));  // total len
    obj_total = (uint32 *)exp_bin_write_int32(&exp_opts->master_bin_mgr, (uint32)1);              // object total
    (void)exp_bin_memory_mgr_sub_begin(&exp_opts->master_bin_mgr, exp_opts->filetype);

    if (exp_opts->create_user == GS_TRUE) {
        // export user definition
        GS_RETURN_IFERR(exp_write_schema_com("\n", &g_exp_txtbuf, g_exp_dpfile));
        exp_tmlog("Exporting user definition of schema %s ...\n", schema_name);
        EXP_RETURN_IFERR(exp_user_definition(exp_opts, schema_name, &alter_tenant));
    }

    if (exp_opts->is_grant == GS_TRUE) {
        // grant role and privilege to user
        GS_RETURN_IFERR(exp_write_schema_com("\n", &g_exp_txtbuf, g_exp_dpfile));
        exp_tmlog("Exporting grant role and privilege of schema %s ...\n", schema_name);
        EXP_RETURN_IFERR(exp_grant_user(exp_opts, schema_name));
    }

    GS_RETURN_IFERR(exp_write_schema_com("\n", &g_exp_txtbuf, g_exp_dpfile));
    GS_RETURN_IFERR(exp_write_schema_com("ALTER SESSION SET CURRENT_SCHEMA = ", &g_exp_txtbuf, g_exp_dpfile));
    exp_write_fmt(GS_TRUE, EXP_WRITE_FMT_100, "%s;\n", schema_name);

    (void)exp_bin_write_int32(&g_export_opts.master_bin_mgr, EXP_OBJECT_END_FLAG);
    exp_bin_memory_mgr_sub_end(&exp_opts->master_bin_mgr, exp_opts->filetype);

    exp_tmlog("Exporting sequence of schema %s ...\n", schema_name);
    EXP_RETURN_IFERR(exp_sequence(exp_opts, schema_name, obj_total));
    exp_bin_memory_mgr_end(&exp_opts->master_bin_mgr, exp_opts->filetype);
  
    // export user profile, begin from EXP_VERSION_2
    exp_tmlog("Exporting profile of schema %s ...\n", schema_name);
    GS_RETURN_IFERR(exp_bin_memory_mgr_begin(&exp_opts->master_bin_mgr, exp_opts->filetype));
    EXP_RETURN_IFERR(exp_user_profile(exp_opts, schema_name));
    exp_bin_memory_mgr_end(&exp_opts->master_bin_mgr, exp_opts->filetype);

    // export user define type, begin from EXP_VERSION_2
    exp_tmlog("Exporting type of schema %s ...\n", schema_name);
    GS_RETURN_IFERR(exp_bin_memory_mgr_begin(&exp_opts->master_bin_mgr, exp_opts->filetype));
    EXP_RETURN_IFERR(exp_user_type(exp_opts, schema_name));
    exp_bin_memory_mgr_end(&exp_opts->master_bin_mgr, exp_opts->filetype);

    // export tables of all users
    exp_tmlog("Exporting tables of schema %s ...\n", schema_name);
    EXP_RETURN_IFERR(exp_user_tables(exp_opts, schema_name));

    // export tables of all PROCEDURES
    exp_tmlog("Exporting procedures/functions/triggers of schema %s ...\n", schema_name);
    GS_RETURN_IFERR(exp_bin_memory_mgr_begin(&exp_opts->master_bin_mgr, exp_opts->filetype));
    EXP_RETURN_IFERR(exp_user_procs(exp_opts, schema_name));
    exp_bin_memory_mgr_end(&exp_opts->master_bin_mgr, exp_opts->filetype); // export bin  tables of all PROCEDURES

    // export tables of all views
    exp_tmlog("Exporting views of schema %s ...\n", schema_name);
    GS_RETURN_IFERR(exp_bin_memory_mgr_begin(&exp_opts->master_bin_mgr, exp_opts->filetype));
    EXP_RETURN_IFERR(exp_user_views(exp_opts, schema_name));
    exp_bin_memory_mgr_end(&exp_opts->master_bin_mgr, exp_opts->filetype);  // export bin tables of all views

    // export synonym in this user, begin from EXP_VERSION_2
    exp_tmlog("Exporting synonyms of schema %s ...\n", schema_name);
    GS_RETURN_IFERR(exp_bin_memory_mgr_begin(&exp_opts->master_bin_mgr, exp_opts->filetype));
    EXP_RETURN_IFERR(exp_user_synonyms(exp_opts, schema_name));
    exp_bin_memory_mgr_end(&exp_opts->master_bin_mgr, exp_opts->filetype);

    // export user package, begin from EXP_VERSION_2
    exp_tmlog("Exporting package of schema %s ...\n", schema_name);
    GS_RETURN_IFERR(exp_bin_memory_mgr_begin(&exp_opts->master_bin_mgr, exp_opts->filetype));
    EXP_RETURN_IFERR(exp_user_package(exp_opts, schema_name));
    exp_bin_memory_mgr_end(&exp_opts->master_bin_mgr, exp_opts->filetype);

    // if has alter tenant before, restore to tenant$root
    if (alter_tenant) {
        GS_RETURN_IFERR(exp_write_schema_com("ALTER SESSION SET TENANT = TENANT$ROOT;\n", &g_exp_txtbuf,
            g_exp_dpfile));
    }
    exp_tmlog("End of export schema %s ...\n\n", schema_name);

    return GS_SUCCESS;
}

static inline int exp_schema(export_options_t *exp_opts)
{
    int status = GS_SUCCESS;
    char *user = NULL;

    GS_RETURN_IFERR(exp_check_privilege(exp_opts));

    (void)exp_bin_write_int32(&exp_opts->master_bin_mgr, exp_opts->obj_list.count);

    for (uint32 i = 0; i < exp_opts->obj_list.count; i++) {
        user = (char *)cm_list_get(&exp_opts->obj_list, i);
        EXP_RETURN_IFERR(exp_single_schema(exp_opts, user));
        // if cancel, stop export
        EXP_RETRUN_IF_CANCEL;
    }

    return status;
}

static inline int exp_all_schemas(export_options_t *exp_opts)
{
    char *user = NULL;

    GS_RETURN_IFERR(exp_check_privilege(exp_opts));
    GS_RETURN_IFERR(exp_get_users(exp_opts));

    (void)exp_bin_write_int32(&g_export_opts.master_bin_mgr, exp_opts->obj_list.count);

    for (uint32 i = 0; i < exp_opts->obj_list.count; i++) {
        user = (char *)cm_list_get(&exp_opts->obj_list, i);
        EXP_RETURN_IFERR(exp_single_schema(exp_opts, user));
    }

    return GSC_SUCCESS;
}

status_t exp_create_tablespaces(bool32 is_first)
{
    GS_RETURN_IFERR(gsc_column_as_string(STMT, 0, g_str_buf, GS_MAX_PACKET_SIZE));
    exp_write_fmt(GS_FALSE, EXP_FMT_BUF_SZ, "'%s'", &g_str_buf);
    GS_RETURN_IFERR(exp_write_str_s(" SIZE ", &g_exp_txtbuf, g_exp_dpfile));

    GS_RETURN_IFERR(gsc_column_as_string(STMT, 1, g_str_buf, GS_MAX_PACKET_SIZE));
    GS_RETURN_IFERR(exp_write_str_s(g_str_buf, &g_exp_txtbuf, g_exp_dpfile));

    if (gsc_get_call_version(CONN) >= CS_VERSION_22) {
        GS_RETURN_IFERR(gsc_column_as_string(STMT, 5, g_str_buf, GS_MAX_PACKET_SIZE));
        if (strcmp((char *)"TRUE", g_str_buf) == 0) {
            GS_RETURN_IFERR(exp_write_str_s(" COMPRESS", &g_exp_txtbuf, g_exp_dpfile));
        }
    }

    GS_RETURN_IFERR(gsc_column_as_string(STMT, 2, g_str_buf, GS_MAX_PACKET_SIZE));
    if (cm_compare_str((char *)"YES", g_str_buf) == 0) {
        GS_RETURN_IFERR(exp_write_str_s(" AUTOEXTEND ON NEXT ", &g_exp_txtbuf, g_exp_dpfile));
        GS_RETURN_IFERR(gsc_column_as_string(STMT, 3, g_str_buf, GS_MAX_PACKET_SIZE));
        GS_RETURN_IFERR(exp_write_str_s(g_str_buf, &g_exp_txtbuf, g_exp_dpfile));
        GS_RETURN_IFERR(exp_write_str_s(" MAXSIZE ", &g_exp_txtbuf, g_exp_dpfile));
        GS_RETURN_IFERR(gsc_column_as_string(STMT, 4, g_str_buf, GS_MAX_PACKET_SIZE));
        GS_RETURN_IFERR(exp_write_str_s(g_str_buf, &g_exp_txtbuf, g_exp_dpfile));
    }

    if (gsc_get_call_version(CONN) >= CS_VERSION_22 && is_first) {
        GS_RETURN_IFERR(gsc_column_as_string(STMT, 6, g_str_buf, GS_MAX_PACKET_SIZE));
        if (cm_compare_str((char *)"MAP", g_str_buf) == 0) {
            GS_RETURN_IFERR(exp_write_str_s(" EXTENT AUTOALLOCATE", &g_exp_txtbuf, g_exp_dpfile));
        }
    }

    GS_RETURN_IFERR(exp_write_str_s(";\n", &g_exp_txtbuf, g_exp_dpfile));
    return GS_SUCCESS;
}

static inline int exp_single_tablespaces(char *tbspaces)
{
    uint32 rows;
    bool32 IS_FIRST = GS_TRUE;
    int iret_sprintf;
    char cmd_buf[GSQL_MAX_TEMP_SQL + 1];

    if (gsc_get_call_version(CONN) >= CS_VERSION_22) {
        iret_sprintf = sprintf_s(cmd_buf, GSQL_MAX_TEMP_SQL,
            "SELECT A.FILE_NAME, A.BYTES, A.AUTOEXTENSIBLE, A.INCREMENT_BY, A.MAXBYTES, "
            "B.COMPRESSION, C.EXTENT_MANAGEMENT "
            "FROM " EXP_TABLESPACES_DATAFILE_AGENT " A "
            "JOIN " EXP_DV_DATA_FILES_AGENT " B ON A.FILE_NAME = B.FILE_NAME "
            "JOIN " EXP_DV_TABLESPACES " C ON A.TABLESPACE_NAME = C.NAME "
            "WHERE A.TABLESPACE_NAME = :tbs ORDER BY A.FILE_NAME");
    } else {
        iret_sprintf = sprintf_s(cmd_buf, GSQL_MAX_TEMP_SQL,
            "SELECT FILE_NAME, BYTES, AUTOEXTENSIBLE, INCREMENT_BY, MAXBYTES "
            "FROM " EXP_TABLESPACES_DATAFILE_AGENT " "
            "WHERE TABLESPACE_NAME = :tbs ORDER BY FILE_NAME");
    }

    if (iret_sprintf == -1) {
        EXP_THROW_ERROR(ERR_SYSTEM_CALL, iret_sprintf);
        return GS_ERROR;
    }

    GS_RETURN_IFERR(gsc_prepare(STMT, (const char *)cmd_buf));

    GS_RETURN_IFERR(gsc_bind_by_pos(STMT, 0, GSC_TYPE_STRING, tbspaces, (int32)strlen(tbspaces), NULL));
    GS_RETURN_IFERR(gsc_execute(STMT));

    do {
        GS_RETURN_IFERR(gsc_fetch(STMT, &rows));
        if (rows == 0) {
            break;
        }
        if (IS_FIRST) {
            GS_RETURN_IFERR(exp_write_str_s("CREATE TABLESPACE ", &g_exp_txtbuf, g_exp_dpfile));
            exp_write_fmt(GS_FALSE, EXP_WRITE_FMT_100, "\"%s\"", tbspaces);
            GS_RETURN_IFERR(exp_write_str_s(" DATAFILE ", &g_exp_txtbuf, g_exp_dpfile));
            GS_RETURN_IFERR(exp_create_tablespaces(IS_FIRST));
            IS_FIRST = GS_FALSE;
        } else {
            GS_RETURN_IFERR(exp_write_str_s("ALTER TABLESPACE ", &g_exp_txtbuf, g_exp_dpfile));
            exp_write_fmt(GS_FALSE, EXP_WRITE_FMT_100, "\"%s\"", tbspaces);
            GS_RETURN_IFERR(exp_write_str_s(" ADD DATAFILE ", &g_exp_txtbuf, g_exp_dpfile));
            GS_RETURN_IFERR(exp_create_tablespaces(IS_FIRST));
        }
    } while (GS_TRUE);

    return GS_SUCCESS;
}

static inline int exp_get_all_tbspace(list_t *tmp_tbsname_list)
{
    uint32 rows;
    char *ptr = NULL;
    int iret_sprintf;
    char cmd_buf[GSQL_MAX_TEMP_SQL + 1];

    iret_sprintf = sprintf_s(cmd_buf, GSQL_MAX_TEMP_SQL,
                             "SELECT DISTINCT TABLESPACE_NAME "
                             "FROM " EXP_TABLESPACES_DATAFILE_AGENT " "
                             "WHERE TABLESPACE_NAME NOT IN ('SYSTEM','TEMP','UNDO','USERS','TEMP2','TEMP2_UNDO','SYSAUX') ORDER BY TABLESPACE_NAME");
    if (iret_sprintf == -1) {
        EXP_THROW_ERROR(ERR_SYSTEM_CALL, iret_sprintf);
        return GS_ERROR;
    }

    GS_RETURN_IFERR(gsc_prepare(STMT, (const char *)cmd_buf));
    GS_RETURN_IFERR(gsc_execute(STMT));

    do {
        GS_RETURN_IFERR(gsc_fetch(STMT, &rows));
        if (rows == 0) {
            break;
        }
        GS_RETURN_IFERR(gsc_column_as_string(STMT, 0, g_str_buf, GS_MAX_PACKET_SIZE));
        if (cm_list_new(tmp_tbsname_list, (pointer_t *)&ptr) != GS_SUCCESS) {
            EXP_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "new tmp_tbsname_list failed");
            return GS_ERROR;
        }
        MEMS_EXP_RETURN_IFERR(strncpy_s(ptr, GSQL_MAX_OBJECT_LEN, g_str_buf, GSQL_MAX_OBJECT_LEN - 1));
    } while (GS_TRUE);

    return GS_SUCCESS;
}

static inline int exp_all_tablespaces(void)
{
    char *tbspaces = NULL;
    list_t tmp_tbsname_list;
    int ret;

    exp_create_objlist(&tmp_tbsname_list, GSQL_MAX_OBJECT_LEN);
    ret = exp_get_all_tbspace(&tmp_tbsname_list);
    if (ret != GS_SUCCESS) {
        cm_reset_list(&tmp_tbsname_list);
        return ret;
    }

    for (uint32 i = 0; i < tmp_tbsname_list.count; i++) {
        tbspaces = (char *)cm_list_get(&tmp_tbsname_list, i);
        ret = exp_single_tablespaces(tbspaces);
        if (ret != GS_SUCCESS) {
            break;
        }
    }
    cm_reset_list(&tmp_tbsname_list);
    return ret;
}

static inline int exp_tablespace(void)
{
    return exp_all_tablespaces();
}

static inline int exp_single_tenant(char *tenant)
{
    uint32 rows;
    int iret_sprintf;
    char default_space[GS_NAME_BUFFER_SIZE];
    char cmd_buf[GSQL_MAX_TEMP_SQL + 1];

    iret_sprintf = sprintf_s(cmd_buf, GSQL_MAX_TEMP_SQL, "SELECT DEFAULT_TABLESPACE FROM ADM_TENANTS "
                             "WHERE NAME = :tenant");
    if (iret_sprintf == -1) {
        EXP_THROW_ERROR(ERR_SYSTEM_CALL, iret_sprintf);
        return GS_ERROR;
    }

    GS_RETURN_IFERR(gsc_prepare(STMT, (const char *)cmd_buf));
    GS_RETURN_IFERR(gsc_bind_by_pos(STMT, 0, GSC_TYPE_STRING, tenant, (int32)strlen(tenant), NULL));
    GS_RETURN_IFERR(gsc_execute(STMT));
    GS_RETURN_IFERR(gsc_fetch(STMT, &rows));
    if (rows == 0) {
        EXP_THROW_ERROR(ERR_TENANT_NOT_EXIST, tenant);
        return GS_SUCCESS;
    }
    GS_RETURN_IFERR(gsc_column_as_string(STMT, 0, default_space, GS_NAME_BUFFER_SIZE));

    iret_sprintf = sprintf_s(cmd_buf, GSQL_MAX_TEMP_SQL, "SELECT TABLESPACE_NAME FROM "EXP_DV_TENANT_TABLESPACES
                             " WHERE TENANT_NAME = :tenant AND TABLESPACE_NAME != :default_space");
    if (iret_sprintf == -1) {
        EXP_THROW_ERROR(ERR_SYSTEM_CALL, iret_sprintf);
        return GS_ERROR;
    }
    GS_RETURN_IFERR(gsc_prepare(STMT, (const char *)cmd_buf));
    GS_RETURN_IFERR(gsc_bind_by_pos(STMT, 0, GSC_TYPE_STRING, tenant, (int32)strlen(tenant), NULL));
    GS_RETURN_IFERR(gsc_bind_by_pos(STMT, 1, GSC_TYPE_STRING, default_space, (int32)strlen(default_space), NULL));
    GS_RETURN_IFERR(gsc_execute(STMT));

    GS_RETURN_IFERR(exp_write_str_s("CREATE TENANT ", &g_exp_txtbuf, g_exp_dpfile));
    exp_write_fmt(GS_FALSE, EXP_WRITE_FMT_100, "\"%s\"", tenant);
    GS_RETURN_IFERR(exp_write_str_s(" TABLESPACES(", &g_exp_txtbuf, g_exp_dpfile));
    exp_write_fmt(GS_FALSE, EXP_WRITE_FMT_100, "\"%s\"", default_space);
    do {
        GS_RETURN_IFERR(gsc_fetch(STMT, &rows));
        if (rows == 0) {
            break;
        }
        GS_RETURN_IFERR(gsc_column_as_string(STMT, 0, g_str_buf, GS_MAX_PACKET_SIZE));
        exp_write_fmt(GS_FALSE, EXP_WRITE_FMT_100, ",\"%s\"", g_str_buf);
    } while (GS_TRUE);
    GS_RETURN_IFERR(exp_write_str_s(");\n", &g_exp_txtbuf, g_exp_dpfile));
    return GS_SUCCESS;
}

static inline int exp_get_all_tenant(list_t *tmp_tenant_list)
{
    uint32 rows;
    char *ptr = NULL;
    int iret_sprintf;
    char cmd_buf[GSQL_MAX_TEMP_SQL + 1];

    iret_sprintf = sprintf_s(cmd_buf, GSQL_MAX_TEMP_SQL,
        "SELECT NAME FROM SYS.SYS_TENANTS WHERE TENANT_ID != 0 ORDER BY NAME");
    if (iret_sprintf == -1) {
        EXP_THROW_ERROR(ERR_SYSTEM_CALL, iret_sprintf);
        return GS_ERROR;
    }

    GS_RETURN_IFERR(gsc_prepare(STMT, (const char *)cmd_buf));
    GS_RETURN_IFERR(gsc_execute(STMT));

    do {
        GS_RETURN_IFERR(gsc_fetch(STMT, &rows));
        if (rows == 0) {
            break;
        }
        GS_RETURN_IFERR(gsc_column_as_string(STMT, 0, g_str_buf, GS_MAX_PACKET_SIZE));
        if (cm_list_new(tmp_tenant_list, (pointer_t *)&ptr) != GS_SUCCESS) {
            EXP_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "new tmp_tenant_list failed");
            return GS_ERROR;
        }
        MEMS_EXP_RETURN_IFERR(strncpy_s(ptr, GSQL_MAX_OBJECT_LEN, g_str_buf, GSQL_MAX_OBJECT_LEN - 1));
    } while (GS_TRUE);

    return GS_SUCCESS;
}

static inline int exp_all_tenants(void)
{
    char *tenant = NULL;
    list_t tmp_tenant_list;
    int ret;

    if (gsc_get_call_version(CONN) <= CS_VERSION_17) {
        return GS_SUCCESS;
    }

    exp_create_objlist(&tmp_tenant_list, GS_TENANT_BUFFER_SIZE);
    ret = exp_get_all_tenant(&tmp_tenant_list);
    if (ret != GS_SUCCESS) {
        cm_reset_list(&tmp_tenant_list);
        return ret;
    }

    for (uint32 i = 0; i < tmp_tenant_list.count; i++) {
        tenant = (char *)cm_list_get(&tmp_tenant_list, i);
        ret = exp_single_tenant(tenant);
        if (ret != GS_SUCCESS) {
            break;
        }
    }
    cm_reset_list(&tmp_tenant_list);
    return ret;
}

static inline int exp_prepare(export_options_t *exp_opts)
{
    uint32 size = EXP_MAX_FILE_BUF * 5;
    if (!g_export_opts.show_create_table) {
        exp_tmlog("Preparing to export ...\n");
    }
    exp_free_filebuf();
    exp_close_writer();
    exp_close_logger();
    g_exp_fbuf = (char *)malloc(size);  // modifications for exp binary files
    if (g_exp_fbuf == NULL) {
        EXP_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)EXP_MAX_FILE_BUF, "exporting file buf");
        return GS_ERROR;
    }

    MEMS_RETURN_IFERR(memset_s(g_exp_fbuf, size, 0, size));

    g_lob_fbuf = NULL;

    GS_RETURN_IFERR(exp_open_writer(exp_opts));
    GS_RETURN_IFERR(exp_open_logger(exp_opts->log_file));

    g_exp_txtbuf.str = g_exp_fbuf;
    g_exp_txtbuf.len = 0;
    g_exp_txtbuf.max_size = size;

    g_exp_lob_buff = (char *)malloc(MAX_EXP_LOB_BUFF_SIZE);  // malloc lob buffer
    if (g_exp_lob_buff == NULL) {
        EXP_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)MAX_EXP_LOB_BUFF_SIZE, "exporting lob buffer");
        return GS_ERROR;
    }

    return GSC_SUCCESS;
}

static inline int exp_print_nlsparams(void)
{
    uint32 rows;
    int iret_sprintf;
    char cmd_buf[GSQL_MAX_TEMP_SQL + 1];

    iret_sprintf = sprintf_s(cmd_buf, GSQL_MAX_TEMP_SQL,
                             "SELECT PARAMETER, VALUE "
                             "FROM " EXP_SESSION_NLS_AGENT);
    if (iret_sprintf == -1) {
        EXP_THROW_ERROR(ERR_SYSTEM_CALL, iret_sprintf);
        return GS_ERROR;
    }

    GS_RETURN_IFERR(gsc_prepare(STMT, (const char *)cmd_buf));
    GS_RETURN_IFERR(gsc_execute(STMT));

    exp_bin_reset_txtbuf();

    do {
        GS_RETURN_IFERR(gsc_fetch(STMT, &rows));
        if (rows == 0) {
            break;
        }

        /* 'show create table' option suppresses irrelevant info display */
        if (!g_export_opts.show_create_table) {
            GS_RETURN_IFERR(exp_write_str_s("ALTER SESSION SET ", &g_exp_txtbuf, g_exp_dpfile));

            GS_RETURN_IFERR(gsc_column_as_string(STMT, 0, g_str_buf, GS_MAX_PACKET_SIZE));
            exp_write_fmt(GS_FALSE, GSQL_MAX_QUOTE_NAME_SIZE, "%s = ", g_str_buf);

            GS_RETURN_IFERR(gsc_column_as_string(STMT, 1, g_str_buf, GS_MAX_PACKET_SIZE));
            exp_write_fmt(GS_FALSE, GSQL_MAX_QUOTE_NAME_SIZE, "'%s';\n", g_str_buf);
        }
    } while (GS_TRUE);
    if (!g_export_opts.show_create_table) {
        GS_RETURN_IFERR(exp_write_str_s("\n", &g_exp_txtbuf, g_exp_dpfile));
    }

    return GS_SUCCESS;
}

static inline int exp_single_trigger(export_options_t *exp_opts, const char *user, const char *trigger)
{
    uint32 rows;
    int iret_sprintf;
    char cmd_buf[GSQL_MAX_TEMP_SQL + 1];

    iret_sprintf = sprintf_s(cmd_buf, GSQL_MAX_TEMP_SQL,
                             "SELECT SOURCE "
                             "FROM " EXP_TRIGGERS_AGENT " "
                             "WHERE OWNER = UPPER(:o) AND TRIGGER_NAME = :p");
    if (iret_sprintf == -1) {
        EXP_THROW_ERROR(ERR_SYSTEM_CALL, iret_sprintf);
        return GS_ERROR;
    }

    GS_RETURN_IFERR(gsc_prepare(STMT, (const char *)cmd_buf));
    GS_RETURN_IFERR(gsc_bind_by_pos(STMT, 0, GSC_TYPE_STRING, user, (int32)strlen(user), NULL));
    GS_RETURN_IFERR(gsc_bind_by_pos(STMT, 1, GSC_TYPE_STRING, trigger, (int32)strlen(trigger), NULL));
    GS_RETURN_IFERR(gsc_execute(STMT));

    do {
        GS_RETURN_IFERR(gsc_fetch(STMT, &rows));
        if (rows == 0) {
            break;
        }

        exp_log(EXP_INDENT "exporting trigger %s\n", trigger);
        GS_RETURN_IFERR(exp_write_schema_com("CREATE OR REPLACE TRIGGER ", &g_exp_txtbuf, g_exp_dpfile));
        exp_write_schema_quote(trigger);
        GS_RETURN_IFERR(exp_write_schema_com("\n", &g_exp_txtbuf, g_exp_dpfile));

        GS_RETURN_IFERR(exp_write_schema_lob(STMT, 0, g_str_buf, CLT_LOB_BUFFER_SIZE, NULL));
        GS_RETURN_IFERR(exp_write_schema_com("\n", &g_exp_txtbuf, g_exp_dpfile));
    } while (GS_TRUE);

    return GS_SUCCESS;
}

static inline int exp_get_tbl_trigger(export_options_t *exp_opts, const char *user, const char *table,
                                      list_t *tbl_triggers)
{
    char *ptr = NULL;
    uint32 rows;
    int iret_sprintf;
    char cmd_buf[GSQL_MAX_TEMP_SQL + 1];

    iret_sprintf = sprintf_s(cmd_buf, GSQL_MAX_TEMP_SQL,
                             "SELECT TRIGGER_NAME  "
                             "FROM " EXP_TRIGGERS_AGENT " "
                             "WHERE OWNER = UPPER(:o) AND TABLE_NAME = :p "
                             "ORDER BY 1");
    if (iret_sprintf == -1) {
        EXP_THROW_ERROR(ERR_SYSTEM_CALL, iret_sprintf);
        return GS_ERROR;
    }

    GS_RETURN_IFERR(gsc_prepare(STMT, (const char *)cmd_buf));
    GS_RETURN_IFERR(gsc_bind_by_pos(STMT, 0, GSC_TYPE_STRING, user, (int32)strlen(user), NULL));
    GS_RETURN_IFERR(gsc_bind_by_pos(STMT, 1, GSC_TYPE_STRING, table, (int32)strlen(table), NULL));
    GS_RETURN_IFERR(gsc_execute(STMT));

    do {
        GS_RETURN_IFERR(gsc_fetch(STMT, &rows));
        if (rows == 0) {
            break;
        }
        GS_RETURN_IFERR(gsc_column_as_string(STMT, 0, g_str_buf, GS_MAX_PACKET_SIZE));
        if (cm_list_new(tbl_triggers, (pointer_t *)&ptr) != GS_SUCCESS) {
            return GS_ERROR;
        }
        MEMS_EXP_RETURN_IFERR(strncpy_s(ptr, GSQL_MAX_OBJECT_LEN, g_str_buf, GSQL_MAX_OBJECT_LEN - 1));
    } while (GS_TRUE);

    return GS_SUCCESS;
}

static inline int exp_tbl_trigger_scripts(export_options_t *exp_opts, const char *user, const char *table,
                                          uint32 *trigger_total)
{
    int status;
    list_t tbl_triggers;

    exp_create_objlist(&tbl_triggers, GSQL_MAX_OBJECT_LEN);
    do {
        status = exp_get_tbl_trigger(exp_opts, user, table, &tbl_triggers);
        if ((status != GS_SUCCESS) || (tbl_triggers.count == 0)) {
            break;
        }

        if (trigger_total != NULL) {
            *trigger_total += tbl_triggers.count;
        }

        // export tables of triggers
        if (tbl_triggers.count) {
            exp_tmlog("Exporting triggers of table %s ...\n", table);
        }

        for (uint32 i = 0; i < tbl_triggers.count; i++) {
            (void)exp_bin_memory_mgr_sub_begin(&exp_opts->master_bin_mgr, exp_opts->filetype);
            status = exp_single_trigger(exp_opts, user, (char *)cm_list_get(&tbl_triggers, i));
            if (status != GS_SUCCESS) {
                break;
            }

            status = exp_write_schema_com("\n", &g_exp_txtbuf, g_exp_dpfile);
            if (status != GS_SUCCESS) {
                break;
            }

            (void)exp_bin_write_int32(&g_export_opts.master_bin_mgr, EXP_OBJECT_END_FLAG);
            exp_bin_memory_mgr_sub_end(&exp_opts->master_bin_mgr, exp_opts->filetype);
        }
    } while (GS_FALSE);
    cm_reset_list(&tbl_triggers);
    return status;
}

static inline int exp_tbl_triggers(export_options_t *exp_opts, const char *user, list_t *table_list)
{
    char *tmp_table = NULL;
    uint32 *trigger_total = NULL;

    if (exp_opts->skip_triggers) {
        (void)exp_bin_write_int64(&exp_opts->master_bin_mgr, (uint64)0);
        return GS_SUCCESS;
    }

    GS_RETURN_IFERR(exp_bin_memory_mgr_begin(&exp_opts->master_bin_mgr, exp_opts->filetype));
    trigger_total = (uint32 *)exp_bin_write_int32(&exp_opts->master_bin_mgr, (uint32)0);

    for (uint32 i = 0; i < table_list->count; i++) {
        tmp_table = (char *)cm_list_get(table_list, i);
        if (exp_opts->exp_type == EXP_TABLE &&
            exp_opts->tbs_list.count > 0 &&
            GS_SUCCESS != exp_tablespace_filter(exp_opts, user, tmp_table)) {
            continue;
        }
        EXP_RETURN_IFERR(exp_tbl_trigger_scripts(exp_opts, user, tmp_table, trigger_total));
        if (g_export_opts.filetype == FT_TXT) {
            GS_RETURN_IFERR(exp_write_str_s("\n", &g_exp_txtbuf, g_exp_dpfile));
        }
    }
    exp_bin_memory_mgr_end(&exp_opts->master_bin_mgr, exp_opts->filetype);  // export bin  tables of triggers
    return GS_SUCCESS;
}

static inline int exp_get_user_triggers(export_options_t *exp_opts, const char *user, list_t *user_triggers)
{
    exp_obj_info_t *ptr = NULL;
    uint32 rows;
    char cmd_buf[GSQL_MAX_TEMP_SQL + 1];
    exp_prepare_sql_param_t param;

    param.get_proc_param.exp_opts = exp_opts;
    param.get_proc_param.user = user;
    GS_RETURN_IFERR(EXP_PREPARE_SQL(EXP_GET_USER_TRIGGERS_LIST, cmd_buf, GSQL_MAX_TEMP_SQL, &param));

    GS_RETURN_IFERR(gsc_prepare(STMT, (const char *)cmd_buf));
    GS_RETURN_IFERR(gsc_execute(STMT));

    do {
        GS_RETURN_IFERR(gsc_fetch(STMT, &rows));
        if (rows == 0) {
            break;
        }
        GS_RETURN_IFERR(gsc_column_as_string(STMT, 0, g_str_buf, GS_MAX_PACKET_SIZE));
        if (cm_list_new(user_triggers, (pointer_t *)&ptr) != GS_SUCCESS) {
            return GS_ERROR;
        }

        MEMS_RETURN_IFERR(strncpy_s(ptr->obj_name, sizeof(ptr->obj_name), g_str_buf, sizeof(ptr->obj_name) - 1));
        MEMS_RETURN_IFERR(strncpy_s(ptr->obj_type, sizeof(ptr->obj_type), "TRIGGER", strlen("TRIGGER")));
    } while (GS_TRUE);

    return GS_SUCCESS;
}

static inline int exp_user_triggers(export_options_t *exp_opts, const char *user)
{
    int status;
    list_t user_triggers;

    if (exp_opts->skip_triggers) {
        (void)exp_bin_write_int64(&exp_opts->master_bin_mgr, (uint64)0);
        return GS_SUCCESS;
    }

    GS_RETURN_IFERR(exp_bin_memory_mgr_begin(&exp_opts->master_bin_mgr, exp_opts->filetype));
    exp_create_objlist(&user_triggers, sizeof(exp_obj_info_t));
    do {
        status = exp_get_user_triggers(exp_opts, user, &user_triggers);
        if ((status != GS_SUCCESS) || (user_triggers.count == 0)) {
            (void)exp_bin_write_int32(&exp_opts->master_bin_mgr, (uint32)0);
            break;
        }

        exp_tmlog("Exporting triggers of schema %s ...\n", user);
        status = exp_prepare_proc_info();
        if (status != GS_SUCCESS) {
            break;
        }

        status = exp_proc_scripts(exp_opts, user, &user_triggers);
        if (status != GS_SUCCESS) {
            break;
        }
    } while (GS_FALSE);
    cm_reset_list(&user_triggers);
    exp_bin_memory_mgr_end(&exp_opts->master_bin_mgr, exp_opts->filetype);  // export bin  tables of all PROCEDURES
    return status;
}

static inline int exp_execute(export_options_t *exp_opts)
{
    GS_RETURN_IFERR(exp_prepare(exp_opts));

    GS_RETURN_IFERR(exp_write_head());
    /* 'show create table' option suppresses irrelevant info display */
    if (!exp_opts->show_create_table) {
        exp_print_options(exp_opts);
    }

    GS_RETURN_IFERR(exp_print_nlsparams());

    if (exp_opts->tablespace) {
        GS_RETURN_IFERR(exp_tablespace());
    }

    if (exp_opts->tenant) {
        GS_RETURN_IFERR(exp_all_tenants());
    }

    if (exp_opts->exp_role) {
        // export user roles expect system preset roles
        exp_tmlog("Exporting roles  ...\n");
        EXP_RETURN_IFERR(exp_user_role(exp_opts));

        // grant privilege to role
        exp_tmlog("Grant privilege to role ...\n");
        EXP_RETURN_IFERR(exp_grant_privilege2role(exp_opts));
    }

    GS_RETURN_IFERR(exp_bin_write_str(&exp_opts->master_bin_mgr, g_exp_txtbuf.str,
        g_exp_txtbuf.len));  // write session info to bin file
    exp_bin_reset_txtbuf();

    if (exp_opts->exp_type == EXP_TABLE) {
        GS_RETURN_IFERR(exp_check_privilege(exp_opts));
        (void)exp_bin_write_int32(&exp_opts->master_bin_mgr, (uint32)0); // set default value of schema total
        (void)exp_bin_write_int64(&exp_opts->master_bin_mgr, (uint32)0); // sequence len/total
        (void)exp_bin_write_int64(&exp_opts->master_bin_mgr, (uint64)0); // profile total len
        (void)exp_bin_write_int64(&exp_opts->master_bin_mgr, (uint64)0); // type total len
        GS_RETURN_IFERR(exp_table_scripts(exp_opts, exp_opts->schema_name, &exp_opts->exp_tables.table_list));
        GS_RETURN_IFERR(exp_tbl_triggers(exp_opts, exp_opts->schema_name, &exp_opts->exp_tables.table_list));  // fuctions/pl len/total
        (void)exp_bin_write_int64(&exp_opts->master_bin_mgr, (uint64)0); // views total len
        (void)exp_bin_write_int64(&exp_opts->master_bin_mgr, (uint64)0); // synonyms total len
        (void)exp_bin_write_int64(&exp_opts->master_bin_mgr, (uint64)0); // package total len
    } else if (exp_opts->exp_type == EXP_ALL_TABLES) {
        GS_RETURN_IFERR(exp_check_privilege(exp_opts));
        (void)exp_bin_write_int32(&exp_opts->master_bin_mgr, (uint32)0); // set default value of schema total
        (void)exp_bin_write_int64(&exp_opts->master_bin_mgr, (uint32)0); // sequence len/total
        (void)exp_bin_write_int64(&exp_opts->master_bin_mgr, (uint64)0); // profile total len
        (void)exp_bin_write_int64(&exp_opts->master_bin_mgr, (uint64)0); // type total len
        EXP_RETURN_IFERR(exp_user_tables(exp_opts, exp_opts->schema_name));
        EXP_RETURN_IFERR(exp_user_triggers(exp_opts, exp_opts->schema_name));
        (void)exp_bin_write_int64(&exp_opts->master_bin_mgr, (uint64)0); // views total len
        (void)exp_bin_write_int64(&exp_opts->master_bin_mgr, (uint64)0); // synonyms total len
        (void)exp_bin_write_int64(&exp_opts->master_bin_mgr, (uint64)0); // package total len
    } else
    if (exp_opts->exp_type == EXP_SCHEMA) {
        GS_RETURN_IFERR(exp_schema(exp_opts));
    } else {
        GS_RETURN_IFERR(exp_all_schemas(exp_opts));
    }

    /* 'show create table' option suppresses irrelevant info display */
    if ((g_exp_dpfile != NULL) && (exp_opts->filetype == FT_TXT) && !exp_opts->show_create_table) {
        exp_write_fmt(GS_FALSE, GSQL_MAX_QUOTE_NAME_SIZE, "-- end of exp: %s\n", exp_now());
    }

    return GSC_SUCCESS;
}

void exp_clear_resource(export_options_t *exp_opts)
{
    char realfile[GS_MAX_FILE_PATH_LENGH] = { 0x00 };

    if (g_exp_dpfile == NULL) {
        // if DUMP file exists , do not clear file.
        return;
    }

    if (realpath_file(exp_opts->dump_file, realfile, GS_MAX_FILE_PATH_LENGH) != GS_SUCCESS) {
        return;
    }

    if (cm_file_exist((const char *)realfile)) {
        cm_remove_file((const char *)realfile);
        return;
    }
}

status_t exp_get_current_schema(export_options_t *exp_opts)
{
    if (exp_opts->exp_type == EXP_TABLE || exp_opts->exp_type == EXP_ALL_TABLES) {
        text_t curr_schema = { exp_opts->schema_name, sizeof(exp_opts->schema_name) };
        if (gsql_get_curr_schema(&curr_schema) != GS_SUCCESS) {
            EXP_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "failed to get current schema!");
            return GS_ERROR;
        }
    }
    
    return GS_SUCCESS;
}

void exp_reset_is_myself(export_options_t *exp_opts)
{
    if (exp_opts->exp_type == EXP_TABLE || exp_opts->exp_type == EXP_ALL_TABLES) {
        exp_opts->is_myself = GS_FALSE;
        if (cm_str_equal_ins(exp_opts->schema_name, g_conn_info.username)) {
            exp_opts->is_myself = GS_TRUE;
        }
    }
}

status_t gsql_export_lex_prepare(lex_t *lex, text_t *cmd_text, uint32 *matched_id)
{
    sql_text_t sql_text;
    sql_text.value = *cmd_text;
    sql_text.loc.line = 1;
    sql_text.loc.column = 1;

    lex_trim(&sql_text);
    lex_init(lex, &sql_text);
    lex_init_keywords();

    cm_reset_error();
    EXP_RESET_ERROR;

    if (lex_expected_fetch_1of2(lex, "EXP", "EXPORT", matched_id) != GS_SUCCESS) {
        gsql_print_error(NULL);
        return GS_ERROR;
    }

    if (lex_try_fetch_1ofn(lex, matched_id, 6, "help", "usage", "option", "-h", "version", "-v") != GS_SUCCESS) {
        gsql_print_error(NULL);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t gsql_export_result_dealing(int32 status)
{
    /* 'show create table' option suppresses irrelevant info display */
    if (status != GS_SUCCESS && g_export_opts.show_create_table) {
        exp_tmlog_error(CONN);
        exp_tmlog("SHOW CREATE TABLE failed.\n");
        return status;
    }

    if (status != GSC_SUCCESS) {
        exp_tmlog("\n");
        exp_tmlog_error(CONN);
        exp_tmlog("Logical export failed.\n\n"); /* !! do not change, interface for other platform */
    } else {
        exp_tmlog("Logical export succeeded.\n\n"); /* !! do not change, interface for other platform */
    }

    exp_free(&g_export_opts);
    return status;
}

status_t gsql_export_impl(void)
{
    int status;
    uint32 prefetch_rows = 2000;

    do {
        status = exp_get_current_schema(&g_export_opts);
        GS_BREAK_IF_ERROR(status);
        exp_reset_is_myself(&g_export_opts);
        status = exp_init_conn_info(&g_export_opts);
        GS_BREAK_IF_ERROR(status);
        status = exp_init_scn(&g_export_opts);
        GS_BREAK_IF_ERROR(status);

        /* 'show create table' option suppresses irrelevant info display */
        if (!g_export_opts.show_create_table) {
            exp_tmlog("Verify options ...\n");
        }
        status = exp_verify_opts(&g_export_opts);
        GS_BREAK_IF_ERROR(status);

        // exp_execute involving memory allocation, thus the errno cannot be
        // directly returned before exp_free
        if (!g_export_opts.show_create_table) {
            exp_tmlog("Starting export ...\n");
        }
        init_exp_bin_env(&g_export_opts);
        status = gsql_set_session_interactive_mode(GS_FALSE);
        GS_BREAK_IF_ERROR(status);
        status = gsc_set_stmt_attr(STMT, GSC_ATTR_PREFETCH_ROWS, &prefetch_rows, 0);
        GS_BREAK_IF_ERROR(status);
        status = exp_execute(&g_export_opts);

        g_export_opts.exp_status = status;
        clean_exp_bin_env(&g_export_opts);
        GS_BREAK_IF_ERROR(status);
        /* reconnect to server, enable interactive check */
        status = gsql_set_session_interactive_mode(GS_TRUE);
        GS_BREAK_IF_ERROR(status);
    } while (0);

    return status;
}

status_t gsql_execute_export()
{
    uint32 num_width = 0;
    uint32 attr_len = 0;
    uint32 new_num_width = (uint32)GS_MAX_DEC_OUTPUT_ALL_PREC;
    (void)gsc_get_conn_attr(CONN, GSC_ATTR_NUM_WIDTH, &num_width, sizeof(uint32), &attr_len);
    (void)gsc_set_conn_attr(CONN, GSC_ATTR_NUM_WIDTH, &new_num_width, sizeof(uint32));

    int status = gsql_export_impl();

    (void)gsc_set_conn_attr(CONN, GSC_ATTR_NUM_WIDTH, &num_width, sizeof(uint32));
    return status;
}

status_t gsql_export(text_t *cmd_text, uint8 show_parse_info)
{
    int status;
    uint32 matched_id;
    lex_t lex;

    GS_RETURN_IFERR(gsql_export_lex_prepare(&lex, cmd_text, &matched_id));

    if (matched_id == EXP_DESC_VERSION || matched_id == EXP_DESC_HYPHEN_V) {
        gsql_display_export_version_info();
        return GS_SUCCESS;
    }

    if (matched_id != EXP_DESC_UNUSED) {
        gsql_display_export_usage();
        return GS_SUCCESS;
    }

    if (!IS_CONN) {
        GSQL_PRINTF(ZSERR_EXPORT, "connection is not established");
        return GS_ERROR;
    }

    GS_RETURN_IFERR(exp_reset_opts(&g_export_opts));

    if (show_parse_info) {
        exp_tmlog("Parsing export options ... \n");
    }

    if (exp_parse_opts(&lex, &g_export_opts) != GSC_SUCCESS) {
        status = GS_ERROR;  // the lex error is in client
    } else {
        if (!g_export_opts.show_create_table && gsql_check_tenant() != GS_SUCCESS) {
            return gsql_export_result_dealing(GS_ERROR);
        }

        status = gsql_execute_export();

        /* display create table DDL clause here when 'show create table' option is on */
        if (g_export_opts.show_create_table) {
            if (status != GS_SUCCESS) {
                exp_tmlog_error(CONN);
                exp_tmlog("SHOW CREATE TABLE failed.\n");
            } else {
                exp_tmlog("%s", g_exp_txtbuf.str);
            }
            return status;
        }

        if (g_export_opts.filetype == FT_TXT && !g_export_opts.show_create_table) {
            (void)exp_flush_s(&g_exp_txtbuf, g_exp_dpfile);
        }
    }

    gsql_export_result_dealing(status);
    if (status != GSC_SUCCESS) {
        // clear invalid DUMP file.
        exp_clear_resource(&g_export_opts);
    }
    return status;
}

status_t init_exp_cache(exp_cache_t* exp_cache, uint32 unit_cnt, exp_cache_unit_type_t root_type)
{
    GS_RETURN_IFERR(gsc_common_init_fixed_memory_pool_ex(&exp_cache->fixed_mem_pool,
        MAX_SQL_SIZE + 1, unit_cnt, EXP_MAX_TABLE_CACHE_EXT_CNT));

    exp_cache->root_unit.type = root_type;
    exp_cache->root_unit.content.str = gsc_common_alloc_fixed_buffer(&exp_cache->fixed_mem_pool);
    if (exp_cache->root_unit.content.str == NULL) {
        EXP_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)exp_cache->fixed_mem_pool.block_size, "table root cache unit");
        return GS_ERROR;
    }
    exp_cache->root_unit.content.len = 0;
    exp_cache->root_unit.max_size = exp_cache->fixed_mem_pool.block_size;
    exp_cache->record_cnt = 0;
    return GS_SUCCESS;
}

status_t alloc_exp_cache_unit(exp_cache_t* exp_cache, exp_cache_unit_type_t type, exp_cache_unit_t** unit)
{
    exp_cache_unit_t* cache_unit = NULL;
    fixed_memory_pool_t* pool = &exp_cache->fixed_mem_pool;

    if (sizeof(exp_cache_unit_t) + exp_cache->root_unit.content.len > exp_cache->root_unit.max_size) {
        EXP_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)sizeof(exp_cache_unit_t), "table cache unit");
        return GS_ERROR;
    }
    cache_unit = (exp_cache_unit_t*)(exp_cache->root_unit.content.str + exp_cache->root_unit.content.len);
    exp_cache->root_unit.content.len += sizeof(exp_cache_unit_t);

    cache_unit->content.str = gsc_common_alloc_fixed_buffer(pool);
    if (cache_unit->content.str == NULL) {
        EXP_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)pool->block_size, "table cache unit");
        return GS_ERROR;
    }
    cache_unit->content.len = 0;
    cache_unit->max_size = pool->block_size;
    cache_unit->type = type;
    exp_cache->curr_unit = cache_unit;
    *unit = cache_unit;
    return GS_SUCCESS;
}

status_t exp_start_cache_unit(exp_cache_t* exp_cache, exp_cache_unit_type_t type)
{
    return alloc_exp_cache_unit(exp_cache, type, &(exp_cache->curr_unit));
}

status_t exp_extend_cache_unit(exp_cache_t* exp_cache)
{
    return alloc_exp_cache_unit(exp_cache, exp_cache->curr_unit->type, &(exp_cache->curr_unit));
}

status_t alloc_column_cache_info(exp_cache_t* exp_cache, exp_cache_column_info_t** column_info)
{
    exp_cache_column_info_t* new_column_info = NULL;
    exp_cache_unit_t *cache_unit = NULL;
    
    if (EXP_CACHE_REMAIN_SIZE(exp_cache) < sizeof(exp_cache_column_info_t) &&
        exp_extend_cache_unit(exp_cache) != GS_SUCCESS) {
        EXP_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)sizeof(exp_cache_column_info_t), "table column info unit");
        return GS_ERROR;
    }

    cache_unit = exp_cache->curr_unit;
    new_column_info = (exp_cache_column_info_t*)(cache_unit->content.str + cache_unit->content.len);
    cache_unit->content.len += sizeof(exp_cache_column_info_t);
    *column_info = new_column_info;
    return GS_SUCCESS;
}

status_t alloc_column_subfile_info(exp_cache_t* exp_cache, char** subfile)
{
    char* new_subfile = NULL;
    exp_cache_unit_t *cache_unit = NULL;

    if (EXP_CACHE_REMAIN_SIZE(exp_cache) < EXP_MAX_SUBFILE_NAME_LEN &&
        exp_extend_cache_unit(exp_cache) != GS_SUCCESS) {
        EXP_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)EXP_MAX_SUBFILE_NAME_LEN, "table subfile info unit");
        return GS_ERROR;
    }

    cache_unit = exp_cache->curr_unit;
    new_subfile = (char*)(cache_unit->content.str + cache_unit->content.len);
    cache_unit->content.len += EXP_MAX_SUBFILE_NAME_LEN;
    *subfile = new_subfile;
    return GS_SUCCESS;
}

status_t get_exp_cache_unit(exp_cache_t* exp_cache, exp_cache_unit_type_t type, exp_cache_unit_t** unit)
{
    uint32 cache_unit_cnt = EXP_CACHE_UNIT_CNT(exp_cache);
    exp_cache_unit_t* cache_unit = NULL;
    uint32 i = 0;

    for (; i < cache_unit_cnt; i++) {
        cache_unit = EXP_CACHE_UNIT_I(exp_cache, i);
        if (cache_unit->type == type) {
            *unit = cache_unit;
            break;
        }
    }
    
    return (i == cache_unit_cnt) ? GS_ERROR : GS_SUCCESS;
}

void uninit_exp_cache(exp_cache_t* exp_cache)
{
    gsc_common_uninit_fixed_memory_pool(&exp_cache->fixed_mem_pool);
}

bool8 exp_cache_init_iterator(exp_cache_t *exp_cache, exp_cache_unit_type_t type, exp_cache_iterator_t *iter)
{
    uint32 cache_unit_cnt = EXP_CACHE_UNIT_CNT(exp_cache);
    exp_cache_unit_t* cache_unit = NULL;
    uint32 i = 0;

    iter->type = type;
    iter->idx = 0;

    for (; i < cache_unit_cnt; i++) {
        cache_unit = EXP_CACHE_UNIT_I(exp_cache, i);
        if (cache_unit->type == type) {
            break;
        }
    }

    iter->idx = i;
    return (i != cache_unit_cnt);
}

bool8 exp_cache_next_iterator(exp_cache_t *exp_cache, exp_cache_iterator_t *iter)
{
    uint32 cache_unit_cnt = EXP_CACHE_UNIT_CNT(exp_cache);
    exp_cache_unit_t* cache_unit = NULL;
    uint32 i = iter->idx + 1;

    for (; i < cache_unit_cnt; i++) {
        cache_unit = EXP_CACHE_UNIT_I(exp_cache, i);
        if (cache_unit->type == iter->type) {
            break;
        }
    }

    iter->idx = i;
    return (i != cache_unit_cnt);
}

exp_cache_unit_t* exp_cache_get_iterator(exp_cache_t *exp_cache, exp_cache_iterator_t *iter)
{
    return EXP_CACHE_UNIT_I(exp_cache, iter->idx);
}

bool8 exp_subfile_init_iterator_ex(exp_cache_t *exp_cache, exp_subfile_iterator_t *iter, uint32 unit_offset)
{
    uint32 cache_unit_cnt = EXP_CACHE_UNIT_CNT(exp_cache);
    exp_cache_unit_t* cache_unit = NULL;
    uint32 i = 0;

    iter->unit_idx = 0;
    iter->unit_offset = unit_offset;

    for (; i < cache_unit_cnt; i++) {
        cache_unit = EXP_CACHE_UNIT_I(exp_cache, i);
        if (cache_unit->type == EXP_CACHE_SUB_FILE_NAME &&
            iter->unit_offset < cache_unit->content.len) {
            break;
        }
    }

    iter->unit_idx = i;
    return (i != cache_unit_cnt);
}

bool8 exp_subfile_init_iterator(exp_cache_t *exp_cache, exp_subfile_iterator_t *iter)
{
    return exp_subfile_init_iterator_ex(exp_cache, iter, 0);
}

bool8 exp_subfile_reach_end(exp_cache_t *exp_cache, exp_subfile_iterator_t *iter)
{
    uint32 cache_unit_cnt = EXP_CACHE_UNIT_CNT(exp_cache);
    exp_cache_unit_t* cache_unit = NULL;

    for (uint32 i = 0; i < cache_unit_cnt; i++) {
        cache_unit = EXP_CACHE_UNIT_I(exp_cache, i);
        if (cache_unit->type == EXP_CACHE_SUB_FILE_NAME &&
            iter->unit_offset < cache_unit->content.len) {
            return GS_FALSE;
        }
    }
    return GS_TRUE;
}

bool8 exp_subfile_next_unit(exp_cache_t *exp_cache, exp_subfile_iterator_t *iter)
{
    uint32 cache_unit_cnt = EXP_CACHE_UNIT_CNT(exp_cache);
    exp_cache_unit_t* cache_unit = NULL;

    for (iter->unit_idx = iter->unit_idx + 1; iter->unit_idx < cache_unit_cnt; iter->unit_idx++) {
        cache_unit = EXP_CACHE_UNIT_I(exp_cache, iter->unit_idx);
        if (cache_unit->type == EXP_CACHE_SUB_FILE_NAME &&
            iter->unit_offset < cache_unit->content.len) {
            return GS_TRUE;
        }
    }
    return GS_FALSE;
}

bool8 exp_subfile_next_iterator(exp_cache_t *exp_cache, exp_subfile_iterator_t *iter)
{
    while (!exp_subfile_reach_end(exp_cache, iter)) {
        if (exp_subfile_next_unit(exp_cache, iter)) {
            return GS_TRUE;
        }
        
        if (exp_subfile_init_iterator_ex(exp_cache, iter, iter->unit_offset + EXP_MAX_SUBFILE_NAME_LEN)) {
            return GS_TRUE;
        }
    }

    return GS_FALSE;
}

char* exp_subfile_get_iterator(exp_cache_t *exp_cache, exp_subfile_iterator_t *iter)
{
    exp_cache_unit_t* cache_unit = NULL;

    cache_unit = EXP_CACHE_UNIT_I(exp_cache, iter->unit_idx);
    return cache_unit->content.str + iter->unit_offset;
}

status_t cache_unit_append_escape_str(exp_cache_unit_t* unit, const char* str, char escape)
{
    text_t text;
    cm_str2text((char *)str, &text);

    return cache_unit_append_escape_text(unit, &text, escape);
}

status_t cache_unit_append_escape_text(exp_cache_unit_t* unit, const text_t* text, char escape)
{
    uint32 need_size;
    for (uint32 i = 0; i < text->len; i++) {
        need_size = ((text->str[i] == escape) ? EXP_ESCAPE_CHAR_LEN : 1);
        if (unit->content.len + need_size > unit->max_size) {
            exp_tmlog("append %s to table cache unit failed, sql too long: %s\n", text->str, unit->content.str);
            return GS_ERROR;
        }
        CM_TEXT_APPEND(&unit->content, text->str[i]);
        if (text->str[i] == escape) {
            CM_TEXT_APPEND(&unit->content, text->str[i]);
        }
    }
    return GS_SUCCESS;
}

status_t cache_unit_append_str(exp_cache_unit_t* unit, const char* str)
{
    text_t text;
    cm_str2text((char *)str, &text);

    return cache_unit_append_text(unit, &text);
}

status_t cache_unit_append_str_quote(exp_cache_unit_t* unit, const char* str)
{
    if (g_export_opts.quote_names) {
        GS_RETURN_IFERR(cache_unit_append_str(unit, "\""));
        GS_RETURN_IFERR(cache_unit_append_str(unit, str));
        GS_RETURN_IFERR(cache_unit_append_str(unit, "\""));
    } else {
        GS_RETURN_IFERR(cache_unit_append_str(unit, str));
    }
    return GS_SUCCESS;
}

status_t exp_cache_append_str(exp_cache_t* exp_cache, const char* str)
{
    if (EXP_CACHE_REMAIN_SIZE(exp_cache) < strlen(str) &&
        exp_extend_cache_unit(exp_cache) != GS_SUCCESS) {
        exp_tmlog("append %s to table cache unit failed, sql too long: %s\n", str,
            exp_cache->curr_unit->content.str);
        return GS_ERROR;
    }

    return cache_unit_append_str(exp_cache->curr_unit, str);
}

status_t exp_cache_append_str_quote(exp_cache_t* exp_cache, const char* str)
{
    if (EXP_CACHE_REMAIN_SIZE(exp_cache) < (strlen(str) + EXP_QUOTA_LEN) &&
        exp_extend_cache_unit(exp_cache) != GS_SUCCESS) {
        exp_tmlog("append %s to table cache unit failed, sql too long: %s\n", str,
            exp_cache->curr_unit->content.str);
        return GS_ERROR;
    }

    return cache_unit_append_str_quote(exp_cache->curr_unit, str);
}

status_t exp_cache_append_text(exp_cache_t* exp_cache, const text_t* text)
{
    if (EXP_CACHE_REMAIN_SIZE(exp_cache) < text->len &&
        exp_extend_cache_unit(exp_cache) != GS_SUCCESS) {
        exp_tmlog("append %s to table cache unit failed, sql too long: %s\n", text->str,
            exp_cache->curr_unit->content.str);
        return GS_ERROR;
    }

    return cache_unit_append_text(exp_cache->curr_unit, text);
}

status_t exp_cache_append_escape_str(exp_cache_t* exp_cache, const char* str, char escape)
{
    if (EXP_CACHE_REMAIN_SIZE(exp_cache) < strlen(str) * EXP_ESCAPE_CHAR_LEN &&
        exp_extend_cache_unit(exp_cache) != GS_SUCCESS) {
        exp_tmlog("append %s to table cache unit failed, sql too long: %s\n", str,
            exp_cache->curr_unit->content.str);
        return GS_ERROR;
    }

    return cache_unit_append_escape_str(exp_cache->curr_unit, str, escape);
}

void reset_exp_cache(exp_cache_t* exp_cache)
{
    uint32 cache_unit_cnt = exp_cache->root_unit.content.len / sizeof(exp_cache_unit_t);
    exp_cache_unit_t* cache_unit = NULL;
    for (uint32 i = 0; i < cache_unit_cnt; i++) {
        cache_unit = (exp_cache_unit_t*)(exp_cache->root_unit.content.str + sizeof(exp_cache_unit_t) * i);
        gsc_common_free_fixed_buffer(&exp_cache->fixed_mem_pool, cache_unit->content.str);
    }
    exp_cache->root_unit.content.len = 0;
    exp_cache->record_cnt = 0;
}

status_t cache_unit_append_text(exp_cache_unit_t* unit, const text_t* text)
{
    if (text->len + unit->content.len > unit->max_size) {
        exp_tmlog("append %s to table cache unit failed, sql too long: %s\n", text->str, unit->content.str);
        return GS_ERROR;
    }

    cm_concat_text(&unit->content, unit->max_size, text);
    return GS_SUCCESS;
}

static status_t table_cache_write_create_table(exp_cache_t* table_cache)
{
    if (g_export_opts.content & CT_EXP_META) {
        GS_RETURN_IFERR(exp_bin_memory_mgr_sub_begin(&g_export_opts.master_bin_mgr, g_export_opts.filetype));
        GS_RETURN_IFERR(exp_cache_unit_write_file(table_cache, EXP_CACHE_CREATE_TABLE));
        exp_bin_memory_mgr_sub_end(&g_export_opts.master_bin_mgr, g_export_opts.filetype);
    } else {
        if (exp_bin_write_int32(&g_export_opts.master_bin_mgr, 0) == NULL) {
            return GS_ERROR;
        }
    }
    
    return GS_SUCCESS;
}

static status_t table_cache_write_table_name(exp_cache_t* table_cache)
{
    exp_cache_unit_t* cache_unit = NULL;

    if (g_export_opts.content & CT_EXP_DATA) {
        GS_RETURN_IFERR(get_exp_cache_unit(table_cache, EXP_CACHE_TABLE_NAME, &cache_unit));

        GS_RETURN_IFERR(exp_bin_write_shortstr(&g_export_opts.master_bin_mgr,
            cache_unit->content.str, cache_unit->content.len));
    }

    return GS_SUCCESS;
}

static status_t table_cache_write_record_cnt(exp_cache_t* table_cache)
{
    if (g_export_opts.content & CT_EXP_DATA) {
        return exp_bin_write_int64(&g_export_opts.master_bin_mgr,
            table_cache->record_cnt) == NULL ? GS_ERROR : GS_SUCCESS;
    }

    return GS_SUCCESS;
}

static status_t table_cache_write_field(exp_cache_t* table_cache)
{
    exp_cache_unit_t* cache_unit = NULL;
    uint16 column_cnt = 0;
    exp_cache_column_info_t* column_info = NULL;

    if (g_export_opts.content & CT_EXP_DATA) {
        if (get_exp_cache_unit(table_cache, EXP_CACHE_COLUMN_INFO, &cache_unit) == GS_SUCCESS) {
            column_cnt = cache_unit->content.len / (uint32)sizeof(exp_cache_column_info_t);

            // total of table fields
            if (exp_bin_write_short(&g_export_opts.master_bin_mgr, column_cnt) == NULL) {
                exp_tmlog("append column cnt failed\n");
                return GS_ERROR;
            }

            for (uint16 i = 0; i < column_cnt; i++) {
                column_info = (exp_cache_column_info_t*)(cache_unit->content.str + sizeof(exp_cache_column_info_t) * i);
                GS_RETURN_IFERR(exp_bin_write_shortstr(&g_export_opts.master_bin_mgr, column_info->name,
                    (uint16)strlen(column_info->name))); // field name
                (void)exp_bin_write_short(&g_export_opts.master_bin_mgr, column_info->type);  // field type
                (void)exp_bin_write_short(&g_export_opts.master_bin_mgr, column_info->size);  // field size
                (void)exp_bin_write_bytes(&g_export_opts.master_bin_mgr,
                    (char*)(&column_info->is_array), sizeof(uchar)); // field is_array
            }
        } else {
            if (exp_bin_write_short(&g_export_opts.master_bin_mgr, 0) == NULL) {
                exp_tmlog("append column cnt failed\n");
                return GS_ERROR;
            }
        }
    }

    return GS_SUCCESS;
}

static status_t table_cache_write_subfile(exp_cache_t* table_cache)
{
    exp_subfile_iterator_t iter;
    uint32 total_subfile_cnt = 0;
    char* total_subfile_addr = NULL;
    char* subfile = NULL;

    if (!((g_export_opts.content & CT_EXP_DATA) && exp_subfile_init_iterator(table_cache, &iter))) {
        /* set subfile number to 0 */
        if (exp_bin_write_int32(&g_export_opts.master_bin_mgr, 0) == NULL) {
            return GS_ERROR;
        }
        return GS_SUCCESS;
    }
    
    // reserved the total subfile addr
    total_subfile_addr = exp_bin_write_int32(&g_export_opts.master_bin_mgr, total_subfile_cnt);
    if (total_subfile_addr == NULL) {
        exp_tmlog("append subfile cnt failed\n");
        return GS_ERROR;
    }
    
    // write one file name of each cache unit repeated for the reason to import each dn part data
    do {
        subfile = exp_subfile_get_iterator(table_cache, &iter);
        GS_RETURN_IFERR(exp_bin_write_shortstr(&g_export_opts.master_bin_mgr,
            subfile, (uint16)strlen(subfile)));
        total_subfile_cnt++;
    } while (exp_subfile_next_iterator(table_cache, &iter));

    *(uint32 *)total_subfile_addr = total_subfile_cnt;

    return GS_SUCCESS;
}

static status_t table_cache_write_index(exp_cache_t* table_cache)
{
    exp_cache_unit_t* cache_unit = NULL;

    if ((g_export_opts.content & CT_EXP_META) &&
        get_exp_cache_unit(table_cache, EXP_CACHE_TABLE_INDEX, &cache_unit) == GS_SUCCESS &&
        cache_unit->content.len > 0) {
        (void)exp_bin_memory_mgr_sub_begin(&g_export_opts.master_bin_mgr, g_export_opts.filetype);

        GS_RETURN_IFERR(exp_bin_write_bytes(&g_export_opts.master_bin_mgr,
            cache_unit->content.str, cache_unit->content.len));

        (void)exp_bin_memory_mgr_sub_end(&g_export_opts.master_bin_mgr, g_export_opts.filetype);
    } else {
        /* set index length to 0 */
        if (exp_bin_write_int32(&g_export_opts.master_bin_mgr, 0) == NULL) {
            return GS_ERROR;
        }
    }
    return GS_SUCCESS;
}

status_t table_cache_write_file(exp_cache_t* table_cache)
{
    if (g_export_opts.filetype == FT_BIN) {
        // 1. write create table info
        GS_RETURN_IFERR(table_cache_write_create_table(table_cache));

        // 2. write table name
        GS_RETURN_IFERR(table_cache_write_table_name(table_cache));

        // 3. write record number
        GS_RETURN_IFERR(table_cache_write_record_cnt(table_cache));

        // 4. write field info
        GS_RETURN_IFERR(table_cache_write_field(table_cache));

        // 5. write subfile info
        GS_RETURN_IFERR(table_cache_write_subfile(table_cache));

        // 6. write index info
        GS_RETURN_IFERR(table_cache_write_index(table_cache));
    }
    // 7. reset table cached info
    reset_exp_cache(table_cache);
    return GS_SUCCESS;
}

status_t exp_cache_unit_write_file(exp_cache_t* exp_cache, exp_cache_unit_type_t type)
{
    exp_cache_unit_t *cache_unit = NULL;
    exp_cache_iterator_t iter;

    if (!exp_cache_init_iterator(exp_cache, type, &iter)) {
        exp_tmlog("cache unit %u not found when write file.", (uint32)type);
        return GS_ERROR;
    }

    do {
        cache_unit = exp_cache_get_iterator(exp_cache, &iter);
        if (g_export_opts.filetype == FT_BIN) {
            GS_RETURN_IFERR(exp_bin_write_bytes(&g_export_opts.master_bin_mgr,
                cache_unit->content.str, cache_unit->content.len));
        } else {
            GS_RETURN_IFERR(exp_write_text_s(&cache_unit->content, &g_exp_txtbuf, g_exp_dpfile));
        }
    } while (exp_cache_next_iterator(exp_cache, &iter));

    return GS_SUCCESS;
}

status_t view_cache_write_file(exp_cache_t* view_cache)
{
    GS_RETURN_IFERR(exp_bin_memory_mgr_sub_begin(&g_export_opts.master_bin_mgr, g_export_opts.filetype));

    // wirte head
    GS_RETURN_IFERR(exp_write_schema_com("CREATE OR REPLACE FORCE VIEW ", &g_exp_txtbuf, g_exp_dpfile));

    // write view name
    GS_RETURN_IFERR(exp_cache_unit_write_file(view_cache, EXP_CACHE_VIEW_NAME));

    // write view columns
    GS_RETURN_IFERR(exp_write_schema_com("\n", &g_exp_txtbuf, g_exp_dpfile));
    GS_RETURN_IFERR(exp_cache_unit_write_file(view_cache, EXP_CACHE_VIEW_COLUMNS));
    GS_RETURN_IFERR(exp_write_schema_com(" AS\n", &g_exp_txtbuf, g_exp_dpfile));

    // write view src
    GS_RETURN_IFERR(exp_cache_unit_write_file(view_cache, EXP_CACHE_VIEW_SRC));
    GS_RETURN_IFERR(exp_write_schema_com("\n", &g_exp_txtbuf, g_exp_dpfile));

    // write end flag
    if (g_export_opts.filetype == FT_BIN &&
        exp_bin_write_int32(&g_export_opts.master_bin_mgr, EXP_OBJECT_END_FLAG) == NULL) {
        return GS_ERROR;
    }

    exp_bin_memory_mgr_sub_end(&g_export_opts.master_bin_mgr, g_export_opts.filetype);

    // reset table cached info
    reset_exp_cache(view_cache);

    return GS_SUCCESS;
}

status_t obj_cache_write_file(exp_cache_t* obj_cache)
{
    GS_RETURN_IFERR(exp_bin_memory_mgr_sub_begin(&g_export_opts.master_bin_mgr, g_export_opts.filetype));

    // wirte head
    GS_RETURN_IFERR(exp_write_schema_com("CREATE OR REPLACE ", &g_exp_txtbuf, g_exp_dpfile));
    GS_RETURN_IFERR(exp_cache_unit_write_file(obj_cache, EXP_CACHE_OBJ_TYPE));
    GS_RETURN_IFERR(exp_write_schema_com(" ", &g_exp_txtbuf, g_exp_dpfile));

    // write obj name
    GS_RETURN_IFERR(exp_cache_unit_write_file(obj_cache, EXP_CACHE_OBJ_NAME));
    GS_RETURN_IFERR(exp_write_schema_com("\n", &g_exp_txtbuf, g_exp_dpfile));

    // write obj src
    GS_RETURN_IFERR(exp_cache_unit_write_file(obj_cache, EXP_CACHE_OBJ_SRC));
    GS_RETURN_IFERR(exp_write_schema_com("\n", &g_exp_txtbuf, g_exp_dpfile));

    // write end flag
    if (g_export_opts.filetype == FT_BIN &&
        exp_bin_write_int32(&g_export_opts.master_bin_mgr, EXP_OBJECT_END_FLAG) == NULL) {
        return GS_ERROR;
    }

    exp_bin_memory_mgr_sub_end(&g_export_opts.master_bin_mgr, g_export_opts.filetype);

    // reset table cached info
    reset_exp_cache(obj_cache);

    return GS_SUCCESS;
}

status_t table_cache_write_txt_tab_meta(exp_cache_t* table_cache)
{
    if (g_export_opts.filetype == FT_TXT) {
        GS_RETURN_IFERR(exp_cache_unit_write_file(table_cache, EXP_CACHE_CREATE_TABLE));
    }

    return GS_SUCCESS;
}

status_t table_cache_write_txt_tab_index_meta(exp_cache_t* table_cache)
{
    if (g_export_opts.filetype == FT_TXT) {
        GS_RETURN_IFERR(exp_cache_unit_write_file(table_cache, EXP_CACHE_TABLE_INDEX));
    }

    return GS_SUCCESS;
}
