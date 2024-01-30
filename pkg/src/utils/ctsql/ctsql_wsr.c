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
 * ctsql_wsr.c
 *
 *
 * IDENTIFICATION
 * src/utils/ctsql/ctsql_wsr.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctsql_wsr.h"
#include "cm_base.h"
#include "cm_lex.h"
#include "cm_log.h"
#include "cm_utils.h"
#include "cm_utils.h"
#include "ctsql_common.h"
#include "ctsql_export.h"
#include "ctsql_wsr_head.h"
#include "ctsql_wsr_snap.h"
#include "ctsql_wsr_session.h"
#include "ctsql_wsr_sql.h"
#include "ctsql_wsr_segment.h"
#include "ctsql_wsr_parameter.h"
#include "ctsql_wsr_analyse.h"
#include "ctsql_wsr_buffer.h"

#define CT_WSR_SQL_PREFIX_6    6
#define CT_WSR_SQL_PREFIX_10   10
#define CT_WSR_SQL_PREFIX_15   15
#define CT_WSR_SQL_PREFIX_20   20
#define CT_WSR_SQL_PREFIX_30   30

static list_t g_wsr_shd_node;
char g_wsr_report_path[CT_MAX_FILE_PATH_LENGH];
FILE *g_wsr_report_summary_fp = NULL;

void wsr_print_shd_err(ctconn_conn_t wsr_conn, char *node_name)
{
    if (node_name != NULL) {
        ctsql_print_error(wsr_conn);
        ctsql_printf("WSR Report Build failed,node name %s.\n", node_name);
    } else {
        ctsql_print_error(wsr_conn);
        ctsql_printf("WSR Report Build failed.\n");
    }
}

void wsr_print_shd_succ(const char *node_name, const wsr_options_t *wsr_opts)
{
    if (node_name != NULL) {
        ctsql_printf("WSR report node %s success \n", node_name);
    } else {
        ctsql_printf("WSR report Generation Success.\n\n");
        ctsql_printf("WSR report file name : %s\n", wsr_opts->file_name);
    }
}

void ctsql_display_wsr_usage(void)
{
    ctsql_printf("The syntax of generating a WSR report is as follows: \n\n");
    ctsql_printf("     Format:  WSR snap_id1 snap_id2 \"FILENAME\" [ shard ] \n");
    ctsql_printf("     Format:  WSR starttime endtime \"FILENAME\" \n");
    ctsql_printf("              snap_id1 and snap_id2 indicate the IDs of the start and end snapshots,"
        " respectively. FILENAME is optional.\n");
    ctsql_printf("              If no snapshot is generated, you can specify the start time and end time"
        " to generate the report. The time format is yyyy-mm-dd hh24:mi:ss.\n");
    ctsql_printf("              You can use the command with shard to collect the WSR information of cluster, "
        "but only support on CN node.\n");
    ctsql_printf("              You can create a snapshot using the SYS.WSR$CREATE_SNAPSHOT stored "
        "procedure and obtain snapshot IDs from the adm_hist_snapshot system view.\n");
    ctsql_printf("              You can also create a global snapshot to the whole cluster through the "
        "WSR CREATE_GLOBAL_SNAPSHOT command, but only support on CN node.\n");
    ctsql_printf("              You can drop snapshots using the WSR$DROP_SNAPSHOT_RANGE stored procedure and "
        "obtain the latest 20 snapshot IDs by running the WSR list command.\n");
    ctsql_printf("     Example1: WSR 10 20\n");
    ctsql_printf("     Use snapshot 10 and snapshot 20 to generate a report, with a default report name.\n");
    ctsql_printf("     Example2: WSR 10 20 \"e:\\wsr.html\"\n");
    ctsql_printf("     Use snapshot 10 and snapshot 20 to generate a report, with a specified report name.\n");
    ctsql_printf("     Example3: WSR list\n");
    ctsql_printf("     Obtain information about the latest 20 snapshots.\n");
    ctsql_printf("     Example4: WSR list 50\n");
    ctsql_printf("     Obtain information about the latest 50 snapshots.\n");
    ctsql_printf("     Example5: CALL WSR$CREATE_SNAPSHOT;\n");
    ctsql_printf("     Create a snapshot.\n");
    ctsql_printf("     Example6: CALL WSR$DROP_SNAPSHOT_RANGE(10, 20);\n");
    ctsql_printf("     Drop snapshots from snapshot 10 to snapshot 20.\n");
    ctsql_printf("     Example7: WSR CREATE_GLOBAL_SNAPSHOT\n");
    ctsql_printf("     Create a golbal snapshot.\n");
    ctsql_printf("     Example8: wsr \"2021-06-16 10:00:00\" \"2021-06-16 10:10:00\"\n");
    ctsql_printf("     Specify the start time and end time to generate the report.\n");
    ctsql_printf("Note: For WSR, the values of the SQL_STAT and TIMED_STATS system parameters are true.\n");
    ctsql_printf("\n");
}

status_t wsr_show_snapid(uint32 listNum)
{
    uint32 rows;
    int iret_sprintf;
    char cmd_buf[CTSQL_MAX_TEMP_SQL + 1];

    iret_sprintf = sprintf_s(cmd_buf, CTSQL_MAX_TEMP_SQL,
                             "SELECT LPAD(SNAP_ID, 15, ' '), TO_CHAR(SNAP_TIME, 'YYYY-MM-DD HH24:MI:SS'), "
                             "TO_CHAR(STARTUP_TIME, 'YYYY-MM-DD HH24:MI:SS') "
                             "FROM ADM_HIST_SNAPSHOT ORDER BY SNAP_ID DESC LIMIT %u", listNum);
    if (iret_sprintf == -1) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, iret_sprintf);
        return CT_ERROR;
    }

    CT_RETURN_IFERR(ctconn_prepare(STMT, (const char *)cmd_buf));
    CT_RETURN_IFERR(ctconn_execute(STMT));

    ctsql_printf("Listing the lastest Completed Snapshots\n\n");
    ctsql_printf("    Snap Id          Snap Started      DB_startup_time\n");
    ctsql_printf("---------------  -------------------  ------------------\n");

    do {
        CT_RETURN_IFERR(ctconn_fetch(STMT, &rows));
        if (rows == 0) {
            break;
        }

        CT_RETURN_IFERR(ctconn_column_as_string(STMT, 0, g_str_buf, WSR_MAX_RECEV_LEN));
        ctsql_printf("%s", g_str_buf);
        ctsql_printf("  ");
        CT_RETURN_IFERR(ctconn_column_as_string(STMT, 1, g_str_buf, WSR_MAX_RECEV_LEN));
        ctsql_printf("%s", g_str_buf);
        ctsql_printf("  ");
        CT_RETURN_IFERR(ctconn_column_as_string(STMT, 2, g_str_buf, WSR_MAX_RECEV_LEN));
        ctsql_printf("%s", g_str_buf);
        ctsql_printf("\n");
    } while (CT_TRUE);
    ctsql_printf("\n");

    return CTCONN_SUCCESS;
}
static status_t ctsql_get_wsr_base_info(lex_t *lex, wsr_options_t *wsr_opts, wsr_info_t *wsr_info)
{
    uint32 rows;
    uint32 *data = NULL;
    bool32 is_null = CT_FALSE;
    uint32 size;
    errno_t errcode;
    char cmd_buf[MAX_CMD_LEN + 1];
    char str_buf[WSR_MAX_RECEV_LEN + 1];
    
    PRTS_RETURN_IFERR(sprintf_s(cmd_buf, MAX_CMD_LEN,
        "SELECT TO_CHAR(SNAP_TIME, 'YYYY-MM-DD HH24:MI:SS'), CAST(SESSIONS AS BINARY_INTEGER),"
        " CAST (CURSORS AS BINARY_INTEGER),"
        "CAST(to_number(TO_DATE((to_char(sysdate, 'yyyy-mm-dd hh24:mi:ss')),'yyyy-mm-dd hh24:mi:ss')"
        " - TO_DATE(to_char(SNAP_TIME, 'yyyy-mm-dd hh24:mi:ss'),'yyyy-mm-dd hh24:mi:ss'))* 86400 AS BINARY_INTEGER) "
        " FROM ADM_HIST_SNAPSHOT WHERE SNAP_ID = %u",
        wsr_opts->start_snap_id));

    CT_RETURN_IFERR(ctconn_prepare(wsr_opts->curr_stmt, (const char *)cmd_buf));
    CT_RETURN_IFERR(ctconn_execute(wsr_opts->curr_stmt));

    CT_RETURN_IFERR(ctconn_fetch(wsr_opts->curr_stmt, &rows));
    if (rows == 0) {
        CT_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "start_snap_id doesn't exist!");
        return CT_ERROR;
    }

    CT_RETURN_IFERR(ctconn_column_as_string(wsr_opts->curr_stmt, 0, str_buf, WSR_MAX_RECEV_LEN));
    errcode = strncpy_s(wsr_info->start_time, MAX_WSR_DATE_LEN, str_buf, WSR_MAX_RECEV_LEN);
    if (errcode != EOK) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
        return CT_ERROR;
    }

    if (ctconn_get_column_by_id(wsr_opts->curr_stmt, 1, (void **)&data, &size, &is_null) != CT_SUCCESS) {
        ctsql_print_error(wsr_opts->curr_conn);
        return CTCONN_ERROR;
    }

    wsr_info->start_sessions = is_null ? 0 : *data;

    CT_RETURN_IFERR(ctconn_column_as_string(wsr_opts->curr_stmt, 2, str_buf, WSR_MAX_RECEV_LEN));

    if (ctconn_get_column_by_id(wsr_opts->curr_stmt, 2, (void **)&data, &size, &is_null) != CT_SUCCESS) {
        ctsql_print_error(wsr_opts->curr_conn);
        return CTCONN_ERROR;
    }
    wsr_info->start_cursors = is_null ? 0 : *data;

    if (ctconn_get_column_by_id(wsr_opts->curr_stmt, 3, (void **)&data, &size, &is_null) != CT_SUCCESS) {
        ctsql_print_error(wsr_opts->curr_conn);
        return CTCONN_ERROR;
    }
    wsr_info->shd_start_timesapce = is_null ? 0 : *data;
    
    PRTS_RETURN_IFERR(sprintf_s(cmd_buf, MAX_CMD_LEN,
        "SELECT TO_CHAR(SNAP_TIME, 'YYYY-MM-DD HH24:MI:SS'), CAST (SESSIONS AS BINARY_INTEGER), "
        "CAST(CURSORS AS BINARY_INTEGER),"
        "CAST (to_number(TO_DATE((to_char(sysdate, 'yyyy-mm-dd hh24:mi:ss')),'yyyy-mm-dd hh24:mi:ss')"
        " -TO_DATE(to_char(SNAP_TIME, 'yyyy-mm-dd hh24:mi:ss'),'yyyy-mm-dd hh24:mi:ss'))* 86400 AS BINARY_INTEGER) "
        "FROM ADM_HIST_SNAPSHOT WHERE SNAP_ID = %u",
        wsr_opts->end_snap_id));

    CT_RETURN_IFERR(ctconn_prepare(wsr_opts->curr_stmt, (const char *)cmd_buf));
    CT_RETURN_IFERR(ctconn_execute(wsr_opts->curr_stmt));

    CT_RETURN_IFERR(ctconn_fetch(wsr_opts->curr_stmt, &rows));
    if (rows == 0) {
        CT_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "end_snap_id doesn't exist!");
        return CT_ERROR;
    }

    CT_RETURN_IFERR(ctconn_column_as_string(wsr_opts->curr_stmt, 0, str_buf, WSR_MAX_RECEV_LEN));
    MEMS_RETURN_IFERR(strncpy_s(wsr_info->end_time, MAX_WSR_DATE_LEN, str_buf, WSR_MAX_RECEV_LEN));

    if (ctconn_get_column_by_id(wsr_opts->curr_stmt, 1, (void **)&data, &size, &is_null) != CT_SUCCESS) {
        ctsql_print_error(wsr_opts->curr_conn);
        return CTCONN_ERROR;
    }

    wsr_info->end_sessions = is_null ? 0 : *data;

    CT_RETURN_IFERR(ctconn_column_as_string(wsr_opts->curr_stmt, 2, str_buf, WSR_MAX_RECEV_LEN));

    if (ctconn_get_column_by_id(wsr_opts->curr_stmt, 2, (void **)&data, &size, &is_null) != CT_SUCCESS) {
        ctsql_print_error(wsr_opts->curr_conn);
        return CTCONN_ERROR;
    }
    wsr_info->end_cursors = is_null ? 0 : *data;
    
    if (ctconn_get_column_by_id(wsr_opts->curr_stmt, 3, (void **)&data, &size, &is_null) != CT_SUCCESS) {
        ctsql_print_error(wsr_opts->curr_conn);
        return CTCONN_ERROR;
    }
    wsr_info->shd_end_timesapce = is_null ? 0 : *data;
    return CTCONN_SUCCESS;
}

static status_t wsr_parse_opts_check(lex_t *lex, wsr_options_t *wsr_opts, wsr_info_t *wsr_info)
{
    char cmd_buf[MAX_CMD_LEN + 1];
    char *data = NULL;
    unsigned int size;
    unsigned int is_null;
    unsigned int row;
    int i_result;

    PRTS_RETURN_IFERR(sprintf_s(cmd_buf, MAX_CMD_LEN, "CALL SYS.WSR$INSTANCE_SNAP_CHECKPARA('%s', '%s', :p1)",
        wsr_info->start_time, wsr_info->end_time));

    CT_RETURN_IFERR(ctconn_prepare(wsr_opts->curr_stmt, (const char *)cmd_buf));
    CT_RETURN_IFERR(ctconn_bind_by_pos2(wsr_opts->curr_stmt, 0, CTCONN_TYPE_INTEGER, (void *)&i_result,
        sizeof(int32), NULL, CTCONN_OUTPUT));
    CT_RETURN_IFERR(ctconn_execute(wsr_opts->curr_stmt));
    CT_RETURN_IFERR(ctconn_fetch_outparam(wsr_opts->curr_stmt, &row));
    CT_RETURN_IFERR(ctconn_get_outparam_by_id(wsr_opts->curr_stmt, 0, (void **)&data, &size, &is_null));

    i_result = *(int *)data;

    if (i_result == 1) {
        CT_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "invaid input!");
        return CT_ERROR;
    } else if (i_result == 2) {
        CT_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "STARTTIME should be lower than ENDTIME!");
        return CT_ERROR;
    }

    return CTCONN_SUCCESS;
}

static status_t wsr_parse_opts_filename(lex_t *lex, wsr_options_t *wsr_opts, wsr_info_t *wsr_info)
{
    char dump_file[CT_MAX_FILE_PATH_LENGH];
    wsr_opts->switch_shd_off = CT_FALSE;
    g_wsr_report_path[0] = '\0';
    word_t word;
    clt_stmt_t *stmt = (clt_stmt_t *)STMT;

    if (lex->curr_text->len == 0) {
        PRTS_RETURN_IFERR(snprintf_s(wsr_opts->file_name, CT_MAX_FILE_NAME_LEN, CT_MAX_FILE_NAME_LEN - 1,
            "wsrrpt_%u_%u.html", wsr_opts->start_snap_id, wsr_opts->end_snap_id));
    } else {
        if (lex_expected_fetch_enclosed_string(lex, &word) != CT_SUCCESS) {
            CT_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "use double quotes for FILENAME");
            return CT_ERROR;
        }

        CT_RETURN_IFERR(cm_text2str(&word.text.value, dump_file, CT_MAX_FILE_PATH_LENGH));
        cm_trim_filename(dump_file, CT_MAX_FILE_PATH_LENGH, g_wsr_report_path);
        cm_trim_dir((const char *)dump_file, CT_MAX_FILE_NAME_LEN, wsr_opts->file_name);
        if (strcmp(wsr_opts->file_name, g_wsr_report_path) == 0) {
            g_wsr_report_path[0] = '\0';
        }
    }

    if (lex->curr_text->len == 0) {
        return CTCONN_SUCCESS;
    }

    if (!cm_text_str_equal_ins(&word.text.value, "shard")) {
        CT_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "Wrong input!");
        return CT_ERROR;
    }

    if (stmt->conn->node_type != CS_TYPE_CN) {
        CT_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "This command only support in the CN nodes.");
        return CT_ERROR;
    }

    wsr_opts->switch_shd_off = CT_TRUE;

    MEMS_RETURN_IFERR(strcpy_s(dump_file, CT_MAX_FILE_PATH_LENGH, g_wsr_report_path));
    MEMS_RETURN_IFERR(strcat_s(dump_file, CT_MAX_FILE_PATH_LENGH, "WsrDetails/"));
    if (!cm_dir_exist((const char *)dump_file)) {
        if (cm_create_dir((const char *)dump_file) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CTCONN_SUCCESS;
}

static status_t wsr_parse_opts(lex_t *lex, wsr_options_t *wsr_opts, wsr_info_t *wsr_info)
{
    word_t word;
    clt_stmt_t *stmt = (clt_stmt_t *)STMT;
    wsr_opts->start_snap_id = 0;
    wsr_opts->end_snap_id = 0;
    wsr_info->start_time[0] = '\0';
    wsr_info->end_time[0] = '\0';
    wsr_opts->curr_conn = CONN;
    wsr_opts->curr_stmt = STMT;

    CTCONN_CHECK_OBJECT_NULL_GS(stmt, "statement");
    if (lex_expected_fetch_uint32(lex, &wsr_opts->start_snap_id) != CT_SUCCESS) {
        if (lex_expected_fetch_enclosed_string(lex, &word) != CT_SUCCESS) {
            CT_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "use double quotes for STARTTIME!");
            return CT_ERROR;
        } else {
            wsr_opts->input_snap_id = CT_FALSE;
        }

        CT_RETURN_IFERR(cm_text2str(&word.text.value, (char *)wsr_info->start_time, CT_MAX_PARAM_LEN));
    } else {
        wsr_opts->input_snap_id = CT_TRUE;
    }

    if (wsr_opts->input_snap_id) {
        if (lex_expected_fetch_uint32(lex, &wsr_opts->end_snap_id) != CT_SUCCESS) {
            CT_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "invaid input!");
            return CT_ERROR;
        }

        if (wsr_opts->start_snap_id >= wsr_opts->end_snap_id) {
            CT_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "start_snap_id is greater than end_snap_id!");
            return CT_ERROR;
        }
    } else {
        if (lex_expected_fetch_enclosed_string(lex, &word) != CT_SUCCESS) {
            CT_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "use double quotes for ENDTIME!");
            return CT_ERROR;
        }
        CT_RETURN_IFERR(cm_text2str(&word.text.value, (char *)wsr_info->end_time, CT_MAX_PARAM_LEN));
        CT_RETURN_IFERR(wsr_parse_opts_check(lex, wsr_opts, wsr_info));
    }

    CT_RETURN_IFERR(wsr_parse_opts_filename(lex, wsr_opts, wsr_info));

    if (wsr_opts->input_snap_id) {
        CT_RETURN_IFERR(ctsql_get_wsr_base_info(lex, wsr_opts, wsr_info));
    }

    return CTCONN_SUCCESS;
}

static int wsr_open_writer(wsr_options_t *wsr_opts)
{
    char wsr_file_path[CT_MAX_FILE_PATH_LENGH];
    char dump_path[CT_MAX_FILE_PATH_LENGH] = { 0x00 };
    
    if (wsr_opts->file_name == NULL || cm_str_equal_ins(wsr_opts->file_name, "stdout")) {
        wsr_opts->wsr_dpfile = NULL;  // null for write the content into cmd
        return CTCONN_SUCCESS;
    }

    if (strlen(g_wsr_report_path) > 0 && !cm_dir_exist(g_wsr_report_path)) {
        CT_THROW_ERROR(ERR_PATH_NOT_EXIST, g_wsr_report_path);
        return CT_ERROR;
    }

    if (wsr_opts->file_name[0] == '\0') {
        CT_THROW_ERROR(ERR_CLT_INVALID_ATTR, "file name", wsr_opts->file_name);
        return CT_ERROR;
    }

    MEMS_RETURN_IFERR(strcpy_s(wsr_file_path, CT_MAX_FILE_PATH_LENGH, g_wsr_report_path));
    if (wsr_opts->switch_shd_off == CT_TRUE) {
        MEMS_RETURN_IFERR(strcat_s(wsr_file_path, CT_MAX_FILE_PATH_LENGH, "WsrDetails/"));
    }
    MEMS_RETURN_IFERR(strcat_s(wsr_file_path, CT_MAX_FILE_PATH_LENGH, wsr_opts->file_name));
    
    // open file
    CT_RETURN_IFERR(realpath_file(wsr_file_path, dump_path, CT_MAX_FILE_PATH_LENGH));
    wsr_opts->wsr_dpfile = fopen(dump_path, "w+");
    if (wsr_opts->wsr_dpfile == NULL) {
        CT_THROW_ERROR(ERR_OPEN_FILE, dump_path, errno);
        return CT_ERROR;
    }

    if (cm_fchmod(FILE_MODE_OF_WSR, wsr_opts->wsr_dpfile) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CTCONN_SUCCESS;
}

static void wsr_close_writer(wsr_options_t *wsr_opts)
{
    if (wsr_opts->wsr_dpfile != NULL) {
        fclose(wsr_opts->wsr_dpfile);
        wsr_opts->wsr_dpfile = NULL;
    }
}

/* force the text in file buf into file */
static inline void wsr_flush(wsr_options_t *wsr_opts)
{
    if (!CM_IS_EMPTY(&wsr_opts->wsr_txtbuf)) {
        wsr_writer(wsr_opts, wsr_opts->wsr_txtbuf.str, wsr_opts->wsr_txtbuf.len);
        wsr_opts->wsr_txtbuf.len = 0;
    }
}

static inline void wsr_free_filebuf(wsr_options_t *wsr_opts)
{
    if (wsr_opts->wsr_fbuf != NULL) {
        free(wsr_opts->wsr_fbuf);
        wsr_opts->wsr_fbuf = NULL;
    }
}

static inline void wsr_free(wsr_options_t *wsr_opts)
{
    wsr_close_writer(wsr_opts);
    wsr_free_filebuf(wsr_opts);
}

static void wsr_write_str3(const char *str)
{
    if (g_wsr_report_summary_fp == NULL) {
        return;
    }

    (void)fwrite(str, 1, strlen(str), g_wsr_report_summary_fp);
    (void)fwrite("\n", 1, strlen("\n"), g_wsr_report_summary_fp);
}

static void wsr_write_fmt3(uint32 max_fmt_sz, const char *fmt, ...)
{
    int32 len;
    va_list var_list;
    va_start(var_list, fmt);
    char sql_buf[MAX_SQL_SIZE_WSR + 4];

    len = vsnprintf_s(sql_buf, MAX_SQL_SIZE_WSR, max_fmt_sz, fmt, var_list);
    va_end(var_list);
    if (len < 0) {
        ctsql_printf("Copy var_list to EXP_FMT_BUFER failed under using wsr tool.\n");
        return;
    }
    wsr_write_str3(sql_buf);
}

static inline int wsr_prepare(wsr_options_t *wsr_opts, const char *node_name)
{
    int len;
    char *html = ".html";
    int html_len = (int)strlen(html);
    
    wsr_opts->wsr_fbuf = (char *)malloc(WSR_MAX_FILE_BUF);
    if (wsr_opts->wsr_fbuf == NULL) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)WSR_MAX_FILE_BUF, "exporting file buf");
        return CT_ERROR;
    }

    len = (int)strlen(wsr_opts->file_name);
    if (wsr_opts->switch_shd_off && node_name != NULL && len > html_len) {
        if (strstr(wsr_opts->file_name, html) != NULL) {
            wsr_opts->file_name[len - html_len] = '\0';
            MEMS_RETURN_IFERR(strcat_s(wsr_opts->file_name, CT_MAX_FILE_NAME_LEN, "_"));
            MEMS_RETURN_IFERR(strcat_s(wsr_opts->file_name, CT_MAX_FILE_NAME_LEN, node_name));
            MEMS_RETURN_IFERR(strcat_s(wsr_opts->file_name, CT_MAX_FILE_NAME_LEN, html));
        } else {
            MEMS_RETURN_IFERR(strcat_s(wsr_opts->file_name, CT_MAX_FILE_NAME_LEN, "_"));
            MEMS_RETURN_IFERR(strcat_s(wsr_opts->file_name, CT_MAX_FILE_NAME_LEN, node_name));
        }
    }

    CT_RETURN_IFERR(wsr_open_writer(wsr_opts));

    wsr_opts->wsr_txtbuf.str = wsr_opts->wsr_fbuf;
    wsr_opts->wsr_txtbuf.len = 0;
    wsr_opts->wsr_txtbuf.max_size = WSR_MAX_FILE_BUF;

    return CTCONN_SUCCESS;
}

static int wsr_build_report(wsr_options_t *wsr_opts, wsr_info_t *wsr_info, char *node_name)
{
    CT_RETURN_IFERR(wsr_prepare(wsr_opts, node_name));
    CT_RETURN_IFERR(wsr_get_dbinfo(wsr_opts, wsr_info));

    if (wsr_opts->input_snap_id) {
        CT_RETURN_IFERR(wsr_build_wsr_info_t(wsr_opts, wsr_info));
    }

    CT_RETURN_IFERR(wsr_build_header(wsr_opts, wsr_info));

    if (wsr_opts->input_snap_id) {
        CT_RETURN_IFERR(wsr_build_load_profile(wsr_opts, wsr_info));
        CT_RETURN_IFERR(wsr_build_efficiency(wsr_opts, wsr_info));
        CT_RETURN_IFERR(wsr_build_top_events(wsr_opts, wsr_info));
        CT_RETURN_IFERR(wsr_build_host_cpu(wsr_opts, wsr_info));
        CT_RETURN_IFERR(wsr_build_host_mem(wsr_opts, wsr_info));
    }

    CT_RETURN_IFERR(wsr_build_instance_snap(wsr_opts, wsr_info));
    CT_RETURN_IFERR(wsr_build_instance_buffer(wsr_opts, wsr_info));

    if (wsr_opts->input_snap_id) {
        CT_RETURN_IFERR(wsr_build_top_session(wsr_opts, wsr_info));
    }

    CT_RETURN_IFERR(wsr_build_top_session_sql(wsr_opts, wsr_info));
    CT_RETURN_IFERR(wsr_build_top_session_trans(wsr_opts, wsr_info));

    if (wsr_opts->input_snap_id) {
        CT_RETURN_IFERR(wsr_build_top_session_cursors_start(wsr_opts, wsr_info));
        CT_RETURN_IFERR(wsr_build_top_session_cursors_end(wsr_opts, wsr_info));
    }

    if (wsr_opts->input_snap_id) {
        CT_RETURN_IFERR(wsr_build_sql_elapsed(wsr_opts, wsr_info));
        CT_RETURN_IFERR(wsr_build_longsql_time(wsr_opts, wsr_info));
        CT_RETURN_IFERR(wsr_build_cpu_time(wsr_opts, wsr_info));
        CT_RETURN_IFERR(wsr_build_io_wait(wsr_opts, wsr_info));
        CT_RETURN_IFERR(wsr_build_sql_gets(wsr_opts, wsr_info));
        CT_RETURN_IFERR(wsr_build_sql_reads(wsr_opts, wsr_info));
        CT_RETURN_IFERR(wsr_build_sql_executions(wsr_opts, wsr_info));
        CT_RETURN_IFERR(wsr_build_sql_parses(wsr_opts, wsr_info));
        CT_RETURN_IFERR(wsr_build_sql_first_letters(wsr_opts, wsr_info, CT_WSR_SQL_PREFIX_6));
        CT_RETURN_IFERR(wsr_build_sql_first_letters(wsr_opts, wsr_info, CT_WSR_SQL_PREFIX_10));
        CT_RETURN_IFERR(wsr_build_sql_first_letters(wsr_opts, wsr_info, CT_WSR_SQL_PREFIX_15));
        CT_RETURN_IFERR(wsr_build_sql_first_letters(wsr_opts, wsr_info, CT_WSR_SQL_PREFIX_20));
        CT_RETURN_IFERR(wsr_build_sql_first_letters(wsr_opts, wsr_info, CT_WSR_SQL_PREFIX_30));
        CT_RETURN_IFERR(wsr_build_long_sql_first_letters(wsr_opts, wsr_info, CT_WSR_SQL_PREFIX_15));
        CT_RETURN_IFERR(wsr_build_long_sql_first_letters(wsr_opts, wsr_info, CT_WSR_SQL_PREFIX_30));
    }
    CT_RETURN_IFERR(wsr_build_sql_content(wsr_opts, wsr_info));

    if (wsr_opts->input_snap_id) {
        CT_RETURN_IFERR(wsr_build_segment_stat(wsr_opts, wsr_info));
        CT_RETURN_IFERR(wsr_build_report_summary(wsr_opts, wsr_info));
        CT_RETURN_IFERR(wsr_build_parameter(wsr_opts, wsr_info));
    }
    return CTCONN_SUCCESS;
}

status_t wsr_check_parameter(wsr_options_t *wsr_opts)
{
    uint32 rows;
    char cmd_buf[MAX_CMD_LEN + 1];
    char str_buf[WSR_MAX_RECEV_LEN + 1];
    
    PRTS_RETURN_IFERR(sprintf_s(cmd_buf, MAX_CMD_LEN,
        "SELECT COUNT(*) FROM DV_PARAMETERS WHERE NAME IN ('SQL_STAT', 'TIMED_STATS') AND UPPER(VALUE) = 'TRUE' "));

    CT_RETURN_IFERR(ctconn_prepare(wsr_opts->curr_stmt, (const char *)cmd_buf));
    CT_RETURN_IFERR(ctconn_execute(wsr_opts->curr_stmt));

    CT_RETURN_IFERR(ctconn_fetch(wsr_opts->curr_stmt, &rows));

    if (rows == 0) {
        return CT_ERROR;
    }

    CT_RETURN_IFERR(ctconn_column_as_string(wsr_opts->curr_stmt, 0, str_buf, WSR_MAX_RECEV_LEN));

    if (str_buf[0] != '2') {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "SQL_STAT and TIMED_STATS should be true");
        return CT_ERROR;
    }

    return CTCONN_SUCCESS;
}

void wsr_free_node_info(void)
{
    uint32 num;
    wsr_shd_info_t *node_info = NULL;
    
    for (num = 0; num < g_wsr_shd_node.count; num++) {
        node_info = (wsr_shd_info_t *)cm_list_get(&g_wsr_shd_node, num);
        if (node_info->node_conn.stmt != NULL) {
            ctconn_free_stmt(node_info->node_conn.stmt);
        }
        
        if (node_info->node_conn.conn != NULL) {
            ctconn_disconnect(node_info->node_conn.conn);
            ctconn_free_conn(node_info->node_conn.conn);
        }
    }
    
    cm_reset_list(&g_wsr_shd_node);
}

static status_t wsr_save_conn_info(wsr_shd_info_t *node_info)
{
    uint32_t total_len = 0;
    char str_buf[WSR_MAX_RECEV_LEN + 1];
    // node_name
    CT_RETURN_IFERR(ctconn_column_as_string(STMT, 0, str_buf, WSR_MAX_RECEV_LEN));
    MEMS_RETURN_IFERR(strncpy_s(node_info->node_name, (size_t)WSR_MAX_NODE_NAME, str_buf, strlen(str_buf)));
    
    // host
    CT_RETURN_IFERR(ctconn_column_as_string(STMT, 1, str_buf, WSR_MAX_RECEV_LEN));
    MEMS_RETURN_IFERR(strncpy_s(node_info->node_conn.server_url,
        (size_t)(CM_UNIX_DOMAIN_PATH_LEN + 4UL), str_buf, strlen(str_buf)));
    total_len += (uint32_t)strlen(str_buf);

    // add colon format ':'
    node_info->node_conn.server_url[total_len] = ':';
    total_len += 1;

    // port
    CT_RETURN_IFERR(ctconn_column_as_string(STMT, 2, str_buf, WSR_MAX_RECEV_LEN));

    MEMS_RETURN_IFERR(strncpy_s(node_info->node_conn.server_url + total_len,
        (size_t)(CM_UNIX_DOMAIN_PATH_LEN + 4UL - total_len), str_buf, strlen(str_buf)));
    
    return CT_SUCCESS;
}

static status_t wsr_node_save_conn_info(wsr_shd_info_t *node_info)
{
    // get url
    CT_RETURN_IFERR(wsr_save_conn_info(node_info));

    // get user
    ctsql_get_saved_user(node_info->node_conn.username, CT_NAME_BUFFER_SIZE + CT_STR_RESERVED_LEN);

    if (par_exp_create_dn_connectdb(&node_info->node_conn, CT_TRUE) != CT_SUCCESS) {
        (void)exp_clean_pwd_info(&node_info->node_conn);
        return CT_ERROR;
    }
    
    // clean the pwd info
    return exp_clean_pwd_info(&node_info->node_conn);
}
static status_t wsr_init_node_conn_info(list_t *shd_node_list)
{
    uint32 rows;
    char cmd_buf[MAX_CMD_LEN + 1];
    wsr_shd_info_t *node_info = NULL;
    
    PRTS_RETURN_IFERR(sprintf_s(cmd_buf, MAX_CMD_LEN,
        "SELECT NODE_NAME, NODE_HOST, NODE_PORT FROM SYS." WSR_DATA_NODE_AGENT " "
        "WHERE (NODE_TYPE='DATANODE' AND IS_PRIMARY = 1) OR NODE_TYPE='COORDINATOR' ORDER BY GROUP_ID DESC"));

    CT_RETURN_IFERR(ctconn_prepare(STMT, (const char *)cmd_buf));
    CT_RETURN_IFERR(ctconn_execute(STMT));
    
    do {
        CT_RETURN_IFERR(ctconn_fetch(STMT, &rows));
        if (rows == 0) {
            break;
        }
        
        CT_RETURN_IFERR(cm_list_new(shd_node_list, (void **)&node_info));
        CT_RETURN_IFERR(wsr_node_save_conn_info(node_info));
    } while (CT_TRUE);

    return CT_SUCCESS;
}

static status_t wsr_get_cluster_info(void)
{
    status_t status;
    wsr_free_node_info();
    cm_create_list(&g_wsr_shd_node, sizeof(wsr_shd_info_t));
    status = wsr_init_node_conn_info(&g_wsr_shd_node);
    if (status != CT_SUCCESS) {
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static void wsr_init_shd_info(wsr_shd_mess_t *shd_info, wsr_options_t *wsr_opts,
    wsr_info_t *wsr_info, wsr_shd_info_t *node_info)
{
    MEMS_RETVOID_IFERR(memset_s(shd_info, sizeof(wsr_shd_mess_t), 0, sizeof(wsr_shd_mess_t)));
    MEMS_RETVOID_IFERR(strcpy_s(shd_info->shd_wsr_opt.file_name,
        sizeof(shd_info->shd_wsr_opt.file_name), wsr_opts->file_name));
    MEMS_RETVOID_IFERR(strcpy_s(shd_info->shd_wsr_info.start_time,
        sizeof(shd_info->shd_wsr_info.start_time), wsr_info->start_time));
    MEMS_RETVOID_IFERR(strcpy_s(shd_info->shd_wsr_info.end_time,
        sizeof(shd_info->shd_wsr_info.end_time), wsr_info->end_time));
    shd_info->shd_wsr_opt.curr_conn = node_info->node_conn.conn;
    shd_info->shd_wsr_opt.curr_stmt = node_info->node_conn.stmt;
    shd_info->shd_wsr_opt.switch_shd_off = wsr_opts->switch_shd_off;
    shd_info->shd_wsr_info.node_name = node_info->node_name;
    shd_info->shd_wsr_info.shd_start_timesapce = wsr_info->shd_start_timesapce;
    shd_info->shd_wsr_info.shd_end_timesapce = wsr_info->shd_end_timesapce;
    return;
}

static status_t wsr_get_remote_snap_info(wsr_options_t *wsr_opts, wsr_info_t *wsr_info)
{
    lex_t lex;
    uint32 rows, size;
    bool32 is_null = CT_FALSE;
    uint32 *data = NULL;
    char cmd_buf[MAX_CMD_LEN + 1];

    ctconn_stmt_t wsr_stmt = wsr_opts->curr_stmt;

    if (wsr_info->shd_start_timesapce > 0 && wsr_info->shd_end_timesapce > 0) {
        PRTS_RETURN_IFERR(sprintf_s(cmd_buf, MAX_CMD_LEN,
            "select MAX(SNAP_ID), MIN(SNAP_ID) from ADM_HIST_SNAPSHOT "
            "where SNAP_TIME between (sysdate - %u /86400 -5/86400)"
            "and (sysdate - %u /86400 +5/86400)",
            wsr_info->shd_start_timesapce, wsr_info->shd_end_timesapce));
    } else {
        PRTS_RETURN_IFERR(sprintf_s(cmd_buf, MAX_CMD_LEN,
            "select MAX(SNAP_ID), MIN(SNAP_ID) from ADM_HIST_SNAPSHOT where "
            "SNAP_TIME between (to_timestamp ('%s','YYYY-MM-DD HH24:MI:SS.ff')-5/86400)"
            "and (to_timestamp ('%s','YYYY-MM-DD HH24:MI:SS.ff') +5/86400)",
            wsr_info->start_time, wsr_info->end_time));
    }

    CT_RETURN_IFERR(ctconn_prepare(wsr_stmt, (const char *)cmd_buf));
    CT_RETURN_IFERR(ctconn_execute(wsr_stmt));
    CT_RETURN_IFERR(ctconn_fetch(wsr_stmt, &rows));

    if (rows == 0) {
        CTSQL_PRINTF(ZSERR_WSR, "Time to snap id failed!");
        return CTCONN_ERROR;
    }
    
    CT_RETURN_IFERR(ctconn_get_column_by_id(wsr_stmt, 0, (void **)&data, &size, &is_null));
    wsr_opts->end_snap_id = is_null ? 0 : *data;
    CT_RETURN_IFERR(ctconn_get_column_by_id(wsr_stmt, 1, (void **)&data, &size, &is_null));
    wsr_opts->start_snap_id = is_null ? 0 : *data;
    
    if (wsr_opts->start_snap_id < wsr_opts->end_snap_id) {
        CT_RETURN_IFERR(ctsql_get_wsr_base_info(&lex, wsr_opts, wsr_info));
        return CTCONN_SUCCESS;
    }
    
    CTSQL_PRINTF(ZSERR_WSR, "Time to snap id failed!");
    return CTCONN_ERROR;
}

static status_t wsr_exec_core(wsr_options_t *wsr_opts, wsr_info_t *wsr_info, char *node_name)
{
    if (wsr_check_parameter(wsr_opts) != CT_SUCCESS) {
        return CT_ERROR;
    }
    
    return wsr_build_report(wsr_opts, wsr_info, node_name);
}

static void  wsr_exec_shard_core(thread_t *thread)
{
    status_t status;
    wsr_shd_mess_t *shd_info = (wsr_shd_mess_t *)thread->argument;
    if (shd_info == NULL) {
        return;
    }
    
    wsr_info_t    *wsr_info   = &shd_info->shd_wsr_info;
    wsr_options_t *wsr_opt    = &shd_info->shd_wsr_opt;
    char          *node_name  = shd_info->shd_wsr_info.node_name;
    
    wsr_opt->wsr_result = CT_ERROR;
    status = wsr_get_remote_snap_info(wsr_opt, wsr_info);
    if (status != CT_SUCCESS) {
        wsr_print_shd_err(wsr_opt->curr_conn, node_name);
        return;
    }
    
    status = wsr_exec_core(wsr_opt, wsr_info, node_name);
    if (status != CT_SUCCESS) {
        wsr_print_shd_err(wsr_opt->curr_conn, node_name);
        return;
    }

    wsr_opt->wsr_result = CT_SUCCESS;
    wsr_print_shd_succ(node_name, NULL);
    return;
}

static void wsr_create_glb_snaps_core(thread_t *thread)
{
    status_t status;
    char *cmd_buf = "CALL SYS.WSR$CREATE_SNAPSHOT";
    
    wsr_shd_info_t *node_info = (wsr_shd_info_t *)thread->argument;
    if (node_info == NULL) {
        return;
    }
    
    ctconn_stmt_t wsr_stmt = node_info->node_conn.stmt;
    status = ctconn_prepare(wsr_stmt, cmd_buf);
    if (status != CT_SUCCESS) {
        CTSQL_PRINTF(ZSERR_WSR, "wsr create %s snapshot failed! \n\n", node_info->node_name);
        return;
    }
    
    status = ctconn_execute(wsr_stmt);
    if (status != CT_SUCCESS) {
        CTSQL_PRINTF(ZSERR_WSR, "wsr create %s snapshot failed! \n\n", node_info->node_name);
        return;
    }
    
    ctsql_printf("wsr create %s snapshot success! \n\n", node_info->node_name);
    return;
}

static status_t wsr_create_glb_snaps_proc()
{
    uint32 num;
    status_t status;
    wsr_shd_info_t *node_info = NULL;
    clt_stmt_t *stmt = (clt_stmt_t *)STMT;
    
    if (stmt == NULL) {
        CT_THROW_ERROR(ERR_CLT_OBJECT_IS_NULL, "statement");
        ctsql_print_error(CONN);
        return CT_ERROR;
    }
    
    if (stmt->conn->node_type != CS_TYPE_CN) {
        CTSQL_PRINTF(ZSERR_WSR, "This command only support in the CN nodes.\n");
        return CT_ERROR;
    }
    
    status = wsr_get_cluster_info();
    if (status != CTCONN_SUCCESS) {
        CTSQL_PRINTF(ZSERR_WSR, "Create a golbal snapshot failed.\n");
        return status;
    }

    for (num = 0; num < g_wsr_shd_node.count; num++) {
        node_info = (wsr_shd_info_t *)cm_list_get(&g_wsr_shd_node, num);
        if (node_info->node_conn.conn == NULL) {
            (void)ctsql_print_disconn_error();
            continue;
        }
        
        status = cm_create_thread(wsr_create_glb_snaps_core, 0, node_info, &node_info->thread);
        if (status) {
            continue;
        }
    }
    
    for (num = 0; num < g_wsr_shd_node.count; num++) {
        node_info = (wsr_shd_info_t *)cm_list_get(&g_wsr_shd_node, num);
        cm_close_thread(&node_info->thread);
    }
    
    wsr_free_node_info();
    return status;
}

static void wsr_build_summary_header(void)
{
    wsr_write_str3("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">");
    wsr_write_str3("<HTML lang=\"en\">");
    wsr_write_str3("    <HEAD>");
    wsr_write_str3("        <META content=\"IE=5.0000\" http-equiv=\"X-UA-Compatible\">");
    wsr_write_str3("<TITLE>Workload Statistics Report Snaps</TITLE> ");
    wsr_write_str3("        <META http-equiv=\"Content-Type\" content=\"text/html; charset=gb2312\">");
    wsr_write_str3("        <style type=\"text/css\">");
    wsr_write_str3("            </style>");
    wsr_write_str3("            <STYLE type=\"text/css\">");
    wsr_write_str3("            div.wsr {");
    wsr_write_str3("                font: normal 13pt Arial, Helvetica, Geneva, sans-serif;");
    wsr_write_str3("                color: black;");
    wsr_write_str3("                background-color: #f1f1f1;");
    wsr_write_str3("            }");
    wsr_write_str3("            table{");
    wsr_write_str3("                table-layout: auto;");
    wsr_write_str3("            }");
    wsr_write_str3("            .table tr {");
    wsr_write_str3("                height: 30px;");
    wsr_write_str3("            }");
    wsr_write_str3("            .table td{");
    wsr_write_str3("               ");
    wsr_write_str3("                border:1px solid #ddd;");
    wsr_write_str3("                white-space: nowrap;");
    wsr_write_str3("                overflow: hidden;");
    wsr_write_str3("                text-overflow: ellipsis;");
    wsr_write_str3("            }");
    wsr_write_str3("            .table th{");
    wsr_write_str3("                text-align:left;");
    wsr_write_str3("                background:#ddd;");
    wsr_write_str3("                border-collapse:collapse;");
    wsr_write_str3("                white-space: nowrap;");
    wsr_write_str3("                overflow: hidden;");
    wsr_write_str3("                text-overflow: ellipsis;");
    wsr_write_str3("            }");
    wsr_write_str3("            h1{");
    wsr_write_str3("                font: bold 16pt Arial,Helvetica,Geneva,sans-serif;");
    wsr_write_str3("                    color: white;");
    wsr_write_str3("                    background-color: black;");
    wsr_write_str3("                    border-bottom: 1px solid black;");
    wsr_write_str3("                    margin-top: -6pt;");
    wsr_write_str3("                    margin-bottom: 0pt;");
    wsr_write_str3("                    padding: 15px 0px 15px 0px;");
    wsr_write_str3("                    display: block;   ");
    wsr_write_str3("                    margin-block-start: 0.67em;");
    wsr_write_str3("                    margin-block-end: 0.67em;");
    wsr_write_str3("                    margin-inline-start: 0px;");
    wsr_write_str3("                    margin-inline-end: 0px;");
    wsr_write_str3("                    margin-left:20px;");
    wsr_write_str3("            }");
    wsr_write_str3("            .title{");
    wsr_write_str3("                    background-color: black;");
    wsr_write_str3("            }");
    wsr_write_str3("            .wsrg{");
    wsr_write_str3("                color:black;");
    wsr_write_str3("                font-weight: bold;");
    wsr_write_str3("            }");
    wsr_write_str3("            a{");
    wsr_write_str3("                color:black;");
    wsr_write_str3("            }");
    wsr_write_str3("            p {");
    wsr_write_str3("                background-color: #ffffff;");
    wsr_write_str3("                padding: 20px;");
    wsr_write_str3("                box-shadow: 0 0 20px 5px rgba(0, 0, 0, .05);");
    wsr_write_str3("                border-radius: 3px;");
    wsr_write_str3("                display: block;");
    wsr_write_str3("                margin-block-start: 1em;");
    wsr_write_str3("                margin-block-end: 1em;");
    wsr_write_str3("                margin-inline-start: 0px;");
    wsr_write_str3("                margin-inline-end: 0px;");
    wsr_write_str3("                border:1px solid #ddd;");
    wsr_write_str3("            }");
    wsr_write_str3("            .hidden {");
    wsr_write_str3("                position: absolute;");
    wsr_write_str3("                left: -10000px;");
    wsr_write_str3("                top: auto;");
    wsr_write_str3("                width: 1px;");
    wsr_write_str3("                height: 1px;");
    wsr_write_str3("                overflow: hidden;");
    wsr_write_str3("                width: 100%;");
    wsr_write_str3("            }");
    wsr_write_str3("            .table {");
    wsr_write_str3("                width:97.5%;");
    wsr_write_str3("                max-width:90%;");
    wsr_write_str3("                margin-top: 10px;");
    wsr_write_str3("                font-size: 14px;");
    wsr_write_str3("                border:1px solid #ddd;");
    wsr_write_str3("                -ms-border-collapse:collapse;");
    wsr_write_str3("            }");
    wsr_write_str3("            table.wsrdiff {");
    wsr_write_str3("                width: -webkit-fill-available;");
    wsr_write_str3("            }");
    wsr_write_str3("            font {");
    wsr_write_str3("                font-weight: bold;");
    wsr_write_str3("                font-size: 18px;");
    wsr_write_str3("                font-family: \"Microsoft Yahei\", Arial, Tahoma, Verdana, SimSun;");
    wsr_write_str3("                color:#666;");
    wsr_write_str3("            }");
    wsr_write_str3("            .pad {");
    wsr_write_str3("                margin-left: 17px;");
    wsr_write_str3("            }");
    wsr_write_str3("            .doublepad {");
    wsr_write_str3("                margin-left: 34px;");
    wsr_write_str3("            }");
    wsr_write_str3("td.wsrc    {font-size: 14px;font-weight: normal;height: 40px;"
        "padding-top: 10px;color:black;background:white; vertical-align:top;}");
    wsr_write_str3("        </STYLE>");
    wsr_write_str3("        <META name=\"GENERATOR\" content=\"MSHTML 11.00.9600.19236\">");
    wsr_write_str3("    </HEAD>");
    wsr_write_str3("");
    wsr_write_str3("    <body>");
    wsr_write_str3("            <font face=\"Courier New, Courier, mono\" color=\"#666\">WSR LIST</font>");
    wsr_write_str3("            <table class=\"table table-hover\" >");
    wsr_write_str3("              <thead>");
}

static void wsr_build_summary_list(char *node_name)
{
    wsr_write_str3("        <tr>");
    wsr_write_fmt3(WSR_FMT_SIZE_500, "      <td><a class=\"wsrg\" href=\"#%s\">%s</a></td>", node_name, node_name);
    wsr_write_str3("        </tr>");
}

static void wsr_build_summary_body(wsr_options_t *wsr_opts, wsr_info_t *wsr_info)
{
    wsr_write_str3("        <li>");
    wsr_write_fmt3(WSR_FMT_SIZE_500, "      <DIV class=\"wsr\" id=\"%s\">", wsr_info->node_name);
    wsr_opts->wsr_txtbuf.str[wsr_opts->wsr_txtbuf.len] = '\0';
    wsr_write_str3(wsr_opts->wsr_txtbuf.str + wsr_opts->header_len);
    wsr_write_str3("        </li>");
}

static void wsr_build_summary_report(wsr_shd_mess_t *wsr_shd_mess)
{
    uint32 num;
    wsr_info_t *wsr_info = NULL;
    wsr_options_t *wsr_opts = NULL;
    char wsr_file_path[CT_MAX_FILE_PATH_LENGH];
    char dump_path[CT_MAX_FILE_PATH_LENGH] = {0};
    
    MEMS_RETVOID_IFERR(strcpy_s(wsr_file_path, CT_MAX_FILE_PATH_LENGH, g_wsr_report_path));
    if (strlen(wsr_file_path) > 0 && !cm_dir_exist((const char *)wsr_file_path)) {
        CTSQL_PRINTF(ZSERR_WSR, "%s is not an existing folder, Build summary report failed!\n", wsr_file_path);
        return;
    }

    MEMS_RETVOID_IFERR(strcat_s(wsr_file_path, CT_MAX_FILE_PATH_LENGH, (char*)WSR_SUMMAY_FILE_NAME));
    CT_RETVOID_IFERR(realpath_file(wsr_file_path, dump_path, CT_MAX_FILE_PATH_LENGH));
    g_wsr_report_summary_fp = fopen(dump_path, "w+");
    if (g_wsr_report_summary_fp == NULL) {
        CTSQL_PRINTF(ZSERR_WSR, "Failed to open the file %s, the error code was %d, Build summary report failed!\n",
            dump_path, errno);
        return;
    }
    
    if (cm_fchmod(FILE_MODE_OF_WSR, g_wsr_report_summary_fp) != CT_SUCCESS) {
        return;
    }

    // write header
    wsr_build_summary_header();

    // write list
    for (num = 0; num < g_wsr_shd_node.count; num++) {
        wsr_info = &(wsr_shd_mess[num].shd_wsr_info);
        wsr_opts = &(wsr_shd_mess[num].shd_wsr_opt);
        if (wsr_opts->wsr_result == CT_SUCCESS && wsr_opts->wsr_buff_exhaust == CT_FALSE) {
            wsr_build_summary_list(wsr_info->node_name);
        }
    }
    
    wsr_write_str3("        </thead>");
    wsr_write_str3("        </table>");
    wsr_write_str3("        <ul>");

    // write body
    for (num = 0; num < g_wsr_shd_node.count; num++) {
        wsr_opts = &(wsr_shd_mess[num].shd_wsr_opt);
        wsr_info = &(wsr_shd_mess[num].shd_wsr_info);
        if (wsr_opts->wsr_result == CT_SUCCESS && wsr_opts->wsr_buff_exhaust == CT_FALSE) {
            wsr_build_summary_body(wsr_opts, wsr_info);
        }
    }
    
    wsr_write_str3("        </ul>");
    wsr_write_str3("        </body>");
    wsr_write_str3("        </html>");
    
    fclose(g_wsr_report_summary_fp);
    g_wsr_report_summary_fp = NULL;
    return;
}

void wsr_write_report_proc(wsr_shd_mess_t *wsr_shd_mess)
{
    uint32 num;
    wsr_options_t *wsr_opts = NULL;

    wsr_build_summary_report(wsr_shd_mess);
    for (num = 0; num < g_wsr_shd_node.count; num++) {
        wsr_opts = &(wsr_shd_mess[num].shd_wsr_opt);
        if (wsr_opts->wsr_result == CT_SUCCESS) {
            wsr_writer(wsr_opts, wsr_opts->wsr_txtbuf.str, wsr_opts->wsr_txtbuf.len);
        }
        wsr_free(wsr_opts);
    }
}
static status_t wsr_exec_shard_proc(wsr_options_t *wsr_opts, wsr_info_t *wsr_info)
{
    uint32 num;
    status_t status;
    uint32 node_count;
    wsr_shd_info_t *node_info = NULL;
    wsr_shd_mess_t *wsr_shd_mess = NULL;
    
    status = wsr_get_cluster_info();
    if (status != CT_SUCCESS) {
        CTSQL_PRINTF(ZSERR_WSR, "WSR Report Build failed.\n");
        return status;
    }

    node_count = g_wsr_shd_node.count;
    wsr_shd_mess = (wsr_shd_mess_t*)malloc(sizeof(wsr_shd_mess_t) * node_count);
    if (wsr_shd_mess == NULL) {
        wsr_free_node_info();
        return CT_ERROR;
    }

    for (num = 0; num < node_count; num++) {
        node_info = (wsr_shd_info_t *)cm_list_get(&g_wsr_shd_node, num);
        if (node_info->node_conn.conn == NULL) {
            (void)ctsql_print_disconn_error();
            continue;
        }
        
        wsr_init_shd_info(&wsr_shd_mess[num], wsr_opts, wsr_info, node_info);
        status = cm_create_thread(wsr_exec_shard_core, 0, &wsr_shd_mess[num], &node_info->thread);
        if (status) {
            continue;
        }
    }
    
    for (num = 0; num < node_count; num++) {
        node_info = (wsr_shd_info_t *)cm_list_get(&g_wsr_shd_node, num);
        cm_close_thread(&node_info->thread);
    }
    
    wsr_write_report_proc(wsr_shd_mess);
    wsr_free_node_info();
    free(wsr_shd_mess);
    return status;
}

static status_t ctsql_wsr_deal(lex_t *lex)
{
    status_t status;
    wsr_info_t wsr_info;
    wsr_options_t wsr_opts;
    wsr_opts.wsr_dpfile = NULL;
    wsr_opts.wsr_fbuf = NULL;
    
    status = wsr_parse_opts(lex, &wsr_opts, &wsr_info);
    if (status != CT_SUCCESS) {
        wsr_print_shd_err(wsr_opts.curr_conn, NULL);
        return CT_ERROR;
    }

    if (wsr_opts.switch_shd_off == CT_FALSE) {
        status = wsr_exec_core(&wsr_opts, &wsr_info, NULL);
        if (status == CT_SUCCESS) {
            wsr_flush(&wsr_opts);
            wsr_print_shd_succ(NULL, &wsr_opts);
        } else {
            wsr_print_shd_err(wsr_opts.curr_conn, NULL);
        }
        wsr_free(&wsr_opts);
    } else {
        status = wsr_exec_shard_proc(&wsr_opts, &wsr_info);
    }
    
    return status;
}

status_t ctsql_wsr(text_t *cmd_text)
{
    uint32 matched_id;
    lex_t lex;
    sql_text_t sql_text;
    sql_text.value = *cmd_text;
    sql_text.loc.line = 1;
    sql_text.loc.column = 1;
    
    lex_trim(&sql_text);
    lex_init(&lex, &sql_text);
    lex_init_keywords();

    if (lex_try_fetch_1ofn(&lex, &matched_id, 3, "help", "usage", "option") != CT_SUCCESS) {
        ctsql_print_error(NULL);
        return CT_ERROR;
    }

    if (matched_id != CT_INVALID_ID32 || sql_text.len == 0) {
        ctsql_display_wsr_usage();
        return CT_SUCCESS;
    }

    if (lex_try_fetch_1ofn(&lex, &matched_id, 2, "list", "create_global_snapshot") != CT_SUCCESS) {
        ctsql_print_error(NULL);
        return CT_ERROR;
    }

    if (matched_id == 0 || sql_text.len == 0) {
        int32 listNum;

        if (lex_expected_fetch_int32(&lex, &listNum) != CT_SUCCESS) {
            cm_reset_error();
            listNum = WSR_DEFAULT_LIST_NUM;
        }

        if (wsr_show_snapid(listNum) != CT_SUCCESS) {
            ctsql_print_error(CONN);
            return CT_ERROR;
        }
        return CT_SUCCESS;
    } else if (matched_id == 1 || sql_text.len == 0) {
        CT_RETURN_IFERR(wsr_create_glb_snaps_proc());
        return CT_SUCCESS;
    }

    return ctsql_wsr_deal(&lex);
}