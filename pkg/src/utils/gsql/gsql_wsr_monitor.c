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
 * gsql_wsr_monitor.c
 *
 *
 * IDENTIFICATION
 * src/utils/gsql/gsql_wsr_monitor.c
 *
 * -------------------------------------------------------------------------
 */
#include "gsql_wsr_head.h"
#include "gsql_wsr_monitor.h"

#define GS_MONITOR_LINE_LEN                  (uint32)1000
#define GS_MONITOR_TIME_CONVERT              (uint32)1000
#define GS_MONITOR_DEFAULT_TIMES             (uint32)100

typedef enum {
    EMONITOR_TIMES,
    EMONITOR_FILE,
    EMONITOR_TYPE,
    EMONITOR_INTERVAL
} monitor_item_t;

static const word_record_t g_monitor_records[] = {
    { .id = EMONITOR_TIMES,
      .tuple = { 1, { "TIMES" } }
    },
    { .id = EMONITOR_FILE,
      .tuple = { 1, { "FILE" } }
    },
    { .id = EMONITOR_TYPE,
      .tuple = { 1, { "TYPE" } }
    },
    { .id = EMONITOR_INTERVAL,
      .tuple = { 1, { "INTERVAL" } }
    },
};

#define MONITOR_OPT_SIZE ELEMENT_COUNT(g_monitor_records)

typedef enum {
    MONITOR_ALL = 0,
    MONITOR_HOST,
    MONITOR_SESSION,
    MONITOR_MEMORY,
    MONITOR_APP,
    MONITOR_SYNC,
    MONITOR_TABLESPACE,
    MONITOR_EVENT
} export_type_t;

typedef struct st_monitor_options {
    uint32 times;
    char dump_file[GS_MAX_FILE_PATH_LENGH];
    uint32 type;
    uint32 interval;
} monitor_options_t;

static FILE *g_monitor_logfile = (FILE *)NULL;

#define monitor_log(fmt, ...)                               \
    do {                                                \
        gsql_printf(fmt, ##__VA_ARGS__);                \
        if (g_monitor_logfile != NULL) {                    \
            fprintf(g_monitor_logfile, fmt, ##__VA_ARGS__); \
        }                                               \
    } while (0)

static void gsql_display_wsr_monitor_host(void)
{
    gsql_printf("                        1: Host\n");
    gsql_printf("                            %%user: %s\n", g_wsritemdesc[WSR_ITEM_CPU_USER]);
    gsql_printf("                            %%system: %s\n", g_wsritemdesc[WSR_ITEM_CPU_SYSTEM]);
    gsql_printf("                            %%iowait: %s\n", g_wsritemdesc[WSR_ITEM_IOWAIT]);
    gsql_printf("                            %%idle: %s\n", g_wsritemdesc[WSR_ITEM_IDLE]);
}

static void gsql_display_wsr_monitor_session(void)
{
    gsql_printf("                        2: Session & Transaction\n");
    gsql_printf("                            Sessions: %s\n", g_wsritemdesc[WSR_ITEM_SESSIONS]);
    gsql_printf("                            ActiveSess: %s\n", g_wsritemdesc[WSR_ITEM_ACTIVE_SESSIONS]);
    gsql_printf("                            Trans: %s\n", g_wsritemdesc[WSR_ITEM_TRANSACTIONS]);
    gsql_printf("                            LongSQL: %s\n", g_wsritemdesc[WSR_ITEM_LONG_SQL]);
    gsql_printf("                            LongTrans: %s\n", g_wsritemdesc[WSR_ITEM_LONG_TRANS]);
}

static void gsql_display_wsr_monitor_memory(void)
{
    gsql_printf("                        3. Memory\n");
    gsql_printf("                            DataDirty :%s\n", g_wsritemdesc[WSR_ITEM_DIRTY_DATA]);
    gsql_printf("                            DataPin: %s\n", g_wsritemdesc[WSR_ITEM_PIN_DATA]);
    gsql_printf("                            DataFree: %s\n", g_wsritemdesc[WSR_ITEM_FREE_DATA]);
    gsql_printf("                            TempFree: %s\n", g_wsritemdesc[WSR_ITEM_FREE_TEMP]);
    gsql_printf("                            TempHWM: %s\n", g_wsritemdesc[WSR_ITEM_TEMP_HWM]);
    gsql_printf("                            TempSwap: %s\n", g_wsritemdesc[WSR_ITEM_TEMP_SWAP]);
}

static void gsql_display_wsr_monitor_performance(void)
{
    gsql_printf("                        4. Performance\n");
    gsql_printf("                            Physical: %s\n", g_wsritemdesc[WSR_ITEM_PHYSICAL_READ]);
    gsql_printf("                            Logical: %s\n", g_wsritemdesc[WSR_ITEM_LOGICAL_READ]);
    gsql_printf("                            Commit: %s\n", g_wsritemdesc[WSR_ITEM_COMMITS]);
    gsql_printf("                            Rollback: %s\n", g_wsritemdesc[WSR_ITEM_ROLLBACKS]);
    gsql_printf("                            RedoSize: %s\n", g_wsritemdesc[WSR_ITEM_REDO_SIZE]);
    gsql_printf("                            Execute: %s\n", g_wsritemdesc[WSR_ITEM_EXECUTIONS]);
    gsql_printf("                            Fetch: %s\n", g_wsritemdesc[WSR_ITEM_FETCHS]);
    gsql_printf("                            Login: %s\n", g_wsritemdesc[WSR_ITEM_LOGINS]);
    gsql_printf("                            HardParse: %s\n", g_wsritemdesc[WSR_ITEM_HARD_PARSES]);
    gsql_printf("                            DBWRPages: %s\n", g_wsritemdesc[WSR_ITEM_DBWR_PAGES]);
    gsql_printf("                            DBWRTIME: %s\n", g_wsritemdesc[WSR_ITEM_DBWR_TIME]);
}

static void gsql_display_wsr_monitor_sync(void)
{
    gsql_printf("                        5. SYNC\n");
    gsql_printf("                            MinLog: %s\n", g_wsritemdesc[WSR_ITEM_MIN_REDO_SYNC]);
    gsql_printf("                            MinSyReply: %s\n", g_wsritemdesc[WSR_ITEM_MIN_REDO_REPLY]);
    gsql_printf("                            MaxLog: %s\n", g_wsritemdesc[WSR_ITEM_MAX_REDO_SYNC]);
    gsql_printf("                            MaxSyReply: %s\n", g_wsritemdesc[WSR_ITEM_MAX_REDO_REPLY]);
    gsql_printf("                            MinLgReply: %s\n", g_wsritemdesc[WSR_ITEM_MIN_LOGICAL_DELAY]);
    gsql_printf("                            MaxLgReply: %s\n", g_wsritemdesc[WSR_ITEM_MAX_LOGICAL_DELAY]);
}

static void gsql_display_wsr_monitor_tablespace(void)
{
    gsql_printf("                        6. Tablespace\n");
    gsql_printf("                            TXN_Pages: %s\n", g_wsritemdesc[WSR_ITEM_TXN_PAGES]);
    gsql_printf("                            Undo_Pages: %s\n", g_wsritemdesc[WSR_ITEM_UNDO_PAGES]);
    gsql_printf("                            System: %s\n", g_wsritemdesc[WSR_ITEM_SYSTEM_TABLESPACE]);
    gsql_printf("                            Sysaux: %s\n", g_wsritemdesc[WSR_ITEM_SYSAUX_TABLESPACE]);
    gsql_printf("                            Users: %s\n", g_wsritemdesc[WSR_ITEM_USER_TABLESPACE]);
    gsql_printf("                            ArchLogs: %s\n", g_wsritemdesc[WSR_ITEM_ARCH_LOGS]);
}

static void gsql_display_wsr_monitor_event(void)
{
    gsql_printf("                        7. Event\n");
    gsql_printf("                            Latch_Data: %s\n", g_wsritemdesc[WSR_ITEM_EVENT_LATCH_DATA]);
    gsql_printf("                            FileSync: %s\n", g_wsritemdesc[WSR_ITEM_EVENT_FILE_SYNC]);
    gsql_printf("                            BusyWaits: %s\n", g_wsritemdesc[WSR_ITEM_EVENT_BUFFER_BUSY]);
    gsql_printf("                            TXRowLock: %s\n", g_wsritemdesc[WSR_ITEM_EVENT_TX_LOCK]);
    gsql_printf("                            Scattered: %s\n", g_wsritemdesc[WSR_ITEM_EVENT_SCATTER_READ]);
    gsql_printf("                            Sequential: %s\n", g_wsritemdesc[WSR_ITEM_EVENT_SEQ_READ]);
    gsql_printf("                            ReadOther: %s\n", g_wsritemdesc[WSR_ITEM_EVENT_READ_BY_OTHER]);
    gsql_printf("                            ArchNeeded: %s\n", g_wsritemdesc[WSR_ITEM_EVENT_ARCH_NEEDED]);
    gsql_printf("                            AdLock: %s\n", g_wsritemdesc[WSR_ITEM_EVENT_ADVISE_LOCK]);
    gsql_printf("                            TableSLock: %s\n", g_wsritemdesc[WSR_ITEM_EVENT_TABLE_S_LOCK]);
    gsql_printf("                            SwitchIn: %s\n", g_wsritemdesc[WSR_ITEM_EVENT_REDO_SWITCH]);
    gsql_printf("                            ITL_Enq: %s\n", g_wsritemdesc[WSR_ITEM_EVENT_ITL_ENQ]);
}

static void gsql_display_wsr_monitor_h(void)
{
    gsql_printf("The syntax of monitor is: \n\n");
    gsql_printf("     Format:  monitor [KEYWORD=value]\n");
    gsql_printf("     Example: monitor\n");
    gsql_printf("              or monitor type=2\n");
    gsql_printf("              or monitor file=""abc.txt"" type=3\n\n");
    gsql_printf("Keyword                 Description (Default)\n");
    gsql_printf("------------------------------------------------------------------------------------------"
        "---------------------------------\n");
    gsql_printf("FILE                    Log file of screen output, using double quotes.\n");
    gsql_printf("TYPE                    Data type, default is 0.\n");
    gsql_printf("                        0: ALL\n");
    
    gsql_display_wsr_monitor_host();
    gsql_display_wsr_monitor_session();
    gsql_display_wsr_monitor_memory();
    gsql_display_wsr_monitor_performance();
    gsql_display_wsr_monitor_sync();
    gsql_display_wsr_monitor_tablespace();
    gsql_display_wsr_monitor_event();

    gsql_printf("TIMES                   Times to loop, default is 50.\n");
    gsql_printf("INTERVAL                Query and print interval. The default value is the same as that of the "
        "WSR$CREATE_SESSION_SNAPSHOT task.\n\n");
    gsql_printf("Note: To change the data generation interval, call WSR$MODIFY_SETTING interface using SYS.\n");
    gsql_printf("      For example, change the interval to 5s:\n");
    gsql_printf("          call WSR$MODIFY_SETTING(I_IN_SESSION_INTERVAL => 5); \n");
    gsql_printf("\n");
}

static int monitor_parse_opts_file(lex_t *lex, monitor_options_t *monitor_opts)
{
    word_t word;

    if (lex_expected_fetch_dqstring(lex, &word) != GS_SUCCESS) {
        GS_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "use double quotes for FILE!");
        return GS_ERROR;
    }
    GS_RETURN_IFERR(cm_text2str(&word.text.value, monitor_opts->dump_file, GS_MAX_FILE_PATH_LENGH));

    char path[GS_MAX_FILE_PATH_LENGH] = { 0x00 };
    char file_name[GS_MAX_FILE_PATH_LENGH] = { 0x00 };
    cm_trim_filename(monitor_opts->dump_file, GS_MAX_FILE_PATH_LENGH, path);
    cm_trim_dir(monitor_opts->dump_file, sizeof(file_name), file_name);
    if (strlen(path) != strlen(monitor_opts->dump_file) && !cm_dir_exist((const char *)path)) {
        GS_SRC_THROW_ERROR_EX(LEX_LOC, ERR_PATH_NOT_EXIST, "File path not exists!");
        return GS_ERROR;
    } else if (file_name[0] == '\0') {
        GS_SRC_THROW_ERROR_EX(LEX_LOC, ERR_CLT_INVALID_ATTR, "Wrong file name!");
        return GS_ERROR;
    }

    GS_RETURN_IFERR(realpath_file(monitor_opts->dump_file, path, GS_MAX_FILE_PATH_LENGH));

    if (cm_fopen(path, "w+", FILE_PERM_OF_DATA, &g_monitor_logfile) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static int monitor_parse_opts(lex_t *lex, monitor_options_t *monitor_opts)
{
    uint32 matched_id;

    g_monitor_logfile = NULL;

    while (!lex_eof(lex)) {
        GS_RETURN_IFERR(lex_try_match_records(lex, g_monitor_records, MONITOR_OPT_SIZE, (uint32 *)&matched_id));

        if (matched_id == GS_INVALID_ID32) {
            GS_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "invaid input!");
            return GS_ERROR;
        }

        GS_RETURN_IFERR(lex_expected_fetch_word(lex, "="));

        switch (matched_id) {
            case EMONITOR_TIMES:
                GS_RETURN_IFERR(lex_expected_fetch_uint32(lex, &(monitor_opts->times)));
                break;

            case EMONITOR_FILE:

                GS_RETURN_IFERR(monitor_parse_opts_file(lex, monitor_opts));
                break;

            case EMONITOR_TYPE:
                GS_RETURN_IFERR(lex_expected_fetch_uint32(lex, &(monitor_opts->type)));
                if (monitor_opts->type > MONITOR_EVENT) {
                    GS_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "type should between 0 and 7.");
                    return GS_ERROR;
                }

                break;

            case EMONITOR_INTERVAL:
                GS_RETURN_IFERR(lex_expected_fetch_uint32(lex, &(monitor_opts->interval)));
                break;

            default:
                break;
        }
        GS_RETURN_IFERR(lex_skip_comments(lex, NULL));
    }

    return lex_expected_end(lex);
}

status_t monitor_get_head(monitor_options_t *monitor_opts, char* data_head)
{
    char host[GS_MONITOR_LINE_LEN] = "        %%user      %%system      %%iowait        %%idle";
    char session[GS_MONITOR_LINE_LEN] = "     Sessions   ActiveSess        Trans      LongSQL    LongTrans";
    char memory[GS_MONITOR_LINE_LEN] = "    DataDirty      DataPin     DataFree     TempFree      TempHWM     TempSwap";
    char app[GS_MONITOR_LINE_LEN] = "     Physical      Logical       Commit     Rollback     RedoSize      Execute"
        "        Fetch        Login    HardParse    DBWRPages     DBWRTime";
    char sync[GS_MONITOR_LINE_LEN] = "       MinLog   MinSyReply       MaxLog   MaxSyReply             MinLgReply             MaxLgReply";
    char tablespace[GS_MONITOR_LINE_LEN] = "    TXN_Pages   Undo_Pages       System       Sysaux        Users     "
        "ArchLogs";
    char event[GS_MONITOR_LINE_LEN] = "   Latch_Data     FileSync    BusyWaits    TXRowLock    Scattered   Sequential"
        "    ReadOther   ArchNeeded       AdLock   TableSLock     SwitchIn      ITL_Enq";

    MEMS_RETURN_IFERR(strcpy_s(data_head, GS_MONITOR_LINE_LEN, "SNAP_TIME"));

    switch (monitor_opts->type) {
        case MONITOR_HOST:
            MEMS_RETURN_IFERR(strcat_s(data_head, GS_MONITOR_LINE_LEN, host));
            break;
        case MONITOR_SESSION:
            MEMS_RETURN_IFERR(strcat_s(data_head, GS_MONITOR_LINE_LEN, session));
            break;
        case MONITOR_MEMORY:
            MEMS_RETURN_IFERR(strcat_s(data_head, GS_MONITOR_LINE_LEN, memory));
            break;
        case MONITOR_APP:
            MEMS_RETURN_IFERR(strcat_s(data_head, GS_MONITOR_LINE_LEN, app));
            break;
        case MONITOR_SYNC:
            MEMS_RETURN_IFERR(strcat_s(data_head, GS_MONITOR_LINE_LEN, sync));
            break;
        case MONITOR_TABLESPACE:
            MEMS_RETURN_IFERR(strcat_s(data_head, GS_MONITOR_LINE_LEN, tablespace));
            break;
        case MONITOR_EVENT:
            MEMS_RETURN_IFERR(strcat_s(data_head, GS_MONITOR_LINE_LEN, event));
            break;
        default:
            MEMS_RETURN_IFERR(strcat_s(data_head, GS_MONITOR_LINE_LEN, host));
            MEMS_RETURN_IFERR(strcat_s(data_head, GS_MONITOR_LINE_LEN, session));
            MEMS_RETURN_IFERR(strcat_s(data_head, GS_MONITOR_LINE_LEN, memory));
            MEMS_RETURN_IFERR(strcat_s(data_head, GS_MONITOR_LINE_LEN, app));
            MEMS_RETURN_IFERR(strcat_s(data_head, GS_MONITOR_LINE_LEN, sync));
            MEMS_RETURN_IFERR(strcat_s(data_head, GS_MONITOR_LINE_LEN, tablespace));
            MEMS_RETURN_IFERR(strcat_s(data_head, GS_MONITOR_LINE_LEN, event));
            break;
    }

    return GS_SUCCESS;
}

status_t monitor_get_interval(monitor_options_t *monitor_opts)
{
    gsc_stmt_t resultset;
    uint32 rows;
    uint32 *data = NULL;
    char cmd_buf[MAX_CMD_LEN + 1];
    bool32 is_null = GS_FALSE;
    uint32 size;

    PRTS_RETURN_IFERR(sprintf_s(cmd_buf, MAX_CMD_LEN, "CALL SYS.WSR$GETINTERVAL"));

    if (gsc_prepare(STMT, (const char *)cmd_buf) != GS_SUCCESS) {
        gsql_print_error(CONN);
        return GS_ERROR;
    }

    if (gsc_execute(STMT) != GS_SUCCESS) {
        gsql_print_error(CONN);
        return GS_ERROR;
    }

    GS_RETURN_IFERR(gsc_get_implicit_resultset(STMT, &resultset));
    GS_RETURN_IFERR(gsc_fetch(resultset, &rows));

    if (rows == 0) {
        return GS_ERROR;
    }

    if (gsc_get_column_by_id(resultset, 0, (void **)&data, &size, &is_null) != GS_SUCCESS) {
        gsql_print_error(CONN);
        return GS_ERROR;
    } else {
        monitor_opts->interval = is_null ? 0 : *data;
    }
    
    return GS_SUCCESS;
}

static void monitor_close_logger(void)
{
    if (g_monitor_logfile != NULL) {
        fclose(g_monitor_logfile);
        g_monitor_logfile = NULL;
    }
}

status_t monitor_print_content(monitor_options_t *monitor_opts, char* data_head)
{
    char content[GS_MONITOR_LINE_LEN];
    gsc_stmt_t resultset;
    uint32 rows;
    char cmd_buf[MAX_CMD_LEN + 1];

    PRTS_RETURN_IFERR(sprintf_s(cmd_buf, MAX_CMD_LEN, "CALL SYS.WSR$GETCONTENT(%u)", monitor_opts->type));

    if (gsc_prepare(STMT, (const char *)cmd_buf) != GS_SUCCESS) {
        gsql_print_error(CONN);
        return GS_ERROR;
    }

    if (gsc_execute(STMT) != GS_SUCCESS) {
        gsql_print_error(CONN);
        return GS_ERROR;
    }

    GS_RETURN_IFERR(gsc_get_implicit_resultset(STMT, &resultset));
    GS_RETURN_IFERR(gsc_fetch(resultset, &rows));
    
    if (rows == 0) {
        return GS_SUCCESS;
    }

    GS_RETURN_IFERR(gsc_column_as_string(resultset, 0, content, GS_MONITOR_LINE_LEN));

    monitor_log(data_head);
    monitor_log("\n");
    monitor_log(content);
    monitor_log("\n\n");
    return GS_SUCCESS;
}

static status_t gsql_monitor_deal(monitor_options_t* monitor_opts)
{
    char head[GS_MONITOR_LINE_LEN] = {'\0'};
    GS_RETURN_IFERR(monitor_get_head(monitor_opts, (char *)head));

    if (monitor_opts->interval == 0) {
        GS_RETURN_IFERR(monitor_get_interval(monitor_opts));
    }

    for (uint32 i = 0; i < monitor_opts->times; i++) {
        if (i != 0) {
            cm_sleep(monitor_opts->interval * GS_MONITOR_TIME_CONVERT);
        }
        GS_RETURN_IFERR(monitor_print_content(monitor_opts, (char *)head));
    }

    monitor_close_logger();
    return GSC_SUCCESS;
}

status_t gsql_monitor(text_t *cmd_text)
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

    monitor_options_t monitor_opts = {
        .times = GS_MONITOR_DEFAULT_TIMES,
        .dump_file = "\0",
        .type = MONITOR_ALL,
        .interval = 0,
    };

    if (lex_try_fetch_1ofn(&lex, &matched_id, 3, "help", "usage", "option") != GS_SUCCESS) {
        gsql_print_error(NULL);
        return GS_ERROR;
    }

    if (matched_id != GS_INVALID_ID32) {
        gsql_display_wsr_monitor_h();
        return GS_SUCCESS;
    }
    
    if (monitor_parse_opts(&lex, &monitor_opts) != GS_SUCCESS) {
        gsql_print_error(CONN);
        return GS_ERROR;
    }

    return gsql_monitor_deal(&monitor_opts);
}