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
 * ctbackup.c
 *
 *
 * IDENTIFICATION
 * src/utils/ctbackup/ctbackup.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctbackup_module.h"
#include "ctbackup.h"
#include "ctbackup_factory.h"
#include "ctbackup_common.h"

#ifdef WIN32
const char *cantiand_get_dbversion()
{
    return "NONE";
}
#else

extern const char* cantiand_get_dbversion(void);

#endif

static void ctbackup_show_version(void)
{
    printf("%s\n", cantiand_get_dbversion());
}

static void ctbackup_show_usage(void)
{
    printf("Usage: [ctbackup --backup | ctbackup --prepare | ctbackup --copy-back | ctbackup --archivelog\n");
    printf("     | ctbackup --reconciel-mysql | ctbackup --query-incremental-mode | ctbackup --purge-logs\n");
    printf("                                                                | ctbackup --help]  [OPTIONS]\n");
    printf("Options:\n");
    printf("--defaults-file=#        Configuration file path of MySQL, Only read default options "
                                        "from the given file.\n");
    printf("%*s%s", COMMENT_SPACE, "", "for --backup | --copy-back\n");
    printf("--user=#                 This option specifies the MySQL username used when connecting to the server.\n");
    printf("%*s%s", COMMENT_SPACE, "", "for --backup | --reconciel-mysql\n");
    printf("--password=#             This option specifies the password to use when connecting to the server.\n");
    printf("%*s%s", COMMENT_SPACE, "", "for --backup | --reconciel-mysql\n");
    printf("--host=#                 This option specifies the host to use when connecting to "
                                        "the database server with TCP/IP.\n");
    printf("%*s%s", COMMENT_SPACE, "", "for --backup | --reconciel-mysql\n");
    printf("--port=#                 This option specifies the port to use when connecting to "
                                        "the database server with TCP/IP.\n");
    printf("%*s%s", COMMENT_SPACE, "", "for --backup | --reconciel-mysql\n");
    printf("--target-dir=#           This option specifies the destination directory for the backup.\n");
    printf("%*s%s", COMMENT_SPACE, "", "This option specifies the source directory for "
                                            "prepare, copy-back or query-incremental-mode.\n");
    printf("%*s%s", COMMENT_SPACE, "", "for --backup | --prepare | --copy-back | --query-incremental-mode.\n");
    printf("--socket=#               This option specifies the socket to use when connecting to "
                                        "the local database server.\n");
    printf("%*s%s", COMMENT_SPACE, "", "for --backup\n");
    printf("--datadir=#              This option specifies the datadir for your MySQL server.\n");
    printf("%*s%s", COMMENT_SPACE, "", "for --backup | --copy-back\n");
    printf("--incremental            This option tells ctbackup to create an incremental backup.\n");
    printf("%*s%s", COMMENT_SPACE, "", "for --backup\n");
    printf("--cumulative             This option specifies the incremental backup type to cumulative. "
                                        "Note: the type can be switched only after a new full backup.\n");
    printf("%*s%s", COMMENT_SPACE, "", "for --backup --incremental\n");
    printf("--databases-exclude=#    Excluding databases based on name.\n");
    printf("%*s%s", COMMENT_SPACE, "", "for --backup\n");
    printf("--parallel=#             This option specifies the number of threads to use "
                                        "for backup, prepare or copy-back.\n");
    printf("%*s%s", COMMENT_SPACE, "", "for --backup | --prepare | --copy-back\n");

    printf("--compress=lz4           This option tells ctbackup to compress output data, "
                                    "only can choose lz4 compression algorithm.\n");
    printf("%*s%s", COMMENT_SPACE, "", "for --backup\n");

    printf("--decompress             This option tells ctbackup to decompress backup data, "
                                    "lz4 is chosen by default.\n");
    printf("%*s%s", COMMENT_SPACE, "", "for --prepare\n");
    printf("--force-ddl              This option tells ctbackup to ignore the SQL error when reconciel.\n");
    printf("%*s%s", COMMENT_SPACE, "", "for --reconciel\n");
    printf("--skip-badblock          This option tells ctbackup to ignore badblock in datafiles when backup.\n");
    printf("%*s%s", COMMENT_SPACE, "", "for --backup\n");
    printf("--repair-type            This option tells ctbackup to choose repair-type for badblock in datafiles.\n");
    printf("%*s%s", COMMENT_SPACE, "", "for --restore.\n");
}

void ctbackup_show_help(void)
{
    ctbackup_show_version();
    ctbackup_show_usage();
}

static inline ctbak_topic_t ctbak_parse_topic(char** argv, int32 argc)
{
    if (cm_str_equal(argv[1], "-v") || cm_str_equal(argv[1], "--version")) {
        return CTBAK_VERSION;
    }
    if (cm_str_equal(argv[1], "-h") || cm_str_equal(argv[1], "--help")) {
        return CTBAK_HELP;
    }

    if (cm_str_equal(argv[1], CTBAK_ARG_BACKUP)) {
        return CTBAK_BACKUP;
    }

    if (cm_str_equal(argv[1], CTBAK_ARG_PREPARE)) {
        return CTBAK_PREPARE;
    }

    if (cm_str_equal(argv[1], CTBAK_ARG_COPYBACK)) {
        return CTBAK_COPYBACK;
    }

    if (cm_str_equal(argv[1], CTBAK_ARG_ARCHIVELOG)) {
        return CTBAK_ARCHIVE_LOG;
    }

    if (cm_str_equal(argv[1], CTBAK_ARG_RECONCIEL_MYSQL)) {
        return CTBAK_RECONCIEL_MYSQL;
    }

    if (cm_str_equal(argv[1], CTBAK_ARG_QUERY_INCREMENTAL_MODE)) {
        return CTBAK_QUERY_INCREMENTAL_MODE;
    }

    if (cm_str_equal(argv[1], CTBAK_ARG_PURGE_LOGS)) {
        return CTBAK_PURGE_LOGS;
    }
    return CTBAK_INVALID;
}

EXTER_ATTACK status_t ctbak_process_args(int32 argc, char** argv)
{
    if (argc > CTBACKUP_MAX_PARAMETER_CNT) {
        printf("The current number of ctbackup parameters exceeds %u\n", CTBACKUP_MAX_PARAMETER_CNT);
        return CT_ERROR;
    }
    ctbak_topic_t topic = ctbak_parse_topic(argv, argc);
    if (topic == CTBAK_INVALID) {
        return CT_ERROR;
    }
    if (topic == CTBAK_HELP) {
        ctbackup_show_help();
        return CT_SUCCESS;
    }
    if (topic == CTBAK_VERSION) {
        ctbackup_show_version();
        return CT_SUCCESS;
    }
    ctbak_cmd_t* ctbak_cmd = ctbak_factory_generate_cmd(topic);
    if (ctbak_cmd == NULL) {
        printf("[ctbackup]failed to generate ctbak_cmd!\n");
        return CT_ERROR;
    }
    ctbak_param_t empty_ctbak_param = {0};
    ctbak_cmd->ctbak_param = &empty_ctbak_param;
    if (ctbak_cmd->parse_args(argc, argv, ctbak_cmd->ctbak_param) != CT_SUCCESS) {
        printf("cmd %s parse args error!\n", ctbak_cmd->cmd_name);
        free_input_params(ctbak_cmd->ctbak_param);
        free(ctbak_cmd);
        return CT_ERROR;
    }
    if (ctbak_cmd->do_exec(ctbak_cmd->ctbak_param) != CT_SUCCESS) {
        printf("cmd %s execute error!\n", ctbak_cmd->cmd_name);
        free(ctbak_cmd);
        return CT_ERROR;
    }
    free(ctbak_cmd);
    return CT_SUCCESS;
}
