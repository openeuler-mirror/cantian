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
 * ct_tbox.c
 *
 *
 * IDENTIFICATION
 * src/ctbox/ct_tbox.c
 *
 * -------------------------------------------------------------------------
 */
#include "ct_tbox_module.h"
#include "cm_date.h"
#include "ct_miner.h"
#include "ct_repair.h"
#include "ct_func.h"
#include "cm_kmc.h"
#include "ct_tbox.h"
#include "ct_tbox_audit.h"
#ifdef WIN32
#define cm_strdup _strdup
#else
#define cm_strdup strdup
#endif

#ifdef WIN32
const char *cantiand_get_dbversion()
{
    return "NONE";
}
#endif

static void usage(void)
{
    printf("ctbox contains cminer, crepair and cfunc tools for cantian.\n"
           "\n"
           "Usage:\n"
           "  ctbox -T [cminer | crepair | cfunc] [OPTIONS]\n"
           "\nRequired options:\n"
           "  -T TOOLNAME  the cminer tool, crepair tool or cfunc tool to use\n");

    printf("\nCommon options:\n"
           "  --help, -h       show this help, then exit\n"
           "  --version, -V    output version information, then exit\n"
           "\nExamples:\n"
           "  ctbox --help\n"
           "  ctbox -T cminer  --help\n"
           "  ctbox -T crepair --help\n"
           "  ctbox -T cfunc   --help\n"
           "  ctbox -T cminer  -l XXX\n"
           "  ctbox -T crepair -f XXX -s XXX -t XXX\n"
           "  ctbox -T cfunc   -f int2pageid XXX\n");
}

static status_t tbox_option_t_check(int argc, char *argv[], char **tool_name)
{
    int32 c = miner_getopt(argc, argv, "T:");
    while (c != -1) {
        if (c == 'T') {
            if (*tool_name != NULL) {
                printf("must secify cminer or crepair or cfunc to use\n");
                CM_FREE_PTR(*tool_name);
                return CT_ERROR;
            }
            *tool_name = (char *)cm_strdup(g_gm_optarg);
            break;
        } else {
            printf("try use \"--help\" for more information.\n");
            CM_FREE_PTR(*tool_name);
            return CT_ERROR;
        }
    }

    if (*tool_name == NULL) {
        printf("try use \"--help\" for more information.\n");
        return CT_ERROR;
    }
    
    return CT_SUCCESS;
}

static status_t tbox_call_miner(int argc, char *argv[])
{
    int32 err_code = 0;
    const char *err_msg = NULL;
    date_t c_start, c_end;
    c_start = cm_now();
    if (miner_execute(argc, argv) != CT_SUCCESS) {
        (void)cm_kmc_finalize();
        cm_get_error(&err_code, &err_msg, NULL);
        printf("Ctbox miner error, CT-%05d, %s\n", err_code, err_msg);
        return CT_ERROR;
    }
    c_end = cm_now();
    printf("Ctbox miner use time %f s\n", (double)(c_end - c_start) / MS_PER_SEC);
    (void)cm_kmc_finalize();
    return CT_SUCCESS;
}

static status_t tbox_call_repair(int argc, char *argv[])
{
    int32 err_code = 0;
    const char *err_msg = NULL;
    status_t status = repair_execute(argc, argv);
    if (status != CT_SUCCESS) {
        cm_get_error(&err_code, &err_msg, NULL);
        printf("Ctbox repair error, CT-%05d, %s\n", err_code, err_msg);
    }
    tbox_write_audit_log(argc, argv, err_code);
    return status;
}

static status_t tbox_call_func(int argc, char *argv[])
{
    int32 err_code = 0;
    const char *err_msg = NULL;
    if (func_execute(argc, argv) != CT_SUCCESS) {
        cm_get_error(&err_code, &err_msg, NULL);
        printf("Ctbox func error, CT-%05d, %s\n", err_code, err_msg);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t tbox_exe_tool_by_tname(int argc, char *argv[], char *tool_name)
{
    if (strcmp(tool_name, "cminer") == 0) {
        return tbox_call_miner(argc, argv);
    } else if (strcmp(tool_name, "crepair") == 0) {
        return tbox_call_repair(argc, argv);
    } else if (strcmp(tool_name, "cfunc") == 0) {
        return tbox_call_func(argc, argv);
    } else {
        printf("invalid tool name : \"%s\"\n", tool_name);
        return CT_ERROR;
    }
}


EXTER_ATTACK int main(int argc, char *argv[])
{
    char *tool_name = NULL;

    if (argc > 1) {
        if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-?") == 0 || strcmp(argv[1], "-h") == 0) {
            usage();
            return CT_SUCCESS;
        }

        if (strcmp(argv[1], "--version") == 0 || strcmp(argv[1], "-V") == 0) {
            tbox_print_version();
            return CT_SUCCESS;
        }

        if (strcmp(argv[1], "-T") != 0) {
            printf("invalid argument : \"%s\"", argv[1]);
            printf("the first option must be -T.\n");
            return CT_SUCCESS;
        }
    }

    status_t ret = tbox_option_t_check(argc, argv, &tool_name);
    if (ret == CT_SUCCESS) {
        cm_str_lower(tool_name);
        ret = tbox_exe_tool_by_tname(argc, argv, tool_name);
    }

    CM_FREE_PTR(tool_name);
    return ret;
}
