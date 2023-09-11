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
 * gs_tbox.c
 *
 *
 * IDENTIFICATION
 * src/gstbox/gs_tbox.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_date.h"
#include "gs_miner.h"
#include "gs_repair.h"
#include "gs_func.h"
#include "cm_kmc.h"
#include "gs_tbox.h"
#include "gs_tbox_audit.h"
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
    printf("ztbox contains zminer, zrepair and zfunc tools for Z-engine.\n"
           "\n"
           "Usage:\n"
           "  ztbox -T [zminer | zrepair | zfunc] [OPTIONS]\n"
           "\nRequired options:\n"
           "  -T TOOLNAME  the zminer tool, zrepair tool or zfunc tool to use\n");

    printf("\nCommon options:\n"
           "  --help, -h       show this help, then exit\n"
           "  --version, -V    output version information, then exit\n"
           "\nExamples:\n"
           "  ztbox --help\n"
           "  ztbox -T zminer  --help\n"
           "  ztbox -T zrepair --help\n"
           "  ztbox -T zfunc   --help\n"
           "  ztbox -T zminer  -l XXX\n"
           "  ztbox -T zrepair -f XXX -s XXX -t XXX\n"
           "  ztbox -T zfunc   -f int2pageid XXX\n");
}

static status_t tbox_option_t_check(int argc, char *argv[], char **tool_name)
{
    int32 c = miner_getopt(argc, argv, "T:");
    while (c != -1) {
        if (c == 'T') {
            if (*tool_name != NULL) {
                printf("must secify zminer or zrepair or zfunc to use\n");
                CM_FREE_PTR(*tool_name);
                return GS_ERROR;
            }
            *tool_name = (char *)cm_strdup(g_gm_optarg);
            break;
        } else {
            printf("try use \"--help\" for more information.\n");
            CM_FREE_PTR(*tool_name);
            return GS_ERROR;
        }
    }

    if (*tool_name == NULL) {
        printf("try use \"--help\" for more information.\n");
        return GS_ERROR;
    }
    
    return GS_SUCCESS;
}

static status_t tbox_call_miner(int argc, char *argv[])
{
    int32 err_code = 0;
    const char *err_msg = NULL;
    date_t c_start, c_end;
    c_start = cm_now();
    if (miner_execute(argc, argv) != GS_SUCCESS) {
        (void)cm_kmc_finalize();
        cm_get_error(&err_code, &err_msg, NULL);
        printf("Ztbox miner error, CT-%05d, %s\n", err_code, err_msg);
        return GS_ERROR;
    }
    c_end = cm_now();
    printf("Ztbox miner use time %f s\n", (double)(c_end - c_start) / MS_PER_SEC);
    (void)cm_kmc_finalize();
    return GS_SUCCESS;
}

static status_t tbox_call_repair(int argc, char *argv[])
{
    int32 err_code = 0;
    const char *err_msg = NULL;
    status_t status = repair_execute(argc, argv);
    if (status != GS_SUCCESS) {
        cm_get_error(&err_code, &err_msg, NULL);
        printf("Ztbox repair error, CT-%05d, %s\n", err_code, err_msg);
    }
    tbox_write_audit_log(argc, argv, err_code);
    return status;
}

static status_t tbox_call_func(int argc, char *argv[])
{
    int32 err_code = 0;
    const char *err_msg = NULL;
    if (func_execute(argc, argv) != GS_SUCCESS) {
        cm_get_error(&err_code, &err_msg, NULL);
        printf("Ztbox func error, CT-%05d, %s\n", err_code, err_msg);
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

static status_t tbox_exe_tool_by_tname(int argc, char *argv[], char *tool_name)
{
    if (strcmp(tool_name, "zminer") == 0) {
        return tbox_call_miner(argc, argv);
    } else if (strcmp(tool_name, "zrepair") == 0) {
        return tbox_call_repair(argc, argv);
    } else if (strcmp(tool_name, "zfunc") == 0) {
        return tbox_call_func(argc, argv);
    } else {
        printf("invalid tool name : \"%s\"\n", tool_name);
        return GS_ERROR;
    }
}


EXTER_ATTACK int main(int argc, char *argv[])
{
    char *tool_name = NULL;

    if (argc > 1) {
        if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-?") == 0 || strcmp(argv[1], "-h") == 0) {
            usage();
            return GS_SUCCESS;
        }

        if (strcmp(argv[1], "--version") == 0 || strcmp(argv[1], "-V") == 0) {
            tbox_print_version();
            return GS_SUCCESS;
        }

        if (strcmp(argv[1], "-T") != 0) {
            printf("invalid argument : \"%s\"", argv[1]);
            printf("the first option must be -T.\n");
            return GS_SUCCESS;
        }
    }

    status_t ret = tbox_option_t_check(argc, argv, &tool_name);
    if (ret == GS_SUCCESS) {
        cm_str_lower(tool_name);
        ret = tbox_exe_tool_by_tname(argc, argv, tool_name);
    }

    CM_FREE_PTR(tool_name);
    return ret;
}
