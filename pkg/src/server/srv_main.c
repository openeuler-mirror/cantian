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
 * srv_main.c
 *
 *
 * IDENTIFICATION
 * src/server/srv_main.c
 *
 * -------------------------------------------------------------------------
 */
#include "srv_module.h"
#include "cm_defs.h"
#include "cm_file.h"
#include "srv_instance.h"
#include "cm_coredump.h"
#include "upgrade_struct_check.h"
#include <malloc.h>

typedef struct st_setup_assit {
    db_startup_phase_t start_mode;
    bool32 is_coordinator;
    bool32 is_datanode;
    bool32 is_gts;
} setup_assist_t;

static inline int srv_find_arg(int argc, char * const argv[], const char *find_arg)
{
    for (int i = 1; i < argc; i++) {
        if (cm_str_equal_ins(argv[i], find_arg)) {
            return i;
        }
    }
    return 0;
}

#define CT_MAX_CANTIAND_ARG 5

#ifdef __CANTIAND_CN__
static void srv_usage()
{
    printf("Usage: cantiand [OPTION]\n"
        "   Or: cantiand [-h|-H]\n"
        "   Or: cantiand [-v|-V]\n"
        "   Or: cantiand [mode]\n"
        "   Or: cantiand [mode] -D db_home_path\n"
        "   Or: cantiand [mount/open] [node_type] -D db_home_path\n"
        "Option:\n"
        "\t -h/-H                 show the help information.\n"
        "\t -v/-V                 show version information.\n"
        "\t mode                  specify database starting mode, nomount/mount/open, default open.\n"
        "\t -D                    specify database home path.\n"
        "\t node_type             specify sharding node type, --datanode/--coordinator/--gtsnode.\n");
}

static status_t srv_check_args(int argc, char * const argv[])
{
    int32 i = 1;

    if (argc > CT_MAX_CANTIAND_ARG) {
        printf("too many argument\n");
        return CT_ERROR;
    }

    while (i < argc) {
        if (strcmp(argv[i], "nomount") == 0) {
        } else if (strcmp(argv[i], "mount") == 0) {
        } else if (strcmp(argv[i], "open") == 0) {
        } else if (cm_str_equal_ins(argv[i], "--coordinator")) {
        } else if (cm_str_equal_ins(argv[i], "--datanode")) {
        } else if (cm_str_equal_ins(argv[i], "--gtsnode")) {
        } else if ((strcmp(argv[i], "-D") == 0)) { /* cantiandb nomount/mount/open -D specified_path */
            if (i + 1 >= argc) {
                printf("invalid argument: %s\n", argv[i]);
                return CT_ERROR;
            }
            i++;
            int len = (int)strlen((char *)argv[i]);
            if (len <= 1 || len >= (CT_MAX_PATH_LEN - 1)) {
                printf("invalid argument: %s %s\n", argv[i - 1], argv[i]);
                return CT_ERROR;
            }
        } else {
            printf("invalid argument: %s\n", argv[i]);
            return CT_ERROR;
        }

        i++;
    }

    return CT_SUCCESS;
}

static status_t srv_process_node_type_args(int argc, char *argv[], setup_assist_t *assist)
{
    int pos = srv_find_arg(argc, argv, "--coordinator");
    assist->is_coordinator = pos > 0 ? CT_TRUE : CT_FALSE;
    pos = srv_find_arg(argc, argv, "--datanode");
    assist->is_datanode = pos > 0 ? CT_TRUE : CT_FALSE;
    pos = srv_find_arg(argc, argv, "--gtsnode");
    assist->is_gts = pos > 0 ? CT_TRUE : CT_FALSE;

    if (assist->is_coordinator + assist->is_datanode + assist->is_gts > 1) {
        printf("invalid argument: the database node_type should be --coordinator or --datanode or --gtsnode.\n");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

#else
static void srv_usage(void)
{
    printf("Usage: cantiand [OPTION]\n"
        "   Or: cantiand [-h|-H]\n"
        "   Or: cantiand [-v|-V]\n"
        "   Or: cantiand [mode]\n"
        "   Or: cantiand [mode] -D db_home_path\n"
        "   Or: cantiand [mount/open] -D db_home_path\n"
        "Option:\n"
        "\t -h/-H                 show the help information.\n"
        "\t -v/-V                 show version information.\n"
        "\t mode                  specify database starting mode, nomount/mount/open, default open.\n"
        "\t -D                    specify database home path.\n"
        "\t node_type             specify node type, --datanode.\n");
}

static status_t srv_check_args(int argc, char * const argv[])
{
    int32 i = 1;

    if (argc > CT_MAX_CANTIAND_ARG) {
        printf("too many argument\n");
        return CT_ERROR;
    }

    while (i < argc) {
        if (strcmp(argv[i], "nomount") == 0) {
        } else if (strcmp(argv[i], "mount") == 0) {
        } else if (strcmp(argv[i], "open") == 0) {
        } else if (cm_str_equal_ins(argv[i], "--datanode")) {
        } else if ((strcmp(argv[i], "-D") == 0)) { /* cantiandb nomount/mount/open -D specified_path */
            if (i + 1 >= argc) {
                printf("invalid argument: %s\n", argv[i]);
                return CT_ERROR;
            }
            i++;
            int len = (int)strlen((char *)argv[i]);
            if (len <= 1 || len >= (CT_MAX_PATH_LEN - 1)) {
                printf("invalid argument: %s %s\n", argv[i - 1], argv[i]);
                return CT_ERROR;
            }
        } else {
            printf("invalid argument: %s\n", argv[i]);
            return CT_ERROR;
        }

        i++;
    }

    return CT_SUCCESS;
}

static status_t srv_process_node_type_args(int argc, char *argv[], setup_assist_t *assist)
{
    int pos = srv_find_arg(argc, argv, "--datanode");
    assist->is_datanode = pos > 0 ? CT_TRUE : CT_FALSE;
    return CT_SUCCESS;
}
#endif

static status_t srv_process_setup_args(int argc, char *argv[], setup_assist_t *assist)
{
    if (srv_process_node_type_args(argc, argv, assist) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (srv_find_arg(argc, argv, "nomount")) {
        assist->start_mode = STARTUP_NOMOUNT;
        if (assist->is_coordinator || assist->is_datanode || assist->is_gts) {
            printf("invalid argument: the database is initializing for nomount, --datanode or "
                "--coordinator  or --gtsnode are not allowed.\n");
            return CT_ERROR;
        }
    } else if (srv_find_arg(argc, argv, "mount")) {
        assist->start_mode = STARTUP_MOUNT;
    } else {
        assist->start_mode = STARTUP_OPEN;
    }

    int pos = srv_find_arg(argc, argv, "-D");
    if (pos > 0 && (pos + 1) < argc) {
        g_database_home = argv[pos + 1];
    }

    return CT_SUCCESS;
}

static status_t srv_startup(int argc, char *argv[])
{
    setup_assist_t assist;

    assist.start_mode = STARTUP_OPEN;
    assist.is_coordinator = CT_FALSE;
    assist.is_datanode = CT_FALSE;
    assist.is_gts = CT_FALSE;

    if (argc > 1) {
        CT_RETURN_IFERR(srv_check_args(argc, argv));
        CT_RETURN_IFERR(srv_process_setup_args(argc, argv, &assist));
    }

    return srv_instance_startup(assist.start_mode, assist.is_coordinator, assist.is_datanode, assist.is_gts);
}

#ifdef WIN32
char *cantiand_get_dbversion()
{
    return "NONE";
}
#else
extern char *cantiand_get_dbversion(void);
#endif

static inline void srv_print_version(void)
{
    printf("%s\n", cantiand_get_dbversion());
}

#define CT_ARENA_MAX 32

static inline void set_mallopt()
{
#ifndef WITH_DAAC
    (void)mallopt(M_ARENA_MAX, 1);
#else
    // only for mysql + daac in one process mode
    (void)mallopt(M_ARENA_MAX, CT_ARENA_MAX);
#endif
}

static inline void cantiand_pre_exit(void)
{
    srv_unlock_db();
}

EXTER_ATTACK int32 cantiand_lib_main(int argc, char *argv[])
{
    SET_UNHANDLED_EXECEPTION_FILTER("cantiand");

#ifndef WIN32

    set_mallopt();

    // make a copy for arg and environment value since we may change the process title
    if (save_origin_argument(argc, &argv) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Aborted due to resave the argv and environ");
        printf("instance startup failed\n");
        fflush(stdout);
        return CT_ERROR;
    }

    // check root
    if (geteuid() == 0 || getuid() != geteuid()) {
        printf("The root user is not permitted to execute the cantiand server "
            "and the real uids must be the same as the effective uids.\n");
        fflush(stdout);
        return CT_ERROR;
    }
#endif

    if (argc == 2) {
        if (strcmp(argv[1], "-v") == 0 || strcmp(argv[1], "-V") == 0) {
            srv_print_version();
            return CT_SUCCESS;
        } else if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "-H") == 0) {
            srv_usage();
            return CT_SUCCESS;
        }
    }

    log_param_t *log_param = cm_log_param_instance();
    log_param->log_instance_startup = CT_FALSE;

    cm_init_error_handler(cm_set_srv_error);
    cm_set_hook_pre_exit(cantiand_pre_exit);

    if (srv_startup(argc, argv) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Instance Startup Failed");
        printf("instance startup failed\n");
        fflush(stdout);
        return CT_ERROR;
    }

    log_param->log_instance_startup = CT_FALSE;

    if (srv_instance_loop() != CT_SUCCESS) {
        cm_unlock_fd(g_instance->lock_fd);
        cm_close_file(g_instance->lock_fd);
        printf("instance exit\n");
        fflush(stdout);
        return CT_ERROR;
    }

    cm_unlock_fd(g_instance->lock_fd);
    cm_close_file(g_instance->lock_fd);
    return CT_SUCCESS;
}

EXTER_ATTACK int32 main(int argc, char *argv[])
{
    return cantiand_lib_main(argc, argv);
}
