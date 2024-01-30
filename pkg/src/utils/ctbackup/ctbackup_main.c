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
 * ctbackup_main.c
 *
 *
 * IDENTIFICATION
 * src/utils/ctbackup/ctbackup_main.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctbackup.h"
#include "ctbackup_info.h"

int32 main(int32 argc, char *argv[])
{
    SET_UNHANDLED_EXECEPTION_FILTER(CTBACKUP_NAME);

    CT_RETURN_IFERR(cm_regist_signal(SIGQUIT, SIG_IGN));

    if (argc > 1) {
        if (ctbak_process_args(argc, argv) != CT_SUCCESS) {
            ctbackup_show_help();
            exit(EXIT_FAILURE);
        }
    }
    exit(EXIT_SUCCESS);
}
