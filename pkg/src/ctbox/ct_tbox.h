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
 * ct_tbox.h
 *
 *
 * IDENTIFICATION
 * src/ctbox/ct_tbox.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CTBOX_H__
#define __CTBOX_H__

#include "cm_defs.h"

extern const char *cantiand_get_dbversion(void);
#define TBOX_DATAFILE_VERSION DATAFILE_STRUCTURE_VERSION

static inline void tbox_print_version(void)
{
    printf("Database version: %s\nCtobx datafile version: %u\n",
        cantiand_get_dbversion(), (uint32)TBOX_DATAFILE_VERSION);
}

#endif

