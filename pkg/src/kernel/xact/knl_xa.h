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
 * knl_xa.h
 *
 *
 * IDENTIFICATION
 * src/kernel/xact/knl_xa.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_XA_H__
#define __KNL_XA_H__

#include "knl_page.h"
#include "knl_session.h"
#include "knl_log.h"
#include "knl_xa_persist.h"

static inline char *xa_status2str(xa_status_t status)
{
    switch (status) {
        case XA_START:
            return "START";
        case XA_SUSPEND:
            return "SUSPEND";
        case XA_PHASE1:
            return "PREPAREING";
        case XA_PENDING:
            return "PREPARED";
        case XA_PHASE2:
            return "ENDING PREPARED";
        case XA_INVALID:
            return "INVALID";
        default:
            return "INVALID XA STATUS";
    }
}

#endif

