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
 * opr_div.h
 *
 *
 * IDENTIFICATION
 * src/common/variant/opr_div.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __OPR_DIV_H__
#define __OPR_DIV_H__

#include "var_opr.h"

status_t opr_exec_div(opr_operand_set_t *op_set);
status_t opr_type_infer_div(ct_type_t left, ct_type_t right, ct_type_t *result);

#endif
