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
 * ctsql_option.h
 *
 *
 * IDENTIFICATION
 * src/utils/ctsql/ctsql_option.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CTSQL_OPTION_H__
#define __CTSQL_OPTION_H__

#include "ctsql.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MATCH_CRT_CER_PEM(path)    (is_match_suffix(path, ".crt") || is_match_suffix(path, ".CRT") ||    \
                                    is_match_suffix(path, ".cer") || is_match_suffix(path, ".CER") ||    \
                                    is_match_suffix(path, ".pem") || is_match_suffix(path, ".PEM"))
#define MATCH_KEY_PEM(path)        (is_match_suffix(path, ".key") || is_match_suffix(path, ".KEY") ||    \
                                    is_match_suffix(path, ".pem") || is_match_suffix(path, ".PEM"))
#define MATCH_CRL_PEM(path)        (is_match_suffix(path, ".crl") || is_match_suffix(path, ".CRL") ||    \
                                    is_match_suffix(path, ".pem") || is_match_suffix(path, ".PEM"))

status_t ctsql_set(text_t *line, text_t *params);
void ctsql_show(text_t *params);
void ctsql_init_ssl_config(void);

#ifdef __cplusplus
}
#endif

#endif /* __CTSQL_OPTION_H__ */