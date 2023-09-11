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
 * cm_util.c
 *
 *
 * IDENTIFICATION
 * src/common/cm_util.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_util.h"
#include "cm_regexp.h"

#ifdef __cplusplus
extern "C" {
#endif

keyword_map_item_t g_key_pattern[] = {
    // create database link identified by
    { "CREATE.*?\\s*.*?DATABASE.*?\\s*.*?LINK.*?\\s*.*?IDENTIFIED.*?\\s*.*?BY", "SQL CONTAINS:CREATE DATABASE LINK" },
    // alter database link identified by
    { "ALTER.*?\\s*.*?DATABASE.*?\\s*.*?LINK.*?\\s*.*?IDENTIFIED.*?\\s*.*?BY", "SQL CONTAINS:ALTER DATABASE LINK" },
    // create database identified by
    { "CREATE.*?\\s*.*?DATABASE.*?\\s*.*?IDENTIFIED.*?\\s*.*?BY",      "SQL CONTAINS:CREATE DATABASE" },
    // create role/user identified by
    { "CREATE.*?\\s*.*?IDENTIFIED.*?\\s*.*?BY",                        "SQL CONTAINS:CREATE USER OR ROLE" },
    // alter role/user identified by
    { "ALTER.*?\\s*.*?IDENTIFIED.*?\\s*.*?BY",                         "SQL CONTAINS:ALTER USER OR ROLE" },
    // create node  user ='' pwd  = ''
    { "CREATE.*?\\s*.*?NODE[\\s\\S]*?PASSWORD",                        "SQL CONTAINS:CREATE NODE" },
    // alter node   pwd  = ''
    { "ALTER.*?\\s*.*?NODE[\\s\\S]*?PASSWORD",                         "SQL CONTAINS:ALTER NODE" },
    // set CTCLIENT_SSL_KEY_PWD =
    { "SET.*?\\s*.*?CTCLIENT_SSL_KEY_PASSWD",                              "SQL CONTAINS:SET CTCLIENT_SSL_KEY_PASSWD" },
    // conn user/pwd
    { "CONN.*?\\s*.*?/",                                               "SQL CONTAINS:CONN" },
    // connect user/pwd
    { "CONNECT.*?\\s*.*?/",                                            "SQL CONTAINS:CONNECT" },
    // alter system set _fatctor_key =
    { "SET.*?\\s*.*?_FACTOR_KEY",                                      "SQL CONTAINS:ALTER SYSTEM SET _FACTOR_KEY" },
    // alter system set local_key =
    { "SET.*?\\s*.*?LOCAL_KEY",                                        "SQL CONTAINS:ALTER SYSTEM SET LOCAL_KEY" },
    // alter system set ssl_key_pwd =
    { "SET.*?\\s*.*?SSL_KEY_PASSWORD",                                 "SQL CONTAINS:ALTER SYSTEM SET SSL_KEY_PASSWORD" },
    // alter system set _ENCRYPTION_ALG =
    { "SET.*?\\s*.*?_ENCRYPTION_ALG",                                  "SQL CONTAINS:ALTER SYSTEM SET _ENCRYPTION_ALG" },
    // alter system set _SYS_PWD =
    { "SET.*?\\s*.*?_SYS_PASSWORD",                                    "SQL CONTAINS:ALTER SYSTEM SET _SYS_PASSWORD" },
    // backup database
    { "BACKUP.*?\\s*.*?DATABASE.*?\\s*.*?PASSWORD",                    "SQL CONTAINS:BACKUP DATABASE" },
    // restore database
    { "RESTORE.*?\\s*.*?DATABASE.*?\\s*.*?FROM.*?\\s*.*?PASSWORD",     "SQL CONTAINS:RESTORE DATABASE" },
    // dump encrypt file
    { "DUMP\\s+.*?ENCRYPT.*?\\s*.*?BY",                                "SQL CONTAINS:DUMP ENCRYPT" },
    // load decrypt file
    { "LOAD\\s+.*?DECRYPT.*?\\s*.*?BY",                                "SQL CONTAINS:LOAD DECRYPT" },
    // exp encrypt file
    { "EXP.*?\\s*.*?ENCRYPT.*?\\s*.*?=",                               "SQL CONTAINS:EXP OR EXPORT ENCRYPT" },
    // imp decrypt file
    { "IMP.*?\\s*.*?DECRYPT.*?\\s*.*?=",                               "SQL CONTAINS:IMP OR IMPORT DECRYPT" },
};

#define KEY_PATTERN_COUNT (sizeof(g_key_pattern) / sizeof(keyword_map_item_t))

void cm_text_reg_match(text_t *text, const char *pattern, int32 *pos, charset_type_t charset)
{
    void *code = NULL;
    text_t match_param = { .str = "i", .len = 1 };  // ignore case
    regexp_substr_assist_t assist = { .code = code, .subject = *text, .offset = 0,
        .occur = 1, .subexpr = 0, .charset = charset };

    if (GS_SUCCESS != cm_regexp_compile(&code, pattern, &match_param, charset)) {
        return;
    }

    assist.code = code;
    if (GS_SUCCESS != cm_regexp_instr(pos, &assist, GS_TRUE)) {
        cm_regexp_free(code);
        return;
    }

    cm_regexp_free(code);
}

static inline void cm_get_star_pos(text_t *text, bool32 end, uint32 *comm_pos, charset_type_t charset)
{
    int32 pos;
    char pattern[] = { "[*]{2,}" };
    void *code = NULL;
    text_t match_param = { .str = "i", .len = 1 };  // ignore case
    regexp_substr_assist_t assist = { .code = code, .subject = *text, .offset = 0,
        .occur = 1, .subexpr = 0, .charset = charset };

    pos = 0;  // init pos
    if (GS_SUCCESS != cm_regexp_compile(&code, pattern, &match_param, charset)) {
        return;
    }

    assist.code = code;
    if (GS_SUCCESS != cm_regexp_instr(&pos, &assist, end)) {
        cm_regexp_free(code);
        return;
    }

    cm_regexp_free(code);

    // if matched,return pos ,get mattch type
    if (pos != 0) {
        *comm_pos = (uint32)(pos - 1);
        return;
    }

    return;
}

void cm_text_star_to_one(text_t *text)
{
    uint32 start, end, len;
    text_t left_text = *text;

    for (;;) {
        if (left_text.len > 0) {
            start = 0;
            end = 0;

            // try get star end pos, use GBK without UTF check.
            cm_get_star_pos(&left_text, GS_TRUE, &end, CHARSET_GBK);

            // not find star,first find end pos,start pos may be at 0
            if (end == 0) {
                return;
            }

            // get star start pos, use GBK without UTF check.
            cm_get_star_pos(&left_text, GS_FALSE, &start, CHARSET_GBK);
            len = (end - start);

            left_text.str = left_text.str + start;
            left_text.len = text->len - (uint32)(left_text.str - text->str);

            if (len < left_text.len) {
                // keep one *
                MEMS_RETVOID_IFERR(memmove_s(left_text.str + 1, left_text.len - len, left_text.str + len,
                                             left_text.len - len));
            }
            left_text.str = left_text.str + 1;    // skip the keyword ' '
            left_text.len = left_text.len - len;  // set star len  to len
            text->len -= (len - 1);               // text->len change to (text->len - len + * )
        } else {
            return;
        }
    }
}

void cm_text_try_map_key2type(const text_t *text, int32 *matched_pat_id, bool32 *matched)
{
    int32 i;
    int32 pos = 0;
    text_t left_text = *text;

    // try to match pattern
    for (i = 0; i < KEY_PATTERN_COUNT; i++) {
        // use GBK to ignore UTF8 check.
        cm_text_reg_match(&left_text, g_key_pattern[i].keyword_pattern, &pos, CHARSET_GBK);
        if (pos != 0) {
            *matched = GS_TRUE;
            *matched_pat_id = i;
            break;
        }
    }

    return;
}

#ifdef __cplusplus
}
#endif
