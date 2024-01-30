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
 * cm_nls.c
 *
 *
 * IDENTIFICATION
 * src/common/cm_nls.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_common_module.h"
#include "cm_nls.h"

#ifdef __cplusplus
extern "C" {
#endif

/** one to one corresponding to nlsparam_id_t, for managing NLS parameters */
const nlsparam_item_t g_nlsparam_items[] = {
    [NLS_CALENDAR] = { NLS_CALENDAR,            { "NLS_CALENDAR", 12 }, CT_FALSE, CT_FALSE, CT_FALSE, NULL },
    [NLS_CHARACTERSET] = { NLS_CHARACTERSET,        { "NLS_CHARACTERSET", 16 }, CT_FALSE, CT_FALSE, CT_FALSE, NULL },
    [NLS_COMP] = { NLS_COMP,                { "NLS_COMP", 8 }, CT_FALSE, CT_FALSE, CT_FALSE, NULL },
    [NLS_CURRENCY] = { NLS_CURRENCY,            { "NLS_CURRENCY", 12 }, CT_FALSE, CT_FALSE, CT_FALSE, NULL },
    [NLS_DATE_FORMAT] = { NLS_DATE_FORMAT,         { "NLS_DATE_FORMAT", 15 }, CT_TRUE, CT_FALSE, CT_FALSE, cm_verify_date_fmt },
    [NLS_DATE_LANGUAGE] = { NLS_DATE_LANGUAGE,       { "NLS_DATE_LANGUAGE", 17 }, CT_FALSE, CT_FALSE, CT_FALSE, NULL },
    [NLS_DUAL_CURRENCY] = { NLS_DUAL_CURRENCY,       { "NLS_DUAL_CURRENCY", 17 }, CT_FALSE, CT_FALSE, CT_FALSE, NULL },
    [NLS_ISO_CURRENCY] = { NLS_ISO_CURRENCY,        { "NLS_ISO_CURRENCY", 16 }, CT_FALSE, CT_FALSE, CT_FALSE, NULL },
    [NLS_LANGUAGE] = { NLS_LANGUAGE,            { "NLS_LANGUAGE", 12 }, CT_FALSE, CT_FALSE, CT_FALSE, NULL },
    [NLS_LENGTH_SEMANTICS] = { NLS_LENGTH_SEMANTICS,    { "NLS_LENGTH_SEMANTICS", 20 }, CT_FALSE, CT_FALSE, CT_FALSE, NULL },
    [NLS_NCHAR_CHARACTERSET] = { NLS_NCHAR_CHARACTERSET,  { "NLS_NCHAR_CHARACTERSET", 22 }, CT_FALSE, CT_FALSE, CT_FALSE, NULL },
    [NLS_NCHAR_CONV_EXCP] = { NLS_NCHAR_CONV_EXCP,     { "NLS_NCHAR_CONV_EXCP", 19 }, CT_FALSE, CT_FALSE, CT_FALSE, NULL },
    [NLS_NUMERIC_CHARACTERS] = { NLS_NUMERIC_CHARACTERS,  { "NLS_NUMERIC_CHARACTERS", 22 }, CT_FALSE, CT_FALSE, CT_FALSE, NULL },
    [NLS_RDBMS_VERSION] = { NLS_RDBMS_VERSION,       { "NLS_RDBMS_VERSION", 17 }, CT_FALSE, CT_FALSE, CT_FALSE, NULL },
    [NLS_SORT] = { NLS_SORT,                { "NLS_SORT", 8 }, CT_FALSE, CT_FALSE, CT_FALSE, NULL },
    [NLS_TERRITORY] = { NLS_TERRITORY,           { "NLS_TERRITORY", 13 }, CT_FALSE, CT_FALSE, CT_FALSE, NULL },
    [NLS_TIMESTAMP_FORMAT] = { NLS_TIMESTAMP_FORMAT,    { "NLS_TIMESTAMP_FORMAT", 20 }, CT_TRUE, CT_FALSE, CT_FALSE, cm_verify_timestamp_fmt },
    [NLS_TIMESTAMP_TZ_FORMAT] = { NLS_TIMESTAMP_TZ_FORMAT, { "NLS_TIMESTAMP_TZ_FORMAT", 23 }, CT_TRUE, CT_FALSE, CT_FALSE, NULL },
    [NLS_TIME_FORMAT] = { NLS_TIME_FORMAT,         { "NLS_TIME_FORMAT", 15 }, CT_TRUE, CT_FALSE, CT_FALSE, NULL },
    [NLS_TIME_TZ_FORMAT] = { NLS_TIME_TZ_FORMAT,      { "NLS_TIME_TZ_FORMAT", 18 }, CT_TRUE, CT_FALSE, CT_FALSE, NULL },
};

const nlsparams_t g_default_session_nlsparams = {
    {
        [NLS_DATE_FORMAT] = { "YYYY-MM-DD HH24:MI:SS",            21 },
        [NLS_TIMESTAMP_FORMAT] = { "YYYY-MM-DD HH24:MI:SS.FF",         24 },
        [NLS_TIMESTAMP_TZ_FORMAT] = { "YYYY-MM-DD HH24:MI:SS.FF TZH:TZM", 32 },
        [NLS_TIME_FORMAT] = { "HH:MI:SS.FF AM",                   14 },
        [NLS_TIME_TZ_FORMAT] = { "HH:MI:SS.FF AM TZR",               18 },
    },
    cm_session_nlsparam_geter,
    TIMEZONE_OFFSET_DEFAULT,
};

void cm_session_nlsparam_geter(const nlsparams_t *nls, nlsparam_id_t id, text_t *text)
{
    CM_ASSERT((uint32)id < NLS__MAX_PARAM_NUM);
    CM_ASSERT(g_nlsparam_items[id].ss_used);
    cm_nlsvalue2text(&nls->nlsvalues[id], text);
}

status_t cm_session_nls_seter(nlsparams_t *params, nlsparam_id_t id, const text_t *param_value)
{
    const nlsparam_item_t *item = NULL;

    // Step 1. Find the NLS option
    if ((uint32)id >= NLS__MAX_PARAM_NUM) {
        CT_THROW_ERROR_EX(ERR_ASSERT_ERROR, "id(%u) < NLS__MAX_PARAM_NUM(%u)", (uint32)id, (uint32)NLS__MAX_PARAM_NUM);
        return CT_ERROR;
    }
    item = &g_nlsparam_items[id];
    if (!item->ss_used) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER_NAME, T2S(&item->key));
        return CT_ERROR;
    }

    // Step 2. Verify the input parameter
    if (param_value->len >= MAX_NLS_PARAM_LENGTH) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, T2S(&item->key), (int64)MAX_NLS_PARAM_LENGTH);
        return CT_ERROR;
    }
    if (item->verifier != NULL) {
        if (item->verifier(param_value) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    // Step 3. Set the value
    CM_SET_NLSPARAM(&(params->nlsvalues[id]), param_value);
    return CT_SUCCESS;
}

#ifdef __cplusplus
}

#endif