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
 * cm_nls.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_nls.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __CM_NLS_H__
#define __CM_NLS_H__

#include "cm_defs.h"
#include "cm_text.h"
#include "cm_date.h"

#ifdef WIN32
#else
#include <string.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif
/*
* @addtogroup NLS
* @brief The head file for cantian's Globalization of Language --
*       National Language Support
* The support session parameter id */
typedef enum en_nlsparam_id {
    NLS_CALENDAR = 0,
    NLS_CHARACTERSET,
    NLS_COMP,
    NLS_CURRENCY,
    NLS_DATE_FORMAT,
    NLS_DATE_LANGUAGE,
    NLS_DUAL_CURRENCY,
    NLS_ISO_CURRENCY,
    NLS_LANGUAGE,
    NLS_LENGTH_SEMANTICS,
    NLS_NCHAR_CHARACTERSET,
    NLS_NCHAR_CONV_EXCP,
    NLS_NUMERIC_CHARACTERS,
    NLS_RDBMS_VERSION,
    NLS_SORT,
    NLS_TERRITORY,
    NLS_TIMESTAMP_FORMAT,
    NLS_TIMESTAMP_TZ_FORMAT,
    NLS_TIME_FORMAT,
    NLS_TIME_TZ_FORMAT,
    NLS__MAX_PARAM_NUM /* do not use it as parameter id */
} nlsparam_id_t;

typedef status_t (*cm_nlsparam_verifier)(const text_t *param_value);

typedef struct st_nlsparam_item {
    nlsparam_id_t id;
    text_t key;
    bool32 ss_used; /* refer to session_param_id */
    bool32 ins_used;
    bool32 db_used;
    cm_nlsparam_verifier verifier;
} nlsparam_item_t;

extern const nlsparam_item_t g_nlsparam_items[NLS__MAX_PARAM_NUM];

#define MAX_NLS_PARAM_LENGTH 60
typedef struct st_nlstext {
    char str[MAX_NLS_PARAM_LENGTH];
    uint32 len;
} nlsvalue_t;

typedef struct st_nlsparams nlsparams_t;
typedef void (*cm_nlsparam_geter)(const nlsparams_t *params, nlsparam_id_t id, text_t *text);
struct st_nlsparams {
    nlsvalue_t         nlsvalues[NLS__MAX_PARAM_NUM];
    cm_nlsparam_geter  param_geter;
    timezone_info_t    client_timezone;  // client timezone for "SESSIONTIMEZONE"
};

/*
 * this function is used to get current session timezone
 */
static inline timezone_info_t cm_get_session_time_zone(const nlsparams_t* nls_params)
{
    return nls_params->client_timezone;
}
    
typedef struct st_nls_setting_def {
    nlsparam_id_t id;
    text_t value;
} nls_setting_def_t;

#define CM_SET_NLSPARAM(nls_val, text_val)                             \
    do {                                                               \
        nlsvalue_t *__nls_val = nls_val;                               \
        GS_RETURN_IFERR(cm_text2str((text_val), __nls_val->str, MAX_NLS_PARAM_LENGTH)); \
        __nls_val->len = (uint32)strlen(__nls_val->str);                       \
    } while (0)

void cm_session_nlsparam_geter(const nlsparams_t *nls, nlsparam_id_t id, text_t *text);
status_t cm_session_nls_seter(nlsparams_t *params, nlsparam_id_t id, const text_t *param_value);

static inline void cm_nlsvalue2text(const nlsvalue_t *nls_text, text_t *text)
{
    text->str = (char *)nls_text->str;
    text->len = nls_text->len;
}

static inline status_t cm_text2nlsvalue(const text_t *text, nlsvalue_t *nls_text)
{
    errno_t errcode = strncpy_s(nls_text->str, MAX_NLS_PARAM_LENGTH, text->str, text->len);
    if (SECUREC_UNLIKELY(errcode != EOK)) {
        GS_THROW_ERROR(ERR_CLT_INVALID_VALUE, "text2nlsvalue error", (uint32)errcode);
        return GS_ERROR;
    }
    nls_text->len = text->len;
    return GS_SUCCESS;
}

extern const nlsparams_t g_default_session_nlsparams;

#define GS_DEFALUT_SESSION_NLS_PARAMS (&g_default_session_nlsparams)

static inline status_t cm_init_session_nlsparams(nlsparams_t *params)
{
    MEMS_RETURN_IFERR(memcpy_sp(params, sizeof(nlsparams_t), &g_default_session_nlsparams, sizeof(nlsparams_t)));
    return GS_SUCCESS;
}

static inline void cm_default_nls_geter(nlsparam_id_t id, text_t *fmt_text)
{
    g_default_session_nlsparams.param_geter(&g_default_session_nlsparams, id, fmt_text);
}

/** @} */  // end group NLS
#ifdef __cplusplus
}
#endif

#endif  // end __CM_NLS_H__
