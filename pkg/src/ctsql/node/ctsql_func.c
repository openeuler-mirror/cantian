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
 * ctsql_func.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/node/ctsql_func.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctsql_func.h"
#include "ctsql_scan.h"
#include "ctsql_package.h"
#include "ctsql_proj.h"
#include "ctsql_json.h"
#include "ctsql_jsonb.h"
#include "func_calculate.h"
#include "func_string.h"
#include "func_aggr.h"
#include "func_interval.h"
#include "func_date.h"
#include "func_regexp.h"
#include "func_hex.h"
#include "func_convert.h"
#include "func_group.h"
#include "func_others.h"
#include "dtc_drc.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SQL_FUNC_COUNT ELEMENT_COUNT(g_func_tab)

/*
 * **NOTE:**
 * 1. The function must be arranged by alphabetical ascending order.
 * 2. An enum stands for function index was added in ctsql_func.h for z_sharding.
 * if any built-in function added or removed from the following array,
 * please modify the enum definition, too.
 * 3. add function should add the define id in en_function_item_id at ctsql_func.h.
 */
/* **NOTE:** The function must be arranged by alphabetical ascending order. */
sql_func_t g_func_tab[] = {
    { { (char *)"abs", 3 }, sql_func_abs, sql_verify_abs, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_ABS, FO_USUAL, CT_TRUE },
    { { (char *)"acos", 4 }, sql_func_acos, sql_verify_trigonometric, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_ACOS, FO_USUAL, CT_FALSE },
    { { (char *)"add_months", 10 }, sql_func_add_months, sql_verify_add_months, AGGR_TYPE_NONE, FO_SPECIAL, ID_FUNC_ITEM_ADD_MONTHS, FO_USUAL, CT_FALSE },
    { { (char *)"approx_count_distinct", 21 }, sql_func_approx_count_distinct, sql_verify_approx_count_distinct, AGGR_TYPE_APPX_CNTDIS, FO_NONE, ID_FUNC_ITEM_APPX_CNTDIS, FO_USUAL, CT_FALSE },
    { { (char *)"array_agg", 9 }, sql_func_array_agg, sql_verify_array_agg, AGGR_TYPE_ARRAY_AGG, FO_NONE, ID_FUNC_ITEM_ARRAY_AGG, FO_USUAL, CT_FALSE },
    { { (char *)"array_length", 12 }, sql_func_array_length, sql_verify_array_length, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_ARRAY_LENGTH, FO_USUAL, CT_FALSE },
    { { (char *)"ascii", 5 }, sql_func_ascii, sql_verify_ascii, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_ASCII, FO_USUAL, CT_FALSE },
    { { (char *)"asciistr", 8 }, sql_func_asciistr, sql_verify_asciistr, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_ASCIISTR, FO_USUAL, CT_FALSE },
    { { (char *)"asin", 4 }, sql_func_asin, sql_verify_trigonometric, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_ASIN, FO_USUAL, CT_FALSE },
    { { (char *)"atan", 4 }, sql_func_atan, sql_verify_trigonometric, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_ATAN, FO_USUAL, CT_FALSE },
    { { (char *)"atan2", 5 }, sql_func_atan2, sql_verify_atan2, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_ATAN2, FO_USUAL, CT_FALSE },
    { { (char *)"avg", 3 }, sql_func_normal_aggr, sql_verify_avg, AGGR_TYPE_AVG, FO_NONE, ID_FUNC_ITEM_AVG, FO_USUAL, CT_FALSE },
    { { (char *)"bin2hex", 7 }, sql_func_bin2hex, sql_verify_bin2hex, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_BIN2HEX, FO_USUAL, CT_FALSE },
    { { (char *)"bitand", 6 }, sql_func_bit_and, sql_verify_bit_func, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_BITAND, FO_USUAL, CT_FALSE },
    { { (char *)"bitor", 5 }, sql_func_bit_or, sql_verify_bit_func, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_BITOR, FO_USUAL, CT_FALSE },
    { { (char *)"bitxor", 6 }, sql_func_bit_xor, sql_verify_bit_func, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_BITXOR, FO_USUAL, CT_FALSE },
    { { (char *)"cast", 4 }, sql_func_cast, sql_verify_cast, AGGR_TYPE_NONE, FO_SPECIAL, ID_FUNC_ITEM_CAST, FO_USUAL, CT_FALSE },
    { { (char *)"ceil", 4 }, sql_func_ceil, sql_verify_ceil, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_CEIL, FO_USUAL, CT_FALSE },
    { { (char *)"char", 4 }, sql_func_chr, sql_verify_chr, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_CHAR, FO_USUAL, CT_FALSE },
    { { (char *)"char_length", 11 }, sql_func_length, sql_verify_length, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_CHAR_LENGTH, FO_USUAL, CT_FALSE },
    { { (char *)"chr", 3 }, sql_func_chr, sql_verify_chr, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_CHR, FO_USUAL, CT_FALSE },
    { { (char *)"coalesce", 8 }, sql_func_coalesce, sql_verify_coalesce, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_COALESCE, FO_USUAL, CT_FALSE },
    { { (char *)"concat", 6 }, sql_func_concat, sql_verify_concat, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_CONCAT, FO_USUAL, CT_FALSE },
    { { (char *)"concat_ws", 9 }, sql_func_concat_ws, sql_verify_concat_ws, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_CONCAT_WS, FO_USUAL, CT_FALSE },
    { { (char *)"connection_id", 13 }, sql_func_connection_id, sql_verify_connection_id, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_CONNECTION_ID, FO_USUAL, CT_FALSE },
    { { (char *)"convert", 7 }, sql_func_cast, sql_verify_cast, AGGR_TYPE_NONE, FO_SPECIAL, ID_FUNC_ITEM_CONVERT, FO_USUAL, CT_FALSE },
    { { (char *)"corr", 4 }, sql_func_covar_or_corr, sql_verify_covar_or_corr, AGGR_TYPE_CORR, FO_NONE, ID_FUNC_ITEM_CORR, FO_COVAR, CT_FALSE },
    { { (char *)"cos", 3 }, sql_func_cos, sql_verify_trigonometric, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_COS, FO_USUAL, CT_FALSE },
    { { (char *)"count", 5 }, sql_func_count, sql_verify_count, AGGR_TYPE_COUNT, FO_NONE, ID_FUNC_ITEM_COUNT, FO_USUAL, CT_FALSE },
    { { (char *)"covar_pop", 9 }, sql_func_covar_or_corr, sql_verify_covar_or_corr, AGGR_TYPE_COVAR_POP, FO_NONE, ID_FUNC_ITEM_COVAR_POP, FO_COVAR, CT_FALSE },
    { { (char *)"covar_samp", 10 }, sql_func_covar_or_corr, sql_verify_covar_or_corr, AGGR_TYPE_COVAR_SAMP, FO_NONE, ID_FUNC_ITEM_COVAR_SAMP, FO_COVAR, CT_FALSE },
    { { (char *)"cume_dist", 9 }, sql_func_cume_dist, sql_verify_cume_dist, AGGR_TYPE_CUME_DIST, FO_NONE, ID_FUNC_ITEM_CUME_DIST, FO_USUAL, CT_FALSE },
    { { (char *)"current_timestamp", 17 }, sql_func_current_timestamp, sql_verify_current_timestamp, AGGR_TYPE_NONE, FO_SPECIAL, ID_FUNC_ITEM_CURRENT_TIMESTAMP, FO_USUAL, CT_FALSE },
    { { (char *)"decode", 6 }, sql_func_decode, sql_verify_decode, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_DECODE, FO_USUAL, CT_TRUE },
    { { (char *)"dense_rank", 10 }, sql_func_dense_rank, sql_verify_dense_rank, AGGR_TYPE_DENSE_RANK, FO_NONE, ID_FUNC_ITEM_DENSE_RANK, FO_USUAL, CT_FALSE },
    { { (char *)"empty_blob", 10 }, sql_func_empty_blob, sql_verify_empty_blob, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_EMPTY_BLOB, FO_USUAL, CT_FALSE },
    { { (char *)"empty_clob", 10 }, sql_func_empty_clob, sql_verify_empty_clob, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_EMPTY_CLOB, FO_USUAL, CT_FALSE },
    { { (char *)"exp", 3 }, sql_func_exp, sql_verify_exp, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_EXP, FO_USUAL, CT_FALSE },
    { { (char *)"extract", 7 }, sql_func_extract, sql_verify_extract, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_EXTRACT, FO_USUAL, CT_FALSE },
    { { (char *)"find_in_set", 11 }, sql_func_find_in_set, sql_verify_find_in_set, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_FIND_IN_SET, FO_USUAL, CT_FALSE },
    { { (char *)"floor", 5 }, sql_func_floor, sql_verify_floor, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_FLOOR, FO_USUAL, CT_FALSE },
    { { (char *)"found_rows", 10 }, sql_func_found_rows, sql_verify_found_rows, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_FOUND_ROWS, FO_USUAL, CT_FALSE },
    { { (char *)"from_tz", 7 }, sql_func_from_tz, sql_verify_from_tz, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_FROM_TZ, FO_USUAL, CT_FALSE },
    { { (char *)"from_unixtime", 13 }, sql_func_from_unixtime, sql_verify_from_unixtime, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_FROM_UNIXTIME, FO_USUAL, CT_FALSE },
    { { (char *)"getutcdate", 10 }, sql_func_utcdate, sql_verify_utcdate, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_GETUTCDATE, FO_USUAL, CT_FALSE },
    { { (char *)"get_lock", 8 }, sql_func_get_lock, sql_verify_alck_nm_and_to, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_GET_LOCK, FO_USUAL, CT_FALSE },
    { { (char *)"get_shared_lock", 15 }, sql_func_get_shared_lock, sql_verify_alck_nm_and_to, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_GET_SHARED_LOCK, FO_USUAL, CT_FALSE },
    { { (char *)"get_xact_lock", 13 }, sql_func_get_xact_lock, sql_verify_alck_nm_and_to, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_GET_XACT_LOCK, FO_USUAL, CT_FALSE },
    { { (char *)"get_xact_shared_lock", 20 }, sql_func_get_xact_shared_lock, sql_verify_alck_nm_and_to, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_GET_XACT_SHARED_LOCK, FO_USUAL, CT_FALSE },
    { { (char *)"greatest", 8 }, sql_func_greatest, sql_verify_least_greatest, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_GREATEST, FO_USUAL, CT_FALSE },
    { { (char *)"grouping", 8 }, sql_func_grouping, sql_verify_grouping, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_GROUPING, FO_USUAL, CT_FALSE },
    { { (char *)"grouping_id", 11 }, sql_func_grouping_id, sql_verify_grouping_id, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_GROUPING_ID, FO_USUAL, CT_FALSE },
    { { (char *)"group_concat", 12 }, sql_func_group_concat, sql_verify_group_concat, AGGR_TYPE_GROUP_CONCAT, FO_NONE, ID_FUNC_ITEM_GROUP_CONCAT, FO_USUAL, CT_FALSE },
    { { (char *)"gscn2date", 9 }, sql_func_gscn2date, sql_verify_gscn2date, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_GSCN2DATE, FO_USUAL, CT_FALSE },
    { { (char *)"ct_hash", 7 }, sql_func_ct_hash, sql_verify_ct_hash, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_CT_HASH, FO_USUAL, CT_FALSE },
    { { (char *)"hash", 4 }, sql_func_hash, sql_verify_hash, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_HASH, FO_USUAL, CT_FALSE },
    { { (char *)"hex", 3 }, sql_func_hex, sql_verify_hex, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_HEX, FO_USUAL, CT_FALSE },
    { { (char *)"hex2bin", 7 }, sql_func_hex2bin, sql_verify_hex2bin, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_HEX2BIN, FO_USUAL, CT_FALSE },
    { { (char *)"hextoraw", 8 }, sql_func_hextoraw, sql_verify_hextoraw, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_HEXTORAW, FO_USUAL, CT_FALSE },
    { { (char *)"if", 2 }, sql_func_if, sql_verify_if, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_IF, FO_USUAL, CT_FALSE },
    { { (char *)"ifnull", 6 }, sql_func_ifnull, sql_verify_ifnull, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_IFNULL, FO_USUAL, CT_FALSE },
    { { (char *)"inet_aton", 9 }, sql_func_inet_aton, sql_verify_inet_aton, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_INET_ATON, FO_USUAL, CT_FALSE },
    { { (char *)"inet_ntoa", 9 }, sql_func_inet_ntoa, sql_verify_inet_ntoa, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_INET_NTOA, FO_USUAL, CT_FALSE },
    { { (char *)"insert", 6 }, sql_func_insert, sql_verify_insert_func, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_INSERT, FO_USUAL, CT_FALSE },
    { { (char *)"instr", 5 }, sql_func_instr, sql_verify_instr, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_INSTR, FO_USUAL, CT_FALSE },
    { { (char *)"instrb", 6 }, sql_func_instrb, sql_verify_instr, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_INSTRB, FO_USUAL, CT_FALSE },
    { { (char *)"isnumeric", 9 }, sql_func_is_numeric, sql_verify_is_numeric, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_ISNUMERIC, FO_USUAL, CT_FALSE },
    { { (char *)"jsonb_array_length", 18 }, sql_func_jsonb_array_length, sql_verify_jsonb_array_length, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_JSONB_ARRAY_LENGTH, FO_USUAL, CT_FALSE },
    { { (char *)"jsonb_exists", 12 }, sql_func_jsonb_exists, sql_verify_jsonb_exists, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_JSONB_EXISTS, FO_USUAL, CT_FALSE },
    { { (char *)"jsonb_mergepatch", 16 }, sql_func_jsonb_mergepatch, sql_verify_jsonb_mergepatch, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_JSONB_MERGEPATCH, FO_USUAL, CT_FALSE },
    { { (char *)"jsonb_query", 11 }, sql_func_jsonb_query, sql_verify_jsonb_query, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_JSONB_QUERY, FO_USUAL, CT_FALSE },
    { { (char *)"jsonb_set", 9 }, sql_func_jsonb_set, sql_verify_jsonb_set, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_JSONB_SET, FO_USUAL, CT_FALSE },
    { { (char *)"jsonb_value", 11 }, sql_func_jsonb_value, sql_verify_jsonb_value, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_JSONB_VALUE, FO_USUAL, CT_TRUE },
    { { (char *)"json_array", 10 }, sql_func_json_array, sql_verify_json_array, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_JSON_ARRAY, FO_USUAL, CT_FALSE },
    { { (char *)"json_array_length", 17 }, sql_func_json_array_length, sql_verify_json_array_length, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_JSON_ARRAY_LENGTH, FO_USUAL, CT_FALSE },
    { { (char *)"json_exists", 11 }, sql_func_json_exists, sql_verify_json_exists, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_JSON_EXISTS, FO_USUAL, CT_FALSE },
    { { (char *)"json_mergepatch", 15 }, sql_func_json_mergepatch, sql_verify_json_mergepatch, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_JSON_MERGEPATCH, FO_USUAL, CT_FALSE },
    { { (char *)"json_object", 11 }, sql_func_json_object, sql_verify_json_object, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_JSON_OBJECT, FO_USUAL, CT_FALSE },
    { { (char *)"json_query", 10 }, sql_func_json_query, sql_verify_json_query, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_JSON_QUERY, FO_USUAL, CT_FALSE },
    { { (char *)"json_set", 8 }, sql_func_json_set, sql_verify_json_set, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_JSON_SET, FO_USUAL, CT_FALSE },
    { { (char *)"json_value", 10 }, sql_func_json_value, sql_verify_json_value, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_JSON_VALUE, FO_USUAL, CT_TRUE },
    { { (char *)"last_day", 8 }, sql_func_last_day, sql_verify_last_day, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_LAST_DAY, FO_USUAL, CT_FALSE },
    { { (char *)"last_insert_id", 14 }, sql_func_last_insert_id, sql_verify_last_insert_id, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_LAST_INSERT_ID, FO_USUAL, CT_FALSE },
    { { (char *)"least", 5 }, sql_func_least, sql_verify_least_greatest, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_LEAST, FO_USUAL, CT_FALSE },
    { { (char *)"left", 4 }, sql_func_left, sql_verify_left, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_LEFT, FO_USUAL, CT_FALSE },
    { { (char *)"length", 6 }, sql_func_length, sql_verify_length, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_LENGTH, FO_USUAL, CT_FALSE },
    { { (char *)"lengthb", 7 }, sql_func_lengthb, sql_verify_length, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_LENGTHB, FO_USUAL, CT_FALSE },
    { { (char *)"listagg", 7 }, sql_func_group_concat, sql_verify_listagg, AGGR_TYPE_GROUP_CONCAT, FO_NONE, ID_FUNC_ITEM_LISTAGG, FO_USUAL, CT_FALSE },
    { { (char *)"ln", 2 }, sql_func_ln, sql_verify_ln, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_LN, FO_USUAL, CT_FALSE },
    { { (char *)"lnnvl", 5 }, sql_func_lnnvl, sql_verify_lnnvl, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_LNNVL, FO_USUAL, CT_FALSE },
    { { (char *)"localtimestamp", 14 }, sql_func_localtimestamp, sql_verify_localtimestamp, AGGR_TYPE_NONE, FO_SPECIAL, ID_FUNC_ITEM_LOCALTIMESTAMP, FO_USUAL, CT_FALSE },
    { { (char *)"locate", 6 }, sql_func_locate, sql_verify_locate, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_LOCATE, FO_USUAL, CT_FALSE },
    { { (char *)"log", 3 }, sql_func_log, sql_verify_log, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_LOG, FO_USUAL, CT_FALSE },
    { { (char *)"lower", 5 }, sql_func_lower, sql_verify_lower, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_LOWER, FO_USUAL, CT_TRUE },
    { { (char *)"lpad", 4 }, sql_func_lpad, sql_verify_pad, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_LPAD, FO_USUAL, CT_FALSE },
    { { (char *)"ltrim", 5 }, sql_func_ltrim, sql_verify_rltrim, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_LTRIM, FO_USUAL, CT_FALSE },
    { { (char *)"max", 3 }, sql_func_normal_aggr, sql_verify_min_max, AGGR_TYPE_MAX, FO_NONE, ID_FUNC_ITEM_MAX, FO_USUAL, CT_FALSE },
    { { (char *)"md5", 3 }, sql_func_md5, sql_verify_md5, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_MD5, FO_USUAL, CT_FALSE },
    { { (char *)"median", 6 }, sql_func_normal_aggr, sql_verify_median, AGGR_TYPE_MEDIAN, FO_NONE, ID_FUNC_ITEM_MEDIAN, FO_USUAL, CT_FALSE },
    { { (char *)"min", 3 }, sql_func_normal_aggr, sql_verify_min_max, AGGR_TYPE_MIN, FO_NONE, ID_FUNC_ITEM_MIN, FO_USUAL, CT_FALSE },
    { { (char *)"mod", 3 }, sql_func_mod, sql_verify_mod, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_MOD, FO_USUAL, CT_FALSE },
    { { (char *)"months_between", 14 }, sql_func_months_between, sql_verify_months_between, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_MONTHS_BETWEEN, FO_USUAL, CT_FALSE },
    { { (char *)"next_day", 8 }, sql_func_next_day, sql_verify_next_day, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_NEXT_DAY, FO_USUAL, CT_FALSE },
    { { (char *)"now", 3 }, sql_func_current_timestamp, sql_verify_current_timestamp, AGGR_TYPE_NONE, FO_SPECIAL, ID_FUNC_ITEM_NOW, FO_USUAL, CT_FALSE },
    { { (char *)"nullif", 6 }, sql_func_nullif, sql_verify_nullif, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_NULLIF, FO_USUAL, CT_FALSE },
    { { (char *)"numtodsinterval", 15 }, sql_func_numtodsinterval, sql_verify_numtodsinterval, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_NUMTODSINTERVAL, FO_USUAL, CT_FALSE },
    { { (char *)"numtoyminterval", 15 }, sql_func_numtoyminterval, sql_verify_numtoyminterval, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_NUMTOYMINTERVAL, FO_USUAL, CT_FALSE },
    { { (char *)"nvl", 3 }, sql_func_nvl, sql_verify_nvl, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_NVL, FO_USUAL, CT_TRUE },
    { { (char *)"nvl2", 4 }, sql_func_nvl2, sql_verify_nvl2, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_NVL2, FO_USUAL, CT_TRUE },
    { { (char *)"object_id", 9 }, sql_func_object_id, sql_verify_object_id, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_OBJECT_ID, FO_USUAL, CT_FALSE },
    { { (char *)"page_masterid", 13 }, sql_func_page2masterid, sql_verify_page2masterid, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_PAGE_MASTERID },
    { { (char *)"pi", 2 }, sql_func_pi, sql_verify_pi, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_PI, FO_USUAL, CT_FALSE },
    { { (char *)"power", 5 }, sql_func_power, sql_verify_power, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_POWER, FO_USUAL, CT_FALSE },
    { { (char *)"radians", 7 }, sql_func_radians, sql_verify_radians, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_RADIANS, FO_USUAL, CT_TRUE },
    { { (char *)"rand", 4 }, sql_func_rand, sql_verify_rand, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_RAND, FO_USUAL, CT_FALSE },
    { { (char *)"rank", 4 }, sql_func_dense_rank, sql_verify_dense_rank, AGGR_TYPE_RANK, FO_NONE, ID_FUNC_ITEM_RANK, FO_USUAL, CT_FALSE },
    { { (char *)"rawtohex", 8 }, sql_func_rawtohex, sql_verify_rawtohex, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_RAWTOHEX, FO_USUAL, CT_FALSE },
    { { (char *)"regexp_count", 12 }, sql_func_regexp_count, sql_verify_regexp_count, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_REGEXP_COUNT, FO_USUAL, CT_FALSE },
    { { (char *)"regexp_instr", 12 }, sql_func_regexp_instr, sql_verify_regexp_instr, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_REGEXP_INSTR, FO_USUAL, CT_TRUE },
    { { (char *)"regexp_replace", 14 }, sql_func_regexp_replace, sql_verify_regexp_replace, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_REGEXP_REPLACE, FO_USUAL, CT_FALSE },
    { { (char *)"regexp_substr", 13 }, sql_func_regexp_substr, sql_verify_regexp_substr, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_REGEXP_SUBSTR, FO_USUAL, CT_TRUE },
    { { (char *)"release_lock", 12 }, sql_func_release_lock, sql_verify_alck_name, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_RELEASE_LOCK, FO_USUAL, CT_FALSE },
    { { (char *)"release_shared_lock", 19 }, sql_func_release_shared_lock, sql_verify_alck_name, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_RELEASE_SHARED_LOCK, FO_USUAL, CT_FALSE },
    { { (char *)"repeat", 6 }, sql_func_repeat, sql_verify_repeat, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_PEPEAT, FO_USUAL, CT_FALSE },
    { { (char *)"replace", 7 }, sql_func_replace, sql_verify_replace, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_REPLACE, FO_USUAL, CT_FALSE },
    { { (char *)"reverse", 7 }, sql_func_reverse, sql_verify_reverse, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_REVERSE, FO_USUAL, CT_TRUE },
    { { (char *)"right", 5 }, sql_func_right, sql_verify_right, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_RIGHT, FO_USUAL, CT_FALSE },
    { { (char *)"round", 5 }, sql_func_round, sql_verify_round_trunc, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_ROUND, FO_USUAL, CT_FALSE },
    { { (char *)"rpad", 4 }, sql_func_rpad, sql_verify_pad, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_RPAD, FO_USUAL, CT_FALSE },
    { { (char *)"rtrim", 5 }, sql_func_rtrim, sql_verify_rltrim, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_RTRIM, FO_USUAL, CT_FALSE },
    { { (char *)"scn2date", 8 }, sql_func_scn2date, sql_verify_scn2date, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_SCN2DATE, FO_USUAL, CT_FALSE },
    { { (char *)"serial_lastval", 14 }, sql_func_serial_lastval, sql_verify_serial_lastval, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_SERIAL_LASTVAL, FO_USUAL, CT_FALSE },
    { { (char *)"sha", 3 }, sql_func_sha1, sql_verify_sha1, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_SHA, FO_USUAL, CT_FALSE },
    { { (char *)"sha1", 4 }, sql_func_sha1, sql_verify_sha1, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_SHA1, FO_USUAL, CT_FALSE },
    { { (char *)"sign", 4 }, sql_func_sign, sql_verify_sign, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_SIGN, FO_USUAL, CT_FALSE },
    { { (char *)"sin", 3 }, sql_func_sin, sql_verify_trigonometric, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_SIN, FO_USUAL, CT_FALSE },
    { { (char *)"soundex", 7 }, sql_func_soundex, sql_verify_soundex, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_SOUNDEX, FO_USUAL, CT_FALSE },
    { { (char *)"space", 5 }, sql_func_space, sql_verify_space, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_SPACE, FO_USUAL, CT_FALSE },
    { { (char *)"sqrt", 4 }, sql_func_sqrt, sql_verify_sqrt, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_SQRT, FO_USUAL, CT_FALSE },
    { { (char *)"stddev", 6 }, sql_func_normal_aggr, sql_verify_stddev_intern, AGGR_TYPE_STDDEV, FO_NONE, ID_FUNC_ITEM_STDDEV, FO_USUAL, CT_FALSE },
    { { (char *)"stddev_pop", 10 }, sql_func_normal_aggr, sql_verify_stddev_intern, AGGR_TYPE_STDDEV_POP, FO_NONE, ID_FUNC_ITEM_STDDEV_POP, FO_USUAL, CT_FALSE },
    { { (char *)"stddev_samp", 11 }, sql_func_normal_aggr, sql_verify_stddev_intern, AGGR_TYPE_STDDEV_SAMP, FO_NONE, ID_FUNC_ITEM_STDDEV_SAMP, FO_USUAL, CT_FALSE },
    { { (char *)"substr", 6 }, sql_func_substr, sql_verify_substr, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_SUBSTR, FO_USUAL, CT_TRUE },
    { { (char *)"substrb", 7 }, sql_func_substrb, sql_verify_substr, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_SUBSTRB, FO_USUAL, CT_TRUE },
    { { (char *)"substring", 9 }, sql_func_substr, sql_verify_substr, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_SUBSTRING, FO_USUAL, CT_FALSE },
    { { (char *)"substring_index", 15 }, sql_func_substring_index, sql_verify_substring_index, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_SUBSTRING_INDEX, FO_USUAL, CT_FALSE },
    { { (char *)"sum", 3 }, sql_func_normal_aggr, sql_verify_sum, AGGR_TYPE_SUM, FO_NONE, ID_FUNC_ITEM_SUM, FO_USUAL, CT_FALSE },
    { { (char *)"systimestamp", 12 }, sql_func_sys_timestamp, sql_verify_current_timestamp, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_SYSTIMESTAMP, FO_USUAL, CT_FALSE },
    { { (char *)"sys_connect_by_path", 19 }, sql_func_sys_connect_by_path, sql_verify_sys_connect_by_path, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_SYS_CONNECT_BY_PATH, FO_USUAL, CT_FALSE },
    { { (char *)"sys_context", 11 }, sql_func_sys_context, sql_verify_sys_context, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_SYS_CONTEXT, FO_USUAL, CT_FALSE },
    { { (char *)"sys_extract_utc", 15 }, sql_func_sys_extract_utc, sql_verify_sys_extract_utc, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_SYS_EXTRACT_UTC, FO_USUAL, CT_FALSE },
    { { (char *)"sys_guid", 8 }, sql_func_sys_guid, sql_verify_sys_guid, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_SYS_GUID, FO_USUAL, CT_FALSE },
    { { (char *)"tan", 3 }, sql_func_tan, sql_verify_trigonometric, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_TAN, FO_USUAL, CT_FALSE },
    { { (char *)"tanh", 4 }, sql_func_tanh, sql_verify_tanh, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_TANH, FO_USUAL, CT_FALSE },
    { { (char *)"timestampadd", 12 }, sql_func_timestampadd, sql_verify_timestampadd, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_TIMESTAMPADD, FO_USUAL, CT_FALSE },
    { { (char *)"timestampdiff", 13 }, sql_func_timestampdiff, sql_verify_timestampdiff, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_TIMESTAMPDIFF, FO_USUAL, CT_FALSE },
    { { (char *)"to_blob", 7 }, sql_func_to_blob, sql_verify_to_blob, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_TO_BLOB, FO_USUAL, CT_FALSE },
    { { (char *)"to_char", 7 }, sql_func_to_char, sql_verify_to_char, AGGR_TYPE_NONE, FO_SPECIAL, ID_FUNC_ITEM_TO_CHAR, FO_USUAL, CT_TRUE },
    { { (char *)"to_clob", 7 }, sql_func_to_clob, sql_verify_to_clob, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_TO_CLOB, FO_USUAL, CT_FALSE },
    { { (char *)"to_date", 7 }, sql_func_to_date, sql_verify_to_date, AGGR_TYPE_NONE, FO_SPECIAL, ID_FUNC_ITEM_TO_DATE, FO_USUAL, CT_TRUE },
    { { (char *)"to_dsinterval", 13 }, sql_func_to_dsinterval, sql_verify_to_dsinterval, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_TO_DSINTERVAL, FO_USUAL, CT_FALSE },
    { { (char *)"to_multi_byte", 13 }, sql_func_to_multi_byte, sql_verify_to_single_or_multi_byte, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_TO_MULTI_BYTE, FO_USUAL, CT_FALSE },
    { { (char *)"to_nchar", 8 }, sql_func_to_nchar, sql_verify_to_nchar, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_TO_NCHAR, FO_USUAL, CT_FALSE },
    { { (char *)"to_number", 9 }, sql_func_to_number, sql_verify_to_number, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_TO_NUMBER, FO_USUAL, CT_TRUE },
    { { (char *)"to_single_byte", 14 }, sql_func_to_single_byte, sql_verify_to_single_or_multi_byte, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_TO_SINGLE_BYTE, FO_USUAL, CT_FALSE },
    { { (char *)"to_timestamp", 12 }, sql_func_to_timestamp, sql_verify_to_timestamp, AGGR_TYPE_NONE, FO_SPECIAL, ID_FUNC_ITEM_TO_TIMESTAMP, FO_USUAL, CT_FALSE },
    { { (char *)"to_yminterval", 13 }, sql_func_to_yminterval, sql_verify_to_yminterval, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_TO_YMINTERVAL, FO_USUAL, CT_FALSE },
    { { (char *)"translate", 9 }, sql_func_translate, sql_verify_translate, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_TRANSLATE, FO_USUAL, CT_FALSE },
    { { (char *)"trim", 4 }, sql_func_trim, sql_verify_trim, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_TRIM, FO_USUAL, CT_TRUE },
    { { (char *)"trunc", 5 }, sql_func_trunc, sql_verify_round_trunc, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_TRUNC, FO_USUAL, CT_TRUE },
    { { (char *)"try_get_lock", 12 }, sql_func_try_get_lock, sql_verify_alck_name, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_TRY_GET_LOCK, FO_USUAL, CT_FALSE },
    { { (char *)"try_get_shared_lock", 19 }, sql_func_try_get_shared_lock, sql_verify_alck_name, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_TRY_GET_SHARED_LOCK, FO_USUAL, CT_FALSE },
    { { (char *)"try_get_xact_lock", 17 }, sql_func_try_get_xact_lock, sql_verify_alck_name, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_TRY_GET_XACT_LOCK, FO_USUAL, CT_FALSE },
    { { (char *)"try_get_xact_shared_lock", 24 }, sql_func_try_get_xact_shared_lock, sql_verify_alck_name, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_TRY_GET_XACT_SHARED_LOCK, FO_USUAL, CT_FALSE },
    { { (char *)"type_id2name", 12 }, sql_func_type_name, sql_verify_to_type_mapped, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_TYPE_ID2NAME, FO_USUAL, CT_FALSE },
    { { (char *)"unhex", 5 }, sql_func_unhex, sql_verify_unhex, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_UNHEX, FO_USUAL, CT_FALSE },
    { { (char *)"unix_timestamp", 14 }, sql_func_unix_timestamp, sql_verify_unix_timestamp, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_UNIX_TIMESTAMP, FO_USUAL, CT_FALSE },
    { { (char *)"updating", 8 }, sql_func_updating, sql_verify_updating, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_UPDATING, FO_USUAL, CT_FALSE },
    { { (char *)"upper", 5 }, sql_func_upper, sql_verify_upper, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_UPPER, FO_USUAL, CT_TRUE },
    { { (char *)"userenv", 7 }, sql_func_userenv, sql_verify_userenv, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_USERENV, FO_USUAL, CT_FALSE },
    { { (char *)"utc_date", 8 }, sql_func_utcdate, sql_verify_utcdate, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_UTCDATE, FO_USUAL, CT_FALSE },
    { { (char *)"utc_timestamp", 13 }, sql_func_utctimestamp, sql_verify_utctimestamp, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_UTCTIMESTAMP, FO_USUAL, CT_FALSE },
    { { (char *)"uuid", 4 }, sql_func_sys_guid, sql_verify_sys_guid, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_UUID, FO_USUAL, CT_FALSE },
    { { (char *)"values", 6 }, sql_func_values, sql_verify_values, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_VALUES, FO_USUAL, CT_FALSE },
    { { (char *)"variance", 8 }, sql_func_normal_aggr, sql_verify_stddev_intern, AGGR_TYPE_VARIANCE, FO_NONE, ID_FUNC_ITEM_VARIANCE, FO_USUAL, CT_FALSE },
    { { (char *)"var_pop", 7 }, sql_func_normal_aggr, sql_verify_stddev_intern, AGGR_TYPE_VAR_POP, FO_NONE, ID_FUNC_ITEM_VAR_POP, FO_USUAL, CT_FALSE },
    { { (char *)"var_samp", 8 }, sql_func_normal_aggr, sql_verify_stddev_intern, AGGR_TYPE_VAR_SAMP, FO_NONE, ID_FUNC_ITEM_VAR_SAMP, FO_USUAL, CT_FALSE },
    { { (char *)"version", 7 }, sql_func_version, sql_verify_version, AGGR_TYPE_NONE, FO_NONE, ID_FUNC_ITEM_VERSION, FO_USUAL, CT_FALSE },
    { { (char *)"vsize", 5 }, sql_func_vsize, sql_verify_vsize, AGGR_TYPE_NONE, FO_NORMAL, ID_FUNC_ITEM_VSIZE, FO_USUAL, CT_FALSE },
};


/* *************************************************************************** */
/*    End of type declarations for internal use within ctsql_func.c            */
/* *************************************************************************** */

uint32 sql_func_binsearch(const text_t *name, sql_func_item_t get_item, void *set, uint32 count)
{
    uint32 begin_pos, end_pos, mid_pos;
    int32 cmp;

    cmp = cm_compare_text_ins(name, get_item(set, 0));
    if (cmp == 0) {
        return 0;
    } else if (cmp < 0) {
        return CT_INVALID_ID32;
    }

    cmp = cm_compare_text_ins(name, get_item(set, count - 1));
    if (cmp == 0) {
        return count - 1;
    } else if (cmp > 0) {
        return CT_INVALID_ID32;
    }

    begin_pos = 0;
    end_pos = count - 1;
    mid_pos = (begin_pos + end_pos) / 2;

    while (end_pos - 1 > begin_pos) {
        cmp = cm_compare_text_ins(name, get_item(set, mid_pos));
        if (cmp == 0) {
            return mid_pos;
        } else if (cmp < 0) {
            end_pos = mid_pos;
            mid_pos = (end_pos + begin_pos) / 2;
        } else {
            begin_pos = mid_pos;
            mid_pos = (end_pos + begin_pos) / 2;
        }
    }
    return CT_INVALID_ID32;
}
uint32 sql_get_func_id(const text_t *func_name)
{
    uint32 begin_pos, end_pos, mid_pos;
    int32 cmp;

    cmp = cm_compare_text_ins(func_name, &g_func_tab[0].name);
    if (cmp == 0) {
        return 0;
    } else if (cmp < 0) {
        return CT_INVALID_ID32;
    }

    cmp = cm_compare_text_ins(func_name, &g_func_tab[SQL_FUNC_COUNT - 1].name);
    if (cmp == 0) {
        return SQL_FUNC_COUNT - 1;
    } else if (cmp > 0) {
        return CT_INVALID_ID32;
    }

    begin_pos = 0;
    end_pos = SQL_FUNC_COUNT - 1;
    mid_pos = (begin_pos + end_pos) / 2;

    while (end_pos - 1 > begin_pos) {
        cmp = cm_compare_text_ins(func_name, &g_func_tab[mid_pos].name);
        if (cmp == 0) {
            return mid_pos;
        } else if (cmp < 0) {
            end_pos = mid_pos;
            mid_pos = (end_pos + begin_pos) / 2;
        } else {
            begin_pos = mid_pos;
            mid_pos = (end_pos + begin_pos) / 2;
        }
    }
    return CT_INVALID_ID32;
}

status_t sql_verify_func_node(sql_verifier_t *verf, expr_node_t *func, uint16 min_args, uint16 max_args,
    uint32 type_arg_no)
{
    uint16 arg_count = 0;

    CM_POINTER2(verf, func);
    expr_tree_t *expr = func->argument;
    while (expr != NULL) {
        arg_count++;
        if ((expr->root->type == EXPR_NODE_PRIOR) && (verf->excl_flags & SQL_EXCL_PRIOR)) {
            CT_SRC_THROW_ERROR_EX(expr->loc, ERR_SQL_SYNTAX_ERROR, "prior must be in the condition of connect by");
            return CT_ERROR;
        }

        if (sql_verify_expr_node(verf, expr->root) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (arg_count == type_arg_no) {
            func->typmod = TREE_TYPMODE(expr);
        }

        expr = expr->next;
    }

    if (arg_count < min_args || arg_count > max_args) {
        CT_SRC_THROW_ERROR(func->loc, ERR_INVALID_FUNC_PARAM_COUNT, T2S(&func->word.func.name), min_args, max_args);
        return CT_ERROR;
    }

    func->value.v_func.arg_cnt = arg_count;

    return CT_SUCCESS;
}

uint32 sql_get_lob_var_length(variant_t *var)
{
    switch (var->v_lob.type) {
        case CT_LOB_FROM_KERNEL:
            return knl_lob_size((knl_handle_t)var->v_lob.knl_lob.bytes);

        case CT_LOB_FROM_VMPOOL:
            return var->v_lob.vm_lob.size;

        case CT_LOB_FROM_NORMAL:
        default:
            return var->v_lob.normal_lob.value.len;
    }
}

status_t sql_get_clob_char_len_from_knl(sql_stmt_t *stmt, variant_t *var, uint32 *char_len)
{
    knl_handle_t lob_locator = (knl_handle_t)var->v_lob.knl_lob.bytes;
    uint32 len = knl_lob_size(lob_locator);

    uint32 offset, read_size, utf8_text_len, ignore_bytes, buf_len, i;
    text_t v_text;
    char *buf = NULL;
    status_t ret = CT_SUCCESS;

    buf_len = MIN(len, CT_MAX_EXEC_LOB_SIZE);
    CT_RETURN_IFERR(sql_push(stmt, buf_len, (void **)&buf));
    ignore_bytes = 0;
    offset = 0;
    *char_len = 0;

    do {
        ret = knl_read_lob(stmt->session, lob_locator, offset, (void *)buf, buf_len, &read_size, NULL);
        CT_BREAK_IF_ERROR(ret);

        // check ignore bytes validity as utf8 character
        if (read_size < ignore_bytes) {
            CT_THROW_ERROR(ERR_NLS_INTERNAL_ERROR, "utf-8 buffer");
            ret = CT_ERROR;
            break;
        }

        for (i = 0; i < ignore_bytes; i++) {
            if (!IS_VALID_UTF8_CHAR((uint8)*(buf + i))) {
                CT_THROW_ERROR(ERR_NLS_INTERNAL_ERROR, "utf-8 buffer");
                ret = CT_ERROR;
                break;
            }
        }

        if (read_size == ignore_bytes) {
            ignore_bytes = 0;
            break;
        }

        v_text.str = buf + ignore_bytes;
        v_text.len = read_size - ignore_bytes;
        ret = GET_DATABASE_CHARSET->length_ignore(&v_text, (uint32 *)&utf8_text_len, &ignore_bytes);
        CT_BREAK_IF_ERROR(ret);

        *char_len += utf8_text_len;
        offset += read_size;
    } while (offset < len);

    if (ignore_bytes != 0) {
        CT_THROW_ERROR(ERR_NLS_INTERNAL_ERROR, "utf-8 buffer");
        ret = CT_ERROR;
    }

    CTSQL_POP(stmt);
    return ret;
}

status_t sql_get_clob_char_len_from_bind(sql_stmt_t *stmt, variant_t *var, uint32 *char_len)
{
    uint32 len = var->v_lob.vm_lob.size;

    uint32 vmid, page_len, utf8_text_len, ignore_bytes, i;
    vm_page_t *page = NULL;
    text_t lob_value;
    vm_pool_t *vm_pool = stmt->mtrl.pool;

    ignore_bytes = 0;
    vmid = var->v_lob.vm_lob.entry_vmid;
    *char_len = 0;

    while (len > 0) {
        CT_RETURN_IFERR(vm_open(stmt->session, vm_pool, vmid, &page));
        page_len = MIN(len, CT_VMEM_PAGE_SIZE);
        // check ignore bytes validity as utf8 character
        if (page_len < ignore_bytes) {
            vm_close(stmt->session, vm_pool, vmid, VM_ENQUE_HEAD);
            CT_THROW_ERROR(ERR_NLS_INTERNAL_ERROR, "utf-8 buffer");
            return CT_ERROR;
        }

        for (i = 0; i < ignore_bytes; i++) {
            if (!IS_VALID_UTF8_CHAR((uint8)*((char *)page->data + i))) {
                vm_close(stmt->session, vm_pool, vmid, VM_ENQUE_HEAD);
                CT_THROW_ERROR(ERR_NLS_INTERNAL_ERROR, "utf-8 buffer");
                return CT_ERROR;
            }
        }

        if (page_len == ignore_bytes) {
            ignore_bytes = 0;
            vm_close(stmt->session, vm_pool, vmid, VM_ENQUE_HEAD);
            break;
        }

        lob_value.len = page_len - ignore_bytes;
        lob_value.str = (char *)page->data + ignore_bytes;
        if (GET_DATABASE_CHARSET->length_ignore(&lob_value, (uint32 *)&utf8_text_len, &ignore_bytes) != CT_SUCCESS) {
            vm_close(stmt->session, vm_pool, vmid, VM_ENQUE_HEAD);
            return CT_ERROR;
        }

        vm_close(stmt->session, vm_pool, vmid, VM_ENQUE_HEAD);
        vmid = vm_get_ctrl(vm_pool, vmid)->sort_next;

        *char_len += utf8_text_len;
        len -= page_len;
    }

    if (ignore_bytes != 0) {
        CT_THROW_ERROR(ERR_NLS_INTERNAL_ERROR, "utf-8 buffer");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t sql_get_clob_char_len_from_normal(variant_t *var, uint32 *char_len)
{
    text_t lob_val = var->v_lob.normal_lob.value;

    return GET_DATABASE_CHARSET->length(&lob_val, char_len);
}

status_t sql_get_utf8_clob_char_len(sql_stmt_t *stmt, variant_t *var, uint32 *len)
{
    switch (var->v_lob.type) {
        case CT_LOB_FROM_KERNEL:
            return sql_get_clob_char_len_from_knl(stmt, var, len);
        case CT_LOB_FROM_VMPOOL:
            return sql_get_clob_char_len_from_bind(stmt, var, len);
        case CT_LOB_FROM_NORMAL:
            return sql_get_clob_char_len_from_normal(var, len);
        default:
            CT_THROW_ERROR(ERR_UNKNOWN_LOB_TYPE, "do get lob value");
            return CT_ERROR;
    }
}

bool32 sql_verify_lob_func_args(ct_type_t datatype)
{
    bool32 res = CT_FALSE;
    switch (datatype) {
        case CT_TYPE_BLOB:
        case CT_TYPE_CLOB:
        case CT_TYPE_IMAGE:
        case CT_TYPE_CHAR:
        case CT_TYPE_VARCHAR:
        case CT_TYPE_STRING:
        case CT_TYPE_RAW:
            res = CT_TRUE;
            break;
        default:
            res = CT_FALSE;
            break;
    }
    return res;
}

status_t sql_invoke_func(sql_stmt_t *stmt, expr_node_t *node, variant_t *result)
{
    uint32 id = node->value.v_func.func_id;
    sql_func_t *func = NULL;
    status_t status;
    bool32 ready = CT_FALSE;
    CM_POINTER2(stmt, result);

    result->ctrl = 0;

    if (node->value.v_func.pack_id != CT_INVALID_ID32) {
        return sql_invoke_pack_func(stmt, node, result);
    }

    if (id >= SQL_FUNC_COUNT) {
        // only if some built-in functions been removed
        CT_THROW_ERROR(ERR_INVALID_FUNC, id);
        return CT_ERROR;
    }

    result->type = CT_TYPE_UNKNOWN;
    func = sql_get_func(&node->value.v_func);
    CTSQL_SAVE_STACK(stmt);
    if (stmt->context != NULL && stmt->context->has_func_index && func->indexable) {
        CT_RETURN_IFERR(sql_try_get_value_from_index(stmt, node, result, &ready));
    }
    if (ready) {
        status = CT_SUCCESS;
    } else {
        status = func->invoke(stmt, node, result);
    }

    CTSQL_RESTORE_STACK(stmt);
    return status;
}

status_t sql_exec_expr_as_string(sql_stmt_t *stmt, expr_tree_t *arg, variant_t *var, text_t **text)
{
    text_buf_t buffer;

    CT_RETURN_IFERR(sql_exec_expr(stmt, arg, var));
    if (var->type == CT_TYPE_COLUMN) {
        return CT_SUCCESS;
    }

    *text = VALUE_PTR(text_t, var);

    if (var->is_null) {
        (*text)->len = 0;
        return CT_SUCCESS;
    }

    if (CT_IS_BINSTR_TYPE2(arg->root->datatype, var->type)) {
        if (var_as_string(SESSION_NLS(stmt), var, NULL) != CT_SUCCESS) {
            return CT_ERROR;
        }
        sql_keep_stack_variant(stmt, var);
        return CT_SUCCESS;
    }

    CTSQL_SAVE_STACK(stmt);

    sql_keep_stack_variant(stmt, var);
    if (sql_push_textbuf(stmt, CT_CONVERT_BUFFER_SIZE, &buffer) != CT_SUCCESS) {
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }
    switch (arg->root->datatype) {
        case CT_TYPE_TIMESTAMP:
        case CT_TYPE_TIMESTAMP_TZ:
        case CT_TYPE_TIMESTAMP_LTZ:
        case CT_TYPE_TIMESTAMP_TZ_FAKE:
        case CT_TYPE_INTERVAL_DS:
        case CT_TYPE_INTERVAL_YM:
            if (var_as_string2(SESSION_NLS(stmt), var, &buffer, &arg->root->typmod) != CT_SUCCESS) {
                CTSQL_RESTORE_STACK(stmt);
                return CT_ERROR;
            }
            break;
        default:
            if (var_as_string(SESSION_NLS(stmt), var, &buffer) != CT_SUCCESS) {
                CTSQL_RESTORE_STACK(stmt);
                return CT_ERROR;
            }
    }

    CTSQL_RESTORE_STACK(stmt);
    sql_keep_stack_variant(stmt, var);
    return CT_SUCCESS;
}

status_t sql_func_page2masterid(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    CM_POINTER3(stmt, func, result);
    expr_tree_t *arg = func->argument;
    variant_t value;

    result->is_null = CT_FALSE;
    result->type = CT_TYPE_UINT32;
    result->v_uint32 = 0;

    SQL_EXEC_FUNC_ARG(arg, &value, result, stmt);
    if (value.type != CT_TYPE_STRING || value.is_null) {
        return CT_SUCCESS; /* ignore illegal input */
    }

    uint32 file, page;
    errno_t ret = 0;
    ret = sscanf_s(value.v_text.str, "%u-%u", &file, &page);
    if (ret == -1) {
        return CT_SUCCESS; /* ignore illegal input */
    }

    page_id_t pageid;
    pageid.file = (uint16)file;
    pageid.page = page;

    uint8 inst_id = CT_INVALID_ID8;
    drc_get_page_master_id(pageid, &inst_id);
    result->v_uint32 = inst_id;

    return CT_SUCCESS;
}

status_t sql_verify_page2masterid(sql_verifier_t *verifier, expr_node_t *func)
{
    CM_POINTER2(verifier, func);

    if (sql_verify_func_node(verifier, func, 1, 1, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }

    func->datatype = CT_TYPE_STRING;
    func->size = cm_get_datatype_strlen(func->argument->root->datatype, func->argument->root->size);

    return CT_SUCCESS;
}

#ifdef __cplusplus
}
#endif
