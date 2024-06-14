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
 * knl_rstat.c
 *
 *
 * IDENTIFICATION
 * src/kernel/statistics/knl_rstat.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_common_module.h"
#include "knl_rstat.h"
#include "cm_file.h"
#include "ostat_load.h"
#include "ostat_common.h"
#include "knl_context.h"
#include "knl_table.h"
#include "knl_mtrl.h"
#include "temp_btree.h"
#include "dc_part.h"
#include "knl_sys_part_defs.h"
#include "tse_ddl_list.h"

#define STATS_GET_ENDPOINT(column_handler) \
    ((column_handler)->hist_info.prev_endpoint + (column_handler)->hist_info.dnv_per_num)
#define STATS_CALC_EXTENT_NUM(blocks, extent_size) \
    ((uint32)(((blocks) + (extent_size) - 1) / (extent_size)))
#define STATS_SAMPLE_PAGES_PER_EXT(sample_size, total_extents) \
    ((uint32)(((sample_size) + (total_extents) - 1) / (total_extents)))
// segment->extents is not greater than max value of uint32
#define STATS_SAMPLE_EXTENTS_PER_SEG(sample_size, stats_sampler)    \
    ((uint32)((sample_size) / (stats_sampler)->pages_per_ext))
#define STATS_GET_SAMPLE_EXT_STEP(stats_sampler)                \
    ((stats_sampler)->total_extents / (stats_sampler)->sample_extents)
#define STATA_SAMPLE_CURRENT_EXTENT(stat_sample)                \
    (((stat_sample)->hwm_extents > 0) && ((stat_sample)->sample_extent.count < (stat_sample)->pages_per_ext))
#define NOT_MAP_OR_FIRST_EXTENT(stat_sample, page)              \
    ((stat_sample)->hwm_extents > 1 && (page)->head.type != PAGE_TYPE_HEAP_MAP)
#define STATS_NOT_DATA_PAGE(type)                               \
    ((type) != PAGE_TYPE_HEAP_DATA && (type) != PAGE_TYPE_PCRH_DATA)
#define STATS_MIN_SAMPLE_BLOCKS                                 32
#define STATS_REVISE_SAMPLE_RATIO(table_stats, stats_sample)  \
    ((table_stats)->estimate_sample_ratio * (stats_sample)->hwm_pages / (stats_sample)->sample_size)
#define STATS_IS_ANALYZE_SINGLE_PART(stats_table, part_id)  \
    ((stats_table)->single_part_analyze && (stats_table)->specify_part_id == (part_id))
#define STATS_IS_NOT_SPECIFY_PART(stats_table, part_id)  \
    ((stats_table)->single_part_analyze && (stats_table)->specify_part_id != (part_id))
#define STATS_GLOBAL_CBO_STATS_EXIST(entity)                    \
    ((entity)->stat_exists && (entity)->cbo_table_stats->global_stats_exist)
#define STATS_GENERATE_SERIERS_PAGE_STAP(stat_sample)                    \
    ((stat_sample)->extent_size >= EXT_SIZE_1024) &&                      \
    ((stat_sample)->pages_per_ext >= ((stat_sample)->extent_size * 0.7))
#define STATS_IS_PART_INDEX(stats_idx)      ((stats_idx)->part_index != NULL)

#define STATS_MAP_ROW_COUNT                                        1
#define STATS_UPDATE_SYS_HIST_COUNT                                2
#define STATS_SYS_MON_MODS_ALL_INDEX_2                             2
#define STATS_SYS_MON_MODS_ALL_ANALYZE_TIME                        5
#define ADDITIONAL_NDV_FACTOR_THRESHOLD                            0.1
#define STATS_DOUBLE_REVISE_NUM                                    0.5
#define STATS_MIN_SAMPLE_RATIO_EXT                                 0.3
#define STATS_MIN_SAMPLE_EXTENTS                                   1
#define STATS_REPORT_FORMAT                                        "%s/%s_%s"
#define STATS_REPORT_DIR                                           "%s/opt"
#define STATS_SYS_TABLE_COLS_NUM                                   5
#define STATS_SYS_HISTATTR_COLS_NUM                                4
#define STATS_SYS_INDEX_COLS_NUM                                   10
#define STATS_FLUSH_ENTITY_NUM                                     10
#define IS_FULL_SAMPLE(ff)                                         (fabs(ff) < CT_REAL_PRECISION)
#define IS_STATS_TABLE_TYPE(table)                                 \
    (((table)->desc.type == TABLE_TYPE_HEAP) || ((table)->desc.type == TABLE_TYPE_NOLOGGING))
#define IS_ANALYZE_ALL_PARTS(table_stats)                         ((table_stats)->part_stats.part_id == CT_INVALID_ID32)
#define STATS_NEED_AMPLIFY(sample_ratio, is_parent)             (((sample_ratio) > CT_REAL_PRECISION) && (!(is_parent)))

latch_t g_stats_latch = { .lock = 0, .shared_count = 0, .stat = 0, .sid = 0, .unused = 0 };


/* dynamic statistics use autonomous transaction to commit modification of system table
 */
void stats_commit(knl_session_t *session, bool32 is_dynamic)
{
    if (is_dynamic) {
        return;
    }

    knl_commit(session);
}
/* dynamic statistics use autonomous transaction to rollback modification of system table
*/
void stats_rollback(knl_session_t *session, bool32 is_dynamic)
{
    if (is_dynamic) {
        return;
    }

    knl_rollback(session, NULL);
}

/* There are 3 situations that statistics is not persistent
 * 1.Gathering temp table dynamically
 * 2.Gathering global transaction temp table manually
 * 3.Gathering local temp table manually
 */
static inline bool32 stats_no_persistent(stats_table_t *table_stats)
{
    if (!STATS_IS_ANALYZE_TEMP_TABLE(table_stats)) {
        return CT_FALSE;
    }

    knl_dict_type_t table_type = table_stats->temp_table->table_cache->table_type;
    uint32 table_id = table_stats->temp_table->table_cache->table_id;
    bool32 is_dynamic = table_stats->is_dynamic;
    
    return !STATS_MANUAL_SESSION_GTT(table_type, table_id, is_dynamic);
}

void stats_internal_commit(knl_session_t *session, stats_table_t *table_stats)
{
    if (stats_no_persistent(table_stats)) {
        return;
    }

    if (table_stats->is_dynamic) {
        return;
    }

    if (!table_stats->is_part) {
        return;
    }

    knl_commit(session);
}

void stats_internal_rollback(knl_session_t *session, stats_table_t *table_stats)
{
    if (stats_no_persistent(table_stats)) {
        return;
    }

    if (table_stats->is_dynamic) {
        return;
    }

    if (!table_stats->is_part) {
        return;
    }

    knl_rollback(session, NULL);
}

int32 stats_compare_data_ex(void *data1, uint16 size_1, void *data2, uint16 size_2, knl_column_t *column)
{
    uint16 size1 = size_1;
    uint16 size2 = size_2;
    if (size1 == CT_NULL_VALUE_LEN || size2 == CT_NULL_VALUE_LEN) {
        return (size1 == size2) ? 0 : (size1 == CT_NULL_VALUE_LEN) ? 1 : -1;
    }

    if (size1 > column->size && size1 != CT_NULL_VALUE_LEN) {
        size1 = column->size;
    }

    if (size2 > column->size && size2 != CT_NULL_VALUE_LEN) {
        size2 = column->size;
    }

    return var_compare_data_ex(data1, size1, data2, size2, column->datatype);
}

static inline void stats_decode_mtrl_row(mtrl_row_t *row, char *data)
{
    row->data = data;
    cm_decode_row(data, row->offsets, row->lens, NULL);
}

static inline int32 stats_compare_mtrl_row(mtrl_segment_t *segment, mtrl_row_t *row1, mtrl_row_t *row2)
{
    knl_column_t *column = NULL;
    uint32 result;

    column = (knl_column_t *)segment->cmp_items;

    result = stats_compare_data_ex(STATS_CDATA(row1, 0), STATS_CSIZE(row1, 0),
                                   STATS_CDATA(row2, 0), STATS_CSIZE(row2, 0), column);
    return result;
}

static inline status_t stats_pcrb_compare_mtrl_key(mtrl_segment_t *segment, char *data1, char *data2, int32 *result)
{
    btree_t *btree = (btree_t *)segment->cmp_items;
    knl_scan_key_t scan_key;
    index_profile_t *profile = INDEX_PROFILE(btree->index);

    pcrb_decode_key(profile, (pcrb_key_t *)data1, &scan_key);
    *result = pcrb_compare_key(profile, &scan_key, (pcrb_key_t *)data2, CT_TRUE, NULL);
    return CT_SUCCESS;
}

static inline status_t stats_btree_compare_mtrl_key(mtrl_segment_t *segment, char *data1, char *data2, int32 *result)
{
    btree_t *btree = (btree_t *)segment->cmp_items;
    knl_scan_key_t scan_key;

    btree_decode_key(btree->index, (btree_key_t *)data1, &scan_key);
    *result = btree_compare_key(btree->index, &scan_key, (btree_key_t *)data2, CT_TRUE, NULL);
    return CT_SUCCESS;
}

status_t stats_mtrl_sort_cmp(mtrl_segment_t *segment, char *data1, char *data2, int32 *result)
{
    mtrl_row_t row1, row2;
    stats_decode_mtrl_row(&row1, data1);
    stats_decode_mtrl_row(&row2, data2);
    *result = stats_compare_mtrl_row(segment, &row1, &row2);
    return CT_SUCCESS;
}

static status_t inline stats_try_begin_auton_rm(knl_session_t *session, bool32 is_dynamic)
{
    if (!is_dynamic) {
        return CT_SUCCESS;
    }

    return knl_begin_auton_rm(session);
}


static void inline stats_try_end_auton_rm(knl_session_t *session, status_t status, bool32 is_dynamic)
{
    if (!is_dynamic) {
        return;
    }

    knl_end_auton_rm(session, status);
}

static uint64 inline stats_calc_row_avg_len(stats_table_info_t info)
{
    uint64 avg_len = info.row_len / info.rows;
    return avg_len;
}

static void inline stats_get_row_avg_len(stats_table_info_t *info)
{
    if (info->rows != 0) {
        info->avg_row_len = stats_calc_row_avg_len(*info);
    } else {
        info->avg_row_len = 0;
    }
}

static status_t stats_match_histgram(void *handle, bool32 *match)
{
    stats_match_cond_t *cond = (stats_match_cond_t *)handle;
    knl_cursor_t *cursor = cond->cursor;
    *match = CT_FALSE;

    switch (cond->match_type) {
        case MATCH_PART:
            if (CURSOR_COLUMN_SIZE(cursor, HIST_PART_ID) != CT_NULL_VALUE_LEN) {
                uint32 part = *(uint32 *)CURSOR_COLUMN_DATA(cursor, HIST_PART_ID);
                if (part != cond->part_id) {
                    return CT_SUCCESS;
                }
            }
            break;

        case MATCH_SUBPART:
            if (CURSOR_COLUMN_SIZE(cursor, HIST_SUBPART_ID) != CT_NULL_VALUE_LEN) {
                uint64 subpart = *(uint64 *)CURSOR_COLUMN_DATA(cursor, HIST_SUBPART_ID);
                if (subpart != cond->subpart_id) {
                    return CT_SUCCESS;
                }
            }
            break;

        case MATCH_COLUMN:
            if (CURSOR_COLUMN_SIZE(cursor, HIST_COLUMN_ID) != CT_NULL_VALUE_LEN) {
                uint32 col_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, HIST_COLUMN_ID);
                if (col_id != cond->col_id) {
                    return CT_SUCCESS;
                }
            }
            break;

        default:
            break;
    }

    *match = CT_TRUE;
    return CT_SUCCESS;
}

static status_t stats_match_histhead(void *handle, bool32 *match)
{
    stats_match_cond_t *cond = (stats_match_cond_t *)handle;
    knl_cursor_t *cursor = cond->cursor;
    *match = CT_FALSE;

    switch (cond->match_type) {
        case MATCH_PART:
            if (CURSOR_COLUMN_SIZE(cursor, HIST_HEAD_PART_ID) != CT_NULL_VALUE_LEN) {
                uint32 part = *(uint32 *)CURSOR_COLUMN_DATA(cursor, HIST_HEAD_PART_ID);
                if (part != cond->part_id) {
                    return CT_SUCCESS;
                }
            }
            break;

        case MATCH_SUBPART:
            if (CURSOR_COLUMN_SIZE(cursor, HIST_HEAD_SUBPART_ID) != CT_NULL_VALUE_LEN) {
                uint64 subpart = *(uint64 *)CURSOR_COLUMN_DATA(cursor, HIST_HEAD_SUBPART_ID);
                if (subpart != cond->subpart_id) {
                    return CT_SUCCESS;
                }
            }
            break;

        case MATCH_COLUMN:
            if (CURSOR_COLUMN_SIZE(cursor, HIST_HEAD_COLUMN_ID) != CT_NULL_VALUE_LEN) {
                uint32 col_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, HIST_HEAD_COLUMN_ID);
                if (col_id != cond->col_id) {
                    return CT_SUCCESS;
                }
            }
            break;

        default:
            break;
    }

    *match = CT_TRUE;
    return CT_SUCCESS;
}

static status_t stats_match_sys_dmls(void *handle, bool32 *match)
{
    stats_match_cond_t *cond = (stats_match_cond_t *)handle;
    knl_cursor_t *cursor = cond->cursor;
    *match = CT_FALSE;

    if (cond->part_id == CT_INVALID_ID32) {
        *match = CT_TRUE;
        return CT_SUCCESS;
    }

    if (CURSOR_COLUMN_SIZE(cursor, STATS_MON_MODS_PART_ID) != CT_NULL_VALUE_LEN) {
        uint32 part = *(uint32 *)CURSOR_COLUMN_DATA(cursor, STATS_MON_MODS_PART_ID);
        if (part != cond->part_id) {
            return CT_SUCCESS;
        }
    }

    *match = CT_TRUE;
    return CT_SUCCESS;
}

status_t stats_create_report_file(const char *stats_file_name, int32 *report_file)
{
    char stats_report_name[STATS_MAX_REPORT_NAME_LEN] = { 0 }; /* 4 bytes for ".csv" */
    int32 ret;

    if (cm_file_exist(stats_file_name)) {
        CT_LOG_RUN_INF("[STATS] Stats report file %s already exits", stats_file_name);
        return CT_ERROR;
    }

    ret = sprintf_s(stats_report_name, STATS_MAX_REPORT_NAME_LEN, "%s.csv", stats_file_name);
    knl_securec_check_ss(ret);

    if (cm_file_exist(stats_report_name) && cm_remove_file(stats_report_name) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[STATS] failed to remove remained stats report file %s", stats_report_name);
        return CT_ERROR;
    }

    if (cm_create_file(stats_report_name, O_BINARY | O_SYNC | O_RDWR | O_EXCL, report_file) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[STATS] failed to create stats report file %s", stats_report_name);
        cm_close_file(*report_file);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t stats_init_report_file(knl_session_t *session, dc_entity_t *entity, stats_option_t *stats_option)
{
    char stats_file_name[CT_MAX_FILE_NAME_LEN];
    char stats_file_dir[CT_MAX_FILE_NAME_LEN];
    int32 ret;
    log_param_t *log_param = cm_log_param_instance();

    ret = sprintf_s(stats_file_dir, CT_MAX_FILE_NAME_LEN, STATS_REPORT_DIR, log_param->log_home);
    knl_securec_check_ss(ret);

    if (!cm_dir_exist(stats_file_dir)) {
        if (cm_create_dir(stats_file_dir) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[STATS] failed to create dir %s", stats_file_dir);
            return CT_ERROR;
        }
    }

    ret = sprintf_s(stats_file_name, CT_MAX_FILE_NAME_LEN, STATS_REPORT_FORMAT, stats_file_dir,
                    entity->entry->name, "TAB");
    knl_securec_check_ss(ret);

    if (stats_create_report_file(stats_file_name, &stats_option->report_tab_file) != CT_SUCCESS) {
        return CT_ERROR;
    }

    ret = sprintf_s(stats_file_name, CT_MAX_FILE_NAME_LEN, STATS_REPORT_FORMAT, stats_file_dir,
                    entity->entry->name, "IDX");
    knl_securec_check_ss(ret);

    if (stats_create_report_file(stats_file_name, &stats_option->report_idx_file) != CT_SUCCESS) {
        return CT_ERROR;
    }

    ret = sprintf_s(stats_file_name, CT_MAX_FILE_NAME_LEN, STATS_REPORT_FORMAT, stats_file_dir,
                    entity->entry->name, "COL");
    knl_securec_check_ss(ret);

    if (stats_create_report_file(stats_file_name, &stats_option->report_col_file) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

void stats_close_report_file(bool8 is_report, stats_option_t *stats_option)
{
    if (is_report) {
        cm_close_file(stats_option->report_col_file);
        cm_close_file(stats_option->report_tab_file);
        cm_close_file(stats_option->report_idx_file);
    }
}

static status_t stats_values_convert_str(knl_column_t *column, text_t *res_value, text_t *value)
{
    binary_t bin;
    dec8_t dec;

    switch (column->datatype) {
        case CT_TYPE_BOOLEAN:
            cm_bool2text(*(bool32 *)res_value->str, value);
            break;

        case CT_TYPE_UINT32:
            cm_uint32_to_text(*(uint32 *)res_value->str, value);
            break;
        case CT_TYPE_INTEGER:
            cm_int2text(*(int32 *)res_value->str, value);
            break;

        case CT_TYPE_DATE:
            if (cm_date2text(*(date_t *)res_value->str, NULL, value, STATS_MAX_BUCKET_SIZE) != CT_SUCCESS) {
                return CT_ERROR;
            }
            break;
        case CT_TYPE_TIMESTAMP:
        case CT_TYPE_TIMESTAMP_TZ_FAKE:
        case CT_TYPE_TIMESTAMP_LTZ:
            if (cm_timestamp2text(*(date_t *)res_value->str, NULL, value, STATS_MAX_BUCKET_SIZE) != CT_SUCCESS) {
                return CT_ERROR;
            }
            break;
        case CT_TYPE_DATE_MYSQL:
        case CT_TYPE_DATETIME_MYSQL:
        case CT_TYPE_TIME_MYSQL:
            if (cm_date2text_mysql(column->datatype, *(date_t *)res_value->str, NULL, value, STATS_MAX_BUCKET_SIZE) !=
                CT_SUCCESS) {
                return CT_ERROR;
            }
            break;

        case CT_TYPE_TIMESTAMP_TZ:
            if (cm_timestamp_tz2text((timestamp_tz_t *)res_value->str, NULL, value,
                STATS_MAX_BUCKET_SIZE) != CT_SUCCESS) {
                return CT_ERROR;
            }
            break;

        case CT_TYPE_UINT64:
            cm_uint64_to_text(*(uint64 *)res_value->str, value);
            break;
        case CT_TYPE_BIGINT:
            cm_bigint2text(*(int64 *)res_value->str, value);
            break;

        case CT_TYPE_REAL:
            cm_real2text(*(double *)res_value->str, value);
            break;

        case CT_TYPE_STRING:
        case CT_TYPE_CHAR:
        case CT_TYPE_VARCHAR:
            value->len = res_value->len;
            (void)cm_text2str(res_value, value->str, STATS_MAX_BUCKET_SIZE);
            break;

        case CT_TYPE_NUMBER:
        case CT_TYPE_NUMBER3:
        case CT_TYPE_DECIMAL:
            if (cm_dec_4_to_8(&dec, (dec4_t *)res_value->str, res_value->len) != CT_SUCCESS) {
                return CT_ERROR;
            }
            (void)cm_dec_to_text(&dec, STATS_DEC_BUCKET_SIZE, value);
            break;
        case CT_TYPE_NUMBER2:
            CT_RETURN_IFERR(cm_dec_2_to_8(&dec, (payload_t *)res_value->str, res_value->len));
            (void)cm_dec_to_text(&dec, STATS_DEC_BUCKET_SIZE, value);
            break;

        case CT_TYPE_INTERVAL_YM:
            (void)cm_yminterval2text(*(interval_ym_t *)res_value->str, value);
            break;

        case CT_TYPE_INTERVAL_DS:
            (void)cm_dsinterval2text(*(interval_ds_t *)res_value->str, value);
            break;

        default:
            bin.bytes = (uint8 *)res_value->str;
            if (res_value->len >= STATS_MAX_BUCKET_SIZE / 2) {
                // because binary type -> text,size of text will be twice size of binary
                // eg:binary "22222111" --> text "3232323232313131"
                bin.size = (STATS_MAX_BUCKET_SIZE - 1) / 2;
            } else {
                bin.size = res_value->len;
            }
            value->len = STATS_MAX_BUCKET_SIZE;
            if (cm_bin2text(&bin, CT_FALSE, value) != CT_SUCCESS) {
                return CT_ERROR;
            }
            break;
    }

    return CT_SUCCESS;
}

void stats_set_load_info(stats_load_info_t *load_info, dc_entity_t *entity, bool32 load_subpart, uint32 part_id)
{
    load_info->load_subpart = load_subpart;
    
    if (entity->cbo_table_stats != NULL && STATS_GLOBAL_CBO_STATS_EXIST(entity)) {
        load_info->parent_part_id = part_id;
    } else {
        load_info->parent_part_id = CT_INVALID_ID32;
    }
}

static status_t stats_write_report_hist_value(stats_col_handler_t *column_handler, cbo_stats_column_t *cbo_col,
                                              int32 report_file, text_t *value, text_t *endpoint_value)
{
    knl_column_t *column = column_handler->column;
    cbo_column_hist_t *hist_infos = NULL;
    uint32 buck_pos = column_handler->hist_info.bucket_num;
    text_t old_value;
    char val_buf[STATS_DEC_BUCKET_SIZE] = { '\0' };
    char ep_buf[STATS_DEC_BUCKET_SIZE] = { '\0' };
    text_t old_ep_num;

    old_value.len = 0;
    old_value.str = val_buf;

    old_ep_num.len = 0;
    old_ep_num.str = ep_buf;
   
    if (cbo_col != NULL && cbo_col->column_hist != NULL) {
        hist_infos = cbo_col->column_hist[buck_pos];
    }

    (void)cm_write_str(report_file, value->str);
    (void)cm_write_str(report_file, ",");
    (void)cm_write_str(report_file, endpoint_value->str);
    (void)cm_write_str(report_file, ",");

    if (hist_infos != NULL) {
        if (stats_values_convert_str(column, &hist_infos->ep_value, &old_value) != CT_SUCCESS) {
            return CT_ERROR;
        }

        (void)cm_write_str(report_file, old_value.str);
        (void)cm_write_str(report_file, ",");
        cm_uint32_to_text((uint32)hist_infos->ep_number, &old_ep_num);
        (void)cm_write_str(report_file, old_ep_num.str);
        (void)cm_write_str(report_file, ",");
    }

    (void)cm_write_str(report_file, "\n");
    return CT_SUCCESS;
}

static status_t stats_put_report_hist_value(knl_session_t *session, stats_col_handler_t *column_handler,
                                            dc_entity_t *entity, stats_table_t *tab_stats)
{
    int32 report_file = tab_stats->stats_option.report_col_file;
    cbo_stats_column_t *cbo_col = NULL;
    mtrl_cursor_t *mtrl_cur = &column_handler->mtrl.mtrl_cur;
    knl_column_t *column = column_handler->column;
    uint32 endpoint = column_handler->hist_info.endpoint;
    text_t res_value;
    char val_buf[STATS_DEC_BUCKET_SIZE] = { '\0' };
    char ep_buf[STATS_DEC_BUCKET_SIZE] = { '\0' };
    text_t value;
    text_t endpoint_value;

    res_value.len = STATS_GET_ROW_SIZE(mtrl_cur);
    res_value.str = STATS_GET_ROW_DATA(mtrl_cur);

    value.len = 0;
    value.str = val_buf;

    endpoint_value.len = 0;
    endpoint_value.str = ep_buf;
    cm_uint32_to_text(endpoint, &endpoint_value);

    if (res_value.len == 0) {
        res_value.str = '\0';
    }

    if (res_value.len > STATS_MAX_BUCKET_SIZE) {
        res_value.len = STATS_MAX_BUCKET_SIZE;
    }

    if (stats_values_convert_str(column, &res_value, &value) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (tab_stats->part_stats.part_id != CT_INVALID_ID32) {
        cbo_col = knl_get_cbo_part_column(session, entity, tab_stats->part_stats.part_no, column->id);
    } else {
        cbo_col = knl_get_cbo_column(session, entity, column->id);
    }

    if (stats_write_report_hist_value(column_handler, cbo_col, report_file, &value, &endpoint_value) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static void stats_write_uint32_deviation_rate(uint32 ori_value, uint32 verify_value, int32 report_file)
{
    double deviation_rate;
    char buf[STATS_MAX_BUCKET_SIZE] = { '\0' };
    text_t value;

    value.len = 0;
    value.str = buf;

    if (verify_value != 0) {
        deviation_rate = ((double)(int32)(ori_value - verify_value) / (int32)verify_value);
        cm_real2text(deviation_rate, &value);
        (void)cm_write_str(report_file, "Deviation rate:");
        (void)cm_write_str(report_file, value.str);
        (void)cm_write_str(report_file, ",");
        return;
    }

    if (verify_value == ori_value) {
        (void)cm_write_str(report_file, "Deviation rate:0,");
    } else {
        (void)cm_write_str(report_file, "Deviation rate:-1,");
    }
}

static void stats_write_double_deviation_rate(double ori_value, double verify_value, int32 report_file)
{
    double deviation_rate;
    char buf[STATS_MAX_BUCKET_SIZE] = { '\0' };
    text_t value;

    value.len = 0;
    value.str = buf;

    if (verify_value > CT_REAL_PRECISION) {
        deviation_rate = (double)((ori_value - verify_value) / verify_value);
        cm_real2text(deviation_rate, &value);
        (void)cm_write_str(report_file, "Deviation rate:");
        (void)cm_write_str(report_file, value.str);
        (void)cm_write_str(report_file, ",");
    } else {
        (void)cm_write_str(report_file, "Deviation rate:-1,");
    }
}

static void stats_write_origin_idx_value(cbo_stats_index_t *cbo_idx, stats_index_t *stats_idx, int32 report_file,
                                         text_t *value)
{
    if (cbo_idx == NULL) {
        (void)cm_write_str(report_file, "OLD_BLEVEL:0,");
        (void)cm_write_str(report_file, "OLD_LEVEL_BLOCKS:0,");
        (void)cm_write_str(report_file, "OLD_DISTKEY:0,");
        (void)cm_write_str(report_file, "OLD_CLUFAC:0,");
        (void)cm_write_str(report_file, "OLD_AVG_DATA_KEY:0,");
        (void)cm_write_str(report_file, "OLD_AVG_LEAF_KEY:0,");
        (void)cm_write_str(report_file, "OLD_EMPTY_LEAF_BLOCKS:0,");
        (void)cm_write_str(report_file, "OLD_COMB_COLS_2_NDV:0,");
        (void)cm_write_str(report_file, "OLD_COMB_COLS_3_NDV:0,");
        (void)cm_write_str(report_file, "OLD_COMB_COLS_4_NDV:0,");
        (void)cm_write_str(report_file, "\n");

        for (uint32 i = 0; i < STATS_SYS_INDEX_COLS_NUM; i++) {
            stats_write_uint32_deviation_rate(0, 0, report_file);
        }
        (void)cm_write_str(report_file, "\n");
        return;
    }

    cm_uint32_to_text(cbo_idx->blevel, value);
    (void)cm_write_str(report_file, "OLD_BLEVEL:");
    (void)cm_write_str(report_file, value->str);

    cm_uint32_to_text(cbo_idx->leaf_blocks, value);
    (void)cm_write_str(report_file, ",OLD_LEVEL_BLOCKS:");
    (void)cm_write_str(report_file, value->str);

    cm_uint32_to_text(cbo_idx->distinct_keys, value);
    (void)cm_write_str(report_file, ",OLD_DISTKEY:");
    (void)cm_write_str(report_file, value->str);

    cm_uint32_to_text(cbo_idx->clustering_factor, value);
    (void)cm_write_str(report_file, ",OLD_CLUFAC:");
    (void)cm_write_str(report_file, value->str);

    cm_real2text(cbo_idx->avg_data_key, value);
    (void)cm_write_str(report_file, ",OLD_AVG_DATA_KEY:");
    (void)cm_write_str(report_file, value->str);

    cm_real2text(cbo_idx->avg_leaf_key, value);
    (void)cm_write_str(report_file, ",OLD_AVG_LEAF_KEY:");
    (void)cm_write_str(report_file, value->str);

    cm_uint32_to_text(cbo_idx->empty_leaf_blocks, value);
    (void)cm_write_str(report_file, ",OLD_EMPTY_LEAF_BLOCKS:");
    (void)cm_write_str(report_file, value->str);

    cm_uint32_to_text(cbo_idx->comb_cols_2_ndv, value);
    (void)cm_write_str(report_file, ",OLD_COMB_COLS_2_NDV:");
    (void)cm_write_str(report_file, value->str);

    cm_uint32_to_text(cbo_idx->comb_cols_3_ndv, value);
    (void)cm_write_str(report_file, ",OLD_COMB_COLS_3_NDV:");
    (void)cm_write_str(report_file, value->str);

    cm_uint32_to_text(cbo_idx->comb_cols_4_ndv, value);
    (void)cm_write_str(report_file, ",OLD_COMB_COLS_4_NDV:");
    (void)cm_write_str(report_file, value->str);
    (void)cm_write_str(report_file, "\n");

    stats_write_uint32_deviation_rate(cbo_idx->blevel, stats_idx->info.height, report_file);
    stats_write_uint32_deviation_rate(cbo_idx->leaf_blocks, stats_idx->info.leaf_blocks, report_file);
    stats_write_uint32_deviation_rate(cbo_idx->distinct_keys, stats_idx->info.distinct_keys, report_file);
    stats_write_uint32_deviation_rate(cbo_idx->clustering_factor, stats_idx->clus_factor, report_file);
    stats_write_double_deviation_rate(cbo_idx->avg_data_key, stats_idx->avg_data_key, report_file);
    stats_write_double_deviation_rate(cbo_idx->avg_leaf_key, stats_idx->avg_leaf_key, report_file);
    stats_write_uint32_deviation_rate(cbo_idx->empty_leaf_blocks, stats_idx->info.empty_leaves, report_file);
    stats_write_uint32_deviation_rate(cbo_idx->comb_cols_2_ndv, stats_idx->info.comb_cols_2_ndv, report_file);
    stats_write_uint32_deviation_rate(cbo_idx->comb_cols_3_ndv, stats_idx->info.comb_cols_3_ndv, report_file);
    stats_write_uint32_deviation_rate(cbo_idx->comb_cols_4_ndv, stats_idx->info.comb_cols_4_ndv, report_file);
    (void)cm_write_str(report_file, "\n");
    (void)cm_write_str(report_file, "\n");
}

static void stats_write_report_idx_value(knl_session_t *session, dc_entity_t *entity, stats_index_t *stats_idx,
                                         stats_table_t *table_stats)
{
    cbo_stats_index_t *cbo_idx = NULL;
    int32 report_file = table_stats->stats_option.report_idx_file;
    index_t *idx = stats_idx->btree->index;
    char buf[STATS_MAX_BUCKET_SIZE] = { '\0' };
    text_t value;

    if (!entity->stat_exists) {
        CT_LOG_RUN_ERR("[STATS] fail to write report because of the statistics' absence of the table %s.",
            entity->entry->name);
        return;
    }

    value.len = 0;
    value.str = buf;

    (void)cm_write_str(report_file, "INDEX:");
    (void)cm_write_str(report_file, idx->desc.name);

    cm_uint32_to_text(stats_idx->part_id, &value);
    (void)cm_write_str(report_file, " PART_ID:");
    (void)cm_write_str(report_file, value.str);
    (void)cm_write_str(report_file, "\n");

    cm_uint32_to_text(stats_idx->info.height, &value);
    (void)cm_write_str(report_file, " BLEVEL:");
    (void)cm_write_str(report_file, value.str);

    cm_uint32_to_text(stats_idx->info.leaf_blocks, &value);
    (void)cm_write_str(report_file, ",LEVEL_BLOCKS:");
    (void)cm_write_str(report_file, value.str);

    cm_uint32_to_text(stats_idx->info.distinct_keys, &value);
    (void)cm_write_str(report_file, ",DISTKEY:");
    (void)cm_write_str(report_file, value.str);

    cm_uint32_to_text(stats_idx->clus_factor, &value);
    (void)cm_write_str(report_file, ",CLUFAC:");
    (void)cm_write_str(report_file, value.str);

    cm_real2text(stats_idx->avg_data_key, &value);
    (void)cm_write_str(report_file, ",AVG_DATA_KEY:");
    (void)cm_write_str(report_file, value.str);

    cm_real2text(stats_idx->avg_leaf_key, &value);
    (void)cm_write_str(report_file, ",AVG_LEAF_KEY:");
    (void)cm_write_str(report_file, value.str);

    cm_uint32_to_text(stats_idx->info.empty_leaves, &value);
    (void)cm_write_str(report_file, ",EMPTY_LEAF_BLOCKS:");
    (void)cm_write_str(report_file, value.str);

    cm_uint32_to_text(stats_idx->info.comb_cols_2_ndv, &value);
    (void)cm_write_str(report_file, ",COMB_COLS_2_NDV:");
    (void)cm_write_str(report_file, value.str);

    cm_uint32_to_text(stats_idx->info.comb_cols_3_ndv, &value);
    (void)cm_write_str(report_file, ",COMB_COLS_3_NDV:");
    (void)cm_write_str(report_file, value.str);

    cm_uint32_to_text(stats_idx->info.comb_cols_4_ndv, &value);
    (void)cm_write_str(report_file, ",COMB_COLS_4_NDV:");
    (void)cm_write_str(report_file, value.str);
    (void)cm_write_str(report_file, ",\n");

    if (stats_idx->part_id == CT_INVALID_ID32) {
        cbo_idx = knl_get_cbo_index(session, entity, idx->desc.id);
    } else {
        cbo_idx = knl_get_cbo_part_index(session, entity, stats_idx->part_index->part_no, idx->desc.id);
    }

    stats_write_origin_idx_value(cbo_idx, stats_idx, report_file, &value);
}

static void stats_write_origin_tab_values(cbo_stats_table_t *cbo_tab, stats_table_t *stats_tab, int32 report_file,
                                          text_t *value, bool32 is_part)
{
    if (cbo_tab == NULL) {
        (void)cm_write_str(report_file, "OLD_ROW_NUM:0");
        (void)cm_write_str(report_file, ",OLD_BLOCKS:0");
        (void)cm_write_str(report_file, ",OLD_EMPTY_BLOCK:0");
        (void)cm_write_str(report_file, ",OLD_AVG_ROW_LEN:0");
        (void)cm_write_str(report_file, ",OLD_SAMPLE_SIZE:0");

        for (uint32 i = 0; i < STATS_SYS_TABLE_COLS_NUM; i++) {
            stats_write_uint32_deviation_rate(0, 0, report_file);
        }

        (void)cm_write_str(report_file, "\n");
        return;
    }

    cm_uint32_to_text(cbo_tab->rows, value);
    (void)cm_write_str(report_file, "OLD_ROW_NUM:");
    (void)cm_write_str(report_file, value->str);

    cm_uint32_to_text(cbo_tab->blocks, value);
    (void)cm_write_str(report_file, ",OLD_BLOCKS:");
    (void)cm_write_str(report_file, value->str);

    cm_uint32_to_text(cbo_tab->empty_blocks, value);
    (void)cm_write_str(report_file, ",OLD_EMPTY_BLOCK:");
    (void)cm_write_str(report_file, value->str);

    cm_uint32_to_text((uint32)cbo_tab->avg_row_len, value);
    (void)cm_write_str(report_file, ",OLD_AVG_ROW_LEN:");
    (void)cm_write_str(report_file, value->str);

    cm_uint32_to_text(cbo_tab->sample_size, value);
    (void)cm_write_str(report_file, ",OLD_SAMPLE_SIZE:");
    (void)cm_write_str(report_file, value->str);
    (void)cm_write_str(report_file, "\n");

    if (is_part) {
        stats_write_uint32_deviation_rate(cbo_tab->rows, stats_tab->part_stats.info.rows, report_file);
        stats_write_uint32_deviation_rate(cbo_tab->blocks, stats_tab->part_stats.info.blocks, report_file);
        stats_write_uint32_deviation_rate(cbo_tab->empty_blocks, stats_tab->part_stats.info.empty_block, report_file);
        stats_write_uint32_deviation_rate((uint32)cbo_tab->avg_row_len, (uint32)stats_tab->part_stats.info.avg_row_len,
                                          report_file);
        stats_write_uint32_deviation_rate(cbo_tab->sample_size, (uint32)stats_tab->part_stats.info.sample_size, report_file);
    } else {
        stats_write_uint32_deviation_rate(cbo_tab->rows, stats_tab->tab_info.rows, report_file);
        stats_write_uint32_deviation_rate(cbo_tab->blocks, stats_tab->tab_info.blocks, report_file);
        stats_write_uint32_deviation_rate(cbo_tab->empty_blocks, stats_tab->tab_info.empty_block, report_file);
        stats_write_uint32_deviation_rate((uint32)cbo_tab->avg_row_len, (uint32)stats_tab->tab_info.avg_row_len, report_file);
        stats_write_uint32_deviation_rate(cbo_tab->sample_size, (uint32)stats_tab->tab_info.sample_size, report_file);
    }
    
    (void)cm_write_str(report_file, "\n");
    (void)cm_write_str(report_file, "\n");
}

static status_t stats_write_report_tab_value(knl_session_t *session, dc_entity_t *entity, stats_table_t *stats_tab,
                                             bool32 is_part)
{
    int32 report_file = stats_tab->stats_option.report_tab_file;
    cbo_stats_table_t *cbo_tab = NULL;
    char buf[STATS_MAX_BUCKET_SIZE] = { '\0' };
    text_t value;

    value.len = 0;
    value.str = buf;
    
    cm_uint32_to_text(stats_tab->part_stats.part_id, &value);
    (void)cm_write_str(report_file, "PART ID:");
    (void)cm_write_str(report_file, value.str);

    cm_real2text(stats_tab->estimate_sample_ratio, &value);
    (void)cm_write_str(report_file, ",SAMPLE_RATIO:");
    (void)cm_write_str(report_file, value.str);
    (void)cm_write_str(report_file, "\n");

    if (is_part) {
        cm_uint32_to_text(stats_tab->part_stats.info.rows, &value);
        (void)cm_write_str(report_file, "ROW_NUM:");
        (void)cm_write_str(report_file, value.str);

        cm_uint32_to_text(stats_tab->part_stats.info.blocks, &value);
        (void)cm_write_str(report_file, ",BLOCKS:");
        (void)cm_write_str(report_file, value.str);

        cm_uint32_to_text(stats_tab->part_stats.info.empty_block, &value);
        (void)cm_write_str(report_file, ",EMPTY_BLOCK:");
        (void)cm_write_str(report_file, value.str);

        cm_uint32_to_text((uint32)stats_tab->part_stats.info.avg_row_len, &value);
        (void)cm_write_str(report_file, ",AVG_ROW_LEN:");
        (void)cm_write_str(report_file, value.str);

        cm_uint32_to_text((uint32)stats_tab->part_stats.info.sample_size, &value);
        (void)cm_write_str(report_file, ",SAMPLE_SIZE:");
        (void)cm_write_str(report_file, value.str);
    } else {
        cm_uint32_to_text(stats_tab->tab_info.rows, &value);
        (void)cm_write_str(report_file, "ROW_NUM:");
        (void)cm_write_str(report_file, value.str);

        cm_uint32_to_text(stats_tab->tab_info.blocks, &value);
        (void)cm_write_str(report_file, ",BLOCKS:");
        (void)cm_write_str(report_file, value.str);

        cm_uint32_to_text(stats_tab->tab_info.empty_block, &value);
        (void)cm_write_str(report_file, ",EMPTY_BLOCK:");
        (void)cm_write_str(report_file, value.str);

        cm_uint32_to_text((uint32)stats_tab->tab_info.avg_row_len, &value);
        (void)cm_write_str(report_file, ",AVG_ROW_LEN:");
        (void)cm_write_str(report_file, value.str);

        cm_uint32_to_text((uint32)stats_tab->tab_info.sample_size, &value);
        (void)cm_write_str(report_file, ",SAMPLE_SIZE:");
        (void)cm_write_str(report_file, value.str);
    }
    (void)cm_write_str(report_file, "\n");

    if (stats_tab->part_stats.part_id == CT_INVALID_ID32) {
        cbo_tab = knl_get_cbo_table(session, entity);
    } else {
        cbo_tab = knl_get_cbo_part_table(session, entity, stats_tab->part_stats.part_no);
    }

    stats_write_origin_tab_values(cbo_tab, stats_tab, report_file, &value, is_part);
    return CT_SUCCESS;
}

static void stats_write_report_col_header(knl_column_t *col, stats_col_handler_t *stats_col, int32 report_file,
                                          uint32 part_id)
{
    char buf[STATS_MAX_BUCKET_SIZE] = { '\0' };
    text_t value;

    value.len = 0;
    value.str = buf;

    cm_real2text(stats_col->simple_ratio, &value);
    (void)cm_write_str(report_file, "COLUMN:");
    (void)cm_write_str(report_file, col->name);
    (void)cm_write_str(report_file, ",SAMPLE_RATIO:");
    (void)cm_write_str(report_file, value.str);

    cm_uint32_to_text(part_id, &value);
    (void)cm_write_str(report_file, ",PART_ID:");
    (void)cm_write_str(report_file, value.str);
    (void)cm_write_str(report_file, ",");
    (void)cm_write_str(report_file, "\n");

    (void)cm_write_str(report_file, "HISTGRAM INFO");
    (void)cm_write_str(report_file, ",\n");

    (void)cm_write_str(report_file, "VERIFY_VALUE,");
    (void)cm_write_str(report_file, "VERIFY_ENDPOINT,");
    (void)cm_write_str(report_file, "CURR_VALUE,");
    (void)cm_write_str(report_file, "CURR_ENDPOINT,");
    (void)cm_write_str(report_file, "\n");
}

static void stats_write_report_col_tail(knl_session_t *session, stats_col_handler_t *stats_col,
                                        dc_entity_t *entity, stats_table_t *tab_stats)
{
    int32 report_file = tab_stats->stats_option.report_col_file;
    cbo_stats_column_t *cbo_col = NULL;
    knl_column_t *column = stats_col->column;
    char buf[STATS_MAX_BUCKET_SIZE] = { '\0' };
    text_t value;

    value.len = 0;
    value.str = buf;

    (void)cm_write_str(report_file, "COLUMN INFO:,");
    (void)cm_write_str(report_file, "\n");

    cm_uint32_to_text(stats_col->total_rows, &value);
    (void)cm_write_str(report_file, "TOTAL_NUM:");
    (void)cm_write_str(report_file, value.str);

    cm_uint32_to_text(stats_col->dist_num, &value);
    (void)cm_write_str(report_file, ",DIST_NUM:");
    (void)cm_write_str(report_file, value.str);

    cm_uint32_to_text(stats_col->null_num, &value);
    (void)cm_write_str(report_file, ",NULL_NUM:");
    (void)cm_write_str(report_file, value.str);

    cm_uint32_to_text(stats_col->hist_info.bucket_num, &value);
    (void)cm_write_str(report_file, ",BUCKET_NUM:");
    (void)cm_write_str(report_file, value.str);
    (void)cm_write_str(report_file, ",\n");

    if (tab_stats->part_stats.part_id != CT_INVALID_ID32) {
        cbo_col = knl_get_cbo_part_column(session, entity, tab_stats->part_stats.part_no, column->id);
    } else {
        cbo_col = knl_get_cbo_column(session, entity, column->id);
    }

    if (cbo_col != NULL) {
        cm_uint32_to_text(cbo_col->total_rows, &value);
        (void)cm_write_str(report_file, "OLD_TOTAL_NUM:");
        (void)cm_write_str(report_file, value.str);

        cm_uint32_to_text(cbo_col->num_distinct, &value);
        (void)cm_write_str(report_file, ",OLD_DIST_NUM:");
        (void)cm_write_str(report_file, value.str);

        cm_uint32_to_text(cbo_col->num_null, &value);
        (void)cm_write_str(report_file, ",OLD_NULL_NUM:");
        (void)cm_write_str(report_file, value.str);

        cm_uint32_to_text(cbo_col->num_buckets, &value);
        (void)cm_write_str(report_file, ",OLD_BUCKET_NUM:");
        (void)cm_write_str(report_file, value.str);
        (void)cm_write_str(report_file, ",\n");

        stats_write_uint32_deviation_rate(cbo_col->total_rows, stats_col->total_rows, report_file);
        stats_write_uint32_deviation_rate(cbo_col->num_distinct, stats_col->dist_num, report_file);
        stats_write_uint32_deviation_rate(cbo_col->num_null, stats_col->null_num, report_file);
        stats_write_uint32_deviation_rate(cbo_col->num_buckets, stats_col->hist_info.bucket_num, report_file);
    } else {
        (void)cm_write_str(report_file, "OLD_TOTAL_NUM:0");
        (void)cm_write_str(report_file, ",OLD_DIST_NUM:0");
        (void)cm_write_str(report_file, ",OLD_NULL_NUM:0");
        (void)cm_write_str(report_file, ",OLD_BUCKET_NUM:0");
        (void)cm_write_str(report_file, ",\n");
        for (uint32 i = 0; i < STATS_SYS_HISTATTR_COLS_NUM; i++) {
            stats_write_uint32_deviation_rate(0, 0, report_file);
        }
    }

    (void)cm_write_str(report_file, "\n");
}

void stats_init_column_handler(knl_session_t *session, stats_col_handler_t *column_handler,
    stats_col_context_t *col_ctx, stats_tab_context_t *tab_ctx)
{
    stats_table_t *table_stats = tab_ctx->table_stats;
    mtrl_context_t *temp_ctx = tab_ctx->mtrl_tab_ctx;
    uint32 temp_seg = tab_ctx->mtrl_tab_seg;
    errno_t ret;
    knl_column_t *column = col_ctx->column;
    ret = memset_sp(column_handler, sizeof(stats_col_handler_t), 0, sizeof(stats_col_handler_t));
    knl_securec_check(ret);
    column_handler->column = column;

    mtrl_init_context(&column_handler->mtrl.mtrl_ctx, session);
    column_handler->mtrl.mtrl_ctx.sort_cmp = stats_mtrl_sort_cmp;
    column_handler->max_bucket_size = session->kernel->attr.stats_max_buckets;

    column_handler->stats_cur = col_ctx->stats_cur;
    column_handler->min_value.str = column_handler->min_buf;
    column_handler->min_value.len = CT_NULL_VALUE_LEN;
    column_handler->max_value.str = column_handler->max_buf;
    column_handler->max_value.len = CT_NULL_VALUE_LEN;
    column_handler->mtrl.mtrl_table_ctx = temp_ctx;
    column_handler->mtrl.temp_seg_id = temp_seg;
    column_handler->simple_ratio = table_stats->estimate_sample_ratio;
    column_handler->is_nologging = tab_ctx->table_stats->is_nologging;

    if (table_stats->is_part) {
        column_handler->g_rid = table_stats->part_start_rid;  // for record data position in temp table of every table part
    }
}

bool32 stats_check_same_page_step(stats_sampler_t *stat_sample, uint32 randvalue)
{
    uint32 i;

    for (i = 1; i < stat_sample->pages_per_ext; i++) {
        if (stat_sample->random_step[i] == randvalue) {
            return CT_TRUE;
        }

        if (stat_sample->random_step[i] == 0) {
            break;
        }
    }
   
    stat_sample->random_step[i] = randvalue;
    return CT_FALSE;
}

void stats_random_page_step(stats_sampler_t *stat_sample)
{
    uint32 randvalue = 0;
    bool32 is_exist = CT_TRUE;

    while (is_exist) {
        randvalue = cm_random(stat_sample->extent_size);
        if (randvalue >= stat_sample->extent_size) {
            randvalue = randvalue % stat_sample->extent_size;
        }

        if (randvalue == 0) {
            randvalue++;
        }

        is_exist = stats_check_same_page_step(stat_sample, randvalue);
    }
}

static void stats_series_page_step(stats_sampler_t *stat_sample)
{
    uint32 rand_value = 0;
    uint32 step = 0;

    uint32 value_range = stat_sample->extent_size - stat_sample->pages_per_ext;

    if (value_range > 0) {
        rand_value = cm_random(value_range);
        if (rand_value > value_range) {
            rand_value = rand_value % value_range;
        }
    }

    for (uint32 i = 0; i < stat_sample->pages_per_ext; i++) {
        step = i + rand_value;

        if (step >= stat_sample->extent_size) {
            step = stat_sample->extent_size - 1;
        }

        stat_sample->random_step[i] = step;
    }
}

static inline void stats_generate_random_step(stats_sampler_t *stat_sample)
{
    if (STATS_GENERATE_SERIERS_PAGE_STAP(stat_sample)) {
        stats_series_page_step(stat_sample);
        return;
    }
    
    for (uint32 i = 1; i < stat_sample->pages_per_ext; i++) {
        stats_random_page_step(stat_sample);
    }
}

status_t stats_next_page_in_extent(knl_session_t *session, knl_cursor_t *cursor, stats_sampler_t *stat_sample,
                                   uint8 *type)
{
    page_id_t page_id;
    table_t *table = (table_t *)cursor->table;
    page_type_t expect_type;
    heap_page_t *page = NULL;
    errno_t ret;
    uint32 pos = stat_sample->sample_extent.count;
    uint32 random_step = stat_sample->random_step[pos];
    char *name = IS_PART_TABLE(table) ? ((table_part_t*)cursor->table_part)->desc.name :
        table->desc.name;  // table name or table part name

    page_id = stat_sample->current_extent;
    page_id.page += random_step;

    if (!spc_validate_page_id(session, page_id)) {
        CT_THROW_ERROR(ERR_OBJECT_ALREADY_DROPPED, name);
        return CT_ERROR;
    }

    expect_type = (table->desc.cr_mode == CR_PAGE) ? PAGE_TYPE_PCRH_DATA : PAGE_TYPE_HEAP_DATA;

    if (session->stat_sample) {
        if (buf_read_page(session, page_id, LATCH_MODE_S,
            ENTER_PAGE_NORMAL | ENTER_PAGE_SEQUENTIAL) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } else {
        if (buf_read_prefetch_page(session, page_id, LATCH_MODE_S, ENTER_PAGE_SEQUENTIAL) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
   
    page = (heap_page_t *)CURR_PAGE(session);
    *type = page->head.type;

    if (page->head.type == PAGE_TYPE_HEAP_MAP || page->head.type == PAGE_TYPE_HEAP_HEAD) {
        stat_sample->map_pages++;
    } else {
        if (!heap_check_page(session, cursor, page, expect_type)) {
            cursor->eof = CT_TRUE;
            buf_leave_page(session, CT_FALSE);
            return CT_SUCCESS;
        }

        ret = memcpy_sp(cursor->page_buf, DEFAULT_PAGE_SIZE(session), page, DEFAULT_PAGE_SIZE(session));
        knl_securec_check(ret);
        SET_ROWID_PAGE(&cursor->rowid, page_id);
    }

    stat_sample->hwm_pages++;
    stat_sample->sample_extent.count++;
    stat_sample->sample_extent.last = page_id;

    buf_leave_page(session, CT_FALSE);
    return CT_SUCCESS;
}

static void stats_next_extent_size(stats_sampler_t *stat_sample, stats_table_t *tab_stats,
    heap_segment_t *segment, heap_page_t *page)
{
    uint32 origin_ext_size = stat_sample->extent_size;
    errno_t ret;

    if (stat_sample->hwm_extents == segment->extents.count) {
        stat_sample->extent_size = spc_ext_size_by_id(page->head.ext_size) - segment->ufp_count;
    } else {
        stat_sample->extent_size = spc_ext_size_by_id(page->head.ext_size);
    }
    stat_sample->pages_per_ext = (uint32)ceil(stat_sample->extent_size * tab_stats->estimate_sample_ratio);

    if (stat_sample->extent_size != origin_ext_size) {
        ret = memset_sp(stat_sample->random_step, sizeof(uint32) * stat_sample->pages_per_ext,
                        0, sizeof(uint32) * stat_sample->pages_per_ext);
        knl_securec_check(ret);
        stats_generate_random_step(stat_sample);
    }
}

static status_t stats_next_extent_page(knl_session_t *session, knl_cursor_t *cursor, stats_sampler_t *stat_sample,
                                       uint8 *type, stats_table_t *tab_stats)
{
    heap_segment_t *segment = (heap_segment_t *)(CURSOR_HEAP(cursor)->segment);
    space_t *space = SPACE_GET(session, segment->space_id);
    table_t *table = (table_t *)cursor->table;
    page_id_t extent;
    page_type_t expect_type = (table->desc.cr_mode == CR_PAGE) ? PAGE_TYPE_PCRH_DATA : PAGE_TYPE_HEAP_DATA;
    uint32 i = 0;
    char *name = IS_PART_TABLE(table) ? ((table_part_t*)cursor->table_part)->desc.name :
        table->desc.name;  // table name or table part name

    if (stat_sample->hwm_extents == 0) {
        extent = segment->extents.first;
    } else {
        extent = stat_sample->current_extent;
    }

    for (;;) {
        if (IS_INVALID_PAGID(extent)) {
            cursor->eof = CT_TRUE;
            return CT_SUCCESS;
        }

        if (!spc_validate_page_id(session, extent)) {
            CT_THROW_ERROR(ERR_OBJECT_ALREADY_DROPPED, name);
            return CT_ERROR;
        }

        if (buf_read_page(session, extent, LATCH_MODE_S,
            ENTER_PAGE_NORMAL | ENTER_PAGE_SEQUENTIAL) != CT_SUCCESS) {
            return CT_ERROR;
        }
       
        heap_page_t *page = (heap_page_t *)CURR_PAGE(session);

        if (NOT_MAP_OR_FIRST_EXTENT(stat_sample, page) && !heap_check_page(session, cursor, page, expect_type)) {
            buf_leave_page(session, CT_FALSE);
            if (cursor->page_soft_damaged) {
                CT_THROW_ERROR(ERR_PAGE_SOFT_DAMAGED, (cursor)->rowid.file, (cursor)->rowid.page);
            } else {
                CT_THROW_ERROR(ERR_OBJECT_ALREADY_DROPPED, name);
            }
            return CT_ERROR;
        }

        if (stat_sample->hwm_extents == 0 || i == stat_sample->extent_step) {
            errno_t ret = memcpy_sp(cursor->page_buf, DEFAULT_PAGE_SIZE(session), page, DEFAULT_PAGE_SIZE(session));
            knl_securec_check(ret);

            SET_ROWID_PAGE(&cursor->rowid, AS_PAGID(page->head.id));
            stat_sample->hwm_extents++;
            stat_sample->hwm_pages++;
            stat_sample->sample_extent.count = 1;
            stat_sample->sample_extent.first = extent;
            stat_sample->sample_extent.last = extent;
            stat_sample->current_extent = extent;

            if (SPACE_IS_BITMAPMANAGED(space)) {
                stats_next_extent_size(stat_sample, tab_stats, segment, page);
            }

            *type = page->head.type;

            buf_leave_page(session, CT_FALSE);
            return CT_SUCCESS;
        }

        extent = AS_PAGID(page->head.next_ext);
        buf_leave_page(session, CT_FALSE);
        i++;
    }
}

static status_t stats_next_sample_page(knl_session_t *session, knl_cursor_t *cursor, stats_table_t *tab_stats,
                                       stats_sampler_t *stat_sample, uint8 *type)
{
    heap_segment_t *segment = NULL;
    table_t *table = (table_t *)cursor->table;
    page_id_t entry = (CURSOR_HEAP(cursor)->entry);
    knl_scn_t seg_scn = IS_PART_TABLE(table) ? ((table_part_t*)cursor->table_part)->desc.seg_scn : table->desc.seg_scn;
    char *name = IS_PART_TABLE(table) ? ((table_part_t*)cursor->table_part)->desc.name :
        table->desc.name;  // table name or table part name

    if (!spc_validate_page_id(session, entry)) {
        CT_THROW_ERROR(ERR_OBJECT_ALREADY_DROPPED, name);
        return CT_ERROR;
    }

    buf_enter_page(session, entry, LATCH_MODE_S, ENTER_PAGE_NORMAL);
    page_head_t *page = (page_head_t *)CURR_PAGE(session);
    segment = HEAP_SEG_HEAD(session);
    if (page->type != PAGE_TYPE_HEAP_HEAD || segment->seg_scn != seg_scn) {
        CT_THROW_ERROR(ERR_OBJECT_ALREADY_DROPPED, name);
        buf_leave_page(session, CT_FALSE);
        return CT_ERROR;
    }
    buf_leave_page(session, CT_FALSE);

    if (stat_sample->hwm_pages >= stat_sample->sample_size) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }

    if (STATA_SAMPLE_CURRENT_EXTENT(stat_sample)) {
        return stats_next_page_in_extent(session, cursor, stat_sample, type);
    }

    return stats_next_extent_page(session, cursor, stat_sample, type, tab_stats);
}

void stats_sample_init(knl_session_t *session, stats_sampler_t *stats_sampler, uint32 extents_count, space_t *space,
                       uint64 sample_size, double sample_ratio)
{
    errno_t ret;
    uint32 steps_len;

    stats_sampler->sample_size = sample_size;
    stats_sampler->total_extents = extents_count;
    stats_sampler->hwm_extents = 0;
    stats_sampler->hwm_pages = 0;
    stats_sampler->sample_extent.count = 0;
    stats_sampler->sample_extent.first = INVALID_PAGID;
    stats_sampler->sample_extent.last = INVALID_PAGID;
    stats_sampler->current_extent = INVALID_PAGID;
    stats_sampler->extent_size = space->ctrl->extent_size;

    if (SPACE_IS_BITMAPMANAGED(space)) {
        stats_sampler->extent_step = 1;
        stats_sampler->pages_per_ext = (uint32)ceil(sample_ratio * space->ctrl->extent_size);
        stats_sampler->sample_extents = extents_count;
    } else {
        stats_sampler->pages_per_ext = STATS_SAMPLE_PAGES_PER_EXT(sample_size, stats_sampler->total_extents);
        stats_sampler->sample_extents = STATS_SAMPLE_EXTENTS_PER_SEG(sample_size, stats_sampler);
        stats_sampler->extent_step = STATS_GET_SAMPLE_EXT_STEP(stats_sampler);
    }

    steps_len = CT_MAX_EXTENT_SIZE * sizeof(uint32);
    stats_sampler->random_step = (uint32 *)cm_push(session->stack, steps_len);
    ret = memset_sp(stats_sampler->random_step, steps_len, 0, steps_len);
    knl_securec_check(ret);

    stats_generate_random_step(stats_sampler);
}

void stats_open_histgram_cursor(knl_session_t *session, knl_cursor_t *cursor, knl_cursor_action_t action,
    uint32 index_id, bool32 is_nologging)
{
    if (is_nologging) {
        knl_open_sys_cursor(session, cursor, action, SYS_TEMP_HISTGRAM_ID, index_id);
    } else {
        knl_open_sys_cursor(session, cursor, action, SYS_HISTGRM_ID, index_id);
    }
}

void stats_open_hist_abstr_cursor(knl_session_t *session, knl_cursor_t *cursor, knl_cursor_action_t action,
    uint32 index_id, bool32 is_nologging)
{
    if (is_nologging) {
        knl_open_sys_cursor(session, cursor, action, SYS_TEMP_HIST_HEAD_ID, index_id);
    } else {
        knl_open_sys_cursor(session, cursor, action, SYS_HIST_HEAD_ID, index_id);
    }
}

status_t stats_delete_histhead_by_subpart(knl_session_t *session, table_part_t *sub_part, bool32 is_nologging)
{
    knl_cursor_t *cursor = NULL;
    uint64 part;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);
    stats_open_hist_abstr_cursor(session, cursor, CURSOR_ACTION_DELETE, IX_HIST_HEAD_003_ID, is_nologging);
    knl_init_index_scan(cursor, CT_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&sub_part->desc.uid,
        sizeof(uint32), IX_COL_HIST_HEAD_003_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER,
        (void *)&sub_part->desc.table_id, sizeof(uint32), IX_COL_HIST_HEAD_003_TABLE_ID);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_HIST_HEAD_003_COL_ID);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_HIST_HEAD_003_SPARE1);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_HIST_HEAD_003_SPARE2);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_INTEGER, (void *)&sub_part->desc.uid,
        sizeof(uint32), IX_COL_HIST_HEAD_003_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_INTEGER,
        (void *)&sub_part->desc.table_id, sizeof(uint32), IX_COL_HIST_HEAD_003_TABLE_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_HIST_HEAD_003_COL_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_HIST_HEAD_003_SPARE1);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_HIST_HEAD_003_SPARE2);

    for (;;) {
        if (CT_SUCCESS != knl_fetch(session, cursor)) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }

        if (cursor->eof) {
            break;
        }

        part = *(uint64 *)CURSOR_COLUMN_DATA(cursor, HIST_HEAD_PART_ID);
        if (part != (uint64)sub_part->desc.parent_partid) {
            continue;
        }

        uint64 subpart = *(uint64 *)CURSOR_COLUMN_DATA(cursor, HIST_HEAD_SUBPART_ID);
        if (subpart != (uint64)sub_part->desc.part_id) {
            continue;
        }

        if (CT_SUCCESS != knl_internal_delete(session, cursor)) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}

status_t stats_delete_histhead_by_part(knl_session_t *session, knl_dictionary_t *dc, uint32 part_id)
{
    table_t *table = DC_TABLE(dc);
    knl_match_cond_t org_match_cond = session->match_cond;
    stats_match_cond_t cond;

    CM_SAVE_STACK(session->stack);

    knl_cursor_t *cursor = knl_push_cursor(session);
    stats_open_hist_abstr_cursor(session, cursor, CURSOR_ACTION_DELETE, IX_HIST_HEAD_003_ID,
        IS_NOLOGGING_BY_TABLE_TYPE(table->desc.type));
    knl_init_index_scan(cursor, CT_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&dc->uid,
                     sizeof(uint32), IX_COL_HIST_HEAD_003_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&dc->oid,
                     sizeof(uint32), IX_COL_HIST_HEAD_003_TABLE_ID);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_HIST_HEAD_003_COL_ID);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_HIST_HEAD_003_SPARE1);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_HIST_HEAD_003_SPARE2);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_INTEGER, (void *)&dc->uid,
                     sizeof(uint32), IX_COL_HIST_HEAD_003_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_INTEGER, (void *)&dc->oid,
                     sizeof(uint32), IX_COL_HIST_HEAD_003_TABLE_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_HIST_HEAD_003_COL_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_HIST_HEAD_003_SPARE1);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_HIST_HEAD_003_SPARE2);
    
    cursor->stmt = (void *)&cond;
    session->match_cond = stats_match_histhead;
    cond.session = session;
    cond.cursor = cursor;
    cond.part_id = part_id;
    cond.subpart_id = CT_INVALID_ID32;
    cond.col_id = CT_INVALID_ID32;
    cond.match_type = MATCH_PART;

    for (;;) {
        if (CT_SUCCESS != knl_fetch(session, cursor)) {
            session->match_cond = org_match_cond;
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }

        if (cursor->eof) {
            break;
        }

        if (CT_SUCCESS != knl_internal_delete(session, cursor)) {
            session->match_cond = org_match_cond;
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }
    }

    session->match_cond = org_match_cond;
    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}

status_t stats_delete_histhead_by_column(knl_session_t *session, knl_cursor_t *cursor, knl_column_t *column,
                                         stats_table_t *table_stats, uint32 part_id, bool32 is_subpart)
{
    bool32 is_part = table_stats->is_part;
    uint64 part = part_id;

    CM_SAVE_STACK(session->stack);
    stats_open_hist_abstr_cursor(session, cursor, CURSOR_ACTION_DELETE, IX_HIST_HEAD_003_ID, table_stats->is_nologging);
    knl_init_index_scan(cursor, CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&column->uid,
        sizeof(uint32), IX_COL_HIST_HEAD_003_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&column->table_id,
        sizeof(uint32), IX_COL_HIST_HEAD_003_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&column->id,
        sizeof(uint32), IX_COL_HIST_HEAD_003_COL_ID);

    if (is_part) {
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_BIGINT, (void *)&part,
            sizeof(uint64), IX_COL_HIST_HEAD_003_SPARE1);
    } else {
        knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_IS_NULL, IX_COL_HIST_HEAD_003_SPARE1);
    }
    if (is_subpart) {
        uint64 sub_part = (part == CT_INVALID_ID32) ? CT_INVALID_ID32 : table_stats->part_stats.sub_stats->part_id;
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_BIGINT, (void *)&sub_part,
            sizeof(uint64), IX_COL_HIST_HEAD_003_SPARE2);
    } else {
        knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_IS_NULL, IX_COL_HIST_HEAD_003_SPARE2);
    }
    if (CT_SUCCESS != knl_fetch(session, cursor)) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    if (cursor->eof) {
        CM_RESTORE_STACK(session->stack);
        return CT_SUCCESS;
    }

    if (CT_SUCCESS != knl_internal_delete(session, cursor)) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}

status_t stats_delete_histgrams(knl_session_t *session, knl_cursor_t *cursor, knl_column_t *column, bool32 is_dynamic,
    bool32 is_nologging)
{
    knl_scan_key_t *l_key = NULL;
    knl_scan_key_t *r_key = NULL;

    stats_open_histgram_cursor(session, cursor, CURSOR_ACTION_DELETE, IX_HIST_003_ID, is_nologging);
    knl_init_index_scan(cursor, CT_FALSE);
    l_key = &cursor->scan_range.l_key;
    r_key = &cursor->scan_range.r_key;

    knl_set_scan_key(INDEX_DESC(cursor->index), l_key, CT_TYPE_INTEGER, (void *)&column->uid, sizeof(uint32),
                     IX_COL_HIST_003_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), l_key, CT_TYPE_INTEGER, (void *)&column->table_id, sizeof(uint32),
                     IX_COL_HIST_003_TABLE_ID);
    knl_set_key_flag(l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_HIST_003_COL_ID);
    knl_set_key_flag(l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_HIST_003_PART_ID);
    knl_set_key_flag(l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_HIST_003_ENDPOINT);

    knl_set_scan_key(INDEX_DESC(cursor->index), r_key, CT_TYPE_INTEGER, (void *)&column->uid, sizeof(uint32),
                     IX_COL_HIST_003_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), r_key, CT_TYPE_INTEGER, (void *)&column->table_id, sizeof(uint32),
                     IX_COL_HIST_003_TABLE_ID);
    knl_set_key_flag(r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_HIST_003_COL_ID);
    knl_set_key_flag(r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_HIST_003_PART_ID);
    knl_set_key_flag(r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_HIST_003_ENDPOINT);

    for (;;) {
        if (CT_SUCCESS != knl_fetch(session, cursor)) {
            return CT_ERROR;
        }

        if (cursor->eof) {
            break;
        }

        if (CT_SUCCESS != knl_internal_delete(session, cursor)) {
            return CT_ERROR;
        }

        session->stat->hists_deletes++;
    }

    return CT_SUCCESS;
}

status_t stats_delete_histgram_by_subpart(knl_session_t *session, knl_cursor_t *cursor, table_part_t *subpart,
    bool32 is_nologging)
{
    uint32 part = 0;

    stats_open_histgram_cursor(session, cursor, CURSOR_ACTION_DELETE, IX_HIST_003_ID, is_nologging);
    knl_init_index_scan(cursor, CT_FALSE);
    knl_scan_key_t *l_key = &cursor->scan_range.l_key;
    knl_scan_key_t *r_key = &cursor->scan_range.r_key;

    knl_set_scan_key(INDEX_DESC(cursor->index), l_key, CT_TYPE_INTEGER, (void *)&subpart->desc.uid, sizeof(uint32),
        IX_COL_HIST_003_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), l_key, CT_TYPE_INTEGER, (void *)&subpart->desc.table_id, sizeof(uint32),
        IX_COL_HIST_003_TABLE_ID);
    knl_set_key_flag(l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_HIST_003_COL_ID);
    knl_set_key_flag(l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_HIST_003_PART_ID);
    knl_set_key_flag(l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_HIST_003_ENDPOINT);

    knl_set_scan_key(INDEX_DESC(cursor->index), r_key, CT_TYPE_INTEGER, (void *)&subpart->desc.uid, sizeof(uint32),
        IX_COL_HIST_003_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), r_key, CT_TYPE_INTEGER, (void *)&subpart->desc.table_id, sizeof(uint32),
        IX_COL_HIST_003_TABLE_ID);
    knl_set_key_flag(r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_HIST_003_COL_ID);
    knl_set_key_flag(r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_HIST_003_PART_ID);
    knl_set_key_flag(r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_HIST_003_ENDPOINT);

    for (;;) {
        if (CT_SUCCESS != knl_fetch(session, cursor)) {
            return CT_ERROR;
        }

        if (cursor->eof) {
            break;
        }

        part = *(uint32 *)CURSOR_COLUMN_DATA(cursor, HIST_PART_ID);
        if (part != (uint64)subpart->desc.parent_partid) {
            continue;
        }

        uint64 subpart_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, HIST_SUBPART_ID);
        if (subpart_id != (uint64)subpart->desc.part_id) {
            continue;
        }

        if (CT_SUCCESS != knl_internal_delete(session, cursor)) {
            return CT_ERROR;
        }

        session->stat->hists_deletes++;
    }

    return CT_SUCCESS;
}

void stats_set_part_histgram_scan_key(knl_cursor_t *cursor, knl_column_t *column, uint32 part_id)
{
    knl_scan_key_t *l_key = &cursor->scan_range.l_key;
    knl_scan_key_t *r_key = &cursor->scan_range.r_key;
    knl_set_scan_key(INDEX_DESC(cursor->index), l_key, CT_TYPE_INTEGER, (void *)&column->uid, sizeof(uint32),
        IX_COL_HIST_003_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), l_key, CT_TYPE_INTEGER, (void *)&column->table_id, sizeof(uint32),
        IX_COL_HIST_003_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), l_key, CT_TYPE_INTEGER, (void *)&column->id, sizeof(uint32),
        IX_COL_HIST_003_COL_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), l_key, CT_TYPE_INTEGER, (void *)&part_id, sizeof(uint32),
        IX_COL_HIST_003_PART_ID);
    knl_set_key_flag(l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_HIST_003_ENDPOINT);

    knl_set_scan_key(INDEX_DESC(cursor->index), r_key, CT_TYPE_INTEGER, (void *)&column->uid, sizeof(uint32),
        IX_COL_HIST_003_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), r_key, CT_TYPE_INTEGER, (void *)&column->table_id, sizeof(uint32),
        IX_COL_HIST_003_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), r_key, CT_TYPE_INTEGER, (void *)&column->id, sizeof(uint32),
        IX_COL_HIST_003_COL_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), r_key, CT_TYPE_INTEGER, (void *)&part_id, sizeof(uint32),
        IX_COL_HIST_003_PART_ID);
    knl_set_key_flag(r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_HIST_003_ENDPOINT);
}

status_t stats_delete_histgram_subpart_column(knl_session_t *session, knl_cursor_t *cursor, knl_column_t *column,
    knl_part_locate_t part_loc, bool32 is_nologging)
{
    uint64 part;

    stats_open_histgram_cursor(session, cursor, CURSOR_ACTION_DELETE, IX_HIST_003_ID, is_nologging);
    knl_init_index_scan(cursor, CT_FALSE);
    stats_set_part_histgram_scan_key(cursor, column, part_loc.part_no);

    for (;;) {
        if (CT_SUCCESS != knl_fetch(session, cursor)) {
            return CT_ERROR;
        }

        if (cursor->eof) {
            break;
        }

        part = *(uint64 *)CURSOR_COLUMN_DATA(cursor, HIST_SUBPART_ID);
        if (part != part_loc.part_no) {
            continue;
        }

        if (CT_SUCCESS != knl_internal_delete(session, cursor)) {
            return CT_ERROR;
        }

        session->stat->hists_deletes++;
    }

    return CT_SUCCESS;
}

status_t stats_delete_histgram_part_column(knl_session_t *session, knl_cursor_t *cursor, knl_column_t *column,
                                           uint32 part_id, bool32 is_nologging)
{
    uint32 part = 0;

    stats_open_histgram_cursor(session, cursor, CURSOR_ACTION_DELETE, IX_HIST_003_ID, is_nologging);
    knl_init_index_scan(cursor, CT_FALSE);
    stats_set_part_histgram_scan_key(cursor, column, part_id);

    for (;;) {
        if (CT_SUCCESS != knl_fetch(session, cursor)) {
            return CT_ERROR;
        }

        if (cursor->eof) {
            break;
        }

        part = *(uint32 *)CURSOR_COLUMN_DATA(cursor, HIST_PART_ID);
        if (part != part_id) {
            continue;
        }

        if (CT_SUCCESS != knl_internal_delete(session, cursor)) {
            return CT_ERROR;
        }

        session->stat->hists_deletes++;
    }

    return CT_SUCCESS;
}

status_t stats_delete_histgram_by_part(knl_session_t *session, knl_cursor_t *cursor, knl_dictionary_t *dc,
                                       uint32 part_id)
{
    table_t *table = DC_TABLE(dc);
    bool32 is_nologging = IS_NOLOGGING_BY_TABLE_TYPE(table->desc.type);
    knl_match_cond_t org_match_cond = session->match_cond;
    stats_match_cond_t cond;
    stats_open_histgram_cursor(session, cursor, CURSOR_ACTION_DELETE, IX_HIST_003_ID, is_nologging);
    knl_init_index_scan(cursor, CT_FALSE);
    knl_scan_key_t *l_key = &cursor->scan_range.l_key;
    knl_scan_key_t *r_key = &cursor->scan_range.r_key;

    knl_set_scan_key(INDEX_DESC(cursor->index), l_key, CT_TYPE_INTEGER, (void *)&dc->uid, sizeof(uint32),
                     IX_COL_HIST_003_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), l_key, CT_TYPE_INTEGER, (void *)&dc->oid, sizeof(uint32),
                     IX_COL_HIST_003_TABLE_ID);
    knl_set_key_flag(l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_HIST_003_COL_ID);
    knl_set_key_flag(l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_HIST_003_PART_ID);
    knl_set_key_flag(l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_HIST_003_ENDPOINT);

    knl_set_scan_key(INDEX_DESC(cursor->index), r_key, CT_TYPE_INTEGER, (void *)&dc->uid, sizeof(uint32),
                     IX_COL_HIST_003_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), r_key, CT_TYPE_INTEGER, (void *)&dc->oid, sizeof(uint32),
                     IX_COL_HIST_003_TABLE_ID);
    knl_set_key_flag(r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_HIST_003_COL_ID);
    knl_set_key_flag(r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_HIST_003_PART_ID);
    knl_set_key_flag(r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_HIST_003_ENDPOINT);
    
    cursor->stmt = (void *)&cond;
    session->match_cond = stats_match_histgram;
    cond.session = session;
    cond.cursor = cursor;
    cond.part_id = part_id;
    cond.subpart_id = CT_INVALID_ID32;
    cond.col_id = CT_INVALID_ID32;
    cond.match_type = MATCH_PART;

    for (;;) {
        if (CT_SUCCESS != knl_fetch(session, cursor)) {
            session->match_cond = org_match_cond;
            return CT_ERROR;
        }

        if (cursor->eof) {
            break;
        }

        if (CT_SUCCESS != knl_internal_delete(session, cursor)) {
            session->match_cond = org_match_cond;
            return CT_ERROR;
        }

        session->stat->hists_deletes++;
    }

    session->match_cond = org_match_cond;
    return CT_SUCCESS;
}

static status_t stats_delete_from_sys_histgram(knl_session_t *session, knl_cursor_t *cursor, uint32 uid, uint32 oid,
    bool32 is_nologging)
{
    knl_scan_key_t *l_key = NULL;
    knl_scan_key_t *r_key = NULL;
    stats_open_histgram_cursor(session, cursor, CURSOR_ACTION_DELETE, IX_HIST_003_ID, is_nologging);
    l_key = &cursor->scan_range.l_key;
    r_key = &cursor->scan_range.r_key;
    knl_init_index_scan(cursor, CT_FALSE);
    if (oid == CT_INVALID_ID32) {
        knl_set_scan_key(INDEX_DESC(cursor->index), l_key, CT_TYPE_INTEGER, &uid, sizeof(uint32),
                         IX_COL_HIST_003_USER_ID);
        knl_set_key_flag(l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_HIST_003_TABLE_ID);
        knl_set_key_flag(l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_HIST_003_COL_ID);
        knl_set_key_flag(l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_HIST_003_PART_ID);
        knl_set_key_flag(l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_HIST_003_ENDPOINT);

        knl_set_scan_key(INDEX_DESC(cursor->index), r_key, CT_TYPE_INTEGER, &uid, sizeof(uint32),
                         IX_COL_HIST_003_USER_ID);
        knl_set_key_flag(r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_HIST_003_TABLE_ID);
        knl_set_key_flag(r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_HIST_003_COL_ID);
        knl_set_key_flag(r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_HIST_003_PART_ID);
        knl_set_key_flag(r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_HIST_003_ENDPOINT);
    } else {
        knl_set_scan_key(INDEX_DESC(cursor->index), l_key, CT_TYPE_INTEGER, &uid, sizeof(uint32),
                         IX_COL_HIST_003_USER_ID);
        knl_set_scan_key(INDEX_DESC(cursor->index), l_key, CT_TYPE_INTEGER, &oid, sizeof(uint32),
                         IX_COL_HIST_003_TABLE_ID);
        knl_set_key_flag(l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_HIST_003_COL_ID);
        knl_set_key_flag(l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_HIST_003_PART_ID);
        knl_set_key_flag(l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_HIST_003_ENDPOINT);

        knl_set_scan_key(INDEX_DESC(cursor->index), r_key, CT_TYPE_INTEGER, &uid, sizeof(uint32),
                         IX_COL_HIST_003_USER_ID);
        knl_set_scan_key(INDEX_DESC(cursor->index), r_key, CT_TYPE_INTEGER, &oid, sizeof(uint32),
                         IX_COL_HIST_003_TABLE_ID);
        knl_set_key_flag(r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_HIST_003_COL_ID);
        knl_set_key_flag(r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_HIST_003_PART_ID);
        knl_set_key_flag(r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_HIST_003_ENDPOINT);
    }

    for (;;) {
        if (CT_SUCCESS != knl_fetch(session, cursor)) {
            return CT_ERROR;
        }

        if (cursor->eof) {
            break;
        }

        if (CT_SUCCESS != knl_internal_delete(session, cursor)) {
            return CT_ERROR;
        }

        session->stat->hists_deletes++;
    }

    return CT_SUCCESS;
}
static status_t stats_delete_from_sys_hist_head(knl_session_t *session, knl_cursor_t *cursor, uint32 uid, uint32 oid,
    bool32 is_nologging)
{
    knl_scan_key_t *l_key = NULL;
    knl_scan_key_t *r_key = NULL;
    stats_open_hist_abstr_cursor(session, cursor, CURSOR_ACTION_DELETE, IX_HIST_HEAD_003_ID, is_nologging);
    l_key = &cursor->scan_range.l_key;
    r_key = &cursor->scan_range.r_key;
    knl_init_index_scan(cursor, CT_FALSE);
    if (oid == CT_INVALID_ID32) {
        knl_set_scan_key(INDEX_DESC(cursor->index), l_key, CT_TYPE_INTEGER, &uid, sizeof(uint32),
                         IX_COL_HIST_HEAD_003_USER_ID);
        knl_set_key_flag(l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_HIST_HEAD_003_TABLE_ID);
        knl_set_key_flag(l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_HIST_HEAD_003_COL_ID);
        knl_set_key_flag(l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_HIST_HEAD_003_SPARE1);
        knl_set_scan_key(INDEX_DESC(cursor->index), r_key, CT_TYPE_INTEGER, &uid, sizeof(uint32),
                         IX_COL_HIST_HEAD_003_USER_ID);
        knl_set_key_flag(r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_HIST_HEAD_003_TABLE_ID);
        knl_set_key_flag(r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_HIST_HEAD_003_COL_ID);
        knl_set_key_flag(r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_HIST_HEAD_003_SPARE1);
    } else {
        knl_set_scan_key(INDEX_DESC(cursor->index), l_key, CT_TYPE_INTEGER, &uid, sizeof(uint32),
                         IX_COL_HIST_HEAD_003_USER_ID);
        knl_set_scan_key(INDEX_DESC(cursor->index), l_key, CT_TYPE_INTEGER, &oid, sizeof(uint32),
                         IX_COL_HIST_HEAD_003_TABLE_ID);
        knl_set_key_flag(l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_HIST_HEAD_003_COL_ID);
        knl_set_key_flag(l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_HIST_HEAD_003_SPARE1);
        knl_set_scan_key(INDEX_DESC(cursor->index), r_key, CT_TYPE_INTEGER, &uid, sizeof(uint32),
                         IX_COL_HIST_HEAD_003_USER_ID);
        knl_set_scan_key(INDEX_DESC(cursor->index), r_key, CT_TYPE_INTEGER, &oid, sizeof(uint32),
                         IX_COL_HIST_HEAD_003_TABLE_ID);
        knl_set_key_flag(r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_HIST_HEAD_003_COL_ID);
        knl_set_key_flag(r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_HIST_HEAD_003_SPARE1);
    }
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_HIST_HEAD_003_SPARE2);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_HIST_HEAD_003_SPARE2);

    for (;;) {
        if (CT_SUCCESS != knl_fetch(session, cursor)) {
            return CT_ERROR;
        }

        if (cursor->eof) {
            break;
        }

        if (CT_SUCCESS != knl_internal_delete(session, cursor)) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

status_t stats_drop_hists(knl_session_t *session, uint32 uid, uint32 oid, bool32 is_nologging)
{
    knl_cursor_t *cursor = NULL;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);

    cursor->row = (row_head_t *)cursor->buf;

    if (stats_delete_from_sys_histgram(session, cursor, uid, oid, is_nologging) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    if (stats_delete_from_sys_hist_head(session, cursor, uid, oid, is_nologging) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}

status_t stats_put_result_value(row_assist_t *ra, text_t *res_value, ct_type_t type)
{
    char buf[STATS_DEC_BUCKET_SIZE] = { '\0' };
    text_t value;
    binary_t bin;
    dec8_t d8;

    value.len = 0;
    value.str = buf;

    if (res_value->len == CT_NULL_VALUE_LEN) {
        row_put_null(ra);
        return CT_SUCCESS;
    }

    if (res_value->len == 0 && !CT_IS_NUMBER_TYPE(type)) {
        return row_put_text(ra, &value);
    }

    if (res_value->len > STATS_MAX_BUCKET_SIZE) {
        res_value->len = STATS_MAX_BUCKET_SIZE;
    }

    switch (type) {
        case CT_TYPE_BOOLEAN:
            cm_bool2text(*(bool32 *)res_value->str, &value);
            break;

        case CT_TYPE_UINT32:
            cm_uint32_to_text(*(uint32 *)res_value->str, &value);
            break;
        case CT_TYPE_INTEGER:
            cm_int2text(*(int32 *)res_value->str, &value);
            break;

        case CT_TYPE_DATE:
            if (cm_date2text(*(date_t *)res_value->str, NULL, &value, STATS_MAX_BUCKET_SIZE) != CT_SUCCESS) {
                return CT_ERROR;
            }
            break;
        case CT_TYPE_TIMESTAMP:
        case CT_TYPE_TIMESTAMP_TZ_FAKE:
        case CT_TYPE_TIMESTAMP_LTZ:
            if (cm_timestamp2text(*(timestamp_t *)res_value->str, NULL, &value, STATS_MAX_BUCKET_SIZE) != CT_SUCCESS) {
                return CT_ERROR;
            }
            break;
        case CT_TYPE_DATE_MYSQL:
        case CT_TYPE_DATETIME_MYSQL:
        case CT_TYPE_TIME_MYSQL:
            if (cm_date2text_mysql(type, *(date_t *)res_value->str, NULL, &value, STATS_MAX_BUCKET_SIZE) !=
                CT_SUCCESS) {
                return CT_ERROR;
            }
            break;

        case CT_TYPE_TIMESTAMP_TZ:
            if (cm_timestamp_tz2text((timestamp_tz_t *)res_value->str, NULL, &value,
                STATS_MAX_BUCKET_SIZE) != CT_SUCCESS) {
                return CT_ERROR;
            }
            break;

        case CT_TYPE_UINT64:
            cm_uint64_to_text(*(uint64 *)res_value->str, &value);
            break;
        case CT_TYPE_BIGINT:
            cm_bigint2text(*(int64 *)res_value->str, &value);
            break;

        case CT_TYPE_REAL:
            cm_real2text(*(double *)res_value->str, &value);
            break;

        case CT_TYPE_STRING:
        case CT_TYPE_CHAR:
        case CT_TYPE_VARCHAR:
            value.len = res_value->len;
            value.str = res_value->str;
            break;

        case CT_TYPE_NUMBER:
        case CT_TYPE_NUMBER3:
        case CT_TYPE_DECIMAL:
            if (cm_dec_4_to_8(&d8, (dec4_t *)res_value->str, res_value->len) != CT_SUCCESS) {
                return CT_ERROR;
            }
            (void)cm_dec_to_text(&d8, STATS_DEC_BUCKET_SIZE, &value);
            break;

        case CT_TYPE_NUMBER2:
            CT_RETURN_IFERR(cm_dec_2_to_8(&d8, (payload_t *)res_value->str, res_value->len));
            (void)cm_dec_to_text(&d8, STATS_DEC_BUCKET_SIZE, &value);
            break;

        case CT_TYPE_INTERVAL_YM:
            (void)cm_yminterval2text(*(interval_ym_t *)res_value->str, &value);
            break;

        case CT_TYPE_INTERVAL_DS:
            (void)cm_dsinterval2text(*(interval_ds_t *)res_value->str, &value);
            break;

        default:
            bin.bytes = (uint8 *)res_value->str;
            if (res_value->len >= STATS_MAX_BUCKET_SIZE / 2) {
                // because binary type -> text,size of text will be twice size of binary
                // eg:binary "22222111" --> text "3232323232313131"
                bin.size = (STATS_MAX_BUCKET_SIZE - 1) / 2;
            } else {
                bin.size = res_value->len;
            }
            value.len = STATS_MAX_BUCKET_SIZE;
            if (cm_bin2text(&bin, CT_FALSE, &value) != CT_SUCCESS) {
                return CT_ERROR;
            }
            break;
    }

    return row_put_text(ra, &value);
}

static void stats_set_histgram_scan_key(knl_cursor_t *cursor, knl_column_t *column, uint32 part_id, bool32 is_part)
{
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&column->uid,
                     sizeof(uint32), IX_COL_HIST_003_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&column->table_id,
                     sizeof(uint32), IX_COL_HIST_003_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&column->id,
                     sizeof(uint32), IX_COL_HIST_003_COL_ID);

    if (is_part) {
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&part_id,
                         sizeof(uint32), IX_COL_HIST_003_PART_ID);
    } else {
        knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_IS_NULL, IX_COL_HIST_003_PART_ID);
    }

    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_HIST_003_ENDPOINT);

    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_INTEGER, (void *)&column->uid,
                     sizeof(uint32), IX_COL_HIST_003_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_INTEGER, (void *)&column->table_id,
                     sizeof(uint32), IX_COL_HIST_003_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_INTEGER, (void *)&column->id,
                     sizeof(uint32), IX_COL_HIST_003_COL_ID);

    if (is_part) {
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_INTEGER, (void *)&part_id,
                         sizeof(uint32), IX_COL_HIST_003_PART_ID);
    } else {
        knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_IS_NULL, IX_COL_HIST_003_PART_ID);
    }

    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_HIST_003_ENDPOINT);
}

static int32 stats_hist_endpoint_comparator(const void *pa, const void *pb)
{
    const stats_hist_assist_t *a = (const stats_hist_assist_t *)pa;
    const stats_hist_assist_t *b = (const stats_hist_assist_t *)pb;

    if (a->endpoint < b->endpoint) {
        return -1;
    }
    if (a->endpoint > b->endpoint) {
        return 1;
    }

    /* equal pageid is impossible */
    return 0;
}

static inline void stats_hists_sort(stats_hist_assist_t *hists, uint32 buckets)
{
    qsort(hists, buckets, sizeof(stats_hist_assist_t), stats_hist_endpoint_comparator);
}

static void stats_sort_subpart_histgrams(stats_hist_assist_t *hist_assit, stats_hist_rowids_t *hist_rowids,
                                         uint32 bucket_num)
{
    stats_hists_sort(hist_assit, bucket_num);

    for (uint32 i = 0; i < bucket_num; i++) {
        hist_rowids->rowid_list[i] = hist_assit[i].row_id;
        hist_rowids->bucket_num++;
    }
}

static inline void stats_set_hist_rowids(knl_cursor_t *cursor, stats_hist_rowids_t *hist_rowids,
    stats_hist_assist_t *hist_assit, uint32 *bucket_num, bool32 is_subpart)
{
    uint32 slot = *bucket_num;
    
    if (is_subpart) {
        hist_assit[slot].endpoint = *(uint32*)CURSOR_COLUMN_DATA(cursor, HIST_EP_NUM);
        hist_assit[slot].row_id = cursor->rowid;
    } else {
        hist_rowids->rowid_list[slot] = cursor->rowid;
        hist_rowids->bucket_num++;
    }

    slot++;
    *bucket_num = slot;
}

static status_t stats_get_old_buckets(knl_session_t *session, stats_col_handler_t *column_handler,
    stats_table_t *table_stats)
{
    knl_cursor_t *cursor = column_handler->stats_cur;
    uint32 bucket_num = 0;
    uint32 curr_buckets = column_handler->hist_info.bucket_num;
    stats_hist_rowids_t *hist_rowids = column_handler->hist_rowids;
    stats_part_table_t *part_stats = &table_stats->part_stats;
    uint64 subpart_id = (part_stats->is_subpart) ? part_stats->sub_stats->part_id : CT_INVALID_ID32;
    stats_hist_assist_t hist_assit[STATS_HISTGRAM_MAX_SIZE];
    errno_t ret = memset_s(&hist_assit, sizeof(stats_hist_assist_t) * STATS_HISTGRAM_MAX_SIZE,
                           0xFF, sizeof(stats_hist_assist_t) * STATS_HISTGRAM_MAX_SIZE);
    knl_securec_check(ret);

    stats_open_histgram_cursor(session, cursor, CURSOR_ACTION_DELETE, IX_HIST_003_ID, column_handler->is_nologging);
    knl_init_index_scan(cursor, CT_FALSE);
    stats_set_histgram_scan_key(cursor, column_handler->column, table_stats->part_stats.part_id, table_stats->is_part);

    for (;;) {
        if (knl_fetch(session, cursor) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (cursor->eof) {
            break;
        }

        if (!part_stats->is_subpart) {
            if (bucket_num < curr_buckets) {
                stats_set_hist_rowids(cursor, hist_rowids, hist_assit, &bucket_num, CT_FALSE);
                continue;
            }
            // drop part and analyze table concurrently,some histgrams of drop part can remain. we need clean them.
            if (knl_internal_delete(session, cursor) != CT_SUCCESS) {
                return CT_ERROR;
            }

            session->stat->hists_deletes++;
            continue;
        }

        bool32 subpart_found = (CURSOR_COLUMN_SIZE(cursor, HIST_SUBPART_ID) != CT_NULL_VALUE_LEN) &&
            (subpart_id == *(uint64*)CURSOR_COLUMN_DATA(cursor, HIST_SUBPART_ID));
        if (subpart_found) {
            if (bucket_num < curr_buckets) {
                stats_set_hist_rowids(cursor, hist_rowids, hist_assit, &bucket_num, CT_TRUE);
                continue;
            }
            // drop part and analyze table concurrently,some histgrams of drop part can remain. we need clean them.
            if (knl_internal_delete(session, cursor) != CT_SUCCESS) {
                return CT_ERROR;
            }

            session->stat->hists_deletes++;
            continue;
        }
    }

    knl_panic(bucket_num <= curr_buckets);
    if (part_stats->is_subpart) {
        stats_sort_subpart_histgrams(hist_assit, hist_rowids, bucket_num);
    }

    return CT_SUCCESS;
}

static status_t stats_check_histgram_exist(knl_session_t *session, stats_col_handler_t *column_handler,
                                           stats_table_t *table_stats)
{
    stats_part_table_t *part_stats = &table_stats->part_stats;
    knl_cursor_t *cursor = column_handler->stats_cur;
    knl_column_t *column = column_handler->column;
    uint64 subpart_id = (part_stats->is_subpart) ? part_stats->sub_stats->part_id : CT_INVALID_ID32;

    if (stats_no_persistent(table_stats)) {
        /* temp table statistics info does not saved in systable$
         * 1.ltt
         * 2.trans gtt
         * 3.dynamic stats for session gtt
         */
        return CT_SUCCESS;
    }
    stats_open_histgram_cursor(session, cursor, CURSOR_ACTION_SELECT, IX_HIST_003_ID, column_handler->is_nologging);
    knl_init_index_scan(cursor, CT_FALSE);
    stats_set_histgram_scan_key(cursor, column, table_stats->part_stats.part_id, table_stats->is_part);

    for (;;) {
        if (knl_fetch(session, cursor) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (cursor->eof) {
            break;
        }

        if (!part_stats->is_subpart) {
            column_handler->hist_exits = CT_TRUE;
            break;
        }

        if (CURSOR_COLUMN_SIZE(cursor, HIST_SUBPART_ID) != CT_NULL_VALUE_LEN &&
            subpart_id == *(uint64*)CURSOR_COLUMN_DATA(cursor, HIST_SUBPART_ID)) {
            column_handler->hist_exits = CT_TRUE;
            break;
        }
    }

    return CT_SUCCESS;
}

static status_t stats_delete_old_histgram(knl_session_t *session, knl_cursor_t *cursor, stats_hist_rowids_t *hist_buckets,
                                          stats_table_t *table_stats)
{
    stats_open_histgram_cursor(session, cursor, CURSOR_ACTION_DELETE, CT_INVALID_ID32, table_stats->is_nologging);
    cursor->scan_mode = SCAN_MODE_ROWID;
    cursor->fetch = TABLE_ACCESSOR(cursor)->do_rowid_fetch;
    cursor->rowid_no = STATS_ROWID_NO;
    cursor->rowid_count = STATS_ROWID_COUNT;

    for (uint32 i = hist_buckets->curr_bucket; i < hist_buckets->bucket_num; i++) {
        cursor->rowid_array[STATS_ROWID_NO] = hist_buckets->rowid_list[i];

        if (knl_fetch(session, cursor) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (cursor->eof) {
            break;
        }

        if (knl_internal_delete(session, cursor) != CT_SUCCESS) {
            return CT_ERROR;
        }

        session->stat->hists_deletes++;
        cursor->rowid_no = STATS_ROWID_NO;
        cursor->rowid_count = STATS_ROWID_COUNT;
    }

    return CT_SUCCESS;
}

status_t stats_fetch_distinct(stats_col_handler_t *column_handler, bool32 is_gather)
{
    mtrl_context_t *ctx = &column_handler->mtrl.mtrl_ctx;
    mtrl_cursor_t *mtrl_cur = &column_handler->mtrl.mtrl_cur;
    bool32 group_changed = CT_FALSE;

    if (mtrl_cur->eof) {
        return CT_SUCCESS;
    }

    while (!(group_changed || mtrl_cur->eof)) {
        if (mtrl_fetch_group(ctx, mtrl_cur, &group_changed) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (is_gather) {
            if (STATS_GET_ROW_SIZE(mtrl_cur) != CT_NULL_VALUE_LEN) {
                column_handler->hist_info.dnv_per_num++;
            }
        } else {
            if (STATS_GET_ROW_SIZE(mtrl_cur) == CT_NULL_VALUE_LEN && !mtrl_cur->eof) {
                column_handler->null_num++;
            }
            column_handler->total_rows++;
        }
    }

    return CT_SUCCESS;
}

static status_t stats_calc_distinct_num(knl_session_t *session, stats_col_handler_t *column_handler)
{
    mtrl_cursor_t  *mtrl_cur = &column_handler->mtrl.mtrl_cur;

    for (;;) {
        if (stats_fetch_distinct(column_handler, CT_FALSE) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (session->canceled) {
            CT_THROW_ERROR(ERR_OPERATION_CANCELED);
            return CT_ERROR;
        }

        if (session->killed) {
            CT_THROW_ERROR(ERR_OPERATION_KILLED);
            return CT_ERROR;
        }

        if (mtrl_cur->eof) {
            if (column_handler->total_rows > 0) {
                column_handler->total_rows--;
            }

            break;
        }

        if (STATS_GET_ROW_SIZE(mtrl_cur) != CT_NULL_VALUE_LEN) {
            column_handler->dist_num++;
        }
    }

    return CT_SUCCESS;
}

static status_t stats_put_mtrl_row(row_assist_t *ra, knl_column_t *rs_col, char *ptr, uint32 len)
{
    binary_t bin;
    text_t text;
    dec2_t dec2 = {0};
    if (len == CT_NULL_VALUE_LEN) {
        row_put_null(ra);
        return CT_SUCCESS;
    }

    switch (rs_col->datatype) {
        case CT_TYPE_BOOLEAN:
            (void)row_put_bool(ra, *(bool32 *)ptr);
            break;

        case CT_TYPE_UINT32:
            (void)row_put_uint32(ra, *(uint32 *)ptr);
            break;

        case CT_TYPE_INTEGER:
            (void)row_put_int32(ra, *(int32 *)ptr);
            break;

        case CT_TYPE_UINT64:
            (void)row_put_uint64(ra, *(uint64 *)ptr);
            break;

        case CT_TYPE_BIGINT:
            (void)row_put_int64(ra, *(int64 *)ptr);
            break;

        case CT_TYPE_REAL:
            (void)row_put_real(ra, *(double *)ptr);
            break;

        case CT_TYPE_DATE:
        case CT_TYPE_DATETIME_MYSQL:
        case CT_TYPE_TIME_MYSQL:
        case CT_TYPE_DATE_MYSQL:
            (void)row_put_date(ra, *(date_t *)ptr);
            break;

        case CT_TYPE_INTERVAL_DS:
            (void)row_put_dsinterval(ra, *((interval_ds_t *)ptr));
            break;

        case CT_TYPE_INTERVAL_YM:
            (void)row_put_yminterval(ra, *((interval_ym_t *)ptr));
            break;

        case CT_TYPE_TIMESTAMP:
        case CT_TYPE_TIMESTAMP_TZ_FAKE:
        case CT_TYPE_TIMESTAMP_LTZ:
            (void)row_put_timestamp(ra, *(date_t *)ptr);
            break;

        case CT_TYPE_TIMESTAMP_TZ:
            (void)row_put_timestamp_tz(ra, (timestamp_tz_t *)ptr);
            break;

        case CT_TYPE_STRING:
        case CT_TYPE_CHAR:
        case CT_TYPE_VARCHAR:
            text.str = ptr;
            text.len = len;
            (void)row_put_text(ra, &text);
            break;

        case CT_TYPE_NUMBER:
        case CT_TYPE_NUMBER3:
        case CT_TYPE_DECIMAL:
            if (len == 0 && ra->is_csf) {
                return csf_put_zero(ra);
            } else {
                return row_put_dec4_core(ra, (dec4_t*)ptr);
            }
        case CT_TYPE_NUMBER2:
            if (len == 0 && ra->is_csf) {
                return csf_put_zero(ra);
            } else {
                cm_dec2_copy_ex(&dec2, (const payload_t *)ptr, len);
                return row_put_dec2_core(ra, &dec2);
            }
        default:
            bin.bytes = (uint8 *)ptr;
            bin.size = len;
            (void)row_put_bin(ra, &bin);
            break;
    }

    return CT_SUCCESS;
}

static status_t stats_make_mtrl_rs_row(mtrl_cursor_t *cursor, knl_column_t *rs_col, char *buf, bool32 *has_null)
{
    char *ptr = NULL;
    uint32 len;
    row_assist_t ra;
    row_head_t *row = (row_head_t*)cursor->row.data;

    cm_row_init(&ra, buf, CT_MAX_ROW_SIZE, STATS_MAP_ROW_COUNT, row->is_csf);
    ptr = cursor->row.data + cursor->row.offsets[rs_col->id];
    if (rs_col->id >= (uint32)ROW_COLUMN_COUNT((row_head_t *)cursor->row.data)) {
        len = CT_NULL_VALUE_LEN;
    } else {
        len = cursor->row.lens[rs_col->id];
    }

    if (len == CT_NULL_VALUE_LEN) {
        *has_null = CT_TRUE;
    }

    if (stats_put_mtrl_row(&ra, rs_col, ptr, len) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t stats_get_sample_page(knl_session_t *session, knl_cursor_t *cursor, stats_sampler_t *tab_sample,
                                      stats_table_t *tab_stats)
{
    table_t *table = (table_t *)cursor->table;
    heap_page_t *page = NULL;
    page_id_t page_id;
    uint8 type;
    uint32 blocks = 0;
    uint32 empty_block = 0;

    cursor->eof = CT_FALSE;

    for (;;) {
        if (stats_next_sample_page(session, cursor, tab_stats, tab_sample, &type) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (cursor->eof) {
            break;
        }

        if (STATS_NOT_DATA_PAGE(type)) {
            continue;
        }

        page_id = tab_sample->sample_extent.last;
        knl_set_table_scan_range(session, cursor, page_id, page_id);

        page = (heap_page_t *)cursor->page_buf;

        blocks++;

        if (page->rows == 0) {
            empty_block++;
            continue;
        }

        break;
    }

    if (IS_PART_TABLE(table)) {
        if (tab_stats->part_stats.is_subpart) {
            tab_stats->part_stats.sub_stats->info.blocks += blocks;
            tab_stats->part_stats.sub_stats->info.empty_block += empty_block;
        } else {
            tab_stats->part_stats.info.blocks += blocks;
            tab_stats->part_stats.info.empty_block += empty_block;
        }
    } else {
        tab_stats->tab_info.blocks += blocks;
        tab_stats->tab_info.empty_block += empty_block;
    }

    return CT_SUCCESS;
}

static status_t stats_get_nonsample_page(knl_session_t *session, knl_cursor_t *cursor, stats_table_t *tab_stats)
{
    uint32 blocks = 0;
    uint32 empty_block = 0;

    if (IS_INVALID_ROWID(cursor->rowid)) {
        return CT_SUCCESS;
    }

    table_t *table = (table_t *)cursor->table;
    page_type_t expect_type = (table->desc.cr_mode == CR_PAGE) ? PAGE_TYPE_PCRH_DATA : PAGE_TYPE_HEAP_DATA;
    page_id_t page_id = GET_ROWID_PAGE(cursor->rowid);
    char *name = IS_PART_TABLE(table) ? ((table_part_t*)cursor->table_part)->desc.name :
        table->desc.name;  // table name or table part name

    if (buf_read_prefetch_page(session, page_id, LATCH_MODE_S, ENTER_PAGE_SEQUENTIAL) != CT_SUCCESS) {
        return CT_ERROR;
    }

    heap_page_t *page = (heap_page_t *)CURR_PAGE(session);

    if (!heap_check_page(session, cursor, page, expect_type)) {
        buf_leave_page(session, CT_FALSE);
        if (cursor->page_soft_damaged) {
            CT_THROW_ERROR(ERR_PAGE_SOFT_DAMAGED, (cursor)->rowid.file, (cursor)->rowid.page);
        } else {
            CT_THROW_ERROR(ERR_OBJECT_ALREADY_DROPPED, name);
        }
        return CT_ERROR;
    }

    errno_t ret = memcpy_sp(cursor->page_buf, DEFAULT_PAGE_SIZE(session), page, DEFAULT_PAGE_SIZE(session));
    knl_securec_check(ret);

    blocks++;

    if (page->rows == 0) {
        empty_block++;
    }

    buf_leave_page(session, CT_FALSE);
    knl_set_table_scan_range(session, cursor, page_id, page_id);
    cursor->eof = CT_FALSE;

    if (IS_PART_TABLE(table)) {
        if (tab_stats->part_stats.is_subpart) {
            tab_stats->part_stats.sub_stats->info.blocks += blocks;
            tab_stats->part_stats.sub_stats->info.empty_block += empty_block;
        } else {
            tab_stats->part_stats.info.blocks += blocks;
            tab_stats->part_stats.info.empty_block += empty_block;
        }
    } else {
        tab_stats->tab_info.blocks += blocks;
        tab_stats->tab_info.empty_block += empty_block;
    }

    return CT_SUCCESS;
}

/*
 * just append rowid on row tail and change row size, not change any others
 */
static inline void stats_row_append_rowid(knl_cursor_t *cursor, char *row)
{
    row_head_t *head = NULL;
    errno_t      ret;

    ret = memcpy_s(row, cursor->row->size, (char *)cursor->row, cursor->row->size);
    knl_securec_check(ret);
    ret = memcpy_s(row + cursor->row->size, sizeof(rowid_t), &cursor->rowid, sizeof(rowid_t));
    knl_securec_check(ret);

    head = (row_head_t *)row;
    head->size += sizeof(rowid_t);
}

/*
 * when analyze table, we load analyzed table and create temp table, otherwise row of temp table have
 * rowid at row tail.
 */
static inline void stats_get_rowid(mtrl_cursor_t *cursor, rowid_t **rowid)
{
    row_head_t *head = (row_head_t *)cursor->row.data;
    *rowid = (rowid_t *)(cursor->row.data + head->size - sizeof(rowid_t));
}

status_t stats_insert_row(knl_session_t *session, knl_cursor_t *cursor, mtrl_context_t  *temp_ctx,
                          uint32 seg_id, stats_table_t *table_stats)
{
    table_t *table = (table_t *)cursor->table;
    page_id_t page_id = GET_ROWID_PAGE(cursor->rowid);
    heap_page_t *page = NULL;
    mtrl_rowid_t rid;
    uint32 rows = 0;
    uint64 row_len = 0;
    mtrl_segment_t *segment = NULL;
    char *row = (char *)cm_push(session->stack, CT_MAX_ROW_SIZE + sizeof(rowid_t));

    segment = temp_ctx->segments[seg_id];
    if (mtrl_open_page(temp_ctx, segment->vm_list.last, &segment->curr_page) != CT_SUCCESS) {
        cm_pop(session->stack);
        return CT_ERROR;
    }

    for (;;) {
        if (knl_fetch(session, cursor) != CT_SUCCESS) {
            mtrl_close_page(temp_ctx, segment->vm_list.last);
            segment->curr_page = NULL;
            cm_pop(session->stack);
            return CT_ERROR;
        }

        if (session->canceled) {
            CT_THROW_ERROR(ERR_OPERATION_CANCELED);
            mtrl_close_page(temp_ctx, segment->vm_list.last);
            segment->curr_page = NULL;
            cm_pop(session->stack);
            return CT_ERROR;
        }

        if (session->killed) {
            CT_THROW_ERROR(ERR_OPERATION_KILLED);
            mtrl_close_page(temp_ctx, segment->vm_list.last);
            segment->curr_page = NULL;
            cm_pop(session->stack);
            return CT_ERROR;
        }

        if (cursor->eof) {
            if (!STATS_IS_ANALYZE_TEMP_TABLE(table_stats)) {
                if (buf_read_page(session, page_id, LATCH_MODE_S,
                                  ENTER_PAGE_NORMAL | ENTER_PAGE_SEQUENTIAL) != CT_SUCCESS) {
                    mtrl_close_page(temp_ctx, segment->vm_list.last);
                    segment->curr_page = NULL;
                    cm_pop(session->stack);
                    return CT_ERROR;
                }
                page = (heap_page_t *)CURR_PAGE(session);
                SET_ROWID_PAGE(&cursor->rowid, AS_PAGID(page->next));
                buf_leave_page(session, CT_FALSE);
            }

            break;
        }

        rows++;
        row_len += cursor->row->size;

        /*
         * because make index key will use rowid but mtrl_cursor will not storage it, so
         * we must append rowid at row tail.
         */
        stats_row_append_rowid(cursor, row);

        if (mtrl_insert_row(temp_ctx, seg_id, row, &rid) != CT_SUCCESS) {
            mtrl_close_page(temp_ctx, segment->vm_list.last);
            segment->curr_page = NULL;
            cm_pop(session->stack);
            return CT_ERROR;
        }
        table_stats->now_rid = rid;
    }

    if (IS_PART_TABLE(table)) {
        if (table_stats->part_stats.is_subpart) {
            table_stats->part_stats.sub_stats->info.rows += rows;
            table_stats->part_stats.sub_stats->info.row_len += row_len;
        } else {
            table_stats->part_stats.info.rows += rows;
            table_stats->part_stats.info.row_len += row_len;
        }
    } else {
        table_stats->tab_info.rows += rows;
        table_stats->tab_info.row_len += row_len;
    }

    mtrl_close_page(temp_ctx, segment->vm_list.last);
    segment->curr_page = NULL;
    cm_pop(session->stack);
    return CT_SUCCESS;
}

static status_t get_next_tmptab_page(knl_session_t *session, stats_table_t *table_stats, knl_cursor_t *cursor)
{
    uint32 curr_sample_pageid;
    vm_page_t *current_vm_page = NULL;
    vm_ctrl_t *vm_ctrl = NULL;
    temp_heap_page_t *current_heap_page = NULL;

    if (table_stats->temp_table->prev_sample_pageid == CT_INVALID_ID32) {
        curr_sample_pageid = table_stats->temp_table->first_pageid;
    } else {
        vm_ctrl = vm_get_ctrl(session->temp_mtrl->pool, table_stats->temp_table->prev_sample_pageid);
        curr_sample_pageid = vm_ctrl->next;
    }

    cursor->rowid.vmid = curr_sample_pageid;
    cursor->eof = CT_FALSE;
    table_stats->temp_table->prev_sample_pageid = curr_sample_pageid;

    if (curr_sample_pageid == CT_INVALID_ID32) {
        return CT_SUCCESS;
    }

    if (buf_enter_temp_page_nolock(session, curr_sample_pageid) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Fail to open heap migr vm page (%u).", curr_sample_pageid);
        return CT_ERROR;
    }

    current_vm_page = buf_curr_temp_page(session);
    current_heap_page = (temp_heap_page_t *)current_vm_page->data;

    if (current_heap_page->dirs == 0) {
        table_stats->tab_info.empty_block++;
    }

    table_stats->tab_info.blocks++;
    buf_leave_temp_page_nolock(session, CT_FALSE);

    return CT_SUCCESS;
}


static status_t stats_insert_mtrl_temp_table(knl_session_t *session, knl_cursor_t *cursor, mtrl_context_t *temp_ctx,
                                             uint32 seg_id, stats_table_t *table_stats)
{
    uint32 sample_pages = 0;

    session->stat_sample = CT_TRUE;

    for (;;) {
        if (sample_pages >= table_stats->temp_table->sample_pages) {
            break;
        }

        if (get_next_tmptab_page(session, table_stats, cursor) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (stats_insert_row(session, cursor, temp_ctx, seg_id, table_stats) != CT_SUCCESS) {
            return CT_ERROR;
        }

        sample_pages++;
    }

    stats_get_row_avg_len(&table_stats->tab_info);
    session->stat_sample = CT_FALSE;

    return CT_SUCCESS;
}

bool8 stats_set_sample(stats_sampler_t *stats_sample)
{
    double ratio_per_ext;
    ratio_per_ext = ((double)stats_sample->pages_per_ext / (double)stats_sample->extent_size);
   
    if (ratio_per_ext > STATS_MIN_SAMPLE_RATIO_EXT) {
        return CT_FALSE;
    }
    
    return CT_TRUE;
}

static void stats_flow_control(knl_session_t *session, knl_cursor_t *cursor, stats_table_t *table_stats)
{
    uint32 cost_limit = session->kernel->attr.stats_cost_limit;
    uint32 cost_delay = session->kernel->attr.stats_cost_delay;
    table_t *table = (table_t*)cursor->table;
    uint32 blocks = 0;

    if (cost_limit == 0 || cost_delay == 0) {
        return;
    }

    if (IS_PART_TABLE(table)) {
        blocks = table_stats->part_stats.info.blocks;
    } else {
        blocks = table_stats->tab_info.blocks;
    }

    if (blocks == 0) {
        return;
    }

    if (blocks % cost_limit == 0) {
        cm_sleep(cost_delay + 1);
    }
}

static status_t stats_insert_mtrl_heap_table(knl_session_t *session, knl_cursor_t *cursor, mtrl_context_t *temp_ctx,
                                             stats_sampler_t *stats_sample, uint32 seg_id, stats_table_t *table_stats)
{
    bool32 is_sample = (stats_sample->sample_size != CT_INVALID_ID32) ? CT_TRUE : CT_FALSE;
    table_t *table = (table_t *)cursor->table;
    stats_table_info_t *info = NULL;

    table_stats->part_start_rid = table_stats->now_rid;

    if (is_sample) {
        session->stat_sample = stats_set_sample(stats_sample);
    }

    for (;;) {
        if (is_sample) {
            if (stats_get_sample_page(session, cursor, stats_sample, table_stats) != CT_SUCCESS) {
                session->stat_sample = CT_FALSE;
                return CT_ERROR;
            }
        } else {
            if (stats_get_nonsample_page(session, cursor, table_stats) != CT_SUCCESS) {
                return CT_ERROR;
            }
        }

        if (cursor->eof) {
            if (is_sample && stats_sample->hwm_pages < stats_sample->sample_size) {
                table_stats->estimate_sample_ratio = STATS_REVISE_SAMPLE_RATIO(table_stats, stats_sample);
            }

            if (is_sample) {
                session->stat_sample = CT_FALSE;
            }

            break;
        }

        stats_flow_control(session, cursor, table_stats);

        if (stats_insert_row(session, cursor, temp_ctx, seg_id, table_stats) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (IS_PART_TABLE(table)) {
        if (table_stats->part_stats.is_subpart) {
            info = &table_stats->part_stats.sub_stats->info;
        } else {
            info = &table_stats->part_stats.info;
        }
    } else {
        info = &table_stats->tab_info;
    }
    stats_get_row_avg_len(info);
    return CT_SUCCESS;
}

static status_t stats_open_mtrl_rs_cursor(mtrl_rowid_t rid, mtrl_context_t *temp_ctx,
                                          mtrl_cursor_t *cursor, uint32 temp_seg)
{
    vm_page_t      *page = NULL;

    if (rid.vmid == 0 && rid.slot == 0) {
        return mtrl_open_rs_cursor(temp_ctx, temp_seg, cursor);
    }

    if (mtrl_open_page(temp_ctx, rid.vmid, &page) != CT_SUCCESS) {
        return CT_ERROR;
    }

    cursor->eof = CT_FALSE;
    cursor->row.data = NULL;
    cursor->rs_vmid = rid.vmid;
    cursor->slot = rid.slot + 1;
    cursor->rs_page = (mtrl_page_t *)page->data;

    return CT_SUCCESS;
}

static status_t stats_mtrl_distinct(knl_session_t *session, stats_col_handler_t *column_handler)
{
    mtrl_rowid_t rid;
    char *buf = NULL;
    mtrl_context_t *ctx = &column_handler->mtrl.mtrl_ctx;
    mtrl_context_t *temp_ctx = column_handler->mtrl.mtrl_table_ctx;
    mtrl_cursor_t *cursor = &column_handler->mtrl.mtrl_cur;
    uint32 dist_seg = column_handler->mtrl.dist_seg_id;
    uint32 temp_seg = column_handler->mtrl.temp_seg_id;

    if (stats_open_mtrl_rs_cursor(column_handler->g_rid, temp_ctx, cursor, temp_seg) != CT_SUCCESS) {
        return CT_ERROR;
    }

    buf = (char *)column_handler->col_buf;

    for (;;) {
        if (mtrl_fetch_rs(temp_ctx, cursor, CT_TRUE) != CT_SUCCESS) {
            mtrl_close_cursor(temp_ctx, cursor);
            return CT_ERROR;
        }

        if (session->canceled) {
            mtrl_close_cursor(temp_ctx, cursor);
            CT_THROW_ERROR(ERR_OPERATION_CANCELED);
            return CT_ERROR;
        }

        if (session->killed) {
            mtrl_close_cursor(temp_ctx, cursor);
            CT_THROW_ERROR(ERR_OPERATION_KILLED);
            return CT_ERROR;
        }

        if (cursor->eof) {
            break;
        }

        if (stats_make_mtrl_rs_row(cursor, column_handler->column, buf, &column_handler->has_null) != CT_SUCCESS) {
            mtrl_close_cursor(temp_ctx, cursor);
            return CT_ERROR;
        }

        if (mtrl_insert_row(ctx, dist_seg, buf, &rid) != CT_SUCCESS) {
            mtrl_close_cursor(temp_ctx, cursor);
            return CT_ERROR;
        }
    }

    mtrl_close_cursor(temp_ctx, cursor);
    return CT_SUCCESS;
}

uint32 stats_get_table_pages(knl_session_t *session, table_t *table, uint32 *extent_count)
{
    uint32 estimate_blocks = 0;
    heap_segment_t *segment = NULL;
    space_t *space = NULL;

    if (IS_INVALID_PAGID(table->desc.entry)) {
        return estimate_blocks;
    }

    if (!spc_validate_page_id(session, table->desc.entry)) {
        CT_LOG_RUN_ERR("stats table error: table name: %s has been droped", table->desc.name);
        return estimate_blocks;
    }

    buf_enter_page(session, table->desc.entry, LATCH_MODE_S, ENTER_PAGE_NORMAL);
    page_head_t *page = (page_head_t *)CURR_PAGE(session);
    segment = HEAP_SEG_HEAD(session);
    if (page->type != PAGE_TYPE_HEAP_HEAD || segment->seg_scn != table->desc.seg_scn) {
        CT_LOG_RUN_ERR("stats table error: table name: %s has been droped", table->desc.name);
        buf_leave_page(session, CT_FALSE);
        return estimate_blocks;
    }

    space = SPACE_GET(session, table->desc.space_id);
    estimate_blocks = heap_get_segment_page_count(space, segment) - segment->ufp_count;
    *extent_count = segment->extents.count;
    buf_leave_page(session, CT_FALSE);
    return estimate_blocks;
}

uint32 stats_get_table_part_pages(knl_session_t *session, table_part_t *table_part, uint32 *extent_count)
{
    uint32 estimate_blocks = 0;
    heap_segment_t *segment = NULL;
    space_t *space = NULL;

    if (IS_INVALID_PAGID(table_part->desc.entry)) {
        return estimate_blocks;
    }

    if (!spc_validate_page_id(session, table_part->desc.entry)) {
        CT_LOG_RUN_ERR("stats table part error: table part name: %s has been droped", table_part->desc.name);
        return estimate_blocks;
    }

    buf_enter_page(session, table_part->desc.entry, LATCH_MODE_S, ENTER_PAGE_NORMAL);
    page_head_t *page = (page_head_t *)CURR_PAGE(session);
    segment = HEAP_SEG_HEAD(session);
    if (page->type != PAGE_TYPE_HEAP_HEAD || segment->seg_scn != table_part->desc.seg_scn) {
        CT_LOG_RUN_ERR("stats table table_part error: table table_part name: %s has been droped",
            table_part->desc.name);
        buf_leave_page(session, CT_FALSE);
        return estimate_blocks;
    }

    space = SPACE_GET(session, table_part->desc.space_id);
    estimate_blocks = heap_get_segment_page_count(space, segment) - segment->ufp_count;
    *extent_count = segment->extents.count;
    buf_leave_page(session, CT_FALSE);
    return estimate_blocks;
}

/*
 * when sample statistics, we will check this:
 * 1. if blocks < space->ctrl->extent_size, use full statistics replace sample statistics.
 * 2. if sample_size < space->ctrl->extent_size, assign sample_size = space->ctrl->extent_size.
 */
static void inline stats_check_min_sample_size(uint64 blocks, uint64 *sample_size, uint64 min_blocks,
                                               double *sample_ratio)
{
    if (blocks < min_blocks) {
        *sample_ratio = STATS_FULL_TABLE_SAMPLE_RATIO;
    } else {
        if (*sample_size < min_blocks) {
            *sample_size = min_blocks;
            *sample_ratio = ((double)(*sample_size)) / blocks;
        }
    }

    if (IS_FULL_SAMPLE(*sample_ratio - STATS_SAMPLE_MAX_RATIO)) {
        *sample_ratio = STATS_FULL_TABLE_SAMPLE_RATIO;
    }
}

static void stats_sample_ratio_init(knl_session_t *session, knl_dictionary_t *dc, stats_sampler_t *stats_sample,
                                    double *sample_ratio, stats_table_t *table_stats)
{
    dc_entity_t *entity = DC_ENTITY(dc);
    table_t *table = &entity->table;
    table_part_t *table_part = NULL;
    space_t *space = NULL;
    uint64 blocks = 0;
    uint64 sample_size;
    errno_t ret;
    uint32 min_sample_blocks;
    uint64 estimate_sample_size;
    uint32 extents_count = 0;

    if (IS_PART_TABLE(table)) {
        table_part = TABLE_GET_PART(table, table_stats->part_stats.part_no);
        if (IS_PARENT_TABPART(&table_part->desc)) {
            uint32 subpart_no = table_stats->part_stats.sub_stats->part_no;
            table_part_t *table_subpart = PART_GET_SUBENTITY(table->part_table, table_part->subparts[subpart_no]);
            space = SPACE_GET(session, table_subpart->desc.space_id);
            blocks = stats_get_table_part_pages(session, table_subpart, &extents_count);
        } else {
            space = SPACE_GET(session, table_part->desc.space_id);
            blocks = stats_get_table_part_pages(session, table_part, &extents_count);
        }
    } else {
        space = SPACE_GET(session, table->desc.space_id);
        blocks = stats_get_table_pages(session, table, &extents_count);
    }

    // sample_radio is between [0, 1), so blocks * *sample_radio is not greater than max value of uint64
    sample_size = (uint64)(int64)(blocks * *sample_ratio);
    /*
     * if segment->extents.count is 1 ,it means the analyze table may be a small table that has a few rows
     * so we must analyze table full.
     */
    if (extents_count == STATS_MIN_SAMPLE_EXTENTS) {
        min_sample_blocks = space->ctrl->extent_size;
    } else {
        min_sample_blocks = (space->ctrl->extent_size < STATS_MIN_SAMPLE_BLOCKS) ? space->ctrl->extent_size :
                            STATS_MIN_SAMPLE_BLOCKS;
    }
 
    estimate_sample_size = (sample_size > min_sample_blocks) ? sample_size : min_sample_blocks;

    if (*sample_ratio > CT_REAL_PRECISION) {
        /* min sample blocks is bigger one between one extent size and STATS_MIN_SAMPLE_BLOCKS */
        stats_check_min_sample_size(blocks, &sample_size, estimate_sample_size, sample_ratio);
    }

    if (*sample_ratio > CT_REAL_PRECISION) {
        ret = memset_sp(stats_sample, sizeof(stats_sampler_t), 0, sizeof(stats_sampler_t));
        knl_securec_check(ret);
        stats_sample_init(session, stats_sample, extents_count, space, sample_size, *sample_ratio);
    } else {
        stats_sample->sample_size = CT_INVALID_ID32;
    }
}
/*
 * we need to create a temp table for all part tables when analyzing partition table,
 * because we need to gather every part statistics to generate global statistics of
 * partition table after we analyzed every part table.
 */
status_t stats_create_global_mtrl_table(knl_session_t *session, knl_dictionary_t *dc, mtrl_context_t *temp_ctx,
                                        uint32 seg_id, stats_table_t *table_stats)
{
    knl_cursor_t *cursor = NULL;
    stats_sampler_t stats_sample;
    errno_t ret;

    ret = memset_s(&stats_sample, sizeof(stats_sampler_t), 0, sizeof(stats_sampler_t));
    knl_securec_check(ret);

    CM_SAVE_STACK(session->stack);
    cursor = knl_push_cursor(session);
    knl_init_cursor_buf(session, cursor);
    cursor->action = CURSOR_ACTION_SELECT;
    cursor->scan_mode = SCAN_MODE_TABLE_FULL;
    cursor->part_loc.part_no = table_stats->part_stats.part_no;
    if (table_stats->part_stats.is_subpart) {
        cursor->part_loc.subpart_no = table_stats->part_stats.sub_stats->part_no;
    }

    if (knl_open_cursor(session, cursor, dc) != CT_SUCCESS) {
        knl_close_cursor(session, cursor);
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    cursor->isolevel = ISOLATION_CURR_COMMITTED;

    if (STATS_IS_ANALYZE_SINGLE_PART(table_stats, table_stats->part_stats.part_id)) {
        stats_sample_ratio_init(session, dc, &stats_sample, &table_stats->part_sample_ratio, table_stats);
    } else {
        stats_sample_ratio_init(session, dc, &stats_sample, &table_stats->estimate_sample_ratio, table_stats);
    }
    status_t result = stats_insert_mtrl_heap_table(session, cursor, temp_ctx, &stats_sample, seg_id, table_stats);
    if (result != CT_SUCCESS) {
        knl_close_cursor(session, cursor);
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    knl_close_cursor(session, cursor);
    CM_RESTORE_STACK(session->stack);
    SYNC_POINT_GLOBAL_START(COLLECT_STATISTICS_CREATE_TEMP_TABLE_FAIL, &result, CT_ERROR);
    SYNC_POINT_GLOBAL_END;
    return result;
}

status_t stats_create_mtrl_table(knl_session_t *session, knl_dictionary_t *dc, stats_tab_context_t *tab_ctx)
{
    mtrl_context_t *temp_ctx = tab_ctx->mtrl_tab_ctx;
    uint32 seg_id = tab_ctx->mtrl_tab_seg;
    stats_table_t *table_stats = tab_ctx->table_stats;
    knl_cursor_t *cursor = NULL;
    stats_sampler_t stats_sample;
    errno_t ret;

    ret = memset_s(&stats_sample, sizeof(stats_sampler_t), 0, sizeof(stats_sampler_t));
    knl_securec_check(ret);

    CM_SAVE_STACK(session->stack);
    cursor = knl_push_cursor(session);
    knl_init_cursor_buf(session, cursor);
    cursor->action = CURSOR_ACTION_SELECT;
    cursor->scan_mode = SCAN_MODE_TABLE_FULL;
    cursor->part_loc.part_no = table_stats->part_stats.part_no;
    status_t result = knl_open_cursor(session, cursor, dc);
    if (result != CT_SUCCESS) {
        knl_close_cursor(session, cursor);
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    cursor->isolevel = ISOLATION_CURR_COMMITTED;

    if (!STATS_IS_ANALYZE_TEMP_TABLE(table_stats)) {
        stats_sample_ratio_init(session, dc, &stats_sample, &table_stats->estimate_sample_ratio, table_stats);
    }

    if (!STATS_IS_ANALYZE_TEMP_TABLE(table_stats)) {
        if (stats_insert_mtrl_heap_table(session, cursor, temp_ctx, &stats_sample, seg_id, table_stats) != CT_SUCCESS) {
            mtrl_close_segment(temp_ctx, seg_id);
            knl_close_cursor(session, cursor);
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }
    } else {
        if (stats_insert_mtrl_temp_table(session, cursor, temp_ctx, seg_id, table_stats) != CT_SUCCESS) {
            mtrl_close_segment(temp_ctx, seg_id);
            knl_close_cursor(session, cursor);
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }
    }

    mtrl_close_segment(temp_ctx, seg_id);
    knl_close_cursor(session, cursor);
    CM_RESTORE_STACK(session->stack);
    SYNC_POINT_GLOBAL_START(COLLECT_STATISTICS_CREATE_TEMP_TABLE_FAIL, &result, CT_ERROR);
    SYNC_POINT_GLOBAL_END;
    return result;
}

status_t stats_alloc_vm_memory(knl_session_t *session, uint32 *vmid, char **page)
{
    vm_page_t *vm_page = NULL;

    if (vm_alloc(session, session->temp_pool, vmid) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (vm_open(session, session->temp_pool, *vmid, &vm_page) != CT_SUCCESS) {
        vm_free(session, session->temp_pool, *vmid);
        return CT_ERROR;
    }

    *page = vm_page->data;
    return CT_SUCCESS;
}

void stats_close_vm(knl_handle_t session, uint32 vmid)
{
    knl_session_t *se = (knl_session_t *)session;
    if (vmid == CT_INVALID_ID32) {
        return;
    }

    vm_close_and_free(se, se->temp_pool, vmid);
}

static status_t stats_create_distinct_values(knl_session_t *session, stats_col_handler_t *column_handler)
{
    mtrl_context_t *ctx = &column_handler->mtrl.mtrl_ctx;
    uint32 *seg_id = &column_handler->mtrl.dist_seg_id;
    mtrl_cursor_t *mtrl_cur = &column_handler->mtrl.mtrl_cur;

    if (mtrl_create_segment(ctx, MTRL_SEGMENT_DISTINCT, (handle_t)column_handler->column, seg_id) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (mtrl_open_segment(ctx, *seg_id) != CT_SUCCESS) {
        return CT_ERROR;
    }
 
    if (stats_mtrl_distinct(session, column_handler) != CT_SUCCESS) {
        mtrl_close_segment(ctx, *seg_id);
        return CT_ERROR;
    }

    mtrl_close_segment(ctx, *seg_id);
    if (mtrl_sort_segment(ctx, *seg_id) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (mtrl_open_cursor(ctx, *seg_id, mtrl_cur) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t stats_update_sys_subindexpart(knl_session_t *session, stats_index_t *stats_index)
{
    row_assist_t ra;
    knl_scan_key_t *key = NULL;
    uint16 size;
    knl_cursor_t *cursor = NULL;

    if (stats_try_begin_auton_rm(session, stats_index->is_dynamic) != CT_SUCCESS) {
        return CT_ERROR;
    }

    CM_SAVE_STACK(session->stack);
    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_SUB_INDEX_PARTS_ID, IX_SYS_INDEXSUBPART001_ID);
    knl_init_index_scan(cursor, CT_TRUE);
    key = &cursor->scan_range.l_key;
    knl_set_scan_key(INDEX_DESC(cursor->index), key, CT_TYPE_INTEGER, &stats_index->uid, sizeof(uint32),
        IX_COL_SYS_INDEXSUBPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, CT_TYPE_INTEGER, &stats_index->table_id, sizeof(uint32),
        IX_COL_SYS_INDEXSUBPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, CT_TYPE_INTEGER, &stats_index->idx_id, sizeof(uint32),
        IX_COL_SYS_INDEXSUBPART001_INDEX_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, CT_TYPE_INTEGER, &stats_index->part_id, sizeof(uint32),
        IX_COL_SYS_INDEXSUBPART001_PARENT_PART_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, CT_TYPE_INTEGER, &stats_index->subpart_id, sizeof(uint32),
        IX_COL_SYS_INDEXSUBPART001_SUB_PART_ID);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        stats_try_end_auton_rm(session, CT_ERROR, stats_index->is_dynamic);
        return CT_ERROR;
    }

    if (cursor->eof) {
        CM_RESTORE_STACK(session->stack);
        CT_THROW_ERROR(ERR_INDEX_ALREADY_DROPPED, T2S(&stats_index->name));
        stats_try_end_auton_rm(session, CT_ERROR, stats_index->is_dynamic);
        return CT_ERROR;
    }

    row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), STATS_SYS_INDEX_COLUMN_COUNT);

    cursor->update_info.count = STATS_SYS_INDEX_COLUMN_COUNT;
    row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), STATS_SYS_INDEX_COLUMN_COUNT);
    (void)row_put_int32(&ra, stats_index->info.height);  // btree level
    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, stats_index->info.leaf_blocks));
    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, stats_index->info.distinct_keys));
    (void)row_put_real(&ra, stats_index->avg_leaf_key);
    (void)row_put_real(&ra, stats_index->avg_data_key);
    (void)row_put_date(&ra, cm_now());
    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, stats_index->info.empty_leaves));
    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, stats_index->clus_factor));  // clus_factor
    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, stats_index->sample_size));
    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, stats_index->info.comb_cols_2_ndv));
    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, stats_index->info.comb_cols_3_ndv));
    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, stats_index->info.comb_cols_4_ndv));

    for (uint32 i = 0; i < STATS_SYS_INDEX_COLUMN_COUNT; i++) {
        cursor->update_info.columns[i] = i + STATS_SYS_INDEXPART_COLUMN_NUM;
    }

    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, &size);

    if (knl_internal_update(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        stats_try_end_auton_rm(session, CT_ERROR, stats_index->is_dynamic);
        return CT_ERROR;
    }

    CM_RESTORE_STACK(session->stack);

    stats_try_end_auton_rm(session, CT_SUCCESS, stats_index->is_dynamic);
    return CT_SUCCESS;
}

status_t stats_update_sys_indexpart(knl_session_t *session, stats_index_t *stats_index)
{
    row_assist_t ra;
    knl_scan_key_t *key = NULL;
    uint16 size;
    knl_cursor_t *cursor = NULL;

    if (stats_try_begin_auton_rm(session, stats_index->is_dynamic) != CT_SUCCESS) {
        return CT_ERROR;
    }
 
    CM_SAVE_STACK(session->stack);
    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_INDEXPART_ID, IX_SYS_INDEXPART001_ID);
    knl_init_index_scan(cursor, CT_TRUE);
    key = &cursor->scan_range.l_key;
    knl_set_scan_key(INDEX_DESC(cursor->index), key, CT_TYPE_INTEGER, &stats_index->uid, sizeof(uint32),
                     IX_COL_SYS_INDEXPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, CT_TYPE_INTEGER, &stats_index->table_id, sizeof(uint32),
                     IX_COL_SYS_INDEXPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, CT_TYPE_INTEGER, &stats_index->idx_id, sizeof(uint32),
                     IX_COL_SYS_INDEXPART001_INDEX_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, CT_TYPE_INTEGER, &stats_index->part_id, sizeof(uint32),
                     IX_COL_SYS_INDEXPART001_PART_ID);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        stats_try_end_auton_rm(session, CT_ERROR, stats_index->is_dynamic);
        return CT_ERROR;
    }

    if (cursor->eof) {
        CM_RESTORE_STACK(session->stack);
        CT_THROW_ERROR(ERR_INDEX_ALREADY_DROPPED, T2S(&stats_index->name));
        stats_try_end_auton_rm(session, CT_ERROR, stats_index->is_dynamic);
        return CT_ERROR;
    }

    row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), STATS_SYS_INDEX_COLUMN_COUNT);

    cursor->update_info.count = STATS_SYS_INDEX_COLUMN_COUNT;
    row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), STATS_SYS_INDEX_COLUMN_COUNT);
    (void)row_put_int32(&ra, stats_index->info.height);  // btree level
    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, stats_index->info.leaf_blocks));
    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, stats_index->info.distinct_keys));
    (void)row_put_real(&ra, stats_index->avg_leaf_key);
    (void)row_put_real(&ra, stats_index->avg_data_key);
    (void)row_put_date(&ra, cm_now());
    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, stats_index->info.empty_leaves));
    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, stats_index->clus_factor));  // clus_factor
    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, stats_index->sample_size));
    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, stats_index->info.comb_cols_2_ndv));
    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, stats_index->info.comb_cols_3_ndv));
    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, stats_index->info.comb_cols_4_ndv));

    for (uint32 i = 0; i < STATS_SYS_INDEX_COLUMN_COUNT; i++) {
        cursor->update_info.columns[i] = i + STATS_SYS_INDEXPART_COLUMN_NUM;
    }

    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, &size);

    if (knl_internal_update(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        stats_try_end_auton_rm(session, CT_ERROR, stats_index->is_dynamic);
        return CT_ERROR;
    }

    CM_RESTORE_STACK(session->stack);

    stats_try_end_auton_rm(session, CT_SUCCESS, stats_index->is_dynamic);

    return CT_SUCCESS;
}

static status_t stats_update_sys_index(knl_session_t *session, stats_index_t *stats_index)
{
    row_assist_t ra;
    knl_scan_key_t *key = NULL;
    uint16 size;
    knl_cursor_t *cursor = NULL;
    
    if (stats_try_begin_auton_rm(session, stats_index->is_dynamic) != CT_SUCCESS) {
        return CT_ERROR;
    }

    CM_SAVE_STACK(session->stack);
    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_INDEX_ID, IX_SYS_INDEX_002_ID);
    knl_init_index_scan(cursor, CT_TRUE);
    key = &cursor->scan_range.l_key;
    knl_set_scan_key(INDEX_DESC(cursor->index), key, CT_TYPE_INTEGER, &stats_index->uid, sizeof(uint32),
                     IX_COL_SYS_INDEX_002_USER);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, CT_TYPE_STRING, stats_index->name.str, stats_index->name.len,
                     IX_COL_SYS_INDEX_002_NAME);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, CT_TYPE_INTEGER, &stats_index->table_id, sizeof(uint32),
                     IX_COL_SYS_INDEX_002_TABLE);
    
    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        stats_try_end_auton_rm(session, CT_ERROR, stats_index->is_dynamic);
        return CT_ERROR;
    }

    if (cursor->eof) {
        CM_RESTORE_STACK(session->stack);
        CT_THROW_ERROR(ERR_INDEX_ALREADY_DROPPED, T2S(&stats_index->name));
        stats_try_end_auton_rm(session, CT_ERROR, stats_index->is_dynamic);
        return CT_ERROR;
    }

    row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), STATS_SYS_INDEX_COLUMN_COUNT);

    cursor->update_info.count = STATS_SYS_INDEX_COLUMN_COUNT;
    row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), STATS_SYS_INDEX_COLUMN_COUNT);
    (void)row_put_int32(&ra, stats_index->info.height);  // btree level
    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, stats_index->info.leaf_blocks));
    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, stats_index->info.distinct_keys));
    (void)row_put_real(&ra, stats_index->avg_leaf_key);
    (void)row_put_real(&ra, stats_index->avg_data_key);
    (void)row_put_date(&ra, cm_now());
    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, stats_index->info.empty_leaves));
    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, stats_index->clus_factor));  // clus_factor
    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, stats_index->sample_size));
    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, stats_index->info.comb_cols_2_ndv));
    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, stats_index->info.comb_cols_3_ndv));
    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, stats_index->info.comb_cols_4_ndv));

    cursor->update_info.columns[0] = STATS_SYS_INDEX_BLEVEL_COLUMN;
    cursor->update_info.columns[1] = STATS_SYS_INDEX_LEAF_BLOCKS_COLUMN;
    cursor->update_info.columns[2] = STATS_SYS_INDEX_NDV_KEY_COLUMN;
    cursor->update_info.columns[3] = STATS_SYS_INDEX_AVG_LBK_COLUMN;
    cursor->update_info.columns[4] = STATS_SYS_INDEX_AVG_DBK_COLUMN;
    cursor->update_info.columns[5] = STATS_SYS_INDEX_ANALYZETIME_COLUMN;
    cursor->update_info.columns[6] = STATS_SYS_INDEX_EMPTY_BLOCK_COLUMN;
    cursor->update_info.columns[7] = STATS_SYS_INDEX_COLFAC_COLUMN;
    cursor->update_info.columns[8] = STATS_SYS_INDEX_SAMSIZE_COLUMN;
    cursor->update_info.columns[9] = STATS_SYS_INDEX_COMB2_NDV_COLUMN;
    cursor->update_info.columns[10] = STATS_SYS_INDEX_COMB3_NDV_COLUMN;
    cursor->update_info.columns[11] = STATS_SYS_INDEX_COMB4_NDV_COLUMN;

    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, &size);

    if (knl_internal_update(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        stats_try_end_auton_rm(session, CT_ERROR, stats_index->is_dynamic);
        return CT_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    stats_try_end_auton_rm(session, CT_SUCCESS, stats_index->is_dynamic);

    return CT_SUCCESS;
}

void stats_reset_index_stats(stats_index_t *stats_idx)
{
    stats_idx->info.height = 0;
    stats_idx->info.clustor = 0;
    stats_idx->info.distinct_keys = 0;
    stats_idx->info.empty_leaves = 0;
    stats_idx->info.leaf_blocks = 0;
    stats_idx->info.comb_cols_2_ndv = 0;
    stats_idx->info.comb_cols_3_ndv = 0;
    stats_idx->info.comb_cols_4_ndv = 0;
    stats_idx->avg_data_key = 0;
    stats_idx->avg_leaf_key = 0;
    stats_idx->clus_factor = 0;
}

static void stats_mtrl2knl_cursor(mtrl_cursor_t *mtrl_cur, knl_cursor_t *knl_cur)
{
    rowid_t *rowid = NULL;
    row_head_t *row = (row_head_t *)mtrl_cur->row.data;

    stats_get_rowid(mtrl_cur, &rowid);

    knl_cur->row = row;
    knl_cur->offsets = mtrl_cur->row.offsets;
    knl_cur->lens = mtrl_cur->row.lens;
    knl_cur->rowid = *rowid;
    knl_cur->table = NULL;
}

static status_t stats_make_index_key(knl_handle_t session, mtrl_cursor_t *cursor,
                                     index_t *idx, char *key_buf)
{
    knl_cursor_t *knl_cur = NULL;

    CM_SAVE_STACK(((knl_session_t *)session)->stack);
    knl_cur = knl_push_cursor(session);
    stats_mtrl2knl_cursor(cursor, knl_cur);

    if (knl_make_key(session, knl_cur, idx, key_buf) != CT_SUCCESS) {
        CM_RESTORE_STACK(((knl_session_t *)session)->stack);
        return CT_ERROR;
    }

    CM_RESTORE_STACK(((knl_session_t *)session)->stack);
    return CT_SUCCESS;
}

static status_t stats_mtrl_index_key(knl_session_t *session, index_t *idx, stats_index_t *stats_idx)
{
    mtrl_rowid_t       rid;
    mtrl_context_t    *ctx = &stats_idx->mtrl.mtrl_ctx;
    mtrl_context_t    *temp_ctx = stats_idx->mtrl.mtrl_table_ctx;
    mtrl_cursor_t     *cursor = &stats_idx->mtrl.mtrl_cur;
    uint32             dist_seg = stats_idx->mtrl.dist_seg_id;
    uint32             temp_seg = stats_idx->mtrl.temp_seg_id;

    if (stats_open_mtrl_rs_cursor(stats_idx->g_rid, temp_ctx, cursor, temp_seg) != CT_SUCCESS) {
        return CT_ERROR;
    }

    char *key = (char *)cm_push(session->stack, CT_KEY_BUF_SIZE);
    errno_t ret = memset_sp(key, CT_KEY_BUF_SIZE, 0, CT_KEY_BUF_SIZE);
    knl_securec_check(ret);

    for (;;) {
        if (mtrl_fetch_rs(temp_ctx, cursor, CT_TRUE) != CT_SUCCESS) {
            mtrl_close_cursor(temp_ctx, cursor);
            cm_pop(session->stack);
            return CT_ERROR;
        }

        if (session->canceled) {
            mtrl_close_cursor(temp_ctx, cursor);
            cm_pop(session->stack);
            CT_THROW_ERROR(ERR_OPERATION_CANCELED);
            return CT_ERROR;
        }

        if (session->killed) {
            mtrl_close_cursor(temp_ctx, cursor);
            cm_pop(session->stack);
            CT_THROW_ERROR(ERR_OPERATION_KILLED);
            return CT_ERROR;
        }

        if (cursor->eof) {
            break;
        }

        if (stats_make_index_key(session, cursor, idx, key) != CT_SUCCESS) {
            mtrl_close_cursor(temp_ctx, cursor);
            cm_pop(session->stack);
            return CT_ERROR;
        }

        if (mtrl_insert_row(ctx, dist_seg, key, &rid) != CT_SUCCESS) {
            mtrl_close_cursor(temp_ctx, cursor);
            cm_pop(session->stack);
            return CT_ERROR;
        }
    }

    mtrl_close_cursor(temp_ctx, cursor);
    cm_pop(session->stack);

    return CT_SUCCESS;
}

static status_t stats_create_mtrl_index(knl_session_t *session, index_t *idx, stats_index_t *stats_idx)
{
    mtrl_context_t *ctx = &stats_idx->mtrl.mtrl_ctx;
    uint32 *seg_id = &stats_idx->mtrl.dist_seg_id;
    uint8 seg_type;

    if (idx->desc.cr_mode == CR_PAGE) {
        seg_type = MTRL_SEGMENT_PCR_BTREE;
        ctx->sort_cmp = stats_pcrb_compare_mtrl_key;
    } else {
        seg_type = MTRL_SEGMENT_RCR_BTREE;
        ctx->sort_cmp = stats_btree_compare_mtrl_key;
    }

    if (mtrl_create_segment(ctx, seg_type, stats_idx->btree, seg_id) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (mtrl_open_segment(ctx, *seg_id) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (stats_mtrl_index_key(session, idx, stats_idx) != CT_SUCCESS) {
        mtrl_close_segment(ctx, *seg_id);
        return CT_ERROR;
    }

    mtrl_close_segment(ctx, *seg_id);
    if (mtrl_sort_segment(ctx, *seg_id) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static void stats_gather_pcrb_key(knl_session_t *session, index_t *idx, stats_index_t *stats_idx, pcrb_key_t *prev_key,
                                  stats_table_t *table_stats)
{
    mtrl_cursor_t *cursor = &stats_idx->mtrl.mtrl_cur;
    pcrb_key_t     *key = (pcrb_key_t *)cursor->sort.row;
    errno_t         ret;

    dc_entity_t *entity = idx->entity;
    cbo_stats_index_t *cbo_index = knl_get_cbo_index(session, entity, idx->desc.id);

    if (stats_idx->info.keys == 0) {
        stats_idx->clus_factor++;
    } else {
        if (!STATS_IS_ANALYZE_TEMP_TABLE(table_stats)) {
            if (!IS_SAME_PAGID(prev_key->rowid, key->rowid)) {
                stats_idx->clus_factor++;
            }
        } else {
            if (!IS_SAME_TEMP_PAGEID(prev_key->rowid, key->rowid)) {
                stats_idx->clus_factor++;
            }
        }
    }

    // clear for next analyze
    if (stats_idx->info.distinct_keys == 0) {
        if (table_stats->part_stats.part_no == CT_INVALID_ID32 ||
            (!table_stats->part_stats.is_subpart && table_stats->part_stats.part_no == 0) ||
            (table_stats->part_stats.is_subpart && table_stats->part_stats.part_no == 0 &&
             table_stats->part_stats.sub_stats->part_no == 0)) {
            for (uint32_t i = 0; i < MAX_KEY_COLUMNS; i++) {
                cbo_index->distinct_keys_arr[i] = 0;
            }
        }
    }

    pcrb_calc_ndv_key(session, idx, key, prev_key, &stats_idx->info);

    stats_idx->info.keys++;
    stats_idx->info.keys_total_size += key->size;

    ret = memcpy_sp(prev_key, CT_KEY_BUF_SIZE, key, (uint32)(key->size));
    knl_securec_check(ret);
}

static void stats_gather_btree_key(knl_session_t *session, index_t *idx,
                                   stats_index_t *stats_idx, btree_key_t *prev_key, stats_table_t *table_stats)
{
    mtrl_cursor_t *cursor = &stats_idx->mtrl.mtrl_cur;
    btree_key_t    *key = (btree_key_t *)cursor->sort.row;
    errno_t         ret;

    if (stats_idx->info.keys == 0) {
        stats_idx->clus_factor++;
    } else {
        if (!STATS_IS_ANALYZE_TEMP_TABLE(table_stats)) {
            if (!IS_SAME_PAGID(prev_key->rowid, key->rowid)) {
                stats_idx->clus_factor++;
            }
        } else {
            if (!IS_SAME_TEMP_PAGEID(prev_key->rowid, key->rowid)) {
                stats_idx->clus_factor++;
            }
        }
    }

    btree_calc_ndv_key(session, idx, key, prev_key, &stats_idx->info);

    stats_idx->info.keys++;
    stats_idx->info.keys_total_size += key->size;

    ret = memcpy_sp(prev_key, CT_KEY_BUF_SIZE, key, (uint32)(key->size));
    knl_securec_check(ret);
}

static inline int32 stats_calc_diff(uint32 sampled_ndv, double sampled_ratio, uint32 total_row, uint32 total_ndv)
{
    double probability = 1.0 - sampled_ratio;
    double pow_value = pow(probability, (double)total_row / (double)total_ndv);

    return (int32)(sampled_ndv - total_ndv * (1.0 - pow_value));
}

/* bernoulli trials. Calculate the transcendental equation with dichotomy method */
static uint32 stats_calc_ndv_with_iteration(uint32 min_value_input, uint32 max_value_input, uint32 total_number,
    uint32 sampled_dist, double sampled_ratio)
{
    uint32 min_value = min_value_input;
    uint32 max_value = max_value_input;
    uint32 mid_value = (min_value + max_value) / 2;
    uint32 iteration_time = 0;
    int32 diff;

    if (stats_calc_diff(sampled_dist, sampled_ratio, total_number, max_value) == 0) {
        return max_value;
    }

    while (max_value - min_value > 1 && iteration_time < STATS_MAX_ITERATION_TIME) {
        iteration_time++;
        diff = stats_calc_diff(sampled_dist, sampled_ratio, total_number, mid_value);
        if (diff < 0) {
            max_value = mid_value;
        } else if (diff > 0) {
            min_value = mid_value;
        } else {
            break;
        }
        mid_value = (min_value + max_value) / 2;
    }
    return mid_value;
}

uint32 stats_estimate_ndv(uint32 sampled_ndv, uint32 sampled_row, double sampled_ratio)
{
    uint32 total_row;
    uint32 ndv_max;
    uint32 ndv_min = 0;

    total_row = (uint32)(sampled_row / sampled_ratio);
    ndv_max = (uint32)(sampled_ndv / sampled_ratio);

    if (sampled_row == 0) {
        return sampled_ndv;
    }

    return stats_calc_ndv_with_iteration(ndv_min, ndv_max, total_row, sampled_ndv, sampled_ratio);
}

static void stats_get_index_height(knl_session_t *session, index_t *idx, stats_index_t *stats_idx,
    stats_table_t *table_stats)
{
    temp_btree_segment_t *temp_segment = NULL;
    knl_tree_info_t tree_info;
    page_id_t btree_entry = STATS_IS_PART_INDEX(stats_idx) ? stats_idx->part_index->btree.entry : idx->btree.entry;
    knl_scn_t seg_scn = STATS_IS_PART_INDEX(stats_idx) ? stats_idx->part_index->desc.seg_scn : idx->desc.seg_scn;

    if (STATS_IS_ANALYZE_TEMP_TABLE(table_stats)) {
        temp_segment = &table_stats->temp_table->table_cache->index_root[idx->desc.id];
        stats_idx->info.height = temp_segment->level == CT_INVALID_ID32 ? 0 : temp_segment->level;
    } else {
        if (IS_INVALID_PAGID(btree_entry)) {
            return;
        }

        if (buf_read_page(session, btree_entry, LATCH_MODE_S, ENTER_PAGE_NORMAL) != CT_SUCCESS) {
            return;
        }
        
        page_head_t *page = (page_head_t *)CURR_PAGE(session);
        btree_segment_t *segment = BTREE_GET_SEGMENT(session);
        if (page->type != PAGE_TYPE_BTREE_HEAD || segment->seg_scn != seg_scn) {
            buf_leave_page(session, CT_FALSE);
            CT_LOG_RUN_ERR("stats index error: found page scn is not seg scn, index name: %s", idx->desc.name);
            return;
        }

        tree_info.value = cm_atomic_get(&segment->tree_info.value);
        stats_idx->info.height = (uint32)tree_info.level;
        buf_leave_page(session, CT_FALSE);
    }
}

static void stats_estimate_total_idx_stats(stats_index_t *stats_idx)
{
    stats_idx->sample_size = stats_idx->info.keys;

    if (stats_idx->sample_ratio > CT_REAL_PRECISION) {
        stats_idx->info.comb_cols_2_ndv = stats_estimate_ndv(stats_idx->info.comb_cols_2_ndv, stats_idx->info.keys,
            stats_idx->sample_ratio);
        stats_idx->info.comb_cols_3_ndv = stats_estimate_ndv(stats_idx->info.comb_cols_3_ndv, stats_idx->info.keys,
            stats_idx->sample_ratio);
        stats_idx->info.comb_cols_4_ndv = stats_estimate_ndv(stats_idx->info.comb_cols_4_ndv, stats_idx->info.keys,
            stats_idx->sample_ratio);
        stats_idx->info.distinct_keys = stats_estimate_ndv(stats_idx->info.distinct_keys,
            stats_idx->info.keys, stats_idx->sample_ratio);

        stats_idx->info.keys = (uint32)(stats_idx->info.keys / stats_idx->sample_ratio);
        stats_idx->info.keys_total_size = (uint64)(stats_idx->info.keys_total_size / stats_idx->sample_ratio);
        stats_idx->clus_factor = (uint32)(stats_idx->clus_factor / stats_idx->sample_ratio);
    }
}

static status_t stats_gather_key_info(knl_session_t *session, index_t *idx, stats_index_t *stats_idx,
                                      stats_table_t *table_stats)
{
    mtrl_context_t *ctx = &stats_idx->mtrl.mtrl_ctx;
    mtrl_cursor_t *cursor = &stats_idx->mtrl.mtrl_cur;
    uint32 dist_seg = stats_idx->mtrl.dist_seg_id;
    pcrb_key_t *prev_pcrb_key = NULL;
    btree_key_t *prev_btree_key = NULL;
    errno_t ret;

    CM_SAVE_STACK(session->stack);

    if (idx->desc.cr_mode == CR_PAGE) {
        prev_pcrb_key = (pcrb_key_t *)cm_push(session->stack, CT_KEY_BUF_SIZE);
        ret = memset_sp(prev_pcrb_key, CT_KEY_BUF_SIZE, 0, CT_KEY_BUF_SIZE);
        knl_securec_check(ret);
    } else {
        prev_btree_key = (btree_key_t *)cm_push(session->stack, CT_KEY_BUF_SIZE);
        ret = memset_sp(prev_btree_key, CT_KEY_BUF_SIZE, 0, CT_KEY_BUF_SIZE);
        knl_securec_check(ret);
    }

    if (mtrl_open_cursor(ctx, dist_seg, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    for (;;) {
        if (mtrl_fetch_sort_key(ctx, cursor) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            mtrl_close_cursor(ctx, cursor);
            return CT_ERROR;
        }

        if (session->canceled) {
            CM_RESTORE_STACK(session->stack);
            mtrl_close_cursor(ctx, cursor);
            CT_THROW_ERROR(ERR_OPERATION_CANCELED);
            return CT_ERROR;
        }

        if (session->killed) {
            CM_RESTORE_STACK(session->stack);
            mtrl_close_cursor(ctx, cursor);
            CT_THROW_ERROR(ERR_OPERATION_KILLED);
            return CT_ERROR;
        }

        if (cursor->eof) {
            break;
        }

        if (idx->desc.cr_mode == CR_PAGE) {
            stats_gather_pcrb_key(session, idx, stats_idx, prev_pcrb_key, table_stats);
        } else {
            stats_gather_btree_key(session, idx, stats_idx, prev_btree_key, table_stats);
        }
    }

    stats_get_index_height(session, idx, stats_idx, table_stats);

    stats_estimate_total_idx_stats(stats_idx);

    mtrl_close_cursor(ctx, cursor);
    CM_RESTORE_STACK(session->stack);

    return CT_SUCCESS;
}


static void stats_estimate_tmp_leaf_page(knl_session_t *session, stats_index_t *stats_idx,
    stats_table_t *table_stats)
{
    uint64 key_cost_size;
    uint32 avg_key_len;
    uint64 page_data_size;
    // assume that half of each btree page is used
    double page_load_factor = 0.5;
    uint32 level = stats_idx->info.height;
    uint32 ratio;
    uint64 higher_level_page = 1;
    uint64 estimate_data_page = 0;
    uint32 estimate_leaf_page;
    mtrl_segment_t *segment = NULL;
    uint32 index_segid = table_stats->temp_table->table_cache->index_segid;

    segment = session->temp_mtrl->segments[index_segid];

    if (stats_idx->info.height == 1) {
        stats_idx->info.leaf_blocks = 1;
        stats_idx->info.empty_leaves = 0;
        return;
    }

    if (stats_idx->info.keys == 0) {
        return;
    }

    // key len must be smaller than max value of uint32
    avg_key_len = (uint32)(stats_idx->info.keys_total_size / stats_idx->info.keys);
    page_data_size = CT_VMEM_PAGE_SIZE - sizeof(temp_btree_page_t) - sizeof(temp_page_tail_t);
    ratio = (uint32)(page_data_size * page_load_factor / (avg_key_len + sizeof(temp_btree_dir_t)));
    stats_idx->sample_size = stats_idx->info.keys;

    estimate_data_page += higher_level_page;

    for (; level > 0; level--) {
        higher_level_page = higher_level_page * ratio;
        estimate_data_page += higher_level_page;
    }

    key_cost_size = stats_idx->info.keys_total_size + stats_idx->info.keys * sizeof(temp_btree_dir_t);
    estimate_leaf_page = (uint32)((key_cost_size + page_data_size * page_load_factor - 1) /
        (page_data_size * page_load_factor));

    double leaf_block_percent = (double)higher_level_page / estimate_data_page;
    // after calculate ratio of estimate_leaf_page to all page, use ratio multiple real total page
    stats_idx->info.leaf_blocks = (uint32)(segment->vm_list.count * leaf_block_percent);

    if (stats_idx->info.leaf_blocks > estimate_leaf_page) {
        stats_idx->info.empty_leaves = stats_idx->info.leaf_blocks - estimate_leaf_page;
    } else {
        stats_idx->info.empty_leaves = 0;
    }
}

/*
* 1. we must estimate empty leaves when all records of the table have been deleted
* 2. because we can not fetch heap data for making btree keys, we use the length of key from root node as avg_key_len
*
*/
static void stats_estimate_btree_empty_pages(knl_session_t *session, index_t *idx, stats_index_t *stats_idx,
    btree_segment_t *segment)
{
    uint32 dir_size = idx->desc.cr_mode == CR_ROW ? sizeof(btree_dir_t) : sizeof(pcrb_dir_t);
    uint32 itl_size = idx->desc.cr_mode == CR_ROW ? sizeof(itl_t) : sizeof(pcr_itl_t);
    uint64 avg_key_len = 0;
    uint64 page_data_size;
    // assume that half of each btree page is used
    double page_load_factor = 0.5;
    uint32 level = stats_idx->info.height;
    uint64 higher_level_page = 1;
    uint64 estimate_data_page = 0;
    uint32 recycled_cnt = segment->del_pages.count + segment->recycled_pages.count;
    uint32 unused_page = recycled_cnt + segment->ufp_count + 1; // 1 is map page
    space_t *space = SPACE_GET(session, segment->space_id);
    uint32 real_total_page = btree_get_segment_page_count(space, segment) - unused_page;

    page_type_t page_type = (idx->desc.cr_mode == CR_PAGE) ? PAGE_TYPE_PCRB_NODE : PAGE_TYPE_BTREE_NODE;

    if (!spc_validate_page_id(session, AS_PAGID(segment->tree_info.root))) {
        CT_LOG_RUN_ERR("stats index error: index name: %s has been droped", idx->desc.name);
        return;
    }

    if (buf_read_page(session, AS_PAGID(segment->tree_info.root), LATCH_MODE_S, ENTER_PAGE_NORMAL) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[STATS] ERROR INFO: failed to read page %u-%u",
            AS_PAGID(segment->tree_info.root).file, AS_PAGID(segment->tree_info.root).page);
        return;
    }
    btree_page_t *page = BTREE_CURR_PAGE(session);

    if (btree_check_segment_scn(page, page_type, segment->seg_scn) != CT_SUCCESS) {
        buf_leave_page(session, CT_FALSE);
        CT_LOG_RUN_ERR("stats index error: found page scn is not seg scn, index name: %s", idx->desc.name);
        return;
    }

    for (uint32 j = 1; j < page->keys; j++) {
        if (idx->desc.cr_mode == CR_PAGE) {
            pcrb_dir_t *pcrb_dir = pcrb_get_dir(page, j);
            pcrb_key_t *pcrb_key = PCRB_GET_KEY(page, pcrb_dir);
            avg_key_len += (pcrb_key->size - sizeof(page_id_t));
        } else {
            btree_dir_t *dir = BTREE_GET_DIR(page, j);
            btree_key_t *key = BTREE_GET_KEY(page, dir);
            avg_key_len += key->size;
        }
    }

    avg_key_len = (page->keys > 1) ? (uint64)(avg_key_len / (page->keys - 1)) : 0;
    page_data_size = DEFAULT_PAGE_SIZE(session) - sizeof(btree_page_t) - space->ctrl->cipher_reserve_size -
                        sizeof(page_tail_t) - page->itls * itl_size;
    buf_leave_page(session, CT_FALSE);

    uint32 ratio = (uint32)(page_data_size * page_load_factor / (avg_key_len + dir_size));
    estimate_data_page += higher_level_page;

    for (; level > 0; level--) {
        higher_level_page = higher_level_page * ratio;
        estimate_data_page += higher_level_page;
    }

    double leaf_block_percent = (double)higher_level_page / estimate_data_page;
    // leaf_blocks is equal to empty_leaves, eg: delete from table
    stats_idx->info.leaf_blocks = (uint32)(real_total_page * leaf_block_percent);
    stats_idx->info.empty_leaves = stats_idx->info.leaf_blocks;
}

/*
 * 1. assume parent of leaf node is half occupied. With avg_key_size,
 *    we can estimate the percentage of leaf nodes to total nodes.
 *    Then, with the total nodes number, we can estimate leaf nodes named leaf_nodes_1.
 * 2. assume leaf node is half occupied. With total key size, we can estimate total leaf nodes as leaf_nodes_2.
 * 3. empty leaf nodes is leaf_nodes_1 plus leaf_nodes_2
 */
static void stats_estimate_leaf_page(knl_session_t *session, index_t *idx, stats_index_t *stats_idx,
    btree_segment_t *segment)
{
    uint32      dir_size;
    uint64      key_cost_size;
    uint32      avg_key_len;
    uint64      page_data_size;
    // assume that half of each btree page is used
    double      page_load_factor = 0.5;
    uint32      level = stats_idx->info.height;
    uint32      ratio;
    uint64      higher_level_page = 1;
    uint64      estimate_data_page = 0;
    uint32      estimate_leaf_page;
    uint32      unused_page;
    uint32      real_total_page;
    space_t    *space = SPACE_GET(session, segment->space_id);

    unused_page = segment->del_pages.count + segment->recycled_pages.count + segment->ufp_count + 1; // 1 is map page
    real_total_page = btree_get_segment_page_count(space, segment) - unused_page;

    if (stats_idx->info.height == 1) {
        stats_idx->info.leaf_blocks = 1;
        stats_idx->info.empty_leaves = real_total_page - stats_idx->info.leaf_blocks;
        return;
    }

    if (stats_idx->info.keys == 0) {
        stats_estimate_btree_empty_pages(session, idx, stats_idx, segment);
        return;
    }

    dir_size = idx->desc.cr_mode == CR_ROW ? sizeof(btree_dir_t) : sizeof(pcrb_dir_t);

    // key len must be smaller than max value of uint32
    avg_key_len = (uint32)(stats_idx->info.keys_total_size / stats_idx->info.keys);
    page_data_size = DEFAULT_PAGE_SIZE(session) - sizeof(btree_page_t) -
        space->ctrl->cipher_reserve_size - sizeof(page_tail_t) - sizeof(itl_t);
    ratio = (uint32)(int32)(page_data_size * page_load_factor / (avg_key_len + dir_size));

    estimate_data_page += higher_level_page;

    for (; level > 0; level--) {
        higher_level_page = higher_level_page * ratio;
        estimate_data_page += higher_level_page;
    }

    key_cost_size = stats_idx->info.keys_total_size + stats_idx->info.keys * dir_size;
    estimate_leaf_page = (uint32)((key_cost_size + page_data_size * page_load_factor - 1) /
        (page_data_size * page_load_factor));

    double leaf_block_percent = (double)higher_level_page / estimate_data_page;
    // after calculate ratio of estimate_leaf_page to all page, use ratio multiple real total page
    stats_idx->info.leaf_blocks = (uint32)(real_total_page * leaf_block_percent);

    if (stats_idx->info.leaf_blocks > estimate_leaf_page) {
        stats_idx->info.empty_leaves = stats_idx->info.leaf_blocks - estimate_leaf_page;
    } else {
        stats_idx->info.empty_leaves = 0;
    }
}

static void stats_estimate_tmpidx_page_info(knl_session_t *session, index_t *idx, stats_index_t *stats_idx,
                                            stats_table_t *table_stats)
{
    stats_idx->uid = idx->desc.uid;
    stats_idx->name.str = idx->desc.name;
    // index name len is not greater than 68
    stats_idx->name.len = (uint16)strlen(idx->desc.name);
    stats_idx->table_id = idx->desc.table_id;
    stats_idx->idx_id = idx->desc.id;

    uint32 index_segid = table_stats->temp_table->table_cache->index_segid;
    if (index_segid == CT_INVALID_ID32 || index_segid >= session->temp_mtrl->seg_count) {
        return;
    }
    mtrl_segment_t *mtrl_segment = session->temp_mtrl->segments[index_segid];
    if (mtrl_segment == NULL) {
        return;
    }

    stats_estimate_tmp_leaf_page(session, stats_idx, table_stats);

    if (stats_idx->info.distinct_keys != 0) {
        stats_idx->avg_leaf_key = (double)stats_idx->info.leaf_blocks / (double)stats_idx->info.distinct_keys;
        stats_idx->avg_data_key = (double)(mtrl_segment->vm_list.count) / stats_idx->info.distinct_keys;
    }
}

static void stats_estimate_page_info(knl_session_t *session, index_t *idx, stats_index_t *stats_idx)
{
    page_id_t btree_entry = STATS_IS_PART_INDEX(stats_idx) ? stats_idx->part_index->desc.entry : idx->desc.entry;
    knl_scn_t seg_scn = STATS_IS_PART_INDEX(stats_idx) ? stats_idx->part_index->desc.seg_scn : idx->desc.seg_scn;
    space_t *space = STATS_IS_PART_INDEX(stats_idx) ? SPACE_GET(session, stats_idx->part_index->desc.space_id) :
        SPACE_GET(session, idx->desc.space_id);

    if (IS_INVALID_PAGID(btree_entry)) {
        return;
    }
    if (buf_read_page(session, btree_entry, LATCH_MODE_S, ENTER_PAGE_NORMAL) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[STATS] ERROR INFO: failed to read page %u-%u", btree_entry.file, btree_entry.page);
        return;
    }
    page_head_t *page = (page_head_t *)CURR_PAGE(session);
    btree_segment_t *segment = BTREE_GET_SEGMENT(session);
    if (page->type != PAGE_TYPE_BTREE_HEAD || segment->seg_scn != seg_scn) {
        buf_leave_page(session, CT_FALSE);
        CT_LOG_RUN_ERR("stats index error: found current seg scn is not origin seg scn, index name: %s",
            idx->desc.name);
        return;
    }
  
    stats_estimate_leaf_page(session, idx, stats_idx, segment);
    uint32 segment_blocks = btree_get_segment_page_count(space, segment);

    if (stats_idx->part_index == NULL) {
        stats_idx->uid = idx->desc.uid;
        stats_idx->name.str = idx->desc.name;
        // index name len is not greater than 68
        stats_idx->name.len = (uint16)strlen(idx->desc.name);
        stats_idx->table_id = idx->desc.table_id;
        stats_idx->idx_id = idx->desc.id;
    } else {
        stats_idx->uid = stats_idx->part_index->desc.uid;
        stats_idx->table_id = stats_idx->part_index->desc.table_id;
        stats_idx->idx_id = stats_idx->part_index->desc.index_id;
        stats_idx->name.str = stats_idx->part_index->desc.name;
        stats_idx->name.len = (uint16)strlen(stats_idx->part_index->desc.name);
    }

    uint32 recycled_cnt = segment->del_pages.count + segment->recycled_pages.count;
    if (stats_idx->info.distinct_keys == 0) {
        stats_idx->avg_leaf_key = stats_idx->info.leaf_blocks;
        stats_idx->avg_data_key = segment_blocks - recycled_cnt;
    } else {
        stats_idx->avg_leaf_key = (double)stats_idx->info.leaf_blocks / (double)stats_idx->info.distinct_keys;
        stats_idx->avg_data_key = (double)(segment_blocks - recycled_cnt) / stats_idx->info.distinct_keys;
    }
    buf_leave_page(session, CT_FALSE);
}

static void stats_init_index_handler(knl_session_t *session, stats_index_t *stats_idx, double sample_ratio)
{
    errno_t ret;

    ret = memset_sp(stats_idx, sizeof(stats_index_t), 0, sizeof(stats_index_t));
    knl_securec_check(ret);

    mtrl_init_context(&stats_idx->mtrl.mtrl_ctx, session);
    stats_idx->sample_ratio = sample_ratio;
    stats_idx->part_index = NULL;
}

void stats_calc_index_empty_size(knl_session_t *session, dc_entity_t *entity, index_t *idx, stats_index_t *stats_idx)
{
    knl_part_locate_t part_loc;

    if (stats_idx->part_id != CT_INVALID_ID32) {
        if (stats_idx->is_subpart) {
            part_loc.part_no = stats_idx->part_index->parent_partno;
            part_loc.subpart_no = stats_idx->part_index->part_no;
        } else {
            part_loc.part_no = stats_idx->part_index->part_no;
            part_loc.subpart_no = CT_INVALID_ID32;
        }
    } else {
        part_loc.part_no = CT_INVALID_ID32;
        part_loc.subpart_no = CT_INVALID_ID32;
    }

    dc_calc_index_empty_size(session, entity, idx->desc.slot, part_loc, stats_idx->info.empty_leaves);
}

static status_t stats_persist_index_stats(knl_session_t *session, stats_index_t *stats_idx, stats_table_t *table_stats)
{
    bool8 is_report = table_stats->stats_option.is_report;
    dc_entity_t *entity = stats_idx->btree->index->entity;
    index_t *idx = stats_idx->btree->index;

    if (is_report) {
        stats_write_report_idx_value(session, entity, stats_idx, table_stats);
        return CT_SUCCESS;
    }

    if (stats_no_persistent(table_stats)) {
        cbo_load_tmptab_index_stats(table_stats->temp_table->table_cache->cbo_stats, stats_idx);
        return CT_SUCCESS;
    }

    stats_calc_index_empty_size(session, entity, idx, stats_idx);
    stats_idx->uid = idx->desc.uid;
    stats_idx->name.str = idx->desc.name;
    stats_idx->name.len = (uint16)strlen(idx->desc.name);
    stats_idx->table_id = idx->desc.table_id;
    if (stats_idx->part_id != CT_INVALID_ID32) {
        if (stats_idx->is_subpart) {
            return stats_update_sys_subindexpart(session, stats_idx);
        }

        return stats_update_sys_indexpart(session, stats_idx);
    }
    
    return stats_update_sys_index(session, stats_idx);
}

/*
* There are two cases for dynamic statistics
* case 1: all statistics is missing
* case 2: just a certain columns statistics is missing
* for case 2 we will check index statistics is existed or not, it will reduce duplicate statistics for indexes
*/
bool32 stats_dynamic_ignore_index(knl_session_t *session, dc_entity_t *entity, uint32 index_id,
                                  stats_table_t *table_stats)
{
    knl_analyze_dynamic_type_t dynamic_type = table_stats->stats_option.dynamic_type;
    cbo_stats_index_t *stats_index = NULL;

    if (!table_stats->is_dynamic) {
        return CT_FALSE;
    }

    if (dynamic_type == STATS_ALL) {
        return CT_FALSE;
    }

    if (table_stats->is_part) {
        uint32 part_no = table_stats->part_stats.part_no;
        
        if (table_stats->part_stats.is_subpart) {
            uint32 subpart_no = table_stats->part_stats.sub_stats->part_no;
            stats_index = knl_get_cbo_subpart_index(session, entity, part_no, index_id, subpart_no);
        } else {
            stats_index = knl_get_cbo_part_index(session, entity, part_no, index_id);
        }
    } else {
        stats_index = knl_get_cbo_index(session, entity, index_id);
    }

    if (stats_index != NULL && stats_index->is_ready) {
        return CT_TRUE;
    }
    return CT_FALSE;
}

static status_t stats_gather_index_entity(knl_session_t *session, knl_dictionary_t *dc, index_t *idx,
    stats_index_t *stats_idx, stats_table_t *table_stats)
{
    dc_entity_t *entity = DC_ENTITY(dc);

    if (stats_dynamic_ignore_index(session, entity, idx->desc.id, table_stats)) {
        return CT_SUCCESS;
    }

    if (stats_create_mtrl_index(session, idx, stats_idx) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (stats_gather_key_info(session, idx, stats_idx, table_stats) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (STATS_IS_ANALYZE_TEMP_TABLE(table_stats)) {
        stats_estimate_tmpidx_page_info(session, idx, stats_idx, table_stats);
    } else {
        stats_estimate_page_info(session, idx, stats_idx);
    }

    if (!STATS_IS_ANALYZE_TEMP_TABLE(table_stats)) {
        page_id_t btree_entry = (stats_idx->part_index != NULL) ? stats_idx->part_index->btree.entry : idx->btree.entry;
        knl_scn_t seg_scn = (stats_idx->part_index != NULL) ? stats_idx->part_index->desc.seg_scn : idx->desc.seg_scn;
        if (!IS_INVALID_PAGID(btree_entry)) {
            if (buf_read_page(session, btree_entry, LATCH_MODE_S, ENTER_PAGE_NORMAL) != CT_SUCCESS) {
                CT_LOG_RUN_ERR("[STATS] ERROR INFO: failed to read page %u-%u", btree_entry.file, btree_entry.page);
                return CT_ERROR;
            }
            page_head_t *page = (page_head_t *)CURR_PAGE(session);
            btree_segment_t *segment = BTREE_GET_SEGMENT(session);
            if (page->type != PAGE_TYPE_BTREE_HEAD || segment->seg_scn != seg_scn) {
                buf_leave_page(session, CT_FALSE);
                CT_LOG_DEBUG_WAR("stats index error: found current seg scn is not origin seg scn, index name: %s",
                    idx->desc.name);
                return CT_SUCCESS;
            }
            buf_leave_page(session, CT_FALSE);
        }
    }

    if (stats_persist_index_stats(session, stats_idx, table_stats) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t stats_persist_empty_index_stats(knl_session_t *session, stats_index_t *stats_idx, index_t *idx,
                                                stats_table_t *tab_stats)
{
    bool8 is_report = tab_stats->stats_option.is_report;
    dc_entity_t *entity = stats_idx->btree->index->entity;

    stats_idx->uid = idx->desc.uid;
    stats_idx->name.str = idx->desc.name;
    // index name len is not greater than 68
    stats_idx->name.len = (uint16)strlen(idx->desc.name);
    stats_idx->table_id = idx->desc.table_id;
    stats_idx->idx_id = idx->desc.id;

    stats_reset_index_stats(stats_idx);
 
    if (is_report) {
        stats_write_report_idx_value(session, entity, stats_idx, tab_stats);
        return CT_SUCCESS;
    }

    if (stats_update_sys_index(session, stats_idx) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

/*
 * this function will gather index info, if index is part index, info 0 will be writen in index$
 */
status_t stats_gather_indexes(knl_session_t *session, knl_dictionary_t *dc, stats_table_t *table_stats,
                              mtrl_context_t *mtrl_tab_ctx, uint32 temp_seg)
{
    table_t          *table;
    dc_entity_t      *entity = DC_ENTITY(dc);
    index_t          *index = NULL;
    uint32            i;
    stats_index_t     stats_idx;
    btree_t          *btree = NULL;
    errno_t           ret;
    status_t result = CT_SUCCESS;
    SYNC_POINT_GLOBAL_START(COLLECT_STATISTICS_INDEX_FAIL, &result, CT_ERROR);
    table = &entity->table;
    btree = (btree_t *)cm_push(session->stack, sizeof(btree_t));
    ret = memset_sp(btree, sizeof(btree_t), 0, sizeof(btree_t));
    knl_securec_check(ret);

    if (table->index_set.count == 0) {
        cm_pop(session->stack);
        return CT_SUCCESS;
    }

    for (i = 0; i < table->index_set.count; i++) {
        index = table->index_set.items[i];
        btree->index = index;
        stats_init_index_handler(session, &stats_idx, table_stats->estimate_sample_ratio);
        stats_idx.part_id = CT_INVALID_ID32;
        stats_idx.is_dynamic = table_stats->is_dynamic;
        stats_idx.index_no = i;
        stats_idx.mtrl.mtrl_table_ctx = mtrl_tab_ctx;
        stats_idx.mtrl.temp_seg_id = temp_seg;
        stats_idx.btree = btree;

        if (IS_PART_INDEX(index)) {
            if (stats_persist_empty_index_stats(session, &stats_idx, index, table_stats) != CT_SUCCESS) {
                mtrl_release_context(&stats_idx.mtrl.mtrl_ctx);
                cm_pop(session->stack);
                stats_internal_rollback(session, table_stats);
                return CT_ERROR;
            }
            continue;
        }

        if (table_stats->single_part_analyze && STATS_GLOBAL_CBO_STATS_EXIST(entity)) {
            continue;
        }

        if (stats_gather_index_entity(session, dc, index, &stats_idx, table_stats) != CT_SUCCESS) {
            mtrl_release_context(&stats_idx.mtrl.mtrl_ctx);
            cm_pop(session->stack);
            stats_internal_rollback(session, table_stats);
            return CT_ERROR;
        }
    
        mtrl_release_context(&stats_idx.mtrl.mtrl_ctx);
    }

    cm_pop(session->stack);
    stats_internal_commit(session, table_stats);
    SYNC_POINT_GLOBAL_END;
    return result;
}

static status_t stats_update_sys_column(knl_session_t *session, stats_col_handler_t *column_handler,
                                        bool32 is_dynamic)
{
    knl_cursor_t *cursor = column_handler->stats_cur;
    row_assist_t ra;
    knl_scan_key_t *key = NULL;
    uint16 size;
    knl_column_t *column = column_handler->column;

    CM_SAVE_STACK(session->stack);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_COLUMN_ID, IX_SYS_COLUMN_001_ID);
    key = &cursor->scan_range.l_key;
    knl_init_index_scan(cursor, CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, CT_TYPE_INTEGER, &column->uid, sizeof(uint32),
                     IX_COL_SYS_COLUMN_001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, CT_TYPE_INTEGER, &column->table_id, sizeof(uint32),
                     IX_COL_SYS_COLUMN_001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, CT_TYPE_INTEGER, &column->id, sizeof(uint32),
                     IX_COL_SYS_COLUMN_001_ID);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    if (cursor->eof) {
        CM_RESTORE_STACK(session->stack);
        CT_THROW_ERROR(ERR_OBJECT_ALREADY_DROPPED, column->name);
        return CT_ERROR;
    }

    cursor->update_info.count = STATS_SYS_COLUMN_COLUMN_COUNT;
    row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), STATS_SYS_COLUMN_COLUMN_COUNT);
    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, column_handler->dist_num));  // num distinct

    if (stats_put_result_value(&ra, &column_handler->min_value, column_handler->column->datatype) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    if (stats_put_result_value(&ra, &column_handler->max_value, column_handler->column->datatype) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    if (column_handler->hist_info.type == FREQUENCY) {
        (void)row_put_str(&ra, "FREQUENCY");
    } else {
        (void)row_put_str(&ra, "HEIGHT BALANCED");
    }

    for (uint32 i = 0; i < STATS_SYS_COLUMN_COLUMN_COUNT; i++) {
        cursor->update_info.columns[i] = i + STATS_SYS_COLUMN_COLUMN_NUM;
    }

    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, &size);

    if (knl_internal_update(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}

static void stats_calc_max_min_value(stats_col_handler_t *column_handler, uint32 fetch_count, uint32 last_rows)
{
    mtrl_cursor_t *mtrl_cur = &column_handler->mtrl.mtrl_cur;
    errno_t ret;
    uint32 len;

    len = STATS_GET_ROW_SIZE(mtrl_cur);
    if (len != CT_NULL_VALUE_LEN && len > STATS_MAX_BUCKET_SIZE) {
        len = STATS_MAX_BUCKET_SIZE;
    }

    /*
     * first sort column data order by asc, second we fetch column sorted data by asc,
     * so fisrt data is min value when num == 1
     */
    if (fetch_count == 1) {
        column_handler->min_value.len = len;
        column_handler->max_value.len = column_handler->min_value.len;

        if (len != 0 && len != CT_NULL_VALUE_LEN) {
            ret = memcpy_sp(column_handler->min_value.str, STATS_MAX_BUCKET_SIZE, STATS_GET_ROW_DATA(mtrl_cur), len);
            knl_securec_check(ret);
        }
    }

    /*
     * sort column data order by asc,for null data its len == 65535,
     * null data is sorted first for all sorted data,so it must be min value
     */
    if (len != CT_NULL_VALUE_LEN && fetch_count == last_rows) {
        column_handler->max_value.len = len;

        if (len != 0) {
            ret = memcpy_sp(column_handler->max_value.str, STATS_MAX_BUCKET_SIZE, STATS_GET_ROW_DATA(mtrl_cur), len);
            knl_securec_check(ret);
        }
    }
}

static uint64 stats_calc_high_hist_bucket(uint32 buck_id, uint32 row_count, uint16 bucket_size)
{
    uint64 end = ((uint64)row_count) * (buck_id + 1) / bucket_size;
    uint64 start = ((uint64)row_count) * buck_id / bucket_size;

    return end - start;
}

static void stats_generate_one_histgram(stats_col_handler_t *column_handler)
{
    mtrl_cursor_t *mtrl_cur = &column_handler->mtrl.mtrl_cur;
    text_t bucket;
    uint32 endpoint = 0;
    stats_hist_type_t type = column_handler->hist_info.type;
    uint32 hist_pos = column_handler->histgram.hist_num;
    stats_hist_entity_t *hist = &column_handler->histgram.hist[hist_pos];

    bucket.len = STATS_GET_ROW_SIZE(mtrl_cur);
    bucket.str = STATS_GET_ROW_DATA(mtrl_cur);

    if (bucket.len == CT_NULL_VALUE_LEN) {
        return;
    }

    column_handler->histgram.hist_num++;
    if (type == FREQUENCY && column_handler->simple_ratio > CT_REAL_PRECISION) {
        endpoint = (uint32)(column_handler->hist_info.endpoint / column_handler->simple_ratio);
    } else {
        endpoint = column_handler->hist_info.endpoint;
    }

    hist->endpoint = endpoint;
   
    if (bucket.len > STATS_MAX_BUCKET_SIZE) {
        bucket.len = STATS_MAX_BUCKET_SIZE;
    }

    if (bucket.len == 0) {
        hist->len = 0;
        return;
    }

    errno_t ret = memcpy_sp(&hist->bucket, bucket.len, bucket.str, bucket.len);
    knl_securec_check(ret);

    hist->len = bucket.len;
}

static status_t stats_generate_histgram(knl_session_t *session, stats_col_handler_t *column_handler,
                                        stats_table_t *table_stats, dc_entity_t *entity)
{
    bool32 is_report = table_stats->stats_option.is_report;

    if (is_report) {
        return stats_put_report_hist_value(session, column_handler, entity, table_stats);
    }

    if (stats_no_persistent(table_stats)) {
        if (cbo_load_tmptab_histgram(session, entity, table_stats->temp_table->table_cache->cbo_stats,
                                     column_handler) != CT_SUCCESS) {
            return CT_ERROR;
        }

        return CT_SUCCESS;
    }

    stats_generate_one_histgram(column_handler);
    return CT_SUCCESS;
}

static status_t stats_create_height_hist(knl_session_t *session, stats_col_handler_t *column_handler,
                                         stats_table_t *table_stats, dc_entity_t *entity)
{
    mtrl_context_t *ctx = &column_handler->mtrl.mtrl_ctx;
    mtrl_cursor_t *mtrl_cur = &column_handler->mtrl.mtrl_cur;
    uint32 real_rows = column_handler->total_rows - column_handler->null_num;
    uint32 bucket_id = 1;
    bool32 group_changed = CT_FALSE;
    uint64 buck_hwm;
    uint32 fetch_count = 0;
    uint16 bucket_size = column_handler->max_bucket_size;

    buck_hwm = stats_calc_high_hist_bucket(0, real_rows, bucket_size);
    column_handler->hist_info.type = HEIGHT_BALANCED;
    column_handler->hist_exits = CT_FALSE;

    do {
        if (mtrl_fetch_group(ctx, mtrl_cur, &group_changed) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (session->canceled) {
            CT_THROW_ERROR(ERR_OPERATION_CANCELED);
            return CT_ERROR;
        }

        if (session->killed) {
            CT_THROW_ERROR(ERR_OPERATION_KILLED);
            return CT_ERROR;
        }

        if (mtrl_cur->eof) {
            break;
        }

        if (STATS_GET_ROW_SIZE(mtrl_cur) == CT_NULL_VALUE_LEN) {
            continue;
        }

        fetch_count++;

        stats_calc_max_min_value(column_handler, fetch_count, real_rows);

        buck_hwm--;

        if (buck_hwm == 0) {
            column_handler->hist_info.endpoint = bucket_id;

            if (stats_generate_histgram(session, column_handler, table_stats, entity) != CT_SUCCESS) {
                return CT_ERROR;
            }
          
            buck_hwm += stats_calc_high_hist_bucket(bucket_id, real_rows, bucket_size);
            bucket_id++;
            column_handler->hist_info.bucket_num++;
        }
    } while (!mtrl_cur->eof);
    knl_panic(column_handler->hist_info.bucket_num == column_handler->max_bucket_size);
    return CT_SUCCESS;
}

static status_t stats_create_frequency_hist(knl_session_t *session, stats_col_handler_t *column_handler,
                                            stats_table_t *table_stats, dc_entity_t *entity)
{
    mtrl_cursor_t *mtrl_cur = &column_handler->mtrl.mtrl_cur;
    uint32 fetch_count = 0;
    uint32 last_fetch = column_handler->dist_num;
    column_handler->hist_info.type = FREQUENCY;

    do {
        if (stats_fetch_distinct(column_handler, CT_TRUE) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (session->canceled) {
            CT_THROW_ERROR(ERR_OPERATION_CANCELED);
            return CT_ERROR;
        }

        if (session->killed) {
            CT_THROW_ERROR(ERR_OPERATION_KILLED);
            return CT_ERROR;
        }

        if (mtrl_cur->eof) {
            break;
        }

        if (STATS_GET_ROW_SIZE(mtrl_cur) == CT_NULL_VALUE_LEN) {
            continue;
        }

        fetch_count++;

        stats_calc_max_min_value(column_handler, fetch_count, last_fetch);

        column_handler->hist_info.endpoint = STATS_GET_ENDPOINT(column_handler);
        column_handler->hist_info.prev_endpoint = column_handler->hist_info.endpoint;

        if (stats_generate_histgram(session, column_handler, table_stats, entity) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (STATS_GET_ROW_SIZE(mtrl_cur) != CT_NULL_VALUE_LEN) {
            column_handler->hist_info.bucket_num++;
            column_handler->hist_info.dnv_per_num = 0;
        }
    } while (!mtrl_cur->eof);

    return CT_SUCCESS;
}

static status_t stats_handler_distinct_values(knl_session_t *session, dc_entity_t *entity,
                                              stats_col_handler_t *column_handler, stats_table_t *table_stats)
{
    mtrl_context_t *ctx = &column_handler->mtrl.mtrl_ctx;
    mtrl_cursor_t *mtrl_cur = &column_handler->mtrl.mtrl_cur;
    knl_column_t *column = column_handler->column;
    uint16 max_bucket_size = column_handler->max_bucket_size;
    
    if (stats_calc_distinct_num(session, column_handler) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (table_stats->stats_option.is_report) {
        stats_write_report_col_header(column, column_handler, table_stats->stats_option.report_col_file,
            table_stats->part_stats.part_id);
    }
   
    if (mtrl_open_cursor(ctx, column_handler->mtrl.dist_seg_id, mtrl_cur) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (column_handler->dist_num > max_bucket_size) {
        // to handle high hist
        if (stats_create_height_hist(session, column_handler, table_stats, entity) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } else {
        // to handle frequency hist
        if (stats_create_frequency_hist(session, column_handler, table_stats, entity) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

status_t stats_write_sys_hist_head(knl_session_t *session, stats_col_handler_t *column_handler, stats_table_t *table_stats,
                                   uint32 part_id, bool32 is_subpart)
{
    stats_part_table_t *part_stats = &table_stats->part_stats;
    knl_cursor_t *cursor = column_handler->stats_cur;
    table_t *table = NULL;
    uint32 max_size = session->kernel->attr.max_row_size;
    row_assist_t ra;
    knl_column_t *column = column_handler->column;
    double density;
    cursor->rowid_no = 0;
    cursor->rowid_count = 0;
   
    if (stats_delete_histhead_by_column(session, cursor, column, table_stats, part_id, is_subpart) != CT_SUCCESS) {
        return CT_ERROR;
    }
    
    CM_SAVE_STACK(session->stack);
    stats_open_hist_abstr_cursor(session, cursor, CURSOR_ACTION_INSERT, CT_INVALID_ID32, column_handler->is_nologging);
    table = (table_t *)cursor->table;
    row_init(&ra, cursor->buf, max_size, table->desc.column_count);
    (void)row_put_int32(&ra, column->uid);
    (void)row_put_int32(&ra, column->table_id);
    (void)row_put_int32(&ra, column->id);
    (void)row_put_int32(&ra, column_handler->hist_info.bucket_num);
    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, column_handler->total_rows));
    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, column_handler->null_num));
    (void)row_put_int64(&ra, cm_now());

    if (stats_put_result_value(&ra, &column_handler->min_value, column_handler->column->datatype) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    if (stats_put_result_value(&ra, &column_handler->max_value, column_handler->column->datatype) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, column_handler->dist_num));

    if (column_handler->dist_num == 0) {
        density = 0;
    } else {
        density = (double)(1) / (double)(column_handler->dist_num);
    }

    (void)row_put_real(&ra, density);

    if (table_stats->is_part) {
        (void)row_put_int64(&ra, (uint64)part_id);
    } else {
        (void)row_put_null(&ra);
    }

    if (part_stats->is_subpart) {
        uint64 subpart = (part_id == CT_INVALID_ID32) ? CT_INVALID_ID32 : part_stats->sub_stats->part_id;
        (void)row_put_int64(&ra, subpart);
    } else {
        (void)row_put_null(&ra);
    }

    uint32 sample_size = (column_handler->simple_ratio < CT_REAL_PRECISION) ? column_handler->total_rows :
        (uint32)column_handler->total_rows * column_handler->simple_ratio;
    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, sample_size));
    (void)row_put_null(&ra);  // spare4 reserved

    if (knl_internal_insert(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}

status_t stats_persist_global_column_stats(knl_session_t *session, stats_col_handler_t *column_handler,
                                           stats_table_t *table_stats, dc_entity_t *entity)
{
    stats_part_table_t *part_stats = &table_stats->part_stats;
    if (stats_no_persistent(table_stats)) {
        if (cbo_load_tmptab_column_stats(session, entity, table_stats->temp_table->table_cache->cbo_stats,
            column_handler) != CT_SUCCESS) {
            return CT_ERROR;
        }

        return CT_SUCCESS;
    }

    if (part_stats->part_id == CT_INVALID_ID32 && !part_stats->is_subpart) {
        if (stats_update_sys_column(session, column_handler, table_stats->is_dynamic) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

status_t stats_update_sys_subtablepart(knl_session_t *session, table_part_t *table_sub, stats_table_info_t *tab_info,
                                       bool32 is_dynamic)
{
    knl_cursor_t *cursor = NULL;
    row_assist_t ra;
    knl_scan_key_t *key = NULL;
    uint16 size;

    if (stats_try_begin_auton_rm(session, is_dynamic) != CT_SUCCESS) {
        return CT_ERROR;
    }

    CM_SAVE_STACK(session->stack);
    cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_SUB_TABLE_PARTS_ID, IX_SYS_TABLESUBPART001_ID);
    key = &cursor->scan_range.l_key;
    knl_init_index_scan(cursor, CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, CT_TYPE_INTEGER, &table_sub->desc.uid, sizeof(uint32),
        IX_COL_SYS_TABLESUBPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, CT_TYPE_INTEGER, &table_sub->desc.table_id, sizeof(uint32),
        IX_COL_SYS_TABLESUBPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, CT_TYPE_INTEGER, &table_sub->desc.parent_partid, sizeof(uint32),
        IX_COL_SYS_TABLESUBPART001_PARENT_PART_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, CT_TYPE_INTEGER, &table_sub->desc.part_id, sizeof(uint32),
        IX_COL_SYS_TABLESUBPART001_SUB_PART_ID);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        stats_try_end_auton_rm(session, CT_ERROR, is_dynamic);
        return CT_ERROR;
    }

    if (cursor->eof) {
        CM_RESTORE_STACK(session->stack);
        CT_THROW_ERROR(ERR_OBJECT_ALREADY_DROPPED, table_sub->desc.name);
        stats_try_end_auton_rm(session, CT_ERROR, is_dynamic);
        return CT_ERROR;
    }

    cursor->update_info.count = STATS_SYS_TABLESUBPART_COLUMN_COUNT;
    row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), STATS_SYS_TABLESUBPART_COLUMN_COUNT);
    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, tab_info->rows));
    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, tab_info->blocks));
    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, tab_info->empty_block));
    (void)row_put_int32(&ra, tab_info->avg_row_len);
    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, tab_info->sample_size));
    tab_info->analyze_time = cm_now();
    (void)row_put_int64(&ra, tab_info->analyze_time);

    for (uint32 i = 0; i < STATS_SYS_TABLESUBPART_COLUMN_COUNT; i++) {
        cursor->update_info.columns[i] = i + STATS_SYS_TABLESUBPART_COLUMN_NUM;
    }

    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, &size);

    if (knl_internal_update(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        stats_try_end_auton_rm(session, CT_ERROR, is_dynamic);
        return CT_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    stats_try_end_auton_rm(session, CT_SUCCESS, is_dynamic);
    return CT_SUCCESS;
}

status_t stats_update_sys_tablepart(knl_session_t *session, knl_dictionary_t *dc, stats_table_t *tab_stats)
{
    knl_cursor_t *cursor = NULL;
    row_assist_t ra;
    knl_scan_key_t *key = NULL;
    uint16 size;
    bool8 is_report = tab_stats->stats_option.is_report;
    table_t *table = DC_TABLE(dc);
    table_part_t *table_part = TABLE_GET_PART(table, tab_stats->part_stats.part_no);

    if (is_report) {
        stats_write_report_tab_value(session, DC_ENTITY(dc), tab_stats, CT_TRUE);
        return CT_SUCCESS;
    }

    if (tab_stats->is_dynamic && tab_stats->stats_option.dynamic_type == STATS_COLUMNS) {
        return CT_SUCCESS;
    }

    if (stats_try_begin_auton_rm(session, tab_stats->is_dynamic) != CT_SUCCESS) {
        return CT_ERROR;
    }

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_TABLEPART_ID, IX_SYS_TABLEPART001_ID);
    key = &cursor->scan_range.l_key;
    knl_init_index_scan(cursor,
                        CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, CT_TYPE_INTEGER, &tab_stats->uid, sizeof(uint32),
                     IX_COL_SYS_TABLEPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, CT_TYPE_INTEGER, &tab_stats->tab_id, sizeof(uint32),
                     IX_COL_SYS_TABLEPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, CT_TYPE_INTEGER, &tab_stats->part_stats.part_id, sizeof(uint32),
                     IX_COL_SYS_TABLEPART001_PART_ID);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        stats_try_end_auton_rm(session, CT_ERROR, tab_stats->is_dynamic);
        return CT_ERROR;
    }

    if (cursor->eof) {
        CM_RESTORE_STACK(session->stack);
        CT_THROW_ERROR(ERR_OBJECT_ALREADY_DROPPED, table_part->desc.name);
        stats_try_end_auton_rm(session, CT_ERROR, tab_stats->is_dynamic);
        return CT_ERROR;
    }

    cursor->update_info.count = STATS_SYS_TABLE_COLUMN_COUNT;
    row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), STATS_SYS_TABLE_COLUMN_COUNT);
    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, tab_stats->part_stats.info.rows));
    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, tab_stats->part_stats.info.blocks));
    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, tab_stats->part_stats.info.empty_block));
    (void)row_put_int32(&ra, tab_stats->part_stats.info.avg_row_len);
    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, tab_stats->part_stats.info.sample_size));
    tab_stats->tab_info.analyze_time = cm_now();
    (void)row_put_int64(&ra, tab_stats->tab_info.analyze_time);

    for (uint32 i = 0; i < STATS_SYS_TABLE_COLUMN_COUNT; i++) {
        cursor->update_info.columns[i] = i + STATS_SYS_TABLEPART_COLUMN_NUM;
    }

    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, &size);

    if (knl_internal_update(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        stats_try_end_auton_rm(session, CT_ERROR, tab_stats->is_dynamic);
        return CT_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    stats_try_end_auton_rm(session, CT_SUCCESS, tab_stats->is_dynamic);
    return CT_SUCCESS;
}

void stats_estimate_column_stats(stats_table_t *table_stats, stats_col_handler_t *column_handler)
{
    double estimate_sample_ratio = 0;
    if (STATS_IS_ANALYZE_SINGLE_PART(table_stats, table_stats->part_stats.part_id)) {
        estimate_sample_ratio = table_stats->part_sample_ratio;
    } else {
        estimate_sample_ratio = table_stats->estimate_sample_ratio;
    }

    if (estimate_sample_ratio > CT_REAL_PRECISION) {
        column_handler->dist_num = stats_estimate_ndv(column_handler->dist_num, column_handler->total_rows,
                                                      estimate_sample_ratio);
        column_handler->total_rows = (uint32)(int32)(column_handler->total_rows / estimate_sample_ratio);
        column_handler->null_num = (uint32)(int32)(column_handler->null_num / estimate_sample_ratio);
    }
}

static status_t stats_update_sys_histhead(knl_session_t *session, stats_col_handler_t *column_handler,
    bool32 *global_exists, bool32 is_subpart)
{
    knl_cursor_t *cursor = column_handler->stats_cur;
    row_assist_t ra;
    knl_scan_key_t *key = NULL;
    uint16 size;
    knl_column_t *column = column_handler->column;
    uint64 part_id = CT_INVALID_ID32;
    double   density = 0;

    CM_SAVE_STACK(session->stack);
    stats_open_hist_abstr_cursor(session, cursor, CURSOR_ACTION_UPDATE, IX_HIST_HEAD_003_ID, column_handler->is_nologging);
    knl_init_index_scan(cursor, CT_TRUE);
    key = &cursor->scan_range.l_key;
    knl_set_scan_key(INDEX_DESC(cursor->index), key, CT_TYPE_INTEGER, &column->uid, sizeof(uint32),
        IX_COL_HIST_HEAD_003_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, CT_TYPE_INTEGER, &column->table_id, sizeof(uint32),
        IX_COL_HIST_HEAD_003_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, CT_TYPE_INTEGER, &column->id, sizeof(uint32),
        IX_COL_HIST_HEAD_003_COL_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, CT_TYPE_INTEGER, &part_id, sizeof(uint64),
        IX_COL_HIST_HEAD_003_SPARE1);
    if (is_subpart) {
        knl_set_scan_key(INDEX_DESC(cursor->index), key, CT_TYPE_INTEGER, &part_id, sizeof(uint64),
            IX_COL_HIST_HEAD_003_SPARE2);
    } else {
        knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_IS_NULL, IX_COL_HIST_HEAD_003_SPARE2);
    }
    
    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    if (cursor->eof) {
        CM_RESTORE_STACK(session->stack);
        *global_exists = CT_FALSE;
        return CT_SUCCESS;
    }

    row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), STATS_GLOBAL_HISTHEAD_COLUMNS);
    cursor->update_info.count = STATS_GLOBAL_HISTHEAD_COLUMNS;
    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, column_handler->total_rows));
    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, column_handler->null_num));
    (void)row_put_int64(&ra, cm_now());

    if (stats_put_result_value(&ra, &column_handler->min_value, column_handler->column->datatype) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    if (stats_put_result_value(&ra, &column_handler->max_value, column_handler->column->datatype) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, column_handler->dist_num));

    if (column_handler->dist_num == 0) {
        density = 0;
    } else {
        density = (double)(1) / (double)(column_handler->dist_num);
    }

    (void)row_put_real(&ra, density);
    uint32 sample_size = (column_handler->simple_ratio < CT_REAL_PRECISION) ? column_handler->total_rows :
        (uint32)column_handler->total_rows * column_handler->simple_ratio;
    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, sample_size));
    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, &size);
    cursor->update_info.columns[0] = HIST_HEAD_TOTAL_ROWS;
    cursor->update_info.columns[1] = HIST_HEAD_NULL_NUM;
    cursor->update_info.columns[2] = HIST_HEAD_ANALYZE_TIME;
    cursor->update_info.columns[3] = HIST_HEAD_LOW_VALUE;
    cursor->update_info.columns[4] = HIST_HEAD_HIGH_VALUE;
    cursor->update_info.columns[5] = HIST_HEAD_DIST_NUM;
    cursor->update_info.columns[6] = HIST_HEAD_DENSITY;
    cursor->update_info.columns[7] = HIST_HEAD_SAMPLE_SIZE;

    if (knl_internal_update(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}

void stats_set_global_extreme_value(stats_col_handler_t *col_handler, cbo_stats_column_t *col_stats)
{
    knl_column_t *column = col_handler->column;
    int32 result;
    errno_t        ret;

    result = stats_compare_data_ex(col_stats->low_value.str, col_stats->low_value.len,
        col_handler->min_value.str, col_handler->min_value.len, column);
    // if extreme_value of col_stats len is 0, it means the column no data,
    if (col_stats->low_value.len != CT_NULL_VALUE_LEN && col_stats->low_value.len != 0) {
        // if extreme_value of col_handler len is 65535(CT_NULL_VALUE_LEN), it means the analyzing column is no data,
        // so we need set extreme_value of other columns as global stats
        if (result < 0 || col_handler->min_value.len == CT_NULL_VALUE_LEN) {
            ret = memcpy_sp(col_handler->min_value.str, STATS_MAX_BUCKET_SIZE, col_stats->low_value.str,
                col_stats->low_value.len);
            knl_securec_check(ret);
            col_handler->min_value.len = col_stats->low_value.len;
        }
    }

    result = stats_compare_data_ex(col_stats->high_value.str, col_stats->high_value.len,
        col_handler->max_value.str, col_handler->max_value.len, column);

    if (col_stats->high_value.len != CT_NULL_VALUE_LEN && col_stats->high_value.len != 0) {
        // if extreme_value of col_handler len is 65535(CT_NULL_VALUE_LEN), it means the column no data,
        // so we need set extreme_value of other columns as global stats
        if (result > 0 || col_handler->max_value.len == CT_NULL_VALUE_LEN) {
            ret = memcpy_sp(col_handler->max_value.str, STATS_MAX_BUCKET_SIZE, col_stats->high_value.str,
                col_stats->high_value.len);
            knl_securec_check(ret);
            col_handler->max_value.len = col_stats->high_value.len;
        }
    }
}

void stats_set_global_col_stats(stats_col_handler_t *col_handler, cbo_stats_column_t *col_stats)
{
    col_handler->dist_num = col_handler->dist_num > col_stats->num_distinct ?
                            col_handler->dist_num : col_stats->num_distinct;
    col_handler->null_num = col_handler->null_num > col_stats->num_null ?
                            col_handler->null_num : col_stats->num_null;
    col_handler->total_rows = col_handler->total_rows > col_stats->total_rows ?
                              col_handler->total_rows : col_stats->total_rows;
    stats_set_global_extreme_value(col_handler, col_stats);
}

status_t stats_update_global_histhead(knl_session_t *session, stats_col_handler_t *column_handler,
                                      stats_table_t *table_stats, dc_entity_t *entity)
{
    knl_column_t *column = column_handler->column;
    cbo_stats_column_t *col_stats = NULL;
    part_table_t *part_table = NULL;
    uint32 total_rows = 0;
    uint32 dist_num = 0;
    uint32 null_num = 0;
    bool32 is_part_key = CT_FALSE;
    bool32 global_stats_exist = CT_TRUE;
    bool32 is_subpart = table_stats->part_stats.is_subpart;
    
    if (!table_stats->is_part) {
        return CT_SUCCESS;
    }

    if (!table_stats->single_part_analyze) {
        return CT_SUCCESS;
    }

    if (!STATS_GLOBAL_CBO_STATS_EXIST(entity)) {
        return CT_SUCCESS;
    }

    part_table = entity->table.part_table;
    for (uint32 i = 0; i < part_table->desc.partkeys; i++) {
        if (column->id == part_table->keycols[i].column_id) {
            is_part_key = CT_TRUE;
            break;
        }
    }

    for (uint32 i = 0; i < part_table->desc.partcnt; i++) {
        col_stats = knl_get_cbo_part_column(session, entity, i, column->id);
        if (col_stats == NULL) {
            continue;
        }

        if (i == table_stats->part_stats.part_no) {
            continue;
        }

        total_rows += col_stats->total_rows;
        null_num += col_stats->num_null;
        // if the column is part key, we only need to add up ndv
        if (is_part_key) {
            dist_num += col_stats->num_distinct;
        } else {
            if (dist_num < col_stats->num_distinct) {
                dist_num = col_stats->num_distinct;
            }
        }

        stats_set_global_extreme_value(column_handler, col_stats);
    }

    column_handler->total_rows += total_rows;
    column_handler->null_num += null_num;

    if (is_part_key) {
        column_handler->dist_num += dist_num;
    } else {
        column_handler->dist_num = (dist_num > column_handler->dist_num) ? dist_num : column_handler->dist_num;
    }

    col_stats = knl_get_cbo_column(session, entity, column->id);
    if (col_stats != NULL) {
        stats_set_global_col_stats(column_handler, col_stats);
    }
    
    if (stats_update_sys_histhead(session, column_handler, &global_stats_exist, is_subpart) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (!global_stats_exist) {
        if (stats_write_sys_hist_head(session, column_handler, table_stats, CT_INVALID_ID32,
            is_subpart) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static status_t stats_write_histgram(knl_session_t *session, knl_cursor_t *cursor, knl_column_t *column,
                                     stats_hist_entity_t *hist_entity, stats_table_t *table_stats)
{
    table_t *table = NULL;
    uint32 max_size = session->kernel->attr.max_row_size;
    row_assist_t ra;
    text_t bucket;
    uint32 endpoint = hist_entity->endpoint;
    stats_part_table_t *part_stats = &table_stats->part_stats;

    bucket.len = hist_entity->len;
    bucket.str = hist_entity->bucket;

    if (bucket.len == CT_NULL_VALUE_LEN) {
        return CT_SUCCESS;
    }
    stats_open_histgram_cursor(session, cursor, CURSOR_ACTION_INSERT, CT_INVALID_ID32, table_stats->is_nologging);
    table = (table_t *)cursor->table;
    row_init(&ra, cursor->buf, max_size, table->desc.column_count);
    (void)row_put_int32(&ra, column->uid);
    (void)row_put_int32(&ra, column->table_id);
    (void)row_put_int32(&ra, column->id);

    if (stats_put_result_value(&ra, &bucket, column->datatype) != CT_SUCCESS) {
        return CT_ERROR;
    }

    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, endpoint));

    if (table_stats->is_part) {
        (void)row_put_int32(&ra, table_stats->part_stats.part_id);
    } else {
        (void)row_put_null(&ra);
    }

    (void)row_put_null(&ra);  // epvalue to do
    if (part_stats->is_subpart) {
        (void)row_put_int64(&ra, part_stats->sub_stats->part_id);  // subpart id
    } else {
        (void)row_put_null(&ra);  // spare1 reserved
    }
    
    (void)row_put_null(&ra);  // spare2 reserved
    (void)row_put_null(&ra);  // spare3 reserved

    if (knl_internal_insert(session, cursor) != CT_SUCCESS) {
        return CT_ERROR;
    }

    session->stat->hists_inserts++;
    return CT_SUCCESS;
}

static status_t stats_update_histgram(knl_session_t *session, stats_col_handler_t *column_handler,
                                      stats_table_t *table_stats)
{
    stats_hists_t histgrams = column_handler->histgram;
    stats_hist_rowids_t *hist_rowids = column_handler->hist_rowids;
    knl_column_t *column = column_handler->column;
    row_assist_t ra;
    text_t bucket;
    uint16 size;
    stats_hist_type_t type = column_handler->hist_info.type;
    uint32 update_count = histgrams.hist_num > hist_rowids->bucket_num ? hist_rowids->bucket_num : histgrams.hist_num;
    uint32 new_count = (type == FREQUENCY) ? histgrams.hist_num : column_handler->max_bucket_size;
    knl_cursor_t *cursor = column_handler->stats_cur;
    stats_open_histgram_cursor(session, cursor, CURSOR_ACTION_UPDATE, CT_INVALID_ID32, column_handler->is_nologging);
    cursor->scan_mode = SCAN_MODE_ROWID;
    cursor->fetch = TABLE_ACCESSOR(cursor)->do_rowid_fetch;
    
    for (uint32 i = 0; i < update_count; i++) {
        cursor->rowid_no = STATS_ROWID_NO;
        cursor->rowid_count = STATS_ROWID_COUNT;
        cursor->rowid_array[STATS_ROWID_NO] = hist_rowids->rowid_list[i];
        
        if (knl_fetch(session, cursor) != CT_SUCCESS) {
            return CT_ERROR;
        }

        hist_rowids->curr_bucket++;

        if (cursor->eof) {
            continue;
        }

        bucket.len = histgrams.hist[i].len;
        bucket.str = histgrams.hist[i].bucket;
        cursor->update_info.count = STATS_UPDATE_SYS_HIST_COUNT;
        row_init(&ra, cursor->update_info.data, DEFAULT_PAGE_SIZE(session), STATS_UPDATE_SYS_HIST_COUNT);

        cursor->update_info.columns[0] = HIST_EP_VALUE;
        cursor->update_info.columns[1] = HIST_EP_NUM;

        if (stats_put_result_value(&ra, &bucket, column->datatype) != CT_SUCCESS) {
            return CT_ERROR;
        }

        (void)row_put_int32(&ra, MIN(CT_MAX_INT32, histgrams.hist[i].endpoint));
        cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, &size);

        if (knl_internal_update(session, cursor) != CT_SUCCESS) {
            return CT_ERROR;
        }

        session->stat->hists_updates++;
    }
    cursor->rowid_no = 0;
    cursor->rowid_count = 0;
    for (uint32 i = update_count; i < new_count; i++) {
        if (stats_write_histgram(session, cursor, column, &histgrams.hist[i], table_stats) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static status_t stats_clean_all_histgrams(knl_session_t *session, stats_col_handler_t *column_handler,
                                          stats_table_t *table_stats)
{
    knl_column_t *column = column_handler->column;
    knl_cursor_t *cursor = column_handler->stats_cur;
    bool32 is_subpart = table_stats->part_stats.is_subpart;
    knl_part_locate_t part_loc;

    if (IS_ANALYZE_ALL_PARTS(table_stats)) {
        if (stats_delete_histgrams(session, cursor, column, table_stats->is_dynamic,
            column_handler->is_nologging) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } else {
        if (is_subpart) {
            part_loc.part_no = table_stats->part_stats.part_id;
            part_loc.subpart_no = table_stats->part_stats.sub_stats->part_id;
            if (stats_delete_histgram_subpart_column(session, cursor, column, part_loc,
                column_handler->is_nologging) != CT_SUCCESS) {
                return CT_ERROR;
            }
        } else {
            if (stats_delete_histgram_part_column(session, cursor, column,
                table_stats->part_stats.part_id, column_handler->is_nologging) != CT_SUCCESS) {
                return CT_ERROR;
            }
        }
    }

    return CT_SUCCESS;
}

static status_t stats_persit_histgram(knl_session_t *session, stats_col_handler_t *column_handler,
                                      stats_table_t *table_stats)
{
    stats_hists_t histgram = column_handler->histgram;
    knl_column_t *column = column_handler->column;
    knl_cursor_t *cursor = column_handler->stats_cur;

    /*
    * total rows is 0,it means data of table is deleted totally,we need to
    * delete old histgrams last time
    */
    if (column_handler->total_rows == 0) {
        /* if part_id != CT_INVALID32 ,it means to gather one part statistics */
        if (stats_clean_all_histgrams(session, column_handler, table_stats) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (stats_check_histgram_exist(session, column_handler, table_stats) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (column_handler->hist_exits) {
        /* update + insert/delete */
        if (stats_get_old_buckets(session, column_handler, table_stats) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (stats_update_histgram(session, column_handler, table_stats) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (stats_delete_old_histgram(session, cursor, column_handler->hist_rowids, table_stats) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } else {
        /* insert new histgrams */
        for (uint32 i = 0; i < histgram.hist_num; i++) {
            if (stats_write_histgram(session, cursor, column, &histgram.hist[i], table_stats) != CT_SUCCESS) {
                return CT_ERROR;
            }
        }
    }

    return CT_SUCCESS;
}

static status_t stats_persist_column_stats(knl_session_t *session, stats_col_handler_t *column_handler,
                                           stats_table_t *table_stats, dc_entity_t *entity)
{
    bool32 is_report = table_stats->stats_option.is_report;
    stats_hist_rowids_t hist_rowids;
    errno_t ret;
    bool32 is_subpart = table_stats->part_stats.is_subpart;

    ret = memset_sp(&hist_rowids, sizeof(stats_hist_rowids_t), 0, sizeof(stats_hist_rowids_t));
    knl_securec_check(ret);
    column_handler->hist_rowids = &hist_rowids;

    stats_estimate_column_stats(table_stats, column_handler);

    if (is_report) {
        stats_write_report_col_tail(session, column_handler, entity, table_stats);
        return CT_SUCCESS;
    }

    if (!stats_no_persistent(table_stats)) {
        if (stats_persit_histgram(session, column_handler, table_stats) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (stats_write_sys_hist_head(session, column_handler, table_stats, table_stats->part_stats.part_id,
                                      is_subpart) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (stats_update_global_histhead(session, column_handler, table_stats, entity) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    status_t result = stats_persist_global_column_stats(session, column_handler, table_stats, entity);
    if (result != CT_SUCCESS) {
        return CT_ERROR;
    }

    SYNC_POINT_GLOBAL_START(COLLECT_STATISTICS_PERSISTENCE_THROUGH_RESULT_FAIL, &result, CT_ERROR);
    SYNC_POINT_GLOBAL_END;
    return result;
}

static status_t stats_parall_persist_stats(knl_session_t *session, stats_par_ctrl_t *ctrl)
{
    stats_col_handler_t *column_handler = NULL;
    stats_par_context_t *par_ctx = NULL;
    stats_tab_context_t *tab_ctx = ctrl->tab_ctx;
    dc_entity_t *entity = ctrl->entity;

    for (uint32 i = 0; i < CT_MAX_STATS_PARALL_THREADS; i++) {
        uint16 id = ctrl->par_thread_queue.id_list[i];

        if (id == CT_INVALID_ID16) {
            continue;
        }

        par_ctx = &ctrl->par_ctx[id];
        if (par_ctx->thread.closed || par_ctx->thread.result == CT_ERROR) {
            return CT_ERROR;
        }
        column_handler = par_ctx->col_ctx.col_handler;
        if (stats_persist_column_stats(session, column_handler, tab_ctx->table_stats, entity) != CT_SUCCESS) {
            par_ctx->thread.result = CT_ERROR;
            par_ctx->thread.closed = CT_TRUE;
            return CT_ERROR;
        }
        ctrl->finish_count++;
        par_ctx->is_wait = CT_FALSE;
    }

    errno_t ret = memset_sp(&ctrl->par_thread_queue.id_list, sizeof(uint16) * CT_MAX_STATS_PARALL_THREADS, 0xFF,
                            sizeof(uint16) * CT_MAX_STATS_PARALL_THREADS);
    knl_securec_check(ret);
    ctrl->par_thread_queue.pos = 0;
    ctrl->sort_finished = CT_FALSE;
    return CT_SUCCESS;
}

static status_t stats_gather_one_column(knl_session_t *session, stats_col_context_t *col_ctx,
                                        stats_tab_context_t *tab_ctx, dc_entity_t *entity)
{
    stats_table_t *table_stats = tab_ctx->table_stats;
    stats_col_handler_t *column_handler = col_ctx->col_handler;

    stats_init_column_handler(session, column_handler, col_ctx, tab_ctx);

    if (stats_create_distinct_values(session, column_handler) != CT_SUCCESS) {
        mtrl_release_context(&column_handler->mtrl.mtrl_ctx);
        return CT_ERROR;
    }

    if (stats_handler_distinct_values(session, entity, column_handler, table_stats) != CT_SUCCESS) {
        mtrl_release_context(&column_handler->mtrl.mtrl_ctx);
        return CT_ERROR;
    }

    mtrl_release_context(&column_handler->mtrl.mtrl_ctx);
    return CT_SUCCESS;
}

status_t stats_alloc_vm(knl_handle_t handle, mtrl_page_t **page, stats_vm_list *vm_list)
{
    knl_session_t *session = (knl_session_t *)handle;
    uint32 vmid;
    vm_page_t *vm_page = NULL;

    if (vm_alloc(session, session->temp_pool, &vmid) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (vm_open(session, session->temp_pool, vmid, &vm_page) != CT_SUCCESS) {
        vm_free(session, session->temp_pool, vmid);
        return CT_ERROR;
    }

    *page = (mtrl_page_t *)vm_page->data;
    mtrl_init_page(*page, vmid);

    for (uint32 i = 0; i < STATS_PARALL_MAX_VM_PAGES; i++) {
        if (vm_list->id_list[i] == CT_INVALID_ID32) {
            vm_list->id_list[i] = vmid;
            break;
        }
    }

    return CT_SUCCESS;
}

void stats_close_vms(knl_handle_t session, stats_vm_list *vm_list)
{
    knl_session_t *se = (knl_session_t *)session;
    uint32 vmid = 0;

    for (uint32 i = 0; i < STATS_PARALL_MAX_VM_PAGES; i++) {
        vmid = vm_list->id_list[i];
        if (vmid != CT_INVALID_ID32) {
            vm_close_and_free(se, se->temp_pool, vmid);
        }
    }
}

void *stats_push_stack_from_vm(mtrl_page_t *page, uint32 size)
{
    char *ptr = NULL;

    if (page->free_begin + size > CT_VMEM_PAGE_SIZE) {
        return NULL;
    }

    ptr = ((char *)page + page->free_begin);
    page->rows++;
    page->free_begin += size;
    return ptr;
}

status_t stats_push_cursor_from_vm(knl_handle_t handle, stats_vm_list *vm_list, knl_cursor_t **cursor)
{
    knl_session_t *session = (knl_session_t *)handle;
    char *ext_buf = NULL;
    uint32 ext_size;
    mtrl_page_t *page = NULL;

    if (stats_alloc_vm(handle, &page, vm_list) != CT_SUCCESS) {
        return CT_ERROR;
    }

    *cursor = (knl_cursor_t *)stats_push_stack_from_vm(page, session->kernel->attr.cursor_size);
    knl_panic_log(*cursor != NULL, "cursor is NULL.");

    /* 2 pages, one is for cursor->row, one is for cursor->page_buf */
    ext_buf = (*cursor)->buf + 2 * DEFAULT_PAGE_SIZE(session);
    ext_size = session->kernel->attr.max_column_count * sizeof(uint16);
    (*cursor)->offsets = (uint16 *)ext_buf;
    (*cursor)->lens = (uint16 *)(ext_buf + ext_size);

    (*cursor)->update_info.columns = (uint16 *)stats_push_stack_from_vm(page, ext_size);
    knl_panic_log((*cursor)->update_info.columns != NULL,
                  "update_info's columns is NULL, panic info: page %u-%u type %u table %s index %s",
                  (*cursor)->rowid.file, (*cursor)->rowid.page, ((page_head_t *)(*cursor)->page_buf)->type,
                  ((table_t *)(*cursor)->table)->desc.name, ((index_t *)(*cursor)->index)->desc.name);

    (*cursor)->update_info.offsets = (uint16 *)stats_push_stack_from_vm(page, ext_size);
    knl_panic_log((*cursor)->update_info.offsets != NULL,
                  "update_info's offsets is NULL, panic info: page %u-%u type %u table %s index %s",
                  (*cursor)->rowid.file, (*cursor)->rowid.page, ((page_head_t *)(*cursor)->page_buf)->type,
                  ((table_t *)(*cursor)->table)->desc.name, ((index_t *)(*cursor)->index)->desc.name);

    (*cursor)->update_info.lens = (uint16 *)stats_push_stack_from_vm(page, ext_size);
    knl_panic_log((*cursor)->update_info.lens != NULL,
                  "update_info's lens is NULL, panic info: page %u-%u type %u table %s index %s",
                  (*cursor)->rowid.file, (*cursor)->rowid.page, ((page_head_t *)(*cursor)->page_buf)->type,
                  ((table_t *)(*cursor)->table)->desc.name, ((index_t *)(*cursor)->index)->desc.name);

    KNL_INIT_CURSOR(*cursor);

    return CT_SUCCESS;
}

status_t stats_alloc_mem_from_vm(knl_handle_t handle, stats_vm_list *vm_list, char **ptr, uint32 size)
{
    uint32 ext_size = CM_ALIGN8(size);
    mtrl_page_t *page = NULL;

    if (stats_alloc_vm(handle, &page, vm_list) != CT_SUCCESS) {
        return CT_ERROR;
    }

    *ptr = stats_push_stack_from_vm(page, ext_size);
    return CT_SUCCESS;
}

knl_column_t *stats_get_column_fron_queue(stats_cols_list_t *spec_list, dc_entity_t *entity)
{
    uint16 col_id = 0;
    knl_column_t *column = NULL;

    while (spec_list->pos != spec_list->column_count) {
        col_id = spec_list->col_list[spec_list->pos];
        column = dc_get_column(entity, col_id);
        if (KNL_COLUMN_INVISIBLE(column)) {
            column = NULL;
            spec_list->pos++;
            continue;
        }

        if (COLUMN_IS_LOB(column)) {
            column = NULL;
            spec_list->pos++;
            continue;
        }

        spec_list->pos++;
        break;
    }

    return column;
}

static inline void stats_record_alive_thread(stats_par_ctrl_t *ctrl, bool32 is_add)
{
    cm_spin_lock(&ctrl->read_lock, NULL);
    if (is_add) {
        ctrl->alive_threads++;
    } else {
        ctrl->alive_threads--;
    }
    cm_spin_unlock(&ctrl->read_lock);
}

static inline void stats_sorted_threads_enqueue(stats_par_ctrl_t *ctrl, stats_par_context_t *par_ctx)
{
    cm_spin_lock(&ctrl->read_lock, NULL);
    ctrl->sort_count++;
    ctrl->par_thread_queue.id_list[ctrl->par_thread_queue.pos] = par_ctx->id;
    ctrl->par_thread_queue.pos++;
    cm_spin_unlock(&ctrl->read_lock);
}

void stats_parallel_proc(thread_t *thread)
{
    stats_par_context_t *par_ctx = (stats_par_context_t *)thread->argument;
    stats_par_ctrl_t *ctrl = (stats_par_ctrl_t *)par_ctx->par_ctrl;
    knl_session_t *session = ctrl->session;
    stats_tab_context_t *tab_ctx = ctrl->tab_ctx;
    dc_entity_t *entity = ctrl->entity;
    thread->result = CT_SUCCESS;

    while (!thread->closed) {
        /* parallel statistics failed or all columns finished sorted,we must stop thread to work */
        if (!ctrl->parall_success || ctrl->all_finished) {
            stats_record_alive_thread(ctrl, CT_FALSE);
            return;
        }

        /* when all columns has sorted or sorted queue is full, we must set this tag
         * for informing main thread starting writing sys tables
         */
        if (ctrl->sort_finished) {
            continue;
        }

        cm_spin_lock(&ctrl->read_lock, NULL);
        /* sorted queue is full,we should stop sorting and start writing sys tables */
        if (ctrl->all_thread_ready && ctrl->par_thread_queue.pos == ctrl->thread_count) {
            ctrl->sort_finished = CT_TRUE;
            cm_spin_unlock(&ctrl->read_lock);
            continue;
        }

        /* thread has finished sorting and in sorted queue,it must wait untildevelop_cse_b180_kernel_cleancode1
         * the main thread writing sys tables finished
         */
        if (par_ctx->is_wait) {
            cm_spin_unlock(&ctrl->read_lock);
            continue;
        }

        knl_column_t *column = stats_get_column_fron_queue(ctrl->col_list, entity);

        /* all columns has sorted or are sorting */
        if (ctrl->col_list->pos == ctrl->col_list->column_count) {
            ctrl->all_finished = CT_TRUE;
            ctrl->sort_finished = CT_TRUE;
        }

        if (column == NULL) {
            cm_spin_unlock(&ctrl->read_lock);
            continue;
        }

        par_ctx->col_ctx.column = column;
        cm_spin_unlock(&ctrl->read_lock);

        if (stats_gather_one_column(session, &par_ctx->col_ctx, tab_ctx, entity) != CT_SUCCESS) {
            ctrl->parall_success = CT_FALSE;
            stats_record_alive_thread(ctrl, CT_FALSE);
            thread->result = CT_ERROR;
            thread->closed = CT_TRUE;
            return;
        }

        par_ctx->is_wait = CT_TRUE;
        stats_sorted_threads_enqueue(ctrl, par_ctx);
    }
}

status_t stats_parallel_proc_clean(knl_session_t *session, stats_par_ctrl_t *ctrl)
{
    status_t status = CT_SUCCESS;

    while (!ctrl->parall_success) {
        if (ctrl->alive_threads == 0) {
            break;
        }
        
        if (session->killed || session->canceled) {
            break;
        }
        continue;
    }

    for (uint32 i = 0; i < ctrl->thread_count; i++) {
        cm_close_thread(&ctrl->par_ctx[i].thread);
        if (ctrl->par_ctx[i].thread.result != CT_SUCCESS) {
            status = CT_ERROR;
            CT_THROW_ERROR(ERR_FAILED_PARALL_GATHER_STATS);
            continue;
        }
    }

    return status;
}

void stats_estimate_radio_by_type(knl_session_t *session, stats_table_t *stats_table, uint64 default_sample_size,
                                  uint64 estimate_blocks, uint64 specify_part_esti_blocks)
{
    knl_analyze_type_t sample_type = stats_table->stats_option.analyze_type;

    switch (sample_type) {
        case STATS_AUTO_SAMPLE:
            /*
                * eg: analyze table hzy_hist compute statistics or use dbe_stats.auto_sample_size to analyze table;
                * it does not set sample_ratio obviously, sample_ratio is set 0 default,
                * we need judge size of table is beyond default sample size(128M) or not
                */
            if (estimate_blocks * DEFAULT_PAGE_SIZE(session) > default_sample_size) {
                stats_table->estimate_sample_ratio = ((double)default_sample_size) /
                                                     (estimate_blocks * DEFAULT_PAGE_SIZE(session));
            }

            if (specify_part_esti_blocks * DEFAULT_PAGE_SIZE(session) > default_sample_size) {
                stats_table->part_sample_ratio = ((double)default_sample_size) /
                                                 (specify_part_esti_blocks * DEFAULT_PAGE_SIZE(session));
            }

            break;

        case STATS_DEFAULT_SAMPLE:
            /*
            * eg: exec DBE_STATS.COLLECT_TABLE_STATS('SYS', 'HZY_HIGH_HIST'); is does not set sample_ratio obviously,
            * sample_ratio is set 0.1 default,we need judge size of table is beyond default sample size(128M) or not
            */
            if (estimate_blocks * DEFAULT_PAGE_SIZE(session) < default_sample_size) {
                stats_table->estimate_sample_ratio = STATS_FULL_TABLE_SAMPLE_RATIO;
            }

            if (specify_part_esti_blocks * DEFAULT_PAGE_SIZE(session) < default_sample_size) {
                stats_table->part_sample_ratio = STATS_FULL_TABLE_SAMPLE_RATIO;
            }

            break;

        case STATS_SPECIFIED_SAMPLE:
            break;
        default:
            break;
    }
}

void stats_force_estimate_sample_ratio(knl_session_t *session, stats_table_t *stats_table, uint64 estimate_blocks,
                                       uint64 specify_part_blocks)
{
    uint64 default_sample_size = session->kernel->attr.stats_sample_size;
    double ori_sample_ratio = stats_table->estimate_sample_ratio;

    if (ori_sample_ratio < CT_REAL_PRECISION) {
        stats_table->estimate_sample_ratio = ((double)default_sample_size) /
                                                          (estimate_blocks * DEFAULT_PAGE_SIZE(session));

        if (specify_part_blocks * DEFAULT_PAGE_SIZE(session) > default_sample_size) {
            stats_table->part_sample_ratio = ((double)default_sample_size) /
                                                          (specify_part_blocks * DEFAULT_PAGE_SIZE(session));
        }
    } else {
        stats_table->estimate_sample_ratio = ((double)default_sample_size) /
                                                          (estimate_blocks * DEFAULT_PAGE_SIZE(session));

        if (specify_part_blocks * ori_sample_ratio * DEFAULT_PAGE_SIZE(session) > default_sample_size) {
            stats_table->part_sample_ratio = ((double)default_sample_size) /
                                                          (specify_part_blocks * DEFAULT_PAGE_SIZE(session));
        }
    }
}

uint32 stats_get_pages_from_subparts(knl_session_t *session, knl_dictionary_t *dc, table_part_t *table_part)
{
    table_t *table = DC_TABLE(dc);
    table_part_t *sub_part = NULL;
    uint32 estimate_blocks = 0;
    uint32 extents = 0;

    for (uint32 i = 0; i < table_part->desc.subpart_cnt; i++) {
        sub_part = PART_GET_SUBENTITY(table->part_table, table_part->subparts[i]);
        if (sub_part == NULL) {
            continue;
        }

        if (!sub_part->heap.loaded) {
            if (dc_load_table_part_segment(session, dc->handle, (table_part_t *)sub_part) != CT_SUCCESS) {
                CT_LOG_RUN_WAR("[DC] could not load table partition %s of table %s.%s, segment corrupted",
                    sub_part->desc.name, session->kernel->dc_ctx.users[table->desc.uid]->desc.name,
                    table->desc.name);
                cm_reset_error();
                continue;
            }
        }

        estimate_blocks += stats_get_table_part_pages(session, sub_part, &extents);
    }

    return estimate_blocks;
}

uint32 stats_get_pages_from_tablepart(knl_session_t *session, knl_dictionary_t *dc, table_part_t *table_part)
{
    table_t *table = DC_TABLE(dc);
    uint32 estimate_blocks = 0;
    uint32 extents = 0;

    if (!table_part->heap.loaded) {
        if (dc_load_table_part_segment(session, dc->handle, table_part) != CT_SUCCESS) {
            CT_LOG_RUN_WAR("[DC] could not load table partition %s of table %s.%s, segment corrupted",
                table_part->desc.name, session->kernel->dc_ctx.users[table->desc.uid]->desc.name,
                table->desc.name);
            cm_reset_error();
            return estimate_blocks;
        }
    }

    estimate_blocks = stats_get_table_part_pages(session, table_part, &extents);
    return estimate_blocks;
}

void stats_estimate_sample_ratio(knl_session_t *session, knl_dictionary_t *dc, stats_table_t *stats_table,
                                 bool32 force_sample)
{
    table_t *table = DC_TABLE(dc);
    double ori_sample_ratio = stats_table->estimate_sample_ratio;
    uint64 default_sample_size = session->kernel->attr.stats_sample_size;
    uint64 estimate_blocks = 0;
    uint64 specify_part_blocks = 0;
    part_table_t *part_table = NULL;
    table_part_t *table_part = NULL;
    uint32 extents_count = 0;

    if (IS_PART_TABLE(table)) {
        part_table = table->part_table;

        for (uint32 i = 0; i < part_table->desc.partcnt; i++) {
            table_part = TABLE_GET_PART(table, i);
            if (!IS_READY_PART(table_part)) {
                continue;
            }
            /*
            * if we analyze one part using DBMS package,such as
            * DBE_STATS.COLLECT_TABLE_STATS
            * (
            *  'HZY_PSTATS1',              //USER NAME
            *  'STATS_INTERVAL_NEW',       //TABLE NAME
            *  'PART_H1',                  //PART NAME
            *  30                          //SAMPLE RATIO
            *  )
            * we should estimate blocks of one partition specified for calculate number of sample blocks.
            */
            if (IS_PARENT_TABPART(&table_part->desc)) {
                if (STATS_IS_ANALYZE_SINGLE_PART(stats_table, table_part->desc.part_id)) {
                    specify_part_blocks = stats_get_pages_from_subparts(session, dc, table_part);
                }

                estimate_blocks += stats_get_pages_from_subparts(session, dc, table_part);
            } else {
                if (STATS_IS_ANALYZE_SINGLE_PART(stats_table, table_part->desc.part_id)) {
                    specify_part_blocks = stats_get_pages_from_tablepart(session, dc, table_part);
                }

                estimate_blocks += stats_get_pages_from_tablepart(session, dc, table_part);
            }
        }
    } else {
        estimate_blocks = stats_get_table_pages(session, table, &extents_count);
    }

    if (estimate_blocks == 0) {
        return;
    }
    /*
     * if set STATS_FORCE_SAMPLE to true, it means max sample size is default_sample_size that it is
     * STATISTICS_SAMPLE_SIZE in params no matter how much the sampling rate is set.If size of table
     * is less default_sample_size, we use sampling rate of the user set,otherwise sample default_sample_size
     * to generate statistics
     */
    if (force_sample) {
        if (ori_sample_ratio < CT_REAL_PRECISION) {
            if (estimate_blocks * DEFAULT_PAGE_SIZE(session) > default_sample_size) {
                stats_force_estimate_sample_ratio(session, stats_table, estimate_blocks, specify_part_blocks);
                return;
            }
        }

        if (estimate_blocks * ori_sample_ratio * DEFAULT_PAGE_SIZE(session) > default_sample_size) {
            stats_force_estimate_sample_ratio(session, stats_table, estimate_blocks, specify_part_blocks);
            return;
        }
    }

    stats_estimate_radio_by_type(session, stats_table, default_sample_size, estimate_blocks, specify_part_blocks);
}

void stats_add_columns_list(stats_cols_list_t *columns_list, uint16 col_id)
{
    for (uint32 j = 0; j < columns_list->max_count; j++) {
        if (columns_list->col_list[j] == col_id) {
            break;
        }

        if (columns_list->col_list[j] == CT_INVALID_ID16) {
            columns_list->col_list[j] = col_id;
            columns_list->column_count++;
            break;
        }
    }
}

void stats_add_func_idx_columns(index_t *idx, stats_cols_list_t *idx_columns, uint32 icol_pos)
{
    knl_icol_info_t *icol_info = NULL;
    uint16 col_id = 0;

    icol_info = (knl_icol_info_t *)(idx->desc.columns_info + icol_pos);

    for (uint16 j = 0; j < icol_info->arg_count; j++) {
        col_id = icol_info->arg_cols[j];
        stats_add_columns_list(idx_columns, col_id);
    }
}

void stats_get_idx_columns(index_t *idx, stats_cols_list_t *idx_columns)
{
    uint16 col_id = 0;
   
    if (idx->desc.is_func) {
        for (uint32 i = 0; i < idx->desc.column_count; i++) {
            col_id = idx->desc.columns[i];

            if (col_id < DC_VIRTUAL_COL_START) {
                stats_add_columns_list(idx_columns, col_id);
                continue;
            }
 
            stats_add_func_idx_columns(idx, idx_columns, i);
        }
    } else {
        for (uint32 i = 0; i < idx->desc.column_count; i++) {
            col_id = idx->desc.columns[i];
            stats_add_columns_list(idx_columns, col_id);
        }
    }
}

void  stats_generate_all_cols_list(dc_entity_t *entity, stats_cols_list_t *col_list)
{
    knl_column_t *column = NULL;

    for (uint32 i = 0; i < entity->column_count; i++) {
        column = dc_get_column(entity, i);
        col_list->col_list[i] = column->id;
        col_list->column_count++;
    }
}

void  stats_generate_idx_cols_list(dc_entity_t *entity, stats_cols_list_t *col_list)
{
    table_t      *table = &entity->table;
    index_t      *idx = NULL;

    for (uint32 i = 0; i < table->index_set.total_count; i++) {
        idx = table->index_set.items[i];
        stats_get_idx_columns(idx, col_list);
    }
}

void  stats_generate_specified_cols_list(dc_entity_t *entity, stats_cols_list_t *col_list,
                                         stats_table_t *table_stats, bool32 with_index_cols)
{
    table_t      *table = &entity->table;
    index_t      *idx = NULL;
    knl_stats_specified_cols *specified_cols = table_stats->stats_option.specify_cols;
    uint32 col_id;

    for (uint32 i = 0; i < specified_cols->cols_count; i++) {
        col_id = specified_cols->specified_cols[i];
        stats_add_columns_list(col_list, col_id);
    }

    if (!with_index_cols) {
        return;
    }

    for (uint32 i = 0; i < table->index_set.total_count; i++) {
        idx = table->index_set.items[i];
        stats_get_idx_columns(idx, col_list);
    }
}

void stats_generate_columns_list(dc_entity_t *entity, stats_table_t *table_stats, stats_method_opt_type_t method_opt,
                                 stats_cols_list_t *col_list)
{
    switch (method_opt) {
        case FOR_ALL_COLUMNS:
            stats_generate_all_cols_list(entity, col_list);
            break;
        case FOR_ALL_INDEX_COLUMNS:
            stats_generate_idx_cols_list(entity, col_list);
            break;
        case FOR_SPECIFIED_COLUMNS:
            stats_generate_specified_cols_list(entity, col_list, table_stats, CT_FALSE);
            break;
        case FOR_SPECIFIED_INDEXED_COLUMNS:
            stats_generate_specified_cols_list(entity, col_list, table_stats, CT_TRUE);
            break;
        default:
            stats_generate_all_cols_list(entity, col_list);
            break;
    }
}

void stats_init_columns_list(knl_session_t *session, stats_cols_list_t *column_list)
{
    column_list->max_count = session->kernel->attr.max_column_count;
    column_list->column_count = 0;
    column_list->pos = 0;
    column_list->col_list = NULL;
}

void stats_init_column_context(knl_session_t *session, stats_col_context_t *col_ctx)
{
    knl_cursor_t *cursor = NULL;
    errno_t ret = memset_sp(col_ctx, sizeof(stats_col_context_t), 0, sizeof(stats_col_context_t));
    knl_securec_check(ret);

    stats_col_handler_t *column_handler = (stats_col_handler_t *)cm_push(session->stack, sizeof(stats_col_handler_t));
    cursor = knl_push_cursor(session);
    col_ctx->col_handler = column_handler;
    col_ctx->stats_cur = cursor;
}

status_t stats_normal_gather_columns(knl_session_t *session, dc_entity_t *entity, stats_tab_context_t *tab_ctx,
                                     stats_cols_list_t *column_list)
{
    uint16 col_id;
    knl_column_t *column = NULL;
    stats_col_context_t col_ctx;

    CM_SAVE_STACK(session->stack);
    stats_init_column_context(session, &col_ctx);

    for (uint32 i = 0; i < column_list->column_count; i++) {
        col_id = column_list->col_list[i];
        column = dc_get_column(entity, col_id);
        if (KNL_COLUMN_INVISIBLE(column)) {
            continue;
        }

        if (COLUMN_IS_LOB(column)) {
            continue;
        }

        col_ctx.column = column;

        if (stats_gather_one_column(session, &col_ctx, tab_ctx, entity) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }

        if (stats_persist_column_stats(session, col_ctx.col_handler, tab_ctx->table_stats, entity) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}

status_t stats_wait_persist_end(knl_session_t *session, stats_par_ctrl_t *ctrl)
{
    status_t status = CT_SUCCESS;

    while (CT_TRUE) {
        if (session->killed || session->canceled) {
            ctrl->parall_success = CT_FALSE;
            status = CT_ERROR;
            break;
        }
        /*
         * when tag of sort_finished is true and the number of alive threads is 0, there may be a situation that the
         * last thread has finished sort and exited, but the statistics is not persist. So we need to persist statistics
         * of the last column.
         */
        if (!ctrl->sort_finished && ctrl->alive_threads > 0) {
            continue;
        }
        /* when tag of all_finished is true, it means there are not no-sort columns,all columns have finished sorting or
           are sorting.
         * 1. all columns have finished sorting, all sort threads are not working and the number of alive threads is 0.
         * 2. there are some columns are sorting, some sort threads are working and the number of alive threads is not 0.
         * we must ensure all columns have finished sorting, then the main thread starting writing sys tables
         */
        if (ctrl->all_finished && ctrl->alive_threads > 0) {
            continue;
        }

        if (stats_parall_persist_stats(session, ctrl) != CT_SUCCESS) {
            ctrl->parall_success = CT_FALSE;
            status = CT_ERROR;
            break;
        }
       
        if (ctrl->alive_threads == 0) {
            break;
        }
    }

    return status;
}

status_t stats_create_parall_threads(knl_session_t *session, stats_par_ctrl_t *ctrl, stats_vm_list *vm_list,
                                     uint32 thread_num)
{
    stats_par_context_t *par_ctx = NULL;
    status_t status = CT_SUCCESS;

    ctrl->all_thread_ready = CT_FALSE;
    for (uint32 i = 0; i < thread_num; i++) {
        par_ctx = &ctrl->par_ctx[i];
        par_ctx->par_ctrl = (void*)ctrl;
        par_ctx->id = i;
        par_ctx->is_wait = CT_FALSE;

        if (stats_alloc_mem_from_vm(session, vm_list, (char**)&par_ctx->col_ctx.col_handler,
            sizeof(stats_col_handler_t)) != CT_SUCCESS) {
            status = CT_ERROR;
            break;
        }

        if (stats_push_cursor_from_vm(session, vm_list, &par_ctx->col_ctx.stats_cur) != CT_SUCCESS) {
            status = CT_ERROR;
            break;
        }

        if (cm_create_thread(stats_parallel_proc, 0, par_ctx, &par_ctx->thread) != CT_SUCCESS) {
            ctrl->parall_success = CT_FALSE;
            status = CT_ERROR;
            break;
        }

        stats_record_alive_thread(ctrl, CT_TRUE);
        ctrl->thread_count++;
    }

    if (status == CT_SUCCESS) {
        cm_spin_lock(&ctrl->read_lock, NULL);
        ctrl->all_thread_ready = CT_TRUE;
        cm_spin_unlock(&ctrl->read_lock);
    }

    return status;
}

status_t stats_parall_gather_columns(knl_session_t *session, dc_entity_t *entity, stats_tab_context_t *tab_ctx,
                                     stats_cols_list_t *column_list)
{
    stats_par_ctrl_t ctrl;
    stats_vm_list vm_list;
    errno_t ret;
    uint32 stats_max_paraller = session->kernel->attr.stats_paraller_threads;

    ret = memset_sp(&vm_list, sizeof(stats_vm_list), 0xFF, sizeof(stats_vm_list));
    knl_securec_check(ret);

    ret = memset_sp(&ctrl, sizeof(stats_par_ctrl_t), 0, sizeof(stats_par_ctrl_t));
    knl_securec_check(ret);

    ret = memset_sp(&ctrl.par_thread_queue.id_list, sizeof(uint16) * CT_MAX_STATS_PARALL_THREADS, 0xFF,
                    sizeof(uint16) * CT_MAX_STATS_PARALL_THREADS);
    knl_securec_check(ret);

    session->thread_shared = CT_TRUE;
    ctrl.session = session;
    ctrl.tab_ctx = tab_ctx;
    ctrl.entity = entity;
    ctrl.col_list = column_list;
    ctrl.parall_success = CT_TRUE;
    
    uint32 thread_num = (column_list->column_count > stats_max_paraller) ? stats_max_paraller : column_list->column_count;
    
    status_t status = stats_create_parall_threads(session, &ctrl, &vm_list, thread_num);
    if (status != CT_ERROR) {
        session->stats_parall = ctrl.thread_count;
        status = stats_wait_persist_end(session, &ctrl);
    }
   
    if (stats_parallel_proc_clean(session, &ctrl) != CT_SUCCESS) {
        stats_close_vms(session, &vm_list);
        session->thread_shared = CT_FALSE;
        return CT_ERROR;
    }

    stats_close_vms(session, &vm_list);
    session->thread_shared = CT_FALSE;
    return status;
}

static inline bool32 stats_judge_paraller(knl_session_t *session, uint32 col_count)
{
    uint32 cpu_count = session->kernel->attr.cpu_count;
    bool32 enable_parall = session->kernel->attr.stats_enable_parall;

    if (!enable_parall || cpu_count < STATS_PARALL_MIN_CPU_COUNT || col_count < STATS_PARALL_MIN_COLUMN_COUNT) {
        return CT_FALSE;
    }

    return CT_TRUE;
}

status_t stats_gather_columns(knl_session_t *session, dc_entity_t *entity, stats_table_t *table_stats,
                              mtrl_context_t *mtrl_tab_ctx, uint32 mtrl_tab_seg)
{
    errno_t ret;
    stats_tab_context_t tab_ctx;
    stats_cols_list_t column_list;
    status_t status;

    if (!STATS_DYNAMICAL_TRANS_GTT(entity->type, table_stats->is_dynamic)) {
        if (stats_try_begin_auton_rm(session, table_stats->is_dynamic) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    ret = memset_sp(&tab_ctx, sizeof(stats_tab_context_t), 0, sizeof(stats_tab_context_t));
    knl_securec_check(ret);

    tab_ctx.table_stats = table_stats;
    tab_ctx.mtrl_tab_ctx = mtrl_tab_ctx;
    tab_ctx.mtrl_tab_seg = mtrl_tab_seg;

    CM_SAVE_STACK(session->stack);
    stats_init_columns_list(session, &column_list);
    column_list.col_list = (uint16 *)cm_push(session->stack, sizeof(uint16) * column_list.max_count);
    ret = memset_sp(column_list.col_list, sizeof(uint16) * column_list.max_count, 0xFF,
                    sizeof(uint16) * column_list.max_count);
    knl_securec_check(ret);
    stats_generate_columns_list(entity, table_stats, table_stats->stats_option.method_opt, &column_list);

    bool32 is_paraller = stats_judge_paraller(session, column_list.column_count);
    if (STATS_ENABLE_PARALLER(table_stats, is_paraller)) {
        status = stats_parall_gather_columns(session, entity, &tab_ctx, &column_list);
    } else {
        status = stats_normal_gather_columns(session, entity, &tab_ctx, &column_list);
    }

    CM_RESTORE_STACK(session->stack);
    
    if (status == CT_SUCCESS) {
        stats_internal_commit(session, table_stats);
    } else {
        stats_internal_rollback(session, table_stats);
    }

    if (!STATS_DYNAMICAL_TRANS_GTT(entity->type, table_stats->is_dynamic)) {
        stats_try_end_auton_rm(session, status, table_stats->is_dynamic);
    }
    return status;
}

status_t stats_gather_part_columns(knl_session_t *session, knl_dictionary_t *dc, stats_tab_context_t *tab_ctx)
{
    stats_table_t *table_stats = tab_ctx->table_stats;
    mtrl_context_t *temp_ctx = tab_ctx->mtrl_tab_ctx;
    uint32 temp_seg = tab_ctx->mtrl_tab_seg;
    dc_entity_t *entity = DC_ENTITY(dc);

    if (stats_create_global_mtrl_table(session, dc, temp_ctx, temp_seg, table_stats) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (STATS_IS_NOT_SPECIFY_PART(table_stats, table_stats->part_stats.part_id)) {
        return CT_SUCCESS;
    }

    if (stats_gather_columns(session, entity, table_stats, temp_ctx, temp_seg) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t stats_gather_global_columns_stats(knl_session_t *session, knl_dictionary_t *dc, stats_table_t *table_stats,
                                           mtrl_context_t *temp_ctx, uint32 temp_seg)
{
    dc_entity_t *entity = DC_ENTITY(dc);
    bool32 is_exist = CT_FALSE;
    cbo_stats_table_t *cbo_stats = entity->cbo_table_stats;

    if (table_stats->specify_part_id != CT_INVALID_ID32) {
        if (STATS_GLOBAL_CBO_STATS_EXIST(entity)) {
            for (uint32 i = 0; i < cbo_stats->max_col_id; i++) {
                cbo_stats_column_t  *cbo_column = cbo_get_column_stats(cbo_stats, i);

                if (cbo_column != NULL) {
                    is_exist = CT_TRUE;
                    break;
                }
            }
        }
       
        if (is_exist) {
            return CT_SUCCESS;
        }
    }

    table_stats->part_start_rid.vmid = 0;
    table_stats->part_start_rid.slot = 0;
    table_stats->part_stats.part_id = CT_INVALID_ID32;

    if (stats_gather_columns(session, entity, table_stats, temp_ctx, temp_seg) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

uint32 stats_amplify_num_rows(uint32 num_rows, double sample_ratio)
{
    if (sample_ratio < CT_REAL_PRECISION) {
        return num_rows;
    }

    uint64 result_rows = (uint64)(int64)(num_rows / sample_ratio);
    if (result_rows < CT_MAX_INT32) {
        return (uint32)result_rows;
    }

    return (uint32)CT_MAX_INT32;
}

uint32 stats_add_num_rows(uint32 ori_rows, int32 curr_rows)
{
    uint64 result_rows = (uint64)ori_rows + curr_rows;
    if (result_rows < CT_MAX_INT32) {
        return (uint32)result_rows;
    }

    return (uint32)CT_MAX_INT32;
}

void stats_estimate_whole_stats(stats_part_table_t *part_stats, double sample_ratio)
{
    part_stats->info.blocks = (uint32)(int32)(part_stats->info.blocks / sample_ratio);
    part_stats->info.empty_block = (uint32)(int32)(part_stats->info.empty_block / sample_ratio);
    part_stats->info.rows = stats_amplify_num_rows(part_stats->info.rows, sample_ratio);
    part_stats->info.row_len = (uint64)(int64)(part_stats->info.row_len / sample_ratio);
}

void stats_increase_table_part_stats(cbo_stats_table_t *cbo_global_stats, stats_table_t *global_stats,
                                     stats_part_table_t *part_stats, uint32 part_no, bool32 is_parent)
{
    cbo_stats_table_t *cbo_part_stats = CBO_GET_TABLE_PART(cbo_global_stats, part_no);
    double part_sample_ratio = global_stats->part_sample_ratio;

    part_stats->info.sample_size = is_parent ? part_stats->info.sample_size : part_stats->info.rows;
    global_stats->tab_info.sample_size = cbo_global_stats->sample_size +
                                (part_stats->info.sample_size - cbo_part_stats->sample_size);

    if (STATS_NEED_AMPLIFY(part_sample_ratio, is_parent)) {
        stats_estimate_whole_stats(part_stats, part_sample_ratio);
    }

    int32 inc_num_rows = part_stats->info.rows - cbo_part_stats->rows;
    global_stats->tab_info.blocks = cbo_global_stats->blocks + (part_stats->info.blocks - cbo_part_stats->blocks);
    global_stats->tab_info.empty_block = cbo_global_stats->empty_blocks +
                                (part_stats->info.empty_block - cbo_part_stats->empty_blocks);
    global_stats->tab_info.rows = stats_add_num_rows(cbo_global_stats->rows, inc_num_rows);

    int64 row_len = (int64)((cbo_global_stats->avg_row_len * cbo_global_stats->rows) +
                            (part_stats->info.row_len - (cbo_part_stats->avg_row_len * cbo_part_stats->rows)));
    global_stats->tab_info.row_len = (uint64)cm_abs64(row_len);
}

void stats_calc_global_part_stats(dc_entity_t *entity, stats_table_t *global_stats, uint32 part_no, bool32 is_parent)
{
    stats_part_table_t *part_stats = &global_stats->part_stats;
    cbo_stats_table_t  *cbo_global_stats = entity->cbo_table_stats;
    cbo_stats_table_t  *cbo_part_stats = CBO_GET_TABLE_PART(cbo_global_stats, part_no);
    double part_sample_ratio = global_stats->part_sample_ratio;

    if (cbo_part_stats == NULL) {
        part_stats->info.sample_size = is_parent ? part_stats->info.sample_size : part_stats->info.rows;
        global_stats->tab_info.sample_size = cbo_global_stats->sample_size + part_stats->info.sample_size;
        
        if (STATS_NEED_AMPLIFY(part_sample_ratio, is_parent)) {
            stats_estimate_whole_stats(part_stats, part_sample_ratio);
        }

        global_stats->tab_info.blocks = cbo_global_stats->blocks + part_stats->info.blocks;
        global_stats->tab_info.empty_block = cbo_global_stats->empty_blocks + part_stats->info.empty_block;
        global_stats->tab_info.rows = stats_add_num_rows(cbo_global_stats->rows, part_stats->info.rows);
        global_stats->tab_info.row_len = (cbo_global_stats->avg_row_len * cbo_global_stats->rows) + part_stats->info.row_len;
    } else {
        stats_increase_table_part_stats(cbo_global_stats, global_stats, part_stats, part_no, is_parent);
    }
}

/*
 * add up every table part statistics  for part table statistics
 */
void stats_calc_global_table_stats(stats_table_t *table_stats, bool32 is_parent)
{
    stats_part_table_t *part_stats = &table_stats->part_stats;
    double sample_ratio = 0;

    part_stats->info.sample_size = is_parent ? part_stats->info.sample_size : part_stats->info.rows;
    table_stats->tab_info.sample_size += part_stats->info.sample_size;

    if (STATS_IS_ANALYZE_SINGLE_PART(table_stats, table_stats->part_stats.part_id)) {
        sample_ratio = table_stats->part_sample_ratio;
    } else {
        sample_ratio = table_stats->estimate_sample_ratio;
    }

    if (STATS_NEED_AMPLIFY(sample_ratio, is_parent)) {
        stats_estimate_whole_stats(part_stats, sample_ratio);
    }
  
    table_stats->tab_info.blocks += part_stats->info.blocks;
    table_stats->tab_info.empty_block += part_stats->info.empty_block;
    table_stats->tab_info.rows = stats_add_num_rows(table_stats->tab_info.rows, part_stats->info.rows);
    table_stats->tab_info.row_len += part_stats->info.row_len;
}

void stats_prepare_gather_subpart_index(knl_session_t *session, stats_table_t *table_stats, stats_index_t *stats_idx,
                                        index_part_t *index_part)
{
    if (STATS_IS_ANALYZE_SINGLE_PART(table_stats, table_stats->part_stats.part_id)) {
        stats_init_index_handler(session, stats_idx, table_stats->part_sample_ratio);
    } else {
        stats_init_index_handler(session, stats_idx, table_stats->estimate_sample_ratio);
    }

    stats_idx->g_rid = table_stats->part_start_rid;
    stats_idx->part_id = table_stats->part_stats.part_id;
    stats_part_table_t *sub_part = table_stats->part_stats.sub_stats;
    stats_idx->subpart_id = sub_part->part_id;
    stats_idx->part_index = index_part;
    stats_idx->is_dynamic = table_stats->is_dynamic;
}

void stats_init_part_index_info(stats_index_t *stats_idx, index_t *idx)
{
    stats_idx->uid = idx->desc.uid;
    stats_idx->name.str = idx->desc.name;
    // index name len is not greater than 68
    stats_idx->name.len = (uint16)strlen(idx->desc.name);
    stats_idx->is_encode = idx->desc.is_encode;
    stats_idx->table_id = idx->desc.table_id;
    stats_idx->idx_id = idx->desc.id;
}

status_t stats_gather_part_index(knl_session_t *session, knl_dictionary_t *dc, stats_tab_context_t *tab_ctx)
{
    stats_table_t *table_stats = tab_ctx->table_stats;
    mtrl_context_t *mtrl_tab_ctx = tab_ctx->mtrl_tab_ctx;
    uint32 mtrl_tab_seg = tab_ctx->mtrl_tab_seg;
    uint32 part_no = table_stats->part_stats.part_no;
    table_t          *table = DC_TABLE(dc);
    stats_index_t     stats_idx;
    status_t result = CT_SUCCESS;
    SYNC_POINT_GLOBAL_START(COLLECT_STATISTICS_INDEX_FAIL, &result, CT_ERROR)
    CM_SAVE_STACK(session->stack);
    btree_t *btree = (btree_t *)cm_push(session->stack, sizeof(btree_t));
    errno_t ret = memset_sp(btree, sizeof(btree_t), 0, sizeof(btree_t));
    knl_securec_check(ret);

    for (uint32 i = 0; i < table->index_set.count; i++) {
        index_t *idx = table->index_set.items[i];
        if (!IS_PART_INDEX(idx)) {
            continue;
        }

        index_part_t *index_part = INDEX_GET_PART(idx, part_no);
        btree->index = idx;

        if (STATS_IS_ANALYZE_SINGLE_PART(table_stats, table_stats->part_stats.part_id)) {
            stats_init_index_handler(session, &stats_idx, table_stats->part_sample_ratio);
        } else {
            stats_init_index_handler(session, &stats_idx, table_stats->estimate_sample_ratio);
        }

        stats_idx.g_rid = table_stats->part_start_rid;
        stats_idx.part_id = index_part->desc.part_id;
        stats_idx.part_index = index_part;
        stats_idx.is_dynamic = table_stats->is_dynamic;
        stats_idx.mtrl.mtrl_table_ctx = mtrl_tab_ctx;
        stats_idx.mtrl.temp_seg_id = mtrl_tab_seg;
        stats_idx.btree = btree;

        if (IS_PARENT_IDXPART(&index_part->desc)) {
            stats_init_part_index_info(&stats_idx, idx);

            if (stats_update_sys_indexpart(session, &stats_idx) != CT_SUCCESS) {
                mtrl_release_context(&stats_idx.mtrl.mtrl_ctx);
                CM_RESTORE_STACK(session->stack);
                stats_internal_rollback(session, table_stats);
                return CT_ERROR;
            }
            continue;
        }

        if (stats_gather_index_entity(session, dc, idx, &stats_idx, table_stats) != CT_SUCCESS) {
            mtrl_release_context(&stats_idx.mtrl.mtrl_ctx);
            CM_RESTORE_STACK(session->stack);
            stats_internal_rollback(session, table_stats);
            return CT_ERROR;
        }
        
        mtrl_release_context(&stats_idx.mtrl.mtrl_ctx);
    }
    
    CM_RESTORE_STACK(session->stack);
    stats_internal_commit(session, table_stats);
    SYNC_POINT_GLOBAL_END;
    return result;
}

static status_t stats_update_empty_sys_subindexs(knl_session_t *session, part_index_t *part_index,
    index_part_t *idx_part, stats_index_t *index_stats)
{
    index_part_t *sub_part = NULL;

    for (uint32 j = 0; j < idx_part->desc.subpart_cnt; j++) {
        sub_part = PART_GET_SUBENTITY(part_index, idx_part->subparts[j]);
        if (sub_part == NULL) {
            continue;
        }

        index_stats->subpart_id = sub_part->desc.part_id;

        if (stats_update_sys_subindexpart(session, index_stats)) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

status_t stats_update_empty_sys_indexparts(knl_session_t *session, index_t *idx, stats_index_t *index_stats, uint32 part_id)
{
    part_index_t *part_idx = idx->part_index;
    index_part_t *idx_part = NULL;

    for (uint32 i = 0; i < part_idx->desc.partcnt; i++) {
        idx_part = INDEX_GET_PART(idx, i);
        if (idx_part == NULL) {
            continue;
        }

        index_stats->part_id = idx_part->desc.part_id;
        index_stats->uid = idx_part->desc.uid;
        index_stats->table_id = idx_part->desc.table_id;
        index_stats->idx_id = idx_part->desc.index_id;
        
        if (IS_PARENT_IDXPART(&idx_part->desc)) {
            if (stats_update_empty_sys_subindexs(session, idx->part_index, idx_part, index_stats) != CT_SUCCESS) {
                return CT_ERROR;
            }
        }
        /*
        * if part_id is CT_INVALID_ID32, it means to gather all parts statistics,
        * we set all table part statistics to empty
        */
        if (part_id == CT_INVALID_ID32) {
            if (stats_update_sys_indexpart(session, index_stats) != CT_SUCCESS) {
                return CT_ERROR;
            }
            continue;
        }
        /*
        * if part_id is normal part id, it means to gather one part statistics,
        * we set the table part statistics to empty
        */
        if (part_id == idx_part->desc.part_id) {
            if (stats_update_sys_indexpart(session, index_stats) != CT_SUCCESS) {
                return CT_ERROR;
            }
            break;
        }
    }

    return CT_SUCCESS;
}

static status_t stats_update_empty_sys_subparts(knl_session_t *session, table_t *table, table_part_t *table_part,
    stats_table_t *table_stats)
{
    table_part_t *sub_part = NULL;
    stats_table_info_t tab_info;
    errno_t ret;

    for (uint32 j = 0; j < table_part->desc.subpart_cnt; j++) {
        sub_part = PART_GET_SUBENTITY(table->part_table, table_part->subparts[j]);
        if (sub_part == NULL) {
            continue;
        }
       
        ret = memset_s(&tab_info, sizeof(stats_table_info_t), 0, sizeof(stats_table_info_t));
        knl_securec_check(ret);

        if (stats_update_sys_subtablepart(session, sub_part, &tab_info, table_stats->is_dynamic) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

status_t stats_update_empty_sys_tablepart(knl_session_t *session, knl_dictionary_t *dc, stats_table_t *table_stats,
                                          uint32 part_id)
{
    table_t *table = DC_TABLE(dc);
    part_table_t *part_table = table->part_table;
    table_part_t *table_part = NULL;

    for (uint32 i = 0; i < part_table->desc.partcnt; i++) {
        table_part = TABLE_GET_PART(table, i);
        if (!IS_READY_PART(table_part)) {
            continue;
        }
        table_stats->uid = table_part->desc.uid;
        table_stats->tab_id = table_part->desc.table_id;
        table_stats->part_stats.part_id = table_part->desc.part_id;
        table_stats->part_stats.part_no = i;
        if (IS_PARENT_TABPART(&table_part->desc)) {
            if (stats_update_empty_sys_subparts(session, table, table_part, table_stats) != CT_SUCCESS) {
                return CT_ERROR;
            }
        }
        /*
        * if part_id is CT_INVALID_ID32, it means to gather all parts statistics,
        * we set all table part statistics to empty
        */
        if (part_id == CT_INVALID_ID32) {
            if (stats_update_sys_tablepart(session, dc, table_stats) != CT_SUCCESS) {
                return CT_ERROR;
            }
            continue;
        }
        /*
        * if part_id is normal part id, it means to gather one part statistics,
        * we set the table part statistics to empty
        */
        if (part_id == table_part->desc.part_id) {
            if (stats_update_sys_tablepart(session, dc, table_stats) != CT_SUCCESS) {
                return CT_ERROR;
            }
            break;
        }
    }

    return CT_SUCCESS;
}

static status_t stats_try_gather_empty_subpart(knl_session_t *session, knl_dictionary_t *dc, table_part_t *table_subpart,
                                               bool32 *is_empty, bool32 is_dynamic)
{
    stats_table_info_t tab_info;
    stats_index_t index_stats;
    dc_entity_t *entity = DC_ENTITY(dc);
    table_t *table = &entity->table;
    index_t *idx = NULL;
    errno_t ret;

    if (table_subpart == NULL) {
        return CT_SUCCESS;
    }

    if (!table_subpart->heap.loaded) {
        if (dc_load_table_part_segment(session, dc->handle, table_subpart) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (table_subpart->heap.segment != NULL) {
        *is_empty = CT_FALSE;
        return CT_SUCCESS;
    }

    ret = memset_s(&index_stats, sizeof(stats_index_t), 0, sizeof(stats_index_t));
    knl_securec_check(ret);

    for (uint32 i = 0; i < table->index_set.count; i++) {
        idx = table->index_set.items[i];
        index_stats.table_id = idx->desc.table_id;
        index_stats.idx_id = idx->desc.id;
        index_stats.uid = idx->desc.uid;
        index_stats.name.str = idx->desc.name;
        // index name is smaller than 68
        index_stats.name.len = (uint16)strlen(idx->desc.name);
        index_stats.is_encode = idx->desc.is_encode;
        index_stats.is_dynamic = is_dynamic;
        index_stats.subpart_id = table_subpart->desc.part_id;
        index_stats.part_id = table_subpart->desc.parent_partid;

        if (IS_PART_INDEX(idx)) {
            // to update indexpart$
            if (stats_update_sys_subindexpart(session, &index_stats) != CT_SUCCESS) {
                stats_rollback(session, is_dynamic);
                return CT_ERROR;
            }
        }
        stats_commit(session, is_dynamic);
    }

    ret = memset_s(&tab_info, sizeof(stats_table_info_t), 0, sizeof(stats_table_info_t));
    knl_securec_check(ret);

    if (stats_update_sys_subtablepart(session, table_subpart, &tab_info, is_dynamic) != CT_SUCCESS) {
        stats_rollback(session, is_dynamic);
        return CT_ERROR;
    }
    stats_commit(session, is_dynamic);
    *is_empty = CT_TRUE;
    return CT_SUCCESS;
}

static status_t stats_check_segment_valid(knl_session_t *session, table_part_t *table_part, heap_segment_t **seg)
{
    if (!spc_validate_page_id(session, table_part->desc.entry)) {
        return CT_SUCCESS;
    }

    buf_enter_page(session, table_part->desc.entry, LATCH_MODE_S, ENTER_PAGE_NORMAL);
    page_head_t *page = (page_head_t *)CURR_PAGE(session);
    *seg = HEAP_SEG_HEAD(session);
    if (page->type != PAGE_TYPE_HEAP_HEAD || (*seg)->seg_scn != table_part->desc.seg_scn) {
        CT_THROW_ERROR(ERR_OBJECT_ALREADY_DROPPED, table_part->desc.name);
        buf_leave_page(session, CT_FALSE);
        return CT_ERROR;
    }
    buf_leave_page(session, CT_FALSE);
  
    return CT_SUCCESS;
}

static status_t stats_try_gather_empty_part(knl_session_t *session, knl_dictionary_t *dc, table_part_t *table_part,
                                            bool32 *is_empty, bool32 is_dynamic)
{
    stats_table_t tab_stats;
    stats_index_t index_stats;
    table_t *table = DC_TABLE(dc);
    heap_segment_t *seg = NULL;

    if (!table_part->heap.loaded) {
        if (dc_load_table_part_segment(session, dc->handle, table_part) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
    // if entry is invalid page id,it means segment is not created.
    if (stats_check_segment_valid(session, table_part, &seg) != CT_SUCCESS) {
        return CT_ERROR;
    }
    
    /*
    * 1. heap table and not empty,we need to gather statistics;
    * 2. temp table,we set statistics information to 0, no matter it is empty or not;
    * 3. nologging table behave as heap table;
    */
    if (IS_STATS_TABLE_TYPE(table) && seg != NULL) {
        *is_empty = CT_FALSE;
        return CT_SUCCESS;
    }

    errno_t ret = memset_s(&index_stats, sizeof(stats_index_t), 0, sizeof(stats_index_t));
    knl_securec_check(ret);

    ret = memset_s(&tab_stats, sizeof(stats_table_t), 0, sizeof(stats_table_t));
    knl_securec_check(ret);

    tab_stats.is_dynamic = is_dynamic;
    tab_stats.is_part = CT_TRUE;
    for (uint32 i = 0; i < table->index_set.count; i++) {
        index_t *idx = table->index_set.items[i];
        index_stats.uid = idx->desc.uid;
        index_stats.name.str = idx->desc.name;
        // index name is smaller than 68
        index_stats.name.len = (uint16)strlen(idx->desc.name);
        index_stats.is_dynamic = is_dynamic;

        if (!IS_PART_INDEX(idx)) {
            continue;
        }

        // to update indexpart$
        if (stats_update_empty_sys_indexparts(session, idx, &index_stats, table_part->desc.part_id) != CT_SUCCESS) {
            stats_internal_rollback(session, &tab_stats);
            return CT_ERROR;
        }
    }

    if (stats_update_empty_sys_tablepart(session, dc, &tab_stats, table_part->desc.part_id) != CT_SUCCESS) {
        stats_internal_rollback(session, &tab_stats);
        return CT_ERROR;
    }

    stats_internal_commit(session, &tab_stats);
    *is_empty = CT_TRUE;
    return CT_SUCCESS;
}

/*
* add up every table sub part statistics for table part statistics
*/
void stats_calc_parent_part_stats(stats_table_t *table_stats)
{
    stats_part_table_t *parent_part = &table_stats->part_stats;
    stats_part_table_t *sub_part = parent_part->sub_stats;
    double sample_ratio = 0;

    sub_part->info.sample_size = sub_part->info.rows;
    parent_part->info.sample_size += sub_part->info.sample_size;

    if (STATS_IS_ANALYZE_SINGLE_PART(table_stats, parent_part->part_id)) {
        sample_ratio = table_stats->part_sample_ratio;
    } else {
        sample_ratio = table_stats->estimate_sample_ratio;
    }

    if (sample_ratio > CT_REAL_PRECISION) {
        stats_estimate_whole_stats(sub_part, sample_ratio);
    }

    parent_part->info.blocks += sub_part->info.blocks;
    parent_part->info.empty_block += sub_part->info.empty_block;
    parent_part->info.rows = stats_add_num_rows(parent_part->info.rows, sub_part->info.rows);
    parent_part->info.row_len += sub_part->info.row_len;
}

status_t stats_gather_table_one_subpart(knl_session_t *session, knl_dictionary_t *dc, table_part_t *table_subpart,
    stats_tab_context_t *tab_ctx, bool32 *is_empty_subpart)
{
    stats_table_t *table_stats = tab_ctx->table_stats;
    mtrl_context_t *temp_ctx = tab_ctx->mtrl_tab_ctx;
    uint32 temp_seg = tab_ctx->mtrl_tab_seg;
    dc_entity_t *entity = DC_ENTITY(dc);
    bool32 is_dynamic = table_stats->is_dynamic;

    if (!table_subpart->heap.loaded) {
        if (dc_load_table_part_segment(session, dc->handle, table_subpart) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (stats_try_gather_empty_subpart(session, dc, table_subpart, is_empty_subpart,
        is_dynamic) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (*is_empty_subpart) {
        return CT_SUCCESS;
    }

    if (stats_create_global_mtrl_table(session, dc, temp_ctx, temp_seg, table_stats) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (stats_gather_columns(session, entity, table_stats, temp_ctx, temp_seg) != CT_SUCCESS) {
        return CT_ERROR;
    }

    stats_calc_parent_part_stats(table_stats);

    stats_table_info_t *tab_info = &table_stats->part_stats.sub_stats->info;
    if (stats_update_sys_subtablepart(session, table_subpart, tab_info, is_dynamic) != CT_SUCCESS) {
        stats_rollback(session, is_dynamic);
        return CT_ERROR;
    }

    stats_commit(session, is_dynamic);
    return CT_SUCCESS;
}

status_t stats_gather_subpart_index(knl_session_t *session, knl_dictionary_t *dc, stats_tab_context_t *tab_ctx)
{
    stats_table_t *table_stats = tab_ctx->table_stats;
    mtrl_context_t *mtrl_tab_ctx = tab_ctx->mtrl_tab_ctx;
    uint32 mtrl_tab_seg = tab_ctx->mtrl_tab_seg;
    table_t *table = DC_TABLE(dc);
    stats_index_t stats_idx;
    uint32  part_no = table_stats->part_stats.part_no;
    btree_t *btree = (btree_t *)cm_push(session->stack, sizeof(btree_t));
    errno_t ret = memset_sp(btree, sizeof(btree_t), 0, sizeof(btree_t));
    knl_securec_check(ret);

    for (uint32 i = 0; i < table->index_set.count; i++) {
        index_t *idx = table->index_set.items[i];
        if (!IS_PART_INDEX(idx)) {
            continue;
        }

        index_part_t *index_part = INDEX_GET_PART(idx, part_no);
        if (!IS_PARENT_IDXPART(&index_part->desc)) {
            continue;
        }
        uint32  subpart_no = table_stats->part_stats.sub_stats->part_no;
        index_part_t *index_subpart = PART_GET_SUBENTITY(idx->part_index, index_part->subparts[subpart_no]);
        btree->index = idx;
        
        stats_prepare_gather_subpart_index(session, table_stats, &stats_idx, index_subpart);
        stats_idx.is_subpart = CT_TRUE;
        stats_idx.mtrl.mtrl_table_ctx = mtrl_tab_ctx;
        stats_idx.mtrl.temp_seg_id = mtrl_tab_seg;
        stats_idx.btree = btree;

        if (stats_gather_index_entity(session, dc, idx, &stats_idx, table_stats) != CT_SUCCESS) {
            cm_pop(session->stack);
            mtrl_release_context(&stats_idx.mtrl.mtrl_ctx);
            stats_internal_rollback(session, table_stats);
            return CT_ERROR;
        }

        mtrl_release_context(&stats_idx.mtrl.mtrl_ctx);
    }

    cm_pop(session->stack);
    stats_internal_commit(session, table_stats);
    return CT_SUCCESS;
}

status_t stats_gather_table_subpart(knl_session_t *session, knl_dictionary_t *dc, table_part_t *table_compart,
                                    stats_tab_context_t *tab_ctx, stats_part_table_t *sub_part)
{
    stats_table_t *table_stats = tab_ctx->table_stats;
    mtrl_context_t *temp_ctx = tab_ctx->mtrl_tab_ctx;
    uint32 temp_seg = tab_ctx->mtrl_tab_seg;
    stats_part_table_t *compart_stats = &table_stats->part_stats;
    double ori_sample_ratio = STATS_IS_ANALYZE_SINGLE_PART(table_stats, table_stats->part_stats.part_id) ?
        table_stats->part_sample_ratio : table_stats->estimate_sample_ratio;
    bool32 is_empty_part = CT_FALSE;
    table_stats->part_stats.is_subpart = CT_TRUE;
    table_stats->part_stats.parent_start_rid = table_stats->now_rid;
    table_t *table = DC_TABLE(dc);
    
    for (uint32 i = 0; i < table_compart->desc.subpart_cnt; i++) {
        table_part_t *table_subpart = PART_GET_SUBENTITY(table->part_table, table_compart->subparts[i]);

        if (table_subpart == NULL) {
            continue;
        }

        errno_t ret = memset_sp(sub_part, sizeof(stats_part_table_t), 0, sizeof(stats_part_table_t));
        knl_securec_check(ret);
        is_empty_part = CT_FALSE;
        compart_stats->sub_stats = sub_part;
        compart_stats->sub_stats->part_no = i;
        compart_stats->sub_stats->part_id = table_subpart->desc.part_id;

        if (STATS_IS_ANALYZE_SINGLE_PART(table_stats, table_stats->part_stats.part_id)) {
            table_stats->part_sample_ratio = ori_sample_ratio;
        } else {
            table_stats->estimate_sample_ratio = ori_sample_ratio;
        }

        if (stats_gather_table_one_subpart(session, dc, table_subpart, tab_ctx, &is_empty_part) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (is_empty_part) {
            continue;
        }

        if (stats_gather_subpart_index(session, dc, tab_ctx) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    dc_entity_t *entity = DC_ENTITY(dc);

    table_stats->part_start_rid = table_stats->part_stats.parent_start_rid;
    table_stats->part_stats.sub_stats->part_id = CT_INVALID_ID32;
    // gather parent part global column statistics
    if (stats_gather_columns(session, entity, table_stats, temp_ctx, temp_seg) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t stats_gather_single_table_part(knl_session_t *session, knl_dictionary_t *dc, stats_tab_context_t *tab_ctx)
{
    stats_table_t *table_stats = tab_ctx->table_stats;
    stats_part_table_t *part_stats = &table_stats->part_stats;
    table_t *table = DC_TABLE(dc);
    part_table_t *part_table = table->part_table;
    table_part_t *table_part = NULL;
    uint32 part_no;
    bool32 is_empty = CT_FALSE;
    stats_part_table_t sub_part;

    for (part_no = 0; part_no < part_table->desc.partcnt; part_no++) {
        table_part = TABLE_GET_PART(table, part_no);
        if (!IS_READY_PART(table_part)) {
            continue;
        }

        if (table_part->desc.part_id == table_stats->specify_part_id) {
            break;
        }
    }

    errno_t ret = memset_s(part_stats, sizeof(stats_part_table_t), 0, sizeof(stats_part_table_t));
    knl_securec_check(ret);

    table_stats->is_part = CT_TRUE;
    part_stats->part_no = part_no;
    part_stats->part_id = table_part->desc.part_id;
    bool32 is_parent = IS_PARENT_TABPART(&table_part->desc);
    if (is_parent) {
        if (stats_gather_table_subpart(session, dc, table_part, tab_ctx, &sub_part) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } else {
        if (!table_part->heap.loaded) {
            if (dc_load_table_part_segment(session, dc->handle, table_part) != CT_SUCCESS) {
                return CT_ERROR;
            }
        }

        if (stats_try_gather_empty_part(session, dc, table_part, &is_empty, table_stats->is_dynamic) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (is_empty) {
            stats_calc_global_part_stats(DC_ENTITY(dc), table_stats, part_no, is_parent);
            return CT_SUCCESS;
        }

        if (stats_gather_part_columns(session, dc, tab_ctx) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    stats_calc_global_part_stats(DC_ENTITY(dc), table_stats, part_no, is_parent);
    
    if (part_stats->is_subpart) {
        if (part_stats->info.rows != 0) {
            part_stats->info.avg_row_len = stats_calc_row_avg_len(part_stats->info);
        }
    }

    if (stats_update_sys_tablepart(session, dc, table_stats) != CT_SUCCESS) {
        stats_internal_rollback(session, table_stats);
        return CT_ERROR;
    }
    stats_internal_commit(session, table_stats);

    if (stats_gather_part_index(session, dc, tab_ctx) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (table_stats->tab_info.rows != 0) {
        table_stats->tab_info.avg_row_len = stats_calc_row_avg_len(table_stats->tab_info);
    }
    
    return CT_SUCCESS;
}

void stats_subtract_part_stats(stats_table_info_t *info, cbo_stats_table_t *part_stats)
{
    info->rows -= part_stats->rows;
    info->blocks -= part_stats->blocks;
    info->empty_block -= part_stats->empty_blocks;
    info->sample_size -= part_stats->sample_size;
}

static status_t stats_update_global_by_subpart(knl_session_t *session, knl_dictionary_t *dc, uint32 part_no,
                                               stats_table_info_t lose_info)
{
    knl_cursor_t *cursor = NULL;
    row_assist_t ra;
    knl_scan_key_t *key = NULL;
    table_t *table = NULL;
    uint16 size;
    dc_entity_t *entity = DC_ENTITY(dc);
    stats_table_info_t info;
    cbo_stats_table_t *part_stats = NULL;

    if (!entity->stat_exists) {
        return CT_SUCCESS;
    }

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);
    table = DC_TABLE(dc);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_TABLE_ID, IX_SYS_TABLE_001_ID);
    key = &cursor->scan_range.l_key;
    knl_init_index_scan(cursor, CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, CT_TYPE_INTEGER, &table->desc.uid, sizeof(uint32),
        IX_COL_SYS_TABLE_001_USER_ID);
    // table name is smaller than 68
    knl_set_scan_key(INDEX_DESC(cursor->index), key, CT_TYPE_STRING, table->desc.name,
        (uint16)strlen(table->desc.name), IX_COL_SYS_TABLE_001_NAME);
    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    knl_panic_log(!cursor->eof, "data is not found, panic info: page %u-%u type %u table %s index %s",
                  cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, table->desc.name,
                  ((index_t *)cursor->index)->desc.name);

    if (CURSOR_COLUMN_SIZE(cursor, TABLE_ANALYZE_TIME) == CT_NULL_VALUE_LEN) {
        CM_RESTORE_STACK(session->stack);
        return CT_SUCCESS;
    }

    info.rows = *(uint32*)CURSOR_COLUMN_DATA(cursor, TABLE_ROWS);
    info.blocks = *(uint32*)CURSOR_COLUMN_DATA(cursor, TABLE_BLOCKS);
    info.empty_block = *(uint32*)CURSOR_COLUMN_DATA(cursor, TABLE_EMPTY_BLOCK);
    info.sample_size = *(uint32*)CURSOR_COLUMN_DATA(cursor, TABLE_SAMPLE_SIZE);
    
    part_stats = CBO_GET_TABLE_PART(entity->cbo_table_stats, part_no);
    if (part_stats != NULL) {
        info.rows -= (part_stats->rows - lose_info.rows);
        info.blocks -= (part_stats->blocks - lose_info.blocks);
        info.empty_block -= (part_stats->empty_blocks - lose_info.empty_block);
        info.sample_size -= (part_stats->sample_size - lose_info.sample_size);
    }

    cursor->update_info.count = STATS_GLOBAL_PARTTABLE_COLUMNS;
    row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), STATS_GLOBAL_PARTTABLE_COLUMNS);
    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, info.rows));
    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, info.blocks));
    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, info.empty_block));
    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, info.sample_size));

    cursor->update_info.columns[0] = TABLE_ROWS;
    cursor->update_info.columns[1] = TABLE_BLOCKS;
    cursor->update_info.columns[2] = TABLE_EMPTY_BLOCK;
    cursor->update_info.columns[3] = TABLE_SAMPLE_SIZE;

    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, &size);

    if (knl_internal_update(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}

// for drop subpart to update parent part stats
status_t stats_update_global_partstats(knl_session_t *session, knl_dictionary_t *dc, uint32 partid, uint32 subpart_no)
{
    row_assist_t ra;
    knl_scan_key_t *key = NULL;
    uint16 size;
    cbo_stats_table_t *part_stats = NULL;
    dc_entity_t *entity = DC_ENTITY(dc);
    stats_table_info_t info;
    uint32 part_no = 0;
    table_part_t *parent = NULL;

    if (!entity->stat_exists) {
        return CT_SUCCESS;
    }

    CM_SAVE_STACK(session->stack);

    knl_cursor_t *cursor = knl_push_cursor(session);
    table_t *table = DC_TABLE(dc);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_TABLEPART_ID, IX_SYS_TABLEPART001_ID);
    key = &cursor->scan_range.l_key;
    knl_init_index_scan(cursor, CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, CT_TYPE_INTEGER, &table->desc.uid, sizeof(uint32),
        IX_COL_SYS_TABLEPART001_USER_ID);
    // table name is smaller than 68
    knl_set_scan_key(INDEX_DESC(cursor->index), key, CT_TYPE_INTEGER, &table->desc.id, sizeof(uint32),
        IX_COL_SYS_TABLEPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, CT_TYPE_INTEGER, &partid, sizeof(uint32),
        IX_COL_SYS_TABLEPART001_PART_ID);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    knl_panic_log(!cursor->eof, "data is not found, panic info: page %u-%u type %u table %s index %s",
                  cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, table->desc.name,
                  ((index_t *)cursor->index)->desc.name);

    if (CURSOR_COLUMN_SIZE(cursor, TABLE_PART_ANALYZE_TIME) == CT_NULL_VALUE_LEN) {
        CM_RESTORE_STACK(session->stack);
        return CT_SUCCESS;
    }

    info.rows = *(uint32*)CURSOR_COLUMN_DATA(cursor, TABLE_PART_ROWS);
    info.blocks = *(uint32*)CURSOR_COLUMN_DATA(cursor, TABLE_PART_BLOCKS);
    info.empty_block = *(uint32*)CURSOR_COLUMN_DATA(cursor, TABLE_PART_EMPTY_BLOCK);
    info.sample_size = *(uint32*)CURSOR_COLUMN_DATA(cursor, TABLE_PART_SAMPLE_SIZE);
   
    for (part_no = 0; part_no < table->part_table->desc.partcnt; part_no++) {
        parent = TABLE_GET_PART(table, part_no);
        if (!IS_READY_PART(parent)) {
            continue;
        }

        if (parent->desc.part_id == partid) {
            break;
        }
    }

    part_stats = knl_get_cbo_subpart_table(session, entity, part_no, subpart_no);
    if (part_stats != NULL) {
        stats_subtract_part_stats(&info, part_stats);
    }

    cursor->update_info.count = STATS_GLOBAL_PARTTABLE_COLUMNS;
    row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), STATS_GLOBAL_PARTTABLE_COLUMNS);
    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, info.rows));
    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, info.blocks));
    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, info.empty_block));
    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, info.sample_size));

    cursor->update_info.columns[0] = TABLE_PART_ROWS;
    cursor->update_info.columns[1] = TABLE_PART_BLOCKS;
    cursor->update_info.columns[2] = TABLE_PART_EMPTY_BLOCK;
    cursor->update_info.columns[3] = TABLE_PART_SAMPLE_SIZE;

    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, &size);

    if (knl_internal_update(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    CM_RESTORE_STACK(session->stack);

    if (stats_update_global_by_subpart(session, dc, part_no, info) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t stats_update_global_tablestats(knl_session_t *session, knl_dictionary_t *dc, uint32 part_no)
{
    knl_cursor_t *cursor = NULL;
    row_assist_t ra;
    knl_scan_key_t *key = NULL;
    table_t *table = NULL;
    uint16 size;
    cbo_stats_table_t *part_stats = NULL;
    dc_entity_t *entity = DC_ENTITY(dc);
    stats_table_info_t info;
    
    if (!entity->stat_exists) {
        return CT_SUCCESS;
    }

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);
    table = DC_TABLE(dc);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_TABLE_ID, IX_SYS_TABLE_001_ID);
    key = &cursor->scan_range.l_key;
    knl_init_index_scan(cursor, CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, CT_TYPE_INTEGER, &table->desc.uid, sizeof(uint32),
                     IX_COL_SYS_TABLE_001_USER_ID);
    // table name is smaller than 68
    knl_set_scan_key(INDEX_DESC(cursor->index), key, CT_TYPE_STRING, table->desc.name,
                     (uint16)strlen(table->desc.name), IX_COL_SYS_TABLE_001_NAME);
    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    knl_panic_log(!cursor->eof, "data is not found, panic info: page %u-%u type %u table %s index %s",
                  cursor->rowid.file, cursor->rowid.page, ((page_head_t *)cursor->page_buf)->type, table->desc.name,
                  ((index_t *)cursor->index)->desc.name);
   
    if (CURSOR_COLUMN_SIZE(cursor, TABLE_ANALYZE_TIME) == CT_NULL_VALUE_LEN) {
        CM_RESTORE_STACK(session->stack);
        return CT_SUCCESS;
    }

    info.rows = *(uint32*)CURSOR_COLUMN_DATA(cursor, TABLE_ROWS);
    info.blocks = *(uint32*)CURSOR_COLUMN_DATA(cursor, TABLE_BLOCKS);
    info.empty_block = *(uint32*)CURSOR_COLUMN_DATA(cursor, TABLE_EMPTY_BLOCK);
    info.sample_size = *(uint32*)CURSOR_COLUMN_DATA(cursor, TABLE_SAMPLE_SIZE);

    part_stats = knl_get_cbo_part_table(session, entity, part_no);
    if (part_stats != NULL) {
        stats_subtract_part_stats(&info, part_stats);
    }

    cursor->update_info.count = STATS_GLOBAL_PARTTABLE_COLUMNS;
    row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), STATS_GLOBAL_PARTTABLE_COLUMNS);
    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, info.rows));
    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, info.blocks));
    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, info.empty_block));
    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, info.sample_size));

    cursor->update_info.columns[0] = TABLE_ROWS;
    cursor->update_info.columns[1] = TABLE_BLOCKS;
    cursor->update_info.columns[2] = TABLE_EMPTY_BLOCK;
    cursor->update_info.columns[3] = TABLE_SAMPLE_SIZE;

    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, &size);

    if (knl_internal_update(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}

static status_t stats_update_sys_table(knl_session_t *session, stats_table_t *tab_stats,
                                       knl_dictionary_t *dc)
{
    knl_cursor_t *cursor = NULL;
    row_assist_t ra;
    knl_scan_key_t *key = NULL;
    table_t *table = NULL;
    uint16 size;
    bool8 is_report = tab_stats->stats_option.is_report;

    if (is_report) {
        stats_write_report_tab_value(session, DC_ENTITY(dc), tab_stats, CT_FALSE);
        return CT_SUCCESS;
    }

    if (tab_stats->is_dynamic && tab_stats->stats_option.dynamic_type == STATS_COLUMNS) {
        return CT_SUCCESS;
    }

    if (stats_try_begin_auton_rm(session, tab_stats->is_dynamic) != CT_SUCCESS) {
        return CT_ERROR;
    }

    CM_SAVE_STACK(session->stack);
    cursor = knl_push_cursor(session);
    table = DC_TABLE(dc);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_TABLE_ID, IX_SYS_TABLE_001_ID);
    key = &cursor->scan_range.l_key;
    knl_init_index_scan(cursor, CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, CT_TYPE_INTEGER, &table->desc.uid, sizeof(uint32),
        IX_COL_SYS_TABLE_001_USER_ID);
 
    // table name is smaller than 68
    knl_set_scan_key(INDEX_DESC(cursor->index), key, CT_TYPE_STRING, table->desc.name,
                     (uint16)strlen(table->desc.name), IX_COL_SYS_TABLE_001_NAME);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        stats_try_end_auton_rm(session, CT_ERROR, tab_stats->is_dynamic);
        return CT_ERROR;
    }

    if (cursor->eof) {
        CM_RESTORE_STACK(session->stack);
        CT_THROW_ERROR(ERR_OBJECT_ALREADY_DROPPED, table->desc.name);
        stats_try_end_auton_rm(session, CT_ERROR, tab_stats->is_dynamic);
        return CT_ERROR;
    }

    cursor->update_info.count = STATS_SYS_TABLE_COLUMN_COUNT;
    row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), STATS_SYS_TABLE_COLUMN_COUNT);
    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, tab_stats->tab_info.rows));
    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, tab_stats->tab_info.blocks));
    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, tab_stats->tab_info.empty_block));
    (void)row_put_int64(&ra, tab_stats->tab_info.avg_row_len);
    //  this sample size is analyzed rows, so it is smaller than max value of uint32
    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, tab_stats->tab_info.sample_size));
    tab_stats->tab_info.analyze_time = cm_now();
    (void)row_put_int64(&ra, tab_stats->tab_info.analyze_time);

    for (uint32 i = 0; i < STATS_SYS_TABLE_COLUMN_COUNT; i++) {
        cursor->update_info.columns[i] = i + STATS_SYS_TABLE_COLUMN_NUM;
    }

    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, &size);

    if (knl_internal_update(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        stats_try_end_auton_rm(session, CT_ERROR, tab_stats->is_dynamic);
        return CT_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    stats_try_end_auton_rm(session, CT_SUCCESS, tab_stats->is_dynamic);

    return CT_SUCCESS;
}

status_t stats_gather_table(knl_session_t *session, knl_dictionary_t *dc, stats_table_t *tab_stats)
{
    bool8 is_report = tab_stats->stats_option.is_report;
    stats_table_info_t *info = &tab_stats->tab_info;

    if (!tab_stats->is_part) {
        info->sample_size = info->rows;

        if (tab_stats->estimate_sample_ratio > CT_REAL_PRECISION) {
            info->blocks = (uint32)(int32)(info->blocks / tab_stats->estimate_sample_ratio);
            info->empty_block = (uint32)(int32)(info->empty_block / tab_stats->estimate_sample_ratio);
            info->rows = stats_amplify_num_rows(info->rows, tab_stats->estimate_sample_ratio);
        }
    }

    if (is_report) {
        stats_write_report_tab_value(session, DC_ENTITY(dc), tab_stats, CT_FALSE);
        return CT_SUCCESS;
    }

    if (stats_no_persistent(tab_stats)) {
        cbo_load_tmptab_table_stats(tab_stats->temp_table->table_cache->cbo_stats, tab_stats, dc);
        return CT_SUCCESS;
    }

    if (stats_update_sys_table(session, tab_stats, dc) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t db_delete_mon_sysmods(knl_session_t *session, uint32 uid, uint32 table_id, uint32 dele_part_id,
                               bool32 is_dynamic)
{
    knl_cursor_t *cursor = NULL;
    knl_match_cond_t org_match_cond = session->match_cond;
    stats_match_cond_t cond;
    /*
    * dynamic statistics gather a few blocks(default 10 pages) to generate table statistics, it is only accurate
    * for small tables.For big tables, getting more accurate statistics, DBA need to gather statistics using
    * DBMS package manually or database system trigger timing task for updating statistics automatically. Timed task
    * need dml monitor statistics for judging recollect statistics or not.So for dynamic statistics,we do not need
    * to delete dml monitor statistics.
    */
    if (is_dynamic) {
        return CT_SUCCESS;
    }

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_DELETE, SYS_MON_MODS_ALL_ID, IX_MODS_001_ID);
    knl_init_index_scan(cursor, CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &uid, sizeof(uint32),
                     IX_COL_MODS_001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &table_id, sizeof(uint32),
                     IX_COL_MODS_001_TABLE_ID);
    cursor->stmt = (void *)&cond;
    session->match_cond = stats_match_sys_dmls;
    cond.session = session;
    cond.cursor = cursor;
    cond.part_id = dele_part_id;
    cond.subpart_id = CT_INVALID_ID32;
    cond.col_id = CT_INVALID_ID32;
    cond.match_type = MATCH_PART;
  
    while (!cursor->eof) {
        if (CT_SUCCESS != knl_fetch(session, cursor)) {
            session->match_cond = org_match_cond;
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }

        if (cursor->eof) {
            break;
        }
            
        if (CT_SUCCESS != knl_internal_delete(session, cursor)) {
            session->match_cond = org_match_cond;
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }
    }

    session->match_cond = org_match_cond;
    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}

status_t db_insert_sys_mon_mods(knl_session_t *session, knl_cursor_t *cursor, stats_table_mon_t *table_smon,
                                uint32 uid, uint32 id, uint32 part_id, bool32 is_part)
{
    table_t *table = NULL;
    row_assist_t ra;

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_INSERT, SYS_MON_MODS_ALL_ID, CT_INVALID_ID32);
    table = (table_t *)cursor->table;

    row_init(&ra, (char *)cursor->row, HEAP_MAX_ROW_SIZE(session), table->desc.column_count);
    (void)row_put_int32(&ra, uid);  // user id
    (void)row_put_int32(&ra, id);   // base table id
    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, table_smon->inserts));
    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, table_smon->updates));
    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, table_smon->deletes));
    (void)row_put_date(&ra, table_smon->timestamp);
    (void)row_put_int32(&ra, 0);
    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, table_smon->drop_segments));
    if (is_part) {
        (void)row_put_int32(&ra, 1);
    } else {
        (void)row_put_int32(&ra, 0);
    }

    (void)row_put_int32(&ra, part_id);

    if (knl_internal_insert(session, cursor) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t db_update_sys_mon_modes(knl_session_t *session, knl_cursor_t *cursor, stats_table_mon_t *table_smon)
{
    row_assist_t ra;
    uint16 size;

    row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), STATS_MON_MODS_UPDATE_COLUMNS);
    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, table_smon->inserts));
    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, table_smon->updates));
    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, table_smon->deletes));
    (void)row_put_date(&ra, table_smon->timestamp);
    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, table_smon->drop_segments));
    cursor->update_info.count = STATS_MON_MODS_UPDATE_COLUMNS;
    cursor->update_info.columns[0] = STATS_MON_MODS_INSERTS_COLUMN;
    cursor->update_info.columns[1] = STATS_MON_MODS_UPDATES_COLUMN;
    cursor->update_info.columns[2] = STATS_MON_MODS_DELETES_COLUMN;
    cursor->update_info.columns[3] = STATS_MON_MODS_MODIFYTIME_COLUMN;
    cursor->update_info.columns[4] = STATS_MON_MODS_DROP_SEG_COLUMN;
    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, &size);

    if (knl_internal_update(session, cursor) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t stats_check_empty_table_subpart(knl_session_t *session, knl_dictionary_t *dc, table_part_t *table_subpart,
                                                bool32 *is_empty)
{
    if (!table_subpart->heap.loaded) {
        if (dc_load_table_part_segment(session, dc->handle, table_subpart) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (table_subpart->heap.segment != NULL) {
        *is_empty = CT_FALSE;
        return CT_SUCCESS;
    }

    return CT_SUCCESS;
}

static status_t stats_check_empty_table_part(knl_session_t *session, knl_dictionary_t *dc, table_part_t *table_part, bool32 *is_empty)
{
    table_part_t *table_sub = NULL;
    bool32 is_empty_part = CT_TRUE;
    table_t *table = DC_TABLE(dc);

    if (table_part == NULL) {
        return CT_SUCCESS;
    }

    if (!IS_PARENT_TABPART(&table_part->desc)) {
        if (!table_part->heap.loaded) {
            if (dc_load_table_part_segment(session, dc->handle, table_part) != CT_SUCCESS) {
                return CT_ERROR;
            }
        }

        if (table_part->heap.segment != NULL) {
            *is_empty = CT_FALSE;
            return CT_SUCCESS;
        }

        return CT_SUCCESS;
    }

    for (uint32 i = 0; i < table_part->desc.subpart_cnt; i++) {
        table_sub = PART_GET_SUBENTITY(table->part_table, table_part->subparts[i]);
        if (table_sub == NULL) {
            continue;
        }

        if (stats_check_empty_table_subpart(session, dc, table_sub, &is_empty_part) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (is_empty_part != CT_TRUE) {
            break;
        }
    }

    *is_empty = is_empty_part;
    return CT_SUCCESS;
}

status_t stats_check_empty_table(knl_session_t *session, knl_dictionary_t *dc, bool32 *is_empty)
{
    dc_entity_t *entity = DC_ENTITY(dc);
    table_t *table = &entity->table;
    part_table_t *part_table = table->part_table;
    knl_temp_cache_t *temp_table = NULL;
    mtrl_segment_t *segment = NULL;

    if (IS_TEMP_TABLE_BY_DC(dc)) {
        temp_table = knl_get_temp_cache((knl_handle_t)session, dc->uid, dc->oid);
        if (temp_table != NULL) {
            segment = session->temp_mtrl->segments[temp_table->table_segid];

            if (segment->vm_list.count != 0) {
                *is_empty = CT_FALSE;
            }
        }
    } else if (IS_PART_TABLE(table)) {
        for (uint32 i = 0; i < part_table->desc.partcnt; i++) {
            table_part_t *table_part = TABLE_GET_PART(table, i);
            if (!IS_READY_PART(table_part)) {
                continue;
            }

            if (stats_check_empty_table_part(session, dc, table_part, is_empty) != CT_SUCCESS) {
                return CT_ERROR;
            }

            if (*is_empty != CT_TRUE) {
                break;
            }
        }
    } else {
        if (table->heap.segment != NULL) {
            *is_empty = CT_FALSE;
        }
    }

    return CT_SUCCESS;
}

bool32 stats_check_old_nologging(knl_session_t *session, knl_cursor_t *cursor)
{
    date_t analyze_time;
    knl_scn_t analyze_scn;
    knl_dictionary_t dc;
    db_get_sys_dc(session, SYS_TEMP_HISTGRAM_ID, &dc);

    if (CURSOR_COLUMN_SIZE(cursor, SYS_TABLE_COL_ANALYZETIME) != CT_NULL_VALUE_LEN) {
        analyze_time = *(date_t*)CURSOR_COLUMN_DATA(cursor, SYS_TABLE_COL_ANALYZETIME);
        if (knl_timestamp_to_scn(session, analyze_time, &analyze_scn) != CT_SUCCESS) {
            return CT_TRUE;
        }

        return dc.org_scn > analyze_scn;
    }

    return CT_FALSE;
}

status_t stats_clean_spc_stats(knl_session_t *session, space_t *space)
{
    knl_cursor_t *cursor = NULL;
    uint32 table_id;
    uint32 user_id;
    uint32 space_id;
    stats_table_t tab_stats;
    errno_t ret;
    bool32 is_old_nologging = CT_FALSE;

    knl_set_session_scn(session, CT_INVALID_ID64);
    CM_SAVE_STACK(session->stack);
    cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_TABLE_ID, CT_INVALID_ID32);
    cursor->isolevel = ISOLATION_CURR_COMMITTED;

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    ret = memset_sp(&tab_stats, sizeof(stats_table_t), 0, sizeof(stats_table_t));
    knl_securec_check(ret);

    while (!cursor->eof) {
        space_id = (*(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_TABLE_COL_SPACE_ID));
        if (space_id == space->ctrl->id) {
            user_id = (*(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_TABLE_COL_USER_ID));
            table_id = (*(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_TABLE_COL_ID));
            is_old_nologging = stats_check_old_nologging(session, cursor);
            if (stats_delete_table_stats(session, user_id, table_id, is_old_nologging) != CT_SUCCESS) {
                knl_rollback(session, NULL);
            } else {
                knl_commit(session);
            }
        }

        if (knl_fetch(session, cursor) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);

    return CT_SUCCESS;
}

void stats_clean_nologging_stats(knl_session_t *session)
{
    if (DB_IS_READONLY(session) || DB_IS_MAINTENANCE(session)) {
        return;
    }

    /* drop table after undo complete, otherwise we cannot lock_table_directly when truncate table */
    while (DB_IN_BG_ROLLBACK(session)) {
        if (session->canceled) {
            return;
        }

        if (session->killed) {
            return;
        }

        cm_sleep(100);
    }

    if (db_truncate_sys_table(session, SYS_TEMP_HISTGRAM_ID) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("failed to truncate SYS_TEMP_HISTGRAM when cleaning nologging data.");
    }

    if (db_truncate_sys_table(session, SYS_TEMP_HIST_HEAD_ID) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("failed to truncate SYS_TEMP_HIST_HEAD when cleaning nologging data.");
    }

    space_t *space = NULL;

    /* skip built-in tablespace */
    for (uint32 i = 0; i < CT_MAX_SPACES; i++) {
        space = SPACE_GET(session, i);
        if (!spc_need_clean(space)) {
            continue;
        }

        if (stats_clean_spc_stats(session, space) != CT_SUCCESS) {
            continue;
        }
    }
}

static status_t stats_gather_empty_table(knl_session_t *session, knl_dictionary_t *dc, bool32 *is_empty,
                                         bool32 is_dynamic)
{
    stats_table_t tab_stats;
    stats_index_t index_stats;
    stats_col_handler_t *column_handler = NULL;
    dc_entity_t *entity = DC_ENTITY(dc);
    table_t *table = &entity->table;
    index_t *idx = NULL;
    knl_column_t *column = NULL;
    errno_t ret;
    bool32 no_segment = CT_TRUE;

    if (stats_check_empty_table(session, dc, &no_segment) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (!no_segment) {
        *is_empty = CT_FALSE;
        return CT_SUCCESS;
    }

    /* stats for ltt or trans gtt doesn't be writen in system table */
    if (IS_LTT_BY_NAME(table->desc.name) || table->desc.type == TABLE_TYPE_TRANS_TEMP) {
        return CT_SUCCESS;
    }

    if (table->desc.type == TABLE_TYPE_SESSION_TEMP && is_dynamic) {
        return CT_SUCCESS;
    }

    ret = memset_sp(&tab_stats, sizeof(stats_table_t), 0, sizeof(stats_table_t));
    knl_securec_check(ret);

    tab_stats.is_dynamic = is_dynamic;
    tab_stats.is_part = IS_PART_TABLE(table);
    // if the table is not empty, we just start one  auto session to commit statistics of columns when dynamic statistics
    // there are 3 sys tables(sys_columns,sys_histgram,sys_hist_abstr) will be written for columns statistics,
    // for empty table we only write sys_columns.
    if (stats_try_begin_auton_rm(session, is_dynamic) != CT_SUCCESS) {
        return CT_ERROR;
    }

    // statistics infos of empty table will be set zero
    column_handler = (stats_col_handler_t *)cm_push(session->stack, sizeof(stats_col_handler_t));
    ret = memset_s(column_handler, sizeof(stats_col_handler_t), 0, sizeof(stats_col_handler_t));
    knl_securec_check(ret);
    column_handler->max_value.len = CT_NULL_VALUE_LEN;
    column_handler->min_value.len = CT_NULL_VALUE_LEN;

    column_handler->stats_cur = knl_push_cursor(session);
    for (uint32 i = 0; i < entity->column_count; i++) {
        column = dc_get_column(entity, i);
        column_handler->column = column;

        if (stats_update_sys_column(session, column_handler, is_dynamic) != CT_SUCCESS) {
            cm_pop(session->stack);
            stats_internal_rollback(session, &tab_stats);
            stats_try_end_auton_rm(session, CT_ERROR, is_dynamic);
            return CT_ERROR;
        }
    }
    cm_pop(session->stack);
    stats_try_end_auton_rm(session, CT_SUCCESS, is_dynamic);

    ret = memset_sp(&index_stats, sizeof(stats_index_t), 0, sizeof(stats_index_t));
    knl_securec_check(ret);
    for (uint32 i = 0; i < table->index_set.count; i++) {
        idx = table->index_set.items[i];

        index_stats.uid = idx->desc.uid;
        index_stats.name.str = idx->desc.name;
        index_stats.table_id = idx->desc.table_id;
        // index name is smaller than 68
        index_stats.name.len = (uint16)strlen(idx->desc.name);
        index_stats.is_dynamic = is_dynamic;

        if (IS_PART_INDEX(idx)) {
            // to update indexpart$
            if (stats_update_empty_sys_indexparts(session, idx, &index_stats, CT_INVALID_ID32) != CT_SUCCESS) {
                stats_internal_rollback(session, &tab_stats);
                return CT_ERROR;
            }
        } else {
            if (stats_update_sys_index(session, &index_stats) != CT_SUCCESS) {
                stats_internal_rollback(session, &tab_stats);
                return CT_ERROR;
            }
        }
    }
    
    if (IS_PART_TABLE(table)) {
        // to update tablepart$
        if (stats_update_empty_sys_tablepart(session, dc, &tab_stats, CT_INVALID_ID32) != CT_SUCCESS) {
            stats_internal_rollback(session, &tab_stats);
            return CT_ERROR;
        }
    }

    /*
     * we should set statistics to 0 in sys_tables when table is empty no matter it is partition table or not
     */
    if (stats_update_sys_table(session, &tab_stats, dc) != CT_SUCCESS) {
        stats_internal_rollback(session, &tab_stats);
        return CT_ERROR;
    }

    stats_internal_commit(session, &tab_stats);
    *is_empty = CT_TRUE;
    return CT_SUCCESS;
}

static void stats_init_table_stats(knl_dictionary_t *dc, stats_table_t *table_stats, stats_option_t stats_option,
                                   bool8 single_part_analyze, uint32 specify_part_id)
{
    table_t *table = DC_TABLE(dc);
    errno_t ret;

    ret = memset_s(table_stats, sizeof(stats_table_t), 0, sizeof(stats_table_t));
    knl_securec_check(ret);
    table_stats->uid = dc->uid;
    table_stats->tab_id = dc->oid;
    table_stats->estimate_sample_ratio = stats_option.sample_ratio;
    table_stats->stats_option = stats_option;

    if (!IS_PART_TABLE(table)) {
        table_stats->is_part = CT_FALSE;
        table_stats->part_stats.part_id = CT_INVALID_ID32;
        table_stats->part_stats.part_no = CT_INVALID_ID32;
    }

    table_stats->single_part_analyze = single_part_analyze;
    table_stats->specify_part_id = specify_part_id;
    table_stats->part_sample_ratio = stats_option.sample_ratio;
}

static status_t stats_gather_each_table_part(knl_session_t *session, knl_dictionary_t *dc,
    stats_tab_context_t *tab_ctx, table_part_t *table_part)
{
    stats_table_t *table_stats = tab_ctx->table_stats;
    bool32 is_empty = CT_FALSE;
    stats_part_table_t sub_part;

    if (!IS_PARENT_TABPART(&table_part->desc) && !table_part->heap.loaded) {
        if (dc_load_table_part_segment(session, dc->handle, table_part) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (IS_PARENT_TABPART(&table_part->desc)) {
        if (stats_gather_table_subpart(session, dc, table_part, tab_ctx, &sub_part) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } else {
        /*
         * if some table part is empty,we should set statistics to 0  and write current time for statistics time in
         * sys_tableparts and sys_indexpart
         */
        if (stats_try_gather_empty_part(session, dc, table_part, &is_empty, table_stats->is_dynamic) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (is_empty) {
            return CT_SUCCESS;
        }

        if (stats_gather_part_columns(session, dc, tab_ctx) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    bool32 is_parent = IS_PARENT_TABPART(&table_part->desc);
    stats_calc_global_table_stats(table_stats, is_parent);

    if (table_stats->part_stats.is_subpart && table_stats->part_stats.info.rows != 0) {
        table_stats->part_stats.info.avg_row_len = stats_calc_row_avg_len(table_stats->part_stats.info);
    }

    if (stats_update_sys_tablepart(session, dc, table_stats) != CT_SUCCESS) {
        stats_rollback(session, table_stats->is_dynamic);
        return CT_ERROR;
    }
    stats_commit(session, table_stats->is_dynamic);

    if (stats_gather_part_index(session, dc, tab_ctx) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

/*
 * gather statistics of all table parts
 * 1. analyze all table parts, generate all parts statistics and the global statistics including table,index,
 *    columns statistics
 * 2. analyze the part table using specifying part such as DBE_STATS.COLLECT_TABLE_STATS(user_name,table_name,part_name)
 *    when the global table statistics is not existed.
 * @note we need use this interface when analyzing specified table part and the global table statistics is not existed.
 * @attention this interface only generates the global column statistics when analyzing specified table part
 */
status_t stats_gather_all_table_parts(knl_session_t *session, knl_dictionary_t *dc, stats_tab_context_t *tab_ctx)
{
    stats_table_t *table_stats = tab_ctx->table_stats;
    mtrl_context_t *temp_ctx = tab_ctx->mtrl_tab_ctx;
    uint32 temp_seg = tab_ctx->mtrl_tab_seg;
    table_t *table = DC_TABLE(dc);
    part_table_t *part_table = table->part_table;
    double ori_sample_ratio = table_stats->estimate_sample_ratio;

    for (uint32 i = 0; i < part_table->desc.partcnt; i++) {
        table_part_t *table_part = TABLE_GET_PART(table, i);
        if (!IS_READY_PART(table_part)) {
            continue;
        }
        table_stats->is_part = CT_TRUE;

        errno_t ret = memset_s(&table_stats->part_stats, sizeof(stats_part_table_t), 0, sizeof(stats_part_table_t));
        knl_securec_check(ret);
        table_stats->part_stats.part_no = i;
        table_stats->part_stats.part_id = table_part->desc.part_id;
        table_stats->estimate_sample_ratio = ori_sample_ratio;

        if (stats_gather_each_table_part(session, dc, tab_ctx, table_part) != CT_SUCCESS) {
            int32 err_code = cm_get_error_code();
            if (!IS_PART_DROPPED_OR_TRUNCATED(err_code)) {
                return CT_ERROR;
            }

            cm_reset_error();
            CT_LOG_RUN_WAR("CT-%d, fail to gather the %s partition %s, it or its subpartition has been dropped or truncated.",
                err_code, table->desc.name, table_part->desc.name);
        }
    }

    if (table_stats->tab_info.rows != 0) {
        table_stats->estimate_sample_ratio = ((double)(table_stats->tab_info.sample_size) / table_stats->tab_info.rows);
        table_stats->tab_info.avg_row_len = stats_calc_row_avg_len(table_stats->tab_info);
    }

    if (IS_FULL_SAMPLE(table_stats->estimate_sample_ratio - STATS_SAMPLE_MAX_RATIO)) {
        table_stats->estimate_sample_ratio = STATS_FULL_TABLE_SAMPLE_RATIO;
    }

    if (stats_gather_global_columns_stats(session, dc, table_stats, temp_ctx, temp_seg) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t stats_gather_part_table(knl_session_t *session, knl_dictionary_t *dc, stats_tab_context_t *tab_ctx)
{
    stats_table_t *table_stats = tab_ctx->table_stats;
    dc_entity_t *entity = DC_ENTITY(dc);

    /*
     * we need to estimate the statistics of global table when analyze one part, cbo_table_stats of entity recodes
     * global statistics of all parts. When we analyzed some one part, we will use the part statistics analyzed right
     * now and global statistics of all parts in entity to estimate the newest statistics of global table.So we need
     * judge cbo statistics is existed in dictionary cache or not.
     */
    if (table_stats->single_part_analyze && STATS_GLOBAL_CBO_STATS_EXIST(entity)) {
        /* only analyze single table part */
        return stats_gather_single_table_part(session, dc, tab_ctx);
    }

    /* analyze all table parts, but only generate table statistics and not update histgram of all parts,
     * and using every statistics of table part to estimate the statistics of global table
     */
    return stats_gather_all_table_parts(session, dc, tab_ctx);
}

static void stats_init_temp_ctx(knl_session_t *session, mtrl_context_t *temp_ctx)
{
    errno_t  ret;

    ret = memset_sp(temp_ctx, sizeof(mtrl_context_t), 0, sizeof(mtrl_context_t));
    knl_securec_check(ret);
    mtrl_init_context(temp_ctx, session);
    temp_ctx->sort_cmp = NULL;
}

status_t stats_prepare_table_context(knl_session_t *session, stats_tab_context_t *table_ctx)
{
    mtrl_context_t *temp_ctx = table_ctx->mtrl_tab_ctx;

    stats_init_temp_ctx(session, temp_ctx);

    if (mtrl_create_segment(temp_ctx, MTRL_SEGMENT_TEMP, NULL, &table_ctx->mtrl_tab_seg) != CT_SUCCESS) {
        mtrl_release_context(temp_ctx);
        return CT_ERROR;
    }

    if (mtrl_open_segment(temp_ctx, table_ctx->mtrl_tab_seg) != CT_SUCCESS) {
        mtrl_release_context(temp_ctx);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t stats_gather_table_part(knl_session_t *session, knl_dictionary_t *dc, stats_option_t stats_option,
                                 table_part_t *table_part, bool32 is_dynamic)
{
    stats_tab_context_t tab_ctx;
    stats_table_t table_stats;
    mtrl_context_t *mtrl_tab_ctx = NULL;
    errno_t ret;
    bool32 force_sample = session->kernel->attr.enable_sample_limit;
    table_t *table = DC_TABLE(dc);
    stats_init_table_stats(dc, &table_stats, stats_option, CT_TRUE, table_part->desc.part_id);
    
    /*
     * if sample_ratio is equal to 0, it means we need to scan full table to generate statistics
     * it will generate too much buffer page exchange with PAGE IN hard disk., so we must check
     * size of table is Satisfied with default sample size in config
     */
    stats_estimate_sample_ratio(session, dc, &table_stats, force_sample);
    table_stats.is_dynamic = is_dynamic;
    table_stats.is_nologging = IS_NOLOGGING_BY_TABLE_TYPE(table->desc.type);
    CM_SAVE_STACK(session->stack);
    mtrl_tab_ctx = (mtrl_context_t *)cm_push(session->stack, sizeof(mtrl_context_t));
    ret = memset_s(mtrl_tab_ctx, sizeof(mtrl_context_t), 0, sizeof(mtrl_context_t));
    knl_securec_check(ret);

    tab_ctx.table_stats = &table_stats;
    tab_ctx.mtrl_tab_ctx = mtrl_tab_ctx;

    if (stats_prepare_table_context(session, &tab_ctx) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    if (stats_gather_part_table(session, dc, &tab_ctx) != CT_SUCCESS) {
        mtrl_release_context(mtrl_tab_ctx);
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    if (stats_gather_indexes(session, dc, &table_stats, mtrl_tab_ctx, tab_ctx.mtrl_tab_seg) != CT_SUCCESS) {
        mtrl_release_context(mtrl_tab_ctx);
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    if (stats_gather_table(session, dc, &table_stats) != CT_SUCCESS) {
        mtrl_release_context(mtrl_tab_ctx);
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    if (table_stats.stats_option.is_report) {
        mtrl_release_context(mtrl_tab_ctx);
        CM_RESTORE_STACK(session->stack);
        return CT_SUCCESS;
    }
    
    if (db_delete_mon_sysmods(session, dc->uid, dc->oid, table_part->desc.part_id, is_dynamic) != CT_SUCCESS) {
        mtrl_release_context(mtrl_tab_ctx);
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    mtrl_release_context(mtrl_tab_ctx);
    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}

status_t stats_gather_normal_table(knl_session_t *session, knl_dictionary_t *dc, stats_option_t stats_option,
                                   bool32 is_dynamic)
{
    table_t *table = DC_TABLE(dc);
    bool32 is_empty = CT_FALSE;
    stats_table_t table_stats;
    mtrl_context_t *mtrl_tab_ctx = NULL;
    stats_tab_context_t table_ctx;
    bool32 force_sample = session->kernel->attr.enable_sample_limit;
    bool8 is_report = stats_option.is_report;

    if (is_report) {
        if (stats_init_report_file(session, DC_ENTITY(dc), &stats_option) != CT_SUCCESS) {
            stats_close_report_file(is_report, &stats_option);
            return CT_ERROR;
        }
    }
    
    if (stats_gather_empty_table(session, dc, &is_empty, is_dynamic) != CT_SUCCESS) {
        stats_close_report_file(is_report, &stats_option);
        return CT_ERROR;
    }

    if (is_empty) {
        stats_close_report_file(is_report, &stats_option);
        return CT_SUCCESS;
    }

    stats_init_table_stats(dc, &table_stats, stats_option, CT_FALSE, CT_INVALID_ID32);

    /*
     * if sample_ratio is equal to 0, it means we need to scan full table to generate statistics
     * it will generate too much buffer page exchange with PAGE IN hard disk., so we must check
     * size of table is Satisfied with default sample size in config
     */
    stats_estimate_sample_ratio(session, dc, &table_stats, force_sample);
    table_stats.is_dynamic = is_dynamic;
    table_stats.is_nologging = IS_NOLOGGING_BY_TABLE_TYPE(table->desc.type);
    CM_SAVE_STACK(session->stack);
    mtrl_tab_ctx = (mtrl_context_t *)cm_push(session->stack, sizeof(mtrl_context_t));
    
    table_ctx.table_stats = &table_stats;
    table_ctx.mtrl_tab_ctx = mtrl_tab_ctx;

    if (stats_prepare_table_context(session, &table_ctx) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        stats_close_report_file(is_report, &stats_option);
        return CT_ERROR;
    }

    /*
     * modify table will update column$ and update table$, we must ensure
     * analyze table first update column$,second update table$ for preventing deadlock
     */
    if (IS_PART_TABLE(table)) {
        if (stats_gather_part_table(session, dc, &table_ctx) != CT_SUCCESS) {
            mtrl_release_context(mtrl_tab_ctx);
            CM_RESTORE_STACK(session->stack);
            stats_close_report_file(is_report, &stats_option);
            return CT_ERROR;
        }
    } else {
        if (stats_create_mtrl_table(session, dc, &table_ctx) != CT_SUCCESS) {
            mtrl_release_context(mtrl_tab_ctx);
            CM_RESTORE_STACK(session->stack);
            stats_close_report_file(is_report, &stats_option);
            return CT_ERROR;
        }

        if (stats_gather_columns(session, DC_ENTITY(dc), &table_stats, mtrl_tab_ctx, table_ctx.mtrl_tab_seg) != CT_SUCCESS) {
            mtrl_release_context(mtrl_tab_ctx);
            CM_RESTORE_STACK(session->stack);
            stats_close_report_file(is_report, &stats_option);
            return CT_ERROR;
        }
    }

    if (stats_gather_indexes(session, dc, &table_stats, mtrl_tab_ctx, table_ctx.mtrl_tab_seg) != CT_SUCCESS) {
        mtrl_release_context(mtrl_tab_ctx);
        CM_RESTORE_STACK(session->stack);
        stats_close_report_file(is_report, &stats_option);
        return CT_ERROR;
    }

    if (stats_gather_table(session, dc, &table_stats) != CT_SUCCESS) {
        mtrl_release_context(mtrl_tab_ctx);
        CM_RESTORE_STACK(session->stack);
        stats_close_report_file(is_report, &stats_option);
        return CT_ERROR;
    }

    if (is_report) {
        mtrl_release_context(mtrl_tab_ctx);
        CM_RESTORE_STACK(session->stack);
        stats_close_report_file(is_report, &stats_option);
        return CT_SUCCESS;
    }

    if (db_delete_mon_sysmods(session, table->desc.uid, table->desc.id, CT_INVALID_ID32,
                              is_dynamic) != CT_SUCCESS) {
        mtrl_release_context(mtrl_tab_ctx);
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    mtrl_release_context(mtrl_tab_ctx);
    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}

static void stats_init_temp_sample(knl_session_t *session, stats_table_t *table_stats)
{
    mtrl_segment_t *segment;

    segment = session->temp_mtrl->segments[table_stats->temp_table->table_cache->table_segid];
    table_stats->temp_table->first_pageid = segment->vm_list.first;
    table_stats->temp_table->prev_sample_pageid = CT_INVALID_ID32;

    if (table_stats->estimate_sample_ratio < CT_REAL_PRECISION) {
        table_stats->temp_table->sample_pages = segment->vm_list.count;
    } else {
        table_stats->temp_table->sample_pages = (uint32)(segment->vm_list.count * table_stats->estimate_sample_ratio);
    }

    if (table_stats->temp_table->sample_pages == 0) {
        table_stats->temp_table->sample_pages = 1;
        table_stats->estimate_sample_ratio = (double)table_stats->temp_table->sample_pages / segment->vm_list.count;
    }
}

status_t stats_gather_temp_table(knl_session_t *session, knl_dictionary_t *dc, stats_option_t stats_option,
                                 bool32 is_dynamic)
{
    stats_tab_context_t tab_ctx;
    stats_table_t table_stats;
    stats_tmptab_t temp_table;
    dc_entity_t *entity = DC_ENTITY(dc);
    bool32 is_empty = CT_TRUE;
    bool8 is_report = stats_option.is_report;

    if (is_report) {
        if (stats_init_report_file(session, entity, &stats_option) != CT_SUCCESS) {
            stats_close_report_file(is_report, &stats_option);
            return CT_ERROR;
        }
    }

    stats_init_table_stats(dc, &table_stats, stats_option, CT_FALSE, CT_INVALID_ID32);
    errno_t ret = memset_s(&temp_table, sizeof(stats_tmptab_t), 0, sizeof(stats_tmptab_t));
    knl_securec_check(ret);

    table_stats.temp_table = &temp_table;
    table_stats.temp_table->table_cache = NULL;

    if (knl_ensure_temp_cache(session, entity, &table_stats.temp_table->table_cache) != CT_SUCCESS) {
        stats_close_report_file(is_report, &stats_option);
        return CT_ERROR;
    }
    table_stats.is_dynamic = is_dynamic;

    if (stats_gather_empty_table(session, dc, &is_empty, is_dynamic) != CT_SUCCESS) {
        stats_close_report_file(is_report, &stats_option);
        return CT_ERROR;
    }

    if (is_empty) {
        stats_close_report_file(is_report, &stats_option);
        return CT_SUCCESS;
    }

    stats_init_temp_sample(session, &table_stats);

    if (cbo_alloc_temp_table_stats(session, entity, table_stats.temp_table->table_cache, is_dynamic) != CT_SUCCESS) {
        stats_close_report_file(is_report, &stats_option);
        return CT_ERROR;
    }

    CM_SAVE_STACK(session->stack);
    mtrl_context_t *mtrl_tab_ctx = (mtrl_context_t *)cm_push(session->stack, sizeof(mtrl_context_t));
    stats_init_temp_ctx(session, mtrl_tab_ctx);

    tab_ctx.table_stats = &table_stats;
    tab_ctx.mtrl_tab_ctx = mtrl_tab_ctx;

    if (stats_prepare_table_context(session, &tab_ctx) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        stats_close_report_file(is_report, &stats_option);
        return CT_ERROR;
    }

    if (stats_create_mtrl_table(session, dc, &tab_ctx) != CT_SUCCESS) {
        mtrl_release_context(mtrl_tab_ctx);
        CM_RESTORE_STACK(session->stack);
        stats_close_report_file(is_report, &stats_option);
        return CT_ERROR;
    }

    if (stats_gather_columns(session, DC_ENTITY(dc), &table_stats, mtrl_tab_ctx, tab_ctx.mtrl_tab_seg) != CT_SUCCESS) {
        mtrl_release_context(mtrl_tab_ctx);
        CM_RESTORE_STACK(session->stack);
        stats_close_report_file(is_report, &stats_option);
        return CT_ERROR;
    }

    if (stats_gather_indexes(session, dc, &table_stats, mtrl_tab_ctx, tab_ctx.mtrl_tab_seg) != CT_SUCCESS) {
        mtrl_release_context(mtrl_tab_ctx);
        CM_RESTORE_STACK(session->stack);
        stats_close_report_file(is_report, &stats_option);
        return CT_ERROR;
    }

    if (stats_gather_table(session, dc, &table_stats) != CT_SUCCESS) {
        mtrl_release_context(mtrl_tab_ctx);
        CM_RESTORE_STACK(session->stack);
        stats_close_report_file(is_report, &stats_option);
        return CT_ERROR;
    }

    mtrl_release_context(mtrl_tab_ctx);
    CM_RESTORE_STACK(session->stack);
    stats_close_report_file(is_report, &stats_option);
    return CT_SUCCESS;
}

static heap_segment_t *stats_get_part_heap_segment(knl_session_t *session,
    table_t *table, table_part_t *table_part)
{
    heap_segment_t *heap_seg = NULL;
    table_part_t *table_subpart = NULL;

    if (!IS_PARENT_TABPART(&table_part->desc)) {
        if (!STATS_IS_INVALID_PART_TABLE(table_part)) {
            heap_seg = HEAP_SEGMENT(session, table_part->heap.entry, table_part->heap.segment);
        }
        return heap_seg;
    }

    for (uint32 i = 0; i < table_part->desc.subpart_cnt; i++) {
        table_subpart = PART_GET_SUBENTITY(table->part_table, table_part->subparts[i]);
        if (!STATS_IS_INVALID_PART_TABLE(table_subpart)) {
            return HEAP_SEGMENT(session, table_subpart->heap.entry, table_subpart->heap.segment);
        }
    }

    return NULL;
}

static heap_segment_t *stats_get_heap_segment(knl_session_t *session, table_t *table)
{
    heap_segment_t *heap_seg = NULL;
    table_part_t *table_part = NULL;

    if (!IS_PART_TABLE(table)) {
        if (table->heap.segment == NULL) {
            return NULL;
        }
        return HEAP_SEGMENT(session, table->heap.entry, table->heap.segment);
    }

    for (uint32 i = 0; i < table->part_table->desc.partcnt; i++) {
        table_part = TABLE_GET_PART(table, i);
        if (table_part != NULL) {
            heap_seg = stats_get_part_heap_segment(session, table, table_part);
            if (heap_seg != NULL) {
                break;
            }
        }
    }

    return heap_seg;
}

static btree_segment_t *stats_get_part_btree_segment(knl_session_t *session,
    index_t *idx, index_part_t *index_part)
{
    btree_segment_t *btree_seg = NULL;
    index_part_t *index_subpart = NULL;

    if (!IS_PARENT_IDXPART(&index_part->desc)) {
        if (!STATS_IS_INVALID_PART_INDEX(index_part)) {
            btree_seg = BTREE_SEGMENT(session, index_part->btree.entry, index_part->btree.segment);
        }

        return btree_seg;
    }

    for (uint32 i = 0; i < index_part->desc.subpart_cnt; i++) {
        index_subpart = PART_GET_SUBENTITY(idx->part_index, index_part->subparts[i]);
        if (!STATS_IS_INVALID_PART_INDEX(index_subpart)) {
            return BTREE_SEGMENT(session, index_subpart->btree.entry, index_subpart->btree.segment);
        }
    }

    return NULL;
}

static btree_segment_t *stats_get_btree_segment(knl_session_t *session, index_t *idx)
{
    btree_segment_t *btree_seg = NULL;
    index_part_t *index_part = NULL;

    if (!IS_PART_INDEX(idx)) {
        if (idx->btree.segment == NULL) {
            return NULL;
        }
        return BTREE_SEGMENT(session, idx->btree.entry, idx->btree.segment);
    }

    for (uint32 i = 0; i < idx->part_index->desc.partcnt; i++) {
        index_part = INDEX_GET_PART(idx, i);
        if (index_part != NULL) {
            btree_seg = stats_get_part_btree_segment(session, idx, index_part);
            if (btree_seg != NULL) {
                break;
            }
        }
    }

    return btree_seg;
}

static bool32 stats_check_segment_dropped(knl_session_t *session, table_t *table, index_t *idx)
{
    heap_segment_t *heap_seg = stats_get_heap_segment(session, table);
    if (heap_seg == NULL) {
        return CT_TRUE;
    }

    btree_segment_t *btree_seg = stats_get_btree_segment(session, idx);
    if (btree_seg == NULL) {
        return CT_TRUE;
    }

    return CT_FALSE;
}

static status_t stats_sample_stats_one_btree(knl_session_t *session, btree_t *btree, btree_info_t *info,
                                             double sample_ratio)
{
    btree_segment_t *segment = (btree_segment_t *)btree->segment;
    knl_tree_info_t tree_info;
    page_id_t page_id;
    page_id_t prev_page_id = INVALID_PAGID;
    btree_key_t *compare_bkey = NULL;
    pcrb_key_t *compare_pkey = NULL;

    if (segment == NULL) {
        return CT_SUCCESS;
    }

    tree_info.value = cm_atomic_get(&segment->tree_info.value);
    info->height = (uint32)tree_info.level;

    if (btree_level_first_page(session, btree, 1, &page_id) != CT_SUCCESS) {
        return CT_ERROR;
    }

    CM_SAVE_STACK(session->stack);
    if (info->height == 1) {
        if (btree->index->desc.cr_mode == CR_PAGE) {
            compare_pkey = (pcrb_key_t *)cm_push(session->stack, CT_KEY_BUF_SIZE);
            compare_pkey->is_infinite = CT_TRUE;
            compare_pkey->size = sizeof(pcrb_key_t);
            pcrb_stats_leaf_page(session, btree, info, &page_id, &prev_page_id, compare_pkey);
        } else {
            compare_bkey = (btree_key_t *)cm_push(session->stack, CT_KEY_BUF_SIZE);
            compare_bkey->is_infinite = CT_TRUE;
            compare_bkey->size = sizeof(btree_key_t);
            btree_stats_leaf_page(session, btree, info, &page_id, &prev_page_id, compare_bkey);
        }
    } else {
        if (btree->index->desc.cr_mode == CR_PAGE) {
            if (pcrb_stats_leaf_by_parent(session, btree, sample_ratio, info, page_id) != CT_SUCCESS) {
                CM_RESTORE_STACK(session->stack);
                return CT_ERROR;
            }
        } else {
            if (btree_stats_leaf_by_parent(session, btree, sample_ratio, info, page_id) != CT_SUCCESS) {
                CM_RESTORE_STACK(session->stack);
                return CT_ERROR;
            }
        }
    }

    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}

static inline void stats_init_stats_index(stats_index_t *stats_idx, index_t *idx)
{
    errno_t ret = memset_sp(stats_idx, sizeof(stats_index_t), 0, sizeof(stats_index_t));
    knl_securec_check(ret);

    stats_idx->is_subpart = CT_FALSE;
    stats_idx->subpart_id = CT_INVALID_ID32;
    stats_idx->part_id = CT_INVALID_ID32;
    stats_idx->uid = idx->desc.uid;
    stats_idx->table_id = idx->desc.table_id;
    stats_idx->idx_id = idx->desc.id;
}

static status_t stats_save_btree_stats(knl_session_t *session, index_t *idx, stats_index_t *stats_idx,
                                       btree_segment_t *segment, bool32 is_dynamic)
{
    space_t *space = SPACE_GET(session, segment->space_id);

    stats_idx->clus_factor = stats_idx->info.clustor;
    stats_idx->is_dynamic = is_dynamic;
    stats_idx->sample_size = stats_idx->info.keys - 1; // 1 is minimum key

    if (stats_idx->part_id == CT_INVALID_ID32) {
        stats_idx->name.str = idx->desc.name;
        stats_idx->name.len = (uint32)strlen(idx->desc.name);
    } else {
        stats_idx->name.str = stats_idx->part_index->desc.name;
        stats_idx->name.len = (uint32)strlen(stats_idx->part_index->desc.name);
    }

    if (stats_idx->info.distinct_keys == 0) {
        stats_idx->avg_data_key = 0;
        stats_idx->avg_leaf_key = 0;
    } else {
        uint32 recycled_cnt = segment->del_pages.count + segment->recycled_pages.count;
        stats_idx->avg_leaf_key = (double)stats_idx->info.leaf_blocks / (double)stats_idx->info.distinct_keys;
        stats_idx->avg_data_key = (double)(btree_get_segment_page_count(space, segment) -
            recycled_cnt) / (double)stats_idx->info.distinct_keys;
    }

    stats_calc_index_empty_size(session, idx->entity, idx, stats_idx);
    if (stats_idx->part_id == CT_INVALID_ID32) {
        if (stats_update_sys_index(session, stats_idx) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } else if (stats_idx->subpart_id == CT_INVALID_ID32) {
        if (stats_update_sys_indexpart(session, stats_idx) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } else {
        if (stats_update_sys_subindexpart(session, stats_idx) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static status_t stats_sample_stats_btree_subpart(knl_session_t *session, index_t *idx,
    index_part_t *index_part, double sample_ratio, bool32 is_dynamic)
{
    index_part_t *index_subpart = NULL;
    stats_index_t stats_idx;

    for (uint32 i = 0; i < index_part->desc.subpart_cnt; i++) {
        index_subpart = PART_GET_SUBENTITY(idx->part_index, index_part->subparts[i]);
        if (STATS_IS_INVALID_PART_INDEX(index_subpart)) {
            continue;
        }

        stats_init_stats_index(&stats_idx, idx);
        stats_idx.part_id = index_part->desc.part_id;
        stats_idx.subpart_id = index_subpart->desc.part_id;
        stats_idx.part_index = index_subpart;
        stats_idx.is_subpart = CT_TRUE;

        if (stats_sample_stats_one_btree(session, &index_subpart->btree,
            &stats_idx.info, sample_ratio) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (stats_save_btree_stats(session, idx, &stats_idx,
            (btree_segment_t *)index_subpart->btree.segment, is_dynamic) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    stats_init_stats_index(&stats_idx, idx);
    stats_idx.part_id = index_part->desc.part_id;
    stats_idx.name.str = index_part->desc.name;
    stats_idx.name.len = (uint16)strlen(index_part->desc.name); // index name len is not greater than 68

    return stats_update_sys_indexpart(session, &stats_idx);
}

static status_t stats_sample_stats_btree_part(knl_session_t *session, index_t *idx,
    double sample_ratio, bool32 is_dynamic)
{
    index_part_t *index_part = NULL;
    stats_index_t stats_idx;

    for (uint32 i = 0; i < idx->part_index->desc.partcnt; i++) {
        index_part = INDEX_GET_PART(idx, i);
        if (index_part == NULL) {
            continue;
        }

        if (!IS_PARENT_IDXPART(&index_part->desc)) {
            if (STATS_IS_INVALID_PART_INDEX(index_part)) {
                continue;
            }

            stats_init_stats_index(&stats_idx, idx);
            stats_idx.part_id = index_part->desc.part_id;
            stats_idx.part_index = index_part;

            if (stats_sample_stats_one_btree(session, &index_part->btree,
                &stats_idx.info, sample_ratio) != CT_SUCCESS) {
                return CT_ERROR;
            }

            if (stats_save_btree_stats(session, idx, &stats_idx,
                (btree_segment_t *)index_part->btree.segment, is_dynamic) != CT_SUCCESS) {
                return CT_ERROR;
            }
        } else {
            if (stats_sample_stats_btree_subpart(session, idx, index_part,
                sample_ratio, is_dynamic) != CT_SUCCESS) {
                return CT_ERROR;
            }
        }
    }

    stats_init_stats_index(&stats_idx, idx);
    stats_idx.name.str = idx->desc.name;
    stats_idx.name.len = (uint16)strlen(idx->desc.name);

    return stats_update_sys_index(session, &stats_idx);
}

static status_t stats_sample_stats_btree(knl_session_t *session, index_t *idx, double sample_ratio, bool32 is_dynamic)
{
    stats_index_t stats_idx;

    if (!IS_PART_INDEX(idx)) {
        stats_init_stats_index(&stats_idx, idx);

        if (stats_sample_stats_one_btree(session, &idx->btree, &stats_idx.info, sample_ratio) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (stats_save_btree_stats(session, idx, &stats_idx,
            (btree_segment_t *)idx->btree.segment, is_dynamic) != CT_SUCCESS) {
            return CT_ERROR;
        }

        return CT_SUCCESS;
    }

    return stats_sample_stats_btree_part(session, idx, sample_ratio, is_dynamic);
}

static status_t stats_full_stats_one_btree(knl_session_t *session, btree_t *btree, btree_info_t *info)
{
    if (btree->index->desc.cr_mode == CR_PAGE) {
        if (pcrb_full_stats_info(session, btree, info) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } else {
        if (btree_full_stats_info(session, btree, info) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static status_t stats_full_stats_btree_subpart(knl_session_t *session, index_t *idx,
    index_part_t *index_part, bool32 is_dynamic)
{
    index_part_t *index_subpart = NULL;
    stats_index_t stats_idx;

    for (uint32 i = 0; i < index_part->desc.subpart_cnt; i++) {
        index_subpart = PART_GET_SUBENTITY(idx->part_index, index_part->subparts[i]);
        if (STATS_IS_INVALID_PART_INDEX(index_subpart)) {
            continue;
        }

        stats_init_stats_index(&stats_idx, idx);
        stats_idx.part_id = index_part->desc.part_id;
        stats_idx.subpart_id = index_subpart->desc.part_id;
        stats_idx.part_index = index_subpart;
        stats_idx.is_subpart = CT_TRUE;

        if (stats_full_stats_one_btree(session, &index_subpart->btree, &stats_idx.info) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (stats_save_btree_stats(session, idx, &stats_idx,
            (btree_segment_t *)index_subpart->btree.segment, is_dynamic) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    stats_init_stats_index(&stats_idx, idx);
    stats_idx.part_id = index_part->desc.part_id;
    stats_idx.name.str = index_part->desc.name;
    stats_idx.name.len = (uint16)strlen(index_part->desc.name); // index name len is not greater than 68

    return stats_update_sys_indexpart(session, &stats_idx);
}

static status_t stats_full_stats_btree_part(knl_session_t *session, index_t *idx, bool32 is_dynamic)
{
    index_part_t *index_part = NULL;
    stats_index_t stats_idx;

    for (uint32 i = 0; i < idx->part_index->desc.partcnt; i++) {
        index_part = INDEX_GET_PART(idx, i);
        if (index_part == NULL) {
            continue;
        }

        if (!IS_PARENT_IDXPART(&index_part->desc)) {
            if (STATS_IS_INVALID_PART_INDEX(index_part)) {
                continue;
            }

            stats_init_stats_index(&stats_idx, idx);
            stats_idx.part_id = index_part->desc.part_id;
            stats_idx.part_index = index_part;

            if (stats_full_stats_one_btree(session, &index_part->btree, &stats_idx.info) != CT_SUCCESS) {
                return CT_ERROR;
            }

            if (stats_save_btree_stats(session, idx, &stats_idx,
                (btree_segment_t *)index_part->btree.segment, is_dynamic) != CT_SUCCESS) {
                return CT_ERROR;
            }
        } else {
            if (stats_full_stats_btree_subpart(session, idx, index_part, is_dynamic) != CT_SUCCESS) {
                return CT_ERROR;
            }
        }
    }

    stats_init_stats_index(&stats_idx, idx);
    stats_idx.name.str = idx->desc.name;
    stats_idx.name.len = (uint16)strlen(idx->desc.name);

    return stats_update_sys_index(session, &stats_idx);
}

static status_t stats_full_stats_btree(knl_session_t *session, index_t *idx, bool32 is_dynamic)
{
    stats_index_t stats_idx;

    if (!IS_PART_INDEX(idx)) {
        stats_init_stats_index(&stats_idx, idx);

        if (stats_full_stats_one_btree(session, &idx->btree, &stats_idx.info) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (stats_save_btree_stats(session, idx, &stats_idx,
            (btree_segment_t *)idx->btree.segment, is_dynamic) != CT_SUCCESS) {
            return CT_ERROR;
        }
        return CT_SUCCESS;
    }

    return stats_full_stats_btree_part(session, idx, is_dynamic);
}

static status_t stats_write_empty_sys_index(knl_session_t *session, stats_index_t *stats_idx)
{
    if (stats_idx->part_id == CT_INVALID_ID32) {
        if (stats_update_sys_index(session, stats_idx) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } else if (stats_idx->subpart_id == CT_INVALID_ID32) {
        if (stats_update_sys_indexpart(session, stats_idx) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } else {
        if (stats_update_sys_subindexpart(session, stats_idx) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static status_t stats_write_empty_btree_stats(knl_session_t *session, index_t *idx)
{
    stats_index_t stats_idx;

    stats_init_stats_index(&stats_idx, idx);
    stats_idx.name.str = idx->desc.name;
    stats_idx.name.len = (uint16)strlen(idx->desc.name); // index name len is not greater than 68
    if (stats_write_empty_sys_index(session, &stats_idx) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (!IS_PART_INDEX(idx)) {
        return CT_SUCCESS;
    }

    for (uint32 i = 0; i < idx->part_index->desc.partcnt; i++) {
        index_part_t *index_part = INDEX_GET_PART(idx, i);
        if (index_part == NULL) {
            continue;
        }

        stats_init_stats_index(&stats_idx, idx);
        stats_idx.part_id = index_part->desc.part_id;
        stats_idx.name.str = index_part->desc.name;
        stats_idx.name.len = (uint16)strlen(index_part->desc.name);

        if (stats_write_empty_sys_index(session, &stats_idx) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (!IS_PARENT_IDXPART(&index_part->desc)) {
            continue;
        }

        for (int j = 0; j < index_part->desc.subpart_cnt; j++) {
            index_part_t *index_subpart = PART_GET_SUBENTITY(idx->part_index, index_part->subparts[j]);
            if (index_subpart == NULL) {
                continue;
            }

            stats_idx.subpart_id = index_subpart->desc.part_id;
            stats_idx.is_subpart = CT_TRUE;
            stats_idx.name.str = index_subpart->desc.name;
            stats_idx.name.len = (uint16)strlen(index_subpart->desc.name);
            if (stats_write_empty_sys_index(session, &stats_idx) != CT_SUCCESS) {
                return CT_ERROR;
            }
        }
    }

    return CT_SUCCESS;
}

static status_t stats_gather_btree_stats(knl_session_t *session, knl_dictionary_t *dc, index_t *idx,
                                         double sample_ratio, bool32 is_dynamic)
{
    table_t *table = DC_TABLE(dc);

    if (stats_check_segment_dropped(session, table, idx)) {
        if (stats_write_empty_btree_stats(session, idx) != CT_SUCCESS) {
            return CT_ERROR;
        }

        return CT_SUCCESS;
    }

    if (sample_ratio > CT_REAL_PRECISION) {
        if (stats_sample_stats_btree(session, idx, sample_ratio, is_dynamic) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } else {
        if (stats_full_stats_btree(session, idx, is_dynamic) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

status_t stats_gather_index_by_btree(knl_session_t *session, knl_dictionary_t *dc, knl_analyze_index_def_t *def,
                                     bool32 is_dynamic)
{
    table_t *table = NULL;
    dc_entity_t *entity = DC_ENTITY(dc);
    index_t *idx = NULL;
    uint32 i;

    table = &entity->table;
    if (table->index_set.count == 0) {
        return CT_SUCCESS;
    }

    for (i = 0; i < table->index_set.count; i++) {
        if (cm_text_str_equal(&def->name, table->index_set.items[i]->desc.name)) {
            idx = table->index_set.items[i];
            break;
        }
    }

    if (idx == NULL) {
        CT_THROW_ERROR(ERR_INDEX_NOT_EXIST, T2S(&def->owner), T2S_EX(&def->name));
        return CT_ERROR;
    }

    if (IS_FULL_SAMPLE(def->sample_ratio - STATS_SAMPLE_MAX_RATIO)) {
        def->sample_ratio = STATS_FULL_TABLE_SAMPLE_RATIO;
    }

    if (stats_gather_btree_stats(session, dc, idx, def->sample_ratio, is_dynamic) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t db_write_sys_mon_modes(knl_session_t *session, stats_table_mon_t *table_smon, uint32 uid, uint32 id,
                                uint32 part_id, bool32 is_part)
{
    if (table_smon->timestamp == 0) {
        return CT_SUCCESS;
    }

    CM_SAVE_STACK(session->stack);

    knl_cursor_t *cursor = knl_push_cursor(session);
    knl_set_session_scn(session, CT_INVALID_ID64);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_MON_MODS_ALL_ID, STATS_SYS_MON_MODS_ALL_INDEX_2);
    knl_init_index_scan(cursor, CT_TRUE);
    knl_scan_key_t *key = &cursor->scan_range.l_key;
    knl_set_scan_key(INDEX_DESC(cursor->index), key, CT_TYPE_INTEGER, &uid, sizeof(uint32), IX_COL_MODS_003_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, CT_TYPE_INTEGER, &id, sizeof(uint32), IX_COL_MODS_003_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, CT_TYPE_INTEGER, &part_id, sizeof(uint32),
                     IX_COL_MODS_003_PART_ID);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    if (cursor->eof) {
        if (db_insert_sys_mon_mods(session, cursor, table_smon, uid, id, part_id, is_part) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }
    } else {
        date_t analy_time = *(int64 *)CURSOR_COLUMN_DATA(cursor, STATS_SYS_MON_MODS_ALL_ANALYZE_TIME);
        if (analy_time >= table_smon->timestamp) {
            CM_RESTORE_STACK(session->stack);
            return CT_SUCCESS;
        }

        if (db_update_sys_mon_modes(session, cursor, table_smon) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }
    }
    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}

status_t db_flush_sys_mon_modes(knl_session_t *session, dc_entity_t *entity, uint32 uid, uint32 id)
{
    table_t *table = &entity->table;
    part_table_t *part_table = NULL;
    table_part_t *table_part = NULL;
    stats_table_mon_t *table_smon = NULL;

    if (entity->entry->appendix == NULL) {
        return CT_SUCCESS;
    }

    if (IS_PART_TABLE(table)) {
        part_table = table->part_table;
        for (uint32 i = 0; i < part_table->desc.partcnt; i++) {
            table_part = TABLE_GET_PART(table, i);
            if (!IS_READY_PART(table_part)) {
                continue;
            }

            table_smon = &table_part->table_smon;

            if (db_write_sys_mon_modes(session, table_smon, uid, id, table_part->desc.part_id, CT_TRUE) != CT_SUCCESS) {
                return CT_ERROR;
            }
        }
        /* FOR ALL PART TABLE DML STATISTICS TO WRITE MON_MODES$ */
        table_smon = &entity->entry->appendix->table_smon;
        if (db_write_sys_mon_modes(session, table_smon, uid, id, CT_INVALID_ID32, CT_TRUE) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } else {
        table_smon = &entity->entry->appendix->table_smon;
        if (db_write_sys_mon_modes(session, table_smon, uid, id, CT_INVALID_ID32, CT_FALSE) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

status_t stats_flush_monitor_force(knl_session_t *session, dc_entity_t *entity)
{
    if (dc_is_reserved_entry(entity->entry->uid, entity->entry->id)) {
        return CT_SUCCESS;
    }

    if (knl_begin_auton_rm(session) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (db_flush_sys_mon_modes(session, entity, entity->table.desc.uid, entity->table.desc.id) != CT_SUCCESS) {
        knl_end_auton_rm(session, CT_ERROR);
        return CT_ERROR;
    }

    knl_end_auton_rm(session, CT_SUCCESS);
    return CT_SUCCESS;
}

static inline bool32 stats_need_suspend(knl_session_t *session)
{
    return db_in_switch(&session->kernel->switch_ctrl);
}

status_t stats_flush_monitor_normal(knl_session_t *session)
{
    status_t status = CT_SUCCESS;
    knl_dictionary_t dc;
    uint32 uid = CT_INVALID_ID32;
    uint32 table_id = CT_INVALID_ID32;
    bool32 eof = CT_FALSE;
    dc_appendix_t *appendix = NULL;

    for (;;) {
        status = CT_SUCCESS;
        if (dc_scan_all_tables(session, &uid, &table_id, &eof) != CT_SUCCESS) {
            cm_reset_error();
            continue;
        }

        if (eof || stats_need_suspend(session)) {
            break;
        }

        if (session->canceled) {
            break;
        }

        if (session->killed) {
            break;
        }

        if (knl_open_dc_by_id(session, uid, table_id, &dc, CT_TRUE) != CT_SUCCESS) {
            CT_LOG_RUN_WAR("Open %u.%u monitor statistic failed normal, please gather statistics manually",
                           uid, table_id);
            cm_reset_error();
            continue;
        }
        appendix = ((dc_entity_t *)dc.handle)->entry->appendix;
        if (appendix == NULL) {
            dc_close(&dc);
            continue;
        }

        if (strncmp(((dc_entity_t *)dc.handle)->entry->name, MYSQL_TMP_TABLE_PREFIX, MYSQL_TMP_TABLE_PREFIX_LEN) == 0) {
            dc_close(&dc);
            continue;
        }
        if (lock_table_shared_directly(session, &dc) == CT_SUCCESS) {
            if (db_flush_sys_mon_modes(session, DC_ENTITY(&dc), uid, table_id) != CT_SUCCESS) {
                status = CT_ERROR;
            }
        } else {
            status = CT_ERROR;
        }

        if (status == CT_ERROR) {
            CT_LOG_RUN_WAR("Flush %s.%s monitor statistic failed normal, please gather statistics manually",
                           DC_ENTITY(&dc)->entry->user->desc.name, DC_ENTITY(&dc)->table.desc.name);
            knl_rollback(session, NULL);
        } else {
            knl_commit(session);
        }

        unlock_tables_directly(session);
        dc_close(&dc);
    }

    return status;
}

status_t stats_flush_monitor_from_lru(knl_session_t *session)
{
    status_t status = CT_SUCCESS;
    knl_dictionary_t ori_dc, dc;
    uint32 uid = CT_INVALID_ID32;
    uint32 table_id = CT_INVALID_ID32;
    dc_entity_t *entity = NULL;
    bool32 is_found = CT_FALSE;

    for (uint32 pos = 0; pos < STATS_FLUSH_ENTITY_NUM; pos++) {
        status = CT_SUCCESS;
        is_found = CT_FALSE;
        if (stats_need_suspend(session)) {
            break;
        }

        if (session->canceled || session->killed) {
            break;
        }

        entity = dc_get_entity_from_lru(session, pos, &is_found);
        if (!is_found || entity == NULL) {
            continue;
        }

        ori_dc.handle = entity;
        ori_dc.kernel = session->kernel;
        uid = entity->entry->uid;
        table_id = entity->entry->id;
   
        if (knl_open_dc_by_id(session, uid, table_id, &dc, CT_TRUE) != CT_SUCCESS) {
            CT_LOG_RUN_WAR("Open %s.%s falied from dc lru, please gather statistics manually",
                           entity->entry->user->desc.name, entity->table.desc.name);
            cm_reset_error();
            dc_close(&ori_dc);
            continue;
        }

        if (lock_table_shared_directly(session, &dc) == CT_SUCCESS) {
            if (db_flush_sys_mon_modes(session, DC_ENTITY(&dc), uid, table_id) != CT_SUCCESS) {
                status = CT_ERROR;
            }
        } else {
            status = CT_ERROR;
        }

        if (status == CT_ERROR) {
            CT_LOG_RUN_WAR("Flush %s.%s monitor statistic failed from dc lru, please gather statistics manually",
                           DC_ENTITY(&dc)->entry->user->desc.name, DC_ENTITY(&dc)->table.desc.name);
            knl_rollback(session, NULL);
        } else {
            knl_commit(session);
        }

        btree_flush_garbage_size(session, entity);

        unlock_tables_directly(session);
        dc_close(&ori_dc);
        dc_close(&dc);
    }

    return status;
}

void stats_proc(thread_t *thread)
{
    knl_session_t *session = (knl_session_t *)thread->argument;
    uint32 count = 0;
    stats_t *ctx = &session->kernel->stats_ctx;
    switch_ctrl_t *ctrl = &session->kernel->switch_ctrl;
    uint32 sleep_time = 100;

    cm_set_thread_name("stats");
    CT_LOG_RUN_INF("stats thread started");
    KNL_SESSION_SET_CURR_THREADID(session, cm_get_current_thread_id());
    ctx->stats_gathering = CT_FALSE;

    while (!thread->closed) {
        if (session->kernel->db.status != DB_STATUS_OPEN) {
            session->status = SESSION_INACTIVE;
            cm_sleep(200);
            continue;
        }

        if (DB_IS_MAINTENANCE(session) || DB_IS_READONLY(session) || !DB_IS_PRIMARY(&session->kernel->db) ||
            ctrl->request != SWITCH_REQ_NONE) {
            session->status = SESSION_INACTIVE;
            cm_sleep(200);
            continue;
        }

        if (!DB_IS_STATS_ENABLED(session->kernel)) {
            session->status = SESSION_INACTIVE;
            cm_sleep(200);
            continue;
        }

        if (!session->kernel->dc_ctx.completed || DB_IN_BG_ROLLBACK(session)) {
            session->status = SESSION_INACTIVE;
            cm_sleep(200);
            continue;
        }

        if (session->status == SESSION_INACTIVE) {
            session->status = SESSION_ACTIVE;
        }

        if (0 == count % STATS_LRU_TABLE_MONITOR_INTERVAL) {
            db_set_with_switchctrl_lock(ctrl, &ctx->stats_gathering);
            if (!ctx->stats_gathering) {
                cm_sleep(sleep_time);
                continue;
            }

            (void)stats_flush_monitor_from_lru(session);
            ctx->stats_gathering = CT_FALSE;
        }

        if (0 == count % STATS_TABLE_MONITOR_INTERVAL) {
            db_set_with_switchctrl_lock(ctrl, &ctx->stats_gathering);
            if (!ctx->stats_gathering) {
                cm_sleep(sleep_time);
                continue;
            }

            (void)stats_flush_monitor_normal(session);
            ctx->stats_gathering = CT_FALSE;
        }

        cm_sleep(1000);
        count++;
    }

    CT_LOG_RUN_INF("stats thread closed");
    KNL_SESSION_CLEAR_THREADID(session);
}

status_t knl_flush_table_monitor(knl_handle_t session)
{
    knl_session_t *se = (knl_session_t *)session;

    if (DB_IS_READONLY(se)) {
        CT_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "operation on read only mode");
        return CT_ERROR;
    }

    if (DB_STATUS_OPEN != se->kernel->db.status) {
        return CT_SUCCESS;
    }

    if (DB_IS_MAINTENANCE(se) || !DB_IS_PRIMARY(&se->kernel->db) ||
        se->kernel->switch_ctrl.request != SWITCH_REQ_NONE) {
        return CT_SUCCESS;
    }

    if (!se->kernel->dc_ctx.completed || DB_IN_BG_ROLLBACK(se)) {
        return CT_SUCCESS;
    }

    if (stats_flush_monitor_normal(se) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

void stats_close(knl_session_t *session)
{
    knl_instance_t *kernel = session->kernel;
    stats_t *ctx = &kernel->stats_ctx;

    cm_close_thread(&ctx->thread);
}

void stats_buf_init(knl_session_t *session, knl_buf_wait_t *temp_stat)
{
    temp_stat->wait_count = 0;
    temp_stat->wait_time = session->stat_page.r_sleeps + session->stat_page.x_sleeps + session->stat_page.s_sleeps +
                           session->stat_page.ix_sleeps;
}

void stats_buf_record(knl_session_t *session, knl_buf_wait_t *temp_stat, buf_ctrl_t *ctrl)
{
    uint64 wait_time = session->stat_page.r_sleeps + session->stat_page.x_sleeps + session->stat_page.s_sleeps +
                       session->stat_page.ix_sleeps;

    if (wait_time != temp_stat->wait_time) {
        switch (ctrl->page->type) {
            case PAGE_TYPE_BTREE_HEAD:
            case PAGE_TYPE_HEAP_HEAD:
                session->buf_wait[SEGMENT_HEADER].wait_time += wait_time - temp_stat->wait_time;
                session->buf_wait[SEGMENT_HEADER].wait_count++;
                break;

            case PAGE_TYPE_UNDO_HEAD:
                session->buf_wait[UNDO_HEADER].wait_count++;
                session->buf_wait[UNDO_HEADER].wait_time += wait_time - temp_stat->wait_time;
                break;

            case PAGE_TYPE_SPACE_HEAD:
            case PAGE_TYPE_HEAP_MAP:
                session->buf_wait[FREE_LIST].wait_count++;
                session->buf_wait[FREE_LIST].wait_time += wait_time - temp_stat->wait_time;
                break;

            case PAGE_TYPE_UNDO:
                session->buf_wait[UNDO_BLOCK].wait_count++;
                session->buf_wait[UNDO_BLOCK].wait_time += wait_time - temp_stat->wait_time;
                break;

            case PAGE_TYPE_BTREE_NODE:
            case PAGE_TYPE_HEAP_DATA:
                session->buf_wait[DATA_BLOCK].wait_count++;
                session->buf_wait[DATA_BLOCK].wait_time += wait_time - temp_stat->wait_time;
                break;

            default:
                break;
        }
    }
}

static status_t stats_seg_insert(knl_session_t *session, knl_cursor_t *cursor, knl_seg_stats_desc_t *desc)
{
    row_assist_t ra;

    if (desc->logic_reads == 0 && desc->physical_reads == 0 && desc->physical_writes == 0) {
        return CT_SUCCESS;
    }

    if (knl_open_sys_temp_cursor(session, cursor, CURSOR_ACTION_INSERT, SYS_TMP_SEG_STAT_ID,
                                 CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }

    row_init(&ra, cursor->buf, HEAP_MAX_ROW_SIZE(session), STATS_TMP_SEG_STAT_ALL_COLUMNS);
    (void)row_put_int64(&ra, desc->org_scn);
    (void)row_put_int32(&ra, desc->uid);
    (void)row_put_int32(&ra, desc->oid);
    (void)row_put_int64(&ra, MIN(CT_MAX_INT64, desc->logic_reads));
    (void)row_put_int64(&ra, MIN(CT_MAX_INT64, desc->physical_writes));
    (void)row_put_int64(&ra, MIN(CT_MAX_INT64, desc->physical_reads));
    (void)row_put_int64(&ra, MIN(CT_MAX_INT64, desc->itl_waits));
    (void)row_put_int64(&ra, MIN(CT_MAX_INT64, desc->buf_busy_waits));
    (void)row_put_int64(&ra, MIN(CT_MAX_INT64, desc->row_lock_waits));

    if (knl_internal_insert(session, cursor) != CT_SUCCESS) {
        knl_close_cursor(session, cursor);
        return CT_ERROR;
    }

    knl_close_cursor(session, cursor);
    return CT_SUCCESS;
}

static inline void stats_seg_init_desc(seg_stat_t seg_stat, uint32 uid, uint32 oid, knl_scn_t org_scn,
                                       knl_seg_stats_desc_t *desc)
{
    desc->org_scn = org_scn;
    desc->uid = uid;
    desc->oid = oid;
    desc->logic_reads = seg_stat.logic_reads;
    desc->physical_writes = seg_stat.physical_writes;
    desc->physical_reads = seg_stat.physical_reads;
    desc->itl_waits = seg_stat.itl_waits;
    desc->buf_busy_waits = seg_stat.buf_busy_waits;
    desc->row_lock_waits = seg_stat.row_lock_waits;
}

static status_t stats_update_record(knl_session_t *session, knl_cursor_t *cursor,
    knl_seg_stats_desc_t *desc)
{
    row_assist_t ra;

    if (knl_open_sys_temp_cursor(session, cursor, CURSOR_ACTION_UPDATE,
                                 SYS_TMP_SEG_STAT_ID, IDX_OBJECT_ID) != CT_SUCCESS) {
        return CT_ERROR;
    }

    knl_init_index_scan(cursor, CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_BIGINT, &desc->org_scn,
                     sizeof(knl_scn_t), IX_COL_OBJECT_UID);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        knl_close_cursor(session, cursor);
        return CT_ERROR;
    }

    if (cursor->eof) {
        if (stats_seg_insert(session, cursor, desc) != CT_SUCCESS) {
            knl_close_cursor(session, cursor);
            return CT_ERROR;
        }
    } else {
        row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), STATS_TMP_SEG_STAT_UPDATE_COLUMNS);

        (void)row_put_int64(&ra, MIN(CT_MAX_INT64, desc->logic_reads));
        (void)row_put_int64(&ra, MIN(CT_MAX_INT64, desc->physical_writes));
        (void)row_put_int64(&ra, MIN(CT_MAX_INT64, desc->physical_reads));
        (void)row_put_int64(&ra, MIN(CT_MAX_INT64, desc->itl_waits));
        (void)row_put_int64(&ra, MIN(CT_MAX_INT64, desc->buf_busy_waits));
        (void)row_put_int64(&ra, MIN(CT_MAX_INT64, desc->row_lock_waits));
        cursor->update_info.count = STATS_TMP_SEG_STAT_UPDATE_COLUMNS;
        cursor->update_info.columns[0] = STATS_TMP_SEG_STAT_LOGICREADS_COLUMN;
        cursor->update_info.columns[1] = STATS_TMP_SEG_STAT_PHYSICALWRITES_COLUMN;
        cursor->update_info.columns[2] = STATS_TMP_SEG_STAT_PHYSICALREADS_COLUMN;
        cursor->update_info.columns[3] = STATS_TMP_SEG_STAT_ITLWAITS_COLUMN;
        cursor->update_info.columns[4] = STATS_TMP_SEG_STAT_BUFBUSYWAITS_COLUMN;
        cursor->update_info.columns[5] = STATS_TMP_SEG_STAT_ROWLOCKWAITS_COLUMN;

        cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, NULL);

        if (knl_internal_update(session, cursor) != CT_SUCCESS) {
            knl_close_cursor(session, cursor);
            return CT_ERROR;
        }
    }

    knl_close_cursor(session, cursor);
    return CT_SUCCESS;
}

static status_t stats_insert_record(knl_session_t *session, knl_cursor_t *cursor, dc_entity_t *entity)
{
    uint32 i, j;
    table_t *table;
    index_t *idx = NULL;
    index_part_t *index_part = NULL;
    table_part_t *table_part = NULL;
    knl_seg_stats_desc_t desc;

    table = &entity->table;
    stats_seg_init_desc(table->heap.stat, table->desc.uid, table->desc.id, table->desc.org_scn, &desc);
    if (stats_update_record(session, cursor, &desc) != CT_SUCCESS) {
        CT_LOG_DEBUG_ERR("insert table %u.%u statistic info failed, org_scn: %llu",
                         table->desc.uid, table->desc.id, table->desc.org_scn);
        return CT_ERROR;
    }

    if (IS_PART_TABLE(table)) {
        for (i = 0; i < table->part_table->desc.partcnt; i++) {
            table_part = PART_GET_ENTITY(table->part_table, i);
            if (!IS_READY_PART(table_part)) {
                continue;
            }

            stats_seg_init_desc(table_part->heap.stat, table->desc.uid,
                                table->desc.id, table_part->desc.org_scn, &desc);
            if (stats_update_record(session, cursor, &desc) != CT_SUCCESS) {
                CT_LOG_DEBUG_ERR("insert table %u.%u part_table statistic info failed, org_scn: %llu",
                                 table->desc.uid, table->desc.id, table_part->desc.org_scn);
                return CT_ERROR;
            }
        }
    }

    for (i = 0; i < table->index_set.count; i++) {
        idx = table->index_set.items[i];
        stats_seg_init_desc(idx->btree.stat, table->desc.uid, table->desc.id, idx->desc.org_scn, &desc);
        if (stats_update_record(session, cursor, &desc) != CT_SUCCESS) {
            CT_LOG_DEBUG_ERR("insert table %u.%u index statistic info failed, org_scn: %llu",
                             table->desc.uid, table->desc.id, idx->desc.org_scn);
            return CT_ERROR;
        }

        if (!IS_PART_INDEX(idx)) {
            continue;
        }

        for (j = 0; j < idx->part_index->desc.partcnt; j++) {
            index_part = PART_GET_ENTITY(idx->part_index, j);
            if (index_part == NULL) {
                continue;
            }

            stats_seg_init_desc(index_part->btree.stat, table->desc.uid,
                                table->desc.id, index_part->desc.org_scn, &desc);
            if (stats_update_record(session, cursor, &desc) != CT_SUCCESS) {
                CT_LOG_DEBUG_ERR("insert table %u.%u part_index statistic info failed, org_scn: %llu",
                                 table->desc.uid, table->desc.id, index_part->desc.org_scn);
                return CT_ERROR;
            }
        }
    }

    return CT_SUCCESS;
}

status_t stats_temp_insert(knl_session_t *session, struct st_dc_entity *dc_entity)
{
    knl_session_t *temp_session = session->kernel->sessions[SESSION_ID_TMP_STAT];
    dc_entity_t *entity = (dc_entity_t *)dc_entity;
    knl_cursor_t *cursor = NULL;
    const char *msg = NULL;
    source_location_t loc;
    int32 code;

    if (DB_IS_MAINTENANCE(session) || session->bootstrap || session->kernel->db.status != DB_STATUS_OPEN) {
        return CT_SUCCESS;
    }

    if (entity == NULL) {
        return CT_SUCCESS;
    }

    if (entity->type > DICT_TYPE_TEMP_TABLE_SESSION) {
        return CT_SUCCESS;
    }

    cm_latch_x(&g_stats_latch, SESSION_ID_TMP_STAT, NULL);
    CM_SAVE_STACK(temp_session->stack);

    cm_get_error(&code, &msg, &loc);
    cursor = knl_push_cursor(temp_session);
    if (stats_insert_record(temp_session, cursor, entity) != CT_SUCCESS) {
        knl_rollback(temp_session, NULL);
        cm_revert_error(code, msg, &loc);
        CM_RESTORE_STACK(temp_session->stack);
        cm_unlatch(&g_stats_latch, NULL);
        return CT_ERROR;
    }

    knl_commit(temp_session);
    CM_RESTORE_STACK(temp_session->stack);

    cm_unlatch(&g_stats_latch, NULL);

    return CT_SUCCESS;
}

status_t stats_seg_load_entity(knl_session_t *session, knl_scn_t org_scn, seg_stat_t *seg_stat)
{
    knl_session_t *temp_session = session->kernel->sessions[SESSION_ID_TMP_STAT];
    knl_cursor_t *cursor = NULL;
    const char *msg = NULL;
    source_location_t loc;
    int32 code;

    if (DB_IS_MAINTENANCE(session) || session->bootstrap || session->kernel->db.status != DB_STATUS_OPEN) {
        return CT_SUCCESS;
    }

    cm_latch_x(&g_stats_latch, SESSION_ID_TMP_STAT, NULL);
    CM_SAVE_STACK(temp_session->stack);

    cm_get_error(&code, &msg, &loc);
    cursor = knl_push_cursor(temp_session);
    if (knl_open_sys_temp_cursor(temp_session, cursor, CURSOR_ACTION_SELECT,
                                 SYS_TMP_SEG_STAT_ID, IDX_OBJECT_ID) != CT_SUCCESS) {
        cm_revert_error(code, msg, &loc);
        CM_RESTORE_STACK(temp_session->stack);
        cm_unlatch(&g_stats_latch, NULL);
        return CT_ERROR;
    }

    knl_init_index_scan(cursor, CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_BIGINT, &org_scn, sizeof(knl_scn_t),
                     IX_COL_OBJECT_UID);

    if (knl_fetch(temp_session, cursor) != CT_SUCCESS) {
        knl_close_temp_tables(temp_session, DICT_TYPE_TEMP_TABLE_TRANS);
        knl_close_cursor(temp_session, cursor);
        cm_revert_error(code, msg, &loc);
        CM_RESTORE_STACK(temp_session->stack);
        cm_unlatch(&g_stats_latch, NULL);
        return CT_ERROR;
    }

    if (!cursor->eof) {
        seg_stat->logic_reads = *(uint64 *)CURSOR_COLUMN_DATA(cursor, TMP_SEG_STAT_COL_LOGIC_READS);
        seg_stat->physical_writes = *(uint64 *)CURSOR_COLUMN_DATA(cursor, TMP_SEG_STAT_COL_PHYSICAL_WRITES);
        seg_stat->physical_reads = *(uint64 *)CURSOR_COLUMN_DATA(cursor, TMP_SEG_STAT_COL_PHYSICAL_READS);
        seg_stat->itl_waits = *(uint32 *)CURSOR_COLUMN_DATA(cursor, TMP_SEG_STAT_COL_ITL_WAITS);
        seg_stat->buf_busy_waits = *(uint32 *)CURSOR_COLUMN_DATA(cursor, TMP_SEG_STAT_COL_BUF_BUSY_WAITS);
        seg_stat->row_lock_waits = *(uint32 *)CURSOR_COLUMN_DATA(cursor, TMP_SEG_STAT_COL_ROW_LOCK_WAITS);
    }

    knl_close_temp_tables(temp_session, DICT_TYPE_TEMP_TABLE_TRANS);
    knl_close_cursor(temp_session, cursor);
    CM_RESTORE_STACK(temp_session->stack);

    cm_unlatch(&g_stats_latch, NULL);
    return CT_SUCCESS;
}

/*
 * stats_purge_stats_by_time
 *
 * This function is used to purge stats before given time.
 */
status_t stats_purge_stats_by_time(knl_session_t *session, int64 max_analyze_time)
{
    knl_cursor_t *cursor = NULL;
    int64 analyze_time;
    uint32 uid, table_id;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);

    cursor->scan_mode = SCAN_MODE_TABLE_FULL;
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_TABLE_ID, CT_INVALID_ID32);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    while (!cursor->eof) {
        if (session->canceled) {
            CT_THROW_ERROR(ERR_OPERATION_CANCELED);
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }

        if (session->killed) {
            CT_THROW_ERROR(ERR_OPERATION_KILLED);
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }

        uid = *(uint32 *)CURSOR_COLUMN_DATA(cursor, TABLE_UID);
        table_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, TABLE_TABLE_ID);
        analyze_time = *(int64 *)CURSOR_COLUMN_DATA(cursor, TABLE_ANALYZE_TIME);
        if (analyze_time <= max_analyze_time) {
            if (stats_delete_table_stats(session, uid, table_id, CT_FALSE) != CT_SUCCESS) {
                knl_rollback(session, NULL);
                cm_reset_error();
            } else {
                knl_commit(session);
            }
        }

        /* fetch next row */
        if (knl_fetch(session, cursor) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);

    return CT_SUCCESS;
}

/*
 * stats_reset_tablepart$
 * input parameter:
 * uid    user id;
 * oid    table id
 */
static status_t stats_reset_sys_tablepart(knl_session_t *session, uint32 uid, uint32 oid,
                                          uint32 part_id)
{
    knl_cursor_t *cursor = NULL;
    row_assist_t ra;
    uint16 size;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_TABLEPART_ID, IX_SYS_TABLEPART001_ID);
    knl_init_index_scan(cursor,
                        CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &uid, sizeof(uint32),
                     IX_COL_SYS_TABLEPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &oid, sizeof(uint32),
                     IX_COL_SYS_TABLEPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &part_id, sizeof(uint32),
                     IX_COL_SYS_TABLEPART001_PART_ID);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    if (!cursor->eof) {
        cursor->update_info.count = STATS_SYS_TABLE_COLUMN_COUNT;
        row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), STATS_SYS_TABLE_COLUMN_COUNT);
        row_put_null(&ra);
        row_put_null(&ra);
        row_put_null(&ra);
        row_put_null(&ra);
        row_put_null(&ra);
        row_put_null(&ra);

        cursor->update_info.columns[0] = TABLE_PART_ROWS;
        cursor->update_info.columns[1] = TABLE_PART_BLOCKS;
        cursor->update_info.columns[2] = TABLE_PART_EMPTY_BLOCK;
        cursor->update_info.columns[3] = TABLE_PART_AVG_ROW_LEN;
        cursor->update_info.columns[4] = TABLE_PART_SAMPLE_SIZE;
        cursor->update_info.columns[5] = TABLE_PART_ANALYZE_TIME;

        cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, &size);

        if (knl_internal_update(session, cursor) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);

    return CT_SUCCESS;
}

status_t stats_reset_sys_indexpart_by_part(knl_session_t *session, uint32 uid, uint32 oid, uint32 part_id)
{
    knl_cursor_t *cursor = NULL;
    uint32 part;
    row_assist_t ra;
    uint16 size;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_INDEXPART_ID, IX_SYS_INDEXPART001_ID);
    knl_init_index_scan(cursor,
                        CT_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &uid, sizeof(uint32),
                     IX_COL_SYS_INDEXPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &oid, sizeof(uint32),
                     IX_COL_SYS_INDEXPART001_TABLE_ID);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_INDEXPART001_INDEX_ID);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_INDEXPART001_PART_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_INTEGER, &uid, sizeof(uint32),
                     IX_COL_SYS_INDEXPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_INTEGER, &oid, sizeof(uint32),
                     IX_COL_SYS_INDEXPART001_TABLE_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_INDEXPART001_INDEX_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_INDEXPART001_PART_ID);

    for (;;) {
        if (knl_fetch(session, cursor) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }

        if (cursor->eof) {
            break;
        }

        part = *(uint32 *)CURSOR_COLUMN_DATA(cursor, INDEX_PART_ID);
        if (part != part_id) {
            continue;
        }

        cursor->update_info.count = STATS_SYS_INDEX_COLUMN_COUNT;
        row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), STATS_SYS_INDEX_COLUMN_COUNT);

        for (uint32 i = 0; i < STATS_SYS_INDEX_COLUMN_COUNT; i++) {
            row_put_null(&ra);
        }

        cursor->update_info.columns[0] = INDEX_PART_BLEVEL;
        cursor->update_info.columns[1] = INDEX_PART_LEVEL_BLOCKS;
        cursor->update_info.columns[2] = INDEX_PART_DISTINCT_KEYS;
        cursor->update_info.columns[3] = INDEX_PART_AVG_LEAF_BLOCKS_PER_KEY;
        cursor->update_info.columns[4] = INDEX_PART_AVG_DATA_BLOCKS_PER_KEY;
        cursor->update_info.columns[5] = INDEX_PART_ANALYZE_TIME;
        cursor->update_info.columns[6] = INDEX_PART_EMPTY_LEAF_BLOCKS;
        cursor->update_info.columns[7] = INDEX_PART_CLUSTER_FACTOR;
        cursor->update_info.columns[8] = INDEX_PART_SAMPLE_SIZE;
        cursor->update_info.columns[9] = INDEX_PART_COMB_2_NDV;
        cursor->update_info.columns[10] = INDEX_PART_COMB_3_NDV;
        cursor->update_info.columns[11] = INDEX_PART_COMB_4_NDV;

        cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, &size);

        if (knl_internal_update(session, cursor) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}

/*
 * stats_reset_indexpart$
 * input parameter:
 * uid    user id;
 * oid    table id
 */
static status_t stats_reset_sys_indexpart(knl_session_t *session, uint32 uid, uint32 oid, uint32 idx_id,
                                          uint32 part_id)
{
    knl_cursor_t *cursor = NULL;
    row_assist_t ra;
    uint16 size;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_INDEXPART_ID, IX_SYS_INDEXPART001_ID);
    knl_init_index_scan(cursor,
                        CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &uid, sizeof(uint32),
                     IX_COL_SYS_INDEXPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &oid, sizeof(uint32),
                     IX_COL_SYS_INDEXPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &idx_id, sizeof(uint32),
                     IX_COL_SYS_INDEXPART001_INDEX_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &part_id, sizeof(uint32),
                     IX_COL_SYS_INDEXPART001_PART_ID);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    if (!cursor->eof) {
        cursor->update_info.count = STATS_SYS_INDEX_COLUMN_COUNT;
        row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), STATS_SYS_INDEX_COLUMN_COUNT);

        for (uint32 i = 0; i < STATS_SYS_INDEX_COLUMN_COUNT; i++) {
            row_put_null(&ra);
        }

        cursor->update_info.columns[0] = INDEX_PART_BLEVEL;
        cursor->update_info.columns[1] = INDEX_PART_LEVEL_BLOCKS;
        cursor->update_info.columns[2] = INDEX_PART_DISTINCT_KEYS;
        cursor->update_info.columns[3] = INDEX_PART_AVG_LEAF_BLOCKS_PER_KEY;
        cursor->update_info.columns[4] = INDEX_PART_AVG_DATA_BLOCKS_PER_KEY;
        cursor->update_info.columns[5] = INDEX_PART_ANALYZE_TIME;
        cursor->update_info.columns[6] = INDEX_PART_EMPTY_LEAF_BLOCKS;
        cursor->update_info.columns[7] = INDEX_PART_CLUSTER_FACTOR;
        cursor->update_info.columns[8] = INDEX_PART_SAMPLE_SIZE;
        cursor->update_info.columns[9] = INDEX_PART_COMB_2_NDV;
        cursor->update_info.columns[10] = INDEX_PART_COMB_3_NDV;
        cursor->update_info.columns[11] = INDEX_PART_COMB_4_NDV;

        cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, &size);

        if (knl_internal_update(session, cursor) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);

    return CT_SUCCESS;
}

/*
 * stats_reset_systable$
 * input parameter:
 * uid    user id;
 * oid    table id
 */
static status_t stats_reset_sys_table(knl_session_t *session, uint32 uid, uint32 oid)
{
    knl_cursor_t *cursor = NULL;
    row_assist_t ra;
    uint16 size;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_TABLE_ID, IX_SYS_TABLE_002_ID);
    knl_init_index_scan(cursor,
                        CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &uid, sizeof(uint32),
                     IX_COL_SYS_TABLE_002_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &oid, sizeof(uint32),
                     IX_COL_SYS_TABLE_002_ID);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    while (!cursor->eof) {
        cursor->update_info.count = STATS_SYS_TABLE_COLUMN_COUNT;
        row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), STATS_SYS_TABLE_COLUMN_COUNT);
        row_put_null(&ra);
        row_put_null(&ra);
        row_put_null(&ra);
        row_put_null(&ra);
        row_put_null(&ra);
        row_put_null(&ra);

        cursor->update_info.columns[0] = TABLE_ROWS;
        cursor->update_info.columns[1] = TABLE_BLOCKS;
        cursor->update_info.columns[2] = TABLE_EMPTY_BLOCK;
        cursor->update_info.columns[3] = TABLE_AVG_ROW_LEN;
        cursor->update_info.columns[4] = TABLE_SAMPLE_SIZE;
        cursor->update_info.columns[5] = TABLE_ANALYZE_TIME;

        cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, &size);

        if (knl_internal_update(session, cursor) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }

        if (knl_fetch(session, cursor) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}

static status_t stats_reset_sys_column(knl_session_t *session, uint32 uid, uint32 oid)
{
    knl_cursor_t *cursor = NULL;
    row_assist_t ra;
    uint16 size;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_COLUMN_ID, IX_SYS_COLUMN_001_ID);
    knl_init_index_scan(cursor,
                        CT_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &uid, sizeof(uint32),
                     IX_COL_SYS_COLUMN_001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &oid, sizeof(uint32),
                     IX_COL_SYS_COLUMN_001_TABLE_ID);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_COLUMN_001_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_INTEGER, &uid, sizeof(uint32),
                     IX_COL_SYS_COLUMN_001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_INTEGER, &oid, sizeof(uint32),
                     IX_COL_SYS_COLUMN_001_TABLE_ID);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_COLUMN_001_ID);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    while (!cursor->eof) {
        cursor->update_info.count = STATS_SYS_COLUMN_COLUMN_COUNT;
        row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), STATS_SYS_COLUMN_COLUMN_COUNT);
        row_put_null(&ra);
        row_put_null(&ra);
        row_put_null(&ra);
        row_put_null(&ra);

        for (uint32 i = 0; i < STATS_SYS_COLUMN_COLUMN_COUNT; i++) {
            cursor->update_info.columns[i] = i + STATS_SYS_COLUMN_COLUMN_NUM;
        }

        cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, &size);

        if (knl_internal_update(session, cursor) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }

        if (knl_fetch(session, cursor) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);

    return CT_SUCCESS;
}

/*
 * stats_reset_sysindex$
 *
 * NOTE:
 * reset BLEVEL, LEVEL_BLOCKS, DISTINCT_KEYS, AVG_LEAF_BLOCKS_PER_KEY,
 *       AVG_DATA_BLOCKS_PER_KEY, ANALYZETIME, CLUFAC, SAMPLESIZE to NULL
 */
static status_t stats_reset_sys_index(knl_session_t *session, uint32 uid, uint32 oid)
{
    knl_cursor_t *cursor = NULL;
    row_assist_t ra;
    uint16 size;

    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_INDEX_ID, IX_SYS_INDEX_001_ID);
    knl_init_index_scan(cursor,
                        CT_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &uid, sizeof(uint32),
                     IX_COL_SYS_INDEX_001_USER);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &oid, sizeof(uint32),
                     IX_COL_SYS_INDEX_001_TABLE);
    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_INDEX_001_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_INTEGER, &uid, sizeof(uint32),
                     IX_COL_SYS_INDEX_001_USER);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_INTEGER, &oid, sizeof(uint32),
                     IX_COL_SYS_INDEX_001_TABLE);
    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_INDEX_001_ID);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    while (!cursor->eof) {
        cursor->update_info.count = STATS_SYS_INDEX_COLUMN_COUNT;
        row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), STATS_SYS_INDEX_COLUMN_COUNT);
        row_put_null(&ra);
        row_put_null(&ra);
        row_put_null(&ra);
        row_put_null(&ra);
        row_put_null(&ra);
        row_put_null(&ra);
        row_put_null(&ra);
        row_put_null(&ra);
        row_put_null(&ra);
        row_put_null(&ra);
        row_put_null(&ra);
        row_put_null(&ra);

        cursor->update_info.columns[0] = STATS_SYS_INDEX_BLEVEL_COLUMN;
        cursor->update_info.columns[1] = STATS_SYS_INDEX_LEAF_BLOCKS_COLUMN;
        cursor->update_info.columns[2] = STATS_SYS_INDEX_NDV_KEY_COLUMN;
        cursor->update_info.columns[3] = STATS_SYS_INDEX_AVG_LBK_COLUMN;
        cursor->update_info.columns[4] = STATS_SYS_INDEX_AVG_DBK_COLUMN;
        cursor->update_info.columns[5] = STATS_SYS_INDEX_ANALYZETIME_COLUMN;
        cursor->update_info.columns[6] = STATS_SYS_INDEX_EMPTY_BLOCK_COLUMN;
        cursor->update_info.columns[7] = STATS_SYS_INDEX_COLFAC_COLUMN;
        cursor->update_info.columns[8] = STATS_SYS_INDEX_SAMSIZE_COLUMN;
        cursor->update_info.columns[9] = STATS_SYS_INDEX_COMB2_NDV_COLUMN;
        cursor->update_info.columns[10] = STATS_SYS_INDEX_COMB3_NDV_COLUMN;
        cursor->update_info.columns[11] = STATS_SYS_INDEX_COMB4_NDV_COLUMN;

        cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, &size);

        if (knl_internal_update(session, cursor) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }
        if (knl_fetch(session, cursor) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }
    }

    CM_RESTORE_STACK(session->stack);

    return CT_SUCCESS;
}

status_t stats_reset_tableparts_stats(knl_session_t *session, knl_dictionary_t *dc)
{
    table_t *table = DC_TABLE(dc);
    part_table_t *part_table = table->part_table;
    table_part_t *table_part = NULL;

    for (uint32 i = 0; i < part_table->desc.partcnt; i++) {
        table_part = TABLE_GET_PART(table, i);
        if (!IS_READY_PART(table_part)) {
            continue;
        }

        if (stats_reset_sys_tablepart(session, dc->uid, dc->oid, table_part->desc.part_id) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

status_t stats_reset_indexparts_stats(knl_session_t *session, knl_dictionary_t *dc)
{
    table_t *table = DC_TABLE(dc);
    index_t *idx = NULL;
    part_index_t *part_index = NULL;
    index_part_t *index_part = NULL;

    for (uint32 i = 0; i < table->index_set.count; i++) {
        idx = table->index_set.items[i];

        if (!IS_PART_INDEX(idx)) {
            continue;
        }

        part_index = idx->part_index;

        for (uint32 j = 0; j < part_index->desc.partcnt; j++) {
            index_part = INDEX_GET_PART(idx, j);
            if (index_part == NULL) {
                continue;
            }

            if (stats_reset_sys_indexpart(session, dc->uid, dc->oid, idx->desc.id,
                                          index_part->desc.part_id) != CT_SUCCESS) {
                return CT_ERROR;
            }
        }
    }

    return CT_SUCCESS;
}

/*
 * delete part stats
 *
 */
status_t stats_delete_part_stats(knl_session_t *session, const uint32 uid, const uint32 oid, uint32 part_id)
{
    knl_dictionary_t dc;
    bool32 need_delete = CT_FALSE;
    stats_load_info_t load_info;

    if (knl_open_dc_by_id(session, uid, oid, &dc, CT_TRUE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (stats_check_analyzing(session, &dc, &need_delete, CT_FALSE) != CT_SUCCESS) {
        dc_close(&dc);
        return CT_ERROR;
    }

    if (!need_delete) {
        dc_close(&dc);
        return CT_SUCCESS;
    }
    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);
    if (stats_delete_histgram_by_part(session, cursor, &dc, part_id) != CT_SUCCESS) {
        stats_set_analyzed(session, &dc, need_delete);
        dc_close(&dc);
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }
    CM_RESTORE_STACK(session->stack);

    if (stats_delete_histhead_by_part(session, &dc, part_id) != CT_SUCCESS) {
        stats_set_analyzed(session, &dc, need_delete);
        dc_close(&dc);
        return CT_ERROR;
    }

    if (stats_reset_sys_indexpart_by_part(session, uid, oid, part_id) != CT_SUCCESS) {
        stats_set_analyzed(session, &dc, need_delete);
        dc_close(&dc);
        return CT_ERROR;
    }

    if (stats_reset_sys_tablepart(session, uid, oid, part_id) != CT_SUCCESS) {
        stats_set_analyzed(session, &dc, need_delete);
        dc_close(&dc);
        return CT_ERROR;
    }

    stats_set_analyzed(session, &dc, need_delete);
    load_info.parent_part_id = part_id;
    load_info.load_subpart = CT_TRUE;
    if (stats_refresh_dc(session, &dc, load_info) != CT_SUCCESS) {
        dc_close(&dc);
        return CT_ERROR;
    }
    dc_close(&dc);
    return CT_SUCCESS;
}

status_t stats_reset_table_stats(knl_session_t *session, knl_dictionary_t *dc, bool32 is_old_nologging)
{
    uint32 uid = dc->uid;
    uint32 oid = dc->oid;
    bool32 need_delete = CT_FALSE;
    table_t *table = DC_TABLE(dc);

    if (stats_check_analyzing(session, dc, &need_delete, CT_FALSE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (!need_delete) {
        return CT_SUCCESS;
    }

    bool32 is_nologging = is_old_nologging ? is_old_nologging : IS_NOLOGGING_BY_TABLE_TYPE(table->desc.type);
    if (stats_drop_hists(session, uid, oid, is_nologging) != CT_SUCCESS) {
        stats_set_analyzed(session, dc, need_delete);
        return CT_ERROR;
    }

    if (stats_reset_sys_column(session, uid, oid) != CT_SUCCESS) {
        stats_set_analyzed(session, dc, need_delete);
        return CT_ERROR;
    }

    if (stats_reset_sys_index(session, uid, oid) != CT_SUCCESS) {
        stats_set_analyzed(session, dc, need_delete);
        return CT_ERROR;
    }

    if (stats_reset_sys_table(session, uid, oid) != CT_SUCCESS) {
        stats_set_analyzed(session, dc, need_delete);
        return CT_ERROR;
    }

    dc_entity_t *entity = DC_ENTITY(dc);
    cbo_stats_table_t  *cbo_stats = entity->cbo_table_stats;

    if (IS_PART_TABLE(table)) {
        if (stats_reset_indexparts_stats(session, dc) != CT_SUCCESS) {
            stats_set_analyzed(session, dc, need_delete);
            return CT_ERROR;
        }

        if (stats_reset_tableparts_stats(session, dc) != CT_SUCCESS) {
            stats_set_analyzed(session, dc, need_delete);
            return CT_ERROR;
        }

        if (cbo_stats != NULL) {
            cbo_stats->global_stats_exist = CT_FALSE;
        }
    }

    stats_set_analyzed(session, dc, need_delete);
    return CT_SUCCESS;
}

/*
 * stats_delete_stats
 *
 * This function is used to delete the stats of table.
 */
status_t stats_delete_table_stats(knl_session_t *session, const uint32 uid, const uint32 oid, bool32 is_old_nologging)
{
    knl_dictionary_t dc;
    stats_load_info_t load_info;

    if (knl_open_dc_by_id(session, uid, oid, &dc, CT_TRUE) != CT_SUCCESS) {
        return CT_ERROR;
    }
    
    if (stats_reset_table_stats(session, &dc, is_old_nologging) != CT_SUCCESS) {
        dc_close(&dc);
        return CT_ERROR;
    }
    stats_set_load_info(&load_info, DC_ENTITY(&dc), CT_TRUE, CT_INVALID_ID32);

    if (stats_refresh_dc(session, &dc, load_info) != CT_SUCCESS) {
        dc_close(&dc);
        return CT_ERROR;
    }

    dc_close(&dc);
    return CT_SUCCESS;
}

void stats_calc_global_dml_stats(stats_table_mon_t *global_mon, stats_table_mon_t *part_mon)
{
    global_mon->inserts = (global_mon->inserts >= part_mon->inserts) ? (global_mon->inserts - part_mon->inserts) :
        global_mon->inserts;
    global_mon->deletes = (global_mon->deletes >= part_mon->deletes) ? (global_mon->deletes - part_mon->deletes) :
        global_mon->deletes;
    global_mon->updates = (global_mon->updates >= part_mon->updates) ? (global_mon->updates - part_mon->updates) :
        global_mon->updates;
    global_mon->drop_segments = (global_mon->drop_segments >= part_mon->drop_segments) ?
        (global_mon->drop_segments - part_mon->drop_segments) : global_mon->inserts;
    global_mon->is_change = CT_FALSE;
    global_mon->timestamp = cm_now();
}

void stats_disable_table_part_mon(knl_dictionary_t *dc, table_part_t *table_part, bool32 analyzed)
{
    dc_entity_t *entity = DC_ENTITY(dc);
    stats_table_mon_t *tab_mon = NULL;

    if (!analyzed || table_part == NULL) {
        return;
    }

    if (entity->entry->appendix == NULL) {
        return;
    }

    tab_mon = &entity->entry->appendix->table_smon;
    stats_calc_global_dml_stats(tab_mon, &table_part->table_smon);
    errno_t ret = memset_sp(&table_part->table_smon, sizeof(stats_table_mon_t), 0, sizeof(stats_table_mon_t));
    knl_securec_check(ret);
}

static inline bool32 stats_check_table_has_active_txn(dc_entity_t *entity, const knl_session_t *session) {
    cm_spin_lock(&entity->entry->sch_lock_mutex, &session->stat->spin_stat.stat_sch_lock);
    bool32 in_txn = CT_FALSE;
    if (entity->entry->sch_lock != NULL) {
        in_txn = (entity->entry->sch_lock->shared_count > 1);
    }
    cm_spin_unlock(&entity->entry->sch_lock_mutex);
    return in_txn;
}

void stats_disable_table_mon(knl_session_t *session, knl_dictionary_t *dc, bool32 analyzed)
{
    dc_entity_t *entity = DC_ENTITY(dc);
    table_t *table = &entity->table;
    part_table_t *part_table = NULL;
    table_part_t *table_part = NULL;
    stats_table_mon_t *tab_mon = NULL;
    
    if (!analyzed) {
        return;
    }

    if (IS_TEMP_TABLE_BY_DC(dc)) {
        knl_temp_cache_t *temp_cache = knl_get_temp_cache(session, table->desc.uid, table->desc.id);
        if (temp_cache == NULL) {
            return;
        }

        tab_mon = &temp_cache->table_smon;
    } else {
        if (entity->entry->appendix == NULL) {
            return;
        }

        tab_mon = &entity->entry->appendix->table_smon;
    }

    errno_t ret;
    bool32 has_active_txn = stats_check_table_has_active_txn(entity, session);
    if (!has_active_txn) {
        ret = memset_sp(tab_mon, sizeof(stats_table_mon_t), 0, sizeof(stats_table_mon_t));
        knl_securec_check(ret);
    }

    if (IS_PART_TABLE(table)) {
        part_table = table->part_table;
        for (uint32 i = 0; i < part_table->desc.partcnt; i++) {
            table_part = TABLE_GET_PART(table, i);
            if (!IS_READY_PART(table_part)) {
                continue;
            }
            
            if (!has_active_txn) { 
                ret = memset_sp(&table_part->table_smon, sizeof(stats_table_mon_t), 0, sizeof(stats_table_mon_t));
                knl_securec_check(ret);
            }
        }
    }
}

status_t stats_refresh_dc(knl_session_t *session, knl_dictionary_t *dc, stats_load_info_t load_info)
{
    if (dc->type == DICT_TYPE_TEMP_TABLE_TRANS) {
        return CT_SUCCESS;
    }

    dc_entity_t *entity = DC_ENTITY(dc);

    knl_set_session_scn(session, CT_INVALID_ID64);
    if (cbo_refresh_statistics(session, entity, load_info) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t rd_internal_refresh_dc(knl_session_t *session, dc_entity_t *entity, stats_load_info_t *load_info)
{
    knl_set_session_scn(session, CT_INVALID_ID64);
    if (cbo_refresh_statistics(session, entity, *load_info) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

void stats_dc_invalidate(knl_session_t *session, knl_dictionary_t *dc)
{
    dc_entity_t *entity = DC_ENTITY(dc);

    if (lock_table_directly(session, dc, LOCK_INF_WAIT) != CT_SUCCESS) {
        CT_LOG_RUN_WAR("lock table failed when invalidate statistics");
        return;
    }

    if (lock_child_table_directly(session, entity, CT_FALSE) != CT_SUCCESS) {
        unlock_tables_directly(session);
        CT_LOG_RUN_WAR("lock table failed when invalidate statistics");
        return;
    }

    dc_invalidate_children(session, entity);
    dc_invalidate(session, entity);

    unlock_tables_directly(session);
}

void stats_set_analyzed(knl_session_t *session, knl_dictionary_t *dc, bool32 analyzed)
{
    if (!analyzed) {
        return;
    }

    dc_entity_t *entity = DC_ENTITY(dc);

    cm_spin_lock(&entity->entry->lock, &session->stat->spin_stat.stat_dc_entry);
    entity->is_analyzing = CT_FALSE;
    cm_spin_unlock(&entity->entry->lock);
}

status_t stats_check_analyzing(knl_session_t *session, knl_dictionary_t *dc, bool32 *need_analyze,
                               bool32 is_dynamic)
{
    dc_entity_t *entity = DC_ENTITY(dc);
    table_t *table = &entity->table;
    date_t analyze_time = 0;
    date_t now_date = cm_now();
    knl_scan_key_t *key = NULL;
    knl_cursor_t *cursor = NULL;
    status_t status = CT_SUCCESS;

    cm_spin_lock(&entity->entry->lock, &session->stat->spin_stat.stat_dc_entry);
    if (!entity->is_analyzing) {
        entity->is_analyzing = CT_TRUE;
        *need_analyze = CT_TRUE;
        cm_spin_unlock(&entity->entry->lock);
        return CT_SUCCESS;
    } else {
        if (is_dynamic) {
            cm_spin_unlock(&entity->entry->lock);
            return CT_SUCCESS;
        }
    }
    cm_spin_unlock(&entity->entry->lock);

    CM_SAVE_STACK(session->stack);
    cursor = knl_push_cursor(session);

    while (CT_TRUE) {
        if (session->canceled) {
            CT_THROW_ERROR(ERR_OPERATION_CANCELED);
            status = CT_ERROR;
            break;
        }

        if (session->killed) {
            CT_THROW_ERROR(ERR_OPERATION_KILLED);
            status = CT_ERROR;
            break;
        }

        cm_spin_lock(&entity->entry->lock, &session->stat->spin_stat.stat_dc_entry);
        if (entity->is_analyzing) {
            cm_spin_unlock(&entity->entry->lock);
            cm_spin_sleep();
            continue;
        }
        cm_spin_unlock(&entity->entry->lock);

        table = DC_TABLE(dc);
        knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_TABLE_ID, IX_SYS_TABLE_001_ID);
        key = &cursor->scan_range.l_key;
        knl_init_index_scan(cursor,
                            CT_TRUE);
        knl_set_scan_key(INDEX_DESC(cursor->index), key, CT_TYPE_INTEGER, &table->desc.uid, sizeof(uint32),
                         IX_COL_SYS_TABLE_001_USER_ID);
        // table name is smaller than 68
        knl_set_scan_key(INDEX_DESC(cursor->index), key, CT_TYPE_STRING, table->desc.name,
                         (uint16)strlen(table->desc.name), IX_COL_SYS_TABLE_001_NAME);

        if (knl_fetch(session, cursor) != CT_SUCCESS) {
            status = CT_ERROR;
            break;
        }

        if (cursor->eof) {
            CT_THROW_ERROR(ERR_OBJECT_ALREADY_DROPPED, "table");
            status = CT_ERROR;
            break;
        }

        cm_spin_lock(&entity->entry->lock, &session->stat->spin_stat.stat_dc_entry);
        if (entity->is_analyzing) {
            cm_spin_unlock(&entity->entry->lock);
            cm_spin_sleep();
            continue;
        }

        /* no analyze table */
        if (CURSOR_COLUMN_SIZE(cursor, TABLE_ANALYZE_TIME) == CT_NULL_VALUE_LEN) {
            entity->is_analyzing = CT_TRUE;
            *need_analyze = CT_TRUE;
            cm_spin_unlock(&entity->entry->lock);
            break;
        }

        analyze_time = *(date_t *)CURSOR_COLUMN_DATA(cursor, TABLE_ANALYZE_TIME);
        /* first concurrent analyze table thread analyze failed, second will analyze table again */
        if (now_date >= analyze_time) {
            entity->is_analyzing = CT_TRUE;
            *need_analyze = CT_TRUE;
            cm_spin_unlock(&entity->entry->lock);
            break;
        }

        cm_spin_unlock(&entity->entry->lock);
        break;
    }

    CM_RESTORE_STACK(session->stack);
    return status;
}

static void stats_recorde_table_change(knl_cursor_t *cursor, stats_table_mon_t *table_smon)
{
    table_smon->is_change = CT_TRUE;
    table_smon->timestamp = cm_now();
    switch (cursor->action) {
        case CURSOR_ACTION_UPDATE:
            table_smon->updates++;
            break;
        case CURSOR_ACTION_INSERT:
            table_smon->inserts += (cursor->rowid_count > 0) ? cursor->rowid_count : 1;
            break;
        case CURSOR_ACTION_DELETE:
            table_smon->deletes++;
            break;

        default:
            break;
    }
}

void stats_monitor_table_change(knl_cursor_t *cursor)
{
    dc_entity_t *entity = (dc_entity_t *)cursor->dc_entity;
    table_t *table = &entity->table;

    if (IS_PART_TABLE(table)) {
        table_part_t *table_part = TABLE_GET_PART(table, cursor->part_loc.part_no);
        stats_recorde_table_change(cursor, &table_part->table_smon);
    }

    if (TABLE_IS_TEMP(table->desc.type)) {
        knl_temp_cache_t *temp_cache = cursor->temp_cache;
        stats_recorde_table_change(cursor, &temp_cache->table_smon);
    } else {
        stats_recorde_table_change(cursor, &entity->entry->appendix->table_smon);
    }
}

void stats_init_stats_option(stats_option_t *stats_option, knl_analyze_tab_def_t *def)
{
    errno_t ret;

    ret = memset_sp(stats_option, sizeof(stats_option_t), 0, sizeof(stats_option_t));
    knl_securec_check(ret);

    stats_option->sample_ratio =  def->sample_ratio < CT_REAL_PRECISION
                                    ? STATS_FULL_TABLE_SAMPLE_RATIO : (def->sample_ratio / 100);
    stats_option->sample_level = BLOCK_SAMPLE;
    stats_option->method_opt = def->method_opt.option;
    stats_option->analyze_type = def->sample_type;
    stats_option->dynamic_type = def->dynamic_type;
    stats_option->is_report = def->is_report;
    stats_option->report_col_file = INVALID_FILE_HANDLE;
    stats_option->report_idx_file = INVALID_FILE_HANDLE;
    stats_option->report_tab_file = INVALID_FILE_HANDLE;

    if (def->method_opt.option == FOR_SPECIFIED_COLUMNS || def->method_opt.option == FOR_SPECIFIED_INDEXED_COLUMNS) {
        stats_option->specify_cols = &def->specify_cols;
    }
}

status_t stats_find_part(knl_session_t *session, knl_analyze_tab_def_t *def, knl_dictionary_t *dc,
                         table_part_t **table_part)
{
    table_t *table = DC_TABLE(dc);
    part_table_t *part_table = table->part_table;
    char no_str[STATS_MAX_PARTNO_MSG_LEN];
    text_t partno_str;

    partno_str.str = (char *)no_str;
    partno_str.len = STATS_MAX_PARTNO_MSG_LEN;

    if (def->part_name.len > 0) {
        if (!part_table_find_by_name(part_table, &def->part_name, table_part)) {
            CT_THROW_ERROR(ERR_PARTITION_NOT_EXIST, "table", T2S(&def->part_name));
            return CT_ERROR;
        }

        if ((*table_part)->desc.not_ready == PARTITON_NOT_READY) {
            CT_THROW_ERROR(ERR_PARTITION_NOT_READY, "table", T2S(&def->part_name));
            return CT_ERROR;
        }
    } else {
        if (def->part_no == CT_INVALID_ID32) {
            CT_THROW_ERROR(ERR_EXCEED_MAX_PARTCNT, (uint32)CT_MAX_PART_COUNT);
            return CT_ERROR;
        }

        *table_part = PART_GET_ENTITY(part_table, def->part_no);

        if (*table_part == NULL) {
            cm_uint32_to_text(def->part_no, &partno_str);
            CT_THROW_ERROR(ERR_PARTITION_NOT_EXIST, "table", T2S(&partno_str));
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

status_t stats_set_analyze_time(knl_session_t *session, knl_dictionary_t *dc, bool32 locked)
{
    knl_cursor_t *cursor = NULL;
    row_assist_t ra;
    knl_scan_key_t *key = NULL;
    table_t *table = NULL;
    uint16 size;

    CM_SAVE_STACK(session->stack);
    cursor = knl_push_cursor(session);
    table = DC_TABLE(dc);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_TABLE_ID, IX_SYS_TABLE_001_ID);
    key = &cursor->scan_range.l_key;
    knl_init_index_scan(cursor, CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, CT_TYPE_INTEGER, &table->desc.uid, sizeof(uint32),
                     IX_COL_SYS_TABLE_001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, CT_TYPE_STRING, table->desc.name,
                     (uint16)strlen(table->desc.name), IX_COL_SYS_TABLE_001_NAME);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    if (cursor->eof) {
        CM_RESTORE_STACK(session->stack);
        CT_THROW_ERROR(ERR_OBJECT_ALREADY_DROPPED, "table");
        return CT_ERROR;
    }

    cursor->update_info.count = 1;
    row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), 1);
    if (locked) {
        (void)row_put_int64(&ra, CT_INVALID_ID64);
    } else {
        (void)row_put_date(&ra, cm_now());
    }
    cursor->update_info.columns[0] = SYS_TABLE_COL_ANALYZETIME;

    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, &size);

    if (knl_internal_update(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}

static status_t stats_calc_table_empty_block(knl_session_t *session, knl_table_set_stats_t *tab_stats,
    uint32 *empty_block)
{
    if ((tab_stats->rownums == 0 && tab_stats->avgrlen != 0) || (tab_stats->avgrlen == 0 && tab_stats->rownums != 0)) {
        CT_LOG_RUN_ERR("stats: fail to estimate empty block according to given parameters");
        return CT_ERROR;
    }

    if (tab_stats->rownums != 0 && tab_stats->avgrlen != 0 && tab_stats->blknums == 0) {
        CT_LOG_RUN_ERR("stats: fail to estimate empty block according to given parameters");
        return CT_ERROR;
    }

    uint32 block_data_size = DEFAULT_PAGE_SIZE(session) - sizeof(heap_page_t) - sizeof(page_tail_t) - sizeof(itl_t);
    uint32 non_empty_block = (uint32)((tab_stats->avgrlen * tab_stats->rownums) / block_data_size);
    *empty_block = (tab_stats->blknums > non_empty_block) ? (tab_stats->blknums - non_empty_block) : 0;
    return CT_SUCCESS;
}

static void stats_verfiy_table_stats(knl_cursor_t *cursor, knl_table_set_stats_t *tab_stats)
{
    knl_table_set_stats_t sys_stats;

    errno_t ret = memset_sp(&sys_stats, sizeof(knl_table_set_stats_t), 0, sizeof(knl_table_set_stats_t));
    knl_securec_check(ret);

    if (tab_stats->is_single_part) {
        if (CURSOR_COLUMN_SIZE(cursor, SYS_INDEXPART_COL_ANALYZETIME) != CT_NULL_VALUE_LEN) {
            sys_stats.rownums = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_TABLEPART_COL_ROWCNT);
            sys_stats.blknums = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_TABLEPART_COL_BLKCNT);
            sys_stats.avgrlen = *(uint64 *)CURSOR_COLUMN_DATA(cursor, SYS_TABLEPART_COL_AVGRLN);
            // samplesize should be got by uint32 while the type of sys_stats.samplesize is uint64
            sys_stats.samplesize = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_TABLEPART_COL_SAMPLESIZE);
        }
    } else {
        if (CURSOR_COLUMN_SIZE(cursor, SYS_TABLE_COL_ANALYZETIME) != CT_NULL_VALUE_LEN) {
            sys_stats.rownums = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_TABLE_COL_NUM_ROWS);
            sys_stats.blknums = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_TABLE_COL_BLOCKS);
            sys_stats.avgrlen = *(uint64 *)CURSOR_COLUMN_DATA(cursor, SYS_TABLE_COL_AVG_ROW_LEN);
            // samplesize should be got by uint32 while the type of sys_stats.samplesize is uint64
            sys_stats.samplesize = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_TABLE_COL_SAMPLESIZE);
        }
    }

    tab_stats->rownums = (tab_stats->rownums == CT_INVALID_ID32) ? sys_stats.rownums : tab_stats->rownums;
    tab_stats->blknums = (tab_stats->blknums == CT_INVALID_ID32) ? sys_stats.blknums : tab_stats->blknums;
    tab_stats->avgrlen = (tab_stats->avgrlen == CT_INVALID_ID64) ? sys_stats.avgrlen : tab_stats->avgrlen;
    tab_stats->samplesize = (tab_stats->samplesize == CT_INVALID_ID64) ? sys_stats.samplesize : tab_stats->samplesize;
}

static void stats_set_table_updata_info(knl_update_info_t *update_info, knl_table_set_stats_t *tab_stats)
{
    if (tab_stats->is_single_part) {
        update_info->columns[0] = SYS_TABLEPART_COL_ROWCNT;
        update_info->columns[1] = SYS_TABLEPART_COL_BLKCNT;
        update_info->columns[2] = SYS_TABLEPART_COL_EMPCNT;
        update_info->columns[3] = SYS_TABLEPART_COL_AVGRLN;
        update_info->columns[4] = SYS_TABLEPART_COL_SAMPLESIZE;
        update_info->columns[5] = SYS_TABLEPART_COL_ANALYZETIME;
    } else {
        update_info->columns[0] = SYS_TABLE_COL_NUM_ROWS;
        update_info->columns[1] = SYS_TABLE_COL_BLOCKS;
        update_info->columns[2] = SYS_TABLE_COL_EMPTY_BLOCKS;
        update_info->columns[3] = SYS_TABLE_COL_AVG_ROW_LEN;
        update_info->columns[4] = SYS_TABLE_COL_SAMPLESIZE;
        update_info->columns[5] = SYS_TABLE_COL_ANALYZETIME;
    }
}

static status_t stats_update_sys_table_force(knl_session_t *session, knl_dictionary_t *dc,
                                             knl_table_set_stats_t *tab_stats)
{
    knl_cursor_t *cursor = NULL;
    row_assist_t ra;
    knl_scan_key_t *key = NULL;
    table_t *table = NULL;
    uint16 size;

    CM_SAVE_STACK(session->stack);
    cursor = knl_push_cursor(session);
    table = DC_TABLE(dc);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_TABLE_ID, IX_SYS_TABLE_001_ID);
    key = &cursor->scan_range.l_key;
    knl_init_index_scan(cursor, CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, CT_TYPE_INTEGER, &table->desc.uid, sizeof(uint32),
                     IX_COL_SYS_TABLE_001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, CT_TYPE_STRING, table->desc.name,
                     (uint16)strlen(table->desc.name), IX_COL_SYS_TABLE_001_NAME);
   
    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    if (cursor->eof) {
        CM_RESTORE_STACK(session->stack);
        CT_THROW_ERROR(ERR_OBJECT_ALREADY_DROPPED, "table");
        return CT_ERROR;
    }

    stats_verfiy_table_stats(cursor, tab_stats);

    uint32 empty_block = 0;
    if (stats_calc_table_empty_block(session, tab_stats, &empty_block) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        CT_THROW_ERROR(ERR_INVALID_OPERATION, ", fail to estimate empty_block");
        return CT_ERROR;
    }

    cursor->update_info.count = UPDATE_COLUMN_COUNT_SIX;
    row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), UPDATE_COLUMN_COUNT_SIX);
    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, tab_stats->rownums));
    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, tab_stats->blknums));
    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, empty_block));
    (void)row_put_int64(&ra, tab_stats->avgrlen);
    (void)row_put_int64(&ra, MIN(CT_MAX_INT32, tab_stats->samplesize));
    (void)row_put_int64(&ra, CT_INVALID_ID64);

    stats_set_table_updata_info(&cursor->update_info, tab_stats);
    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, &size);

    if (knl_internal_update(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    CM_RESTORE_STACK(session->stack);

    return stats_set_analyze_time(session, dc, CT_TRUE);
}

static status_t stats_update_sys_tablepart_force(knl_session_t *session, knl_dictionary_t *dc, table_part_t *table_part,
                                                 knl_table_set_stats_t *tab_stats)
{
    knl_cursor_t *cursor = NULL;
    row_assist_t ra;
    knl_scan_key_t *key = NULL;
    uint16 size;

    CM_SAVE_STACK(session->stack);
    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_TABLEPART_ID, IX_SYS_TABLEPART001_ID);
    key = &cursor->scan_range.l_key;
    knl_init_index_scan(cursor, CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, CT_TYPE_INTEGER, &table_part->desc.uid, sizeof(uint32),
                     IX_COL_SYS_TABLEPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, CT_TYPE_INTEGER, &table_part->desc.table_id, sizeof(uint32),
                     IX_COL_SYS_TABLEPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, CT_TYPE_INTEGER, &table_part->desc.part_id, sizeof(uint32),
                     IX_COL_SYS_TABLEPART001_PART_ID);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    if (cursor->eof) {
        CM_RESTORE_STACK(session->stack);
        CT_THROW_ERROR(ERR_OBJECT_ALREADY_DROPPED, table_part->desc.name);
        return CT_ERROR;
    }

    stats_verfiy_table_stats(cursor, tab_stats);

    uint32 empty_block = 0;
    if (stats_calc_table_empty_block(session, tab_stats, &empty_block) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        CT_THROW_ERROR(ERR_INVALID_OPERATION, ", fail to estimate empty_block");
        return CT_ERROR;
    }

    cursor->update_info.count = UPDATE_COLUMN_COUNT_FIVE;
    row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), UPDATE_COLUMN_COUNT_FIVE);
    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, tab_stats->rownums));
    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, tab_stats->blknums));
    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, empty_block));
    (void)row_put_int64(&ra, tab_stats->avgrlen);
    (void)row_put_int64(&ra, MIN(CT_MAX_INT32, tab_stats->samplesize));
    (void)row_put_int64(&ra, CT_INVALID_ID64);

    stats_set_table_updata_info(&cursor->update_info, tab_stats);
    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, &size);

    if (knl_internal_update(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    CM_RESTORE_STACK(session->stack);

    return stats_set_analyze_time(session, dc, CT_TRUE);
}

static void stats_set_colunm_updata_info(knl_session_t *session, knl_cursor_t *cursor,
    knl_column_set_stats_t *col_stats)
{
    row_assist_t ra;
    uint16 size;
    knl_update_info_t *update_info = &cursor->update_info;

    cursor->update_info.count = UPDATE_COLUMN_COUNT_SIX;
    row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), UPDATE_COLUMN_COUNT_SIX);
    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, col_stats->nullnum));
    (void)row_put_int64(&ra, CT_INVALID_ID64);
    (void)row_put_text(&ra, &col_stats->min_value);
    (void)row_put_text(&ra, &col_stats->max_value);
    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, col_stats->distnum));
    (void)row_put_real(&ra, col_stats->density);

    update_info->columns[0] = SYS_HISTGRAM_ABSTR_COL_NUM_NULL;
    update_info->columns[1] = SYS_HISTGRAM_ABSTR_COL_ANALYZETIME;
    update_info->columns[2] = SYS_HISTGRAM_ABSTR_COL_MINVALUE;
    update_info->columns[3] = SYS_HISTGRAM_ABSTR_COL_MAXVALUE;
    update_info->columns[4] = SYS_HISTGRAM_ABSTR_COL_NUM_DISTINCT;
    update_info->columns[5] = SYS_HISTGRAM_ABSTR_COL_DENSITY;

    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, &size);
}

static void stats_verfiy_colunm_stats(knl_cursor_t *cursor, knl_column_set_stats_t *col_stats)
{
    knl_column_set_stats_t sys_stats;

    errno_t ret = memset_sp(&sys_stats, sizeof(knl_column_set_stats_t), 0, sizeof(knl_column_set_stats_t));
    knl_securec_check(ret);

    if (CURSOR_COLUMN_SIZE(cursor, SYS_HISTGRAM_ABSTR_COL_ANALYZETIME) != CT_NULL_VALUE_LEN) {
        sys_stats.nullnum = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_HISTGRAM_ABSTR_COL_NUM_NULL);
        sys_stats.distnum = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_HISTGRAM_ABSTR_COL_NUM_DISTINCT);
        sys_stats.density = *(double *)CURSOR_COLUMN_DATA(cursor, SYS_HISTGRAM_ABSTR_COL_DENSITY);
        sys_stats.min_value.str = CURSOR_COLUMN_DATA(cursor, SYS_HISTGRAM_ABSTR_COL_MINVALUE);
        sys_stats.min_value.len = CURSOR_COLUMN_SIZE(cursor, SYS_HISTGRAM_ABSTR_COL_MINVALUE);
        sys_stats.max_value.str = CURSOR_COLUMN_DATA(cursor, SYS_HISTGRAM_ABSTR_COL_MAXVALUE);
        sys_stats.max_value.len = CURSOR_COLUMN_SIZE(cursor, SYS_HISTGRAM_ABSTR_COL_MAXVALUE);
    }

    col_stats->nullnum = (col_stats->nullnum == CT_INVALID_ID32) ? sys_stats.nullnum : col_stats->nullnum;
    col_stats->distnum = (col_stats->distnum == CT_INVALID_ID32) ? sys_stats.distnum : col_stats->distnum;
    col_stats->density = (col_stats->density == CT_INVALID_ID64) ? sys_stats.density : col_stats->density;
    if (col_stats->max_value.len == CT_NULL_VALUE_LEN) {
        ret = memcpy_sp(col_stats->max_value.str, STATS_MAX_BUCKET_SIZE,
            sys_stats.max_value.str, sys_stats.max_value.len);
        knl_securec_check(ret);

        col_stats->max_value.len = sys_stats.max_value.len;
    }

    if (col_stats->min_value.len == CT_NULL_VALUE_LEN) {
        ret = memcpy_sp(col_stats->min_value.str, STATS_MAX_BUCKET_SIZE,
            sys_stats.min_value.str, sys_stats.min_value.len);
        knl_securec_check(ret);

        col_stats->min_value.len = sys_stats.min_value.len;
    }
}

status_t stats_update_sys_histhead_force(knl_session_t *session, knl_dictionary_t *dc, knl_column_set_stats_t *col_stats,
                                         table_part_t *table_part, knl_column_t *column)
{
    uint64 part_id = (table_part != NULL) ? table_part->desc.part_id : CT_INVALID_ID32;
    table_t *table = DC_TABLE(dc);

    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);

    stats_open_hist_abstr_cursor(session, cursor, CURSOR_ACTION_UPDATE, IX_HIST_HEAD_003_ID,
        IS_NOLOGGING_BY_TABLE_TYPE(DC_TABLE(dc)->desc.type));
    knl_init_index_scan(cursor, CT_TRUE);
    knl_scan_key_t *key = &cursor->scan_range.l_key;
    knl_set_scan_key(INDEX_DESC(cursor->index), key, CT_TYPE_INTEGER, &column->uid, sizeof(uint32),
                     IX_COL_HIST_HEAD_003_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, CT_TYPE_INTEGER, &column->table_id, sizeof(uint32),
                     IX_COL_HIST_HEAD_003_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, CT_TYPE_INTEGER, &column->id, sizeof(uint32),
                     IX_COL_HIST_HEAD_003_COL_ID);
    if (IS_PART_TABLE(table)) {
        knl_set_scan_key(INDEX_DESC(cursor->index), key, CT_TYPE_BIGINT, &part_id, sizeof(uint64),
            IX_COL_HIST_HEAD_003_SPARE1);
    } else {
        knl_set_key_flag(key, SCAN_KEY_IS_NULL, IX_COL_HIST_HEAD_003_SPARE1);
    }

    if (IS_PART_TABLE(table) && IS_COMPART_TABLE(table->part_table)) {
        knl_set_scan_key(INDEX_DESC(cursor->index), key, CT_TYPE_BIGINT, &part_id, sizeof(uint64),
            IX_COL_HIST_HEAD_003_SPARE2);
    } else {
        knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_IS_NULL, IX_COL_HIST_HEAD_003_SPARE2);
    }

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    if (cursor->eof) {
        CM_RESTORE_STACK(session->stack);
        CT_THROW_ERROR(ERR_OBJECT_NOT_EXISTS, "column statistics of", column->name);
        return CT_ERROR;
    }

    stats_verfiy_colunm_stats(cursor, col_stats);
    stats_set_colunm_updata_info(session, cursor, col_stats);

    if (knl_internal_update(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    return stats_set_analyze_time(session, dc, CT_TRUE);
}

static void stats_set_index_updata_info(knl_update_info_t *update_info, knl_index_set_stats_t *idx_stats)
{
    if (idx_stats->is_single_part) {
        update_info->columns[0] = SYS_INDEXPART_COL_BLEVEL;
        update_info->columns[1] = SYS_INDEXPART_COL_LEVEL_BLOCKS;
        update_info->columns[2] = SYS_INDEXPART_COL_DISTKEY;
        update_info->columns[3] = SYS_INDEXPART_COL_LBLKKEY;
        update_info->columns[4] = SYS_INDEXPART_COL_DBLKKEY;
        update_info->columns[5] = SYS_INDEXPART_COL_ANALYZETIME;
        update_info->columns[6] = SYS_INDEXPART_COL_EMPTY_LEAF_BLOCKS;
        update_info->columns[7] = SYS_INDEXPART_COL_CLUFAC;
        update_info->columns[8] = SYS_INDEXPART_COL_COMB_COLS_2_NDV;
        update_info->columns[9] = SYS_INDEXPART_COL_COMB_COLS_3_NDV;
        update_info->columns[10] = SYS_INDEXPART_COL_COMB_COLS_4_NDV;
    } else {
        update_info->columns[0] = SYS_INDEX_COLUMN_ID_BLEVEL;
        update_info->columns[1] = SYS_INDEX_COLUMN_ID_LEVEL_BLOCKS;
        update_info->columns[2] = SYS_INDEX_COLUMN_ID_DISTINCT_KEYS;
        update_info->columns[3] = SYS_INDEX_COLUMN_ID_AVG_LEAF_BLOCKS_PER_KEY;
        update_info->columns[4] = SYS_INDEX_COLUMN_ID_AVG_DATA_BLOCKS_PER_KEY;
        update_info->columns[5] = SYS_INDEX_COLUMN_ID_ANALYZETIME;
        update_info->columns[6] = SYS_INDEX_COLUMN_ID_EMPTY_LEAF_BLOCKS;
        update_info->columns[7] = SYS_INDEX_COLUMN_ID_CLUFAC;
        update_info->columns[8] = SYS_INDEX_COLUMN_ID_COMB2_NDV;
        update_info->columns[9] = SYS_INDEX_COLUMN_ID_COMB3_NDV;
        update_info->columns[10] = SYS_INDEX_COLUMN_ID_COMB4_NDV;
    }
}

static void stats_verfiy_index_stats(knl_cursor_t *cursor, knl_index_set_stats_t *idx_stats)
{
    knl_index_set_stats_t sys_stats;

    errno_t ret = memset_sp(&sys_stats, sizeof(knl_index_set_stats_t), 0, sizeof(knl_index_set_stats_t));
    knl_securec_check(ret);

    if (idx_stats->is_single_part) {
        if (CURSOR_COLUMN_SIZE(cursor, SYS_INDEXPART_COL_ANALYZETIME) != CT_NULL_VALUE_LEN) {
            sys_stats.indlevel = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_INDEXPART_COL_BLEVEL);
            sys_stats.numlblks = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_INDEXPART_COL_LEVEL_BLOCKS);
            sys_stats.numdist = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_INDEXPART_COL_DISTKEY);
            sys_stats.avglblk = *(double *)CURSOR_COLUMN_DATA(cursor, SYS_INDEXPART_COL_LBLKKEY);
            sys_stats.avgdblk = *(double *)CURSOR_COLUMN_DATA(cursor, SYS_INDEXPART_COL_DBLKKEY);
            sys_stats.clstfct = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_INDEXPART_COL_CLUFAC);
            sys_stats.combndv2 = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_INDEXPART_COL_COMB_COLS_2_NDV);
            sys_stats.combndv3 = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_INDEXPART_COL_COMB_COLS_3_NDV);
            sys_stats.combndv4 = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_INDEXPART_COL_COMB_COLS_4_NDV);
        }
    } else {
        if (CURSOR_COLUMN_SIZE(cursor, SYS_INDEX_COLUMN_ID_ANALYZETIME) != CT_NULL_VALUE_LEN) {
            sys_stats.indlevel = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_INDEX_COLUMN_ID_BLEVEL);
            sys_stats.numlblks = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_INDEX_COLUMN_ID_LEVEL_BLOCKS);
            sys_stats.numdist = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_INDEX_COLUMN_ID_DISTINCT_KEYS);
            sys_stats.avglblk = *(double *)CURSOR_COLUMN_DATA(cursor, SYS_INDEX_COLUMN_ID_AVG_LEAF_BLOCKS_PER_KEY);
            sys_stats.avgdblk = *(double *)CURSOR_COLUMN_DATA(cursor, SYS_INDEX_COLUMN_ID_AVG_DATA_BLOCKS_PER_KEY);
            sys_stats.clstfct = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_INDEX_COLUMN_ID_CLUFAC);
            sys_stats.combndv2 = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_INDEX_COLUMN_ID_COMB2_NDV);
            sys_stats.combndv3 = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_INDEX_COLUMN_ID_COMB3_NDV);
            sys_stats.combndv4 = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_INDEX_COLUMN_ID_COMB4_NDV);
        }
    }

    idx_stats->indlevel = (idx_stats->indlevel == CT_INVALID_ID32) ? sys_stats.indlevel : idx_stats->indlevel;
    idx_stats->numlblks = (idx_stats->numlblks == CT_INVALID_ID32) ? sys_stats.numlblks : idx_stats->numlblks;
    idx_stats->numdist = (idx_stats->numdist == CT_INVALID_ID32) ? sys_stats.numdist : idx_stats->numdist;
    idx_stats->avglblk = (idx_stats->avglblk == CT_INVALID_ID64) ? sys_stats.avglblk : idx_stats->avglblk;
    idx_stats->avgdblk = (idx_stats->avgdblk == CT_INVALID_ID64) ? sys_stats.avgdblk : idx_stats->avgdblk;
    idx_stats->clstfct = (idx_stats->clstfct == CT_INVALID_ID32) ? sys_stats.clstfct : idx_stats->clstfct;
    idx_stats->combndv2 = (idx_stats->combndv2 == CT_INVALID_ID32) ? sys_stats.combndv2 : idx_stats->combndv2;
    idx_stats->combndv3 = (idx_stats->combndv3 == CT_INVALID_ID32) ? sys_stats.combndv3 : idx_stats->combndv3;
    idx_stats->combndv4 = (idx_stats->combndv4 == CT_INVALID_ID32) ? sys_stats.combndv4 : idx_stats->combndv4;
}

static inline status_t stats_check_idx_stats_params(knl_index_set_stats_t *idx_stats)
{
    if (idx_stats->avgdblk == 0 || idx_stats->numlblks == 0 || idx_stats->avglblk == 0) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t stats_calc_empty_leaves_index(knl_session_t *session, index_t *idx, knl_index_set_stats_t *idx_stats,
    btree_segment_t *segment, uint32 *empty_block)
{
    uint32 dir_size = (idx->desc.cr_mode == CR_ROW) ? sizeof(btree_dir_t) : sizeof(pcrb_dir_t);
    uint32 itl_size = (idx->desc.cr_mode == CR_ROW) ? sizeof(itl_t) : sizeof(pcr_itl_t);
    uint32 level = idx_stats->indlevel;
    uint64 higher_level_page = 1;
    uint64 estimate_data_page = 0;
    page_type_t page_type = (idx->desc.cr_mode == CR_PAGE) ? PAGE_TYPE_PCRB_NODE : PAGE_TYPE_BTREE_NODE;

    if (!spc_validate_page_id(session, AS_PAGID(segment->tree_info.root))) {
        CT_LOG_RUN_ERR("stats: index %s has been droped", idx->desc.name);
        return CT_ERROR;
    }

    buf_enter_page(session, AS_PAGID(segment->tree_info.root), LATCH_MODE_S, ENTER_PAGE_NORMAL);
    btree_page_t *page = BTREE_CURR_PAGE(session);

    if (btree_check_segment_scn(page, page_type, segment->seg_scn) != CT_SUCCESS) {
        buf_leave_page(session, CT_FALSE);
        CT_LOG_RUN_ERR("stats: page scn is different from seg scn, index name: %s", idx->desc.name);
        return CT_ERROR;
    }

    uint64 avg_key_len = 0;
    for (uint32 i = 1; i < page->keys; i++) {
        if (idx->desc.cr_mode == CR_PAGE) {
            pcrb_dir_t *pcrb_dir = pcrb_get_dir(page, i);
            pcrb_key_t *pcrb_key = PCRB_GET_KEY(page, pcrb_dir);
            avg_key_len += (pcrb_key->size - sizeof(page_id_t));
        } else {
            btree_dir_t *dir = BTREE_GET_DIR(page, i);
            btree_key_t *key = BTREE_GET_KEY(page, dir);
            avg_key_len += key->size;
        }
    }

    buf_leave_page(session, CT_FALSE);

    avg_key_len = (page->keys > 1) ? (uint64)(avg_key_len / (page->keys - 1)) : 0;
    uint32 page_data_size = DEFAULT_PAGE_SIZE(session) - sizeof(btree_page_t) -
        (SPACE_GET(session, segment->space_id))->ctrl->cipher_reserve_size - sizeof(page_tail_t) -
        page->itls * itl_size;
    double page_load_factor = 0.5; // assume that half of each btree page is used
    uint32 ratio = (uint32)(page_data_size * page_load_factor / (avg_key_len + dir_size));

    /* estimate leaf_block_percent */
    estimate_data_page += higher_level_page;
    for (; level > 0; level--) {
        higher_level_page = higher_level_page * ratio;
        estimate_data_page += higher_level_page;
    }

    double leaf_block_percent = (double)higher_level_page / estimate_data_page;
    uint64 total_data_block = (uint64)(idx_stats->avgdblk * (idx_stats->numlblks / idx_stats->avglblk));
    uint32 non_empty_leaves = (uint32)(total_data_block * leaf_block_percent);
    *empty_block = (non_empty_leaves > idx_stats->numlblks) ? (non_empty_leaves - idx_stats->numlblks) : 0;

    return CT_SUCCESS;
}

static status_t stats_calc_empty_block_index(knl_session_t *session, index_t *idx, knl_index_set_stats_t *idx_stats,
    uint32 *empty_block)
{
    if (stats_check_idx_stats_params(idx_stats) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("stats: fail to estimate empty block according to given parameters");
        return CT_ERROR;
    }

    page_id_t btree_entry = idx->desc.entry;
    knl_scn_t seg_scn = idx->desc.seg_scn;

    if (IS_INVALID_PAGID(btree_entry)) {
        CT_LOG_RUN_ERR("stats: invalid page id, index name: %s", idx->desc.name);
        return CT_ERROR;
    }

    buf_enter_page(session, btree_entry, LATCH_MODE_S, ENTER_PAGE_NORMAL);
    page_head_t *page = (page_head_t *)CURR_PAGE(session);
    btree_segment_t *segment = BTREE_GET_SEGMENT(session);
 
    if (page->type != PAGE_TYPE_BTREE_HEAD || segment->seg_scn != seg_scn) {
        buf_leave_page(session, CT_FALSE);
        CT_LOG_RUN_ERR("stats: current seg scn is different from origin seg scn, index name: %s", idx->desc.name);
        return CT_ERROR;
    }

    status_t ret = stats_calc_empty_leaves_index(session, idx, idx_stats, segment, empty_block);
    buf_leave_page(session, CT_FALSE);
    return ret;
}

static void stats_update_sys_index_row(knl_session_t *session, knl_cursor_t *cursor,
    knl_index_set_stats_t *idx_stats, uint32 empty_block)
{
    row_assist_t ra;
    uint16 size;

    row_init(&ra, cursor->update_info.data, HEAP_MAX_ROW_SIZE(session), UPDATE_COLUMN_COUNT_ELEVEN);
    (void)row_put_int32(&ra, MIN(CT_MAX_ROOT_LEVEL, idx_stats->indlevel));
    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, idx_stats->numlblks));
    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, idx_stats->numdist));
    (void)row_put_real(&ra, idx_stats->avglblk);
    (void)row_put_real(&ra, idx_stats->avgdblk);
    (void)row_put_int64(&ra, CT_INVALID_ID64);
    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, empty_block));
    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, idx_stats->clstfct));
    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, idx_stats->combndv2));
    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, idx_stats->combndv3));
    (void)row_put_int32(&ra, MIN(CT_MAX_INT32, idx_stats->combndv4));

    stats_set_index_updata_info(&cursor->update_info, idx_stats);
    cm_decode_row(cursor->update_info.data, cursor->update_info.offsets, cursor->update_info.lens, &size);

    return;
}

status_t stats_update_sys_index_force(knl_session_t *session, knl_dictionary_t *dc, knl_index_set_stats_t *idx_stats,
                                      index_t *index)
{
    knl_scan_key_t *key = NULL;

    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_INDEX_ID, IX_SYS_INDEX_002_ID);
    knl_init_index_scan(cursor, CT_TRUE);
    key = &cursor->scan_range.l_key;
    knl_set_scan_key(INDEX_DESC(cursor->index), key, CT_TYPE_INTEGER, &index->desc.uid, sizeof(uint32),
                     IX_COL_SYS_INDEX_002_USER);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, CT_TYPE_STRING, index->desc.name,
                     (uint16)strlen(index->desc.name), IX_COL_SYS_INDEX_002_NAME);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, CT_TYPE_INTEGER, &index->desc.table_id, sizeof(uint32),
                     IX_COL_SYS_INDEX_002_TABLE);
    
    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    if (cursor->eof) {
        CM_RESTORE_STACK(session->stack);
        CT_THROW_ERROR(ERR_INDEX_ALREADY_DROPPED, index->desc.name);
        return CT_ERROR;
    }

    stats_verfiy_index_stats(cursor, idx_stats);

    uint32 empty_block = 0;
    if (stats_calc_empty_block_index(session, index, idx_stats, &empty_block) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        CT_THROW_ERROR(ERR_INVALID_OPERATION, ", fail to estimate empty_block.");
        return CT_ERROR;
    }

    cursor->update_info.count = UPDATE_COLUMN_COUNT_ELEVEN;
    stats_update_sys_index_row(session, cursor, idx_stats, empty_block);
    if (knl_internal_update(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    CM_RESTORE_STACK(session->stack);

    return stats_set_analyze_time(session, dc, CT_TRUE);
}

static status_t stats_calc_empty_leaves_part(knl_session_t *session, index_part_t *idx_part,
    knl_index_set_stats_t *idx_stats, btree_segment_t *segment, uint32 *empty_block)
{
    uint32 dir_size = (idx_part->desc.cr_mode == CR_ROW) ? sizeof(btree_dir_t) : sizeof(pcrb_dir_t);
    uint32 itl_size = (idx_part->desc.cr_mode == CR_ROW) ? sizeof(itl_t) : sizeof(pcr_itl_t);
    uint32 level = idx_stats->indlevel;
    uint64 higher_level_page = 1;
    uint64 estimate_data_page = 0;
    page_type_t page_type = (idx_part->desc.cr_mode == CR_PAGE) ? PAGE_TYPE_PCRB_NODE : PAGE_TYPE_BTREE_NODE;

    if (!spc_validate_page_id(session, AS_PAGID(segment->tree_info.root))) {
        CT_LOG_RUN_ERR("stats: part index %s has been droped", idx_part->desc.name);
        return CT_ERROR;
    }

    buf_enter_page(session, AS_PAGID(segment->tree_info.root), LATCH_MODE_S, ENTER_PAGE_NORMAL);
    btree_page_t *page = BTREE_CURR_PAGE(session);

    if (btree_check_segment_scn(page, page_type, segment->seg_scn) != CT_SUCCESS) {
        buf_leave_page(session, CT_FALSE);
        CT_LOG_RUN_ERR("stats: page scn is different from seg scn, part index: %s", idx_part->desc.name);
        return CT_ERROR;
    }

    uint64 avg_key_len = 0;
    for (uint32 i = 1; i < page->keys; i++) {
        if (idx_part->desc.cr_mode == CR_PAGE) {
            pcrb_dir_t *pcrb_dir = pcrb_get_dir(page, i);
            pcrb_key_t *pcrb_key = PCRB_GET_KEY(page, pcrb_dir);
            avg_key_len += (pcrb_key->size - sizeof(page_id_t));
        } else {
            btree_dir_t *dir = BTREE_GET_DIR(page, i);
            btree_key_t *key = BTREE_GET_KEY(page, dir);
            avg_key_len += key->size;
        }
    }

    buf_leave_page(session, CT_FALSE);

    avg_key_len = (page->keys > 1) ? (uint64)(avg_key_len / (page->keys - 1)) : 0;
    uint32 page_data_size = DEFAULT_PAGE_SIZE(session) - sizeof(btree_page_t) -
        (SPACE_GET(session, segment->space_id))->ctrl->cipher_reserve_size - sizeof(page_tail_t) -
        page->itls * itl_size;
    double page_load_factor = 0.5; // assume that half of each btree page is used
    uint32 ratio = (uint32)(page_data_size * page_load_factor / (avg_key_len + dir_size));

    /* estimate leaf_block_percent */
    estimate_data_page += higher_level_page;
    for (; level > 0; level--) {
        higher_level_page = higher_level_page * ratio;
        estimate_data_page += higher_level_page;
    }

    double leaf_block_percent = (double)higher_level_page / estimate_data_page;
    uint64 total_data_block = (uint64)(idx_stats->avgdblk * (idx_stats->numlblks / idx_stats->avglblk));
    uint32 non_empty_leaves = (uint32)(total_data_block * leaf_block_percent);
    *empty_block = (non_empty_leaves > idx_stats->numlblks) ? (non_empty_leaves - idx_stats->numlblks) : 0;

    return CT_SUCCESS;
}

static status_t stats_calc_empty_block_part(knl_session_t *session, index_part_t *idx_part,
    knl_index_set_stats_t *idx_stats, uint32 *empty_block)
{
    if (stats_check_idx_stats_params(idx_stats) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("stats: fail to estimate empty block according to given parameters");
        return CT_ERROR;
    }

    page_id_t btree_entry = idx_part->desc.entry;
    knl_scn_t seg_scn = idx_part->desc.seg_scn;

    if (IS_INVALID_PAGID(btree_entry)) {
        CT_LOG_RUN_ERR("stats: invalid page id, part index: %s", idx_part->desc.name);
        return CT_ERROR;
    }

    buf_enter_page(session, btree_entry, LATCH_MODE_S, ENTER_PAGE_NORMAL);
    page_head_t *page = (page_head_t *)CURR_PAGE(session);
    btree_segment_t *segment = BTREE_GET_SEGMENT(session);

    if (page->type != PAGE_TYPE_BTREE_HEAD || segment->seg_scn != seg_scn) {
        buf_leave_page(session, CT_FALSE);
        CT_LOG_RUN_ERR("stats: current seg scn is different from origin seg scn, part index: %s", idx_part->desc.name);
        return CT_ERROR;
    }

    status_t ret = stats_calc_empty_leaves_part(session, idx_part, idx_stats, segment, empty_block);
    buf_leave_page(session, CT_FALSE);

    return ret;
}

status_t stats_update_sys_indexpart_force(knl_session_t *session, knl_dictionary_t *dc,
                                          knl_index_set_stats_t *idx_stats, index_part_t *idx_part)
{
    knl_scan_key_t *key = NULL;

    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_UPDATE, SYS_INDEXPART_ID, IX_SYS_INDEXPART001_ID);
    key = &cursor->scan_range.l_key;
    knl_init_index_scan(cursor, CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, CT_TYPE_INTEGER, &idx_part->desc.uid, sizeof(uint32),
                     IX_COL_SYS_INDEXPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, CT_TYPE_INTEGER, &idx_part->desc.table_id, sizeof(uint32),
                     IX_COL_SYS_INDEXPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, CT_TYPE_INTEGER, &idx_part->desc.index_id, sizeof(uint32),
                     IX_COL_SYS_INDEXPART001_INDEX_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), key, CT_TYPE_INTEGER, &idx_part->desc.part_id, sizeof(uint32),
                     IX_COL_SYS_INDEXPART001_PART_ID);
    
    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    if (cursor->eof) {
        CM_RESTORE_STACK(session->stack);
        CT_THROW_ERROR(ERR_INDEX_ALREADY_DROPPED, idx_part->desc.name);
        return CT_ERROR;
    }

    stats_verfiy_index_stats(cursor, idx_stats);

    uint32 empty_block = 0;
    if (stats_calc_empty_block_part(session, idx_part, idx_stats, &empty_block) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        CT_THROW_ERROR(ERR_INVALID_OPERATION, ", fail to estimate empty_block.");
        return CT_ERROR;
    }

    cursor->update_info.count = UPDATE_COLUMN_COUNT_ELEVEN;
    stats_update_sys_index_row(session, cursor, idx_stats, empty_block);

    if (knl_internal_update(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    CM_RESTORE_STACK(session->stack);

    return stats_set_analyze_time(session, dc, CT_TRUE);
}

status_t stats_set_tables(knl_session_t *session, knl_dictionary_t *dc, knl_table_set_stats_t *tab_stats,
                          table_part_t *table_part)
{
    stats_load_info_t load_info;
    dc_entity_t *entity = DC_ENTITY(dc);

    if (tab_stats->is_single_part) {
        if (stats_update_sys_tablepart_force(session, dc, table_part, tab_stats) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } else {
        if (stats_update_sys_table_force(session, dc, tab_stats) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
    stats_set_load_info(&load_info, entity, CT_TRUE, CT_INVALID_ID32);

    if (stats_refresh_dc(session, dc, load_info) != CT_SUCCESS) {
        return CT_ERROR;
    }
    
    cm_latch_x(&entity->cbo_latch, session->id, NULL);
    if (!entity->stat_exists) {
        cm_unlatch(&entity->cbo_latch, NULL);
        CT_THROW_ERROR(ERR_INVALID_DC, entity->entry->name);
        CT_LOG_RUN_ERR("[DC] could not load table statistics %s.%s.", entity->entry->user_name, entity->entry->name);
        return CT_ERROR;
    }

    entity->stats_locked = CT_TRUE;
    cm_unlatch(&entity->cbo_latch, NULL);
   
    return CT_SUCCESS;
}

static status_t stats_set_text_value(knl_session_t *session, dc_entity_t *entity,
    knl_column_t *column, text_t *src, text_t *dest)
{
    if (src->len == CT_NULL_VALUE_LEN) {
        return CT_SUCCESS;
    }

    if (SECUREC_UNLIKELY(src->str == NULL || src->len > STATS_MAX_BUCKET_SIZE)) {
        return CT_ERROR;
    }

    if (cbo_alloc_value_mem(session, entity->memory, column, &dest->str) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (cbo_get_stats_values(entity, column, src, dest) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t stats_set_cbo_column_value(knl_session_t *session, dc_entity_t *entity,
    knl_column_t *column, knl_column_set_stats_t *col_stats, cbo_stats_column_t *cbo_column)
{
    cbo_column->num_distinct = col_stats->distnum;
    cbo_column->density = col_stats->density;
    cbo_column->num_null = col_stats->nullnum;
    if (stats_set_text_value(session, entity, column, &col_stats->max_value,
        &cbo_column->high_value) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (stats_set_text_value(session, entity, column, &col_stats->min_value,
        &cbo_column->low_value) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t stats_set_column(knl_session_t *session, knl_dictionary_t *dc, knl_column_set_stats_t *col_stats,
                          table_part_t *table_part, knl_column_t *column)
{
    dc_entity_t *entity = DC_ENTITY(dc);
    cbo_stats_table_t *cbo_stats = entity->cbo_table_stats;
    cbo_stats_column_t *cbo_column = NULL;
    stats_load_info_t load_info;
    char max_buf[STATS_MAX_BUCKET_SIZE] = {0};
    char min_buf[STATS_MAX_BUCKET_SIZE] = {0};

    col_stats->max_value.str = (col_stats->max_value.len == CT_NULL_VALUE_LEN) ? max_buf : col_stats->max_value.str;
    col_stats->min_value.str = (col_stats->min_value.len == CT_NULL_VALUE_LEN) ? min_buf : col_stats->min_value.str;

    if (stats_update_sys_histhead_force(session, dc, col_stats, table_part, column) != CT_SUCCESS) {
        return CT_ERROR;
    }
    
    cm_latch_x(&entity->cbo_latch, session->id, NULL);

    if (!entity->stat_exists) {
        cm_unlatch(&entity->cbo_latch, NULL);
        CT_THROW_ERROR(ERR_INVALID_DC, entity->entry->name);
        CT_LOG_RUN_ERR("[DC] could not load table statistics %s.%s.", entity->entry->user_name, entity->entry->name);
        return CT_ERROR;
    }

    if (table_part != NULL) {
        cbo_stats_table_t *part_stats = CBO_GET_TABLE_PART(cbo_stats, table_part->part_no);
        if (part_stats == NULL) {
            cm_unlatch(&entity->cbo_latch, NULL);
            return CT_SUCCESS;
        }

        if (!part_stats->is_ready) {
            stats_set_load_info(&load_info, entity, CT_TRUE, CT_INVALID_ID32);
            if (cbo_load_table_part_stats(session, entity, table_part->part_no, load_info, CT_TRUE) != CT_SUCCESS) {
                cm_unlatch(&entity->cbo_latch, NULL);
                return CT_ERROR;
            }
        }
        cbo_column = cbo_get_column_stats(part_stats, column->id);
    } else {
        cbo_column = cbo_get_column_stats(cbo_stats, column->id);
    }

    if (cbo_column == NULL) {
        CT_LOG_RUN_WAR("Failed to modify %s.%s the %d column stats, it is not analyzed",
            entity->entry->user->desc.name, entity->table.desc.name, column->id);
        cm_unlatch(&entity->cbo_latch, NULL);
        return CT_SUCCESS;
    }

    if (stats_set_cbo_column_value(session, entity, column, col_stats, cbo_column) != CT_SUCCESS) {
        cm_unlatch(&entity->cbo_latch, NULL);
        return CT_ERROR;
    }

    entity->stats_locked = CT_TRUE;
    cm_unlatch(&entity->cbo_latch, NULL);
    return CT_SUCCESS;
}

status_t stats_set_index(knl_session_t *session, knl_dictionary_t *dc, knl_index_set_stats_t *idx_stats,
                         index_part_t *idx_part, index_t *index)
{
    dc_entity_t *entity = DC_ENTITY(dc);
    cbo_stats_index_t *cbo_idx_stats = NULL;
    cbo_stats_index_t *part_idx_stats = NULL;

    if (idx_stats->is_single_part) {
        if (stats_update_sys_indexpart_force(session, dc, idx_stats, idx_part) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } else {
        if (stats_update_sys_index_force(session, dc, idx_stats, index) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    cm_latch_x(&entity->cbo_latch, session->id, NULL);

    if (!entity->stat_exists) {
        cm_unlatch(&entity->cbo_latch, NULL);
        CT_THROW_ERROR(ERR_INVALID_DC, entity->entry->name);
        CT_LOG_RUN_ERR("[DC] could not load table statistics %s.%s.", entity->entry->user_name, entity->entry->name);
        return CT_ERROR;
    }

    if (idx_stats->is_single_part) {
        cbo_idx_stats = entity->cbo_table_stats->indexs[index->desc.slot];
        part_idx_stats = CBO_GET_INDEX_PART(cbo_idx_stats, idx_part->part_no);
        if (part_idx_stats == NULL) {
            cm_unlatch(&entity->cbo_latch, NULL);
            return CT_SUCCESS;
        }

        if (!part_idx_stats->is_ready) {
            if (cbo_load_index_part_stats(session, entity, idx_part->part_no, index->desc.id) != CT_SUCCESS) {
                cm_unlatch(&entity->cbo_latch, NULL);
                return CT_ERROR;
            }
        }
        part_idx_stats->blevel = idx_stats->indlevel;
        part_idx_stats->clustering_factor = idx_stats->clstfct;
        part_idx_stats->avg_data_key = idx_stats->avgdblk;
        part_idx_stats->avg_leaf_key = idx_stats->avglblk;
        part_idx_stats->distinct_keys = idx_stats->numdist;
        part_idx_stats->comb_cols_2_ndv = idx_stats->combndv2;
        part_idx_stats->comb_cols_3_ndv = idx_stats->combndv3;
        part_idx_stats->comb_cols_4_ndv = idx_stats->combndv4;
    } else {
        cbo_idx_stats = entity->cbo_table_stats->indexs[index->desc.slot];
        cbo_idx_stats->blevel = idx_stats->indlevel;
        cbo_idx_stats->clustering_factor = idx_stats->clstfct;
        cbo_idx_stats->avg_data_key = idx_stats->avgdblk;
        cbo_idx_stats->avg_leaf_key = idx_stats->avglblk;
        cbo_idx_stats->distinct_keys = idx_stats->numdist;
        cbo_idx_stats->comb_cols_2_ndv = idx_stats->combndv2;
        cbo_idx_stats->comb_cols_3_ndv = idx_stats->combndv3;
        cbo_idx_stats->comb_cols_4_ndv = idx_stats->combndv4;
    }

    entity->stats_locked = CT_TRUE;
    cm_unlatch(&entity->cbo_latch, NULL);
    return CT_SUCCESS;
}

void stats_flush_logic_log(knl_session_t *session, knl_dictionary_t *dc, stats_load_info_t *load_info)
{
    dc_entity_t *entity = DC_ENTITY(dc);
    rd_refresh_dc_t rd_ref;
    
    if (knl_begin_auton_rm(session) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Analyze %s.%s statistics write logic log failed ", entity->entry->user->desc.name,
                       entity->table.desc.name);
        return;
    }

    rd_ref.op_type = RD_REFRESH_DC;
    rd_ref.uid = dc->uid;
    rd_ref.oid = dc->oid;
    rd_ref.load_subpart = load_info->load_subpart;
    rd_ref.parent_part_id = load_info->parent_part_id;
    log_put(session, RD_LOGIC_OPERATION, &rd_ref, sizeof(rd_refresh_dc_t), LOG_ENTRY_FLAG_NONE);

    knl_end_auton_rm(session, CT_SUCCESS);
}

status_t stats_analyze_normal_table(knl_session_t *session, knl_dictionary_t *dc, stats_option_t stats_option,
                                    bool32 is_dynamic, bool32 *need_analyze)
{
     *need_analyze = CT_FALSE;

    if (stats_check_analyzing(session, dc, need_analyze, is_dynamic) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (!(*need_analyze)) {
        return CT_SUCCESS;
    }

    CM_SAVE_STACK(session->stack);
    if (stats_gather_normal_table(session, dc, stats_option, is_dynamic) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }
    CM_RESTORE_STACK(session->stack);

    return CT_SUCCESS;
}

status_t stats_analyze_single_table_part(knl_session_t *session, knl_dictionary_t *dc, knl_analyze_tab_def_t *def,
                                         stats_option_t stats_option, bool32 is_dynamic)
{
    def->need_analyzed = CT_FALSE;
    def->table_part = NULL;

    if (stats_find_part(session, def, dc, (table_part_t**)&def->table_part) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (stats_check_analyzing(session, dc, &def->need_analyzed, is_dynamic) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (!def->need_analyzed) {
        return CT_SUCCESS;
    }

    if (stats_gather_table_part(session, dc, stats_option, (table_part_t *)def->table_part, is_dynamic) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t stats_analyze_index(knl_session_t *session, knl_dictionary_t *dc, knl_analyze_index_def_t *def,
                             bool32 is_dynamic)
{
    def->need_analyzed = CT_FALSE;

    if (stats_check_analyzing(session, dc, &def->need_analyzed, is_dynamic) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (!def->need_analyzed) {
        return CT_SUCCESS;
    }

    if (stats_gather_index_by_btree(session, dc, def, is_dynamic) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}
