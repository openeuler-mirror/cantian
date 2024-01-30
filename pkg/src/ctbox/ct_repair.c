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
 * ct_repair.c
 *
 *
 * IDENTIFICATION
 * src/ctbox/ct_repair.c
 *
 * -------------------------------------------------------------------------
 */
#include "ct_tbox_module.h"
#include "ct_repair.h"
#include "ct_miner.h"
#include "ct_page.h"
#include "rcr_btree.h"
#include "knl_undo.h"
#include "knl_lob.h"
#include "temp_btree.h"
#include "ct_tbox_audit.h"
#include "dtc_database.h"

#ifdef WIN32
#define cm_strdup _strdup
#else
#define cm_strdup strdup
#endif

#define CREPAIR_INTERACTION_DEFAULT_TIMEOUT (uint32)10

status_t repair_check_file_exists(text_t *file);
status_t repair_set_ctrl_core_version(uint32 item_size, void *item_ptr, text_t *value);
status_t repair_set_ctrl_node_rcy(uint32 item_size, void *item_ptr, text_t *value);
status_t repair_set_ctrl_node_lrp(uint32 item_size, void *item_ptr, text_t *value);
status_t repair_set_ctrl_core_rfp(uint32 item_size, void *item_ptr, text_t *value);
status_t repair_set_ctrl_core_archive(uint32 item_size, void *item_ptr, text_t *value);
status_t repair_set_ctrl_core_resetlogs(uint32 item_size, void *item_ptr, text_t *value);

status_t repair_ctrlfile_func_uint8(uint32 item_size, void *item_ptr, text_t *value)
{
    uint16 val;
    if (cm_text2uint16(value, &val) != CT_SUCCESS) {
        printf("param value \'%s\' can not be converted to uint16 type.\n", value->str);
        return CT_ERROR;
    }
    *(uint8 *)item_ptr = (uint8)val;
    return CT_SUCCESS;
}

status_t repair_ctrlfile_func_uint16(uint32 item_size, void *item_ptr, text_t *value)
{
    uint16 val;
    if (cm_text2uint16(value, &val) != CT_SUCCESS) {
        printf("param value \'%s\' can not be converted to uint16 type.\n", value->str);
        return CT_ERROR;
    }
    *(uint16 *)item_ptr = val;
    return CT_SUCCESS;
}

status_t repair_ctrlfile_func_uint32(uint32 item_size, void *item_ptr, text_t *value)
{
    uint32 val;
    if (cm_text2uint32(value, &val) != CT_SUCCESS) {
        printf("param value \'%s\' can not be converted to uint32 type.\n", value->str);
        return CT_ERROR;
    }
    *(uint32 *)item_ptr = val;
    return CT_SUCCESS;
}

status_t repair_ctrlfile_func_int32(uint32 item_size, void *item_ptr, text_t *value)
{
    int32 val;
    if (cm_text2int(value, &val) != CT_SUCCESS) {
        printf("param value \'%s\' can not be converted to int32 type.\n", value->str);
        return CT_ERROR;
    }
    *(int32 *)item_ptr = val;
    return CT_SUCCESS;
}

status_t repair_ctrlfile_func_bool32(uint32 item_size, void *item_ptr, text_t *value)
{
    uint32 val;
    if (cm_text2uint32(value, &val) != CT_SUCCESS) {
        printf("param value \'%s\' can not be converted to uint32 type.\n", value->str);
        return CT_ERROR;
    }
    if (val != CT_FALSE && val != CT_TRUE) {
        printf("param value \'%s\' is invalid.\n", value->str);
        return CT_ERROR;
    }
    *(uint32 *)item_ptr = val;
    return CT_SUCCESS;
}

status_t repair_ctrlfile_func_int64(uint32 item_size, void *item_ptr, text_t *value)
{
    int64 val;
    if (cm_text2bigint(value, &val) != CT_SUCCESS) {
        printf("param value \'%s\' can not be converted to int64 type.\n", value->str);
        return CT_ERROR;
    }
    *(int64 *)item_ptr = val;
    return CT_SUCCESS;
}

status_t repair_ctrlfile_func_uint64(uint32 item_size, void *item_ptr, text_t *value)
{
    uint64 val;
    if (cm_text2uint64(value, &val) != CT_SUCCESS) {
        printf("param value \'%s\' can not be converted to uint64 type.\n", value->str);
        return CT_ERROR;
    }
    *(uint64 *)item_ptr = val;
    return CT_SUCCESS;
}

status_t repair_ctrlfile_func_page_id_t(uint32 item_size, void *item_ptr, text_t *value)
{
    page_id_t *page_id = (page_id_t *)item_ptr;
    text_t file_str;
    text_t page_str;
    uint16 uint16_value;
    uint32 uint32_value;

    cm_split_text(value, '-', '\0', &file_str, &page_str);
    cm_trim_text(&file_str);
    cm_trim_text(&page_str);

    if (cm_text2uint16(&file_str, &uint16_value) != CT_SUCCESS) {
        printf("param value \'%s\' is invalid.\n", value->str);
        return CT_ERROR;
    }
    page_id->file = uint16_value;

    if (cm_text2uint32(&page_str, &uint32_value) != CT_SUCCESS) {
        printf("param value \'%s\' is invalid.\n", value->str);
        return CT_ERROR;
    }
    page_id->page = uint32_value;

    return CT_SUCCESS;
}

status_t repair_ctrlfile_func_time_t(uint32 item_size, void *item_ptr, text_t *value)
{
    date_t date;
    text_t date_fmt1 = { "YYYY-MM-DD HH24:MI:SS", 21 };
    if (cm_text2date(value, &date_fmt1, &date) != CT_SUCCESS) {
        printf("param value \'%s\' is invalid.\n", value->str);
        return CT_ERROR;
    }
    *(time_t *)item_ptr = cm_date2time(date);
    return CT_SUCCESS;
}

status_t repair_set_ctrl_protect_mode(uint32 item_size, void *item_ptr, text_t *value)
{
    uint16 val;
    if (cm_text2uint16(value, &val) != CT_SUCCESS) {
        printf("param value \'%s\' can not be converted to uint16 type.\n", value->str);
        return CT_ERROR;
    }
    if (val < MAXIMUM_PERFORMANCE  || val > MAXIMUM_PROTECTION) {
        printf("param value \'%s\' is beyond the type range.\n", value->str);
        return CT_ERROR;
    }
    *(uint16 *)item_ptr = val;
    return CT_SUCCESS;
}

status_t repair_set_ctrl_lrep_mode(uint32 item_size, void *item_ptr, text_t *value)
{
    uint16 val;
    if (cm_text2uint16(value, &val) != CT_SUCCESS) {
        printf("param value \'%s\' can not be converted to uint16 type.\n", value->str);
        return CT_ERROR;
    }
    if (val != LOG_REPLICATION_OFF && val != LOG_REPLICATION_ON) {
        printf("param value \'%s\' is beyond the type range.\n", value->str);
        return CT_ERROR;
    }
    *(uint16 *)item_ptr = val;
    return CT_SUCCESS;
}

status_t repair_set_ctrl_db_role(uint32 item_size, void *item_ptr, text_t *value)
{
    uint16 val;
    if (cm_text2uint16(value, &val) != CT_SUCCESS) {
        printf("param value \'%s\' can not be converted to uint16 type.\n", value->str);
        return CT_ERROR;
    }
    if (val < REPL_ROLE_PRIMARY || val > REPL_ROLE_CASCADED_PHYSICAL_STANDBY) {
        printf("param value \'%s\' is beyond the type range.\n", value->str);
        return CT_ERROR;
    }
    *(uint16 *)item_ptr = val;
    return CT_SUCCESS;
}

status_t repair_set_ctrl_archive_mode(uint32 item_size, void *item_ptr, text_t *value)
{
    uint16 val;
    if (cm_text2uint16(value, &val) != CT_SUCCESS) {
        printf("param value \'%s\' can not be converted to uint16 type.\n", value->str);
        return CT_ERROR;
    }
    if (val != ARCHIVE_LOG_OFF && val != ARCHIVE_LOG_ON) {
        printf("param value \'%s\' is beyond the type range.\n", value->str);
        return CT_ERROR;
    }
    *(uint16 *)item_ptr = val;
    return CT_SUCCESS;
}

status_t repair_set_ctrl_device_type(uint32 item_size, void *item_ptr, text_t *value)
{
    uint16 val;
    if (cm_text2uint16(value, &val) != CT_SUCCESS) {
        printf("param value \'%s\' can not be converted to uint16 type.\n", value->str);
        return CT_ERROR;
    }
    if (val > DEV_TYPE_CFS || val < DEV_TYPE_FILE) {
        printf("param value \'%s\' is beyond the type range.\n", value->str);
        return CT_ERROR;
    }
    *(uint16 *)item_ptr = val;
    return CT_SUCCESS;
}

status_t repair_set_ctrl_logfile_status(uint32 item_size, void *item_ptr, text_t *value)
{
    uint16 val;
    if (cm_text2uint16(value, &val) != CT_SUCCESS) {
        printf("param value \'%s\' can not be converted to uint16 type.\n", value->str);
        return CT_ERROR;
    }
    if (val >= LOG_FILE_UNUSED  || val < LOG_FILE_INACTIVE) {
        printf("param value \'%s\' is beyond the type range.\n", value->str);
        return CT_ERROR;
    }
    *(uint16 *)item_ptr = val;
    return CT_SUCCESS;
}

status_t repair_set_ctrl_core_charset(uint32 item_size, void *item_ptr, text_t *value)
{
    uint16 val;
    if (cm_text2uint16(value, &val) != CT_SUCCESS) {
        printf("param value \'%s\' can not be converted to uint16 type.\n", value->str);
        return CT_ERROR;
    }
    if (val > 1) {
        printf("param value \'%s\' is beyond the type range.\n", value->str);
        return CT_ERROR;
    }
    *(uint16 *)item_ptr = val;
    return CT_SUCCESS;
}

status_t repair_set_ctrl_common_str(uint32 item_size, void *item_ptr, text_t *value)
{
    errno_t ret;
    char *str = (char *)item_ptr;
    if (value->len > item_size) {
        printf("param value \'%s\' is too long.\n", value->str);
        return CT_ERROR;
    }

    ret = memcpy_sp(str, item_size, value->str, value->len);
    knl_securec_check(ret);
    if (value->len < item_size) {
        str[value->len] = '\0';
    }
    return CT_SUCCESS;
}

status_t repair_set_ctrl_common_file(uint32 item_size, void *item_ptr, text_t *value)
{
    errno_t ret;
    char *str = (char *)item_ptr;
    if (value->len > item_size) {
        printf("param value \'%s\' is too long.\n", value->str);
        return CT_ERROR;
    }

    // check
    if (repair_check_file_exists(value) != CT_SUCCESS) {
        return CT_ERROR;
    }

    ret = memcpy_sp(str, item_size, value->str, value->len);
    knl_securec_check(ret);
    if (value->len < item_size) {
        str[value->len] = '\0';
    }
    return CT_SUCCESS;
}

typedef status_t (*repair_ctrlfile_func_t)(uint32 item_size, void *item_ptr, text_t *value);

typedef struct st_repair_ctrlfile_items {
    const char *name;
    uint32 item_size;
    uint32 item_offset;
    repair_ctrlfile_func_t repair_func;
} repair_ctrlfile_items_t;

#define REPAIR_CTRL_ITEM(name, obj, item, type)  \
    { (name), (uint32)(sizeof(type)), (uint32)(OFFSET_OF(obj, item)), repair_ctrlfile_func_##type}

#define REPAIR_CTRL_ITEM_WITH_FUNC(name, obj, item, type, func)  \
    { (name), (uint32)(sizeof(type)), (uint32)(OFFSET_OF(obj, item)), (func)}

#define REPAIR_CTRL_ITEM_WITH_LEN_FUNC(name, obj, item, len, func)  \
    { (name), (uint32)(len), (uint32)(OFFSET_OF(obj, item)), (func)}

#define ARCHIVE_LOGS_LEN (sizeof(arch_log_id_t) * CT_MAX_ARCH_DEST)

#define REPAIR_CTRLFILE_CORE_ITEM_COUNT \
    (sizeof(g_repair_ctrlfile_core_items_list) / sizeof(repair_ctrlfile_items_t))
repair_ctrlfile_items_t g_repair_ctrlfile_core_items_list[] = {
    REPAIR_CTRL_ITEM_WITH_FUNC("version", core_ctrl_t, version, ctrl_version_t, repair_set_ctrl_core_version),
    REPAIR_CTRL_ITEM("startup_times", core_ctrl_t, open_count, uint32),
    REPAIR_CTRL_ITEM("dbid_times", core_ctrl_t, dbid, uint32),
    REPAIR_CTRL_ITEM_WITH_LEN_FUNC("database_name", core_ctrl_t, name, CT_DB_NAME_LEN, repair_set_ctrl_common_str),
    REPAIR_CTRL_ITEM("init_time", core_ctrl_t, init_time, time_t),

    REPAIR_CTRL_ITEM("table$_entry", core_ctrl_t, sys_table_entry, page_id_t),
    REPAIR_CTRL_ITEM("ix_table$1_entry", core_ctrl_t, ix_sys_table1_entry, page_id_t),
    REPAIR_CTRL_ITEM("ix_table$2_entry", core_ctrl_t, ix_sys_table2_entry, page_id_t),
    REPAIR_CTRL_ITEM("column$_entry", core_ctrl_t, sys_column_entry, page_id_t),
    REPAIR_CTRL_ITEM("ix_column$_entry", core_ctrl_t, ix_sys_column_entry, page_id_t),
    REPAIR_CTRL_ITEM("index$_entry", core_ctrl_t, sys_index_entry, page_id_t),
    REPAIR_CTRL_ITEM("ix_index$1_entry", core_ctrl_t, ix_sys_index1_entry, page_id_t),
    REPAIR_CTRL_ITEM("ix_index$2_entry", core_ctrl_t, ix_sys_index2_entry, page_id_t),
    REPAIR_CTRL_ITEM("user$_entry", core_ctrl_t, sys_index_entry, page_id_t),
    REPAIR_CTRL_ITEM("ix_user$1_entry", core_ctrl_t, ix_sys_user1_entry, page_id_t),
    REPAIR_CTRL_ITEM("ix_user$2_entry", core_ctrl_t, ix_sys_user2_entry, page_id_t),

    REPAIR_CTRL_ITEM("build_completed", core_ctrl_t, build_completed, bool32),
    REPAIR_CTRL_ITEM_WITH_FUNC("archive_mode", core_ctrl_t, log_mode, archive_mode_t, repair_set_ctrl_archive_mode),
    REPAIR_CTRL_ITEM_WITH_LEN_FUNC("archive_logs", core_ctrl_t, archived_log, ARCHIVE_LOGS_LEN, repair_set_ctrl_core_archive),
    REPAIR_CTRL_ITEM_WITH_FUNC("db_role", core_ctrl_t, db_role, repl_role_t, repair_set_ctrl_db_role),
    REPAIR_CTRL_ITEM_WITH_FUNC("protect_mode", core_ctrl_t, protect_mode, repl_mode_t, repair_set_ctrl_protect_mode),

    REPAIR_CTRL_ITEM("space_count", core_ctrl_t, space_count, uint32),
    REPAIR_CTRL_ITEM("device_count", core_ctrl_t, device_count, uint32),
    REPAIR_CTRL_ITEM("page_size", core_ctrl_t, page_size, uint32),
    REPAIR_CTRL_ITEM("undo_segments", core_ctrl_t, undo_segments, uint32),
    REPAIR_CTRL_ITEM_WITH_FUNC("reset_logs", core_ctrl_t, resetlogs, reset_log_t, repair_set_ctrl_core_resetlogs),
    REPAIR_CTRL_ITEM_WITH_FUNC("lrep_mode", core_ctrl_t, lrep_mode, lrep_mode_t, repair_set_ctrl_lrep_mode),
        
    REPAIR_CTRL_ITEM("max_column_count", core_ctrl_t, max_column_count, uint32),
    REPAIR_CTRL_ITEM("open_inconsistency", core_ctrl_t, open_inconsistency, bool32),

    REPAIR_CTRL_ITEM_WITH_FUNC("charset_id", core_ctrl_t, charset_id, uint32, repair_set_ctrl_core_charset),
    REPAIR_CTRL_ITEM("dw_file_id", core_ctrl_t, dw_file_id, uint32),
    REPAIR_CTRL_ITEM("dw_area_pages", core_ctrl_t, dw_area_pages, uint32),
    REPAIR_CTRL_ITEM("system_space", core_ctrl_t, system_space, uint32),
    REPAIR_CTRL_ITEM("sysaux_space", core_ctrl_t, sysaux_space, uint32),
    REPAIR_CTRL_ITEM("user_space", core_ctrl_t, user_space, uint32),
    REPAIR_CTRL_ITEM("temp_undo_space", core_ctrl_t, temp_undo_space, uint32),
    REPAIR_CTRL_ITEM("temp_space", core_ctrl_t, temp_space, uint32),
    REPAIR_CTRL_ITEM("undo_segments_extended", core_ctrl_t, undo_segments_extended, bool32),
    REPAIR_CTRL_ITEM("clustered", core_ctrl_t, clustered, bool32),
    REPAIR_CTRL_ITEM("node_count", core_ctrl_t, node_count, uint32),
    REPAIR_CTRL_ITEM("max_nodes", core_ctrl_t, max_nodes, uint32),
};

#define REPAIR_CTRLFILE_STORAGE_LOGFILE_ITEM_COUNT \
    (sizeof(g_repair_ctrlfile_storage_logfile_items_list) / sizeof(repair_ctrlfile_items_t))
repair_ctrlfile_items_t g_repair_ctrlfile_storage_logfile_items_list[] = {
    REPAIR_CTRL_ITEM_WITH_LEN_FUNC("name", log_file_ctrl_t, name, CT_FILE_NAME_BUFFER_SIZE, repair_set_ctrl_common_file),
    REPAIR_CTRL_ITEM("size", log_file_ctrl_t, size, int64),
    REPAIR_CTRL_ITEM("hwm", log_file_ctrl_t, hwm, int64),
    REPAIR_CTRL_ITEM("seq", log_file_ctrl_t, seq, uint32),
    REPAIR_CTRL_ITEM("block_size", log_file_ctrl_t, block_size, uint16),
    REPAIR_CTRL_ITEM("flg", log_file_ctrl_t, flg, uint16),
    REPAIR_CTRL_ITEM_WITH_FUNC("type", log_file_ctrl_t, type, device_type_t, repair_set_ctrl_device_type),
    REPAIR_CTRL_ITEM_WITH_FUNC("status", log_file_ctrl_t, status, logfile_status_t, repair_set_ctrl_logfile_status),
    REPAIR_CTRL_ITEM("forward", log_file_ctrl_t, forward, uint16),
    REPAIR_CTRL_ITEM("backward", log_file_ctrl_t, backward, uint16),
};

#define REPAIR_CTRLFILE_STORAGE_SPACE_ITEM_COUNT \
    (sizeof(g_repair_ctrlfile_storage_space_items_list) / sizeof(repair_ctrlfile_items_t))
repair_ctrlfile_items_t g_repair_ctrlfile_storage_space_items_list[] = {
    REPAIR_CTRL_ITEM("spaceid", space_ctrl_t, id, uint32),
    REPAIR_CTRL_ITEM("used", space_ctrl_t, used, bool32),
    REPAIR_CTRL_ITEM_WITH_LEN_FUNC("name", space_ctrl_t, name, CT_NAME_BUFFER_SIZE, repair_set_ctrl_common_str),
    REPAIR_CTRL_ITEM("flag", space_ctrl_t, flag, uint16),
    REPAIR_CTRL_ITEM("block_size", space_ctrl_t, block_size, uint16),
    REPAIR_CTRL_ITEM("extent_size", space_ctrl_t, extent_size, uint32),
    REPAIR_CTRL_ITEM("file_hwm", space_ctrl_t, file_hwm, uint32),
    REPAIR_CTRL_ITEM("type", space_ctrl_t, type, uint32),
    REPAIR_CTRL_ITEM("org_scn", space_ctrl_t, org_scn, uint32),
    REPAIR_CTRL_ITEM("encrypt_version", space_ctrl_t, encrypt_version, uint8),
    REPAIR_CTRL_ITEM("cipher_reserve_size", space_ctrl_t, cipher_reserve_size, uint8),
};

#define REPAIR_CTRLFILE_STORAGE_DATAFILES_ITEM_COUNT \
    (sizeof(g_repair_ctrlfile_storage_datafiles_items_list) / sizeof(repair_ctrlfile_items_t))
repair_ctrlfile_items_t g_repair_ctrlfile_storage_datafiles_items_list[] = {
    REPAIR_CTRL_ITEM("dfileid", datafile_ctrl_t, id, uint32),
    REPAIR_CTRL_ITEM("used", datafile_ctrl_t, used, bool32),
    REPAIR_CTRL_ITEM_WITH_LEN_FUNC("name", datafile_ctrl_t, name, CT_FILE_NAME_BUFFER_SIZE, repair_set_ctrl_common_file),
    REPAIR_CTRL_ITEM("size", datafile_ctrl_t, size, int64),
    REPAIR_CTRL_ITEM("block_size", datafile_ctrl_t, block_size, uint16),
    REPAIR_CTRL_ITEM("flag", datafile_ctrl_t, flag, uint16),
    REPAIR_CTRL_ITEM_WITH_FUNC("type", datafile_ctrl_t, type, device_type_t, repair_set_ctrl_device_type),
    REPAIR_CTRL_ITEM("auto_extend_size", datafile_ctrl_t, auto_extend_size, int64),
    REPAIR_CTRL_ITEM("auto_extend_maxsize", datafile_ctrl_t, auto_extend_maxsize, int64),
};

#define REPAIR_CTRLFILE_STORAGE_ARCHIVE_ITEM_COUNT \
    (sizeof(g_repair_ctrlfile_storage_archive_items_list) / sizeof(repair_ctrlfile_items_t))
repair_ctrlfile_items_t g_repair_ctrlfile_storage_archive_items_list[] = {
    REPAIR_CTRL_ITEM("recid", arch_ctrl_t, recid, uint32),
    REPAIR_CTRL_ITEM("dest_id", arch_ctrl_t, dest_id, uint32),
    REPAIR_CTRL_ITEM("rst_id", arch_ctrl_t, rst_id, uint32),
    REPAIR_CTRL_ITEM("asn", arch_ctrl_t, asn, uint32),
    REPAIR_CTRL_ITEM("stamp", arch_ctrl_t, stamp, int64),
    REPAIR_CTRL_ITEM("blocks", arch_ctrl_t, blocks, int32),
    REPAIR_CTRL_ITEM("block_size", arch_ctrl_t, block_size, int32),
    REPAIR_CTRL_ITEM("start_lsn", arch_ctrl_t, start_lsn, uint64),
    REPAIR_CTRL_ITEM("end_lsn", arch_ctrl_t, end_lsn, uint64),
    REPAIR_CTRL_ITEM("first", arch_ctrl_t, first, uint64),
    REPAIR_CTRL_ITEM("last", arch_ctrl_t, last, uint64),
    REPAIR_CTRL_ITEM_WITH_LEN_FUNC("name", arch_ctrl_t, name, CT_FILE_NAME_BUFFER_SIZE, repair_set_ctrl_common_file),
};

#define REPAIR_CTRLFILE_STORAGE_NODE_ITEM_COUNT \
    (sizeof(g_repair_ctrlfile_storage_node_items_list) / sizeof(repair_ctrlfile_items_t))
repair_ctrlfile_items_t g_repair_ctrlfile_storage_node_items_list[] = {
    REPAIR_CTRL_ITEM("scn", dtc_node_ctrl_t, scn, int64),
    REPAIR_CTRL_ITEM_WITH_FUNC("rcy_point", dtc_node_ctrl_t, rcy_point, log_point_t, repair_set_ctrl_node_rcy),
    REPAIR_CTRL_ITEM_WITH_FUNC("lrp_point", dtc_node_ctrl_t, lrp_point, log_point_t, repair_set_ctrl_node_lrp),
    REPAIR_CTRL_ITEM("ckpt_id", dtc_node_ctrl_t, ckpt_id, uint64),
    REPAIR_CTRL_ITEM("dw_start", dtc_node_ctrl_t, dw_start, uint32),
    REPAIR_CTRL_ITEM("dw_end", dtc_node_ctrl_t, dw_end, uint32),
    REPAIR_CTRL_ITEM("lsn", dtc_node_ctrl_t, lsn, int64),
    REPAIR_CTRL_ITEM("lfn", dtc_node_ctrl_t, lfn, int64),
    REPAIR_CTRL_ITEM("log_count", dtc_node_ctrl_t, log_count, uint32),
    REPAIR_CTRL_ITEM("log_hwm", dtc_node_ctrl_t, log_hwm, uint32),
    REPAIR_CTRL_ITEM("log_first", dtc_node_ctrl_t, log_first, uint32),
    REPAIR_CTRL_ITEM("log_last", dtc_node_ctrl_t, log_last, uint32),
    REPAIR_CTRL_ITEM("archived_start", dtc_node_ctrl_t, archived_start, uint32),
    REPAIR_CTRL_ITEM("archived_end", dtc_node_ctrl_t, archived_end, uint32),
    REPAIR_CTRL_ITEM("shutdown_consistency", dtc_node_ctrl_t, shutdown_consistency, bool32),
    REPAIR_CTRL_ITEM("open_inconsistency", dtc_node_ctrl_t, open_inconsistency, bool32),
    REPAIR_CTRL_ITEM("consistent_lfn", dtc_node_ctrl_t, consistent_lfn, uint64),
    REPAIR_CTRL_ITEM("swap_space", dtc_node_ctrl_t, swap_space, uint32),
    REPAIR_CTRL_ITEM("undo_space", dtc_node_ctrl_t, undo_space, uint32),
    REPAIR_CTRL_ITEM("last_asn", dtc_node_ctrl_t, last_asn, uint32),
    REPAIR_CTRL_ITEM("last_lfn", dtc_node_ctrl_t, last_lfn, uint32),
};

static void usage(void)
{
    printf("crepair is an repair tool for cantian.\n"
           "\n"
           "Usage:\n"
           "  crepair [OPTIONS]\n"
           "\nRequired options:\n"
           "  -f DATAFILE  the database datafile to repair\n");

    printf("\nOptional options:\n"
           "  -s set the first page to repair(default, 0)\n"
           "  -n set the page number to repair(default, 1)\n"
           "  -p set page size of datafile to parse(default, 8192)\n"
           "  -H set the page head data to repair page\n"
           "  -c set the page ctrl data to repair page\n"
           "  -k set the ctrlfile to be repaired\n"
           "  -C calculate the checksum value again\n"
           "  -t set the page tail data to repair page\n"
           "  -F force repair datafile when the version is inconsistent\n"
           "\nCommon options:\n"
           "  --help, -h       show this help, then exit\n"
           "  --version, -V    output version information, then exit\n");
}

static inline void repair_init_input_common(repair_input_common_t* input_common)
{
    input_common->page_size = MINER_DEF_PAGE_SIZE;
    input_common->start = CT_INVALID_ID64;
    input_common->count = CT_INVALID_ID32;
    input_common->log_path = NULL;
}

static inline void repair_free_input_common(repair_input_common_t* input_common)
{
    CM_FREE_PTR(input_common->log_path);
}

static void repair_init_page_input(repair_page_def_t *page_input)
{
    page_input->datafile = NULL;
    page_input->ctrlfile = NULL;

    page_input->head_input.input_str = NULL;
    page_input->head_input.file_handle = CT_INVALID_INT32;
    page_input->head_input.is_file = CT_FALSE;

    page_input->tail_input.input_str = NULL;
    page_input->tail_input.file_handle = CT_INVALID_INT32;
    page_input->tail_input.is_file = CT_FALSE;

    page_input->ctrl_input.input_str = NULL;
    page_input->ctrl_input.file_handle = CT_INVALID_INT32;
    page_input->ctrl_input.is_file = CT_FALSE;

    page_input->is_force = CT_FALSE;
    page_input->is_checksum = CT_FALSE;

    page_input->log_path[0] = '\0';
}

static void repair_free_page_input(repair_page_def_t *page_input)
{
    CM_FREE_PTR(page_input->datafile);
    CM_FREE_PTR(page_input->ctrlfile);
    CM_FREE_PTR(page_input->ctrl_input.input_str);
    CM_FREE_PTR(page_input->head_input.input_str);
    CM_FREE_PTR(page_input->tail_input.input_str);
}

static void repair_warning_timeout(uint32 timeout)
{
#ifdef WIN32
    return;
#else
    char confirm[CT_MAX_CMD_LEN] = { 0 };
    char *env_quiet = getenv("CTBOX_CONFIRM_QUIET");
    bool32 quiet_flag = CT_FALSE;

    if (env_quiet != NULL && cm_str2bool(env_quiet, &quiet_flag) == CT_SUCCESS) {
        if (quiet_flag) {
            return;
        }
    }

    while (CT_TRUE) {
        printf("Warning: modifying datafile may cause unexpected results(unable to start DB, data lost, etc), must be sure the page size you input correctly. Continue anyway? (y/n):");
        (void)fflush(stdout);

        timeval_t tv_begin, tv_end;
        (void)cm_gettimeofday(&tv_begin);

        while (NULL == cm_fgets_nonblock(confirm, sizeof(confirm), stdin)) {
            (void)cm_gettimeofday(&tv_end);
            if (tv_end.tv_sec - tv_begin.tv_sec > (long)timeout) {
                printf("\nConfirm crepair operation timeout.\r\n");
                exit(EXIT_FAILURE);
            }
        }

        if (0 == cm_strcmpni(confirm, "y\n", sizeof("y\n")) ||
            0 == cm_strcmpni(confirm, "yes\n", sizeof("yes\n"))) {
            break;
        } else if (0 == cm_strcmpni(confirm, "n\n", sizeof("n\n")) ||
                   0 == cm_strcmpni(confirm, "no\n", sizeof("no\n"))) {
            exit(EXIT_FAILURE);
        } else {
            printf("\n");
        }
    }

#endif
}

static inline status_t repair_check_file_version(repair_page_def_t *page_input)
{
    // current, only support datafile / ctrlfile(no logfile)
    if (page_input->datafile != NULL) {
        return miner_verify_datafile_version(page_input->datafile,
            (uint32)(CORE_CTRL_PAGE_ID + 1) * CT_DFLT_CTRL_BLOCK_SIZE);
    } else {
        // ctrlfile will be verified later
        return CT_SUCCESS;
    }
}

status_t repair_verify_input(repair_page_def_t *page_input, const char *input_path, int argc, char *argv[])
{
    if (g_gm_optind < argc) {
        printf("try use \"--help\" for more information.\n");
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, argv[g_gm_optind]);
        return CT_ERROR;
    }

    if ((page_input->datafile == NULL && page_input->ctrlfile == NULL) || (page_input->head_input.input_str == NULL &&
        page_input->ctrl_input.input_str == NULL && page_input->tail_input.input_str == NULL)) {
        printf("must have datafile/ctrlfile and repair data input. try use \"--help\" for more information.\n");
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "input");
        return CT_ERROR;
    }

    if (page_input->datafile != NULL && page_input->ctrlfile != NULL) {
        printf("must have only one datafile/ctrlfile. try use \"--help\" for more information.\n");
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "input");
        return CT_ERROR;
    }

    if (tbox_verify_log_path(input_path, page_input) == CT_ERROR) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "log path");
        return CT_ERROR;
    }

    if (page_input->is_force == CT_FALSE) {
        if (repair_check_file_version(page_input)) {
            return CT_ERROR;
        }
    }

    return tbox_init_audit_log(page_input->log_path);
}

static status_t inline repair_opt_proc_of_f(repair_page_def_t *page_input)
{
    if (page_input->datafile != NULL || g_gm_optarg == NULL) {
        printf("must specify a data file to repair\n");
        return CT_ERROR;
    }
    page_input->datafile = (char *)cm_strdup(g_gm_optarg);
    if (page_input->datafile == NULL) {
        printf("datafile strdup failed.\n");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t inline repair_opt_proc_of_k(repair_page_def_t *page_input)
{
    if (page_input->ctrlfile != NULL || g_gm_optarg == NULL) {
        printf("must specify a data file to repair\n");
        return CT_ERROR;
    }
    page_input->ctrlfile = (char *)cm_strdup(g_gm_optarg);
    if (page_input->ctrlfile == NULL) {
        printf("ctrlfile strdup failed.\n");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t inline repair_opt_proc_of_H(repair_page_def_t *page_input)
{
    if (page_input->head_input.input_str != NULL || g_gm_optarg == NULL) {
        printf("must specify a page head data to repair\n");
        return CT_ERROR;
    }
    page_input->head_input.input_str = (char *)cm_strdup(g_gm_optarg);
    if (page_input->head_input.input_str == NULL) {
        printf("head_input strdup failed.\n");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t inline repair_opt_proc_of_c(repair_page_def_t *page_input)
{
    if (page_input->ctrl_input.input_str != NULL || g_gm_optarg == NULL) {
        printf("must specify a page ctrl data to repair\n");
        return CT_ERROR;
    }
    page_input->ctrl_input.input_str = (char *)cm_strdup(g_gm_optarg);
    if (page_input->ctrl_input.input_str == NULL) {
        printf("ctrl_input strdup failed.\n");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t inline repair_opt_proc_of_t(repair_page_def_t *page_input)
{
    if (page_input->tail_input.input_str != NULL || g_gm_optarg == NULL) {
        printf("must specify a page tail data to repair\n");
        return CT_ERROR;
    }
    page_input->tail_input.input_str = (char *)cm_strdup(g_gm_optarg);
    if (page_input->tail_input.input_str == NULL) {
        printf("tail_input strdup failed.\n");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t repair_opt_proc_of_L(repair_input_common_t *input_common)
{
    if (input_common->log_path != NULL || g_gm_optarg == NULL) {
        printf("must secify a log path if you set -L\n");
        return CT_ERROR;
    }
    input_common->log_path = (char *)cm_strdup(g_gm_optarg);
    if (input_common->log_path == NULL) {
        printf("log_path strdup failed.\n");
        return CT_ERROR;
    }
    if (access(input_common->log_path, R_OK) || access(input_common->log_path, W_OK) ||
        access(input_common->log_path, X_OK)) {
        printf("access %s error: Permission denied.\n", input_common->log_path);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t repair_init_parameters(int argc, char *argv[], repair_page_def_t *page_input,
    repair_input_common_t *input_common)
{
    status_t status = CT_SUCCESS;
    int32 c;
    c = miner_getopt(argc, argv, "Ff:s:n:p:H:Cc:t:L:k:");
    while (c != -1) {
        switch (c) {
            case 'f':
                status = repair_opt_proc_of_f(page_input);
                break;

            case 'k':
                status = repair_opt_proc_of_k(page_input);
                break;

            case 'C':
                page_input->is_checksum = CT_TRUE;
                break;
 
            case 'n':
                input_common->count = (uint32)atoi(g_gm_optarg);
                break;
 
            case 'p':
                input_common->page_size = (uint32)atoi(g_gm_optarg);
                break;
 
            case 's':
                input_common->start = (uint64)atoi(g_gm_optarg);
                break;
 
            case 'H':
                status = repair_opt_proc_of_H(page_input);
                break;
 
            case 'c':
                status = repair_opt_proc_of_c(page_input);
                break;
 
            case 't':
                status = repair_opt_proc_of_t(page_input);
                break;
            case 'L':
                status = repair_opt_proc_of_L(input_common);
                break;
            case 'F':
                page_input->is_force = CT_TRUE;
                break;
            default:
                printf("try use \"--help\" for more information.\n");
                return CT_ERROR;
        }
        c = miner_getopt(argc, argv, "Ff:s:n:p:H:Cc:t:L:k:");
    }

    return status;
}

char *repair_text_alloc_str(text_t *value)
{
    errno_t ret;

    char *filepath = (char *)malloc(value->len + 1);
    if (filepath == NULL) {
        printf("malloc memory %u failed.\n", value->len + 1);
        return NULL;
    }
    ret = memcpy_sp(filepath, value->len, value->str, value->len);
    if (ret != EOK) {
        CM_FREE_PTR(filepath);
        return NULL;
    }

    filepath[value->len] = '\0';
    return filepath;
}

status_t repair_check_file_exists(text_t *file)
{
    char *filepath = repair_text_alloc_str(file);
    if (filepath == NULL) {
        return CT_ERROR;
    }

    if (!cm_file_exist(filepath)) {
        printf("file \'%s\' is not exists.\n", filepath);
        CM_FREE_PTR(filepath);
        return CT_ERROR;
    }
    
    CM_FREE_PTR(filepath);
    return CT_SUCCESS;
}

status_t repair_set_ctrl_logfiles(database_ctrl_t *ctrl, text_t *part, uint32 node_id, uint32 part_idx, text_t *value)
{
    uint32 i = 0;
    log_file_ctrl_t *logfile = NULL;
    logfile = (log_file_ctrl_t *)db_get_log_ctrl_item(ctrl->pages, part_idx, sizeof(log_file_ctrl_t), ctrl->log_segment,
        node_id);

    for (; i < REPAIR_CTRLFILE_STORAGE_LOGFILE_ITEM_COUNT; i++) {
        repair_ctrlfile_items_t *item = &g_repair_ctrlfile_storage_logfile_items_list[i];
        if (cm_text_str_equal(part, item->name)) {
            return item->repair_func(item->item_size, (void *)(((char *)logfile) + item->item_offset), value);
        }
    }

    printf("param value \'%s\' is not supported.\n", part->str);
    return CT_ERROR;
}

status_t repair_set_ctrl_spaces(database_ctrl_t *ctrl, text_t *part, uint32 part_idx, text_t *value)
{
    uint32 i = 0;
    space_ctrl_t *space = NULL;
    space = (space_ctrl_t *)db_get_ctrl_item(ctrl->pages, part_idx, sizeof(space_ctrl_t), ctrl->space_segment);

    for (; i < REPAIR_CTRLFILE_STORAGE_SPACE_ITEM_COUNT; i++) {
        repair_ctrlfile_items_t *item = &g_repair_ctrlfile_storage_space_items_list[i];
        if (cm_text_str_equal(part, item->name)) {
            return item->repair_func(item->item_size, (void *)(((char *)space) + item->item_offset), value);
        }
    }

    printf("param value \'%s\' is not supported.\n", part->str);
    return CT_ERROR;
}

status_t repair_set_ctrl_datafiles(database_ctrl_t *ctrl, text_t *part, uint32 part_idx, text_t *value)
{
    uint32 i = 0;
    datafile_ctrl_t *datafile = NULL;
    datafile = (datafile_ctrl_t *)db_get_ctrl_item(ctrl->pages, part_idx, sizeof(datafile_ctrl_t), ctrl->datafile_segment);

    for (; i < REPAIR_CTRLFILE_STORAGE_DATAFILES_ITEM_COUNT; i++) {
        repair_ctrlfile_items_t *item = &g_repair_ctrlfile_storage_datafiles_items_list[i];
        if (cm_text_str_equal(part, item->name)) {
            return item->repair_func(item->item_size, (void *)(((char *)datafile) + item->item_offset), value);
        }
    }

    printf("param value \'%s\' is not supported.\n", part->str);
    return CT_ERROR;
}

status_t repair_set_ctrl_archive(database_ctrl_t *ctrl, text_t *part, uint32 node_id, uint32 part_idx, text_t *value)
{
    uint32 i = 0;
    arch_ctrl_t *arch_ctrl = NULL;
    arch_ctrl =
        (arch_ctrl_t *)db_get_log_ctrl_item(ctrl->pages, part_idx, sizeof(arch_ctrl_t), ctrl->arch_segment, node_id);

    for (; i < REPAIR_CTRLFILE_STORAGE_ARCHIVE_ITEM_COUNT; i++) {
        repair_ctrlfile_items_t *item = &g_repair_ctrlfile_storage_archive_items_list[i];
        if (cm_text_str_equal(part, item->name)) {
            return item->repair_func(item->item_size, (void *)(((char *)arch_ctrl) + item->item_offset), value);
        }
    }

    printf("param value \'%s\' is not supported.\n", part->str);
    return CT_ERROR;
}

status_t repair_set_ctrl_node(database_ctrl_t *ctrl, text_t *part, uint32 node_id, text_t *value)
{
    uint32 i = 0;
    dtc_node_ctrl_t *node_ctrl = (dtc_node_ctrl_t *)ctrl->pages[CTRL_LOG_SEGMENT + node_id].buf;

    for (; i < REPAIR_CTRLFILE_STORAGE_NODE_ITEM_COUNT; i++) {
        repair_ctrlfile_items_t *item = &g_repair_ctrlfile_storage_node_items_list[i];
        if (cm_text_str_equal(part, item->name)) {
            return item->repair_func(item->item_size, (void *)(((char *)node_ctrl) + item->item_offset), value);
        }
    }

    printf("param value \'%s\' is not supported.\n", part->str);
    return CT_ERROR;
}

status_t repair_set_ctrl_cluster_files(database_ctrl_t *ctrl, text_t *part, uint32 node_id, text_t *value)
{
    text_t part1, part2;
    uint32 part_idx = CT_INVALID_ID32;
    if (node_id >= ctrl->core.node_count) {
        printf("the node index(%u) is beyond the range(%u).\n", node_id, ctrl->core.node_count);
        return CT_ERROR;
    }
    cm_split_text(part, '.', '\0', &part1, &part2);
    if (repair_get_item_index(&part1, &part_idx) != CT_SUCCESS) {
        printf("param value \'%s\' is invalid.\n", part->str);
        return CT_ERROR;
    }
    if (part_idx == CT_INVALID_ID32) {
        printf("param value \'%s\' is invalid.\n", part->str);
        return CT_ERROR;
    }
    cm_trim_text(&part1);
    cm_trim_text(&part2);
    if (cm_text_str_equal(&part1, "archive")) {
        if (part_idx >= CT_MAX_ARCH_NUM) {
            printf("the archive index(%u) is beyond the range(%u).\n", part_idx, CT_MAX_ARCH_NUM);
            return CT_ERROR;
        }
        return repair_set_ctrl_archive(ctrl, &part2, node_id, part_idx, value);
    } else if (cm_text_str_equal(&part1, "logfiles")) {
        if (part_idx >= CT_MAX_LOG_FILES) {
            printf("the logfiles index(%u) is beyond the range(%u).\n", part_idx, CT_MAX_LOG_FILES);
            return CT_ERROR;
        }
        return repair_set_ctrl_logfiles(ctrl, &part2, node_id, part_idx, value);
    } else {
        printf("param value \'%s\' is invalid.\n", part1.str);
        return CT_ERROR;
    }
}

status_t repair_set_ctrl_storage(database_ctrl_t *ctrl, text_t *part, text_t *value)
{
    text_t part1, part2;
    uint32 part_idx = CT_INVALID_ID32;
    uint32 node_id = CT_INVALID_ID32;
    uint32 array_index = CT_INVALID_ID32;

    cm_split_text(part, '.', '\0', &part1, &part2);
    if (repair_get_item_index(&part1, &array_index) != CT_SUCCESS) {
        printf("param value \'%s\' is invalid.\n", part->str);
        return CT_ERROR;
    }
    if (array_index == CT_INVALID_ID32) {
        printf("param value \'%s\' is invalid.\n", part->str);
        return CT_ERROR;
    }

    cm_trim_text(&part1);
    cm_trim_text(&part2);

    if (cm_text_str_equal(&part1, "node")) {
        node_id = array_index;
        if (node_id >= ctrl->core.node_count) {
            printf("the node index(%u) is beyond the range(%u).\n", node_id, ctrl->core.node_count);
            return CT_ERROR;
        }
        return repair_set_ctrl_node(ctrl, &part2, node_id, value);
    } else if (cm_text_str_equal(&part1, "spaces")) {
        part_idx = array_index;
        if (part_idx >= CT_MAX_SPACES) {
            printf("the spaces index(%u) is beyond the range(%u).\n", part_idx, CT_MAX_SPACES);
            return CT_ERROR;
        }
        return repair_set_ctrl_spaces(ctrl, &part2, part_idx, value);
    } else if (cm_text_str_equal(&part1, "datafiles")) {
        part_idx = array_index;
        if (part_idx >= CT_MAX_DATA_FILES) {
            printf("the datafiles index(%u) is beyond the range(%u).\n", part_idx, CT_MAX_DATA_FILES);
            return CT_ERROR;
        }
        return repair_set_ctrl_datafiles(ctrl, &part2, part_idx, value);
    } else if (cm_text_str_equal(&part1, "redo")) {
        node_id = array_index;
        return repair_set_ctrl_cluster_files(ctrl, &part2, node_id, value);
    } else {
        printf("param value \'%s\' is invalid.\n", part1.str);
        return CT_ERROR;
    }
}

// core attrs repair blow
status_t repair_set_ctrl_core_resetlogs(uint32 item_size, void *item_ptr, text_t *value)
{
    reset_log_t *resetlogs = (reset_log_t *)item_ptr;
    char *str = repair_text_alloc_str(value);
    if (str == NULL) {
        return CT_ERROR;
    }

    errno_t ret = sscanf_s(str, "%u-%u-%llu", &resetlogs->rst_id, &resetlogs->last_asn,
        &resetlogs->last_lfn);
    if (ret == -1) {
        printf("param value \'%s\' is invalid.\n", value->str);
        CM_FREE_PTR(str);
        return CT_ERROR;
    }

    CM_FREE_PTR(str);
    return CT_SUCCESS;
}

status_t repair_set_ctrl_core_archive(uint32 item_size, void *item_ptr, text_t *value)
{
    uint32 pos;
    text_t line;
    uint32 id = 0;
    char *src_str;
    arch_log_id_t *archived_log = (arch_log_id_t *)item_ptr;

    src_str = repair_text_alloc_str(value);
    if (src_str == NULL) {
        return CT_ERROR;
    }
    line.len = value->len;
    line.str = src_str;

    while (!CM_IS_EMPTY(&line)) {
        pos = (uint32)strcspn(line.str, "-") + 1;
        if (pos == 1) {
            printf("param value \'%s\' is invalid.\n", value->str);
            CM_FREE_PTR(src_str);
            return CT_ERROR;
        }
        line.str[pos - 1] = '\0';
        if (cm_str2uint64(line.str, &archived_log[id++].arch_log)) {
            printf("param value \'%s\' is invalid.\n", value->str);
            CM_FREE_PTR(src_str);
            return CT_ERROR;
        }

        if (line.len < pos || id == CT_MAX_ARCH_DEST) {
            break;
        }

        line.str += pos;
        line.len -= pos;
        cm_trim_text(&line);
    }

    CM_FREE_PTR(src_str);
    return CT_SUCCESS;
}

status_t repair_set_ctrl_core_rfp(uint32 item_size, void *item_ptr, text_t *value)
{
    raft_point_t *rfp_point = (raft_point_t *)item_ptr;
    char *str = repair_text_alloc_str(value);
    if (str == NULL) {
        return CT_ERROR;
    }

    errno_t ret = sscanf_s(str, "scn(%llu)-lfn(%llu)-raft_index(%llu)", &rfp_point->scn,
        &rfp_point->lfn,
        &rfp_point->raft_index);
    if (ret == -1) {
        printf("param value \'%s\' is invalid.\n", value->str);
        CM_FREE_PTR(str);
        return CT_ERROR;
    }

    CM_FREE_PTR(str);
    return CT_SUCCESS;
}

status_t repair_set_ctrl_node_lrp(uint32 item_size, void *item_ptr, text_t *value)
{
    uint32 rst_id;
    uint64 lfn;
    log_point_t *lrp_point = (log_point_t *)item_ptr;
    char *str = repair_text_alloc_str(value);
    if (str == NULL) {
        return CT_ERROR;
    }

    errno_t ret =
        sscanf_s(str, "%u-%u-%u-%llu-%llu", &lrp_point->asn, &lrp_point->block_id, &rst_id, &lfn, &lrp_point->lsn);
    if (ret == -1) {
        (void)printf("param value \'%s\' is invalid.\n", value->str);
        CM_FREE_PTR(str);
        return CT_ERROR;
    }

    lrp_point->rst_id = rst_id;
    lrp_point->lfn = lfn;
    CM_FREE_PTR(str);
    return CT_SUCCESS;
}

status_t repair_set_ctrl_node_rcy(uint32 item_size, void *item_ptr, text_t *value)
{
    uint32 rst_id;
    uint64 lfn;
    log_point_t *rcy_point = (log_point_t *)item_ptr;
    char *str = repair_text_alloc_str(value);
    if (str == NULL) {
        return CT_ERROR;
    }

    errno_t ret =
        sscanf_s(str, "%u-%u-%u-%llu-%llu", &rcy_point->asn, &rcy_point->block_id, &rst_id, &lfn, &rcy_point->lsn);
    if (ret == -1) {
        (void)printf("param value \'%s\' is invalid.\n", value->str);
        CM_FREE_PTR(str);
        return CT_ERROR;
    }

    rcy_point->rst_id = rst_id;
    rcy_point->lfn = lfn;
    CM_FREE_PTR(str);
    return CT_SUCCESS;
}

status_t repair_set_ctrl_core_version(uint32 item_size, void *item_ptr, text_t *value)
{
    ctrl_version_t *version = (ctrl_version_t *)item_ptr;
    char *str = repair_text_alloc_str(value);
    if (str == NULL) {
        return CT_ERROR;
    }

    errno_t ret = sscanf_s(str, "%hu-%hu-%hu-%hu", &version->main, &version->major,
        &version->revision, &version->inner);
    if (ret == -1) {
        printf("param value \'%s\' is invalid.\n", value->str);
        CM_FREE_PTR(str);
        return CT_ERROR;
    }

    CM_FREE_PTR(str);
    return CT_SUCCESS;
}

status_t repair_set_ctrl_core(database_ctrl_t *ctrl, text_t *part, text_t *value)
{
    uint32 i = 0;
    core_ctrl_t *core = (core_ctrl_t *)&ctrl->pages[1].buf[0];
    
    for (; i < REPAIR_CTRLFILE_CORE_ITEM_COUNT; i++) {
        repair_ctrlfile_items_t *item = &g_repair_ctrlfile_core_items_list[i];
        if (cm_text_str_equal(part, item->name)) {
            return item->repair_func(item->item_size, (void *)(((char *)core) + item->item_offset), value);
        }
    }

    printf("param value \'%s\' is not supported.\n", part->str);
    return CT_ERROR;
}

status_t repair_set_ctrl_page_kv(database_ctrl_t *ctrl, text_t *name, text_t *value)
{
    text_t part1, part2;
    cm_split_text(name, '.', '\0', &part1, &part2);

    cm_trim_text(&part1);
    cm_trim_text(&part2);
    if (cm_text_str_equal(&part1, "core")) {
        return repair_set_ctrl_core(ctrl, &part2, value);
    } else if (cm_text_str_equal(&part1, "storage")) {
        return repair_set_ctrl_storage(ctrl, &part2, value);
    } else {
        printf("param value \'%s\' is invalid.\n", part1.str);
        return CT_ERROR;
    }
}

status_t repair_ctrlfile_core(database_ctrl_t *ctrl, char *crtlinfo)
{
    uint32 i = 0;
    uint32 line_no = 0;
    text_t text, name, value;
    bool32 is_eof = CT_FALSE;

    text.len = (uint32)strlen(crtlinfo);
    text.str = crtlinfo;

    // format this input str.
    for (i = 0; i < text.len; i++) {
        if (text.str[i] == ',') {
            text.str[i] = '\n';
        }
    }

    for (;;) {
        // get every kv
        if (repair_parse_kv(&text, &name, &value, &line_no, &is_eof) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (is_eof) {
            break;
        }
        cm_trim_text(&name);
        cm_trim_text(&value);
        cm_text_lower(&name);

        if (repair_set_ctrl_page_kv(ctrl, &name, &value) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

status_t repair_ctrlfile_prepare(repair_page_def_t *page_input, database_ctrl_t *ctrl, int32 *handle)
{
    int32 read_size;
    errno_t ret;
    uint32 size = CTRL_MAX_PAGES_CLUSTERED * CT_DFLT_CTRL_BLOCK_SIZE;

    ctrl->pages = (ctrl_page_t *)malloc(size);
    if (ctrl->pages == NULL) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)size, "miner parse ctrlfile");
        return CT_ERROR;
    }

    ret = memset_sp((char *)ctrl->pages, size, 0, size);
    if (ret != EOK) {
        CM_FREE_PTR(ctrl->pages);
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)CT_MAX_LOG_BUFFER_SIZE, "miner parse ctrlfile");
        return CT_ERROR;
    }

    if (cm_open_file(page_input->ctrlfile, O_RDWR | O_BINARY | O_SYNC, handle) != CT_SUCCESS) {
        CM_FREE_PTR(ctrl->pages);
        return CT_ERROR;
    }

    if (cm_seek_file(*handle, 0, SEEK_SET) != 0) {
        cm_close_file(*handle);
        CM_FREE_PTR(ctrl->pages);
        CT_THROW_ERROR(ERR_SEEK_FILE, 0, SEEK_SET, errno);
        return CT_ERROR;
    }

    if (cm_read_file(*handle, (void *)ctrl->pages, size, &read_size) != CT_SUCCESS) {
        cm_close_file(*handle);
        CM_FREE_PTR(ctrl->pages);
        return CT_ERROR;
    }

    if (miner_verify_ctrlfile(ctrl, CT_FALSE) != CT_SUCCESS) {
        cm_close_file(*handle);
        CM_FREE_PTR(ctrl->pages);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t repair_ctrlfile(repair_page_def_t *page_input)
{
    database_ctrl_t ctrl;
    int32 handle = -1;
    uint32 size = CTRL_MAX_PAGES_CLUSTERED * CT_DFLT_CTRL_BLOCK_SIZE;

    if (repair_ctrlfile_prepare(page_input, &ctrl, &handle) != CT_SUCCESS) {
        printf("repair prepare fail.\n");
        return CT_ERROR;
    }

    miner_init_ctrlfile(&ctrl);

    // modify
    if (repair_ctrlfile_core(&ctrl, page_input->ctrl_input.input_str) != CT_SUCCESS) {
        cm_close_file(handle);
        CM_FREE_PTR(ctrl.pages);
        return CT_ERROR;
    }

    // calc checksum again
    if (page_input->is_checksum) {
        miner_calc_ctrlfile_checksum(&ctrl);
    }

    // write to ctrlfile again
    if (cm_seek_file(handle, 0, SEEK_SET) != 0) {
        cm_close_file(handle);
        CM_FREE_PTR(ctrl.pages);
        CT_THROW_ERROR(ERR_SEEK_FILE, 0, SEEK_SET, errno);
        return CT_ERROR;
    }

    if (cm_write_file(handle, (void *)ctrl.pages, size) != CT_SUCCESS) {
        cm_close_file(handle);
        CM_FREE_PTR(ctrl.pages);
        return CT_ERROR;
    }

    cm_close_file(handle);
    CM_FREE_PTR(ctrl.pages);
    return CT_SUCCESS;
}

status_t repair_execute(int argc, char *argv[])
{
    repair_page_def_t page_input;
    repair_input_common_t input_common;
    
    repair_init_page_input(&page_input);
    repair_init_input_common(&input_common);

    if (argc > g_gm_optind) {
        if (strcmp(argv[g_gm_optind], "--help") == 0 || strcmp(argv[g_gm_optind], "-?") == 0 ||
            strcmp(argv[g_gm_optind], "-h") == 0) {
            usage();
            return CT_SUCCESS;
        }

        if (strcmp(argv[g_gm_optind], "--version") == 0 || strcmp(argv[g_gm_optind], "-V") == 0) {
            printf("repair (Z-engine) 1.0.1\n");
            return CT_SUCCESS;
        }
    }

    if (repair_init_parameters(argc, argv, &page_input, &input_common)) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "crepair input parameter");
        repair_free_page_input(&page_input);
        repair_free_input_common(&input_common);
        return CT_ERROR;
    }

    if (repair_verify_input(&page_input, input_common.log_path, argc, argv) == CT_ERROR) {
        repair_free_page_input(&page_input);
        repair_free_input_common(&input_common);
        return CT_ERROR;
    }

    repair_warning_timeout(CREPAIR_INTERACTION_DEFAULT_TIMEOUT);

    status_t status = CT_SUCCESS;
    if (page_input.datafile != NULL) {
        status = repair_datafile(&page_input, &input_common);
    } else if (page_input.ctrlfile != NULL) {
        status = repair_ctrlfile(&page_input);
    } else {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "crepair input parameter");
        repair_free_page_input(&page_input);
        repair_free_input_common(&input_common);
        return CT_ERROR;
    }

    repair_free_page_input(&page_input);
    repair_free_input_common(&input_common);
    return status;
}

