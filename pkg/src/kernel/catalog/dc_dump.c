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
 * dc_dump.c
 *
 *
 * IDENTIFICATION
 * src/kernel/catalog/dc_dump.c
 *
 * -------------------------------------------------------------------------
 */
#include "dc_dump.h"

#define MAX_DUMP_FILE_SIZE (10 * 1024 * 1024) // 10M

status_t dc_dump_prepare(cm_dump_t *dump, dc_dump_info_t *info, char *file_name, uint32 name_size)
{
    if (!CM_IS_EMPTY(&info->dump_file)) {
        errno_t ret = memset_sp(file_name, name_size, 0, name_size);
        knl_securec_check(ret);
        if (info->dump_file.len >= name_size) {
            GS_THROW_ERROR(ERR_INVALID_FILE_NAME, T2S(&info->dump_file), name_size);
            return GS_ERROR;
        }

        ret = memcpy_sp(file_name, name_size, info->dump_file.str, info->dump_file.len);
        knl_securec_check(ret);

        if (cm_file_exist(file_name)) {
            GS_THROW_ERROR(ERR_FILE_ALREADY_EXIST, file_name, "failed to dump catalog");
            return GS_ERROR;
        } else if (cm_create_file(file_name, O_RDWR | O_BINARY | O_SYNC, &dump->handle) != GS_SUCCESS) {
            return GS_ERROR;
        }
        return GS_SUCCESS;
    }

    if (cm_open_file(file_name, O_RDWR | O_CREAT | O_APPEND, &dump->handle) != GS_SUCCESS) {
        return GS_ERROR;
    }

    int64 file_size;
    cm_get_filesize(file_name, &file_size);
    if (file_size > MAX_DUMP_FILE_SIZE) {
        GS_LOG_RUN_ERR("[DB] the size of dump file %s is more than %d, need delete first",
            file_name, MAX_DUMP_FILE_SIZE);
        GS_THROW_ERROR(ERR_DATAFILE_RESIZE_EXCEED, file_size, MAX_DUMP_FILE_SIZE);
        cm_close_file(dump->handle);
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

static status_t dc_dump_index(cm_dump_t *dump, index_t *index)
{
    cm_dump(dump, "*****INDEX %s*****\n", index->desc.name);
    cm_dump(dump, "is_part: %d\n", index->desc.parted);
    if (IS_PART_INDEX(index)) {
        CM_DUMP_WRITE_FILE(dump);
        return GS_SUCCESS;
    }

    btree_t *btree = &index->btree;
    if (btree != NULL) {
        cm_dump(dump, "entry: %d-%d\n", AS_PAGID(&btree->entry).file, AS_PAGID(&btree->entry).page);
        cm_dump(dump, "extend_lock: %d\n", btree->extend_lock);
        cm_dump(dump, "wait_recycle: %u\n", btree->wait_recycle);
        cm_dump(dump, "is_recycling: %u\n", btree->is_recycling);
        cm_dump(dump, "alloc_pages: %lld\n", btree->chg_stats.alloc_pages);
        cm_dump(dump, "delete_size: %lld\n", btree->chg_stats.delete_size);
        cm_dump(dump, "empty_size: %llu\n", btree->chg_stats.empty_size);
        cm_dump(dump, "first_empty_size: %llu\n", btree->chg_stats.first_empty_size);
        cm_dump(dump, "ow_del_scn: %llu\n", btree->chg_stats.ow_del_scn);
        cm_dump(dump, "is_shadow: %d\n", btree->is_shadow);
        cm_dump(dump, "is_splitting: %d\n\n", btree->is_splitting);
    }
    CM_DUMP_WRITE_FILE(dump);
    return GS_SUCCESS;
}

static status_t dc_dump_table_entry(cm_dump_t *dump, dc_dump_info_t info, knl_dictionary_t dc)
{
    dc_entry_t *entry = DC_ENTRY(&dc);
    dc_entity_t *entity = DC_ENTITY(&dc);
    char date[GS_MAX_TIME_STRLEN] = { 0 };

    (void)cm_date2str(cm_now(), "yyyy-mm-dd hh24:mi:ss", date, GS_MAX_TIME_STRLEN);
    cm_dump(dump, "%s\n", date);
    cm_dump(dump, "------- Start Dump Table Dictionary Cache Info -------\n");
    cm_dump(dump, "TABLE_NAME: %s\n", T2S(&info.table_name));
    cm_dump(dump, "TABLE_ID: %d\n", entity->table.desc.id);
    cm_dump(dump, "INDEX_COUNT: %d\n", entity->table.desc.index_count);
    CM_DUMP_WRITE_FILE(dump);
    cm_dump(dump, "----Entry info:\n");
    cm_dump(dump, "lock: %d           /* avoid load entity concurrently */\n", entry->lock);
    cm_dump(dump, "serial_lock: %d    /* avoid update serial value concurrently */\n", entry->serial_lock.lock);
    cm_dump(dump, "sch_lock_mutex: %d /* avoid change lock status concurrently */\n", entry->sch_lock_mutex);
    cm_dump(dump, "ref_lock: %d       /* avoid change ref_count concurrently */\n", entry->ref_lock);
    cm_dump(dump, "ref_count %d\n", entry->ref_count);
    CM_DUMP_WRITE_FILE(dump);

    cm_dump(dump, "recycled: %d         /* TRUE when table has been dropped */\n", entry->recycled);
    cm_dump(dump, "ready: %d            /* TRUE when entry has been created */\n", entry->ready);
    cm_dump(dump, "need_empty_entry: %d /* only valid for nologging table */\n", entry->need_empty_entry);
    cm_dump(dump, "used: %d             /* FALSE when entry in the freelist */\n", entry->used);
    cm_dump(dump, "is_free: %d          /* TRUE when table has been dropped */\n", entry->is_free);
    CM_DUMP_WRITE_FILE(dump);

    cm_dump(dump, "----Entity info:\n");
    cm_dump(dump, "ref_lock: %d\n", entity->ref_lock);
    cm_dump(dump, "ref_count %d\n", entity->ref_count);
    cm_dump(dump, "stats_version: %d\n", entity->stats_version);
    cm_dump(dump, "cbo_latch: %d\n", entity->cbo_latch.stat);
    CM_DUMP_WRITE_FILE(dump);

    cm_dump(dump, "contain_lob: %d    /* TRUE when table has lob column */\n", entity->contain_lob);
    cm_dump(dump, "corrupted: %d      /* TRUE when segment has been broken */\n", entity->corrupted);
    cm_dump(dump, "has_udef_col: %d   /* TRUE when table has updated default column */\n", entity->has_udef_col);
    cm_dump(dump, "valid: %d          /* TRUE when table doing DDL concurrently */\n", entity->valid);
    cm_dump(dump, "forbid_dml: %d     /* TRUE when constraint has been disabled */\n", entity->forbid_dml);
    cm_dump(dump, "has_serial_col: %d /* TRUE when table has serial/auto_increment column */\n", entity->has_serial_col);
    cm_dump(dump, "is_analyzing: %d, stats_locked: %d, stat_exists: %d\n\n",
        entity->is_analyzing, entity->stats_locked, entity->stat_exists);
    CM_DUMP_WRITE_FILE(dump);
    return GS_SUCCESS;
}

status_t dc_dump_table(knl_session_t *session, cm_dump_t *dump, dc_dump_info_t info)
{
    knl_dictionary_t dc;
    char file_name[GS_MAX_FILE_NAME_LEN];

    if (knl_open_dc(session, &info.user_name, &info.table_name, &dc) != GS_SUCCESS) {
        return GS_ERROR;
    }

    errno_t ret = memset_sp(file_name, GS_MAX_FILE_NAME_LEN, 0, GS_MAX_FILE_NAME_LEN);
    knl_securec_check(ret);
    ret = snprintf_s(file_name, GS_MAX_FILE_NAME_LEN, GS_MAX_FILE_NAME_LEN - 1, "%s/trc/%s_%s_DUMP.trc",
        session->kernel->home, T2S(&info.user_name), T2S_EX(&info.table_name));
    knl_securec_check_ss(ret);

    if (dc_dump_prepare(dump, &info, file_name, GS_MAX_FILE_NAME_LEN) != GS_SUCCESS) {
        knl_close_dc(&dc);
        return GS_ERROR;
    }

    dc_entity_t *entity = DC_ENTITY(&dc);
    dump->offset = 0;
    if (dc_dump_table_entry(dump, info, dc) != GS_SUCCESS) {
        knl_close_dc(&dc);
        cm_close_file(dump->handle);
        return GS_ERROR;
    }

    index_t *index = NULL;
    for (uint32 i = 0; i < entity->table.index_set.total_count; i++) {
        index = entity->table.index_set.items[i];
        if (dc_dump_index(dump, index) != GS_SUCCESS) {
            knl_close_dc(&dc);
            cm_close_file(dump->handle);
            return GS_ERROR;
        }
    }
    cm_dump(dump, "-------- End of Dump Table ------\n\n");
    if (cm_dump_flush(dump) != GS_SUCCESS) {
        knl_close_dc(&dc);
        cm_close_file(dump->handle);
        return GS_ERROR;
    }

    knl_close_dc(&dc);
    cm_close_file(dump->handle);
    return GS_SUCCESS;
}

status_t dc_dump_user(knl_session_t *session, cm_dump_t *dump, dc_dump_info_t info)
{
    char file_name[GS_MAX_FILE_NAME_LEN];
    dc_user_t *user = NULL;

    if (dc_open_user(session, &info.user_name, &user) != GS_SUCCESS) {
        return GS_ERROR;
    }

    errno_t ret = memset_sp(file_name, GS_MAX_FILE_NAME_LEN, 0, GS_MAX_FILE_NAME_LEN);
    knl_securec_check(ret);
    ret = snprintf_s(file_name, GS_MAX_FILE_NAME_LEN, GS_MAX_FILE_NAME_LEN - 1, "%s/trc/USER_%s_DUMP.trc",
        session->kernel->home, T2S(&info.user_name));
    knl_securec_check_ss(ret);
    if (dc_dump_prepare(dump, &info, file_name, GS_MAX_FILE_NAME_LEN) != GS_SUCCESS) {
        return GS_ERROR;
    }
    dump->offset = 0;
    char date[GS_MAX_TIME_STRLEN] = { 0 };

    (void)cm_date2str(cm_now(), "yyyy-mm-dd hh24:mi:ss", date, GS_MAX_TIME_STRLEN);
    cm_dump(dump, "%s\n", date);
    cm_dump(dump, "------- Start Dump User Dictionary Cache Info -------\n");
    cm_dump(dump, "user_name: %s\n", user->desc.name);
    CM_DUMP_WRITE_FILE(dump);
    cm_dump(dump, "----User spin_lock info:\n");
    cm_dump(dump, "lock: %d       /* avoid concurrent allocation of entry */\n", user->lock);
    cm_dump(dump, "load_lock: %d  /* for is_loaded flag */\n", user->load_lock);
    cm_dump(dump, "s_lock: %d     /* avoid changing user status concurrently */\n", user->s_lock);
    cm_dump(dump, "user_latch: %d /* avoid concurrent execution of drop user and create/drop object */\n",
            user->user_latch.latch.stat);
    cm_dump(dump, "lib_latch: %d  /* latch for pl */\n", user->lib_latch.latch.stat);
    CM_DUMP_WRITE_FILE(dump);

    cm_dump(dump, "----User flag info:\n");
    cm_dump(dump, "status: %d /* 1-normal, 2-locked, 3-offline, 4-dropped*/\n", user->status);
    cm_dump(dump, "is_loaded: %d, has_nologging: %d\n", user->is_loaded, user->has_nologging);
    cm_dump(dump, "entry_lwm: %d, entry_hwm: %d\n", user->entry_lwm, user->entry_hwm);
    cm_dump(dump, "-------- End of Dump User ------\n\n");
    CM_DUMP_WRITE_FILE(dump);
    cm_close_file(dump->handle);
    return GS_SUCCESS;
}
