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
 * knl_space_base.c
 *
 *
 * IDENTIFICATION
 * src/kernel/tablespace/knl_space_base.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_space_module.h"
#include "knl_space_base.h"
#include "cm_log.h"
#include "cm_file.h"
#include "cm_kmc.h"
#include "knl_context.h"
#include "dtc_database.h"
#include "dtc_dls.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SPACE_FILE_PER_LINE (uint32)(80)
#define SPACE_VIEW_WAIT_INTERVAL    100

bool32 spc_try_lock_space(knl_session_t *session, space_t *space, uint32 wait_time, const char *operation)
{
    for (;;) {
        if (SECUREC_UNLIKELY(session->canceled)) {
            CT_THROW_ERROR(ERR_OPERATION_CANCELED);
            return CT_FALSE;
        }

        if (SECUREC_UNLIKELY(session->killed)) {
            CT_THROW_ERROR(ERR_OPERATION_KILLED);
            return CT_FALSE;
        }

        if (SECUREC_UNLIKELY(!SPACE_IS_ONLINE(space))) {
            CT_THROW_ERROR(ERR_SPACE_OFFLINE, space->ctrl->name, operation);
            return CT_FALSE;
        }

        if (dls_spin_try_lock(session, &space->lock)) {
            break;
        }
        cm_sleep(wait_time);
    }
    return CT_TRUE;
}

bool32 spc_view_try_lock_space(knl_session_t *session, space_t *space, const char *operation)
{
    return spc_try_lock_space(session, space, SPACE_VIEW_WAIT_INTERVAL, operation);
}

bool32 spc_try_lock_space_file(knl_session_t *session, space_t *space, datafile_t *df)
{
    if (!spc_try_lock_space(session, space, SPACE_DDL_WAIT_INTERVAL, "punch space failed")) {
        return CT_FALSE;
    }

    if (!DATAFILE_IS_ONLINE(df) || df->space_id >= CT_MAX_SPACES || DF_FILENO_IS_INVAILD(df) || space->is_empty ||
        !space->ctrl->used || !SPACE_IS_ONLINE(space)) {
        char *space_name = (df->space_id >= CT_MAX_SPACES) ? "invalid space" : space->ctrl->name;
        dls_spin_unlock(session, &space->lock);
        CT_THROW_ERROR(ERR_SPACE_OFFLINE, space_name, "punch space failed");
        return CT_FALSE;
    }

    return CT_TRUE;
}

/*
 * get total page count by extent count
 */
uint32 spc_pages_by_ext_cnt(space_t *space, uint32 extent_count, uint8 seg_page_type)
{
    uint32 extent_cnt = extent_count;
    uint32 total_pages = 0;

    if (SPACE_IS_AUTOALLOCATE(space) && seg_page_type != PAGE_TYPE_LOB_HEAD) {
        if (extent_cnt > EXT_SIZE_1024_BOUNDARY) {
            total_pages += (extent_cnt - EXT_SIZE_1024_BOUNDARY) * EXT_SIZE_8192;
            extent_cnt = EXT_SIZE_1024_BOUNDARY;
        }

        if (extent_cnt > EXT_SIZE_128_BOUNDARY) {
            total_pages += (extent_cnt - EXT_SIZE_128_BOUNDARY) * EXT_SIZE_1024;
            extent_cnt = EXT_SIZE_128_BOUNDARY;
        }

        if (extent_cnt > EXT_SIZE_8_BOUNDARY) {
            total_pages += (extent_cnt - EXT_SIZE_8_BOUNDARY) * EXT_SIZE_128;
            extent_cnt = EXT_SIZE_8_BOUNDARY;
        }

        total_pages += extent_cnt * EXT_SIZE_8;
    } else {
        total_pages = extent_cnt * space->ctrl->extent_size;
    }
    return total_pages;
}

bool32 spc_validate_datefile(datafile_t *df)
{
    if (DF_FILENO_IS_INVAILD(df) || !df->ctrl->used || !DATAFILE_IS_ONLINE(df)) {
        return CT_FALSE;
    }
    return CT_TRUE;
}

static inline bool32 spc_check_space_entry_pageid(space_head_t *space_head, page_id_t entry_page_id)
{
    page_head_t *head_page = (page_head_t *)((char *)space_head - PAGE_HEAD_SIZE);
    return IS_SAME_PAGID(AS_PAGID(head_page->id), entry_page_id);
}

bool32 spc_validate_page_id(knl_session_t *session, page_id_t page_id)
{
    datafile_t *df = NULL;
    space_t *space = NULL;
    uint32 dw_file_id;

    if (IS_INVALID_PAGID(page_id) || page_id.page == 0) {
        return CT_FALSE;
    }

    df = DATAFILE_GET(session, page_id.file);
    if (!spc_validate_datefile(df)) {
        return CT_FALSE;
    }

    space = SPACE_GET(session, df->space_id);
    if (!SPACE_IS_ONLINE(space)) {
        return CT_FALSE;
    }

    if (IS_SWAP_SPACE(space)) {
        return CT_FALSE;
    }

    dw_file_id = knl_get_dbwrite_file_id(session);
    if (DATAFILE_CONTAINS_DW(df, dw_file_id)) {
        if (page_id.page < DW_SPC_HWM_START && page_id.page > DW_DISTRICT_BEGIN(session->kernel->id)) {
            return CT_FALSE;
        }
    }

    if (session->kernel->db.status == DB_STATUS_OPEN && !DB_ATTR_ENABLE_HWM_CHANGE(session)) {
        if (page_id.page < space->head->hwms[df->file_no] && spc_check_space_entry_pageid(space->head, space->entry)) {
            return CT_TRUE;
        }
    }

    if (page_id.page >= SPACE_HEAD_RESIDENT(session, space)->hwms[df->file_no]) {
        return CT_FALSE;
    }

#ifdef DB_DEBUG_VERSION
    /* there is no temp2_undo rollback during recovery */
    if (DB_IS_BG_ROLLBACK_SE(session)) {
        knl_panic_log(SPACE_IS_LOGGING(space), "current space is logging table space, panic info: page %u-%u",
                      page_id.file, page_id.page);
    }
#endif

    return CT_TRUE;
}

status_t space_head_dump(knl_session_t *session, page_head_t *page_head, cm_dump_t *dump)
{
    space_head_t *space_head = (space_head_t *)((char *)page_head + PAGE_HEAD_SIZE);

    cm_dump(dump, "space head information\n");
    cm_dump(dump, "\tsegment_count: %u", space_head->segment_count);
    cm_dump(dump, "\tdatafile_count: %u", space_head->datafile_count);
    cm_dump(dump, "\tfree_extents: count %u \tfirst %u-%u \tlast %u-%u\n", space_head->free_extents.count,
        space_head->free_extents.first.file, space_head->free_extents.first.page,
        space_head->free_extents.last.file, space_head->free_extents.last.page);
    cm_dump(dump, "datafile hwms information:");
    CM_DUMP_WRITE_FILE(dump);
    for (uint32 slot = 0; slot < CT_MAX_SPACE_FILES; slot++) {
        /* space files per line 80 */
        if (slot % SPACE_FILE_PER_LINE == 0) {
            cm_dump(dump, "\n\t");
        }

        cm_dump(dump, "%u ", space_head->hwms[slot]);
        CM_DUMP_WRITE_FILE(dump);
    }

    return CT_SUCCESS;
}

uint32 spc_ext_cnt_by_pages(space_t *space, uint32 page_count)
{
    uint32 extent_cnt;

    if (page_count == 0 || page_count == CT_INVALID_ID32) {
        return CT_INVALID_ID32;
    }

    if (SPACE_IS_AUTOALLOCATE(space)) {
        if (page_count >= EXT_SIZE_1024_PAGE_BOUNDARY) {
            extent_cnt = CM_CALC_ALIGN(page_count - EXT_SIZE_1024_PAGE_BOUNDARY, EXT_SIZE_8192) / EXT_SIZE_8192;
            extent_cnt += EXT_SIZE_1024_BOUNDARY;
        } else if (page_count >= EXT_SIZE_128_PAGE_BOUNDARY) {
            extent_cnt = CM_CALC_ALIGN(page_count - EXT_SIZE_128_PAGE_BOUNDARY, EXT_SIZE_1024) / EXT_SIZE_1024;
            extent_cnt += EXT_SIZE_128_BOUNDARY;
        } else if (page_count >= EXT_SIZE_8_PAGE_BOUNDARY) {
            extent_cnt = CM_CALC_ALIGN(page_count - EXT_SIZE_8_PAGE_BOUNDARY, EXT_SIZE_128) / EXT_SIZE_128;
            extent_cnt += EXT_SIZE_8_BOUNDARY;
        } else {
            extent_cnt = CM_CALC_ALIGN(page_count, EXT_SIZE_8) / EXT_SIZE_8;
        }
    } else {
        extent_cnt = CM_CALC_ALIGN(page_count, space->ctrl->extent_size) / space->ctrl->extent_size;
    }
    return extent_cnt;
}

// get current extent size and next extent
page_id_t spc_get_size_next_ext(knl_session_t *session, space_t *space, page_id_t extent, uint32 *ext_size)
{
    page_head_t *last_page = NULL;

    buf_enter_page(session, extent, LATCH_MODE_S, ENTER_PAGE_NORMAL);
    last_page = (page_head_t *)session->curr_page;

    *ext_size = spc_get_page_ext_size(space, last_page->ext_size);

    page_id_t next_extent = AS_PAGID(last_page->next_ext);
    buf_leave_page(session, CT_FALSE);
    return next_extent;
}

uint64 spc_count_pages_with_ext(knl_session_t *session, space_t *space, bool32 used)
{
    datafile_t *df = NULL;
    uint64 total_pages = 0;

    CM_POINTER2(session, space);
    dls_spin_lock(session, &space->lock, &session->stat->spin_stat.stat_space);
    for (uint32 i = 0; i < space->ctrl->file_hwm; i++) {
        if (CT_INVALID_ID32 == space->ctrl->files[i]) {
            continue;
        }

        if (used) {
            total_pages += SPACE_HEAD_RESIDENT(session, space)->hwms[i];
        } else {
            df = DATAFILE_GET(session, space->ctrl->files[i]);
            if (!DATAFILE_IS_ONLINE(df)) {
                continue;
            }
            if (DATAFILE_IS_AUTO_EXTEND(df)) {
                total_pages += (uint64)df->ctrl->auto_extend_maxsize / DEFAULT_PAGE_SIZE(session);
            } else {
                total_pages += (uint32)((uint64)df->ctrl->size / DEFAULT_PAGE_SIZE(session));
            }
        }
    }

    dls_spin_unlock(session, &space->lock);

    return total_pages;
}

uint64 spc_count_backup_pages(knl_session_t *session, space_t *space)
{
    datafile_t *df = NULL;
    uint64 total_pages = 0;
    uint32 dw_file_id = knl_get_dbwrite_file_id(session);

    CM_POINTER2(session, space);
    dls_spin_lock(session, &space->lock, &session->stat->spin_stat.stat_space);

    for (uint32 i = 0; i < space->ctrl->file_hwm; i++) {
        if (space->ctrl->files[i] == CT_INVALID_ID32) {
            continue;
        }

        /*
         * in datafile including double write area, double write area only backup space_head page
         * in normal datafile, read skip file_hdr
         */
        df = DATAFILE_GET(session, space->ctrl->files[i]);
        if (!DATAFILE_IS_ONLINE(df) || !df->ctrl->used) {
            continue;
        }
        if (DATAFILE_CONTAINS_DW(df, dw_file_id)) {
            total_pages += (SPACE_HEAD_RESIDENT(session, space)->hwms[i] - DW_SPC_HWM_START + 1);
        } else {
            total_pages += (SPACE_HEAD_RESIDENT(session, space)->hwms[i] - 1);
        }
    }

    dls_spin_unlock(session, &space->lock);
    return total_pages;
}

bool32 spc_valid_space_object(knl_session_t *session, uint32 space_id)
{
    space_t *space = SPACE_GET(session, space_id);

    if (SPACE_IS_DEFAULT(space)) {
        return CT_TRUE;
    }

    if (!space->ctrl->used || !SPACE_IS_ONLINE(space)) {
        return CT_FALSE;
    }

    return CT_TRUE;
}

void spc_concat_extent(knl_session_t *session, page_id_t last_ext, page_id_t ext)
{
    page_head_t *head = NULL;

    buf_enter_page(session, last_ext, LATCH_MODE_X, ENTER_PAGE_NORMAL);
    head = (page_head_t *)CURR_PAGE(session);
    TO_PAGID_DATA(ext, head->next_ext);

    bool32 need_redo = SPC_IS_LOGGING_BY_PAGEID(session, last_ext);
    if (need_redo) {
        log_put(session, RD_SPC_CONCAT_EXTENT, &ext, sizeof(page_id_t), LOG_ENTRY_FLAG_NONE);
    }
    buf_leave_page(session, CT_TRUE);
}

void spc_concat_extents(knl_session_t *session, page_list_t *extents, const page_list_t *next_exts)
{
    spc_concat_extent(session, extents->last, next_exts->first);
    extents->count += next_exts->count;
    extents->last = next_exts->last;
}

/*
 * db crash when creating space may bring out space that is not completed after recovery,
 * so we need to clean those garbage spaces after recovery or before standby is becoming primary.
 */
status_t spc_clean_garbage_space(knl_session_t *session)
{
    space_t *space = NULL;
    char spc_name[CT_NAME_BUFFER_SIZE];
    uint32 i;
    errno_t ret;

    CT_LOG_RUN_INF("[SPACE] Clean garbage tablespace start");
    for (i = 0; i < CT_MAX_SPACES; i++) {
        space = SPACE_GET(session, i);
        if (!space->ctrl->used || space->ctrl->file_hwm != 0) {
            continue;
        }

        ret = strncpy_s(spc_name, CT_NAME_BUFFER_SIZE, space->ctrl->name, sizeof(space->ctrl->name) - 1);
        knl_securec_check(ret);

        if (spc_remove_space(session, space, TABALESPACE_INCLUDE || TABALESPACE_DFS_AND, CT_TRUE) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (db_save_space_ctrl(session, space->ctrl->id) != CT_SUCCESS) {
            CM_ABORT(0, "[SPACE] ABORT INFO: failed to save whole control file when drop tablespace");
        }

        CT_LOG_RUN_INF("[SPACE] succeed to clean garbage tablespace %s", spc_name);
    }

    CT_LOG_RUN_INF("[SPACE] Clean garbage tablespace end");

    return CT_SUCCESS;
}

page_id_t spc_get_next_ext(knl_session_t *session, page_id_t extent)
{
    buf_enter_page(session, extent, LATCH_MODE_S, ENTER_PAGE_NORMAL);
    page_head_t *last_page = (page_head_t *)session->curr_page;
    page_id_t next_extent = AS_PAGID(last_page->next_ext);
    buf_leave_page(session, CT_FALSE);
    return next_extent;
}

uint32 spc_get_df_used_pages(knl_session_t *session, space_t *space, uint32 file_no)
{
    datafile_t *df = NULL;

    if (SPACE_IS_BITMAPMANAGED(space)) {
        df = DATAFILE_GET(session, space->ctrl->files[file_no]);
        return df_get_used_pages(session, df);
    } else {
        buf_enter_page(session, space->entry, LATCH_MODE_S, ENTER_PAGE_RESIDENT);
        uint32 count = space->head->hwms[file_no];
        buf_leave_page(session, CT_FALSE);
        return count;
    }
}

status_t spc_get_space_name(knl_session_t *session, uint32 space_id, text_t *space_name)
{
    space_t *space = NULL;

    if (space_id >= CT_MAX_SPACES) {
        CT_THROW_ERROR(ERR_TOO_MANY_OBJECTS, CT_MAX_SPACES, "tablespace");
        return CT_ERROR;
    }

    space = SPACE_GET(session, space_id);
    if (!space->ctrl->used) {
        CT_THROW_ERROR(ERR_OBJECT_ID_NOT_EXIST, "tablespace", space_id);
        return CT_ERROR;
    }

    cm_str2text(space->ctrl->name, space_name);
    return CT_SUCCESS;
}

status_t spc_get_device_type(knl_session_t *session, text_t *spc_name, device_type_t *type)
{
    datafile_t *df = NULL;
    space_t *space = NULL;
    uint32 space_id;
    if (CT_SUCCESS != spc_get_space_id(session, spc_name, CT_FALSE, &space_id)) {
        return CT_ERROR;
    }

    space = KNL_GET_SPACE(session, space_id);
    dls_spin_lock(session, &space->lock, &session->stat->spin_stat.stat_space);
    for (uint32 i = 0; i < CT_MAX_SPACE_FILES; i++) {
        if (CT_INVALID_ID32 == space->ctrl->files[i]) {
            continue;
        }

        df = DATAFILE_GET(session, space->ctrl->files[i]);
        break;
    }
    dls_spin_unlock(session, &space->lock);

    if (df == NULL) {
        CT_THROW_ERROR(ERR_SPACE_NO_DATAFILE);
        return CT_ERROR;
    }
    *type = df->ctrl->type;
    return CT_SUCCESS;
}

status_t spc_get_space_id(knl_session_t *session, const text_t *name, bool32 is_for_create_db, uint32 *space_id)
{
    space_t *space = NULL;
    uint32 i;
    CM_POINTER3(session, name, space_id);

    for (i = 0; i < CT_MAX_SPACES; i++) {
        space = SPACE_GET(session, i);
        if (!space->ctrl->used) {
            continue;
        }

        if (cm_text_str_equal(name, space->ctrl->name) && is_for_create_db == space->ctrl->is_for_create_db) {
            break;
        }
    }

    if (i >= CT_MAX_SPACES) {
        CT_THROW_ERROR(ERR_SPACE_NOT_EXIST, T2S(name));
        return CT_ERROR;
    }

    if (space_id == NULL) {
        CT_LOG_RUN_ERR("space_id is null pointer!");
        return CT_ERROR;
    }
    *space_id = i;
    return CT_SUCCESS;
}

status_t spc_check_user_privs(knl_session_t *session, uint32 space_id)
{
    space_t *space = SPACE_GET(session, space_id);

    if (!(IS_SYSTEM_SPACE(space) || IS_SYSAUX_SPACE(space))) {
        return CT_SUCCESS;
    }

    if (knl_check_sys_priv_by_uid(session, session->uid, USE_ANY_TABLESPACE)) {
        return CT_SUCCESS;
    }

    CT_THROW_ERROR(ERR_NO_SPACE_PRIV, space->ctrl->name);
    return CT_ERROR;
}

// get space id and check if space is usable in the tenant by user id
status_t spc_check_by_uid(knl_session_t *session, const text_t *name, uint32 space_id, uint32 uid)
{
    dc_user_t *user = NULL;

    if (dc_open_user_by_id(session, uid, &user) != CT_SUCCESS) {
        return CT_ERROR;
    }
    
    if (spc_check_user_privs(session, space_id) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return spc_check_by_tid(session, name, space_id, user->desc.tenant_id);
}

// get space id and check if space is usable in the tenant by tenant id
status_t spc_check_by_tid(knl_session_t *session, const text_t *name, uint32 space_id, uint32 tid)
{
    dc_tenant_t *tenant = NULL;
    bool32 flag;

    if (tid == SYS_TENANTROOT_ID) {
        return CT_SUCCESS;
    }
    if (dc_open_tenant_by_id(session, tid, &tenant) != CT_SUCCESS) {
        return CT_ERROR;
    }

    flag = dc_get_tenant_tablespace_bitmap(&tenant->desc, space_id);
    dc_close_tenant(session, tid);
    if (!flag) {
        CT_THROW_ERROR(ERR_SPACE_DISABLED, T2S(name));
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

uint64 spc_count_pages(knl_session_t *session, space_t *space, bool32 used)
{
    datafile_t *df = NULL;
    uint64 total_pages = 0;

    CM_POINTER2(session, space);

    dls_spin_lock(session, &space->lock, &session->stat->spin_stat.stat_space);

    /*
     * for undo space , total pages is less than 2^22 * 1000
     * for other spaces, total pages is less than 2^30 * 1000
     */
    for (uint32 i = 0; i < space->ctrl->file_hwm; i++) {
        if (CT_INVALID_ID32 == space->ctrl->files[i]) {
            continue;
        }

        if (used) {
            total_pages += SPACE_HEAD_RESIDENT(session, space)->hwms[i];
        } else {
            df = DATAFILE_GET(session, space->ctrl->files[i]);
            total_pages += (uint32)((uint64)df->ctrl->size / DEFAULT_PAGE_SIZE(session));
        }
    }

    dls_spin_unlock(session, &space->lock);

    return total_pages;
}

/* Set df->space_id without mount datafiles. This function is used when DB is started as mount mode */
void spc_set_space_id(knl_session_t *session)
{
    datafile_t *df = NULL;
    space_t *space = NULL;
    uint32 file_id;

    for (uint32 spc_id = 0; spc_id < CT_MAX_SPACES; spc_id++) {
        space = SPACE_GET(session, spc_id);
        if (!SPACE_IS_ONLINE(space) || !space->ctrl->used) {
            continue;
        }

        for (uint32 i = 0; i < space->ctrl->file_hwm; i++) {
            file_id = space->ctrl->files[i];
            if (file_id == CT_INVALID_ID32) {
                continue;
            }

            df = DATAFILE_GET(session, file_id);
            df->file_no = i;
            df->space_id = space->ctrl->id;
        }
    }
}

bool32 spc_need_clean(space_t *space)
{
    if (space->ctrl->file_hwm == 0) {
        return CT_FALSE;
    }

    if (SPACE_IS_LOGGING(space)) {
        return CT_FALSE;
    }

    if (IS_SWAP_SPACE(space)) {
        return CT_FALSE;
    }

    if (!SPACE_IS_ONLINE(space)) {
        return CT_FALSE;
    }

    if (IS_TEMP2_UNDO_SPACE(space)) {
        return CT_FALSE;
    }

    return CT_TRUE;
}

/*
 * judge whether need to add a new bitmap group after datafile extended.
 * the max pages that managed by current bitmap group including
 * 1.file head page, space head page, bitmap head page
 * 2.total bitmap pages of each bitmap group
 * 3.data pages managed by each bitmap group
 */
static bool32 spc_need_more_map_group(knl_session_t *session, datafile_t *df)
{
    uint32 i;
    int64 total_pages, total_size;
    df_map_group_t group;

    total_pages = 0;
    for (i = 0; i < df->map_head->group_count; i++) {
        group = df->map_head->groups[i];
        total_pages += group.page_count;
    }

    total_pages += total_pages * DF_MAP_BIT_CNT(session) * df->map_head->bit_unit; // add up data pages
    total_pages += DF_MAP_HEAD_PAGE + 1;  // add up three head pages
    total_size = total_pages * DEFAULT_PAGE_SIZE(session);

    return total_size < df->ctrl->size;
}

int64 spc_get_extend_size(knl_session_t *session, datafile_t *df, uint32 extent_size, bool32 *need_group)
{
    int64 size;

    if (df->ctrl->size + df->ctrl->auto_extend_size > df->ctrl->auto_extend_maxsize) {
        size = df->ctrl->auto_extend_maxsize - df->ctrl->size;
    } else {
        size = df->ctrl->auto_extend_size;
    }

    if (size < extent_size * DEFAULT_PAGE_SIZE(session)) {
        size = extent_size * DEFAULT_PAGE_SIZE(session);
    }

    /* if need to add new bitmap group, extend bitmap space additionally */
    *need_group = spc_need_more_map_group(session, df);
    if (*need_group) {
        size += DF_MAP_GROUP_SIZE * DEFAULT_PAGE_SIZE(session);
    }

    return size;
}

/*
 * find the smallest file that fulfil the requirment to extend
 */
status_t spc_find_extend_file(knl_session_t *session, space_t *space, uint32 extent_size, uint32 *file_no,
    bool32 is_compress)
{
    datafile_t *df = NULL;
    uint32 id;
    int64 size = 0;

    for (id = 0; id < space->ctrl->file_hwm; id++) {
        if (CT_INVALID_ID32 == space->ctrl->files[id]) {
            continue;
        }

        df = DATAFILE_GET(session, space->ctrl->files[id]);
        if (!is_compress != !DATAFILE_IS_COMPRESS(df)) {
            continue;
        }
        if (DATAFILE_IS_AUTO_EXTEND(df) && (df->ctrl->size < size || size == 0)) {
            /* guarantee that can alloc an extent at lease after extend */
            if (df->ctrl->size + extent_size * DEFAULT_PAGE_SIZE(session) > df->ctrl->auto_extend_maxsize) {
                continue;
            }

            *file_no = id;
            size = df->ctrl->size;
        }
    }

    if (*file_no == CT_INVALID_ID32) {
        CT_THROW_ERROR(ERR_ALLOC_EXTENT, space->ctrl->name);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

void spc_alloc_free_extent(knl_session_t *session, space_t *space, page_id_t *extent)
{
    bool32 need_redo = SPACE_IS_LOGGING(space);

    buf_enter_page(session, space->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);
    knl_panic_log(!IS_INVALID_PAGID(space->head->free_extents.first),
                  "the first of free_extents is invalid, panic info: first page of extents %u-%u type %u",
                  space->head->free_extents.first.file, space->head->free_extents.first.page,
                  ((page_head_t *)CURR_PAGE(session))->type);
    knl_panic_log(!IS_INVALID_PAGID(space->head->free_extents.last),
                  "the last of free_extents is invalid, panic info: last page of extents %u-%u type %u",
                  space->head->free_extents.last.file, space->head->free_extents.last.page,
                  ((page_head_t *)CURR_PAGE(session))->type);
    *extent = space->head->free_extents.first;
    space->head->free_extents.count--;
    
    if (space->head->free_extents.count == 0) {
        space->head->free_extents.first = INVALID_PAGID;
        space->head->free_extents.last = INVALID_PAGID;
    } else {
        space->head->free_extents.first = spc_get_next_ext(session, *extent);
        knl_panic_log(!IS_INVALID_PAGID(space->head->free_extents.first),
                      "the first of free_extents is invalid page, panic info: first page of extents %u-%u",
                      space->head->free_extents.first.file, space->head->free_extents.first.page);
        knl_panic_log(!IS_INVALID_PAGID(space->head->free_extents.last),
                      "the last of free_extents is invalid page, panic info: last page of extents %u-%u",
                      space->head->free_extents.last.file, space->head->free_extents.last.page);
    }
    
    if (need_redo) {
        log_put(session, RD_SPC_ALLOC_EXTENT, &space->head->free_extents, sizeof(page_list_t), LOG_ENTRY_FLAG_NONE);
    }
    buf_leave_page(session, CT_TRUE);
}

space_t *spc_get_undo_space(knl_session_t *session, uint8 inst_id)
{
    uint32 space_id;

    space_id = dtc_get_ctrl(session, inst_id)->undo_space;

    return SPACE_GET(session, space_id);
}

void spc_unlock_space(knl_session_t *session, space_t *space)
{
    dls_spin_unlock(session, &space->lock);
}

bool32 spc_is_remote_swap_space(knl_session_t *session, space_t *space)
{
    return (IS_SWAP_SPACE(space) && space->ctrl->id != dtc_my_ctrl(session)->swap_space);
}

#ifdef __cplusplus
}
#endif

