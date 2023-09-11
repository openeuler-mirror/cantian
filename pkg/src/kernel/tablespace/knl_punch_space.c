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
 * knl_punch_space.c
 *
 *
 * IDENTIFICATION
 * src/kernel/tablespace/knl_punch_space.c
 *
 * -------------------------------------------------------------------------
 */

#include "knl_punch_space.h"
#include "knl_context.h"
#include "dtc_dls.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SPACE_PUNCH_CKPT_INTERVAL 4096

static inline void spc_print_punch_log(knl_session_t *session, space_t *space, const char *info)
{
    spc_punch_head_t *punch_head = SPACE_PUNCH_HEAD_PTR(space);
    page_list_t *p_ing = &punch_head->punching_exts;
    page_list_t *p_ed = &punch_head->punched_exts;
    page_list_t *free = &space->head->free_extents;
    GS_LOG_DEBUG_INF("[SPC PUNCH] %s: free extents count %u first %u-%u last %u-%u, punching extents count %u "
        "first %u-%u last %u-%u, punched extents count %u first %u-%u last %u-%u.", info,
        free->count, (uint32)free->first.file, free->first.page, (uint32)free->last.file, free->last.page,
        p_ing->count, (uint32)p_ing->first.file, p_ing->first.page, (uint32)p_ing->last.file, p_ing->last.page,
        p_ed->count, (uint32)p_ed->first.file, p_ed->first.page, (uint32)p_ed->last.file, p_ed->last.page);
}

void spc_set_datafile_ctrl_punched(knl_session_t *session, uint16 file_id)
{
    knl_panic_log(file_id != GS_INVALID_FILEID, "file id is invalid when set datafile ctrl punched");
    datafile_t *df = DATAFILE_GET(session, file_id);
    if (!df->ctrl->punched) {
        df->ctrl->punched = GS_TRUE;
        if (db_save_datafile_ctrl(session, file_id) != GS_SUCCESS) {
            CM_ABORT(0, "[SPACE] ABORT INFO: failed to save datafile ctrl");
        }
    }
}

// warning: ext_size need to less than KNL_MAX_ATOMIC_PAGES
void spc_punch_extent(knl_session_t *session, page_id_t first_page, uint32 ext_size)
{
    page_id_t punch_page = first_page;
    page_tail_t *tail = NULL;
    rd_punch_page_t redo = {0};

    spc_set_datafile_ctrl_punched(session, punch_page.file);
    for (uint32 i = 0; i < ext_size; i++) {
        log_atomic_op_begin(session);
        buf_enter_page(session, punch_page, LATCH_MODE_X, ENTER_PAGE_NO_READ);
        page_head_t *page = (page_head_t*)session->curr_page;
        TO_PAGID_DATA(punch_page, page->id);
        page->type = PAGE_TYPE_PUNCH_PAGE;
        page->size_units = page_size_units(DEFAULT_PAGE_SIZE(session));
        page->pcn = 0;
        tail = PAGE_TAIL(page);
        tail->checksum = 0;
        tail->pcn = 0;
        redo.page_id.page = punch_page.page;
        redo.page_id.file = punch_page.file;
        log_put(session, RD_PUNCH_FORMAT_PAGE, &redo, sizeof(rd_punch_page_t), LOG_ENTRY_FLAG_NONE);
        buf_leave_page(session, GS_TRUE);
        punch_page.page++;
        log_atomic_op_end(session);
    }
}

static inline bool32 spc_punch_normal_verify_extent(page_id_t *page_id)
{
    if (IS_INVALID_PAGID(*page_id) || page_id->file == 0) {
        return GS_FALSE;
    }
    return GS_TRUE;
}

void spc_punch_residual_extents(knl_session_t *session, uint32 extent_size, page_list_t *punch_exts)
{
    page_id_t page_id = punch_exts->first;
    page_id_t next_page_id;
    for (uint32 i = 0; i < punch_exts->count; i++) {
        // first get next page id, because extent may be punched by ckpt
        if (!spc_punch_normal_verify_extent(&page_id)) {
            GS_LOG_RUN_WAR("punch extent(%u-%u) is invailed, extent list first is %u-%u.",
                page_id.file, page_id.page, punch_exts->first.file, punch_exts->first.page);
            GS_LOG_RUN_WAR("punch residual extent is invailed, may cause %llu space leak.",
                (uint64)extent_size * (punch_exts->count - i) * DEFAULT_PAGE_SIZE(session));
            return;
        }
        next_page_id = spc_get_next_ext(session, page_id);
        // normal space do not punhc extent's first page, so we can get next extent after punch
        spc_punch_extent(session, page_id, extent_size);
        page_id = next_page_id;
    }
}

status_t spc_punch_bitmap_batch_extents(knl_session_t *session, df_map_page_t *map_page, spc_punch_info_t *punch_info,
    uint32 *bit, int64 *punch_size)
{
    datafile_t *df = DATAFILE_GET(session, map_page->first_page.file);
    uint8 *bitmap = map_page->bitmap;
    int32 i = (int32)*bit;
    int64 punch_pages = 0;
    status_t status = GS_SUCCESS;

    while (i >= 0) {
        if (DF_MAP_MATCH(bitmap, *bit)) {
            // to punch
            page_id_t extent = map_page->first_page;
            extent.page += *bit * df->map_head->bit_unit;
            spc_punch_extent(session, extent, df->map_head->bit_unit);
            *punch_size += df->map_head->bit_unit * DEFAULT_PAGE_SIZE(session);
            punch_info->do_punch_size -= DEFAULT_PAGE_SIZE(session) *  df->map_head->bit_unit;
            punch_pages += df->map_head->bit_unit;
        }

        (*bit)--;
        i--;

        if (punch_info->do_punch_size <= 0) {
            break;
        }

        if (punch_pages == SPACE_PUNCH_CKPT_INTERVAL) {
            break;
        }

        if (session->canceled) {
            GS_THROW_ERROR(ERR_OPERATION_CANCELED);
            status = GS_ERROR;
            break;
        }

        if (session->killed) {
            GS_THROW_ERROR(ERR_OPERATION_KILLED);
            status = GS_ERROR;
            break;
        }
    }

    return status;
}

bool32 spc_check_bitmap_enable_punch(knl_session_t *session, page_id_t map_pageid, uint32 *curr_hwm, datafile_t *df)
{
    buf_enter_page(session, map_pageid, LATCH_MODE_S, ENTER_PAGE_NORMAL);
    df_map_page_t *map_page = (df_map_page_t *)CURR_PAGE(session);

    if (map_page->first_page.page > *curr_hwm) {
        buf_leave_page(session, GS_FALSE);
        return GS_FALSE;
    }

    if (map_page->free_bits == 0) {
        *curr_hwm -= (DF_MAP_BIT_CNT(session) * df->map_head->bit_unit) + 1;
        buf_leave_page(session, GS_FALSE);
        return GS_FALSE;
    }
    buf_leave_page(session, GS_FALSE);
    return GS_TRUE;
}

bool32 spc_punch_bitmap_check_break(knl_session_t *session, spc_punch_info_t *punch_info, status_t *status)
{
    if (punch_info->do_punch_size <= 0) {
        return GS_TRUE;
    }

    if (session->canceled) {
        GS_THROW_ERROR(ERR_OPERATION_CANCELED);
        *status = GS_ERROR;
        return GS_TRUE;
    }

    if (session->killed) {
        GS_THROW_ERROR(ERR_OPERATION_KILLED);
        *status = GS_ERROR;
        return GS_TRUE;
    }

    return GS_FALSE;
}

static status_t spc_punch_bitmap_free_bits(knl_session_t *session, datafile_t *df, page_id_t map_pagid,
    uint32 *curr_hwm, spc_punch_info_t *punch_info)
{
    status_t status = GS_SUCCESS;
    int64 punch_size = 0;
    space_t *space = SPACE_GET(session, df->space_id);
    df_map_page_t *map_page = (df_map_page_t *)cm_push(session->stack, DEFAULT_PAGE_SIZE(session));
    knl_panic(map_page != NULL);
    int32 i = GS_INVALID_INT32;
    uint32 bit_uints = 0;
    uint32 bit = DF_MAP_BIT_CNT(session);

    for (;;) {
        if (!spc_try_lock_space(session, space, SPACE_DDL_WAIT_INTERVAL, "punch space failed")) {
            status = GS_ERROR;
            break;
        }

        buf_enter_page(session, map_pagid, LATCH_MODE_S, ENTER_PAGE_NORMAL);
        errno_t ret = memcpy_sp(map_page, DEFAULT_PAGE_SIZE(session), CURR_PAGE(session), DEFAULT_PAGE_SIZE(session));
        knl_securec_check(ret);
        buf_leave_page(session, GS_FALSE);

        if (i == GS_INVALID_INT32) {
            bit_uints = *curr_hwm - map_page->first_page.page;
            bit = (bit_uints / df->map_head->bit_unit) - 1;
            i = (int32)bit;
        }

        if (spc_punch_bitmap_batch_extents(session, map_page, punch_info, &bit, &punch_size) != GS_SUCCESS) {
            dls_spin_unlock(session, &space->lock);
            status = GS_ERROR;
            break;
        }

        dls_spin_unlock(session, &space->lock);
        // do inc ckpt when punching 4096 pages
        ckpt_trigger(session, GS_TRUE, CKPT_TRIGGER_INC);

        i = (int32)bit;

        if (i < 0) {
            break;
        }

        if (spc_punch_bitmap_check_break(session, punch_info, &status)) {
            break;
        }
    }

    *curr_hwm -= bit_uints + 1;
    punch_info->real_punch_size += punch_size;
    cm_pop(session->stack);
    GS_LOG_DEBUG_INF("[SPC] punch expected page count %llu in map page %d-%d", punch_size / DEFAULT_PAGE_SIZE(session),
        map_pagid.file, map_pagid.page);
    return status;
}

status_t spc_punch_fetch_bitmap_group(knl_session_t *session, space_t *space, datafile_t *df,
    uint32 hwm, spc_punch_info_t *punch_info)
{
    df_map_group_t *map_group = NULL;
    page_id_t curr_map;
    uint32 curr_hwm = hwm;

    for (int32 i = df->map_head->group_count - 1; i >= 0; i--) {
        map_group = &df->map_head->groups[i];
        curr_map = map_group->first_map;
        curr_map.page += (map_group->page_count - 1);

        for (int32 k = map_group->page_count; k > 0; k--) {
            if (punch_info->do_punch_size <= 0) {
                break;
            }

            if (!spc_try_lock_space_file(session, space, df)) {
                return GS_ERROR;
            }

            if (!spc_check_bitmap_enable_punch(session, curr_map, &curr_hwm, df)) {
                dls_spin_unlock(session, &space->lock);
                curr_map.page--;
                continue;
            }

            dls_spin_unlock(session, &space->lock);

            if (spc_punch_bitmap_free_bits(session, df, curr_map, &curr_hwm, punch_info) != GS_SUCCESS) {
                return GS_ERROR;
            }

            curr_map.page--;
        }
    }

    return GS_SUCCESS;
}

// if change this func, plz change func spc_punch_check_normalspc_invaild
status_t spc_punch_check_space_invaild(knl_session_t *session, space_t *space)
{
    if (SPACE_IS_DEFAULT(space)) {
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "punch tablespace", "default tablespace");
        return GS_ERROR;
    }

    if (SPACE_IS_ENCRYPT(space)) {
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "punch tablespace", "ENCRYPT tablespace");
        return GS_ERROR;
    }

    if (IS_UNDO_SPACE(space)) {
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "punch tablespace", "undo tablespace");
        return GS_ERROR;
    }

    if (IS_TEMP_SPACE(space)) {
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "punch tablespace", "temp tablespace");
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t spc_punch_precheck(knl_session_t *session, space_t *space)
{
    if (session->kernel->db.status != DB_STATUS_OPEN) {
        GS_THROW_ERROR(ERR_DATABASE_NOT_OPEN, "punch tablespace");
        return GS_ERROR;
    }

    if (!SPACE_IS_ONLINE(space)) {
        GS_THROW_ERROR(ERR_SPACE_OFFLINE, space->ctrl->name, "punch tablespace failed");
        return GS_ERROR;
    }

    return spc_punch_check_space_invaild(session, space) != GS_SUCCESS;
}

status_t spc_punch_space_bitmap(knl_session_t *session, space_t *space, spc_punch_info_t *punch_info)
{
    datafile_t *df = NULL;
    status_t status = GS_SUCCESS;

    if (!spc_try_lock_space(session, space, SPACE_DDL_WAIT_INTERVAL, "punch space failed")) {
        return GS_ERROR;
    }

    if (space->punching) {
        spc_unlock_space(session, space);
        GS_THROW_ERROR(ERR_OPERATIONS_NOT_ALLOW, "space %s is punching, parallel punching is not allowed",
            space->ctrl->name);
        return GS_ERROR;
    }

    space->punching = GS_TRUE;
    spc_unlock_space(session, space);

    for (uint32 i = 0; i < space->ctrl->file_hwm; i++) {
        if (space->ctrl->files[i] == GS_INVALID_ID32) {
            continue;
        }

        df = DATAFILE_GET(session, space->ctrl->files[i]);
        if (DATAFILE_IS_COMPRESS(df) || !DATAFILE_IS_ONLINE(df)) {
            continue;
        }

        if (spc_punch_fetch_bitmap_group(session, space, df, space->head->hwms[i], punch_info) != GS_SUCCESS) {
            status = GS_ERROR;
            break;
        }
    }

    if (!spc_try_lock_space(session, space, SPACE_DDL_WAIT_INTERVAL, "punch space failed")) {
        space->punching = GS_FALSE;
        return GS_ERROR;
    }

    space->punching = GS_FALSE;
    spc_unlock_space(session, space);
    return status;
}

// output is target_ext: new_head->first --> target_ext-->last
void spc_concat_page_to_pagelist(knl_session_t *session, page_id_t new_head, page_list_t *target_ext)
{
    if (target_ext->count == 0) {
        target_ext->count++;
        target_ext->first = new_head;
        target_ext->last = new_head;
    } else {
        knl_panic_log(!IS_INVALID_PAGID(target_ext->first),
            "punch the first of free_extents is invalid page, panic info: first page of extents %u-%u",
            target_ext->first.file, target_ext->first.page);
        knl_panic_log(!IS_INVALID_PAGID(target_ext->last),
            "punch the last of free_extents is invalid page, panic info: last page of extents %u-%u",
            target_ext->last.file, target_ext->last.page);
        spc_concat_extent(session, new_head, target_ext->first);
        target_ext->first = new_head;
        target_ext->count++;
    }
}

void spc_clean_punching_extents(knl_session_t *session, space_t *space)
{
    log_atomic_op_begin(session);
    buf_enter_page(session, space->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);
    spc_punch_head_t *punch_head = SPACE_PUNCH_HEAD_PTR(space);

    spc_init_page_list(&punch_head->punching_exts);
    log_put(session, RD_SPC_PUNCH_EXTENTS, &punch_head->punching_exts, sizeof(rd_punch_extents_t),
        LOG_ENTRY_FLAG_NONE);

    buf_leave_page(session, GS_TRUE);
    log_atomic_op_end(session);
    spc_print_punch_log(session, space, "clean punching extens");
}

void spc_punch_free_extent(knl_session_t *session, space_t *space)
{
    log_atomic_op_begin(session);
    buf_enter_page(session, space->entry, LATCH_MODE_X, ENTER_PAGE_RESIDENT);

    page_id_t ext = space->head->free_extents.first;

    space->head->free_extents.first = spc_get_next_ext(session, ext);
    space->head->free_extents.count--;
    if (space->head->free_extents.count == 0) {
        space->head->free_extents.first = INVALID_PAGID;
        space->head->free_extents.last = INVALID_PAGID;
    }

    // pick free extents first, reset punching, set new head to punched extent
    spc_punch_head_t *punch_head = SPACE_PUNCH_HEAD_PTR(space);
    page_list_t *punching = &(punch_head->punching_exts);
    knl_panic_log(punching->count <= 1, "punching extent count %u is large than 1, first(%u-%u) last(%u-%u)",
        punching->count, punching->first.file, punching->first.page, punching->last.file, punching->last.page);
    punching->count = 1;
    punching->first = ext;
    punching->last = ext;
    spc_concat_page_to_pagelist(session, ext, &punch_head->punched_exts);

    log_put(session, RD_SPC_FREE_EXTENT, &space->head->free_extents, sizeof(page_list_t), LOG_ENTRY_FLAG_NONE);
    log_put(session, RD_SPC_PUNCH_EXTENTS, &punch_head->punching_exts,
        sizeof(rd_punch_extents_t), LOG_ENTRY_FLAG_NONE);

    buf_leave_page(session, GS_TRUE);
    log_atomic_op_end(session);

    spc_print_punch_log(session, space, "punch free extent");
}

void spc_force_reset_punching_stat(knl_session_t *session, space_t *space, volatile bool8 *punching)
{
    if (cm_get_error_code() == ERR_SPACE_OFFLINE) {
        *punching = GS_FALSE;
        return;
    }

    dls_spin_lock(session, &space->lock, &session->stat->spin_stat.stat_space);
    *punching = GS_FALSE;
    dls_spin_unlock(session, &space->lock);
}

void spc_clean_residual_punching_extent(knl_session_t *session, space_t *space)
{
    spc_punch_head_t *punch_head = SPACE_PUNCH_HEAD_PTR(space);
    int64 punching_num = punch_head->punching_exts.count;
    if (SECUREC_LIKELY(punching_num == 0)) {
        return;
    }

    spc_punch_residual_extents(session, space->ctrl->extent_size, &punch_head->punching_exts);
    spc_clean_punching_extents(session, space);
    spc_print_punch_log(session, space, "free residual punching extens");
}

// punch part(one extent) one by one
status_t spc_punching_free_extents_part(knl_session_t *session, space_t *space, uint32 expect_exts, uint32 *real_exts)
{
    *real_exts = 0;
    page_id_t punch_ext;

    if (!spc_try_lock_space(session, space, SPACE_DDL_WAIT_INTERVAL, "punch space failed")) {
        return GS_ERROR;
    }

    if (SECUREC_UNLIKELY(spc_is_punching(session, space, "parallel punch"))) {
        spc_unlock_space(session, space);
        return GS_ERROR;
    }

    // extent size maybe 8192, ckpt_exts can not be 0, so + 1
    uint32 ckpt_exts = SPACE_PUNCH_CKPT_INTERVAL / space->ctrl->extent_size + 1;
    space->punching = GS_TRUE;
    spc_clean_residual_punching_extent(session, space);

    while (expect_exts > *real_exts) {
        if (SECUREC_UNLIKELY(!SPACE_IS_ONLINE(space))) {
            GS_THROW_ERROR(ERR_SPACE_OFFLINE, space->ctrl->name, "punch tablespace failed");
            space->punching = GS_FALSE;
            spc_unlock_space(session, space);
            return GS_ERROR;
        }

        if (space->head->free_extents.count == 0) {
            break;
        }

        punch_ext = space->head->free_extents.first;
        spc_punch_free_extent(session, space);
        spc_unlock_space(session, space);

        spc_punch_extent(session, punch_ext, space->ctrl->extent_size);
        (*real_exts)++;
        if ((*real_exts) % ckpt_exts == 0) {
            ckpt_trigger(session, GS_TRUE, CKPT_TRIGGER_INC);
        }

        if (!spc_try_lock_space(session, space, SPACE_DDL_WAIT_INTERVAL, "punch space failed")) {
            // reset space->punching inside
            spc_force_reset_punching_stat(session, space, &space->punching);
            return GS_ERROR;
        }
    }

    spc_clean_punching_extents(session, space);
    space->punching = GS_FALSE;
    spc_unlock_space(session, space);
    return GS_SUCCESS;
}

static inline status_t spc_punch_space_normal(knl_session_t *session, space_t *space, spc_punch_info_t *punch_info)
{
    uint32 expect_num = (uint32)(punch_info->do_punch_size / DEFAULT_PAGE_SIZE(session) / space->ctrl->extent_size);
    uint32 real_punch_exts;
    status_t status = spc_punching_free_extents_part(session, space, expect_num, &real_punch_exts);
    punch_info->real_punch_size = (int64)real_punch_exts * DEFAULT_PAGE_SIZE(session) * space->ctrl->extent_size;
    return status;
}

status_t spc_punch_space(knl_session_t *session, space_t *space, spc_punch_info_t *punch_info)
{
    if (!SPACE_IS_BITMAPMANAGED(space)) {
        return spc_punch_space_normal(session, space, punch_info);
    }

    return spc_punch_space_bitmap(session, space, punch_info);
}

status_t spc_punch_hole(knl_session_t *session, space_t *space, int64 punch_size)
{
    if (spc_punch_precheck(session, space) != GS_SUCCESS) {
        return GS_ERROR;
    }

    uint64 space_size = DEFAULT_PAGE_SIZE(session) * spc_count_pages_with_ext(session, space, GS_TRUE);
    spc_punch_info_t punch_info;
    if (punch_size == GS_INVALID_INT64) {
        punch_info.do_punch_size = space_size;
    } else {
        punch_info.do_punch_size = (space_size < punch_size) ? space_size : punch_size;
    }

    punch_info.real_punch_size = 0;
    status_t status = spc_punch_space(session, space, &punch_info);

    GS_LOG_RUN_INF("[SPC] punch space %s, expect size %lld, punched size %lld.", space->ctrl->name,
        punch_info.do_punch_size, punch_info.real_punch_size);
    return status;
}

#ifdef __cplusplus
}
#endif

