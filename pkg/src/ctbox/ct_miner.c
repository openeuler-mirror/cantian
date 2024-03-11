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
 * ct_miner.c
 *
 *
 * IDENTIFICATION
 * src/ctbox/ct_miner.c
 *
 * -------------------------------------------------------------------------
 */
#include <string.h>
#include "ct_tbox_module.h"
#include "ct_miner.h"
#include "ct_miner_desc.h"
#include "cm_file.h"
#include "cm_kmc.h"
#include "knl_recovery.h"
#include "rcr_btree.h"
#include "knl_undo.h"
#include "knl_buffer.h"
#include "knl_lob.h"
#include "pcr_heap.h"
#include "knl_database.h"
#include "ct_tbox.h"
#include "ct_tbox_audit.h"
#include "knl_ctrl_restore.h"
#include "dtc_database.h"
#include "cm_dbstore.h"
#ifdef WIN32
#define cm_strdup _strdup
#else
#define cm_strdup strdup
#endif

#define MINER_BUFFER_SIZE    (uint32)(1024)
#define MINER_BAK_FILE_TYPE         ".bak"
#define MINER_BAK_FILE_TYPE_LEN     strlen(MINER_BAK_FILE_TYPE)
#define MINER_BACKUP_SET            "backupset"
const text_t g_date_fmt = { "YYYY-MM-DD HH24:MI:SS", 21 };

int32 g_gm_optopt;
int32 g_gm_optind = 1;
char *g_gm_optarg = NULL;
static uint64 g_curr_batch_lsn; // max lsn of log groups inside current batch
static uint64 g_batch_lfn;
static const char g_zero_page[CT_LARGE_PAGE_SIZE];

log_desc_t *g_log_desc = NULL;

typedef struct st_miner_page {
    page_type_t type;
    const char *name;
} miner_page_t;

typedef struct st_miner_input_def {
    uint32 page_size;
    page_type_t type;
    bool32 is_lfn;
    bool32 is_version;
    bool32 modify_version;
    bool32 is_backup;
    bool32 is_backupset;
    bool32 is_checksum;
    bool32 is_force;
    bool32 is_decompress;
    uint64 start;
    uint32 count;
    char *logfile;
    char *datafile;
    char *ctrlfile;
    char *inputfile;
    char input_name[CT_FILE_NAME_BUFFER_SIZE];
    char *logfiles[CT_REDO_LOG_NUM];
    bool32 has_xid;
    xid_t xids[CT_XID_NUM];
    uint8 xid_cnt;
    uint8 log_cnt;
    char *keya;
    char *keyb;
    uint32 part_num; // part num of dbstor
    uint32 serial_num; // serial number of current file for dbstor
    bool32 use_dbstor;
} miner_input_def_t;

typedef struct st_miner_log_file_def {
    char *filedir;
    char *buf;
    int32 handle;
    uint32 asn;
    log_file_head_t head;
} miner_log_file_t;

static miner_page_t g_miner_page[] = {
    { PAGE_TYPE_FREE_PAGE,  "free" },
    { PAGE_TYPE_SPACE_HEAD, "space_head" },
    { PAGE_TYPE_HEAP_HEAD,  "heap_segment" },
    { PAGE_TYPE_HEAP_MAP,   "map" },
    { PAGE_TYPE_HEAP_DATA,  "heap" },
    { PAGE_TYPE_UNDO_HEAD,  "undo_segment" },
    { PAGE_TYPE_TXN,        "txn" },
    { PAGE_TYPE_UNDO,       "undo" },
    { PAGE_TYPE_BTREE_HEAD, "btree_segment" },
    { PAGE_TYPE_BTREE_NODE, "btree" },
    { PAGE_TYPE_LOB_HEAD,   "lob_segment" },
    { PAGE_TYPE_LOB_DATA,   "lob" },
};

#define NUM_PAGE_TYPE   (sizeof(g_miner_page) / sizeof(miner_page_t))
#define NULL_2_STR(ptr) (((ptr) != NULL && (*(char *)(ptr)) != '\0') ? (ptr) : "(null)")
static inline void filter_null(char *ptr)
{
    if (strcmp(ptr, "(null)") == 0) {
        *ptr = '\0';
    }
}

static status_t miner_log_init(void)
{
    log_manager_t *lmgr = NULL;
    uint32 i;
    uint32 count;

    g_log_desc = (log_desc_t *)malloc(sizeof(log_desc_t) * RD_TYPE_END);
    if (g_log_desc == NULL) {
        CT_THROW_ERROR (ERR_ALLOC_MEMORY, (uint64)(sizeof(log_desc_t) * RD_TYPE_END), "miner log init");
        return CT_ERROR;
    }

    log_get_manager(&lmgr, &count);

    for (i = 0; i < count; i++) {
        g_log_desc[lmgr[i].type].name = lmgr[i].name;
        g_log_desc[lmgr[i].type].desc_proc = lmgr[i].desc_proc;
    }

    return CT_SUCCESS;
}

static status_t miner_read_file_head(int32 handle, log_file_head_t *head, int64 *offset)
{
    int size;

    if (cm_seek_file(handle, 0, SEEK_SET) != 0) {
        CT_THROW_ERROR(ERR_SEEK_FILE, 0, SEEK_SET, errno);
        return CT_ERROR;
    }

    if (cm_read_file(handle, head, sizeof(log_file_head_t), &size) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (size != sizeof(log_file_head_t)) {
        CT_THROW_ERROR(ERR_FILE_SIZE_MISMATCH, (int64)size, (uint64)sizeof(log_file_head_t));
        return CT_ERROR;
    }

    *offset = (int64)CM_CALC_ALIGN((uint32)size, (uint32)head->block_size);
    return CT_SUCCESS;
}

static bool32 miner_need_read_file(char *buf, uint32 *data_offset, int32 *data_size)
{
    log_batch_t *head = NULL;

    if ((uint32)*data_size - *data_offset < sizeof(log_batch_t)) {
        return CT_TRUE;
    }

    head = (log_batch_t *)(buf + *data_offset);

    if (head->size > (uint32)*data_size - *data_offset) {
        return CT_TRUE;
    }

    return CT_FALSE;
}

static status_t miner_verify_batch_checksum(log_batch_t *batch, bool32 is_checksum)
{
    uint16 org_cks = batch->checksum;
    uint32 cks;
    uint16 curr_cks;
    
    if (is_checksum && org_cks != CT_INVALID_CHECKSUM) {
        batch->checksum = CT_INVALID_CHECKSUM;
        cks = cm_get_checksum(batch, batch->size);
        curr_cks = REDUCE_CKS2UINT16(cks);
        batch->checksum = org_cks;
        if (org_cks != curr_cks) {
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

status_t miner_load_batch(int32 *handle, char *buf, int32 size, uint32 *data_offset, int32 *data_size,
                          int64 *file_offset, log_batch_t **batch_ptr, bool32 *file_finish)
{
    log_batch_t *batch = NULL;
    log_batch_tail_t *tail = NULL;

    if (miner_need_read_file(buf, data_offset, data_size)) {
        if (cm_seek_file(*handle, *file_offset, SEEK_SET) != *file_offset) {
            CT_THROW_ERROR(ERR_SEEK_FILE, *file_offset, SEEK_SET, errno);
            return CT_ERROR;
        }

        if (cm_read_file(*handle, buf, size, data_size) != CT_SUCCESS) {
            return CT_ERROR;
        }
        *data_offset = 0;
    }

    if (*data_size == 0) {
        *file_finish = CT_TRUE;
        return CT_SUCCESS;
    }

    if ((uint32)(*data_size) < sizeof(log_batch_t) + sizeof(log_batch_tail_t)) {
        CT_THROW_ERROR(ERR_FILE_SIZE_MISMATCH, (int64)(*data_size),
                       (uint64)(sizeof(log_batch_t) + sizeof(log_batch_tail_t)));
        return CT_ERROR;
    }

    batch = (log_batch_t *)(buf + *data_offset);
    if (batch->space_size < batch->size || (uint32)(*data_size) < batch->size) {
        CT_THROW_ERROR(ERR_INVALID_BATCH, "batch size");
        *file_finish = CT_TRUE;
        return CT_SUCCESS;
    }

    if (batch->head.magic_num != LOG_MAGIC_NUMBER) {
        CT_THROW_ERROR(ERR_INVALID_BATCH, "head");
        *file_finish = CT_TRUE;
        return CT_SUCCESS;
    }

    tail = (log_batch_tail_t *)(buf + *data_offset + batch->size - sizeof(log_batch_tail_t));
    if (tail->magic_num != LOG_MAGIC_NUMBER) {
        CT_THROW_ERROR(ERR_INVALID_BATCH, "tail");
        return CT_ERROR;
    }

    if (batch->head.point.lfn != tail->point.lfn) {
        CT_THROW_ERROR(ERR_INVALID_BATCH, "lfn");
        return CT_ERROR;
    }

    /* the max size of log buffer is 64M, the size of batch is less than 64M */
    *data_offset += batch->space_size;
    *file_offset += batch->space_size;
    *batch_ptr = batch;

    return CT_SUCCESS;
}

static log_group_t *miner_fetch_group(log_cursor_t *cursor)
{
    log_group_t *group;
    log_group_t *temp = NULL;
    uint32 i;
    uint32 id;

    id = 0;
    group = CURR_GROUP(cursor, 0);

    for (i = 1; i < cursor->part_count; i++) {
        if (group == NULL) {
            group = CURR_GROUP(cursor, i);
            id = i;
            continue;
        }

        temp = CURR_GROUP(cursor, i);
        if (temp == NULL) {
            continue;
        }

        if (group->lsn > temp->lsn) {
            group = temp;
            id = i;
        }
    }

    if (group == NULL) {
        return NULL;
    }

    /* the max size of log buffer is 64M, the size of batch is less than 64M */
    cursor->offsets[id] += LOG_GROUP_ACTUAL_SIZE(group);

    return group;
}

static void miner_verify_loghead_checksum(log_file_head_t *head, bool32 is_checksum)
{
    uint32 org_cks = head->checksum;
    uint32 curr_cks;

    if (is_checksum && org_cks != CT_INVALID_CHECKSUM) {
        head->checksum = CT_INVALID_CHECKSUM;
        curr_cks = cm_get_checksum(head, sizeof(log_file_head_t));
        head->checksum = org_cks;
        printf("log file head verify checksum: %s\n", (org_cks == curr_cks) ? "success" : "corrupted");
    }
}

static status_t batch_decrypt(log_batch_t *batch)
{
    if (batch->encrypted) {
        char *plain_buf = (char *)malloc(batch->space_size);
        if (plain_buf == NULL) {
            CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)batch->space_size, "miner batch decrypt");
            return CT_ERROR;
        }
        uint32 plain_size = batch->space_size;

        if (log_decrypt(NULL, batch, plain_buf, plain_size) != CT_SUCCESS) {
            CT_THROW_ERROR(ERR_INVALID_BATCH, "decrypt batch");
            CM_FREE_PTR(plain_buf);
            return CT_ERROR;
        }
        CM_FREE_PTR(plain_buf);
    }
    return CT_SUCCESS;
}

static void fetch_part(log_batch_t *batch, log_cursor_t *cursor)
{
    char *ptr = NULL;
    cursor->part_count = batch->part_count;
    ptr = (char *)batch + sizeof(log_batch_t);
    for (uint32 i = 0; i < batch->part_count; i++) {
        cursor->parts[i] = (log_part_t *)ptr;
        cursor->offsets[i] = sizeof(log_part_t);
        ptr += cursor->parts[i]->size + sizeof(log_part_t);
    }
}

static bool32 fetch_group(log_cursor_t *cursor, bool32 is_lfn, uint64 start, uint32 count, uint32 *group_count)
{
    bool32 fetch_group_count_is_over = CT_FALSE;
    log_group_t *group = miner_fetch_group(cursor);
    while (group != NULL) {
        if (!is_lfn && start != CT_INVALID_ID64 && group->lsn < start) {
            group = miner_fetch_group(cursor);
            continue;
        }

        miner_desc_group(group);
        (*group_count)++;

        if (!is_lfn && count != CT_INVALID_ID32 && *group_count >= count) {
            fetch_group_count_is_over = CT_TRUE;
        }
        group = miner_fetch_group(cursor);
    }
    return fetch_group_count_is_over;
}

static status_t miner_load_batch_dbstor(char *buf, uint32 *data_offset, int32 data_size, int64 *file_offset,
    log_batch_t **batch_ptr, bool32 *file_start, bool32 *file_finish)
{
    CT_RETURN_IFERR(dbs_tool_global_handle()->get_curr_log_offset(buf, (uint32_t)data_size, (uint32_t *)file_offset,
        (uint32_t *)data_offset, (uint64_t *)&g_curr_batch_lsn));
    if (*file_offset == 0) {
        *file_finish = CT_TRUE;
    }
    if (*file_finish) {
        if (*file_start) {
            printf("\tend batch lsn: %llu\n", g_curr_batch_lsn);
        }
        return CT_SUCCESS;
    }
    if (!*file_start) {
        printf("\tstart batch lsn: %llu\n", g_curr_batch_lsn);
        *file_start = CT_TRUE;
    }
    *batch_ptr = (log_batch_t *)(buf + *data_offset);

    return CT_SUCCESS;
}

static void miner_verify_log_batch(char *buf, log_batch_t *batch, bool32 is_checksum, uint32 *data_offset,
    int32 *data_size)
{
    if (!is_checksum) {
        return;
    }
    bool32 had_error = CT_FALSE;

    if (miner_verify_batch_checksum(batch, is_checksum) != CT_SUCCESS) {
        had_error = CT_TRUE;
        printf("\tERROR REASON: log batch checksum failed");
    }

    if (batch->space_size < batch->size) {
        had_error = CT_TRUE;
        printf("\tERROR REASON: invalid batch size");
    }

    if (batch->head.magic_num != LOG_MAGIC_NUMBER) {
        had_error = CT_TRUE;
        printf("\tERROR REASON: invalid head magic");
    }
    if (*data_offset + batch->size <= *data_size) {
        log_batch_tail_t *tail = (log_batch_tail_t *)(buf + *data_offset + batch->size - sizeof(log_batch_tail_t));
        if (tail->magic_num != LOG_MAGIC_NUMBER) {
            had_error = CT_TRUE;
            printf("\tERROR REASON: invalid tail magic");
        }

        if (batch->head.point.lfn != tail->point.lfn) {
            had_error = CT_TRUE;
            printf("\tERROR REASON: head doesn't match with tail");
        }
    } else {
        had_error = CT_TRUE;
        printf("\tERROR REASON: invalid batch size");
    }

    if (g_batch_lfn != 0 && g_batch_lfn + 1 != batch->head.point.lfn) {
        had_error = CT_TRUE;
        printf("\tERROR REASON: misplace error");
    }

    if (had_error) {
        g_batch_lfn = 0;
        printf("\tERROR OFFSET:%u, \t ERROR LSN:%llu\n", *data_offset, g_curr_batch_lsn);
    } else {
        g_batch_lfn = batch->head.point.lfn;
    }
}

static status_t fetch_batch(char *buf, int32 *handle, int64 *file_offset, uint64 start, uint32 count, bool32 is_lfn,
    bool32 is_checksum, bool32 use_dbstor)
{
    bool32 file_finish;
    bool32 file_start = CT_FALSE;
    log_batch_t *batch = NULL;
    uint32 data_offset = 0;
    int32 data_size = 0;
    log_cursor_t cursor;
    uint32 group_count = 0;
    uint32 batch_count = 0;
    if (use_dbstor) {
        if (cm_read_file(*handle, buf, (int32)CT_MAX_LOG_BUFFER_SIZE, &data_size) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
    for (;;) {
        file_finish = CT_FALSE;
        if (!use_dbstor) {
            CT_RETURN_IFERR(miner_load_batch(handle, buf, (int32)CT_MAX_LOG_BUFFER_SIZE, &data_offset,
                &data_size, file_offset, &batch, &file_finish));
        } else {
            CT_RETURN_IFERR(
                miner_load_batch_dbstor(buf, &data_offset, data_size, file_offset, &batch, &file_start, &file_finish));
        }
        if (file_finish) {
            printf("\tcurrent file finished\n");
            break;
        }

        miner_verify_log_batch(buf, batch, is_checksum, &data_offset, &data_size);

        if (is_lfn && start != CT_INVALID_ID64 && batch->head.point.lfn < start) {
            continue;
        }
        if (!is_checksum) {
            printf("\nbatch: %llu size: %u space_size: %u ", (uint64)batch->head.point.lfn, batch->size, batch->space_size);
            printf("scn: %llu parts: %u checksum: %u\n", batch->scn, batch->part_count, batch->checksum);
            printf("block_id: %u\n", batch->head.point.block_id);

            CT_RETURN_IFERR(batch_decrypt(batch));

            fetch_part(batch, &cursor);

            if (fetch_group(&cursor, is_lfn, start, count, &group_count) == CT_TRUE) {
                break;
            }
        }
        batch_count++;

        if (is_lfn && count != CT_INVALID_ID32 && batch_count >= count) {
            break;
        }
    }
    return CT_SUCCESS;
}

static status_t miner_decompress_logfile(const char *logpath, uint64 start, uint32 count,
    bool32 is_lfn, bool32 is_checksum)
{
    int32 handle = CT_INVALID_HANDLE;
    int32 data_size;
    log_file_head_t head;

    if (cm_open_file(logpath, O_RDONLY | O_BINARY, &handle) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (cm_read_file(handle, &head, sizeof(log_file_head_t), &data_size) != CT_SUCCESS) {
        cm_close_file(handle);
        return CT_ERROR;
    }
    if (data_size != sizeof(log_file_head_t)) {
        cm_close_file(handle);
        return CT_ERROR;
    }

    printf("file head: first_scn %llu last_scn %llu write_pos %llu asn %u reset_id %u cmp_algorithm %d checksum %u\n",
        head.first, head.last, head.write_pos, head.asn, head.rst_id, head.cmp_algorithm, head.checksum);

    cm_close_file(handle);
    return CT_SUCCESS;
}

static status_t miner_parse_logfile(const char *logpath, uint64 start, uint32 count, bool32 is_lfn, bool32 is_checksum,
    bool32 use_dbstor)
{
    int32 handle;
    log_file_head_t head;
    int64 file_offset = 0;

    if (miner_log_init() != CT_SUCCESS) {
        return CT_ERROR;
    }

    char *buf = (char *)malloc(CT_MAX_LOG_BUFFER_SIZE);
    if (buf == NULL) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)CT_MAX_LOG_BUFFER_SIZE, "miner parse logfile");
        return CT_ERROR;
    }

    errno_t rc_memzero = memset_s(buf, CT_MAX_LOG_BUFFER_SIZE, 0, CT_MAX_LOG_BUFFER_SIZE);
    if (rc_memzero != EOK) {
        CM_FREE_PTR(buf);
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)CT_MAX_LOG_BUFFER_SIZE, "miner parse logfile");
        return CT_ERROR;
    }
    if (cm_open_file(logpath, O_RDONLY | O_BINARY, &handle) != CT_SUCCESS) {
        CM_FREE_PTR(buf);
        return CT_ERROR;
    }

    if (!use_dbstor && miner_read_file_head(handle, &head, &file_offset) != CT_SUCCESS) {
        cm_close_file(handle);
        CM_FREE_PTR(buf);
        return CT_ERROR;
    }
    if (!use_dbstor && !is_checksum) {
        printf(
            "file head: first_scn %llu last_scn %llu write_pos %llu asn %u reset_id %u dbid %u "
            "cmp_algorithm %d checksum %u\n",
            head.first, head.last, head.write_pos, head.asn, head.rst_id, head.dbid,
            head.cmp_algorithm, head.checksum);
    }
    if (!use_dbstor) {
        miner_verify_loghead_checksum(&head, is_checksum);
    }
    status_t ret = fetch_batch(buf, &handle, &file_offset, start, count, is_lfn, is_checksum, use_dbstor);

    cm_close_file(handle);
    CM_FREE_PTR(buf);
    return ret;
}

status_t miner_read_page(int32 handle, char *buf, int64 offset, uint32 page_size)
{
    int size;

    if (cm_seek_file(handle, offset, SEEK_SET) != offset) {
        CT_THROW_ERROR(ERR_SEEK_FILE, offset, SEEK_SET, errno);
        return CT_ERROR;
    }

    if (cm_read_file(handle, buf, page_size, &size) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if ((uint32)size == 0) {
        printf("\n\tcurrent file finished\n");
        return CT_ERROR;
    }

    if ((uint32)size < page_size) {
        printf("\tERROR REASON: invalid page size, ERROR OFFSET:%lld", offset);
        printf("\n\tcurrent file finished\n");
        CT_THROW_ERROR(ERR_FILE_SIZE_MISMATCH, (uint64)size, (uint64)page_size);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}
static void miner_verify_datafile(page_head_t *head, miner_input_def_t *input, int64 i)
{
    bool32 had_error = CT_FALSE;
    if (input->page_size != PAGE_SIZE(*head)) {
        had_error = CT_TRUE;
        printf("\tERROR REASON: invalid page size");
    }
    page_tail_t *tail = (page_tail_t *)((char *)head + input->page_size - sizeof(page_tail_t));
    if (tail->checksum != CT_INVALID_CHECKSUM && page_verify_checksum(head, input->page_size) == CT_FALSE) {
        had_error = CT_TRUE;
        printf("\tERROR REASON: checksum error");
    }
    if (head->pcn != tail->pcn) {
        had_error = CT_TRUE;
        printf("\tERROR REASON: head doesn't match with tail");
    }
    if (input->use_dbstor) {
        uint32 page_id = (uint32)dbs_tool_global_handle()->get_correct_page_id((uint32_t)input->part_num,
            (uint32_t)input->serial_num, (uint32_t)input->page_size, (uint64_t)i * input->page_size);
        if (AS_PAGID(head->id).page != page_id) {
            had_error = CT_TRUE;
            printf("\tERROR REASON: misplace error");
        }
    }
    if (had_error) {
        printf("\tERROR OFFSET:%lld\n", i * input->page_size);
    }
    return;
}

static status_t miner_parse_datafile(miner_input_def_t *input)
{
    char *buf = NULL;
    page_head_t *head = NULL;
    int32 handle;
    uint32 hack_count = 0;
    int64 i;

    if (cm_open_file(input->datafile, O_RDONLY | O_BINARY, &handle) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (input->page_size == 0) {
        cm_close_file(handle);
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)input->page_size, "data page");
        return CT_ERROR;
    }

    buf = (char *)malloc(input->page_size);
    if (buf == NULL) {
        cm_close_file(handle);
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)input->page_size, "miner parse datafile");
        return CT_ERROR;
    }

    i = (input->start != CT_INVALID_ID64) ? (int64)input->start : 0;

    while (miner_read_page(handle, buf, i * input->page_size, input->page_size) == CT_SUCCESS) {
        if (memcmp(buf, g_zero_page, input->page_size) == 0) {
            i++;
            continue;
        }
        head = (page_head_t *)buf;
        if (input->is_checksum) {
            miner_verify_datafile(head, input, i);
        } else if (input->type == PAGE_TYPE_END || input->type == (page_type_t)head->type) {
            miner_desc_page((uint32)i, buf, input->page_size, input->is_checksum, input->is_force);
            hack_count++;
        }

        if (input->count != CT_INVALID_ID32 && hack_count >= input->count) {
            break;
        }

        i++;
    }

    cm_close_file(handle);
    CM_FREE_PTR(buf);
    return CT_SUCCESS;
}

void miner_calc_ctrlfile_checksum(database_ctrl_t *ctrl)
{
    uint32 i;
    ctrl_page_t *pages = ctrl->pages;
    uint32 max_pages = ctrl->core.clustered ? CTRL_MAX_PAGES_CLUSTERED : CTRL_MAX_PAGES_NONCLUSTERED;

    for (i = 1; i < max_pages; i++) {
        page_calc_checksum((page_head_t *)&pages[i], CT_DFLT_CTRL_BLOCK_SIZE);
    }
}

status_t miner_verify_ctrlfile(database_ctrl_t *ctrl, bool32 is_checksum)
{
    uint32 i;
    uint32 max_pages = ctrl->core.clustered ? CTRL_MAX_PAGES_CLUSTERED : CTRL_MAX_PAGES_NONCLUSTERED;
    ctrl_page_t *pages = ctrl->pages;
    if (!is_checksum) {
        return CT_SUCCESS;
    }
    for (i = 0; i < max_pages; i++) {
        bool8 had_error = CT_FALSE;
        if (pages[i].head.pcn != pages[i].tail.pcn) {
            had_error = CT_TRUE;
            printf("\tERROR REASON: head doesn't match with tail");
        }
        if (pages[i].tail.checksum != CT_INVALID_CHECKSUM
            && !page_verify_checksum((page_head_t *)&pages[i], CT_DFLT_CTRL_BLOCK_SIZE)) {
            had_error = CT_TRUE;
            printf("\tERROR REASON: checksum failed");
        }
        if (had_error) {
            printf("\tERROR OFFSET:%u\n", i * CT_DFLT_CTRL_BLOCK_SIZE);
        }
    }

    return CT_SUCCESS;
}

void miner_init_ctrlfile(database_ctrl_t *ctrl)
{
    ctrl->core = *(core_ctrl_t *)&ctrl->pages[1].buf[0];
    uint32 inst_count = ctrl->core.clustered ? CT_MAX_INSTANCES : 1;
    uint32 offset = ctrl->core.clustered ? (CT_MAX_INSTANCES + CTRL_LOG_SEGMENT) : CTRL_LOG_SEGMENT + 1;
    uint32 count;

    ctrl->log_segment = offset;
    count = CTRL_MAX_BUF_SIZE / sizeof(log_file_ctrl_t);
    uint32 pages_per_inst = (CT_MAX_LOG_FILES - 1) / count + 1;
    offset = offset + pages_per_inst * inst_count;

    ctrl->space_segment = offset;
    count = CTRL_MAX_BUF_SIZE / sizeof(space_ctrl_t);
    pages_per_inst = (CT_MAX_SPACES - 1) / count + 1;
    offset = offset + pages_per_inst;

    ctrl->datafile_segment = offset;
    count = CTRL_MAX_BUF_SIZE / sizeof(datafile_ctrl_t);
    pages_per_inst = (CT_MAX_DATA_FILES - 1) / count + 1;
    offset = offset + pages_per_inst;

    ctrl->arch_segment = offset;
}

static status_t miner_parse_ctrlfile(const char *filepath, bool32 is_checksum)
{
    database_ctrl_t ctrl;
    int32 read_size;
    int32 handle;
    errno_t ret;
    uint32 size = CTRL_MAX_PAGES_CLUSTERED * CT_DFLT_CTRL_BLOCK_SIZE;

    if (cm_open_file(filepath, O_RDONLY | O_BINARY, &handle) != CT_SUCCESS) {
        return CT_ERROR;
    }

    ctrl.pages = (ctrl_page_t *)malloc(size);
    if (ctrl.pages == NULL) {
        cm_close_file(handle);
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)size, "miner parse ctrlfile");
        return CT_ERROR;
    }

    ret = memset_sp((char *)ctrl.pages, size, 0, size);
    if (ret != EOK) {
        CM_FREE_PTR(ctrl.pages);
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)CT_MAX_LOG_BUFFER_SIZE, "miner parse ctrlfile");
        cm_close_file(handle);
        return CT_ERROR;
    }

    if (cm_seek_file(handle, 0, SEEK_SET) != 0) {
        cm_close_file(handle);
        CM_FREE_PTR(ctrl.pages);
        CT_THROW_ERROR(ERR_SEEK_FILE, 0, SEEK_SET, errno);
        return CT_ERROR;
    }

    if (cm_read_file(handle, (void *)ctrl.pages, size, &read_size) != CT_SUCCESS) {
        cm_close_file(handle);
        CM_FREE_PTR(ctrl.pages);
        return CT_ERROR;
    }

    if (miner_verify_ctrlfile(&ctrl, is_checksum) != CT_SUCCESS) {
        cm_close_file(handle);
        CM_FREE_PTR(ctrl.pages);
        return CT_ERROR;
    }
    if (!is_checksum) {
        miner_init_ctrlfile(&ctrl);
        miner_desc_ctrlfile(&ctrl);
    } else {
        printf("\n\tcurrent file finished\n");
    }

    cm_close_file(handle);
    CM_FREE_PTR(ctrl.pages);
    return CT_SUCCESS;
}

status_t open_inputfile(char *inputfile, FILE **file)
{
    char *realpathRes = realpath(inputfile, NULL);
    if (realpathRes == NULL) {
        CT_THROW_ERROR(ERR_INVALID_FILE_NAME, inputfile, errno);
        return CT_ERROR; // 规范化的错误处理
    }
    *file = fopen(realpathRes, "rb+");
    free(realpathRes);
    realpathRes = NULL;
    if (*file == NULL) {
        CT_THROW_ERROR(ERR_OPEN_FILE, inputfile, errno);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t miner_parse_backup_info(const char *input_file, char **read_buf,
    uint32 buf_size, bak_head_t **bak_head)
{
    int32 read_size;
    int32 handle = CT_INVALID_HANDLE;

    if (cm_open_file(input_file, O_RDWR | O_BINARY | O_SYNC, &handle) != CT_SUCCESS) {
        return CT_ERROR;
    }

    *bak_head = (bak_head_t *)(*read_buf);

    if (cm_read_file(handle, *read_buf, buf_size, &read_size) != CT_SUCCESS) {
        cm_close_file(handle);
        *bak_head = NULL;
        return CT_ERROR;
    }

    if ((uint32)read_size < sizeof(bak_head_t)) {
        CT_THROW_ERROR(ERR_READ_DEVICE_INCOMPLETE, read_size, sizeof(bak_head_t));
        cm_close_file(handle);
        *bak_head = NULL;
        return CT_ERROR;
    }

    cm_close_file(handle);
    return CT_SUCCESS;
}

static status_t miner_parse_backup_head(const char *input_file)
{
    uint32 offset = 0;
    bak_head_t *bak_head = NULL;
    char *read_buf = (char *)malloc(CT_BACKUP_BUFFER_SIZE);

    if (read_buf == NULL) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)CT_BACKUP_BUFFER_SIZE, "cminer");
        return CT_ERROR;
    }

    if (miner_parse_backup_info(input_file, &read_buf, CT_BACKUP_BUFFER_SIZE, &bak_head) != CT_SUCCESS) {
        CM_FREE_PTR(read_buf);
        return CT_ERROR;
    }

    offset += sizeof(bak_head_t);

    miner_desc_backup_info(bak_head, read_buf, offset);
    CM_FREE_PTR(read_buf);
    return CT_SUCCESS;
}

static status_t miner_decompress_to_disk(int32 file, knl_compress_t *compress_ctx, char *read_buf, uint32 read_size,
                                         bool32 read_end, bak_t *bak)
{
    uint32 left_size = 0;
    uint32 left_offset;
    uint32 write_size;
    uint32 align_size = CT_DFLT_LOG_BLOCK_SIZE;
    errno_t ret;

    char *compress_buf = compress_ctx->compress_buf.aligned_buf;
    knl_compress_set_input(bak->record.attr.compress, compress_ctx, read_buf, read_size);

    for (;;) {
        if (knl_decompress(bak->record.attr.compress, compress_ctx, read_end, compress_buf + left_size,
            CT_BACKUP_BUFFER_SIZE - left_size) != CT_SUCCESS) {
            return CT_ERROR;
        }
        knl_panic(compress_ctx->write_len + left_size <= CT_BACKUP_BUFFER_SIZE);

        write_size = compress_ctx->write_len + left_size;

        left_size = write_size % align_size;
        left_offset = write_size - left_size;
        write_size -= left_size;

        if (cm_write_file(file, compress_buf, write_size) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (left_size > 0) {
            ret = memmove_s(compress_buf, CT_BACKUP_BUFFER_SIZE, compress_buf + left_offset, left_size);
            if (ret != EOK) {
                CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)CT_MAX_LOG_BUFFER_SIZE, "miner decompress to disk");
                return CT_ERROR;
            }
        }

        if (compress_ctx->finished) {
            break;
        }
    }
    return CT_SUCCESS;
}

status_t miner_decompress_parameters_init(const char *inputfile, const char *outputbase, char **read_buf, bak_t **bak, int32 *out_handle, int32 *in_handle)
{
    char head_path[CT_FILE_NAME_BUFFER_SIZE];
    text_t head_path_text;
    bak_head_t *bak_head = NULL;

    char output_file[CT_MAX_FILE_NAME_LEN] = { 0 };
    PRTS_PRINT_RETURN_IFERR(snprintf_s(output_file, CT_MAX_FILE_NAME_LEN, CT_MAX_FILE_NAME_LEN - 1,
        "%s%s", outputbase, MINER_BAK_FILE_TYPE));

    if (cm_file_exist(output_file)) {
        CT_THROW_ERROR(ERR_DATAFILE_ALREADY_EXIST, output_file);
        return CT_ERROR;
    }

    *read_buf = (char *)malloc(CT_BACKUP_BUFFER_SIZE + sizeof(bak_t));
    if (*read_buf == NULL) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)CT_BACKUP_BUFFER_SIZE + sizeof(bak_t), "cminer read buffer");
        return CT_ERROR;
    }

    cm_trim_filename(inputfile, CT_FILE_NAME_BUFFER_SIZE, head_path);
    if (strlen(inputfile) == strlen(head_path)) {
        head_path_text.str = MINER_BACKUP_SET;
        head_path_text.len = (uint32)strlen(MINER_BACKUP_SET);
    } else {
        head_path_text.str = head_path;
        head_path_text.len = (uint32)strlen(head_path);
        cm_concat_string(&head_path_text, CT_FILE_NAME_BUFFER_SIZE, MINER_BACKUP_SET);
        head_path_text.str[head_path_text.len] = '\0';
    }

    if (miner_parse_backup_info(head_path_text.str, read_buf,
        CT_BACKUP_BUFFER_SIZE + sizeof(bak_t), &bak_head) != CT_SUCCESS) {
        CM_FREE_PTR(*read_buf);
        return CT_ERROR;
    }
    *bak = (bak_t *)(*read_buf + CT_BACKUP_BUFFER_SIZE);
    (*bak)->record.attr.compress = bak_head->attr.compress;
    if ((*bak)->record.attr.compress == COMPRESS_NONE) {
        CT_THROW_ERROR(ERR_DECOMPRESS_ERROR, "miner", COMPRESS_NONE, "input file is uncompressed");
        CM_FREE_PTR(*read_buf);
        return CT_ERROR;
    }

    if (cm_open_file(inputfile, O_RDWR | O_BINARY | O_SYNC, in_handle) != CT_SUCCESS) {
        CM_FREE_PTR(*read_buf);
        return CT_ERROR;
    }

    if (cm_create_file(output_file, O_RDWR | O_BINARY | O_SYNC, out_handle) != CT_SUCCESS) {
        cm_close_file(*in_handle);
        CM_FREE_PTR(*read_buf);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

void close_decompress_resource(int32 in_handle, int32 out_handle, char *read_buf, knl_compress_t *compress_ctx)
{
    cm_close_file(in_handle);
    cm_close_file(out_handle);
    CM_FREE_PTR(read_buf);
    if (compress_ctx != NULL) {
        CM_FREE_PTR(compress_ctx->compress_buf.aligned_buf);
    }
}

static status_t miner_decompress_log_head(const char *inputfile, char *read_buf, int32 in_handle, int32 out_handle)
{
    int32 read_size;
    text_t path_text;
    path_text.str = (char *)inputfile;
    path_text.len = (uint32)strlen(inputfile);

    if (cm_text_str_contain_equal_ins(&path_text, "arch", (uint32)strlen("arch")) ||
        cm_text_str_contain_equal_ins(&path_text, "log", (uint32)strlen("log"))) {
        if (cm_read_file(in_handle, read_buf, sizeof(log_file_head_t), &read_size) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (read_size < sizeof(log_file_head_t)) {
            printf("failed to read log file head, read size %d less than %u", read_size,
                (uint32)sizeof(log_file_head_t));
            return CT_ERROR;
        }

        log_file_head_t head = *(log_file_head_t *)read_buf;
        uint32 fill_size = CM_CALC_ALIGN(sizeof(log_file_head_t), (uint32)head.block_size) - sizeof(log_file_head_t);
        if (cm_read_file(in_handle, read_buf + sizeof(log_file_head_t), fill_size, &read_size) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (read_size != fill_size) {
            printf("failed to read log file head, read size %d less than %u", read_size, fill_size);
            return CT_ERROR;
        }

        if (cm_write_file(out_handle, read_buf, head.block_size) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static status_t miner_decompress_bakfile(const char *inputfile, const char *outputfile)
{
    int32 out_handle = CT_INVALID_HANDLE;
    int32 in_handle = CT_INVALID_HANDLE;
    int32 read_size;
    bool32 read_end = CT_FALSE;
    knl_compress_t compress_ctx;
    bak_t *bak = NULL;
    char *read_buf = NULL;

    if (outputfile == NULL) {
        return CT_ERROR;
    }

    if (miner_decompress_parameters_init(inputfile, outputfile, &read_buf, &bak, &out_handle, &in_handle) == CT_ERROR) {
        return CT_ERROR;
    }

    if (miner_decompress_log_head(inputfile, read_buf, in_handle, out_handle) != CT_SUCCESS) {
        close_decompress_resource(in_handle, out_handle, read_buf, NULL);
        return CT_ERROR;
    }

    compress_ctx.compress_buf.aligned_buf = (char *)malloc(CT_BACKUP_BUFFER_SIZE);
    if (compress_ctx.compress_buf.aligned_buf == NULL) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)CT_BACKUP_BUFFER_SIZE, "cminer uncomperss buffer");
        close_decompress_resource(in_handle, out_handle, read_buf, NULL);
        return CT_ERROR;
    }

    status_t status = knl_compress_alloc(bak->record.attr.compress, &compress_ctx, CT_FALSE);
    if (status == CT_ERROR) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, "cminer uncomperss alloc error");
        close_decompress_resource(in_handle, out_handle, read_buf, &compress_ctx);
        return CT_ERROR;
    }

    status = knl_compress_init(bak->record.attr.compress, &compress_ctx, CT_FALSE);

    while (!read_end && status == CT_SUCCESS) {
        if (cm_read_file(in_handle, read_buf, CT_BACKUP_BUFFER_SIZE, &read_size) != CT_SUCCESS) {
            status = CT_ERROR;
            break;
        }

        read_end = (bool32)((uint32)read_size < CT_BACKUP_BUFFER_SIZE);
        if (miner_decompress_to_disk(out_handle, &compress_ctx, read_buf, (uint32)read_size, read_end, bak) !=
            CT_SUCCESS) {
            status = CT_ERROR;
            break;
        }
    }

    knl_compress_end(bak->record.attr.compress, &compress_ctx, CT_FALSE);
    knl_compress_free(bak->record.attr.compress, &compress_ctx, CT_FALSE);
    close_decompress_resource(in_handle, out_handle, read_buf, &compress_ctx);
    return status;
}

static status_t miner_update_version(const char *filepath)
{
    ctrl_version_t ctrl_version;
    int32 handle;
    uint32 size = sizeof(ctrl_version_t);
    uint32 offset = CT_DFLT_CTRL_BLOCK_SIZE + sizeof(page_head_t);

    ctrl_version.main = CORE_VERSION_MAIN;
    ctrl_version.major = CORE_VERSION_MAJOR;
    ctrl_version.revision = CORE_VERSION_REVISION;
    ctrl_version.inner = CORE_VERSION_INNER;

    if (cm_open_file(filepath, O_RDWR | O_BINARY | O_SYNC, &handle) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (cm_seek_file(handle, (int64)offset, SEEK_SET) != offset) {
        cm_close_file(handle);
        CT_THROW_ERROR(ERR_SEEK_FILE, offset, SEEK_SET, errno);
        return CT_ERROR;
    }

    if (cm_write_file(handle, &ctrl_version, size) != CT_SUCCESS) {
        cm_close_file(handle);
        return CT_ERROR;
    }

    cm_close_file(handle);
    return CT_SUCCESS;
}

static void miner_show_version(database_ctrl_t *ctrl)
{
    printf("version:    %hu.%hu.%hu.%hu", ctrl->core.version.main, ctrl->core.version.major,
           ctrl->core.version.revision, ctrl->core.version.inner);
}

static status_t miner_ctrlfile_version(const char *filepath)
{
    database_ctrl_t ctrl;
    int32 read_size;
    int32 handle;
    uint32 size = CTRL_MAX_PAGES_CLUSTERED * CT_DFLT_CTRL_BLOCK_SIZE;

    if (cm_open_file(filepath, O_RDONLY | O_BINARY, &handle) != CT_SUCCESS) {
        return CT_ERROR;
    }

    ctrl.pages = (ctrl_page_t *)malloc(size);
    if (ctrl.pages == NULL) {
        cm_close_file(handle);
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)size, "page");
        return CT_ERROR;
    }

    if (cm_seek_file(handle, 0, SEEK_SET) != 0) {
        cm_close_file(handle);
        CM_FREE_PTR(ctrl.pages);
        CT_THROW_ERROR(ERR_SEEK_FILE, 0, SEEK_SET, errno);
        return CT_ERROR;
    }

    if (cm_read_file(handle, (void *)ctrl.pages, size, &read_size) != CT_SUCCESS) {
        cm_close_file(handle);
        CM_FREE_PTR(ctrl.pages);
        return CT_ERROR;
    }

    miner_init_ctrlfile(&ctrl);

    if (miner_verify_ctrlfile(&ctrl, CT_FALSE) != CT_SUCCESS) {
        cm_close_file(handle);
        CM_FREE_PTR(ctrl.pages);
        return CT_ERROR;
    }

    miner_show_version(&ctrl);

    cm_close_file(handle);
    CM_FREE_PTR(ctrl.pages);
    return CT_SUCCESS;
}

static void usage(void)
{
    printf("cminer is an analysis tool for cantian.\n"
           "\n"
           "Usage:\n"
           "  cminer [OPTIONS]\n"
           "\nRequired options:\n"
           "  -c CTRLFILE    the database ctrlfile to parse or generate\n"
           "  -l LOGFILE     the database logfile to parse\n"
           "  -f DATAFILE    the database datafile to parse\n"
           "  -z BACKUPFILE  the backup file to parse or decompress\n");

    printf("\nOptional options:\n"
           "  -s set the start point to parse\n"
           "  -n set the number to parse\n"
           "  -b parse logfile on batch level(default, group level)\n"
           "  -t only show specified page type when parsing datafile\n"
           "  -p set page size of datafile to parse(default, 8192)\n"
           "  -C verify checksum when parse file or calc checksum when generate ctrlfile \n"
           "  -A first kmc key file \n"
           "  -B second kmc key file \n"
           "  -F force analysis file when the version is inconsistent\n"
           "  -d decompress logfile\n"
           "  -D use dbstor\n"
           "  -P part num of dbstor\n"
           "  -S serial number of current file for dbstor\n"
           "\nCommon options:\n"
           "  --help, -h       show this help, then exit\n"
           "  --version, -V    output version information, then exit\n");
}

static status_t miner_init_input(miner_input_def_t *input)
{
    errno_t ret;
    input->page_size = MINER_DEF_PAGE_SIZE;
    input->type = PAGE_TYPE_END;
    input->is_lfn = CT_FALSE;
    input->is_version = CT_FALSE;
    input->modify_version = CT_FALSE;
    input->is_backup = CT_FALSE;
    input->is_backupset = CT_FALSE;
    input->is_checksum = CT_FALSE;
    input->is_force = CT_FALSE;
    input->start = CT_INVALID_ID64;
    input->count = CT_INVALID_ID32;
    input->logfile = NULL;
    input->datafile = NULL;
    input->ctrlfile = NULL;
    input->inputfile = NULL;
    input->has_xid = CT_FALSE;
    input->is_decompress = CT_FALSE;
    input->log_cnt = 0;
    input->xid_cnt = 0;
    input->keya = NULL;
    input->keyb = NULL;
    input->part_num = 0;
    input->serial_num = 0;
    input->use_dbstor = CT_FALSE;
    for (uint8 i = 0; i < CT_REDO_LOG_NUM; i++) {
        input->logfiles[i] = NULL;
    }
    ret = memset_s(input->input_name, CT_FILE_NAME_BUFFER_SIZE, 0, CT_FILE_NAME_BUFFER_SIZE);
    if (ret != EOK) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t miner_validate_opt(int nargc, char *nargv[], char **place_str)
{
    char place_c;
    if (!**place_str) {
        if (g_gm_optind >= nargc || *(nargv[g_gm_optind]) != '-') {
            *place_str = "";
            return CT_ERROR;
        }

        *place_str = nargv[g_gm_optind];
        place_c = (*place_str)[1];
        ++(*place_str);

        if (place_c && (**place_str) == '-' && (*place_str)[1] == '\0') {
            ++g_gm_optind;
            *place_str = "";
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

int32 miner_opt_parse(int nargc, char *nargv[], char **place_str, const char *ostr)
{
#ifdef WIN32
    const char *oc = NULL;
#else
    char *oc = NULL;
#endif

    if (g_gm_optopt != (int32)':') {
        oc = strchr(ostr, g_gm_optopt);
    }

    if (g_gm_optopt == (int32)':' || oc == NULL) {
        if (g_gm_optopt == (int32)'-') {
            *place_str = "";
            return -1;
        }

        if (!(**place_str)) {
            ++g_gm_optind;
        }

        if (*ostr != ':') {
            printf("illegal option -- %c\n", (char)g_gm_optopt);
        }
        return (int32)'?';
    }

    ++oc;

    if (*oc != ':') {
        g_gm_optarg = NULL;
        if (!(**place_str)) {
            ++g_gm_optind;
        }
    } else {
        if (**place_str) {
            g_gm_optarg = *place_str;
        } else if (nargc <= ++g_gm_optind) {
            *place_str = "";
            if (*ostr == ':') {
                return (int32)':';
            }

            printf("option requires an argument -- %c\n", (char)g_gm_optopt);
            return (int32)'?';
        } else {
            g_gm_optarg = nargv[g_gm_optind];
        }

        *place_str = "";
        ++g_gm_optind;
    }
    return 0;
}

int32 miner_getopt(int nargc, char *nargv[], const char *ostr)
{
    static char *place_str = "";

    CT_RETURN_IFERR(miner_validate_opt(nargc, nargv, &place_str));

    g_gm_optopt = (int32)*place_str;
    place_str++;

    int32 ret = miner_opt_parse(nargc, nargv, &place_str, ostr);
    if (ret != 0) {
        return ret;
    }

    return g_gm_optopt;
}

static bool32 miner_usage(int argc, char *argv[])
{
    if (argc > g_gm_optind) {
        if (strcmp(argv[g_gm_optind], "--help") == 0 || strcmp(argv[g_gm_optind], "-?") == 0 ||
            strcmp(argv[g_gm_optind], "-h") == 0) {
            usage();
            return CT_TRUE;
        }

        if (strcmp(argv[g_gm_optind], "--version") == 0 || strcmp(argv[g_gm_optind], "-V") == 0) {
            tbox_print_version();
            return CT_TRUE;
        }
    }
    return CT_FALSE;
}

static status_t miner_get_ctrlfile(miner_input_def_t *input)
{
    if (input->datafile != NULL || input->logfile != NULL) {
        printf("must specify a log or data or control file to parse\n");
        return CT_ERROR;
    }

    if (input->ctrlfile != NULL || g_gm_optarg == NULL) {
        printf("must specify a control file to parse\n");
        return CT_ERROR;
    }

    input->ctrlfile = (char *)cm_strdup(g_gm_optarg);
    if (input->ctrlfile == NULL) {
        printf("ctrlfile strdup failed.\n");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t miner_get_datafile(miner_input_def_t *input)
{
    if (input->logfile != NULL || input->ctrlfile != NULL) {
        printf("must specify a log or data or control file to parse\n");
        return CT_ERROR;
    }

    if (input->datafile != NULL || g_gm_optarg == NULL) {
        printf("must specify a data file to parse\n");
        return CT_ERROR;
    }

    input->datafile = (char *)cm_strdup(g_gm_optarg);
    if (input->datafile == NULL) {
        printf("datafile strdup failed.\n");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t miner_get_logfile(miner_input_def_t *input)
{
    if (input->datafile != NULL || input->ctrlfile != NULL) {
        printf("must specify a log or data or control file to parse\n");
        return CT_ERROR;
    }

    if (input->logfile != NULL || g_gm_optarg == NULL) {
        printf("must specify a log file to parse\n");
        return CT_ERROR;
    }

    input->logfile = (char *)cm_strdup(g_gm_optarg);
    if (input->logfile == NULL) {
        printf("logfile strdup failed.\n");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t split_log_names(char *src, const char *separator, char **dest, uint8 *num)
{
    char *pNext = NULL;
    char *next_token = NULL;
    uint8 count = 0;
    if (src == NULL || strlen(src) == 0) {
        return CT_ERROR;
    }
    if (separator == NULL || strlen(separator) == 0) {
        return CT_ERROR;
    }
    pNext = (char *)strtok_s(src, separator, &next_token);
    while (pNext != NULL) {
        *dest++ = pNext;
        ++count;
        pNext = (char *)strtok_s(NULL, separator, &next_token);
    }
    *num = count;
    return CT_SUCCESS;
}

static status_t miner_get_logfiles(miner_input_def_t *input)
{
    if (input->logfile == NULL) {
        printf("must specify a log file to parse\n");
        return CT_ERROR;
    }
    return split_log_names(input->logfile, ",", input->logfiles, &input->log_cnt);
}

static status_t miner_get_backup_file(miner_input_def_t *input)
{
    if (input->inputfile != NULL) {
        CM_FREE_PTR(input->inputfile);
    }

    if (g_gm_optarg == NULL) {
        printf("must specify a backup file\n");
        return CT_ERROR;
    }
    input->inputfile = (char *)cm_strdup(g_gm_optarg);
    input->is_backup = CT_TRUE;
    if (input->inputfile == NULL) {
        printf("failed to get file name of backup file");
        return CT_ERROR;
    }
    cm_trim_dir(input->inputfile, CT_FILE_NAME_BUFFER_SIZE, input->input_name);
    if (cm_str_equal(input->input_name, MINER_BACKUP_SET)) {
        input->is_backupset = CT_TRUE;
    }

    return CT_SUCCESS;
}

static status_t miner_get_page_type(miner_input_def_t *input)
{
    uint32 i;
    for (i = 0; i < NUM_PAGE_TYPE; i++) {
        if (g_gm_optarg == NULL) {
            printf("must specify a page type to parse\n");
            return CT_ERROR;
        }

        if (strcmp(g_gm_optarg, g_miner_page[i].name) == 0) {
            break;
        }
    }

    if (i == NUM_PAGE_TYPE) {
        printf("invalid page type (-t): %s\n", g_gm_optarg);
        return CT_ERROR;
    }
    input->type = g_miner_page[i].type;

    return CT_SUCCESS;
}

static status_t miner_get_xid(miner_input_def_t *input)
{
    if (g_gm_optarg == NULL) {
        printf("no xid specified\n");
        return CT_ERROR;
    }
    char *xid_str = (char *)cm_strdup(g_gm_optarg);
    char *xid_str_bak = xid_str;
    if (xid_str == NULL) {
        printf("xid_str strdup failed.\n");
        return CT_ERROR;
    }
    uint64 xid_number[CT_XID_NUM] = { 0 };
    int cnt = 0;
    while (*xid_str != '\0') {
        if (*xid_str == ',') {
            ++cnt;
        } else if (*xid_str >= '0' && *xid_str <= '9') {
            if (cnt >= CT_XID_NUM) {
                printf("input too many xid\n");
                CM_FREE_PTR(xid_str_bak);
                return CT_ERROR;
            }
            xid_number[cnt] = xid_number[cnt] * CARRY_FACTOR + (uint64)(*xid_str - '0');
        } else {
            printf("input wrong xid\n");
            CM_FREE_PTR(xid_str_bak);
            return CT_ERROR;
        }
        xid_str++;
    }
    input->xid_cnt = cnt + 1;
    for (uint8 i = 0; i <= cnt; i++) {
        input->xids[i].value = xid_number[i];
    }
    CM_FREE_PTR(xid_str_bak);
    return CT_SUCCESS;
}

typedef status_t(*miner_opt_func) (miner_input_def_t *input);

typedef struct func_opt_proc {
    int32 option;
    miner_opt_func opt_proc;
}func_opt_proc_t;


static void miner_free_input(miner_input_def_t *input)
{
    CM_FREE_PTR(input->logfile);
    CM_FREE_PTR(input->datafile);
    CM_FREE_PTR(input->inputfile);
    CM_FREE_PTR(input->ctrlfile);
    CM_FREE_PTR(input->keya);
    CM_FREE_PTR(input->keyb);
}

static inline status_t miner_opt_proc_of_P(miner_input_def_t *input)
{
    input->part_num = (uint32)atoi(g_gm_optarg);
    return CT_SUCCESS;
}

static inline status_t miner_opt_proc_of_S(miner_input_def_t *input)
{
    input->serial_num = (uint32)atoi(g_gm_optarg);
    return CT_SUCCESS;
}

static inline status_t miner_opt_proc_of_D(miner_input_def_t *input)
{
    input->use_dbstor = CT_TRUE;
    return CT_SUCCESS;
}

static inline status_t miner_opt_proc_of_v(miner_input_def_t *input)
{
    input->is_version = CT_TRUE;
    return CT_SUCCESS;
}

static inline status_t miner_opt_proc_of_u(miner_input_def_t *input)
{
    input->modify_version = CT_TRUE;
    return CT_SUCCESS;
}

static inline status_t miner_opt_proc_of_b(miner_input_def_t *input)
{
    input->is_lfn = CT_TRUE;
    return CT_SUCCESS;
}

static inline status_t miner_opt_proc_of_C(miner_input_def_t *input)
{
    input->is_checksum = CT_TRUE;
    return CT_SUCCESS;
}

static inline status_t miner_opt_proc_of_A(miner_input_def_t *input)
{
    input->keya = (char *)cm_strdup(g_gm_optarg);
    if (input->keya == NULL) {
        printf("input->keya strdup failed.\n");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static inline status_t miner_opt_proc_of_B(miner_input_def_t *input)
{
    input->keyb = (char *)cm_strdup(g_gm_optarg);
    if (input->keyb == NULL) {
        printf("input->keyb strdup failed.\n");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static inline status_t miner_opt_proc_of_c(miner_input_def_t *input)
{
    return miner_get_ctrlfile(input);
}

static inline status_t miner_opt_proc_of_f(miner_input_def_t *input)
{
    return miner_get_datafile(input);
}

static status_t miner_opt_proc_of_l(miner_input_def_t *input)
{
    if (miner_get_logfile(input) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (miner_get_logfiles(input) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (input->log_cnt > CT_REDO_LOG_NUM) {
        printf("input too many redo files");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static inline status_t miner_opt_proc_of_x(miner_input_def_t *input)
{
    if (miner_get_xid(input) == CT_SUCCESS) {
        input->has_xid = CT_TRUE;
    }
    return CT_SUCCESS;
}

static inline status_t miner_opt_proc_of_z(miner_input_def_t *input)
{
    return miner_get_backup_file(input);
}

static inline status_t miner_opt_proc_of_n(miner_input_def_t *input)
{
    input->count = (uint32)atoi(g_gm_optarg);
    return CT_SUCCESS;
}

static inline status_t miner_opt_proc_of_p(miner_input_def_t *input)
{
    input->page_size = (uint32)atoi(g_gm_optarg);
    return CT_SUCCESS;
}

static inline status_t miner_opt_proc_of_s(miner_input_def_t *input)
{
    input->start = (uint64)atoi(g_gm_optarg);
    return CT_SUCCESS;
}

static inline status_t miner_opt_proc_of_t(miner_input_def_t *input)
{
    return miner_get_page_type(input);
}

static inline status_t miner_opt_proc_of_F(miner_input_def_t *input)
{
    input->is_force = CT_TRUE;
    return CT_SUCCESS;
}

static inline status_t miner_opt_proc_of_d(miner_input_def_t *input)
{
    input->is_decompress = CT_TRUE;
    return CT_SUCCESS;
}

static inline status_t miner_opt_proc_of_default(miner_input_def_t *input)
{
    printf("try use \"--help\" for more information.\n");
    return CT_ERROR;
}

func_opt_proc_t g_miner_opts_procs[] = {
    { 'v', miner_opt_proc_of_v },
    { 'u', miner_opt_proc_of_u },
    { 'b', miner_opt_proc_of_b },
    { 'C', miner_opt_proc_of_C },
    { 'A', miner_opt_proc_of_A },
    { 'B', miner_opt_proc_of_B },
    { 'c', miner_opt_proc_of_c },
    { 'f', miner_opt_proc_of_f },
    { 'l', miner_opt_proc_of_l },
    { 'x', miner_opt_proc_of_x },
    { 'z', miner_opt_proc_of_z },
    { 'n', miner_opt_proc_of_n },
    { 'p', miner_opt_proc_of_p },
    { 's', miner_opt_proc_of_s },
    { 't', miner_opt_proc_of_t },
    { 'F', miner_opt_proc_of_F },
    { 'd', miner_opt_proc_of_d },
    { 'P', miner_opt_proc_of_P },
    { 'S', miner_opt_proc_of_S },
    { 'D', miner_opt_proc_of_D }
};

static miner_opt_func inline get_opt_proc_func(int32 opt)
{
    uint32 opt_proc_size = sizeof(g_miner_opts_procs) / sizeof(g_miner_opts_procs[0]);
    for (uint32 opt_proc_index = 0; opt_proc_index < opt_proc_size; opt_proc_index++) {
        if (g_miner_opts_procs[opt_proc_index].option == opt) {
            return g_miner_opts_procs[opt_proc_index].opt_proc;
        }
    }
    return miner_opt_proc_of_default;
}

static status_t miner_get_input(int argc, char *argv[], miner_input_def_t *input)
{
    int32 c;

    c = miner_getopt(argc, argv, "bvuCFdDc:f:l:z:n:p:s:t:A:B:x:P:S:");

    while (c != -1) {
        miner_opt_func opt_proc_func = get_opt_proc_func(c);
        CT_RETURN_IFERR(opt_proc_func(input));
        c = miner_getopt(argc, argv, "bvuCFdDc:f:l:z:n:p:s:t:A:B:x:P:S:");
    }

    // for kmc keys, need both null or both not null
    if (input->keya != NULL && input->keyb != NULL) {
        CT_RETURN_IFERR(cm_kmc_init(CT_SERVER, input->keya, input->keyb));
        CT_RETURN_IFERR(cm_kmc_init_domain(CT_KMC_KERNEL_DOMAIN));
        return CT_SUCCESS;
    }

    if (input->keya == NULL && input->keyb == NULL) {
        return CT_SUCCESS;
    }

    CT_THROW_ERROR(ERR_INVALID_PARAMETER, "-A or -B");
    return CT_ERROR;
}

status_t miner_verify_datafile_version(char *file_name, uint32 size)
{
    int32 handle;

    if (cm_open_file(file_name, O_RDONLY | O_BINARY, &handle) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (size == 0) {
        cm_close_file(handle);
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)size, "datafile page");
        return CT_ERROR;
    }

    char *buf = (char *)malloc(size);
    if (buf == NULL) {
        cm_close_file(handle);
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)size, "parse datafile");
        return CT_ERROR;
    }

    // verify log_file_ctrl_bk_t.version, only used first page
    status_t status = miner_read_page(handle, buf, 0, size);
    if (status == CT_SUCCESS) {
        datafile_ctrl_bk_t *ctrl_bk = (datafile_ctrl_bk_t *)((char *)buf +
            sizeof(page_head_t) + sizeof(datafile_header_t));
        if (TBOX_DATAFILE_VERSION != ctrl_bk->version) {
            status = CT_ERROR;
            CT_THROW_ERROR(ERR_PARAMETER_NOT_MATCH, "CTBOX DATAFILE STRUCTURE VERSION",
                TBOX_DATAFILE_VERSION, ctrl_bk->version);
        }
    }

    cm_close_file(handle);
    CM_FREE_PTR(buf);
    return status;
}

status_t miner_verify_logfile_version(char *file_name, uint32 size)
{
    int32 handle;

    if (cm_open_file(file_name, O_RDONLY | O_BINARY, &handle) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (size == 0) {
        cm_close_file(handle);
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)size, "logfile page");
        return CT_ERROR;
    }

    char *buf = (char *)malloc(size);
    if (buf == NULL) {
        cm_close_file(handle);
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)size, "parse datafile");
        return CT_ERROR;
    }

    // verify log_file_ctrl_bk_t.version, only used first page
    status_t status = miner_read_page(handle, buf, 0, size);
    if (status == CT_SUCCESS) {
        log_file_ctrl_bk_t *ctrl_bk = (log_file_ctrl_bk_t *)((char *)buf + sizeof(log_file_head_t));
        if (TBOX_DATAFILE_VERSION != ctrl_bk->version) {
            status = CT_ERROR;
            CT_THROW_ERROR(ERR_PARAMETER_NOT_MATCH, "CTBOX DATAFILE STRUCTURE VERSION",
                TBOX_DATAFILE_VERSION, ctrl_bk->version);
        }
    }

    cm_close_file(handle);
    CM_FREE_PTR(buf);
    return status;
}

status_t miner_verify_corefile_version(char *file_name, uint32 page_size)
{
    database_ctrl_t ctrl;
    status_t status = CT_SUCCESS;
    int32 read_size;
    int32 handle;
    uint32 size = (CORE_CTRL_PAGE_ID + 1) * CT_DFLT_CTRL_BLOCK_SIZE;

    if (cm_open_file(file_name, O_RDONLY | O_BINARY, &handle) != CT_SUCCESS) {
        return CT_ERROR;
    }

    ctrl.pages = (ctrl_page_t *)malloc(size);
    if (ctrl.pages == NULL) {
        cm_close_file(handle);
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)size, "page");
        return CT_ERROR;
    }

    if (cm_seek_file(handle, 0, SEEK_SET) != 0) {
        cm_close_file(handle);
        CM_FREE_PTR(ctrl.pages);
        CT_THROW_ERROR(ERR_SEEK_FILE, 0, SEEK_SET, errno);
        return CT_ERROR;
    }

    if (cm_read_file(handle, (void *)ctrl.pages, size, &read_size) != CT_SUCCESS) {
        cm_close_file(handle);
        CM_FREE_PTR(ctrl.pages);
        return CT_ERROR;
    }

    core_ctrl_t *core = (core_ctrl_t *)ctrl.pages[1].buf;

    if (TBOX_DATAFILE_VERSION != core->version.inner) {
        status = CT_ERROR;
        CT_THROW_ERROR(ERR_PARAMETER_NOT_MATCH, "CTBOX DATAFILE STRUCTURE VERSION",
            TBOX_DATAFILE_VERSION, core->version.inner);
    }

    cm_close_file(handle);
    CM_FREE_PTR(ctrl.pages);
    return status;
}

status_t miner_check_file_version(miner_input_def_t *input)
{
    uint32 ctrl_head_size;
    status_t ret = CT_SUCCESS;

    // redolog
    if (input->logfile != NULL) {
        ctrl_head_size = (uint32)sizeof(log_file_ctrl_bk_t) + sizeof(log_file_head_t);
        ret = miner_verify_logfile_version(input->logfile, ctrl_head_size);
    // datafile
    } else if (input->datafile != NULL) {
        ctrl_head_size = (uint32)sizeof(datafile_ctrl_bk_t) + sizeof(page_head_t) + sizeof(datafile_header_t);
        ret = miner_verify_datafile_version(input->datafile, ctrl_head_size);
    // core ctrl
    } else if (input->ctrlfile != NULL) {
        ctrl_head_size = (uint32)(CORE_CTRL_PAGE_ID + 1) * CT_DFLT_CTRL_BLOCK_SIZE;
        ret = miner_verify_corefile_version(input->ctrlfile, ctrl_head_size);
    // several redo logs
    } else if (input->logfiles != NULL) {
        ctrl_head_size = sizeof(log_file_ctrl_bk_t) + sizeof(log_file_head_t);
        for (int i = 0; i < CT_REDO_LOG_NUM; i++) {
            if (input->logfiles[i] != NULL && ret == CT_SUCCESS) {
                ret = miner_verify_logfile_version(input->logfiles[i], ctrl_head_size);
            }
        }
    }

    if (ret != CT_SUCCESS) {
        printf("try use \"--help\" for more information.\n");
    }

    return ret;
}

status_t miner_check_bak_version(char *input_file)
{
    bak_head_t *bak_head = NULL;
    char *read_buf = (char *)malloc(CT_BACKUP_BUFFER_SIZE);

    if (read_buf == NULL) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)CT_BACKUP_BUFFER_SIZE, "cminer");
        return CT_ERROR;
    }

    if (miner_parse_backup_info(input_file, &read_buf, CT_BACKUP_BUFFER_SIZE, &bak_head) != CT_SUCCESS) {
        CM_FREE_PTR(read_buf);
        return CT_ERROR;
    }

    status_t status = CT_SUCCESS;
    if (bak_head->df_struc_version != TBOX_DATAFILE_VERSION) {
        status = CT_ERROR;
        CT_THROW_ERROR(ERR_PARAMETER_NOT_MATCH, "CTBOX DATAFILE STRUCTURE VERSION",
            TBOX_DATAFILE_VERSION, bak_head->df_struc_version);
    }
    CM_FREE_PTR(read_buf);
    return status;
}

status_t miner_check_backupset_version(const char *inputfile)
{
    char head_path[CT_FILE_NAME_BUFFER_SIZE];
    text_t head_path_text;

    cm_trim_filename(inputfile, CT_FILE_NAME_BUFFER_SIZE, head_path);
    if (strlen(inputfile) == strlen(head_path)) {
        head_path_text.str = MINER_BACKUP_SET;
        head_path_text.len = (uint32)strlen(MINER_BACKUP_SET);
    } else {
        head_path_text.str = head_path;
        head_path_text.len = (uint32)strlen(head_path);
        cm_concat_string(&head_path_text, CT_FILE_NAME_BUFFER_SIZE, MINER_BACKUP_SET);
        head_path_text.str[head_path_text.len] = '\0';
    }

    return miner_check_bak_version(head_path_text.str);
}

static inline bool32 miner_is_bak_file(char *input_file)
{
    size_t len = (uint32)strlen(input_file);
    if (len <= MINER_BAK_FILE_TYPE_LEN) {
        return CT_FALSE;
    }

    if (cm_strcmpni(input_file + (len - MINER_BAK_FILE_TYPE_LEN), MINER_BAK_FILE_TYPE, MINER_BAK_FILE_TYPE_LEN) == 0) {
        return CT_TRUE;
    }

    return CT_FALSE;
}

bool32 miner_need_backupset_file(miner_input_def_t *input, char **input_file)
{
    bool32 is_bak = CT_FALSE;
    // redolog
    if (input->logfile != NULL) {
        is_bak = miner_is_bak_file(input->logfile);
        *input_file = input->logfile;
    // datafile
    } else if (input->datafile != NULL) {
        is_bak = miner_is_bak_file(input->datafile);
        *input_file = input->datafile;
    // core ctrl
    } else if (input->ctrlfile != NULL) {
        is_bak = miner_is_bak_file(input->ctrlfile);
        *input_file = input->ctrlfile;
    }

    return is_bak;
}

static status_t miner_check_input(miner_input_def_t *input)
{
    if (input->datafile == NULL && input->logfile == NULL && input->ctrlfile == NULL && !input->is_backupset) {
        if (input->inputfile != NULL && input->is_backup) {
            printf("must set output filename to decompress, cminer -z backup file -f output file\n");
        }
        printf("try use \"--help\" for more information.\n");
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "cminer input parameter");
        return CT_ERROR;
    }

    if (input->inputfile != NULL && input->ctrlfile == NULL && !input->is_backup) {
        printf("must specify a control file to generate\n");
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "cminer input parameter");
        return CT_ERROR;
    }

    if (input->inputfile != NULL && input->datafile == NULL && input->is_backup && !input->is_backupset) {
        printf("must set output filename to decompress, cminer -z backup file -f output file\n");
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "cminer input parameter");
        return CT_ERROR;
    }

    if (input->page_size == 0) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "page size");
        return CT_ERROR;
    }

    // force excute, ignore verify version
    if (input->is_force == CT_TRUE) {
        return CT_SUCCESS;
    }

    // check inputfile, if got inputfile , -c -f -l should be output ignore version check
    //  1, -z file, must have backupset
    //  2, -i generate core ctrl
    if (input->inputfile != NULL) {
        if (input->is_backup) {
            if (miner_check_backupset_version(input->inputfile) == CT_ERROR) {
                return CT_ERROR;
            }
        }
        return CT_SUCCESS;
    }

    // check file version, if it is .bak file
    char *input_file = NULL;
    if (miner_need_backupset_file(input, &input_file) == CT_TRUE) {
        return miner_check_backupset_version(input_file);
    }

    // check file version
    return miner_check_file_version(input);
}

static status_t miner_parse_log_file_msg(miner_log_file_t *msg, int64 *file_offset)
{
    msg->buf = (char *)malloc(CT_MAX_LOG_BUFFER_SIZE);

    if (msg->buf == NULL) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)CT_MAX_LOG_BUFFER_SIZE, "miner parse logfile");
        return CT_ERROR;
    }

    errno_t rc_memzero = memset_s(msg->buf, CT_MAX_LOG_BUFFER_SIZE, 0, CT_MAX_LOG_BUFFER_SIZE);
    if (rc_memzero != EOK) {
        CM_FREE_PTR(msg->buf);
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)CT_MAX_LOG_BUFFER_SIZE, "miner parse logfile");
        return CT_ERROR;
    }
    if (cm_open_file(msg->filedir, O_RDONLY | O_BINARY, &msg->handle) != CT_SUCCESS) {
        CM_FREE_PTR(msg->buf);
        return CT_ERROR;
    }

    if (miner_read_file_head(msg->handle, &msg->head, file_offset) != CT_SUCCESS) {
        cm_close_file(msg->handle);
        CM_FREE_PTR(msg->buf);
        return CT_ERROR;
    }
    msg->asn = msg->head.asn;
    return CT_SUCCESS;
}

static void copy_log_file_msg(miner_log_file_t *dest, miner_log_file_t *src)
{
    dest->asn = src->asn;
    dest->filedir = src->filedir;
    dest->handle = src->handle;
    dest->head = src->head;
    dest->buf = src->buf;
}

static void miner_sort_log_files(miner_log_file_t *log_files_msg, int64 *file_offset, int cnt)
{
    miner_log_file_t tmp;
    uint8 minIndex;
    uint32 minAsn;
    int64 temp;
    for (uint8 i = 0; i < cnt - 1; i++) {
        minIndex = i;
        minAsn = log_files_msg[i].asn;
        for (uint8 j = i + 1; j < cnt; j++) {
            if (log_files_msg[j].asn < minAsn) {
                minAsn = log_files_msg[j].asn;
                minIndex = j;
            }
        }
        if (minIndex != i) {
            copy_log_file_msg(&tmp, &log_files_msg[minIndex]);
            copy_log_file_msg(&log_files_msg[minIndex], &log_files_msg[i]);
            copy_log_file_msg(&log_files_msg[i], &tmp);
            temp = file_offset[minIndex];
            file_offset[minIndex] = file_offset[i];
            file_offset[i] = temp;
        }
    }
}

static status_t fetch_group_xid(log_cursor_t *cursor, bool32 is_lfn, uint64 start, uint32 count, miner_log_file_t *msg, bool32 has_xid, tx_msg_t *tx_msg, uint8 xid_cnt)
{
    bool32 fetch_group_is_over = CT_FALSE;
    log_group_t *group = miner_fetch_group(cursor);
    uint32 group_count = 0;

    while (group != NULL) {
        if (!is_lfn && start != CT_INVALID_ID64 && group->lsn < start) {
            group = miner_fetch_group(cursor);
            continue;
        }

        miner_desc_group_xid(group, has_xid, tx_msg, xid_cnt);
        group_count++;

        if (!is_lfn && count != CT_INVALID_ID32 && group_count >= count) {
            fetch_group_is_over = CT_TRUE;
            break;
        }
        group = miner_fetch_group(cursor);
    }

    return fetch_group_is_over;
}

static status_t miner_parse_each_logfile(const char *logpath, uint64 start, uint32 count, bool32 is_lfn,
    bool32 is_checksum, miner_log_file_t *msg, int64 file_offset, bool32 has_xid, tx_msg_t *tx_msg, uint8 xid_cnt,
    bool32 use_dbstor)
{
    log_batch_t *batch = NULL;
    log_file_head_t head = msg->head;
    uint32 data_offset = 0;
    int32 data_size = 0;
    log_cursor_t cursor;
    uint32 batch_count = 0;
    bool32 file_finish;
    status_t ret = CT_SUCCESS;

    printf("file head: first_scn %llu last_scn %llu write_pos %llu asn %u reset_id %u checksum %u\n",
           head.first, head.last, head.write_pos, head.asn, head.rst_id, head.checksum);
    miner_verify_loghead_checksum(&msg->head, is_checksum);

    for (;;) {
        file_finish = CT_FALSE;
        ret = miner_load_batch(&msg->handle, msg->buf, (int32)CT_MAX_LOG_BUFFER_SIZE, &data_offset,
                               &data_size, &file_offset, &batch, &file_finish);
        if (ret == CT_ERROR) {
            break;
        }

        if (file_finish) {
            printf("\n\tcurrent file finished\n");
            break;
        }
        if (is_lfn && start != CT_INVALID_ID64 && batch->head.point.lfn < start) {
            continue;
        }
        printf("\nbatch: %llu size: %u space_size: %u ", (uint64)batch->head.point.lfn, batch->size, batch->space_size);
        printf("scn: %llu parts: %u checksum: %u\n", batch->scn, batch->part_count, batch->checksum);
        miner_verify_batch_checksum(batch, is_checksum);
        ret = batch_decrypt(batch);
        if (ret == CT_ERROR) {
            break;
        }

        fetch_part(batch, &cursor);

        if (fetch_group_xid(&cursor, is_lfn, start, count, msg, has_xid, tx_msg, xid_cnt)) {
            break;
        }

        batch_count++;
        if (is_lfn && count != CT_INVALID_ID32 && batch_count >= count) {
            break;
        }
    }

    cm_close_file(msg->handle);
    CM_FREE_PTR(msg->buf);
    return ret;
}

static status_t miner_parse_logfiles(char **logpaths, uint64 start, uint32 count, bool32 is_lfn, bool32 is_checksum, miner_input_def_t *input)
{
    miner_log_file_t log_files_msg[CT_REDO_LOG_NUM];
    int64 file_offset[CT_REDO_LOG_NUM] = {0};
    tx_msg_t tx_msg[CT_XID_NUM];
   
    if (miner_log_init() != CT_SUCCESS) {
        return CT_ERROR;
    }

    for (uint8 i = 0; i < input->log_cnt; i++) {
        log_files_msg[i].filedir = logpaths[i];
        if (miner_parse_log_file_msg(&log_files_msg[i], &file_offset[i]) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    miner_sort_log_files(log_files_msg, file_offset, input->log_cnt);
    for (uint8 i = 0; i < input->xid_cnt; i++) {
        tx_msg[i].xid = input->xids[i];
    }
    for (uint8 i = 0; i < input->log_cnt; i++) {
        if (miner_parse_each_logfile(log_files_msg[i].filedir, start, count, is_lfn, is_checksum, &log_files_msg[i],
            file_offset[i], input->has_xid, tx_msg, input->xid_cnt, input->use_dbstor) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

static status_t miner_parse_input(miner_input_def_t *input)
{
    if (input->use_dbstor) {
        if (dbs_tool_init_lib() != CT_SUCCESS) {
            CT_LOG_RUN_ERR("Failed to init lib.");
            return CT_ERROR;
        }
    }

    status_t ret;
    if (input->datafile != NULL && !input->is_backup) {
        ret = miner_parse_datafile(input);
    } else if (input->logfile != NULL || input->logfiles[0] != NULL) {
        if (input->has_xid) {
            ret = miner_parse_logfiles(input->logfiles, input->start, input->count, input->is_lfn,
                input->is_checksum, input);
        } else if (input->is_decompress) {
            ret = miner_decompress_logfile(input->logfile, input->start, input->count, input->is_lfn,
                input->is_checksum);
        } else {
            ret = miner_parse_logfile(input->logfile, input->start, input->count, input->is_lfn,
                input->is_checksum, input->use_dbstor);
        }
    } else if (input->inputfile != NULL && input->is_backup) {
        if (input->is_backupset) {
            ret = miner_parse_backup_head(input->inputfile);
        } else {
            ret = miner_decompress_bakfile(input->inputfile, input->datafile);
        }
    } else if (input->ctrlfile != NULL) {
        ret = miner_parse_ctrlfile(input->ctrlfile, input->is_checksum);
    } else {
        ret = CT_ERROR;
    }

    return ret;
}

status_t miner_execute(int argc, char *argv[])
{
    miner_input_def_t input;

    if (miner_init_input(&input) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (miner_usage(argc, argv)) {
        return CT_SUCCESS;
    }

    if (miner_get_input(argc, argv, &input) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "cminer input parameter");
        miner_free_input(&input);
        return CT_ERROR;
    }

    if (g_gm_optind < argc) {
        printf("invalid argument : \"%s\"", argv[g_gm_optind]);
        printf("try use \"--help\" for more information.\n");
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "cminer input parameter");
        miner_free_input(&input);
        return CT_ERROR;
    }

    if (miner_check_input(&input) != CT_SUCCESS) {
        miner_free_input(&input);
        return CT_ERROR;
    }

    if (input.ctrlfile != NULL && input.is_version) {
        if (miner_ctrlfile_version(input.ctrlfile) == CT_ERROR) {
            printf("%s is not a ctrlfile", input.ctrlfile);
            miner_free_input(&input);
            return CT_ERROR;
        }
        miner_free_input(&input);
        return CT_SUCCESS;
    }

    if (input.ctrlfile != NULL && input.modify_version) {
        if (miner_update_version(input.ctrlfile) == CT_ERROR) {
            printf("%s is not a ctrlfile", input.ctrlfile);
            miner_free_input(&input);
            return CT_ERROR;
        }
        printf("Success update version.");
        miner_free_input(&input);
        return CT_SUCCESS;
    }

    if (miner_parse_input(&input) != CT_SUCCESS) {
        miner_free_input(&input);
        return CT_ERROR;
    }

    miner_free_input(&input);
    return CT_SUCCESS;
}
