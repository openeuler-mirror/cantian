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
 * knl_page.h
 *
 *
 * IDENTIFICATION
 * src/kernel/buffer/knl_page.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_PAGE_H__
#define __KNL_PAGE_H__

#include "knl_buffer_module.h"
#include "cm_defs.h"
#include "cm_checksum.h"
#include "cm_kmc.h"
#include "cm_file.h"
#include "knl_interface.h"
#include "knl_session.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PAGE_HEAD_SIZE            (sizeof(page_head_t))
#define PAGE_TAIL_SIZE            (sizeof(page_tail_t))
#define PAGE_VALID_SIZE(session)  (DEFAULT_PAGE_SIZE(session) - sizeof(page_head_t) - PAGE_TAIL_SIZE)
#define CURR_PAGE(session)        ((session)->curr_page)
#define CURR_CR_PAGE(session)     ((session)->curr_cr_page)
#define PAGE_HEAD(page)           ((page_head_t *)(page))
#define PAGE_TAIL(page)           ((page_tail_t *)((char *)(page) + PAGE_SIZE(*(page)) - PAGE_TAIL_SIZE))
#define PAGE_CHECKSUM(page, size) (((page_tail_t *)((char *)(page) + (size) - PAGE_TAIL_SIZE))->checksum)
#define AS_HEAP_PAGE(page)        ((heap_page_t *)(page))
#define AS_BTREE_PAGE(page)       ((btree_page_t *)(page))
#define PAGE_TYPE(page)           (PAGE_HEAD(page)->type)
#define PAGE_GET_LSN(page)        (((page_head_t *)(page))->lsn)
#define PAGE_GET_PAGEID(page)     (AS_PAGID((page)->id))
#define COMPRESS_PAGE_HEAD(page)  ((compress_page_head_t *)((char *)(page) + sizeof(page_head_t)))
#define COMPRESS_PAGE_VALID_SIZE(session)  \
    (DEFAULT_PAGE_SIZE(session) - sizeof(page_head_t) - sizeof(compress_page_head_t))
#define COMPRESS_GROUP_VALID_SIZE(session) (COMPRESS_PAGE_VALID_SIZE(session) * PAGE_GROUP_COUNT)

typedef enum st_page_type {
    PAGE_TYPE_FREE_PAGE = 0,
    PAGE_TYPE_SPACE_HEAD = 1,   // space head page
    PAGE_TYPE_HEAP_HEAD = 2,    // heap segment page
    PAGE_TYPE_HEAP_MAP = 3,     // heap map page
    PAGE_TYPE_HEAP_DATA = 4,    // heap page
    PAGE_TYPE_UNDO_HEAD = 5,    // undo segment page
    PAGE_TYPE_TXN = 6,          // txn page
    PAGE_TYPE_UNDO = 7,         // undo page
    PAGE_TYPE_BTREE_HEAD = 8,   // btree segment page
    PAGE_TYPE_BTREE_NODE = 9,   // btree page
    PAGE_TYPE_LOB_HEAD = 10,    // lob segment page
    PAGE_TYPE_LOB_DATA = 11,    // lob data page
    PAGE_TYPE_TEMP_HEAP = 12,   // temp heap page
    PAGE_TYPE_TEMP_INDEX = 13,  // temp index page
    PAGE_TYPE_FILE_HEAD = 15,
    PAGE_TYPE_CTRL = 16,
    PAGE_TYPE_PCRH_DATA = 17,
    PAGE_TYPE_PCRB_NODE = 18,
    PAGE_TYPE_DF_MAP_HEAD = 19,
    PAGE_TYPE_DF_MAP_DATA = 20,
    PAGE_TYPE_PUNCH_PAGE = 21,
    /* add new page type here */
    PAGE_TYPE_COUNT = 22,
    PAGE_TYPE_END = 255,
} page_type_t;

#pragma pack(4)
// common page head
typedef struct st_page_head {
    pagid_data_t id;  // page id 6 Bytes
    uint8 type;
    uint8 size_units;
    pagid_data_t next_ext;  // page id for next extent 6 Bytes
    uint8 ext_size : 2;
    uint8 encrypted : 1;
    uint8 compressed : 1;
    uint8 soft_damage : 1;
    uint8 hard_damage : 1;
    uint8 unused : 2;
    uint8 unused1;
    uint64 lsn;  // log change number
    uint32 pcn;
    uint32 unused2;
} page_head_t;

typedef struct st_page_tail {
    uint16 checksum;
    uint16 reserve;
    uint32 pcn;  // page change number
} page_tail_t;
#pragma pack()

typedef struct st_compress_page_head {
    uint64 compressed_size : 20;
    uint64 compress_algo : 4;
    uint64 group_cnt : 4;
    uint64 checksum : 16;
    uint64 unused : 20;
} compress_page_head_t;

// PAGE_MARGIN_SIZE must more than 124
#define PAGE_MARGIN_SIZE     192
#define DEFAULT_PAGE_SIZE(session)    (((knl_session_t *)(session))->kernel->attr.page_size)
#define PAGE_UNIT_SIZE       4096
#define PAGE_SIZE(page)      ((page).size_units * PAGE_UNIT_SIZE)
#define CHECK_PAGE_PCN(page) ((page)->pcn == PAGE_TAIL(page)->pcn)
#define PAGE_DUMP_SIZE       1024
#define PAGE_IS_SOFT_DAMAGE(page) ((page)->soft_damage)
#define PAGE_IS_HARD_DAMAGE(page) ((page)->hard_damage)
#define PAGE_IS_HARD_DAMAGE_ZERO(page) (PAGE_IS_HARD_DAMAGE(page) && PAGE_SIZE(*(page)) == 0)

void page_init(knl_session_t *session, page_head_t *page, page_id_t id, page_type_t type);
void page_free(knl_session_t *session, page_head_t *page);
status_t page_cipher_reserve_size(knl_session_t *session, encrypt_version_t version, uint8 *cipher_reserve_size);
status_t page_encrypt(knl_session_t *session, page_head_t *page, uint8 encrypt_version, uint8 cipher_reserve_size);
status_t page_decrypt(knl_session_t *session, page_head_t *page);

#define CM_DUMP_WRITE_FILE(dump) \
    do { \
        if (cm_dump_flush(dump) != CT_SUCCESS) { \
            return CT_ERROR; \
        } \
    } while (0)

static inline bool32 page_verify_checksum(page_head_t *page, uint32 page_size)
{
    uint16 org_cks = PAGE_CHECKSUM(page, page_size);

    PAGE_CHECKSUM(page, page_size) = CT_INVALID_CHECKSUM;
    uint32 cks = cm_get_checksum(page, page_size);
    PAGE_CHECKSUM(page, page_size) = org_cks;

    return (org_cks == REDUCE_CKS2UINT16(cks));
}


static inline void page_calc_checksum(page_head_t *page, uint32 page_size)
{
    PAGE_CHECKSUM(page, page_size) = CT_INVALID_CHECKSUM;
    uint32 cks = cm_get_checksum(page, page_size);
    PAGE_CHECKSUM(page, page_size) = REDUCE_CKS2UINT16(cks);
}

static inline bool32 page_compress_verify_checksum(page_head_t *page, uint32 page_size)
{
    uint16 org_cks = (uint16)COMPRESS_PAGE_HEAD(page)->checksum;

    COMPRESS_PAGE_HEAD(page)->checksum = CT_INVALID_CHECKSUM;
    uint32 cks = cm_get_checksum(page, page_size);
    COMPRESS_PAGE_HEAD(page)->checksum = org_cks;

    return (org_cks == REDUCE_CKS2UINT16(cks));
}

static inline void page_compress_calc_checksum(page_head_t *page, uint32 page_size)
{
    COMPRESS_PAGE_HEAD(page)->checksum = CT_INVALID_CHECKSUM;
    uint32 cks = cm_get_checksum(page, page_size);
    COMPRESS_PAGE_HEAD(page)->checksum = REDUCE_CKS2UINT16(cks);
}

static inline const char *page_type(uint8 type)
{
    switch (type) {
        case PAGE_TYPE_FREE_PAGE:
            return "free";
        case PAGE_TYPE_SPACE_HEAD:
            return "space_head";
        case PAGE_TYPE_HEAP_HEAD:
            return "heap_segment";
        case PAGE_TYPE_HEAP_MAP:
            return "heap_map";
        case PAGE_TYPE_HEAP_DATA:
            return "heap";
        case PAGE_TYPE_UNDO_HEAD:
            return "undo_segment";
        case PAGE_TYPE_TXN:
            return "txn";
        case PAGE_TYPE_UNDO:
            return "undo";
        case PAGE_TYPE_BTREE_HEAD:
            return "btree_segment";
        case PAGE_TYPE_BTREE_NODE:
            return "btree";
        case PAGE_TYPE_LOB_HEAD:
            return "lob_segment";
        case PAGE_TYPE_LOB_DATA:
            return "lob";
        case PAGE_TYPE_TEMP_HEAP:
            return "temp_heap";
        case PAGE_TYPE_TEMP_INDEX:
            return "temp_index";
        case PAGE_TYPE_CTRL:
            return "ctrl";
        case PAGE_TYPE_FILE_HEAD:
            return "file_head";
        case PAGE_TYPE_PCRH_DATA:
            return "pcr_heap";
        case PAGE_TYPE_PCRB_NODE:
            return "pcr_btree";
        case PAGE_TYPE_DF_MAP_HEAD:
            return "datafile_map_head";
        case PAGE_TYPE_DF_MAP_DATA:
            return "datafile_map_data";
        case PAGE_TYPE_PUNCH_PAGE:
            return "punched_page";
        default:
            return "invalid";
    }
}

static inline page_id_t as_normal_page_id(undo_page_id_t undo_page)
{
    page_id_t normal_page;
    normal_page.file = undo_page.file;
    normal_page.page = undo_page.page;
    normal_page.aligned = 0;
    return normal_page;
}

static inline undo_page_id_t as_undo_page_id(page_id_t normal_page)
{
    undo_page_id_t undo_page;
    undo_page.file = normal_page.file;
    undo_page.page = normal_page.page;
    return undo_page;
}

static inline page_id_t make_page_id(uint16 file, uint32 page)
{
    page_id_t page_id;
    page_id.file = file;
    page_id.page = page;
    page_id.aligned = 0;
    return page_id;
}

static inline bool32 page_type_suport_encrypt(uint8 page_type)
{
    if (page_type == PAGE_TYPE_HEAP_DATA || page_type == PAGE_TYPE_PCRH_DATA ||
        page_type == PAGE_TYPE_BTREE_NODE || page_type == PAGE_TYPE_PCRB_NODE ||
        page_type == PAGE_TYPE_LOB_DATA || page_type == PAGE_TYPE_UNDO) {
        return CT_TRUE;
    }
    return CT_FALSE;
}

static inline bool32 page_type_suport_nolog_insert(uint8 type)
{
    if (type == PAGE_TYPE_HEAP_DATA || type == PAGE_TYPE_PCRH_DATA ||
        type == PAGE_TYPE_BTREE_NODE || type == PAGE_TYPE_PCRB_NODE ||
        type == PAGE_TYPE_LOB_DATA) {
        return CT_TRUE;
    }
    return CT_FALSE;
}

static inline bool32 page_soft_damaged(page_head_t *head)
{
    if (PAGE_IS_SOFT_DAMAGE(head)) {
        CT_LOG_RUN_WAR("[NOLOG INSERT] page: %u-%u is soft damage", AS_PAGID(head->id).file, AS_PAGID(head->id).page);
        return CT_TRUE;
    }

    return CT_FALSE;
}

static inline bool32 page_is_damaged(page_head_t *head)
{
    if (PAGE_IS_SOFT_DAMAGE(head) || PAGE_IS_HARD_DAMAGE(head)) {
        CT_LOG_RUN_WAR("page: %u-%u is damage", AS_PAGID(head->id).file, AS_PAGID(head->id).page);
        return CT_TRUE;
    }

    return CT_FALSE;
}

#define PAGID_U2N  as_normal_page_id
#define PAGID_N2U  as_undo_page_id
#define MAKE_PAGID make_page_id

#define PAGID_LT(p1, p2)    ((p1).file < (p2).file || ((p1).file == (p2).file && (p1).page < (p2).page))
#define PAGID_GT(p1, p2)    ((p1).file > (p2).file || ((p1).file == (p2).file && (p1).page > (p2).page))

#ifdef __cplusplus
}
#endif

#endif
