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
 * knl_page.c
 *
 *
 * IDENTIFICATION
 * src/kernel/buffer/knl_page.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_buffer_module.h"
#include "knl_page.h"
#include "cm_file.h"
#include "cm_kmc.h"
#include "knl_context.h"
#include "knl_undo.h"
#include "pcr_btree.h"

#ifdef __cplusplus
extern "C" {
#endif

void page_init(knl_session_t *session, page_head_t *page, page_id_t id, page_type_t type)
{
    page_tail_t *tail = NULL;
    uint32 size = session->kernel->db.datafiles[id.file].ctrl->block_size;
    errno_t ret;

    ret = memset_sp(page, DEFAULT_PAGE_SIZE(session), 0, DEFAULT_PAGE_SIZE(session));
    knl_securec_check(ret);
    TO_PAGID_DATA(id, page->id);
    TO_PAGID_DATA(INVALID_PAGID, page->next_ext);
    page->size_units = page_size_units(size);
    page->type = type;
    tail = PAGE_TAIL(page);
    tail->checksum = 0;
    tail->pcn = 0;
}

void page_free(knl_session_t *session, page_head_t *page)
{
    page_tail_t *tail = NULL;
    page_id_t next_ext;
    page_id_t id;
    errno_t ret;

    id = AS_PAGID(page->id);
    next_ext = AS_PAGID(page->next_ext);

    ret = memset_sp(page, DEFAULT_PAGE_SIZE(session), 0, DEFAULT_PAGE_SIZE(session));
    knl_securec_check(ret);

    TO_PAGID_DATA(id, page->id);
    TO_PAGID_DATA(next_ext, page->next_ext);
    page->size_units = page_size_units(DEFAULT_PAGE_SIZE(session));
    page->type = PAGE_TYPE_FREE_PAGE;
    tail = PAGE_TAIL(page);
    tail->pcn = 0;
}

status_t page_cipher_reserve_size(knl_session_t *session, encrypt_version_t version, uint8 *cipher_reserve_size)
{
    uint32 page_cost_size = DEFAULT_PAGE_SIZE(session) - sizeof(page_head_t) - sizeof(page_tail_t);
    uint32 max_cipher_len;

    if (cm_get_cipher_len(page_cost_size, &max_cipher_len) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("get cipher len failed");
        return CT_ERROR;
    }

    uint32 max_size = CM_ALIGN4(max_cipher_len - page_cost_size + sizeof(cipher_ctrl_t));
    TO_UINT8_OVERFLOW_CHECK(max_size, uint32);

    *cipher_reserve_size = max_size;
    CM_SAVE_STACK(session->stack);

    char *plain_buf = (char *)cm_push(session->stack, DEFAULT_PAGE_SIZE(session));
    uint32 plain_len = page_cost_size - max_size;
    char *cipher_buf = (char *)cm_push(session->stack, DEFAULT_PAGE_SIZE(session));
    uint32 cipher_len = DEFAULT_PAGE_SIZE(session);

    status_t status = cm_kmc_encrypt(CT_KMC_KERNEL_DOMAIN, version, plain_buf,
        plain_len, cipher_buf, &cipher_len);
    if (status != CT_SUCCESS) {
        CT_LOG_RUN_ERR("fail to try encrypt");
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    uint32 real_size = cipher_len - plain_len;
    TO_UINT8_OVERFLOW_CHECK(real_size, uint32);

    if ((uint32)(real_size + sizeof(cipher_ctrl_t)) > max_size) {
        CT_LOG_RUN_ERR("real size %u more than max_size %u.", (uint32)(real_size + sizeof(cipher_ctrl_t)), max_size);
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}

static cipher_ctrl_t *page_cipher_ctrl(page_head_t *page)
{
    uint32 ctrl_offset = 0;
    switch (page->type) {
        case PAGE_TYPE_HEAP_DATA:
        case PAGE_TYPE_PCRH_DATA:
            ctrl_offset = sizeof(heap_page_t);
            break;
        case PAGE_TYPE_BTREE_NODE:
        case PAGE_TYPE_PCRB_NODE:
            ctrl_offset = sizeof(btree_page_t);
            break;
        case PAGE_TYPE_UNDO:
            ctrl_offset = sizeof(undo_page_t);
            break;
        case PAGE_TYPE_LOB_DATA:
            ctrl_offset = PAGE_SIZE(*page) - sizeof(page_tail_t) - sizeof(cipher_ctrl_t);
            break;
        default:
            CT_LOG_RUN_ERR("page type %d not support encrypt.", page->type);
            return NULL;
    }
    return (cipher_ctrl_t *)((char *)page + ctrl_offset);
}

static uint8 page_cipher_offset(page_head_t *page)
{
    uint8 cipher_offset = 0;
    switch (page->type) {
        case PAGE_TYPE_HEAP_DATA:
        case PAGE_TYPE_PCRH_DATA:
            cipher_offset = sizeof(heap_page_t) + sizeof(cipher_ctrl_t);
            break;
        case PAGE_TYPE_BTREE_NODE:
        case PAGE_TYPE_PCRB_NODE:
            cipher_offset = sizeof(btree_page_t) + sizeof(cipher_ctrl_t);
            break;
        case PAGE_TYPE_LOB_DATA:
            cipher_offset = sizeof(lob_data_page_t);
            break;
        case PAGE_TYPE_UNDO:
            cipher_offset = sizeof(undo_page_t) + sizeof(cipher_ctrl_t);
            break;
        default:
            CT_LOG_RUN_ERR("[GET CIPHER OFFSET ERROR]page type %d not support.", page->type);
            break;
    }

    return cipher_offset;
}

static char *page_plain_buf(page_head_t *page, uint8 cipher_reserve_size, uint32 *offset_len)
{
    char *plain_buf = NULL;

    if (*offset_len != 0) {
        return NULL;
    }

    switch (page->type) {
        case PAGE_TYPE_HEAP_DATA:
        case PAGE_TYPE_PCRH_DATA:
            *offset_len = sizeof(heap_page_t) + cipher_reserve_size;
            break;
        case PAGE_TYPE_BTREE_NODE:
        case PAGE_TYPE_PCRB_NODE:
            *offset_len = sizeof(btree_page_t) + cipher_reserve_size;
            break;
        case PAGE_TYPE_LOB_DATA:
            *offset_len = sizeof(lob_data_page_t);
            break;
        case PAGE_TYPE_UNDO:
            *offset_len = sizeof(undo_page_t) + cipher_reserve_size;
            break;
        default:
            CT_LOG_RUN_ERR("page type %d not support encrypt.", page->type);
            break;
    }

    plain_buf = (char *)page + *offset_len;

    return plain_buf;
}

static uint32 page_plain_len(knl_session_t *session, page_head_t *page, uint8 cipher_reserve_size)
{
    uint32 page_meta_size = 0;
    uint32 page_left_size = DEFAULT_PAGE_SIZE(session) - sizeof(page_tail_t) - cipher_reserve_size;

    switch (page->type) {
        case PAGE_TYPE_HEAP_DATA:
        case PAGE_TYPE_PCRH_DATA:
            page_meta_size = sizeof(heap_page_t);
            break;
        case PAGE_TYPE_BTREE_NODE:
        case PAGE_TYPE_PCRB_NODE:
            page_meta_size = sizeof(btree_page_t);
            break;
        case PAGE_TYPE_LOB_DATA:
            page_meta_size = sizeof(lob_data_page_t);
            break;
        case PAGE_TYPE_UNDO:
            page_meta_size = sizeof(undo_page_t);
            break;
        default:
            CT_LOG_RUN_ERR("page type %d not support encrypt.", page->type);
            break;
    }

    return page_left_size - page_meta_size;
}

#ifdef LOG_DIAG
static char *page_reserved_cipher_buf(uint16 cipher_offset, page_head_t *page, uint8 cipher_reserve_size)
{
    char *reserved_buf = NULL;
    switch (page->type) {
        case PAGE_TYPE_HEAP_DATA:
        case PAGE_TYPE_PCRH_DATA:
        case PAGE_TYPE_BTREE_NODE:
        case PAGE_TYPE_PCRB_NODE:
        case PAGE_TYPE_UNDO:
            reserved_buf = ((char *)page + cipher_offset);
            break;
        case PAGE_TYPE_LOB_DATA:
            reserved_buf = ((char *)page + PAGE_SIZE(*page) - sizeof(page_tail_t) - cipher_reserve_size);
            break;
        default:
            knl_panic_log(0, "page type is unknown, panic info: page %u-%u type %u", AS_PAGID(page->id).file,
                          AS_PAGID(page->id).page, page->type);
            break;
    }

    return reserved_buf;
}

static void check_ctrl_befor_encrypt(cipher_ctrl_t *cipher_ctrl, page_head_t *page,
    page_id_t page_id, uint8 cipher_reserve_size)
{
    if (page->encrypted != 0 ||
        cipher_ctrl->cipher_expanded_size != 0 ||
        cipher_ctrl->encrypt_version != 0 ||
        cipher_ctrl->offset != 0 ||
        cipher_ctrl->reserved != 0) {
        knl_panic_log(CT_FALSE, "invalid cipher ctrl before encrypt: "
            "page_info: page %u, file %u, page_type %u,"
            "cipher_ctrl: encrypted: %u, encrypt_version: %u, cipher_expanded_size: %u, offset: %u, plain_cks: %u, "
            "space->ctrl->cipher_reserve_size: %u ",
            page_id.page, page_id.file, page->type, page->encrypted, cipher_ctrl->encrypt_version,
            cipher_ctrl->cipher_expanded_size, cipher_ctrl->offset, cipher_ctrl->plain_cks,
            cipher_reserve_size);
    }
}

static void check_ctrl_after_encrypt(cipher_ctrl_t *cipher_ctrl, page_head_t *page,
    page_id_t page_id, uint32 cipher_len, uint32 plain_len, uint8 cipher_reserve_size)
{
    if (cipher_ctrl->cipher_expanded_size + sizeof(cipher_ctrl_t) > cipher_reserve_size ||
        cipher_len + sizeof(cipher_ctrl_t) > plain_len + cipher_reserve_size) {
        knl_panic_log(CT_FALSE, "invalid cipher ctrl after encrypt :"
            "page_info: page %u, file %u, page_type %u, "
            "cipher_ctrl: encrypted: %u, encrypt_version: %u, cipher_expanded_size: %u, offset: %u, plain_cks: %u, "
            "space->ctrl->cipher_reserve_size: %u ",
            page_id.page, page_id.file, page->type, page->encrypted, cipher_ctrl->encrypt_version,
            cipher_ctrl->cipher_expanded_size, cipher_ctrl->offset, cipher_ctrl->plain_cks,
            cipher_reserve_size);
    }
}

static void check_reserve_ciper_buf(page_head_t *page, page_id_t page_id,
    cipher_ctrl_t *cipher_ctrl, uint8 cipher_reserve_size)
{
    uint16 cipher_offset = page_cipher_offset(page);
    char *reserved_cipher_buf = page_reserved_cipher_buf(cipher_offset, page, cipher_reserve_size);
    uint8 reserved_cipher_size = cipher_reserve_size - sizeof(cipher_ctrl_t);

    for (int i = 0; i < reserved_cipher_size; i++) {
        if (reserved_cipher_buf[i] == 0) {
            continue;
        }
        knl_panic_log(0, "invalid reserved cipher buf. "
            "page_info: page %u, file %u, page_type %u, "
            "cipher_ctrl: encrypted: %u, encrypt_version: %u, cipher_expanded_size: %u, offset: %u, plain_cks: %u, "
            "space->ctrl->cipher_reserve_size: %u ",
            page_id.page, page_id.file, page->type, page->encrypted, cipher_ctrl->encrypt_version,
            cipher_ctrl->cipher_expanded_size, cipher_ctrl->offset, cipher_ctrl->plain_cks,
            cipher_reserve_size);
    }
}

static void check_ctrl_before_decrypt(space_t *space, cipher_ctrl_t *cipher_ctrl, page_head_t *page,
    page_id_t page_id, uint32 cipher_len, uint32 org_plain_len)
{
    if (!page->encrypted ||
        cipher_ctrl->cipher_expanded_size == 0 ||
        cipher_ctrl->encrypt_version == NO_ENCRYPT ||
        cipher_ctrl->cipher_expanded_size + sizeof(cipher_ctrl_t) > space->ctrl->cipher_reserve_size ||
        cipher_len > org_plain_len + space->ctrl->cipher_reserve_size) {
        knl_panic_log(CT_FALSE, "invalid cipher ctrl before decrypt : "
            "page_info: page %u, file %u, page_type %u,"
            "cipher_ctrl: encrypted: %u, encrypt_version: %u, cipher_expanded_size: %u, offset: %u, plain_cks: %u, "
            "space->ctrl->cipher_reserve_size: %u ",
            page_id.page, page_id.file, page->type, page->encrypted, cipher_ctrl->encrypt_version,
            cipher_ctrl->cipher_expanded_size, cipher_ctrl->offset, cipher_ctrl->plain_cks,
            space->ctrl->cipher_reserve_size);
    }
}
#endif

status_t page_encrypt(knl_session_t *session, page_head_t *page, uint8 encrypt_version, uint8 cipher_reserve_size)
{
    cipher_ctrl_t *cipher_ctrl = page_cipher_ctrl(page);
    cipher_ctrl->plain_cks = 0;

#ifdef LOG_DIAG
    page_id_t page_id = AS_PAGID(page->id);
    if (page->type == PAGE_TYPE_UNDO) {
        knl_panic_log(undo_valid_encrypt(session, page), "undo space is not encrypt, panic info: page %u-%u type %u",
                      page_id.file, page_id.page, page->type);
    }
    check_ctrl_befor_encrypt(cipher_ctrl, page, page_id, cipher_reserve_size);
    check_reserve_ciper_buf(page, page_id, cipher_ctrl, cipher_reserve_size);
    page_calc_checksum(page, DEFAULT_PAGE_SIZE(session));
    cipher_ctrl->plain_cks = PAGE_CHECKSUM(page, DEFAULT_PAGE_SIZE(session));
#endif

    CM_SAVE_STACK(session->stack);
    char *cipher_buf = (char *)cm_push(session->stack, DEFAULT_PAGE_SIZE(session));
    uint32 cipher_len = DEFAULT_PAGE_SIZE(session);
    uint32 offset_len = 0;
    char *plain_buf = page_plain_buf(page, cipher_reserve_size, &offset_len);
    uint32 plain_len = page_plain_len(session, page, cipher_reserve_size);

    status_t status = cm_kmc_encrypt(CT_KMC_KERNEL_DOMAIN, encrypt_version,
        plain_buf, plain_len, cipher_buf, &cipher_len);
    if (status != CT_SUCCESS) {
        CT_LOG_RUN_ERR("page encrypt failed.");
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    page->encrypted = CT_TRUE;
    cipher_ctrl->cipher_expanded_size = cipher_len - plain_len;
    cipher_ctrl->offset = page_cipher_offset(page);
    cipher_ctrl->encrypt_version = encrypt_version;
    cipher_ctrl->reserved = 0;

#ifdef LOG_DIAG
    check_ctrl_after_encrypt(cipher_ctrl, page, page_id, cipher_len, plain_len, cipher_reserve_size);
#endif

    errno_t ret = memcpy_sp((char *)page + cipher_ctrl->offset, DEFAULT_PAGE_SIZE(session) - cipher_ctrl->offset,
        cipher_buf, cipher_len);
    knl_securec_check(ret);

    if (session->kernel->attr.db_block_checksum == CKS_FULL) {
        page_calc_checksum(page, DEFAULT_PAGE_SIZE(session));
    }
    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}

#ifdef LOG_DIAG
static void page_checksum_after_decrypt(knl_session_t *session, page_head_t *page, cipher_ctrl_t *cipher_ctrl,
    cipher_ctrl_t *temp_ctrl, uint8 cipher_reserve_size)
{
    page_id_t page_id = AS_PAGID(page->id);
    PAGE_CHECKSUM(page, DEFAULT_PAGE_SIZE(session)) = cipher_ctrl->plain_cks;
    cipher_ctrl->plain_cks = 0;
    if (!page_verify_checksum(page, DEFAULT_PAGE_SIZE(session))) {
        knl_panic_log(CT_FALSE, "invaid page plain data: "
            "page_info: page %u, file %u, page_type %u, "
            "cipher_ctrl: encrypted: %u, encrypt_version: %u, cipher_expanded_size: %u, offset: %u, plain_cks: %u, "
            "space->ctrl->cipher_reserve_size: %u ",
            page_id.page, page_id.file, page->type, page->encrypted, temp_ctrl->encrypt_version,
            temp_ctrl->cipher_expanded_size, temp_ctrl->offset, temp_ctrl->plain_cks,
            cipher_reserve_size);
    }

    if (page->type == PAGE_TYPE_UNDO) {
        knl_panic_log(undo_valid_encrypt(session, page), "undo space is not encrypt, panic info: page %u-%u type %u",
                      page_id.file, page_id.page, page->type);
    }
}
#endif

status_t page_decrypt(knl_session_t *session, page_head_t *page)
{
    space_t *space = SPACE_GET(session, DATAFILE_GET(session, AS_PAGID_PTR(page->id)->file)->space_id);
    uint8 cipher_reserve_size = space->ctrl->cipher_reserve_size;
    cipher_ctrl_t *cipher_ctrl = page_cipher_ctrl(page);
    uint32 offset_len = 0;
    char *org_plain_buf = page_plain_buf(page, cipher_reserve_size, &offset_len);
    uint32 org_plain_len = page_plain_len(session, page, cipher_reserve_size);
    uint32 cipher_len = org_plain_len + cipher_ctrl->cipher_expanded_size;

#ifdef LOG_DIAG
    page_id_t page_id = AS_PAGID(page->id);
    knl_panic_log(page_type_suport_encrypt(page->type), "current page type is not suport encrypt, panic info: "
                  "page %u-%u type %u", AS_PAGID(page->id).file, AS_PAGID(page->id).page, page->type);
    check_ctrl_before_decrypt(space, cipher_ctrl, page, page_id, cipher_len, org_plain_len);
#endif

    CM_SAVE_STACK(session->stack);
    char *plain_buf = (char *)cm_push(session->stack, DEFAULT_PAGE_SIZE(session));
    uint32 plain_len = DEFAULT_PAGE_SIZE(session);
    if (cm_kmc_decrypt(CT_KMC_KERNEL_DOMAIN, (char *)page + cipher_ctrl->offset, cipher_len,
        plain_buf, &plain_len) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("page decrypt failed");
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    knl_panic_log(plain_len == org_plain_len, "the plain_len is not equal org_plain_len, panic info: "
                  "page %u-%u type %u plain_len %u org_plain_len %u",
                  AS_PAGID(page->id).file, AS_PAGID(page->id).page, page->type, plain_len, org_plain_len);
    errno_t ret = memcpy_sp(org_plain_buf, DEFAULT_PAGE_SIZE(session) - offset_len, plain_buf, plain_len);
    knl_securec_check(ret);

#ifdef LOG_DIAG
    cipher_ctrl_t temp_ctrl = *cipher_ctrl;
    char *reserved_cipher_buf = page_reserved_cipher_buf(cipher_ctrl->offset, page, cipher_reserve_size);
    uint8 reserved_cipher_size = space->ctrl->cipher_reserve_size - sizeof(cipher_ctrl_t);
    ret = memset_sp(reserved_cipher_buf, reserved_cipher_size, 0, reserved_cipher_size);
    knl_securec_check(ret);
#endif

    cipher_ctrl->cipher_expanded_size = 0;
    page->encrypted = CT_FALSE;
    cipher_ctrl->encrypt_version = 0;
    cipher_ctrl->offset = 0;
    cipher_ctrl->reserved = 0;

#ifdef LOG_DIAG
    page_checksum_after_decrypt(session, page, cipher_ctrl, &temp_ctrl, cipher_reserve_size);
#endif
    cipher_ctrl->plain_cks = 0;

    if (session->kernel->attr.db_block_checksum == CKS_FULL) {
        page_calc_checksum(page, DEFAULT_PAGE_SIZE(session));
    }
    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}

#ifdef __cplusplus
}
#endif

