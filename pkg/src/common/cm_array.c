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
 * cm_array.c
 *
 *
 * IDENTIFICATION
 * src/common/cm_array.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_array.h"
#include "cm_memory.h"
#include "cm_decimal.h"
#include "cm_interval.h"
#include "var_inc.h"
#include "cm_date.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef WIN32
    __declspec(thread) handle_t tls_session_handle = NULL;
    __declspec(thread) handle_t tls_pool_handle = NULL;
#else
    __thread handle_t tls_session_handle = NULL;
    __thread handle_t tls_pool_handle = NULL;
#endif

void array_set_handle(handle_t session_handle, handle_t pool_handle)
{
    tls_session_handle = session_handle;
    tls_pool_handle = pool_handle;
}

static status_t array_modify_head_offset(handle_t session, vm_pool_t *vm_pool, uint32 vmid,
    uint32 total_count, uint32 size, bool32 is_compress)
{
    vm_page_t *page = NULL;

    if (vm_open(session, vm_pool, vmid, &page) != GS_SUCCESS) {
        return GS_ERROR;
    }

    array_head_t *array_head = (array_head_t *)page->data;
    array_head->size = size;
    if (is_compress) {
        array_head->offset = sizeof(array_head_t) + total_count * sizeof(elem_dir_t);
    } else {
        uint32 dir_page_count = cm_get_dir_page_count(array_head->offset);
        array_head->offset = dir_page_count * GS_VMEM_PAGE_SIZE;
    }

    vm_close(session, vm_pool, vmid, VM_ENQUE_HEAD);

    return GS_SUCCESS;
}

static uint32 array_modify_dir_offset(char* buf, uint32 dir_count, const uint32 ctrl_size,
    const uint32 total_dir_count, const bool32 is_first_vm, const bool32 is_compress)
{
    /* A: suppose that dir_size is (x.y * (GS_VMEM_PAGE_SIZE - sizeof(array_head_t)) + n.m * GS_VMEM_PAGE_SIZE),
          there are three situations we should consider bellow :
          1) x is equal to 0 and y is more than 0, n and m are both equal to 0
          2) x is equal to 1 and y is equal to 0, n and m are both equal to 0
          3) x is equal to 1 and y is equal to 0, n and m are not both equal to 0
          so dir_count <= MAX_DIR_COUNT_IN_ONE_VM - 1 in first vm page
       B: array_head_t is in first vm page, when uncompress/compress array dir in first vm page,
          we should skip the buf of array_head_t which is 16 bytes */
    uint32 curr_dir_count;
    char* buf_dir = NULL;
    if (is_first_vm) {
        curr_dir_count = MIN(total_dir_count - dir_count, MAX_DIR_COUNT_IN_ONE_VM - 1);
        buf_dir = buf + sizeof(array_head_t);
    } else {
        curr_dir_count = MIN(total_dir_count - dir_count, MAX_DIR_COUNT_IN_ONE_VM);
        buf_dir = buf;
    }

    for (uint32 offset = 0; offset < curr_dir_count; offset++) {
        elem_dir_t* dir = (elem_dir_t*)(buf_dir + offset * sizeof(elem_dir_t));
        /* if the element is null, can not update the offset value */
        if (dir->offset != ELEMENT_NULL_OFFSET) {
            if (is_compress) {
                dir->offset -= (GS_VMEM_PAGE_SIZE - ctrl_size % GS_VMEM_PAGE_SIZE);
            } else {
                dir->offset += (GS_VMEM_PAGE_SIZE - ctrl_size % GS_VMEM_PAGE_SIZE);
            }
        }
    }

    return curr_dir_count;
}

status_t array_update_ctrl(handle_t session, vm_pool_t *vm_pool, vm_lob_t *vlob,
    uint32 size, uint32 total_dir_cnt, bool32 compress)
{
    uint32 ctrl_size = sizeof(array_head_t) + total_dir_cnt * sizeof(elem_dir_t);
    uint32 dir_cnt = 0;
    uint32 cur_dir_cnt;
    uint32 vmid = vlob->entry_vmid;
    vm_page_t *page = NULL;

    GS_RETURN_IFERR(array_modify_head_offset(session, vm_pool, vmid, total_dir_cnt, size, compress));
    while (dir_cnt != total_dir_cnt) {
        CM_ASSERT(vmid != GS_INVALID_ID32);
        GS_RETURN_IFERR(vm_open(session, vm_pool, vmid, &page));
        
        if (vmid == vlob->entry_vmid) {
            cur_dir_cnt = array_modify_dir_offset(page->data, dir_cnt, ctrl_size, total_dir_cnt, GS_TRUE, compress);
        } else {
            cur_dir_cnt = array_modify_dir_offset(page->data, dir_cnt, ctrl_size, total_dir_cnt, GS_FALSE, compress);
        }
        dir_cnt += cur_dir_cnt;
        
        vm_close(session, vm_pool, vmid, VM_ENQUE_HEAD);
        vmid = vm_get_ctrl(vm_pool, vmid)->sort_next;
    }

    return GS_SUCCESS;
}

/* for vm lob init & extend value page */
status_t array_extend_vm_page(array_assist_t *aa, vm_lob_t *vlob)
{
    if (vm_alloc_and_append(aa->session, aa->pool, aa->list) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (vlob->entry_vmid == GS_INVALID_ID32) {
        vlob->entry_vmid = aa->list->last;
        vlob->last_vmid = aa->list->last;
    } else {
        vm_get_ctrl(aa->pool, vlob->last_vmid)->sort_next = aa->list->last;
        vlob->last_vmid = aa->list->last;
    }

    return GS_SUCCESS;
}

/* for element directory page extend.
   change the pages chain :
        last_dir_page -> first_val_page
   to :
        last_dir_page -> new_dir_page -> first_val_page
*/
status_t array_extend_dir_page(array_assist_t *aa, vm_lob_t *vlob)
{
    uint32 last_dir_vmid;
    uint32 first_val_vmid;
    vm_page_t *page = NULL;
    array_head_t *head = NULL;

    if (vlob->entry_vmid == GS_INVALID_ID32) {
        /* should init & alloc page */
        GS_THROW_ERROR(ERR_ASSERT_ERROR, "array directory extend failed since page not init or alloc");
        return GS_ERROR;
    }

    if (vm_alloc_and_append(aa->session, aa->pool, aa->list) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (vm_open(aa->session, aa->pool, vlob->entry_vmid, &page) != GS_SUCCESS) {
        return GS_ERROR;
    }

    head = (array_head_t *)(page->data);
    last_dir_vmid = array_get_vmid_by_offset(aa, vlob, head->offset - 1);
    first_val_vmid = vm_get_ctrl(aa->pool, last_dir_vmid)->sort_next;

    vm_get_ctrl(aa->pool, aa->list->last)->sort_next = first_val_vmid;
    vm_get_ctrl(aa->pool, last_dir_vmid)->sort_next = aa->list->last;
    head->offset += GS_VMEM_PAGE_SIZE;
    head->size += GS_VMEM_PAGE_SIZE;
    vlob->size += GS_VMEM_PAGE_SIZE;
    vm_close(aa->session, aa->pool, vlob->entry_vmid, VM_ENQUE_TAIL);
    return GS_SUCCESS;
}

status_t array_update_dir_offset(array_assist_t *aa, vm_lob_t *vlob)
{
    array_head_t head;
    vm_page_t *page = NULL;
    elem_dir_t *dir = NULL;
    bool32 switch_page = GS_FALSE;

    GS_RETURN_IFERR(vm_open(aa->session, aa->pool, vlob->entry_vmid, &page));
    head = *(array_head_t *)(page->data);
    dir = (elem_dir_t *)(page->data + sizeof(array_head_t));

    uint32 count = 0;
    uint32 vmid = vlob->entry_vmid;
    while (count < head.count) {
        if (switch_page) {
            vm_close(aa->session, aa->pool, vmid, VM_ENQUE_TAIL);
            vmid = vm_get_ctrl(aa->pool, vmid)->sort_next;
            GS_RETURN_IFERR(vm_open(aa->session, aa->pool, vmid, &page));
            dir = (elem_dir_t *)page->data;
            switch_page = GS_FALSE;
        }

        dir->offset += GS_VMEM_PAGE_SIZE;
        dir++;
        count++;

        if ((char *)dir == page->data + GS_VMEM_PAGE_SIZE) {
            switch_page = GS_TRUE;
        }
    }

    vm_close(aa->session, aa->pool, vmid, VM_ENQUE_TAIL);
    return GS_SUCCESS;
}

uint32 array_get_vmid_by_offset(array_assist_t *aa, vm_lob_t *vlob, uint32 offset)
{
    uint32 vmid;
    uint32 count;

    count = offset / GS_VMEM_PAGE_SIZE;
    vmid = vlob->entry_vmid;
    while (count > 0 && vmid != GS_INVALID_ID32) {
        vmid = vm_get_ctrl(aa->pool, vmid)->sort_next;
        count--;
    }

    return vmid;
}

/* get the free bytes of the last value page
   if no free space, then extend a value page
   the last value page vmid is not equal to the list->last
*/
uint32 array_get_free_bytes(array_assist_t *aa, vm_lob_t *vlob)
{
    uint32 free_bytes;
    vm_page_t *page = NULL;
    array_head_t *head = NULL;

    if (vm_open(aa->session, aa->pool, vlob->entry_vmid, &page) != GS_SUCCESS) {
        return 0;
    }

    head = (array_head_t *)(page->data);
    if (head->size > 0 && (head->size % GS_VMEM_PAGE_SIZE == 0)) {
        free_bytes = 0;
    } else {
        free_bytes = GS_VMEM_PAGE_SIZE - head->size % GS_VMEM_PAGE_SIZE;
    }
    vm_close(aa->session, aa->pool, vlob->entry_vmid, VM_ENQUE_TAIL);

    /* allocate next page */
    if (free_bytes == 0) {
        if (array_extend_vm_page(aa, vlob) != GS_SUCCESS) {
            return 0;
        }

        free_bytes = GS_VMEM_PAGE_SIZE;
    }

    return free_bytes;
}

status_t array_get_value_offset(array_assist_t *aa, vm_lob_t *vlob, uint32 *offset)
{
    array_head_t *head = NULL;
    vm_page_t *page = NULL;

    if (vm_open(aa->session, aa->pool, vlob->entry_vmid, &page) != GS_SUCCESS) {
        return GS_ERROR;
    }

    head = (array_head_t *)(page->data);
    *offset = head->size;
    vm_close(aa->session, aa->pool, vlob->entry_vmid, VM_ENQUE_TAIL);
    return GS_SUCCESS;
}

status_t array_get_value_vmid(array_assist_t *aa, vm_lob_t *vlob, uint32 *vmid, uint32 *offset)
{
    if (array_get_value_offset(aa, vlob, offset) != GS_SUCCESS) {
        return GS_ERROR;
    }

    *vmid = array_get_vmid_by_offset(aa, vlob, *offset);
    if (*vmid == GS_INVALID_ID32) {
        GS_THROW_ERROR(ERR_ASSERT_ERROR, "cannot get array value page");
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

uint32 array_get_last_dir_vmid(array_assist_t *aa, vm_lob_t *vlob)
{
    uint32 vmid;
    uint32 dir_page_cnt;
    array_head_t head;
    vm_page_t *page = NULL;

    if (vm_open(aa->session, aa->pool, vlob->entry_vmid, &page) != GS_SUCCESS) {
        return GS_INVALID_ID32;
    }

    head = *(array_head_t *)(page->data);
    vm_close(aa->session, aa->pool, vlob->entry_vmid, VM_ENQUE_TAIL);

    /* get the last vmid of directory page */
    dir_page_cnt = cm_get_dir_page_count(head.offset);
    vmid = vlob->entry_vmid;
    while (dir_page_cnt > 1 && vmid != GS_INVALID_ID32) {
        dir_page_cnt--;
        vmid = vm_get_ctrl(aa->pool, vmid)->sort_next;
    }

    return vmid;
}

status_t array_get_last_dir_end(array_assist_t *aa, vm_lob_t *vlob, uint32 *dir_end)
{
    array_head_t *head = NULL;
    vm_page_t *page = NULL;

    if (vm_open(aa->session, aa->pool, vlob->entry_vmid, &page) != GS_SUCCESS) {
        return GS_ERROR;
    }

    head = (array_head_t *)(page->data);
    *dir_end = sizeof(array_head_t) + head->count * sizeof(elem_dir_t);
    vm_close(aa->session, aa->pool, vlob->entry_vmid, VM_ENQUE_TAIL);
    return GS_SUCCESS;
}

status_t array_get_last_dir_offset(array_assist_t *aa, vm_lob_t *vlob, uint32 *offset)
{
    array_head_t *head = NULL;
    vm_page_t *page = NULL;

    if (vm_open(aa->session, aa->pool, vlob->entry_vmid, &page) != GS_SUCCESS) {
        return GS_ERROR;
    }

    head = (array_head_t *)(page->data);
    if (head->count == 0) {
        *offset = 0;
    } else {
        *offset = sizeof(array_head_t) + (head->count - 1) * sizeof(elem_dir_t);
    }
    vm_close(aa->session, aa->pool, vlob->entry_vmid, VM_ENQUE_TAIL);
    return GS_SUCCESS;
}

status_t array_get_dimension(array_assist_t *aa, vm_lob_t *vlob, uint32 *dimension)
{
    uint32 vmid;
    uint32 offset;
    vm_page_t *page = NULL;
    elem_dir_t *dir = NULL;

    vmid = array_get_last_dir_vmid(aa, vlob);
    if (vmid == GS_INVALID_ID32) {
        GS_THROW_ERROR(ERR_ASSERT_ERROR, "cannot get array element dimension");
        return GS_ERROR;
    }

    if (array_get_last_dir_offset(aa, vlob, &offset) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (offset == 0) {
        *dimension = 0;
    } else {
        if (vm_open(aa->session, aa->pool, vmid, &page) != GS_SUCCESS) {
            return GS_ERROR;
        }

        dir = (elem_dir_t *)(page->data + offset % GS_VMEM_PAGE_SIZE);
        *dimension = (uint32)dir->subscript;
        vm_close(aa->session, aa->pool, vmid, VM_ENQUE_TAIL);
    }

    return GS_SUCCESS;
}

status_t array_get_element_count(array_assist_t *aa, vm_lob_t *vlob, uint32 *count)
{
    array_head_t *head = NULL;
    vm_page_t *page = NULL;

    if (vm_open(aa->session, aa->pool, vlob->entry_vmid, &page) != GS_SUCCESS) {
        return GS_ERROR;
    }

    head = (array_head_t *)(page->data);
    *count = head->count;
    vm_close(aa->session, aa->pool, vlob->entry_vmid, VM_ENQUE_TAIL);
    return GS_SUCCESS;
}

status_t array_get_element_datatype(array_assist_t *aa, vm_lob_t *vlob, int16 *datatype)
{
    array_head_t *head = NULL;
    vm_page_t *page = NULL;

    if (vm_open(aa->session, aa->pool, vlob->entry_vmid, &page) != GS_SUCCESS) {
        return GS_ERROR;
    }

    head = (array_head_t *)(page->data);
    *datatype = head->datatype;
    vm_close(aa->session, aa->pool, vlob->entry_vmid, VM_ENQUE_TAIL);
    return GS_SUCCESS;
}


status_t array_inc_head_size(array_assist_t *aa, vm_lob_t *vlob, uint32 inc)
{
    array_head_t *head = NULL;
    vm_page_t *page = NULL;

    if (vm_open(aa->session, aa->pool, vlob->entry_vmid, &page) != GS_SUCCESS) {
        return GS_ERROR;
    }

    head = (array_head_t *)(page->data);
    head->size += inc;
    vm_close(aa->session, aa->pool, vlob->entry_vmid, VM_ENQUE_TAIL);
    return GS_SUCCESS;
}

status_t array_inc_head_count(array_assist_t *aa, vm_lob_t *vlob, uint32 inc)
{
    array_head_t *head = NULL;
    vm_page_t *page = NULL;

    if (vm_open(aa->session, aa->pool, vlob->entry_vmid, &page) != GS_SUCCESS) {
        return GS_ERROR;
    }

    head = (array_head_t *)(page->data);
    head->count += inc;
    vm_close(aa->session, aa->pool, vlob->entry_vmid, VM_ENQUE_TAIL);
    return GS_SUCCESS;
}

status_t array_update_head_datatype(array_assist_t *aa, vm_lob_t *vlob, uint32 datatype)
{
    array_head_t *head = NULL;
    vm_page_t *page = NULL;

    if (vm_open(aa->session, aa->pool, vlob->entry_vmid, &page) != GS_SUCCESS) {
        return GS_ERROR;
    }

    head = (array_head_t *)(page->data);
    head->datatype = (int32)datatype;
    vm_close(aa->session, aa->pool, vlob->entry_vmid, VM_ENQUE_TAIL);
    return GS_SUCCESS;
}

status_t array_append_directory(array_assist_t *aa, uint32 subscript, uint32 size,
                                bool8 is_null, bool32 last, vm_lob_t *vlob)
{
    uint32 dir_vmid;
    vm_page_t *page = NULL;
    elem_dir_t *dir = NULL;

    if (array_get_last_dir_end(aa, vlob, &aa->dir_curr) != GS_SUCCESS) {
        return GS_ERROR;
    }

    /* need extend pages for element directory if the current page has not enough space */
    if (aa->dir_curr > 0 && aa->dir_curr % GS_VMEM_PAGE_SIZE == 0) {
        if (array_extend_dir_page(aa, vlob) != GS_SUCCESS) {
            return GS_ERROR;
        }

        // update offset in old directory
        GS_RETURN_IFERR(array_update_dir_offset(aa, vlob));
    }
    /* reset prev element last flag */
    if (aa->dir_curr > sizeof(elem_dir_t)) {
        dir_vmid = array_get_vmid_by_offset(aa, vlob, aa->dir_curr - sizeof(elem_dir_t));
        if (dir_vmid == GS_INVALID_ID32) {
            GS_THROW_ERROR(ERR_ASSERT_ERROR, "cannot get array prev element directory");
            return GS_ERROR;
        }

        if (vm_open(aa->session, aa->pool, dir_vmid, &page) != GS_SUCCESS) {
            return GS_ERROR;
        }

        dir = (elem_dir_t *)(page->data + (aa->dir_curr - sizeof(elem_dir_t)) % GS_VMEM_PAGE_SIZE);
        dir->last = GS_FALSE;
        vm_close(aa->session, aa->pool, dir_vmid, VM_ENQUE_TAIL);
    }
    /* find the directory page to append the directory */
    dir_vmid = array_get_vmid_by_offset(aa, vlob, aa->dir_curr);
    if (dir_vmid == GS_INVALID_ID32) {
        GS_THROW_ERROR(ERR_ASSERT_ERROR, "cannot get array directory page");
        return GS_ERROR;
    }

    if (vm_open(aa->session, aa->pool, dir_vmid, &page) != GS_SUCCESS) {
        return GS_ERROR;
    }

    dir = (elem_dir_t *)(page->data + aa->dir_curr % GS_VMEM_PAGE_SIZE);
    /* set subscript */
    dir->subscript = (int32)subscript;
    /* set offset */
    if (array_get_value_offset(aa, vlob, &dir->offset) != GS_SUCCESS) {
        vm_close(aa->session, aa->pool, dir_vmid, VM_ENQUE_TAIL);
        return GS_ERROR;
    }
    /* set element values size */
    dir->size = size;
    /* is the last element of the array */
    dir->last = last;

    if (dir->size == 0 && is_null == GS_TRUE) {
        dir->offset = ELEMENT_NULL_OFFSET;
    }

    vm_close(aa->session, aa->pool, dir_vmid, VM_ENQUE_TAIL);
    return GS_SUCCESS;
}

status_t array_append_value(array_assist_t *aa, char *value, uint32 size_input, vm_lob_t *vlob)
{
    errno_t err;
    uint32 free_bytes;
    uint32 write_bytes;
    uint32 val_vmid;
    uint32 val_offset;
    char *val_addr = NULL;
    vm_page_t *page = NULL;
    uint32 size = size_input;
    
    while (size > 0) {
        free_bytes = array_get_free_bytes(aa, vlob);
        if (free_bytes == 0) {
            GS_THROW_ERROR(ERR_NO_FREE_VMEM, "can't allocate page from virtual memory pool");
            return GS_ERROR;
        }

        if (array_get_value_vmid(aa, vlob, &val_vmid, &val_offset) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (vm_open(aa->session, aa->pool, val_vmid, &page) != GS_SUCCESS) {
            return GS_ERROR;
        }

        write_bytes = MIN(free_bytes, size);
        val_addr = page->data + val_offset % GS_VMEM_PAGE_SIZE;
        err = memcpy_sp(val_addr, free_bytes, value, write_bytes);
        if (err != EOK) {
            vm_close(aa->session, aa->pool, val_vmid, VM_ENQUE_HEAD);
            GS_THROW_ERROR(ERR_SYSTEM_CALL, err);
            return GS_ERROR;
        }

        vm_close(aa->session, aa->pool, val_vmid, VM_ENQUE_TAIL);
        if (array_inc_head_size(aa, vlob, write_bytes) != GS_SUCCESS) {
            return GS_ERROR;
        }
        vlob->size += write_bytes;
        size -= write_bytes;
        value += write_bytes;
    }

    return GS_SUCCESS;
}

status_t array_append_element(array_assist_t *aa, uint32 subscript, void *data, uint32 size, bool8 is_null,
                              bool32 last, vm_lob_t *vlob)
{
    if (array_append_directory(aa, subscript, size, is_null, last, vlob) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (array_inc_head_count(aa, vlob, 1) != GS_SUCCESS) {
        return GS_ERROR;
    }

    /* null element, only keep the directory */
    if (size == 0) {
        return GS_SUCCESS;
    }

    return array_append_value(aa, data, size, vlob);
}

static inline status_t cm_check_bufsize_and_set_stat(uint32 buf_size, uint32 need_len, status_t* status)
{
    if (buf_size < need_len + 1) {
        GS_THROW_ERROR(ERR_BUFFER_OVERFLOW, need_len + 1, buf_size);
        *status = GS_ERROR;
    } else {
        *status = GS_SUCCESS;
    }

    return *status;
}

status_t cm_element_as_string(array_assist_t *aa, const nlsparams_t *nls, var_array_t *var,
                              elem_dir_t *dir, text_t *text, uint32 max_buf_size)
{
    char *data = NULL;
    uint32 buf_size;
    text_t ele_text;
    text_t fmt_text;
    status_t status = GS_SUCCESS;
    timestamp_tz_t tstz;
    timestamp_ltz_t v_tstamp_ltz;
    vm_lob_t *vlob = &var->value.vm_lob;
    dec2_t d2;

    data = text->str + text->len;
    buf_size = max_buf_size - text->len;
    ele_text.str = data;
    ele_text.len = 0;

    if (dir->size == 0) {
        if (dir->offset == ELEMENT_NULL_OFFSET) {
            return cm_concat_string(text, max_buf_size, "NULL");
        } else {
            return GS_SUCCESS;
        }
    }
    
    if (array_get_value_by_dir(aa, data, buf_size, vlob, dir) != GS_SUCCESS) {
        return GS_ERROR;
    }

    switch (var->type) {
        case GS_TYPE_STRING:
        case GS_TYPE_CHAR:
        case GS_TYPE_VARCHAR:
            /* the string is already in the buffer */
            ele_text.len = dir->size;
            break;

        case GS_TYPE_UINT32:
            GS_BREAK_IF_ERROR(cm_check_bufsize_and_set_stat(buf_size, GS_MAX_UINT32_STRLEN, &status));
            cm_uint32_to_text(*(uint32 *)data, &ele_text);
            break;

        case GS_TYPE_INTEGER:
            GS_BREAK_IF_ERROR(cm_check_bufsize_and_set_stat(buf_size, GS_MAX_INT32_STRLEN, &status));
            cm_int2text(*(int32 *)data, &ele_text);
            break;

        case GS_TYPE_BOOLEAN:
            GS_BREAK_IF_ERROR(cm_check_bufsize_and_set_stat(buf_size, GS_MAX_BOOL_STRLEN, &status));
            cm_bool2text(*(bool32 *)data, &ele_text);
            break;

        case GS_TYPE_BIGINT:
            GS_BREAK_IF_ERROR(cm_check_bufsize_and_set_stat(buf_size, GS_MAX_INT64_STRLEN, &status));
            cm_bigint2text(*(int64 *)data, &ele_text);
            break;

        case GS_TYPE_REAL:
            GS_BREAK_IF_ERROR(cm_check_bufsize_and_set_stat(buf_size, GS_MAX_REAL_OUTPUT_STRLEN, &status));
            cm_real2text(*(double *)data, &ele_text);
            break;

        case GS_TYPE_NUMBER:
        case GS_TYPE_DECIMAL:
            status = cm_dec4_to_text((const dec4_t *)data, GS_MAX_DEC_OUTPUT_PREC, &ele_text);
            break;
        case GS_TYPE_NUMBER2:
            cm_dec2_copy_ex(&d2, (const payload_t *)data, (uint8)dir->size);
            status = cm_dec2_to_text(&d2, GS_MAX_DEC_OUTPUT_PREC, &ele_text);
            break;
        case GS_TYPE_DATE:
            nls->param_geter(nls, NLS_DATE_FORMAT, &fmt_text);
            status = cm_date2text(*(date_t *)data, &fmt_text, &ele_text, buf_size);
            break;

        case GS_TYPE_TIMESTAMP:
        case GS_TYPE_TIMESTAMP_TZ_FAKE:
            nls->param_geter(nls, NLS_TIMESTAMP_FORMAT, &fmt_text);
            status = cm_timestamp2text(*(timestamp_t *)data, &fmt_text, &ele_text, buf_size);
            break;

        case GS_TYPE_TIMESTAMP_TZ:
            tstz = *(timestamp_tz_t *)data;
            nls->param_geter(nls, NLS_TIMESTAMP_TZ_FORMAT, &fmt_text);
            status = cm_timestamp_tz2text(&tstz, &fmt_text, &ele_text, buf_size);
            break;

        case GS_TYPE_TIMESTAMP_LTZ: {
            nls->param_geter(nls, NLS_TIMESTAMP_FORMAT, &fmt_text);
            /* convert from dbtiomezone to sessiontimezone */
            v_tstamp_ltz = *(timestamp_ltz_t*)data;
            v_tstamp_ltz = cm_adjust_date_between_two_tzs(v_tstamp_ltz, cm_get_db_timezone(),
                                                          cm_get_session_time_zone(nls));
            status = cm_timestamp2text(v_tstamp_ltz, &fmt_text, &ele_text, buf_size);
            break;
        }

        case GS_TYPE_INTERVAL_DS:
            cm_dsinterval2text(*(interval_ds_t *)data, &ele_text);
            break;

        case GS_TYPE_INTERVAL_YM:
            cm_yminterval2text(*(interval_ym_t *)data, &ele_text);
            break;

        default:
            GS_SET_ERROR_MISMATCH(GS_TYPE_STRING, var->type);
            return GS_ERROR;
    }

    GS_RETURN_IFERR(status);
    text->len += ele_text.len;
    return GS_SUCCESS;
}

status_t cm_array2text(const nlsparams_t *nls, var_array_t *var, text_t *text)
{
    uint32 dir_start, dir_end, dir_vmid, curr_vmid;
    elem_dir_t *dir = NULL;
    vm_page_t *dir_page = NULL;
    array_assist_t aa;
    uint32 max_buf_size = text->len;
    bool32 switch_page = GS_TRUE;
    text->len = 0;

    if (tls_session_handle == NULL || tls_pool_handle == NULL) {
        GS_THROW_ERROR(ERR_ARRAY_TO_STR_FAILED);
        return GS_ERROR;
    }

    aa.session = tls_session_handle;
    aa.pool = (vm_pool_t *)tls_pool_handle;
    GS_RETURN_IFERR(array_get_last_dir_end(&aa, &var->value.vm_lob, &dir_end));

    dir_start = sizeof(array_head_t);
    dir_vmid = var->value.vm_lob.entry_vmid;

    GS_RETURN_IFERR(cm_concat_string(text, max_buf_size, "{"));
    while (dir_start < dir_end && dir_vmid != GS_INVALID_ID32) {
        if (switch_page && vm_open(aa.session, aa.pool, dir_vmid, &dir_page) != GS_SUCCESS) {
            return GS_ERROR;
        }
        dir = (elem_dir_t *)(dir_page->data + dir_start % GS_VMEM_PAGE_SIZE);
        /* convert element value to string */
        if (cm_element_as_string(&aa, nls, var, dir, text, max_buf_size) != GS_SUCCESS) {
            vm_close(aa.session, aa.pool, dir_vmid, VM_ENQUE_TAIL);
            return GS_ERROR;
        }

        if (dir_start + sizeof(elem_dir_t) < dir_end) {
            if (cm_concat_string(text, max_buf_size, ",") != GS_SUCCESS) {
                vm_close(aa.session, aa.pool, dir_vmid, VM_ENQUE_TAIL);
                return GS_ERROR;
            }
        }

        curr_vmid = dir_vmid;
        if (dir_start % GS_VMEM_PAGE_SIZE + sizeof(elem_dir_t) >= GS_VMEM_PAGE_SIZE) {
            dir_vmid = vm_get_ctrl(aa.pool, dir_vmid)->sort_next;
            switch_page = GS_TRUE;
        } else {
            switch_page = GS_FALSE;
        }

        dir_start += sizeof(elem_dir_t);
        /* switch to next page or no elements need to convert, then close the current vm page */
        if (switch_page == GS_TRUE || dir_start >= dir_end || dir_vmid == GS_INVALID_ID32) {
            vm_close(aa.session, aa.pool, curr_vmid, VM_ENQUE_TAIL);
        }
    }

    return cm_concat_string(text, max_buf_size, "}");
}

status_t array_init(array_assist_t *aa, handle_t session, vm_pool_t *pool, id_list_t *list, vm_lob_t *vlob)
{
    vm_page_t *page = NULL;

    aa->session = session;
    aa->pool = pool;
    aa->list = list;
    cm_reset_vm_lob(vlob);

    /* allocate at least 1 pages for element directory */
    if (array_extend_vm_page(aa, vlob) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (vm_open(session, pool, vlob->entry_vmid, &page) != GS_SUCCESS) {
        return GS_ERROR;
    }

    aa->buf = page->data;
    aa->head = (array_head_t *)page->data;
    aa->dir_curr = sizeof(array_head_t);
    aa->dir_end = sizeof(array_head_t);
    aa->head->size = GS_VMEM_PAGE_SIZE;
    aa->head->count = 0;
    aa->head->offset = GS_VMEM_PAGE_SIZE;
    vm_close(session, pool, vlob->entry_vmid, VM_ENQUE_HEAD);
    vlob->size = GS_VMEM_PAGE_SIZE;
    return GS_SUCCESS;
}

static void cm_search_dir_in_page(array_search_assist_t *sa, uint32 *dir_vmid, uint32 *dir_offset)
{
    elem_dir_t *start_dir = NULL;
    elem_dir_t *end_dir = NULL;
    elem_dir_t *mid_dir = NULL;
    elem_dir_t *dst_dir = NULL;
    
    if (sa->vmid == sa->vlob->entry_vmid) {
        start_dir = (elem_dir_t *)(sa->page->data + sa->dir_start);
    } else {
        start_dir = (elem_dir_t *)(sa->page->data);
    }
    
    end_dir = cm_get_array_end_dir(sa->page->data, sa->dir_end, sa->last_dir_page);

    /* try to find the element directory in the page */
    while (start_dir <= end_dir) {
        mid_dir = start_dir + (((char *)end_dir - (char *)start_dir) / sizeof(elem_dir_t)) / 2;
        if (sa->mode == ARRAY_SEARCH_EQUAL) {
            if (mid_dir->subscript == sa->subscript) {
                dst_dir = mid_dir;
                break;
            } else if (mid_dir->subscript < sa->subscript) {
                start_dir = mid_dir + 1;
            } else {
                end_dir = mid_dir - 1;
            }
        } else if (sa->mode == ARRAY_SEARCH_FIRST) {
            if (mid_dir->subscript >= sa->subscript) {
                dst_dir = mid_dir;
                end_dir = mid_dir - 1;
            } else {
                start_dir = mid_dir + 1;
            }
        }
    }

    /* dst_dir is the first element dir to find */
    if (dst_dir != NULL) {
        *dir_vmid = sa->vmid;
        *dir_offset = (uint32)((char *)dst_dir - sa->page->data);
    } else {
        *dir_vmid = GS_INVALID_ID32;
        *dir_offset = 0;
    }
}

/* find the element directory fits the requirements */
static status_t cm_find_dir(array_assist_t *aa, vm_lob_t *src_lob, int subscript,
                            uint32 *id, uint32 *offset, array_search_mode mode)
{
    uint32 dir_page_count;
    uint32 dir_start;
    uint32 dir_end;
    uint32 vmid;
    vm_page_t *page = NULL;
    array_head_t head;
    elem_dir_t *end_dir = NULL;
    array_search_assist_t sa;
    bool32 last_dir_page;

    if (vm_open(aa->session, aa->pool, src_lob->entry_vmid, &page) != GS_SUCCESS) {
        return GS_ERROR;
    }

    head = *(array_head_t *)page->data;
    vm_close(aa->session, aa->pool, src_lob->entry_vmid, VM_ENQUE_HEAD);

    /* no elements */
    if (head.count == 0) {
        *id = GS_INVALID_ID32;
        *offset = 0;
        return GS_SUCCESS;
    }

    dir_start = sizeof(array_head_t);
    dir_end = dir_start + (head.count - 1) * sizeof(elem_dir_t);
    dir_page_count = cm_get_dir_page_count(head.offset);

    vmid = src_lob->entry_vmid;
    for (uint32 i = 1; i <= dir_page_count; i++) {
        if (vm_open(aa->session, aa->pool, vmid, &page) != GS_SUCCESS) {
            return GS_ERROR;
        }

        last_dir_page = ((i == dir_page_count) ? GS_TRUE : GS_FALSE);
        end_dir = cm_get_array_end_dir(page->data, dir_end, last_dir_page);
        /* hit : the find element directory in this page */
        if (end_dir->subscript == subscript) {
            *id = vmid;
            *offset = (uint32)((char *)end_dir - page->data);
            vm_close(aa->session, aa->pool, vmid, VM_ENQUE_HEAD);
            return GS_SUCCESS;
        }

        /* the element directory is in the next page */
        if (end_dir->subscript < subscript) {
            /* try to find start element in next page */
            vm_close(aa->session, aa->pool, vmid, VM_ENQUE_HEAD);
            vmid = vm_get_ctrl(aa->pool, vmid)->sort_next;
            continue;
        } else {
            /* found the page of the current page  */
            sa.vlob = src_lob;
            sa.page = page;
            sa.vmid = vmid;
            sa.subscript = subscript;
            sa.dir_start = dir_start;
            sa.dir_end = dir_end;
            sa.mode = mode;
            sa.last_dir_page = last_dir_page;
            cm_search_dir_in_page(&sa, id, offset);
            vm_close(aa->session, aa->pool, vmid, VM_ENQUE_HEAD);
            return GS_SUCCESS;
        }
    }

    *id = GS_INVALID_ID32;
    *offset = 0;
    return GS_SUCCESS;
}

/* find the element directory that element.subscript == subscript */
static status_t cm_find_equal_dir(array_assist_t *aa, vm_lob_t *src_lob, int subscript, uint32 *id, uint32 *offset)
{
    return cm_find_dir(aa, src_lob, subscript, id, offset, ARRAY_SEARCH_EQUAL);
}

/* find the first element directory that element.subscript >= subscript */
static status_t cm_find_first_dir(array_assist_t *aa, vm_lob_t *src_lob, int subscript, uint32 *id, uint32 *offset)
{
    uint32 count;
    /* need fetch all elements, start from the first */
    if (subscript == GS_INVALID_ID32 || subscript == 1) {
        if (array_get_element_count(aa, src_lob, &count) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (count > 0) {
            *id = src_lob->entry_vmid;
            *offset = sizeof(array_head_t);
        } else {
            *id = GS_INVALID_ID32;
            *offset = 0;
        }

        return GS_SUCCESS;
    }

    return cm_find_dir(aa, src_lob, subscript, id, offset, ARRAY_SEARCH_FIRST);
}

static bool32 cm_subscript_in_range(int subscript, int start, int end)
{
    if (start == GS_INVALID_ID32 && end == GS_INVALID_ID32) {
        return GS_TRUE;
    }

    if (end != GS_INVALID_ID32) {
        return (bool32)(subscript >= start && subscript <= end);
    } else {
        return (bool32)(subscript == start);
    }
}

static status_t array_copy_element(array_assist_t *src_aa, vm_lob_t *src_lob, elem_dir_t *dir,
                                   array_assist_t *dst_aa, vm_lob_t *dst_lob, uint32 new_subscript)
{
    uint32 offset;
    uint32 val_vmid;
    char *value = NULL;
    uint32 size;
    uint32 copy_size;
    vm_page_t *val_page = NULL;

    /* copy dir */
    if (array_append_directory(dst_aa, new_subscript, dir->size, ELEMENT_IS_NULL(dir), GS_TRUE,
                               dst_lob) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (array_inc_head_count(dst_aa, dst_lob, 1) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (dir->size == 0) {
        return GS_SUCCESS;
    }
    /* copy value from src_lob to dst_lob */
    val_vmid = array_get_vmid_by_offset(src_aa, src_lob, dir->offset);
    if (val_vmid == GS_INVALID_ID32) {
        GS_THROW_ERROR(ERR_ASSERT_ERROR, "cannot get next page to store array element value");
        return GS_ERROR;
    }

    size = dir->size;
    offset = dir->offset;
    while (size > 0) {
        if (vm_open(src_aa->session, src_aa->pool, val_vmid, &val_page) != GS_SUCCESS) {
            return GS_ERROR;
        }

        value = val_page->data + offset % GS_VMEM_PAGE_SIZE;
        copy_size = MIN(size, GS_VMEM_PAGE_SIZE - offset % GS_VMEM_PAGE_SIZE);
        if (array_append_value(dst_aa, value, copy_size, dst_lob) != GS_SUCCESS) {
            vm_close(src_aa->session, src_aa->pool, val_vmid, VM_ENQUE_TAIL);
            return GS_ERROR;
        }

        vm_close(src_aa->session, src_aa->pool, val_vmid, VM_ENQUE_TAIL);
        /* next page */
        size -= copy_size;
        if (size > 0) {
            val_vmid = vm_get_ctrl(src_aa->pool, val_vmid)->sort_next;
            if (val_vmid == GS_INVALID_ID32) {
                return GS_ERROR;
            }
        }
        offset += copy_size;
    }

    return GS_SUCCESS;
}

static status_t cm_get_elements_value(subarray_assist_t *sa)
{
    vm_page_t *dir_page = NULL;
    elem_dir_t *dir = NULL;
    handle_t session = sa->src_aa->session;
    vm_pool_t *pool = sa->src_aa->pool;
    bool32 swith_page = GS_TRUE;
    uint32 curr_vmid;
    uint32 new_subscript = 1; /* temp array subscript should start with 1 */

    while (sa->dir_vmid != GS_INVALID_ID32) {
        if (swith_page) {
            if (vm_open(session, pool, sa->dir_vmid, &dir_page) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }

        dir = (elem_dir_t *)(dir_page->data + sa->dir_offset);
        if (cm_subscript_in_range(dir->subscript, sa->start, sa->end)) {
            if (array_copy_element(sa->src_aa, sa->src_vlob, dir,
                                   &sa->dst_aa, sa->dst_vlob, new_subscript) != GS_SUCCESS) {
                vm_close(session, pool, sa->dir_vmid, VM_ENQUE_TAIL);
                return GS_ERROR;
            }
            new_subscript++;
        } else {
            /* element is not in [start:end] */
            vm_close(session, pool, sa->dir_vmid, VM_ENQUE_TAIL);
            break;
        }

        /* is the last element's directory, no more elements */
        if (dir->last == GS_TRUE) {
            vm_close(session, pool, sa->dir_vmid, VM_ENQUE_TAIL);
            break;
        }

        curr_vmid = sa->dir_vmid;
        sa->dir_offset = (sa->dir_offset + sizeof(elem_dir_t)) % GS_VMEM_PAGE_SIZE;
        if (sa->dir_offset == 0) {
            sa->dir_vmid = vm_get_ctrl(pool, sa->dir_vmid)->sort_next;
            swith_page = GS_TRUE;
        } else {
            swith_page = GS_FALSE;
        }

        if (swith_page || sa->dir_vmid == GS_INVALID_ID32) {
            vm_close(session, pool, curr_vmid, VM_ENQUE_TAIL);
        }
    }

    return GS_SUCCESS;
}

status_t array_get_subarray(array_assist_t *aa, vm_lob_t *src_lob, vm_lob_t *dst_lob, int32 start, int32 end)
{
    subarray_assist_t sa;

    /* get all, not need to find */
    if (start == GS_INVALID_ID32 && end == GS_INVALID_ID32) {
        *dst_lob = *src_lob;
        return GS_SUCCESS;
    }

    /* should init first for empty array */
    if (array_init(&sa.dst_aa, aa->session, aa->pool, aa->list, dst_lob) != GS_SUCCESS) {
        return GS_ERROR;
    }

    /* try to find the start element's directory in the vm lob, return page id & directory offset */
    if (cm_find_first_dir(aa, src_lob, start, &sa.dir_vmid, &sa.dir_offset) != GS_SUCCESS) {
        return GS_ERROR;
    } else if (sa.dir_vmid != GS_INVALID_ID32) {
        sa.src_aa = aa;
        sa.src_vlob = src_lob;
        sa.dst_vlob = dst_lob;
        sa.start = start;
        sa.end = end;
        return cm_get_elements_value(&sa);
    }

    /* no element found, return null */
    return GS_SUCCESS;
}

status_t array_get_value_by_dir(array_assist_t *aa, char *buf, uint32 size_input, vm_lob_t *vlob, elem_dir_t *dir)
{
    errno_t err;
    uint32 remain_size;
    uint32 copy_size;
    uint32 val_vmid;
    char *ele_val = NULL;
    vm_page_t *page = NULL;
    uint32 size = size_input;

    val_vmid = array_get_vmid_by_offset(aa, vlob, dir->offset);
    if (val_vmid == GS_INVALID_ID32) {
        GS_THROW_ERROR(ERR_ASSERT_ERROR, "cannot get array element value");
        return GS_ERROR;
    }

    if (vm_open(aa->session, aa->pool, val_vmid, &page) != GS_SUCCESS) {
        return GS_ERROR;
    }

    ele_val = page->data + dir->offset % GS_VMEM_PAGE_SIZE;
    remain_size = dir->size;

    if (remain_size > size) {
        vm_close(aa->session, aa->pool, val_vmid, VM_ENQUE_TAIL);
        GS_THROW_ERROR(ERR_BUFFER_OVERFLOW, dir->size, size);
        return GS_ERROR;
    }

    copy_size = MIN(remain_size, GS_VMEM_PAGE_SIZE - dir->offset % GS_VMEM_PAGE_SIZE);
    while (copy_size > 0) {
        err = memcpy_sp(buf, size, ele_val, copy_size);
        if (err != EOK) {
            vm_close(aa->session, aa->pool, val_vmid, VM_ENQUE_TAIL);
            GS_THROW_ERROR(ERR_SYSTEM_CALL, err);
            return GS_ERROR;
        }

        vm_close(aa->session, aa->pool, val_vmid, VM_ENQUE_TAIL);
        /* get the remain value part from the next page */
        remain_size -= copy_size;
        buf += copy_size;
        size -= copy_size;
        copy_size = MIN(GS_VMEM_PAGE_SIZE, remain_size);
        if (copy_size > 0) {
            val_vmid = vm_get_ctrl(aa->pool, val_vmid)->sort_next;
            if (val_vmid == GS_INVALID_ID32) {
                GS_THROW_ERROR(ERR_ASSERT_ERROR, "cannot get array element value");
                return GS_ERROR;
            }
            if (vm_open(aa->session, aa->pool, val_vmid, &page) != GS_SUCCESS) {
                return GS_ERROR;
            }

            ele_val = page->data;
        }
    }

    return GS_SUCCESS;
}

/* get element size and offset */
status_t array_get_element_info(array_assist_t *aa, uint32 *size, uint32 *offset, vm_lob_t *vlob, uint32 subscript)
{
    uint32 dir_offset;
    uint32 dir_vmid;
    elem_dir_t *dir = NULL;
    vm_page_t *dir_page = NULL;

    if (cm_find_equal_dir(aa, vlob, (int)subscript, &dir_vmid, &dir_offset) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (dir_vmid == GS_INVALID_ID32) {
        /* can not find the element with the subscript,
           element value is null */
        *size = 0;
        return GS_SUCCESS;
    }

    if (vm_open(aa->session, aa->pool, dir_vmid, &dir_page) != GS_SUCCESS) {
        return GS_ERROR;
    }
    /* return the element size */
    dir = (elem_dir_t *)(dir_page->data + dir_offset);
    *size = dir->size;
    if (offset != NULL) {
        *offset = dir->offset;
    }
    vm_close(aa->session, aa->pool, dir_vmid, VM_ENQUE_TAIL);
    return GS_SUCCESS;
}

status_t array_get_element_by_subscript(array_assist_t *aa, char *buf, uint32 size, vm_lob_t *vlob, uint32 subscript)
{
    uint32 dir_offset;
    uint32 dir_vmid;
    elem_dir_t dir;
    vm_page_t *dir_page = NULL;

    if (cm_find_equal_dir(aa, vlob, (int)subscript, &dir_vmid, &dir_offset) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (dir_vmid == GS_INVALID_ID32) {
        /* can not find the element with the subscript */
        return GS_SUCCESS;
    }

    if (vm_open(aa->session, aa->pool, dir_vmid, &dir_page) != GS_SUCCESS) {
        return GS_ERROR;
    }
    /* get an element & value */
    dir = *(elem_dir_t *)(dir_page->data + dir_offset);
    vm_close(aa->session, aa->pool, dir_vmid, VM_ENQUE_TAIL);

    if (array_get_value_by_dir(aa, buf, size, vlob, &dir) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

/* update an element's value, the size may changed:
   if the the updated size > element.size, then move the value of the element to end of the last page,
   and update the directory.offset
*/
status_t array_update_element_by_dir(array_assist_t *aa, char *data, uint32 size,
                                     elem_dir_t *dir, vm_lob_t *vlob)
{
    errno_t ret;
    uint32 val_vmid;
    vm_page_t *val_page = NULL;

    /* set the element to null */
    if (size == 0) {
        dir->offset = ELEMENT_NULL_OFFSET;
        dir->size = 0;
        return GS_SUCCESS;
    }

    if (dir->size >= size) {
        val_vmid = array_get_vmid_by_offset(aa, vlob, dir->offset);
        if (val_vmid == GS_INVALID_ID32) {
            GS_THROW_ERROR(ERR_ASSERT_ERROR, "cannot update array element value");
            return GS_ERROR;
        }

        if (vm_open(aa->session, aa->pool, val_vmid, &val_page) != GS_SUCCESS) {
            return GS_ERROR;
        }

        ret = memcpy_sp(val_page->data + dir->offset % GS_VMEM_PAGE_SIZE, size, data, size);
        if (ret != EOK) {
            vm_close(aa->session, aa->pool, val_vmid, VM_ENQUE_TAIL);
            GS_THROW_ERROR(ERR_SYSTEM_CALL, ret);
            return GS_ERROR;
        }
        vm_close(aa->session, aa->pool, val_vmid, VM_ENQUE_TAIL);
    } else {
        /* append the value at the end of the last value page, and update the directory offset.
           no need to change other elements' value offset
        */
        if (array_get_value_offset(aa, vlob, &dir->offset) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (array_append_value(aa, data, size, vlob) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    dir->size = size;
    return GS_SUCCESS;
}

static status_t array_move_dir(array_assist_t *aa, vm_lob_t *vlob, uint32 vmid,
                               bool32 first, bool32 last, uint32 offset)
{
    errno_t err;
    uint32 next_vmid;
    uint32 start = 0;
    uint32 end = GS_VMEM_PAGE_SIZE;
    uint32 dir_end;
    vm_page_t *next_page = NULL;
    vm_page_t *page = NULL;
    array_head_t *head = NULL;

    if (vm_open(aa->session, aa->pool, vlob->entry_vmid, &page) != GS_SUCCESS) {
        return GS_ERROR;
    }
    head = (array_head_t *)(page->data);
    dir_end = sizeof(array_head_t) + head->count * sizeof(elem_dir_t);
    vm_close(aa->session, aa->pool, vlob->entry_vmid, VM_ENQUE_TAIL);

    if (first) {
        start = offset;
    }

    if (last) {
        end = dir_end % GS_VMEM_PAGE_SIZE;
    }

    if (start + sizeof(elem_dir_t) > end) {
        return GS_SUCCESS;
    }

    if (vm_open(aa->session, aa->pool, vmid, &page) != GS_SUCCESS) {
        return GS_ERROR;
    }

    /* the last dir in current page should move to the next page */
    if (end + sizeof(elem_dir_t) > GS_VMEM_PAGE_SIZE) {
        if (last) {
            /* should extend a new dir page first */
            if (array_extend_dir_page(aa, vlob) != GS_SUCCESS) {
                vm_close(aa->session, aa->pool, vmid, VM_ENQUE_TAIL);
                return GS_ERROR;
            }
            if (array_update_dir_offset(aa, vlob) != GS_SUCCESS) {
                vm_close(aa->session, aa->pool, vmid, VM_ENQUE_TAIL);
                return GS_ERROR;
            }
            next_vmid = aa->list->last;
        } else {
            next_vmid = vm_get_ctrl(aa->pool, vmid)->sort_next;
        }

        if (vm_open(aa->session, aa->pool, next_vmid, &next_page) != GS_SUCCESS) {
            vm_close(aa->session, aa->pool, vmid, VM_ENQUE_TAIL);
            return GS_ERROR;
        }
        /* copy the last dir of the current page to the next page */
        err = memmove_s(next_page->data, sizeof(elem_dir_t),
                        page->data + end - sizeof(elem_dir_t), sizeof(elem_dir_t));
        if (err != EOK) {
            vm_close(aa->session, aa->pool, next_vmid, VM_ENQUE_TAIL);
            vm_close(aa->session, aa->pool, vmid, VM_ENQUE_TAIL);
            GS_THROW_ERROR(ERR_SYSTEM_CALL, err);
            return GS_ERROR;
        }

        vm_close(aa->session, aa->pool, next_vmid, VM_ENQUE_TAIL);

        /* move dir data in current page */
        err = memmove_s(page->data + start + sizeof(elem_dir_t), end - start - sizeof(elem_dir_t),
                        page->data + start, end - start - sizeof(elem_dir_t));
        if (err != EOK) {
            vm_close(aa->session, aa->pool, vmid, VM_ENQUE_TAIL);
            GS_THROW_ERROR(ERR_SYSTEM_CALL, err);
            return GS_ERROR;
        }
    } else {
        /* move dir data in current page */
        err = memmove_s(page->data + start + sizeof(elem_dir_t), end - start,
                        page->data + start, end - start);
        if (err != EOK) {
            vm_close(aa->session, aa->pool, vmid, VM_ENQUE_TAIL);
            GS_THROW_ERROR(ERR_SYSTEM_CALL, err);
            return GS_ERROR;
        }
    }

    vm_close(aa->session, aa->pool, vmid, VM_ENQUE_TAIL);
    return GS_SUCCESS;
}

/* move all the directories to the next position start from dir */
static status_t array_shift_dir(array_assist_t *aa, vm_lob_t *vlob, uint32 dir_vmid, uint32 dir_offset)
{
    uint32 last_vmid;
    uint32 curr_vmid;
    uint32 proc_vmid;
    uint32 temp_vmid;
    bool32 first = GS_FALSE;
    bool32 last = GS_TRUE;

    /* now curr_vmid is the last vmid of directory page */
    last_vmid = array_get_last_dir_vmid(aa, vlob);
    curr_vmid = last_vmid;
    while (curr_vmid != GS_INVALID_ID32) {
        /* move dir data */
        first = (bool32)(curr_vmid == dir_vmid);
        last = (bool32)(curr_vmid == last_vmid);
        if (array_move_dir(aa, vlob, curr_vmid, first, last, dir_offset) != GS_SUCCESS) {
            return GS_ERROR;
        }

        /* all dir pages processed */
        if (first) {
            break;
        }

        proc_vmid = curr_vmid;
        /* get the prev page vmid */
        temp_vmid = vlob->entry_vmid;
        while (temp_vmid != proc_vmid) {
            curr_vmid = temp_vmid;
            temp_vmid = vm_get_ctrl(aa->pool, temp_vmid)->sort_next;
        }
    }

    return GS_SUCCESS;
}

status_t array_insert_element(array_assist_t *aa, char *data, uint32 size, uint32 subscript, vm_lob_t *vlob,
                              elem_dir_t *dir, uint32 dir_vmid, uint32 dir_offset)
{
    /* insert a new directory before the directory found */
    if (array_shift_dir(aa, vlob, dir_vmid, dir_offset) != GS_SUCCESS) {
        return GS_ERROR;
    }
    
    /* update the new directory information */
    dir->subscript = (int32)subscript;
    dir->size = size;
    dir->last = GS_FALSE;

    if (array_inc_head_count(aa, vlob, 1) != GS_SUCCESS) {
        return GS_ERROR;
    }

    /* null element */
    if (size == 0) {
        dir->offset = 0;
        return GS_SUCCESS;
    }

    if (array_get_value_offset(aa, vlob, &dir->offset) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (array_append_value(aa, data, size, vlob) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t array_update_element_by_subscript(array_assist_t *aa, char *data, uint32 size, bool8 is_null,
                                           uint32 subscript, vm_lob_t *vlob)
{
    uint32 dir_vmid;
    uint32 dir_offset;
    vm_page_t *page = NULL;
    elem_dir_t *dir = NULL;

    if (cm_find_first_dir(aa, vlob, (int)subscript, &dir_vmid, &dir_offset) != GS_SUCCESS) {
        return GS_ERROR;
    }

    /* the element does not exist, and subscript > all elements
       need add a new element
    */
    if (dir_vmid == GS_INVALID_ID32) {
        return array_append_element(aa, subscript, data, size, is_null, GS_TRUE, vlob);
    }

    if (vm_open(aa->session, aa->pool, dir_vmid, &page) != GS_SUCCESS) {
        return GS_ERROR;
    }

    dir = (elem_dir_t *)(page->data + dir_offset % GS_VMEM_PAGE_SIZE);
    if (subscript == (uint32)dir->subscript) {
        if (array_update_element_by_dir(aa, data, size, dir, vlob) != GS_SUCCESS) {
            vm_close(aa->session, aa->pool, dir_vmid, VM_ENQUE_TAIL);
            return GS_ERROR;
        }
    } else if (subscript < (uint32)dir->subscript) {
        /* insert a new directory before the directory found */
        if (array_insert_element(aa, data, size, subscript, vlob, dir, dir_vmid, dir_offset) != GS_SUCCESS) {
            vm_close(aa->session, aa->pool, dir_vmid, VM_ENQUE_TAIL);
            return GS_ERROR;
        }
    }

    vm_close(aa->session, aa->pool, dir_vmid, VM_ENQUE_TAIL);
    return GS_SUCCESS;
}

bool32 array_str_invalid(text_t *src)
{
    if (src->len < strlen("{}")) {
        return GS_TRUE;
    }

    if (src->str[0] != '{' || src->str[src->len - 1] != '}') {
        return GS_TRUE;
    }

    return GS_FALSE;
}

bool32 array_str_null(text_t *src)
{
    /* skip {} */
    src->str++;
    src->len -= 2; // 2 is the length of {}
    cm_text_skip_spaces(src);
    return (bool32)(src->len == 0);
}

status_t array_get_element_str(text_t *src, text_t *dst, bool32 *last)
{
    bool32 complete = GS_TRUE;
    bool32 has_quote = GS_FALSE;

    while (src->len > 0) {
        switch (src->str[0]) {
            /* found an element */
            case ',':
                cm_text_skip_spaces(dst);
                if (dst->len == 0) {
                    GS_THROW_ERROR(ERR_INVALID_ARRAY_FORMAT);
                    return GS_ERROR;
                }
                cm_text_skip(src, 1);
                cm_text_skip_spaces(src);
                /* expect one more element */
                if (src->len == 0) {
                    GS_THROW_ERROR(ERR_INVALID_ARRAY_FORMAT);
                    return GS_ERROR;
                }
                return GS_SUCCESS;

            /* char/varchar type */
            case '"':
                if (dst->len > 0) {
                    /* " must be the first */
                    GS_THROW_ERROR(ERR_INVALID_ARRAY_FORMAT);
                    return GS_ERROR;
                }
                cm_text_skip(src, 1);
                complete = GS_FALSE;
                while (src->len > 0) {
                    if (src->str[0] == '"') {
                        complete = GS_TRUE;
                        cm_text_skip(src, 1);
                        break;
                    }
                    /* abc''d -> abc'd */
                    if (src->str[0] == '\'' && src->len > 1 && src->str[1] == '\'') {
                        CM_TEXT_APPEND(dst, src->str[0]);
                        cm_text_skip(src, 2);
                        continue;
                    }
                    /* "abc\"d" -> abc"d */
                    if (src->str[0] == '\\' && src->len > 1 && src->str[1] == '"') {
                        CM_TEXT_APPEND(dst, src->str[1]);
                        cm_text_skip(src, 2);
                        continue;
                    }

                    CM_TEXT_APPEND(dst, src->str[0]);
                    cm_text_skip(src, 1);
                }

                /* text is not complete */
                if (!complete) {
                    GS_THROW_ERROR(ERR_INVALID_ARRAY_FORMAT);
                    return GS_ERROR;
                }
                has_quote = GS_TRUE;
                break;

            default:
                /* invalid format : '{"1234"123, 123, 123}' */
                if (has_quote == GS_TRUE) {
                    GS_THROW_ERROR(ERR_INVALID_ARRAY_FORMAT);
                    return GS_ERROR;
                }
                CM_TEXT_APPEND(dst, src->str[0]);
                cm_text_skip(src, 1);
        }
    }

    *last = GS_TRUE;
    cm_text_skip_spaces(dst);
    return GS_SUCCESS;
}

status_t array_convert_inline_lob(handle_t session, vm_pool_t *pool, var_array_t *v, char *buf, uint32 buf_len)
{
    errno_t err;
    uint32 i;
    elem_dir_t *dir = NULL;

    if (v->count == 0) {
        return GS_SUCCESS;
    }

    uint32 vmid = v->value.vm_lob.entry_vmid;
    uint32 ctrl_size = v->count * sizeof(elem_dir_t);
    uint32 remain_size = ctrl_size;
    uint32 copy_size = 0;
    char *addr = buf;
    uint32 len = buf_len;
    uint32 offset;
    vm_page_t *page = NULL;

    while (vmid != GS_INVALID_ID32) {
        GS_RETURN_IFERR(vm_open(session, pool, vmid, &page));
        copy_size = MIN(remain_size, GS_VMEM_PAGE_SIZE);
        offset = (vmid == v->value.vm_lob.entry_vmid) ? sizeof(array_head_t) : 0;
        err = memcpy_sp(addr, len, page->data + offset, copy_size);
        if (err != EOK) {
            vm_close(session, pool, vmid, VM_ENQUE_TAIL);
            GS_THROW_ERROR(ERR_SYSTEM_CALL, err);
            return GS_ERROR;
        }

        vm_close(session, pool, vmid, VM_ENQUE_TAIL);
        remain_size -= copy_size;
        len -= copy_size;
        addr += copy_size;
        vmid = vm_get_ctrl(pool, vmid)->sort_next;
        if (remain_size == 0) {
            /* switch to value page, update the remain_size */
            remain_size = buf_len - ctrl_size;
        }
    }

    for (i = 0; i < v->count; i++) {
        dir = (elem_dir_t *)buf + i;
        /* if the element is null, can not update the offset value */
        if (dir->offset != ELEMENT_NULL_OFFSET) {
            dir->offset -= (GS_VMEM_PAGE_SIZE - (ctrl_size + sizeof(array_head_t)) % GS_VMEM_PAGE_SIZE);
        }
    }

    return GS_SUCCESS;
}

#ifdef __cplusplus
}
#endif
