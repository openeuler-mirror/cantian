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
 * cm_array.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_array.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_ARRAY_H_
#define __CM_ARRAY_H_

#include "cm_defs.h"
#include "cm_text.h"
#include "cm_lob.h"
#include "cm_memory.h"
#include "cm_nls.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_var_array_t {
    int16 type;         /* datatype of array elements */
    int8 reserve[2];    /* pad bytes */
    uint32 count;       /* count of elements */
    var_lob_t value;    /* subscripts and values of all elements */
} var_array_t;

typedef struct st_elem_dir_t {
    int32 subscript;    /* subscript id */
    uint32 offset;      /* value position offset */
    uint32 size;        /* value size, 0 means null */
    bool32 last;        /* last element */
} elem_dir_t;

/* array store structure:
+-------+------+----------+--------+----------+----------+-----+----------+--------+--------+-----+
| count | size | datatype | offset | elem_dir | elem_dir | ... | elem_dir | value1 | value2 | ... |
+-------+------+----------+--------+----------+----------+-----+----------+--------+--------+-----+
|<-------------------------- dir_curr ------------------>|
|<--------------------------------- dir_end ----------------------------->|<----- value --------->|
|<----------------------------------------- size ------------------------------------------------>|
*/

/* caution: when need to add member, should keep :
   sizeof(array_head_t) = N * sizeof(elem_dir_t)
*/
typedef struct st_array_head_t {
    uint32 count;   /* element count */
    uint32 size;    /* total size */
    int32 datatype; /* element datatype */
    uint32 offset;  /* the first value offset equal to GS_VMEM_PAGE_SIZE * n.m,
                       1) when uncompressed, m = 0 and n >= 1
                       2) when compressed, (m = 0 and n >= 1) or (m > 0 and n >=0) */
} array_head_t;

typedef struct st_array_assist_t {
    handle_t session;
    id_list_t *list;
    vm_pool_t *pool;
    char *buf;
    uint32 dir_curr;
    uint32 dir_end;
    array_head_t *head;
} array_assist_t;

typedef enum en_search_mode {
    ARRAY_SEARCH_EQUAL  = 0,    /* search the dir that dir.subscript = subscript */
    ARRAY_SEARCH_FIRST  = 1,    /* search the first dir that dir.subscript >= subscript */
} array_search_mode;

typedef enum en_update_mode {
    ARRAY_UPDATE_POINT  = 0,    /* update only one element */
    ARRAY_UPDATE_RANGE  = 1,    /* update elements in range */
} array_update_mode;

typedef struct st_array_search_assist_t {
    vm_lob_t *vlob;             /* search element directory in the vlob */
    vm_page_t *page;            /* search from which page */
    uint32 vmid;                /* vmid of the page for search */
    int subscript;              /* search key */
    uint32 dir_start;           /* the first element directory in the page */
    uint32 dir_end;             /* the last element directory in the page */
    bool32 last_dir_page;       /* is the last directory page */
    array_search_mode mode;     /* search mode */
} array_search_assist_t;

typedef struct st_subarray_assist_t {
    array_assist_t *src_aa;
    vm_lob_t *src_vlob;
    uint32 dir_vmid;
    uint32 dir_offset;
    array_assist_t dst_aa;
    vm_lob_t *dst_vlob;
    int32 start;
    int32 end;
} subarray_assist_t;

typedef struct st_output_element_head {
    uint32 subscript;
    uint32 size;
} output_element_head_t;

#define ELEMENT_HEAD_SIZE   sizeof(output_element_head_t)

typedef struct st_clt_array_assist {
    char *dst;
    void *locator;
    void *ele_val;
    uint32 dst_len;
    uint32 dst_offset;
    uint32 expect_subscript;
} clt_array_assist_t;

#define ELEMENT_NULL_OFFSET       UINT32_MAX
#define ELEMENT_IS_NULL(dir)      ((dir)->size == 0 && (dir)->offset == ELEMENT_NULL_OFFSET)
#define MAX_DIR_COUNT_IN_ONE_VM   (GS_VMEM_PAGE_SIZE / sizeof(elem_dir_t))
#define COMPRESS_ARRAY   GS_TRUE
#define UNCOMPRESS_ARRAY GS_FALSE
#define ARRAY_USED_VM_PAGES 2
#define ARRAY_UNUSED_SPACE_IN_VM (GS_VMEM_PAGE_SIZE / 128)

#define ARRAY_INIT_ASSIST_INFO(aa, stmt)                \
    do {                                                \
        (aa)->session = KNL_SESSION(stmt);              \
        (aa)->pool = (stmt)->mtrl.pool;                 \
        (aa)->list = sql_get_exec_lob_list(stmt);       \
    } while (0)

void array_set_handle(handle_t session_handle, handle_t pool_handle);
bool32 array_str_invalid(text_t *src);
bool32 array_str_null(text_t *src);
status_t array_init(array_assist_t *aa, handle_t session, vm_pool_t *pool, id_list_t *list, vm_lob_t *vlob);
status_t array_append_element(array_assist_t *aa, uint32 subscript, void *data, uint32 size, bool8 is_null,
                              bool32 last, vm_lob_t *vlob);
status_t array_get_subarray(array_assist_t *aa, vm_lob_t *src_lob, vm_lob_t *dst_lob, int32 start, int32 end);
uint32 array_get_vmid_by_offset(array_assist_t *aa, vm_lob_t *vlob, uint32 offset);
status_t array_get_element_info(array_assist_t *aa, uint32 *size, uint32 *offset, vm_lob_t *vlob, uint32 subscript);
status_t array_get_value_by_dir(array_assist_t *aa, char *buf, uint32 size_input, vm_lob_t *vlob, elem_dir_t *dir);
status_t array_get_last_dir_end(array_assist_t *aa, vm_lob_t *vlob, uint32 *dir_end);
status_t array_get_element_count(array_assist_t *aa, vm_lob_t *vlob, uint32 *count);
status_t array_get_element_datatype(array_assist_t *aa, vm_lob_t *vlob, int16 *datatype);
status_t array_get_dimension(array_assist_t *aa, vm_lob_t *vlob, uint32 *dimension);
status_t array_update_head_datatype(array_assist_t *aa, vm_lob_t *vlob, uint32 datatype);
status_t cm_array2text(const nlsparams_t *nls, var_array_t *var, text_t *text);
status_t array_get_element_by_subscript(array_assist_t *aa, char *buf, uint32 size, vm_lob_t *vlob, uint32 subscript);
status_t array_update_element_by_subscript(array_assist_t *aa, char *data, uint32 size, bool8 is_null,
                                           uint32 subscript, vm_lob_t *vlob);
status_t array_get_element_str(text_t *src, text_t *dst, bool32 *last);
status_t array_convert_inline_lob(handle_t session, vm_pool_t *pool, var_array_t *v, char *buf, uint32 buf_len);
status_t array_extend_vm_page(array_assist_t *aa, vm_lob_t *vlob);
status_t array_update_ctrl(handle_t session, vm_pool_t *vm_pool, vm_lob_t *vlob,
    uint32 size, uint32 total_dir_cnt, bool32 compress);

static inline uint32 cm_get_vlob_page_num(vm_pool_t *vm_pool, vm_lob_t *vlob)
{
    uint32 count = 0;
    uint32 vmid = vlob->entry_vmid;
    while (vmid != GS_INVALID_ID32) {
        count++;
        vmid = vm_get_ctrl(vm_pool, vmid)->sort_next;
    }
    return count;
}

static inline status_t cm_get_array_head(handle_t session, vm_pool_t *vm_pool, vm_lob_t *vlob, array_head_t *head)
{
    vm_page_t *page = NULL;
    uint32 vmid = vlob->entry_vmid;
    GS_RETURN_IFERR(vm_open(session, vm_pool, vmid, &page));
    *head = *(array_head_t *)page->data;
    vm_close(session, vm_pool, vmid, VM_ENQUE_HEAD);
    return GS_SUCCESS;
}

static inline status_t cm_get_array_head_offset(handle_t se, vm_pool_t *pool, var_array_t *v, uint32* head_offset)
{
    vm_page_t *page = NULL;
    GS_RETURN_IFERR(vm_open(se, pool, v->value.vm_lob.entry_vmid, &page));
    array_head_t *head = (array_head_t *)page->data;
    *head_offset = head->offset;
    vm_close(se, pool, v->value.vm_lob.entry_vmid, VM_ENQUE_TAIL);
    return GS_SUCCESS;
}

/* 1) after sql_compress_array_xxx, head_offset is equal to ctrl_size
   2) before sql_compress_array_xxx, head_offset is euqal to (n * GS_VMEM_PAGE_SIZE)
      notice: when ctrl_size is equal to (n * GS_VMEM_PAGE_SIZE), it is the same scene with 1)
*/
static inline status_t array_actual_size(handle_t session, vm_pool_t *pool, var_array_t *v,
    uint32* total_size, uint32* head_offset)
{
    uint32 ctrl_size = sizeof(array_head_t) + v->count * sizeof(elem_dir_t);
    
    GS_RETURN_IFERR(cm_get_array_head_offset(session, pool, v, head_offset));

    if (*head_offset == ctrl_size) {
        *total_size = v->value.vm_lob.size;
    } else {
        *total_size = v->value.vm_lob.size - (GS_VMEM_PAGE_SIZE - ctrl_size % GS_VMEM_PAGE_SIZE);
    }

    return GS_SUCCESS;
}

static inline status_t cm_update_mtrl_array_count(handle_t session, vm_pool_t *pool, var_array_t *v_array)
{
    vm_page_t *page = NULL;
    GS_RETURN_IFERR(vm_open(session, pool, v_array->value.vm_lob.entry_vmid, &page));
    array_head_t *head = (array_head_t *)page->data;
    v_array->count = head->count;
    vm_close(session, pool, v_array->value.vm_lob.entry_vmid, VM_ENQUE_TAIL);
    return GS_SUCCESS;
}

/* after compress the space between last dir and first data
   the offset of array_head_t is n.m * GS_VMEM_PAGE_SIZE,
   and when m > 0 , dir page count should add one */
static inline uint32 cm_get_dir_page_count(uint32 head_offset)
{
    uint32 count = head_offset / GS_VMEM_PAGE_SIZE;
    return ((head_offset % GS_VMEM_PAGE_SIZE > 0) ? (count + 1) : count);
}

static inline elem_dir_t* cm_get_array_end_dir(char* data, uint32 dir_end, bool32 is_last_dir_page)
{
    elem_dir_t* end_dir = NULL;
    if (is_last_dir_page) {
        end_dir = (elem_dir_t *)(data + (dir_end % GS_VMEM_PAGE_SIZE));
    } else {
        end_dir = (elem_dir_t *)(data + GS_VMEM_PAGE_SIZE - sizeof(elem_dir_t));
    }
    return end_dir;
}

#ifdef __cplusplus
}
#endif

#endif
