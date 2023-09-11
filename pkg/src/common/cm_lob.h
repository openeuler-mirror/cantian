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
 * cm_lob.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_lob.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_LOB_H_
#define __CM_LOB_H_

#include "cm_defs.h"
#include "cm_text.h"
#include "cm_binary.h"

#ifdef __cplusplus
extern "C" {
#endif

/* lob value can from kernel(lob_locator_t) or vm_pool(vm_lob_t)
  * vm_cli_lob_t is same with gsc_lob_t to preserve lob info in order to transform to client */
typedef struct st_vm_cli_lob_t {
    /* size + type must be defined first!!! */
    uint32 size;  // data length
    uint32 type;
    uint32 entry_vmid;  // entry page, virtual memory id
    uint32 last_vmid;   // the last page, virtual memory id
} vm_cli_lob_t;

/* lob value can from kernel(lob_locator_t) or vm_pool(vm_lob_t) */
typedef struct st_vm_lob_t {
    /* size + type must be defined first!!! */
    uint32 size;  // data length
    uint32 type;
    uint32 entry_vmid;  // entry page, virtual memory id
    uint32 last_vmid;   // the last page, virtual memory id
    uint32 node_id : 9;
    uint32 unused : 23;
} vm_lob_t;

typedef struct st_normal_lob_t {
    /* size + type must be defined first!!! */
    uint32 size;
    uint32 type;
    text_t value;
    uint32 node_id : 9;
    uint32 unused : 23;
} normal_lob_t;

typedef struct st_vm_lob_id_t {
    uint32 entry_vmid;  // entry page, virtual memory id
    uint32 last_vmid;   // the last page, virtual memory id
} vm_lob_id_t;

#define VM_LOB_LOCATOR_SIZE        sizeof(vm_lob_t)
#define GS_LOB_FROM_KERNEL         0
#define GS_LOB_FROM_VMPOOL         1
#define GS_LOB_FROM_NORMAL         2
#define GS_IS_VALID_LOB_TYPE(type)                                                                                     \
    ((type) == GS_LOB_FROM_KERNEL || (type) == GS_LOB_FROM_VMPOOL || (type) == GS_LOB_FROM_NORMAL)

static inline void cm_reset_vm_lob(vm_lob_t *vlob)
{
    vlob->size = 0;
    vlob->type = GS_LOB_FROM_VMPOOL;
    vlob->entry_vmid = GS_INVALID_ID32;
    vlob->last_vmid = GS_INVALID_ID32;
}

static inline void cm_reset_normal_lob(normal_lob_t *nlob)
{
    nlob->size = 0;
    nlob->type = GS_LOB_FROM_NORMAL;
    nlob->value.len = 0;
    nlob->value.str = NULL;
}

#pragma pack(4)

static inline void cm_vmcli_lob2vm_lob(vm_lob_t *vlob, const vm_cli_lob_t* vlob_client)
{
    vlob->size = vlob_client->size;
    vlob->type = vlob_client->type;
    vlob->entry_vmid = vlob_client->entry_vmid;
    vlob->last_vmid = vlob_client->last_vmid;
}

typedef struct st_var_lob_t {
    uint32 type;  // lob value from 0:kernel 1:vm_pool 2:default value
    union {
        binary_t knl_lob;
        vm_lob_t vm_lob;
        normal_lob_t normal_lob;  // only for default value in insert or cast to clob/blob
    };
} var_lob_t;
#pragma pack()

#ifdef __cplusplus
}
#endif

#endif
