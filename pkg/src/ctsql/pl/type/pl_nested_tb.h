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
 * pl_nested_tb.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/type/pl_nested_tb.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __PL_NESTED_TB_H__
#define __PL_NESTED_TB_H__

#include "pl_collection.h"
#ifdef __cplusplus
extern "C" {
#endif

#define VM_NTBL_EXT_SIZE 32
#define VM_NTBL_MAP_STEP 32
#define VM_NTBL_EXT_MAPS ((VM_NTBL_EXT_SIZE - 1) / VM_NTBL_MAP_STEP + 1)

#define VM_NTBL_MAP_MASK(ID) (1 << ((ID) % VM_NTBL_MAP_STEP))
#define VM_NTML_MAP_ARRAY(ID, MAP) ((MAP)[(ID) / VM_NTBL_MAP_STEP])

#define VM_NTBL_MAP_POS(ID) ((ID) % VM_NTBL_EXT_SIZE)
#define VM_NTBL_MAP_OCCUPY(ID, MAP) \
    (VM_NTML_MAP_ARRAY(VM_NTBL_MAP_POS(ID), (MAP)) &= (~(VM_NTBL_MAP_MASK(VM_NTBL_MAP_POS(ID)))))
#define VM_NTBL_MAP_EXISTS(ID, MAP)                                                                                 \
    (((VM_NTML_MAP_ARRAY(VM_NTBL_MAP_POS(ID), (MAP)) & (VM_NTBL_MAP_MASK(VM_NTBL_MAP_POS(ID)))) == 0) ? (CT_TRUE) : \
                                                                                                        (CT_FALSE))
#define VM_NTBL_MAP_FREE(ID, MAP) \
    (VM_NTML_MAP_ARRAY(VM_NTBL_MAP_POS(ID), (MAP)) |= (VM_NTBL_MAP_MASK(VM_NTBL_MAP_POS(ID))))

typedef struct st_vm_ntbl_ext {
    mtrl_rowid_t slot[VM_NTBL_EXT_SIZE];
    mtrl_rowid_t next;
    uint32 map[VM_NTBL_EXT_MAPS]; // 0 OCCUPIED SLOT / 1 FREE SLOT
} vm_ntbl_ext_t;

typedef struct st_mtrl_ntbl_head {
    mtrl_ctrl_t ctrl;
    mtrl_rowid_t tail;
    vm_ntbl_ext_t ntbl[0];
} mtrl_ntbl_head_t;

#define UDT_NTBL_EXTNUM(id) ((id) / VM_NTBL_EXT_SIZE + 1)

void udt_reg_nested_table_method(void);

#ifdef __cplusplus
}
#endif

#endif
