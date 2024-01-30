
/*
* Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
* Description: cm kmc persistent
* Create: 2023-06-19
*/
#ifndef __CM_KMC_PERSISTENT_H__
#define __CM_KMC_PERSISTENT_H__
 
#ifdef __cplusplus
extern "C" {
#endif
#define CT_KMC_MAX_MK_SIZE     (uint32)256 // WSEC_MK_LEN_MAX
#define CT_KMC_MK_HASH_LEN     (uint32)8 // WSEC_MK_HASH_REC_LEN

typedef struct st_rd_create_mk_begin {
    uint32 op_type;
    uint32 max_mkid;
    uint64 reserved;
} rd_create_mk_begin_t;

typedef struct st_rd_mk_data {
    uint32 op_type;
    uint32 len;
    uint64 offset;
    uint32 reserved;
    char data[CT_KMC_MAX_MK_SIZE];
} rd_mk_data_t;

typedef struct st_rd_create_mk_end {
    uint32 op_type;
    uint32 mk_id;
    uint32 hash_len;
    uint32 reserved;
    char hash[CT_KMC_MK_HASH_LEN];
} rd_create_mk_end_t;

typedef struct st_rd_alter_server_mk {
    uint32 op_type;
    uint64 reserved;
} rd_alter_server_mk_t;

#ifdef __cplusplus
}
#endif
 
#endif