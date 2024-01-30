
/*
* Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
* Description: kernel space manager persistent
* Create: 2023-06-19
*/
#ifndef __KNL_CREATE_SPACE_PERSIST_H__
#define __KNL_CREATE_SPACE_PERSIST_H__
 
#ifdef __cplusplus
extern "C" {
#endif
#pragma pack(4)
typedef struct st_rd_create_space {
    uint32 space_id;
    uint32 extent_size;
    uint64 org_scn;
    uint16 flags;
    uint16 block_size;
    char name[CT_NAME_BUFFER_SIZE];
    uint32 type;
    uint8 encrypt_version;
    uint8 cipher_reserve_size;
    uint8 is_for_create_db;
    uint8 reserved2[3];
} rd_create_space_t;

typedef struct st_rd_create_datafile {
    uint32 id;        // datafile id in whole database
    uint32 space_id;  // tablespace id
    uint32 file_no;   // sequence number in tablespace
    uint16 flags;
    uint16 reserve;
    uint64 size;
    int64 auto_extend_size;
    int64 auto_extend_maxsize;
    char name[CT_FILE_NAME_BUFFER_SIZE];
    uint32 type;
} rd_create_datafile_t;

typedef struct st_rd_create_datafile_daac {
    uint32 op_type;
    rd_create_datafile_t datafile;
} rd_create_datafile_daac_t;

typedef struct st_rd_extend_undo {
    uint16 old_undo_segments;
    uint16 undo_segments;
} rd_extend_undo_segments_t;

typedef struct st_rd_update_head {
    page_id_t entry;
    uint16 space_id;  // tablespace id
    uint16 file_no;   // sequence number in tablespace
} rd_update_head_t;

typedef struct st_rd_create_space_daac {
    uint32 op_type;
    rd_create_space_t space;
} rd_create_space_daac_t;

#pragma pack()
#ifdef __cplusplus
}
#endif
 
#endif