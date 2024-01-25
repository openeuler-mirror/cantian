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
 * dml_defs.h
 *
 *
 * IDENTIFICATION
 * src/kernel/include/dml_defs.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_DML_DEFS_H__
#define __KNL_DML_DEFS_H__

#include "knl_defs.h"

#ifdef __cplusplus
extern "C" {
#endif
    
    
typedef struct st_knl_column {
    uint32 id;   // column id
    char *name;  // column name
    uint32 uid;
    uint32 table_id;
    uint32 datatype;
    uint32 size;            // column size
    int32 precision;        // precision, for number type
    int32 scale;            // scale, for number type
    bool32 nullable;        // null or not null
    uint32 flags;           // hidden, deleted, compressed...
    text_t default_text;    // raw expr text
    void *lob;

    void *default_expr;         // deserialized default expr
    void *ddm_expr;             // deserialized ddm expr
    void *update_default_expr;  // deserialized update default expr
    uint32 next;                // hash next
    latch_t cbo_col_latch;      // for CBO statistics sync object
    bool32 is_collate;
    uint16 collate_id;
    uint8 mysql_ori_datatype;    // column origin datatype at mysql
    uint8 mysql_unsigned;        // column origin unsigned at mysql
} knl_column_t;

typedef enum st_nologing_type {
    LOGGING_LEVEL = 0,
    SESSION_LEVEL = 1,
    TABLE_LEVEL = 2,
} nologing_type_t;

#define KNL_COLUMN_FLAG_HIDDEN         0x00000001
#define KNL_COLUMN_FLAG_DELETED        0x00000002
#define KNL_COLUMN_FLAG_COMPRESSED     0x00000004
#define KNL_COLUMN_FLAG_SERIAL         0x00000008
#define KNL_COLUMN_FLAG_UPDATE_DEFAULT 0x00000010
#define KNL_COLUMN_FLAG_CHARACTER      0x00000020
#define KNL_COLUMN_FLAG_VIRTUAL        0x00000040 /* virtual column, used for function based index */
#define KNL_COLUMN_FLAG_DESCEND        0x00000080 /* is in descend order, used for descend index   */
#define KNL_COLUMN_FLAG_QUOTE          0x00000100 /* is column name wrapped with double quotation */
#define KNL_COLUMN_FLAG_DEFAULT_NULL   0x00000200 /* default text, empty string treated as '' or null */
#define KNL_COLUMN_FLAG_ARRAY          0x00000400 /* column is an array */
#define KNL_COLUMN_FLAG_JSONB          0x00000800 /* column is an jsonb, actually is blob */

#define KNL_COLUMN_INVISIBLE(col) \
    ((col)->flags & (KNL_COLUMN_FLAG_HIDDEN | KNL_COLUMN_FLAG_DELETED | KNL_COLUMN_FLAG_VIRTUAL))
#define KNL_COLUMN_IS_DELETED(col)        (((col)->flags & KNL_COLUMN_FLAG_DELETED) != 0)
#define KNL_COLUMN_IS_HIDDEN(col)         (((col)->flags & KNL_COLUMN_FLAG_HIDDEN) != 0)
#define KNL_COLUMN_IS_UPDATE_DEFAULT(col) (((col)->flags & KNL_COLUMN_FLAG_UPDATE_DEFAULT) != 0)
#define KNL_COLUMN_IS_CHARACTER(col)      (((col)->flags & KNL_COLUMN_FLAG_CHARACTER) != 0)
#define KNL_COLUMN_IS_SERIAL(col)         (((col)->flags & KNL_COLUMN_FLAG_SERIAL) != 0)
#define KNL_COLUMN_HAS_QUOTE(col)         (((col)->flags & KNL_COLUMN_FLAG_QUOTE) != 0)
#define KNL_COLUMN_IS_VIRTUAL(col)        (((col)->flags & KNL_COLUMN_FLAG_VIRTUAL) != 0)
#define KNL_COLUMN_IS_DESCEND(col)        (((col)->flags & KNL_COLUMN_FLAG_DESCEND) != 0)
#define KNL_COLUMN_IS_DEFAULT_NULL(col)   (((col)->flags & KNL_COLUMN_FLAG_DEFAULT_NULL) != 0)
#define KNL_COLUMN_IS_ARRAY(col)          (((col)->flags & KNL_COLUMN_FLAG_ARRAY) != 0)
#define KNL_COLUMN_IS_JSONB(col)          (((col)->flags & KNL_COLUMN_FLAG_JSONB) != 0)

/* mode of for update */
typedef enum st_rowmark_type {
    ROWMARK_WAIT_BLOCK = 0,
    ROWMARK_WAIT_SECOND,
    ROWMARK_NOWAIT,
    ROWMARK_SKIP_LOCKED
} rowmark_type_t;

typedef union st_rowmark {
    uint64 value;
    struct {
        rowmark_type_t type;
        uint32 wait_seconds;  // For ROWMARK_WAIT
    };
} rowmark_t;

typedef enum en_knl_scan_mode {
    SCAN_MODE_TABLE_FULL = 1,  // table full scan, read data page by page
    SCAN_MODE_ROWID = 2,       // scan by rowid
    SCAN_MODE_INDEX = 3,       // index range scan, ascended
} knl_scan_mode_t;

typedef enum en_knl_cursor_action {
    CURSOR_ACTION_FOR_UPDATE_SCAN = 1,
    CURSOR_ACTION_SELECT = 2,
    CURSOR_ACTION_UPDATE = 3,
    CURSOR_ACTION_INSERT = 4,
    CURSOR_ACTION_DELETE = 5,
} knl_cursor_action_t;

#define SCAN_KEY_NORMAL         0
#define SCAN_KEY_LEFT_INFINITE  1
#define SCAN_KEY_RIGHT_INFINITE 2
#define SCAN_KEY_MINIMAL        3
#define SCAN_KEY_MAXIMAL        4
#define SCAN_KEY_IS_NULL        5

typedef struct st_knl_scan_key_t {
    uint8 flags[CT_MAX_INDEX_COLUMNS];
    uint16 offsets[CT_MAX_INDEX_COLUMNS];
    char *buf;
} knl_scan_key_t;

typedef struct st_knl_scan_range {
    union {
        // index scan range
        struct {
            char l_buf[CT_KEY_BUF_SIZE];
            char r_buf[CT_KEY_BUF_SIZE];
            char org_buf[CT_KEY_BUF_SIZE];
            knl_scan_key_t l_key;
            knl_scan_key_t r_key;
            knl_scan_key_t org_key;
            bool32 is_equal;
        };

        // table scan range
        struct {
            page_id_t l_page;
            page_id_t r_page;
        };
    };
} knl_scan_range_t;

typedef struct st_knl_update_info {
    uint16 count;  // column count
    char *data;
    uint16 *columns;  // use pointer and the space is specified where it is used
    uint16 *offsets;  // use pointer and the space is specified where it is used
    uint16 *lens;     // use pointer and the space is specified where it is used
} knl_update_info_t;

typedef struct st_key_locator {
    knl_scn_t seg_scn;  // scn of btree segment
    uint64 lsn;         // the lsn of current page
    page_id_t page_id;  // the page of current key
    page_id_t next_page_id;
    page_id_t prev_page_id;
    knl_scn_t pid_snap_scn; // the time get page id
    knl_scn_t next_pid_snap_scn; // the time get next page id and prev page id
    uint64 index_ver;
    uint16 slot;
    uint16 slot_end;
    uint32 pcn;       // current page change number
    uint8 is_located; // if cursor has located the start point of scan
    uint8 is_last_key;
    uint8 page_cache;
    bool8 is_initialized;
    bool8 match_left; // if match cond is needed for start point of scan range
    bool8 match_right;  // if match cond is need for end point of scan range
    bool8 cmp_end; // if compare with right key needed
    uint8 equal_cols;
    bool8 skip_cache;
    uint8 aligned[7];
} key_locator_t;

/* memory definition of snapshot using for history version read */
typedef struct st_undo_snapshot {
    knl_scn_t scn;            /* < commit scn of (cursor) snapshot row */
    undo_page_id_t undo_page; /* < prev undo page of (cursor) snapshot row */
    uint64 xid;
    uint16 undo_slot;         /* < prev undo slot of (cursor) snapshot row */
    uint16 is_xfirst : 1;     /* < whether is first time change or first allocated dir or itl for PCR */
    uint16 is_owscn : 1;      /* < whether the snapshot commit scn is overwrite scn */
    uint16 is_valid : 1;      /* < whether to do snapshot query or snapshot consistent check(in read committed ) */
    uint16 contain_subpartno : 1;    /* < whether the undo data contain subpart_no */
    uint16 unused : 12;       /* < unused flag */
} undo_snapshot_t;

#define KNL_ROWID_LEN        sizeof(rowid_t)
#define REMOTE_ROWNODEID_LEN sizeof(uint16)
#define KNL_ROWID_ARRAY_SIZE (uint32)(CT_ROWID_BUF_SIZE / KNL_ROWID_LEN)
    
/* Function type, use to fetch row from an opened cursor */
typedef struct st_knl_cursor knl_cursor_t;

typedef status_t (*knl_cursor_operator_t)(knl_handle_t session, knl_cursor_t *cursor);
typedef status_t (*knl_cursor_operator1_t)(knl_handle_t session, knl_cursor_t *cursor, bool32 *is_found);

typedef struct st_knl_part_locate {
    uint32 part_no;
    uint32 subpart_no;
} knl_part_locate_t;

typedef struct st_knl_parts_locate {
    knl_part_locate_t part[MAX_REBUILD_PARTS];
    uint32 specified_parts;
} knl_parts_locate_t;

static const knl_part_locate_t g_invalid_part_loc = { .part_no = CT_INVALID_ID32, .subpart_no = CT_INVALID_ID32 };

/*
 * struct used for init cursor
 * @note must be consistent with variable in cursor,
 * variable which needs to be init during init cursor must
 * be copied here in the same position
 */
typedef struct st_init_cursor {
    void *stmt;                    // for callback, match condition argument
    knl_handle_t temp_cache;  // temp table
    vm_page_t *vm_page;            // cursor vm_page
    int32 file;                    // for long sql
    knl_part_locate_t part_loc;    // for part locate
    uint16 rowid_count;            // for rowid scan
    uint16 decode_count;           // for row decode
    uint8 chain_count;            // count of row chains
    uint8 index_slot;              // for index scan
    bool8 index_dsc : 1;          // index descending scan
    bool8 index_only : 1;          // index only scan
    bool8 index_ffs : 1;           // for index fast full scan
    bool8 index_ss : 1;            // for index skip scan
    bool8 index_paral : 1;         // for index parallel scan
    bool8 index_prefetch_row : 1;  // for index
    bool8 skip_index_match : 1;    // no need to match conditions on index first
    bool8 asc_relocate_next_key : 1;

    bool8 set_default;             // judge set default
    bool8 restrict_part;           // scan restricted on partition specified by part_no
    bool8 restrict_subpart;           // scan restricted on subpartition specified by part_no and subpart_no
    bool8 is_valid;                // cursor is valid
    bool8 eof;                     // end of fetch
    bool8 logging : 1;             // bulk load nologging hint
    bool8 page_soft_damaged : 1;   // page is soft-damaged by nologging insert
    bool8 res_flag : 6;         // reserved flag for nologging insert
    bool8 global_cached;           // cache page in cr_pool
    rowmark_t rowmark;
    bool8 is_splitting;             // for split partition
    bool8 for_update_fetch;        // for update flag
    nologing_type_t nologging_type;
} init_cursor_t;

typedef struct st_json_step_loc {
    uint32 pair_idx;
    uint32 pair_offset;
} json_step_loc_t;

typedef struct st_json_table_exec {
    bool8 table_ready;
    bool8 end;
    bool8 last_extend;
    bool8 exists;
    uint64 ordinality;
    json_step_loc_t *loc;
    struct st_json_path *basic_path;
    pointer_t json_value;
    pointer_t json_assist;
} json_table_exec_t;

typedef struct st_knl_cursor {
    union {
        // variables should be initialized during cursor init
        struct {
            void *stmt;                    // for callback, match condition argument
            knl_handle_t temp_cache;  // temp table
            vm_page_t *vm_page;            // cursor vm_page
            int32 file;                    // for long sql
            knl_part_locate_t part_loc;    // for locating a part
            uint16 rowid_count;            // for rowid scan
            uint16 decode_count;           // for row decode
            uint8 chain_count;            // count of row chains
            uint8 index_slot;              // for index scan

            union {
                struct {
                    bool8 index_dsc : 1;          // index descending scan
                    bool8 index_only : 1;          // index only scan
                    bool8 index_ffs : 1;           // for index fast full scan
                    bool8 index_ss : 1;            // for index skip scan
                    bool8 index_paral : 1;         // for index parallel scan
                    bool8 index_prefetch_row : 1;  // for index
                    bool8 skip_index_match : 1;    // no need to match conditions on index first
                    bool8 asc_relocate_next_key : 1; // asc relocate next key
                };
                uint8 index_flag;
            };

            bool8 set_default;             // judge set default
            bool8 restrict_part;           // scan restricted on partition specified by part_no
            bool8 restrict_subpart;        // scan restricted on subpartition specified by part_no and subpart_no
            bool8 is_valid;                // cursor is valid
            bool8 eof;                     // end of fetch
            bool8 logging : 1;             // bulk load nologging hint
            bool8 page_soft_damaged : 1;   // page is soft-damaged by nologging insert
            bool8 res_flag : 6;         // reserved flag for nologging insert
            bool8 global_cached;           // cache page in cr_pool
            rowmark_t rowmark;             // for update mode
            bool8 is_splitting;            // for split partition
            bool8 for_update_fetch;        // for update flag
            nologing_type_t nologging_type;
        };

        init_cursor_t init_cursor;  // used for init cursor
    };

    // Set by SQL engine
    knl_scan_mode_t scan_mode;      // index scan or full table scan
    knl_cursor_action_t action;     // select/update/delete
    knl_scan_range_t scan_range;    // for index scan or table scan
    knl_update_info_t update_info;  // for update pointer to page buffer

    // Save the row that would be inserted in INSERT ... UPDATE statements, and
    // referred by VALUES(col_name) to construct UPDATE column
    // when duplicate-key conflict occurred.
    // notice:
    //     1. knl_cursor_t::insert_info only set in INSERT ... UPDATE statements,
    //     2. and only insert_info::data/lens/offsets used
    knl_update_info_t insert_info;

    // Set by kernel
    uint16 decode_cln_total;  // decoding column total
    uint16 *offsets;          // for decoding row
    uint16 *lens;             // for decoding row
    uint16 lob_inline_num;    // for lob inline columns count
    uint16 data_size;         // row data size
    knl_dict_type_t dc_type;  // dictionary type
    knl_handle_t dc_entity;   // handle of dictionary entity
    knl_handle_t table;       // handle of table
    knl_handle_t table_part;  // handle of table part
    knl_handle_t index;       // handle of index
    knl_handle_t index_part;  // handle of index part

    char *vnc_column;  // vnc = violate notnull constraint. if the column can't be null, but set null to the column

    // external table
    int32 fd;     // fd of external file
    text_t text;  // row buffer

    char key[CT_KEY_BUF_SIZE];                  // key data
    rowid_t rowid_array[KNL_ROWID_ARRAY_SIZE];  // for rowid scan

    key_locator_t key_loc;  // key location info
    uint16 bitmap;          // store key bitmap
    bool8 disable_pk_update; // disable batch update primary/unique key

    knl_scn_t scn;        // commit scn of current row (current sys scn if transaction in progress)
    knl_scn_t query_scn;  // query scn for current table scan
    uint64 query_lsn;     // query lsn for current table scan
    uint64 xid;           // the session when the cursor was opened
    uint64 reused_xid;    // the itl_xid has been reused

    // for temp table, this value is from session->ssn (uint64) or session->ssn (uint64), otherwise ,
    // this value is from session->xact_ssn (uint32) or session->xact_ssn (uint32)
    uint64 ssn;                   // sql sequence number used for stmt visibility judgment
    rowid_t rowid;                // row id
    rowid_t link_rid;             // linked row id
    rowid_t conflict_rid;         // conflict row id when update primary key
    rowid_t rowid_pos;            // row id for pos
    undo_snapshot_t snapshot;     // snapshot of current row
    char *chain_info;             // row chain info
    row_head_t *row;              // current row data, point to buf
    char *page_buf;               // page buf
    uint16 rowid_no;              // for rowid scan or batch insert
    uint16 row_offset;            // current row offset of row batch from cursor->row, used by batch insert
    bool8 is_locked;              // has locked any rows
    bool8 ssi_conflict;           // conflict in serialized scan
    uint8 isolevel;               // isolation level for current table scan
    bool8 cleanout;               // page cleanout during full page scan
    bool8 is_xfirst;              // is the first operation on row/key in current transaction
    bool8 page_cache;             // page cache mode
    bool32 is_found;              // is row founded
    date_t cc_cache_time;         // the last reset scn time with current committed isolation
    uint32 tenant_id;             // record row tenant_id
    knl_cursor_operator_t fetch;  // registered when open cursor
    bool8 skip_lock;              // skip lock table when open cursor
    uint8 conflict_idx_slot;      // member for saving conflict index slot
    bool8 null_first;             // if compatible mysql, effect null comparison
    bool8 no_cascade_check;       // cascade check for mysql
    bool8 no_logic_logging;       // no logic logging for DML operations caused by mysql triggers
    void *cond;                   // for push condition
    bool8 mysql_using;            // for mysql connection in cursor alloc/free
    bool8 is_cascade;             // if cascade, no need to redo
    bool8 is_create_select;       // whether it is CREATE TABLE ... SELECT
    char buf[0];                  // row buffer and page buffer
} knl_cursor_t;

/*
 * Kernel support row level consistent read mode and page level consistent read mode
 */
typedef enum st_cr_mode {
    CR_ROW = 0,
    CR_PAGE = 1,
} cr_mode_t;

/*
 * Kernel support row format setting, it is a default value.
 */
typedef enum st_row_format {
    ROW_FORMAT_ASF = 0,
    ROW_FORMAT_CSF = 1,
} row_format_t;

/*
 * btree interface
 */
typedef struct st_knl_icol_info {
    bool32 is_func;
    ct_type_t datatype;
    uint32 size;
    bool32 is_dsc;
    uint16 arg_count;
    uint16 *arg_cols;
} knl_icol_info_t;

#define KNL_INDEX_FLAG_INVALID              0x00000004 /* index flag is invalid */

#define KNL_INDEX_FLAG_IS_INVALID(index_flags)          (((index_flags) & KNL_INDEX_FLAG_INVALID) != 0)

typedef struct st_index_profile {
    uint32 table_id;
    uint16 uid;
    uint8 index_id;
    bool8 is_shadow;
    bool32 primary;
    bool32 unique;
    bool32 global_idx_for_part_table;
    bool32 is_compart_table;
    uint32 column_count;
    ct_type_t types[CT_MAX_INDEX_COLUMNS];
    uint16_t collate_id[CT_MAX_INDEX_COLUMNS];
    bool8 null_first;
    uint8 reserve[3];
} index_profile_t;

typedef struct st_knl_index_desc {
    uint32 slot;
    uint32 id;
    uint32 uid;
    uint32 space_id;
    uint32 table_id;
    char name[CT_NAME_BUFFER_SIZE];
    knl_scn_t org_scn;
    knl_scn_t seg_scn;
    page_id_t entry;
    bool32 primary;
    bool32 unique;
    index_type_t type;
    uint32 column_count;
    uint16 columns[CT_MAX_INDEX_COLUMNS];
    uint32 initrans;
    cr_mode_t cr_mode;
    union {
        uint32 flags;
        struct {
            uint32 is_cons : 1;     /* << index is created by constraint */
            uint32 is_disabled : 1; /* << index is disable for index scan */
            uint32 is_invalid : 1;  /* << index is invalid, no need to handle it */
            uint32 is_stored : 1;   /* << index is stored in specified space */
            uint32 is_encode : 1;   /* << index name encode by uid.table_id.index_name, deprecated field */
            uint32 is_func : 1;     /* << index contains function index column */
            uint32 is_reverse : 1;
            uint32 is_nologging : 1; /* create index in nologging mode */
            uint32 unused_flag : 24;
        };
    };
    uint32 parted;
    uint32 pctfree;
    bool32 is_enforced; /* << enforce index is used by constraint, which cannot be dropped via drop index */
    knl_icol_info_t *columns_info;
    uint16 max_key_size;
    uint8  maxtrans;
    bool8  part_idx_invalid;
    bool8 is_dsc; // true for dsc index

    index_profile_t profile;  // TODO: to be deleted
} knl_index_desc_t;

void knl_init_key(knl_index_desc_t *desc, char *buf, rowid_t *rid);
void knl_set_key_rowid(knl_index_desc_t *desc, char *buf, rowid_t *rid);
void knl_put_key_data(knl_index_desc_t *desc, char *buf, ct_type_t type, const void *data, uint16 len, uint16 id);
uint32 knl_get_key_size(knl_index_desc_t *desc, const char *buf);
void knl_set_key_size(knl_index_desc_t *desc, knl_scan_key_t *key, uint32 size);
uint32 knl_scan_key_size(knl_index_desc_t *desc, knl_scan_key_t *key);
void knl_init_index_scan(knl_cursor_t *cursor, bool32 is_equal);
void knl_set_scan_key(knl_index_desc_t *desc, knl_scan_key_t *scan_key, ct_type_t type, const void *data, uint16 len,
                      uint16 id);
void knl_set_key_flag(knl_scan_key_t *border, uint8 flag, uint16 id);
void knl_get_index_name(knl_index_desc_t *desc, char *name, uint32 max_len);

status_t knl_insert(knl_handle_t session, knl_cursor_t *cursor);
status_t knl_internal_insert(knl_handle_t session, knl_cursor_t *cursor);
status_t knl_insert_indexes(knl_handle_t handle, knl_cursor_t *cursor);
status_t knl_delete(knl_handle_t session, knl_cursor_t *cursor);
status_t knl_internal_delete(knl_handle_t handle, knl_cursor_t *cursor);
status_t knl_update(knl_handle_t session, knl_cursor_t *cursor);
status_t knl_internal_update(knl_handle_t session, knl_cursor_t *cursor);
status_t knl_crosspart_update(knl_handle_t se, knl_cursor_t *cursor, knl_part_locate_t new_part_loc);
status_t knl_fetch(knl_handle_t session, knl_cursor_t *cursor);
status_t knl_fetch_by_rowid(knl_handle_t session, knl_cursor_t *cursor, bool32 *is_found);
status_t knl_copy_row(knl_handle_t handle, knl_cursor_t *src, knl_cursor_t *dest);
status_t knl_lock_row(knl_handle_t session, knl_cursor_t *cursor, bool32 *is_found);
status_t knl_verify_children_dependency(knl_handle_t session, knl_cursor_t *cursor, bool32 is_update, uint8 depth);
status_t knl_verify_ref_integrities(knl_handle_t session, knl_cursor_t *cursor);

knl_column_t *knl_find_column(text_t *col_name, knl_dictionary_t *dc);
knl_column_t *knl_get_column(knl_handle_t dc_entity, uint32 id);


typedef struct st_knl_paral_range {
    uint32 workers;                        // actual workers
    page_id_t l_page[CT_MAX_PARAL_QUERY];  // left range list
    page_id_t r_page[CT_MAX_PARAL_QUERY];  // right range list
} knl_paral_range_t;

status_t knl_get_paral_schedule(knl_handle_t handle, knl_dictionary_t *dc, knl_part_locate_t part_loc, uint32 workers,
    knl_paral_range_t *range);
uint16 knl_get_column_id(knl_dictionary_t *dc, text_t *name);
uint32 knl_get_column_count(knl_handle_t dc_entity);
#ifdef __cplusplus
}
#endif

#endif
