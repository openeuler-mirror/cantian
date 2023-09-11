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
 * gs_page.h
 *
 *
 * IDENTIFICATION
 * src/gstbox/gs_page.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __GSPAGE_H__
#define __GSPAGE_H__

#include "knl_page.h"

typedef struct st_input_data {
    char *input_str;
    int32 file_handle;
    bool32 is_file;
} input_data_t;

typedef struct st_repair_page_def {
    char *datafile;
    char *ctrlfile;
    input_data_t head_input;
    input_data_t tail_input;
    input_data_t ctrl_input;
    char log_path[GS_FILE_NAME_BUFFER_SIZE];
    bool32 is_force;
    bool32 is_checksum;
} repair_page_def_t;

typedef struct st_repair_input_common {
    uint32 page_size;
    uint64 start;
    uint32 count;
    char *log_path;
}repair_input_common_t;

status_t repair_parse_kv(text_t *text, text_t *name, text_t *value, uint32 *line_no, bool32 *is_eof);
status_t repair_format_input(input_data_t input, char *buf, int32 buf_len, int32 *real_len);
status_t repair_datafile(repair_page_def_t *page_input, repair_input_common_t *input_common);
status_t repair_get_item_index(text_t *name, uint32 *array_index);
uint32   extent_begin_page_sn(uint32 page_sn);
status_t repair_write_page(int32 handle, char *buf, int64 offset, uint32 page_size);

#endif
