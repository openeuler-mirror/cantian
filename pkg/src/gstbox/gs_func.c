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
 * gs_func.c
 *
 *
 * IDENTIFICATION
 * src/gstbox/gs_func.c
 *
 * -------------------------------------------------------------------------
 */
#include "gs_func.h"
#include "gs_miner.h"
#include "gs_tbox.h"
#include "gs_page.h"
#include "rcr_btree.h"
#include "cm_file.h"

#ifdef WIN32
#define cm_strdup _strdup
#else
#define cm_strdup strdup
#endif


#define ZTBOX_REPAIR_OPT_NUM        3
#define ZTBOX_BITMAP_EXT_BASE_SIZE  EXT_SIZE_8
#define REPAIR_BLOCK_PAGES          1048576 // 8G // 524288 // 4G (4 * 1024 * 1024 * 1024 / 8192)
#define REPAIR_PROCESS_NUM          32

typedef status_t (*func_parse)(int argc, char *argv[]);
typedef void (*func_usage)(void);
typedef struct st_func_type_parse {
    char *func_name;
    func_parse func_parse_proc;
    func_usage func_usage_proc;
} func_type_parse_t;

typedef struct st_file_info {
    int32 handle;
    char *file_path;
} file_info_t;

typedef struct st_extent_info {
    uint32 idx;
    page_id_t page_id;
} extent_info_t;

typedef struct st_func_intput_def {
    uint32 page_sn;
    char  *file_path;
    bool8 is_decompress_extent;

    char *head_buf;
    int32 handle;
} func_input_def_t;

typedef struct st_map_group_lock {
    spinlock_t page_locks[DF_MAP_GROUP_SIZE];
} map_group_lock_t;

typedef struct st_repair_src_info {
    file_info_t data_file;
    int64 file_size;        // input datafile size
    file_info_t output_file;
    uint32 page_size;
    bool32 repair;
    char *buf_map_head;     // buf for map head
    char *buf_src_bt;       // source datafile bitmap data pages
    char *buf_output_bt;    // output datafile bitmap data pages
    uint32 next_page_id;
    spinlock_t lock;        // lock for alloc blocks
    map_group_lock_t *group_locks;
}repair_src_info_t;

typedef struct st_repair_process {
    thread_t thread;
    int idx;
    bool32 finish;
    repair_src_info_t *src_info;
} repair_process_t;

typedef struct st_repair_thread_src {
    file_info_t file;
    uint32 p_size;
    bool32 repair;
    char *buf_ext;         // buf for echo page
    char *buf_seg;         // buf for echo page
    char *buf_map_head;     // buf for map head, not alloc
    char *buf_output_bt;    // output datafile bitmap data pages, not alloc
    spinlock_t *lock;
    map_group_lock_t *group_locks;
}repair_thread_src_t;

static status_t func_int2pageid(int argc, char *argv[]);
static status_t func_int2undo_pageid(int argc, char *argv[]);
static status_t func_scn2time(int argc, char *argv[]);
static status_t func_dump_extents(int argc, char *argv[]);
static status_t func_repair_space(int argc, char *argv[]);
static status_t func_date2time_t(int argc, char *argv[]);
static status_t func_date2scn(int argc, char *argv[]);

static status_t func_usage_ex(int argc, char *argv[]);
static status_t func_init_input(func_input_def_t *input);
static status_t func_get_input(int argc, char *argv[], func_input_def_t *input);
static status_t func_check_input(int argc, char *argv[], func_input_def_t *input);
static void func_free_input(func_input_def_t *input);
static status_t func_decompress_extent(int argc, char *argv[]);
static status_t func_desc_compress_extent(page_head_t *head, compress_page_head_t *group_head, uint32 page_sn);
static status_t func_zstd_decompress_extent(char *dst_buf, uint32 dst_buf_size,
    page_head_t *head, compress_page_head_t *group_head);
static void func_int2pageid_usage(void);
static void func_int2undo_usage(void);
static void func_scn2time_usage(void);
static void func_dump_extents_usage(void);
static void func_date2time_t_usage(void);
static void func_date2scn_usage(void);
static void func_repair_space_usage(void);
static void func_decompress_extent_usage(void);

static uint16 ztbox_df_map_bit_cnt(uint16 page_size)
{
    return (uint16)((page_size - sizeof(df_map_page_t) - sizeof(page_tail_t)) * DF_BYTE_TO_BITS);
}

func_type_parse_t g_func_proc[] = {
    { "int2pageid",      func_int2pageid,      func_int2pageid_usage },
    { "int2undo_pageid", func_int2undo_pageid, func_int2undo_usage },
    { "scn2time",        func_scn2time,        func_scn2time_usage },
    { "dump_extents",    func_dump_extents,    func_dump_extents_usage },
    { "date2time_t",     func_date2time_t,     func_date2time_t_usage },
    { "date2scn",        func_date2scn,        func_date2scn_usage },
    { "repair_space_loss", func_repair_space,  func_repair_space_usage },
    { "decompress_page", func_decompress_extent, func_decompress_extent_usage },
};

func_type_parse_t g_ztbox_func_proc[] = {
    { "scn2time",        func_scn2time,        func_scn2time_usage },
    { "date2time_t",     func_date2time_t,     func_date2time_t_usage },
    { "date2scn",        func_date2scn,        func_date2scn_usage },
};

#define NUM_FUNC_TYPE (sizeof(g_func_proc) / sizeof(func_type_parse_t))
#define ZTBOX_NUM_FUNC_TYPE (sizeof(g_ztbox_func_proc) / sizeof(func_type_parse_t))

static status_t func_int2pageid(int argc, char *argv[])
{
    page_id_t tmp_id;
    int64 tmp_int64;
    int32 need_opt_num = 1;
    if (argc - g_gm_optind < need_opt_num) {
        printf("int2pageid must has input int parameter].");
        printf("try use \"--help\" for more information.\n");
        GS_THROW_ERROR(ERR_INVALID_PARAMETER, "int2pageid input parameter");
        return GS_ERROR;
    }

    cm_str2bigint(argv[g_gm_optind++], &tmp_int64);
    tmp_id = *(page_id_t *)&tmp_int64;

    if (g_gm_optind < argc) {
        printf("try use \"--help\" for more information.\n");
        GS_THROW_ERROR(ERR_INVALID_PARAMETER, argv[g_gm_optind]);
        return GS_ERROR;
    }

    printf("%u-%u\n", tmp_id.file, tmp_id.page);
    return GS_SUCCESS;
}

static void func_int2pageid_usage(void)
{
    printf("-f int2pageid int_value\n");
}

static status_t func_int2undo_pageid(int argc, char *argv[])
{
    undo_page_id_t tmp_id;
    uint32 tmp_int32 = GS_INVALID_ID32;
    int32 need_opt_num = 1;

    if (argc - g_gm_optind < need_opt_num) {
        printf("int2undo_pageid must has input int parameter].");
        printf("try use \"--help\" for more information.\n");
        GS_THROW_ERROR(ERR_INVALID_PARAMETER, "int2undo_pageid input parameter");
        return GS_ERROR;
    }

    cm_str2uint32(argv[g_gm_optind++], &tmp_int32);
    tmp_id = *(undo_page_id_t *)&tmp_int32;

    if (g_gm_optind < argc) {
        printf("try use \"--help\" for more information.\n");
        GS_THROW_ERROR(ERR_INVALID_PARAMETER, argv[g_gm_optind]);
        return GS_ERROR;
    }

    printf("%u-%u\n", tmp_id.file, tmp_id.page);
    return GS_SUCCESS;
}

static void func_int2undo_usage(void)
{
    printf("-f int2undo_pageid int_value\n");
}

static status_t func_scn2time(int argc, char *argv[])
{
    timeval_t tv;
    time_t init_time;
    time_t t;
    struct tm *today = NULL;
    timeval_t *time_val = &tv;
    knl_scn_t scn;
    char timef[GS_MAX_NUMBER_LEN];
    int32 need_opt_num = 2;

    if (argc - g_gm_optind < need_opt_num) {
        printf("scn2time must has input init_time and scn value.");
        printf("try use \"--help\" for more information.\n");
        GS_THROW_ERROR(ERR_INVALID_PARAMETER, "scn2time input parameter");
        return GS_ERROR;
    }

    cm_str2uint64(argv[g_gm_optind++], (uint64 *)&init_time);
    cm_str2uint64(argv[g_gm_optind++], (uint64 *)&scn);
    KNL_SCN_TO_TIME(scn, time_val, init_time);

    if (g_gm_optind < argc) {
        printf("try use \"--help\" for more information.\n");
        GS_THROW_ERROR(ERR_INVALID_PARAMETER, argv[g_gm_optind]);
        return GS_ERROR;
    }

    t = tv.tv_sec;
    today = localtime(&t);
    if (today != NULL) {
        (void)strftime(timef, GS_MAX_NUMBER_LEN, "%Y-%m-%d   %H:%M:%S ", today);
        printf("%s\r\n ", timef);
        return GS_SUCCESS;
    }

    GS_THROW_ERROR_EX(ERR_INVALID_PARAMETER, "invalid scn %llu and init time %llu", (uint64)scn, (uint64)init_time);
    return GS_ERROR;
}

static void func_scn2time_usage(void)
{
    printf("-f scn2time init_time scn\n");
}

static void func_dump_extents_usage(void)
{
    printf("-f dump_extents file_count file_id_1 file_path_1 ... first_extents_file first_extent_page "
           "last_extent_file last_extent_page extents_count page_size [filter_file_id]\n");
}

static void func_repair_space_usage(void)
{
    printf("-f repair_space_loss bitmap_file_path output_file_path page_size [repair]\n");
}

static status_t dump_extents(file_info_t *files, page_list_t *extents, uint32 page_size, uint32 filter_file)
{
    status_t status = GS_SUCCESS;
    page_id_t page_id = extents->first;
    if (page_size == 0 || page_size > UINT16_MAX || page_size % GS_PAGE_UNIT_SIZE != 0) {
        return GS_ERROR;
    }

    char *buf = (char *)malloc(page_size);
    if (buf == NULL) {
        GS_THROW_ERROR(ERR_ALLOC_MEMORY, page_size, "dump_extents");
        return GS_ERROR;
    }

    printf("%-5s %-10s %-5s\n", "file", "page", "idx");

    for (uint32 i = 0; i < extents->count; i++) {
        if (IS_INVALID_PAGID(page_id)) {
            printf("the %u extent is invalid page id %u-%u\n", i, (uint32)page_id.file, (uint32)page_id.page);
            GS_THROW_ERROR(ERR_INVALID_PAGE_ID, "");
            status = GS_ERROR;
            break;
        }

        if (files[page_id.file].file_path == NULL || files[page_id.file].handle == GS_INVALID_ID32) {
            printf("dump_extents need file path of file id %u].", page_id.file);
            printf("try use \"--help\" for more information.\n");
            GS_THROW_ERROR(ERR_INVALID_PARAMETER, "dump_extents input parameter");
            status = GS_ERROR;
            break;
        }

        if (filter_file == GS_INVALID_ID32 || page_id.file == filter_file) {
            printf("%-5u %-10u %-5u\n", page_id.file, page_id.page, i);
        }

        if (miner_read_page(files[page_id.file].handle, buf, page_id.page * page_size, page_size) != GS_SUCCESS) {
            status = GS_ERROR;
            break;
        }
        page_head_t *page = (page_head_t *)buf;
        page_id = AS_PAGID(page->next_ext);
    }

    free(buf);
    return status;
}

static void func_close_files(uint32 file_count, uint32 *file_no, file_info_t *files)
{
    for (uint32 i = 0; i < file_count; i++) {
        uint32 tmp = file_no[i];
        cm_close_file(files[tmp].handle);
    }
}

static void func_dump_extents_init(char *argv[], uint32 *page_size, page_list_t *extents)
{
    uint32 tmp;
    
    cm_str2uint32(argv[g_gm_optind++], &tmp);
    extents->first.file = (uint16)tmp;
    cm_str2uint32(argv[g_gm_optind++], &tmp);
    extents->first.page = (uint16)tmp;
    cm_str2uint32(argv[g_gm_optind++], &tmp);
    extents->last.file = (uint16)tmp;
    cm_str2uint32(argv[g_gm_optind++], &tmp);
    extents->last.page = (uint16)tmp;
    cm_str2uint32(argv[g_gm_optind++], &extents->count);
    cm_str2uint32(argv[g_gm_optind++], page_size);
}

static status_t func_dump_extents(int argc, char *argv[])
{
    uint32 file_count = GS_INVALID_ID32;
    int32 need_opt_num = 9;
    file_info_t files[GS_MAX_DATA_FILES];
    uint32 file_no[GS_MAX_DATA_FILES];
    uint32 i, tmp, page_size;

    if (argc - g_gm_optind < need_opt_num) {
        printf("try use \"--help\" for more information.\n");
        GS_THROW_ERROR(ERR_INVALID_PARAMETER, "dump_extents input parameter");
        return GS_ERROR;
    }

    cm_str2uint32(argv[g_gm_optind++], &file_count);
    if (file_count > GS_MAX_DATA_FILES) {
        printf("try use \"--help\" for more information.\n");
        GS_THROW_ERROR(ERR_INVALID_PARAMETER, "file count parameter is invalid");
        return GS_ERROR;
    }

    for (i = 0; i < GS_MAX_DATA_FILES; i++) {
        files[i].handle = GS_INVALID_ID32;
        files[i].file_path = NULL;
    }
    
    for (i = 0; i < file_count; i++) {
        cm_str2uint32(argv[g_gm_optind++], &tmp);
        if (tmp >= GS_MAX_DATA_FILES) {
            printf("try use \"--help\" for more information.\n");
            GS_THROW_ERROR(ERR_INVALID_PARAMETER, "file id parameter is invalid");
            return GS_ERROR;
        }
        
        file_no[i] = tmp;
        files[tmp].file_path = argv[g_gm_optind++];
        if (cm_open_file(files[tmp].file_path, O_RDONLY | O_BINARY, &files[tmp].handle) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    page_list_t extents;
    uint32 filter_file = GS_INVALID_ID32;

    func_dump_extents_init(argv, &page_size, &extents);

    if (g_gm_optind < argc) {
        if (cm_str2uint32(argv[g_gm_optind++], &filter_file) != GS_SUCCESS) {
            func_close_files(file_count, file_no, files);
            printf("try use \"--help\" for more information.\n");
            GS_THROW_ERROR(ERR_INVALID_PARAMETER, argv[g_gm_optind - 1]);
            return GS_ERROR;
        }
    }

    if (g_gm_optind < argc) {
        func_close_files(file_count, file_no, files);
        printf("try use \"--help\" for more information.\n");
        GS_THROW_ERROR(ERR_INVALID_PARAMETER, argv[g_gm_optind]);
        return GS_ERROR;
    }

    status_t status = dump_extents(files, &extents, page_size, filter_file);

    func_close_files(file_count, file_no, files);

    return status;
}

static status_t func_date2time_t(int argc, char *argv[])
{
    text_t text;
    time_t tmp_time;
    int32 need_opt_num = 1;

    if (argc - g_gm_optind < need_opt_num) {
        printf("date2time_t must has input date parameter.");
        printf("try use \"--help\" for more information.\n");
        GS_THROW_ERROR(ERR_INVALID_PARAMETER, "date2time_t input parameter");
        return GS_ERROR;
    }
    cm_str2text(argv[g_gm_optind++], &text);
    
    date_t date;
    text_t date_fmt1 = { "YYYY-MM-DD HH24:MI:SS", 21 };
    if (cm_text2date(&text, &date_fmt1, &date) != GS_SUCCESS) {
        printf("param value \'%s\' is invalid.\n", (&text)->str);
        return GS_ERROR;
    }
    tmp_time = cm_date2time(date);
    
    if (g_gm_optind < argc) {
        printf("try use \"--help\" for more information.\n");
        GS_THROW_ERROR(ERR_INVALID_PARAMETER, argv[g_gm_optind]);
        return GS_ERROR;
    }

    printf("%lld\r\n ", (int64)tmp_time);
    return GS_SUCCESS;
}

static void func_date2time_t_usage(void)
{
    printf("-f date2time_t date\n");
}

static status_t func_init_input(func_input_def_t *input)
{
    input->page_sn = GS_INVALID_ID32;
    input->file_path = NULL;
    input->head_buf = NULL;
    input->handle = GS_INVALID_INT32;
    input->is_decompress_extent = GS_FALSE;
    return GS_SUCCESS;
}

static status_t func_get_input(int argc, char *argv[], func_input_def_t *input)
{
    int32 c = miner_getopt(argc, argv, "F:P:");
    while (c != -1) {
        switch (c) {
            case 'F':
                if (input->file_path == NULL && g_gm_optarg != NULL) {
                    input->file_path = (char *)cm_strdup(g_gm_optarg);
                } else {
                    printf("try use \"ztbox -T zfunc -f decompress_page --help/-h\" for more information.\n");
                    return GS_ERROR;
                }
                break;
            case 'P':
                if (input->page_sn == GS_INVALID_ID32 && g_gm_optarg != NULL) {
                    input->page_sn = (uint32)atoi(g_gm_optarg);
                } else {
                    printf("try use \"ztbox -T zfunc -f decompress_page --help/-h\" for more information.\n");
                    return GS_ERROR;
                }
                break;
            default:
                printf("try use \"ztbox -T zfunc -f decompress_page --help/-h\" for more information.\n");
                return GS_ERROR;
        }
        c = miner_getopt(argc, argv, "F:P:");
    }
    return GS_SUCCESS;
}

static status_t func_check_input(int argc, char *argv[], func_input_def_t *input)
{
    if (g_gm_optind > argc) {
        printf("invalid argument : \"%s\"", argv[g_gm_optind]);
        GS_THROW_ERROR(ERR_INVALID_PARAMETER, "zfunc input parameter");
        return GS_ERROR;
    }
    if (input->is_decompress_extent) {
        if (input->file_path == NULL) {
            return GS_ERROR;
        }
        if (!cm_file_exist(input->file_path)) {
            return GS_ERROR;
        }
        if (input->page_sn == GS_INVALID_ID32) {
            return GS_ERROR;
        }
    }
    return GS_SUCCESS;
}

static void func_free_input(func_input_def_t *input)
{
    CM_FREE_PTR(input->file_path);
    CM_FREE_PTR(input->head_buf);
    if (input->handle != GS_INVALID_INT32) {
        cm_close_file(input->handle);
        input->handle = GS_INVALID_INT32;
    }
}

static status_t func_decompress_extent(int argc, char *argv[])
{
    func_input_def_t input;
    page_head_t *head = NULL;
    compress_page_head_t *group_head = NULL;
    if (func_usage_ex(argc, argv) == GS_SUCCESS) {
        return GS_SUCCESS;
    }
    if (func_init_input(&input) != GS_SUCCESS) {
        func_free_input(&input);
        return GS_ERROR;
    }
    if (func_get_input(argc, argv, &input) != GS_SUCCESS) {
        GS_THROW_ERROR(ERR_INVALID_PARAMETER, "zfunc input parameter");
        func_free_input(&input);
        return GS_ERROR;
    }
    input.is_decompress_extent = GS_TRUE;
    if (func_check_input(argc, argv, &input) != GS_SUCCESS) {
        GS_THROW_ERROR(ERR_INVALID_PARAMETER, "zfunc input parameter");
        func_free_input(&input);
        return GS_ERROR;
    }
    const char *file_path = input.file_path;
    if (cm_open_file(file_path, O_RDWR | O_BINARY | O_SYNC, &input.handle) != GS_SUCCESS) {
        func_free_input(&input);
        return GS_ERROR;
    }
    input.head_buf = (char *)malloc(FUNC_DEF_PAGE_SIZE * PAGE_GROUP_COUNT);
    if (input.head_buf == NULL) {
        func_free_input(&input);
        GS_THROW_ERROR(ERR_ALLOC_MEMORY, MINER_DEF_PAGE_SIZE, "zfunc decompress page");
        return GS_ERROR;
    }
    if (miner_read_page(input.handle, input.head_buf, extent_begin_page_sn(input.page_sn) * FUNC_DEF_PAGE_SIZE,
        FUNC_DEF_PAGE_SIZE * PAGE_GROUP_COUNT) != GS_SUCCESS) {
        func_free_input(&input);
        return GS_ERROR;
    }
    head = (page_head_t *)input.head_buf;
    group_head = COMPRESS_PAGE_HEAD(head);
    if (func_desc_compress_extent(head, group_head, input.page_sn) != GS_SUCCESS) {
        func_free_input(&input);
        return GS_ERROR;
    }
    func_free_input(&input);
    return GS_SUCCESS;
}

static status_t func_desc_compress_extent(page_head_t *head, compress_page_head_t *group_head, uint32 page_sn)
{
    if (!head->compressed) {
        printf("don't find compressed page with id:%u.\n ", extent_begin_page_sn(page_sn));
        return GS_ERROR;
    }
    char *dst_buf = NULL;
    uint32 dst_buf_size = PAGE_GROUP_COUNT * PAGE_SIZE(*head);
    dst_buf = (char *)malloc(dst_buf_size);
    if (dst_buf == NULL) {
        GS_THROW_ERROR(ERR_ALLOC_MEMORY, dst_buf_size, "zfunc decompress datafile");
        return GS_ERROR;
    }
    switch (group_head->compress_algo) {
        case COMPRESS_ZSTD: {
            if (func_zstd_decompress_extent(dst_buf, dst_buf_size, head, group_head) != GS_SUCCESS) {
                printf("Error! ZSTD decompress extent fault");
                CM_FREE_PTR(dst_buf);
                return GS_ERROR;
            }
            for (int i = 0; i < PAGE_GROUP_COUNT; ++i) {
                miner_desc_page(extent_begin_page_sn(page_sn) + i, dst_buf + i * FUNC_DEF_PAGE_SIZE, FUNC_DEF_PAGE_SIZE,
                    GS_FALSE, GS_FALSE);
            }
            break;
        }
        case COMPRESS_ZLIB: {
            printf("COMPRESS_ZLIB nonsupport.");
            break;
        }
        case COMPRESS_LZ4: {
            printf("COMPRESS_LZ4 nonsupport.");
            break;
        }
        default: {
            printf("NULL algorithm");
            break;
        }
    }
    CM_FREE_PTR(dst_buf);
    return GS_SUCCESS;
}

static status_t func_zstd_decompress_extent(char *dst_buf, uint32 dst_buf_size,
    page_head_t *head, compress_page_head_t *group_head)
{
    char *src_buf = (char *)malloc(group_head->compressed_size);
    if (src_buf == NULL) {
        GS_THROW_ERROR(ERR_ALLOC_MEMORY, group_head->compressed_size, "zfunc decompress page");
        CM_FREE_PTR(src_buf);
        return GS_ERROR;
    }

    uint32 count;
    uint32 remain_size = group_head->compressed_size;
    uint32 length_compressed_page_body = FUNC_DEF_PAGE_SIZE - PAGE_HEAD_SIZE - sizeof(compress_page_head_t);
    uint32 src_moved_size = PAGE_HEAD_SIZE + sizeof(compress_page_head_t);
    uint32 dst_moved_size = 0;

    while (remain_size > 0) {
        if (remain_size < length_compressed_page_body) {
            count = remain_size;
        } else {
            count = length_compressed_page_body;
        }
        errno_t ret = memcpy_sp(src_buf + dst_moved_size, remain_size, (char *)head + src_moved_size, count);
        if (ret != EOK) {
            GS_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)GS_MAX_LOG_BUFFER_SIZE, "func ZSTD decompress extent block");
            CM_FREE_PTR(src_buf);
            return GS_ERROR;
        }
        dst_moved_size += count;
        src_moved_size += FUNC_DEF_PAGE_SIZE;
        remain_size -= count;
    }
    uint32 verify_size = ZSTD_decompress(dst_buf, dst_buf_size, src_buf, group_head->compressed_size);
    if (verify_size != dst_buf_size) {
        printf("Error! Impossible because zstd will check this condition!");
        CM_FREE_PTR(src_buf);
        return GS_ERROR;
    }
    CM_FREE_PTR(src_buf);
    return GS_SUCCESS;
}

static void func_decompress_extent_usage(void)
{
    printf("decompress_page is an decompressing tool to decompress the entire extent.\n"
        "Usage:\n"
        "ztbox -T zfunc -f decompress_page -F <filename> -P <page_id>\n"
        "filename --the table compressed file to decompress.\n"
        "page_id -- the id of compressed page to decompress.\n"
        "eg:ztbox -T zfunc -f decompress_page -F compress -P 193\n"
    );
}

static status_t func_usage_ex(int argc, char *argv[])
{
    if (argc < g_gm_optind) {
        return GS_ERROR;
    }
    if (strcmp(argv[g_gm_optind], "--help") == 0 || strcmp(argv[g_gm_optind], "-h") == 0) {
        for (int i = 0; i < NUM_FUNC_TYPE; ++i) {
            if (strcmp(argv[g_gm_optind - 1], g_func_proc[i].func_name) == 0) {
                g_func_proc[i].func_usage_proc();
                return GS_SUCCESS;
            }
        }
    }
    if (strcmp(argv[g_gm_optind], "--version") == 0 || strcmp(argv[g_gm_optind], "-V") == 0) {
        tbox_print_version();
        return GS_SUCCESS;
    }
    return GS_ERROR;
}

static status_t func_date2scn(int argc, char *argv[])
{
    time_t init_time;
    uint64 scn;
    int32 need_opt_num = 2;

    if (argc - g_gm_optind < need_opt_num) {
        printf("date2scn must has input init_time and date value.");
        printf("try use \"--help\" for more information.\n");
        GS_THROW_ERROR(ERR_INVALID_PARAMETER, "date2scn input parameter");
        return GS_ERROR;
    }
    cm_str2uint64(argv[g_gm_optind++], (uint64 *)&init_time);
    
    text_t date_fmt1 = { "YYYY-MM-DD HH24:MI:SS", 21 };
    struct timeval time;
    time.tv_usec = 0;
    cm_str2time(argv[g_gm_optind++], &date_fmt1, &time.tv_sec);

    if (time.tv_sec < init_time) {
        GS_THROW_ERROR(ERR_TOO_OLD_SCN, "no snapshot found based on specified time");
        return GS_ERROR;
    }

    scn = KNL_TIME_TO_SCN(&time, init_time);
    printf("%llu\r\n ", (uint64)scn);
    return GS_SUCCESS;
}

static void func_date2scn_usage(void)
{
    printf("-f date2scn init_time date\n");
}

static void usage(void)
{
    uint32 i;
    printf("Zfunc contains common functions for Z-engine.\n"
           "\n"
           "Usage:\n"
           "  zfunc [OPTIONS]\n"
           "\nRequired options:\n"
           "  -f FUNCTIONNAME  the function name to use\n");

    printf("\nCommon options:\n"
           "  --help, -h       show this help, then exit\n"
           "  --version, -V    output version information, then exit\n");

    for (i = 0; i < NUM_FUNC_TYPE; i++) {
        g_func_proc[i].func_usage_proc();
    }
}

static status_t copy_map_pages(repair_src_info_t *info)
{
    int64 maps_offset;
    uint32 maps_size;
    df_map_head_t *map_head = (df_map_head_t *)info->buf_map_head;
    int64 total_size = 0;
    if (info->page_size == 0 || info->page_size > UINT16_MAX || info->page_size % GS_PAGE_UNIT_SIZE != 0) {
        return GS_ERROR;
    }
    for (uint32 i = 0; i < map_head->group_count; i++) {
        df_map_group_t *map_group = &map_head->groups[i];
        maps_offset = (int64)(map_group->first_map.page) * info->page_size;
        maps_size = map_group->page_count * info->page_size;
        // read bitmap pages to src buf and output buf
        if (miner_read_page(info->data_file.handle, info->buf_src_bt, maps_offset, maps_size) != GS_SUCCESS) {
            return GS_ERROR;
        }
        knl_securec_check(memcpy_sp(info->buf_output_bt + total_size, maps_size, info->buf_src_bt, maps_size));
        total_size += maps_size;
    }
    // write to output file, total size less than int32 range
    return repair_write_page(info->output_file.handle, info->buf_output_bt, 0, (uint32)total_size);
}

static inline uint32 repair_ext_size_by_cnt(uint32 count)
{
    if (count < EXT_SIZE_8_BOUNDARY) {
        return EXT_SIZE_8;
    } else if (count < EXT_SIZE_128_BOUNDARY) {
        return EXT_SIZE_128;
    } else if (count < EXT_SIZE_1024_BOUNDARY) {
        return EXT_SIZE_1024;
    } else {
        return EXT_SIZE_8192;
    }
}

static uint32 repair_ext_size_by_id(uint8 size_id)
{
    switch (size_id) {
        case EXT_SIZE_8_ID:
            return EXT_SIZE_8;
        case EXT_SIZE_128_ID:
            return EXT_SIZE_128;
        case EXT_SIZE_1024_ID:
            return EXT_SIZE_1024;
        case EXT_SIZE_8192_ID:
            return EXT_SIZE_8192;
        default:
            return EXT_SIZE_8;
    }
}

static uint8 repair_ext_id_by_size(uint32 extent_size)
{
    switch (extent_size) {
        case EXT_SIZE_8:
            return EXT_SIZE_8_ID;
        case EXT_SIZE_128:
            return EXT_SIZE_128_ID;
        case EXT_SIZE_1024:
            return EXT_SIZE_1024_ID;
        case EXT_SIZE_8192:
            return EXT_SIZE_8192_ID;
        default:
            return EXT_SIZE_8_ID;
    }
}

static inline uint32 repair_calc_bitmap_pages(df_map_head_t *map_head)
{
    uint32 page_count = 0;
    df_map_group_t *map_group = NULL;
    for (uint32 i = 0; i < map_head->group_count; i++) {
        map_group = &map_head->groups[i];
        page_count += map_group->page_count;
    }

    return page_count;
}

static uint32 repair_locate_map_by_pageid(char *buf_bitmap_pages, df_map_head_t *map_head, page_id_t page_id,
    uint32 page_size, uint16 *map_id, uint16 *bit_id)
{
    uint32 i, page_start, page_end;
    df_map_group_t *map_group = NULL;
    df_map_page_t *map_page = NULL;
    uint32 start = 0;
    /* find bitmap group, map page id in group and bit id in bitmap of this extent */
    for (i = 0; i < map_head->group_count; i++) {
        map_group = &map_head->groups[i];
        map_page = (df_map_page_t *)(buf_bitmap_pages + start * page_size);
        page_start = map_page->first_page.page;

        page_end = page_start + ztbox_df_map_bit_cnt(page_size) * map_head->bit_unit * map_group->page_count - 1;
        if (page_id.page <= page_end) {
            *map_id = (page_id.page - page_start) / map_head->bit_unit / ztbox_df_map_bit_cnt(page_size);
            *bit_id = (page_id.page - page_start) / map_head->bit_unit % ztbox_df_map_bit_cnt(page_size);
            break;
        }
        start += map_group->page_count;
    }
    return (start + *map_id);
}

static void repair_free_extent(char *bitmap_buf, df_map_head_t *map_head,
    page_head_t *extent, uint32 page_size, map_group_lock_t *page_locks)
{
    uint16 bit_id = 0;
    uint16 map_id = 0;
    page_id_t page_id = AS_PAGID(&extent->id);
    uint32 page_offset = repair_locate_map_by_pageid(bitmap_buf, map_head, page_id, page_size, &map_id, &bit_id);

    /*
     * 1 fix bits
     * 2 try update free_begin and free bits
     * 3 DO NOT write file here, write outfile in last
     */
    df_map_page_t *map_page = (df_map_page_t *)(bitmap_buf + (int64)(page_offset) * page_size);
    uint16 bit_len = spc_ext_size_by_id((uint8)extent->ext_size) / map_head->bit_unit;

    spinlock_t *lock = &(page_locks[page_offset / DF_MAP_GROUP_SIZE].page_locks[page_offset % DF_MAP_GROUP_SIZE]);
    cm_spin_lock(lock, NULL);
    df_unset_bitmap(map_page->bitmap, bit_id, bit_len);
    map_page->free_bits += bit_len;
    knl_panic(map_page->free_bits <= ztbox_df_map_bit_cnt(page_size));
    if (bit_id < map_page->free_begin) {
        map_page->free_begin = bit_id;
    }
    cm_spin_unlock(lock);
}

static status_t repair_try_repair_one_extent(repair_thread_src_t *t_src, page_list_t *extents, bool32 is_degrade,
    uint32 ext_size, uint32 exp_ext_size)
{
    if (!t_src->repair) {
        return GS_SUCCESS;
    }
    uint32 page_size = t_src->p_size;
    file_info_t *date_file = &t_src->file;
    page_head_t *page_head = (page_head_t *)t_src->buf_ext;
    if (!is_degrade) {
        page_head->ext_size = repair_ext_id_by_size(exp_ext_size);
        page_calc_checksum(page_head, page_size);
        // WRITE to SOURCE DATA FILE
        if (repair_write_page(date_file->handle, t_src->buf_ext,
            (int64)(extents->first.page) * page_size, page_size) != GS_SUCCESS) {
            printf("[FATAL] ztbox repair error, write datafile %s.\n", date_file->file_path);
            return GS_ERROR;
        }
        printf("Repair datafile %s page %u ext_size from %u to %u.\n",
            date_file->file_path, extents->first.page, ext_size, exp_ext_size);
    } else {
        printf("[WARNING]Can not repair datafile %s page %u ext_size from %u to %u. "
            "Because segment alloc has been degraded.\n",
            date_file->file_path, extents->first.page, ext_size, exp_ext_size);
    }
    return GS_SUCCESS;
}

static status_t repair_free_extents(repair_thread_src_t *t_src, page_list_t *extents,
    bool32 auto_alloc, bool32 is_degrade, uint32 *leak_exts, uint32 *leak_pages)
{
    uint32 idx = 0;
    uint32 ext_size, exp_ext_size;
    df_map_head_t *map_head = (df_map_head_t *)t_src->buf_map_head;
    file_info_t *date_file = &t_src->file;
    uint32 page_size = t_src->p_size;
    page_head_t *page_head = NULL;
    *leak_exts = 0;
    *leak_pages = 0;

    while (extents->count > 0) {
        if (IS_INVALID_PAGID(extents->first)) {
            printf("the %u extent is invalid page id %u-%u\n",
                extents->count, (uint32)extents->first.file, (uint32)extents->first.page);
            GS_THROW_ERROR(ERR_INVALID_PAGE_ID, "");
            return GS_ERROR;
        }

        if (miner_read_page(date_file->handle, t_src->buf_ext,
            (int64)(extents->first.page) * page_size, page_size) != GS_SUCCESS) {
            printf("read datafile %s error, offset is %lld ,read size is %u", date_file->file_path,
                (int64)(extents->first.page) * page_size, page_size);
            return GS_ERROR;
        }

        page_head = (page_head_t *)t_src->buf_ext;
        ext_size = repair_ext_size_by_id((uint8)page_head->ext_size);
        exp_ext_size = repair_ext_size_by_cnt(idx);
        // only lob is not auto allocate
        if (!auto_alloc) {
            if (ext_size != ZTBOX_BITMAP_EXT_BASE_SIZE) {
                printf("[FATAL] extent size %u is not equal to expect extent size %u, "
                    "but it is not auto allocate segment.\n", ext_size, exp_ext_size);
                return GS_ERROR;
            }
        } else if (ext_size != exp_ext_size) {
            if (repair_try_repair_one_extent(t_src, extents, is_degrade, ext_size,
                exp_ext_size) != GS_SUCCESS) {
                return GS_ERROR;
            }
            (*leak_exts)++;
            (*leak_pages) += abs(exp_ext_size - ext_size);
            // should output this invalid extent info? write this extent page_head to output file tail
        }

        // update output bitmap file buf, like delete.
        repair_free_extent(t_src->buf_output_bt, map_head, page_head, page_size, t_src->group_locks);

        extents->first = AS_PAGID(page_head->next_ext);
        extents->count--;
        idx++;
    }

    return GS_SUCCESS;
}

static uint32 repair_map_page_bits(df_map_page_t *output_map_page, df_map_page_t *df_map_page,
    page_id_t *map_page_id, uint32 page_size)
{
    // use search result fix datafile bitmap
    uint32 bit_id = 0;
    uint32 fix_count = 0;
    while (bit_id < ztbox_df_map_bit_cnt(page_size)) {
        if (DF_MAP_UNMATCH(output_map_page->bitmap, bit_id)) {
            DF_MAP_UNSET(df_map_page->bitmap, bit_id);
            df_map_page->free_bits++;
            if (bit_id < df_map_page->free_begin) {
                df_map_page->free_begin = bit_id;
            }
            printf("Repair bitmap page %u-%u, bit position %u, free bits %u\n",
                map_page_id->file, map_page_id->page, bit_id, df_map_page->free_bits);
            fix_count++;
        }
        bit_id++;
    }
    return fix_count;
}

static status_t repair_map_page(file_info_t *data_file, df_map_page_t *output_map_page, char *df_page_buf,
    uint32 page_size)
{
    page_id_t *map_page_id = AS_PAGID_PTR(output_map_page->page_head.id);
    if (output_map_page->free_bits < ztbox_df_map_bit_cnt(page_size)) {
        if (miner_read_page(data_file->handle, df_page_buf, (int64)(map_page_id->page) * page_size,
            page_size) != GS_SUCCESS) {
            printf("Can not read datafile %s, offset %u, read size %u.\n",
                data_file->file_path, (map_page_id->page) * page_size, page_size);
            return GS_ERROR;
        }
        df_map_page_t *df_map_page = (df_map_page_t *)df_page_buf;
        // use search result fix datafile bitmap
        uint32 fix_count = repair_map_page_bits(output_map_page, df_map_page, map_page_id, page_size);
        if (fix_count > 0) {
            printf("[SUMMARY]ztbox repair bitmap page %u-%u, fix %u bits, free bits %u, free begin %u.\n",
                map_page_id->file, map_page_id->page, fix_count, df_map_page->free_bits, df_map_page->free_begin);
            if (df_map_page->free_bits > ztbox_df_map_bit_cnt(page_size)) {
                printf("[FATAL]ztbox repair error, source bitmap page %u-%u free bits %u large than max bits %u.\n",
                    map_page_id->file, map_page_id->page, df_map_page->free_bits, ztbox_df_map_bit_cnt(page_size));
                return GS_ERROR;
            }

            // reset bitmap page on disk
            page_calc_checksum(&df_map_page->page_head, page_size);
            if (repair_write_page(data_file->handle, df_page_buf,
                (int64)(map_page_id->page) * page_size, page_size) != GS_SUCCESS) {
                printf("[FATAL]ztbox repair error, write datafile %s error.\n", data_file->file_path);
                return GS_ERROR;
            }
        }
    }
    return GS_SUCCESS;
}

static status_t repair_map_pages(repair_src_info_t *src_info, uint32 page_count)
{
    char *page_buf = (char *)malloc(src_info->page_size); // only for bitmap head
    if (page_buf == NULL) {
        printf("[ERROR]alloc page buf %u error.\n", src_info->page_size);
        return GS_ERROR;
    }

    df_map_page_t *map_page = NULL;
    for (uint32 i = 0; i < page_count; i++) {
        map_page = (df_map_page_t *)(src_info->buf_output_bt + i * src_info->page_size);
        if (repair_map_page(&src_info->data_file, map_page, page_buf, src_info->page_size) != GS_SUCCESS) {
            CM_FREE_PTR(page_buf);
            return GS_ERROR;
        }
    }
    CM_FREE_PTR(page_buf);
    return GS_SUCCESS;
}

static uint32 repair_calc_set_bits(repair_src_info_t *src_info, uint32 page_count)
{
    df_map_page_t *map_page = NULL;
    uint32 page_size = src_info->page_size;
    uint32 bits = 0;
    for (uint32 i = 0; i < page_count; i++) {
        map_page = (df_map_page_t *)(src_info->buf_output_bt + i * src_info->page_size);
        bits += ztbox_df_map_bit_cnt(page_size) - map_page->free_bits;
    }
    return bits;
}

static inline void repair_release_resource(repair_src_info_t *src_info)
{
    cm_close_file(src_info->data_file.handle);
    cm_close_file(src_info->output_file.handle);
    CM_FREE_PTR(src_info->buf_map_head);
    CM_FREE_PTR(src_info->buf_src_bt);
    CM_FREE_PTR(src_info->buf_output_bt);
    CM_FREE_PTR(src_info->group_locks);
}

static void repair_init_src_info(repair_src_info_t *src_info)
{
    src_info->data_file.handle = GS_INVALID_HANDLE;
    src_info->data_file.file_path = NULL;
    src_info->output_file.handle = GS_INVALID_HANDLE;
    src_info->data_file.file_path = NULL;
    src_info->repair = GS_FALSE;
    src_info->buf_map_head = NULL;
    src_info->buf_src_bt = NULL;
    src_info->buf_output_bt = NULL;
    src_info->next_page_id = DF_MAP_HWM_START;
    src_info->lock = 0;
    src_info->group_locks = NULL;
}

status_t repair_get_input(int argc, char *argv[], repair_src_info_t *src_info, uint32 *bitmap_pages)
{
    if (argc - g_gm_optind < ZTBOX_REPAIR_OPT_NUM) {
        printf("try use \"--help\" for more information.\n");
        GS_THROW_ERROR(ERR_INVALID_PARAMETER, "dump_extents input parameter");
        return GS_ERROR;
    }

    // first get data file path, open file by REPAIR.
    src_info->data_file.file_path = argv[g_gm_optind++];
    src_info->output_file.file_path = argv[g_gm_optind++];

    cm_str2uint32(argv[g_gm_optind++], &(src_info->page_size));
    if (src_info->page_size == 0) {
        printf("page size must large then 0.\n");
        return GS_ERROR;
    }

    if (g_gm_optind < argc) {
        if (cm_strcmpi(argv[g_gm_optind++], "repair") == 0) {
            src_info->repair = GS_TRUE;
        }
    }

    uint32 df_mode = O_BINARY | (src_info->repair ? O_RDWR : O_RDONLY);
    if (cm_open_file(src_info->data_file.file_path, df_mode, &src_info->data_file.handle) != GS_SUCCESS) {
        printf("Can not open datafile %s.\n", src_info->data_file.file_path);
        return GS_ERROR;
    }

    if (cm_open_file(src_info->output_file.file_path, O_RDWR | O_BINARY | O_SYNC | O_CREAT | O_TRUNC,
        &src_info->output_file.handle) != GS_SUCCESS) {
        cm_close_file(src_info->data_file.handle);
        printf("Can not open output file %s.\n", src_info->output_file.file_path);
        return GS_ERROR;
    }

    cm_get_filesize(src_info->data_file.file_path, &(src_info->file_size));

    src_info->buf_map_head = (char *)malloc(src_info->page_size); // only for bitmap head
    if (src_info->buf_map_head == NULL) {
        printf("Alloc memory %u failed.\n", src_info->page_size);
        return GS_ERROR;
    }

    if (miner_read_page(src_info->data_file.handle, src_info->buf_map_head,
        (int64)(src_info->page_size) * DF_MAP_HEAD_PAGE, src_info->page_size) != GS_SUCCESS) {
        printf("Read file %s error, fail to get bitmap head.", src_info->data_file.file_path);
        return GS_ERROR;
    }
    
    *bitmap_pages = repair_calc_bitmap_pages((df_map_head_t *)src_info->buf_map_head);
    int64 total_size = (int64)(*bitmap_pages) * src_info->page_size;
    src_info->buf_src_bt = (char *)malloc(total_size);
    src_info->buf_output_bt = (char *)malloc(total_size);
    if (src_info->buf_src_bt == NULL || src_info->buf_output_bt == NULL) {
        printf("Alloc memory %lld failed.\n", total_size);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t repair_init_map_page_lock(repair_src_info_t *src_info)
{
    df_map_head_t *map_head = (df_map_head_t *)src_info->buf_map_head;
    uint32 size = sizeof(map_group_lock_t) * map_head->group_count;
    if (size == 0) {
        return GS_ERROR;
    }
    src_info->group_locks = (map_group_lock_t *)malloc(size);
    if (src_info->group_locks == NULL) {
        printf("Alloc memory %u failed.\n", size);
        return GS_ERROR;
    }
    if (memset_sp(src_info->group_locks, size, 0, size) != EOK) {
        printf("Memory set %u failed.\n", size);
        return GS_ERROR;
    }
    return GS_SUCCESS;
}
/*
 * 1 check parameter
 * 2 alloc resource
 */
status_t repair_prepare(int argc, char *argv[], repair_src_info_t *src_info, uint32 *bitmap_pages)
{
    repair_init_src_info(src_info);

    if (repair_get_input(argc, argv, src_info, bitmap_pages) != GS_SUCCESS) {
        repair_release_resource(src_info);
        return GS_ERROR;
    }

    if (repair_init_map_page_lock(src_info) != GS_SUCCESS) {
        repair_release_resource(src_info);
        return GS_ERROR;
    }

    // copy all map pages to output file
    if (copy_map_pages(src_info) != GS_SUCCESS) {
        repair_release_resource(src_info);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static inline status_t repair_write_file(file_info_t *data_file, char *buf_file, uint32 file_size)
{
    if (repair_write_page(data_file->handle, buf_file, 0, file_size) != GS_SUCCESS) {
        printf("[FATAL]ztbox repair error, write datafile %s error, size %u.\n",
            data_file->file_path, file_size);
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

static inline void repair_try_print_segment_info(uint32 leak_exts, uint32 leak_pages, page_head_t *page,
    bool32 free_ext)
{
    page_id_t *page_id = AS_PAGID_PTR(page->id);
    if (leak_exts > 0) {
        printf("[SUMMARY segment] %s %u-%u find %s extent size error, %u extents leaked, %u pages leaked.\n",
            page_type(page->type), page_id->file, page_id->page, free_ext ? "free extent" : "extent",
            leak_exts, leak_pages);
    }
}

static inline void repair_init_segment_info(bool32 *is_degrade, bool32 *is_free_degrade, bool32 *auto_alloc,
    page_list_t *free_extents)
{
    *is_degrade = GS_FALSE;
    *is_free_degrade = GS_FALSE;
    *auto_alloc = GS_TRUE;
    free_extents->count = 0;
}

/*
 * read for each block, defined asd 4G
 *   parameter start is page id
 */
static status_t repair_scan_one_block(repair_thread_src_t *t_src, uint32 start)
{
    bool32 auto_alloc = GS_TRUE;
    uint32 leak_exts, leak_pages;   // bit map page count
    page_head_t *page = NULL;
    page_list_t extents, free_extents;
    bool32 is_degrade = GS_FALSE;
    bool32 is_free_degrade = GS_FALSE;
    for (int64 i = start; i < start + REPAIR_BLOCK_PAGES; i += ZTBOX_BITMAP_EXT_BASE_SIZE) {
        if (miner_read_page(t_src->file.handle, t_src->buf_seg, i * t_src->p_size, t_src->p_size) != GS_SUCCESS) {
            return GS_SUCCESS;
        }

        page = (page_head_t *)t_src->buf_seg;
        repair_init_segment_info(&is_degrade, &is_free_degrade, &auto_alloc, &free_extents);
        switch (page->type) {
            case PAGE_TYPE_HEAP_HEAD: {
                    heap_segment_t *heap_seg = (heap_segment_t *)((char *)page + PAGE_HEAD_SIZE);
                    extents = heap_seg->extents;
                    free_extents = heap_seg->free_extents;
                    is_degrade = (heap_seg->page_count == 0) ? GS_FALSE : GS_TRUE;
                    is_free_degrade = (heap_seg->free_page_count == 0) ? GS_FALSE : GS_TRUE;
                }
                break;
            case PAGE_TYPE_BTREE_HEAD: {
                    btree_segment_t *btree_seg = (btree_segment_t *)((char *)page + CM_ALIGN8(sizeof(btree_page_t)));
                    extents = btree_seg->extents;
                    is_degrade = (btree_seg->page_count == 0) ? GS_FALSE : GS_TRUE;
                }
                break;
            case PAGE_TYPE_LOB_HEAD: {
                    lob_segment_t *lob_seg = (lob_segment_t *)((char *)page + PAGE_HEAD_SIZE);
                    extents = lob_seg->extents;
                    auto_alloc = GS_FALSE;
                }
                break;
            default:
                continue;
        }

        if (repair_free_extents(t_src, &extents, auto_alloc, is_degrade, &leak_exts, &leak_pages) != GS_SUCCESS) {
            return GS_ERROR;
        }
        repair_try_print_segment_info(leak_exts, leak_pages, page, GS_FALSE);

        if (repair_free_extents(t_src, &free_extents, auto_alloc, is_free_degrade, &leak_exts,
            &leak_pages) != GS_SUCCESS) {
            return GS_ERROR;
        }
        repair_try_print_segment_info(leak_exts, leak_pages, page, GS_TRUE);
    }

    return GS_SUCCESS;
}

static status_t repair_init_thread_source(repair_src_info_t *src_info, repair_thread_src_t *t_src)
{
    t_src->p_size =  src_info->page_size;
    t_src->buf_map_head = src_info->buf_map_head;
    t_src->buf_output_bt = src_info->buf_output_bt;
    t_src->repair = src_info->repair;
    t_src->lock = &src_info->lock;
    t_src->group_locks = src_info->group_locks;
    t_src->buf_ext = (char *)malloc(t_src->p_size);      // for extents
    t_src->buf_seg = (char *)malloc(t_src->p_size);      // for segemnt
    if (t_src->buf_ext == NULL || t_src->buf_seg == NULL) {
        printf("alloc memory %u error.\n", t_src->p_size);
        CM_FREE_PTR(t_src->buf_ext);
        CM_FREE_PTR(t_src->buf_seg);
        GS_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)t_src->p_size, "repair space loss");
        return GS_ERROR;
    }

    t_src->file.file_path = src_info->data_file.file_path;
    uint32 df_mode = O_BINARY | (src_info->repair ? O_RDWR : O_RDONLY);
    if (cm_open_file(t_src->file.file_path, df_mode, &t_src->file.handle) != GS_SUCCESS) {
        printf("Can not open data file %s.\n", t_src->file.file_path);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static void repair_release_thread_source(repair_thread_src_t *t_src)
{
    CM_FREE_PTR(t_src->buf_ext);
    CM_FREE_PTR(t_src->buf_seg);
}

static inline bool32 repair_paral_get_blocks(repair_src_info_t *src_info, uint32 *start_page)
{
    cm_spin_lock(&src_info->lock, NULL);
    if (src_info->file_size / src_info->page_size < src_info->next_page_id) {
        cm_spin_unlock(&src_info->lock);
        return GS_FALSE;
    }
    *start_page = src_info->next_page_id;
    src_info->next_page_id += REPAIR_BLOCK_PAGES;
    cm_spin_unlock(&src_info->lock);
    return GS_TRUE;
}

void repair_paral_task_proc(thread_t *thread)
{
    repair_process_t *proc = (repair_process_t *)thread->argument;
    repair_src_info_t *src_info = proc->src_info;
    repair_thread_src_t t_src;

    if (repair_init_thread_source(src_info, &t_src) != GS_SUCCESS) {
        printf("[ERROR] init work thread resouce error.\n");
        proc->finish = GS_TRUE;
        return;
    }

    uint32 start_page;
    while (repair_paral_get_blocks(src_info, &start_page)) {
        if (repair_scan_one_block(&t_src, start_page) != GS_SUCCESS) {
            printf("[ERROR] scan block error, start page %u, thread id %d\n", start_page, proc->idx);
            continue;
        }
    }
    repair_release_thread_source(&t_src);
    proc->finish = GS_TRUE;
}

static status_t repair_run(repair_src_info_t *src_info)
{
    repair_process_t repair_proc[REPAIR_PROCESS_NUM];

    if (src_info->file_size <= 0) {
        printf("[ERROR] file \"%s\" size %lld is invaild.\n", src_info->data_file.file_path,
            src_info->file_size);
        return GS_ERROR;
    }

    // page number is uint32, file size is int64. there is correct
    uint32 pages = src_info->file_size / src_info->page_size;
    uint32 blocks = pages / REPAIR_BLOCK_PAGES + 1;
    uint32 run_thread = (blocks < REPAIR_PROCESS_NUM) ? blocks : REPAIR_PROCESS_NUM;

    repair_process_t *proc = NULL;
    for (uint32 i = 0; i < run_thread; i++) {
        proc = &repair_proc[i];
        proc->finish = GS_FALSE;
        proc->idx = i;
        proc->src_info = src_info;
        if (cm_create_thread(repair_paral_task_proc, 0, proc, &proc->thread) != GS_SUCCESS) {
            printf("[ERROR] create thread %u error\n", i);
            return GS_ERROR;
        }
    }

    // wait for all threads finish
    for (uint32 i = 0; i < run_thread; i++) {
        proc = &repair_proc[i];
        while (!proc->finish) {
            cm_sleep(200);     // check finish every one second
        }
        cm_close_thread(&proc->thread);
    }

    return GS_SUCCESS;
}

static status_t func_repair_execute(int argc, char *argv[])
{
    repair_src_info_t src_info;
    status_t status = GS_SUCCESS;
    uint32 page_count;      // bit map page count

    if (repair_prepare(argc, argv, &src_info, &page_count) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (repair_run(&src_info) == GS_SUCCESS) {
        status = repair_write_file(&src_info.output_file, src_info.buf_output_bt,
            page_count * src_info.page_size);
    }

    uint32 leak_spc_pages = repair_calc_set_bits(&src_info, page_count) * DF_BYTE_TO_BITS;
    printf("[SUMMARY space] ztbox find leak space: %llu KB(%u PAGEs). Parse file \"%s\" for details.\n",
        (uint64)(leak_spc_pages) * src_info.page_size / SIZE_K(1), leak_spc_pages, src_info.output_file.file_path);
    // repair map pages of bitmap file, will reopen data_file
    if (status == GS_SUCCESS && src_info.repair) {
        status = repair_map_pages(&src_info, page_count);
    }

    repair_release_resource(&src_info);
    return status;
}

static status_t func_repair_space(int argc, char *argv[])
{
    date_t c_start = cm_now();
    if (func_repair_execute(argc, argv) != GS_SUCCESS) {
        printf("Ztbox zfunc repair_space_loss Error.\n");
        return GS_ERROR;
    }
    date_t c_end = cm_now();
    printf("Ztbox zfunc repair_space_loss use time %f s\n", (double)(c_end - c_start) / MS_PER_SEC);
    return GS_SUCCESS;
}

static status_t func_execute_usage(int argc, char *argv[])
{
    if (argc > g_gm_optind) {
        if (strcmp(argv[g_gm_optind], "--help") == 0 || strcmp(argv[g_gm_optind], "-?") == 0 ||
            strcmp(argv[g_gm_optind], "-h") == 0) {
            usage();
            return GS_SUCCESS;
        }

        if (strcmp(argv[g_gm_optind], "--version") == 0 || strcmp(argv[g_gm_optind], "-V") == 0) {
            tbox_print_version();
            return GS_SUCCESS;
        }
    }
    return GS_ERROR;
}

status_t func_execute(int argc, char *argv[])
{
    char *fname = NULL;
    int32 c;
    uint32 i;

    if (func_execute_usage(argc, argv) == GS_SUCCESS) {
        return GS_SUCCESS;
    }

    c = miner_getopt(argc, argv, "f:");
    while (c != -1) {
        if (c == 'f') {
            if (fname != NULL) {
                printf("must secify one function to use\n");
                GS_THROW_ERROR(ERR_INVALID_PARAMETER, "zfunc input parameter");
                CM_FREE_PTR(fname);
                return GS_ERROR;
            }
            fname = (char *)cm_strdup(g_gm_optarg);
            break;
        } else {
            printf("try use \"--help\" for more information.\n");
            GS_THROW_ERROR(ERR_INVALID_PARAMETER, "zfunc input parameter");
            return GS_ERROR;
        }
    }

    if (fname == NULL) {
        printf("must have -f option.try use \"--help\" for more information.\n");
        GS_THROW_ERROR(ERR_INVALID_PARAMETER, "zfunc input parameter");
        return GS_ERROR;
    }

    cm_str_lower(fname);
    for (i = 0; i < NUM_FUNC_TYPE; i++) {
        if (strcmp(g_func_proc[i].func_name, fname) == 0) {
            CM_FREE_PTR(fname);
            return g_func_proc[i].func_parse_proc(argc, argv);
        }
    }

    printf("try use \"--help\" for more information.\n");
    GS_THROW_ERROR(ERR_INVALID_PARAMETER, fname);
    CM_FREE_PTR(fname);
    return GS_ERROR;
}
