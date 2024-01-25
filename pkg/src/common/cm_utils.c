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
 * cm_utils.c
 *
 *
 * IDENTIFICATION
 * src/common/cm_utils.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_common_module.h"
#include "cm_utils.h"
#include "cm_text.h"
#include "cm_timer.h"
#include "cm_encrypt.h"
#include "evp.h"
#include "cm_epoll.h"
#ifndef WIN32
#include <sys/inotify.h>
#endif

uint8 g_nonnaming_chars[256] = {
    [';'] = 1,
    ['|'] = 1,
    ['`'] = 1,
    ['$'] = 1,
    ['&'] = 1,
    ['>'] = 1,
    ['<'] = 1,
    ['\"'] = 1,
    ['\''] = 1,
    ['!'] = 1,
    [' '] = 1,
    [169] = 1,
};

// compare with the above, add characters that affect connection string analysis
uint8 g_nonnaming_chars_ex[256] = {
    [';'] = 1,
    ['|'] = 1,
    ['`'] = 1,
    ['$'] = 1,
    ['&'] = 1,
    ['>'] = 1,
    ['<'] = 1,
    ['\"'] = 1,
    ['\''] = 1,
    ['!'] = 1,
    [' '] = 1,
    [169] = 1,
    ['@'] = 1,
    ['/'] = 1,
    [':'] = 1,
    [','] = 1,
};

#define IS_SPECIAL_CHAR(c) ((' ' <= (c) && (c) <= '/') || (':' <= (c) && (c) <= '@') ||  \
        ('[' <= (c) && (c) <= '`') || ('{' <= (c) && (c) <= '~'))
#define IS_NUM_CHAR(c)     ((c) >= '0' && (c) <= '9')
#define IS_UPPER_LETTER(c) ((c) >= 'A' && (c) <= 'Z')
#define IS_LOWER_LETTER(c) ((c) >= 'a' && (c) <= 'z')
#define IS_LETTER(c)       (IS_UPPER_LETTER(c) || IS_LOWER_LETTER(c))

status_t cm_verify_password_check(const char *pText, uint32 i, uint32 *type_count, bool32 *num_flag,
                                  bool32 *upper_flag, bool32 *lower_flag, bool32 *special_flag)
{
    // pwd can not include ';'
    if (pText[i] == ';') {
        CT_THROW_ERROR(ERR_PASSWORD_FORMAT_ERROR, "Password contains unexpected character.\n");
        return CT_ERROR;
    }
    if (IS_NUM_CHAR(pText[i])) {
        if (!(*num_flag)) {
            *num_flag = CT_TRUE;
            (*type_count)++;
        }
    } else if (IS_UPPER_LETTER(pText[i])) {
        if (!(*upper_flag)) {
            *upper_flag = CT_TRUE;
            (*type_count)++;
        }
    } else if (IS_LOWER_LETTER(pText[i])) {
        if (!(*lower_flag)) {
            *lower_flag = CT_TRUE;
            (*type_count)++;
        }
    } else if (IS_SPECIAL_CHAR(pText[i])) {
        if (!(*special_flag)) {
            *special_flag = CT_TRUE;
            (*type_count)++;
        }
    } else {
        CT_THROW_ERROR(ERR_PASSWORD_FORMAT_ERROR, "Password contains unexpected character.\n");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t cm_verify_password_str(const char *name, const char *passwd, uint32 pwd_min_len)
{
    const char *pText = passwd;
    size_t len = strlen(pText);
    uint32 type_count = 0;
    bool32 num_flag = CT_FALSE;
    bool32 upper_flag = CT_FALSE;
    bool32 lower_flag = CT_FALSE;
    bool32 special_flag = CT_FALSE;
    char name_reverse[CT_NAME_BUFFER_SIZE] = {0};

    /* enforce minimum length */
    if ((uint32)len < pwd_min_len) {
        CT_THROW_ERROR(ERR_PASSWORD_FORMAT_ERROR, "password can't be less than min length characters");
        return CT_ERROR;
    }

    /* check maximum length */
    if (len > CT_PASSWD_MAX_LEN) {
        CT_THROW_ERROR(ERR_PASSWORD_FORMAT_ERROR, "password can't be greater than max length characters");
        return CT_ERROR;
    }

    if (name != NULL) {
        /* check if the pwd is the username or the reverse of the username */
        if (strlen(pText) == strlen(name) && cm_strcmpni(pText, name, strlen(name)) == 0) {
            CT_THROW_ERROR(ERR_PASSWORD_FORMAT_ERROR, "password can not been same with user name");
            return CT_ERROR;
        }

        cm_str_reverse(name_reverse, name, CT_NAME_BUFFER_SIZE);
        if (strlen(pText) == strlen(name_reverse) && cm_strcmpni(pText, name_reverse, strlen(name_reverse)) == 0) {
            CT_THROW_ERROR(ERR_PASSWORD_FORMAT_ERROR, "password cannot be the same as the reverse of the name");
            return CT_ERROR;
        }
    }
    
    /* The pwd should contain at least two type the following characters:
    A. at least one lowercase letter
    B. at least one uppercase letter
    C. at least one digit
    D. at least one special character: `~!@#$%^&*()-_=+\|[{}];:'",<.>/? and space
    If pwd contains the other character ,will return error. */
    for (uint32 i = 0; i < len; i++) {
        if (cm_verify_password_check(pText, i, &type_count, &num_flag, &upper_flag, &lower_flag,
                                     &special_flag) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (type_count < CM_PASSWD_MIN_TYPE) {
        CT_THROW_ERROR(ERR_PASSWORD_IS_TOO_SIMPLE);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

const static uint64 RAND_P1 = 0x5DEECE66DL;
const static uint64 RAND_P2 = 0xBL;
const static uint64 RAND_P3 = 0XFFFFFFFFFFFFL;

static inline uint32 cm_rand_next(int64 *seed, uint32 bits)
{
    int64 old_seed, next_seed;
    atomic_t cur_seed = *seed;
    do {
        old_seed = cm_atomic_get(&cur_seed);
        next_seed = (int64)(((uint64)old_seed * RAND_P1 + RAND_P2) & RAND_P3);
    } while (!cm_atomic_cas(&cur_seed, old_seed, next_seed));
    *seed = cur_seed;
    return (uint32)((uint64)next_seed >> (48 - bits));
}

/* not for CSPRNG scenario */
uint32 cm_rand_int32(int64 *seed, uint32 range)
{
    uint32 r_next, r_mask, value;

    r_next = cm_rand_next(seed, 31);
    r_mask = range - 1;

    if ((range & r_mask) == 0) {
        r_next = (uint32)(((uint64)range * r_next) >> 31);
    } else {
        value = r_next;
        r_next = value % range;
        while (value + r_mask < r_next) {
            r_next = value % range;
            value = cm_rand_next(seed, 31);
        }
    }
    return r_next;
}

/* not for CSPRNG scenario */
uint32 cm_random(uint32 range)
{
    int64 seed;
    (void)cm_rand((uchar *)&seed, sizeof(int64));
    return cm_rand_int32(&seed, range);
}

#define CT_ASCII_ALPHA_COUNT 26
#define CT_ASCII_ALPHA_CHAR_COUNT 36
#define CT_ASCII_UPPER_CHAR_DELTA 65
#define CT_ASCII_LOWER_CHAR_DELTA 97
#define CT_ASCII_PRINTABLE_COUNT 96
#define CT_ASCII_PRINTABLE_BASE 31
#define CT_ASCII_NUMBER_DELTA 22

void cm_rand_string(uint32 length, char mode, char *buf)
{
    int64 randseed;
    uint32 randvalue;
    cm_rand((uchar *)&randseed, sizeof(int64));

    for (uint32 i = 0; i < length; i++) {
        switch (mode) {
            case 'l':
            case 'L':
                /* lowercase alpha characters */
                randvalue = cm_rand_int32(&randseed, CT_ASCII_ALPHA_COUNT);
                buf[i] = randvalue + CT_ASCII_LOWER_CHAR_DELTA;
                break;
            case 'a':
            case 'A':
                /* mixed case alpha characters */
                randvalue = cm_rand_int32(&randseed, CT_ASCII_ALPHA_COUNT * 2);
                if (randvalue < CT_ASCII_ALPHA_COUNT) {
                    buf[i] = randvalue + CT_ASCII_UPPER_CHAR_DELTA;
                } else {
                    buf[i] = randvalue + CT_ASCII_LOWER_CHAR_DELTA - CT_ASCII_ALPHA_COUNT;
                }
                break;
            case 'x':
            case 'X':
                /* uppercase alpha-numeric characters */
                randvalue = cm_rand_int32(&randseed, CT_ASCII_ALPHA_CHAR_COUNT);
                if (randvalue < CT_ASCII_ALPHA_COUNT) {
                    buf[i] = randvalue + CT_ASCII_UPPER_CHAR_DELTA;
                } else {
                    buf[i] = randvalue + CT_ASCII_NUMBER_DELTA;
                }
                break;
            case 'p':
            case 'P':
                /* any printable characters */
                randvalue = cm_rand_int32(&randseed, CT_ASCII_PRINTABLE_COUNT);
                buf[i] = randvalue + CT_ASCII_PRINTABLE_BASE;
                break;
            case 'u':
            case 'U':
            default:
                /* uppercase alpha characters */
                randvalue = cm_rand_int32(&randseed, CT_ASCII_ALPHA_COUNT);
                buf[i] = randvalue + CT_ASCII_UPPER_CHAR_DELTA;
                break;
        }
    }
    buf[length] = '\0';
}

status_t cm_aligned_malloc(int64 size, const char *name, aligned_buf_t *buf)
{
    buf->alloc_buf = (char *)malloc((size_t)(size + CT_MAX_ALIGN_SIZE_4K));
    if (buf->alloc_buf == NULL) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)size, name);
        return CT_ERROR;
    }

    buf->aligned_buf = (char *)cm_aligned_buf(buf->alloc_buf);
    buf->buf_size = size;
    return CT_SUCCESS;
}

status_t cm_aligned_realloc(int64 size, const char *name, aligned_buf_t *buf)
{
    cm_aligned_free(buf);
    return cm_aligned_malloc(size, name, buf);
}

void cm_calc_md5(const uchar *data, uint32 len, uchar *md, uint32 *size)
{
    const EVP_MD *type = EVP_get_digestbyname("md5");
    (void)EVP_Digest(data, len, md, size, type, NULL);
}

status_t cm_load_symbol(void *lib_handle, char *symbol, void **sym_lib_handle)
{
#ifndef WIN32
    const char *dlsym_err = NULL;

    *sym_lib_handle = dlsym(lib_handle, symbol);
    dlsym_err = dlerror();
    if (dlsym_err != NULL) {
        CT_THROW_ERROR(ERR_LOAD_SYMBOL, symbol, dlsym_err);
        return CT_ERROR;
    }
#endif // !WIN32
    return CT_SUCCESS;
}

status_t cm_open_dl(void **lib_handle, char *symbol)
{
#ifdef WIN32
    CT_THROW_ERROR(ERR_LOAD_LIBRARY, symbol, cm_get_os_error());
    return CT_ERROR;
#else
    *lib_handle = dlopen(symbol, RTLD_LAZY);
    if (*lib_handle == NULL) {
        CT_THROW_ERROR(ERR_LOAD_LIBRARY, symbol, cm_get_os_error());
        return CT_ERROR;
    }
    return CT_SUCCESS;
#endif
}

void cm_close_dl(void *lib_handle)
{
#ifndef WIN32
    (void)dlclose(lib_handle);
#endif
}

status_t cm_watch_file_init(int32 *watch_fd, int32 *epoll_fd)
{
#ifndef WIN32
    struct epoll_event ev;

    *epoll_fd = epoll_create1(0);
    if (*epoll_fd < 0) {
        return CT_ERROR;
    }

    *watch_fd = inotify_init();
    if (*watch_fd < 0) {
        return CT_ERROR;
    }

    ev.events = EPOLLIN;
    ev.data.fd = *watch_fd;

    if (epoll_ctl(*epoll_fd, EPOLL_CTL_ADD, *watch_fd, &ev) != 0) {
        return CT_ERROR;
    }
#else
    *watch_fd = CT_INVALID_ID32;
    *epoll_fd = CT_INVALID_ID32;
#endif
    return CT_SUCCESS;
}

status_t cm_add_device_watch(device_type_t type, int32 fd, const char *file_name, int32 *wd)
{
#ifndef WIN32
    if (type == DEV_TYPE_FILE) {
        *wd = inotify_add_watch(fd, file_name, IN_DELETE_SELF | IN_ATTRIB | IN_MOVE_SELF);
        if (*wd < 0) {
            return CT_ERROR;
        }
    } else {
        *wd = -1;
    }
#endif
    return CT_SUCCESS;
}

status_t cm_rm_device_watch(device_type_t type, int32 fd, int32 *wd)
{
#ifndef WIN32
    if (type == DEV_TYPE_FILE) {
        if (inotify_rm_watch(fd, *wd) < 0) {
            return CT_ERROR;
        }
    }
    *wd = -1;
#endif
    return CT_SUCCESS;
}

status_t cm_watch_file_event(int32 watch_fd, int32 epoll_fd, int32 *wd)
{
#ifndef WIN32
    int32 event_num, read_size;
    char buf[1024];
    struct epoll_event e_event;
    struct inotify_event *i_event = NULL;
    char *tmp = NULL;

    event_num = epoll_wait(epoll_fd, &e_event, 1, 200);
    if (event_num <= 0) {
        return CT_ERROR;
    }

    /* handle inotify event */
    if (e_event.data.fd == watch_fd) {
        read_size = read(watch_fd, buf, sizeof(buf));
        if (read_size <= 0) {
            return CT_ERROR;
        }

        for (tmp = buf; tmp < buf + read_size; tmp += sizeof(struct inotify_event) + i_event->len) {
            i_event = (struct inotify_event *)tmp;

            if (((i_event->mask & IN_ATTRIB) && !(i_event->mask & IN_DELETE_SELF)) || (i_event->mask & IN_MOVE_SELF)) {
                /* could not get name of  that has been removed/unlinked, so return wd */
                *wd = i_event->wd;
                return CT_SUCCESS;
            }
        }
    }
#endif
    return CT_ERROR;
}

#ifndef WIN32

/* used to save origin argc and argv in main execution */
#define cm_strdup strdup
extern char **environ;
static int g_ori_argc;
static char **g_ori_argv;

static char *g_proctitle_buf = NULL;  // point at argv[0]
static size_t g_proctitle_buf_size = 0;
static size_t g_curr_used_len = 0;

static void cm_free_secptr(uint16 idex, char **free_ptr)
{
    for (uint16 i = 0; i < idex; i++) {
        CM_FREE_PTR(free_ptr[i]);
    }
    CM_FREE_PTR(free_ptr);
}

/* move arg and environ to another available space.
 * 1.save origin argument value.
 * 2.move environment to new room.
 * 3.make a copy of argv.
 */
status_t save_origin_argument(int argc, char ***argv)
{
    g_ori_argc = argc;
    g_ori_argv = *argv;
    char *argv_end_pos = NULL;
    char **env_new = NULL;
    char **argv_new = NULL;
    char **env_ori = environ;

    int32 i;

    for (i = 0; i < argc; i++) {
        if (i == 0 || argv_end_pos + 1 == (*argv)[i]) {
            argv_end_pos = (*argv)[i] + strlen((*argv)[i]);
        }
    }

    for (i = 0; environ[i] != NULL; i++) {
        if (argv_end_pos + 1 == environ[i]) {
            argv_end_pos = environ[i] + strlen(environ[i]);
        }
    }
    g_proctitle_buf = (*argv)[0];
    g_proctitle_buf_size = argv_end_pos - (*argv)[0];

    env_new = (char **)malloc((i + 1) * sizeof(char *));
    if (env_new == NULL) {
        CT_LOG_RUN_ERR("failed to realloc memory for environment value");
        return CT_ERROR;
    }
    for (i = 0; environ[i] != NULL; i++) {
        env_new[i] = cm_strdup(environ[i]);
        if (env_new[i] == NULL) {
            CT_LOG_RUN_ERR("failed to realloc memory for environment value");
            cm_free_secptr(i, env_new);
            return CT_ERROR;
        }
    }
    env_new[i] = NULL;
    uint16 env_count = i;
    environ = env_new;

    argv_new = (char **)malloc((argc + 1) * sizeof(char *));
    if (argv_new == NULL) {
        CT_LOG_RUN_ERR("failed to realloc memory for argv value");
        environ = env_ori;
        cm_free_secptr(env_count, env_new);
        return CT_ERROR;
    }

    for (i = 0; i < argc; i++) {
        argv_new[i] = cm_strdup((*argv)[i]);
        if (argv_new[i] == NULL) {
            CT_LOG_RUN_ERR("failed to realloc memory for argv value");
            environ = env_ori;
            cm_free_secptr(i, argv_new);
            cm_free_secptr(env_count, env_new);
            return CT_ERROR;
        }
    }

    argv_new[i] = NULL;
    *argv = argv_new;

    return CT_SUCCESS;
}

status_t init_process_title(const char *title, uint32 len)
{
    if (g_ori_argv == NULL || g_proctitle_buf == NULL) {
        return CT_ERROR;
    }
    for (int i = 1; i < g_ori_argc; i++) {
        g_ori_argv[i] = g_proctitle_buf + g_proctitle_buf_size;
    }

    if (g_proctitle_buf_size - 1 < len) {
        return CT_ERROR;
    }
    PRTS_RETURN_IFERR(snprintf_s(g_proctitle_buf, g_proctitle_buf_size, g_proctitle_buf_size - 1, "%s", title));
    g_curr_used_len = strlen(g_proctitle_buf);
    if (g_curr_used_len < g_proctitle_buf_size) {
        size_t left_len = g_proctitle_buf_size - g_curr_used_len;
        MEMS_RETURN_IFERR(memset_s(g_proctitle_buf + g_curr_used_len, left_len, '\0', left_len));
    }
    return CT_SUCCESS;
}

void cm_usleep(uint32 us)
{
    int32 time = us;
    if (0 == time) {
        time = 1;
    }

#ifdef WIN32
    Sleep((time + 999) / 1000);
#else
    (void)usleep(time);
#endif
}

#endif