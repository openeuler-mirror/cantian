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
 * dsw_shm_ctrl.c
 *
 *
 * IDENTIFICATION
 * src/tse/message_queue/dsw_shm_ctrl.c
 *
 * -------------------------------------------------------------------------
 */

#include <unistd.h>
#include <stdio.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/types.h>
#include <sys/stat.h> /* For mode constants */
#include <sys/file.h> /* for flock */
#include <fcntl.h>    /* For O_* constants */
#include <semaphore.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <sys/mman.h>
#include "dsw_shm_pri.h"
#include "dsw_typedef.h"

#define SHM_COMM_CONFIG "/dev/shm/cantian_shm_config_%d.txt"
#define SHM_KEY_COUNT_LINE_MAX (30)
#define SHM_MAX_TOKEN_NUM (16)
#define SHM_MAX_LINE_SIZE (256 + 32)

struct key_map_s {
    shm_key_t key;
    unsigned long addr;
};

static struct key_map_s *g_key_map = NULL;
static int g_key_map_nr = 0;
static pthread_mutex_t g_ctrl_lock = PTHREAD_MUTEX_INITIALIZER;


static int shm_load_config(int fd);
static int shm_get_config_file(int *ret_fd, int i);
static int shm_put_config_file(int fd);

/* There are more details in dsw_shm.h */
int shm_get_all_keys(int *pos, struct shm_key_s key_list[], int nr_key_list)
{
    int i, n, index = -1;

    if (*pos < 0) {
        LOG_SHM_ERROR("*pos = %d is error", *pos);
        return -1;
    }

    pthread_mutex_lock(&g_ctrl_lock);
    if (g_key_map == NULL) {
        int fd, ret;
        for (index = 0; index < 2; index++) {
            ret = shm_get_config_file(&fd, index);
            if (ret < 0) {
                LOG_SHM_ERROR("shm_get_config_file, errno = %d", errno);
                continue;
            }
            if (shm_load_config(fd) < 0) {
                (void)shm_put_config_file(fd);
                continue;
            }
            (void)shm_put_config_file(fd);
            break;
        }

        if (index == 2) {
            LOG_SHM_ERROR("the shm config file not exist or destoryed!");
            pthread_mutex_unlock(&g_ctrl_lock);
            return -1;
        }
    }

    if (*pos >= g_key_map_nr) {
        pthread_mutex_unlock(&g_ctrl_lock);
        return 0;
    }
    n = *pos + nr_key_list;
    n = n < g_key_map_nr ? n : g_key_map_nr;
    for (i = *pos; i < n; i++) {
        key_list[i] = g_key_map[i].key;
    }
    pthread_mutex_unlock(&g_ctrl_lock);

    i = n - *pos;
    *pos = n;
    return i;
}


static bool file_exist(char *name, size_t nameLen)
{
    DSW_ASSERT(name != NULL);
    DSW_ASSERT(nameLen != 0);
    return access(name, F_OK) == 0;
}


static void *shm_mmap_attach(shm_key_t *key)
{
    int fd;
    void *addr;

    // mode 0777
    fd = shm_open(key->mmap_name, O_RDWR, 0777);
    if (fd == -1) {
        LOG_SHM_ERROR("shm_mmap_attach open mmap file failed! file=%s, errno = %d", key->mmap_name, errno);
        return NULL;
    }

    addr = mmap(NULL, sizeof(shm_area_t), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (MAP_FAILED == addr) {
        close(fd);
        LOG_SHM_ERROR("shm_mmap_attach mmap return error, errno = %d", errno);
        return NULL;
    }

    close(fd);
    return addr;
}

static void *shm_sysv_attach(shm_key_t *key)
{
    int id;
    void *addr;

    if (key->sysv_key == (key_t)0) {
        LOG_SHM_ERROR("the shm_sysv_key ==  0, error!");
        return NULL;
    }

    id = shmget(key->sysv_key, 0, 0);
    if (id < 0) {
        LOG_SHM_ERROR("shmget return error, errno = %d", errno);
        return NULL;
    }

    addr = shmat(id, NULL, 0);
    if (addr == (void *)-1) {
        LOG_SHM_ERROR("shmat return error, errno = %d", errno);
        return NULL;
    }

    return addr;
}

static void *shm_iv_attach(shm_key_t *key, int is_server)
{
    int fd;
    void *addr;

    LOG_SHM_INFO("shm_iv_attach start, devname=%s is_server=%d.", key->dev_name, is_server);

    if (is_server) {
        fd = shm_open(key->dev_name, O_RDWR, S_IRWXU);
    } else {
        char *realPathRes = NULL;
        realPathRes = realpath(key->dev_name, NULL);
        if (realPathRes == NULL) {
            LOG_SHM_ERROR("shm_iv_attach input devfilename is abnormal!");
            return NULL;
        } else {
            fd = open(realPathRes, O_RDWR);
            free(realPathRes);
        }
    }

    if (fd == -1) {
        LOG_SHM_ERROR("shm_iv_attach open failed, devname=%s is_server=%d err=%d:%s.", key->dev_name, is_server, errno,
            strerror(errno));

        return NULL;
    }

    if (is_server) {
        addr = mmap(NULL, sizeof(shm_area_t), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    } else {
        addr = mmap(NULL, sizeof(shm_area_t), PROT_READ | PROT_WRITE, MAP_SHARED, fd, getpagesize());
    }

    close(fd);
    if (MAP_FAILED == addr) {
        LOG_SHM_ERROR("shm_mmap_attach mmap failed, devname=%s is_server=%d err=%d:%s.", key->dev_name, is_server,
            errno, strerror(errno));
        return NULL;
    }

    return addr;
}

static void shm_mmap_detach(void *addr)
{
    int ret;

    ret = munmap(addr, sizeof(shm_area_t));
    if (ret < 0) {
        LOG_SHM_ERROR("shm_mmap_detach  munmap return error, errno = %d", errno);
    }
}

static void shm_sysv_detach(void *addr)
{
    int ret;

    ret = shmdt(addr);
    if (ret < 0) {
        LOG_SHM_ERROR("shmdt return error, errno = %d", errno);
    }
}

static void shm_iv_detach(void *addr)
{
    int ret;

    ret = munmap(addr, sizeof(shm_area_t));
    if (ret < 0) {
        LOG_SHM_ERROR("shm_mmap_detach  munmap return error, errno = %d", errno);
    }
}

static int shm_get_seg_config_slave(shm_key_t *key, int is_server, void **addr, unsigned long *total_size)
{
    shm_area_t *area;

    if (key->type == SHM_KEY_SYSV) {
        area = (shm_area_t *)shm_sysv_attach(key);
    } else if (key->type == SHM_KEY_MMAP) {
        area = (shm_area_t *)shm_mmap_attach(key);
    } else if (key->type == SHM_KEY_IV) {
        area = (shm_area_t *)shm_iv_attach(key, is_server);
    } else {
        LOG_SHM_ERROR("type=%d invalid.", key->type);
        return -1;
    }

    if (area == NULL) {
        LOG_SHM_ERROR("shm attach failed, type=%d is_server=%d.", key->type, is_server);
        return -1;
    }

    *addr = (void *)area->head.addr;
    *total_size = area->head.total_size;

    if (key->type == SHM_KEY_SYSV) {
        shm_sysv_detach(area);
    } else if (key->type == SHM_KEY_MMAP) {
        shm_mmap_detach(area);
    } else if (key->type == SHM_KEY_IV) {
        shm_iv_detach(area);
    } else {
        LOG_SHM_ERROR("type=%d invalid.", key->type);
        return -1;
    }
    return 0;
}

/* split the whole line buffer to a few tokens, and then return the number
   of tokens ware taken
 */
static int get_tokens(char *line, char *tokens[], size_t lineLen)
{
    DSW_ASSERT(lineLen != 0);
    int n = 0, space = 1;
    char *p;

    for (p = line; *p; p++) {
        if (space) {
            if (!isspace(*p)) {
                tokens[n] = p;
                n++;
                if (n >= SHM_MAX_KEY_NUM) {
                    break;
                }
                space = 0;
            } else {
                *p = '\0';
            }
        } else {
            if (isspace(*p)) {
                space = 1;
                *p = '\0';
            }
        }
    }

    return n;
}

/* translate the string into integer */
static int hex2n(char *s, unsigned long *n)
{
    char *p;
    unsigned long r = 0;

    if (strlen(s) <= 3 || s[0] != '0' || (s[1] != 'x' && s[1] != 'X')) {
        return -1;
    }

    for (p = s + 2; *p; p++) {
        r <<= 4;
        if (*p >= '0' && *p <= '9') {
            r += (unsigned long)(*p - '0');
        } else if (*p >= 'a' && *p <= 'f') {
            r += (unsigned long)(*p - 'a' + 10);
        } else if (*p >= 'A' && *p <= 'F') {
            r += (unsigned long)(*p - 'A' + 10);
        } else {
            return -1;
        }
    }
    *n = r;
    return 0;
}


static int cmp_key(shm_key_t *k1, shm_key_t *k2)
{
    if (k1->type != k2->type) {
        return -1;
    }
    if (k1->type == SHM_KEY_SYSV) {
        return k1->sysv_key == k2->sysv_key ? 0 : -1;
    } else if (k1->type == SHM_KEY_MMAP) {
        return strcmp(k1->mmap_name, k2->mmap_name);
    } else {
        LOG_SHM_ERROR("unknow type");
    }

    return -1;
}

bool shm_obj_exist(shm_key_t *key)
{
    if (key->type == SHM_KEY_SYSV) {
        return shmget(key->sysv_key, 0, 0) != -1;
    } else if (key->type == SHM_KEY_MMAP) {
        return file_exist(key->mmap_name, sizeof(key->mmap_name));
    } else {
        LOG_SHM_ERROR("unknow type");
    }

    return false;
}


static int shm_get_addr(struct key_map_s *key_map, int *n, shm_key_t *key, void **p_addr)
{
    char slot_used[SHM_MAX_KEY_NUM];
    int i, slot;

    if (key->type == SHM_KEY_SYSV && key->sysv_key == (key_t)0) {
        LOG_SHM_ERROR("the shm_key == 0, error!");
        return -1;
    }

    memset_s(slot_used, sizeof(slot_used), 0, sizeof(slot_used));
    for (i = 0; i < *n; i++) {
        /* got it */
        if (cmp_key(&key_map[i].key, key) == 0) {
            *p_addr = (void *)key_map[i].addr;
            return 0;
        }

        slot = shm_addr2slot(key_map[i].addr);
        if (slot < 0 || slot >= SHM_MAX_KEY_NUM) {
            LOG_SHM_ERROR("shm_get_addr, slot error, shm_type=%d, addr=%lx, slot=%d", key_map[i].key.type,
                key_map[i].addr, slot);
            return -1;
        }
        slot_used[slot] = 1;
    }

    if (*n >= SHM_MAX_KEY_NUM) {
        LOG_SHM_ERROR("shm_get_addr, address is too many");
        return -1;
    }

    /* find an unused address slot */
    for (i = 0; i < SHM_MAX_KEY_NUM; i++) {
        if (slot_used[i]) {
            continue;
        }
        memcpy_s(&key_map[*n].key, sizeof(*key), key, sizeof(*key));
        key_map[*n].addr = shm_slot2addr(i);
        *p_addr = (void *)key_map[*n].addr;
        (*n)++;
        return 0;
    }

    LOG_SHM_ERROR("shm_get_addr, all of slots are used");
    return -1;
}

int shm_get_shm_type_and_addr(char *tokens[], struct key_map_s *key_map, int n, int lineno, int *count,
    int *is_count)
{
    int r;

    if (!strcmp(tokens[0], "key")) {
        *count = atoi(tokens[2]);
        *is_count = 1;
        return 0;
    }

    if (!strcmp(tokens[0], "sysv")) {
        unsigned long sysv_key = 0;
        key_map[n].key.type = SHM_KEY_SYSV;
        r = hex2n(tokens[1], &sysv_key);
        key_map[n].key.sysv_key = (key_t)sysv_key;
        if (r < 0) {
            LOG_SHM_ERROR("shm_parse_and_update_config, first parameter error at line %d", lineno);
            return -1;
        }
    } else if (!strcmp(tokens[0], "mmap")) {
        key_map[n].key.type = SHM_KEY_MMAP;
        r = strcpy_s(key_map[n].key.mmap_name, NAME_MAX, tokens[1]);
        if (r != 0) {
            LOG_SHM_ERROR("strcpy_s failed. %d", r);
            return -1;
        }
    } else {
        LOG_SHM_ERROR("unknow type '%s'\n at line %d", tokens[0], lineno);
        return -1;
    }

    r = hex2n(tokens[2], &key_map[n].addr);
    if (r < 0) {
        LOG_SHM_ERROR("shm_parse_and_update_config, second parameter error at line %d", lineno);
        return -1;
    }

    if ((key_map[n].addr & (SHM_MAX_SIZE - 1)) != 0) {
        LOG_SHM_ERROR("shm_parse_and_update_config, address is not aligned to 4GB boundary at line %d, addr=%lx",
            lineno, key_map[n].addr);
        return -1;
    }

    return 0;
}

static int shm_get_file_line(int fd, char line[])
{
    int rb = 0; // read byte num
    ssize_t ret;

    while (1) {
        ret = read(fd, &line[rb], 1);
        if (ret == 0) {
            LOG_SHM_INFO("read config file end.");
            break;
        }
        if (ret < 0) {
            LOG_SHM_ERROR("read config file error, errno = %d", errno);
            break;
        }
        if (line[rb] == '\n') {
            break;
        }

        if (rb >= SHM_MAX_LINE_SIZE - 2) { // leave a byte to store '\0'
            LOG_SHM_ERROR("config file line size greater than %d", SHM_MAX_LINE_SIZE);
            break;
        }

        rb++;
    }

    if (rb > 0) {
        rb++;
        line[rb] = '\0';
    }

    return rb;
}

static int shm_parse_config(int fd, struct key_map_s *key_map)
{
    char *tokens[SHM_MAX_TOKEN_NUM], line[SHM_MAX_LINE_SIZE];
    int r, n = 0, lineno = 0, ret, pre_count = 0, is_conut = 0, file_count = 0;

    while (shm_get_file_line(fd, line) > 0) {
        line[sizeof(line) - 1] = '\0';
        lineno++;
        r = get_tokens(line, tokens, sizeof(line));
        if (r == 0 || *tokens[0] == '#') { // it is a blank line or a comments line
            continue;
        }
        if (r < 3) {
            free(key_map);
            LOG_SHM_ERROR("shm_parse_and_update_config, parameter too few at line %d, r = %d", lineno, r);
            return -1;
        }

        ret = shm_get_shm_type_and_addr(tokens, key_map, n, lineno, &pre_count, &is_conut);
        if (ret < 0) {
            free(key_map);
            LOG_SHM_ERROR("shm_parse_and_update_config: shm_get_shm_type_and_addr error.");
            return -1;
        }

        if (is_conut == 1) {
            is_conut = 0;
            continue;
        }

        file_count++; /* count the true config num */

        if (!shm_obj_exist(&key_map[n].key)) {
            continue;
        }

        n++;
    }

    if (file_count != pre_count) {
        free(key_map);
        LOG_SHM_ERROR("pre_count = %d, n = %d the count is not equal.", pre_count, n);
        return -1;
    }

    LOG_SHM_INFO("pre_count = %d, n = %d", pre_count, n);

    return n;
}

void shm_update_config(int fd, struct key_map_s *key_map, int n1)
{
    int i;
    ssize_t ret;
    char info[] = "# this file is generated by program automatically, don't modify it.\n# format is: type key addr.\n";
    char line[SHM_KEY_COUNT_LINE_MAX] = {'\0'};
    char keyinfo[SHM_MAX_LINE_SIZE] = {0};

    ret = ftruncate(fd, 0);
    if (ret < 0) {
        LOG_SHM_ERROR("truncate file size to zero error, errno = %d", errno);
        return;
    }

    lseek(fd, 0, SEEK_SET);

    ret = write(fd, info, strlen(info));
    if (ret < 0) {
        LOG_SHM_ERROR("write info to file error, errno = %d", errno);
        return;
    }

    snprintf_s(line, SHM_KEY_COUNT_LINE_MAX, SHM_KEY_COUNT_LINE_MAX - 1, "key count %d\n", g_key_map_nr);

    ret = write(fd, line, strlen(line));
    if (ret < 0) {
        LOG_SHM_ERROR("write info to file error, errno = %d", errno);
        return;
    }

    for (i = 0; i < n1; i++) {
        if (key_map[i].key.type == SHM_KEY_SYSV) {
            ret = snprintf_s(keyinfo, SHM_MAX_LINE_SIZE, SHM_MAX_LINE_SIZE - 1,
                "sysv 0x%x 0x%lx\n", key_map[i].key.sysv_key, key_map[i].addr);
        } else if (key_map[i].key.type == SHM_KEY_MMAP) {
            ret = snprintf_s(keyinfo, SHM_MAX_LINE_SIZE, SHM_MAX_LINE_SIZE - 1,
                "mmap %s 0x%lx\n", key_map[i].key.mmap_name, key_map[i].addr);
        } else {
            ret = snprintf_s(keyinfo, SHM_MAX_LINE_SIZE, SHM_MAX_LINE_SIZE - 1,
                "#error, unknow type %d\n", key_map[i].key.type);
        }
        if (ret < 0) {
            LOG_SHM_ERROR("copy key info to buffer error, errno = %d", ret)
            return;
        }
        ret = write(fd, keyinfo, strlen(keyinfo));
        if (ret < 0) {
            LOG_SHM_ERROR("write key info to file error, errno = %d", errno);
            return;
        }
    }

    fsync(fd);
}

static int shm_load_config(int fd)
{
    if (g_key_map != NULL) { /* It has already been loaded */
        return 0;
    }

    g_key_map = (struct key_map_s *)malloc(sizeof(struct key_map_s) * SHM_MAX_KEY_NUM);
    if (g_key_map == NULL) {
        LOG_SHM_ERROR("shm_parse_and_update_config:malloc key_map_s error. errno = %d", errno);
        return -1;
    }

    memset_s(g_key_map, sizeof(struct key_map_s) * SHM_MAX_KEY_NUM, 0, sizeof(struct key_map_s) * SHM_MAX_KEY_NUM);

    g_key_map_nr = shm_parse_config(fd, g_key_map);
    if (g_key_map_nr < 0) {
        LOG_SHM_ERROR("shm_parse_config failed");
        g_key_map = NULL;
        return -1;
    }
    return 0;
}

static int shm_parse_and_update_config(int fd, shm_key_t *key, void **addr)
{
    int n1, r;

    if (shm_load_config(fd) < 0) {
        LOG_SHM_ERROR("shm_load_config return error");
        return -1;
    }

    n1 = g_key_map_nr;
    r = shm_get_addr(g_key_map, &n1, key, addr);
    if (r < 0) {
        LOG_SHM_ERROR("shm_parse_and_update_config, shm_get_addr return error");
        return -1;
    }

    /* write back to config file */
    if (n1 != g_key_map_nr) {
        shm_update_config(fd, g_key_map, n1);
        g_key_map_nr = n1;
    }

    return 0;
}

static int shm_get_config_file(int *ret_fd, int i)
{
    int fd;
    int ret;
    int flags;
    char file_name[SHM_PATH_MAX] = {0};

    snprintf_s(file_name, SHM_PATH_MAX, SHM_PATH_MAX - 1, SHM_COMM_CONFIG, i);

    if (!file_exist(file_name, sizeof(file_name))) {
        flags = O_RDWR | O_CREAT;
    } else {
        flags = O_RDWR;
    }

    fd = open(file_name, flags, 0660);
    if (fd < 0) {
        LOG_SHM_ERROR("open, errno = %d", errno);
        return -1;
    }

    ret = flock(fd, LOCK_EX);
    if (ret == -1) {
        LOG_SHM_ERROR("flock, errno = %d", errno);
        close(fd);
        return -1;
    }
    *ret_fd = fd;

    return 0;
}

static int shm_put_config_file(int fd)
{
    int ret;

    ret = flock(fd, LOCK_UN);
    if (ret == -1) {
        LOG_SHM_ERROR("flock, errno = %d, fd = %d", errno, fd);
        return -1;
    }

    close(fd);

    return 0;
}

static int shm_get_seg_config_master(shm_key_t *key, void **addr)
{
    int fd[2], ret, i, usefull_index = -1;

    for (i = 0; i < 2; i++) {
        ret = shm_get_config_file(&fd[i], i);
        if (ret < 0) {
            LOG_SHM_ERROR("shm_get_config_file, errno = %d", errno);
            continue;
        }

        ret = shm_parse_and_update_config(fd[i], key, addr);
        if (ret < 0) {
            LOG_SHM_ERROR("shm_parse_and_update_config, errno = %d", errno);
            continue;
        }

        usefull_index = i;
    }

    if (usefull_index == -1) {
        LOG_SHM_ERROR("shm_parse_and_update_config,have no config can use!", errno);
        (void)shm_put_config_file(fd[0]);
        (void)shm_put_config_file(fd[1]);
        return -1;
    }

    // LOG_SHM_INFO("g_key_map_nr = %d", g_key_map_nr);
    for (i = 0; i < 2; i++) {
        shm_update_config(fd[i], g_key_map, g_key_map_nr);
        (void)shm_put_config_file(fd[i]);
    }

    return 0;
}

int shm_get_seg_config(shm_key_t *key, int is_master, int is_server, void **addr, unsigned long *total_size)
{
    int ret;

    pthread_mutex_lock(&g_ctrl_lock);
    if (is_master) {
        ret = shm_get_seg_config_master(key, addr);
    } else {
        ret = shm_get_seg_config_slave(key, is_server, addr, total_size);
    }
    pthread_mutex_unlock(&g_ctrl_lock);
    return ret;
}

void shm_delete_one_key_in_list(int index)
{
    if (index < 0 || index >= MAX_SHM_SEG_NUM) {
        LOG_SHM_ERROR("seg index is error, seg index = %d", index);
        return;
    }

    g_key_map_nr--;
    if (index != g_key_map_nr) {
        memcpy_s(&g_key_map[index], sizeof(struct key_map_s), &g_key_map[g_key_map_nr], sizeof(struct key_map_s));
    }
}

int shm_delete_seg_key_item(shm_key_t key)
{
    int i, dest_index = -1, is_found = 0, index;
    int fd, ret;

    for (i = 0; i < g_key_map_nr; ++i) {
        if (cmp_key(&g_key_map[i].key, &key) == 0) {
            dest_index = i;
            is_found = 1;
            break;
        }
    }

    if (is_found == 0) {
        return -1;
    }

    shm_delete_one_key_in_list(dest_index);

    for (index = 0; index < 2; index++) {
        ret = shm_get_config_file(&fd, index);
        if (ret < 0) {
            LOG_SHM_ERROR("shm_get_config_file, errno = %d", errno);
            return -1;
        }

        shm_update_config(fd, g_key_map, g_key_map_nr);

        (void)shm_put_config_file(fd);
    }

    return 0;
}