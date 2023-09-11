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
 * dsw_shm.h
 *
 *
 * IDENTIFICATION
 * src/tse/message_queue/dsw_shm.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef dsw_shm_pub_h__
#define dsw_shm_pub_h__

#include <sys/ipc.h>
#include <sys/shm.h>
#include <limits.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "dsw_message.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cpluscplus */

#define SHM_KEY_NULL 0
#define SHM_KEY_SYSV 1
#define SHM_KEY_MMAP 2
#define SHM_KEY_UNSOCK 3 /* unix socket */
#define SHM_KEY_VSOCK 4
#define SHM_KEY_IV 5
#define SHM_KEY_MAX 3

#define MQ_SHM_MMAP_NAME "cantian"
#define MQ_SHM_MMAP_DIR "/dev/shm"

typedef enum shm_message_priority_e {
    SHM_PRIORITY_NORMAL = 0,
    SHM_PRIORITY_HIGH
} shm_message_priority_t;

typedef enum shm_log_level_e {
    SHM_LOG_LEVEL_INFO,
    SHM_LOG_LEVEL_ERROR
} shm_log_level_t;

typedef struct shm_key_s {
    int type;
    union {
        struct {
            key_t sysv_key;
        };
        struct {
            char shm_name[NAME_MAX];
            char mmap_name[NAME_MAX];
            int seg_id;
        };
        struct {
            char unix_name[NAME_MAX];
        };
        struct {
            char vsock_port;
            char vsock_cid;
        };
        struct {
            char dev_name[NAME_MAX];
            char sock_path[NAME_MAX];
        };
    };
} shm_key_t;

#define MAX_SHM_PROC 20 /* The maximum number of business processes in an instance */
#define MIN_SHM_PROC 0
#define MYSQL_PROC_START 2
#define MAX_MEM_CLASS 32                    /* the capacity of mem_class [] */
#define SHM_MAX_LEN (4096L * 1024L * 1024L) /* The maximum size of a shared memory */
#define SHM_ADDR 0x300000000000UL           /* Shared memory area starting address */
#define MAX_SHM_SEG_NUM 128                 /* The number of instances of shared memory support */
#define SHM_MAX_LOG_LENTH 1024              /* The maximum length of the shared memory log string */


/* ****************************************************************************
 variable name           :  shm_mem_class.
 Functional description  :  The entry of memory object configration

 Precautions             �� The structure is only initialized in the master, and the
                          message size of all communication units must strictly
                          respect the format of the message structure.
**************************************************************************** */
typedef struct shm_mem_class {
    int size; /* The size of a message */
    int num;  /* The number of corresponding size data in the storage unit */
} shm_mem_class_t;


/* ****************************************************************************
 variable name            :  shm_seg_s
 Functional description   :  Shared memory instance tag, used to mark an instance
                             of multiple instances need to initialize the structure
                             of the variable
 Precautions              �� The structure variable can not access its members at
                             the use level and must be freed after its use.
**************************************************************************** */
struct shm_seg_s;

/* ****************************************************************************
 function name           :  shm_init
 Functional description  :  Initialize the shared memory area corresponding to
                            the instance and obtain the right to initialize the
                            memory segment
 Input paraments         :  shm_key_t shm_key: Shared memory application label (one
                                           segment corresponds to a label).
 Output paraments        :  Null
 Return value            :  struct shm_seg_s *seg : Shared memory segment label;
 Precautions             :  The initialization process must be executed after the
                            master initialization process, otherwise it fails.
**************************************************************************** */
struct shm_seg_s *shm_init(shm_key_t *shm_key, int is_server);


/* ****************************************************************************
 function name           :  shm_get_all_keys
 Functional description  :  get all segments
 Input paraments         :
                            pos -- the first key which return in the list, when
                            the returned the 'pos' will be updated to the new
                            next position

                            key_list -- an array use to contain the keys which
                            returned

                            nr_key_list -- number of rooms of the key_list

 Output paraments        :  the 'pos' will be updated to the new value

 Return value            :
                            >0 -- the number of valid keys that returned
                            ==0 -- there is not more keys can be returned from
                                   the position 'pos'
                            <0  -- there must be an error happend
**************************************************************************** */
int shm_get_all_keys(int *pos, struct shm_key_s key_list[], int nr_key_list);


/* ****************************************************************************
 function name           :  is_shm
 Functional description  :  To determine whether a piece of memory is shared memory area
 Input paraments         :  struct shm_seg_s *seg : Shared memory segment label;
                            void *addr : Shared memory measured address.
 Output paraments        :  Null
 Return value            :  int: Returns 1 in shared memory; otherwise returns 0.
*************************************************************************** */
int is_shm(struct shm_seg_s *seg, void *addr);


/* ****************************************************************************
 function name           :  shm_alloc
 Functional description  :  Apply for a piece of memory in the shared memory area
 Input paraments         :  struct shm_seg_s *seg : Shared memory segment label;
                            size_t size : The requested memory block size.
 Return value            :  void *: Return the pointer of the requested memory block.

**************************************************************************** */
void *shm_alloc(struct shm_seg_s *seg, size_t size);

/* ****************************************************************************
function name           :  shm_free
Functional description  :  Release shared memory
Input paraments         :  struct shm_seg_s *seg : Shared memory segment label;
                           void *ptr : Release shared memory
Return value            :  Null
Precautions             :  If the specified shared memory reference count is greater
                           than 1, using this function will only subtract 1 from the
                           reference count of that memory block, and will not actually
                           free this memory.
**************************************************************************** */
void shm_free(struct shm_seg_s *seg, void *ptr);

/* ****************************************************************************
 function name           :  shm_proc_start
 Functional description  :  Initialize and start listening thread (start listening)
 Input paraments         :  struct shm_seg_s *seg : Shared memory segment label;
                            int proc_id : Business module process id.
                            int thread_num : Receive queue thread number.
                            int (*recv_msg)(struct shm_seg_s *, dsw_message_block_t *) : Receive callback function.
 Output paraments        :  Null
 Return value            :  int : Return 0 success; otherwise fail.
**************************************************************************** */
int shm_proc_start(struct shm_seg_s *seg, int proc_id, int thread_num, cpu_set_t *mask, int is_dynamic,
    int (*recv_msg)(struct shm_seg_s *, dsw_message_block_t *));

/* ****************************************************************************
 function name           :  shm_proc_alive
 Functional description  :  Check the corresponding proc_id process is still working.
 Input paraments         :  struct shm_seg_s *seg : Shared memory segment label;
                            int proc_id : Business module process id.
 Return value            :  Null
**************************************************************************** */
int shm_proc_alive(struct shm_seg_s *seg, int proc_id);


/* ****************************************************************************
 function name           :  shm_send_msg
 Functional description  :  send massages
 Input paraments         :  struct shm_seg_s *seg : Shared memory segment label;
                            int proc_id :Business module process id.
                            dsw_message_block_t *msg : Message structure compatible
                            with the dsware framework.
 Return value            :  int : Return 0 success; otherwise fail.
**************************************************************************** */
int shm_send_msg(struct shm_seg_s *seg, int proc_id, dsw_message_block_t *msg);

/* ****************************************************************************
function name           :  shm_seg_exit
Functional description  :  Structure memory to release segment tags.
Input paraments         :  struct shm_seg_s *seg : Shared memory segment label;
Return value            :  Null
**************************************************************************** */
void shm_seg_exit(struct shm_seg_s *seg);

/* ****************************************************************************
 function name           :  shm_master_init
 Functional description  :  Initialize the master process.
 Input paraments         :  shm_key_t shm_key: Shared memory application label
                                          (one instance corresponds to a label).
                            shm_mem_class_t mem_class[]: Memory application form.
                            int nr_mem_class: Memory application form size.
 Return value            :  struct shm_seg_s *seg : Shared memory segment label;
 Precautions             :  The process of initialization must define the message
                            format of shared memory, and run in the context or process
                            of non-IO process.
**************************************************************************** */
struct shm_seg_s *shm_master_init(shm_key_t *shm_key, shm_mem_class_t mem_class[], int nr_mem_class);


/* ****************************************************************************
 function name           :  shm_master_exit
 Functional description  :  remove a segment from master
 Input paraments         :  seg -- pointer of the segment
 Return value            :  0 -- success, -1 -- failed
 Precautions             :  must call shm_seg_exit before call this function
**************************************************************************** */
int shm_master_exit(struct shm_seg_s *seg);

/* ****************************************************************************
function name           :  shm_set_info_log_writer/shm_set_error_log_writer
Functional description  :  Register the callback function that outputs log information
Input paraments         :  void (*writer)(char *, int)) : Callback function to output log information
                          (Callback function parameters include information content string and string length)
Return value            :  Null
**************************************************************************** */
void shm_set_info_log_writer(void (*writer)(char *, int));
void shm_set_error_log_writer(void (*writer)(char *, int));


/* ****************************************************************************
 function name           :  shm_write_log_info/shm_write_log_error
 Functional description  :  log print function
 Input paraments         :  char *log_text The contents of the string log.
                            int length : String length
 Return value            :  Null
 Precautions             :  This function is for JNI only.
**************************************************************************** */
void shm_write_log_info(char *log_text, int length);
void shm_write_log_error(char *log_text, int length);

void shm_assign_proc_id(struct shm_seg_s *seg, int proc_id);

void shm_set_thread_calm_time(uint32_t time_us);

void shm_set_proc_connected_callback(int (*func)(int *));

int shm_client_connect(shm_key_t *shm_key, int *client_id);
void shm_client_disconnect(void);

int shm_tpool_init(int thd_num);
void shm_tpool_destroy(void);

#ifdef __cplusplus
}
#endif /* __cpluscplus */
#endif // dsw_shm_pub_h__
