/**
* Copyright(C), 2014 - 2015, Huawei Tech. Co., Ltd. ALL RIGHTS RESERVED. \n
*/

/**
* @file dpax_list.h
* @brief 基础组件链表操作接口
* @verbatim 
   功能描述：基础组件链表操作接口
   目标用户：SPA,POOL
   使用约束：NA
   升级影响: no
@endverbatim
*/

#ifndef __DPAX_LIST_H__
#define __DPAX_LIST_H__

#include "vos_win/vos/lvos_list.h"

typedef struct list_head list_head_t;

#if 0
/**
 *@defgroup  osax_list 链表操作
 *@ingroup osax
*/
#include "dp_base.h"

#ifdef WIN32

#include "lvos_list.h"

#else

#include <unistd.h>
#include <errno.h>
#include <stddef.h>
#include "dpax_segment.h"
#include "dpax_macro.h"

#endif

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

#ifdef WIN32

#define DPAX_INIT_LIST_HEAD		INIT_LIST_HEAD
#define dpax_list_for_each		list_for_each
#define dpax_list_for_each_safe	list_for_each_safe
#define dpax_list_entry			list_entry
#define dpax_list_add			list_add
#define dpax_list_add_tail		list_add_tail
#define dpax_list_del_init		list_del_init
#define dpax_list_del			list_del
#define dpax_list_for_del_each	list_for_del_each
#define dpax_list_move			list_move
#define dpax_list_move_tail		list_move_tail
#define dpax_list_empty			list_empty
#define dpax_list_splice		list_splice
#define dpax_list_splice_init	list_splice_init
#define dpax_list_for_each_entry	list_for_each_entry

 #define dpax_list_first_entry(ptr, type, member) \
    dpax_list_entry((ptr)->next, type, member)

 #define dpax_list_next_entry(pos, type, member) \
    dpax_list_entry((pos)->member.next, type, member)

#define dpax_list_for_each_entry_safe(pos, n, type, head, member) /*lint -save -e26*/  \
    for (pos = dpax_list_entry((head)->next, type, member),  \
        n = dpax_list_entry(pos->member.next, type, member); \
        &pos->member != (head);         \
        pos = n, n = dpax_list_entry(n->member.next, type, member)) /*lint -restore*/

#define dpax_list_for_each_entry_reverse(pos, type, head, member)      \
    for (pos = dpax_list_entry((head)->prev, type, member);  \
        &pos->member != (head);         \
        pos = dpax_list_entry(pos->member.prev, type, member))

#define dpax_list_for_each_entry_safe_reverse(pos, n, type, head, member)       \
    for (pos = dpax_list_entry((head)->prev, type, member),  \
        n = dpax_list_entry(pos->member.prev, type, member); \
        &pos->member != (head);                                    \
        pos = n, n = dpax_list_entry(n->member.prev, type, member))

#define dpax_list_for_each_entry_continue(pos, type, head, member)     \
    for (pos = dpax_list_entry(pos->member.next, type, member);  \
        &pos->member != (head);                 \
        pos = dpax_list_entry(pos->member.next, type, member))

#define dpax_list_for_del_all(pos, type, listHead, name)  \
do {                                                    \
    dpax_list_for_del_each(pos, listHead) {               \
        name = dpax_list_entry(pos, type, listNode);      \
        dpax_list_del(pos);                               \
        free(name);                                     \
    }                                                   \
} while(0)

#else

#ifndef LIST_POISON1
#define LIST_POISON1  ((void *) 0x00100100)
#endif
#ifndef LIST_POISON2
#define LIST_POISON2  ((void *) 0x00200200)
#endif
/**
* @brief 
  功能描述: 链表结构定义
  使用约束: NA
  升级影响: no
*/
struct list_head {
        struct list_head *next, *prev;   /**< 前驱后驱指针  */
};

typedef struct list_head list_head_t;

/**
* 链表头结点结构初始化
*/
#define DPAX_LIST_HEAD_INIT(name) { &(name), &(name) }
 
#define DPAX_LIST_HEAD(name) \
        struct list_head name = DPAX_LIST_HEAD_INIT(name)

/** 
 * 链表头初始化 
 */
#define LIST_HEAD_INIT(name) { &(name), &(name) }

#define LIST_HEAD(name) \
    struct list_head name = LIST_HEAD_INIT(name)

/**
* @brief 功能描述: 初始化链表元素节点
* @verbatim
  目标用户: 链表
  使用约束: ptr不能为空
  升级影响: no
@endverbatim

* @param[in]  ptr - 链表节点指针
* @retval NA
*/
#define DPAX_INIT_LIST_NODE(ptr)   { (ptr)->next = (struct list_head *)LIST_POISON1; (ptr)->prev = (struct list_head *)LIST_POISON2; }

/**
* @brief 功能描述: 判断链表节点是否初始化
* @verbatim
  目标用户: 链表
  使用约束: ptr不能为空
  升级影响: no
@endverbatim

* @param[in]  ptr - 链表节点指针
* @retval true  - 已初始化
        false - 未初始化
*/
#define IS_LIST_NODE_INIT(ptr)  ((LIST_POISON1 == (void*)((ptr)->next)) && (LIST_POISON2 == (void*)((ptr)->prev)))

/**
* @brief 功能描述: 通过链表地址获得结构体指针
* @verbatim
  目标用户: 链表
  使用约束: head不能为空
  升级影响: no
@endverbatim

* @param[in]  _ptr   - 结构体链表成员变量的指针
* @param[in]  _type  - 结构体类型
* @param[in]  _memb  - 结构体链表变量名称
* @retval 结构体指针
*/
#define dpax_list_entry(_ptr, _type, _memb)   /*lint -e718 -e746 -e78 -e516 */ \
                container_of(_ptr, _type, _memb)   /*lint +e718 +e746 +e78 +e516 */
				
/**
* @brief 功能描述: 向后遍历链表
* @verbatim
  目标用户: 链表
  使用约束: head不能为空
  升级影响: no
@endverbatim

* @param[in]  pos    - 遍历链表的游标节点
* @param[in]  head  - 链表的头结点
* @retval NA
*/
#define dpax_list_for_each(pos, head) \
    for (pos = (head)->next; pos != (head); pos = pos->next)

/**
* @brief 功能描述: 向后遍历链表
* @verbatim
  目标用户: 链表
  使用约束: 用户必须自行在遍历过程中删除链表元素，否则将导致死循环
  升级影响: no
@endverbatim

* @param[in]  pos    - 遍历链表的游标节点
* @param[in]  head  - 链表的头结点
* @retval NA
*/
#define dpax_list_for_del_each(pos, head) \
    for (pos = (head)->next; pos != (head); \
            pos = (head)->next)

/**
* @brief 功能描述: 向后遍历链表,支持删除链表元素
* @verbatim
  目标用户: 链表
  使用约束: head不能为空
  升级影响: no
@endverbatim

* @param[in]  pos    - 遍历链表的游标节点
* @param[in]  n      - 用作临时缓存的节点
* @param[in]  head  - 链表的头结点
* @retval NA
*/
#define dpax_list_for_each_safe(pos, n, head) \
    for (pos = (head)->next, n = pos->next; pos != (head); \
         pos = n, n = pos->next)


/**
* @brief 功能描述: 获取链表的第一个元素
* @verbatim
  目标用户: 链表
  使用约束: list不能为空
  升级影响: no
@endverbatim

* @param[in]  ptr    - 要取出元素的链表头
* @param[in]  type  - 链表所嵌入的结构体类型
* @param[in]  member  - 结构体链表成员名称
* @retval NA
*/
 #define dpax_list_first_entry(ptr, type, member) \
    dpax_list_entry((ptr)->next, type, member)

/**
* @brief 功能描述: 获取链表节点的下一个元素
* @verbatim
  目标用户: 链表
  使用约束: list不能为空
  升级影响: no
@endverbatim

* @param[in]  pos    - 遍历链表的游标节点
* @param[in]  type  - 链表所嵌入的结构体类型
* @param[in]  member  - 结构体链表成员名称
* @retval NA
*/
 #define dpax_list_next_entry(pos, type, member) \
    dpax_list_entry((pos)->member.next, type, member)

/**
* @brief 功能描述: 向后遍历链表，获取链表所在结构体指针
* @verbatim
  目标用户: 链表
  使用约束: head不能为空
  升级影响: no
@endverbatim

* @param[in]  pos    - 遍历链表的游标节点
* @param[in]  head  - 链表的头结点
* @param[in]  member  - 结构体链表成员名称
* @retval NA
*/
#define dpax_list_for_each_entry(pos, type, head, member)                          \
    for (pos = dpax_list_entry((head)->next, type, member);      \
         &pos->member != (head);                                    \
         pos = dpax_list_entry(pos->member.next, type, member))

/**
* @brief 功能描述: 向后遍历链表，获取链表所在结构体指针，遍历过程中支持删除操作
* @verbatim
  目标用户: 链表
  使用约束: head不能为空
  升级影响: no
@endverbatim

* @param[in]  pos    - 遍历链表的游标节点
* @param[in]  head  - 链表的头结点
* @param[in]  n      - 链表所在结构体缓存节点
* @param[in]  member  - 结构体链表成员名称
* @retval NA
*/
#define dpax_list_for_each_entry_safe(pos, n, type, head, member) /*lint -save -e26*/  \
    for (pos = dpax_list_entry((head)->next, type, member),  \
        n = dpax_list_entry(pos->member.next, type, member); \
        &pos->member != (head);         \
        pos = n, n = dpax_list_entry(n->member.next, type, member)) /*lint -restore*/


/**
* @brief 功能描述: 向前遍历链表，获取链表所在结构体指针
* @verbatim
  目标用户: 链表
  使用约束: head不能为空, 遍历过程中不支持删除操作
  升级影响: no
@endverbatim

* @param[in]  pos    - 遍历链表的游标节点
* @param[in]  head  - 链表的头结点
* @param[in]  member  - 结构体链表成员名称
* @retval NA
*/
#define dpax_list_for_each_entry_reverse(pos, type, head, member)      \
    for (pos = dpax_list_entry((head)->prev, type, member);  \
        &pos->member != (head);         \
        pos = dpax_list_entry(pos->member.prev, type, member))
		
/**
* @brief 功能描述: 向前遍历链表，获取链表所在结构体指针，遍历过程中支持删除操作
* @verbatim
  目标用户: 链表
  使用约束: head不能为空
  升级影响: no
@endverbatim

* @param[in]  pos    - 遍历链表的游标节点
* @param[in]  n      - 链表所在结构体缓存节点
* @param[in]  head  - 链表的头结点
* @param[in]  member  - 结构体链表成员名称
* @retval NA
*/
#define dpax_list_for_each_entry_safe_reverse(pos, n, type, head, member)       \
    for (pos = dpax_list_entry((head)->prev, type, member),  \
        n = dpax_list_entry(pos->member.prev, type, member); \
        &pos->member != (head);                                    \
        pos = n, n = dpax_list_entry(n->member.prev, type, member))

/**
* @brief 功能描述: 从当前节点处，向后遍历链表，获取链表所在结构体指针
* @verbatim
  目标用户: 链表
  使用约束: head不能为空，pos指针不能为空，遍历过程中不支持删除操作
  升级影响: no
@endverbatim

* @param[in]  pos    - 遍历链表的游标节点
* @param[in]  head  - 链表的头结点
* @param[in]  member  - 结构体链表成员名称
* @retval NA
*/
#define dpax_list_for_each_entry_continue(pos, type, head, member)     \
    for (pos = dpax_list_entry(pos->member.next, type, member);  \
        &pos->member != (head);                 \
        pos = dpax_list_entry(pos->member.next, type, member))

/** * @brief 初始化链表头
 * @param[in] ptr 链表结构指针
   \return 无
*/
#define INIT_LIST_HEAD(ptr) { \
        (ptr)->next = (ptr); (ptr)->prev = (ptr); \
    }


/**
* @brief 功能描述: 初始化链表头，链表头的前驱和后驱节点都指向自身
* @verbatim
  目标用户: 链表
  使用约束: 调用者list不能为空
  升级影响: no
@endverbatim

* @param[in]  list    - 链表指针
* @retval NA
*/
static inline void DPAX_INIT_LIST_HEAD(struct list_head *list)
{
    list->next = list;
    list->prev = list;
}

static inline void __list_add(struct list_head *newnode,
			           struct list_head *prev,
			           struct list_head *next)
{
	next->prev = newnode;
	newnode->next = next;
	newnode->prev = prev;
	prev->next = newnode;
}

/**
* @brief 功能描述: 添加新的链表元素到链表头
* @verbatim
  目标用户: 链表
  使用约束: newnode和head不能为空
  升级影响: no
@endverbatim

* @param[in]  newnode    - 待添加链表结构指针
* @param[in]  head  - 链表头结构指针
* @retval NA
*/
static inline void dpax_list_add(struct list_head *newnode, struct list_head *head)
{

#if (defined DPAX_DEBUG_SUPPORT)
    if (!IS_LIST_NODE_INIT(newnode))
    {
        DPAX_DBG_PANIC();
    }
#endif

    __list_add(newnode, head, head->next);
}

/**
* @brief 功能描述: 添加新的链表元素到链表尾
* @verbatim
  目标用户: 链表
  使用约束: newnode和head不能为空
  升级影响: no
@endverbatim

* @param[in]  newnode    - 待添加链表结构指针
* @param[in]  head  - 链表头结构指针
* @retval NA
*/
static inline void dpax_list_add_tail(struct list_head *newnode, struct list_head *head)
{
#if (defined DPAX_DEBUG_SUPPORT)
    if (!IS_LIST_NODE_INIT(newnode))
    {
        DPAX_DBG_PANIC();
    }
#endif
    __list_add(newnode, head->prev, head);
}

static inline void dpax_list_insert(struct list_head* new_node, struct list_head* prev_node, struct list_head* next_node)
{
    __list_add(new_node, prev_node, next_node);
}


static inline void __list_del(struct list_head * prev, struct list_head * next)
{
    next->prev = prev;
    prev->next = next;
}

/**
* @brief 功能描述: 从链表删除节点
* @verbatim
  目标用户: 链表
  使用约束: entry不能为空
  升级影响: no
@endverbatim

* @param[in]  entry    - 待删除的链表节点
* @retval NA
*/
static inline void dpax_list_del(struct list_head *entry)
{
#if (defined DPAX_DEBUG_SUPPORT)
    if (IS_LIST_NODE_INIT(entry))
    {
        DPAX_DBG_PANIC();
    }
#endif    
    __list_del(entry->prev, entry->next);
    DPAX_INIT_LIST_NODE(entry);
}

/**
 * list_empty - tests whether a list is empty
 * @head: the list to test.
 */
static inline int list_empty(const struct list_head *head)
{
	return head->next == head;
}


static inline list_head_t* dpax_list_get_first(list_head_t* head)
{
    return list_empty(head) ? NULL : head->next;
}

static inline list_head_t* dpax_list_get_tail(list_head_t* head)
{

    return  (head->prev == head) ? NULL : head->prev;
}

static inline list_head_t* dpax_list_del_first(list_head_t* head)
{
    list_head_t* ret = NULL;

    ret = head->next;
    if (ret == head)
    {
        /* the list is free */
        return NULL;
    }
    else
    {
        dpax_list_del(ret);
    }

    return ret;
}



/**
* @brief 功能描述: 将节点从链表删除后重新初始化该节点
* @verbatim
  目标用户: 链表
  使用约束: entry不能为空
  升级影响: no
@endverbatim

* @param[in]  entry    - 待删除的链表节点
* @retval NA
*/
static inline void dpax_list_del_init(struct list_head *entry)
{
#if (defined DPAX_DEBUG_SUPPORT)
    if (IS_LIST_NODE_INIT(entry))
    {
        DPAX_DBG_PANIC();
    }
#endif   

    __list_del(entry->prev, entry->next);
    DPAX_INIT_LIST_HEAD(entry);
}

static inline list_head_t* dpax_list_del_tail(list_head_t* head)
{
    list_head_t* ret;

    ret = head->prev;
    if (ret == head)
    {
        /* the list is free */
        return NULL;
    }
    else
    {
        dpax_list_del(ret);
    }

    return ret;
}



#define dpax_list_for_del_all(pos, type, listHead, name)  \
do {                                                    \
    dpax_list_for_del_each(pos, listHead) {               \
        name = dpax_list_entry(pos, type, listNode);      \
        dpax_list_del(pos);                               \
        free(name);                                     \
    }                                                   \
} while(0)

/**
* @brief 功能描述: 将当前链表节点移动到链表头
* @verbatim
  目标用户: 链表
  使用约束: list不为空，head不为空
  升级影响: no
@endverbatim

* @param[in]  list    - 当前需要移动的节点指针
* @param[in]  head  - 链表头指针
* @retval NA
*/
static inline void dpax_list_move(struct list_head *list, struct list_head *head)
{
    dpax_list_del(list);
    dpax_list_add(list, head);
}

/**
* @brief 功能描述: 将当前链表节点移动到链表尾
* @verbatim
  目标用户: 链表
  使用约束: list不为空，head不为空
  升级影响: no
@endverbatim

* @param[in]  list    - 当前需要移动的节点指针
* @param[in]  head  - 链表头指针
* @retval NA
*/
static inline void dpax_list_move_tail(struct list_head *list, struct list_head *head)
{
    dpax_list_del(list);
    dpax_list_add_tail(list, head);
}

/**
* @brief 功能描述: 判断链表是否为空
* @verbatim
  目标用户: 链表
  使用约束: head不为空
  升级影响: no
@endverbatim

* @param[in]  head  - 链表头指针
* @retval NA
*/
static inline int dpax_list_empty(const struct list_head *head)
{
    return head->next == head;
}

/**
* @brief 功能描述: 判断表头的前一个结点和后一个结点是否为其本身，如果同时满足则返回false，否则返回值为true。
* @verbatim
  目标用户: 链表
  使用约束: head不为空
  升级影响: no
@endverbatim

* @param[in]  head  - 链表头指针
* @retval NA
*/
static inline int dpax_list_empty_careful(const struct list_head *head)
{
	struct list_head *next = head->next;
	return (next == head) && (next == head->prev);
}

/**
* @brief 功能描述: 判断当前节点是否为最末节点
* @verbatim
  目标用户: 链表
  使用约束: list不为空
  升级影响: no
@endverbatim

* @param[in]  list    - 当前节点指针
* @param[in]  head  - 链表头指针
* @retval NA
*/
static inline int dpax_list_is_last(const struct list_head *list,
                const struct list_head *head)
{
    return list->next == head;
}

#define INIT_LIST_NODE(ptr)   { (ptr)->next = (struct list_head *)LIST_POISON1; (ptr)->prev = (struct list_head *)LIST_POISON2; }



/**
* @brief 功能描述: 向前遍历链表
* @verbatim
	目标用户: 链表
	使用约束: 遍历过程中不允许删除链表元素
	升级影响: no
@endverbatim
* @param[in]  pos	  - 当前所指向的链表节点
* @param[in]  head	 - 链表头指针
* @retval NA
*/
#define dpax_list_for_each_prev(pos, head) \
            for (pos = (head)->prev; pos != (head); pos = pos->prev) 

/**
* @brief 功能描述: 遍历链表
* @verbatim
	目标用户: 链表
	使用约束: list不为空，head不为空；遍历过程中支持用户自行删除链表元素，用户可自行决定是否删除
	升级影响: no
@endverbatim
* @param[in]  pos	  - 当前所指向的链表节点
* @param[in]  p	  - 循环临时值
* @param[in]  head	 - 链表头指针
* @retval NA
*/           
#define dpax_list_for_each_prev_safe(pos, p, head)\
                        for(pos = (head)->prev, p = pos->prev; pos != (head);\
                            pos = p, p = pos->prev)

/*适配dsware 新增*/
static inline void dpax_list_replace(list_head_t* old_node, list_head_t* new_node)
{
    new_node->next = old_node->next;
    new_node->next->prev = new_node;
    new_node->prev = old_node->prev;
    new_node->prev->next = new_node;
    DPAX_INIT_LIST_HEAD(old_node);
}

/*适配dsware 新增*/
static inline int dpax_list_check_in_queue(list_head_t* node)
{
    if ((node->next == node) && (node->prev == node))
    {
        return 0;
    }

    return 1;
}

/*适配dsware 新增*/
static inline void dpax_list_merge(list_head_t *first_list, list_head_t *second_list)
{
    if (dpax_list_empty(second_list))
    {
        return;
    }

    if (dpax_list_empty(first_list))
    {
        dpax_list_replace(second_list, first_list);
        return;
    }

    list_head_t *first_list_end = first_list->prev;
    list_head_t *second_list_begin = second_list->next;
    list_head_t *second_list_end = second_list->prev;

    first_list_end->next = second_list_begin;
    second_list_begin->prev = first_list_end;
    second_list_end->next = first_list;
    first_list->prev = second_list_end;

    DPAX_INIT_LIST_HEAD(second_list);
}

/*适配dsware 新增*/
static inline int dpax_list_node_is_tail(list_head_t* node, list_head_t* head)
{
    if (node == head->prev)
    {
        return 1;
    }

    return 0;
}

/*适配dsware 新增*/
static inline int dpax_list_node_is_first(list_head_t* node, list_head_t* head)
{
    if (node == head->next)
    {
        return 1;
    }

    return 0;
}


#endif

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */
#endif

#endif 
