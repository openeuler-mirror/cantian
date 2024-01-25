/******************************************************************************

                  版权所有 (C), 2008-2008, 华为赛门铁克科技有限公司

 ******************************************************************************
  文 件 名   : lvos_list.h
  版 本 号   : 初稿
  作    者   : x00001559
  生成日期   : 2008年6月4日
  最近修改   :
  功能描述   : 链表操作宏定义
  函数列表   :
  修改历史   :
  1.日    期   : 2008年6月4日
    作    者   : x00001559
    修改内容   : 创建文件

******************************************************************************/
/**
    \file  lvos_list.h
    \brief 链表操作宏定义，无调用上下文限制，即可以用于中断上下文
    \note  支持windows/linux_kernel/linux_user

    \date 2008-08-19
*/

/** \addtogroup VOS_LIST 链表操作
    链表操作以Linux本身的接口为原型封装
    @{ 
*/

#ifndef __LVOS_LIST_H__
#define __LVOS_LIST_H__

#if defined(__LINUX_USR__) || defined(WIN32) || defined(_PCLINT_)

/*
 * These are non-NULL pointers that will result in page faults
 * under normal circumstances, used to verify that nobody uses
 * non-initialized list entries.
 */
#define LIST_POISON1  ((struct list_head *) 0x00100100)
#define LIST_POISON2  ((struct list_head *) 0x00200200)

/* 注意，Linux用户态和WIN32的list功能没有互斥访问保护 */
/** \brief list节点结构
*/
struct list_head {
    struct list_head *next, *prev;/* next后指针，prev前指针 */
};

/** \brief 链表头初始化 */
#define LIST_HEAD_INIT(name) { &(name), &(name) }

/** \brief 链表头初始化 */
#define LIST_HEAD(name) \
    struct list_head name = LIST_HEAD_INIT(name)

/** \brief 初始化链表头
    \param[in] ptr 链表结构指针
    \return 无
*/
#define INIT_LIST_HEAD(ptr) { \
    (ptr)->next = (ptr); (ptr)->prev = (ptr); \
}



static inline void __list_add(struct list_head *new_head,
                  struct list_head *prev,
                  struct list_head *next)
{
    /* 添加到链表 */
    next->prev = new_head;
    new_head->next = next;
    new_head->prev = prev;
    prev->next = new_head;
}

/** \brief 添加新的链表元素到链表头
    \param[in] new_head 待添加链表结构指针
    \param[in] head 链表头结构指针
    \return 无
*/
static inline void list_add(struct list_head *new_head, struct list_head *head)
{
    /* 添加到链表头 */
    __list_add(new_head, head, head->next);
}
/*lint -sem(list_add2, custodial(1)) */
static inline void list_add2(void *nodeStruct, uint32_t nodeOffset, struct list_head *head)
{
    list_add((struct list_head *)((char *)nodeStruct + nodeOffset), head);
}

/** \brief 添加新的链表元素到链表尾
    \param[in] new_head 待添加链表结构指针
    \param[in] head 链表头结构指针
    \return 无
*/
static inline void list_add_tail(struct list_head *new_head, struct list_head *head)
{
    /* 添加到链表尾 */
    __list_add(new_head, head->prev, head);
}
/*lint -sem(list_add_tail2, custodial(1)) */
static inline void list_add_tail2(void *nodeStruct, uint32_t nodeOffset, struct list_head *head)
{
    list_add_tail((struct list_head *)((char *)nodeStruct + nodeOffset), head);
}

static inline void __list_del(struct list_head * prev, struct list_head * next)
{
    /* 从链表删除 */
    next->prev = prev;
    prev->next = next;
}

/** \brief 从链表删除节点
    \param[in] entry 待删除链表结构指针
    \return 无
*/
static inline void list_del(struct list_head *entry)
{
    /* 删除链表记录 */
    __list_del(entry->prev, entry->next);
    entry->next = LIST_POISON1;
    entry->prev = LIST_POISON2;
}

/** \brief 判断链表是否为空
    \param[in] head 链表头指针
    \return 无
*/
static inline int list_empty(struct list_head *head)
{
    /* 判断链表是否为空 */
    return head->next == head;
}

/** \brief 删除指定链表元素并初始化
    \param[in] entry 待删除并初始化的链表元素
    \return 无
*/
static inline void list_del_init(struct list_head *entry)
{
    __list_del(entry->prev, entry->next);
    INIT_LIST_HEAD(entry); 
}

/** \brief 转移链表元素到新链表头
    \param[in] list 旧链表的链表头
    \param[in] head 新链表的链表头
    \return 无
*/
static inline void list_move(struct list_head *list, struct list_head *head)
{
    __list_del(list->prev, list->next);
    list_add(list, head);
}

/** \brief 转移链表元素到新链表尾
    \param[in] list 旧链表的链表头
    \param[in] head 新链表的链表头
    \return 无
*/
static inline void list_move_tail(struct list_head *list, struct list_head *head)
{
    __list_del(list->prev, list->next);
    list_add_tail(list, head);
}

/** \brief 通过链表地址获得结构体指针
    \param[in] ptr 链表结构指针
    \param[in] type 结构体类型
    \param[in] member 结构体中链表所表示的字段
    \return 无
*/
#define list_entry(ptr, type, member) \
    ((type *)(void *)((char *)(ptr) - offsetof(type, member)))

/** \brief 向后遍历链表
    \attention 遍历过程中不允许删除链表元素
    \param[in] pos 当前所指向的链表节点
    \param[in] head 链表头指针
    \return 无
*/
#define list_for_each(pos, head) \
    for (pos = (head)->next; pos != (head); \
            pos = pos->next)

/** \brief 从pos的下一个节点, 向后遍历链表
    \attention 遍历过程中不允许删除链表元素
    \param[in] pos 指定的链表节点
    \param[in] head 链表头指针
    \return 无
*/
#define list_for_each_continue(pos, head)\
        for ((pos) = (pos)->next; (pos) != (head); (pos) = (pos)->next)

/** \brief 向后遍历链表
    \attention 用户必须自行在遍历过程中删除链表元素，否则将导致死循环
    \param[in] pos 当前所指向的链表节点
    \param[in] head 链表头指针
    \return 无
*/
#define list_for_del_each(pos, head) \
    for (pos = (head)->next; pos != (head); \
            pos = (head)->next)

/** \brief 向后遍历链表
    \attention 遍历过程中支持用户自行删除链表元素，用户可自行决定是否删除
    \param[in] pos 当前所指向的链表节点
    \param[in] n   循环临时值
    \param[in] head 链表头指针
    \return 无
*/
#define list_for_each_safe(pos, n, head) for (pos = (head)->next, n = pos->next; pos != (head); pos = n, n = pos->next)

/** \brief 从pos的下一个节点开始, 向后遍历链表
    \attention 遍历过程中支持用户自行删除链表元素，用户可自行决定是否删除
    \param[in] pos 指定的链表节点
    \param[in] n   循环临时值
    \param[in] head 链表头指针
    \return 无
*/
#define list_for_each_safe_continue(pos, n, head)\
        for ((pos) = (pos)->next, n = (pos)->next; pos != (head); \
             (pos) = n, n = (pos)->next)


#define list_for_each_prev_safe(pos, p, head)\
        for(pos = (head)->prev, p = pos->prev; pos != (head);\
            pos = p, p = pos->prev)

/** \brief 向前遍历链表
    \attention 遍历过程中不允许删除链表元素
    \param[in] pos 当前所指向的链表节点
    \param[in] head 链表头指针
    \return 无
*/
#define list_for_each_prev(pos, head) \
            for (pos = (head)->prev; pos != (head); pos = pos->prev) 

/** \brief 向后遍历链表，并获得链表所在结构体指针
    \attention 遍历过程中不允许删除链表元素
    \param[in] pos 链表所在结构体指针
    \param[in] type 结构体类型
    \param[in] head 链表头指针
    \param[in] member 结构体成员名
    \return 无
*/
#define list_for_each_entry(pos, type, head, member)\
                for (pos = list_entry((head)->next, type, member);\
                &pos->member != (head);\
                pos = list_entry(pos->member.next, type, member))

#elif defined(__KERNEL__) /* Linux内核态  */
#include <linux/list.h>

/** \brief 向后遍历链表
    \attention 用户必须自行在遍历过程中删除链表元素，否则将导致死循环
    \param[in] pos 当前所指向的链表节点
    \param[in] head 链表头指针
    \return 无
*/
#define list_for_del_each(pos, head) \
    for (pos = (head)->next; pos != (head); \
            pos = (head)->next)

/** \brief 从pos的下一个节点, 向后遍历链表
    \attention 遍历过程中不允许删除链表元素
    \param[in] pos 指定的链表节点
    \param[in] head 链表头指针
    \return 无
*/
#define list_for_each_continue(pos, head)\
        for ((pos) = (pos)->next; (pos) != (head); (pos) = (pos)->next)

/** \brief 从pos的下一个节点开始, 向后遍历链表
    \attention 遍历过程中支持用户自行删除链表元素，用户可自行决定是否删除
    \param[in] pos 指定的链表节点
    \param[in] n   循环临时值
    \param[in] head 链表头指针
    \return 无
*/
#define list_for_each_safe_continue(pos, n, head)\
        for ((pos) = (pos)->next, n = (pos)->next; pos != (head); \
             (pos) = n, n = (pos)->next)

#else
#error "platform not specify"
#endif

#define INIT_LIST_NODE(ptr)   { (ptr)->next = LIST_POISON1; (ptr)->prev = LIST_POISON2; }

#define IS_LIST_NODE_INIT(ptr)  ((LIST_POISON1 == (ptr)->next) && (LIST_POISON2 == (ptr)->prev))

#endif /* __LVOS_LIST_H__ */

/** @} */

