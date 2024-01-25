/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2014-2020. All rights reserved.
 * Description: ARRAY header file
 * Create: 2014-10-27
 */

#ifndef KMC_SRC_COMMON_WSECV2_ARRAY_H
#define KMC_SRC_COMMON_WSECV2_ARRAY_H

#include "wsecv2_type.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Indicates the increase when the memory is reallocated after the memory is used up (number of elements). */
#define WSEC_ARR_GROW_BY 16
#define WSEC_ARR_MEM_SIZE(num) ((num) * sizeof(WsecVoid *))

typedef WsecVoid *WsecAddr;
typedef WsecVoid *WsecArray;

/* element indicates the address of element to be deleted from the array,elementSize indicates the element length. */
typedef WsecVoid (* CallbackRemoveElement)(WsecHandle kmcCtx, WsecVoid *element, WsecUint32 elementSize);
typedef int (* CallbackCompare)(const WsecVoid *a, const WsecVoid *b);

typedef struct TagWsecArrayData {
    /* Address pointing to each element pointer (the element data storage space is managed by the app) */
    WsecVoid **itemAddr;
    int        countUsed;   /* Number of used elements. */
    /* Current maximum length. If the length exceeds the value of countUsed, the length is appended based on growNum. */
    int        countMax;
    /* Memory growth rate (If the value is too large, memory resources are wasted. */
    /* If the value is too small, memory fragments may occur.) */
    int        growNum;
    WsecUint32 elementSize; /* Element Size */
    CallbackCompare       cmpElement;
    CallbackRemoveElement removeElement;
} WsecArrayData;

/* Array initialization: specifies the initial array length and array growth. */
WsecArray WsecArrInitialize(WsecHandle kmcCtx, int elementNum, WsecUint32 elementSize,
    int growNum,
    CallbackCompare cmpElement, CallbackRemoveElement removeElement);

/* Release after array running out */
WsecArray WsecArrFinalize(WsecHandle kmcCtx, WsecArray arr);

/* Obtains data at a specified location. */
WsecVoid *WsecArrGetAt(const WsecVoid *arr, int idx);

/* Adding an element */
int WsecArrAdd(WsecHandle kmcCtx, WsecArray arr, WsecVoid *element);

/* Adding elements in sequence */
int WsecArrAddOrderly(WsecHandle kmcCtx, WsecArray arr, WsecVoid *element);

unsigned long WsecArrAddOrderlyNotRepeat(WsecHandle kmcCtx, WsecArray arr, WsecVoid *element);

/* Cloning and Adding Elements in Sequence */
int WsecArrCloneAddOrderly(WsecHandle kmcCtx, WsecArray arr, const WsecVoid *element, size_t elementSize);

/* Inserts an element to a specified position. */
WsecBool WsecArrInsertAt(WsecHandle kmcCtx, WsecArray arr, int idx, WsecVoid *element);

/* Deletes an element from a specified position. */
WsecVoid WsecArrRemoveAt(WsecHandle kmcCtx, WsecArray arr, int idx);

/* Clear Array */
WsecVoid WsecArrRemoveAll(WsecHandle kmcCtx, WsecArray arr);

/* Obtains the number of occupied elements in an array. */
int WsecArrGetCount(const WsecArray arr);

/* Quick troubleshooting */
WsecVoid WsecArrQuickSort(WsecArray arr);

/* Search */
WsecVoid *WsecArrBinarySearch(const WsecArray arr, const WsecVoid *key);

int WsecArrBinarySearchAt(const WsecArray arr, const WsecVoid *key);

WsecVoid WsecArrStdRemoveElement(WsecHandle kmcCtx, WsecVoid *element, WsecUint32 elementSize);

#ifdef __cplusplus
}
#endif  /* __cplusplus */

#endif /* KMC_SRC_COMMON_WSECV2_ARRAY_H */
