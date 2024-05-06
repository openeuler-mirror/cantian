#include "func_mgr.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

uintptr_t return_bool(FUNCTION_ARGS)
{
    FMGR_RETURN(true);
}

uintptr_t add_two_short(FUNCTION_ARGS)
{
    if (FMGR_ARG_IS_NULL(0)) {
        FMGR_RETURN_NULL;
    }
    if (FMGR_ARG_IS_NULL(1)) {
        FMGR_RETURN_NULL;
    }
    
    short arg1 = FMGR_GET_ARG_VALUE(0, short);
    unsigned short arg2 = FMGR_GET_ARG_VALUE(1, unsigned short);
    
    FMGR_RETURN(arg1 + arg2);
}

uintptr_t sub_two_int(FUNCTION_ARGS)
{
    if (FMGR_ARG_IS_NULL(0)) {
        FMGR_RETURN_NULL;
    }
    if (FMGR_ARG_IS_NULL(1)) {
        FMGR_RETURN_NULL;
    }
    int arg1 = FMGR_GET_ARG_VALUE(0, int);
    unsigned int arg2 = FMGR_GET_ARG_VALUE(1, unsigned int);
    FMGR_RETURN(arg1 - arg2);
}

uintptr_t mul_two_bigint(FUNCTION_ARGS)
{
    if (FMGR_ARG_IS_NULL(0)) {
        FMGR_RETURN_NULL;
    }
    if (FMGR_ARG_IS_NULL(1)) {
        FMGR_RETURN_NULL;
    }
    long long arg1 = FMGR_GET_ARG_VALUE(0, long long);
    long long arg2 = FMGR_GET_ARG_VALUE(1, long long);

    FMGR_RETURN(arg1 * arg2);
}

uintptr_t div_two_double(FUNCTION_ARGS)
{
    if (FMGR_ARG_IS_NULL(0)) {
        FMGR_RETURN_NULL;
    }
    if (FMGR_ARG_IS_NULL(1)) {
        FMGR_RETURN_NULL;
    }
    
    double arg1 = FMGR_GET_ARG_VALUE(0, double);
    double arg2 = FMGR_GET_ARG_VALUE(1, double);

    FMGR_RETURN_DOUBLE(arg1 / arg2);
}


uintptr_t copy_binary(FUNCTION_ARGS)
{
    if (FMGR_ARG_IS_NULL(0)) {
        FMGR_RETURN_NULL;
    }
    cbinary_t  *t = FMGR_GET_ARG_PTR(0, cbinary_t);
    
    cbinary_t  *new_t = (cbinary_t *) FMGR_ALLOC(sizeof(cbinary_t));
    if (new_t == NULL) {
        FMGR_RETURN_NULL; 
    }
    new_t->bytes = FMGR_ALLOC(t->size);
    if (new_t->bytes == NULL) {
        FMGR_RETURN_NULL;
    }
    new_t->size = t->size;
    memcpy((void *) new_t->bytes,
           (void *) t->bytes,
           new_t->size);
    FMGR_RETURN(new_t);
}

uintptr_t concat_binary(FUNCTION_ARGS)
{
    if (FMGR_ARG_IS_NULL(0)) {
        FMGR_RETURN_NULL;
    }
    if (FMGR_ARG_IS_NULL(1)) {
        FMGR_RETURN_NULL;
    }
    if (FMGR_ARG_IS_NULL(2)) {
        FMGR_RETURN_NULL;
    }
    cbinary_t  *arg1 = FMGR_GET_ARG_PTR(0, cbinary_t);
    cbinary_t  *arg2 = FMGR_GET_ARG_PTR(1, cbinary_t);
    cbinary_t  *arg3 = FMGR_GET_ARG_PTR(2, cbinary_t);
    int new_text_size = arg1->size + arg2->size + arg3->size;
    cbinary_t *new_text = (cbinary_t *) FMGR_ALLOC(sizeof(cbinary_t));
    if (new_text == NULL) {
        FMGR_RETURN_NULL; 
    }
    new_text->bytes = (char *) FMGR_ALLOC(new_text_size);
    if (new_text->bytes == NULL) {
        FMGR_RETURN_NULL; 
    }
    new_text->size = new_text_size;
    memcpy(new_text->bytes, arg1->bytes, arg1->size);
    memcpy(new_text->bytes + arg1->size,
           arg2->bytes, arg2->size);
    memcpy(new_text->bytes + arg1->size + arg2->size,
           arg3->bytes, arg3->size);
    FMGR_RETURN(new_text);
}

uintptr_t copy_text(FUNCTION_ARGS)
{
    if (FMGR_ARG_IS_NULL(0)) {
        FMGR_RETURN_NULL;
    }
    
    ctext_t  *t = FMGR_GET_ARG_PTR(0, ctext_t);
    
    ctext_t  *new_t = (ctext_t *) FMGR_ALLOC(sizeof(ctext_t));
    if (new_t == NULL) {
        FMGR_RETURN_NULL; 
    }
    new_t->str = FMGR_ALLOC(t->len);
    if (new_t->str == NULL) {
        FMGR_RETURN_NULL;
    }
    new_t->len = t->len;
    memcpy((void *) new_t->str,
           (void *) t->str,
           new_t->len);
    FMGR_SET_ARG_PTR(1, new_t);
    FMGR_RETURN(new_t);
    
}


uintptr_t concat_text(FUNCTION_ARGS)
{
    if (FMGR_ARG_IS_NULL(0)) {
        FMGR_RETURN_NULL;
    }
    
    if (FMGR_ARG_IS_NULL(1)) {
        FMGR_RETURN_NULL;
    }
    ctext_t  *arg1 = FMGR_GET_ARG_PTR(0, ctext_t);
    ctext_t  *arg2 = FMGR_GET_ARG_PTR(1, ctext_t);
    
    int new_text_size = arg1->len + arg2->len;
    ctext_t *new_text = (ctext_t *) FMGR_ALLOC(sizeof(ctext_t));
    if (new_text == NULL) {
        FMGR_RETURN_NULL; 
    }
    new_text->str = (char *) FMGR_ALLOC(new_text_size);
    if (new_text->str == NULL) {
        FMGR_RETURN_NULL; 
    }
    new_text->len = new_text_size;
    memcpy(new_text->str, arg1->str, arg1->len);
    memcpy(new_text->str + arg1->len,
           arg2->str, arg2->len);
    FMGR_SET_ARG_PTR(2, new_text);
    FMGR_RETURN_VOID;
}

uintptr_t in_out_param(FUNCTION_ARGS)
{
    if (FMGR_ARG_IS_NULL(0)) {
        FMGR_RETURN_NULL;
    }
    if (FMGR_ARG_IS_NULL(1)) {
        FMGR_RETURN_NULL;
    }
    if (FMGR_ARG_IS_NULL(2)) {
        FMGR_RETURN_NULL;
    }
    if (FMGR_ARG_IS_NULL(3)) {
        FMGR_RETURN_NULL;
    }

    int       arg1  = FMGR_GET_ARG_VALUE(0, int);
    double    arg2  = FMGR_GET_ARG_VALUE(1, double);
    cbinary_t *arg3 = FMGR_GET_ARG_PTR(2, cbinary_t);
    ctext_t   *arg4 = FMGR_GET_ARG_PTR(3, ctext_t);
    FMGR_SET_ARG_VALUE(0, int, arg1 + 1);
    FMGR_SET_ARG_VALUE(1, double, arg2 + 1);
    memset(arg3->bytes, '1', arg3->size);
    memset(arg4->str, 'z', arg4->len);
    
    FMGR_RETURN_VOID;
}

uintptr_t exception_core(FUNCTION_ARGS)
{   
    *((unsigned int *)NULL) = 1;
    FMGR_RETURN(1);
}

