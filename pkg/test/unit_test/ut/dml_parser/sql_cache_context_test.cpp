#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include <mockcpp/mockcpp.hpp>
#include <sys/time.h>
#include <iostream>

extern "C" {
#include "dml_parser.h"
#include "ctsql_stmt.h"
#include "ctsql_context.h"
#include "cm_context_pool.h"
#include "cm_text.h"
#include "srv_session.h"
#include "cm_context_pool.h"
#include "cm_list.h"
#include "ctsql_statistics.h"
#include "knl_session.h"
#include "srv_instance.h"

}

extern "C" {
    status_t sql_cache_context(sql_stmt_t *stmt, context_bucket_t *bucket, sql_text_t *sql, uint32 hash_value);
}

using namespace std;
extern instance_t *g_instance;
class TestSqlCacheContext : public testing::Test {
protected:
    instance_t mock_instance;
    sql_stmt_t *stmt;
    context_bucket_t bucket;
    sql_text_t sql;
    uint32 hash_value = 1234;
    sql_context_t mock_context;
    session_t *session;
    context_pool_t pool;
    lru_list_t lru_list;
    context_map_t map;
    galist_t tables;
    ctx_stat_t stat;
    context_ctrl_t ctrl;
    memory_context_t memory;
    // knl_session_t knl_session;
    void SetUp() override {
        memset(&mock_instance, 0, sizeof(mock_instance));
        memset(&pool, 0, sizeof(pool));
        pool.bucket_count=1;
        pool.lru_list_cnt=1;
        g_instance = &mock_instance; // 将全局变量指向模拟对象
        g_instance->sql.pool = &pool;
        stmt = new sql_stmt_t();
        session = new session_t();
        
        stmt->context = &mock_context;
        stmt->context->stat = stat;
        stmt->context->tables = &tables;
        stmt->context->tables->count = 1;
        stmt->context->stat.parse_calls = 0;
        stmt->context->ctrl = ctrl;
        stmt->context->ctrl.memory = &memory;
        stmt->session = session;
        pool.lru_list = &lru_list;
        pool.map = &map;

    }
    void TearDown() override {
        // 清理动态分配的内存
        delete stmt;
        g_instance = nullptr; 
    }
    // static int MockCtxPoolFind(context_pool_t *pool, text_t *text, uint32 hash_value, uint32 uid, uint32 remote_conn_type,
    //                 bool32 is_direct_route){
    //     sql_context_t mock_cached_ctx;
    //     memset(&mock_cached_ctx, 0, sizeof(mock_cached_ctx));
    //     return &mock_cached_ctx;
    // }
    static bool32 MockSqlCheckCtxTRUE(sql_stmt_t *stmt, sql_context_t *ctx){
        return CT_TRUE;
    }
     static bool32 MockSqlCheckCtxCTFALSE(sql_stmt_t *stmt, sql_context_t *ctx){
        return CT_FALSE;
    }
    static void MockSqlFreeContext(sql_context_t *ctx){
        return ;
    }
};


TEST_F(TestSqlCacheContext, Should_return_status_CTSUCCESS_when_cached_ctx_null)
{
    
    status_t ret = sql_cache_context(stmt,&bucket,&sql,hash_value);


    EXPECT_EQ(ret, CT_SUCCESS);

   
    // 验证 Mock 调用
    GlobalMockObject::verify();
}


TEST_F(TestSqlCacheContext, Should_return_status_CTSUCCESS_when_cached_ctx_not_null_sql_check_ctx_ctrue)
{
    MOCKER(ctx_pool_find)
            .stubs()
            .will(returnValue((void*)&mock_context));
    

    MOCKER(sql_check_ctx)
            .stubs()
            .will(invoke(MockSqlCheckCtxTRUE));
    MOCKER(sql_free_context)
            .stubs()
            .will(invoke(MockSqlFreeContext));        
    status_t ret = sql_cache_context(stmt,&bucket,&sql,hash_value);        
    EXPECT_EQ(ret, CT_SUCCESS);

   
    // 验证 Mock 调用
    GlobalMockObject::verify();
}

TEST_F(TestSqlCacheContext, Should_return_status_CTSUCCESS_when_cached_ctx_not_null_sql_check_ctx_false)
{
    MOCKER(ctx_pool_find)
            .stubs()
            .will(returnValue((void*)&mock_context));
    

    MOCKER(sql_check_ctx)
            .stubs()
            .will(invoke(MockSqlCheckCtxCTFALSE));
    MOCKER(sql_free_context)
            .stubs()
            .will(invoke(MockSqlFreeContext));        
    status_t ret = sql_cache_context(stmt,&bucket,&sql,hash_value);        
    EXPECT_EQ(ret, CT_SUCCESS) ;

   
    // 验证 Mock 调用
    GlobalMockObject::verify();
}


