#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include <mockcpp/mockcpp.hpp>
#include <iostream>
#include <cstdlib>

extern "C" {
#include "srv_session.h"
#include "ctc_srv_util.h"
#include "ctc_srv.h"
#include "ctc_ddl.h"
#include "ctsql_statistics.h"
#include "ctsql_stmt.h"
#include "cm_log.h"
#include "knl_defs.h"
#include "knl_session.h"
#include "knl_database.h"
#include "knl_interface.h"
#include "srv_instance.h"
#include "srv_mq.h"
#include "srv_mq_msg.h"
#include "cm_text.h"
#include "dml_parser.h"
#include "types.h"
}

extern "C" {
    bool32 sql_get_context_cache(sql_stmt_t *stmt, text_t *sql, uint32 *sql_id, context_bucket_t **bid, ctx_stat_t *herit_stat);
}

class TestSqlGetContextCache : public testing::Test {
protected:
    context_bucket_t *bucket = NULL;
    text_t sql;
    uint32 hash_value;
    ctx_stat_t herit_stat;
    sql_context_t mock_context;
    knl_session_t knl_session;
    memory_context_t mock_memory;
    id_list_t mock_pages;
    ctc_handler_t mock_tch;
    session_t mock_session;
    sql_stmt_t mock_stmt;
    knl_session_t mock_knl_session;
    instance_t mock_instance;
    lex_t mock_lex;
    sql_text_t mock_text;
    knl_instance_t mock_kernel;
    context_pool_t mock_sql_pool;
    
    void SetUp() override {
        memset(&mock_kernel, 0, sizeof(mock_kernel));
        memset(&mock_instance, 0, sizeof(mock_instance));
        // memset(&mock_tch, 0, sizeof(mock_tch));
        memset(&mock_session, 0, sizeof(mock_session));
        memset(&mock_stmt, 0, sizeof(mock_stmt));
        memset(&mock_lex, 0, sizeof(mock_lex));
        memset(&mock_context, 0, sizeof(mock_context));
        memset(&mock_text, 0, sizeof(mock_text));
        // memset(&mock_stack, 0, sizeof(mock_stack));
        memset(&mock_session.knl_session, 0, sizeof(mock_session.knl_session));
        memset(&mock_sql_pool, 0, sizeof(mock_sql_pool));
        memset(&mock_memory, 0, sizeof(mock_memory));

        // mock_tch.sess_addr = (uint64)&mock_session;
        mock_stmt.param_info.paramset_size = 0;
        mock_session.lex = &mock_lex;
        mock_lex.text = mock_text;
        mock_stmt.session = &mock_session;
        mock_session.current_stmt = &mock_stmt;
        mock_stmt.context = &mock_context;
        g_instance = &mock_instance;
        g_instance->sql.pool = &mock_sql_pool;
        // g_instance->sql.enable_sql_statistic_stat = true;
        // mock_tch.pre_sess_addr == 0;
        // mock_session.knl_session.stack = &mock_stack;
        mock_session.knl_session.kernel = &mock_kernel;
        // mock_kernel.attr.mysql_metadata_in_cantian = true;
        // mock_def_list.count = 1;

        // mock_stack_memory = malloc(1024);
        // memset(&bucket.parsing_lock, 0, sizeof(bucket.parsing_lock));
    }

    void TearDown() override {
        // 清理动态分配的内存
    }

    static uint32 MockCmHashText(const text_t *text, uint32 range) {
        return 0;
    }

    static void MockCmRecursiveLock(uint16 sid, recursive_lock_t *lock, spin_statis_t *stat) {}

    static void MockCmRecursiveUnlock(recursive_lock_t *lock) {}

    static void* MockCtxPoolFind(context_pool_t *pool, text_t *text, uint32 hash_value, uint32 uid, uint32 remote_conn_type, bool32 is_direct_route) {
        static sql_context_t mock_context;
        return &mock_context;
    }

    static bool32 MockSqlCheckCtx(sql_stmt_t *stmt, sql_context_t *ctx) {
        return CT_TRUE;
    }

    static void MockSqlReleaseContext(sql_stmt_t *stmt) {}

    static int64 MockCmAtomicInc(atomic_t *val) {
        return __sync_add_and_fetch(val, 1);
    }

    static int64 MockCmAtomicAdd(atomic_t *val, int64 count){
    return __sync_add_and_fetch(val, count);
    }

    static void MockCtxPoolLruMoveToHead(context_pool_t *pool, context_ctrl_t *ctrl) {}
};

TEST_F(TestSqlGetContextCache, CacheHit) {
    // 模拟函数行为
    MOCKER(cm_hash_text)
        .stubs()
        .will(invoke(MockCmHashText));
    MOCKER(cm_recursive_lock)
        .stubs()
        .will(invoke(MockCmRecursiveLock));
    MOCKER(cm_recursive_unlock)
        .stubs()
        .will(invoke(MockCmRecursiveUnlock));
    MOCKER(ctx_pool_find)
        .stubs()
        .will(invoke(MockCtxPoolFind));
    MOCKER(sql_check_ctx)
        .stubs()
        .will(invoke(MockSqlCheckCtx));
    MOCKER(sql_release_context)
        .stubs()
        .will(invoke(MockSqlReleaseContext));
    MOCKER(cm_atomic_inc)
        .stubs()
        .will(invoke(MockCmAtomicInc));
    MOCKER(cm_atomic_add)
        .stubs()
        .will(invoke(MockCmAtomicAdd));
    MOCKER(ctx_pool_lru_move_to_head)
        .stubs()
        .will(invoke(MockCtxPoolLruMoveToHead));

    mock_context.ctrl.memory = &mock_memory;
    mock_memory.pages = mock_pages;
    mock_memory.pages.count = 1;
    mock_context.in_sql_pool = true;

    bool32 result = sql_get_context_cache(&mock_stmt, &sql, &hash_value, &bucket, &herit_stat);

    EXPECT_EQ(result, CT_TRUE);
}