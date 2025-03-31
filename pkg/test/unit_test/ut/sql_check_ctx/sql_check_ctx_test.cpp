#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include <mockcpp/mockcpp.hpp>
#include <iostream>

extern "C" {
#include "dml_parser.h"
#include "cm_error.h"
}

extern "C" {
    bool32 sql_check_ctx(sql_stmt_t *stmt, sql_context_t *ctx);
    status_t sql_check_tables(sql_stmt_t *stmt, sql_context_t *ctx);
    bool32 sql_check_procedures(sql_stmt_t *stmt, galist_t *dc_lst);
    void cm_reset_error(void);
}

class SqlCheckCtxTest : public ::testing::Test {
protected:
    void SetUp() override {
        stmt.param_info.paramset_size = 1;
        stmt.is_explain = false;
        stmt.batch_rows = 10;
        stmt.total_rows = 20;
        stmt.eof = false;

        ctx.policy_used = false;
        ctx.dc_lst = &dc_list;
    }

    void TearDown() override {
        GlobalMockObject::reset();
    }

    sql_stmt_t stmt;
    sql_context_t ctx;
    galist_t dc_list;
};

// 测试用例
TEST_F(SqlCheckCtxTest, PolicyUsed) {
    ctx.policy_used = true;

    bool32 result = sql_check_ctx(&stmt, &ctx);
    EXPECT_EQ(result, CT_FALSE);
}

TEST_F(SqlCheckCtxTest, CheckTablesFail) {
    ctx.policy_used = false;

    MOCKER(sql_check_tables).stubs().will(returnValue(CT_ERROR));
    MOCKER(cm_reset_error).stubs().will(returnValue(CT_TRUE));


    bool32 result = sql_check_ctx(&stmt, &ctx);
    EXPECT_EQ(result, CT_FALSE);
}

TEST_F(SqlCheckCtxTest, CheckProceduresFail) {
    ctx.policy_used = false;

    MOCKER(sql_check_tables).stubs().will(returnValue(CT_SUCCESS));
    MOCKER(sql_check_procedures).stubs().will(returnValue(CT_FALSE));

    bool32 result = sql_check_ctx(&stmt, &ctx);
    EXPECT_EQ(result, CT_FALSE);
}

TEST_F(SqlCheckCtxTest, CheckSuccess) {
    ctx.policy_used = false;

    MOCKER(sql_check_tables).stubs().will(returnValue(CT_SUCCESS));
    MOCKER(sql_check_procedures).stubs().will(returnValue(CT_TRUE));

    bool32 result = sql_check_ctx(&stmt, &ctx);
    EXPECT_EQ(result, CT_TRUE);
}