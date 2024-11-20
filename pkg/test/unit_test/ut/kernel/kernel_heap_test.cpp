#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include <mockcpp/mockcpp.hpp>
#include <string>
#include "srv_instance.h"
#include "srv_session.h"
#include "srv_agent.h"
#include "knl_heap.h"
#include "knl_interface.h"
#include "ctsql_stmt.h"
#include "knl_undo.h"

#ifdef WIN32
#define SEPRRATOR "\\"
#else
#define SEPRRATOR "/"
#endif

extern instance_t *g_instance;

status_t ut_init()
{
    return CT_SUCCESS;
}

status_t ut_prepare(text_t sql_text, sql_stmt_t *sql_stmt)
{
    return CT_SUCCESS;
}

class ut_test_heap : public testing::Test
{
protected:
    void SetUp() override
    {
    }
    void TearDown() override
    {
        GlobalMockObject::reset();
    }
};

TEST(ut_test_heap, create_db)
{
    text_t sql_text;
    status_t status;
    std::string g_data_dir;
    char *gsdb_home = getenv("CTDB_HOME");
    sql_stmt_t *sql_stmt = nullptr;
    
    status = ut_init();
    EXPECT_EQ(CT_SUCCESS, status);
}