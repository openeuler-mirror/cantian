#define __LINUX_USER__
#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include <mockcpp/mockcpp.hpp>
#include <stdint.h>
extern "C"
{
#include  "cm_defs.h"
#include "mes_func.h"
#include "cm_error.h"
}

using namespace std;

extern mes_instance_t g_mes;

class MesTest : public testing::Test
{
protected:
    void SetUp() override
    {
    }
    void TearDown() override
    {
    }
};

TEST_F(MesTest, mes_connection_test)
{
    bool32 ret = CT_ERROR;
    uint32 inst_id = 0;
    char *ip = NULL;
    uint16 port = 0;
    ret = mes_connection_ready(inst_id);
    EXPECT_EQ(CT_SUCCESS, ret);   
}