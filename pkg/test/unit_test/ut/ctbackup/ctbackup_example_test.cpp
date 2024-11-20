#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include <mockcpp/mockcpp.hpp>
#include "ctbackup.h"
#include "ctbackup_backup.h"
#include "ctbackup_common.h"
#include "ctbackup_info.h"
#include "ctbackup_prepare.h"
#include "ctbackup_copyback.h"
#include "ctbackup_archivelog.h"
#include "ctbackup_reconciel_mysql.h"
#include "ctbackup_factory.h"

using namespace std;

class TestCtbackup : public testing::Test
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

TEST_F(TestCtbackup, Should_return_CT_SUCCESS_when_ctbak_process_args_backup)
{
    int argc = 2;
    char *argv[] = {CTBACKUP_NAME, CTBAK_ARG_BACKUP, nullptr};
    MOCKER(ctbak_do_backup).expects(once()).will(returnValue(CT_SUCCESS));
    MOCKER(ctbak_parse_backup_args).expects(once()).will(returnValue(CT_SUCCESS));
    status_t status = ctbak_process_args(argc, argv);
    EXPECT_EQ(status, CT_SUCCESS);
    GlobalMockObject::verify();
}