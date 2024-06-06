/*!
 * This program is used for regressing test for Cantian SQL engine
 *
 * \author Created by pufuan p00421579
 * \date 2017/09/23
 */
#include <ctype.h>
#include <sys/stat.h>
#include <signal.h>

#ifdef HAVE_SYS_RESOURCE_H
#include <sys/time.h>
#include <sys/resource.h>
#endif
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "cm_text.h"
#include "cm_file.h"
#include "cm_list.h"
#include "cm_date.h"
// #include <win32.h>
#ifdef WIN32
#include <conio.h>
#include <windows.h>
#include <direct.h>
#define getcwd _getcwd // stupid MSFT "deprecation" warning
#else
#include <termios.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

static const char *progname;

#ifndef WIN32					/* not used in WIN32 case */
#define DEFAULT_SHELL   "/bin/sh";
static char *shellprog = DEFAULT_SHELL;
#endif

/*
* On Windows we use -w in diff switches to avoid problems with inconsistent
* newline representation.  The actual result files will generally have
* Windows-style newlines, but the comparison files might or might not.
*/
#ifndef WIN32
const char *basic_diff_opts = "-w -B -C3";
const char *pretty_diff_opts = "-w -C3";
#else
const char *basic_diff_opts = "-w -B -C3";
const char *pretty_diff_opts = "-w -C3";
#endif


#ifndef WIN32
#define PID_TYPE pid_t
#define INVALID_PID (-1)
#else
#define PID_TYPE HANDLE
#define INVALID_PID INVALID_HANDLE_VALUE
#endif

#define   MAX_TEST_NAME_LEN  256
#define   MAX_FILE_LEN  1024

#define   MAX_PARALLEL_TESTS   100

typedef enum en_test_type
{
    TT_NORMAL,
    TT_INTERACT,
} test_type_t;

char  g_ttyp_flag[2] = {'t', 'i'};

typedef struct gtest_t
{
    char  name[MAX_TEST_NAME_LEN];
    char  sqlfile[MAX_FILE_LEN];
    char  outfile[MAX_FILE_LEN];
    char  expfile[MAX_FILE_LEN];
    date_t begin_time;
    date_t end_time;
} gtest_t;

typedef struct test_group_t
{
    gtest_t      tests[MAX_PARALLEL_TESTS];
    PID_TYPE     pids[MAX_PARALLEL_TESTS];
    int          statuses[MAX_PARALLEL_TESTS];
    uint32       num;
    test_type_t  t_typ;
} test_group_t;

test_group_t   g_cases;
int  g_fail_count = 0;
int  g_success_count = 0;

typedef PID_TYPE(*test_function) (const char * conn_str, gtest_t* test);


/* default values */
#define BINDIR       ".\\ctsql.exe"      /* the default path of ctsql.exe */
#define SCHEDULE     "./ct_schedule"
#define INPUTDIR     "./sql/"
#define OUTPUTDIR    "./results/"
#define EXPECTDIR    "./expected/"
#define HOST         "127.0.0.1"
#define PORT         "1611"
#define DB_USER      "sys/sys"
#define DEFLT_CONNS  100

typedef enum
{
    OPT_UNKNOWN    = -1,
    OPT_HELP       = 0,
    OPT_BINDIR     = 1, 
    OPT_INPUTDIR   = 2,
    OPT_OUTPUTDIR  = 3,
    OPT_EXPECTDIR  = 4,
    OPT_SCHEDULE   = 5,  
    OPT_HOST       = 6,
    OPT_PORT       = 7,
    OPT_USER       = 8,
    OPT_MAX_CONN   = 9
//    OPT_PASSWORD   = 9,
} opt_type;



typedef struct st_option
{
    opt_type    flag;
    const char *name;
    union
    {
        char   *value;
        uint32  ival;
    };

} option_t;

/* options settable from command line, if they are not specified, used default values */
static option_t g_opts[] = {
    { OPT_HELP       , "--help",        .value = NULL },
    { OPT_BINDIR     , "--bindir",      .value = BINDIR },
    { OPT_INPUTDIR   , "--inputdir",    .value = INPUTDIR },
    { OPT_OUTPUTDIR  , "--outputdir",   .value = OUTPUTDIR },
    { OPT_EXPECTDIR  , "--expectdir",   .value = EXPECTDIR },
    { OPT_SCHEDULE   , "--schedule",    .value = SCHEDULE },
    { OPT_HOST       , "--host",        .value = HOST },
    { OPT_PORT       , "--port",        .value = PORT },
    { OPT_USER       , "--user",        .value = DB_USER },
    { OPT_MAX_CONN   , "--max_conns",   .ival  = DEFLT_CONNS },
    { OPT_UNKNOWN    , .name = NULL,    .value = NULL }
};

static char g_conn_str[MAX_FILE_LEN];

PID_TYPE spawn_process(const char *cmdline);

/*
* Print "doing something ..." --- supplied text should not end with newline
*/
static void
gr_printf(const char *fmt, ...)
{
    va_list		ap;

    va_start(ap, fmt);
    vfprintf(stdout, fmt, ap);
    fflush(stdout);
    va_end(ap);
}

/*
* Wait for specified subprocesses to finish, and return their exit
* statuses into statuses[]
*
* If names isn't NULL, print each subprocess's name as it finishes
*
* Note: it's OK to scribble on the pids array, but not on the names array
*/
static void
wait_for_tests(int pos, int num_tests)
{
    int			tests_left;
    int			i;

#ifdef WIN32
    PID_TYPE   *active_pids = malloc(num_tests * sizeof(PID_TYPE));
    memcpy(active_pids, g_cases.pids + pos, num_tests * sizeof(PID_TYPE));
#endif

    tests_left = num_tests;
    while (tests_left > 0)
    {
        PID_TYPE	p;

#ifndef WIN32
        int			exit_status;

        p = wait(&exit_status);

        if (p == INVALID_PID)
        {
            fprintf(stderr, "Failed to wait for subprocesses: %s\n",
                strerror(errno));
            exit(2);
        }
#else
        DWORD		exit_status;
        int			r;

        r = WaitForMultipleObjects(tests_left, active_pids, FALSE, INFINITE);
        if (r < (int)WAIT_OBJECT_0 || r >= (int)WAIT_OBJECT_0 + tests_left)
        {
            fprintf(stderr, "Failed to wait for subprocesses: error code %lu\n",
                GetLastError());
            exit(2);
        }
        p = active_pids[r - (int)WAIT_OBJECT_0];
        /* compact the active_pids array */
        active_pids[r - (int)WAIT_OBJECT_0] = active_pids[tests_left - 1];
#endif   /* WIN32 */

        for (i = 0; i < num_tests; i++)
        {
            if (p == g_cases.pids[pos + i])
            {
#ifdef WIN32
                GetExitCodeProcess(g_cases.pids[pos + i], &exit_status);
                CloseHandle(g_cases.pids[pos + i]);
#endif
                g_cases.pids[i + pos] = INVALID_PID;
                g_cases.statuses[i + pos] = (int)exit_status;
                g_cases.tests[i + pos].end_time = cm_now();
                tests_left--;
                break;
            }
        }
    }

#ifdef WIN32
    free(active_pids);
#endif
}



static inline void mk_test_sqlfile(const char* sch_name, char* sql_file)
{
    /* bindir/inputdir/[*.sql] */
    memset(sql_file, 0, MAX_FILE_LEN);
    int len = sprintf(sql_file, "%s%s.sql",
        g_opts[OPT_INPUTDIR].value,
        sch_name
    );
    if (len <= 0 || len >= MAX_FILE_LEN)
    {
        fprintf(stderr, "The script file name is too long: [%s]\n", sch_name);
        exit(-1);
    }
}

static inline void mk_test_outfile(const char* sch_name, char* out_file)
{
    /* outputdir/[*.out] */
    memset(out_file, 0, MAX_FILE_LEN);
    int len = sprintf(out_file, "%s%s.out",
        g_opts[OPT_OUTPUTDIR].value,
        sch_name
    );
    if (len <= 0 || len >= MAX_FILE_LEN)
    {
        fprintf(stderr, "The output file name is too long: [%s]\n", sch_name);
        exit(-1);
    }
}

static inline void mk_test_expectedfile(const char* sch_name, char* expected_file)
{
    /* bindir/expected/[*.out] */
    memset(expected_file, 0, MAX_FILE_LEN);
    int len = sprintf(expected_file, "%s%s.out",
        g_opts[OPT_EXPECTDIR].value,
        sch_name
    );
    if (len <= 0 || len >= MAX_FILE_LEN)
    {
        fprintf(stderr, "The output file name is too long: [%s]\n", sch_name);
        exit(-1);
    }
}

/*
* Add an item at the end of a file_list_t.
*/
static void prepare_test_group(text_t *line, int line_no, test_type_t ttyp)
{
    text_t  name;
    g_cases.num = 0;
    g_cases.t_typ = ttyp;

    while (cm_fetch_text(line, ' ', '\0', &name))
    {
        cm_trim_text(&name);
        if (CM_IS_EMPTY(&name))
        {
            continue;
        }
        if (name.len >= MAX_TEST_NAME_LEN)
        {
            CM_NULL_TERM(&name);
            fprintf(stderr, "The test case name is too long: %s, line: %d \n", name.str, line_no);
            exit(-1);
        }

        cm_text2str(&name, g_cases.tests[g_cases.num].name, MAX_TEST_NAME_LEN);
        g_cases.num++;
        if (g_cases.num > MAX_PARALLEL_TESTS)
        {
            fprintf(stderr, "Too many parallel tests in schedule file \"%s:%d\" \n", g_opts[OPT_SCHEDULE].value, line_no);
            exit(-1);
        }
        cm_trim_text(line);
    }
}

static PID_TYPE ctsql_exec_test(const char* conn_str, gtest_t* test, test_type_t ttyp)
{
    char  ctsql_cmd[MAX_FILE_LEN * 4];
    char  log_file[MAX_FILE_LEN];
    PID_TYPE	pid;

    mk_test_sqlfile(test->name, test->sqlfile);
    mk_test_outfile(test->name, test->outfile);
    mk_test_expectedfile(test->name, test->expfile);

    (void)sprintf_s(log_file, MAX_FILE_LEN, "%s.log", test->outfile);

    if (ttyp == TT_INTERACT)
    {
        sprintf(ctsql_cmd, "%s < %s > %s",
            conn_str,
            test->sqlfile,
            log_file
        );
    } else
    {
        sprintf(ctsql_cmd, "%s -c \"spool %s; @%s; spool off;\" > %s",
            conn_str,
            test->outfile,
            test->sqlfile,
            log_file
        );
    }

    // sprintf(ctsql_cmd, "%s < %s > %s", g_conn_str, REGRESS_TMP_FILE, log_file);

    test->begin_time = cm_now();
    pid = spawn_process(ctsql_cmd);

    if (pid == INVALID_PID)
    {
        fprintf(stderr, "Could not start process for test %s\n",
            test->name);
        exit(2);
    }

    return pid;
}

static void exec_test_group(int line_no)
{
    uint32 i;

    if (g_cases.num < 1)
    {
        fprintf(stderr, "Syntax error in schedule file \"%s\" line %d\n",
            g_opts[OPT_SCHEDULE].value, line_no);
        exit(-1);
    }
    if (g_cases.num == 1)
    {
        g_cases.pids[0] = ctsql_exec_test(g_conn_str, &g_cases.tests[0], g_cases.t_typ);
        wait_for_tests(0, 1);
        return;
    }

    if (g_cases.num <= g_opts[OPT_MAX_CONN].ival)
    {
        gr_printf("Parallel group (%d tests):", g_cases.num);
        for (i = 0; i < g_cases.num; i++)
        {
            g_cases.pids[i] = ctsql_exec_test(g_conn_str, &g_cases.tests[i], g_cases.t_typ);
            gr_printf(" %s", g_cases.tests[i].name);
        }
        wait_for_tests(0, g_cases.num);
        gr_printf("\n");
        return;
    }
    else
    {
        int			oldest = 0;
        gr_printf("Parallel group (%d tests, in groups of %d): ", g_cases.num, g_opts[OPT_MAX_CONN].ival);
        for (i = 0; i < g_cases.num; i++)
        {
            if (i - oldest >= g_opts[OPT_MAX_CONN].ival)
            {
                wait_for_tests(oldest, i - oldest);
                oldest = i;
            }
            g_cases.pids[i] = ctsql_exec_test(g_conn_str, &g_cases.tests[i], g_cases.t_typ);
            gr_printf(" %s", g_cases.tests[i].name);
        }
        wait_for_tests(oldest, i - oldest);
        gr_printf("\n");
    }
}

#define _(x) (x)
static void help()
{
    printf(_("CantianKernel regression test driver\n"));
    printf(_("\n"));
    printf(_("Usage:\n  %s [OPTION]... [EXTRA-TEST]...\n"), "ct_regress");
    printf(_("\n"));
    printf(_("Options:\n"));
    printf(_("  --bindir=DIR              the DIR of ctsql.exe (default \""BINDIR"\")\n"));
    printf(_("  --inputdir=DIR            take input files from DIR (default \""INPUTDIR"\")\n"));
    printf(_("  --outputdir=DIR           place output files in DIR (default \""OUTPUTDIR"\")\n"));
    printf(_("  --expectdir=DIR           place output files in DIR (default \""EXPECTDIR"\")\n"));
    printf(_("  --schedule=FILE           use test ordering schedule from FILE\n"));
    printf(_("Options for using an existing installation:\n"));
    printf(_("  --host=HOST               use postmaster running on HOST (default \""HOST"\")\n"));
    printf(_("  --port=PORT               use postmaster running at PORT (default \""PORT"\")\n"));
    printf(_("  --user=USER               connect as USER (default \""DB_USER"\")\n"));
    printf(_("  --max_conns=int           maximal connections for parallel test (default %d)\n"), DEFLT_CONNS);

    printf(_("\n"));
    printf(_("Format of schedule file:\n"));
    printf(_("  test: test_case_name -- normal testing\n"));
    printf(_("  test: case1 case2 case3 -- parallel testing\n"));
    printf(_("  interact:  test_case_name -- testing with some interacting input\n"));
    printf(_("\n"));
}

static void set_opts(int argc, char* argv[], option_t* opts)
{
    int i, j;
    size_t name_len;
    char* opt_str;

    progname = argv[0];
    for(i=1; i<argc; i++)
    {
        opt_str = argv[i];
        name_len = strcspn(opt_str, "=");
        for (j = 0; opts[j].name != NULL; j++)
        {
            if (strlen(opts[j].name) == name_len && strncmp(opt_str, opts[j].name, name_len) == 0)
            {
                switch (opts[j].flag)
                {
                case OPT_HELP:
                case OPT_UNKNOWN:
                    help(); exit(0);
                    break;

                case OPT_MAX_CONN:
                {
                    text_t  numtext;
                    cm_str2text(opt_str + name_len + 1, &numtext);
                    if (cm_text2uint32_ex(&numtext, &opts[j].ival) != NERR_SUCCESS)
                    {
                        fprintf(stderr, "The MAX_CONNS must be an unsigned integer\n");
                        exit(-1);
                    }
                    if (opts[j].ival > MAX_PARALLEL_TESTS)
                    {
                        fprintf(stderr, "MAX_CONNS can not exceeds %d\n", MAX_PARALLEL_TESTS);
                        exit(-1);
                    }
                    break;
                }
                default:
                    opts[j].value = opt_str + name_len + 1;
                    break;
                }
            }
        }
    }
}

static void print_opts(const option_t* opts, int sz)
{
    printf("The options for regress: \n");
    for (int i=0; i<sz; i++)
    {
        if (NULL != opts[i].value)
        {
            switch (opts[i].flag)
            {
            case OPT_MAX_CONN:
                gr_printf("% 12s : %u\n", opts[i].name + 2, opts[i].ival);
                break;
            default:
                gr_printf("% 12s : %s\n", opts[i].name + 2, opts[i].value);
                break;
            }
        }
    }
}


static void parse_param(int argc, char * argv[])
{
    set_opts(argc, argv, g_opts);
    print_opts(g_opts, sizeof(g_opts)/sizeof(option_t));
}

static void diff_test_group();
static void wait_for_tests(int pos, int num_tests);

static test_type_t get_test_type(text_t* txt)
{
    static const text_t  tt_cat = {.str = "INTERACT", .len = 8};

    cm_trim_text(txt);
    if (cm_text_equal_ins(txt, &tt_cat))
    {
        return TT_INTERACT;
    }

    return TT_NORMAL;
}

static void read_schedule(const char* sch_file)
{
    char buf[MAX_FILE_LEN*3];
    text_t line;
    text_t head;
    FILE* file_hdl;
    int line_no;

    if ((file_hdl = fopen(sch_file, "r")) == NULL)
    {
        fprintf(stderr, "Failed to open schedule file: %s \n", sch_file);
        exit(-1);
    }

    printf("Schedule list: \n");
    line_no = 0;
    while (fgets(buf, sizeof(buf), file_hdl) != NULL)
    {
        line_no++;
        buf[strcspn(buf, "\r\n")] = 0;
        line.str = buf;
        line.len = (uint32)strlen(buf);

        cm_trim_text(&line);
        if (CM_IS_EMPTY(&line))
        {
            continue;
        }
        // remove head (`test: `) and space
        uint32 pos = (uint32)strcspn(line.str, ":") + 1;

        head.str = line.str;
        head.len = pos - 1;

        line.str += pos;
        line.len -= pos;
        cm_trim_text(&line);

        if (line.len <= 0) /* read blank line */
        {
            continue;
        }
        prepare_test_group(&line, line_no, get_test_type(&head));
        exec_test_group(line_no);
        diff_test_group();
    }
    fclose(file_hdl);
    gr_printf("\nSummary: \n");
    gr_printf("    %d test(s) passed, %d test(s) failed. \n", g_success_count, g_fail_count);
    if (g_fail_count > 0)
    {
        gr_printf("Result:  FAILED \n");
    }
    gr_printf("\n");
}


#ifdef WIN32
typedef BOOL(WINAPI * __CreateRestrictedToken) (HANDLE, DWORD, DWORD, PSID_AND_ATTRIBUTES, DWORD, PLUID_AND_ATTRIBUTES, DWORD, PSID_AND_ATTRIBUTES, PHANDLE);

/* Windows API define missing from some versions of MingW headers */
#ifndef  DISABLE_MAX_PRIVILEGE
#define DISABLE_MAX_PRIVILEGE	0x1
#endif

/*
* GetTokenUser(HANDLE hToken, PTOKEN_USER *ppTokenUser)
*
* Get the users token information from a process token.
*
* The caller of this function is responsible for calling LocalFree() on the
* returned TOKEN_USER memory.
*/
static BOOL
GetTokenUser(HANDLE hToken, PTOKEN_USER *ppTokenUser)
{
    DWORD		dwLength;

    *ppTokenUser = NULL;

    if (!GetTokenInformation(hToken,
        TokenUser,
        NULL,
        0,
        &dwLength))
    {
        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
        {
            *ppTokenUser = (PTOKEN_USER)LocalAlloc(LPTR, dwLength);

            if (*ppTokenUser == NULL)
            {
                gr_printf("Could not allocate %lu bytes of memory", dwLength);
                return FALSE;
            }
        }
        else
        {
            gr_printf("Could not get token information buffer size: error code %lu", GetLastError());
            return FALSE;
        }
    }

    if (!GetTokenInformation(hToken,
        TokenUser,
        *ppTokenUser,
        dwLength,
        &dwLength))
    {
        LocalFree(*ppTokenUser);
        *ppTokenUser = NULL;

        gr_printf("Could not get token information: error code %lu", GetLastError());
        return FALSE;
    }

    /* Memory in *ppTokenUser is LocalFree():d by the caller */
    return TRUE;
}

/*
* AddUserToTokenDacl(HANDLE hToken)
*
* This function adds the current user account to the restricted
* token used when we create a restricted process.
*
* This is required because of some security changes in Windows
* that appeared in patches to XP/2K3 and in Vista/2008.
*
* On these machines, the Administrator account is not included in
* the default DACL - you just get Administrators + System. For
* regular users you get User + System. Because we strip Administrators
* when we create the restricted token, we are left with only System
* in the DACL which leads to access denied errors for later CreatePipe()
* and CreateProcess() calls when running as Administrator.
*
* This function fixes this problem by modifying the DACL of the
* token the process will use, and explicitly re-adding the current
* user account.  This is still secure because the Administrator account
* inherits its privileges from the Administrators group - it doesn't
* have any of its own.
*/
BOOL
AddUserToTokenDacl(HANDLE hToken)
{
    int			i;
    ACL_SIZE_INFORMATION asi;
    ACCESS_ALLOWED_ACE *pace;
    DWORD		dwNewAclSize;
    DWORD		dwSize = 0;
    DWORD		dwTokenInfoLength = 0;
    PACL		pacl = NULL;
    PTOKEN_USER pTokenUser = NULL;
    TOKEN_DEFAULT_DACL tddNew;
    TOKEN_DEFAULT_DACL *ptdd = NULL;
    TOKEN_INFORMATION_CLASS tic = TokenDefaultDacl;
    BOOL		ret = FALSE;

    /* Figure out the buffer size for the DACL info */
    if (!GetTokenInformation(hToken, tic, (LPVOID)NULL, dwTokenInfoLength, &dwSize))
    {
        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
        {
            ptdd = (TOKEN_DEFAULT_DACL *)LocalAlloc(LPTR, dwSize);
            if (ptdd == NULL)
            {
                gr_printf("Could not allocate %lu bytes of memory", dwSize);
                goto cleanup;
            }

            if (!GetTokenInformation(hToken, tic, (LPVOID)ptdd, dwSize, &dwSize))
            {
                gr_printf("Could not get token information: error code %lu", GetLastError());
                goto cleanup;
            }
        }
        else
        {
            gr_printf("Could not get token information buffer size: error code %lu", GetLastError());
            goto cleanup;
        }
    }

    /* Get the ACL info */
    if (!GetAclInformation(ptdd->DefaultDacl, (LPVOID)&asi,
        (DWORD) sizeof(ACL_SIZE_INFORMATION),
        AclSizeInformation))
    {
        gr_printf("Could not get ACL information: error code %lu", GetLastError());
        goto cleanup;
    }

    /* Get the current user SID */
    if (!GetTokenUser(hToken, &pTokenUser))
        goto cleanup;			/* callee printed a message */

                                /* Figure out the size of the new ACL */
    dwNewAclSize = asi.AclBytesInUse + sizeof(ACCESS_ALLOWED_ACE) +
        GetLengthSid(pTokenUser->User.Sid) - sizeof(DWORD);

    /* Allocate the ACL buffer & initialize it */
    pacl = (PACL)LocalAlloc(LPTR, dwNewAclSize);
    if (pacl == NULL)
    {
        gr_printf("Could not allocate %lu bytes of memory", dwNewAclSize);
        goto cleanup;
    }

    if (!InitializeAcl(pacl, dwNewAclSize, ACL_REVISION))
    {
        gr_printf("Could not initialize ACL: error code %lu", GetLastError());
        goto cleanup;
    }

    /* Loop through the existing ACEs, and build the new ACL */
    for (i = 0; i < (int)asi.AceCount; i++)
    {
        if (!GetAce(ptdd->DefaultDacl, i, (LPVOID *)&pace))
        {
            gr_printf("Could not get ACE: error code %lu", GetLastError());
            goto cleanup;
        }

        if (!AddAce(pacl, ACL_REVISION, MAXDWORD, pace, ((PACE_HEADER)pace)->AceSize))
        {
            gr_printf("Could not add ACE: error code %lu", GetLastError());
            goto cleanup;
        }
    }

    /* Add the new ACE for the current user */
    if (!AddAccessAllowedAceEx(pacl, ACL_REVISION, OBJECT_INHERIT_ACE, GENERIC_ALL, pTokenUser->User.Sid))
    {
        gr_printf("Could not add access allowed ACE: error code %lu", GetLastError());
        goto cleanup;
    }

    /* Set the new DACL in the token */
    tddNew.DefaultDacl = pacl;

    if (!SetTokenInformation(hToken, tic, (LPVOID)&tddNew, dwNewAclSize))
    {
        gr_printf("Could not set token information: error code %lu", GetLastError());
        goto cleanup;
    }

    ret = TRUE;

cleanup:
    if (pTokenUser)
        LocalFree((HLOCAL)pTokenUser);

    if (pacl)
        LocalFree((HLOCAL)pacl);

    if (ptdd)
        LocalFree((HLOCAL)ptdd);

    return ret;
}

/*
* Create a restricted token and execute the specified process with it.
*
* Returns restricted token on success and 0 on failure.
*
* On NT4, or any other system not containing the required functions, will
* NOT execute anything.
*/
HANDLE
CreateRestrictedProcess(char *cmd, PROCESS_INFORMATION *processInfo, const char *progname)
{
    BOOL		b;
    STARTUPINFO si;
    HANDLE		origToken;
    HANDLE		restrictedToken;
    SID_IDENTIFIER_AUTHORITY NtAuthority = { SECURITY_NT_AUTHORITY };
    SID_AND_ATTRIBUTES dropSids[2];
    __CreateRestrictedToken _CreateRestrictedToken = NULL;
    HANDLE		Advapi32Handle;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);

    Advapi32Handle = LoadLibrary("ADVAPI32.DLL");
    if (Advapi32Handle != NULL)
    {
        _CreateRestrictedToken = (__CreateRestrictedToken)GetProcAddress(Advapi32Handle, "CreateRestrictedToken");
    }

    if (_CreateRestrictedToken == NULL)
    {
        fprintf(stderr, _("%s: WARNING: cannot create restricted tokens on this platform\n"), progname);
        if (Advapi32Handle != NULL)
            FreeLibrary(Advapi32Handle);
        return 0;
    }

    /* Open the current token to use as a base for the restricted one */
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &origToken))
    {
        fprintf(stderr, _("%s: could not open process token: error code %lu\n"), progname, GetLastError());
        return 0;
    }

    /* Allocate list of SIDs to remove */
    ZeroMemory(&dropSids, sizeof(dropSids));
    if (!AllocateAndInitializeSid(&NtAuthority, 2,
        SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0,
        0, &dropSids[0].Sid) ||
        !AllocateAndInitializeSid(&NtAuthority, 2,
            SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_POWER_USERS, 0, 0, 0, 0, 0,
            0, &dropSids[1].Sid))
    {
        fprintf(stderr, _("%s: could not allocate SIDs: error code %lu\n"),
            progname, GetLastError());
        return 0;
    }

    b = _CreateRestrictedToken(origToken,
        DISABLE_MAX_PRIVILEGE,
        sizeof(dropSids) / sizeof(dropSids[0]),
        dropSids,
        0, NULL,
        0, NULL,
        &restrictedToken);

    FreeSid(dropSids[1].Sid);
    FreeSid(dropSids[0].Sid);
    CloseHandle(origToken);
    FreeLibrary(Advapi32Handle);

    if (!b)
    {
        fprintf(stderr, _("%s: could not create restricted token: error code %lu\n"),
            progname, GetLastError());
        return 0;
    }

#ifndef __CYGWIN__
    AddUserToTokenDacl(restrictedToken);
#endif

    if (!CreateProcessAsUser(restrictedToken,
        NULL,
        cmd,
        NULL,
        NULL,
        TRUE,
        CREATE_SUSPENDED,
        NULL,
        NULL,
        &si,
        processInfo))

    {
        fprintf(stderr, _("%s: could not start process for command \"%s\": error code %lu\n"), progname, cmd, GetLastError());
        return 0;
    }

    ResumeThread(processInfo->hThread);
    return restrictedToken;
}
#endif



/*
* Spawn a process to execute the given shell command; don't wait for it
*
* Returns the process ID (or HANDLE) so we can wait for it later
*/
PID_TYPE
spawn_process(const char *cmdline)
{
    char  proc_cmd[MAX_FILE_LEN * 4] = {0};
#ifndef WIN32
    pid_t		pid;

    /*
    * Must flush I/O buffers before fork.  Ideally we'd use fflush(NULL) here
    * ... does anyone still care about systems where that doesn't work?
    */
    fflush(stdout);
    fflush(stderr);

    pid = fork();
    if (pid == -1)
    {
        fprintf(stderr, "%s: could not fork: %s\n", progname, strerror(errno));
        exit(2);
    }
    if (pid == 0)
    {
        /*
        * In child
        *
        * Instead of using system(), exec the shell directly, and tell it to
        * "exec" the command too.  This saves two useless processes per
        * parallel test case.
        */
        
        snprintf(proc_cmd, sizeof(proc_cmd), "exec %s", cmdline);
        execl(shellprog, shellprog, "-c", proc_cmd, (char *)NULL);
        fprintf(stderr, "%s: could not exec \"%s\": %s\n",
            progname, shellprog, strerror(errno));
        _exit(1);				/* not exit() here... */
    }
    /* in parent */
    return pid;
#else
    PROCESS_INFORMATION pi;
    STARTUPINFO  si;
    DWORD       ret;
    const char * shell_name;

    shell_name = getenv("COMSPEC");
    if (NULL == shell_name)
    {
        shell_name = "cmd.exe";
    }

    memset(&pi, 0, sizeof(pi));
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    snprintf(proc_cmd, sizeof(proc_cmd), "/c %s", cmdline);

    if (!CreateProcess(shell_name, proc_cmd,
        NULL,
        NULL,
        TRUE,
        CREATE_SUSPENDED,
        NULL,
        NULL,
        &si,
        &pi))
    {
        fprintf(stderr, "%s: could not start process for command \"%s\": error code %lu\n", progname, proc_cmd, GetLastError());
        return INVALID_PID;
    }

    do
    {
        ret = ResumeThread(pi.hThread);
    } while (ret != 0);

    CloseHandle(pi.hThread);
    return pi.hProcess;
#endif
}


static long file_size(const char *file)
{
    long		r;
    FILE	   *f = fopen(file, "r");

    if (!f)
    {
        fprintf(stderr, "could not open file \"%s\" for reading: %s\n", file, strerror(errno));
        return -1;
    }
    fseek(f, 0, SEEK_END);
    r = ftell(f);
    fclose(f);
    return r;
}

#ifndef WIFEXITED
#define WIFEXITED(w)	(((w) & 0XFFFFFF00) == 0)
#define WIFSIGNALED(w)	(!WIFEXITED(w))
#define WEXITSTATUS(w)	(w)
#define WTERMSIG(w)		(w)
#endif // WIFEXITED

/*
* Run a "diff" command and also check that it didn't crash
*/
static int is_diff(const char* diff_cmd, const char* diff_file)
{
    int r;

    r = system(diff_cmd);
    if (!WIFEXITED(r) || WEXITSTATUS(r) > 1)
    {
        // fprintf(stderr, "diff command failed with status %d: %s\n", r, diff_cmd);
        return 2;
    }
#ifdef WIN32
    /*
    * On WIN32, if the 'diff' command cannot be found, system() returns 1,
    * but produces nothing to stdout, so we check for that here.
    */
    if (WEXITSTATUS(r) == 1 && file_size(diff_file) <= 0)
    {
        fprintf(stderr, "diff command not found: %s\n", diff_cmd);
        return 2;
    }
#endif

    return WEXITSTATUS(r);
}
/* diff a single schedule by comparing result_file and expected_file. If there are
 * same, return CT_TRUE, else return CT_FALSE. */
static bool32 diff_single_schedule(const char* sch_name, const char* result_file, const char* expected_file)
{
    char diff_cmd[MAX_FILE_LEN * 3];
    char diff_file[MAX_FILE_LEN];
    char log_file[MAX_FILE_LEN];

    /* Name to use for temporary diff file */
    snprintf(diff_file, sizeof(diff_file), "%s.diff", result_file);

    /* OK, run the diff */
    snprintf(diff_cmd, sizeof(diff_cmd),
        "diff %s \"%s\" \"%s\" > \"%s\"",
        basic_diff_opts, expected_file, result_file, diff_file);

    /* Two files are same */
    if (is_diff(diff_cmd, diff_file) == 0)
    {
        cm_remove_file(diff_file);

        snprintf(log_file, MAX_FILE_LEN, "%s.log", result_file);
        cm_remove_file(log_file);
        return CT_TRUE;
    }
    else
    {
        return CT_FALSE;
    }
}

static void diff_test_group()
{
    for (uint32 i = 0; i < g_cases.num; i++)
    {
        date_t elapsed = g_cases.tests[i].end_time - g_cases.tests[i].begin_time;

        gr_printf(" [%c]      %-24s:  ", g_ttyp_flag[g_cases.t_typ], g_cases.tests[i].name);
        if (diff_single_schedule(g_cases.tests[i].name, 
            g_cases.tests[i].outfile,
            g_cases.tests[i].expfile) == CT_TRUE)
        {
            gr_printf("OK      Elapsed: %0.3f sec\n", (double)elapsed / (1000 * 1000));
            g_success_count++;
        }
        else
        {
            gr_printf("FAILED  Elapsed: %0.3f sec\n", (double)elapsed / (1000 * 1000));
            g_fail_count++;
        }
    }
    if (g_cases.num > 1)
    {
        gr_printf("\n");
    }
}


EXTER_ATTACK int main(int argc, char * argv[])
{
    char buf[MAX_FILE_LEN];

    gr_printf("The working PATH is: %s \n", getcwd(buf, MAX_FILE_LEN));

#ifndef WIN32
    shellprog = getenv("SHELL");
    if (NULL == shellprog)
    {
        shellprog = DEFAULT_SHELL;
    }
#endif

    // Step 1. Parse parameters from command
    parse_param(argc, argv);

    // Step 1.5: Make connection str
    snprintf(g_conn_str, MAX_FILE_LEN, "%s %s@%s:%s", /* user@host:port, user=username/password */
        g_opts[OPT_BINDIR].value,
        g_opts[OPT_USER].value,
        g_opts[OPT_HOST].value,
        g_opts[OPT_PORT].value
    );

    // Step 2. Read and make schedule from schedule file
    read_schedule(g_opts[OPT_SCHEDULE].value);

    return 0;
}
