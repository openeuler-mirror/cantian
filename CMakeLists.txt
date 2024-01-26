cmake_minimum_required(VERSION 3.14.1)

project(CantianDB)

include(
        "${PROJECT_SOURCE_DIR}/build/cmake_include/CMakeListsInclude.txt"
)

include_directories(
        "${PROJECT_SOURCE_DIR}/build/include"

        "${PROJECT_SOURCE_DIR}/open_source/libaio/include"
        "${PROJECT_SOURCE_DIR}/open_source/lz4/include"
        "${PROJECT_SOURCE_DIR}/open_source/odbc/include"
        "${PROJECT_SOURCE_DIR}/open_source/openssl/include/openssl"
        "${PROJECT_SOURCE_DIR}/open_source/openssl/include"
        "${PROJECT_SOURCE_DIR}/open_source/pcre/include"
        "${PROJECT_SOURCE_DIR}/open_source/zlib/include"
        "${PROJECT_SOURCE_DIR}/open_source/Zstandard/include"

        "${PROJECT_SOURCE_DIR}/platform/huawei_security/include"
        "${PROJECT_SOURCE_DIR}/library/kmc"

        "${PROJECT_SOURCE_DIR}/build_dependence/unixODBC/include"
        "${PROJECT_SOURCE_DIR}/build_dependence/libaio/include" 

        "${PROJECT_SOURCE_DIR}/pkg/src/common/variant"
        "${PROJECT_SOURCE_DIR}/pkg/src/common"
        "${PROJECT_SOURCE_DIR}/pkg/src/driver"
        "${PROJECT_SOURCE_DIR}/pkg/src/driver/ctconn"
        "${PROJECT_SOURCE_DIR}/pkg/src/driver/odbc"
        "${PROJECT_SOURCE_DIR}/pkg/src/protocol"
        "${PROJECT_SOURCE_DIR}/pkg/src/server"
        "${PROJECT_SOURCE_DIR}/pkg/src/server/params"
        "${PROJECT_SOURCE_DIR}/pkg/src/shard"
        "${PROJECT_SOURCE_DIR}/pkg/src/shard/rebalance"
        "${PROJECT_SOURCE_DIR}/pkg/src/shard/ddl"
        "${PROJECT_SOURCE_DIR}/pkg/src/shard/dml"
        "${PROJECT_SOURCE_DIR}/pkg/src/shard/route"
        "${PROJECT_SOURCE_DIR}/pkg/src/shard/adapter"
        "${PROJECT_SOURCE_DIR}/pkg/src/shard/dblink"
        "${PROJECT_SOURCE_DIR}/pkg/src/ctsql"
        "${PROJECT_SOURCE_DIR}/pkg/src/ctsql/catalog"
        "${PROJECT_SOURCE_DIR}/pkg/src/ctsql/executor"
        "${PROJECT_SOURCE_DIR}/pkg/src/ctsql/json"
        "${PROJECT_SOURCE_DIR}/pkg/src/ctsql/node"
        "${PROJECT_SOURCE_DIR}/pkg/src/ctsql/function"
        "${PROJECT_SOURCE_DIR}/pkg/src/ctsql/optimizer"
        "${PROJECT_SOURCE_DIR}/pkg/src/ctsql/parallel"
        "${PROJECT_SOURCE_DIR}/pkg/src/ctsql/parser"
        "${PROJECT_SOURCE_DIR}/pkg/src/ctsql/parser_ddl"
        "${PROJECT_SOURCE_DIR}/pkg/src/ctsql/plan"
        "${PROJECT_SOURCE_DIR}/pkg/src/ctsql/pl"
        "${PROJECT_SOURCE_DIR}/pkg/src/ctsql/pl/include"
        "${PROJECT_SOURCE_DIR}/pkg/src/ctsql/pl/clang"
        "${PROJECT_SOURCE_DIR}/pkg/src/ctsql/pl/debug"
        "${PROJECT_SOURCE_DIR}/pkg/src/ctsql/pl/meta"
        "${PROJECT_SOURCE_DIR}/pkg/src/ctsql/pl/persist"
        "${PROJECT_SOURCE_DIR}/pkg/src/ctsql/pl/type"
        "${PROJECT_SOURCE_DIR}/pkg/src/ctsql/pl/ast"
        "${PROJECT_SOURCE_DIR}/pkg/src/ctsql/pl/parser"
        "${PROJECT_SOURCE_DIR}/pkg/src/ctsql/pl/common"
        "${PROJECT_SOURCE_DIR}/pkg/src/ctsql/pl/executor"
        "${PROJECT_SOURCE_DIR}/pkg/src/ctsql/verifier"

        "${PROJECT_SOURCE_DIR}/pkg/src/kernel"
        "${PROJECT_SOURCE_DIR}/pkg/src/kernel/backup"
        "${PROJECT_SOURCE_DIR}/pkg/src/kernel/buffer"
        "${PROJECT_SOURCE_DIR}/pkg/src/kernel/catalog"
        "${PROJECT_SOURCE_DIR}/pkg/src/kernel/common"
        "${PROJECT_SOURCE_DIR}/pkg/src/kernel/daemon"
        "${PROJECT_SOURCE_DIR}/pkg/src/kernel/flashback"
        "${PROJECT_SOURCE_DIR}/pkg/src/kernel/include"
        "${PROJECT_SOURCE_DIR}/pkg/src/kernel/index"
        "${PROJECT_SOURCE_DIR}/pkg/src/kernel/lob"
        "${PROJECT_SOURCE_DIR}/pkg/src/kernel/persist"
        "${PROJECT_SOURCE_DIR}/pkg/src/kernel/replication"
        "${PROJECT_SOURCE_DIR}/pkg/src/kernel/sequence"
        "${PROJECT_SOURCE_DIR}/pkg/src/kernel/statistics"
        "${PROJECT_SOURCE_DIR}/pkg/src/kernel/table"
        "${PROJECT_SOURCE_DIR}/pkg/src/kernel/tablespace"
        "${PROJECT_SOURCE_DIR}/pkg/src/kernel/xact"

        "${PROJECT_SOURCE_DIR}/pkg/src/utils"
        "${PROJECT_SOURCE_DIR}/pkg/src/utils/gspe"
        "${PROJECT_SOURCE_DIR}/pkg/src/utils/ctsql"
        "${PROJECT_SOURCE_DIR}/pkg/src/utils/ctbackup"
        "${PROJECT_SOURCE_DIR}/pkg/src/ctbox"
        "${PROJECT_SOURCE_DIR}/pkg/src/ztrst"
        "${PROJECT_SOURCE_DIR}/pkg/src/gbp"
        "${PROJECT_SOURCE_DIR}/pkg/src/extproc"
        "${PROJECT_SOURCE_DIR}/pkg/src/ctsql/pl/include"
        "${PROJECT_SOURCE_DIR}/pkg/src/mec"
        "${PROJECT_SOURCE_DIR}/pkg/src/tse"
        "${PROJECT_SOURCE_DIR}/library/xnet/include"
        "${PROJECT_SOURCE_DIR}/library/xnet/include/vos_win/vos"
        "${PROJECT_SOURCE_DIR}/library/xnet/include/infrastructure"
)

if (UNIX)
    execute_process(
            COMMAND uname -p
            OUTPUT_VARIABLE OS_ARCH
            OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    if (OS_ARCH STREQUAL "x86_64")
        set(CMAKE_C_COMPILER "/usr/local/bin/gcc")
        set(CMAKE_CXX_COMPILER "/usr/local/bin/g++")
    endif()

    message(${CMAKE_BUILD_TYPE})
    if (${CMAKE_BUILD_TYPE} STREQUAL "Debug"
            OR ${CMAKE_BUILD_TYPE} STREQUAL "")
        message(STATUS "CMAKE_BUILD_TYPE is Debug")
        set(CMAKE_BUILD_TYPE Debug)
        add_compile_definitions(_DEBUG)
    elseif (${CMAKE_BUILD_TYPE} STREQUAL "Release")
        message(STATUS "CMAKE_BUILD_TYPE is Release")
        set(CMAKE_BUILD_TYPE Release)
        set(CMAKE_CXX_FLAGS_RELEASE "-O2 -DNDEBUG")
    else ()
        message(STATUS "unknown CMAKE_BUILD_TYPE = " ${CMAKE_BUILD_TYPE})
    endif ()

    # Use "-fPIC" / "-fPIE" for all targets by default, including static libs
    set(CMAKE_POSITION_INDEPENDENT_CODE ON)
    # CMake doesn't add "-pie" by default for executables
    add_link_options(-pie)

    execute_process(
            COMMAND uname -p
            OUTPUT_VARIABLE OS_ARCH
            OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    set(CMAKE_SYSTEM_PROCESSOR ${OS_ARCH})

    if (OS_ARCH STREQUAL "aarch64")
        message(STATUS "aarch64 CPU")
        option(USE_H1620 OFF)
        if (USE_H1620)
            add_compile_options(-march=armv8-a+crc+lse)
            message(STATUS "Toolchain: Build aarch64 USE_H1620")
        else ()
            add_compile_options(-march=armv8-a+crc)
        endif (USE_H1620)

        add_compile_options(-mtune=cortex-a72 -fsigned-char -g -ggdb3 -march=armv8-a+crc -funwind-tables)
    else ()
        message(STATUS "x86_64 CPU")
        add_compile_options(-mtune=nocona -fsigned-char -msse4.2 )
    endif ()
else ()
    set(CMAKE_BUILD_TYPE Debug)
    add_compile_definitions(_DEBUG)
endif ()

option(USE32BIT OFF)
if (USE32BIT)
    add_compile_options(-m32)
    set(CLI_BIT "32")
    message(STATUS "Toolchain: Build in 32 bits")
else ()
    message(STATUS "Toolchain: Build in 64 bits")
endif (USE32BIT)

if ("${CMAKE_SIZEOF_VOID_P}" EQUAL "8")
    message("++ 64 bit architecture")
    set(ARCHBIT "64")
else ()
    message("++ 32 bit architecture")
    set(ARCHBIT "32")
    add_compile_options(-m32)
endif ()

## BUILD OPT
option(USE_CBOTEST OFF)
if (USE_CBOTEST)
    add_compile_definitions(TEST_CBO)
    message(STATUS "Toolchain: Build use -DTEST_CBO")
endif (USE_CBOTEST)

option(USE_PROTECT_BUF OFF)
if (USE_PROTECT_BUF)
    add_compile_definitions(__PROTECT_BUF__)
    message(STATUS "Toolchain: Build use -D__PROTECT_BUF__")
endif (USE_PROTECT_BUF)

option(USE_PROTECT_VM OFF)
if (USE_PROTECT_VM)
    add_compile_definitions(__PROTECT_VM__)
    message(STATUS "Toolchain: Build use -D__PROTECT_VM__")
endif (USE_PROTECT_VM)

option(USE_CANTIAND_CN OFF)
if (USE_CANTIAND_CN)
    add_compile_definitions(__CANTIAND_CN__)
    message(STATUS "Toolchain: Build use -D__CANTIAND_CN__")
endif (USE_CANTIAND_CN)

option(USE_TEST_MEM OFF)
if (USE_TEST_MEM)
    add_compile_definitions(TEST_MEM)
    message(STATUS "Toolchain: Build use -DTEST_MEM")
endif (USE_TEST_MEM)

option(CMS_UT_TEST OFF)
if (CMS_UT_TEST)
    add_compile_definitions(CMS_UT_TEST)
    message(STATUS "Toolchain: Build use -DCMS_UT_TEST")
endif (CMS_UT_TEST)

option(USE_CRC OFF)
if (USE_CRC)
    add_compile_definitions(_DEBUG)
    add_compile_definitions(DB_CRC_CHECK)
    message(STATUS "Toolchain: Build use -DDB_DEBUG_VERSION -DDB_CRC_CHECK")
endif (USE_CRC)

option(USE_LCOV OFF)
if (USE_LCOV)
    add_compile_options(-fprofile-arcs -ftest-coverage)
    add_link_options(-fprofile-arcs -ftest-coverage)
    add_compile_definitions(_CMS_LCOV_TEST_)
    add_compile_definitions(_CANTIAN_LCOV_TEST_)
    message(STATUS "Toolchain: Build use -DBUILD_LCOV")
endif (USE_LCOV)

option(USE_LLT OFF)
if (USE_LLT)
    add_compile_definitions(_DEBUG)
    message(STATUS "Toolchain: Build use -DDB_DEBUG_VERSION ")
endif (USE_LLT)

option(USE_ASAN OFF)
if (USE_ASAN)
    add_compile_options(-fsanitize=address -fsanitize-recover=address -fsanitize=undefined -fsanitize-recover=undefined  -ggdb -fno-omit-frame-pointer -fno-optimize-sibling-calls)
    add_link_options(-fsanitize=address -fsanitize-recover=address -fsanitize=undefined -fsanitize-recover=undefined  -ggdb -fno-omit-frame-pointer -fno-optimize-sibling-calls)
    message(STATUS "Toolchain: Build with ASAN TEST Configure")
endif (USE_ASAN)

option(USE_TSAN OFF)
if (USE_TSAN)
    add_compile_options(-fsanitize=thread -ggdb -fno-omit-frame-pointer)
    add_link_options(-fsanitize=thread -ggdb -fno-omit-frame-pointer)
    message(STATUS "Toolchain: Build with TSAN TEST Configure")
endif (USE_TSAN)

option(USE_STD_PYZENITH OFF)
if (USE_STD_PYZENITH)
    add_compile_definitions(STD_PYZENITH)
    message(STATUS "Toolchain: Build use -DSTD_PYZENITH")
endif (USE_STD_PYZENITH)

option(USE_OSS_BUILD OFF)
if (USE_OSS_BUILD)
    add_compile_definitions(OSS_BUILD)
    message(STATUS "Toolchain: Build use -DOSS_BUILD")
endif (USE_OSS_BUILD)

option(DAAC_READ_WRITE OFF)
if (DAAC_READ_WRITE)
    add_compile_definitions(DAAC_READ_WRITE)
    message(STATUS "Toolchain: Build with DAAC_READ_WRITE")
endif (DAAC_READ_WRITE)

if (UNIX)
    set_property(TARGET PROPERTY C_STANDARD 99)
    add_compile_options(-fPIC -Wall -MMD -fno-strict-aliasing -fsigned-char -fms-extensions)
    add_compile_definitions(_GNU_SOURCE _LARGEFILE64_SOURCE KNL_PREFIX _REENTRANT)

    add_compile_options(-fvisibility=default -fstack-protector-strong --param ssp-buffer-size=4)
    add_link_options(-Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,now)
    set(CMAKE_SKIP_RPATH TRUE)

    set(JAVA_INCLUDE_DIR $ENV{JAVA_HOME})

    if (NOT PYTHON_INCLUDE_DIR)
        if (NOT DEFINED ENV{PYTHON_INCLUDE_DIR})
            # environment variable PYTHON_INCLUDE_DIR not found 
            find_package(PythonLibs REQUIRED)
        else ()
            set(PYTHON_INCLUDE_DIR $ENV{PYTHON_INCLUDE_DIR})
        endif ()
    endif ()
    include_directories(${PYTHON_INCLUDE_DIR})

endif ()

set(CANTIANDB_LIBRARY "${PROJECT_SOURCE_DIR}/library")
set(CANTIANDB_SRC "${PROJECT_SOURCE_DIR}/pkg/src")

set(OPENSSL_LIB_PATH "${CANTIANDB_LIBRARY}/openssl/lib")
set(SECUREC_LIB_PATH "${CANTIANDB_LIBRARY}/huawei_security/lib")

set(PCRE_LIB_PATH "${CANTIANDB_LIBRARY}/pcre/lib")
set(Z_LIB_PATH "${CANTIANDB_LIBRARY}/zlib/lib")
set(ODBC_LIB_PATH "${CANTIANDB_LIBRARY}/odbc/lib")
set(LZ4_LIB_PATH "${CANTIANDB_LIBRARY}/lz4/lib")
set(ZSTD_LIB_PATH "${CANTIANDB_LIBRARY}/Zstandard/lib")
set(CMC_LIB_PATH "${CANTIANDB_LIBRARY}/kmc/lib")

set(VPP_LIB_PATH "${SECUREC_LIB_PATH}")

set(ZEN_OUTPUT_PATH "${PROJECT_SOURCE_DIR}/output")
set(CANTIANDB_LIB "${ZEN_OUTPUT_PATH}/lib")
set(CANTIANDB_BIN "${ZEN_OUTPUT_PATH}/bin")

option(USE_FUZZASAN OFF)
if (USE_FUZZASAN)
    add_compile_options(-fsanitize=address -fsanitize=undefined -fsanitize-coverage=trace-pc,trace-cmp -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address -fsanitize=undefined -fsanitize-coverage=trace-pc,trace-cmp -fno-omit-frame-pointer)
    message(STATUS "Toolchain: Build with USE_FUZZASAN TEST Configure")
    add_compile_definitions(_CANTIAN_FUZZ_TEST_) 
endif (USE_FUZZASAN)

if (NOT COMMIT_ID)
    execute_process(
            COMMAND bash -c "cat ${PROJECT_SOURCE_DIR}/build/conf/git_message.in | grep git_id |  awk -F'=' '{print  $2}'"
            OUTPUT_VARIABLE COMMIT_ID
            OUTPUT_STRIP_TRAILING_WHITESPACE
    )
endif ()
message(STATUS ${COMMIT_ID})

execute_process(
        COMMAND bash -c "cat ${PROJECT_SOURCE_DIR}/build/conf/git_message.in | grep gitVersion |  awk -F'=' '{print  $2}'"
        OUTPUT_VARIABLE WHOLE_COMMIT_ID
        OUTPUT_STRIP_TRAILING_WHITESPACE
)
message(STATUS ${WHOLE_COMMIT_ID})

execute_process(
    COMMAND bash -c "cat ${PROJECT_SOURCE_DIR}/build/conf/git_message.in | grep driver_commit_id |  awk -F'=' '{print  $2}'"
    OUTPUT_VARIABLE DRIVER_COMMIT_ID
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
message(STATUS ${DRIVER_COMMIT_ID})

execute_process(
    COMMAND bash -c "cat ${PROJECT_SOURCE_DIR}/build/conf/git_message.in | grep ctsql_commit_id |  awk -F'=' '{print  $2}'"
    OUTPUT_VARIABLE CTSQL_COMMIT_ID
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
message(STATUS ${CTSQL_COMMIT_ID})

if (UNIX)
    message("UNIX Release check")

    ## OS NAME related, consider to abandon
    if (EXISTS "/etc/redhat-release")
        execute_process(
                COMMAND bash -c "cat /etc/redhat-release | grep '2.0 (SP3)'"
                OUTPUT_VARIABLE Euler_SP3
        )
        execute_process(
                COMMAND bash -c "cat /etc/redhat-release | grep '2.0 (SP5)'"
                OUTPUT_VARIABLE Euler_SP5
        )
        execute_process(
                COMMAND bash -c "cat /etc/redhat-release | grep '2.0 (SP8)'"
                OUTPUT_VARIABLE Euler_SP8
        )
        execute_process(
                COMMAND bash -c "cat /etc/redhat-release | grep 'Red Hat'"
                OUTPUT_VARIABLE RED_HAT_OS
        )

        if (NOT RED_HAT_OS STREQUAL "")
            message("REDHAT Release")
            add_compile_definitions(RED_HAT)
        elseif ((NOT Euler_SP3 STREQUAL "") OR (NOT Euler_SP5 STREQUAL ""))
            message("EULER20SP3(SP5) Release")
        elseif (NOT Euler_SP8 STREQUAL "")
            message("EULER20SP8 Release")
        endif ()
    elseif (EXISTS "/etc/centos-release")
        message("CentOS Release")
    elseif (EXISTS "/etc/SuSE-release")
        message("SUSE Release")
    elseif (EXISTS "/etc/neokylin-release")
        add_compile_definitions(RED_HAT)
        message("KYLIN Release")
    elseif (EXISTS "/etc/openEuler-release")
	    message("OpenEuler Release")
    endif ()

    ## unzip 3rdparty lib
    execute_process(
            COMMAND ${CMAKE_COMMAND} -E tar -xvf ${PCRE_LIB_PATH}/libpcre.tar WORKING_DIRECTORY ${PCRE_LIB_PATH}/
    )
    execute_process(
            COMMAND ${CMAKE_COMMAND} -E tar -xvf ${Z_LIB_PATH}/libz.tar WORKING_DIRECTORY ${Z_LIB_PATH}/
    )
    if (NOT USE_OSS_BUILD)
        execute_process(
                COMMAND ${CMAKE_COMMAND} -E tar -xvf ${ODBC_LIB_PATH}/libodbc.tar WORKING_DIRECTORY ${ODBC_LIB_PATH}/
        )
    endif ()
    execute_process(
            COMMAND ${CMAKE_COMMAND} -E tar -xvf ${ZSTD_LIB_PATH}/libzstd.tar WORKING_DIRECTORY ${ZSTD_LIB_PATH}/
    )
    execute_process(
            COMMAND ${CMAKE_COMMAND} -E tar -xvf ${LZ4_LIB_PATH}/liblz4.tar WORKING_DIRECTORY ${LZ4_LIB_PATH}/
    )
endif (UNIX)


set(vpp_libsecurec "libsecurec.a")
set(vpp_libipsi_crypto "libcrypto.a")
set(vpp_libipsi_ssl "libssl.a")

set(hw_kmc_lib "")
set(hw_sdp_lib "")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99 -g -ldl -pthread")
add_compile_options(-fno-common)
add_compile_options(-Wtrampolines)
add_compile_options(-Wno-address)
add_compile_options(-freg-struct-return)
add_compile_options(-pipe)
add_link_options(-Wl,-Bsymbolic)
if (UNIX)
    add_link_options(-rdynamic)
endif()

link_directories(${CANTIANDB_LIB} "${CANTIANDB_LIBRARY}/protobuf/lib" ${CANTIANDB_LIBRARY} ${OPENSSL_LIB_PATH} ${PCRE_LIB_PATH} ${Z_LIB_PATH} ${ODBC_LIB_PATH} ${VPP_LIB_PATH}
         ${ZSTD_LIB_PATH} ${KMC_LIB_PATH} ${LZ4_LIB_PATH} ${AES_LIB_PATH})

# add subdir, this should be the last line!!
add_subdirectory(pkg)
