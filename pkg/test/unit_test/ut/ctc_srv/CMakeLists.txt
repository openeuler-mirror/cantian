message(STATUS "build ctc_srv_ut...")

include_directories(${CMAKE_SOURCE_DIR}/pkg/src/ctc)
include_directories(${CMAKE_SOURCE_DIR}/library/protobuf)
include_directories(${CMAKE_SOURCE_DIR}/pkg/src/rc)
set(CTC_SRV_UT_SOURCE ${CMAKE_SOURCE_DIR}/pkg/test/unit_test/ut/ctc_srv/ctc_srv_test_main.cpp
                      ${CMAKE_SOURCE_DIR}/pkg/test/unit_test/ut/ctc_srv/ctc_cbo_test.cpp
                      ${CMAKE_SOURCE_DIR}/pkg/test/unit_test/ut/ctc_srv/ctc_trx_begin_test.cpp
                      ${CMAKE_SOURCE_DIR}/pkg/test/unit_test/ut/ctc_srv/ctc_statistic_begin_test.cpp
                      ${CMAKE_SOURCE_DIR}/pkg/test/unit_test/ut/ctc_srv/ctc_mq_trx_begin_test.cpp
                      ${CMAKE_SOURCE_DIR}/pkg/test/unit_test/ut/ctc_srv/ctc_mq_statistic_begin_test.cpp
		              ${CMAKE_SOURCE_DIR}/pkg/test/unit_test/ut/ctc_srv/ctc_trx_commit_test.cpp
		              ${CMAKE_SOURCE_DIR}/pkg/test/unit_test/ut/ctc_srv/ctc_statistic_commit_test.cpp
		              ${CMAKE_SOURCE_DIR}/pkg/test/unit_test/ut/ctc_srv/ctc_mq_trx_commit_test.cpp
		              ${CMAKE_SOURCE_DIR}/pkg/test/unit_test/ut/ctc_srv/ctc_mq_statistic_commit_test.cpp)

#add_compile_options(-fno-common)
add_compile_options(-Wall -fpermissive)

#add_link_options(-Wl, -Bsymbolic)
add_link_options(-rdynamic)

add_executable(ctc_srv_test ${CTC_SRV_UT_SOURCE})
set_target_properties(ctc_srv_test PROPERTIES LINKER_LANGUAGE "CXX")

target_link_libraries(ctc_srv_test 
                     -Wl,--start-group 
                     gtest mockcpp gmock zetms zecms zeprotocol m rt dl z zstd lz4
                     zecmssrc zeclient zerc zecommon zemes zefdsa zectc zecluster
                     zeserver zekernel zesql pthread  z 
                     -Wl,--end-group)
target_compile_definitions(ctc_srv_test PRIVATE -DCT_LIB_VERSION=${DD_CT_LIB_VERSION})
target_compile_definitions(ctc_srv_test PRIVATE -DGETDBVERSION=${DD_GETDBVERSION})