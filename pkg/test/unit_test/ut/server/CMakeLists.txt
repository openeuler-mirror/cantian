message(STATUS "build server_ut...")

include_directories(${CMAKE_SOURCE_DIR}/pkg/src/cluster)
include_directories(${CMAKE_SOURCE_DIR}/pkg/src/rc)
include_directories(${CMAKE_SOURCE_DIR}/pkg/src/common)
include_directories(${CMAKE_SOURCE_DIR}/pkg/src/kernel/include)
include_directories(${CMAKE_SOURCE_DIR}/pkg/src/ctc)
set(SERVER_UT_SOURCE ${CMAKE_SOURCE_DIR}/pkg/test/unit_test/ut/server/server_test_main.cpp
                ${CMAKE_SOURCE_DIR}/pkg/test/unit_test/ut/server/view_test.cpp)


#add_compile_options(-fno-common)
add_compile_options(-Wall -fpermissive)

#add_link_options(-Wl, -Bsymbolic)
add_link_options(-rdynamic)

add_executable(server_test ${SERVER_UT_SOURCE})
set_target_properties(server_test PROPERTIES LINKER_LANGUAGE "CXX")

target_link_libraries(server_test 
                     -Wl,--start-group 
                     gtest mockcpp gmock zetms zecms zeprotocol m rt dl z zstd lz4
                     zecmssrc zeclient zerc zecommon zemes zefdsa zectc zecluster
                     zeserver zekernel zesql pthread  z 
                     -Wl,--end-group)
target_compile_definitions(server_test PRIVATE -DCT_LIB_VERSION=${DD_CT_LIB_VERSION})
target_compile_definitions(server_test PRIVATE -DGETDBVERSION=${DD_GETDBVERSION})
