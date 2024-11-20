message(STATUS "build common_ut...")

include_directories(${CMAKE_SOURCE_DIR}/pkg/src/common)
set(COMMON_UT_SOURCE ${CMAKE_SOURCE_DIR}/pkg/test/unit_test/ut/common/common_test_main.cpp
                ${CMAKE_SOURCE_DIR}/pkg/test/unit_test/ut/common/common_device_test.cpp)

#add_compile_options(-fno-common)
add_compile_options(-Wall -fpermissive)

#add_link_options(-Wl, -Bsymbolic)
add_link_options(-rdynamic)

add_executable(common_test ${COMMON_UT_SOURCE})
set_target_properties(common_test PROPERTIES LINKER_LANGUAGE "CXX")

target_link_libraries(common_test 
                     -Wl,--start-group 
                     gtest mockcpp gmock zetms zecms zeprotocol m rt dl z zstd lz4
                     zecmssrc zeclient zerc zecommon zemes zefdsa zectc zecluster
                     zeserver zekernel zesql pthread  z 
                     -Wl,--end-group)
target_compile_definitions(common_test PRIVATE -DCT_LIB_VERSION=${DD_CT_LIB_VERSION})
target_compile_definitions(common_test PRIVATE -DGETDBVERSION=${DD_GETDBVERSION})