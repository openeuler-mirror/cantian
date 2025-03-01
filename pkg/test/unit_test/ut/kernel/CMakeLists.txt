message(STATUS "build kernel_ut...")

include_directories(${CMAKE_SOURCE_DIR}/pkg/src/cluster)
include_directories(${CMAKE_SOURCE_DIR}/pkg/src/rc)
include_directories(${CMAKE_SOURCE_DIR}/pkg/src/kernel/include)
include_directories(${CMAKE_SOURCE_DIR}/pkg/src/ctsql)
include_directories(${CMAKE_SOURCE_DIR}/pkg/src/server)
set(KNL_UT_SOURCE ${CMAKE_SOURCE_DIR}/pkg/test/unit_test/ut/kernel/kernel_test_main.cpp
                ${CMAKE_SOURCE_DIR}/pkg/test/unit_test/ut/kernel/kernel_heap_test.cpp)

#add_compile_options(-fno-common)
add_compile_options(-Wall -fpermissive)

#add_link_options(-Wl, -Bsymbolic)
add_link_options(-rdynamic)

add_executable(knl_test ${KNL_UT_SOURCE})
set_target_properties(knl_test PROPERTIES LINKER_LANGUAGE "CXX")

target_link_libraries(knl_test 
                     -Wl,--start-group 
                     gtest mockcpp gmock zetms zecms zeprotocol m rt dl z zstd lz4
                     zecmssrc zeclient zerc zecommon zemes zefdsa zectc zecluster
                     zeserver zekernel zesql pthread  z 
                     -Wl,--end-group)
target_compile_definitions(knl_test PRIVATE -DCT_LIB_VERSION=${DD_CT_LIB_VERSION})
target_compile_definitions(knl_test PRIVATE -DGETDBVERSION=${DD_GETDBVERSION})