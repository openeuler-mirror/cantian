message(STATUS "build message_queue_ut...")

include_directories(${CMAKE_SOURCE_DIR}/pkg/src/ctc/message_queue)
set(DEMO_SOURCE ${CMAKE_SOURCE_DIR}/pkg/test/unit_test/ut/message_queue/message_queue_test_main.cpp)


#add_compile_options(-fno-common)
add_compile_options(-Wall -fpermissive)

#add_link_options(-Wl, -Bsymbolic)
add_link_options(-rdynamic)

add_executable(message_queue_test ${DEMO_SOURCE})
set_target_properties(message_queue_test PROPERTIES LINKER_LANGUAGE "CXX")

target_link_libraries(message_queue_test 
                     -Wl,--start-group 
                     gtest mockcpp gmock zetms zecms zeprotocol m rt dl z zstd lz4
                     zecmssrc zeclient zerc zecommon zemes zefdsa zectc zecluster
                     zeserver zekernel zesql pthread  z 
                     -Wl,--end-group)
target_compile_definitions(message_queue_test PRIVATE -DCT_LIB_VERSION=${DD_CT_LIB_VERSION})
target_compile_definitions(message_queue_test PRIVATE -DGETDBVERSION=${DD_GETDBVERSION})
