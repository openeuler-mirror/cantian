include_directories("${CMAKE_SOURCE_DIR}/open_source/googletest/googletest/include")
include_directories("${CMAKE_SOURCE_DIR}/open_source/googletest/googlemock/include")
include_directories("${CMAKE_SOURCE_DIR}/open_source/mockcpp/include")
include_directories("${CMAKE_SOURCE_DIR}/open_source/mockcpp/3rdparty")

set(GTEST_LIB_PATH "${CMAKE_SOURCE_DIR}/library/googletest/lib")
set(MOCKCPP_LIB_PATH "${CMAKE_SOURCE_DIR}/library/mockcpp/lib")
link_directories(${GTEST_LIB_PATH} ${MOCKCPP_LIB_PATH})
add_subdirectory(ut)
