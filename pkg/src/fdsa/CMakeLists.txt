include_directories(
        "${CANTIANDB_SRC}/cluster"
        "${CANTIANDB_SRC}/cms/interface"
        "${CANTIANDB_SRC}/rc"
        "${CANTIANDB_SRC}/zenfs"
        "${CANTIANDB_SRC}/fdsa"
        "${CMAKE_CURRENT_SOURCE_DIR}"
        "${CMAKE_CURRENT_SOURCE_DIR}/backup"
        "${CMAKE_CURRENT_SOURCE_DIR}/buffer"
        "${CMAKE_CURRENT_SOURCE_DIR}/catalog"
        "${CMAKE_CURRENT_SOURCE_DIR}/common/variant"
        "${CMAKE_CURRENT_SOURCE_DIR}/common"
        "${CMAKE_CURRENT_SOURCE_DIR}/daemon"
        "${CMAKE_CURRENT_SOURCE_DIR}/flashback"
        "${CMAKE_CURRENT_SOURCE_DIR}/include"
        "${CMAKE_CURRENT_SOURCE_DIR}/index"
        "${CMAKE_CURRENT_SOURCE_DIR}/lob"
        "${CMAKE_CURRENT_SOURCE_DIR}/persist"
        "${CMAKE_CURRENT_SOURCE_DIR}/replication"
        "${CMAKE_CURRENT_SOURCE_DIR}/sequence"
        "${CMAKE_CURRENT_SOURCE_DIR}/statistics"
        "${CMAKE_CURRENT_SOURCE_DIR}/table"
        "${CMAKE_CURRENT_SOURCE_DIR}/tablespace"
        "${CMAKE_CURRENT_SOURCE_DIR}/xact"
)
set(CMAKE_C_FLAGS "-D__LINUX_USR__")
aux_source_directory(. FDSA_SRC)
link_directories(${CANTIANDB_LIB} "${CANTIANDB_LIBRARY}/protobuf/lib")
# generate static library
add_library(zefdsa STATIC ${FDSA_SRC})
target_link_libraries(zefdsa PRIVATE zecommon)