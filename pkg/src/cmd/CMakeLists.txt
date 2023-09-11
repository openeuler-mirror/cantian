include_directories(
	"${CTDB_SRC}/cluster"
	"${CTDB_SRC}/rc"
	"${CTDB_SRC}/cms/interface"
        "${CMAKE_CURRENT_SOURCE_DIR}"
        "${CMAKE_CURRENT_SOURCE_DIR}/json"
        "${CMAKE_CURRENT_SOURCE_DIR}/function"

)

set(LIBRARY_OUTPUT_PATH ${CTDB_LIB})

aux_source_directory(. SQL_SRC)
aux_source_directory(./json SQL_JSON_SRC)
aux_source_directory(./function SQL_FUNCTION_SRC)
set(SQL_ALL_SRC
        ${SQL_SRC}
        ${SQL_FUNCTION_SRC}
        ${SQL_JSON_SRC}
        )

link_directories(${CTDB_LIB} ${PCRE_LIB_PATH} ${VPP_LIB_PATH} ${Z_LIB_PATH})

add_library(zesql STATIC ${SQL_ALL_SRC})
if (USE_FUZZASAN)
target_link_libraries(zesql PRIVATE zekernel)
endif(USE_FUZZASAN)
