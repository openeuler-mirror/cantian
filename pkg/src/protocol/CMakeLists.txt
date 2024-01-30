include_directories(
        "${CMAKE_CURRENT_SOURCE_DIR}"
)

link_directories(${CANTIANDB_LIB})

aux_source_directory(. PROTOCOL_SRC)

option(USE_FUZZASAN OFF)
if (USE_FUZZASAN)
    add_compile_options(-fsanitize-coverage=trace-pc)
endif(USE_FUZZASAN)
# generate static library
add_library(zeprotocol_static STATIC ${PROTOCOL_SRC})
# generate dynamic library
add_library(zeprotocol SHARED ${PROTOCOL_SRC})
# dynamic libraries and static libraries exist at the same time
set_target_properties(zeprotocol PROPERTIES OUTPUT_NAME zeprotocol
        CLEAN_DIRECT_OUTPUT 1
        ARCHIVE_OUTPUT_DIRECTORY ${CANTIANDB_LIB}
        )
set_target_properties(zeprotocol_static PROPERTIES OUTPUT_NAME zeprotocol
        CLEAN_DIRECT_OUTPUT 1
        ARCHIVE_OUTPUT_DIRECTORY ${CANTIANDB_LIB}
        )
if (USE_FUZZASAN)
    target_link_libraries(zeprotocol PRIVATE zecommon pthread m rt Secodefuzz)
else ()
    target_link_libraries(zeprotocol PRIVATE zecommon pthread m rt)
endif(USE_FUZZASAN)
