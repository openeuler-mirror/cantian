include_directories(
        "${CMAKE_CURRENT_SOURCE_DIR}/interface"
        "${CTDB_LIBRARY}/dbstor"
        "${CTDB_LIBRARY}/xnet/include"
        "${CTDB_SRC}/upgrade_check"
        "${CTDB_SRC}/cms/cms"
)

aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/interface INTERFACE_SRC)
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/cms CMS_SRC)


set(CMS_TOTAL_SRC ${INTERFACE_SRC} ${CMS_SRC})

# generate static library
add_library(zecms STATIC ${INTERFACE_SRC})
add_library(zecmssrc STATIC ${CMS_SRC})
add_executable(cms ${CMS_TOTAL_SRC} ${VERSION_SRC})
if (USE_FUZZASAN)
	add_compile_options(-fsanitize-coverage=trace-pc)
    target_link_libraries(cms PRIVATE zemes zecms zeprotocol zecommon m rt pthread dl z Secodefuzz)
else()
    target_link_libraries(cms PRIVATE zemes zecms zeprotocol zecommon m rt pthread dl z)
endif(USE_FUZZASAN)
target_compile_definitions(cms PRIVATE -DGS_LIB_VERSION=${DD_GS_LIB_VERSION})
target_compile_definitions(cms PRIVATE -DGETDBVERSION=${DD_GETDBVERSION})