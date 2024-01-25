#### ctsql ####
aux_source_directory(../ctsql CTSQL_SRC)

if (USE_FUZZASAN)
    add_compile_options(-fsanitize-coverage=trace-pc)
    ADD_EXECUTABLE(ctsql ${CTSQL_SRC} ${CTSQL_VERSION_SRC})
    target_link_libraries(ctsql PRIVATE zesql zeprotocol zecommon zeclient m rt pthread dl z Secodefuzz)
else ()
    ADD_EXECUTABLE(ctsql ${CTSQL_SRC} ${CTSQL_VERSION_SRC})
    target_link_libraries(ctsql PRIVATE zesql zeprotocol zecommon zeclient m rt pthread dl z)
endif(USE_FUZZASAN)
target_compile_definitions(ctsql PRIVATE -DCT_CTSQL_VERSION=${DD_CT_CTSQL_VERSION})
target_compile_definitions(ctsql PRIVATE -DGET_CTSQL_VERSION=${DD_GETCTSQLVERSION})
