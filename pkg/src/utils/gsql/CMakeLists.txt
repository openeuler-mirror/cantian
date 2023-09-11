#### ctclient ####
aux_source_directory(. ctclient_SRC)

if (USE_FUZZASAN)
    add_compile_options(-fsanitize-coverage=trace-pc)
    ADD_EXECUTABLE(ctclient ${ctclient_SRC} ${GSQL_VERSION_SRC})
    target_link_libraries(ctclient PRIVATE zesql zeprotocol zecommon zeclient m rt pthread dl z Secodefuzz)
else ()
    ADD_EXECUTABLE(ctclient ${ctclient_SRC} ${GSQL_VERSION_SRC})
    target_link_libraries(ctclient PRIVATE zesql zeprotocol zecommon zeclient m rt pthread dl z)
endif(USE_FUZZASAN)
target_compile_definitions(ctclient PRIVATE -DGS_GSQL_VERSION=${DD_GS_GSQL_VERSION})
target_compile_definitions(ctclient PRIVATE -DGET_GSQL_VERSION=${DD_GETGSQLVERSION})
