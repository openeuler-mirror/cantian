aux_source_directory(./ctversion.c VERSION_SRC)

add_library(zeversion STATIC ${VERSION_SRC})
add_compile_definitions(CT_LIB_VERSION=${DD_CT_LIB_VERSION})
add_compile_definitions(GETDBVERSION=${DD_GETDBVERSION})
