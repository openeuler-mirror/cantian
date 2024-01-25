include_directories(
        "${CANTIANDB_SRC}/cms/interface"
)

aux_source_directory(. RC_SRC)

# generate static library
add_library(zerc STATIC ${RC_SRC})
if (USE_FUZZASAN)
        add_compile_options(-fsanitize-coverage=trace-pc)
        target_link_libraries(zerc PRIVATE zecms Secodefuzz)
else ()
        target_link_libraries(zerc PRIVATE zecms)
endif(USE_FUZZASAN)
