include_directories(
	"${CTDB_SRC}/rc"
	"${CTDB_SRC}/mec"
    "${CTDB_SRC}/tse"
	"${CTDB_SRC}/kernel/common"
	"${CTDB_SRC}/cms/interface"
)

aux_source_directory(. CLUSTER_SRC)
link_directories(${CTDB_LIB} "${CTDB_LIBRARY}/protobuf/lib")
# generate static library
add_library(zecluster STATIC ${CLUSTER_SRC})
if (USE_FUZZASAN)
	add_compile_options(-fsanitize-coverage=trace-pc)
endif(USE_FUZZASAN)
target_link_libraries(zecluster PRIVATE zerc zectc)
