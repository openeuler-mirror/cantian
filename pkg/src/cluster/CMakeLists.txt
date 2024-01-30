include_directories(
	"${CANTIANDB_SRC}/rc"
	"${CANTIANDB_SRC}/mec"
    "${CANTIANDB_SRC}/tse"
	"${CANTIANDB_SRC}/kernel/common"
	"${CANTIANDB_SRC}/cms/interface"
	"${CANTIANDB_SRC}/tms"
	"${CANTIANDB_SRC}/fdsa"
	"${CMAKE_CURRENT_SOURCE_DIR}"
)

aux_source_directory(. CLUSTER_SRC)
link_directories(${CANTIANDB_LIB} "${CANTIANDB_LIBRARY}/protobuf/lib")
# generate static library
add_library(zecluster STATIC ${CLUSTER_SRC})
if (USE_FUZZASAN)
	add_compile_options(-fsanitize-coverage=trace-pc)
endif(USE_FUZZASAN)
target_link_libraries(zecluster PRIVATE zerc zectc zetms zefdsa)