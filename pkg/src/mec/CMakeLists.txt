include_directories(
	"${CANTIANDB_SRC}/cluster"
	"${CANTIANDB_SRC}/rc"
	"${CANTIANDB_SRC}/cms/interface"
	"${CANTIANDB_SRC}/tms"
)

aux_source_directory(. MEC_SRC)

set(CMAKE_C_FLAGS "-D__LINUX_USR__")

# generate static library
add_library(zemes STATIC ${MEC_SRC})
target_link_libraries(zemes PRIVATE zerc zetms)