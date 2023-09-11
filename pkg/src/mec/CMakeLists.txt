include_directories(
	"${CTDB_SRC}/cluster"
	"${CTDB_SRC}/rc"
	"${CTDB_SRC}/cms/interface"
)

aux_source_directory(. MEC_SRC)

if (NOT _DBSTOR_ENABLE_)
    list(REMOVE_ITEM MEC_SRC
    ./mes_uc.c)
endif()

set(CMAKE_C_FLAGS "-D__LINUX_USR__")

# generate static library
add_library(zemes STATIC ${MEC_SRC})
target_link_libraries(zemes PRIVATE zerc)