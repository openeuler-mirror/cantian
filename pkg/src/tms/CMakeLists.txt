aux_source_directory(. TMS_SRC)

# generate static library
add_library(zetms STATIC ${TMS_SRC})