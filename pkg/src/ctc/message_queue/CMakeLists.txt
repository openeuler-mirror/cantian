aux_source_directory(. MESSAGE_SRC)

# generate shard library
add_library(message_queue SHARED ${MESSAGE_SRC})