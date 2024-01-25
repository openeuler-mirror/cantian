/* -------------------------------------------------------------------------
 *  This file is part of the Cantian project.
 * Copyright (c) 2024 Huawei Technologies Co.,Ltd.
 *
 * Cantian is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 *          http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 * -------------------------------------------------------------------------
 *
 * tc_db.pb-c.c
 *
 *
 * IDENTIFICATION
 * src/tse/protobuf/tc_db.pb-c.c
 *
 * -------------------------------------------------------------------------
 */
/* Generated from: tc_db.proto */

/* Do not generate deprecated warnings for self */
#ifndef PROTOBUF_C__NO_DEPRECATED
#define PROTOBUF_C__NO_DEPRECATED
#endif

#include "tc_db.pb-c.h"
void   tc_db__tse_ddlcolumn_data_type_def__init
                     (TcDb__TseDDLColumnDataTypeDef         *message)
{
  static const TcDb__TseDDLColumnDataTypeDef init_value = TC_DB__TSE_DDLCOLUMN_DATA_TYPE_DEF__INIT;
  *message = init_value;
}
size_t tc_db__tse_ddlcolumn_data_type_def__get_packed_size
                     (const TcDb__TseDDLColumnDataTypeDef *message)
{
  assert(message->base.descriptor == &tc_db__tse_ddlcolumn_data_type_def__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t tc_db__tse_ddlcolumn_data_type_def__pack
                     (const TcDb__TseDDLColumnDataTypeDef *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &tc_db__tse_ddlcolumn_data_type_def__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t tc_db__tse_ddlcolumn_data_type_def__pack_to_buffer
                     (const TcDb__TseDDLColumnDataTypeDef *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &tc_db__tse_ddlcolumn_data_type_def__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
TcDb__TseDDLColumnDataTypeDef *
       tc_db__tse_ddlcolumn_data_type_def__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (TcDb__TseDDLColumnDataTypeDef *)
     protobuf_c_message_unpack (&tc_db__tse_ddlcolumn_data_type_def__descriptor,
                                allocator, len, data);
}
void   tc_db__tse_ddlcolumn_data_type_def__free_unpacked
                     (TcDb__TseDDLColumnDataTypeDef *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &tc_db__tse_ddlcolumn_data_type_def__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   tc_db__tse_ddlcolumn_def__init
                     (TcDb__TseDDLColumnDef         *message)
{
  static const TcDb__TseDDLColumnDef init_value = TC_DB__TSE_DDLCOLUMN_DEF__INIT;
  *message = init_value;
}
size_t tc_db__tse_ddlcolumn_def__get_packed_size
                     (const TcDb__TseDDLColumnDef *message)
{
  assert(message->base.descriptor == &tc_db__tse_ddlcolumn_def__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t tc_db__tse_ddlcolumn_def__pack
                     (const TcDb__TseDDLColumnDef *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &tc_db__tse_ddlcolumn_def__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t tc_db__tse_ddlcolumn_def__pack_to_buffer
                     (const TcDb__TseDDLColumnDef *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &tc_db__tse_ddlcolumn_def__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
TcDb__TseDDLColumnDef *
       tc_db__tse_ddlcolumn_def__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (TcDb__TseDDLColumnDef *)
     protobuf_c_message_unpack (&tc_db__tse_ddlcolumn_def__descriptor,
                                allocator, len, data);
}
void   tc_db__tse_ddlcolumn_def__free_unpacked
                     (TcDb__TseDDLColumnDef *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &tc_db__tse_ddlcolumn_def__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   tc_db__tse_ddlforeign_key_element_def__init
                     (TcDb__TseDDLForeignKeyElementDef         *message)
{
  static const TcDb__TseDDLForeignKeyElementDef init_value = TC_DB__TSE_DDLFOREIGN_KEY_ELEMENT_DEF__INIT;
  *message = init_value;
}
size_t tc_db__tse_ddlforeign_key_element_def__get_packed_size
                     (const TcDb__TseDDLForeignKeyElementDef *message)
{
  assert(message->base.descriptor == &tc_db__tse_ddlforeign_key_element_def__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t tc_db__tse_ddlforeign_key_element_def__pack
                     (const TcDb__TseDDLForeignKeyElementDef *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &tc_db__tse_ddlforeign_key_element_def__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t tc_db__tse_ddlforeign_key_element_def__pack_to_buffer
                     (const TcDb__TseDDLForeignKeyElementDef *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &tc_db__tse_ddlforeign_key_element_def__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
TcDb__TseDDLForeignKeyElementDef *
       tc_db__tse_ddlforeign_key_element_def__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (TcDb__TseDDLForeignKeyElementDef *)
     protobuf_c_message_unpack (&tc_db__tse_ddlforeign_key_element_def__descriptor,
                                allocator, len, data);
}
void   tc_db__tse_ddlforeign_key_element_def__free_unpacked
                     (TcDb__TseDDLForeignKeyElementDef *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &tc_db__tse_ddlforeign_key_element_def__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   tc_db__tse_ddlforeign_key_def__init
                     (TcDb__TseDDLForeignKeyDef         *message)
{
  static const TcDb__TseDDLForeignKeyDef init_value = TC_DB__TSE_DDLFOREIGN_KEY_DEF__INIT;
  *message = init_value;
}
size_t tc_db__tse_ddlforeign_key_def__get_packed_size
                     (const TcDb__TseDDLForeignKeyDef *message)
{
  assert(message->base.descriptor == &tc_db__tse_ddlforeign_key_def__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t tc_db__tse_ddlforeign_key_def__pack
                     (const TcDb__TseDDLForeignKeyDef *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &tc_db__tse_ddlforeign_key_def__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t tc_db__tse_ddlforeign_key_def__pack_to_buffer
                     (const TcDb__TseDDLForeignKeyDef *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &tc_db__tse_ddlforeign_key_def__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
TcDb__TseDDLForeignKeyDef *
       tc_db__tse_ddlforeign_key_def__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (TcDb__TseDDLForeignKeyDef *)
     protobuf_c_message_unpack (&tc_db__tse_ddlforeign_key_def__descriptor,
                                allocator, len, data);
}
void   tc_db__tse_ddlforeign_key_def__free_unpacked
                     (TcDb__TseDDLForeignKeyDef *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &tc_db__tse_ddlforeign_key_def__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   tc_db__tse_ddltable_key_part__init
                     (TcDb__TseDDLTableKeyPart         *message)
{
  static const TcDb__TseDDLTableKeyPart init_value = TC_DB__TSE_DDLTABLE_KEY_PART__INIT;
  *message = init_value;
}
size_t tc_db__tse_ddltable_key_part__get_packed_size
                     (const TcDb__TseDDLTableKeyPart *message)
{
  assert(message->base.descriptor == &tc_db__tse_ddltable_key_part__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t tc_db__tse_ddltable_key_part__pack
                     (const TcDb__TseDDLTableKeyPart *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &tc_db__tse_ddltable_key_part__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t tc_db__tse_ddltable_key_part__pack_to_buffer
                     (const TcDb__TseDDLTableKeyPart *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &tc_db__tse_ddltable_key_part__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
TcDb__TseDDLTableKeyPart *
       tc_db__tse_ddltable_key_part__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (TcDb__TseDDLTableKeyPart *)
     protobuf_c_message_unpack (&tc_db__tse_ddltable_key_part__descriptor,
                                allocator, len, data);
}
void   tc_db__tse_ddltable_key_part__free_unpacked
                     (TcDb__TseDDLTableKeyPart *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &tc_db__tse_ddltable_key_part__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   tc_db__tse_ddltable_key__init
                     (TcDb__TseDDLTableKey         *message)
{
  static const TcDb__TseDDLTableKey init_value = TC_DB__TSE_DDLTABLE_KEY__INIT;
  *message = init_value;
}
size_t tc_db__tse_ddltable_key__get_packed_size
                     (const TcDb__TseDDLTableKey *message)
{
  assert(message->base.descriptor == &tc_db__tse_ddltable_key__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t tc_db__tse_ddltable_key__pack
                     (const TcDb__TseDDLTableKey *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &tc_db__tse_ddltable_key__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t tc_db__tse_ddltable_key__pack_to_buffer
                     (const TcDb__TseDDLTableKey *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &tc_db__tse_ddltable_key__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
TcDb__TseDDLTableKey *
       tc_db__tse_ddltable_key__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (TcDb__TseDDLTableKey *)
     protobuf_c_message_unpack (&tc_db__tse_ddltable_key__descriptor,
                                allocator, len, data);
}
void   tc_db__tse_ddltable_key__free_unpacked
                     (TcDb__TseDDLTableKey *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &tc_db__tse_ddltable_key__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   tc_db__tse_msg_comm_def__init
                     (TcDb__TseMsgCommDef         *message)
{
  static const TcDb__TseMsgCommDef init_value = TC_DB__TSE_MSG_COMM_DEF__INIT;
  *message = init_value;
}
size_t tc_db__tse_msg_comm_def__get_packed_size
                     (const TcDb__TseMsgCommDef *message)
{
  assert(message->base.descriptor == &tc_db__tse_msg_comm_def__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t tc_db__tse_msg_comm_def__pack
                     (const TcDb__TseMsgCommDef *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &tc_db__tse_msg_comm_def__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t tc_db__tse_msg_comm_def__pack_to_buffer
                     (const TcDb__TseMsgCommDef *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &tc_db__tse_msg_comm_def__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
TcDb__TseMsgCommDef *
       tc_db__tse_msg_comm_def__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (TcDb__TseMsgCommDef *)
     protobuf_c_message_unpack (&tc_db__tse_msg_comm_def__descriptor,
                                allocator, len, data);
}
void   tc_db__tse_msg_comm_def__free_unpacked
                     (TcDb__TseMsgCommDef *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &tc_db__tse_msg_comm_def__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   tc_db__tse_ddlpartition_table_def__init
                     (TcDb__TseDDLPartitionTableDef         *message)
{
  static const TcDb__TseDDLPartitionTableDef init_value = TC_DB__TSE_DDLPARTITION_TABLE_DEF__INIT;
  *message = init_value;
}
size_t tc_db__tse_ddlpartition_table_def__get_packed_size
                     (const TcDb__TseDDLPartitionTableDef *message)
{
  assert(message->base.descriptor == &tc_db__tse_ddlpartition_table_def__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t tc_db__tse_ddlpartition_table_def__pack
                     (const TcDb__TseDDLPartitionTableDef *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &tc_db__tse_ddlpartition_table_def__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t tc_db__tse_ddlpartition_table_def__pack_to_buffer
                     (const TcDb__TseDDLPartitionTableDef *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &tc_db__tse_ddlpartition_table_def__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
TcDb__TseDDLPartitionTableDef *
       tc_db__tse_ddlpartition_table_def__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (TcDb__TseDDLPartitionTableDef *)
     protobuf_c_message_unpack (&tc_db__tse_ddlpartition_table_def__descriptor,
                                allocator, len, data);
}
void   tc_db__tse_ddlpartition_table_def__free_unpacked
                     (TcDb__TseDDLPartitionTableDef *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &tc_db__tse_ddlpartition_table_def__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   tc_db__tse_ddlpartition_def__init
                     (TcDb__TseDDLPartitionDef         *message)
{
  static const TcDb__TseDDLPartitionDef init_value = TC_DB__TSE_DDLPARTITION_DEF__INIT;
  *message = init_value;
}
size_t tc_db__tse_ddlpartition_def__get_packed_size
                     (const TcDb__TseDDLPartitionDef *message)
{
  assert(message->base.descriptor == &tc_db__tse_ddlpartition_def__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t tc_db__tse_ddlpartition_def__pack
                     (const TcDb__TseDDLPartitionDef *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &tc_db__tse_ddlpartition_def__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t tc_db__tse_ddlpartition_def__pack_to_buffer
                     (const TcDb__TseDDLPartitionDef *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &tc_db__tse_ddlpartition_def__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
TcDb__TseDDLPartitionDef *
       tc_db__tse_ddlpartition_def__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (TcDb__TseDDLPartitionDef *)
     protobuf_c_message_unpack (&tc_db__tse_ddlpartition_def__descriptor,
                                allocator, len, data);
}
void   tc_db__tse_ddlpartition_def__free_unpacked
                     (TcDb__TseDDLPartitionDef *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &tc_db__tse_ddlpartition_def__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   tc_db__tse_ddlcreate_table_def__init
                     (TcDb__TseDDLCreateTableDef         *message)
{
  static const TcDb__TseDDLCreateTableDef init_value = TC_DB__TSE_DDLCREATE_TABLE_DEF__INIT;
  *message = init_value;
}
size_t tc_db__tse_ddlcreate_table_def__get_packed_size
                     (const TcDb__TseDDLCreateTableDef *message)
{
  assert(message->base.descriptor == &tc_db__tse_ddlcreate_table_def__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t tc_db__tse_ddlcreate_table_def__pack
                     (const TcDb__TseDDLCreateTableDef *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &tc_db__tse_ddlcreate_table_def__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t tc_db__tse_ddlcreate_table_def__pack_to_buffer
                     (const TcDb__TseDDLCreateTableDef *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &tc_db__tse_ddlcreate_table_def__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
TcDb__TseDDLCreateTableDef *
       tc_db__tse_ddlcreate_table_def__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (TcDb__TseDDLCreateTableDef *)
     protobuf_c_message_unpack (&tc_db__tse_ddlcreate_table_def__descriptor,
                                allocator, len, data);
}
void   tc_db__tse_ddlcreate_table_def__free_unpacked
                     (TcDb__TseDDLCreateTableDef *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &tc_db__tse_ddlcreate_table_def__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   tc_db__tse_ddlalter_table_porp__init
                     (TcDb__TseDDLAlterTablePorp         *message)
{
  static const TcDb__TseDDLAlterTablePorp init_value = TC_DB__TSE_DDLALTER_TABLE_PORP__INIT;
  *message = init_value;
}
size_t tc_db__tse_ddlalter_table_porp__get_packed_size
                     (const TcDb__TseDDLAlterTablePorp *message)
{
  assert(message->base.descriptor == &tc_db__tse_ddlalter_table_porp__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t tc_db__tse_ddlalter_table_porp__pack
                     (const TcDb__TseDDLAlterTablePorp *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &tc_db__tse_ddlalter_table_porp__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t tc_db__tse_ddlalter_table_porp__pack_to_buffer
                     (const TcDb__TseDDLAlterTablePorp *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &tc_db__tse_ddlalter_table_porp__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
TcDb__TseDDLAlterTablePorp *
       tc_db__tse_ddlalter_table_porp__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (TcDb__TseDDLAlterTablePorp *)
     protobuf_c_message_unpack (&tc_db__tse_ddlalter_table_porp__descriptor,
                                allocator, len, data);
}
void   tc_db__tse_ddlalter_table_porp__free_unpacked
                     (TcDb__TseDDLAlterTablePorp *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &tc_db__tse_ddlalter_table_porp__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   tc_db__tse_ddlalter_table_drop__init
                     (TcDb__TseDDLAlterTableDrop         *message)
{
  static const TcDb__TseDDLAlterTableDrop init_value = TC_DB__TSE_DDLALTER_TABLE_DROP__INIT;
  *message = init_value;
}
size_t tc_db__tse_ddlalter_table_drop__get_packed_size
                     (const TcDb__TseDDLAlterTableDrop *message)
{
  assert(message->base.descriptor == &tc_db__tse_ddlalter_table_drop__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t tc_db__tse_ddlalter_table_drop__pack
                     (const TcDb__TseDDLAlterTableDrop *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &tc_db__tse_ddlalter_table_drop__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t tc_db__tse_ddlalter_table_drop__pack_to_buffer
                     (const TcDb__TseDDLAlterTableDrop *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &tc_db__tse_ddlalter_table_drop__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
TcDb__TseDDLAlterTableDrop *
       tc_db__tse_ddlalter_table_drop__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (TcDb__TseDDLAlterTableDrop *)
     protobuf_c_message_unpack (&tc_db__tse_ddlalter_table_drop__descriptor,
                                allocator, len, data);
}
void   tc_db__tse_ddlalter_table_drop__free_unpacked
                     (TcDb__TseDDLAlterTableDrop *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &tc_db__tse_ddlalter_table_drop__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   tc_db__tse_ddlalter_table_drop_key__init
                     (TcDb__TseDDLAlterTableDropKey         *message)
{
  static const TcDb__TseDDLAlterTableDropKey init_value = TC_DB__TSE_DDLALTER_TABLE_DROP_KEY__INIT;
  *message = init_value;
}
size_t tc_db__tse_ddlalter_table_drop_key__get_packed_size
                     (const TcDb__TseDDLAlterTableDropKey *message)
{
  assert(message->base.descriptor == &tc_db__tse_ddlalter_table_drop_key__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t tc_db__tse_ddlalter_table_drop_key__pack
                     (const TcDb__TseDDLAlterTableDropKey *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &tc_db__tse_ddlalter_table_drop_key__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t tc_db__tse_ddlalter_table_drop_key__pack_to_buffer
                     (const TcDb__TseDDLAlterTableDropKey *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &tc_db__tse_ddlalter_table_drop_key__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
TcDb__TseDDLAlterTableDropKey *
       tc_db__tse_ddlalter_table_drop_key__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (TcDb__TseDDLAlterTableDropKey *)
     protobuf_c_message_unpack (&tc_db__tse_ddlalter_table_drop_key__descriptor,
                                allocator, len, data);
}
void   tc_db__tse_ddlalter_table_drop_key__free_unpacked
                     (TcDb__TseDDLAlterTableDropKey *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &tc_db__tse_ddlalter_table_drop_key__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   tc_db__tse_ddlalter_table_alter_column__init
                     (TcDb__TseDDLAlterTableAlterColumn         *message)
{
  static const TcDb__TseDDLAlterTableAlterColumn init_value = TC_DB__TSE_DDLALTER_TABLE_ALTER_COLUMN__INIT;
  *message = init_value;
}
size_t tc_db__tse_ddlalter_table_alter_column__get_packed_size
                     (const TcDb__TseDDLAlterTableAlterColumn *message)
{
  assert(message->base.descriptor == &tc_db__tse_ddlalter_table_alter_column__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t tc_db__tse_ddlalter_table_alter_column__pack
                     (const TcDb__TseDDLAlterTableAlterColumn *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &tc_db__tse_ddlalter_table_alter_column__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t tc_db__tse_ddlalter_table_alter_column__pack_to_buffer
                     (const TcDb__TseDDLAlterTableAlterColumn *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &tc_db__tse_ddlalter_table_alter_column__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
TcDb__TseDDLAlterTableAlterColumn *
       tc_db__tse_ddlalter_table_alter_column__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (TcDb__TseDDLAlterTableAlterColumn *)
     protobuf_c_message_unpack (&tc_db__tse_ddlalter_table_alter_column__descriptor,
                                allocator, len, data);
}
void   tc_db__tse_ddlalter_table_alter_column__free_unpacked
                     (TcDb__TseDDLAlterTableAlterColumn *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &tc_db__tse_ddlalter_table_alter_column__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   tc_db__tse_ddlalter_table_def__init
                     (TcDb__TseDDLAlterTableDef         *message)
{
  static const TcDb__TseDDLAlterTableDef init_value = TC_DB__TSE_DDLALTER_TABLE_DEF__INIT;
  *message = init_value;
}
size_t tc_db__tse_ddlalter_table_def__get_packed_size
                     (const TcDb__TseDDLAlterTableDef *message)
{
  assert(message->base.descriptor == &tc_db__tse_ddlalter_table_def__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t tc_db__tse_ddlalter_table_def__pack
                     (const TcDb__TseDDLAlterTableDef *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &tc_db__tse_ddlalter_table_def__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t tc_db__tse_ddlalter_table_def__pack_to_buffer
                     (const TcDb__TseDDLAlterTableDef *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &tc_db__tse_ddlalter_table_def__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
TcDb__TseDDLAlterTableDef *
       tc_db__tse_ddlalter_table_def__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (TcDb__TseDDLAlterTableDef *)
     protobuf_c_message_unpack (&tc_db__tse_ddlalter_table_def__descriptor,
                                allocator, len, data);
}
void   tc_db__tse_ddlalter_table_def__free_unpacked
                     (TcDb__TseDDLAlterTableDef *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &tc_db__tse_ddlalter_table_def__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   tc_db__tse_ddltruncate_table_def__init
                     (TcDb__TseDDLTruncateTableDef         *message)
{
  static const TcDb__TseDDLTruncateTableDef init_value = TC_DB__TSE_DDLTRUNCATE_TABLE_DEF__INIT;
  *message = init_value;
}
size_t tc_db__tse_ddltruncate_table_def__get_packed_size
                     (const TcDb__TseDDLTruncateTableDef *message)
{
  assert(message->base.descriptor == &tc_db__tse_ddltruncate_table_def__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t tc_db__tse_ddltruncate_table_def__pack
                     (const TcDb__TseDDLTruncateTableDef *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &tc_db__tse_ddltruncate_table_def__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t tc_db__tse_ddltruncate_table_def__pack_to_buffer
                     (const TcDb__TseDDLTruncateTableDef *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &tc_db__tse_ddltruncate_table_def__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
TcDb__TseDDLTruncateTableDef *
       tc_db__tse_ddltruncate_table_def__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (TcDb__TseDDLTruncateTableDef *)
     protobuf_c_message_unpack (&tc_db__tse_ddltruncate_table_def__descriptor,
                                allocator, len, data);
}
void   tc_db__tse_ddltruncate_table_def__free_unpacked
                     (TcDb__TseDDLTruncateTableDef *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &tc_db__tse_ddltruncate_table_def__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   tc_db__tse_ddltruncate_table_partition_def__init
                     (TcDb__TseDDLTruncateTablePartitionDef         *message)
{
  static const TcDb__TseDDLTruncateTablePartitionDef init_value = TC_DB__TSE_DDLTRUNCATE_TABLE_PARTITION_DEF__INIT;
  *message = init_value;
}
size_t tc_db__tse_ddltruncate_table_partition_def__get_packed_size
                     (const TcDb__TseDDLTruncateTablePartitionDef *message)
{
  assert(message->base.descriptor == &tc_db__tse_ddltruncate_table_partition_def__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t tc_db__tse_ddltruncate_table_partition_def__pack
                     (const TcDb__TseDDLTruncateTablePartitionDef *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &tc_db__tse_ddltruncate_table_partition_def__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t tc_db__tse_ddltruncate_table_partition_def__pack_to_buffer
                     (const TcDb__TseDDLTruncateTablePartitionDef *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &tc_db__tse_ddltruncate_table_partition_def__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
TcDb__TseDDLTruncateTablePartitionDef *
       tc_db__tse_ddltruncate_table_partition_def__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (TcDb__TseDDLTruncateTablePartitionDef *)
     protobuf_c_message_unpack (&tc_db__tse_ddltruncate_table_partition_def__descriptor,
                                allocator, len, data);
}
void   tc_db__tse_ddltruncate_table_partition_def__free_unpacked
                     (TcDb__TseDDLTruncateTablePartitionDef *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &tc_db__tse_ddltruncate_table_partition_def__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   tc_db__tse_ddlrename_table_def__init
                     (TcDb__TseDDLRenameTableDef         *message)
{
  static const TcDb__TseDDLRenameTableDef init_value = TC_DB__TSE_DDLRENAME_TABLE_DEF__INIT;
  *message = init_value;
}
size_t tc_db__tse_ddlrename_table_def__get_packed_size
                     (const TcDb__TseDDLRenameTableDef *message)
{
  assert(message->base.descriptor == &tc_db__tse_ddlrename_table_def__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t tc_db__tse_ddlrename_table_def__pack
                     (const TcDb__TseDDLRenameTableDef *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &tc_db__tse_ddlrename_table_def__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t tc_db__tse_ddlrename_table_def__pack_to_buffer
                     (const TcDb__TseDDLRenameTableDef *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &tc_db__tse_ddlrename_table_def__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
TcDb__TseDDLRenameTableDef *
       tc_db__tse_ddlrename_table_def__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (TcDb__TseDDLRenameTableDef *)
     protobuf_c_message_unpack (&tc_db__tse_ddlrename_table_def__descriptor,
                                allocator, len, data);
}
void   tc_db__tse_ddlrename_table_def__free_unpacked
                     (TcDb__TseDDLRenameTableDef *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &tc_db__tse_ddlrename_table_def__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   tc_db__tse_ddldrop_table_def__init
                     (TcDb__TseDDLDropTableDef         *message)
{
  static const TcDb__TseDDLDropTableDef init_value = TC_DB__TSE_DDLDROP_TABLE_DEF__INIT;
  *message = init_value;
}
size_t tc_db__tse_ddldrop_table_def__get_packed_size
                     (const TcDb__TseDDLDropTableDef *message)
{
  assert(message->base.descriptor == &tc_db__tse_ddldrop_table_def__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t tc_db__tse_ddldrop_table_def__pack
                     (const TcDb__TseDDLDropTableDef *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &tc_db__tse_ddldrop_table_def__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t tc_db__tse_ddldrop_table_def__pack_to_buffer
                     (const TcDb__TseDDLDropTableDef *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &tc_db__tse_ddldrop_table_def__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
TcDb__TseDDLDropTableDef *
       tc_db__tse_ddldrop_table_def__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (TcDb__TseDDLDropTableDef *)
     protobuf_c_message_unpack (&tc_db__tse_ddldrop_table_def__descriptor,
                                allocator, len, data);
}
void   tc_db__tse_ddldrop_table_def__free_unpacked
                     (TcDb__TseDDLDropTableDef *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &tc_db__tse_ddldrop_table_def__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   tc_db__tse_ddlalter_index_def__init
                     (TcDb__TseDDLAlterIndexDef         *message)
{
  static const TcDb__TseDDLAlterIndexDef init_value = TC_DB__TSE_DDLALTER_INDEX_DEF__INIT;
  *message = init_value;
}
size_t tc_db__tse_ddlalter_index_def__get_packed_size
                     (const TcDb__TseDDLAlterIndexDef *message)
{
  assert(message->base.descriptor == &tc_db__tse_ddlalter_index_def__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t tc_db__tse_ddlalter_index_def__pack
                     (const TcDb__TseDDLAlterIndexDef *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &tc_db__tse_ddlalter_index_def__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t tc_db__tse_ddlalter_index_def__pack_to_buffer
                     (const TcDb__TseDDLAlterIndexDef *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &tc_db__tse_ddlalter_index_def__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
TcDb__TseDDLAlterIndexDef *
       tc_db__tse_ddlalter_index_def__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (TcDb__TseDDLAlterIndexDef *)
     protobuf_c_message_unpack (&tc_db__tse_ddlalter_index_def__descriptor,
                                allocator, len, data);
}
void   tc_db__tse_ddlalter_index_def__free_unpacked
                     (TcDb__TseDDLAlterIndexDef *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &tc_db__tse_ddlalter_index_def__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   tc_db__tse_ddlauto_extend_def__init
                     (TcDb__TseDDLAutoExtendDef         *message)
{
  static const TcDb__TseDDLAutoExtendDef init_value = TC_DB__TSE_DDLAUTO_EXTEND_DEF__INIT;
  *message = init_value;
}
size_t tc_db__tse_ddlauto_extend_def__get_packed_size
                     (const TcDb__TseDDLAutoExtendDef *message)
{
  assert(message->base.descriptor == &tc_db__tse_ddlauto_extend_def__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t tc_db__tse_ddlauto_extend_def__pack
                     (const TcDb__TseDDLAutoExtendDef *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &tc_db__tse_ddlauto_extend_def__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t tc_db__tse_ddlauto_extend_def__pack_to_buffer
                     (const TcDb__TseDDLAutoExtendDef *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &tc_db__tse_ddlauto_extend_def__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
TcDb__TseDDLAutoExtendDef *
       tc_db__tse_ddlauto_extend_def__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (TcDb__TseDDLAutoExtendDef *)
     protobuf_c_message_unpack (&tc_db__tse_ddlauto_extend_def__descriptor,
                                allocator, len, data);
}
void   tc_db__tse_ddlauto_extend_def__free_unpacked
                     (TcDb__TseDDLAutoExtendDef *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &tc_db__tse_ddlauto_extend_def__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   tc_db__tse_ddldata_file_def__init
                     (TcDb__TseDDLDataFileDef         *message)
{
  static const TcDb__TseDDLDataFileDef init_value = TC_DB__TSE_DDLDATA_FILE_DEF__INIT;
  *message = init_value;
}
size_t tc_db__tse_ddldata_file_def__get_packed_size
                     (const TcDb__TseDDLDataFileDef *message)
{
  assert(message->base.descriptor == &tc_db__tse_ddldata_file_def__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t tc_db__tse_ddldata_file_def__pack
                     (const TcDb__TseDDLDataFileDef *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &tc_db__tse_ddldata_file_def__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t tc_db__tse_ddldata_file_def__pack_to_buffer
                     (const TcDb__TseDDLDataFileDef *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &tc_db__tse_ddldata_file_def__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
TcDb__TseDDLDataFileDef *
       tc_db__tse_ddldata_file_def__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (TcDb__TseDDLDataFileDef *)
     protobuf_c_message_unpack (&tc_db__tse_ddldata_file_def__descriptor,
                                allocator, len, data);
}
void   tc_db__tse_ddldata_file_def__free_unpacked
                     (TcDb__TseDDLDataFileDef *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &tc_db__tse_ddldata_file_def__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   tc_db__tse_ddlspace_def__init
                     (TcDb__TseDDLSpaceDef         *message)
{
  static const TcDb__TseDDLSpaceDef init_value = TC_DB__TSE_DDLSPACE_DEF__INIT;
  *message = init_value;
}
size_t tc_db__tse_ddlspace_def__get_packed_size
                     (const TcDb__TseDDLSpaceDef *message)
{
  assert(message->base.descriptor == &tc_db__tse_ddlspace_def__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t tc_db__tse_ddlspace_def__pack
                     (const TcDb__TseDDLSpaceDef *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &tc_db__tse_ddlspace_def__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t tc_db__tse_ddlspace_def__pack_to_buffer
                     (const TcDb__TseDDLSpaceDef *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &tc_db__tse_ddlspace_def__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
TcDb__TseDDLSpaceDef *
       tc_db__tse_ddlspace_def__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (TcDb__TseDDLSpaceDef *)
     protobuf_c_message_unpack (&tc_db__tse_ddlspace_def__descriptor,
                                allocator, len, data);
}
void   tc_db__tse_ddlspace_def__free_unpacked
                     (TcDb__TseDDLSpaceDef *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &tc_db__tse_ddlspace_def__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   tc_db__tse_ddldrop_space_def__init
                     (TcDb__TseDDLDropSpaceDef         *message)
{
  static const TcDb__TseDDLDropSpaceDef init_value = TC_DB__TSE_DDLDROP_SPACE_DEF__INIT;
  *message = init_value;
}
size_t tc_db__tse_ddldrop_space_def__get_packed_size
                     (const TcDb__TseDDLDropSpaceDef *message)
{
  assert(message->base.descriptor == &tc_db__tse_ddldrop_space_def__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t tc_db__tse_ddldrop_space_def__pack
                     (const TcDb__TseDDLDropSpaceDef *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &tc_db__tse_ddldrop_space_def__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t tc_db__tse_ddldrop_space_def__pack_to_buffer
                     (const TcDb__TseDDLDropSpaceDef *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &tc_db__tse_ddldrop_space_def__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
TcDb__TseDDLDropSpaceDef *
       tc_db__tse_ddldrop_space_def__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (TcDb__TseDDLDropSpaceDef *)
     protobuf_c_message_unpack (&tc_db__tse_ddldrop_space_def__descriptor,
                                allocator, len, data);
}
void   tc_db__tse_ddldrop_space_def__free_unpacked
                     (TcDb__TseDDLDropSpaceDef *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &tc_db__tse_ddldrop_space_def__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   tc_db__tse_ddlalter_space_def__init
                     (TcDb__TseDDLAlterSpaceDef         *message)
{
  static const TcDb__TseDDLAlterSpaceDef init_value = TC_DB__TSE_DDLALTER_SPACE_DEF__INIT;
  *message = init_value;
}
size_t tc_db__tse_ddlalter_space_def__get_packed_size
                     (const TcDb__TseDDLAlterSpaceDef *message)
{
  assert(message->base.descriptor == &tc_db__tse_ddlalter_space_def__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t tc_db__tse_ddlalter_space_def__pack
                     (const TcDb__TseDDLAlterSpaceDef *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &tc_db__tse_ddlalter_space_def__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t tc_db__tse_ddlalter_space_def__pack_to_buffer
                     (const TcDb__TseDDLAlterSpaceDef *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &tc_db__tse_ddlalter_space_def__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
TcDb__TseDDLAlterSpaceDef *
       tc_db__tse_ddlalter_space_def__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (TcDb__TseDDLAlterSpaceDef *)
     protobuf_c_message_unpack (&tc_db__tse_ddlalter_space_def__descriptor,
                                allocator, len, data);
}
void   tc_db__tse_ddlalter_space_def__free_unpacked
                     (TcDb__TseDDLAlterSpaceDef *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &tc_db__tse_ddlalter_space_def__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
static const ProtobufCFieldDescriptor tc_db__tse_ddlcolumn_data_type_def__field_descriptors[5] =
{
  {
    "datatype",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_INT32,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLColumnDataTypeDef, datatype),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "size",
    2,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLColumnDataTypeDef, size),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "precision",
    3,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLColumnDataTypeDef, precision),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "scale",
    4,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_INT32,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLColumnDataTypeDef, scale),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "mysql_ori_datatype",
    5,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_INT32,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLColumnDataTypeDef, mysql_ori_datatype),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned tc_db__tse_ddlcolumn_data_type_def__field_indices_by_name[] = {
  0,   /* field[0] = datatype */
  4,   /* field[4] = mysql_ori_datatype */
  2,   /* field[2] = precision */
  3,   /* field[3] = scale */
  1,   /* field[1] = size */
};
static const ProtobufCIntRange tc_db__tse_ddlcolumn_data_type_def__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 5 }
};
const ProtobufCMessageDescriptor tc_db__tse_ddlcolumn_data_type_def__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "tc_db.TseDDLColumnDataTypeDef",
  "TseDDLColumnDataTypeDef",
  "TcDb__TseDDLColumnDataTypeDef",
  "tc_db",
  sizeof(TcDb__TseDDLColumnDataTypeDef),
  5,
  tc_db__tse_ddlcolumn_data_type_def__field_descriptors,
  tc_db__tse_ddlcolumn_data_type_def__field_indices_by_name,
  1,  tc_db__tse_ddlcolumn_data_type_def__number_ranges,
  (ProtobufCMessageInit) tc_db__tse_ddlcolumn_data_type_def__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor tc_db__tse_ddlcolumn_def__field_descriptors[14] =
{
  {
    "name",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLColumnDef, name),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "datatype",
    2,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLColumnDef, datatype),
    &tc_db__tse_ddlcolumn_data_type_def__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "is_option_set",
    4,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLColumnDef, is_option_set),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "col_id",
    5,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLColumnDef, col_id),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "cons_name",
    6,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLColumnDef, cons_name),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "ref_user",
    10,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLColumnDef, ref_user),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "ref_table",
    11,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLColumnDef, ref_table),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "default_text",
    12,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLColumnDef, default_text),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "comment",
    13,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLColumnDef, comment),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "alter_mode",
    14,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLColumnDef, alter_mode),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "collate",
    15,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT64,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLColumnDef, collate),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "new_name",
    16,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLColumnDef, new_name),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "is_unsigned",
    17,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLColumnDef, is_unsigned),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "default_func_name",
    18,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLColumnDef, default_func_name),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned tc_db__tse_ddlcolumn_def__field_indices_by_name[] = {
  9,   /* field[9] = alter_mode */
  3,   /* field[3] = col_id */
  10,   /* field[10] = collate */
  8,   /* field[8] = comment */
  4,   /* field[4] = cons_name */
  1,   /* field[1] = datatype */
  13,   /* field[13] = default_func_name */
  7,   /* field[7] = default_text */
  2,   /* field[2] = is_option_set */
  12,   /* field[12] = is_unsigned */
  0,   /* field[0] = name */
  11,   /* field[11] = new_name */
  6,   /* field[6] = ref_table */
  5,   /* field[5] = ref_user */
};
static const ProtobufCIntRange tc_db__tse_ddlcolumn_def__number_ranges[3 + 1] =
{
  { 1, 0 },
  { 4, 2 },
  { 10, 5 },
  { 0, 14 }
};
const ProtobufCMessageDescriptor tc_db__tse_ddlcolumn_def__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "tc_db.TseDDLColumnDef",
  "TseDDLColumnDef",
  "TcDb__TseDDLColumnDef",
  "tc_db",
  sizeof(TcDb__TseDDLColumnDef),
  14,
  tc_db__tse_ddlcolumn_def__field_descriptors,
  tc_db__tse_ddlcolumn_def__field_indices_by_name,
  3,  tc_db__tse_ddlcolumn_def__number_ranges,
  (ProtobufCMessageInit) tc_db__tse_ddlcolumn_def__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor tc_db__tse_ddlforeign_key_element_def__field_descriptors[2] =
{
  {
    "src_column_name",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLForeignKeyElementDef, src_column_name),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "ref_column_name",
    2,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLForeignKeyElementDef, ref_column_name),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned tc_db__tse_ddlforeign_key_element_def__field_indices_by_name[] = {
  1,   /* field[1] = ref_column_name */
  0,   /* field[0] = src_column_name */
};
static const ProtobufCIntRange tc_db__tse_ddlforeign_key_element_def__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 2 }
};
const ProtobufCMessageDescriptor tc_db__tse_ddlforeign_key_element_def__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "tc_db.TseDDLForeignKeyElementDef",
  "TseDDLForeignKeyElementDef",
  "TcDb__TseDDLForeignKeyElementDef",
  "tc_db",
  sizeof(TcDb__TseDDLForeignKeyElementDef),
  2,
  tc_db__tse_ddlforeign_key_element_def__field_descriptors,
  tc_db__tse_ddlforeign_key_element_def__field_indices_by_name,
  1,  tc_db__tse_ddlforeign_key_element_def__number_ranges,
  (ProtobufCMessageInit) tc_db__tse_ddlforeign_key_element_def__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor tc_db__tse_ddlforeign_key_def__field_descriptors[8] =
{
  {
    "name",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLForeignKeyDef, name),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "unique_index_name",
    2,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLForeignKeyDef, unique_index_name),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "match_opt",
    3,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLForeignKeyDef, match_opt),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "update_opt",
    4,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLForeignKeyDef, update_opt),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "delete_opt",
    5,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLForeignKeyDef, delete_opt),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "referenced_table_schema_name",
    6,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLForeignKeyDef, referenced_table_schema_name),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "referenced_table_name",
    7,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLForeignKeyDef, referenced_table_name),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "elements",
    8,
    PROTOBUF_C_LABEL_REPEATED,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(TcDb__TseDDLForeignKeyDef, n_elements),
    offsetof(TcDb__TseDDLForeignKeyDef, elements),
    &tc_db__tse_ddlforeign_key_element_def__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned tc_db__tse_ddlforeign_key_def__field_indices_by_name[] = {
  4,   /* field[4] = delete_opt */
  7,   /* field[7] = elements */
  2,   /* field[2] = match_opt */
  0,   /* field[0] = name */
  6,   /* field[6] = referenced_table_name */
  5,   /* field[5] = referenced_table_schema_name */
  1,   /* field[1] = unique_index_name */
  3,   /* field[3] = update_opt */
};
static const ProtobufCIntRange tc_db__tse_ddlforeign_key_def__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 8 }
};
const ProtobufCMessageDescriptor tc_db__tse_ddlforeign_key_def__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "tc_db.TseDDLForeignKeyDef",
  "TseDDLForeignKeyDef",
  "TcDb__TseDDLForeignKeyDef",
  "tc_db",
  sizeof(TcDb__TseDDLForeignKeyDef),
  8,
  tc_db__tse_ddlforeign_key_def__field_descriptors,
  tc_db__tse_ddlforeign_key_def__field_indices_by_name,
  1,  tc_db__tse_ddlforeign_key_def__number_ranges,
  (ProtobufCMessageInit) tc_db__tse_ddlforeign_key_def__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor tc_db__tse_ddltable_key_part__field_descriptors[6] =
{
  {
    "name",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLTableKeyPart, name),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "length",
    2,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLTableKeyPart, length),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "datatype",
    3,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_INT32,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLTableKeyPart, datatype),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "is_func",
    4,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BOOL,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLTableKeyPart, is_func),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "func_text",
    5,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLTableKeyPart, func_text),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "func_name",
    6,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLTableKeyPart, func_name),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned tc_db__tse_ddltable_key_part__field_indices_by_name[] = {
  2,   /* field[2] = datatype */
  5,   /* field[5] = func_name */
  4,   /* field[4] = func_text */
  3,   /* field[3] = is_func */
  1,   /* field[1] = length */
  0,   /* field[0] = name */
};
static const ProtobufCIntRange tc_db__tse_ddltable_key_part__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 6 }
};
const ProtobufCMessageDescriptor tc_db__tse_ddltable_key_part__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "tc_db.TseDDLTableKeyPart",
  "TseDDLTableKeyPart",
  "TcDb__TseDDLTableKeyPart",
  "tc_db",
  sizeof(TcDb__TseDDLTableKeyPart),
  6,
  tc_db__tse_ddltable_key_part__field_descriptors,
  tc_db__tse_ddltable_key_part__field_indices_by_name,
  1,  tc_db__tse_ddltable_key_part__number_ranges,
  (ProtobufCMessageInit) tc_db__tse_ddltable_key_part__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor tc_db__tse_ddltable_key__field_descriptors[10] =
{
  {
    "user",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLTableKey, user),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "table",
    2,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLTableKey, table),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "name",
    3,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLTableKey, name),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "space",
    4,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLTableKey, space),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "key_type",
    5,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_INT32,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLTableKey, key_type),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "algorithm",
    6,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_INT32,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLTableKey, algorithm),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "is_func",
    7,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BOOL,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLTableKey, is_func),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "columns",
    8,
    PROTOBUF_C_LABEL_REPEATED,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(TcDb__TseDDLTableKey, n_columns),
    offsetof(TcDb__TseDDLTableKey, columns),
    &tc_db__tse_ddltable_key_part__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "is_constraint",
    9,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BOOL,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLTableKey, is_constraint),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "is_dsc",
    10,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BOOL,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLTableKey, is_dsc),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned tc_db__tse_ddltable_key__field_indices_by_name[] = {
  5,   /* field[5] = algorithm */
  7,   /* field[7] = columns */
  8,   /* field[8] = is_constraint */
  9,   /* field[9] = is_dsc */
  6,   /* field[6] = is_func */
  4,   /* field[4] = key_type */
  2,   /* field[2] = name */
  3,   /* field[3] = space */
  1,   /* field[1] = table */
  0,   /* field[0] = user */
};
static const ProtobufCIntRange tc_db__tse_ddltable_key__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 10 }
};
const ProtobufCMessageDescriptor tc_db__tse_ddltable_key__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "tc_db.TseDDLTableKey",
  "TseDDLTableKey",
  "TcDb__TseDDLTableKey",
  "tc_db",
  sizeof(TcDb__TseDDLTableKey),
  10,
  tc_db__tse_ddltable_key__field_descriptors,
  tc_db__tse_ddltable_key__field_indices_by_name,
  1,  tc_db__tse_ddltable_key__number_ranges,
  (ProtobufCMessageInit) tc_db__tse_ddltable_key__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor tc_db__tse_msg_comm_def__field_descriptors[4] =
{
  {
    "inst_id",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseMsgCommDef, inst_id),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "thd_id",
    2,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseMsgCommDef, thd_id),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "handler_id",
    3,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseMsgCommDef, handler_id),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "sess_addr",
    4,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT64,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseMsgCommDef, sess_addr),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned tc_db__tse_msg_comm_def__field_indices_by_name[] = {
  2,   /* field[2] = handler_id */
  0,   /* field[0] = inst_id */
  3,   /* field[3] = sess_addr */
  1,   /* field[1] = thd_id */
};
static const ProtobufCIntRange tc_db__tse_msg_comm_def__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 4 }
};
const ProtobufCMessageDescriptor tc_db__tse_msg_comm_def__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "tc_db.TseMsgCommDef",
  "TseMsgCommDef",
  "TcDb__TseMsgCommDef",
  "tc_db",
  sizeof(TcDb__TseMsgCommDef),
  4,
  tc_db__tse_msg_comm_def__field_descriptors,
  tc_db__tse_msg_comm_def__field_indices_by_name,
  1,  tc_db__tse_msg_comm_def__number_ranges,
  (ProtobufCMessageInit) tc_db__tse_msg_comm_def__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor tc_db__tse_ddlpartition_table_def__field_descriptors[2] =
{
  {
    "name",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLPartitionTableDef, name),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "subpart_table_list",
    2,
    PROTOBUF_C_LABEL_REPEATED,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(TcDb__TseDDLPartitionTableDef, n_subpart_table_list),
    offsetof(TcDb__TseDDLPartitionTableDef, subpart_table_list),
    &tc_db__tse_ddlpartition_table_def__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned tc_db__tse_ddlpartition_table_def__field_indices_by_name[] = {
  0,   /* field[0] = name */
  1,   /* field[1] = subpart_table_list */
};
static const ProtobufCIntRange tc_db__tse_ddlpartition_table_def__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 2 }
};
const ProtobufCMessageDescriptor tc_db__tse_ddlpartition_table_def__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "tc_db.TseDDLPartitionTableDef",
  "TseDDLPartitionTableDef",
  "TcDb__TseDDLPartitionTableDef",
  "tc_db",
  sizeof(TcDb__TseDDLPartitionTableDef),
  2,
  tc_db__tse_ddlpartition_table_def__field_descriptors,
  tc_db__tse_ddlpartition_table_def__field_indices_by_name,
  1,  tc_db__tse_ddlpartition_table_def__number_ranges,
  (ProtobufCMessageInit) tc_db__tse_ddlpartition_table_def__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor tc_db__tse_ddlpartition_def__field_descriptors[3] =
{
  {
    "part_type",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLPartitionDef, part_type),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "subpart_type",
    2,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLPartitionDef, subpart_type),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "part_table_list",
    3,
    PROTOBUF_C_LABEL_REPEATED,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(TcDb__TseDDLPartitionDef, n_part_table_list),
    offsetof(TcDb__TseDDLPartitionDef, part_table_list),
    &tc_db__tse_ddlpartition_table_def__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned tc_db__tse_ddlpartition_def__field_indices_by_name[] = {
  2,   /* field[2] = part_table_list */
  0,   /* field[0] = part_type */
  1,   /* field[1] = subpart_type */
};
static const ProtobufCIntRange tc_db__tse_ddlpartition_def__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 3 }
};
const ProtobufCMessageDescriptor tc_db__tse_ddlpartition_def__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "tc_db.TseDDLPartitionDef",
  "TseDDLPartitionDef",
  "TcDb__TseDDLPartitionDef",
  "tc_db",
  sizeof(TcDb__TseDDLPartitionDef),
  3,
  tc_db__tse_ddlpartition_def__field_descriptors,
  tc_db__tse_ddlpartition_def__field_indices_by_name,
  1,  tc_db__tse_ddlpartition_def__number_ranges,
  (ProtobufCMessageInit) tc_db__tse_ddlpartition_def__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor tc_db__tse_ddlcreate_table_def__field_descriptors[14] =
{
  {
    "schema",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLCreateTableDef, schema),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "name",
    2,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLCreateTableDef, name),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "space",
    3,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLCreateTableDef, space),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "columns",
    4,
    PROTOBUF_C_LABEL_REPEATED,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(TcDb__TseDDLCreateTableDef, n_columns),
    offsetof(TcDb__TseDDLCreateTableDef, columns),
    &tc_db__tse_ddlcolumn_def__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "fk_list",
    5,
    PROTOBUF_C_LABEL_REPEATED,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(TcDb__TseDDLCreateTableDef, n_fk_list),
    offsetof(TcDb__TseDDLCreateTableDef, fk_list),
    &tc_db__tse_ddlforeign_key_def__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "key_list",
    6,
    PROTOBUF_C_LABEL_REPEATED,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(TcDb__TseDDLCreateTableDef, n_key_list),
    offsetof(TcDb__TseDDLCreateTableDef, key_list),
    &tc_db__tse_ddltable_key__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "auto_increment_value",
    7,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT64,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLCreateTableDef, auto_increment_value),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "options",
    8,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLCreateTableDef, options),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "db_name",
    9,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLCreateTableDef, db_name),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "sql_str",
    10,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLCreateTableDef, sql_str),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "alter_table_name",
    11,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLCreateTableDef, alter_table_name),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "alter_db_name",
    12,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLCreateTableDef, alter_db_name),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "is_create_as_select",
    13,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BOOL,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLCreateTableDef, is_create_as_select),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "partition_def",
    14,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLCreateTableDef, partition_def),
    &tc_db__tse_ddlpartition_def__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned tc_db__tse_ddlcreate_table_def__field_indices_by_name[] = {
  11,   /* field[11] = alter_db_name */
  10,   /* field[10] = alter_table_name */
  6,   /* field[6] = auto_increment_value */
  3,   /* field[3] = columns */
  8,   /* field[8] = db_name */
  4,   /* field[4] = fk_list */
  12,   /* field[12] = is_create_as_select */
  5,   /* field[5] = key_list */
  1,   /* field[1] = name */
  7,   /* field[7] = options */
  13,   /* field[13] = partition_def */
  0,   /* field[0] = schema */
  2,   /* field[2] = space */
  9,   /* field[9] = sql_str */
};
static const ProtobufCIntRange tc_db__tse_ddlcreate_table_def__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 14 }
};
const ProtobufCMessageDescriptor tc_db__tse_ddlcreate_table_def__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "tc_db.TseDDLCreateTableDef",
  "TseDDLCreateTableDef",
  "TcDb__TseDDLCreateTableDef",
  "tc_db",
  sizeof(TcDb__TseDDLCreateTableDef),
  14,
  tc_db__tse_ddlcreate_table_def__field_descriptors,
  tc_db__tse_ddlcreate_table_def__field_indices_by_name,
  1,  tc_db__tse_ddlcreate_table_def__number_ranges,
  (ProtobufCMessageInit) tc_db__tse_ddlcreate_table_def__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor tc_db__tse_ddlalter_table_porp__field_descriptors[6] =
{
  {
    "new_name",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLAlterTablePorp, new_name),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "pctfree",
    2,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLAlterTablePorp, pctfree),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "appendonly",
    3,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLAlterTablePorp, appendonly),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "enable_row_move",
    4,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLAlterTablePorp, enable_row_move),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "shrink_opt",
    5,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLAlterTablePorp, shrink_opt),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "serial_start",
    6,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_INT64,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLAlterTablePorp, serial_start),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned tc_db__tse_ddlalter_table_porp__field_indices_by_name[] = {
  2,   /* field[2] = appendonly */
  3,   /* field[3] = enable_row_move */
  0,   /* field[0] = new_name */
  1,   /* field[1] = pctfree */
  5,   /* field[5] = serial_start */
  4,   /* field[4] = shrink_opt */
};
static const ProtobufCIntRange tc_db__tse_ddlalter_table_porp__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 6 }
};
const ProtobufCMessageDescriptor tc_db__tse_ddlalter_table_porp__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "tc_db.TseDDLAlterTablePorp",
  "TseDDLAlterTablePorp",
  "TcDb__TseDDLAlterTablePorp",
  "tc_db",
  sizeof(TcDb__TseDDLAlterTablePorp),
  6,
  tc_db__tse_ddlalter_table_porp__field_descriptors,
  tc_db__tse_ddlalter_table_porp__field_indices_by_name,
  1,  tc_db__tse_ddlalter_table_porp__number_ranges,
  (ProtobufCMessageInit) tc_db__tse_ddlalter_table_porp__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor tc_db__tse_ddlalter_table_drop__field_descriptors[3] =
{
  {
    "name",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLAlterTableDrop, name),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "drop_type",
    2,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_INT32,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLAlterTableDrop, drop_type),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "key_type",
    3,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_INT32,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLAlterTableDrop, key_type),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned tc_db__tse_ddlalter_table_drop__field_indices_by_name[] = {
  1,   /* field[1] = drop_type */
  2,   /* field[2] = key_type */
  0,   /* field[0] = name */
};
static const ProtobufCIntRange tc_db__tse_ddlalter_table_drop__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 3 }
};
const ProtobufCMessageDescriptor tc_db__tse_ddlalter_table_drop__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "tc_db.TseDDLAlterTableDrop",
  "TseDDLAlterTableDrop",
  "TcDb__TseDDLAlterTableDrop",
  "tc_db",
  sizeof(TcDb__TseDDLAlterTableDrop),
  3,
  tc_db__tse_ddlalter_table_drop__field_descriptors,
  tc_db__tse_ddlalter_table_drop__field_indices_by_name,
  1,  tc_db__tse_ddlalter_table_drop__number_ranges,
  (ProtobufCMessageInit) tc_db__tse_ddlalter_table_drop__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor tc_db__tse_ddlalter_table_drop_key__field_descriptors[3] =
{
  {
    "name",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLAlterTableDropKey, name),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "drop_type",
    2,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_INT32,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLAlterTableDropKey, drop_type),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "key_type",
    3,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_INT32,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLAlterTableDropKey, key_type),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned tc_db__tse_ddlalter_table_drop_key__field_indices_by_name[] = {
  1,   /* field[1] = drop_type */
  2,   /* field[2] = key_type */
  0,   /* field[0] = name */
};
static const ProtobufCIntRange tc_db__tse_ddlalter_table_drop_key__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 3 }
};
const ProtobufCMessageDescriptor tc_db__tse_ddlalter_table_drop_key__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "tc_db.TseDDLAlterTableDropKey",
  "TseDDLAlterTableDropKey",
  "TcDb__TseDDLAlterTableDropKey",
  "tc_db",
  sizeof(TcDb__TseDDLAlterTableDropKey),
  3,
  tc_db__tse_ddlalter_table_drop_key__field_descriptors,
  tc_db__tse_ddlalter_table_drop_key__field_indices_by_name,
  1,  tc_db__tse_ddlalter_table_drop_key__number_ranges,
  (ProtobufCMessageInit) tc_db__tse_ddlalter_table_drop_key__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor tc_db__tse_ddlalter_table_alter_column__field_descriptors[7] =
{
  {
    "name",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLAlterTableAlterColumn, name),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "new_name",
    2,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLAlterTableAlterColumn, new_name),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "type",
    3,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLAlterTableAlterColumn, type),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "has_no_default",
    4,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BOOL,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLAlterTableAlterColumn, has_no_default),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "has_default",
    5,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BOOL,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLAlterTableAlterColumn, has_default),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "is_default_null",
    6,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BOOL,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLAlterTableAlterColumn, is_default_null),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "default_text",
    7,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLAlterTableAlterColumn, default_text),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned tc_db__tse_ddlalter_table_alter_column__field_indices_by_name[] = {
  6,   /* field[6] = default_text */
  4,   /* field[4] = has_default */
  3,   /* field[3] = has_no_default */
  5,   /* field[5] = is_default_null */
  0,   /* field[0] = name */
  1,   /* field[1] = new_name */
  2,   /* field[2] = type */
};
static const ProtobufCIntRange tc_db__tse_ddlalter_table_alter_column__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 7 }
};
const ProtobufCMessageDescriptor tc_db__tse_ddlalter_table_alter_column__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "tc_db.TseDDLAlterTableAlterColumn",
  "TseDDLAlterTableAlterColumn",
  "TcDb__TseDDLAlterTableAlterColumn",
  "tc_db",
  sizeof(TcDb__TseDDLAlterTableAlterColumn),
  7,
  tc_db__tse_ddlalter_table_alter_column__field_descriptors,
  tc_db__tse_ddlalter_table_alter_column__field_indices_by_name,
  1,  tc_db__tse_ddlalter_table_alter_column__number_ranges,
  (ProtobufCMessageInit) tc_db__tse_ddlalter_table_alter_column__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor tc_db__tse_ddlalter_table_def__field_descriptors[20] =
{
  {
    "action",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLAlterTableDef, action),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "options",
    2,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLAlterTableDef, options),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "user",
    3,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLAlterTableDef, user),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "name",
    4,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLAlterTableDef, name),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "drop_list",
    5,
    PROTOBUF_C_LABEL_REPEATED,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(TcDb__TseDDLAlterTableDef, n_drop_list),
    offsetof(TcDb__TseDDLAlterTableDef, drop_list),
    &tc_db__tse_ddlalter_table_drop__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "alter_list",
    6,
    PROTOBUF_C_LABEL_REPEATED,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(TcDb__TseDDLAlterTableDef, n_alter_list),
    offsetof(TcDb__TseDDLAlterTableDef, alter_list),
    &tc_db__tse_ddlalter_table_alter_column__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "create_list",
    7,
    PROTOBUF_C_LABEL_REPEATED,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(TcDb__TseDDLAlterTableDef, n_create_list),
    offsetof(TcDb__TseDDLAlterTableDef, create_list),
    &tc_db__tse_ddlcolumn_def__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "table_def",
    8,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLAlterTableDef, table_def),
    &tc_db__tse_ddlalter_table_porp__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "add_key_list",
    9,
    PROTOBUF_C_LABEL_REPEATED,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(TcDb__TseDDLAlterTableDef, n_add_key_list),
    offsetof(TcDb__TseDDLAlterTableDef, add_key_list),
    &tc_db__tse_ddltable_key__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "drop_key_list",
    10,
    PROTOBUF_C_LABEL_REPEATED,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(TcDb__TseDDLAlterTableDef, n_drop_key_list),
    offsetof(TcDb__TseDDLAlterTableDef, drop_key_list),
    &tc_db__tse_ddlalter_table_drop_key__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "add_foreign_key_list",
    11,
    PROTOBUF_C_LABEL_REPEATED,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(TcDb__TseDDLAlterTableDef, n_add_foreign_key_list),
    offsetof(TcDb__TseDDLAlterTableDef, add_foreign_key_list),
    &tc_db__tse_ddlforeign_key_def__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "new_auto_increment_value",
    12,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT64,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLAlterTableDef, new_auto_increment_value),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "db_name",
    13,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLAlterTableDef, db_name),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "sql_str",
    14,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLAlterTableDef, sql_str),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "alter_index_list",
    15,
    PROTOBUF_C_LABEL_REPEATED,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(TcDb__TseDDLAlterTableDef, n_alter_index_list),
    offsetof(TcDb__TseDDLAlterTableDef, alter_index_list),
    &tc_db__tse_ddlalter_index_def__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "drop_partition_names",
    16,
    PROTOBUF_C_LABEL_REPEATED,
    PROTOBUF_C_TYPE_STRING,
    offsetof(TcDb__TseDDLAlterTableDef, n_drop_partition_names),
    offsetof(TcDb__TseDDLAlterTableDef, drop_partition_names),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "add_part_list",
    17,
    PROTOBUF_C_LABEL_REPEATED,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(TcDb__TseDDLAlterTableDef, n_add_part_list),
    offsetof(TcDb__TseDDLAlterTableDef, add_part_list),
    &tc_db__tse_ddlpartition_table_def__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "hash_coalesce_count",
    18,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLAlterTableDef, hash_coalesce_count),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "systimestamp",
    19,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_INT64,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLAlterTableDef, systimestamp),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "tz_offset_UTC",
    20,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_INT32,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLAlterTableDef, tz_offset_utc),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned tc_db__tse_ddlalter_table_def__field_indices_by_name[] = {
  0,   /* field[0] = action */
  10,   /* field[10] = add_foreign_key_list */
  8,   /* field[8] = add_key_list */
  16,   /* field[16] = add_part_list */
  14,   /* field[14] = alter_index_list */
  5,   /* field[5] = alter_list */
  6,   /* field[6] = create_list */
  12,   /* field[12] = db_name */
  9,   /* field[9] = drop_key_list */
  4,   /* field[4] = drop_list */
  15,   /* field[15] = drop_partition_names */
  17,   /* field[17] = hash_coalesce_count */
  3,   /* field[3] = name */
  11,   /* field[11] = new_auto_increment_value */
  1,   /* field[1] = options */
  13,   /* field[13] = sql_str */
  18,   /* field[18] = systimestamp */
  7,   /* field[7] = table_def */
  19,   /* field[19] = tz_offset_UTC */
  2,   /* field[2] = user */
};
static const ProtobufCIntRange tc_db__tse_ddlalter_table_def__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 20 }
};
const ProtobufCMessageDescriptor tc_db__tse_ddlalter_table_def__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "tc_db.TseDDLAlterTableDef",
  "TseDDLAlterTableDef",
  "TcDb__TseDDLAlterTableDef",
  "tc_db",
  sizeof(TcDb__TseDDLAlterTableDef),
  20,
  tc_db__tse_ddlalter_table_def__field_descriptors,
  tc_db__tse_ddlalter_table_def__field_indices_by_name,
  1,  tc_db__tse_ddlalter_table_def__number_ranges,
  (ProtobufCMessageInit) tc_db__tse_ddlalter_table_def__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor tc_db__tse_ddltruncate_table_def__field_descriptors[5] =
{
  {
    "schema",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLTruncateTableDef, schema),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "name",
    2,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLTruncateTableDef, name),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "db_name",
    4,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLTruncateTableDef, db_name),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "sql_str",
    5,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLTruncateTableDef, sql_str),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "no_check_fk",
    6,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLTruncateTableDef, no_check_fk),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned tc_db__tse_ddltruncate_table_def__field_indices_by_name[] = {
  2,   /* field[2] = db_name */
  1,   /* field[1] = name */
  4,   /* field[4] = no_check_fk */
  0,   /* field[0] = schema */
  3,   /* field[3] = sql_str */
};
static const ProtobufCIntRange tc_db__tse_ddltruncate_table_def__number_ranges[2 + 1] =
{
  { 1, 0 },
  { 4, 2 },
  { 0, 5 }
};
const ProtobufCMessageDescriptor tc_db__tse_ddltruncate_table_def__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "tc_db.TseDDLTruncateTableDef",
  "TseDDLTruncateTableDef",
  "TcDb__TseDDLTruncateTableDef",
  "tc_db",
  sizeof(TcDb__TseDDLTruncateTableDef),
  5,
  tc_db__tse_ddltruncate_table_def__field_descriptors,
  tc_db__tse_ddltruncate_table_def__field_indices_by_name,
  2,  tc_db__tse_ddltruncate_table_def__number_ranges,
  (ProtobufCMessageInit) tc_db__tse_ddltruncate_table_def__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor tc_db__tse_ddltruncate_table_partition_def__field_descriptors[9] =
{
  {
    "user",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLTruncateTablePartitionDef, user),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "db_name",
    2,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLTruncateTablePartitionDef, db_name),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "table_name",
    3,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLTruncateTablePartitionDef, table_name),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "partition_name",
    4,
    PROTOBUF_C_LABEL_REPEATED,
    PROTOBUF_C_TYPE_STRING,
    offsetof(TcDb__TseDDLTruncateTablePartitionDef, n_partition_name),
    offsetof(TcDb__TseDDLTruncateTablePartitionDef, partition_name),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "partition_id",
    5,
    PROTOBUF_C_LABEL_REPEATED,
    PROTOBUF_C_TYPE_UINT32,
    offsetof(TcDb__TseDDLTruncateTablePartitionDef, n_partition_id),
    offsetof(TcDb__TseDDLTruncateTablePartitionDef, partition_id),
    NULL,
    NULL,
    0 | PROTOBUF_C_FIELD_FLAG_PACKED,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "sql_str",
    6,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLTruncateTablePartitionDef, sql_str),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "is_subpart",
    7,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BOOL,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLTruncateTablePartitionDef, is_subpart),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "subpartition_name",
    8,
    PROTOBUF_C_LABEL_REPEATED,
    PROTOBUF_C_TYPE_STRING,
    offsetof(TcDb__TseDDLTruncateTablePartitionDef, n_subpartition_name),
    offsetof(TcDb__TseDDLTruncateTablePartitionDef, subpartition_name),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "subpartition_id",
    9,
    PROTOBUF_C_LABEL_REPEATED,
    PROTOBUF_C_TYPE_UINT32,
    offsetof(TcDb__TseDDLTruncateTablePartitionDef, n_subpartition_id),
    offsetof(TcDb__TseDDLTruncateTablePartitionDef, subpartition_id),
    NULL,
    NULL,
    0 | PROTOBUF_C_FIELD_FLAG_PACKED,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned tc_db__tse_ddltruncate_table_partition_def__field_indices_by_name[] = {
  1,   /* field[1] = db_name */
  6,   /* field[6] = is_subpart */
  4,   /* field[4] = partition_id */
  3,   /* field[3] = partition_name */
  5,   /* field[5] = sql_str */
  8,   /* field[8] = subpartition_id */
  7,   /* field[7] = subpartition_name */
  2,   /* field[2] = table_name */
  0,   /* field[0] = user */
};
static const ProtobufCIntRange tc_db__tse_ddltruncate_table_partition_def__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 9 }
};
const ProtobufCMessageDescriptor tc_db__tse_ddltruncate_table_partition_def__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "tc_db.TseDDLTruncateTablePartitionDef",
  "TseDDLTruncateTablePartitionDef",
  "TcDb__TseDDLTruncateTablePartitionDef",
  "tc_db",
  sizeof(TcDb__TseDDLTruncateTablePartitionDef),
  9,
  tc_db__tse_ddltruncate_table_partition_def__field_descriptors,
  tc_db__tse_ddltruncate_table_partition_def__field_indices_by_name,
  1,  tc_db__tse_ddltruncate_table_partition_def__number_ranges,
  (ProtobufCMessageInit) tc_db__tse_ddltruncate_table_partition_def__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor tc_db__tse_ddlrename_table_def__field_descriptors[12] =
{
  {
    "action",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLRenameTableDef, action),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "options",
    2,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLRenameTableDef, options),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "user",
    3,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLRenameTableDef, user),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "new_user",
    4,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLRenameTableDef, new_user),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "new_table_name",
    5,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLRenameTableDef, new_table_name),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "new_db_name",
    6,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLRenameTableDef, new_db_name),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "old_table_name",
    7,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLRenameTableDef, old_table_name),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "old_db_name",
    8,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLRenameTableDef, old_db_name),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "current_db_name",
    9,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLRenameTableDef, current_db_name),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "sql_str",
    10,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLRenameTableDef, sql_str),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "old_constraints_name",
    11,
    PROTOBUF_C_LABEL_REPEATED,
    PROTOBUF_C_TYPE_STRING,
    offsetof(TcDb__TseDDLRenameTableDef, n_old_constraints_name),
    offsetof(TcDb__TseDDLRenameTableDef, old_constraints_name),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "new_constraints_name",
    12,
    PROTOBUF_C_LABEL_REPEATED,
    PROTOBUF_C_TYPE_STRING,
    offsetof(TcDb__TseDDLRenameTableDef, n_new_constraints_name),
    offsetof(TcDb__TseDDLRenameTableDef, new_constraints_name),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned tc_db__tse_ddlrename_table_def__field_indices_by_name[] = {
  0,   /* field[0] = action */
  8,   /* field[8] = current_db_name */
  11,   /* field[11] = new_constraints_name */
  5,   /* field[5] = new_db_name */
  4,   /* field[4] = new_table_name */
  3,   /* field[3] = new_user */
  10,   /* field[10] = old_constraints_name */
  7,   /* field[7] = old_db_name */
  6,   /* field[6] = old_table_name */
  1,   /* field[1] = options */
  9,   /* field[9] = sql_str */
  2,   /* field[2] = user */
};
static const ProtobufCIntRange tc_db__tse_ddlrename_table_def__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 12 }
};
const ProtobufCMessageDescriptor tc_db__tse_ddlrename_table_def__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "tc_db.TseDDLRenameTableDef",
  "TseDDLRenameTableDef",
  "TcDb__TseDDLRenameTableDef",
  "tc_db",
  sizeof(TcDb__TseDDLRenameTableDef),
  12,
  tc_db__tse_ddlrename_table_def__field_descriptors,
  tc_db__tse_ddlrename_table_def__field_indices_by_name,
  1,  tc_db__tse_ddlrename_table_def__number_ranges,
  (ProtobufCMessageInit) tc_db__tse_ddlrename_table_def__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor tc_db__tse_ddldrop_table_def__field_descriptors[6] =
{
  {
    "options",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLDropTableDef, options),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "user",
    2,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLDropTableDef, user),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "name",
    3,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLDropTableDef, name),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "dbname_und",
    4,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLDropTableDef, dbname_und),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "db_name",
    5,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLDropTableDef, db_name),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "sql_str",
    6,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLDropTableDef, sql_str),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned tc_db__tse_ddldrop_table_def__field_indices_by_name[] = {
  4,   /* field[4] = db_name */
  3,   /* field[3] = dbname_und */
  2,   /* field[2] = name */
  0,   /* field[0] = options */
  5,   /* field[5] = sql_str */
  1,   /* field[1] = user */
};
static const ProtobufCIntRange tc_db__tse_ddldrop_table_def__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 6 }
};
const ProtobufCMessageDescriptor tc_db__tse_ddldrop_table_def__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "tc_db.TseDDLDropTableDef",
  "TseDDLDropTableDef",
  "TcDb__TseDDLDropTableDef",
  "tc_db",
  sizeof(TcDb__TseDDLDropTableDef),
  6,
  tc_db__tse_ddldrop_table_def__field_descriptors,
  tc_db__tse_ddldrop_table_def__field_indices_by_name,
  1,  tc_db__tse_ddldrop_table_def__number_ranges,
  (ProtobufCMessageInit) tc_db__tse_ddldrop_table_def__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor tc_db__tse_ddlalter_index_def__field_descriptors[6] =
{
  {
    "user",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLAlterIndexDef, user),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "name",
    2,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLAlterIndexDef, name),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "type",
    3,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLAlterIndexDef, type),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "table",
    4,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLAlterIndexDef, table),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "new_name",
    5,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLAlterIndexDef, new_name),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "key_type",
    6,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_INT32,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLAlterIndexDef, key_type),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned tc_db__tse_ddlalter_index_def__field_indices_by_name[] = {
  5,   /* field[5] = key_type */
  1,   /* field[1] = name */
  4,   /* field[4] = new_name */
  3,   /* field[3] = table */
  2,   /* field[2] = type */
  0,   /* field[0] = user */
};
static const ProtobufCIntRange tc_db__tse_ddlalter_index_def__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 6 }
};
const ProtobufCMessageDescriptor tc_db__tse_ddlalter_index_def__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "tc_db.TseDDLAlterIndexDef",
  "TseDDLAlterIndexDef",
  "TcDb__TseDDLAlterIndexDef",
  "tc_db",
  sizeof(TcDb__TseDDLAlterIndexDef),
  6,
  tc_db__tse_ddlalter_index_def__field_descriptors,
  tc_db__tse_ddlalter_index_def__field_indices_by_name,
  1,  tc_db__tse_ddlalter_index_def__number_ranges,
  (ProtobufCMessageInit) tc_db__tse_ddlalter_index_def__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor tc_db__tse_ddlauto_extend_def__field_descriptors[3] =
{
  {
    "enabled",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BOOL,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLAutoExtendDef, enabled),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "nextsize",
    2,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT64,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLAutoExtendDef, nextsize),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "maxsize",
    3,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_INT64,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLAutoExtendDef, maxsize),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned tc_db__tse_ddlauto_extend_def__field_indices_by_name[] = {
  0,   /* field[0] = enabled */
  2,   /* field[2] = maxsize */
  1,   /* field[1] = nextsize */
};
static const ProtobufCIntRange tc_db__tse_ddlauto_extend_def__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 3 }
};
const ProtobufCMessageDescriptor tc_db__tse_ddlauto_extend_def__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "tc_db.TseDDLAutoExtendDef",
  "TseDDLAutoExtendDef",
  "TcDb__TseDDLAutoExtendDef",
  "tc_db",
  sizeof(TcDb__TseDDLAutoExtendDef),
  3,
  tc_db__tse_ddlauto_extend_def__field_descriptors,
  tc_db__tse_ddlauto_extend_def__field_indices_by_name,
  1,  tc_db__tse_ddlauto_extend_def__number_ranges,
  (ProtobufCMessageInit) tc_db__tse_ddlauto_extend_def__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor tc_db__tse_ddldata_file_def__field_descriptors[5] =
{
  {
    "name",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLDataFileDef, name),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "size",
    2,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_INT64,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLDataFileDef, size),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "block_size",
    3,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_INT32,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLDataFileDef, block_size),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "autoextend",
    4,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLDataFileDef, autoextend),
    &tc_db__tse_ddlauto_extend_def__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "node_id",
    5,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLDataFileDef, node_id),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned tc_db__tse_ddldata_file_def__field_indices_by_name[] = {
  3,   /* field[3] = autoextend */
  2,   /* field[2] = block_size */
  0,   /* field[0] = name */
  4,   /* field[4] = node_id */
  1,   /* field[1] = size */
};
static const ProtobufCIntRange tc_db__tse_ddldata_file_def__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 5 }
};
const ProtobufCMessageDescriptor tc_db__tse_ddldata_file_def__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "tc_db.TseDDLDataFileDef",
  "TseDDLDataFileDef",
  "TcDb__TseDDLDataFileDef",
  "tc_db",
  sizeof(TcDb__TseDDLDataFileDef),
  5,
  tc_db__tse_ddldata_file_def__field_descriptors,
  tc_db__tse_ddldata_file_def__field_indices_by_name,
  1,  tc_db__tse_ddldata_file_def__number_ranges,
  (ProtobufCMessageInit) tc_db__tse_ddldata_file_def__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor tc_db__tse_ddlspace_def__field_descriptors[9] =
{
  {
    "name",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLSpaceDef, name),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "type",
    2,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLSpaceDef, type),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "in_memory",
    3,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BOOL,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLSpaceDef, in_memory),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "autooffline",
    4,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BOOL,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLSpaceDef, autooffline),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "extent_size",
    5,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLSpaceDef, extent_size),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "datafiles_list",
    6,
    PROTOBUF_C_LABEL_REPEATED,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(TcDb__TseDDLSpaceDef, n_datafiles_list),
    offsetof(TcDb__TseDDLSpaceDef, datafiles_list),
    &tc_db__tse_ddldata_file_def__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "flags",
    7,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLSpaceDef, flags),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "db_name",
    8,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLSpaceDef, db_name),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "sql_str",
    9,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLSpaceDef, sql_str),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned tc_db__tse_ddlspace_def__field_indices_by_name[] = {
  3,   /* field[3] = autooffline */
  5,   /* field[5] = datafiles_list */
  7,   /* field[7] = db_name */
  4,   /* field[4] = extent_size */
  6,   /* field[6] = flags */
  2,   /* field[2] = in_memory */
  0,   /* field[0] = name */
  8,   /* field[8] = sql_str */
  1,   /* field[1] = type */
};
static const ProtobufCIntRange tc_db__tse_ddlspace_def__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 9 }
};
const ProtobufCMessageDescriptor tc_db__tse_ddlspace_def__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "tc_db.TseDDLSpaceDef",
  "TseDDLSpaceDef",
  "TcDb__TseDDLSpaceDef",
  "tc_db",
  sizeof(TcDb__TseDDLSpaceDef),
  9,
  tc_db__tse_ddlspace_def__field_descriptors,
  tc_db__tse_ddlspace_def__field_indices_by_name,
  1,  tc_db__tse_ddlspace_def__number_ranges,
  (ProtobufCMessageInit) tc_db__tse_ddlspace_def__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor tc_db__tse_ddldrop_space_def__field_descriptors[4] =
{
  {
    "obj_name",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLDropSpaceDef, obj_name),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "option",
    2,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLDropSpaceDef, option),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "db_name",
    3,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLDropSpaceDef, db_name),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "sql_str",
    4,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLDropSpaceDef, sql_str),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned tc_db__tse_ddldrop_space_def__field_indices_by_name[] = {
  2,   /* field[2] = db_name */
  0,   /* field[0] = obj_name */
  1,   /* field[1] = option */
  3,   /* field[3] = sql_str */
};
static const ProtobufCIntRange tc_db__tse_ddldrop_space_def__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 4 }
};
const ProtobufCMessageDescriptor tc_db__tse_ddldrop_space_def__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "tc_db.TseDDLDropSpaceDef",
  "TseDDLDropSpaceDef",
  "TcDb__TseDDLDropSpaceDef",
  "tc_db",
  sizeof(TcDb__TseDDLDropSpaceDef),
  4,
  tc_db__tse_ddldrop_space_def__field_descriptors,
  tc_db__tse_ddldrop_space_def__field_indices_by_name,
  1,  tc_db__tse_ddldrop_space_def__number_ranges,
  (ProtobufCMessageInit) tc_db__tse_ddldrop_space_def__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor tc_db__tse_ddlalter_space_def__field_descriptors[6] =
{
  {
    "action",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLAlterSpaceDef, action),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "name",
    2,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLAlterSpaceDef, name),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "new_name",
    3,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLAlterSpaceDef, new_name),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "auto_extend_size",
    4,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT64,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLAlterSpaceDef, auto_extend_size),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "db_name",
    5,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLAlterSpaceDef, db_name),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "sql_str",
    6,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__TseDDLAlterSpaceDef, sql_str),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned tc_db__tse_ddlalter_space_def__field_indices_by_name[] = {
  0,   /* field[0] = action */
  3,   /* field[3] = auto_extend_size */
  4,   /* field[4] = db_name */
  1,   /* field[1] = name */
  2,   /* field[2] = new_name */
  5,   /* field[5] = sql_str */
};
static const ProtobufCIntRange tc_db__tse_ddlalter_space_def__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 6 }
};
const ProtobufCMessageDescriptor tc_db__tse_ddlalter_space_def__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "tc_db.TseDDLAlterSpaceDef",
  "TseDDLAlterSpaceDef",
  "TcDb__TseDDLAlterSpaceDef",
  "tc_db",
  sizeof(TcDb__TseDDLAlterSpaceDef),
  6,
  tc_db__tse_ddlalter_space_def__field_descriptors,
  tc_db__tse_ddlalter_space_def__field_indices_by_name,
  1,  tc_db__tse_ddlalter_space_def__number_ranges,
  (ProtobufCMessageInit) tc_db__tse_ddlalter_space_def__init,
  NULL,NULL,NULL    /* reserved[123] */
};
