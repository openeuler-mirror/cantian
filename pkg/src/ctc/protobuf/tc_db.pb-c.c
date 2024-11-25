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
 * src/ctc/protobuf/tc_db.pb-c.c
 *
 * -------------------------------------------------------------------------
 */
/* Generated from: tc_db.proto */

/* Do not generate deprecated warnings for self */
#ifndef PROTOBUF_C__NO_DEPRECATED
#define PROTOBUF_C__NO_DEPRECATED
#endif

#include "tc_db.pb-c.h"
void   tc_db__ctc_ddlcolumn_data_type_def__init
                     (TcDb__CtcDDLColumnDataTypeDef         *message)
{
  static const TcDb__CtcDDLColumnDataTypeDef init_value = TC_DB__CTC_DDLCOLUMN_DATA_TYPE_DEF__INIT;
  *message = init_value;
}
size_t tc_db__ctc_ddlcolumn_data_type_def__get_packed_size
                     (const TcDb__CtcDDLColumnDataTypeDef *message)
{
  assert(message->base.descriptor == &tc_db__ctc_ddlcolumn_data_type_def__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t tc_db__ctc_ddlcolumn_data_type_def__pack
                     (const TcDb__CtcDDLColumnDataTypeDef *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &tc_db__ctc_ddlcolumn_data_type_def__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t tc_db__ctc_ddlcolumn_data_type_def__pack_to_buffer
                     (const TcDb__CtcDDLColumnDataTypeDef *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &tc_db__ctc_ddlcolumn_data_type_def__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
TcDb__CtcDDLColumnDataTypeDef *
       tc_db__ctc_ddlcolumn_data_type_def__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (TcDb__CtcDDLColumnDataTypeDef *)
     protobuf_c_message_unpack (&tc_db__ctc_ddlcolumn_data_type_def__descriptor,
                                allocator, len, data);
}
void   tc_db__ctc_ddlcolumn_data_type_def__free_unpacked
                     (TcDb__CtcDDLColumnDataTypeDef *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &tc_db__ctc_ddlcolumn_data_type_def__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   tc_db__ctc_ddlcolumn_def__init
                     (TcDb__CtcDDLColumnDef         *message)
{
  static const TcDb__CtcDDLColumnDef init_value = TC_DB__CTC_DDLCOLUMN_DEF__INIT;
  *message = init_value;
}
size_t tc_db__ctc_ddlcolumn_def__get_packed_size
                     (const TcDb__CtcDDLColumnDef *message)
{
  assert(message->base.descriptor == &tc_db__ctc_ddlcolumn_def__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t tc_db__ctc_ddlcolumn_def__pack
                     (const TcDb__CtcDDLColumnDef *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &tc_db__ctc_ddlcolumn_def__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t tc_db__ctc_ddlcolumn_def__pack_to_buffer
                     (const TcDb__CtcDDLColumnDef *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &tc_db__ctc_ddlcolumn_def__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
TcDb__CtcDDLColumnDef *
       tc_db__ctc_ddlcolumn_def__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (TcDb__CtcDDLColumnDef *)
     protobuf_c_message_unpack (&tc_db__ctc_ddlcolumn_def__descriptor,
                                allocator, len, data);
}
void   tc_db__ctc_ddlcolumn_def__free_unpacked
                     (TcDb__CtcDDLColumnDef *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &tc_db__ctc_ddlcolumn_def__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   tc_db__ctc_ddlforeign_key_element_def__init
                     (TcDb__CtcDDLForeignKeyElementDef         *message)
{
  static const TcDb__CtcDDLForeignKeyElementDef init_value = TC_DB__CTC_DDLFOREIGN_KEY_ELEMENT_DEF__INIT;
  *message = init_value;
}
size_t tc_db__ctc_ddlforeign_key_element_def__get_packed_size
                     (const TcDb__CtcDDLForeignKeyElementDef *message)
{
  assert(message->base.descriptor == &tc_db__ctc_ddlforeign_key_element_def__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t tc_db__ctc_ddlforeign_key_element_def__pack
                     (const TcDb__CtcDDLForeignKeyElementDef *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &tc_db__ctc_ddlforeign_key_element_def__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t tc_db__ctc_ddlforeign_key_element_def__pack_to_buffer
                     (const TcDb__CtcDDLForeignKeyElementDef *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &tc_db__ctc_ddlforeign_key_element_def__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
TcDb__CtcDDLForeignKeyElementDef *
       tc_db__ctc_ddlforeign_key_element_def__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (TcDb__CtcDDLForeignKeyElementDef *)
     protobuf_c_message_unpack (&tc_db__ctc_ddlforeign_key_element_def__descriptor,
                                allocator, len, data);
}
void   tc_db__ctc_ddlforeign_key_element_def__free_unpacked
                     (TcDb__CtcDDLForeignKeyElementDef *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &tc_db__ctc_ddlforeign_key_element_def__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   tc_db__ctc_ddlforeign_key_def__init
                     (TcDb__CtcDDLForeignKeyDef         *message)
{
  static const TcDb__CtcDDLForeignKeyDef init_value = TC_DB__CTC_DDLFOREIGN_KEY_DEF__INIT;
  *message = init_value;
}
size_t tc_db__ctc_ddlforeign_key_def__get_packed_size
                     (const TcDb__CtcDDLForeignKeyDef *message)
{
  assert(message->base.descriptor == &tc_db__ctc_ddlforeign_key_def__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t tc_db__ctc_ddlforeign_key_def__pack
                     (const TcDb__CtcDDLForeignKeyDef *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &tc_db__ctc_ddlforeign_key_def__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t tc_db__ctc_ddlforeign_key_def__pack_to_buffer
                     (const TcDb__CtcDDLForeignKeyDef *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &tc_db__ctc_ddlforeign_key_def__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
TcDb__CtcDDLForeignKeyDef *
       tc_db__ctc_ddlforeign_key_def__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (TcDb__CtcDDLForeignKeyDef *)
     protobuf_c_message_unpack (&tc_db__ctc_ddlforeign_key_def__descriptor,
                                allocator, len, data);
}
void   tc_db__ctc_ddlforeign_key_def__free_unpacked
                     (TcDb__CtcDDLForeignKeyDef *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &tc_db__ctc_ddlforeign_key_def__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   tc_db__ctc_ddltable_key_part__init
                     (TcDb__CtcDDLTableKeyPart         *message)
{
  static const TcDb__CtcDDLTableKeyPart init_value = TC_DB__CTC_DDLTABLE_KEY_PART__INIT;
  *message = init_value;
}
size_t tc_db__ctc_ddltable_key_part__get_packed_size
                     (const TcDb__CtcDDLTableKeyPart *message)
{
  assert(message->base.descriptor == &tc_db__ctc_ddltable_key_part__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t tc_db__ctc_ddltable_key_part__pack
                     (const TcDb__CtcDDLTableKeyPart *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &tc_db__ctc_ddltable_key_part__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t tc_db__ctc_ddltable_key_part__pack_to_buffer
                     (const TcDb__CtcDDLTableKeyPart *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &tc_db__ctc_ddltable_key_part__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
TcDb__CtcDDLTableKeyPart *
       tc_db__ctc_ddltable_key_part__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (TcDb__CtcDDLTableKeyPart *)
     protobuf_c_message_unpack (&tc_db__ctc_ddltable_key_part__descriptor,
                                allocator, len, data);
}
void   tc_db__ctc_ddltable_key_part__free_unpacked
                     (TcDb__CtcDDLTableKeyPart *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &tc_db__ctc_ddltable_key_part__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   tc_db__ctc_ddltable_key__init
                     (TcDb__CtcDDLTableKey         *message)
{
  static const TcDb__CtcDDLTableKey init_value = TC_DB__CTC_DDLTABLE_KEY__INIT;
  *message = init_value;
}
size_t tc_db__ctc_ddltable_key__get_packed_size
                     (const TcDb__CtcDDLTableKey *message)
{
  assert(message->base.descriptor == &tc_db__ctc_ddltable_key__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t tc_db__ctc_ddltable_key__pack
                     (const TcDb__CtcDDLTableKey *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &tc_db__ctc_ddltable_key__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t tc_db__ctc_ddltable_key__pack_to_buffer
                     (const TcDb__CtcDDLTableKey *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &tc_db__ctc_ddltable_key__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
TcDb__CtcDDLTableKey *
       tc_db__ctc_ddltable_key__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (TcDb__CtcDDLTableKey *)
     protobuf_c_message_unpack (&tc_db__ctc_ddltable_key__descriptor,
                                allocator, len, data);
}
void   tc_db__ctc_ddltable_key__free_unpacked
                     (TcDb__CtcDDLTableKey *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &tc_db__ctc_ddltable_key__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   tc_db__ctc_msg_comm_def__init
                     (TcDb__CtcMsgCommDef         *message)
{
  static const TcDb__CtcMsgCommDef init_value = TC_DB__CTC_MSG_COMM_DEF__INIT;
  *message = init_value;
}
size_t tc_db__ctc_msg_comm_def__get_packed_size
                     (const TcDb__CtcMsgCommDef *message)
{
  assert(message->base.descriptor == &tc_db__ctc_msg_comm_def__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t tc_db__ctc_msg_comm_def__pack
                     (const TcDb__CtcMsgCommDef *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &tc_db__ctc_msg_comm_def__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t tc_db__ctc_msg_comm_def__pack_to_buffer
                     (const TcDb__CtcMsgCommDef *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &tc_db__ctc_msg_comm_def__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
TcDb__CtcMsgCommDef *
       tc_db__ctc_msg_comm_def__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (TcDb__CtcMsgCommDef *)
     protobuf_c_message_unpack (&tc_db__ctc_msg_comm_def__descriptor,
                                allocator, len, data);
}
void   tc_db__ctc_msg_comm_def__free_unpacked
                     (TcDb__CtcMsgCommDef *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &tc_db__ctc_msg_comm_def__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   tc_db__ctc_ddlpartition_table_def__init
                     (TcDb__CtcDDLPartitionTableDef         *message)
{
  static const TcDb__CtcDDLPartitionTableDef init_value = TC_DB__CTC_DDLPARTITION_TABLE_DEF__INIT;
  *message = init_value;
}
size_t tc_db__ctc_ddlpartition_table_def__get_packed_size
                     (const TcDb__CtcDDLPartitionTableDef *message)
{
  assert(message->base.descriptor == &tc_db__ctc_ddlpartition_table_def__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t tc_db__ctc_ddlpartition_table_def__pack
                     (const TcDb__CtcDDLPartitionTableDef *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &tc_db__ctc_ddlpartition_table_def__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t tc_db__ctc_ddlpartition_table_def__pack_to_buffer
                     (const TcDb__CtcDDLPartitionTableDef *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &tc_db__ctc_ddlpartition_table_def__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
TcDb__CtcDDLPartitionTableDef *
       tc_db__ctc_ddlpartition_table_def__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (TcDb__CtcDDLPartitionTableDef *)
     protobuf_c_message_unpack (&tc_db__ctc_ddlpartition_table_def__descriptor,
                                allocator, len, data);
}
void   tc_db__ctc_ddlpartition_table_def__free_unpacked
                     (TcDb__CtcDDLPartitionTableDef *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &tc_db__ctc_ddlpartition_table_def__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   tc_db__ctc_ddlpartition_def__init
                     (TcDb__CtcDDLPartitionDef         *message)
{
  static const TcDb__CtcDDLPartitionDef init_value = TC_DB__CTC_DDLPARTITION_DEF__INIT;
  *message = init_value;
}
size_t tc_db__ctc_ddlpartition_def__get_packed_size
                     (const TcDb__CtcDDLPartitionDef *message)
{
  assert(message->base.descriptor == &tc_db__ctc_ddlpartition_def__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t tc_db__ctc_ddlpartition_def__pack
                     (const TcDb__CtcDDLPartitionDef *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &tc_db__ctc_ddlpartition_def__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t tc_db__ctc_ddlpartition_def__pack_to_buffer
                     (const TcDb__CtcDDLPartitionDef *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &tc_db__ctc_ddlpartition_def__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
TcDb__CtcDDLPartitionDef *
       tc_db__ctc_ddlpartition_def__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (TcDb__CtcDDLPartitionDef *)
     protobuf_c_message_unpack (&tc_db__ctc_ddlpartition_def__descriptor,
                                allocator, len, data);
}
void   tc_db__ctc_ddlpartition_def__free_unpacked
                     (TcDb__CtcDDLPartitionDef *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &tc_db__ctc_ddlpartition_def__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   tc_db__ctc_ddlcreate_table_def__init
                     (TcDb__CtcDDLCreateTableDef         *message)
{
  static const TcDb__CtcDDLCreateTableDef init_value = TC_DB__CTC_DDLCREATE_TABLE_DEF__INIT;
  *message = init_value;
}
size_t tc_db__ctc_ddlcreate_table_def__get_packed_size
                     (const TcDb__CtcDDLCreateTableDef *message)
{
  assert(message->base.descriptor == &tc_db__ctc_ddlcreate_table_def__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t tc_db__ctc_ddlcreate_table_def__pack
                     (const TcDb__CtcDDLCreateTableDef *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &tc_db__ctc_ddlcreate_table_def__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t tc_db__ctc_ddlcreate_table_def__pack_to_buffer
                     (const TcDb__CtcDDLCreateTableDef *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &tc_db__ctc_ddlcreate_table_def__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
TcDb__CtcDDLCreateTableDef *
       tc_db__ctc_ddlcreate_table_def__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (TcDb__CtcDDLCreateTableDef *)
     protobuf_c_message_unpack (&tc_db__ctc_ddlcreate_table_def__descriptor,
                                allocator, len, data);
}
void   tc_db__ctc_ddlcreate_table_def__free_unpacked
                     (TcDb__CtcDDLCreateTableDef *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &tc_db__ctc_ddlcreate_table_def__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   tc_db__ctc_ddlalter_table_porp__init
                     (TcDb__CtcDDLAlterTablePorp         *message)
{
  static const TcDb__CtcDDLAlterTablePorp init_value = TC_DB__CTC_DDLALTER_TABLE_PORP__INIT;
  *message = init_value;
}
size_t tc_db__ctc_ddlalter_table_porp__get_packed_size
                     (const TcDb__CtcDDLAlterTablePorp *message)
{
  assert(message->base.descriptor == &tc_db__ctc_ddlalter_table_porp__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t tc_db__ctc_ddlalter_table_porp__pack
                     (const TcDb__CtcDDLAlterTablePorp *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &tc_db__ctc_ddlalter_table_porp__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t tc_db__ctc_ddlalter_table_porp__pack_to_buffer
                     (const TcDb__CtcDDLAlterTablePorp *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &tc_db__ctc_ddlalter_table_porp__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
TcDb__CtcDDLAlterTablePorp *
       tc_db__ctc_ddlalter_table_porp__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (TcDb__CtcDDLAlterTablePorp *)
     protobuf_c_message_unpack (&tc_db__ctc_ddlalter_table_porp__descriptor,
                                allocator, len, data);
}
void   tc_db__ctc_ddlalter_table_porp__free_unpacked
                     (TcDb__CtcDDLAlterTablePorp *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &tc_db__ctc_ddlalter_table_porp__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   tc_db__ctc_ddlalter_table_drop__init
                     (TcDb__CtcDDLAlterTableDrop         *message)
{
  static const TcDb__CtcDDLAlterTableDrop init_value = TC_DB__CTC_DDLALTER_TABLE_DROP__INIT;
  *message = init_value;
}
size_t tc_db__ctc_ddlalter_table_drop__get_packed_size
                     (const TcDb__CtcDDLAlterTableDrop *message)
{
  assert(message->base.descriptor == &tc_db__ctc_ddlalter_table_drop__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t tc_db__ctc_ddlalter_table_drop__pack
                     (const TcDb__CtcDDLAlterTableDrop *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &tc_db__ctc_ddlalter_table_drop__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t tc_db__ctc_ddlalter_table_drop__pack_to_buffer
                     (const TcDb__CtcDDLAlterTableDrop *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &tc_db__ctc_ddlalter_table_drop__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
TcDb__CtcDDLAlterTableDrop *
       tc_db__ctc_ddlalter_table_drop__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (TcDb__CtcDDLAlterTableDrop *)
     protobuf_c_message_unpack (&tc_db__ctc_ddlalter_table_drop__descriptor,
                                allocator, len, data);
}
void   tc_db__ctc_ddlalter_table_drop__free_unpacked
                     (TcDb__CtcDDLAlterTableDrop *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &tc_db__ctc_ddlalter_table_drop__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   tc_db__ctc_ddlalter_table_drop_key__init
                     (TcDb__CtcDDLAlterTableDropKey         *message)
{
  static const TcDb__CtcDDLAlterTableDropKey init_value = TC_DB__CTC_DDLALTER_TABLE_DROP_KEY__INIT;
  *message = init_value;
}
size_t tc_db__ctc_ddlalter_table_drop_key__get_packed_size
                     (const TcDb__CtcDDLAlterTableDropKey *message)
{
  assert(message->base.descriptor == &tc_db__ctc_ddlalter_table_drop_key__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t tc_db__ctc_ddlalter_table_drop_key__pack
                     (const TcDb__CtcDDLAlterTableDropKey *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &tc_db__ctc_ddlalter_table_drop_key__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t tc_db__ctc_ddlalter_table_drop_key__pack_to_buffer
                     (const TcDb__CtcDDLAlterTableDropKey *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &tc_db__ctc_ddlalter_table_drop_key__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
TcDb__CtcDDLAlterTableDropKey *
       tc_db__ctc_ddlalter_table_drop_key__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (TcDb__CtcDDLAlterTableDropKey *)
     protobuf_c_message_unpack (&tc_db__ctc_ddlalter_table_drop_key__descriptor,
                                allocator, len, data);
}
void   tc_db__ctc_ddlalter_table_drop_key__free_unpacked
                     (TcDb__CtcDDLAlterTableDropKey *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &tc_db__ctc_ddlalter_table_drop_key__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   tc_db__ctc_ddlalter_table_alter_column__init
                     (TcDb__CtcDDLAlterTableAlterColumn         *message)
{
  static const TcDb__CtcDDLAlterTableAlterColumn init_value = TC_DB__CTC_DDLALTER_TABLE_ALTER_COLUMN__INIT;
  *message = init_value;
}
size_t tc_db__ctc_ddlalter_table_alter_column__get_packed_size
                     (const TcDb__CtcDDLAlterTableAlterColumn *message)
{
  assert(message->base.descriptor == &tc_db__ctc_ddlalter_table_alter_column__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t tc_db__ctc_ddlalter_table_alter_column__pack
                     (const TcDb__CtcDDLAlterTableAlterColumn *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &tc_db__ctc_ddlalter_table_alter_column__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t tc_db__ctc_ddlalter_table_alter_column__pack_to_buffer
                     (const TcDb__CtcDDLAlterTableAlterColumn *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &tc_db__ctc_ddlalter_table_alter_column__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
TcDb__CtcDDLAlterTableAlterColumn *
       tc_db__ctc_ddlalter_table_alter_column__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (TcDb__CtcDDLAlterTableAlterColumn *)
     protobuf_c_message_unpack (&tc_db__ctc_ddlalter_table_alter_column__descriptor,
                                allocator, len, data);
}
void   tc_db__ctc_ddlalter_table_alter_column__free_unpacked
                     (TcDb__CtcDDLAlterTableAlterColumn *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &tc_db__ctc_ddlalter_table_alter_column__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   tc_db__ctc_ddlalter_table_def__init
                     (TcDb__CtcDDLAlterTableDef         *message)
{
  static const TcDb__CtcDDLAlterTableDef init_value = TC_DB__CTC_DDLALTER_TABLE_DEF__INIT;
  *message = init_value;
}
size_t tc_db__ctc_ddlalter_table_def__get_packed_size
                     (const TcDb__CtcDDLAlterTableDef *message)
{
  assert(message->base.descriptor == &tc_db__ctc_ddlalter_table_def__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t tc_db__ctc_ddlalter_table_def__pack
                     (const TcDb__CtcDDLAlterTableDef *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &tc_db__ctc_ddlalter_table_def__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t tc_db__ctc_ddlalter_table_def__pack_to_buffer
                     (const TcDb__CtcDDLAlterTableDef *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &tc_db__ctc_ddlalter_table_def__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
TcDb__CtcDDLAlterTableDef *
       tc_db__ctc_ddlalter_table_def__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (TcDb__CtcDDLAlterTableDef *)
     protobuf_c_message_unpack (&tc_db__ctc_ddlalter_table_def__descriptor,
                                allocator, len, data);
}
void   tc_db__ctc_ddlalter_table_def__free_unpacked
                     (TcDb__CtcDDLAlterTableDef *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &tc_db__ctc_ddlalter_table_def__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   tc_db__ctc_ddltruncate_table_def__init
                     (TcDb__CtcDDLTruncateTableDef         *message)
{
  static const TcDb__CtcDDLTruncateTableDef init_value = TC_DB__CTC_DDLTRUNCATE_TABLE_DEF__INIT;
  *message = init_value;
}
size_t tc_db__ctc_ddltruncate_table_def__get_packed_size
                     (const TcDb__CtcDDLTruncateTableDef *message)
{
  assert(message->base.descriptor == &tc_db__ctc_ddltruncate_table_def__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t tc_db__ctc_ddltruncate_table_def__pack
                     (const TcDb__CtcDDLTruncateTableDef *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &tc_db__ctc_ddltruncate_table_def__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t tc_db__ctc_ddltruncate_table_def__pack_to_buffer
                     (const TcDb__CtcDDLTruncateTableDef *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &tc_db__ctc_ddltruncate_table_def__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
TcDb__CtcDDLTruncateTableDef *
       tc_db__ctc_ddltruncate_table_def__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (TcDb__CtcDDLTruncateTableDef *)
     protobuf_c_message_unpack (&tc_db__ctc_ddltruncate_table_def__descriptor,
                                allocator, len, data);
}
void   tc_db__ctc_ddltruncate_table_def__free_unpacked
                     (TcDb__CtcDDLTruncateTableDef *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &tc_db__ctc_ddltruncate_table_def__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   tc_db__ctc_ddltruncate_table_partition_def__init
                     (TcDb__CtcDDLTruncateTablePartitionDef         *message)
{
  static const TcDb__CtcDDLTruncateTablePartitionDef init_value = TC_DB__CTC_DDLTRUNCATE_TABLE_PARTITION_DEF__INIT;
  *message = init_value;
}
size_t tc_db__ctc_ddltruncate_table_partition_def__get_packed_size
                     (const TcDb__CtcDDLTruncateTablePartitionDef *message)
{
  assert(message->base.descriptor == &tc_db__ctc_ddltruncate_table_partition_def__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t tc_db__ctc_ddltruncate_table_partition_def__pack
                     (const TcDb__CtcDDLTruncateTablePartitionDef *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &tc_db__ctc_ddltruncate_table_partition_def__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t tc_db__ctc_ddltruncate_table_partition_def__pack_to_buffer
                     (const TcDb__CtcDDLTruncateTablePartitionDef *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &tc_db__ctc_ddltruncate_table_partition_def__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
TcDb__CtcDDLTruncateTablePartitionDef *
       tc_db__ctc_ddltruncate_table_partition_def__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (TcDb__CtcDDLTruncateTablePartitionDef *)
     protobuf_c_message_unpack (&tc_db__ctc_ddltruncate_table_partition_def__descriptor,
                                allocator, len, data);
}
void   tc_db__ctc_ddltruncate_table_partition_def__free_unpacked
                     (TcDb__CtcDDLTruncateTablePartitionDef *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &tc_db__ctc_ddltruncate_table_partition_def__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   tc_db__ctc_ddlrename_table_def__init
                     (TcDb__CtcDDLRenameTableDef         *message)
{
  static const TcDb__CtcDDLRenameTableDef init_value = TC_DB__CTC_DDLRENAME_TABLE_DEF__INIT;
  *message = init_value;
}
size_t tc_db__ctc_ddlrename_table_def__get_packed_size
                     (const TcDb__CtcDDLRenameTableDef *message)
{
  assert(message->base.descriptor == &tc_db__ctc_ddlrename_table_def__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t tc_db__ctc_ddlrename_table_def__pack
                     (const TcDb__CtcDDLRenameTableDef *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &tc_db__ctc_ddlrename_table_def__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t tc_db__ctc_ddlrename_table_def__pack_to_buffer
                     (const TcDb__CtcDDLRenameTableDef *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &tc_db__ctc_ddlrename_table_def__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
TcDb__CtcDDLRenameTableDef *
       tc_db__ctc_ddlrename_table_def__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (TcDb__CtcDDLRenameTableDef *)
     protobuf_c_message_unpack (&tc_db__ctc_ddlrename_table_def__descriptor,
                                allocator, len, data);
}
void   tc_db__ctc_ddlrename_table_def__free_unpacked
                     (TcDb__CtcDDLRenameTableDef *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &tc_db__ctc_ddlrename_table_def__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   tc_db__ctc_ddldrop_table_def__init
                     (TcDb__CtcDDLDropTableDef         *message)
{
  static const TcDb__CtcDDLDropTableDef init_value = TC_DB__CTC_DDLDROP_TABLE_DEF__INIT;
  *message = init_value;
}
size_t tc_db__ctc_ddldrop_table_def__get_packed_size
                     (const TcDb__CtcDDLDropTableDef *message)
{
  assert(message->base.descriptor == &tc_db__ctc_ddldrop_table_def__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t tc_db__ctc_ddldrop_table_def__pack
                     (const TcDb__CtcDDLDropTableDef *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &tc_db__ctc_ddldrop_table_def__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t tc_db__ctc_ddldrop_table_def__pack_to_buffer
                     (const TcDb__CtcDDLDropTableDef *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &tc_db__ctc_ddldrop_table_def__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
TcDb__CtcDDLDropTableDef *
       tc_db__ctc_ddldrop_table_def__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (TcDb__CtcDDLDropTableDef *)
     protobuf_c_message_unpack (&tc_db__ctc_ddldrop_table_def__descriptor,
                                allocator, len, data);
}
void   tc_db__ctc_ddldrop_table_def__free_unpacked
                     (TcDb__CtcDDLDropTableDef *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &tc_db__ctc_ddldrop_table_def__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   tc_db__ctc_ddlalter_index_def__init
                     (TcDb__CtcDDLAlterIndexDef         *message)
{
  static const TcDb__CtcDDLAlterIndexDef init_value = TC_DB__CTC_DDLALTER_INDEX_DEF__INIT;
  *message = init_value;
}
size_t tc_db__ctc_ddlalter_index_def__get_packed_size
                     (const TcDb__CtcDDLAlterIndexDef *message)
{
  assert(message->base.descriptor == &tc_db__ctc_ddlalter_index_def__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t tc_db__ctc_ddlalter_index_def__pack
                     (const TcDb__CtcDDLAlterIndexDef *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &tc_db__ctc_ddlalter_index_def__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t tc_db__ctc_ddlalter_index_def__pack_to_buffer
                     (const TcDb__CtcDDLAlterIndexDef *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &tc_db__ctc_ddlalter_index_def__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
TcDb__CtcDDLAlterIndexDef *
       tc_db__ctc_ddlalter_index_def__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (TcDb__CtcDDLAlterIndexDef *)
     protobuf_c_message_unpack (&tc_db__ctc_ddlalter_index_def__descriptor,
                                allocator, len, data);
}
void   tc_db__ctc_ddlalter_index_def__free_unpacked
                     (TcDb__CtcDDLAlterIndexDef *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &tc_db__ctc_ddlalter_index_def__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   tc_db__ctc_ddlauto_extend_def__init
                     (TcDb__CtcDDLAutoExtendDef         *message)
{
  static const TcDb__CtcDDLAutoExtendDef init_value = TC_DB__CTC_DDLAUTO_EXTEND_DEF__INIT;
  *message = init_value;
}
size_t tc_db__ctc_ddlauto_extend_def__get_packed_size
                     (const TcDb__CtcDDLAutoExtendDef *message)
{
  assert(message->base.descriptor == &tc_db__ctc_ddlauto_extend_def__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t tc_db__ctc_ddlauto_extend_def__pack
                     (const TcDb__CtcDDLAutoExtendDef *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &tc_db__ctc_ddlauto_extend_def__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t tc_db__ctc_ddlauto_extend_def__pack_to_buffer
                     (const TcDb__CtcDDLAutoExtendDef *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &tc_db__ctc_ddlauto_extend_def__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
TcDb__CtcDDLAutoExtendDef *
       tc_db__ctc_ddlauto_extend_def__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (TcDb__CtcDDLAutoExtendDef *)
     protobuf_c_message_unpack (&tc_db__ctc_ddlauto_extend_def__descriptor,
                                allocator, len, data);
}
void   tc_db__ctc_ddlauto_extend_def__free_unpacked
                     (TcDb__CtcDDLAutoExtendDef *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &tc_db__ctc_ddlauto_extend_def__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   tc_db__ctc_ddldata_file_def__init
                     (TcDb__CtcDDLDataFileDef         *message)
{
  static const TcDb__CtcDDLDataFileDef init_value = TC_DB__CTC_DDLDATA_FILE_DEF__INIT;
  *message = init_value;
}
size_t tc_db__ctc_ddldata_file_def__get_packed_size
                     (const TcDb__CtcDDLDataFileDef *message)
{
  assert(message->base.descriptor == &tc_db__ctc_ddldata_file_def__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t tc_db__ctc_ddldata_file_def__pack
                     (const TcDb__CtcDDLDataFileDef *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &tc_db__ctc_ddldata_file_def__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t tc_db__ctc_ddldata_file_def__pack_to_buffer
                     (const TcDb__CtcDDLDataFileDef *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &tc_db__ctc_ddldata_file_def__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
TcDb__CtcDDLDataFileDef *
       tc_db__ctc_ddldata_file_def__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (TcDb__CtcDDLDataFileDef *)
     protobuf_c_message_unpack (&tc_db__ctc_ddldata_file_def__descriptor,
                                allocator, len, data);
}
void   tc_db__ctc_ddldata_file_def__free_unpacked
                     (TcDb__CtcDDLDataFileDef *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &tc_db__ctc_ddldata_file_def__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   tc_db__ctc_ddlspace_def__init
                     (TcDb__CtcDDLSpaceDef         *message)
{
  static const TcDb__CtcDDLSpaceDef init_value = TC_DB__CTC_DDLSPACE_DEF__INIT;
  *message = init_value;
}
size_t tc_db__ctc_ddlspace_def__get_packed_size
                     (const TcDb__CtcDDLSpaceDef *message)
{
  assert(message->base.descriptor == &tc_db__ctc_ddlspace_def__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t tc_db__ctc_ddlspace_def__pack
                     (const TcDb__CtcDDLSpaceDef *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &tc_db__ctc_ddlspace_def__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t tc_db__ctc_ddlspace_def__pack_to_buffer
                     (const TcDb__CtcDDLSpaceDef *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &tc_db__ctc_ddlspace_def__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
TcDb__CtcDDLSpaceDef *
       tc_db__ctc_ddlspace_def__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (TcDb__CtcDDLSpaceDef *)
     protobuf_c_message_unpack (&tc_db__ctc_ddlspace_def__descriptor,
                                allocator, len, data);
}
void   tc_db__ctc_ddlspace_def__free_unpacked
                     (TcDb__CtcDDLSpaceDef *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &tc_db__ctc_ddlspace_def__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   tc_db__ctc_ddldrop_space_def__init
                     (TcDb__CtcDDLDropSpaceDef         *message)
{
  static const TcDb__CtcDDLDropSpaceDef init_value = TC_DB__CTC_DDLDROP_SPACE_DEF__INIT;
  *message = init_value;
}
size_t tc_db__ctc_ddldrop_space_def__get_packed_size
                     (const TcDb__CtcDDLDropSpaceDef *message)
{
  assert(message->base.descriptor == &tc_db__ctc_ddldrop_space_def__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t tc_db__ctc_ddldrop_space_def__pack
                     (const TcDb__CtcDDLDropSpaceDef *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &tc_db__ctc_ddldrop_space_def__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t tc_db__ctc_ddldrop_space_def__pack_to_buffer
                     (const TcDb__CtcDDLDropSpaceDef *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &tc_db__ctc_ddldrop_space_def__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
TcDb__CtcDDLDropSpaceDef *
       tc_db__ctc_ddldrop_space_def__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (TcDb__CtcDDLDropSpaceDef *)
     protobuf_c_message_unpack (&tc_db__ctc_ddldrop_space_def__descriptor,
                                allocator, len, data);
}
void   tc_db__ctc_ddldrop_space_def__free_unpacked
                     (TcDb__CtcDDLDropSpaceDef *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &tc_db__ctc_ddldrop_space_def__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   tc_db__ctc_ddlalter_space_def__init
                     (TcDb__CtcDDLAlterSpaceDef         *message)
{
  static const TcDb__CtcDDLAlterSpaceDef init_value = TC_DB__CTC_DDLALTER_SPACE_DEF__INIT;
  *message = init_value;
}
size_t tc_db__ctc_ddlalter_space_def__get_packed_size
                     (const TcDb__CtcDDLAlterSpaceDef *message)
{
  assert(message->base.descriptor == &tc_db__ctc_ddlalter_space_def__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t tc_db__ctc_ddlalter_space_def__pack
                     (const TcDb__CtcDDLAlterSpaceDef *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &tc_db__ctc_ddlalter_space_def__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t tc_db__ctc_ddlalter_space_def__pack_to_buffer
                     (const TcDb__CtcDDLAlterSpaceDef *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &tc_db__ctc_ddlalter_space_def__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
TcDb__CtcDDLAlterSpaceDef *
       tc_db__ctc_ddlalter_space_def__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (TcDb__CtcDDLAlterSpaceDef *)
     protobuf_c_message_unpack (&tc_db__ctc_ddlalter_space_def__descriptor,
                                allocator, len, data);
}
void   tc_db__ctc_ddlalter_space_def__free_unpacked
                     (TcDb__CtcDDLAlterSpaceDef *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &tc_db__ctc_ddlalter_space_def__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
static const ProtobufCFieldDescriptor tc_db__ctc_ddlcolumn_data_type_def__field_descriptors[5] =
{
  {
    "datatype",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_INT32,
    0,   /* quantifier_offset */
    offsetof(TcDb__CtcDDLColumnDataTypeDef, datatype),
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
    offsetof(TcDb__CtcDDLColumnDataTypeDef, size),
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
    offsetof(TcDb__CtcDDLColumnDataTypeDef, precision),
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
    offsetof(TcDb__CtcDDLColumnDataTypeDef, scale),
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
    offsetof(TcDb__CtcDDLColumnDataTypeDef, mysql_ori_datatype),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned tc_db__ctc_ddlcolumn_data_type_def__field_indices_by_name[] = {
  0,   /* field[0] = datatype */
  4,   /* field[4] = mysql_ori_datatype */
  2,   /* field[2] = precision */
  3,   /* field[3] = scale */
  1,   /* field[1] = size */
};
static const ProtobufCIntRange tc_db__ctc_ddlcolumn_data_type_def__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 5 }
};
const ProtobufCMessageDescriptor tc_db__ctc_ddlcolumn_data_type_def__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "tc_db.CtcDDLColumnDataTypeDef",
  "CtcDDLColumnDataTypeDef",
  "TcDb__CtcDDLColumnDataTypeDef",
  "tc_db",
  sizeof(TcDb__CtcDDLColumnDataTypeDef),
  5,
  tc_db__ctc_ddlcolumn_data_type_def__field_descriptors,
  tc_db__ctc_ddlcolumn_data_type_def__field_indices_by_name,
  1,  tc_db__ctc_ddlcolumn_data_type_def__number_ranges,
  (ProtobufCMessageInit) tc_db__ctc_ddlcolumn_data_type_def__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor tc_db__ctc_ddlcolumn_def__field_descriptors[14] =
{
  {
    "name",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__CtcDDLColumnDef, name),
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
    offsetof(TcDb__CtcDDLColumnDef, datatype),
    &tc_db__ctc_ddlcolumn_data_type_def__descriptor,
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
    offsetof(TcDb__CtcDDLColumnDef, is_option_set),
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
    offsetof(TcDb__CtcDDLColumnDef, col_id),
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
    offsetof(TcDb__CtcDDLColumnDef, cons_name),
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
    offsetof(TcDb__CtcDDLColumnDef, ref_user),
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
    offsetof(TcDb__CtcDDLColumnDef, ref_table),
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
    offsetof(TcDb__CtcDDLColumnDef, default_text),
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
    offsetof(TcDb__CtcDDLColumnDef, comment),
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
    offsetof(TcDb__CtcDDLColumnDef, alter_mode),
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
    offsetof(TcDb__CtcDDLColumnDef, collate),
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
    offsetof(TcDb__CtcDDLColumnDef, new_name),
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
    offsetof(TcDb__CtcDDLColumnDef, is_unsigned),
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
    offsetof(TcDb__CtcDDLColumnDef, default_func_name),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned tc_db__ctc_ddlcolumn_def__field_indices_by_name[] = {
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
static const ProtobufCIntRange tc_db__ctc_ddlcolumn_def__number_ranges[3 + 1] =
{
  { 1, 0 },
  { 4, 2 },
  { 10, 5 },
  { 0, 14 }
};
const ProtobufCMessageDescriptor tc_db__ctc_ddlcolumn_def__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "tc_db.CtcDDLColumnDef",
  "CtcDDLColumnDef",
  "TcDb__CtcDDLColumnDef",
  "tc_db",
  sizeof(TcDb__CtcDDLColumnDef),
  14,
  tc_db__ctc_ddlcolumn_def__field_descriptors,
  tc_db__ctc_ddlcolumn_def__field_indices_by_name,
  3,  tc_db__ctc_ddlcolumn_def__number_ranges,
  (ProtobufCMessageInit) tc_db__ctc_ddlcolumn_def__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor tc_db__ctc_ddlforeign_key_element_def__field_descriptors[2] =
{
  {
    "src_column_name",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__CtcDDLForeignKeyElementDef, src_column_name),
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
    offsetof(TcDb__CtcDDLForeignKeyElementDef, ref_column_name),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned tc_db__ctc_ddlforeign_key_element_def__field_indices_by_name[] = {
  1,   /* field[1] = ref_column_name */
  0,   /* field[0] = src_column_name */
};
static const ProtobufCIntRange tc_db__ctc_ddlforeign_key_element_def__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 2 }
};
const ProtobufCMessageDescriptor tc_db__ctc_ddlforeign_key_element_def__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "tc_db.CtcDDLForeignKeyElementDef",
  "CtcDDLForeignKeyElementDef",
  "TcDb__CtcDDLForeignKeyElementDef",
  "tc_db",
  sizeof(TcDb__CtcDDLForeignKeyElementDef),
  2,
  tc_db__ctc_ddlforeign_key_element_def__field_descriptors,
  tc_db__ctc_ddlforeign_key_element_def__field_indices_by_name,
  1,  tc_db__ctc_ddlforeign_key_element_def__number_ranges,
  (ProtobufCMessageInit) tc_db__ctc_ddlforeign_key_element_def__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor tc_db__ctc_ddlforeign_key_def__field_descriptors[8] =
{
  {
    "name",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__CtcDDLForeignKeyDef, name),
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
    offsetof(TcDb__CtcDDLForeignKeyDef, unique_index_name),
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
    offsetof(TcDb__CtcDDLForeignKeyDef, match_opt),
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
    offsetof(TcDb__CtcDDLForeignKeyDef, update_opt),
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
    offsetof(TcDb__CtcDDLForeignKeyDef, delete_opt),
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
    offsetof(TcDb__CtcDDLForeignKeyDef, referenced_table_schema_name),
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
    offsetof(TcDb__CtcDDLForeignKeyDef, referenced_table_name),
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
    offsetof(TcDb__CtcDDLForeignKeyDef, n_elements),
    offsetof(TcDb__CtcDDLForeignKeyDef, elements),
    &tc_db__ctc_ddlforeign_key_element_def__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned tc_db__ctc_ddlforeign_key_def__field_indices_by_name[] = {
  4,   /* field[4] = delete_opt */
  7,   /* field[7] = elements */
  2,   /* field[2] = match_opt */
  0,   /* field[0] = name */
  6,   /* field[6] = referenced_table_name */
  5,   /* field[5] = referenced_table_schema_name */
  1,   /* field[1] = unique_index_name */
  3,   /* field[3] = update_opt */
};
static const ProtobufCIntRange tc_db__ctc_ddlforeign_key_def__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 8 }
};
const ProtobufCMessageDescriptor tc_db__ctc_ddlforeign_key_def__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "tc_db.CtcDDLForeignKeyDef",
  "CtcDDLForeignKeyDef",
  "TcDb__CtcDDLForeignKeyDef",
  "tc_db",
  sizeof(TcDb__CtcDDLForeignKeyDef),
  8,
  tc_db__ctc_ddlforeign_key_def__field_descriptors,
  tc_db__ctc_ddlforeign_key_def__field_indices_by_name,
  1,  tc_db__ctc_ddlforeign_key_def__number_ranges,
  (ProtobufCMessageInit) tc_db__ctc_ddlforeign_key_def__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor tc_db__ctc_ddltable_key_part__field_descriptors[7] =
{
  {
    "name",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__CtcDDLTableKeyPart, name),
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
    offsetof(TcDb__CtcDDLTableKeyPart, length),
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
    offsetof(TcDb__CtcDDLTableKeyPart, datatype),
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
    offsetof(TcDb__CtcDDLTableKeyPart, is_func),
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
    offsetof(TcDb__CtcDDLTableKeyPart, func_text),
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
    offsetof(TcDb__CtcDDLTableKeyPart, func_name),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "is_unsigned",
    7,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(TcDb__CtcDDLTableKeyPart, is_unsigned),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned tc_db__ctc_ddltable_key_part__field_indices_by_name[] = {
  2,   /* field[2] = datatype */
  5,   /* field[5] = func_name */
  4,   /* field[4] = func_text */
  3,   /* field[3] = is_func */
  6,   /* field[6] = is_unsigned */
  1,   /* field[1] = length */
  0,   /* field[0] = name */
};
static const ProtobufCIntRange tc_db__ctc_ddltable_key_part__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 7 }
};
const ProtobufCMessageDescriptor tc_db__ctc_ddltable_key_part__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "tc_db.CtcDDLTableKeyPart",
  "CtcDDLTableKeyPart",
  "TcDb__CtcDDLTableKeyPart",
  "tc_db",
  sizeof(TcDb__CtcDDLTableKeyPart),
  7,
  tc_db__ctc_ddltable_key_part__field_descriptors,
  tc_db__ctc_ddltable_key_part__field_indices_by_name,
  1,  tc_db__ctc_ddltable_key_part__number_ranges,
  (ProtobufCMessageInit) tc_db__ctc_ddltable_key_part__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor tc_db__ctc_ddltable_key__field_descriptors[11] =
{
  {
    "user",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__CtcDDLTableKey, user),
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
    offsetof(TcDb__CtcDDLTableKey, table),
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
    offsetof(TcDb__CtcDDLTableKey, name),
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
    offsetof(TcDb__CtcDDLTableKey, space),
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
    offsetof(TcDb__CtcDDLTableKey, key_type),
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
    offsetof(TcDb__CtcDDLTableKey, algorithm),
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
    offsetof(TcDb__CtcDDLTableKey, is_func),
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
    offsetof(TcDb__CtcDDLTableKey, n_columns),
    offsetof(TcDb__CtcDDLTableKey, columns),
    &tc_db__ctc_ddltable_key_part__descriptor,
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
    offsetof(TcDb__CtcDDLTableKey, is_constraint),
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
    offsetof(TcDb__CtcDDLTableKey, is_dsc),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "parallelism",
    11,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_INT32,
    0,   /* quantifier_offset */
    offsetof(TcDb__CtcDDLTableKey, parallelism),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned tc_db__ctc_ddltable_key__field_indices_by_name[] = {
  5,   /* field[5] = algorithm */
  7,   /* field[7] = columns */
  8,   /* field[8] = is_constraint */
  9,   /* field[9] = is_dsc */
  6,   /* field[6] = is_func */
  4,   /* field[4] = key_type */
  2,   /* field[2] = name */
  10,   /* field[10] = parallelism */
  3,   /* field[3] = space */
  1,   /* field[1] = table */
  0,   /* field[0] = user */
};
static const ProtobufCIntRange tc_db__ctc_ddltable_key__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 11 }
};
const ProtobufCMessageDescriptor tc_db__ctc_ddltable_key__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "tc_db.CtcDDLTableKey",
  "CtcDDLTableKey",
  "TcDb__CtcDDLTableKey",
  "tc_db",
  sizeof(TcDb__CtcDDLTableKey),
  11,
  tc_db__ctc_ddltable_key__field_descriptors,
  tc_db__ctc_ddltable_key__field_indices_by_name,
  1,  tc_db__ctc_ddltable_key__number_ranges,
  (ProtobufCMessageInit) tc_db__ctc_ddltable_key__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor tc_db__ctc_msg_comm_def__field_descriptors[4] =
{
  {
    "inst_id",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(TcDb__CtcMsgCommDef, inst_id),
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
    offsetof(TcDb__CtcMsgCommDef, thd_id),
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
    offsetof(TcDb__CtcMsgCommDef, handler_id),
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
    offsetof(TcDb__CtcMsgCommDef, sess_addr),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned tc_db__ctc_msg_comm_def__field_indices_by_name[] = {
  2,   /* field[2] = handler_id */
  0,   /* field[0] = inst_id */
  3,   /* field[3] = sess_addr */
  1,   /* field[1] = thd_id */
};
static const ProtobufCIntRange tc_db__ctc_msg_comm_def__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 4 }
};
const ProtobufCMessageDescriptor tc_db__ctc_msg_comm_def__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "tc_db.CtcMsgCommDef",
  "CtcMsgCommDef",
  "TcDb__CtcMsgCommDef",
  "tc_db",
  sizeof(TcDb__CtcMsgCommDef),
  4,
  tc_db__ctc_msg_comm_def__field_descriptors,
  tc_db__ctc_msg_comm_def__field_indices_by_name,
  1,  tc_db__ctc_msg_comm_def__number_ranges,
  (ProtobufCMessageInit) tc_db__ctc_msg_comm_def__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor tc_db__ctc_ddlpartition_table_def__field_descriptors[2] =
{
  {
    "name",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__CtcDDLPartitionTableDef, name),
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
    offsetof(TcDb__CtcDDLPartitionTableDef, n_subpart_table_list),
    offsetof(TcDb__CtcDDLPartitionTableDef, subpart_table_list),
    &tc_db__ctc_ddlpartition_table_def__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned tc_db__ctc_ddlpartition_table_def__field_indices_by_name[] = {
  0,   /* field[0] = name */
  1,   /* field[1] = subpart_table_list */
};
static const ProtobufCIntRange tc_db__ctc_ddlpartition_table_def__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 2 }
};
const ProtobufCMessageDescriptor tc_db__ctc_ddlpartition_table_def__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "tc_db.CtcDDLPartitionTableDef",
  "CtcDDLPartitionTableDef",
  "TcDb__CtcDDLPartitionTableDef",
  "tc_db",
  sizeof(TcDb__CtcDDLPartitionTableDef),
  2,
  tc_db__ctc_ddlpartition_table_def__field_descriptors,
  tc_db__ctc_ddlpartition_table_def__field_indices_by_name,
  1,  tc_db__ctc_ddlpartition_table_def__number_ranges,
  (ProtobufCMessageInit) tc_db__ctc_ddlpartition_table_def__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor tc_db__ctc_ddlpartition_def__field_descriptors[3] =
{
  {
    "part_type",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(TcDb__CtcDDLPartitionDef, part_type),
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
    offsetof(TcDb__CtcDDLPartitionDef, subpart_type),
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
    offsetof(TcDb__CtcDDLPartitionDef, n_part_table_list),
    offsetof(TcDb__CtcDDLPartitionDef, part_table_list),
    &tc_db__ctc_ddlpartition_table_def__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned tc_db__ctc_ddlpartition_def__field_indices_by_name[] = {
  2,   /* field[2] = part_table_list */
  0,   /* field[0] = part_type */
  1,   /* field[1] = subpart_type */
};
static const ProtobufCIntRange tc_db__ctc_ddlpartition_def__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 3 }
};
const ProtobufCMessageDescriptor tc_db__ctc_ddlpartition_def__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "tc_db.CtcDDLPartitionDef",
  "CtcDDLPartitionDef",
  "TcDb__CtcDDLPartitionDef",
  "tc_db",
  sizeof(TcDb__CtcDDLPartitionDef),
  3,
  tc_db__ctc_ddlpartition_def__field_descriptors,
  tc_db__ctc_ddlpartition_def__field_indices_by_name,
  1,  tc_db__ctc_ddlpartition_def__number_ranges,
  (ProtobufCMessageInit) tc_db__ctc_ddlpartition_def__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor tc_db__ctc_ddlcreate_table_def__field_descriptors[14] =
{
  {
    "schema",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__CtcDDLCreateTableDef, schema),
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
    offsetof(TcDb__CtcDDLCreateTableDef, name),
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
    offsetof(TcDb__CtcDDLCreateTableDef, space),
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
    offsetof(TcDb__CtcDDLCreateTableDef, n_columns),
    offsetof(TcDb__CtcDDLCreateTableDef, columns),
    &tc_db__ctc_ddlcolumn_def__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "fk_list",
    5,
    PROTOBUF_C_LABEL_REPEATED,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(TcDb__CtcDDLCreateTableDef, n_fk_list),
    offsetof(TcDb__CtcDDLCreateTableDef, fk_list),
    &tc_db__ctc_ddlforeign_key_def__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "key_list",
    6,
    PROTOBUF_C_LABEL_REPEATED,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(TcDb__CtcDDLCreateTableDef, n_key_list),
    offsetof(TcDb__CtcDDLCreateTableDef, key_list),
    &tc_db__ctc_ddltable_key__descriptor,
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
    offsetof(TcDb__CtcDDLCreateTableDef, auto_increment_value),
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
    offsetof(TcDb__CtcDDLCreateTableDef, options),
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
    offsetof(TcDb__CtcDDLCreateTableDef, db_name),
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
    offsetof(TcDb__CtcDDLCreateTableDef, sql_str),
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
    offsetof(TcDb__CtcDDLCreateTableDef, alter_table_name),
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
    offsetof(TcDb__CtcDDLCreateTableDef, alter_db_name),
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
    offsetof(TcDb__CtcDDLCreateTableDef, is_create_as_select),
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
    offsetof(TcDb__CtcDDLCreateTableDef, partition_def),
    &tc_db__ctc_ddlpartition_def__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned tc_db__ctc_ddlcreate_table_def__field_indices_by_name[] = {
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
static const ProtobufCIntRange tc_db__ctc_ddlcreate_table_def__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 14 }
};
const ProtobufCMessageDescriptor tc_db__ctc_ddlcreate_table_def__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "tc_db.CtcDDLCreateTableDef",
  "CtcDDLCreateTableDef",
  "TcDb__CtcDDLCreateTableDef",
  "tc_db",
  sizeof(TcDb__CtcDDLCreateTableDef),
  14,
  tc_db__ctc_ddlcreate_table_def__field_descriptors,
  tc_db__ctc_ddlcreate_table_def__field_indices_by_name,
  1,  tc_db__ctc_ddlcreate_table_def__number_ranges,
  (ProtobufCMessageInit) tc_db__ctc_ddlcreate_table_def__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor tc_db__ctc_ddlalter_table_porp__field_descriptors[6] =
{
  {
    "new_name",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__CtcDDLAlterTablePorp, new_name),
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
    offsetof(TcDb__CtcDDLAlterTablePorp, pctfree),
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
    offsetof(TcDb__CtcDDLAlterTablePorp, appendonly),
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
    offsetof(TcDb__CtcDDLAlterTablePorp, enable_row_move),
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
    offsetof(TcDb__CtcDDLAlterTablePorp, shrink_opt),
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
    offsetof(TcDb__CtcDDLAlterTablePorp, serial_start),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned tc_db__ctc_ddlalter_table_porp__field_indices_by_name[] = {
  2,   /* field[2] = appendonly */
  3,   /* field[3] = enable_row_move */
  0,   /* field[0] = new_name */
  1,   /* field[1] = pctfree */
  5,   /* field[5] = serial_start */
  4,   /* field[4] = shrink_opt */
};
static const ProtobufCIntRange tc_db__ctc_ddlalter_table_porp__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 6 }
};
const ProtobufCMessageDescriptor tc_db__ctc_ddlalter_table_porp__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "tc_db.CtcDDLAlterTablePorp",
  "CtcDDLAlterTablePorp",
  "TcDb__CtcDDLAlterTablePorp",
  "tc_db",
  sizeof(TcDb__CtcDDLAlterTablePorp),
  6,
  tc_db__ctc_ddlalter_table_porp__field_descriptors,
  tc_db__ctc_ddlalter_table_porp__field_indices_by_name,
  1,  tc_db__ctc_ddlalter_table_porp__number_ranges,
  (ProtobufCMessageInit) tc_db__ctc_ddlalter_table_porp__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor tc_db__ctc_ddlalter_table_drop__field_descriptors[3] =
{
  {
    "name",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__CtcDDLAlterTableDrop, name),
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
    offsetof(TcDb__CtcDDLAlterTableDrop, drop_type),
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
    offsetof(TcDb__CtcDDLAlterTableDrop, key_type),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned tc_db__ctc_ddlalter_table_drop__field_indices_by_name[] = {
  1,   /* field[1] = drop_type */
  2,   /* field[2] = key_type */
  0,   /* field[0] = name */
};
static const ProtobufCIntRange tc_db__ctc_ddlalter_table_drop__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 3 }
};
const ProtobufCMessageDescriptor tc_db__ctc_ddlalter_table_drop__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "tc_db.CtcDDLAlterTableDrop",
  "CtcDDLAlterTableDrop",
  "TcDb__CtcDDLAlterTableDrop",
  "tc_db",
  sizeof(TcDb__CtcDDLAlterTableDrop),
  3,
  tc_db__ctc_ddlalter_table_drop__field_descriptors,
  tc_db__ctc_ddlalter_table_drop__field_indices_by_name,
  1,  tc_db__ctc_ddlalter_table_drop__number_ranges,
  (ProtobufCMessageInit) tc_db__ctc_ddlalter_table_drop__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor tc_db__ctc_ddlalter_table_drop_key__field_descriptors[3] =
{
  {
    "name",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__CtcDDLAlterTableDropKey, name),
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
    offsetof(TcDb__CtcDDLAlterTableDropKey, drop_type),
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
    offsetof(TcDb__CtcDDLAlterTableDropKey, key_type),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned tc_db__ctc_ddlalter_table_drop_key__field_indices_by_name[] = {
  1,   /* field[1] = drop_type */
  2,   /* field[2] = key_type */
  0,   /* field[0] = name */
};
static const ProtobufCIntRange tc_db__ctc_ddlalter_table_drop_key__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 3 }
};
const ProtobufCMessageDescriptor tc_db__ctc_ddlalter_table_drop_key__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "tc_db.CtcDDLAlterTableDropKey",
  "CtcDDLAlterTableDropKey",
  "TcDb__CtcDDLAlterTableDropKey",
  "tc_db",
  sizeof(TcDb__CtcDDLAlterTableDropKey),
  3,
  tc_db__ctc_ddlalter_table_drop_key__field_descriptors,
  tc_db__ctc_ddlalter_table_drop_key__field_indices_by_name,
  1,  tc_db__ctc_ddlalter_table_drop_key__number_ranges,
  (ProtobufCMessageInit) tc_db__ctc_ddlalter_table_drop_key__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor tc_db__ctc_ddlalter_table_alter_column__field_descriptors[7] =
{
  {
    "name",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__CtcDDLAlterTableAlterColumn, name),
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
    offsetof(TcDb__CtcDDLAlterTableAlterColumn, new_name),
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
    offsetof(TcDb__CtcDDLAlterTableAlterColumn, type),
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
    offsetof(TcDb__CtcDDLAlterTableAlterColumn, has_no_default),
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
    offsetof(TcDb__CtcDDLAlterTableAlterColumn, has_default),
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
    offsetof(TcDb__CtcDDLAlterTableAlterColumn, is_default_null),
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
    offsetof(TcDb__CtcDDLAlterTableAlterColumn, default_text),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned tc_db__ctc_ddlalter_table_alter_column__field_indices_by_name[] = {
  6,   /* field[6] = default_text */
  4,   /* field[4] = has_default */
  3,   /* field[3] = has_no_default */
  5,   /* field[5] = is_default_null */
  0,   /* field[0] = name */
  1,   /* field[1] = new_name */
  2,   /* field[2] = type */
};
static const ProtobufCIntRange tc_db__ctc_ddlalter_table_alter_column__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 7 }
};
const ProtobufCMessageDescriptor tc_db__ctc_ddlalter_table_alter_column__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "tc_db.CtcDDLAlterTableAlterColumn",
  "CtcDDLAlterTableAlterColumn",
  "TcDb__CtcDDLAlterTableAlterColumn",
  "tc_db",
  sizeof(TcDb__CtcDDLAlterTableAlterColumn),
  7,
  tc_db__ctc_ddlalter_table_alter_column__field_descriptors,
  tc_db__ctc_ddlalter_table_alter_column__field_indices_by_name,
  1,  tc_db__ctc_ddlalter_table_alter_column__number_ranges,
  (ProtobufCMessageInit) tc_db__ctc_ddlalter_table_alter_column__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor tc_db__ctc_ddlalter_table_def__field_descriptors[20] =
{
  {
    "action",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(TcDb__CtcDDLAlterTableDef, action),
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
    offsetof(TcDb__CtcDDLAlterTableDef, options),
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
    offsetof(TcDb__CtcDDLAlterTableDef, user),
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
    offsetof(TcDb__CtcDDLAlterTableDef, name),
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
    offsetof(TcDb__CtcDDLAlterTableDef, n_drop_list),
    offsetof(TcDb__CtcDDLAlterTableDef, drop_list),
    &tc_db__ctc_ddlalter_table_drop__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "alter_list",
    6,
    PROTOBUF_C_LABEL_REPEATED,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(TcDb__CtcDDLAlterTableDef, n_alter_list),
    offsetof(TcDb__CtcDDLAlterTableDef, alter_list),
    &tc_db__ctc_ddlalter_table_alter_column__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "create_list",
    7,
    PROTOBUF_C_LABEL_REPEATED,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(TcDb__CtcDDLAlterTableDef, n_create_list),
    offsetof(TcDb__CtcDDLAlterTableDef, create_list),
    &tc_db__ctc_ddlcolumn_def__descriptor,
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
    offsetof(TcDb__CtcDDLAlterTableDef, table_def),
    &tc_db__ctc_ddlalter_table_porp__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "add_key_list",
    9,
    PROTOBUF_C_LABEL_REPEATED,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(TcDb__CtcDDLAlterTableDef, n_add_key_list),
    offsetof(TcDb__CtcDDLAlterTableDef, add_key_list),
    &tc_db__ctc_ddltable_key__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "drop_key_list",
    10,
    PROTOBUF_C_LABEL_REPEATED,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(TcDb__CtcDDLAlterTableDef, n_drop_key_list),
    offsetof(TcDb__CtcDDLAlterTableDef, drop_key_list),
    &tc_db__ctc_ddlalter_table_drop_key__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "add_foreign_key_list",
    11,
    PROTOBUF_C_LABEL_REPEATED,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(TcDb__CtcDDLAlterTableDef, n_add_foreign_key_list),
    offsetof(TcDb__CtcDDLAlterTableDef, add_foreign_key_list),
    &tc_db__ctc_ddlforeign_key_def__descriptor,
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
    offsetof(TcDb__CtcDDLAlterTableDef, new_auto_increment_value),
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
    offsetof(TcDb__CtcDDLAlterTableDef, db_name),
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
    offsetof(TcDb__CtcDDLAlterTableDef, sql_str),
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
    offsetof(TcDb__CtcDDLAlterTableDef, n_alter_index_list),
    offsetof(TcDb__CtcDDLAlterTableDef, alter_index_list),
    &tc_db__ctc_ddlalter_index_def__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "drop_partition_names",
    16,
    PROTOBUF_C_LABEL_REPEATED,
    PROTOBUF_C_TYPE_STRING,
    offsetof(TcDb__CtcDDLAlterTableDef, n_drop_partition_names),
    offsetof(TcDb__CtcDDLAlterTableDef, drop_partition_names),
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
    offsetof(TcDb__CtcDDLAlterTableDef, n_add_part_list),
    offsetof(TcDb__CtcDDLAlterTableDef, add_part_list),
    &tc_db__ctc_ddlpartition_table_def__descriptor,
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
    offsetof(TcDb__CtcDDLAlterTableDef, hash_coalesce_count),
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
    offsetof(TcDb__CtcDDLAlterTableDef, systimestamp),
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
    offsetof(TcDb__CtcDDLAlterTableDef, tz_offset_utc),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned tc_db__ctc_ddlalter_table_def__field_indices_by_name[] = {
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
static const ProtobufCIntRange tc_db__ctc_ddlalter_table_def__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 20 }
};
const ProtobufCMessageDescriptor tc_db__ctc_ddlalter_table_def__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "tc_db.CtcDDLAlterTableDef",
  "CtcDDLAlterTableDef",
  "TcDb__CtcDDLAlterTableDef",
  "tc_db",
  sizeof(TcDb__CtcDDLAlterTableDef),
  20,
  tc_db__ctc_ddlalter_table_def__field_descriptors,
  tc_db__ctc_ddlalter_table_def__field_indices_by_name,
  1,  tc_db__ctc_ddlalter_table_def__number_ranges,
  (ProtobufCMessageInit) tc_db__ctc_ddlalter_table_def__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor tc_db__ctc_ddltruncate_table_def__field_descriptors[5] =
{
  {
    "schema",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__CtcDDLTruncateTableDef, schema),
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
    offsetof(TcDb__CtcDDLTruncateTableDef, name),
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
    offsetof(TcDb__CtcDDLTruncateTableDef, db_name),
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
    offsetof(TcDb__CtcDDLTruncateTableDef, sql_str),
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
    offsetof(TcDb__CtcDDLTruncateTableDef, no_check_fk),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned tc_db__ctc_ddltruncate_table_def__field_indices_by_name[] = {
  2,   /* field[2] = db_name */
  1,   /* field[1] = name */
  4,   /* field[4] = no_check_fk */
  0,   /* field[0] = schema */
  3,   /* field[3] = sql_str */
};
static const ProtobufCIntRange tc_db__ctc_ddltruncate_table_def__number_ranges[2 + 1] =
{
  { 1, 0 },
  { 4, 2 },
  { 0, 5 }
};
const ProtobufCMessageDescriptor tc_db__ctc_ddltruncate_table_def__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "tc_db.CtcDDLTruncateTableDef",
  "CtcDDLTruncateTableDef",
  "TcDb__CtcDDLTruncateTableDef",
  "tc_db",
  sizeof(TcDb__CtcDDLTruncateTableDef),
  5,
  tc_db__ctc_ddltruncate_table_def__field_descriptors,
  tc_db__ctc_ddltruncate_table_def__field_indices_by_name,
  2,  tc_db__ctc_ddltruncate_table_def__number_ranges,
  (ProtobufCMessageInit) tc_db__ctc_ddltruncate_table_def__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor tc_db__ctc_ddltruncate_table_partition_def__field_descriptors[9] =
{
  {
    "user",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__CtcDDLTruncateTablePartitionDef, user),
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
    offsetof(TcDb__CtcDDLTruncateTablePartitionDef, db_name),
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
    offsetof(TcDb__CtcDDLTruncateTablePartitionDef, table_name),
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
    offsetof(TcDb__CtcDDLTruncateTablePartitionDef, n_partition_name),
    offsetof(TcDb__CtcDDLTruncateTablePartitionDef, partition_name),
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
    offsetof(TcDb__CtcDDLTruncateTablePartitionDef, n_partition_id),
    offsetof(TcDb__CtcDDLTruncateTablePartitionDef, partition_id),
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
    offsetof(TcDb__CtcDDLTruncateTablePartitionDef, sql_str),
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
    offsetof(TcDb__CtcDDLTruncateTablePartitionDef, is_subpart),
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
    offsetof(TcDb__CtcDDLTruncateTablePartitionDef, n_subpartition_name),
    offsetof(TcDb__CtcDDLTruncateTablePartitionDef, subpartition_name),
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
    offsetof(TcDb__CtcDDLTruncateTablePartitionDef, n_subpartition_id),
    offsetof(TcDb__CtcDDLTruncateTablePartitionDef, subpartition_id),
    NULL,
    NULL,
    0 | PROTOBUF_C_FIELD_FLAG_PACKED,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned tc_db__ctc_ddltruncate_table_partition_def__field_indices_by_name[] = {
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
static const ProtobufCIntRange tc_db__ctc_ddltruncate_table_partition_def__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 9 }
};
const ProtobufCMessageDescriptor tc_db__ctc_ddltruncate_table_partition_def__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "tc_db.CtcDDLTruncateTablePartitionDef",
  "CtcDDLTruncateTablePartitionDef",
  "TcDb__CtcDDLTruncateTablePartitionDef",
  "tc_db",
  sizeof(TcDb__CtcDDLTruncateTablePartitionDef),
  9,
  tc_db__ctc_ddltruncate_table_partition_def__field_descriptors,
  tc_db__ctc_ddltruncate_table_partition_def__field_indices_by_name,
  1,  tc_db__ctc_ddltruncate_table_partition_def__number_ranges,
  (ProtobufCMessageInit) tc_db__ctc_ddltruncate_table_partition_def__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor tc_db__ctc_ddlrename_table_def__field_descriptors[12] =
{
  {
    "action",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(TcDb__CtcDDLRenameTableDef, action),
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
    offsetof(TcDb__CtcDDLRenameTableDef, options),
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
    offsetof(TcDb__CtcDDLRenameTableDef, user),
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
    offsetof(TcDb__CtcDDLRenameTableDef, new_user),
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
    offsetof(TcDb__CtcDDLRenameTableDef, new_table_name),
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
    offsetof(TcDb__CtcDDLRenameTableDef, new_db_name),
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
    offsetof(TcDb__CtcDDLRenameTableDef, old_table_name),
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
    offsetof(TcDb__CtcDDLRenameTableDef, old_db_name),
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
    offsetof(TcDb__CtcDDLRenameTableDef, current_db_name),
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
    offsetof(TcDb__CtcDDLRenameTableDef, sql_str),
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
    offsetof(TcDb__CtcDDLRenameTableDef, n_old_constraints_name),
    offsetof(TcDb__CtcDDLRenameTableDef, old_constraints_name),
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
    offsetof(TcDb__CtcDDLRenameTableDef, n_new_constraints_name),
    offsetof(TcDb__CtcDDLRenameTableDef, new_constraints_name),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned tc_db__ctc_ddlrename_table_def__field_indices_by_name[] = {
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
static const ProtobufCIntRange tc_db__ctc_ddlrename_table_def__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 12 }
};
const ProtobufCMessageDescriptor tc_db__ctc_ddlrename_table_def__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "tc_db.CtcDDLRenameTableDef",
  "CtcDDLRenameTableDef",
  "TcDb__CtcDDLRenameTableDef",
  "tc_db",
  sizeof(TcDb__CtcDDLRenameTableDef),
  12,
  tc_db__ctc_ddlrename_table_def__field_descriptors,
  tc_db__ctc_ddlrename_table_def__field_indices_by_name,
  1,  tc_db__ctc_ddlrename_table_def__number_ranges,
  (ProtobufCMessageInit) tc_db__ctc_ddlrename_table_def__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor tc_db__ctc_ddldrop_table_def__field_descriptors[6] =
{
  {
    "options",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(TcDb__CtcDDLDropTableDef, options),
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
    offsetof(TcDb__CtcDDLDropTableDef, user),
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
    offsetof(TcDb__CtcDDLDropTableDef, name),
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
    offsetof(TcDb__CtcDDLDropTableDef, dbname_und),
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
    offsetof(TcDb__CtcDDLDropTableDef, db_name),
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
    offsetof(TcDb__CtcDDLDropTableDef, sql_str),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned tc_db__ctc_ddldrop_table_def__field_indices_by_name[] = {
  4,   /* field[4] = db_name */
  3,   /* field[3] = dbname_und */
  2,   /* field[2] = name */
  0,   /* field[0] = options */
  5,   /* field[5] = sql_str */
  1,   /* field[1] = user */
};
static const ProtobufCIntRange tc_db__ctc_ddldrop_table_def__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 6 }
};
const ProtobufCMessageDescriptor tc_db__ctc_ddldrop_table_def__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "tc_db.CtcDDLDropTableDef",
  "CtcDDLDropTableDef",
  "TcDb__CtcDDLDropTableDef",
  "tc_db",
  sizeof(TcDb__CtcDDLDropTableDef),
  6,
  tc_db__ctc_ddldrop_table_def__field_descriptors,
  tc_db__ctc_ddldrop_table_def__field_indices_by_name,
  1,  tc_db__ctc_ddldrop_table_def__number_ranges,
  (ProtobufCMessageInit) tc_db__ctc_ddldrop_table_def__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor tc_db__ctc_ddlalter_index_def__field_descriptors[6] =
{
  {
    "user",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__CtcDDLAlterIndexDef, user),
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
    offsetof(TcDb__CtcDDLAlterIndexDef, name),
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
    offsetof(TcDb__CtcDDLAlterIndexDef, type),
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
    offsetof(TcDb__CtcDDLAlterIndexDef, table),
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
    offsetof(TcDb__CtcDDLAlterIndexDef, new_name),
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
    offsetof(TcDb__CtcDDLAlterIndexDef, key_type),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned tc_db__ctc_ddlalter_index_def__field_indices_by_name[] = {
  5,   /* field[5] = key_type */
  1,   /* field[1] = name */
  4,   /* field[4] = new_name */
  3,   /* field[3] = table */
  2,   /* field[2] = type */
  0,   /* field[0] = user */
};
static const ProtobufCIntRange tc_db__ctc_ddlalter_index_def__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 6 }
};
const ProtobufCMessageDescriptor tc_db__ctc_ddlalter_index_def__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "tc_db.CtcDDLAlterIndexDef",
  "CtcDDLAlterIndexDef",
  "TcDb__CtcDDLAlterIndexDef",
  "tc_db",
  sizeof(TcDb__CtcDDLAlterIndexDef),
  6,
  tc_db__ctc_ddlalter_index_def__field_descriptors,
  tc_db__ctc_ddlalter_index_def__field_indices_by_name,
  1,  tc_db__ctc_ddlalter_index_def__number_ranges,
  (ProtobufCMessageInit) tc_db__ctc_ddlalter_index_def__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor tc_db__ctc_ddlauto_extend_def__field_descriptors[3] =
{
  {
    "enabled",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BOOL,
    0,   /* quantifier_offset */
    offsetof(TcDb__CtcDDLAutoExtendDef, enabled),
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
    offsetof(TcDb__CtcDDLAutoExtendDef, nextsize),
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
    offsetof(TcDb__CtcDDLAutoExtendDef, maxsize),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned tc_db__ctc_ddlauto_extend_def__field_indices_by_name[] = {
  0,   /* field[0] = enabled */
  2,   /* field[2] = maxsize */
  1,   /* field[1] = nextsize */
};
static const ProtobufCIntRange tc_db__ctc_ddlauto_extend_def__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 3 }
};
const ProtobufCMessageDescriptor tc_db__ctc_ddlauto_extend_def__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "tc_db.CtcDDLAutoExtendDef",
  "CtcDDLAutoExtendDef",
  "TcDb__CtcDDLAutoExtendDef",
  "tc_db",
  sizeof(TcDb__CtcDDLAutoExtendDef),
  3,
  tc_db__ctc_ddlauto_extend_def__field_descriptors,
  tc_db__ctc_ddlauto_extend_def__field_indices_by_name,
  1,  tc_db__ctc_ddlauto_extend_def__number_ranges,
  (ProtobufCMessageInit) tc_db__ctc_ddlauto_extend_def__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor tc_db__ctc_ddldata_file_def__field_descriptors[5] =
{
  {
    "name",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__CtcDDLDataFileDef, name),
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
    offsetof(TcDb__CtcDDLDataFileDef, size),
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
    offsetof(TcDb__CtcDDLDataFileDef, block_size),
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
    offsetof(TcDb__CtcDDLDataFileDef, autoextend),
    &tc_db__ctc_ddlauto_extend_def__descriptor,
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
    offsetof(TcDb__CtcDDLDataFileDef, node_id),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned tc_db__ctc_ddldata_file_def__field_indices_by_name[] = {
  3,   /* field[3] = autoextend */
  2,   /* field[2] = block_size */
  0,   /* field[0] = name */
  4,   /* field[4] = node_id */
  1,   /* field[1] = size */
};
static const ProtobufCIntRange tc_db__ctc_ddldata_file_def__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 5 }
};
const ProtobufCMessageDescriptor tc_db__ctc_ddldata_file_def__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "tc_db.CtcDDLDataFileDef",
  "CtcDDLDataFileDef",
  "TcDb__CtcDDLDataFileDef",
  "tc_db",
  sizeof(TcDb__CtcDDLDataFileDef),
  5,
  tc_db__ctc_ddldata_file_def__field_descriptors,
  tc_db__ctc_ddldata_file_def__field_indices_by_name,
  1,  tc_db__ctc_ddldata_file_def__number_ranges,
  (ProtobufCMessageInit) tc_db__ctc_ddldata_file_def__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor tc_db__ctc_ddlspace_def__field_descriptors[9] =
{
  {
    "name",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__CtcDDLSpaceDef, name),
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
    offsetof(TcDb__CtcDDLSpaceDef, type),
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
    offsetof(TcDb__CtcDDLSpaceDef, in_memory),
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
    offsetof(TcDb__CtcDDLSpaceDef, autooffline),
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
    offsetof(TcDb__CtcDDLSpaceDef, extent_size),
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
    offsetof(TcDb__CtcDDLSpaceDef, n_datafiles_list),
    offsetof(TcDb__CtcDDLSpaceDef, datafiles_list),
    &tc_db__ctc_ddldata_file_def__descriptor,
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
    offsetof(TcDb__CtcDDLSpaceDef, flags),
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
    offsetof(TcDb__CtcDDLSpaceDef, db_name),
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
    offsetof(TcDb__CtcDDLSpaceDef, sql_str),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned tc_db__ctc_ddlspace_def__field_indices_by_name[] = {
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
static const ProtobufCIntRange tc_db__ctc_ddlspace_def__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 9 }
};
const ProtobufCMessageDescriptor tc_db__ctc_ddlspace_def__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "tc_db.CtcDDLSpaceDef",
  "CtcDDLSpaceDef",
  "TcDb__CtcDDLSpaceDef",
  "tc_db",
  sizeof(TcDb__CtcDDLSpaceDef),
  9,
  tc_db__ctc_ddlspace_def__field_descriptors,
  tc_db__ctc_ddlspace_def__field_indices_by_name,
  1,  tc_db__ctc_ddlspace_def__number_ranges,
  (ProtobufCMessageInit) tc_db__ctc_ddlspace_def__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor tc_db__ctc_ddldrop_space_def__field_descriptors[4] =
{
  {
    "obj_name",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(TcDb__CtcDDLDropSpaceDef, obj_name),
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
    offsetof(TcDb__CtcDDLDropSpaceDef, option),
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
    offsetof(TcDb__CtcDDLDropSpaceDef, db_name),
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
    offsetof(TcDb__CtcDDLDropSpaceDef, sql_str),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned tc_db__ctc_ddldrop_space_def__field_indices_by_name[] = {
  2,   /* field[2] = db_name */
  0,   /* field[0] = obj_name */
  1,   /* field[1] = option */
  3,   /* field[3] = sql_str */
};
static const ProtobufCIntRange tc_db__ctc_ddldrop_space_def__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 4 }
};
const ProtobufCMessageDescriptor tc_db__ctc_ddldrop_space_def__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "tc_db.CtcDDLDropSpaceDef",
  "CtcDDLDropSpaceDef",
  "TcDb__CtcDDLDropSpaceDef",
  "tc_db",
  sizeof(TcDb__CtcDDLDropSpaceDef),
  4,
  tc_db__ctc_ddldrop_space_def__field_descriptors,
  tc_db__ctc_ddldrop_space_def__field_indices_by_name,
  1,  tc_db__ctc_ddldrop_space_def__number_ranges,
  (ProtobufCMessageInit) tc_db__ctc_ddldrop_space_def__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor tc_db__ctc_ddlalter_space_def__field_descriptors[6] =
{
  {
    "action",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(TcDb__CtcDDLAlterSpaceDef, action),
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
    offsetof(TcDb__CtcDDLAlterSpaceDef, name),
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
    offsetof(TcDb__CtcDDLAlterSpaceDef, new_name),
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
    offsetof(TcDb__CtcDDLAlterSpaceDef, auto_extend_size),
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
    offsetof(TcDb__CtcDDLAlterSpaceDef, db_name),
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
    offsetof(TcDb__CtcDDLAlterSpaceDef, sql_str),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned tc_db__ctc_ddlalter_space_def__field_indices_by_name[] = {
  0,   /* field[0] = action */
  3,   /* field[3] = auto_extend_size */
  4,   /* field[4] = db_name */
  1,   /* field[1] = name */
  2,   /* field[2] = new_name */
  5,   /* field[5] = sql_str */
};
static const ProtobufCIntRange tc_db__ctc_ddlalter_space_def__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 6 }
};
const ProtobufCMessageDescriptor tc_db__ctc_ddlalter_space_def__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "tc_db.CtcDDLAlterSpaceDef",
  "CtcDDLAlterSpaceDef",
  "TcDb__CtcDDLAlterSpaceDef",
  "tc_db",
  sizeof(TcDb__CtcDDLAlterSpaceDef),
  6,
  tc_db__ctc_ddlalter_space_def__field_descriptors,
  tc_db__ctc_ddlalter_space_def__field_indices_by_name,
  1,  tc_db__ctc_ddlalter_space_def__number_ranges,
  (ProtobufCMessageInit) tc_db__ctc_ddlalter_space_def__init,
  NULL,NULL,NULL    /* reserved[123] */
};
