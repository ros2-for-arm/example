//
// Copyright (c) 2018, ARM Limited.
//
// SPDX-License-Identifier: Apache-2.0
//

#include <string.h>
#include <tee_client_api.h>
#include <ta_security_api/ta_public.h>

#include <ca_security_api/teec_utils.h>
#include <ca_security_api/aes_api.h>

TEEC_Result
ca_aes_generate_encrypted_key(
  TEEC_Session * session,
  TEEC_SharedMemory * key,
  uint32_t size_out)
{
  uint32_t ret_origin;
  TEEC_Operation op;
  TEEC_Result res;

  memset(&op, 0, sizeof(op));
  op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INOUT,
      TEEC_NONE,
      TEEC_NONE,
      TEEC_NONE);
  op.params[0].memref.parent = key;
  op.params[0].memref.size = size_out;

  res = TEEC_InvokeCommand(session,
      TA_COMMAND_GENERATE_AND_ENCRYPT_SECRET,
      &op,
      &ret_origin);
  ca_teec_check_result(res,
    __func__,
    "TEEC_InvokeCommand TA_GENERATE_ENCRYPT_AES_KEY");
  return res;
}

TEEC_Result
ca_aes_decrypt_and_allocate_key(
  TEEC_Session * session,
  TEEC_SharedMemory * encrypted_key,
  uint32_t size_encrypted_key)
{
  uint32_t ret_origin;
  TEEC_Operation op;
  TEEC_Result res = TEEC_SUCCESS;

  memset(&op, 0, sizeof(op));
  op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INPUT,
      TEEC_NONE,
      TEEC_NONE,
      TEEC_NONE);
  op.params[0].memref.parent = encrypted_key;
  op.params[0].memref.size = size_encrypted_key;

  res = TEEC_InvokeCommand(session,
      TA_COMMAND_DECRYPT_AND_STORE_SECRET,
      &op,
      &ret_origin);
  ca_teec_check_result(res,
    __func__,
    "TEEC_InvokeCommand TA_DECRYPT_ALLOCATE_AES_KEY");
  return res;
}
