/*
* Copyright (c) 2018, ARM Limited.
*
* SPDX-License-Identifier: Apache-2.0
*/

#include <stdio.h>
#include <err.h>
#include <teec_utils.h>
#include <tee_client_api.h>
#include <ta_public.h>
#include <aes_api.h>

TEEC_Result aes_operate(TEEC_Session* session,  uint32_t  opcode,
                        TEEC_SharedMemory* in,  uint32_t  size_in,
                        TEEC_SharedMemory* iv,  uint32_t  size_iv,
                        TEEC_SharedMemory* out, uint32_t* size_out)
{
  uint32_t ret_origin;
  TEEC_Operation op;
  TEEC_Result res;

  memset(&op, 0, sizeof(op));
  op.params[0].memref.parent = in;
  op.params[0].memref.size   = size_in;
  op.params[1].memref.parent = out;
  op.params[1].memref.size   = *size_out;
  op.params[2].memref.parent = iv;
  op.params[2].memref.size   = size_iv;

  if(opcode == 0) {
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INPUT,
             TEEC_MEMREF_PARTIAL_OUTPUT,
             TEEC_MEMREF_PARTIAL_OUTPUT,
             TEEC_NONE);
    res = TEEC_InvokeCommand(session, TA_COMMAND_AES_ENCRYPT, &op,
           &ret_origin);
    teec_checkResult(res, __func__, "TEEC_InvokeCommand TA_ENCRYPT_AES");
  } else {
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INPUT,
             TEEC_MEMREF_PARTIAL_OUTPUT,
             TEEC_MEMREF_PARTIAL_INPUT,
             TEEC_NONE);
    res = TEEC_InvokeCommand(session, TA_COMMAND_AES_DECRYPT, &op,
           &ret_origin);
    teec_checkResult(res, __func__, "TEEC_InvokeCommand TA_DECRYPT_AES");
  }
  return res;
}

TEEC_Result aes_generateAndEncryptSecret(TEEC_Session* session,
                                         TEEC_SharedMemory* encrypted_out,
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

  op.params[0].memref.parent = encrypted_out;
  op.params[0].memref.size = size_out;
  res = TEEC_InvokeCommand(session,
                           TA_COMMAND_GENERATE_AND_ENCRYPT_SECRET,
                           &op, &ret_origin);
  teec_checkResult(res, __func__,
                   "TEEC_InvokeCommand TA_GENERATE_ENCRYPT_AES_KEY");
  return res;
}

TEEC_Result aes_createKeyFromEncryptedSecret(TEEC_Session* session,
                                             TEEC_SharedMemory* encrypted_in,
                                             uint32_t size_in)
{
  uint32_t ret_origin;
  TEEC_Operation op;
  TEEC_Result res = TEEC_SUCCESS;

  memset(&op, 0, sizeof(op));
  op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INPUT,
           TEEC_NONE,
           TEEC_NONE,
           TEEC_NONE);
  op.params[0].memref.parent = encrypted_in;
  op.params[0].memref.size = size_in;
  res = TEEC_InvokeCommand(session, TA_COMMAND_DECRYPT_AND_STORE_SECRET,
         &op, &ret_origin);
  teec_checkResult(res, __func__,
                   "TEEC_InvokeCommand TA_DECRYPT_ALLOCATE_AES_KEY");
  return res;
}
