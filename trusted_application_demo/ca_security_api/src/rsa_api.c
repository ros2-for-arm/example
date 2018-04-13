//
// Copyright (c) 2018, ARM Limited.
//
// SPDX-License-Identifier: Apache-2.0
//

#include <string.h>
#include <tee_client_api.h>
#include <ta_security_api/ta_public.h>

#include <ca_security_api/teec_utils.h>
#include <ca_security_api/rsa_api.h>

TEEC_Result
ca_rsa_operate(
  TEEC_Session * session,
  uint32_t opcode,
  TEEC_SharedMemory * in,
  size_t size_in,
  TEEC_SharedMemory * out,
  size_t size_out)
{
  uint32_t ret_origin;
  TEEC_Operation op;
  TEEC_Result res;

  memset(&op, 0, sizeof(op));
  op.paramTypes = TEEC_PARAM_TYPES(
    TEEC_VALUE_INPUT,
    TEEC_MEMREF_PARTIAL_INPUT,
    TEEC_MEMREF_PARTIAL_OUTPUT,
    TEEC_NONE);

  op.params[0].value.a = opcode;
  op.params[1].memref.parent = in;
  op.params[1].memref.size = size_in;
  op.params[2].memref.parent = out;
  op.params[2].memref.size = size_out;

  res = TEEC_InvokeCommand(session, TA_COMMAND_RSA_OPERATION, &op, &ret_origin);

  ca_teec_print_result(
    res,
    __func__,
    "TEEC_InvokeCommand TA_COMMAND_RSA_OPERATION");
  return res;
}

TEEC_Result
ca_rsa_certify(
  TEEC_Session * session,
  TEEC_SharedMemory * in,
  size_t size_in,
  TEEC_SharedMemory * sha_out)
{
  uint32_t ret_origin;
  TEEC_Operation op;
  TEEC_Result res;

  memset(&op, 0, sizeof(op));
  op.params[0].memref.parent = in;
  op.params[0].memref.size = size_in;
  op.params[1].memref.parent = sha_out;
  op.params[1].memref.size = sha_out->size;

  op.paramTypes = TEEC_PARAM_TYPES(
    TEEC_MEMREF_PARTIAL_INOUT,
    TEEC_MEMREF_PARTIAL_OUTPUT,
    TEEC_NONE,
    TEEC_NONE);

  res = TEEC_InvokeCommand(
    session,
    TA_COMMAND_RSA_COMPUTE_DIGEST,
    &op,
    &ret_origin);

  ca_teec_print_result(res, __func__, "TEEC_InvokeCommand TA_RSA_SIGN_COMPUTE");
  return res;
}

bool
ca_rsa_verify(
  TEEC_Session * session,
  TEEC_SharedMemory * message_in,
  size_t size_message_in,
  TEEC_SharedMemory * sha_in,
  size_t size_sha_in)
{
  uint32_t ret_origin;
  TEEC_Operation op;
  TEEC_Result res;

  memset(&op, 0, sizeof(op));
  op.params[0].memref.parent = message_in;
  op.params[0].memref.size = size_message_in;
  op.params[1].memref.parent = sha_in;
  op.params[1].memref.size = size_sha_in;

  op.paramTypes = TEEC_PARAM_TYPES(
    TEEC_MEMREF_PARTIAL_INPUT,
    TEEC_MEMREF_PARTIAL_INPUT,
    TEEC_NONE,
    TEEC_NONE);
  res = TEEC_InvokeCommand(
    session,
    TA_COMMAND_RSA_COMPARE_DIGESTS,
    &op,
    &ret_origin);

  if (TEEC_SUCCESS != res) {
    return false;
  }

  ca_teec_print_result(
    res,
    __func__,
    "TEEC_InvokeCommand TA_RSA_VERIFY_COMPARE");

  return true;
}
