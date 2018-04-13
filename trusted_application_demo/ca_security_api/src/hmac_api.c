//
// Copyright (c) 2018, ARM Limited.
//
// SPDX-License-Identifier: Apache-2.0
//

#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <tee_client_api.h>
#include <ta_security_api/ta_public.h>

#include <ca_security_api/teec_utils.h>
#include <ca_security_api/hmac_api.h>

TEEC_Result
ca_hmac_compute(
  TEEC_Session * session,
  TEEC_SharedMemory * in,
  TEEC_SharedMemory * sha_out,
  size_t size_in)
{
  uint32_t ret_origin;
  TEEC_Operation op;
  TEEC_Result res;

  memset(&op, 0, sizeof(op));
  op.params[0].memref.parent = in;
  op.params[0].memref.size = size_in;
  op.params[1].memref.parent = sha_out;
  op.params[1].memref.size = sha_out->size;

  op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INPUT,
      TEEC_MEMREF_PARTIAL_OUTPUT,
      TEEC_NONE,
      TEEC_NONE);

  res = TEEC_InvokeCommand(session,
      TA_COMMAND_HMAC_COMPUTE_DIGEST,
      &op,
      &ret_origin);
  ca_teec_print_result(res, __func__, "TEEC_InvokeCommand TA_HMAC_COMPUTE");
  return res;
}

bool
ca_hmac_compare(
  TEEC_Session * session,
  TEEC_SharedMemory * message_in,
  TEEC_SharedMemory * sha_in,
  size_t size_message)
{
  uint32_t ret_origin;
  TEEC_Operation op;
  TEEC_Result res;

  memset(&op, 0, sizeof(op));
  op.params[0].memref.parent = message_in;
  op.params[0].memref.size = size_message;
  op.params[1].memref.parent = sha_in;
  op.params[1].memref.size = sha_in->size;

  op.paramTypes = TEEC_PARAM_TYPES(
    TEEC_MEMREF_PARTIAL_INPUT,
    TEEC_MEMREF_PARTIAL_INPUT,
    TEEC_NONE,
    TEEC_NONE);

  res = TEEC_InvokeCommand(
    session,
    TA_COMMAND_HMAC_COMPARE_DIGESTS,
    &op,
    &ret_origin);

  ca_teec_print_result(
    res,
    __func__,
    "TEEC_InvokeCommand TA_COMMAND_HMAC_COMPARE_DIGESTS");

  return TEEC_SUCCESS == res;
}
