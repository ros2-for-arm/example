//
// Copyright (c) 2018, ARM Limited.
//
// SPDX-License-Identifier: Apache-2.0
//

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <tee_client_api.h>

#include <ca_security_api/teec_utils.h>

void
ca_teec_print_result(
  TEEC_Result res,
  const char * function,
  const char * errmsg)
{
  printf("\nRet: 0x%x ", res);
  if (TEEC_SUCCESS != res) {
    fprintf(stderr, "[ERROR] in %s \n[MSG] %s: ", function, errmsg);
    switch ((uint32_t)res) {
      case TEEC_ERROR_GENERIC:
        fprintf(stderr, "TEEC_ERROR_GENERIC\n");
      case TEEC_ERROR_ACCESS_DENIED:
        fprintf(stderr, "TEEC_ERROR_ACCESS_DENIED\n");
        break;
      case TEEC_ERROR_CANCEL:
        fprintf(stderr, "TEEC_ERROR_CANCEL\n");
        break;
      case TEEC_ERROR_ACCESS_CONFLICT:
        fprintf(stderr, "TEEC_ERROR_ACCESS_CONFLICT\n");
        break;
      case TEEC_ERROR_EXCESS_DATA:
        fprintf(stderr, "TEEC_ERROR_EXCESS_DATA\n");
        break;
      case TEEC_ERROR_BAD_FORMAT:
        fprintf(stderr, "TEEC_ERROR_BAD_FORMAT\n");
        break;
      case TEEC_ERROR_BAD_PARAMETERS:
        fprintf(stderr, "TEEC_ERROR_BAD_PARAMETERS\n");
        break;
      case TEEC_ERROR_BAD_STATE:
        fprintf(stderr, "TEEC_ERROR_BAD_STATE\n");
        break;
      case TEEC_ERROR_ITEM_NOT_FOUND:
        fprintf(stderr, "TEEC_ERROR_ITEM_NOT_FOUND\n");
        break;
      case TEEC_ERROR_NOT_IMPLEMENTED:
        fprintf(stderr, "TEEC_ERROR_NOT_IMPLEMENTED\n");
        break;
      case TEEC_ERROR_NOT_SUPPORTED:
        fprintf(stderr, "TEEC_ERROR_NOT_SUPPORTED\n");
        break;
      case TEEC_ERROR_NO_DATA:
        fprintf(stderr, "TEEC_ERROR_NO_DATA\n");
        break;
      case TEEC_ERROR_OUT_OF_MEMORY:
        fprintf(stderr, "TEEC_ERROR_OUT_OF_MEMORY\n");
        break;
      case TEEC_ERROR_BUSY:
        fprintf(stderr, "TEEC_ERROR_BUSY\n");
        break;
      case TEEC_ERROR_COMMUNICATION:
        fprintf(stderr, "TEEC_ERROR_COMMUNICATION\n");
        break;
      case TEEC_ERROR_SECURITY:
        fprintf(stderr, "TEEC_ERROR_SECURITY\n");
        break;
      case TEEC_ERROR_SHORT_BUFFER:
        fprintf(stderr, "TEEC_ERROR_SHORT_BUFFER\n");
        break;
      case TEEC_ERROR_EXTERNAL_CANCEL:
        fprintf(stderr, "TEEC_ERROR_EXTERNAL_CANCEL\n");
        break;
      case TEEC_ERROR_TARGET_DEAD:
        fprintf(stderr, "TEEC_ERROR_TARGET_DEAD\n");
        break;
      default:
        fprintf(stderr, "Unknown opcode\n");
        break;
    }
  }
  printf("SUCCESS: %s\n", errmsg);
}

TEEC_Result
ca_teec_allocate_shared_memory(
  TEEC_Context * ctx,
  TEEC_SharedMemory * shm,
  size_t sz,
  uint32_t flags)
{
  TEEC_Result res;
  shm->flags = flags;
  shm->buffer = NULL;
  shm->size = sz;
  res = TEEC_AllocateSharedMemory(ctx, shm);
  ca_teec_print_result(res, __func__, "TEEC_AllocateSharedMemory");
  return res;
}

TEEC_Result
ca_teec_open_session(
  TEEC_UUID uuid,
  TEEC_Context * ctx,
  TEEC_Session * sess)
{
  TEEC_Result res;
  uint32_t err_origin;

  res = TEEC_InitializeContext(NULL, ctx);
  ca_teec_print_result(res, __func__, "TEEC_InitializeContext");
  if (TEEC_SUCCESS != res) {
    return res;
  }

  res = TEEC_OpenSession(ctx,
      sess,
      &uuid,
      TEEC_LOGIN_PUBLIC,
      NULL,
      NULL,
      &err_origin);
  ca_teec_print_result(res, __func__, "TEEC_OpenSession");
  if (TEEC_SUCCESS != res) {
    TEEC_CloseSession(sess);
  }

  return res;
}

void
ca_teec_close_session(TEEC_Context * ctx, TEEC_Session * sess)
{
  TEEC_CloseSession(sess);
  TEEC_FinalizeContext(ctx);
}
