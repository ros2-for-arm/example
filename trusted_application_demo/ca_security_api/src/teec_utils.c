/*
 * Copyright (c) 2018, ARM Limited.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <tee_client_api.h>

#include "teec_utils.h"

void
ca_teec_check_result(TEEC_Result res, const char *function, const char *errmsg)
{
  printf("\nRet: 0x%x ", res);
  if (res != TEEC_SUCCESS) {
    printf("[ERROR] in %s \n[MSG] %s: ", function, errmsg);
    switch ((uint32_t)res) {
    case TEEC_ERROR_GENERIC:
      printf("TEEC_ERROR_GENERIC\n");
    case TEEC_ERROR_ACCESS_DENIED:
      printf("TEEC_ERROR_ACCESS_DENIED\n");
      break;
    case TEEC_ERROR_CANCEL:
      printf("TEEC_ERROR_CANCEL\n");
      break;
    case TEEC_ERROR_ACCESS_CONFLICT:
      printf("TEEC_ERROR_ACCESS_CONFLICT\n");
      break;
    case TEEC_ERROR_EXCESS_DATA:
      printf("TEEC_ERROR_EXCESS_DATA\n");
      break;
    case TEEC_ERROR_BAD_FORMAT:
      printf("TEEC_ERROR_BAD_FORMAT\n");
      break;
    case TEEC_ERROR_BAD_PARAMETERS:
      printf("TEEC_ERROR_BAD_PARAMETERS\n");
      break;
    case TEEC_ERROR_BAD_STATE:
      printf("TEEC_ERROR_BAD_STATE\n");
      break;
    case TEEC_ERROR_ITEM_NOT_FOUND:
      printf("TEEC_ERROR_ITEM_NOT_FOUND\n");
      break;
    case TEEC_ERROR_NOT_IMPLEMENTED:
      printf("TEEC_ERROR_NOT_IMPLEMENTED\n");
      break;
    case TEEC_ERROR_NOT_SUPPORTED:
      printf("TEEC_ERROR_NOT_SUPPORTED\n");
      break;
    case TEEC_ERROR_NO_DATA:
      printf("TEEC_ERROR_NO_DATA\n");
      break;
    case TEEC_ERROR_OUT_OF_MEMORY:
      printf("TEEC_ERROR_OUT_OF_MEMORY\n");
      break;
    case TEEC_ERROR_BUSY:
      printf("TEEC_ERROR_BUSY\n");
      break;
    case TEEC_ERROR_COMMUNICATION:
      printf("TEEC_ERROR_COMMUNICATION\n");
      break;
    case TEEC_ERROR_SECURITY:
      printf("TEEC_ERROR_SECURITY\n");
      break;
    case TEEC_ERROR_SHORT_BUFFER:
      printf("TEEC_ERROR_SHORT_BUFFER\n");
      break;
    case TEEC_ERROR_EXTERNAL_CANCEL:
      printf("TEEC_ERROR_EXTERNAL_CANCEL\n");
      break;
    case TEEC_ERROR_TARGET_DEAD:
      printf("TEEC_ERROR_TARGET_DEAD\n");
      break;
    default:
      printf("Unknown opcode\n");
      break;
    }
  }
  printf("SUCCESS: %s\n", errmsg);
}

TEEC_Result
ca_teec_allocate_shared_memory(TEEC_Context *ctx,
                               TEEC_SharedMemory *shm,
                               size_t sz,
                               uint32_t flags)
{
  TEEC_Result res;
  shm->flags = flags;
  shm->buffer = NULL;
  shm->size = sz;
  res = TEEC_AllocateSharedMemory(ctx, shm);
  ca_teec_check_result(res, __func__, "TEEC_AllocateSharedMemory");
  return res;
}

TEEC_Result
ca_teec_open_session(TEEC_UUID uuid,
                     TEEC_Context *ctx,
                     TEEC_Session *sess)
{
  TEEC_Result res;
  uint32_t err_origin;

  res = TEEC_InitializeContext(NULL, ctx);
  ca_teec_check_result(res, __func__, "TEEC_InitializeContext");
  if (res != TEEC_SUCCESS) {
    return res;
  }

  res = TEEC_OpenSession(ctx,
                         sess,
                         &uuid,
                         TEEC_LOGIN_PUBLIC,
                         NULL,
                         NULL,
                         &err_origin);
  ca_teec_check_result(res, __func__, "TEEC_OpenSession");
  if (res != TEEC_SUCCESS) {
    TEEC_CloseSession(sess);
  }

  return res;
}

void
ca_teec_close_session(TEEC_Context *ctx, TEEC_Session *sess)
{
  TEEC_CloseSession(sess);
  TEEC_FinalizeContext(ctx);
}
