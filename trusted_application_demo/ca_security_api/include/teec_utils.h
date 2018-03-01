/*
* Copyright (c) 2018, ARM Limited.
*
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef __TEEC_UTILS_H
#define __TEEC_UTILS_H

#include <stdio.h>
#include <err.h>
#include <tee_client_api.h>

void teec_checkResult(TEEC_Result res, const char* function, const char* errmsg);

TEEC_Result teec_allocateSharedMemory(TEEC_Context* ctx,
                                      TEEC_SharedMemory *shm, size_t sz,
                                      uint32_t flags);

TEEC_Result teec_openSession(TEEC_UUID uuid, TEEC_Context* ctx,
                             TEEC_Session* sess);

void teec_closeSession(TEEC_Context* ctx, TEEC_Session* sess);

inline void teec_exitOnFailure(TEEC_Context* ctx, TEEC_Session* sess, TEEC_Result res){
  if (res != TEEC_SUCCESS){
    if(ctx != NULL && sess != NULL){
      teec_closeSession(ctx, sess);
    }
    exit(res);
  }
}

#endif //__TEEC_UTILS_H
