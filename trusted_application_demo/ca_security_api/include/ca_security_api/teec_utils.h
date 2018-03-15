//
// Copyright (c) 2018, ARM Limited.
//
// SPDX-License-Identifier: Apache-2.0
//

#ifndef CA_SECURITY_API__TEEC_UTILS_H_
#define CA_SECURITY_API__TEEC_UTILS_H_

# if __cplusplus
extern "C"
{
# endif

#include <stdlib.h>
#include <tee_client_api.h>

void
ca_teec_check_result(TEEC_Result res, const char * function, const char * errmsg);

TEEC_Result
ca_teec_allocate_shared_memory(
  TEEC_Context * ctx,
  TEEC_SharedMemory * shm,
  size_t sz,
  uint32_t flags);

TEEC_Result
ca_teec_open_session(TEEC_UUID uuid, TEEC_Context * ctx, TEEC_Session * sess);

void
ca_teec_close_session(TEEC_Context * ctx, TEEC_Session * sess);

inline void
ca_teec_exit_on_failure(TEEC_Context * ctx, TEEC_Session * sess, TEEC_Result res)
{
  if (TEEC_SUCCESS != res) {
    if (NULL != ctx && NULL != sess) {
      ca_teec_close_session(ctx, sess);
    }
    exit(res);
  }
}

# if __cplusplus
}
# endif

#endif  // CA_SECURITY_API__TEEC_UTILS_H_
