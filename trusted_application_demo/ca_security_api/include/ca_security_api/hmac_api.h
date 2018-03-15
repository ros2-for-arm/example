//
// Copyright (c) 2018, ARM Limited.
//
// SPDX-License-Identifier: Apache-2.0
//

#ifndef CA_SECURITY_API__HMAC_API_H_
#define CA_SECURITY_API__HMAC_API_H_

# if __cplusplus
extern "C"
{
# endif

#include <stdbool.h>
#include <tee_client_api.h>

#define HMAC_API_SHA1_SIZE_BYTE 20

TEEC_Result
ca_hmac_compute(
  TEEC_Session * session,
  TEEC_SharedMemory * in,
  TEEC_SharedMemory * sha_out,
  uint32_t size_in);

bool
ca_hmac_compare(
  TEEC_Session * session,
  TEEC_SharedMemory * message_in,
  TEEC_SharedMemory * sha_in,
  uint32_t size_message);

# if __cplusplus
}
# endif

#endif  // CA_SECURITY_API__HMAC_API_H_
