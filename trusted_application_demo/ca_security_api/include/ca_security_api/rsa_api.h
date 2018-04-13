//
// Copyright (c) 2018, ARM Limited.
//
// SPDX-License-Identifier: Apache-2.0
//

#ifndef CA_SECURITY_API__RSA_API_H_
#define CA_SECURITY_API__RSA_API_H_

# if __cplusplus
extern "C"
{
# endif

#include <stdbool.h>
#include <tee_client_api.h>

#define TEE_ERROR_SIGNATURE_INVALID  0xFFFF3072
#define RSA_API_SIZE_ENCRYPTED_BYTE  128

TEEC_Result
ca_rsa_operate(
  TEEC_Session * session,
  uint32_t opcode,
  TEEC_SharedMemory * in,
  size_t size_in,
  TEEC_SharedMemory * out,
  size_t size_out);

TEEC_Result
ca_rsa_certify(
  TEEC_Session * session,
  TEEC_SharedMemory * in,
  size_t size_in,
  TEEC_SharedMemory * sha_out);

bool
ca_rsa_verify(
  TEEC_Session * session,
  TEEC_SharedMemory * message_in,
  size_t size_message_in,
  TEEC_SharedMemory * sha_in,
  size_t size_sha_in);

# if __cplusplus
}
# endif

#endif  // CA_SECURITY_API__RSA_API_H_
