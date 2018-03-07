/*
 * Copyright (c) 2018, ARM Limited.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef CA_SECURITY_API__AES_API_H_
#define CA_SECURITY_API__AES_API_H_

#include <tee_client_api.h>

TEEC_Result ca_aes_generate_encrypted_key(TEEC_Session *session,
                                          TEEC_SharedMemory *key,
                                          uint32_t size_out);

TEEC_Result ca_aes_decrypt_and_allocate_key(TEEC_Session *session,
                                            TEEC_SharedMemory *encrypted_key,
                                            uint32_t size_encrypted_key);

#endif // CA_SECURITY_API__AES_API_H_
