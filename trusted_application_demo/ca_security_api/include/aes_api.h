/*
* Copyright (c) 2018, ARM Limited.
*
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef __AES_API_H
#define __AES_API_H

#include <err.h>
#include <tee_client_api.h>

TEEC_Result aes_operate(TEEC_Session* session, uint32_t opcode,
                        TEEC_SharedMemory* in,  uint32_t  size_in,
                        TEEC_SharedMemory* iv,  uint32_t  size_iv,
                        TEEC_SharedMemory* out, uint32_t* size_out);

TEEC_Result aes_generateAndEncryptSecret(TEEC_Session* session,
                                         TEEC_SharedMemory* encrypted_out,
                                         uint32_t size_out);

TEEC_Result aes_createKeyFromEncryptedSecret(TEEC_Session* session,
                                             TEEC_SharedMemory* encrypted_in,
                                             uint32_t size_in);

#endif //__AES_API_H
