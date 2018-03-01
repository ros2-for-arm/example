/*
* Copyright (c) 2018, ARM Limited.
*
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef __HMAC_API_H
#define __HMAC_API_H

#include <err.h>
#include <tee_client_api.h>
#include <stdbool.h>

#define HMAC_API_SHA1_SIZE 20

TEEC_Result hmac_computeSHA(TEEC_Session* session, TEEC_SharedMemory* in,
                            TEEC_SharedMemory* sha_out, uint32_t size_in);

bool hmac_compareSHA(TEEC_Session* session, TEEC_SharedMemory* message_in,
                     TEEC_SharedMemory* sha_in, uint32_t size_message);

#endif //__HMAC_API_H
