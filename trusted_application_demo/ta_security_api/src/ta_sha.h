/*
 * Copyright (c) 2018, ARM Limited.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef TA_SECURITY_API__TA_SHA_H_
#define TA_SECURITY_API__TA_SHA_H_

#include <stdint.h>

#define TA_SHA_SIZE_OF_SHA1 20

TEE_Result ta_sha_digest(void* buff_in, uint32_t buff_size,
                         void* sha_out, uint32_t* sha_size);

TEE_Result ta_initialize_digest(void);

#endif // TA_SECURITY_API__TA_SHA_H_
