/*
* Copyright (c) 2018, ARM Limited.
*
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef __TA_SHA_H
#define __TA_SHA_H

#include <stdint.h>

#define TA_SHA_SIZE_OF_SHA1 20

TEE_Result ta_sha_digest(void* buff_in, uint32_t buff_size,
       void* sha_out, uint32_t* sha_size);

TEE_Result ta_initialize_digest(void);

#endif
