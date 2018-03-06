/*
 * Copyright (c) 2018, ARM Limited.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef TA_SECURITY_API__TA_RSA_H_
#define TA_SECURITY_API__TA_RSA_H_

#include <stdint.h>

#define TA_RSA_ENCRYPT 0
#define TA_RSA_DECRYPT 1

#define TA_RSA1024_KEY_SIZE_BIT  1024

TEE_Result ta_rsa_prepare_key(void);

TEE_Result ta_rsa_operation(uint32_t mode,
                            void* buff_in, uint32_t size_buff_in,
                            void* buff_out, uint32_t* size_buff_out);

TEE_Result ta_rsa_sign_digest(void* buff_in,  uint32_t size_buff_in,
                              void* buff_out, uint32_t* size_buff_out);

TEE_Result ta_rsa_compare_digest(void* buff_in,  uint32_t size_buff_in,
                                 void* sha_in,   uint32_t size_sha_in);

#endif // TA_SECURITY_API__TA_RSA_H_
