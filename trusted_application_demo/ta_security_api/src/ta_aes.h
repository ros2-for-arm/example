/*
 * Copyright (c) 2018, ARM Limited.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __TA_AES_H
#define __TA_AES_H

#include <stdint.h>

#define TA_AES128_SIZE    128
#define TA_AES128_SIZE_BYTE   (TA_AES128_SIZE >> 3)

#define TA_AES_IS_KEY_SIZE_SUPPORTED(keysize) ((keysize) == TA_AES128_SIZE)

TEE_Result
ta_aes_generate_and_encrypt_key(uint32_t key_size_bit,
                                void *buff_out,
                                uint32_t *size_buff_out);

TEE_Result
ta_aes_decrypt_and_allocate_key(uint32_t key_size_bit,
                                void *buffer_in,
                                uint32_t size_buff_in);

TEE_Result
ta_aes_hmac_digest(void *buff_in,
                   uint32_t size_buff_in,
                   void *buff_out,
                   uint32_t *size_buff_out);

TEE_Result
ta_aes_hmac_compare(void *buff_in,
                    uint32_t size_buff_in,
                    void *sha_in,
                    uint32_t size_sha_in);

#endif
