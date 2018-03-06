/*
 * Copyright (c) 2018, ARM Limited.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __TA_AES_H
#define __TA_AES_H

#include <stdint.h>

#define TA_AES128_SIZE    128
#define TA_AES128_SIZE_BYTE   (TA_AES128_SIZE / 8)

#define TA_AES_IS_KEY_SIZE_SUPPORTED(keysize) ( (keysize)==TA_AES128_SIZE )

TEE_Result ta_aes_generate_and_encrypt_key(uint32_t id,
                                           uint32_t key_size_bit,
                                           void* buff_out,
                                           uint32_t* size_buff_out);

TEE_Result ta_aes_decrypt_and_allocate_key(uint32_t id,
                                           uint32_t key_size_bit,
                                           void* buffer_in,
                                           uint32_t size_buff_in);


TEE_Result ta_aes_hmac_digest(uint32_t id, void* buff_in,
                              uint32_t size_buff_in,
                              void* buff_out,
                              uint32_t* size_buff_out);

TEE_Result ta_aes_hmac_compare(uint32_t id, void* buff_in,
                               uint32_t size_buff_in, void* sha_in,
                               uint32_t size_sha_in);

TEE_Result ta_aes_encrypt(uint32_t id,   void* buff_in,  uint32_t size_buff_in,
                          void* buff_out, uint32_t* size_buff_out,
                          void* iv,   uint32_t* iv_size_byte);

TEE_Result ta_aes_decrypt(uint32_t id,   void* buff_in,  uint32_t size_buff_in,
                          void* buff_out, uint32_t* size_buff_out,
                          void* iv,   uint32_t iv_size_byte);

#endif
