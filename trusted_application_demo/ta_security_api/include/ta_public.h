/*
 * Copyright (c) 2018, ARM Limited.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef TA_SECURITY_API__TA_PUBLIC_INCLUDE_H_
#define TA_SECURITY_API__TA_PUBLIC_INCLUDE_H_

/* Generated from https://www.uuidgenerator.net/ */
#define TA_TRUSTED_UUID { 0xaed3b02c, 0x8e42, 0x11e7, \
                          { 0xbb, 0x31, 0xbe, 0x2e, 0x44, 0xb0, 0x6b, 0x34} }

#define TA_COMMAND_DECRYPT_AND_STORE_SECRET  0
#define TA_COMMAND_GENERATE_AND_ENCRYPT_SECRET  1
#define TA_COMMAND_RSA_OPERATION    2
#define TA_COMMAND_HMAC_COMPARE_DIGESTS    3
#define TA_COMMAND_HMAC_COMPUTE_DIGEST    4
#define TA_COMMAND_RSA_COMPARE_DIGESTS    5
#define TA_COMMAND_RSA_COMPUTE_DIGEST    6
#define TA_COMMAND_AES_ENCRYPT      7
#define TA_COMMAND_AES_DECRYPT      8

#define TA_PUBLIC_MAX_KEY_STORAGE    8

#endif // TA_SECURITY_API__TA_PUBLIC_INCLUDE_H_
