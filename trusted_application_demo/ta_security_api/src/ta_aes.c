//
// Copyright (c) 2018, ARM Limited.
//
// SPDX-License-Identifier: Apache-2.0
//

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "ta_security_api/ta_public.h"

#include "ta_security_api/ta_aes.h"
#include "ta_security_api/ta_rsa.h"
#include "ta_security_api/ta_utils.h"

static TEE_OperationHandle aes_encrypt_op_handle;
static TEE_OperationHandle aes_decrypt_op_handle;
static TEE_OperationHandle hmac_op_handle;

static TEE_Result
ta_aes_initialize_key(
  void * aes_secret,
  uint32_t size_secret,
  uint32_t key_size_bit,
  TEE_OperationHandle * encrypt_op_handle,
  TEE_OperationHandle * decrypt_op_handle);

static TEE_Result
ta_aes_initialize_hmac(
  void * aes_secret,
  uint32_t size_secret,
  uint32_t key_size_bit,
  TEE_OperationHandle * hmac_handle);

static TEE_Result
ta_aes_initialize_hmac(
  void * aes_secret,
  uint32_t size_secret,
  uint32_t key_size_bit,
  TEE_OperationHandle * hmac_handle)
{
  TEE_Attribute attrs[1];
  TEE_ObjectHandle object_handle;
  TEE_Result result;

  attrs[0].attributeID = TEE_ATTR_SECRET_VALUE;
  attrs[0].content.ref.buffer = aes_secret;
  attrs[0].content.ref.length = size_secret;

  // Object handle should not be initialized
  object_handle = (TEE_ObjectHandle)NULL;
  result = TEE_AllocateTransientObject(TEE_TYPE_HMAC_SHA1,
      key_size_bit,
      &object_handle);
  if (TEE_SUCCESS != result) {
    return result;
  }

  result = TEE_PopulateTransientObject(object_handle, attrs, 1);
  if (TEE_SUCCESS != result) {
    return result;
  }

  // Allocate the operation handle for decryption
  result = ta_utils_create_handle(object_handle,
      TEE_ALG_HMAC_SHA1,
      TEE_MODE_MAC,
      hmac_handle);
  if (TEE_SUCCESS != result) {
    return result;
  }

  TEE_FreeTransientObject(object_handle);

  return result;
}

/*
 * Setup a decryt and encryption operation handler from a given secret.
 * Those handles will be used to encrypt/decrypt/verify/certify messages using
 * AES and HMAC.
 */
static TEE_Result
ta_aes_initialize_key(
  void * aes_secret,
  uint32_t size_secret,
  uint32_t key_size_bit,
  TEE_OperationHandle * encrypt_op_handle,
  TEE_OperationHandle * decrypt_op_handle)
{
  TEE_Attribute attrs[1];
  TEE_ObjectHandle object_handle;
  TEE_Result result;

  // We want AES key that are of size 64, 128, 256 bits
  if (!TA_AES_IS_KEY_SIZE_SUPPORTED(key_size_bit)) {
    return TEE_ERROR_BAD_PARAMETERS;
  }

  // Buffer should be greater or equal to the size of the key
  if (size_secret < (key_size_bit / 8)) {
    return TEE_ERROR_BAD_PARAMETERS;
  }

  // Fill the attribute feature with the AES secret.
  attrs[0].attributeID = TEE_ATTR_SECRET_VALUE;
  attrs[0].content.ref.buffer = aes_secret;
  attrs[0].content.ref.length = size_secret;

  // Object handle should not be initialized
  object_handle = (TEE_ObjectHandle)NULL;
  // Allocate the object handle that is used to store the key
  result = TEE_AllocateTransientObject(TEE_TYPE_AES,
      key_size_bit,
      &object_handle);
  if (TEE_SUCCESS != result) {
    return result;
  }

  // Initialise the AES secret key of the object handle
  result = TEE_PopulateTransientObject(object_handle, attrs, 1);
  if (TEE_SUCCESS != result) {
    return result;
  }

  // Allocate the operation handle for encryption
  result = ta_utils_create_handle(object_handle,
      TEE_ALG_AES_CBC_NOPAD,
      TEE_MODE_ENCRYPT,
      encrypt_op_handle);
  if (TEE_SUCCESS != result) {
    return result;
  }

  // Allocate the operation handle for decryption
  result = ta_utils_create_handle(object_handle,
      TEE_ALG_AES_CBC_NOPAD,
      TEE_MODE_DECRYPT,
      decrypt_op_handle);
  if (TEE_SUCCESS != result) {
    return result;
  }

  TEE_FreeTransientObject(object_handle);
  return result;
}

/*
 * Generate a secret of the input length. This secret is stored and directly
 * returned encrypted through RSA.
 */
TEE_Result
ta_aes_generate_and_encrypt_key(
  uint32_t key_size_bit,
  void * buff_out,
  uint32_t * size_buff_out)
{
  TEE_Result result = TEE_SUCCESS;
  void * aes_secret;
  uint32_t size_aes_secret_byte;

  if (!TA_AES_IS_KEY_SIZE_SUPPORTED(key_size_bit)) {
    return TEE_ERROR_BAD_PARAMETERS;
  }

  size_aes_secret_byte = key_size_bit / 8;
  aes_secret = TEE_Malloc(size_aes_secret_byte, TEE_MALLOC_FILL_ZERO);
  TEE_GenerateRandom(aes_secret, size_aes_secret_byte);

  result = ta_aes_initialize_hmac(aes_secret,
      size_aes_secret_byte,
      key_size_bit,
      &hmac_op_handle);
  if (TEE_SUCCESS != result) {
    goto error;
  }

  result = ta_aes_initialize_key(aes_secret,
      size_aes_secret_byte,
      key_size_bit,
      &aes_encrypt_op_handle,
      &aes_decrypt_op_handle);
  if (TEE_SUCCESS != result) {
    goto error;
  }

  result = ta_rsa_operation(TA_RSA_ENCRYPT,
      aes_secret,
      size_aes_secret_byte,
      buff_out,
      size_buff_out);
  if (TEE_SUCCESS != result) {
    goto error;
  }

error:
  TEE_Free(aes_secret);
  return result;
}

/*
 * Setup the key for a specific ID. The key is coming encrypted by RSA
 * and thus should be decrypted before storing it.
 */
TEE_Result
ta_aes_decrypt_and_allocate_key(
  uint32_t key_size_bit,
  void * buffer_in,
  uint32_t size_buff_in)
{
  TEE_Result result = TEE_SUCCESS;
  void * aes_secret;
  uint32_t size_aes_secret;

  size_aes_secret = size_buff_in;
  aes_secret = TEE_Malloc(size_buff_in, 0);
  result = ta_rsa_operation(TA_RSA_DECRYPT,
      buffer_in,
      size_buff_in,
      aes_secret,
      &size_aes_secret);
  if (TEE_SUCCESS != result) {
    goto error;
  }

  result = ta_aes_initialize_hmac(aes_secret,
      key_size_bit / 8,
      key_size_bit,
      &hmac_op_handle);
  if (TEE_SUCCESS != result) {
    goto error;
  }

  result = ta_aes_initialize_key(aes_secret,
      key_size_bit / 8,
      key_size_bit,
      &aes_encrypt_op_handle,
      &aes_decrypt_op_handle);
  if (TEE_SUCCESS != result) {
    goto error;
  }

error:
  TEE_Free(aes_secret);
  return result;
}

/*
 * Get the ID of the secret to sign the digest of the message given in input
 * The output message has a size of 20 bytes. The size of the output buffer is
 * checked and set in the function TEE_MACComputeFinal. So initially it should
 * have a size of at least 20 bytes for SHA1 HMAC
 */
TEE_Result
ta_aes_hmac_digest(
  void * buff_in,
  uint32_t size_buff_in,
  void * buff_out,
  uint32_t * size_buff_out)
{
  TEE_Result result = TEE_SUCCESS;

  TEE_MACInit(hmac_op_handle, (void *)NULL, 0);
  result = TEE_MACComputeFinal(hmac_op_handle,
      buff_in,
      size_buff_in,
      buff_out,
      size_buff_out);
  return result;
}

/*
 * Get the message and compare its digest to check if it has been certified.
 */
TEE_Result
ta_aes_hmac_compare(
  void * buff_in,
  uint32_t size_buff_in,
  void * sha_in,
  uint32_t size_sha_in)
{
  TEE_Result result = TEE_SUCCESS;

  TEE_MACInit(hmac_op_handle, (void *)NULL, 0);
  result = TEE_MACCompareFinal(hmac_op_handle,
      buff_in,
      size_buff_in,
      sha_in,
      size_sha_in);
  return result;
}
