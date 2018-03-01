/*
* Copyright (c) 2018, ARM Limited.
*
* SPDX-License-Identifier: Apache-2.0
*/

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "ta_rsa.h"
#include "ta_sha.h"
#include "ta_rsa_keys.h"
#include "ta_utils.h"

static TEE_OperationHandle rsa_decrypt_op_handle;
static TEE_OperationHandle rsa_encrypt_op_handle;
static TEE_OperationHandle rsa_sign_op_handle;
static TEE_OperationHandle rsa_verify_op_handle;

TEE_Result ta_rsa_prepare_key(void)
{
  const uint32_t _NUMBER_ATTRIBUTE_RSA_KEY=8;

  TEE_ObjectHandle object_handle;
  TEE_Result result;
  TEE_Attribute attrs[_NUMBER_ATTRIBUTE_RSA_KEY];

  /* As we only want to create a pair of key with precomputed value,
   * we need to specify those arguments */
  INITIALIZE_ATTRIBUTE_PARAMETERS_RSA(attrs, RSA1024_KEY1);

  // Object handle should not be initialized
  object_handle = (TEE_ObjectHandle) NULL;

  result = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR,
                                       TA_RSA1024_KEY_SIZE_BIT,
                                       &object_handle);
  if(result != TEE_SUCCESS){
    return result;
  }

  result = TEE_PopulateTransientObject(object_handle,
                                       attrs,
                                       _NUMBER_ATTRIBUTE_RSA_KEY);
  if(result != TEE_SUCCESS){
    return result;
  }

  // Create operation handler for encryption
  result = ta_utils_create_handle(object_handle,
                                  TEE_ALG_RSA_NOPAD,
                                  TEE_MODE_ENCRYPT,
                                  &rsa_encrypt_op_handle);
  if(result != TEE_SUCCESS){
    return result;
  }

  // Create operation handler for decryption
  result = ta_utils_create_handle(object_handle,
                                  TEE_ALG_RSA_NOPAD,
                                  TEE_MODE_DECRYPT,
                                  &rsa_decrypt_op_handle);
  if(result != TEE_SUCCESS){
    return result;
  }

  // Create operation handler for signature
  result = ta_utils_create_handle(object_handle,
                                  TEE_ALG_RSASSA_PKCS1_V1_5_SHA1,
                                  TEE_MODE_SIGN,
                                  &rsa_sign_op_handle);
  if(result != TEE_SUCCESS){
    return result;
  }

  // Create operation handler for verification
  result = ta_utils_create_handle(object_handle,
                                  TEE_ALG_RSASSA_PKCS1_V1_5_SHA1,
                                  TEE_MODE_VERIFY,
                                  &rsa_verify_op_handle);
  if(result != TEE_SUCCESS){
    return result;
  }

  // Can be freed as it has been copied in the handlers
  TEE_FreeTransientObject(object_handle);

  return result;
}

TEE_Result ta_rsa_operation(uint32_t mode,
          void* buff_in,  uint32_t size_buff_in,
          void* buff_out, uint32_t* size_buff_out)
{

  TEE_Result ret = TEE_ERROR_BAD_PARAMETERS;
  if (mode == TA_RSA_ENCRYPT) {

    ret = TEE_AsymmetricEncrypt(rsa_encrypt_op_handle,
                                (TEE_Attribute*) NULL,
                                0,
                                buff_in,
                                size_buff_in,
                                buff_out,
                                size_buff_out);

  } else if (mode == TA_RSA_DECRYPT) {
    // size of input buffer is given in byte
    if(size_buff_in < (TA_RSA1024_KEY_SIZE_BIT/8)){
      return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = TEE_AsymmetricDecrypt(rsa_decrypt_op_handle,
                                (TEE_Attribute*) NULL,
                                0,
                                buff_in,
                                size_buff_in,
                                buff_out,
                                size_buff_out);
  }

  return ret;
}

TEE_Result ta_rsa_sign_digest(void* buff_in,  uint32_t size_buff_in,
            void* buff_out, uint32_t* size_buff_out)
{
  TEE_Result ret = TEE_SUCCESS;
  void* sha;
  uint32_t size_sha;

  sha = TEE_Malloc(TA_SHA_SIZE_OF_SHA1, 0);
  size_sha = TA_SHA_SIZE_OF_SHA1;

  ret = ta_sha_digest(buff_in,
                      size_buff_in,
                      sha,
                      &size_sha);
  if (ret != TEE_SUCCESS) {
    goto error;
  }

  ret = TEE_AsymmetricSignDigest(rsa_sign_op_handle,
                                 (TEE_Attribute*) NULL,
                                 0,
                                 sha,
                                 size_sha,
                                 buff_out,
                                 size_buff_out);
error:
  TEE_Free(sha);
  return ret;
}

TEE_Result ta_rsa_compare_digest(void* buff_in,  uint32_t size_buff_in,
         void* sha_in,   uint32_t size_sha_in)
{
  TEE_Result ret = TEE_SUCCESS;
  void* sha;
  uint32_t size_sha;

  sha = TEE_Malloc(TA_SHA_SIZE_OF_SHA1, 0);
  ret = ta_sha_digest(buff_in,
                      size_buff_in,
                      sha,
                      &size_sha);
  if (ret != TEE_SUCCESS) {
    goto error;
  }

  ret = TEE_AsymmetricVerifyDigest(rsa_verify_op_handle,
                                   (TEE_Attribute*) NULL,
                                   0,
                                   sha,
                                   size_sha,
                                   sha_in,
                                   size_sha_in);
error:
  TEE_Free(sha);
  return ret;
}
