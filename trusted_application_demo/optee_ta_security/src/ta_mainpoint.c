/*
* Copyright (c) 2018, ARM Limited.
*
* SPDX-License-Identifier: Apache-2.0
*/

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "ta_public.h"
#include "user_ta_header_defines.h"

#include "ta_rsa.h"
#include "ta_aes.h"
#include "ta_sha.h"

/*
 * Called when the instance of the TA is created. This is the first call in
 * the TA.
 */
TEE_Result TA_CreateEntryPoint(void)
{
  return TEE_SUCCESS;
}

/*
 * Called when the instance of the TA is destroyed if the TA has not
 * crashed or panicked. Last call in the TA.
 */
void TA_DestroyEntryPoint(void)
{

}

/*
 * Called when a new session is opened to the TA.
 */
TEE_Result TA_OpenSessionEntryPoint(uint32_t paramTypes, TEE_Param params[4],
                                    void** sessionContext)
{

  TEE_Result result;
  uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
                                             TEE_PARAM_TYPE_NONE,
                                             TEE_PARAM_TYPE_NONE,
                                             TEE_PARAM_TYPE_NONE);
  if (paramTypes != exp_param_types)
    return TEE_ERROR_BAD_PARAMETERS;

  result = ta_initialize_digest();
  if(result != TEE_SUCCESS){
    return result;
  }

  result = ta_rsa_prepare_key();
  if(result != TEE_SUCCESS){
    return result;
  }

  (void) params;
  (void) sessionContext;

  /* Need to return Success or the session won't be created. */
  return result;
}

/*
 * Called when a session is closed
 */
void TA_CloseSessionEntryPoint(void *sessionContext)
{
  (void) sessionContext;
}

/*
 * Parse the input parameters to call a subfunction.
 * The message buffer and size are contained in the memory reference 0
 * This function will output the digest and its size to memory reference 1
 */
static TEE_Result ta_mainpoint_hmac_digest(uint32_t paramTypes,
                                           TEE_Param params[4])
{
  TEE_Result result = TEE_SUCCESS;
  void* message;
  void* hmac_digest;
  uint32_t size_message;
  uint32_t* size_hmac_digest;
  uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                             TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                             TEE_PARAM_TYPE_NONE,
                                             TEE_PARAM_TYPE_NONE);
  if (paramTypes != exp_param_types)
    return TEE_ERROR_BAD_PARAMETERS;

  message = (void*) params[0].memref.buffer;
  size_message = params[0].memref.size;

  hmac_digest = (void*) params[1].memref.buffer;
  size_hmac_digest = &(params[1].memref.size);

  result = ta_aes_hmac_digest(0, message, size_message,
               hmac_digest, size_hmac_digest);
  return result;
}

/*
 * Parse the input parameter to extract the buffer locations and calls a
 * subfunction.
 * The message input is digested and the resulting byte array is compared to
 * the input hmac digest.
 */
static TEE_Result ta_mainpoint_hmac_compare(uint32_t paramTypes,
                                            TEE_Param params[4])
{
  TEE_Result result = TEE_SUCCESS;
  void* message;
  void* hmac_digest;
  uint32_t size_message;
  uint32_t size_hmac_digest;
  uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                             TEE_PARAM_TYPE_MEMREF_INPUT,
                                             TEE_PARAM_TYPE_NONE,
                                             TEE_PARAM_TYPE_NONE);
  if (paramTypes != exp_param_types)
    return TEE_ERROR_BAD_PARAMETERS;

  message = (void*) params[0].memref.buffer;
  size_message = params[0].memref.size;

  hmac_digest = (void*) params[1].memref.buffer;
  size_hmac_digest = params[1].memref.size;

  result = ta_aes_hmac_compare(0, message, size_message,
                hmac_digest, size_hmac_digest);
  return result;
}

/*
 * Parse the incomming parameters and calls the subfunction for RSA encryption
 * or decryption depending on the mode specified.
 * For encryption, the output buffer must be 1024/8 = 128 bytes or bigger for
 * RSA1024 encryption
 * For decryption, the size of the output buffer is changed to the actual size
 * of the plain text message.
 */
static TEE_Result ta_mainpoint_rsa_operation(uint32_t param_types,
               TEE_Param params[4])
{
  TEE_Result result = TEE_SUCCESS;
  uint32_t mode;
  void* buff_in;
  void* buff_out;
  uint32_t size_buff_in;
  uint32_t* size_buff_out;

  uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
                                             TEE_PARAM_TYPE_MEMREF_INPUT,
                                             TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                             TEE_PARAM_TYPE_NONE);
  if (param_types != exp_param_types)
    return TEE_ERROR_BAD_PARAMETERS;

  mode = params[0].value.a;

  buff_in = (void*) params[1].memref.buffer;
  size_buff_in = params[1].memref.size;

  buff_out = (void*) params[2].memref.buffer;
  size_buff_out = &(params[2].memref.size);

  result = ta_rsa_operation(mode, buff_in,  size_buff_in,
            buff_out, size_buff_out);
  return result;
}

/*
 * Parse the arguments and call a subfunction to generate a random array
 * of byte corresponding to the secret for AES encryption/decryption
 * The output buffer must have a size of at least 1024/8 = 128 bytes
 * as the result is RSA1024 encrypted.
 */
static
TEE_Result ta_mainpoint_generate_and_encrypt_secret(uint32_t param_types,
                TEE_Param params[4])
{
  TEE_Result result;
  void* encrypted_aes_secret;
  uint32_t* size_encrypted_aes_secret;
  uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
                                             TEE_PARAM_TYPE_NONE,
                                             TEE_PARAM_TYPE_NONE,
                                             TEE_PARAM_TYPE_NONE);
  if (param_types != exp_param_types)
    return TEE_ERROR_BAD_PARAMETERS;

  encrypted_aes_secret = (void*) params[0].memref.buffer;
  size_encrypted_aes_secret = &(params[0].memref.size);

  result = ta_aes_generate_and_encrypt_key(0, TA_AES128_SIZE,
             encrypted_aes_secret,
             size_encrypted_aes_secret);
  return result;
}

/*
 * Parse the incomming parameters and call a subfunction to extract the secret.
 * The input buffer is RSA encrypted and should hold the secret key for AES.
 */
static
TEE_Result ta_mainpoint_decrypt_and_store_secret(uint32_t param_types,
             TEE_Param params[4])
{
  TEE_Result result = TEE_SUCCESS;
  void* encrypted_aes_secret;
  uint32_t size_encrypted_aes_secret;

  uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                             TEE_PARAM_TYPE_NONE,
                                             TEE_PARAM_TYPE_NONE,
                                             TEE_PARAM_TYPE_NONE);
  if (param_types != exp_param_types)
    return TEE_ERROR_BAD_PARAMETERS;

  encrypted_aes_secret = (void*) params[0].memref.buffer;
  size_encrypted_aes_secret = params[0].memref.size;

  result = ta_aes_decrypt_and_allocate_key(0, TA_AES128_SIZE,
             encrypted_aes_secret,
             size_encrypted_aes_secret);
  return result;
}

static TEE_Result ta_mainpoint_rsa_sign_digest(uint32_t param_types,
                                               TEE_Param params[4])
{
  TEE_Result result = TEE_SUCCESS;
  void* message;
  void* rsa_digest;
  uint32_t size_message;
  uint32_t size_rsa_digest;
  uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
                                             TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                             TEE_PARAM_TYPE_NONE,
                                             TEE_PARAM_TYPE_NONE);
  if (param_types != exp_param_types)
    return TEE_ERROR_BAD_PARAMETERS;

  message = (void*) params[0].memref.buffer;
  size_message = params[0].memref.size;

  rsa_digest = (void*) params[1].memref.buffer;
  size_rsa_digest = params[1].memref.size;

  result = ta_rsa_sign_digest(message,  size_message,
            rsa_digest, &size_rsa_digest);
  return result;
}

static TEE_Result ta_mainpoint_rsa_compare_digest(uint32_t param_types,
                                                  TEE_Param params[4])
{
  TEE_Result result = TEE_SUCCESS;
  void* buff_in;
  void* buff_sha_in;
  uint32_t size_buff_in;
  uint32_t size_buff_sha_in;

  uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                             TEE_PARAM_TYPE_MEMREF_INPUT,
                                             TEE_PARAM_TYPE_NONE,
                                             TEE_PARAM_TYPE_NONE);
  if (param_types != exp_param_types)
    return TEE_ERROR_BAD_PARAMETERS;

  buff_in = (void*) params[0].memref.buffer;
  size_buff_in = params[0].memref.size;

  buff_sha_in = (void*) params[1].memref.buffer;
  size_buff_sha_in = params[1].memref.size;

  result = ta_rsa_compare_digest(buff_in, size_buff_in,
               buff_sha_in, size_buff_sha_in);
  return result;
}

static TEE_Result ta_mainpoint_aes_decrypt(uint32_t param_types,
             TEE_Param params[4])
{
  TEE_Result result = TEE_SUCCESS;
  void* buff_in;
  void* buff_out;
  void* iv;
  uint32_t iv_size_byte;
  uint32_t size_buff_in;
  uint32_t* size_buff_out;
  uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                             TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                             TEE_PARAM_TYPE_MEMREF_INPUT,
                                             TEE_PARAM_TYPE_NONE);
  if (param_types != exp_param_types)
    return TEE_ERROR_BAD_PARAMETERS;

  buff_in = (void*) params[0].memref.buffer;
  size_buff_in = params[0].memref.size;

  buff_out = (void*) params[1].memref.buffer;
  size_buff_out = &(params[1].memref.size);

  iv = (void*) params[2].memref.buffer;
  iv_size_byte =  params[2].memref.size;

  result = ta_aes_decrypt(0, buff_in, size_buff_in,
           buff_out, size_buff_out,
           iv, iv_size_byte);

  return result;
}

static TEE_Result ta_mainpoint_aes_encrypt(uint32_t param_types,
                                           TEE_Param params[4])
{
  TEE_Result result = TEE_SUCCESS;
  void* plain_message;
  void* cipher_message;
  void* iv;
  uint32_t size_plain_message;
  uint32_t size_cipher_message;
  uint32_t size_iv;
  uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                             TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                             TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                             TEE_PARAM_TYPE_NONE);
  if (param_types != exp_param_types)
    return TEE_ERROR_BAD_PARAMETERS;

  plain_message = (void*) params[0].memref.buffer;
  size_plain_message = params[0].memref.size;

  cipher_message = (void*) params[1].memref.buffer;
  size_cipher_message = params[1].memref.size;

  iv = (void*) params[2].memref.buffer;
  size_iv = params[2].memref.size;

  result = ta_aes_encrypt(0, plain_message, size_plain_message,
           cipher_message, &size_cipher_message,
           iv, &size_iv);
  return result;
}

/*
 * Called when a TA is invoked. sess_ctx hold that value that was
 * assigned by TA_OpenSessionEntryPoint(). The rest of the paramters
 * comes from normal world.
 */
TEE_Result TA_InvokeCommandEntryPoint(void* sessionContext, uint32_t commandID,
                                      uint32_t paramTypes, TEE_Param params[4])
{
  switch (commandID) {
  case TA_COMMAND_DECRYPT_AND_STORE_SECRET:
    return ta_mainpoint_decrypt_and_store_secret(paramTypes, params);
  case TA_COMMAND_GENERATE_AND_ENCRYPT_SECRET:
    return ta_mainpoint_generate_and_encrypt_secret(paramTypes, params);
  case TA_COMMAND_RSA_OPERATION:
    return ta_mainpoint_rsa_operation(paramTypes, params);
  case TA_COMMAND_HMAC_COMPARE_DIGESTS:
    return ta_mainpoint_hmac_compare(paramTypes, params);
  case TA_COMMAND_HMAC_COMPUTE_DIGEST:
    return ta_mainpoint_hmac_digest(paramTypes, params);
  case TA_COMMAND_RSA_COMPARE_DIGESTS:
    return ta_mainpoint_rsa_compare_digest(paramTypes, params);
  case TA_COMMAND_RSA_COMPUTE_DIGEST:
    return ta_mainpoint_rsa_sign_digest(paramTypes, params);
  case TA_COMMAND_AES_ENCRYPT:
    return ta_mainpoint_aes_encrypt(paramTypes, params);
  case TA_COMMAND_AES_DECRYPT:
    return ta_mainpoint_aes_decrypt(paramTypes, params);
  default:
    return TEE_ERROR_NOT_SUPPORTED;
  }

  (void) sessionContext;
}
