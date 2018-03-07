/*
 * Copyright (c) 2018, ARM Limited.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "ta_sha.h"

static TEE_OperationHandle sha1_op_handle;

TEE_Result
ta_sha_digest(void *buff_in,
              uint32_t buff_size,
              void *sha_out,
              uint32_t *sha_size)
{
  TEE_Result result = TEE_SUCCESS;

  result = TEE_DigestDoFinal(sha1_op_handle,
                             buff_in,
                             buff_size,
                             sha_out,
                             sha_size);
  return result;
}

TEE_Result
ta_initialize_digest(void)
{
  TEE_Result result;

  // Allocate the operation handle for hashing
  result = TEE_AllocateOperation(&sha1_op_handle,
                                 TEE_ALG_SHA1,
                                 TEE_MODE_DIGEST,
                                 0);
  if (TEE_SUCCESS != result) {
    return result;
  }

  /* Add more digests handle allocation here
     ...
   */
  return result;
}
