/*
* Copyright (c) 2018, ARM Limited.
*
* SPDX-License-Identifier: Apache-2.0
*/

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "ta_utils.h"

TEE_Result ta_utils_create_handle(TEE_ObjectHandle object_handle,
          uint32_t algorithm, uint32_t mode,
          TEE_OperationHandle* op_handle){
  TEE_Result result;
  TEE_ObjectInfo keyInfo;

  TEE_GetObjectInfo(object_handle, &keyInfo);
  result = TEE_AllocateOperation(op_handle,
               algorithm,
               mode,
               keyInfo.maxObjectSize);
  if(result != TEE_SUCCESS){
    return result;
  }

  result = TEE_SetOperationKey(*op_handle, object_handle);
  return result;
}
