/*
* Copyright (c) 2018, ARM Limited.
*
* SPDX-License-Identifier: Apache-2.0
*/

#ifndef __TA_UTILS_H
#define __TA_UTILS_H

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <stdint.h>

TEE_Result ta_utils_create_handle(TEE_ObjectHandle object_handle,
          uint32_t algorithm, uint32_t mode,
          TEE_OperationHandle* op_handle);
#endif
