//
// Copyright (c) 2018, ARM Limited.
//
// SPDX-License-Identifier: Apache-2.0
//

// This file is called by the makefile TA_DEV_KIT_DIR/mk/ta_dev_kit.mk
// It is expected to be in the same directory of the makefile
// The name and path to this file cannot be changed

#ifndef USER_TA_HEADER_DEFINES_H_
#define USER_TA_HEADER_DEFINES_H_

#include "ta_security_api/ta_public.h"

#define STR_TRACE_USER_TA "Trusted Application"

// The following flags are used to update the ta_head structure in
// <Optee OS Path>/<Platform>/export-ta_arm64/src/user_ta_header.c
#define TA_UUID TA_TRUSTED_UUID
#define TA_FLAGS                    (TA_FLAG_MULTI_SESSION | TA_FLAG_EXEC_DDR)
#define TA_STACK_SIZE               ( 2 * 1024)
#define TA_DATA_SIZE                (32 * 1024)

#define TA_CURRENT_TA_EXT_PROPERTIES \
  {TA_PROP_STR_DESCRIPTION, USER_TA_PROP_TYPE_STRING, STR_TRACE_USER_TA}, \
  {TA_PROP_STR_VERSION, USER_TA_PROP_TYPE_U32, &(const uint32_t) {0x0001}}

#endif  // USER_TA_HEADER_DEFINES_H_
