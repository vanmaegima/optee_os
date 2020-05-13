/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#ifndef TEE_I2C_H
#define TEE_I2C_H

#include "tee_api_types.h"

TEE_Result tee_i2c_transfer(struct TEE_I2CRequest *p, size_t *bytes);

#endif
