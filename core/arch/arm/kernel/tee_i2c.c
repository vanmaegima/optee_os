// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2020 Foundries Ltd <jorge@foundries.io>
 *
 * Brief   Access to linux i2c bus
 *
 */
#include <kernel/tee_i2c.h>
#include <kernel/thread.h>
#include <mm/mobj.h>
#include <optee_rpc_cmd.h>
#include <string.h>

static struct mobj *mobj;

#define I2C_BUFFER_LENGTH 512

TEE_Result tee_i2c_transfer(struct TEE_I2CRequest *req, size_t *bytes)
{
	TEE_Result res = TEE_SUCCESS;

	if (!req || req->bufferLen > I2C_BUFFER_LENGTH) {
		EMSG("increase buffer size (%d)", (uint32_t)req->bufferLen);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (!mobj) {
		mobj = thread_rpc_alloc_kernel_payload(I2C_BUFFER_LENGTH);
		if (!mobj) {
			EMSG("increase linux CONFIG_OPTEE_SHM_NUM_PRIV_PAGES");
			return TEE_ERROR_OUT_OF_MEMORY;
		}

		assert(mobj_get_va(mobj, 0));
	}

	if (req->mode == TEE_MODE_WRITE)
		memcpy(mobj_get_va(mobj, 0), req->buffer, req->bufferLen);

	struct thread_param p[] = {
		[0] = THREAD_PARAM_VALUE(IN, req->mode, req->bus, req->chip),
		[1] = THREAD_PARAM_MEMREF(INOUT, mobj, 0, req->bufferLen),
		[2] = THREAD_PARAM_VALUE(OUT, 0, 0, 0),
	};

	res = thread_rpc_cmd(OPTEE_MSG_RPC_CMD_I2C_TRANSFER, ARRAY_SIZE(p), p);
	if (res != TEE_SUCCESS)
		return res;

	*bytes = (size_t)p[2].u.value.a;

	if (req->mode == TEE_MODE_READ)
		memcpy(req->buffer, mobj_get_va(mobj, 0), *bytes);

	return res;
}
