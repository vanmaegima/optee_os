// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2018, Linaro Limited */
/* Copyright (c) 2019, Foundries.IO */

#include <ta_fiovb.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <string.h>
#include <util.h>

#define DEFAULT_LOCK_STATE	0

static const uint32_t storageid = TEE_STORAGE_PRIVATE_RPMB;
static const char *named_value_prefix = "named_value_";

static TEE_Result get_named_object_name(char *name_orig,
					uint32_t name_orig_size,
					char *name, uint32_t *name_size)
{
	size_t pref_len = strlen(named_value_prefix);

	if (name_orig_size + pref_len >
	    TEE_OBJECT_ID_MAX_LEN)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Start with prefix */
	TEE_MemMove(name, named_value_prefix, pref_len);

	/* Concatenate provided object name */
	TEE_MemMove(name + pref_len, name_orig, name_orig_size);

	*name_size = name_orig_size + pref_len;

	return TEE_SUCCESS;
}

static TEE_Result check_valid_value(char *val)
{
	const char *valid_values[] = PERSIST_VALUE_LIST;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(valid_values); i++) {
		if (strcmp(val, valid_values[i]) == 0)
			return TEE_SUCCESS;
	}

	return TEE_ERROR_ITEM_NOT_FOUND;
}

static TEE_Result write_persist_value(uint32_t pt,
				      TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	const uint32_t flags = TEE_DATA_FLAG_ACCESS_READ |
			       TEE_DATA_FLAG_ACCESS_WRITE |
			       TEE_DATA_FLAG_OVERWRITE;
	TEE_Result res;
	TEE_ObjectHandle h;

	char name_full[TEE_OBJECT_ID_MAX_LEN];
	uint32_t name_full_sz;

	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	char *name_buf = params[0].memref.buffer;
	uint32_t name_buf_sz = params[0].memref.size;

	if (check_valid_value(name_buf) != TEE_SUCCESS) {
		EMSG("Not found %s", name_buf);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	char *value = params[1].memref.buffer;
	uint32_t value_sz = params[1].memref.size;

	res = get_named_object_name(name_buf, name_buf_sz,
				    name_full, &name_full_sz);
	if (res)
		return res;

	res = TEE_CreatePersistentObject(storageid, name_full,
					 name_full_sz,
					 flags, NULL, value,
					 value_sz, &h);
	if (res)
		EMSG("Can't create named object value, res = 0x%x", res);

	TEE_CloseObject(h);

	return res;
}

static TEE_Result read_persist_value(uint32_t pt,
				      TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	uint32_t flags = TEE_DATA_FLAG_ACCESS_READ |
			 TEE_DATA_FLAG_ACCESS_WRITE;
	TEE_Result res;
	TEE_ObjectHandle h;

	char name_full[TEE_OBJECT_ID_MAX_LEN];
	uint32_t name_full_sz;
	uint32_t count;

	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	char *name_buf = params[0].memref.buffer;

	if (check_valid_value(name_buf) != TEE_SUCCESS) {
		EMSG("Not found %s", name_buf);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	uint32_t name_buf_sz = params[0].memref.size;

	char *value = params[1].memref.buffer;
	uint32_t value_sz = params[1].memref.size;

	res = get_named_object_name(name_buf, name_buf_sz,
				    name_full, &name_full_sz);
	if (res)
		return res;

	res = TEE_OpenPersistentObject(storageid, name_full,
				       name_full_sz, flags, &h);
	if (res) {
		EMSG("Can't open named object value, res = 0x%x", res);
		return res;
	}

	res =  TEE_ReadObjectData(h, value, value_sz, &count);
	if (res) {
		EMSG("Can't read named object value, res = 0x%x", res);
		goto out;
	}

	params[1].memref.size = count;
out:
	TEE_CloseObject(h);

	return res;
}

TEE_Result TA_CreateEntryPoint(void)
{
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t pt __unused,
				    TEE_Param params[4] __unused,
				    void **session __unused)
{
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess __unused)
{
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess __unused, uint32_t cmd,
				      uint32_t pt,
				      TEE_Param params[TEE_NUM_PARAMS])
{
	switch (cmd) {
	case TA_FIOVB_CMD_READ_PERSIST_VALUE:
		return read_persist_value(pt, params);
	case TA_FIOVB_CMD_WRITE_PERSIST_VALUE:
		return write_persist_value(pt, params);
	default:
		EMSG("Command ID 0x%x is not supported", cmd);
		return TEE_ERROR_NOT_SUPPORTED;
	}
}
