// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) Foundries Ltd. 2020 - All Rights Reserved
 * Author: Jorge Ramirez <jorge@foundries.io>
 *
 * This sequence follows the Global Platform Specification 2.2 - Ammendment D
 * for Secure Channel Porotocol 03
 *
 */

#include <se050.h>
#include <se050_utils.h>
#include <scp.h>
#include <stdint.h>
#include <string.h>

static sss_status_t encrypt_key_and_get_kcv(uint8_t *enc, uint8_t *kc,
					    uint8_t *key, sss_se05x_ctx_t *ctx,
					    uint32_t id)
{
	uint8_t ones[AES_KEY_LEN_nBYTE] = { [0 ... AES_KEY_LEN_nBYTE - 1] = 1 };
	uint8_t enc_len = AES_KEY_LEN_nBYTE;
	uint8_t kc_len = AES_KEY_LEN_nBYTE;
	sss_status_t st = kStatus_SSS_Fail;
	sss_object_t *dek_object = NULL;
	sss_se05x_symmetric_t symm = { 0 };
	sss_se05x_object_t ko = { 0 };
	uint8_t dek[AES_KEY_LEN_nBYTE] = { 0 };
	size_t dek_len = sizeof(dek);
	size_t dek_bit_len = dek_len * 8;

	st = sss_se05x_key_object_init(&ko, &ctx->ks);
	if (st != kStatus_SSS_Success)
		return kStatus_SSS_Fail;

	st = sss_se05x_key_object_allocate_handle(&ko, id,
						  kSSS_KeyPart_Default,
						  kSSS_CipherType_AES,
						  AES_KEY_LEN_nBYTE,
						  kKeyObject_Mode_Transient);
	if (st != kStatus_SSS_Success)
		return kStatus_SSS_Fail;

	st = sss_se05x_key_store_set_key(&ctx->ks, &ko, key, AES_KEY_LEN_nBYTE,
					 AES_KEY_LEN_nBYTE * 8, NULL, 0);
	if (st != kStatus_SSS_Success)
		return kStatus_SSS_Fail;

	st = sss_se05x_symmetric_context_init(&symm, &ctx->session, &ko,
					      kAlgorithm_SSS_AES_ECB,
					      kMode_SSS_Encrypt);
	if (st != kStatus_SSS_Success)
		return kStatus_SSS_Fail;

	st = sss_se05x_cipher_one_go(&symm, NULL, 0, ones, kc, kc_len);
	if (st != kStatus_SSS_Success)
		return kStatus_SSS_Fail;

	/* Encyrpt the sensitive data with the scp03 dek */
	dek_object = &ctx->open_ctx.auth.ctx.scp03.pStatic_ctx->Dek;
	st = se050_host_key_store_get_key(&ctx->host_ks, dek_object,
					  dek, &dek_len, &dek_bit_len);
	if (st != kStatus_SSS_Success)
		return kStatus_SSS_Fail;

	st = sss_se05x_key_store_set_key(&ctx->ks, &ko, dek, AES_KEY_LEN_nBYTE,
					 AES_KEY_LEN_nBYTE * 8, NULL, 0);
	if (st != kStatus_SSS_Success)
		return kStatus_SSS_Fail;

	st = sss_se05x_cipher_one_go(&symm, NULL, 0, key, enc, enc_len);
	if (st != kStatus_SSS_Success)
		return kStatus_SSS_Fail;

	if (symm.keyObject)
		sss_se05x_symmetric_context_free(&symm);

	sss_se05x_key_object_free(&ko);

	return kStatus_SSS_Success;
}

static sss_status_t prepare_key_data(uint8_t *key, uint8_t *cmd,
				     sss_se05x_ctx_t *ctx, uint32_t id)
{
	uint8_t kc[AES_KEY_LEN_nBYTE] = { 0 };
	sss_status_t status = kStatus_SSS_Fail;

	/* GP key type AES */
	cmd[0] = PUT_KEYS_KEY_TYPE_CODING_AES;
	/* Length of the 'AES key data' */
	cmd[1] = AES_KEY_LEN_nBYTE + 1;
	/* Length of 'AES key' */
	cmd[2] = AES_KEY_LEN_nBYTE;
	/* Length of key check  */
	cmd[3 + AES_KEY_LEN_nBYTE] = CRYPTO_KEY_CHECK_LEN;

	status = encrypt_key_and_get_kcv(&cmd[3], kc, key, ctx, id);
	if (status != kStatus_SSS_Success)
		return status;

	memcpy(&cmd[3 + AES_KEY_LEN_nBYTE + 1], kc, CRYPTO_KEY_CHECK_LEN);

	return kStatus_SSS_Success;
}

sss_status_t se050_prepare_rotate_cmd(sss_se05x_ctx_t *ctx,
				      struct s050_scp_rotate_cmd *cmd,
				      struct se050_scp_key *keys)

{
	sss_se05x_session_t *session = &ctx->session;
	sss_status_t status = kStatus_SSS_Fail;
	smStatus_t st = SM_NOT_OK;
	size_t kcv_len = 0;
	size_t cmd_len = 0;
	uint8_t key_version = 0;
	/* order of elements in the array matters */
	uint8_t *key[] = { [0] = keys->enc,
			   [1] = keys->mac,
			   [2] = keys->dek,
	};
	uint32_t oid = 0;
	size_t i = 0;

	/* add version to replace in the header */
	key_version = ctx->open_ctx.auth.ctx.scp03.pStatic_ctx->keyVerNo;

	/* packet for SCP03 keys provision: key_version to replace */
	cmd->cmd[cmd_len] = key_version;
	cmd_len += 1;

	cmd->kcv[kcv_len] = key_version;
	kcv_len += 1;

	for (i = 0; i < ARRAY_SIZE(key); i++) {
		if (!key[i])
			goto error;

		status = se050_get_oid(kKeyObject_Mode_Transient, &oid);
		if (status != kStatus_SSS_Success)
			goto error;

		status = prepare_key_data(key[i], &cmd->cmd[cmd_len], ctx, oid);
		if (status != kStatus_SSS_Success)
			goto error;

		memcpy(&cmd->kcv[kcv_len],
		       &cmd->cmd[cmd_len + 3 + AES_KEY_LEN_nBYTE + 1],
		       CRYPTO_KEY_CHECK_LEN);

		cmd_len += (3 + AES_KEY_LEN_nBYTE + 1 + CRYPTO_KEY_CHECK_LEN);
		kcv_len += CRYPTO_KEY_CHECK_LEN;
	}

	cmd->cmd_len = cmd_len;
	cmd->kcv_len = kcv_len;

	return kStatus_SSS_Success;
error:
	EMSG("error preparing scp03 rotation command");

	return kStatus_SSS_Fail;
}
