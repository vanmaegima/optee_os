// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) Foundries Ltd. 2020 - All Rights Reserved
 * Author: Jorge Ramirez <jorge@foundries.io>
 */

#include <initcall.h>
#include <se050.h>

sss_se05x_key_store_t		*se050_kstore;
sss_se05x_session_t		*se050_session;
static sss_se05x_ctx_t		se050_ctx;

static TEE_Result core_service_init(sss_se05x_ctx_t *ctx,
				    sss_se05x_session_t **session,
				    sss_se05x_key_store_t **kstore,
				    bool encryption)
{
	sss_status_t status = kStatus_SSS_Success;

	status = se050_session_open(ctx, encryption);
	if (kStatus_SSS_Success != status)
		return TEE_ERROR_GENERIC;

#if CFG_CORE_SE05X_INIT_NVM
	IMSG("========================");
	IMSG(" WARNING: FACTORY RESET");
	IMSG("========================");
	status = se050_factory_reset(ctx);
	if (kStatus_SSS_Success != status)
		return TEE_ERROR_GENERIC;
#endif
	if (ctx->session.subsystem == kType_SSS_SubSystem_NONE)
		return TEE_ERROR_GENERIC;

	status = se050_kestore_and_object_init(ctx);
	if (kStatus_SSS_Success != status)
		return TEE_ERROR_GENERIC;

	IMSG("se050 [scp03 %s]", encryption ? "ON" : "OFF");
	*session = (sss_se05x_session_t *)((void *)&ctx->session);
	*kstore = (sss_se05x_key_store_t *)((void *)&ctx->ks);

	return TEE_SUCCESS;
}

/*
 *  The display information shows the OFEID we need to setup encryption.
 *  Therefore it should be done over an unencrypted/unsecure channel
 */
static TEE_Result se050_service_init(void)
{
	bool reinit = !!CFG_CORE_SE05X_DISPLAY_INFO;
	TEE_Result ret = TEE_SUCCESS;

re_initialize:
	ret = core_service_init(&se050_ctx, &se050_session, &se050_kstore,
				!reinit);
	if (ret != TEE_SUCCESS)
		return ret;

	if (reinit) {
		se050_display_board_info(se050_session);
		sss_se05x_session_close(se050_session);
		reinit = 0;
		goto re_initialize;
	}

	IMSG("se050 [ready]");

	return TEE_SUCCESS;
}

service_init(se050_service_init);
