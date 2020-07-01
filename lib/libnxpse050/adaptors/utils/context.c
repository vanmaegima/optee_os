// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) Foundries Ltd. 2020 - All Rights Reserved
 * Author: Jorge Ramirez <jorge@foundries.io>
 */

#include <initcall.h>
#include <kernel/panic.h>
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
	if (status != kStatus_SSS_Success)
		return TEE_ERROR_GENERIC;

#if defined(CFG_CORE_SE05X_INIT_NVM) && CFG_CORE_SE05X_INIT_NVM
	IMSG("========================");
	IMSG(" WARNING: FACTORY RESET");
	IMSG("========================");
	status = se050_factory_reset(ctx);
	if (kStatus_SSS_Success != status)
		return TEE_ERROR_GENERIC;
#endif
	if (ctx->session.subsystem == kType_SSS_SubSystem_NONE)
		return TEE_ERROR_GENERIC;

	status = se050_key_store_and_object_init(ctx);
	if (status != kStatus_SSS_Success)
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
	sss_status_t status = kStatus_SSS_Success;
	TEE_Result ret = TEE_SUCCESS;
	bool enable_scp03 = false;
	bool provision = false;
	bool reinit = false;

#if defined(CFG_CORE_SE05X_SCP03_PROVISION)
	provision = !!CFG_CORE_SE05X_SCP03_PROVISION;
#endif
#if defined(CFG_CORE_SE05X_DISPLAY_INFO)
	reinit = !!CFG_CORE_SE05X_DISPLAY_INFO;
#endif
	if (provision || !reinit)
		enable_scp03 = true;

re_initialize:
	ret = core_service_init(&se050_ctx, &se050_session, &se050_kstore,
				enable_scp03);
	if (ret != TEE_SUCCESS)
		panic();

	/* after provisioning the new keys, reboot the system and provide
	 * a build with the new ones (until these can be read from some secured
	 * storage - TODO)
	 */
	if (provision) {
		IMSG("provisioning scp03 keys");
		status = se050_rotate_scp03_keys(&se050_ctx);
		if (status != kStatus_SSS_Success)
			panic();

		sss_se05x_session_close(se050_session);

		IMSG("now rebuild the image with the new keys and boot it");
		IMSG("=======================");
		IMSG("PLEASE REBOOT THE BOARD");
		IMSG("waiting..");
		IMSG("======================");
		/* do not allow further usage of the SE050 without a reboot */
		while (true)
			;
	}

	if (!enable_scp03) {
		se050_display_board_info(se050_session);
		sss_se05x_session_close(se050_session);
		/* enforce scp03 */
		enable_scp03 = true;
		goto re_initialize;
	}

	IMSG("se050 [ready]");

	return TEE_SUCCESS;
}

service_init(se050_service_init);
