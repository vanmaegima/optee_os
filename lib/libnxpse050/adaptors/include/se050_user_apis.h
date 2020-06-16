/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (C) Foundries Ltd. 2020 - All Rights Reserved
 * Author: Jorge Ramirez <jorge@foundries.io>
 */

#ifndef SE050_USER_APIS_H_
#define SE050_USER_APIS_H_

#include <fsl_sss_se05x_apis.h>
#include <fsl_sss_se05x_types.h>
#include <nxScp03_Types.h>
#include <se050_sss_apis.h>

sss_status_t se050_configure_host(sss_session_t *host_session,
				  sss_key_store_t *host_ks,
				  SE_Connect_Ctx_t *open_ctx,
				  struct se050_auth_ctx *auth_ctx,
				  SE_AuthType_t auth_type);

#endif /* SE050_USER_APIS_H_ */
