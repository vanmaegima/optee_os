/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (C) Foundries Ltd. 2020 - All Rights Reserved
 * Author: Jorge Ramirez <jorge@foundries.io>
 */

#ifndef SE050_UTILS_H_
#define SE050_UTILS_H_

#include <se050.h>

/* watermark keys to support SKS search */
#define SE050_KEY_WATERMARK		0xDEADBEEF

#define WATERMARKED(x)			\
((uint64_t)(((uint64_t)SE050_KEY_WATERMARK) << 32) + (x))

sss_status_t se050_get_oid(sss_key_object_mode_t type, uint32_t *val);

struct rsa_keypair;
struct ecc_keypair;

uint32_t se050_rsa_keypair_from_nvm(struct rsa_keypair *key);
uint32_t se050_ecc_keypair_from_nvm(struct ecc_keypair *key);
uint64_t se050_generate_private_key(uint32_t oid);

void se050_signature_der2bin(uint8_t *p, size_t *p_len);
void se050_refcount_init_ctx(uint8_t **cnt);
int se050_refcount_final_ctx(uint8_t *cnt);

void se050_display_board_info(sss_se05x_session_t *session);

#endif /* SE050_UTILS_H_ */
