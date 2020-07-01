// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) Foundries Ltd. 2020 - All Rights Reserved
 * Author: Jorge Ramirez <jorge@foundries.io>
 */

#include <crypto/crypto.h>
#include <se050.h>

/* base value for secure objects (transient and persistent) */
#define OID_MIN			((uint32_t)(0x00000001))
#define OID_MAX			((uint32_t)(OID_MIN + 0x7BFFFFFE))
#define NBR_OID			((uint32_t)(OID_MAX - OID_MIN))

#define IS_WATERMARKED(x)	(((x) & WATERMARKED(0)) == WATERMARKED(0))

static uint32_t generate_oid(void)
{
	uint32_t oid = OID_MIN;
	uint32_t random = 0;
	int i = 0;

	for (i = 0; i < NBR_OID; i++) {
		if (crypto_rng_read(&random, sizeof(random)) != TEE_SUCCESS)
			return 0;

		random &= OID_MAX;

		oid = OID_MIN + random;
		if (oid > OID_MAX)
			continue;

		if (!se050_key_exists(oid, &se050_session->s_ctx))
			return oid;
	}

	return 0;
}

/*
 *
 * @param mode
 * @param val
 *
 * @return sss_status_t
 */
sss_status_t se050_get_oid(sss_key_object_mode_t mode, uint32_t *val)
{
	SE05x_MemoryType_t type = kSE05x_MemoryType_PERSISTENT;
	sss_status_t status = kStatus_SSS_Success;
	uint16_t mem = 0;
	uint32_t oid = 0;

	if (!val)
		return kStatus_SSS_Fail;

	if (mode == kKeyObject_Mode_Transient)
		type = kSE05x_MemoryType_TRANSIENT_RESET;

	status = se050_get_free_memory(&se050_session->s_ctx, &mem, type);
	if (status != kStatus_SSS_Success) {
		mem = 0;
		EMSG("failure retrieving free memory");
		return kStatus_SSS_Fail;
	}

	oid = generate_oid();
	if (!oid) {
		EMSG("cant access rng");
		return kStatus_SSS_Fail;
	}

	if (type == kKeyObject_Mode_Persistent) {
		IMSG("allocated persistent object: 0x%x", oid);
		if (mem && mem < 100)
			IMSG("WARNING, low persistent memory");
	} else {
		if (mem && mem < 100)
			IMSG("WARNING, low transient memory");
	}

	*val = oid;

	return kStatus_SSS_Success;
}

static uint32_t se050_key(uint64_t key)
{
	uint32_t oid = (uint32_t)key;

	if (!IS_WATERMARKED(key))
		return 0;

	if (oid < OID_MIN || oid > OID_MAX)
		return 0;

	return oid;
}

uint32_t se050_rsa_keypair_from_nvm(struct rsa_keypair *key)
{
	uint64_t key_id = 0;

	if (!key)
		return 0;

	if (crypto_bignum_num_bytes(key->d) != sizeof(uint64_t))
		return 0;

	crypto_bignum_bn2bin(key->d, (uint8_t *)&key_id);

	return se050_key(key_id);
}

uint32_t se050_ecc_keypair_from_nvm(struct ecc_keypair *key)
{
	uint64_t key_id = 0;

	if (!key)
		return 0;

	if (crypto_bignum_num_bytes(key->d) != sizeof(uint64_t))
		return 0;

	crypto_bignum_bn2bin(key->d, (uint8_t *)&key_id);

	return se050_key(key_id);
}

uint64_t se050_generate_private_key(uint32_t oid)
{
	return WATERMARKED(oid);
}

/*
 * Parse a DER formated signature and extract the raw data
 * @param p
 * @param p_len
 */
void se050_signature_der2bin(uint8_t *p, size_t *p_len)
{
	uint8_t buffer[256] = { 0 };
	uint8_t *k, *output = p;
	size_t buffer_len = 0;
	size_t len = 0;

	if (!p || !p_len)
		return;

	p++;		/* tag: 0x30      */
	p++;		/* field: total len */
	p++;		/* tag: 0x02      */
	len = *p++;	/* field: r_len */

	if (*p == 0x00) { /* handle special case */
		len = len - 1;
		p++;
	}
	memcpy(buffer, p, len);

	p = p + len;
	p++;		/* tag: 0x2       */
	k = p;
	p++;		/* field: s_len     */

	if (*p == 0x00) { /* handle special case */
		*k = *k - 1;
		p++;
	}
	memcpy(buffer + len, p, *k);
	buffer_len = len + *k;

	memcpy(output, buffer, buffer_len);
	*p_len = buffer_len;
}

/*
 * @param cnt
 */
void se050_refcount_init_ctx(uint8_t **cnt)
{
	if (!*cnt) {
		*cnt = calloc(1, sizeof(uint8_t));
		if (*cnt)
			**cnt = 1;
	} else {
		**cnt = **cnt + 1;
	}
}

/*
 * @param cnt
 *
 * @return int
 */
int se050_refcount_final_ctx(uint8_t *cnt)
{
	if (!cnt)
		return 1;

	if (!*cnt) {
		free(cnt);
		return 1;
	}

	*cnt = *cnt - 1;

	return 0;
}
