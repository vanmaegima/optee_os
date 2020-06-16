// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) Foundries Ltd. 2020 - All Rights Reserved
 * Author: Jorge Ramirez <jorge@foundries.io>
 */

#include <assert.h>
#include <crypto/crypto.h>
#include <kernel/panic.h>
#include <se050.h>
#include <string.h>

static uint32_t algo_tee2se050(uint32_t algo)
{
	switch (algo) {
	case TEE_ALG_ECDSA_P192:
		return kAlgorithm_SSS_ECDSA_SHA1;
	case TEE_ALG_ECDSA_P224:
		return kAlgorithm_SSS_ECDSA_SHA224;
	case TEE_ALG_ECDSA_P256:
		return kAlgorithm_SSS_ECDSA_SHA256;
	case TEE_ALG_ECDSA_P384:
		return kAlgorithm_SSS_ECDSA_SHA384;
	case TEE_ALG_ECDSA_P521:
		return kAlgorithm_SSS_ECDSA_SHA512;
	default:
		EMSG("ecc curve 0x%x not enabled", algo);
		return kAlgorithm_None;
	}
}

static uint32_t cipher_tee2se050(uint32_t curve)
{
	switch (curve) {
	case TEE_ECC_CURVE_NIST_P192:
	case TEE_ECC_CURVE_NIST_P224:
	case TEE_ECC_CURVE_NIST_P256:
	case TEE_ECC_CURVE_NIST_P384:
	case TEE_ECC_CURVE_NIST_P521:
		return kSSS_CipherType_EC_NIST_P;
	default:
		EMSG("cipher 0x%x not enabled", curve);
		return kSSS_CipherType_NONE;
	}
}

static uint32_t curve_tee2se050(uint32_t curve)
{
	switch (curve) {
	case TEE_ECC_CURVE_NIST_P192:
		return kSE05x_ECCurve_NIST_P192;
	case TEE_ECC_CURVE_NIST_P224:
		return kSE05x_ECCurve_NIST_P224;
	case TEE_ECC_CURVE_NIST_P256:
		return kSE05x_ECCurve_NIST_P256;
	case TEE_ECC_CURVE_NIST_P384:
		return kSE05x_ECCurve_NIST_P384;
	case TEE_ECC_CURVE_NIST_P521:
		return kSE05x_ECCurve_NIST_P521;
	default:
		EMSG("curve 0x%x not enabled", curve);
		return kSE05x_ECCurve_NA;
	}
}

static uint32_t curve_se0502tee(uint32_t curve)
{
	switch (curve) {
	case kSE05x_ECCurve_NIST_P192:
		return TEE_ECC_CURVE_NIST_P192;
	case kSE05x_ECCurve_NIST_P224:
		return TEE_ECC_CURVE_NIST_P224;
	case kSE05x_ECCurve_NIST_P256:
		return TEE_ECC_CURVE_NIST_P256;
	case kSE05x_ECCurve_NIST_P384:
		return TEE_ECC_CURVE_NIST_P384;
	case kSE05x_ECCurve_NIST_P521:
		return TEE_ECC_CURVE_NIST_P521;
	default:
		EMSG("curve 0x%x not enabled", curve);
		panic();
	}
}

static TEE_Result ecc_get_key_size(uint32_t curve, uint32_t algo,
				   size_t *kB, size_t *kb)
{
	/*
	 * Note GPv1.1 indicates TEE_ALG_ECDH_NIST_P192_DERIVE_SHARED_SECRET
	 * but defines TEE_ALG_ECDH_P192
	 */
	switch (curve) {
	case TEE_ECC_CURVE_NIST_P192:
		*kb = 192;
		*kB = 24;
		if (algo && algo != TEE_ALG_ECDSA_P192 &&
		    algo != TEE_ALG_ECDH_P192)
			return TEE_ERROR_BAD_PARAMETERS;
		break;
	case TEE_ECC_CURVE_NIST_P224:
		*kb = 224;
		*kB = 28;
		if (algo && algo != TEE_ALG_ECDSA_P224 &&
		    algo != TEE_ALG_ECDH_P224)
			return TEE_ERROR_BAD_PARAMETERS;
		break;
	case TEE_ECC_CURVE_NIST_P256:
		*kb = 256;
		*kB = 32;
		if (algo && algo != TEE_ALG_ECDSA_P256 &&
		    algo != TEE_ALG_ECDH_P256)
			return TEE_ERROR_BAD_PARAMETERS;
		break;
	case TEE_ECC_CURVE_NIST_P384:
		*kb = 384;
		*kB = 48;
		if (algo && algo != TEE_ALG_ECDSA_P384 &&
		    algo != TEE_ALG_ECDH_P384)
			return TEE_ERROR_BAD_PARAMETERS;
		break;
	case TEE_ECC_CURVE_NIST_P521:
		*kb = 521;
		*kB = 66;
		if (algo && algo != TEE_ALG_ECDSA_P521 &&
		    algo != TEE_ALG_ECDH_P521)
			return TEE_ERROR_BAD_PARAMETERS;
		break;
	default:
		*kb = 0;
		*kB = 0;
		return TEE_ERROR_NOT_SUPPORTED;
	}

	return TEE_SUCCESS;
}

static TEE_Result set_binary_data(struct bignum *b, size_t key_len, uint8_t **p,
				  size_t *len)
{
	uint8_t leading_zeros = 0;
	uint8_t *q = NULL;
	size_t a = crypto_bignum_num_bytes(b);

	if (!a)
		return TEE_ERROR_GENERIC;

	if (a != key_len) {
		leading_zeros = key_len - a;
		a = key_len;
	}

	q = (uint8_t *)calloc(1, a);
	if (!q)
		return TEE_ERROR_OUT_OF_MEMORY;

	crypto_bignum_bn2bin(b, q + leading_zeros);

	*len = a;
	*p = q;

	return TEE_SUCCESS;
}

static TEE_Result se050_inject_public_key(sss_se05x_object_t *k_object,
					  struct ecc_public_key *key,
					  size_t key_len)
{
	struct ecc_public_key_bin key_bin = { 0 };
	sss_status_t st = kStatus_SSS_Fail;
	TEE_Result ret = TEE_ERROR_GENERIC;
	uint32_t oid = 0;

	st = sss_se05x_key_object_init(k_object, se050_kstore);
	if (st != kStatus_SSS_Success)
		return TEE_ERROR_BAD_PARAMETERS;

	st = se050_get_oid(kKeyObject_Mode_Transient, &oid);
	if (st != kStatus_SSS_Success)
		return TEE_ERROR_GENERIC;

	st = sss_se05x_key_object_allocate_handle(k_object, oid,
						  kSSS_KeyPart_Public,
						  cipher_tee2se050(key->curve),
						  0,
						  kKeyObject_Mode_Transient);
	if (st != kStatus_SSS_Success)
		return TEE_ERROR_BAD_PARAMETERS;

	ret = set_binary_data(key->x, key_len, &key_bin.x, &key_bin.x_len);
	if (ret != TEE_SUCCESS)
		return ret;

	ret = set_binary_data(key->y, key_len, &key_bin.y, &key_bin.y_len);
	if (ret != TEE_SUCCESS) {
		free(key_bin.x);
		return ret;
	}

	key_bin.curve = curve_tee2se050(key->curve);

	st = se050_key_store_set_ecc_key_bin(se050_kstore, k_object, NULL,
					     &key_bin);

	free(key_bin.x);
	free(key_bin.y);

	if (st != kStatus_SSS_Success)
		return TEE_ERROR_BAD_PARAMETERS;

	return TEE_SUCCESS;
}

static TEE_Result se050_inject_keypair(sss_se05x_object_t *k_object,
				       struct ecc_keypair *key,
				       size_t key_len)
{
	sss_status_t st = kStatus_SSS_Fail;
	struct ecc_keypair_bin key_bin = { 0 };
	uint32_t key_id = 0;
	TEE_Result ret = TEE_ERROR_GENERIC;
	uint32_t oid = 0;

	st = sss_se05x_key_object_init(k_object, se050_kstore);
	if (st != kStatus_SSS_Success)
		return TEE_ERROR_BAD_PARAMETERS;

	/* key generated by se050 */
	key_id = se050_ecc_keypair_from_nvm(key);
	if (key_id) {
		st = sss_se05x_key_object_get_handle(k_object, key_id);
		if (st != kStatus_SSS_Success)
			return TEE_ERROR_BAD_PARAMETERS;

		return TEE_SUCCESS;
	}

	st = se050_get_oid(kKeyObject_Mode_Transient, &oid);
	if (st != kStatus_SSS_Success)
		return TEE_ERROR_GENERIC;

	/* key generated by external tool */
	st = sss_se05x_key_object_allocate_handle(k_object, oid,
						  kSSS_KeyPart_Pair,
						  cipher_tee2se050(key->curve),
						  0,
						  kKeyObject_Mode_Transient);
	if (st != kStatus_SSS_Success)
		return TEE_ERROR_BAD_PARAMETERS;

	ret = set_binary_data(key->d, key_len, &key_bin.d, &key_bin.d_len);
	if (ret != TEE_SUCCESS)
		return ret;

	ret = set_binary_data(key->x, key_len, &key_bin.x, &key_bin.x_len);
	if (ret != TEE_SUCCESS) {
		free(key_bin.d);
		return ret;
	}

	ret = set_binary_data(key->y, key_len, &key_bin.y, &key_bin.y_len);
	if (ret != TEE_SUCCESS) {
		free(key_bin.d);
		free(key_bin.x);
		return ret;
	}

	key_bin.curve = curve_tee2se050(key->curve);

	st = se050_key_store_set_ecc_key_bin(se050_kstore, k_object, &key_bin,
					     NULL);

	free(key_bin.d);
	free(key_bin.x);
	free(key_bin.y);

	if (st != kStatus_SSS_Success)
		return TEE_ERROR_BAD_PARAMETERS;

	return TEE_SUCCESS;
}

TEE_Result crypto_acipher_ecc_sign(uint32_t algo, struct ecc_keypair *key,
				   const uint8_t *msg, size_t msg_len,
				   uint8_t *sig, size_t *sig_len)
{
	sss_status_t st = kStatus_SSS_Fail;
	sss_se05x_asymmetric_t ctx = { 0 };
	sss_se05x_object_t kobject = { 0 };
	TEE_Result res = TEE_SUCCESS;
	size_t key_bytes = 0;
	size_t key_bits = 0;

	res = ecc_get_key_size(key->curve, algo, &key_bytes, &key_bits);
	if (res != TEE_SUCCESS)
		goto exit;

	res = se050_inject_keypair(&kobject, key, key_bytes);
	if (res != TEE_SUCCESS)
		goto exit;

	st = sss_se05x_asymmetric_context_init(&ctx, se050_session, &kobject,
					       algo_tee2se050(algo),
					       kMode_SSS_Sign);
	if (st != kStatus_SSS_Success) {
		sss_se05x_key_store_erase_key(se050_kstore, &kobject);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	st = sss_se05x_asymmetric_sign_digest(&ctx, (uint8_t *)msg, msg_len,
					      sig, sig_len);
	if (st != kStatus_SSS_Success) {
		EMSG("curve: 0x%x", key->curve);
		res = TEE_ERROR_BAD_PARAMETERS;
		goto exit;
	}

	se050_signature_der2bin(sig, sig_len);
exit:
	if (!se050_ecc_keypair_from_nvm(key))
		sss_se05x_key_store_erase_key(se050_kstore, &kobject);

	sss_se05x_asymmetric_context_free(&ctx);

	return res;
}

TEE_Result crypto_acipher_ecc_verify(uint32_t algo, struct ecc_public_key *key,
				     const uint8_t *msg, size_t msg_len,
				     const uint8_t *sig, size_t sig_len)
{
	sss_status_t st = kStatus_SSS_Fail;
	sss_se05x_asymmetric_t ctx = { 0 };
	sss_se05x_object_t kobject = { 0 };
	TEE_Result res = TEE_SUCCESS;
	uint8_t signature[256];
	size_t signature_len = sizeof(signature);
	size_t key_bytes = 0;
	size_t key_bits = 0;

	res = ecc_get_key_size(key->curve, algo, &key_bytes, &key_bits);
	if (res != TEE_SUCCESS)
		goto exit;

	res = se050_inject_public_key(&kobject, key, key_bytes);
	if (res != TEE_SUCCESS)
		goto exit;

	st = sss_se05x_asymmetric_context_init(&ctx, se050_session, &kobject,
					       algo_tee2se050(algo),
					       kMode_SSS_Verify);
	if (st != kStatus_SSS_Success) {
		sss_se05x_key_store_erase_key(se050_kstore, &kobject);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	st = sss_util_asn1_ecdaa_get_signature(signature, &signature_len,
					       (uint8_t *)sig, sig_len);
	if (st != kStatus_SSS_Success) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto exit;
	}

	st = sss_se05x_asymmetric_verify_digest(&ctx, (uint8_t *)msg, msg_len,
						(uint8_t *)signature,
						signature_len);
	if (st != kStatus_SSS_Success)
		res = TEE_ERROR_SIGNATURE_INVALID;
exit:
	sss_se05x_key_store_erase_key(se050_kstore, &kobject);
	sss_se05x_asymmetric_context_free(&ctx);

	return res;
}

TEE_Result crypto_acipher_gen_ecc_key(struct ecc_keypair *key)
{
	sss_status_t st = kStatus_SSS_Fail;
	sss_se05x_object_t k_object = { 0 };
	TEE_Result ret = TEE_SUCCESS;
	uint8_t kf[512] = { 0 };
	size_t kB = 0, kb = 0;
	uint32_t oid = 0;
	uint64_t kid = 0;

	ret = ecc_get_key_size(key->curve, 0, &kB, &kb);
	if (ret != TEE_SUCCESS)
		return ret;

	ret = TEE_ERROR_BAD_PARAMETERS;

	st = sss_se05x_key_object_init(&k_object, se050_kstore);
	if (st != kStatus_SSS_Success)
		return TEE_ERROR_BAD_PARAMETERS;

	st = se050_get_oid(kKeyObject_Mode_Persistent, &oid);
	if (st != kStatus_SSS_Success)
		return TEE_ERROR_GENERIC;

	st = sss_se05x_key_object_allocate_handle(&k_object, oid,
						  kSSS_KeyPart_Pair,
						  cipher_tee2se050(key->curve),
						  0,
						  kKeyObject_Mode_Persistent);
	if (st != kStatus_SSS_Success)
		return TEE_ERROR_BAD_PARAMETERS;

	st = sss_se05x_key_store_generate_key(se050_kstore, &k_object, kb,
					      &se050_asym_policy);
	if (st != kStatus_SSS_Success)
		return TEE_ERROR_BAD_PARAMETERS;

	kB = sizeof(kf);
	st = se050_key_store_get_ecc_key_bin(se050_kstore, &k_object, kf, &kB);
	if (st != kStatus_SSS_Success) {
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto exit;
	}

	/* skip the DER tag */
	crypto_bignum_bin2bn(kf + 1, kB / 2, key->x);
	crypto_bignum_bin2bn(kf + 1 + kB / 2, kB / 2, key->y);

	/* the se050 does not provide the private key */
	kid = se050_generate_private_key(oid);
	crypto_bignum_bin2bn((uint8_t *)&kid, sizeof(kid), key->d);

	key->curve = curve_se0502tee(k_object.curve_id);
	ret = TEE_SUCCESS;
exit:
	if (ret != TEE_SUCCESS) {
		IMSG("ecc key generation failed");
		sss_se05x_key_store_erase_key(se050_kstore, &k_object);
	}

	return ret;
}
