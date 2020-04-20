#include <drivers/imx_caam_mkvb.h>
#include <kernel/tee_common_otp.h>
#include <string.h>

static uint8_t stored_key[MKVB_SIZE];
static bool mkvb_retrieved;

#if defined(CFG_GET_ALTERNATIVE_HUK)
static bool caam_use_test_hw_key;

#if defined(CFG_MX7ULP)
/* HUK on open boards (read during tests) */
static uint8_t hw_test_key[] = {
	0xc2, 0x0c, 0x77, 0xec, 0xad, 0x89, 0xdc, 0x96,
	0xb7, 0x9f, 0xc8, 0xf7, 0xda, 0xab, 0x97, 0xb4,
	0x2a, 0xe8, 0xdf, 0x98, 0x3d, 0x74, 0x1c, 0x34,
	0xac, 0xa8, 0x63, 0xca, 0xeb, 0x5f, 0xde, 0xcd,
};
#else
#error "please provide alternative huk !"
static uint8_t hw_test_key[] = { 0 };
#endif

TEE_Result tee_otp_enable_test_hw_unique_key(void)
{
	if (!caam_use_test_hw_key) {
		caam_use_test_hw_key = true;
		return TEE_SUCCESS;
	}

	return TEE_ERROR_SECURITY;
}
#endif

TEE_Result tee_otp_get_hw_unique_key(struct tee_hw_unique_key *hwkey)
{
	int ret = TEE_ERROR_SECURITY;

#if defined(CFG_GET_ALTERNATIVE_HUK)
	if (caam_use_test_hw_key) {
		memcpy(&hwkey->data, &hw_test_key, sizeof(hwkey->data));

		/* reset so the real HUK can be used if needed */
		caam_use_test_hw_key = false;
		return TEE_SUCCESS;
	}
#endif
	if (!mkvb_retrieved) {
		ret = caam_get_mkvb(stored_key);
		if (ret)
			return ret;
		mkvb_retrieved = true;
	}
	memcpy(&hwkey->data, &stored_key, sizeof(hwkey->data));
	return TEE_SUCCESS;
}
