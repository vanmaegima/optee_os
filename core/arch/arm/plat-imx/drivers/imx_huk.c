#include <drivers/imx_caam_mkvb.h>
#include <kernel/tee_common_otp.h>
#include <string.h>
#include <trace.h>

static uint8_t stored_key[MKVB_SIZE];
static bool mkvb_retrieved;

#if defined(CFG_GET_ALTERNATIVE_HUK)
static bool caam_use_test_hw_key;

/* HUK on open boards (read during tests) */
static uint8_t hw_test_key[] = { CFG_GET_ALTERNATIVE_HUK };

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
		if (sizeof(hw_test_key) != sizeof(hwkey->data)) {
			EMSG("invalid CFG_GET_ALTERNATIVE_HUK size (%d, %d)",
			     sizeof(hw_test_key), sizeof(hwkey->data));
			return TEE_ERROR_SECURITY;
		}

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
