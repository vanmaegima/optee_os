// SPDX-License-Identifier: BSD-2-Clause
/*
 * (c) 2021 Jorge Ramirez <jorge@foundries.io>, Foundries Ltd.
 */

#include <arm.h>
#include <crypto/crypto.h>
#include <initcall.h>
#include <io.h>
#include <kernel/boot.h>
#include <kernel/delay.h>
#include <kernel/dt.h>
#include <kernel/panic.h>
#include <libfdt.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <rng_support.h>
#include <stdlib.h>
#include <string.h>
#include <tee/tee_cryp_utl.h>
#include <trace.h>
#include <util.h>

#define RNGB_COMMAND			0x0004
#define RNGB_CONTROL			0x0008
#define RNGB_STATUS			0x000C
#define RNGB_ERROR			0x0010
#define RNGB_FIFO			0x0014

#define RNGB_CMD_CLR_ERR		0x00000020
#define RNGB_CMD_CLR_INT		0x00000010
#define RNGB_CMD_SEED			0x00000002
#define RNGB_CMD_SELF_TEST		0x00000001

#define RNGB_CTRL_MASK_ERROR		0x00000040
#define RNGB_CTRL_MASK_DONE		0x00000020

#define RNGB_STATUS_ERROR		0x00010000
#define RNGB_STATUS_FIFO_LEVEL_MASK	0x00000f00
#define RNGB_STATUS_FIFO_LEVEL_SHIFT	8
#define RNGB_STATUS_SEED_DONE		0x00000020
#define RNGB_STATUS_ST_DONE		0x00000010

#define RNGB_ERROR_STATUS_STAT_ERR	0x00000008

static struct imx_rng {
	struct io_pa_va base;
	uint32_t error;
} rngb = {
#if !defined(CFG_DT) || defined(CFG_EXTERNAL_DTB_OVERLAY)
#if defined(RNGB_BASE)
	.base.pa = RNGB_BASE,
#else
#error IMX_RNGB driver not supported on this platform
#endif
#endif
};

static void wait_for_irq(struct imx_rng *rng)
{
	uint64_t tref = timeout_init_us(1000000);
	uint32_t status = 0;

	while (!timeout_elapsed(tref)) {
		rng->error = io_read32(rng->base.va + RNGB_ERROR);
		status = io_read32(rng->base.va + RNGB_STATUS);
		if (status & (RNGB_STATUS_SEED_DONE | RNGB_STATUS_ST_DONE))
			return;
	}
	panic();
}

static void irq_clear(struct imx_rng *rng)
{
	uint32_t ctrl = 0;
	uint32_t cmd = 0;

	ctrl = io_read32(rng->base.va + RNGB_CONTROL);
	ctrl |= RNGB_CTRL_MASK_DONE | RNGB_CTRL_MASK_ERROR;
	io_write32(rng->base.va + RNGB_CONTROL, ctrl);

	cmd = io_read32(rng->base.va + RNGB_COMMAND);
	cmd |= RNGB_CMD_CLR_INT | RNGB_CMD_CLR_ERR;
	io_write32(rng->base.va + RNGB_COMMAND, cmd);
}

static void irq_unmask(struct imx_rng *rng)
{
	uint32_t ctrl = 0;

	ctrl = io_read32(rng->base.va + RNGB_CONTROL);
	ctrl &= ~(RNGB_CTRL_MASK_DONE | RNGB_CTRL_MASK_ERROR);
	io_write32(rng->base.va + RNGB_CONTROL, ctrl);
}

static void rng_seed(struct imx_rng *rng)
{
	uint64_t tref = timeout_init_us(1000000);
	uint32_t cmd = 0;

	cmd = io_read32(rng->base.va + RNGB_COMMAND);
	io_write32(rng->base.va + RNGB_COMMAND, cmd | RNGB_CMD_CLR_ERR);
	do {
		irq_unmask(rng);
		cmd = io_read32(rng->base.va + RNGB_COMMAND);
		io_write32(rng->base.va + RNGB_COMMAND, cmd | RNGB_CMD_SEED);
		wait_for_irq(rng);
		irq_clear(rng);
		if (!rng->error)
			return;
	} while (!timeout_elapsed(tref));
	panic();
}

#if defined(CFG_DT) && !defined(CFG_EXTERNAL_DTB_OVERLAY)
static const char *const rng_match = "fsl,imx25-rngb";
static TEE_Result map_controller(void)
{
	void *fdt = get_dt();
	size_t size = 0;
	int off = 0;

	if (!fdt)
		return TEE_ERROR_NOT_SUPPORTED;

	off = fdt_node_offset_by_compatible(fdt, off, rng_match);
	if (off < 0)
		return TEE_ERROR_NOT_SUPPORTED;

	if (dt_map_dev(fdt, off, &rngb.base.va, &size) < 0)
		return TEE_ERROR_NOT_SUPPORTED;

	rngb.base.pa = virt_to_phys((void *)rngb.base.va);

	return TEE_SUCCESS;
}
#else

static TEE_Result get_va(paddr_t pa, vaddr_t *va)
{
	if (!core_mmu_add_mapping(MEM_AREA_IO_SEC, pa, 0x4000))
		return TEE_ERROR_GENERIC;

	*va = (vaddr_t)phys_to_virt(pa, MEM_AREA_IO_SEC);
	if (*va)
		return TEE_SUCCESS;

	return TEE_ERROR_GENERIC;
}

static TEE_Result map_controller(void)
{
	if (get_va(rngb.base.pa, &rngb.base.va))
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}
#endif

TEE_Result crypto_rng_read(void *buf, size_t len)
{
	uint32_t status = 0;
	uint32_t words = 0;
	uint32_t val = 0;
	uint32_t *rngbuf = buf;

	if (!rngb.base.va || !rngb.base.pa)
		return TEE_ERROR_BAD_STATE;

	while (len) {
		status = io_read32(rngb.base.va + RNGB_STATUS);
		if (status & RNGB_STATUS_ERROR)
			return TEE_ERROR_BAD_STATE;

		words = (status & RNGB_STATUS_FIFO_LEVEL_MASK) >>
			RNGB_STATUS_FIFO_LEVEL_SHIFT;

		if (words) {
			val = io_read32(rngb.base.va + RNGB_FIFO);
			if (len > sizeof(uint32_t)) {
				len = len - sizeof(uint32_t);
				memcpy(rngbuf, &val, sizeof(uint32_t));
				rngbuf++;
			} else {
				memcpy(rngbuf, &val, len);
				len = 0;
			}
		}
	}

	return TEE_SUCCESS;
}

uint8_t hw_get_random_byte(void)
{
	uint8_t data = 0;

	if (crypto_rng_read(&data, 1))
		panic();

	return data;
}

void plat_rng_init(void)
{
}

static TEE_Result rngb_init(void)
{
	if (map_controller())
		panic();
	rng_seed(&rngb);

	return TEE_SUCCESS;
}

driver_init(rngb_init);
