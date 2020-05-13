/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2020 Foundries Ltd
 */

#ifndef __MX8M_CRM_REGS_H
#define __MX8M_CRM_REGS_H

#define CCM_BASE		0x30380000
#define CCGR_CLK_ON_MASK	0x03

/* CCGRx Registers (Clock Gating) */
#define CCM_CCGR0		0x4000
#define CCM_CCGRx_OFFSET	0x10
#define CCM_CCGRx(idx)		(((idx) * CCM_CCGRx_OFFSET) + CCM_CCGR0)
#define CCM_CCGRx_SET(idx)	(CCM_CCGRx(idx) + 0x4)
#define CCM_CCGRx_CLR(idx)	(CCM_CCGRx(idx) + 0x8)
#define CCM_CCGRx_TOG(idx)	(CCM_CCGRx(idx) + 0xC)

#define BS_CCM_CCGRx_SETTING(idx)	((idx) * 4)
#define BM_CCM_CCGRx_SETTING(idx)	\
			SHIFT_U32(0x3, BS_CCM_CCGRx_SETTING(idx))
#define CCM_CCGRx_DISABLE(idx)		\
			SHIFT_U32(0, BS_CCM_CCGRx_SETTING(idx))
#define CCM_CCGRx_RUN(idx)		\
			BIT32(BS_CCM_CCGRx_SETTING(idx))
#define CCM_CCGRx_RUN_WAIT(idx)		\
			SHIFT_U32(0x2, BS_CCM_CCGRx_SETTING(idx))
#define CCM_CCGRx_ALWAYS_ON(idx)	\
			SHIFT_U32(0x3, BS_CCM_CCGRx_SETTING(idx))
#endif  /* __MX8M_CRM_REGS_H */
