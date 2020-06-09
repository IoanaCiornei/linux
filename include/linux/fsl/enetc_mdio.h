/* SPDX-License-Identifier: (GPL-2.0+ OR BSD-3-Clause) */
/* Copyright 2019 NXP */

#ifndef _FSL_ENETC_MDIO_H_
#define _FSL_ENETC_MDIO_H_

#include <linux/phy.h>

struct enetc_hw;

struct enetc_mdio_priv {
	struct enetc_hw *hw;
	int mdio_base;
};

#if IS_REACHABLE(CONFIG_FSL_ENETC_MDIO)

int enetc_mdio_read(struct mii_bus *bus, int phy_id, int regnum);
int enetc_mdio_write(struct mii_bus *bus, int phy_id, int regnum, u16 value);
struct enetc_hw *enetc_hw_alloc(struct device *dev, void __iomem *port_regs);

#else

static inline int enetc_mdio_read(struct mii_bus *bus, int phy_id, int regnum)
{ return -EINVAL; }
static inline int enetc_mdio_write(struct mii_bus *bus, int phy_id, int regnum,
				   u16 value)
{ return -EINVAL; }
struct enetc_hw *enetc_hw_alloc(struct device *dev, void __iomem *port_regs)
{ return ERR_PTR(-EINVAL); }

#endif

#endif
