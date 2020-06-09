// SPDX-License-Identifier: (GPL-2.0+ OR BSD-3-Clause)
/*
 * Copyright 2020 NXP
 * Lynx PCS helpers
 */

#ifndef __LINUX_MDIO_LYNX_PCS_H
#define __LINUX_MDIO_LYNX_PCS_H

#include <linux/phy.h>
#include <linux/mdio.h>

struct mdio_lynx_pcs {
	struct mdio_device *dev;

	void (*an_restart)(struct mdio_device *pcs, phy_interface_t ifmode);

	void (*get_state)(struct mdio_device *pcs, phy_interface_t ifmode,
			  struct phylink_link_state *state);

	int (*config)(struct mdio_device *pcs, unsigned int mode,
		      phy_interface_t ifmode,
		      const unsigned long *advertising);

	void (*link_up)(struct mdio_device *pcs, unsigned int mode,
			phy_interface_t ifmode, int speed, int duplex);
};

#if IS_ENABLED(CONFIG_MDIO_LYNX_PCS)
struct mdio_lynx_pcs *mdio_lynx_pcs_create(struct mdio_device *mdio_dev);

void mdio_lynx_pcs_free(struct mdio_lynx_pcs *pcs);
#else
static inline struct mdio_lynx_pcs_ops *mdio_lynx_pcs_get_ops(void)
{
	return NULL;
}

static void mdio_lynx_pcs_free(struct mdio_lynx_pcs *pcs)
{
	return;
}
#endif

#endif /* __LINUX_MDIO_LYNX_PCS_H */
