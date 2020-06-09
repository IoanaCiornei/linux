/* SPDX-License-Identifier: (GPL-2.0+ OR BSD-3-Clause) */
/* Copyright 2020 NXP
 * Lynx PCS helpers
 */

#ifndef __LINUX_PCS_LYNX_H
#define __LINUX_PCS_LYNX_H

#include <linux/phy.h>
#include <linux/mdio.h>

void lynx_pcs_an_restart(struct mdio_device *pcs, phy_interface_t ifmode);

void lynx_pcs_get_state(struct mdio_device *pcs, phy_interface_t ifmode,
			struct phylink_link_state *state);

int lynx_pcs_config(struct mdio_device *pcs, unsigned int mode,
		    phy_interface_t ifmode,
		    const unsigned long *advertising);

void lynx_pcs_link_up(struct mdio_device *pcs, unsigned int mode,
		      phy_interface_t interface,
		      int speed, int duplex);

#endif /* __LINUX_PCS_LYNX_H */
