// SPDX-License-Identifier: (GPL-2.0+ OR BSD-3-Clause)
/*
 * Copyright 2020 NXP
 * Lynx PCS helpers
 */

#include <linux/mdio.h>
#include <linux/phylink.h>
#include <linux/mdio-lynx-pcs.h>

#define SGMII_LINK_TIMER1		0x12
#define SGMII_LINK_TIMER1_VAL		0x06a0

#define SGMII_LINK_TIMER2		0x13
#define SGMII_LINK_TIMER2_VAL		0x0003

#define SGMII_IF_MODE			0x14
#define SGMII_IF_MODE_SGMII_EN		BIT(0)
#define SGMII_IF_MODE_USE_SGMII_AN	BIT(1)
#define SGMII_IF_MODE_SPEED(x)		(((x) << 2) & GENMASK(3, 2))
#define SGMII_IF_MODE_SPEED_MSK		GENMASK(3, 2)
#define SGMII_IF_MODE_DUPLEX		BIT(4)

#define USXGMII_ADVERTISE_LNKS(x)	(((x) << 15) & BIT(15))
#define USXGMII_ADVERTISE_FDX		BIT(12)
#define USXGMII_ADVERTISE_SPEED(x)	(((x) << 9) & GENMASK(11, 9))

#define USXGMII_LPA_LSTATUS(lpa)	((lpa) >> 15)
#define USXGMII_LPA_DUPLEX(lpa)		(((lpa) & GENMASK(12, 12)) >> 12)
#define USXGMII_LPA_SPEED(lpa)		(((lpa) & GENMASK(11, 9)) >> 9)

enum usxgmii_speed {
	USXGMII_SPEED_10	= 0,
	USXGMII_SPEED_100	= 1,
	USXGMII_SPEED_1000	= 2,
	USXGMII_SPEED_2500	= 4,
};

enum sgmii_speed {
	SGMII_SPEED_10		= 0,
	SGMII_SPEED_100		= 1,
	SGMII_SPEED_1000	= 2,
	SGMII_SPEED_2500	= 2,
};

// TODO:
#if 0

 * this was after forcing the speed + duplex.
 * documentation says this is read-only

		/* Yes, not a mistake: speed is given by IF_MODE. */
		mdiobus_write(bus, addr, MII_BMCR,
			      BMCR_RESET | BMCR_SPEED1000 | BMCR_FULLDPLX);

#endif

static void lynx_pcs_an_restart_usxgmii(struct mdio_device *pcs)
{
	mdiobus_c45_write(pcs->bus, pcs->addr,
			  MDIO_MMD_VEND2, MII_BMCR,
			  BMCR_RESET | BMCR_ANENABLE | BMCR_ANRESTART);
}

static void lynx_pcs_an_restart(struct mdio_device *pcs, phy_interface_t ifmode)
{
	switch (ifmode) {
	case PHY_INTERFACE_MODE_SGMII:
	case PHY_INTERFACE_MODE_QSGMII:
		phylink_mii_c22_pcs_an_restart(pcs);
		break;
	case PHY_INTERFACE_MODE_USXGMII:
		lynx_pcs_an_restart_usxgmii(pcs);
		break;
	case PHY_INTERFACE_MODE_2500BASEX:
		break;
	default:
		dev_err(&pcs->dev, "Invalid PCS interface type %s\n",
			phy_modes(ifmode));
		break;
	}
}

static void lynx_pcs_get_state_usxgmii(struct mdio_device *pcs,
				       struct phylink_link_state *state)
{
	struct mii_bus *bus = pcs->bus;
	int addr = pcs->addr;
	int status, lpa;

	status = mdiobus_c45_read(bus, addr, MDIO_MMD_VEND2, MII_BMSR);
	if (status < 0)
		return;

	state->link = !!(status & MDIO_STAT1_LSTATUS);
	state->an_complete = !!(status & MDIO_AN_STAT1_COMPLETE);
	if (!state->link || !state->an_complete)
		return;

	lpa = mdiobus_c45_read(bus, addr, MDIO_MMD_VEND2, MII_LPA);
	if (lpa < 0)
		return;

	switch (USXGMII_LPA_SPEED(lpa)) {
	case USXGMII_SPEED_10:
		state->speed = SPEED_10;
		break;
	case USXGMII_SPEED_100:
		state->speed = SPEED_100;
		break;
	case USXGMII_SPEED_1000:
		state->speed = SPEED_1000;
		break;
	case USXGMII_SPEED_2500:
		state->speed = SPEED_2500;
		break;
	default:
		break;
	}

	if (USXGMII_LPA_DUPLEX(lpa))
		state->duplex = DUPLEX_FULL;
	else
		state->duplex = DUPLEX_HALF;
}

static void lynx_pcs_get_state_2500basex(struct mdio_device *pcs,
					 struct phylink_link_state *state)
{
	struct mii_bus *bus = pcs->bus;
	int addr = pcs->addr;
	int bmsr, lpa;

	bmsr = mdiobus_read(bus, addr, MII_BMSR);
	lpa = mdiobus_read(bus, addr, MII_LPA);
	if (bmsr < 0 || lpa < 0) {
		state->link = false;
		return;
	}

	state->link = !!(bmsr & BMSR_LSTATUS);
	state->an_complete = !!(bmsr & BMSR_ANEGCOMPLETE);
	if (!state->link)
		return;

	state->speed = SPEED_2500;
	// TODO: why pause?
	state->pause |= MLO_PAUSE_TX | MLO_PAUSE_RX;
}

static void lynx_pcs_get_state(struct mdio_device *pcs, phy_interface_t ifmode,
			       struct phylink_link_state *state)
{
	switch (ifmode) {
	case PHY_INTERFACE_MODE_SGMII:
	case PHY_INTERFACE_MODE_QSGMII:
		phylink_mii_c22_pcs_get_state(pcs, state);
		break;
	case PHY_INTERFACE_MODE_2500BASEX:
		lynx_pcs_get_state_2500basex(pcs, state);
		break;
	case PHY_INTERFACE_MODE_USXGMII:
		lynx_pcs_get_state_usxgmii(pcs, state);
		break;
	default:
		break;
	}

	dev_err(&pcs->dev,
		"mode=%s/%s/%s link=%u an_enabled=%u an_complete=%u\n",
		phy_modes(ifmode),
		phy_speed_to_str(state->speed),
		phy_duplex_to_str(state->duplex),
		state->link, state->an_enabled, state->an_complete);
}

/* We enable SGMII AN only when the PHY has managed = "in-band-status" in the
 * device tree. If we are in MLO_AN_PHY mode, we program directly state->speed
 * into the PCS, which is retrieved out-of-band over MDIO. This also has the
 * benefit of working with SGMII fixed-links, like downstream switches, where
 * both link partners attempt to operate as AN slaves and therefore AN never
 * completes.
 */
static int lynx_pcs_config_sgmii(struct mdio_device *pcs, unsigned int mode,
				 const unsigned long *advertising)
{
	struct mii_bus *bus = pcs->bus;
	int addr = pcs->addr;
	u16 if_mode;
	int err;

	// TODO: check if the timers need to setup only for in-band since they
	// are autoneg timers

	/* Adjust link timer for SGMII */
	mdiobus_write(bus, addr, SGMII_LINK_TIMER1, SGMII_LINK_TIMER1_VAL);
	mdiobus_write(bus, addr, SGMII_LINK_TIMER2, SGMII_LINK_TIMER2_VAL);

	/* SGMII spec requires tx_config_Reg[15:0] to be exactly 0x4001
	 * for the MAC PCS in order to acknowledge the AN.
	 */
	mdiobus_write(bus, addr, MII_ADVERTISE,
		      ADVERTISE_SGMII | ADVERTISE_LPACK);

	if_mode = SGMII_IF_MODE_SGMII_EN;
	if (mode == MLO_AN_INBAND)
		if_mode |= SGMII_IF_MODE_USE_SGMII_AN;
	mdiobus_modify(bus, addr, SGMII_IF_MODE,
		       SGMII_IF_MODE_SGMII_EN | SGMII_IF_MODE_USE_SGMII_AN,
		       if_mode);

	err = phylink_mii_c22_pcs_config(pcs, mode, PHY_INTERFACE_MODE_SGMII,
					 advertising);
	return err;
}

static int lynx_pcs_config_usxgmii(struct mdio_device *pcs, unsigned int mode,
				   const unsigned long *advertising)
{
	struct mii_bus *bus = pcs->bus;
	int addr = pcs->addr;

	// TODO: check which documentation has these bits detailed

	/* Configure device ability for the USXGMII Replicator */
	mdiobus_c45_write(bus, addr, MDIO_MMD_VEND2, MII_ADVERTISE,
			  USXGMII_ADVERTISE_SPEED(USXGMII_SPEED_2500) |
			  USXGMII_ADVERTISE_LNKS(1) |
			  ADVERTISE_SGMII |
			  ADVERTISE_LPACK |
			  USXGMII_ADVERTISE_FDX);
	return 0;
}

static int lynx_pcs_config(struct mdio_device *pcs, unsigned int mode,
			   phy_interface_t ifmode,
			   const unsigned long *advertising)
{
	switch (ifmode) {
	case PHY_INTERFACE_MODE_SGMII:
	case PHY_INTERFACE_MODE_QSGMII:
		lynx_pcs_config_sgmii(pcs, mode, advertising);
		break;
	case PHY_INTERFACE_MODE_2500BASEX:
		/* 2500Base-X only works without in-band AN,
		 * thus nothing to do here */
		break;
	case PHY_INTERFACE_MODE_USXGMII:
		lynx_pcs_config_usxgmii(pcs, mode, advertising);
		break;
	default:
		return -EOPNOTSUPP;
	}

	return 0;
}

static void lynx_pcs_link_up_sgmii(struct mdio_device *pcs, unsigned int mode,
				   int speed, int duplex)
{
	struct mii_bus *bus = pcs->bus;
	u16 if_mode = 0, sgmii_speed;
	int addr = pcs->addr;

	/* The PCS needs to be configured manually only
	 * when not operating on in-band mode */
	if (mode == MLO_AN_INBAND)
		return;

	if (duplex == DUPLEX_HALF)
		if_mode |= SGMII_IF_MODE_DUPLEX;

	switch (speed) {
	case SPEED_1000:
		sgmii_speed = SGMII_SPEED_1000;
		break;
	case SPEED_100:
		sgmii_speed = SGMII_SPEED_100;
		break;
	case SPEED_10:
		sgmii_speed = SGMII_SPEED_10;
		break;
	case SPEED_UNKNOWN:
		/* Silently don't do anything */
		return;
	default:
		dev_err(&pcs->dev, "Invalid PCS speed %d\n", speed);
		return;
	}
	if_mode |= SGMII_IF_MODE_SPEED(sgmii_speed);

	mdiobus_modify(bus, addr, SGMII_IF_MODE,
		       SGMII_IF_MODE_DUPLEX | SGMII_IF_MODE_SPEED_MSK,
		       if_mode);
}

// TODO: comment
/* 2500Base-X is SerDes protocol 7 on Felix and 6 on ENETC. It is a SerDes lane
 * clocked at 3.125 GHz which encodes symbols with 8b/10b and does not have
 * auto-negotiation of any link parameters. Electrically it is compatible with
 * a single lane of XAUI.
 * The hardware reference manual wants to call this mode SGMII, but it isn't
 * really, since the fundamental features of SGMII:
 * - Downgrading the link speed by duplicating symbols
 * - Auto-negotiation
 * are not there.
 * The speed is configured at 1000 in the IF_MODE and BMCR MDIO registers
 * because the clock frequency is actually given by a PLL configured in the
 * Reset Configuration Word (RCW).
 * Since there is no difference between fixed speed SGMII w/o AN and 802.3z w/o
 * AN, we call this PHY interface type 2500Base-X. In case a PHY negotiates a
 * lower link speed on line side, the system-side interface remains fixed at
 * 2500 Mbps and we do rate adaptation through pause frames.
 */
static void lynx_pcs_link_up_2500basex(struct mdio_device *pcs,
				       unsigned int mode,
				       int speed, int duplex)
{
	struct mii_bus *bus = pcs->bus;
	int addr = pcs->addr;

	if (mode == MLO_AN_INBAND) {
		dev_err(&pcs->dev, "AN not supported for 2500BaseX\n");
		return;
	}

	mdiobus_write(bus, addr, SGMII_IF_MODE,
		      SGMII_IF_MODE_SGMII_EN |
		      SGMII_IF_MODE_SPEED(SGMII_SPEED_2500));

#if 0
	// TODO: check if these need to be set
	mdiobus_write(bus, addr, MII_BMCR,
		      BMCR_SPEED1000 | BMCR_FULLDPLX | BMCR_RESET);
#endif
}

static void lynx_pcs_link_up(struct mdio_device *pcs, unsigned int mode,
			     phy_interface_t interface,
			     int speed, int duplex)
{
	switch (interface) {
	case PHY_INTERFACE_MODE_SGMII:
	case PHY_INTERFACE_MODE_QSGMII:
		lynx_pcs_link_up_sgmii(pcs, mode, speed, duplex);
		break;
	case PHY_INTERFACE_MODE_2500BASEX:
		lynx_pcs_link_up_2500basex(pcs, mode, speed, duplex);
		break;
	case PHY_INTERFACE_MODE_USXGMII:
		/* At the moment, only in-band AN is supported for USXGMII
		 * so nothing to do in link_up */
		break;
	default:
		break;
	}
}

struct mdio_lynx_pcs *mdio_lynx_pcs_create(struct mdio_device *mdio_dev)
{
	struct mdio_lynx_pcs *pcs;

	if (WARN_ON(!mdio_dev))
		return NULL;

	pcs = kzalloc(sizeof(*pcs), GFP_KERNEL);
	if (!pcs)
		return NULL;

	pcs->dev = mdio_dev;
	pcs->an_restart = lynx_pcs_an_restart;
	pcs->get_state = lynx_pcs_get_state;
	pcs->link_up = lynx_pcs_link_up;
	pcs->config = lynx_pcs_config;

	return pcs;
}
EXPORT_SYMBOL(mdio_lynx_pcs_create);

void mdio_lynx_pcs_free(struct mdio_lynx_pcs *pcs)
{
	kfree(pcs);
}
EXPORT_SYMBOL(mdio_lynx_pcs_free);
