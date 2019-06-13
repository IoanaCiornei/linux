.. SPDX-License-Identifier: GPL-2.0
.. include:: <isonum.txt>

===============================
DPAA2 MAC / PHY proxy interface
===============================

:Copyright: |copy| 2019 NXP


Overview
--------

The DPAA2 MAC / PHY proxy interface driver binds to DPAA2 DPMAC objects, which
are dynamically discovered on the fsl-mc bus. Once probed, the driver looks up
the device tree for PHYLINK-compatible OF bindings (phy-handle) and does the
following:

- registers itself with the Management Complex (MC) firmware to receive
  interrupts for:

        - Link up/down (on the PHY)
        - Link configuration changes requested

- creates a PHYLINK instance based on its device_node and connects to the
  specified PHY

- notifies the MC firmware of any link status change received from PHYLINK


DPAA2 Software Architecture
---------------------------

Among other DPAA2 objects, the fsl-mc bus exports DPNI objects (abstracting a
network interface) and DPMAC objects (abstracting a MAC) which are probed and
managed by two different drivers: dpaa2-eth and dpaa2-mac.

Data connections may be established between a DPNI and a DPMAC, or between two
DPNIs.  A DPNI may be directly assigned to a guest software partition, whereas
a DPMAC object is always managed from the root (most privileged) container.

For netif_carrier_on/netif_carrier_off, the MC firmware presents to the DPNI
object an abstracted view of the link state:

.. code-block:: none

  Sources of abstracted link state information presented by the MC firmware

                                               +--------------------------------------+
  +------------+                               |                           xgmac_mdio |
  | net_device |                 +---------+   |  +-----+  +-----+  +-----+  +-----+  |
  +------------+                 | phylink |<--|  | PHY |  | PHY |  | PHY |  | PHY |  |
        ^                        +---------+   |  +-----+  +-----+  +-----+  +-----+  |
        |                             |        |                    External MDIO bus |
    dpaa2-eth                     dpaa2-mac    +--------------------------------------+
        ^                             |
        |                             |                                           Linux
  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        |                             |                                     MC firmware
        |              /|             V
  +----------+        / |       +----------+
  |          |       /  |       |          |
  |          |       |  |       |          |
  |   DPNI   |<------|  |<------|   DPMAC  |
  |          |       |  |       |          |
  |          |       \  |<---+  |          |
  +----------+        \ |    |  +----------+
                       \|    |
                             |
           +--------------------------------------+
           | MC firmware polling MAC PCS for link |
           |  +-----+  +-----+  +-----+  +-----+  |
           |  | PCS |  | PCS |  | PCS |  | PCS |  |
           |  +-----+  +-----+  +-----+  +-----+  |
           |                    Internal MDIO bus |
           +--------------------------------------+


Depending on an MC firmware configuration setting, each MAC may be in one of two modes:

- DPMAC_LINK_TYPE_FIXED: the link state management is handled exclusively by
  the MC firmware by polling the MAC PCS.

- DPMAC_LINK_TYPE_PHY: the link state comes as an input to the MC firmware
  itself through the dpmac_set_link_cfg() function.

In both cases, the MC firmware emits an abstracted link state information to
the connected DPNI which can be retrieved using the dpni_get_link_state()
command.  This way, users of DPNI interfaces are not required to implement
complex PHY drivers.

In DPMAC_LINK_TYPE_FIXED mode, a dpaa2-mac driver is not necessary.

Implementation
--------------

After the system boots and the DPNIs are connected to DPMACs, all network
interfaces have their respective net_devices exported and ready to be used.

When the dpaa2-eth interface link is requested to go up, the following set of
steps must happen::

  Inter-driver communication between fsl-mc bus objects through the MC firmware

                             +-----------+                     +-------------+
                             |           | ------------------> | MC firmware |
                             | dpaa2-eth |         (1)         |             |
                             |           | < - - - - - - - - - |             |
                             +-----------+         (6)         |             |
                                   |                           |             |
                                  eth0                         |             |
                                                               |             |
  +---------+                +-----------+                     |             |
  | PHYLINK | <------------  | dpaa2-mac | <------------------ |             |
  |         |      (3)       |           |         (2)         |             |
  |         |                |           |                     |             |
  |         | ------------>  |           | ------------------> |             |
  +---------+      (4)       +-----------+         (5)         |             |
                                                               +-------------+

  (1) dpni_enable() - Enable network interface, allowing receiving/sending frames
  (2) MC sends DPMAC_IRQ_EVENT_LINK_UP_REQ to the dpmac object
  (3) The dpaa2-mac driver calls phylink_start() on the PHYLINK instance
  (4) PHYLINK notifies the dpaa2-mac driver through the .mac_config and
      .mac_link_up calbacks
  (5) With the information received in the phylink_link_state structure, the
      dpaa2-mac driver informs the firmware of the new link state
  (6) At any later time, the dpaa2-eth driver may find the updated link state
      by calling dpni_get_link_state() to the MC firmware

And the following output is seen in the console::

 # ip link set dev eth0 up
 [14894.837845] fsl_dpaa2_mac dpmac.17: configuring for phy/rgmii-id link mode
 [14896.895953] fsl_dpaa2_mac dpmac.17: Link is Up - 1Gbps/Full - flow control off
 [14896.897478] fsl_dpaa2_eth dpni.0 eth1: Link Event: state up


In case of a link change requested by the user through ethtool on the dpaa2-eth
interface, the same calling flow as above happens between DPNI driver -> MC ->
DPMAC driver -> PHYLINK and back. However in this case the functions are
different::

  (1) The dpaa2-eth driver, on the .set_link_ksettings() callback, sends a
      dpni_set_link_cfg() to the firmware, informing it about the new
      configuration requested. This firmware command will carry link state
      options such as autoneg on/off, advertising, duplex, speed.
  (2) The MC firmware will trigger an DPMAC_IRQ_EVENT_LINK_CFG_REQ.
  (3) Upon receiving the interrupt, the dpaa2-mac driver will get the
      requested configuration parameters and construct a new
      ethtool_link_ksettings command based on them. This will be passed to
      phylink_ethtool_ksettings_set.
  (4) If the link state changes, the .mac_config() routine will be called by
      PHYLINK.
  (5) The dpaa2-mac driver passes the current state of link from the
      phylink_link_state argument and notifies the firmware of all the changes
      (autoneg, speed, etc) through another dpmac_set_link_state() command.
  (6) Same as above, the DPNI driver can retrieve the updated link state
      information at a later time through dpni_get_link_state().
