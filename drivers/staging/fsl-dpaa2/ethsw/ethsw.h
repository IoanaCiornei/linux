/* SPDX-License-Identifier: GPL-2.0 */
/*
 * DPAA2 Ethernet Switch declarations
 *
 * Copyright 2014-2016 Freescale Semiconductor Inc.
 * Copyright 2017-2018 NXP
 *
 */

#ifndef __ETHSW_H
#define __ETHSW_H

#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/rtnetlink.h>
#include <linux/if_vlan.h>
#include <uapi/linux/if_bridge.h>
#include <net/switchdev.h>
#include <linux/if_bridge.h>
#include <linux/fsl/mc.h>

#include <soc/fsl/dpaa2-io.h>

#include "dpsw-cmd.h"
#include "dpsw.h"

/* Number of IRQs supported */
#define DPSW_IRQ_NUM	2

/* Port is member of VLAN */
#define ETHSW_VLAN_MEMBER	1
/* VLAN to be treated as untagged on egress */
#define ETHSW_VLAN_UNTAGGED	2
/* Untagged frames will be assigned to this VLAN */
#define ETHSW_VLAN_PVID		4
/* VLAN configured on the switch */
#define ETHSW_VLAN_GLOBAL	8

/* Maximum Frame Length supported by HW (currently 10k) */
#define DPAA2_MFL		(10 * 1024)
#define ETHSW_MAX_FRAME_LENGTH	(DPAA2_MFL - VLAN_ETH_HLEN - ETH_FCS_LEN)
#define ETHSW_L2_MAX_FRM(mtu)	((mtu) + VLAN_ETH_HLEN + ETH_FCS_LEN)

/* Number of receive queues (one RX and one TX_CONF) */
#define ETHSW_RX_NUM_FQS		2

/* Hardware requires alignment for ingress/egress buffer addresses */
#define DPAA2_ETHSW_RX_BUF_RAW_SIZE	PAGE_SIZE
#define DPAA2_ETHSW_RX_BUF_TAILROOM \
	SKB_DATA_ALIGN(sizeof(struct skb_shared_info))
#define DPAA2_ETHSW_RX_BUF_SIZE \
	(DPAA2_ETHSW_RX_BUF_RAW_SIZE- DPAA2_ETHSW_RX_BUF_TAILROOM)

/* Dequeue store size */
#define DPAA2_ETHSW_STORE_SIZE		16

/* Buffer management */
#define BUFS_PER_CMD			7
#define DPAA2_ETHSW_BUFS_PERCPU		(1024 * BUFS_PER_CMD)
#define DPAA2_ETHSW_REFILL_THRESH	(DPAA2_ETHSW_BUFS_PERCPU * 5 / 6)

/* ACL related configuration points */
#define DPAA2_ETHSW_PORT_MAX_ACL_ENTRIES	16
#define DPAA2_ETHSW_PORT_ACL_KEY_SIZE		sizeof(struct dpsw_prep_acl_entry)

/* Number of times to retry DPIO portal operations while waiting
 * for portal to finish executing current command and become
 * available. We want to avoid being stuck in a while loop in case
 * hardware becomes unresponsive, but not give up too easily if
 * the portal really is busy for valid reasons
 */
#define DPAA2_ETHSW_SWP_BUSY_RETRIES	1000

/* Hardware annotation buffer size */
#define DPAA2_ETHSW_HWA_SIZE		64
/* Software annotation buffer size */
#define DPAA2_ETHSW_SWA_SIZE		64

#define DPAA2_ETHSW_TX_BUF_ALIGN	64

#define DPAA2_ETHSW_TX_DATA_OFFSET \
	(DPAA2_ETHSW_HWA_SIZE + DPAA2_ETHSW_SWA_SIZE)

#define DPAA2_ETHSW_NEEDED_HEADROOM \
	(DPAA2_ETHSW_TX_DATA_OFFSET + DPAA2_ETHSW_TX_BUF_ALIGN)

extern const struct ethtool_ops ethsw_port_ethtool_ops;

struct ethsw_core;

struct ethsw_fq {
	void (*consume)(struct ethsw_fq *fq, const struct dpaa2_fd *fd);
	struct ethsw_core *ethsw;
	enum dpsw_queue_type type;
	struct dpaa2_io_notification_ctx nctx;
	struct dpaa2_io_store *store;
	struct napi_struct napi;
	u32 fqid;
};

/* Per port private data */
struct ethsw_port_priv {
	struct net_device	*netdev;
	u16			idx;
	struct ethsw_core	*ethsw_data;
	u8			link_state;
	u8			stp_state;
	bool			flood;

	u8			vlans[VLAN_VID_MASK + 1];
	u16			pvid;
	struct net_device	*bridge_dev;
	u16			acl_id;
	u8			acl_cnt;
	u16			tx_qdid;
};


#define DPAA2_ETHSW_CTRL_IF_MIN_MAJOR 8
#define DPAA2_ETHSW_CTRL_IF_MIN_MINOR 4

enum dpaa2_ethsw_features {
	DPAA2_ETHSW_CONTROL_TRAFFIC = BIT(0),
};

/* Switch data */
struct ethsw_core {
	struct device			*dev;
	struct fsl_mc_io		*mc_io;
	u16				dpsw_handle;
	struct dpsw_attr		sw_attr;
	int				dev_id;
	struct ethsw_port_priv		**ports;
	struct iommu_domain		*iommu_domain;
	int				features;

	u8				vlans[VLAN_VID_MASK + 1];
	bool				learning;

	struct ethsw_fq			fq[ETHSW_RX_NUM_FQS];
	struct fsl_mc_device		*dpbp_dev;
	int 				buf_count;
	u16				bpid;
	int				napi_users;
};

static inline bool ethsw_has_ctrl_if(struct ethsw_core *ethsw)
{
	if (!ethsw->features & DPAA2_ETHSW_CONTROL_TRAFFIC)
		return false;

	return !(ethsw->sw_attr.options & DPSW_OPT_CTRL_IF_DIS);
}
#endif	/* __ETHSW_H */
