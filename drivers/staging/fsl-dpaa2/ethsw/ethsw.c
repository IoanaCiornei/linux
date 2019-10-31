// SPDX-License-Identifier: GPL-2.0
/*
 * DPAA2 Ethernet Switch driver
 *
 * Copyright 2014-2016 Freescale Semiconductor Inc.
 * Copyright 2017-2018 NXP
 *
 */

#include <linux/module.h>

#include <linux/interrupt.h>
#include <linux/msi.h>
#include <linux/kthread.h>
#include <linux/workqueue.h>
#include <linux/iommu.h>

#include <linux/fsl/mc.h>

#include "ethsw.h"

static struct workqueue_struct *ethsw_owq;

/* Minimal supported DPSW version */
#define DPSW_MIN_VER_MAJOR		8
#define DPSW_MIN_VER_MINOR		1

#define DEFAULT_VLAN_ID			1

static void *dpaa2_iova_to_virt(struct iommu_domain *domain,
				dma_addr_t iova_addr)
{
	phys_addr_t phys_addr;

	phys_addr = domain ? iommu_iova_to_phys(domain, iova_addr) : iova_addr;

	return phys_to_virt(phys_addr);
}

static int ethsw_add_vlan(struct ethsw_core *ethsw, u16 vid)
{
	int err;

	struct dpsw_vlan_cfg	vcfg = {
		.fdb_id = 0,
	};

	err = dpsw_vlan_add(ethsw->mc_io, 0,
			    ethsw->dpsw_handle, vid, &vcfg);
	if (err) {
		dev_err(ethsw->dev, "dpsw_vlan_add err %d\n", err);
		return err;
	}
	ethsw->vlans[vid] = ETHSW_VLAN_MEMBER;

	return 0;
}

static int ethsw_port_set_pvid(struct ethsw_port_priv *port_priv, u16 pvid)
{
	struct ethsw_core *ethsw = port_priv->ethsw_data;
	struct net_device *netdev = port_priv->netdev;
	struct dpsw_tci_cfg tci_cfg = { 0 };
	bool is_oper;
	int err, ret;

	err = dpsw_if_get_tci(ethsw->mc_io, 0, ethsw->dpsw_handle,
			      port_priv->idx, &tci_cfg);
	if (err) {
		netdev_err(netdev, "dpsw_if_get_tci err %d\n", err);
		return err;
	}

	tci_cfg.vlan_id = pvid;

	/* Interface needs to be down to change PVID */
	is_oper = netif_oper_up(netdev);
	if (is_oper) {
		err = dpsw_if_disable(ethsw->mc_io, 0,
				      ethsw->dpsw_handle,
				      port_priv->idx);
		if (err) {
			netdev_err(netdev, "dpsw_if_disable err %d\n", err);
			return err;
		}
	}

	err = dpsw_if_set_tci(ethsw->mc_io, 0, ethsw->dpsw_handle,
			      port_priv->idx, &tci_cfg);
	if (err) {
		netdev_err(netdev, "dpsw_if_set_tci err %d\n", err);
		goto set_tci_error;
	}

	/* Delete previous PVID info and mark the new one */
	port_priv->vlans[port_priv->pvid] &= ~ETHSW_VLAN_PVID;
	port_priv->vlans[pvid] |= ETHSW_VLAN_PVID;
	port_priv->pvid = pvid;

set_tci_error:
	if (is_oper) {
		ret = dpsw_if_enable(ethsw->mc_io, 0,
				     ethsw->dpsw_handle,
				     port_priv->idx);
		if (ret) {
			netdev_err(netdev, "dpsw_if_enable err %d\n", ret);
			return ret;
		}
	}

	return err;
}

static int ethsw_port_add_vlan(struct ethsw_port_priv *port_priv,
			       u16 vid, u16 flags)
{
	struct ethsw_core *ethsw = port_priv->ethsw_data;
	struct net_device *netdev = port_priv->netdev;
	struct dpsw_vlan_if_cfg vcfg;
	int err;

	if (port_priv->vlans[vid]) {
		netdev_warn(netdev, "VLAN %d already configured\n", vid);
		return -EEXIST;
	}

	vcfg.num_ifs = 1;
	vcfg.if_id[0] = port_priv->idx;
	err = dpsw_vlan_add_if(ethsw->mc_io, 0, ethsw->dpsw_handle, vid, &vcfg);
	if (err) {
		netdev_err(netdev, "dpsw_vlan_add_if err %d\n", err);
		return err;
	}

	port_priv->vlans[vid] = ETHSW_VLAN_MEMBER;

	if (flags & BRIDGE_VLAN_INFO_UNTAGGED) {
		err = dpsw_vlan_add_if_untagged(ethsw->mc_io, 0,
						ethsw->dpsw_handle,
						vid, &vcfg);
		if (err) {
			netdev_err(netdev,
				   "dpsw_vlan_add_if_untagged err %d\n", err);
			return err;
		}
		port_priv->vlans[vid] |= ETHSW_VLAN_UNTAGGED;
	}

	if (flags & BRIDGE_VLAN_INFO_PVID) {
		err = ethsw_port_set_pvid(port_priv, vid);
		if (err)
			return err;
	}

	return 0;
}

static int ethsw_set_learning(struct ethsw_core *ethsw, bool enable)
{
	enum dpsw_fdb_learning_mode learn_mode;
	int err;

	if (enable)
		learn_mode = DPSW_FDB_LEARNING_MODE_HW;
	else
		learn_mode = DPSW_FDB_LEARNING_MODE_DIS;

	err = dpsw_fdb_set_learning_mode(ethsw->mc_io, 0, ethsw->dpsw_handle, 0,
					 learn_mode);
	if (err) {
		dev_err(ethsw->dev, "dpsw_fdb_set_learning_mode err %d\n", err);
		return err;
	}
	ethsw->learning = enable;

	return 0;
}

static int ethsw_port_set_flood(struct ethsw_port_priv *port_priv, bool enable)
{
	int err;

	err = dpsw_if_set_flooding(port_priv->ethsw_data->mc_io, 0,
				   port_priv->ethsw_data->dpsw_handle,
				   port_priv->idx, enable);
	if (err) {
		netdev_err(port_priv->netdev,
			   "dpsw_if_set_flooding err %d\n", err);
		return err;
	}
	port_priv->flood = enable;

	return 0;
}

static int ethsw_port_set_stp_state(struct ethsw_port_priv *port_priv, u8 state)
{
	struct dpsw_stp_cfg stp_cfg = {
		.vlan_id = DEFAULT_VLAN_ID,
		.state = state,
	};
	int err;

	if (!netif_oper_up(port_priv->netdev) || state == port_priv->stp_state)
		return 0;	/* Nothing to do */

	err = dpsw_if_set_stp(port_priv->ethsw_data->mc_io, 0,
			      port_priv->ethsw_data->dpsw_handle,
			      port_priv->idx, &stp_cfg);
	if (err) {
		netdev_err(port_priv->netdev,
			   "dpsw_if_set_stp err %d\n", err);
		return err;
	}

	port_priv->stp_state = state;

	return 0;
}

static int ethsw_dellink_switch(struct ethsw_core *ethsw, u16 vid)
{
	struct ethsw_port_priv *ppriv_local = NULL;
	int i, err;

	if (!ethsw->vlans[vid])
		return -ENOENT;

	err = dpsw_vlan_remove(ethsw->mc_io, 0, ethsw->dpsw_handle, vid);
	if (err) {
		dev_err(ethsw->dev, "dpsw_vlan_remove err %d\n", err);
		return err;
	}
	ethsw->vlans[vid] = 0;

	for (i = 0; i < ethsw->sw_attr.num_ifs; i++) {
		ppriv_local = ethsw->ports[i];
		ppriv_local->vlans[vid] = 0;
	}

	return 0;
}

static int ethsw_port_fdb_add_uc(struct ethsw_port_priv *port_priv,
				 const unsigned char *addr)
{
	struct dpsw_fdb_unicast_cfg entry = {0};
	int err;

	entry.if_egress = port_priv->idx;
	entry.type = DPSW_FDB_ENTRY_STATIC;
	ether_addr_copy(entry.mac_addr, addr);

	err = dpsw_fdb_add_unicast(port_priv->ethsw_data->mc_io, 0,
				   port_priv->ethsw_data->dpsw_handle,
				   0, &entry);
	if (err)
		netdev_err(port_priv->netdev,
			   "dpsw_fdb_add_unicast err %d\n", err);
	return err;
}

static int ethsw_port_fdb_del_uc(struct ethsw_port_priv *port_priv,
				 const unsigned char *addr)
{
	struct dpsw_fdb_unicast_cfg entry = {0};
	int err;

	entry.if_egress = port_priv->idx;
	entry.type = DPSW_FDB_ENTRY_STATIC;
	ether_addr_copy(entry.mac_addr, addr);

	err = dpsw_fdb_remove_unicast(port_priv->ethsw_data->mc_io, 0,
				      port_priv->ethsw_data->dpsw_handle,
				      0, &entry);
	/* Silently discard error for calling multiple times the del command */
	if (err && err != -ENXIO)
		netdev_err(port_priv->netdev,
			   "dpsw_fdb_remove_unicast err %d\n", err);
	return err;
}

static int ethsw_port_fdb_add_mc(struct ethsw_port_priv *port_priv,
				 const unsigned char *addr)
{
	struct dpsw_fdb_multicast_cfg entry = {0};
	int err;

	ether_addr_copy(entry.mac_addr, addr);
	entry.type = DPSW_FDB_ENTRY_STATIC;
	entry.num_ifs = 1;
	entry.if_id[0] = port_priv->idx;

	err = dpsw_fdb_add_multicast(port_priv->ethsw_data->mc_io, 0,
				     port_priv->ethsw_data->dpsw_handle,
				     0, &entry);
	/* Silently discard error for calling multiple times the add command */
	if (err && err != -ENXIO)
		netdev_err(port_priv->netdev, "dpsw_fdb_add_multicast err %d\n",
			   err);
	return err;
}

static int ethsw_port_fdb_del_mc(struct ethsw_port_priv *port_priv,
				 const unsigned char *addr)
{
	struct dpsw_fdb_multicast_cfg entry = {0};
	int err;

	ether_addr_copy(entry.mac_addr, addr);
	entry.type = DPSW_FDB_ENTRY_STATIC;
	entry.num_ifs = 1;
	entry.if_id[0] = port_priv->idx;

	err = dpsw_fdb_remove_multicast(port_priv->ethsw_data->mc_io, 0,
					port_priv->ethsw_data->dpsw_handle,
					0, &entry);
	/* Silently discard error for calling multiple times the del command */
	if (err && err != -ENAVAIL)
		netdev_err(port_priv->netdev,
			   "dpsw_fdb_remove_multicast err %d\n", err);
	return err;
}

static int port_fdb_add(struct ndmsg *ndm, struct nlattr *tb[],
			struct net_device *dev, const unsigned char *addr,
			u16 vid, u16 flags,
			struct netlink_ext_ack *extack)
{
	if (is_unicast_ether_addr(addr))
		return ethsw_port_fdb_add_uc(netdev_priv(dev),
					     addr);
	else
		return ethsw_port_fdb_add_mc(netdev_priv(dev),
					     addr);
}

static int port_fdb_del(struct ndmsg *ndm, struct nlattr *tb[],
			struct net_device *dev,
			const unsigned char *addr, u16 vid)
{
	if (is_unicast_ether_addr(addr))
		return ethsw_port_fdb_del_uc(netdev_priv(dev),
					     addr);
	else
		return ethsw_port_fdb_del_mc(netdev_priv(dev),
					     addr);
}

static void port_get_stats(struct net_device *netdev,
			   struct rtnl_link_stats64 *stats)
{
	struct ethsw_port_priv *port_priv = netdev_priv(netdev);
	u64 tmp;
	int err;

	err = dpsw_if_get_counter(port_priv->ethsw_data->mc_io, 0,
				  port_priv->ethsw_data->dpsw_handle,
				  port_priv->idx,
				  DPSW_CNT_ING_FRAME, &stats->rx_packets);
	if (err)
		goto error;

	err = dpsw_if_get_counter(port_priv->ethsw_data->mc_io, 0,
				  port_priv->ethsw_data->dpsw_handle,
				  port_priv->idx,
				  DPSW_CNT_EGR_FRAME, &stats->tx_packets);
	if (err)
		goto error;

	err = dpsw_if_get_counter(port_priv->ethsw_data->mc_io, 0,
				  port_priv->ethsw_data->dpsw_handle,
				  port_priv->idx,
				  DPSW_CNT_ING_BYTE, &stats->rx_bytes);
	if (err)
		goto error;

	err = dpsw_if_get_counter(port_priv->ethsw_data->mc_io, 0,
				  port_priv->ethsw_data->dpsw_handle,
				  port_priv->idx,
				  DPSW_CNT_EGR_BYTE, &stats->tx_bytes);
	if (err)
		goto error;

	err = dpsw_if_get_counter(port_priv->ethsw_data->mc_io, 0,
				  port_priv->ethsw_data->dpsw_handle,
				  port_priv->idx,
				  DPSW_CNT_ING_FRAME_DISCARD,
				  &stats->rx_dropped);
	if (err)
		goto error;

	err = dpsw_if_get_counter(port_priv->ethsw_data->mc_io, 0,
				  port_priv->ethsw_data->dpsw_handle,
				  port_priv->idx,
				  DPSW_CNT_ING_FLTR_FRAME,
				  &tmp);
	if (err)
		goto error;
	stats->rx_dropped += tmp;

	err = dpsw_if_get_counter(port_priv->ethsw_data->mc_io, 0,
				  port_priv->ethsw_data->dpsw_handle,
				  port_priv->idx,
				  DPSW_CNT_EGR_FRAME_DISCARD,
				  &stats->tx_dropped);
	if (err)
		goto error;

	return;

error:
	netdev_err(netdev, "dpsw_if_get_counter err %d\n", err);
}

static bool port_has_offload_stats(const struct net_device *netdev,
				   int attr_id)
{
	return (attr_id == IFLA_OFFLOAD_XSTATS_CPU_HIT);
}

static int port_get_offload_stats(int attr_id,
				  const struct net_device *netdev,
				  void *sp)
{
	switch (attr_id) {
	case IFLA_OFFLOAD_XSTATS_CPU_HIT:
		port_get_stats((struct net_device *)netdev, sp);
		return 0;
	}

	return -EINVAL;
}

static int port_change_mtu(struct net_device *netdev, int mtu)
{
	struct ethsw_port_priv *port_priv = netdev_priv(netdev);
	int err;

	err = dpsw_if_set_max_frame_length(port_priv->ethsw_data->mc_io,
					   0,
					   port_priv->ethsw_data->dpsw_handle,
					   port_priv->idx,
					   (u16)ETHSW_L2_MAX_FRM(mtu));
	if (err) {
		netdev_err(netdev,
			   "dpsw_if_set_max_frame_length() err %d\n", err);
		return err;
	}

	netdev->mtu = mtu;
	return 0;
}

static int port_carrier_state_sync(struct net_device *netdev)
{
	struct ethsw_port_priv *port_priv = netdev_priv(netdev);
	struct ethsw_core *ethsw = port_priv->ethsw_data;
	struct dpsw_link_state state;
	int err;

	err = dpsw_if_get_link_state(port_priv->ethsw_data->mc_io, 0,
				     port_priv->ethsw_data->dpsw_handle,
				     port_priv->idx, &state);
	if (err) {
		netdev_err(netdev, "dpsw_if_get_link_state() err %d\n", err);
		return err;
	}

	WARN_ONCE(state.up > 1, "Garbage read into link_state");

	if (state.up != port_priv->link_state) {
		if (state.up) {
			netif_carrier_on(netdev);
			if (ethsw_has_ctrl_if(ethsw))
				netif_tx_start_all_queues(netdev);
		} else {
			netif_carrier_off(netdev);
			if (ethsw_has_ctrl_if(ethsw))
				netif_tx_stop_all_queues(netdev);
		}
		port_priv->link_state = state.up;
	}
	return 0;
}

/* Manage all NAPI intances for the control interface.
 *
 * We only have one RX queue and one Tx Conf queue for all
 * switch ports. Therefore, we only need to enable the NAPI instance once, the
 * first time one of the switch ports run .dev_open().
 */

static void ethsw_enable_ctrl_if_napi(struct ethsw_core *ethsw)
{
	int i;

	/* a new interface is using the NAPI instance */
	ethsw->napi_users++;

	/* if there is already an user of the instance, return */
	if (ethsw->napi_users > 1)
		return;

	if (!ethsw_has_ctrl_if(ethsw))
		return;

	for (i = 0; i < ETHSW_RX_NUM_FQS; i++)
		napi_enable(&ethsw->fq[i].napi);
}

static void ethsw_disable_ctrl_if_napi(struct ethsw_core *ethsw)
{
	int i;

	/* If we are not the last interface using the NAPI, return */
	ethsw->napi_users--;
	if (ethsw->napi_users)
		return;

	if (!ethsw_has_ctrl_if(ethsw))
		return;

	for (i = 0; i < ETHSW_RX_NUM_FQS; i++)
		napi_disable(&ethsw->fq[i].napi);
}

static int port_open(struct net_device *netdev)
{
	struct ethsw_port_priv *port_priv = netdev_priv(netdev);
	struct ethsw_core *ethsw = port_priv->ethsw_data;
	int err;

	if (!ethsw_has_ctrl_if(port_priv->ethsw_data)) {
		/* No need to allow Tx as control interface is disabled */
		netif_tx_stop_all_queues(netdev);
	}

	err = dpsw_if_enable(port_priv->ethsw_data->mc_io, 0,
			     port_priv->ethsw_data->dpsw_handle,
			     port_priv->idx);
	if (err) {
		netdev_err(netdev, "dpsw_if_enable err %d\n", err);
		return err;
	}

	/* sync carrier state */
	err = port_carrier_state_sync(netdev);
	if (err) {
		netdev_err(netdev,
			   "port_carrier_state_sync err %d\n", err);
		goto err_carrier_sync;
	}

	ethsw_enable_ctrl_if_napi(ethsw);

	return 0;

err_carrier_sync:
	dpsw_if_disable(port_priv->ethsw_data->mc_io, 0,
			port_priv->ethsw_data->dpsw_handle,
			port_priv->idx);
	return err;
}

static int port_stop(struct net_device *netdev)
{
	struct ethsw_port_priv *port_priv = netdev_priv(netdev);
	struct ethsw_core *ethsw = port_priv->ethsw_data;
	int err;

	err = dpsw_if_disable(port_priv->ethsw_data->mc_io, 0,
			      port_priv->ethsw_data->dpsw_handle,
			      port_priv->idx);
	if (err) {
		netdev_err(netdev, "dpsw_if_disable err %d\n", err);
		return err;
	}

	ethsw_disable_ctrl_if_napi(ethsw);

	return 0;
}

static int swdev_get_port_parent_id(struct net_device *dev,
				    struct netdev_phys_item_id *ppid)
{
	struct ethsw_port_priv *port_priv = netdev_priv(dev);

	ppid->id_len = 1;
	ppid->id[0] = port_priv->ethsw_data->dev_id;

	return 0;
}

static int port_get_phys_name(struct net_device *netdev, char *name,
			      size_t len)
{
	struct ethsw_port_priv *port_priv = netdev_priv(netdev);
	int err;

	err = snprintf(name, len, "p%d", port_priv->idx);
	if (err >= len)
		return -EINVAL;

	return 0;
}

struct ethsw_dump_ctx {
	struct net_device *dev;
	struct sk_buff *skb;
	struct netlink_callback *cb;
	int idx;
};

static int ethsw_fdb_do_dump(struct fdb_dump_entry *entry,
			     struct ethsw_dump_ctx *dump)
{
	int is_dynamic = entry->type & DPSW_FDB_ENTRY_DINAMIC;
	u32 portid = NETLINK_CB(dump->cb->skb).portid;
	u32 seq = dump->cb->nlh->nlmsg_seq;
	struct nlmsghdr *nlh;
	struct ndmsg *ndm;

	if (dump->idx < dump->cb->args[2])
		goto skip;

	nlh = nlmsg_put(dump->skb, portid, seq, RTM_NEWNEIGH,
			sizeof(*ndm), NLM_F_MULTI);
	if (!nlh)
		return -EMSGSIZE;

	ndm = nlmsg_data(nlh);
	ndm->ndm_family  = AF_BRIDGE;
	ndm->ndm_pad1    = 0;
	ndm->ndm_pad2    = 0;
	ndm->ndm_flags   = NTF_SELF;
	ndm->ndm_type    = 0;
	ndm->ndm_ifindex = dump->dev->ifindex;
	ndm->ndm_state   = is_dynamic ? NUD_REACHABLE : NUD_NOARP;

	if (nla_put(dump->skb, NDA_LLADDR, ETH_ALEN, entry->mac_addr))
		goto nla_put_failure;

	nlmsg_end(dump->skb, nlh);

skip:
	dump->idx++;
	return 0;

nla_put_failure:
	nlmsg_cancel(dump->skb, nlh);
	return -EMSGSIZE;
}

static int port_fdb_valid_entry(struct fdb_dump_entry *entry,
				struct ethsw_port_priv *port_priv)
{
	int idx = port_priv->idx;
	int valid;

	if (entry->type & DPSW_FDB_ENTRY_TYPE_UNICAST)
		valid = entry->if_info == port_priv->idx;
	else
		valid = entry->if_mask[idx / 8] & BIT(idx % 8);

	return valid;
}

static int port_fdb_dump(struct sk_buff *skb, struct netlink_callback *cb,
			 struct net_device *net_dev,
			 struct net_device *filter_dev, int *idx)
{
	struct ethsw_port_priv *port_priv = netdev_priv(net_dev);
	struct ethsw_core *ethsw = port_priv->ethsw_data;
	struct device *dev = net_dev->dev.parent;
	struct fdb_dump_entry *fdb_entries;
	struct fdb_dump_entry fdb_entry;
	struct ethsw_dump_ctx dump = {
		.dev = net_dev,
		.skb = skb,
		.cb = cb,
		.idx = *idx,
	};
	dma_addr_t fdb_dump_iova;
	u16 num_fdb_entries;
	u32 fdb_dump_size;
	int err = 0, i;
	u8 *dma_mem;

	fdb_dump_size = ethsw->sw_attr.max_fdb_entries * sizeof(fdb_entry);
	dma_mem = kzalloc(fdb_dump_size, GFP_KERNEL);
	if (!dma_mem)
		return -ENOMEM;

	fdb_dump_iova = dma_map_single(dev, dma_mem, fdb_dump_size,
				       DMA_FROM_DEVICE);
	if (dma_mapping_error(dev, fdb_dump_iova)) {
		netdev_err(net_dev, "dma_map_single() failed\n");
		err = -ENOMEM;
		goto err_map;
	}

	err = dpsw_fdb_dump(ethsw->mc_io, 0, ethsw->dpsw_handle, 0,
			    fdb_dump_iova, fdb_dump_size, &num_fdb_entries);
	if (err) {
		netdev_err(net_dev, "dpsw_fdb_dump() = %d\n", err);
		goto err_dump;
	}

	dma_unmap_single(dev, fdb_dump_iova, fdb_dump_size, DMA_FROM_DEVICE);

	fdb_entries = (struct fdb_dump_entry *)dma_mem;
	for (i = 0; i < num_fdb_entries; i++) {
		fdb_entry = fdb_entries[i];

		if (!port_fdb_valid_entry(&fdb_entry, port_priv))
			continue;

		err = ethsw_fdb_do_dump(&fdb_entry, &dump);
		if (err)
			goto end;
	}

end:
	*idx = dump.idx;

	kfree(dma_mem);

	return 0;

err_dump:
	dma_unmap_single(dev, fdb_dump_iova, fdb_dump_size, DMA_TO_DEVICE);
err_map:
	kfree(dma_mem);
	return err;
}

static int ethsw_build_single_fd(struct ethsw_core *ethsw,
				 struct sk_buff *skb,
				 struct dpaa2_fd *fd)
{
	struct device *dev = ethsw->dev;
	struct sk_buff **skbh;
	dma_addr_t addr;
	u8 *buff_start;
	void *hwa;

	buff_start = PTR_ALIGN(skb->data - DPAA2_ETHSW_TX_DATA_OFFSET -
			       DPAA2_ETHSW_TX_BUF_ALIGN,
			       DPAA2_ETHSW_TX_BUF_ALIGN);

	/* Clear FAS to have consistent values for TX confirmation. It is
	 * located in the first 8 bytes of the buffer's hardware annotation
	 * area
	 */
	hwa = buff_start + DPAA2_ETHSW_SWA_SIZE;
	memset(hwa, 0, 8);

	/* Store a backpointer to the skb at the beginning of the buffer
	 * (in the private data area) such that we can release it
	 * on Tx confirm
	 */
	skbh = (struct sk_buff **)buff_start;
	*skbh = skb;

	addr = dma_map_single(dev, buff_start,
			      skb_tail_pointer(skb) - buff_start,
			      DMA_TO_DEVICE);
	if (unlikely(dma_mapping_error(dev, addr)))
		return -ENOMEM;

	/* Setup the FD fields */
	memset(fd, 0, sizeof(*fd));

	dpaa2_fd_set_addr(fd, addr);
	dpaa2_fd_set_offset(fd, (u16)(skb->data - buff_start));
	dpaa2_fd_set_len(fd, skb->len);
	dpaa2_fd_set_format(fd, dpaa2_fd_single);

	return 0;
}

static void ethsw_free_fd(const struct ethsw_core *ethsw,
			  const struct dpaa2_fd *fd)
{
	struct device *dev = ethsw->dev;
	unsigned char *buffer_start;
	dma_addr_t fd_addr;
	struct sk_buff **skbh, *skb;

	fd_addr = dpaa2_fd_get_addr(fd);
	skbh = dpaa2_iova_to_virt(ethsw->iommu_domain, fd_addr);

	skb = *skbh;
	buffer_start = (unsigned char *)skbh;

	dma_unmap_single(dev, fd_addr,
			 skb_tail_pointer(skb) - buffer_start,
			 DMA_TO_DEVICE);

	/* Move on with skb release */
	dev_kfree_skb(skb);
}

static netdev_tx_t ethsw_port_tx(struct sk_buff *skb,
				 struct net_device *net_dev)
{
	struct ethsw_port_priv *port_priv = netdev_priv(net_dev);
	struct ethsw_core *ethsw = port_priv->ethsw_data;
	int retries = DPAA2_ETHSW_SWP_BUSY_RETRIES;
	struct dpaa2_fd fd;
	int err;

	if (!ethsw_has_ctrl_if(ethsw)) {
		goto err_free_skb;
	}

	if (unlikely(skb_headroom(skb) < DPAA2_ETHSW_NEEDED_HEADROOM)) {
		struct sk_buff *ns;

		ns = skb_realloc_headroom(skb, DPAA2_ETHSW_NEEDED_HEADROOM);
		if (unlikely(!ns)) {
			netdev_err(net_dev, "Error reallocating skb headroom\n");
			goto err_free_skb;
		}
		dev_kfree_skb(skb);
		skb = ns;
	}

	/* We'll be holding a back-reference to the skb until Tx confirmation */
	skb = skb_unshare(skb, GFP_ATOMIC);
	if (unlikely(!skb)) {
		/* skb_unshare() has already freed the skb */
		netdev_err(net_dev, "Error copying the socket buffer\n");
		goto err_exit;
	}

	if (skb_is_nonlinear(skb)) {
		netdev_err(net_dev, "No support for non-linear SKBs!\n");
		goto err_free_skb;
	}

	err = ethsw_build_single_fd(ethsw, skb, &fd);
	if (unlikely(err)) {
		netdev_err(net_dev, "ethsw_build_*_fd() %d\n", err);
		goto err_free_skb;
	}

	do {
		err = dpaa2_io_service_enqueue_qd(NULL,
						  port_priv->tx_qdid,
						  8, 0, &fd);
		retries--;
	} while (err == -EBUSY && retries);

	if (unlikely(err < 0)) {
		ethsw_free_fd(ethsw, &fd);
		goto err_exit;
	}

	return NETDEV_TX_OK;

err_free_skb:
	dev_kfree_skb(skb);
err_exit:
	return NETDEV_TX_OK;
}

static const struct net_device_ops ethsw_port_ops = {
	.ndo_open		= port_open,
	.ndo_stop		= port_stop,

	.ndo_set_mac_address	= eth_mac_addr,
	.ndo_get_stats64	= port_get_stats,
	.ndo_change_mtu		= port_change_mtu,
	.ndo_has_offload_stats	= port_has_offload_stats,
	.ndo_get_offload_stats	= port_get_offload_stats,
	.ndo_fdb_add		= port_fdb_add,
	.ndo_fdb_del		= port_fdb_del,
	.ndo_fdb_dump		= port_fdb_dump,

	.ndo_start_xmit		= ethsw_port_tx,
	.ndo_get_port_parent_id	= swdev_get_port_parent_id,
	.ndo_get_phys_port_name = port_get_phys_name,
};

static void ethsw_links_state_update(struct ethsw_core *ethsw)
{
	int i;

	for (i = 0; i < ethsw->sw_attr.num_ifs; i++)
		port_carrier_state_sync(ethsw->ports[i]->netdev);
}

static irqreturn_t ethsw_irq0_handler_thread(int irq_num, void *arg)
{
	struct device *dev = (struct device *)arg;
	struct ethsw_core *ethsw = dev_get_drvdata(dev);

	/* Mask the events and the if_id reserved bits to be cleared on read */
	u32 status = DPSW_IRQ_EVENT_LINK_CHANGED | 0xFFFF0000;
	int err;

	err = dpsw_get_irq_status(ethsw->mc_io, 0, ethsw->dpsw_handle,
				  DPSW_IRQ_INDEX_IF, &status);
	if (err) {
		dev_err(dev, "Can't get irq status (err %d)\n", err);

		err = dpsw_clear_irq_status(ethsw->mc_io, 0, ethsw->dpsw_handle,
					    DPSW_IRQ_INDEX_IF, 0xFFFFFFFF);
		if (err)
			dev_err(dev, "Can't clear irq status (err %d)\n", err);
		goto out;
	}

	if (status & DPSW_IRQ_EVENT_LINK_CHANGED)
		ethsw_links_state_update(ethsw);

out:
	return IRQ_HANDLED;
}

static int ethsw_setup_irqs(struct fsl_mc_device *sw_dev)
{
	struct device *dev = &sw_dev->dev;
	struct ethsw_core *ethsw = dev_get_drvdata(dev);
	u32 mask = DPSW_IRQ_EVENT_LINK_CHANGED;
	struct fsl_mc_device_irq *irq;
	int err;

	err = fsl_mc_allocate_irqs(sw_dev);
	if (err) {
		dev_err(dev, "MC irqs allocation failed\n");
		return err;
	}

	if (WARN_ON(sw_dev->obj_desc.irq_count != DPSW_IRQ_NUM)) {
		err = -EINVAL;
		goto free_irq;
	}

	err = dpsw_set_irq_enable(ethsw->mc_io, 0, ethsw->dpsw_handle,
				  DPSW_IRQ_INDEX_IF, 0);
	if (err) {
		dev_err(dev, "dpsw_set_irq_enable err %d\n", err);
		goto free_irq;
	}

	irq = sw_dev->irqs[DPSW_IRQ_INDEX_IF];

	err = devm_request_threaded_irq(dev, irq->msi_desc->irq,
					NULL,
					ethsw_irq0_handler_thread,
					IRQF_NO_SUSPEND | IRQF_ONESHOT,
					dev_name(dev), dev);
	if (err) {
		dev_err(dev, "devm_request_threaded_irq(): %d\n", err);
		goto free_irq;
	}

	err = dpsw_set_irq_mask(ethsw->mc_io, 0, ethsw->dpsw_handle,
				DPSW_IRQ_INDEX_IF, mask);
	if (err) {
		dev_err(dev, "dpsw_set_irq_mask(): %d\n", err);
		goto free_devm_irq;
	}

	err = dpsw_set_irq_enable(ethsw->mc_io, 0, ethsw->dpsw_handle,
				  DPSW_IRQ_INDEX_IF, 1);
	if (err) {
		dev_err(dev, "dpsw_set_irq_enable(): %d\n", err);
		goto free_devm_irq;
	}

	return 0;

free_devm_irq:
	devm_free_irq(dev, irq->msi_desc->irq, dev);
free_irq:
	fsl_mc_free_irqs(sw_dev);
	return err;
}

static void ethsw_teardown_irqs(struct fsl_mc_device *sw_dev)
{
	struct device *dev = &sw_dev->dev;
	struct ethsw_core *ethsw = dev_get_drvdata(dev);
	int err;

	err = dpsw_set_irq_enable(ethsw->mc_io, 0, ethsw->dpsw_handle,
				  DPSW_IRQ_INDEX_IF, 0);
	if (err)
		dev_err(dev, "dpsw_set_irq_enable err %d\n", err);

	fsl_mc_free_irqs(sw_dev);
}

static int port_attr_stp_state_set(struct net_device *netdev,
				   struct switchdev_trans *trans,
				   u8 state)
{
	struct ethsw_port_priv *port_priv = netdev_priv(netdev);

	if (switchdev_trans_ph_prepare(trans))
		return 0;

	return ethsw_port_set_stp_state(port_priv, state);
}

static int port_attr_br_flags_pre_set(struct net_device *netdev,
				      struct switchdev_trans *trans,
				      unsigned long flags)
{
	if (flags & ~(BR_LEARNING | BR_FLOOD))
		return -EINVAL;

	return 0;
}

static int port_attr_br_flags_set(struct net_device *netdev,
				  struct switchdev_trans *trans,
				  unsigned long flags)
{
	struct ethsw_port_priv *port_priv = netdev_priv(netdev);
	int err = 0;

	if (switchdev_trans_ph_prepare(trans))
		return 0;

	/* Learning is enabled per switch */
	err = ethsw_set_learning(port_priv->ethsw_data,
				 !!(flags & BR_LEARNING));
	if (err)
		goto exit;

	err = ethsw_port_set_flood(port_priv, !!(flags & BR_FLOOD));

exit:
	return err;
}

static int swdev_port_attr_set(struct net_device *netdev,
			       const struct switchdev_attr *attr,
			       struct switchdev_trans *trans)
{
	int err = 0;

	switch (attr->id) {
	case SWITCHDEV_ATTR_ID_PORT_STP_STATE:
		err = port_attr_stp_state_set(netdev, trans,
					      attr->u.stp_state);
		break;
	case SWITCHDEV_ATTR_ID_PORT_PRE_BRIDGE_FLAGS:
		err = port_attr_br_flags_pre_set(netdev, trans,
						 attr->u.brport_flags);
		break;
	case SWITCHDEV_ATTR_ID_PORT_BRIDGE_FLAGS:
		err = port_attr_br_flags_set(netdev, trans,
					     attr->u.brport_flags);
		break;
	case SWITCHDEV_ATTR_ID_BRIDGE_VLAN_FILTERING:
		/* VLANs are supported by default  */
		break;
	default:
		err = -EOPNOTSUPP;
		break;
	}

	return err;
}

static int port_vlans_add(struct net_device *netdev,
			  const struct switchdev_obj_port_vlan *vlan,
			  struct switchdev_trans *trans)
{
	struct ethsw_port_priv *port_priv = netdev_priv(netdev);
	int vid, err = 0;

	if (switchdev_trans_ph_prepare(trans))
		return 0;

	for (vid = vlan->vid_begin; vid <= vlan->vid_end; vid++) {
		if (!port_priv->ethsw_data->vlans[vid]) {
			/* this is a new VLAN */
			err = ethsw_add_vlan(port_priv->ethsw_data, vid);
			if (err)
				return err;

			port_priv->ethsw_data->vlans[vid] |= ETHSW_VLAN_GLOBAL;
		}
		err = ethsw_port_add_vlan(port_priv, vid, vlan->flags);
		if (err)
			break;
	}

	return err;
}

static int port_lookup_address(struct net_device *netdev, int is_uc,
			       const unsigned char *addr)
{
	struct netdev_hw_addr_list *list = (is_uc) ? &netdev->uc : &netdev->mc;
	struct netdev_hw_addr *ha;

	netif_addr_lock_bh(netdev);
	list_for_each_entry(ha, &list->list, list) {
		if (ether_addr_equal(ha->addr, addr)) {
			netif_addr_unlock_bh(netdev);
			return 1;
		}
	}
	netif_addr_unlock_bh(netdev);
	return 0;
}

static int port_mdb_add(struct net_device *netdev,
			const struct switchdev_obj_port_mdb *mdb,
			struct switchdev_trans *trans)
{
	struct ethsw_port_priv *port_priv = netdev_priv(netdev);
	int err;

	if (switchdev_trans_ph_prepare(trans))
		return 0;

	/* Check if address is already set on this port */
	if (port_lookup_address(netdev, 0, mdb->addr))
		return -EEXIST;

	err = ethsw_port_fdb_add_mc(port_priv, mdb->addr);
	if (err)
		return err;

	err = dev_mc_add(netdev, mdb->addr);
	if (err) {
		netdev_err(netdev, "dev_mc_add err %d\n", err);
		ethsw_port_fdb_del_mc(port_priv, mdb->addr);
	}

	return err;
}

static int swdev_port_obj_add(struct net_device *netdev,
			      const struct switchdev_obj *obj,
			      struct switchdev_trans *trans)
{
	int err;

	switch (obj->id) {
	case SWITCHDEV_OBJ_ID_PORT_VLAN:
		err = port_vlans_add(netdev,
				     SWITCHDEV_OBJ_PORT_VLAN(obj),
				     trans);
		break;
	case SWITCHDEV_OBJ_ID_PORT_MDB:
		err = port_mdb_add(netdev,
				   SWITCHDEV_OBJ_PORT_MDB(obj),
				   trans);
		break;
	default:
		err = -EOPNOTSUPP;
		break;
	}

	return err;
}

static int ethsw_port_del_vlan(struct ethsw_port_priv *port_priv, u16 vid)
{
	struct ethsw_core *ethsw = port_priv->ethsw_data;
	struct net_device *netdev = port_priv->netdev;
	struct dpsw_vlan_if_cfg vcfg;
	int i, err;

	if (!port_priv->vlans[vid])
		return -ENOENT;

	if (port_priv->vlans[vid] & ETHSW_VLAN_PVID) {
		err = ethsw_port_set_pvid(port_priv, 0);
		if (err)
			return err;
	}

	vcfg.num_ifs = 1;
	vcfg.if_id[0] = port_priv->idx;
	if (port_priv->vlans[vid] & ETHSW_VLAN_UNTAGGED) {
		err = dpsw_vlan_remove_if_untagged(ethsw->mc_io, 0,
						   ethsw->dpsw_handle,
						   vid, &vcfg);
		if (err) {
			netdev_err(netdev,
				   "dpsw_vlan_remove_if_untagged err %d\n",
				   err);
		}
		port_priv->vlans[vid] &= ~ETHSW_VLAN_UNTAGGED;
	}

	if (port_priv->vlans[vid] & ETHSW_VLAN_MEMBER) {
		err = dpsw_vlan_remove_if(ethsw->mc_io, 0, ethsw->dpsw_handle,
					  vid, &vcfg);
		if (err) {
			netdev_err(netdev,
				   "dpsw_vlan_remove_if err %d\n", err);
			return err;
		}
		port_priv->vlans[vid] &= ~ETHSW_VLAN_MEMBER;

		/* Delete VLAN from switch if it is no longer configured on
		 * any port
		 */
		for (i = 0; i < ethsw->sw_attr.num_ifs; i++)
			if (ethsw->ports[i]->vlans[vid] & ETHSW_VLAN_MEMBER)
				return 0; /* Found a port member in VID */

		ethsw->vlans[vid] &= ~ETHSW_VLAN_GLOBAL;

		err = ethsw_dellink_switch(ethsw, vid);
		if (err)
			return err;
	}

	return 0;
}

static int port_vlans_del(struct net_device *netdev,
			  const struct switchdev_obj_port_vlan *vlan)
{
	struct ethsw_port_priv *port_priv = netdev_priv(netdev);
	int vid, err = 0;

	if (netif_is_bridge_master(vlan->obj.orig_dev))
		return -EOPNOTSUPP;

	for (vid = vlan->vid_begin; vid <= vlan->vid_end; vid++) {
		err = ethsw_port_del_vlan(port_priv, vid);
		if (err)
			break;
	}

	return err;
}

static int port_mdb_del(struct net_device *netdev,
			const struct switchdev_obj_port_mdb *mdb)
{
	struct ethsw_port_priv *port_priv = netdev_priv(netdev);
	int err;

	if (!port_lookup_address(netdev, 0, mdb->addr))
		return -ENOENT;

	err = ethsw_port_fdb_del_mc(port_priv, mdb->addr);
	if (err)
		return err;

	err = dev_mc_del(netdev, mdb->addr);
	if (err) {
		netdev_err(netdev, "dev_mc_del err %d\n", err);
		return err;
	}

	return err;
}

static int swdev_port_obj_del(struct net_device *netdev,
			      const struct switchdev_obj *obj)
{
	int err;

	switch (obj->id) {
	case SWITCHDEV_OBJ_ID_PORT_VLAN:
		err = port_vlans_del(netdev, SWITCHDEV_OBJ_PORT_VLAN(obj));
		break;
	case SWITCHDEV_OBJ_ID_PORT_MDB:
		err = port_mdb_del(netdev, SWITCHDEV_OBJ_PORT_MDB(obj));
		break;
	default:
		err = -EOPNOTSUPP;
		break;
	}
	return err;
}

static int
ethsw_switchdev_port_attr_set_event(struct net_device *netdev,
		struct switchdev_notifier_port_attr_info *port_attr_info)
{
	int err;

	err = swdev_port_attr_set(netdev, port_attr_info->attr,
				  port_attr_info->trans);

	port_attr_info->handled = true;
	return notifier_from_errno(err);
}

/* For the moment, only flood setting needs to be updated */
static int port_bridge_join(struct net_device *netdev,
			    struct net_device *upper_dev)
{
	struct ethsw_port_priv *port_priv = netdev_priv(netdev);
	struct ethsw_core *ethsw = port_priv->ethsw_data;
	int i, err;

	for (i = 0; i < ethsw->sw_attr.num_ifs; i++)
		if (ethsw->ports[i]->bridge_dev &&
		    (ethsw->ports[i]->bridge_dev != upper_dev)) {
			netdev_err(netdev,
				   "Only one bridge supported per DPSW object!\n");
			return -EINVAL;
		}

	/* Enable flooding */
	err = ethsw_port_set_flood(port_priv, 1);
	if (!err)
		port_priv->bridge_dev = upper_dev;

	return err;
}

static int port_bridge_leave(struct net_device *netdev)
{
	struct ethsw_port_priv *port_priv = netdev_priv(netdev);
	int err;

	/* Disable flooding */
	err = ethsw_port_set_flood(port_priv, 0);
	if (!err)
		port_priv->bridge_dev = NULL;

	return err;
}

static bool ethsw_port_dev_check(const struct net_device *netdev)
{
	return netdev->netdev_ops == &ethsw_port_ops;
}

static int port_netdevice_event(struct notifier_block *unused,
				unsigned long event, void *ptr)
{
	struct net_device *netdev = netdev_notifier_info_to_dev(ptr);
	struct netdev_notifier_changeupper_info *info = ptr;
	struct net_device *upper_dev;
	int err = 0;

	if (!ethsw_port_dev_check(netdev))
		return NOTIFY_DONE;

	/* Handle just upper dev link/unlink for the moment */
	if (event == NETDEV_CHANGEUPPER) {
		upper_dev = info->upper_dev;
		if (netif_is_bridge_master(upper_dev)) {
			if (info->linking)
				err = port_bridge_join(netdev, upper_dev);
			else
				err = port_bridge_leave(netdev);
		}
	}

	return notifier_from_errno(err);
}

static struct notifier_block port_nb __read_mostly = {
	.notifier_call = port_netdevice_event,
};

struct ethsw_switchdev_event_work {
	struct work_struct work;
	struct switchdev_notifier_fdb_info fdb_info;
	struct net_device *dev;
	unsigned long event;
};

static void ethsw_switchdev_event_work(struct work_struct *work)
{
	struct ethsw_switchdev_event_work *switchdev_work =
		container_of(work, struct ethsw_switchdev_event_work, work);
	struct net_device *dev = switchdev_work->dev;
	struct switchdev_notifier_fdb_info *fdb_info;
	int err;

	rtnl_lock();
	fdb_info = &switchdev_work->fdb_info;

	switch (switchdev_work->event) {
	case SWITCHDEV_FDB_ADD_TO_DEVICE:
		if (!fdb_info->added_by_user)
			break;
		if (is_unicast_ether_addr(fdb_info->addr))
			err = ethsw_port_fdb_add_uc(netdev_priv(dev),
						    fdb_info->addr);
		else
			err = ethsw_port_fdb_add_mc(netdev_priv(dev),
						    fdb_info->addr);
		if (err)
			break;
		fdb_info->offloaded = true;
		call_switchdev_notifiers(SWITCHDEV_FDB_OFFLOADED, dev,
					 &fdb_info->info, NULL);
		break;
	case SWITCHDEV_FDB_DEL_TO_DEVICE:
		if (!fdb_info->added_by_user)
			break;
		if (is_unicast_ether_addr(fdb_info->addr))
			ethsw_port_fdb_del_uc(netdev_priv(dev), fdb_info->addr);
		else
			ethsw_port_fdb_del_mc(netdev_priv(dev), fdb_info->addr);
		break;
	}

	rtnl_unlock();
	kfree(switchdev_work->fdb_info.addr);
	kfree(switchdev_work);
	dev_put(dev);
}

/* Called under rcu_read_lock() */
static int port_switchdev_event(struct notifier_block *unused,
				unsigned long event, void *ptr)
{
	struct net_device *dev = switchdev_notifier_info_to_dev(ptr);
	struct ethsw_switchdev_event_work *switchdev_work;
	struct switchdev_notifier_fdb_info *fdb_info = ptr;

	if (!ethsw_port_dev_check(dev))
		return NOTIFY_DONE;

	if (event == SWITCHDEV_PORT_ATTR_SET)
		return ethsw_switchdev_port_attr_set_event(dev, ptr);

	switchdev_work = kzalloc(sizeof(*switchdev_work), GFP_ATOMIC);
	if (!switchdev_work)
		return NOTIFY_BAD;

	INIT_WORK(&switchdev_work->work, ethsw_switchdev_event_work);
	switchdev_work->dev = dev;
	switchdev_work->event = event;

	switch (event) {
	case SWITCHDEV_FDB_ADD_TO_DEVICE:
	case SWITCHDEV_FDB_DEL_TO_DEVICE:
		memcpy(&switchdev_work->fdb_info, ptr,
		       sizeof(switchdev_work->fdb_info));
		switchdev_work->fdb_info.addr = kzalloc(ETH_ALEN, GFP_ATOMIC);
		if (!switchdev_work->fdb_info.addr)
			goto err_addr_alloc;

		ether_addr_copy((u8 *)switchdev_work->fdb_info.addr,
				fdb_info->addr);

		/* Take a reference on the device to avoid being freed. */
		dev_hold(dev);
		break;
	default:
		kfree(switchdev_work);
		return NOTIFY_DONE;
	}

	queue_work(ethsw_owq, &switchdev_work->work);

	return NOTIFY_DONE;

err_addr_alloc:
	kfree(switchdev_work);
	return NOTIFY_BAD;
}

static int
ethsw_switchdev_port_obj_event(unsigned long event, struct net_device *netdev,
			struct switchdev_notifier_port_obj_info *port_obj_info)
{
	int err = -EOPNOTSUPP;

	switch (event) {
	case SWITCHDEV_PORT_OBJ_ADD:
		err = swdev_port_obj_add(netdev, port_obj_info->obj,
					 port_obj_info->trans);
		break;
	case SWITCHDEV_PORT_OBJ_DEL:
		err = swdev_port_obj_del(netdev, port_obj_info->obj);
		break;
	}

	port_obj_info->handled = true;
	return notifier_from_errno(err);
}

static int port_switchdev_blocking_event(struct notifier_block *unused,
					 unsigned long event, void *ptr)
{
	struct net_device *dev = switchdev_notifier_info_to_dev(ptr);

	if (!ethsw_port_dev_check(dev))
		return NOTIFY_DONE;

	switch (event) {
	case SWITCHDEV_PORT_OBJ_ADD: /* fall through */
	case SWITCHDEV_PORT_OBJ_DEL:
		return ethsw_switchdev_port_obj_event(event, dev, ptr);
	case SWITCHDEV_PORT_ATTR_SET:
		return ethsw_switchdev_port_attr_set_event(dev, ptr);
	}

	return NOTIFY_DONE;
}

static struct notifier_block port_switchdev_nb = {
	.notifier_call = port_switchdev_event,
};

static struct notifier_block port_switchdev_blocking_nb = {
	.notifier_call = port_switchdev_blocking_event,
};

static int ethsw_register_notifier(struct device *dev)
{
	int err;

	err = register_netdevice_notifier(&port_nb);
	if (err) {
		dev_err(dev, "Failed to register netdev notifier\n");
		return err;
	}

	err = register_switchdev_notifier(&port_switchdev_nb);
	if (err) {
		dev_err(dev, "Failed to register switchdev notifier\n");
		goto err_switchdev_nb;
	}

	err = register_switchdev_blocking_notifier(&port_switchdev_blocking_nb);
	if (err) {
		dev_err(dev, "Failed to register switchdev blocking notifier\n");
		goto err_switchdev_blocking_nb;
	}

	return 0;

err_switchdev_blocking_nb:
	unregister_switchdev_notifier(&port_switchdev_nb);
err_switchdev_nb:
	unregister_netdevice_notifier(&port_nb);
	return err;
}

/* Build a linear skb based on a single-buffer frame descriptor */
static struct sk_buff *ethsw_build_linear_skb(struct ethsw_core *ethsw,
					      const struct dpaa2_fd *fd)
{
	u16 fd_offset = dpaa2_fd_get_offset(fd);
	u32 fd_length = dpaa2_fd_get_len(fd);
	struct device *dev = ethsw->dev;
	struct sk_buff *skb = NULL;
	dma_addr_t addr;
	void *fd_vaddr;

	addr = dpaa2_fd_get_addr(fd);
	dma_unmap_single(dev, addr, DPAA2_ETHSW_RX_BUF_SIZE,
			 DMA_FROM_DEVICE);
	fd_vaddr = dpaa2_iova_to_virt(ethsw->iommu_domain, addr);
	prefetch(fd_vaddr + fd_offset);

	skb = build_skb(fd_vaddr, DPAA2_ETHSW_RX_BUF_SIZE +
			SKB_DATA_ALIGN(sizeof(struct skb_shared_info)));
	if (unlikely(!skb)) {
		dev_err(dev, "build_skb() failed\n");
		return NULL;
	}

	skb_reserve(skb, fd_offset);
	skb_put(skb, fd_length);

	ethsw->buf_count--;

	return skb;
}

static void ethsw_tx_conf(struct ethsw_fq *fq,
			  const struct dpaa2_fd *fd)
{
	ethsw_free_fd(fq->ethsw, fd);
}

static void ethsw_rx(struct ethsw_fq *fq,
		     const struct dpaa2_fd *fd)
{
	struct ethsw_core *ethsw = fq->ethsw;
	struct ethsw_port_priv *port_priv;
	struct net_device *netdev;
	struct sk_buff *skb;
	int if_id = -1;
	u16 vlan_tci;
	int err;

	/* prefetch the frame descriptor */
	prefetch(fd);

	/* get switch ingress interface ID */
	if_id = upper_32_bits(dpaa2_fd_get_flc(fd)) & 0x0000FFFF;

	if (if_id < 0 || if_id >= ethsw->sw_attr.num_ifs) {
		dev_err(ethsw->dev, "Frame received from unknown interface!\n");
		goto err_free_fd;
	}
	port_priv = ethsw->ports[if_id];
	netdev = port_priv->netdev;

	/* build the SKB based on the FD received */
	if (dpaa2_fd_get_format(fd) == dpaa2_fd_single) {
		skb = ethsw_build_linear_skb(ethsw, fd);
	} else {
		netdev_err(netdev, "Received invalid frame format\n");
		goto err_free_fd;
	}

	if (unlikely(!skb))
		goto err_free_fd;

	skb_reset_mac_header(skb);

	/* Remove VLAN 1 for received frame */
	// TODO: we should remove the PVID, I think
	err = __skb_vlan_pop(skb, &vlan_tci);
	if (unlikely(err))
		dev_info(ethsw->dev, "skb_vlan_pop() failed %d", err);

	skb->dev = netdev;
	skb->protocol = eth_type_trans(skb, skb->dev);

	netif_receive_skb(skb);

	return;

err_free_fd:
	ethsw_free_fd(ethsw, fd);
}

static int ethsw_setup_fqs(struct ethsw_core *ethsw)
{
	struct dpsw_ctrl_if_attr ctrl_if_attr;
	struct device *dev = ethsw->dev;
	int i = 0;
	int err;

	err = dpsw_ctrl_if_get_attributes(ethsw->mc_io, 0,
					  ethsw->dpsw_handle,
					  &ctrl_if_attr);
	if (err) {
		dev_err(dev, "dpsw_ctrl_if_get_attributes() = %d\n", err);
		return err;
	}

	ethsw->fq[i].fqid = ctrl_if_attr.rx_fqid;
	ethsw->fq[i].ethsw = ethsw;
	ethsw->fq[i].type = DPSW_QUEUE_RX;
	ethsw->fq[i++].consume = ethsw_rx;

	ethsw->fq[i].fqid = ctrl_if_attr.tx_err_conf_fqid;
	ethsw->fq[i].ethsw = ethsw;
	ethsw->fq[i].type = DPSW_QUEUE_TX_ERR_CONF;
	ethsw->fq[i++].consume = ethsw_tx_conf;

	return 0;
}

/* Free buffers acquired from the buffer pool or which were meant to
 * be released in the pool
 */
static void ethsw_free_bufs(struct ethsw_core *ethsw, u64 *buf_array, int count)
{
	struct device *dev = ethsw->dev->parent;
	void *vaddr;
	int i;

	for (i = 0; i < count; i++) {
		vaddr = dpaa2_iova_to_virt(ethsw->iommu_domain, buf_array[i]);
		dma_unmap_page(dev, buf_array[i], DPAA2_ETHSW_RX_BUF_SIZE,
			       DMA_BIDIRECTIONAL);
		free_pages((unsigned long)vaddr, 0);
	}
}

/* Perform a single release command to add buffers
 * to the specified buffer pool
 */
static int ethsw_add_bufs(struct ethsw_core *ethsw, u16 bpid)
{
	struct device *dev = ethsw->dev->parent;
	u64 buf_array[BUFS_PER_CMD];
	struct page *page;
	int retries = 0;
	dma_addr_t addr;
	int err;
	int i;

	for (i = 0; i < BUFS_PER_CMD; i++) {
		/* Allocate one page for each Rx buffer. WRIOP sees
		 * the entire page except for a tailroom reserved for
		 * skb shared info
		 */
		page = dev_alloc_pages(0);
		if (!page) {
			dev_err(dev, "buffer allocation failed\n");
			goto err_alloc;
		}

		addr = dma_map_page(dev, page, 0, DPAA2_ETHSW_RX_BUF_SIZE,
				    DMA_FROM_DEVICE);
		if (dma_mapping_error(dev, addr)) {
			dev_err(dev, "dma_map_single() failed\n");
			goto err_map;
		}
		buf_array[i] = addr;
	}

release_bufs:
	/* In case the portal is busy, retry until successful or
	 * max retries hit.
	 */
	while ((err = dpaa2_io_service_release(NULL, bpid,
					       buf_array, i)) == -EBUSY) {
		if (retries++ >= DPAA2_ETHSW_SWP_BUSY_RETRIES)
			break;

		cpu_relax();
	}

	/* If release command failed, clean up and bail out.
	 */
	if (err) {
		ethsw_free_bufs(ethsw, buf_array, i);
		return 0;
	}

	return i;

err_map:
	__free_pages(page, 0);
err_alloc:
	/* If we managed to allocate at least some buffers,
	 * release them to hardware
	 */
	if (i)
		goto release_bufs;

	return 0;
}

static int ethsw_refill_bp(struct ethsw_core *ethsw)
{
	int *count = &ethsw->buf_count;
	int new_count;
	int err = 0;

	if (unlikely(*count < DPAA2_ETHSW_REFILL_THRESH)) {
		do {
			new_count = ethsw_add_bufs(ethsw, ethsw->bpid);
			if (unlikely(!new_count)) {
				/* Out of memory; abort for now, we'll
				 * try later on
				 */
				break;
			}
			*count += new_count;
		} while (*count < DPAA2_ETHSW_BUFS_PERCPU);

		if (unlikely(*count < DPAA2_ETHSW_BUFS_PERCPU))
			err = -ENOMEM;
	}

	return err;
}

static int ethsw_seed_bp(struct ethsw_core *ethsw)
{
	int *count, i;

	// TODO: remove PERCPU
	for (i = 0; i < DPAA2_ETHSW_BUFS_PERCPU; i += BUFS_PER_CMD) {
		count = &ethsw->buf_count;
		*count += ethsw_add_bufs(ethsw, ethsw->bpid);

		if (unlikely(*count < BUFS_PER_CMD))
			return -ENOMEM;
	}

	return 0;
}

static void ethsw_drain_bp(struct ethsw_core *ethsw)
{
	u64 buf_array[BUFS_PER_CMD];
	int ret;

	do {
		ret = dpaa2_io_service_acquire(NULL, ethsw->bpid,
					       buf_array, BUFS_PER_CMD);
		if (ret < 0) {
			dev_err(ethsw->dev,
				"dpaa2_io_service_acquire() = %d\n", ret);
			return;
		}
		ethsw_free_bufs(ethsw, buf_array, ret);

	} while (ret);
}

static int ethsw_setup_dpbp(struct ethsw_core *ethsw)
{
	struct dpsw_ctrl_if_pools_cfg dpsw_ctrl_if_pools_cfg = { 0 };
	struct device *dev = ethsw->dev;
	struct fsl_mc_device *dpbp_dev;
	struct dpbp_attr dpbp_attrs;
	int err;

	err = fsl_mc_object_allocate(to_fsl_mc_device(dev), FSL_MC_POOL_DPBP,
				     &dpbp_dev);
	if (err) {
		if (err == -ENXIO)
			err = -EPROBE_DEFER;
		else
			dev_err(dev, "DPBP device allocation failed\n");
		return err;
	}
	ethsw->dpbp_dev = dpbp_dev;

	err = dpbp_open(ethsw->mc_io, 0, dpbp_dev->obj_desc.id,
			&dpbp_dev->mc_handle);
	if (err) {
		dev_err(dev, "dpbp_open() failed\n");
		goto err_open;
	}

	err = dpbp_reset(ethsw->mc_io, 0, dpbp_dev->mc_handle);
	if (err) {
		dev_err(dev, "dpbp_reset() failed\n");
		goto err_reset;
	}

	err = dpbp_enable(ethsw->mc_io, 0, dpbp_dev->mc_handle);
	if (err) {
		dev_err(dev, "dpbp_enable() failed\n");
		goto err_enable;
	}

	err = dpbp_get_attributes(ethsw->mc_io, 0, dpbp_dev->mc_handle,
				  &dpbp_attrs);
	if (err) {
		dev_err(dev, "dpbp_get_attributes() failed\n");
		goto err_get_attr;
	}

	dpsw_ctrl_if_pools_cfg.num_dpbp = 1;
	dpsw_ctrl_if_pools_cfg.pools[0].dpbp_id = dpbp_attrs.id;
	dpsw_ctrl_if_pools_cfg.pools[0].buffer_size = DPAA2_ETHSW_RX_BUF_SIZE;
	dpsw_ctrl_if_pools_cfg.pools[0].backup_pool = 0;

	err = dpsw_ctrl_if_set_pools(ethsw->mc_io, 0, ethsw->dpsw_handle,
				     &dpsw_ctrl_if_pools_cfg);
	if (err) {
		dev_err(dev, "dpsw_ctrl_if_set_pools() failed\n");
		goto err_get_attr;
	}
	ethsw->bpid = dpbp_attrs.id;

	return 0;

err_get_attr:
	dpbp_disable(ethsw->mc_io, 0, dpbp_dev->mc_handle);
err_enable:
err_reset:
	dpbp_close(ethsw->mc_io, 0, dpbp_dev->mc_handle);
err_open:
	fsl_mc_object_free(dpbp_dev);
	return err;
}

static void ethsw_free_dpbp(struct ethsw_core *ethsw)
{
	dpbp_disable(ethsw->mc_io, 0, ethsw->dpbp_dev->mc_handle);
	dpbp_close(ethsw->mc_io, 0, ethsw->dpbp_dev->mc_handle);
	fsl_mc_object_free(ethsw->dpbp_dev);
}

static int ethsw_alloc_rings(struct ethsw_core *ethsw)
{
	int i;

	for (i = 0; i < ETHSW_RX_NUM_FQS; i++) {
		ethsw->fq[i].store =
			dpaa2_io_store_create(DPAA2_ETHSW_STORE_SIZE,
					      ethsw->dev);
		if (!ethsw->fq[i].store) {
			dev_err(ethsw->dev, "dpaa2_io_store_create failed\n");
			goto err_ring;
		}
	}

	return 0;

err_ring:
	for (i = 0; i < ETHSW_RX_NUM_FQS; i++) {
		if (!ethsw->fq[i].store)
			break;
		dpaa2_io_store_destroy(ethsw->fq[i].store);
	}

	return -ENOMEM;
}

static void ethsw_destroy_rings(struct ethsw_core *ethsw)
{
	int i;

	for (i = 0; i < ETHSW_RX_NUM_FQS; i++)
		dpaa2_io_store_destroy(ethsw->fq[i].store);
}

static int ethsw_pull_fq(struct ethsw_fq *fq)
{
	int err, retries = 0;

	/* Try to pull from the FQ while the portal is busy and we didn't hit
	 * the maximum number fo retries
	 */
	do {
		err = dpaa2_io_service_pull_fq(NULL,
					       fq->fqid,
					       fq->store);
		cpu_relax();
	} while (err == -EBUSY && retries++ < DPAA2_ETHSW_SWP_BUSY_RETRIES);

	if (unlikely(err))
		dev_err(fq->ethsw->dev, "dpaa2_io_service_pull err %d", err);

	return err;
}

/* Consume all frames pull-dequeued into the store */
static int ethsw_store_consume(struct ethsw_fq *fq)
{
	struct ethsw_core *ethsw = fq->ethsw;
	int cleaned = 0, is_last;
	struct dpaa2_dq *dq;
	int retries = 0;

	do {
		/* Get the next available FD from the store */
		dq = dpaa2_io_store_next(fq->store, &is_last);
		if (unlikely(!dq)) {
			if (retries++ >= DPAA2_ETHSW_SWP_BUSY_RETRIES) {
				dev_err_once(ethsw->dev,
					     "No valid dequeue response\n");
				return -ETIMEDOUT;
			}
			continue;
		}

		/* Process the FD */
		fq->consume(fq, dpaa2_dq_fd(dq));
		cleaned++;

	} while (!is_last);

	return cleaned;
}

/* NAPI poll routine */
static int ethsw_poll(struct napi_struct *napi, int budget)
{
	int err, cleaned = 0, store_cleaned, work_done;
	struct ethsw_fq *fq;
	int retries = 0;

	fq = container_of(napi, struct ethsw_fq, napi);

	do {
		err = ethsw_pull_fq(fq);
		if (unlikely(err))
			break;

		/* Refill pool if appropriate */
		ethsw_refill_bp(fq->ethsw);

		store_cleaned = ethsw_store_consume(fq);
		cleaned += store_cleaned;

		if (cleaned >= budget) {
			work_done = budget;
			goto out;
		}

	} while (store_cleaned);

	/* We didn't consume entire budget, so finish napi and
	 * re-enable data availability notifications
	 */
	napi_complete_done(napi, cleaned);
	do {
		err = dpaa2_io_service_rearm(NULL, &fq->nctx);
		cpu_relax();
	} while (err == -EBUSY && retries++ < DPAA2_ETHSW_SWP_BUSY_RETRIES);

	work_done = max(cleaned, 1);
out:

	return work_done;
}

static void ethsw_fqdan_cb(struct dpaa2_io_notification_ctx *nctx)
{
	struct ethsw_fq *fq;

	fq = container_of(nctx, struct ethsw_fq, nctx);

	napi_schedule_irqoff(&fq->napi);
}

static int ethsw_setup_dpio(struct ethsw_core *ethsw)
{
	struct dpaa2_io_notification_ctx *nctx;
	struct dpsw_ctrl_if_queue_cfg queue_cfg;
	int err, i, j;

	for (i = 0; i < ETHSW_RX_NUM_FQS; i++) {
		nctx = &ethsw->fq[i].nctx;

		nctx->is_cdan = 0;
		nctx->id = ethsw->fq[i].fqid;
		nctx->desired_cpu = DPAA2_IO_ANY_CPU;
		nctx->cb = ethsw_fqdan_cb;

		err = dpaa2_io_service_register(NULL, nctx, ethsw->dev);
		if (err) {
			err = -EPROBE_DEFER;
			goto err_register;
		}

		queue_cfg.options = DPSW_CTRL_IF_QUEUE_OPT_DEST |
				    DPSW_CTRL_IF_QUEUE_OPT_USER_CTX;
		queue_cfg.dest_cfg.dest_type = DPSW_CTRL_IF_DEST_DPIO;
		queue_cfg.dest_cfg.dest_id = nctx->dpio_id;
		queue_cfg.dest_cfg.priority = 0;
		queue_cfg.user_ctx = nctx->qman64;

		err = dpsw_ctrl_if_set_queue(ethsw->mc_io, 0,
					     ethsw->dpsw_handle,
					     ethsw->fq[i].type,
					     &queue_cfg);
		if (err)
			goto err_set_queue;
	}

	return 0;

err_set_queue:
	dpaa2_io_service_deregister(NULL, nctx, ethsw->dev);
err_register:
	for (j = 0; j < i; j++)
		dpaa2_io_service_deregister(NULL, &ethsw->fq[j].nctx,
					    ethsw->dev);

	return err;
}

static void ethsw_free_dpio(struct ethsw_core *ethsw)
{
	int i;

	for (i = 0; i < ETHSW_RX_NUM_FQS; i++)
		dpaa2_io_service_deregister(NULL, &ethsw->fq[i].nctx,
					    ethsw->dev);
}

static int ethsw_ctrl_if_setup(struct ethsw_core *ethsw)
{
	int err;

	/* setup FQs for Rx and Tx Conf */
	err = ethsw_setup_fqs(ethsw);
	if (err)
		return err;

	/* setup the buffer poll needed on the Rx path */
	err = ethsw_setup_dpbp(ethsw);
	if (err)
		return err;

	err = ethsw_seed_bp(ethsw);
	if (err)
		goto err_free_dpbp;

	err = ethsw_alloc_rings(ethsw);
	if (err)
		goto err_drain_dpbp;

	err = ethsw_setup_dpio(ethsw);
	if (err)
		goto err_destroy_rings;

	err = dpsw_ctrl_if_enable(ethsw->mc_io, 0, ethsw->dpsw_handle);
	if (err) {
		dev_err(ethsw->dev, "dpsw_ctrl_if_enable err %d\n", err);
		goto err_deregister_dpio;
	}

	ethsw->napi_users = 0;

	return 0;

err_deregister_dpio:
	ethsw_free_dpio(ethsw);
err_destroy_rings:
	ethsw_destroy_rings(ethsw);
err_drain_dpbp:
	ethsw_drain_bp(ethsw);
err_free_dpbp:
	ethsw_free_dpbp(ethsw);

	return err;
}

static int ethsw_init(struct fsl_mc_device *sw_dev)
{
	struct device *dev = &sw_dev->dev;
	struct ethsw_core *ethsw = dev_get_drvdata(dev);
	u16 version_major, version_minor, i;
	struct dpsw_stp_cfg stp_cfg;
	int err;

	ethsw->dev_id = sw_dev->obj_desc.id;

	err = dpsw_open(ethsw->mc_io, 0, ethsw->dev_id, &ethsw->dpsw_handle);
	if (err) {
		dev_err(dev, "dpsw_open err %d\n", err);
		return err;
	}

	err = dpsw_get_attributes(ethsw->mc_io, 0, ethsw->dpsw_handle,
				  &ethsw->sw_attr);
	if (err) {
		dev_err(dev, "dpsw_get_attributes err %d\n", err);
		goto err_close;
	}

	err = dpsw_get_api_version(ethsw->mc_io, 0,
				   &version_major,
				   &version_minor);
	if (err) {
		dev_err(dev, "dpsw_get_api_version err %d\n", err);
		goto err_close;
	}

	/* Minimum supported DPSW version check */
	if (version_major < DPSW_MIN_VER_MAJOR ||
	    (version_major == DPSW_MIN_VER_MAJOR &&
	     version_minor < DPSW_MIN_VER_MINOR)) {
		dev_err(dev, "DPSW version %d:%d not supported. Use %d.%d or greater.\n",
			version_major,
			version_minor,
			DPSW_MIN_VER_MAJOR, DPSW_MIN_VER_MINOR);
		err = -ENOTSUPP;
		goto err_close;
	}

	err = dpsw_reset(ethsw->mc_io, 0, ethsw->dpsw_handle);
	if (err) {
		dev_err(dev, "dpsw_reset err %d\n", err);
		goto err_close;
	}

	err = dpsw_fdb_set_learning_mode(ethsw->mc_io, 0, ethsw->dpsw_handle, 0,
					 DPSW_FDB_LEARNING_MODE_HW);
	if (err) {
		dev_err(dev, "dpsw_fdb_set_learning_mode err %d\n", err);
		goto err_close;
	}

	stp_cfg.vlan_id = DEFAULT_VLAN_ID;
	stp_cfg.state = DPSW_STP_STATE_FORWARDING;

	for (i = 0; i < ethsw->sw_attr.num_ifs; i++) {
		err = dpsw_if_set_stp(ethsw->mc_io, 0, ethsw->dpsw_handle, i,
				      &stp_cfg);
		if (err) {
			dev_err(dev, "dpsw_if_set_stp err %d for port %d\n",
				err, i);
			goto err_close;
		}

		err = dpsw_if_set_broadcast(ethsw->mc_io, 0,
					    ethsw->dpsw_handle, i, 1);
		if (err) {
			dev_err(dev,
				"dpsw_if_set_broadcast err %d for port %d\n",
				err, i);
			goto err_close;
		}
	}

	ethsw_owq = alloc_ordered_workqueue("%s_ordered", WQ_MEM_RECLAIM,
					    "ethsw");
	if (!ethsw_owq) {
		err = -ENOMEM;
		goto err_close;
	}

	if (ethsw_has_ctrl_if(ethsw)) {
		err = ethsw_ctrl_if_setup(ethsw);
		if (err)
			goto err_destroy_ordered_workqueue;
	}

	err = ethsw_register_notifier(dev);
	if (err)
		goto err_destroy_ordered_workqueue;

	return 0;

err_destroy_ordered_workqueue:
	destroy_workqueue(ethsw_owq);

err_close:
	dpsw_close(ethsw->mc_io, 0, ethsw->dpsw_handle);
	return err;
}

/* Add an ACL to redirect frames with specific destination MAC address to
 * control interface
 */
static int ethsw_acl_mac_to_ctr_if(struct ethsw_port_priv *port_priv,
				   const char *mac)
{
	struct device *dev = port_priv->netdev->dev.parent;
	struct net_device *netdev = port_priv->netdev;
	struct dpsw_acl_entry_cfg acl_entry_cfg;
	struct dpsw_acl_fields *acl_h, *acl_m;
	struct dpsw_acl_key acl_key;
	u8 *cmd_buff;
	int err = 0;

	acl_h = &acl_key.match;
	acl_m = &acl_key.mask;

	if (port_priv->acl_cnt >= DPAA2_ETHSW_PORT_MAX_ACL_ENTRIES) {
		netdev_err(netdev, "ACL table full\n");
		return -ENOMEM;
	}

	/* Match destination MAC address */
	memset(&acl_key, 0, sizeof(acl_key));
	ether_addr_copy(acl_h->l2_dest_mac, mac);
	eth_broadcast_addr(acl_m->l2_dest_mac);

	cmd_buff = kzalloc(DPAA2_ETHSW_PORT_ACL_KEY_SIZE, GFP_KERNEL);
	if (!cmd_buff)
		return -ENOMEM;
	dpsw_acl_prepare_entry_cfg(&acl_key, cmd_buff);

	/* Add entry */
	memset(&acl_entry_cfg, 0, sizeof(acl_entry_cfg));
	acl_entry_cfg.precedence = port_priv->acl_cnt;
	acl_entry_cfg.result.action = DPSW_ACL_ACTION_REDIRECT_TO_CTRL_IF;
	acl_entry_cfg.key_iova = dma_map_single(dev, cmd_buff,
						DPAA2_ETHSW_PORT_ACL_KEY_SIZE,
						DMA_TO_DEVICE);
	if (unlikely(dma_mapping_error(dev, acl_entry_cfg.key_iova))) {
		netdev_err(netdev, "DMA mapping failed\n");
		err = -EFAULT;
		goto err_map_key;
	}

	err = dpsw_acl_add_entry(port_priv->ethsw_data->mc_io, 0,
				 port_priv->ethsw_data->dpsw_handle,
				 port_priv->acl_id, &acl_entry_cfg);
	if (err) {
		netdev_err(netdev, "dpsw_acl_add_entry() failed %d\n", err);
		goto err_add_entry;
	}

	port_priv->acl_cnt++;

err_add_entry:
	dma_unmap_single(dev, acl_entry_cfg.key_iova,
			 DPAA2_ETHSW_PORT_ACL_KEY_SIZE, DMA_TO_DEVICE);
err_map_key:
	kfree(cmd_buff);

	return err;
}

static int ethsw_port_set_ctrl_if_acl(struct ethsw_port_priv *port_priv)
{
	const char stp_mac[ETH_ALEN] = {0x01, 0x80, 0xC2, 0x00, 0x00, 0x00};

	return ethsw_acl_mac_to_ctr_if(port_priv, stp_mac);
}

static int ethsw_port_init(struct ethsw_port_priv *port_priv, u16 port)
{
	struct ethsw_core *ethsw = port_priv->ethsw_data;
	struct net_device *netdev = port_priv->netdev;
	struct dpsw_acl_if_cfg acl_if_cfg;
	struct dpsw_if_attr dpsw_if_attr;
	struct dpsw_vlan_if_cfg vcfg;
	struct dpsw_acl_cfg acl_cfg;
	int err;

	/* Switch starts with all ports configured to VLAN 1. Need to
	 * remove this setting to allow configuration at bridge join
	 */
	vcfg.num_ifs = 1;
	vcfg.if_id[0] = port_priv->idx;

	err = dpsw_vlan_remove_if_untagged(ethsw->mc_io, 0, ethsw->dpsw_handle,
					   DEFAULT_VLAN_ID, &vcfg);
	if (err) {
		netdev_err(netdev, "dpsw_vlan_remove_if_untagged err %d\n",
			   err);
		return err;
	}

	err = ethsw_port_set_pvid(port_priv, 0);
	if (err)
		return err;

	err = dpsw_vlan_remove_if(ethsw->mc_io, 0, ethsw->dpsw_handle,
				  DEFAULT_VLAN_ID, &vcfg);
	if (err)
		netdev_err(netdev, "dpsw_vlan_remove_if err %d\n", err);

	/* create the ACL table for this particular interface */
	acl_cfg.max_entries = DPAA2_ETHSW_PORT_MAX_ACL_ENTRIES,
	err = dpsw_acl_add(ethsw->mc_io, 0, ethsw->dpsw_handle,
			   &port_priv->acl_id, &acl_cfg);
	if (err) {
		netdev_err(netdev, "dpsw_acl_add err %d\n", err);
		return err;
	}

	acl_if_cfg.num_ifs = 1,
	acl_if_cfg.if_id[0] = port_priv->idx;
	err = dpsw_acl_add_if(ethsw->mc_io, 0, ethsw->dpsw_handle,
			      port_priv->acl_id, &acl_if_cfg);
	if (err) {
		netdev_err(netdev, "dpsw_acl_add_if err %d\n", err);
		goto err_remove_acl;
	}

	err = ethsw_port_set_ctrl_if_acl(port_priv);
	if (err)
		goto err_remove_acl_if;

	err = dpsw_if_get_attributes(ethsw->mc_io, 0, ethsw->dpsw_handle,
				     port_priv->idx, &dpsw_if_attr);
	if (err) {
		netdev_err(netdev, "dpsw_if_get_attributes err %d\n", err);
		goto err_remove_acl_if;
	}
	port_priv->tx_qdid = dpsw_if_attr.qdid;

	return 0;

err_remove_acl_if:
	dpsw_acl_remove_if(ethsw->mc_io, 0, ethsw->dpsw_handle,
			   port_priv->acl_id, &acl_if_cfg);
err_remove_acl:
	dpsw_acl_remove(ethsw->mc_io, 0, ethsw->dpsw_handle,
			port_priv->acl_id);

	return err;
}

static void ethsw_unregister_notifier(struct device *dev)
{
	struct notifier_block *nb;
	int err;

	nb = &port_switchdev_blocking_nb;
	err = unregister_switchdev_blocking_notifier(nb);
	if (err)
		dev_err(dev,
			"Failed to unregister switchdev blocking notifier (%d)\n", err);

	err = unregister_switchdev_notifier(&port_switchdev_nb);
	if (err)
		dev_err(dev,
			"Failed to unregister switchdev notifier (%d)\n", err);

	err = unregister_netdevice_notifier(&port_nb);
	if (err)
		dev_err(dev,
			"Failed to unregister netdev notifier (%d)\n", err);
}

static void ethsw_takedown(struct fsl_mc_device *sw_dev)
{
	struct device *dev = &sw_dev->dev;
	struct ethsw_core *ethsw = dev_get_drvdata(dev);
	int err;

	ethsw_unregister_notifier(dev);

	err = dpsw_close(ethsw->mc_io, 0, ethsw->dpsw_handle);
	if (err)
		dev_warn(dev, "dpsw_close err %d\n", err);
}

static void ethsw_ctrl_if_teardown(struct ethsw_core *ethsw)
{
	dpsw_ctrl_if_disable(ethsw->mc_io, 0, ethsw->dpsw_handle);
	ethsw_free_dpio(ethsw);
	ethsw_destroy_rings(ethsw);
	ethsw_drain_bp(ethsw);
	ethsw_free_dpbp(ethsw);
}

static void ethsw_port_takedown(struct ethsw_port_priv *port_priv)
{
	struct dpsw_acl_if_cfg acl_if_cfg;

	acl_if_cfg.num_ifs = 1,
	acl_if_cfg.if_id[0] = port_priv->idx;
	dpsw_acl_remove_if(port_priv->ethsw_data->mc_io, 0,
			   port_priv->ethsw_data->dpsw_handle,
			   port_priv->acl_id, &acl_if_cfg);

	dpsw_acl_remove(port_priv->ethsw_data->mc_io, 0,
			port_priv->ethsw_data->dpsw_handle,
			port_priv->acl_id);
}

static int ethsw_remove(struct fsl_mc_device *sw_dev)
{
	struct ethsw_port_priv *port_priv;
	struct ethsw_core *ethsw;
	struct device *dev;
	int i;

	dev = &sw_dev->dev;
	ethsw = dev_get_drvdata(dev);

	if (ethsw_has_ctrl_if(ethsw))
		ethsw_ctrl_if_teardown(ethsw);

	ethsw_teardown_irqs(sw_dev);

	destroy_workqueue(ethsw_owq);

	dpsw_disable(ethsw->mc_io, 0, ethsw->dpsw_handle);

	for (i = 0; i < ethsw->sw_attr.num_ifs; i++) {
		port_priv = ethsw->ports[i];
		unregister_netdev(port_priv->netdev);
		ethsw_port_takedown(port_priv);
		free_netdev(port_priv->netdev);
	}
	kfree(ethsw->ports);

	ethsw_takedown(sw_dev);
	fsl_mc_portal_free(ethsw->mc_io);

	kfree(ethsw);

	dev_set_drvdata(dev, NULL);

	return 0;
}

static int ethsw_probe_port(struct ethsw_core *ethsw, u16 port_idx)
{
	struct ethsw_port_priv *port_priv;
	struct device *dev = ethsw->dev;
	struct net_device *port_netdev;
	int err;

	port_netdev = alloc_etherdev(sizeof(struct ethsw_port_priv));
	if (!port_netdev) {
		dev_err(dev, "alloc_etherdev error\n");
		return -ENOMEM;
	}

	port_priv = netdev_priv(port_netdev);
	port_priv->netdev = port_netdev;
	port_priv->ethsw_data = ethsw;

	port_priv->idx = port_idx;
	port_priv->stp_state = BR_STATE_FORWARDING;

	/* Flooding is implicitly enabled */
	port_priv->flood = true;

	SET_NETDEV_DEV(port_netdev, dev);
	port_netdev->netdev_ops = &ethsw_port_ops;
	port_netdev->ethtool_ops = &ethsw_port_ethtool_ops;

	/* Set MTU limits */
	port_netdev->min_mtu = ETH_MIN_MTU;
	port_netdev->max_mtu = ETHSW_MAX_FRAME_LENGTH;

	err = ethsw_port_init(port_priv, port_idx);
	if (err)
		goto err_port_probe;

	err = register_netdev(port_netdev);
	if (err < 0) {
		dev_err(dev, "register_netdev error %d\n", err);
		goto err_port_probe;
	}

	ethsw->ports[port_idx] = port_priv;

	return 0;

err_port_probe:
	free_netdev(port_netdev);

	return err;
}

static int ethsw_probe(struct fsl_mc_device *sw_dev)
{
	struct device *dev = &sw_dev->dev;
	struct ethsw_core *ethsw;
	int i, err;

	/* Allocate switch core*/
	ethsw = kzalloc(sizeof(*ethsw), GFP_KERNEL);

	if (!ethsw)
		return -ENOMEM;

	ethsw->dev = dev;
	ethsw->iommu_domain = iommu_get_domain_for_dev(dev);
	dev_set_drvdata(dev, ethsw);

	err = fsl_mc_portal_allocate(sw_dev, FSL_MC_IO_ATOMIC_CONTEXT_PORTAL,
				     &ethsw->mc_io);
	if (err) {
		if (err == -ENXIO)
			err = -EPROBE_DEFER;
		else
			dev_err(dev, "fsl_mc_portal_allocate err %d\n", err);
		goto err_free_drvdata;
	}

	err = ethsw_init(sw_dev);
	if (err)
		goto err_free_cmdport;

	/* DEFAULT_VLAN_ID is implicitly configured on the switch */
	ethsw->vlans[DEFAULT_VLAN_ID] = ETHSW_VLAN_MEMBER;

	/* Learning is implicitly enabled */
	ethsw->learning = true;

	ethsw->ports = kcalloc(ethsw->sw_attr.num_ifs, sizeof(*ethsw->ports),
			       GFP_KERNEL);
	if (!(ethsw->ports)) {
		err = -ENOMEM;
		goto err_takedown;
	}

	for (i = 0; i < ethsw->sw_attr.num_ifs; i++) {
		err = ethsw_probe_port(ethsw, i);
		if (err)
			goto err_free_ports;
	}

	if (ethsw_has_ctrl_if(ethsw)) {
		netif_napi_add(ethsw->ports[0]->netdev, &ethsw->fq[0].napi, ethsw_poll,
			       NAPI_POLL_WEIGHT);
		netif_napi_add(ethsw->ports[0]->netdev, &ethsw->fq[1].napi, ethsw_poll,
			       NAPI_POLL_WEIGHT);

	}

	err = dpsw_enable(ethsw->mc_io, 0, ethsw->dpsw_handle);
	if (err) {
		dev_err(ethsw->dev, "dpsw_enable err %d\n", err);
		goto err_free_ports;
	}

	/* Setup IRQs */
	err = ethsw_setup_irqs(sw_dev);
	if (err)
		goto err_stop;

	dev_info(dev, "probed %d port switch\n", ethsw->sw_attr.num_ifs);
	return 0;

err_stop:
	dpsw_disable(ethsw->mc_io, 0, ethsw->dpsw_handle);

err_free_ports:
	/* Cleanup registered ports only */
	for (i--; i >= 0; i--) {
		unregister_netdev(ethsw->ports[i]->netdev);
		free_netdev(ethsw->ports[i]->netdev);
	}
	kfree(ethsw->ports);

err_takedown:
	ethsw_takedown(sw_dev);

err_free_cmdport:
	fsl_mc_portal_free(ethsw->mc_io);

err_free_drvdata:
	kfree(ethsw);
	dev_set_drvdata(dev, NULL);

	return err;
}

static const struct fsl_mc_device_id ethsw_match_id_table[] = {
	{
		.vendor = FSL_MC_VENDOR_FREESCALE,
		.obj_type = "dpsw",
	},
	{ .vendor = 0x0 }
};
MODULE_DEVICE_TABLE(fslmc, ethsw_match_id_table);

static struct fsl_mc_driver eth_sw_drv = {
	.driver = {
		.name = KBUILD_MODNAME,
		.owner = THIS_MODULE,
	},
	.probe = ethsw_probe,
	.remove = ethsw_remove,
	.match_id_table = ethsw_match_id_table
};

module_fsl_mc_driver(eth_sw_drv);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("DPAA2 Ethernet Switch Driver");
