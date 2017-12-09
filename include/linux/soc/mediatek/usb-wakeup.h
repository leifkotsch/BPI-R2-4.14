/*
 * Copyright (c) 2017 MediaTek Inc.
 * Author: Chunfeng Yun <chunfeng.yun@mediatek.com>
 *
 * SPDX-License-Identifier: GPL-2.0
 *
 */

#ifndef __MTK_USB_WAKEUP_H__
#define __MTK_USB_WAKEUP_H__

#include <linux/device.h>
#include <linux/err.h>
#include <linux/mutex.h>
#include <linux/of.h>

struct mtu_wakeup;

/**
 * struct mtu_wakeup_ops - set of function pointers for performing
 *    mtu_wakeup operations
 * @enable: enable a type of usb wakeup when system suspend
 * @disable: disable a type of usb wakeup when system resume
 * @owner: the module owner using the ops
 */
struct mtu_wakeup_ops {
	int	(*enable)(struct mtu_wakeup *uwk);
	int	(*disable)(struct mtu_wakeup *uwk);
	struct module *owner;
};

/**
 * struct mtu_wakeup - represents the MediaTek USB wakeup device
 * @parent: the parent device of the mtu_wakeup
 * @node: associated device tree node
 * @ops: function pointers for performing mtu_wakeup operations
 * @mutex: mutex to protect @ops
 * @count: used to protect when the mtu_wakeup is used by multiple consumers
 */
struct mtu_wakeup {
	struct device *parent;
	struct device_node *node;
	const struct mtu_wakeup_ops *ops;
	struct mutex mutex;
	int count;
};

/**
 * struct mtu_wakeup_provider - represents the mtu_wakeup provider
 * @dev: the parent device of the mtu_wakeup
 * @list: to maintain a linked list of mtu_wakeup providers
 * @of_node: associated device tree node
 * @of_xlate: function pointer to obtain mtu_wakeup instance from
 *	its tree node
 */
struct mtu_wakeup_provider {
	struct device *dev;
	struct list_head list;
	struct device_node *of_node;
	struct mtu_wakeup *(*of_xlate)(struct device *dev,
		struct of_phandle_args *args);
};

#if IS_ENABLED(CONFIG_MTK_UWK)
struct mtu_wakeup *devm_of_uwk_get_by_index(
	struct device *dev, struct device_node *np, int index);
int mtu_wakeup_enable(struct mtu_wakeup *uwk);
int mtu_wakeup_disable(struct mtu_wakeup *uwk);

#else
struct mtu_wakeup *devm_of_uwk_get_by_index(
	struct device *dev, struct device_node *np, int index)
{
	return ERR_PTR(-ENODEV);
}

int mtu_wakeup_enable(struct mtu_wakeup *uwk)
{
	return uwk ? -ENODEV : 0;
}

int mtu_wakeup_disable(struct mtu_wakeup *uwk)
{
	return uwk ? -ENODEV : 0;
}
#endif

#endif	/* __MTK_USB_WAKEUP_H__ */
