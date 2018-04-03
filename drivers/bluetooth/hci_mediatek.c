// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2018 MediaTek Inc.

/*
 * Bluetooth HCI Serial driver for MediaTek SoC
 *
 * Author: Sean Wang <sean.wang@mediatek.com>
 *
 */

#include <linux/clk.h>
#include <linux/errno.h>
#include <linux/firmware.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/pm_runtime.h>
#include <linux/unaligned/le_struct.h>
#include <linux/serdev.h>
#include <linux/skbuff.h>
#include <linux/types.h>
#include <net/bluetooth/bluetooth.h>
#include <net/bluetooth/hci_core.h>

#include "hci_uart.h"

#define FIRMWARE_MT7622		"mediatek/mt7622_patch_firmware.bin"

#define MTK_STP_HDR_SIZE	4
#define MTK_STP_TLR_SIZE	2
#define MTK_WMT_HDR_SIZE	5
#define MTK_WMT_CMD_SIZE	(MTK_WMT_HDR_SIZE + MTK_STP_HDR_SIZE + \
				 MTK_STP_TLR_SIZE + HCI_ACL_HDR_SIZE)

enum {
	MTK_WMT_PATCH_DWNLD = 0x1,
	MTK_WMT_FUNC_CTRL = 0x6,
	MTK_WMT_RST = 0x7
};

struct mtk_stp_splitter {
	u8	pad[6];
	u8	cursor;
	u16	dlen;
};

struct mtk_bt_dev {
	struct hci_uart hu;
	struct clk *clk;
	struct sk_buff *rx_skb;
	struct sk_buff_head txq;
	struct completion wmt_cmd;
	struct mtk_stp_splitter *sp;
};

struct mtk_stp_hdr {
	__u8 prefix;
	__u8 dlen1:4;
	__u8 type:4;
	__u8 dlen2:8;
	__u8 cs;
} __packed;

struct mtk_wmt_hdr {
	__u8	dir;
	__u8	op;
	__le16	dlen;
	__u8	flag;
} __packed;

static void mtk_stp_reset(struct mtk_stp_splitter *sp)
{
	sp->cursor = 2;
	sp->dlen = 0;
}

static const unsigned char *
mtk_stp_split(struct device *dev, struct mtk_stp_splitter *sp,
	      const unsigned char *data, int count, int *sz_h4)
{
	struct mtk_stp_hdr *shdr;

	/* The cursor is reset when all the data of STP is being consumed. */
	if (!sp->dlen && sp->cursor >= 6)
		sp->cursor = 0;

	/* Filling pad until all STP info is obtained. */
	while (sp->cursor < 6 && count > 0) {
		sp->pad[sp->cursor] = *data;
		sp->cursor++;
		data++;
		count--;
	}

	/* Retrieve STP info and have a sanity check. */
	if (!sp->dlen && sp->cursor >= 6) {
		shdr = (struct mtk_stp_hdr *)&sp->pad[2];
		sp->dlen = shdr->dlen1 << 8 | shdr->dlen2;

		/* Resync STP when unexpected data is being read. */
		if (shdr->prefix != 0x80 || sp->dlen > 2048) {
			dev_err(dev, "stp format unexpect (%d, %d)",
				shdr->prefix, sp->dlen);
			mtk_stp_reset(sp);
		}
	}

	/* Directly leave when there's no data found for H4 can process. */
	if (count <= 0)
		return NULL;

	/* Tranlate to how much the size of data H4 can handle so far. */
	*sz_h4 = min_t(int, count, sp->dlen);
	/* Update remaining the size of STP packet. */
	sp->dlen -= *sz_h4;

	/* Data points to STP payload which can be handled by H4. */
	return data;
}

static void mtk_stp_hdr_build(struct mtk_stp_hdr *shdr, u8 type, u32 dlen)
{
	__u8 *p = (__u8 *)shdr;

	shdr->prefix = 0x80;
	shdr->dlen1 = (dlen & 0xf00) >> 8;
	shdr->type = type;
	shdr->dlen2 = dlen & 0xff;
	shdr->cs = (p[0] + p[1] + p[2]) & 0xff;
}

static int mtk_enqueue(struct hci_uart *hu, struct sk_buff *skb)
{
	struct mtk_bt_dev *btdev = hu->priv;
	struct mtk_stp_hdr *shdr;
	struct sk_buff *new_skb;
	int dlen;

	memcpy(skb_push(skb, 1), &hci_skb_pkt_type(skb), 1);
	dlen = skb->len;

	/* Make sure of STP header at least has 4-bytes free space to fill. */
	if (unlikely(skb_headroom(skb) < MTK_STP_HDR_SIZE)) {
		new_skb = skb_realloc_headroom(skb, MTK_STP_HDR_SIZE);
		kfree_skb(skb);
		skb = new_skb;
	}

	/* Build for STP packet format. */
	shdr = skb_push(skb, MTK_STP_HDR_SIZE);
	mtk_stp_hdr_build(shdr, 0, dlen);
	skb_put_zero(skb, MTK_STP_TLR_SIZE);

	skb_queue_tail(&btdev->txq, skb);

	return 0;
}

static int mtk_wmt_cmd_sync(struct hci_uart *hu, u8 opcode, u8 flag, u16 plen,
			    const void *param)
{
	struct mtk_bt_dev *btdev = hu->priv;
	struct hci_command_hdr *hhdr;
	struct hci_acl_hdr *ahdr;
	struct mtk_wmt_hdr *whdr;
	struct sk_buff *skb;
	int ret = 0;

	init_completion(&btdev->wmt_cmd);

	skb = bt_skb_alloc(plen + MTK_WMT_CMD_SIZE, GFP_KERNEL);
	if (!skb)
		return -ENOMEM;

	/*
	 * WMT data is carried in either ACL or HCI format with op code as
	 * 0xfc6f and followed by a WMT header and its actual payload.
	 */
	switch (opcode) {
	case MTK_WMT_PATCH_DWNLD:
		ahdr = skb_put(skb, HCI_ACL_HDR_SIZE);
		ahdr->handle = cpu_to_le16(0xfc6f);
		ahdr->dlen   = cpu_to_le16(plen + MTK_WMT_HDR_SIZE);
		break;
	default:
		hhdr = skb_put(skb, HCI_COMMAND_HDR_SIZE);
		hhdr->opcode = cpu_to_le16(0xfc6f);
		hhdr->plen = plen + MTK_WMT_HDR_SIZE;
		break;
	}

	hci_skb_pkt_type(skb) = opcode == MTK_WMT_PATCH_DWNLD ?
				HCI_ACLDATA_PKT : HCI_COMMAND_PKT;

	/* Start to build a WMT header and its actual payload. */
	whdr = skb_put(skb, MTK_WMT_HDR_SIZE);
	whdr->dir = 1;
	whdr->op = opcode;
	whdr->dlen = cpu_to_le16(plen + 1);
	whdr->flag = flag;
	skb_put_data(skb, param, plen);

	mtk_enqueue(hu, skb);
	hci_uart_tx_wakeup(hu);

	/*
	 * Waiting a WMT event response, while we must take care in case of
	 * failures for the wait.
	 */
	ret = wait_for_completion_interruptible_timeout(&btdev->wmt_cmd, HZ);

	return ret > 0 ? 0 : ret < 0 ? ret : -ETIMEDOUT;
}

static int mtk_setup_fw(struct hci_uart *hu)
{
	struct mtk_bt_dev *btdev = hu->priv;
	const struct firmware *fw;
	struct device *dev;
	const char *fwname;
	const u8 *fw_ptr;
	size_t fw_size;
	int err, dlen;
	u8 flag;

	dev = &hu->serdev->dev;
	fwname = FIRMWARE_MT7622;

	init_completion(&btdev->wmt_cmd);

	err = request_firmware(&fw, fwname, dev);
	if (err < 0) {
		dev_err(dev, "%s: Failed to load firmware file (%d)",
			hu->hdev->name, err);
		return err;
	}

	fw_ptr = fw->data;
	fw_size = fw->size;

	/* The size of a patch header at least has 30 bytes. */
	if (fw_size < 30)
		return -EINVAL;

	while (fw_size > 0) {
		dlen = min_t(int, 1000, fw_size);

		/* Tell deivice the position in sequence. */
		flag = (fw_size - dlen <= 0) ? 3 :
		       (fw_size < fw->size) ? 2 : 1;

		err = mtk_wmt_cmd_sync(hu, MTK_WMT_PATCH_DWNLD, flag,
				       dlen, fw_ptr);
		if (err < 0)
			break;

		fw_size -= dlen;
		fw_ptr += dlen;
	}

	release_firmware(fw);

	return err;
}

static int mtk_open(struct hci_uart *hu)
{
	struct mtk_bt_dev *btdev = hu->priv;
	struct device *dev;
	int err = 0;

	dev = &hu->serdev->dev;

	serdev_device_open(hu->serdev);
	skb_queue_head_init(&btdev->txq);

	/* Setup the usage of H4. */
	hu->alignment = 1;
	hu->padding = 0;
	mtk_stp_reset(btdev->sp);

	/* Enable the power domain and clock the device requires */
	pm_runtime_enable(dev);
	err = pm_runtime_get_sync(dev);
	if (err < 0) {
		pm_runtime_disable(dev);
		return err;
	}

	err = clk_prepare_enable(btdev->clk);
	if (err < 0) {
		pm_runtime_put_sync(dev);
		pm_runtime_disable(dev);
	}

	return err;
}

static int mtk_close(struct hci_uart *hu)
{
	struct mtk_bt_dev *btdev = hu->priv;
	struct device *dev = &hu->serdev->dev;
	u8 param = 0x0;

	skb_queue_purge(&btdev->txq);
	kfree_skb(btdev->rx_skb);

	/* Disable the device. */
	mtk_wmt_cmd_sync(hu, MTK_WMT_FUNC_CTRL, 0x0, sizeof(param), &param);

	/* Shutdown the clock and power domain the device requires. */
	clk_disable_unprepare(btdev->clk);

	pm_runtime_put_sync(dev);
	pm_runtime_disable(dev);

	serdev_device_close(hu->serdev);

	return 0;
}

int mtk_recv_frame(struct hci_dev *hdev, struct sk_buff *skb)
{
	struct hci_event_hdr *hdr = (void *)skb->data;
	struct hci_uart *hu = hci_get_drvdata(hdev);
	struct mtk_bt_dev *btdev = hu->priv;

	if (hci_skb_pkt_type(skb) == HCI_EVENT_PKT &&
	    hdr->evt == 0xe4) {
		complete(&btdev->wmt_cmd);
		kfree_skb(skb);
		return 0;
	}

	return hci_recv_frame(hdev, skb);
}

static const struct h4_recv_pkt mtk_recv_pkts[] = {
	{ H4_RECV_ACL,		.recv = mtk_recv_frame },
	{ H4_RECV_SCO,		.recv = mtk_recv_frame },
	{ H4_RECV_EVENT,	.recv = mtk_recv_frame },
};

static int mtk_recv(struct hci_uart *hu, const void *data, int count)
{
	const unsigned char *p_left = data, *p_h4;
	struct mtk_bt_dev *btdev = hu->priv;
	int sz_left = count, sz_h4, adv;
	struct device *dev;
	int err;

	if (!test_bit(HCI_UART_REGISTERED, &hu->flags))
		return -EUNATCH;

	dev = &hu->serdev->dev;

	while (sz_left > 0) {
		p_h4 = mtk_stp_split(dev, btdev->sp, p_left, sz_left, &sz_h4);
		if (!p_h4)
			break;

		adv = p_h4 - p_left;
		sz_left -= adv;
		p_left += adv;

		btdev->rx_skb = h4_recv_buf(hu->hdev, btdev->rx_skb,
					    p_h4, sz_h4, mtk_recv_pkts,
					    ARRAY_SIZE(mtk_recv_pkts));
		if (IS_ERR(btdev->rx_skb)) {
			err = PTR_ERR(btdev->rx_skb);
			dev_err(dev, "Frame reassembly failed (%d)", err);
			btdev->rx_skb = NULL;
			return err;
		}

		sz_left -= sz_h4;
		p_left += sz_h4;
	}

	return count;
}

static struct sk_buff *mtk_dequeue(struct hci_uart *hu)
{
	struct mtk_bt_dev *btdev = hu->priv;

	return skb_dequeue(&btdev->txq);
}

static int mtk_flush(struct hci_uart *hu)
{
	struct mtk_bt_dev *btdev = hu->priv;

	skb_queue_purge(&btdev->txq);

	return 0;
}

static int mtk_setup(struct hci_uart *hu)
{
	struct device *dev;
	u8 param = 0x1;
	int err;

	dev = &hu->serdev->dev;

	/* Setup a firmware which the device definitely requires. */
	err = mtk_setup_fw(hu);
	if (err < 0) {
		dev_err(dev, "Fail at setup FW (%d): %d", __LINE__, err);
		return err;
	}

	/* Activate funciton the firmware provides to. */
	err = mtk_wmt_cmd_sync(hu, MTK_WMT_RST, 0x4, 0, 0);
	if (err < 0) {
		dev_err(dev, "Fail at WMT RST (%d): %d", __LINE__, err);
		return err;
	}

	/* Enable Bluetooth protocol. */
	err = mtk_wmt_cmd_sync(hu, MTK_WMT_FUNC_CTRL, 0x0, sizeof(param),
			       &param);
	if (err < 0)
		dev_err(dev, "Fail at FUNC CTRL (%d): %d", __LINE__, err);

	return err;
}

static const struct hci_uart_proto mtk_proto = {
	.id		= HCI_UART_MTK,
	.name		= "MediaTek",
	.open		= mtk_open,
	.close		= mtk_close,
	.recv		= mtk_recv,
	.enqueue	= mtk_enqueue,
	.dequeue	= mtk_dequeue,
	.flush		= mtk_flush,
	.setup		= mtk_setup,
	.manufacturer	= 1,
};

static int mtk_bluetooth_serdev_probe(struct serdev_device *serdev)
{
	struct device *dev = &serdev->dev;
	struct mtk_bt_dev *btdev;
	int err = 0;

	btdev = devm_kzalloc(dev, sizeof(*btdev), GFP_KERNEL);
	if (!btdev)
		return -ENOMEM;

	btdev->sp = devm_kzalloc(dev, sizeof(*btdev->sp), GFP_KERNEL);
	if (!btdev->sp)
		return -ENOMEM;

	btdev->clk = devm_clk_get(dev, "ref");
	if (IS_ERR(btdev->clk))
		return PTR_ERR(btdev->clk);

	btdev->hu.serdev = serdev;
	btdev->hu.priv = btdev;

	serdev_device_set_drvdata(serdev, btdev);

	err = hci_uart_register_device(&btdev->hu, &mtk_proto);
	if (err)
		dev_err(dev, "Could not register bluetooth uart: %d", err);

	return err;
}

static void mtk_bluetooth_serdev_remove(struct serdev_device *serdev)
{
	struct mtk_bt_dev *btdev = serdev_device_get_drvdata(serdev);

	hci_uart_unregister_device(&btdev->hu);
}

static const struct of_device_id mtk_bluetooth_of_match[] = {
	{ .compatible = "mediatek,mt7622-bluetooth" },
	{},
};
MODULE_DEVICE_TABLE(of, mtk_bluetooth_of_match);

static struct serdev_device_driver mtk_bluetooth_serdev_driver = {
	.probe = mtk_bluetooth_serdev_probe,
	.remove = mtk_bluetooth_serdev_remove,
	.driver = {
		.name = "mediatek-bluetooth",
		.of_match_table = of_match_ptr(mtk_bluetooth_of_match),
	},
};

module_serdev_device_driver(mtk_bluetooth_serdev_driver);

MODULE_AUTHOR("Sean Wang <sean.wang@mediatek.com>");
MODULE_DESCRIPTION("Bluetooth HCI Serial driver for MediaTek SoC");
MODULE_LICENSE("GPL v2");
