// SPDX-License-Identifier: GPL-2.0
/*
 * carplay.c - carplay usb driver
 *
 * Copyright (C) 2018 MediaTek Inc.
 *
 * Author: Chunfeng Yun <chunfeng.yun@mediatek.com>
 *
 */

#include <linux/debugfs.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/usb.h>

/*
 * usage:
 * The requirement for the platform using Carplay feature is that support
 * the USB Dual Role Switch feature, and must have a USB-A receptacle
 * that is capable of functioning in both USB Host and USB Device roles.
 *
 * 1. Apple iphone is enumerated as a usb device
 * 2. switch Apple iphone to host mode, by, e.g.
 *    echo host > /sys/kernel/debug/usb/carplay.1-1/mode
 * 3. switch the platform to device mode, but meanwhile should keep vbus alive;
 * 4. use carplay feature after the platform is enumerated as a usb device;
 * 5. when unplug usb cable, switch the platform back to host mode.
 *
 * step 2 is supported by this driver;
 * step 1, 3, 4, 5 should be supported by the USB Dual-Role Controller Driver
 *    on the platform.
 *
 * For more detailed information, please refer to "Chapter 46. USB Role Switch"
 * in MFI Accessroy Interface Specification.pdf
 */

#define CARPLAY_NAME "carplay"
#define VENDER_REQ_DEV_TO_HOST 0x51

struct usb_carplay {
	struct usb_interface *intf;
	struct usb_device *udev;
	struct dentry *droot;
	struct device *idev;
	bool is_host;
};

static int carplay_switch_to_host(struct usb_carplay *ucp)
{
	struct usb_device *udev = ucp->udev;
	int retval;

	if (!ucp->udev)
		return -ENODEV;

	retval = usb_control_msg(udev, usb_rcvctrlpipe(udev, 0),
			VENDER_REQ_DEV_TO_HOST, USB_TYPE_VENDOR,
			1, 0, NULL, 0, USB_CTRL_GET_TIMEOUT);

	dev_dbg(ucp->idev, "%s retval = %d\n", __func__, retval);

	if (retval != 0) {
		dev_err(ucp->idev, "%s fail retval = %d\n", __func__, retval);
		return retval;
	}
	ucp->is_host = true;

	return 0;
}

static int carplay_mode_show(struct seq_file *sf, void *unused)
{
	struct usb_carplay *ucp = sf->private;

	seq_printf(sf, "current mode: %s\n(usage: echo host > mode)\n",
		ucp->is_host ? "host" : "device");

	return 0;
}

static int carplay_mode_open(struct inode *inode, struct file *file)
{
	return single_open(file, carplay_mode_show, inode->i_private);
}

static ssize_t carplay_mode_write(struct file *file,
	const char __user *ubuf, size_t count, loff_t *ppos)
{
	struct seq_file *sf = file->private_data;
	struct usb_carplay *ucp = sf->private;
	char buf[16];

	if (copy_from_user(&buf, ubuf, min_t(size_t, sizeof(buf) - 1, count)))
		return -EFAULT;

	if (!strncmp(buf, "host", 4) && !ucp->is_host) {
		carplay_switch_to_host(ucp);
	} else {
		dev_err(ucp->idev, "wrong setting\n");
		return -EINVAL;
	}

	return count;
}

static const struct file_operations carplay_mode_fops = {
	.open = carplay_mode_open,
	.write = carplay_mode_write,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static struct dentry *carplay_debugfs_init(struct usb_carplay *ucp)
{
	struct dentry *root;
	const char *udev_name = dev_name(&ucp->udev->dev);
	char name[16];

	snprintf(name, sizeof(name), "%s.%s", CARPLAY_NAME, udev_name);
	root = debugfs_create_dir(name, usb_debug_root);
	if (!root) {
		dev_err(ucp->idev, "create debugfs root failed\n");
		return root;
	}
	ucp->droot = root;

	return debugfs_create_file("mode", 0664, root, ucp,
			&carplay_mode_fops);
}

static void carplay_debugfs_exit(struct usb_carplay *ucp)
{
	debugfs_remove_recursive(ucp->droot);
}

static int carplay_probe(struct usb_interface *intf,
	const struct usb_device_id *id)
{
	struct usb_device *udev;
	struct usb_carplay *ucp;
	struct dentry *de;

	udev = interface_to_usbdev(intf);

	ucp = kzalloc(sizeof(*ucp), GFP_KERNEL);
	if (!ucp)
		return -ENOMEM;

	ucp->udev = usb_get_dev(udev);
	ucp->intf = intf;
	ucp->idev = &intf->dev;
	usb_set_intfdata(intf, ucp);
	ucp->is_host = false;

	de = carplay_debugfs_init(ucp);
	if (IS_ERR_OR_NULL(de)) {
		usb_set_intfdata(intf, NULL);
		usb_put_dev(ucp->udev);
		kfree(ucp);
		return -ENOMEM;
	}

	dev_info(ucp->idev, "carplay attached\n");
	return 0;
}

static void carplay_disconnect(struct usb_interface *intf)
{
	struct usb_carplay *ucp = usb_get_intfdata(intf);

	usb_set_intfdata(intf, NULL);
	usb_put_dev(ucp->udev);
	carplay_debugfs_exit(ucp);
	kfree(ucp);
	dev_info(&intf->dev, "carplay disconnected\n");
}

static const struct usb_device_id carplay_id_table[] = {
	/* generic EZ-USB FX2 controller (or development board) */
	{ USB_DEVICE(0x05ac, 0x12a8) },
	{}
};

MODULE_DEVICE_TABLE(usb, carplay_id_table);

static struct usb_driver carplay_driver = {
	.name = CARPLAY_NAME,
	.id_table = carplay_id_table,
	.probe = carplay_probe,
	.disconnect = carplay_disconnect,
};

module_usb_driver(carplay_driver);

MODULE_AUTHOR("Chunfeng Yun <chunfeng.yun@mediatek.com>");
MODULE_DESCRIPTION("USB Carplay Driver");
MODULE_LICENSE("GPL");
