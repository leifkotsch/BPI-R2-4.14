/*
 * mtk-mmsys.c  --  Mediatek MMSYS multi-function driver
 *
 *  Copyright (c) 2017 Matthias Brugger <matthias.bgg@gmail.com>
 *
 * Author: Matthias Brugger <matthias.bgg@gmail.com>
 *
 * For licencing details see kernel-base/COPYING
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/mfd/core.h>
#include <linux/mfd/mmsys.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_device.h>
#include <linux/platform_device.h>
#include <linux/regmap.h>

enum {
	MMSYS_MT2701 = 1,
};

static const struct mfd_cell mmsys_mt2701_devs[] = {
	{ .name = "clk-mt2701-mm", },
	{ .name = "drm-mt2701-mm", },
};

static int mmsys_probe(struct platform_device *pdev)
{
	struct mmsys_dev *private;
	const struct mfd_cell *mmsys_cells;
	int nr_cells;
	long id;
	int ret;

	id = (long) of_device_get_match_data(&pdev->dev);
	if (!id) {
		dev_err(&pdev->dev, "of_device_get match_data() failed\n");
		return -EINVAL;
	}

	switch (id) {
	case MMSYS_MT2701:
		mmsys_cells = mmsys_mt2701_devs;
		nr_cells = ARRAY_SIZE(mmsys_mt2701_devs);
		break;
	default:
		return -ENODEV;
	}

	private = devm_kzalloc(&pdev->dev, sizeof(*private), GFP_KERNEL);
	if (!private)
		return -ENOMEM;

	private->dev = &pdev->dev;
	dev_set_drvdata(private->dev, private);

	private->of_node = pdev->dev.of_node;

	ret = devm_mfd_add_devices(private->dev, 0, mmsys_cells, nr_cells,
					NULL, 0, NULL);
	if (ret) {
		dev_err(&pdev->dev, "failed to add MFD devices %d\n", ret);
		return ret;
	}

	return 0;
};

static const struct of_device_id of_match_mmsys[] = {
	{ .compatible = "mediatek,mt2701-mmsys",
	  .data = (void *) MMSYS_MT2701,
	},
	{ /* sentinel */ },
};

static struct platform_driver mmsys_drv = {
	.probe = mmsys_probe,
	.driver = {
		.name = "mediatek-mmysys",
		.of_match_table = of_match_ptr(of_match_mmsys),
	},
};

builtin_platform_driver(mmsys_drv);

MODULE_DESCRIPTION("Mediatek MMSYS multi-function driver");
MODULE_LICENSE("GPL");
