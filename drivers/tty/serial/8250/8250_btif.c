/*
 * Driver for MediaTek BTIF Controller
 *
 * Copyright (C) 2017 Sean Wang <sean.wang@mediatek.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#include <linux/clk.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/of_irq.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>
#include <linux/pm_runtime.h>
#include <linux/serial_8250.h>
#include <linux/serial_reg.h>

#include "8250.h"

#define MTK_BTIF_TRI_LVL	0x60
#define BTIF_LOOP		BIT(7)

struct mtk_btif_data {
	int			line;
	struct clk		*main_clk;
};

static void
mtk_btif_do_pm(struct uart_port *port, unsigned int state, unsigned int old)
{
	if (!state)
		pm_runtime_get_sync(port->dev);

	serial8250_do_pm(port, state, old);

	if (state)
		pm_runtime_put_sync_suspend(port->dev);
}

static int mtk_btif_probe_of(struct platform_device *pdev, struct uart_port *p,
			     struct mtk_btif_data *data)
{
	int err;

	data->main_clk = devm_clk_get(&pdev->dev, "main");
	if (IS_ERR(data->main_clk)) {
		dev_warn(&pdev->dev, "Can't get main clock\n");
		return PTR_ERR(data->main_clk);
	}

	err = clk_prepare_enable(data->main_clk);
	if (err) {
		dev_warn(&pdev->dev, "Can't prepare main_clk\n");
		clk_put(data->main_clk);
		return err;
	}

	p->uartclk = clk_get_rate(data->main_clk);

	return 0;
}

static int mtk_btif_runtime_suspend(struct device *dev)
{
	struct mtk_btif_data *data = dev_get_drvdata(dev);

	clk_disable_unprepare(data->main_clk);

	return 0;
}

static int mtk_btif_runtime_resume(struct device *dev)
{
	struct mtk_btif_data *data = dev_get_drvdata(dev);
	int err;

	err = clk_prepare_enable(data->main_clk);
	if (err) {
		dev_warn(dev, "Can't enable main clock\n");
		return err;
	}

	return 0;
}

static int mtk_btif_probe(struct platform_device *pdev)
{
	struct uart_8250_port uart = {};
	struct resource *regs = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	struct resource *irq = platform_get_resource(pdev, IORESOURCE_IRQ, 0);
	struct mtk_btif_data *data;
	int err;
	u32 tmp;

	if (!regs || !irq) {
		dev_err(&pdev->dev, "no registers/irq defined\n");
		return -EINVAL;
	}

	uart.port.membase = devm_ioremap(&pdev->dev, regs->start,
					 resource_size(regs));
	if (!uart.port.membase)
		return -ENOMEM;

	data = devm_kzalloc(&pdev->dev, sizeof(*data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	if (pdev->dev.of_node) {
		err = mtk_btif_probe_of(pdev, &uart.port, data);
		if (err)
			return err;
	} else {
		return -ENODEV;
	}

	spin_lock_init(&uart.port.lock);
	uart.port.mapbase = regs->start;
	uart.port.irq = irq->start;
	uart.port.pm = mtk_btif_do_pm;
	uart.port.type = PORT_8250;
	uart.port.flags = UPF_FIXED_TYPE;
	uart.port.dev = &pdev->dev;
	uart.port.iotype = UPIO_MEM32;
	uart.port.regshift = 2;
	uart.port.private_data = data;

	platform_set_drvdata(pdev, data);

	pm_runtime_enable(&pdev->dev);

	if (!pm_runtime_enabled(&pdev->dev)) {
		err = mtk_btif_runtime_resume(&pdev->dev);
		if (err)
			return err;
	}

	if (of_property_read_bool(pdev->dev.of_node, "mediatek,loopback")) {
		dev_info(&pdev->dev, "btif is entering loopback mode\n");
		tmp = readl(uart.port.membase + MTK_BTIF_TRI_LVL);
		tmp |= BTIF_LOOP;
		writel(tmp, uart.port.membase + MTK_BTIF_TRI_LVL);
	}

	data->line = serial8250_register_8250_port(&uart);
	if (data->line < 0)
		return data->line;

	return 0;
}

static int mtk_btif_remove(struct platform_device *pdev)
{
	struct mtk_btif_data *data = platform_get_drvdata(pdev);

	pm_runtime_get_sync(&pdev->dev);

	serial8250_unregister_port(data->line);

	pm_runtime_disable(&pdev->dev);
	pm_runtime_put_noidle(&pdev->dev);

	if (!pm_runtime_status_suspended(&pdev->dev))
		mtk_btif_runtime_suspend(&pdev->dev);

	return 0;
}

#ifdef CONFIG_PM_SLEEP
static int mtk_btif_suspend(struct device *dev)
{
	struct mtk_btif_data *data = dev_get_drvdata(dev);

	serial8250_suspend_port(data->line);

	return 0;
}

static int mtk_btif_resume(struct device *dev)
{
	struct mtk_btif_data *data = dev_get_drvdata(dev);

	serial8250_resume_port(data->line);

	return 0;
}
#endif /* CONFIG_PM_SLEEP */

static const struct dev_pm_ops mtk_btif_pm_ops = {
	SET_SYSTEM_SLEEP_PM_OPS(mtk_btif_suspend, mtk_btif_resume)
	SET_RUNTIME_PM_OPS(mtk_btif_runtime_suspend, mtk_btif_runtime_resume,
			   NULL)
};

static const struct of_device_id mtk_btif_of_match[] = {
	{ .compatible = "mediatek,mt7622-btif" },
	{ .compatible = "mediatek,mt7623-btif" },
	{ /* Sentinel */ }
};
MODULE_DEVICE_TABLE(of, mtk_btif_of_match);

static struct platform_driver mtk_btif_platform_driver = {
	.driver = {
		.name		= "mediatek-btif",
		.pm		= &mtk_btif_pm_ops,
		.of_match_table	= mtk_btif_of_match,
	},
	.probe			= mtk_btif_probe,
	.remove			= mtk_btif_remove,
};
module_platform_driver(mtk_btif_platform_driver);

MODULE_AUTHOR("Sean Wang <sean.wang@mediatek.com>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("MediaTek BTIF controller driver");
