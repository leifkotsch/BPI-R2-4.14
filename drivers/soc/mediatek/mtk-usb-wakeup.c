/*
 * Copyright (c) 2017 MediaTek Inc.
 * Author: Chunfeng Yun <chunfeng.yun@mediatek.com>
 *
 * SPDX-License-Identifier: GPL-2.0
 *
 */

#include <dt-bindings/soc/mediatek,usb-wakeup.h>
#include <linux/kernel.h>
#include <linux/mfd/syscon.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_platform.h>
#include <linux/regmap.h>
#include <linux/slab.h>
#include <linux/soc/mediatek/usb-wakeup.h>

/* mt8173, mt8176 etc */
#define PERI_WK_CTRL1	0x4
#define WC1_IS_C(x)	(((x) & 0xf) << 26) /* cycle debounce */
#define WC1_IS_EN	BIT(25)
#define WC1_IS_P	BIT(6)  /* polarity for ip sleep */

/* mt2712 etc */
#define PERI_SSUSB_SPM_CTRL	0x0
#define SSC_LINE_STATE_CHG	GENMASK(11, 8)
#define SSC_LINE_STATE_EN	GENMASK(6, 5)
#define SSC_IP_SLEEP_EN	BIT(4)
#define SSC_SPM_INT_EN		BIT(1)

enum mtk_uwk_vers {
	MTK_UWK_V1 = 1,
	MTK_UWK_V2,
};

struct mtk_uwk_pdata {
	enum mtk_uwk_vers vers;
};

/**
 * @reg_base: register offset within a syscon @wkc (e.g. pericfg module)
 * @type: the types of wakeup, such as IP-SLEEP, LINE-STATE etc
 */
struct mtk_uwk_instance {
	struct mtu_wakeup uwk;
	u32 reg_base;
	u32 reg_len;
	u32 type;
};

struct mtk_uwk {
	struct device *dev;
	struct regmap *wkc;
	const struct mtk_uwk_pdata *data;
	struct mtk_uwk_instance **inst;
	int num_inst;
};

static LIST_HEAD(of_uwk_providers);
static DEFINE_MUTEX(of_uwk_mutex);

static struct mtu_wakeup_provider *of_uwk_provider_add(struct device *dev,
		struct mtu_wakeup *(*of_xlate)(struct device *dev,
		struct of_phandle_args *args))
{
	struct mtu_wakeup_provider *provider;

	provider = kzalloc(sizeof(*provider), GFP_KERNEL);
	if (!provider)
		return ERR_PTR(-ENOMEM);

	provider->dev = dev;
	provider->of_node = of_node_get(dev->of_node);
	provider->of_xlate = of_xlate;

	mutex_lock(&of_uwk_mutex);
	list_add_tail(&provider->list, &of_uwk_providers);
	mutex_unlock(&of_uwk_mutex);

	return provider;
}

static void of_uwk_provider_del(struct device_node *np)
{
	struct mtu_wakeup_provider *provider;

	mutex_lock(&of_uwk_mutex);
	list_for_each_entry(provider, &of_uwk_providers, list) {
		if (provider->of_node == np) {
			list_del(&provider->list);
			of_node_put(provider->of_node);
			kfree(provider);
			break;
		}
	}
	mutex_unlock(&of_uwk_mutex);
}

static struct mtu_wakeup *of_uwk_get_from_provider(
		struct of_phandle_args *args)
{
	struct mtu_wakeup_provider *provider;
	struct device_node *child_np;
	struct mtu_wakeup *uwk;

	mutex_lock(&of_uwk_mutex);
	list_for_each_entry(provider, &of_uwk_providers, list) {
		for_each_child_of_node(provider->of_node, child_np) {
			if (child_np == args->np) {
				uwk = provider->of_xlate(provider->dev, args);
				mutex_unlock(&of_uwk_mutex);
				return uwk;
			}
		}
	}
	mutex_unlock(&of_uwk_mutex);

	return ERR_PTR(-EPROBE_DEFER);
}

static struct mtu_wakeup *of_uwk_get(struct device_node *np, int index)
{
	struct mtu_wakeup *uwk = NULL;
	struct of_phandle_args args;
	int ret;

	ret = of_parse_phandle_with_args(np, "mediatek,uwks",
				"#mediatek,uwk-cells", index, &args);
	if (ret)
		return ERR_PTR(-ENODEV);

	if (!of_device_is_available(args.np)) {
		dev_warn(uwk->parent, "Requested uwk is disabled\n");
		uwk = ERR_PTR(-ENODEV);
		goto put_node;
	}

	uwk = of_uwk_get_from_provider(&args);

put_node:
	of_node_put(args.np);
	return uwk;
}

static void devm_uwk_release(struct device *dev, void *res)
{
	struct mtu_wakeup *uwk = *(struct mtu_wakeup **)res;

	if (IS_ERR_OR_NULL(uwk))
		return;

	module_put(uwk->ops->owner);
	put_device(uwk->parent);
}

struct mtu_wakeup *devm_of_uwk_get_by_index(
		struct device *dev, struct device_node *np, int index)
{
	struct mtu_wakeup **ptr, *uwk;

	ptr = devres_alloc(devm_uwk_release, sizeof(*ptr), GFP_KERNEL);
	if (!ptr)
		return ERR_PTR(-ENOMEM);

	uwk = of_uwk_get(np, index);
	if (IS_ERR(uwk)) {
		devres_free(ptr);
		return uwk;
	}

	if (!try_module_get(uwk->ops->owner)) {
		devres_free(ptr);
		return ERR_PTR(-EPROBE_DEFER);
	}

	get_device(uwk->parent);

	*ptr = uwk;
	devres_add(dev, ptr);

	return uwk;
}
EXPORT_SYMBOL_GPL(devm_of_uwk_get_by_index);

int mtu_wakeup_enable(struct mtu_wakeup *uwk)
{
	int ret = 0;

	if (!uwk)
		return 0;

	mutex_lock(&uwk->mutex);
	if (uwk->count == 0 && uwk->ops->enable) {
		ret = uwk->ops->enable(uwk);
		if (ret) {
			dev_err(uwk->parent, "uwk enable failed(%d)\n", ret);
			goto out;
		}
	}
	++uwk->count;

out:
	mutex_unlock(&uwk->mutex);
	return ret;
}
EXPORT_SYMBOL_GPL(mtu_wakeup_enable);

int mtu_wakeup_disable(struct mtu_wakeup *uwk)
{
	int ret = 0;

	if (!uwk)
		return 0;

	mutex_lock(&uwk->mutex);
	if (uwk->count == 1 && uwk->ops->disable) {
		ret =  uwk->ops->disable(uwk);
		if (ret) {
			dev_err(uwk->parent, "uwk disable failed(%d)\n", ret);
			goto out;
		}
	}
	--uwk->count;

out:
	mutex_unlock(&uwk->mutex);
	return ret;
}
EXPORT_SYMBOL_GPL(mtu_wakeup_disable);

static struct mtk_uwk_instance *to_mwk_inst(struct mtu_wakeup *uwk)
{
	return uwk ? container_of(uwk, struct mtk_uwk_instance, uwk) : NULL;
}

static int mwk_v1_enable(struct mtk_uwk *mwk, struct mtk_uwk_instance *inst)
{
	struct regmap *wkc = mwk->wkc;
	u32 val;

	/* Only IP-SLEEP is supported */
	if (inst->type != MTU_WK_IP_SLEEP)
		return 0;

	regmap_read(wkc, PERI_WK_CTRL1, &val);
	val &= ~(WC1_IS_P | WC1_IS_C(0xf));
	val |= WC1_IS_EN | WC1_IS_C(0x8);
	regmap_write(wkc, PERI_WK_CTRL1, val);
	regmap_read(wkc, PERI_WK_CTRL1, &val);
	dev_dbg(mwk->dev, "%s: WK_CTRL1=%#x, type=%d\n",
		__func__, val, inst->type);

	return 0;
}

static int mwk_v1_disable(struct mtk_uwk *mwk, struct mtk_uwk_instance *inst)
{
	if (inst->type == MTU_WK_IP_SLEEP)
		regmap_update_bits(mwk->wkc, PERI_WK_CTRL1, WC1_IS_EN, 0);

	return 0;
}

static int mwk_v2_enable(struct mtk_uwk *mwk, struct mtk_uwk_instance *inst)
{
	struct regmap *wkc = mwk->wkc;
	u32 rbase = inst->reg_base;
	u32 val;

	regmap_read(wkc, rbase + PERI_SSUSB_SPM_CTRL, &val);
	switch (inst->type) {
	case MTU_WK_IP_SLEEP:
		val |= SSC_IP_SLEEP_EN;
		break;
	case MTU_WK_LINE_STATE:
		val |= SSC_LINE_STATE_EN | SSC_LINE_STATE_CHG;
		break;
	default:
		/* checked by xlate, ignore the error */
		break;
	}
	val |= SSC_SPM_INT_EN;
	regmap_write(wkc, rbase + PERI_SSUSB_SPM_CTRL, val);
	regmap_read(wkc, rbase + PERI_SSUSB_SPM_CTRL, &val);
	dev_dbg(mwk->dev, "%s: CTRL=%#x, type=%d\n",
		__func__, val, inst->type);

	return 0;
}

static int mwk_v2_disable(struct mtk_uwk *mwk, struct mtk_uwk_instance *inst)
{
	struct regmap *wkc = mwk->wkc;
	u32 rbase = inst->reg_base;
	u32 val;

	regmap_read(wkc, rbase + PERI_SSUSB_SPM_CTRL, &val);
	switch (inst->type) {
	case MTU_WK_IP_SLEEP:
		val &= ~SSC_IP_SLEEP_EN;
		break;
	case MTU_WK_LINE_STATE:
		val &= ~(SSC_LINE_STATE_EN | SSC_LINE_STATE_CHG);
		break;
	default:
		break;
	}
	val &= ~SSC_SPM_INT_EN;
	regmap_write(wkc, rbase + PERI_SSUSB_SPM_CTRL, val);
	dev_dbg(mwk->dev, "%s: type=%d\n", __func__, inst->type);

	return 0;
}

static int mwk_enable(struct mtu_wakeup *uwk)
{
	struct mtk_uwk_instance *inst = to_mwk_inst(uwk);
	struct mtk_uwk *mwk = dev_get_drvdata(uwk->parent);
	int ret = 0;

	switch (mwk->data->vers) {
	case MTK_UWK_V1:
		ret = mwk_v1_enable(mwk, inst);
		break;
	case MTK_UWK_V2:
		ret = mwk_v2_enable(mwk, inst);
		break;
	default:
		break;
	}
	return ret;
}

static int mwk_disable(struct mtu_wakeup *uwk)
{
	struct mtk_uwk_instance *inst = to_mwk_inst(uwk);
	struct mtk_uwk *mwk = dev_get_drvdata(uwk->parent);
	int ret = 0;

	switch (mwk->data->vers) {
	case MTK_UWK_V1:
		ret = mwk_v1_disable(mwk, inst);
		break;
	case MTK_UWK_V2:
		ret = mwk_v2_disable(mwk, inst);
		break;
	default:
		break;
	}
	return ret;
}

static struct mtk_uwk_instance *mwk_inst_create(struct device *dev,
		struct device_node *np,
		const struct mtu_wakeup_ops *ops)
{
	struct mtk_uwk_instance *inst;
	struct mtu_wakeup *uwk;
	u32 buf[2];
	int ret;

	inst = devm_kzalloc(dev, sizeof(*inst), GFP_KERNEL);
	if (!inst)
		return ERR_PTR(-ENOMEM);

	ret = of_property_read_u32_array(np, "reg", buf, ARRAY_SIZE(buf));
	if (ret) {
		dev_err(dev, "fail to read reg\n");
		return ERR_PTR(ret);
	}

	inst->reg_base = buf[0];
	inst->reg_len = buf[1];
	uwk = &inst->uwk;
	uwk->node = np;
	uwk->ops = ops;
	uwk->parent = dev;
	mutex_init(&uwk->mutex);
	dev_dbg(dev, "reg: %#x/%#x\n", inst->reg_base, inst->reg_len);

	return inst;
}

static struct mtu_wakeup *mwk_xlate(struct device *dev,
		struct of_phandle_args *args)
{
	struct mtk_uwk *mwk = dev_get_drvdata(dev);
	struct mtk_uwk_instance *inst = NULL;
	struct device_node *uwk_np = args->np;
	int index;

	if (args->args_count != 1) {
		dev_err(dev, "invalid number of cells in uwk property\n");
		return ERR_PTR(-EINVAL);
	}

	for (index = 0; index < mwk->num_inst; index++)
		if (uwk_np == mwk->inst[index]->uwk.node) {
			inst = mwk->inst[index];
			break;
		}

	if (!inst) {
		dev_err(dev, "failed to find appropriate uwk\n");
		return ERR_PTR(-EINVAL);
	}

	inst->type = args->args[0];
	if (!(inst->type == MTU_WK_IP_SLEEP ||
	      inst->type == MTU_WK_LINE_STATE)) {
		dev_err(dev, "unsupported uwk type=%d\n", inst->type);
		return ERR_PTR(-EINVAL);
	}

	return &inst->uwk;
}

static const struct mtu_wakeup_ops mwk_ops = {
	.enable = mwk_enable,
	.disable = mwk_disable,
	.owner = THIS_MODULE,
};

static const struct mtk_uwk_pdata mwk_v1_pdata = {
	.vers = MTK_UWK_V1,
};

static const struct mtk_uwk_pdata mwk_v2_pdata = {
	.vers = MTK_UWK_V2,
};

static const struct of_device_id mwk_id_table[] = {
	{ .compatible = "mediatek,usb-wk-v1", .data = &mwk_v1_pdata },
	{ .compatible = "mediatek,usb-wk-v2", .data = &mwk_v2_pdata },
	{ },
};
MODULE_DEVICE_TABLE(of, mwk_id_table);

static int mtk_uwk_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct device_node *np = dev->of_node;
	struct device_node *child_np;
	struct mtu_wakeup_provider *provider;
	struct mtk_uwk *mwk;
	int index;
	int ret;

	mwk = devm_kzalloc(dev, sizeof(*mwk), GFP_KERNEL);
	if (!mwk)
		return -ENOMEM;

	mwk->data = of_device_get_match_data(dev);
	if (!mwk->data)
		return -EINVAL;

	mwk->num_inst = of_get_child_count(np);
	mwk->inst = devm_kcalloc(dev, mwk->num_inst,
				  sizeof(*mwk->inst), GFP_KERNEL);
	if (!mwk->inst)
		return -ENOMEM;

	mwk->dev = dev;
	platform_set_drvdata(pdev, mwk);

	mwk->wkc = syscon_regmap_lookup_by_phandle(np, "mediatek,wkc");
	if (IS_ERR(mwk->wkc)) {
		dev_err(dev, "fail to get mediatek,wkc syscon\n");
		return PTR_ERR(mwk->wkc);
	}

	index = 0;
	for_each_child_of_node(np, child_np) {
		struct mtk_uwk_instance *inst;

		inst = mwk_inst_create(dev, child_np, &mwk_ops);
		if (IS_ERR(inst)) {
			dev_err(dev, "failed to create mwk instance\n");
			ret = PTR_ERR(inst);
			goto put_child;
		}

		mwk->inst[index] = inst;
		index++;
	}

	provider = of_uwk_provider_add(dev, mwk_xlate);

	return PTR_ERR_OR_ZERO(provider);

put_child:
	of_node_put(child_np);
	return ret;
}

static int mtk_uwk_remove(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct device_node *np = dev->of_node;

	of_uwk_provider_del(np);
	return 0;
}

static struct platform_driver mtk_uwk_drv = {
	.probe = mtk_uwk_probe,
	.remove = mtk_uwk_remove,
	.driver = {
		.name = "mtk_uwk",
		.owner = THIS_MODULE,
		.of_match_table = mwk_id_table,
	},
};

module_platform_driver(mtk_uwk_drv);
MODULE_AUTHOR("Chunfeng Yun <chunfeng.yun@mediatek.com>");
MODULE_DESCRIPTION("MediaTek USB Wakeup driver");
MODULE_LICENSE("GPL v2");
