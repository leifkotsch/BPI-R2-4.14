/*
 * mtk2701-irq.c  --  Mediatek 2701 audio driver irq function
 *
 * Copyright (c) 2016 MediaTek Inc.
 * Author: Garlic Tseng <garlic.tseng@mediatek.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_address.h>

#include "mtk2701-reg.h"
#include "mtk2701-afe-common.h"
#include "mtk2701-irq.h"

u32 mtk2701_asys_irq_status(struct mtk_afe *afe)
{
	u32 status = 0;

	regmap_read(afe->regmap, ASYS_IRQ_STATUS, &status);
	return status;
}

void mtk2701_asys_irq_clear(struct mtk_afe *afe, u32 status)
{
	regmap_write(afe->regmap, ASYS_IRQ_CLR, status);
}

void mtk2701_memif_isr(struct mtk_afe *afe, struct mtk_afe_memif *memif)
{
	if (memif) {
		u32 base, cur;

		mtk2701_afe_memif_base(afe, memif, &base);
		mtk2701_afe_memif_pointer(afe, memif, &cur);
		memif->hw_ptr = cur - base;
		snd_pcm_period_elapsed(memif->substream);
	}
}

int mtk2701_afe_memif_base(struct mtk_afe *afe, struct mtk_afe_memif *memif,
			   u32 *base)
{
	if (!memif || !memif->data) {
		dev_err(afe->dev, "%s() error: invalid memif %p\n",
			__func__, memif);
		return -EINVAL;
	}
	if (!base)
		return -ENOMEM;
	regmap_read(afe->regmap, memif->data->reg_ofs_base, base);
	return 0;
}

int mtk2701_afe_memif_pointer(struct mtk_afe *afe, struct mtk_afe_memif *memif,
			      u32 *cur_ptr)
{
	if (!memif || !memif->data) {
		dev_err(afe->dev, "%s() error: invalid memif %p\n",
			__func__, memif);
		return -EINVAL;
	}
	if (!cur_ptr)
		return -ENOMEM;
	regmap_read(afe->regmap, memif->data->reg_ofs_cur, cur_ptr);
	return 0;
}

static DEFINE_MUTEX(asys_irqs_lock);
int mtk2701_asys_irq_acquire(struct mtk_afe *afe)
{
	int i;

	mutex_lock(&asys_irqs_lock);
	for (i = IRQ_ASYS_START; i < IRQ_ASYS_END; ++i) {
		if (afe->irqs[i].irq_occupyed == 0) {
			afe->irqs[i].irq_occupyed = 1;
			mutex_unlock(&asys_irqs_lock);
			return i;
		}
	}
	mutex_unlock(&asys_irqs_lock);
	return IRQ_NUM;
}

int mtk2701_asys_irq_release(struct mtk_afe *afe, int irq_id)
{
	mutex_lock(&asys_irqs_lock);
	if (irq_id >= IRQ_ASYS_START && irq_id < IRQ_ASYS_END) {
		afe->irqs[irq_id].irq_occupyed = 0;
		mutex_unlock(&asys_irqs_lock);
		return 0;
	}
	mutex_unlock(&asys_irqs_lock);
	return -EINVAL;
}

MODULE_DESCRIPTION("MTK2701 irq control");
MODULE_AUTHOR("Garlic Tseng <garlic.tseng@mediatek.com>");
MODULE_LICENSE("GPL v2");
