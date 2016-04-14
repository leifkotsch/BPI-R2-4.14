/*
 * mtk2701-irq.h  --  Mediatek 2701 audio driver irq function definition
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

#ifndef _MTK_2701_IRQ_H_
#define _MTK_2701_IRQ_H_

u32 mtk2701_asys_irq_status(struct mtk_afe *afe);
void mtk2701_asys_irq_clear(struct mtk_afe *afe, u32 status);
void mtk2701_memif_isr(struct mtk_afe *afe, struct mtk_afe_memif *memif);
int mtk2701_afe_memif_base(struct mtk_afe *afe, struct mtk_afe_memif *memif,
			   u32 *base);
int mtk2701_afe_memif_pointer(struct mtk_afe *afe, struct mtk_afe_memif *memif,
			      u32 *cur_ptr);
int mtk2701_asys_irq_acquire(struct mtk_afe *afe);
int mtk2701_asys_irq_release(struct mtk_afe *afe, int irq_id);

#endif
