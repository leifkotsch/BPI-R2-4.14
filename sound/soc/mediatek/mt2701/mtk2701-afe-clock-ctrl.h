/*
 * mtk2701-afe-clock-ctrl.h  --  Mediatek 2701 afe clock ctrl definition
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

#ifndef _MTK2701_AFE_CLOCK_CTRL_H_
#define _MTK2701_AFE_CLOCK_CTRL_H_

void mtk2701_afe_enable_clock(struct mtk_afe *afe, int en);
void mtk2701_turn_on_a1sys_clock(struct mtk_afe *afe);
void mtk2701_turn_off_a1sys_clock(struct mtk_afe *afe);
void mtk2701_turn_on_a2sys_clock(struct mtk_afe *afe);
void mtk2701_turn_off_a2sys_clock(struct mtk_afe *afe);
void mtk2701_turn_on_afe_clock(struct mtk_afe *afe);
void mtk2701_turn_off_afe_clock(struct mtk_afe *afe);

#endif
