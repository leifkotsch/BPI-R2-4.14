/*
 * mtk2701-afe-clock-ctrl.c  --  Mediatek 2701 afe clock ctrl
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

#include <sound/soc.h>
#include <linux/regmap.h>
#include <linux/pm_runtime.h>

#include "mtk2701-reg.h"
#include "mtk2701-afe-common.h"
#include "mtk2701-afe-clock-ctrl.h"

void mtk2701_afe_enable_clock(struct mtk_afe *afe, int en)
{
	if (en) {
		mtk2701_turn_on_a1sys_clock(afe);
		mtk2701_turn_on_a2sys_clock(afe);
		mtk2701_turn_on_afe_clock(afe);
		regmap_update_bits(afe->regmap, ASYS_TOP_CON,
				   AUDIO_TOP_CON0_A1SYS_A2SYS_ON,
				   AUDIO_TOP_CON0_A1SYS_A2SYS_ON);
		regmap_update_bits(afe->regmap, AFE_DAC_CON0,
				   AFE_DAC_CON0_AFE_ON, AFE_DAC_CON0_AFE_ON);
		regmap_write(afe->regmap, PWR2_TOP_CON, PWR2_TOP_CON_INIT_VAL);
		regmap_write(afe->regmap, PWR1_ASM_CON1,
			     PWR1_ASM_CON1_INIT_VAL);
		regmap_write(afe->regmap, PWR2_ASM_CON1,
			     PWR2_ASM_CON1_INIT_VAL);
	} else {
		mtk2701_turn_off_afe_clock(afe);
		mtk2701_turn_off_a1sys_clock(afe);
		mtk2701_turn_off_a2sys_clock(afe);
		regmap_update_bits(afe->regmap, ASYS_TOP_CON,
				   AUDIO_TOP_CON0_A1SYS_A2SYS_ON, 0);
		regmap_update_bits(afe->regmap, AFE_DAC_CON0,
				   AFE_DAC_CON0_AFE_ON, 0);
	}
}

void mtk2701_turn_on_a1sys_clock(struct mtk_afe *afe)
{
	int ret = 0;
	struct audio_clock_attr *aud_clks = afe->aud_clks;

	/* Set Mux */
	ret = clk_prepare_enable(aud_clks[AUDCLK_TOP_AUD_MUX1_SEL].clock);
	if (ret)
		dev_err(afe->dev, "%s clk_prepare_enable %s fail %d\n",
			__func__,
			aud_clks[AUDCLK_TOP_AUD_MUX1_SEL].clock_data->name,
			ret);

	ret = clk_set_parent(aud_clks[AUDCLK_TOP_AUD_MUX1_SEL].clock,
			     aud_clks[AUDCLK_TOP_AUD1PLL_98M].clock);
	if (ret)
		dev_err(afe->dev, "%s clk_set_parent %s-%s fail %d\n", __func__,
			aud_clks[AUDCLK_TOP_AUD_MUX1_SEL].clock_data->name,
			aud_clks[AUDCLK_TOP_AUD1PLL_98M].clock_data->name, ret);

	/* Set Divider */
	ret = clk_prepare_enable(aud_clks[AUDCLK_TOP_AUD_MUX1_DIV].clock);
	if (ret)
		dev_err(afe->dev, "%s clk_prepare_enable %s fail %d\n",
			__func__,
			aud_clks[AUDCLK_TOP_AUD_MUX1_DIV].clock_data->name,
			ret);
	ret = clk_set_rate(aud_clks[AUDCLK_TOP_AUD_MUX1_DIV].clock,
			   98304000 / 2);
	if (ret)
		dev_err(afe->dev, "%s clk_set_parent %s-%d fail %d\n", __func__,
			aud_clks[AUDCLK_TOP_AUD_MUX1_DIV].clock_data->name,
			98304000 / 2, ret);

	/* Enable clock gate */
	ret = clk_enable(aud_clks[AUDCLK_TOP_AUD_48K_TIMING].clock);
	if (ret)
		dev_err(afe->dev, "%s clk_enable %s fail %d\n", __func__,
			aud_clks[AUDCLK_TOP_AUD_48K_TIMING].clock_data->name,
			ret);
	/* Enable infra audio */
	ret = clk_enable(aud_clks[AUDCLK_INFRA_SYS_AUDIO].clock);
	if (ret)
		dev_err(afe->dev, "%s clk_enable %s fail %d\n", __func__,
			aud_clks[AUDCLK_INFRA_SYS_AUDIO].clock_data->name, ret);
}

void mtk2701_turn_off_a1sys_clock(struct mtk_afe *afe)
{
	struct audio_clock_attr *aud_clks = afe->aud_clks;

	clk_disable(aud_clks[AUDCLK_INFRA_SYS_AUDIO].clock);
	clk_disable(aud_clks[AUDCLK_TOP_AUD_48K_TIMING].clock);
	clk_disable_unprepare(aud_clks[AUDCLK_TOP_AUD_MUX1_DIV].clock);
	clk_disable_unprepare(aud_clks[AUDCLK_TOP_AUD_MUX1_SEL].clock);
}

void mtk2701_turn_on_a2sys_clock(struct mtk_afe *afe)
{
	int ret = 0;
	struct audio_clock_attr *aud_clks = afe->aud_clks;
	/* Set Mux */
	ret = clk_prepare_enable(aud_clks[AUDCLK_TOP_AUD_MUX2_SEL].clock);
	if (ret)
		dev_err(afe->dev, "%s clk_prepare_enable %s fail %d\n",
			__func__,
			aud_clks[AUDCLK_TOP_AUD_MUX2_SEL].clock_data->name,
			ret);
	ret = clk_set_parent(aud_clks[AUDCLK_TOP_AUD_MUX2_SEL].clock,
			     aud_clks[AUDCLK_TOP_AUD2PLL_90M].clock);
	if (ret)
		dev_err(afe->dev, "%s clk_set_parent %s-%s fail %d\n", __func__,
			aud_clks[AUDCLK_TOP_AUD_MUX2_SEL].clock_data->name,
			aud_clks[AUDCLK_TOP_AUD2PLL_90M].clock_data->name, ret);
	/* Set Divider */
	ret = clk_prepare_enable(aud_clks[AUDCLK_TOP_AUD_MUX2_DIV].clock);
	if (ret)
		dev_err(afe->dev, "%s clk_prepare_enable %s fail %d\n",
			__func__,
			aud_clks[AUDCLK_TOP_AUD_MUX2_DIV].clock_data->name,
			ret);
	ret = clk_set_rate(aud_clks[AUDCLK_TOP_AUD_MUX2_DIV].clock,
			   90316800 / 2);
	if (ret)
		dev_err(afe->dev, "%s clk_set_parent %s-%d fail %d\n", __func__,
			aud_clks[AUDCLK_TOP_AUD_MUX2_DIV].clock_data->name,
			90316800 / 2, ret);

	/* Enable clock gate */
	ret = clk_enable(aud_clks[AUDCLK_TOP_AUD_44K_TIMING].clock);
	if (ret)
		dev_err(afe->dev, "%s clk_enable %s fail %d\n", __func__,
			aud_clks[AUDCLK_TOP_AUD_44K_TIMING].clock_data->name,
			ret);
	/* Enable infra audio */
	ret = clk_enable(aud_clks[AUDCLK_INFRA_SYS_AUDIO].clock);
	if (ret)
		dev_err(afe->dev, "%s clk_enable %s fail %d\n", __func__,
			aud_clks[AUDCLK_INFRA_SYS_AUDIO].clock_data->name, ret);
}

void mtk2701_turn_off_a2sys_clock(struct mtk_afe *afe)
{
	struct audio_clock_attr *aud_clks = afe->aud_clks;

	clk_disable(aud_clks[AUDCLK_INFRA_SYS_AUDIO].clock);
	clk_disable(aud_clks[AUDCLK_TOP_AUD_44K_TIMING].clock);
	clk_disable_unprepare(aud_clks[AUDCLK_TOP_AUD_MUX2_DIV].clock);
	clk_disable_unprepare(aud_clks[AUDCLK_TOP_AUD_MUX2_SEL].clock);
}

void mtk2701_turn_on_afe_clock(struct mtk_afe *afe)
{
	int ret;
	struct audio_clock_attr *aud_clks = afe->aud_clks;

	/*MT_CG_INFRA_AUDIO, INFRA_PDN_STA[5]*/
	ret = clk_enable(aud_clks[AUDCLK_INFRA_SYS_AUDIO].clock);
	if (ret)
		dev_err(afe->dev, "%s clk_enable %s fail %d\n", __func__,
			aud_clks[AUDCLK_INFRA_SYS_AUDIO].clock_data->name, ret);

	/* Set AUDCLK_TOP_AUDINTBUS to AUDCLK_TOP_SYSPLL1_D4 */
	ret = clk_prepare_enable(aud_clks[AUDCLK_TOP_AUDINTBUS].clock);
	if (ret)
		dev_err(afe->dev, "%s clk_prepare_enable %s fail %d\n",
			__func__,
			aud_clks[AUDCLK_TOP_AUDINTBUS].clock_data->name, ret);

	ret = clk_set_parent(aud_clks[AUDCLK_TOP_AUDINTBUS].clock,
			     aud_clks[AUDCLK_TOP_SYSPLL1_D4].clock);
	if (ret)
		dev_err(afe->dev, "%s clk_set_parent %s-%s fail %d\n", __func__,
			aud_clks[AUDCLK_TOP_AUDINTBUS].clock_data->name,
			aud_clks[AUDCLK_TOP_SYSPLL1_D4].clock_data->name, ret);

	/* Set AUDCLK_TOP_ASM_H_SEL to AUDCLK_TOP_UNIVPLL2_D2*/
	ret = clk_prepare_enable(aud_clks[AUDCLK_TOP_ASM_H_SEL].clock);
	if (ret)
		dev_err(afe->dev, "%s clk_prepare_enable %s fail %d\n",
			__func__,
			aud_clks[AUDCLK_TOP_ASM_H_SEL].clock_data->name, ret);

	ret = clk_set_parent(aud_clks[AUDCLK_TOP_ASM_H_SEL].clock,
			     aud_clks[AUDCLK_TOP_UNIVPLL2_D2].clock);
	if (ret)
		dev_err(afe->dev, "%s clk_set_parent %s-%s fail %d\n", __func__,
			aud_clks[AUDCLK_TOP_ASM_H_SEL].clock_data->name,
			aud_clks[AUDCLK_TOP_UNIVPLL2_D2].clock_data->name, ret);

	if (ret)
		dev_err(afe->dev, "%s clk_enable %s fail %d\n", __func__,
			aud_clks[AUDCLK_TOP_ASM_H_SEL].clock_data->name, ret);

	/* Set AUDCLK_TOP_ASM_M_SEL to AUDCLK_TOP_UNIVPLL2_D4*/
	ret = clk_prepare_enable(aud_clks[AUDCLK_TOP_ASM_M_SEL].clock);
	if (ret)
		dev_err(afe->dev, "%s clk_prepare_enable %s fail %d\n",
			__func__,
			aud_clks[AUDCLK_TOP_ASM_M_SEL].clock_data->name, ret);

	ret = clk_set_parent(aud_clks[AUDCLK_TOP_ASM_M_SEL].clock,
			     aud_clks[AUDCLK_TOP_UNIVPLL2_D4].clock);
	if (ret)
		dev_err(afe->dev, "%s clk_set_parent %s-%s fail %d\n", __func__,
			aud_clks[AUDCLK_TOP_ASM_M_SEL].clock_data->name,
			aud_clks[AUDCLK_TOP_UNIVPLL2_D4].clock_data->name, ret);

	regmap_update_bits(afe->regmap, AUDIO_TOP_CON0,
			   AUDIO_TOP_CON0_PDN_AFE, 0);
	regmap_update_bits(afe->regmap, AUDIO_TOP_CON0,
			   AUDIO_TOP_CON0_PDN_APLL_CK, 0);
	regmap_update_bits(afe->regmap, AUDIO_TOP_CON4,
			   AUDIO_TOP_CON4_PDN_A1SYS, 0);
	regmap_update_bits(afe->regmap, AUDIO_TOP_CON4,
			   AUDIO_TOP_CON4_PDN_A2SYS, 0);
	regmap_update_bits(afe->regmap, AUDIO_TOP_CON4,
			   AUDIO_TOP_CON4_PDN_AFE_CONN, 0);
}

void mtk2701_turn_off_afe_clock(struct mtk_afe *afe)
{
	struct audio_clock_attr *aud_clks = afe->aud_clks;

	/*MT_CG_INFRA_AUDIO,*/
	clk_disable(aud_clks[AUDCLK_INFRA_SYS_AUDIO].clock);

	clk_disable_unprepare(aud_clks[AUDCLK_TOP_AUDINTBUS].clock);
	clk_disable_unprepare(aud_clks[AUDCLK_TOP_ASM_H_SEL].clock);
	clk_disable_unprepare(aud_clks[AUDCLK_TOP_ASM_M_SEL].clock);

	regmap_update_bits(afe->regmap, AUDIO_TOP_CON0,
			   AUDIO_TOP_CON0_PDN_AFE, AUDIO_TOP_CON0_PDN_AFE);
	regmap_update_bits(afe->regmap, AUDIO_TOP_CON0,
			   AUDIO_TOP_CON0_PDN_APLL_CK,
			   AUDIO_TOP_CON0_PDN_APLL_CK);
	regmap_update_bits(afe->regmap, AUDIO_TOP_CON4,
			   AUDIO_TOP_CON4_PDN_A1SYS, AUDIO_TOP_CON4_PDN_A1SYS);
	regmap_update_bits(afe->regmap, AUDIO_TOP_CON4,
			   AUDIO_TOP_CON4_PDN_A2SYS, AUDIO_TOP_CON4_PDN_A2SYS);
	regmap_update_bits(afe->regmap, AUDIO_TOP_CON4,
			   AUDIO_TOP_CON4_PDN_AFE_CONN,
			   AUDIO_TOP_CON4_PDN_AFE_CONN);
}

MODULE_DESCRIPTION("MTK2701 afe clock control");
MODULE_AUTHOR("Garlic Tseng <garlic.tseng@mediatek.com>");
MODULE_LICENSE("GPL v2");
