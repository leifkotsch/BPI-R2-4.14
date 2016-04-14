/*
 * mtk2701-afe-common.h  --  Mediatek 2701 audio driver definitions
 *
 * Copyright (c) 2016 MediaTek Inc.
 * Author: Garlic Tseng <garlic.tseng@mediatek.com>
 *             Koro Chen <koro.chen@mediatek.com>
 *             Sascha Hauer <s.hauer@pengutronix.de>
 *             Hidalgo Huang <hidalgo.huang@mediatek.com>
 *             Ir Lian <ir.lian@mediatek.com>
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

#ifndef _MTK_AFE_COMMON_H_
#define _MTK_AFE_COMMON_H_
#include <sound/soc.h>
#include <linux/clk.h>
#include <linux/regmap.h>

#define MTK_MEMIF_STREAM_NUM (SNDRV_PCM_STREAM_LAST + 1)

enum {
	MTK_AFE_I2S_1,
	MTK_AFE_I2S_2,
	MTK_AFE_I2S_3,
	MTK_AFE_I2S_4,
	MTK_I2S_NUM,
};

enum {
	MTK_AFE_MEMIF_1,
	MTK_AFE_MEMIF_2,
	MTK_AFE_MEMIF_3,
	MTK_AFE_MEMIF_4,
	MTK_AFE_MEMIF_5,
	MTK_AFE_MEMIF_SINGLE_NUM,
	MTK_AFE_MEMIF_M = MTK_AFE_MEMIF_SINGLE_NUM,
	MTK_AFE_MEMIF_NUM,
	MTK_AFE_IO_I2S = MTK_AFE_MEMIF_NUM,
	MTK_AFE_IO_2ND_I2S,
	MTK_AFE_IO_3RD_I2S,
	MTK_AFE_IO_4TH_I2S,
	MTK_AFE_IO_5TH_I2S,
	MTK_AFE_IO_6TH_I2S,
	MTK_AFE_IO_MRG_O,
	MTK_AFE_IO_MRG_I,
};

enum {
	/*need for DAIBT, will implement before review*/
/*
	IRQ_AFE_IRQ1,
	IRQ_AFE_IRQ2,
*/
	IRQ_ASYS_START,
	IRQ_ASYS_IRQ1 = IRQ_ASYS_START,
	IRQ_ASYS_IRQ2,
	IRQ_ASYS_IRQ3,
	IRQ_ASYS_END,
	IRQ_NUM = IRQ_ASYS_END,
};

enum {
	DIV_ID_MCLK_TO_BCK,
	DIV_ID_BCK_TO_LRCK,
};

/*2701 clock def*/
enum audio_system_clock_type {
	AUDCLK_INFRA_SYS_AUDIO,
	AUDCLK_TOP_AUD_MUX1_SEL,
	AUDCLK_TOP_AUD_MUX2_SEL,
	AUDCLK_TOP_AUD_MUX1_DIV,
	AUDCLK_TOP_AUD_MUX2_DIV,
	AUDCLK_TOP_AUD_48K_TIMING,
	AUDCLK_TOP_AUD_44K_TIMING,
	AUDCLK_TOP_AUDPLL_MUX_SEL,
	AUDCLK_TOP_APLL_SEL,
	AUDCLK_TOP_AUD1PLL_98M,
	AUDCLK_TOP_AUD2PLL_90M,
	AUDCLK_TOP_HADDS2PLL_98M,
	AUDCLK_TOP_HADDS2PLL_294M,
	AUDCLK_TOP_AUDPLL,
	AUDCLK_TOP_AUDPLL_D4,
	AUDCLK_TOP_AUDPLL_D8,
	AUDCLK_TOP_AUDPLL_D16,
	AUDCLK_TOP_AUDPLL_D24,
	AUDCLK_TOP_AUDINTBUS,
	AUDCLK_CLK_26M,
	AUDCLK_TOP_SYSPLL1_D4,
	AUDCLK_TOP_AUD_K1_SRC_SEL,
	AUDCLK_TOP_AUD_K2_SRC_SEL,
	AUDCLK_TOP_AUD_K3_SRC_SEL,
	AUDCLK_TOP_AUD_K4_SRC_SEL,
	AUDCLK_TOP_AUD_K5_SRC_SEL,
	AUDCLK_TOP_AUD_K6_SRC_SEL,
	AUDCLK_TOP_AUD_K1_SRC_DIV,
	AUDCLK_TOP_AUD_K2_SRC_DIV,
	AUDCLK_TOP_AUD_K3_SRC_DIV,
	AUDCLK_TOP_AUD_K4_SRC_DIV,
	AUDCLK_TOP_AUD_K5_SRC_DIV,
	AUDCLK_TOP_AUD_K6_SRC_DIV,
	AUDCLK_TOP_AUD_I2S1_MCLK,
	AUDCLK_TOP_AUD_I2S2_MCLK,
	AUDCLK_TOP_AUD_I2S3_MCLK,
	AUDCLK_TOP_AUD_I2S4_MCLK,
	AUDCLK_TOP_AUD_I2S5_MCLK,
	AUDCLK_TOP_AUD_I2S6_MCLK,
	AUDCLK_TOP_ASM_M_SEL,
	AUDCLK_TOP_ASM_H_SEL,
	AUDCLK_TOP_UNIVPLL2_D4,
	AUDCLK_TOP_UNIVPLL2_D2,
	AUDCLK_TOP_SYSPLL_D5,
	CLOCK_NUM
};

struct audio_clock_attr_data {
	const char *name;
	const bool prepare_once;
};

struct audio_clock_attr {
	struct audio_clock_attr_data *clock_data;
	bool is_prepared;
	struct clk *clock;
};

struct mtk_afe;
struct snd_pcm_substream;

struct mtk_afe_memif_data {
	int id;
	const char *name;
	int reg_ofs_base;
	int reg_ofs_cur;
	int fs_reg;
	int fs_shift;
	int mono_reg;
	int mono_shift;
	int enable_shift;
	int hd_reg;
	int hd_shift;
	int agent_disable_shift;
};

struct mtk_afe_irq_data {
	int irq_id;
	int irq_cnt_reg;
	int irq_cnt_shift;
	int irq_cnt_maskbit;
	int irq_fs_reg;
	int irq_fs_shift;
	int irq_fs_maskbit;
	int irq_en_reg;
	int irq_en_shift;
	int irq_occupy;
};

struct mtk_afe_irq {
	const struct mtk_afe_irq_data *irq_data;
	int irq_occupyed;
	struct mtk_afe_memif *memif;
	void (*isr)(struct mtk_afe *afe, struct mtk_afe_memif *memif);
};

struct mtk_afe_memif {
	unsigned int phys_buf_addr;
	int buffer_size;
	unsigned int hw_ptr;
	struct snd_pcm_substream *substream;
	const struct mtk_afe_memif_data *data;
	struct mtk_afe_irq *irq;
};

struct mtk_i2s_data {
	int i2s_ctrl_reg;
	int i2s_pwn_shift;
	int i2s_asrc_fs_shift;
	int i2s_asrc_fs_mask;
};

enum mtk_i2s_dir {
	I2S_OUT,
	I2S_IN,
	I2S_DIR_NUM,
};

struct mtk_i2s_path {
	int dai_id;
	int mclk_rate;
	int div_mclk_to_bck;
	int div_bck_to_lrck;
	int format;
	snd_pcm_format_t stream_fmt;
	int on[I2S_DIR_NUM];
	int occupied[I2S_DIR_NUM];
	const struct mtk_i2s_data *i2s_data[2];
};

struct mtk_afe {
	void __iomem *base_addr;
	struct device *dev;
	struct regmap *regmap;
	struct mtk_afe_memif memif[MTK_AFE_MEMIF_NUM][MTK_MEMIF_STREAM_NUM];
	struct audio_clock_attr aud_clks[CLOCK_NUM];
	struct mtk_afe_irq irqs[IRQ_NUM];
	struct mtk_i2s_path i2s_path[MTK_I2S_NUM];
};

#endif
