/*
 * Mediatek ALSA SoC AFE platform driver for 2701
 *
 * Copyright (c) 2016 MediaTek Inc.
 * Author: Garlic Tseng <garlic.tseng@mediatek.com>
 *             Koro Chen <koro.chen@mediatek.com>
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

#include <linux/delay.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/pm_runtime.h>
#include <sound/soc.h>

#include "mtk2701-afe-common.h"

#include "mtk2701-afe-clock-ctrl.h"
#include "mtk2701-irq.h"
#include "mtk2701-reg.h"

#define AFE_BASE_END_OFFSET	8
#define AFE_IRQ_STATUS_BITS	0xff
#define PLL_DOMAIN_0_RATE	98304000
#define PLL_DOMAIN_1_RATE	90316800

static const struct snd_pcm_hardware mtk2701_afe_hardware = {
	.info = SNDRV_PCM_INFO_MMAP | SNDRV_PCM_INFO_INTERLEAVED
		| SNDRV_PCM_INFO_RESUME | SNDRV_PCM_INFO_MMAP_VALID,
	.formats = SNDRV_PCM_FMTBIT_S16_LE | SNDRV_PCM_FMTBIT_S24_LE
		   | SNDRV_PCM_FMTBIT_S32_LE,
	.period_bytes_min = 1024,
	.period_bytes_max = 1024 * 256,
	.periods_min = 4,
	.periods_max = 1024,
	.buffer_bytes_max = 1024 * 1024 * 16,
	.fifo_size = 0,
};

static snd_pcm_uframes_t mtk2701_afe_pcm_pointer
			 (struct snd_pcm_substream *substream)
{
	struct snd_soc_pcm_runtime *rtd = substream->private_data;
	struct mtk_afe *afe = snd_soc_platform_get_drvdata(rtd->platform);
	int stream_dir = substream->stream;
	struct mtk_afe_memif *memif = &afe->memif[rtd->cpu_dai->id][stream_dir];

	return bytes_to_frames(substream->runtime, memif->hw_ptr);
}

static const struct snd_pcm_ops mtk2701_afe_pcm_ops = {
	.ioctl = snd_pcm_lib_ioctl,
	.pointer = mtk2701_afe_pcm_pointer,
};

static int mtk2701_afe_pcm_new(struct snd_soc_pcm_runtime *rtd)
{
	size_t size;
	struct snd_card *card = rtd->card->snd_card;
	struct snd_pcm *pcm = rtd->pcm;

	size = mtk2701_afe_hardware.buffer_bytes_max;
	return snd_pcm_lib_preallocate_pages_for_all(pcm, SNDRV_DMA_TYPE_DEV,
						     card->dev, size, size);
}

static void mtk2701_afe_pcm_free(struct snd_pcm *pcm)
{
	snd_pcm_lib_preallocate_free_for_all(pcm);
}

static const struct snd_soc_platform_driver mtk2701_afe_pcm_platform = {
	.ops = &mtk2701_afe_pcm_ops,
	.pcm_new = mtk2701_afe_pcm_new,
	.pcm_free = mtk2701_afe_pcm_free,
};

struct mtk2701_afe_rate {
	unsigned int rate;
	unsigned int regvalue;
};

static const struct mtk2701_afe_rate mtk2701_afe_i2s_rates[] = {
	{ .rate = 8000, .regvalue = 0 },
	{ .rate = 12000, .regvalue = 1 },
	{ .rate = 16000, .regvalue = 2 },
	{ .rate = 24000, .regvalue = 3 },
	{ .rate = 32000, .regvalue = 4 },
	{ .rate = 48000, .regvalue = 5 },
	{ .rate = 96000, .regvalue = 6 },
	{ .rate = 192000, .regvalue = 7 },
	{ .rate = 384000, .regvalue = 8 },
	{ .rate = 7350, .regvalue = 16 },
	{ .rate = 11025, .regvalue = 17 },
	{ .rate = 14700, .regvalue = 18 },
	{ .rate = 22050, .regvalue = 19 },
	{ .rate = 29400, .regvalue = 20 },
	{ .rate = 44100, .regvalue = 21 },
	{ .rate = 88200, .regvalue = 22 },
	{ .rate = 176400, .regvalue = 23 },
	{ .rate = 352800, .regvalue = 24 },
};

static const struct mtk2701_afe_rate mtk2701_afe_irq_rates[] = {
	{ .rate = 8000, .regvalue = 0 },
	{ .rate = 12000, .regvalue = 1 },
	{ .rate = 16000, .regvalue = 2 },
	{ .rate = 24000, .regvalue = 3 },
	{ .rate = 32000, .regvalue = 4 },
	{ .rate = 48000, .regvalue = 5 },
	{ .rate = 96000, .regvalue = 6 },
	{ .rate = 192000, .regvalue = 7 },
	{ .rate = 11025, .regvalue = 9 },
	{ .rate = 22050, .regvalue = 0xb },
	{ .rate = 44100, .regvalue = 0xd },
	{ .rate = 88200, .regvalue = 0xe },
	{ .rate = 176400, .regvalue = 0xf },
};

void mtk2701_mclk_configuration(struct mtk_afe *afe, int id, int domain,
				int mclk)
{
	int ret;
	int aud_src_div_id = AUDCLK_TOP_AUD_K1_SRC_DIV + id;
	int aud_src_clk_id = AUDCLK_TOP_AUD_K1_SRC_SEL + id;
	struct audio_clock_attr *clks = afe->aud_clks;

	/* Set MCLK Kx_SRC_SEL(domain) */
	ret = clk_prepare_enable(clks[aud_src_clk_id].clock);
	if (ret)
		dev_err(afe->dev, "%s clk_prepare_enable %s fail %d\n",
			__func__, clks[aud_src_clk_id].clock_data->name, ret);

	if (domain == 0) {
		ret = clk_set_parent(clks[aud_src_clk_id].clock,
				     clks[AUDCLK_TOP_AUD_MUX1_SEL].clock);
		if (ret)
			dev_err(afe->dev, "%s clk_set_parent %s-%s fail %d\n",
				__func__, clks[aud_src_clk_id].clock_data->name,
				clks[AUDCLK_TOP_AUD_MUX1_SEL].clock_data->name,
				ret);
	} else {
		ret = clk_set_parent(clks[aud_src_clk_id].clock,
				     clks[AUDCLK_TOP_AUD_MUX2_SEL].clock);
		if (ret)
			dev_err(afe->dev, "%s clk_set_parent %s-%s fail %d\n",
				__func__, clks[aud_src_clk_id].clock_data->name,
				clks[AUDCLK_TOP_AUD_MUX2_SEL].clock_data->name,
				ret);
	}
	clk_disable_unprepare(clks[aud_src_clk_id].clock);

	/* Set MCLK Kx_SRC_DIV(divider) */
	ret = clk_prepare_enable(clks[aud_src_div_id].clock);
	if (ret)
		dev_err(afe->dev, "%s clk_prepare_enable %s fail %d\n",
			__func__, clks[aud_src_div_id].clock_data->name, ret);

	ret = clk_set_rate(clks[aud_src_div_id].clock, mclk);
	if (ret)
		dev_err(afe->dev, "%s clk_set_rate %s-%d fail %d\n", __func__,
			clks[aud_src_div_id].clock_data->name, mclk, ret);
	clk_disable_unprepare(clks[aud_src_div_id].clock);
}

int mtk2701_dai_num_to_i2s(struct mtk_afe *afe, int num)
{
	int val = num - MTK_AFE_IO_I2S;

	if (val < 0 || val > MTK_I2S_NUM) {
		dev_err(afe->dev, "%s, num not available, num %d, val %d\n",
			__func__, num, val);
		return -1;
	}
	return val;
}

static int mtk2701_afe_i2s_fs(unsigned int sample_rate)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(mtk2701_afe_i2s_rates); i++)
		if (mtk2701_afe_i2s_rates[i].rate == sample_rate)
			return mtk2701_afe_i2s_rates[i].regvalue;

	return -EINVAL;
}

/*need for BT, will implement BT before upstream*/
/*
static int mtk2701_afe_irq_fs(unsigned int sample_rate)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(mtk2701_afe_irq_rates); i++)
		if (mtk2701_afe_irq_rates[i].rate == sample_rate)
			return mtk2701_afe_irq_rates[i].regvalue;

	return -EINVAL;
}
*/

static int mtk2701_afe_i2s_enable_clks(struct mtk_afe *afe,
				       struct audio_clock_attr *clk_attr)
{
	int ret;

	if (clk_attr->clock_data->prepare_once)
		ret = clk_enable(clk_attr->clock);
	else
		ret = clk_prepare_enable(clk_attr->clock);
	if (ret) {
		dev_err(afe->dev, "Failed to enable %s\n",
			clk_attr->clock_data->name);
		return ret;
	}
	return 0;
}

static int mtk2701_afe_i2s_disable_clks(struct mtk_afe *afe,
					struct audio_clock_attr *clk_attr)
{
	if (clk_attr->clock_data->prepare_once)
		clk_disable(clk_attr->clock);
	else
		clk_disable_unprepare(clk_attr->clock);
	return 0;
}

static int mtk2701_afe_i2s_startup(struct snd_pcm_substream *substream,
				   struct snd_soc_dai *dai)
{
	struct snd_soc_pcm_runtime *rtd = substream->private_data;
	struct mtk_afe *afe = snd_soc_platform_get_drvdata(rtd->platform);
	int i2s_num = mtk2701_dai_num_to_i2s(afe, dai->id);

	/*enable mclk*/
	mtk2701_afe_i2s_enable_clks(afe,
			&afe->aud_clks[AUDCLK_TOP_AUD_I2S1_MCLK + i2s_num]);
	return 0;
}

static int mtk2701_afe_i2s_path_shutdown(struct snd_pcm_substream *substream,
					 struct snd_soc_dai *dai,
					 int dir_invert)
{
	struct snd_soc_pcm_runtime *rtd = substream->private_data;
	struct mtk_afe *afe = snd_soc_platform_get_drvdata(rtd->platform);
	int i2s_num = mtk2701_dai_num_to_i2s(afe, dai->id);
	struct mtk_i2s_path *i2s_path = &afe->i2s_path[i2s_num];
	const struct mtk_i2s_data *i2s_data;
	int stream_dir = substream->stream;

	if (dir_invert)	{
		if (stream_dir == SNDRV_PCM_STREAM_PLAYBACK)
			stream_dir = SNDRV_PCM_STREAM_CAPTURE;
		else
			stream_dir = SNDRV_PCM_STREAM_PLAYBACK;
	}
	i2s_data = i2s_path->i2s_data[stream_dir];

	i2s_path->on[stream_dir]--;
	if (i2s_path->on[stream_dir] < 0) {
		dev_warn(afe->dev, "i2s_path->on: %d, dir: %d\n",
			 i2s_path->on[stream_dir], stream_dir);
		i2s_path->on[stream_dir] = 0;
	}
	if (i2s_path->on[stream_dir])
		return 0;

	/*disable i2s*/
	regmap_update_bits(afe->regmap, i2s_data->i2s_ctrl_reg,
			   ASYS_I2S_CON_I2S_EN, 0);
	regmap_update_bits(afe->regmap, AUDIO_TOP_CON4,
			   1 << i2s_data->i2s_pwn_shift,
			   1 << i2s_data->i2s_pwn_shift);
	return 0;
}

static void mtk2701_afe_i2s_shutdown(struct snd_pcm_substream *substream,
				     struct snd_soc_dai *dai)
{
	struct snd_soc_pcm_runtime *rtd = substream->private_data;
	struct mtk_afe *afe = snd_soc_platform_get_drvdata(rtd->platform);
	int i2s_num = mtk2701_dai_num_to_i2s(afe, dai->id);
	struct mtk_i2s_path *i2s_path = &afe->i2s_path[i2s_num];

	if (i2s_path->occupied[substream->stream]) {
		i2s_path->occupied[substream->stream] = 0;
	} else {
		dev_info(afe->dev,
			 "i2s not occpuied but someone want to shutdown it.\n");
		goto I2S_UNSTART;
	}

	mtk2701_afe_i2s_path_shutdown(substream, dai, 0);

	/*need to disable i2s-out path when disable i2s-in*/
	if (substream->stream == SNDRV_PCM_STREAM_CAPTURE)
		mtk2701_afe_i2s_path_shutdown(substream, dai, 1);

I2S_UNSTART:
	/*disable mclk*/
	mtk2701_afe_i2s_disable_clks(afe,
			&afe->aud_clks[AUDCLK_TOP_AUD_I2S1_MCLK + i2s_num]);
}

static int mtk2701_i2s_path_prepare_enable(struct snd_pcm_substream *substream,
					   struct snd_soc_dai *dai,
					   int dir_invert)
{
	struct snd_soc_pcm_runtime *rtd = substream->private_data;
	struct mtk_afe *afe = snd_soc_platform_get_drvdata(rtd->platform);
	int i2s_num = mtk2701_dai_num_to_i2s(afe, dai->id);
	struct mtk_i2s_path *i2s_path = &afe->i2s_path[i2s_num];
	const struct mtk_i2s_data *i2s_data;
	struct snd_pcm_runtime * const runtime = substream->runtime;
	int reg, fs, w_len = 1;
	int stream_dir = substream->stream;
	unsigned int mask = 0, val = 0;

	if (dir_invert) {
		if (stream_dir == SNDRV_PCM_STREAM_PLAYBACK)
			stream_dir = SNDRV_PCM_STREAM_CAPTURE;
		else
			stream_dir = SNDRV_PCM_STREAM_PLAYBACK;
	}
	i2s_data = i2s_path->i2s_data[stream_dir];

	/*no need to enable if already done*/
	i2s_path->on[stream_dir]++;

	if (i2s_path->on[stream_dir] != 1)
		return 0;

	fs = mtk2701_afe_i2s_fs(runtime->rate);

	if (i2s_path->div_bck_to_lrck == 32)
		w_len = 0;
	else if (i2s_path->div_bck_to_lrck == 64)
		w_len = 1;
	else
		dev_warn(dai->dev, "%s() bad bit count %d\n", __func__,
			 afe->i2s_path[i2s_num].div_bck_to_lrck);

	mask = ASYS_I2S_CON_FS |
		ASYS_I2S_CON_MULTI_CH | /*0*/
		ASYS_I2S_CON_I2S_COUPLE_MODE | /*0*/
		ASYS_I2S_CON_I2S_MODE |
		ASYS_I2S_CON_WIDE_MODE;

	val = ASYS_I2S_CON_FS_SET(fs) |
	       ASYS_I2S_CON_I2S_MODE |
	       ASYS_I2S_CON_WIDE_MODE_SET(w_len);

	if (stream_dir == SNDRV_PCM_STREAM_CAPTURE) {
		mask |= ASYS_I2S_IN_PHASE_FIX;
		val |= ASYS_I2S_IN_PHASE_FIX;
	}

	regmap_update_bits(afe->regmap, i2s_data->i2s_ctrl_reg, mask, val);

	if (stream_dir == SNDRV_PCM_STREAM_PLAYBACK)
		reg = ASMO_TIMING_CON1;
	else
		reg = ASMI_TIMING_CON1;

	regmap_update_bits(afe->regmap, reg,
		      i2s_data->i2s_asrc_fs_mask << i2s_data->i2s_asrc_fs_shift,
		      fs << i2s_data->i2s_asrc_fs_shift);

	/*enable i2s*/
	regmap_update_bits(afe->regmap, AUDIO_TOP_CON4,
			   1 << i2s_data->i2s_pwn_shift,
			   0 << i2s_data->i2s_pwn_shift);

	/*reset irq hw status before enable*/
	regmap_update_bits(afe->regmap, i2s_data->i2s_ctrl_reg,
			   ASYS_I2S_CON_RESET, ASYS_I2S_CON_RESET);
	udelay(1);
	regmap_update_bits(afe->regmap, i2s_data->i2s_ctrl_reg,
			   ASYS_I2S_CON_RESET, 0);
	udelay(1);
	regmap_update_bits(afe->regmap, i2s_data->i2s_ctrl_reg,
			   ASYS_I2S_CON_I2S_EN, ASYS_I2S_CON_I2S_EN);
	return 0;
}

static int mtk2701_afe_i2s_prepare(struct snd_pcm_substream *substream,
				   struct snd_soc_dai *dai)
{
	int clk_domain;

	struct snd_soc_pcm_runtime *rtd = substream->private_data;
	struct mtk_afe *afe = snd_soc_platform_get_drvdata(rtd->platform);
	int i2s_num = mtk2701_dai_num_to_i2s(afe, dai->id);
	struct mtk_i2s_path *i2s_path = &afe->i2s_path[i2s_num];
	const int mclk_rate = i2s_path->mclk_rate;

	if (i2s_path->occupied[substream->stream])
		return -EBUSY;
	i2s_path->occupied[substream->stream] = 1;

	if (PLL_DOMAIN_0_RATE % mclk_rate == 0) {
		clk_domain = 0;
	} else if (PLL_DOMAIN_1_RATE % mclk_rate == 0) {
		clk_domain = 1;
	} else {
		dev_err(dai->dev, "%s() bad mclk rate %d\n",
			__func__, mclk_rate);
		return -EINVAL;
	}
	mtk2701_mclk_configuration(afe, i2s_num, clk_domain, mclk_rate);

	if (substream->stream == SNDRV_PCM_STREAM_PLAYBACK) {
		mtk2701_i2s_path_prepare_enable(substream, dai, 0);
	} else {
		/*need to enable i2s-out path when enable i2s-in*/
		/*prepare for another direction "out"*/
		mtk2701_i2s_path_prepare_enable(substream, dai, 1);
		/*prepare for "in"*/
		mtk2701_i2s_path_prepare_enable(substream, dai, 0);
	}

	return 0;
}

static int mtk2701_afe_i2s_set_sysclk(struct snd_soc_dai *dai, int clk_id,
				      unsigned int freq, int dir)
{
	struct mtk_afe *afe = dev_get_drvdata(dai->dev);
	int i2s_num = mtk2701_dai_num_to_i2s(afe, dai->id);
	/* mclk */
	if (dir == SND_SOC_CLOCK_IN) {
		dev_warn(dai->dev,
			 "%s() warning: mt2701 doesn't support mclk input\n",
			__func__);
		return -EINVAL;
	}
	afe->i2s_path[i2s_num].mclk_rate = freq;
	return 0;
}

static int mtk2701_afe_i2s_set_clkdiv(struct snd_soc_dai *dai, int div_id,
				      int div)
{
	struct mtk_afe *afe = dev_get_drvdata(dai->dev);
	int i2s_num = mtk2701_dai_num_to_i2s(afe, dai->id);

	switch (div_id) {
	case DIV_ID_MCLK_TO_BCK:
		afe->i2s_path[i2s_num].div_mclk_to_bck = div;
		break;
	case DIV_ID_BCK_TO_LRCK:
		afe->i2s_path[i2s_num].div_bck_to_lrck = div;
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

static int mtk2701_afe_i2s_set_fmt(struct snd_soc_dai *dai, unsigned int fmt)
{
	struct mtk_afe *afe = dev_get_drvdata(dai->dev);
	int i2s_num = mtk2701_dai_num_to_i2s(afe, dai->id);

	afe = dev_get_drvdata(dai->dev);
	afe->i2s_path[i2s_num].format = fmt;
	return 0;
}

static int mtk2701_playback_mem_avail(struct mtk_afe *afe, int memif_num)
{
	struct mtk_afe_memif *memif_tmp;

	if (memif_num >= MTK_AFE_MEMIF_1 &&
	    memif_num < MTK_AFE_MEMIF_SINGLE_NUM) {
		memif_tmp =
		    &afe->memif[MTK_AFE_MEMIF_M][SNDRV_PCM_STREAM_PLAYBACK];
		if (memif_tmp->substream)
			return 0;
	} else if (memif_num == MTK_AFE_MEMIF_M) {
		int i;

		for (i = MTK_AFE_MEMIF_1; i < MTK_AFE_MEMIF_SINGLE_NUM; ++i) {
			memif_tmp = &afe->memif[i][SNDRV_PCM_STREAM_PLAYBACK];
			if (memif_tmp->substream)
				return 0;
		}
	}
	return 1;
}

static int mtk2701_afe_dais_startup(struct snd_pcm_substream *substream,
				    struct snd_soc_dai *dai)
{
	struct snd_soc_pcm_runtime *rtd = substream->private_data;
	struct mtk_afe *afe = snd_soc_platform_get_drvdata(rtd->platform);
	struct snd_pcm_runtime *runtime = substream->runtime;
	int stream_dir = substream->stream;
	int memif_num = rtd->cpu_dai->id;
	struct mtk_afe_memif *memif = &afe->memif[memif_num][stream_dir];
	int is_dlm = 0;
	int ret, i;
	struct mtk_afe_memif *memif_tmp;

	if (memif->substream) {
		dev_warn(afe->dev, "%s memif is occupied, stream_dir %d, memif_num = %d\n",
			 __func__, stream_dir, memif_num);
		return -EBUSY;
	}

	if (stream_dir == SNDRV_PCM_STREAM_PLAYBACK &&
	    !mtk2701_playback_mem_avail(afe, memif_num)) {
		dev_warn(afe->dev, "%s memif is not available, stream_dir %d, memif_num %d\n",
			 __func__, stream_dir, memif_num);
		return -EBUSY;
	}

	if (memif_num == MTK_AFE_MEMIF_M &&
	    stream_dir == SNDRV_PCM_STREAM_PLAYBACK)
		is_dlm = 1;

	memif->substream = substream;

	snd_pcm_hw_constraint_step(substream->runtime, 0,
				   SNDRV_PCM_HW_PARAM_BUFFER_BYTES, 16);
	/*enable agent*/
	regmap_update_bits(afe->regmap, AUDIO_TOP_CON5,
			   1 << memif->data->agent_disable_shift,
			   0 << memif->data->agent_disable_shift);
	if (is_dlm) {
		for (i = MTK_AFE_MEMIF_1; i < MTK_AFE_MEMIF_SINGLE_NUM; ++i) {
			memif_tmp = &afe->memif[i][SNDRV_PCM_STREAM_PLAYBACK];
			regmap_update_bits(afe->regmap, AUDIO_TOP_CON5,
				     1 << memif_tmp->data->agent_disable_shift,
				     0 << memif_tmp->data->agent_disable_shift);
		}
	}

	snd_soc_set_runtime_hwparams(substream, &mtk2701_afe_hardware);

	ret = snd_pcm_hw_constraint_integer(runtime,
					    SNDRV_PCM_HW_PARAM_PERIODS);
	if (ret < 0)
		dev_err(afe->dev, "snd_pcm_hw_constraint_integer failed\n");

	/*require irq resource*/
	if (!memif->irq) {
		int irq_id = mtk2701_asys_irq_acquire(afe);

		if (irq_id != IRQ_NUM) {
			/* link */
			memif->irq = &afe->irqs[irq_id];
			afe->irqs[irq_id].memif = memif;
			afe->irqs[irq_id].isr = mtk2701_memif_isr;
		} else {
			dev_err(afe->dev, "%s() error: no more asys irq\n",
				__func__);
		}
	}
	return ret;
}

static void mtk2701_afe_dais_shutdown(struct snd_pcm_substream *substream,
				      struct snd_soc_dai *dai)
{
	struct snd_soc_pcm_runtime *rtd = substream->private_data;
	struct mtk_afe *afe = snd_soc_platform_get_drvdata(rtd->platform);
	int stream_dir = substream->stream;
	struct mtk_afe_memif *memif = &afe->memif[rtd->cpu_dai->id][stream_dir];
	int irq_id, i;
	int is_dlm = 0;
	struct mtk_afe_memif *memif_tmp;

	irq_id = memif->irq->irq_data->irq_id;
	if (rtd->cpu_dai->id == MTK_AFE_MEMIF_M &&
	    stream_dir == SNDRV_PCM_STREAM_PLAYBACK)
		is_dlm = 1;

	regmap_update_bits(afe->regmap, AUDIO_TOP_CON5,
			   1 << memif->data->agent_disable_shift,
			   1 << memif->data->agent_disable_shift);
	if (is_dlm) {
		for (i = MTK_AFE_MEMIF_1; i < MTK_AFE_MEMIF_SINGLE_NUM; ++i) {
			memif_tmp = &afe->memif[i][SNDRV_PCM_STREAM_PLAYBACK];
			regmap_update_bits(afe->regmap, AUDIO_TOP_CON5,
				     1 << memif_tmp->data->agent_disable_shift,
				     1 << memif_tmp->data->agent_disable_shift);
		}
	}
	mtk2701_asys_irq_release(afe, irq_id);
	memif->irq = NULL;
	afe->irqs[irq_id].memif = NULL;
	afe->irqs[irq_id].isr = NULL;
	memif->substream = NULL;
}

static int mtk2701_afe_dais_hw_params(struct snd_pcm_substream *substream,
				      struct snd_pcm_hw_params *params,
				      struct snd_soc_dai *dai)
{
	int ret;

	ret = snd_pcm_lib_malloc_pages(substream, params_buffer_bytes(params));
	if (ret < 0)
		return ret;
	return 0;
}

static int mtk2701_afe_dais_hw_free(struct snd_pcm_substream *substream,
				    struct snd_soc_dai *dai)
{
	return snd_pcm_lib_free_pages(substream);
}

static int mtk2701_afe_dais_prepare(struct snd_pcm_substream *substream,
				    struct snd_soc_dai *dai)
{
	struct snd_soc_pcm_runtime *rtd  = substream->private_data;
	struct snd_pcm_runtime * const runtime = substream->runtime;
	struct mtk_afe *afe = snd_soc_platform_get_drvdata(rtd->platform);
	int stream_dir = substream->stream;
	struct mtk_afe_memif *memif = &afe->memif[rtd->cpu_dai->id][stream_dir];
	int is_dlm = 0;
	int hd_audio = 0;
	int fs;
	int channels = runtime->channels;

	if (rtd->cpu_dai->id == MTK_AFE_MEMIF_M &&
	    stream_dir == SNDRV_PCM_STREAM_PLAYBACK)
		is_dlm = 1;

	/*set hd mode*/
	switch (substream->runtime->format) {
	case SNDRV_PCM_FORMAT_S16_LE:
		hd_audio = 0;
		break;
	case SNDRV_PCM_FORMAT_S32_LE:
		hd_audio = 1;
		break;
	case SNDRV_PCM_FORMAT_S24_LE:
		hd_audio = 1;
		break;
	default:
		dev_err(afe->dev, "%s() error: unsupported format %d\n",
			__func__, substream->runtime->format);
		break;
	}

	regmap_update_bits(afe->regmap, memif->data->hd_reg,
			   1 << memif->data->hd_shift,
		   hd_audio << memif->data->hd_shift);

	memif->phys_buf_addr = substream->runtime->dma_addr;
	memif->buffer_size = substream->runtime->dma_bytes;
	memif->hw_ptr = 0;

	/* set rate */
	if (memif->data->fs_shift < 0)
		return 0;

	fs = mtk2701_afe_i2s_fs(runtime->rate);
	if (fs < 0)
		return -EINVAL;

	regmap_update_bits(afe->regmap, memif->data->fs_reg,
			   0x1f << memif->data->fs_shift,
			   fs << memif->data->fs_shift);
	/* set channel */
	if (memif->data->mono_shift >= 0) {
		unsigned int mono = (runtime->channels == 1) ? 1 : 0;

		regmap_update_bits(afe->regmap, memif->data->mono_reg,
				   1 << memif->data->mono_shift,
				   mono << memif->data->mono_shift);
	}
	/* start */
	regmap_write(afe->regmap,
		     memif->data->reg_ofs_base, memif->phys_buf_addr);
	/* end */
	regmap_write(afe->regmap,
		     memif->data->reg_ofs_base + AFE_BASE_END_OFFSET,
		     memif->phys_buf_addr + memif->buffer_size - 1);

	if (is_dlm) { /*setting for multi-ch playback*/
		regmap_update_bits(afe->regmap,
				   AFE_MEMIF_PBUF_SIZE,
				   AFE_MEMIF_PBUF_SIZE_DLM_MASK,
				   AFE_MEMIF_PBUF_SIZE_FULL_INTERLEAVE);
		regmap_update_bits(afe->regmap,
				   AFE_MEMIF_PBUF_SIZE,
				   AFE_MEMIF_PBUF_SIZE_DLM_BYTE_MASK,
				   AFE_MEMIF_PBUF_SIZE_DLM_32BYTES);
		regmap_update_bits(afe->regmap,
				   AFE_MEMIF_PBUF_SIZE,
				   AFE_MEMIF_PBUF_SIZE_DLM_CH_MASK,
				   AFE_MEMIF_PBUF_SIZE_DLM_CH(channels));

	} else if (stream_dir == SNDRV_PCM_STREAM_PLAYBACK) {
		regmap_update_bits(afe->regmap,
				   AFE_MEMIF_PBUF_SIZE,
				   AFE_MEMIF_PBUF_SIZE_DLM_MASK,
				   AFE_MEMIF_PBUF_SIZE_PAIR_INTERLEAVE);
	}
	return 0;
}

static int mtk2701_afe_dais_trigger(struct snd_pcm_substream *substream,
				    int cmd, struct snd_soc_dai *dai)
{
	struct snd_soc_pcm_runtime *rtd = substream->private_data;
	struct mtk_afe *afe = snd_soc_platform_get_drvdata(rtd->platform);
	int stream_dir = substream->stream;
	struct mtk_afe_memif *memif = &afe->memif[rtd->cpu_dai->id][stream_dir];
	struct mtk_afe_memif *memif_tmp;
	struct snd_pcm_runtime * const runtime = substream->runtime;
	unsigned int counter = runtime->period_size;

	switch (cmd) {
	case SNDRV_PCM_TRIGGER_START:
	case SNDRV_PCM_TRIGGER_RESUME:
		/*memory interface enable*/
		if (memif->data->enable_shift >= 0)
			regmap_update_bits(afe->regmap, AFE_DAC_CON0,
					   1 << memif->data->enable_shift,
					   1 << memif->data->enable_shift);

		/* set irq counter */
		regmap_update_bits(afe->regmap,
			      memif->irq->irq_data->irq_cnt_reg,
			      memif->irq->irq_data->irq_cnt_maskbit
			      << memif->irq->irq_data->irq_cnt_shift,
			      counter << (memif->irq->irq_data->irq_cnt_shift));
		/* set irq fs */
		if (memif->irq->irq_data->irq_fs_shift >= 0) {
			int fs;
			/*need for BT, will implement it before upstream*/
			/*
			if(memif->irqdata->irq_id == IRQ_AFE_IRQ1 ||
			   memif->irqdata->irq_id == IRQ_AFE_IRQ2 )
				fs = mtk2701_afe_irq_fs(runtime->rate);
			else
				fs = mtk2701_afe_i2s_fs(runtime->rate);
			*/
			fs = mtk2701_afe_i2s_fs(runtime->rate);
			if (fs < 0)
				return -EINVAL;

			regmap_update_bits(afe->regmap,
				      memif->irq->irq_data->irq_fs_reg,
				      memif->irq->irq_data->irq_fs_maskbit
				      << memif->irq->irq_data->irq_fs_shift,
				      fs << memif->irq->irq_data->irq_fs_shift);
		}

		if (rtd->cpu_dai->id == MTK_AFE_MEMIF_M &&
		    stream_dir == SNDRV_PCM_STREAM_PLAYBACK) {
			memif_tmp = &afe->memif[MTK_AFE_MEMIF_1][stream_dir];
			regmap_update_bits(afe->regmap, AFE_DAC_CON0,
					   1 << memif_tmp->data->enable_shift,
					   1 << memif_tmp->data->enable_shift);
		}
		/* enable interrupt */
		regmap_update_bits(afe->regmap,
				   memif->irq->irq_data->irq_en_reg,
				   1 << memif->irq->irq_data->irq_en_shift,
				   1 << memif->irq->irq_data->irq_en_shift);
		return 0;
	case SNDRV_PCM_TRIGGER_STOP:
	case SNDRV_PCM_TRIGGER_SUSPEND:
		/* disable interrupt */
		regmap_update_bits(afe->regmap,
				   memif->irq->irq_data->irq_en_reg,
				   1 << memif->irq->irq_data->irq_en_shift,
				   0 << memif->irq->irq_data->irq_en_shift);
		memif->hw_ptr = 0;
		/*memory interface disable*/
		if (memif->data->enable_shift >= 0)
			regmap_update_bits(afe->regmap, AFE_DAC_CON0,
					   1 << memif->data->enable_shift, 0);
		if (rtd->cpu_dai->id == MTK_AFE_MEMIF_M &&
		    stream_dir == SNDRV_PCM_STREAM_PLAYBACK) {
			memif_tmp = &afe->memif[MTK_AFE_MEMIF_1][stream_dir];
			regmap_update_bits(afe->regmap, AFE_DAC_CON0,
					   1 << memif_tmp->data->enable_shift,
					   0);
		}
		return 0;
	default:
		return -EINVAL;
	}
}

/* FE DAIs */
static const struct snd_soc_dai_ops mtk2701_afe_dai_ops = {
	.startup	= mtk2701_afe_dais_startup,
	.shutdown	= mtk2701_afe_dais_shutdown,
	.hw_params	= mtk2701_afe_dais_hw_params,
	.hw_free	= mtk2701_afe_dais_hw_free,
	.prepare	= mtk2701_afe_dais_prepare,
	.trigger	= mtk2701_afe_dais_trigger,
};

/* BE DAIs */
static const struct snd_soc_dai_ops mtk2701_afe_i2s_ops = {
	.startup	= mtk2701_afe_i2s_startup,
	.shutdown	= mtk2701_afe_i2s_shutdown,
	.prepare	= mtk2701_afe_i2s_prepare,
	.set_sysclk	= mtk2701_afe_i2s_set_sysclk,
	.set_clkdiv	= mtk2701_afe_i2s_set_clkdiv,
	.set_fmt	= mtk2701_afe_i2s_set_fmt,
};

static struct snd_soc_dai_driver mtk2701_afe_pcm_dais[] = {
	/* FE DAIs: memory intefaces to CPU */
	{
		.name = "PCM0",
		.id = MTK_AFE_MEMIF_1,
		.playback = {
			.stream_name = "DL1",
			.channels_min = 1,
			.channels_max = 2,
			.rates = SNDRV_PCM_RATE_8000_192000,
			.formats = (SNDRV_PCM_FMTBIT_S16_LE
				| SNDRV_PCM_FMTBIT_S24_LE
				| SNDRV_PCM_FMTBIT_S32_LE)
		},
		.capture = {
			.stream_name = "UL1",
			.channels_min = 1,
			.channels_max = 2,
			.rates = SNDRV_PCM_RATE_8000_48000,
			.formats = SNDRV_PCM_FMTBIT_S16_LE,
		},
		.ops = &mtk2701_afe_dai_ops,
	},
	{
		.name = "PCM_multi",
		.id = MTK_AFE_MEMIF_M,
		.playback = {
			.stream_name = "DLM",
			.channels_min = 1,
			.channels_max = 8,
			.rates = SNDRV_PCM_RATE_8000_192000,
			.formats = (SNDRV_PCM_FMTBIT_S16_LE
				| SNDRV_PCM_FMTBIT_S24_LE
				| SNDRV_PCM_FMTBIT_S32_LE)

		},
		.ops = &mtk2701_afe_dai_ops,
	},
	{
		.name = "PCM1",
		.id = MTK_AFE_MEMIF_2,
		.capture = {
			.stream_name = "UL2",
			.channels_min = 1,
			.channels_max = 2,
			.rates = SNDRV_PCM_RATE_8000_192000,
			.formats = (SNDRV_PCM_FMTBIT_S16_LE
				| SNDRV_PCM_FMTBIT_S24_LE
				| SNDRV_PCM_FMTBIT_S32_LE)

		},
		.ops = &mtk2701_afe_dai_ops,
	},
	{
	/* BE DAIs */
		.name = "I2S0",
		.id = MTK_AFE_IO_I2S,
		.playback = {
			.stream_name = "I2S0 Playback",
			.channels_min = 1,
			.channels_max = 2,
			.rates = SNDRV_PCM_RATE_8000_192000,
			.formats = (SNDRV_PCM_FMTBIT_S16_LE
				| SNDRV_PCM_FMTBIT_S24_LE
				| SNDRV_PCM_FMTBIT_S32_LE)

		},
		.capture = {
			.stream_name = "I2S0 Capture",
			.channels_min = 1,
			.channels_max = 2,
			.rates = SNDRV_PCM_RATE_8000_192000,
			.formats = (SNDRV_PCM_FMTBIT_S16_LE
				| SNDRV_PCM_FMTBIT_S24_LE
				| SNDRV_PCM_FMTBIT_S32_LE)

		},
		.ops = &mtk2701_afe_i2s_ops,
		.symmetric_rates = 1,
	},
	{
		.name = "I2S1",
		.id = MTK_AFE_IO_2ND_I2S,
		.playback = {
			.stream_name = "I2S1 Playback",
			.channels_min = 1,
			.channels_max = 2,
			.rates = SNDRV_PCM_RATE_8000_192000,
			.formats = (SNDRV_PCM_FMTBIT_S16_LE
				| SNDRV_PCM_FMTBIT_S24_LE
				| SNDRV_PCM_FMTBIT_S32_LE)
			},
		.capture = {
			.stream_name = "I2S1 Capture",
			.channels_min = 1,
			.channels_max = 2,
			.rates = SNDRV_PCM_RATE_8000_192000,
			.formats = (SNDRV_PCM_FMTBIT_S16_LE
				| SNDRV_PCM_FMTBIT_S24_LE
				| SNDRV_PCM_FMTBIT_S32_LE)
			},
		.ops = &mtk2701_afe_i2s_ops,
		.symmetric_rates = 1,
	},
	{
		.name = "I2S2",
		.id = MTK_AFE_IO_3RD_I2S,
		.playback = {
			.stream_name = "I2S2 Playback",
			.channels_min = 1,
			.channels_max = 2,
			.rates = SNDRV_PCM_RATE_8000_192000,
			.formats = (SNDRV_PCM_FMTBIT_S16_LE
				| SNDRV_PCM_FMTBIT_S24_LE
				| SNDRV_PCM_FMTBIT_S32_LE)
			},
		.capture = {
			.stream_name = "I2S2 Capture",
			.channels_min = 1,
			.channels_max = 2,
			.rates = SNDRV_PCM_RATE_8000_192000,
			.formats = (SNDRV_PCM_FMTBIT_S16_LE
				| SNDRV_PCM_FMTBIT_S24_LE
				| SNDRV_PCM_FMTBIT_S32_LE)
			},
		.ops = &mtk2701_afe_i2s_ops,
		.symmetric_rates = 1,
	},
	{
		.name = "I2S3",
		.id = MTK_AFE_IO_4TH_I2S,
		.playback = {
			.stream_name = "I2S3 Playback",
			.channels_min = 1,
			.channels_max = 2,
			.rates = SNDRV_PCM_RATE_8000_192000,
			.formats = (SNDRV_PCM_FMTBIT_S16_LE
				| SNDRV_PCM_FMTBIT_S24_LE
				| SNDRV_PCM_FMTBIT_S32_LE)
			},
		.capture = {
			.stream_name = "I2S3 Capture",
			.channels_min = 1,
			.channels_max = 2,
			.rates = SNDRV_PCM_RATE_8000_192000,
			.formats = (SNDRV_PCM_FMTBIT_S16_LE
				| SNDRV_PCM_FMTBIT_S24_LE
				| SNDRV_PCM_FMTBIT_S32_LE)
			},
		.ops = &mtk2701_afe_i2s_ops,
		.symmetric_rates = 1,
	},
};

static const struct snd_kcontrol_new mtk2701_afe_o00_mix[] = {
	SOC_DAPM_SINGLE_AUTODISABLE("I00 Switch", AFE_CONN0, 0, 1, 0),
};

static const struct snd_kcontrol_new mtk2701_afe_o01_mix[] = {
	SOC_DAPM_SINGLE_AUTODISABLE("I01 Switch", AFE_CONN1, 1, 1, 0),
};

static const struct snd_kcontrol_new mtk2701_afe_o02_mix[] = {
	SOC_DAPM_SINGLE_AUTODISABLE("I02 Switch", AFE_CONN2, 2, 1, 0),
};

static const struct snd_kcontrol_new mtk2701_afe_o03_mix[] = {
	SOC_DAPM_SINGLE_AUTODISABLE("I03 Switch", AFE_CONN3, 3, 1, 0),
};

static const struct snd_kcontrol_new mtk2701_afe_o15_mix[] = {
	SOC_DAPM_SINGLE_AUTODISABLE("I12 Switch", AFE_CONN15, 12, 1, 0),
};

static const struct snd_kcontrol_new mtk2701_afe_o16_mix[] = {
	SOC_DAPM_SINGLE_AUTODISABLE("I13 Switch", AFE_CONN16, 13, 1, 0),
};

static const struct snd_kcontrol_new mtk2701_afe_o17_mix[] = {
	SOC_DAPM_SINGLE_AUTODISABLE("I14 Switch", AFE_CONN17, 14, 1, 0),
};

static const struct snd_kcontrol_new mtk2701_afe_o18_mix[] = {
	SOC_DAPM_SINGLE_AUTODISABLE("I15 Switch", AFE_CONN18, 15, 1, 0),
};

static const struct snd_kcontrol_new mtk2701_afe_o19_mix[] = {
	SOC_DAPM_SINGLE_AUTODISABLE("I16 Switch", AFE_CONN19, 16, 1, 0),
};

static const struct snd_kcontrol_new mtk2701_afe_o20_mix[] = {
	SOC_DAPM_SINGLE_AUTODISABLE("I17 Switch", AFE_CONN20, 17, 1, 0),
};

static const struct snd_kcontrol_new mtk2701_afe_o21_mix[] = {
	SOC_DAPM_SINGLE_AUTODISABLE("I18 Switch", AFE_CONN21, 18, 1, 0),
};

static const struct snd_kcontrol_new mtk2701_afe_o22_mix[] = {
	SOC_DAPM_SINGLE_AUTODISABLE("I19 Switch", AFE_CONN22, 19, 1, 0),
};

static const struct snd_kcontrol_new mtk2701_afe_o23_mix[] = {
	SOC_DAPM_SINGLE_AUTODISABLE("I20 Switch", AFE_CONN23, 20, 1, 0),
};

static const struct snd_kcontrol_new mtk2701_afe_o24_mix[] = {
	SOC_DAPM_SINGLE_AUTODISABLE("I21 Switch", AFE_CONN24, 21, 1, 0),
};

static const struct snd_kcontrol_new mtk2701_afe_multi_ch_out_i2s0[] = {
	SOC_DAPM_SINGLE_AUTODISABLE("Multi ch Out I2s0", ASYS_I2SO1_CON, 26, 1,
				    0),
};

static const struct snd_kcontrol_new mtk2701_afe_multi_ch_out_i2s1[] = {
	SOC_DAPM_SINGLE_AUTODISABLE("Multi ch Out I2s1", ASYS_I2SO2_CON, 26, 1,
				    0),
};

static const struct snd_kcontrol_new mtk2701_afe_multi_ch_out_i2s2[] = {
	SOC_DAPM_SINGLE_AUTODISABLE("Multi ch Out I2s2", PWR2_TOP_CON, 17, 1,
				    0),
};

static const struct snd_kcontrol_new mtk2701_afe_multi_ch_out_i2s3[] = {
	SOC_DAPM_SINGLE_AUTODISABLE("Multi ch Out I2s3", PWR2_TOP_CON, 18, 1,
				    0),
};

static const struct snd_kcontrol_new mtk2701_afe_multi_ch_out_i2s4[] = {
	SOC_DAPM_SINGLE_AUTODISABLE("Multi ch Out I2s4", PWR2_TOP_CON, 19, 1,
				    0),
};

static const struct snd_kcontrol_new mtk2701_afe_multi_ch_out_asrc0[] = {
	SOC_DAPM_SINGLE_AUTODISABLE("Multi ch asrc out0", AUDIO_TOP_CON4, 14, 1,
				    1),
};

static const struct snd_kcontrol_new mtk2701_afe_multi_ch_out_asrc1[] = {
	SOC_DAPM_SINGLE_AUTODISABLE("Multi ch asrc out1", AUDIO_TOP_CON4, 15, 1,
				    1),
};

static const struct snd_kcontrol_new mtk2701_afe_multi_ch_out_asrc2[] = {
	SOC_DAPM_SINGLE_AUTODISABLE("Multi ch asrc out2", PWR2_TOP_CON, 6, 1,
				    1),
};

static const struct snd_kcontrol_new mtk2701_afe_multi_ch_out_asrc3[] = {
	SOC_DAPM_SINGLE_AUTODISABLE("Multi ch asrc out3", PWR2_TOP_CON, 7, 1,
				    1),
};

static const struct snd_kcontrol_new mtk2701_afe_multi_ch_out_asrc4[] = {
	SOC_DAPM_SINGLE_AUTODISABLE("Multi ch asrc out4", PWR2_TOP_CON, 8, 1,
				    1),
};

static const struct snd_soc_dapm_widget mtk2701_afe_pcm_widgets[] = {
	/* inter-connections */
	SND_SOC_DAPM_MIXER("I00", SND_SOC_NOPM, 0, 0, NULL, 0),
	SND_SOC_DAPM_MIXER("I01", SND_SOC_NOPM, 0, 0, NULL, 0),
	SND_SOC_DAPM_MIXER("I02", SND_SOC_NOPM, 0, 0, NULL, 0),
	SND_SOC_DAPM_MIXER("I03", SND_SOC_NOPM, 0, 0, NULL, 0),
	SND_SOC_DAPM_MIXER("I12", SND_SOC_NOPM, 0, 0, NULL, 0),
	SND_SOC_DAPM_MIXER("I13", SND_SOC_NOPM, 0, 0, NULL, 0),
	SND_SOC_DAPM_MIXER("I14", SND_SOC_NOPM, 0, 0, NULL, 0),
	SND_SOC_DAPM_MIXER("I15", SND_SOC_NOPM, 0, 0, NULL, 0),
	SND_SOC_DAPM_MIXER("I16", SND_SOC_NOPM, 0, 0, NULL, 0),
	SND_SOC_DAPM_MIXER("I17", SND_SOC_NOPM, 0, 0, NULL, 0),
	SND_SOC_DAPM_MIXER("I18", SND_SOC_NOPM, 0, 0, NULL, 0),
	SND_SOC_DAPM_MIXER("I19", SND_SOC_NOPM, 0, 0, NULL, 0),

	SND_SOC_DAPM_MIXER("O00", SND_SOC_NOPM, 0, 0, mtk2701_afe_o00_mix,
			   ARRAY_SIZE(mtk2701_afe_o00_mix)),
	SND_SOC_DAPM_MIXER("O01", SND_SOC_NOPM, 0, 0, mtk2701_afe_o01_mix,
			   ARRAY_SIZE(mtk2701_afe_o01_mix)),
	SND_SOC_DAPM_MIXER("O02", SND_SOC_NOPM, 0, 0, mtk2701_afe_o02_mix,
			   ARRAY_SIZE(mtk2701_afe_o02_mix)),
	SND_SOC_DAPM_MIXER("O03", SND_SOC_NOPM, 0, 0, mtk2701_afe_o03_mix,
			   ARRAY_SIZE(mtk2701_afe_o03_mix)),
	SND_SOC_DAPM_MIXER("O15", SND_SOC_NOPM, 0, 0, mtk2701_afe_o15_mix,
			   ARRAY_SIZE(mtk2701_afe_o15_mix)),
	SND_SOC_DAPM_MIXER("O16", SND_SOC_NOPM, 0, 0, mtk2701_afe_o16_mix,
			   ARRAY_SIZE(mtk2701_afe_o16_mix)),
	SND_SOC_DAPM_MIXER("O17", SND_SOC_NOPM, 0, 0, mtk2701_afe_o17_mix,
			   ARRAY_SIZE(mtk2701_afe_o17_mix)),
	SND_SOC_DAPM_MIXER("O18", SND_SOC_NOPM, 0, 0, mtk2701_afe_o18_mix,
			   ARRAY_SIZE(mtk2701_afe_o18_mix)),
	SND_SOC_DAPM_MIXER("O19", SND_SOC_NOPM, 0, 0, mtk2701_afe_o19_mix,
			   ARRAY_SIZE(mtk2701_afe_o19_mix)),
	SND_SOC_DAPM_MIXER("O20", SND_SOC_NOPM, 0, 0, mtk2701_afe_o20_mix,
			   ARRAY_SIZE(mtk2701_afe_o20_mix)),
	SND_SOC_DAPM_MIXER("O21", SND_SOC_NOPM, 0, 0, mtk2701_afe_o21_mix,
			   ARRAY_SIZE(mtk2701_afe_o21_mix)),
	SND_SOC_DAPM_MIXER("O22", SND_SOC_NOPM, 0, 0, mtk2701_afe_o22_mix,
			   ARRAY_SIZE(mtk2701_afe_o22_mix)),
	SND_SOC_DAPM_MIXER("I12I13", SND_SOC_NOPM, 0, 0,
			   mtk2701_afe_multi_ch_out_i2s0,
			   ARRAY_SIZE(mtk2701_afe_multi_ch_out_i2s0)),
	SND_SOC_DAPM_MIXER("I14I15", SND_SOC_NOPM, 0, 0,
			   mtk2701_afe_multi_ch_out_i2s1,
			   ARRAY_SIZE(mtk2701_afe_multi_ch_out_i2s1)),
	SND_SOC_DAPM_MIXER("I16I17", SND_SOC_NOPM, 0, 0,
			   mtk2701_afe_multi_ch_out_i2s2,
			   ARRAY_SIZE(mtk2701_afe_multi_ch_out_i2s2)),
	SND_SOC_DAPM_MIXER("I18I19", SND_SOC_NOPM, 0, 0,
			   mtk2701_afe_multi_ch_out_i2s3,
			   ARRAY_SIZE(mtk2701_afe_multi_ch_out_i2s3)),

	SND_SOC_DAPM_MIXER("ASRC_O0", SND_SOC_NOPM, 0, 0,
			   mtk2701_afe_multi_ch_out_asrc0,
			   ARRAY_SIZE(mtk2701_afe_multi_ch_out_asrc0)),
	SND_SOC_DAPM_MIXER("ASRC_O1", SND_SOC_NOPM, 0, 0,
			   mtk2701_afe_multi_ch_out_asrc1,
			   ARRAY_SIZE(mtk2701_afe_multi_ch_out_asrc1)),
	SND_SOC_DAPM_MIXER("ASRC_O2", SND_SOC_NOPM, 0, 0,
			   mtk2701_afe_multi_ch_out_asrc2,
			   ARRAY_SIZE(mtk2701_afe_multi_ch_out_asrc2)),
	SND_SOC_DAPM_MIXER("ASRC_O3", SND_SOC_NOPM, 0, 0,
			   mtk2701_afe_multi_ch_out_asrc3,
			   ARRAY_SIZE(mtk2701_afe_multi_ch_out_asrc3)),
};

static const struct snd_soc_dapm_route mtk2701_afe_pcm_routes[] = {
	{"I12", NULL, "DL1"},
	{"I13", NULL, "DL1"},
	{"I2S0 Playback", NULL, "O15"},
	{"I2S0 Playback", NULL, "O16"},
	{"I2S1 Playback", NULL, "O17"},
	{"I2S1 Playback", NULL, "O18"},
	{"I2S2 Playback", NULL, "O19"},
	{"I2S2 Playback", NULL, "O20"},
	{"I2S3 Playback", NULL, "O21"},
	{"I2S3 Playback", NULL, "O22"},

	{"UL1", NULL, "O00"},
	{"UL1", NULL, "O01"},
	{"UL2", NULL, "O02"},
	{"UL2", NULL, "O03"},
	{"I00", NULL, "I2S0 Capture"},
	{"I01", NULL, "I2S0 Capture"},

	{"I02", NULL, "I2S1 Capture"},
	{"I03", NULL, "I2S1 Capture"},
	/*I02,03 link to UL2, also need to open I2S0*/
	{"I02", NULL, "I2S0 Capture"},
	{"I03", NULL, "I2S0 Capture"},

	{"ASRC_O0", "Multi ch asrc out0", "DLM"},
	{"ASRC_O1", "Multi ch asrc out1", "DLM"},
	{"ASRC_O2", "Multi ch asrc out2", "DLM"},
	{"ASRC_O3", "Multi ch asrc out3", "DLM"},

	{"I12I13", "Multi ch Out I2s0", "ASRC_O0"},
	{"I14I15", "Multi ch Out I2s1", "ASRC_O1"},
	{"I16I17", "Multi ch Out I2s2", "ASRC_O2"},
	{"I18I19", "Multi ch Out I2s3", "ASRC_O3"},

	{ "I12", NULL, "I12I13" },
	{ "I13", NULL, "I12I13" },
	{ "I14", NULL, "I14I15" },
	{ "I15", NULL, "I14I15" },
	{ "I16", NULL, "I16I17" },
	{ "I17", NULL, "I16I17" },
	{ "I18", NULL, "I18I19" },
	{ "I19", NULL, "I18I19" },

	{ "O00", "I00 Switch", "I00" },
	{ "O01", "I01 Switch", "I01" },
	{ "O02", "I02 Switch", "I02" },
	{ "O03", "I03 Switch", "I03" },

	{ "O15", "I12 Switch", "I12" },
	{ "O16", "I13 Switch", "I13" },
	{ "O17", "I14 Switch", "I14" },
	{ "O18", "I15 Switch", "I15" },
	{ "O19", "I16 Switch", "I16" },
	{ "O20", "I17 Switch", "I17" },
	{ "O21", "I18 Switch", "I18" },
	{ "O22", "I19 Switch", "I19" },
};

static const struct snd_soc_component_driver mtk2701_afe_pcm_dai_component = {
	.name = "mtk-afe-pcm-dai",
	.dapm_widgets = mtk2701_afe_pcm_widgets,
	.num_dapm_widgets = ARRAY_SIZE(mtk2701_afe_pcm_widgets),
	.dapm_routes = mtk2701_afe_pcm_routes,
	.num_dapm_routes = ARRAY_SIZE(mtk2701_afe_pcm_routes),
};

static const struct mtk_afe_memif_data
		    memif_data[MTK_AFE_MEMIF_NUM][MTK_MEMIF_STREAM_NUM] = {
	{
		{
			.name = "DL1",
			.id = MTK_AFE_MEMIF_1,
			.reg_ofs_base = AFE_DL1_BASE,
			.reg_ofs_cur = AFE_DL1_CUR,
			.fs_reg = AFE_DAC_CON1,
			.fs_shift = 0,
			.mono_reg = AFE_DAC_CON3,
			.mono_shift = 16,
			.enable_shift = 1,
			.hd_reg = AFE_MEMIF_HD_CON0,
			.hd_shift = 0,
			.agent_disable_shift = 6,
		},
		{
			.name = "UL1",
			.id = MTK_AFE_MEMIF_1,
			.reg_ofs_base = AFE_VUL_BASE,
			.reg_ofs_cur = AFE_VUL_CUR,
			.fs_reg = AFE_DAC_CON2,
			.fs_shift = 0,
			.mono_reg = AFE_DAC_CON4,
			.mono_shift = 0,
			.enable_shift = 10,
			.hd_reg = AFE_MEMIF_HD_CON1,
			.hd_shift = 0,
			.agent_disable_shift = 0,
		}
	},
	{
		{
			.name = "DL2",
			.id = MTK_AFE_MEMIF_2,
			.reg_ofs_base = AFE_DL2_BASE,
			.reg_ofs_cur = AFE_DL2_CUR,
			.fs_reg = AFE_DAC_CON1,
			.fs_shift = 5,
			.mono_reg = AFE_DAC_CON3,
			.mono_shift = 17,
			.enable_shift = 2,
			.hd_reg = AFE_MEMIF_HD_CON0,
			.hd_shift = 2,
			.agent_disable_shift = 7,
		},
		{
			.name = "UL2",
			.id = MTK_AFE_MEMIF_2,
			.reg_ofs_base = AFE_UL2_BASE,
			.reg_ofs_cur = AFE_UL2_CUR,
			.fs_reg = AFE_DAC_CON2,
			.fs_shift = 5,
			.mono_reg = AFE_DAC_CON4,
			.mono_shift = 2,
			.enable_shift = 11,
			.hd_reg = AFE_MEMIF_HD_CON1,
			.hd_shift = 2,
			.agent_disable_shift = 1,
		}
	},
	{
		{
			.name = "DL3",
			.id = MTK_AFE_MEMIF_3,
			.reg_ofs_base = AFE_DL3_BASE,
			.reg_ofs_cur = AFE_DL3_CUR,
			.fs_reg = AFE_DAC_CON1,
			.fs_shift = 10,
			.mono_reg = AFE_DAC_CON3,
			.mono_shift = 18,
			.enable_shift = 3,
			.hd_reg = AFE_MEMIF_HD_CON0,
			.hd_shift = 4,
			.agent_disable_shift = 8,
		},
		{
			.name = "UL3",
			.id = MTK_AFE_MEMIF_3,
			.reg_ofs_base = AFE_UL3_BASE,
			.reg_ofs_cur = AFE_UL3_CUR,
			.fs_reg = AFE_DAC_CON2,
			.fs_shift = 10,
			.mono_reg = AFE_DAC_CON4,
			.mono_shift = 4,
			.enable_shift = 12,
			.hd_reg = AFE_MEMIF_HD_CON0,
			.hd_shift = 0,
			.agent_disable_shift = 2,
		}
	},
	{
		{
			.name = "DL4",
			.id = MTK_AFE_MEMIF_4,
			.reg_ofs_base = AFE_DL4_BASE,
			.reg_ofs_cur = AFE_DL4_CUR,
			.fs_reg = AFE_DAC_CON1,
			.fs_shift = 15,
			.mono_reg = AFE_DAC_CON3,
			.mono_shift = 19,
			.enable_shift = 4,
			.hd_reg = AFE_MEMIF_HD_CON0,
			.hd_shift = 6,
			.agent_disable_shift = 9,
		},
		{
			.name = "UL4",
			.id = MTK_AFE_MEMIF_4,
			.reg_ofs_base = AFE_UL4_BASE,
			.reg_ofs_cur = AFE_UL4_CUR,
			.fs_reg = AFE_DAC_CON2,
			.fs_shift = 15,
			.mono_reg = AFE_DAC_CON4,
			.mono_shift = 6,
			.enable_shift = 13,
			.hd_reg = AFE_MEMIF_HD_CON0,
			.hd_shift = 6,
			.agent_disable_shift = 3,
		}
	},
	{
		{
			.name = "DL5",
			.id = MTK_AFE_MEMIF_5,
			.reg_ofs_base = AFE_DL5_BASE,
			.reg_ofs_cur = AFE_DL5_CUR,
			.fs_reg = AFE_DAC_CON1,
			.fs_shift = 20,
			.mono_reg = AFE_DAC_CON3,
			.mono_shift = 20,
			.enable_shift = 5,
			.hd_reg = AFE_MEMIF_HD_CON0,
			.hd_shift = 8,
			.agent_disable_shift = 10,
		},
		{
			.name = "UL5",
			.id = MTK_AFE_MEMIF_5,
			.reg_ofs_base = AFE_UL5_BASE,
			.reg_ofs_cur = AFE_UL5_CUR,
			.fs_reg = AFE_DAC_CON2,
			.fs_shift = 20,
			.mono_reg = AFE_DAC_CON4,
			.mono_shift = 8,
			.enable_shift = 14,
			.hd_reg = AFE_MEMIF_HD_CON0,
			.hd_shift = 8,
			.agent_disable_shift = 4,
		}
	},
	{
		{
			.name = "DLM",
			.id = MTK_AFE_MEMIF_M,
			.reg_ofs_base = AFE_DLMCH_BASE,
			.reg_ofs_cur = AFE_DLMCH_CUR,
			.fs_reg = AFE_DAC_CON1,
			.fs_shift = 0,
			.mono_reg = -1,
			.mono_shift = -1,
			.enable_shift = 7,
			.hd_reg = AFE_MEMIF_PBUF_SIZE,
			.hd_shift = 28,
			.agent_disable_shift = 12,
		},
		{
		}
	}
};

static const struct mtk_afe_irq_data irq_data[IRQ_NUM] = {
	{
		.irq_id = IRQ_ASYS_IRQ1,
		.irq_cnt_reg = ASYS_IRQ1_CON,
		.irq_cnt_shift = 0,
		.irq_cnt_maskbit = 0xffffff,
		.irq_fs_reg = ASYS_IRQ1_CON,
		.irq_fs_shift = 24,
		.irq_fs_maskbit = 0x1f,
		.irq_en_reg = ASYS_IRQ1_CON,
		.irq_en_shift = 31,
	},
	{
		.irq_id = IRQ_ASYS_IRQ2,
		.irq_cnt_reg = ASYS_IRQ2_CON,
		.irq_cnt_shift = 0,
		.irq_cnt_maskbit = 0xffffff,
		.irq_fs_reg = ASYS_IRQ2_CON,
		.irq_fs_shift = 24,
		.irq_fs_maskbit = 0x1f,
		.irq_en_reg = ASYS_IRQ2_CON,
		.irq_en_shift = 31,
	},
	{
		.irq_id = IRQ_ASYS_IRQ3,
		.irq_cnt_reg = ASYS_IRQ3_CON,
		.irq_cnt_shift = 0,
		.irq_cnt_maskbit = 0xffffff,
		.irq_fs_reg = ASYS_IRQ3_CON,
		.irq_fs_shift = 24,
		.irq_fs_maskbit = 0x1f,
		.irq_en_reg = ASYS_IRQ3_CON,
		.irq_en_shift = 31,
	}
};

static const struct mtk_i2s_data mtk2701_i2s_data[MTK_I2S_NUM][2] = {
	{
		{
			.i2s_ctrl_reg = ASYS_I2SO1_CON,
			.i2s_pwn_shift = 6,
			.i2s_asrc_fs_shift = 0,
			.i2s_asrc_fs_mask = 0x1f,

		},
		{
			.i2s_ctrl_reg = ASYS_I2SIN1_CON,
			.i2s_pwn_shift = 0,
			.i2s_asrc_fs_shift = 0,
			.i2s_asrc_fs_mask = 0x1f,

		},
	},
	{
		{
			.i2s_ctrl_reg = ASYS_I2SO2_CON,
			.i2s_pwn_shift = 7,
			.i2s_asrc_fs_shift = 5,
			.i2s_asrc_fs_mask = 0x1f,

		},
		{
			.i2s_ctrl_reg = ASYS_I2SIN2_CON,
			.i2s_pwn_shift = 1,
			.i2s_asrc_fs_shift = 5,
			.i2s_asrc_fs_mask = 0x1f,

		},
	},
	{
		{
			.i2s_ctrl_reg = ASYS_I2SO3_CON,
			.i2s_pwn_shift = 8,
			.i2s_asrc_fs_shift = 10,
			.i2s_asrc_fs_mask = 0x1f,

		},
		{
			.i2s_ctrl_reg = ASYS_I2SIN3_CON,
			.i2s_pwn_shift = 2,
			.i2s_asrc_fs_shift = 10,
			.i2s_asrc_fs_mask = 0x1f,

		},
	},
	{
		{
			.i2s_ctrl_reg = ASYS_I2SO4_CON,
			.i2s_pwn_shift = 9,
			.i2s_asrc_fs_shift = 15,
			.i2s_asrc_fs_mask = 0x1f,

		},
		{
			.i2s_ctrl_reg = ASYS_I2SIN4_CON,
			.i2s_pwn_shift = 3,
			.i2s_asrc_fs_shift = 15,
			.i2s_asrc_fs_mask = 0x1f,

		},
	},
};

static struct audio_clock_attr_data aud_clks_data[CLOCK_NUM] = {
	[AUDCLK_INFRA_SYS_AUDIO] = {"infra_sys_audio_clk", true},
	[AUDCLK_TOP_AUD_MUX1_SEL] = {"top_audio_mux1_sel", false},
	[AUDCLK_TOP_AUD_MUX2_SEL] = {"top_audio_mux2_sel", false},
	[AUDCLK_TOP_AUD_MUX1_DIV] = {"top_audio_mux1_div", false},
	[AUDCLK_TOP_AUD_MUX2_DIV] = {"top_audio_mux2_div", false},
	[AUDCLK_TOP_AUD_48K_TIMING] = {"top_audio_48k_timing", true},
	[AUDCLK_TOP_AUD_44K_TIMING] = {"top_audio_44k_timing", true},
	[AUDCLK_TOP_AUDPLL_MUX_SEL] = {"top_audpll_mux_sel", false},
	[AUDCLK_TOP_APLL_SEL] = {"top_apll_sel", false},
	[AUDCLK_TOP_AUD1PLL_98M] = {"top_aud1_pll_98M", false},
	[AUDCLK_TOP_AUD2PLL_90M] = {"top_aud2_pll_90M", false},
	[AUDCLK_TOP_HADDS2PLL_98M] = {"top_hadds2_pll_98M", false},
	[AUDCLK_TOP_HADDS2PLL_294M] = {"top_hadds2_pll_294M", false},
	[AUDCLK_TOP_AUDPLL] = {"top_audpll", false},
	[AUDCLK_TOP_AUDPLL_D4] = {"top_audpll_d4", false},
	[AUDCLK_TOP_AUDPLL_D8] = {"top_audpll_d8", false},
	[AUDCLK_TOP_AUDPLL_D16] = {"top_audpll_d16", false},
	[AUDCLK_TOP_AUDPLL_D24] = {"top_audpll_d24", false},
	[AUDCLK_TOP_AUDINTBUS] = {"top_audintbus_sel", false},
	[AUDCLK_CLK_26M] = {"clk_26m", false },
	[AUDCLK_TOP_SYSPLL1_D4] = {"top_syspll1_d4", false},
	[AUDCLK_TOP_AUD_K1_SRC_SEL] = {"top_aud_k1_src_sel", false},
	[AUDCLK_TOP_AUD_K2_SRC_SEL] = {"top_aud_k2_src_sel", false},
	[AUDCLK_TOP_AUD_K3_SRC_SEL] = {"top_aud_k3_src_sel", false},
	[AUDCLK_TOP_AUD_K4_SRC_SEL] = {"top_aud_k4_src_sel", false},
	[AUDCLK_TOP_AUD_K5_SRC_SEL] = {"top_aud_k5_src_sel", false},
	[AUDCLK_TOP_AUD_K6_SRC_SEL] = {"top_aud_k6_src_sel", false},
	[AUDCLK_TOP_AUD_K1_SRC_DIV] = {"top_aud_k1_src_div", false},
	[AUDCLK_TOP_AUD_K2_SRC_DIV] = {"top_aud_k2_src_div", false},
	[AUDCLK_TOP_AUD_K3_SRC_DIV] = {"top_aud_k3_src_div", false},
	[AUDCLK_TOP_AUD_K4_SRC_DIV] = {"top_aud_k4_src_div", false},
	[AUDCLK_TOP_AUD_K5_SRC_DIV] = {"top_aud_k5_src_div", false},
	[AUDCLK_TOP_AUD_K6_SRC_DIV] = {"top_aud_k6_src_div", false},
	[AUDCLK_TOP_AUD_I2S1_MCLK] = {"top_aud_i2s1_mclk", true},
	[AUDCLK_TOP_AUD_I2S2_MCLK] = {"top_aud_i2s2_mclk", true},
	[AUDCLK_TOP_AUD_I2S3_MCLK] = {"top_aud_i2s3_mclk", true},
	[AUDCLK_TOP_AUD_I2S4_MCLK] = {"top_aud_i2s4_mclk", true},
	[AUDCLK_TOP_AUD_I2S5_MCLK] = {"top_aud_i2s5_mclk", true},
	[AUDCLK_TOP_AUD_I2S6_MCLK] = {"top_aud_i2s6_mclk", true},
	[AUDCLK_TOP_ASM_M_SEL] = {"top_asm_m_sel", false},
	[AUDCLK_TOP_ASM_H_SEL] = {"top_asm_h_sel", false},
	[AUDCLK_TOP_UNIVPLL2_D4] = {"top_univpll2_d4", false},
	[AUDCLK_TOP_UNIVPLL2_D2] = {"top_univpll2_d2", false},
	[AUDCLK_TOP_SYSPLL_D5] = {"top_syspll_d5", false},
};

static const struct regmap_config mtk2701_afe_regmap_config = {
	.reg_bits = 32,
	.reg_stride = 4,
	.val_bits = 32,
	.max_register = AFE_END_ADDR,
	.cache_type = REGCACHE_NONE,
};

static irqreturn_t mtk2701_asys_isr(int irq_id, void *dev)
{
	int id;
	struct mtk_afe *afe = dev;
	struct mtk_afe_irq *irq;
	u32 status;

	status = mtk2701_asys_irq_status(afe);
	mtk2701_asys_irq_clear(afe, status);

	for (id = IRQ_ASYS_START; id < IRQ_ASYS_END; ++id) {
		irq = &afe->irqs[id];
		if (status & (0x1 << (id - IRQ_ASYS_START)) && irq->isr)
			irq->isr(afe, irq->memif);
	}
	return IRQ_HANDLED;
}

static int mtk2701_afe_runtime_suspend(struct device *dev)
{
	struct mtk_afe *afe = dev_get_drvdata(dev);

	mtk2701_afe_enable_clock(afe, 0);
	return 0;
}

static int mtk2701_afe_runtime_resume(struct device *dev)
{
	struct mtk_afe *afe = dev_get_drvdata(dev);

	pr_warn("%s\n", __func__);
	mtk2701_afe_enable_clock(afe, 1);
	return 0;
}

static int mtk2701_afe_init_audio_clk(struct mtk_afe *afe)
{
	size_t i;
	int ret = 0;
	struct audio_clock_attr *aud_clks = afe->aud_clks;

	for (i = 0; i < CLOCK_NUM; i++) {
		aud_clks[i].clock = devm_clk_get(afe->dev,
						 aud_clks[i].clock_data->name);
		if (IS_ERR(aud_clks[i].clock)) {
			dev_err(afe->dev, "%s devm_clk_get %s fail\n",
				__func__, aud_clks[i].clock_data->name);
			return PTR_ERR(aud_clks[i].clock);
		}
	}
	for (i = 0; i < CLOCK_NUM; i++) {
		if (aud_clks[i].clock_data->prepare_once) {
			ret = clk_prepare(aud_clks[i].clock);
			if (ret) {
				dev_err(afe->dev, "%s clk_prepare %s fail %d\n",
					__func__, aud_clks[i].clock_data->name,
				       ret);
				break;
			}
			aud_clks[i].is_prepared = true;
		}
	}
	return ret;
}

static int mtk2701_afe_pcm_dev_probe(struct platform_device *pdev)
{
	int ret, i, j;
	unsigned int irq_id;
	struct mtk_afe *afe;
	struct resource *res;

	ret = 0;
	afe = devm_kzalloc(&pdev->dev, sizeof(*afe), GFP_KERNEL);
	if (!afe)
		return -ENOMEM;

	afe->dev = &pdev->dev;
/* need for BT*/
/*
	irq_id = platform_get_irq(pdev, 0);
	if (!irq_id) {
		dev_err(afe->dev, "np %s no first irq\n", afe->dev->of_node->name);
		return -ENXIO;
	}

	//TODO, change it to no flag.
	//TODO check irq handler
	ret = devm_request_irq(afe->dev, irq_id, mtk_afe_irq_handler,
			       IRQF_TRIGGER_LOW, "afe-isr", (void *)afe);
	if (ret) {
		dev_err(afe->dev, "could not request_irq for afe-isr\n");
		return ret;
	}
*/
	irq_id = platform_get_irq(pdev, 1);
	if (!irq_id) {
		dev_err(afe->dev, "%s no second irq\n",
			afe->dev->of_node->name);
		return -ENXIO;
	}
	ret = devm_request_irq(afe->dev, irq_id, mtk2701_asys_isr,
			       IRQF_TRIGGER_NONE, "asys-isr", (void *)afe);
	if (ret) {
		dev_err(afe->dev, "could not request_irq for asys-isr\n");
		return ret;
	}

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);

	afe->base_addr = devm_ioremap_resource(&pdev->dev, res);

	if (IS_ERR(afe->base_addr))
		return PTR_ERR(afe->base_addr);

	afe->regmap = devm_regmap_init_mmio(&pdev->dev, afe->base_addr,
		&mtk2701_afe_regmap_config);
	if (IS_ERR(afe->regmap))
		return PTR_ERR(afe->regmap);

	for (i = 0; i < MTK_AFE_MEMIF_NUM; i++)
		for (j = 0; j < MTK_MEMIF_STREAM_NUM; ++j)
			afe->memif[i][j].data = &memif_data[i][j];
	for (i = 0; i < IRQ_NUM; i++)
		afe->irqs[i].irq_data = &irq_data[i];

	for (i = 0; i < CLOCK_NUM; i++)
		afe->aud_clks[i].clock_data = &aud_clks_data[i];

	for (i = 0; i < MTK_I2S_NUM; i++) {
		afe->i2s_path[i].i2s_data[I2S_OUT]
			= &mtk2701_i2s_data[i][I2S_OUT];
		afe->i2s_path[i].i2s_data[I2S_IN]
			= &mtk2701_i2s_data[i][I2S_IN];
	}

	/* initial audio related clock */
	ret = mtk2701_afe_init_audio_clk(afe);
	platform_set_drvdata(pdev, afe);

	ret = snd_soc_register_platform(&pdev->dev, &mtk2701_afe_pcm_platform);
	if (ret) {
		dev_warn(afe->dev, "err_platform\n");
		goto err_platform;
	}

	ret = snd_soc_register_component(&pdev->dev,
					 &mtk2701_afe_pcm_dai_component,
					 mtk2701_afe_pcm_dais,
					 ARRAY_SIZE(mtk2701_afe_pcm_dais));
	if (ret) {
		dev_warn(afe->dev, "err_dai_component\n");
		goto err_dai_component;
	}
	/*enable afe clock*/
	mtk2701_afe_enable_clock(afe, 1);
	return 0;
err_platform:
	snd_soc_unregister_platform(&pdev->dev);
err_dai_component:
	snd_soc_unregister_component(&pdev->dev);
	return ret;
}

static int mtk2701_afe_pcm_dev_remove(struct platform_device *pdev)
{
	struct mtk_afe *afe = platform_get_drvdata(pdev);

	snd_soc_unregister_component(&pdev->dev);
	snd_soc_unregister_platform(&pdev->dev);
	/*disable afe clock*/
	mtk2701_afe_enable_clock(afe, 0);
	return 0;
}

static const struct of_device_id mtk2701_afe_pcm_dt_match[] = {
	{ .compatible = "mediatek,mt2701-audio", }
};
MODULE_DEVICE_TABLE(of, mtk2701_afe_pcm_dt_match);

static const struct dev_pm_ops mtk2701_afe_pm_ops = {
	SET_RUNTIME_PM_OPS(mtk2701_afe_runtime_suspend,
			   mtk2701_afe_runtime_resume, NULL)
};

static struct platform_driver mtk2701_afe_pcm_driver = {
	.driver = {
		   .name = "mt2701-audio",
		   .owner = THIS_MODULE,
		   .of_match_table = mtk2701_afe_pcm_dt_match,
#ifdef CONFIG_PM
		   .pm = &mtk2701_afe_pm_ops,
#endif
	},
	.probe = mtk2701_afe_pcm_dev_probe,
	.remove = mtk2701_afe_pcm_dev_remove,
};

module_platform_driver(mtk2701_afe_pcm_driver);

MODULE_DESCRIPTION("Mediatek ALSA SoC AFE platform driver for 2701");
MODULE_AUTHOR("Garlic Tseng <garlic.tseng@mediatek.com>");
MODULE_LICENSE("GPL v2");
