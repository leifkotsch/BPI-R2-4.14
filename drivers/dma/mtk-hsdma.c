/*
 * Driver for Mediatek High-Speed DMA Controller
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
#include <linux/delay.h>
#include <linux/dmaengine.h>
#include <linux/dma-mapping.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/iopoll.h>
#include <linux/jiffies.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/of_dma.h>
#include <linux/platform_device.h>
#include <linux/slab.h>

#include "virt-dma.h"

#define MTK_DMA_DEV KBUILD_MODNAME

#define MTK_HSDMA_USEC_POLL		20
#define MTK_HSDMA_TIMEOUT_POLL		200000

#define MTK_HSDMA_DMA_BUSWIDTHS (BIT(DMA_SLAVE_BUSWIDTH_UNDEFINED) | \
				 BIT(DMA_SLAVE_BUSWIDTH_1_BYTE) | \
				 BIT(DMA_SLAVE_BUSWIDTH_2_BYTES) | \
				 BIT(DMA_SLAVE_BUSWIDTH_4_BYTES))

/* Max size of data one descriptor can move */
#define MTK_DMA_MAX_DATA_ITEMS		0x3fff

/* The default number of virtual channel */
#define MTK_DMA_MAX_VCHANNELS		3

/* MTK_DMA_SIZE must be 2 of power and 4 for the minimal */
#define MTK_DMA_SIZE			256
#define MTK_HSDMA_NEXT_DESP_IDX(x, y)	(((x) + 1) & ((y) - 1))
#define MTK_HSDMA_PREV_DESP_IDX(x, y)	(((x) - 1) & ((y) - 1))
#define MTK_HSDMA_MAX_LEN		0x3f80
#define MTK_HSDMA_ALIGN_SIZE		4
#define MTK_HSDMA_TIMEOUT		HZ

/* Registers and related fields definition */
#define MTK_HSDMA_TX_BASE		0x0
#define MTK_HSDMA_TX_CNT		0x4
#define MTK_HSDMA_TX_CPU		0x8
#define MTK_HSDMA_TX_DMA		0xc
#define MTK_HSDMA_RX_BASE		0x100
#define MTK_HSDMA_RX_CNT		0x104
#define MTK_HSDMA_RX_CPU		0x108
#define MTK_HSDMA_RX_DMA		0x10c
#define MTK_HSDMA_INFO			0x200
#define MTK_HSDMA_GLO			0x204
#define MTK_HSDMA_GLO_TX2B_OFFSET	BIT(31)
#define MTK_HSDMA_GLO_MULTI_DMA		BIT(10)
#define MTK_HSDMA_TX_WB_DDONE		BIT(6)
#define MTK_HSDMA_BURST_64BYTES		(0x2 << 4)
#define MTK_HSDMA_BURST_32BYTES		(0x1 << 4)
#define MTK_HSDMA_BURST_16BYTES		(0x0 << 4)
#define MTK_HSDMA_GLO_RX_BUSY		BIT(3)
#define MTK_HSDMA_GLO_RX_DMA		BIT(2)
#define MTK_HSDMA_GLO_TX_BUSY		BIT(1)
#define MTK_HSDMA_GLO_TX_DMA		BIT(0)
#define MTK_HSDMA_GLO_DMA		(MTK_HSDMA_GLO_TX_DMA |\
					 MTK_HSDMA_GLO_RX_DMA)
#define MTK_HSDMA_GLO_BUSY		(MTK_HSDMA_GLO_RX_BUSY |\
					 MTK_HSDMA_GLO_TX_BUSY)
#define MTK_HSDMA_GLO_DEFAULT		(MTK_HSDMA_GLO_TX_DMA | \
					 MTK_HSDMA_GLO_RX_DMA | \
					 MTK_HSDMA_TX_WB_DDONE | \
					 MTK_HSDMA_BURST_64BYTES | \
					 MTK_HSDMA_GLO_MULTI_DMA)
#define MTK_HSDMA_RESET			0x208
#define MTK_HSDMA_RST_TX		BIT(0)
#define MTK_HSDMA_RST_RX		BIT(16)
#define MTK_HSDMA_DLYINT		0x20c
#define MTK_HSDMA_RXDLY_INT_EN		BIT(15)
#define MTK_HSDMA_RXMAX_PINT(x)		(((x) & 0x7f) << 8)
#define MTK_HSDMA_RXMAX_PTIME(x)	(((x) & 0xff))
#define MTK_HSDMA_DLYINT_DEFAULT	(MTK_HSDMA_RXDLY_INT_EN |\
					 MTK_HSDMA_RXMAX_PINT(30) |\
					 MTK_HSDMA_RXMAX_PINT(50))
#define MTK_HSDMA_FREEQ_THR		0x210
#define MTK_HSDMA_INT_STATUS		0x220
#define MTK_HSDMA_INT_ENABLE		0x228
#define MTK_HSDMA_INT_RXDONE		BIT(16)
#define MTK_HSDMA_PLEN_MASK		0x3fff
#define MTK_HSDMA_DESC_DDONE		BIT(31)
#define MTK_HSDMA_DESC_LS0		BIT(30)
#define MTK_HSDMA_DESC_PLEN(x)		(((x) & MTK_HSDMA_PLEN_MASK) << 16)

enum mtk_hsdma_cb_flags {
	VDESC_FINISHED	= 0x01,
};

#define IS_VDESC_FINISHED(x) ((x) == VDESC_FINISHED)

struct mtk_hsdma_device;

/* The placement of descriptors should be kept at 4-bytes alignment */
struct mtk_hsdma_pdesc {
	__le32 des1;
	__le32 des2;
	__le32 des3;
	__le32 des4;
} __packed __aligned(4);

struct mtk_hsdma_cb {
	struct virt_dma_desc *vd;
	enum mtk_hsdma_cb_flags flags;
};

struct mtk_hsdma_vdesc {
	struct virt_dma_desc vd;
	size_t len;
	dma_addr_t dest;
	dma_addr_t src;
	u32 num_sgs;
};

struct mtk_hsdma_ring {
	struct mtk_hsdma_pdesc *txd;
	struct mtk_hsdma_pdesc *rxd;
	struct mtk_hsdma_cb *cb;
	dma_addr_t tphys;
	dma_addr_t rphys;
	u16 cur_tptr;
	u16 cur_rptr;
};

struct mtk_hsdma_pchan {
	u32 sz_ring;
	atomic_t free_count;
	struct mtk_hsdma_ring ring;
	struct mtk_hsdma_device *hsdma;
};

struct mtk_hsdma_vchan {
	struct virt_dma_chan vc;
	struct virt_dma_desc *vd_uncompleted;
	struct mtk_hsdma_pchan *pc;
	struct list_head node;
	atomic_t refcnt;
};

struct mtk_hsdma_device {
	struct dma_device ddev;
	void __iomem *base;
	struct clk *clk;
	u32 irq;
	bool busy;

	struct mtk_hsdma_vchan *vc;
	struct mtk_hsdma_pchan pc;
	struct list_head vc_pending;
	struct mtk_hsdma_vchan *vc_uncompleted;

	struct tasklet_struct housekeeping;
	struct tasklet_struct scheduler;
	atomic_t pc_refcnt;
	u32 dma_requests;
	/* Lock used to protect the list vc_pending */
	spinlock_t lock;
};

static struct device *chan2dev(struct dma_chan *chan)
{
	return &chan->dev->device;
}

static struct mtk_hsdma_device *to_hsdma_dev(struct dma_chan *chan)
{
	return container_of(chan->device, struct mtk_hsdma_device,
			    ddev);
}

static inline struct mtk_hsdma_vchan *to_hsdma_vchan(struct dma_chan *chan)
{
	return container_of(chan, struct mtk_hsdma_vchan, vc.chan);
}

static struct mtk_hsdma_vdesc *to_hsdma_vdesc(struct virt_dma_desc *vd)
{
	return container_of(vd, struct mtk_hsdma_vdesc, vd);
}

static struct device *hsdma2dev(struct mtk_hsdma_device *hsdma)
{
	return hsdma->ddev.dev;
}

static u32 mtk_dma_read(struct mtk_hsdma_device *hsdma, u32 reg)
{
	return readl(hsdma->base + reg);
}

static void mtk_dma_write(struct mtk_hsdma_device *hsdma, u32 reg, u32 val)
{
	writel(val, hsdma->base + reg);
}

static void mtk_dma_rmw(struct mtk_hsdma_device *hsdma, u32 reg,
			u32 mask, u32 set)
{
	u32 val;

	val = mtk_dma_read(hsdma, reg);
	val &= ~mask;
	val |= set;
	mtk_dma_write(hsdma, reg, val);
}

static void mtk_dma_set(struct mtk_hsdma_device *hsdma, u32 reg, u32 val)
{
	mtk_dma_rmw(hsdma, reg, 0, val);
}

static void mtk_dma_clr(struct mtk_hsdma_device *hsdma, u32 reg, u32 val)
{
	mtk_dma_rmw(hsdma, reg, val, 0);
}

static void mtk_hsdma_vdesc_free(struct virt_dma_desc *vd)
{
	kfree(container_of(vd, struct mtk_hsdma_vdesc, vd));
}

static int mtk_hsdma_busy_wait(struct mtk_hsdma_device *hsdma)
{
	u32 status = 0;

	return readl_poll_timeout(hsdma->base + MTK_HSDMA_GLO, status,
				  !(status & MTK_HSDMA_GLO_BUSY),
				  MTK_HSDMA_USEC_POLL,
				  MTK_HSDMA_TIMEOUT_POLL);
}

static int mtk_hsdma_alloc_pchan(struct mtk_hsdma_device *hsdma,
				 struct mtk_hsdma_pchan *pc)
{
	int i, ret;
	struct mtk_hsdma_ring *ring = &pc->ring;

	dev_dbg(hsdma2dev(hsdma), "Allocating pchannel\n");

	memset(pc, 0, sizeof(*pc));
	pc->hsdma = hsdma;
	atomic_set(&pc->free_count, MTK_DMA_SIZE - 1);
	pc->sz_ring = 2 * MTK_DMA_SIZE * sizeof(*ring->txd);
	ring->txd = dma_alloc_coherent(hsdma2dev(hsdma),
				       pc->sz_ring, &ring->tphys,
				       GFP_ATOMIC | __GFP_ZERO);
	if (!ring->txd)
		return -ENOMEM;

	memset(ring->txd, 0, pc->sz_ring);
	for (i = 0; i < MTK_DMA_SIZE; i++)
		ring->txd[i].des2 = MTK_HSDMA_DESC_LS0 | MTK_HSDMA_DESC_DDONE;

	ring->cb = kcalloc(MTK_DMA_SIZE, sizeof(*ring->cb), GFP_KERNEL);
	if (!ring->cb) {
		ret = -ENOMEM;
		goto err_free_dma;
	}

	ring->rxd = &ring->txd[MTK_DMA_SIZE];
	ring->rphys = ring->tphys + MTK_DMA_SIZE * sizeof(*ring->txd);
	ring->cur_rptr = MTK_DMA_SIZE - 1;

	mtk_dma_clr(hsdma, MTK_HSDMA_GLO, MTK_HSDMA_GLO_DMA);
	ret = mtk_hsdma_busy_wait(hsdma);
	if (ret < 0)
		goto err_free_cb;

	mtk_dma_write(hsdma, MTK_HSDMA_TX_BASE, ring->tphys);
	mtk_dma_write(hsdma, MTK_HSDMA_TX_CNT, MTK_DMA_SIZE);
	mtk_dma_write(hsdma, MTK_HSDMA_TX_CPU, ring->cur_tptr);
	mtk_dma_write(hsdma, MTK_HSDMA_RX_BASE, ring->rphys);
	mtk_dma_write(hsdma, MTK_HSDMA_RX_CNT, MTK_DMA_SIZE);
	mtk_dma_write(hsdma, MTK_HSDMA_RX_CPU, ring->cur_rptr);
	mtk_dma_set(hsdma, MTK_HSDMA_RESET,
		    MTK_HSDMA_RST_TX | MTK_HSDMA_RST_RX);
	mtk_dma_clr(hsdma, MTK_HSDMA_RESET,
		    MTK_HSDMA_RST_TX | MTK_HSDMA_RST_RX);
	mtk_dma_set(hsdma, MTK_HSDMA_GLO, MTK_HSDMA_GLO_DMA);
	mtk_dma_set(hsdma, MTK_HSDMA_INT_ENABLE, MTK_HSDMA_INT_RXDONE);
	mtk_dma_write(hsdma, MTK_HSDMA_DLYINT, MTK_HSDMA_DLYINT_DEFAULT);

	dev_dbg(hsdma2dev(hsdma), "Allocating pchannel done\n");

	return 0;

err_free_cb:
	kfree(ring->cb);

err_free_dma:
	dma_free_coherent(hsdma2dev(hsdma),
			  pc->sz_ring, ring->txd, ring->tphys);
	return ret;
}

static void mtk_hsdma_free_pchan(struct mtk_hsdma_device *hsdma,
				 struct mtk_hsdma_pchan *pc)
{
	struct mtk_hsdma_ring *ring = &pc->ring;

	dev_dbg(hsdma2dev(hsdma), "Freeing pchannel\n");

	mtk_dma_clr(hsdma, MTK_HSDMA_GLO, MTK_HSDMA_GLO_DMA);

	mtk_hsdma_busy_wait(hsdma);

	mtk_dma_clr(hsdma, MTK_HSDMA_INT_ENABLE, MTK_HSDMA_INT_RXDONE);
	mtk_dma_write(hsdma, MTK_HSDMA_TX_BASE, 0);
	mtk_dma_write(hsdma, MTK_HSDMA_TX_CNT, 0);
	mtk_dma_write(hsdma, MTK_HSDMA_TX_CPU, 0);
	mtk_dma_write(hsdma, MTK_HSDMA_RX_BASE, 0);
	mtk_dma_write(hsdma, MTK_HSDMA_RX_CNT, 0);
	mtk_dma_write(hsdma, MTK_HSDMA_RX_CPU, MTK_DMA_SIZE - 1);

	mtk_dma_set(hsdma, MTK_HSDMA_RESET,
		    MTK_HSDMA_RST_TX | MTK_HSDMA_RST_RX);
	mtk_dma_clr(hsdma, MTK_HSDMA_RESET,
		    MTK_HSDMA_RST_TX | MTK_HSDMA_RST_RX);

	mtk_dma_set(hsdma, MTK_HSDMA_GLO, MTK_HSDMA_GLO_DMA);

	kfree(ring->cb);

	dma_free_coherent(hsdma2dev(hsdma),
			  pc->sz_ring, ring->txd, ring->tphys);

	dev_dbg(hsdma2dev(hsdma), "Freeing pchannel done\n");
}

static int mtk_hsdma_alloc_chan_resources(struct dma_chan *c)
{
	struct mtk_hsdma_device *hsdma = to_hsdma_dev(c);
	struct mtk_hsdma_vchan  *vc = to_hsdma_vchan(c);
	int ret = 0;

	if (!atomic_read(&hsdma->pc_refcnt))
		ret = mtk_hsdma_alloc_pchan(hsdma, &hsdma->pc);

	vc->pc = &hsdma->pc;
	atomic_inc(&hsdma->pc_refcnt);
	atomic_set(&vc->refcnt, 0);

	return ret;
}

static void mtk_hsdma_free_chan_resources(struct dma_chan *c)
{
	struct mtk_hsdma_device *hsdma = to_hsdma_dev(c);
	struct mtk_hsdma_vchan  *vc = to_hsdma_vchan(c);

	spin_lock_bh(&hsdma->lock);
	list_del_init(&vc->node);
	spin_unlock_bh(&hsdma->lock);

	if (!atomic_dec_and_test(&hsdma->pc_refcnt))
		return;

	mtk_hsdma_free_pchan(hsdma, vc->pc);
	vchan_free_chan_resources(to_virt_chan(c));
}

static int mtk_hsdma_consume_one_vdesc(struct mtk_hsdma_pchan *pc,
				       struct mtk_hsdma_vdesc *hvd)
{
	struct mtk_hsdma_device *hsdma = pc->hsdma;
	struct mtk_hsdma_ring *ring = &pc->ring;
	struct mtk_hsdma_pdesc *txd, *rxd;
	u32 i, tlen;
	u16 maxfills, prev, old_ptr, handled;

	maxfills = min_t(u32, hvd->num_sgs, atomic_read(&pc->free_count));
	if (!maxfills)
		return -ENOSPC;

	hsdma->busy = true;
	old_ptr = ring->cur_tptr;
	for (i = 0; i < maxfills ; i++) {
		tlen = (hvd->len > MTK_HSDMA_MAX_LEN) ?
		       MTK_HSDMA_MAX_LEN : hvd->len;
		txd = &ring->txd[ring->cur_tptr];
		WRITE_ONCE(txd->des1, hvd->src);
		WRITE_ONCE(txd->des2,
			   MTK_HSDMA_DESC_LS0 | MTK_HSDMA_DESC_PLEN(tlen));
		rxd = &ring->rxd[ring->cur_tptr];
		WRITE_ONCE(rxd->des1, hvd->dest);
		WRITE_ONCE(rxd->des2, MTK_HSDMA_DESC_PLEN(tlen));
		ring->cur_tptr = MTK_HSDMA_NEXT_DESP_IDX(ring->cur_tptr,
							 MTK_DMA_SIZE);
		hvd->src  += tlen;
		hvd->dest += tlen;
		hvd->len  -= tlen;
		hvd->num_sgs--;
	}

	prev = MTK_HSDMA_PREV_DESP_IDX(ring->cur_tptr, MTK_DMA_SIZE);

	if (!hvd->len) {
		ring->cb[prev].vd = &hvd->vd;
		ring->cb[prev].flags = VDESC_FINISHED;
	}

	handled = (ring->cur_tptr - old_ptr) & (MTK_DMA_SIZE - 1);
	atomic_sub(handled, &pc->free_count);

	/*
	 * Ensue all changes to the ring space flushed before we
	 * continue.
	 */
	wmb();
	mtk_dma_write(hsdma, MTK_HSDMA_TX_CPU, ring->cur_tptr);
	return !hvd->len ? 0 : -ENOSPC;
}

static struct mtk_hsdma_vchan *
mtk_hsdma_pick_vchan(struct mtk_hsdma_device *hsdma)
{
	struct mtk_hsdma_vchan *vc;

	if (hsdma->vc_uncompleted)
		return hsdma->vc_uncompleted;

	spin_lock(&hsdma->lock);
	if (list_empty(&hsdma->vc_pending)) {
		vc = 0;
	} else {
		vc = list_first_entry(&hsdma->vc_pending,
				      struct mtk_hsdma_vchan,
				      node);
	}
	spin_unlock(&hsdma->lock);

	return vc;
}

static int mtk_hsdma_vc_vd(struct mtk_hsdma_device *hsdma,
			   struct mtk_hsdma_vchan *vc,
			   struct virt_dma_desc *vd) {
	struct mtk_hsdma_vdesc *hvd;
	int ret;

	hvd = to_hsdma_vdesc(vd);

	spin_lock(&vc->vc.lock);
	if (!list_empty(&vd->node))
		list_del_init(&vd->node);
	spin_unlock(&vc->vc.lock);

	/* Mapping the descriptor into the ring space of HSDMA */
	ret = mtk_hsdma_consume_one_vdesc(vc->pc, hvd);

	/*
	 * Remember vc and vd if out of space in the ring happened
	 * which will be handled firstly in the next schedule.
	 */
	if (ret < 0) {
		hsdma->vc_uncompleted = vc;
		vc->vd_uncompleted = vd;
		return ret;
	}

	spin_lock(&vc->vc.lock);
	vd = vchan_next_desc(&vc->vc);
	spin_unlock(&vc->vc.lock);

	/*
	 * Re-queue the current channel to the pending list if pending
	 * descriptors on the current channel are still available.
	 */
	spin_lock(&hsdma->lock);
	if (!list_empty(&vc->node)) {
		if (!vd)
			list_del_init(&vc->node);
		else
			list_move_tail(&vc->node, &hsdma->vc_pending);
	}
	spin_unlock(&hsdma->lock);

	return 0;
}

static void mtk_hsdma_schedule(unsigned long data)
{
	struct mtk_hsdma_device *hsdma = (struct mtk_hsdma_device *)data;
	struct mtk_hsdma_vchan *vc;
	struct virt_dma_desc *vd;
	bool vc_removed;

	vc = mtk_hsdma_pick_vchan(hsdma);
	if (!vc)
		return;

	if (!vc->vd_uncompleted) {
		spin_lock(&vc->vc.lock);
		vd = vchan_next_desc(&vc->vc);
		spin_unlock(&vc->vc.lock);
	} else {
		vd = vc->vd_uncompleted;
		atomic_dec(&vc->refcnt);
	}

	hsdma->vc_uncompleted = 0;
	vc->vd_uncompleted = 0;

	while (vc && vd) {
		spin_lock(&hsdma->lock);
		vc_removed = list_empty(&vc->node);
		/*
		 * Refcnt increases for the indication that one more descriptor
		 * is ready for the process if the corresponding channel is
		 * active.
		 */
		if (!vc_removed)
			atomic_inc(&vc->refcnt);
		spin_unlock(&hsdma->lock);

		/*
		 * One descriptor is the unit for each round consuming and the
		 * returned negative value for mtk_hsdma_vc_vd occurs if it's
		 * out of space in the ring of HSDMA.
		 */
		if (!vc_removed && mtk_hsdma_vc_vd(hsdma, vc, vd) < 0)
			break;

		/* Switch to the next channel waiting on the pending list */
		vc = mtk_hsdma_pick_vchan(hsdma);
		if (vc) {
			spin_lock(&vc->vc.lock);
			vd = vchan_next_desc(&vc->vc);
			spin_unlock(&vc->vc.lock);
		}
	}
}

static void mtk_hsdma_housekeeping(unsigned long data)
{
	struct mtk_hsdma_device *hsdma = (struct mtk_hsdma_device *)data;
	struct mtk_hsdma_vchan *hvc;
	struct mtk_hsdma_pchan *pc;
	struct mtk_hsdma_pdesc *rxd;
	struct mtk_hsdma_cb *cb;
	struct virt_dma_chan *vc;
	struct virt_dma_desc *vd, *tmp;
	u16 next;
	u32 status;
	LIST_HEAD(comp);

	pc = &hsdma->pc;

	status = mtk_dma_read(hsdma, MTK_HSDMA_INT_STATUS);
	mtk_dma_write(hsdma, MTK_HSDMA_INT_STATUS, status);

	while (1) {
		next = MTK_HSDMA_NEXT_DESP_IDX(pc->ring.cur_rptr,
					       MTK_DMA_SIZE);
		rxd = &pc->ring.rxd[next];
		cb = &pc->ring.cb[next];

		/*
		 * If no MTK_HSDMA_DESC_DDONE is specified in rxd->des2, that
		 * means 1) the hardware doesn't finish the data moving yet
		 * for the corresponding descriptor or 2) the hardware meets
		 * the end of data moved.
		 */
		if (!(rxd->des2 & MTK_HSDMA_DESC_DDONE))
			break;

		if (IS_VDESC_FINISHED(cb->flags))
			list_add_tail(&cb->vd->node, &comp);

		WRITE_ONCE(rxd->des1, 0);
		WRITE_ONCE(rxd->des2, 0);
		cb->flags = 0;
		pc->ring.cur_rptr = next;
		atomic_inc(&pc->free_count);
	}

	/*
	 * Ensure all changes to all the descriptors in ring space being
	 * flushed before we continue.
	 */
	wmb();
	mtk_dma_write(hsdma, MTK_HSDMA_RX_CPU, pc->ring.cur_rptr);
	mtk_dma_set(hsdma, MTK_HSDMA_INT_ENABLE, MTK_HSDMA_INT_RXDONE);

	list_for_each_entry_safe(vd, tmp, &comp, node) {
		vc = to_virt_chan(vd->tx.chan);
		spin_lock(&vc->lock);
		vchan_cookie_complete(vd);
		spin_unlock(&vc->lock);

		hvc = to_hsdma_vchan(vd->tx.chan);
		atomic_dec(&hvc->refcnt);
	}

	/*
	 * An indication to HSDMA as not busy allows the user context to start
	 * the next HSDMA scheduler.
	 */
	if (atomic_read(&pc->free_count) == MTK_DMA_SIZE - 1)
		hsdma->busy = false;

	tasklet_schedule(&hsdma->scheduler);
}

static irqreturn_t mtk_hsdma_chan_irq(int irq, void *devid)
{
	struct mtk_hsdma_device *hsdma = devid;

	tasklet_schedule(&hsdma->housekeeping);

	/* Interrupt is enabled until the housekeeping tasklet is completed */
	mtk_dma_clr(hsdma, MTK_HSDMA_INT_ENABLE,
		    MTK_HSDMA_INT_RXDONE);

	return IRQ_HANDLED;
}

static void mtk_hsdma_issue_pending(struct dma_chan *c)
{
	struct mtk_hsdma_device *hsdma = to_hsdma_dev(c);
	struct mtk_hsdma_vchan *vc = to_hsdma_vchan(c);
	bool issued;

	spin_lock_bh(&vc->vc.lock);
	issued = vchan_issue_pending(&vc->vc);
	spin_unlock_bh(&vc->vc.lock);

	spin_lock_bh(&hsdma->lock);
	if (list_empty(&vc->node))
		list_add_tail(&vc->node, &hsdma->vc_pending);
	spin_unlock_bh(&hsdma->lock);

	if (issued && !hsdma->busy)
		tasklet_schedule(&hsdma->scheduler);
}

static struct dma_async_tx_descriptor *mtk_hsdma_prep_dma_memcpy(
	struct dma_chan *c, dma_addr_t dest,
	dma_addr_t src, size_t len, unsigned long flags)
{
	struct mtk_hsdma_vdesc *hvd;

	hvd = kzalloc(sizeof(*hvd), GFP_NOWAIT);
	if (!hvd)
		return NULL;

	hvd->len = len;
	hvd->src = src;
	hvd->dest = dest;
	hvd->num_sgs = DIV_ROUND_UP(len, MTK_HSDMA_MAX_LEN);

	return vchan_tx_prep(to_virt_chan(c), &hvd->vd, flags);
}

static int mtk_hsdma_terminate_all(struct dma_chan *c)
{
	struct mtk_hsdma_device *hsdma = to_hsdma_dev(c);
	struct virt_dma_chan *vc = to_virt_chan(c);
	struct mtk_hsdma_vchan *hvc = to_hsdma_vchan(c);
	LIST_HEAD(head);

	/*
	 * Hardware doesn't support abort, so remove the channel from the
	 * pendling list and wait for those data for the channel already in
	 * the ring space of HSDMA all transferred done.
	 */
	spin_lock_bh(&hsdma->lock);
	list_del_init(&hvc->node);
	spin_unlock_bh(&hsdma->lock);

	while (atomic_read(&hvc->refcnt)) {
		dev_dbg_ratelimited(chan2dev(c), "%s %d %d\n",
				    __func__, __LINE__,
				    (u32)atomic_read(&hvc->refcnt));
		usleep_range(100, 200);
	}

	spin_lock_bh(&vc->lock);
	vchan_get_all_descriptors(vc, &head);
	spin_unlock_bh(&vc->lock);
	vchan_dma_desc_free_list(vc, &head);

	return 0;
}

static void mtk_hsdma_synchronize(struct dma_chan *c)
{
	struct virt_dma_chan *vc = to_virt_chan(c);

	vchan_synchronize(vc);
}

static int mtk_hsdma_hw_init(struct mtk_hsdma_device *hsdma)
{
	int ret;

	ret = clk_prepare_enable(hsdma->clk);
	if (ret < 0) {
		dev_err(hsdma2dev(hsdma),
			"clk_prepare_enable failed: %d\n", ret);
		return ret;
	}

	mtk_dma_write(hsdma, MTK_HSDMA_INT_ENABLE, 0);
	mtk_dma_write(hsdma, MTK_HSDMA_GLO, MTK_HSDMA_GLO_DEFAULT);

	return 0;
}

static int mtk_hsdma_hw_deinit(struct mtk_hsdma_device *hsdma)
{
	mtk_dma_write(hsdma, MTK_HSDMA_INT_ENABLE, 0);
	mtk_dma_write(hsdma, MTK_HSDMA_GLO, 0);

	clk_disable_unprepare(hsdma->clk);

	return 0;
}

static const struct of_device_id mtk_dma_match[] = {
	{ .compatible = "mediatek,mt7623-hsdma" },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, mtk_dma_match);

static int mtk_dma_probe(struct platform_device *pdev)
{
	struct mtk_hsdma_device *hsdma;
	struct mtk_hsdma_vchan *vc;
	struct dma_device *dd;
	struct resource *res;
	int i, ret;

	hsdma = devm_kzalloc(&pdev->dev, sizeof(*hsdma), GFP_KERNEL);
	if (!hsdma)
		return -ENOMEM;

	dd = &hsdma->ddev;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	hsdma->base = devm_ioremap_resource(&pdev->dev, res);
	if (IS_ERR(hsdma->base))
		return PTR_ERR(hsdma->base);

	hsdma->clk = devm_clk_get(&pdev->dev, "hsdma");
	if (IS_ERR(hsdma->clk)) {
		dev_err(&pdev->dev, "Error: Missing controller clock\n");
		return PTR_ERR(hsdma->clk);
	}

	res = platform_get_resource(pdev, IORESOURCE_IRQ, 0);
	if (!res) {
		dev_err(&pdev->dev, "No irq resource for %s\n",
			dev_name(&pdev->dev));
		return -EINVAL;
	}
	hsdma->irq = res->start;

	INIT_LIST_HEAD(&hsdma->vc_pending);
	spin_lock_init(&hsdma->lock);
	atomic_set(&hsdma->pc_refcnt, 0);
	dma_cap_set(DMA_MEMCPY, dd->cap_mask);

	dd->copy_align = MTK_HSDMA_ALIGN_SIZE;
	dd->device_alloc_chan_resources = mtk_hsdma_alloc_chan_resources;
	dd->device_free_chan_resources = mtk_hsdma_free_chan_resources;
	dd->device_tx_status = dma_cookie_status;
	dd->device_issue_pending = mtk_hsdma_issue_pending;
	dd->device_prep_dma_memcpy = mtk_hsdma_prep_dma_memcpy;
	dd->device_terminate_all = mtk_hsdma_terminate_all;
	dd->device_synchronize = mtk_hsdma_synchronize;
	dd->src_addr_widths = MTK_HSDMA_DMA_BUSWIDTHS;
	dd->dst_addr_widths = MTK_HSDMA_DMA_BUSWIDTHS;
	dd->directions = BIT(DMA_MEM_TO_MEM);
	dd->residue_granularity = DMA_RESIDUE_GRANULARITY_DESCRIPTOR;
	dd->dev = &pdev->dev;
	INIT_LIST_HEAD(&dd->channels);

	hsdma->dma_requests = MTK_DMA_MAX_VCHANNELS;
	if (pdev->dev.of_node && of_property_read_u32(pdev->dev.of_node,
						      "dma-requests",
						      &hsdma->dma_requests)) {
		dev_info(&pdev->dev,
			 "Using %u as missing dma-requests property\n",
			 MTK_DMA_MAX_VCHANNELS);
	}

	hsdma->vc = devm_kcalloc(&pdev->dev, hsdma->dma_requests,
				 sizeof(*hsdma->vc), GFP_KERNEL);
	if (!hsdma->vc)
		return -ENOMEM;

	for (i = 0; i < hsdma->dma_requests; i++) {
		vc = &hsdma->vc[i];
		vc->vc.desc_free = mtk_hsdma_vdesc_free;
		vchan_init(&vc->vc, dd);
		INIT_LIST_HEAD(&vc->node);
	}

	ret = dma_async_device_register(dd);
	if (ret)
		return ret;

	ret = of_dma_controller_register(pdev->dev.of_node,
					 of_dma_xlate_by_chan_id, hsdma);
	if (ret < 0) {
		dev_err(&pdev->dev,
			"Mediatek HSDMA OF registration failed %d\n", ret);
		goto err_unregister;
	}

	mtk_hsdma_hw_init(hsdma);

	tasklet_init(&hsdma->housekeeping, mtk_hsdma_housekeeping,
		     (unsigned long)hsdma);
	tasklet_init(&hsdma->scheduler, mtk_hsdma_schedule,
		     (unsigned long)hsdma);

	ret = devm_request_irq(&pdev->dev, hsdma->irq,
			       mtk_hsdma_chan_irq, 0,
			       dev_name(&pdev->dev), hsdma);
	if (ret) {
		dev_err(&pdev->dev,
			"request_irq failed with err %d channel %d\n",
			ret, i);
		goto err_unregister;
	}

	platform_set_drvdata(pdev, hsdma);

	dev_info(&pdev->dev, "Mediatek HSDMA driver registered\n");

	return 0;

err_unregister:
	dma_async_device_unregister(dd);

	return ret;
}

static int mtk_dma_remove(struct platform_device *pdev)
{
	struct mtk_hsdma_device *hsdma = platform_get_drvdata(pdev);

	of_dma_controller_free(pdev->dev.of_node);
	dma_async_device_unregister(&hsdma->ddev);

	tasklet_kill(&hsdma->scheduler);
	tasklet_kill(&hsdma->housekeeping);

	mtk_hsdma_hw_deinit(hsdma);

	return 0;
}

static struct platform_driver mtk_dma_driver = {
	.probe		= mtk_dma_probe,
	.remove		= mtk_dma_remove,
	.driver = {
		.name		= MTK_DMA_DEV,
		.of_match_table	= mtk_dma_match,
	},
};
module_platform_driver(mtk_dma_driver);

MODULE_DESCRIPTION("Mediatek High-Speed DMA Controller Driver");
MODULE_AUTHOR("Sean Wang <sean.wang@mediatek.com>");
MODULE_LICENSE("GPL");
