/* Header of MMSYS MFD core driver for Mediatek platforms
 *
 * Copyright (c) 2017 Matthias Brugger <matthias.bgg@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License version 2 as published by the
 * Free Software Foundation.
 */

#ifndef __MEDIATEK_MMSYS__H__
#define __MEDIATEK_MMSYS__H__

struct mmsys_dev {
	struct device		*dev;
	struct device_node	*of_node;
};

#endif
