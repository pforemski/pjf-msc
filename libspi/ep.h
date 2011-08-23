/*
 * spi: Statistical Packet Inspection
 * Copyright (C) 2011 Paweł Foremski <pawel@foremski.pl>
 * This software is licensed under GNU GPL version 3
 */

#ifndef _EP_H_
#define _EP_H_

#include "datastructures.h"

/** Destroy endpoint memory */
void ep_destroy(struct spi_ep *ep);

/** Save packet of endpoint given by ip and port
 * @param source     packet source
 * @param epa        endpoint address
 * @param ts         packet timestamp
 * @param data       payload (N bytes)
 * @param size       real packet size
 * @return           endpoint structure
 */
struct spi_ep *ep_new_pkt(struct spi_source *source, spi_epaddr_t epa,
	const struct timeval *ts, void *data, uint32_t size);

#endif
