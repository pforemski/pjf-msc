/*
 * spi: Statistical Packet Inspection
 * Copyright (C) 2011 Paweł Foremski <pawel@foremski.pl>
 * This software is licensed under GNU GPL version 3
 */

#ifndef _EP_H_
#define _EP_H_

#include "datastructures.h"

/** Fix endpoint addresses so that epa1 < epa2 */
static inline void epa_fix(spi_epaddr_t *epa1, spi_epaddr_t *epa2)
{
	if (*epa1 > *epa2) {
		spi_epaddr_t tmp = *epa2;
		*epa2 = *epa1;
		*epa1 = tmp;
	}
}

/** Destroy endpoint memory */
void ep_destroy(struct spi_ep *ep);

/** Save packet of endpoint given by ip and port
 * @param source     packet source
 * @param proto      protocol
 * @param epa        endpoint address
 * @param ts         packet timestamp
 * @param data       payload (N bytes)
 * @param size       real packet size
 * @return           endpoint structure
 */
struct spi_ep *ep_new_pkt(struct spi_source *source, spi_proto_t proto, spi_epaddr_t epa,
	const struct timeval *ts, void *data, uint32_t size);

#endif
