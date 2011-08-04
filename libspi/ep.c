/*
 * spi: Statistical Packet Inspection
 * Copyright (C) 2011 Paweł Foremski <pawel@foremski.pl>
 * This software is licensed under GNU GPL version 3
 */

#include <libpjf/lib.h>

#include "datastructures.h"
#include "spi.h"
#include "ep.h"

static char *_k(struct spi_source *source, spi_proto_t proto, spi_epaddr_t epa)
{
	static char key[] = "X-X-XXXxxxXXXxxxXXXXX";
	snprintf(key, sizeof key, "%u-%u-%llu",
		(source->type == SPI_SOURCE_FILE) ? source->fd : 0,
		proto, epa);
	return key;
}

/******************/

void ep_destroy(struct spi_ep *ep)
{
	mmatic_free(ep->mm);
}

struct spi_ep *ep_new_pkt(struct spi_source *source, spi_proto_t proto, spi_epaddr_t epa,
	const struct timeval *ts, void *data, uint32_t size)
{
	struct spi *spi = source->spi;
	struct spi_ep *ep;
	char *key;
	struct spi_pkt *pkt;
	mmatic *mm;

	key = _k(source, proto, epa);
	ep = thash_get(spi->eps, key);
	if (!ep) {
		mm = mmatic_create();
		ep = mmatic_zalloc(mm, sizeof *ep);
		ep->mm = mm;
		ep->source = source;
		ep->proto = proto;
		ep->epa = epa;
		thash_set(spi->eps, key, ep);

		source->eps++;

		dbg(8, "new ep %s\n", spi_epa2a(epa));
	}

	/* make packet */
	pkt = mmatic_zalloc(ep->mm, sizeof *pkt);
	pkt->size = size;
	pkt->payload = mmatic_zalloc(ep->mm, spi->options.N);
	memcpy(pkt->payload, data, spi->options.N);
	memcpy(&pkt->ts, ts, sizeof(struct timeval));

	/* update last packet time */
	memcpy(&ep->last, ts, sizeof(struct timeval));

	/* store packet */
	if (!ep->pkts)
		ep->pkts = tlist_create(mmatic_freeptr, ep->mm);

	tlist_push(ep->pkts, pkt);

	/* generate event if pkts big enough */
	if (!ep->gclock && tlist_count(ep->pkts) >= spi->options.C) {
		ep->gclock = true;
		spi_announce(spi, "endpointPacketsReady", 0, ep, false);
		dbg(7, "ep %s ready\n", spi_epa2a(epa));
	}

	return ep;
}
