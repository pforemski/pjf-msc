/*
 * spi: Statistical Packet Inspection
 * Copyright (C) 2011 Paweł Foremski <pawel@foremski.pl>
 * This software is licensed under GNU GPL version 3
 */

#include <libpjf/lib.h>

#include "datastructures.h"
#include "spi.h"
#include "ep.h"

static char *_k(struct spi_source *source, spi_epaddr_t epa)
{
	static char key[256];
	snprintf(key, sizeof key, "%u-%llu",
		(source->type == SPI_SOURCE_FILE) ? source->fd : 0,
		epa);
	return key;
}

/******************/

/** Handle moment in which endpoint is deleted */
void ep_destroy(struct spi_ep *ep)
{
	struct spi_source *source = ep->source;
	struct spi_stats *stats = &(source->spi->stats);

	/* a testing endpoint: update performance metrics */
	if (source->testing && ep->predictions > 0) {
		stats->test_all++;
		stats->test_all_signs += ep->predictions;

		stats->test_is[source->label]++;
		stats->test_signs[source->label] += ep->predictions;

		if (ep->verdict == 0)
			ep->verdict = SPI_LABEL_UNKNOWN;

		if (ep->verdict == source->label) {
			stats->test_ok++;
			stats->test_ok_signs += ep->predictions;
		} else {
			stats->test_FN[source->label]++;
			stats->test_FP[ep->verdict]++;

			dbg(1, "%s: %s is %d but classified as %d\n",
				spi_src2a(ep->source), spi_epa2a(ep->epa),
				source->label, ep->verdict);
		}
	}

	mmatic_free(ep->mm);
}

struct spi_ep *ep_new_pkt(struct spi_source *source, spi_epaddr_t epa,
	const struct timeval *ts, void *data, uint32_t size)
{
	struct spi *spi = source->spi;
	struct spi_ep *ep;
	char *key;
	struct spi_pkt *pkt;
	mmatic *mm;

	key = _k(source, epa);
	ep = thash_get(spi->eps, key);
	if (!ep) {
		mm = mmatic_create();
		ep = mmatic_zalloc(mm, sizeof *ep);
		ep->mm = mm;
		ep->source = source;
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
	if (ep->gclock1 == 0 && tlist_count(ep->pkts) >= spi->options.C) {
		ep->gclock1++;
		spi_announce(spi, "endpointPacketsReady", 0, ep, false);
		dbg(7, "ep %s ready\n", spi_epa2a(epa));
	}

	return ep;
}
