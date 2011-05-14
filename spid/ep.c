/*
 * spid: Statistical Packet Inspection
 * Copyright (C) 2011 Paweł Foremski <pawel@foremski.pl>
 * This software is licensed under GNU GPL version 3
 */

#include <libpjf/lib.h>

#include "datastructures.h"
#include "spid.h"
#include "ep.h"

static char *_k(struct source *source, proto_t proto, epaddr_t epa)
{
	static char key[] = "X-X-XXXxxxXXXxxxXXXXX";
	snprintf(key, sizeof key, "%u-%u-%llu",
		(source->type == SPI_SOURCE_FILE) ? source->fd : 0,
		proto, epa);
	return key;
}

/******************/

void ep_destroy(struct ep *ep)
{
	mmatic_free(ep->mm);
}

struct ep *ep_new_pkt(struct source *source, proto_t proto, epaddr_t epa,
	const struct timeval *ts, void *data, uint32_t size)
{
	struct spid *spid = source->spid;
	struct ep *ep;
	char *key;
	struct pkt *pkt;
	mmatic *mm;

	key = _k(source, proto, epa);
	ep = thash_get(spid->eps, key);
	if (!ep) {
		mm = mmatic_create();
		ep = mmatic_zalloc(mm, sizeof *ep);
		ep->mm = mm;
		ep->proto = proto;
		ep->epa = epa;
		thash_set(spid->eps, key, ep);
	}

	/* make packet */
	pkt = mmatic_zalloc(ep->mm, sizeof *pkt);
	pkt->source = source;
	pkt->size = size;
	pkt->payload = mmatic_zalloc(ep->mm, spid->options.N);
	memcpy(pkt->payload, data, spid->options.N);
	memcpy(&pkt->ts, ts, sizeof(struct timeval));

	/* update last packet time */
	memcpy(&ep->last, ts, sizeof(struct timeval));

	/* store packet */
	if (!ep->pkts)
		ep->pkts = tlist_create(mmatic_freeptrs, ep->mm);

	tlist_push(ep->pkts, pkt);

	/* generate event if pkts big enough */
	if (!ep->has_C && tlist_count(ep->pkts) >= spid->options.C) {
		ep->has_C = true;
		spid_announce(spid, SPI_EVENT_ENDPOINT_HAS_C_PKTS, ep, 0);
	}

	return ep;
}
