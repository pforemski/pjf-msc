/*
 * spid: Statistical Packet Inspection
 * Copyright (C) 2011 Paweł Foremski <pawel@foremski.pl>
 * This software is licensed under GNU GPL version 3
 */

#include "ep.h"
#include "datastructures.h"

static char *_k(proto_t proto, uint32_t ip, uint16_t port)
{
	static char key[] = "1-111.111.111.111:11111";
	snprintf(key, sizeof key, "%u-%u-%u", proto, ip, port);
	return key;
}

/******************/

void ep_destroy(struct ep *ep)
{
	mmatic_free(ep->mm);
}

struct ep *ep_new_pkt(const struct pkt *pkt, proto_t proto, uint32_t ip, uint16_t port)
{
	struct spid *spid = pkt->source->spid;
	struct ep *ep;
	char *key;
	struct pkt *mypkt;
	mmatic *mm;

	key = _k(proto, ip, port);
	ep = thash_get(spid->eps, key);
	if (!ep) {
		mm = mmatic_create();
		ep = mmatic_zalloc(mm, sizeof *ep);
		ep->mm = mm;
		ep->proto = proto;
		ep->ip = ip;
		ep->port = port;
		thash_set(spid->eps, key, ep);
	}

	gettimeofday(&ep->last, NULL); // TODO

	/* make copy of packet */
	mypkt = mmatic_zalloc(ep->mm, sizeof *mypkt);
	mypkt->payload = mmatic_zalloc(ep->mm, spid->options.N);
	mypkt->ts = mmatic_zalloc(ep->mm, sizeof(struct timeval));

	mypkt->source = pkt->source;
	mypkt->size = pkt->size;
	memcpy(mypkt->payload, pkt->payload, spid->options.N);
	memcpy(mypkt->ts, pkt->ts, sizeof(struct timeval));

	if (!ep->pkts)
		ep->pkts = tlist_create(NULL, ep->mm);

	tlist_push(ep->pkts, mypkt);

	return ep;
}
