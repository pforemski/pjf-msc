/*
 * spid: Statistical Packet Inspection
 * Copyright (C) 2011 Paweł Foremski <pawel@foremski.pl>
 * This software is licensed under GNU GPL version 3
 */

#include <pcap.h>
#define __FAVOR_BSD
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include "flow.h"
#include "ep.h"
#include "datastructures.h"

static char *_k(struct source *source, proto_t proto, epaddr_t epa1, epaddr_t epa2)
{
	static char key[] = "X-X-XXXxxxXXXxxxXXXXX-XXXxxxXXXxxxXXXXX";
	snprintf(key, sizeof key, "%u-%u-%llu-%llu",
		(source->type == SPI_SOURCE_FILE) ? source->fd : 0,
		proto, epa1, epa2);
	return key;
}

/***********/

void flow_destroy(struct flow *flow)
{
	mmatic_freeptr(flow);
}

void flow_tcp_flags(struct source *source, epaddr_t epa1, epaddr_t epa2, struct tcphdr *tcp)
{
	struct flow *flow;
	char *key;

	epa_fix(&epa1, &epa2);

	key = _k(source, SPI_PROTO_TCP, epa1, epa2);
	flow = thash_get(source->spid->flows, key);
	if (!flow)
		return;

	/* handle RST: close both sides */
	if (tcp->th_flags & TH_RST) {
		flow->rst++;
		return;
	}

	/* handle FIN: close one side (lower is 1, higher is 2) */
	if (tcp->th_flags & TH_FIN) {
		flow->fin++;
		return;
	}
}

int flow_count(struct source *source, proto_t proto, epaddr_t epa1, epaddr_t epa2,
	const struct timeval *ts)
{
	struct spid *spid = source->spid;
	struct flow *flow;
	char *key;

	epa_fix(&epa1, &epa2);

	key = _k(source, proto, epa1, epa2);
	flow = thash_get(spid->flows, key);
	if (!flow) {
		flow = mmatic_zalloc(spid, sizeof *flow);
		flow->source = source;
		flow->proto = proto;
		flow->epa1 = epa1;
		flow->epa2 = epa2;
		thash_set(spid->flows, key, flow);
	}

	memcpy(&flow->last, ts, sizeof(struct timeval));

	flow->counter++;

	/* NB: can generate spid event if counter >= 80 */

	return flow->counter;
}
