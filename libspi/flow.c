/*
 * spi: Statistical Packet Inspection
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

static inline char *_k(struct spi_source *source, spi_proto_t proto, spi_epaddr_t src, spi_epaddr_t dst)
{
	static char key[] = "X-X-XXXxxxXXXxxxXXXXX-XXXxxxXXXxxxXXXXX";

	snprintf(key, sizeof key, "%u-%u-%llu-%llu",
			(source->type == SPI_SOURCE_FILE) ? source->fd : 0,
			proto, MIN(src, dst), MAX(src, dst));

	return key;
}

static inline struct spi_flow *_get_flow(struct spi_source *source, spi_proto_t proto, spi_epaddr_t src, spi_epaddr_t dst)
{
	return thash_get(source->spi->flows, _k(source, proto, src, dst));
}

static inline void _set_flow(struct spi_source *source, spi_proto_t proto,
	spi_epaddr_t src, spi_epaddr_t dst, struct spi_flow *flow)
{
	thash_set(source->spi->flows, _k(source, proto, src, dst), flow);
}

/***********/

void flow_destroy(struct spi_flow *flow)
{
	mmatic_freeptr(flow);
}

void flow_tcp_flags(struct spi_source *source, spi_epaddr_t src, spi_epaddr_t dst, struct tcphdr *tcp)
{
	struct spi_flow *flow;

	flow = _get_flow(source, SPI_PROTO_TCP, src, dst);
	if (!flow)
		return;

	/* handle RST */
	if (tcp->th_flags & TH_RST) {
		flow->rst |= 1 + (src > dst);
		return;
	}

	/* handle FIN */
	if (tcp->th_flags & TH_FIN) {
		flow->fin++;
		flow->fin |= 1 + (src > dst);
		return;
	}
}

int flow_count(struct spi_source *source, spi_proto_t proto, spi_epaddr_t src, spi_epaddr_t dst,
	const struct timeval *ts)
{
	struct spi *spi = source->spi;
	struct spi_flow *flow;

	flow = _get_flow(source, proto, src, dst);
	if (!flow) {
		flow = mmatic_zalloc(spi, sizeof *flow);
		flow->source = source;
		flow->proto = proto;
		flow->epa1 = MIN(src, dst);
		flow->epa2 = MAX(src, dst);
		_set_flow(source, proto, src, dst, flow);
	}

	memcpy(&flow->last, ts, sizeof(struct timeval));

	flow->counter++;

	/* NB: can generate spi event if counter >= 80 */

	return flow->counter;
}
