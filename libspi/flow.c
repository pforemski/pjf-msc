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

static inline char *_k(struct spi_source *source, spi_epaddr_t src, spi_epaddr_t dst)
{
	static char key[258];

	snprintf(key, sizeof key, "%u-%llu-%llu",
			(source->type == SPI_SOURCE_FILE) ? source->fd : 0,
			MIN(src, dst), MAX(src, dst));

	return key;
}

static inline struct spi_flow *_get_flow(struct spi_source *source, spi_epaddr_t src, spi_epaddr_t dst)
{
	return thash_get(source->spi->flows, _k(source, src, dst));
}

static inline void _set_flow(struct spi_source *source, spi_epaddr_t src, spi_epaddr_t dst, struct spi_flow *flow)
{
	thash_set(source->spi->flows, _k(source, src, dst), flow);
}

/***********/

void flow_destroy(struct spi_flow *flow)
{
	mmatic_free(flow);
}

void flow_tcp_flags(struct spi_source *source, spi_epaddr_t src, spi_epaddr_t dst, struct tcphdr *tcp)
{
	struct spi_flow *flow;

	flow = _get_flow(source, src, dst);
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

int flow_count(struct spi_source *source, spi_epaddr_t src, spi_epaddr_t dst, const struct timeval *ts)
{
	struct spi *spi = source->spi;
	struct spi_flow *flow;

	flow = _get_flow(source, src, dst);
	if (!flow) {
		flow = mmatic_zalloc(spi, sizeof *flow);
		flow->source = source;
		flow->epa1 = MIN(src, dst);
		flow->epa2 = MAX(src, dst);
		_set_flow(source, src, dst, flow);
	}

	memcpy(&flow->last, ts, sizeof(struct timeval));
	return ++flow->counter;
}
