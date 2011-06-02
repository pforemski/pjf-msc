/*
 * spi: Statistical Packet Inspection
 * Copyright (C) 2011 Paweł Foremski <pawel@foremski.pl>
 * This software is licensed under GNU GPL version 3
 */

#ifndef _FLOW_H_
#define _FLOW_H_

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include "datastructures.h"

/** Destroy flow memory */
void flow_destroy(struct spi_flow *flow);

/** Interpret TCP flags
 * Look for RST and FIN flags and close matching flow if necessary
 * @param epa1        endpoint 1 address
 * @param epa2        endpoint 2 address
 * @param tcp         tcp header
 */
void flow_tcp_flags(struct spi_source *source, spi_epaddr_t epa1, spi_epaddr_t epa2, struct tcphdr *tcp);

/** Count flow packet
 * @param proto       flow protocol
 * @param epa1        endpoint 1 address
 * @param epa2        endpoint 2 address
 * @param ts          packet timestamp
 * @return            flow packet counter
 */
int flow_count(struct spi_source *source, spi_proto_t proto, spi_epaddr_t epa1, spi_epaddr_t epa2,
	const struct timeval *ts);

#endif