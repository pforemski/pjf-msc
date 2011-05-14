/*
 * spid: Statistical Packet Inspection
 * Copyright (C) 2011 Paweł Foremski <pawel@foremski.pl>
 * This software is licensed under GNU GPL version 3
 */

#ifndef _EP_H_
#define _EP_H_

#include <pcap.h>
#define __FAVOR_BSD
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "datastructures.h"

/** Fix endpoint addresses so that epa1 < epa2 */
static inline void epa_fix(epaddr_t *epa1, epaddr_t *epa2)
{
	if (*epa1 > *epa2) {
		epaddr_t tmp = *epa2;
		*epa2 = *epa1;
		*epa1 = tmp;
	}
}

/** Print endpoint address in human-readable format */
static inline const char *epa_print(epaddr_t epa)
{
	static char buf[] = "111.111.111.111:11111";
	struct in_addr addr;

	addr.s_addr = epa >> 16;
	snprintf(buf, sizeof buf, "%s:%u", inet_ntoa(addr), (uint16_t) epa);
	return buf;
}

/** Destroy endpoint memory */
void ep_destroy(struct ep *ep);

/** Save packet of endpoint given by ip and port
 * @param source     packet source
 * @param proto      protocol
 * @param epa        endpoint address
 * @param ts         packet timestamp
 * @param data       payload (N bytes)
 * @param size       real packet size
 * @return           endpoint structure
 */
struct ep *ep_new_pkt(struct source *source, proto_t proto, epaddr_t epa,
	const struct timeval *ts, void *data, uint32_t size);

#endif
