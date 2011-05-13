/*
 * spid: Statistical Packet Inspection
 * Copyright (C) 2011 Paweł Foremski <pawel@foremski.pl>
 * This software is licensed under GNU GPL version 3
 */

#ifndef _FLOW_H_
#define _FLOW_H_

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include "datastructures.h"

/** Destroy flow memory */
void flow_destroy(struct flow *flow);

/** Interpret TCP flags
 * Look for RST and FIN flags and close matching flow if necessary
 * @param ip          ip header
 * @param tcp         tcp header
 */
void flow_flags(struct spid *spid, struct ip *ip, struct tcphdr *tcp);

/** Get flow packet counter */
int flow_count(struct spid *spid, struct ip *ip, struct tcphdr *tcp);

#endif
