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
#include "datastructures.h"

static char *_k(struct ip *ip, struct tcphdr *tcp)
{
	static char key[] = "tcp-111.111.111.111:11111-222.222.222.222:22222";
	char addr1[] = "111.111.111.111:11111";
	char addr2[] = "111.111.111.111:11111";

	snprintf(addr1, sizeof addr1, "%s:%u", inet_ntoa(ip->ip_src), tcp->th_sport);
	snprintf(addr2, sizeof addr2, "%s:%u", inet_ntoa(ip->ip_dst), tcp->th_dport);

	if (ip->ip_src.s_addr < ip->ip_dst.s_addr)
		snprintf(key, sizeof key, "tcp-%s-%s", addr1, addr2);
	else
		snprintf(key, sizeof key, "tcp-%s-%s", addr2, addr1);

	return key;
}

/***********/

void flow_destroy(struct flow *flow)
{
	mmatic_freeptr(flow);
}

void flow_flags(struct spid *spid, struct ip *ip, struct tcphdr *tcp)
{
	struct flow *flow;
	bool *target;
	char *key;

	key = _k(ip, tcp);
	flow = thash_get(spid->flows, key);
	if (!flow)
		return;

	/* handle RST: close both sides */
	if (tcp->th_flags & TH_RST) {
		flow->fin1 = true;
		flow->fin2 = true;
		return;
	}

	/* handle FIN: close one side (lower is 1, higher is 2) */
	if (tcp->th_flags & TH_FIN) {
		if (ip->ip_src.s_addr < ip->ip_dst.s_addr)
			target = &flow->fin1;
		else
			target = &flow->fin2;

		*target = true;
		return;
	}
}

int flow_count(struct spid *spid, struct ip *ip, struct tcphdr *tcp)
{
	struct flow *flow;
	char *key;

	key = _k(ip, tcp);
	flow = thash_get(spid->flows, key);
	if (!flow) {
		flow = mmatic_zalloc(spid, sizeof *flow);
		thash_set(spid->flows, key, flow);
	}

	gettimeofday(&flow->last, NULL); // TODO
	flow->counter++;

	return flow->counter;
}
