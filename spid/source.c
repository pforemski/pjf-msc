/*
 * spid: Statistical Packet Inspection
 * Copyright (C) 2011 Paweł Foremski <pawel@foremski.pl>
 * This software is licensed under GNU GPL version 3
 */

#include <pcap.h>

/* for parsing libpcap packets */
#define __FAVOR_BSD
#include <net/if.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "spid.h"
#include "ep.h"
#include "flow.h"

static int _pcap_err(pcap_t *pcap, const char *func)
{
	dbg(0, "%s: %s\n", func, pcap_geterr(pcap));
	return -1;
}

static int _pcap_add_filter(struct source *source, pcap_t *pcap, const char *filter)
{
	struct bpf_program *cf;

	cf = mmatic_alloc(source->spid->mm, sizeof *cf);

	if (!filter)
		filter = SPI_PCAP_DEFAULT_FILTER;

	if (pcap_compile(pcap, cf, filter, 0, 0) == -1)
		return _pcap_err(pcap, "pcap_compile()");

	if (pcap_setfilter(pcap, cf) == -1)
		return _pcap_err(pcap, "pcap_setfilter()");

	return 0;
}

static void _parse_new_packet(struct source *source,
	const struct timeval *tstamp, uint16_t pktlen, uint8_t *msg, uint16_t msglen)
{
#define PTROK(ptr, s) ((((uint8_t *) ptr) + (s) - msg) <= msglen)
	struct ether_header *eth;
	struct ip *ip;
	uint16_t iplen;
	struct tcphdr *tcp;
	struct udphdr *udp;
	uint8_t *data;
	bool istcp = 0;
	struct pkt pkt;
	struct ep *ep;

	/* Ethernet */
	eth = (struct ether_header *) msg;
	if (!PTROK(eth, sizeof *eth)) {
		dbg(8, "skipping too short Ethernet frame\n");
		return;
	}

	switch (ntohs(eth->ether_type)) {
		case ETHERTYPE_IP:
			ip = (struct ip *) (msg + 14);
			break;
		case ETHERTYPE_VLAN:
			ip = (struct ip *) (msg + 18);
			break;
		case ETHERTYPE_ARP:
		case ETHERTYPE_REVARP:
		case ETHERTYPE_IPV6:
		case 0x888E: /* EAPOL */
			return;
		default:
			dbg(8, "skipping unknown ether type 0x%04X\n", ntohs(eth->ether_type));
			return;
	}

	/* IP */
	if (!PTROK(ip, sizeof *ip)) {
		dbg(8, "skipping too short IP packet\n");
		return;
	} else if (ip->ip_v != 4) {
		dbg(8, "skipping IPv%u packet\n", ip->ip_v);
		return;
	}
	iplen = ip->ip_hl * 4;

	/* TCP/UDP */
	switch (ip->ip_p) {
		case IPPROTO_TCP:
			tcp = (struct tcphdr *) (((uint8_t *) ip) + iplen);
			if (!PTROK(tcp, sizeof *tcp)) {
				dbg(8, "skipping too short TCP packet\n");
				return;
			}

			istcp = 1;
			flow_flags(source->spid, ip, tcp);

			data = ((uint8_t *) tcp) + tcp->th_off * 4;
			break;

		case IPPROTO_UDP:
			udp = (struct udphdr *) (((uint8_t *) ip) + iplen);
			if (!PTROK(udp, sizeof *udp)) {
				dbg(8, "skipping too short UDP packet\n");
				return;
			}

			data = ((uint8_t *) udp) + sizeof *udp;
			break;

		case IPPROTO_ICMP:
			return;
		default:
			dbg(8, "skipping non-TCP/UDP packet, proto=%u\n", ip->ip_p);
			return;
	}

	/* payload */
	if (!PTROK(data, source->spid->options.N)) {
		dbg(12, "skipping too short packet (need %u bytes of payload, pktlen=%u, msglen=%u)\n",
			source->spid->options.N, pktlen, msglen);
		return;
	}

	if (istcp && flow_count(source->spid, ip, tcp) > source->spid->options.P) {
		dbg(12, "skipping TCP packet past %u first packets of TCP flow\n",
			source->spid->options.P);
		return;
	}

	pkt.source = source;
	pkt.payload = data;
	pkt.ts = (struct timeval *) tstamp;
	pkt.size = pktlen;

	/* TODO: add at one endpoint? */

	/* source endpoint */
	if (istcp)
		ep = ep_new_pkt(&pkt, SPI_PROTO_TCP, ip->ip_src.s_addr, tcp->th_sport);
	else
		ep = ep_new_pkt(&pkt, SPI_PROTO_UDP, ip->ip_src.s_addr, udp->uh_sport);

	if (ep && tlist_count(ep->pkts) >= source->spid->options.C)
		spid_announce(source->spid, SPI_EVENT_ENDPOINT_HAS_C_PKTS, ep, 0);

	/* destination endpoint */
	if (istcp)
		ep = ep_new_pkt(&pkt, SPI_PROTO_TCP, ip->ip_dst.s_addr, tcp->th_dport);
	else
		ep = ep_new_pkt(&pkt, SPI_PROTO_UDP, ip->ip_dst.s_addr, udp->uh_dport);

	if (ep && tlist_count(ep->pkts) >= source->spid->options.C)
		spid_announce(source->spid, SPI_EVENT_ENDPOINT_HAS_C_PKTS, ep, 0);
}

static void _pcap_callback(u_char *arg, const struct pcap_pkthdr *msginfo, const u_char *msg)
{
	struct source *source = (struct source *) arg;

	/* NB: assuming Ethernet header starts at msg[0] */
	_parse_new_packet(source,
		&msginfo->ts, msginfo->len,
		(uint8_t *) msg, MIN(msginfo->caplen, msginfo->len));
}

static inline void _pcap_read(struct source *source, pcap_t *pcap)
{
	switch (pcap_dispatch(pcap, SPI_PCAP_MAX, _pcap_callback, (u_char *) source)) {
		case 0:  /* no packets */
			dbg(1, "should not happen\n");
			return;
		case -1: /* error */
			_pcap_err(pcap, "pcap_dispatch()");
			return;
		case -2: /* break loop (?!) */
			die("pcap_dispatch() returned -2\n");
			return;
	}
}

/******************/

void source_destroy(struct source *source)
{
	/* TODO: close files, etc. */

	mmatic_freeptr(source);
}

int source_file_init(struct source *source, const char *args)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	FILE *stream;
	char *path, *filter;

	path = mmatic_strdup(source->spid->mm, args);
	filter = strchr(path, ' ');
	if (filter) *filter++ = '\0';

	source->as.file.pcap = pcap_open_offline(path, errbuf);
	if (!source->as.file.pcap) {
		dbg(0, "pcap_open_offline(): %s\n", errbuf);
		return -1;
	}

	stream = pcap_file(source->as.file.pcap);
	if (!stream) {
		dbg(0, "pcap_file(): stream=NULL\n");
		return -1;
	}

	source->as.file.path = path;
	source->fd = fileno(stream);
	return _pcap_add_filter(source, source->as.file.pcap, filter);
}

void source_file_read(int fd, short evtype, void *arg)
{
	struct source *source = arg;
	_pcap_read(source, source->as.file.pcap);
}

int source_sniff_init(struct source *source, const char *args)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	char *ifname, *filter;

	ifname = mmatic_strdup(source->spid->mm, args);
	filter = strchr(ifname, ' ');
	if (filter) *filter++ = '\0';

	source->as.sniff.pcap = pcap_open_live(ifname, SPI_PCAP_SNAPLEN, 1, SPI_PCAP_TIMEOUT, errbuf);
	if (!source->as.sniff.pcap) {
		dbg(0, "pcap_open_live(): %s\n", errbuf);
		return -1;
	}

	source->as.sniff.ifname = ifname;
	source->fd = pcap_fileno(source->as.sniff.pcap);
	return _pcap_add_filter(source, source->as.sniff.pcap, filter);
}

void source_sniff_read(int fd, short evtype, void *arg)
{
	struct source *source = arg;
	_pcap_read(source, source->as.sniff.pcap);
}
