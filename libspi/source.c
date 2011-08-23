/*
 * spi: Statistical Packet Inspection
 * Copyright (C) 2011 Paweł Foremski <pawel@foremski.pl>
 * This software is licensed under GNU GPL version 3
 */

#include <event2/event.h>
#include <pcap.h>

/* for parsing libpcap packets */
#define __FAVOR_BSD
#include <net/if.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "source.h"
#include "spi.h"
#include "ep.h"
#include "flow.h"

#define TCP_EPA_SRC(ip, tcp) (((uint64_t) SPI_PROTO_TCP << 48) | ((uint64_t) (ip)->ip_src.s_addr << 16) | ntohs((tcp)->th_sport))
#define TCP_EPA_DST(ip, tcp) (((uint64_t) SPI_PROTO_TCP << 48) | ((uint64_t) (ip)->ip_dst.s_addr << 16) | ntohs((tcp)->th_dport))
#define UDP_EPA_SRC(ip, udp) (((uint64_t) SPI_PROTO_UDP << 48) | ((uint64_t) (ip)->ip_src.s_addr << 16) | ntohs((udp)->uh_sport))
#define UDP_EPA_DST(ip, udp) (((uint64_t) SPI_PROTO_UDP << 48) | ((uint64_t) (ip)->ip_dst.s_addr << 16) | ntohs((udp)->uh_dport))

static int _pcap_err(pcap_t *pcap, const char *func, const char *id)
{
	dbg(0, "%s: %s: %s\n", func, id, pcap_geterr(pcap));
	return -1;
}

static int _pcap_add_filter(struct spi_source *source, pcap_t *pcap, const char *filter)
{
	struct bpf_program *cf;

	cf = mmatic_alloc(source->spi->mm, sizeof *cf);

	if (!filter)
		filter = SPI_PCAP_DEFAULT_FILTER;

	if (pcap_compile(pcap, cf, filter, 0, 0) == -1)
		return _pcap_err(pcap, "pcap_compile()", filter);

	if (pcap_setfilter(pcap, cf) == -1)
		return _pcap_err(pcap, "pcap_setfilter()", filter);

	return 0;
}

static void _parse_new_packet(struct spi_source *source,
	const struct timeval *tstamp, uint16_t pktlen, uint8_t *msg, uint16_t msglen)
{
#define PTROK(ptr, s) ((((uint8_t *) ptr) + (s) - msg) <= msglen)
	struct ether_header *eth;
	struct ip *ip;
	uint16_t iplen;
	struct tcphdr *tcp;
	struct udphdr *udp;
	uint8_t *data;
	spi_epaddr_t src, dst;

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
			if (!PTROK(tcp, sizeof *tcp))
				return;

			src = TCP_EPA_SRC(ip, tcp);
			dst = TCP_EPA_DST(ip, tcp);

			/* catch FIN/RST flags ASAP */
			flow_tcp_flags(source, src, dst, tcp);

			/* check if at least N bytes */
			data = ((uint8_t *) tcp) + tcp->th_off * 4;
			if (!PTROK(data, source->spi->options.N))
				return;

			/* enforce the P limit */
			if (flow_count(source, src, dst, tstamp) > source->spi->options.P)
				return;

			break;

		case IPPROTO_UDP:
			udp = (struct udphdr *) (((uint8_t *) ip) + iplen);
			if (!PTROK(udp, sizeof *udp))
				return;

			src = UDP_EPA_SRC(ip, udp);
			dst = UDP_EPA_DST(ip, udp);

			/* check if at least N bytes */
			data = ((uint8_t *) udp) + sizeof *udp;
			if (!PTROK(data, source->spi->options.N))
				return;

			break;

		case IPPROTO_ICMP:
			return;
		default:
			dbg(8, "skipping non-TCP/UDP packet, proto=%u\n", ip->ip_p);
			return;
	}

	/* XXX: add at both endpoints */
	ep_new_pkt(source, src, tstamp, data, pktlen);
	ep_new_pkt(source, dst, tstamp, data, pktlen);
}

static void _pcap_callback(u_char *arg, const struct pcap_pkthdr *msginfo, const u_char *msg)
{
	struct spi_source *source = (struct spi_source *) arg;

	source->counter++;

	/* move virtual time forward */
	if (source->type == SPI_SOURCE_FILE) {
		memcpy(&source->as.file.time, &msginfo->ts, sizeof(struct timeval));

		/* suggest garbage collector each virtual SPI_GC_INTERVAL seconds */
		if (source->as.file.gctime.tv_sec == 0) {
			source->as.file.gctime.tv_sec = source->as.file.time.tv_sec;
		} else if (source->as.file.gctime.tv_sec + SPI_GC_INTERVAL < source->as.file.time.tv_sec) {
			spi_announce(source->spi, "gcSuggestion", 0, NULL, false);
			source->as.file.gctime.tv_sec = source->as.file.time.tv_sec;
		}
	}

	/* NB: assuming Ethernet header starts at msg[0] */
	_parse_new_packet(source,
		&msginfo->ts, msginfo->len,
		(uint8_t *) msg, MIN(msginfo->caplen, msginfo->len));
}

static inline void _pcap_read(struct spi_source *source, pcap_t *pcap)
{
	switch (pcap_dispatch(pcap, SPI_PCAP_MAX, _pcap_callback, (u_char *) source)) {
		case 0:  /* no packets */
			source_close(source);
			return;
		case -1: /* error */
			if (source->type == SPI_SOURCE_FILE)
				_pcap_err(pcap, "pcap_dispatch()", source->as.file.path);
			else if (source->type == SPI_SOURCE_SNIFF)
				_pcap_err(pcap, "pcap_dispatch()", source->as.sniff.ifname);
			else
				_pcap_err(pcap, "pcap_dispatch()", "a pcap source");
			return;
		case -2: /* break loop (?!) */
			die("pcap_dispatch() returned -2\n");
			return;
	}
}

void source_close(struct spi_source *source)
{
	if (source->closed)
		return;

	switch (source->type) {
		case SPI_SOURCE_FILE:
			source_file_close(source);
			break;
		case SPI_SOURCE_SNIFF:
			source_sniff_close(source);
			break;
	}

	spi_announce(source->spi, "gcSuggestion", 0, NULL, false);
	spi_announce(source->spi, "sourceClosed", 0, source, false);
}

void source_destroy(struct spi_source *source)
{
	source_close(source);
	mmatic_freeptr(source);
}

/******/

int source_file_init(struct spi_source *source, const char *args)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	FILE *stream;
	char *path, *filter;

	path = mmatic_strdup(source->spi->mm, args);
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

	dbg(1, "pcap file %s opened\n", path);

	source->as.file.path = path;
	source->fd = fileno(stream);
	return _pcap_add_filter(source, source->as.file.pcap, filter);
}

void source_file_read(int fd, short evtype, void *arg)
{
	struct spi_source *source = arg;
	_pcap_read(source, source->as.file.pcap);
}

void source_file_close(struct spi_source *source)
{
	source->closed = true;

	if (source->evread) {
		event_del(source->evread);
		event_free(source->evread);
		source->evread = NULL;
	}

	pcap_close(source->as.file.pcap);
	source->as.file.time.tv_sec = -1;  /* = set virtual "now" to infinity */

	dbg(1, "pcap file %s finished and closed\n", source->as.file.path);
	dbg(2, "  read %u packets, %u samples (learned %u), %u endpoints\n",
		source->counter, source->signatures, source->learned, source->eps);
}

/******/

int source_sniff_init(struct spi_source *source, const char *args)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	char *ifname, *filter;

	ifname = mmatic_strdup(source->spi->mm, args);
	filter = strchr(ifname, ' ');
	if (filter) *filter++ = '\0';

	source->as.sniff.pcap = pcap_open_live(ifname, SPI_PCAP_SNAPLEN, 1, SPI_PCAP_TIMEOUT, errbuf);
	if (!source->as.sniff.pcap) {
		dbg(0, "pcap_open_live(): %s\n", errbuf);
		return -1;
	}

	dbg(1, "interface %s opened\n", ifname);

	source->as.sniff.ifname = ifname;
	source->fd = pcap_fileno(source->as.sniff.pcap);
	return _pcap_add_filter(source, source->as.sniff.pcap, filter);
}

void source_sniff_read(int fd, short evtype, void *arg)
{
	struct spi_source *source = arg;
	source->counter++;
	_pcap_read(source, source->as.sniff.pcap);
}

void source_sniff_close(struct spi_source *source)
{
	source->closed = true;

	if (source->evread) {
		event_del(source->evread);
		event_free(source->evread);
		source->evread = NULL;
	}

	pcap_close(source->as.sniff.pcap);

	dbg(1, "sniff source %s finished and closed\n", source->as.sniff.ifname);
	dbg(2, "  read %u packets, %u samples (learned %u), %u endpoints\n",
		source->counter, source->signatures, source->learned, source->eps);
}
