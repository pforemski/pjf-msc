/*
 * spid: Statistical Packet Inspection
 * Copyright (C) 2011 Paweł Foremski <pawel@foremski.pl>
 * This software is licensed under GNU GPL version 3
 */

#include <pcap.h>
#include "spid.h"

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

static void _pcap_callback(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *pkt)
{
	struct source *source = (struct source *) arg;

	/* TODO */
	dbg(0, "new packet! source %d:)\n", source->type);
}

static inline void _pcap_read(struct source *source, pcap_t *pcap)
{
	switch (pcap_dispatch(pcap, SPI_PCAP_MAX, _pcap_callback, (u_char *) source)) {
		case 0:  /* no packets */
			/* TODO: should not happen */
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
