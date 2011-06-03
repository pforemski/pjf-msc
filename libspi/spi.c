/*
 * spi: Statistical Packet Inspection
 * Copyright (C) 2011 Paweł Foremski <pawel@foremski.pl>
 * This software is licensed under GNU GPL version 3
 */

#include <sys/time.h>
#include <libpjf/lib.h>
#include <event2/event.h>
#include <stdlib.h>

#include "settings.h"
#include "datastructures.h"
#include "spi.h"
#include "source.h"
#include "ep.h"
#include "flow.h"
#include "kissp.h"
#include "verdict.h"

/** Setup default options */
static void _options_defaults(struct spi *spi)
{
	spi->options.N = SPI_DEFAULT_N;
	spi->options.P = SPI_DEFAULT_P;
	spi->options.C = SPI_DEFAULT_C;
}

/** Garbage collector */
static void _gc(int fd, short evtype, void *arg)
{
	struct spi *spi = arg;
	const char *key;
	struct spi_flow *flow;
	struct spi_ep *ep;
	struct timeval systime;
	uint32_t now;

	gettimeofday(&systime, NULL);

	thash_iter_loop(spi->flows, key, flow) {
		if (flow->source->type == SPI_SOURCE_FILE)
			now = flow->source->as.file.time.tv_sec;
		else
			now = systime.tv_sec;

		if (flow->last.tv_sec + SPI_FLOW_TIMEOUT < now)
			thash_set(spi->flows, key, NULL);
	}

	thash_iter_loop(spi->eps, key, ep) {
		/* skip eps waiting for classification */
		if (ep->pending)
			continue;

		if (ep->source->type == SPI_SOURCE_FILE)
			now = ep->source->as.file.time.tv_sec;
		else
			now = systime.tv_sec;

		if (ep->last.tv_sec + SPI_EP_TIMEOUT < now)
			thash_set(spi->eps, key, NULL);
	}
}

static bool _gc_suggested(struct spi *spi, const char *evname, void *data)
{
	_gc(0, 0, spi);
	return true;
}

/** Handler for new spi events */
static void _new_spi_event(int fd, short evtype, void *arg)
{
	struct spi_event *se = arg;
	struct spi *spi = se->spi;
	struct spi_subscriber *ss;

	if (((int) thash_get(spi->aggstatus, se->evname)) == SPI_AGG_PENDING)
		thash_set(spi->aggstatus, se->evname, (void *) SPI_AGG_READY);

	tlist_iter_loop(se->sl, ss) {
		if (!ss->handler(spi, se->evname, se->arg))
			tlist_remove(se->sl);
	}

	if (se->argfree)
		mmatic_freeptr(se->arg);

	mmatic_freeptr(se);
}

/*******************************/

struct spi *spi_init(struct spi_options *so)
{
	mmatic *mm;
	struct spi *spi;
	struct timeval tv;

	/* avoid epoll as it fails on pcap file fds */
	putenv("EVENT_NOEPOLL=1");

	/* data structure */
	mm = mmatic_create();
	spi = mmatic_zalloc(mm, sizeof *spi);
	spi->mm = mm;
	spi->eb = event_base_new();
	spi->sources = tlist_create(source_destroy, mm);
	spi->eps = thash_create_strkey(ep_destroy, mm);
	spi->flows = thash_create_strkey(flow_destroy, mm);
	spi->subscribers = thash_create_strkey(tlist_free, mm);
	spi->aggstatus = thash_create_strkey(NULL, mm);

	/* options */
	if (so)
		memcpy(&spi->options, so, sizeof *so);
	else
		_options_defaults(spi);

	/*
	 * setup events
	 */

	/* garbage collector */
	tv.tv_sec = SPI_GC_INTERVAL;
	tv.tv_usec = 0;
	spi->evgc = event_new(spi->eb, -1, EV_PERSIST, _gc, spi);
	event_add(spi->evgc, &tv);
	spi_subscribe(spi, "gcSuggestion", _gc_suggested, true);

	/* NB: "new packet" events will be added by spi_source_add() */

	/* initialize classifier */
	kissp_init(spi);

	/* initialize verdict */
	verdict_init(spi);

	/* TODO: statistics / diagnostics? */

	return spi;
}

int spi_source_add(struct spi *spi, spi_source_t type, spi_label_t label, const char *args)
{
	struct spi_source *source;
	int (*initcb)(struct spi_source *source, const char *args);
	void (*readcb)(int fd, short evtype, void *arg);
	int rc;

	source = mmatic_zalloc(spi->mm, sizeof *source);
	source->spi = spi;
	source->type = type;
	source->label = label;

	/* callbacks */
	switch (type) {
		case SPI_SOURCE_FILE:
			initcb = source_file_init;
			readcb = source_file_read;
			break;
		case SPI_SOURCE_SNIFF:
			initcb  = source_sniff_init;
			readcb = source_sniff_read;
			break;
	}

	/* initialize source handler, should give us valid source->fd to monitor */
	rc = initcb(source, args);
	if (rc != 0)
		return rc;

	/* monitor source fd for new packets */
	source->evread = event_new(spi->eb, source->fd, EV_READ | EV_PERSIST, readcb, source);
	event_add(source->evread, 0);

	tlist_push(spi->sources, source);
	return rc;
}

int spi_loop(struct spi *spi)
{
	int rc;

	spi->running = true;
	rc = event_base_loop(spi->eb, EVLOOP_ONCE);
	spi->running = false;

	return rc;
}

int spi_stop(struct spi *spi)
{
	struct timeval tv = { 0, 0 };
	return event_base_loopexit(spi->eb, &tv);
}

void spi_announce(struct spi *spi, const char *evname, uint32_t delay_ms, void *arg, bool argfree)
{
	struct spi_event *se;
	struct timeval tv;
	int s;
	tlist *sl;

	/* handle aggregation */
	s = (int) thash_get(spi->aggstatus, evname);
	switch (s) {
		case SPI_AGG_IGNORE:
			break;
		case SPI_AGG_PENDING:
			goto quit;
		case SPI_AGG_READY:
			thash_set(spi->aggstatus, evname, (void *) SPI_AGG_PENDING);
			break;
	}

	if (delay_ms)
		dbg(8, "event %s in %u ms\n", evname, delay_ms);
	else
		dbg(8, "event %s\n", evname);

	/* get subscriber list */
	sl = thash_get(spi->subscribers, evname);
	if (!sl)
		goto quit;

	se = mmatic_alloc(spi->mm, sizeof *se);
	se->spi = spi;
	se->evname = evname;
	se->sl = sl;
	se->arg = arg;
	se->argfree = argfree;

	tv.tv_sec  = delay_ms / 1000;
	tv.tv_usec = (delay_ms % 1000) * 1000;

	/* XXX: queue instead of instant handler call */
	event_base_once(spi->eb, -1, EV_TIMEOUT, _new_spi_event, se, &tv);
	return;

quit:
	if (argfree) mmatic_freeptr(arg);
	return;
}

void spi_subscribe(struct spi *spi, const char *evname, spi_event_cb_t *cb, bool aggregate)
{
	struct spi_subscriber *ss;
	tlist *sl;

	/* get subscriber list */
	sl = thash_get(spi->subscribers, evname);
	if (!sl) {
		sl = tlist_create(mmatic_freeptr, spi->mm);
		thash_set(spi->subscribers, evname, sl);
	}

	/* append callback to subscriber list */
	ss = mmatic_zalloc(spi->mm, sizeof *ss);
	ss->handler = cb;
	tlist_push(sl, ss);

	if (aggregate)
		thash_set(spi->aggstatus, evname, (void *) SPI_AGG_READY);
	else
		thash_set(spi->aggstatus, evname, (void *) SPI_AGG_IGNORE);
}

void spi_free(struct spi *spi)
{
	if (spi->running) {
		dbg(0, "error: spi_free() while in spi_loop() - ignoring\n");
		return;
	}

	verdict_free(spi);
	kissp_free(spi);

	event_del(spi->evgc);
	event_free(spi->evgc);
	event_base_free(spi->eb);

	thash_free(spi->aggstatus);
	thash_free(spi->subscribers);
	thash_free(spi->flows);
	thash_free(spi->eps);
	tlist_free(spi->sources);

	mmatic_free(spi->mm);
}

/*
 * vim: path=.,/usr/include,/usr/local/include,~/local/include
 */
