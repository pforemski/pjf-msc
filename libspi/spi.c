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

/* Check if there is still something to do, otherwise announce "finished" */
static bool _check_if_finished(struct spi *spi, const char *evname, void *data)
{
	struct spi_source *source;
	int sources = 0;

	/* still some traindata waiting to be used */
	if (spi_pending(spi, "traindataUpdated"))
		return true;

	/* traindata queue empty? */
	if (tlist_count(spi->trainqueue) > 0)
		return true;

	/* are there open sources? */
	tlist_iter_loop(spi->sources, source) {
		if (!source->closed)
			sources++;
	}

	if (sources > 0)
		return true;

	/* everything ready */
	spi_announce(spi, "finished", 0, NULL, false);

	return true;
}

static void _subscriber_free(void *arg)
{
	struct spi_subscribers *ss = arg;

	tlist_free(ss->hl);
	tlist_free(ss->ahl);
	mmatic_freeptr(ss);
}

void spi_signature_free(void *arg)
{
	struct spi_signature *sign = arg;

	mmatic_freeptr(sign->c);
	mmatic_freeptr(sign);
}

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
	int flows = 0, eps = 0;

	gettimeofday(&systime, NULL);

	thash_iter_loop(spi->flows, key, flow) {
		/* drop all closed TCP connections */
		if (flow->rst == 3 || flow->fin == 3) {
			thash_set(spi->flows, key, NULL);
			continue;
		}

		/* check timeout */
		if (flow->source->type == SPI_SOURCE_FILE)
			now = flow->source->as.file.time.tv_sec;
		else
			now = systime.tv_sec;

		if (flow->last.tv_sec + SPI_FLOW_TIMEOUT < now)
			thash_set(spi->flows, key, NULL);

		flows++;
	}

	thash_iter_loop(spi->eps, key, ep) {
		/* skip eps under use */
		if (ep->gclock) {
			eps++;
			continue;
		}

		if (ep->source->type == SPI_SOURCE_FILE)
			now = ep->source->as.file.time.tv_sec;
		else
			now = systime.tv_sec;

		if (ep->last.tv_sec + SPI_EP_TIMEOUT < now)
			thash_set(spi->eps, key, NULL);

		eps++;
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
	union spi_ptr2eventcb_tool pf;

	if (spi_pending(spi, se->evname))
		thash_set(spi->aggstatus, se->evname, (void *) SPI_AGG_READY);

	/* handler list */
	tlist_iter_loop(se->ss->hl, pf.ptr) {
		if (!pf.func(spi, se->evname, se->arg))
			tlist_remove(se->ss->hl);
	}

	/* after handler list */
	tlist_iter_loop(se->ss->ahl, pf.ptr) {
		if (!pf.func(spi, se->evname, se->arg))
			tlist_remove(se->ss->ahl);
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
	spi->subscribers = thash_create_strkey(_subscriber_free, mm);
	spi->aggstatus = thash_create_strkey(NULL, mm);
	spi->traindata = tlist_create(spi_signature_free, spi->mm);
	spi->trainqueue = tlist_create(NULL, spi->mm); /* @1: dont free */

	/* options */
	if (so)
		memcpy(&spi->options, so, sizeof *so);
	else
		_options_defaults(spi);

	/*
	 * setup events
	 * NB: new packet events will be added in spi_source_add()
	 */

	/* garbage collector */
	tv.tv_sec = SPI_GC_INTERVAL;
	tv.tv_usec = 0;
	spi->evgc = event_new(spi->eb, -1, EV_PERSIST, _gc, spi);
	event_add(spi->evgc, &tv);
	spi_subscribe(spi, "gcSuggestion", _gc_suggested, true);
	spi_subscribe(spi, "classifierModelUpdated", _gc_suggested, true);

	/* monitor for end of work */
	spi_subscribe_after(spi, "sourceClosed", _check_if_finished, true);
	spi_subscribe_after(spi, "traindataUpdated", _check_if_finished, true);

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

	if (spi->quitting)
		return 2;

	spi->running = true;
	rc = event_base_loop(spi->eb, EVLOOP_ONCE);
	spi->running = false;

	return rc;
}

void spi_stop(struct spi *spi)
{
	spi->quitting = true;
	event_base_loopbreak(spi->eb);
}

void spi_announce(struct spi *spi, const char *evname, uint32_t delay_ms, void *arg, bool argfree)
{
	struct spi_event *se;
	struct timeval tv;
	int s;
	struct spi_subscribers *ss;

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

	/* get subscribers */
	ss = thash_get(spi->subscribers, evname);
	if (!ss)
		goto quit;

	se = mmatic_alloc(spi->mm, sizeof *se);
	se->spi = spi;
	se->evname = evname;
	se->ss = ss;
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

static void _subscribe_to(struct spi *spi, const char *evname, spi_event_cb_t *cb, bool aggregate, bool to_ah)
{
	struct spi_subscribers *ss;
	union spi_ptr2eventcb_tool pf;

	/* get subscribers */
	ss = thash_get(spi->subscribers, evname);
	if (!ss) {
		ss = mmatic_zalloc(spi->mm, sizeof *ss);
		ss->hl = tlist_create(NULL, spi->mm);
		ss->ahl = tlist_create(NULL, spi->mm);
		thash_set(spi->subscribers, evname, ss);
	}

	/* append callback to appropriate subscriber list */
	pf.func = cb;
	tlist_push(to_ah ? ss->ahl : ss->hl, pf.ptr);

	if (aggregate)
		thash_set(spi->aggstatus, evname, (void *) SPI_AGG_READY);
	else
		thash_set(spi->aggstatus, evname, (void *) SPI_AGG_IGNORE);
}

void spi_subscribe(struct spi *spi, const char *evname, spi_event_cb_t *cb, bool aggregate)
{
	_subscribe_to(spi, evname, cb, aggregate, false);
}

void spi_subscribe_after(struct spi *spi, const char *evname, spi_event_cb_t *cb, bool aggregate)
{
	_subscribe_to(spi, evname, cb, aggregate, true);
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

	tlist_free(spi->trainqueue);
	tlist_free(spi->traindata);
	thash_free(spi->aggstatus);
	thash_free(spi->subscribers);
	thash_free(spi->flows);
	thash_free(spi->eps);
	tlist_free(spi->sources);

	mmatic_free(spi->mm);
}

bool spi_pending(struct spi *spi, const char *evname)
{
	return (((int) thash_get(spi->aggstatus, evname)) == SPI_AGG_PENDING);
}

void spi_train(struct spi *spi, struct spi_signature *sign)
{
	tlist_push(spi->traindata, sign);

	/* update model with a delay so many training samples have chance to be queued */
	spi_announce(spi, "traindataUpdated", SPI_TRAINING_DELAY, NULL, false);

	return;
}

void spi_trainqueue_add(struct spi *spi, struct spi_signature *sign)
{
	tlist_push(spi->trainqueue, sign);
}

void spi_trainqueue_commit(struct spi *spi)
{
	struct spi_signature *sign;

	tlist_iter_loop(spi->trainqueue, sign) {
		tlist_push(spi->traindata, sign); /* @1 */
		spi->learned_tq++;
	}

	tlist_flush(spi->trainqueue);
	spi_announce(spi, "traindataUpdated", 0, NULL, false);
}

/*
 * vim: path=.,/usr/include,/usr/local/include,~/local/include
 */
