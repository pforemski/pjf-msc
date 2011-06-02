/*
 * spid: Statistical Packet Inspection
 * Copyright (C) 2011 Paweł Foremski <pawel@foremski.pl>
 * This software is licensed under GNU GPL version 3
 */

#include <sys/time.h>
#include <libpjf/lib.h>
#include <event2/event.h>
#include <stdlib.h>

#include "settings.h"
#include "datastructures.h"
#include "spid.h"
#include "source.h"
#include "ep.h"
#include "flow.h"
#include "kissp.h"
#include "verdict.h"

/** Setup default options */
static void _options_defaults(struct spid *spid)
{
	spid->options.N = SPI_DEFAULT_N;
	spid->options.P = SPI_DEFAULT_P;
	spid->options.C = SPI_DEFAULT_C;
}

/** Garbage collector */
static void _gc(int fd, short evtype, void *arg)
{
	struct spid *spid = arg;
	const char *key;
	struct flow *flow;
	struct ep *ep;
	struct timeval systime;
	uint32_t now;

	gettimeofday(&systime, NULL);

	thash_iter_loop(spid->flows, key, flow) {
		if (flow->source->type == SPI_SOURCE_FILE)
			now = flow->source->as.file.time.tv_sec;
		else
			now = systime.tv_sec;

		if (flow->last.tv_sec + SPI_FLOW_TIMEOUT < now)
			thash_set(spid->flows, key, NULL);
	}

	thash_iter_loop(spid->eps, key, ep) {
		/* skip eps waiting for classification */
		if (ep->pending)
			continue;

		if (ep->source->type == SPI_SOURCE_FILE)
			now = ep->source->as.file.time.tv_sec;
		else
			now = systime.tv_sec;

		if (ep->last.tv_sec + SPI_EP_TIMEOUT < now)
			thash_set(spid->eps, key, NULL);
	}
}

static void _gc_suggested(struct spid *spid, const char *evname, void *data)
{
	_gc(0, 0, spid);
}

/** Handler for new spid events */
static void _new_spid_event(int fd, short evtype, void *arg)
{
	struct spid_event *se = arg;
	struct spid *spid = se->spid;
	struct spid_subscriber *ss;

	if (((int) thash_get(spid->aggstatus, se->evname)) == SPI_AGG_PENDING)
		thash_set(spid->aggstatus, se->evname, (void *) SPI_AGG_READY);

	tlist_iter_loop(se->sl, ss) {
		ss->handler(spid, se->evname, se->arg);
	}

	if (se->argfree)
		mmatic_freeptr(se->arg);

	mmatic_freeptr(se);
}

/*******************************/

struct spid *spid_init(struct spid_options *so)
{
	mmatic *mm;
	struct spid *spid;
	struct timeval tv;

	/* avoid epoll as it fails on pcap file fds */
	putenv("EVENT_NOEPOLL=1");

	/* data structure */
	mm = mmatic_create();
	spid = mmatic_zalloc(mm, sizeof *spid);
	spid->mm = mm;
	spid->eb = event_base_new();
	spid->sources = tlist_create(source_destroy, mm);
	spid->eps = thash_create_strkey(ep_destroy, mm);
	spid->flows = thash_create_strkey(flow_destroy, mm);
	spid->subscribers = thash_create_strkey(tlist_free, mm);
	spid->aggstatus = thash_create_strkey(NULL, mm);

	/* options */
	if (so)
		memcpy(&spid->options, so, sizeof *so);
	else
		_options_defaults(spid);

	/*
	 * setup events
	 */

	/* garbage collector */
	tv.tv_sec = SPI_GC_INTERVAL;
	tv.tv_usec = 0;
	spid->evgc = event_new(spid->eb, -1, EV_PERSIST, _gc, spid);
	event_add(spid->evgc, &tv);
	spid_subscribe(spid, "gcSuggestion", _gc_suggested, true);

	/* NB: "new packet" events will be added by spid_source_add() */

	/* initialize classifier */
	kissp_init(spid);

	/* initialize verdict */
	verdict_init(spid);

	/* TODO: statistics / diagnostics? */

	return spid;
}

int spid_source_add(struct spid *spid, spid_source_t type, label_t label, const char *args)
{
	struct source *source;
	int (*initcb)(struct source *source, const char *args);
	void (*readcb)(int fd, short evtype, void *arg);
	int rc;

	source = mmatic_zalloc(spid->mm, sizeof *source);
	source->spid = spid;
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
	source->evread = event_new(spid->eb, source->fd, EV_READ | EV_PERSIST, readcb, source);
	event_add(source->evread, 0);

	tlist_push(spid->sources, source);
	return rc;
}

int spid_loop(struct spid *spid)
{
	int rc;

	spid->running = true;
	rc = event_base_loop(spid->eb, EVLOOP_ONCE);
	spid->running = false;

	return rc;
}

int spid_stop(struct spid *spid)
{
	struct timeval tv = { 0, 0 };
	return event_base_loopexit(spid->eb, &tv);
}

void spid_announce(struct spid *spid, const char *evname, uint32_t delay_ms, void *arg, bool argfree)
{
	struct spid_event *se;
	struct timeval tv;
	int s;
	tlist *sl;

	/* handle aggregation */
	s = (int) thash_get(spid->aggstatus, evname);
	switch (s) {
		case SPI_AGG_IGNORE:
			break;
		case SPI_AGG_PENDING:
			goto quit;
		case SPI_AGG_READY:
			thash_set(spid->aggstatus, evname, (void *) SPI_AGG_PENDING);
			break;
	}

	/* get subscriber list */
	sl = thash_get(spid->subscribers, evname);
	if (!sl)
		goto quit;

	se = mmatic_alloc(spid->mm, sizeof *se);
	se->spid = spid;
	se->evname = evname;
	se->sl = sl;
	se->arg = arg;
	se->argfree = argfree;

	tv.tv_sec  = delay_ms / 1000;
	tv.tv_usec = (delay_ms % 1000) * 1000;

	/* XXX: queue instead of instant handler call */
	event_base_once(spid->eb, -1, EV_TIMEOUT, _new_spid_event, se, &tv);
	return;

quit:
	if (argfree) mmatic_freeptr(arg);
	return;
}

void spid_subscribe(struct spid *spid, const char *evname, spid_event_cb_t *cb, bool aggregate)
{
	struct spid_subscriber *ss;
	tlist *sl;

	/* get subscriber list */
	sl = thash_get(spid->subscribers, evname);
	if (!sl) {
		sl = tlist_create(mmatic_freeptr, spid->mm);
		thash_set(spid->subscribers, evname, sl);
	}

	/* append callback to subscriber list */
	ss = mmatic_zalloc(spid->mm, sizeof *ss);
	ss->handler = cb;
	tlist_push(sl, ss);

	if (aggregate)
		thash_set(spid->aggstatus, evname, (void *) SPI_AGG_READY);
	else
		thash_set(spid->aggstatus, evname, (void *) SPI_AGG_IGNORE);
}

void spid_free(struct spid *spid)
{
	if (spid->running) {
		dbg(0, "error: spid_free() while in spid_loop() - ignoring\n");
		return;
	}

	verdict_free(spid);
	kissp_free(spid);

	event_del(spid->evgc);
	event_free(spid->evgc);
	event_base_free(spid->eb);

	thash_free(spid->aggstatus);
	thash_free(spid->subscribers);
	thash_free(spid->flows);
	thash_free(spid->eps);
	tlist_free(spid->sources);

	mmatic_free(spid->mm);
}

/*
 * vim: path=.,/usr/include,/usr/local/include,~/local/include
 */
