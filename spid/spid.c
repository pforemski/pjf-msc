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

static void _gc_suggested(struct spid *spid, spid_event_t code, void *data)
{
	_gc(0, 0, spid);
}

/** Handler for new spid events */
static void _new_spid_event(int fd, short evtype, void *arg)
{
	struct spid_event *se = arg;
	struct spid_subscriber *ss;

	tlist_iter_loop(se->spid->subscribers[se->code], ss) {
		if (se->spid->status[se->code] == 1)
			se->spid->status[se->code] = 0;

		ss->handler(se->spid, se->code, se->data);
	}

	mmatic_freeptr(se);
}

/*******************************/

struct spid *spid_init(struct spid_options *so)
{
	int i;
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

	for (i = 0; i < SPI_EVENT_MAX; i++)
		spid->subscribers[i] = tlist_create(mmatic_freeptr, mm);

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
	spid_subscribe(spid, SPI_EVENT_SUGGEST_GC, _gc_suggested, true);

	/* NB: "new packet" events will be added by spid_source_add() */

	/* initialize classifier */
	kissp_init(spid);

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

void spid_announce(struct spid *spid, spid_event_t code, void *data, uint32_t delay_ms)
{
	struct spid_event *se;
	struct timeval tv;

	if (spid->status[code] == 1)
		return;
	else if (spid->status[code] == 0)
		spid->status[code] = 1;

	se = mmatic_alloc(spid->mm, sizeof *se);
	se->spid = spid;
	se->code = code;
	se->data = data;

	tv.tv_sec  = delay_ms / 1000;
	tv.tv_usec = (delay_ms % 1000) * 1000;

	/* XXX: queue instead of instant handler call */
	event_base_once(spid->eb, -1, EV_TIMEOUT, _new_spid_event, se, &tv);
}

void spid_subscribe(struct spid *spid, spid_event_t code, spid_event_cb_t *cb, bool aggregate)
{
	struct spid_subscriber *ss;

	ss = mmatic_alloc(spid->mm, sizeof *ss);
	ss->handler = cb;

	tlist_push(spid->subscribers[code], ss);

	if (aggregate)
		spid->status[code] = 0;
	else
		spid->status[code] = -1;
}

void spid_free(struct spid *spid)
{
	int i;

	if (spid->running) {
		dbg(0, "error: spid_free() while in spid_loop() - ignoring\n");
		return;
	}

	kissp_free(spid);

	event_del(spid->evgc);
	event_free(spid->evgc);
	event_base_free(spid->eb);

	for (i = 0; i < SPI_EVENT_MAX; i++)
		tlist_free(spid->subscribers[i]);

	thash_free(spid->flows);
	thash_free(spid->eps);
	tlist_free(spid->sources);

	mmatic_free(spid->mm);
}

/*
 * vim: path=.,/usr/include,/usr/local/include,~/local/include
 */
