/*
 * spid: Statistical Packet Inspection: verdict issuer
 * Copyright (C) 2011 Paweł Foremski <pawel@foremski.pl>
 * This software is licensed under GNU GPL version 3
 */

#include "datastructures.h"
#include "settings.h"
#include "verdict.h"
#include "spid.h"
#include "ep.h"

void _simple_verdict(struct spid *spid, struct classification_result *cr)
{
	cr->ep->verdict = cr->result;
	cr->ep->verdict_prob = 1.0;
	cr->ep->verdict_count++;
}

/*****/

void verdict_init(struct spid *spid)
{
	struct verdict *v;

	v = mmatic_zalloc(spid->mm, sizeof *v);
	v->type = SPI_VERDICT_SIMPLE; /* TODO :) */
	spid->vdata = v;

	spid_subscribe(spid, "endpointClassification", verdict_new_classification, false);
}

void verdict_free(struct spid *spid)
{
	mmatic_freeptr(spid->vdata);
	return;
}

void verdict_new_classification(struct spid *spid, const char *evname, void *arg)
{
	struct verdict *v = spid->vdata;
	struct classification_result *cr = arg;
	label_t old_value;

	old_value = cr->ep->verdict;

	/* update ep->verdict_prob and fetch new verdict value */
	switch (v->type) {
		case SPI_VERDICT_SIMPLE:
			_simple_verdict(spid, cr);
			break;
		case SPI_VERDICT_EWMA:
			dbg(0, "TODO\n");
			break;
	}

	dbg(5, "ep %s is %u\n", epa_print(cr->ep->epa), cr->ep->verdict);

	/* announce verdict only if it changed */
	if (old_value != cr->ep->verdict)
		spid_announce(spid, "endpointVerdictChanged", 0, cr->ep, false);
}
