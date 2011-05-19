/*
 * spid: Statistical Packet Inspection
 * Copyright (C) 2011 Paweł Foremski <pawel@foremski.pl>
 * This software is licensed under GNU GPL version 3
 */

#include "datastructures.h"
#include "spid.h"
#include "kissp.h"
#include "ep.h"

void kissp_init(struct spid *spid)
{
	spid_subscribe(spid, SPI_EVENT_ENDPOINT_HAS_C_PKTS, kissp_ep_ready);
}

void kissp_ep_ready(struct spid *spid, spid_event_t code, void *data)
{
	struct ep *ep = data;

	/* just to be sure */
	if (tlist_count(ep->pkts) < spid->options.C)
		return;

	/* TODO
	 * - check for memory leaks before further work :)
	 * - compare liblinear and libsvm API
	 * - calculate ep->pkts signature: a (spid->options.N*2 + 3)-long array of (double) coordinates
	 *   -> idea: use liblinears? (libsvm?) array of struct feature_node arrays ended by (-1,?)
	 * - if ep->source->label != 0
	 *   -> queue the signature
	 *   -> announce kissp_train(label?) with 100ms delay
	 *     -> in handler use model* train(struct problem *, struct parameter *) to get the model
	 * - else
	 *   -> model* is needed
	 *   -> use int predict_probability(struct model *, struct feature_node *, double *output_probabilities) to classify
	 *   -> call or announce verdict_new_classification(ep, label, output_probabilities?) ?
	 *     -> can announce action_changed(ep) with some delay
	  */

	dbg(5, "endpoint %s ready!\n", epa_print(ep->epa));
	tlist_flush(ep->pkts);
	ep->has_C = false;
}
