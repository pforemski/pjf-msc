/*
 * spid: Statistical Packet Inspection: KISS PLUS classifier
 * Copyright (C) 2011 Paweł Foremski <pawel@foremski.pl>
 * This software is licensed under GNU GPL version 3
 */

#include "datastructures.h"
#include "spid.h"
#include "kissp.h"
#include "ep.h"

static void _signature_free(void *arg)
{
	struct signature *sign = arg;

	mmatic_freeptr(sign->c);
	mmatic_freeptr(sign);
}

static struct signature *_signature_compute(struct spid *spid, tlist *pkts)
{
	struct signature *sign;

	sign = mmatic_zalloc(spid->mm, sizeof *sign);

	/* N bytes * 2 groups + 3 additional (size, delay and jitter) + 1 ending */
	sign->c = mmatic_zalloc(spid->mm, sizeof(*sign->c) * (spid->options.N*2 + 3 + 1));

	/* TODO :)
	sign->c[0..23] = byte occurance counter;
	sign->c[24] = avgsize;
	sign->c[25] = avgdelay;
	sign->c[26] = avgjitter; */

	sign->c[27].index = -1;
	return sign;
}

static void _signature_train(struct spid *spid, struct signature *sign, label_t label)
{
	//s->label = label;
	// tlist_push(kissp->traindata, sign);
	return;
}

/****/

void kissp_init(struct spid *spid)
{
	struct kissp *kissp;

	/* subscribe to endpoints accumulating 80+ packets */
	spid_subscribe(spid, SPI_EVENT_ENDPOINT_HAS_C_PKTS, kissp_ep_ready, false);

	kissp = mmatic_zalloc(spid->mm, sizeof *kissp);
	kissp->traindata = tlist_create(_signature_free, spid->mm);

	spid->cdata = kissp;

	/* TODO: subscribe to SPI_EVENT_KISSP_TRAIN */
}

void kissp_free(struct spid *spid)
{
	struct kissp *kissp = spid->cdata;

	tlist_free(kissp->traindata);
	mmatic_freeptr(kissp);
	spid->cdata = NULL;
}

void kissp_ep_ready(struct spid *spid, spid_event_t code, void *data)
{
	struct kissp *kissp = spid->cdata;
	struct ep *ep = data;
	struct signature *sign;

	/* just to be sure */
	if (tlist_count(ep->pkts) < spid->options.C)
		return;

	sign = _signature_compute(spid, ep->pkts);

	/* if a labelled sample, learn from it */
	if (ep->source->label != 0) {
		//_signature_train(spid, sign, ep->source->label);

		/* update model by running learning algo in 100ms from now */
		spid_announce(spid, SPI_EVENT_KISSP_TRAIN, NULL, 100);

		/* TODO
		 *   -> queue the signature
		 *   -> announce kissp_train(label?) with 100ms delay
		 *     -> in handler use model* train(struct problem *, struct parameter *) to get the model
		 */
	} else {
		/* TODO
		 * - else
		 *   -> model* is needed
		 *   -> use int predict_probability(struct model *, struct feature_node *, double *output_probabilities) to classify
		 *   -> call or announce verdict_new_classification(ep, label, output_probabilities?) ?
		 *     -> can announce action_changed(ep) with some delay
		  */

		_signature_free(sign);
	}

	dbg(5, "endpoint %s ready!\n", epa_print(ep->epa));
	tlist_flush(ep->pkts);
	ep->pending = false;
}
