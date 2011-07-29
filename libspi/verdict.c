/*
 * spi: Statistical Packet Inspection: verdict issuer
 * Copyright (C) 2011 Paweł Foremski <pawel@foremski.pl>
 * This software is licensed under GNU GPL version 3
 */

#include "datastructures.h"
#include "settings.h"
#include "verdict.h"
#include "spi.h"
#include "ep.h"

static void _simple_verdict(struct spi *spi, struct spi_classresult *cr)
{
	cr->ep->verdict = cr->result;
	cr->ep->verdict_prob = cr->cprob[cr->result];
	cr->ep->verdict_count++;
}

/*****/

static void _ewma_verdict(struct spi *spi, struct spi_classresult *cr)
{
	struct verdict *v = spi->vdata;
	struct ewma_verdict *ev = cr->ep->vdata;
	int i;
	double max = 0.0;
	spi_label_t max_label = 0;

	if (!ev) {
		ev = mmatic_zalloc(cr->ep->mm, sizeof *ev);
		cr->ep->vdata = ev;
	}

	for (i = 1; i < N(ev->cprob); i++) {
		ev->cprob[i] = EWMA(ev->cprob[i], cr->cprob[i], v->as.ewma.N);

		if (ev->cprob[i] > max) {
			max = ev->cprob[i];
			max_label = i;
		}
	}

	cr->ep->verdict = max_label;
	cr->ep->verdict_prob = max;
	cr->ep->verdict_count++;
}

/*****/

static bool _verdict_new_classification(struct spi *spi, const char *evname, void *arg)
{
	struct verdict *v = spi->vdata;
	struct spi_classresult *cr = arg;
	struct spi_ep *ep = cr->ep;
	int i;
	spi_label_t old_value;

	old_value = cr->ep->verdict;

	if (debug >= 5) {
		dbg(-1, "%s %-21s predicted as %d probs ",
			spi_proto2a(ep->proto), spi_epa2a(ep->epa), cr->result);
		for (i = 1; i < 10; i++)
			dbg(-1, "%.2f ", cr->cprob[i]);
		dbg(-1, "\n");
	}


	/* update ep->verdict_prob and fetch new verdict value */
	switch (v->type) {
		case SPI_VERDICT_SIMPLE:
			_simple_verdict(spi, cr);
			break;
		case SPI_VERDICT_EWMA:
			_ewma_verdict(spi, cr);
			break;
	}

	/* treat as "unknown" if below threshold */
	if (spi->options.verdict_threshold > 0.0 && cr->ep->verdict_prob < spi->options.verdict_threshold)
		cr->ep->verdict = 0;

	dbg(9, "ep %s is %u\n", spi_epa2a(cr->ep->epa), cr->ep->verdict);

	/* announce verdict only if it changed */
	if (old_value != cr->ep->verdict)
		spi_announce(spi, "endpointVerdictChanged", 0, cr->ep, false);

	return true;
}

/*****/

void verdict_init(struct spi *spi)
{
	struct verdict *v;

	spi_subscribe(spi, "endpointClassification", _verdict_new_classification, false);

	v = mmatic_zalloc(spi->mm, sizeof *v);
	spi->vdata = v;

	if (spi->options.verdict_simple) {
		v->type = SPI_VERDICT_SIMPLE;
	} else {
		v->type = SPI_VERDICT_EWMA;
		v->as.ewma.N = spi->options.verdict_ewma_len ? spi->options.verdict_ewma_len : 5;
	}
}

void verdict_free(struct spi *spi)
{
	mmatic_freeptr(spi->vdata);
	return;
}
