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

/** Find the distance between the first and the second highest value in cprob */
static double _cprob_dist(spi_cprob_t cprob)
{
	int i;
	double m1 = 0.0, m2 = 0.0;

	for (i = 1; i <= SPI_LABEL_MAX; i++) {
		if (cprob[i] > m2) {
			if (cprob[i] > m1) {
				m2 = m1;
				m1 = cprob[i];
			} else {
				m2 = cprob[i];
			}
		}
	}

	return (m1 - m2);
}

static void _cr_dump(struct spi_classresult *cr, int num)
{
	struct spi_ep *ep = cr->ep;
	int i;

	dbg(-1, "%-21s predicted as %d probs ", spi_epa2a(ep->epa), cr->result);
	for (i = 1; i < num; i++)
		dbg(-1, "%.2f ", cr->cprob[i]);
	dbg(-1, "  -> dist %g\n", _cprob_dist(cr->cprob));
}

/*****/

/** Use the best result so far */
static void _best_verdict(struct spi *spi, struct spi_classresult *cr)
{
	double dist;

	dist = _cprob_dist(cr->cprob);
	if (dist > cr->ep->verdict_prob) {
		cr->ep->verdict = cr->result;
		cr->ep->verdict_prob = dist;
	}
}

/*****/

static void _simple_verdict(struct spi *spi, struct spi_classresult *cr)
{
	cr->ep->verdict = cr->result;
	cr->ep->verdict_prob = _cprob_dist(cr->cprob);
}

/*****/

static void _ewma_verdict(struct spi *spi, struct spi_classresult *cr)
{
	struct verdict *v = spi->vdata;
	struct ewma_verdict *ev = cr->ep->vdata;
	int i;
	double m1 = 0.0, m2 = 0.0;
	spi_label_t max_label = 0;

	/* special case if its first verdict request */
	if (!ev) {
		ev = mmatic_zalloc(cr->ep->mm, sizeof *ev);
		cr->ep->vdata = ev;

		/* init EWMA with class. result */
		memcpy(ev->cprob, cr->cprob, sizeof(spi_cprob_t));

		/* fall-back on simple verdict */
		_simple_verdict(spi, cr);
	} else {
		/* update EWMA */
		for (i = 1; i <= SPI_LABEL_MAX; i++) {
			ev->cprob[i] = EWMA(ev->cprob[i], cr->cprob[i], v->as.ewma.N);

			/* collect info as _cprob_dist() */
			if (ev->cprob[i] > m2) {
				if (ev->cprob[i] > m1) {
					max_label = i;
					m2 = m1;
					m1 = ev->cprob[i];
				} else {
					m2 = ev->cprob[i];
				}
			}
		}

		if (m1 - m2 > cr->ep->verdict_prob) {
			cr->ep->verdict = max_label;
			cr->ep->verdict_prob = (m1 - m2);
		}
	}
}

/*****/

static bool _verdict_new_classification(struct spi *spi, const char *evname, void *arg)
{
	struct verdict *v = spi->vdata;
	struct spi_classresult *cr = arg;
	struct spi_ep *ep = cr->ep;
	spi_label_t old_value;

	if (debug >= 4)
		_cr_dump(cr, 10);

	/* store current classification verdict */
	old_value = cr->ep->verdict;

	/* update ep->verdict_prob and fetch new verdict value */
	switch (v->type) {
		case SPI_VERDICT_SIMPLE:
			_simple_verdict(spi, cr);
			break;
		case SPI_VERDICT_EWMA:
			_ewma_verdict(spi, cr);
			break;
		case SPI_VERDICT_BEST:
			_best_verdict(spi, cr);
			break;
	}

	/* correct the verdict - treat as "unknown" if it is below the threshold */
	if (cr->ep->verdict_prob < spi->options.verdict_threshold) {
		cr->ep->verdict = 0;
		cr->ep->verdict_prob = 0;
	}

	/* announce only if the verdict changed */
	if (cr->ep->verdict != old_value) {
		cr->ep->verdict_count++;
		spi_announce(spi, "endpointVerdictChanged", 0, cr->ep, false);
	} else {
		ep->gclock = false;
	}

	return true;
}

static bool _verdict_eaten(struct spi *spi, const char *evname, void *arg)
{
	struct spi_ep *ep = arg;

	/* information consumed by listener - mark endpoint as GC-possible */
	ep->gclock = false;

	return true;
}

/*****/

void verdict_init(struct spi *spi)
{
	struct verdict *v;

	spi_subscribe(spi, "endpointClassification", _verdict_new_classification, false);
	spi_subscribe_after(spi, "endpointVerdictChanged", _verdict_eaten, false);

	v = mmatic_zalloc(spi->mm, sizeof *v);
	spi->vdata = v;

	if (spi->options.verdict_simple) {
		v->type = SPI_VERDICT_SIMPLE;
	} else if (spi->options.verdict_best) {
		v->type = SPI_VERDICT_BEST;
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
