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

void _simple_verdict(struct spi *spi, struct spi_classresult *cr)
{
	cr->ep->verdict = cr->result;
	cr->ep->verdict_prob = 1.0;
	cr->ep->verdict_count++;
}

/*****/

bool verdict_new_classification(struct spi *spi, const char *evname, void *arg)
{
	struct verdict *v = spi->vdata;
	struct spi_classresult *cr = arg;
	spi_label_t old_value;

	old_value = cr->ep->verdict;

	/* update ep->verdict_prob and fetch new verdict value */
	switch (v->type) {
		case SPI_VERDICT_SIMPLE:
			_simple_verdict(spi, cr);
			break;
		case SPI_VERDICT_EWMA:
			dbg(0, "TODO\n");
			break;
	}

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

	v = mmatic_zalloc(spi->mm, sizeof *v);
	v->type = SPI_VERDICT_SIMPLE; /* TODO :) */
	spi->vdata = v;

	spi_subscribe(spi, "endpointClassification", verdict_new_classification, false);
}

void verdict_free(struct spi *spi)
{
	mmatic_freeptr(spi->vdata);
	return;
}
