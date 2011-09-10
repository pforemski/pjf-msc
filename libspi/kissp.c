/*
 * spi: Statistical Packet Inspection: KISS PLUS classifier
 * Copyright (C) 2011 Paweł Foremski <pawel@foremski.pl>
 * This software is licensed under GNU GPL version 3
 */

#include <math.h>
#include <svm.h>

#include "datastructures.h"
#include "spi.h"
#include "kissp.h"
#include "ep.h"

/********** libsvm */
static void _svm_print_func(const char *msg)
{
	while (*msg == '\n') msg++;
	dbg(7, "libsvm: %s", msg);
}

static void _svm_init(struct spi *spi)
{
	struct kissp *kissp = spi->cdata;

	if (spi->options.libsvm_params) {
		memcpy(&kissp->svm.params, spi->options.libsvm_params, sizeof kissp->svm.params);
	} else {
		/* defaults */
		kissp->svm.params.kernel_type = RBF;
		kissp->svm.params.gamma = 0.5; /* found by grid.py */
		kissp->svm.params.C = 2.0; /* found by grid.py */
		kissp->svm.params.eps = 0.1;

		kissp->svm.params.nr_weight = 0;     /* NB: .weight_label and .weight not set */
		kissp->svm.params.cache_size = 100;
		kissp->svm.params.shrinking = 1;
	}

	/* required options */
	kissp->svm.params.svm_type = C_SVC;
	kissp->svm.params.probability = 1; /* NB */

	kissp->svm.labels = mmatic_zalloc(spi->mm, sizeof(int) * SPI_LABEL_MAX);

	svm_set_print_string_function(_svm_print_func);
}

static bool _svm_train(struct spi *spi, const char *evname, void *data)
{
	struct kissp *kissp = spi->cdata;
	struct svm_problem p;
	struct spi_signature *s;
	int i;
	const char *err;

	/* describe the problem */
	p.l = tlist_count(spi->traindata);
	p.x = mmatic_alloc(spi->mm, (sizeof (void *)) * p.l);
	p.y = mmatic_alloc(spi->mm, (sizeof (double)) * p.l);

	i = 0;
	tlist_iter_loop(spi->traindata, s) {
		p.x[i] = (struct svm_node *) s->c;   /* NB: identical */
		p.y[i] = s->label;
		i++;
	}

	/* check */
	err = svm_check_parameter(&p, &kissp->svm.params);
	if (err) {
		dbg(1, "libsvm training failed: check_parameter(): %s\n", err);
		return true;
	}

	/* destroy previous model */
	if (kissp->svm.model)
		svm_free_and_destroy_model(&kissp->svm.model);

	/* run */
	kissp->svm.model = svm_train(&p, &kissp->svm.params);
	kissp->svm.nr_class = svm_get_nr_class(kissp->svm.model);
	svm_get_labels(kissp->svm.model, kissp->svm.labels);

	dbg(5, "updated libsvm model, nr_class=%d\n", kissp->svm.nr_class);
	spi_announce(spi, "classifierModelUpdated", 0, NULL, false);

	mmatic_freeptr(p.x);
	mmatic_freeptr(p.y);

	return true;
}

static bool _svm_predict(struct spi *spi, struct spi_signature *sign, struct spi_ep *ep)
{
	struct kissp *kissp = spi->cdata;
	struct spi_classresult *cr;
	int i;

	if (!kissp->svm.model) {
		dbg(1, "cant classify: no model\n");
		return false;
	}

	cr = mmatic_zalloc(spi->mm, sizeof *cr);
	cr->ep = ep;
	cr->result = svm_predict_probability(kissp->svm.model, (struct svm_node *) sign->c, cr->cprob_lib);

	/* rewrite from libsvm's to ours */
	for (i = 0; i < kissp->svm.nr_class; i++)
		cr->cprob[kissp->svm.labels[i]] = cr->cprob_lib[i];

	ep->gclock2++;
	spi_announce(spi, "endpointClassification", 0, cr, true);

	return true;
}

/********** signature generation */
#define GV2I(group, value) (((group) * 16) + ((value) % 16))

/** Compute window signature and eat packets */
static struct spi_signature *_signature_compute_eat(struct spi *spi, struct spi_ep *ep)
{
	struct kissp *kissp = spi->cdata;
	struct spi_signature *sign; /** the resultant signature */
	struct spi_coordinate *c;   /** shortcut pointer inside sign->c[] */
	struct spi_pkt *pkt;
	uint8_t *o;             /** table of occurances note: uint8_t because options.C < 256 */
	int i, j, pktcnt;
	double E;               /** expected number of occurances */
	double max;             /** max value of single KISS signature coordinate */
	void *v;

	struct timeval Tp;      /** previous packet time */
	struct timeval Tdiff;   /** delay to previous packet */
	uint32_t x, xp = 0;     /** delay: current, previous */
	tlist *delays;          /** delay queue */

	double An, A = 0;       /** average delay estimation */
	double S = 0;           /** delay std deviation estimation */
	double xlimit;          /** delay outlier limit */

	double avgdelay = 0;    /** average delay */
	double avgjitter = 0;   /** average jitter */
	double avgsize = 0;     /** average packet size */

	sign = mmatic_zalloc(spi->mm, sizeof *sign);
	o = mmatic_zalloc(spi->mm, spi->options.N * 2 * 16); /* 2N groups, in each 16 groups */
	delays = tlist_create(NULL, spi->mm);

	timerclear(&Tp);

	/* +1 for ending index=-1 */
	sign->c = mmatic_zalloc(spi->mm, sizeof(*sign->c) * (kissp->feature_num + 1));

	/* 1) count byte occurances in each of 2N groups
	 * 2) compute approximate mean packet size
	 * 3) determine approximate mean delay and its variance */
	for (pktcnt = 0; pktcnt < spi->options.C && (pkt = tlist_shift(ep->pkts)); pktcnt++) {
		for (i = 0; i < spi->options.N; i++) {
			o[GV2I(2*i + 0, pkt->payload[i] & 0x0f)]++;
			o[GV2I(2*i + 1, pkt->payload[i]   >> 4)]++;
		}

		avgsize += (pkt->size - avgsize) / (pktcnt + 1);

		if (pktcnt > 0) {
			timersub(&pkt->ts, &Tp, &Tdiff);
			x = Tdiff.tv_sec * 1000 + Tdiff.tv_usec / 1000;

			v = (void *) (x + 1);
			tlist_push(delays, v);    /* @1: 0 is ~ NULL, avoid it */

			An = A + (x - A) / pktcnt;
			S += (x - A) * (x - An);
			A = An;
		}

		memcpy(&Tp, &pkt->ts, sizeof Tp);
	}

	/* expected value of occurances */
	E = (double) pktcnt / 16.0;

	/* max is when there is one constant value and rest=0 */
	max = (pow(E - pktcnt, 2.0) + 15*pow(E - 0.0, 2.0)) / E;

	/* for each group sum up the difference of occurance from expected value */
	for (i = 0; i < spi->options.N * 2; i++) {
		c = &sign->c[i];

		c->index = i + 1;
		for (j = 0; j < 16; j++)
			c->value += pow(E - o[GV2I(i, j)], 2.0);
		c->value /= E;
		c->value /= max; /* normalize */
	}

	if (!kissp->options.pktstats) {
		sign->c[spi->options.N * 2].index = -1;
	} else {
		/* compute average delay and jitter, without outliers */
		S = sqrt(S / pktcnt);        /* now its standard deviation */
		xlimit = A + 1.645 * S;      /* outside of 10% of std dist. area */
		i = j = 1;
		tlist_iter_loop(delays, v) {
			x = ((uint32_t) v) - 1; /* @1 */

			if (x > xlimit)
				continue;

			if (i > 1) {
				if (xp > x)
					avgjitter += (xp - x - avgjitter) / j++;
				else
					avgjitter += (x - xp - avgjitter) / j++;
			}

			avgdelay += (x - avgdelay) / i++;
			xp = x;
		}

		dbg(7, "ep %s flow stats: avgsize=%.0fB avgdelay=%.0fms avgjitter=%0.fms\n",
			spi_epa2a(ep->epa), avgsize, avgdelay, avgjitter);

		/* normalize avg stats */
		if (avgsize > 1500)
			avgsize = 1.0;
		else
			avgsize /= 1500.0;

		if (avgdelay > 1000)
			avgdelay = 1.0;
		else
			avgdelay /= 1000.0;

		if (avgjitter > 1000)
			avgjitter = 1.0;
		else
			avgjitter /= 1000;

		/* write KISS+ features */
		i = spi->options.N * 2;

		/* average size */
		sign->c[i].index = i + 1;
		sign->c[i].value = avgsize;
		i++;

		/* average delay */
		sign->c[i].index = i + 1;
		sign->c[i].value = avgdelay;
		i++;

		/* average jitter */
		sign->c[i].index = i + 1;
		sign->c[i].value = avgjitter;
		i++;

		/* transmission protocol */
		sign->c[i].index = i + 1;
		sign->c[i].value = ((double) spi_epa2proto(ep->epa) / 2.0);
		i++;

		sign->c[i].index = -1;
	}

	mmatic_freeptr(o);
	tlist_free(delays);

	if (debug >= 5) {
		dbg(-1, "%-21s ", spi_epa2a(ep->epa));
		for (i = 0; sign->c[i].index > 0; i++)
			dbg(-1, "%.3f ", sign->c[i].value);
		dbg(-1, "\n");
	}

	return sign;
}

/********** event handlers */

/** Receives "endpointPacketsReady */
static bool _ep_ready(struct spi *spi, const char *evname, void *data)
{
	struct spi_ep *ep = data;
	struct spi_source *source = ep->source;
	struct spi_signature *sign;

	while (tlist_count(ep->pkts) >= spi->options.C) {
		sign = _signature_compute_eat(spi, ep);
		source->signatures++;

		/* if a learning source, submit as a training sample */
		if (source->label && !source->testing) {
			sign->label = source->label;

			spi_train(spi, sign);
			source->learned++;
			spi->stats.learned_pkt++;
		} else {
			/* make a prediction */
			if (_svm_predict(spi, sign, ep))
				ep->predictions++;

			spi_signature_free(sign);
		}
	}

	ep->gclock1--;
	return true;
}

/**********/

void kissp_init(struct spi *spi)
{
	struct kissp *kissp;

	/* subscribe to endpoints accumulating 80+ packets */
	spi_subscribe(spi, "endpointPacketsReady", _ep_ready, false);

	/* subscribe to new learning samples */
	spi_subscribe(spi, "traindataUpdated", _svm_train, true);

	/* KISS+ internal data */
	kissp = mmatic_zalloc(spi->mm, sizeof *kissp);
	spi->cdata = kissp;

	if (spi->options.kiss_std) {
		kissp->options.pktstats = false;
		kissp->feature_num = spi->options.N*2;
	} else {
		kissp->options.pktstats = true;
		kissp->feature_num = spi->options.N*2 + SPI_KISSP_FEATURES;
	}

	/* initialize underlying classifier library */
	_svm_init(spi);
}

void kissp_free(struct spi *spi)
{
	struct kissp *kissp = spi->cdata;

	mmatic_freeptr(kissp);
	spi->cdata = NULL;
}


