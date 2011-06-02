/*
 * spi: Statistical Packet Inspection: KISS PLUS classifier
 * Copyright (C) 2011 Paweł Foremski <pawel@foremski.pl>
 * This software is licensed under GNU GPL version 3
 */

#include <math.h>
#include "datastructures.h"
#include "spi.h"
#include "kissp.h"
#include "ep.h"

/********** liblinear */
static void _linear_print_func(const char *msg)
{
	while (*msg == '\n') msg++;
	dbg(9, "liblinear: %s", msg);
}

static void _linear_init(struct spi *spi)
{
	struct kissp *kissp = spi->cdata;

	/* set parameters (TODO?) */
	kissp->as.linear.params.solver_type = L2R_L2LOSS_SVC_DUAL;
	kissp->as.linear.params.eps = 0.1;
	kissp->as.linear.params.C = 1;
	kissp->as.linear.params.nr_weight = 0;     /* NB: .weight_label and .weight not set */

	set_print_string_function(_linear_print_func);
}

static void _linear_train(struct spi *spi)
{
	struct kissp *kissp = spi->cdata;
	struct problem p;
	struct signature *s;
	int i;
	const char *err;

	/* describe the problem */
	p.l = tlist_count(kissp->traindata);

	p.n = spi->options.N * 2;
	if (kissp->options.pktstats)
		p.n += 3;

	p.x = mmatic_alloc(spi->mm, (sizeof (void *)) * p.l);
	p.y = mmatic_alloc(spi->mm, (sizeof (int)) * p.l);

	i = 0;
	tlist_iter_loop(kissp->traindata, s) {
		p.x[i] = (struct feature_node *) s->c;   /* NB: identical */
		p.y[i] = s->label;
		i++;
	}

	p.bias = -1.0;

	/* check */
	err = check_parameter(&p, &kissp->as.linear.params);
	if (err) {
		dbg(1, "liblinear training failed: check_parameter(): %s\n", err);
		return;
	}

	/* destroy previous model */
	if (kissp->as.linear.model)
		free_and_destroy_model(&kissp->as.linear.model);

	/* run */
	kissp->as.linear.model = train(&p, &kissp->as.linear.params);

	dbg(5, "updated liblinear model, nr_class=%d, nr_feature=%d\n",
		kissp->as.linear.model->nr_class,
		kissp->as.linear.model->nr_feature);

	mmatic_freeptr(p.x);
	mmatic_freeptr(p.y);
}

static void _linear_predict(struct spi *spi, struct signature *sign, struct spi_ep *ep)
{
	struct kissp *kissp = spi->cdata;
	struct spi_classresult *cr;

	if (!kissp->as.linear.model) {
		dbg(1, "cant classify: no model\n");
		return;
	}

	cr = mmatic_zalloc(spi->mm, sizeof *cr);
	cr->ep = ep;

	switch (kissp->as.linear.params.solver_type) {
		case L2R_LR:
		case L1R_LR:
			/* logistic regression supports prediction probability */
			cr->result = predict_probability(kissp->as.linear.model, (struct feature_node *) sign->c, cr->cprob);
			break;
		default:
			cr->result = predict(kissp->as.linear.model, (struct feature_node *) sign->c);
			cr->cprob[cr->result] = 1.0;
			break;
	}

	spi_announce(spi, "endpointClassification", 0, cr, true);
}

/********** libsvm */
static void _svm_train(struct spi *spi)
{
	dbg(0, "TODO :)\n");
}

/********** signature generation */
static void _signature_free(void *arg)
{
	struct signature *sign = arg;

	mmatic_freeptr(sign->c);
	mmatic_freeptr(sign);
}

#define GV2I(group, value) (((group) * 16) + ((value) % 16))

/** Compute window signature and eat packets */
static struct signature *_signature_compute_eat(struct spi *spi, tlist *pkts)
{
	struct kissp *kissp = spi->cdata;
	struct signature *sign; /** the resultant signature */
	struct coordinate *c;   /** shortcut pointer inside sign->c[] */
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

	/* 2N groups + 3 additional (size, delay and jitter) + 1 ending */
	sign->c = mmatic_zalloc(spi->mm, sizeof(*sign->c) * (spi->options.N*2 + 3 + 1));

	/* 1) count byte occurances in each of 2N groups
	 * 2) compute approximate mean packet size
	 * 3) determine approximate mean delay and its variance */
	for (pktcnt = 0; pktcnt < spi->options.C && (pkt = tlist_shift(pkts)); pktcnt++) {
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

		/* add packet stats as 3 last coordinates */
		i = spi->options.N * 2;

		sign->c[i].index = i + 1;
		sign->c[i].value = avgsize;
		i++;

		sign->c[i].index = i + 1;
		sign->c[i].value = avgdelay;
		i++;

		sign->c[i].index = i + 1;
		sign->c[i].value = avgjitter;
		i++;

		sign->c[i].index = -1;
	}

	mmatic_freeptr(o);
	tlist_free(delays);
	return sign;
}

/** Add given signature to training samples and schedule le-learning */
static void _signature_add_train(struct spi *spi, struct signature *sign, spi_label_t label)
{
	struct kissp *kissp = spi->cdata;

	/* assign label to the sample and queue as a training sample */
	sign->label = label;
	tlist_push(kissp->traindata, sign);

	/* update model with a delay so many training samples have chance to be queued */
	spi_announce(spi, "kisspTraindataUpdated", SPI_TRAINING_DELAY, NULL, false);

	return;
}

/********** event handlers, workers, etc */
void _predict(struct spi *spi, struct signature *sign, struct spi_ep *ep)
{
	struct kissp *kissp = spi->cdata;

	switch (kissp->options.method) {
		case KISSP_LIBLINEAR:
			_linear_predict(spi, sign, ep);
			break;
		case KISSP_LIBSVM:
			dbg(0, "TODO :)\n");
			break;
	}
}

/** Receives "endpointPacketsReady */
static void _ep_ready(struct spi *spi, const char *evname, void *data)
{
	struct spi_ep *ep = data;
	struct signature *sign;

	while (tlist_count(ep->pkts) >= spi->options.C) {
		sign = _signature_compute_eat(spi, ep->pkts);

		/* if a labelled sample, learn from it */
		if (ep->source->label != 0) {
			_signature_add_train(spi, sign, ep->source->label);
		} else {
			_predict(spi, sign, ep);
			_signature_free(sign);
		}
	}

	ep->pending = false;
}

/** Receives "kisspTraindataUpdated */
void _train(struct spi *spi, const char *evname, void *data)
{
	struct kissp *kissp = spi->cdata;

	dbg(1, "training with %u samples in traindata\n", tlist_count(kissp->traindata));

	switch (kissp->options.method) {
		case KISSP_LIBLINEAR:
			_linear_train(spi);
			break;
		case KISSP_LIBSVM:
			_svm_train(spi);
			break;
	}
}

/**********/

void kissp_init(struct spi *spi)
{
	struct kissp *kissp;

	/* subscribe to endpoints accumulating 80+ packets */
	spi_subscribe(spi, "endpointPacketsReady", _ep_ready, false);

	/* subscribe to new learning samples */
	spi_subscribe(spi, "kisspTraindataUpdated", _train, true);

	kissp = mmatic_zalloc(spi->mm, sizeof *kissp);
	kissp->traindata = tlist_create(_signature_free, spi->mm);
	spi->cdata = kissp;

	/* TODO: let for choosing options */
	kissp->options.pktstats = true;
	kissp->options.method = KISSP_LIBLINEAR;
	_linear_init(spi);
}

void kissp_free(struct spi *spi)
{
	struct kissp *kissp = spi->cdata;

	tlist_free(kissp->traindata);
	mmatic_freeptr(kissp);
	spi->cdata = NULL;
}


