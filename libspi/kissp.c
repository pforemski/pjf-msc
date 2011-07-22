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

	if (spi->options.liblinear_params) {
		memcpy(&kissp->as.linear.params, spi->options.liblinear_params, sizeof kissp->as.linear.params);
	} else {
		/* defaults */
		kissp->as.linear.params.solver_type = L2R_L2LOSS_SVC_DUAL;
		kissp->as.linear.params.eps = 0.1;
		kissp->as.linear.params.C = 1;
		kissp->as.linear.params.nr_weight = 0;     /* NB: .weight_label and .weight not set */
	}

	set_print_string_function(_linear_print_func);
}

static void _linear_train(struct spi *spi)
{
	struct kissp *kissp = spi->cdata;
	struct problem p;
	struct spi_signature *s;
	int i;
	const char *err;

	/* describe the problem */
	p.l = tlist_count(spi->traindata);
	p.n = kissp->feature_num;
	p.x = mmatic_alloc(spi->mm, (sizeof (void *)) * p.l);
	p.y = mmatic_alloc(spi->mm, (sizeof (int)) * p.l);

	i = 0;
	tlist_iter_loop(spi->traindata, s) {
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

	spi_announce(spi, "classifierModelUpdated", 0, NULL, false);

	mmatic_freeptr(p.x);
	mmatic_freeptr(p.y);
}

static void _linear_predict(struct spi *spi, struct spi_signature *sign, struct spi_ep *ep)
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
static void _svm_print_func(const char *msg)
{
	while (*msg == '\n') msg++;
	dbg(9, "libsvm: %s", msg);
}

static void _svm_init(struct spi *spi)
{
	struct kissp *kissp = spi->cdata;

	if (spi->options.libsvm_params) {
		memcpy(&kissp->as.svm.params, spi->options.libsvm_params, sizeof kissp->as.svm.params);
	} else {
		/* defaults */
		kissp->as.svm.params.svm_type = C_SVC;
		kissp->as.svm.params.kernel_type = RBF;
		kissp->as.svm.params.degree = 3;

		kissp->as.svm.params.gamma = 1.0 / (double) kissp->feature_num;
		kissp->as.svm.params.coef0 = 0.0;

		kissp->as.svm.params.cache_size = 100.0;
		kissp->as.svm.params.eps = 0.1;
		kissp->as.svm.params.C = 1;
		kissp->as.svm.params.nr_weight = 0;     /* NB: .weight_label and .weight not set */

		kissp->as.svm.params.nu = 0.5;
		kissp->as.svm.params.p = 0.1;

		kissp->as.svm.params.shrinking = 1;
		kissp->as.svm.params.probability = 1; /* NB */
	}

	svm_set_print_string_function(_svm_print_func);
}

static void _svm_train(struct spi *spi)
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
	err = svm_check_parameter(&p, &kissp->as.svm.params);
	if (err) {
		dbg(1, "libsvm training failed: check_parameter(): %s\n", err);
		return;
	}

	/* destroy previous model */
	if (kissp->as.svm.model)
		svm_destroy_model(kissp->as.svm.model);
//		svm_free_and_destroy_model(&kissp->as.svm.model);

	/* run */
	kissp->as.svm.model = svm_train(&p, &kissp->as.svm.params);

	dbg(5, "updated libsvm model, nr_class=%d\n",
		svm_get_nr_class(kissp->as.svm.model));

	spi_announce(spi, "classifierModelUpdated", 0, NULL, false);

	mmatic_freeptr(p.x);
	mmatic_freeptr(p.y);
}

static void _svm_predict(struct spi *spi, struct spi_signature *sign, struct spi_ep *ep)
{
	struct kissp *kissp = spi->cdata;
	struct spi_classresult *cr;

	if (!kissp->as.svm.model) {
		dbg(1, "cant classify: no model\n");
		return;
	}

	cr = mmatic_zalloc(spi->mm, sizeof *cr);
	cr->ep = ep;

	switch (kissp->as.svm.params.svm_type) {
		case C_SVC:
		case NU_SVC:
			cr->result = svm_predict_probability(kissp->as.svm.model, (struct svm_node *) sign->c, cr->cprob);
			break;
		default:
			cr->result = svm_predict(kissp->as.svm.model, (struct svm_node *) sign->c);
			cr->cprob[cr->result] = 1.0;
			break;
	}

	spi_announce(spi, "endpointClassification", 0, cr, true);
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
		sign->c[i].value = ep->proto;
		i++;

		sign->c[i].index = -1;
	}

	mmatic_freeptr(o);
	tlist_free(delays);

	if (ep->source->label)
		sign->label = ep->source->label;

	return sign;
}

/** Make classification of given signature */
static void _predict(struct spi *spi, struct spi_signature *sign, struct spi_ep *ep)
{
	struct kissp *kissp = spi->cdata;

	switch (kissp->options.method) {
		case KISSP_LIBLINEAR:
			_linear_predict(spi, sign, ep);
			break;
		case KISSP_LIBSVM:
			_svm_predict(spi, sign, ep);
			break;
	}
}

/********** event handlers */

/** Receives "endpointPacketsReady */
static bool _ep_ready(struct spi *spi, const char *evname, void *data)
{
	struct spi_ep *ep = data;
	struct spi_signature *sign;

	while (tlist_count(ep->pkts) >= spi->options.C) {
		sign = _signature_compute_eat(spi, ep);
		ep->source->samples++;

		/* if a labelled sample, learn from it */
		if (sign->label) {
			spi_train(spi, sign);
			ep->source->learned++;
			spi->learned_pkt++;

			dbg(5, "learned proto %d from ep %s\n", sign->label, spi_epa2a(ep->epa));
		} else {
			_predict(spi, sign, ep);
			spi_signature_free(sign);
		}
	}

	ep->pending = false;
	return true;
}

/** Receives "traindataUpdated" */
static bool _train(struct spi *spi, const char *evname, void *data)
{
	struct kissp *kissp = spi->cdata;

	dbg(2, "training with %u samples in traindata\n", tlist_count(spi->traindata));

	switch (kissp->options.method) {
		case KISSP_LIBLINEAR:
			_linear_train(spi);
			break;
		case KISSP_LIBSVM:
			_svm_train(spi);
			break;
	}

	return true;
}

/**********/

void kissp_init(struct spi *spi)
{
	struct kissp *kissp;

	/* subscribe to endpoints accumulating 80+ packets */
	spi_subscribe(spi, "endpointPacketsReady", _ep_ready, false);

	/* subscribe to new learning samples */
	spi_subscribe(spi, "traindataUpdated", _train, true);

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

	if (spi->options.kiss_linear) {
		kissp->options.method = KISSP_LIBLINEAR;
		_linear_init(spi);
	} else {
		kissp->options.method = KISSP_LIBSVM;
		_svm_init(spi);
	}
}

void kissp_free(struct spi *spi)
{
	struct kissp *kissp = spi->cdata;

	mmatic_freeptr(kissp);
	spi->cdata = NULL;
}


