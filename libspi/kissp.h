/*
 * spi: Statistical Packet Inspection: KISS PLUS classifier
 * Copyright (C) 2011 Paweł Foremski <pawel@foremski.pl>
 * This software is licensed under GNU GPL version 3
 */

#ifndef _KISSP_H_
#define _KISSP_H_

#include <linear.h> /* liblinear */
#include <svm.h>

#include "datastructures.h"

/** Number of additional features in KISS+ vs KISS */
#define SPI_KISSP_FEATURES 4

/** Factor of random samples */
#define SPI_KISSP_RANDOM_FACT 0.5

/** Internal KISSP data */
struct kissp {
	int feature_num;         /** number of signature coordinates */
	tlist *randoms;          /** random signatures for "unknown" protocol */

	/** KISSP options */
	struct {
		bool pktstats;       /** use packet stats in signatures */
		enum {
			KISSP_LIBLINEAR,
			KISSP_LIBSVM
		} method;            /** classification method */
	} options;

	/** per-method internal data */
	union {
		struct {
			struct model *model;      /** liblinear model */
			struct parameter params;  /** liblinear parameters */
			int *labels;                  /** translation of svm->libspi labels */
			int nr_class;                 /** number of classes */
		} linear;

		struct {
			struct svm_model *model;      /** libsvm model */
			struct svm_parameter params;  /** libsvm parameters */
			int *labels;                  /** translation of svm->libspi labels */
			int nr_class;                 /** number of classes */
		} svm;
	} as;
};

/** Initialize KISS+ classifier */
void kissp_init(struct spi *spi);

/** Deinitialize classifier and free memory */
void kissp_free(struct spi *spi);

#endif
