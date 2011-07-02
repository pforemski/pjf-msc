/*
 * spi: Statistical Packet Inspection: KISS PLUS classifier
 * Copyright (C) 2011 Paweł Foremski <pawel@foremski.pl>
 * This software is licensed under GNU GPL version 3
 */

#ifndef _KISSP_H_
#define _KISSP_H_

#include <linear.h> /* liblinear */
#include <libsvm/svm.h>

#include "datastructures.h"

/** Number of additional features in KISS+ vs KISS */
#define SPI_KISSP_FEATURES 4

/** Internal KISSP data */
struct kissp {
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
		} linear;
	} as;
};

/** Initialize KISS+ classifier */
void kissp_init(struct spi *spi);

/** Deinitialize classifier and free memory */
void kissp_free(struct spi *spi);

#endif
