/*
 * spi: Statistical Packet Inspection: KISS PLUS classifier
 * Copyright (C) 2011 Paweł Foremski <pawel@foremski.pl>
 * This software is licensed under GNU GPL version 3
 */

#ifndef _KISSP_H_
#define _KISSP_H_

#include <libsvm/svm.h>

#include "datastructures.h"

/** Number of additional features in KISS+ vs KISS */
#define SPI_KISSP_FEATURES 4

/** Internal KISSP data */
struct kissp {
	int feature_num;                 /** number of signature coordinates */

	/** KISSP options */
	struct {
		bool pktstats;               /** use packet stats in signatures */
	} options;

	/** internal SVM data */
	struct {
		struct svm_model *model;      /** libsvm model */
		struct svm_parameter params;  /** libsvm parameters */
		int *labels;                  /** translation of svm->libspi labels */
		int nr_class;                 /** number of classes */
	} svm;
};

/** Initialize KISS+ classifier */
void kissp_init(struct spi *spi);

/** Deinitialize classifier and free memory */
void kissp_free(struct spi *spi);

#endif
