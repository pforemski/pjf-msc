/*
 * spi: Statistical Packet Inspection: verdict issuer
 * Copyright (C) 2011 Paweł Foremski <pawel@foremski.pl>
 * This software is licensed under GNU GPL version 3
 */

#ifndef _VERDICT_H_
#define _VERDICT_H_

#include "datastructures.h"

/** Per-endpoint verdict data */
struct spi_ep_verdict {
	/** type-dependent info */
	union {
		struct verdict_ep_emwa_t {
			spi_cprob_t cprob; /** histogram of verdicts over time: EWMA of class. probabilty for each label */
		} ewma;
	} as;
};

/** Global verdict data */
struct verdict {
	/** type of verdict decision */
	enum verdict_t {
		SPI_VERDICT_SIMPLE,
		SPI_VERDICT_EWMA
	} type;

	/** type-dependent info */
	union {
		struct verdict_ewma_t {
			uint16_t N;   /** EWMA length */
		} ewma;
	} as;
};

/** Initialize verdict issuer */
void verdict_init(struct spi *spi);

/** Deinitialize and free memory */
void verdict_free(struct spi *spi);

/** Handler for new endpoint classification results */
void verdict_new_classification(struct spi *spi, const char *evname, void *arg);

#endif
