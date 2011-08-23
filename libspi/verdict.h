/*
 * spi: Statistical Packet Inspection: verdict issuer
 * Copyright (C) 2011 Paweł Foremski <pawel@foremski.pl>
 * This software is licensed under GNU GPL version 3
 */

#ifndef _VERDICT_H_
#define _VERDICT_H_

#include "datastructures.h"

/** Per-endpoint EWMA verdict data */
struct ewma_verdict {
	/** histogram of verdicts over time:
	 * EWMA of classification probabilty for each label */
	spi_cprob_t cprob;
};

/** Global verdict data */
struct verdict {
	/** type of verdict decision */
	enum {
		SPI_VERDICT_SIMPLE,
		SPI_VERDICT_EWMA,
		SPI_VERDICT_BEST
	} type;

	/** type-dependent info */
	union {
		struct {
			uint16_t N;   /** EWMA length */
		} ewma;
	} as;
};

/** Initialize verdict issuer */
void verdict_init(struct spi *spi);

/** Deinitialize and free memory */
void verdict_free(struct spi *spi);

#endif
