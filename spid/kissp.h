/*
 * spid: Statistical Packet Inspection: KISS PLUS classifier
 * Copyright (C) 2011 Paweł Foremski <pawel@foremski.pl>
 * This software is licensed under GNU GPL version 3
 */

#ifndef _KISSP_H_
#define _KISSP_H_

#include <linear.h> /* liblinear */
#include <libsvm/svm.h>

#include "datastructures.h"

/** Feature vector coordinate */
struct coordinate {
	int index;
	double value;
};

/** Represents feature vector - packet window signature */
struct signature {
	label_t label;
	struct coordinate *c;
};

/** Internal KISSP data */
struct kissp {
	tlist *traindata;        /** signatures with labels */
};

/** Initialize KISS+ classifier */
void kissp_init(struct spid *spid);

/** Deinitialize classifier and free memory */
void kissp_free(struct spid *spid);

/** Receives events of endpoint being ready for classification
 * @param code      SPI_EVENT_ENDPOINT_HAS_C_PKTS
 * @param data      struct ep pointer
 */
void kissp_ep_ready(struct spid *spid, spid_event_t code, void *data);

#endif
