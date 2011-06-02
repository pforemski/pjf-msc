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
	tlist *traindata;        /** list of struct signature*: signatures with labels */

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
void kissp_init(struct spid *spid);

/** Deinitialize classifier and free memory */
void kissp_free(struct spid *spid);

#endif
