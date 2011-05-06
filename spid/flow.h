/*
 * spid: Statistical Packet Inspection
 * Copyright (C) 2011 Paweł Foremski <pawel@foremski.pl>
 * This software is licensed under GNU GPL version 3
 */

#ifndef _FLOW_H_
#define _FLOW_H_

#include "datastructures.h"

/** Destroy flow memory */
void flow_destroy(struct flow *flow);

#endif
