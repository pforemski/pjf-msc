/*
 * spid: Statistical Packet Inspection
 * Copyright (C) 2011 Paweł Foremski <pawel@foremski.pl>
 * This software is licensed under GNU GPL version 3
 */

#include "flow.h"
#include "datastructures.h"

void flow_destroy(struct flow *flow)
{
	mmatic_freeptr(flow);
}
