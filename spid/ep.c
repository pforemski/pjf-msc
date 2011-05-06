/*
 * spid: Statistical Packet Inspection
 * Copyright (C) 2011 Paweł Foremski <pawel@foremski.pl>
 * This software is licensed under GNU GPL version 3
 */

#include "ep.h"
#include "datastructures.h"

void ep_destroy(struct ep *ep)
{
	mmatic_free(ep->mm);
}
