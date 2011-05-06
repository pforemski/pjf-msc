/*
 * spid: Statistical Packet Inspection
 * Copyright (C) 2011 Paweł Foremski <pawel@foremski.pl>
 * This software is licensed under GNU GPL version 3
 */

#include "datastructures.h"
#include "source.h"

void source_destroy(struct source *source)
{
	/* TODO: close files, etc. */

	mmatic_freeptr(source);
}
