/*
 * spid: Statistical Packet Inspection
 * Copyright (C) 2011 Paweł Foremski <pawel@foremski.pl>
 * This software is licensed under GNU GPL version 3
 */

#ifndef _SOURCE_H_
#define _SOURCE_H_

#include "datastructures.h"

/** Close source and destroy memory */
void source_destroy(struct source *source);

#endif
