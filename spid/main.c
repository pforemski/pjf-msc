/*
 * spid: Statistical Packet Inspection
 * Copyright (C) 2011 Paweł Foremski <pawel@foremski.pl>
 * This software is licensed under GNU GPL version 3
 */

#include <libpjf/main.h>

#include "datastructures.h"
#include "spid.h"

int main(int argc, char *argv[])
{
	struct spid *spid;

	debug = 10;
	spid = spid_init(argc, (const char **) argv, NULL);

	while (true) {
		spid_loop(spid);
	}

	return 1;
}

/*
 * vim: path=.,/usr/include,/usr/local/include,~/local/include
 */
