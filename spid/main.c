/*
 * spi: Statistical Packet Inspection
 * Copyright (C) 2011 Paweł Foremski <pawel@foremski.pl>
 * This software is licensed under GNU GPL version 3
 */

#include <libpjf/main.h>

#include "datastructures.h"
#include "spi.h"

int main(int argc, char *argv[])
{
	struct spi *spi;
	struct spi_options so;
	int i;

	debug = 10;

	so.N = SPI_DEFAULT_N;
	so.P = SPI_DEFAULT_P;
	so.C = SPI_DEFAULT_C;
	spi = spi_init(&so);

	if (spi_source_add(spi, SPI_SOURCE_SNIFF, 0, "wlan0 "))
		return 1;

	if (spi_source_add(spi, SPI_SOURCE_FILE, 1, "/home/pjf/makro/mgr/dumps/udp/dns2"))
		return 1;

//	if (spi_source_add(spi, SPI_SOURCE_FILE, 0, "/home/pjf/makro/mgr/dumps/udp/dns3"))
//		return 1;

	while (spi_loop(spi) == 0);

	spi_free(spi);
	return 1;
}

/*
 * vim: path=.,/usr/include,/usr/local/include,~/local/include
 */
