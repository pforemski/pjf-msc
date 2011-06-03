/*
 * spi: Statistical Packet Inspection
 * Paweł Foremski <pawel@foremski.pl> 2011
 * This software is licensed under GNU GPL version 3
 */

#ifndef _SETTINGS_H_
#define _SETTINGS_H_

/** Number of packets in classification window */
#define SPI_DEFAULT_C 80

/** Max number of packets from single TCP connection */
#define SPI_DEFAULT_P 5

/** Number of payload bytes to analyze */
#define SPI_DEFAULT_N 12

/** Garbage collector interval */
#define SPI_GC_INTERVAL 10

/** pcap snaplen */
#define SPI_PCAP_SNAPLEN 100

/** pcap read timeout [ms] */
#define SPI_PCAP_TIMEOUT 10

/** pcap max no of packets read once */
#define SPI_PCAP_MAX SPI_DEFAULT_C

/** pcap default filter */
#define SPI_PCAP_DEFAULT_FILTER "tcp or udp"

/** Timeout a flow if no packets for given no. of seconds
 * Affects mostly the SPI_DEFAULT_P limit of TCP packets per window */
#define SPI_FLOW_TIMEOUT 300

/** Endpoint timeout */
#define SPI_EP_TIMEOUT 300

/** Delay in ms between registering first training sample and actual training */
#define SPI_TRAINING_DELAY 3000

#endif
