#ifndef MY_DUMP_H
#define MY_DUMP_H

#include <arpa/inet.h>
#include <ctype.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void print_help(FILE *fd);
void int_handler(int sig);

#endif
