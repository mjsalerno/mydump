#include "mydump.h"
#include <netinet/if_ether.h>

pcap_t *handle = NULL;

int main(int argc, char * argv[]) {

    char *ival = NULL;
    char *rval = NULL;
    char *sval = NULL;
    char *bpf = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    int index;
    int c;
    int rtn;
    bpf_u_int32 mask;
    bpf_u_int32 net;
    struct bpf_program fp;

    opterr = 0;
    while ((c = getopt (argc, argv, "i:r:s:")) != -1) {
        switch (c) {
            case 'h':
                print_help(stdout);
                exit(EXIT_SUCCESS);
                break;
            case 'i':
                ival = optarg;
                break;
            case 'r':
                rval = optarg;
                break;
            case 's':
                sval = optarg;
                break;
            case '?':
                if (optopt == 'c')
                    fprintf (stderr, "Option -%c requires an argument.\n", optopt);
                else if (isprint (optopt))
                    fprintf (stderr, "Unknown option `-%c'.\n", optopt);
                else
                    fprintf (stderr,
                            "Unknown option character `\\x%x'.\n",
                            optopt);
                print_help(stderr);

                return 1;
            default:
                abort ();
        }
    }

    printf ("i = %s, r = %s, s = %s\n", ival, rval, sval);
    for (index = optind; index < argc; index++) {
        bpf = argv[index];
        if(index > optind) {
            fprintf(stderr, "Please put BPF in quotes\n");
            exit(EXIT_FAILURE);
        }
        //printf ("Non-option argument %s\n", argv[index]);
    }

    if(ival == NULL) {
        ival = pcap_lookupdev(errbuf);
        if(ival == NULL) {
            fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
            return(2);
        } else {
            printf("sniffing on: %s\n", ival);
        }

    }

    if (pcap_lookupnet(ival, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", ival, errbuf);
        net = 0;
        mask = 0;
    }

    handle = pcap_open_live(ival, BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return(2);
    }

    if(bpf != NULL) {
        if (pcap_compile(handle, &fp, bpf, 0, net) == -1) {
            fprintf(stderr, "Couldn't parse filter %s: %s\n", bpf, pcap_geterr(handle));
            return(2);
        }

        if (pcap_setfilter(handle, &fp) == -1) {
            fprintf(stderr, "Couldn't install filter %s: %s\n", bpf, pcap_geterr(handle));
            return(2);
        }
    }

    signal(SIGINT, int_handler);
    rtn = pcap_loop(handle, -1, got_packet, NULL);
    if(rtn == -1) {
        fprintf(stderr, "%s\n", pcap_geterr(handle));
        return EXIT_FAILURE;
    }

    pcap_close(handle);
    return EXIT_SUCCESS;
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ether_header *eth_hdr;
    struct iphdr *ip_hdr;
    struct tcphdr *tcp_hdr;
    struct udphdr *udp_hdr;

    eth_hdr = (struct ether_header *) packet;
    uint32_t eth_type = ntohs(eth_hdr->ether_type);

    if(eth_type != ETHERTYPE_IP) {
        return;
    }
    
    print_time(header->ts);

    printf("%02X:%02X:%02X:%02X:%02X:%02X",
        (unsigned char) eth_hdr->ether_shost[0],
        (unsigned char) eth_hdr->ether_shost[1],
        (unsigned char) eth_hdr->ether_shost[2],
        (unsigned char) eth_hdr->ether_shost[3],
        (unsigned char) eth_hdr->ether_shost[4],
        (unsigned char) eth_hdr->ether_shost[5]);
    printf(" -> %02X:%02X:%02X:%02X:%02X:%02X type 0x%04X len %d\n",
        (unsigned char) eth_hdr->ether_dhost[0],
        (unsigned char) eth_hdr->ether_dhost[1],
        (unsigned char) eth_hdr->ether_dhost[2],
        (unsigned char) eth_hdr->ether_dhost[3],
        (unsigned char) eth_hdr->ether_dhost[4],
        (unsigned char) eth_hdr->ether_dhost[5],
        eth_type,
        header->len);

    /* Print IP stuff */
    char *ip_src = malloc(sizeof(char) * BUFF_SIZE);
    char *ip_dst = malloc(sizeof(char) * BUFF_SIZE);
    char *type_name = malloc(sizeof(char) * BUFF_SIZE);
    char *tmp_src = NULL;
    char *tmp_dst = NULL;
    ip_hdr = (struct iphdr*)(eth_hdr + 1);
    u_char *data = NULL;

    memset(ip_src, 0, BUFF_SIZE);
    memset(ip_dst, 0, BUFF_SIZE);
    memset(type_name, 0, BUFF_SIZE);

    tmp_src = inet_ntoa(*(struct in_addr*)&ip_hdr->saddr);
    strncpy(ip_src, tmp_src, 15);
    tmp_src = ip_src + strlen(ip_src);

    tmp_dst = inet_ntoa(*(struct in_addr*)&ip_hdr->daddr);
    strncpy(ip_dst, tmp_dst, 15);
    tmp_dst = ip_dst + strlen(ip_dst);

   /*TODO: read file and time and data*/ 

    switch(ip_hdr->protocol) {
        case IPPROTO_TCP:
            tcp_hdr = (struct tcphdr*) (ip_hdr + 1);
            sprintf(tmp_src, ":%hu", ntohs(tcp_hdr->source));
            sprintf(tmp_dst, ":%hu", ntohs(tcp_hdr->dest));
            sprintf(type_name, "%s", "TCP");
            data = (u_char *)((unsigned char *)tcp_hdr + (tcp_hdr->doff * 4));
            break;

        case IPPROTO_UDP:
            udp_hdr = (struct udphdr*) (ip_hdr + 1);
            sprintf(tmp_src, ":%hu", ntohs(udp_hdr->source));
            sprintf(tmp_dst, ":%hu", ntohs(udp_hdr->dest));
            sprintf(type_name, "%s", "UDP");
            data = (u_char *) (udp_hdr + 1);
            break;

        case IPPROTO_ICMP:
            sprintf(type_name, "%s", "ICMP");
            data = (u_char *) (ip_hdr + 1);
            break;

        default:
            sprintf(type_name, "%s", "OTHER");
            data = (u_char *) (ip_hdr + 1);
            break;
    }

    printf("%s -> %s %s\n", ip_src, ip_dst, type_name);

    while(1) {
        if(data >= (packet + header->caplen)) break;

        memset(ip_src, 0, BUFF_SIZE);
        memset(ip_dst, 0, BUFF_SIZE);
        tmp_src = ip_src;
        tmp_dst = ip_dst;
        int i = 0;
        int j = 0;

        for(i = 0, j = 0; i < 48 && data < (packet + header->caplen); i = i + 3, j++, data++) {
            sprintf(ip_src + i, " %02X", (*data));
            if(isprint(*data)) {
                sprintf(ip_dst + j, "%c", *data);
            } else {
                sprintf(ip_dst + j, ".");
            }
        }

        printf("%s  %s\n", ip_src + 1, ip_dst);

    }
    printf("\n\n");


    free(ip_dst);
    free(ip_src);
    free(type_name);

}

void int_handler(int sig) {
    if(handle != NULL)
        pcap_breakloop(handle);
}

void print_time (struct timeval tv) {
    struct tm* ptm;
    char time_string[40];
    long milliseconds;

    /* Obtain the time of day, and convert it to a tm struct. */
    gettimeofday (&tv, NULL);
    ptm = localtime (&tv.tv_sec);
    /* Format the date and time, down to a single second. */
    strftime (time_string, sizeof (time_string), "%Y-%m-%d %H:%M:%S", ptm);
    /* Compute milliseconds from microseconds. */
    milliseconds = tv.tv_usec / 1000;
    /* Print the formatted time, in seconds, followed by a decimal point
     *    and the milliseconds. */
    printf ("%s.%03ld ", time_string, milliseconds);
}

void print_help(FILE *fd) {
    fprintf(fd, "mydump [-i interface] [-r file] [-s string] expression\n\n");
    fprintf(fd, "-i  Listen on network device <interface> (e.g., eth0). If not specified, mydump\n");
    fprintf(fd, "    should select a default interface to listen on.\n\n");
    fprintf(fd, "-r  Read packets from <file> (tcpdump format).\n\n");
    fprintf(fd, "-s  Keep only packets that contain <string> in their payload. You are not\n");
    fprintf(fd, "    required to implement wildcard or regular expression matching. A simple\n");
    fprintf(fd, "    string matching operation should suffice.\n\n");
    fprintf(fd, "<expression> is a BPF filter that specifies which packets will be dumped. If no\n");
    fprintf(fd, "filter is given, all packets seen on the interface (or contained in the trace)\n");
    fprintf(fd, "will be dumped. Otherwise, only packets matching <expression> will be dumped.\n\n");
}

