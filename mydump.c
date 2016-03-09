#include "mydump.h"

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
    printf("Packet len: %d\n", header->len);
    printf("packet: %s\n", packet);

}

void int_handler(int sig) {
    if(handle != NULL)
        pcap_breakloop(handle);
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

