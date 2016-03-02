#include "mydump.h"

void print_help(FILE *fd);

int main(int argc, char * argv[]) {

    char *ival = NULL;
    char *rval = NULL;
    char *sval = NULL;
    int index;
    int c;

    opterr = 0;
    while ((c = getopt (argc, argv, "i:r:s:")) != -1) {
        switch (c) {
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
        printf ("Non-option argument %s\n", argv[index]);
    }

        return 0;
}

void print_help(FILE *fd) {
    fprintf(fd, "mydump [-i interface] [-r file] [-s string] expression\n\n");
    fprintf(fd, "-i  Listen on network device <interface> (e.g., eth0). If not specified, mydump\n");
    fprintf(fd, "    should select a default interface to listen on.\n\n");
    fprintf(fd, "-r  Read packets from <file> (tcpdump format).\n\n");
    fprintf(fd, "-s  Keep only packets that contain <string> in their payload. You are not");
    fprintf(fd, "    required to implement wildcard or regular expression matching. A simple");
    fprintf(fd, "    string matching operation should suffice.");
}
