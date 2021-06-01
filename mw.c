#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "libwormhole.h"

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: mw send|recv <file>\n");
        exit(1);
    }

    if (strcmp(argv[1], "send") == 0) {
        GoString filename;

        filename.p = argv[2];
        filename.n = strlen(argv[2]);

        printf("sending..\n");
        sendFile(filename);
    }

    if (strcmp(argv[1], "recv") == 0) {
        printf("receiving..\n");
        recvAction();
    }
}
