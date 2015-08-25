//
// Created by redlionstl on 8/25/15.
//

#include "scan_error.h"

void exit_with_error(const char* errbuf) {
    printf("%s", errbuf);
    exit(255);
}