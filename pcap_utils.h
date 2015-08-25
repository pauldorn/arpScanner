//
// Created by redlionstl on 8/25/15.
//

#ifndef ARPSCANNER_PCAP_UTILS_H
#define ARPSCANNER_PCAP_UTILS_H

#include <pcap/pcap.h>

typedef struct {
    bpf_u_int32 mask;
    bpf_u_int32 net;
    pcap_t *handle;
} pcap_info;


void pcap_init(const char* interfaceNamem, const char* filter, pcap_info* pcapInfo);
void pcap_dispose(pcap_info* pcapInfo);

#endif //ARPSCANNER_PCAP_UTILS_H
