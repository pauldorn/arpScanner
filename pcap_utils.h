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


void initialize_pcap(const char* interfaceName, const char* filter, pcap_info* pcapInfo);
void stop_pcap(pcap_info* pcapInfo);

#endif //ARPSCANNER_PCAP_UTILS_H
