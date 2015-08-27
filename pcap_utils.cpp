//
// Created by redlionstl on 8/25/15.
//

#include "pcap_utils.h"
#include "scan_error.h"
#include <dlfcn.h>

#define RING_BUFFER_SIZE 2*1024*1024

// Without immediate mode some architectures (e.g. Linux with TPACKET_V3)
// will buffer replies and potentially cause a *long* delay in packet
// reception

// pcap_set_immediate_mode is new as of libpcap 1.5.1, so we check for
// this new method dynamically ...
typedef void* (*set_immediate_fn)(pcap_t *p, int immediate);
void *_pcap_lib_handle = dlopen("libpcap.so", RTLD_LAZY);
set_immediate_fn set_immediate_mode =
        (set_immediate_fn)(dlsym(_pcap_lib_handle, "pcap_set_immediate_mode"));

void initialize_pcap(const char* interfaceName, const char* filter, pcap_info* pcapInfo) {
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;

    if (pcap_lookupnet(interfaceName, &pcapInfo->net, &pcapInfo->mask, errbuf) == -1) {
        pcapInfo->net = 0;
        pcapInfo->mask = 0;
        fprintf(stderr, "Warning: %s - This may not actually work\n", errbuf);
    }
    // Initialize PCAP
    pcapInfo->handle = pcap_create((char *) interfaceName, errbuf);

    if (pcapInfo->handle == NULL)
        exit_with_error(errbuf);

    // 64KB is the max IPv4 packet size
    if (pcap_set_snaplen(pcapInfo->handle, 65535) != 0)
        exit_with_error("Unable to set snaplen");

    // Always use promiscuous mode
    if (pcap_set_promisc(pcapInfo->handle, 1) != 0)
        exit_with_error("Unable to set promiscuous mode");

    // Try to set buffer size. Sometimes the OS has a lower limit that it will
    // silently enforce.
    if (pcap_set_buffer_size(pcapInfo->handle, RING_BUFFER_SIZE) != 0)
        exit_with_error("Unable to set buffer size");

    // Set "timeout" on read, even though we are also setting nonblock below.
    // On Linux this is required.
    if (pcap_set_timeout(pcapInfo->handle, 1000) != 0)
        exit_with_error("Unable to set read timeout");

#if __linux__
    if (set_immediate_mode != NULL)
        set_immediate_mode(pcapInfo->handle, 1);
#endif

    if (pcap_activate(pcapInfo->handle) != 0)
        exit_with_error(pcap_geterr(pcapInfo->handle));

    if (pcap_setnonblock(pcapInfo->handle, 1, errbuf) == -1)
        exit_with_error(errbuf);

    if (pcap_compile(pcapInfo->handle, &fp, filter, 1, pcapInfo->net) == -1)
        exit_with_error(pcap_geterr(pcapInfo->handle));

    if (pcap_setfilter(pcapInfo->handle, &fp) == -1)
        exit_with_error(pcap_geterr(pcapInfo->handle));

    pcap_freecode(&fp);
};

void stop_pcap(pcap_info* pcapInfo) {
    pcap_close(pcapInfo->handle);
}