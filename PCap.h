//
// Created by pauldorn on 8/26/15.
//

#ifndef ARPSCANNER_PCAP_H
#define ARPSCANNER_PCAP_H


#include <pcap/pcap.h>
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

typedef struct {
    int PRIORITY;
    int CFI;
    int VID;
} v_lan_info ;

typedef struct {
    bpf_u_int32 mask;
    bpf_u_int32 net;
    pcap_t *handle;
} pcap_info;


class PCap {
    pcap_info pcapInfo;
    uv_poll_t pollHandle;
    void Stop();

    virtual void packetParser(const struct pcap_pkthdr *h, const u_char *bytes);
    static void packetHandler(uv_poll_t* handle, int status, int event);
    static void packetDispatch(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);

public :
    PCap(const char* interfaceName, const char* filter);
    ~PCap();
    void Start(uv_loop_t* uv_loop);



};


#endif //ARPSCANNER_PCAP_H
