//
// Created by pauldorn on 8/26/15.
//

#include <uv.h>
#include <assert.h>
#include <iostream>
#include "PCap.h"
#include "scan_error.h"
#include <dlfcn.h>
// Without immediate mode some architectures (e.g. Linux with TPACKET_V3)
// will buffer replies and potentially cause a *long* delay in packet
// reception

// pcap_set_immediate_mode is new as of libpcap 1.5.1, so we check for
// this new method dynamically ...
typedef void* (*set_immediate_fn)(pcap_t *p, int immediate);
void *_pcap_lib_handle = dlopen("libpcap.so", RTLD_LAZY);
set_immediate_fn set_immediate_mode =
        (set_immediate_fn)(dlsym(_pcap_lib_handle, "pcap_set_immediate_mode"));

using namespace std;

PCap::PCap(const char* interfaceName, const char* filter) {
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;

    if (pcap_lookupnet(interfaceName, &pcapInfo.net, &pcapInfo.mask, errbuf) == -1) {
        pcapInfo.net = 0;
        pcapInfo.mask = 0;
        fprintf(stderr, "Warning: %s - This may not actually work\n", errbuf);
    }
    // Initialize PCAP
    pcapInfo.handle = pcap_create((char *) interfaceName, errbuf);

    if (pcapInfo.handle == NULL)
        exit_with_error(errbuf);

    // 64KB is the max IPv4 packet size
    if (pcap_set_snaplen(pcapInfo.handle, 65535) != 0)
        exit_with_error("Unable to set snaplen");

    // Always use promiscuous mode
    if (pcap_set_promisc(pcapInfo.handle, 1) != 0)
        exit_with_error("Unable to set promiscuous mode");

    // Try to set buffer size. Sometimes the OS has a lower limit that it will
    // silently enforce.arpCap->addPacketProcesor()
    if (pcap_set_buffer_size(pcapInfo.handle, RING_BUFFER_SIZE) != 0)
        exit_with_error("Unable to set buffer size");

    // Set "timeout" on read, even though we are also setting nonblock below.
    // On Linux this is required.
    if (pcap_set_timeout(pcapInfo.handle, 1000) != 0)
        exit_with_error("Unable to set read timeout");

#if __linux__
    if (set_immediate_mode != NULL)
        set_immediate_mode(pcapInfo.handle, 1);
#endif

    if (pcap_activate(pcapInfo.handle) != 0)
        exit_with_error(pcap_geterr(pcapInfo.handle));

    if (pcap_setnonblock(pcapInfo.handle, 1, errbuf) == -1)
        exit_with_error(errbuf);

    if (pcap_compile(pcapInfo.handle, &fp, filter, 1, pcapInfo.net) == -1)
        exit_with_error(pcap_geterr(pcapInfo.handle));

    if (pcap_setfilter(pcapInfo.handle, &fp) == -1)
        exit_with_error(pcap_geterr(pcapInfo.handle));

    pcap_freecode(&fp);
};

void PCap::packetParser(const struct pcap_pkthdr *h, const u_char *bytes) {
    int offset = 0, i;
    char dstmac[12];
    char srcmac[12];
    char *buf_ptr;
    int type = 0;
    v_lan_info vlan;

    cout << "Parsing packet" << endl;

    // 32-bit Destination MAC Address
    buf_ptr = dstmac;
    for (i = 0; i < 6; ++i) {
        buf_ptr += sprintf(buf_ptr, "%02X", bytes[offset + i]);
    }
    buf_ptr = srcmac;
    offset += 6;
    // 32-bit Source MAC Address
    for (i = 0; i < 6; ++i) {
        buf_ptr += sprintf(buf_ptr, "%02X", bytes[offset + i]);
    }
    offset += 6;

    if (bytes[offset] == 0x81 && bytes[offset + 1] == 0x00) {
        // VLAN tag
        offset += 2;
        vlan.PRIORITY = bytes[offset] >> 0x1F;
        vlan.CFI = (bytes[offset] & 0x10) > 0;
        vlan.VID = ((bytes[offset] & 0x0F) << 8) + bytes[offset + 1];
        offset += 2;
    }

    // 16-bit Type/Length
    int typelen = (bytes[offset] << 8) | bytes[offset + 1];
    if (typelen <= 1500) {
        //length = typelen;
    }
    else if (typelen >= 1536)
        type = typelen;

    offset = offset + 2;

    // Determine type
    if (type == 2054) {
        // ARP
        int opcode = (bytes[offset+6] << 8) | bytes[offset + 7];
        if (opcode == 2) {
            cout << "Found ARP Reply" << endl;
        }
    }
}

void PCap::packetDispatch(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    PCap* pcap = (PCap*) user;
    pcap->packetParser(h, bytes);
}

void PCap::packetHandler(uv_poll_t* handle, int status, int event) {
    cout << "Got called" << endl;

    PCap* pcap = (PCap*) handle->data;

    int packet_count;

    do {
        packet_count = pcap_dispatch(pcap->pcapInfo.handle, 1, packetDispatch, (u_char*) handle->data);
    } while (packet_count > 0);
}

void PCap::Start(uv_loop_t* uv_loop) {
    // So in theory PCAP is listening on the interface in argv[1]
    int fd = pcap_get_selectable_fd(pcapInfo.handle);
    int r;

    // When we want to pass other state information into the callback,
    // the data field on poll_handle is our "friend". Make it this.
    pollHandle.data = (void*) this;

    r = uv_poll_init(uv_loop, &pollHandle, fd);
    assert(r == 0);
    r = uv_poll_start(&pollHandle, UV_READABLE, PCap::packetHandler);
    assert(r == 0);

};

PCap::~PCap() {
    Stop();
}
void PCap::Stop() {
    uv_poll_stop(&pollHandle);
};
