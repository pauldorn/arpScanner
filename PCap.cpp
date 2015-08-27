//
// Created by pauldorn on 8/26/15.
//

#include <uv.h>
#include <assert.h>
#include <iostream>
#include "PCap.h"
#include "pcap_utils.h"

using namespace std;

PCap::PCap(const char* interfaceName, const char* filter) {
    initialize_pcap(interfaceName, filter, &pcapInfo);
    // Start listening on
    Start();
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

void PCap::Start() {
    // So in theory PCAP is listening on the interface in argv[1]
    int fd = pcap_get_selectable_fd(pcapInfo.handle);
    int r;

    // When we want to pass other state information into the callback,
    // the data field on poll_handle is our "friend". Make it this.
    pollHandle.data = (void*) this;

    r = uv_poll_init(uv_default_loop(), &pollHandle, fd);
    assert(r == 0);
    r = uv_poll_start(&pollHandle, UV_READABLE, PCap::packetHandler);
    assert(r == 0);

};

PCap::~PCap() {
    Stop();
}
void PCap::Stop() {
    stop_pcap(&pcapInfo);
};
