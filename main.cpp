#include <iostream>
#include <assert.h>
#include <uv.h>
#include "pcap_utils.h"


using namespace std;

typedef struct {
    int PRIORITY;
    int CFI;
    int VID;
} v_lan_info ;

void packet_parser(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
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

struct pcap_data_t {
    pcap_t* cap_handle;
} ;

void cb_packets(uv_poll_t* async, int status, int event) {
    cout << "Got called" << endl;
    pcap_data_t *pcap_data = (pcap_data_t*)async->data;
    int packet_count;

    do {
        packet_count = pcap_dispatch(pcap_data->cap_handle, 1, packet_parser, (u_char*) pcap_data);
    } while (packet_count > 0);
}

void timer_cb(uv_timer_t* timer_handle) {
    cout << "Timer was called" << endl;
    uv_stop(uv_default_loop());
}


int main(int argc, const char* argv[]) {
    int r;

    uv_loop_t* loop_handle_ptr = uv_default_loop();
    uv_timer_t send_timer;
    char buffer[65535];
    const char* arp_filter = "arp or (vlan and arp)";

    pcap_info pcapInfo;

    pcap_init(argv[1], arp_filter, &pcapInfo);

    // So in theory PCAP is listening on the interface in argv[1]
    int fd = pcap_get_selectable_fd(pcapInfo.handle);
    pcap_data_t pcap_data;
    pcap_data.cap_handle = pcapInfo.handle;

    uv_poll_t poll_handle;

    // When we want to pass other state information into the callback,
    // the data field on poll_handle is our friend.
    poll_handle.data = (void*) &pcap_data;

    r = uv_poll_init(uv_default_loop(), &poll_handle, fd);
    assert(r == 0);
    r = uv_poll_start(&poll_handle, UV_READABLE, cb_packets);
    assert(r == 0);

    uv_timer_init(loop_handle_ptr, &send_timer);
    // send packets every ten msecs (warning, this is 10 seconds between STARTS)
    uv_timer_start(&send_timer, timer_cb, 60000, 0);

    cout << "Entering event loop" << endl;

    // Process messages indefinitely, yielding unused time back to kernel
    uv_run(uv_default_loop(), UV_RUN_DEFAULT);

    // We got here, so we know we are done.
    pcap_dispose(&pcapInfo);
    return 0;
}