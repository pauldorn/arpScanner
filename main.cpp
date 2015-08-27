#include <iostream>
#include <assert.h>
#include <uv.h>
#include <pcap/pcap.h>
#include <dlfcn.h>
#include "arp.h"

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

struct v_lan_info {
    int PRIORITY;
    int CFI;
    int VID;
};

void packet_parser(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    int offset = 0, i;
    char dstmac[12];
    char srcmac[12];
    char ipResponder[16];
    char outb[12];
    char *buf_ptr;
    int type;
    v_lan_info vlan;
    int length;

//    cout << "Parsing packet" << endl;

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
    if (typelen <= 1500)
        length = typelen;
    else if (typelen >= 1536)
        type = typelen;

    offset = offset + 2;

    // Determine type
    if (type == 2054) {
        // ARP
        buf_ptr = ipResponder;
        for (i = 0; i < 4; ++i) {
            buf_ptr += sprintf(buf_ptr, "%d.", bytes[offset + 14 + i]);
        }
//        macSender = mac.toString(captureBuffer.slice(ret.offset + 8, ret.offset + 8 + 6)),
//                ipSender = JSON.parse(JSON.stringify(captureBuffer.slice(ret.offset + 14, ret.offset + 14 + 4))).join('.');

        int opcode = (bytes[offset+6] << 8) | bytes[offset + 7];
        if (opcode == 2) {
            cout << "Found ARP Reply: " << srcmac << ":::" <<  ipResponder << endl;
        }
    }

}



u_char ipRangeStart[] = { 192, 168, 211, 1 };
uint32_t ipRangeLength = 254;

char arp_packet[42];
pcap_t* pcap_handle;

void timer_cb(uv_timer_t* timer_handle) {
//    cout << "Timer was called" << endl;
    uv_stop(uv_default_loop());
}

void range_iteration_cb(uv_timer_t* rangeTimer) {
    uint32_t i;
    u_char localMac[6] = { 0x00, 0x14, 0xd1, 0x26, 0x75, 0x84 };

    if((uint64_t)(rangeTimer->data) == 0 ) {
        initArpTemplate(arp_packet);
    }

    for(i=0; i < 10 && (uint64_t)(rangeTimer->data) <= ipRangeLength; i++) {
        fillArpTemplate(arp_packet, (char*)localMac, (char*)ipRangeStart);
        pcap_sendpacket(pcap_handle, (u_char*)arp_packet, sizeof(arp_packet));
        rangeTimer->data = (void*)(((uint64_t)rangeTimer->data) + 1);
        ipRangeStart[3] ++;
        if(ipRangeStart[3] == 0) {
            ipRangeStart[2] ++;
            if(ipRangeStart[2] == 0) {
                ipRangeStart[1] ++;
                if(ipRangeStart[1] == 0) {
                    ipRangeStart[0] ++ ;
                }
            }
        }
    }

    if ((uint64_t)(rangeTimer->data) > ipRangeLength) {
        uv_timer_stop(rangeTimer);
        uv_timer_start(rangeTimer, timer_cb, 1000, 0);
    }

}


struct pcap_data_t {
    pcap_t* cap_handle;
} ;

void cb_packets(uv_poll_t* async, int status, int event) {
//    cout << "Got called" << endl;
    pcap_data_t *pcap_data = (pcap_data_t*)async->data;
    int packet_count;

    do {
        packet_count = pcap_dispatch(pcap_data->cap_handle, 1, packet_parser, (u_char*) pcap_data);
    } while (packet_count > 0);
}


void exit_with_error(const char* errbuf) {
    printf("%s", errbuf);
    exit(255);
}

int main(int argc, const char* argv[]) {
    int r;

    uv_async_t async_handle;
    uv_loop_t* loop_handle_ptr = uv_default_loop();
    uv_timer_t send_timer;
    struct bpf_program fp;
    char buffer[65535];
    int bufSize =  2*1024*1024;
    const char* filter = "arp or (vlan and arp)";
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 mask;
    bpf_u_int32 net;

    if (pcap_lookupnet(argv[1], &net, &mask, errbuf) == -1) {
        net = 0;
        mask = 0;
        fprintf(stderr, "Warning: %s - This may not actually work\n", errbuf);
    }
    // Initialize PCAP
    pcap_handle = pcap_create((char*)argv[1], errbuf);

    if (pcap_handle == NULL)
        exit_with_error(errbuf);

    // 64KB is the max IPv4 packet size
    if (pcap_set_snaplen(pcap_handle, 65535) != 0)
        exit_with_error("Unable to set snaplen");

    // Always use promiscuous mode
    if (pcap_set_promisc(pcap_handle, 1) != 0)
        exit_with_error("Unable to set promiscuous mode");

    // Try to set buffer size. Sometimes the OS has a lower limit that it will
    // silently enforce.
    if (pcap_set_buffer_size(pcap_handle, bufSize) != 0)
        exit_with_error("Unable to set buffer size");

    // Set "timeout" on read, even though we are also setting nonblock below.
    // On Linux this is required.
    if (pcap_set_timeout(pcap_handle, 1000) != 0)
        exit_with_error("Unable to set read timeout");

#if __linux__
    if (set_immediate_mode != NULL)
        set_immediate_mode(pcap_handle, 1);
#endif

    if (pcap_activate(pcap_handle) != 0)
        exit_with_error(pcap_geterr(pcap_handle));

    if (pcap_setnonblock(pcap_handle, 1, errbuf) == -1)
        exit_with_error(errbuf);

    if (pcap_compile(pcap_handle, &fp, filter, 1, net) == -1)
        exit_with_error(pcap_geterr(pcap_handle));

    if (pcap_setfilter(pcap_handle, &fp) == -1)
        exit_with_error(pcap_geterr(pcap_handle));

    pcap_freecode(&fp);

    // So in theory PCAP is listening on the interface in argv[1]
    int fd = pcap_get_selectable_fd(pcap_handle);
    pcap_data_t pcap_data;
    pcap_data.cap_handle = pcap_handle;

    uv_poll_t poll_handle;
    r = uv_poll_init(uv_default_loop(), &poll_handle, fd);
    assert(r == 0);
    r = uv_poll_start(&poll_handle, UV_READABLE, cb_packets);
    assert(r == 0);
    // When we want to pass other state information into the callback,
    // the data field on poll_handle is our friend.
    poll_handle.data = (void*) &pcap_data;

    uv_timer_init(loop_handle_ptr, &send_timer);
    // send packets every ten msecs (warning, this is 10 seconds between STARTS)
    send_timer.data = (void*)0;

    uv_timer_start(&send_timer, range_iteration_cb, 10, 10);

//    cout << "Entering event loop" << endl;
    uv_run(uv_default_loop(), UV_RUN_DEFAULT);
    return 0;
}