#include <iostream>
#include <assert.h>
#include <uv.h>

#include "PCap.h"

using namespace std;


struct pcap_data_t {
    pcap_t* cap_handle;
} ;



void timer_cb(uv_timer_t* timer_handle) {
    cout << "Timer was called" << endl;
    uv_stop(uv_default_loop());
}

void signalHandler(uv_signal_t* handle, int signum) {
    cout << "Terminating event loop" << endl;
    uv_stop(uv_default_loop());
}

int main(int argc, const char* argv[]) {

    // Exit the event loop gracefully on SIGINT
    uv_signal_t signalHandle;
    uv_signal_init(uv_default_loop(), &signalHandle);
    uv_signal_start(&signalHandle, signalHandler, SIGINT);

    // Capture arp packets
    const char* arp_filter = "arp or (vlan and arp)";
    PCap* arpCap = new PCap(argv[1], arp_filter);

    arpCap->addPacketProcesor()
//    uv_timer_init(loop_handle_ptr, &send_timer);
//
//    uv_timer_start(&send_timer, timer_cb, 60000, 0);

    cout << "Entering event loop" << endl;

    // Process messages indefinitely, yielding unused time back to kernel
    uv_run(uv_default_loop(), UV_RUN_DEFAULT);

    cout << "Exiting" << endl;
    // We got here, so we know we are done.
    delete arpCap;
    return 0;
}