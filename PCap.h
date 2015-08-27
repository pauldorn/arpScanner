//
// Created by pauldorn on 8/26/15.
//

#ifndef ARPSCANNER_PCAP_H
#define ARPSCANNER_PCAP_H


#include <pcap/pcap.h>
#include "pcap_utils.h"


typedef struct {
    int PRIORITY;
    int CFI;
    int VID;
} v_lan_info ;


class PCap {
    pcap_info pcapInfo;
    uv_poll_t pollHandle;
    void Start();
    void Stop();

    virtual void packetParser(const struct pcap_pkthdr *h, const u_char *bytes);
    static void packetHandler(uv_poll_t* handle, int status, int event);
    static void packetDispatch(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);

public :
    PCap(const char* interfaceName, const char* filter);
    ~PCap();



};


#endif //ARPSCANNER_PCAP_H
