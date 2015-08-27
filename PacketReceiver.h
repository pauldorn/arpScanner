//
// Created by redlionstl on 8/27/15.
//

#ifndef ARPSCANNER_PACKETRECEIVER_H
#define ARPSCANNER_PACKETRECEIVER_H


#include <pcap/pcap.h>

class PacketReceiver {

public:
    virtual void receivePacket(pcap_pkthdr* h, const char* bytes) = 0;
};


#endif //ARPSCANNER_PACKETRECEIVER_H
