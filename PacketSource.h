//
// Created by redlionstl on 8/27/15.
//

#ifndef ARPSCANNER_PACKETSOURCE_H
#define ARPSCANNER_PACKETSOURCE_H


#include <pcap/pcap.h>
#include <vector>
#include "PacketReceiver.h"

using namespace std;

class PacketSource {

    vector<PacketReceiver*> listeners;

    void addPacketListener(PacketReceiver* packetReceiver);

protected:
    void sendPacket(pcap_pkthdr* h, const char* bytes, int offset);
};


#endif //ARPSCANNER_PACKETSOURCE_H
