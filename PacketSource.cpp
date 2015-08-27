//
// Created by redlionstl on 8/27/15.
//

#include "PacketSource.h"


void PacketSource::addPacketListener(PacketReceiver* packetReceiver) {
    vector<PacketReceiver*>::iterator it = listeners.begin();
    listeners.insert(it, packetReceiver);
}


void PacketSource::sendPacket(pcap_pkthdr* h, const char* bytes, int offset) {
    vector<PacketReceiver*>::iterator it = listeners.begin();
    while(it < listeners.end()) {
        (*it)->receivePacket(h, bytes);
        it++;
    }
}