//
// Created by redlionstl on 8/25/15.
//

#include "arp.h"
#include <string.h>


void initArpTemplate(char* arpBuffer) {
    memcpy(arpBuffer, arpTemplate, sizeof(arpTemplate));
};

void fillArpTemplate(char* arpBuffer, const char* localMac, const char* targetIp) {
    memcpy(arpBuffer + SENDER_MAC_OFFSET, localMac, 6);
    memcpy(arpBuffer + TARGET_IP_OFFSET, targetIp, 4);
    memcpy(arpBuffer + SOURCE_MAC_ADDRESS, localMac, 6);
};