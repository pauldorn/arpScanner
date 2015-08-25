//
// Created by redlionstl on 8/25/15.
//

#ifndef ARPSCANNER_ARP_H
#define ARPSCANNER_ARP_H


#include <sys/types.h>

#define SENDER_MAC_OFFSET 22
#define TARGET_IP_OFFSET 38
#define SOURCE_MAC_ADDRESS 6
#define ARP_PACKET_SIZE 42

const u_char arpTemplate[] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // 0    = Destination MAC
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 6    = Source MAC
        0x08, 0x06, // 12   = EtherType = ARP
        // ARP
        0x00, 0x01, // 14/0   = Hardware Type = Ethernet (or wifi)
        0x08, 0x00, // 16/2   = Protocol type = ipv4 (request ipv4 route info)
        0x06, 0x04, // 18/4   = Hardware Addr Len (Ether/MAC = 6), Protocol Addr Len (ipv4 = 4)
        0x00, 0x01, // 20/6   = Operation (ARP, who-has)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 22/8   = Sender Hardware Addr (MAC)
        0x00, 0x00, 0x00, 0x00, // 28/14  = Sender Protocol address (ipv4)
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 32/18  = Target Hardware Address (Blank/nulls for who-has)
        0x00, 0x00, 0x00, 0x00 // 38/24  = Target Protocol address (ipv4)
};

void initArpTemplate(char* arpBuffer);

void fillArpTemplate(char* arpBuffer, const char* localMac, const char* targetIp);



#endif //ARPSCANNER_ARP_H
