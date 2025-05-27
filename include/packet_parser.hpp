#ifndef PACKET_PARSER_HPP
#define PACKET_PARSER_HPP

#include <pcap.h>
#include <string>
#include <cstdint>

// ethernet header
struct EthernetHeader {
    uint8_t dest_mac[6];      // destination mac address
    uint8_t src_mac[6];       // src mac address
    uint16_t ethertype;       // type --> protocol
};

// ip header (simplified ipv4)
struct IPHeader {
    uint8_t version_ihl;      // version (4 bits) + internet header length (4 bits)
    uint8_t type_of_service;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_fragoff;   // flags (3 bits) + fragment offset (13 bits)
    uint8_t ttl;              // time to live
    uint8_t protocol;
    uint16_t checksum;        // header checksum
    uint32_t src_addr;
    uint32_t dest_addr;
};

// tcp header (simplified)
struct TCPHeader {
    uint16_t src_port;
    uint16_t dest_port;
    uint32_t seq_num;         // sequence number
    uint32_t ack_num;         // acknowledgment number
    uint8_t data_offset;      // data offset (4 bits) + reserved (4 bits)
    uint8_t flags;   
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;
};

// udp header
struct UDPHeader {
    uint16_t src_port;
    uint16_t dest_port;
    uint16_t length;
    uint16_t checksum;
};

class PacketParser {
public:
    PacketParser();
    ~PacketParser();
    
    // main parsing function
    void parsePacket(const uint8_t* packet, int packet_len);
    
    // protocol-specific parsing functions
    void parseEthernet(const uint8_t* packet, int packet_len);
    void parseIP(const uint8_t* packet, int packet_len);
    void parseTCP(const uint8_t* packet, int packet_len, uint32_t src_ip, uint32_t dest_ip);
    void parseUDP(const uint8_t* packet, int packet_len, uint32_t src_ip, uint32_t dest_ip);
    
    std::string macToString(const uint8_t* mac);
    std::string ipToString(uint32_t ip);
    std::string protocolToString(uint8_t protocol);
    void printPacketHex(const uint8_t* packet, int length, int bytes_per_line = 16);
    
    void printStatistics();
    void resetStatistics();
    
private:
    // counters
    uint64_t total_packets_;
    uint64_t tcp_packets_;
    uint64_t udp_packets_;
    uint64_t icmp_packets_;
    uint64_t other_packets_;
    
    uint16_t ntohs_custom(uint16_t value);
    uint32_t ntohl_custom(uint32_t value);
};

#endif