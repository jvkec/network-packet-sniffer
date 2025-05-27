#include "packet_parser.hpp"
#include "utils.hpp"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <arpa/inet.h>
#include <netinet/in.h>

PacketParser::PacketParser() 
    : total_packets_(0), tcp_packets_(0), udp_packets_(0), 
      icmp_packets_(0), other_packets_(0) {
}

PacketParser::~PacketParser() {
}

void PacketParser::parsePacket(const uint8_t* packet, int packet_len) {
    total_packets_++;
    
    if (packet_len < 14) {  // min ethernet frame size
        Utils::printWarning("Packet too small to contain Ethernet header");
        return;
    }
    
    parseEthernet(packet, packet_len);
}

void PacketParser::parseEthernet(const uint8_t* packet, int packet_len) {
    const EthernetHeader* eth_header = reinterpret_cast<const EthernetHeader*>(packet);
    
    std::cout << Utils::Colors::GREEN << "Ethernet Header:" << Utils::Colors::RESET << std::endl;
    std::cout << "  Source MAC: " << macToString(eth_header->src_mac) << std::endl;
    std::cout << "  Dest MAC: " << macToString(eth_header->dest_mac) << std::endl;
    
    uint16_t ethertype = ntohs(eth_header->ethertype);
    std::cout << "  EtherType: 0x" << std::hex << ethertype << std::dec;
    
    // determine next layer protocol
    switch (ethertype) {
        case 0x0800:  // ipv4
            std::cout << " (IPv4)" << std::endl;
            if (packet_len > 14) {
                parseIP(packet + 14, packet_len - 14);
            }
            break;
        case 0x0806:  // arp
            std::cout << " (ARP)" << std::endl;
            other_packets_++;
            break;
        case 0x86DD:  // ipv6
            std::cout << " (IPv6)" << std::endl;
            other_packets_++;
            break;
        default:
            std::cout << " (Unknown)" << std::endl;
            other_packets_++;
            break;
    }
}

void PacketParser::parseIP(const uint8_t* packet, int packet_len) {
    if (packet_len < 20) {  // min ip header size
        Utils::printWarning("Packet too small to contain IP header");
        return;
    }
    
    const IPHeader* ip_header = reinterpret_cast<const IPHeader*>(packet);
    
    uint8_t version = (ip_header->version_ihl >> 4) & 0x0F;
    uint8_t ihl = ip_header->version_ihl & 0x0F;
    uint8_t header_length = ihl * 4;
    
    if (version != 4) {
        std::cout << "  Non-IPv4 packet (version " << static_cast<int>(version) << ")" << std::endl;
        other_packets_++;
        return;
    }
    
    std::cout << Utils::Colors::YELLOW << "IP Header:" << Utils::Colors::RESET << std::endl;
    std::cout << "  Version: " << static_cast<int>(version) << std::endl;
    std::cout << "  Header Length: " << static_cast<int>(header_length) << " bytes" << std::endl;
    std::cout << "  Total Length: " << ntohs(ip_header->total_length) << " bytes" << std::endl;
    std::cout << "  Protocol: " << static_cast<int>(ip_header->protocol) 
              << " (" << protocolToString(ip_header->protocol) << ")" << std::endl;
    std::cout << "  TTL: " << static_cast<int>(ip_header->ttl) << std::endl;
    std::cout << "  Source IP: " << ipToString(ip_header->src_addr) << std::endl;
    std::cout << "  Dest IP: " << ipToString(ip_header->dest_addr) << std::endl;
    
    // parse next layer based on protocol
    if (packet_len > header_length) {
        const uint8_t* next_layer = packet + header_length;
        int remaining_len = packet_len - header_length;
        
        switch (ip_header->protocol) {
            case 6:   // tcp
                parseTCP(next_layer, remaining_len, ip_header->src_addr, ip_header->dest_addr);
                break;
            case 17:  // udp
                parseUDP(next_layer, remaining_len, ip_header->src_addr, ip_header->dest_addr);
                break;
            case 1:   // icmp
                std::cout << Utils::Colors::MAGENTA << "ICMP Packet" << Utils::Colors::RESET << std::endl;
                icmp_packets_++;
                break;
            default:
                std::cout << "Other IP protocol: " << static_cast<int>(ip_header->protocol) << std::endl;
                other_packets_++;
                break;
        }
    }
    
    // print packet data in hex format
    std::cout << Utils::Colors::CYAN << "Packet Data (first 64 bytes):" << Utils::Colors::RESET << std::endl;
    printPacketHex(packet, std::min(packet_len, 64));
}

void PacketParser::parseTCP(const uint8_t* packet, int packet_len, uint32_t src_ip, uint32_t dest_ip) {
    if (packet_len < 20) {  // min tcp header size
        Utils::printWarning("Packet too small to contain TCP header");
        return;
    }
    
    tcp_packets_++;
    
    const TCPHeader* tcp_header = reinterpret_cast<const TCPHeader*>(packet);
    
    std::cout << Utils::Colors::RED << "TCP Header:" << Utils::Colors::RESET << std::endl;
    std::cout << "  Source Port: " << ntohs(tcp_header->src_port) << std::endl;
    std::cout << "  Dest Port: " << ntohs(tcp_header->dest_port) << std::endl;
    std::cout << "  Sequence Number: " << ntohl(tcp_header->seq_num) << std::endl;
    std::cout << "  Ack Number: " << ntohl(tcp_header->ack_num) << std::endl;
    
    // parse tcp flags
    std::cout << "  Flags: ";
    if (tcp_header->flags & 0x01) std::cout << "FIN ";
    if (tcp_header->flags & 0x02) std::cout << "SYN ";
    if (tcp_header->flags & 0x04) std::cout << "RST ";
    if (tcp_header->flags & 0x08) std::cout << "PSH ";
    if (tcp_header->flags & 0x10) std::cout << "ACK ";
    if (tcp_header->flags & 0x20) std::cout << "URG ";
    std::cout << std::endl;
    
    std::cout << "  Window Size: " << ntohs(tcp_header->window) << std::endl;
    std::cout << "  Checksum: 0x" << std::hex << ntohs(tcp_header->checksum) << std::dec << std::endl;
    
    // determine application protocol based on port numbers
    uint16_t src_port = ntohs(tcp_header->src_port);
    uint16_t dest_port = ntohs(tcp_header->dest_port);
    
    std::cout << "  Application: ";
    if (src_port == 80 || dest_port == 80) {
        std::cout << "HTTP";
    } else if (src_port == 443 || dest_port == 443) {
        std::cout << "HTTPS";
    } else if (src_port == 21 || dest_port == 21) {
        std::cout << "FTP";
    } else if (src_port == 22 || dest_port == 22) {
        std::cout << "SSH";
    } else if (src_port == 23 || dest_port == 23) {
        std::cout << "Telnet";
    } else if (src_port == 25 || dest_port == 25) {
        std::cout << "SMTP";
    } else if (src_port == 53 || dest_port == 53) {
        std::cout << "DNS";
    } else {
        std::cout << "Unknown/Other";
    }
    std::cout << std::endl;
}

void PacketParser::parseUDP(const uint8_t* packet, int packet_len, uint32_t src_ip, uint32_t dest_ip) {
    if (packet_len < 8) {  // UDP header size
        Utils::printWarning("Packet too small to contain UDP header");
        return;
    }
    
    udp_packets_++;
    
    const UDPHeader* udp_header = reinterpret_cast<const UDPHeader*>(packet);
    
    std::cout << Utils::Colors::BLUE << "UDP Header:" << Utils::Colors::RESET << std::endl;
    std::cout << "  Source Port: " << ntohs(udp_header->src_port) << std::endl;
    std::cout << "  Dest Port: " << ntohs(udp_header->dest_port) << std::endl;
    std::cout << "  Length: " << ntohs(udp_header->length) << " bytes" << std::endl;
    std::cout << "  Checksum: 0x" << std::hex << ntohs(udp_header->checksum) << std::dec << std::endl;
    
    // determine application protocol based on port numbers
    uint16_t src_port = ntohs(udp_header->src_port);
    uint16_t dest_port = ntohs(udp_header->dest_port);
    
    std::cout << "  Application: ";
    if (src_port == 53 || dest_port == 53) {
        std::cout << "DNS";
    } else if (src_port == 67 || dest_port == 67 || src_port == 68 || dest_port == 68) {
        std::cout << "DHCP";
    } else if (src_port == 123 || dest_port == 123) {
        std::cout << "NTP";
    } else if (src_port == 161 || dest_port == 161 || src_port == 162 || dest_port == 162) {
        std::cout << "SNMP";
    } else {
        std::cout << "Unknown/Other";
    }
    std::cout << std::endl;
}

std::string PacketParser::macToString(const uint8_t* mac) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (int i = 0; i < 6; ++i) {
        if (i > 0) oss << ":";
        oss << std::setw(2) << static_cast<int>(mac[i]);
    }
    return oss.str();
}

std::string PacketParser::ipToString(uint32_t ip) {
    struct in_addr addr;
    addr.s_addr = ip;
    return std::string(inet_ntoa(addr));
}

std::string PacketParser::protocolToString(uint8_t protocol) {
    switch (protocol) {
        case 1: return "ICMP";
        case 6: return "TCP";
        case 17: return "UDP";
        case 2: return "IGMP";
        case 4: return "IP-in-IP";
        case 41: return "IPv6";
        case 47: return "GRE";
        case 50: return "ESP";
        case 51: return "AH";
        case 89: return "OSPF";
        default: return "Unknown";
    }
}

void PacketParser::printPacketHex(const uint8_t* packet, int length, int bytes_per_line) {
    for (int i = 0; i < length; i += bytes_per_line) {
        // print offset
        std::cout << std::hex << std::setfill('0') << std::setw(4) << i << "  ";
        
        // print hex bytes
        for (int j = 0; j < bytes_per_line; ++j) {
            if (i + j < length) {
                std::cout << std::hex << std::setfill('0') << std::setw(2) 
                         << static_cast<int>(packet[i + j]) << " ";
            } else {
                std::cout << "   ";
            }
            
            if (j == 7) std::cout << " ";
        }
        
        std::cout << " |";
        
        // ascii representation
        for (int j = 0; j < bytes_per_line && i + j < length; ++j) {
            uint8_t byte = packet[i + j];
            if (byte >= 32 && byte <= 126) {
                std::cout << static_cast<char>(byte);
            } else {
                std::cout << ".";
            }
        }
        
        std::cout << "|" << std::dec << std::endl;
    }
}

void PacketParser::printStatistics() {
    std::cout << std::endl << Utils::Colors::GREEN << "=== Capture Statistics ===" << Utils::Colors::RESET << std::endl;
    std::cout << "Total packets: " << total_packets_ << std::endl;
    std::cout << "TCP packets: " << tcp_packets_ << " (" 
              << (total_packets_ > 0 ? (tcp_packets_ * 100.0 / total_packets_) : 0) << "%)" << std::endl;
    std::cout << "UDP packets: " << udp_packets_ << " (" 
              << (total_packets_ > 0 ? (udp_packets_ * 100.0 / total_packets_) : 0) << "%)" << std::endl;
    std::cout << "ICMP packets: " << icmp_packets_ << " (" 
              << (total_packets_ > 0 ? (icmp_packets_ * 100.0 / total_packets_) : 0) << "%)" << std::endl;
    std::cout << "Other packets: " << other_packets_ << " (" 
              << (total_packets_ > 0 ? (other_packets_ * 100.0 / total_packets_) : 0) << "%)" << std::endl;
}

void PacketParser::resetStatistics() {
    total_packets_ = 0;
    tcp_packets_ = 0;
    udp_packets_ = 0;
    icmp_packets_ = 0;
    other_packets_ = 0;
}

uint16_t PacketParser::ntohs_custom(uint16_t value) {
    return ntohs(value);
}

uint32_t PacketParser::ntohl_custom(uint32_t value) {
    return ntohl(value);
}