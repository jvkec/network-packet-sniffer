#ifndef SNIFFER_HPP
#define SNIFFER_HPP

#include <pcap.h>
#include <string>
#include <memory>
#include "packet_parser.hpp"

class Sniffer {
public:
    Sniffer(const std::string& device = "", const std::string& filter = "");
    ~Sniffer();
    
    void start();
    void stop();
    
    // config functions
    bool setDevice(const std::string& device);
    bool setFilter(const std::string& filter);
    void setPromiscuous(bool promiscuous);
    void setSnapLength(int snap_len);
    void setPacketCount(int count); // 0 = unlimited
    
    void listDevices();
    std::string getCurrentDevice() const;
    bool isRunning() const;
    
    // packet callback (static for pcap compatibility)
    static void packetHandler(uint8_t* user_data, const struct pcap_pkthdr* pkthdr, const uint8_t* packet);
    
private:
    // pcap handle
    pcap_t* handle_;
    
    // configuration params 
    std::string device_;
    std::string filter_;
    bool promiscuous_;
    int snap_len_;
    int packet_count_;
    bool running_;
    
    std::unique_ptr<PacketParser> parser_;
    
    bool initializeCapture();
    void cleanup();
    std::string getDefaultDevice();
    bool compileAndSetFilter();
};

#endif