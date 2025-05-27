#include "sniffer.hpp"
#include "utils.hpp"
#include <iostream>
#include <stdexcept>
#include <cstring>
#include <unistd.h>

Sniffer::Sniffer(const std::string& device, const std::string& filter)
    : handle_(nullptr), device_(device), filter_(filter), promiscuous_(false),
      snap_len_(65535), packet_count_(0), running_(false) {

    parser_ = std::make_unique<PacketParser>();
    
    // if no device specified, find default
    if (device_.empty()) {
        device_ = getDefaultDevice();
    }
}

Sniffer::~Sniffer() {
    cleanup();
}

void Sniffer::start() {
    if (running_) {
        throw std::runtime_error("Sniffer is already running");
    }
    
    if (!initializeCapture()) {
        throw std::runtime_error("Failed to initialize packet capture");
    }
    
    running_ = true;
    
    // start packet capture loop
    int result = pcap_loop(handle_, packet_count_, packetHandler, reinterpret_cast<uint8_t*>(this));
    
    if (result == -1) {
        throw std::runtime_error("Error in packet capture: " + std::string(pcap_geterr(handle_)));
    }
    
    running_ = false;
    
    parser_->printStatistics();
}

void Sniffer::stop() {
    if (handle_ && running_) {
        pcap_breakloop(handle_);
        running_ = false;
    }
}

bool Sniffer::setDevice(const std::string& device) {
    if (running_) {
        Utils::printWarning("Cannot change device while capture is running");
        return false;
    }
    
    device_ = device.empty() ? getDefaultDevice() : device;
    return true;
}

bool Sniffer::setFilter(const std::string& filter) {
    filter_ = filter;
    
    // if capture already initialized, recompile filter
    if (handle_) {
        return compileAndSetFilter();
    }
    
    return true;
}

void Sniffer::setPromiscuous(bool promiscuous) {
    if (running_) {
        Utils::printWarning("Cannot change promiscuous mode while capture is running");
        return;
    }
    promiscuous_ = promiscuous;
}

void Sniffer::setSnapLength(int snap_len) {
    if (running_) {
        Utils::printWarning("Cannot change snap length while capture is running");
        return;
    }
    snap_len_ = snap_len;
}

void Sniffer::setPacketCount(int count) {
    packet_count_ = count;
}

void Sniffer::listDevices() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs;
    pcap_if_t* device;
    
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
      std::cerr << "Error finding devices: " << errbuf << std::endl;
      return;
    }
    
    std::cout << Utils::Colors::CYAN << "Available network interfaces:" << Utils::Colors::RESET << std::endl;
    std::cout << std::string(50, '-') << std::endl;
    
    int i = 0;
    for (device = alldevs; device != nullptr; device = device->next) {
        std::cout << Utils::Colors::GREEN << ++i << ". " << device->name << Utils::Colors::RESET;
        
        if (device->description) {
            std::cout << " (" << device->description << ")";
        }
        
        std::cout << std::endl;
        
        // printing addresses
        for (pcap_addr_t* addr = device->addresses; addr != nullptr; addr = addr->next) {
            if (addr->addr && addr->addr->sa_family == AF_INET) {
                struct sockaddr_in* addr_in = (struct sockaddr_in*)addr->addr;
                std::cout << "   IP: " << inet_ntoa(addr_in->sin_addr) << std::endl;
            }
        }
    }
    
    pcap_freealldevs(alldevs);
}

std::string Sniffer::getCurrentDevice() const {
    return device_;
}

bool Sniffer::isRunning() const {
    return running_;
}

void Sniffer::packetHandler(uint8_t* user_data, const struct pcap_pkthdr* pkthdr, const uint8_t* packet) {
    Sniffer* sniffer = reinterpret_cast<Sniffer*>(user_data);
    
    std::cout << Utils::Colors::BLUE << "\n=== Packet Captured ===" << Utils::Colors::RESET << std::endl;
    std::cout << "Timestamp: " << Utils::formatTimestamp(pkthdr->ts) << std::endl;
    std::cout << "Captured length: " << pkthdr->caplen << " bytes" << std::endl;
    std::cout << "Original length: " << pkthdr->len << " bytes" << std::endl;
    
    // parse the packet
    sniffer->parser_->parsePacket(packet, pkthdr->caplen);
    
    std::cout << std::string(50, '-') << std::endl;
}

bool Sniffer::initializeCapture() {
    char errbuf[PCAP_ERRBUF_SIZE];
    
    // opening device for packet capture
    handle_ = pcap_open_live(device_.c_str(), snap_len_, promiscuous_ ? 1 : 0, 1000, errbuf);
    
    if (handle_ == nullptr) {
        Utils::printError("Cannot open device " + device_ + ": " + std::string(errbuf));
        return false;
    }
    
    // check if device provides ethernet headers
    if (pcap_datalink(handle_) != DLT_EN10MB) {
        Utils::printWarning("Device " + device_ + " doesn't provide Ethernet headers");
    }
    // compile and set filter if specified
    if (!filter_.empty() && !compileAndSetFilter()) {
        return false;
    }
    
    return true;
}

void Sniffer::cleanup() {
    if (handle_) {
        pcap_close(handle_);
        handle_ = nullptr;
    }
    running_ = false;
}

std::string Sniffer::getDefaultDevice() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs;
    
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        Utils::printError("Error finding devices: " + std::string(errbuf));
        return "any"; // fallback to "any" device
    }
    
    // use first device if available
    std::string result = "any";
    if (alldevs != nullptr) {
        result = alldevs->name;
        pcap_freealldevs(alldevs);
    }
    
    return result;
}

bool Sniffer::compileAndSetFilter() {
    struct bpf_program fp;
    bpf_u_int32 mask;
    bpf_u_int32 net;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    // getting network mask
    if (pcap_lookupnet(device_.c_str(), &net, &mask, errbuf) == -1) {
        Utils::printWarning("Cannot get network mask for device " + device_ + ": " + std::string(errbuf));
        net = 0;
        mask = 0;
    }
    
    // compile filter
    if (pcap_compile(handle_, &fp, filter_.c_str(), 0, net) == -1) {
        Utils::printError("Cannot compile filter '" + filter_ + "': " + std::string(pcap_geterr(handle_)));
        return false;
    }
    
    // set filter
    if (pcap_setfilter(handle_, &fp) == -1) {
        Utils::printError("Cannot set filter '" + filter_ + "': " + std::string(pcap_geterr(handle_)));
        pcap_freecode(&fp);
        return false;
    }
    
    pcap_freecode(&fp);
    return true;
}