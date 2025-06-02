#include <iostream>
#include <signal.h>
#include <cstring>
#include <getopt.h>
#include "sniffer.hpp"
#include "utils.hpp"

Sniffer* g_sniffer = nullptr;

void signalHandler(int signal) {
    std::cout << "\n" << Utils::Colors::YELLOW << "Received signal " << signal 
              << ". Stopping packet capture..." << Utils::Colors::RESET << std::endl;
    
    if (g_sniffer) {
        g_sniffer->stop();
    }
    exit(0);
}

void printUsage(const char* program_name) {
    std::cout << "Usage: " << program_name << " [OPTIONS]\n"
              << "Network Packet Sniffer\n\n"
              << "Options:\n"
              << "  -i, --interface DEVICE    Network interface to capture on\n"
              << "  -f, --filter FILTER       BPF filter expression\n"
              << "  -c, --count COUNT         Number of packets to capture (0 = unlimited)\n"
              << "  -s, --snaplen LENGTH      Snapshot length (default: 65535)\n"
              << "  -p, --promiscuous         Enable promiscuous mode\n"
              << "  -l, --list                List available network interfaces\n"
              << "  -h, --help               Show this help message\n\n"
              << "Examples:\n"
              << "  sudo " << program_name << " -i eth0\n"
              << "  sudo " << program_name << " -i eth0 -f \"tcp port 80\"\n"
              << "  sudo " << program_name << " -i any -c 100 -p\n"
              << std::endl;
}

int main(int argc, char* argv[]) {
    if (Utils::requiresRoot()) {
        Utils::printError("This program requires root privileges to capture packets.");
        Utils::printInfo("Please run with sudo: sudo " + std::string(argv[0]));
        return 1;
    }
    
    // default values
    std::string device = "";
    std::string filter = "";
    int packet_count = 0;
    int snap_len = 65535;
    bool promiscuous = false;
    bool list_devices = false;
    
    // command line options
    static struct option long_options[] = {
        {"interface",    required_argument, 0, 'i'},
        {"filter",       required_argument, 0, 'f'},
        {"count",        required_argument, 0, 'c'},
        {"snaplen",      required_argument, 0, 's'},
        {"promiscuous",  no_argument,       0, 'p'},
        {"list",         no_argument,       0, 'l'},
        {"help",         no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };
    
    int option_index = 0;
    int c;
    
    while ((c = getopt_long(argc, argv, "i:f:c:s:plh", long_options, &option_index)) != -1) {
        switch (c) {
            case 'i':
                device = optarg;
                break;
            case 'f':
                filter = optarg;
                break;
            case 'c':
                packet_count = std::atoi(optarg);
                if (packet_count < 0) {
                    Utils::printError("Invalid packet count. Must be >= 0.");
                    return 1;
                }
                break;
            case 's':
                snap_len = std::atoi(optarg);
                if (snap_len <= 0) {
                    Utils::printError("Invalid snap length. Must be > 0.");
                    return 1;
                }
                break;
            case 'p':
                promiscuous = true;
                break;
            case 'l':
                list_devices = true;
                break;
            case 'h':
                printUsage(argv[0]);
                return 0;
            case '?':
                printUsage(argv[0]);
                return 1;
            default:
                break;
        }
    }
    
    try {
        Sniffer sniffer(device, filter);
        g_sniffer = &sniffer;
        
        if (list_devices) {
            sniffer.listDevices();
            return 0;
        }
        
        sniffer.setPromiscuous(promiscuous);
        sniffer.setSnapLength(snap_len);
        sniffer.setPacketCount(packet_count);
        
        signal(SIGINT, signalHandler);   // Ctrl+C
        signal(SIGTERM, signalHandler);  // Termination request
        
        Utils::printInfo("Starting packet capture...");
        Utils::printInfo("Device: " + sniffer.getCurrentDevice());
        if (!filter.empty()) {
            Utils::printInfo("Filter: " + filter);
        }
        if (packet_count > 0) {
            Utils::printInfo("Packet count: " + std::to_string(packet_count));
        } else {
            Utils::printInfo("Packet count: unlimited (press Ctrl+C to stop)");
        }
        Utils::printInfo("Promiscuous mode: " + std::string(promiscuous ? "enabled" : "disabled"));
        std::cout << std::string(50, '=') << std::endl;
        
        sniffer.start();
        
    } catch (const std::exception& e) {
        Utils::printError("Error: " + std::string(e.what()));
        return 1;
    }
    
    return 0;
}
