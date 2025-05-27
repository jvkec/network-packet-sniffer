#ifndef UTILS_HPP
#define UTILS_HPP

#include <string>
#include <vector>
#include <cstdint>

namespace Utils {
    // string utils
    std::string trim(const std::string& str);
    std::vector<std::string> split(const std::string& str, char delimiter);
    std::string toLowerCase(const std::string& str);
    std::string toUpperCase(const std::string& str);
    
    // network utils
    bool isValidIPAddress(const std::string& ip);
    bool isValidMACAddress(const std::string& mac);
    uint32_t ipStringToInt(const std::string& ip);
    std::string ipIntToString(uint32_t ip);
    
    // time utils
    std::string getCurrentTimestamp();
    std::string formatTimestamp(const struct timeval& tv);
    
    // conversion utils
    std::string bytesToHex(const uint8_t* data, size_t length);
    std::string formatBytes(uint64_t bytes);
    
    // sytem utils
    bool requiresRoot();
    void printError(const std::string& message);
    void printInfo(const std::string& message);
    void printWarning(const std::string& message);
    namespace Colors {
        extern const std::string RESET;
        extern const std::string RED;
        extern const std::string GREEN;
        extern const std::string YELLOW;
        extern const std::string BLUE;
        extern const std::string MAGENTA;
        extern const std::string CYAN;
        extern const std::string WHITE;
    }
}

#endif