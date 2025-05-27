#include "utils.hpp"
#include <algorithm>
#include <sstream>
#include <regex>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <unistd.h>
#include <sys/time.h>
#include <arpa/inet.h>

// Color definitions
namespace Utils {
    namespace Colors {
        const std::string RESET = "\033[0m";
        const std::string RED = "\033[31m";
        const std::string GREEN = "\033[32m";
        const std::string YELLOW = "\033[33m";
        const std::string BLUE = "\033[34m";
        const std::string MAGENTA = "\033[35m";
        const std::string CYAN = "\033[36m";
        const std::string WHITE = "\033[37m";
    }
}

namespace Utils {
    
    std::string trim(const std::string& str) {
        size_t first = str.find_first_not_of(' ');
        if (first == std::string::npos) return "";
        size_t last = str.find_last_not_of(' ');
        return str.substr(first, (last - first + 1));
    }
    
    std::vector<std::string> split(const std::string& str, char delimiter) {
        std::vector<std::string> tokens;
        std::stringstream ss(str);
        std::string token;
        
        while (std::getline(ss, token, delimiter)) {
            tokens.push_back(trim(token));
        }
        
        return tokens;
    }
    
    std::string toLowerCase(const std::string& str) {
        std::string result = str;
        std::transform(result.begin(), result.end(), result.begin(), ::tolower);
        return result;
    }
    
    std::string toUpperCase(const std::string& str) {
        std::string result = str;
        std::transform(result.begin(), result.end(), result.begin(), ::toupper);
        return result;
    }
    
    bool isValidIPAddress(const std::string& ip) {
        std::regex ip_regex(
            R"(^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$)"
        );
        return std::regex_match(ip, ip_regex);
    }
    
    bool isValidMACAddress(const std::string& mac) {
        std::regex mac_regex(R"(^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$)");
        return std::regex_match(mac, mac_regex);
    }
    
    uint32_t ipStringToInt(const std::string& ip) {
        struct in_addr addr;
        if (inet_aton(ip.c_str(), &addr)) {
            return addr.s_addr;
        }
        return 0;
    }
    
    std::string ipIntToString(uint32_t ip) {
        struct in_addr addr;
        addr.s_addr = ip;
        return std::string(inet_ntoa(addr));
    }
    
    std::string getCurrentTimestamp() {
        auto now = std::time(nullptr);
        auto tm = *std::localtime(&now);
        
        std::ostringstream oss;
        oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
        return oss.str();
    }
    
    std::string formatTimestamp(const struct timeval& tv) {
        auto tm = *std::localtime(&tv.tv_sec);
        
        std::ostringstream oss;
        oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
        oss << "." << std::setfill('0') << std::setw(6) << tv.tv_usec;
        return oss.str();
    }
    
    std::string bytesToHex(const uint8_t* data, size_t length) {
        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        
        for (size_t i = 0; i < length; ++i) {
            oss << std::setw(2) << static_cast<int>(data[i]);
            if (i < length - 1) oss << " ";
        }
        
        return oss.str();
    }
    
    std::string formatBytes(uint64_t bytes) {
        const char* suffixes[] = {"B", "KB", "MB", "GB", "TB"};
        double size = static_cast<double>(bytes);
        int suffix_index = 0;
        
        while (size >= 1024.0 && suffix_index < 4) {
            size /= 1024.0;
            suffix_index++;
        }
        
        std::ostringstream oss;
        if (suffix_index == 0) {
            oss << static_cast<uint64_t>(size) << " " << suffixes[suffix_index];
        } else {
            oss << std::fixed << std::setprecision(2) << size << " " << suffixes[suffix_index];
        }
        
        return oss.str();
    }
    
    bool requiresRoot() {
        return getuid() != 0;
    }
    
    void printError(const std::string& message) {
        std::cerr << Colors::RED << "[ERROR] " << message << Colors::RESET << std::endl;
    }
    
    void printInfo(const std::string& message) {
        std::cout << Colors::GREEN << "[INFO] " << message << Colors::RESET << std::endl;
    }
    
    void printWarning(const std::string& message) {
        std::cout << Colors::YELLOW << "[WARNING] " << message << Colors::RESET << std::endl;
    }
}