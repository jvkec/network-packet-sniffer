#include <iostream>
#include <cassert>
#include <cstring>
#include "packet_parser.hpp"
#include "utils.hpp"

// Simple test framework
class TestRunner {
public:
    static void runAllTests() {
        std::cout << Utils::Colors::CYAN << "Running Packet Parser Tests..." << Utils::Colors::RESET << std::endl;
        
        testMacToString();
        testIpToString();
        testProtocolToString();
        testBytesToHex();
        testIPValidation();
        testMACValidation();
        
        std::cout << Utils::Colors::GREEN << "All tests passed!" << Utils::Colors::RESET << std::endl;
    }
    
private:
    static void testMacToString() {
        std::cout << "Testing MAC address formatting... ";
        
        PacketParser parser;
        uint8_t mac[6] = {0x00, 0x1b, 0x21, 0x3e, 0x37, 0x6d};
        std::string result = parser.macToString(mac);
        std::string expected = "00:1b:21:3e:37:6d";
        
        assert(result == expected);
        std::cout << Utils::Colors::GREEN << "PASSED" << Utils::Colors::RESET << std::endl;
    }
    
    static void testIpToString() {
        std::cout << "Testing IP address formatting... ";
        
        PacketParser parser;
        uint32_t ip = inet_addr("192.168.1.1");
        std::string result = parser.ipToString(ip);
        std::string expected = "192.168.1.1";
        
        assert(result == expected);
        std::cout << Utils::Colors::GREEN << "PASSED" << Utils::Colors::RESET << std::endl;
    }
    
    static void testProtocolToString() {
        std::cout << "Testing protocol string conversion... ";
        
        PacketParser parser;
        assert(parser.protocolToString(1) == "ICMP");
        assert(parser.protocolToString(6) == "TCP");
        assert(parser.protocolToString(17) == "UDP");
        assert(parser.protocolToString(255) == "Unknown");
        
        std::cout << Utils::Colors::GREEN << "PASSED" << Utils::Colors::RESET << std::endl;
    }
    
    static void testBytesToHex() {
        std::cout << "Testing bytes to hex conversion... ";
        
        uint8_t data[] = {0xDE, 0xAD, 0xBE, 0xEF};
        std::string result = Utils::bytesToHex(data, 4);
        std::string expected = "de ad be ef";
        
        assert(result == expected);
        std::cout << Utils::Colors::GREEN << "PASSED" << Utils::Colors::RESET << std::endl;
    }
    
    static void testIPValidation() {
        std::cout << "Testing IP address validation... ";
        
        assert(Utils::isValidIPAddress("192.168.1.1") == true);
        assert(Utils::isValidIPAddress("255.255.255.255") == true);
        assert(Utils::isValidIPAddress("0.0.0.0") == true);
        assert(Utils::isValidIPAddress("256.1.1.1") == false);
        assert(Utils::isValidIPAddress("192.168.1") == false);
        assert(Utils::isValidIPAddress("not.an.ip.address") == false);
        
        std::cout << Utils::Colors::GREEN << "PASSED" << Utils::Colors::RESET << std::endl;
    }
    
    static void testMACValidation() {
        std::cout << "Testing MAC address validation... ";
        
        assert(Utils::isValidMACAddress("00:1b:21:3e:37:6d") == true);
        assert(Utils::isValidMACAddress("00-1B-21-3E-37-6D") == true);
        assert(Utils::isValidMACAddress("FF:FF:FF:FF:FF:FF") == true);
        assert(Utils::isValidMACAddress("00:1b:21:3e:37") == false);
        assert(Utils::isValidMACAddress("not:a:mac:address") == false);
        
        std::cout << Utils::Colors::GREEN << "PASSED" << Utils::Colors::RESET << std::endl;
    }
};

int main() {
    TestRunner::runAllTests();
    return 0;
}