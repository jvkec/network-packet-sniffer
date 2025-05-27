#ifndef SNIFFERS_HPP
#define SNIFFERS_HPP

#include <pcap.h>
#include <string>

class Sniffer 
{
  public:
    Sniffer(const std::string& device, const std::string& filter);
    ~Sniffer();

    void start();
    void stop();
    
  private:
  

};


#endif