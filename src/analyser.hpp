#ifndef ANALYSER_HPP
#define ANALYSER_HPP

#include <string>
#include <pcap.h>

class Analyser {
    private:
        std::string deviceName;
        pcap_t* handle;
        char* errbuf;
        bool capturing;

        void processPacket(const struct pcap_pkthdr* header, const u_char* packetData);

        static void staticCallback(u_char* user, const struct pcap_pkthdr* header, const u_char* packetData);

    public:
        Analyser(std::string device); // Construtor
        ~Analyser(); // Destrutor
        bool startCapture();
        void stopCapture();
};

#endif