#ifndef SNIFFER_HPP
#define SNIFFER_HPP

#include <string>
#include <vector>
#include <pcap.h>

// Estrutura para armazenar informações de um dispositivo de rede
struct NetworkDevice {
    std::string name;        // Nome do dispositivo (ex: eth0, wlan0)
    std::string description; // Descrição do dispositivo
    bool hasAddress;         // Se tem endereço IP configurado
    
    NetworkDevice(std::string n, std::string desc, bool addr)
        : name(n), description(desc), hasAddress(addr) {}
};

class Sniffer {
    private:
        std::string deviceName;
        pcap_t* handle;
        char* errbuf;
        bool capturing;

        void processPacket(const struct pcap_pkthdr* header, const u_char* packetData);

        static void staticCallback(u_char* user, const struct pcap_pkthdr* header, const u_char* packetData);

    public:
        Sniffer(std::string device); // Construtor
        ~Sniffer(); // Destrutor
        bool startCapture();
        void stopCapture();
        
        // Métodos estáticos para gerenciar dispositivos (não dependem de instância)
        static std::vector<NetworkDevice> listAvailableDevices();
        static std::string selectDeviceInteractive();
};

#endif

