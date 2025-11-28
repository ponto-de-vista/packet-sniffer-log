#ifndef SNIFFER_HPP
#define SNIFFER_HPP

#include <string>
#include <vector>
#include <memory>
#include <pcap.h>
#include "packet.hpp"

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
        char errbuf[PCAP_ERRBUF_SIZE];
        bool capturing;

        // Processa dados brutos e constrói um Packet estruturado
        Packet buildPacket(const struct pcap_pkthdr* header, const u_char* packetData);
        
        // Métodos auxiliares para construir cada camada
        std::unique_ptr<EthernetHeader> parseEthernetHeader(const u_char* data);
        std::unique_ptr<IPHeader> parseIPHeader(const u_char* data, uint16_t etherType, int& ipHeaderLen);
        std::unique_ptr<TransportHeader> parseTransportHeader(const u_char* data, 
                                                               uint8_t protocol, 
                                                               int ipHeaderLen);

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

