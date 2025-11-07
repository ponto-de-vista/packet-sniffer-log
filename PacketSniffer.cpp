#include <iostream>
#include <string>
#include <pcap.h>

class PacketSniffer {
private:
    std::string deviceName;
    pcap_t* handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    bool capturing;

    void processPacket(const struct pcap_pkthdr* header, const u_char* packetData) {
        std::cout << "Pacote capturado! Tamanho: " << header->len << " bytes\n";
    }

    static void staticCallback(u_char* user, const struct pcap_pkthdr* header, const u_char* packetData) {
        PacketSniffer* sniffer = reinterpret_cast<PacketSniffer*>(user);

        sniffer->processPacket(header, packetData);
    }

public:
    PacketSniffer(std::string device) : deviceName(device), handle(nullptr), capturing(false) {
        std::cout << "Sniffer inicializado para o dispositivo: " << device << std::endl;
    }

    ~PacketSniffer() {
        if (handle) {
            pcap_close(handle);
            std::cout << "Handle de captura fechado." << std::endl;
        }
    }

    bool startCapture() {
        handle = pcap_open_live(deviceName.c_str(), BUFSIZ, 1, 1000, errbuf);
        if (handle == nullptr) {
            std::cerr << "Erro ao abrir dispositivo: " << errbuf << std::endl;
            return false;
        }

        std::cout << "Captura iniciada. Pressione Ctrl+C para parar (ou chame stopCapture de outra thread)." << std::endl;
        capturing = true;

        pcap_loop(handle, -1, staticCallback, reinterpret_cast<u_char*>(this));

        std::cout << "Loop de captura terminado." << std::endl;

        capturing = false;
        pcap_close(handle);
        handle = nullptr;
        return true;
    }

    void stopCapture() {
        if (capturing && handle) {
            std::cout << "Solicitando parada da captura..." << std::endl;
            pcap_breakloop(handle);
        }
    }
};

int main() {
    std::string device = "\\Device\\NPF_{4A03F203-76CC-40A6-AED1-6F255E028E81}";

    try {
        PacketSniffer sniffer(device);
        
        if (!sniffer.startCapture()) {
            std::cerr << "Falha ao iniciar a captura." << std::endl;
            return 1;
        }

    } catch (const std::exception& e) {
        std::cerr << "Exceção: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}