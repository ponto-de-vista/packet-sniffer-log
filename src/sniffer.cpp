#include "sniffer.hpp" // Inclui o header da própria classe
#include <iostream>
#include <iomanip>
#include <netinet/ether.h>    // Para estruturas Ethernet
#include <netinet/ip.h>       // Para estruturas IP
#include <netinet/tcp.h>      // Para estruturas TCP
#include <netinet/udp.h>      // Para estruturas UDP
#include <arpa/inet.h>        // Para inet_ntoa, ntohs

using namespace std;

// Construtor
Sniffer::Sniffer(string device)
    : deviceName(device), handle(nullptr), capturing(false) {
    cout << "Sniffer de pacotes iniciado!" << "\n";
}

// Destrutor
Sniffer::~Sniffer() {
    if (handle) {
        pcap_close(handle);
        cout << "Handle de captura fechado." << endl;
    }
}

bool Sniffer::startCapture() {
    handle = pcap_open_live(deviceName.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        cerr << "Erro ao abrir dispositivo: " << errbuf << endl;
        return false;
    }

    cout << "Captura iniciada. Pressione Ctrl+C para parar." << endl;
    capturing = true;

    pcap_loop(handle, -1, staticCallback, reinterpret_cast<u_char*>(this));

    cout << "Loop de captura terminado." << endl;

    capturing = false;
    if (handle) {
        pcap_close(handle);
        handle = nullptr;
    }
    return true;
}

void Sniffer::stopCapture() {
    if (capturing && handle) {
        cout << "Solicitando parada da captura..." << endl;
        pcap_breakloop(handle);
    }
}

void Sniffer::processPacket(const struct pcap_pkthdr* header, const u_char* packetData) {
    cout << "\n========== PACOTE CAPTURADO ==========" << endl;
    cout << "Timestamp: " << header->ts.tv_sec << "." << header->ts.tv_usec << endl;
    cout << "Tamanho capturado: " << header->caplen << " bytes" << endl;
    cout << "Tamanho real: " << header->len << " bytes" << endl;
    
    // ===== CAMADA ETHERNET (Layer 2) =====
    const struct ether_header* eth = (struct ether_header*)packetData;
    
    cout << "\n--- Ethernet Header ---" << endl;
    cout << "MAC Origem: ";
    for (int i = 0; i < 6; i++) {
        cout << hex << setw(2) << setfill('0') << (int)eth->ether_shost[i];
        if (i < 5) cout << ":";
    }
    cout << dec << endl;
    
    cout << "MAC Destino: ";
    for (int i = 0; i < 6; i++) {
        cout << hex << setw(2) << setfill('0') << (int)eth->ether_dhost[i];
        if (i < 5) cout << ":";
    }
    cout << dec << endl;
    
    u_short ether_type = ntohs(eth->ether_type);
    cout << "Tipo Ethernet: 0x" << hex << ether_type << dec;
    
    // Verificar se é IPv4
    if (ether_type == ETHERTYPE_IP) {
        cout << " (IPv4)" << endl;
        
        // ===== CAMADA IP (Layer 3) =====
        const struct ip* ip_header = (struct ip*)(packetData + sizeof(struct ether_header));
        
        cout << "\n--- IP Header ---" << endl;
        cout << "Versão IP: " << (int)((ip_header->ip_hl >> 4) & 0x0F) << endl;
        cout << "IP Origem: " << inet_ntoa(ip_header->ip_src) << endl;
        cout << "IP Destino: " << inet_ntoa(ip_header->ip_dst) << endl;
        cout << "TTL: " << (int)ip_header->ip_ttl << endl;
        
        int protocol = ip_header->ip_p;
        cout << "Protocolo: ";
        
        // Calcular tamanho do header IP
        int ip_header_len = (ip_header->ip_hl & 0x0f) * 4;
        
        // ===== CAMADA TRANSPORTE (Layer 4) =====
        if (protocol == IPPROTO_TCP) {
            cout << "TCP (6)" << endl;
            
            const struct tcphdr* tcp = (struct tcphdr*)(packetData + sizeof(struct ether_header) + ip_header_len);
            
            cout << "\n--- TCP Header ---" << endl;
            cout << "Porta Origem: " << ntohs(tcp->th_sport) << endl;
            cout << "Porta Destino: " << ntohs(tcp->th_dport) << endl;
            cout << "Sequence Number: " << ntohl(tcp->th_seq) << endl;
            cout << "Acknowledgment Number: " << ntohl(tcp->th_ack) << endl;
            
            // Flags TCP
            cout << "Flags: ";
            if (tcp->th_flags & TH_FIN) cout << "FIN ";
            if (tcp->th_flags & TH_SYN) cout << "SYN ";
            if (tcp->th_flags & TH_RST) cout << "RST ";
            if (tcp->th_flags & TH_PUSH) cout << "PUSH ";
            if (tcp->th_flags & TH_ACK) cout << "ACK ";
            if (tcp->th_flags & TH_URG) cout << "URG ";
            cout << endl;
            
        } else if (protocol == IPPROTO_UDP) {
            cout << "UDP (17)" << endl;
            
            const struct udphdr* udp = (struct udphdr*)(packetData + sizeof(struct ether_header) + ip_header_len);
            
            cout << "\n--- UDP Header ---" << endl;
            cout << "Porta Origem: " << ntohs(udp->uh_sport) << endl;
            cout << "Porta Destino: " << ntohs(udp->uh_dport) << endl;
            cout << "Tamanho: " << ntohs(udp->uh_ulen) << " bytes" << endl;
            
        } else if (protocol == IPPROTO_ICMP) {
            cout << "ICMP (1)" << endl;
            
        } else {
            cout << "Outro (" << protocol << ")" << endl;
        }
        
    } else if (ether_type == ETHERTYPE_IPV6) {
        cout << " (IPv6)" << endl;
        cout << "IPv6 não implementado neste exemplo" << endl;
        
    } else if (ether_type == ETHERTYPE_ARP) {
        cout << " (ARP)" << endl;
        cout << "ARP não implementado neste exemplo" << endl;
        
    } else {
        cout << " (Desconhecido)" << endl;
    }
    
    cout << "======================================\n" << endl;
}

void Sniffer::staticCallback(u_char* user, const struct pcap_pkthdr* header, const u_char* packetData) {
    Sniffer* sniffer = reinterpret_cast<Sniffer*>(user);
    sniffer->processPacket(header, packetData);
}

// Método estático para listar todos os dispositivos de rede disponíveis
vector<NetworkDevice> Sniffer::listAvailableDevices() {
    vector<NetworkDevice> devices;
    pcap_if_t* alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    // Busca todos os dispositivos de rede disponíveis
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        cerr << "Erro ao buscar dispositivos: " << errbuf << endl;
        return devices; // Retorna vetor vazio
    }
    
    // Itera sobre os dispositivos encontrados
    for (pcap_if_t* dev = alldevs; dev != nullptr; dev = dev->next) {
        string name = dev->name;
        string description = (dev->description) ? dev->description : "Sem descrição";
        bool hasAddress = (dev->addresses != nullptr);
        
        devices.push_back(NetworkDevice(name, description, hasAddress));
    }
    
    // Libera a memória alocada pela pcap_findalldevs
    pcap_freealldevs(alldevs);
    
    return devices;
}

// Método estático para seleção interativa de dispositivo
string Sniffer::selectDeviceInteractive() {
    cout << "\n========== DISPOSITIVOS DE REDE DISPONÍVEIS ==========" << endl;
    
    vector<NetworkDevice> devices = listAvailableDevices();
    
    if (devices.empty()) {
        cerr << "Nenhum dispositivo de rede encontrado!" << endl;
        return "";
    }
    
    // Exibe a lista de dispositivos
    cout << "\nSelecione um dispositivo:\n" << endl;
    for (size_t i = 0; i < devices.size(); i++) {
        cout << "[" << (i + 1) << "] " << devices[i].name;
        
        if (!devices[i].description.empty() && devices[i].description != "Sem descrição") {
            cout << " - " << devices[i].description;
        }
        
        if (devices[i].hasAddress) {
            cout << " (com IP configurado)";
        }
        
        cout << endl;
    }
    
    cout << "\n[0] Capturar de todos os dispositivos (any)" << endl;
    cout << "\n======================================================" << endl;
    
    // Solicita a escolha do usuário
    int choice;
    cout << "\nDigite o número do dispositivo: ";
    cin >> choice;
    
    // Valida a escolha
    if (choice == 0) {
        cout << "Selecionado: Todos os dispositivos (any)" << endl;
        return "any";
    } else if (choice > 0 && choice <= static_cast<int>(devices.size())) {
        string selectedDevice = devices[choice - 1].name;
        cout << "Selecionado: " << selectedDevice << endl;
        return selectedDevice;
    } else {
        cerr << "Opção inválida!" << endl;
        return "";
    }
}

