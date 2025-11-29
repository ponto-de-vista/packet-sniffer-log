#include "sniffer.hpp" // Inclui o header da própria classe
#include <iostream>
#include <iomanip>
#include <sstream>
#include <netinet/ether.h>    // Para estruturas Ethernet
#include <netinet/ip.h>       // Para estruturas IP
#include <netinet/tcp.h>      // Para estruturas TCP
#include <netinet/udp.h>      // Para estruturas UDP
#include <arpa/inet.h>        // Para inet_ntoa, ntohs

using namespace std;

// Construtor
Sniffer::Sniffer(string device) 
: deviceName(device), handle(nullptr), capturing(false) 
{
    cout << "Sniffer de pacotes iniciado!" << "\n";
}

// Destrutor
Sniffer::~Sniffer() 
{
    if (handle) 
    {
        pcap_close(handle);
        cout << "Handle de captura fechado." << endl;
    }
}

bool Sniffer::startCapture() 
{
    handle = pcap_open_live(deviceName.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) 
    {
        cerr << "Erro ao abrir dispositivo: " << errbuf << endl;
        return false;
    }

    cout << "Captura iniciada. Pressione Ctrl+C para parar." << endl;
    capturing = true;
    shouldStop = false;
    
    // Inicia captura em thread separada
    captureThread = std::thread(&Sniffer::captureLoop, this);
    
    return true;
}

void Sniffer::captureLoop()
{
    pcap_loop(handle, -1, staticCallback, reinterpret_cast<u_char*>(this));
    cout << "Loop de captura terminado." << endl;
    capturing = false;
}

void Sniffer::stopCapture() 
{
    if (capturing && handle) 
    {
        cout << "Solicitando parada da captura..." << endl;
        pcap_breakloop(handle);
        
        if (captureThread.joinable()) 
        {
            captureThread.join();
        }
        
        if (handle) 
        {
            pcap_close(handle);
            handle = nullptr;
        }
    }
}

// ===== PARSE ETHERNET HEADER =====
unique_ptr<EthernetHeader> Sniffer::parseEthernetHeader(const u_char* data) 
{
    const struct ether_header* eth = (struct ether_header*)data;
    
    // Converte MAC para string
    ostringstream srcMac, dstMac;
    for (int i = 0; i < 6; i++) 
    {
        srcMac << hex << setw(2) << setfill('0') << (int)eth->ether_shost[i];
        dstMac << hex << setw(2) << setfill('0') << (int)eth->ether_dhost[i];
        if (i < 5) {
            srcMac << ":";
            dstMac << ":";
        }
    }
    
    uint16_t etherType = ntohs(eth->ether_type);
    
    return make_unique<EthernetHeader>(srcMac.str(), dstMac.str(), etherType);
}

// ===== PARSE IP HEADER =====
unique_ptr<IPHeader> Sniffer::parseIPHeader(const u_char* data, uint16_t etherType, int& ipHeaderLen)
{
    if (etherType != ETHERTYPE_IP) 
    {
        ipHeaderLen = 0;
        return nullptr; // Não é IPv4
    }
    
    const struct ip* ip_header = (struct ip*)(data + sizeof(struct ether_header));
    
    // Extrai informações
    uint8_t version = (ip_header->ip_hl >> 4) & 0x0F;
    string srcIP = inet_ntoa(ip_header->ip_src);
    string dstIP = inet_ntoa(ip_header->ip_dst);
    uint8_t ttl = ip_header->ip_ttl;
    uint8_t protocol = ip_header->ip_p;
    uint16_t identification = ntohs(ip_header->ip_id);
    
    // Calcula tamanho do header IP
    ipHeaderLen = (ip_header->ip_hl & 0x0f) * 4;
    
    return make_unique<IPv4Header>(srcIP, dstIP, protocol, ttl, version, identification);
}

// ===== PARSE TRANSPORT HEADER =====
unique_ptr<TransportHeader> Sniffer::parseTransportHeader(const u_char* data, 
                                                           uint8_t protocol, 
                                                           int ipHeaderLen) {
    const u_char* transportData = data + sizeof(struct ether_header) + ipHeaderLen;
    
    if (protocol == IPPROTO_TCP) 
    {
        const struct tcphdr* tcp = (struct tcphdr*)transportData;
        
        uint16_t srcPort = ntohs(tcp->th_sport);
        uint16_t dstPort = ntohs(tcp->th_dport);
        uint32_t seqNum = ntohl(tcp->th_seq);
        uint32_t ackNum = ntohl(tcp->th_ack);
        uint8_t flags = tcp->th_flags;
        
        return make_unique<TCPHeader>(srcPort, dstPort, seqNum, ackNum, flags);
        
    } 
    else if (protocol == IPPROTO_UDP) 
    {
        const struct udphdr* udp = (struct udphdr*)transportData;
        
        uint16_t srcPort = ntohs(udp->uh_sport);
        uint16_t dstPort = ntohs(udp->uh_dport);
        uint16_t length = ntohs(udp->uh_ulen);
        
        return make_unique<UDPHeader>(srcPort, dstPort, length);
        
    } 
    else if (protocol == IPPROTO_ICMP) 
    {
        return make_unique<ICMPHeader>();
    }
    
    return nullptr; // Protocolo não suportado
}

// ===== BUILD PACKET =====
Packet Sniffer::buildPacket(const struct pcap_pkthdr* header, const u_char* packetData) {
    Packet packet;
    
    // Define metadados
    timespec ts;
    ts.tv_sec = header->ts.tv_sec;
    ts.tv_nsec = header->ts.tv_usec * 1000; // converte microsegundos para nanosegundos
    packet.setTimestamp(ts);
    packet.setCapturedLength(header->caplen);
    packet.setActualLength(header->len);
    packet.setRawData(packetData, header->caplen);
    
    // Parse Ethernet Header
    auto ethHeader = parseEthernetHeader(packetData);
    uint16_t etherType = ethHeader->getEtherType();
    packet.setEthernetHeader(move(ethHeader));
    
    // Parse IP Header (se for IPv4)
    int ipHeaderLen = 0;
    auto ipHeader = parseIPHeader(packetData, etherType, ipHeaderLen);
    
    if (ipHeader) 
    {
        uint8_t protocol = ipHeader->getProtocol();
        packet.setIPHeader(move(ipHeader));
        
        // Parse Transport Header
        auto transportHeader = parseTransportHeader(packetData, protocol, ipHeaderLen);
        if (transportHeader) 
        {
            packet.setTransportHeader(move(transportHeader));
        }
    }
    
    return packet;
}

void Sniffer::staticCallback(u_char* user, const struct pcap_pkthdr* header, const u_char* packetData) {
    Sniffer* sniffer = reinterpret_cast<Sniffer*>(user);
    
    // Constrói o pacote estruturado
    Packet packet = sniffer->buildPacket(header, packetData);
    
    // Exibe as informações detalhadas do pacote
    //cout << packet.getDetailedInfo() << endl;

    // cout << sniffer->deviceName;
}

// Método estático para listar todos os dispositivos de rede disponíveis
vector<NetworkDevice> Sniffer::listAvailableDevices() 
{
    vector<NetworkDevice> devices;
    pcap_if_t* alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    // Busca todos os dispositivos de rede disponíveis
    if (pcap_findalldevs(&alldevs, errbuf) == -1) 
    {
        cerr << "Erro ao buscar dispositivos: " << errbuf << endl;
        return devices; // Retorna vetor vazio
    }
    
    // Itera sobre os dispositivos encontrados
    for (pcap_if_t* dev = alldevs; dev != nullptr; dev = dev->next) 
    {
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
string Sniffer::selectDeviceInteractive() 
{
    cout << "\n========== DISPOSITIVOS DE REDE DISPONÍVEIS ==========" << endl;
    
    vector<NetworkDevice> devices = listAvailableDevices();
    
    if (devices.empty()) 
    {
        cerr << "Nenhum dispositivo de rede encontrado!" << endl;
        return "";
    }
    
    // Exibe a lista de dispositivos
    cout << "\nSelecione um dispositivo:\n" << endl;
    for (size_t i = 0; i < devices.size(); i++) 
    {
        cout << "[" << (i + 1) << "] " << devices[i].name;
        
        if (!devices[i].description.empty() && devices[i].description != "Sem descrição") 
        {
            cout << " - " << devices[i].description;
        }
        
        if (devices[i].hasAddress) 
        {
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
    if (choice == 0) 
    {
        cout << "Selecionado: Todos os dispositivos (any)" << endl;
        return "any";
    } 
    else if (choice > 0 && choice <= static_cast<int>(devices.size())) 
    {
        string selectedDevice = devices[choice - 1].name;
        cout << "Selecionado: " << selectedDevice << endl;
        return selectedDevice;
    } 
    else
    {
        cerr << "Opção inválida!" << endl;
        return "";
    }
}

