#include "analyser.hpp" // Inclui o header da própria classe
#include <iostream>

using namespace std;

// Construtor
Analyser::Analyser(string device)
    : deviceName(device), handle(nullptr), capturing(false) {
    cout << "Analisador de pacotes!" << "\n";
}

// Destrutor
Analyser::~Analyser() {
    if (handle) {
        pcap_close(handle);
        cout << "Handle de captura fechado." << endl;
    }
}

bool Analyser::startCapture() {
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

void Analyser::stopCapture() {
    if (capturing && handle) {
        cout << "Solicitando parada da captura..." << endl;
        pcap_breakloop(handle);
    }
}

void Analyser::processPacket(const struct pcap_pkthdr* header, const u_char* packetData) {
    cout << "Pacote capturado! Tamanho: " << header->len << " bytes\n";
}

void Analyser::staticCallback(u_char* user, const struct pcap_pkthdr* header, const u_char* packetData) {
    Analyser* sniffer = reinterpret_cast<Analyser*>(user);
    sniffer->processPacket(header, packetData);
}