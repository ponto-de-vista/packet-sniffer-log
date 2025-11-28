#include "packet.hpp"
#include <iomanip>
#include <sstream>

using namespace std;

// ===== ETHERNET HEADER =====
string EthernetHeader::getEtherTypeString() const {
    switch(etherType) {
        case 0x0800: return "IPv4";
        case 0x0806: return "ARP";
        case 0x86DD: return "IPv6";
        default: return "Desconhecido";
    }
}

string EthernetHeader::toString() const {
    ostringstream oss;
    oss << "--- Ethernet Header ---\n";
    oss << "MAC Origem: " << srcMac << "\n";
    oss << "MAC Destino: " << dstMac << "\n";
    oss << "Tipo: 0x" << hex << setw(4) << setfill('0') << etherType 
        << dec << " (" << getEtherTypeString() << ")";
    return oss.str();
}

// ===== IPv4 HEADER =====
string IPv4Header::toString() const {
    ostringstream oss;
    oss << "--- IP Header ---\n";
    oss << "Versão: IPv" << (int)version << "\n";
    oss << "IP Origem: " << srcIP << "\n";
    oss << "IP Destino: " << dstIP << "\n";
    oss << "TTL: " << (int)ttl << "\n";
    oss << "Protocolo: " << (int)protocol;
    return oss.str();
}

// ===== IPv6 HEADER =====
string IPv6Header::toString() const {
    ostringstream oss;
    oss << "--- IP Header ---\n";
    oss << "Versão: IPv6\n";
    oss << "IP Origem: " << srcIP << "\n";
    oss << "IP Destino: " << dstIP << "\n";
    oss << "TTL: " << (int)ttl << "\n";
    oss << "Protocolo: " << (int)protocol;
    return oss.str();
}

// ===== TCP HEADER =====
string TCPHeader::getFlagsString() const {
    ostringstream oss;
    bool first = true;
    
    if (hasFIN()) { oss << "FIN"; first = false; }
    if (hasSYN()) { if (!first) oss << " "; oss << "SYN"; first = false; }
    if (hasRST()) { if (!first) oss << " "; oss << "RST"; first = false; }
    if (hasPUSH()) { if (!first) oss << " "; oss << "PUSH"; first = false; }
    if (hasACK()) { if (!first) oss << " "; oss << "ACK"; first = false; }
    if (hasURG()) { if (!first) oss << " "; oss << "URG"; first = false; }
    
    if (first) oss << "NENHUMA";
    
    return oss.str();
}

string TCPHeader::toString() const {
    ostringstream oss;
    oss << "--- TCP Header ---\n";
    oss << "Porta Origem: " << srcPort << "\n";
    oss << "Porta Destino: " << dstPort << "\n";
    oss << "Sequence Number: " << seqNumber << "\n";
    oss << "Acknowledgment Number: " << ackNumber << "\n";
    oss << "Flags: " << getFlagsString();
    return oss.str();
}

// ===== UDP HEADER =====
string UDPHeader::toString() const {
    ostringstream oss;
    oss << "--- UDP Header ---\n";
    oss << "Porta Origem: " << srcPort << "\n";
    oss << "Porta Destino: " << dstPort << "\n";
    oss << "Tamanho: " << length << " bytes";
    return oss.str();
}

// ===== ICMP HEADER =====
string ICMPHeader::toString() const {
    ostringstream oss;
    oss << "--- ICMP Header ---\n";
    oss << "Protocolo: ICMP";
    return oss.str();
}

// ===== PACKET =====
string Packet::getSummary() const {
    ostringstream oss;
    
    // Resumo básico
    if (hasIPHeader() && hasTransportHeader()) {
        oss << ipHeader->getSrcIP() << ":" << transportHeader->getSrcPort() 
            << " -> " 
            << ipHeader->getDstIP() << ":" << transportHeader->getDstPort()
            << " [" << transportHeader->getProtocolName() << "]";
    } else if (hasIPHeader()) {
        oss << ipHeader->getSrcIP() << " -> " << ipHeader->getDstIP()
            << " [" << ipHeader->getVersionString() << "]";
    } else if (hasEthernetHeader()) {
        oss << ethernetHeader->getSrcMac() << " -> " << ethernetHeader->getDstMac()
            << " [" << ethernetHeader->getEtherTypeString() << "]";
    } else {
        oss << "Pacote sem headers identificados";
    }
    
    return oss.str();
}

string Packet::getDetailedInfo() const {
    ostringstream oss;
    
    oss << "\n========== PACOTE CAPTURADO ==========\n";
    
    // Metadados
    oss << "Timestamp: " << timestamp.tv_sec << "." << timestamp.tv_nsec << "\n";
    oss << "Tamanho capturado: " << capturedLength << " bytes\n";
    oss << "Tamanho real: " << actualLength << " bytes\n";
    
    // Ethernet Header
    if (hasEthernetHeader()) {
        oss << "\n" << ethernetHeader->toString() << "\n";
    }
    
    // IP Header
    if (hasIPHeader()) {
        oss << "\n" << ipHeader->toString() << "\n";
    }
    
    // Transport Header
    if (hasTransportHeader()) {
        oss << "\n" << transportHeader->toString() << "\n";
    }
    
    oss << "======================================\n";
    
    return oss.str();
}

