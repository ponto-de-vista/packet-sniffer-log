#ifndef PACKET_HPP
#define PACKET_HPP

#include <string>
#include <memory>
#include <ctime>
#include <vector>
#include <sstream>

// ===== CAMADA ETHERNET (Layer 2) =====
class EthernetHeader 
{
    private:
        std::string srcMac;
        std::string dstMac;
        uint16_t etherType;

    public:
        EthernetHeader(const std::string& src, const std::string& dst, uint16_t type)
            : srcMac(src), dstMac(dst), etherType(type) {}
        
        std::string getSrcMac() const { return srcMac; }
        std::string getDstMac() const { return dstMac; }
        uint16_t getEtherType() const { return etherType; }
        std::string getEtherTypeString() const;
        
        std::string toString() const;
};

// ===== CAMADA IP (Layer 3) - ABSTRATA =====
class IPHeader 
{
    protected:
        std::string srcIP;
        std::string dstIP;
        uint8_t protocol;
        uint8_t ttl;

    public:
        IPHeader(const std::string& src, const std::string& dst, uint8_t proto, uint8_t t)
            : srcIP(src), dstIP(dst), protocol(proto), ttl(t) {}
        
        virtual ~IPHeader() = default;
        
        std::string getSrcIP() const { return srcIP; }
        std::string getDstIP() const { return dstIP; }
        uint8_t getProtocol() const { return protocol; }
        uint8_t getTTL() const { return ttl; }
        
        virtual std::string toString() const = 0; // Método virtual puro
        virtual std::string getVersionString() const = 0;
};

// IPv4 específico
class IPv4Header : public IPHeader 
{
    private:
        uint8_t version;
        uint16_t identification;

    public:
        IPv4Header(const std::string& src, const std::string& dst, 
                uint8_t proto, uint8_t ttl, uint8_t ver, uint16_t id)
            : IPHeader(src, dst, proto, ttl), version(ver), identification(id) {}
        
        uint8_t getVersion() const { return version; }
        std::string getVersionString() const override { return "IPv4"; }
        std::string toString() const override;
};

// IPv6 (para futuro)
class IPv6Header : public IPHeader 
{
    public:
        IPv6Header(const std::string& src, const std::string& dst, uint8_t proto, uint8_t ttl)
            : IPHeader(src, dst, proto, ttl) {}
        
        std::string getVersionString() const override { return "IPv6"; }
        std::string toString() const override;
};

// ===== CAMADA TRANSPORTE (Layer 4) - ABSTRATA =====
class TransportHeader 
{
    protected:
        uint16_t srcPort;
        uint16_t dstPort;

    public:
        TransportHeader(uint16_t src, uint16_t dst) : srcPort(src), dstPort(dst) {}
        
        virtual ~TransportHeader() = default;
        
        uint16_t getSrcPort() const { return srcPort; }
        uint16_t getDstPort() const { return dstPort; }
        
        virtual std::string toString() const = 0;
        virtual std::string getProtocolName() const = 0;
};

// TCP específico
class TCPHeader : public TransportHeader 
{
    private:
        uint32_t seqNumber;
        uint32_t ackNumber;
        uint8_t flags;

    public:
        TCPHeader(uint16_t src, uint16_t dst, uint32_t seq, uint32_t ack, uint8_t f)
            : TransportHeader(src, dst), seqNumber(seq), ackNumber(ack), flags(f) {}
        
        uint32_t getSeqNumber() const { return seqNumber; }
        uint32_t getAckNumber() const { return ackNumber; }
        uint8_t getFlags() const { return flags; }
        
        bool hasFIN() const { return flags & 0x01; }
        bool hasSYN() const { return flags & 0x02; }
        bool hasRST() const { return flags & 0x04; }
        bool hasPUSH() const { return flags & 0x08; }
        bool hasACK() const { return flags & 0x10; }
        bool hasURG() const { return flags & 0x20; }
        
        std::string getFlagsString() const;
        std::string getProtocolName() const override { return "TCP"; }
        std::string toString() const override;
};

// UDP específico
class UDPHeader : public TransportHeader 
{
    private:
        uint16_t length;

    public:
        UDPHeader(uint16_t src, uint16_t dst, uint16_t len)
            : TransportHeader(src, dst), length(len) {}
        
        uint16_t getLength() const { return length; }
        std::string getProtocolName() const override { return "UDP"; }
        std::string toString() const override;
};

// ICMP
class ICMPHeader : public TransportHeader 
{
    public:
        ICMPHeader() : TransportHeader(0, 0) {}
        
        std::string getProtocolName() const override { return "ICMP"; }
        std::string toString() const override;
};

// ===== CLASSE PACKET COMPLETA =====
class Packet 
{
    private:
        // Metadados do pacote
        timespec timestamp;
        uint32_t capturedLength;
        uint32_t actualLength;
        
        // Camadas (usando smart pointers)
        std::unique_ptr<EthernetHeader> ethernetHeader;
        std::unique_ptr<IPHeader> ipHeader;
        std::unique_ptr<TransportHeader> transportHeader;
        
        // Dados brutos (opcional, para análise profunda)
        std::vector<uint8_t> rawData;

    public:
        Packet() : capturedLength(0), actualLength(0) 
        {
            timestamp.tv_sec = 0;
            timestamp.tv_nsec = 0;
        }
        
        // Setters para as camadas
        void setEthernetHeader(std::unique_ptr<EthernetHeader> header) 
        {
            ethernetHeader = std::move(header);
        }
        
        void setIPHeader(std::unique_ptr<IPHeader> header) 
        {
            ipHeader = std::move(header);
        }
        
        void setTransportHeader(std::unique_ptr<TransportHeader> header) 
        {
            transportHeader = std::move(header);
        }
        
        void setTimestamp(timespec ts) { timestamp = ts; }
        void setCapturedLength(uint32_t len) { capturedLength = len; }
        void setActualLength(uint32_t len) { actualLength = len; }
        void setRawData(const uint8_t* data, uint32_t len) {
            rawData.assign(data, data + len);
        }
        
        // Getters
        const EthernetHeader* getEthernetHeader() const { return ethernetHeader.get(); }
        const IPHeader* getIPHeader() const { return ipHeader.get(); }
        const TransportHeader* getTransportHeader() const { return transportHeader.get(); }
        
        timespec getTimestamp() const { return timestamp; }
        uint32_t getCapturedLength() const { return capturedLength; }
        uint32_t getActualLength() const { return actualLength; }
        const std::vector<uint8_t>& getRawData() const { return rawData; }
        
        // Métodos auxiliares
        bool hasEthernetHeader() const { return ethernetHeader != nullptr; }
        bool hasIPHeader() const { return ipHeader != nullptr; }
        bool hasTransportHeader() const { return transportHeader != nullptr; }
        
        std::string getSummary() const;
        std::string getDetailedInfo() const;
};

#endif

