# FioTubarão - Analisador de Tráfego de Rede

O **FioTubarão** é um *Sniffer* de pacotes de rede desenvolvido em C++ moderno (C++17), utilizando o framework Qt 6 para a interface gráfica. O software captura, decodifica e visualiza o tráfego de rede em tempo real, aplicando conceitos de Orientação a Objetos, Gerenciamento de Memória e Concorrência.

**Disciplina:** Programação Orientada a Objetos

**Autor:** Bryan Pinheiro de Souza - bryanpinheiro@unisantos.br;

**Autor:** Fernando Costa Okada Ferreira - fernandocosta@unisantos.br;

**Autor:** Lucas Athayde - lucas.athayde@unisantos.br;

## Arquitetura do Sistema

O projeto adota uma arquitetura orientada a eventos, separando a lógica de captura (pcap) da interface de apresentação (Qt framework).

### Diagrama de Classes e Fluxo

```mermaid
classDiagram
    class GUI {
        +GUI()
        +~GUI()
        +updateTable(QString src, QString dst, QString protocol, int length)
        -Sniffer *analisador
        -QWidget window
        -QVBoxLayout *layout
        -QTableWidget *table_widget
        -int window_size
        -std::string device_selected
        -bool has_started
    }

    class Sniffer {
        +Sniffer(std::string device, QObject *parent)
        +~Sniffer()
        +startCapture()
        +stopCapture()
        +static std::vector<NetworkDevice> listAvailableDevices()
        +static std::string selectDeviceInteractive()
        -std::string deviceName
        -pcap_t* handle
        -char errbuf[PCAP_ERRBUF_SIZE]
        -bool capturing
        -std::thread captureThread
        -std::atomic<bool> shouldStop
        -Packet buildPacket(const struct pcap_pkthdr* header, const u_char* packetData)
        -std::unique_ptr<EthernetHeader> parseEthernetHeader(const u_char* data)
        -std::unique_ptr<IPHeader> parseIPHeader(const u_char* data, uint16_t etherType, int& ipHeaderLen)
        -std::unique_ptr<TransportHeader> parseTransportHeader(const u_char* data, uint8_t protocol, int ipHeaderLen)
        -static void staticCallback(u_char* user, const struct pcap_pkthdr* header, const u_char* packetData)
        -void captureLoop()
        -- Signals --
        +packetCaptured(QString src, QString dst, QString protocol, int length)
    }

    class Packet {
        +Packet()
        +setEthernetHeader(std::unique_ptr<EthernetHeader> header)
        +setIPHeader(std::unique_ptr<IPHeader> header)
        +setTransportHeader(std::unique_ptr<TransportHeader> header)
        +setTimestamp(timespec ts)
        +setCapturedLength(uint32_t len)
        +setActualLength(uint32_t len)
        +setRawData(const uint8_t* data, uint32_t len)
        +getEthernetHeader()
        +getIPHeader()
        +getTransportHeader()
        +getTimestamp()
        +getCapturedLength()
        +getActualLength()
        +getRawData()
        +hasEthernetHeader()
        +hasIPHeader()
        +hasTransportHeader()
        +getSummary()
        +getDetailedInfo()
        -timespec timestamp
        -uint32_t capturedLength
        -uint32_t actualLength
        -std::unique_ptr<EthernetHeader> ethernetHeader
        -std::unique_ptr<IPHeader> ipHeader
        -std::unique_ptr<TransportHeader> transportHeader
        -std::vector<uint8_t> rawData
    }

    class EthernetHeader {
        +EthernetHeader(const std::string& src, const std::string& dst, uint16_t type)
        +getSrcMac()
        +getDstMac()
        +getEtherType()
        +getEtherTypeString()
        +toString()
        -std::string srcMac
        -std::string dstMac
        -uint16_t etherType
    }

    class IPHeader {
        +IPHeader(const std::string& src, const std::string& dst, uint8_t proto, uint8_t t)
        +~IPHeader()
        +getSrcIP()
        +getDstIP()
        +getProtocol()
        +getTTL()
        +toString()*
        +getVersionString()*
        #std::string srcIP
        #std::string dstIP
        #uint8_t protocol
        #uint8_t ttl
    }

    class IPv4Header {
        +IPv4Header(const std::string& src, const std::string& dst, uint8_t proto, uint8_t ttl, uint8_t ver, uint16_t id)
        +getVersion()
        +getVersionString()
        +toString()
        -uint8_t version
        -uint16_t identification
    }

    class IPv6Header {
        +IPv6Header(const std::string& src, const std::string& dst, uint8_t proto, uint8_t ttl)
        +getVersionString()
        +toString()
    }

    class TransportHeader {
        +TransportHeader(uint16_t src, uint16_t dst)
        +~TransportHeader()
        +getSrcPort()
        +getDstPort()
        +toString()*
        +getProtocolName()*
        #uint16_t srcPort
        #uint16_t dstPort
    }

    class TCPHeader {
        +TCPHeader(uint16_t src, uint16_t dst, uint32_t seq, uint32_t ack, uint8_t f)
        +getSeqNumber()
        +getAckNumber()
        +getFlags()
        +hasFIN()
        +hasSYN()
        +hasRST()
        +hasPUSH()
        +hasACK()
        +hasURG()
        +getFlagsString()
        +getProtocolName()
        +toString()
        -uint32_t seqNumber
        -uint32_t ackNumber
        -uint8_t flags
    }

    class UDPHeader {
        +UDPHeader(uint16_t src, uint16_t dst, uint16_t len)
        +getLength()
        +getProtocolName()
        +toString()
        -uint16_t length
    }

    class ICMPHeader {
        +ICMPHeader()
        +getProtocolName()
        +toString()
    }
    
    class Styles {
        +buttonAnalyzeStyle()
        +buttonStopStyle()
        +titleStyle()
    }

    GUI "1" o-- "1" Sniffer : Instancia
    GUI ..> Styles : Usa
    Sniffer ..> Packet : Cria e Popula
    Sniffer ..> GUI : Emite Sinal (packetCaptured)
    Packet *-- EthernetHeader : Contém
    Packet *-- IPHeader : Contém
    Packet *-- TransportHeader : Contém
    IPv4Header --|> IPHeader : Herda
    IPv6Header --|> IPHeader : Herda
    TCPHeader --|> TransportHeader : Herda
    UDPHeader --|> TransportHeader : Herda
    ICMPHeader --|> TransportHeader : Herda
```

### Detalhamento dos Módulos (OOP)

#### 1\. Entry Point (`main.cpp`)

Responsável pelo **Bootstrap** da aplicação. Implementa um mecanismo de auto-elevação de privilégios:

  - Verifica o UID do processo (`getuid()`).
  - Caso não seja *root*, reinicia a aplicação utilizando `pkexec` (Linux), preservando variáveis de ambiente gráfico como `DISPLAY`.

#### 2\. Controlador de Captura (`sniffer.hpp` / `.cpp`)

Atua como um **Wrapper** orientado a objetos sobre a biblioteca `libpcap`.

  - **Multithreading:** Executa o loop de captura (`pcap_loop`) em uma `std::thread` dedicada, evitando o congelamento da interface gráfica.
  - **Sinais e Slots:** Herda de `QObject` para emitir **sinais assíncronos** (`packetCaptured`) à GUI sempre que um pacote é processado.
  - **Parsing:** Contém a lógica de conversão de dados brutos (`u_char*`) para objetos estruturados.

#### 3\. Modelo de Dados (`packet.hpp` / `.cpp`)

Representa a entidade do pacote capturado, utilizando **Polimorfismo** e **Composição** para mapear as camadas do Modelo OSI:

  - **Gerenciamento de Memória:** Utiliza `std::unique_ptr` para garantir que a memória dos cabeçalhos (Ethernet, IPv4, TCP/UDP) seja alocada e liberada automaticamente.
  - **Abstração:** Classes base abstratas (`IPHeader`, `TransportHeader`) permitem tratamento genérico de diferentes protocolos (ex: TCP e UDP herdam de TransportHeader).

#### 4\. Interface Gráfica (`gui.hpp` / `.cpp`)

Desenvolvida com o framework **Qt6**.

  - **Slots:** O método `updateTable` recebe os dados da thread de captura e atualiza a `QTableWidget` de forma thread-safe (o Qt gerencia a fila de eventos entre threads).

-----

## Requisitos de Sistema

  * **Linguagem:** C++17
  * **Framework:** Qt 6 (Componente Widgets)
  * **Build System:** CMake 3.10+
  * **Bibliotecas de Captura:**
      * **Linux:** `libpcap`
      * **Windows:** `Npcap`

### Instalação das Dependências (Debian/Ubuntu/WSL)

```bash
sudo apt update
sudo apt install -y build-essential g++ cmake pkg-config
sudo apt install -y libpcap-dev
sudo apt install -y qt6-base-dev libgl1-mesa-dev libxkbcommon-dev
```

-----

## Compilação e Build

Este projeto utiliza **CMake Presets** para simplificar a configuração em diferentes ambientes.

### Linux / WSL

```bash
# 1. Configurar o projeto (Gera os Makefiles)
cmake --preset linux-debug

# 2. Compilar o binário
cmake --build --preset linux-debug
```

### Windows (Visual Studio 2022)

```bash
cmake --preset windows-debug
cmake --build --preset windows-debug
```

-----

## Como Executar

O executável final é gerado dentro da pasta `out/build`. A captura de pacotes exige acesso direto à placa de rede, portanto, **privilégios de administrador são necessários**.

```bash
# Executar no Linux/WSL
sudo ./out/build/linux-debug/PacketSniffer
```
-----

## Estrutura de Arquivos

  * `src/main.cpp`: Ponto de entrada, checagem de root e inicialização do Qt.
  * `src/sniffer.cpp`: Lógica de conexão com o hardware de rede e loop de captura.
  * `src/packet.cpp`: Definição das classes de cabeçalhos (Ethernet, IP, TCP, UDP) e formatação de strings.
  * `src/gui.cpp`: Construção da janela, tabela e botões.
  * `src/styles.hpp`: Definições de CSS (Qt Style Sheets) para a interface.
  * `CMakeLists.txt`: Script de configuração de compilação, embora testado somente no linux.

-----
