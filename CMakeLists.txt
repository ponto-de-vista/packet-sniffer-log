cmake_minimum_required(VERSION 3.10.0)
project(PacketSniffer VERSION 0.1.0 LANGUAGES C CXX)

include(CTest)
enable_testing()

add_executable(PacketSniffer ./src/main.cpp)

set_property(TARGET PacketSniffer PROPERTY CXX_STANDARD 17)

if(WIN32)
    # --- Configuração do Windows (Npcap) ---
    message(STATUS "Configurando para Windows (Npcap)")

    # Define uma macro para seu código C++ (ex: #ifdef PCAP_ON_WINDOWS)
    target_compile_definitions(PacketSniffer PRIVATE PCAP_ON_WINDOWS)

    # Usa o módulo FindPcap padrão do CMake.
    # NOTA: Isso requer que o "Npcap SDK" esteja instalado!
    find_package(Pcap REQUIRED)

    # Adiciona os diretórios de include do Npcap ao seu alvo
    target_include_directories(PacketSniffer PRIVATE ${PCAP_INCLUDE_DIR})

    # Linka as bibliotecas do Npcap (e a biblioteca de sockets do Windows)
    target_link_libraries(PacketSniffer PRIVATE ${PCAP_LIBRARY} ws2_32)

else()
    # --- Configuração do Linux (libpcap) ---
    message(STATUS "Configurando para Linux (libpcap)")

    # Usa pkg-config para encontrar libpcap (padrão no Linux)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(PCAP REQUIRED libpcap) # Procura por 'pcap'

    # Adiciona os diretórios de include do libpcap
    target_include_directories(PacketSniffer PRIVATE ${PCAP_INCLUDE_DIRS})

    # Linka a biblioteca libpcap
    target_link_libraries(PacketSniffer PRIVATE ${PCAP_LIBRARIES})

endif()