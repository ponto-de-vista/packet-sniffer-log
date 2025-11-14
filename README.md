# Analisador de Pacotes

Um sniffer de pacotes de rede desenvolvido em C++ que captura e analisa tráfego de rede em tempo real.

## Arquitetura

**função main:**
- Inicia o tempo em 0
- Exibe o intervalo entre cada print da linha
- Exibe o pacote juntamente com o tempo

**Analisador (Classe):**
- Método para receber pacotes
- Device name
- Device description

**Pacote (Classe):**
- Campo para dados
- Campo para cabeçalhos (demais informações como endereço e destino)

**ConversorDePacote (Classe):**
- Utilizada pela classe Pacote
- Campo para converter bytes para os endereços IPs

## Requisitos e Instalação no Linux

### 1. Instalar Dependências

Primeiro, instale os compiladores e ferramentas necessárias:

```bash
# Atualizar lista de pacotes
sudo apt update

# Instalar compilador C++, CMake e ferramentas de build
sudo apt install -y build-essential g++ cmake pkg-config

# Instalar biblioteca libpcap para captura de pacotes
sudo apt install -y libpcap-dev
```

### 2. Verificar Instalação

Verifique se tudo foi instalado corretamente:

```bash
g++ --version      # Deve mostrar GCC 9.0 ou superior
cmake --version    # Deve mostrar CMake 3.10 ou superior
pkg-config --version
```

## Compilação

### Método 1: Com CMake (Recomendado)

```bash
# 1. Configurar o projeto (executar apenas uma vez)
cmake --preset linux-debug

# 2. Compilar o projeto
cmake --build --preset linux-debug
```

O executável será gerado em: `./out/build/linux-debug/PacketSniffer`

### Método 2: Compilação Manual (apenas main.cpp)

```bash
g++ -o main ./src/main.cpp -lpcap
```

## Execução

Para executar o programa, é necessário usar `sudo` porque a captura de pacotes requer privilégios de superusuário para acessar as interfaces de rede:

```bash
# Executar o sniffer de pacotes
sudo ./out/build/linux-debug/PacketSniffer
```

**Nota:** O programa precisa de permissões root para escutar todos os dispositivos de rede.

## Bibliotecas Utilizadas

- **Linux:** libpcap - Biblioteca para captura de pacotes de rede
- **Windows:** Npcap - Versão Windows da libpcap

## Requisitos do Sistema

- **Sistema Operacional:** Linux (Ubuntu, Debian, Fedora, etc.) ou Windows
- **Compilador:** GCC 9.0+ com suporte a C++17
- **CMake:** Versão 3.10 ou superior
- **Biblioteca:** libpcap (Linux) ou Npcap (Windows)