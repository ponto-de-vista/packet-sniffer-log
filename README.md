# Analisador de Pacotes

função main:

-> inicia o tempo em 0.

-> exibe o intervalo entre cada print da liha, 

-> exibe o pacote juntamente com o tempo.

--------------------------

-> Analisador (Classe), metodo para receber pacotes

-> device name

-> device description

------------------------

-> Pacote (Classe)

-> Campo para dados

-> Campo para cabeçalhos (demais informações como endereço e destino)

----------------------------

-> ConversorDePacote (Classe), vai ser utilizada pela classe 
Pacote

-> Campo para converter bytes para os endereços IPs

-----------------------------

Bibliotecas: 

-> Linux: libpcap (sudo apt install libpcap-dev)

-> Windows: npcap

-----------------------------

-> (COM CMAKE) Criar pasta de build e compila, gerando o executavel

```
cmake --build --preset linux-debug
```

-> (SEM CMAKE) Gera o build e compila somente a main.cpp

```
g++ -o main ./src/main.cpp
```

------------------------------

Executar o programa no linux:

(Utilizar "sudo" porque precisa de permissão para escutar todos os dispositivos)

```
sudo ./out/build/linux-debug/PacketSniffer
```