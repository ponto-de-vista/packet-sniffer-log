#include "sniffer.hpp"
#include "gui.hpp"
#include <iostream>  // Contém classes para input e output, como o 'cout'
#include <QApplication>
#include <iostream>
using namespace std;

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    GUI* ui = new GUI();
    app.exec();
  
    cout << "=== PACKET SNIFFER ===" << endl;
    cout << "Bem-vindo ao analisador de pacotes de rede!\n" << endl;

    try {
        // Método 1: Seleção interativa (recomendado)
        string device = Sniffer::selectDeviceInteractive();
        
        if (device.empty()) {
            cerr << "Nenhum dispositivo selecionado. Encerrando..." << endl;
            return 1;
        }
        
        // Cria o sniffer com o dispositivo selecionado
        Sniffer sniffer(device, ui);
        
        // Inicia a captura
        if (!sniffer.startCapture()) {
            cerr << "Falha ao iniciar a captura." << endl;
            return 1;
        }

    } catch (const exception& e) {
        cerr << "Exceção: " << e.what() << endl;
        return 1;
    }
    
    return 0;
}