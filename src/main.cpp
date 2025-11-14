#include "sniffer.hpp"
#include <iostream>  // Contém classes para input e output, como o 'cout'
#include <QApplication>
#include <QWidget>
#include <QPushButton>
#include <QLabel>
#include <QVBoxLayout>

using namespace std; // Permite utilizar as classes diretamente, sem precisar de 'std::cout'

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    QWidget window;

    window.setWindowTitle("Analisador de Pacotes");
    window.setMinimumSize(500, 500);
    window.setMaximumSize(500, 500);

    QLabel *titleLabel = new QLabel("Analisador de Pacotes");

    titleLabel->setStyleSheet("font-size: 24px; font-weight: bold;");

    QPushButton *button = new QPushButton("Analisar!");
    QVBoxLayout *layout = new QVBoxLayout(&window);

    layout->addStretch(1); 
    layout->addWidget(titleLabel, 0, Qt::AlignHCenter);
    layout->addWidget(button, 0, Qt::AlignHCenter);
    layout->addStretch(1);

    window.show();

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
        Sniffer sniffer(device);
        
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