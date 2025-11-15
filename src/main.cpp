#include "sniffer.hpp"
#include "gui.hpp"
#include <iostream>  // Contém classes para input e output, como o 'cout'
#include <QApplication>

using namespace std; // Permite utilizar as classes diretamente, sem precisar de 'std::cout'

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    GUI* ui = new GUI();
    app.exec();
    
    return 0;
}