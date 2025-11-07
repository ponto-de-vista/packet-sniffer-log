#include "analyser.hpp" // Inclui o header da própria classe
#include <iostream>     // Inclui o iostream aqui
using namespace std;

Analyser::Analyser(string dev)
{
    device = dev;
    cout << "Analisador de pacotes!" << "\n";
}
