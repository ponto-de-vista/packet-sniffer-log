#include <iostream>  // Contém classes para input e output, como o 'cout'
#include "analyser.hpp"
using namespace std; // Permite utilizar as classes diretamente, sem precisar de 'std::cout'

int main(void)
{
    cout << "Olá" << "\n"; // << eh um operador de inserção. Envia dados da direita para o objeto na esquerda.
    Analyser my_obj("eth0");
    return 0;
}