#include "analyser.hpp"
#include <iostream>  // Contém classes para input e output, como o 'cout'
using namespace std; // Permite utilizar as classes diretamente, sem precisar de 'std::cout'

int main(void)
{
    //std::string device = "\\Device\\NPF_{4A03F203-76CC-40A6-AED1-6F255E028E81}";
    std::string device = "any";

    try {
        Analyser sniffer(device);
        
        if (!sniffer.startCapture()) {
            std::cerr << "Falha ao iniciar a captura." << std::endl;
            return 1;
        }

    } catch (const std::exception& e) {
        std::cerr << "Exceção: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}