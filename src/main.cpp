#include "gui.hpp"
#include <QApplication>
using namespace std;

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    GUI* ui = new GUI();
    app.exec();
    return 0;
}