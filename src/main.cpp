#include "gui.hpp"
#include <QApplication>
#include <QProcess>
#include <unistd.h>
#include <iostream>

using namespace std;

int main(int argc, char *argv[])
{
    if (getuid() != 0) 
    {
        QProcess process;
        QStringList args;
        args << "-E" << "-S" << argv[0];
        
        process.setProcessChannelMode(QProcess::ForwardedChannels);
        process.start("sudo", args);
        process.waitForFinished(-1);
        return 0;
    }

    QApplication app(argc, argv);
    GUI* ui = new GUI();
    app.exec();
    return 0;
}