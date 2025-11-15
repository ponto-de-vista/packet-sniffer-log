#ifndef GUI_HPP
#define GUI_HPP

#include "sniffer.hpp"
#include <QApplication>
#include <QWidget>
#include <QPushButton>
#include <QLabel>
#include <QVBoxLayout>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QMainWindow>

class GUI : public QMainWindow
{
    private:
        Sniffer *sniffer;
        QWidget window;
        QVBoxLayout *layout;
        QTableWidget *tableWidget;
        int window_size = 800;

    public:
        GUI();
        ~GUI();
        void insertRow(std::vector<std::string> packets);
};

#endif
