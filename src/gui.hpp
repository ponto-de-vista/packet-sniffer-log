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
        Sniffer *analisador;
        QWidget window;
        QVBoxLayout *layout;
        QTableWidget *table_widget;
        int window_size = 800;
        std::string device_selected;
        bool has_started = false;

    public:
        GUI();
        ~GUI();

    public slots:
        void updateTable(QString src, QString dst, QString protocol, int length);
};

#endif
