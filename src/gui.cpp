#include "gui.hpp"
#include <iostream>

using namespace std;

GUI::GUI() 
{
    this->window.setWindowTitle("Analisador de Pacotes");
    this->window.setMinimumSize(800, 800);
    this->window.setMaximumSize(800, 800);

    QLabel *titleLabel = new QLabel("Analisador de Pacotes");

    titleLabel->setStyleSheet("font-size: 24px; font-weight: bold;");

    QPushButton *button = new QPushButton("Analisar!");

    this->layout = new QVBoxLayout(&window);

    this->tableWidget = new QTableWidget(this);

    this->tableWidget->setColumnCount(2);
    this->tableWidget->setHorizontalHeaderLabels({"Origem", "Dest"});
    this->tableWidget->resizeColumnsToContents();

    this->tableWidget->setFixedWidth(700);
    this->tableWidget->setFixedHeight(600);
    
    // Layout
    layout->addStretch(1); 
    layout->addWidget(titleLabel, 0, Qt::AlignHCenter);
    layout->addWidget(tableWidget, 0, Qt::AlignHCenter);

    layout->addStretch(1);

    window.show();
}

void GUI::insertRow(vector<string> packets) 
{
    int row = this->tableWidget->rowCount();

    if (row < 2)
    {
        this->tableWidget->insertRow(row);

        QTableWidgetItem *origemItem = new QTableWidgetItem(QString::fromStdString(packets[0]));
        QTableWidgetItem *destItem = new QTableWidgetItem(QString::fromStdString(packets[1]));

        this->tableWidget->setItem(row, 0, origemItem);
        this->tableWidget->setItem(row, 1, destItem);
    }
}

GUI::~GUI() 
{
    cout << "Fechando.";
}