#include "gui.hpp"
#include "styles.hpp"
#include <iostream>
#include <QHeaderView>
#include <QComboBox>
#include <QLabel>
#include <QPushButton>
#include <QVBoxLayout>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QString>

using namespace std;

GUI::GUI()
{
    QLabel *title_label = new QLabel("Analisador de Pacotes");
    title_label->setStyleSheet(Styles::titleStyle());

    QPushButton *button = new QPushButton("Analisar!");
    button->setStyleSheet(Styles::buttonAnalyzeStyle());

    QObject::connect(button, &QPushButton::clicked, this, [this, button]() 
    {
        if (this->has_started)
        {
            this->has_started = false;
            button->setText("Analisar!");
            button->setStyleSheet(Styles::buttonAnalyzeStyle());

            
            if (this->analisador) 
            {
                this->analisador->disconnect();
                this->analisador->stopCapture();
                delete this->analisador;
                this->analisador = nullptr;
            }
        }
        else
        {
            this->table_widget->setRowCount(0);

            this->has_started = true;
            button->setText("Parar");
            button->setStyleSheet(Styles::buttonStopStyle());

            this->analisador = new Sniffer(this->device_selected);

            QObject::connect(this->analisador, &Sniffer::packetCaptured, this, &GUI::updateTable);

            this->analisador->startCapture();
        }
    });

    /*
        TABELA
    */

    this->table_widget = new QTableWidget(this);
    this->table_widget->setColumnCount(4);
    this->table_widget->setHorizontalHeaderLabels({"Origem", "Dest", "Protocolo", "Tamanho"});
    this->table_widget->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    this->table_widget->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    this->table_widget->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
    this->table_widget->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
    this->table_widget->setFixedWidth(700);
    this->table_widget->setFixedHeight(600);

    /*
        SELETOR DE DISPOSITIVOS
    */

    QComboBox *device_combo = new QComboBox(this);
    this->device_selected = "";

    vector<NetworkDevice> all_devices = Sniffer::listAvailableDevices();

    for (const auto &device : all_devices) 
    {
        device_combo->addItem(QString::fromStdString(device.name));
    }

    if (!all_devices.empty())
    {
        this->device_selected = all_devices[0].name;
        device_combo->setCurrentIndex(0);
    }

    QObject::connect(
        device_combo, 
        QOverload<const QString &>::of(&QComboBox::currentTextChanged),
        this, 
        [this](const QString &text) 
        {
            this->device_selected = text.toStdString();
            this->window.setWindowTitle(QString("Analisador de pacotes: ") + text);
        }
    );

    /*
        INSERE OS COMPONENTES VISUAIS
    */

    this->window.setMinimumSize(800, 800);
    this->window.setMaximumSize(800, 800);

    this->layout = new QVBoxLayout(&window);
    this->layout->addWidget(title_label, 0, Qt::AlignHCenter);
    this->layout->addWidget(device_combo, 0, Qt::AlignHCenter);
    this->layout->addWidget(button, 0, Qt::AlignHCenter);
    this->layout->addWidget(table_widget, 0, Qt::AlignHCenter);
    this->window.show();
}

void GUI::updateTable(QString src, QString dst, QString protocol, int length) 
{
    int row = this->table_widget->rowCount();
    this->table_widget->insertRow(row);

    QTableWidgetItem *srcItem = new QTableWidgetItem(src);
    QTableWidgetItem *dstItem = new QTableWidgetItem(dst);
    QTableWidgetItem *protoItem = new QTableWidgetItem(protocol);
    QTableWidgetItem *lenItem = new QTableWidgetItem(QString::number(length));

    this->table_widget->setItem(row, 0, srcItem);
    this->table_widget->setItem(row, 1, dstItem);
    this->table_widget->setItem(row, 2, protoItem);
    this->table_widget->setItem(row, 3, lenItem);
}

GUI::~GUI() 
{
    cout << "Fechando.";
}