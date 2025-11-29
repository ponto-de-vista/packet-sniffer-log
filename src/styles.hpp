#ifndef STYLES_HPP
#define STYLES_HPP

#include <QString>

class Styles
{
    public:
        static QString buttonAnalyzeStyle()
        {
            return "QPushButton { "
                "    font-size: 14px; "
                "    background-color: #00AA00; "
                "    color: white; "
                "    padding: 5px; "
                "    border-radius: 5px; "
                "    border: none; "
                "} "
                "QPushButton:hover { "
                "    background-color: #00DD00; "
                "} "
                "QPushButton:pressed { "
                "    background-color: #008800; "
                "}";
        }

        static QString buttonStopStyle()
        {
            return "QPushButton { "
                "    font-size: 14px; "
                "    background-color: #FF0000; "
                "    color: white; "
                "    padding: 5px; "
                "    border-radius: 5px; "
                "    border: none; "
                "} "
                "QPushButton:hover { "
                "    background-color: #FF3333; "
                "} "
                "QPushButton:pressed { "
                "    background-color: #CC0000; "
                "}";
        }

        static QString titleStyle()
        {
            return "font-size: 24px; font-weight: bold;";
        }
};

#endif