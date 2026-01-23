#include <QApplication>
#include <QTranslator>
#include <QLocale>
#include "MainWindow.h"

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    
    app.setApplicationName("ECH Workers");
    app.setApplicationVersion("1.0.0");
    app.setOrganizationName("ECH Workers");
    
    MainWindow window;
    window.show();
    
    return app.exec();
}
