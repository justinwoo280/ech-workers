#include <QApplication>
#include <QTranslator>
#include <QLocale>
#include <QLocalSocket>
#include <QLocalServer>
#include <QMessageBox>
#include <QIcon>
#include "MainWindow.h"

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    
    app.setApplicationName("ECH Workers");
    app.setApplicationVersion("1.0.0");
    app.setOrganizationName("ECH Workers");
    
    // 设置应用程序图标
    app.setWindowIcon(QIcon(":/icons/logo.ico"));
    
    // 防止重复开启
    QString socketName = "ECHWorkersGUI_SingleInstance";
    QLocalSocket socket;
    socket.connectToServer(socketName);
    
    if (socket.waitForConnected(500)) {
        // 已经有实例在运行，发送消息并退出
        QMessageBox::information(nullptr, "ECH Workers", 
            "程序已经在运行中，请检查系统托盘。");
        return 0;
    }
    
    // 创建本地服务器防止重复启动
    QLocalServer server;
    if (!server.listen(socketName)) {
        QMessageBox::critical(nullptr, "错误", 
            "无法启动单实例服务器: " + server.errorString());
        return 1;
    }
    
    MainWindow window;
    window.show();
    
    return app.exec();
}
