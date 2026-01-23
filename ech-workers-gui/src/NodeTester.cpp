#include "NodeTester.h"
#include <QTimer>

void NodeTester::testNode(const EWPNode &node, Callback callback)
{
    auto tester = new NodeTester(node, callback, nullptr);
    tester->startTest();
}

NodeTester::NodeTester(const EWPNode &node, Callback callback, QObject *parent)
    : QObject(parent)
    , node(node)
    , callback(callback)
    , socket(new QTcpSocket(this))
{
    connect(socket, &QTcpSocket::connected, this, &NodeTester::onConnected);
    connect(socket, &QTcpSocket::errorOccurred, this, &NodeTester::onError);
    
    // 5秒超时
    QTimer::singleShot(5000, this, &NodeTester::onTimeout);
}

void NodeTester::startTest()
{
    timer.start();
    
    QString host = node.serverIP.isEmpty() ? node.serverAddress : node.serverIP;
    socket->connectToHost(host, node.serverPort);
}

void NodeTester::onConnected()
{
    int latency = static_cast<int>(timer.elapsed());
    socket->disconnectFromHost();
    
    if (callback) {
        callback(latency);
    }
    
    deleteLater();
}

void NodeTester::onError(QAbstractSocket::SocketError error)
{
    Q_UNUSED(error)
    
    if (callback) {
        callback(-1);  // -1 表示失败
    }
    
    deleteLater();
}

void NodeTester::onTimeout()
{
    if (socket->state() != QAbstractSocket::ConnectedState) {
        socket->abort();
        
        if (callback) {
            callback(-1);  // 超时
        }
        
        deleteLater();
    }
}
