#pragma once

#include <QObject>
#include <QTcpSocket>
#include <QElapsedTimer>
#include <functional>
#include "EWPNode.h"

class NodeTester : public QObject
{
    Q_OBJECT

public:
    using Callback = std::function<void(int latency)>;
    
    static void testNode(const EWPNode &node, Callback callback);

private:
    explicit NodeTester(const EWPNode &node, Callback callback, QObject *parent = nullptr);
    void startTest();

private slots:
    void onConnected();
    void onError(QAbstractSocket::SocketError error);
    void onTimeout();

private:
    EWPNode node;
    Callback callback;
    QTcpSocket *socket;
    QElapsedTimer timer;
};
