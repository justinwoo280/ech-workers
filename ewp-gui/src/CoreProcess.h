#pragma once

#include <QObject>
#include <QProcess>
#include <QString>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include "EWPNode.h"

class CoreProcess : public QObject
{
    Q_OBJECT

public:
    explicit CoreProcess(QObject *parent = nullptr);
    ~CoreProcess();

    bool start(const EWPNode &node, bool tunMode = false);
    void stop();
    bool isRunning() const;
    
    QString getListenAddr() const { return listenAddr; }
    QString getLastError() const { return lastError; }

signals:
    void started();
    void stopped();
    void errorOccurred(const QString &error);
    void logReceived(const QString &message);

private slots:
    void onProcessStarted();
    void onProcessFinished(int exitCode, QProcess::ExitStatus exitStatus);
    void onProcessError(QProcess::ProcessError error);
    void onReadyReadStandardOutput();
    void onReadyReadStandardError();

private:
    QStringList buildArguments(const EWPNode &node, bool tunMode);
    QString findCoreExecutable();

    void sendQuitRequest();

    QProcess *process = nullptr;
    QNetworkAccessManager *networkManager = nullptr;
    QString coreExecutable;
    QString listenAddr = "127.0.0.1:30000";
    QString controlAddr;
    QString lastError;
    bool gracefulStop = false;
};
