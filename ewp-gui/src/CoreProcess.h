#pragma once

#include <QObject>
#include <QProcess>
#include <QString>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QTimer>
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

    static constexpr int kMaxRetries = 3;

signals:
    void started();
    void stopped();
    void errorOccurred(const QString &error);
    void logReceived(const QString &message);
    void reconnecting(int attempt, int maxAttempts);
    void reconnectFailed();

private slots:
    void onProcessStarted();
    void onProcessFinished(int exitCode, QProcess::ExitStatus exitStatus);
    void onProcessError(QProcess::ProcessError error);
    void onReadyReadStandardOutput();
    void onReadyReadStandardError();
    void attemptReconnect();

private:
    bool startCore(const EWPNode &node, bool tunMode);
    QString generateConfigFile(const EWPNode &node, bool tunMode);
    QString findCoreExecutable();
    void sendQuitRequest();
    void scheduleReconnect();

    QProcess *process = nullptr;
    QNetworkAccessManager *networkManager = nullptr;
    QTimer *retryTimer = nullptr;
    QString coreExecutable;
    QString listenAddr = "127.0.0.1:1080";
    QString controlAddr;
    QString lastError;
    QString configFilePath;
    bool gracefulStop = false;
    int retryCount = 0;
    EWPNode lastNode;
    bool lastTunMode = false;

#ifdef Q_OS_WIN
    bool startElevatedCore(const QStringList &args);
    void pollElevatedExit();
    void stopElevatedCore();

    void *elevatedHandle = nullptr;
    QTimer *exitPollTimer = nullptr;
    bool usingElevation = false;
#endif
};
