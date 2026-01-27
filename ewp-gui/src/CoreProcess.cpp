#include "CoreProcess.h"
#include <QCoreApplication>
#include <QDir>
#include <QDebug>
#include <QNetworkRequest>
#include <QUrl>

CoreProcess::CoreProcess(QObject *parent)
    : QObject(parent)
{
    coreExecutable = findCoreExecutable();
    networkManager = new QNetworkAccessManager(this);
}

CoreProcess::~CoreProcess()
{
    stop();
}

QString CoreProcess::findCoreExecutable()
{
    QString appDir = QCoreApplication::applicationDirPath();
    QString path = appDir + "/ewp-core-client.exe";
    
    if (QFile::exists(path)) {
        return path;
    }
    
    path = appDir + "/../ewp-core-client.exe";
    if (QFile::exists(path)) {
        return QDir(path).absolutePath();
    }
    
    return "ewp-core-client.exe";
}

bool CoreProcess::start(const EWPNode &node, bool tunMode)
{
    if (isRunning()) {
        lastError = "进程已在运行";
        return false;
    }
    
    if (!QFile::exists(coreExecutable)) {
        lastError = "找不到核心文件: " + coreExecutable;
        emit errorOccurred(lastError);
        return false;
    }
    
    if (!node.isValid()) {
        lastError = "节点配置无效";
        emit errorOccurred(lastError);
        return false;
    }
    
    QStringList args = buildArguments(node, tunMode);
    
    process = new QProcess(this);
    
    connect(process, &QProcess::started, this, &CoreProcess::onProcessStarted);
    connect(process, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
            this, &CoreProcess::onProcessFinished);
    connect(process, &QProcess::errorOccurred, this, &CoreProcess::onProcessError);
    connect(process, &QProcess::readyReadStandardOutput, 
            this, &CoreProcess::onReadyReadStandardOutput);
    connect(process, &QProcess::readyReadStandardError, 
            this, &CoreProcess::onReadyReadStandardError);
    
    qDebug() << "启动核心:" << coreExecutable << args;
    
    process->start(coreExecutable, args);
    
    if (!process->waitForStarted(5000)) {
        lastError = "启动超时";
        emit errorOccurred(lastError);
        delete process;
        process = nullptr;
        return false;
    }
    
    return true;
}

void CoreProcess::stop()
{
    if (!isRunning()) return;
    
    gracefulStop = true;
    
    // 尝试通过控制服务器优雅退出
    if (!controlAddr.isEmpty()) {
        sendQuitRequest();
        // 等待短时间，如果没有退出则强制终止
        if (process->waitForFinished(500)) {
            delete process;
            process = nullptr;
            return;
        }
    }
    
    // 快速终止
    process->terminate();
    if (!process->waitForFinished(300)) {
        process->kill();
        process->waitForFinished(200);
    }
    
    delete process;
    process = nullptr;
}

void CoreProcess::sendQuitRequest()
{
    if (controlAddr.isEmpty()) return;
    
    QUrl url(QString("http://%1/quit").arg(controlAddr));
    QNetworkRequest request(url);
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    request.setTransferTimeout(500);  // 500ms 超时
    
    QNetworkReply *reply = networkManager->post(request, QByteArray());
    connect(reply, &QNetworkReply::finished, reply, &QNetworkReply::deleteLater);
}

bool CoreProcess::isRunning() const
{
    return process && process->state() == QProcess::Running;
}

QStringList CoreProcess::buildArguments(const EWPNode &node, bool tunMode)
{
    QStringList args;
    
    // 监听地址
    args << "-l" << listenAddr;
    
    // 服务器地址 (包含路径)
    QString serverUrl;
    switch (node.transportMode) {
        case EWPNode::WS:
            serverUrl = QString("wss://%1:%2%3")
                .arg(node.serverAddress)
                .arg(node.serverPort)
                .arg(node.wsPath);
            args << "-mode" << "ws";
            break;
        case EWPNode::GRPC:
            serverUrl = QString("grpcs://%1:%2/%3")
                .arg(node.serverAddress)
                .arg(node.serverPort)
                .arg(node.grpcServiceName);
            args << "-mode" << "grpc";
            break;
        case EWPNode::XHTTP:
            serverUrl = QString("https://%1:%2%3")
                .arg(node.serverAddress)
                .arg(node.serverPort)
                .arg(node.xhttpPath);
            args << "-mode" << "xhttp";
            args << "-xhttp-mode" << node.xhttpMode;
            break;
    }
    
    args << "-f" << serverUrl;
    
    // 应用层协议配置
    if (node.appProtocol == EWPNode::TROJAN) {
        args << "-protocol" << "trojan";
        args << "-password" << node.trojanPassword;
    } else {
        args << "-token" << node.uuid;
    }
    
    // 优选 IP
    if (!node.serverIP.isEmpty()) {
        args << "-ip" << node.serverIP;
    }
    
    // ECH 配置
    if (!node.enableECH) {
        args << "-fallback";
    } else {
        if (!node.echDomain.isEmpty()) {
            args << "-ech" << node.echDomain;
        }
        if (!node.dnsServer.isEmpty()) {
            args << "-dns" << node.dnsServer;
        }
    }
    
    // 高级配置 (仅 EWP 协议)
    if (node.appProtocol == EWPNode::EWP) {
        if (!node.enableFlow) {
            args << "-flow=false";
        }
    }
    if (node.enablePQC) {
        args << "-pqc";
    }
    
    // TUN 模式
    if (tunMode) {
        args << "-tun";
    }
    
    // 控制服务器（用于优雅退出）
    args << "-control" << "127.0.0.1:0";
    
    return args;
}

void CoreProcess::onProcessStarted()
{
    emit started();
}

void CoreProcess::onProcessFinished(int exitCode, QProcess::ExitStatus exitStatus)
{
    Q_UNUSED(exitCode)
    
    // 如果是优雅退出，不报告崩溃
    if (exitStatus == QProcess::CrashExit && !gracefulStop) {
        emit errorOccurred("核心进程崩溃");
    }
    
    gracefulStop = false;
    controlAddr.clear();
    emit stopped();
}

void CoreProcess::onProcessError(QProcess::ProcessError error)
{
    // 优雅退出时忽略 Crashed 错误（Windows 上 terminate() 会触发此错误）
    if (gracefulStop && error == QProcess::Crashed) {
        return;
    }
    
    QString errorMsg;
    
    switch (error) {
        case QProcess::FailedToStart:
            errorMsg = "进程启动失败";
            break;
        case QProcess::Crashed:
            errorMsg = "进程崩溃";
            break;
        case QProcess::Timedout:
            errorMsg = "进程超时";
            break;
        default:
            errorMsg = "未知错误";
            break;
    }
    
    emit errorOccurred(errorMsg);
}

void CoreProcess::onReadyReadStandardOutput()
{
    if (!process) return;
    
    QByteArray data = process->readAllStandardOutput();
    QString text = QString::fromUtf8(data).trimmed();
    
    if (!text.isEmpty()) {
        for (const auto &line : text.split('\n')) {
            QString trimmedLine = line.trimmed();
            // 解析控制服务器地址
            if (trimmedLine.startsWith("CONTROL_ADDR=")) {
                controlAddr = trimmedLine.mid(13);
            }
            emit logReceived(trimmedLine);
        }
    }
}

void CoreProcess::onReadyReadStandardError()
{
    if (!process) return;
    
    QByteArray data = process->readAllStandardError();
    QString text = QString::fromUtf8(data).trimmed();
    
    if (!text.isEmpty()) {
        for (const auto &line : text.split('\n')) {
            emit logReceived("[ERR] " + line.trimmed());
        }
    }
}
